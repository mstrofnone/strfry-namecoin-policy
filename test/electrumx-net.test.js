'use strict';

/**
 * Networked tests for ElectrumXClient that use a local fake-Electrum TCP
 * server so we can exercise the handshake-await (#6) and tip-cache (#7)
 * fixes end-to-end without hitting real infrastructure.
 *
 * Plain TCP only — no TLS — so we can keep the test lightweight and
 * avoid generating self-signed certs.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const {
  ElectrumXClient,
  buildNameIndexScript,
  electrumScriptHash,
  pushData,
  parseNameFromTx,
  OP_NAME_UPDATE,
  _resetTipCacheForTests,
} = require('../src/electrumx');

function makeNameTxHex(name, value) {
  return Buffer.concat([
    Buffer.from([OP_NAME_UPDATE]),
    pushData(Buffer.from(name, 'ascii')),
    pushData(Buffer.from(value, 'utf8')),
    Buffer.from([0x6d, 0x75]),
  ]).toString('hex');
}

/**
 * Start a tiny line-oriented JSON-RPC server. `handlers` maps method name
 * → fn(params) → result | Promise<result> | { __error: '...' } to send a
 * JSON-RPC error.
 *
 * `opts.versionDelayMs` (default 0): hold the server.version reply this
 *   long so tests can drive timeouts.
 * `opts.versionFails`: if true, return a JSON-RPC error for server.version.
 */
function startFakeServer(handlers, opts = {}) {
  const calls = [];
  const server = net.createServer((sock) => {
    let buf = '';
    sock.setEncoding('utf8');
    sock.on('data', async (chunk) => {
      buf += chunk;
      let nl;
      while ((nl = buf.indexOf('\n')) !== -1) {
        const line = buf.slice(0, nl).trim();
        buf = buf.slice(nl + 1);
        if (!line) continue;
        let msg;
        try { msg = JSON.parse(line); } catch (_) { continue; }
        calls.push({ method: msg.method, params: msg.params });
        const fn = handlers[msg.method];
        let resp;
        if (msg.method === 'server.version' && opts.versionDelayMs) {
          await new Promise((r) => setTimeout(r, opts.versionDelayMs));
        }
        if (msg.method === 'server.version' && opts.versionFails) {
          resp = { jsonrpc: '2.0', id: msg.id, error: { code: 1, message: 'no thanks' } };
        } else if (typeof fn === 'function') {
          try {
            const r = await fn(msg.params);
            if (r && r.__error) {
              resp = { jsonrpc: '2.0', id: msg.id, error: { code: 1, message: r.__error } };
            } else {
              resp = { jsonrpc: '2.0', id: msg.id, result: r };
            }
          } catch (e) {
            resp = { jsonrpc: '2.0', id: msg.id, error: { code: 1, message: e.message } };
          }
        } else {
          resp = { jsonrpc: '2.0', id: msg.id, error: { code: -32601, message: 'method not found' } };
        }
        try { sock.write(JSON.stringify(resp) + '\n'); } catch (_) {}
      }
    });
    sock.on('error', () => {});
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({ port, server, calls, close: () => new Promise((r) => server.close(() => r())) });
    });
  });
}

function makeHandlers({ name, value, tipHeight = 1000, txHeight = 900 } = {}) {
  const script = buildNameIndexScript(Buffer.from(name, 'ascii'));
  const expectedSh = electrumScriptHash(script);
  const txid = 'aa' + 'bb'.repeat(31);
  const txHex = makeNameTxHex(name, value);
  return {
    expectedSh,
    txid,
    handlers: {
      'server.version': () => ['ElectrumX 1.0', '1.4'],
      'blockchain.scripthash.get_history': ([sh]) => {
        if (sh !== expectedSh) return [];
        return [{ tx_hash: txid, height: txHeight }];
      },
      'blockchain.transaction.get': ([h]) => {
        if (h !== txid) throw new Error('unknown tx');
        return { vout: [{ scriptPubKey: { hex: txHex } }] };
      },
      'blockchain.headers.subscribe': () => ({ height: tipHeight }),
    },
  };
}

// ── Fix #6: server.version handshake is awaited ──────────────────────────

test('ElectrumXClient: nameShow fails fast when server.version times out', async () => {
  _resetTipCacheForTests();
  const { handlers } = makeHandlers({
    name: 'd/x', value: JSON.stringify({ nostr: 'a'.repeat(64) }),
  });
  // Hold server.version reply longer than the 2s handshake budget. With
  // retries=0 and timeoutMs short, total wall time should be < a couple
  // seconds. We assert the error mentions handshake.
  const fake = await startFakeServer(handlers, { versionDelayMs: 4000 });
  const client = new ElectrumXClient({
    host: '127.0.0.1', port: fake.port, tls: false,
    timeoutMs: 8000, retries: 0,
  });
  const t0 = Date.now();
  await assert.rejects(() => client.nameShow('d/x'), /handshake/i);
  const elapsed = Date.now() - t0;
  assert.ok(elapsed < 3500, `handshake should timeout in ~2s, took ${elapsed}ms`);
  await fake.close();
});

test('ElectrumXClient: handshake error trips retry instead of being swallowed', async () => {
  _resetTipCacheForTests();
  const { handlers } = makeHandlers({
    name: 'd/x', value: JSON.stringify({ nostr: 'a'.repeat(64) }),
  });
  // Server returns a JSON-RPC error for version. With retries=1 we
  // expect 2 connect attempts; both fail → final reject.
  const fake = await startFakeServer(handlers, { versionFails: true });
  const client = new ElectrumXClient({
    host: '127.0.0.1', port: fake.port, tls: false,
    timeoutMs: 4000, retries: 1,
  });
  await assert.rejects(() => client.nameShow('d/x'), /handshake/i);
  // Each connect attempt sends one server.version → with retries=1 we expect 2.
  const versionCalls = fake.calls.filter((c) => c.method === 'server.version').length;
  assert.equal(versionCalls, 2, 'failed handshake must trip the retry loop');
  await fake.close();
});

// ── Fix #7: blockchain.headers.subscribe is cached for 60s ───────────────

test('ElectrumXClient: tip is cached across resolves (no extra subscribe call)', async () => {
  _resetTipCacheForTests();
  const value = JSON.stringify({ nostr: 'a'.repeat(64) });
  const { handlers } = makeHandlers({ name: 'd/x', value, tipHeight: 1000, txHeight: 990 });
  const fake = await startFakeServer(handlers);
  const client = new ElectrumXClient({
    host: '127.0.0.1', port: fake.port, tls: false,
    timeoutMs: 4000, retries: 0, minConfirmations: 1,
  });

  const r1 = await client.nameShow('d/x');
  assert.equal(r1.value, value);
  const r2 = await client.nameShow('d/x');
  assert.equal(r2.value, value);

  const subscribes = fake.calls.filter((c) => c.method === 'blockchain.headers.subscribe').length;
  assert.equal(subscribes, 1, 'second resolve should reuse the cached tip');
  await fake.close();
});

test('ElectrumXClient: minConfirmations=0 still resolves a 1-conf update', async () => {
  _resetTipCacheForTests();
  const value = JSON.stringify({ nostr: 'b'.repeat(64) });
  const { handlers } = makeHandlers({ name: 'd/y', value, tipHeight: 1000, txHeight: 1000 });
  const fake = await startFakeServer(handlers);
  const client = new ElectrumXClient({
    host: '127.0.0.1', port: fake.port, tls: false,
    timeoutMs: 4000, retries: 0, minConfirmations: 0,
  });
  const r = await client.nameShow('d/y');
  assert.equal(r.value, value);
  await fake.close();
});

test('ElectrumXClient: minConfirmations=10 rejects a fresh update', async () => {
  _resetTipCacheForTests();
  const value = JSON.stringify({ nostr: 'c'.repeat(64) });
  const { handlers } = makeHandlers({ name: 'd/z', value, tipHeight: 1000, txHeight: 1000 });
  const fake = await startFakeServer(handlers);
  const client = new ElectrumXClient({
    host: '127.0.0.1', port: fake.port, tls: false,
    timeoutMs: 4000, retries: 0, minConfirmations: 10,
  });
  // Fresh tx (1 conf) gets filtered out → null.
  const r = await client.nameShow('d/z');
  assert.equal(r, null);
  await fake.close();
});
