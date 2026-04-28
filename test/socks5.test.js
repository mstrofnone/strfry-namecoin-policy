'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const { connectSocks5 } = require('../src/socks5');

/**
 * Spin up a tiny SOCKS5 server that:
 *   1. Validates the greeting (5, 1, 0)
 *   2. Replies with "no-auth selected" (5, 0)
 *   3. Validates a CONNECT request to a fixed target
 *   4. Replies success (5, 0, 0, 1, 0,0,0,0, 0,0)
 *   5. Then echoes data (so we can verify tunnel works)
 *
 * Returns { server, port, lastRequest }.
 */
function startMockSocks5({ failWith = null, allowedTargets = null } = {}) {
  const lastRequest = { greeting: null, connect: null };
  const server = net.createServer((sock) => {
    let stage = 'greet';
    let buf = Buffer.alloc(0);
    sock.on('data', (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      if (stage === 'greet') {
        if (buf.length < 2) return;
        const nm = buf[1];
        if (buf.length < 2 + nm) return;
        lastRequest.greeting = buf.slice(0, 2 + nm);
        buf = buf.slice(2 + nm);
        // Reply with "no-auth"
        sock.write(Buffer.from([0x05, 0x00]));
        stage = 'connect';
      }
      if (stage === 'connect') {
        // VER=5 CMD=1 RSV=0 ATYP=3 LEN NAME PORT(2)
        if (buf.length < 5) return;
        if (buf[3] !== 0x03) {
          sock.write(Buffer.from([0x05, 0x08, 0x00, 0x01, 0,0,0,0, 0,0]));
          sock.end();
          return;
        }
        const dlen = buf[4];
        const need = 5 + dlen + 2;
        if (buf.length < need) return;
        const reqBytes = buf.slice(0, need);
        lastRequest.connect = reqBytes;
        const host = reqBytes.slice(5, 5 + dlen).toString('ascii');
        const port = reqBytes.readUInt16BE(5 + dlen);
        lastRequest.host = host;
        lastRequest.port = port;
        buf = buf.slice(need);

        if (failWith != null) {
          sock.write(Buffer.from([0x05, failWith, 0x00, 0x01, 0,0,0,0, 0,0]));
          sock.end();
          return;
        }
        if (allowedTargets && !allowedTargets.includes(`${host}:${port}`)) {
          sock.write(Buffer.from([0x05, 0x02, 0x00, 0x01, 0,0,0,0, 0,0]));
          sock.end();
          return;
        }

        // Success.
        sock.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0]));
        stage = 'tunnel';
        // Echo any leftover + future bytes (for tests that send data after handshake).
        if (buf.length > 0) sock.write(buf);
      }
      if (stage === 'tunnel') {
        // Echo
        if (buf.length > 0) {
          sock.write(buf);
          buf = Buffer.alloc(0);
        }
      }
    });
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      resolve({ server, port: server.address().port, lastRequest });
    });
  });
}

test('connectSocks5: sends correct greeting + CONNECT bytes', async () => {
  const { server, port, lastRequest } = await startMockSocks5();
  const sock = await connectSocks5({
    proxyHost: '127.0.0.1', proxyPort: port,
    host: 'electrumx.example.com', port: 50002,
  });
  // Greeting: 0x05 0x01 0x00
  assert.deepEqual(Array.from(lastRequest.greeting), [0x05, 0x01, 0x00]);
  // CONNECT: 0x05 0x01 0x00 0x03 LEN <name> <port BE>
  const cr = lastRequest.connect;
  assert.equal(cr[0], 0x05);
  assert.equal(cr[1], 0x01);
  assert.equal(cr[2], 0x00);
  assert.equal(cr[3], 0x03);
  assert.equal(cr[4], 'electrumx.example.com'.length);
  assert.equal(cr.slice(5, 5 + cr[4]).toString('ascii'), 'electrumx.example.com');
  assert.equal(cr.readUInt16BE(5 + cr[4]), 50002);
  sock.destroy();
  await new Promise((r) => server.close(r));
});

test('connectSocks5: tunnel echoes data after handshake', async () => {
  const { server, port } = await startMockSocks5();
  const sock = await connectSocks5({
    proxyHost: '127.0.0.1', proxyPort: port,
    host: 'target.example', port: 12345,
  });
  const got = await new Promise((res, rej) => {
    let buf = '';
    sock.on('data', (d) => { buf += d.toString('utf8'); if (buf.includes('hello')) res(buf); });
    sock.on('error', rej);
    sock.write('hello');
  });
  assert.match(got, /hello/);
  sock.destroy();
  await new Promise((r) => server.close(r));
});

test('connectSocks5: rejects when CONNECT fails', async () => {
  const { server, port } = await startMockSocks5({ failWith: 0x05 }); // connection refused
  await assert.rejects(
    connectSocks5({
      proxyHost: '127.0.0.1', proxyPort: port,
      host: 'target.example', port: 9,
    }),
    /CONNECT failed with REP=0x5/,
  );
  await new Promise((r) => server.close(r));
});

test('connectSocks5: times out when proxy is silent', async () => {
  const peers = [];
  const silentServer = net.createServer((sock) => { peers.push(sock); /* never reply */ });
  await new Promise((r) => silentServer.listen(0, '127.0.0.1', r));
  const port = silentServer.address().port;
  await assert.rejects(
    connectSocks5({
      proxyHost: '127.0.0.1', proxyPort: port,
      host: 'target.example', port: 9,
      timeoutMs: 100,
    }),
    /SOCKS5 timeout/,
  );
  for (const s of peers) { try { s.destroy(); } catch (_) {} }
  await new Promise((r) => silentServer.close(r));
});

test('connectSocks5: rejects bad ver in greeting reply', async () => {
  const badServer = net.createServer((sock) => {
    sock.on('data', () => {
      // Reply with wrong version
      sock.write(Buffer.from([0x04, 0x00]));
    });
  });
  await new Promise((r) => badServer.listen(0, '127.0.0.1', r));
  const port = badServer.address().port;
  await assert.rejects(
    connectSocks5({
      proxyHost: '127.0.0.1', proxyPort: port,
      host: 'target.example', port: 9,
      timeoutMs: 1000,
    }),
    /bad version/,
  );
  await new Promise((r) => badServer.close(r));
});

test('connectSocks5: rejects when proxy refuses all auth methods', async () => {
  const badServer = net.createServer((sock) => {
    sock.on('data', () => {
      sock.write(Buffer.from([0x05, 0xff]));
    });
  });
  await new Promise((r) => badServer.listen(0, '127.0.0.1', r));
  const port = badServer.address().port;
  await assert.rejects(
    connectSocks5({
      proxyHost: '127.0.0.1', proxyPort: port,
      host: 'target.example', port: 9,
      timeoutMs: 1000,
    }),
    /rejected all auth methods/,
  );
  await new Promise((r) => badServer.close(r));
});
