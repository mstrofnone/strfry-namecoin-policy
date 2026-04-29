'use strict';

/**
 * End-to-end black-box test: spawn the plugin binary, pipe JSONL in,
 * read JSONL out. Stubs the resolver by pointing at a non-.bit NIP-05
 * (no ElectrumX required) and by omitting NAMECOIN_ELECTRUMX_HOST.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const path = require('node:path');

const BIN = path.join(__dirname, '..', 'bin', 'strfry-namecoin-policy.js');

function runPlugin({ env = {}, inputLines = [], timeoutMs = 5000 }) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [BIN], {
      env: { ...process.env, ...env, NAMECOIN_POLICY_LOG_LEVEL: 'silent' },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let out = '';
    let err = '';
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error(`plugin timed out after ${timeoutMs}ms; stderr=${err}`));
    }, timeoutMs);

    child.stdout.on('data', (c) => { out += c.toString('utf8'); });
    child.stderr.on('data', (c) => { err += c.toString('utf8'); });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code, stdout: out, stderr: err });
    });

    for (const line of inputLines) {
      child.stdin.write(line + '\n');
    }
    child.stdin.end();
  });
}

test('plugin: accepts kind:0 with non-.bit nip05 (no ElectrumX configured)', async () => {
  const event = {
    type: 'new',
    event: {
      id: 'a'.repeat(64),
      pubkey: 'b'.repeat(64),
      kind: 0,
      content: JSON.stringify({ nip05: 'alice@example.com' }),
      tags: [], created_at: 1, sig: '00',
    },
    receivedAt: 0, sourceType: 'IP4', sourceInfo: '127.0.0.1',
  };
  const { code, stdout } = await runPlugin({
    env: {}, // no NAMECOIN_ELECTRUMX_HOST
    inputLines: [JSON.stringify(event)],
  });

  assert.equal(code, 0);
  const out = stdout.trim().split('\n').filter(Boolean).map((l) => JSON.parse(l));
  assert.equal(out.length, 1);
  assert.equal(out[0].id, 'a'.repeat(64));
  assert.equal(out[0].action, 'accept');
});

test('plugin: accepts kind:1 by default', async () => {
  const event = {
    type: 'new',
    event: {
      id: 'c'.repeat(64),
      pubkey: 'd'.repeat(64),
      kind: 1,
      content: 'hello world',
      tags: [], created_at: 1, sig: '00',
    },
  };
  const { code, stdout } = await runPlugin({ inputLines: [JSON.stringify(event)] });
  assert.equal(code, 0);
  const out = JSON.parse(stdout.trim());
  assert.equal(out.action, 'accept');
  assert.equal(out.id, 'c'.repeat(64));
});

test('plugin: tolerates malformed input line and keeps running', async () => {
  const goodEvent = {
    type: 'new',
    event: {
      id: 'e'.repeat(64), pubkey: 'f'.repeat(64), kind: 1,
      content: '', tags: [], created_at: 1, sig: '00',
    },
  };
  const { code, stdout } = await runPlugin({
    inputLines: ['this is not json', JSON.stringify(goodEvent)],
  });
  assert.equal(code, 0);
  const lines = stdout.trim().split('\n').filter(Boolean).map((l) => JSON.parse(l));
  assert.equal(lines.length, 2);
  assert.equal(lines[0].action, 'reject'); // malformed
  assert.equal(lines[1].action, 'accept'); // good event
  assert.equal(lines[1].id, 'e'.repeat(64));
});

test('plugin: rejects .bit NIP-05 when no ElectrumX configured (fail-closed default)', async () => {
  // Hardened default: without an ElectrumX host we can't verify, so we
  // refuse rather than silently rubber-stamping the identity. Operators
  // who explicitly want the legacy behavior must opt in via
  // NAMECOIN_POLICY_SOFT_FAIL=true.
  const event = {
    type: 'new',
    event: {
      id: '1'.repeat(64), pubkey: '2'.repeat(64), kind: 0,
      content: JSON.stringify({ nip05: 'alice@testls.bit' }),
      tags: [], created_at: 1, sig: '00',
    },
  };
  const { code, stdout, stderr } = await runPlugin({
    env: { NAMECOIN_POLICY_LOG_LEVEL: 'info' },
    inputLines: [JSON.stringify(event)],
  });
  assert.equal(code, 0);
  const res = JSON.parse(stdout.trim());
  assert.equal(res.action, 'reject');
  assert.match(res.msg, /Namecoin .bit NIP-05 verification unavailable/);
  assert.match(stderr, /NAMECOIN_ELECTRUMX_HOST not set/);
});

test('plugin: NAMECOIN_POLICY_SOFT_FAIL=true restores legacy accept-everything', async () => {
  const event = {
    type: 'new',
    event: {
      id: '3'.repeat(64), pubkey: '4'.repeat(64), kind: 0,
      content: JSON.stringify({ nip05: 'alice@testls.bit' }),
      tags: [], created_at: 1, sig: '00',
    },
  };
  const { code, stdout, stderr } = await runPlugin({
    env: { NAMECOIN_POLICY_SOFT_FAIL: 'true' },
    inputLines: [JSON.stringify(event)],
  });
  assert.equal(code, 0);
  const res = JSON.parse(stdout.trim());
  assert.equal(res.action, 'accept');
  // Banner about soft-fail still shows up.
  assert.match(stderr, /SOFT_FAIL=true/);
});

test('plugin: NAMECOIN_ELECTRUMX_INSECURE=true emits a banner', async () => {
  // No host needed for the banner check — we only assert stderr formatting.
  const event = {
    type: 'new',
    event: {
      id: '5'.repeat(64), pubkey: '6'.repeat(64), kind: 1,
      content: '', tags: [], created_at: 1, sig: '00',
    },
  };
  const { code, stderr } = await runPlugin({
    env: { NAMECOIN_ELECTRUMX_INSECURE: 'true' },
    inputLines: [JSON.stringify(event)],
  });
  assert.equal(code, 0);
  assert.match(stderr, /TLS verification DISABLED/);
  assert.match(stderr, /vulnerable to MITM/);
});
