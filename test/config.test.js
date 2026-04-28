'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadConfig, makeLogger } = require('../src/config');

test('loadConfig: defaults when only host provided', () => {
  const c = loadConfig({ NAMECOIN_ELECTRUMX_HOST: 'example.com' });
  assert.equal(c.host, 'example.com');
  assert.equal(c.tls, true);
  assert.equal(c.port, 50002);
  assert.equal(c.mode, 'kind0-only');
  assert.equal(c.cacheTtlMs, 300_000);
  assert.equal(c.logLevel, 'info');
  assert.equal(c.allowNonBit, true);
});

test('loadConfig: plaintext TCP picks port 50001 automatically', () => {
  const c = loadConfig({
    NAMECOIN_ELECTRUMX_HOST: 'example.com',
    NAMECOIN_ELECTRUMX_TLS: 'false',
  });
  assert.equal(c.tls, false);
  assert.equal(c.port, 50001);
});

test('loadConfig: explicit port wins', () => {
  const c = loadConfig({
    NAMECOIN_ELECTRUMX_HOST: 'example.com',
    NAMECOIN_ELECTRUMX_PORT: '57002',
  });
  assert.equal(c.port, 57002);
});

test('loadConfig: rejects invalid mode', () => {
  assert.throws(() => loadConfig({
    NAMECOIN_ELECTRUMX_HOST: 'x',
    NAMECOIN_POLICY_MODE: 'nonsense',
  }), /NAMECOIN_POLICY_MODE/);
});

test('loadConfig: rejects invalid log level', () => {
  assert.throws(() => loadConfig({
    NAMECOIN_ELECTRUMX_HOST: 'x',
    NAMECOIN_POLICY_LOG_LEVEL: 'chatty',
  }), /NAMECOIN_POLICY_LOG_LEVEL/);
});

test('loadConfig: parses booleans', () => {
  const c = loadConfig({
    NAMECOIN_ELECTRUMX_HOST: 'x',
    NAMECOIN_POLICY_ALLOW_NON_BIT: 'false',
  });
  assert.equal(c.allowNonBit, false);
});

// ─── makeLogger threshold tests ───
//
// `makeLogger(level)` returns a logger of the form `(msgLevel, ...args) => void`.
// Threshold rules:
//   - level=silent  → emits nothing
//   - level=info    → emits info but not debug
//   - level=debug   → emits info and debug
// Messages with msgLevel='silent' are never emitted regardless of threshold.
//
// We capture by stubbing console.error (the logger writes to stderr because
// strfry's plugin protocol owns stdout).

function captureStderr(fn) {
  const lines = [];
  const orig = console.error;
  console.error = (...args) => { lines.push(args); };
  try { fn(); } finally { console.error = orig; }
  return lines;
}

test('makeLogger: level=info emits info but suppresses debug', () => {
  const log = makeLogger('info');
  const lines = captureStderr(() => {
    log('info', 'visible');
    log('debug', 'should be suppressed');
  });
  assert.equal(lines.length, 1);
  assert.match(lines[0][0], /\binfo\b/);
  assert.equal(lines[0][1], 'visible');
});

test('makeLogger: level=debug emits both info and debug', () => {
  const log = makeLogger('debug');
  const lines = captureStderr(() => {
    log('info',  'i-msg');
    log('debug', 'd-msg');
  });
  assert.equal(lines.length, 2);
  assert.equal(lines[0][1], 'i-msg');
  assert.equal(lines[1][1], 'd-msg');
});

test('makeLogger: level=silent emits nothing', () => {
  const log = makeLogger('silent');
  const lines = captureStderr(() => {
    log('info',  'nope');
    log('debug', 'nope');
    log('silent', 'nope');
  });
  assert.equal(lines.length, 0);
});

test('makeLogger: msgLevel="silent" is never emitted, even at debug threshold', () => {
  const log = makeLogger('debug');
  const lines = captureStderr(() => {
    log('silent', 'should never appear');
  });
  assert.equal(lines.length, 0);
});

test('makeLogger: unknown msgLevel falls back to info-class threshold', () => {
  // unknown levels default to info-class (1). At threshold info, they emit;
  // at silent, they don't.
  const lInfo   = makeLogger('info');
  const lSilent = makeLogger('silent');
  const a = captureStderr(() => lInfo('weird', 'x'));
  const b = captureStderr(() => lSilent('weird', 'x'));
  assert.equal(a.length, 1);
  assert.equal(b.length, 0);
});
