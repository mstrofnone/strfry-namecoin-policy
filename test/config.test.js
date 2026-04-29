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

test('loadConfig: NAMECOIN_POLICY_MIN_CONFIRMATIONS defaults to 1', () => {
  const c = loadConfig({ NAMECOIN_ELECTRUMX_HOST: 'x' });
  assert.equal(c.minConfirmations, 1);
});

test('loadConfig: NAMECOIN_POLICY_MIN_CONFIRMATIONS honors 0 (for tests)', () => {
  const c = loadConfig({
    NAMECOIN_ELECTRUMX_HOST: 'x',
    NAMECOIN_POLICY_MIN_CONFIRMATIONS: '0',
  });
  assert.equal(c.minConfirmations, 0);
});

test('loadConfig: NAMECOIN_POLICY_MIN_CONFIRMATIONS accepts a positive int', () => {
  const c = loadConfig({
    NAMECOIN_ELECTRUMX_HOST: 'x',
    NAMECOIN_POLICY_MIN_CONFIRMATIONS: '6',
  });
  assert.equal(c.minConfirmations, 6);
});

test('loadConfig: NAMECOIN_POLICY_MIN_CONFIRMATIONS rejects non-integer', () => {
  assert.throws(() => loadConfig({
    NAMECOIN_ELECTRUMX_HOST: 'x',
    NAMECOIN_POLICY_MIN_CONFIRMATIONS: 'six',
  }), /NAMECOIN_POLICY_MIN_CONFIRMATIONS/);
});

test('loadConfig: NAMECOIN_POLICY_MIN_CONFIRMATIONS rejects negative', () => {
  assert.throws(() => loadConfig({
    NAMECOIN_ELECTRUMX_HOST: 'x',
    NAMECOIN_POLICY_MIN_CONFIRMATIONS: '-1',
  }), /NAMECOIN_POLICY_MIN_CONFIRMATIONS/);
});

test('loadConfig: NAMECOIN_POLICY_NEG_CACHE_TTL_MS defaults to 30000', () => {
  const c = loadConfig({ NAMECOIN_ELECTRUMX_HOST: 'x' });
  assert.equal(c.negCacheTtlMs, 30_000);
});

test('loadConfig: NAMECOIN_POLICY_NEG_CACHE_TTL_MS honors override', () => {
  const c = loadConfig({
    NAMECOIN_ELECTRUMX_HOST: 'x',
    NAMECOIN_POLICY_NEG_CACHE_TTL_MS: '5000',
  });
  assert.equal(c.negCacheTtlMs, 5000);
});

test('loadConfig: NAMECOIN_POLICY_NEG_CACHE_TTL_MS rejects garbage', () => {
  assert.throws(() => loadConfig({
    NAMECOIN_ELECTRUMX_HOST: 'x',
    NAMECOIN_POLICY_NEG_CACHE_TTL_MS: 'never',
  }), /NAMECOIN_POLICY_NEG_CACHE_TTL_MS/);
});

// ── Hardening: new env vars ──
test('loadConfig: rate-limiter defaults', () => {
  const c = loadConfig({ NAMECOIN_ELECTRUMX_HOST: 'x' });
  assert.equal(c.lookupRps, 5);
  assert.equal(c.lookupBurst, 10);
  assert.equal(c.lookupQueueMs, 2000);
});

test('loadConfig: rate-limiter overrides', () => {
  const c = loadConfig({
    NAMECOIN_ELECTRUMX_HOST: 'x',
    NAMECOIN_POLICY_LOOKUP_RPS: '20',
    NAMECOIN_POLICY_LOOKUP_BURST: '50',
    NAMECOIN_POLICY_LOOKUP_QUEUE_MS: '0',
  });
  assert.equal(c.lookupRps, 20);
  assert.equal(c.lookupBurst, 50);
  assert.equal(c.lookupQueueMs, 0);
});

test('loadConfig: rejects invalid rate-limiter values', () => {
  assert.throws(() => loadConfig({
    NAMECOIN_ELECTRUMX_HOST: 'x',
    NAMECOIN_POLICY_LOOKUP_RPS: '-1',
  }), /LOOKUP_RPS/);
  assert.throws(() => loadConfig({
    NAMECOIN_ELECTRUMX_HOST: 'x',
    NAMECOIN_POLICY_LOOKUP_BURST: 'nope',
  }), /LOOKUP_BURST/);
  assert.throws(() => loadConfig({
    NAMECOIN_ELECTRUMX_HOST: 'x',
    NAMECOIN_POLICY_LOOKUP_QUEUE_MS: '-5',
  }), /LOOKUP_QUEUE_MS/);
});

test('loadConfig: softFail defaults to false', () => {
  const c = loadConfig({ NAMECOIN_ELECTRUMX_HOST: 'x' });
  assert.equal(c.softFail, false);
});

test('loadConfig: softFail honors NAMECOIN_POLICY_SOFT_FAIL=true', () => {
  const c = loadConfig({ NAMECOIN_POLICY_SOFT_FAIL: 'true' });
  assert.equal(c.softFail, true);
});

test('loadConfig: insecure surfaces on config object', () => {
  const c = loadConfig({
    NAMECOIN_ELECTRUMX_HOST: 'x',
    NAMECOIN_ELECTRUMX_INSECURE: 'true',
  });
  assert.equal(c.insecure, true);
  assert.equal(c.rejectUnauthorized, false);
});

test('loadConfig: hosts list overrides single host', () => {
  const c = loadConfig({
    NAMECOIN_ELECTRUMX_HOSTS: 'a.example:50002, b.example:50003',
    NAMECOIN_ELECTRUMX_HOST: 'ignored.example',
  });
  assert.equal(c.hosts.length, 2);
  assert.deepEqual(c.hosts[0], { host: 'a.example', port: 50002, tls: true });
  assert.deepEqual(c.hosts[1], { host: 'b.example', port: 50003, tls: true });
});

test('loadConfig: hosts inherits tls=false default port 50001', () => {
  const c = loadConfig({
    NAMECOIN_ELECTRUMX_HOSTS: 'a.example:50001,b.example:50002',
    NAMECOIN_ELECTRUMX_TLS: 'false',
  });
  assert.equal(c.hosts.length, 2);
  assert.deepEqual(c.hosts[0], { host: 'a.example', port: 50001, tls: false });
  assert.deepEqual(c.hosts[1], { host: 'b.example', port: 50002, tls: false });
});

test('loadConfig: socks5 proxy', () => {
  const c = loadConfig({
    NAMECOIN_ELECTRUMX_HOST: 'x',
    NAMECOIN_ELECTRUMX_SOCKS5: '127.0.0.1:9050',
  });
  assert.deepEqual(c.socks5, { host: '127.0.0.1', port: 9050 });
});

test('loadConfig: cachePath unset = null', () => {
  const c = loadConfig({ NAMECOIN_ELECTRUMX_HOST: 'x' });
  assert.equal(c.cachePath, null);
});

test('loadConfig: cachePath set', () => {
  const c = loadConfig({
    NAMECOIN_ELECTRUMX_HOST: 'x',
    NAMECOIN_POLICY_CACHE_PATH: '/var/cache/strfry-namecoin/cache.db',
  });
  assert.equal(c.cachePath, '/var/cache/strfry-namecoin/cache.db');
});

test('loadConfig: metricsPort defaults to 0 (disabled)', () => {
  const c = loadConfig({ NAMECOIN_ELECTRUMX_HOST: 'x' });
  assert.equal(c.metricsPort, 0);
});

test('loadConfig: metricsPort accepts integer', () => {
  const c = loadConfig({
    NAMECOIN_ELECTRUMX_HOST: 'x',
    NAMECOIN_POLICY_METRICS_PORT: '9091',
  });
  assert.equal(c.metricsPort, 9091);
});

test('loadConfig: rejects invalid metricsPort', () => {
  assert.throws(() => loadConfig({
    NAMECOIN_ELECTRUMX_HOST: 'x',
    NAMECOIN_POLICY_METRICS_PORT: '70000',
  }), /NAMECOIN_POLICY_METRICS_PORT/);
});

test('loadConfig: poolKeepaliveMs default 30000', () => {
  const c = loadConfig({ NAMECOIN_ELECTRUMX_HOST: 'x' });
  assert.equal(c.poolKeepaliveMs, 30_000);
});

test('loadConfig: poolKeepaliveMs=0 disables pooling', () => {
  const c = loadConfig({
    NAMECOIN_ELECTRUMX_HOST: 'x',
    NAMECOIN_POLICY_POOL_KEEPALIVE_MS: '0',
  });
  assert.equal(c.poolKeepaliveMs, 0);
});

test('loadConfig: rejects malformed socks5', () => {
  assert.throws(() => loadConfig({
    NAMECOIN_ELECTRUMX_HOST: 'x',
    NAMECOIN_ELECTRUMX_SOCKS5: 'no-port-here',
  }), /NAMECOIN_ELECTRUMX_SOCKS5/);
});

test('loadConfig: rejects malformed hosts entry', () => {
  assert.throws(() => loadConfig({
    NAMECOIN_ELECTRUMX_HOSTS: 'a.example:bad',
  }), /NAMECOIN_ELECTRUMX_HOSTS/);
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
