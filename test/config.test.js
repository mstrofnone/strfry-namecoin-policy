'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadConfig } = require('../src/config');

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
