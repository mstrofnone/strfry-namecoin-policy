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
