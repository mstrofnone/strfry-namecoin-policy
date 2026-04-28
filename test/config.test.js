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
