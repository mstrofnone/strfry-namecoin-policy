'use strict';

/**
 * Integration tests for the operational wiring done in index.js:
 *   - PersistentLRU is used when NAMECOIN_POLICY_CACHE_PATH is set
 *   - Metrics flow through handler accept/reject
 *   - makeCache falls back to in-memory on construction failure
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { makeHandler, makeCache } = require('../src/index');
const { LRUCache } = require('../src/cache');
const { PersistentLRU } = require('../src/persistent-cache');
const { Metrics, NullMetrics } = require('../src/metrics');

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'strfry-wiring-'));
}

const PK = 'a'.repeat(64);

function quietLogger() {}

function baseConfig(overrides = {}) {
  return {
    host: 'h.example', port: 50002, tls: true,
    hosts: null, socks5: null,
    certPinSha256: null, rejectUnauthorized: true,
    timeoutMs: 5000, retries: 2,
    mode: 'kind0-only', cacheTtlMs: 300_000, cachePath: null,
    metricsPort: 0, poolKeepaliveMs: 30_000,
    logLevel: 'silent', allowNonBit: true,
    ...overrides,
  };
}

function newEvent({ id = 'e'.repeat(64), kind = 0, pubkey = PK, content = '' }) {
  return { type: 'new', event: { id, kind, pubkey, content, tags: [], created_at: 1, sig: '00' } };
}

test('makeCache: returns LRUCache when cachePath unset', () => {
  const c = makeCache({ cachePath: null, namespace: 'x', max: 10, ttlMs: 1000, logger: quietLogger });
  assert.ok(c instanceof LRUCache);
});

test('makeCache: returns PersistentLRU when cachePath set', () => {
  const dir = tmpDir();
  const c = makeCache({
    cachePath: path.join(dir, 'cache.db'),
    namespace: 'rs',
    max: 10,
    ttlMs: 1000,
    logger: quietLogger,
  });
  assert.ok(c instanceof PersistentLRU);
  c.set('k', { ok: true });
  assert.deepEqual(c.get('k'), { ok: true });
  c.close && c.close();
  fs.rmSync(dir, { recursive: true, force: true });
});

test('makeCache: falls back to LRUCache when path is not writable', () => {
  // /dev/null/foo can't be created (parent isn't a directory)
  const c = makeCache({
    cachePath: '/dev/null/cant-create-here',
    namespace: 'rs',
    max: 10,
    ttlMs: 1000,
    logger: quietLogger,
  });
  assert.ok(c instanceof LRUCache);
});

test('makeCache: separate namespaces in same file are isolated', () => {
  const dir = tmpDir();
  const file = path.join(dir, 'cache.db');
  const a = makeCache({ cachePath: file, namespace: 'A', max: 10, ttlMs: 1000, logger: quietLogger });
  const b = makeCache({ cachePath: file, namespace: 'B', max: 10, ttlMs: 1000, logger: quietLogger });
  a.set('k', 1);
  b.set('k', 2);
  assert.equal(a.get('k'), 1);
  assert.equal(b.get('k'), 2);
  a.close && a.close();
  b.close && b.close();
  fs.rmSync(dir, { recursive: true, force: true });
});

test('handler: emits acceptances_total metric on accept', async () => {
  const metrics = new Metrics();
  const handle = makeHandler({
    config: baseConfig(),
    resolver: { async resolve() { return null; } },
    verifiedAuthors: new LRUCache({ max: 10 }),
    metrics, logger: quietLogger,
  });
  await handle(newEvent({ kind: 1, content: 'hi' }));
  const txt = metrics.render();
  assert.match(txt, /acceptances_total 1/);
});

test('handler: emits rejections_total{reason=...} metric on reject', async () => {
  const metrics = new Metrics();
  const handle = makeHandler({
    config: baseConfig({ mode: 'all-kinds-require-bit' }),
    resolver: { async resolve() { return null; } },
    verifiedAuthors: new LRUCache({ max: 10 }),
    metrics, logger: quietLogger,
  });
  await handle(newEvent({ kind: 1, content: 'hi' }));
  const txt = metrics.render();
  assert.match(txt, /rejections_total\{reason="unverified-author"\} 1/);
});

test('handler: emits lookup_duration_ms histogram for .bit lookups', async () => {
  const metrics = new Metrics();
  const handle = makeHandler({
    config: baseConfig(),
    resolver: { async resolve() { return { pubkey: PK, relays: [] }; } },
    verifiedAuthors: new LRUCache({ max: 10 }),
    metrics, logger: quietLogger,
  });
  await handle(newEvent({ content: JSON.stringify({ nip05: 'alice@testls.bit' }) }));
  const txt = metrics.render();
  assert.match(txt, /lookup_duration_ms_count 1/);
});

test('handler: NullMetrics is no-op (no throw)', async () => {
  const handle = makeHandler({
    config: baseConfig(),
    resolver: { async resolve() { return null; } },
    verifiedAuthors: new LRUCache({ max: 10 }),
    metrics: new NullMetrics(), logger: quietLogger,
  });
  const r = await handle(newEvent({ kind: 1 }));
  assert.equal(r.action, 'accept');
});

test('handler: works without metrics field at all (defaults to NullMetrics)', async () => {
  const handle = makeHandler({
    config: baseConfig(),
    resolver: { async resolve() { return null; } },
    verifiedAuthors: new LRUCache({ max: 10 }),
    logger: quietLogger,
  });
  const r = await handle(newEvent({ kind: 1 }));
  assert.equal(r.action, 'accept');
});
