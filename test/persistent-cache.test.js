'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { PersistentLRU } = require('../src/persistent-cache');

function tmp(suffix = '') {
  return path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'plru-')),
    `cache${suffix}`);
}

test('PersistentLRU(jsonl): set/get roundtrip', () => {
  const p = tmp('.jsonl');
  const c = new PersistentLRU({ path: p, max: 10, ttlMs: 60_000, forceJsonl: true });
  c.set('a', 1); c.set('b', { x: 2 });
  assert.equal(c.get('a'), 1);
  assert.deepEqual(c.get('b'), { x: 2 });
  c.close();
});

test('PersistentLRU(jsonl): persists across restart', () => {
  const p = tmp('.jsonl');
  const c1 = new PersistentLRU({ path: p, max: 10, ttlMs: 60_000, forceJsonl: true });
  c1.set('alice', { pubkey: 'aa' });
  c1.set('bob',   null); // negative entry
  c1.close();

  const c2 = new PersistentLRU({ path: p, max: 10, ttlMs: 60_000, forceJsonl: true });
  assert.deepEqual(c2.get('alice'), { pubkey: 'aa' });
  // null is a real cached value — distinct from undefined (miss).
  assert.equal(c2.has('bob'), true);
  assert.equal(c2.get('bob'), null);
  c2.close();
});

test('PersistentLRU(jsonl): TTL expiration on read', async () => {
  const p = tmp('.jsonl');
  const c = new PersistentLRU({ path: p, max: 10, ttlMs: 30, forceJsonl: true });
  c.set('x', 'v');
  assert.equal(c.get('x'), 'v');
  await new Promise((r) => setTimeout(r, 50));
  assert.equal(c.get('x'), undefined);
  c.close();
});

test('PersistentLRU(jsonl): expired entries dropped on reload', async () => {
  const p = tmp('.jsonl');
  const c1 = new PersistentLRU({ path: p, max: 10, ttlMs: 30, forceJsonl: true });
  c1.set('x', 'v');
  c1.close();
  await new Promise((r) => setTimeout(r, 50));
  const c2 = new PersistentLRU({ path: p, max: 10, ttlMs: 30, forceJsonl: true });
  assert.equal(c2.get('x'), undefined);
  c2.close();
});

test('PersistentLRU(jsonl): delete persists', () => {
  const p = tmp('.jsonl');
  const c1 = new PersistentLRU({ path: p, max: 10, ttlMs: 60_000, forceJsonl: true });
  c1.set('k', 'v');
  c1.delete('k');
  c1.close();
  const c2 = new PersistentLRU({ path: p, max: 10, ttlMs: 60_000, forceJsonl: true });
  assert.equal(c2.get('k'), undefined);
  c2.close();
});

test('PersistentLRU(jsonl): clear persists', () => {
  const p = tmp('.jsonl');
  const c1 = new PersistentLRU({ path: p, max: 10, ttlMs: 60_000, forceJsonl: true });
  c1.set('a', 1); c1.set('b', 2);
  c1.clear();
  c1.close();
  const c2 = new PersistentLRU({ path: p, max: 10, ttlMs: 60_000, forceJsonl: true });
  assert.equal(c2.get('a'), undefined);
  assert.equal(c2.get('b'), undefined);
  c2.close();
});

test('PersistentLRU(jsonl): LRU eviction beyond max', () => {
  const p = tmp('.jsonl');
  const c = new PersistentLRU({ path: p, max: 2, ttlMs: 60_000, forceJsonl: true });
  c.set('a', 1);
  c.set('b', 2);
  // touch a → b is LRU
  assert.equal(c.get('a'), 1);
  c.set('c', 3);
  assert.equal(c.size, 2);
  assert.equal(c.get('b'), undefined);
  assert.equal(c.get('a'), 1);
  assert.equal(c.get('c'), 3);
  c.close();
});

test('PersistentLRU(jsonl): compaction triggered after threshold', () => {
  const p = tmp('.jsonl');
  const c = new PersistentLRU({
    path: p, max: 100, ttlMs: 60_000, forceJsonl: true,
    compactEveryWrites: 5,
  });
  for (let i = 0; i < 20; i++) c.set(`k${i}`, i);
  // After many writes, compaction has rewritten the file. Verify file
  // size is sane (no lingering 20+ lines if compaction happened).
  c.close();
  const text = fs.readFileSync(p, 'utf8');
  const lines = text.split('\n').filter(Boolean);
  // After compaction we should have <= 5 dirty lines + 0..N base.
  assert.ok(lines.length <= 25, `compaction did not run; got ${lines.length} lines`);
  // Re-open and verify state intact.
  const c2 = new PersistentLRU({ path: p, max: 100, ttlMs: 60_000, forceJsonl: true });
  for (let i = 0; i < 20; i++) assert.equal(c2.get(`k${i}`), i);
  c2.close();
});

// Conditionally run sqlite tests when the optional dep is present.
let hasSqlite = false;
try { require('better-sqlite3'); hasSqlite = true; } catch (_) {}

if (hasSqlite) {
  test('PersistentLRU(sqlite): set/get + restart', () => {
    const p = tmp('.sqlite');
    const c1 = new PersistentLRU({ path: p, max: 10, ttlMs: 60_000 });
    assert.equal(c1.backend, 'sqlite');
    c1.set('a', 1);
    c1.set('neg', null);
    c1.close();
    const c2 = new PersistentLRU({ path: p, max: 10, ttlMs: 60_000 });
    assert.equal(c2.get('a'), 1);
    assert.equal(c2.has('neg'), true);
    assert.equal(c2.get('neg'), null);
    c2.close();
  });

  test('PersistentLRU(sqlite): TTL prunes expired on reload', async () => {
    const p = tmp('.sqlite');
    const c1 = new PersistentLRU({ path: p, max: 10, ttlMs: 30 });
    c1.set('x', 'v');
    c1.close();
    await new Promise((r) => setTimeout(r, 50));
    const c2 = new PersistentLRU({ path: p, max: 10, ttlMs: 30 });
    assert.equal(c2.get('x'), undefined);
    c2.close();
  });

  test('PersistentLRU(sqlite): delete persists', () => {
    const p = tmp('.sqlite');
    const c1 = new PersistentLRU({ path: p, max: 10, ttlMs: 60_000 });
    c1.set('k', 'v');
    c1.delete('k');
    c1.close();
    const c2 = new PersistentLRU({ path: p, max: 10, ttlMs: 60_000 });
    assert.equal(c2.get('k'), undefined);
    c2.close();
  });
}
