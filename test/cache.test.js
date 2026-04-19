'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { LRUCache } = require('../src/cache');

test('LRUCache: set/get roundtrip', () => {
  const c = new LRUCache({ max: 3, ttlMs: 60_000 });
  c.set('a', 1); c.set('b', 2); c.set('c', 3);
  assert.equal(c.get('a'), 1);
  assert.equal(c.get('b'), 2);
  assert.equal(c.get('c'), 3);
  assert.equal(c.size, 3);
});

test('LRUCache: evicts least-recently-used', () => {
  const c = new LRUCache({ max: 2, ttlMs: 60_000 });
  c.set('a', 1);
  c.set('b', 2);
  // touch a so b becomes LRU
  assert.equal(c.get('a'), 1);
  c.set('c', 3);
  assert.equal(c.get('b'), undefined, 'b should have been evicted');
  assert.equal(c.get('a'), 1);
  assert.equal(c.get('c'), 3);
});

test('LRUCache: TTL expiration', async () => {
  const c = new LRUCache({ max: 10, ttlMs: 30 });
  c.set('x', 'v');
  assert.equal(c.get('x'), 'v');
  await new Promise((r) => setTimeout(r, 50));
  assert.equal(c.get('x'), undefined);
});

test('LRUCache: delete/clear', () => {
  const c = new LRUCache({ max: 10 });
  c.set('a', 1); c.set('b', 2);
  assert.equal(c.delete('a'), true);
  assert.equal(c.get('a'), undefined);
  c.clear();
  assert.equal(c.size, 0);
});

test('LRUCache: stores null/undefined safely', () => {
  const c = new LRUCache({ max: 10 });
  c.set('a', null);
  assert.equal(c.has('a'), true);
  assert.equal(c.get('a'), null);
});
