'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { TokenBucket } = require('../src/ratelimit');

test('TokenBucket: starts full; consumes burst then blocks', async () => {
  let now = 1000;
  const tb = new TokenBucket({ rps: 1, burst: 3, queueMs: 0, now: () => now });
  assert.equal(tb.tryAcquire(), true);
  assert.equal(tb.tryAcquire(), true);
  assert.equal(tb.tryAcquire(), true);
  assert.equal(tb.tryAcquire(), false, 'fourth call exceeds burst');
});

test('TokenBucket: refills over time at configured rps', async () => {
  let now = 0;
  const tb = new TokenBucket({ rps: 10, burst: 1, queueMs: 0, now: () => now });
  assert.equal(tb.tryAcquire(), true);
  assert.equal(tb.tryAcquire(), false);
  // 100ms = 1 token at 10 rps
  now += 100;
  assert.equal(tb.tryAcquire(), true);
  // Spend more than full \u2192 cap at burst
  now += 10_000;
  assert.equal(tb.tryAcquire(), true);
  assert.equal(tb.tryAcquire(), false, 'capped at burst=1');
});

test('TokenBucket: acquire() returns false after queueMs expires', async () => {
  const tb = new TokenBucket({ rps: 1, burst: 1, queueMs: 50 });
  assert.equal(await tb.acquire(), true);   // burst
  const t0 = Date.now();
  const ok = await tb.acquire();             // empty bucket, queue 50ms
  const dt = Date.now() - t0;
  assert.equal(ok, false, 'expected timeout');
  assert.ok(dt >= 40, `should have waited at least ~queueMs (got ${dt}ms)`);
});

test('TokenBucket: acquire() succeeds when refill arrives within queueMs', async () => {
  // 50 rps means a token every 20ms. queueMs=200 should be plenty.
  const tb = new TokenBucket({ rps: 50, burst: 1, queueMs: 200 });
  assert.equal(await tb.acquire(), true);   // burst
  const ok = await tb.acquire();             // wait for refill
  assert.equal(ok, true);
});

test('TokenBucket: rejects pathological config', () => {
  assert.throws(() => new TokenBucket({ rps: 0, burst: 1 }), /rps/);
  assert.throws(() => new TokenBucket({ rps: 1, burst: 0 }), /burst/);
  assert.throws(() => new TokenBucket({ rps: 1, burst: 1, queueMs: -1 }), /queueMs/);
});
