'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { HostBreaker, INITIAL_COOLDOWN_MS, MAX_COOLDOWN_MS } = require('../src/circuit');

function fakeClock(start = 1_000_000) {
  let t = start;
  return {
    now: () => t,
    advance: (ms) => { t += ms; },
  };
}

const HOSTS = [
  { host: 'a.example', port: 50002 },
  { host: 'b.example', port: 50002 },
  { host: 'c.example', port: 50002 },
];

test('HostBreaker: round-robins healthy hosts', () => {
  const cb = new HostBreaker(HOSTS, { now: () => 1 });
  const seen = new Set();
  for (let i = 0; i < HOSTS.length; i++) {
    const { host } = cb.pickNext();
    seen.add(host.host);
  }
  assert.equal(seen.size, 3);
});

test('HostBreaker: failure opens circuit, second pick skips host', () => {
  const clk = fakeClock();
  const cb = new HostBreaker(HOSTS, { now: clk.now });
  const a = cb.pickNext();
  cb.recordFailure(a.index);
  // Next picks should skip the open host until cooldown.
  for (let i = 0; i < 10; i++) {
    const p = cb.pickNext();
    assert.notEqual(p.host.host, HOSTS[a.index].host);
  }
});

test('HostBreaker: open host goes half-open after cooldown, single probe', () => {
  const clk = fakeClock();
  const cb = new HostBreaker(HOSTS, { now: clk.now });

  // Fail host index 0
  const a = cb.pickNext();
  assert.equal(a.index, 0);
  cb.recordFailure(0);

  clk.advance(INITIAL_COOLDOWN_MS);

  // Advance past cooldown. Now host 0 should be half-open and pick-able.
  // Force the cursor past the others by failing them too:
  cb.recordFailure(1);
  cb.recordFailure(2);

  const p1 = cb.pickNext(); // should pick a half-open host
  assert.equal(p1.allOpen, false); // half-open is not "all open"
  // Second pick: half-open in flight, so all are open => allOpen=true
  const p2 = cb.pickNext();
  assert.equal(p2.allOpen, true);
});

test('HostBreaker: success on half-open closes the circuit', () => {
  const clk = fakeClock();
  const cb = new HostBreaker(HOSTS, { now: clk.now });
  cb.recordFailure(0);
  clk.advance(INITIAL_COOLDOWN_MS);
  cb.recordFailure(1); // force the picker past 1 too
  cb.recordFailure(2);
  const p = cb.pickNext();
  cb.recordSuccess(p.index);
  const snap = cb.snapshot();
  assert.equal(snap[p.index].state, 'closed');
  assert.equal(snap[p.index].failures, 0);
  assert.equal(snap[p.index].cooldownMs, INITIAL_COOLDOWN_MS);
});

test('HostBreaker: failure on half-open re-opens with exponential backoff', () => {
  const clk = fakeClock();
  const cb = new HostBreaker(HOSTS, { now: clk.now });

  cb.recordFailure(0);
  let snap = cb.snapshot();
  assert.equal(snap[0].cooldownMs, INITIAL_COOLDOWN_MS);

  // First reprobe: cooldown elapses, half-open, fail it
  clk.advance(INITIAL_COOLDOWN_MS);
  // Force the cursor: fail b and c too
  cb.recordFailure(1); cb.recordFailure(2);
  let p = cb.pickNext();
  cb.recordFailure(p.index); // half-open -> open; cooldown doubles
  snap = cb.snapshot();
  assert.equal(snap[p.index].cooldownMs, INITIAL_COOLDOWN_MS * 2);

  // Doubling continues
  for (let i = 0; i < 10; i++) {
    clk.advance(snap[p.index].cooldownMs + 1);
    const p2 = cb.pickNext();
    if (p2.index === p.index) cb.recordFailure(p2.index);
    snap = cb.snapshot();
  }
  // Capped at MAX_COOLDOWN_MS
  assert.ok(snap[p.index].cooldownMs <= MAX_COOLDOWN_MS);
  assert.ok(snap[p.index].cooldownMs >= INITIAL_COOLDOWN_MS * 2);
});

test('HostBreaker: when all open, still returns a host with allOpen=true', () => {
  const cb = new HostBreaker(HOSTS, { now: () => 1 });
  cb.recordFailure(0);
  cb.recordFailure(1);
  cb.recordFailure(2);
  const p = cb.pickNext();
  assert.equal(p.allOpen, true);
  assert.ok(['a.example', 'b.example', 'c.example'].includes(p.host.host));
});

test('HostBreaker: throws on empty host list', () => {
  assert.throws(() => new HostBreaker([]), /at least one host/);
  assert.throws(() => new HostBreaker(null), /at least one host/);
});
