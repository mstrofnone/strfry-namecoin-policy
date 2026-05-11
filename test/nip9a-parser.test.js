'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { parseRulesEvent, pickActiveRules, NIP9A_KIND } = require('../src/nip9a-parser');

const OWNER = '6cdebccabda1dfa058ab85352a79509b592b2bdfa0370325e28ec1cb4f18667d';

function makeRulesEvent(over = {}) {
  return {
    id: 'a'.repeat(64),
    pubkey: OWNER,
    created_at: 1_700_000_000,
    kind: NIP9A_KIND,
    tags: [
      ['d', 'relay-testls-bit'],
      ['a', `34550:${OWNER}:relay-testls-bit`],
      ['k', '1', '16384', '50'],
      ['k', '0'],
      ['p', '00'.repeat(32), 'allow', 'contributor'],
      ['p', 'ff'.repeat(32), 'deny'],
      ['max_event_size', '262144'],
    ],
    content: '',
    sig: 'b'.repeat(128),
    ...over,
  };
}

describe('nip9a-parser', () => {
  it('parses a well-formed rules event', () => {
    const r = parseRulesEvent(makeRulesEvent());
    assert.ok(r, 'expected parsed Rules object');
    assert.equal(r.dTag, 'relay-testls-bit');
    assert.equal(r.communityAddress, `34550:${OWNER}:relay-testls-bit`);
    assert.equal(r.kindRules.length, 2);
    assert.deepEqual(r.kindRules[0], { kind: 1, maxBytes: 16384, maxPerAuthorPerDay: 50 });
    assert.deepEqual(r.kindRules[1], { kind: 0, maxBytes: null, maxPerAuthorPerDay: null });
    assert.equal(r.pubkeyRules.length, 2);
    assert.equal(r.pubkeyRules[0].policy, 'allow');
    assert.equal(r.pubkeyRules[1].policy, 'deny');
    assert.equal(r.maxEventSize, 262144);
    assert.equal(r.minRulesCreatedAt, null);
  });

  it('rejects wrong kind', () => {
    const r = parseRulesEvent(makeRulesEvent({ kind: 1 }));
    assert.equal(r, null);
  });

  it('rejects missing d tag', () => {
    const ev = makeRulesEvent();
    ev.tags = ev.tags.filter((t) => t[0] !== 'd');
    assert.equal(parseRulesEvent(ev), null);
  });

  it('lowercases pubkey policy entries', () => {
    const upper = 'AB'.repeat(32);
    const ev = makeRulesEvent();
    ev.tags.push(['p', upper, 'allow']);
    const r = parseRulesEvent(ev);
    const found = r.pubkeyRules.find((p) => p.pubkey === upper.toLowerCase());
    assert.ok(found, 'expected lowercased pubkey rule');
  });

  it('ignores malformed pubkey rules (wrong length, bad policy)', () => {
    const ev = makeRulesEvent({ tags: [
      ['d', 'x'],
      ['p', 'tooshort', 'allow'],
      ['p', 'aa'.repeat(32), 'maybe'],   // bad policy
    ] });
    const r = parseRulesEvent(ev);
    assert.equal(r.pubkeyRules.length, 0);
  });

  it('honours min_rules_created_at ratchet', () => {
    const r = parseRulesEvent(makeRulesEvent({
      tags: [['d', 'x'], ['k', '1'], ['min_rules_created_at', '1746604800']],
    }));
    assert.equal(r.minRulesCreatedAt, 1_746_604_800);
  });

  it('rejects non-34550 a tags (NIP-29 h binding not parsed yet)', () => {
    const r = parseRulesEvent(makeRulesEvent({ tags: [
      ['d', 'x'],
      ['a', '34550:wrong:x'],
      ['a', '34551:x:x'],
    ] }));
    // First valid 34550: prefix wins; 34551 is ignored.
    assert.equal(r.communityAddress, '34550:wrong:x');
  });
});

describe('nip9a-parser: pickActiveRules', () => {
  function r(createdAt, opts = {}) {
    return parseRulesEvent(makeRulesEvent({
      id: ('a'.repeat(63)) + (createdAt % 10).toString(),
      created_at: createdAt,
      tags: [
        ['d', 'x'],
        ['k', '1'],
        ...(opts.ratchet ? [['min_rules_created_at', String(opts.ratchet)]] : []),
      ],
    }));
  }

  it('returns null on empty', () => {
    assert.equal(pickActiveRules([]), null);
  });

  it('returns the latest by createdAt', () => {
    const a = r(1_000), b = r(2_000), c = r(1_500);
    assert.equal(pickActiveRules([a, b, c]).createdAt, 2_000);
  });

  it('honours the highest ratchet across the candidate set', () => {
    // Old (no ratchet), then new with ratchet=1500. An attacker replays
    // the old; the new is preserved -> picker rejects the old.
    const old = r(1_000);
    const recent = r(2_000, { ratchet: 1_500 });
    const replay = r(1_200);
    const picked = pickActiveRules([old, recent, replay]);
    assert.equal(picked.createdAt, 2_000);
  });

  it('drops the only candidate when it falls below its own ratchet', () => {
    // Defensive: ratchet > own createdAt is invalid signing but should not crash.
    const bad = r(1_000, { ratchet: 5_000 });
    assert.equal(pickActiveRules([bad]), null);
  });
});
