'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { NamecoinResolver } = require('../src/resolver');

const PK_ROOT  = 'a'.repeat(64);
const PK_ALICE = 'b'.repeat(64);
const PK_ID    = 'c'.repeat(64);

test('parseIdentifier: bare .bit', () => {
  assert.deepEqual(NamecoinResolver.parseIdentifier('testls.bit'),
    { namecoinName: 'd/testls', localPart: '_' });
});

test('parseIdentifier: user@domain.bit', () => {
  assert.deepEqual(NamecoinResolver.parseIdentifier('alice@testls.bit'),
    { namecoinName: 'd/testls', localPart: 'alice' });
});

test('parseIdentifier: _@domain.bit', () => {
  assert.deepEqual(NamecoinResolver.parseIdentifier('_@testls.bit'),
    { namecoinName: 'd/testls', localPart: '_' });
});

test('parseIdentifier: d/name direct', () => {
  assert.deepEqual(NamecoinResolver.parseIdentifier('d/example'),
    { namecoinName: 'd/example', localPart: '_' });
});

test('parseIdentifier: id/name direct', () => {
  assert.deepEqual(NamecoinResolver.parseIdentifier('id/alice'),
    { namecoinName: 'id/alice', localPart: '_' });
});

test('parseIdentifier: case insensitive', () => {
  assert.deepEqual(NamecoinResolver.parseIdentifier('Alice@TestLS.BIT'),
    { namecoinName: 'd/testls', localPart: 'alice' });
});

test('parseIdentifier: rejects regular nip05', () => {
  assert.equal(NamecoinResolver.parseIdentifier('alice@example.com'), null);
  assert.equal(NamecoinResolver.parseIdentifier('alice@example.io'), null);
  assert.equal(NamecoinResolver.parseIdentifier(''), null);
  assert.equal(NamecoinResolver.parseIdentifier(null), null);
});

test('parseIdentifier: rejects multi-level .bit (sub.example.bit)', () => {
  // Namecoin names do not support dotted subdomains on-chain
  assert.equal(NamecoinResolver.parseIdentifier('sub.example.bit'), null);
});

test('extractFromValue: simple domain form', () => {
  const json = JSON.stringify({ nostr: PK_ROOT });
  assert.deepEqual(
    NamecoinResolver.extractFromValue(json, '_', 'd/example'),
    { pubkey: PK_ROOT, relays: [] }
  );
});

test('extractFromValue: extended domain form with names+relays', () => {
  const json = JSON.stringify({
    nostr: {
      names: { _: PK_ROOT, alice: PK_ALICE },
      relays: { [PK_ALICE]: ['wss://relay.example.com', 'wss://nos.lol'] },
    },
  });
  assert.deepEqual(
    NamecoinResolver.extractFromValue(json, 'alice', 'd/example'),
    { pubkey: PK_ALICE, relays: ['wss://relay.example.com', 'wss://nos.lol'] }
  );
  assert.deepEqual(
    NamecoinResolver.extractFromValue(json, '_', 'd/example'),
    { pubkey: PK_ROOT, relays: [] }
  );
  assert.equal(
    NamecoinResolver.extractFromValue(json, 'nobody', 'd/example'),
    null
  );
});

test('extractFromValue: identity namespace simple', () => {
  const json = JSON.stringify({ nostr: PK_ID });
  assert.deepEqual(
    NamecoinResolver.extractFromValue(json, '_', 'id/alice'),
    { pubkey: PK_ID, relays: [] }
  );
});

test('extractFromValue: identity namespace object', () => {
  const json = JSON.stringify({ nostr: { pubkey: PK_ID, relays: ['wss://x'] } });
  assert.deepEqual(
    NamecoinResolver.extractFromValue(json, '_', 'id/alice'),
    { pubkey: PK_ID, relays: ['wss://x'] }
  );
});

// ─── Single-identity object form on d/ ──────────────────────────────────────
//
// ifa-0001 doesn't mandate that domain records use the `nostr.names`
// sub-dictionary. Operators who own a name outright commonly publish:
//
//   {"nostr": {"pubkey": "<hex>", "relays": ["wss://..."]}}
//
// (The same shape `id/` records use.) Resolve only the root local-part
// from this shape — there's no sub-identity dictionary, so a request for
// `alice@example.bit` against this shape correctly falls through to null.

test('extractFromValue: domain single-identity object form (d/mstrofnone)', () => {
  const json = JSON.stringify({
    nostr: {
      pubkey: PK_ROOT,
      relays: ['wss://relay.testls.bit/', 'wss://relay.nostr.wine/'],
    },
  });
  assert.deepEqual(
    NamecoinResolver.extractFromValue(json, '_', 'd/mstrofnone'),
    { pubkey: PK_ROOT, relays: ['wss://relay.testls.bit/', 'wss://relay.nostr.wine/'] }
  );
});

test('extractFromValue: domain single-identity form does NOT resolve non-root', () => {
  const json = JSON.stringify({ nostr: { pubkey: PK_ROOT } });
  assert.equal(
    NamecoinResolver.extractFromValue(json, 'alice', 'd/mstrofnone'),
    null
  );
});

test('extractFromValue: domain single-identity form without relays still works', () => {
  const json = JSON.stringify({ nostr: { pubkey: PK_ROOT } });
  assert.deepEqual(
    NamecoinResolver.extractFromValue(json, '_', 'd/mstrofnone'),
    { pubkey: PK_ROOT, relays: [] }
  );
});

test('extractFromValue: domain single-identity form rejects malformed pubkey', () => {
  const json = JSON.stringify({ nostr: { pubkey: 'not-a-hex-pubkey' } });
  assert.equal(
    NamecoinResolver.extractFromValue(json, '_', 'd/x'),
    null
  );
});

test('extractFromValue: hybrid record — names dict wins for sub-identities, falls back to bare pubkey for root', () => {
  // Publisher mistake or migration: a record with both `names` and a bare
  // `pubkey`. Named sub-identities resolve through the names dict, which
  // is more specific. Root falls back to the bare `pubkey` if names has
  // no `_` entry. Importantly, a non-root lookup that misses the names
  // dict must NOT silently return the root pubkey — that would hand
  // alice@example.bit the root operator's identity.
  const json = JSON.stringify({
    nostr: {
      pubkey: PK_ROOT,
      names: { alice: PK_ALICE },
    },
  });
  // alice resolves through the names dict.
  assert.deepEqual(
    NamecoinResolver.extractFromValue(json, 'alice', 'd/example'),
    { pubkey: PK_ALICE, relays: [] }
  );
  // Non-existent named lookup must NOT silently fall back to bare pubkey.
  assert.equal(
    NamecoinResolver.extractFromValue(json, 'nobody', 'd/example'),
    null
  );
  // Root falls back to the bare `pubkey` since names has no `_` entry.
  assert.deepEqual(
    NamecoinResolver.extractFromValue(json, '_', 'd/example'),
    { pubkey: PK_ROOT, relays: [] }
  );
});

test('extractFromValue: hybrid record with explicit names["_"] beats bare pubkey', () => {
  const json = JSON.stringify({
    nostr: {
      pubkey: PK_ALICE, // would be the fallback
      names: { _: PK_ROOT },
    },
  });
  assert.deepEqual(
    NamecoinResolver.extractFromValue(json, '_', 'd/example'),
    { pubkey: PK_ROOT, relays: [] }
  );
});

test('extractFromValue: rejects non-hex', () => {
  assert.equal(
    NamecoinResolver.extractFromValue(JSON.stringify({ nostr: 'notahexstring' }), '_', 'd/x'),
    null
  );
});

test('extractFromValue: rejects missing nostr key', () => {
  assert.equal(
    NamecoinResolver.extractFromValue(JSON.stringify({ foo: 'bar' }), '_', 'd/x'),
    null
  );
});

test('extractFromValue: rejects malformed JSON', () => {
  assert.equal(NamecoinResolver.extractFromValue('not json', '_', 'd/x'), null);
  assert.equal(NamecoinResolver.extractFromValue('', '_', 'd/x'), null);
});

// ─── resolve() with stubbed ElectrumX client ──────────────────────────────

function stubClient(responses) {
  return {
    calls: [],
    async nameShow(name) {
      this.calls.push(name);
      if (!(name in responses)) return null;
      const v = responses[name];
      if (v instanceof Error) throw v;
      return v;
    },
  };
}

test('resolve: happy path, caches result', async () => {
  const client = stubClient({
    'd/testls': { name: 'd/testls', value: JSON.stringify({ nostr: { names: { _: PK_ROOT } } }) },
  });
  const r = new NamecoinResolver({ client, cacheTtlMs: 10_000 });

  const first = await r.resolve('testls.bit');
  assert.deepEqual(first, { pubkey: PK_ROOT, relays: [] });
  assert.equal(client.calls.length, 1);

  const second = await r.resolve('testls.bit');
  assert.deepEqual(second, { pubkey: PK_ROOT, relays: [] });
  assert.equal(client.calls.length, 1, 'should be cached');
});

test('resolve: unknown name returns null (and caches)', async () => {
  const client = stubClient({}); // every name → null
  const r = new NamecoinResolver({ client });
  assert.equal(await r.resolve('nosuchname.bit'), null);
  assert.equal(await r.resolve('nosuchname.bit'), null);
  assert.equal(client.calls.length, 1, 'negative results are cached');
});

test('resolve: non-namecoin identifier returns null without calling client', async () => {
  const client = stubClient({});
  const r = new NamecoinResolver({ client });
  assert.equal(await r.resolve('alice@example.com'), null);
  assert.equal(client.calls.length, 0);
});

test('resolve: errors are not cached', async () => {
  let nCalls = 0;
  const err = new Error('boom');
  const client = {
    async nameShow() { nCalls++; throw err; },
  };
  const r = new NamecoinResolver({ client });
  assert.equal(await r.resolve('testls.bit'), null);
  assert.equal(await r.resolve('testls.bit'), null);
  assert.equal(nCalls, 2, 'errors must not be cached (allow retry)');
});
