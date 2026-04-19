'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { makeHandler } = require('../src/index');
const { LRUCache } = require('../src/cache');

const PK_MATCH    = 'a'.repeat(64);
const PK_MISMATCH = 'b'.repeat(64);
const PK_UNKNOWN  = 'c'.repeat(64);

const quietLogger = () => {};

function makeResolverStub(table) {
  // table: identifier(lc) -> {pubkey, relays}  OR null
  return {
    async resolve(identifier) {
      const k = identifier.toLowerCase();
      if (!(k in table)) return null;
      return table[k];
    },
  };
}

function newEvent({ id = 'e'.repeat(64), kind = 0, pubkey = PK_MATCH, content = '' }) {
  return { type: 'new', event: { id, kind, pubkey, content, tags: [], created_at: 1, sig: '00' } };
}

function baseConfig(overrides = {}) {
  return {
    host: 'electrumx.example',
    port: 50002,
    tls: true,
    certPinSha256: null,
    timeoutMs: 5000,
    retries: 2,
    mode: 'kind0-only',
    cacheTtlMs: 300_000,
    logLevel: 'silent',
    allowNonBit: true,
    ...overrides,
  };
}

test('handler: kind0 with matching .bit NIP-05 → accept', async () => {
  const resolver = makeResolverStub({
    'alice@testls.bit': { pubkey: PK_MATCH, relays: [] },
  });
  const handle = makeHandler({
    config: baseConfig(),
    resolver,
    verifiedAuthors: new LRUCache({ max: 10 }),
    logger: quietLogger,
  });
  const res = await handle(newEvent({
    content: JSON.stringify({ name: 'alice', nip05: 'alice@testls.bit' }),
  }));
  assert.deepEqual({ id: res.id, action: res.action }, { id: 'e'.repeat(64), action: 'accept' });
});

test('handler: kind0 with mismatched .bit NIP-05 → reject', async () => {
  const resolver = makeResolverStub({
    'alice@testls.bit': { pubkey: PK_MISMATCH, relays: [] },
  });
  const handle = makeHandler({
    config: baseConfig(),
    resolver,
    verifiedAuthors: new LRUCache({ max: 10 }),
    logger: quietLogger,
  });
  const res = await handle(newEvent({
    content: JSON.stringify({ nip05: 'alice@testls.bit' }),
  }));
  assert.equal(res.action, 'reject');
  assert.match(res.msg, /invalid: Namecoin NIP-05/);
});

test('handler: kind0 with .bit that cannot be resolved → reject', async () => {
  const resolver = makeResolverStub({}); // everything resolves to null
  const handle = makeHandler({
    config: baseConfig(),
    resolver,
    verifiedAuthors: new LRUCache({ max: 10 }),
    logger: quietLogger,
  });
  const res = await handle(newEvent({
    content: JSON.stringify({ nip05: 'ghost@nonexistent.bit' }),
  }));
  assert.equal(res.action, 'reject');
  assert.match(res.msg, /could not be resolved/);
});

test('handler: kind0 with non-.bit NIP-05 passes through by default', async () => {
  const resolver = makeResolverStub({});
  const handle = makeHandler({
    config: baseConfig(),
    resolver,
    verifiedAuthors: new LRUCache({ max: 10 }),
    logger: quietLogger,
  });
  const res = await handle(newEvent({
    content: JSON.stringify({ nip05: 'alice@example.com' }),
  }));
  assert.equal(res.action, 'accept');
});

test('handler: kind0 with non-.bit NIP-05 rejected when allowNonBit=false', async () => {
  const resolver = makeResolverStub({});
  const handle = makeHandler({
    config: baseConfig({ allowNonBit: false }),
    resolver,
    verifiedAuthors: new LRUCache({ max: 10 }),
    logger: quietLogger,
  });
  const res = await handle(newEvent({
    content: JSON.stringify({ nip05: 'alice@example.com' }),
  }));
  assert.equal(res.action, 'reject');
});

test('handler: kind0 with no nip05 field → accept', async () => {
  const handle = makeHandler({
    config: baseConfig(),
    resolver: makeResolverStub({}),
    verifiedAuthors: new LRUCache({ max: 10 }),
    logger: quietLogger,
  });
  const res = await handle(newEvent({ content: JSON.stringify({ name: 'nobody' }) }));
  assert.equal(res.action, 'accept');
});

test('handler: kind0 with malformed content → accept (permissive)', async () => {
  const handle = makeHandler({
    config: baseConfig(),
    resolver: makeResolverStub({}),
    verifiedAuthors: new LRUCache({ max: 10 }),
    logger: quietLogger,
  });
  const res = await handle(newEvent({ content: 'not json at all' }));
  assert.equal(res.action, 'accept');
});

test('handler: kind 1 accepted in kind0-only mode', async () => {
  const handle = makeHandler({
    config: baseConfig(),
    resolver: makeResolverStub({}),
    verifiedAuthors: new LRUCache({ max: 10 }),
    logger: quietLogger,
  });
  const res = await handle(newEvent({ kind: 1, content: 'hello' }));
  assert.equal(res.action, 'accept');
});

test('handler: all-kinds-require-bit — unverified author rejected', async () => {
  const handle = makeHandler({
    config: baseConfig({ mode: 'all-kinds-require-bit' }),
    resolver: makeResolverStub({}),
    verifiedAuthors: new LRUCache({ max: 10 }),
    logger: quietLogger,
  });
  const res = await handle(newEvent({ kind: 1, pubkey: PK_UNKNOWN, content: 'hi' }));
  assert.equal(res.action, 'reject');
  assert.match(res.msg, /requires a verified Namecoin/);
});

test('handler: all-kinds-require-bit — author verified via prior kind:0', async () => {
  const resolver = makeResolverStub({
    'alice@testls.bit': { pubkey: PK_MATCH, relays: [] },
  });
  const verifiedAuthors = new LRUCache({ max: 10 });
  const handle = makeHandler({
    config: baseConfig({ mode: 'all-kinds-require-bit' }),
    resolver,
    verifiedAuthors,
    logger: quietLogger,
  });

  // First: a matching kind:0 to prime the cache
  const r1 = await handle(newEvent({ content: JSON.stringify({ nip05: 'alice@testls.bit' }) }));
  assert.equal(r1.action, 'accept');

  // Then: a kind:1 from same pubkey — should pass
  const r2 = await handle(newEvent({ kind: 1, pubkey: PK_MATCH, content: 'hello' }));
  assert.equal(r2.action, 'accept');

  // And a kind:1 from some other pubkey — still rejected
  const r3 = await handle(newEvent({ kind: 1, pubkey: PK_UNKNOWN, content: 'hello' }));
  assert.equal(r3.action, 'reject');
});

test('handler: non-new request type passes through', async () => {
  const handle = makeHandler({
    config: baseConfig(),
    resolver: makeResolverStub({}),
    verifiedAuthors: new LRUCache({ max: 10 }),
    logger: quietLogger,
  });
  const res = await handle({ type: 'something-else', event: { id: 'x'.repeat(64) } });
  assert.equal(res.action, 'accept');
});

test('handler: missing event → reject', async () => {
  const handle = makeHandler({
    config: baseConfig(),
    resolver: makeResolverStub({}),
    verifiedAuthors: new LRUCache({ max: 10 }),
    logger: quietLogger,
  });
  const res = await handle({ type: 'new' });
  assert.equal(res.action, 'reject');
});

test('handler: echoes event id on responses', async () => {
  const handle = makeHandler({
    config: baseConfig(),
    resolver: makeResolverStub({}),
    verifiedAuthors: new LRUCache({ max: 10 }),
    logger: quietLogger,
  });
  const res = await handle(newEvent({ id: 'f'.repeat(64), kind: 1, content: '' }));
  assert.equal(res.id, 'f'.repeat(64));
});
