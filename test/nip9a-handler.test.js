'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { makeHandler } = require('../src/index');
const { LRUCache } = require('../src/cache');
const { Nip9aLoader } = require('../src/nip9a-loader');
const { NIP9A_KIND } = require('../src/nip9a-parser');

// All hex pubkeys are 64-char lowercase.
const PK_AUTHOR   = '6cdebccabda1dfa058ab85352a79509b592b2bdfa0370325e28ec1cb4f18667d';
const PK_VIP      = '43185edecb675892824b1a37a57f3e407fbde2eda7201a3829b8cf4ba7c5b4f0';
const PK_RANDOM   = '11'.repeat(32);
const OWNER       = PK_VIP; // same key signs community + rules in our example
const COMMUNITY   = `34550:${OWNER}:relay-testls-bit`;

const quietLogger = () => {};

function makeResolverStub(table) {
  return {
    async resolve(identifier) {
      const k = identifier.toLowerCase();
      return k in table ? table[k] : null;
    },
  };
}

function newEvent(over = {}) {
  return {
    type: 'new',
    event: {
      id: over.id || 'e'.repeat(64),
      kind: over.kind ?? 1,
      pubkey: over.pubkey || PK_AUTHOR,
      content: over.content || '',
      tags: over.tags || [],
      created_at: over.created_at || 1,
      sig: '00',
    },
  };
}

function baseConfig(over = {}) {
  return {
    host: 'electrumx.example',
    port: 50002,
    tls: true,
    certPinSha256: null,
    timeoutMs: 5000,
    retries: 2,
    mode: 'all-kinds-require-bit',  // realistic deployment shape
    cacheTtlMs: 300_000,
    logLevel: 'silent',
    allowNonBit: false,
    nip9aRulesFile: null,
    nip9aCommunity: COMMUNITY,
    nip9aRequireRules: false,
    nip9aRejectImetaKind1: false,
    ...over,
  };
}

function loaderWithRules(rules) {
  const l = new Nip9aLoader({ community: COMMUNITY, logger: quietLogger });
  l.offer({
    id: 'r'.repeat(64),
    pubkey: OWNER,
    kind: NIP9A_KIND,
    created_at: 1_700_000_000,
    content: '',
    sig: 's'.repeat(128),
    tags: rules,
  });
  return l;
}

describe('handler + nip9a: text-only baseline', () => {
  it('accepts kind:1 from a verified .bit author', async () => {
    const verified = new LRUCache({ max: 10 });
    verified.set(PK_AUTHOR, true);
    const nip9a = loaderWithRules([
      ['d', 'relay-testls-bit'],
      ['a', COMMUNITY],
      ['k', '1'],
      ['k', '0'],
      ['k', '7'],
      ['max_event_size', '65536'],
    ]);

    const handle = makeHandler({
      config: baseConfig(),
      resolver: makeResolverStub({}),
      verifiedAuthors: verified,
      logger: quietLogger,
      nip9a,
    });

    const res = await handle(newEvent({ kind: 1, content: 'hello world' }));
    assert.equal(res.action, 'accept');
  });

  it('rejects kind:1063 (file metadata) from non-whitelisted author', async () => {
    const verified = new LRUCache({ max: 10 });
    verified.set(PK_AUTHOR, true);
    const nip9a = loaderWithRules([
      ['d', 'relay-testls-bit'], ['a', COMMUNITY],
      ['k', '1'], ['k', '7'],
    ]);

    const handle = makeHandler({
      config: baseConfig(),
      resolver: makeResolverStub({}),
      verifiedAuthors: verified,
      logger: quietLogger,
      nip9a,
    });

    const res = await handle(newEvent({ kind: 1063 }));
    assert.equal(res.action, 'reject');
    assert.match(res.msg, /kind 1063 is not allowed/);
  });

  it('rejects denied pubkey even if kind is allowed', async () => {
    const verified = new LRUCache({ max: 10 });
    verified.set(PK_AUTHOR, true);
    const nip9a = loaderWithRules([
      ['d', 'relay-testls-bit'], ['a', COMMUNITY],
      ['k', '1'],
      ['p', PK_AUTHOR, 'deny'],
    ]);

    const handle = makeHandler({
      config: baseConfig(),
      resolver: makeResolverStub({}),
      verifiedAuthors: verified,
      logger: quietLogger,
      nip9a,
    });

    const res = await handle(newEvent({ kind: 1 }));
    assert.equal(res.action, 'reject');
    assert.match(res.msg, /deny-list/);
  });

  it('rejects unverified .bit author before checking NIP-9A rules', async () => {
    // verifiedAuthors empty -> author gate trips first.
    const handle = makeHandler({
      config: baseConfig(),
      resolver: makeResolverStub({}),
      verifiedAuthors: new LRUCache({ max: 10 }),
      logger: quietLogger,
      nip9a: loaderWithRules([['d','relay-testls-bit'],['a',COMMUNITY],['k','1']]),
    });
    const res = await handle(newEvent({ kind: 1 }));
    assert.equal(res.action, 'reject');
    assert.match(res.msg, /verified Namecoin \.bit NIP-05/);
  });

  it('passes through when no rules in force and require=false', async () => {
    const verified = new LRUCache({ max: 10 });
    verified.set(PK_AUTHOR, true);
    const handle = makeHandler({
      config: baseConfig(),
      resolver: makeResolverStub({}),
      verifiedAuthors: verified,
      logger: quietLogger,
      nip9a: new Nip9aLoader({ community: COMMUNITY }), // empty
    });
    const res = await handle(newEvent({ kind: 1063 }));
    assert.equal(res.action, 'accept');
  });

  it('rejects everything when require_rules=true but loader is empty', async () => {
    const verified = new LRUCache({ max: 10 });
    verified.set(PK_AUTHOR, true);
    const handle = makeHandler({
      config: baseConfig({ nip9aRequireRules: true }),
      resolver: makeResolverStub({}),
      verifiedAuthors: verified,
      logger: quietLogger,
      nip9a: new Nip9aLoader({ community: COMMUNITY }),
    });
    const res = await handle(newEvent({ kind: 1 }));
    assert.equal(res.action, 'reject');
    assert.match(res.msg, /no NIP-9A rules document in force/);
  });

  it('absorbs incoming kind:34551 events into the loader', async () => {
    const verified = new LRUCache({ max: 10 });
    verified.set(OWNER, true);
    const loader = new Nip9aLoader({ community: COMMUNITY });
    const handle = makeHandler({
      config: baseConfig(),
      resolver: makeResolverStub({}),
      verifiedAuthors: verified,
      logger: quietLogger,
      nip9a: loader,
    });
    // Use the OWNER pubkey for the inbound event (community owner publishing
    // their own rules). The handler treats this as a non-kind-0 event after
    // the .bit gate; since allowNonBit=false we cannot rely on kind:0 to
    // verify the author. Pre-warm verifiedAuthors instead.
    const ev = {
      type: 'new',
      event: {
        id: 'r'.repeat(64),
        pubkey: OWNER,
        kind: NIP9A_KIND,
        created_at: 1_700_000_000,
        tags: [['d','relay-testls-bit'],['a',COMMUNITY],['k','1']],
        content: '',
        sig: 's'.repeat(128),
      },
    };
    const res = await handle(ev);
    assert.equal(res.action, 'accept');
    assert.ok(loader.hasActive(), 'loader should have absorbed the rules event');
  });
});

describe('handler + nip9a: imeta defence-in-depth', () => {
  it('rejects kind:1 with imeta from non-whitelisted author when toggle is on', async () => {
    const verified = new LRUCache({ max: 10 });
    verified.set(PK_AUTHOR, true);
    const handle = makeHandler({
      config: baseConfig({ nip9aRejectImetaKind1: true }),
      resolver: makeResolverStub({}),
      verifiedAuthors: verified,
      logger: quietLogger,
      nip9a: loaderWithRules([['d','relay-testls-bit'],['a',COMMUNITY],['k','1']]),
    });
    const res = await handle(newEvent({
      kind: 1,
      tags: [['imeta', 'url https://blossom.example/abc.png', 'm image/png']],
    }));
    assert.equal(res.action, 'reject');
    assert.match(res.msg, /imeta media tags requires whitelist/);
  });

  it('allows kind:1 with imeta from `p allow` whitelisted author', async () => {
    const verified = new LRUCache({ max: 10 });
    verified.set(PK_VIP, true);
    const handle = makeHandler({
      config: baseConfig({ nip9aRejectImetaKind1: true }),
      resolver: makeResolverStub({}),
      verifiedAuthors: verified,
      logger: quietLogger,
      nip9a: loaderWithRules([
        ['d','relay-testls-bit'], ['a',COMMUNITY],
        ['k','1'],
        ['p', PK_VIP, 'allow', 'uploader'],
      ]),
    });
    const res = await handle(newEvent({
      pubkey: PK_VIP,
      kind: 1,
      tags: [['imeta','url https://blossom.example/abc.png']],
    }));
    assert.equal(res.action, 'accept');
  });

  it('allows kind:1 without imeta even when toggle is on', async () => {
    const verified = new LRUCache({ max: 10 });
    verified.set(PK_AUTHOR, true);
    const handle = makeHandler({
      config: baseConfig({ nip9aRejectImetaKind1: true }),
      resolver: makeResolverStub({}),
      verifiedAuthors: verified,
      logger: quietLogger,
      nip9a: loaderWithRules([['d','relay-testls-bit'],['a',COMMUNITY],['k','1']]),
    });
    const res = await handle(newEvent({ kind: 1, content: 'plain text' }));
    assert.equal(res.action, 'accept');
  });
});
