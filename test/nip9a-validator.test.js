'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { validate, eventByteSize, Violations } = require('../src/nip9a-validator');
const { parseRulesEvent, NIP9A_KIND } = require('../src/nip9a-parser');

const OWNER  = '6cdebccabda1dfa058ab85352a79509b592b2bdfa0370325e28ec1cb4f18667d';
const ALICE  = '11'.repeat(32);
const BOB    = '22'.repeat(32);
const VIP    = '33'.repeat(32);

function rules(over = {}) {
  return parseRulesEvent({
    id: 'r'.repeat(64),
    pubkey: OWNER,
    kind: NIP9A_KIND,
    created_at: 1_700_000_000,
    sig: 's'.repeat(128),
    content: '',
    tags: over.tags || [
      ['d', 'relay-testls-bit'],
      ['a', `34550:${OWNER}:relay-testls-bit`],
      ['k', '1'],
      ['k', '0'],
      ['k', '7'],
      ['k', '3'],
      ['k', '10002'],
      ['p', VIP, 'allow'],
      ['p', BOB, 'deny'],
      ['max_event_size', '65536'],
    ],
  });
}

function ctx(over = {}) {
  return { author: ALICE, kind: 1, sizeBytes: 256, ...over };
}

describe('nip9a-validator: text-only baseline (deployment shape)', () => {
  it('accepts kind:1 from any author', () => {
    assert.equal(validate(rules(), ctx()), null);
  });

  it('rejects kind:1063 (file metadata) for non-VIP', () => {
    const v = validate(rules(), ctx({ kind: 1063 }));
    assert.ok(v);
    assert.equal(v.type, Violations.KIND_NOT_ALLOWED);
    assert.equal(v.kind, 1063);
  });

  it('rejects kind:20 (NIP-68 pictures) for non-VIP', () => {
    const v = validate(rules(), ctx({ kind: 20, author: VIP }));
    assert.equal(v.type, Violations.KIND_NOT_ALLOWED,
      'spec semantics: `allow` does NOT expand the kind whitelist');
  });

  it('rejects denied pubkey even on allowed kind', () => {
    const v = validate(rules(), ctx({ author: BOB }));
    assert.equal(v.type, Violations.AUTHOR_DENIED);
  });
});

describe('nip9a-validator: size and stale', () => {
  it('rejects oversize event', () => {
    const v = validate(rules(), ctx({ sizeBytes: 70_000 }));
    assert.equal(v.type, Violations.MAX_SIZE_EXCEEDED);
    assert.equal(v.maxBytes, 65536);
  });

  it('rejects events under stale ratchet', () => {
    const r = parseRulesEvent({
      id: 'r'.repeat(64), pubkey: OWNER, kind: NIP9A_KIND,
      created_at: 1_700_000_000, sig: 's'.repeat(128), content: '',
      tags: [['d','x'],['k','1'],['min_rules_created_at','1800000000']],
    });
    const v = validate(r, ctx());
    assert.equal(v.type, Violations.STALE_RULES);
  });
});

describe('nip9a-validator: quotas', () => {
  it('enforces per-author per-day quota when provided', () => {
    const r = parseRulesEvent({
      id: 'r'.repeat(64), pubkey: OWNER, kind: NIP9A_KIND,
      created_at: 1_700_000_000, sig: 's'.repeat(128), content: '',
      tags: [['d','x'],['k','1','','50']],
    });
    const v = validate(r, ctx({ postsTodayByKind: (k) => k === 1 ? 50 : 0 }));
    assert.equal(v.type, Violations.QUOTA_EXCEEDED);
    assert.equal(v.maxPerDay, 50);
  });

  it('skips quota when no counter provided', () => {
    const r = parseRulesEvent({
      id: 'r'.repeat(64), pubkey: OWNER, kind: NIP9A_KIND,
      created_at: 1_700_000_000, sig: 's'.repeat(128), content: '',
      tags: [['d','x'],['k','1','','50']],
    });
    assert.equal(validate(r, ctx()), null);
  });
});

describe('nip9a-validator: WoT gates', () => {
  it('allows when any gate passes', () => {
    const r = parseRulesEvent({
      id: 'r'.repeat(64), pubkey: OWNER, kind: NIP9A_KIND,
      created_at: 1_700_000_000, sig: 's'.repeat(128), content: '',
      tags: [['d','x'],['k','1'],['wot',OWNER,'2'],['wot',VIP,'1']],
    });
    let calls = 0;
    const result = validate(r, ctx({
      wotResolver: (author, root, depth) => { calls++; return root === VIP; },
    }));
    assert.equal(result, null);
    assert.ok(calls >= 1);
  });

  it('rejects when no gate passes', () => {
    const r = parseRulesEvent({
      id: 'r'.repeat(64), pubkey: OWNER, kind: NIP9A_KIND,
      created_at: 1_700_000_000, sig: 's'.repeat(128), content: '',
      tags: [['d','x'],['k','1'],['wot',OWNER,'2']],
    });
    const v = validate(r, ctx({ wotResolver: () => false }));
    assert.equal(v.type, Violations.WOT_GATE_FAILED);
  });

  it('VIP with allow bypasses WoT gate entirely', () => {
    const r = parseRulesEvent({
      id: 'r'.repeat(64), pubkey: OWNER, kind: NIP9A_KIND,
      created_at: 1_700_000_000, sig: 's'.repeat(128), content: '',
      tags: [['d','x'],['k','1'],['p',VIP,'allow'],['wot',OWNER,'2']],
    });
    const calls = [];
    const result = validate(r, ctx({
      author: VIP,
      wotResolver: (...a) => { calls.push(a); return false; },
    }));
    assert.equal(result, null);
    assert.equal(calls.length, 0, 'allow-listed author must not invoke wotResolver');
  });
});

describe('nip9a-validator: eventByteSize', () => {
  it('counts UTF-8 bytes of JSON-encoded event', () => {
    const ev = { kind: 1, content: 'hello', tags: [['t','x']] };
    const expected = Buffer.byteLength(JSON.stringify(ev), 'utf8');
    assert.equal(eventByteSize(ev), expected);
  });

  it('counts multibyte characters correctly', () => {
    const ev = { kind: 1, content: '日本語' };
    const expected = Buffer.byteLength(JSON.stringify(ev), 'utf8');
    assert.equal(eventByteSize(ev), expected);
  });
});
