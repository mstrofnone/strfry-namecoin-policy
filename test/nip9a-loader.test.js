'use strict';

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { Nip9aLoader } = require('../src/nip9a-loader');
const { NIP9A_KIND } = require('../src/nip9a-parser');

const OWNER = '6cdebccabda1dfa058ab85352a79509b592b2bdfa0370325e28ec1cb4f18667d';
const OTHER = 'ff'.repeat(32);

function rulesEvent(opts = {}) {
  return {
    id: opts.id || 'a'.repeat(64),
    pubkey: opts.pubkey || OWNER,
    created_at: opts.createdAt || 1_700_000_000,
    kind: NIP9A_KIND,
    tags: opts.tags || [
      ['d', 'relay-testls-bit'],
      ['a', `34550:${OWNER}:relay-testls-bit`],
      ['k', '1'],
      ['max_event_size', '65536'],
    ],
    content: '',
    sig: 's'.repeat(128),
  };
}

let tmpdir;
beforeEach(() => { tmpdir = fs.mkdtempSync(path.join(os.tmpdir(), 'nip9a-loader-')); });
afterEach(() => { fs.rmSync(tmpdir, { recursive: true, force: true }); });

describe('Nip9aLoader: stream offers', () => {
  it('accepts the first valid rules event', () => {
    const l = new Nip9aLoader({});
    assert.equal(l.offer(rulesEvent()), true);
    assert.ok(l.hasActive());
    assert.equal(l.active().dTag, 'relay-testls-bit');
  });

  it('replaces with a newer createdAt', () => {
    const l = new Nip9aLoader({});
    l.offer(rulesEvent({ createdAt: 1_000 }));
    l.offer(rulesEvent({ id: 'b'.repeat(64), createdAt: 2_000 }));
    assert.equal(l.active().createdAt, 2_000);
  });

  it('ignores older events', () => {
    const l = new Nip9aLoader({});
    l.offer(rulesEvent({ createdAt: 2_000 }));
    l.offer(rulesEvent({ id: 'b'.repeat(64), createdAt: 1_000 }));
    assert.equal(l.active().createdAt, 2_000);
  });

  it('rejects events from the wrong owner when community is set', () => {
    const l = new Nip9aLoader({ community: `34550:${OWNER}:relay-testls-bit` });
    assert.equal(l.offer(rulesEvent({ pubkey: OTHER })), false);
    assert.equal(l.hasActive(), false);
    assert.equal(l.offer(rulesEvent()), true);
    assert.ok(l.hasActive());
  });

  it('rejects malformed events', () => {
    const l = new Nip9aLoader({});
    assert.equal(l.offer({ kind: NIP9A_KIND }), false);
    assert.equal(l.offer({ kind: 1, tags: [] }), false);
    assert.equal(l.hasActive(), false);
  });

  it('rejects wrong d-tag when community pins one', () => {
    const l = new Nip9aLoader({ community: `34550:${OWNER}:relay-testls-bit` });
    assert.equal(l.offer(rulesEvent({ tags: [
      ['d', 'wrong-d'],
      ['a', `34550:${OWNER}:wrong-d`],
      ['k', '1'],
    ] })), false);
  });
});

describe('Nip9aLoader: file source', () => {
  it('loads rules from a JSON file at start()', () => {
    const file = path.join(tmpdir, 'rules.json');
    fs.writeFileSync(file, JSON.stringify(rulesEvent()));
    const l = new Nip9aLoader({ filePath: file });
    l.start();
    try {
      assert.ok(l.hasActive());
      assert.equal(l.active().dTag, 'relay-testls-bit');
    } finally {
      l.stop();
    }
  });

  it('reload() picks up file changes', () => {
    const file = path.join(tmpdir, 'rules.json');
    fs.writeFileSync(file, JSON.stringify(rulesEvent({ createdAt: 1_000 })));
    const l = new Nip9aLoader({ filePath: file });
    l.start();
    try {
      assert.equal(l.active().createdAt, 1_000);
      fs.writeFileSync(file, JSON.stringify(rulesEvent({ id: 'c'.repeat(64), createdAt: 9_999 })));
      l.reload();
      assert.equal(l.active().createdAt, 9_999);
    } finally {
      l.stop();
    }
  });

  it('survives a missing file (atomic rename race) without losing state', () => {
    const file = path.join(tmpdir, 'rules.json');
    fs.writeFileSync(file, JSON.stringify(rulesEvent({ createdAt: 1_000 })));
    const l = new Nip9aLoader({ filePath: file });
    l.start();
    try {
      assert.equal(l.active().createdAt, 1_000);
      fs.unlinkSync(file);
      l.reload();
      assert.equal(l.active().createdAt, 1_000, 'active rules persist across transient file loss');
    } finally {
      l.stop();
    }
  });

  it('survives malformed JSON without losing prior state', () => {
    const file = path.join(tmpdir, 'rules.json');
    fs.writeFileSync(file, JSON.stringify(rulesEvent({ createdAt: 1_000 })));
    const l = new Nip9aLoader({ filePath: file });
    l.start();
    try {
      assert.equal(l.active().createdAt, 1_000);
      fs.writeFileSync(file, '{ not valid json');
      l.reload();
      assert.equal(l.active().createdAt, 1_000);
      assert.match(l.lastFileError, /JSON parse/);
    } finally {
      l.stop();
    }
  });
});

describe('Nip9aLoader: community parsing', () => {
  it('throws on malformed community address', () => {
    assert.throws(() => new Nip9aLoader({ community: 'not-a-community' }),
      /expected "34550:<hex64>:<d>"/);
  });

  it('accepts a well-formed community', () => {
    const l = new Nip9aLoader({ community: `34550:${OWNER}:foo` });
    assert.ok(l);
  });
});
