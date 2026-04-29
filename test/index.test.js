'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { extractNip05 } = require('../src/index');

// extractNip05 covers the kind:0 content payload. It must:
//   - return null for non-strings, non-JSON, JSON arrays/primitives
//   - return null when the doc has no string `nip05`
//   - return the trimmed nip05 string otherwise

test('extractNip05: returns null for non-string content', () => {
  assert.equal(extractNip05(null), null);
  assert.equal(extractNip05(undefined), null);
  assert.equal(extractNip05(42), null);
  assert.equal(extractNip05({}), null);
});

test('extractNip05: returns null for empty string', () => {
  assert.equal(extractNip05(''), null);
});

test('extractNip05: returns null for malformed JSON', () => {
  assert.equal(extractNip05('not json'), null);
  assert.equal(extractNip05('{nip05:'), null);
});

test('extractNip05: returns null when nip05 missing or non-string', () => {
  assert.equal(extractNip05(JSON.stringify({})), null);
  assert.equal(extractNip05(JSON.stringify({ nip05: 42 })), null);
  assert.equal(extractNip05(JSON.stringify({ nip05: null })), null);
  assert.equal(extractNip05(JSON.stringify({ nip05: { v: 'x' } })), null);
});

test('extractNip05: trims and returns the nip05 string', () => {
  assert.equal(extractNip05(JSON.stringify({ nip05: '  alice@example.bit  ' })),
    'alice@example.bit');
});

test('extractNip05: returns null for empty/whitespace-only nip05', () => {
  assert.equal(extractNip05(JSON.stringify({ nip05: '   ' })), null);
  assert.equal(extractNip05(JSON.stringify({ nip05: '' })), null);
});

// ─── Failure-mode test (skipped pending fix/correctness-batch1) ───

test.skip('extractNip05: rejects JSON arrays as top-level doc', () => {
  // TODO(fix/correctness-batch1): currently `JSON.parse('[…]')` returns an
  // array, and `typeof array === 'object'` is true, so extractNip05 falls
  // through and returns null only because `doc.nip05` happens to be undefined.
  // It should explicitly reject arrays via Array.isArray(doc) === true so
  // that a payload like `[{"nip05":"x@y.bit"}]` (or any other array shape)
  // can never accidentally satisfy a future code path that iterates the doc.
  //
  // When the fix lands on fix/correctness-batch1, this test should drop
  // .skip and pass: passing an array MUST return null, even when the array
  // contains an object with a nip05 field.
  assert.equal(extractNip05(JSON.stringify([{ nip05: 'alice@example.bit' }])), null);
  assert.equal(extractNip05(JSON.stringify([])), null);
  assert.equal(extractNip05(JSON.stringify(['alice@example.bit'])), null);
});
