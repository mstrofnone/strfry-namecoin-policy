'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const {
  buildNameIndexScript,
  electrumScriptHash,
  parseNameScript,
  parseNameFromTx,
  pushData,
  OP_NAME_UPDATE,
  OP_NAME_FIRSTUPDATE,
} = require('../src/electrumx');

test('pushData: short push (< 0x4c)', () => {
  const data = Buffer.from('hello', 'utf8');
  const out = pushData(data);
  assert.equal(out[0], data.length);
  assert.deepEqual(out.slice(1), data);
});

test('pushData: medium push uses OP_PUSHDATA1', () => {
  const data = Buffer.alloc(100, 0xaa);
  const out = pushData(data);
  assert.equal(out[0], 0x4c);
  assert.equal(out[1], 100);
  assert.equal(out.length, 2 + 100);
});

test('pushData: large push uses OP_PUSHDATA2', () => {
  const data = Buffer.alloc(300, 0xbb);
  const out = pushData(data);
  assert.equal(out[0], 0x4d);
  assert.equal(out.readUInt16LE(1), 300);
  assert.equal(out.length, 3 + 300);
});

test('buildNameIndexScript: matches expected byte layout for d/testls', () => {
  const name = Buffer.from('d/testls', 'ascii');
  const script = buildNameIndexScript(name);
  // OP_NAME_UPDATE (0x53) + push(name: 8 bytes: 0x08 "d/testls") + push(""): 0x00 + 0x6d 0x75 0x6a
  const expected = Buffer.concat([
    Buffer.from([0x53]),
    Buffer.from([0x08]), name,
    Buffer.from([0x00, 0x6d, 0x75, 0x6a]),
  ]);
  assert.deepEqual(script, expected);
});

test('electrumScriptHash: reverses SHA-256 output', () => {
  const script = Buffer.from('deadbeef', 'hex');
  const hash = crypto.createHash('sha256').update(script).digest();
  const expected = Buffer.from(hash).reverse().toString('hex');
  assert.equal(electrumScriptHash(script), expected);
});

test('parseNameScript: NAME_UPDATE with small value', () => {
  const name = Buffer.from('d/example', 'ascii');
  const value = Buffer.from('{"nostr":"' + 'a'.repeat(64) + '"}', 'utf8');
  const script = Buffer.concat([
    Buffer.from([OP_NAME_UPDATE]),
    pushData(name),
    pushData(value),
    Buffer.from([0x6d, 0x75]),          // OP_2DROP OP_DROP
    Buffer.from([0x76, 0xa9, 0x14]),    // fake address script stub
    Buffer.alloc(20, 0x00),
    Buffer.from([0x88, 0xac]),
  ]);
  const parsed = parseNameScript(script);
  assert.equal(parsed.name, 'd/example');
  assert.equal(parsed.value, value.toString('utf8'));
  assert.equal(parsed.op, OP_NAME_UPDATE);
});

test('parseNameScript: NAME_FIRSTUPDATE skips the rand push', () => {
  const name = Buffer.from('d/new', 'ascii');
  const rand = Buffer.alloc(12, 0xcd);
  const value = Buffer.from('{"nostr":"b_b_b"}', 'utf8');
  const script = Buffer.concat([
    Buffer.from([OP_NAME_FIRSTUPDATE]),
    pushData(name),
    pushData(rand),
    pushData(value),
    Buffer.from([0x6d, 0x75, 0x51]), // 2drop drop OP_1 (stub)
  ]);
  const parsed = parseNameScript(script);
  assert.equal(parsed.name, 'd/new');
  assert.equal(parsed.value, value.toString('utf8'));
  assert.equal(parsed.op, OP_NAME_FIRSTUPDATE);
});

test('parseNameScript: uses OP_PUSHDATA1 for a larger value', () => {
  const name = Buffer.from('d/big', 'ascii');
  const longValue = Buffer.from('x'.repeat(200), 'utf8');
  const script = Buffer.concat([
    Buffer.from([OP_NAME_UPDATE]),
    pushData(name),
    pushData(longValue),
    Buffer.from([0x6d, 0x75]),
  ]);
  const parsed = parseNameScript(script);
  assert.equal(parsed.name, 'd/big');
  assert.equal(parsed.value, longValue.toString('utf8'));
});

test('parseNameScript: rejects non-NAME scripts', () => {
  assert.equal(parseNameScript(Buffer.from([0x76, 0xa9])), null);
  assert.equal(parseNameScript(Buffer.from([])), null);
  assert.equal(parseNameScript(null), null);
});

test('parseNameFromTx: finds the matching vout among several', () => {
  const name = Buffer.from('d/me', 'ascii');
  const value = Buffer.from('{"nostr":"deadbeef"}', 'utf8');
  const nameScript = Buffer.concat([
    Buffer.from([OP_NAME_UPDATE]),
    pushData(name),
    pushData(value),
    Buffer.from([0x6d, 0x75]),
  ]).toString('hex');

  const tx = {
    vout: [
      { scriptPubKey: { hex: '76a914' + '00'.repeat(20) + '88ac' } }, // normal p2pkh
      { scriptPubKey: { hex: nameScript } },
      { scriptPubKey: { hex: '6a' + '00'.repeat(10) } }, // OP_RETURN
    ],
  };
  const parsed = parseNameFromTx(tx, 'd/me');
  assert.equal(parsed.name, 'd/me');
  assert.equal(parsed.value, value.toString('utf8'));
});

test('parseNameFromTx: returns null if no vout matches the name', () => {
  const tx = {
    vout: [
      { scriptPubKey: { hex: '76a914' + '00'.repeat(20) + '88ac' } },
    ],
  };
  assert.equal(parseNameFromTx(tx, 'd/me'), null);
});

test('parseNameFromTx: returns null if name mismatches', () => {
  const name = Buffer.from('d/other', 'ascii');
  const value = Buffer.from('{}', 'utf8');
  const nameScript = Buffer.concat([
    Buffer.from([OP_NAME_UPDATE]),
    pushData(name),
    pushData(value),
    Buffer.from([0x6d, 0x75]),
  ]).toString('hex');
  const tx = { vout: [{ scriptPubKey: { hex: nameScript } }] };
  assert.equal(parseNameFromTx(tx, 'd/me'), null);
});

// ─── Failure-mode tests (skipped pending sibling branches) ───
//
// These guard against known-but-not-yet-fixed correctness issues. They are
// `t.skip()` until `fix/correctness-batch1` lands the corresponding fixes;
// at that point, drop the .skip and they should pass.

test.skip('electrumx: mempool-pollution — resolver picks confirmed tx over height=0 entry', async () => {
  // TODO(fix/correctness-batch1): when get_history returns a mix of
  //   [{height: 0, tx_hash: <unconfirmed/junk>}, {height: 100, tx_hash: <real NAME_UPDATE>}]
  // the client must NOT just `history[history.length - 1]`. Instead it should
  // ignore height<=0 entries (mempool / unconfirmed) and pick the highest
  // confirmed height. Currently the code uses last-element-wins, which can be
  // poisoned by a node that returns mempool entries appended last.
  //
  // To exercise this end-to-end we'll need a TCP/TLS mock-server harness
  // (none exists in this repo yet); the harness is being introduced on
  // `fix/correctness-batch1`. When it lands, drop .skip and assert that
  // ElectrumXClient#nameShow resolves to the value embedded in the height=100
  // tx, not the height=0 junk one.
  assert.fail('placeholder — enable on fix/correctness-batch1');
});

test.skip('electrumx: canonical-script-collision — latest tx has no NAME_UPDATE vout', async () => {
  // TODO(fix/correctness-batch1): the canonical name-index script can match
  // unrelated transactions (especially across reorgs / second-layer index
  // collisions). If `blockchain.transaction.get` returns a tx whose vouts
  // contain no NAME_UPDATE/NAME_FIRSTUPDATE for `expectedName`, the client
  // currently returns null — but we should walk *back* through history to
  // find the latest tx that does contain the matching name, instead of
  // giving up on the latest entry.
  //
  // Needs the same TCP mock harness as the mempool-pollution case.
  assert.fail('placeholder — enable on fix/correctness-batch1');
});

test.skip('electrumx: TLS cert-pin mismatch surfaces a definitive error', async () => {
  // TODO(fix/correctness-batch1): there is no TLS mock-server harness yet,
  // so we cannot drive `getPeerCertificate(true)` to return a known DER blob
  // without standing up a real TLS endpoint with a controlled cert.
  // The pin-mismatch path in _connectAndQuery (around onConnect) is exercised
  // manually via `test:live` today.
  //
  // When the harness lands, assert that connecting with a wrong
  // `certPinSha256` rejects with /Cert pin mismatch/ and that retries do
  // NOT reconnect (the error currently isn't marked .electrumxDefinitive,
  // so it does retry; that's a separate question for the correctness branch).
  assert.fail('placeholder — enable on fix/correctness-batch1');
});

test.skip('electrumx: NAME_FIRSTUPDATE rand must be exactly 20 bytes (19-byte case rejected)', () => {
  // TODO(fix/correctness-batch1): NAME_FIRSTUPDATE's `rand` push is defined
  // by namecoin-core as exactly 20 bytes. parseNameScript currently accepts
  // any push length for `rand` and treats it as the rand slot, so a script
  // with a 19-byte (or 21-byte) push between name and value is mis-parsed
  // as a valid NAME_FIRSTUPDATE.
  //
  // Once fixed, the parser must return null (or fall through to the
  // NAME_UPDATE branch's strict layout) for these malformed scripts.
  const name = Buffer.from('d/x', 'ascii');
  const badRand = Buffer.alloc(19, 0x11); // wrong length
  const value = Buffer.from('{}', 'utf8');
  const script = Buffer.concat([
    Buffer.from([OP_NAME_FIRSTUPDATE]),
    pushData(name),
    pushData(badRand),
    pushData(value),
    Buffer.from([0x6d, 0x75]),
  ]);
  const parsed = parseNameScript(script);
  assert.equal(parsed, null, '19-byte rand must not be accepted as NAME_FIRSTUPDATE');
});

test.skip('electrumx: NAME_FIRSTUPDATE rand must be exactly 20 bytes (21-byte case rejected)', () => {
  // TODO(fix/correctness-batch1): mirror of the 19-byte test, with a 21-byte
  // rand push. Same fix expected.
  const name = Buffer.from('d/x', 'ascii');
  const badRand = Buffer.alloc(21, 0x22);
  const value = Buffer.from('{}', 'utf8');
  const script = Buffer.concat([
    Buffer.from([OP_NAME_FIRSTUPDATE]),
    pushData(name),
    pushData(badRand),
    pushData(value),
    Buffer.from([0x6d, 0x75]),
  ]);
  const parsed = parseNameScript(script);
  assert.equal(parsed, null, '21-byte rand must not be accepted as NAME_FIRSTUPDATE');
});
