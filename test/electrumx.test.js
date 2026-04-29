'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const {
  ElectrumXClient,
  buildNameIndexScript,
  electrumScriptHash,
  parseNameScript,
  parseNameFromTx,
  pushData,
  selectNameRowFromHistory,
  NAME_EXPIRE_DEPTH,
  parseCertPins,
  OP_NAME_UPDATE,
  OP_NAME_FIRSTUPDATE,
  NAMECOIN_NAME_MAX_BYTES,
} = require('../src/electrumx');

// Build a tx with a single NAME_UPDATE vout for the given name+value.
function makeNameTx(name, value) {
  const nameScript = Buffer.concat([
    Buffer.from([OP_NAME_UPDATE]),
    pushData(Buffer.from(name, 'ascii')),
    pushData(Buffer.from(value, 'utf8')),
    Buffer.from([0x6d, 0x75]),
  ]).toString('hex');
  return { vout: [{ scriptPubKey: { hex: nameScript } }] };
}

// Build a tx whose only NAME_* vout is for a DIFFERENT name (canonical-script collision).
function makeJunkTx(otherName) {
  return makeNameTx(otherName, '{"junk":true}');
}

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

test('parseNameScript: NAME_FIRSTUPDATE skips the rand push (canonical 20-byte rand)', () => {
  const name = Buffer.from('d/new', 'ascii');
  const rand = Buffer.alloc(20, 0xcd);
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

test('parseNameScript: FIRSTUPDATE with 19-byte fake-rand does NOT mis-parse as FIRSTUPDATE', () => {
  // A 19-byte middle push is not a valid Namecoin rand. The parser must
  // not treat it as `rand` and silently skip it — doing so would let an
  // attacker craft a script where the *real* nostr value sits in the
  // first push and a junk push gets interpreted as the value.
  const name = Buffer.from('d/x', 'ascii');
  const fakeRand = Buffer.alloc(19, 0xab);
  const realValue = Buffer.from('{"nostr":"d_d_d"}', 'utf8');
  const script = Buffer.concat([
    Buffer.from([OP_NAME_FIRSTUPDATE]),
    pushData(name),
    pushData(fakeRand),
    pushData(realValue),
    Buffer.from([0x6d, 0x75]),
  ]);
  const parsed = parseNameScript(script);
  // We fall back to UPDATE-shape parsing, so the SECOND push (the 19-byte
  // junk) is what gets read as the value — NOT the realValue push. This
  // is the safe behavior: the consumer will then fail JSON parsing and
  // reject, instead of trusting an attacker-controlled real-looking value.
  assert.equal(parsed.name, 'd/x');
  assert.notEqual(parsed.value, realValue.toString('utf8'),
    'must not mis-parse a 19-byte rand-shaped push as FIRSTUPDATE rand');
  assert.equal(parsed.value.length, 19);
});

test('parseNameScript: FIRSTUPDATE with 21-byte fake-rand does NOT mis-parse as FIRSTUPDATE', () => {
  const name = Buffer.from('d/x', 'ascii');
  const fakeRand = Buffer.alloc(21, 0xab);
  const realValue = Buffer.from('{"nostr":"e_e_e"}', 'utf8');
  const script = Buffer.concat([
    Buffer.from([OP_NAME_FIRSTUPDATE]),
    pushData(name),
    pushData(fakeRand),
    pushData(realValue),
    Buffer.from([0x6d, 0x75]),
  ]);
  const parsed = parseNameScript(script);
  assert.equal(parsed.name, 'd/x');
  assert.notEqual(parsed.value, realValue.toString('utf8'),
    'must not mis-parse a 21-byte rand-shaped push as FIRSTUPDATE rand');
  assert.equal(parsed.value.length, 21);
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

// ── Hardening: SPKI / DER cert pin parsing ──

test('parseCertPins: legacy 64-hex DER fingerprint', () => {
  const hex = 'a'.repeat(64);
  assert.deepEqual(parseCertPins(hex), [{ kind: 'der', hex }]);
});

test('parseCertPins: SPKI base64 form', () => {
  // 32-byte zero buffer encodes to 'AAAA...' base64 of length 44 (with padding).
  const b64 = Buffer.alloc(32).toString('base64');
  const pins = parseCertPins(`sha256/${b64}`);
  assert.equal(pins.length, 1);
  assert.equal(pins[0].kind, 'spki');
  assert.equal(pins[0].b64, b64);
});

test('parseCertPins: comma-separated mixed pins', () => {
  const hex = 'b'.repeat(64);
  const b64 = Buffer.alloc(32, 1).toString('base64');
  const pins = parseCertPins(`${hex}, sha256/${b64}`);
  assert.equal(pins.length, 2);
  assert.equal(pins[0].kind, 'der');
  assert.equal(pins[0].hex, hex);
  assert.equal(pins[1].kind, 'spki');
  assert.equal(pins[1].b64, b64);
});

test('parseCertPins: rejects malformed entries', () => {
  assert.throws(() => parseCertPins('not-hex-not-spki'), /CERT_PIN/);
  assert.throws(() => parseCertPins('sha256/'), /CERT_PIN/);
  assert.throws(() => parseCertPins('sha256/' + Buffer.alloc(8).toString('base64')), /32 bytes/);
  assert.throws(() => parseCertPins('aa'), /64 hex chars/);
});

test('parseCertPins: empty / null returns empty list', () => {
  assert.deepEqual(parseCertPins(null), []);
  assert.deepEqual(parseCertPins(''), []);
  assert.deepEqual(parseCertPins('  ,  ,'), []);
});

// ── Hardening: nameShow rejects oversize names without opening a socket ──

test('ElectrumXClient.nameShow: rejects empty name', async () => {
  const c = new ElectrumXClient({ host: 'unused.invalid', tls: false, retries: 0, timeoutMs: 100 });
  await assert.rejects(c.nameShow(''), /outside \[1, 255\]/);
});

test('ElectrumXClient.nameShow: rejects names longer than 255 bytes', async () => {
  const c = new ElectrumXClient({ host: 'unused.invalid', tls: false, retries: 0, timeoutMs: 100 });
  const big = 'd/' + 'a'.repeat(NAMECOIN_NAME_MAX_BYTES); // 257 bytes
  await assert.rejects(c.nameShow(big), /outside \[1, 255\]/);
});

test('ElectrumXClient.nameShow: rejects non-string', async () => {
  const c = new ElectrumXClient({ host: 'unused.invalid', tls: false, retries: 0, timeoutMs: 100 });
  await assert.rejects(c.nameShow(null), /must be a string/);
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

// ── Fix #1: mempool / unconfirmed poisoning ───────────────────────────────

test('selectNameRowFromHistory: ignores mempool entry (height <= 0) at the end', async () => {
  // Attacker broadcasts a tx that lands at the end of history with height 0
  // and a forged value. The real, confirmed update at the older entry must win.
  const realValue = JSON.stringify({ nostr: 'a'.repeat(64) });
  const forgedValue = JSON.stringify({ nostr: 'b'.repeat(64) });
  const txs = {
    real:  makeNameTx('d/x', realValue),
    forged: makeNameTx('d/x', forgedValue),
  };
  const history = [
    { tx_hash: 'real', height: 1000 },
    { tx_hash: 'forged', height: 0 },     // mempool / unconfirmed
  ];
  const out = await selectNameRowFromHistory({
    name: 'd/x', history, tip: 1005, minConfirmations: 1,
    fetchTx: async (h) => txs[h],
  });
  assert.equal(out.value, realValue);
  assert.equal(out.txid, 'real');
  assert.equal(out.height, 1000);
});

test('selectNameRowFromHistory: drops entries with insufficient confirmations', async () => {
  const v1 = JSON.stringify({ nostr: 'a'.repeat(64) });
  const v2 = JSON.stringify({ nostr: 'b'.repeat(64) });
  const txs = {
    confirmed: makeNameTx('d/x', v1),
    fresh:     makeNameTx('d/x', v2),
  };
  // tip=1000; fresh@height 1000 has 1 conf, confirmed@height 990 has 11.
  // With minConfirmations=6, fresh is filtered out; confirmed wins.
  const history = [
    { tx_hash: 'confirmed', height: 990 },
    { tx_hash: 'fresh',     height: 1000 },
  ];
  const out = await selectNameRowFromHistory({
    name: 'd/x', history, tip: 1000, minConfirmations: 6,
    fetchTx: async (h) => txs[h],
  });
  assert.equal(out.txid, 'confirmed');
  assert.equal(out.value, v1);
});

test('selectNameRowFromHistory: minConfirmations=0 honors mempool-skipping but accepts 1-conf', async () => {
  const v = JSON.stringify({ nostr: 'a'.repeat(64) });
  const txs = { good: makeNameTx('d/x', v) };
  const out = await selectNameRowFromHistory({
    name: 'd/x',
    history: [{ tx_hash: 'good', height: 1000 }],
    tip: 1000,
    minConfirmations: 0,
    fetchTx: async (h) => txs[h],
  });
  assert.equal(out.txid, 'good');
});

// ── Fix #2: canonical-script collision walk ───────────────────────────────

test('selectNameRowFromHistory: walks past junk UTXO on canonical scripthash', async () => {
  // Latest entry is a junk tx (name doesn't match what we asked for).
  // The previous entry IS a real NAME_UPDATE for the requested name.
  // Old behavior: parse latest only, return null, censoring the live name.
  // New behavior: walk back, find the real update, return it.
  const realValue = JSON.stringify({ nostr: 'a'.repeat(64) });
  const txs = {
    junk: makeJunkTx('d/different'),
    real: makeNameTx('d/x', realValue),
  };
  const history = [
    { tx_hash: 'real', height: 900 },
    { tx_hash: 'junk', height: 1000 },
  ];
  const out = await selectNameRowFromHistory({
    name: 'd/x', history, tip: 1005, minConfirmations: 1,
    fetchTx: async (h) => txs[h],
  });
  assert.ok(out, 'must not return null when a valid older update exists');
  assert.equal(out.txid, 'real');
  assert.equal(out.value, realValue);
});

test('selectNameRowFromHistory: caps walk at MAX_HISTORY_WALK to bound work', async () => {
  // Adversarial history: 200 junk entries, none for our name.
  // We must give up after walking the cap, not loop forever or fetch all 200.
  const history = [];
  const txs = {};
  for (let i = 0; i < 200; i++) {
    const h = `junk${i}`;
    history.push({ tx_hash: h, height: 1000 - i });
    txs[h] = makeJunkTx('d/different');
  }
  let fetches = 0;
  const out = await selectNameRowFromHistory({
    name: 'd/x', history, tip: 1100, minConfirmations: 1,
    fetchTx: async (h) => { fetches++; return txs[h]; },
  });
  assert.equal(out, null);
  assert.ok(fetches <= 32, `expected \u2264 32 fetches, got ${fetches}`);
});

// ── Fix #3: expiry uses parsed-update height ──────────────────────────────

test('selectNameRowFromHistory: expiry uses chosen tx height, not the latest history entry', async () => {
  // Latest history entry is a junk tx at a recent height. The actual
  // NAME_UPDATE is much older and BEYOND the expiry window. Old code
  // would pick the latest and not flag expiry; new code picks the real
  // (old) one and correctly flags expiry.
  const realValue = JSON.stringify({ nostr: 'a'.repeat(64) });
  const txs = {
    junk: makeJunkTx('d/different'),
    real: makeNameTx('d/x', realValue),
  };
  const tip = 100_000;
  // chosen height = 50_000 → tip - 50_000 = 50_000 ≥ NAME_EXPIRE_DEPTH (36000) → expired
  const history = [
    { tx_hash: 'real', height: 50_000 },
    { tx_hash: 'junk', height: 99_000 }, // junk near tip
  ];
  await assert.rejects(
    () => selectNameRowFromHistory({
      name: 'd/x', history, tip, minConfirmations: 1,
      fetchTx: async (h) => txs[h],
    }),
    /expired/
  );
});

test('selectNameRowFromHistory: returns expires_in from chosen tx height', async () => {
  const v = JSON.stringify({ nostr: 'a'.repeat(64) });
  const txs = {
    junk: makeJunkTx('d/different'),
    real: makeNameTx('d/x', v),
  };
  const tip = 1100;
  const history = [
    { tx_hash: 'real', height: 1000 },
    { tx_hash: 'junk', height: 1099 },
  ];
  const out = await selectNameRowFromHistory({
    name: 'd/x', history, tip, minConfirmations: 1,
    fetchTx: async (h) => txs[h],
  });
  assert.equal(out.txid, 'real');
  assert.equal(out.height, 1000);
  assert.equal(out.expires_in, NAME_EXPIRE_DEPTH - (tip - 1000));
});

// ── Fix #1 + #2 together: attacker can't poison a recently-updated name ──

test('selectNameRowFromHistory: mempool junk + confirmed real = real wins', async () => {
  const real = JSON.stringify({ nostr: 'a'.repeat(64) });
  const txs = {
    real:  makeNameTx('d/x', real),
    msink: makeNameTx('d/x', JSON.stringify({ nostr: 'b'.repeat(64) })),
  };
  const history = [
    { tx_hash: 'real',  height: 1000 },
    { tx_hash: 'msink', height: 0 }, // attacker mempool tx
  ];
  const out = await selectNameRowFromHistory({
    name: 'd/x', history, tip: 1010, minConfirmations: 1,
    fetchTx: async (h) => txs[h],
  });
  assert.equal(out.value, real);
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
