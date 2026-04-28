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
  selectNameRowFromHistory,
  NAME_EXPIRE_DEPTH,
  OP_NAME_UPDATE,
  OP_NAME_FIRSTUPDATE,
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
