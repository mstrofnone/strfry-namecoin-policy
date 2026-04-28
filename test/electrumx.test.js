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
  parseCertPins,
  OP_NAME_UPDATE,
  OP_NAME_FIRSTUPDATE,
  NAMECOIN_NAME_MAX_BYTES,
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
