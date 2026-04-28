'use strict';

const net = require('net');
const tls = require('tls');
const crypto = require('crypto');
const { EventEmitter } = require('events');

/**
 * Minimal namecoin-ElectrumX client (Electrum protocol 1.4).
 *
 * Uses the generic Electrum method set to resolve a Namecoin name:
 *   1. Build the canonical name index script:
 *        OP_NAME_UPDATE <push(name)> <push("")> OP_2DROP OP_DROP OP_RETURN
 *   2. scripthash = reverse(SHA-256(script)).hex
 *   3. blockchain.scripthash.get_history  → list of (tx_hash, height)
 *   4. blockchain.transaction.get(latest_tx_hash, true) → scan vouts for
 *      a script starting with OP_NAME_UPDATE; read the name and value
 *      push-data items.
 *   5. blockchain.headers.subscribe → current tip; check expiry
 *      (names expire after 36 000 blocks since last update).
 *
 * This matches the algorithm used by Amethyst and Nostur, so it works
 * against any ElectrumX server with a Namecoin name index — including
 * servers that don't expose a `blockchain.name.show` extension.
 *
 * Transport: one TCP/TLS connection per resolve. Short-lived, reused by
 * nobody. Good enough for a low-qps write-policy plugin backed by an
 * in-memory LRU cache.
 *
 * No external deps — Node built-ins only.
 */

// ── Namecoin / Bitcoin script opcodes ──────────────────────────────────────
const OP_0            = 0x00;
const OP_PUSHDATA1    = 0x4c;
const OP_PUSHDATA2    = 0x4d;
const OP_PUSHDATA4    = 0x4e;
const OP_RETURN       = 0x6a;
const OP_2DROP        = 0x6d;
const OP_DROP         = 0x75;
// Namecoin re-uses OP_3 (0x53) as OP_NAME_UPDATE; OP_2 (0x52) = OP_NAME_FIRSTUPDATE.
// Both start NAME_* scripts. `blockchain.scripthash.get_history` returns all
// transactions whose UTXOs index under the canonical script, which is fine —
// we just need to pick up the latest one.
const OP_NAME_UPDATE      = 0x53;
const OP_NAME_FIRSTUPDATE = 0x52;

const NAME_EXPIRE_DEPTH = 36_000;  // Namecoin names expire after ~36k blocks (~36 weeks)
const NAMECOIN_NAME_MAX_BYTES = 255;  // Namecoin consensus cap on name length

/**
 * Parse the NAMECOIN_ELECTRUMX_CERT_PIN env value into a list of pin
 * descriptors. Accepts:
 *   - Plain 64-hex string  → DER fingerprint of the peer cert.
 *   - `sha256/<base64>`    → SHA-256 of the peer's SubjectPublicKeyInfo (SPKI).
 *   - Comma-separated list of either form (any-match).
 *
 * @param {string|null|undefined} raw
 * @returns {Array<{kind:'der',hex:string} | {kind:'spki',b64:string}>}
 */
function parseCertPins(raw) {
  if (!raw) return [];
  const out = [];
  for (const part of String(raw).split(',')) {
    const p = part.trim();
    if (!p) continue;
    if (/^sha256\//i.test(p)) {
      const b64 = p.slice(p.indexOf('/') + 1).trim();
      if (!b64) throw new Error(`NAMECOIN_ELECTRUMX_CERT_PIN: empty SPKI pin in "${p}"`);
      // Tolerate both standard and url-safe base64. Validate by decoding.
      const buf = Buffer.from(b64, 'base64');
      if (buf.length !== 32) {
        throw new Error(`NAMECOIN_ELECTRUMX_CERT_PIN: SPKI pin "${p}" must decode to 32 bytes (got ${buf.length})`);
      }
      out.push({ kind: 'spki', b64: buf.toString('base64') });
    } else {
      const hex = p.toLowerCase().replace(/[^0-9a-f]/g, '');
      if (hex.length !== 64) {
        throw new Error(`NAMECOIN_ELECTRUMX_CERT_PIN: hex DER pin "${p}" must be 64 hex chars (got ${hex.length})`);
      }
      out.push({ kind: 'der', hex });
    }
  }
  return out;
}

class ElectrumXClient extends EventEmitter {
  /**
   * @param {object} opts
   * @param {string} opts.host
   * @param {number} [opts.port=50002]
   * @param {boolean} [opts.tls=true]
   * @param {string|null} [opts.certPinSha256]  hex-encoded SHA-256 of DER cert
   * @param {boolean} [opts.rejectUnauthorized]  override default (default: true unless pinning)
   * @param {number} [opts.timeoutMs=5000]
   * @param {number} [opts.retries=2]
   * @param {(level:string,...args:any[])=>void} [opts.logger]
   */
  constructor(opts = {}) {
    super();
    if (!opts.host) throw new Error('ElectrumXClient: host is required');
    this.host = opts.host;
    this.useTls = opts.tls !== false;
    this.port = Number(opts.port) || (this.useTls ? 50002 : 50001);
    // Accept either:
    //   - 64-hex DER fingerprint (legacy);
    //   - `sha256/<base64>` SPKI pin (survives cert rotation);
    //   - comma-separated mix of both (any match wins, for rotation).
    this.certPins = parseCertPins(opts.certPinSha256);
    // Back-compat: keep certPinSha256 set when there's exactly one DER pin
    // so downstream callers can still read it as a flag.
    this.certPinSha256 = (this.certPins.length === 1 && this.certPins[0].kind === 'der')
      ? this.certPins[0].hex
      : (this.certPins.length > 0 ? '__pinned__' : null);
    this.rejectUnauthorized = opts.rejectUnauthorized ?? !(this.certPins.length > 0);
    this.timeoutMs = Number(opts.timeoutMs) || 5000;
    this.retries = Number.isFinite(opts.retries) ? opts.retries : 2;
    this.logger = opts.logger || (() => {});
  }

  /**
   * Resolve a Namecoin name to its current value + metadata.
   *
   * @param {string} name  e.g. "d/testls"
   * @returns {Promise<{name:string,value:string,txid:string,height:number,expires_in?:number,tip?:number}|null>}
   */
  async nameShow(name) {
    if (typeof name !== 'string') {
      const err = new Error('ElectrumX nameShow: name must be a string');
      err.electrumxDefinitive = true;
      throw err;
    }
    // Namecoin consensus caps name length at 255 bytes; refuse longer names
    // before constructing a script (which would overflow OP_PUSHDATA1's len byte).
    const nameBytes = Buffer.byteLength(name, 'utf8');
    if (nameBytes === 0 || nameBytes > NAMECOIN_NAME_MAX_BYTES) {
      const err = new Error(`ElectrumX nameShow: name length ${nameBytes} bytes outside [1, ${NAMECOIN_NAME_MAX_BYTES}]`);
      err.electrumxDefinitive = true;
      throw err;
    }
    let lastErr = null;
    for (let attempt = 0; attempt <= this.retries; attempt++) {
      try {
        return await this._connectAndQuery(name);
      } catch (err) {
        lastErr = err;
        this.logger('debug', `electrumx nameShow(${name}) attempt ${attempt + 1} failed: ${err.message}`);
        if (err.electrumxDefinitive) throw err; // not-found / expired: don't retry
        if (attempt < this.retries) await sleep(150 * (attempt + 1));
      }
    }
    throw lastErr || new Error('ElectrumX nameShow failed');
  }

  /**
   * One full resolve cycle over a single connection.
   */
  _connectAndQuery(name) {
    return new Promise((resolve, reject) => {
      let socket;
      let settled = false;
      let buf = '';
      /** @type {Map<number, {resolve:Function, reject:Function}>} */
      const pending = new Map();
      let nextId = 1;

      const finish = (err, value) => {
        if (settled) return;
        settled = true;
        try { socket && socket.destroy(); } catch (_) {}
        clearTimeout(timer);
        if (err) reject(err); else resolve(value);
      };

      const timer = setTimeout(() => {
        finish(new Error(`ElectrumX timeout after ${this.timeoutMs}ms (${name})`));
      }, this.timeoutMs);

      const send = (method, params) => new Promise((res, rej) => {
        const id = nextId++;
        pending.set(id, { resolve: res, reject: rej });
        try {
          socket.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
        } catch (err) {
          pending.delete(id);
          rej(err);
        }
      });

      const onConnect = async () => {
        if (this.useTls && this.certPins.length > 0) {
          try {
            const peerCert = socket.getPeerCertificate(true);
            if (!peerCert || !peerCert.raw) {
              return finish(new Error('No peer certificate available to verify pin'));
            }
            const derFp = crypto.createHash('sha256').update(peerCert.raw).digest('hex');
            const spkiB64 = peerCert.pubkey
              ? crypto.createHash('sha256').update(peerCert.pubkey).digest('base64')
              : null;
            const matched = this.certPins.some((pin) => {
              if (pin.kind === 'der') return pin.hex === derFp;
              if (pin.kind === 'spki') return spkiB64 != null && pin.b64 === spkiB64;
              return false;
            });
            if (!matched) {
              const observed = `der=${derFp}` + (spkiB64 ? ` spki=sha256/${spkiB64}` : '');
              return finish(new Error(`Cert pin mismatch: no configured pin matched (observed ${observed})`));
            }
          } catch (e) {
            return finish(new Error(`Cert pin verification failed: ${e.message}`));
          }
        }
        try {
          const result = await doResolve();
          finish(null, result);
        } catch (err) {
          finish(err);
        }
      };

      const doResolve = async () => {
        // 1. Handshake — the server may require it before other calls
        await send('server.version', ['strfry-namecoin-policy/0.1', '1.4']).catch(() => null);

        // 2. Canonical name-index scripthash
        const script = buildNameIndexScript(Buffer.from(name, 'ascii'));
        const scripthash = electrumScriptHash(script);

        // 3. History
        const history = await send('blockchain.scripthash.get_history', [scripthash]);
        if (!Array.isArray(history) || history.length === 0) {
          // No history ⇒ name has never existed (or the server has no name index).
          return null;
        }
        // Latest = last element of the list
        const latest = history[history.length - 1];
        const txHash = latest && latest.tx_hash;
        const height = latest && typeof latest.height === 'number' ? latest.height : 0;
        if (typeof txHash !== 'string') return null;

        // 4. Fetch tx (verbose)
        const tx = await send('blockchain.transaction.get', [txHash, true]);

        // 5. Tip (for expiry check)
        let tip = null;
        try {
          const headers = await send('blockchain.headers.subscribe', []);
          if (headers && typeof headers.height === 'number') tip = headers.height;
        } catch (_) { /* some servers may not have subscribe; tolerate */ }

        if (tip != null && height > 0 && (tip - height) >= NAME_EXPIRE_DEPTH) {
          const err = new Error(`Namecoin name "${name}" expired`);
          err.electrumxDefinitive = true;
          throw err;
        }

        // 6. Parse NAME_* script from the vouts
        const parsed = parseNameFromTx(tx, name);
        if (!parsed) return null;

        const result = {
          name: parsed.name,
          value: parsed.value,
          txid: txHash,
          height,
        };
        if (tip != null && height > 0) {
          result.expires_in = NAME_EXPIRE_DEPTH - (tip - height);
          result.tip = tip;
        }
        return result;
      };

      try {
        const connectOpts = { host: this.host, port: this.port };
        if (this.useTls) {
          // RFC 6066 SNI must be a hostname, not an IP.
          const isIp = net.isIP(this.host) !== 0;
          socket = tls.connect({
            ...connectOpts,
            rejectUnauthorized: this.rejectUnauthorized,
            ...(isIp ? {} : { servername: this.host }),
          }, onConnect);
        } else {
          socket = net.connect(connectOpts, onConnect);
        }

        socket.setEncoding('utf8');
        socket.on('data', (chunk) => {
          buf += chunk;
          let nl;
          while ((nl = buf.indexOf('\n')) !== -1) {
            const line = buf.slice(0, nl).trim();
            buf = buf.slice(nl + 1);
            if (!line) continue;
            let msg;
            try {
              msg = JSON.parse(line);
            } catch (e) {
              return finish(new Error(`ElectrumX parse error: ${e.message}`));
            }
            if (msg.id == null) continue; // async subscription notification — ignore
            const p = pending.get(msg.id);
            if (!p) continue;
            pending.delete(msg.id);
            if (msg.error) {
              const em = typeof msg.error === 'object'
                ? (msg.error.message || JSON.stringify(msg.error))
                : String(msg.error);
              p.reject(new Error(`ElectrumX error: ${em}`));
            } else {
              p.resolve(msg.result);
            }
          }
        });

        socket.on('error', (err) => finish(new Error(`ElectrumX socket error: ${err.message}`)));
        socket.on('end',   () => finish(new Error('ElectrumX connection closed before response')));
        socket.on('close', () => {
          // If there are still pending requests, reject them
          for (const p of pending.values()) p.reject(new Error('Connection closed'));
          pending.clear();
          finish(new Error('ElectrumX connection closed before response'));
        });
      } catch (err) {
        finish(err);
      }
    });
  }
}

// ── Script / scripthash helpers ────────────────────────────────────────────

/**
 * Build Bitcoin-style push-data: opcode(s) + raw bytes.
 * @param {Buffer} data
 * @returns {Buffer}
 */
function pushData(data) {
  const len = data.length;
  if (len < OP_PUSHDATA1) {
    return Buffer.concat([Buffer.from([len]), data]);
  }
  if (len <= 0xff) {
    return Buffer.concat([Buffer.from([OP_PUSHDATA1, len]), data]);
  }
  if (len <= 0xffff) {
    const hdr = Buffer.alloc(3);
    hdr[0] = OP_PUSHDATA2;
    hdr.writeUInt16LE(len, 1);
    return Buffer.concat([hdr, data]);
  }
  const hdr = Buffer.alloc(5);
  hdr[0] = OP_PUSHDATA4;
  hdr.writeUInt32LE(len, 1);
  return Buffer.concat([hdr, data]);
}

/**
 * Canonical script used by namecoin-ElectrumX to index name lookups:
 *   OP_NAME_UPDATE <push(name)> <push("")> OP_2DROP OP_DROP OP_RETURN
 *
 * @param {Buffer} nameBytes  ASCII-encoded name like "d/testls"
 * @returns {Buffer}
 */
function buildNameIndexScript(nameBytes) {
  return Buffer.concat([
    Buffer.from([OP_NAME_UPDATE]),
    pushData(nameBytes),
    pushData(Buffer.alloc(0)),
    Buffer.from([OP_2DROP, OP_DROP, OP_RETURN]),
  ]);
}

/**
 * Electrum protocol scripthash: SHA-256 → reverse bytes → hex.
 * @param {Buffer} script
 * @returns {string}
 */
function electrumScriptHash(script) {
  const h = crypto.createHash('sha256').update(script).digest();
  return Buffer.from(h).reverse().toString('hex');
}

/**
 * Read a push-data item from a script buffer at position `pos`.
 *
 * @param {Buffer} script
 * @param {number} pos
 * @returns {{data:Buffer, next:number}|null}
 */
function readPushData(script, pos) {
  if (pos >= script.length) return null;
  const op = script[pos];

  if (op === OP_0) return { data: Buffer.alloc(0), next: pos + 1 };

  if (op > 0 && op < OP_PUSHDATA1) {
    const end = pos + 1 + op;
    if (end > script.length) return null;
    return { data: script.slice(pos + 1, end), next: end };
  }

  if (op === OP_PUSHDATA1) {
    if (pos + 2 > script.length) return null;
    const len = script[pos + 1];
    const end = pos + 2 + len;
    if (end > script.length) return null;
    return { data: script.slice(pos + 2, end), next: end };
  }

  if (op === OP_PUSHDATA2) {
    if (pos + 3 > script.length) return null;
    const len = script.readUInt16LE(pos + 1);
    const end = pos + 3 + len;
    if (end > script.length) return null;
    return { data: script.slice(pos + 3, end), next: end };
  }

  if (op === OP_PUSHDATA4) {
    if (pos + 5 > script.length) return null;
    const len = script.readUInt32LE(pos + 1);
    const end = pos + 5 + len;
    if (end > script.length) return null;
    return { data: script.slice(pos + 5, end), next: end };
  }

  return null;
}

/**
 * Parse a NAME_* script and return {name, value}.
 *
 * Script layout:
 *   <OP_NAME_UPDATE or OP_NAME_FIRSTUPDATE> <push(name)> [<push(rand)>] <push(value)> OP_2DROP OP_DROP <address script...>
 *
 * NAME_FIRSTUPDATE has an extra 'rand' push between name and value. We
 * detect it by looking ahead: if the next push-data after the name is
 * short (<= 32 bytes) AND is followed by another push-data before
 * OP_2DROP, we treat it as the rand and skip to the value.
 *
 * @param {Buffer} script
 * @returns {{name:string, value:string, op:number}|null}
 */
function parseNameScript(script) {
  if (!script || script.length < 4) return null;
  const op = script[0];
  if (op !== OP_NAME_UPDATE && op !== OP_NAME_FIRSTUPDATE) return null;

  const first = readPushData(script, 1);
  if (!first) return null;

  let valueBuf = null;
  if (op === OP_NAME_FIRSTUPDATE) {
    // name, rand, value
    const rand = readPushData(script, first.next);
    if (!rand) return null;
    const v = readPushData(script, rand.next);
    if (!v) return null;
    valueBuf = v.data;
  } else {
    // name, value
    const v = readPushData(script, first.next);
    if (!v) return null;
    valueBuf = v.data;
  }

  return {
    op,
    name: first.data.toString('ascii'),
    value: valueBuf.toString('utf8'),
  };
}

/**
 * Walk a verbose transaction's vouts looking for a NAME_* output whose
 * name matches `expectedName`.
 *
 * @param {any} tx
 * @param {string} expectedName
 * @returns {{name:string, value:string}|null}
 */
function parseNameFromTx(tx, expectedName) {
  if (!tx || typeof tx !== 'object' || !Array.isArray(tx.vout)) return null;
  for (const vout of tx.vout) {
    const hex = vout && vout.scriptPubKey && vout.scriptPubKey.hex;
    if (typeof hex !== 'string') continue;
    // Quick filter: NAME_* scripts start with 0x52 or 0x53
    const first = hex.slice(0, 2).toLowerCase();
    if (first !== '53' && first !== '52') continue;
    let script;
    try {
      script = Buffer.from(hex, 'hex');
    } catch (_) { continue; }
    const parsed = parseNameScript(script);
    if (!parsed) continue;
    if (parsed.name === expectedName) return parsed;
  }
  return null;
}

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

module.exports = {
  ElectrumXClient,
  // Exposed for unit tests / advanced use
  buildNameIndexScript,
  electrumScriptHash,
  parseNameScript,
  parseNameFromTx,
  pushData,
  readPushData,
  parseCertPins,
  OP_NAME_UPDATE,
  OP_NAME_FIRSTUPDATE,
  NAME_EXPIRE_DEPTH,
  NAMECOIN_NAME_MAX_BYTES,
};
