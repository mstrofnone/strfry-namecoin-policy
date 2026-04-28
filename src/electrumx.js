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
const MAX_HISTORY_WALK = 32;       // cap newest→oldest scan to bound work on adversarial histories
const TIP_CACHE_TTL_MS = 60_000;   // 60s in-process cache for chain tip
const VERSION_HANDSHAKE_TIMEOUT_MS = 2000; // dedicated short timeout for server.version

// Module-level chain-tip cache. Stale-by-60s is safe because expiry math
// has a 36000-block grace window.
let cachedTip = null;
let cachedTipAt = 0;

/** Test-only: reset the module-level tip cache. */
function _resetTipCacheForTests() { cachedTip = null; cachedTipAt = 0; }

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
   * @param {number} [opts.minConfirmations=1]  minimum confirmations a tx must have to be trusted
   * @param {(level:string,...args:any[])=>void} [opts.logger]
   */
  constructor(opts = {}) {
    super();
    if (!opts.host) throw new Error('ElectrumXClient: host is required');
    this.host = opts.host;
    this.useTls = opts.tls !== false;
    this.port = Number(opts.port) || (this.useTls ? 50002 : 50001);
    this.certPinSha256 = opts.certPinSha256
      ? String(opts.certPinSha256).toLowerCase().replace(/[^0-9a-f]/g, '')
      : null;
    this.rejectUnauthorized = opts.rejectUnauthorized ?? !this.certPinSha256;
    this.timeoutMs = Number(opts.timeoutMs) || 5000;
    this.retries = Number.isFinite(opts.retries) ? opts.retries : 2;
    this.minConfirmations = Number.isFinite(opts.minConfirmations)
      ? Math.max(0, Math.floor(opts.minConfirmations))
      : 1;
    this.logger = opts.logger || (() => {});
  }

  /**
   * Resolve a Namecoin name to its current value + metadata.
   *
   * @param {string} name  e.g. "d/testls"
   * @returns {Promise<{name:string,value:string,txid:string,height:number,expires_in?:number,tip?:number}|null>}
   */
  async nameShow(name) {
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
        if (this.useTls && this.certPinSha256) {
          try {
            const peerCert = socket.getPeerCertificate(true);
            if (!peerCert || !peerCert.raw) {
              return finish(new Error('No peer certificate available to verify pin'));
            }
            const fp = crypto.createHash('sha256').update(peerCert.raw).digest('hex');
            if (fp !== this.certPinSha256) {
              return finish(new Error(
                `Cert pin mismatch: expected ${this.certPinSha256} got ${fp}`
              ));
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
        // 1. Handshake — many servers reject subsequent calls (or drop the
        //    connection) if you race past the version handshake. Treat
        //    failure here as a connect-level failure so the retry loop
        //    kicks in. Use a tight timeout so a dead server doesn't burn
        //    the entire per-attempt budget on the handshake alone.
        try {
          await withTimeout(
            send('server.version', ['strfry-namecoin-policy/0.2', '1.4']),
            VERSION_HANDSHAKE_TIMEOUT_MS,
            `server.version handshake timed out after ${VERSION_HANDSHAKE_TIMEOUT_MS}ms`
          );
        } catch (e) {
          throw new Error(`ElectrumX handshake failed: ${e.message}`);
        }

        // 2. Canonical name-index scripthash
        const script = buildNameIndexScript(Buffer.from(name, 'ascii'));
        const scripthash = electrumScriptHash(script);

        // 3. History
        const history = await send('blockchain.scripthash.get_history', [scripthash]);
        if (!Array.isArray(history) || history.length === 0) {
          // No history ⇒ name has never existed (or the server has no name index).
          return null;
        }

        // 4. Tip (for confirmation filter + expiry math). Use module-level
        //    cache; only call subscribe on cache miss.
        let tip = null;
        const now = Date.now();
        if (cachedTip != null && (now - cachedTipAt) < TIP_CACHE_TTL_MS) {
          tip = cachedTip;
        } else {
          try {
            const headers = await send('blockchain.headers.subscribe', []);
            if (headers && typeof headers.height === 'number') {
              tip = headers.height;
              cachedTip = tip;
              cachedTipAt = now;
            }
          } catch (_) { /* some servers may not have subscribe; tolerate */ }
        }

        // 5+6+7. Filter history, walk newest → oldest, parse, expiry-check.
        const fetchTx = (txHash) => send('blockchain.transaction.get', [txHash, true]);
        return await selectNameRowFromHistory({
          name, history, tip,
          minConfirmations: this.minConfirmations,
          fetchTx,
          logger: this.logger,
        });
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

// Namecoin's `rand` value in NAME_FIRSTUPDATE is exactly 20 bytes
// (160 bits). Anything else is either malformed or an UPDATE-shaped
// script that happens to start with the OP_NAME_FIRSTUPDATE opcode
// because of a script-template collision. Validate it strictly so we
// don't mis-parse and treat a junk middle push as `rand`.
const NAME_FIRSTUPDATE_RAND_LEN = 20;

/**
 * Parse a NAME_* script and return {name, value}.
 *
 * Script layout:
 *   <OP_NAME_UPDATE or OP_NAME_FIRSTUPDATE> <push(name)> [<push(rand=20B)>] <push(value)> OP_2DROP OP_DROP <address script...>
 *
 * NAME_FIRSTUPDATE has an extra 'rand' push between name and value
 * which MUST be exactly 20 bytes. If a candidate FIRSTUPDATE script
 * has a middle push of any other length we fall through to the
 * 2-push (UPDATE-style) interpretation rather than blindly skipping
 * a push of unknown size.
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
    // name, rand(20B), value
    const rand = readPushData(script, first.next);
    if (rand && rand.data.length === NAME_FIRSTUPDATE_RAND_LEN) {
      const v = readPushData(script, rand.next);
      if (!v) return null;
      valueBuf = v.data;
    } else {
      // Malformed FIRSTUPDATE — fall back to the 2-push UPDATE shape
      // rather than mis-parsing the middle push as `rand`.
      const v = readPushData(script, first.next);
      if (!v) return null;
      valueBuf = v.data;
    }
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

/**
 * Pure(ish) helper: given an ElectrumX history list, the chain tip, a
 * confirmation requirement, and a tx fetcher, pick the highest-height
 * confirmed tx whose vouts contain a NAME_UPDATE / NAME_FIRSTUPDATE for
 * the requested name. Returns the same shape as nameShow.
 *
 * Implements three correctness fixes:
 *   1. Filters out mempool/unconfirmed (height <= 0) and entries with
 *      fewer than minConfirmations confirmations BEFORE picking.
 *   2. Walks newest → oldest (capped at MAX_HISTORY_WALK) so a junk UTXO
 *      that landed on the canonical scripthash can't censor the real
 *      name.
 *   3. Uses the actual chosen tx's height for expiry math.
 *
 * @param {object} args
 * @param {string} args.name
 * @param {Array<{tx_hash:string, height:number}>} args.history
 * @param {number|null} args.tip
 * @param {number} args.minConfirmations
 * @param {(txHash:string)=>Promise<any>} args.fetchTx
 * @param {(level:string,...args:any[])=>void} [args.logger]
 * @returns {Promise<{name:string,value:string,txid:string,height:number,expires_in?:number,tip?:number}|null>}
 */
async function selectNameRowFromHistory({ name, history, tip, minConfirmations, fetchTx, logger }) {
  const log = logger || (() => {});
  if (!Array.isArray(history) || history.length === 0) return null;

  const minConf = Number.isFinite(minConfirmations) ? Math.max(0, Math.floor(minConfirmations)) : 1;

  // Filter: drop unconfirmed (height <= 0) and under-confirmed entries.
  const filtered = [];
  for (const h of history) {
    if (!h || typeof h.tx_hash !== 'string') continue;
    const ht = typeof h.height === 'number' ? h.height : 0;
    if (ht <= 0) continue;
    if (tip != null && minConf > 0) {
      const conf = (tip - ht) + 1;
      if (conf < minConf) continue;
    }
    filtered.push({ tx_hash: h.tx_hash, height: ht });
  }
  if (filtered.length === 0) return null;

  // Newest → oldest by height.
  filtered.sort((a, b) => b.height - a.height);

  // Walk; pick first tx whose vouts contain a NAME_* for the exact name.
  const walk = filtered.slice(0, MAX_HISTORY_WALK);
  let chosenHeight = 0;
  let chosenTxHash = null;
  let chosenParsed = null;
  for (const entry of walk) {
    let tx;
    try {
      tx = await fetchTx(entry.tx_hash);
    } catch (e) {
      log('debug', `electrumx tx.get(${entry.tx_hash}) failed: ${e.message}`);
      continue;
    }
    const parsed = parseNameFromTx(tx, name);
    if (!parsed) continue;
    chosenHeight = entry.height;
    chosenTxHash = entry.tx_hash;
    chosenParsed = parsed;
    break;
  }
  if (!chosenParsed) return null;

  // Expiry uses the chosen tx's height — not the latest history entry.
  if (tip != null && chosenHeight > 0 && (tip - chosenHeight) >= NAME_EXPIRE_DEPTH) {
    const err = new Error(`Namecoin name "${name}" expired`);
    err.electrumxDefinitive = true;
    throw err;
  }

  const result = {
    name: chosenParsed.name,
    value: chosenParsed.value,
    txid: chosenTxHash,
    height: chosenHeight,
  };
  if (tip != null && chosenHeight > 0) {
    result.expires_in = NAME_EXPIRE_DEPTH - (tip - chosenHeight);
    result.tip = tip;
  }
  return result;
}

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

/**
 * Wrap a promise with a per-call timeout. The original promise keeps
 * running but the returned promise rejects after `ms`.
 * @template T
 * @param {Promise<T>} p
 * @param {number} ms
 * @param {string} msg
 * @returns {Promise<T>}
 */
function withTimeout(p, ms, msg) {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(msg)), ms);
    p.then(
      (v) => { clearTimeout(t); resolve(v); },
      (e) => { clearTimeout(t); reject(e); }
    );
  });
}

module.exports = {
  ElectrumXClient,
  // Exposed for unit tests / advanced use
  buildNameIndexScript,
  electrumScriptHash,
  parseNameScript,
  parseNameFromTx,
  pushData,
  readPushData,
  OP_NAME_UPDATE,
  OP_NAME_FIRSTUPDATE,
  NAME_EXPIRE_DEPTH,
  MAX_HISTORY_WALK,
  TIP_CACHE_TTL_MS,
  selectNameRowFromHistory,
  _resetTipCacheForTests,
};
