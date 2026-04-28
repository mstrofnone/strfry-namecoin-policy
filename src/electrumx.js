'use strict';

const net = require('net');
const tls = require('tls');
const crypto = require('crypto');
const { EventEmitter } = require('events');
const { connect: rawConnect } = require('./connect');
const { HostBreaker } = require('./circuit');
const { NullMetrics } = require('./metrics');

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
 * Transport modes (picked from constructor opts):
 *
 *   - Direct per-resolve TCP/TLS                 (poolKeepaliveMs=0)
 *   - Pooled keepalive TCP/TLS                   (poolKeepaliveMs>0)
 *   - SOCKS5-tunneled either of the above        (socks5={host,port})
 *   - Multi-host with circuit breaker            (hosts=[…], len>=1)
 *   - Happy-eyeballs IPv6/IPv4                   (automatic for direct/pooled)
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
const OP_NAME_UPDATE      = 0x53;
const OP_NAME_FIRSTUPDATE = 0x52;

const NAME_EXPIRE_DEPTH = 36_000;  // Namecoin names expire after ~36k blocks (~36 weeks)
const MAX_HISTORY_WALK = 32;       // cap newest→oldest scan to bound work on adversarial histories
const TIP_CACHE_TTL_MS = 60_000;   // 60s in-process cache for chain tip
const VERSION_HANDSHAKE_TIMEOUT_MS = 2000; // dedicated short timeout for server.version
const NAMECOIN_NAME_MAX_BYTES = 255;  // Namecoin consensus cap on name length

// Module-level chain-tip cache. Stale-by-60s is safe because expiry math
// has a 36000-block grace window.
let cachedTip = null;
let cachedTipAt = 0;

/** Test-only: reset the module-level tip cache. */
function _resetTipCacheForTests() { cachedTip = null; cachedTipAt = 0; }

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

/**
 * Verify a connected TLS socket against a parsed pin list. Throws
 * with a useful message on mismatch / missing certificate. No-op when
 * `pins` is empty.
 */
function verifyCertPins(socket, pins) {
  if (!pins || pins.length === 0) return;
  const peerCert = socket.getPeerCertificate(true);
  if (!peerCert || !peerCert.raw) {
    throw new Error('No peer certificate available to verify pin');
  }
  const derFp = crypto.createHash('sha256').update(peerCert.raw).digest('hex');
  const spkiB64 = peerCert.pubkey
    ? crypto.createHash('sha256').update(peerCert.pubkey).digest('base64')
    : null;
  const matched = pins.some((pin) => {
    if (pin.kind === 'der') return pin.hex === derFp;
    if (pin.kind === 'spki') return spkiB64 != null && pin.b64 === spkiB64;
    return false;
  });
  if (!matched) {
    const observed = `der=${derFp}` + (spkiB64 ? ` spki=sha256/${spkiB64}` : '');
    throw new Error(`Cert pin mismatch: no configured pin matched (observed ${observed})`);
  }
}


class ElectrumXClient extends EventEmitter {
  /**
   * @param {object} opts
   * @param {string}  [opts.host]                 single-host shorthand
   * @param {number}  [opts.port=50002]
   * @param {boolean} [opts.tls=true]
   * @param {Array<{host:string,port:number,tls?:boolean}>} [opts.hosts]
   *                                              multi-host (overrides single)
   * @param {{host:string,port:number}|null} [opts.socks5]
   * @param {number}  [opts.poolKeepaliveMs=0]    0 = per-resolve connections
   * @param {string|null} [opts.certPinSha256]    hex-encoded SHA-256 of DER cert OR comma-separated pin list
   * @param {boolean} [opts.rejectUnauthorized]
   * @param {number}  [opts.timeoutMs=5000]
   * @param {number}  [opts.retries=2]
   * @param {number}  [opts.minConfirmations=1]   minimum confirmations a tx must have to be trusted
   * @param {object}  [opts.metrics]              Metrics or NullMetrics
   * @param {(level:string,...args:any[])=>void} [opts.logger]
   */
  constructor(opts = {}) {
    super();
    const hosts = Array.isArray(opts.hosts) && opts.hosts.length
      ? opts.hosts.map((h) => ({
          host: h.host,
          port: Number(h.port) || ((h.tls ?? opts.tls ?? true) ? 50002 : 50001),
          tls: h.tls ?? (opts.tls !== false),
        }))
      : (opts.host ? [{
          host: opts.host,
          port: Number(opts.port) || ((opts.tls !== false) ? 50002 : 50001),
          tls: opts.tls !== false,
        }] : null);

    if (!hosts) throw new Error('ElectrumXClient: host (or hosts) is required');
    this.hosts = hosts;
    // Back-compat for callers that read .host / .port / .useTls.
    this.host = hosts[0].host;
    this.port = hosts[0].port;
    this.useTls = hosts[0].tls;
    this.breaker = new HostBreaker(hosts, { logger: opts.logger });

    this.socks5 = opts.socks5 || null;
    this.poolKeepaliveMs = Number(opts.poolKeepaliveMs) || 0;
    // Pin list (DER + SPKI). Empty when not pinning.
    this.certPins = parseCertPins(opts.certPinSha256);
    // Back-compat: keep .certPinSha256 set when exactly one DER pin is configured.
    this.certPinSha256 = (this.certPins.length === 1 && this.certPins[0].kind === 'der')
      ? this.certPins[0].hex
      : (this.certPins.length > 0 ? '__pinned__' : null);
    this.rejectUnauthorized = opts.rejectUnauthorized ?? !(this.certPins.length > 0);
    this.timeoutMs = Number(opts.timeoutMs) || 5000;
    this.retries = Number.isFinite(opts.retries) ? opts.retries : 2;
    this.minConfirmations = Number.isFinite(opts.minConfirmations)
      ? Math.max(0, Math.floor(opts.minConfirmations))
      : 1;
    this.metrics = opts.metrics || new NullMetrics();
    this.logger = opts.logger || (() => {});

    /** @type {Map<string, PooledConnection>} pool keyed by `host:port` */
    this.pool = new Map();
  }

  /** Stable pool key. */
  _hostKey(h) { return `${h.host}:${h.port}:${h.tls ? 'tls' : 'tcp'}`; }

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

    // Try up to (retries+1) attempts across hosts. Each attempt picks
    // a host from the circuit breaker (round-robin among healthy ones,
    // or forced probe if all open).
    const maxAttempts = this.retries + 1;
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      const { host, index } = this.breaker.pickNext();
      const t0 = Date.now();
      try {
        const result = await this._queryOnHost(host, name);
        this.breaker.recordSuccess(index);
        this.metrics.observe('lookup_duration_ms', Date.now() - t0);
        return result;
      } catch (err) {
        const dur = Date.now() - t0;
        this.metrics.observe('lookup_duration_ms', dur);
        this.metrics.inc('electrumx_errors_total', { type: classifyError(err) });
        lastErr = err;
        this.logger('debug', `electrumx ${host.host}:${host.port} nameShow(${name}) attempt ${attempt + 1}/${maxAttempts} failed: ${err.message}`);
        // Definitive errors (name expired etc.) propagate immediately
        // without recording a host failure.
        if (err.electrumxDefinitive) throw err;
        this.breaker.recordFailure(index);
        if (attempt < maxAttempts - 1) await sleep(150 * (attempt + 1));
      }
    }
    throw lastErr || new Error('ElectrumX nameShow failed');
  }

  /**
   * Run one nameShow query against a specific host. In pool mode,
   * reuses an existing warm connection; otherwise opens a new one.
   *
   * @param {{host:string,port:number,tls?:boolean}} host
   * @param {string} name
   */
  async _queryOnHost(host, name) {
    if (this.poolKeepaliveMs > 0) {
      return this._queryPooled(host, name);
    }
    return this._queryDedicated(host, name);
  }

  /** Per-resolve dedicated TCP/TLS connection (legacy mode). */
  _queryDedicated(host, name) {
    return new Promise((resolve, reject) => {
      let socket;
      let settled = false;
      let buf = '';
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
        finish(new Error(`ElectrumX timeout after ${this.timeoutMs}ms (${name} via ${host.host}:${host.port})`));
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

      const onConnected = async (sock) => {
        socket = sock;
        socket.setEncoding('utf8');

        // Cert pinning (TLS only). Multi-pin (DER + SPKI) — any-match wins.
        if (host.tls && this.certPins.length > 0) {
          try {
            verifyCertPins(socket, this.certPins);
          } catch (e) {
            return finish(e);
          }
        }


        socket.on('data', (chunk) => {
          buf += chunk;
          let nl;
          while ((nl = buf.indexOf('\n')) !== -1) {
            const line = buf.slice(0, nl).trim();
            buf = buf.slice(nl + 1);
            if (!line) continue;
            let msg;
            try { msg = JSON.parse(line); }
            catch (e) { return finish(new Error(`ElectrumX parse error: ${e.message}`)); }
            if (msg.id == null) continue; // async subscription notification
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
          for (const p of pending.values()) p.reject(new Error('Connection closed'));
          pending.clear();
          finish(new Error('ElectrumX connection closed before response'));
        });

        try {
          const result = await runResolve(send, name, {
            minConfirmations: this.minConfirmations,
            logger: this.logger,
          });
          finish(null, result);
        } catch (err) {
          finish(err);
        }
      };

      // Open the connection (SOCKS5 or direct, TLS or plain).
      rawConnect({
        host: host.host,
        port: host.port,
        tls: !!host.tls,
        rejectUnauthorized: this.rejectUnauthorized,
        socks5: this.socks5,
        timeoutMs: this.timeoutMs,
        logger: this.logger,
      }).then(onConnected, finish);
    });
  }

  /** Pooled-connection query path. */
  async _queryPooled(host, name) {
    const key = this._hostKey(host);
    let pc = this.pool.get(key);
    if (!pc || pc.dead) {
      pc = new PooledConnection({
        host,
        socks5: this.socks5,
        certPins: this.certPins,
        rejectUnauthorized: this.rejectUnauthorized,
        connectTimeoutMs: this.timeoutMs,
        keepaliveMs: this.poolKeepaliveMs,
        logger: this.logger,
        onClose: () => {
          // Drop from the map when this connection terminates.
          if (this.pool.get(key) === pc) this.pool.delete(key);
        },
      });
      this.pool.set(key, pc);
    }
    return pc.request(name, this.timeoutMs, {
      minConfirmations: this.minConfirmations,
      logger: this.logger,
    });
  }

  /** Close all pooled connections. Idempotent. */
  close() {
    for (const pc of this.pool.values()) {
      try { pc.destroy(); } catch (_) {}
    }
    this.pool.clear();
  }
}

// ── Pooled connection ──────────────────────────────────────────────────────

/**
 * Single warm TCP/TLS connection to one ElectrumX host with an internal
 * request queue and idle timeout. Multiple concurrent `request(name)`
 * calls multiplex over the same socket via JSON-RPC ids.
 */
class PooledConnection {
  constructor({ host, socks5, certPins, rejectUnauthorized, connectTimeoutMs, keepaliveMs, logger, onClose }) {
    this.host = host;
    this.socks5 = socks5;
    this.certPins = certPins || [];
    this.rejectUnauthorized = rejectUnauthorized;
    this.connectTimeoutMs = connectTimeoutMs;
    this.keepaliveMs = keepaliveMs;
    this.logger = logger;
    this.onClose = onClose;

    this.socket = null;
    this.connecting = null; // Promise resolving when ready
    this.dead = false;
    this.buf = '';
    /** @type {Map<number, {resolve:Function, reject:Function, timer:any}>} */
    this.pending = new Map();
    this.nextId = 1;
    this.idleTimer = null;
  }

  /**
   * Send a nameShow query. Returns a promise.
   */
  async request(name, queryTimeoutMs, opts = {}) {
    if (this.dead) throw new Error('PooledConnection: already dead');

    await this._ensureConnected();
    if (this.dead) throw new Error('PooledConnection: connection lost');

    this._cancelIdle();
    try {
      const result = await runResolve(
        (m, p) => this._call(m, p, queryTimeoutMs),
        name,
        {
          minConfirmations: opts.minConfirmations,
          logger: opts.logger || this.logger,
        }
      );
      this._scheduleIdle();
      return result;
    } catch (err) {
      // Propagate; if the connection died, _scheduleIdle is a no-op.
      this._scheduleIdle();
      throw err;
    }
  }

  _ensureConnected() {
    if (this.socket && !this.dead) return Promise.resolve();
    if (this.connecting) return this.connecting;
    this.connecting = (async () => {
      try {
        const sock = await rawConnect({
          host: this.host.host,
          port: this.host.port,
          tls: !!this.host.tls,
          rejectUnauthorized: this.rejectUnauthorized,
          socks5: this.socks5,
          timeoutMs: this.connectTimeoutMs,
          logger: this.logger,
        });
        // Cert pinning post-handshake. Multi-pin (DER + SPKI) — any-match wins.
        if (this.host.tls && this.certPins.length > 0) {
          try {
            verifyCertPins(sock, this.certPins);
          } catch (e) {
            sock.destroy();
            throw e;
          }
        }

        sock.setEncoding('utf8');
        sock.on('data', (chunk) => this._onData(chunk));
        sock.on('error', (err) => this._kill(new Error(`pool socket error: ${err.message}`)));
        sock.on('end',   () => this._kill(new Error('pool socket end')));
        sock.on('close', () => this._kill(new Error('pool socket closed')));

        this.socket = sock;
      } finally {
        this.connecting = null;
      }
    })();
    return this.connecting;
  }

  _onData(chunk) {
    this.buf += chunk;
    let nl;
    while ((nl = this.buf.indexOf('\n')) !== -1) {
      const line = this.buf.slice(0, nl).trim();
      this.buf = this.buf.slice(nl + 1);
      if (!line) continue;
      let msg;
      try { msg = JSON.parse(line); }
      catch (_) { continue; }
      if (msg.id == null) continue;
      const p = this.pending.get(msg.id);
      if (!p) continue;
      this.pending.delete(msg.id);
      clearTimeout(p.timer);
      if (msg.error) {
        const em = typeof msg.error === 'object'
          ? (msg.error.message || JSON.stringify(msg.error))
          : String(msg.error);
        p.reject(new Error(`ElectrumX error: ${em}`));
      } else {
        p.resolve(msg.result);
      }
    }
  }

  _call(method, params, timeoutMs) {
    return new Promise((resolve, reject) => {
      if (this.dead || !this.socket) return reject(new Error('PooledConnection: not connected'));
      const id = this.nextId++;
      const timer = setTimeout(() => {
        if (this.pending.has(id)) {
          this.pending.delete(id);
          reject(new Error(`ElectrumX request timeout (${method}) after ${timeoutMs}ms`));
        }
      }, timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      try {
        this.socket.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
      } catch (err) {
        this.pending.delete(id);
        clearTimeout(timer);
        reject(err);
      }
    });
  }

  _kill(err) {
    if (this.dead) return;
    this.dead = true;
    this._cancelIdle();
    if (this.socket) {
      try { this.socket.destroy(); } catch (_) {}
      this.socket = null;
    }
    for (const p of this.pending.values()) {
      clearTimeout(p.timer);
      p.reject(err);
    }
    this.pending.clear();
    if (this.onClose) try { this.onClose(); } catch (_) {}
  }

  _cancelIdle() {
    if (this.idleTimer) {
      clearTimeout(this.idleTimer);
      this.idleTimer = null;
    }
  }

  _scheduleIdle() {
    this._cancelIdle();
    if (this.dead || this.pending.size > 0) return;
    if (!this.keepaliveMs || this.keepaliveMs <= 0) return;
    this.idleTimer = setTimeout(() => {
      this.logger('debug', `pool: idle timeout reached, closing ${this.host.host}:${this.host.port}`);
      this._kill(new Error('idle timeout'));
    }, this.keepaliveMs);
    // Don't keep the event loop alive for an idle pooled connection.
    if (typeof this.idleTimer.unref === 'function') this.idleTimer.unref();
  }

  destroy() { this._kill(new Error('explicit destroy')); }
}

// ── Resolve algorithm ──────────────────────────────────────────────────────

/**
 * Run the Electrum resolve sequence over a `send(method, params)` function.
 * Used by both the per-resolve and pooled paths.
 *
 * Implements the security-critical resolution loop:
 *   - tight handshake timeout (so a dead server can't burn the per-attempt budget)
 *   - module-level chain-tip cache (60s TTL) to avoid every lookup re-fetching the tip
 *   - newest→oldest history walk (capped at MAX_HISTORY_WALK) with confirmation filter
 *   - expiry math against the chosen tx's height, not the latest history entry
 *
 * @param {(method:string, params:any[]) => Promise<any>} send
 * @param {string} name
 * @param {{minConfirmations?:number, logger?:Function}} [opts]
 * @returns {Promise<{name:string,value:string,txid:string,height:number,expires_in?:number,tip?:number}|null>}
 */
async function runResolve(send, name, opts = {}) {
  const minConfirmations = Number.isFinite(opts.minConfirmations) ? opts.minConfirmations : 1;
  const logger = opts.logger || (() => {});

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
    minConfirmations,
    fetchTx,
    logger,
  });
}

// ── Script / scripthash helpers ────────────────────────────────────────────

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

function buildNameIndexScript(nameBytes) {
  return Buffer.concat([
    Buffer.from([OP_NAME_UPDATE]),
    pushData(nameBytes),
    pushData(Buffer.alloc(0)),
    Buffer.from([OP_2DROP, OP_DROP, OP_RETURN]),
  ]);
}

function electrumScriptHash(script) {
  const h = crypto.createHash('sha256').update(script).digest();
  return Buffer.from(h).reverse().toString('hex');
}

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

function parseNameFromTx(tx, expectedName) {
  if (!tx || typeof tx !== 'object' || !Array.isArray(tx.vout)) return null;
  for (const vout of tx.vout) {
    const hex = vout && vout.scriptPubKey && vout.scriptPubKey.hex;
    if (typeof hex !== 'string') continue;
    const first = hex.slice(0, 2).toLowerCase();
    if (first !== '53' && first !== '52') continue;
    let script;
    try { script = Buffer.from(hex, 'hex'); }
    catch (_) { continue; }
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

function classifyError(err) {
  const msg = err && err.message ? err.message : String(err);
  if (/timeout/i.test(msg)) return 'timeout';
  if (/cert pin/i.test(msg)) return 'cert-pin';
  if (/socket error|ECONNRESET|EPIPE|ENETUNREACH|EHOSTUNREACH/i.test(msg)) return 'socket';
  if (/parse error/i.test(msg)) return 'parse';
  if (/closed before response|connection closed/i.test(msg)) return 'closed';
  if (/SOCKS5/i.test(msg)) return 'socks5';
  if (/TLS/i.test(msg)) return 'tls';
  if (/DNS/i.test(msg)) return 'dns';
  if (/ECONNREFUSED/i.test(msg)) return 'refused';
  if (/all addresses failed/i.test(msg)) return 'unreachable';
  return 'other';
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
  PooledConnection,
  buildNameIndexScript,
  electrumScriptHash,
  parseNameScript,
  parseNameFromTx,
  pushData,
  readPushData,
  parseCertPins,
  verifyCertPins,
  classifyError,
  OP_NAME_UPDATE,
  OP_NAME_FIRSTUPDATE,
  NAME_EXPIRE_DEPTH,
  MAX_HISTORY_WALK,
  TIP_CACHE_TTL_MS,
  selectNameRowFromHistory,
  _resetTipCacheForTests,
  NAMECOIN_NAME_MAX_BYTES,
};
