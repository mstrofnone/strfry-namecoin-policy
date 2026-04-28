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

const NAME_EXPIRE_DEPTH = 36_000;  // ~36 weeks

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
   * @param {string|null} [opts.certPinSha256]    hex-encoded SHA-256 of DER cert
   * @param {boolean} [opts.rejectUnauthorized]
   * @param {number}  [opts.timeoutMs=5000]
   * @param {number}  [opts.retries=2]
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
    this.breaker = new HostBreaker(hosts, { logger: opts.logger });

    this.socks5 = opts.socks5 || null;
    this.poolKeepaliveMs = Number(opts.poolKeepaliveMs) || 0;
    this.certPinSha256 = opts.certPinSha256
      ? String(opts.certPinSha256).toLowerCase().replace(/[^0-9a-f]/g, '')
      : null;
    this.rejectUnauthorized = opts.rejectUnauthorized ?? !this.certPinSha256;
    this.timeoutMs = Number(opts.timeoutMs) || 5000;
    this.retries = Number.isFinite(opts.retries) ? opts.retries : 2;
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

        // Cert pinning (TLS only).
        if (host.tls && this.certPinSha256) {
          try {
            const peerCert = socket.getPeerCertificate(true);
            if (!peerCert || !peerCert.raw) {
              return finish(new Error('No peer certificate available to verify pin'));
            }
            const fp = crypto.createHash('sha256').update(peerCert.raw).digest('hex');
            if (fp !== this.certPinSha256) {
              return finish(new Error(`Cert pin mismatch: expected ${this.certPinSha256} got ${fp}`));
            }
          } catch (e) {
            return finish(new Error(`Cert pin verification failed: ${e.message}`));
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
          const result = await runResolve(send, name, this.timeoutMs);
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
        certPinSha256: this.certPinSha256,
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
    return pc.request(name, this.timeoutMs);
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
  constructor({ host, socks5, certPinSha256, rejectUnauthorized, connectTimeoutMs, keepaliveMs, logger, onClose }) {
    this.host = host;
    this.socks5 = socks5;
    this.certPinSha256 = certPinSha256;
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
  async request(name, queryTimeoutMs) {
    if (this.dead) throw new Error('PooledConnection: already dead');

    await this._ensureConnected();
    if (this.dead) throw new Error('PooledConnection: connection lost');

    this._cancelIdle();
    try {
      const result = await runResolve((m, p) => this._call(m, p, queryTimeoutMs), name, queryTimeoutMs);
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
        // Cert pinning post-handshake.
        if (this.host.tls && this.certPinSha256) {
          const peerCert = sock.getPeerCertificate(true);
          if (!peerCert || !peerCert.raw) {
            sock.destroy();
            throw new Error('No peer certificate available to verify pin');
          }
          const fp = crypto.createHash('sha256').update(peerCert.raw).digest('hex');
          if (fp !== this.certPinSha256) {
            sock.destroy();
            throw new Error(`Cert pin mismatch: expected ${this.certPinSha256} got ${fp}`);
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
 * @param {(method:string, params:any[]) => Promise<any>} send
 * @param {string} name
 * @returns {Promise<{name:string,value:string,txid:string,height:number,expires_in?:number,tip?:number}|null>}
 */
async function runResolve(send, name /* , timeoutMs */) {
  // 1. Handshake — best effort
  try { await send('server.version', ['strfry-namecoin-policy/0.2', '1.4']); } catch (_) {}

  // 2. Canonical name-index scripthash
  const script = buildNameIndexScript(Buffer.from(name, 'ascii'));
  const scripthash = electrumScriptHash(script);

  // 3. History
  const history = await send('blockchain.scripthash.get_history', [scripthash]);
  if (!Array.isArray(history) || history.length === 0) return null;
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
  } catch (_) { /* tolerate */ }

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

function parseNameScript(script) {
  if (!script || script.length < 4) return null;
  const op = script[0];
  if (op !== OP_NAME_UPDATE && op !== OP_NAME_FIRSTUPDATE) return null;

  const first = readPushData(script, 1);
  if (!first) return null;

  let valueBuf = null;
  if (op === OP_NAME_FIRSTUPDATE) {
    const rand = readPushData(script, first.next);
    if (!rand) return null;
    const v = readPushData(script, rand.next);
    if (!v) return null;
    valueBuf = v.data;
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

module.exports = {
  ElectrumXClient,
  PooledConnection,
  buildNameIndexScript,
  electrumScriptHash,
  parseNameScript,
  parseNameFromTx,
  pushData,
  readPushData,
  classifyError,
  OP_NAME_UPDATE,
  OP_NAME_FIRSTUPDATE,
  NAME_EXPIRE_DEPTH,
};
