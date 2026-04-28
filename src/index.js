'use strict';

/**
 * strfry write-policy plugin: Namecoin .bit NIP-05 verification.
 *
 * Protocol (see https://github.com/hoytech/strfry/blob/master/docs/plugins.md):
 *   stdin : one JSON object per line, with keys:
 *             type ("new"), event, receivedAt, sourceType, sourceInfo, authed
 *   stdout: one JSON object per line, with keys:
 *             id (event id), action (accept|reject|shadowReject), msg?
 *
 * Behavior (see README for full config):
 *   kind 0 (metadata):
 *     - If content.nip05 ends in ".bit": resolve via ElectrumX and verify
 *       that the declared pubkey matches event.pubkey. Accept on match,
 *       reject otherwise.
 *     - If content.nip05 is non-.bit: accept (unless NAMECOIN_POLICY_ALLOW_NON_BIT=false).
 *     - If content.nip05 missing/invalid: accept.
 *   other kinds:
 *     - Default (mode=kind0-only): accept.
 *     - mode=all-kinds-require-bit: require that the author's pubkey has
 *       been seen in a verified .bit kind:0 during this process's lifetime
 *       (cached). Otherwise reject.
 */

const readline = require('readline');
const { ElectrumXClient } = require('./electrumx');
const { NamecoinResolver } = require('./resolver');
const { LRUCache } = require('./cache');
const { PersistentLRU } = require('./persistent-cache');
const { Metrics, NullMetrics } = require('./metrics');
const { loadConfig, makeLogger } = require('./config');

/**
 * Construct and run the plugin using process.stdin/stdout.
 */
async function run({ env = process.env, stdin = process.stdin, stdout = process.stdout } = {}) {
  let config;
  try {
    config = loadConfig(env);
  } catch (err) {
    // Fatal config errors -> log and exit so strfry shows an internal-error.
    // This only happens at startup; once running we never throw to stdout.
    console.error(`[strfry-namecoin-policy] fatal config error: ${err.message}`);
    process.exit(2);
  }
  const logger = makeLogger(config.logLevel);

  if (!config.host) {
    logger('info', 'NAMECOIN_ELECTRUMX_HOST not set — plugin will accept all events without verification.');
  }

  // ── Metrics ─────────────────────────────────────────────────────────
  const metrics = config.metricsPort > 0 ? new Metrics() : new NullMetrics();
  if (config.metricsPort > 0) {
    try {
      await metrics.startServer({ port: config.metricsPort, host: '127.0.0.1', logger });
    } catch (err) {
      logger('info', `failed to start metrics listener on 127.0.0.1:${config.metricsPort}: ${err.message}`);
    }
  }

  const client = (config.host || (config.hosts && config.hosts.length)) ? new ElectrumXClient({
    host: config.host,
    port: config.port,
    tls:  config.tls,
    hosts: config.hosts,
    socks5: config.socks5,
    poolKeepaliveMs: config.poolKeepaliveMs,
    certPinSha256: config.certPinSha256,
    rejectUnauthorized: config.rejectUnauthorized,
    timeoutMs: config.timeoutMs,
    retries:   config.retries,
    metrics,
    logger,
  }) : null;

  // ── Caches (persistent if NAMECOIN_POLICY_CACHE_PATH set) ───────────
  const resolverCache = makeCache({
    cachePath: config.cachePath,
    namespace: 'resolver',
    max: 2000,
    ttlMs: config.cacheTtlMs,
    logger,
  });
  const verifiedAuthors = makeCache({
    cachePath: config.cachePath,
    namespace: 'verifiedAuthors',
    max: 20_000,
    ttlMs: config.cacheTtlMs,
    logger,
  });

  const resolver = client ? new NamecoinResolver({
    client,
    cache: resolverCache,
    metrics,
    logger,
  }) : null;

  const handler = makeHandler({ config, resolver, verifiedAuthors, metrics, logger });

  const rl = readline.createInterface({
    input: stdin,
    output: stdout,
    terminal: false,
    crlfDelay: Infinity,
  });

  rl.on('line', async (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    let req;
    try {
      req = JSON.parse(trimmed);
    } catch (err) {
      logger('info', `malformed input line: ${err.message}`);
      // Can't echo an id — the safest thing is to emit nothing and let strfry time out,
      // but that stalls the relay. Instead emit a reject with id=null; strfry ignores
      // unknown-id responses, but older versions tolerate it.
      writeLine(stdout, { id: null, action: 'reject', msg: 'invalid: malformed plugin input' });
      return;
    }

    let res;
    try {
      res = await handler(req);
    } catch (err) {
      logger('info', `handler error: ${err.stack || err.message}`);
      res = safeErrorResponse(req, 'internal: namecoin policy handler error');
    }
    writeLine(stdout, res);
  });

  // Never exit on stdin end — strfry may reopen. But readline's 'close'
  // fires when stdin hits EOF; exiting cleanly is fine then.
  rl.on('close', () => {
    logger('debug', 'stdin closed, exiting');
    process.exit(0);
  });
}

/**
 * Build the per-request handler. Exposed for unit tests so we can feed
 * crafted input messages without spinning up readline/stdin.
 *
 * @returns {(req:any) => Promise<{id:any, action:string, msg?:string}>}
 */
function makeHandler({ config, resolver, verifiedAuthors, metrics, logger }) {
  const m = metrics || new NullMetrics();
  const accept = (id) => { m.inc('acceptances_total'); return { id, action: 'accept' }; };
  const reject = (id, reason, msg) => {
    m.inc('rejections_total', { reason });
    return { id, action: 'reject', msg };
  };

  return async function handle(req) {
    if (!req || typeof req !== 'object') {
      return reject(null, 'non-object', 'invalid: non-object plugin message');
    }
    if (req.type !== 'new') {
      logger('debug', `ignoring non-new request type: ${req.type}`);
      return accept(req?.event?.id ?? null);
    }

    const event = req.event;
    if (!event || typeof event !== 'object' || typeof event.id !== 'string') {
      return reject(null, 'missing-event', 'invalid: missing event');
    }
    const id = event.id;
    const kind = Number(event.kind);
    const pubkey = typeof event.pubkey === 'string' ? event.pubkey.toLowerCase() : '';

    if (!pubkey) {
      return reject(id, 'missing-pubkey', 'invalid: missing event.pubkey');
    }

    // ── Kind 0: metadata. Check nip05 field. ──
    if (kind === 0) {
      const nip05 = extractNip05(event.content);
      if (!nip05) {
        logger('debug', `kind0 ${id} has no nip05 — accept`);
        return accept(id);
      }

      const lowered = nip05.toLowerCase();
      const isNamecoin = NamecoinResolver.isNamecoinIdentifier(lowered);

      if (!isNamecoin) {
        if (config.allowNonBit) {
          logger('debug', `kind0 ${id} nip05=${nip05} non-.bit — accept (pass-through)`);
          return accept(id);
        }
        return reject(id, 'non-bit-blocked',
          'blocked: only Namecoin .bit NIP-05 identifiers are accepted on this relay');
      }

      if (!resolver) {
        // No resolver configured — treat as soft-fail.
        logger('info', `kind0 ${id} has .bit NIP-05 but no ElectrumX configured — accept`);
        return accept(id);
      }

      const t0 = Date.now();
      const resolved = await resolver.resolve(lowered);
      m.observe('lookup_duration_ms', Date.now() - t0);

      if (!resolved) {
        return reject(id, 'unresolved',
          `invalid: Namecoin NIP-05 "${nip05}" could not be resolved (name missing, expired, or malformed)`);
      }
      if (resolved.pubkey !== pubkey) {
        return reject(id, 'pubkey-mismatch',
          `invalid: Namecoin NIP-05 "${nip05}" maps to ${resolved.pubkey.slice(0, 16)}… but event.pubkey is ${pubkey.slice(0, 16)}…`);
      }

      // Remember this pubkey for all-kinds-require-bit mode.
      verifiedAuthors.set(pubkey, true);
      logger('info', `kind0 ${id} verified Namecoin NIP-05 "${nip05}" → ${pubkey.slice(0, 16)}…`);
      return accept(id);
    }

    // ── Non-kind-0 events ──
    if (config.mode === 'all-kinds-require-bit') {
      if (verifiedAuthors.has(pubkey)) {
        return accept(id);
      }
      return reject(id, 'unverified-author',
        'blocked: this relay requires a verified Namecoin .bit NIP-05 identity (publish a kind:0 first)');
    }

    return accept(id);
  };
}

/**
 * Pull the `nip05` string out of a kind:0 event's content.
 */
function extractNip05(content) {
  if (typeof content !== 'string' || !content) return null;
  let doc;
  try { doc = JSON.parse(content); } catch (_) { return null; }
  if (!doc || typeof doc !== 'object') return null;
  const nip05 = doc.nip05;
  if (typeof nip05 !== 'string') return null;
  const trimmed = nip05.trim();
  return trimmed || null;
}

function safeErrorResponse(req, msg) {
  const id = (req && req.event && typeof req.event.id === 'string') ? req.event.id : null;
  return { id, action: 'reject', msg };
}

function writeLine(stream, obj) {
  try {
    stream.write(JSON.stringify(obj) + '\n');
  } catch (err) {
    // Truly can't recover — fall through
    console.error('[strfry-namecoin-policy] failed to write response:', err.message);
  }
}

/**
 * Build a cache: PersistentLRU when cachePath is set, otherwise LRUCache.
 * If PersistentLRU construction fails (disk perms, sqlite corruption, etc.),
 * fall back to in-memory LRU and log loudly. We don't want a cache-disk
 * issue to take the relay offline.
 */
function makeCache({ cachePath, namespace, max, ttlMs, logger }) {
  if (!cachePath) return new LRUCache({ max, ttlMs });
  try {
    return new PersistentLRU({
      path: cachePath,
      namespace,
      max,
      ttlMs,
      logger,
    });
  } catch (err) {
    logger('info', `persistent cache (${namespace}) at ${cachePath} unavailable: ${err.message} — using in-memory only`);
    return new LRUCache({ max, ttlMs });
  }
}

module.exports = { run, makeHandler, extractNip05, makeCache };
