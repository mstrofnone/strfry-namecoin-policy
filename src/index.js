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
const { TokenBucket } = require('./ratelimit');
const { PersistentLRU } = require('./persistent-cache');
const { Metrics, NullMetrics } = require('./metrics');
const { loadConfig, makeLogger } = require('./config');
const { Nip9aLoader } = require('./nip9a-loader');
const { validate: nip9aValidate, eventByteSize: nip9aSize, Violations: NIP9A_V } = require('./nip9a-validator');
const { NIP9A_KIND } = require('./nip9a-parser');

function emitInsecureBanner() {
  const bar = '='.repeat(64);
  console.error(bar);
  console.error('WARNING: NAMECOIN_ELECTRUMX_INSECURE=true — TLS verification DISABLED.');
  console.error('Your ElectrumX traffic is vulnerable to MITM. Use NAMECOIN_ELECTRUMX_CERT_PIN instead.');
  console.error(bar);
}

function emitNoHostBanner({ softFail }) {
  if (softFail) {
    console.error('[strfry-namecoin-policy] WARN: NAMECOIN_ELECTRUMX_HOST not set and NAMECOIN_POLICY_SOFT_FAIL=true — accepting all events without verification (INSECURE).');
  } else {
    console.error('[strfry-namecoin-policy] WARN: NAMECOIN_ELECTRUMX_HOST not set — rejecting all .bit lookups (set NAMECOIN_POLICY_SOFT_FAIL=true to bypass)');
  }
}

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

  if (config.insecure) emitInsecureBanner();
  if (!config.host) emitNoHostBanner({ softFail: config.softFail });

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
    minConfirmations: config.minConfirmations,
    metrics,
    logger,
  }) : null;

  const rateLimiter = client ? new TokenBucket({
    rps: config.lookupRps,
    burst: config.lookupBurst,
    queueMs: config.lookupQueueMs,
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
    cacheTtlMs: config.cacheTtlMs,
    negCacheTtlMs: config.negCacheTtlMs,
    metrics,
    logger,
    rateLimiter,
  }) : null;

  // ── NIP-9A rules loader (https://github.com/nostr-protocol/nips/pull/2331) ──
  // Only constructed when at least one of file or community is set. If both
  // are unset the loader is null and no rules enforcement runs (back-compat
  // for v0.2.x deployments).
  let nip9a = null;
  if (config.nip9aRulesFile || config.nip9aCommunity) {
    nip9a = new Nip9aLoader({
      filePath: config.nip9aRulesFile,
      community: config.nip9aCommunity,
      logger,
    });
    nip9a.start();
    process.on('SIGHUP', () => {
      logger('info', 'nip9a: SIGHUP received, reloading rules file');
      nip9a.reload();
    });
  }

  const handler = makeHandler({ config, resolver, verifiedAuthors, metrics, logger, nip9a });

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
function makeHandler({ config, resolver, verifiedAuthors, metrics, logger, nip9a }) {
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

    // ── NIP-9A rules events: never block protocol traffic. The owner needs
    //    to be able to publish rules updates even if the current rules
    //    document does not whitelist kind:34551. Offer to the loader for
    //    live updates, then accept iff the .bit author gate would otherwise
    //    let the author publish anything (mode=kind0-only always, or
    //    mode=all-kinds-require-bit when the pubkey is in verifiedAuthors).
    //    See nip9a-refimpl/bin/strfry-policy.js for the same convention.
    if (kind === NIP9A_KIND && nip9a) {
      const accepted = nip9a.offer(event, 'stream');
      logger('debug', `kind ${NIP9A_KIND} (NIP-9A rules) ${accepted ? 'absorbed' : 'ignored by loader'}`);
      if (config.mode !== 'all-kinds-require-bit' || verifiedAuthors.has(pubkey)) {
        return accept(id);
      }
      return reject(id, 'unverified-author',
        'blocked: rules events from this pubkey require a verified Namecoin .bit NIP-05 first (publish a kind:0 first)');
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
        // No ElectrumX configured. Default = fail closed (reject .bit
        // lookups we can't verify). Setting NAMECOIN_POLICY_SOFT_FAIL=true
        // restores the legacy accept-everything behavior.
        if (config.softFail) {
          logger('info', `kind0 ${id} has .bit NIP-05 but no ElectrumX configured \u2014 accept (SOFT_FAIL)`);
          return accept(id);
        }
        return reject(id, 'no-resolver',
          'blocked: Namecoin .bit NIP-05 verification unavailable (no ElectrumX configured)');
      }

      const t0 = Date.now();
      const resolved = await resolver.resolve(lowered);
      m.observe('lookup_duration_ms', Date.now() - t0);

      if (!resolved) {
        if (resolver.lastWasRateLimited) {
          return reject(id, 'rate-limited',
            'rate-limited: too many .bit lookups in flight, try again');
        }
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

    // ── Non-kind-0 events: .bit author gate first, then NIP-9A rules gate. ──
    if (config.mode === 'all-kinds-require-bit') {
      if (!verifiedAuthors.has(pubkey)) {
        return reject(id, 'unverified-author',
          'blocked: this relay requires a verified Namecoin .bit NIP-05 identity (publish a kind:0 first)');
      }
    }

    // ── NIP-9A rules gate. Applies AFTER .bit verification so the rules
    //    document only sees events from authors the relay has already
    //    decided are allowed to write at all. The whitelist `p allow` tags
    //    are layered on top: NIP-9A's kind whitelist (`k`) gates the
    //    baseline; per-pubkey `p allow` tags can DENY only (per spec
    //    semantics, allow is informational unless the rules expand kinds
    //    via a parallel rules doc).
    //
    //    See README "NIP-9A integration" and `nip9a-validator.js` for the
    //    exact evaluation order.
    if (nip9a && (nip9a.hasActive() || config.nip9aRequireRules)) {
      const rules = nip9a.active();
      if (!rules) {
        if (config.nip9aRequireRules) {
          return reject(id, 'nip9a-no-rules',
            'blocked: no NIP-9A rules document in force (relay startup or misconfiguration)');
        }
      } else {
        const violation = nip9aValidate(rules, {
          author: pubkey,
          kind,
          sizeBytes: nip9aSize(event),
          // No quota tracking in this layer; see README "Limitations".
          // No WoT resolver here; relays SHOULD defer WoT to clients per NIP-9A.
        });
        if (violation) {
          return reject(id, `nip9a:${violation.type}`,
            `nip-9a: ${humanise(violation)}`);
        }
      }
    }

    // ── Optional defence-in-depth: reject kind:1 with imeta tags from
    //    non-whitelisted authors. NIP-9A's `k` tag whitelists kinds, but
    //    kind:1 events can still carry file attachments via `imeta` tags
    //    (NIP-92) pointing at Blossom / IPFS / arbitrary http(s) hosts.
    //    Operators wanting hard "text-only kind:1" should enable this and
    //    list trusted uploaders as `p allow` in the rules.
    if (config.nip9aRejectImetaKind1 && kind === 1 && hasImetaTag(event) && !isWhitelisted(nip9a, pubkey)) {
      return reject(id, 'nip9a:imeta-blocked',
        'blocked: kind:1 with imeta media tags requires whitelist (publish via an allowed pubkey)');
    }

    return accept(id);
  };
}

function humanise(v) {
  switch (v.type) {
    case NIP9A_V.STALE_RULES:        return `stale rules (created_at=${v.rulesCreatedAt} < min=${v.minRulesCreatedAt})`;
    case NIP9A_V.AUTHOR_DENIED:      return `author ${v.author.slice(0,16)}… is on the deny-list for this community`;
    case NIP9A_V.KIND_NOT_ALLOWED:   return `kind ${v.kind} is not allowed by community rules (whitelisted kinds only)`;
    case NIP9A_V.KIND_SIZE_EXCEEDED: return `kind ${v.kind} event of ${v.sizeBytes}B exceeds per-kind cap ${v.maxBytes}B`;
    case NIP9A_V.MAX_SIZE_EXCEEDED:  return `event of ${v.sizeBytes}B exceeds max_event_size ${v.maxBytes}B`;
    case NIP9A_V.QUOTA_EXCEEDED:     return `kind ${v.kind} quota of ${v.maxPerDay}/day reached for this author (${v.postsToday} already today)`;
    case NIP9A_V.WOT_GATE_FAILED:    return `web-of-trust gate (${v.gateCount}) refused this author`;
    default:                          return `rule violation: ${v.type}`;
  }
}

function hasImetaTag(event) {
  if (!event || !Array.isArray(event.tags)) return false;
  for (const t of event.tags) {
    if (Array.isArray(t) && t[0] === 'imeta') return true;
  }
  return false;
}

function isWhitelisted(nip9a, pubkey) {
  if (!nip9a) return false;
  const rules = nip9a.active();
  if (!rules) return false;
  for (const r of rules.pubkeyRules) {
    if (r.pubkey === pubkey && r.policy === 'allow') return true;
  }
  return false;
}

/**
 * Pull the `nip05` string out of a kind:0 event's content.
 */
function extractNip05(content) {
  if (typeof content !== 'string' || !content) return null;
  let doc;
  try { doc = JSON.parse(content); } catch (_) { return null; }
  if (!doc || typeof doc !== 'object') return null;
  // typeof [] === 'object' — reject arrays so a kind:0 with content
  // = '["alice@x.bit"]' can't sneak through.
  if (Array.isArray(doc)) return null;
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

module.exports = { run, makeHandler, extractNip05, makeCache, hasImetaTag, isWhitelisted, humanise };
