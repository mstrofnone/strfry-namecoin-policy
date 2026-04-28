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

  const client = config.host ? new ElectrumXClient({
    host: config.host,
    port: config.port,
    tls:  config.tls,
    certPinSha256: config.certPinSha256,
    rejectUnauthorized: config.rejectUnauthorized,
    timeoutMs: config.timeoutMs,
    retries:   config.retries,
    minConfirmations: config.minConfirmations,
    logger,
  }) : null;

  const resolver = client ? new NamecoinResolver({
    client,
    cacheTtlMs: config.cacheTtlMs,
    negCacheTtlMs: config.negCacheTtlMs,
    logger,
  }) : null;

  // Cache of pubkey -> true, for authors we've seen verified via a .bit kind:0
  // this process. Only used for mode=all-kinds-require-bit.
  const verifiedAuthors = new LRUCache({ max: 20_000, ttlMs: config.cacheTtlMs });

  const handler = makeHandler({ config, resolver, verifiedAuthors, logger });

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
function makeHandler({ config, resolver, verifiedAuthors, logger }) {
  return async function handle(req) {
    if (!req || typeof req !== 'object') {
      return { id: null, action: 'reject', msg: 'invalid: non-object plugin message' };
    }
    if (req.type !== 'new') {
      logger('debug', `ignoring non-new request type: ${req.type}`);
      return { id: req?.event?.id ?? null, action: 'accept' };
    }

    const event = req.event;
    if (!event || typeof event !== 'object' || typeof event.id !== 'string') {
      return { id: null, action: 'reject', msg: 'invalid: missing event' };
    }
    const id = event.id;
    const kind = Number(event.kind);
    const pubkey = typeof event.pubkey === 'string' ? event.pubkey.toLowerCase() : '';

    if (!pubkey) {
      return { id, action: 'reject', msg: 'invalid: missing event.pubkey' };
    }

    // ── Kind 0: metadata. Check nip05 field. ──
    if (kind === 0) {
      const nip05 = extractNip05(event.content);
      if (!nip05) {
        logger('debug', `kind0 ${id} has no nip05 — accept`);
        return { id, action: 'accept' };
      }

      const lowered = nip05.toLowerCase();
      const isNamecoin = NamecoinResolver.isNamecoinIdentifier(lowered);

      if (!isNamecoin) {
        if (config.allowNonBit) {
          logger('debug', `kind0 ${id} nip05=${nip05} non-.bit — accept (pass-through)`);
          return { id, action: 'accept' };
        }
        return { id, action: 'reject',
          msg: 'blocked: only Namecoin .bit NIP-05 identifiers are accepted on this relay' };
      }

      if (!resolver) {
        // No resolver configured — treat as soft-fail.
        logger('info', `kind0 ${id} has .bit NIP-05 but no ElectrumX configured — accept`);
        return { id, action: 'accept' };
      }

      const resolved = await resolver.resolve(lowered);
      if (!resolved) {
        return { id, action: 'reject',
          msg: `invalid: Namecoin NIP-05 "${nip05}" could not be resolved (name missing, expired, or malformed)` };
      }
      if (resolved.pubkey !== pubkey) {
        return { id, action: 'reject',
          msg: `invalid: Namecoin NIP-05 "${nip05}" maps to ${resolved.pubkey.slice(0, 16)}… but event.pubkey is ${pubkey.slice(0, 16)}…` };
      }

      // Remember this pubkey for all-kinds-require-bit mode.
      verifiedAuthors.set(pubkey, true);
      logger('info', `kind0 ${id} verified Namecoin NIP-05 "${nip05}" → ${pubkey.slice(0, 16)}…`);
      return { id, action: 'accept' };
    }

    // ── Non-kind-0 events ──
    if (config.mode === 'all-kinds-require-bit') {
      if (verifiedAuthors.has(pubkey)) {
        return { id, action: 'accept' };
      }
      return { id, action: 'reject',
        msg: 'blocked: this relay requires a verified Namecoin .bit NIP-05 identity (publish a kind:0 first)' };
    }

    return { id, action: 'accept' };
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

module.exports = { run, makeHandler, extractNip05 };
