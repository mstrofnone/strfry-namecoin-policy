'use strict';

const { LRUCache } = require('./cache');

// Bound on the post-namespace stem (the bit between `d/`/`id/` and end).
// Namecoin doesn't enforce this exact value at consensus, but in practice
// `.bit` names are short. 64 chars is more than enough for any real name
// and keeps adversarial input out of the ElectrumX call path.
const MAX_STEM_LEN = 64;
// Hard cap on full namecoin name length we will hand to nameShow().
// `id/` + 64 = 67. `d/` + 64 = 66. Use 67 as the upper bound.
const MAX_NAMECOIN_NAME_BYTES = 67;

/**
 * NIP-05 "name@domain.bit" → Namecoin pubkey resolver.
 *
 * Accepts identifiers in these forms:
 *   alice@example.bit   → name "d/example", local "alice"
 *   example.bit         → name "d/example", local "_"
 *   _@example.bit       → name "d/example", local "_"
 *   d/example           → name "d/example", local "_"     (advanced)
 *   id/alice            → name "id/alice", local "_"      (identity namespace)
 *
 * Value formats supported inside the Namecoin name's JSON value:
 *   {"nostr": "<hex>"}
 *   {"nostr": {"names": {"_": "<hex>", "alice": "<hex>"}, "relays": {"<hex>": [...]}}}
 *   {"nostr": {"pubkey": "<hex>", "relays": [...]}}        (id/ simple)
 */

const HEX64_RE = /^[0-9a-f]{64}$/i;

class NamecoinResolver {
  /**
   * @param {object} opts
   * @param {import('./electrumx').ElectrumXClient} opts.client
   * @param {number} [opts.cacheTtlMs=300000]   long TTL for successful or fully-resolved-negative results
   * @param {number} [opts.negCacheTtlMs=30000] short TTL for parse-failure / transient negatives
   * @param {number} [opts.cacheMax=2000]
   * @param {(level:string,...args:any[])=>void} [opts.logger]
   */
  constructor({ client, cacheTtlMs = 300_000, negCacheTtlMs = 30_000, cacheMax = 2000, logger, rateLimiter } = {}) {
    if (!client) throw new Error('NamecoinResolver: client is required');
    this.client = client;
    this.cache = new LRUCache({ max: cacheMax, ttlMs: cacheTtlMs });
    this.cacheTtlMs = cacheTtlMs;
    this.negCacheTtlMs = negCacheTtlMs;
    this.logger = logger || (() => {});
    // Optional global ElectrumX lookup limiter. Cache hits MUST NOT count
    // against the budget, so this only fires on a true cache miss path.
    this.rateLimiter = rateLimiter || null;
    /** Set to true when the most recent resolve() was throttled out. */
    this.lastWasRateLimited = false;
  }

  /**
   * Parse a NIP-05-style identifier into its Namecoin components.
   * Returns null if it doesn't look like a Namecoin identifier.
   *
   * @param {string} identifier
   * @returns {{namecoinName:string, localPart:string}|null}
   */
  static parseIdentifier(identifier) {
    if (!identifier || typeof identifier !== 'string') return null;
    const id = identifier.trim().toLowerCase();
    if (!id) return null;

    const finalize = (parsed) => {
      if (!parsed) return null;
      // Reject overlong names to keep adversarial input out of the
      // ElectrumX call path. Stem bound is post-namespace; full bound
      // is on the encoded namecoinName.
      const stem = parsed.namecoinName.replace(/^(d|id)\//, '');
      if (stem.length === 0 || stem.length > MAX_STEM_LEN) return null;
      if (Buffer.byteLength(parsed.namecoinName, 'utf8') > MAX_NAMECOIN_NAME_BYTES) return null;
      return parsed;
    };

    // d/<name> or id/<name>  (direct namespace form)
    if (/^(d|id)\/[^/\s@]+$/.test(id)) {
      return finalize({ namecoinName: id, localPart: '_' });
    }

    // user@domain.bit  or  user@d/name
    if (id.includes('@')) {
      const atIdx = id.lastIndexOf('@');
      const local = id.slice(0, atIdx) || '_';
      const domain = id.slice(atIdx + 1);
      if (!domain) return null;
      if (domain.endsWith('.bit')) {
        const stem = domain.slice(0, -4);
        if (!stem || stem.includes('/') || stem.includes('.')) return null;
        return finalize({ namecoinName: `d/${stem}`, localPart: local });
      }
      if (/^(d|id)\/[^/\s]+$/.test(domain)) {
        return finalize({ namecoinName: domain, localPart: local });
      }
      return null;
    }

    // bare  example.bit
    if (id.endsWith('.bit')) {
      const stem = id.slice(0, -4);
      if (!stem || stem.includes('/') || stem.includes('.')) return null;
      return finalize({ namecoinName: `d/${stem}`, localPart: '_' });
    }

    return null;
  }

  /**
   * Check whether a NIP-05 identifier is a Namecoin identifier
   * that this resolver knows how to handle.
   */
  static isNamecoinIdentifier(identifier) {
    return NamecoinResolver.parseIdentifier(identifier) !== null;
  }

  /**
   * Extract a pubkey (and optional relay hints) for the given local part
   * from a Namecoin name value JSON document.
   *
   * @param {string} valueJson
   * @param {string} localPart
   * @param {string} namecoinName  used to choose id/ vs d/ branch
   * @returns {{pubkey:string, relays:string[]}|null}
   */
  static extractFromValue(valueJson, localPart, namecoinName) {
    if (!valueJson || typeof valueJson !== 'string') return null;
    let doc;
    try { doc = JSON.parse(valueJson); } catch (_) { return null; }
    if (!doc || typeof doc !== 'object') return null;

    const nostr = doc.nostr;
    if (nostr == null) return null;

    // Identity namespace
    const isIdNs = /^id\//.test(namecoinName);

    // String form:  {"nostr": "<hex>"}  — works for both namespaces
    if (typeof nostr === 'string') {
      return HEX64_RE.test(nostr) ? { pubkey: nostr.toLowerCase(), relays: [] } : null;
    }

    if (typeof nostr !== 'object') return null;

    if (isIdNs) {
      // {"nostr": {"pubkey": "<hex>", "relays": [...]}}
      if (typeof nostr.pubkey === 'string' && HEX64_RE.test(nostr.pubkey)) {
        const relays = Array.isArray(nostr.relays) ? nostr.relays.filter((r) => typeof r === 'string') : [];
        return { pubkey: nostr.pubkey.toLowerCase(), relays };
      }
      return null;
    }

    // Domain namespace.
    //
    // Two object shapes are accepted:
    //
    //   1. Extended NIP-05-like form (used when one name covers many
    //      sub-identities):
    //        {"nostr": {"names": {"_": "<hex>", "alice": "<hex>"},
    //                   "relays": {"<hex>": [...]}}}
    //
    //   2. Single-identity form (same shape used by id/, natural for a
    //      one-owner name):
    //        {"nostr": {"pubkey": "<hex>", "relays": [...]}}
    //      Only the root local-part (`_`) resolves from this shape; a
    //      request for `alice@example.bit` against a single-identity
    //      record falls through to null because there's no sub-identity
    //      dictionary.
    //
    // If a record carries BOTH (a publisher mistake or migration), the
    // names dict wins for non-root lookups, and the names["_"] entry
    // wins for root lookups, falling back to the bare pubkey field.
    const names = nostr.names;
    if (names && typeof names === 'object') {
      const pk = names[localPart];
      if (typeof pk === 'string' && HEX64_RE.test(pk)) {
        let relays = [];
        if (nostr.relays && typeof nostr.relays === 'object' && !Array.isArray(nostr.relays)) {
          const r = nostr.relays[pk];
          if (Array.isArray(r)) relays = r.filter((x) => typeof x === 'string');
        }
        return { pubkey: pk.toLowerCase(), relays };
      }
      // Don't fall back to single-identity for non-root lookups when a
      // names dict is present — it would silently hand `alice@example.bit`
      // the root operator's pubkey, which is wrong.
      if (localPart !== '_') return null;
    }

    // Single-identity form. Only root is resolvable.
    if (
      localPart === '_' &&
      typeof nostr.pubkey === 'string' &&
      HEX64_RE.test(nostr.pubkey)
    ) {
      const relays = Array.isArray(nostr.relays)
        ? nostr.relays.filter((r) => typeof r === 'string')
        : [];
      return { pubkey: nostr.pubkey.toLowerCase(), relays };
    }

    return null;
  }

  /**
   * Resolve a NIP-05-style Namecoin identifier to a pubkey + relay hints.
   * Returns null on not-found / wrong shape / invalid value.
   *
   * Results (including negatives) are cached with the configured TTL.
   */
  async resolve(identifier) {
    this.lastWasRateLimited = false;
    const parsed = NamecoinResolver.parseIdentifier(identifier);
    if (!parsed) return null;
    const key = `${parsed.namecoinName}|${parsed.localPart}`;
    const cached = this.cache.get(key);
    if (cached !== undefined) return cached;

    // Cache miss: this will hit ElectrumX, so it counts against the budget.
    if (this.rateLimiter) {
      const ok = await this.rateLimiter.acquire();
      if (!ok) {
        this.lastWasRateLimited = true;
        this.logger('info', `namecoin resolve rate-limited for ${identifier}`);
        // Don't cache — this is a transient overload signal.
        return null;
      }
    }

    let result = null;
    let row = null;
    // Categorize the negative result for cache TTL purposes:
    //   'success-negative'  → record exists, JSON parses, nostr present,
    //                         but no key matches THIS local part. Stable
    //                         answer; safe to cache long.
    //   'parse-failure'     → record exists but its value isn't
    //                         parseable / has no nostr field, OR
    //                         nameShow returned null. Could be a
    //                         transient ElectrumX issue or a publisher
    //                         mid-flight; cache short.
    let negKind = null;
    try {
      row = await this.client.nameShow(parsed.namecoinName);
      if (row && typeof row.value === 'string') {
        result = NamecoinResolver.extractFromValue(row.value, parsed.localPart, parsed.namecoinName);
        if (result === null) {
          negKind = classifyParseFailure(row.value) ? 'parse-failure' : 'success-negative';
        }
      } else if (row === null) {
        // nameShow returned null — could be "never existed" or a
        // transient ElectrumX hiccup the client swallowed. Be safe and
        // use the short TTL so we don't cache a stale-no-record for 5min.
        negKind = 'parse-failure';
      } else {
        // row exists but row.value is not a string — malformed.
        negKind = 'parse-failure';
      }
    } catch (err) {
      this.logger('info', `namecoin resolve error for ${identifier}: ${err.message}`);
      // Do not cache transient errors — return null without caching so a retry can succeed
      return null;
    }

    if (result === null && negKind === 'parse-failure' && this.negCacheTtlMs !== this.cacheTtlMs) {
      // Short-TTL negative cache for parse failures / transient nulls so
      // a hiccup doesn't poison for the full long-cache window.
      this.cache.set(key, result, { ttlMs: this.negCacheTtlMs });
    } else {
      this.cache.set(key, result);
    }
    return result;
  }
}

/**
 * Decide whether a Namecoin name value that produced no resolved pubkey
 * looks like a parse failure (malformed/no-nostr) or a successful
 * negative (well-formed record, just no entry for this local-part).
 *
 * Returns true for parse failures, false for success-negatives.
 */
function classifyParseFailure(valueJson) {
  if (typeof valueJson !== 'string' || !valueJson) return true;
  let doc;
  try { doc = JSON.parse(valueJson); } catch (_) { return true; }
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) return true;
  if (doc.nostr == null) return true;
  // nostr is present in some recognized shape — the lookup was a
  // proper negative for this local-part.
  return false;
}

module.exports = { NamecoinResolver };
