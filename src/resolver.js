'use strict';

const { LRUCache } = require('./cache');

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
   * @param {number} [opts.cacheTtlMs=300000]
   * @param {number} [opts.cacheMax=2000]
   * @param {(level:string,...args:any[])=>void} [opts.logger]
   */
  constructor({ client, cacheTtlMs = 300_000, cacheMax = 2000, logger } = {}) {
    if (!client) throw new Error('NamecoinResolver: client is required');
    this.client = client;
    this.cache = new LRUCache({ max: cacheMax, ttlMs: cacheTtlMs });
    this.logger = logger || (() => {});
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

    // d/<name> or id/<name>  (direct namespace form)
    if (/^(d|id)\/[^/\s@]+$/.test(id)) {
      return { namecoinName: id, localPart: '_' };
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
        return { namecoinName: `d/${stem}`, localPart: local };
      }
      if (/^(d|id)\/[^/\s]+$/.test(domain)) {
        return { namecoinName: domain, localPart: local };
      }
      return null;
    }

    // bare  example.bit
    if (id.endsWith('.bit')) {
      const stem = id.slice(0, -4);
      if (!stem || stem.includes('/') || stem.includes('.')) return null;
      return { namecoinName: `d/${stem}`, localPart: '_' };
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

    // Domain namespace: {"nostr": {"names": {"_": "<hex>", ...}, "relays": {...}}}
    const names = nostr.names;
    if (!names || typeof names !== 'object') return null;
    const pk = names[localPart];
    if (typeof pk !== 'string' || !HEX64_RE.test(pk)) return null;

    let relays = [];
    if (nostr.relays && typeof nostr.relays === 'object') {
      const r = nostr.relays[pk];
      if (Array.isArray(r)) relays = r.filter((x) => typeof x === 'string');
    }
    return { pubkey: pk.toLowerCase(), relays };
  }

  /**
   * Resolve a NIP-05-style Namecoin identifier to a pubkey + relay hints.
   * Returns null on not-found / wrong shape / invalid value.
   *
   * Results (including negatives) are cached with the configured TTL.
   */
  async resolve(identifier) {
    const parsed = NamecoinResolver.parseIdentifier(identifier);
    if (!parsed) return null;
    const key = `${parsed.namecoinName}|${parsed.localPart}`;
    const cached = this.cache.get(key);
    if (cached !== undefined) return cached;

    let result = null;
    try {
      const row = await this.client.nameShow(parsed.namecoinName);
      if (row && typeof row.value === 'string') {
        result = NamecoinResolver.extractFromValue(row.value, parsed.localPart, parsed.namecoinName);
      }
    } catch (err) {
      this.logger('info', `namecoin resolve error for ${identifier}: ${err.message}`);
      // Do not cache transient errors — return null without caching so a retry can succeed
      return null;
    }

    this.cache.set(key, result);
    return result;
  }
}

module.exports = { NamecoinResolver };
