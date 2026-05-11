'use strict';

/**
 * NIP-9A rules loader.
 *
 * Maintains the active kind:34551 rules document for a strfry relay. Two
 * input sources (either, both, or neither — the loader is no-op when both
 * are off):
 *
 *   1. A signed rules-event JSON file at NAMECOIN_POLICY_NIP9A_RULES_FILE.
 *      Re-read on SIGHUP and on every atomic-rename (watch via fs.watchFile;
 *      cheap polling, ~5s mtime check). The file MUST contain a single
 *      kind:34551 nostr event JSON (`{id, pubkey, created_at, kind, tags,
 *      content, sig}`). Signature is NOT verified here — strfry already
 *      verifies sigs on ingest, and the file-loaded copy is operator-supplied
 *      (root-owned, mode 0640) so its provenance is the filesystem.
 *
 *   2. Live updates from the event stream: when the strfry write-policy
 *      plugin accepts a kind:34551 event, it offers it to the loader via
 *      {@link Nip9aLoader.offer}. The loader keeps the latest acceptable
 *      version per (pubkey, dTag) pair, with anti-rollback enforced by the
 *      `min_rules_created_at` floor (see `pickActiveRules`).
 *
 * If a configured COMMUNITY address (`34550:<owner-hex>:<d>`) is set, the
 * loader will ONLY accept rules events whose `pubkey` matches the owner
 * hex and whose bound community matches the address. Without a configured
 * community the loader accepts any well-formed rules event (test mode).
 *
 * Validation is OUT OF SCOPE here — that's `nip9a-validator.js`. The loader's
 * job is "what is the active rules document right now?".
 */

const fs = require('node:fs');
const path = require('node:path');
const { parseRulesEvent, pickActiveRules, NIP9A_KIND } = require('./nip9a-parser');

class Nip9aLoader {
  /**
   * @param {object} opts
   * @param {string|null} [opts.filePath]
   * @param {string|null} [opts.community] "34550:<hex>:<d>" address pointer
   * @param {(level:string, ...args:any[])=>void} [opts.logger]
   * @param {number} [opts.watchIntervalMs] mtime poll interval, default 5s
   */
  constructor({ filePath = null, community = null, logger = () => {}, watchIntervalMs = 5000 } = {}) {
    this.filePath = filePath ? path.resolve(filePath) : null;
    this.community = community || null;
    this.logger = logger;
    this.watchIntervalMs = watchIntervalMs;

    /** @type {Map<string, object>} key = `${pubkey}\u0000${dTag}`, value = parsed rules */
    this._rulesByKey = new Map();
    /** @type {object|null} cached pick from the latest mutation */
    this._active = null;
    /** Diagnostic: last error from the file watcher. */
    this.lastFileError = null;

    if (this.community) {
      const m = this.community.match(/^34550:([0-9a-f]{64}):(.+)$/i);
      if (!m) {
        throw new Error(`NAMECOIN_POLICY_NIP9A_COMMUNITY: expected "34550:<hex64>:<d>", got "${this.community}"`);
      }
      this._ownerHex = m[1].toLowerCase();
      this._dTag = m[2];
    }
  }

  /**
   * Initial load from disk (if configured) and install the watcher.
   * Safe to call multiple times; subsequent calls re-read the file.
   */
  start() {
    if (!this.filePath) return;
    this._loadFromFile();
    try {
      fs.watchFile(this.filePath, { interval: this.watchIntervalMs, persistent: false }, () => {
        this._loadFromFile();
      });
    } catch (err) {
      this.lastFileError = err.message;
      this.logger('info', `nip9a: cannot watch ${this.filePath}: ${err.message}`);
    }
  }

  /**
   * Tear down the file watcher. Used by tests; production processes exit
   * with the strfry plugin lifecycle.
   */
  stop() {
    if (this.filePath) {
      try { fs.unwatchFile(this.filePath); } catch (_) {}
    }
  }

  /**
   * Force a file re-read. Used in tests and on SIGHUP.
   */
  reload() {
    if (this.filePath) this._loadFromFile();
  }

  _loadFromFile() {
    let raw;
    try {
      raw = fs.readFileSync(this.filePath, 'utf8');
    } catch (err) {
      // ENOENT is normal during atomic rename (write tmp, rename onto target).
      // Other errors get logged but don't change the active rules.
      this.lastFileError = err.message;
      if (err.code !== 'ENOENT') {
        this.logger('info', `nip9a: read ${this.filePath} failed: ${err.message}`);
      }
      return;
    }

    let event;
    try {
      event = JSON.parse(raw);
    } catch (err) {
      this.lastFileError = `JSON parse: ${err.message}`;
      this.logger('info', `nip9a: parse ${this.filePath} failed: ${err.message}`);
      return;
    }

    this.lastFileError = null;
    const accepted = this.offer(event, 'file');
    if (!accepted) {
      this.logger('info', `nip9a: file ${this.filePath} produced no usable rules event (rejected by loader filters)`);
    }
  }

  /**
   * Offer a candidate kind:34551 event. Returns true if it became (or remains)
   * a known candidate; false if the loader rejected it (wrong owner, malformed,
   * stale by ratchet).
   *
   * The strfry plugin should call this for every incoming kind:34551 event
   * AFTER any author-side gating (e.g. .bit verification) — the loader does
   * NOT verify signatures; strfry handled that during ingest.
   *
   * @param {object} event raw kind:34551 nostr event
   * @param {'file'|'stream'} [source]
   * @returns {boolean}
   */
  offer(event, source = 'stream') {
    if (!event || event.kind !== NIP9A_KIND) return false;

    const parsed = parseRulesEvent(event);
    if (!parsed) {
      this.logger('debug', `nip9a: malformed rules event (source=${source}) — ignored`);
      return false;
    }

    // Owner / community filter.
    if (this._ownerHex) {
      if (parsed.pubkey.toLowerCase() !== this._ownerHex) {
        this.logger('debug', `nip9a: ignoring rules event from ${parsed.pubkey.slice(0,16)}…; expected owner ${this._ownerHex.slice(0,16)}…`);
        return false;
      }
      if (parsed.dTag !== this._dTag) {
        this.logger('debug', `nip9a: ignoring rules event with d="${parsed.dTag}"; expected "${this._dTag}"`);
        return false;
      }
      if (parsed.communityAddress && parsed.communityAddress !== this.community) {
        this.logger('debug', `nip9a: rules event binds community ${parsed.communityAddress} but expected ${this.community}`);
        return false;
      }
    }

    const key = `${parsed.pubkey}\u0000${parsed.dTag}`;
    const prior = this._rulesByKey.get(key);
    if (prior && prior.createdAt >= parsed.createdAt && prior.id !== parsed.id) {
      // Newer (or same age) already cached — keep prior.
      return false;
    }
    this._rulesByKey.set(key, parsed);

    // Recompute active across all known candidates (cheap; usually 1-2 keys).
    this._active = pickActiveRules([...this._rulesByKey.values()]);

    this.logger('info',
      `nip9a: active rules updated (source=${source} d="${parsed.dTag}" owner=${parsed.pubkey.slice(0,16)}… created_at=${parsed.createdAt} kinds=${parsed.kindRules.length} p=${parsed.pubkeyRules.length})`);
    return true;
  }

  /**
   * The active rules document, or null if no acceptable rules are known.
   * @returns {object|null}
   */
  active() {
    return this._active;
  }

  /**
   * Whether a rules document is currently in force.
   */
  hasActive() {
    return this._active != null;
  }

  /**
   * For diagnostics / tests: dump the candidate set.
   */
  candidates() {
    return [...this._rulesByKey.values()];
  }
}

module.exports = { Nip9aLoader };
