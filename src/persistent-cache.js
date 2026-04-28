'use strict';

/**
 * Persistent on-disk LRU cache with TTL.
 *
 * Same surface as `src/cache.js#LRUCache` (`get/set/has/delete/clear/size`)
 * plus optional persistence so restarts don't lose verified-author or
 * resolver state.
 *
 * Storage backends, picked at construction time:
 *
 *   - SQLite (via the optional `better-sqlite3` dep). Synchronous,
 *     fast, atomic. Used when `require('better-sqlite3')` succeeds.
 *
 *   - JSONL append-log fallback. Used when SQLite is unavailable. One
 *     line per mutation:
 *
 *         {"op":"set","k":"...","v":...,"e":<expiresMs|null>}
 *         {"op":"del","k":"..."}
 *
 *     On open, we replay the log into memory. We compact when the log
 *     grows beyond `compactEveryWrites` mutations (default 1000) by
 *     atomic rename: write `<file>.tmp`, fsync, rename over `<file>`.
 *
 * TTL is honored on read: expired entries are skipped AND removed.
 *
 * Values must be JSON-serializable (we accept anything `JSON.stringify`
 * can handle, including `null`). `undefined` is reserved as a "miss"
 * sentinel and is therefore not storable.
 */

const fs = require('node:fs');
const path = require('node:path');

let Database = null;
try {
  // eslint-disable-next-line global-require
  Database = require('better-sqlite3');
} catch (_) {
  Database = null;
}

const NEG_SENTINEL = Symbol.for('strfry.namecoin.persistent.null');

class PersistentLRU {
  /**
   * @param {object} opts
   * @param {string} opts.path           file path on disk (sqlite or jsonl)
   * @param {number} [opts.max=10000]    LRU cap in memory
   * @param {number} [opts.ttlMs=300000] default TTL ms; 0/Infinity = no expiry
   * @param {number} [opts.compactEveryWrites=1000] jsonl-only compaction threshold
   * @param {string} [opts.namespace="default"]   sqlite-only logical bucket
   * @param {(level:string,...args:any[])=>void} [opts.logger]
   * @param {boolean} [opts.forceJsonl=false] testing knob
   */
  constructor({
    path: filePath,
    max = 10_000,
    ttlMs = 5 * 60 * 1000,
    compactEveryWrites = 1000,
    namespace = 'default',
    logger,
    forceJsonl = false,
  } = {}) {
    if (!filePath) throw new Error('PersistentLRU: path is required');
    if (!Number.isFinite(max) || max <= 0) throw new Error('max must be > 0');
    if (!Number.isFinite(ttlMs) || ttlMs < 0) throw new Error('ttlMs must be >= 0');
    this.path = filePath;
    this.max = max;
    this.ttlMs = ttlMs;
    this.namespace = String(namespace);
    this.compactEveryWrites = compactEveryWrites;
    this.logger = logger || (() => {});
    /** @type {Map<string,{value:any, expires:number}>} */
    this.store = new Map();

    fs.mkdirSync(path.dirname(this.path), { recursive: true });

    this.backend = (!forceJsonl && Database) ? 'sqlite' : 'jsonl';
    if (this.backend === 'sqlite') {
      this._initSqlite();
    } else {
      this._initJsonl();
    }
  }

  _now() { return Date.now(); }

  // ── SQLite backend ─────────────────────────────────────────────────────
  _initSqlite() {
    this.db = new Database(this.path);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('synchronous = NORMAL');
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS kv (
        ns      TEXT NOT NULL,
        k       TEXT NOT NULL,
        v       TEXT NOT NULL,
        expires INTEGER NOT NULL,
        PRIMARY KEY (ns, k)
      );
      CREATE INDEX IF NOT EXISTS kv_expires ON kv(expires);
    `);
    this._stmtGet = this.db.prepare('SELECT v, expires FROM kv WHERE ns=? AND k=?');
    this._stmtSet = this.db.prepare('INSERT OR REPLACE INTO kv (ns,k,v,expires) VALUES (?,?,?,?)');
    this._stmtDel = this.db.prepare('DELETE FROM kv WHERE ns=? AND k=?');
    this._stmtAll = this.db.prepare('SELECT k, v, expires FROM kv WHERE ns=?');
    this._stmtClear = this.db.prepare('DELETE FROM kv WHERE ns=?');

    // Hydrate hot LRU from disk, dropping expired rows along the way.
    const now = this._now();
    const rows = this._stmtAll.all(this.namespace);
    const expired = [];
    for (const row of rows) {
      const expires = row.expires === 0 ? Infinity : row.expires;
      if (this.ttlMs > 0 && expires <= now) {
        expired.push(row.k);
        continue;
      }
      let parsed;
      try { parsed = JSON.parse(row.v); } catch (_) { continue; }
      this.store.set(row.k, { value: parsed, expires });
    }
    if (expired.length) {
      const tx = this.db.transaction((keys) => {
        for (const k of keys) this._stmtDel.run(this.namespace, k);
      });
      try { tx(expired); } catch (e) { this.logger('debug', `pcache: expire-prune failed: ${e.message}`); }
    }
    this._evictIfNeeded();
  }

  // ── JSONL backend ──────────────────────────────────────────────────────
  _initJsonl() {
    this.writes = 0;
    if (fs.existsSync(this.path)) {
      const data = fs.readFileSync(this.path, 'utf8');
      const lines = data.split('\n');
      const now = this._now();
      for (const line of lines) {
        if (!line) continue;
        let rec;
        try { rec = JSON.parse(line); } catch (_) { continue; }
        if (!rec || typeof rec !== 'object') continue;
        if (rec.op === 'set' && typeof rec.k === 'string') {
          const expires = rec.e == null ? Infinity : Number(rec.e);
          if (this.ttlMs > 0 && Number.isFinite(expires) && expires <= now) {
            this.store.delete(rec.k);
            continue;
          }
          this.store.set(rec.k, { value: rec.v, expires });
        } else if (rec.op === 'del' && typeof rec.k === 'string') {
          this.store.delete(rec.k);
        } else if (rec.op === 'clear') {
          this.store.clear();
        }
      }
    }
    // Open append handle.
    this.fd = fs.openSync(this.path, 'a');
    this._evictIfNeeded();
  }

  _appendJsonl(rec) {
    const line = JSON.stringify(rec) + '\n';
    fs.writeSync(this.fd, line);
    this.writes++;
    if (this.writes >= this.compactEveryWrites) {
      try { this._compactJsonl(); } catch (e) {
        this.logger('info', `pcache: compaction failed: ${e.message}`);
      }
    }
  }

  _compactJsonl() {
    const tmp = `${this.path}.tmp`;
    const fd = fs.openSync(tmp, 'w');
    try {
      for (const [k, { value, expires }] of this.store) {
        const e = Number.isFinite(expires) ? expires : null;
        fs.writeSync(fd, JSON.stringify({ op: 'set', k, v: value, e }) + '\n');
      }
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    // Replace.
    try { fs.closeSync(this.fd); } catch (_) {}
    fs.renameSync(tmp, this.path);
    this.fd = fs.openSync(this.path, 'a');
    this.writes = 0;
  }

  // ── Public API ─────────────────────────────────────────────────────────
  get(key) {
    const entry = this.store.get(key);
    if (!entry) {
      if (this.backend === 'sqlite') {
        // Fall through and check sqlite — could've been added by another process,
        // though we don't really support that. Skip the round-trip; we mirror the
        // store fully on init.
      }
      return undefined;
    }
    if (this.ttlMs > 0 && entry.expires <= this._now()) {
      this.delete(key);
      return undefined;
    }
    // Refresh recency.
    this.store.delete(key);
    this.store.set(key, entry);
    return entry.value;
  }

  has(key) { return this.get(key) !== undefined; }

  set(key, value, { ttlMs } = {}) {
    if (value === undefined) {
      // Storing `undefined` would be indistinguishable from a miss. Use `null`.
      value = null;
    }
    const effectiveTtl = ttlMs ?? this.ttlMs;
    const expires = effectiveTtl > 0 ? this._now() + effectiveTtl : Infinity;
    if (this.store.has(key)) this.store.delete(key);
    this.store.set(key, { value, expires });
    this._persistSet(key, value, expires);
    this._evictIfNeeded();
    return value;
  }

  _persistSet(key, value, expires) {
    if (this.backend === 'sqlite') {
      const e = Number.isFinite(expires) ? expires : 0; // 0 = never
      try {
        this._stmtSet.run(this.namespace, key, JSON.stringify(value), e);
      } catch (err) {
        this.logger('info', `pcache: sqlite set failed: ${err.message}`);
      }
    } else {
      const e = Number.isFinite(expires) ? expires : null;
      try {
        this._appendJsonl({ op: 'set', k: key, v: value, e });
      } catch (err) {
        this.logger('info', `pcache: jsonl write failed: ${err.message}`);
      }
    }
  }

  delete(key) {
    const had = this.store.delete(key);
    if (this.backend === 'sqlite') {
      try { this._stmtDel.run(this.namespace, key); } catch (_) {}
    } else {
      try { this._appendJsonl({ op: 'del', k: key }); } catch (_) {}
    }
    return had;
  }

  clear() {
    this.store.clear();
    if (this.backend === 'sqlite') {
      try { this._stmtClear.run(this.namespace); } catch (_) {}
    } else {
      try { this._appendJsonl({ op: 'clear' }); } catch (_) {}
    }
  }

  _evictIfNeeded() {
    while (this.store.size > this.max) {
      const oldest = this.store.keys().next().value;
      // Don't append a delete record per eviction in jsonl — that's
      // O(N) churn. Just drop it from the hot map; the next compaction
      // will write the trimmed view.
      this.store.delete(oldest);
      if (this.backend === 'sqlite') {
        try { this._stmtDel.run(this.namespace, oldest); } catch (_) {}
      }
    }
  }

  get size() { return this.store.size; }

  /** Close handles. Safe to call multiple times. */
  close() {
    if (this.backend === 'sqlite' && this.db) {
      try { this.db.close(); } catch (_) {}
      this.db = null;
    } else if (this.backend === 'jsonl' && this.fd != null) {
      try { fs.closeSync(this.fd); } catch (_) {}
      this.fd = null;
    }
  }
}

module.exports = { PersistentLRU, _hasSqlite: !!Database, NEG_SENTINEL };
