'use strict';

/**
 * Minimal LRU cache with TTL. No external dependencies.
 *
 * Entries expire after `ttlMs` milliseconds. When the store exceeds `max`
 * entries, the least-recently-used entry is evicted. Access (get/set)
 * refreshes recency.
 */
class LRUCache {
  constructor({ max = 1000, ttlMs = 5 * 60 * 1000 } = {}) {
    if (!Number.isFinite(max) || max <= 0) throw new Error('max must be > 0');
    if (!Number.isFinite(ttlMs) || ttlMs < 0) throw new Error('ttlMs must be >= 0');
    this.max = max;
    this.ttlMs = ttlMs;
    /** @type {Map<string, {value:any, expires:number}>} */
    this.store = new Map();
  }

  _now() {
    return Date.now();
  }

  get(key) {
    const entry = this.store.get(key);
    if (!entry) return undefined;
    if (this.ttlMs > 0 && entry.expires <= this._now()) {
      this.store.delete(key);
      return undefined;
    }
    // Refresh recency
    this.store.delete(key);
    this.store.set(key, entry);
    return entry.value;
  }

  has(key) {
    return this.get(key) !== undefined;
  }

  set(key, value, { ttlMs } = {}) {
    const effectiveTtl = ttlMs ?? this.ttlMs;
    const expires = effectiveTtl > 0 ? this._now() + effectiveTtl : Infinity;
    if (this.store.has(key)) this.store.delete(key);
    this.store.set(key, { value, expires });
    while (this.store.size > this.max) {
      const oldest = this.store.keys().next().value;
      this.store.delete(oldest);
    }
    return value;
  }

  delete(key) {
    return this.store.delete(key);
  }

  clear() {
    this.store.clear();
  }

  get size() {
    return this.store.size;
  }
}

module.exports = { LRUCache };
