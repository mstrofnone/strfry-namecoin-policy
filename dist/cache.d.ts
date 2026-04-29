/**
 * Minimal LRU cache with TTL. No external dependencies.
 *
 * Entries expire after `ttlMs` milliseconds. When the store exceeds `max`
 * entries, the least-recently-used entry is evicted. Access (get/set)
 * refreshes recency.
 */
export class LRUCache {
    constructor({ max, ttlMs }?: {
        max?: number;
        ttlMs?: number;
    });
    max: number;
    ttlMs: number;
    /** @type {Map<string, {value:any, expires:number}>} */
    store: Map<string, {
        value: any;
        expires: number;
    }>;
    _now(): number;
    get(key: any): any;
    has(key: any): boolean;
    set(key: any, value: any, { ttlMs }?: {}): any;
    delete(key: any): any;
    clear(): void;
    get size(): any;
}
