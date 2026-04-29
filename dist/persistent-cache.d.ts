export class PersistentLRU {
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
    constructor({ path: filePath, max, ttlMs, compactEveryWrites, namespace, logger, forceJsonl, }?: {
        path: string;
        max?: number;
        ttlMs?: number;
        compactEveryWrites?: number;
        namespace?: string;
        logger?: (level: string, ...args: any[]) => void;
        forceJsonl?: boolean;
    });
    path: string;
    max: number;
    ttlMs: number;
    namespace: string;
    compactEveryWrites: number;
    logger: (level: string, ...args: any[]) => void;
    /** @type {Map<string,{value:any, expires:number}>} */
    store: Map<string, {
        value: any;
        expires: number;
    }>;
    backend: string;
    _now(): number;
    _initSqlite(): void;
    db: any;
    _stmtGet: any;
    _stmtSet: any;
    _stmtDel: any;
    _stmtAll: any;
    _stmtClear: any;
    _initJsonl(): void;
    writes: number;
    fd: any;
    _appendJsonl(rec: any): void;
    _compactJsonl(): void;
    get(key: any): any;
    has(key: any): boolean;
    set(key: any, value: any, { ttlMs }?: {}): any;
    _persistSet(key: any, value: any, expires: any): void;
    delete(key: any): any;
    clear(): void;
    _evictIfNeeded(): void;
    get size(): any;
    /** Close handles. Safe to call multiple times. */
    close(): void;
}
export const NEG_SENTINEL: any;
export declare let _hasSqlite: boolean;
