/**
 * Construct and run the plugin using process.stdin/stdout.
 */
export function run({ env, stdin, stdout }?: {
    env?: any;
    stdin?: any;
    stdout?: any;
}): Promise<void>;
/**
 * Build the per-request handler. Exposed for unit tests so we can feed
 * crafted input messages without spinning up readline/stdin.
 *
 * @returns {(req:any) => Promise<{id:any, action:string, msg?:string}>}
 */
export function makeHandler({ config, resolver, verifiedAuthors, metrics, logger }: {
    config: any;
    resolver: any;
    verifiedAuthors: any;
    metrics: any;
    logger: any;
}): (req: any) => Promise<{
    id: any;
    action: string;
    msg?: string;
}>;
/**
 * Pull the `nip05` string out of a kind:0 event's content.
 */
export function extractNip05(content: any): string;
/**
 * Build a cache: PersistentLRU when cachePath is set, otherwise LRUCache.
 * If PersistentLRU construction fails (disk perms, sqlite corruption, etc.),
 * fall back to in-memory LRU and log loudly. We don't want a cache-disk
 * issue to take the relay offline.
 */
export function makeCache({ cachePath, namespace, max, ttlMs, logger }: {
    cachePath: any;
    namespace: any;
    max: any;
    ttlMs: any;
    logger: any;
}): LRUCache | {
    path: string;
    max: number;
    ttlMs: number;
    namespace: string;
    compactEveryWrites: number;
    logger: (level: string, ...args: any[]) => void;
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
    readonly size: any;
    close(): void;
};
import { LRUCache } from "./cache";
