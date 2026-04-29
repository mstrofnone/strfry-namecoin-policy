export class NamecoinResolver {
    /**
     * Parse a NIP-05-style identifier into its Namecoin components.
     * Returns null if it doesn't look like a Namecoin identifier.
     *
     * @param {string} identifier
     * @returns {{namecoinName:string, localPart:string}|null}
     */
    static parseIdentifier(identifier: string): {
        namecoinName: string;
        localPart: string;
    } | null;
    /**
     * Check whether a NIP-05 identifier is a Namecoin identifier
     * that this resolver knows how to handle.
     */
    static isNamecoinIdentifier(identifier: any): boolean;
    /**
     * Extract a pubkey (and optional relay hints) for the given local part
     * from a Namecoin name value JSON document.
     *
     * @param {string} valueJson
     * @param {string} localPart
     * @param {string} namecoinName  used to choose id/ vs d/ branch
     * @returns {{pubkey:string, relays:string[]}|null}
     */
    static extractFromValue(valueJson: string, localPart: string, namecoinName: string): {
        pubkey: string;
        relays: string[];
    } | null;
    /**
     * @param {object} opts
     * @param {import('./electrumx').ElectrumXClient} opts.client
     * @param {number} [opts.cacheTtlMs=300000]   long TTL for successful or fully-resolved-negative results
     * @param {number} [opts.negCacheTtlMs=30000] short TTL for parse-failure / transient negatives
     * @param {number} [opts.cacheMax=2000]
     * @param {object} [opts.cache]    pre-built cache (LRUCache or PersistentLRU);
     *                                 when set, cacheTtlMs/cacheMax are ignored
     * @param {object} [opts.metrics]  metrics instance (Metrics|NullMetrics)
     * @param {(level:string,...args:any[])=>void} [opts.logger]
     */
    constructor({ client, cacheTtlMs, negCacheTtlMs, cacheMax, cache, metrics, logger, rateLimiter }?: {
        client: import("./electrumx").ElectrumXClient;
        cacheTtlMs?: number;
        negCacheTtlMs?: number;
        cacheMax?: number;
        cache?: object;
        metrics?: object;
        logger?: (level: string, ...args: any[]) => void;
    });
    client: import("./electrumx").ElectrumXClient;
    cache: any;
    cacheTtlMs: number;
    negCacheTtlMs: number;
    metrics: any;
    logger: (level: string, ...args: any[]) => void;
    rateLimiter: any;
    /** Set to true when the most recent resolve() was throttled out. */
    lastWasRateLimited: boolean;
    /**
     * Resolve a NIP-05-style Namecoin identifier to a pubkey + relay hints.
     * Returns null on not-found / wrong shape / invalid value.
     *
     * Results (including negatives) are cached with the configured TTL.
     */
    resolve(identifier: any): Promise<any>;
}
