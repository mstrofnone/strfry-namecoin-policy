export class Nip9aLoader {
    /**
     * @param {object} opts
     * @param {string|null} [opts.filePath]
     * @param {string|null} [opts.community] "34550:<hex>:<d>" address pointer
     * @param {(level:string, ...args:any[])=>void} [opts.logger]
     * @param {number} [opts.watchIntervalMs] mtime poll interval, default 5s
     */
    constructor({ filePath, community, logger, watchIntervalMs }?: {
        filePath?: string | null;
        community?: string | null;
        logger?: (level: string, ...args: any[]) => void;
        watchIntervalMs?: number;
    });
    filePath: any;
    community: string;
    logger: (level: string, ...args: any[]) => void;
    watchIntervalMs: number;
    /** @type {Map<string, object>} key = `${pubkey}\u0000${dTag}`, value = parsed rules */
    _rulesByKey: Map<string, object>;
    /** @type {object|null} cached pick from the latest mutation */
    _active: object | null;
    /** Diagnostic: last error from the file watcher. */
    lastFileError: any;
    _ownerHex: string;
    _dTag: string;
    /**
     * Initial load from disk (if configured) and install the watcher.
     * Safe to call multiple times; subsequent calls re-read the file.
     */
    start(): void;
    /**
     * Tear down the file watcher. Used by tests; production processes exit
     * with the strfry plugin lifecycle.
     */
    stop(): void;
    /**
     * Force a file re-read. Used in tests and on SIGHUP.
     */
    reload(): void;
    _loadFromFile(): void;
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
    offer(event: object, source?: "file" | "stream"): boolean;
    /**
     * The active rules document, or null if no acceptable rules are known.
     * @returns {object|null}
     */
    active(): object | null;
    /**
     * Whether a rules document is currently in force.
     */
    hasActive(): boolean;
    /**
     * For diagnostics / tests: dump the candidate set.
     */
    candidates(): any[];
}
