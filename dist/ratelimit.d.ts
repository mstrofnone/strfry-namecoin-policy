/**
 * Tiny in-process token-bucket rate limiter.
 *
 * No deps. Used to cap the rate at which the plugin will issue ElectrumX
 * lookups (cache hits do NOT count against the budget). When the bucket
 * is empty, callers wait up to `queueMs` for a token; if a token never
 * arrives in that window the acquire() call resolves to `false` and the
 * caller should fail-fast.
 *
 * @example
 *   const rl = new TokenBucket({ rps: 5, burst: 10, queueMs: 2000 });
 *   if (!(await rl.acquire())) return null;  // rate-limited
 *   await doWork();
 */
export class TokenBucket {
    /**
     * @param {object} opts
     * @param {number} [opts.rps=5]      Sustained refill rate, tokens/sec.
     * @param {number} [opts.burst=10]   Bucket capacity / max burst size.
     * @param {number} [opts.queueMs=2000] Max time a caller will wait for a token.
     * @param {() => number} [opts.now]  Clock fn (ms). Override for tests.
     */
    constructor({ rps, burst, queueMs, now }?: {
        rps?: number;
        burst?: number;
        queueMs?: number;
        now?: () => number;
    });
    rps: number;
    burst: number;
    queueMs: number;
    _now: () => number;
    tokens: number;
    lastRefill: number;
    /** Refill the bucket based on elapsed time. */
    _refill(): void;
    /**
     * Try to immediately consume 1 token. Returns true on success.
     * Does NOT wait.
     */
    tryAcquire(): boolean;
    /**
     * Acquire 1 token, waiting up to queueMs if the bucket is currently
     * empty. Resolves to true on success, false if it timed out.
     *
     * @returns {Promise<boolean>}
     */
    acquire(): Promise<boolean>;
}
