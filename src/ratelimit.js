'use strict';

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
class TokenBucket {
  /**
   * @param {object} opts
   * @param {number} [opts.rps=5]      Sustained refill rate, tokens/sec.
   * @param {number} [opts.burst=10]   Bucket capacity / max burst size.
   * @param {number} [opts.queueMs=2000] Max time a caller will wait for a token.
   * @param {() => number} [opts.now]  Clock fn (ms). Override for tests.
   */
  constructor({ rps = 5, burst = 10, queueMs = 2000, now } = {}) {
    if (!(rps > 0)) throw new Error('TokenBucket: rps must be > 0');
    if (!(burst > 0)) throw new Error('TokenBucket: burst must be > 0');
    if (!(queueMs >= 0)) throw new Error('TokenBucket: queueMs must be >= 0');
    this.rps = rps;
    this.burst = burst;
    this.queueMs = queueMs;
    this._now = now || (() => Date.now());
    this.tokens = burst;            // start full
    this.lastRefill = this._now();
  }

  /** Refill the bucket based on elapsed time. */
  _refill() {
    const now = this._now();
    const elapsed = Math.max(0, now - this.lastRefill);
    if (elapsed <= 0) return;
    const add = (elapsed / 1000) * this.rps;
    if (add > 0) {
      this.tokens = Math.min(this.burst, this.tokens + add);
      this.lastRefill = now;
    }
  }

  /**
   * Try to immediately consume 1 token. Returns true on success.
   * Does NOT wait.
   */
  tryAcquire() {
    this._refill();
    if (this.tokens >= 1) {
      this.tokens -= 1;
      return true;
    }
    return false;
  }

  /**
   * Acquire 1 token, waiting up to queueMs if the bucket is currently
   * empty. Resolves to true on success, false if it timed out.
   *
   * @returns {Promise<boolean>}
   */
  async acquire() {
    if (this.tryAcquire()) return true;
    if (this.queueMs <= 0) return false;

    const deadline = this._now() + this.queueMs;
    // Poll-with-backoff. We don't hold a real timer fleet because at the
    // expected rates (single-digit rps) this is cheaper than scheduling
    // wakers on every call.
    while (true) {
      this._refill();
      if (this.tokens >= 1) {
        this.tokens -= 1;
        return true;
      }
      const now = this._now();
      if (now >= deadline) return false;
      // Time until next whole token, capped by remaining deadline.
      const tokensNeeded = 1 - this.tokens;
      const waitForToken = Math.ceil((tokensNeeded / this.rps) * 1000);
      const remaining = deadline - now;
      const wait = Math.max(5, Math.min(waitForToken, remaining));
      await sleep(wait);
    }
  }
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

module.exports = { TokenBucket };
