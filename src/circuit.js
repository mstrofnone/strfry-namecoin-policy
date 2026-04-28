'use strict';

/**
 * Circuit breaker registry for a list of (host, port) ElectrumX backends.
 *
 * State per host:
 *
 *   closed     — healthy, available for round-robin pick
 *   open       — recent failure; skipped until cooldown elapses
 *   half-open  — one probe slot. Success => closed; failure => open
 *                with exponential backoff (cap 5 min)
 *
 * If every host is currently open, `pickNext()` still returns one (we
 * round-robin through them) so the relay degrades gracefully — better
 * to attempt a possibly-flapping ElectrumX than to soft-fail every
 * verification.
 *
 * Time is injected so tests don't need real timers.
 */

const INITIAL_COOLDOWN_MS = 30_000;
const MAX_COOLDOWN_MS = 5 * 60_000;

class HostBreaker {
  /**
   * @param {Array<{host:string,port:number,tls?:boolean}>} hosts
   * @param {{now?:()=>number, logger?:(level:string,...args:any[])=>void}} [opts]
   */
  constructor(hosts, opts = {}) {
    if (!Array.isArray(hosts) || hosts.length === 0) {
      throw new Error('HostBreaker: at least one host required');
    }
    this.hosts = hosts.slice();
    this.now = opts.now || (() => Date.now());
    this.logger = opts.logger || (() => {});
    /** @type {Array<{state:'closed'|'open'|'half-open', openedAt:number, cooldownMs:number, failures:number, halfOpenInFlight:boolean}>} */
    this.state = hosts.map(() => ({
      state: 'closed',
      openedAt: 0,
      cooldownMs: INITIAL_COOLDOWN_MS,
      failures: 0,
      halfOpenInFlight: false,
    }));
    this.cursor = 0;
  }

  /**
   * Pick the next host to try. Always returns one (round-robin) even if
   * every breaker is open. Caller passes the index to `recordSuccess` /
   * `recordFailure` after the request finishes.
   *
   * @returns {{host:{host:string,port:number,tls?:boolean}, index:number, allOpen:boolean}}
   */
  pickNext() {
    const N = this.hosts.length;
    const now = this.now();

    // First, transition any host past its cooldown to half-open.
    for (let i = 0; i < N; i++) {
      const s = this.state[i];
      if (s.state === 'open' && (now - s.openedAt) >= s.cooldownMs) {
        s.state = 'half-open';
        s.halfOpenInFlight = false;
      }
    }

    // Look for a healthy host first, walking the round-robin cursor.
    for (let step = 0; step < N; step++) {
      const idx = (this.cursor + step) % N;
      const s = this.state[idx];
      if (s.state === 'closed') {
        this.cursor = (idx + 1) % N;
        return { host: this.hosts[idx], index: idx, allOpen: false };
      }
      if (s.state === 'half-open' && !s.halfOpenInFlight) {
        s.halfOpenInFlight = true;
        this.cursor = (idx + 1) % N;
        return { host: this.hosts[idx], index: idx, allOpen: false };
      }
    }

    // All open (or half-open with probe in flight). Force a probe anyway.
    const idx = this.cursor % N;
    this.cursor = (idx + 1) % N;
    this.logger('info', `circuit: all ${N} ElectrumX host(s) open; forcing probe of ${this.hosts[idx].host}:${this.hosts[idx].port}`);
    return { host: this.hosts[idx], index: idx, allOpen: true };
  }

  recordSuccess(index) {
    const s = this.state[index];
    if (!s) return;
    if (s.state !== 'closed') {
      this.logger('debug', `circuit: ${this.hosts[index].host}:${this.hosts[index].port} closed (success after ${s.failures} failure(s))`);
    }
    s.state = 'closed';
    s.openedAt = 0;
    s.cooldownMs = INITIAL_COOLDOWN_MS;
    s.failures = 0;
    s.halfOpenInFlight = false;
  }

  recordFailure(index) {
    const s = this.state[index];
    if (!s) return;
    s.failures += 1;
    s.openedAt = this.now();
    s.halfOpenInFlight = false;
    if (s.state === 'half-open') {
      // Probe failed: re-open with exponential backoff (cap 5 min).
      s.cooldownMs = Math.min(s.cooldownMs * 2, MAX_COOLDOWN_MS);
    } else if (s.state === 'closed') {
      // First failure since healthy.
      s.cooldownMs = INITIAL_COOLDOWN_MS;
    }
    s.state = 'open';
    this.logger('debug', `circuit: ${this.hosts[index].host}:${this.hosts[index].port} open for ${s.cooldownMs}ms (failures=${s.failures})`);
  }

  /** For tests / observability. */
  snapshot() {
    return this.state.map((s, i) => ({
      host: this.hosts[i],
      state: s.state,
      cooldownMs: s.cooldownMs,
      failures: s.failures,
      openedAt: s.openedAt,
    }));
  }
}

module.exports = { HostBreaker, INITIAL_COOLDOWN_MS, MAX_COOLDOWN_MS };
