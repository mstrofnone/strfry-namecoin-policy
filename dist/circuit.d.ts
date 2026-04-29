export class HostBreaker {
    /**
     * @param {Array<{host:string,port:number,tls?:boolean}>} hosts
     * @param {{now?:()=>number, logger?:(level:string,...args:any[])=>void}} [opts]
     */
    constructor(hosts: Array<{
        host: string;
        port: number;
        tls?: boolean;
    }>, opts?: {
        now?: () => number;
        logger?: (level: string, ...args: any[]) => void;
    });
    hosts: {
        host: string;
        port: number;
        tls?: boolean;
    }[];
    now: () => number;
    logger: (level: string, ...args: any[]) => void;
    /** @type {Array<{state:'closed'|'open'|'half-open', openedAt:number, cooldownMs:number, failures:number, halfOpenInFlight:boolean}>} */
    state: Array<{
        state: "closed" | "open" | "half-open";
        openedAt: number;
        cooldownMs: number;
        failures: number;
        halfOpenInFlight: boolean;
    }>;
    cursor: number;
    /**
     * Pick the next host to try. Always returns one (round-robin) even if
     * every breaker is open. Caller passes the index to `recordSuccess` /
     * `recordFailure` after the request finishes.
     *
     * @returns {{host:{host:string,port:number,tls?:boolean}, index:number, allOpen:boolean}}
     */
    pickNext(): {
        host: {
            host: string;
            port: number;
            tls?: boolean;
        };
        index: number;
        allOpen: boolean;
    };
    recordSuccess(index: any): void;
    recordFailure(index: any): void;
    /** For tests / observability. */
    snapshot(): {
        host: {
            host: string;
            port: number;
            tls?: boolean;
        };
        state: "closed" | "open" | "half-open";
        cooldownMs: number;
        failures: number;
        openedAt: number;
    }[];
}
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
export const INITIAL_COOLDOWN_MS: 30000;
export const MAX_COOLDOWN_MS: number;
