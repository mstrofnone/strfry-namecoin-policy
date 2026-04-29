export class ElectrumXClient {
    /**
     * @param {object} opts
     * @param {string}  [opts.host]                 single-host shorthand
     * @param {number}  [opts.port=50002]
     * @param {boolean} [opts.tls=true]
     * @param {Array<{host:string,port:number,tls?:boolean}>} [opts.hosts]
     *                                              multi-host (overrides single)
     * @param {{host:string,port:number}|null} [opts.socks5]
     * @param {number}  [opts.poolKeepaliveMs=0]    0 = per-resolve connections
     * @param {string|null} [opts.certPinSha256]    hex-encoded SHA-256 of DER cert OR comma-separated pin list
     * @param {boolean} [opts.rejectUnauthorized]
     * @param {number}  [opts.timeoutMs=5000]
     * @param {number}  [opts.retries=2]
     * @param {number}  [opts.minConfirmations=1]   minimum confirmations a tx must have to be trusted
     * @param {object}  [opts.metrics]              Metrics or NullMetrics
     * @param {(level:string,...args:any[])=>void} [opts.logger]
     */
    constructor(opts?: {
        host?: string;
        port?: number;
        tls?: boolean;
        hosts?: Array<{
            host: string;
            port: number;
            tls?: boolean;
        }>;
        socks5?: {
            host: string;
            port: number;
        } | null;
        poolKeepaliveMs?: number;
        certPinSha256?: string | null;
        rejectUnauthorized?: boolean;
        timeoutMs?: number;
        retries?: number;
        minConfirmations?: number;
        metrics?: object;
        logger?: (level: string, ...args: any[]) => void;
    });
    hosts: {
        host: string;
        port: number;
        tls: boolean;
    }[];
    host: string;
    port: number;
    useTls: boolean;
    breaker: HostBreaker;
    socks5: {
        host: string;
        port: number;
    };
    poolKeepaliveMs: number;
    certPins: ({
        kind: "der";
        hex: string;
    } | {
        kind: "spki";
        b64: string;
    })[];
    certPinSha256: string;
    rejectUnauthorized: boolean;
    timeoutMs: number;
    retries: number;
    minConfirmations: number;
    metrics: any;
    logger: (level: string, ...args: any[]) => void;
    /** @type {Map<string, PooledConnection>} pool keyed by `host:port` */
    pool: Map<string, PooledConnection>;
    /** Stable pool key. */
    _hostKey(h: any): string;
    /**
     * Resolve a Namecoin name to its current value + metadata.
     *
     * @param {string} name  e.g. "d/testls"
     * @returns {Promise<{name:string,value:string,txid:string,height:number,expires_in?:number,tip?:number}|null>}
     */
    nameShow(name: string): Promise<{
        name: string;
        value: string;
        txid: string;
        height: number;
        expires_in?: number;
        tip?: number;
    } | null>;
    /**
     * Run one nameShow query against a specific host. In pool mode,
     * reuses an existing warm connection; otherwise opens a new one.
     *
     * @param {{host:string,port:number,tls?:boolean}} host
     * @param {string} name
     */
    _queryOnHost(host: {
        host: string;
        port: number;
        tls?: boolean;
    }, name: string): Promise<any>;
    /** Per-resolve dedicated TCP/TLS connection (legacy mode). */
    _queryDedicated(host: any, name: any): any;
    /** Pooled-connection query path. */
    _queryPooled(host: any, name: any): Promise<any>;
    /** Close all pooled connections. Idempotent. */
    close(): void;
}
/**
 * Single warm TCP/TLS connection to one ElectrumX host with an internal
 * request queue and idle timeout. Multiple concurrent `request(name)`
 * calls multiplex over the same socket via JSON-RPC ids.
 */
export class PooledConnection {
    constructor({ host, socks5, certPins, rejectUnauthorized, connectTimeoutMs, keepaliveMs, logger, onClose }: {
        host: any;
        socks5: any;
        certPins: any;
        rejectUnauthorized: any;
        connectTimeoutMs: any;
        keepaliveMs: any;
        logger: any;
        onClose: any;
    });
    host: any;
    socks5: any;
    certPins: any;
    rejectUnauthorized: any;
    connectTimeoutMs: any;
    keepaliveMs: any;
    logger: any;
    onClose: any;
    socket: any;
    connecting: any;
    dead: boolean;
    buf: string;
    /** @type {Map<number, {resolve:Function, reject:Function, timer:any}>} */
    pending: Map<number, {
        resolve: Function;
        reject: Function;
        timer: any;
    }>;
    nextId: number;
    idleTimer: number;
    /**
     * Send a nameShow query. Returns a promise.
     */
    request(name: any, queryTimeoutMs: any, opts?: {}): Promise<{
        name: string;
        value: string;
        txid: string;
        height: number;
        expires_in?: number;
        tip?: number;
    }>;
    _ensureConnected(): any;
    _onData(chunk: any): void;
    _call(method: any, params: any, timeoutMs: any): any;
    _kill(err: any): void;
    _cancelIdle(): void;
    _scheduleIdle(): void;
    destroy(): void;
}
export function buildNameIndexScript(nameBytes: any): any;
export function electrumScriptHash(script: any): any;
/**
 * Parse a NAME_* script and return {name, value}.
 *
 * Script layout:
 *   <OP_NAME_UPDATE or OP_NAME_FIRSTUPDATE> <push(name)> [<push(rand=20B)>] <push(value)> OP_2DROP OP_DROP <address script...>
 *
 * NAME_FIRSTUPDATE has an extra 'rand' push between name and value
 * which MUST be exactly 20 bytes. If a candidate FIRSTUPDATE script
 * has a middle push of any other length we fall through to the
 * 2-push (UPDATE-style) interpretation rather than blindly skipping
 * a push of unknown size.
 *
 * @param {Buffer} script
 * @returns {{name:string, value:string, op:number}|null}
 */
export function parseNameScript(script: Buffer): {
    name: string;
    value: string;
    op: number;
} | null;
export function parseNameFromTx(tx: any, expectedName: any): {
    name: string;
    value: string;
    op: number;
};
export function pushData(data: any): any;
export function readPushData(script: any, pos: any): {
    data: any;
    next: any;
};
/**
 * Parse the NAMECOIN_ELECTRUMX_CERT_PIN env value into a list of pin
 * descriptors. Accepts:
 *   - Plain 64-hex string  → DER fingerprint of the peer cert.
 *   - `sha256/<base64>`    → SHA-256 of the peer's SubjectPublicKeyInfo (SPKI).
 *   - Comma-separated list of either form (any-match).
 *
 * @param {string|null|undefined} raw
 * @returns {Array<{kind:'der',hex:string} | {kind:'spki',b64:string}>}
 */
export function parseCertPins(raw: string | null | undefined): Array<{
    kind: "der";
    hex: string;
} | {
    kind: "spki";
    b64: string;
}>;
/**
 * Verify a connected TLS socket against a parsed pin list. Throws
 * with a useful message on mismatch / missing certificate. No-op when
 * `pins` is empty.
 */
export function verifyCertPins(socket: any, pins: any): void;
export function classifyError(err: any): "other" | "closed" | "tls" | "timeout" | "cert-pin" | "socket" | "parse" | "socks5" | "dns" | "refused" | "unreachable";
export const OP_NAME_UPDATE: 83;
export const OP_NAME_FIRSTUPDATE: 82;
export const NAME_EXPIRE_DEPTH: 36000;
export const MAX_HISTORY_WALK: 32;
export const TIP_CACHE_TTL_MS: 60000;
/**
 * Pure(ish) helper: given an ElectrumX history list, the chain tip, a
 * confirmation requirement, and a tx fetcher, pick the highest-height
 * confirmed tx whose vouts contain a NAME_UPDATE / NAME_FIRSTUPDATE for
 * the requested name. Returns the same shape as nameShow.
 *
 * Implements three correctness fixes:
 *   1. Filters out mempool/unconfirmed (height <= 0) and entries with
 *      fewer than minConfirmations confirmations BEFORE picking.
 *   2. Walks newest → oldest (capped at MAX_HISTORY_WALK) so a junk UTXO
 *      that landed on the canonical scripthash can't censor the real
 *      name.
 *   3. Uses the actual chosen tx's height for expiry math.
 *
 * @param {object} args
 * @param {string} args.name
 * @param {Array<{tx_hash:string, height:number}>} args.history
 * @param {number|null} args.tip
 * @param {number} args.minConfirmations
 * @param {(txHash:string)=>Promise<any>} args.fetchTx
 * @param {(level:string,...args:any[])=>void} [args.logger]
 * @returns {Promise<{name:string,value:string,txid:string,height:number,expires_in?:number,tip?:number}|null>}
 */
export function selectNameRowFromHistory({ name, history, tip, minConfirmations, fetchTx, logger }: {
    name: string;
    history: Array<{
        tx_hash: string;
        height: number;
    }>;
    tip: number | null;
    minConfirmations: number;
    fetchTx: (txHash: string) => Promise<any>;
    logger?: (level: string, ...args: any[]) => void;
}): Promise<{
    name: string;
    value: string;
    txid: string;
    height: number;
    expires_in?: number;
    tip?: number;
} | null>;
/** Test-only: reset the module-level tip cache. */
export function _resetTipCacheForTests(): void;
export const NAMECOIN_NAME_MAX_BYTES: 255;
import { HostBreaker } from "./circuit";
