/**
 * Build a config object from environment variables.
 * See README.md for the full list.
 */
export function loadConfig(env?: any): {
    host: any;
    port: number;
    tls: any;
    hosts: {
        host: string;
        port: number;
        tls: any;
    }[];
    socks5: {
        host: string;
        port: number;
    };
    certPinSha256: any;
    insecure: any;
    rejectUnauthorized: boolean;
    timeoutMs: number;
    retries: number;
    mode: any;
    cacheTtlMs: number;
    negCacheTtlMs: any;
    minConfirmations: any;
    cachePath: any;
    metricsPort: number;
    poolKeepaliveMs: number;
    logLevel: any;
    allowNonBit: any;
    lookupRps: any;
    lookupBurst: any;
    lookupQueueMs: any;
    softFail: any;
    nip9aRulesFile: any;
    nip9aCommunity: any;
    nip9aRequireRules: any;
    nip9aRejectImetaKind1: any;
};
export function makeLogger(level: any): (msgLevel: any, ...args: any[]) => void;
