/**
 * Build a config object from environment variables.
 * See README.md for the full list.
 */
export function loadConfig(env?: any): {
    host: any;
    port: number;
    tls: any;
    certPinSha256: any;
    rejectUnauthorized: boolean;
    timeoutMs: number;
    retries: number;
    mode: any;
    cacheTtlMs: number;
    logLevel: any;
    allowNonBit: any;
};
export function makeLogger(level: any): (msgLevel: any, ...args: any[]) => void;
