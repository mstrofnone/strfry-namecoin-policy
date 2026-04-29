/**
 * @param {object} opts
 * @param {string} opts.host
 * @param {number} opts.port
 * @param {boolean} [opts.tls=false]
 * @param {string} [opts.servername]            TLS SNI; defaults to host (skipped for IP literals)
 * @param {boolean} [opts.rejectUnauthorized=true]
 * @param {{host:string,port:number}} [opts.socks5]
 * @param {number} [opts.timeoutMs=10000]       overall budget
 * @param {(level:string,...args:any[])=>void} [opts.logger]
 * @returns {Promise<import('node:net').Socket>}
 */
export function connect(opts: {
    host: string;
    port: number;
    tls?: boolean;
    servername?: string;
    rejectUnauthorized?: boolean;
    socks5?: {
        host: string;
        port: number;
    };
    timeoutMs?: number;
    logger?: (level: string, ...args: any[]) => void;
}): Promise<any>;
export const HAPPY_EYEBALLS_DELAY_MS: 250;
