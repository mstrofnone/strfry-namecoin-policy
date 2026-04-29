/**
 * Create a SOCKS5-tunneled TCP connection.
 *
 * @param {object} opts
 * @param {string} opts.proxyHost
 * @param {number} opts.proxyPort
 * @param {string} opts.host    target hostname (sent to SOCKS5 — DNS happens proxy-side)
 * @param {number} opts.port    target port
 * @param {number} [opts.timeoutMs=10000]
 * @returns {Promise<net.Socket>}
 */
export function connectSocks5({ proxyHost, proxyPort, host, port, timeoutMs }: {
    proxyHost: string;
    proxyPort: number;
    host: string;
    port: number;
    timeoutMs?: number;
}): Promise<net.Socket>;
