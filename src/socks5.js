'use strict';

/**
 * Minimal SOCKS5 CONNECT client. No-auth only.
 *
 * Wire format (RFC 1928):
 *
 *   Greeting (client → server):
 *     0x05 <NMETHODS> <METHODS...>      we send 0x05 0x01 0x00
 *
 *   Choice (server → client):
 *     0x05 <method>                     we require method == 0x00
 *
 *   Request (client → server):
 *     0x05 0x01 0x00 <ATYP> <DSTADDR> <DSTPORT>
 *       ATYP=0x03 = domain (we always use this so SOCKS5 does the DNS)
 *
 *   Reply (server → client):
 *     0x05 <REP> 0x00 <ATYP> <BNDADDR> <BNDPORT>
 *       REP must be 0x00 for success.
 *
 * After the reply, the underlying TCP socket is a transparent tunnel
 * to <DSTADDR>:<DSTPORT>. Caller can then upgrade to TLS (or whatever).
 *
 * No timeouts here — caller wraps with their own.
 */

const net = require('node:net');

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
function connectSocks5({ proxyHost, proxyPort, host, port, timeoutMs = 10_000 }) {
  if (!proxyHost) throw new Error('connectSocks5: proxyHost required');
  if (!Number.isFinite(proxyPort)) throw new Error('connectSocks5: proxyPort required');
  if (!host) throw new Error('connectSocks5: host required');
  if (!Number.isFinite(port)) throw new Error('connectSocks5: port required');
  // ATYP=0x03 (domainname) supports up to 255 bytes. RFC 1928.
  const hostBuf = Buffer.from(host, 'ascii');
  if (hostBuf.length > 255) throw new Error('connectSocks5: hostname too long for SOCKS5');

  return new Promise((resolve, reject) => {
    const sock = net.connect({ host: proxyHost, port: proxyPort });
    let stage = 'greeting';
    let buf = Buffer.alloc(0);
    let settled = false;

    const finish = (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      sock.removeAllListeners('data');
      sock.removeAllListeners('error');
      sock.removeAllListeners('end');
      sock.removeAllListeners('close');
      if (err) {
        try { sock.destroy(); } catch (_) {}
        reject(err);
      } else {
        resolve(sock);
      }
    };

    const timer = setTimeout(() => finish(new Error(`SOCKS5 timeout after ${timeoutMs}ms`)), timeoutMs);

    sock.once('connect', () => {
      // Greeting: VER=5, NMETHODS=1, METHOD=0x00 (no-auth)
      sock.write(Buffer.from([0x05, 0x01, 0x00]));
    });

    sock.on('data', (chunk) => {
      buf = Buffer.concat([buf, chunk]);

      if (stage === 'greeting') {
        if (buf.length < 2) return;
        const ver = buf[0], method = buf[1];
        buf = buf.slice(2);
        if (ver !== 0x05) return finish(new Error(`SOCKS5: bad version in greeting reply: 0x${ver.toString(16)}`));
        if (method === 0xff) return finish(new Error('SOCKS5: server rejected all auth methods'));
        if (method !== 0x00) return finish(new Error(`SOCKS5: unsupported auth method 0x${method.toString(16)} (no-auth only)`));

        // Send CONNECT request: VER=5, CMD=1 (CONNECT), RSV=0, ATYP=3 (domain), LEN, NAME, PORT(2)
        const portBuf = Buffer.alloc(2);
        portBuf.writeUInt16BE(port, 0);
        const req = Buffer.concat([
          Buffer.from([0x05, 0x01, 0x00, 0x03, hostBuf.length]),
          hostBuf,
          portBuf,
        ]);
        sock.write(req);
        stage = 'reply';
        return;
      }

      if (stage === 'reply') {
        // Need at least 4 bytes (VER, REP, RSV, ATYP) + variable bnd + 2 port
        if (buf.length < 4) return;
        const ver = buf[0], rep = buf[1], atyp = buf[3];
        if (ver !== 0x05) return finish(new Error(`SOCKS5: bad version in CONNECT reply: 0x${ver.toString(16)}`));
        if (rep !== 0x00) {
          return finish(new Error(`SOCKS5: CONNECT failed with REP=0x${rep.toString(16)} (${repName(rep)})`));
        }
        let need;
        if (atyp === 0x01) need = 4 + 4 + 2;        // IPv4
        else if (atyp === 0x04) need = 4 + 16 + 2;  // IPv6
        else if (atyp === 0x03) {
          if (buf.length < 5) return;
          const dlen = buf[4];
          need = 4 + 1 + dlen + 2;
        } else return finish(new Error(`SOCKS5: unknown ATYP 0x${atyp.toString(16)} in reply`));

        if (buf.length < need) return;
        // Strip the SOCKS reply bytes and hand the socket back. Any
        // remaining bytes after `need` are real tunnel data; emit them
        // as a 'data' event so the caller doesn't lose them.
        const leftover = buf.slice(need);
        buf = Buffer.alloc(0);
        stage = 'tunnel';
        // Detach our data handler before resolving so caller can attach.
        sock.removeAllListeners('data');
        finish(null);
        if (leftover.length > 0) {
          // Re-emit on next tick so the caller has time to attach.
          setImmediate(() => sock.emit('data', leftover));
        }
      }
    });

    sock.on('error', (err) => finish(new Error(`SOCKS5 socket error: ${err.message}`)));
    sock.on('end',   () => finish(new Error('SOCKS5 server closed connection')));
    sock.on('close', () => finish(new Error('SOCKS5 connection closed')));
  });
}

function repName(rep) {
  switch (rep) {
    case 0x01: return 'general SOCKS server failure';
    case 0x02: return 'connection not allowed by ruleset';
    case 0x03: return 'network unreachable';
    case 0x04: return 'host unreachable';
    case 0x05: return 'connection refused';
    case 0x06: return 'TTL expired';
    case 0x07: return 'command not supported';
    case 0x08: return 'address type not supported';
    default:   return 'unknown';
  }
}

module.exports = { connectSocks5 };
