'use strict';

/**
 * Connection helpers for ElectrumX clients.
 *
 *   connect({ host, port, tls, ... })
 *
 * Picks one of three transport paths:
 *
 *   1. SOCKS5  — when `socks5: { host, port }` is set. Open SOCKS5
 *      tunnel, optionally upgrade to TLS. Hostname resolution is
 *      delegated to the proxy; we never call `dns.lookup` here.
 *
 *   2. Happy-eyeballs (RFC 8305 light) — when no SOCKS5 is set and
 *      the target hostname resolves to multiple addresses (typically
 *      A + AAAA). Try them in order with 250 ms staggered starts;
 *      the first TCP connection that completes wins, and the others
 *      are aborted. If the target is already a literal IP we skip
 *      DNS and just connect directly.
 *
 *   3. Single direct connect — fallback when only one address.
 *
 * After TCP is established, if `tls` is true we wrap with
 * `tls.connect({ socket, ... })` and resolve once the secure handshake
 * completes. Cert pinning is the caller's responsibility (it inspects
 * the resolved socket).
 */

const dns = require('node:dns');
const net = require('node:net');
const tls = require('node:tls');
const { connectSocks5 } = require('./socks5');

const HAPPY_EYEBALLS_DELAY_MS = 250;

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
async function connect(opts) {
  const {
    host, port,
    tls: useTls = false,
    servername,
    rejectUnauthorized = true,
    socks5,
    timeoutMs = 10_000,
    logger = () => {},
  } = opts;

  if (!host) throw new Error('connect: host is required');
  if (!Number.isFinite(port)) throw new Error('connect: port is required');

  const tcpSocket = socks5
    ? await connectSocks5({
        proxyHost: socks5.host,
        proxyPort: socks5.port,
        host, port,
        timeoutMs,
      })
    : await connectHappyEyeballs({ host, port, timeoutMs, logger });

  if (!useTls) return tcpSocket;

  return upgradeTls(tcpSocket, {
    host,
    servername,
    rejectUnauthorized,
    timeoutMs,
  });
}

/**
 * Wrap an existing TCP socket with TLS. Resolves once the secure
 * handshake is complete. Any pre-handshake error rejects.
 */
function upgradeTls(rawSocket, { host, servername, rejectUnauthorized, timeoutMs }) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const isIp = net.isIP(host) !== 0;
    const sni = servername || (isIp ? undefined : host);

    const tlsSocket = tls.connect({
      socket: rawSocket,
      rejectUnauthorized,
      ...(sni ? { servername: sni } : {}),
    });

    const finish = (err, sock) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      tlsSocket.removeAllListeners('secureConnect');
      tlsSocket.removeAllListeners('error');
      if (err) {
        try { tlsSocket.destroy(); } catch (_) {}
        try { rawSocket.destroy(); } catch (_) {}
        reject(err);
      } else {
        resolve(sock);
      }
    };

    const timer = setTimeout(() => finish(new Error(`TLS handshake timeout after ${timeoutMs}ms`)), timeoutMs);

    tlsSocket.once('secureConnect', () => finish(null, tlsSocket));
    tlsSocket.once('error', (err) => finish(new Error(`TLS error: ${err.message}`)));
  });
}

/**
 * RFC 8305-light happy-eyeballs. For each resolved address, kick off a
 * connect 250 ms after the previous one. The first to fire 'connect'
 * wins; the others are destroyed.
 */
function connectHappyEyeballs({ host, port, timeoutMs, logger }) {
  return new Promise((resolve, reject) => {
    let settled = false;
    let totalAddrs = 0;
    let errorCount = 0;
    const sockets = [];
    const errors = [];
    const staggerTimers = [];

    const finish = (err, sock) => {
      if (settled) return;
      settled = true;
      clearTimeout(overallTimer);
      for (const t of staggerTimers) clearTimeout(t);
      for (const s of sockets) {
        if (s !== sock) {
          try { s.destroy(); } catch (_) {}
        }
      }
      if (err) reject(err); else resolve(sock);
    };

    const overallTimer = setTimeout(() => {
      finish(new Error(`TCP connect timeout after ${timeoutMs}ms (${host}:${port})`));
    }, timeoutMs);

    const tryAddr = (addr, family) => {
      if (settled) return;
      const s = net.connect({ host: addr, port, family });
      sockets.push(s);
      s.once('connect', () => finish(null, s));
      s.once('error', (err) => {
        errors.push(`${addr}: ${err.message}`);
        errorCount++;
        // If every address has now errored, we're done with no winner.
        if (errorCount >= totalAddrs && sockets.length >= totalAddrs) {
          finish(new Error(`all addresses failed for ${host}:${port}: ${errors.join('; ')}`));
        }
      });
    };

    const scheduleNext = (addrs, i) => {
      if (settled || i >= addrs.length) return;
      tryAddr(addrs[i].address, addrs[i].family);
      if (i + 1 < addrs.length) {
        const t = setTimeout(() => scheduleNext(addrs, i + 1), HAPPY_EYEBALLS_DELAY_MS);
        staggerTimers.push(t);
      }
    };

    // If the host is already a literal IP, skip DNS.
    if (net.isIP(host) !== 0) {
      totalAddrs = 1;
      tryAddr(host, net.isIP(host));
      return;
    }

    dns.lookup(host, { all: true }, (err, addrs) => {
      if (settled) return;
      if (err) return finish(new Error(`DNS lookup ${host} failed: ${err.message}`));
      if (!addrs || addrs.length === 0) return finish(new Error(`DNS lookup ${host} returned no addresses`));
      // Interleave IPv6/IPv4 per RFC 8305 when both are present.
      const ipv6 = addrs.filter((a) => a.family === 6);
      const ipv4 = addrs.filter((a) => a.family === 4);
      const interleaved = [];
      const maxLen = Math.max(ipv6.length, ipv4.length);
      for (let i = 0; i < maxLen; i++) {
        if (i < ipv6.length) interleaved.push(ipv6[i]);
        if (i < ipv4.length) interleaved.push(ipv4[i]);
      }
      totalAddrs = interleaved.length;
      logger('debug', `connect: ${host} -> ${interleaved.map((a) => a.address).join(',')}`);
      scheduleNext(interleaved, 0);
    });
  });
}

module.exports = { connect, HAPPY_EYEBALLS_DELAY_MS };
