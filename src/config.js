'use strict';

/**
 * Build a config object from environment variables.
 * See README.md for the full list.
 */
function loadConfig(env = process.env) {
  const host = env.NAMECOIN_ELECTRUMX_HOST;
  const tls  = parseBool(env.NAMECOIN_ELECTRUMX_TLS, true);
  const port = env.NAMECOIN_ELECTRUMX_PORT
    ? parseInt(env.NAMECOIN_ELECTRUMX_PORT, 10)
    : (tls ? 50002 : 50001);

  const mode = (env.NAMECOIN_POLICY_MODE || 'kind0-only').trim();
  if (!['kind0-only', 'all-kinds-require-bit'].includes(mode)) {
    throw new Error(`NAMECOIN_POLICY_MODE: invalid value "${mode}". Use "kind0-only" or "all-kinds-require-bit".`);
  }

  const logLevel = (env.NAMECOIN_POLICY_LOG_LEVEL || 'info').trim();
  if (!['silent', 'info', 'debug'].includes(logLevel)) {
    throw new Error(`NAMECOIN_POLICY_LOG_LEVEL: invalid value "${logLevel}".`);
  }

  /** Disable TLS verification entirely (testing only — emits a banner). */
  const insecure = parseBool(env.NAMECOIN_ELECTRUMX_INSECURE, false);
  /** Cert pin(s): 64-hex DER fingerprints OR `sha256/<base64>` SPKI pins, comma-separated. */
  const certPinSha256 = env.NAMECOIN_ELECTRUMX_CERT_PIN || null;

  const minConf = parsePosInt(
    env.NAMECOIN_POLICY_MIN_CONFIRMATIONS, 1, 'NAMECOIN_POLICY_MIN_CONFIRMATIONS', { allowZero: true }
  );
  const negCacheTtlMs = parsePosInt(
    env.NAMECOIN_POLICY_NEG_CACHE_TTL_MS, 30_000, 'NAMECOIN_POLICY_NEG_CACHE_TTL_MS', { allowZero: true }
  );

  /** Sustained ElectrumX lookup rate (tokens/sec) for the global bucket. */
  const lookupRps = parsePositiveInt(env.NAMECOIN_POLICY_LOOKUP_RPS, 5, 'NAMECOIN_POLICY_LOOKUP_RPS');
  /** Max burst (bucket capacity) for ElectrumX lookups. */
  const lookupBurst = parsePositiveInt(env.NAMECOIN_POLICY_LOOKUP_BURST, 10, 'NAMECOIN_POLICY_LOOKUP_BURST');
  /** Max time (ms) a single lookup will wait for a token before failing. */
  const lookupQueueMs = parseNonNegativeInt(env.NAMECOIN_POLICY_LOOKUP_QUEUE_MS, 2000, 'NAMECOIN_POLICY_LOOKUP_QUEUE_MS');

  /** If true, missing NAMECOIN_ELECTRUMX_HOST means "accept everything" (footgun, off by default). */
  const softFail = parseBool(env.NAMECOIN_POLICY_SOFT_FAIL, false);

  // Multi-host (overrides single-host shorthand when set).
  const hosts = parseHostList(env.NAMECOIN_ELECTRUMX_HOSTS, tls);

  // SOCKS5 proxy: "host:port" — no auth.
  let socks5 = null;
  try { socks5 = parseHostPort(env.NAMECOIN_ELECTRUMX_SOCKS5); }
  catch (e) { throw new Error(`NAMECOIN_ELECTRUMX_SOCKS5: ${e.message}`); }

  // Persistent cache file path. Unset = in-memory only.
  const cachePath = env.NAMECOIN_POLICY_CACHE_PATH || null;

  // Metrics HTTP listener. 0 = disabled.
  const metricsPort = parseInt(env.NAMECOIN_POLICY_METRICS_PORT || '0', 10);
  if (!Number.isFinite(metricsPort) || metricsPort < 0 || metricsPort > 65535) {
    throw new Error(`NAMECOIN_POLICY_METRICS_PORT: invalid value "${env.NAMECOIN_POLICY_METRICS_PORT}".`);
  }

  // Connection pool keepalive. 0 disables (= per-resolve connection mode).
  const poolKeepaliveMs = parseInt(env.NAMECOIN_POLICY_POOL_KEEPALIVE_MS || '30000', 10);
  if (!Number.isFinite(poolKeepaliveMs) || poolKeepaliveMs < 0) {
    throw new Error(`NAMECOIN_POLICY_POOL_KEEPALIVE_MS: invalid value "${env.NAMECOIN_POLICY_POOL_KEEPALIVE_MS}".`);
  }

  return {
    host,
    port,
    tls,
    hosts,                    // [{host, port, tls}] when multi-host configured, else null
    socks5,                   // {host, port} or null
    certPinSha256,
    insecure,
    // If pinning is set, we verify manually; if INSECURE=1, skip verification entirely.
    // Otherwise use the system trust store.
    rejectUnauthorized: insecure ? false : !certPinSha256,
    timeoutMs: parseInt(env.NAMECOIN_ELECTRUMX_TIMEOUT_MS || '5000', 10),
    retries:   parseInt(env.NAMECOIN_ELECTRUMX_RETRIES   || '2',    10),
    mode,
    cacheTtlMs: parseInt(env.NAMECOIN_POLICY_CACHE_TTL_MS || '300000', 10),
    negCacheTtlMs,
    minConfirmations: minConf,
    cachePath,
    metricsPort,
    poolKeepaliveMs,
    logLevel,
    allowNonBit: parseBool(env.NAMECOIN_POLICY_ALLOW_NON_BIT, true),
    lookupRps,
    lookupBurst,
    lookupQueueMs,
    softFail,
  };
}

/**
 * Parse a non-negative integer env var. Throws on invalid input so
 * misconfiguration fails fast at startup instead of silently degrading.
 */
function parsePosInt(raw, dflt, varName, { allowZero = false } = {}) {
  if (raw == null || raw === '') return dflt;
  const n = Number(raw);
  if (!Number.isFinite(n) || !Number.isInteger(n)) {
    throw new Error(`${varName}: invalid value "${raw}" (expected integer)`);
  }
  if (n < 0 || (!allowZero && n === 0)) {
    throw new Error(`${varName}: invalid value "${raw}" (must be ${allowZero ? '≥0' : '>0'})`);
  }
  return n;
}

/**
 * Parse "h1:p1,h2:p2,..." into [{host, port, tls}, ...]. Returns null if
 * unset/empty. Inherits TLS flag (no per-host override; keep it simple).
 */
function parseHostList(raw, tls) {
  if (!raw || !String(raw).trim()) return null;
  const out = [];
  for (const piece of String(raw).split(',')) {
    const s = piece.trim();
    if (!s) continue;
    let hp;
    try { hp = parseHostPort(s); }
    catch (e) { throw new Error(`NAMECOIN_ELECTRUMX_HOSTS: ${e.message}`); }
    if (!hp) throw new Error(`NAMECOIN_ELECTRUMX_HOSTS: invalid host:port "${s}"`);
    out.push({ host: hp.host, port: hp.port || (tls ? 50002 : 50001), tls });
  }
  return out.length ? out : null;
}

/**
 * Parse "host:port" → { host, port }. Returns null if input empty/unset.
 * Throws if shape is wrong.
 */
function parseHostPort(raw) {
  if (!raw || !String(raw).trim()) return null;
  const s = String(raw).trim();
  // Allow IPv6 in brackets: [::1]:1080
  const m6 = s.match(/^\[([^\]]+)\]:(\d+)$/);
  if (m6) return { host: m6[1], port: parseInt(m6[2], 10) };
  const idx = s.lastIndexOf(':');
  if (idx <= 0 || idx === s.length - 1) {
    throw new Error(`expected host:port, got "${s}"`);
  }
  const host = s.slice(0, idx);
  const port = parseInt(s.slice(idx + 1), 10);
  if (!Number.isFinite(port) || port <= 0 || port > 65535) {
    throw new Error(`expected host:port with 1-65535 port, got "${s}"`);
  }
  return { host, port };
}

function parseBool(val, dflt) {
  if (val == null || val === '') return dflt;
  const v = String(val).toLowerCase().trim();
  if (['1', 'true', 'yes', 'y', 'on'].includes(v)) return true;
  if (['0', 'false', 'no', 'n', 'off'].includes(v)) return false;
  return dflt;
}

function parsePositiveInt(val, dflt, name) {
  if (val == null || val === '') return dflt;
  const n = Number(val);
  if (!Number.isFinite(n) || n <= 0) {
    throw new Error(`${name}: must be a positive number, got "${val}"`);
  }
  return n;
}

function parseNonNegativeInt(val, dflt, name) {
  if (val == null || val === '') return dflt;
  const n = Number(val);
  if (!Number.isFinite(n) || n < 0) {
    throw new Error(`${name}: must be a non-negative number, got "${val}"`);
  }
  return n;
}

function makeLogger(level) {
  const levels = { silent: 0, info: 1, debug: 2 };
  const lv = levels[level] ?? 1;
  return (msgLevel, ...args) => {
    const mlv = levels[msgLevel] ?? 1;
    if (mlv <= lv && mlv > 0) {
      // strfry captures stderr into its own logs
      console.error(`[strfry-namecoin-policy ${msgLevel}]`, ...args);
    }
  };
}

module.exports = { loadConfig, makeLogger };
