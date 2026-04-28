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

  const insecure = parseBool(env.NAMECOIN_ELECTRUMX_INSECURE, false);
  const certPinSha256 = env.NAMECOIN_ELECTRUMX_CERT_PIN || null;

  const minConf = parsePosInt(
    env.NAMECOIN_POLICY_MIN_CONFIRMATIONS, 1, 'NAMECOIN_POLICY_MIN_CONFIRMATIONS', { allowZero: true }
  );
  const negCacheTtlMs = parsePosInt(
    env.NAMECOIN_POLICY_NEG_CACHE_TTL_MS, 30_000, 'NAMECOIN_POLICY_NEG_CACHE_TTL_MS', { allowZero: true }
  );

  return {
    host,
    port,
    tls,
    certPinSha256,
    // If pinning is set, we verify manually; if INSECURE=1, skip verification entirely.
    // Otherwise use the system trust store.
    rejectUnauthorized: insecure ? false : !certPinSha256,
    timeoutMs: parseInt(env.NAMECOIN_ELECTRUMX_TIMEOUT_MS || '5000', 10),
    retries:   parseInt(env.NAMECOIN_ELECTRUMX_RETRIES   || '2',    10),
    mode,
    cacheTtlMs: parseInt(env.NAMECOIN_POLICY_CACHE_TTL_MS || '300000', 10),
    negCacheTtlMs,
    minConfirmations: minConf,
    logLevel,
    allowNonBit: parseBool(env.NAMECOIN_POLICY_ALLOW_NON_BIT, true),
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

function parseBool(val, dflt) {
  if (val == null || val === '') return dflt;
  const v = String(val).toLowerCase().trim();
  if (['1', 'true', 'yes', 'y', 'on'].includes(v)) return true;
  if (['0', 'false', 'no', 'n', 'off'].includes(v)) return false;
  return dflt;
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
