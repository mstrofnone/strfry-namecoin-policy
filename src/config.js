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
    logLevel,
    allowNonBit: parseBool(env.NAMECOIN_POLICY_ALLOW_NON_BIT, true),
  };
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
