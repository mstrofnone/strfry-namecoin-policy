#!/bin/sh
#
# Example strfry wrapper for strfry-namecoin-policy.
#
# strfry's plugin= directive is a single command path (no arguments) when
# auto-reload-on-mtime is desired. This wrapper injects environment variables
# and exec()s the plugin so stdio passes through unchanged.
#
# Install:
#   1. npm install -g strfry-namecoin-policy
#   2. cp wrapper.sh /opt/strfry/plugins/strfry-namecoin-policy-wrapper.sh
#   3. chmod +x /opt/strfry/plugins/strfry-namecoin-policy-wrapper.sh
#   4. In strfry.conf set: writePolicy { plugin = "/opt/strfry/plugins/strfry-namecoin-policy-wrapper.sh"; }
#   5. Reload strfry.

export NAMECOIN_ELECTRUMX_HOST="electrumx.testls.space"
export NAMECOIN_ELECTRUMX_PORT="50002"
export NAMECOIN_ELECTRUMX_TLS="true"
# export NAMECOIN_ELECTRUMX_CERT_PIN="<sha256-of-DER-cert-in-hex>"
export NAMECOIN_POLICY_MODE="kind0-only"
export NAMECOIN_POLICY_CACHE_TTL_MS="300000"
export NAMECOIN_POLICY_LOG_LEVEL="info"
export NAMECOIN_POLICY_ALLOW_NON_BIT="true"

exec /usr/bin/env node /usr/local/lib/node_modules/strfry-namecoin-policy/bin/strfry-namecoin-policy.js
