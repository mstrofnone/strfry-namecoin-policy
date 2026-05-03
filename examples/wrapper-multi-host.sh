#!/bin/sh
#
# Example strfry wrapper using NAMECOIN_ELECTRUMX_HOSTS (multi-host).
#
# This is the RECOMMENDED setup for production .bit-gated relays:
#   - Run a local Namecoin Core + ElectrumX-NMC on the relay host
#     (see https://github.com/namecoin/namecoin.org/pull/749 for an
#     end-to-end deploy script).
#   - List the local server FIRST and one or more public servers as
#     fallback. The plugin's HostBreaker tries hosts in order, marks
#     unhealthy ones, and probes them again after a cooldown.
#   - Pin every cert. NAMECOIN_ELECTRUMX_CERT_PIN accepts a comma-
#     separated list of pins (DER SHA-256 hex, or `sha256/<base64>`
#     SPKI). Each pin is matched independently per host, so it is
#     fine to pin the local self-signed cert AND the public server's
#     cert in the same string.
#
# Why local-primary?
#   - A single public ElectrumX is a single point of failure exactly
#     like DNS + Web PKI was. The whole point of Namecoin .bit NIP-05
#     is to remove that dependency for clients; the relay should not
#     reintroduce it server-side.
#   - Local lookups never leak per-event author metadata to a third
#     party.
#   - Local lookups remove the per-lookup network latency that
#     otherwise dominates write-policy decision time on busy relays.
#
# Install:
#   1. npm install -g strfry-namecoin-policy
#   2. cp wrapper-multi-host.sh /opt/strfry/plugins/strfry-namecoin-policy-wrapper.sh
#   3. chmod +x /opt/strfry/plugins/strfry-namecoin-policy-wrapper.sh
#   4. Edit the host list / pins for your deployment.
#   5. In strfry.conf set: writePolicy { plugin = "/opt/strfry/plugins/strfry-namecoin-policy-wrapper.sh"; }
#   6. Reload strfry.

# Local primary, public fallback. ORDER MATTERS — local is tried first.
export NAMECOIN_ELECTRUMX_HOSTS="127.0.0.1:50002,electrumx.testls.space:50002"
export NAMECOIN_ELECTRUMX_TLS="true"

# Pin every host. Comma-separated; both local self-signed and public
# server pins fit here. Replace the first hex with the SHA-256 of your
# local /home/electrumx/ssl/server.crt in DER form, e.g.
#   openssl x509 -in /home/electrumx/ssl/server.crt -outform DER \
#     | sha256sum | awk '{print $1}'
export NAMECOIN_ELECTRUMX_CERT_PIN="<local-der-sha256-hex>,5365d5bb2619f5401cd88efcaffba5b2a0ea7a992df70f057e9bcd5036c7799c"

# Conservative network behaviour for a server with two upstreams.
export NAMECOIN_ELECTRUMX_TIMEOUT_MS="8000"
export NAMECOIN_ELECTRUMX_RETRIES="2"

# Strict gating: every kind requires a verified .bit author.
export NAMECOIN_POLICY_MODE="all-kinds-require-bit"
export NAMECOIN_POLICY_ALLOW_NON_BIT="false"

# 5 min positive cache, default 30 s negative cache.
export NAMECOIN_POLICY_CACHE_TTL_MS="300000"
export NAMECOIN_POLICY_LOG_LEVEL="info"

exec /usr/bin/env node /usr/local/lib/node_modules/strfry-namecoin-policy/bin/strfry-namecoin-policy.js
