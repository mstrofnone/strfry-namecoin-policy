# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Documentation
- Clarify in README that the plugin talks **only** to ElectrumX (TCP/TLS)
  and never opens a JSON-RPC connection to `namecoind`. Add a
  "Deployment topologies" section covering external public ElectrumX,
  self-hosted ElectrumX + namecoind, and load-balanced failover.

## v0.2.0 — unreleased

### Security
- **SPKI cert pins.** `NAMECOIN_ELECTRUMX_CERT_PIN` now accepts
  `sha256/<base64>` SubjectPublicKeyInfo pins in addition to the legacy
  64-hex DER fingerprint, and accepts a comma-separated list of pins so
  operators can rotate without flipping a kill switch. SPKI pins survive
  cert renewal as long as the key is reused.
- **Rate-limited ElectrumX lookups.** Added an in-process token-bucket
  limiter (`NAMECOIN_POLICY_LOOKUP_RPS`, default 5; `..._BURST`, default 10;
  `..._QUEUE_MS`, default 2000) gating outbound `nameShow` calls. Cache hits
  are exempt. Throttled lookups produce a `rate-limited:` reject so abusive
  clients can't exhaust upstream capacity.
- **Fail-closed by default.** When `NAMECOIN_ELECTRUMX_HOST` is unset, the
  plugin now rejects `.bit` kind:0 events instead of silently accepting them.
  Set `NAMECOIN_POLICY_SOFT_FAIL=true` to opt back into the legacy
  accept-everything behavior. A startup banner makes either choice loud.
- **INSECURE banner.** Setting `NAMECOIN_ELECTRUMX_INSECURE=true` now emits
  a hard-to-miss multi-line warning to stderr at startup so MITM-vulnerable
  setups can't quietly ship to production.
- **Bounded Namecoin name length.** `resolver.parseIdentifier` now rejects
  names whose post-namespace stem exceeds 64 chars, and `electrumx.nameShow`
  refuses names longer than the 255-byte Namecoin consensus cap before
  building a script. Stops adversarial input from blowing up push-data.

## [0.1.0] — 2026-04-19

### Added
- Initial release.
- strfry write-policy plugin (`bin/strfry-namecoin-policy.js`) that reads
  JSONL events from stdin and emits accept/reject decisions to stdout.
- `ElectrumXClient` — minimal TLS/TCP JSON-RPC client with per-query
  timeouts, retries, and optional SHA-256 DER cert pinning.
- `NamecoinResolver` — parses NIP-05 identifiers (`user@name.bit`,
  `name.bit`, `d/name`, `id/name`) and extracts pubkeys/relay hints
  from Namecoin name values.
- LRU cache with TTL for resolved identities.
- Kind:0 verification: any `.bit` NIP-05 is verified against the
  Namecoin blockchain; mismatches are rejected with a NIP-20 message.
- Optional `all-kinds-require-bit` mode: non-kind-0 events require the
  author to have been seen in a verified `.bit` kind:0 first.
- Unit tests (`node:test`) covering cache, resolver parsing/extraction,
  handler logic, config parsing, and an end-to-end stdin/stdout test.
- Live integration test script (`test/live.js`, gated by
  `LIVE_ELECTRUMX=1`).
- README with install, config, strfry.conf snippet, and security notes.
