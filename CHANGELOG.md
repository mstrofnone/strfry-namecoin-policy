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
