# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## v0.2.0 — unreleased

### Added
- **Persistent on-disk cache** (`NAMECOIN_POLICY_CACHE_PATH`). Both the
  resolver cache and the verified-author set persist across restarts.
  Uses `better-sqlite3` when available (now an optional dependency);
  falls back to a JSONL append-log with in-place compaction.
- **Prometheus metrics** (`NAMECOIN_POLICY_METRICS_PORT`). Optional
  HTTP listener bound to `127.0.0.1` exposing `/metrics` and
  `/healthz`. Counters: `lookups_total`, `cache_hits_total`,
  `cache_misses_total`, `acceptances_total`,
  `rejections_total{reason=...}`, `electrumx_errors_total{type=...}`.
  Histogram: `lookup_duration_ms` with `[10,50,100,250,500,1000,
  2500,5000,+Inf]` ms buckets.
- **SOCKS5 client** (`NAMECOIN_ELECTRUMX_SOCKS5`). Pure-Node, no-auth,
  ATYP=domain so DNS is delegated to the proxy — lets you tunnel
  ElectrumX traffic through Tor (`127.0.0.1:9050`) without leaking
  the lookup hostname.
- **Warm-connection pool** (`NAMECOIN_POLICY_POOL_KEEPALIVE_MS`,
  default 30 s). One TCP/TLS connection per host, request-queued via
  JSON-RPC ids. Auto-reconnects after socket death. Set to `0` to keep
  the legacy per-resolve behavior.
- **Multi-ElectrumX with circuit breaker** (`NAMECOIN_ELECTRUMX_HOSTS`).
  Round-robin across a comma-separated host list. Each host has its
  own breaker: 30 s open on failure, exponential backoff (cap 5 min)
  after repeated half-open failures. When every host is open we still
  round-robin (forced probe) rather than soft-fail every event.
- **Happy-eyeballs IPv6/IPv4** (automatic). DNS lookups enumerate all
  addresses; we connect with a 250 ms stagger (RFC 8305 light) and
  the first TCP win cancels the rest. Skipped when SOCKS5 is enabled.
- **`better-sqlite3`** as an `optionalDependencies` entry. Runtime
  falls back to JSONL when it isn't installable on the target.

### Changed
- `ElectrumXClient` constructor now accepts `hosts`, `socks5`,
  `poolKeepaliveMs`, and `metrics`. Single-host shorthand
  (`host`/`port`/`tls`) still works exactly as before.
- `NamecoinResolver` constructor accepts a `cache` (any object
  exposing `get/set/has/delete/clear/size`) and a `metrics` instance.
  When `cache` is supplied, `cacheTtlMs`/`cacheMax` are ignored.

### Documentation
- Add an "Operational" section to README covering all six new env
  vars with one-line examples.
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
