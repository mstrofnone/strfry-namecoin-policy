# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## v0.3.0 — unreleased

### Added
- **NIP-9B rules enforcement.** New optional layer that validates accepted
  events against a signed `kind:34551` *Verifiable Community Rules*
  document
  ([nostr-protocol/nips#2331](https://github.com/nostr-protocol/nips/pull/2331)).
  Shares evaluation order with the Quartz validator merged in
  [vitorpamplona/amethyst#2758](https://github.com/vitorpamplona/amethyst/pull/2758)
  and the JS reference in
  [mstrofnone/nip9a-refimpl](https://github.com/mstrofnone/nip9a-refimpl).
  Author deny-list, kind whitelist, per-kind and global size caps,
  per-day quota gate (passive), WoT gate (passive), and anti-rollback
  ratchet are all honoured. New modules `src/nip9a-parser.js`,
  `src/nip9a-validator.js`, `src/nip9a-loader.js`.
- **New env vars** (all default-off; off = full back-compat with v0.2.x):
    - `NAMECOIN_POLICY_NIP9A_RULES_FILE` — path to a signed rules event
      JSON. Re-read on `SIGHUP` and mtime change. Atomic-rename safe.
    - `NAMECOIN_POLICY_NIP9A_COMMUNITY` — `34550:<hex64>:<d>` address
      pointer that filters which rules events the loader accepts.
    - `NAMECOIN_POLICY_NIP9A_REQUIRE_RULES` — reject everything when the
      loader has no active rules document. Default `false`; rules
      absence is pass-through per NIP-9B behaviour spec.
    - `NAMECOIN_POLICY_NIP9A_REJECT_IMETA_KIND1` — defence-in-depth
      toggle for the common "text-only kind:1 except whitelisted
      uploaders" deployment.
- 50+ new tests across parser, validator, loader and handler
  integration. Loader survives transient atomic-rename gaps and
  malformed JSON without losing prior state.

### Behaviour change (back-compat)
- `kind:34551` events are still accepted by the standard `.bit` author
  gate. With NIP-9B integration disabled (the default), behaviour is
  unchanged. With NIP-9B integration on, `kind:34551` events are accepted
  unconditionally for `kind0-only` mode and require a verified `.bit`
  author for `all-kinds-require-bit` mode — the kind-whitelist check is
  bypassed for protocol events so the owner can publish rules updates
  even when the active rules don't list `34551`.

## v0.2.0 — unreleased

### Security
- **Mempool / unconfirmed-update poisoning fix.** ElectrumX's
  `blockchain.scripthash.get_history` returns unconfirmed txs at the
  end of the list with `height <= 0`. The resolver previously picked
  the last entry blindly, letting an attacker (or a malicious server)
  flip a name's resolved value by broadcasting a tx. History is now
  filtered to confirmed entries with at least
  `NAMECOIN_POLICY_MIN_CONFIRMATIONS` confirmations (default `1`)
  before any tx is fetched.
- **Canonical-script collision DoS / censorship fix.** Walk filtered
  history newest → oldest (capped at 32 entries) until we find a tx
  whose vouts contain a `NAME_UPDATE` / `NAME_FIRSTUPDATE` for the
  *exact* requested name. A junk UTXO landing on the canonical
  scripthash no longer censors the live name.
- **Expiry uses the parsed-update height.** Once the chosen update
  is found, expiry math runs against that tx's height — not the
  latest history entry, which may be junk.
- **`NAME_FIRSTUPDATE` rand-push validation.** `parseNameScript` now
  asserts the rand push is exactly 20 bytes (Namecoin's spec) and
  falls through to the 2-push UPDATE shape otherwise, instead of
  blindly skipping a push of unknown size.
- **`server.version` handshake is awaited.** Previously the handshake
  reply was fire-and-forget (`.catch(() => null)`); some servers drop
  the connection if you race past the version exchange. Failure now
  trips the retry loop. Handshake has its own short 2 s timeout so a
  dead server doesn't burn the full per-attempt budget.
- **Array-JSON guard in `extractNip05`.** A kind:0 with
  `content = '["alice@x.bit"]'` is now structurally rejected at the
  parser level.

### Fixes
- **Negative-cache TTL split.** Parse failures (malformed JSON,
  missing `nostr`, `nameShow` returned null) now use a short TTL
  (default 30 s, configurable via `NAMECOIN_POLICY_NEG_CACHE_TTL_MS`)
  so a transient ElectrumX hiccup doesn't poison for the full 5 min
  long-cache window. Successful negatives — well-formed records that
  don't have an entry for this local-part — still use the long TTL.
- **Cached chain tip.** `blockchain.headers.subscribe` is now called
  at most once per 60 s in-process. Stale-by-60 s is safe because
  expiry has a 36 000-block grace window; the previous behavior
  hit the server on every resolve.

### Added
- New env var `NAMECOIN_POLICY_MIN_CONFIRMATIONS` (default `1`).
- New env var `NAMECOIN_POLICY_NEG_CACHE_TTL_MS` (default `30000`).

## [Unreleased]
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
