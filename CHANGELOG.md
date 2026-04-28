# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
