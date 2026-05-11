# strfry-namecoin-policy

A [**strfry**][strfry] write-policy plugin that verifies **Namecoin `.bit` NIP-05 identities**
against the Namecoin blockchain (via ElectrumX) before accepting Nostr events.

> If a user publishes a kind:0 metadata event with `nip05: "alice@example.bit"`,
> this plugin looks up `d/example` on the Namecoin blockchain, extracts the
> pubkey for local part `alice`, and only accepts the event if it matches
> `event.pubkey`. Everything else gets a NIP-20 rejection.

Namecoin NIP-05 is censorship-resistant identity: no DNS, no web server, no
registrar, no CA — just UTXOs on a public blockchain. This plugin is the
server-side counterpart to client support in [Amethyst][amethyst-pr] and
[Nostur][nostur-pr].

[strfry]: https://github.com/hoytech/strfry
[amethyst-pr]: https://github.com/vitorpamplona/amethyst/pull/1914
[nostur-pr]: https://github.com/nostur-com/nostur-ios-public/pull/60

---

## What it does

For every event strfry is about to store, this plugin decides:

- **kind:0 (metadata)** — parses `content.nip05`:
  - If it ends in `.bit` (or is `d/name` / `id/name`): resolves via
    ElectrumX and requires `event.pubkey` to match.
  - If it's a regular web NIP-05 (`alice@example.com`): passes through
    unverified by default (this plugin is a Namecoin gate, not a web NIP-05
    verifier). Set `NAMECOIN_POLICY_ALLOW_NON_BIT=false` to reject non-.bit
    identities outright.
  - If missing or unparsable: passes through.
- **other kinds** — accepted by default. In strict mode
  (`NAMECOIN_POLICY_MODE=all-kinds-require-bit`), only authors seen in a
  verified `.bit` kind:0 during this process's lifetime are allowed.

Successful resolutions are cached in-memory (LRU, configurable TTL) so a
busy relay doesn't hammer ElectrumX.

## Requirements

- Node.js **≥ 18** (uses only built-ins: `net`, `tls`, `readline`, `crypto`)
- A reachable namecoin-ElectrumX server. Either run your own
  (see the [deployment guide][deploy]) or use a public one such as
  `electrumx.testls.space:50002`.

[deploy]: https://github.com/namecoin/namecoin.org/pull/749

> **You do _not_ need to run `namecoind` on the relay host.** This plugin
> talks **only to ElectrumX** over TCP/TLS — it has no Namecoin Core / Bitcoin
> Core JSON-RPC dependency. See [Deployment topologies](#deployment-topologies)
> below.

## Deployment topologies

This plugin is a thin ElectrumX client. It does not embed, spawn, or speak
JSON-RPC to `namecoind`/`bitcoind`. The only thing it needs is a host:port
that answers the Electrum protocol (1.4) with a Namecoin-aware name index.

That gives you three sensible deployment shapes:

### 1. External public ElectrumX (zero infra)

Point the plugin at a community-run namecoin-ElectrumX server such as
`electrumx.testls.space:50002`. This is the simplest setup and is what the
repo's [examples/wrapper.sh](./examples/wrapper.sh) does by default.

```sh
export NAMECOIN_ELECTRUMX_HOST="electrumx.testls.space"
export NAMECOIN_ELECTRUMX_PORT="50002"
export NAMECOIN_ELECTRUMX_TLS="true"
# Strongly recommended: pin the self-signed cert
export NAMECOIN_ELECTRUMX_CERT_PIN="<sha256-of-cert-DER>"
```

Trust model: you trust the operator not to lie about Namecoin name values.
They can withhold or stale-serve, but they cannot forge consensus.

### 2. Your own ElectrumX (recommended for production relays)

Run [namecoin-electrumx][nx] alongside your own [namecoind][nmc] — usually
on the same host or LAN as the strfry relay — and point the plugin at
`localhost:50002`. The plugin still only speaks the Electrum protocol; the
`namecoind` JSON-RPC link is between *ElectrumX and namecoind*, not between
this plugin and namecoind.

```
  ┌──────────────┐  stdio   ┌────────────┐  Electrum 1.4 (TCP/TLS)  ┌───────────┐
  │   strfry     │ ◀───▶ │ this plug- │ ────────────────────▶ │ ElectrumX │
  │ write-policy │        │    in      │                          │           │
  └──────────────┘        └────────────┘                          └─────┬─────┘
                                                                       │ JSON-RPC
                                                                       ▼
                                                              ┌──────────────┐
                                                              │  namecoind   │
                                                              │ (full node)  │
                                                              └──────────────┘
```

This is the highest-assurance option: nobody else's server is in the
verification path.

[nx]: https://github.com/namecoin/electrumx
[nmc]: https://github.com/namecoin/namecoin-core

### 3. Mixed / failover

The plugin opens one short-lived TCP/TLS connection per uncached resolve,
so swapping the `NAMECOIN_ELECTRUMX_HOST` env var and restarting strfry is
the entire "failover" procedure. There is no built-in pool of servers; if
you want HA, run a TCP load balancer (e.g. HAProxy) in front of multiple
ElectrumX endpoints and point the plugin at the LB.

### What this plugin does **not** do

- ❌ It does **not** open a JSON-RPC connection to `namecoind`. There is no
  `rpcuser`/`rpcpassword`/`rpcport` config, by design.
- ❌ It does **not** require `blockchain.name.show` or any Namecoin-specific
  ElectrumX extension. It uses only the generic Electrum methods
  (`blockchain.scripthash.get_history`, `blockchain.transaction.get`,
  `blockchain.headers.subscribe`) plus pure-JS Bitcoin script parsing —
  same algorithm as Amethyst and Nostur. See [src/electrumx.js](./src/electrumx.js).
- ❌ It does **not** validate SPV proofs. The trust model is "trust the
  ElectrumX server not to serve stale/wrong values" — see
  [Security notes](#security-notes) for mitigations (cert pinning, run your
  own server).

## Install

```bash
npm install -g strfry-namecoin-policy
```

Or from source:

```bash
git clone https://github.com/mstrofnone/strfry-namecoin-policy
cd strfry-namecoin-policy
npm test   # unit tests, hermetic
```

There are **no runtime dependencies** — just vendor the repo directly
wherever strfry runs.

## Configure strfry

strfry's `writePolicy.plugin` directive is a single command path. Since we
need to pass env vars to the plugin, wrap it in a tiny shell script:

**`/opt/strfry/plugins/strfry-namecoin-policy-wrapper.sh`**

```sh
#!/bin/sh
export NAMECOIN_ELECTRUMX_HOST="electrumx.testls.space"
export NAMECOIN_ELECTRUMX_PORT="50002"
export NAMECOIN_POLICY_MODE="kind0-only"
exec /usr/bin/env node /usr/local/lib/node_modules/strfry-namecoin-policy/bin/strfry-namecoin-policy.js
```

Then in **`strfry.conf`**:

```
relay {
    writePolicy {
        plugin = "/opt/strfry/plugins/strfry-namecoin-policy-wrapper.sh"
    }
}
```

Make both files executable and restart strfry. A full example is in
[`examples/strfry.conf.snippet`](examples/strfry.conf.snippet) and
[`examples/wrapper.sh`](examples/wrapper.sh).

## Configuration (environment variables)

| Variable | Default | Description |
|---|---|---|
| `NAMECOIN_ELECTRUMX_HOST` | *(required†)* | Hostname of the ElectrumX server. **Without it (and without `NAMECOIN_ELECTRUMX_HOSTS`), the plugin fails closed by default** — see `NAMECOIN_POLICY_SOFT_FAIL`. † Either `NAMECOIN_ELECTRUMX_HOST` or `NAMECOIN_ELECTRUMX_HOSTS` (multi-host) satisfies this requirement. |
| `NAMECOIN_ELECTRUMX_PORT` | `50002` (TLS) / `50001` (TCP) | TCP port. |
| `NAMECOIN_ELECTRUMX_TLS` | `true` | Use TLS (`true`/`false`). |
| `NAMECOIN_ELECTRUMX_CERT_PIN` | — | One or more cert pins (comma-separated for rotation). Each pin is either a 64-hex SHA-256 of the DER cert, or `sha256/<base64>` for a SubjectPublicKeyInfo pin. When set, the system trust store is bypassed and only matching certs are accepted. |
| `NAMECOIN_ELECTRUMX_INSECURE` | `false` | If `true`, disable TLS verification entirely. **For testing only** — production setups should pin a cert instead. Triggers a loud startup banner. |
| `NAMECOIN_ELECTRUMX_TIMEOUT_MS` | `5000` | Per-query timeout. |
| `NAMECOIN_ELECTRUMX_RETRIES` | `2` | Retry attempts per lookup on connect/parse/IO failure. |
| `NAMECOIN_POLICY_MODE` | `kind0-only` | `kind0-only`: verify only kind:0 with `.bit` NIP-05. `all-kinds-require-bit`: reject all events from authors that haven't been verified yet. |
| `NAMECOIN_POLICY_CACHE_TTL_MS` | `300000` | TTL for resolver cache (ms). |
| `NAMECOIN_POLICY_LOG_LEVEL` | `info` | `silent` / `info` / `debug`. Logs go to stderr and are captured by strfry. |
| `NAMECOIN_POLICY_ALLOW_NON_BIT` | `true` | If `false`, kind:0 events with non-`.bit` NIP-05 identifiers are rejected. |
| `NAMECOIN_POLICY_MIN_CONFIRMATIONS` | `1` | Minimum confirmations a Namecoin name-update tx must have before it's trusted. `0` allows mempool/unconfirmed tx (testing only). Higher values harden against reorgs and malicious-server fabrication at the cost of slightly slower propagation. |
| `NAMECOIN_POLICY_NEG_CACHE_TTL_MS` | `30000` | Short TTL for *parse-failure* negatives (malformed JSON, missing `nostr` key, ElectrumX returned null). Successful negatives — e.g. `bob@x.bit` looking up a record that lists only `_` and `alice` — still use the long `NAMECOIN_POLICY_CACHE_TTL_MS`. |
| `NAMECOIN_POLICY_LOOKUP_RPS` | `5` | Sustained ElectrumX lookup rate (tokens/sec). Cache hits don't count. |
| `NAMECOIN_POLICY_LOOKUP_BURST` | `10` | Max burst size for ElectrumX lookups. |
| `NAMECOIN_POLICY_LOOKUP_QUEUE_MS` | `2000` | Max time (ms) a single lookup will wait for a token before returning a `rate-limited:` reject. |
| `NAMECOIN_POLICY_SOFT_FAIL` | `false` | If `true` and neither `NAMECOIN_ELECTRUMX_HOST` nor `NAMECOIN_ELECTRUMX_HOSTS` is set, accept all events without verification (legacy behavior). Default fails closed. |
| `NAMECOIN_POLICY_NIP9A_RULES_FILE` | — | Path to a signed `kind:34551` JSON event. Loaded at startup and re-read on `SIGHUP`. See [NIP-9A integration](#nip-9a-integration). |
| `NAMECOIN_POLICY_NIP9A_COMMUNITY` | — | Owner-pinned community address pointer `34550:<hex64>:<d>`. Only rules events from the matching owner+d are accepted by the loader. |
| `NAMECOIN_POLICY_NIP9A_REQUIRE_RULES` | `false` | If `true`, reject every non-rules event whenever no NIP-9A rules document is in force. Default is to pass through (rules absence ≠ deny-by-default per NIP). |
| `NAMECOIN_POLICY_NIP9A_REJECT_IMETA_KIND1` | `false` | Defence-in-depth: reject `kind:1` events with `imeta` tags (NIP-92) from authors that are not explicitly `p allow` in the rules document. Lets relays enforce "text-only kind:1 except for whitelisted uploaders" without inventing a non-spec extension. |

### Cert pin formats

`NAMECOIN_ELECTRUMX_CERT_PIN` accepts two pin shapes, and any number of
them comma-separated (any-match):

- **DER fingerprint** — `sha256(DER(cert))` as 64 hex chars. Simple and
  matches what `openssl x509 -outform der | sha256sum` prints, but breaks
  when the cert rotates even if the underlying key is reused.
- **SPKI pin** — `sha256/<base64-of-sha256(SubjectPublicKeyInfo)>`. Survives
  cert rotation as long as the operator keeps the same keypair, which is
  the right default for long-lived self-signed ElectrumX servers. Compute
  with: `openssl s_client -connect host:50002 </dev/null 2>/dev/null |
  openssl x509 -pubkey -noout | openssl pkey -pubin -outform der |
  openssl dgst -sha256 -binary | base64`. Configure as e.g.
  `NAMECOIN_ELECTRUMX_CERT_PIN="sha256/AAAA...=,sha256/BBBB...="` to allow
  a current and a next-rotation key simultaneously.
| `NAMECOIN_ELECTRUMX_HOSTS` | — | Comma-separated `host:port[,host:port,…]` list. Overrides `*_HOST/*_PORT` when set. Round-robin with per-host circuit breaker (30s open, exp backoff to 5min). See [Operational](#operational). |
| `NAMECOIN_ELECTRUMX_SOCKS5` | — | `host:port` of a no-auth SOCKS5 proxy (e.g. `127.0.0.1:9050` for Tor). DNS is delegated to the proxy. |
| `NAMECOIN_POLICY_CACHE_PATH` | — | If set, both the resolver cache and verified-author set persist to this file. Uses `better-sqlite3` (optional dep) when available, falls back to a JSONL append-log otherwise. |
| `NAMECOIN_POLICY_METRICS_PORT` | `0` | If non-zero, expose Prometheus metrics on `127.0.0.1:<port>/metrics`. Always bound to localhost. |
| `NAMECOIN_POLICY_POOL_KEEPALIVE_MS` | `30000` | Idle timeout for the warm ElectrumX connection pool. Set to `0` to use one-connection-per-resolve mode. |

## NIP-9A integration

This plugin can enforce a [NIP-9A](https://github.com/nostr-protocol/nips/pull/2331)
*Verifiable Community Rules* document on top of the Namecoin `.bit` author
gate. The rules document is a signed `kind:34551` event published by the
community owner; it declares the whitelisted event kinds, optional per-kind
size caps and quotas, per-pubkey allow/deny overrides, an optional WoT gate,
and an anti-rollback ratchet. Same schema as the merged Quartz validator in
[vitorpamplona/amethyst#2758](https://github.com/vitorpamplona/amethyst/pull/2758)
and the JS reference in
[mstrofnone/nip9a-refimpl](https://github.com/mstrofnone/nip9a-refimpl);
cross-implementation tests in that repo assert wire compatibility.

### When to enable it

This plugin's `mode=all-kinds-require-bit` already gates *who* can publish.
NIP-9A gates *what* they can publish:

- **"Anyone with a verified `.bit` identity can post text, only whitelisted
  pubkeys can post other kinds"** — the textbook deployment, and the reason
  this integration exists. Publish a `kind:34551` whose `k` tags whitelist
  the text kinds (`1`, `0`, `7`, `5`, `3`, `10002`, `1111`, `9735`) and use
  `p allow` tags for the uploaders. Combine with
  `NAMECOIN_POLICY_NIP9A_REJECT_IMETA_KIND1=true` to also block in-line
  media-via-`imeta` from non-uploaders.
- **Per-author quotas** are part of the spec but not enforced server-side
  by this plugin (no quota counter to consult). They are still enforced
  client-side by Amethyst's composer validation
  ([vitorpamplona/amethyst#2798](https://github.com/vitorpamplona/amethyst/pull/2798)).
- **WoT gates** likewise; clients enforce, this plugin does not.

### How the loader picks the active rules document

The loader maintains a small in-memory cache of `kind:34551` candidates and
picks the active one as follows:

1. If `NAMECOIN_POLICY_NIP9A_COMMUNITY="34550:<owner-hex>:<d>"` is set, only
   events with matching `pubkey` and `d` tag are admitted.
2. If `NAMECOIN_POLICY_NIP9A_RULES_FILE=/path/to/rules.json` is set, the
   file is read at startup and on every mtime change (~5 s poll). The file
   must be the JSON-encoded `kind:34551` event (`{id, pubkey, created_at,
   kind, tags, content, sig}`). Atomic-rename writes are supported (missing
   file mid-rename does not lose state).
3. Incoming `kind:34551` events accepted by the standard `.bit` author gate
   are also offered to the loader, so the owner can publish updates over
   Nostr without restarting the relay.
4. The picker takes the highest `min_rules_created_at` ratchet across all
   candidates and then returns the latest survivor by `created_at`.

See [`src/nip9a-loader.js`](src/nip9a-loader.js) for the implementation.

### Whitelist semantics (important)

NIP-9A's `p allow` does **not** silently expand the kind whitelist — that
would let any allow-listed pubkey publish kinds the rules don't declare,
bypassing the document's whole point. Whitelist semantics in this plugin are:

- `p allow` bypasses the **WoT gate** for that pubkey.
- `p allow` allows that pubkey to publish `kind:1` with `imeta` tags when
  `NAMECOIN_POLICY_NIP9A_REJECT_IMETA_KIND1=true` (this plugin's
  defence-in-depth toggle, *not* a NIP-9A semantic — orthogonal layer).
- `p deny` rejects that pubkey from publishing any kind, overriding any
  `p allow` for the same pubkey (spec semantics).

**Two-tier deployments** that need "baseline text + uploaders also get
kind:1063" should publish two `kind:34551` documents and rotate which one
is served on disk via a deploy-time symlink, or extend `kindRules` to
declare the uploader kinds and pair them with `p allow` for those
uploaders so the human-readable intent matches the wire effect.

### Composing rules events

```jsonc
// kind:34551 event payload, before signing
{
  "kind": 34551,
  "pubkey": "<owner-hex>",
  "created_at": 1746604800,
  "tags": [
    ["d", "relay-testls-bit"],
    ["a", "34550:<owner-hex>:relay-testls-bit"],

    // Text baseline — open to every verified .bit author.
    ["k", "0"],                  // metadata
    ["k", "1", "16384"],         // short notes, 16 KB cap
    ["k", "3"],                  // contacts
    ["k", "5"],                  // deletions
    ["k", "6"],                  // reposts
    ["k", "7"],                  // reactions
    ["k", "1111", "16384"],      // threaded comment (NIP-22)
    ["k", "9735"],               // zap receipts
    ["k", "10002"],              // relay-list metadata

    // File-handling kinds — whitelisted authors only (set them as
    // `p allow` AND publish a sibling rules doc that adds these `k`
    // entries, or use a layered enforcement script — see above).
    // ["k", "1063", "262144"],   // NIP-94 file metadata
    // ["k", "20", "524288"],     // NIP-68 picture-first

    // Whitelist of pubkeys allowed to post file-type events.
    // Populate from the seed script (see below).
    ["p", "<vip-pubkey-1>", "allow", "uploader"],
    ["p", "<vip-pubkey-2>", "allow", "uploader"],

    // Anti-rollback ratchet — defends against stolen-key replay of
    // older laxer versions.
    ["min_rules_created_at", "1746604800"],

    // Hard global cap independent of kind.
    ["max_event_size", "524288"]
  ],
  "content": ""
}
```

Sign with the community owner's key (e.g. via
[`nip9a-refimpl/tools/sign-rules.js`](https://github.com/mstrofnone/nip9a-refimpl)
or any Nostr signing tool) and publish either:

- as a JSON file at `NAMECOIN_POLICY_NIP9A_RULES_FILE` (operator-controlled,
  recommended for relay-scoped policy), **or**
- to the relay itself as a Nostr event — the plugin will absorb it.

Live deploy example (`SIGHUP` re-reads the file without restarting strfry):

```sh
install -o root -g strfry -m 0640 \
    rules.json /etc/strfry/nip9a-rules.json
systemctl kill -s SIGHUP strfry
```

## Operational

For higher-traffic relays, the plugin supports several operational
features that you can opt into via environment variables. All are
off-by-default — the legacy single-host, per-resolve-connection,
in-memory-cache behavior is preserved when these are unset.

| Feature | Env var(s) | Example |
|---|---|---|
| Persistent cache | `NAMECOIN_POLICY_CACHE_PATH` | `NAMECOIN_POLICY_CACHE_PATH=/var/cache/strfry-namecoin/cache.db` |
| Prometheus metrics | `NAMECOIN_POLICY_METRICS_PORT` | `NAMECOIN_POLICY_METRICS_PORT=9091` (curl `http://127.0.0.1:9091/metrics`) |
| SOCKS5 / Tor | `NAMECOIN_ELECTRUMX_SOCKS5` | `NAMECOIN_ELECTRUMX_SOCKS5=127.0.0.1:9050` |
| Connection pool | `NAMECOIN_POLICY_POOL_KEEPALIVE_MS` | `NAMECOIN_POLICY_POOL_KEEPALIVE_MS=60000` (`0` = disable) |
| Multi-ElectrumX + circuit breaker | `NAMECOIN_ELECTRUMX_HOSTS` | `NAMECOIN_ELECTRUMX_HOSTS=ex1.example:50002,ex2.example:50002` |
| Happy-eyeballs IPv6/IPv4 | *(automatic)* | When the host has both A and AAAA records, both are tried with a 250 ms stagger; the first connect wins. Skipped when SOCKS5 is enabled (proxy resolves names). |

Metrics exported (Prometheus textfile format):

- Counters: `lookups_total`, `cache_hits_total`, `cache_misses_total`,
  `acceptances_total`, `rejections_total{reason="…"}`,
  `electrumx_errors_total{type="timeout|socket|tls|cert-pin|parse|closed|socks5|dns|refused|unreachable|other"}`
- Histogram: `lookup_duration_ms` with buckets
  `[10, 50, 100, 250, 500, 1000, 2500, 5000, +Inf]`

The metrics listener binds to `127.0.0.1` only — expose it externally
via an explicit reverse proxy if you need remote scraping.

The persistent cache splits into two sqlite namespaces in one file
(`resolver` for name lookups, `verifiedAuthors` for the
`all-kinds-require-bit` mode). If `better-sqlite3` is not installed
(it's an `optionalDependencies` entry, so `npm install` won't fail if
it can't build), we silently fall back to a JSONL append-log with
periodic in-place compaction. If the cache file can't be opened at
all, we log once and fall back to in-memory — a disk problem will
never take the relay offline.

The circuit breaker keeps each ElectrumX host in `closed` (healthy),
`open` (recent failure, skip for cooldown), or `half-open` (one probe
slot) state. Failures double the cooldown (30 s → 1 min → 2 min → 4
min → 5 min cap); successes reset it. If every configured host is
open, the plugin still round-robins through them — better to attempt
a flapping ElectrumX than to soft-accept every event without
verification.

## Supported identifier forms

| User input in `nip05` | Namecoin name looked up | Local part |
|---|---|---|
| `alice@example.bit` | `d/example` | `alice` |
| `_@example.bit` | `d/example` | `_` |
| `example.bit` | `d/example` | `_` |
| `d/example` | `d/example` | `_` |
| `id/alice` | `id/alice` | `_` |

## Supported Namecoin value formats

Inside the Namecoin name's JSON value, the plugin accepts:

```json
// domain namespace, single user
{"nostr": "<64-char-hex-pubkey>"}
```

```json
// domain namespace, multi-user with relay hints
{
  "nostr": {
    "names":  { "_": "<hex>", "alice": "<hex>", "bob": "<hex>" },
    "relays": { "<hex>": ["wss://relay.example.com"] }
  }
}
```

```json
// identity namespace
{"nostr": "<hex>"}
// or
{"nostr": {"pubkey": "<hex>", "relays": ["wss://..."]}}
```

## Tests

```bash
npm test                 # hermetic unit tests (no network)
LIVE_ELECTRUMX=1 \
  NAMECOIN_ELECTRUMX_HOST=electrumx.testls.space \
  NAMECOIN_ELECTRUMX_PORT=50002 \
  node test/live.js      # hit a real namecoin-ElectrumX server
```

## Security notes

- **TLS cert pinning.** The common public namecoin-ElectrumX servers use
  self-signed certificates. Without pinning you must disable TLS
  verification — don't. Use `NAMECOIN_ELECTRUMX_CERT_PIN` to pin the
  server's SHA-256 DER fingerprint. Example: grab the fingerprint with
  `openssl s_client -connect host:50002 -showcerts </dev/null 2>/dev/null |
   openssl x509 -outform der | sha256sum`.
- **Server trust.** ElectrumX can lie about recent blocks but can't forge
  Namecoin consensus. A malicious server could return stale data
  (pre-update) — this is acceptable for name resolution because Namecoin
  updates are infrequent and a defender can rotate servers. For maximum
  assurance, run your own ElectrumX against your own namecoind.
- **Cache poisoning.** The cache is in-memory and keyed by identifier; it
  does not cross processes and is cleared on restart. Negative results are
  cached (to stop attackers from spamming lookups with garbage names) but
  network errors are **not** cached.
- **No cryptographic signature check.** strfry has already validated
  `event.id` and `event.sig` by the time this plugin sees the event; we
  simply trust the pubkey.

## Limitations / known gaps

- Resolution uses the same scripthash-based algorithm as Amethyst and
  Nostur — `blockchain.scripthash.get_history` + `blockchain.transaction.get`
  + NAME_UPDATE script parsing — so it works against **any** namecoin-aware
  ElectrumX (no non-standard `blockchain.name.show` extension required).
  See [`src/electrumx.js`](src/electrumx.js) for the full protocol.
- No SPV-proof verification. We trust the server's response. A malicious
  or stale server could (in principle) lie about the name's current
  value, but can't forge Namecoin consensus.
- `all-kinds-require-bit` only remembers verified authors for the lifetime
  of the plugin process. If strfry restarts the plugin, the cache
  rebuilds as events flow in again.
- Single plugin slot. strfry currently supports one write-policy plugin
  at a time; chain this with other policies by writing a meta-plugin
  (there are examples upstream) or by contributing to the upstream
  router.

[nmcex]: https://github.com/namecoin/electrumx

## How it resolves a `.bit` name

```
alice@example.bit
    │
    ▼
1. parse           → namecoinName="d/example", localPart="alice"
2. build script    → OP_NAME_UPDATE <push("d/example")> <push("")> OP_2DROP OP_DROP OP_RETURN
3. scripthash      → hex(reverse(SHA-256(script)))
4. get_history     → [{tx_hash, height}, …]   ← last entry wins
5. transaction.get → scan vouts for script starting with 0x53 (OP_NAME_UPDATE) or 0x52 (OP_NAME_FIRSTUPDATE)
6. parse script    → extract JSON value from the second push-data item
7. check expiry    → current_tip - update_height must be < 36 000
8. extract pubkey  → value.nostr.names["alice"]
```

Result is cached and compared against `event.pubkey` on every new kind:0
from that identifier. Cache hits avoid the round-trip entirely.

## Development

```bash
# Run all unit tests
npm test

# Run the end-to-end plugin test (spawns the binary)
node --test test/plugin.test.js
```

The code is deliberately small (~500 lines of Node, no deps) so it's easy
to audit before running inside your relay.

## License

[MIT](LICENSE) © mstrofnone
