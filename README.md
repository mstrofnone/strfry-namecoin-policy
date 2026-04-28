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
| `NAMECOIN_ELECTRUMX_HOST` | *(required)* | Hostname of the ElectrumX server. Without it, the plugin soft-fails open and accepts everything. |
| `NAMECOIN_ELECTRUMX_PORT` | `50002` (TLS) / `50001` (TCP) | TCP port. |
| `NAMECOIN_ELECTRUMX_TLS` | `true` | Use TLS (`true`/`false`). |
| `NAMECOIN_ELECTRUMX_CERT_PIN` | — | Pin a self-signed cert by its **SHA-256 of DER** (64 hex chars). When set, the system trust store is bypassed and only this cert is accepted. |
| `NAMECOIN_ELECTRUMX_INSECURE` | `false` | If `true`, disable TLS verification entirely. **For testing only** — production setups should pin a cert instead. |
| `NAMECOIN_ELECTRUMX_TIMEOUT_MS` | `5000` | Per-query timeout. |
| `NAMECOIN_ELECTRUMX_RETRIES` | `2` | Retry attempts per lookup on connect/parse/IO failure. |
| `NAMECOIN_POLICY_MODE` | `kind0-only` | `kind0-only`: verify only kind:0 with `.bit` NIP-05. `all-kinds-require-bit`: reject all events from authors that haven't been verified yet. |
| `NAMECOIN_POLICY_CACHE_TTL_MS` | `300000` | TTL for resolver cache (ms). |
| `NAMECOIN_POLICY_LOG_LEVEL` | `info` | `silent` / `info` / `debug`. Logs go to stderr and are captured by strfry. |
| `NAMECOIN_POLICY_ALLOW_NON_BIT` | `true` | If `false`, kind:0 events with non-`.bit` NIP-05 identifiers are rejected. |

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
