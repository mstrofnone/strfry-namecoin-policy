#!/usr/bin/env node
'use strict';

/**
 * Live ElectrumX integration test.
 *
 * Connects to a real namecoin-ElectrumX server, resolves a known .bit name,
 * and exercises the resolver. Skipped unless LIVE_ELECTRUMX=1.
 *
 * Usage (against a local namecoind+ElectrumX stack):
 *   NAMECOIN_ELECTRUMX_HOST=127.0.0.1 \
 *   NAMECOIN_ELECTRUMX_PORT=50002 \
 *   LIVE_ELECTRUMX=1 \
 *   node test/live.js
 *
 * Or against a public server:
 *   NAMECOIN_ELECTRUMX_HOST=electrumx.testls.space \
 *   NAMECOIN_ELECTRUMX_PORT=50002 \
 *   LIVE_ELECTRUMX=1 \
 *   node test/live.js
 */

const { ElectrumXClient } = require('../src/electrumx');
const { NamecoinResolver } = require('../src/resolver');

async function main() {
  if (process.env.LIVE_ELECTRUMX !== '1') {
    console.log('SKIP: set LIVE_ELECTRUMX=1 to run the live integration test.');
    return 0;
  }

  const host = process.env.NAMECOIN_ELECTRUMX_HOST || '127.0.0.1';
  const port = parseInt(process.env.NAMECOIN_ELECTRUMX_PORT || '50002', 10);
  const useTls = (process.env.NAMECOIN_ELECTRUMX_TLS || 'true').toLowerCase() !== 'false';

  console.log(`→ connecting to ${useTls ? 'tls' : 'tcp'}://${host}:${port}`);

  const insecure = process.env.NAMECOIN_ELECTRUMX_INSECURE === '1';
  if (insecure) console.log('⚠  TLS verification disabled (NAMECOIN_ELECTRUMX_INSECURE=1)');

  const client = new ElectrumXClient({
    host, port,
    tls: useTls,
    certPinSha256: process.env.NAMECOIN_ELECTRUMX_CERT_PIN || null,
    rejectUnauthorized: !insecure,
    timeoutMs: 10_000,
    retries: 1,
    logger: (lv, ...a) => console.error(`[${lv}]`, ...a),
  });

  const resolver = new NamecoinResolver({ client, cacheTtlMs: 30_000 });

  // Probe: known test vector from amethyst docs
  // d/testls should exist with {"nostr":{"names":{"_":"6cdebcca…"}}}
  const cases = [
    'testls.bit',
    '_@testls.bit',
    'm@testls.bit',
  ];

  let failures = 0;
  for (const id of cases) {
    try {
      const res = await resolver.resolve(id);
      if (res) {
        console.log(`✅ ${id.padEnd(20)} → pubkey=${res.pubkey} relays=${JSON.stringify(res.relays)}`);
      } else {
        console.log(`⚠  ${id.padEnd(20)} → not found (local entry "${NamecoinResolver.parseIdentifier(id)?.localPart}" missing in value)`);
      }
    } catch (err) {
      console.log(`❌ ${id.padEnd(20)} → ${err.message}`);
      failures++;
    }
  }

  // Also directly exercise blockchain.name.show against d/testls
  try {
    const row = await client.nameShow('d/testls');
    if (row) {
      console.log('');
      console.log('raw blockchain.name.show("d/testls"):');
      console.log(`  value = ${row.value}`);
    } else {
      console.log('raw blockchain.name.show("d/testls") → null');
    }
  } catch (err) {
    console.log(`❌ raw name_show error: ${err.message}`);
    failures++;
  }

  return failures === 0 ? 0 : 1;
}

main().then((code) => process.exit(code)).catch((err) => {
  console.error('live test fatal:', err.stack || err);
  process.exit(2);
});
