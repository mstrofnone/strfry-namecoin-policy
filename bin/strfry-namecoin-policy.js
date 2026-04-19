#!/usr/bin/env node
'use strict';

/**
 * strfry-namecoin-policy — entry point invoked by strfry.
 *
 * strfry executes whatever command is configured in `relay.writePolicy.plugin`
 * and pipes events as JSONL over stdin. This script wires up stdin/stdout to
 * the policy handler in src/index.js.
 */

const { run } = require('../src');

run().catch((err) => {
  console.error('[strfry-namecoin-policy] fatal:', err && err.stack ? err.stack : err);
  process.exit(1);
});
