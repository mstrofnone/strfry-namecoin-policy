'use strict';

// Regression test for the "NAMECOIN_ELECTRUMX_HOST not set" startup
// banner: it must NOT fire when the operator has configured the
// multi-host form (NAMECOIN_ELECTRUMX_HOSTS) instead of the legacy
// single-host shorthand. Both forms drive a working ElectrumXClient.

const test = require('node:test');
const assert = require('node:assert/strict');
const { shouldEmitNoHostBanner } = require('../src/index');

test('shouldEmitNoHostBanner: true when neither host nor hosts is set', () => {
  assert.equal(shouldEmitNoHostBanner({}), true);
  assert.equal(shouldEmitNoHostBanner({ host: null, hosts: null }), true);
  assert.equal(shouldEmitNoHostBanner({ host: '', hosts: [] }), true);
});

test('shouldEmitNoHostBanner: false when only single-host shorthand is set', () => {
  assert.equal(shouldEmitNoHostBanner({ host: 'a.example' }), false);
  assert.equal(shouldEmitNoHostBanner({ host: 'a.example', hosts: null }), false);
  assert.equal(shouldEmitNoHostBanner({ host: 'a.example', hosts: [] }), false);
});

test('shouldEmitNoHostBanner: false when only multi-host list is set (regression)', () => {
  // This is the bug fixed by this commit: the previous `!config.host` check
  // alone fired a "rejecting all .bit lookups" warning even though the
  // multi-host config drives a working client.
  const cfg = {
    host: null,
    hosts: [
      { host: 'a.example', port: 50002, tls: true },
      { host: 'b.example', port: 50002, tls: true },
    ],
  };
  assert.equal(shouldEmitNoHostBanner(cfg), false);
});

test('shouldEmitNoHostBanner: false when both forms are set', () => {
  const cfg = {
    host: 'a.example',
    hosts: [{ host: 'b.example', port: 50002, tls: true }],
  };
  assert.equal(shouldEmitNoHostBanner(cfg), false);
});

test('shouldEmitNoHostBanner: hosts must be a real array (defensive)', () => {
  // Non-array `hosts` MUST NOT suppress the banner.
  assert.equal(shouldEmitNoHostBanner({ host: null, hosts: 'a.example:50002' }), true);
  assert.equal(shouldEmitNoHostBanner({ host: null, hosts: { length: 1 } }), true);
});
