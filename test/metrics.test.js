'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { Metrics, NullMetrics } = require('../src/metrics');

test('Metrics: counter inc + render', () => {
  const m = new Metrics();
  m.inc('lookups_total');
  m.inc('lookups_total');
  m.inc('cache_hits_total');
  const text = m.render();
  assert.match(text, /# TYPE lookups_total counter/);
  assert.match(text, /^lookups_total 2$/m);
  assert.match(text, /^cache_hits_total 1$/m);
});

test('Metrics: counter with labels', () => {
  const m = new Metrics();
  m.inc('rejections_total', { reason: 'pubkey-mismatch' });
  m.inc('rejections_total', { reason: 'pubkey-mismatch' });
  m.inc('rejections_total', { reason: 'unresolved' });
  const text = m.render();
  assert.match(text, /^rejections_total\{reason="pubkey-mismatch"\} 2$/m);
  assert.match(text, /^rejections_total\{reason="unresolved"\} 1$/m);
});

test('Metrics: histogram with default buckets', () => {
  const m = new Metrics();
  m.observe('lookup_duration_ms', 5);
  m.observe('lookup_duration_ms', 75);
  m.observe('lookup_duration_ms', 600);
  m.observe('lookup_duration_ms', 99999);
  const text = m.render();
  // bucket le="10" gets the 5; le="50" gets 5; le="100" gets 75; etc.
  assert.match(text, /lookup_duration_ms_bucket\{le="10"\} 1/);
  assert.match(text, /lookup_duration_ms_bucket\{le="100"\} 2/);
  assert.match(text, /lookup_duration_ms_bucket\{le="1000"\} 3/);
  assert.match(text, /lookup_duration_ms_bucket\{le="\+Inf"\} 4/);
  assert.match(text, /lookup_duration_ms_sum 100679/);
  assert.match(text, /lookup_duration_ms_count 4/);
});

test('Metrics: HTTP server serves /metrics', async () => {
  const m = new Metrics();
  m.inc('lookups_total');
  const server = await m.startServer({ port: 0 });
  const { port } = server.address();
  const body = await new Promise((res, rej) => {
    http.get({ host: '127.0.0.1', port, path: '/metrics' }, (resp) => {
      let buf = '';
      resp.on('data', (d) => { buf += d; });
      resp.on('end', () => res({ status: resp.statusCode, body: buf, ct: resp.headers['content-type'] }));
    }).on('error', rej);
  });
  assert.equal(body.status, 200);
  assert.match(body.body, /^lookups_total 1$/m);
  assert.match(body.ct, /^text\/plain/);
  await new Promise((r) => server.close(r));
});

test('Metrics: HTTP server 404s unknown paths', async () => {
  const m = new Metrics();
  const server = await m.startServer({ port: 0 });
  const { port } = server.address();
  const body = await new Promise((res, rej) => {
    http.get({ host: '127.0.0.1', port, path: '/nope' }, (resp) => {
      let buf = '';
      resp.on('data', (d) => { buf += d; });
      resp.on('end', () => res({ status: resp.statusCode, body: buf }));
    }).on('error', rej);
  });
  assert.equal(body.status, 404);
  await new Promise((r) => server.close(r));
});

test('Metrics: server binds to 127.0.0.1 only', async () => {
  const m = new Metrics();
  const server = await m.startServer({ port: 0 });
  const a = server.address();
  assert.equal(a.address, '127.0.0.1');
  await new Promise((r) => server.close(r));
});

test('NullMetrics: no-ops do not throw', () => {
  const m = new NullMetrics();
  m.inc('x');
  m.observe('y', 1);
  assert.equal(m.render(), '');
});

test('Metrics: label values with quotes are escaped', () => {
  const m = new Metrics();
  m.inc('x', { type: 'foo "bar"' });
  const text = m.render();
  assert.match(text, /x\{type="foo \\"bar\\""\} 1/);
});
