'use strict';

/**
 * Tiny metrics module — counters + bucketed histograms — exported in
 * Prometheus textfile format over an optional HTTP listener bound to
 * 127.0.0.1.
 *
 * No external deps. Designed to be cheap on the hot path: a Map lookup
 * + an integer increment, nothing more.
 *
 * Usage:
 *
 *   const m = new Metrics();
 *   m.inc('lookups_total');
 *   m.inc('rejections_total', { reason: 'pubkey-mismatch' });
 *   m.observe('lookup_duration_ms', 137);
 *
 *   const server = m.startServer({ port: 9091 }); // 0/null = disabled
 *
 * For tests, you can use Metrics() without ever calling startServer().
 */

const http = require('node:http');

const DEFAULT_BUCKETS = [10, 50, 100, 250, 500, 1000, 2500, 5000, Infinity];

class Metrics {
  constructor({ buckets = DEFAULT_BUCKETS } = {}) {
    /** @type {Map<string, Map<string, number>>} */
    // counterName -> labelKey -> value
    this.counters = new Map();
    /** @type {Map<string, {buckets:number[], counts:number[], sum:number, count:number}>} */
    this.histograms = new Map();
    this.buckets = buckets.slice();
  }

  /**
   * Increment a counter.
   * @param {string} name
   * @param {Record<string,string|number>} [labels]
   * @param {number} [delta=1]
   */
  inc(name, labels, delta = 1) {
    const lk = labelKey(labels);
    let inner = this.counters.get(name);
    if (!inner) { inner = new Map(); this.counters.set(name, inner); }
    inner.set(lk, (inner.get(lk) || 0) + delta);
  }

  /**
   * Record an observation into a histogram.
   * @param {string} name
   * @param {number} value
   */
  observe(name, value) {
    let h = this.histograms.get(name);
    if (!h) {
      h = {
        buckets: this.buckets.slice(),
        counts: this.buckets.map(() => 0),
        sum: 0,
        count: 0,
      };
      this.histograms.set(name, h);
    }
    h.sum += value;
    h.count += 1;
    for (let i = 0; i < h.buckets.length; i++) {
      if (value <= h.buckets[i]) h.counts[i] += 1;
    }
  }

  /**
   * Render Prometheus exposition format.
   * @returns {string}
   */
  render() {
    const out = [];
    // Counters
    const counterNames = [...this.counters.keys()].sort();
    for (const name of counterNames) {
      out.push(`# HELP ${name} Counter.`);
      out.push(`# TYPE ${name} counter`);
      const inner = this.counters.get(name);
      for (const [lk, v] of inner) {
        if (lk === '') {
          out.push(`${name} ${v}`);
        } else {
          out.push(`${name}{${lk}} ${v}`);
        }
      }
    }
    // Histograms
    const histNames = [...this.histograms.keys()].sort();
    for (const name of histNames) {
      const h = this.histograms.get(name);
      out.push(`# HELP ${name} Histogram (millisecond bucketed).`);
      out.push(`# TYPE ${name} histogram`);
      for (let i = 0; i < h.buckets.length; i++) {
        const le = Number.isFinite(h.buckets[i]) ? String(h.buckets[i]) : '+Inf';
        out.push(`${name}_bucket{le="${le}"} ${h.counts[i]}`);
      }
      out.push(`${name}_sum ${h.sum}`);
      out.push(`${name}_count ${h.count}`);
    }
    return out.join('\n') + '\n';
  }

  /**
   * Start an HTTP listener on 127.0.0.1:port.
   * Resolves to the http.Server. Pass port=0 to bind to a random port
   * (useful for tests). Pass null/undefined/0 to do nothing? No —
   * caller decides; here we always bind when called.
   *
   * @param {{port:number, host?:string, logger?:(level:string,...args:any[])=>void}} opts
   * @returns {Promise<http.Server>}
   */
  startServer({ port, host = '127.0.0.1', logger } = {}) {
    return new Promise((resolve, reject) => {
      const server = http.createServer((req, res) => {
        if (req.url === '/metrics') {
          const body = this.render();
          res.writeHead(200, {
            'Content-Type': 'text/plain; version=0.0.4; charset=utf-8',
            'Content-Length': Buffer.byteLength(body),
          });
          res.end(body);
        } else if (req.url === '/healthz') {
          res.writeHead(200, { 'Content-Type': 'text/plain' });
          res.end('ok\n');
        } else {
          res.writeHead(404, { 'Content-Type': 'text/plain' });
          res.end('not found\n');
        }
      });
      server.on('error', (err) => {
        if (logger) logger('info', `metrics server error: ${err.message}`);
        reject(err);
      });
      server.listen(port, host, () => {
        if (logger) {
          const a = server.address();
          logger('info', `metrics listening on ${typeof a === 'object' ? `${a.address}:${a.port}` : a}`);
        }
        resolve(server);
      });
    });
  }
}

function labelKey(labels) {
  if (!labels) return '';
  const keys = Object.keys(labels).sort();
  if (keys.length === 0) return '';
  const parts = [];
  for (const k of keys) {
    const v = String(labels[k]).replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n');
    parts.push(`${k}="${v}"`);
  }
  return parts.join(',');
}

// A null metrics instance — no-op everything. Saves us from `if (metrics)`
// scattered through the hot path.
class NullMetrics {
  inc() {}
  observe() {}
  render() { return ''; }
  startServer() { return Promise.reject(new Error('NullMetrics: startServer not supported')); }
}

module.exports = { Metrics, NullMetrics, DEFAULT_BUCKETS };
