'use strict';

/**
 * NIP-9B rules event parser (CommonJS port of nip9a-refimpl/lib/parser.js).
 *
 * Parses a `kind:34551` event into a structured object. Pure: no I/O, no
 * dependencies. Same contract as the Quartz `CommunityRulesEvent` accessors
 * in vitorpamplona/amethyst#2758 and the JS validator in
 * github.com/mstrofnone/nip9a-refimpl.
 *
 * Spec: https://github.com/nostr-protocol/nips/pull/2331
 *
 * The wire-compatibility test suite in nip9a-refimpl/test/cross-impl.test.js
 * asserts that this parser and validator produce identical verdicts to the
 * Kotlin/Quartz reference for every scenario.
 *
 * Events that fail validation (wrong kind, missing required tags, malformed
 * numeric fields) return null. Callers should treat absence-of-rules and
 * malformed-rules differently per their own policy.
 */

const NIP9A_KIND = 34551;
const NIP72_COMMUNITY_KIND = 34550;

function parseInt32(value) {
  if (value == null || value === '') return null;
  const n = Number.parseInt(value, 10);
  return Number.isFinite(n) ? n : null;
}

function parseInt64(value) {
  if (value == null || value === '') return null;
  // created_at fits comfortably in safe integer range until 2255.
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

/**
 * @param {object} event a kind:34551 event
 * @returns {object|null} parsed Rules or null on malformed input
 */
function parseRulesEvent(event) {
  if (!event || event.kind !== NIP9A_KIND) return null;
  if (!Array.isArray(event.tags)) return null;

  let dTag = null;
  let communityAddress = null;
  let maxEventSize = null;
  let minRulesCreatedAt = null;
  const kindRules = [];
  const pubkeyRules = [];
  const wotGates = [];

  for (const tag of event.tags) {
    if (!Array.isArray(tag) || tag.length === 0) continue;
    const [name, ...rest] = tag;
    switch (name) {
      case 'd': {
        if (rest[0]) dTag = rest[0];
        break;
      }
      case 'a': {
        if (rest[0] && String(rest[0]).startsWith(`${NIP72_COMMUNITY_KIND}:`)) {
          communityAddress = rest[0];
        }
        break;
      }
      case 'k': {
        const kind = parseInt32(rest[0]);
        if (kind == null) break;
        const maxBytes = parseInt32(rest[1]);
        const maxPerDay = parseInt32(rest[2]);
        kindRules.push({ kind, maxBytes, maxPerAuthorPerDay: maxPerDay });
        break;
      }
      case 'p': {
        const pubkey = rest[0];
        if (typeof pubkey !== 'string' || pubkey.length !== 64) break;
        const policy = rest[1];
        if (policy !== 'allow' && policy !== 'deny') break;
        const role = rest[2] || null;
        pubkeyRules.push({ pubkey: pubkey.toLowerCase(), policy, role });
        break;
      }
      case 'wot': {
        const root = rest[0];
        if (typeof root !== 'string' || root.length !== 64) break;
        const depth = parseInt32(rest[1]);
        if (depth == null || depth <= 0) break;
        wotGates.push({ root: root.toLowerCase(), depth });
        break;
      }
      case 'max_event_size': {
        const v = parseInt32(rest[0]);
        if (v != null && v > 0) maxEventSize = v;
        break;
      }
      case 'min_rules_created_at': {
        const v = parseInt64(rest[0]);
        if (v != null && v >= 0) minRulesCreatedAt = v;
        break;
      }
    }
  }

  if (!dTag) return null; // d tag is REQUIRED per spec

  return {
    id: event.id,
    pubkey: event.pubkey,
    createdAt: event.created_at,
    dTag,
    communityAddress,
    kindRules,
    pubkeyRules,
    wotGates,
    maxEventSize,
    minRulesCreatedAt,
  };
}

/**
 * Pick the active rules from a candidate set: the latest by created_at that
 * also satisfies the FLOOR of every observed `min_rules_created_at` ratchet.
 *
 * The ratchet from a stricter (newer) version forbids an older one even if
 * the newer version is dropped, so we take the max of all observed ratchets
 * as the floor before picking the latest survivor.
 *
 * @param {object[]} candidates parsed Rules
 * @returns {object|null}
 */
function pickActiveRules(candidates) {
  if (!candidates.length) return null;
  let floor = 0;
  for (const r of candidates) {
    if (r.minRulesCreatedAt != null && r.minRulesCreatedAt > floor) {
      floor = r.minRulesCreatedAt;
    }
  }
  let best = null;
  for (const r of candidates) {
    if (r.createdAt < floor) continue;
    if (!best || r.createdAt > best.createdAt) best = r;
  }
  return best;
}

module.exports = {
  NIP9A_KIND,
  NIP72_COMMUNITY_KIND,
  parseRulesEvent,
  pickActiveRules,
};
