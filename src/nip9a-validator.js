'use strict';

/**
 * NIP-9A validator (CommonJS port of nip9a-refimpl/lib/validator.js).
 *
 * Same evaluation order as the Kotlin/Quartz `CommunityRulesValidator.kt`
 * in vitorpamplona/amethyst#2758 and the JS reference in nip9a-refimpl:
 *
 *   1. Stale-rules ratchet (defence in depth; the loader picks the active
 *      rules document but a malformed cache could let an older one through).
 *   2. Author deny-list (overrides everything else, including allow).
 *   3. Kind whitelist.
 *   4. Per-kind size limit.
 *   5. Global max_event_size cap.
 *   6. Per-day quota.
 *   7. WoT gates (skipped if author has explicit `allow`).
 *
 * Returns null on success, or a Violation describing the first failure.
 * Spec: https://github.com/nostr-protocol/nips/pull/2331
 */

const Violations = Object.freeze({
  STALE_RULES: 'stale_rules',
  AUTHOR_DENIED: 'author_denied',
  KIND_NOT_ALLOWED: 'kind_not_allowed',
  KIND_SIZE_EXCEEDED: 'kind_size_exceeded',
  MAX_SIZE_EXCEEDED: 'max_size_exceeded',
  QUOTA_EXCEEDED: 'quota_exceeded',
  WOT_GATE_FAILED: 'wot_gate_failed',
});

/**
 * Look up a per-pubkey policy. `deny` overrides any `allow`, per spec.
 *
 * @param {object} rules
 * @param {string} pubkey hex, lowercase
 * @returns {'allow'|'deny'|null}
 */
function policyFor(rules, pubkey) {
  let allow = null;
  for (const rule of rules.pubkeyRules) {
    if (rule.pubkey !== pubkey) continue;
    if (rule.policy === 'deny') return 'deny';
    allow = 'allow';
  }
  return allow;
}

function ruleForKind(rules, kind) {
  for (const r of rules.kindRules) {
    if (r.kind === kind) return r;
  }
  return null;
}

/**
 * Validate one event against a parsed rules document.
 *
 * @param {object} rules parsed rules (from {@link parseRulesEvent})
 * @param {object} ctx
 * @param {string} ctx.author lowercase hex pubkey
 * @param {number} ctx.kind
 * @param {number} ctx.sizeBytes JSON-encoded event byte size
 * @param {(kind:number)=>number|null} [ctx.postsTodayByKind] optional quota source
 * @param {(author:string, root:string, depth:number)=>boolean} [ctx.wotResolver] optional WoT resolver
 * @returns {{type:string, [k:string]:any}|null} violation or null
 */
function validate(rules, ctx) {
  const { author, kind, sizeBytes, postsTodayByKind, wotResolver } = ctx;

  // 1. Stale-rules ratchet.
  if (rules.minRulesCreatedAt != null && rules.createdAt < rules.minRulesCreatedAt) {
    return {
      type: Violations.STALE_RULES,
      rulesCreatedAt: rules.createdAt,
      minRulesCreatedAt: rules.minRulesCreatedAt,
    };
  }

  // 2. Author deny-list.
  const policy = policyFor(rules, author);
  if (policy === 'deny') {
    return { type: Violations.AUTHOR_DENIED, author };
  }

  // 3. Kind whitelist. Author-allow does NOT override the kind whitelist —
  //    that would silently expand surface area beyond what the rules
  //    declare. Operators wanting per-pubkey kind overrides should add a
  //    second rules layer or split into multiple `k` declarations.
  //    (See README "Whitelist semantics" for the two-tier deployment.)
  const kindRule = ruleForKind(rules, kind);
  if (!kindRule) {
    return { type: Violations.KIND_NOT_ALLOWED, kind };
  }

  // 4. Per-kind size limit.
  if (kindRule.maxBytes != null && sizeBytes > kindRule.maxBytes) {
    return {
      type: Violations.KIND_SIZE_EXCEEDED,
      kind,
      sizeBytes,
      maxBytes: kindRule.maxBytes,
    };
  }

  // 5. Global size cap.
  if (rules.maxEventSize != null && sizeBytes > rules.maxEventSize) {
    return {
      type: Violations.MAX_SIZE_EXCEEDED,
      sizeBytes,
      maxBytes: rules.maxEventSize,
    };
  }

  // 6. Per-day quota.
  if (kindRule.maxPerAuthorPerDay != null && postsTodayByKind) {
    const count = postsTodayByKind(kind);
    if (count != null && count >= kindRule.maxPerAuthorPerDay) {
      return {
        type: Violations.QUOTA_EXCEEDED,
        kind,
        postsToday: count,
        maxPerDay: kindRule.maxPerAuthorPerDay,
      };
    }
  }

  // 7. WoT gates: pass if any one gate accepts. Allow-listed pubkeys bypass.
  if (policy !== 'allow' && rules.wotGates.length > 0 && wotResolver) {
    let anyPass = false;
    for (const gate of rules.wotGates) {
      if (wotResolver(author, gate.root, gate.depth)) {
        anyPass = true;
        break;
      }
    }
    if (!anyPass) {
      return { type: Violations.WOT_GATE_FAILED, gateCount: rules.wotGates.length };
    }
  }

  return null;
}

/**
 * Compute the byte size of an event as it would appear on the wire.
 * Spec defers to "JSON-encoded event size"; we use UTF-8 byte length of
 * `JSON.stringify(event)` to match the Quartz reference exactly.
 */
function eventByteSize(event) {
  return Buffer.byteLength(JSON.stringify(event), 'utf8');
}

module.exports = { Violations, validate, eventByteSize, policyFor };
