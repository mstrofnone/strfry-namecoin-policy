/**
 * NIP-9A rules event parser (CommonJS port of nip9a-refimpl/lib/parser.js).
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
export const NIP9A_KIND: 34551;
export const NIP72_COMMUNITY_KIND: 34550;
/**
 * @param {object} event a kind:34551 event
 * @returns {object|null} parsed Rules or null on malformed input
 */
export function parseRulesEvent(event: object): object | null;
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
export function pickActiveRules(candidates: object[]): object | null;
