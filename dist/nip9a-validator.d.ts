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
export const Violations: Readonly<{
    STALE_RULES: "stale_rules";
    AUTHOR_DENIED: "author_denied";
    KIND_NOT_ALLOWED: "kind_not_allowed";
    KIND_SIZE_EXCEEDED: "kind_size_exceeded";
    MAX_SIZE_EXCEEDED: "max_size_exceeded";
    QUOTA_EXCEEDED: "quota_exceeded";
    WOT_GATE_FAILED: "wot_gate_failed";
}>;
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
export function validate(rules: object, ctx: {
    author: string;
    kind: number;
    sizeBytes: number;
    postsTodayByKind?: (kind: number) => number | null;
    wotResolver?: (author: string, root: string, depth: number) => boolean;
}): {
    type: string;
    [k: string]: any;
} | null;
/**
 * Compute the byte size of an event as it would appear on the wire.
 * Spec defers to "JSON-encoded event size"; we use UTF-8 byte length of
 * `JSON.stringify(event)` to match the Quartz reference exactly.
 */
export function eventByteSize(event: any): any;
/**
 * Look up a per-pubkey policy. `deny` overrides any `allow`, per spec.
 *
 * @param {object} rules
 * @param {string} pubkey hex, lowercase
 * @returns {'allow'|'deny'|null}
 */
export function policyFor(rules: object, pubkey: string): "allow" | "deny" | null;
