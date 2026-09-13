/**
 * Independent trust evaluation (§1.3).
 *
 * A Trust file is verifier-controlled: scoped public-key pins and retained
 * head pins obtained independently of the producing operator's bundle.
 * Importing a key never trusts it; a genesis-zero head pin alone never
 * anchors a history; expiry is half-open on the verifier's own as_of.
 */

import { ProofError } from "./errors.js";
import { ZERO_HASH, verifyMessage, decodeSignature, b64uDecodeStrict, signingMessage, hashJson, D_EVENT_SIGN, D_AUDIT_SIGN } from "./crypto.js";
import {
  cmpStr, compareEventRef, eventRefOf, type Audit, type Event, type EventRef,
  type HeadPin, type KeyMaterial, type KeyPin, type Trust,
} from "./model.js";
import { findSlot } from "./chain.js";
import { jcsString, type Json } from "./canon.js";

function nullFirst(a: string | null, b: string | null): number {
  if (a === null && b === null) return 0;
  if (a === null) return -1;
  if (b === null) return 1;
  return cmpStr(a, b);
}

/** Canonical key-pin order: (role,source,stream,key,numeric first), null first. */
export function keyPinCmp(a: KeyPin, b: KeyPin): number {
  return cmpStr(a.role, b.role) || nullFirst(a.source, b.source) || nullFirst(a.stream, b.stream)
    || cmpStr(a.key, b.key)
    || (BigInt(a.first) < BigInt(b.first) ? -1 : BigInt(a.first) > BigInt(b.first) ? 1 : 0);
}

/** Canonical head-pin order: (role,source,stream,numeric seq,hash). */
export function headPinCmp(a: HeadPin, b: HeadPin): number {
  return cmpStr(a.role, b.role) || nullFirst(a.source, b.source) || nullFirst(a.stream, b.stream)
    || (BigInt(a.seq) < BigInt(b.seq) ? -1 : BigInt(a.seq) > BigInt(b.seq) ? 1 : 0)
    || cmpStr(a.hash, b.hash);
}

/**
 * trustCheck: sorted unique arrays, non-overlapping intervals per
 * (role,scope), no key reuse across origin/audit roles, genesis/head
 * invariants (all schema-level shape was enforced by parseTrust).
 */
export function trustCheck(t: Trust): { code: string } {
  const keys = t.keys;
  for (let i = 1; i < keys.length; i++) {
    if (keyPinCmp(keys[i - 1]!, keys[i]!) >= 0) return { code: "TRUST_INVALID" };
  }
  const heads = t.heads;
  for (let i = 1; i < heads.length; i++) {
    if (headPinCmp(heads[i - 1]!, heads[i]!) >= 0) return { code: "TRUST_INVALID" };
  }
  // No key reuse across origin/audit roles.
  const roles = new Map<string, Set<string>>();
  for (const k of keys) {
    const set = roles.get(k.key) ?? new Set<string>();
    set.add(k.role);
    roles.set(k.key, set);
    if (set.size > 1) return { code: "TRUST_INVALID" };
  }
  // Within each (role,source,stream) scope, intervals must not overlap.
  const byScope = new Map<string, KeyPin[]>();
  for (const k of keys) {
    const scope = `${k.role}\0${k.source ?? ""}\0${k.stream ?? ""}`;
    const arr = byScope.get(scope) ?? [];
    arr.push(k);
    byScope.set(scope, arr);
  }
  for (const arr of byScope.values()) {
    const sorted = arr.slice().sort((a, b) => (BigInt(a.first) < BigInt(b.first) ? -1 : 1));
    for (let i = 1; i < sorted.length; i++) {
      if (BigInt(sorted[i]!.first) <= BigInt(sorted[i - 1]!.last)) return { code: "TRUST_INVALID" };
    }
  }
  // Conflicting head pins for the same slot invalidate the file.
  const headSlots = new Map<string, string>();
  for (const h of heads) {
    const slot = `${h.role}\0${h.source ?? ""}\0${h.stream ?? ""}\0${BigInt(h.seq).toString(10)}`;
    const prev = headSlots.get(slot);
    if (prev !== undefined && prev !== h.hash) return { code: "TRUST_INVALID" };
    headSlots.set(slot, h.hash);
  }
  return { code: "OK" };
}

/** Half-open expiry: as_of ≥ valid_until is expired; null never expires. */
export function trustTime(t: Trust, asOf: string): { code: "OK" | "TRUST_EXPIRED" } {
  if (t.valid_until_unix_ms === null) return { code: "OK" };
  return BigInt(asOf) >= BigInt(t.valid_until_unix_ms) ? { code: "TRUST_EXPIRED" } : { code: "OK" };
}

export type OriginResult = { code: "OK" | "KEY_UNPINNED" | "KEY_INTERVAL" | "KEY_COMPROMISED" | "SIGNATURE_INVALID" };

/**
 * originCheck / auditCheck: one record's key/scope/interval/status
 * attribution under the trust file, plus its mathematical signature under
 * the pinned-or-declared key. The signature must verify under the
 * KeyMaterial whose id equals body.key — never a substituted key.
 */
export function keyCheck(
  record: Event | Audit, key: KeyMaterial, trust: Trust, role: "origin" | "audit",
): OriginResult {
  const body = record.body;
  const isEvent = "source" in body;
  const source = isEvent ? (body as { source: string }).source : null;
  const stream = isEvent ? (body as { stream: string }).stream : null;
  const seq = BigInt(body.seq);
  // Scope-filtered pins for this role.
  const scoped = trust.keys.filter((k) =>
    k.role === role && (role === "audit" ? true : k.source === source && k.stream === stream));
  if (scoped.length === 0) return { code: "KEY_UNPINNED" };
  const pin = scoped.find((k) => k.key === body.key);
  if (!pin) return { code: "KEY_UNPINNED" };
  if (seq < BigInt(pin.first) || seq > BigInt(pin.last)) return { code: "KEY_INTERVAL" };
  if (pin.status === "COMPROMISED") return { code: "KEY_COMPROMISED" };
  const tag = role === "origin" ? D_EVENT_SIGN : D_AUDIT_SIGN;
  const sig = b64uDecodeStrict(record.signature);
  const pub = b64uDecodeStrict(key.public);
  if (key.id !== body.key) return { code: "SIGNATURE_INVALID" };
  if (!verifyMessage(pub, signingMessage(tag, record.hash), sig)) return { code: "SIGNATURE_INVALID" };
  return { code: "OK" };
}

/** Whether a record's signature verifies under the key material it names. */
export function signatureValid(record: Event | Audit, key: KeyMaterial, role: "origin" | "audit"): boolean {
  if (key.id !== record.body.key) return false;
  try {
    const sig = decodeSignature(record.signature);
    const pub = b64uDecodeStrict(key.public);
    const tag = role === "origin" ? D_EVENT_SIGN : D_AUDIT_SIGN;
    return verifyMessage(pub, signingMessage(tag, record.hash), sig);
  } catch {
    return false;
  }
}

export type HeadResult = { code: "OK" | "PIN_AHEAD" | "PIN_MISMATCH" | "PIN_ABSENT" | "CONFLICTED" };

/**
 * headCheck: compare the complete supplied stream against a required head
 * pin. seq beyond the supplied cut is PIN_AHEAD; a differing candidate hash
 * is PIN_MISMATCH; a genesis-zero pin alone is PIN_ABSENT (no anchor).
 * A forked pinned slot matches when any candidate equals the pin; the fork
 * is still reported.
 */
export function headCheck(args: {
  cutSeq: string; events: Event[]; pin: HeadPin;
}): HeadResult {
  const { pin } = args;
  if (pin.seq === "0") {
    return pin.hash === ZERO_HASH ? { code: "PIN_ABSENT" } : { code: "PIN_MISMATCH" };
  }
  if (BigInt(pin.seq) > BigInt(args.cutSeq)) return { code: "PIN_AHEAD" };
  const candidates = findSlot(args.events, pin.source ?? "", pin.stream ?? "", pin.seq);
  if (candidates.length === 0) return { code: "PIN_MISMATCH" };
  if (candidates.some((c) => c.hash === pin.hash)) {
    return candidates.length > 1 ? { code: "CONFLICTED" } : { code: "OK" };
  }
  return { code: "PIN_MISMATCH" };
}

/** Audit-side head check over an audit prefix. */
export function auditHeadCheck(prefix: Audit[], pin: HeadPin): HeadResult {
  if (pin.seq === "0") return pin.hash === ZERO_HASH ? { code: "PIN_ABSENT" } : { code: "PIN_MISMATCH" };
  const maxSeq = prefix.reduce((m, a) => (BigInt(a.body.seq) > m ? BigInt(a.body.seq) : m), 0n);
  if (BigInt(pin.seq) > maxSeq) return { code: "PIN_AHEAD" };
  const at = prefix.filter((a) => a.body.seq === pin.seq);
  if (at.length === 0) return { code: "PIN_MISMATCH" };
  if (at.some((a) => a.hash === pin.hash)) return at.length > 1 ? { code: "CONFLICTED" } : { code: "OK" };
  return { code: "PIN_MISMATCH" };
}

/**
 * anchorCheck: does a head pin provide an external history anchor?
 * Genesis-zero alone does not qualify.
 */
export function anchorCheck(pin: HeadPin): { code: string; origin: string } {
  if (pin.seq === "0" && pin.hash === ZERO_HASH) return { code: "PIN_ABSENT", origin: "SIGNED_UNANCHORED" };
  return { code: "OK", origin: "PINNED" };
}

/** Trust locator digest: H(J(trust)) over the canonical trust object. */
export function trustDigest(t: Trust): string {
  return hashJson(t as unknown as Json);
}
