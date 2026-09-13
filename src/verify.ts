/**
 * §1.7 verification procedure and grading.
 *
 * Phases:
 *   1. size/shape/version/canonical-encoding (callers' parsers; failures
 *      are protocol errors, never a partial report)
 *   2. recompute bundle hash, inventory, object hashes/lengths, event/audit
 *      hashes, key ids, evidence root — mismatch is INVALID
 *   3. every signature under the included KeyMaterial whose id equals the
 *      record's key field — never a substituted key
 *   4. workspace/source scope, cuts, chains, parents, Lamport, duplicate
 *      slots, causal graph
 *   5. replay legal transitions, reconstruct + compare projection, recompute
 *      the selected action closure, verify the audit revision binding
 *   6. independent role/scope/key-interval pins, head consistency, trust
 *      expiry — trust decisions are never copied from the bundle
 *   7. emit the deterministic Verification.
 *
 * On integrity failure: reconstruction NONE, accepted false, trust
 * dimensions UNTRUSTED, freshness UNANCHORED, lineage INCOMPLETE unless an
 * established conflict makes it CONFLICTED, and reasons carry only the
 * first failing phase's sorted findings.
 */

import { ProofError } from "./errors.js";
import { jcsBytes, jcsString, type Json } from "./canon.js";
import {
  bundleHash, evidenceRoot, hashJson, sha256Hex, b64uDecodeStrict, decodeSignature,
  verifyMessage, signingMessage, rotateProofDigest, D_EVENT_SIGN, D_AUDIT_SIGN, ZERO_HASH,
} from "./crypto.js";
import {
  cmpStr, compareEventRef, eventRefOf,
  type Audit, type Bundle, type Event, type EventRef, type Finding, type InventoryItem,
  type KeyMaterial, type ObjectRef, type Requirement, type Trust, type Verification,
  type HeadPin, eventDataObjectRefs,
} from "./model.js";
import { chainCheck, eventRefKey, slotMap } from "./chain.js";
import { replay } from "./replay.js";
import { computeCuts, sortEvents, sortAudit } from "./bundle.js";
import { keyCheck, headCheck, auditHeadCheck, trustCheck, trustTime } from "./trust.js";
import { lineageClosure } from "./lineage.js";

// Findings that invalidate integrity (present contradictory/illegal bytes).
const INVALIDATING = new Set([
  "HASH_MISMATCH", "INVENTORY_MISMATCH", "KEY_MATERIAL_INVALID", "SIGNATURE_INVALID",
  "SCOPE_MISMATCH", "PREV_MISMATCH", "LAMPORT_INVALID", "STATE_TRANSITION",
  "PROJECTION_MISMATCH", "CAUSAL_CYCLE", "AUDIT_FORK", "AUDIT_BINDING_MISMATCH",
  "DELEGATION_REUSED", "DELEGATION_MISMATCH",
]);
// Findings that mark conflicting (never accepted) evidence.
const CONFLICTING = new Set(["SOURCE_FORK", "AUDIT_FORK"]);
// Findings of missing evidence.
const INCOMPLETE_CODES = new Set(["PREFIX_MISSING", "PARENT_MISSING", "PIN_AHEAD"]);

function sortedReasons(findings: Iterable<string>): string[] {
  return [...new Set(findings)].sort();
}

function recomputePhase(b: Bundle): string[] {
  const out: string[] = [];
  if (bundleHash(b.body as unknown as Json) !== b.hash) out.push("HASH_MISMATCH");
  for (const e of b.events) if (hashJsonDomain(e.body) !== e.hash) out.push("HASH_MISMATCH");
  for (const a of b.audit) if (hashJsonDomainA(a.body) !== a.hash) out.push("HASH_MISMATCH");
  for (const k of b.keys) {
    let raw: Buffer;
    try { raw = b64uDecodeStrict(k.public); } catch { out.push("KEY_MATERIAL_INVALID"); continue; }
    if (sha256Hex(raw) !== k.id) out.push("KEY_MATERIAL_INVALID");
  }
  for (const o of b.objects) {
    let raw: Buffer;
    try { raw = b64uDecodeStrict(o.content); } catch { out.push("HASH_MISMATCH"); continue; }
    if (BigInt(raw.byteLength) !== BigInt(o.ref.bytes) || sha256Hex(raw) !== o.ref.digest) {
      out.push("HASH_MISMATCH");
    }
  }
  // Exact inventory: recompute items for supplied envelopes and compare the
  // complete (kind,digest,bytes,availability) sets.
  const expected = new Map<string, InventoryItem>();
  const add = (it: InventoryItem) => expected.set(`${it.kind}:${it.digest}`, it);
  for (const e of sortEvents(b.events)) add(jcsInvItem("event", e as unknown as Json));
  for (const a of sortAudit(b.audit)) add(jcsInvItem("audit", a as unknown as Json));
  for (const k of b.keys.slice().sort((x, y) => cmpStr(x.id, y.id))) add(jcsInvItem("key", k as unknown as Json));
  const refs = distinctRefs(b.events);
  const suppliedBlobs = new Map(b.objects.map((o) => [o.ref.digest, o]));
  for (const r of refs) {
    const blob = suppliedBlobs.get(r.digest);
    add({
      kind: "object", digest: r.digest, bytes: r.bytes,
      availability: blob ? "INCLUDED" : "WITHHELD",
    });
  }
  const got = new Map<string, InventoryItem>();
  for (const i of b.body.inventory) {
    const k = `${i.kind}:${i.digest}`;
    if (got.has(k)) out.push("INVENTORY_MISMATCH");
    got.set(k, i);
  }
  for (const [k, it] of expected) {
    const g = got.get(k);
    if (!g) { out.push("INVENTORY_MISMATCH"); continue; }
    if (g.bytes !== it.bytes) out.push("INVENTORY_MISMATCH");
    if (g.kind !== "object" && g.availability !== "INCLUDED") out.push("INVENTORY_MISMATCH");
    if (g.kind === "object") {
      if (g.availability === "INCLUDED" && !suppliedBlobs.has(g.digest)) out.push("INVENTORY_MISMATCH");
    }
  }
  for (const k of got.keys()) if (!expected.has(k)) out.push("INVENTORY_MISMATCH");
  // A supplied blob that is not a referenced object is still covered by its
  // ref entry above only if referenced; extra blobs are mismatches.
  for (const o of b.objects) if (!refs.some((r) => r.digest === o.ref.digest)) out.push("INVENTORY_MISMATCH");
  // Evidence root over the supplied set; keys are those used by events only.
  const usedIds = new Set(b.events.map((e) => e.body.key));
  const ev = evidenceRoot(
    b.body.sources as unknown as Json,
    sortEvents(b.events) as unknown as Json,
    b.keys.filter((k) => usedIds.has(k.id)).sort((x, y) => cmpStr(x.id, y.id)) as unknown as Json,
    refs as unknown as Json,
  );
  if (ev !== b.body.evidence) out.push("HASH_MISMATCH");
  return out;
}

function jcsInvItem(kind: "event" | "audit" | "key", envelope: Json): InventoryItem {
  const j = jcsBytes(envelope);
  return { kind, digest: hashJson(envelope), bytes: String(j.byteLength), availability: "INCLUDED" };
}

function distinctRefs(events: Event[]): ObjectRef[] {
  const m = new Map<string, ObjectRef>();
  for (const e of events) for (const r of eventDataObjectRefs(e.body.data)) m.set(r.digest, r);
  return [...m.values()].sort((a, b) => cmpStr(a.digest, b.digest));
}

function hashJsonDomain(body: Json): string {
  return sha256Hex(Buffer.concat([Buffer.from("LAGI-PROOF-EVENT/v1"), Buffer.from([0]), jcsBytes(body)]));
}
function hashJsonDomainA(body: Json): string {
  return sha256Hex(Buffer.concat([Buffer.from("LAGI-PROOF-AUDIT/v1"), Buffer.from([0]), jcsBytes(body)]));
}

/** Phase 3: every supplied signature under the record's declared key id. */
function signaturePhase(b: Bundle): string[] {
  const out: string[] = [];
  const keyById = new Map(b.keys.map((k) => [k.id, k]));
  const check = (hash: string, sig: string, keyId: string, tag: string) => {
    const k = keyById.get(keyId);
    if (!k) { out.push("KEY_MATERIAL_INVALID"); return; }
    let pub: Buffer, sraw: Buffer;
    try { pub = b64uDecodeStrict(k.public); sraw = decodeSignature(sig); }
    catch { out.push("KEY_MATERIAL_INVALID"); return; }
    if (!verifyMessage(pub, signingMessage(tag, hash), sraw)) out.push("SIGNATURE_INVALID");
  };
  for (const e of b.events) check(e.hash, e.signature, e.body.key, D_EVENT_SIGN);
  for (const a of b.audit) check(a.hash, a.signature, a.body.key, D_AUDIT_SIGN);
  return out;
}

/** Phase 4: scope, cuts, chains, slots, causal graph. */
function structurePhase(b: Bundle): { findings: Finding[]; cycle: boolean } {
  const out: Finding[] = [];
  const add = (code: string, subjects: EventRef[] = []) =>
    out.push({ code, subjects: subjects.slice().sort(compareEventRef) });

  for (const e of b.events) if (e.body.workspace !== b.body.workspace) add("SCOPE_MISMATCH", [eventRefOf(e)]);
  for (const a of b.audit) if (a.body.workspace !== b.body.workspace) add("SCOPE_MISMATCH");
  const srcIds = new Set(b.body.sources.map((s) => s.id));
  for (const e of b.events) if (!srcIds.has(e.body.source)) add("SCOPE_MISMATCH", [eventRefOf(e)]);

  // Declared cuts must equal the recomputed stream cuts.
  const recomputed = computeCuts(b.events);
  const declared = b.body.cuts.slice().sort((x, y) => cmpStr(x.source, y.source) || cmpStr(x.stream, y.stream));
  if (jcsString(recomputed as unknown as Json) !== jcsString(declared as unknown as Json)) {
    add("INVENTORY_MISMATCH");
  }

  const chain = chainCheck(b.events);
  out.push(...chain.findings);
  // Audit chain: contiguous 1..through, prev links, fork detection.
  out.push(...auditChainFindings(b.audit));
  return { findings: out, cycle: chain.findings.some((f) => f.code === "CAUSAL_CYCLE") };
}

export function auditChainFindings(entries: Audit[]): Finding[] {
  const out: Finding[] = [];
  const add = (code: string, subjects: EventRef[] = []) => out.push({ code, subjects });
  const bySeq = new Map<bigint, Audit[]>();
  for (const a of entries) {
    const s = BigInt(a.body.seq);
    const arr = bySeq.get(s) ?? []; arr.push(a); bySeq.set(s, arr);
  }
  for (const arr of bySeq.values()) if (arr.length > 1) add("AUDIT_FORK");
  const seqs = [...bySeq.keys()].sort((x, y) => (x < y ? -1 : 1));
  for (const a of entries) {
    const s = BigInt(a.body.seq);
    if (s === 1n) {
      if (a.body.prev !== ZERO_HASH) add("PREV_MISMATCH");
      if (a.body.data.kind !== "WorkspaceCreated") add("AUDIT_BINDING_MISMATCH");
    } else {
      const prev = bySeq.get(s - 1n);
      if (!prev) add("PREFIX_MISSING");
      else if (!prev.some((p) => p.hash === a.body.prev)) add("PREV_MISMATCH");
    }
  }
  // Semantics: unique source registration; consecutive publication
  // revisions; stage staged before exactly one terminal; KeyRotated proof.
  const registered = new Set<string>();
  let lastRevision = 0n;
  const stageState = new Map<string, { staged: boolean; terminal: boolean }>();
  for (const a of entries.slice().sort((x, y) => (BigInt(x.body.seq) < BigInt(y.body.seq) ? -1 : 1))) {
    const d = a.body.data;
    switch (d.kind) {
      case "WorkspaceCreated":
        if (a.body.seq !== "1") add("AUDIT_BINDING_MISMATCH");
        break;
      case "SourceRegistered": {
        const sid = (d.source as { id: string }).id;
        if (registered.has(sid)) add("AUDIT_BINDING_MISMATCH"); else registered.add(sid);
        if (BigInt(d.revision as string) !== lastRevision + 1n) add("AUDIT_BINDING_MISMATCH");
        else lastRevision = BigInt(d.revision as string);
        break;
      }
      case "ImportCommitted": {
        if (BigInt(d.revision as string) !== lastRevision + 1n) add("AUDIT_BINDING_MISMATCH");
        else lastRevision = BigInt(d.revision as string);
        const st = stageState.get(d.stage as string) ?? { staged: false, terminal: false };
        if (!st.staged || st.terminal) add("AUDIT_BINDING_MISMATCH");
        st.terminal = true;
        stageState.set(d.stage as string, st);
        break;
      }
      case "ImportCancelled": {
        const st = stageState.get(d.stage as string) ?? { staged: false, terminal: false };
        if (!st.staged || st.terminal) add("AUDIT_BINDING_MISMATCH");
        st.terminal = true;
        stageState.set(d.stage as string, st);
        break;
      }
      case "ImportStaged": {
        const st = stageState.get(d.stage as string) ?? { staged: false, terminal: false };
        if (st.staged) add("AUDIT_BINDING_MISMATCH");
        st.staged = true;
        stageState.set(d.stage as string, st);
        break;
      }
      case "KeyRotated": {
        // proof is next's Ed25519 signature over
        // D("LAGI-PROOF-ROTATE/v1",{workspace,old,next,head}) with head=prev.
        const next = d.next as KeyMaterial;
        const expect = rotateProofDigest(a.body.workspace, d.old as string, next as unknown as Json, a.body.prev);
        try {
          const pub = b64uDecodeStrict(next.public);
          const sig = decodeSignature(d.proof as string);
          if (!verifyMessage(pub, Buffer.from(expect, "hex"), sig)) add("AUDIT_BINDING_MISMATCH");
        } catch { add("AUDIT_BINDING_MISMATCH"); }
        break;
      }
    }
    void seqs;
  }
  return out;
}

/** The complete §1.7 procedure on already-parsed inputs. */
export function verifyBundle(b: Bundle, trust: Trust, requirement: Requirement, asOf: string): Verification {
  const trustHash = hashJson(trust as unknown as Json);
  const base: Verification = {
    v: 1, bundle: b.hash, trust: trustHash, requirement, as_of_unix_ms: asOf,
    accepted: false, integrity: "VALID", lineage: "COMPLETE_RELATIVE",
    reconstruction: "NONE", origin: "UNTRUSTED", audit: "UNTRUSTED",
    freshness: "UNANCHORED", semantics: "RECORDED_STATEMENTS_ONLY",
    current_authority: "UNKNOWN", foreign: foreignList(b), reasons: [],
  };

  // Phase 2 — recomputation.
  const p2 = recomputePhase(b);
  if (p2.length) return failReport(base, p2, false);

  // Phase 3 — signatures.
  const p3 = signaturePhase(b);
  if (p3.length) return failReport(base, p3, false);

  // Phase 4 — scope/chains/slots.
  const p4 = structurePhase(b);
  const conflict = p4.findings.some((f) => CONFLICTING.has(f.code));
  const p4invalid = p4.findings.filter((f) => INVALIDATING.has(f.code));
  if (p4invalid.length) return failReport(base, p4invalid.map((f) => f.code), conflict);

  // Phase 5 — replay/projection/binding.
  const { projection, findings: replayFindings, applied } = replay(b.events, p4.findings);
  const p5: Finding[] = [];
  const projectionComputed = projectionDigestValue(projection);
  if (projectionComputed !== b.body.projection) p5.push({ code: "PROJECTION_MISMATCH", subjects: [] });
  // Selected-action closure must recompute (actions exist in the set).
  const byRef = new Map(b.events.map((e) => [eventRefKey(eventRefOf(e)), e]));
  for (const a of b.body.actions) {
    if (!byRef.has(eventRefKey(a))) p5.push({ code: "ACTION_UNKNOWN", subjects: [a] });
  }
  try {
    lineageClosure(b.events, b.body.actions, 20000, 4096, projection.edges, replayFindings);
  } catch (e) {
    if (e instanceof ProofError && e.code === "PATH_LIMIT") p5.push({ code: "PATH_LIMIT", subjects: [] });
    else if (e instanceof ProofError && e.code === "ACTION_UNKNOWN") p5.push({ code: "ACTION_UNKNOWN", subjects: [] });
    else throw e;
  }
  p5.push(...auditBindingFindings(b));
  const p5invalid = p5.filter((f) => INVALIDATING.has(f.code) || f.code === "ACTION_UNKNOWN" || f.code === "PATH_LIMIT");
  const structuralAll = dedupCodes([...p4.findings, ...p5]);
  if (p5invalid.length) {
    return failReport(base, p5invalid.map((f) => f.code), conflict);
  }

  // Illegal transitions inside replay are integrity failures.
  const replayInvalid = replayFindings.filter((f) => INVALIDATING.has(f.code));
  if (replayInvalid.length) return failReport(base, replayInvalid.map((f) => f.code), conflict);

  // Phase 6 — independent trust.
  const tstruct = trustCheck(trust);
  if (tstruct.code !== "OK") throw new ProofError("TRUST_INVALID", "Trust file is structurally invalid.");
  const expired = trustTime(trust, asOf).code === "TRUST_EXPIRED";

  const tFindings = new Set<string>();
  if (expired) tFindings.add("TRUST_EXPIRED");

  // Origin pins: every populated stream's every event must verify under pins.
  const streams = new Map<string, Event[]>();
  for (const e of b.events) {
    const k = `${e.body.source}\0${e.body.stream}`;
    const arr = streams.get(k) ?? []; arr.push(e); streams.set(k, arr);
  }
  const originHeads = new Map<string, HeadPin[]>();
  for (const h of trust.heads.filter((x) => x.role === "origin")) {
    const k = `${h.source}\0${h.stream}`;
    const arr = originHeads.get(k) ?? []; arr.push(h); originHeads.set(k, arr);
  }
  let originConflict = false, originUntrusted = expired, originIncomplete = false;
  let anyAhead = false, anyUnanchored = false;
  const keyById = new Map(b.keys.map((k) => [k.id, k]));
  const streamAnchored = new Map<string, boolean>();
  for (const [sk, evs] of streams) {
    for (const e of evs) {
      const km = keyById.get(e.body.key);
      if (!km) { originUntrusted = true; tFindings.add("KEY_UNPINNED"); continue; }
      const r = keyCheck(e, km, trust, "origin");
      if (r.code !== "OK") { originUntrusted = true; tFindings.add(r.code); }
    }
    const cut = recomputedCut(evs);
    const allPins = originHeads.get(sk) ?? [];
    const pins = allPins.filter((p) => p.seq !== "0");
    if (!allPins.length) { anyUnanchored = true; tFindings.add("PIN_ABSENT"); }
    let anchored = false;
    for (const pin of pins) {
      const hc = headCheck({ cutSeq: cut, events: evs, pin });
      if (hc.code === "PIN_AHEAD") { anyAhead = true; tFindings.add("PIN_AHEAD"); }
      else if (hc.code === "PIN_MISMATCH") { originConflict = true; tFindings.add("PIN_MISMATCH"); }
      else if (hc.code === "CONFLICTED") { originConflict = true; anchored = true; }
      else anchored = true;
    }
    if (allPins.length && !pins.length) { anyUnanchored = true; tFindings.add("PIN_ABSENT"); }
    if (pins.length && !anchored) {
      if (pins.every((p) => BigInt(p.seq) > BigInt(cut))) originIncomplete = true;
      else anyUnanchored = true;
    }
    streamAnchored.set(sk, anchored);
  }
  // Attributable fork: both candidates satisfy independent origin pins.
  const slots = slotMap(b.events);
  for (const [, arr] of slots) {
    if (arr.length > 1 && arr.every((e) => {
      const km = keyById.get(e.body.key);
      return km && keyCheck(e, km, trust, "origin").code === "OK";
    })) originConflict = true;
  }

  // Audit pins: prefix entries under audit-role pins + a nonzero audit head.
  let auditConflict = false, auditUntrusted = expired, auditIncomplete = false, auditAnchored = false;
  for (const a of b.audit) {
    const km = keyById.get(a.body.key);
    if (!km) { auditUntrusted = true; tFindings.add("KEY_UNPINNED"); continue; }
    const r = keyCheck(a, km, trust, "audit");
    if (r.code !== "OK") { auditUntrusted = true; tFindings.add(r.code); }
  }
  const allAuditPins = trust.heads.filter((h) => h.role === "audit");
  const auditPins = allAuditPins.filter((h) => h.seq !== "0");
  if (!allAuditPins.length || !auditPins.length) { anyUnanchored = true; tFindings.add("PIN_ABSENT"); }
  for (const pin of auditPins) {
    const hc = auditHeadCheck(b.audit, pin);
    if (hc.code === "PIN_AHEAD") { anyAhead = true; auditIncomplete = true; tFindings.add("PIN_AHEAD"); }
    else if (hc.code === "PIN_MISMATCH") { auditConflict = true; tFindings.add("PIN_MISMATCH"); }
    else if (hc.code === "CONFLICTED") { auditConflict = true; auditAnchored = true; }
    else auditAnchored = true;
  }

  const dim = (conf: boolean, untr: boolean, inc: boolean, anchored: boolean): Verification["origin"] =>
    conf ? "CONFLICTED" : untr ? "UNTRUSTED" : inc ? "INCOMPLETE" : anchored ? "PINNED" : "SIGNED_UNANCHORED";
  base.origin = dim(originConflict, originUntrusted, originIncomplete,
    streams.size > 0 && [...streams.keys()].every((sk) => streamAnchored.get(sk)));
  base.audit = dim(auditConflict, auditUntrusted, auditIncomplete, auditAnchored);
  base.freshness = anyAhead ? "BEHIND_REQUIRED_CUT" : anyUnanchored ? "UNANCHORED" : "AT_REQUIRED_CUT";

  // Lineage dimension.
  const gap = structuralAll.some((c) => INCOMPLETE_CODES.has(c));
  base.lineage = conflict ? "CONFLICTED" : gap ? "INCOMPLETE" : "COMPLETE_RELATIVE";

  // Reconstruction: complete native history, legal transitions, no
  // conflicting/gapped lineage, and every referenced object's bytes.
  const objAvail = new Map<string, string>();
  for (const i of b.body.inventory) if (i.kind === "object") objAvail.set(i.digest, i.availability);
  let missingBytes = false;
  for (const r of distinctRefs(b.events)) {
    const av = objAvail.get(r.digest);
    if (av !== "INCLUDED") {
      missingBytes = true;
      tFindings.add(av === "WITHHELD" ? "OBJECT_WITHHELD" : "OBJECT_MISSING");
    }
  }
  const anyRun = projection.runs.length > 0;
  if (!anyRun && b.events.length > 0) base.reconstruction = "NONE";
  else if (conflict || gap || missingBytes) base.reconstruction = "PARTIAL";
  else base.reconstruction = "FULL_RECONSTRUCTION";

  base.integrity = "VALID";
  base.reasons = sortedReasons([...tFindings, ...structuralAll]);
  base.accepted = accept(requirement, base);
  return base;
}

function recomputedCut(evs: Event[]): string {
  return evs.reduce((m, e) => (BigInt(e.body.seq) > m ? BigInt(e.body.seq) : m), 0n).toString();
}
function maxAuditSeq(a: Audit[]): string {
  return a.reduce((m, x) => (BigInt(x.body.seq) > m ? BigInt(x.body.seq) : m), 0n).toString();
}

function projectionDigestValue(p: Json): string {
  return sha256Hex(Buffer.concat([Buffer.from("LAGI-PROOF-PROJECTION/v1"), Buffer.from([0]), jcsBytes(p)]));
}

function dedupCodes(fs: Finding[]): string[] {
  return [...new Set(fs.map((f) => f.code))];
}

function failReport(base: Verification, codes: string[], conflict: boolean): Verification {
  base.integrity = "INVALID";
  base.accepted = false;
  base.reconstruction = "NONE";
  base.origin = "UNTRUSTED";
  base.audit = "UNTRUSTED";
  base.freshness = "UNANCHORED";
  base.lineage = conflict ? "CONFLICTED" : "INCOMPLETE";
  base.reasons = sortedReasons(codes);
  return base;
}

function accept(req: Requirement, v: Verification): boolean {
  if (v.integrity !== "VALID" || v.lineage === "CONFLICTED") return false;
  if (req === "INTEGRITY") return true;
  if (v.reconstruction !== "FULL_RECONSTRUCTION") return false;
  if (req === "RECONSTRUCTION") return true;
  return v.origin === "PINNED" && v.audit === "PINNED" && v.freshness === "AT_REQUIRED_CUT";
}

function foreignList(b: Bundle): Verification["foreign"] {
  const seen = new Map<string, { digest: string; format: Verification["foreign"][number]["format"]; assessment: "NOT_EVALUATED" }>();
  for (const e of b.events) {
    const d = e.body.data;
    if (d.kind === "EvidenceAttached") {
      const o = d.object as unknown as ObjectRef;
      seen.set(`${d.format}\0${o.digest}`, { digest: o.digest, format: d.format as never, assessment: "NOT_EVALUATED" });
    }
  }
  return [...seen.values()].sort((a, b) => cmpStr(a.format, b.format) || cmpStr(a.digest, b.digest));
}

function auditBindingFindings(b: Bundle): Finding[] {
  const out: Finding[] = [];
  const through = b.body.audit_through;
  const rec = b.audit.find((a) => a.body.seq === through.seq && a.hash === through.hash);
  if (!rec) {
    out.push({ code: "AUDIT_BINDING_MISMATCH", subjects: [] });
    return out;
  }
  const d = rec.body.data;
  const binds =
    (d.kind === "ImportCommitted" || d.kind === "SourceRegistered") &&
    d.revision === b.body.revision && d.evidence === b.body.evidence;
  const genesis = d.kind === "WorkspaceCreated" && b.body.revision === "0" && d.evidence === b.body.evidence;
  if (!binds && !genesis) out.push({ code: "AUDIT_BINDING_MISMATCH", subjects: [] });
  return out;
}
