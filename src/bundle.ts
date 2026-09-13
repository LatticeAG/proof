/**
 * Revision, evidence root, inventory, and bundle assembly (§1.6).
 *
 * evidence = D("LAGI-PROOF-EVIDENCE/v1",{sources,events,keys,objects}) with
 * events as complete signed envelopes in bundle order, keys limited to keys
 * used by events, objects the sorted distinct ObjectRef set (refs, not
 * bodies). The root is independent of transport disclosure and audit keys.
 *
 * Inventory digest for event/audit/key is H(J(envelope)); byte count is the
 * J length; objects use the raw ObjectRef digest and declared length.
 */

import { jcsBytes, jcsString, type Json } from "./canon.js";
import { bundleHash, evidenceRoot, hashJson, sha256Hex, ZERO_HASH } from "./crypto.js";
import {
  compareEventRef, eventRefOf, eventDataObjectRefs, cmpStr,
  type Audit, type AuditRef, type BlobT, type Bundle, type BundleBody, type Cut,
  type Event, type EventRef, type InventoryItem, type KeyMaterial, type ObjectRef,
  type Source,
} from "./model.js";
import { auditRefOf } from "./model.js";
import { findSlot } from "./chain.js";

/** Bundle event order: (source, stream, numeric seq, hash). */
export function sortEvents(events: Event[]): Event[] {
  return events.slice().sort((a, b) => compareEventRef(eventRefOf(a), eventRefOf(b)));
}

export function sortKeys(keys: KeyMaterial[]): KeyMaterial[] {
  return keys.slice().sort((a, b) => cmpStr(a.id, b.id));
}

export function sortObjects(objects: BlobT[]): BlobT[] {
  return objects.slice().sort((a, b) => cmpStr(a.ref.digest, b.ref.digest));
}

export function sortSources(sources: Source[]): Source[] {
  return sources.slice().sort((a, b) => cmpStr(a.id, b.id));
}

export function sortCuts(cuts: Cut[]): Cut[] {
  return cuts.slice().sort((a, b) => cmpStr(a.source, b.source) || cmpStr(a.stream, b.stream));
}

export function sortAudit(entries: Audit[]): Audit[] {
  return entries.slice().sort((a, b) => (BigInt(a.body.seq) < BigInt(b.body.seq) ? -1 : 1));
}

export function distinctObjectRefs(events: Event[]): ObjectRef[] {
  const m = new Map<string, ObjectRef>();
  for (const e of events) {
    for (const r of eventDataObjectRefs(e.body.data)) m.set(r.digest, r);
  }
  return [...m.values()].sort((a, b) => cmpStr(a.digest, b.digest));
}

/** Distinct key ids required by events plus audit entries. */
export function usedKeyIds(events: Event[], audit: Audit[] = []): Set<string> {
  const ids = new Set<string>();
  for (const e of events) ids.add(e.body.key);
  for (const a of audit) ids.add(a.body.key);
  return ids;
}

export function computeEvidence(sources: Source[], events: Event[], keys: KeyMaterial[], refs: ObjectRef[]): string {
  return evidenceRoot(
    sortSources(sources) as unknown as Json,
    sortEvents(events) as unknown as Json,
    sortKeys(keys) as unknown as Json,
    refs as unknown as Json,
  );
}

/**
 * Cuts from an event set: the maximum supplied sequence of each populated
 * stream. A forked highest slot cuts with head ZERO and a mandatory fork
 * finding (emitted by the chain check).
 */
export function computeCuts(events: Event[]): Cut[] {
  const byStream = new Map<string, Event[]>();
  for (const e of events) {
    const k = `${e.body.source}\0${e.body.stream}`;
    const arr = byStream.get(k) ?? [];
    arr.push(e);
    byStream.set(k, arr);
  }
  const cuts: Cut[] = [];
  for (const [, evs] of byStream) {
    const maxSeq = evs.reduce((m, e) => (BigInt(e.body.seq) > m ? BigInt(e.body.seq) : m), 0n);
    const top = evs.filter((e) => BigInt(e.body.seq) === maxSeq);
    cuts.push({
      source: evs[0]!.body.source,
      stream: evs[0]!.body.stream,
      through: maxSeq.toString(),
      head: top.length === 1 ? top[0]!.hash : ZERO_HASH,
    });
  }
  return sortCuts(cuts);
}

function inventoryItem(kind: InventoryItem["kind"], digest: string, bytes: bigint, availability: InventoryItem["availability"]): InventoryItem {
  return { kind, digest, bytes: bytes.toString(), availability };
}

export function jcsItem(kind: "event" | "audit" | "key", envelope: Json): InventoryItem {
  const j = jcsBytes(envelope);
  return inventoryItem(kind, hashJson(envelope), BigInt(j.byteLength), "INCLUDED");
}

/**
 * Build the exact inventory for a bundle: every supplied event, audit entry,
 * and key hashed over its canonical envelope; every referenced object by
 * its declared ref with an availability label.
 */
export function buildInventory(
  events: Event[], audit: Audit[], keys: KeyMaterial[],
  refs: ObjectRef[], availability: Map<string, "INCLUDED" | "WITHHELD" | "UNAVAILABLE">,
): InventoryItem[] {
  const items: InventoryItem[] = [];
  for (const e of sortEvents(events)) items.push(jcsItem("event", e as unknown as Json));
  for (const a of sortAudit(audit)) items.push(jcsItem("audit", a as unknown as Json));
  for (const k of sortKeys(keys)) items.push(jcsItem("key", k as unknown as Json));
  for (const r of refs) {
    items.push(inventoryItem("object", r.digest, BigInt(r.bytes), availability.get(r.digest) ?? "UNAVAILABLE"));
  }
  return items.sort((a, b) => cmpStr(`${a.kind}:${a.digest}`, `${b.kind}:${b.digest}`));
}

/**
 * Assemble a bundle (§1.6): complete candidate set of the revision, exact
 * inventory, audit prefix through the publication record, disclosure from
 * the include set.
 */
export function assembleBundle(args: {
  workspace: string; revision: string; sources: Source[]; actions: EventRef[];
  events: Event[]; keys: KeyMaterial[]; audit: Audit[]; refs: ObjectRef[];
  blobs: BlobT[]; availability: Map<string, "INCLUDED" | "WITHHELD" | "UNAVAILABLE">;
  projectionHash: string; evidence: string; auditThrough: AuditRef;
}): Bundle {
  const sources = sortSources(args.sources);
  const actions = args.actions.slice().sort(compareEventRef);
  const cuts = computeCuts(args.events);
  const events = sortEvents(args.events);
  const keys = sortKeys(args.keys);
  const audit = sortAudit(args.audit);
  const objects = sortObjects(args.blobs);
  const refs = args.refs;
  const inventory = buildInventory(events, audit, keys, refs, args.availability);
  const included = objects.length;
  const disclosure =
    refs.length === 0 ? "FULL" as const
      : included === 0 ? "HASHES_ONLY" as const
        : included === refs.length ? "FULL" as const : "REDACTED" as const;
  const body: BundleBody = {
    v: 1, format: "proof-bundle/1", workspace: args.workspace, revision: args.revision,
    sources, actions, cuts, evidence: args.evidence, projection: args.projectionHash,
    inventory, disclosure, audit_through: args.auditThrough,
  };
  return { body, hash: bundleHash(body as unknown as Json), events, keys, audit, objects };
}

/**
 * Apply an include set to an existing bundle (the fixture's P.disclose):
 * drops object bodies, relabels inventory, recomputes the bundle hash.
 */
export function discloseBundle(b: Bundle, include: string[]): Bundle {
  const wanted = new Set(include);
  const objects = b.objects.filter((o) => wanted.has(o.ref.digest));
  const body = (JSON.parse(jcsString(b.body as unknown as Json)) as BundleBody);
  for (const i of body.inventory) {
    if (i.kind === "object" && !wanted.has(i.digest)) i.availability = "WITHHELD";
  }
  body.disclosure =
    objects.length === b.objects.length ? "FULL" : objects.length === 0 ? "HASHES_ONLY" : "REDACTED";
  return { ...b, body, objects, hash: bundleHash(body as unknown as Json) };
}

/**
 * Verify the exact inventory of a parsed bundle (§1.7 phase 2): every
 * supplied item hashed and labelled consistently; every referenced object
 * covered exactly once. Returns finding codes (empty = match).
 */
export function checkInventory(b: Bundle): string[] {
  const findings = new Set<string>();
  // Recompute expected items from the supplied envelopes.
  const expected = buildInventory(
    b.events, b.audit, b.keys,
    b.body.inventory.filter((i) => i.kind === "object").map((i) => ({ digest: i.digest, bytes: i.bytes, media: "application/octet-stream" as const })),
    new Map(b.body.inventory.filter((i) => i.kind === "object").map((i) => [i.digest, i.availability])),
  );
  const got = new Map(b.body.inventory.map((i) => [`${i.kind}:${i.digest}`, i]));
  const exp = new Map(expected.map((i) => [`${i.kind}:${i.digest}`, i]));
  if (got.size !== b.body.inventory.length) findings.add("INVENTORY_MISMATCH");
  for (const [k, item] of exp) {
    const g = got.get(k);
    if (!g) { findings.add("INVENTORY_MISMATCH"); continue; }
    if (item.kind !== "object" && (g.bytes !== item.bytes || g.availability !== item.availability)) {
      findings.add("INVENTORY_MISMATCH");
    }
  }
  for (const k of got.keys()) if (!exp.has(k)) findings.add("INVENTORY_MISMATCH");
  // Every referenced object must be inventoried exactly once.
  const refs = distinctObjectRefs(b.events);
  for (const r of refs) {
    if (!got.has(`object:${r.digest}`)) findings.add("INVENTORY_MISMATCH");
  }
  // Object bytes consistency: included objects must match digest+length.
  for (const o of b.objects) {
    const raw = Buffer.from(o.content, "base64url");
    if (raw.toString("base64url") !== o.content
      || BigInt(raw.byteLength) !== BigInt(o.ref.bytes)
      || sha256Hex(raw) !== o.ref.digest) {
      findings.add("HASH_MISMATCH");
    }
  }
  return [...findings].sort();
}
