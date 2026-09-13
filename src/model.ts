/**
 * Schema validators for the §1 normative IDL.
 *
 * Every object is closed; every field required unless marked `?`; null is
 * legal only where written; no implicit defaults on signed inputs.
 * Errors: SCHEMA_INVALID for shape/bounds, UNSUPPORTED_SCHEMA for a value
 * outside a closed enum, UNSUPPORTED_VERSION for a bad `v`.
 */

import { ProofError } from "./errors.js";
import type { Json, JsonObject } from "./canon.js";
import { jcsBytes } from "./canon.js";
import { b64uDecodeStrict, decodePublicKey, decodeSignature, keyIdFromPublic, ZERO_HASH } from "./crypto.js";

export const HASH_RE = /^[0-9a-f]{64}$/;
export const COUNT_RE = /^(0|[1-9][0-9]*)$/;
export const ID_RE = /^[A-Za-z][A-Za-z0-9_-]{0,63}$/;
export const COUNT_MAX = 9223372036854775807n;

export const MAX_PARENTS = 64;
export const MAX_EVENT_OBJECTS = 16;
export const MAX_EVENT_CANON = 64 * 1024;
export const MAX_AUDIT_CANON = 4 * 1024;
export const MAX_OBJECT_BYTES = 1048576;
export const MAX_BUNDLE_BYTES = 64 * 1024 * 1024;
export const MAX_INVENTORY = 140000;
export const MAX_PROJECTION_EDGES = 200000;
export const MAX_BUNDLE_EVENTS = 20000;
export const MAX_AUDIT_ENTRIES = 100000;
export const MAX_LINEAGE_NODES = 20000;
export const MAX_LINEAGE_DEPTH = 4096;

export const MEDIA = ["application/json", "application/octet-stream", "text/plain"] as const;
export const OUTCOMES = ["SUCCEEDED", "FAILED", "UNKNOWN", "CANCELLED"] as const;
export const FOREIGN_FORMATS = ["world-lineage/1", "vislineage-bundle/1", "covenant-opaque/1"] as const;
export const DISCLOSURES = ["FULL", "HASHES_ONLY", "REDACTED"] as const;
export const REQUIREMENTS = ["INTEGRITY", "RECONSTRUCTION", "ANCHORED"] as const;
export const KEY_ROLES = ["origin", "audit"] as const;
export const KEY_STATUS = ["ACTIVE", "RETIRED", "COMPROMISED"] as const;
export const OPERATIONS = ["read", "write", "compute", "dispatch"] as const;
export const AVAILABILITY = ["INCLUDED", "WITHHELD", "UNAVAILABLE"] as const;

export type Media = (typeof MEDIA)[number];
export type Outcome = (typeof OUTCOMES)[number];
export type ForeignFormat = (typeof FOREIGN_FORMATS)[number];
export type Disclosure = (typeof DISCLOSURES)[number];
export type Requirement = (typeof REQUIREMENTS)[number];

export type ObjectRef = { digest: string; bytes: string; media: Media }
export type BlobT = { ref: ObjectRef; content: string }
export type KeyMaterial = { id: string; public: string }
export type Source = { id: string; namespace: string; profile: "proof-evidence/1" }
export type EventRef = { source: string; stream: string; seq: string; hash: string }
export type Cut = { source: string; stream: string; through: string; head: string }
export type AuditRef = { seq: string; hash: string }
export type EventData = JsonObject & { kind: string };
export interface EventBody extends JsonObject {
  v: 1; workspace: string; source: string; stream: string; seq: string;
  prev: string; lamport: string; key: string; parents: EventRef[]; data: EventData;
}
export type Event = { body: EventBody; hash: string; signature: string }
export type AuditData = JsonObject & { kind: string };
export interface AuditBody extends JsonObject {
  v: 1; workspace: string; seq: string; prev: string; key: string;
  principal: string; request: string; data: AuditData;
}
export type Audit = { body: AuditBody; hash: string; signature: string }
export type KeyPin = {
  key: string; role: "origin" | "audit"; source: string | null; stream: string | null;
  first: string; last: string; status: "ACTIVE" | "RETIRED" | "COMPROMISED";
}
export type HeadPin = { role: "origin" | "audit"; source: string | null; stream: string | null; seq: string; hash: string }
export type Trust = { v: 1; workspace: string; keys: KeyPin[]; heads: HeadPin[]; valid_until_unix_ms: string | null }
export type VerifyOptions = { requirement: Requirement; as_of_unix_ms: string }
export type Batch = { events: Event[]; keys: KeyMaterial[]; objects: BlobT[] }
export type Revision = { revision: string; evidence: string; cuts: Cut[]; events: number; audit: AuditRef }
export type InventoryItem = { kind: "event" | "audit" | "key" | "object"; digest: string; bytes: string; availability: "INCLUDED" | "WITHHELD" | "UNAVAILABLE" }
export interface BundleBody extends JsonObject {
  v: 1; format: "proof-bundle/1"; workspace: string; revision: string;
  sources: Source[]; actions: EventRef[]; cuts: Cut[]; evidence: string;
  projection: string; inventory: InventoryItem[]; disclosure: Disclosure; audit_through: AuditRef;
}
export type Bundle = { body: BundleBody; hash: string; events: Event[]; keys: KeyMaterial[]; audit: Audit[]; objects: BlobT[] }
export type Node = { type: "event" | "object"; ref?: EventRef | ObjectRef; at?: EventRef }
export type Edge = { from: Node; to: Node; kind: string }
export type Finding = { code: string; subjects: EventRef[] }
export interface StepView extends JsonObject { step: string; operation: string; state: string; opened: EventRef; closed: EventRef | null; observations: ObjectRef[]; evidence: { format: ForeignFormat; object: ObjectRef }[] }
export interface RunView extends JsonObject { source: string; stream: string; run: string; hypothetical: boolean; state: string; opened: EventRef; closed: EventRef | null; steps: StepView[] }
export interface Projection extends JsonObject { runs: RunView[]; edges: Edge[]; findings: Finding[]; corrections: EventRef[] }
export type LineageRequest = { revision: string; actions: EventRef[]; max_nodes: number; max_depth: number }
export type Lineage = { revision: string; projection: string; nodes: Node[]; edges: Edge[]; findings: Finding[] }
export interface Verification extends JsonObject {
  v: 1; bundle: string; trust: string; requirement: Requirement; as_of_unix_ms: string;
  accepted: boolean; integrity: "VALID" | "INVALID";
  lineage: "COMPLETE_RELATIVE" | "INCOMPLETE" | "CONFLICTED";
  reconstruction: "FULL_RECONSTRUCTION" | "PARTIAL" | "NONE";
  origin: "PINNED" | "SIGNED_UNANCHORED" | "UNTRUSTED" | "INCOMPLETE" | "CONFLICTED";
  audit: "PINNED" | "SIGNED_UNANCHORED" | "UNTRUSTED" | "INCOMPLETE" | "CONFLICTED";
  freshness: "AT_REQUIRED_CUT" | "BEHIND_REQUIRED_CUT" | "UNANCHORED";
  semantics: "RECORDED_STATEMENTS_ONLY"; current_authority: "UNKNOWN";
  foreign: { digest: string; format: ForeignFormat; assessment: "NOT_EVALUATED" }[];
  reasons: string[];
}

// ---------- scalar checkers ----------

function fail(code: "SCHEMA_INVALID" | "UNSUPPORTED_SCHEMA" | "UNSUPPORTED_VERSION" | "TRUST_INVALID" | "REQUEST_INVALID" | "KEY_MATERIAL_INVALID" | "HASH_MISMATCH" | "BUNDLE_LIMIT", msg: string, field?: string | null): never {
  throw new ProofError(code, msg, field ?? null);
}

export function isObj(v: unknown): v is JsonObject {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export function requireFields(o: JsonObject, fields: string[], field = ""): void {
  for (const f of fields) if (!(f in o)) fail("SCHEMA_INVALID", `Missing field ${f}.`, field || `/${f}`);
  for (const k of Object.keys(o)) if (!fields.includes(k)) fail("SCHEMA_INVALID", `Unknown field ${k}.`, `${field}/${k}`);
}

export function checkHash(v: Json, field = ""): string {
  if (typeof v !== "string" || !HASH_RE.test(v)) fail("SCHEMA_INVALID", "Bad hash.", field);
  return v;
}

export function checkCount(v: Json, field = "", allowZero = true): string {
  if (typeof v !== "string" || !COUNT_RE.test(v)) fail("SCHEMA_INVALID", "Bad count.", field);
  if (BigInt(v) > COUNT_MAX) fail("SCHEMA_INVALID", "Count exceeds bound.", field);
  if (!allowZero && v === "0") fail("SCHEMA_INVALID", "Zero is not an event position.", field);
  return v;
}

export function checkId(v: Json, field = ""): string {
  if (typeof v !== "string" || !ID_RE.test(v)) fail("SCHEMA_INVALID", "Bad id.", field);
  return v;
}

export function checkEnum<T extends string>(v: Json, allowed: readonly T[], field = ""): T {
  if (typeof v !== "string" || !(allowed as readonly string[]).includes(v)) {
    fail("UNSUPPORTED_SCHEMA", `Value outside closed enum at ${field}.`, field);
  }
  return v as T;
}

// ---------- shared leaf types ----------

export function parseObjectRef(v: Json, field = "/object"): ObjectRef {
  if (!isObj(v)) fail("SCHEMA_INVALID", "ObjectRef must be an object.", field);
  requireFields(v, ["digest", "bytes", "media"], field);
  const ref: ObjectRef = {
    digest: checkHash(v.digest!, `${field}/digest`),
    bytes: checkCount(v.bytes!, `${field}/bytes`),
    media: checkEnum(v.media!, MEDIA, `${field}/media`),
  };
  if (BigInt(ref.bytes) > BigInt(MAX_OBJECT_BYTES)) fail("SCHEMA_INVALID", "ObjectRef.bytes exceeds 1 MiB.", `${field}/bytes`);
  return ref;
}

/**
 * Parse a Blob. With strict=true (staging admission, objectCheck) the raw
 * content's length and digest MUST equal ref.bytes/ref.digest; with
 * strict=false (bundle parse during verification) the mismatch is left for
 * the verifier's recompute phase to report as an integrity finding.
 */
export function parseBlob(v: Json, field = "/blob", strict = true): BlobT {
  if (!isObj(v)) fail("SCHEMA_INVALID", "Blob must be an object.", field);
  requireFields(v, ["ref", "content"], field);
  const ref = parseObjectRef(v.ref!, `${field}/ref`);
  if (typeof v.content !== "string") fail("SCHEMA_INVALID", "Blob.content must be a string.", `${field}/content`);
  const raw = b64uDecodeStrict(v.content);
  if (raw.byteLength > MAX_OBJECT_BYTES) fail("SCHEMA_INVALID", "Blob exceeds 1 MiB.", `${field}/content`);
  if (strict) {
    if (BigInt(raw.byteLength) !== BigInt(ref.bytes)) fail("HASH_MISMATCH", "Blob length does not match ref.bytes.");
    if (keyIdFromPublic(raw) !== ref.digest) fail("HASH_MISMATCH", "Blob digest does not match ref.digest.");
  }
  return { ref, content: v.content };
}

/**
 * Parse KeyMaterial. strict=true (staging, key files, KeyRotated.next)
 * additionally enforces id = H(public); strict=false (bundle parse) leaves
 * that to the verifier's recompute phase.
 */
export function parseKeyMaterial(v: Json, field = "/key", strict = true): KeyMaterial {
  if (!isObj(v)) fail("SCHEMA_INVALID", "KeyMaterial must be an object.", field);
  requireFields(v, ["id", "public"], field);
  const id = checkHash(v.id!, `${field}/id`);
  if (typeof v.public !== "string") fail("SCHEMA_INVALID", "public must be a string.", `${field}/public`);
  const raw = decodePublicKey(v.public);
  if (strict && keyIdFromPublic(raw) !== id) fail("KEY_MATERIAL_INVALID", "KeyMaterial.id must equal H(public).");
  return { id, public: v.public };
}

export function parseSource(v: Json, field = "/source"): Source {
  if (!isObj(v)) fail("SCHEMA_INVALID", "Source must be an object.", field);
  requireFields(v, ["id", "namespace", "profile"], field);
  return {
    id: checkId(v.id!, `${field}/id`),
    namespace: checkId(v.namespace!, `${field}/namespace`),
    profile: checkEnum(v.profile!, ["proof-evidence/1"] as const, `${field}/profile`),
  };
}

export function parseEventRef(v: Json, field = "/ref"): EventRef {
  if (!isObj(v)) fail("SCHEMA_INVALID", "EventRef must be an object.", field);
  requireFields(v, ["source", "stream", "seq", "hash"], field);
  return {
    source: checkId(v.source!, `${field}/source`),
    stream: checkId(v.stream!, `${field}/stream`),
    seq: checkCount(v.seq!, `${field}/seq`, false),
    hash: checkHash(v.hash!, `${field}/hash`),
  };
}

export function parseCut(v: Json, field = "/cut"): Cut {
  if (!isObj(v)) fail("SCHEMA_INVALID", "Cut must be an object.", field);
  requireFields(v, ["source", "stream", "through", "head"], field);
  const through = checkCount(v.through!, `${field}/through`);
  const head = checkHash(v.head!, `${field}/head`);
  if (through === "0" && head !== ZERO_HASH) fail("SCHEMA_INVALID", "Zero cut requires ZERO head.", field);
  if (through !== "0" && head === ZERO_HASH) fail("SCHEMA_INVALID", "Nonzero cut requires a nonzero head.", field);
  return { source: checkId(v.source!, `${field}/source`), stream: checkId(v.stream!, `${field}/stream`), through, head };
}

export function parseAuditRef(v: Json, field = "/audit"): AuditRef {
  if (!isObj(v)) fail("SCHEMA_INVALID", "AuditRef must be an object.", field);
  requireFields(v, ["seq", "hash"], field);
  return { seq: checkCount(v.seq!, `${field}/seq`), hash: checkHash(v.hash!, `${field}/hash`) };
}

// ---------- event schema ----------

const EVENT_DATA_KINDS = [
  "RunOpened", "StepOpened", "ObservationRecorded", "StepClosed", "DelegationOffered",
  "DelegationAccepted", "EvidenceAttached", "RunClosed", "CorrectionNoted",
] as const;

function eventDataRefs(data: EventData): ObjectRef[] {
  // Object references are exactly those explicitly present in EventData.
  switch (data.kind) {
    case "RunOpened": {
      const refs = [data.intent as ObjectRef];
      if (data.policy !== null) refs.push(data.policy as ObjectRef);
      return refs;
    }
    case "StepOpened": return data.input === null ? [] : [data.input as ObjectRef];
    case "ObservationRecorded": return [data.value as ObjectRef];
    case "EvidenceAttached": return [data.object as ObjectRef];
    case "CorrectionNoted": return [data.replacement as ObjectRef];
    default: return [];
  }
}

export function eventDataObjectRefs(data: EventData): ObjectRef[] {
  return eventDataRefs(data);
}

export function parseEventData(v: Json, field = "/data"): EventData {
  if (!isObj(v)) fail("SCHEMA_INVALID", "EventData must be an object.", field);
  const kind = checkEnum(v.kind!, EVENT_DATA_KINDS, `${field}/kind`);
  switch (kind) {
    case "RunOpened":
      requireFields(v, ["kind", "run", "intent", "policy", "hypothetical"], field);
      checkId(v.run!, `${field}/run`);
      parseObjectRef(v.intent!, `${field}/intent`);
      if (v.policy !== null) parseObjectRef(v.policy!, `${field}/policy`);
      if (typeof v.hypothetical !== "boolean") fail("SCHEMA_INVALID", "hypothetical must be boolean.", `${field}/hypothetical`);
      break;
    case "StepOpened":
      requireFields(v, ["kind", "run", "step", "operation", "input"], field);
      checkId(v.run!, `${field}/run`);
      checkId(v.step!, `${field}/step`);
      checkEnum(v.operation!, OPERATIONS, `${field}/operation`);
      if (v.input !== null) parseObjectRef(v.input!, `${field}/input`);
      break;
    case "ObservationRecorded":
      requireFields(v, ["kind", "run", "step", "value"], field);
      checkId(v.run!, `${field}/run`); checkId(v.step!, `${field}/step`);
      parseObjectRef(v.value!, `${field}/value`);
      break;
    case "StepClosed": {
      requireFields(v, ["kind", "run", "step", "outcome", "observation"], field);
      checkId(v.run!, `${field}/run`); checkId(v.step!, `${field}/step`);
      const outcome = checkEnum(v.outcome!, OUTCOMES, `${field}/outcome`);
      // outcome/observation-null relation is a body-schema rule (§1.2).
      if ((outcome === "SUCCEEDED" || outcome === "FAILED") && v.observation === null) {
        fail("SCHEMA_INVALID", "Success/failure requires an observation reference.", `${field}/observation`);
      }
      if ((outcome === "UNKNOWN" || outcome === "CANCELLED") && v.observation !== null) {
        fail("SCHEMA_INVALID", "Unknown/cancelled requires a null observation.", `${field}/observation`);
      }
      if (v.observation !== null) parseEventRef(v.observation!, `${field}/observation`);
      break;
    }
    case "DelegationOffered": {
      requireFields(v, ["kind", "run", "delegation", "child", "scope"], field);
      checkId(v.run!, `${field}/run`); checkId(v.delegation!, `${field}/delegation`);
      if (!isObj(v.child)) fail("SCHEMA_INVALID", "child must be an object.", `${field}/child`);
      requireFields(v.child, ["source", "stream", "run"], `${field}/child`);
      checkId(v.child.source!, `${field}/child/source`);
      checkId(v.child.stream!, `${field}/child/stream`);
      checkId(v.child.run!, `${field}/child/run`);
      checkHash(v.scope!, `${field}/scope`);
      break;
    }
    case "DelegationAccepted":
      requireFields(v, ["kind", "run", "delegation", "offer", "scope"], field);
      checkId(v.run!, `${field}/run`); checkId(v.delegation!, `${field}/delegation`);
      parseEventRef(v.offer!, `${field}/offer`);
      checkHash(v.scope!, `${field}/scope`);
      break;
    case "EvidenceAttached":
      requireFields(v, ["kind", "run", "step", "format", "object"], field);
      checkId(v.run!, `${field}/run`); checkId(v.step!, `${field}/step`);
      checkEnum(v.format!, FOREIGN_FORMATS, `${field}/format`);
      parseObjectRef(v.object!, `${field}/object`);
      break;
    case "RunClosed":
      requireFields(v, ["kind", "run", "outcome"], field);
      checkId(v.run!, `${field}/run`);
      checkEnum(v.outcome!, OUTCOMES, `${field}/outcome`);
      break;
    case "CorrectionNoted":
      requireFields(v, ["kind", "target", "replacement", "reason"], field);
      parseEventRef(v.target!, `${field}/target`);
      parseObjectRef(v.replacement!, `${field}/replacement`);
      checkEnum(v.reason!, ["SOURCE_ERROR", "DISPUTE"] as const, `${field}/reason`);
      break;
  }
  return v as EventData;
}

export function parseEventBody(v: Json, field = "/body"): EventBody {
  if (!isObj(v)) fail("SCHEMA_INVALID", "EventBody must be an object.", field);
  requireFields(v, ["v", "workspace", "source", "stream", "seq", "prev", "lamport", "key", "parents", "data"], field);
  if (v.v !== 1) fail("UNSUPPORTED_VERSION", "Unsupported event version.", `${field}/v`);
  const body = v as unknown as EventBody;
  checkId(v.workspace!, `${field}/workspace`);
  checkId(v.source!, `${field}/source`);
  checkId(v.stream!, `${field}/stream`);
  checkCount(v.seq!, `${field}/seq`, false); // seq ≥ 1
  checkHash(v.prev!, `${field}/prev`);
  checkCount(v.lamport!, `${field}/lamport`, false);
  checkHash(v.key!, `${field}/key`);
  if (!Array.isArray(v.parents)) fail("SCHEMA_INVALID", "parents must be an array.", `${field}/parents`);
  if (v.parents.length > MAX_PARENTS) fail("SCHEMA_INVALID", "parents exceeds 64.", `${field}/parents`);
  const parents = v.parents.map((p, i) => parseEventRef(p, `${field}/parents/${i}`));
  // Sets arrive sorted and unique: (source,stream,numeric seq,hash).
  for (let i = 1; i < parents.length; i++) {
    if (compareEventRef(parents[i - 1]!, parents[i]!) >= 0) {
      fail("SCHEMA_INVALID", "parents must be sorted and unique.", `${field}/parents`);
    }
  }
  const data = parseEventData(v.data!, `${field}/data`);
  if (eventDataRefs(data).length > MAX_EVENT_OBJECTS) fail("SCHEMA_INVALID", "objects per event exceeds 16.", `${field}/data`);
  body.parents = parents;
  body.data = data;
  return body;
}

export function parseEvent(v: Json, field = "/event"): Event {
  if (!isObj(v)) fail("SCHEMA_INVALID", "Event must be an object.", field);
  requireFields(v, ["body", "hash", "signature"], field);
  const body = parseEventBody(v.body!, `${field}/body`);
  const hash = checkHash(v.hash!, `${field}/hash`);
  if (typeof v.signature !== "string") fail("SCHEMA_INVALID", "signature must be a string.", `${field}/signature`);
  decodeSignature(v.signature);
  const ev: Event = { body, hash, signature: v.signature };
  if (jcsBytes(body).byteLength > MAX_EVENT_CANON) fail("SCHEMA_INVALID", "Canonical event exceeds 64 KiB.", field);
  return ev;
}

// ---------- audit schema ----------

const AUDIT_KINDS = [
  "WorkspaceCreated", "SourceRegistered", "ConfigActivated", "ImportStaged", "ImportCommitted",
  "ImportCancelled", "DisclosureRecorded", "VerificationRecorded", "KeyRotated", "MigrationActivated",
] as const;

export const DISCLOSURE_METHODS = [
  "source.list", "revision.get", "lineage.get", "bundle.export", "object.get", "audit.export",
] as const;

export function parseAuditData(v: Json, field = "/data"): AuditData {
  if (!isObj(v)) fail("SCHEMA_INVALID", "AuditData must be an object.", field);
  const kind = checkEnum(v.kind!, AUDIT_KINDS, `${field}/kind`);
  switch (kind) {
    case "WorkspaceCreated":
      requireFields(v, ["kind", "config", "revision", "evidence"], field);
      checkHash(v.config!, `${field}/config`);
      if (v.revision !== "0") fail("SCHEMA_INVALID", "WorkspaceCreated revision must be \"0\".", `${field}/revision`);
      checkHash(v.evidence!, `${field}/evidence`);
      break;
    case "SourceRegistered":
      requireFields(v, ["kind", "source", "revision", "evidence"], field);
      parseSource(v.source!, `${field}/source`);
      checkCount(v.revision!, `${field}/revision`, false);
      checkHash(v.evidence!, `${field}/evidence`);
      break;
    case "ConfigActivated":
      requireFields(v, ["kind", "previous", "config"], field);
      checkHash(v.previous!, `${field}/previous`); checkHash(v.config!, `${field}/config`);
      break;
    case "ImportStaged":
      requireFields(v, ["kind", "stage", "batch"], field);
      checkId(v.stage!, `${field}/stage`); checkHash(v.batch!, `${field}/batch`);
      break;
    case "ImportCommitted":
      requireFields(v, ["kind", "stage", "batch", "revision", "evidence"], field);
      checkId(v.stage!, `${field}/stage`); checkHash(v.batch!, `${field}/batch`);
      checkCount(v.revision!, `${field}/revision`, false); checkHash(v.evidence!, `${field}/evidence`);
      break;
    case "ImportCancelled":
      requireFields(v, ["kind", "stage", "reason"], field);
      checkId(v.stage!, `${field}/stage`);
      checkEnum(v.reason!, ["USER", "EXPIRED"] as const, `${field}/reason`);
      break;
    case "DisclosureRecorded":
      requireFields(v, ["kind", "method", "content", "revision"], field);
      checkEnum(v.method!, DISCLOSURE_METHODS, `${field}/method`);
      checkHash(v.content!, `${field}/content`);
      if (v.revision !== null) checkCount(v.revision!, `${field}/revision`, false);
      break;
    case "VerificationRecorded":
      requireFields(v, ["kind", "bundle", "trust", "report"], field);
      checkHash(v.bundle!, `${field}/bundle`); checkHash(v.trust!, `${field}/trust`); checkHash(v.report!, `${field}/report`);
      break;
    case "KeyRotated":
      requireFields(v, ["kind", "old", "next", "proof"], field);
      checkHash(v.old!, `${field}/old`);
      parseKeyMaterial(v.next!, `${field}/next`);
      if (typeof v.proof !== "string") fail("SCHEMA_INVALID", "proof must be a string.", `${field}/proof`);
      decodeSignature(v.proof);
      break;
    case "MigrationActivated":
      requireFields(v, ["kind", "manifest", "from_schema", "to_schema"], field);
      checkHash(v.manifest!, `${field}/manifest`);
      if (!Number.isSafeInteger(v.from_schema) || !Number.isSafeInteger(v.to_schema)) {
        fail("SCHEMA_INVALID", "schema versions must be safe integers.", field);
      }
      break;
  }
  return v as AuditData;
}

export function parseAuditBody(v: Json, field = "/body"): AuditBody {
  if (!isObj(v)) fail("SCHEMA_INVALID", "AuditBody must be an object.", field);
  requireFields(v, ["v", "workspace", "seq", "prev", "key", "principal", "request", "data"], field);
  if (v.v !== 1) fail("UNSUPPORTED_VERSION", "Unsupported audit version.", `${field}/v`);
  checkId(v.workspace!, `${field}/workspace`);
  checkCount(v.seq!, `${field}/seq`, false);
  checkHash(v.prev!, `${field}/prev`);
  checkHash(v.key!, `${field}/key`);
  checkId(v.principal!, `${field}/principal`);
  checkId(v.request!, `${field}/request`);
  const body = v as unknown as AuditBody;
  body.data = parseAuditData(v.data!, `${field}/data`);
  return body;
}

export function parseAudit(v: Json, field = "/audit"): Audit {
  if (!isObj(v)) fail("SCHEMA_INVALID", "Audit must be an object.", field);
  requireFields(v, ["body", "hash", "signature"], field);
  const body = parseAuditBody(v.body!, `${field}/body`);
  const hash = checkHash(v.hash!, `${field}/hash`);
  if (typeof v.signature !== "string") fail("SCHEMA_INVALID", "signature must be a string.", `${field}/signature`);
  decodeSignature(v.signature);
  const a: Audit = { body, hash, signature: v.signature };
  if (jcsBytes(body).byteLength > MAX_AUDIT_CANON) fail("SCHEMA_INVALID", "Canonical audit entry exceeds 4 KiB.", field);
  return a;
}

// ---------- trust ----------

export function parseTrust(v: Json, field = ""): Trust {
  if (!isObj(v)) fail("TRUST_INVALID", "Trust must be an object.");
  requireFields(v, ["v", "workspace", "keys", "heads", "valid_until_unix_ms"]);
  if (v.v !== 1) fail("UNSUPPORTED_VERSION", "Unsupported trust version.", "/v");
  checkId(v.workspace!, "/workspace");
  if (!Array.isArray(v.keys) || !Array.isArray(v.heads)) fail("TRUST_INVALID", "keys/heads must be arrays.");
  const keys = v.keys.map((k, i) => parseKeyPin(k, `/keys/${i}`));
  const heads = v.heads.map((h, i) => parseHeadPin(h, `/heads/${i}`));
  if (v.valid_until_unix_ms !== null) checkCount(v.valid_until_unix_ms!, "/valid_until_unix_ms");
  return { v: 1, workspace: v.workspace as string, keys, heads, valid_until_unix_ms: v.valid_until_unix_ms as string | null };
}

function parseKeyPin(v: Json, field: string): KeyPin {
  if (!isObj(v)) fail("TRUST_INVALID", "KeyPin must be an object.");
  requireFields(v, ["key", "role", "source", "stream", "first", "last", "status"], field);
  const pin: KeyPin = {
    key: checkHash(v.key!, `${field}/key`),
    role: checkEnum(v.role!, KEY_ROLES, `${field}/role`),
    source: v.source === null ? null : checkId(v.source!, `${field}/source`),
    stream: v.stream === null ? null : checkId(v.stream!, `${field}/stream`),
    first: checkCount(v.first!, `${field}/first`, false),
    last: checkCount(v.last!, `${field}/last`),
    status: checkEnum(v.status!, KEY_STATUS, `${field}/status`),
  };
  if (pin.role === "origin" && (pin.source === null || pin.stream === null)) fail("TRUST_INVALID", "Origin pins require source and stream.");
  if (pin.role === "audit" && (pin.source !== null || pin.stream !== null)) fail("TRUST_INVALID", "Audit pins require null scope.");
  if (BigInt(pin.first) > BigInt(pin.last)) fail("TRUST_INVALID", "Key interval first must be ≤ last.");
  return pin;
}

function parseHeadPin(v: Json, field: string): HeadPin {
  if (!isObj(v)) fail("TRUST_INVALID", "HeadPin must be an object.");
  requireFields(v, ["role", "source", "stream", "seq", "hash"], field);
  const pin: HeadPin = {
    role: checkEnum(v.role!, KEY_ROLES, `${field}/role`),
    source: v.source === null ? null : checkId(v.source!, `${field}/source`),
    stream: v.stream === null ? null : checkId(v.stream!, `${field}/stream`),
    seq: checkCount(v.seq!, `${field}/seq`),
    hash: checkHash(v.hash!, `${field}/hash`),
  };
  if (pin.role === "origin" && (pin.source === null || pin.stream === null)) fail("TRUST_INVALID", "Origin heads require source and stream.");
  if (pin.role === "audit" && (pin.source !== null || pin.stream !== null)) fail("TRUST_INVALID", "Audit heads require null scope.");
  if (pin.seq === "0" && pin.hash !== ZERO_HASH) fail("TRUST_INVALID", "Head sequence zero requires ZERO.");
  if (pin.seq !== "0" && pin.hash === ZERO_HASH) fail("TRUST_INVALID", "Nonzero heads require nonzero hashes.");
  return pin;
}

export function parseVerifyOptions(v: Json, field = "/options"): VerifyOptions {
  if (!isObj(v)) fail("SCHEMA_INVALID", "VerifyOptions must be an object.", field);
  requireFields(v, ["requirement", "as_of_unix_ms"], field);
  return {
    requirement: checkEnum(v.requirement!, REQUIREMENTS, `${field}/requirement`),
    as_of_unix_ms: checkCount(v.as_of_unix_ms!, `${field}/as_of_unix_ms`),
  };
}

// ---------- batch / bundle ----------

export function parseBatch(v: Json, field = "/batch"): Batch {
  if (!isObj(v)) fail("SCHEMA_INVALID", "Batch must be an object.", field);
  requireFields(v, ["events", "keys", "objects"], field);
  if (!Array.isArray(v.events) || !Array.isArray(v.keys) || !Array.isArray(v.objects)) {
    fail("SCHEMA_INVALID", "Batch members must be arrays.", field);
  }
  const events = v.events.map((e, i) => parseEvent(e, `${field}/events/${i}`));
  const keys = v.keys.map((k, i) => parseKeyMaterial(k, `${field}/keys/${i}`));
  const objects = v.objects.map((o, i) => parseBlob(o, `${field}/objects/${i}`));
  const dup = (arr: string[]) => new Set(arr).size !== arr.length;
  if (dup(events.map((e) => e.hash))) fail("SCHEMA_INVALID", "Duplicate event in batch.", `${field}/events`);
  if (dup(keys.map((k) => k.id))) fail("SCHEMA_INVALID", "Duplicate key in batch.", `${field}/keys`);
  if (dup(objects.map((o) => o.ref.digest))) fail("SCHEMA_INVALID", "Duplicate object in batch.", `${field}/objects`);
  return { events, keys, objects };
}

export function parseInventoryItem(v: Json, field = "/inventory"): InventoryItem {
  if (!isObj(v)) fail("SCHEMA_INVALID", "InventoryItem must be an object.", field);
  requireFields(v, ["kind", "digest", "bytes", "availability"], field);
  const item: InventoryItem = {
    kind: checkEnum(v.kind!, ["event", "audit", "key", "object"] as const, `${field}/kind`),
    digest: checkHash(v.digest!, `${field}/digest`),
    bytes: checkCount(v.bytes!, `${field}/bytes`),
    availability: checkEnum(v.availability!, AVAILABILITY, `${field}/availability`),
  };
  if (item.kind !== "object" && item.availability !== "INCLUDED") {
    fail("SCHEMA_INVALID", "Only object entries may be WITHHELD or UNAVAILABLE.", `${field}/availability`);
  }
  return item;
}

export function parseBundleBody(v: Json, field = "/body"): BundleBody {
  if (!isObj(v)) fail("SCHEMA_INVALID", "BundleBody must be an object.", field);
  requireFields(v, ["v", "format", "workspace", "revision", "sources", "actions", "cuts", "evidence", "projection", "inventory", "disclosure", "audit_through"], field);
  if (v.v !== 1) fail("UNSUPPORTED_VERSION", "Unsupported bundle version.", `${field}/v`);
  checkEnum(v.format!, ["proof-bundle/1"] as const, `${field}/format`);
  const body = v as unknown as BundleBody;
  checkId(v.workspace!, `${field}/workspace`);
  checkCount(v.revision!, `${field}/revision`);
  if (!Array.isArray(v.sources)) fail("SCHEMA_INVALID", "sources must be an array.", `${field}/sources`);
  body.sources = v.sources.map((s, i) => parseSource(s, `${field}/sources/${i}`));
  if (!Array.isArray(v.actions)) fail("SCHEMA_INVALID", "actions must be an array.", `${field}/actions`);
  if (v.actions.length === 0) fail("REQUEST_INVALID", "Empty action list.", `${field}/actions`);
  body.actions = v.actions.map((a, i) => parseEventRef(a, `${field}/actions/${i}`));
  if (!Array.isArray(v.cuts)) fail("SCHEMA_INVALID", "cuts must be an array.", `${field}/cuts`);
  body.cuts = v.cuts.map((c, i) => parseCut(c, `${field}/cuts/${i}`));
  checkHash(v.evidence!, `${field}/evidence`);
  checkHash(v.projection!, `${field}/projection`);
  if (!Array.isArray(v.inventory)) fail("SCHEMA_INVALID", "inventory must be an array.", `${field}/inventory`);
  if (v.inventory.length > MAX_INVENTORY) fail("BUNDLE_LIMIT", "Inventory exceeds cap.", `${field}/inventory`);
  body.inventory = v.inventory.map((it, i) => parseInventoryItem(it, `${field}/inventory/${i}`));
  checkEnum(v.disclosure!, DISCLOSURES, `${field}/disclosure`);
  body.audit_through = parseAuditRef(v.audit_through!, `${field}/audit_through`);
  return body;
}

export function parseBundle(v: Json, field = ""): Bundle {
  if (!isObj(v)) fail("SCHEMA_INVALID", "Bundle must be an object.", field || "/bundle");
  requireFields(v, ["body", "hash", "events", "keys", "audit", "objects"], field);
  const body = parseBundleBody(v.body!, `${field}/body`);
  const hash = checkHash(v.hash!, `${field}/hash`);
  if (!Array.isArray(v.events) || !Array.isArray(v.keys) || !Array.isArray(v.audit) || !Array.isArray(v.objects)) {
    fail("SCHEMA_INVALID", "Bundle members must be arrays.", field);
  }
  if (v.events.length > MAX_BUNDLE_EVENTS) fail("BUNDLE_LIMIT", "Bundle events exceed cap.", `${field}/events`);
  if (v.audit.length > MAX_AUDIT_ENTRIES) fail("BUNDLE_LIMIT", "Bundle audit exceeds cap.", `${field}/audit`);
  if (v.objects.length > MAX_INVENTORY) fail("BUNDLE_LIMIT", "Bundle objects exceed cap.", `${field}/objects`);
  const b: Bundle = {
    body, hash,
    events: v.events.map((e, i) => parseEvent(e, `${field}/events/${i}`)),
    keys: v.keys.map((k, i) => parseKeyMaterial(k, `${field}/keys/${i}`, false)),
    audit: v.audit.map((a, i) => parseAudit(a, `${field}/audit/${i}`)),
    objects: v.objects.map((o, i) => parseBlob(o, `${field}/objects/${i}`, false)),
  };
  if (jcsBytes(b).byteLength > MAX_BUNDLE_BYTES) fail("BUNDLE_LIMIT", "Canonical bundle exceeds 64 MiB.", field);
  return b;
}

export function parseLineageRequest(v: Json, field = ""): LineageRequest {
  if (!isObj(v)) fail("SCHEMA_INVALID", "LineageRequest must be an object.", field);
  requireFields(v, ["revision", "actions", "max_nodes", "max_depth"], field);
  const req = v as unknown as LineageRequest;
  checkCount(v.revision!, `${field}/revision`);
  if (!Array.isArray(v.actions)) fail("SCHEMA_INVALID", "actions must be an array.", `${field}/actions`);
  req.actions = v.actions.map((a, i) => parseEventRef(a, `${field}/actions/${i}`));
  for (const k of ["max_nodes", "max_depth"] as const) {
    if (!Number.isSafeInteger(v[k])) fail("SCHEMA_INVALID", `${k} must be an integer.`, `${field}/${k}`);
  }
  if (req.max_nodes < 1 || req.max_nodes > MAX_LINEAGE_NODES) fail("SCHEMA_INVALID", "max_nodes out of range.", `${field}/max_nodes`);
  if (req.max_depth < 1 || req.max_depth > MAX_LINEAGE_DEPTH) fail("SCHEMA_INVALID", "max_depth out of range.", `${field}/max_depth`);
  return req;
}

// ---------- ordering ----------

export function cmpStr(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

export function compareEventRef(a: EventRef, b: EventRef): number {
  return cmpStr(a.source, b.source) || cmpStr(a.stream, b.stream)
    || (BigInt(a.seq) < BigInt(b.seq) ? -1 : BigInt(a.seq) > BigInt(b.seq) ? 1 : 0)
    || cmpStr(a.hash, b.hash);
}

export function eventRefOf(e: Event): EventRef {
  return { source: e.body.source, stream: e.body.stream, seq: e.body.seq, hash: e.hash };
}

export function eventNode(e: Event): Node {
  return { type: "event", ref: eventRefOf(e) };
}

export function objectNode(ref: ObjectRef, at: Event): Node {
  return { type: "object", ref, at: eventRefOf(at) };
}

export function auditRefOf(a: Audit): AuditRef {
  return { seq: a.body.seq, hash: a.hash };
}

export function sameEventRef(a: EventRef, b: EventRef): boolean {
  return a.source === b.source && a.stream === b.stream && a.seq === b.seq && a.hash === b.hash;
}

export function slotKey(source: string, stream: string, seq: string): string {
  return `${source}\0${stream}\0${BigInt(seq).toString(10).padStart(20, "0")}`;
}
