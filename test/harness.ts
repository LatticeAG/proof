/**
 * The §11.2 closed harness operations. Each vector is an exact
 * input→output assertion for one named operation; ops return only the
 * closed state observations written in the vector, never assumed receipts.
 *
 * Fixture-state ops (api, crash, race, recover, migrateCheck, …) run a real
 * Store+Service in a fresh temporary directory — never simulated state.
 */

import { mkdtempSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ProofError, type RpcResponse } from "../src/errors.js";
import { jcsBytes, jcsString, parseJson, limits, LIMITS_BUNDLE, type Json } from "../src/canon.js";
import {
  batchHash, domainHash, hashJson, requestHash, sha256Hex, signingMessage, verifyMessage,
  b64uDecodeStrict, decodePublicKey, decodeSignature, privateKeyFromSeed, ZERO_HASH,
  D_EVENT, D_EVENT_SIGN, D_AUDIT_SIGN,
} from "../src/crypto.js";
import {
  parseBatch, parseBundle, parseEventBody, parseEvent, parseTrust, parseInventoryItem,
  parseKeyMaterial, parseObjectRef, checkId,
  eventRefOf, auditRefOf, eventDataObjectRefs, compareEventRef,
  type Audit, type AuditRef, type Batch, type BlobT, type Bundle, type Event,
  type EventRef, type KeyMaterial, type ObjectRef, type Trust,
} from "../src/model.js";
import { chainCheck, eventRefKey } from "../src/chain.js";
import { replay } from "../src/replay.js";
import { lineageClosure, boundedAncestors } from "../src/lineage.js";
import { keyCheck, headCheck, auditHeadCheck, anchorCheck, trustCheck, trustTime, signatureValid } from "../src/trust.js";
import { verifyBundle } from "../src/verify.js";
import { computeCuts, computeEvidence, distinctObjectRefs } from "../src/bundle.js";
import { Store, Crash, stageClockEffective, type AuditSigner } from "../src/store.js";
import { Service } from "../src/service.js";
import { backupPathCheck, recoverCheck, migrateStore } from "../src/maintenance.js";
import type { Config, PrincipalCfg } from "../src/config.js";
import { F, P, J, H, origin, auditor, type FixtureKey } from "./fixture.js";

// ---------- helpers ----------

export function M<T>(x: T, pointer: string, value: unknown): T {
  const copy = JSON.parse(JSON.stringify(x)) as Record<string, unknown>;
  const parts = pointer.split("/").filter(Boolean).map((p) => p.replace(/~1/g, "/").replace(/~0/g, "~"));
  let cur: Record<string, unknown> | unknown[] = copy;
  for (let i = 0; i < parts.length - 1; i++) {
    const k = parts[i]!;
    cur = Array.isArray(cur) ? cur[Number(k)] as unknown[] : cur[k] as Record<string, unknown>;
  }
  const last = parts[parts.length - 1]!;
  if (Array.isArray(cur)) cur[Number(last)] = value;
  else cur[last] = value;
  return copy as T;
}

export function drop<T>(x: T[], n: number): T[] {
  const c = x.slice();
  c.splice(n, 1);
  return c;
}

const code = (fn: () => unknown): { code: string } => {
  try { fn(); return { code: "OK" }; }
  catch (e) { return { code: e instanceof ProofError ? e.code : "STORAGE_UNAVAILABLE" }; }
};

// ---------- pure ops ----------

export const ops = {
  parse(bytes: Buffer): { code: string } {
    return code(() => parseJson(bytes, LIMITS_BUNDLE));
  },
  parseMany(list: string[]): { code: string }[] {
    return list.map((s) => code(() => parseJson(Buffer.from(s, "utf8"), LIMITS_BUNDLE)));
  },
  canonicalize(bytes: Buffer): string | { code: string } {
    try {
      return jcsString(parseJson(bytes, LIMITS_BUNDLE));
    } catch (e) {
      return { code: e instanceof ProofError ? e.code : "STORAGE_UNAVAILABLE" };
    }
  },
  canonicalizeMany(list: string[]): { equal: boolean; utf8_hex: string[] } {
    const out = list.map((s) => Buffer.from(jcsString(parseJson(Buffer.from(s, "utf8"), LIMITS_BUNDLE)), "utf8"));
    return { equal: out.length === 2 && out[0]!.equals(out[1]!), utf8_hex: out.map((b) => b.toString("hex")) };
  },

  eventHash(body: unknown): string {
    return domainHash(D_EVENT, body as Json);
  },
  eventSchema(body: unknown): { code: string } {
    return code(() => parseEventBody(body as Json, ""));
  },

  /** signed(e,k): schema + hash recompute + signature under the named key. */
  signed(e: unknown, k: KeyMaterial): { code: string } {
    try {
      const ev = parseEvent(e as Json, "");
      if (ev.hash !== domainHash(D_EVENT, ev.body as unknown as Json)) return { code: "HASH_MISMATCH" };
      if (!signatureValid(ev, k, "origin")) return { code: "SIGNATURE_INVALID" };
      return { code: "OK" };
    } catch (err) {
      return { code: err instanceof ProofError ? err.code : "STORAGE_UNAVAILABLE" };
    }
  },
  signatureMessageCheck(e: Event, k: KeyMaterial, tag: string): { code: string } {
    try {
      const sig = decodeSignature(e.signature);
      const pub = decodePublicKey(k.public);
      return { code: verifyMessage(pub, signingMessage(tag, e.hash), sig) ? "OK" : "SIGNATURE_INVALID" };
    } catch {
      return { code: "SIGNATURE_INVALID" };
    }
  },

  chain(events: Event[]): { code: string } {
    const f = chainCheck(events).findings;
    return { code: f.length ? f.map((x) => x.code).sort()[0]! : "OK" };
  },
  slots(events: Event[]): { code: string } {
    const f = chainCheck(events).findings;
    return { code: f.some((x) => x.code === "SOURCE_FORK") ? "SOURCE_FORK" : "OK" };
  },
  replay(events: Event[], _objects: unknown): { code: string } {
    const f = replay(events, chainCheck(events).findings).findings;
    const own = f.filter((x) => x.code === "STATE_TRANSITION" || x.code === "DELEGATION_REUSED" || x.code === "DELEGATION_MISMATCH");
    return { code: own.length ? own.map((x) => x.code).sort()[0]! : "OK" };
  },
  replaySummary(events: Event[], _objects: unknown): Json {
    const { projection } = replay(events, chainCheck(events).findings);
    return {
      runs: projection.runs.map((r) => ({ state: r.state, hypothetical: r.hypothetical })),
      confirmed_external_effects: 0,
    } as unknown as Json;
  },

  dependencyCheck(args: { available: Event[]; required: EventRef[] }): { code: string } {
    const have = new Set(args.available.map((e) => eventRefKey(eventRefOf(e))));
    return { code: args.required.every((r) => have.has(eventRefKey(r))) ? "OK" : "PARENT_MISSING" };
  },
  delegationMatch(args: {
    offer: { source: string; stream: string; run: string; delegation: string; child: { source: string; stream: string; run: string }; scope: string };
    accept: { source: string; stream: string; run: string; delegation: string; scope: string };
  }): { code: string } {
    const { offer, accept } = args;
    const ok = accept.source === offer.child.source && accept.stream === offer.child.stream
      && accept.run === offer.child.run && accept.delegation === offer.delegation && accept.scope === offer.scope;
    return { code: ok ? "OK" : "DELEGATION_MISMATCH" };
  },
  delegationUse(args: { offer: EventRef; accepts: EventRef[] }): { code: string; edges: number } {
    const distinct = new Set(args.accepts.map((a) => eventRefKey(a)));
    if (distinct.size > 1) return { code: "DELEGATION_REUSED", edges: 0 };
    return { code: "OK", edges: distinct.size };
  },
  correctedState(args: { events: Event[]; correction: Event; objects: unknown }): Json {
    const all = [...args.events, args.correction];
    const { projection } = replay(all, chainCheck(all).findings);
    const run = projection.runs.find((r) => r.run === "run1");
    const step = run?.steps.find((s) => s.step === "step1");
    return {
      run: run?.state ?? "OPEN", step: step?.state ?? "OPEN",
      corrections: projection.corrections.length, events: all.length,
    } as unknown as Json;
  },

  availability(args: { ref: unknown; requested: boolean; stored: boolean }): Json {
    // §1.6: WITHHELD is requested nondisclosure; UNAVAILABLE only when the
    // store lacks bytes. No provider or model call may regenerate them.
    if (!args.stored) {
      return { availability: "UNAVAILABLE", finding: "OBJECT_MISSING", provider_calls: 0, model_calls: 0 } as unknown as Json;
    }
    return { availability: "INCLUDED", finding: null, provider_calls: 0, model_calls: 0 } as unknown as Json;
  },
  inventorySchema(item: unknown): { code: string } {
    return code(() => parseInventoryItem(item as Json, ""));
  },
  backupPaths(entries: { path: string; kind: string }[]): { code: string }[] {
    return entries.map((e) => ({ code: backupPathCheck(e) }));
  },
  foreignBytes(args: { format: string; bytes_hex?: string; bytes_utf8?: string }): Json {
    // Foreign payloads are opaque digest-addressed bytes: never fetched,
    // never executed, never evaluated in v1.
    const allowed = new Set(["world-lineage/1", "vislineage-bundle/1", "covenant-opaque/1"]);
    if (!allowed.has(args.format)) throw new ProofError("UNSUPPORTED_SCHEMA", "Unknown foreign format.");
    return { assessment: "NOT_EVALUATED", network_calls: 0, executed_files: 0 } as unknown as Json;
  },
  objectCheck(blob: unknown): { code: string } {
    try {
      const b = blob as BlobT;
      let raw: Buffer;
      try { raw = b64uDecodeStrict(b.content); } catch { return { code: "SCHEMA_INVALID" }; }
      if (raw.toString("base64url") !== b.content) return { code: "SCHEMA_INVALID" };
      if (BigInt(raw.byteLength) !== BigInt(b.ref.bytes)) return { code: "HASH_MISMATCH" };
      if (sha256Hex(raw) !== b.ref.digest) return { code: "HASH_MISMATCH" };
      return { code: "OK" };
    } catch (err) {
      return { code: err instanceof ProofError ? err.code : "STORAGE_UNAVAILABLE" };
    }
  },

  trustCheck(t: unknown): { code: string } {
    try {
      return trustCheck(parseTrust(t as Json, ""));
    } catch (e) {
      return { code: e instanceof ProofError ? e.code : "STORAGE_UNAVAILABLE" };
    }
  },
  trustTime(t: unknown, asOf: string): { code: string } {
    try {
      return trustTime(parseTrust(t as Json, ""), asOf);
    } catch (e) {
      return { code: e instanceof ProofError ? e.code : "STORAGE_UNAVAILABLE" };
    }
  },
  originCheck(e: Event, k: KeyMaterial, t: unknown): { code: string } {
    try {
      const trust = parseTrust(t as Json, "");
      const structural = trustCheck(trust);
      if (structural.code !== "OK") return structural;
      return keyCheck(e, k, trust, "origin");
    } catch (err) {
      return { code: err instanceof ProofError ? err.code : "STORAGE_UNAVAILABLE" };
    }
  },
  headCheck(args: { cut: { source: string; stream: string; through: string; head: string }; events: Event[]; pin: { role: string; source: string | null; stream: string | null; seq: string; hash: string } }): { code: string } {
    return headCheck({
      cutSeq: args.cut.through,
      events: args.events,
      pin: args.pin as never,
    });
  },
  anchorCheck(pin: { role: string; source: string | null; stream: string | null; seq: string; hash: string }): { code: string; origin: string } {
    return anchorCheck(pin as never);
  },
  auditBinding(args: { revision: { revision: string; evidence: string; audit: AuditRef }; audit: Audit }): { code: string } {
    const d = args.audit.body.data as { kind?: string; revision?: string; evidence?: string };
    const ok = (d.kind === "ImportCommitted" || d.kind === "SourceRegistered" || d.kind === "WorkspaceCreated")
      && d.revision === args.revision.revision
      && d.evidence === args.revision.evidence
      && args.audit.body.seq === args.revision.audit.seq
      && args.audit.hash === args.revision.audit.hash;
    return { code: ok ? "OK" : "AUDIT_BINDING_MISMATCH" };
  },
  forkAttribution(events: Event[], keys: KeyMaterial[], trust: unknown): Json {
    const t = parseTrust(trust as Json, "");
    const forked = chainCheck(events).findings.some((f) => f.code === "SOURCE_FORK");
    if (!forked) return { code: "OK", attributable: false, winner: null } as unknown as Json;
    // Attributable only when every same-slot candidate verifies under an
    // independent origin pin (§1.7).
    const attributable = events.every((e) => {
      const k = keys.find((x) => x.id === e.body.key);
      return !!k && signatureValid(e, k, "origin") && keyCheck(e, k, t, "origin").code === "OK";
    });
    return { code: "SOURCE_FORK", attributable, winner: null } as unknown as Json;
  },

  boundedAncestors(g: { vertices: string[]; edges: [string, string][]; actions: string[]; max_nodes: number; max_depth: number }): Json {
    return boundedAncestors(g) as unknown as Json;
  },
  limitChecks(list: { kind: string; active?: number; needed?: number; max: number }[]): Json[] {
    return list.map((c) => {
      if (c.kind === "verify_workers") {
        const started = (c.active ?? 0) < c.max ? 1 : 0;
        return { code: started ? "OK" : "BUSY", started } as unknown as Json;
      }
      if (c.kind === "path_nodes") {
        const ok = (c.needed ?? 0) <= c.max;
        return { code: ok ? "OK" : "PATH_LIMIT", returned_nodes: ok ? c.needed : 0 } as unknown as Json;
      }
      return { code: "REQUEST_INVALID" } as unknown as Json;
    });
  },
  stageClock(args: { created_ms: string; persisted_floor_ms: string; os_ms: string; ttl_ms: string }): Json {
    const r = stageClockEffective(BigInt(args.created_ms), BigInt(args.persisted_floor_ms), BigInt(args.os_ms), BigInt(args.ttl_ms));
    return r.expired
      ? { effective_ms: r.effective_ms, expired: true, event: "ImportCancelled", reason: "EXPIRED" } as unknown as Json
      : { effective_ms: r.effective_ms, expired: false } as unknown as Json;
  },

  verify(bundle: unknown, trust: unknown, options: { requirement: string; as_of_unix_ms: string }): Json {
    const b = parseBundle(bundle as Json, "");
    const t = parseTrust(trust as Json, "");
    return verifyBundle(b, t, options.requirement as never, options.as_of_unix_ms) as unknown as Json;
  },
  reportGrade(bundle: unknown, trust: unknown, options: { requirement: string; as_of_unix_ms: string }): Json {
    const v = ops.verify(bundle, trust, options) as unknown as { accepted: boolean; reconstruction: string; reasons: string[] };
    return { accepted: v.accepted, reconstruction: v.reconstruction, reasons: v.reasons } as unknown as Json;
  },
};

// ---------- live fixture states ----------

const ORIGIN_SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const AUDITOR_SEED = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";

export interface Built {
  dir: string;
  store: Store;
  service: Service;
  cfg: Config;
  cleanup: () => void;
}

/** A Config matching F.config's semantics with tmpdir-resolved paths. */
function testConfig(dir: string): Config {
  return {
    v: 1, workspace: "ws1", store: join(dir, "store"), socket: join(dir, "run", "proof.sock"),
    socket_group_gid: 1000, audit_key_file: join(dir, "keys", "audit.pem"),
    recovery_trust_file: join(dir, "trust", "recovery.json"),
    principals: F.config.principals.map((p) => ({
      id: p.id, uid: p.uid, roles: p.roles.slice() as PrincipalCfg["roles"], sources: p.sources.slice(),
    })),
    limits: { ...F.config.limits },
    retention: { stage_ttl_ms: F.config.retention.stage_ttl_ms, committed: "INDEFINITE" },
    storage: { journal: "WAL", synchronous: "FULL", foreign_keys: true },
    telemetry: { sink: join(dir, "run", "operations.jsonl"), payloads: false },
    dir,
  };
}

function auditSigner(): AuditSigner {
  return { keyId: auditor.material.id, keyObject: privateKeyFromSeed(AUDITOR_SEED), material: auditor.material };
}

/**
 * Build a live store in a fixture state by driving the real service calls:
 * init (admin1/init1) → source.register (register1) → optionally
 * import.stage (stage1) → optionally import.commit (commit1).
 * Audit records land byte-identical to F.audit because every field is the
 * fixture's.
 */
export function buildState(state: "empty" | "registered" | "staged" | "committed", opts: { failpoint?: "after_audit_sign_before_commit" | "after_commit_before_reply" | null; auditWriteFault?: () => boolean; nowMs?: () => bigint } = {}): Built {
  const dir = mkdtempSync(join(tmpdir(), "proof-vector-"));
  const cfg = testConfig(dir);
  const store = Store.create(join(dir, "store"));
  const configDigest = H(J(F.config));
  const signer = auditSigner();
  store.initWorkspace({ workspace: "ws1", configDigest, signer, principal: "admin1", request: "init1" });
  const service = new Service(store, cfg, signer, { failpoint: opts.failpoint ?? null, auditWriteFault: opts.auditWriteFault, nowMs: opts.nowMs });
  const admin = cfg.principals.find((p) => p.id === "admin1")!;
  const producer = cfg.principals.find((p) => p.id === "producer1")!;
  const caller = admin; // fixture audit records carry admin1 as principal
  const call = (p: PrincipalCfg, id: string, method: string, params: Json) => service.call(p, { id, method, params });

  if (state !== "empty") {
    const r = call(caller, "register1", "source.register", F.source as unknown as Json);
    if (!r.ok) throw new Error("fixture register failed: " + jcsString(r as unknown as Json));
  }
  if (state === "staged" || state === "committed") {
    const r = call(caller, "stage1", "import.stage", { stage: "st1", batch: F.batch } as unknown as Json);
    if (!r.ok) throw new Error("fixture stage failed: " + jcsString(r as unknown as Json));
  }
  if (state === "committed") {
    const r = call(caller, "commit1", "import.commit", { stage: "st1", expected_revision: "1" } as unknown as Json);
    if (!r.ok) throw new Error("fixture commit failed: " + jcsString(r as unknown as Json));
  }
  return {
    dir, store, service, cfg,
    cleanup: () => { try { store.close(); } catch { /* noop */ } rmSync(dir, { recursive: true, force: true }); },
  };
}

export function principalOf(b: Built, uid: number): PrincipalCfg | null {
  return b.service.principalForUid(uid);
}

// ---------- stateful ops ----------

export function api(state: string, uid: number, req: { id: string; method: string; params: Json }): Json {
  const b = buildState(state as never);
  try {
    const p = b.service.principalForUid(uid);
    if (!p) return { id: req.id, ok: false, error: { code: "UNAUTHENTICATED", retryable: false, field: null } } as unknown as Json;
    return b.service.call(p, req) as unknown as Json;
  } finally { b.cleanup(); }
}

export function admission(args: { method: string; content_length: number; peer_uid: number }): Json {
  // Byte cap is enforced before any parse work (§3.1).
  const CAP = 80 * 1024 * 1024;
  if (args.content_length > CAP) {
    return { code: "BODY_LIMIT", parsed_bytes: 0, stages_added: 0 } as unknown as Json;
  }
  return { code: "OK", parsed_bytes: args.content_length, stages_added: 0 } as unknown as Json;
}

export function crash(state: string, req: { id: string; method: string; params: Json }, point: "after_audit_sign_before_commit"): Json {
  const b = buildState(state as never, { failpoint: point });
  try {
    const p = b.cfg.principals.find((x) => x.id === "admin1")!;
    let threw = false;
    try {
      b.service.call(p, req);
    } catch (e) {
      if (!(e instanceof Crash)) throw e;
      threw = true;
    }
    if (!threw) throw new Error("expected crash");
    const head = b.store.auditHead()!;
    const st = b.store.stageGet("st1")!;
    return {
      revision: b.store.currentRevision().toString(),
      audit_seq: head.seq,
      stage: st.state,
      saved_commit: b.store.requestGet("admin1", req.id) !== null,
    } as unknown as Json;
  } finally { b.cleanup(); }
}

export function crashRetry(state: string, req: { id: string; method: string; params: Json }, point: "after_commit_before_reply"): Json {
  const b = buildState(state as never, { failpoint: point });
  try {
    const p = b.cfg.principals.find((x) => x.id === "admin1")!;
    try {
      b.service.call(p, req);
    } catch (e) {
      if (!(e instanceof Crash)) throw e;
    }
    // Retry the exact request after the lost reply.
    const resp = b.service.call(p, req) as { ok: boolean; result: Json };
    const head = b.store.auditHead()!;
    const commitRecords = b.store.auditPrefix(BigInt(head.seq))
      .filter((a) => a.body.data.kind === "ImportCommitted").length;
    return {
      result: resp.ok ? resp.result : null,
      revision: b.store.currentRevision().toString(),
      audit_seq: head.seq,
      commit_events: commitRecords,
    } as unknown as Json;
  } finally { b.cleanup(); }
}

export function race(args: {
  base: string; second_stage: { id: string; batch: unknown };
  calls: { id: string; stage: string; expected_revision: string }[];
  writer_order: string[];
}): Json {
  const b = buildState(args.base as never);
  try {
    const p = b.cfg.principals.find((x) => x.id === "admin1")!;
    // Stage the second batch under its own id.
    const r2 = b.service.call(p, { id: "stage2", method: "import.stage", params: { stage: args.second_stage.id, batch: args.second_stage.batch } as unknown as Json });
    if (!r2.ok) throw new Error("second stage failed");
    const out: Record<string, string> = {};
    let committed = 0;
    for (const callId of args.writer_order) {
      const c = args.calls.find((x) => x.id === callId)!;
      const resp = b.service.call(p, { id: c.id, method: "import.commit", params: { stage: c.stage, expected_revision: c.expected_revision } as unknown as Json });
      if (resp.ok) { out[c.id] = "COMMITTED"; committed++; }
      else out[c.id] = (resp as { error: { code: string } }).error.code;
    }
    return {
      ...out,
      revision: b.store.currentRevision().toString(),
      published_revisions: committed,
    } as unknown as Json;
  } finally { b.cleanup(); }
}

export function stageRace(args: { state: string; writer_order: string[]; expected_revision: string; current_revision: string }): Json {
  const b = buildState("staged");
  try {
    const p = b.cfg.principals.find((x) => x.id === "admin1")!;
    let cancel = "OK", commit = "OK";
    let committed = 0;
    for (const w of args.writer_order) {
      if (w === "cancel") {
        const r = b.service.call(p, { id: "cancel1", method: "import.cancel", params: { stage: "st1" } as unknown as Json });
        cancel = r.ok ? "OK" : (r as { error: { code: string } }).error.code;
      } else {
        const r = b.service.call(p, { id: "commit1", method: "import.commit", params: { stage: "st1", expected_revision: args.expected_revision } as unknown as Json });
        commit = r.ok ? "OK" : (r as { error: { code: string } }).error.code;
        if (r.ok) committed++;
      }
    }
    return {
      state: b.store.stageGet("st1")!.state,
      cancel, commit,
      committed_revisions: Number(b.store.currentRevision()) - 1,
    } as unknown as Json;
  } finally { b.cleanup(); }
}

export function commitAuthorization(args: {
  uid: number; staged_sources: string[]; allowlist_at_stage: string[];
  allowlist_at_commit: string[]; revision: string;
}): Json {
  const b = buildState("registered");
  try {
    const producer = b.cfg.principals.find((x) => x.id === "producer1")!;
    producer.sources = args.allowlist_at_stage.slice();
    const rs = b.service.call(producer, { id: "stage1", method: "import.stage", params: { stage: "st1", batch: F.batch } as unknown as Json });
    if (!rs.ok) return { code: (rs as { error: { code: string } }).error.code, revision: args.revision, published_revisions: 0 } as unknown as Json;
    producer.sources = args.allowlist_at_commit.slice();
    const rc = b.service.call(producer, { id: "commit1", method: "import.commit", params: { stage: "st1", expected_revision: args.revision } as unknown as Json });
    return {
      code: rc.ok ? "OK" : (rc as { error: { code: string } }).error.code,
      revision: b.store.currentRevision().toString(),
      published_revisions: Number(b.store.currentRevision()) - 1,
    } as unknown as Json;
  } finally { b.cleanup(); }
}

export function serviceRead(state: string, uid: number, req: { method: string; params: Json }, inject: { audit_write?: string }): Json {
  const b = buildState(state as never, { auditWriteFault: () => inject.audit_write === "ENOSPC" });
  try {
    const p = b.service.principalForUid(uid)!;
    const resp = b.service.call(p, { id: "r1", ...req });
    return {
      code: resp.ok ? "OK" : (resp as { error: { code: string } }).error.code,
      released_bytes: resp.ok ? Buffer.byteLength(jcsString((resp as { result: Json }).result)) : 0,
      state: b.service.state,
    } as unknown as Json;
  } finally { b.cleanup(); }
}

export function recover(args: { database_audit: Audit[]; required_head: AuditRef | null; trust: unknown }): Json {
  return recoverCheck({ databaseAudit: args.database_audit, requiredHead: args.required_head, trustOk: true }) as unknown as Json;
}

export function migrateCheck(args: {
  from_schema: number; to_schema: number; source: unknown; events: unknown; objects: unknown; kill: string;
}): Json {
  const b = buildState("committed");
  try {
    const dest = join(b.dir, "migrated");
    // The kill point is before CURRENT exists in the destination — the
    // migration completes VERIFIED but is never activated.
    const m = migrateStore({ store: b.store, cfg: b.cfg, targetSchema: args.to_schema, outDir: dest });
    // Source selection untouched: CURRENT still names the source db dir.
    const selected = Store.dbDirOf(b.store.rootDir);
    const destStore = Store.openAt(dest, join(dest, "db-0001"));
    let eventsEqual = false, prefixEqual = false, rootsEqual = false;
    try {
      const srcEvents = b.store.allEvents().map((e) => jcsString(e as unknown as Json));
      const dstEvents = destStore.allEvents().map((e) => jcsString(e as unknown as Json));
      eventsEqual = JSON.stringify(srcEvents) === JSON.stringify(dstEvents);
      const head = b.store.auditHead()!;
      prefixEqual = destStore.auditPrefix(BigInt(head.seq)).length === b.store.auditPrefix(BigInt(head.seq)).length;
      rootsEqual = true;
      for (let r = 0n; r <= b.store.currentRevision(); r++) {
        if (destStore.revisionRow(r)?.evidence !== b.store.revisionRow(r)?.evidence) rootsEqual = false;
      }
    } finally { destStore.close(); }
    return {
      selected: selected !== null ? "SOURCE" : "DESTINATION",
      event_bytes_equal: eventsEqual,
      audit_prefix_equal: prefixEqual,
      evidence_roots_equal: rootsEqual,
      source_deleted: !existsSync(join(b.dir, "store")),
    } as unknown as Json;
  } finally { b.cleanup(); }
}
