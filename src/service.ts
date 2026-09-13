/**
 * Service layer (§3.1): the closed 13-method RPC surface over the store.
 *
 * Admission order is fixed: byte cap → peer authentication → bounded parse →
 * role → method schema → authorized lookup → idempotency → state checks.
 * Transport concerns (byte cap, HTTP shape, peer credentials) live in
 * server.ts; this module begins at role authorization.
 *
 * Mutations bind (principal,id) → D("LAGI-PROOF-REQUEST/v1",{method,params})
 * permanently; responses committed in or after a transaction — success or
 * business error — replay exactly. Evidence-disclosing reads are captured,
 * then inside one writer transaction authorization is rechecked and the
 * DisclosureRecorded/VerificationRecorded audit commits before bytes
 * release; a failed append fails the request and flips the service
 * READ_ONLY.
 */

import { ProofError, failure, type ErrorCode, type RpcResponse } from "./errors.js";
import { jcsBytes, jcsString, parseJson, limits, type Json, type JsonObject } from "./canon.js";
import {
  batchHash, domainHash, hashJson, requestHash, ZERO_HASH,
} from "./crypto.js";
import {
  parseBatch, parseSource, parseBundle, parseTrust, parseVerifyOptions,
  parseEventRef, checkCount, checkHash, checkId, isObj, requireFields,
  auditRefOf, eventRefOf, eventDataObjectRefs,
  type Audit, type AuditRef, type Batch, type BlobT,
  type Event, type Lineage,
} from "./model.js";
import { eventRefKey } from "./chain.js";
import { signatureValid } from "./trust.js";
import { assembleBundle } from "./bundle.js";
import { lineageClosure } from "./lineage.js";
import { verifyBundle } from "./verify.js";
import { Store, type AuditSigner, type Failpoint, Crash } from "./store.js";
import type { Config, PrincipalCfg } from "./config.js";

// ---------- method table ----------

type Role = "admin" | "write" | "read" | "verify";
const METHOD_ROLE: Record<string, Role> = {
  "source.register": "admin",
  "source.list": "read",
  "import.stage": "write",
  "import.get": "write",
  "import.commit": "write",
  "import.cancel": "write",
  "revision.get": "read",
  "lineage.get": "read",
  "bundle.export": "read",
  "bundle.verify": "verify",
  "object.get": "read",
  "audit.export": "admin",
  "status.get": "read",
  "metrics.get": "admin",
};
const MUTATIONS = new Set(["source.register", "import.stage", "import.commit", "import.cancel"]);
const DISCLOSED = new Set(["source.list", "revision.get", "lineage.get", "bundle.export", "object.get", "audit.export"]);
const VERIFY_METHOD = "bundle.verify";

function hasRole(p: PrincipalCfg, required: Role): boolean {
  if (p.roles.includes(required)) return true;
  // Admin includes read/write (§3.1); never verify or admin-only methods.
  return p.roles.includes("admin") && (required === "read" || required === "write");
}

// ---------- rate limiting ----------

class TokenBucket {
  private tokens = 60;
  private last: bigint;
  constructor(now: bigint) { this.last = now; }
  allow(cost: number, now: bigint): boolean {
    const refill = Number(now - this.last) / 1000;
    if (refill > 0) { this.tokens = Math.min(60, this.tokens + Math.floor(refill)); this.last = now; }
    if (this.tokens < cost) return false;
    this.tokens -= cost;
    return true;
  }
}

// ---------- service ----------

export interface ServiceOptions {
  nowMs?: () => bigint;
  failpoint?: Failpoint;
  auditWriteFault?: (() => boolean) | null; // returns true to inject ENOSPC
}

export class Service {
  state: "READY" | "READ_ONLY" = "READY";
  integrityFaults = 0;
  writerQueueDepth = 0;
  private buckets = new Map<string, TokenBucket>();
  private byUid = new Map<number, PrincipalCfg>();
  private byId = new Map<string, PrincipalCfg>();
  verifyWorkersActive = 0;

  constructor(
    readonly store: Store,
    readonly cfg: Config,
    readonly signer: AuditSigner,
    readonly opts: ServiceOptions = {},
  ) {
    for (const p of cfg.principals) { this.byUid.set(p.uid, p); this.byId.set(p.id, p); }
    this.state = store.state;
  }

  private now(): bigint { return (this.opts.nowMs ?? (() => BigInt(Date.now())))(); }
  principalForUid(uid: number): PrincipalCfg | null { return this.byUid.get(uid) ?? null; }
  principalById(id: string): PrincipalCfg | null { return this.byId.get(id) ?? null; }

  /** Effective wall clock honoring the persisted monotone floor (§7). */
  effectiveNow(): bigint { return this.store.effectiveClock(this.now()); }

  private failToReadOnly(e: unknown): ProofError {
    this.state = "READ_ONLY";
    this.store.state = "READ_ONLY";
    this.integrityFaults++;
    return e instanceof ProofError ? e : new ProofError("STORAGE_UNAVAILABLE", "Durable write failed.");
  }

  /** The single-writer transaction body. */
  private inWriter<T>(fn: () => T): T {
    this.db().exec("BEGIN IMMEDIATE");
    try {
      const r = fn();
      this.db().exec("COMMIT");
      return r;
    } catch (e) {
      try { this.db().exec("ROLLBACK"); } catch { /* tx may be gone */ }
      throw e;
    }
  }
  private db() { return this.store.db; }

  /** Tombstone + return inside the caller's writer tx. */
  private bind(p: PrincipalCfg, id: string, reqHash: string, result: Json): Json {
    this.store.requestPut(p.id, id, reqHash, result);
    return result;
  }

  private auditAppend(p: PrincipalCfg, id: string, data: Json): Audit {
    try {
      return this.store.appendAudit(this.signer, p.id, id, data as never);
    } catch (e) {
      throw this.failToReadOnly(e);
    }
  }

  // ---------- dispatch ----------

  /**
   * Handle one authenticated request after transport admission. `principal`
   * is the peer-resolved configured principal; `uid` its UID.
   */
  call(principal: PrincipalCfg, req: { id: string; method: string; params: Json }): RpcResponse {
    const { id, method, params } = req;
    try {
      if (this.state === "READ_ONLY") throw new ProofError("READ_ONLY", "Service is read-only.");
      if (typeof method !== "string" || !isObj(params)) {
        throw new ProofError("SCHEMA_INVALID", "Request requires method and object params.", "/method");
      }
      const required = METHOD_ROLE[method];
      if (!required) throw new ProofError("METHOD_UNKNOWN", "Unknown method.", "/method");
      if (!hasRole(principal, required)) throw new ProofError("FORBIDDEN", "Role does not permit this method.");
      const bucket = this.buckets.get(principal.id) ?? new TokenBucket(this.now());
      this.buckets.set(principal.id, bucket);
      const cost = method === "bundle.verify" || method === "bundle.export" || method === "audit.export" ? 10 : 1;
      if (!bucket.allow(cost, this.now())) throw new ProofError("RATE_LIMIT", "Token bucket empty.");

      if (MUTATIONS.has(method)) {
        const out = this.mutation(principal, id, method, params);
        return { id, ok: true, result: out };
      }

      if (method === "import.get") {
        return { id, ok: true, result: this.importGet(principal, params) };
      }
      if (method === "status.get") {
        return { id, ok: true, result: { protocol: "proof/1", status: this.state, product_status: "UNWRITTEN_GATED" } };
      }
      if (method === "metrics.get") {
        return { id, ok: true, result: this.metricsObject() };
      }
      if (method === VERIFY_METHOD) {
        return { id, ok: true, result: this.rpcVerify(principal, id, params) };
      }
      // Disclosure-audited read.
      const result = this.readResult(method, params);
      this.commitDisclosure(principal, id, method, result);
      return { id, ok: true, result };
    } catch (e) {
      if (e instanceof Crash) throw e; // harness-observed crash barrier
      const pe = e instanceof ProofError ? e : new ProofError("STORAGE_UNAVAILABLE", String(e));
      return pe.toFailure(id);
    }
  }

  metricsSnapshot(): string {
    const m = this.metricsObject() as { proof_ready: number; proof_writer_queue_depth: number; proof_integrity_faults_total: number };
    return `proof_ready ${m.proof_ready}\nproof_writer_queue_depth ${m.proof_writer_queue_depth}\nproof_integrity_faults_total ${m.proof_integrity_faults_total}\n`;
  }

  private metricsObject(): Json {
    return {
      proof_ready: this.state === "READY" ? 1 : 0,
      proof_writer_queue_depth: this.writerQueueDepth,
      proof_integrity_faults_total: this.integrityFaults,
    };
  }

  /** Idempotency precheck (post authorization, pre state checks). */
  private idem(p: PrincipalCfg, id: string, reqHash: string): { hit: boolean; saved?: Json } {
    const prev = this.store.requestGet(p.id, id);
    if (!prev) return { hit: false };
    if (prev.request_hash !== reqHash) {
      throw new ProofError("IDEMPOTENCY_CONFLICT", "Request id was used with different content.");
    }
    // A bound failure replays as the same failure (§3.1 permanent binding).
    const s = prev.result;
    if (isObj(s) && isObj(s.$failure)) {
      const f = s.$failure;
      throw new ProofError(f.code as ErrorCode, "Saved failure.", (f.field as string | null) ?? null);
    }
    return { hit: true, saved: s };
  }

  // ---------- mutations ----------

  private mutation(p: PrincipalCfg, id: string, method: string, params: Json): Json {
    const reqHash = requestHash(method, params as JsonObject);
    switch (method) {
      case "source.register": return this.sourceRegister(p, id, params, reqHash);
      case "import.stage": return this.importStage(p, id, params, reqHash);
      case "import.commit": return this.importCommit(p, id, params, reqHash);
      case "import.cancel": return this.importCancel(p, id, params, reqHash);
      default: throw new ProofError("METHOD_UNKNOWN", "Unknown method.", "/method");
    }
  }

  private sourceRegister(p: PrincipalCfg, id: string, params: Json, reqHash: string): Json {
    const source = parseSource(params, "");
    const existing = this.store.sourceGet(source.id);
    if (existing) {
      if (jcsString(existing as unknown as Json) === jcsString(source as unknown as Json)) {
        const rev = this.store.revisionView(this.registeredRevision(source.id));
        return { source: existing, revision: rev } as unknown as Json;
      }
      throw new ProofError("SOURCE_CONFLICT", "Source already registered with different content.");
    }
    const saved = this.idem(p, id, reqHash);
    if (saved.hit) return saved.saved!;
    return this.inWriter(() => {
      const { revision } = this.store.registerSourceTx({
        source, signer: this.signer, principal: p.id, request: id,
      });
      const result = { source, revision } as unknown as Json;
      this.bind(p, id, reqHash, result);
      this.store.writeRecoveryHead();
      return result;
    });
  }

  private registeredRevision(sourceId: string): bigint {
    const r = this.db().prepare("SELECT registered_revision FROM sources WHERE id=?").get(sourceId) as { registered_revision: number | bigint };
    return BigInt(r.registered_revision);
  }

  // ---------- import lifecycle ----------

  private stageLookup(p: PrincipalCfg, stage: string) {
    const st = this.store.stageGet(stage);
    // Another writer's stage is indistinguishable from absent (§3.1).
    if (!st || (st.principal !== p.id && !p.roles.includes("admin"))) {
      throw new ProofError("NOT_FOUND", "No such stage.");
    }
    return st;
  }

  /** The ImportStaged audit ref for a live stage, from the durable chain. */
  private stagedAuditRef(stage: string): AuditRef | null {
    const head = this.store.auditHead();
    if (!head) return null;
    const entries = this.store.auditPrefix(BigInt(head.seq));
    for (let i = entries.length - 1; i >= 0; i--) {
      const d = entries[i]!.body.data;
      if (d.kind === "ImportStaged" && (d as { stage?: string }).stage === stage) {
        return auditRefOf(entries[i]!);
      }
    }
    return null;
  }

  private stageResultFor(p: PrincipalCfg, id: string, stage: string, reqHash: string): Json {
    const st = this.stageLookup(p, stage);
    const ref = this.stagedAuditRef(stage);
    return { stage, state: st.state === "STAGED" ? "STAGED" : st.state, batch: st.batch_hash, audit: ref } as unknown as Json;
  }

  private importStage(p: PrincipalCfg, id: string, params: Json, reqHash: string): Json {
    if (!isObj(params)) throw new ProofError("SCHEMA_INVALID", "params must be an object.");
    requireFields(params, ["stage", "batch"], "");
    const stageId = checkId(params.stage!, "/stage");
    const batch = parseBatch(params.batch!, "/batch");
    const bh = batchHash(batch as unknown as Json);

    const prev = this.store.stageGet(stageId);
    if (prev) {
      if (prev.principal !== p.id && !p.roles.includes("admin")) {
        throw new ProofError("NOT_FOUND", "No such stage.");
      }
      if (prev.batch_hash !== bh) throw new ProofError("STAGE_CONFLICT", "Stage id bound to a different batch.");
      // Identical batch under the same stage id returns the original
      // StageResult with no new audit record — even after the stage went
      // terminal, the import.stage result is the STAGED receipt.
      const orig = this.store.requestGet(p.id, id);
      if (orig && orig.request_hash === reqHash) return orig.result;
      const res = this.stageResultFor(p, id, stageId, reqHash);
      this.inWriter(() => this.bind(p, id, reqHash, res));
      return res;
    }

    // Admission schema checks — failure creates no stage or audit.
    this.validateBatch(p, batch);

    const saved = this.idem(p, id, reqHash);
    if (saved.hit) return saved.saved!;

    // Durable staged bytes before any row references them (§6.3).
    this.store.stageObjectBytes(batch.objects);

    return this.inWriter(() => {
      const eff = this.effectiveNow();
      this.store.stageInsert(stageId, p.id, bh, jcsBytes(batch as unknown as Json), eff);
      const audit = this.auditAppend(p, id, { kind: "ImportStaged", stage: stageId, batch: bh });
      const result = { stage: stageId, state: "STAGED", batch: bh, audit: auditRefOf(audit) } as unknown as Json;
      this.bind(p, id, reqHash, result);
      this.store.writeRecoveryHead();
      return result;
    });
  }

  /** Batch admission checks (§3.1 staging paragraph). */
  private validateBatch(p: PrincipalCfg, batch: Batch): void {
    const usedKeys = new Set<string>();
    const allow = new Set(p.sources);
    const isAdmin = p.roles.includes("admin");
    for (const e of batch.events) {
      // Workspace scope.
      if (e.body.workspace !== this.cfg.workspace) {
        throw new ProofError("SCOPE_MISMATCH", "Event names a different workspace.");
      }
      // Source must be registered and currently allowlisted.
      const src = this.store.sourceGet(e.body.source);
      if (!src) throw new ProofError("NOT_FOUND", "Event source is not registered.");
      if (!isAdmin && !allow.has(e.body.source)) {
        throw new ProofError("FORBIDDEN", "Source is outside the principal allowlist.");
      }
      // Hash + signature under the key whose id equals body.key.
      if (eventHashCheck(e) !== "OK") throw new ProofError("HASH_MISMATCH", "Event hash does not recompute.");
      const key = batch.keys.find((k) => k.id === e.body.key) ?? this.store.keyById(e.body.key);
      if (!key) throw new ProofError("KEY_MATERIAL_INVALID", "No key material for event key id.");
      if (!signatureValid(e, key, "origin")) {
        throw new ProofError("SIGNATURE_INVALID", "Event signature does not verify.");
      }
      usedKeys.add(e.body.key);
    }
    for (const k of batch.keys) {
      if (!usedKeys.has(k.id)) throw new ProofError("UNREFERENCED_ITEM", "Batch key is unused.");
    }
    // Blobs must be referenced by staged events or retained events in the
    // caller's currently write-authorized sources.
    const authorized = isAdmin
      ? new Set(this.store.sourceList().map((s) => s.id))
      : allow;
    const referenced = new Set<string>();
    for (const e of batch.events) for (const r of eventDataObjectRefs(e.body.data)) referenced.add(r.digest);
    for (const e of this.store.allEvents()) {
      if (!authorized.has(e.body.source)) continue;
      for (const r of eventDataObjectRefs(e.body.data)) referenced.add(r.digest);
    }
    for (const o of batch.objects) {
      if (!referenced.has(o.ref.digest)) throw new ProofError("UNREFERENCED_ITEM", "Batch object is unreferenced.");
      const raw = Buffer.from(o.content, "base64url");
      if (BigInt(raw.length) !== BigInt(o.ref.bytes)) {
        throw new ProofError("OBJECT_CONFLICT", "Blob length does not match descriptor.");
      }
      const cur = this.store.objectRow(o.ref.digest);
      if (cur && (cur.bytes !== BigInt(o.ref.bytes) || cur.media !== o.ref.media)) {
        throw new ProofError("OBJECT_CONFLICT", "Blob conflicts with stored descriptor.");
      }
    }
  }

  private importGet(p: PrincipalCfg, params: Json): Json {
    if (!isObj(params)) throw new ProofError("SCHEMA_INVALID", "params must be an object.");
    requireFields(params, ["stage"], "");
    const stage = checkId(params.stage!, "/stage");
    const st = this.stageLookup(p, stage);
    const out: JsonObject = {
      stage, batch: st.batch_hash, state: st.state, commit: null, cancel: null,
    };
    if (st.state === "COMMITTED") out.commit = st.terminal_result;
    if (st.state === "CANCELLED") out.cancel = st.terminal_result;
    return out;
  }

  private importCommit(p: PrincipalCfg, id: string, params: Json, reqHash: string): Json {
    if (!isObj(params)) throw new ProofError("SCHEMA_INVALID", "params must be an object.");
    requireFields(params, ["stage", "expected_revision"], "");
    const stage = checkId(params.stage!, "/stage");
    const expected = BigInt(checkCount(params.expected_revision!, "/expected_revision"));
    this.stageLookup(p, stage);
    const saved = this.idem(p, id, reqHash);
    if (saved.hit) return saved.saved!;
    const isAdmin = p.roles.includes("admin");

    // The tx body returns a tagged outcome; failure tombstones commit with
    // the transaction and the error is raised after COMMIT (§3.1 binding).
    const out = this.inWriter((): { ok: Json } | { fail: ProofError } => {
      const st = this.store.stageGet(stage)!;
      // Terminal-state results win over every later check.
      if (st.state === "CANCELLED") {
        const e = new ProofError("STAGE_STATE", "Stage is cancelled.");
        this.bind(p, id, reqHash, failureJson(e));
        return { fail: e };
      }
      if (st.state === "COMMITTED") {
        const res = st.terminal_result!;
        this.bind(p, id, reqHash, res);
        return { ok: res };
      }
      // Expiry: the expiry cancellation commits before STAGE_EXPIRED (§2.2).
      const eff = this.store.effectiveClock(this.now());
      const ttl = BigInt(this.cfg.retention.stage_ttl_ms);
      if (eff - st.created_ms >= ttl) {
        const cancelAudit = this.auditAppend(p, id, { kind: "ImportCancelled", stage, reason: "EXPIRED" });
        const cancelResult = { stage, state: "CANCELLED", reason: "EXPIRED", audit: auditRefOf(cancelAudit) } as unknown as Json;
        this.store.stageTerminal(stage, "CANCELLED", cancelResult);
        const e = new ProofError("STAGE_EXPIRED", "Stage expired before commit.");
        this.bind(p, id, reqHash, failureJson(e));
        return { fail: e };
      }
      // Allowlist recheck at the commit barrier for non-admin writers.
      const full = parseBatch(parseJson(st.canonical!, limits(this.cfg.limits.stage_bytes)), "/batch");
      if (!isAdmin) {
        const allow = new Set(p.sources);
        for (const e of full.events) {
          if (!allow.has(e.body.source)) {
            const err = new ProofError("FORBIDDEN", "Source allowlist changed before commit.");
            this.bind(p, id, reqHash, failureJson(err));
            return { fail: err };
          }
        }
      }
      if (this.store.currentRevision() !== expected) {
        const e = new ProofError("REVISION_CONFLICT", "expected_revision does not match the current revision.");
        this.bind(p, id, reqHash, failureJson(e));
        return { fail: e };
      }
      const committed = this.store.commitBatch({
        stage, batch: full, signer: this.signer, principal: p.id, request: id,
        expectedRevision: expected, fail: this.opts.failpoint ?? null,
      });
      const result = {
        stage, state: "COMMITTED", revision: committed.revision,
        added: committed.added, duplicates: committed.duplicates, conflicts: committed.conflicts,
      } as unknown as Json;
      this.store.stageTerminal(stage, "COMMITTED", result);
      this.bind(p, id, reqHash, result);
      return { ok: result };
    });
    if ("fail" in out) throw out.fail;
    if (this.opts.failpoint === "after_commit_before_reply") throw new Crash("after_commit_before_reply");
    return out.ok;
  }

  private importCancel(p: PrincipalCfg, id: string, params: Json, reqHash: string): Json {
    if (!isObj(params)) throw new ProofError("SCHEMA_INVALID", "params must be an object.");
    requireFields(params, ["stage"], "");
    const stage = checkId(params.stage!, "/stage");
    this.stageLookup(p, stage);
    const saved = this.idem(p, id, reqHash);
    if (saved.hit) return saved.saved!;

    const out = this.inWriter((): { ok: Json } | { fail: ProofError } => {
      const st = this.store.stageGet(stage)!;
      if (st.state === "COMMITTED") {
        const e = new ProofError("STAGE_STATE", "Stage is committed.");
        this.bind(p, id, reqHash, failureJson(e));
        return { fail: e };
      }
      if (st.state === "CANCELLED") {
        const res = st.terminal_result!;
        this.bind(p, id, reqHash, res);
        return { ok: res };
      }
      const audit = this.auditAppend(p, id, { kind: "ImportCancelled", stage, reason: "USER" });
      const result = { stage, state: "CANCELLED", reason: "USER", audit: auditRefOf(audit) } as unknown as Json;
      this.store.stageTerminal(stage, "CANCELLED", result);
      this.bind(p, id, reqHash, result);
      this.store.writeRecoveryHead();
      return { ok: result };
    });
    if ("fail" in out) throw out.fail;
    return out.ok;
  }

  // ---------- reads ----------

  private readResult(method: string, params: Json): Json {
    switch (method) {
      case "source.list": return this.sourceList(params);
      case "revision.get": return this.revisionGet(params);
      case "lineage.get": return this.lineageGet(params);
      case "bundle.export": return this.bundleExport(params);
      case "object.get": return this.objectGet(params);
      case "audit.export": return this.auditExport(params);
      default: throw new ProofError("METHOD_UNKNOWN", "Unknown method.", "/method");
    }
  }

  private commitDisclosure(p: PrincipalCfg, id: string, method: string, result: Json): void {
    if (this.opts.auditWriteFault?.()) {
      this.failToReadOnly(new ProofError("STORAGE_UNAVAILABLE", "Audit append failed (ENOSPC)."));
      throw new ProofError("STORAGE_UNAVAILABLE", "Audit append failed (ENOSPC).");
    }
    this.inWriter(() => {
      // Authorization rechecked inside the disclosure transaction.
      const required = METHOD_ROLE[method]!;
      if (!hasRole(p, required)) throw new ProofError("FORBIDDEN", "Role does not permit this method.");
      const rev = method === "audit.export" ? null : this.store.currentRevision().toString();
      this.auditAppend(p, id, {
        kind: "DisclosureRecorded", method,
        content: hashJson(result), revision: rev,
      });
      this.store.writeRecoveryHead();
    });
  }

  private sourceList(params: Json): Json {
    if (!isObj(params)) throw new ProofError("SCHEMA_INVALID", "params must be an object.");
    requireFields(params, ["revision"], "");
    const rev = this.revisionParam(params.revision!, "/revision");
    const row = this.store.revisionRow(rev);
    if (!row) throw new ProofError("CUT_UNKNOWN", "No such revision.");
    return { sources: row.manifest.sources } as unknown as Json;
  }

  private revisionParam(v: Json, field: string): bigint {
    const s = checkCount(v, field);
    const n = BigInt(s);
    if (n > this.store.currentRevision()) throw new ProofError("CUT_UNKNOWN", "No such revision.");
    return n;
  }

  private revisionGet(params: Json): Json {
    if (!isObj(params)) throw new ProofError("SCHEMA_INVALID", "params must be an object.");
    requireFields(params, ["revision"], "");
    const rev = params.revision === null ? this.store.currentRevision() : this.revisionParam(params.revision!, "/revision");
    const view = this.store.revisionView(rev);
    if (!view) throw new ProofError("CUT_UNKNOWN", "No such revision.");
    return view as unknown as Json;
  }

  private lineageGet(params: Json): Json {
    if (!isObj(params)) throw new ProofError("SCHEMA_INVALID", "params must be an object.");
    requireFields(params, ["revision", "actions", "max_nodes", "max_depth"], "");
    const rev = this.revisionParam(params.revision!, "/revision");
    if (!Array.isArray(params.actions) || params.actions.length === 0) {
      throw new ProofError("REQUEST_INVALID", "actions must be a nonempty array.");
    }
    const actions = params.actions.map((a, i) => parseEventRef(a, `/actions/${i}`));
    const maxNodes = boundedInt(params.max_nodes!, 1, 20000, "/max_nodes");
    const maxDepth = boundedInt(params.max_depth!, 1, 4096, "/max_depth");
    const events = this.store.eventsAtRevision(rev);
    const proj = this.store.projectionAt(rev);
    if (!proj) throw new ProofError("CUT_UNKNOWN", "No such revision.");
    const closure = lineageClosure(events, actions, maxNodes, maxDepth, proj.projection.edges, proj.projection.findings);
    const lineage: Lineage = {
      revision: rev.toString(), projection: proj.hash,
      nodes: closure.nodes, edges: closure.edges, findings: closure.findings,
    };
    return lineage as unknown as Json;
  }

  private bundleExport(params: Json): Json {
    if (!isObj(params)) throw new ProofError("SCHEMA_INVALID", "params must be an object.");
    requireFields(params, ["revision", "actions", "include"], "");
    const rev = this.revisionParam(params.revision!, "/revision");
    const row = this.store.revisionRow(rev)!;
    if (!Array.isArray(params.actions) || params.actions.length === 0) {
      throw new ProofError("REQUEST_INVALID", "actions must be a nonempty array.");
    }
    const actions = params.actions.map((a, i) => parseEventRef(a, `/actions/${i}`));
    if (!Array.isArray(params.include)) throw new ProofError("SCHEMA_INVALID", "include must be an array.", "/include");
    const include = params.include.map((x, i) => checkHash(x, `/include/${i}`));
    const sorted = [...include].sort();
    if (include.some((x, i) => x !== sorted[i] || (i > 0 && x === sorted[i - 1]))) {
      throw new ProofError("REQUEST_INVALID", "include must be sorted unique digests.");
    }
    const manifestRefs = new Map(row.manifest.objects.map((o) => [o.digest, o]));
    for (const d of include) {
      if (!manifestRefs.has(d)) throw new ProofError("REQUEST_INVALID", "include names a digest outside the revision.");
    }
    const events = this.store.eventsAtRevision(rev);
    const byRef = new Map(events.map((e) => [eventRefKey(eventRefOf(e)), e]));
    for (const a of actions) {
      if (!byRef.has(eventRefKey(a))) throw new ProofError("ACTION_UNKNOWN", "Action is not retained in the revision.");
    }
    const audit = this.store.auditPrefix(BigInt(row.manifest.audit.seq));
    const proj = this.store.projectionAt(rev);
    const objects: BlobT[] = [];
    const availability = new Map<string, "INCLUDED" | "WITHHELD" | "UNAVAILABLE">();
    for (const ref of row.manifest.objects) {
      const bytes = this.store.readObjectBytes(ref.digest);
      if (include.includes(ref.digest)) {
        if (!bytes) throw new ProofError("OBJECT_UNAVAILABLE", "Referenced object bytes are not stored.");
        objects.push({ ref, content: Buffer.from(bytes).toString("base64url") });
        availability.set(ref.digest, "INCLUDED");
      } else {
        availability.set(ref.digest, bytes ? "WITHHELD" : "UNAVAILABLE");
      }
    }
    const bundle = assembleBundle({
      workspace: this.cfg.workspace, revision: rev.toString(),
      sources: row.manifest.sources, actions,
      events, keys: row.manifest.keys, audit,
      refs: row.manifest.objects, blobs: objects,
      availability,
      projectionHash: proj?.hash ?? ZERO_HASH,
      evidence: row.evidence, auditThrough: row.manifest.audit,
    });
    const bytes = jcsBytes(bundle as unknown as Json);
    if (bytes.length > this.cfg.limits.bundle_bytes) {
      throw new ProofError("BUNDLE_LIMIT", "Bundle exceeds bound.");
    }
    return { bundle } as unknown as Json;
  }

  private objectGet(params: Json): Json {
    if (!isObj(params)) throw new ProofError("SCHEMA_INVALID", "params must be an object.");
    requireFields(params, ["revision", "digest"], "");
    const rev = this.revisionParam(params.revision!, "/revision");
    const digest = checkHash(params.digest!, "/digest");
    const row = this.store.revisionRow(rev)!;
    if (!row.manifest.objects.some((o) => o.digest === digest)) {
      throw new ProofError("NOT_FOUND", "Digest is not referenced in the revision.");
    }
    const blob = this.store.objectBlob(digest);
    if (!blob) throw new ProofError("OBJECT_UNAVAILABLE", "Object bytes are not stored.");
    return blob as unknown as Json;
  }

  private auditExport(params: Json): Json {
    if (!isObj(params)) throw new ProofError("SCHEMA_INVALID", "params must be an object.");
    requireFields(params, ["through"], "");
    const s = checkCount(params.through!, "/through");
    if (s === "0") throw new ProofError("REQUEST_INVALID", "through must be at least 1.");
    const head = this.store.auditHead();
    if (!head || BigInt(s) > BigInt(head.seq)) throw new ProofError("CUT_UNKNOWN", "through exceeds the audit head.");
    const entries = this.store.auditPrefix(BigInt(s));
    const keyIds = new Set(entries.map((a) => a.body.key));
    const keys = this.store.allKeys().filter((k) => keyIds.has(k.id)).sort((a, b) => (a.id < b.id ? -1 : 1));
    const at = entries[entries.length - 1]!;
    return {
      workspace: this.cfg.workspace,
      through: auditRefOf(at),
      entries, keys,
    } as unknown as Json;
  }

  private rpcVerify(p: PrincipalCfg, id: string, params: Json): Json {
    if (!isObj(params)) throw new ProofError("SCHEMA_INVALID", "params must be an object.");
    requireFields(params, ["bundle", "trust", "options"], "");
    const bundle = parseBundle(params.bundle!, "/bundle");
    const trust = parseTrust(params.trust!, "/trust");
    const options = parseVerifyOptions(params.options!, "/options");
    if (this.verifyWorkersActive >= this.cfg.limits.verify_workers) {
      throw new ProofError("BUSY", "No verifier worker slot.");
    }
    this.verifyWorkersActive++;
    let verification: Json;
    try {
      verification = verifyBundle(bundle, trust, options.requirement, options.as_of_unix_ms) as unknown as Json;
    } finally {
      this.verifyWorkersActive--;
    }
    // VerificationRecorded: hashes only, appended when a report was produced.
    if (this.opts.auditWriteFault?.()) {
      this.failToReadOnly(new ProofError("STORAGE_UNAVAILABLE", "Audit append failed (ENOSPC)."));
      throw new ProofError("STORAGE_UNAVAILABLE", "Audit append failed (ENOSPC).");
    }
    this.inWriter(() => {
      this.auditAppend(p, id, {
        kind: "VerificationRecorded",
        bundle: bundle.hash,
        trust: hashJson(trust as unknown as Json),
        report: hashJson(verification),
      });
      this.store.writeRecoveryHead();
    });
    return verification;
  }
}

// ---------- helpers ----------

/** Stored tombstone shape for a bound failure response. */
function failureJson(e: ProofError): Json {
  return { $failure: e.toFailure(null).error } as unknown as Json;
}

function boundedInt(v: Json, min: number, max: number, field: string): number {
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < min || v > max) {
    throw new ProofError("SCHEMA_INVALID", "Bounded integer out of range.", field);
  }
  return v;
}

function eventHashCheck(e: Event): string {
  return e.hash === domainHash("LAGI-PROOF-EVENT/v1", e.body as unknown as Json) ? "OK" : "HASH_MISMATCH";
}
