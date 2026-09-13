/**
 * Durable store (§6): one workspace per SQLite database, one writer,
 * append-only evidence. Canonical signed bytes and immutable object files
 * are authoritative; projections and indexes are rebuildable caches.
 *
 * Layout (§6.1):
 *   store/CURRENT → db-0001/
 *   db-0001/proof.sqlite3 (+ WAL), objects/sha256/ab/<digest>, staged/,
 *   recovery-head.json (convenience copy — never the independent anchor)
 *
 * Commit protocol (§6.3): object bytes are staged and fsynced before any
 * row references them; the audit record, authoritative rows, revision
 * membership, projection, terminal stage result, and request tombstone
 * commit in one transaction; no reply before COMMIT.
 */

import { DatabaseSync } from "node:sqlite";
import {
  existsSync, mkdirSync, openSync, writeSync, fsyncSync, closeSync, readFileSync,
  renameSync, readdirSync, unlinkSync,
} from "node:fs";
import { join, dirname } from "node:path";
import { ProofError } from "./errors.js";
import { jcsBytes, jcsString, parseJson, LIMITS_BUNDLE, type Json } from "./canon.js";
import {
  auditHash, hashJson, sha256Hex, signingMessage, signMessage,
  D_AUDIT_SIGN, ZERO_HASH, b64uEncode, projectionHash, batchHash,
} from "./crypto.js";
import {
  auditRefOf, compareEventRef, eventRefOf, eventDataObjectRefs, cmpStr,
  type Audit, type AuditData, type AuditRef, type Batch, type BlobT,
  type Event, type EventRef, type KeyMaterial, type ObjectRef,
  type Revision, type Source, type Projection, type Cut,
} from "./model.js";
import { chainCheck, eventRefKey } from "./chain.js";
import { replay } from "./replay.js";
import {
  computeCuts, computeEvidence, distinctObjectRefs, sortEvents, sortKeys, sortSources,
} from "./bundle.js";
import type { KeyObject } from "node:crypto";

export const STORE_SCHEMA = 1;

const DDL = `
CREATE TABLE meta(k TEXT PRIMARY KEY, v BLOB NOT NULL) STRICT;
CREATE TABLE sources(id TEXT PRIMARY KEY, canonical BLOB NOT NULL, registered_revision INTEGER NOT NULL) STRICT;
CREATE TABLE keys(id TEXT PRIMARY KEY, canonical BLOB NOT NULL) STRICT;
CREATE TABLE events(hash TEXT PRIMARY KEY, source TEXT NOT NULL, stream TEXT NOT NULL, seq INTEGER NOT NULL CHECK(seq>0), prev TEXT NOT NULL, key_id TEXT NOT NULL, canonical BLOB NOT NULL, FOREIGN KEY(source) REFERENCES sources(id), FOREIGN KEY(key_id) REFERENCES keys(id)) STRICT;
CREATE INDEX event_slot ON events(source,stream,seq,hash);
CREATE INDEX event_prev ON events(source,stream,prev);
CREATE TABLE objects(digest TEXT PRIMARY KEY, bytes INTEGER NOT NULL CHECK(bytes>=0), media TEXT NOT NULL, available INTEGER NOT NULL CHECK(available IN(0,1))) STRICT;
CREATE TABLE event_objects(event_hash TEXT NOT NULL REFERENCES events(hash), digest TEXT NOT NULL REFERENCES objects(digest), PRIMARY KEY(event_hash,digest)) STRICT;
CREATE TABLE event_parents(child TEXT NOT NULL REFERENCES events(hash), source TEXT NOT NULL, stream TEXT NOT NULL, seq INTEGER NOT NULL, parent_hash TEXT NOT NULL, PRIMARY KEY(child,source,stream,seq,parent_hash)) STRICT;
CREATE INDEX parent_target ON event_parents(source,stream,seq,parent_hash);
CREATE TABLE revisions(revision INTEGER PRIMARY KEY CHECK(revision>=0), evidence TEXT NOT NULL, manifest BLOB NOT NULL, audit_seq INTEGER NOT NULL) STRICT;
CREATE TABLE revision_events(revision INTEGER NOT NULL REFERENCES revisions(revision), event_hash TEXT NOT NULL REFERENCES events(hash), PRIMARY KEY(revision,event_hash)) STRICT;
CREATE TABLE stages(id TEXT PRIMARY KEY, principal TEXT NOT NULL, batch_hash TEXT NOT NULL, canonical BLOB, state TEXT NOT NULL CHECK(state IN('STAGED','COMMITTED','CANCELLED')), created_ms INTEGER NOT NULL, terminal_result BLOB) STRICT;
CREATE INDEX stage_expiry ON stages(state,created_ms);
CREATE TABLE requests(principal TEXT NOT NULL, id TEXT NOT NULL, request_hash TEXT NOT NULL, result BLOB NOT NULL, PRIMARY KEY(principal,id)) STRICT;
CREATE TABLE audit(seq INTEGER PRIMARY KEY CHECK(seq>0), hash TEXT UNIQUE NOT NULL, prev TEXT NOT NULL, key_id TEXT NOT NULL REFERENCES keys(id), canonical BLOB NOT NULL) STRICT;
CREATE INDEX audit_hash ON audit(hash);
CREATE TABLE projections(revision INTEGER PRIMARY KEY REFERENCES revisions(revision), hash TEXT NOT NULL, canonical BLOB NOT NULL) STRICT;
PRAGMA user_version = 1;
`;

/** Signing context for the workspace audit key. */
export interface AuditSigner {
  keyId: string;
  keyObject: KeyObject;
  material: KeyMaterial;
}

export interface StageRow {
  principal: string;
  batch_hash: string;
  canonical: Buffer | null;
  state: "STAGED" | "COMMITTED" | "CANCELLED";
  created_ms: bigint;
  terminal_result: Json | null;
}

export type Failpoint =
  | "after_audit_sign_before_commit"
  | "after_commit_before_reply"
  | null;

export class Crash extends Error {
  constructor(public point: string) { super(`simulated crash at ${point}`); this.name = "Crash"; }
}

export class Store {
  readonly db: DatabaseSync;
  readonly dir: string;      // db-XXXX directory
  readonly rootDir: string;  // store/ directory
  state: "READY" | "READ_ONLY" = "READY";
  integrityFaults = 0;

  private constructor(rootDir: string, dir: string, db: DatabaseSync) {
    this.rootDir = rootDir;
    this.dir = dir;
    this.db = db;
  }

  // ---------- filesystem ----------

  private objPath(digest: string): string {
    return join(this.dir, "objects", "sha256", digest.slice(0, 2), digest);
  }

  /** Durable object write: exclusive file, fsync file + parent directory. */
  writeObjectFile(digest: string, bytes: Buffer): void {
    const p = this.objPath(digest);
    mkdirSync(dirname(p), { recursive: true, mode: 0o700 });
    if (existsSync(p)) {
      const cur = readFileSync(p);
      if (sha256Hex(cur) === digest) return; // adopt after re-verification
      throw new ProofError("OBJECT_CONFLICT", "Existing object file digest mismatch.");
    }
    const tmp = `${p}.tmp-${process.pid}-${Math.floor(Math.random() * 1e9)}`;
    const fd = openSync(tmp, "wx", 0o600);
    try { writeSync(fd, bytes); fsyncSync(fd); } finally { closeSync(fd); }
    renameSync(tmp, p);
    const dfd = openSync(dirname(p), "r");
    try { fsyncSync(dfd); } finally { closeSync(dfd); }
  }

  readObjectBytes(digest: string): Buffer | null {
    const p = this.objPath(digest);
    if (!existsSync(p)) return null;
    const b = readFileSync(p);
    return sha256Hex(b) === digest ? b : null;
  }

  /** Stage object bytes durably before any DB row references them (§6.3). */
  stageObjectBytes(blobs: { ref: { digest: string }; content: string }[]): void {
    for (const b of blobs) {
      const raw = Buffer.from(b.content, "base64url");
      this.writeObjectFile(b.ref.digest, raw);
    }
  }

  private atomicWrite(path: string, bytes: Uint8Array, exclusive = false): void {
    const tmp = `${path}.tmp-${process.pid}`;
    const fd = openSync(tmp, "w", 0o600);
    try { writeSync(fd, bytes); fsyncSync(fd); } finally { closeSync(fd); }
    if (exclusive && existsSync(path)) { unlinkSync(tmp); throw new ProofError("OBJECT_CONFLICT", "Output exists."); }
    renameSync(tmp, path);
    const dfd = openSync(dirname(path), "r");
    try { fsyncSync(dfd); } finally { closeSync(dfd); }
  }

  // ---------- open / create ----------

  static dbDirOf(rootDir: string): string | null {
    const cur = join(rootDir, "CURRENT");
    if (!existsSync(cur)) return null;
    const name = readFileSync(cur, "utf8").trim();
    if (!/^db-[0-9]{4}$/.test(name)) throw new ProofError("RECOVERY_REQUIRED", "CURRENT is corrupt.");
    return name;
  }

  static exists(rootDir: string): boolean {
    const name = Store.dbDirOf(rootDir);
    return name !== null && existsSync(join(rootDir, name, "proof.sqlite3"));
  }

  static openDir(rootDir: string): { dir: string; db: DatabaseSync } {
    const name = Store.dbDirOf(rootDir);
    if (!name) throw new ProofError("RECOVERY_REQUIRED", "No initialized store.");
    const dir = join(rootDir, name);
    const db = new DatabaseSync(join(dir, "proof.sqlite3"));
    db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=true;");
    return { dir, db };
  }

  static open(rootDir: string): Store {
    const { dir, db } = Store.openDir(rootDir);
    return new Store(rootDir, dir, db);
  }

  /** Open a database directory directly (migration destination pre-CURRENT). */
  static openAt(rootDir: string, dir: string): Store {
    const db = new DatabaseSync(join(dir, "proof.sqlite3"));
    db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=true;");
    return new Store(rootDir, dir, db);
  }

  static create(rootDir: string, dbName = "db-0001"): Store {
    if (existsSync(rootDir) && readdirSync(rootDir).filter((f) => f !== "backups").length > 0) {
      throw new ProofError("OBJECT_CONFLICT", "Store directory is nonempty.");
    }
    mkdirSync(rootDir, { recursive: true, mode: 0o700 });
    const dir = join(rootDir, dbName);
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    mkdirSync(join(dir, "objects", "sha256"), { recursive: true });
    mkdirSync(join(dir, "staged"), { recursive: true });
    const db = new DatabaseSync(join(dir, "proof.sqlite3"));
    db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=true;");
    db.exec(DDL);
    const tmp = join(rootDir, ".CURRENT.tmp");
    writeSync(openSync(tmp, "w", 0o600), `${dbName}\n`);
    { const fd = openSync(tmp, "r+"); try { fsyncSync(fd); } finally { closeSync(fd); } }
    renameSync(tmp, join(rootDir, "CURRENT"));
    { const fd = openSync(rootDir, "r"); try { fsyncSync(fd); } finally { closeSync(fd); } }
    return new Store(rootDir, dir, db);
  }

  close(): void { this.db.close(); }

  /** One-writer transaction scope for maintenance commands. */
  inWriterPublic<T>(fn: () => T): T {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const r = fn();
      this.db.exec("COMMIT");
      return r;
    } catch (e) {
      try { this.db.exec("ROLLBACK"); } catch { /* no tx */ }
      throw e;
    }
  }

  // ---------- meta ----------

  metaGet(k: string): Json | undefined {
    const r = this.db.prepare("SELECT v FROM meta WHERE k=?").get(k) as { v: Uint8Array } | undefined;
    return r ? parseJson(Buffer.from(r.v), LIMITS_BUNDLE) : undefined;
  }
  metaSet(k: string, v: Json): void {
    this.db.prepare("INSERT OR REPLACE INTO meta(k,v) VALUES(?,?)").run(k, jcsBytes(v));
  }
  get workspace(): string { return this.metaGet("workspace") as string; }
  get activeAuditKey(): string { return this.metaGet("active_audit_key") as string; }
  get clockFloor(): bigint { return BigInt((this.metaGet("clock_floor_ms") as string | undefined) ?? "0"); }

  /** Persisted nondecreasing wall-clock floor (§7): effective = max(floor, os). */
  effectiveClock(osMs: bigint): bigint {
    const floor = this.clockFloor;
    const eff = osMs > floor ? osMs : floor;
    if (eff !== floor) this.metaSet("clock_floor_ms", eff.toString());
    return eff;
  }

  // ---------- audit ----------

  auditHead(): AuditRef | null {
    const r = this.db.prepare("SELECT seq,hash FROM audit ORDER BY seq DESC LIMIT 1").get() as
      { seq: number | bigint; hash: string } | undefined;
    return r ? { seq: BigInt(r.seq).toString(), hash: r.hash } : null;
  }

  auditAt(seq: bigint): Audit | null {
    const r = this.db.prepare("SELECT canonical FROM audit WHERE seq=?").get(seq) as { canonical: Uint8Array } | undefined;
    return r ? (parseJson(Buffer.from(r.canonical), LIMITS_BUNDLE) as unknown as Audit) : null;
  }

  auditPrefix(through: bigint): Audit[] {
    const rows = this.db.prepare("SELECT canonical FROM audit WHERE seq<=? ORDER BY seq").all(through) as { canonical: Uint8Array }[];
    return rows.map((r) => parseJson(Buffer.from(r.canonical), LIMITS_BUNDLE) as unknown as Audit);
  }

  auditCount(): bigint {
    const r = this.db.prepare("SELECT count(*) AS c FROM audit").get() as { c: number | bigint };
    return BigInt(r.c);
  }

  /** Append one audit record inside the caller's transaction. */
  appendAudit(signer: AuditSigner, principal: string, request: string, data: AuditData): Audit {
    const head = this.auditHead();
    const seq = head ? (BigInt(head.seq) + 1n).toString() : "1";
    const prev = head ? head.hash : ZERO_HASH;
    const body = {
      v: 1, workspace: this.workspace, seq, prev,
      key: signer.keyId, principal, request, data,
    };
    const hash = auditHash(body as unknown as Json);
    const signature = b64uEncode(signMessage(signer.keyObject, signingMessage(D_AUDIT_SIGN, hash)));
    const audit: Audit = { body: body as unknown as Audit["body"], hash, signature };
    this.db.prepare("INSERT INTO audit(seq,hash,prev,key_id,canonical) VALUES(?,?,?,?,?)")
      .run(BigInt(seq), hash, prev, signer.keyId, jcsBytes(audit as unknown as Json));
    return audit;
  }

  ensureKey(k: KeyMaterial): void {
    this.db.prepare("INSERT OR IGNORE INTO keys(id,canonical) VALUES(?,?)")
      .run(k.id, jcsBytes(k as unknown as Json));
  }

  keyById(id: string): KeyMaterial | null {
    const r = this.db.prepare("SELECT canonical FROM keys WHERE id=?").get(id) as { canonical: Uint8Array } | undefined;
    return r ? (parseJson(Buffer.from(r.canonical), LIMITS_BUNDLE) as unknown as KeyMaterial) : null;
  }

  allKeys(): KeyMaterial[] {
    const rows = this.db.prepare("SELECT canonical FROM keys").all() as { canonical: Uint8Array }[];
    return rows.map((r) => parseJson(Buffer.from(r.canonical), LIMITS_BUNDLE) as unknown as KeyMaterial);
  }

  // ---------- init ----------

  /** proof init: WorkspaceCreated at audit seq 1, revision 0. */
  initWorkspace(args: {
    workspace: string; configDigest: string; signer: AuditSigner;
    principal: string; request: string;
  }): { audit: Audit; revision: Revision } {
    if (this.currentRevision() >= 0n) throw new ProofError("OBJECT_CONFLICT", "Store is already initialized.");
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.metaSet("workspace", args.workspace);
      this.metaSet("schema", STORE_SCHEMA);
      this.metaSet("active_audit_key", args.signer.keyId);
      this.metaSet("config", args.configDigest);
      this.metaSet("clock_floor_ms", "0");
      this.ensureKey(args.signer.material);
      const evidence = computeEvidence([], [], [], []);
      const audit = this.appendAudit(args.signer, args.principal, args.request, {
        kind: "WorkspaceCreated", config: args.configDigest, revision: "0", evidence,
      });
      const manifest = {
        sources: [] as Source[], keys: [args.signer.material],
        objects: [] as ObjectRef[], cuts: [] as Cut[], audit: auditRefOf(audit),
      };
      this.db.prepare("INSERT INTO revisions(revision,evidence,manifest,audit_seq) VALUES(0,?,?,1)")
        .run(evidence, jcsBytes(manifest as unknown as Json));
      const proj = replay([], []).projection;
      this.db.prepare("INSERT INTO projections(revision,hash,canonical) VALUES(0,?,?)")
        .run(projectionHash(proj as unknown as Json), jcsBytes(proj as unknown as Json));
      this.db.exec("COMMIT");
      this.writeRecoveryHead();
      return {
        audit,
        revision: { revision: "0", evidence, cuts: [], events: 0, audit: auditRefOf(audit) },
      };
    } catch (e) {
      try { this.db.exec("ROLLBACK"); } catch { /* already rolled back */ }
      throw e;
    }
  }

  /** The in-store convenience copy of the latest audit head (§5.1). */
  writeRecoveryHead(): void {
    const head = this.auditHead();
    if (!head) return;
    const p = join(this.dir, "recovery-head.json");
    const tmp = `${p}.tmp`;
    const fd = openSync(tmp, "w", 0o600);
    try { writeSync(fd, jcsBytes(head as unknown as Json)); fsyncSync(fd); } finally { closeSync(fd); }
    renameSync(tmp, p);
  }

  // ---------- sources ----------

  sourceGet(id: string): Source | null {
    const r = this.db.prepare("SELECT canonical FROM sources WHERE id=?").get(id) as { canonical: Uint8Array } | undefined;
    return r ? (parseJson(Buffer.from(r.canonical), LIMITS_BUNDLE) as unknown as Source) : null;
  }

  sourceList(): Source[] {
    const rows = this.db.prepare("SELECT canonical FROM sources ORDER BY id").all() as { canonical: Uint8Array }[];
    return rows.map((r) => parseJson(Buffer.from(r.canonical), LIMITS_BUNDLE) as unknown as Source);
  }

  // ---------- events / objects ----------

  eventByHash(hash: string): Event | null {
    const r = this.db.prepare("SELECT canonical FROM events WHERE hash=?").get(hash) as { canonical: Uint8Array } | undefined;
    return r ? (parseJson(Buffer.from(r.canonical), LIMITS_BUNDLE) as unknown as Event) : null;
  }

  allEvents(): Event[] {
    const rows = this.db.prepare("SELECT canonical FROM events").all() as { canonical: Uint8Array }[];
    return rows.map((r) => parseJson(Buffer.from(r.canonical), LIMITS_BUNDLE) as unknown as Event);
  }

  eventsAtRevision(rev: bigint): Event[] {
    const rows = this.db.prepare(
      "SELECT e.canonical FROM events e JOIN revision_events re ON e.hash=re.event_hash WHERE re.revision=?",
    ).all(rev) as { canonical: Uint8Array }[];
    const evs = rows.map((r) => parseJson(Buffer.from(r.canonical), LIMITS_BUNDLE) as unknown as Event);
    return sortEvents(evs);
  }

  objectRow(digest: string): { bytes: bigint; media: string; available: boolean } | null {
    const r = this.db.prepare("SELECT bytes,media,available FROM objects WHERE digest=?").get(digest) as
      { bytes: number | bigint; media: string; available: number } | undefined;
    return r ? { bytes: BigInt(r.bytes), media: r.media, available: r.available === 1 } : null;
  }

  objectBlob(digest: string): BlobT | null {
    const row = this.objectRow(digest);
    if (!row || !row.available) return null;
    const bytes = this.readObjectBytes(digest);
    if (!bytes) return null;
    return { ref: { digest, bytes: row.bytes.toString(), media: row.media as never }, content: b64uEncode(bytes) };
  }

  private insertEvent(e: Event): void {
    this.db.prepare("INSERT OR IGNORE INTO events(hash,source,stream,seq,prev,key_id,canonical) VALUES(?,?,?,?,?,?,?)")
      .run(e.hash, e.body.source, e.body.stream, BigInt(e.body.seq), e.body.prev, e.body.key, jcsBytes(e as unknown as Json));
    for (const p of e.body.parents) {
      this.db.prepare("INSERT OR IGNORE INTO event_parents(child,source,stream,seq,parent_hash) VALUES(?,?,?,?,?)")
        .run(e.hash, p.source, p.stream, BigInt(p.seq), p.hash);
    }
    for (const ref of eventDataObjectRefs(e.body.data)) {
      this.db.prepare("INSERT OR IGNORE INTO event_objects(event_hash,digest) VALUES(?,?)").run(e.hash, ref.digest);
    }
  }

  private upsertObjectDescriptor(ref: ObjectRef, available: boolean): void {
    const cur = this.objectRow(ref.digest);
    if (cur) {
      if (cur.bytes !== BigInt(ref.bytes) || cur.media !== ref.media) {
        throw new ProofError("OBJECT_CONFLICT", "Object descriptor conflict.");
      }
      if (available && !cur.available) {
        this.db.prepare("UPDATE objects SET available=1 WHERE digest=?").run(ref.digest);
      }
      return;
    }
    this.db.prepare("INSERT INTO objects(digest,bytes,media,available) VALUES(?,?,?,?)")
      .run(ref.digest, BigInt(ref.bytes), ref.media, available ? 1 : 0);
  }

  // ---------- revisions ----------

  currentRevision(): bigint {
    const r = this.db.prepare("SELECT max(revision) AS r FROM revisions").get() as { r: number | bigint | null };
    return r.r === null ? -1n : BigInt(r.r);
  }

  revisionRow(rev: bigint): { evidence: string; manifest: RevisionManifest; audit_seq: bigint } | null {
    const r = this.db.prepare("SELECT evidence,manifest,audit_seq FROM revisions WHERE revision=?").get(rev) as
      { evidence: string; manifest: Uint8Array; audit_seq: number | bigint } | undefined;
    if (!r) return null;
    return {
      evidence: r.evidence,
      manifest: parseJson(Buffer.from(r.manifest), LIMITS_BUNDLE) as unknown as RevisionManifest,
      audit_seq: BigInt(r.audit_seq),
    };
  }

  revisionView(rev: bigint): Revision | null {
    const row = this.revisionRow(rev);
    if (!row) return null;
    const events = this.eventsAtRevision(rev);
    const count = this.db.prepare("SELECT count(*) AS c FROM revision_events WHERE revision=?").get(rev) as { c: number | bigint };
    return {
      revision: rev.toString(), evidence: row.evidence,
      cuts: row.manifest.cuts, events: Number(count.c), audit: row.manifest.audit,
    };
  }

  projectionAt(rev: bigint): { hash: string; projection: Projection } | null {
    const r = this.db.prepare("SELECT hash,canonical FROM projections WHERE revision=?").get(rev) as
      { hash: string; canonical: Uint8Array } | undefined;
    return r ? { hash: r.hash, projection: parseJson(Buffer.from(r.canonical), LIMITS_BUNDLE) as unknown as Projection } : null;
  }

  // ---------- stages ----------

  stageGet(id: string): StageRow | null {
    const r = this.db.prepare("SELECT principal,batch_hash,canonical,state,created_ms,terminal_result FROM stages WHERE id=?")
      .get(id) as { principal: string; batch_hash: string; canonical: Uint8Array | null; state: StageRow["state"]; created_ms: number | bigint; terminal_result: Uint8Array | null } | undefined;
    if (!r) return null;
    return {
      principal: r.principal, batch_hash: r.batch_hash,
      canonical: r.canonical ? Buffer.from(r.canonical) : null,
      state: r.state, created_ms: BigInt(r.created_ms),
      terminal_result: r.terminal_result ? parseJson(Buffer.from(r.terminal_result), LIMITS_BUNDLE) : null,
    };
  }

  stageInsert(id: string, principal: string, batchHash: string, canonical: Buffer, createdMs: bigint): void {
    this.db.prepare("INSERT INTO stages(id,principal,batch_hash,canonical,state,created_ms) VALUES(?,?,?,?,'STAGED',?)")
      .run(id, principal, batchHash, canonical, createdMs);
  }

  stageTerminal(id: string, state: "COMMITTED" | "CANCELLED", result: Json): void {
    this.db.prepare("UPDATE stages SET state=?, canonical=NULL, terminal_result=? WHERE id=?")
      .run(state, jcsBytes(result), id);
  }

  liveStages(now: bigint, ttlMs: bigint): string[] {
    const rows = this.db.prepare("SELECT id,created_ms FROM stages WHERE state='STAGED'").all() as
      { id: string; created_ms: number | bigint }[];
    return rows.filter((r) => now - BigInt(r.created_ms) >= ttlMs).map((r) => r.id);
  }

  // ---------- idempotency ----------

  requestGet(principal: string, id: string): { request_hash: string; result: Json } | null {
    const r = this.db.prepare("SELECT request_hash,result FROM requests WHERE principal=? AND id=?")
      .get(principal, id) as { request_hash: string; result: Uint8Array } | undefined;
    return r ? { request_hash: r.request_hash, result: parseJson(Buffer.from(r.result), LIMITS_BUNDLE) } : null;
  }

  requestPut(principal: string, id: string, requestHash: string, result: Json): void {
    this.db.prepare("INSERT OR IGNORE INTO requests(principal,id,request_hash,result) VALUES(?,?,?,?)")
      .run(principal, id, requestHash, jcsBytes(result));
  }

  // ---------- publication (§6.3) ----------

  /**
   * Commit a staged batch into a new revision inside one writer transaction.
   * Steps: rechecks → object durability already done at stage → insert
   * evidence rows → evidence root + projection → binding audit record →
   * revision + membership + manifest → terminal result + tombstone → COMMIT.
   *
   * `fail` simulates a crash at the named barrier for conformance.
   */
  commitBatch(args: {
    stage: string; batch: Batch; signer: AuditSigner; principal: string; request: string;
    expectedRevision: bigint; fail?: Failpoint;
  }): { revision: Revision; added: number; duplicates: number; conflicts: number; audit: Audit } {
    const { batch } = args;
    const st = this.stageGet(args.stage)!;
    // Terminal-state and revision rechecks happen here inside the writer tx.
    if (st.state !== "STAGED") throw new ProofError("STAGE_STATE", "Stage is terminal.");
    if (this.currentRevision() !== args.expectedRevision) {
      throw new ProofError("REVISION_CONFLICT", "expected_revision does not match.");
    }
    // Descriptors precede event rows: event_objects has an FK into objects.
    let added = 0, duplicates = 0, conflicts = 0;
    for (const k of batch.keys) this.ensureKey(k);
    const newRefs = new Map<string, ObjectRef>();
    for (const e of batch.events) {
      if (this.eventByHash(e.hash) === null) {
        for (const r of eventDataObjectRefs(e.body.data)) newRefs.set(r.digest, r);
      }
    }
    for (const b of batch.objects) newRefs.set(b.ref.digest, b.ref);
    // Availability only where durable bytes exist (§6.3: fsync before reference).
    for (const ref of newRefs.values()) {
      const blob = batch.objects.find((o) => o.ref.digest === ref.digest);
      const durable = blob ? true : this.readObjectBytes(ref.digest) !== null;
      this.upsertObjectDescriptor(ref, durable);
    }
    // Insert new evidence rows (forks and all — retained as candidates).
    for (const e of batch.events) {
      const exists = this.eventByHash(e.hash) !== null;
      if (exists) { duplicates++; continue; }
      const slot = this.db.prepare("SELECT count(*) AS c FROM events WHERE source=? AND stream=? AND seq=?")
        .get(e.body.source, e.body.stream, BigInt(e.body.seq)) as { c: number | bigint };
      if (BigInt(slot.c) > 0n) conflicts++;
      this.insertEvent(e);
      added++;
    }
    // Evidence root + pure projection over the full candidate set.
    const all = this.allEvents();
    const refs = distinctObjectRefs(all);
    const originKeys = sortKeys(
      this.allKeys().filter((k) => new Set(all.map((e) => e.body.key)).has(k.id)),
    );
    const evidence = computeEvidence(this.sourceList(), all, originKeys, refs);
    const { projection } = replay(all, chainCheck(all).findings);
    if (projection.edges.length > 200000) throw new ProofError("EVENT_LIMIT", "Projection exceeds edge bound.");
    // Publishability bound: projected FULL bundle ≤64 MiB and ≤140000 items.
    const auditSeqNext = (this.auditHead() ? BigInt(this.auditHead()!.seq) : 0n) + 1n;
    const items = all.length + Number(auditSeqNext) + (originKeys.length + 1) + refs.length;
    if (items > 140000) throw new ProofError("BUNDLE_LIMIT", "Projected inventory exceeds cap.");
    const rev = this.currentRevision() + 1n;
    // Binding audit record.
    const audit = this.appendAudit(args.signer, args.principal, args.request, {
      kind: "ImportCommitted", stage: args.stage, batch: st.batch_hash,
      revision: rev.toString(), evidence,
    });
    if (args.fail === "after_audit_sign_before_commit") throw new Crash(args.fail);
    // Revision + cumulative membership + manifest + projection.
    const auditKeys = this.auditPrefix(auditSeqNext).map((a) => a.body.key);
    const manifestKeys = sortKeys(this.allKeys().filter((k) =>
      new Set([...all.map((e) => e.body.key), ...auditKeys]).has(k.id)));
    const manifest = {
      sources: this.sourceList(), keys: manifestKeys, objects: refs,
      cuts: computeCuts(all), audit: auditRefOf(audit),
    };
    this.db.prepare("INSERT INTO revisions(revision,evidence,manifest,audit_seq) VALUES(?,?,?,?)")
      .run(rev, evidence, jcsBytes(manifest as unknown as Json), BigInt(audit.body.seq));
    for (const e of all) {
      this.db.prepare("INSERT INTO revision_events(revision,event_hash) VALUES(?,?)").run(rev, e.hash);
    }
    this.db.prepare("INSERT INTO projections(revision,hash,canonical) VALUES(?,?,?)")
      .run(rev, projectionHash(projection as unknown as Json), jcsBytes(projection as unknown as Json));
    const revision: Revision = {
      revision: rev.toString(), evidence, cuts: computeCuts(all),
      events: all.length, audit: auditRefOf(audit),
    };
    return { revision, added, duplicates, conflicts, audit };
  }

  /** Register a source + publish the next revision inside one transaction. */
  registerSourceTx(args: {
    source: Source; signer: AuditSigner; principal: string; request: string;
  }): { source: Source; revision: Revision; audit: Audit } {
    const rev = this.currentRevision() + 1n;
    this.db.prepare("INSERT INTO sources(id,canonical,registered_revision) VALUES(?,?,?)")
      .run(args.source.id, jcsBytes(args.source as unknown as Json), rev);
    const all = this.allEvents();
    const refs = distinctObjectRefs(all);
    const originKeys = sortKeys(this.allKeys().filter((k) => new Set(all.map((e) => e.body.key)).has(k.id)));
    const evidence = computeEvidence(this.sourceList(), all, originKeys, refs);
    const { projection } = replay(all, chainCheck(all).findings);
    const audit = this.appendAudit(args.signer, args.principal, args.request, {
      kind: "SourceRegistered", source: args.source, revision: rev.toString(), evidence,
    });
    const auditKeys = this.auditPrefix(BigInt(audit.body.seq)).map((a) => a.body.key);
    const manifestKeys = sortKeys(this.allKeys().filter((k) =>
      new Set([...all.map((e) => e.body.key), ...auditKeys]).has(k.id)));
    const manifest = {
      sources: this.sourceList(), keys: manifestKeys, objects: refs,
      cuts: computeCuts(all), audit: auditRefOf(audit),
    };
    this.db.prepare("INSERT INTO revisions(revision,evidence,manifest,audit_seq) VALUES(?,?,?,?)")
      .run(rev, evidence, jcsBytes(manifest as unknown as Json), BigInt(audit.body.seq));
    for (const e of all) {
      this.db.prepare("INSERT INTO revision_events(revision,event_hash) VALUES(?,?)").run(rev, e.hash);
    }
    this.db.prepare("INSERT INTO projections(revision,hash,canonical) VALUES(?,?,?)")
      .run(rev, projectionHash(projection as unknown as Json), jcsBytes(projection as unknown as Json));
    const revision: Revision = {
      revision: rev.toString(), evidence, cuts: computeCuts(all),
      events: all.length, audit: auditRefOf(audit),
    };
    return { source: args.source, revision, audit };
  }
}

export interface RevisionManifest {
  sources: Source[]; keys: KeyMaterial[]; objects: ObjectRef[]; cuts: Cut[]; audit: AuditRef;
}

export function stageClockEffective(createdMs: bigint, persistedFloorMs: bigint, osMs: bigint, ttlMs: bigint): {
  effective_ms: string; expired: boolean;
} {
  const eff = persistedFloorMs > osMs ? persistedFloorMs : osMs;
  return { effective_ms: eff.toString(), expired: eff - createdMs >= ttlMs };
}
