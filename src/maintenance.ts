/**
 * Offline maintenance (§4.1, §5.2, §6.4): recovery verdicts, backup, restore,
 * key rotation, and the schema 1→1 identity migration. All commands run
 * against a stopped writer and take explicit --principal/--request-id where
 * they append audit records.
 */

import {
  existsSync, mkdirSync, readdirSync, readFileSync, lstatSync,
  openSync, writeSync, fsyncSync, closeSync, renameSync, copyFileSync, statSync,
} from "node:fs";
import { join, dirname, resolve, relative, isAbsolute } from "node:path";
import { ProofError } from "./errors.js";
import { jcsBytes, jcsString, parseJson, LIMITS_1MIB, type Json } from "./canon.js";
import {
  sha256Hex, hashJson, domainHash, signMessage, verifyMessage, auditHash,
  decodePublicKey, b64uEncode, rotateProofDigest, D_BACKUP, D_MIGRATION,
} from "./crypto.js";
import {
  parseAuditRef, parseTrust, parseKeyMaterial, auditRefOf, isObj, requireFields, checkId,
  type Audit, type AuditRef, type KeyMaterial, type Trust,
} from "./model.js";
import { auditChainFindings } from "./verify.js";
import { signatureValid } from "./trust.js";
import { Store, type AuditSigner } from "./store.js";
import type { Config } from "./config.js";

// ---------- backup paths ----------

/**
 * §5.2 path rules: relative ASCII slash-separated, no empty/dot/dot-dot/
 * backslash/NUL/absolute components, regular files only — no symlinks.
 */
export function backupPathCheck(entry: { path: string; kind: string }): "OK" | "REQUEST_INVALID" {
  const p = entry.path;
  if (typeof p !== "string" || p.length === 0 || p.length > 4096) return "REQUEST_INVALID";
  if (entry.kind !== "regular") return "REQUEST_INVALID";
  if (!/^[\x20-\x7e]+$/.test(p)) return "REQUEST_INVALID";
  if (p.startsWith("/") || p.endsWith("/") || p.includes("\\") || p.includes("\0")) return "REQUEST_INVALID";
  const parts = p.split("/");
  if (parts.some((x) => x === "" || x === "." || x === "..")) return "REQUEST_INVALID";
  return "OK";
}

// ---------- recovery ----------

export interface RecoveryVerdict {
  state: "READY" | "READ_ONLY";
  code: "OK" | "RECOVERY_REQUIRED";
  writes: number;
}

/**
 * Compare the database audit chain against an independently retained
 * required head (§6.4). A pin ahead of the database, a hash mismatch at the
 * pinned position, or a broken prefix forces READ_ONLY.
 */
export function recoverCheck(args: {
  databaseAudit: Audit[]; requiredHead: AuditRef | null; trustOk: boolean;
}): RecoveryVerdict {
  const { databaseAudit, requiredHead } = args;
  // Chain shape: seq 1..n, prev links, signatures checked by caller via
  // auditChainFindings — here we verify contiguity and the pinned prefix.
  for (let i = 0; i < databaseAudit.length; i++) {
    if (databaseAudit[i]!.body.seq !== String(i + 1)) {
      return { state: "READ_ONLY", code: "RECOVERY_REQUIRED", writes: 0 };
    }
  }
  if (requiredHead) {
    const pinSeq = BigInt(requiredHead.seq);
    if (pinSeq > BigInt(databaseAudit.length)) {
      return { state: "READ_ONLY", code: "RECOVERY_REQUIRED", writes: 0 };
    }
    const at = databaseAudit[Number(pinSeq) - 1];
    if (!at || at.hash !== requiredHead.hash) {
      return { state: "READ_ONLY", code: "RECOVERY_REQUIRED", writes: 0 };
    }
  }
  return { state: "READY", code: "OK", writes: 0 };
}

/**
 * Startup recovery against the configured recovery trust file: verifies the
 * stored audit chain and compares the independent audit head pin.
 */
export function recoverStore(store: Store, trust: Trust | null): RecoveryVerdict {
  const head = store.auditHead();
  if (!head) return { state: "READ_ONLY", code: "RECOVERY_REQUIRED", writes: 0 };
  const entries = store.auditPrefix(BigInt(head.seq));
  if (auditChainFindings(entries).length) {
    return { state: "READ_ONLY", code: "RECOVERY_REQUIRED", writes: 0 };
  }
  // Re-verify every audit signature against the retained key table and check
  // hash recomputation — canonical bytes are authoritative, caches are not.
  const keys = new Map(store.allKeys().map((k) => [k.id, k]));
  for (const a of entries) {
    const k = keys.get(a.body.key);
    if (!k || a.hash !== auditHash(a.body as unknown as Json) ||
        !signatureValid(a, k, "audit")) {
      return { state: "READ_ONLY", code: "RECOVERY_REQUIRED", writes: 0 };
    }
  }
  if (trust) {
    const pin = trust.heads.find((h) => h.role === "audit" && BigInt(h.seq) > 0n) ?? null;
    return recoverCheck({ databaseAudit: entries, requiredHead: pin ? { seq: pin.seq, hash: pin.hash } : null, trustOk: true });
  }
  return { state: "READY", code: "OK", writes: 0 };
}

// ---------- backup ----------

export interface BackupFile { path: string; bytes: string; digest: string }
export interface BackupManifest {
  v: 1; workspace: string; schema: number; audit: AuditRef;
  revisions: { revision: string; evidence: string }[];
  files: BackupFile[]; config: string; digest: string;
}

function* walk(dir: string, base: string): Generator<string> {
  for (const name of readdirSync(dir).sort()) {
    const p = join(dir, name);
    const st = lstatSync(p);
    if (st.isDirectory()) yield* walk(p, base);
    else if (st.isFile()) yield relative(base, p);
  }
}

/** Stopped-writer backup: checkpoint, copy, reread every byte, manifest. */
export function backupStore(store: Store, cfg: Config, outDir: string): BackupManifest {
  if (existsSync(outDir) && readdirSync(outDir).length > 0) {
    throw new ProofError("OBJECT_CONFLICT", "Backup output directory is nonempty.");
  }
  mkdirSync(outDir, { recursive: true, mode: 0o700 });
  // Checkpoint the WAL into the main file (writer stopped), then copy.
  store.db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
  const dbName = Store.dbDirOf(store.rootDir)!;
  const src = join(store.rootDir, dbName);
  const dest = join(outDir, dbName);
  mkdirSync(dest, { recursive: true });
  copyFileSync(join(src, "proof.sqlite3"), join(dest, "proof.sqlite3"));
  // Objects: copy the verified content-addressed tree.
  const objSrc = join(src, "objects");
  if (existsSync(objSrc)) {
    for (const rel of walk(objSrc, src)) {
      const to = join(outDir, dbName, rel);
      mkdirSync(dirname(to), { recursive: true });
      copyFileSync(join(src, rel), to);
    }
  }
  const rh = join(src, "recovery-head.json");
  if (existsSync(rh)) copyFileSync(rh, join(dest, "recovery-head.json"));

  // Reread every copied file; validate path rules; digest each.
  const files: BackupFile[] = [];
  const manifestFiles = new Set<string>();
  for (const rel of walk(outDir, outDir)) {
    const entry = { path: rel.split("/").join("/"), kind: "regular" };
    if (backupPathCheck(entry) !== "OK") throw new ProofError("REQUEST_INVALID", "Backup path violates §5.2 rules.");
    const bytes = readFileSync(join(outDir, rel));
    manifestFiles.add(rel);
    files.push({ path: rel, bytes: String(bytes.length), digest: sha256Hex(bytes) });
  }
  files.sort((a, b) => (a.path < b.path ? -1 : 1));

  const head = store.auditHead();
  if (!head) throw new ProofError("RECOVERY_REQUIRED", "No audit head to back up.");
  const revs: { revision: string; evidence: string }[] = [];
  for (let r = 0n; r <= store.currentRevision(); r++) {
    const row = store.revisionRow(r);
    if (row) revs.push({ revision: r.toString(), evidence: row.evidence });
  }
  const manifest: Omit<BackupManifest, "digest"> = {
    v: 1, workspace: cfg.workspace, schema: 1, audit: head,
    revisions: revs, files, config: hashJson(cfg as unknown as Json),
  };
  const digest = domainHash(D_BACKUP, manifest as unknown as Json);
  const full: BackupManifest = { ...manifest, digest };
  writeAtomic(join(outDir, "manifest.json"), jcsBytes(full as unknown as Json));
  return full;
}

function writeAtomic(path: string, bytes: Uint8Array): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const tmp = `${path}.tmp-${process.pid}`;
  const fd = openSync(tmp, "wx", 0o600);
  try { writeSync(fd, bytes); fsyncSync(fd); } finally { closeSync(fd); }
  renameSync(tmp, path);
}

/** Restore into a NEW directory; never write-ready until head reconciliation. */
export function restoreStore(backupDir: string, outDir: string): { state: "RESTORED"; manifest: string; write_ready: false } {
  const mraw = readFileSync(join(backupDir, "manifest.json"));
  const manifest = parseJson(mraw, LIMITS_1MIB) as unknown as BackupManifest;
  // Verify the manifest digest (digest omitted from the hashed view).
  const { digest, ...rest } = manifest;
  if (domainHash(D_BACKUP, rest as unknown as Json) !== digest) {
    throw new ProofError("HASH_MISMATCH", "Backup manifest digest mismatch.");
  }
  if (existsSync(outDir) && readdirSync(outDir).length > 0) {
    throw new ProofError("OBJECT_CONFLICT", "Restore output directory is nonempty.");
  }
  for (const f of manifest.files) {
    if (backupPathCheck({ path: f.path, kind: "regular" }) !== "OK") {
      throw new ProofError("REQUEST_INVALID", "Backup manifest contains an illegal path.");
    }
    const from = join(backupDir, f.path);
    const bytes = readFileSync(from);
    if (sha256Hex(bytes) !== f.digest || String(bytes.length) !== f.bytes) {
      throw new ProofError("HASH_MISMATCH", `Backup file ${f.path} does not match its manifest entry.`);
    }
    const to = join(outDir, f.path);
    mkdirSync(dirname(to), { recursive: true, mode: 0o700 });
    writeAtomic(to, bytes);
  }
  return { state: "RESTORED", manifest: digest, write_ready: false };
}

// ---------- key rotation ----------

/**
 * Stopped-writer rotation (§4.1, §1.5): CAS on the exact audit head, the new
 * key proves possession over D_ROTATE{workspace,old,next,head}, the old key
 * signs the KeyRotated record, and meta.active_audit_key advances.
 */
export function rotateKey(args: {
  store: Store; oldSigner: AuditSigner; newMaterial: KeyMaterial; newKeyObject: import("node:crypto").KeyObject;
  expectedHead: AuditRef; principal: string; request: string;
}): { state: "ROTATED"; old: string; next: string; audit: AuditRef } {
  const { store } = args;
  const head = store.auditHead();
  if (!head || head.seq !== args.expectedHead.seq || head.hash !== args.expectedHead.hash) {
    throw new ProofError("REVISION_CONFLICT", "expected head does not match the audit head.");
  }
  if (args.newMaterial.id === args.oldSigner.keyId) {
    throw new ProofError("KEY_MATERIAL_INVALID", "Rotation requires a distinct key.");
  }
  // Possession proof under the NEW key: an Ed25519 signature over the raw
  // D("LAGI-PROOF-ROTATE/v1",{workspace,old,next,head}) digest bytes, head
  // equal to the record's own prev (§1.5).
  const proofDigest = rotateProofDigest(store.workspace, args.oldSigner.keyId, args.newMaterial as unknown as Json, head.hash);
  const msg = Buffer.from(proofDigest, "hex");
  const proof = signMessage(args.newKeyObject, msg);
  const pub = decodePublicKey(args.newMaterial.public);
  if (!verifyMessage(pub, msg, proof)) throw new ProofError("KEY_MATERIAL_INVALID", "New key possession proof failed.");

  return store.inWriterPublic(() => {
    store.ensureKey(args.newMaterial);
    const audit = store.appendAudit(args.oldSigner, args.principal, args.request, {
      kind: "KeyRotated", old: args.oldSigner.keyId, next: args.newMaterial, proof: b64uEncode(proof),
    });
    store.metaSet("active_audit_key", args.newMaterial.id);
    store.writeRecoveryHead();
    return { state: "ROTATED" as const, old: args.oldSigner.keyId, next: args.newMaterial.id, audit: auditRefOf(audit) };
  });
}

// ---------- identity migration (schema 1→1) ----------

export interface MigrationManifest {
  v: 1; workspace: string; from_schema: number; to_schema: number;
  source_head: AuditRef; backup: string; destination: string;
  evidence_roots: { revision: string; evidence: string }[];
  state: "PLANNED" | "COPIED" | "VERIFIED" | "ACTIVATED" | "FAILED";
  failed_phase: "COPY" | "VERIFY" | "ACTIVATE" | null;
  digest: string;
}

function migrationDigest(m: Omit<MigrationManifest, "digest">): string {
  return domainHash(D_MIGRATION, m as unknown as Json);
}

function writeManifest(dir: string, m: MigrationManifest): string {
  const name = `migration-${m.state.toLowerCase()}.json`;
  writeAtomic(join(dir, name), jcsBytes(m as unknown as Json));
  return m.digest;
}

/**
 * Offline copy-on-write migration (§10): the only compiled migration is the
 * schema 1→1 identity rebuild. The source selection is never changed; a
 * failure publishes a FAILED manifest and leaves CURRENT untouched.
 */
export function migrateStore(args: {
  store: Store; cfg: Config; targetSchema: number; outDir: string;
  kill?: "before_current_switch" | null;
}): MigrationManifest {
  const { store, cfg, targetSchema, outDir } = args;
  if (targetSchema !== 1) {
    throw new ProofError("UNSUPPORTED_VERSION", "Only schema 1 is compiled.");
  }
  const head = store.auditHead();
  if (!head) throw new ProofError("RECOVERY_REQUIRED", "No audit head.");
  const roots: { revision: string; evidence: string }[] = [];
  for (let r = 0n; r <= store.currentRevision(); r++) {
    const row = store.revisionRow(r);
    if (row) roots.push({ revision: r.toString(), evidence: row.evidence });
  }
  const publish = (state: MigrationManifest["state"], phase: MigrationManifest["failed_phase"]): MigrationManifest => {
    const body: Omit<MigrationManifest, "digest"> = {
      v: 1, workspace: cfg.workspace, from_schema: 1, to_schema: targetSchema,
      source_head: head, backup: "", destination: outDir,
      evidence_roots: roots, state, failed_phase: phase,
    };
    const m: MigrationManifest = { ...body, digest: migrationDigest(body) };
    writeManifest(outDir, m);
    return m;
  };

  if (existsSync(outDir) && readdirSync(outDir).length > 0) {
    throw new ProofError("OBJECT_CONFLICT", "Migration destination is nonempty.");
  }
  mkdirSync(outDir, { recursive: true, mode: 0o700 });
  publish("PLANNED", null);

  const fail = (phase: "COPY" | "VERIFY" | "ACTIVATE", e: unknown): never => {
    publish("FAILED", phase);
    throw e instanceof ProofError ? e : new ProofError("STORAGE_UNAVAILABLE", `Migration failed at ${phase}.`);
  };

  // COPY: checkpoint, byte-for-byte copies of canonical store content.
  try {
    store.db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
    const dbName = Store.dbDirOf(store.rootDir)!;
    const src = join(store.rootDir, dbName);
    const dest = join(outDir, "db-0001");
    mkdirSync(dest, { recursive: true });
    copyFileSync(join(src, "proof.sqlite3"), join(dest, "proof.sqlite3"));
    const objSrc = join(src, "objects");
    if (existsSync(objSrc)) {
      for (const rel of walk(objSrc, src)) {
        const to = join(dest, rel);
        mkdirSync(dirname(to), { recursive: true });
        copyFileSync(join(src, rel), to);
      }
    }
    publish("COPIED", null);
  } catch (e) { fail("COPY", e); }

  if (args.kill === "before_current_switch") {
    // Stopped before CURRENT exists in the destination: source still selected.
    publish("VERIFIED", null);
    throw new ProofError("STORAGE_UNAVAILABLE", "Killed before CURRENT switch.");
  }

  // VERIFY: reopen the copy and compare every revision root and the head.
  try {
    const copied = Store.openAt(outDir, join(outDir, "db-0001"));
    try {
      for (const r of roots) {
        const row = copied.revisionRow(BigInt(r.revision));
        if (!row || row.evidence !== r.evidence) throw new ProofError("HASH_MISMATCH", "Evidence root mismatch.");
      }
      const srcHead = store.auditHead()!, dstHead = copied.auditHead()!;
      if (srcHead.seq !== dstHead.seq || srcHead.hash !== dstHead.hash) {
        throw new ProofError("HASH_MISMATCH", "Audit head mismatch.");
      }
    } finally {
      copied.close();
    }
  } catch (e) { fail("VERIFY", e); }

  return publish("VERIFIED", null);
}

/**
 * Activate a VERIFIED migration: CAS the source head, write the durable
 * MigrationActivated record into the destination, then atomically switch
 * CURRENT. A crash before the switch leaves the old selection.
 */
export function migrateActivate(args: {
  srcRoot: string; destDir: string; manifest: MigrationManifest; expectedHead: AuditRef;
  signer: AuditSigner; principal: string; request: string;
}): MigrationManifest {
  const src = Store.open(args.srcRoot);
  try {
    const head = src.auditHead();
    if (!head || head.seq !== args.expectedHead.seq || head.hash !== args.expectedHead.hash) {
      throw new ProofError("REVISION_CONFLICT", "expected head does not match the source audit head.");
    }
    if (args.manifest.state !== "VERIFIED") {
      throw new ProofError("REQUEST_INVALID", "Manifest is not VERIFIED.");
    }
    const dest = Store.openAt(args.destDir, join(args.destDir, "db-0001"));
    try {
      dest.inWriterPublic(() => {
        dest.appendAudit(args.signer, args.principal, args.request, {
          kind: "MigrationActivated", manifest: args.manifest.digest,
          from_schema: args.manifest.from_schema, to_schema: args.manifest.to_schema,
        });
        dest.writeRecoveryHead();
      });
    } finally { dest.close(); }
    // Atomic CURRENT publication: new fsynced file + rename + dir fsync.
    const tmp = join(args.destDir, ".CURRENT.tmp");
    writeSync(openSync(tmp, "w", 0o600), "db-0001\n");
    { const fd = openSync(tmp, "r+"); try { fsyncSync(fd); } finally { closeSync(fd); } }
    renameSync(tmp, join(args.destDir, "CURRENT"));
    { const fd = openSync(args.destDir, "r"); try { fsyncSync(fd); } finally { closeSync(fd); } }
    const body: Omit<MigrationManifest, "digest"> = {
      v: 1, workspace: args.manifest.workspace, from_schema: args.manifest.from_schema,
      to_schema: args.manifest.to_schema, source_head: args.manifest.source_head,
      backup: args.manifest.backup, destination: args.manifest.destination,
      evidence_roots: args.manifest.evidence_roots, state: "ACTIVATED", failed_phase: null,
    };
    const out: MigrationManifest = { ...body, digest: migrationDigest(body) };
    writeManifest(args.destDir, out);
    return out;
  } finally {
    src.close();
  }
}
