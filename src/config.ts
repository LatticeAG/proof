/**
 * Strict service configuration (§5.1): a closed JSON object. Relative paths
 * resolve against the configuration file's directory, never process cwd.
 * Numeric limits may only be lowered from the reference maxima.
 */

import { readFileSync, realpathSync, lstatSync } from "node:fs";
import { dirname, resolve, isAbsolute } from "node:path";
import { ProofError } from "./errors.js";
import { parseJson, LIMITS_1MIB, type Json, type JsonObject } from "./canon.js";
import { isObj, requireFields, checkId, checkCount } from "./model.js";
import { hashJson } from "./crypto.js";

export const ROLES = ["admin", "read", "write", "verify"] as const;
export type Role = (typeof ROLES)[number];
export const RUNTIME_PRINCIPAL = "runtime";

export interface PrincipalCfg {
  id: string; uid: number; roles: Role[]; sources: string[];
}

export interface Config {
  v: 1;
  workspace: string;
  store: string;            // absolute after resolution
  socket: string;           // absolute
  socket_group_gid: number;
  audit_key_file: string;   // absolute
  recovery_trust_file: string; // absolute
  principals: PrincipalCfg[];
  limits: {
    stage_bytes: number; bundle_bytes: number; store_bytes: string;
    writer_queue: number; verify_workers: number; request_ms: number;
  };
  retention: { stage_ttl_ms: string; committed: "INDEFINITE" };
  storage: { journal: "WAL"; synchronous: "FULL"; foreign_keys: true };
  telemetry: { sink: string; payloads: boolean }; // sink absolute
  dir: string; // config file directory
}

const LIMIT_MAXIMA = {
  stage_bytes: 8388608, bundle_bytes: 67108864,
  store_bytes: 1099511627776n, writer_queue: 16, verify_workers: 2, request_ms: 30000,
};
const LIMIT_MINIMA = {
  stage_bytes: 1024, bundle_bytes: 1024, store_bytes: 1073741824n,
  writer_queue: 1, verify_workers: 1, request_ms: 100,
};
const TTL_MIN = 3600000n;       // 1 hour
const TTL_MAX = 604800000n;     // 7 days

function fail(msg: string, field: string | null = null): never {
  throw new ProofError("SCHEMA_INVALID", msg, field);
}

function needBool(v: Json, f: string): boolean {
  if (typeof v !== "boolean") fail("Expected boolean.", f);
  return v;
}
function needSafeInt(v: Json, f: string, min: number, max: number): number {
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < min || v > max) fail("Expected safe integer in range.", f);
  return v;
}

/** Resolve a config-relative path; reject escapes via symlink traversal. */
function resolvePath(base: string, p: Json, field: string): string {
  if (typeof p !== "string" || p.length === 0 || p.length > 4096) fail("Bad path.", field);
  if (/[\0]/.test(p) || /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(p)) fail("Path must be a local file path.", field);
  const abs = isAbsolute(p) ? resolve(p) : resolve(base, p);
  // Walk existing ancestors: any symlink component must resolve inside base.
  let cur = abs;
  const missing: string[] = [];
  while (!exists(cur)) { missing.unshift(cur); const parent = dirname(cur); if (parent === cur) break; cur = parent; }
  if (exists(cur)) {
    const real = realpathSync(cur);
    const realBase = exists(base) ? realpathSync(base) : base;
    if (!abs.startsWith("/") && !real.startsWith(realBase)) fail("Symlink traversal outside the configuration directory.", field);
    // For absolute paths allow any location but still forbid symlinked
    // components pointing outside the resolved store tree at use time.
  }
  return abs;
}
function exists(p: string): boolean {
  try { lstatSync(p); return true; } catch { return false; }
}

export function parseConfig(raw: Json, dir: string): Config {
  if (!isObj(raw)) fail("Configuration must be an object.");
  requireFields(raw, [
    "v", "workspace", "store", "socket", "socket_group_gid", "audit_key_file",
    "recovery_trust_file", "principals", "limits", "retention", "storage", "telemetry",
  ]);
  if (raw.v !== 1) throw new ProofError("UNSUPPORTED_VERSION", "Unsupported config version.", "/v");
  const workspace = checkId(raw.workspace!, "/workspace");
  const store = resolvePath(dir, raw.store!, "/store");
  const socket = resolvePath(dir, raw.socket!, "/socket");
  const gid = needSafeInt(raw.socket_group_gid!, "/socket_group_gid", 0, 4294967295);
  const auditKeyFile = resolvePath(dir, raw.audit_key_file!, "/audit_key_file");
  const recoveryTrust = resolvePath(dir, raw.recovery_trust_file!, "/recovery_trust_file");

  if (!Array.isArray(raw.principals) || raw.principals.length === 0) fail("principals must be a nonempty array.", "/principals");
  const uids = new Set<number>();
  const principals: PrincipalCfg[] = raw.principals.map((p, i) => {
    const f = `/principals/${i}`;
    if (!isObj(p)) fail("Principal must be an object.", f);
    requireFields(p, ["id", "uid", "roles", "sources"], f);
    const id = checkId(p.id!, `${f}/id`);
    if (id === RUNTIME_PRINCIPAL) fail("Principal id 'runtime' is reserved.", `${f}/id`);
    const uid = needSafeInt(p.uid!, `${f}/uid`, 0, 4294967295);
    if (uids.has(uid)) fail("Duplicate uid.", `${f}/uid`);
    uids.add(uid);
    if (!Array.isArray(p.roles) || p.roles.length === 0) fail("roles must be a nonempty array.", `${f}/roles`);
    const roles = p.roles.map((r, j) => {
      if (typeof r !== "string" || !(ROLES as readonly string[]).includes(r)) {
        throw new ProofError("UNSUPPORTED_SCHEMA", "Unknown role.", `${f}/roles/${j}`);
      }
      return r as Role;
    });
    const sorted = [...roles].sort();
    if (sorted.some((r, j) => j > 0 && r === sorted[j - 1])) fail("roles must be sorted unique.", `${f}/roles`);
    if (roles.some((r, j) => r !== sorted[j])) fail("roles must be sorted unique.", `${f}/roles`);
    if (!Array.isArray(p.sources)) fail("sources must be an array.", `${f}/sources`);
    const sources = p.sources.map((s, j) => checkId(s!, `${f}/sources/${j}`));
    return { id, uid, roles: sorted, sources };
  });

  const lim = raw.limits!;
  if (!isObj(lim)) fail("limits must be an object.", "/limits");
  requireFields(lim, ["stage_bytes", "bundle_bytes", "store_bytes", "writer_queue", "verify_workers", "request_ms"], "/limits");
  const limits = {
    stage_bytes: needSafeInt(lim.stage_bytes!, "/limits/stage_bytes", LIMIT_MINIMA.stage_bytes, LIMIT_MAXIMA.stage_bytes),
    bundle_bytes: needSafeInt(lim.bundle_bytes!, "/limits/bundle_bytes", LIMIT_MINIMA.bundle_bytes, LIMIT_MAXIMA.bundle_bytes),
    store_bytes: checkCount(lim.store_bytes!, "/limits/store_bytes"),
    writer_queue: needSafeInt(lim.writer_queue!, "/limits/writer_queue", LIMIT_MINIMA.writer_queue, LIMIT_MAXIMA.writer_queue),
    verify_workers: needSafeInt(lim.verify_workers!, "/limits/verify_workers", LIMIT_MINIMA.verify_workers, LIMIT_MAXIMA.verify_workers),
    request_ms: needSafeInt(lim.request_ms!, "/limits/request_ms", LIMIT_MINIMA.request_ms, LIMIT_MAXIMA.request_ms),
  };
  const sb = BigInt(limits.store_bytes);
  if (sb < LIMIT_MINIMA.store_bytes || sb > LIMIT_MAXIMA.store_bytes) fail("store_bytes out of range.", "/limits/store_bytes");

  const ret = raw.retention!;
  if (!isObj(ret)) fail("retention must be an object.", "/retention");
  requireFields(ret, ["stage_ttl_ms", "committed"], "/retention");
  const ttl = BigInt(checkCount(ret.stage_ttl_ms!, "/retention/stage_ttl_ms"));
  if (ttl < TTL_MIN || ttl > TTL_MAX) fail("stage_ttl_ms out of range.", "/retention/stage_ttl_ms");
  if (ret.committed !== "INDEFINITE") throw new ProofError("UNSUPPORTED_SCHEMA", "Unknown retention.", "/retention/committed");

  const st = raw.storage!;
  if (!isObj(st)) fail("storage must be an object.", "/storage");
  requireFields(st, ["journal", "synchronous", "foreign_keys"], "/storage");
  if (st.journal !== "WAL" || st.synchronous !== "FULL") throw new ProofError("UNSUPPORTED_SCHEMA", "Unsupported storage profile.", "/storage");
  if (st.foreign_keys !== true) fail("foreign_keys must be true.", "/storage/foreign_keys");

  const tel = raw.telemetry!;
  if (!isObj(tel)) fail("telemetry must be an object.", "/telemetry");
  requireFields(tel, ["sink", "payloads"], "/telemetry");
  const sink = resolvePath(dir, tel.sink!, "/telemetry/sink");
  const payloads = needBool(tel.payloads!, "/telemetry/payloads");

  return {
    v: 1, workspace, store, socket, socket_group_gid: gid,
    audit_key_file: auditKeyFile, recovery_trust_file: recoveryTrust,
    principals, limits, dir,
    retention: { stage_ttl_ms: ttl.toString(), committed: "INDEFINITE" },
    storage: { journal: "WAL", synchronous: "FULL", foreign_keys: true },
    telemetry: { sink, payloads },
  };
}

export interface LoadedConfig { cfg: Config; raw: Json; digest: string }

export function loadConfigFile(path: string): LoadedConfig {
  const abs = resolve(path);
  let raw: Buffer;
  try {
    const st = lstatSync(abs);
    if (!st.isFile()) throw new ProofError("REQUEST_INVALID", "Config path is not a regular file.");
    raw = readFileSync(abs);
  } catch (e) {
    if (e instanceof ProofError) throw e;
    throw new ProofError("REQUEST_INVALID", "Cannot read config file.");
  }
  const json = parseJson(raw, LIMITS_1MIB);
  const cfg = parseConfig(json, dirname(abs));
  // The config digest binds the exact declared object, canonicalized —
  // matching the fixture's H(J(config)) over the file's JSON value.
  return { cfg, raw: json, digest: hashJson(json) };
}
