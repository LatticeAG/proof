/**
 * `proof` CLI (§4). Commands are either offline (init, verify, config check,
 * trust check, backup, restore, key rotate, migrate) or UDS clients.
 * Stdout is always the canonical JSON object plus LF; errors are RpcFailure
 * with id:null for local failures. Exit codes per §4.2.
 */

import http from "node:http";
import { readFileSync, openSync, writeSync, fsyncSync, closeSync, existsSync, renameSync, mkdirSync, unlinkSync } from "node:fs";
import { createPrivateKey, createPublicKey, randomBytes } from "node:crypto";
import { dirname, resolve } from "node:path";
import { ProofError, type ErrorCode } from "./errors.js";
import { jcsString, parseJson, LIMITS_BUNDLE, type Json, type JsonObject } from "./canon.js";
import { sha256Hex, domainHash } from "./crypto.js";
import {
  parseSource, parseBatch, parseTrust, parseEventRef, parseAuditRef,
  parseBundle, checkId, checkCount, checkHash,
  type Trust, type KeyMaterial,
} from "./model.js";
import { trustCheck, trustDigest } from "./trust.js";
import { verifyBundle } from "./verify.js";
import { Store, type AuditSigner } from "./store.js";
import { Service } from "./service.js";
import { ProofServer } from "./server.js";
import { loadConfigFile, type Config } from "./config.js";
import {
  recoverStore, backupStore, restoreStore, rotateKey, migrateStore, migrateActivate,
} from "./maintenance.js";

// ---------- argument plumbing ----------

interface Args { flags: Map<string, string | true>; positionals: string[] }

function parseArgv(argv: string[]): Args {
  const flags = new Map<string, string | true>();
  const positionals: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a.startsWith("--")) {
      const eq = a.indexOf("=");
      if (eq >= 0) flags.set(a.slice(2, eq), a.slice(eq + 1));
      else if (i + 1 < argv.length && !argv[i + 1]!.startsWith("--")) flags.set(a.slice(2), argv[++i]!);
      else flags.set(a.slice(2), true);
    } else positionals.push(a);
  }
  return { flags, positionals };
}

function need(args: Args, name: string): string {
  const v = args.flags.get(name);
  if (typeof v !== "string" || v === "") throw new ProofError("REQUEST_INVALID", `Missing --${name}.`);
  return v;
}

function optional(args: Args, name: string): string | undefined {
  const v = args.flags.get(name);
  return typeof v === "string" ? v : undefined;
}

function noExtra(args: Args, allowed: string[], positionalCount: number): void {
  for (const k of args.flags.keys()) {
    if (!["config", "socket", "json", "timeout-ms", "help", ...allowed].includes(k)) {
      throw new ProofError("REQUEST_INVALID", `Unknown flag --${k}.`);
    }
  }
  if (args.positionals.length !== positionalCount) {
    throw new ProofError("REQUEST_INVALID", "Positional argument mismatch.");
  }
}

// ---------- local file helpers ----------

function readJsonFile(path: string): Json {
  const raw = readFileSync(path);
  return parseJson(raw, LIMITS_BUNDLE);
}

function writeExclusive(path: string, bytes: Buffer): void {
  mkdirSync(dirname(resolve(path)), { recursive: true });
  const tmp = `${path}.tmp-${process.pid}`;
  const fd = openSync(tmp, "wx", 0o600);
  try { writeSync(fd, bytes); fsyncSync(fd); } finally { closeSync(fd); }
  if (existsSync(path)) {
    try { unlinkSync(tmp); } catch { /* noop */ }
    throw new ProofError("OBJECT_CONFLICT", "Output path exists; refusing to overwrite.");
  }
  renameSync(tmp, path);
  const dfd = openSync(dirname(resolve(path)), "r");
  try { fsyncSync(dfd); } finally { closeSync(dfd); }
}

function out(obj: Json | JsonObject): void {
  process.stdout.write(jcsString(obj as Json) + "\n");
}

function failOut(e: ProofError): void {
  const f = { id: null, ok: false, error: { code: e.code, retryable: e.retryable, field: e.field } };
  process.stdout.write(jcsString(f as unknown as Json) + "\n");
}

// ---------- config / signer ----------

function loadConfig(path: string): { cfg: Config; digest: string; raw: Json } {
  const l = loadConfigFile(path);
  return { cfg: l.cfg, digest: l.digest, raw: l.raw };
}

function loadSigner(cfg: Config): AuditSigner {
  const pem = readFileSync(cfg.audit_key_file);
  const keyObject = createPrivateKey({ key: pem, format: "pem" });
  const pub = createPublicKey(keyObject).export({ format: "der", type: "spki" }).subarray(-32);
  const material: KeyMaterial = { id: sha256Hex(pub), public: Buffer.from(pub).toString("base64url") };
  return { keyId: material.id, keyObject, material };
}

function loadTrustFile(path: string, workspace?: string): Trust {
  const t = parseTrust(readJsonFile(resolve(path)), "");
  const structural = trustCheck(t);
  if (structural.code !== "OK") throw new ProofError("TRUST_INVALID", "Trust file is structurally invalid.");
  if (workspace !== undefined && t.workspace !== workspace) {
    throw new ProofError("TRUST_INVALID", "Trust workspace mismatch.");
  }
  return t;
}

// ---------- UDS client ----------

function socketPathOf(args: Args): string {
  const cfgFlag = optional(args, "config");
  const sockFlag = optional(args, "socket");
  if (cfgFlag && sockFlag) throw new ProofError("REQUEST_INVALID", "--config and --socket are mutually exclusive.");
  if (sockFlag) return resolve(sockFlag);
  if (cfgFlag) return loadConfig(cfgFlag).cfg.socket;
  throw new ProofError("REQUEST_INVALID", "Service commands require --config or --socket.");
}

async function rpc(args: Args, method: string, params: Json, id: string): Promise<Json> {
  const socketPath = socketPathOf(args);
  const timeoutMs = Number(optional(args, "timeout-ms") ?? "30000");
  const body = Buffer.from(jcsString({ id, method, params } as Json), "utf8");
  return new Promise<Json>((resolveP, rejectP) => {
    const req = http.request({
      socketPath, path: "/v1/rpc", method: "POST",
      headers: { "content-type": "application/json", "content-length": body.length, "host": "localhost" },
      timeout: timeoutMs,
    }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => {
        try {
          const parsed = parseJson(Buffer.concat(chunks), LIMITS_BUNDLE) as JsonObject;
          if (parsed.ok === true) resolveP(parsed.result as Json);
          else {
            const e = parsed.error as { code: string; field: string | null };
            rejectP(new ProofError(e.code as ErrorCode, "RPC failure.", e.field ?? null));
          }
        } catch (e) { rejectP(e); }
      });
    });
    req.on("timeout", () => { req.destroy(); rejectP(new ProofError("DEADLINE", "Client deadline exceeded.")); });
    req.on("error", () => rejectP(new ProofError("STORAGE_UNAVAILABLE", "Service unreachable.")));
    req.end(body);
  });
}

async function httpGet(args: Args, path: string): Promise<{ status: number; body: Buffer }> {
  const socketPath = socketPathOf(args);
  return new Promise((resolveP, rejectP) => {
    const req = http.request({ socketPath, path, method: "GET", headers: { host: "localhost" } }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => resolveP({ status: res.statusCode ?? 0, body: Buffer.concat(chunks) }));
    });
    req.on("error", () => rejectP(new ProofError("STORAGE_UNAVAILABLE", "Service unreachable.")));
    req.end();
  });
}

// ---------- exit mapping ----------

const EXIT_MAP: Record<string, number> = {
  JSON_INVALID: 2, SCHEMA_INVALID: 2, ID_INVALID: 2, METHOD_UNKNOWN: 2, REQUEST_INVALID: 2,
  MEDIA_TYPE_UNSUPPORTED: 2, METHOD_NOT_ALLOWED: 2, UNSUPPORTED_VERSION: 2, UNSUPPORTED_SCHEMA: 2,
  KEY_MATERIAL_INVALID: 2, UNREFERENCED_ITEM: 2, HASH_MISMATCH: 2, SIGNATURE_INVALID: 2,
  UNAUTHENTICATED: 3, FORBIDDEN: 3, TRUST_INVALID: 3,
  NOT_FOUND: 6, CUT_UNKNOWN: 6, ACTION_UNKNOWN: 6, OBJECT_UNAVAILABLE: 6, IDEMPOTENCY_CONFLICT: 6,
  SOURCE_CONFLICT: 6, STAGE_CONFLICT: 6, STAGE_STATE: 6, STAGE_EXPIRED: 6, REVISION_CONFLICT: 6,
  OBJECT_CONFLICT: 6, SCOPE_MISMATCH: 6,
  BODY_LIMIT: 7, EVENT_LIMIT: 7, BUNDLE_LIMIT: 7, PATH_LIMIT: 7, STORE_LIMIT: 7, RATE_LIMIT: 7,
  BUSY: 7, STORAGE_UNAVAILABLE: 7, SIGNER_UNAVAILABLE: 7, DEADLINE: 7,
  READ_ONLY: 8, RECOVERY_REQUIRED: 8, COUNTER_EXHAUSTED: 8,
};

// ---------- commands ----------

async function cmdInit(args: Args): Promise<void> {
  noExtra(args, ["trust", "principal", "request-id"], 0);
  const { cfg, digest } = loadConfig(need(args, "config"));
  const trustPath = need(args, "trust");
  const trust = loadTrustFile(trustPath, cfg.workspace);
  // §4.1: head pins present must be genesis-zero at init.
  for (const h of trust.heads) {
    if (h.seq !== "0") throw new ProofError("TRUST_INVALID", "Init trust may pin only genesis-zero heads.");
  }
  const principalId = need(args, "principal");
  const p = cfg.principals.find((x) => x.id === principalId);
  if (!p || !p.roles.includes("admin")) throw new ProofError("FORBIDDEN", "Init principal must be a configured admin.");
  const requestId = checkId(need(args, "request-id"), "/request-id");
  const signer = loadSigner(cfg);
  const store = Store.create(cfg.store);
  try {
    const r = store.initWorkspace({ workspace: cfg.workspace, configDigest: digest, signer, principal: p.id, request: requestId });
    store.writeRecoveryHead();
    out({ workspace: cfg.workspace, revision: "0", audit: { seq: r.audit.body.seq, hash: r.audit.hash }, trust: trustDigest(trust) } as unknown as Json);
  } finally { store.close(); }
}

async function cmdServe(args: Args): Promise<void> {
  noExtra(args, [], 0);
  const { cfg } = loadConfig(need(args, "config"));
  const store = Store.open(cfg.store);
  const signer = loadSigner(cfg);
  let trust: Trust | null = null;
  try { trust = loadTrustFile(cfg.recovery_trust_file, cfg.workspace); } catch { trust = null; }
  const verdict = recoverStore(store, trust);
  const service = new Service(store, cfg, signer, {});
  const server = new ProofServer(service, { socketGid: cfg.socket_group_gid });
  await server.listen(cfg.socket);
  if (verdict.state === "READ_ONLY") { service.state = "READ_ONLY"; store.state = "READ_ONLY"; }
  out({ protocol: "proof/1", status: service.state, product_status: "UNWRITTEN_GATED" } as unknown as Json);
  process.stderr.write(`proof serving on ${cfg.socket}\n`);
  await new Promise<void>((res) => {
    const stop = () => { void server.close().then(() => { store.close(); res(); }); };
    process.on("SIGINT", stop); process.on("SIGTERM", stop);
  });
}

async function cmdSourceRegister(args: Args): Promise<void> {
  noExtra(args, ["source", "request-id"], 0);
  const source = parseSource(readJsonFile(resolve(need(args, "source"))), "");
  const r = await rpc(args, "source.register", source as unknown as Json, checkId(need(args, "request-id"), "/request-id"));
  out(r);
}

async function cmdSourceList(args: Args): Promise<void> {
  noExtra(args, ["revision"], 0);
  const params: JsonObject = { revision: checkCount(need(args, "revision"), "/revision") };
  out(await rpc(args, "source.list", params as Json, `req-${randomReqId()}`));
}

async function cmdImportStage(args: Args): Promise<void> {
  noExtra(args, ["stage", "batch", "request-id"], 0);
  const stage = checkId(need(args, "stage"), "/stage");
  const batch = parseBatch(readJsonFile(resolve(need(args, "batch"))), "");
  out(await rpc(args, "import.stage", { stage, batch } as unknown as Json, checkId(need(args, "request-id"), "/request-id")));
}

async function cmdImportGet(args: Args): Promise<void> {
  noExtra(args, ["stage"], 0);
  out(await rpc(args, "import.get", { stage: checkId(need(args, "stage"), "/stage") } as unknown as Json, `req-${randomReqId()}`));
}

async function cmdImportCommit(args: Args): Promise<void> {
  noExtra(args, ["stage", "expected-revision", "request-id"], 0);
  const params = {
    stage: checkId(need(args, "stage"), "/stage"),
    expected_revision: checkCount(need(args, "expected-revision"), "/expected-revision"),
  };
  out(await rpc(args, "import.commit", params as unknown as Json, checkId(need(args, "request-id"), "/request-id")));
}

async function cmdImportCancel(args: Args): Promise<void> {
  noExtra(args, ["stage", "request-id"], 0);
  out(await rpc(args, "import.cancel", { stage: checkId(need(args, "stage"), "/stage") } as unknown as Json, checkId(need(args, "request-id"), "/request-id")));
}

async function cmdRevision(args: Args): Promise<void> {
  noExtra(args, ["revision", "latest"], 1 - 1);
  const hasRev = optional(args, "revision") !== undefined;
  const hasLatest = args.flags.get("latest") === true;
  if (hasRev === hasLatest) throw new ProofError("REQUEST_INVALID", "Exactly one of --revision or --latest.");
  const params: JsonObject = hasLatest ? { revision: null } : { revision: checkCount(need(args, "revision"), "/revision") };
  out(await rpc(args, "revision.get", params as Json, `req-${randomReqId()}`));
}

async function cmdLineage(args: Args): Promise<void> {
  noExtra(args, ["revision", "actions", "max-nodes", "max-depth"], 0);
  const actions = parseJson(readFileSync(resolve(need(args, "actions"))), LIMITS_BUNDLE);
  if (!Array.isArray(actions)) throw new ProofError("SCHEMA_INVALID", "--actions must be EventRef[].");
  const parsed = (actions as Json[]).map((a, i) => parseEventRef(a, `/actions/${i}`));
  const params: JsonObject = {
    revision: checkCount(need(args, "revision"), "/revision"),
    actions: parsed as unknown as Json,
    max_nodes: optional(args, "max-nodes") !== undefined ? Number(checkCount(optional(args, "max-nodes")!, "/max-nodes")) : 4096,
    max_depth: optional(args, "max-depth") !== undefined ? Number(checkCount(optional(args, "max-depth")!, "/max-depth")) : 256,
  };
  out(await rpc(args, "lineage.get", params as Json, `req-${randomReqId()}`));
}

async function cmdExport(args: Args): Promise<void> {
  noExtra(args, ["revision", "actions", "include", "out"], 0);
  const actionsRaw = parseJson(readFileSync(resolve(need(args, "actions"))), LIMITS_BUNDLE);
  if (!Array.isArray(actionsRaw)) throw new ProofError("SCHEMA_INVALID", "--actions must be EventRef[].");
  const includeRaw = parseJson(readFileSync(resolve(need(args, "include"))), LIMITS_BUNDLE);
  if (!Array.isArray(includeRaw)) throw new ProofError("SCHEMA_INVALID", "--include must be Hash[].");
  const include = (includeRaw as Json[]).map((h, i) => checkHash(h, `/include/${i}`));
  const params = {
    revision: checkCount(need(args, "revision"), "/revision"),
    actions: (actionsRaw as Json[]).map((a, i) => parseEventRef(a, `/actions/${i}`)) as unknown as Json,
    include: include as unknown as Json,
  };
  const result = await rpc(args, "bundle.export", params as unknown as Json, `req-${randomReqId()}`);
  const bundle = (result as JsonObject).bundle as JsonObject;
  const bytes = Buffer.from(jcsString(bundle), "utf8");
  writeExclusive(need(args, "out"), bytes);
  out({ bundle: domainHash("LAGI-PROOF-BUNDLE/v1", bundle.body as Json), bytes: String(bytes.byteLength) } as unknown as Json);
}

async function cmdVerify(args: Args): Promise<void> {
  noExtra(args, ["bundle", "trust", "require", "as-of-unix-ms"], 0);
  const bundlePath = need(args, "bundle");
  const bundleBytes = bundlePath === "-"
    ? await readStdin(64 * 1024 * 1024)
    : readFileSync(resolve(bundlePath));
  const trust = parseTrust(readJsonFile(resolve(need(args, "trust"))), "");
  const bundle = parseBundle(parseJson(bundleBytes, LIMITS_BUNDLE), "");
  const require = (optional(args, "require") ?? "ANCHORED") as "INTEGRITY" | "RECONSTRUCTION" | "ANCHORED";
  if (!["INTEGRITY", "RECONSTRUCTION", "ANCHORED"].includes(require)) {
    throw new ProofError("SCHEMA_INVALID", "--require must be INTEGRITY|RECONSTRUCTION|ANCHORED.");
  }
  let asOf = optional(args, "as-of-unix-ms");
  if (asOf === undefined) {
    asOf = String(Date.now());
    process.stderr.write(`as_of_unix_ms defaulting to local verifier wall clock: ${asOf}\n`);
  }
  const v = verifyBundle(bundle, trust, require, checkCount(asOf, "/as-of-unix-ms"));
  out(v as unknown as Json);
  // §4.2: exit 4 on integrity INVALID or CONFLICTED lineage; 5 on other non-acceptance.
  if (v.accepted) process.exitCode = 0;
  else if (v.integrity === "INVALID" || v.lineage === "CONFLICTED") process.exitCode = 4;
  else process.exitCode = 5;
}

async function cmdObject(args: Args): Promise<void> {
  noExtra(args, ["revision", "digest", "out"], 0);
  const params = {
    revision: checkCount(need(args, "revision"), "/revision"),
    digest: checkHash(need(args, "digest"), "/digest"),
  };
  const result = await rpc(args, "object.get", params as unknown as Json, `req-${randomReqId()}`);
  const r = result as JsonObject;
  const blob = r.blob as JsonObject | undefined;
  if (!blob) {
    out(r); // UNAVAILABLE/omitted bodies surface as the result object
    return;
  }
  const content = Buffer.from(String(blob.content), "base64url");
  writeExclusive(need(args, "out"), content);
  out((blob.ref ?? r) as Json);
}

async function cmdAuditExport(args: Args): Promise<void> {
  noExtra(args, ["through", "out"], 0);
  const params = { through: checkCount(need(args, "through"), "/through") };
  const result = await rpc(args, "audit.export", params as unknown as Json, `req-${randomReqId()}`);
  const bytes = Buffer.from(jcsString(result), "utf8");
  writeExclusive(need(args, "out"), bytes);
  out({ through: (result as JsonObject).through, bytes: String(bytes.byteLength) } as unknown as Json);
}

async function cmdStatus(args: Args): Promise<void> {
  noExtra(args, [], 0);
  const r = await httpGet(args, "/healthz");
  process.stdout.write(r.body.toString("utf8") + "\n");
  if (r.status === 200) process.exitCode = 0;
  else if (r.status === 401) process.exitCode = 3;
  else process.exitCode = 8;
}

async function cmdMetrics(args: Args): Promise<void> {
  noExtra(args, [], 0);
  const r = await httpGet(args, "/metrics");
  process.stdout.write(r.body.toString("utf8"));
  if (r.status !== 200) process.exitCode = r.status === 401 ? 3 : r.status === 403 ? 3 : 8;
}

async function cmdConfigCheck(args: Args): Promise<void> {
  noExtra(args, [], 0);
  const { digest } = loadConfig(need(args, "config"));
  out({ valid: true, config: digest } as unknown as Json);
}

async function cmdTrustCheck(args: Args): Promise<void> {
  noExtra(args, ["trust", "workspace"], 0);
  const t = loadTrustFile(need(args, "trust"), need(args, "workspace"));
  out({ valid: true, trust: trustDigest(t) } as unknown as Json);
}

async function cmdBackup(args: Args): Promise<void> {
  noExtra(args, ["out"], 0);
  const { cfg } = loadConfig(need(args, "config"));
  const outDir = resolve(need(args, "out"));
  if (existsSync(outDir)) throw new ProofError("OBJECT_CONFLICT", "Backup output exists.");
  const store = Store.open(cfg.store);
  try {
    const m = backupStore(store, cfg, outDir);
    out(m as unknown as Json);
  } finally { store.close(); }
}

async function cmdRestore(args: Args): Promise<void> {
  noExtra(args, ["backup", "recovery-trust", "out"], 0);
  const { cfg } = loadConfig(need(args, "config"));
  const backup = resolve(need(args, "backup"));
  const outDir = resolve(need(args, "out"));
  loadTrustFile(need(args, "recovery-trust"), cfg.workspace); // validated; comparison is the recovery gate
  const r = restoreStore(backup, outDir);
  out(r as unknown as Json);
}

async function cmdKeyRotate(args: Args): Promise<void> {
  noExtra(args, ["new-key-file", "expected-head", "principal", "request-id"], 0);
  const { cfg } = loadConfig(need(args, "config"));
  const newPem = readFileSync(resolve(need(args, "new-key-file")));
  const newKeyObject = createPrivateKey({ key: newPem, format: "pem" });
  const pub = createPublicKey(newKeyObject).export({ format: "der", type: "spki" }).subarray(-32);
  const newMaterial: KeyMaterial = { id: sha256Hex(pub), public: Buffer.from(pub).toString("base64url") };
  const expected = parseAuditRef(readJsonFile(resolve(need(args, "expected-head"))), "");
  const principalId = need(args, "principal");
  const p = cfg.principals.find((x) => x.id === principalId);
  if (!p || !p.roles.includes("admin")) throw new ProofError("FORBIDDEN", "Rotation requires a configured admin.");
  const store = Store.open(cfg.store);
  try {
    const oldSigner = loadSigner(cfg);
    const r = rotateKey({
      store, oldSigner, newMaterial, newKeyObject, expectedHead: expected,
      principal: p.id, request: checkId(need(args, "request-id"), "/request-id"),
    });
    out(r as unknown as Json);
  } finally { store.close(); }
}

async function cmdMigrate(args: Args): Promise<void> {
  noExtra(args, ["target-schema", "out"], 0);
  const { cfg } = loadConfig(need(args, "config"));
  const target = Number(checkCount(need(args, "target-schema"), "/target-schema")) as number;
  const store = Store.open(cfg.store);
  try {
    const m = migrateStore({ store, cfg, targetSchema: target, outDir: resolve(need(args, "out")) });
    out(m as unknown as Json);
  } finally { store.close(); }
}

async function cmdMigrateActivate(args: Args): Promise<void> {
  noExtra(args, ["manifest", "expected-head", "principal", "request-id"], 0);
  const { cfg } = loadConfig(need(args, "config"));
  const manifestRaw = parseJson(readFileSync(resolve(need(args, "manifest"))), LIMITS_BUNDLE) as JsonObject;
  const expected = parseAuditRef(readJsonFile(resolve(need(args, "expected-head"))), "");
  const principalId = need(args, "principal");
  const p = cfg.principals.find((x) => x.id === principalId);
  if (!p || !p.roles.includes("admin")) throw new ProofError("FORBIDDEN", "Activation requires a configured admin.");
  const destDir = dirname(resolve(need(args, "manifest")));
  const signer = loadSigner(cfg);
  const m = migrateActivate({
    srcRoot: cfg.store, destDir, manifest: manifestRaw as never, expectedHead: expected,
    signer, principal: p.id, request: checkId(need(args, "request-id"), "/request-id"),
  });
  out(m as unknown as Json);
}

// ---------- dispatch ----------

const USAGE = `proof — LatticeAG Proof zone core (UNWRITTEN_GATED)
usage: proof <command> [flags]
commands: init | serve | source register|list | import stage|get|commit|cancel |
          revision | lineage | export | verify | object | audit export |
          status | metrics | config check | trust check | backup | restore |
          key rotate | migrate [activate]
global flags: --config FILE --socket PATH --json --timeout-ms N --help`;

function randomReqId(): string {
  return randomBytes(16).toString("hex");
}

function readStdin(cap: number): Promise<Buffer> {
  return new Promise((res, rej) => {
    const chunks: Buffer[] = [];
    let n = 0;
    process.stdin.on("data", (c: Buffer) => {
      n += c.byteLength;
      if (n > cap) { rej(new ProofError("BODY_LIMIT", "stdin exceeds 64 MiB.")); return; }
      chunks.push(c);
    });
    process.stdin.on("end", () => res(Buffer.concat(chunks)));
    process.stdin.on("error", rej);
  });
}

export async function main(argv: string[]): Promise<number> {
  const args = parseArgv(argv);
  if (args.flags.get("help") === true || args.positionals.length === 0) {
    process.stdout.write(USAGE + "\n");
    return 0;
  }
  const cmd = args.positionals.join(" ");
  // Command words are consumed; noExtra() then counts true surplus.
  args.positionals = [];
  try {
    switch (cmd) {
      case "init": await cmdInit(args); break;
      case "serve": await cmdServe(args); break;
      case "source register": await cmdSourceRegister(args); break;
      case "source list": await cmdSourceList(args); break;
      case "import stage": await cmdImportStage(args); break;
      case "import get": await cmdImportGet(args); break;
      case "import commit": await cmdImportCommit(args); break;
      case "import cancel": await cmdImportCancel(args); break;
      case "revision": await cmdRevision(args); break;
      case "lineage": await cmdLineage(args); break;
      case "export": await cmdExport(args); break;
      case "verify": await cmdVerify(args); break;
      case "object": await cmdObject(args); break;
      case "audit export": await cmdAuditExport(args); break;
      case "status": await cmdStatus(args); break;
      case "metrics": await cmdMetrics(args); break;
      case "config check": await cmdConfigCheck(args); break;
      case "trust check": await cmdTrustCheck(args); break;
      case "backup": await cmdBackup(args); break;
      case "restore": await cmdRestore(args); break;
      case "key rotate": await cmdKeyRotate(args); break;
      case "migrate": await cmdMigrate(args); break;
      case "migrate activate": await cmdMigrateActivate(args); break;
      default:
        throw new ProofError("REQUEST_INVALID", `Unknown command: ${cmd}`);
    }
    return Number(process.exitCode ?? 0);
  } catch (e) {
    if (process.env.PROOF_DEBUG) process.stderr.write(String((e as Error).stack ?? e) + "\n");
    const pe = e instanceof ProofError ? e : new ProofError("STORAGE_UNAVAILABLE", String(e));
    failOut(pe);
    return EXIT_MAP[pe.code] ?? 2;
  }
}
