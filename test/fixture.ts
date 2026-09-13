/**
 * Exact port of the spec §11.1 deterministic fixture program.
 * The two seeds are public RFC 8032 test vectors — never secrets or
 * production identities. All generated values are concrete bytes; F is the
 * exact shared fixture used by the API examples and vectors.
 */

import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";

export const J = (x: unknown): string =>
  Array.isArray(x)
    ? "[" + (x as unknown[]).map(J).join(",") + "]"
    : x !== null && typeof x === "object"
      ? "{" + Object.keys(x as Record<string, unknown>).sort().map((k) => JSON.stringify(k) + ":" + J((x as Record<string, unknown>)[k])).join(",") + "}"
      : JSON.stringify(x);

export const H = (b: Uint8Array | string): string =>
  createHash("sha256").update(typeof b === "string" ? Buffer.from(b) : b).digest("hex");

export const D = (t: string, x: unknown): string =>
  H(Buffer.concat([Buffer.from(t + "\0"), Buffer.from(J(x))]));

export const Z = "0".repeat(64);

const ordered = <T>(a: T[]): T[] => a.slice().sort((x, y) => Buffer.compare(Buffer.from(J(x)), Buffer.from(J(y))));
const cmp = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

export interface FixtureKey {
  secret: ReturnType<typeof createPrivateKey>;
  material: { id: string; public: string };
}

export function key(seed: string): FixtureKey {
  const secret = createPrivateKey({ key: Buffer.from("302e020100300506032b657004220420" + seed, "hex"), format: "der", type: "pkcs8" });
  const bytes = createPublicKey(secret).export({ format: "der", type: "spki" }).subarray(-32);
  return { secret, material: { id: H(Buffer.from(bytes)), public: Buffer.from(bytes).toString("base64url") } };
}

export const origin = key("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
export const auditor = key("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");

export function seal(body: Record<string, unknown>, role = "EVENT", k: FixtureKey = origin) {
  const hash = D("LAGI-PROOF-" + role + "/v1", body);
  const message = Buffer.concat([Buffer.from("LAGI-PROOF-" + role + "-SIGN/v1\0"), Buffer.from(hash, "hex")]);
  const signature = sign(null, message, k.secret).toString("base64url");
  if (!verify(null, message, createPublicKey(k.secret), Buffer.from(signature, "base64url"))) throw Error("fixture signature");
  return { body, hash, signature };
}

export const ref = (e: { body: { source: string; stream: string; seq: string }; hash: string }) =>
  ({ source: e.body.source, stream: e.body.stream, seq: e.body.seq, hash: e.hash });
export const ar = (e: { body: { seq: string }; hash: string }) => ({ seq: e.body.seq, hash: e.hash });
export const en = (e: Parameters<typeof ref>[0]) => ({ type: "event", ref: ref(e) });
export const on = (o: { ref: unknown }, e: Parameters<typeof ref>[0]) => ({ type: "object", ref: o.ref, at: ref(e) });
export const blob = (s: string, media: string) => ({
  ref: { digest: H(Buffer.from(s)), bytes: String(Buffer.byteLength(s)), media },
  content: Buffer.from(s).toString("base64url"),
});

const intent = blob("{}", "application/json");
const observation = blob("ok", "text/plain");
export const source = { id: "src1", namespace: "fixture", profile: "proof-evidence/1" };

export interface FixtureEvent {
  body: { v: 1; workspace: string; source: string; stream: string; seq: string; prev: string; lamport: string; key: string; parents: unknown[]; data: Record<string, unknown> };
  hash: string;
  signature: string;
}

export const event = (data: Record<string, unknown>, n: number, previous: { hash: string } | null, parents: unknown[] = []): FixtureEvent =>
  seal({
    v: 1, workspace: "ws1", source: "src1", stream: "main", seq: String(n),
    prev: previous ? previous.hash : Z, lamport: String(n), key: origin.material.id, parents, data,
  }) as FixtureEvent;

export const events: FixtureEvent[] = [];
events.push(event({ kind: "RunOpened", run: "run1", intent: intent.ref, policy: null, hypothetical: false }, 1, null));
events.push(event({ kind: "StepOpened", run: "run1", step: "step1", operation: "compute", input: null }, 2, events[0]!));
events.push(event({ kind: "ObservationRecorded", run: "run1", step: "step1", value: observation.ref }, 3, events[1]!));
events.push(event({ kind: "StepClosed", run: "run1", step: "step1", outcome: "SUCCEEDED", observation: ref(events[2]!) }, 4, events[2]!, [ref(events[2]!)]));
events.push(event({ kind: "RunClosed", run: "run1", outcome: "SUCCEEDED" }, 5, events[3]!));

export const objects = [intent, observation].sort((a, b) => cmp(a.ref.digest, b.ref.digest));

const edge = (from: unknown, to: unknown, kind: string) => ({ from, to, kind });
export const edges = ordered(
  events.slice(1).map((e, i) => edge(en(events[i]!), en(e), "precedes"))
    .concat([
      edge(on(intent, events[0]!), en(events[0]!), "input"),
      edge(en(events[2]!), on(observation, events[2]!), "observed_as"),
      edge(en(events[2]!), en(events[3]!), "caused_by"),
    ]),
);

export const projection = {
  runs: [{
    source: "src1", stream: "main", run: "run1", hypothetical: false, state: "SUCCEEDED",
    opened: ref(events[0]!), closed: ref(events[4]!),
    steps: [{
      step: "step1", operation: "compute", state: "SUCCEEDED",
      opened: ref(events[1]!), closed: ref(events[3]!),
      observations: [observation.ref], evidence: [],
    }],
  }],
  edges, findings: [], corrections: [],
};
export const projectionHash = D("LAGI-PROOF-PROJECTION/v1", projection);

export const root = (sources: unknown, ev: unknown, ks: unknown, objs: unknown) =>
  D("LAGI-PROOF-EVIDENCE/v1", { sources, events: ev, keys: ks, objects: objs });
export const emptyRoot = root([], [], [], []);
export const registeredRoot = root([source], [], [], []);
export const evidence = root([source], events, [origin.material], objects.map((x) => x.ref));

export const batch = { events, keys: [origin.material], objects };
export const batchHash = D("LAGI-PROOF-BATCH/v1", batch);

export const config = {
  v: 1, workspace: "ws1", store: "./store", socket: "./run/proof.sock", socket_group_gid: 1000,
  audit_key_file: "./keys/audit.pem", recovery_trust_file: "./trust/recovery.json",
  principals: [
    { id: "admin1", uid: 1000, roles: ["admin"], sources: [] },
    { id: "producer1", uid: 1001, roles: ["write"], sources: ["src1"] },
    { id: "reviewer1", uid: 1002, roles: ["read", "verify"], sources: [] },
  ],
  limits: { stage_bytes: 8388608, bundle_bytes: 67108864, store_bytes: "10737418240", writer_queue: 16, verify_workers: 2, request_ms: 30000 },
  retention: { stage_ttl_ms: "86400000", committed: "INDEFINITE" },
  storage: { journal: "WAL", synchronous: "FULL", foreign_keys: true },
  telemetry: { sink: "./run/operations.jsonl", payloads: false },
};

export interface FixtureAudit {
  body: { v: 1; workspace: string; seq: string; prev: string; key: string; principal: string; request: string; data: Record<string, unknown> };
  hash: string;
  signature: string;
}

export const audit: FixtureAudit[] = [];
export function auditEvent(data: Record<string, unknown>, request: string, previous: { hash: string; body: { seq: string } } | null): FixtureAudit {
  return seal(
    { v: 1, workspace: "ws1", seq: String(previous ? Number(previous.body.seq) + 1 : 1), prev: previous ? previous.hash : Z, key: auditor.material.id, principal: "admin1", request, data },
    "AUDIT", auditor,
  ) as FixtureAudit;
}
audit.push(auditEvent({ kind: "WorkspaceCreated", config: H(J(config)), revision: "0", evidence: emptyRoot }, "init1", null));
audit.push(auditEvent({ kind: "SourceRegistered", source, revision: "1", evidence: registeredRoot }, "register1", audit[0]!));
audit.push(auditEvent({ kind: "ImportStaged", stage: "st1", batch: batchHash }, "stage1", audit[1]!));
audit.push(auditEvent({ kind: "ImportCommitted", stage: "st1", batch: batchHash, revision: "2", evidence }, "commit1", audit[2]!));
export const cancelled = auditEvent({ kind: "ImportCancelled", stage: "st1", reason: "USER" }, "cancel1", audit[2]!);

export const cuts = [{ source: "src1", stream: "main", through: "5", head: events[4]!.hash }];
export const revision = { revision: "2", evidence, cuts, events: 5, audit: ar(audit[3]!) };
export const registration = { source, revision: { revision: "1", evidence: registeredRoot, cuts: [], events: 0, audit: ar(audit[1]!) } };
export const stageResult = { stage: "st1", state: "STAGED", batch: batchHash, audit: ar(audit[2]!) };
export const commitResult = { stage: "st1", state: "COMMITTED", revision, added: 5, duplicates: 0, conflicts: 0 };
export const cancelResult = { stage: "st1", state: "CANCELLED", reason: "USER", audit: ar(cancelled) };

export const keys = [origin.material, auditor.material].sort((a, b) => cmp(a.id, b.id));

const item = (kind: string, x: unknown) => ({ kind, digest: H(J(x)), bytes: String(Buffer.byteLength(J(x))), availability: "INCLUDED" });
export const inventory = events.map((e) => item("event", e))
  .concat(audit.map((e) => item("audit", e)), keys.map((k) => item("key", k)),
    objects.map((o) => ({ kind: "object", digest: o.ref.digest, bytes: o.ref.bytes, availability: "INCLUDED" })))
  .sort((a, b) => cmp(a.kind + ":" + a.digest, b.kind + ":" + b.digest));

export const action = ref(events[3]!);
export const body = {
  v: 1, format: "proof-bundle/1", workspace: "ws1", revision: "2",
  sources: [source], actions: [action], cuts, evidence, projection: projectionHash,
  inventory, disclosure: "FULL", audit_through: ar(audit[3]!),
};
export const bundle = { body, hash: D("LAGI-PROOF-BUNDLE/v1", body), events, keys, audit, objects };

export const trust = {
  v: 1, workspace: "ws1",
  keys: [
    { key: auditor.material.id, role: "audit", source: null, stream: null, first: "1", last: "100", status: "ACTIVE" },
    { key: origin.material.id, role: "origin", source: "src1", stream: "main", first: "1", last: "100", status: "ACTIVE" },
  ],
  heads: [
    { role: "audit", source: null, stream: null, seq: "4", hash: audit[3]!.hash },
    { role: "origin", source: "src1", stream: "main", seq: "5", hash: events[4]!.hash },
  ],
  valid_until_unix_ms: null,
};
export const options = { requirement: "ANCHORED", as_of_unix_ms: "1789257600000" };
export const verification = {
  v: 1, bundle: bundle.hash, trust: H(J(trust)), requirement: "ANCHORED", as_of_unix_ms: options.as_of_unix_ms,
  accepted: true, integrity: "VALID", lineage: "COMPLETE_RELATIVE", reconstruction: "FULL_RECONSTRUCTION",
  origin: "PINNED", audit: "PINNED", freshness: "AT_REQUIRED_CUT",
  semantics: "RECORDED_STATEMENTS_ONLY", current_authority: "UNKNOWN", foreign: [], reasons: [],
};
export const lineageEdges = edges.filter((e) => J(e.from) !== J(en(events[4]!)) && J(e.to) !== J(en(events[4]!)));
export const lineage = {
  revision: "2", projection: projectionHash,
  nodes: [on(intent, events[0]!), en(events[0]!), en(events[1]!), en(events[2]!), on(observation, events[2]!), en(events[3]!)],
  edges: lineageEdges, findings: [],
};

export function disclose(b: typeof bundle, include: string[]) {
  const result = JSON.parse(JSON.stringify(b));
  const wanted = new Set(include);
  result.objects = result.objects.filter((o: { ref: { digest: string } }) => wanted.has(o.ref.digest));
  for (const i of result.body.inventory) if (i.kind === "object" && !wanted.has(i.digest)) i.availability = "WITHHELD";
  result.body.disclosure = result.objects.length === b.objects.length ? "FULL" : result.objects.length === 0 ? "HASHES_ONLY" : "REDACTED";
  result.hash = D("LAGI-PROOF-BUNDLE/v1", result.body);
  return result;
}

export const P = { J, H, D, Z, ref, ar, en, on, blob, event, seal, root, disclose, origin, auditor };
export const F = {
  source, events, objects, intent, observation, projection, projectionHash, evidence, batch, batchHash,
  config, audit, keys, auditKey: auditor.material, originKey: origin.material, action, revision,
  registration, stageResult, commitResult, cancelResult, bundle, trust, options, verification, lineage,
  registered: { revision: "1", audit: audit.slice(0, 2) },
  staged: { revision: "1", audit: audit.slice(0, 3), stage: stageResult },
  committed: { revision: "2", audit, stage: commitResult },
};

// Golden invariants from the fixture program.
if (events[0]!.hash !== "8126edf35ef72f9a94909cde60f0c3955cedf774be3a0357f01078b1b1c1c2d9") throw new Error("golden hash");
if (events[0]!.signature !== "ameqsvtAKofB1m1uZrPYDrdI4GCHEppx57f0QP2P-m1OqE-Jkbz4WvIrLTp0iIfck0EdvRQprvzyQHmodDPGBA") throw new Error("golden signature");
