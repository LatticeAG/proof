/**
 * TV-P-01 … TV-P-60 — the exact §11.3 conformance vectors.
 * Every vector runs the named closed harness op against the shared fixture F
 * and asserts the exact expected output; fixture-state ops run a real
 * Store+Service in a fresh temporary directory.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { F, P, origin, auditor } from "./fixture.js";
import {
  ops, M, drop, api, admission, crash, crashRetry, race, stageRace,
  commitAuthorization, serviceRead, recover, migrateCheck,
} from "./harness.js";
import type { Json } from "../src/canon.js";
import type { Event } from "../src/model.js";

const E = (e: { body: unknown; hash: string; signature: string }) => e as unknown as Event;

test("TV-P-01 canonical member order", () => {
  const out = ops.canonicalize(Buffer.from('{"z":0,"a":[true,null,"x"]}'));
  assert.equal(out, '{"a":[true,null,"x"],"z":0}');
});

test("TV-P-02 duplicate object member", () => {
  assert.deepEqual(ops.parse(Buffer.from('{"a":1,"a":2}')), { code: "JSON_INVALID" });
});

test("TV-P-03 unsafe integer and negative zero", () => {
  assert.deepEqual(ops.parseMany(['{"n":9007199254740992}', '{"n":-0}']), [
    { code: "SCHEMA_INVALID" }, { code: "SCHEMA_INVALID" },
  ]);
});

test("TV-P-04 Unicode is not normalized", () => {
  assert.deepEqual(ops.canonicalizeMany(['{"s":"\\u00e9"}', '{"s":"e\\u0301"}']), {
    equal: false,
    utf8_hex: ["7b2273223a22c3a9227d", "7b2273223a2265cc81227d"],
  });
});

test("TV-P-05 frozen native event hash", () => {
  assert.equal(ops.eventHash(F.events[0]!.body), "8126edf35ef72f9a94909cde60f0c3955cedf774be3a0357f01078b1b1c1c2d9");
});

test("TV-P-06 exact Ed25519 signature", () => {
  assert.deepEqual(ops.signed(F.events[0], F.originKey), { code: "OK" });
});

test("TV-P-07 body tampering", () => {
  assert.deepEqual(ops.signed(M(F.events[0], "/body/data/run", "other"), F.originKey), { code: "HASH_MISMATCH" });
});

test("TV-P-08 signature domain separation", () => {
  assert.deepEqual(ops.signatureMessageCheck(E(F.events[0]!), F.originKey, "LAGI-PROOF-AUDIT-SIGN/v1"), { code: "SIGNATURE_INVALID" });
});

test("TV-P-09 noncanonical signature encoding", () => {
  assert.deepEqual(ops.signed(M(F.events[0], "/signature", F.events[0]!.signature + "="), F.originKey), { code: "SCHEMA_INVALID" });
});

test("TV-P-10 sequence zero is not an event", () => {
  assert.deepEqual(ops.eventSchema(M(F.events[0]!.body, "/seq", "0")), { code: "SCHEMA_INVALID" });
});

test("TV-P-11 wrong present predecessor", () => {
  assert.deepEqual(ops.chain([E(F.events[0]!), E(P.seal(M(F.events[1]!.body, "/prev", P.Z)))]), { code: "PREV_MISMATCH" });
});

test("TV-P-12 missing prefix is not forged bytes", () => {
  assert.deepEqual(ops.chain([E(F.events[1]!)]), { code: "PREFIX_MISSING" });
});

test("TV-P-13 same scoped slot, two signed bodies", () => {
  assert.deepEqual(ops.slots([E(F.events[0]!), E(P.seal(M(F.events[0]!.body, "/data/hypothetical", true)))]), { code: "SOURCE_FORK" });
});

test("TV-P-14 same sequence in a different source is not a fork", () => {
  assert.deepEqual(ops.slots([E(F.events[0]!), E(P.seal(M(F.events[0]!.body, "/source", "src2")))]), { code: "OK" });
});

test("TV-P-15 terminal run cannot reopen", () => {
  const late = P.event({ kind: "StepOpened", run: "run1", step: "late", operation: "compute", input: null }, 6, F.events[4]!);
  assert.deepEqual(ops.replay([...F.events.map(E), E(late)], F.objects), { code: "STATE_TRANSITION" });
});

test("TV-P-16 success requires a recorded observation", () => {
  assert.deepEqual(ops.eventSchema(M(F.events[3]!.body, "/data/observation", null)), { code: "SCHEMA_INVALID" });
});

test("TV-P-17 delegation destination substitution", () => {
  assert.deepEqual(ops.delegationMatch({
    offer: { source: "src1", stream: "main", run: "run1", delegation: "d1", child: { source: "src2", stream: "main", run: "child1" }, scope: P.Z },
    accept: { source: "src3", stream: "main", run: "child1", delegation: "d1", scope: P.Z },
  }), { code: "DELEGATION_MISMATCH" });
});

test("TV-P-18 acceptance lacks its exact offer", () => {
  assert.deepEqual(ops.dependencyCheck({
    available: F.events.map(E),
    required: [{ source: "src2", stream: "main", seq: "1", hash: P.Z }],
  }), { code: "PARENT_MISSING" });
});

test("TV-P-19 offer replayed into two acceptances", () => {
  assert.deepEqual(ops.delegationUse({
    offer: F.action,
    accepts: [
      { source: "src2", stream: "main", seq: "1", hash: F.events[0]!.hash },
      { source: "src2", stream: "main", seq: "2", hash: F.events[1]!.hash },
    ],
  }), { code: "DELEGATION_REUSED", edges: 0 });
});

test("TV-P-20 correction preserves original outcome", () => {
  const correction = P.event({ kind: "CorrectionNoted", target: F.action, replacement: F.intent.ref, reason: "DISPUTE" }, 6, F.events[4]!, [F.action]);
  assert.deepEqual(ops.correctedState({ events: F.events.map(E), correction: E(correction), objects: F.objects }), {
    run: "SUCCEEDED", step: "SUCCEEDED", corrections: 1, events: 6,
  });
});

test("TV-P-21 independent anchored reconstruction", () => {
  assert.deepEqual(ops.verify(F.bundle, F.trust, F.options), F.verification);
});

test("TV-P-22 included key is not an origin pin", () => {
  assert.deepEqual(ops.originCheck(E(F.events[0]!), F.originKey, M(F.trust, "/keys", [F.trust.keys[0]])), { code: "KEY_UNPINNED" });
});

test("TV-P-23 independently retained head is ahead", () => {
  assert.deepEqual(ops.headCheck({
    cut: F.revision.cuts[0]!, events: F.events.map(E),
    pin: { role: "origin", source: "src1", stream: "main", seq: "6", hash: F.events[0]!.hash },
  }), { code: "PIN_AHEAD" });
});

test("TV-P-24 same position, different independently pinned head", () => {
  assert.deepEqual(ops.headCheck({
    cut: F.revision.cuts[0]!, events: F.events.map(E),
    pin: { role: "origin", source: "src1", stream: "main", seq: "5", hash: F.events[0]!.hash },
  }), { code: "PIN_MISMATCH" });
});

test("TV-P-25 compromised source key", () => {
  assert.deepEqual(ops.originCheck(E(F.events[0]!), F.originKey, M(F.trust, "/keys/1/status", "COMPROMISED")), { code: "KEY_COMPROMISED" });
});

test("TV-P-26 retired key remains valid in its interval", () => {
  assert.deepEqual(ops.originCheck(E(F.events[0]!), F.originKey, M(F.trust, "/keys/1/status", "RETIRED")), { code: "OK" });
});

test("TV-P-27 pin for another stream is not authority", () => {
  assert.deepEqual(ops.originCheck(E(F.events[0]!), F.originKey, M(F.trust, "/keys/1/stream", "other")), { code: "KEY_UNPINNED" });
});

test("TV-P-28 attributable source equivocation", () => {
  assert.deepEqual(ops.forkAttribution(
    [E(F.events[0]!), E(P.seal(M(F.events[0]!.body, "/data/hypothetical", true)))], F.keys, F.trust,
  ), { code: "SOURCE_FORK", attributable: true, winner: null });
});

test("TV-P-29 hash-only disclosure cannot reconstruct plaintext", () => {
  assert.deepEqual(ops.reportGrade(P.disclose(F.bundle, []), F.trust, F.options), {
    accepted: false, reconstruction: "PARTIAL", reasons: ["OBJECT_WITHHELD"],
  });
});

test("TV-P-30 missing bytes are not regenerated", () => {
  assert.deepEqual(ops.availability({ ref: F.observation.ref, requested: false, stored: false }), {
    availability: "UNAVAILABLE", finding: "OBJECT_MISSING", provider_calls: 0, model_calls: 0,
  });
});

test("TV-P-31 event-envelope redaction is forbidden", () => {
  assert.deepEqual(ops.inventorySchema({ kind: "event", digest: F.events[0]!.hash, bytes: "1", availability: "WITHHELD" }), { code: "SCHEMA_INVALID" });
});

test("TV-P-32 backup path traversal and symlink", () => {
  assert.deepEqual(ops.backupPaths([
    { path: "../keys/audit.pem", kind: "regular" },
    { path: "objects/link", kind: "symlink" },
  ]), [{ code: "REQUEST_INVALID" }, { code: "REQUEST_INVALID" }]);
});

test("TV-P-33 imported URL is never fetched", () => {
  assert.deepEqual(ops.foreignBytes({ format: "world-lineage/1", bytes_hex: "68747470733a2f2f6578616d706c652e636f6d2f" }), {
    assessment: "NOT_EVALUATED", network_calls: 0, executed_files: 0,
  });
});

test("TV-P-34 knowing a digest does not grant read authority", () => {
  assert.deepEqual(api("committed", 1001, {
    id: "q1", method: "object.get",
    params: { revision: "2", digest: F.observation.ref.digest } as unknown as Json,
  }), { id: "q1", ok: false, error: { code: "FORBIDDEN", retryable: false, field: null } });
});

test("TV-P-35 request cap before parsing", () => {
  assert.deepEqual(admission({ method: "import.stage", content_length: 83886081, peer_uid: 1000 }), {
    code: "BODY_LIMIT", parsed_bytes: 0, stages_added: 0,
  });
});

test("TV-P-36 JSON nesting is bounded", () => {
  assert.deepEqual(ops.parse(Buffer.from("[".repeat(33) + "0" + "]".repeat(33))), { code: "SCHEMA_INVALID" });
});

test("TV-P-37 crash before durable publication", () => {
  assert.deepEqual(crash("staged", {
    id: "commit1", method: "import.commit",
    params: { stage: "st1", expected_revision: "1" } as unknown as Json,
  }, "after_audit_sign_before_commit"), {
    revision: "1", audit_seq: "3", stage: "STAGED", saved_commit: false,
  });
});

test("TV-P-38 crash after COMMIT, retry same command", () => {
  assert.deepEqual(crashRetry("staged", {
    id: "commit1", method: "import.commit",
    params: { stage: "st1", expected_revision: "1" } as unknown as Json,
  }, "after_commit_before_reply"), {
    result: F.commitResult, revision: "2", audit_seq: "4", commit_events: 1,
  });
});

test("TV-P-39 idempotency content conflict", () => {
  assert.deepEqual(api("committed", 1000, {
    id: "commit1", method: "import.commit",
    params: { stage: "st1", expected_revision: "2" } as unknown as Json,
  }), { id: "commit1", ok: false, error: { code: "IDEMPOTENCY_CONFLICT", retryable: false, field: null } });
});

test("TV-P-40 two stages race on one revision", () => {
  assert.deepEqual(race({
    base: "staged", second_stage: { id: "st2", batch: F.batch },
    calls: [
      { id: "c1", stage: "st1", expected_revision: "1" },
      { id: "c2", stage: "st2", expected_revision: "1" },
    ],
    writer_order: ["c1", "c2"],
  }), { c1: "COMMITTED", c2: "REVISION_CONFLICT", revision: "2", published_revisions: 1 });
});

test("TV-P-41 restored database behind external pin", () => {
  assert.deepEqual(recover({
    database_audit: F.audit.slice(0, 3) as never, required_head: P.ar(F.audit[3]!), trust: F.trust,
  }), { state: "READ_ONLY", code: "RECOVERY_REQUIRED", writes: 0 });
});

test("TV-P-42 rotation stops at exact key interval", () => {
  assert.deepEqual(ops.originCheck(E(F.events[4]!), F.originKey, M(F.trust, "/keys/1/last", "4")), { code: "KEY_INTERVAL" });
});

test("TV-P-43 identity migration preserves signed history", () => {
  assert.deepEqual(migrateCheck({
    from_schema: 1, to_schema: 1, source: "committed", events: F.events.map(E), objects: F.objects, kill: "before_current_switch",
  }), {
    selected: "SOURCE", event_bytes_equal: true, audit_prefix_equal: true,
    evidence_roots_equal: true, source_deleted: false,
  });
});

test("TV-P-44 disclosure audit failure prevents release", () => {
  assert.deepEqual(serviceRead("committed", 1000, {
    method: "object.get",
    params: { revision: "2", digest: F.observation.ref.digest } as unknown as Json,
  }, { audit_write: "ENOSPC" }), { code: "STORAGE_UNAVAILABLE", released_bytes: 0, state: "READ_ONLY" });
});

test("TV-P-45 trust expires at the upper bound", () => {
  assert.deepEqual(ops.trustTime(M(F.trust, "/valid_until_unix_ms", "1789257600000"), F.options.as_of_unix_ms), { code: "TRUST_EXPIRED" });
});

test("TV-P-46 source permission changes before commit barrier", () => {
  assert.deepEqual(commitAuthorization({
    uid: 1001, staged_sources: ["src1"], allowlist_at_stage: ["src1"], allowlist_at_commit: [], revision: "1",
  }), { code: "FORBIDDEN", revision: "1", published_revisions: 0 });
});

test("TV-P-47 World UNKNOWN stays unevaluated", () => {
  assert.deepEqual(ops.foreignBytes({ format: "world-lineage/1", bytes_utf8: '{"result":"UNKNOWN","disclosure":"FULL"}' }), {
    assessment: "NOT_EVALUATED", network_calls: 0, executed_files: 0,
  });
});

test("TV-P-48 VisLineage normalized-only bytes do not prove execution", () => {
  assert.deepEqual(ops.foreignBytes({ format: "vislineage-bundle/1", bytes_utf8: '{"disclosure":"NORMALIZED_ONLY","semantics":"NOT_VERIFIED"}' }), {
    assessment: "NOT_EVALUATED", network_calls: 0, executed_files: 0,
  });
});

test("TV-P-49 claimed inner INVALID cannot become a verified success", () => {
  assert.deepEqual(ops.foreignBytes({ format: "world-lineage/1", bytes_utf8: '{"verification":"INVALID"}' }), {
    assessment: "NOT_EVALUATED", network_calls: 0, executed_files: 0,
  });
});

test("TV-P-50 hypothetical run stays hypothetical", () => {
  assert.deepEqual(ops.replaySummary([E(P.seal(M(F.events[0]!.body, "/data/hypothetical", true)))], [F.intent]), {
    runs: [{ state: "OPEN", hypothetical: true }], confirmed_external_effects: 0,
  });
});

test("TV-P-51 diamond ancestor closure is not a single convenient path", () => {
  assert.deepEqual(ops.boundedAncestors({
    vertices: ["a", "b", "c", "d"],
    edges: [["a", "b"], ["a", "c"], ["b", "d"], ["c", "d"]],
    actions: ["d"], max_nodes: 4, max_depth: 3,
  }), { nodes: ["a", "b", "c", "d"], edges: [["a", "b"], ["a", "c"], ["b", "d"], ["c", "d"]] });
});

test("TV-P-52 signed wrong logical clock", () => {
  assert.deepEqual(ops.chain([E(F.events[0]!), E(P.seal(M(F.events[1]!.body, "/lamport", "3")))]), { code: "LAMPORT_INVALID" });
});

test("TV-P-53 artifact tampering under the original digest", () => {
  assert.deepEqual(ops.objectCheck(M(F.observation, "/content", "bm8")), { code: "HASH_MISMATCH" });
});

test("TV-P-54 audit signature on a different evidence root", () => {
  assert.deepEqual(ops.auditBinding({
    revision: F.revision as never,
    audit: P.seal(M(F.audit[3]!.body, "/data/evidence", P.Z), "AUDIT", P.auditor) as never,
  }), { code: "AUDIT_BINDING_MISMATCH" });
});

test("TV-P-55 unsupported native version is not ignored", () => {
  assert.deepEqual(ops.eventSchema(M(F.events[0]!.body, "/v", 2)), { code: "UNSUPPORTED_VERSION" });
});

test("TV-P-56 genesis pin is not a history anchor", () => {
  assert.deepEqual(ops.anchorCheck({ role: "origin", source: "src1", stream: "main", seq: "0", hash: P.Z }), {
    code: "PIN_ABSENT", origin: "SIGNED_UNANCHORED",
  });
});

test("TV-P-57 clock rollback cannot renew a stage", () => {
  assert.deepEqual(ops.stageClock({ created_ms: "1000", persisted_floor_ms: "3601000", os_ms: "500", ttl_ms: "3600000" }), {
    effective_ms: "3601000", expired: true, event: "ImportCancelled", reason: "EXPIRED",
  });
});

test("TV-P-58 cancel wins the commit barrier", () => {
  assert.deepEqual(stageRace({ state: "STAGED", writer_order: ["cancel", "commit"], expected_revision: "1", current_revision: "1" }), {
    state: "CANCELLED", cancel: "OK", commit: "STAGE_STATE", committed_revisions: 0,
  });
});

test("TV-P-59 worker and traversal limits fail without partial evidence", () => {
  assert.deepEqual(ops.limitChecks([
    { kind: "verify_workers", active: 2, max: 2 },
    { kind: "path_nodes", needed: 4097, max: 4096 },
  ]), [{ code: "BUSY", started: 0 }, { code: "PATH_LIMIT", returned_nodes: 0 }]);
});

test("TV-P-60 origin/audit key reuse is invalid trust", () => {
  assert.deepEqual(ops.trustCheck(M(F.trust, "/keys/0/key", F.originKey.id)), { code: "TRUST_INVALID" });
});
