#!/usr/bin/env node
// Generate a local starter workspace with a fresh Ed25519 audit key.
import { generateKeyPairSync, createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

const target = process.argv[2];
if (!target || process.argv.length !== 3 || !process.getuid || !process.getgid) {
  console.error("Usage: node examples/generate.mjs NEW_DIRECTORY (Unix only)");
  process.exit(2);
}
const dir = resolve(target);
// Refuse to overwrite an existing workspace or its keys.
mkdirSync(dir, { mode: 0o700 });
mkdirSync(join(dir, "keys"), { mode: 0o700 });
mkdirSync(join(dir, "trust"), { mode: 0o700 });
mkdirSync(join(dir, "run"), { mode: 0o700 });
const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const publicBytes = publicKey.export({ type: "spki", format: "der" }).subarray(-32);
const key = createHash("sha256").update(publicBytes).digest("hex");
const config = {
  v: 1, workspace: "ws1", store: "./store", socket: "./run/proof.sock",
  socket_group_gid: process.getgid(), audit_key_file: "./keys/audit.pem",
  recovery_trust_file: "./trust/recovery.json",
  principals: [{ id: "admin1", uid: process.getuid(), roles: ["admin"], sources: [] }],
  limits: { stage_bytes: 8388608, bundle_bytes: 67108864, store_bytes: "10737418240", writer_queue: 16, verify_workers: 2, request_ms: 30000 },
  retention: { stage_ttl_ms: "86400000", committed: "INDEFINITE" },
  storage: { journal: "WAL", synchronous: "FULL", foreign_keys: true },
  telemetry: { sink: "./run/operations.jsonl", payloads: false },
};
const trust = {
  v: 1, workspace: "ws1",
  keys: [{ key, role: "audit", source: null, stream: null, first: "1", last: "9223372036854775807", status: "ACTIVE" }],
  heads: [{ role: "audit", source: null, stream: null, seq: "0", hash: "0".repeat(64) }],
  valid_until_unix_ms: null,
};
const saveJson = (name, value) => writeFileSync(join(dir, name), JSON.stringify(value, null, 2) + "\n", { mode: 0o600, flag: "wx" });
writeFileSync(join(dir, "keys/audit.pem"), privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600, flag: "wx" });
saveJson("proof.json", config);
saveJson("trust/init.json", trust);
saveJson("trust/recovery.json", trust);
console.log(`Created starter configuration in ${dir}`);
