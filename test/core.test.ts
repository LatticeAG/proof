/** Unit coverage beyond the vector table: parser hostility, RFC 8032,
 * canonical edges, store lifecycle, lineage bounds, disclosure. */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createPrivateKey, createPublicKey, sign } from "node:crypto";
import { parseJson, jcsString, jcsBytes, LIMITS_BUNDLE } from "../src/canon.js";
import {
  sha256Hex, verifyMessage, signingMessage, privateKeyFromSeed, publicKeyBytes,
  keyIdFromPublic, b64uEncode, decodeSignature, ZERO_HASH,
} from "../src/crypto.js";
import { ProofError } from "../src/errors.js";
import { F, P } from "./fixture.js";
import { Store } from "../src/store.js";
import { boundedAncestors } from "../src/lineage.js";
import { discloseBundle } from "../src/bundle.js";
import type { Bundle } from "../src/model.js";
import { verifyBundle } from "../src/verify.js";
import { parseTrust, parseBundle } from "../src/model.js";

// ---------- strict parser ----------

test("parser rejects BOM, duplicate keys at depth, trailing junk", () => {
  for (const s of [
    "﻿{\"a\":1}",
    "{\"a\":{\"b\":1,\"b\":2}}",
    "{\"a\":01}",
    "{\"a\":1.0}",
    "{\"a\":1e3}",
    "{\"a\":+1}",
    "{\"a\":-}",
    "{\"a\":\"\\ud800\"}",
    "{\"a\":\"\\udc00\"}",
    "{\"a\":\"\\ud800\\ud800\"}",
    "{\"a\":9007199254740993}",
    "{\"a\":-0}",
    "[1,]",
    "{,}",
  ]) {
    assert.throws(() => parseJson(Buffer.from(s, "utf8"), LIMITS_BUNDLE), ProofError, s);
  }
});

test("parser accepts lone-pair surrogate escapes and non-BMP", () => {
  const v = parseJson(Buffer.from('{"s":"\\ud83d\\ude00"}'), LIMITS_BUNDLE) as { s: string };
  assert.equal(v.s, "\u{1F600}");
});

test("JCS escapes controls, orders by UTF-16", () => {
  assert.equal(jcsString(parseJson(Buffer.from('{"b":1,"a":2,"A":3,"á":4}'))), '{"A":3,"a":2,"b":1,"á":4}');
  assert.equal(jcsString(parseJson(Buffer.from('"\\u0000\\u001f"'))), '"\\u0000\\u001f"');
});

test("depth boundary: 32 levels parse, 33 rejected", () => {
  const ok = "[".repeat(32) + "0" + "]".repeat(32);
  assert.doesNotThrow(() => parseJson(Buffer.from(ok), LIMITS_BUNDLE));
  assert.throws(() => parseJson(Buffer.from("[".repeat(33) + "0" + "]".repeat(33)), LIMITS_BUNDLE));
});

// ---------- Ed25519 / domains ----------

test("RFC 8032 test vector 1 (empty message)", () => {
  const seed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
  const priv = privateKeyFromSeed(seed);
  const pub = publicKeyBytes(priv);
  assert.equal(pub.toString("hex"), "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
  const sig = sign(null, Buffer.alloc(0), priv);
  assert.equal(sig.toString("hex"),
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
  assert.equal(verifyMessage(pub, Buffer.alloc(0), sig), true);
  assert.equal(verifyMessage(pub, Buffer.from([1]), sig), false);
});

test("signature noncanonicality: trailing '=' rejected, wrong length rejected", () => {
  const good = F.events[0]!.signature;
  assert.throws(() => decodeSignature(good + "="), ProofError);
  assert.throws(() => decodeSignature(good.slice(0, -4)), ProofError);
  assert.throws(() => decodeSignature("!".repeat(86)), ProofError);
});

test("domain separation: same digest, different domain tag fails", () => {
  const pub = publicKeyBytes(privateKeyFromSeed("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"));
  const priv = privateKeyFromSeed("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
  const h = sha256Hex(Buffer.from("x"));
  const sig = sign(null, signingMessage("LAGI-PROOF-EVENT-SIGN/v1", h), priv);
  assert.equal(verifyMessage(pub, signingMessage("LAGI-PROOF-EVENT-SIGN/v1", h), sig), true);
  assert.equal(verifyMessage(pub, signingMessage("LAGI-PROOF-AUDIT-SIGN/v1", h), sig), false);
});

// ---------- store lifecycle ----------

test("store create → reopen preserves state", () => {
  const dir = mkdtempSync(join(tmpdir(), "proof-core-"));
  try {
    const s1 = Store.create(join(dir, "store"));
    s1.close();
    const s2 = Store.open(join(dir, "store"));
    assert.equal(s2.currentRevision(), -1n);
    s2.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Store refuses to open a directory without CURRENT", () => {
  const dir = mkdtempSync(join(tmpdir(), "proof-core-"));
  try {
    assert.throws(() => Store.open(join(dir, "nonexistent")));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---------- lineage bounds ----------

test("boundedAncestors enforces node cap without partial success", () => {
  assert.throws(
    () => boundedAncestors({
      vertices: ["a", "b", "c", "d", "e"],
      edges: [["a", "b"], ["b", "c"], ["c", "d"], ["d", "e"]],
      actions: ["e"], max_nodes: 3, max_depth: 10,
    }),
    (e: unknown) => e instanceof ProofError && e.code === "PATH_LIMIT",
  );
});

test("boundedAncestors depth cap", () => {
  assert.throws(
    () => boundedAncestors({
      vertices: ["a", "b", "c"],
      edges: [["a", "b"], ["b", "c"]],
      actions: ["c"], max_nodes: 10, max_depth: 1,
    }),
    (e: unknown) => e instanceof ProofError && e.code === "PATH_LIMIT",
  );
});

// ---------- disclosure ----------

test("discloseBundle relabels and rehashes", () => {
  const b = F.bundle as unknown as Bundle;
  const red = discloseBundle(b, [F.intent.ref.digest]);
  assert.equal(red.body.disclosure, "REDACTED");
  assert.notEqual(red.hash, b.hash);
  const none = discloseBundle(b, []);
  assert.equal(none.body.disclosure, "HASHES_ONLY");
  const trust = parseTrust(F.trust as never, "");
  const v = verifyBundle(parseBundle(red as never, ""), trust, "ANCHORED", F.options.as_of_unix_ms);
  assert.equal(v.accepted, false);
  assert.equal(v.reconstruction, "PARTIAL");
});
