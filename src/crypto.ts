/**
 * Cryptographic primitives (spec §1.1–1.3).
 *
 * H(b)  = lowercase hex SHA-256 of raw bytes.
 * D(t,x)= H(UTF8(t) || 0x00 || J(x)) — domain-separated digest of canonical JSON.
 * Sign  = Ed25519 (ordinary, not Ed25519ph) over UTF8(tag-SIGN) || 0x00 || HEXDECODE(hash).
 *
 * Signature / public-key encoding is canonical unpadded base64url of exactly
 * 64 / 32 bytes. Noncanonical points, small-order public keys, and
 * noncanonical S are rejected before verification.
 */

import { createHash, createPrivateKey, createPublicKey, sign as nSign, verify as nVerify, type KeyObject } from "node:crypto";
import { ProofError } from "./errors.js";
import { jcsBytes, type Json } from "./canon.js";

export const ZERO_HASH = "0".repeat(64);

export function sha256Hex(b: Uint8Array): string {
  return createHash("sha256").update(b).digest("hex");
}

export function sha256(b: Uint8Array): Buffer {
  return createHash("sha256").update(b).digest();
}

/** H(J(x)) — hash of canonical bytes, no domain prefix (config, trust locators). */
export function hashJson(x: Json): string {
  return sha256Hex(jcsBytes(x));
}

export function domainHash(tag: string, x: Json): string {
  return sha256Hex(Buffer.concat([Buffer.from(tag, "ascii"), Buffer.from([0]), jcsBytes(x)]));
}

export const D_EVENT = "LAGI-PROOF-EVENT/v1";
export const D_EVENT_SIGN = "LAGI-PROOF-EVENT-SIGN/v1";
export const D_AUDIT = "LAGI-PROOF-AUDIT/v1";
export const D_AUDIT_SIGN = "LAGI-PROOF-AUDIT-SIGN/v1";
export const D_PROJECTION = "LAGI-PROOF-PROJECTION/v1";
export const D_EVIDENCE = "LAGI-PROOF-EVIDENCE/v1";
export const D_BUNDLE = "LAGI-PROOF-BUNDLE/v1";
export const D_BATCH = "LAGI-PROOF-BATCH/v1";
export const D_REQUEST = "LAGI-PROOF-REQUEST/v1";
export const D_ROTATE = "LAGI-PROOF-ROTATE/v1";
export const D_BACKUP = "LAGI-PROOF-BACKUP/v1";
export const D_MIGRATION = "LAGI-PROOF-MIGRATION/v1";

export const eventHash = (body: Json) => domainHash(D_EVENT, body);
export const auditHash = (body: Json) => domainHash(D_AUDIT, body);
export const projectionHash = (p: Json) => domainHash(D_PROJECTION, p);
export const bundleHash = (body: Json) => domainHash(D_BUNDLE, body);
export const batchHash = (b: Json) => domainHash(D_BATCH, b);
export const requestHash = (method: string, params: Json) => domainHash(D_REQUEST, { method, params });
export const evidenceRoot = (sources: Json, events: Json, keys: Json, objects: Json) =>
  domainHash(D_EVIDENCE, { sources, events, keys, objects });
export const rotateProofDigest = (workspace: string, old: string, next: Json, head: string) =>
  domainHash(D_ROTATE, { workspace, old, next, head });

export function signingMessage(signTag: string, hashHex: string): Buffer {
  return Buffer.concat([Buffer.from(signTag, "ascii"), Buffer.from([0]), Buffer.from(hashHex, "hex")]);
}

// ---- base64url ----

const B64U_RE = /^[A-Za-z0-9_-]+$/;

export function b64uEncode(b: Uint8Array): string {
  return Buffer.from(b).toString("base64url");
}

/** Canonical unpadded base64url: decode then re-encode must round-trip. */
export function b64uDecodeStrict(s: string, code: "SCHEMA_INVALID" | "KEY_MATERIAL_INVALID" = "SCHEMA_INVALID"): Buffer {
  if (!B64U_RE.test(s)) throw new ProofError(code, "Non-canonical base64url.");
  const b = Buffer.from(s, "base64url");
  if (b.toString("base64url") !== s) throw new ProofError(code, "Non-canonical base64url.");
  return b;
}

// ---- Ed25519 strict profile ----

const ED_L = 2n ** 252n + 27742317777372353535851937790883648493n;
const ED_P = 2n ** 255n - 19n;

/** The eight small-order public keys (canonical encodings), plus identity variants. */
const SMALL_ORDER = new Set([
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0100000000000000000000000000000000000000000000000000000000000000",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
]);

function bytesToBigintLE(b: Uint8Array): bigint {
  let v = 0n;
  for (let i = b.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[i]!);
  return v;
}

/** Canonical Ed25519 public-key validation: 32 bytes, on-curve y, not small order. */
export function checkPublicKey(raw: Uint8Array): void {
  if (raw.byteLength !== 32) throw new ProofError("KEY_MATERIAL_INVALID", "Public key must be 32 bytes.");
  const hex = Buffer.from(raw).toString("hex");
  if (SMALL_ORDER.has(hex)) throw new ProofError("KEY_MATERIAL_INVALID", "Small-order public key.");
  const y = bytesToBigintLE(raw) & ((1n << 255n) - 1n);
  if (y >= ED_P) throw new ProofError("KEY_MATERIAL_INVALID", "Noncanonical public key encoding.");
  // On-curve check: x^2 = (y^2-1)/(d y^2+1) must be a quadratic residue.
  const d = (-121665n * modPow(121666n, ED_P - 2n, ED_P)) % ED_P;
  const yy = (y * y) % ED_P;
  const u = (yy - 1n + ED_P) % ED_P;
  const v = (((d * yy) % ED_P) + 1n) % ED_P;
  const x2 = (u * modPow(v, ED_P - 2n, ED_P)) % ED_P;
  const check = (modPow(x2, (ED_P - 1n) / 2n, ED_P) + ED_P) % ED_P;
  if (x2 !== 0n && check !== 1n) throw new ProofError("KEY_MATERIAL_INVALID", "Public key is not on the curve.");
}

function modPow(b: bigint, e: bigint, m: bigint): bigint {
  let r = 1n; b %= m;
  while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; }
  return r;
}

/** Strict signature encoding check: 64 bytes, canonical S < L. */
export function checkSignatureBytes(raw: Uint8Array): void {
  if (raw.byteLength !== 64) throw new ProofError("SCHEMA_INVALID", "Signature must be 64 bytes.");
  const s = bytesToBigintLE(raw.subarray(32));
  if (s >= ED_L) throw new ProofError("SCHEMA_INVALID", "Noncanonical signature scalar.");
}

export function keyIdFromPublic(raw: Uint8Array): string {
  return sha256Hex(raw);
}

const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

export function privateKeyFromSeed(seedHex: string): KeyObject {
  return createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, Buffer.from(seedHex, "hex")]), format: "der", type: "pkcs8" });
}

export function publicKeyBytes(priv: KeyObject): Buffer {
  return createPublicKey(priv).export({ format: "der", type: "spki" }).subarray(-32);
}

export function signMessage(priv: KeyObject, msg: Uint8Array): Buffer {
  return nSign(null, msg, priv);
}

/**
 * Mathematical Ed25519 verification under the *given* public key bytes.
 * The caller is responsible for checking that the verified key's id equals
 * the record's declared key field (no quiet substitution).
 */
export function verifyMessage(publicRaw: Uint8Array, msg: Uint8Array, sigRaw: Uint8Array): boolean {
  try {
    const spki = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(publicRaw)]);
    const key = createPublicKey({ key: spki, format: "der", type: "spki" });
    return nVerify(null, msg, key, sigRaw);
  } catch {
    return false;
  }
}

/** Decode + strict-check a base64url public key, returning raw bytes. */
export function decodePublicKey(s: string): Buffer {
  const raw = b64uDecodeStrict(s, "KEY_MATERIAL_INVALID");
  checkPublicKey(raw);
  return raw;
}

/** Decode + strict-check a base64url signature, returning raw bytes. */
export function decodeSignature(s: string): Buffer {
  const raw = b64uDecodeStrict(s, "SCHEMA_INVALID");
  checkSignatureBytes(raw);
  return raw;
}
