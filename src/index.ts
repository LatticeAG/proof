/**
 * @latticeag/proof — LatticeAG Proof zone core (OSS).
 *
 * Signed hash-chain receipt verification and lineage reconstruction.
 * Bundles and lineage receipts travel with the work; verify without
 * trusting the operator who produced them.
 *
 * Proof is the Covenant-v1-gated zone: this is the conformance-grade OSS
 * core, not a hosted/live product surface.
 */

export { ProofError, failure, toFailure, type ErrorCode, type RpcResponse, type RpcFailure } from "./errors.js";
export {
  parseJson, jcsString, jcsBytes, limits, LIMITS_BUNDLE, LIMITS_STAGE,
  type Json, type JsonObject,
} from "./canon.js";
export {
  sha256Hex, hashJson, domainHash, evidenceRoot, bundleHash, batchHash, requestHash,
  rotateProofDigest, signingMessage, verifyMessage, signMessage,
  privateKeyFromSeed, publicKeyBytes, keyIdFromPublic,
  b64uDecodeStrict, b64uEncode, decodePublicKey, decodeSignature,
  ZERO_HASH, D_EVENT, D_AUDIT, D_EVENT_SIGN, D_AUDIT_SIGN,
} from "./crypto.js";
export * from "./model.js";
export { chainCheck } from "./chain.js";
export { replay } from "./replay.js";
export { projectionHash } from "./crypto.js";
export {
  computeCuts, computeEvidence, buildInventory, assembleBundle, discloseBundle,
  sortEvents, sortKeys, distinctObjectRefs,
} from "./bundle.js";
export { lineageClosure, boundedAncestors } from "./lineage.js";
export {
  trustCheck, trustTime, keyCheck, headCheck, auditHeadCheck, anchorCheck,
  signatureValid, trustDigest, keyPinCmp, headPinCmp,
} from "./trust.js";
export { verifyBundle } from "./verify.js";
export { Store, Crash, stageClockEffective, type AuditSigner, type RevisionManifest } from "./store.js";
export { Service, type ServiceOptions } from "./service.js";
export { ProofServer, peerUid, type ServerOptions } from "./server.js";
export { parseConfig, loadConfigFile, type Config, type PrincipalCfg, type LoadedConfig } from "./config.js";
export {
  recoverCheck, recoverStore, backupStore, restoreStore, rotateKey,
  migrateStore, migrateActivate, backupPathCheck,
  type BackupManifest, type MigrationManifest, type RecoveryVerdict,
} from "./maintenance.js";

import { parseJson, LIMITS_BUNDLE } from "./canon.js";
import { parseBundle, parseTrust, type Verification } from "./model.js";
import { verifyBundle } from "./verify.js";

/**
 * Offline verification SDK (§4): canonical bytes in, Verification out.
 * No service, no network, no clock — `options.as_of_unix_ms` supplies the
 * verifier's own time context. Requirement defaults to "ANCHORED".
 */
export function verifyBytes(
  bundleUtf8: Uint8Array | string,
  trustUtf8: Uint8Array | string,
  options: { requirement?: "INTEGRITY" | "RECONSTRUCTION" | "ANCHORED"; as_of_unix_ms?: string } = {},
): Verification {
  const bundle = parseBundle(parseJson(
    typeof bundleUtf8 === "string" ? Buffer.from(bundleUtf8, "utf8") : Buffer.from(bundleUtf8), LIMITS_BUNDLE,
  ), "");
  const trust = parseTrust(parseJson(
    typeof trustUtf8 === "string" ? Buffer.from(trustUtf8, "utf8") : Buffer.from(trustUtf8), LIMITS_BUNDLE,
  ), "");
  return verifyBundle(bundle, trust, options.requirement ?? "ANCHORED", options.as_of_unix_ms ?? "0");
}
