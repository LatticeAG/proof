/**
 * Error registry (spec §3.3) and CLI exit mapping (spec §4.2).
 *
 * Every code below is a closed registry member; payload-derived text is
 * never placed into `field` (a JSON Pointer only for the five syntax/schema
 * codes) or into verification `reasons`.
 */

export type ErrorCode =
  | "JSON_INVALID" | "SCHEMA_INVALID" | "ID_INVALID" | "METHOD_UNKNOWN" | "REQUEST_INVALID"
  | "UNAUTHENTICATED" | "FORBIDDEN"
  | "NOT_FOUND" | "CUT_UNKNOWN" | "ACTION_UNKNOWN"
  | "METHOD_NOT_ALLOWED" | "MEDIA_TYPE_UNSUPPORTED"
  | "IDEMPOTENCY_CONFLICT" | "SOURCE_CONFLICT" | "STAGE_CONFLICT" | "STAGE_STATE"
  | "STAGE_EXPIRED" | "REVISION_CONFLICT" | "OBJECT_CONFLICT"
  | "OBJECT_UNAVAILABLE"
  | "BODY_LIMIT" | "EVENT_LIMIT" | "BUNDLE_LIMIT" | "PATH_LIMIT" | "STORE_LIMIT"
  | "HASH_MISMATCH" | "SIGNATURE_INVALID" | "KEY_MATERIAL_INVALID" | "UNREFERENCED_ITEM"
  | "TRUST_INVALID" | "UNSUPPORTED_VERSION" | "UNSUPPORTED_SCHEMA" | "SCOPE_MISMATCH"
  | "RATE_LIMIT"
  | "BUSY" | "STORAGE_UNAVAILABLE" | "SIGNER_UNAVAILABLE" | "DEADLINE"
  | "READ_ONLY" | "RECOVERY_REQUIRED" | "COUNTER_EXHAUSTED";

/** Verification finding codes (§3.3 second registry + §1.4 projection findings). */
export type FindingCode =
  | "INVENTORY_MISMATCH" | "AUDIT_BINDING_MISMATCH" | "SCOPE_MISMATCH" | "PREV_MISMATCH"
  | "LAMPORT_INVALID" | "STATE_TRANSITION" | "PROJECTION_MISMATCH" | "CAUSAL_CYCLE"
  | "SOURCE_FORK" | "AUDIT_FORK" | "DELEGATION_REUSED" | "DELEGATION_MISMATCH"
  | "PARENT_MISSING" | "PREFIX_MISSING" | "OBJECT_WITHHELD" | "OBJECT_MISSING"
  | "KEY_UNPINNED" | "KEY_INTERVAL" | "KEY_COMPROMISED" | "PIN_AHEAD" | "PIN_MISMATCH"
  | "PIN_ABSENT" | "TRUST_EXPIRED" | "HASH_MISMATCH" | "SIGNATURE_INVALID"
  | "KEY_MATERIAL_INVALID" | "TRUST_INVALID";

const HTTP: Record<ErrorCode, number> = {
  JSON_INVALID: 400, SCHEMA_INVALID: 400, ID_INVALID: 400, METHOD_UNKNOWN: 400, REQUEST_INVALID: 400,
  UNAUTHENTICATED: 401, FORBIDDEN: 403,
  NOT_FOUND: 404, CUT_UNKNOWN: 404, ACTION_UNKNOWN: 404,
  METHOD_NOT_ALLOWED: 405, MEDIA_TYPE_UNSUPPORTED: 415,
  IDEMPOTENCY_CONFLICT: 409, SOURCE_CONFLICT: 409, STAGE_CONFLICT: 409, STAGE_STATE: 409,
  STAGE_EXPIRED: 409, REVISION_CONFLICT: 409, OBJECT_CONFLICT: 409,
  OBJECT_UNAVAILABLE: 410,
  BODY_LIMIT: 413, EVENT_LIMIT: 413, BUNDLE_LIMIT: 413, PATH_LIMIT: 413, STORE_LIMIT: 413,
  HASH_MISMATCH: 422, SIGNATURE_INVALID: 422, KEY_MATERIAL_INVALID: 422, UNREFERENCED_ITEM: 422,
  TRUST_INVALID: 422, UNSUPPORTED_VERSION: 422, UNSUPPORTED_SCHEMA: 422, SCOPE_MISMATCH: 422,
  RATE_LIMIT: 429,
  BUSY: 503, STORAGE_UNAVAILABLE: 503, SIGNER_UNAVAILABLE: 503, DEADLINE: 503,
  READ_ONLY: 503, RECOVERY_REQUIRED: 503, COUNTER_EXHAUSTED: 503,
};

const RETRYABLE = new Set<ErrorCode>(["RATE_LIMIT", "BUSY", "STORAGE_UNAVAILABLE", "SIGNER_UNAVAILABLE", "DEADLINE"]);

/** §4.2: RPC failure code → CLI exit code. */
const EXIT: Record<ErrorCode, number> = {
  JSON_INVALID: 2, SCHEMA_INVALID: 2, ID_INVALID: 2, METHOD_UNKNOWN: 2, REQUEST_INVALID: 2,
  MEDIA_TYPE_UNSUPPORTED: 2, METHOD_NOT_ALLOWED: 2, UNSUPPORTED_VERSION: 2, UNSUPPORTED_SCHEMA: 2,
  KEY_MATERIAL_INVALID: 2, UNREFERENCED_ITEM: 2, HASH_MISMATCH: 2, SIGNATURE_INVALID: 2,
  SCOPE_MISMATCH: 2,
  UNAUTHENTICATED: 3, FORBIDDEN: 3, TRUST_INVALID: 3,
  NOT_FOUND: 6, CUT_UNKNOWN: 6, ACTION_UNKNOWN: 6, OBJECT_UNAVAILABLE: 6,
  IDEMPOTENCY_CONFLICT: 6, SOURCE_CONFLICT: 6, STAGE_CONFLICT: 6, STAGE_STATE: 6,
  STAGE_EXPIRED: 6, REVISION_CONFLICT: 6, OBJECT_CONFLICT: 6,
  BODY_LIMIT: 7, EVENT_LIMIT: 7, BUNDLE_LIMIT: 7, PATH_LIMIT: 7, STORE_LIMIT: 7,
  RATE_LIMIT: 7, BUSY: 7, STORAGE_UNAVAILABLE: 7, SIGNER_UNAVAILABLE: 7, DEADLINE: 7,
  READ_ONLY: 8, RECOVERY_REQUIRED: 8, COUNTER_EXHAUSTED: 8,
};

/** Codes that carry a JSON Pointer in `field`; every other code carries null. */
const FIELD_CODES = new Set<ErrorCode>([
  "JSON_INVALID", "SCHEMA_INVALID", "ID_INVALID", "METHOD_UNKNOWN", "REQUEST_INVALID",
]);

export class ProofError extends Error {
  readonly code: ErrorCode;
  readonly field: string | null;
  constructor(code: ErrorCode, message?: string, field?: string | null) {
    super(message ?? code);
    this.name = "ProofError";
    this.code = code;
    this.field = FIELD_CODES.has(code) ? (field ?? null) : null;
  }
  get httpStatus(): number { return HTTP[this.code]; }
  get retryable(): boolean { return RETRYABLE.has(this.code); }
  get exitCode(): number { return EXIT[this.code]; }
  toFailure(id: string | null): RpcFailure {
    return { id, ok: false, error: { code: this.code, retryable: this.retryable, field: this.field } };
  }
}

export interface RpcSuccess<T> { id: string; ok: true; result: T }
export interface RpcFailure {
  id: string | null;
  ok: false;
  error: { code: string; retryable: boolean; field: string | null };
}
export type RpcResponse = RpcSuccess<unknown> | RpcFailure;

export function failure(id: string | null, code: ErrorCode, field: string | null = null): RpcFailure {
  return { id, ok: false, error: { code, retryable: new ProofError(code).retryable, field: FIELD_CODES.has(code) ? field : null } };
}

export function isProofError(e: unknown): e is ProofError {
  return e instanceof ProofError;
}

/** Map an arbitrary thrown value to a public failure; internal details never leak. */
export function toFailure(id: string | null, e: unknown): RpcFailure {
  if (e instanceof ProofError) return e.toFailure(id);
  return failure(id, "STORAGE_UNAVAILABLE");
}
