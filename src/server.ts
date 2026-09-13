/**
 * Transport (§3.1): HTTP/1.1 over one mode-0660 Unix-domain socket; no TCP
 * listener ever exists. Peer authentication is SO_PEERCRED via the native
 * helper on the connection fd; a request cannot select workspace, principal,
 * capabilities, or a proxy-auth header.
 *
 * Admission order: byte cap → peer authentication → bounded parse → role →
 * method schema → authorized lookup → idempotency → state checks.
 *
 * Routes: POST /v1/rpc, GET /healthz, GET /metrics. Everything else is 404;
 * unsupported verbs on declared routes are 405; OPTIONS enables nothing.
 */

import http from "node:http";
import net from "node:net";
import { spawnSync } from "node:child_process";
import { chmodSync, chownSync, existsSync, unlinkSync, mkdirSync, lstatSync } from "node:fs";
import { dirname } from "node:path";
import { ProofError, failure, toFailure, type RpcFailure } from "./errors.js";
import { jcsString, parseJson, limits, type Json } from "./canon.js";
import type { Service } from "./service.js";
import type { PrincipalCfg } from "./config.js";

const CAP_TOTAL = 80 * 1024 * 1024;   // 80 MiB ingress cap before parsing
const CAP_ORDINARY = 8 * 1024 * 1024; // ordinary-method cap after method scan
const PER_UID_RPS = 100;
const PER_UID_CONCURRENT = 8;
const HOST_CONNECTIONS = 16;

export interface ServerOptions {
  peercredHelper?: string;
  uidOverride?: number; // test seam only; production always uses SO_PEERCRED
  socketGid?: number;
}

export function peerUid(socket: net.Socket, helper?: string): number {
  const fd = (socket as unknown as { _handle?: { fd?: number } })._handle?.fd;
  if (fd === undefined || fd < 0) throw new ProofError("UNAUTHENTICATED", "No socket fd for peer credentials.");
  const bin = helper ?? new URL("../../native/peercred", import.meta.url).pathname;
  const r = spawnSync(bin, ["3"], { stdio: ["ignore", "pipe", "ignore", fd], encoding: "utf8" });
  if (r.status !== 0) throw new ProofError("UNAUTHENTICATED", "SO_PEERCRED unavailable.");
  const m = /^uid=(\d+)$/.exec(r.stdout.trim());
  if (!m) throw new ProofError("UNAUTHENTICATED", "Unparseable peer credentials.");
  return Number(m[1]);
}

class RateWindow {
  private hits: number[] = [];
  allow(nowMs: number): boolean {
    this.hits = this.hits.filter((t) => nowMs - t < 1000);
    if (this.hits.length >= PER_UID_RPS) return false;
    this.hits.push(nowMs);
    return true;
  }
}

export class AdmissionLimiter {
  private perUid = new Map<number, { rate: RateWindow; concurrent: number }>();
  private hostConns = 0;

  admit(uid: number, nowMs = Date.now()): { ok: boolean; release: () => void } {
    if (this.hostConns >= HOST_CONNECTIONS) return { ok: false, release: () => {} };
    let e = this.perUid.get(uid);
    if (!e) { e = { rate: new RateWindow(), concurrent: 0 }; this.perUid.set(uid, e); }
    if (!e.rate.allow(nowMs) || e.concurrent >= PER_UID_CONCURRENT) {
      return { ok: false, release: () => {} };
    }
    e.concurrent += 1;
    this.hostConns += 1;
    return { ok: true, release: () => { e!.concurrent -= 1; this.hostConns -= 1; } };
  }
}

export class ProofServer {
  private httpServer: http.Server;
  readonly limiter = new AdmissionLimiter();

  constructor(readonly service: Service, readonly opts: ServerOptions = {}) {
    this.httpServer = http.createServer((req, res) => this.onHttp(req, res));
  }

  private uidFor(socket: net.Socket): number {
    return this.opts.uidOverride ?? peerUid(socket, this.opts.peercredHelper);
  }

  private principalFor(socket: net.Socket): PrincipalCfg {
    const uid = this.uidFor(socket);
    const p = this.service.principalForUid(uid);
    if (!p) throw new ProofError("UNAUTHENTICATED", "Peer credentials map to no provisioned principal.");
    return p;
  }

  private onHttp(req: http.IncomingMessage, res: http.ServerResponse): void {
    const socket = req.socket as net.Socket;
    // HTTP version gate.
    if (req.httpVersion !== "1.1") {
      this.send(res, 505, failure(null, "REQUEST_INVALID"));
      return;
    }
    if (req.headers.host === undefined) {
      this.send(res, 400, failure(null, "REQUEST_INVALID"));
      return;
    }
    // No content encodings or chunked transfer.
    if (req.headers["transfer-encoding"] !== undefined) {
      this.send(res, 400, failure(null, "REQUEST_INVALID"));
      return;
    }
    const cls = req.rawHeaders.filter((h) => h.toLowerCase() === "content-length");
    if (cls.length > 1) {
      this.send(res, 400, failure(null, "REQUEST_INVALID"));
      return;
    }
    // Peer authentication before body admission.
    let uid: number;
    try {
      uid = this.uidFor(socket);
    } catch {
      this.send(res, 401, failure(null, "UNAUTHENTICATED"));
      return;
    }
    const gate = this.limiter.admit(uid);
    if (!gate.ok) {
      res.setHeader("Retry-After", "1");
      this.send(res, 429, failure(null, "RATE_LIMIT"));
      return;
    }
    res.on("close", () => gate.release());

    // Declared routes and verbs.
    const path = req.url;
    const declared = path === "/v1/rpc" || path === "/healthz" || path === "/metrics";
    if (!declared) {
      this.send(res, 404, failure(null, "NOT_FOUND"));
      return;
    }
    if (path === "/v1/rpc" && req.method !== "POST") {
      this.send(res, 405, failure(null, "METHOD_NOT_ALLOWED"));
      return;
    }
    if ((path === "/healthz" || path === "/metrics") && req.method !== "GET") {
      this.send(res, 405, failure(null, "METHOD_NOT_ALLOWED"));
      return;
    }
    if (path === "/healthz") {
      let p: PrincipalCfg;
      try { p = this.principalFor(socket); } catch {
        this.send(res, 401, failure(null, "UNAUTHENTICATED"));
        return;
      }
      void p;
      const ok = this.service.state === "READY";
      this.send(res, ok ? 200 : 503, {
        protocol: "proof/1", status: ok ? "READY" : "UNAVAILABLE", product_status: "UNWRITTEN_GATED",
      } as unknown as Json);
      return;
    }
    if (path === "/metrics") {
      let p: PrincipalCfg;
      try { p = this.principalFor(socket); } catch {
        this.send(res, 401, failure(null, "UNAUTHENTICATED"));
        return;
      }
      if (!p.roles.includes("admin")) {
        this.send(res, 403, failure(null, "FORBIDDEN"));
        return;
      }
      const m = this.service.metricsSnapshot();
      res.writeHead(200, { "content-type": "text/plain; version=0.0.4", "content-length": Buffer.byteLength(m) });
      res.end(m);
      return;
    }

    // POST /v1/rpc: byte cap before any parse work.
    const declaredLen = req.headers["content-length"];
    const len = declaredLen === undefined ? -1 : Number(declaredLen);
    if (declaredLen === undefined || !Number.isSafeInteger(len) || len < 0) {
      this.send(res, 400, failure(null, "REQUEST_INVALID"));
      return;
    }
    if (len > CAP_TOTAL) {
      this.send(res, 413, failure(null, "BODY_LIMIT"));
      req.destroy();
      return;
    }
    const ct = (req.headers["content-type"] ?? "").toString();
    if (!/^application\/json\s*$/.test(ct)) {
      this.send(res, 415, failure(null, "MEDIA_TYPE_UNSUPPORTED"));
      return;
    }
    const chunks: Buffer[] = [];
    let size = 0;
    let aborted = false;
    req.on("data", (c: Buffer) => {
      size += c.byteLength;
      if (size > CAP_TOTAL && !aborted) {
        aborted = true;
        this.send(res, 413, failure(null, "BODY_LIMIT"));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => {
      if (aborted) return;
      const body = Buffer.concat(chunks);
      if (body.length !== len) {
        this.send(res, 400, failure(null, "REQUEST_INVALID"));
        return;
      }
      // Bounded method scan before materializing params.
      const head = body.subarray(0, Math.min(body.length, 65536)).toString("utf8");
      const mm = /"method"\s*:\s*"([A-Za-z0-9._-]+)"/.exec(head);
      const method = mm?.[1] ?? "";
      if (method !== "bundle.verify" && body.length > CAP_ORDINARY) {
        this.send(res, 413, failure(null, "BODY_LIMIT"));
        return;
      }
      let parsed: Json;
      try {
        parsed = parseJson(body, limits(CAP_TOTAL));
      } catch (e) {
        const pe = e instanceof ProofError ? e : new ProofError("JSON_INVALID", "Bad JSON.");
        this.send(res, 400, pe.toFailure(null));
        return;
      }
      const o = parsed as JsonObject;
      let principal: PrincipalCfg;
      try {
        principal = this.principalFor(socket);
      } catch {
        this.send(res, 401, failure(null, "UNAUTHENTICATED"));
        return;
      }
      if (typeof o.id !== "string") {
        this.send(res, 400, failure(null, "SCHEMA_INVALID", "/id"));
        return;
      }
      const resp = this.service.call(principal, {
        id: o.id, method: String(o.method ?? ""), params: (o.params ?? {}) as Json,
      });
      const status = resp.ok ? 200 : httpStatus(resp);
      this.send(res, status, resp as unknown as Json);
    });
    req.on("error", () => {});
  }

  private send(res: http.ServerResponse, status: number, body: Json | RpcFailure): void {
    const payload = jcsString(body as Json);
    res.writeHead(status, {
      "content-type": "application/json",
      "content-length": Buffer.byteLength(payload),
      "connection": "close",
    });
    res.end(payload);
  }

  async listen(socketPath: string): Promise<void> {
    const dir = dirname(socketPath);
    mkdirSync(dir, { recursive: true, mode: 0o710 });
    try { chmodSync(dir, 0o710); } catch { /* best effort */ }
    if (existsSync(socketPath)) {
      const st = lstatSync(socketPath);
      if (!st.isSocket()) throw new ProofError("REQUEST_INVALID", "Socket path exists and is not a socket.");
      unlinkSync(socketPath);
    }
    await new Promise<void>((resolve, reject) => {
      this.httpServer.listen(socketPath, () => {
        chmodSync(socketPath, 0o660);
        if (this.opts.socketGid !== undefined) {
          try { chownSync(socketPath, process.getuid?.() ?? 0, this.opts.socketGid); } catch { /* keep 0660 */ }
        }
        resolve();
      });
      this.httpServer.on("error", reject);
    });
  }

  async close(): Promise<void> {
    await new Promise<void>((r) => this.httpServer.close(() => r()));
  }
}

function httpStatus(resp: RpcFailure): number {
  const code = resp.error.code as keyof typeof HTTP_MAP;
  return HTTP_MAP[code] ?? 400;
}

import type { JsonObject } from "./canon.js";
import type { ErrorCode } from "./errors.js";

const HTTP_MAP: Record<ErrorCode, number> = {
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
