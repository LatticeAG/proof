/**
 * Strict JSON profile + RFC 8785 (JCS) canonicalization, spec §1.1.
 *
 * Parse-time partition:
 *  - not strict JSON (malformed syntax, duplicate members, invalid UTF-8,
 *    BOM, lone surrogates)            → JSON_INVALID
 *  - strict JSON violating the numeric profile or a parser bound
 *    (non-integer / unsafe / negative-zero numbers, depth/member/array
 *    limits)                            → SCHEMA_INVALID
 *
 * Numeric profile: a number literal must be a canonical integer token
 * `-?(0|[1-9][0-9]*)` whose value is a safe integer; fraction, exponent,
 * negative zero, and out-of-range magnitudes are SCHEMA_INVALID. Protocol
 * quantities are decimal Count strings; only bounded tallies and versions
 * appear as JSON numbers.
 *
 * Canonicalization: object members sort by UTF-16 code-unit order (never
 * locale order, never Unicode-normalized); output is minimal UTF-8.
 */

import { ProofError } from "./errors.js";

export type Json = null | boolean | number | string | Json[] | { [k: string]: Json };
export type JsonObject = { [k: string]: Json };

export interface ParseLimits {
  maxDepth: number;
  maxMembers: number;
  maxArray: number;
  maxBytes: number;
}

/** §1.1 JSON limits: depth 32, members/object 1024, ordinary array 4096. */
export function limits(maxBytes: number, maxArray = 4096): ParseLimits {
  return { maxDepth: 32, maxMembers: 1024, maxArray, maxBytes };
}

export const LIMITS_1MIB = limits(1024 * 1024);          // trust file / generic JSON
export const LIMITS_EVENT = limits(64 * 1024);           // canonical event
export const LIMITS_AUDIT = limits(4 * 1024);            // canonical audit entry
export const LIMITS_STAGE = limits(8 * 1024 * 1024);     // stage JSON
export const LIMITS_BUNDLE = limits(64 * 1024 * 1024, 200000); // canonical bundle

const utf8 = new TextDecoder("utf-8", { fatal: true });
const utf8enc = new TextEncoder();

export function decodeStrict(bytes: Uint8Array): string {
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    throw new ProofError("JSON_INVALID", "UTF-8 BOM is not permitted.");
  }
  try {
    return utf8.decode(bytes);
  } catch {
    throw new ProofError("JSON_INVALID", "Invalid UTF-8.");
  }
}

function hasLoneSurrogate(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const n = s.charCodeAt(i + 1);
      if (!(n >= 0xdc00 && n <= 0xdfff)) return true;
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) return true;
  }
  return false;
}

const INT_TOKEN = /^-?(0|[1-9][0-9]*)$/;

class Parser {
  private i = 0;
  private depth = 0;
  constructor(private readonly s: string, private readonly lim: ParseLimits) {}

  parse(): Json {
    this.ws();
    const v = this.value();
    this.ws();
    if (this.i !== this.s.length) throw new ProofError("JSON_INVALID", "Trailing bytes.");
    return v;
  }

  private ws(): void {
    while (this.i < this.s.length) {
      const c = this.s.charCodeAt(this.i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) this.i++;
      else break;
    }
  }

  private peek(): number {
    return this.i < this.s.length ? this.s.charCodeAt(this.i) : -1;
  }

  private value(): Json {
    const c = this.peek();
    if (c === 0x7b) return this.object();
    if (c === 0x5b) return this.array();
    if (c === 0x22) return this.string();
    if (c === 0x74) return this.lit("true", true);
    if (c === 0x66) return this.lit("false", false);
    if (c === 0x6e) return this.lit("null", null);
    if (c === 0x2d || (c >= 0x30 && c <= 0x39)) return this.number();
    throw new ProofError("JSON_INVALID", `Unexpected character at offset ${this.i}.`);
  }

  private lit(word: string, v: Json): Json {
    if (this.s.startsWith(word, this.i)) {
      this.i += word.length;
      return v;
    }
    throw new ProofError("JSON_INVALID", `Invalid literal at offset ${this.i}.`);
  }

  private enter(): void {
    this.depth++;
    if (this.depth > this.lim.maxDepth) {
      throw new ProofError("SCHEMA_INVALID", "Nesting depth exceeds limit.");
    }
  }

  private object(): JsonObject {
    this.i++;
    this.enter();
    const seen = new Set<string>();
    const out: JsonObject = {};
    let members = 0;
    this.ws();
    if (this.peek() === 0x7d) {
      this.i++; this.depth--;
      return out;
    }
    for (;;) {
      this.ws();
      if (this.peek() !== 0x22) throw new ProofError("JSON_INVALID", "Object key must be a string.");
      const key = this.string();
      if (seen.has(key)) throw new ProofError("JSON_INVALID", `Duplicate object member ${JSON.stringify(key)}.`);
      seen.add(key);
      if (++members > this.lim.maxMembers) {
        throw new ProofError("SCHEMA_INVALID", "Object member count exceeds limit.");
      }
      this.ws();
      if (this.peek() !== 0x3a) throw new ProofError("JSON_INVALID", "Expected ':' after object key.");
      this.i++;
      this.ws();
      out[key] = this.value();
      this.ws();
      const c = this.peek();
      if (c === 0x2c) { this.i++; continue; }
      if (c === 0x7d) { this.i++; this.depth--; return out; }
      throw new ProofError("JSON_INVALID", "Expected ',' or '}' in object.");
    }
  }

  private array(): Json[] {
    this.i++;
    this.enter();
    const out: Json[] = [];
    this.ws();
    if (this.peek() === 0x5d) {
      this.i++; this.depth--;
      return out;
    }
    for (;;) {
      this.ws();
      out.push(this.value());
      if (out.length > this.lim.maxArray) {
        throw new ProofError("SCHEMA_INVALID", "Array element count exceeds limit.");
      }
      this.ws();
      const c = this.peek();
      if (c === 0x2c) { this.i++; continue; }
      if (c === 0x5d) { this.i++; this.depth--; return out; }
      throw new ProofError("JSON_INVALID", "Expected ',' or ']' in array.");
    }
  }

  private string(): string {
    this.i++; // opening quote
    let out = "";
    for (;;) {
      if (this.i >= this.s.length) throw new ProofError("JSON_INVALID", "Unterminated string.");
      const c = this.s.charCodeAt(this.i);
      if (c === 0x22) { this.i++; break; }
      if (c === 0x5c) {
        this.i++;
        if (this.i >= this.s.length) throw new ProofError("JSON_INVALID", "Unterminated escape.");
        const e = this.s.charCodeAt(this.i++);
        switch (e) {
          case 0x22: out += '"'; break;
          case 0x5c: out += "\\"; break;
          case 0x2f: out += "/"; break;
          case 0x62: out += "\b"; break;
          case 0x66: out += "\f"; break;
          case 0x6e: out += "\n"; break;
          case 0x72: out += "\r"; break;
          case 0x74: out += "\t"; break;
          case 0x75: {
            if (this.i + 4 > this.s.length) throw new ProofError("JSON_INVALID", "Short \\u escape.");
            const hex = this.s.slice(this.i, this.i + 4);
            if (!/^[0-9a-fA-F]{4}$/.test(hex)) throw new ProofError("JSON_INVALID", "Bad \\u escape.");
            out += String.fromCharCode(parseInt(hex, 16));
            this.i += 4;
            break;
          }
          default: throw new ProofError("JSON_INVALID", "Unknown escape.");
        }
        continue;
      }
      if (c < 0x20) throw new ProofError("JSON_INVALID", "Raw control character in string.");
      out += this.s[this.i++];
    }
    if (hasLoneSurrogate(out)) throw new ProofError("JSON_INVALID", "Lone surrogate in string.");
    return out;
  }

  private number(): number {
    const start = this.i;
    if (this.peek() === 0x2d) this.i++;
    let c = this.peek();
    if (c === 0x30) { this.i++; }
    else if (c >= 0x31 && c <= 0x39) { while (c >= 0x30 && c <= 0x39) { this.i++; c = this.peek(); } }
    else throw new ProofError("JSON_INVALID", `Bad number at offset ${start}.`);
    if (this.peek() === 0x2e) {
      this.i++;
      c = this.peek();
      if (!(c >= 0x30 && c <= 0x39)) throw new ProofError("JSON_INVALID", "Bad fraction.");
      while (c >= 0x30 && c <= 0x39) { this.i++; c = this.peek(); }
    }
    if (this.peek() === 0x65 || this.peek() === 0x45) {
      this.i++;
      c = this.peek();
      if (c === 0x2b || c === 0x2d) { this.i++; c = this.peek(); }
      if (!(c >= 0x30 && c <= 0x39)) throw new ProofError("JSON_INVALID", "Bad exponent.");
      while (c >= 0x30 && c <= 0x39) { this.i++; c = this.peek(); }
    }
    const tok = this.s.slice(start, this.i);
    // Strict JSON succeeded; now enforce the safe-integer numeric profile.
    if (!INT_TOKEN.test(tok)) throw new ProofError("SCHEMA_INVALID", "Number outside safe-integer profile.");
    const v = Number(tok);
    if (!Number.isSafeInteger(v)) throw new ProofError("SCHEMA_INVALID", "Number outside safe-integer profile.");
    if (Object.is(v, -0)) throw new ProofError("SCHEMA_INVALID", "Negative zero is not permitted.");
    return v;
  }
}

export function parseJson(bytes: Uint8Array, lim: ParseLimits = LIMITS_1MIB): Json {
  if (bytes.byteLength > lim.maxBytes) throw new ProofError("BODY_LIMIT", "JSON input exceeds byte limit.");
  return new Parser(decodeStrict(bytes), lim).parse();
}

export function parseJsonString(s: string, lim: ParseLimits = LIMITS_1MIB): Json {
  return parseJson(utf8enc.encode(s), lim);
}

// ---- JCS canonicalization ----

function esc(s: string): string {
  // Identical escaping to JSON.stringify / RFC 8785.
  return JSON.stringify(s);
}

export function jcsString(v: Json): string {
  if (v === null) return "null";
  if (v === true) return "true";
  if (v === false) return "false";
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v)) throw new ProofError("SCHEMA_INVALID", "Non-integer number cannot canonicalize.");
    return String(v);
  }
  if (typeof v === "string") return esc(v);
  if (Array.isArray(v)) return "[" + v.map(jcsString).join(",") + "]";
  const keys = Object.keys(v).sort(); // UTF-16 code-unit order
  return "{" + keys.map((k) => esc(k) + ":" + jcsString(v[k]!)).join(",") + "}";
}

export function jcsBytes(v: Json): Buffer {
  return Buffer.from(jcsString(v), "utf8");
}

/** Byte-order comparison on canonical encodings. */
export function jcsCmp(a: Json, b: Json): number {
  return Buffer.compare(jcsBytes(a), jcsBytes(b));
}

export function sortJcs<T extends Json>(a: T[]): T[] {
  return a.slice().sort(jcsCmp);
}

/** Deep structural equality on parsed JSON (used for idempotent stage checks). */
export function jsonEqual(a: Json, b: Json): boolean {
  return jcsString(a) === jcsString(b);
}

/** Structured deep copy limited to the JSON profile. */
export function jsonClone<T extends Json>(v: T): T {
  return parseJsonString(jcsString(v), LIMITS_BUNDLE) as T;
}

/** JSON Pointer (RFC 6901) mutation for the conformance harness M(). */
export function pointerSet(doc: Json, pointer: string, value: Json): Json {
  const root = jsonClone(doc);
  const segs = pointer.split("/").slice(1).map((s) => s.replace(/~1/g, "/").replace(/~0/g, "~"));
  let cur: Json = root;
  for (let i = 0; i < segs.length - 1; i++) {
    const seg = segs[i]!;
    const next = Array.isArray(cur) ? cur[Number(seg)] : (cur as JsonObject)[seg];
    if (next === undefined) throw new ProofError("REQUEST_INVALID", `Bad pointer ${pointer}.`);
    cur = next;
  }
  const last = segs[segs.length - 1]!;
  if (Array.isArray(cur)) cur[Number(last)] = value;
  else (cur as JsonObject)[last] = value;
  return root;
}
