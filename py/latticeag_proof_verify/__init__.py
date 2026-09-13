"""latticeag-proof-verify — offline Proof bundle verifier.

Public API: verify_bytes(bundle_utf8: bytes, trust_utf8: bytes, options: dict) -> dict

Reimplements the Proof §1.7 verification pipeline without network access:
strict canonical JSON, domain-separated SHA-256, Ed25519 signatures,
hash-chain and replay checks, evidence roots, disclosure labels, and
independent trust-pin grading. The result shape is byte-identical to the
TypeScript `verifyBytes` SDK output.
"""

from __future__ import annotations

import hashlib
import re

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

ZERO_HASH = "0" * 64
MAX_DEPTH = 32
MAX_MEMBERS = 1024
MAX_ARRAY = 4096
MAX_BYTES = 64 * 1024 * 1024
MAX_SAFE = 2**53 - 1
COUNT_MAX = 9223372036854775807
OUTCOMES = ("SUCCEEDED", "FAILED", "UNKNOWN", "CANCELLED")
OPERATIONS = ("read", "write", "compute", "dispatch")

D_EVENT = b"LAGI-PROOF-EVENT/v1"
D_EVENT_SIGN = b"LAGI-PROOF-EVENT-SIGN/v1"
D_AUDIT = b"LAGI-PROOF-AUDIT/v1"
D_AUDIT_SIGN = b"LAGI-PROOF-AUDIT-SIGN/v1"
D_EVIDENCE = b"LAGI-PROOF-EVIDENCE/v1"
D_BUNDLE = b"LAGI-PROOF-BUNDLE/v1"
D_PROJECTION = b"LAGI-PROOF-PROJECTION/v1"
D_ROTATE = b"LAGI-PROOF-ROTATE/v1"


class ProofError(Exception):
    def __init__(self, code: str, field: str | None = None):
        super().__init__(code)
        self.code = code
        self.field = field


def fail(code, field=None):
    raise ProofError(code, field)


# ---------- canonical JSON ----------

_INT_RE = re.compile(r"-?(0|[1-9][0-9]*)$")
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_B64U_RE = re.compile(r"^[A-Za-z0-9_-]*$")
_ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,63}$")


def _esc(ch: str) -> str:
    o = ord(ch)
    if ch == '"':
        return '\\"'
    if ch == "\\":
        return "\\\\"
    if ch in "\b\f\n\r\t":
        return {"\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}[ch]
    if o < 0x20:
        return "\\u%04x" % o
    return ch


def jcs(x) -> str:
    if x is None:
        return "null"
    if x is True:
        return "true"
    if x is False:
        return "false"
    if isinstance(x, str):
        return '"' + "".join(_esc(c) for c in x) + '"'
    if isinstance(x, int):
        return str(x)
    if isinstance(x, list):
        return "[" + ",".join(jcs(i) for i in x) + "]"
    if isinstance(x, dict):
        keys = sorted(x.keys(), key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(jcs(k) + ":" + jcs(x[k]) for k in keys) + "}"
    raise ProofError("SCHEMA_INVALID")


def _utf16_ord(k: str):
    return k.encode("utf-16-be")


class _Parser:
    def __init__(self, data: bytes, max_bytes: int):
        if len(data) > max_bytes:
            fail("SCHEMA_INVALID")
        if data[:3] == b"\xef\xbb\xbf":
            fail("JSON_INVALID")
        try:
            self.s = data.decode("utf-8")
        except UnicodeDecodeError:
            fail("JSON_INVALID")
        self.i = 0
        self.depth = 0

    def value(self):
        self._ws()
        c = self._peek()
        if c == "{":
            return self._obj()
        if c == "[":
            return self._arr()
        if c == '"':
            return self._str()
        if c == "t" or c == "f":
            return self._lit()
        if c == "n":
            return self._null()
        return self._num()

    def _ws(self):
        while self.i < len(self.s) and self.s[self.i] in " \t\n\r":
            self.i += 1

    def _peek(self):
        if self.i >= len(self.s):
            fail("JSON_INVALID")
        return self.s[self.i]

    def _lit(self):
        for w, v in (("true", True), ("false", False)):
            if self.s.startswith(w, self.i):
                self.i += len(w)
                return v
        fail("JSON_INVALID")

    def _null(self):
        if self.s.startswith("null", self.i):
            self.i += 4
            return None
        fail("JSON_INVALID")

    def _num(self):
        m = re.compile(r"-?[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]+)?").match(self.s, self.i)
        if not m or m.group(0) == "":
            fail("JSON_INVALID")
        tok = m.group(0)
        self.i += len(tok)
        if tok.startswith("-"):
            body = tok[1:]
        else:
            body = tok
        if len(body) > 1 and body.startswith("0") and not body.startswith("0."):
            fail("SCHEMA_INVALID")
        if "." in tok or "e" in tok or "E" in tok:
            fail("SCHEMA_INVALID")
        v = int(tok)
        if abs(v) > MAX_SAFE:
            fail("SCHEMA_INVALID")
        if tok == "-0":
            fail("SCHEMA_INVALID")
        return v

    def _str(self):
        self.i += 1
        out = []
        while True:
            if self.i >= len(self.s):
                fail("JSON_INVALID")
            c = self.s[self.i]
            if c == '"':
                self.i += 1
                return "".join(out)
            if c == "\\":
                self.i += 1
                if self.i >= len(self.s):
                    fail("JSON_INVALID")
                e = self.s[self.i]
                if e == "u":
                    hexs = self.s[self.i + 1:self.i + 5]
                    if len(hexs) != 4 or not re.fullmatch(r"[0-9a-fA-F]{4}", hexs):
                        fail("JSON_INVALID")
                    cp = int(hexs, 16)
                    if 0xD800 <= cp <= 0xDBFF:
                        # must pair with low surrogate
                        if self.s[self.i + 5:self.i + 7] != "\\u":
                            fail("JSON_INVALID")
                        lo = self.s[self.i + 7:self.i + 11]
                        if len(lo) != 4 or not re.fullmatch(r"[0-9a-fA-F]{4}", lo):
                            fail("JSON_INVALID")
                        lcp = int(lo, 16)
                        if not (0xDC00 <= lcp <= 0xDFFF):
                            fail("JSON_INVALID")
                        out.append(chr(0x10000 + ((cp - 0xD800) << 10) + (lcp - 0xDC00)))
                        self.i += 11
                        continue
                    if 0xDC00 <= cp <= 0xDFFF:
                        fail("JSON_INVALID")
                    out.append(chr(cp))
                    self.i += 5
                    continue
                if e in '"\\/':
                    out.append(e)
                elif e == "b":
                    out.append("\b")
                elif e == "f":
                    out.append("\f")
                elif e == "n":
                    out.append("\n")
                elif e == "r":
                    out.append("\r")
                elif e == "t":
                    out.append("\t")
                else:
                    fail("JSON_INVALID")
                self.i += 1
                continue
            if ord(c) < 0x20:
                fail("JSON_INVALID")
            out.append(c)
            self.i += 1

    def _obj(self):
        self.i += 1
        self.depth += 1
        if self.depth > MAX_DEPTH:
            fail("SCHEMA_INVALID")
        self._ws()
        if self._peek() == "}":
            self.i += 1
            self.depth -= 1
            return {}
        out = {}
        n = 0
        while True:
            self._ws()
            if self._peek() != '"':
                fail("JSON_INVALID")
            k = self._str()
            if k in out:
                fail("JSON_INVALID")
            self._ws()
            if self._peek() != ":":
                fail("JSON_INVALID")
            self.i += 1
            out[k] = self.value()
            n += 1
            if n > MAX_MEMBERS:
                fail("SCHEMA_INVALID")
            self._ws()
            c = self._peek()
            if c == "}":
                self.i += 1
                self.depth -= 1
                return out
            if c != ",":
                fail("JSON_INVALID")
            self.i += 1

    def _arr(self):
        self.i += 1
        self.depth += 1
        if self.depth > MAX_DEPTH:
            fail("SCHEMA_INVALID")
        self._ws()
        if self._peek() == "]":
            self.i += 1
            self.depth -= 1
            return []
        out = []
        while True:
            out.append(self.value())
            if len(out) > MAX_ARRAY:
                fail("SCHEMA_INVALID")
            self._ws()
            c = self._peek()
            if c == "]":
                self.i += 1
                self.depth -= 1
                return out
            if c != ",":
                fail("JSON_INVALID")
            self.i += 1


def parse_json(data: bytes):
    p = _Parser(data, MAX_BYTES)
    v = p.value()
    p._ws()
    if p.i != len(p.s):
        fail("JSON_INVALID")
    return v


# ---------- crypto ----------

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def domain_hash(tag: bytes, x) -> str:
    return sha256_hex(tag + b"\x00" + jcs(x).encode("utf-8"))


def b64u_dec(s: str) -> bytes:
    if not isinstance(s, str) or not _B64U_RE.fullmatch(s):
        fail("SCHEMA_INVALID")
    import base64
    pad = "=" * (-len(s) % 4)
    try:
        return base64.urlsafe_b64decode(s + pad)
    except Exception:
        fail("SCHEMA_INVALID")


def verify_sig(pub: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
        return True
    except (InvalidSignature, ValueError):
        return False


def signing_message(tag: bytes, digest_hex: str) -> bytes:
    return tag + b"\x00" + bytes.fromhex(digest_hex)


# ---------- model validation ----------

def _is_obj(x):
    return isinstance(x, dict)


def _req(o: dict, keys):
    for k in keys:
        if k not in o:
            fail("SCHEMA_INVALID", "/" + k)


def _count(v):
    if not isinstance(v, str) or not re.fullmatch(r"[0-9]+", v):
        fail("SCHEMA_INVALID")
    n = int(v)
    if n > COUNT_MAX:
        fail("SCHEMA_INVALID")
    return n


def _hash(v):
    if not isinstance(v, str) or not _HASH_RE.fullmatch(v):
        fail("SCHEMA_INVALID")
    return v


def _id(v):
    if not isinstance(v, str) or not _ID_RE.fullmatch(v):
        fail("SCHEMA_INVALID")
    return v


def _object_ref(v):
    _req(v, ["digest", "bytes", "media"])
    _hash(v["digest"])
    _count(v["bytes"])
    if v["media"] not in ("application/json", "application/octet-stream", "text/plain"):
        fail("SCHEMA_INVALID", "/media")
    return v


def _event_ref(v):
    _req(v, ["source", "stream", "seq", "hash"])
    _id(v["source"]); _id(v["stream"])
    if _count(v["seq"]) < 1:
        fail("SCHEMA_INVALID")
    _hash(v["hash"])
    return v


def _audit_ref(v):
    _req(v, ["seq", "hash"])
    if _count(v["seq"]) < 1:
        fail("SCHEMA_INVALID")
    _hash(v["hash"])
    return v


def _key_material(v):
    _req(v, ["id", "public"])
    _hash(v["id"])
    raw = b64u_dec(v["public"])
    if len(raw) != 32:
        fail("KEY_MATERIAL_INVALID")
    return v


def parse_event_body(b):
    _req(b, ["v", "workspace", "source", "stream", "seq", "prev", "lamport", "key", "parents", "data"])
    if b["v"] != 1:
        fail("UNSUPPORTED_VERSION")
    _id(b["workspace"]); _id(b["source"]); _id(b["stream"])
    if _count(b["seq"]) < 1:
        fail("SCHEMA_INVALID")
    _hash(b["prev"])
    if _count(b["lamport"]) < 1:
        fail("SCHEMA_INVALID")
    _hash(b["key"])
    if not isinstance(b["parents"], list):
        fail("SCHEMA_INVALID")
    for p in b["parents"]:
        _event_ref(p)
    if len(b["parents"]) > 64:
        fail("EVENT_LIMIT")
    _event_data(b["data"])
    return b


def _event_data(d):
    if not _is_obj(d) or "kind" not in d:
        fail("SCHEMA_INVALID")
    k = d["kind"]
    if k not in ("RunOpened", "StepOpened", "ObservationRecorded", "StepClosed",
                 "DelegationOffered", "DelegationAccepted", "EvidenceAttached",
                 "RunClosed", "CorrectionNoted"):
        fail("SCHEMA_INVALID")
    if k == "RunOpened":
        _req(d, ["run", "intent", "policy", "hypothetical"])
        _id(d["run"]); _object_ref(d["intent"])
        if d["policy"] is not None:
            _object_ref(d["policy"])
        if not isinstance(d["hypothetical"], bool):
            fail("SCHEMA_INVALID")
    elif k == "StepOpened":
        _req(d, ["run", "step", "operation", "input"])
        _id(d["run"]); _id(d["step"])
        if d["operation"] not in OPERATIONS:
            fail("SCHEMA_INVALID")
        if d["input"] is not None:
            _object_ref(d["input"])
    elif k == "ObservationRecorded":
        _req(d, ["run", "step", "value"])
        _id(d["run"]); _id(d["step"]); _object_ref(d["value"])
    elif k == "StepClosed":
        _req(d, ["run", "step", "outcome", "observation"])
        _id(d["run"]); _id(d["step"])
        if d["outcome"] not in OUTCOMES:
            fail("SCHEMA_INVALID")
        if d["outcome"] in ("SUCCEEDED", "FAILED") and d["observation"] is None:
            fail("SCHEMA_INVALID")
        if d["outcome"] in ("UNKNOWN", "CANCELLED") and d["observation"] is not None:
            fail("SCHEMA_INVALID")
        if d["observation"] is not None:
            _event_ref(d["observation"])
    elif k == "RunClosed":
        _req(d, ["run", "outcome"])
        _id(d["run"])
        if d["outcome"] not in OUTCOMES:
            fail("SCHEMA_INVALID")
    elif k == "CorrectionNoted":
        _req(d, ["target", "replacement", "reason"])
        _event_ref(d["target"]); _object_ref(d["replacement"])
        if d["reason"] not in ("SOURCE_ERROR", "DISPUTE"):
            fail("SCHEMA_INVALID")
    elif k == "EvidenceAttached":
        _req(d, ["run", "step", "format", "object"])
        _id(d["run"]); _id(d["step"]); _object_ref(d["object"])
        if d["format"] not in ("world-lineage/1", "vislineage-bundle/1", "covenant-opaque/1"):
            fail("UNSUPPORTED_SCHEMA")
    elif k == "DelegationOffered":
        _req(d, ["run", "delegation", "child", "scope"])
        _id(d["run"]); _id(d["delegation"])
        _req(d["child"], ["source", "stream", "run"])
        _id(d["child"]["source"]); _id(d["child"]["stream"]); _id(d["child"]["run"])
        _hash(d["scope"])
    elif k == "DelegationAccepted":
        _req(d, ["run", "delegation", "offer", "scope"])
        _id(d["run"]); _id(d["delegation"]); _event_ref(d["offer"]); _hash(d["scope"])


def parse_event(e):
    _req(e, ["body", "hash", "signature"])
    parse_event_body(e["body"])
    _hash(e["hash"])
    sig = b64u_dec(e["signature"])
    if len(sig) != 64:
        fail("SCHEMA_INVALID")
    return e


def parse_audit_body(b):
    _req(b, ["v", "workspace", "seq", "prev", "key", "principal", "request", "data"])
    if b["v"] != 1:
        fail("UNSUPPORTED_VERSION")
    _id(b["workspace"])
    if _count(b["seq"]) < 1:
        fail("SCHEMA_INVALID")
    _hash(b["prev"]); _hash(b["key"])
    _id(b["principal"]); _id(b["request"])
    _audit_data(b["data"])
    return b


def _audit_data(d):
    if not _is_obj(d) or "kind" not in d:
        fail("SCHEMA_INVALID")
    k = d["kind"]
    if k == "WorkspaceCreated":
        _req(d, ["config", "revision", "evidence"])
        _hash(d["config"]); _count(d["revision"]); _hash(d["evidence"])
    elif k == "SourceRegistered":
        _req(d, ["source", "revision", "evidence"])
        _source(d["source"]); _count(d["revision"]); _hash(d["evidence"])
    elif k == "ImportStaged":
        _req(d, ["stage", "batch"]); _id(d["stage"]); _hash(d["batch"])
    elif k == "ImportCommitted":
        _req(d, ["stage", "batch", "revision", "evidence"])
        _id(d["stage"]); _hash(d["batch"]); _count(d["revision"]); _hash(d["evidence"])
    elif k == "ImportCancelled":
        _req(d, ["stage", "reason"])
        _id(d["stage"])
        if d["reason"] not in ("USER", "EXPIRED"):
            fail("SCHEMA_INVALID")
    elif k == "KeyRotated":
        _req(d, ["old", "next", "proof"])
        _hash(d["old"]); _key_material(d["next"])
        if len(b64u_dec(d["proof"])) != 64:
            fail("SCHEMA_INVALID")
    elif k == "MigrationActivated":
        _req(d, ["manifest", "from_schema", "to_schema"])
        _hash(d["manifest"])
    elif k == "DisclosureRecorded":
        _req(d, ["method", "params"])
        _id(d["method"])
    elif k == "VerificationRecorded":
        _req(d, ["bundle", "trust"])
        _hash(d["bundle"]); _hash(d["trust"])
    elif k == "ConfigActivated":
        _req(d, ["previous", "config"]); _hash(d["previous"]); _hash(d["config"])
    else:
        fail("SCHEMA_INVALID")


def _source(s):
    _req(s, ["id", "namespace", "profile"])
    _id(s["id"]); _id(s["namespace"])
    if s["profile"] != "proof-evidence/1":
        fail("SCHEMA_INVALID")
    return s


def parse_audit(a):
    _req(a, ["body", "hash", "signature"])
    parse_audit_body(a["body"])
    _hash(a["hash"])
    if len(b64u_dec(a["signature"])) != 64:
        fail("SCHEMA_INVALID")
    return a


def parse_trust(t):
    _req(t, ["v", "workspace", "keys", "heads", "valid_until_unix_ms"])
    if t["v"] != 1:
        fail("UNSUPPORTED_VERSION")
    _id(t["workspace"])
    if not isinstance(t["keys"], list) or not isinstance(t["heads"], list):
        fail("SCHEMA_INVALID")
    for k in t["keys"]:
        _req(k, ["key", "role", "source", "stream", "first", "last", "status"])
        _hash(k["key"])
        if k["role"] not in ("origin", "audit"):
            fail("SCHEMA_INVALID")
        if k["source"] is not None:
            _id(k["source"])
        if k["stream"] is not None:
            _id(k["stream"])
        if _count(k["first"]) < 1 or _count(k["last"]) < _count(k["first"]):
            fail("SCHEMA_INVALID")
        if k["status"] not in ("ACTIVE", "RETIRED", "COMPROMISED"):
            fail("SCHEMA_INVALID")
    for h in t["heads"]:
        _req(h, ["role", "source", "stream", "seq", "hash"])
        if h["role"] not in ("origin", "audit"):
            fail("SCHEMA_INVALID")
        if h["source"] is not None:
            _id(h["source"])
        if h["stream"] is not None:
            _id(h["stream"])
        _count(h["seq"]); _hash(h["hash"])
    vu = t["valid_until_unix_ms"]
    if vu is not None:
        _count(vu)
    return t


def parse_bundle(b):
    _req(b, ["body", "hash", "events", "keys", "audit", "objects"])
    _hash(b["hash"])
    body = b["body"]
    _req(body, ["v", "format", "workspace", "revision", "sources", "actions", "cuts",
                "evidence", "projection", "inventory", "disclosure", "audit_through"])
    if body["v"] != 1 or body["format"] != "proof-bundle/1":
        fail("UNSUPPORTED_VERSION")
    _id(body["workspace"]); _count(body["revision"])
    for s in body["sources"]:
        _source(s)
    for a in body["actions"]:
        _event_ref(a)
    for c in body["cuts"]:
        _req(c, ["source", "stream", "through", "head"])
        _id(c["source"]); _id(c["stream"]); _count(c["through"]); _hash(c["head"])
    _hash(body["evidence"]); _hash(body["projection"])
    for i in body["inventory"]:
        _req(i, ["kind", "digest", "bytes", "availability"])
        if i["kind"] not in ("event", "audit", "key", "object"):
            fail("SCHEMA_INVALID")
        _hash(i["digest"]); _count(i["bytes"])
        if i["availability"] not in ("INCLUDED", "WITHHELD", "UNAVAILABLE"):
            fail("SCHEMA_INVALID")
        if i["kind"] != "object" and i["availability"] != "INCLUDED":
            fail("SCHEMA_INVALID")
    if body["disclosure"] not in ("FULL", "REDACTED", "HASHES_ONLY"):
        fail("SCHEMA_INVALID")
    _audit_ref(body["audit_through"])
    for e in b["events"]:
        parse_event(e)
    for k in b["keys"]:
        _key_material(k)
    for a in b["audit"]:
        parse_audit(a)
    for o in b["objects"]:
        _req(o, ["ref", "content"])
        _object_ref(o["ref"])
        if not isinstance(o["content"], str):
            fail("SCHEMA_INVALID")
    return b


# ---------- chain checks ----------

def _eref(e):
    return {"source": e["body"]["source"], "stream": e["body"]["stream"],
            "seq": e["body"]["seq"], "hash": e["hash"]}


def _eref_key(r):
    return (r["source"], r["stream"], int(r["seq"]), r["hash"])


def chain_check(events):
    findings = []
    slots = {}
    for e in events:
        k = (e["body"]["source"], e["body"]["stream"], int(e["body"]["seq"]))
        slots.setdefault(k, []).append(e)
    for k, arr in slots.items():
        if len(arr) > 1:
            findings.append({"code": "SOURCE_FORK",
                             "subjects": sorted([_eref(x) for x in arr], key=lambda r: (r["source"], r["stream"], int(r["seq"]), r["hash"]))})
    # prev / prefix / lamport
    by_seq = {}
    for e in events:
        by_seq.setdefault((e["body"]["source"], e["body"]["stream"]), {})[int(e["body"]["seq"])] = e
    for e in events:
        src, st, seq = e["body"]["source"], e["body"]["stream"], int(e["body"]["seq"])
        if seq == 1:
            if e["body"]["prev"] != ZERO_HASH:
                findings.append({"code": "PREV_MISMATCH", "subjects": [_eref(e)]})
        else:
            prev = by_seq.get((src, st), {}).get(seq - 1)
            if prev is None:
                findings.append({"code": "PREFIX_MISSING", "subjects": [_eref(e)]})
            elif prev["hash"] != e["body"]["prev"]:
                findings.append({"code": "PREV_MISMATCH", "subjects": [_eref(e)]})
        # lamport: event lamport = seq (native profile)
        if int(e["body"]["lamport"]) != seq:
            findings.append({"code": "LAMPORT_INVALID", "subjects": [_eref(e)]})
        # parents: no self, no future same-stream parent
        for p in e["body"]["parents"]:
            if p["hash"] == e["hash"]:
                findings.append({"code": "CAUSAL_CYCLE", "subjects": [_eref(e)]})
            if p["source"] == src and p["stream"] == st and int(p["seq"]) >= seq:
                findings.append({"code": "CAUSAL_CYCLE", "subjects": [_eref(e)]})
    # causal cycle detection over available parents
    adj = {}
    node_of = {}
    for e in events:
        node_of[e["hash"]] = e
        adj[e["hash"]] = [p["hash"] for p in e["body"]["parents"]]
    WHITE, GRAY, BLACK = 0, 1, 2
    color = {h: WHITE for h in adj}
    cycle = False

    def dfs(u, stack):
        nonlocal cycle
        color[u] = GRAY
        stack.append(u)
        for v in adj.get(u, []):
            if v not in adj:
                continue
            if color[v] == GRAY:
                cycle = True
            elif color[v] == WHITE:
                dfs(v, stack)
        stack.pop()
        color[u] = BLACK

    import sys
    sys.setrecursionlimit(100000)
    for h in sorted(adj):
        if color[h] == WHITE:
            dfs(h, [])
    if cycle:
        findings.append({"code": "CAUSAL_CYCLE", "subjects": []})
    return findings


def slot_map(events):
    m = {}
    for e in events:
        k = (e["body"]["source"], e["body"]["stream"], int(e["body"]["seq"]))
        m.setdefault(k, []).append(e)
    return m


# ---------- replay ----------

def replay(events, prior_findings):
    """Native state machine: RunOpened→StepOpened→ObservationRecorded→
    StepClosed→RunClosed with delegation/correction evidence."""
    ordered = sorted(events, key=lambda e: (e["body"]["source"], e["body"]["stream"], int(e["body"]["seq"]), e["hash"]))
    findings = [f for f in prior_findings]
    runs = {}
    steps = {}
    offers = {}
    used_offer_accepts = {}
    corrections = []
    applied = set()
    absent = set()
    gap_blocked = set()
    ev_by_hash = {e["hash"]: e for e in ordered}
    forked_hashes = set()
    for f in prior_findings:
        if f["code"] == "SOURCE_FORK":
            for s in f["subjects"]:
                forked_hashes.add(s["hash"])
    fork_blocked_streams = set()
    for e in ordered:
        if e["hash"] in forked_hashes:
            fork_blocked_streams.add((e["body"]["source"], e["body"]["stream"]))

    def deps_missing(e):
        src, st = e["body"]["source"], e["body"]["stream"]
        seq = int(e["body"]["seq"])
        if seq > 1:
            prev_hash = e["body"]["prev"]
            if prev_hash not in applied or prev_hash in gap_blocked:
                return True
        for p in e["body"]["parents"]:
            if p["hash"] in ev_by_hash and p["hash"] not in applied:
                return True
            if p["hash"] in gap_blocked:
                return True
        return False

    for e in ordered:
        src, st, seq = e["body"]["source"], e["body"]["stream"], int(e["body"]["seq"])
        if (src, st) in fork_blocked_streams and e["hash"] not in forked_hashes:
            gap_blocked.add(e["hash"])
            continue
        if deps_missing(e):
            absent.add(e["hash"])
            gap_blocked.add(e["hash"])
            continue
        d = e["body"]["data"]
        k = d["kind"]
        rid = (src, st, d.get("run"))
        if k == "RunOpened":
            runs[rid] = {"open": e, "closed": None, "hypothetical": d["hypothetical"],
                         "intent": d["intent"], "state": "OPEN"}
            applied.add(e["hash"])
        elif k == "StepOpened":
            r = runs.get(rid)
            if r is None or r["closed"] is not None:
                findings.append({"code": "STATE_TRANSITION", "subjects": [_eref(e)]})
                continue
            sid = rid + (d["step"],)
            steps[sid] = {"open": e, "closed": None, "observations": [], "state": "OPEN",
                          "operation": d["operation"]}
            applied.add(e["hash"])
        elif k == "ObservationRecorded":
            sid = rid + (d["step"],)
            s = steps.get(sid)
            if s is None or s["closed"] is not None:
                findings.append({"code": "STATE_TRANSITION", "subjects": [_eref(e)]})
                continue
            s["observations"].append(e)
            applied.add(e["hash"])
        elif k == "StepClosed":
            sid = rid + (d["step"],)
            s = steps.get(sid)
            if s is None or s["closed"] is not None:
                findings.append({"code": "STATE_TRANSITION", "subjects": [_eref(e)]})
                continue
            if d["outcome"] == "SUCCEEDED":
                obs = d.get("observation")
                if obs is None:
                    findings.append({"code": "STATE_TRANSITION", "subjects": [_eref(e)]})
                    continue
                ph = obs["hash"]
                if ph not in {p["hash"] for p in e["body"]["parents"]} or ph not in applied:
                    findings.append({"code": "STATE_TRANSITION", "subjects": [_eref(e)]})
                    continue
            s["closed"] = e
            s["state"] = d["outcome"]
            applied.add(e["hash"])
        elif k == "RunClosed":
            r = runs.get(rid)
            if r is None or r["closed"] is not None:
                findings.append({"code": "STATE_TRANSITION", "subjects": [_eref(e)]})
                continue
            r["closed"] = e
            r["state"] = d["outcome"]
            applied.add(e["hash"])
        elif k == "CorrectionNoted":
            tgt = d["target"]["hash"]
            if tgt not in {p["hash"] for p in e["body"]["parents"]}:
                findings.append({"code": "STATE_TRANSITION", "subjects": [_eref(e)]})
                continue
            corrections.append(e)
            applied.add(e["hash"])
        elif k == "EvidenceAttached":
            applied.add(e["hash"])
        elif k == "DelegationOffered":
            offers[(d["delegation"], d["scope"])] = e
            used_offer_accepts.setdefault((d["delegation"], d["scope"]), [])
            applied.add(e["hash"])
        elif k == "DelegationAccepted":
            key = (d["delegation"], d["scope"])
            if key in used_offer_accepts:
                used_offer_accepts[key].append(e)
            applied.add(e["hash"])
        else:
            applied.add(e["hash"])

    # delegation reuse: >1 accept on an offer suppresses all its edges
    for key, accepts in used_offer_accepts.items():
        if len(set(a["hash"] for a in accepts)) > 1:
            findings.append({"code": "DELEGATION_REUSED", "subjects": []})

    # projection
    proj_runs = []
    edges = []
    for rid, r in sorted(runs.items(), key=lambda kv: (kv[0][0], kv[0][1], kv[0][2])):
        rv = {"source": rid[0], "stream": rid[1], "run": rid[2],
              "hypothetical": r["hypothetical"], "state": r["state"],
              "opened": _eref(r["open"]), "closed": _eref(r["closed"]) if r["closed"] else None,
              "steps": []}
        for sid, s in sorted(steps.items(), key=lambda kv: kv[0]):
            if sid[:3] != rid:
                continue
            rv["steps"].append({
                "step": sid[3], "operation": s["operation"], "state": s["state"],
                "opened": _eref(s["open"]), "closed": _eref(s["closed"]) if s["closed"] else None,
                "observations": [o["body"]["data"]["value"] for o in s["observations"]],
                "evidence": [],
            })
        proj_runs.append(rv)
    # edges: precedes along chains, input/observed_as/caused_by
    by_stream = {}
    for e in ordered:
        by_stream.setdefault((e["body"]["source"], e["body"]["stream"]), []).append(e)
    for evs in by_stream.values():
        evs.sort(key=lambda e: int(e["body"]["seq"]))
        for a, c in zip(evs, evs[1:]):
            edges.append({"from": {"type": "event", "ref": _eref(a)},
                          "to": {"type": "event", "ref": _eref(c)}, "kind": "precedes"})
    for e in ordered:
        d = e["body"]["data"]
        if d["kind"] == "RunOpened":
            edges.append({"from": {"type": "object", "ref": d["intent"], "at": _eref(e)},
                          "to": {"type": "event", "ref": _eref(e)}, "kind": "input"})
        if d["kind"] == "ObservationRecorded":
            edges.append({"from": {"type": "event", "ref": _eref(e)},
                          "to": {"type": "object", "ref": d["value"], "at": _eref(e)},
                          "kind": "observed_as"})
        if d["kind"] == "StepClosed" and d.get("observation"):
            edges.append({"from": {"type": "event", "ref": d["observation"]},
                          "to": {"type": "event", "ref": _eref(e)}, "kind": "caused_by"})
    edges.sort(key=lambda e: jcs(e))
    proj = {"runs": proj_runs, "edges": edges, "findings": [], "corrections": [_eref(c) for c in corrections]}
    return proj, findings, applied


# ---------- trust ----------

def _pin_cmp(k):
    return (k["role"], k["source"] or "", k["stream"] or "", k["key"], int(k["first"]))


def _head_cmp(h):
    return (h["role"], h["source"] or "", h["stream"] or "", int(h["seq"]), h["hash"])


def trust_check(t):
    keys = t["keys"]
    for i in range(1, len(keys)):
        if _pin_cmp(keys[i - 1]) >= _pin_cmp(keys[i]):
            return "TRUST_INVALID"
    heads = t["heads"]
    for i in range(1, len(heads)):
        if _head_cmp(heads[i - 1]) >= _head_cmp(heads[i]):
            return "TRUST_INVALID"
    roles = {}
    for k in keys:
        roles.setdefault(k["key"], set()).add(k["role"])
        if len(roles[k["key"]]) > 1:
            return "TRUST_INVALID"
    scopes = {}
    for k in keys:
        scopes.setdefault((k["role"], k["source"], k["stream"]), []).append(k)
    for arr in scopes.values():
        arr.sort(key=lambda x: int(x["first"]))
        for i in range(1, len(arr)):
            if int(arr[i]["first"]) <= int(arr[i - 1]["last"]):
                return "TRUST_INVALID"
    head_slots = {}
    for h in heads:
        slot = (h["role"], h["source"], h["stream"], int(h["seq"]))
        if slot in head_slots and head_slots[slot] != h["hash"]:
            return "TRUST_INVALID"
        head_slots[slot] = h["hash"]
    return "OK"


def trust_time(t, as_of):
    if t["valid_until_unix_ms"] is None:
        return "OK"
    return "TRUST_EXPIRED" if int(as_of) >= int(t["valid_until_unix_ms"]) else "OK"


def key_check(record, key, trust, role):
    body = record["body"]
    is_event = "source" in body
    source = body.get("source") if is_event else None
    stream = body.get("stream") if is_event else None
    seq = int(body["seq"])
    scoped = [k for k in trust["keys"]
              if k["role"] == role and (role == "audit" or (k["source"] == source and k["stream"] == stream))]
    if not scoped:
        return "KEY_UNPINNED"
    pin = next((k for k in scoped if k["key"] == body["key"]), None)
    if not pin:
        return "KEY_UNPINNED"
    if seq < int(pin["first"]) or seq > int(pin["last"]):
        return "KEY_INTERVAL"
    if pin["status"] == "COMPROMISED":
        return "KEY_COMPROMISED"
    tag = D_EVENT_SIGN if role == "origin" else D_AUDIT_SIGN
    try:
        sig = b64u_dec(record["signature"])
        pub = b64u_dec(key["public"])
    except ProofError:
        return "SIGNATURE_INVALID"
    if key["id"] != body["key"]:
        return "SIGNATURE_INVALID"
    if not verify_sig(pub, signing_message(tag, record["hash"]), sig):
        return "SIGNATURE_INVALID"
    return "OK"


def head_check(cut_seq, events, pin):
    if pin["seq"] == "0":
        return "PIN_ABSENT" if pin["hash"] == ZERO_HASH else "PIN_MISMATCH"
    if int(pin["seq"]) > int(cut_seq):
        return "PIN_AHEAD"
    cands = [e for e in events if e["body"]["source"] == pin["source"]
             and e["body"]["stream"] == pin["stream"] and e["body"]["seq"] == pin["seq"]]
    if not cands:
        return "PIN_MISMATCH"
    if any(c["hash"] == pin["hash"] for c in cands):
        return "CONFLICTED" if len(cands) > 1 else "OK"
    return "PIN_MISMATCH"


def audit_head_check(prefix, pin):
    if pin["seq"] == "0":
        return "PIN_ABSENT" if pin["hash"] == ZERO_HASH else "PIN_MISMATCH"
    max_seq = max((int(a["body"]["seq"]) for a in prefix), default=0)
    if int(pin["seq"]) > max_seq:
        return "PIN_AHEAD"
    at = [a for a in prefix if a["body"]["seq"] == pin["seq"]]
    if not at:
        return "PIN_MISMATCH"
    if any(a["hash"] == pin["hash"] for a in at):
        return "CONFLICTED" if len(at) > 1 else "OK"
    return "PIN_MISMATCH"


# ---------- verify ----------

INVALIDATING = {"HASH_MISMATCH", "INVENTORY_MISMATCH", "KEY_MATERIAL_INVALID", "SIGNATURE_INVALID",
                "SCOPE_MISMATCH", "PREV_MISMATCH", "LAMPORT_INVALID", "STATE_TRANSITION",
                "PROJECTION_MISMATCH", "CAUSAL_CYCLE", "AUDIT_FORK", "AUDIT_BINDING_MISMATCH",
                "DELEGATION_REUSED", "DELEGATION_MISMATCH"}
CONFLICTING = {"SOURCE_FORK", "AUDIT_FORK"}
INCOMPLETE_CODES = {"PREFIX_MISSING", "PARENT_MISSING", "PIN_AHEAD"}


def _distinct_refs(events):
    m = {}
    for e in events:
        d = e["body"]["data"]
        refs = []
        if d["kind"] == "RunOpened":
            refs.append(d["intent"])
        elif d["kind"] == "ObservationRecorded":
            refs.append(d["value"])
        elif d["kind"] == "EvidenceAttached":
            refs.append(d["object"])
        elif d["kind"] == "CorrectionNoted" and d.get("replacement"):
            refs.append(d["replacement"])
        for r in refs:
            m[r["digest"]] = r
    return [m[k] for k in sorted(m)]


def _jcs_item(kind, envelope):
    j = jcs(envelope).encode("utf-8")
    return {"kind": kind, "digest": sha256_hex(j), "bytes": str(len(j)), "availability": "INCLUDED"}


def _sort_events(events):
    return sorted(events, key=lambda e: (e["body"]["source"], e["body"]["stream"], int(e["body"]["seq"]), e["hash"]))


def _sort_audit(a):
    return sorted(a, key=lambda x: int(x["body"]["seq"]))


def _compute_cuts(events):
    by_stream = {}
    for e in events:
        by_stream.setdefault((e["body"]["source"], e["body"]["stream"]), []).append(e)
    cuts = []
    for (src, st), evs in by_stream.items():
        mx = max(int(e["body"]["seq"]) for e in evs)
        top = [e for e in evs if int(e["body"]["seq"]) == mx]
        cuts.append({"source": src, "stream": st, "through": str(mx),
                     "head": top[0]["hash"] if len(top) == 1 else ZERO_HASH})
    return sorted(cuts, key=lambda c: (c["source"], c["stream"]))


def _recompute_phase(b):
    out = []
    if domain_hash(D_BUNDLE, b["body"]) != b["hash"]:
        out.append("HASH_MISMATCH")
    for e in b["events"]:
        if domain_hash(D_EVENT, e["body"]) != e["hash"]:
            out.append("HASH_MISMATCH")
    for a in b["audit"]:
        if domain_hash(D_AUDIT, a["body"]) != a["hash"]:
            out.append("HASH_MISMATCH")
    for k in b["keys"]:
        try:
            raw = b64u_dec(k["public"])
        except ProofError:
            out.append("KEY_MATERIAL_INVALID")
            continue
        if sha256_hex(raw) != k["id"]:
            out.append("KEY_MATERIAL_INVALID")
    for o in b["objects"]:
        try:
            raw = b64u_dec(o["content"])
        except ProofError:
            out.append("HASH_MISMATCH")
            continue
        if len(raw) != int(o["ref"]["bytes"]) or sha256_hex(raw) != o["ref"]["digest"]:
            out.append("HASH_MISMATCH")
    expected = {}
    for e in _sort_events(b["events"]):
        it = _jcs_item("event", e)
        expected[it["kind"] + ":" + it["digest"]] = it
    for a in _sort_audit(b["audit"]):
        it = _jcs_item("audit", a)
        expected[it["kind"] + ":" + it["digest"]] = it
    for k in sorted(b["keys"], key=lambda x: x["id"]):
        it = _jcs_item("key", k)
        expected[it["kind"] + ":" + it["digest"]] = it
    refs = _distinct_refs(b["events"])
    supplied = {o["ref"]["digest"]: o for o in b["objects"]}
    for r in refs:
        expected["object:" + r["digest"]] = {
            "kind": "object", "digest": r["digest"], "bytes": r["bytes"],
            "availability": "INCLUDED" if r["digest"] in supplied else "WITHHELD"}
    got = {}
    for i in b["body"]["inventory"]:
        k = i["kind"] + ":" + i["digest"]
        if k in got:
            out.append("INVENTORY_MISMATCH")
        got[k] = i
    for k, it in expected.items():
        g = got.get(k)
        if g is None:
            out.append("INVENTORY_MISMATCH")
            continue
        if g["bytes"] != it["bytes"]:
            out.append("INVENTORY_MISMATCH")
        if g["kind"] != "object" and g["availability"] != "INCLUDED":
            out.append("INVENTORY_MISMATCH")
        if g["kind"] == "object" and g["availability"] == "INCLUDED" and g["digest"] not in supplied:
            out.append("INVENTORY_MISMATCH")
    for k in got:
        if k not in expected:
            out.append("INVENTORY_MISMATCH")
    for o in b["objects"]:
        if not any(r["digest"] == o["ref"]["digest"] for r in refs):
            out.append("INVENTORY_MISMATCH")
    used = {e["body"]["key"] for e in b["events"]}
    ev = domain_hash(D_EVIDENCE, {
        "sources": sorted(b["body"]["sources"], key=lambda s: s["id"]),
        "events": _sort_events(b["events"]),
        "keys": sorted([k for k in b["keys"] if k["id"] in used], key=lambda x: x["id"]),
        "objects": refs,
    })
    if ev != b["body"]["evidence"]:
        out.append("HASH_MISMATCH")
    return sorted(set(out))


def _signature_phase(b):
    out = []
    key_by_id = {k["id"]: k for k in b["keys"]}
    for e in b["events"]:
        k = key_by_id.get(e["body"]["key"])
        if not k:
            out.append("KEY_MATERIAL_INVALID")
            continue
        try:
            pub = b64u_dec(k["public"]); sig = b64u_dec(e["signature"])
        except ProofError:
            out.append("KEY_MATERIAL_INVALID")
            continue
        if not verify_sig(pub, signing_message(D_EVENT_SIGN, e["hash"]), sig):
            out.append("SIGNATURE_INVALID")
    for a in b["audit"]:
        k = key_by_id.get(a["body"]["key"])
        if not k:
            out.append("KEY_MATERIAL_INVALID")
            continue
        try:
            pub = b64u_dec(k["public"]); sig = b64u_dec(a["signature"])
        except ProofError:
            out.append("KEY_MATERIAL_INVALID")
            continue
        if not verify_sig(pub, signing_message(D_AUDIT_SIGN, a["hash"]), sig):
            out.append("SIGNATURE_INVALID")
    return sorted(set(out))


def _structure_phase(b):
    out = []
    src_ids = {s["id"] for s in b["body"]["sources"]}
    for e in b["events"]:
        if e["body"]["workspace"] != b["body"]["workspace"] or e["body"]["source"] not in src_ids:
            out.append({"code": "SCOPE_MISMATCH", "subjects": [_eref(e)]})
    for a in b["audit"]:
        if a["body"]["workspace"] != b["body"]["workspace"]:
            out.append({"code": "SCOPE_MISMATCH", "subjects": []})
    if jcs(_compute_cuts(b["events"])) != jcs(sorted(b["body"]["cuts"], key=lambda c: (c["source"], c["stream"]))):
        out.append({"code": "INVENTORY_MISMATCH", "subjects": []})
    out.extend(chain_check(b["events"]))
    out.extend(_audit_chain_findings(b["audit"]))
    return out


def _audit_chain_findings(entries):
    out = []
    by_seq = {}
    for a in entries:
        by_seq.setdefault(int(a["body"]["seq"]), []).append(a)
    for arr in by_seq.values():
        if len(arr) > 1:
            out.append({"code": "AUDIT_FORK", "subjects": []})
    for a in entries:
        s = int(a["body"]["seq"])
        if s == 1:
            if a["body"]["prev"] != ZERO_HASH:
                out.append({"code": "PREV_MISMATCH", "subjects": []})
            if a["body"]["data"]["kind"] != "WorkspaceCreated":
                out.append({"code": "AUDIT_BINDING_MISMATCH", "subjects": []})
        else:
            prev = by_seq.get(s - 1)
            if not prev:
                out.append({"code": "PREFIX_MISSING", "subjects": []})
            elif not any(p["hash"] == a["body"]["prev"] for p in prev):
                out.append({"code": "PREV_MISMATCH", "subjects": []})
    registered = set()
    last_rev = 0
    stage_state = {}
    for a in sorted(entries, key=lambda x: int(x["body"]["seq"])):
        d = a["body"]["data"]
        k = d["kind"]
        if k == "WorkspaceCreated":
            if a["body"]["seq"] != "1":
                out.append({"code": "AUDIT_BINDING_MISMATCH", "subjects": []})
        elif k == "SourceRegistered":
            sid = d["source"]["id"]
            if sid in registered or int(d["revision"]) != last_rev + 1:
                out.append({"code": "AUDIT_BINDING_MISMATCH", "subjects": []})
            else:
                registered.add(sid); last_rev = int(d["revision"])
        elif k == "ImportCommitted":
            st = stage_state.setdefault(d["stage"], {"staged": False, "terminal": False})
            if int(d["revision"]) != last_rev + 1 or not st["staged"] or st["terminal"]:
                out.append({"code": "AUDIT_BINDING_MISMATCH", "subjects": []})
            else:
                last_rev = int(d["revision"])
            st["terminal"] = True
        elif k == "ImportCancelled":
            st = stage_state.setdefault(d["stage"], {"staged": False, "terminal": False})
            if not st["staged"] or st["terminal"]:
                out.append({"code": "AUDIT_BINDING_MISMATCH", "subjects": []})
            st["terminal"] = True
        elif k == "ImportStaged":
            st = stage_state.setdefault(d["stage"], {"staged": False, "terminal": False})
            if st["staged"]:
                out.append({"code": "AUDIT_BINDING_MISMATCH", "subjects": []})
            st["staged"] = True
        elif k == "KeyRotated":
            expect = domain_hash(D_ROTATE, {"workspace": a["body"]["workspace"], "old": d["old"],
                                            "next": d["next"], "head": a["body"]["prev"]})
            try:
                pub = b64u_dec(d["next"]["public"]); sig = b64u_dec(d["proof"])
                if not verify_sig(pub, bytes.fromhex(expect), sig):
                    out.append({"code": "AUDIT_BINDING_MISMATCH", "subjects": []})
            except ProofError:
                out.append({"code": "AUDIT_BINDING_MISMATCH", "subjects": []})
    return out


def _audit_binding_findings(b):
    through = b["body"]["audit_through"]
    rec = next((a for a in b["audit"] if a["body"]["seq"] == through["seq"] and a["hash"] == through["hash"]), None)
    if rec is None:
        return [{"code": "AUDIT_BINDING_MISMATCH", "subjects": []}]
    d = rec["body"]["data"]
    binds = d["kind"] in ("ImportCommitted", "SourceRegistered") and \
        d.get("revision") == b["body"]["revision"] and d.get("evidence") == b["body"]["evidence"]
    genesis = d["kind"] == "WorkspaceCreated" and b["body"]["revision"] == "0" and d.get("evidence") == b["body"]["evidence"]
    return [] if (binds or genesis) else [{"code": "AUDIT_BINDING_MISMATCH", "subjects": []}]


def _foreign_list(b):
    seen = {}
    for e in b["events"]:
        d = e["body"]["data"]
        if d["kind"] == "EvidenceAttached":
            o = d["object"]
            seen[(d["format"], o["digest"])] = {"digest": o["digest"], "format": d["format"], "assessment": "NOT_EVALUATED"}
    return sorted(seen.values(), key=lambda x: (x["format"], x["digest"]))


def verify_bundle(b, trust, requirement, as_of):
    v = {
        "v": 1, "bundle": b["hash"], "trust": sha256_hex(jcs(trust).encode()),
        "requirement": requirement, "as_of_unix_ms": as_of,
        "accepted": False, "integrity": "VALID", "lineage": "COMPLETE_RELATIVE",
        "reconstruction": "NONE", "origin": "UNTRUSTED", "audit": "UNTRUSTED",
        "freshness": "UNANCHORED", "semantics": "RECORDED_STATEMENTS_ONLY",
        "current_authority": "UNKNOWN", "foreign": _foreign_list(b), "reasons": [],
    }

    def fail_report(codes, conflict):
        v["integrity"] = "INVALID"; v["accepted"] = False
        v["reconstruction"] = "NONE"; v["origin"] = "UNTRUSTED"; v["audit"] = "UNTRUSTED"
        v["freshness"] = "UNANCHORED"
        v["lineage"] = "CONFLICTED" if conflict else "INCOMPLETE"
        v["reasons"] = sorted(set(codes))
        return v

    p2 = _recompute_phase(b)
    if p2:
        return fail_report(p2, False)
    p3 = _signature_phase(b)
    if p3:
        return fail_report(p3, False)
    p4 = _structure_phase(b)
    conflict = any(f["code"] in CONFLICTING for f in p4)
    p4inv = [f["code"] for f in p4 if f["code"] in INVALIDATING]
    if p4inv:
        return fail_report(p4inv, conflict)

    proj, replay_findings, applied = replay(b["events"], p4)
    p5 = []
    if domain_hash(D_PROJECTION, proj) != b["body"]["projection"]:
        p5.append("PROJECTION_MISMATCH")
    by_hash = {e["hash"]: e for e in b["events"]}
    for a in b["body"]["actions"]:
        if a["hash"] not in by_hash:
            p5.append("ACTION_UNKNOWN")
    p5.extend(f["code"] for f in _audit_binding_findings(b))
    structural_all = list({f["code"] for f in p4} | set(p5))
    p5inv = [c for c in p5 if c in INVALIDATING or c in ("ACTION_UNKNOWN", "PATH_LIMIT")]
    if p5inv:
        return fail_report(p5inv, conflict)
    replay_inv = [f["code"] for f in replay_findings if f["code"] in INVALIDATING]
    if replay_inv:
        return fail_report(replay_inv, conflict)

    if trust_check(trust) != "OK":
        fail("TRUST_INVALID")
    expired = trust_time(trust, as_of) == "TRUST_EXPIRED"
    tf = set()
    if expired:
        tf.add("TRUST_EXPIRED")

    streams = {}
    for e in b["events"]:
        streams.setdefault((e["body"]["source"], e["body"]["stream"]), []).append(e)
    origin_heads = {}
    for h in [x for x in trust["heads"] if x["role"] == "origin"]:
        origin_heads.setdefault((h["source"], h["stream"]), []).append(h)
    origin_conflict = False
    origin_untrusted = expired
    origin_incomplete = False
    any_ahead = False
    any_unanchored = False
    key_by_id = {k["id"]: k for k in b["keys"]}
    stream_anchored = {}
    for sk, evs in streams.items():
        for e in evs:
            km = key_by_id.get(e["body"]["key"])
            if not km:
                origin_untrusted = True; tf.add("KEY_UNPINNED"); continue
            r = key_check(e, km, trust, "origin")
            if r != "OK":
                origin_untrusted = True; tf.add(r)
        cut = str(max(int(e["body"]["seq"]) for e in evs))
        all_pins = origin_heads.get(sk, [])
        pins = [p for p in all_pins if p["seq"] != "0"]
        if not all_pins:
            any_unanchored = True; tf.add("PIN_ABSENT")
        anchored = False
        for pin in pins:
            hc = head_check(cut, evs, pin)
            if hc == "PIN_AHEAD":
                any_ahead = True; tf.add("PIN_AHEAD")
            elif hc == "PIN_MISMATCH":
                origin_conflict = True; tf.add("PIN_MISMATCH")
            elif hc == "CONFLICTED":
                origin_conflict = True; anchored = True
            else:
                anchored = True
        if all_pins and not pins:
            any_unanchored = True; tf.add("PIN_ABSENT")
        if pins and not anchored:
            if all(int(p["seq"]) > int(cut) for p in pins):
                origin_incomplete = True
            else:
                any_unanchored = True
        stream_anchored[sk] = anchored
    for arr in slot_map(b["events"]).values():
        if len(arr) > 1 and all(
                (key_by_id.get(e["body"]["key"]) is not None and
                 key_check(e, key_by_id[e["body"]["key"]], trust, "origin") == "OK") for e in arr):
            origin_conflict = True

    audit_conflict = False
    audit_untrusted = expired
    audit_incomplete = False
    audit_anchored = False
    for a in b["audit"]:
        km = key_by_id.get(a["body"]["key"])
        if not km:
            audit_untrusted = True; tf.add("KEY_UNPINNED"); continue
        r = key_check(a, km, trust, "audit")
        if r != "OK":
            audit_untrusted = True; tf.add(r)
    all_apins = [h for h in trust["heads"] if h["role"] == "audit"]
    apins = [h for h in all_apins if h["seq"] != "0"]
    if not all_apins or not apins:
        any_unanchored = True; tf.add("PIN_ABSENT")
    for pin in apins:
        hc = audit_head_check(b["audit"], pin)
        if hc == "PIN_AHEAD":
            any_ahead = True; audit_incomplete = True; tf.add("PIN_AHEAD")
        elif hc == "PIN_MISMATCH":
            audit_conflict = True; tf.add("PIN_MISMATCH")
        elif hc == "CONFLICTED":
            audit_conflict = True; audit_anchored = True
        else:
            audit_anchored = True

    def dim(conf, untr, inc, anchored):
        return "CONFLICTED" if conf else "UNTRUSTED" if untr else "INCOMPLETE" if inc else "PINNED" if anchored else "SIGNED_UNANCHORED"

    v["origin"] = dim(origin_conflict, origin_untrusted, origin_incomplete,
                      bool(streams) and all(stream_anchored.values()))
    v["audit"] = dim(audit_conflict, audit_untrusted, audit_incomplete, audit_anchored)
    v["freshness"] = "BEHIND_REQUIRED_CUT" if any_ahead else "UNANCHORED" if any_unanchored else "AT_REQUIRED_CUT"

    gap = any(c in INCOMPLETE_CODES for c in structural_all)
    v["lineage"] = "CONFLICTED" if conflict else "INCOMPLETE" if gap else "COMPLETE_RELATIVE"

    obj_avail = {i["digest"]: i["availability"] for i in b["body"]["inventory"] if i["kind"] == "object"}
    missing = False
    for r in _distinct_refs(b["events"]):
        av = obj_avail.get(r["digest"])
        if av != "INCLUDED":
            missing = True
            tf.add("OBJECT_WITHHELD" if av == "WITHHELD" else "OBJECT_MISSING")
    if not proj["runs"] and b["events"]:
        v["reconstruction"] = "NONE"
    elif conflict or gap or missing:
        v["reconstruction"] = "PARTIAL"
    else:
        v["reconstruction"] = "FULL_RECONSTRUCTION"

    v["integrity"] = "VALID"
    v["reasons"] = sorted(tf | set(structural_all))
    v["accepted"] = _accept(requirement, v)
    return v


def _accept(req, v):
    if v["integrity"] != "VALID" or v["lineage"] == "CONFLICTED":
        return False
    if req == "INTEGRITY":
        return True
    if v["reconstruction"] != "FULL_RECONSTRUCTION":
        return False
    if req == "RECONSTRUCTION":
        return True
    return v["origin"] == "PINNED" and v["audit"] == "PINNED" and v["freshness"] == "AT_REQUIRED_CUT"


def verify_bytes(bundle_utf8: bytes, trust_utf8: bytes, options: dict) -> dict:
    """Offline verification. No network, no clock, no provider calls."""
    bundle = parse_bundle(parse_json(bytes(bundle_utf8)))
    trust = parse_trust(parse_json(bytes(trust_utf8)))
    requirement = options.get("requirement", "ANCHORED")
    as_of = options.get("as_of_unix_ms", "0")
    return verify_bundle(bundle, trust, requirement, as_of)
