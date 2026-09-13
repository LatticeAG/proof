"""Cross-language conformance: rebuild the §11.1 fixture in pure Python and
assert identical hashes/signatures/verdicts to the TypeScript implementation.
Golden constants come from the spec's fixture program."""

import base64
import hashlib
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from latticeag_proof_verify import (
    jcs, parse_json, verify_bytes, domain_hash, sha256_hex,
    D_EVENT, D_AUDIT, D_EVIDENCE, D_BUNDLE, D_PROJECTION, ZERO_HASH,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

Z = ZERO_HASH


def J(x):
    return jcs(x)


def H(b):
    if isinstance(b, str):
        b = b.encode()
    return hashlib.sha256(b).hexdigest()


def D(tag, x):
    return domain_hash(tag, x)


def key(seed_hex):
    sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
    pub = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {"secret": sk, "material": {"id": H(pub), "public": base64.urlsafe_b64encode(pub).rstrip(b"=").decode()}}


ORIGIN = key("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
AUDITOR = key("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")


def seal(body, role="EVENT", k=ORIGIN):
    h = D(b"LAGI-PROOF-" + role.encode() + b"/v1", body)
    msg = b"LAGI-PROOF-" + role.encode() + b"-SIGN/v1\x00" + bytes.fromhex(h)
    sig = base64.urlsafe_b64encode(k["secret"].sign(msg)).rstrip(b"=").decode()
    return {"body": body, "hash": h, "signature": sig}


def ref(e):
    return {"source": e["body"]["source"], "stream": e["body"]["stream"], "seq": e["body"]["seq"], "hash": e["hash"]}


def ar(e):
    return {"seq": e["body"]["seq"], "hash": e["hash"]}


def en(e):
    return {"type": "event", "ref": ref(e)}


def on(o, e):
    return {"type": "object", "ref": o["ref"], "at": ref(e)}


def blob(s, media):
    return {"ref": {"digest": H(s.encode()), "bytes": str(len(s.encode())), "media": media},
            "content": base64.urlsafe_b64encode(s.encode()).rstrip(b"=").decode()}


INTENT = blob("{}", "application/json")
OBSERVATION = blob("ok", "text/plain")
SOURCE = {"id": "src1", "namespace": "fixture", "profile": "proof-evidence/1"}


def event(data, n, previous, parents=None):
    return seal({"v": 1, "workspace": "ws1", "source": "src1", "stream": "main", "seq": str(n),
                 "prev": previous["hash"] if previous else Z, "lamport": str(n),
                 "key": ORIGIN["material"]["id"], "parents": parents or [], "data": data})


EVENTS = [
    event({"kind": "RunOpened", "run": "run1", "intent": INTENT["ref"], "policy": None, "hypothetical": False}, 1, None),
    event({"kind": "StepOpened", "run": "run1", "step": "step1", "operation": "compute", "input": None}, 2, None),
    event({"kind": "ObservationRecorded", "run": "run1", "step": "step1", "value": OBSERVATION["ref"]}, 3, None),
    event({"kind": "StepClosed", "run": "run1", "step": "step1", "outcome": "SUCCEEDED", "observation": None}, 4, None),
    event({"kind": "RunClosed", "run": "run1", "outcome": "SUCCEEDED"}, 5, None),
]
# fix prev/parents per fixture
EVENTS[1] = event({"kind": "StepOpened", "run": "run1", "step": "step1", "operation": "compute", "input": None}, 2, EVENTS[0])
EVENTS[2] = event({"kind": "ObservationRecorded", "run": "run1", "step": "step1", "value": OBSERVATION["ref"]}, 3, EVENTS[1])
EVENTS[3] = event({"kind": "StepClosed", "run": "run1", "step": "step1", "outcome": "SUCCEEDED", "observation": ref(EVENTS[2])}, 4, EVENTS[2], [ref(EVENTS[2])])
EVENTS[4] = event({"kind": "RunClosed", "run": "run1", "outcome": "SUCCEEDED"}, 5, EVENTS[3])

OBJECTS = sorted([INTENT, OBSERVATION], key=lambda x: x["ref"]["digest"])


def root(sources, evs, keys, objs):
    return D(D_EVIDENCE, {"sources": sources, "events": evs, "keys": keys, "objects": objs})


EMPTY_ROOT = root([], [], [], [])
REGISTERED_ROOT = root([SOURCE], [], [], [])
EVIDENCE = root([SOURCE], EVENTS, [ORIGIN["material"]], [o["ref"] for o in OBJECTS])
BATCH = {"events": EVENTS, "keys": [ORIGIN["material"]], "objects": OBJECTS}
BATCH_HASH = domain_hash(b"LAGI-PROOF-BATCH/v1", BATCH)

CONFIG = {
    "v": 1, "workspace": "ws1", "store": "./store", "socket": "./run/proof.sock", "socket_group_gid": 1000,
    "audit_key_file": "./keys/audit.pem", "recovery_trust_file": "./trust/recovery.json",
    "principals": [
        {"id": "admin1", "uid": 1000, "roles": ["admin"], "sources": []},
        {"id": "producer1", "uid": 1001, "roles": ["write"], "sources": ["src1"]},
        {"id": "reviewer1", "uid": 1002, "roles": ["read", "verify"], "sources": []},
    ],
    "limits": {"stage_bytes": 8388608, "bundle_bytes": 67108864, "store_bytes": "10737418240",
               "writer_queue": 16, "verify_workers": 2, "request_ms": 30000},
    "retention": {"stage_ttl_ms": "86400000", "committed": "INDEFINITE"},
    "storage": {"journal": "WAL", "synchronous": "FULL", "foreign_keys": True},
    "telemetry": {"sink": "./run/operations.jsonl", "payloads": False},
}

AUDIT = []


def audit_event(data, request, previous):
    return seal({"v": 1, "workspace": "ws1", "seq": str(int(previous["body"]["seq"]) + 1 if previous else 1),
                 "prev": previous["hash"] if previous else Z, "key": AUDITOR["material"]["id"],
                 "principal": "admin1", "request": request, "data": data}, "AUDIT", AUDITOR)


AUDIT.append(audit_event({"kind": "WorkspaceCreated", "config": H(J(CONFIG)), "revision": "0", "evidence": EMPTY_ROOT}, "init1", None))
AUDIT.append(audit_event({"kind": "SourceRegistered", "source": SOURCE, "revision": "1", "evidence": REGISTERED_ROOT}, "register1", AUDIT[0]))
AUDIT.append(audit_event({"kind": "ImportStaged", "stage": "st1", "batch": BATCH_HASH}, "stage1", AUDIT[1]))
AUDIT.append(audit_event({"kind": "ImportCommitted", "stage": "st1", "batch": BATCH_HASH, "revision": "2", "evidence": EVIDENCE}, "commit1", AUDIT[2]))

CUTS = [{"source": "src1", "stream": "main", "through": "5", "head": EVENTS[4]["hash"]}]
KEYS = sorted([ORIGIN["material"], AUDITOR["material"]], key=lambda k: k["id"])


def item(kind, x):
    j = J(x).encode()
    return {"kind": kind, "digest": H(j), "bytes": str(len(j)), "availability": "INCLUDED"}


INVENTORY = sorted(
    [item("event", e) for e in EVENTS] + [item("audit", a) for a in AUDIT] +
    [item("key", k) for k in KEYS] +
    [{"kind": "object", "digest": o["ref"]["digest"], "bytes": o["ref"]["bytes"], "availability": "INCLUDED"} for o in OBJECTS],
    key=lambda i: i["kind"] + ":" + i["digest"])

ACTION = ref(EVENTS[3])
BODY = {"v": 1, "format": "proof-bundle/1", "workspace": "ws1", "revision": "2",
        "sources": [SOURCE], "actions": [ACTION], "cuts": CUTS, "evidence": EVIDENCE,
        "projection": D(D_PROJECTION, PROJECTION := {
            "runs": [{
                "source": "src1", "stream": "main", "run": "run1", "hypothetical": False, "state": "SUCCEEDED",
                "opened": ref(EVENTS[0]), "closed": ref(EVENTS[4]),
                "steps": [{"step": "step1", "operation": "compute", "state": "SUCCEEDED",
                           "opened": ref(EVENTS[1]), "closed": ref(EVENTS[3]),
                           "observations": [OBSERVATION["ref"]], "evidence": []}],
            }],
            "edges": sorted(
                [{"from": en(EVENTS[i]), "to": en(EVENTS[i + 1]), "kind": "precedes"} for i in range(4)] +
                [{"from": on(INTENT, EVENTS[0]), "to": en(EVENTS[0]), "kind": "input"},
                 {"from": en(EVENTS[2]), "to": on(OBSERVATION, EVENTS[2]), "kind": "observed_as"},
                 {"from": en(EVENTS[2]), "to": en(EVENTS[3]), "kind": "caused_by"}],
                key=jcs),
            "findings": [], "corrections": []}),
        "inventory": INVENTORY, "disclosure": "FULL", "audit_through": ar(AUDIT[3])}
BUNDLE = {"body": BODY, "hash": D(D_BUNDLE, BODY), "events": EVENTS, "keys": KEYS, "audit": AUDIT, "objects": OBJECTS}

TRUST = {
    "v": 1, "workspace": "ws1",
    "keys": [
        {"key": AUDITOR["material"]["id"], "role": "audit", "source": None, "stream": None, "first": "1", "last": "100", "status": "ACTIVE"},
        {"key": ORIGIN["material"]["id"], "role": "origin", "source": "src1", "stream": "main", "first": "1", "last": "100", "status": "ACTIVE"},
    ],
    "heads": [
        {"role": "audit", "source": None, "stream": None, "seq": "4", "hash": AUDIT[3]["hash"]},
        {"role": "origin", "source": "src1", "stream": "main", "seq": "5", "hash": EVENTS[4]["hash"]},
    ],
    "valid_until_unix_ms": None,
}
OPTIONS = {"requirement": "ANCHORED", "as_of_unix_ms": "1789257600000"}

EXPECTED = {
    "v": 1, "bundle": BUNDLE["hash"], "trust": H(J(TRUST)), "requirement": "ANCHORED",
    "as_of_unix_ms": OPTIONS["as_of_unix_ms"], "accepted": True, "integrity": "VALID",
    "lineage": "COMPLETE_RELATIVE", "reconstruction": "FULL_RECONSTRUCTION",
    "origin": "PINNED", "audit": "PINNED", "freshness": "AT_REQUIRED_CUT",
    "semantics": "RECORDED_STATEMENTS_ONLY", "current_authority": "UNKNOWN",
    "foreign": [], "reasons": [],
}


class TestFixtureParity(unittest.TestCase):
    def test_golden_event_hash(self):
        self.assertEqual(EVENTS[0]["hash"], "8126edf35ef72f9a94909cde60f0c3955cedf774be3a0357f01078b1b1c1c2d9")

    def test_golden_signature(self):
        self.assertEqual(EVENTS[0]["signature"],
                         "ameqsvtAKofB1m1uZrPYDrdI4GCHEppx57f0QP2P-m1OqE-Jkbz4WvIrLTp0iIfck0EdvRQprvzyQHmodDPGBA")

    def test_canonicalize(self):
        self.assertEqual(jcs(json.loads('{"z":0,"a":[true,null,"x"]}')), '{"a":[true,null,"x"],"z":0}')

    def test_unicode_not_normalized(self):
        a = jcs(parse_json(b'{"s":"\xc3\xa9"}')).encode().hex()
        b = jcs(parse_json('{"s":"é"}'.encode())).encode().hex()
        self.assertEqual(a, "7b2273223a22c3a9227d")
        self.assertEqual(b, "7b2273223a2265cc81227d")

    def test_duplicate_member_rejected(self):
        from latticeag_proof_verify import ProofError
        with self.assertRaises(ProofError) as cm:
            parse_json(b'{"a":1,"a":2}')
        self.assertEqual(cm.exception.code, "JSON_INVALID")

    def test_verify_golden(self):
        result = verify_bytes(J(BUNDLE).encode(), J(TRUST).encode(), OPTIONS)
        self.assertEqual(result, EXPECTED)

    def test_verify_hash_only_disclosure(self):
        import copy
        b = copy.deepcopy(BUNDLE)
        b["objects"] = []
        for i in b["body"]["inventory"]:
            if i["kind"] == "object":
                i["availability"] = "WITHHELD"
        b["body"]["disclosure"] = "HASHES_ONLY"
        b["hash"] = D(D_BUNDLE, b["body"])
        result = verify_bytes(J(b).encode(), J(TRUST).encode(), OPTIONS)
        self.assertFalse(result["accepted"])
        self.assertEqual(result["reconstruction"], "PARTIAL")
        self.assertEqual(result["reasons"], ["OBJECT_WITHHELD"])

    def test_trust_expired(self):
        import copy
        t = copy.deepcopy(TRUST)
        t["valid_until_unix_ms"] = "1789257600000"
        result = verify_bytes(J(BUNDLE).encode(), J(t).encode(), OPTIONS)
        self.assertFalse(result["accepted"])
        self.assertIn("TRUST_EXPIRED", result["reasons"])


if __name__ == "__main__":
    unittest.main()
