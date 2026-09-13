# Proof — LatticeAG zone core

[![LatticeAG](https://img.shields.io/badge/LatticeAG-Proof%20zone-f5a623)](https://github.com/LatticeAG)
[![status: OSS core](https://img.shields.io/badge/status-OSS%20core%2C%20pre--release-f5a623)](#status)
[![spec: P-1.0](https://img.shields.io/badge/spec-P--1.0-blue)](#)
[![license: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![conformance: 60/60](https://img.shields.io/badge/conformance-60%2F60-brightgreen)](#conformance)

**Bundles and lineage receipts travel with the work. Verify without trusting the operator who produced them.**

Proof is the LatticeAG zone that owns signed hash-chain receipts, evidence
roots, lineage reconstruction, and offline verification. Every accepted event
is bound into a predecessor chain; every published revision is bound into a
signed audit chain; every exported bundle carries enough signed material for a
verifier to recompute, reconstruct, and anchor — without contacting or
trusting the operator that produced it.

> Verify without trusting the operator. Preserve conflicting signed
> candidates. Report incompleteness explicitly — never silently.

## Status

This repository is the **OSS core** of the Proof zone: strict canonical JSON,
domain-separated SHA-256, Ed25519 event and audit chains, lifecycle replay to
deterministic projections, bounded lineage closure, evidence roots,
bundle assembly with disclosure labels, independent trust pins, offline
verification, a durable SQLite publication layer, a Unix-domain-socket RPC
service authorized by peer credentials, the `proof` CLI, and a Python
verification package with proven parity.

It is pre-release software. Production activation of the Proof zone is gated
by Covenant-v1 evidence (`UNWRITTEN_GATED`); hosted, cloud, and zone-gated
surfaces are defined interfaces that fail closed or report
`NOT_IMPLEMENTED` — they are never emulated.

## Build and test

```sh
npm ci
npm run build          # TypeScript → dist/
npm run build:native   # cc → native/peercred (Linux SO_PEERCRED helper)
npm test               # 72 tests: 60 spec conformance vectors + 12 core
npm run conformance    # the 60-vector conformance suite alone
npm run test:py        # Python verifier parity suite
npm run lint           # tsc --noEmit
```

Requires Node.js ≥ 22.5 (`node:sqlite`), a C compiler for the peer-credential
helper, and Python ≥ 3.11 with `cryptography` for the Python suite.

## Quick start

```sh
proof init --config proof.json            # create workspace store + genesis audit
proof serve --config proof.json           # UDS service, SO_PEERCRED admission
proof source register --file source.json --request-id rq-1 --config proof.json
proof import stage --stage st1 --batch batch.json --request-id rq-2 --config proof.json
proof import commit --stage st1 --request-id rq-3 --config proof.json
proof export --revision 2 --actions actions.json --include include.json \
    --out receipt.json --config proof.json
proof verify --bundle receipt.json --trust trust.json --require ANCHORED \
    --as-of-unix-ms <ms>
```

All output is canonical JSON. Verification of an exported bundle needs no
service, no network, and no operator cooperation — only the bundle and an
independently maintained trust file.

## Layout

- `src/` — TypeScript core (canon, crypto, model, chain, replay, lineage,
  bundle, trust, verify, store, service, server, maintenance, cli)
- `native/` — Linux `SO_PEERCRED` helper
- `py/latticeag_proof_verify/` — Python verifier (parity-proven)
- `test/` — fixture program, harness, and the 60-vector conformance suite

## License

MIT — see [LICENSE](LICENSE).
