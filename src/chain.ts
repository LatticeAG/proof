/**
 * Stream structure checks (§1.2, §1.7 phase 4):
 *
 *  - slots:  a stream slot (workspace,source,stream,seq) may hold multiple
 *    signed candidates — that is a SOURCE_FORK, never an overwrite.
 *  - chain:  seq starts at 1 with prev=ZERO; at seq>1 the immediately
 *    preceding slot must exist at prev. Missing slot → PREFIX_MISSING;
 *    present nonmatching predecessor → PREV_MISMATCH.
 *  - lamport = 1 + max(previous.lamport, parents.lamport), empty max = 0;
 *    overflow is COUNTER_EXHAUSTED.
 *  - data-field EventRefs must also occur in parents (no hidden deps).
 *  - parents: sorted/unique (schema), no self-parents, no future same-stream
 *    parents, no cross-workspace references.
 */

import { ProofError } from "./errors.js";
import { ZERO_HASH } from "./crypto.js";
import { compareEventRef, eventRefOf, sameEventRef, type Event, type EventRef, type Finding } from "./model.js";

export function eventRefKey(r: EventRef): string {
  return `${r.source}\0${r.stream}\0${r.seq}\0${r.hash}`;
}

export function slotOf(e: Event): { source: string; stream: string; seq: string } {
  return { source: e.body.source, stream: e.body.stream, seq: e.body.seq };
}

function slotKeyOf(e: Event): string {
  return `${e.body.source}\0${e.body.stream}\0${BigInt(e.body.seq).toString(10)}`;
}

/** Group event candidates by stream slot; >1 candidate per slot is a fork. */
export function slotMap(events: Event[]): Map<string, Event[]> {
  const m = new Map<string, Event[]>();
  for (const e of events) {
    const k = slotKeyOf(e);
    const arr = m.get(k);
    if (arr) arr.push(e);
    else m.set(k, [e]);
  }
  return m;
}

/** Harness op `slots` (TV-P-13/14): scoped candidate uniqueness. */
export function slotsCheck(events: Event[]): { code: string } {
  const m = slotMap(events);
  for (const arr of m.values()) {
    if (arr.length > 1) return { code: "SOURCE_FORK" };
  }
  return { code: "OK" };
}

export function forkedSlots(events: Event[]): Set<string> {
  const m = slotMap(events);
  const out = new Set<string>();
  for (const [k, arr] of m) if (arr.length > 1) out.add(k);
  return out;
}

/** Find an event by exact scoped ref. */
export function findByRef(events: Event[], ref: EventRef): Event | undefined {
  return events.find((e) => {
    const r = eventRefOf(e);
    return sameEventRef(r, ref);
  });
}

/** Find all candidates occupying the slot (source,stream,seq) regardless of hash. */
export function findSlot(events: Event[], source: string, stream: string, seq: string): Event[] {
  return events.filter((e) => e.body.source === source && e.body.stream === stream && e.body.seq === seq);
}

/** EventRefs explicitly present inside EventData payload fields. */
export function dataEventRefs(e: Event): EventRef[] {
  const d = e.body.data;
  const out: EventRef[] = [];
  if (d.kind === "StepClosed" && d.observation !== null) out.push(d.observation as EventRef);
  if (d.kind === "DelegationAccepted") out.push(d.offer as EventRef);
  if (d.kind === "CorrectionNoted") out.push(d.target as EventRef);
  return out;
}

export interface ChainResult {
  code: string;
  findings: Finding[];
}

/**
 * Full chain check over an event set (§1.7 phase 4). Collects every finding;
 * `code` is the lexically-first finding for the single-code harness shape.
 */
export function chainCheck(events: Event[]): ChainResult {
  const findings: Finding[] = [];
  const slots = slotMap(events);
  const forked = new Set<string>();
  for (const [k, arr] of slots) {
    if (arr.length > 1) {
      forked.add(k);
      findings.push({ code: "SOURCE_FORK", subjects: arr.map(eventRefOf).sort(compareEventRef) });
    }
  }

  // Per-stream sequence/prev/lamport over each candidate.
  const byStream = new Map<string, Event[]>();
  for (const e of events) {
    const k = `${e.body.source}\0${e.body.stream}`;
    const arr = byStream.get(k);
    if (arr) arr.push(e);
    else byStream.set(k, [e]);
  }

  const refIndex = new Map<string, Event>();
  for (const e of events) refIndex.set(eventRefKey(eventRefOf(e)), e);

  for (const [sk, streamEvents] of byStream) {
    const seqs = new Map<bigint, Event[]>();
    for (const e of streamEvents) {
      const s = BigInt(e.body.seq);
      const arr = seqs.get(s);
      if (arr) arr.push(e);
      else seqs.set(s, [e]);
    }
    const minSeq = [...seqs.keys()].reduce((a, b) => (a < b ? a : b));
    for (const e of streamEvents) {
      const seq = BigInt(e.body.seq);
      const subj = [eventRefOf(e)];
      if (seq === 1n) {
        if (e.body.prev !== ZERO_HASH) findings.push({ code: "PREV_MISMATCH", subjects: subj });
      } else {
        const prevSlot = seqs.get(seq - 1n);
        if (!prevSlot) {
          // Missing predecessor — gap inside supplied range or prefix start.
          findings.push({ code: seq === minSeq ? "PREFIX_MISSING" : "PREFIX_MISSING", subjects: subj });
        } else if (!prevSlot.some((p) => p.hash === e.body.prev)) {
          findings.push({ code: "PREV_MISMATCH", subjects: subj });
        }
      }
      // parents
      let maxParentLamport = 0n;
      let parentOk = true;
      for (const p of e.body.parents) {
        if (sameEventRef(p, eventRefOf(e))) {
          findings.push({ code: "PARENT_MISSING", subjects: subj });
          parentOk = false;
          continue;
        }
        if (p.stream === e.body.stream && BigInt(p.seq) >= seq) {
          findings.push({ code: "PARENT_MISSING", subjects: [eventRefOf(e), p].sort(compareEventRef) });
          parentOk = false;
          continue;
        }
        const target = refIndex.get(eventRefKey(p));
        if (!target) {
          findings.push({ code: "PARENT_MISSING", subjects: [eventRefOf(e), p].sort(compareEventRef) });
          parentOk = false;
          continue;
        }
        if (target.body.lamport !== undefined && BigInt(target.body.lamport) > maxParentLamport) {
          maxParentLamport = BigInt(target.body.lamport);
        }
      }
      // data-field EventRefs must also occur in parents
      for (const dr of dataEventRefs(e)) {
        if (!e.body.parents.some((p) => sameEventRef(p, dr))) {
          findings.push({ code: "PARENT_MISSING", subjects: [eventRefOf(e), dr].sort(compareEventRef) });
        }
      }
      // lamport = 1 + max(prev.lamport, parents.lamport); a missing
      // predecessor makes the expected value unknown — the gap finding
      // stands alone rather than cascading into lamport noise.
      let prevLamport = 0n;
      let prevResolved = seq === 1n;
      if (seq > 1n) {
        const prevSlot = seqs.get(seq - 1n);
        if (prevSlot) {
          const prev = prevSlot.find((p) => p.hash === e.body.prev);
          if (prev) { prevLamport = BigInt(prev.body.lamport); prevResolved = true; }
        }
      }
      const expected = 1n + (prevLamport > maxParentLamport ? prevLamport : maxParentLamport);
      if (prevResolved && parentOk) {
        if (expected > 9223372036854775807n) {
          findings.push({ code: "COUNTER_EXHAUSTED", subjects: subj });
        } else if (BigInt(e.body.lamport) !== expected) {
          findings.push({ code: "LAMPORT_INVALID", subjects: subj });
        }
      }
    }
  }

  findings.sort((a, b) => a.code < b.code ? -1 : a.code > b.code ? 1 : 0);
  return { code: findings.length ? findings[0]!.code : "OK", findings };
}

/**
 * Harness op `chain` — sequence/prev/lamport only. Per §11.2 the op checks
 * "sequence/prev/Lamport" and returns the first violation in stream order:
 * PREFIX_MISSING for a prefix that starts late or skips, PREV_MISMATCH for
 * a present-but-different predecessor, LAMPORT_INVALID for a wrong clock.
 */
export function chainOp(events: Event[]): { code: string } {
  // Preserve caller order: group by stream, sort each by numeric seq.
  const byStream = new Map<string, Event[]>();
  for (const e of events) {
    const k = `${e.body.source}\0${e.body.stream}`;
    const arr = byStream.get(k);
    if (arr) arr.push(e);
    else byStream.set(k, [e]);
  }
  const refIndex = new Map<string, Event>();
  for (const e of events) refIndex.set(eventRefKey(eventRefOf(e)), e);

  for (const [, streamEvents] of [...byStream.entries()].sort(([a], [b]) => (a < b ? -1 : 1))) {
    const sorted = streamEvents.slice().sort((a, b) => (BigInt(a.body.seq) < BigInt(b.body.seq) ? -1 : 1));
    const seqs = new Map<bigint, Event[]>();
    for (const e of sorted) {
      const s = BigInt(e.body.seq);
      const arr = seqs.get(s); if (arr) arr.push(e); else seqs.set(s, [e]);
    }
    for (const e of sorted) {
      const seq = BigInt(e.body.seq);
      if (seq === 1n) {
        if (e.body.prev !== ZERO_HASH) return { code: "PREV_MISMATCH" };
      } else {
        const prevSlot = seqs.get(seq - 1n);
        if (!prevSlot) return { code: "PREFIX_MISSING" };
        const prev = prevSlot.find((p) => p.hash === e.body.prev);
        if (!prev) return { code: "PREV_MISMATCH" };
        // lamport = 1 + max(prev.lamport, max(parents' lamport))
        let m = BigInt(prev.body.lamport);
        for (const p of e.body.parents) {
          const t = refIndex.get(eventRefKey(p));
          if (t && BigInt(t.body.lamport) > m) m = BigInt(t.body.lamport);
        }
        if (BigInt(e.body.lamport) !== m + 1n) return { code: "LAMPORT_INVALID" };
      }
    }
  }
  return { code: "OK" };
}

/** Whether an event's slot is forked inside the given set. */
export function isForked(e: Event, events: Event[]): boolean {
  return findSlot(events, e.body.source, e.body.stream, e.body.seq).length > 1;
}
