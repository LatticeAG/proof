/**
 * Native statement-state reduction (§2.1) → deterministic projection (§1.4).
 *
 * State is derived independently per (source,stream,run). A stream fork or
 * missing ancestor blocks reduction for that stream; an illegal transition
 * is retained evidence, never applied — the run is shown stopped at its
 * last legal state with STATE_TRANSITION recorded.
 *
 * Projection findings carry native structural/lifecycle codes only:
 * SOURCE_FORK, PREFIX_MISSING, PARENT_MISSING, PREV_MISMATCH,
 * LAMPORT_INVALID, CAUSAL_CYCLE, DELEGATION_REUSED, DELEGATION_MISMATCH,
 * STATE_TRANSITION. Availability and trust findings belong to Verification.
 */

import { jcsString, jcsCmp, type Json } from "./canon.js";
import {
  compareEventRef, eventRefOf, sameEventRef, type Edge, type Event, type EventRef,
  type Finding, type Node, type Projection, type RunView, type StepView, type ObjectRef,
  type ForeignFormat,
} from "./model.js";
import { eventRefKey, findSlot, slotMap } from "./chain.js";

type RunState = "OPEN" | "SUCCEEDED" | "FAILED" | "UNKNOWN" | "CANCELLED";

interface StepMut {
  step: string; operation: string; state: RunState;
  opened: EventRef; closed: EventRef | null;
  observations: Map<string, ObjectRef>;
  evidence: Map<string, { format: ForeignFormat; object: ObjectRef }>;
}

interface RunMut {
  source: string; stream: string; run: string; hypothetical: boolean;
  state: RunState; opened: EventRef; closed: EventRef | null;
  steps: Map<string, StepMut>;
}

interface Offer {
  ref: EventRef; delegation: string;
  child: { source: string; stream: string; run: string };
  scope: string;
  accepts: EventRef[];
}

export interface ReplayResult {
  projection: Projection;
  findings: Finding[];
  applied: Set<string>; // eventRefKey set of legally applied events
}

function nodeJcs(n: Node): string {
  return jcsString(n as unknown as Json);
}

function addFinding(list: Finding[], code: string, subjects: EventRef[]): void {
  const uniq = subjects.slice().sort(compareEventRef);
  list.push({ code, subjects: uniq });
}

function isTerminal(s: RunState): boolean {
  return s !== "OPEN";
}

/** Topological order over precedes+caused_by edges; null on causal cycle. */
function causalOrder(events: Event[]): Event[] | null {
  const byRef = new Map<string, Event>();
  for (const e of events) byRef.set(eventRefKey(eventRefOf(e)), e);
  const deps = new Map<string, Set<string>>();
  for (const e of events) {
    const k = eventRefKey(eventRefOf(e));
    const d = new Set<string>();
    const prev = prevCandidate(e, events);
    if (prev) d.add(eventRefKey(eventRefOf(prev)));
    for (const p of e.body.parents) {
      const t = byRef.get(eventRefKey(p));
      if (t) d.add(eventRefKey(p));
    }
    deps.set(k, d);
  }
  // Kahn with J(node) tie-break among ready nodes.
  const ready: Event[] = [];
  const indeg = new Map<string, number>();
  for (const [k, d] of deps) indeg.set(k, d.size);
  for (const e of events) if (indeg.get(eventRefKey(eventRefOf(e))) === 0) ready.push(e);
  ready.sort((a, b) => jcsCmp(eventRefOf(a) as unknown as Json, eventRefOf(b) as unknown as Json));
  const out: Event[] = [];
  const dependents = new Map<string, Event[]>();
  for (const e of events) {
    for (const dep of deps.get(eventRefKey(eventRefOf(e)))!) {
      const arr = dependents.get(dep) ?? [];
      arr.push(e);
      dependents.set(dep, arr);
    }
  }
  while (ready.length) {
    const e = ready.shift()!;
    out.push(e);
    for (const dep of dependents.get(eventRefKey(eventRefOf(e))) ?? []) {
      const k = eventRefKey(eventRefOf(dep));
      indeg.set(k, indeg.get(k)! - 1);
      if (indeg.get(k) === 0) {
        // maintain sorted ready order
        const idx = ready.findIndex((r) => jcsCmp(eventRefOf(r) as unknown as Json, eventRefOf(dep) as unknown as Json) > 0);
        if (idx === -1) ready.push(dep); else ready.splice(idx, 0, dep);
      }
    }
  }
  return out.length === events.length ? out : null;
}

function prevCandidate(e: Event, events: Event[]): Event | undefined {
  if (e.body.seq === "1") return undefined;
  const seq = (BigInt(e.body.seq) - 1n).toString();
  return findSlot(events, e.body.source, e.body.stream, seq).find((p) => p.hash === e.body.prev);
}

/**
 * Full native replay. `structuralFindings` carries the chain-check findings
 * (forks, gaps, lamport) already computed; this reducer adds lifecycle
 * findings and builds the projection.
 */
export function replay(events: Event[], structuralFindings: Finding[]): ReplayResult {
  const findings: Finding[] = structuralFindings.slice();
  const slots = slotMap(events);
  const forkedStreams = new Set<string>();
  for (const [, arr] of slots) {
    if (arr.length > 1) for (const e of arr) forkedStreams.add(`${e.body.source}\0${e.body.stream}`);
  }

  const byRef = new Map<string, Event>();
  for (const e of events) byRef.set(eventRefKey(eventRefOf(e)), e);

  const order = causalOrder(events);
  if (order === null) {
    addFinding(findings, "CAUSAL_CYCLE", events.map(eventRefOf));
  }

  const runs = new Map<string, RunMut>();
  const offers = new Map<string, Offer>();
  const corrections: EventRef[] = [];
  const applied = new Set<string>();
  const edges = new Map<string, Edge>();
  const absent = new Set<string>(); // eventRefKey of events not applied due to missing ancestry
  const gapBlocked = new Set<string>(); // transitively blocked by missing ancestry

  const edge = (from: Node, to: Node, kind: string) => {
    const e: Edge = { from, to, kind };
    edges.set(jcsString(e as unknown as Json), e);
  };
  const en = (e: Event): Node => ({ type: "event", ref: eventRefOf(e) });
  const on = (o: ObjectRef, at: Event): Node => ({ type: "object", ref: o, at: eventRefOf(at) });

  const runKey = (e: Event, run: string) => `${e.body.source}\0${e.body.stream}\0${run}`;

  for (const e of order ?? events) {
    const eref = eventRefOf(e);
    const ek = eventRefKey(eref);
    const body = e.body;
    const d = body.data;
    const streamForked = forkedStreams.has(`${body.source}\0${body.stream}`);
    const prev = prevCandidate(e, events);

    // Structural edges (declared, signed): always emitted for retained candidates.
    if (prev) edge(en(prev), en(e), "precedes");
    for (const p of body.parents) {
      const t = byRef.get(eventRefKey(p));
      if (t) edge(en(t), en(e), "caused_by");
    }
    switch (d.kind) {
      case "RunOpened": {
        edge(on(d.intent as unknown as ObjectRef, e), en(e), "input");
        if (d.policy !== null) edge(on(d.policy as unknown as ObjectRef, e), en(e), "authorized_by");
        break;
      }
      case "StepOpened":
        if (d.input !== null) edge(on(d.input as unknown as ObjectRef, e), en(e), "input");
        break;
      case "ObservationRecorded":
        edge(en(e), on(d.value as unknown as ObjectRef, e), "observed_as");
        break;
      case "EvidenceAttached":
        edge(on(d.object as unknown as ObjectRef, e), en(e), "imported_from");
        break;
      case "CorrectionNoted": {
        const t = byRef.get(eventRefKey(d.target as unknown as EventRef));
        if (t) edge(en(t), en(e), "corrects");
        edge(on(d.replacement as unknown as ObjectRef, e), en(e), "input");
        break;
      }
    }

    // Missing ancestors block application; the finding itself was recorded
    // by the chain check (PARENT_MISSING / PREFIX_MISSING). A dependency
    // that is itself gap-blocked suppresses downstream transition noise —
    // the event is left unapplied without a new finding.
    const depMissing = (k: string | undefined) => !k || !byRef.has(k) || gapBlocked.has(k);
    const depsMissing =
      (body.seq !== "1" && !prev) ||
      (prev !== undefined && gapBlocked.has(eventRefKey(eventRefOf(prev)))) ||
      body.parents.some((p) => depMissing(eventRefKey(p)) || !byRef.has(eventRefKey(p))) ||
      dataRefs(e).some((r) => depMissing(eventRefKey(r)) || !byRef.has(eventRefKey(r)));

    if (streamForked || depsMissing) {
      absent.add(ek);
      // Forked ancestors are ambiguous authorities: dependents cannot be
      // evaluated against either candidate, so they gap-block too.
      gapBlocked.add(ek);
      continue;
    }

    // State machine.
    let ok = true;
    const rk = (run: string) => runKey(e, run);
    switch (d.kind) {
      case "RunOpened": {
        const key = rk(d.run as string);
        if (runs.has(key)) { addFinding(findings, "STATE_TRANSITION", [eref]); ok = false; break; }
        runs.set(key, {
          source: body.source, stream: body.stream, run: d.run as string,
          hypothetical: d.hypothetical as boolean, state: "OPEN",
          opened: eref, closed: null, steps: new Map(),
        });
        break;
      }
      case "StepOpened": {
        const run = runs.get(rk(d.run as string));
        if (!run || isTerminal(run.state) || run.steps.has(d.step as string)) {
          addFinding(findings, "STATE_TRANSITION", [eref]); ok = false; break;
        }
        run.steps.set(d.step as string, {
          step: d.step as string, operation: d.operation as string, state: "OPEN",
          opened: eref, closed: null, observations: new Map(), evidence: new Map(),
        });
        break;
      }
      case "ObservationRecorded": {
        const run = runs.get(rk(d.run as string));
        const step = run?.steps.get(d.step as string);
        if (!run || isTerminal(run.state) || !step || isTerminal(step.state)) {
          addFinding(findings, "STATE_TRANSITION", [eref]); ok = false; break;
        }
        const o = d.value as unknown as ObjectRef;
        step.observations.set(o.digest, o);
        break;
      }
      case "EvidenceAttached": {
        const run = runs.get(rk(d.run as string));
        const step = run?.steps.get(d.step as string);
        if (!run || isTerminal(run.state) || !step || isTerminal(step.state)) {
          addFinding(findings, "STATE_TRANSITION", [eref]); ok = false; break;
        }
        const o = d.object as unknown as ObjectRef;
        step.evidence.set(`${d.format}\0${o.digest}`, { format: d.format as ForeignFormat, object: o });
        break;
      }
      case "StepClosed": {
        const run = runs.get(rk(d.run as string));
        const step = run?.steps.get(d.step as string);
        if (!run || isTerminal(run.state) || !step || isTerminal(step.state)) {
          addFinding(findings, "STATE_TRANSITION", [eref]); ok = false; break;
        }
        const obs = d.observation as EventRef | null;
        if (obs !== null) {
          const target = byRef.get(eventRefKey(obs));
          const good = target && applied.has(eventRefKey(obs))
            && body.parents.some((p) => sameEventRef(p, obs))
            && target.body.data.kind === "ObservationRecorded"
            && target.body.source === e.body.source && target.body.stream === e.body.stream
            && target.body.data.run === d.run && target.body.data.step === d.step;
          if (!good) { addFinding(findings, "STATE_TRANSITION", [eref]); ok = false; break; }
        }
        step.state = d.outcome as RunState;
        step.closed = eref;
        break;
      }
      case "RunClosed": {
        const run = runs.get(rk(d.run as string));
        if (!run || isTerminal(run.state)) {
          addFinding(findings, "STATE_TRANSITION", [eref]); ok = false; break;
        }
        const steps = [...run.steps.values()];
        const allTerm = steps.every((s) => isTerminal(s.state));
        const count = (s: RunState) => steps.filter((x) => x.state === s).length;
        const want = d.outcome as RunState;
        let legal = false;
        if (allTerm) {
          if (want === "SUCCEEDED") legal = steps.length >= 1 && count("SUCCEEDED") === steps.length;
          else if (want === "FAILED") legal = count("FAILED") >= 1;
          else if (want === "UNKNOWN") legal = count("FAILED") === 0 && count("UNKNOWN") >= 1;
          else legal = count("FAILED") === 0 && count("UNKNOWN") === 0 && count("CANCELLED") >= 1;
        }
        if (!legal) { addFinding(findings, "STATE_TRANSITION", [eref]); ok = false; break; }
        run.state = want;
        run.closed = eref;
        break;
      }
      case "DelegationOffered": {
        const run = runs.get(rk(d.run as string));
        const dup = [...offers.values()].some((o) =>
          o.delegation === d.delegation && o.ref.source === body.source && o.ref.stream === body.stream);
        if (!run || isTerminal(run.state) || dup) {
          addFinding(findings, "STATE_TRANSITION", [eref]); ok = false; break;
        }
        offers.set(ek, {
          ref: eref, delegation: d.delegation as string,
          child: d.child as { source: string; stream: string; run: string },
          scope: d.scope as string, accepts: [],
        });
        break;
      }
      case "DelegationAccepted": {
        const run = runs.get(rk(d.run as string));
        if (!run || isTerminal(run.state)) {
          addFinding(findings, "STATE_TRANSITION", [eref]); ok = false; break;
        }
        const offerRef = d.offer as unknown as EventRef;
        const offerEvent = byRef.get(eventRefKey(offerRef));
        const offer = offers.get(eventRefKey(offerRef));
        const matches = offerEvent && offer
          && offer.delegation === d.delegation
          && offer.scope === d.scope
          && offer.child.source === body.source && offer.child.stream === body.stream
          && offer.child.run === d.run;
        if (!matches) {
          addFinding(findings, "DELEGATION_MISMATCH", [eref, offerRef].sort(compareEventRef));
          ok = false;
          break;
        }
        offer!.accepts.push(eref);
        break;
      }
      case "CorrectionNoted": {
        // Guard: the target exists (data ref resolved above) and is an
        // explicit parent. Permitted after the target run closes; annotates,
        // never mutates.
        const tref = d.target as unknown as EventRef;
        if (!body.parents.some((p) => sameEventRef(p, tref))) {
          addFinding(findings, "STATE_TRANSITION", [eref]); ok = false; break;
        }
        corrections.push(eref);
        break;
      }
    }
    if (ok) applied.add(ek); else absent.add(ek);
  }

  // Delegation edges: exactly one matching accept survives; two or more
  // distinct accepts suppress every edge and produce DELEGATION_REUSED.
  for (const offer of offers.values()) {
    if (offer.accepts.length === 1) {
      const offerEvent = byRef.get(eventRefKey(offer.ref))!;
      const acceptEvent = byRef.get(eventRefKey(offer.accepts[0]!))!;
      edge(en(offerEvent), en(acceptEvent), "delegated_from");
    } else if (offer.accepts.length > 1) {
      addFinding(findings, "DELEGATION_REUSED", [offer.ref, ...offer.accepts]);
    }
  }

  // Deterministic projection serialization.
  const runViews: RunView[] = [...runs.values()]
    .map((r): RunView => ({
      source: r.source, stream: r.stream, run: r.run, hypothetical: r.hypothetical,
      state: r.state, opened: r.opened, closed: r.closed,
      steps: [...r.steps.values()]
        .sort((a, b) => (a.step < b.step ? -1 : a.step > b.step ? 1 : 0))
        .map((s): StepView => ({
          step: s.step, operation: s.operation, state: s.state, opened: s.opened, closed: s.closed,
          observations: [...s.observations.values()].sort((a, b) => (a.digest < b.digest ? -1 : 1)),
          evidence: [...s.evidence.values()].sort((a, b) =>
            a.format === b.format ? (a.object.digest < b.object.digest ? -1 : 1) : a.format < b.format ? -1 : 1),
        })),
    }))
    .sort((a, b) =>
      a.source === b.source
        ? a.stream === b.stream
          ? (a.run < b.run ? -1 : a.run > b.run ? 1 : 0)
          : a.stream < b.stream ? -1 : 1
        : a.source < b.source ? -1 : 1);

  const projFindings = dedupFindings(findings);
  const edgeList = [...edges.values()].sort((a, b) => nodeJcsEdge(a) < nodeJcsEdge(b) ? -1 : 1);

  const projection: Projection = {
    runs: runViews,
    edges: edgeList,
    findings: projFindings,
    corrections: corrections.sort(compareEventRef),
  };
  return { projection, findings: projFindings, applied };
}

function nodeJcsEdge(e: Edge): string {
  return jcsString(e as unknown as Json);
}

function dataRefs(e: Event): EventRef[] {
  const d = e.body.data;
  const out: EventRef[] = [];
  if (d.kind === "StepClosed" && d.observation !== null) out.push(d.observation as unknown as EventRef);
  if (d.kind === "DelegationAccepted") out.push(d.offer as unknown as EventRef);
  if (d.kind === "CorrectionNoted") out.push(d.target as unknown as EventRef);
  return out;
}

function dedupFindings(list: Finding[]): Finding[] {
  const m = new Map<string, Finding>();
  for (const f of list) {
    const subs = f.subjects.slice().sort(compareEventRef);
    const key = f.code + "\0" + jcsString(subs as unknown as Json);
    if (!m.has(key)) m.set(key, { code: f.code, subjects: subs });
  }
  return [...m.values()].sort((a, b) =>
    a.code === b.code
      ? jcsCmp(a.subjects as unknown as Json, b.subjects as unknown as Json)
      : a.code < b.code ? -1 : 1);
}
