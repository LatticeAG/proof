/**
 * Lineage reconstruction (§1.4).
 *
 * lineage.get traverses the complete incoming event-ancestor closure of the
 * selected actions, then includes every ObjectRef used by those events —
 * including outward observed_as edges — and returns the induced edges among
 * all included nodes. Node order is Kahn order with J(node) byte-order
 * tie-break; limits count event and object nodes and fail (PATH_LIMIT)
 * rather than truncate.
 */

import { jcsCmp, jcsString, type Json } from "./canon.js";
import { ProofError } from "./errors.js";
import { eventRefOf, type Edge, type Event, type Finding, type Node, type ObjectRef } from "./model.js";
import { eventRefKey } from "./chain.js";
import { eventDataObjectRefs, type EventRef } from "./model.js";

function en(e: Event): Node { return { type: "event", ref: eventRefOf(e) }; }
function on(o: ObjectRef, at: Event): Node { return { type: "object", ref: o, at: eventRefOf(at) }; }
function nj(n: Node): string { return jcsString(n as unknown as Json); }

/**
 * Object nodes used by an event: intent/policy (input/authorized_by),
 * step input (input), observation (observed_as), foreign object
 * (imported_from), correction replacement (input).
 */
function objectNodesOf(e: Event): Node[] {
  const d = e.body.data;
  const out: Node[] = [];
  for (const ref of eventDataObjectRefs(d)) out.push(on(ref, e));
  return out;
}

/** The incoming (ancestor) event edges of one event: prev + parents. */
function ancestorRefs(e: Event, byRef: Map<string, Event>, events: Event[]): Event[] {
  const out: Event[] = [];
  if (e.body.seq !== "1") {
    const prevSeq = (BigInt(e.body.seq) - 1n).toString();
    const prev = events.filter((x) =>
      x.body.source === e.body.source && x.body.stream === e.body.stream
      && x.body.seq === prevSeq && x.hash === e.body.prev);
    out.push(...prev);
  }
  for (const p of e.body.parents) {
    const t = byRef.get(eventRefKey(p));
    if (t) out.push(t);
  }
  return out;
}

export interface LineageResult {
  nodes: Node[];
  edges: Edge[];
  findings: Finding[];
}

/**
 * Compute the lineage subgraph for the selected actions inside a candidate
 * set. `findings` carries projection findings restricted to included event
 * subjects. Throws PATH_LIMIT when the closure or depth exceeds the bound.
 */
export function lineageClosure(
  events: Event[], actions: EventRef[], maxNodes: number, maxDepth: number,
  projectionEdges: Edge[], findings: Finding[],
): LineageResult {
  const byRef = new Map<string, Event>();
  for (const e of events) byRef.set(eventRefKey(eventRefOf(e)), e);
  const actionEvents: Event[] = [];
  for (const a of actions) {
    const t = byRef.get(eventRefKey(a));
    if (!t) throw new ProofError("ACTION_UNKNOWN", "Selected action is not retained in the revision.");
    actionEvents.push(t);
  }

  // BFS ancestor closure with depth bound.
  const included = new Map<string, Event>();
  const depthOf = new Map<string, number>();
  const queue: Event[] = [];
  for (const a of actionEvents) {
    const k = eventRefKey(eventRefOf(a));
    if (!included.has(k)) { included.set(k, a); depthOf.set(k, 0); queue.push(a); }
  }
  while (queue.length) {
    const cur = queue.shift()!;
    const d = depthOf.get(eventRefKey(eventRefOf(cur)))!;
    if (d >= maxDepth) {
      // Do not expand beyond max_depth; if further ancestors exist, fail.
      const further = ancestorRefs(cur, byRef, events).filter((x) => !included.has(eventRefKey(eventRefOf(x))));
      if (further.length) throw new ProofError("PATH_LIMIT", "Lineage depth exceeds bound.");
      continue;
    }
    for (const anc of ancestorRefs(cur, byRef, events)) {
      const k = eventRefKey(eventRefOf(anc));
      if (!included.has(k)) {
        included.set(k, anc);
        depthOf.set(k, d + 1);
        queue.push(anc);
      }
    }
  }

  // Object nodes used by every included event.
  const nodeSet = new Map<string, Node>();
  for (const e of included.values()) {
    nodeSet.set(nj(en(e)), en(e));
    for (const o of objectNodesOf(e)) nodeSet.set(nj(o), o);
  }
  if (nodeSet.size > maxNodes) throw new ProofError("PATH_LIMIT", "Lineage node count exceeds bound.");

  // Induced edges among included nodes.
  const edges: Edge[] = [];
  const seen = new Set<string>();
  for (const e of projectionEdges) {
    const key = jcsString(e as unknown as Json);
    if (seen.has(key)) continue;
    if (nodeSet.has(nj(e.from)) && nodeSet.has(nj(e.to))) {
      seen.add(key);
      edges.push(e);
    }
  }
  edges.sort((a, b) => jcsCmp(a as unknown as Json, b as unknown as Json));

  // Findings restricted to included event subjects.
  const eventKeys = new Set([...included.keys()]);
  const relevant = findings
    .map((f) => ({ code: f.code, subjects: f.subjects.filter((s) => eventKeys.has(eventRefKey(s))) }))
    .filter((f) => f.subjects.length > 0 || true);

  // Kahn order over induced edges; ties by J(node).
  const nodes = [...nodeSet.values()];
  const indeg = new Map<string, number>();
  const deps = new Map<string, string[]>();
  for (const n of nodes) indeg.set(nj(n), 0);
  for (const e of edges) {
    const t = nj(e.to);
    indeg.set(t, (indeg.get(t) ?? 0) + 1);
    const arr = deps.get(nj(e.from)) ?? [];
    arr.push(nj(e.to));
    deps.set(nj(e.from), arr);
  }
  const ready = nodes.filter((n) => indeg.get(nj(n)) === 0).map(nj).sort();
  const byJ = new Map(nodes.map((n) => [nj(n), n]));
  const ordered: Node[] = [];
  while (ready.length) {
    const k = ready.shift()!;
    ordered.push(byJ.get(k)!);
    for (const t of deps.get(k) ?? []) {
      indeg.set(t, indeg.get(t)! - 1);
      if (indeg.get(t) === 0) {
        const idx = ready.findIndex((r) => r > t);
        if (idx === -1) ready.push(t); else ready.splice(idx, 0, t);
      }
    }
  }
  // A causal cycle leaves nodes unvisited; surface them deterministically.
  if (ordered.length !== nodes.length) {
    const rest = nodes.map(nj).filter((k) => !ordered.some((o) => nj(o) === k)).sort();
    for (const k of rest) ordered.push(byJ.get(k)!);
  }

  return { nodes: ordered, edges, findings: relevant };
}

/**
 * boundedAncestors — harness op for the synthetic graph form (TV-P-51):
 * ancestor closure over named vertices with the same induced-edge and
 * Kahn-with-ascending-id semantics.
 */
export function boundedAncestors(g: {
  vertices: string[]; edges: [string, string][]; actions: string[];
  max_nodes: number; max_depth: number;
}): { nodes: string[]; edges: [string, string][] } {
  const adj = new Map<string, string[]>(); // child -> parents (edge a->b means a is ancestor of b)
  for (const [f, t] of g.edges) {
    const arr = adj.get(t) ?? [];
    arr.push(f);
    adj.set(t, arr);
  }
  const included = new Set<string>();
  const depth = new Map<string, number>();
  const queue: string[] = [];
  for (const a of g.actions) { included.add(a); depth.set(a, 0); queue.push(a); }
  while (queue.length) {
    const cur = queue.shift()!;
    const d = depth.get(cur)!;
    if (d >= g.max_depth) {
      // Hitting the depth bound with unexpanded ancestors fails, never truncates.
      if ((adj.get(cur) ?? []).some((p) => !included.has(p))) {
        throw new ProofError("PATH_LIMIT", "Depth bound exceeded.");
      }
      continue;
    }
    for (const p of adj.get(cur) ?? []) {
      if (!included.has(p)) { included.add(p); depth.set(p, d + 1); queue.push(p); }
    }
  }
  if (included.size > g.max_nodes) throw new ProofError("PATH_LIMIT", "Node bound exceeded.");
  const edges = g.edges.filter(([f, t]) => included.has(f) && included.has(t));
  // Kahn over induced edges, tie-break ascending vertex id.
  const indeg = new Map<string, number>();
  const kids = new Map<string, string[]>();
  for (const v of included) indeg.set(v, 0);
  for (const [f, t] of edges) {
    indeg.set(t, (indeg.get(t) ?? 0) + 1);
    const arr = kids.get(f) ?? []; arr.push(t); kids.set(f, arr);
  }
  const ready = [...included].filter((v) => indeg.get(v) === 0).sort();
  const nodes: string[] = [];
  while (ready.length) {
    const v = ready.shift()!;
    nodes.push(v);
    for (const t of kids.get(v) ?? []) {
      indeg.set(t, indeg.get(t)! - 1);
      if (indeg.get(t) === 0) {
        const idx = ready.findIndex((r) => r > t);
        if (idx === -1) ready.push(t); else ready.splice(idx, 0, t);
      }
    }
  }
  for (const v of [...included].sort()) if (!nodes.includes(v)) nodes.push(v);
  return { nodes, edges };
}
