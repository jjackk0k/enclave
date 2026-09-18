// VARVEL — value-guided path search (LATS / MCTS adapted to a probe loop).
//
// RedAmon's headline reasoning feature is an Exploit-Path Search that adapts Monte
// Carlo Tree Search into a language-agent loop (the LATS pattern, ICML 2024): Select →
// Expand → Evaluate → Backpropagate, scoring REAL probes (no rollout/simulation),
// pruning dead branches, bounded depth, auto-activated only when ≥2 credible paths
// exist. This is VARVEL's equivalent — and it goes further than RedAmon's design in two
// ways their whitepaper does not claim: the value function can fold in (a) cross-session
// PRIORS and (b) an OPSEC noise COST, so the search concentrates budget on the paths
// that are both promising AND quiet.
//
// Pure + pluggable: `expand` (candidate children) and `probe` (execute one, → response)
// are injected, so this is hermetically testable and reusable (web paths today; more
// vectors later). It performs discovery/enumeration guidance only — it never fabricates
// or ships an exploit; detonation stays the governed, HITL-gated exploit phase.

// Outcome catalogue: a probe response maps to an outcome class → base value in [0,1].
// (RedAmon uses ~24 classes; this is the compact, web-focused core.)
export const OUTCOME_VALUE = {
  writable: 0.97,          // a state-changing request actually succeeded (broken access control)
  'sensitive-hit': 0.95,   // exposed secret/artifact (.env, .git, dump)
  'write-candidate': 0.90, // OPTIONS/405 reveals write methods (PUT/POST/DELETE) — write surface, probed non-destructively
  listing: 0.85,           // directory listing
  'error-leak': 0.75,      // stack trace / verbose error disclosure
  'auth-wall': 0.45,       // 401/403 — reachable but gated (a bypass candidate)
  'method-block': 0.30,    // 405 — endpoint exists, wrong method
  reachable: 0.35,         // generic 2xx
  redirect: 0.22,          // 3xx
  'waf-block': 0.05,       // actively blocked
  'not-found': 0.0,        // 404 / nothing
};

const hasWriteMethod = (m) => Array.isArray(m) && m.some((x) => /^(PUT|POST|DELETE|PATCH)$/.test(String(x).toUpperCase()));

// Classify a normalized response { status, body?, methods?, wrote? } into {cls, base}.
export function classifyResponse(r) {
  if (!r || r.status == null) return { cls: 'not-found', base: 0 };
  const s = r.status, body = r.body || '';
  if (r.wrote === true) return { cls: 'writable', base: OUTCOME_VALUE.writable };
  if (s === 404) return { cls: 'not-found', base: 0 };
  if (s === 401 || s === 403) return { cls: 'auth-wall', base: OUTCOME_VALUE['auth-wall'] }; // gated wins over write-candidate
  // A reachable endpoint that advertises write methods is the exploit surface (found via OPTIONS — no write performed).
  if (hasWriteMethod(r.methods) && ((s >= 200 && s < 300) || s === 405)) return { cls: 'write-candidate', base: OUTCOME_VALUE['write-candidate'] };
  if (s === 405) return { cls: 'method-block', base: OUTCOME_VALUE['method-block'] };
  if (s === 429 || s === 406 || (s === 400 && /blocked|forbidden|mod_security|waf/i.test(body))) return { cls: 'waf-block', base: OUTCOME_VALUE['waf-block'] };
  if (s >= 300 && s < 400) return { cls: 'redirect', base: OUTCOME_VALUE.redirect };
  if (s >= 200 && s < 300) {
    if (/(^|\n)\s*[A-Z0-9_]+\s*=|BEGIN (RSA|OPENSSH)|aws_secret|-----BEGIN|password|ref: refs\/|\[core\]/i.test(body)) return { cls: 'sensitive-hit', base: OUTCOME_VALUE['sensitive-hit'] };
    if (/index of|directory listing for|\[to parent directory\]/i.test(body)) return { cls: 'listing', base: OUTCOME_VALUE.listing };
    if (/stack trace|traceback|exception in|sqlstate|ora-\d{5}|warning: |fatal error/i.test(body)) return { cls: 'error-leak', base: OUTCOME_VALUE['error-leak'] };
    return { cls: 'reachable', base: OUTCOME_VALUE.reachable };
  }
  if (s >= 500) return { cls: 'error-leak', base: OUTCOME_VALUE['error-leak'] };
  return { cls: 'reachable', base: OUTCOME_VALUE.reachable };
}

let _nid = 0;
function node(descriptor, parent, depth) {
  return { id: ++_nid, descriptor, parent, depth, children: [], untried: null, visits: 0, value: 0, score: 0, cls: null, pruned: false };
}
const mean = (n) => (n.visits ? n.value / n.visits : 0);

// The search. Injected:
//   expand(descriptor, depth) -> [childDescriptor, …]   (candidate next probes)
//   probe(descriptor) -> response                        (async; run ONE real probe)
//   classify(response) -> {cls, base}                    (default classifyResponse)
//   prior(descriptor) -> [0,1]                           (optional cross-session prior boost)
//   opsecCost(descriptor) -> [0,1]                       (optional noise penalty, subtracted)
export async function pathSearch(root, {
  expand, probe, classify = classifyResponse, prior, opsecCost,
  maxDepth = 6, maxProbes = 60, breadth = 6, pruneFloor = 0.15, c = 1.4,
  minCrediblePaths = 2, credibleAt = 0.35,
} = {}) {
  if (typeof expand !== 'function' || typeof probe !== 'function') throw new TypeError('pathSearch needs expand() and probe()');
  _nid = 0;
  const root0 = node(root, null, 0);
  const trace = [];
  let probes = 0;

  const value = (descriptor, resp) => {
    const { cls, base } = classify(resp);
    let v = base;
    if (typeof prior === 'function') v = Math.min(1, v + 0.15 * (Number(prior(descriptor)) || 0));   // priors nudge, never dominate
    if (typeof opsecCost === 'function') v = Math.max(0, v - 0.25 * (Number(opsecCost(descriptor)) || 0)); // quieter paths win ties
    return { cls, v };
  };

  // Seed root's children by probing the initial candidate set (the "≥2 credible paths" test).
  root0.untried = [...expand(root0.descriptor, 0)];
  const seeded = [];
  for (const d of root0.untried.splice(0, breadth)) {
    if (probes >= maxProbes) break;
    const resp = await probe(d); probes++;
    const k = node(d, root0, 1);
    const { cls, v } = value(d, resp); k.cls = cls; k.score = v; k.visits = 1; k.value = v;
    k.pruned = v < pruneFloor;
    root0.children.push(k); seeded.push(k);
    trace.push({ depth: 1, descriptor: d, cls, score: Math.round(v * 100) / 100, pruned: k.pruned });
  }
  root0.visits = seeded.length; root0.value = seeded.reduce((s, k) => s + k.score, 0);

  const credible = seeded.filter((k) => k.score >= credibleAt);
  if (credible.length < minCrediblePaths) {
    return { activated: false, reason: `only ${credible.length} credible path(s) — linear loop suffices`, probes, tree: root0, best: rank(root0).slice(0, 3), trace };
  }

  // A node is worth SELECTING only if it (or a descendant) can still be expanded:
  // not low-value-pruned, under the depth ceiling, and holding unprobed candidates.
  // Low value → not selectable (search ignores it) but NOT pruned-from-ranking: a
  // high-value childless leaf is a real terminal, not a dead end.
  const canExpand = (n) => {
    if (n.pruned) return false;
    if (n.depth < maxDepth && (n.untried === null || n.untried.length > 0)) return true;
    return n.children.some(canExpand);
  };

  // Main MCTS loop over the remaining budget.
  while (probes < maxProbes && canExpand(root0)) {
    // Select: descend by UCT until we reach a node that is itself directly expandable.
    let n = root0;
    while (!(n.depth < maxDepth && (n.untried === null || n.untried.length > 0))) {
      const cands = n.children.filter(canExpand);
      if (!cands.length) break;
      const lnN = Math.log(Math.max(1, n.visits));
      let best = null, bestU = -Infinity;
      for (const k of cands) { const u = mean(k) + c * Math.sqrt(lnN / Math.max(1, k.visits)); if (u > bestU) { bestU = u; best = k; } }
      n = best;
    }
    if (n.untried === null) n.untried = [...expand(n.descriptor, n.depth)];
    if (!n.untried.length) continue; // nothing to expand here; canExpand() will route elsewhere

    const d = n.untried.shift();
    const resp = await probe(d); probes++;
    const child = node(d, n, n.depth + 1);
    const { cls, v } = value(d, resp); child.cls = cls; child.score = v; child.pruned = v < pruneFloor; // pruned = LOW VALUE only
    n.children.push(child);
    trace.push({ depth: child.depth, descriptor: d, cls, score: Math.round(v * 100) / 100, pruned: child.pruned });
    // Backpropagate the real score up the path (no rollout).
    for (let p = child; p; p = p.parent) { p.visits++; p.value += v; }
  }

  return { activated: true, probes, tree: root0, best: rank(root0).slice(0, 5), trace };
}

// The highest-VALUE individual nodes the search found (deduped by path, best score
// kept). Unlike rank() — which scores whole root→leaf paths — this surfaces the single
// most promising endpoints (a write-candidate, a sensitive hit), which is what focuses
// exploitation. Sorted most-valuable first.
export function topNodes(root, n = 5, minScore = 0.4) {
  const seen = new Map();
  const walk = (node) => {
    for (const k of node.children) {
      if (!k.pruned && k.score >= minScore) {
        const key = k.descriptor.path;
        if (!seen.has(key) || seen.get(key).score < k.score) seen.set(key, { descriptor: k.descriptor, cls: k.cls, score: Math.round(k.score * 100) / 100, depth: k.depth });
      }
      walk(k);
    }
  };
  walk(root);
  return [...seen.values()].sort((a, b) => b.score - a.score).slice(0, n);
}

// Rank leaf paths by cumulative value (the promising attack paths the search surfaced).
export function rank(root) {
  const paths = [];
  const walk = (n, acc) => {
    const here = [...acc, n];
    const live = n.children.filter((k) => !k.pruned);
    if (!live.length && n.depth > 0) {
      const steps = here.slice(1);
      paths.push({ score: steps.reduce((s, k) => s + k.score, 0), depth: n.depth, terminal: n.cls, path: steps.map((k) => ({ descriptor: k.descriptor, cls: k.cls, score: Math.round(k.score * 100) / 100 })) });
      return;
    }
    for (const k of live) walk(k, here);
  };
  walk(root, []);
  return paths.sort((a, b) => b.score - a.score);
}
