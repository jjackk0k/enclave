// VARVEL — natural-language query over the attack-surface graph.
//
// RedAmon lets its agent ask the target graph questions in natural language (NL→Cypher
// against Neo4j). VARVEL's surface is an IN-MEMORY graph, so this is a native
// NL→structured-filter — no database, no query language to translate to, and (unlike a
// Neo4j round-trip) every match traces straight back to the node that produced it, which
// pairs with the honesty auditor's provenance story.
//
// Deterministic + hermetically testable. It parses intent (which node type), severity,
// confidence, port, and an "on <host>" relationship constraint out of ordinary phrasing.
// A live agent can call this for grounding; the console exposes it as a search box.

const TYPE_WORDS = [
  [/\b(host|hosts|machine|machines|box|boxes|ip|ips)\b/, 'host'],
  [/\b(subdomain|subdomains|vhost|vhosts)\b/, 'subdomain'],
  [/\b(service|services|port|ports|listen\w*)\b/, 'service'],
  [/\b(endpoint|endpoints|route|routes|url|urls|path|paths)\b/, 'endpoint'],
  [/\b(finding|findings|vuln\w*|weakness\w*|issue|issues)\b/, 'finding'],
  [/\b(exploit|exploits|chain|chains)\b/, 'exploit'],
  [/\b(cred|creds|credential|credentials|password|passwords|secret|secrets)\b/, 'cred'],
  [/\b(tech|technolog\w*|stack|software)\b/, 'tech'],
  [/\b(cve|cves)\b/, 'cve'],
  [/\b(foothold|footholds|shell|shells)\b/, 'foothold'],
  // THE AD TIER's node types (the attack-path view's vocabulary).
  [/\b(account|accounts|principal|principals)\b/, 'account'],
  [/\b(spn|spns)\b/, 'spn'],
];
const SEV_WORDS = [
  [/\b(crit\w*)\b/, 'crit'],
  [/\b(high\w*)\b/, 'high'],
  [/\b(med\w*|moderate)\b/, 'med'],
  [/\b(low\w*)\b/, 'low'],
  [/\b(info\w*)\b/, 'info'],
];

// queryGraph(surfaceJSON, "natural language") -> { interpretation, count, matched, filters }
export function queryGraph(surface, q) {
  const nodes = (surface && surface.nodes) || [];
  const edges = (surface && surface.edges) || [];

  // Extract the "on <host>" relationship FIRST and strip it, so a host label like
  // "nonexistent-host" can't be misread as the node type "host".
  let cleaned = ' ' + String(q || '').toLowerCase().trim() + ' ';
  let host = null;
  const hm = cleaned.match(/\b(?:on|for|at|in|against)\s+([a-z0-9][a-z0-9._-]{1,60})/);
  if (hm) { host = hm[1]; cleaned = cleaned.replace(hm[0], ' '); }

  let type = null;
  for (const [re, t] of TYPE_WORDS) if (re.test(cleaned)) { type = t; break; }
  let sev = null;
  for (const [re, s] of SEV_WORDS) if (re.test(cleaned)) { sev = s; break; }
  const confirmed = /\bconfirmed\b/.test(cleaned);
  const suspected = /\bsuspected\b/.test(cleaned);
  const provedOnly = /\bprov(ed|en)\b/.test(cleaned);
  let port = null;
  const pm = cleaned.match(/\bport\s+(\d{1,5})\b/) || cleaned.match(/[:\s](\d{2,5})\b/);
  if (pm) { const n = Number(pm[1]); if (n > 0 && n <= 65535) port = n; }

  // Resolve an "on <host>" constraint to the set of matching host node ids.
  let hostIds = null;
  if (host) {
    const h = host.toLowerCase();
    const hs = nodes.filter((n) => n.type === 'host' && (String(n.label || '').toLowerCase().includes(h) || String(n.ip || '').toLowerCase().includes(h)));
    hostIds = new Set(hs.map((n) => n.id));
    if (!hostIds.size) hostIds = null; // no such host — ignore the constraint rather than return nothing
  }
  const linkedToHost = (n) => {
    if (!hostIds) return true;
    if (n.type === 'host') return hostIds.has(n.id);
    return edges.some((e) => (hostIds.has(e.from) && e.to === n.id) || (hostIds.has(e.to) && e.from === n.id));
  };

  let matched = nodes.filter((n) => n.type !== 'root');
  if (type) matched = matched.filter((n) => n.type === type);
  if (sev) matched = matched.filter((n) => n.sev === sev);
  if (confirmed) matched = matched.filter((n) => n.confidence === 'confirmed');
  if (suspected) matched = matched.filter((n) => n.confidence === 'suspected');
  if (provedOnly) matched = matched.filter((n) => n.state === 'proved');
  if (port != null) matched = matched.filter((n) => n.port === port);
  matched = matched.filter(linkedToHost);

  const filters = { type, sev, confirmed, suspected, provedOnly, port, host: hostIds ? host : null };
  const bits = [
    type ? type + 's' : 'nodes',
    sev ? `severity ${sev}` : '',
    confirmed ? 'confirmed' : '', suspected ? 'suspected' : '', provedOnly ? 'proved' : '',
    port != null ? `port ${port}` : '',
    hostIds ? `on ${host}` : '',
  ].filter(Boolean);
  return {
    query: String(q || ''),
    interpretation: bits.join(' · '),
    count: matched.length,
    filters,
    matched: matched.slice(0, 200).map((n) => ({ id: n.id, type: n.type, label: n.label, sev: n.sev, confidence: n.confidence, port: n.port, ref: n.ref })),
  };
}

// ——— ATTACK-PATH VIEW (the AD tier's thin rung) ———
// Roast/lateral results land as graph edges so the console/report can answer the
// breach question honestly: "from our current access, what is the SHORTEST path to
// a DA-class principal?" The descriptive shape (as the evidence records it):
//   account --has-spn--> spn --runs-on--> host <--reachable-via:<adapter>-- srcHost
// Ingestion functions take a LIVE Surface (engine/surface.mjs — campaign.surface);
// path search takes either a Surface or its toJSON() shape. MEASURED-NOT-CLAIMED:
// a 'reachable-via' edge is added ONLY for a lateral exec that actually ran
// (item.ok), and a DA-class flag comes from enum evidence (adminCount/group
// membership — a heuristic, surfaced as one), never from a claim.
//
// TRAVERSAL SEMANTICS (the honest privilege flow): the descriptive edges record
// WHERE THINGS LIVE (account->spn->host), but compromise flows the other way for
// containment edges — owning a host exposes the SPNs running on it (runs-on,
// reversed), and cracking an SPN account's ticket yields that account (has-spn,
// reversed). Measured movement rides 'reachable-via:<adapter>' FORWARD (a RAN
// lateral exec only). pathsToPrivileged builds exactly that adjacency.

// Ingest one 'adroast.collected' event's fields (or roastGraphItems output) into
// the surface: account nodes (daClass flagged), one spn node per SPN, host nodes
// for the SPN targets (deduped against surfaced hosts by label/ip). Returns counts.
export function ingestAdRoastEvidence(surface, fields, { hostId = null } = {}) {
  if (!surface || typeof surface.add !== 'function' || typeof surface.link !== 'function') {
    throw new TypeError('ingestAdRoastEvidence needs a live Surface (campaign.surface) — it mutates the graph');
  }
  const items = fields && Array.isArray(fields.accounts) ? fields.accounts : [];
  let added = { accounts: 0, spns: 0, hosts: 0 };
  const findAccount = (user) => [...surface.nodes.values()].find((n) => n.type === 'account' && n.label === user);
  const findHostByName = (name) => {
    const h = String(name || '').toLowerCase();
    if (!h) return null;
    return [...surface.nodes.values()].find((n) => (n.type === 'host' || n.type === 'out')
      && (String(n.label || '').toLowerCase() === h || String(n.ip || '').toLowerCase() === h
        || String(n.label || '').toLowerCase().split('.')[0] === h.split('.')[0]));
  };
  for (const acc of items) {
    if (!acc || !acc.user) continue;
    let accId = (findAccount(acc.user) || {}).id;
    if (!accId) {
      accId = surface.add({ type: 'account', label: String(acc.user), realm: fields.realm || null, daClass: acc.daClass === true });
      added.accounts++;
    } else if (acc.daClass === true) {
      surface.nodes.get(accId).daClass = true; // a later sighting can upgrade the flag
    }
    if (hostId) surface.link(accId, hostId, 'seen-from'); // where the evidence was collected (provenance, NOT control)
    for (const spn of acc.spns || []) {
      const spnStr = String(spn || '');
      if (!spnStr.includes('/')) continue;
      const spnId = surface.add({ type: 'spn', label: spnStr, account: accId });
      added.spns++;
      surface.link(accId, spnId, 'has-spn');
      const hostPart = spnStr.split('/')[1] || '';
      const hostName = hostPart.split(':')[0]; // strip any :port
      let hId = (findHostByName(hostName) || {}).id;
      if (!hId && hostName) {
        hId = surface.add({ type: 'host', label: hostName, discovered: 'ad-enum' });
        added.hosts++;
      }
      if (hId) surface.link(spnId, hId, 'runs-on');
    }
  }
  return added;
}

// Ingest one lateral result (lateralGraphItems output: {srcHost, target, adapter, ok}):
// the measured reachability edge. srcHost = the agent's host id when known (the
// foothold the exec rode from). Only a RAN exec claims reachability.
export function ingestLateralEvidence(surface, item, { fromHostId = null } = {}) {
  if (!surface || typeof surface.add !== 'function' || typeof surface.link !== 'function') {
    throw new TypeError('ingestLateralEvidence needs a live Surface (campaign.surface) — it mutates the graph');
  }
  if (!item || item.ok !== true || !item.target) return { added: false, reason: 'not a successful exec — reachability is measured, never claimed' };
  let fromId = fromHostId;
  if (!fromId && item.srcHost) {
    const h = String(item.srcHost).toLowerCase();
    const found = [...surface.nodes.values()].find((n) => (n.type === 'host' || n.type === 'out') && (String(n.label || '').toLowerCase() === h || String(n.ip || '').toLowerCase() === h));
    fromId = found ? found.id : null;
  }
  if (!fromId) {
    const f = [...surface.nodes.values()].find((n) => n.type === 'foothold');
    fromId = f ? (f.host || f.id) : null; // current access: the first foothold's host
  }
  if (!fromId) return { added: false, reason: 'no source host/foothold in the graph — the edge would hang in the air' };
  const toId = typeof surface.host === 'function' ? surface.host(String(item.target), {}) : surface.add({ type: 'host', label: String(item.target), ip: item.target });
  const kind = 'reachable-via:' + String(item.adapter || 'unknown');
  const before = surface.edges.length;
  surface.link(fromId, toId, kind);
  return { added: surface.edges.length > before, from: fromId, to: toId, kind, adapter: item.adapter || null };
}

const asGraphJson = (g) => (g && typeof g.toJSON === 'function' ? g.toJSON() : g) || { nodes: [], edges: [] };

// Directed BFS shortest path over an explicit adjacency policy. traverse(edge) ->
// 'fwd' | 'rev' | null decides how (or whether) an edge is walkable; the default
// walks every edge forward. match(node) marks the goal set. Returns
// { path:[nodeIds], hops } or null when unreachable — an honest null, never a
// fabricated route.
export function shortestPath(graph, fromId, match, { traverse = null } = {}) {
  const g = asGraphJson(graph);
  if (!fromId || typeof match !== 'function') return null;
  const nodes = new Map((g.nodes || []).map((n) => [n.id, n]));
  if (!nodes.has(fromId)) return null;
  const adj = new Map();
  const push = (a, b) => { if (!adj.has(a)) adj.set(a, []); adj.get(a).push(b); };
  for (const e of g.edges || []) {
    const dir = traverse ? traverse(e) : 'fwd';
    if (dir === 'fwd') push(e.from, e.to);
    else if (dir === 'rev') push(e.to, e.from);
  }
  const prev = new Map([[fromId, null]]);
  const queue = [fromId];
  while (queue.length) {
    const cur = queue.shift();
    const node = nodes.get(cur);
    if (cur !== fromId && node && match(node)) {
      const path = [];
      for (let p = cur; p; p = prev.get(p)) path.unshift(p);
      return { path, hops: path.length - 1 };
    }
    for (const next of adj.get(cur) || []) {
      if (!prev.has(next)) { prev.set(next, cur); queue.push(next); }
    }
  }
  return null;
}

// The AD privilege-flow policy: measured movement ('reachable-via:<adapter>',
// 'pivots', 'lateral') walks FORWARD; containment edges that describe where things
// LIVE ('has-spn', 'runs-on') walk in REVERSE — owning the host exposes the SPN,
// roasting the SPN yields the account. Provenance edges ('seen-from', 'recon',
// 'finding'...) are NOT traversable: they record observation, never access.
export function adTraverse(edge) {
  const k = String((edge && edge.kind) || '');
  if (k.startsWith('reachable-via:') || k === 'pivots' || k === 'lateral') return 'fwd';
  if (k === 'has-spn' || k === 'runs-on') return 'rev';
  return null;
}

// The breach question: shortest path from current access to a DA-class principal.
// Sources: fromId, else every foothold node's host (the engagement's measured
// access). Targets: account nodes flagged daClass by enum evidence. Honest when
// empty.
export function pathsToPrivileged(graph, { fromId = null, limit = 5, traverse = adTraverse } = {}) {
  const g = asGraphJson(graph);
  const nodes = new Map((g.nodes || []).map((n) => [n.id, n]));
  const isDa = (n) => n.type === 'account' && n.daClass === true;
  const sources = fromId ? [fromId] : (g.nodes || []).filter((n) => n.type === 'foothold').map((n) => n.host || n.id);
  const daCount = (g.nodes || []).filter(isDa).length;
  const paths = [];
  for (const src of [...new Set(sources)]) {
    const hit = shortestPath(g, src, isDa, { traverse });
    if (hit) {
      const goal = nodes.get(hit.path[hit.path.length - 1]);
      paths.push({ from: src, to: hit.path[hit.path.length - 1], principal: goal ? goal.label : null, hops: hit.hops, path: hit.path });
    }
    if (paths.length >= limit) break;
  }
  paths.sort((a, b) => a.hops - b.hops);
  return {
    paths,
    assessed: { sources: [...new Set(sources)].length, daClassPrincipals: daCount },
    note: paths.length
      ? paths.length + ' measured path(s) from current access to DA-class principals — every hop is enum evidence or a RAN lateral exec, never a claimed route'
      : daCount === 0
        ? 'no DA-class principals in the graph (roast enum evidence with adminCount/group data lands them here) — no path assessed'
        : 'no path from current access to any DA-class principal over the measured edges — said plainly, never fabricated',
  };
}
