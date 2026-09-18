// VARVEL — attack-surface model.
// The single shared state a campaign builds up and the console renders.
// Pure data + serialization: no I/O, no offensive logic. Orchestration only.
//
// Rich graph model (RedAmon-parity: 17 node types, 20 relationship kinds).
// Node types:
//   root — engagement/operator anchor        out — host outside the signed scope
//   host — in-scope live host                 subdomain — resolves to a host
//   service — an exposed service              port — an open port
//   endpoint — a URL/API path                 tech — a detected technology/component
//   cve — a known vuln affecting a tech       finding — a vetted finding (has severity)
//   exploit — a proposed/proved exploit       cred — a discovered credential
//   account — an account on a host            foothold — established access on a host
//   route — a pivot/lateral path              asset — misc in-scope asset

import { normSev, riskLevel } from './severity.mjs';

export const NODE_TYPES = {
  root: 'engagement', host: 'host', subdomain: 'subdomain', service: 'service', port: 'port',
  endpoint: 'endpoint', tech: 'technology', cve: 'CVE', finding: 'finding', exploit: 'exploit',
  cred: 'credential', account: 'account', foothold: 'foothold', route: 'pivot route',
  asset: 'asset', out: 'out-of-scope',
};
export const EDGE_KINDS = [
  'recon', 'resolves', 'svc', 'listens', 'exposes', 'runs', 'affects', 'finding', 'exploit',
  'yields', 'owns', 'pivots', 'lateral', 'escalates', 'drops', 'probes', 'contains',
  'remediates', 'hold', 'out',
];

// Findings carry a NUMERIC confidence (0-100). A finding at/above CONFIRM_AT is treated
// as "confirmed" — the only tier VARVEL will exploit. RedAmon has no confidence gate at
// all; the numeric score makes ours tunable and lets it feed the value-guided search.
export const CONFIRM_AT = 70;
export function toConf(c) {
  if (typeof c === 'number' && Number.isFinite(c)) return Math.max(0, Math.min(100, Math.round(c)));
  if (c === 'confirmed') return 85;
  if (c === 'suspected') return 40;
  return 40; // unstated -> suspected tier
}

export class Surface {
  constructor(scope) {
    this.scope = scope || { cidrs: [], signedBy: null, engagement: null };
    this.nodes = new Map();
    this.edges = [];
    this.holds = [];
    this.phaseLog = [];
    this.debunked = [];  // soft-404-debunked claims — visibly refuted, never silently dropped
    this._seq = 0;
    this._hostIndex = new Map(); // ip -> node id, for O(1) host dedup
    this.root = this.add({ type: 'root', label: this.scope.engagement || 'engagement', sub: this.scope.signedBy || '' });
  }

  _id(p) { return p + '-' + (++this._seq); }
  add(node) {
    const id = node.id || this._id(node.type || 'n');
    this.nodes.set(id, { id, type: 'host', label: id, sub: '', ...node });
    return id;
  }
  link(from, to, kind = 'contains') {
    if (!this.nodes.has(from) || !this.nodes.has(to)) return;
    if (!this.edges.some((e) => e.from === from && e.to === to && e.kind === kind)) this.edges.push({ from, to, kind });
  }
  _find(pred) { return [...this.nodes.values()].find(pred); }

  // ---- recon ----
  host(ip, { label, inScope = true } = {}) {
    const k = (ip != null && ip !== '') ? String(ip) : null;
    if (k && this._hostIndex.has(k)) return this._hostIndex.get(k); // O(1) dedup by ip
    const id = this.add({ type: inScope ? 'host' : 'out', label: label || ip || 'host', ip });
    this.link(this.root, id, inScope ? 'recon' : 'out');
    if (k) this._hostIndex.set(k, id); // hosts without an ip are NOT deduped (must not collide on undefined)
    return id;
  }
  subdomain(hostId, name) {
    const id = this.add({ type: 'subdomain', label: name });
    this.link(id, hostId, 'resolves');
    return id;
  }
  service(hostId, port, proto, name) {
    const id = this.add({ type: 'service', label: (name || proto || 'svc') + ':' + port, port, proto, host: hostId });
    this.link(hostId, id, 'svc');
    return id;
  }
  endpoint(hostId, url, method) {
    const id = this.add({ type: 'endpoint', label: url, method: method || 'GET' });
    this.link(hostId, id, 'exposes');
    return id;
  }
  tech(hostId, name, version) {
    const id = this.add({ type: 'tech', label: version ? `${name} ${version}` : name, name, version });
    this.link(hostId, id, 'runs');
    return id;
  }

  // ---- validate ----
  cve(id, cvss, affectsId) {
    const nid = this.add({ type: 'cve', label: id, cvss });
    if (affectsId) this.link(nid, affectsId, 'affects');
    return nid;
  }
  finding(hostId, { title, sev = 'med', ref, cve, confidence, evidence } = {}) {
    sev = normSev(sev); // ONE canonical vocabulary — 'critical'/'medium' no longer mis-land as 'med'
    const conf = toConf(confidence); // numeric 0-100
    const node = { type: 'finding', label: title || 'finding', sev, risk: riskLevel(sev), ref, cve, conf, confidence: conf >= CONFIRM_AT ? 'confirmed' : 'suspected' };
    // The validator gate reads evidence (the oracle a claim cites) — keep it on the node.
    if (evidence != null && evidence !== '') node.evidence = String(evidence).slice(0, 600);
    const id = this.add(node);
    this.link(hostId, id, 'finding');
    return id;
  }

  // ---- exploit / post-ex ----
  exploit(findingId, { title, ref, state = 'proposed' } = {}) {
    const id = this.add({ type: 'exploit', label: title || 'exploit', ref, gated: true, state });
    this.link(findingId, id, 'exploit');
    return id;
  }
  cred(fromId, principal, kind) {
    const id = this.add({ type: 'cred', label: principal, kind: kind || 'password' });
    if (fromId) this.link(fromId, id, 'yields');
    return id;
  }
  account(hostId, name) {
    const id = this.add({ type: 'account', label: name });
    this.link(hostId, id, 'owns');
    return id;
  }
  foothold(hostId, kind) {
    const id = this.add({ type: 'foothold', label: kind || 'session', host: hostId });
    this.link(hostId, id, 'escalates');
    return id;
  }
  route(fromHostId, toHostId, via) {
    const id = this.add({ type: 'route', label: via || 'pivot' });
    this.link(fromHostId, id, 'pivots');
    this.link(id, toHostId, 'lateral');
    return id;
  }

  hold({ action, rule, target }) { this.holds.push({ action, rule, target, at: new Date().toISOString() }); }
  note(phase, summary) { this.phaseLog.push({ phase, summary, at: new Date().toISOString() }); }
  // A scanner claim the soft-404 baseline REFUTED (engine/soft404.mjs). Recorded on the
  // surface so the report shows the debunk — a dropped claim without a trace is a lie.
  debunk({ host, path, title, tool }) { this.debunked.push({ host, path, title, tool, reason: 'soft404.match', at: new Date().toISOString() }); }

  // EvoGraph-class cross-session memory: seed hosts + findings from a prior saved
  // surface, marked `inherited` so the auditor still measures only THIS session's
  // real delta. Returns the number of nodes carried forward.
  seedFrom(prior) {
    if (!prior || !Array.isArray(prior.nodes)) return 0;
    let seeded = 0;
    const hosts = prior.nodes.filter((n) => n.type === 'host' && n.ip);
    const hostIp = new Map(hosts.map((n) => [n.id, n.ip]));
    const findingHostIp = new Map();
    for (const e of prior.edges || []) if (e.kind === 'finding' && hostIp.has(e.from)) findingHostIp.set(e.to, hostIp.get(e.from));
    for (const h of hosts) { const id = this.host(h.ip, { label: h.label }); const n = this.nodes.get(id); if (n && !n.inherited) { n.inherited = true; seeded++; } }
    for (const f of prior.nodes.filter((n) => n.type === 'finding')) {
      const ip = findingHostIp.get(f.id);
      const fid = this.finding(ip ? this.host(ip, {}) : this.root, { title: f.label, sev: f.sev, ref: f.ref, confidence: f.confidence });
      const n = this.nodes.get(fid); if (n) n.inherited = true;
      seeded++;
    }
    return seeded;
  }

  counts() {
    const c = { hosts: 0, subdomains: 0, svcs: 0, endpoints: 0, tech: 0, cves: 0, findings: 0, confirmed: 0, crit: 0, risk: { high: 0, medium: 0, info: 0 }, exploits: 0, creds: 0, footholds: 0, routes: 0, holds: this.holds.length };
    for (const n of this.nodes.values()) {
      if (n.type === 'host') c.hosts++;
      else if (n.type === 'subdomain') c.subdomains++;
      else if (n.type === 'service') c.svcs++;
      else if (n.type === 'endpoint') c.endpoints++;
      else if (n.type === 'tech') c.tech++;
      else if (n.type === 'cve') c.cves++;
      else if (n.type === 'finding') { c.findings++; if (n.sev === 'crit') c.crit++; if (n.confidence === 'confirmed') c.confirmed++; c.risk[n.risk || riskLevel(n.sev)]++; }
      else if (n.type === 'exploit') c.exploits++;
      else if (n.type === 'cred') c.creds++;
      else if (n.type === 'foothold') c.footholds++;
      else if (n.type === 'route') c.routes++;
    }
    return c;
  }

  toJSON() {
    return {
      scope: this.scope,
      nodes: [...this.nodes.values()],
      edges: this.edges,
      holds: this.holds,
      phaseLog: this.phaseLog,
      debunked: this.debunked,
      counts: this.counts(),
      model: { nodeTypes: Object.keys(NODE_TYPES).length, edgeKinds: EDGE_KINDS.length },
    };
  }

  static fromJSON(o) {
    const s = new Surface(o.scope);
    s.nodes = new Map((o.nodes || []).map((n) => [n.id, n]));
    s.edges = o.edges || [];
    s.holds = o.holds || [];
    s.phaseLog = o.phaseLog || [];
    s.debunked = o.debunked || [];
    s._seq = (o.nodes || []).length;
    s.root = ((o.nodes || []).find((n) => n.type === 'root') || {}).id;
    s._hostIndex = new Map();
    for (const n of s.nodes.values()) if ((n.type === 'host' || n.type === 'out') && n.ip != null && n.ip !== '') s._hostIndex.set(String(n.ip), n.id);
    // backfill the triage roll-up on legacy saves (stored sev is NOT re-normalized —
    // a historical coercion can't be un-done; risk is derived from what's stored)
    for (const n of s.nodes.values()) if (n.type === 'finding' && !n.risk) n.risk = riskLevel(n.sev);
    return s;
  }
}
