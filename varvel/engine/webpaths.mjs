// VARVEL — web adapter for the value-guided path search (pathsearch.mjs).
//
// Turns the abstract LATS search into concrete web content discovery: an EXPANDER that
// proposes candidate paths and a PROBER that executes ONE probe non-destructively. The
// prober only ever sends GET (for status/body) and OPTIONS (to reveal writable methods
// via the Allow header) — it NEVER performs a write during the search. Detonating the
// write it finds is the governed, HITL-gated exploit phase, not this.

import http from 'node:http';
import https from 'node:https';
import { pathSearch, classifyResponse, topNodes } from './pathsearch.mjs';

const CAP = 2048;
function req(base, path, method, timeout, agents) {
  return new Promise((resolve) => {
    let u; try { u = new URL(path, base); } catch { return resolve(null); }
    if (u.origin !== new URL(base).origin) return resolve(null); // same-origin only
    const lib = u.protocol === 'https:' ? https : http;
    let body = '', settled = false, t;
    const done = (v) => { if (!settled) { settled = true; clearTimeout(t); resolve(v); } };
    const r = lib.request({ hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80), path: u.pathname + u.search, method, timeout, rejectUnauthorized: false, agent: agents ? (u.protocol === 'https:' ? agents.httpsAgent : agents.httpAgent) : undefined, headers: { 'user-agent': 'VARVEL-pathsearch' } }, (res) => {
      res.on('data', (d) => { if (body.length < CAP) body += d.toString('latin1', 0, Math.max(0, CAP - body.length)); });
      res.on('end', () => done({ status: res.statusCode, headers: res.headers, body }));
    });
    t = setTimeout(() => { try { r.destroy(); } catch {} done(null); }, Math.max(timeout, 500));
    r.on('error', () => done(null));
    r.end();
  });
}
const parseAllow = (h) => String((h && h.allow) || '').split(',').map((s) => s.trim().toUpperCase()).filter(Boolean);

// One non-destructive probe: GET, plus OPTIONS when the path looks like it might accept
// writes (so we learn the method surface without ever sending one).
export function webProber(base, { timeout = 1500, agents = null } = {}) {
  return async (d) => {
    const g = await req(base, d.path, 'GET', timeout, agents);
    if (!g) return { status: null };
    let methods = parseAllow(g.headers);
    const worthOptions = !methods.length && (g.status === 405 || (g.status >= 200 && g.status < 300 && /\/(api|banner|users|admin|upload|edit|update|config)\b/i.test(d.path)));
    if (worthOptions) { const o = await req(base, d.path, 'OPTIONS', timeout, agents); if (o) methods = parseAllow(o.headers); }
    return { status: g.status, body: g.body, methods };
  };
}

// A focused content-discovery wordlist; the demo's reachable paths are a subset.
export const ROOT_WORDLIST = [
  '/admin', '/administrator', '/login', '/dashboard', '/console', '/portal',
  '/api', '/api/users', '/api/v1', '/graphql',
  '/admin/api/banner', '/api/banner', '/admin/api/content', '/admin/api/config', // common content-API write paths
  '/.env', '/.git/HEAD', '/.git/config', '/config.json', '/wp-config.php',
  '/backup', '/backup/', '/backup.zip', '/backup/db.sql', '/db.sql', '/robots.txt',
  '/status', '/health', '/metrics', '/internal', '/upload',
];
const COMMON_SUB = ['api', 'admin', 'login', 'users', 'banner', 'config', 'v1', 'internal', 'upload', 'edit', 'update', 'backup', 'db.sql', 'status', 'health'];

// Expander: root emits the seed wordlist; deeper nodes append common sub-resources to a
// reachable path (bounded by path length so it can't run away).
export function webExpander(seedPaths = ROOT_WORDLIST) {
  return (d, depth) => {
    if (depth === 0) return seedPaths.map((p) => ({ path: p }));
    const bp = String(d.path || '').replace(/\/+$/, '');
    if (bp.split('/').filter(Boolean).length >= 5) return []; // depth guard on path segments
    return COMMON_SUB.map((seg) => ({ path: bp + '/' + seg }));
  };
}

// Run the value-guided search against a base URL. Non-destructive; returns pathSearch's
// result ({ activated, probes, best, trace, tree }). The web search space is wide, so
// the initial seed is broad (breadth 12) before the tree concentrates on live branches.
export async function guidedWebSearch(base, { seedPaths, opsecCost, prior, maxProbes = 60, maxDepth = 5, breadth = 12, timeout = 1500, agents = null } = {}) {
  const res = await pathSearch({ path: '__root__' }, {
    expand: webExpander(seedPaths),
    probe: webProber(base, { timeout, agents }),
    classify: classifyResponse,
    opsecCost, prior, maxProbes, maxDepth, breadth,
  });
  res.top = topNodes(res.tree, 8); // highest-value individual endpoints (the exploit focus)
  return res;
}
