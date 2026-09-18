// VARVEL — native API/endpoint/parameter surface discovery (authorized engagements).
//
// recon-BREADTH, not exploitation: this tool maps what a target VOLUNTEERS about its
// own surface — robots.txt, sitemap.xml, OpenAPI/Swagger descriptors, GraphQL's own
// documented read-only introspection query, and the endpoints/parameters referenced by
// the target's own HTML + same-origin JS. GET (+ the introspection POST) only. No
// writes, no injection, no auth brute force, no off-origin requests — ever.
//
// Stealth-aware like tools/webscan.mjs: pass a shared injected `pacer` (engine/stealth
// .mjs makePacer/asPacer) so one emission clock can govern a whole engagement, or a
// `stealth` profile name as a fallback. Every request is paced through it.

import http from 'node:http';
import https from 'node:https';
import { makePacer, asPacer } from '../engine/stealth.mjs';
import { pathPrefixAllowed, sanitizePathPrefixes } from '../engine/scopepath.mjs';

const BODY_CAP = 256 * 1024;          // per-response body cap (descriptors/HTML/JS)
const DEFAULT_MAX_REQUESTS = 40;      // hard total request budget per run
const MAX_JS = 4;                     // same-origin script files to mine
const MAX_SITEMAPS = 3;               // robots Sitemap: lines to follow
const DESCRIPTOR_PATHS = ['/openapi.json', '/swagger.json', '/v2/api-docs', '/api-docs'];
const HTTP_METHODS = ['get', 'post', 'put', 'delete', 'patch', 'head', 'options', 'trace'];

// The documented, read-only schema query — the same one any GraphQL IDE issues.
const INTROSPECTION_QUERY =
  'query IntrospectionQuery { __schema { queryType { name } mutationType { name } ' +
  'types { kind name fields { name args { name } } } } }';

// One raw request, same-origin pre-checked by the caller. Resolves null on any error.
// `hdrs` overrides the default tool UA — the engagement's shared browser persona under stealth.
function raw(u, { method = 'GET', body = null, timeout = 1500, cap = BODY_CAP, hdrs, agents } = {}) {
  return new Promise((resolve) => {
    const lib = u.protocol === 'https:' ? https : http;
    let text = '', settled = false;
    const done = (v) => { if (settled) return; settled = true; clearTimeout(deadline); resolve(v); };
    const headers = hdrs || { 'user-agent': 'VARVEL-apisurface', accept: '*/*' };
    if (body != null) { headers['content-type'] = 'application/json'; headers['content-length'] = Buffer.byteLength(body); }
    const req = lib.request({
      hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname + u.search, method, timeout, rejectUnauthorized: false,
      agent: agents ? (u.protocol === 'https:' ? agents.httpsAgent : agents.httpAgent) : undefined, headers,
    }, (r) => {
      r.on('data', (d) => {
        if (settled) return;
        if (text.length < cap) text += d.toString('utf8', 0, Math.max(0, cap - text.length));
        if (text.length >= cap) { done({ status: r.statusCode, headers: r.headers, body: text }); try { req.destroy(); } catch {} }
      });
      r.on('end', () => done({ status: r.statusCode, headers: r.headers, body: text }));
    });
    const deadline = setTimeout(() => { try { req.destroy(); } catch {} done(null); }, Math.max(timeout * 3, 3000));
    req.on('timeout', () => { try { req.destroy(); } catch {} done(null); });
    req.on('error', () => done(null));
    if (body != null) req.write(body);
    req.end();
  });
}

// Parse robots.txt: Allow/Disallow paths + Sitemap lines (sitemap URLs filtered to
// same-origin by the caller). Returns { paths: [...], sitemaps: [...] }.
export function parseRobots(text) {
  const paths = [], sitemaps = [];
  for (const line of String(text || '').split(/\r?\n/)) {
    const m = /^\s*(allow|disallow|sitemap)\s*:\s*(\S+)/i.exec(line);
    if (!m) continue;
    const [, key, value] = m;
    if (key.toLowerCase() === 'sitemap') sitemaps.push(value);
    else if (value && value !== '/') paths.push(value);
  }
  return { paths, sitemaps };
}

// Parse a sitemap.xml body into absolute URLs (same-origin filtering happens upstream).
export function parseSitemap(text) {
  const urls = [];
  const re = /<loc>\s*([^<]+?)\s*<\/loc>/gi;
  let m;
  while ((m = re.exec(String(text || '')))) urls.push(m[1]);
  return urls;
}

// Parse an OpenAPI/Swagger JSON document into endpoints + params.
// Returns null when the body isn't a recognizable API descriptor.
export function parseOpenApi(text) {
  let doc;
  try { doc = JSON.parse(text); } catch { return null; }
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) return null;
  const isSpec = (doc.openapi || doc.swagger) && doc.paths && typeof doc.paths === 'object';
  if (!isSpec) return null;
  const endpoints = [], params = [];
  for (const [p, item] of Object.entries(doc.paths)) {
    if (!item || typeof item !== 'object') continue;
    const methods = Object.keys(item).filter((k) => HTTP_METHODS.includes(k.toLowerCase()));
    endpoints.push({ path: p, methods: methods.map((m) => m.toUpperCase()) });
    const collect = (list) => {
      for (const prm of Array.isArray(list) ? list : []) {
        if (prm && typeof prm.name === 'string' && prm.name) {
          params.push({ name: prm.name, where: prm.in || 'query', path: p });
        }
      }
    };
    collect(item.parameters);
    for (const m of methods) collect(item[m] && item[m].parameters);
  }
  return {
    kind: doc.openapi ? 'openapi' : 'swagger',
    version: doc.openapi || doc.swagger || null,
    title: (doc.info && doc.info.title) || null,
    endpoints, params,
  };
}

// Parse an introspection response into the query/mutation fields the schema exposes.
// Returns null when introspection didn't come back with a schema.
export function parseIntrospection(text) {
  let doc;
  try { doc = JSON.parse(text); } catch { return null; }
  const schema = doc && doc.data && doc.data.__schema;
  if (!schema || !Array.isArray(schema.types)) return null;
  const roots = [schema.queryType && schema.queryType.name, schema.mutationType && schema.mutationType.name].filter(Boolean);
  const fields = [];
  let typeCount = 0;
  for (const t of schema.types) {
    if (!t || !t.name || t.name.startsWith('__')) continue;
    typeCount++;
    if (!roots.includes(t.name) || !Array.isArray(t.fields)) continue;
    for (const f of t.fields) {
      if (!f || !f.name) continue;
      fields.push({ name: f.name, args: (Array.isArray(f.args) ? f.args : []).map((a) => a && a.name).filter(Boolean) });
    }
  }
  return { typeCount, fields };
}

// Mine HTML for endpoints (links, form actions, inline fetch/URL literals) and params
// (form field names, query-string keys, linked same-origin scripts to fetch next).
export function parseHtml(html, base) {
  const endpoints = [], params = [], scripts = [];
  const text = String(html || '');
  let m;
  const addEndpoint = (rawUrl, source) => {
    if (!rawUrl || /^(mailto|javascript|data|tel):/i.test(rawUrl)) return;
    let u;
    try { u = new URL(rawUrl, base); } catch { return; }
    if (u.origin !== new URL(base).origin) return; // same-origin only
    endpoints.push({ path: u.pathname, source });
    for (const [k] of u.searchParams) params.push({ name: k, where: 'query', source, path: u.pathname });
  };
  const attr = (re, source) => {
    re.lastIndex = 0;
    while ((m = re.exec(text))) addEndpoint(m[1], source);
  };
  attr(/<a\s[^>]*?href\s*=\s*["']([^"']+)["']/gi, 'html-link');
  attr(/<form\s[^>]*?action\s*=\s*["']([^"']+)["']/gi, 'html-form');
  attr(/<(?:iframe|frame|img)\s[^>]*?src\s*=\s*["']([^"']+)["']/gi, 'html-embed');

  const reField = /<(?:input|select|textarea|button)\s[^>]*?name\s*=\s*["']([^"']+)["']/gi;
  while ((m = reField.exec(text))) params.push({ name: m[1], where: 'form', source: 'html-form' });

  const reScript = /<script\s[^>]*?src\s*=\s*["']([^"']+)["']/gi;
  while ((m = reScript.exec(text))) {
    try {
      const u = new URL(m[1], base);
      if (u.origin === new URL(base).origin) scripts.push(u.pathname + u.search);
    } catch { /* not a URL */ }
  }
  extractJsEndpoints(text, base, endpoints, params, 'html-inline');
  return { endpoints, params, scripts };
}

// Mine JS source for fetch/axios calls and conservative API-ish URL literals.
export function extractJsEndpoints(js, base, endpoints, params, source) {
  const text = String(js || '');
  const origin = new URL(base).origin;
  let m;
  const push = (rawUrl, src) => {
    let u;
    try { u = new URL(rawUrl, base); } catch { return; }
    if (u.origin !== origin) return;
    endpoints.push({ path: u.pathname, source: src });
    for (const [k] of u.searchParams) params.push({ name: k, where: 'query', source: src, path: u.pathname });
  };
  const reCall = /(?:fetch|axios\.(?:get|post|put|delete|patch|request)|\$\.(?:get|post|ajax)|\.open)\s*\(\s*((?:['"`][^'"`]{0,300}['"`])(?:\s*\+\s*(?:[\w.]+|['"`][^'"`]{0,120}['"`])){0,8})/g;
  while ((m = reCall.exec(text))) {
    const expr = m[1];
    const lit = /^['"`]([^'"`]{0,300})['"`]/.exec(expr);
    if (!lit) continue;
    push(lit[1], source); // the URL literal itself (endpoint + its own query keys)
    // Continuation literals in the SAME concatenation attribute to this path:
    // fetch('/api/search?q=' + x + '&page=' + p) — the '&page=' fragment carries a key.
    let u;
    try { u = new URL(lit[1], base); } catch { continue; }
    if (u.origin !== origin) continue;
    const reKey = /[?&]([\w.$-]{1,64})=/g;
    let km;
    while ((km = reKey.exec(expr))) params.push({ name: km[1], where: 'query', source, path: u.pathname });
  }
  const reLiteral = /['"`](\/(?:api|v\d{1,2}|graphql|rest|svc|service)(?:\/[\w.{}$-]+)*\/?(?:\?[\w&=+%${}-]*)?)['"`]/g;
  while ((m = reLiteral.exec(text))) push(m[1], source);
}

// base: e.g. 'http://10.10.2.18' or 'https://host:8443'
// `stealth`/`pacer`: optional operational-stealth. `pacer` (a shared injected pacer) wins
// over `stealth` (a profile) so one emission clock can govern a whole engagement.
export async function apiSurface(base, { timeout = 1500, maxRequests = DEFAULT_MAX_REQUESTS, stealth, pacer, agents = null, pathPrefixes = null } = {}) {
  let origin;
  try { const u = new URL(base); if (!/^https?:$/.test(u.protocol)) throw new Error('proto'); origin = u.origin; }
  catch { throw new TypeError('apiSurface: base must be an http(s) URL, got ' + JSON.stringify(base)); }

  pacer = asPacer(pacer) || (stealth ? makePacer(stealth) : null);
  const budget = Math.max(1, Math.floor(maxRequests) || DEFAULT_MAX_REQUESTS);
  let used = 0;
  // Path-prefix scope (fail-closed): out-of-prefix requests are refused BEFORE the
  // wire and recorded honestly (robots.txt/sitemap live at the root — under a
  // /book/-class scope they are OUT and must not be fetched).
  const px = sanitizePathPrefixes(pathPrefixes);
  const scopeRefusals = [];

  // Every request: budget-checked, same-origin enforced, paced through the pacer.
  async function request(path, { method = 'GET', body = null } = {}) {
    if (used >= budget) return null;
    let u;
    try { u = new URL(path, origin); } catch { return null; }
    if (u.origin !== origin) return null; // a `//other-host` reference can never escape scope
    if (!pathPrefixAllowed(u.pathname, px)) {
      if (!scopeRefusals.includes(u.pathname)) scopeRefusals.push(u.pathname);
      return null; // path-scope refusal — never sent
    }
    used++;
    if (pacer) await pacer.pace();
    const r = await raw(u, { method, body, timeout, hdrs: pacer && pacer.requestHeaders ? pacer.requestHeaders({ accept: '*/*' }) : undefined, agents });
    if (pacer && r && (r.status === 429 || r.status === 503)) pacer.penalize(2, 0); // adaptive back-off
    return r;
  }

  const epMap = new Map();   // path -> { path, methods:Set, source }
  const prMap = new Map();   // `${name}:${where}` -> { name, where, source }
  const descriptors = [];
  const findings = [];
  let graphql = null;
  const add = (title, sev, path) => findings.push({ title, sev, path, ref: 'API-' + (findings.length + 1) });
  const addEndpoint = (path, { methods = [], source } = {}) => {
    if (!path || typeof path !== 'string') return;
    const e = epMap.get(path) || { path, methods: new Set(), source };
    for (const mth of methods) e.methods.add(mth);
    epMap.set(path, e);
  };
  const addParam = (name, where, source, path) => {
    if (!name) return;
    const key = name + ':' + (where || 'query') + ':' + (path || '');
    if (!prMap.has(key)) prMap.set(key, { name, where: where || 'query', source, ...(path ? { path } : {}) });
  };
  const ok = (r) => r && r.status >= 200 && r.status < 300;

  // 1) robots.txt -> paths + sitemap pointers (both volunteered by the target itself).
  const robots = await request('/robots.txt');
  if (ok(robots) && !/^</.test(robots.body.trimStart())) {
    const { paths, sitemaps } = parseRobots(robots.body);
    for (const p of paths) {
      try {
        const u = new URL(p, origin);
        if (u.origin !== origin) continue;
        addEndpoint(u.pathname, { source: 'robots' });
        for (const [k] of u.searchParams) addParam(k, 'query', 'robots', u.pathname);
      } catch { /* skip */ }
    }
    // 2) sitemap.xml (+ robots Sitemap: lines, same-origin only, capped).
    const queue = ['/sitemap.xml'];
    for (const s of sitemaps) {
      try {
        const u = new URL(s, origin);
        if (u.origin === origin && queue.length < MAX_SITEMAPS + 1) queue.push(u.pathname + u.search);
      } catch { /* off-origin sitemap: ignored */ }
    }
    for (const sm of queue) {
      const r = await request(sm);
      if (!ok(r)) continue;
      for (const loc of parseSitemap(r.body)) {
        try {
          const u = new URL(loc, origin);
          if (u.origin !== origin) continue;
          addEndpoint(u.pathname, { source: 'sitemap' });
          for (const [k] of u.searchParams) addParam(k, 'query', 'sitemap', u.pathname);
        } catch { /* skip */ }
      }
    }
  }

  // 3) Common API descriptors the app may publish.
  for (const dp of DESCRIPTOR_PATHS) {
    const r = await request(dp);
    if (!ok(r)) continue;
    const spec = parseOpenApi(r.body);
    if (!spec) continue;
    descriptors.push({ path: dp, kind: spec.kind, version: spec.version, title: spec.title, endpoints: spec.endpoints.length });
    for (const e of spec.endpoints) addEndpoint(e.path, { methods: e.methods, source: 'descriptor:' + dp });
    for (const prm of spec.params) addParam(prm.name, prm.where, 'descriptor:' + dp, prm.path);
    // Genuinely notable: the full machine-readable API schema is served unauthenticated.
    add(`${spec.kind === 'swagger' ? 'Swagger' : 'OpenAPI'} descriptor exposed unauthenticated (${spec.endpoints.length} endpoints)`, 'low', dp);
  }

  // 4) GraphQL introspection — the documented read-only schema query, POSTed to /graphql.
  const gql = await request('/graphql', { method: 'POST', body: JSON.stringify({ query: INTROSPECTION_QUERY }) });
  if (ok(gql)) {
    const schema = parseIntrospection(gql.body);
    if (schema) {
      graphql = { path: '/graphql', types: schema.typeCount, fields: schema.fields.length };
      addEndpoint('/graphql', { methods: ['POST'], source: 'graphql' });
      for (const f of schema.fields) {
        addEndpoint('/graphql#' + f.name, { methods: ['POST'], source: 'graphql' });
        for (const a of f.args) addParam(a, 'graphql', 'graphql', '/graphql');
      }
      add(`GraphQL introspection enabled — full schema exposed unauthenticated (${schema.typeCount} types, ${schema.fields.length} root fields)`, 'low', '/graphql');
    }
  }

  // 5) Root HTML + same-origin linked JS: links, forms, fetch()/URL literals.
  const root = await request('/');
  if (ok(root) && /<[a-z!]/i.test(root.body)) {
    const mined = parseHtml(root.body, origin);
    for (const e of mined.endpoints) addEndpoint(e.path, { source: e.source });
    for (const prm of mined.params) addParam(prm.name, prm.where, prm.source, prm.path);
    for (const src of mined.scripts.slice(0, MAX_JS)) {
      const r = await request(src);
      if (!ok(r)) continue;
      const eps = [], prms = [];
      extractJsEndpoints(r.body, origin, eps, prms, 'js:' + src);
      for (const e of eps) addEndpoint(e.path, { source: e.source });
      for (const prm of prms) addParam(prm.name, prm.where, prm.source, prm.path);
    }
  }

  const endpoints = [...epMap.values()]
    .map((e) => ({ path: e.path, ...(e.methods.size ? { methods: [...e.methods] } : {}), source: e.source }))
    .sort((a, b) => a.path.localeCompare(b.path));
  const params = [...prMap.values()].sort((a, b) => a.name.localeCompare(b.name));
  return {
    base: origin,
    endpoints,
    params,
    descriptors,
    graphql,
    findings,
    requests: used,
    scopeRefusals,
    stealth: pacer ? pacer.profile.label : null,
  };
}
