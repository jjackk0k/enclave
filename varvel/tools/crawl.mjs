// VARVEL — native web crawler (authorized engagements).
//
// recon-BREADTH, not exploitation: this is the Katana/Hakrawler job, built native per
// Jack's directive (no industry wrappers). It follows the links and forms the target
// itself serves — BFS over same-origin HTML — to map the NAVIGABLE attack surface:
// endpoints, query parameters, and forms (method + fields). It discovers what a
// wordlist cannot (paths nobody brute-forces) and never guesses: every request is a
// page the target volunteered a route to. GET only. No form submission, no injection,
// no state-changing links (logout/sign-out are skipped), no off-origin requests — ever.
//
// Quieter than content discovery by construction: it requests real linked pages (no
// 404 flood), so its footprint is the 'web-crawl' kind (loudness 2), not the
// brute-force 'web-content-scan' (4).
//
// Stealth-aware like tools/webscan.mjs + tools/apisurface.mjs: pass a shared injected
// `pacer` (engine/stealth.mjs makePacer/asPacer) so one emission clock governs the
// whole engagement, or a `stealth` profile name as a fallback. Every request is paced.

import http from 'node:http';
import https from 'node:https';
import { makePacer, asPacer } from '../engine/stealth.mjs';
import { pathPrefixAllowed, sanitizePathPrefixes } from '../engine/scopepath.mjs';
import { fingerprintPages } from './wappalyze.mjs';
import { extractJsEndpoints } from './apisurface.mjs';

const BODY_CAP = 256 * 1024;         // per-page body cap
const DEFAULT_MAX_PAGES = 25;        // hard page-visit budget per run
const DEFAULT_MAX_DEPTH = 2;         // BFS depth from the entry page (0 = entry only)
const DEFAULT_MAX_VARIANTS = 3;      // query-string variants crawled per distinct path
const ASSET_RE = /\.(?:png|jpe?g|gif|svg|webp|avif|ico|css|m?js|map|woff2?|ttf|eot|pdf|zip|gz|tar|mp[34]|avi|mov|webm|json|xml|txt)(?:[?#]|$)/i;
const STATE_CHANGING_RE = /(?:^|\/)[\w-]*(?:log[\s_-]?out|sign[\s_-]?out|log[\s_-]?off|sign[\s_-]?off)/i;

// One raw GET, same-origin pre-checked by the caller. Resolves null on any error.
// `hdrs` overrides the default tool UA — the engagement's shared browser persona under stealth.
function raw(u, { timeout = 1500, cap = BODY_CAP, hdrs, agents } = {}) {
  return new Promise((resolve) => {
    const lib = u.protocol === 'https:' ? https : http;
    let text = '', settled = false;
    const done = (v) => { if (settled) return; settled = true; clearTimeout(deadline); resolve(v); };
    const req = lib.request({
      hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname + u.search, method: 'GET', timeout, rejectUnauthorized: false,
      agent: agents ? (u.protocol === 'https:' ? agents.httpsAgent : agents.httpAgent) : undefined,
      headers: hdrs || { 'user-agent': 'VARVEL-crawl', accept: 'text/html,application/xhtml+xml,*/*' },
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
    req.end();
  });
}

// Extract navigable links + forms from one HTML page. Links are resolved against
// `base` by the caller; here we return raw attribute values + parsed forms.
//   links:  raw href/action/src values (a, area, form action, iframe/frame)
//   forms:  [{ action, method, fields:[name...], hasPassword }]
export function parsePage(html) {
  const text = String(html || '');
  const links = [], forms = [];
  let m;
  const attr = (re) => { re.lastIndex = 0; while ((m = re.exec(text))) links.push(m[1]); };
  attr(/<a\s[^>]*?href\s*=\s*["']([^"']+)["']/gi);
  attr(/<area\s[^>]*?href\s*=\s*["']([^"']+)["']/gi);
  attr(/<(?:iframe|frame)\s[^>]*?src\s*=\s*["']([^"']+)["']/gi);

  const reForm = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
  while ((m = reForm.exec(text))) {
    const attrs = m[1], inner = m[2];
    const action = (/\baction\s*=\s*["']([^"']*)["']/i.exec(attrs) || [])[1] ?? '';
    const method = ((/\bmethod\s*=\s*["']([^"']*)["']/i.exec(attrs) || [])[1] || 'GET').toUpperCase();
    const fields = [];
    const reField = /<(?:input|select|textarea)\s[^>]*?name\s*=\s*["']([^"']+)["']/gi;
    let f; while ((f = reField.exec(inner))) fields.push(f[1]);
    const hasPassword = /<input\s[^>]*?type\s*=\s*["']password["']/i.test(inner);
    links.push(action);
    forms.push({ action, method, fields, hasPassword });
  }
  return { links, forms };
}

// Normalize a crawled URL for dedupe: path + SORTED query-param NAMES (values vary,
// the surface is the parameter set). Fragments never reach the wire.
export function signatureOf(u) {
  const keys = [...u.searchParams.keys()].sort();
  return u.pathname + (keys.length ? '?' + keys.join('&') : '');
}

// base: e.g. 'http://10.10.2.18:8080' — the crawler never leaves this origin.
export async function crawl(base, { timeout = 1500, maxPages = DEFAULT_MAX_PAGES, maxDepth = DEFAULT_MAX_DEPTH, maxVariants = DEFAULT_MAX_VARIANTS, stealth, pacer, agents = null, pathPrefixes = null } = {}) {
  let origin;
  try { const u = new URL(base); if (!/^https?:$/.test(u.protocol)) throw new Error('proto'); origin = u.origin; }
  catch { throw new TypeError('crawl: base must be an http(s) URL, got ' + JSON.stringify(base)); }

  pacer = asPacer(pacer) || (stealth ? makePacer(stealth) : null);
  // Path-prefix scope (fail-closed): seed at the prefix(es), never the root;
  // out-of-prefix links are refused-and-recorded, never fetched.
  const px = sanitizePathPrefixes(pathPrefixes);
  const confined = px && !px.includes('/');
  const scopeRefusals = [];
  const pageBudget = Math.max(1, Math.floor(maxPages) || DEFAULT_MAX_PAGES);
  const depthCap = Math.max(0, Math.floor(maxDepth));
  const variantCap = Math.max(1, Math.floor(maxVariants) || DEFAULT_MAX_VARIANTS);
  let used = 0;

  const seeds = confined ? px.map((p) => ({ path: p, depth: 0 })) : [{ path: '/', depth: 0 }];
  const queue = [...seeds];
  const seen = new Set(seeds.map((s) => s.path));  // signature-level dedupe
  const variants = new Map();                  // pathname -> query variants visited
  const techEvidence = [];                     // fetched pages, for zero-cost tech fingerprinting
  const pages = [];                            // visited { path, status, depth, linksOut }
  const epMap = new Map();                     // path -> { path, methods:Set, source }
  const prMap = new Map();                     // `${name}:${where}` -> { name, where, source }
  const forms = [];
  const findings = [];
  const add = (title, sev, path) => findings.push({ title, sev, path, ref: 'CRW-' + (findings.length + 1) });
  const addEndpoint = (path, method, source) => {
    if (!path) return;
    const e = epMap.get(path) || { path, methods: new Set(), source };
    if (method) e.methods.add(method);
    epMap.set(path, e);
  };
  const addParam = (name, where, source, path) => {
    if (!name) return;
    const key = name + ':' + where + ':' + (path || '');
    if (!prMap.has(key)) prMap.set(key, { name, where, source, ...(path ? { path } : {}) });
  };

  // Resolve a raw attribute value against a page URL. Returns a same-origin URL or null.
  const resolve = (rawVal, pageUrl) => {
    if (!rawVal || /^(mailto|javascript|data|tel|#)/i.test(rawVal.trim())) return null;
    let u;
    try { u = new URL(rawVal, pageUrl); } catch { return null; }
    if (u.origin !== origin) return null;      // a `//other-host` link can never escape scope
    u.hash = '';
    return u;
  };

  while (queue.length && pages.length < pageBudget) {
    const { path, depth } = queue.shift();
    const pageUrl = new URL(path, origin);
    if (pacer) await pacer.pace();
    used++;
    const r = await raw(pageUrl, { timeout, hdrs: pacer && pacer.requestHeaders ? pacer.requestHeaders({ accept: 'text/html,application/xhtml+xml,*/*' }) : undefined, agents });
    if (pacer && r && (r.status === 429 || r.status === 503)) pacer.penalize(2, 0); // adaptive back-off
    if (!r || r.status < 200 || r.status >= 400) continue;

    const ct = String(r.headers['content-type'] || '');
    if (ct && !/text\/html|application\/xhtml/i.test(ct)) continue;  // linked PDF/XML etc: not crawled
    if (!/<[a-z!]/i.test(r.body)) continue;                          // not HTML (e.g. a JSON endpoint)

    const { links, forms: pageForms } = parsePage(r.body);
    let linksOut = 0;
    techEvidence.push({ headers: r.headers, body: r.body.slice(0, 65536) }); // tech fingerprint rides the crawl — zero extra requests

    for (const f of pageForms) {
      const actionUrl = resolve(f.action || path, pageUrl) || pageUrl;
      addEndpoint(actionUrl.pathname, f.method, 'crawl-form');
      for (const name of f.fields) addParam(name, 'form', 'crawl-form:' + actionUrl.pathname, actionUrl.pathname);
      for (const [k] of actionUrl.searchParams) addParam(k, 'query', 'crawl-form:' + actionUrl.pathname, actionUrl.pathname);
      forms.push({ page: pageUrl.pathname, action: actionUrl.pathname, method: f.method, fields: f.fields });
      // Honest, volunteer-based finding: the app itself serves a password form over cleartext HTTP.
      if (f.hasPassword && pageUrl.protocol === 'http:') add(`Password form served over cleartext HTTP (credentials exposed in transit)`, 'medium', actionUrl.pathname);
    }

    // SPA shell harvest (Build 2): the shell page's inline JS holds the real API
    // calls — fetch('/api/search?q=' + x) etc. A light regex pass (apisurface's
    // extractor, zero extra requests) lands those endpoints + query params on the
    // surface so the OOB / DOM-XSS lanes have parameterized targets.
    {
      const jsEps = [], jsPrms = [];
      extractJsEndpoints(r.body, pageUrl.href, jsEps, jsPrms, 'crawl-inline-js');
      for (const e of jsEps) addEndpoint(e.path, 'GET', e.source);
      for (const prm of jsPrms) addParam(prm.name, prm.where, prm.source, prm.path);
    }

    for (const rawLink of links) {
      const u = resolve(rawLink, pageUrl);
      if (!u) continue;
      if (confined && !pathPrefixAllowed(u.pathname, px)) {
        // out-of-prefix: recorded as an honest refusal, never enqueued, never fetched
        if (!scopeRefusals.includes(u.pathname)) scopeRefusals.push(u.pathname);
        continue;
      }
      addEndpoint(u.pathname, 'GET', 'crawl');
      for (const [k] of u.searchParams) addParam(k, 'query', 'crawl', u.pathname);
      if (depth >= depthCap) continue;                          // record-only beyond the depth cap
      if (ASSET_RE.test(u.pathname)) continue;                  // static assets: not navigable pages
      if (STATE_CHANGING_RE.test(u.pathname)) continue;         // never touch logout/sign-out flows
      const sig = signatureOf(u);
      if (seen.has(sig)) continue;
      // Facet/calendar collapse guard: cap query VARIANTS per path, so ?page=1..N and
      // ?sort=asc/desc don't burn the whole page budget on one endpoint.
      const seenForPath = variants.get(u.pathname) || 0;
      if (u.search && seenForPath >= variantCap) continue;
      seen.add(sig);
      if (u.search) variants.set(u.pathname, seenForPath + 1);
      linksOut++;
      queue.push({ path: u.pathname + u.search, depth: depth + 1 });
    }
    pages.push({ path, status: r.status, depth, linksOut });
  }

  const endpoints = [...epMap.values()]
    .map((e) => ({ path: e.path, methods: [...e.methods], source: e.source }))
    .sort((a, b) => a.path.localeCompare(b.path));
  const params = [...prMap.values()].sort((a, b) => a.name.localeCompare(b.name));
  return {
    base: origin,
    pages,
    endpoints,
    params,
    forms,
    findings,
    tech: fingerprintPages(techEvidence), // aggregated, evidence-carrying, zero extra requests
    requests: used,
    depth: depthCap,
    scopeRefusals,
    stealth: pacer ? pacer.profile.label : null,
  };
}
