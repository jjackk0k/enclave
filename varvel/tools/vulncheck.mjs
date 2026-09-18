// VARVEL — native vulnerability-check template engine (authorized engagements).
//
// The Nuclei slot, built native per Jack's directive. RedAmon shells out to Nuclei with
// 9,000+ YAML templates and lets the volume speak; VARVEL ships a CURATED set of
// high-signal checks where every finding is CONTENT-VERIFIED before it is reported —
// no status-code-only guesses, no "might be vulnerable", nothing the target didn't
// actually volunteer. A VARVEL finding is confirmed by construction.
//
// Three check families, all non-destructive (GET only, no state change, no injection):
//   1. PROBES       — known-exposure paths (/.git, /.env, actuator, phpinfo…) matched on
//                     status AND a content regex. ~16 requests, not a wordlist brute-force.
//   2. PAGE AUDIT   — security headers, cookie flags, version disclosure, and body leak
//                     patterns (stack traces / SQL errors / directory listings) evaluated
//                     on pages already fetched (root + a few crawl-discovered paths).
//   3. CORS PROBE   — one request with a probe Origin; reports only a reflected origin
//                     with credentials (a real misconfig), never the mere presence of CORS.
//
// Stealth-aware like every native tool: pass the engagement's shared `pacer` (preferred)
// or a `stealth` profile; every request is paced and the persona headers are sent.

import http from 'node:http';
import https from 'node:https';
import { makePacer, asPacer } from '../engine/stealth.mjs';
import { pathPrefixAllowed, sanitizePathPrefixes } from '../engine/scopepath.mjs';
import { cveCheck } from '../engine/cvepacks.mjs';
import { makeBaseline, matchesBaseline } from '../engine/soft404.mjs';

const BODY_CAP = 192 * 1024;
const DEFAULT_MAX_PROBES = 20;      // hard request budget (root + CORS + exposure probes)
const MAX_PAGE_PATHS = 5;           // discovered pages to audit for body leaks

// ——— Exposure probes: path + status + CONTENT match → confirmed finding ———
// Every entry was chosen because its content signature is unambiguous: if `match`
// hits, the exposure is real. Keep this list small and high-signal on purpose.
export const PROBES = [
  { id: 'git-head',       path: '/.git/HEAD',           sev: 'high',   match: /ref:\s*refs\//,                          title: 'Exposed .git repository — HEAD readable, source tree recoverable' },
  { id: 'git-config',     path: '/.git/config',         sev: 'high',   match: /\[core\][\s\S]*repositoryformatversion/, title: 'Exposed .git config — repository metadata + remotes readable' },
  { id: 'env-file',       path: '/.env',                sev: 'high',   match: /^\s*(?:[A-Z_][A-Z0-9_]*|export\s+[A-Z_][A-Z0-9_]*)\s*=\s*\S/m, notMatch: /^\s*</, title: 'Exposed .env file — likely credentials and secrets' },
  { id: 'svn-entries',    path: '/.svn/entries',        sev: 'medium', match: /^(?:\d+\n)?dir\b|svn:/,                  title: 'Exposed .svn metadata — working-copy structure readable' },
  { id: 'ds-store',       path: '/.DS_Store',           sev: 'low',    match: /^Bud1|^Bud2/,                            title: 'Exposed .DS_Store — directory filenames leak' },
  { id: 'server-status',  path: '/server-status',       sev: 'medium', match: /Apache Server Status|Scoreboard/i,       title: 'Apache server-status exposed — internal metrics, vhosts, client IPs' },
  { id: 'server-info',    path: '/server-info',         sev: 'medium', match: /Apache Server Information/i,             title: 'Apache server-info exposed — module and config disclosure' },
  { id: 'actuator',       path: '/actuator',            sev: 'medium', match: /"(_links|beans|health|metrics)"/,        title: 'Spring Boot Actuator endpoints exposed unauthenticated' },
  { id: 'actuator-env',   path: '/actuator/env',        sev: 'high',   match: /"(propertySources|systemProperties|systemEnvironment)"/, title: 'Spring Actuator /env exposed — configuration and possible secrets' },
  { id: 'actuator-heapdump', path: '/actuator/heapdump', sev: 'high',  match: /^JAVA PROFILE/,                          title: 'Spring Actuator heapdump exposed — full memory contents (credentials) downloadable' },
  { id: 'phpinfo',        path: '/phpinfo.php',         sev: 'medium', match: /<title>phpinfo\(\)<\/title>|PHP Version/i, title: 'phpinfo() exposed — full environment, paths, and module disclosure' },
  { id: 'elmah',          path: '/elmah.axd',           sev: 'medium', match: /Error Log for|ELMAH/i,                   title: 'ELMAH error log exposed — .NET exception details readable' },
  { id: 'debug-vars',     path: '/debug/vars',          sev: 'low',    match: /"(cmdline|memstats)"/,                   title: 'Go expvar /debug/vars exposed — runtime internals readable' },
  { id: 'wp-user-enum',   path: '/wp-json/wp/v2/users', sev: 'medium', match: /\[\s*\{[^]*?"(slug|name)"\s*:/,          title: 'WordPress user enumeration via unauthenticated REST API' },
  { id: 'phpmyadmin',     path: '/phpmyadmin/',         sev: 'medium', match: /phpMyAdmin/i,                            title: 'phpMyAdmin console reachable — database admin surface exposed' },
  { id: 'tomcat-manager', path: '/manager/html',        sev: 'medium', statusIn: [200, 401], match: /Tomcat|Manager App/i, title: 'Tomcat Manager console reachable' },
];

// ——— Body-leak patterns: applied to pages we fetch ———
export const BODY_LEAKS = [
  { id: 'stack-java',  sev: 'low',    match: /\bat [\w.$]+\([\w$]+\.java:\d+\)/,                 title: 'Java stack trace leaked in response body' },
  { id: 'stack-python',sev: 'low',    match: /Traceback \(most recent call last\)/,              title: 'Python traceback leaked in response body' },
  { id: 'stack-php',   sev: 'low',    match: /(?:Fatal|Warning|Notice)[^\n]{0,120}\bon line \d+/i, title: 'PHP error with file path leaked in response body' },
  { id: 'stack-dotnet',sev: 'low',    match: /\[(?:NullReference|InvalidOperation|Argument)Exception|Server Error in '\S+' Application/, title: '.NET exception page leaked' },
  { id: 'sql-mysql',   sev: 'medium', match: /SQL syntax[^\n]{0,80}MySQL|You have an error in your SQL syntax/i, title: 'MySQL error message leaked — SQL injection surface indicated' },
  { id: 'sql-oracle',  sev: 'medium', match: /\bORA-\d{4,5}\b/,                                  title: 'Oracle database error leaked — SQL injection surface indicated' },
  { id: 'sql-pgsql',   sev: 'medium', match: /PostgreSQL[^\n]{0,60}ERROR|pg_query\(\)/i,          title: 'PostgreSQL error leaked — SQL injection surface indicated' },
  { id: 'dir-listing', sev: 'medium', match: /<title>Index of \//i,                              title: 'Directory listing enabled — contents browsable' },
];

// ——— Security headers audited on the root response ———
export const HEADER_CHECKS = [
  { id: 'hdr-csp',  header: 'content-security-policy',  sev: 'low', title: 'Missing Content-Security-Policy header' },
  { id: 'hdr-xfo',  header: 'x-frame-options',          sev: 'low', title: 'Missing clickjacking protection (X-Frame-Options / frame-ancestors)' },
  { id: 'hdr-xcto', header: 'x-content-type-options',   sev: 'info', title: 'Missing X-Content-Type-Options: nosniff' },
  { id: 'hdr-refp', header: 'referrer-policy',          sev: 'info', title: 'Missing Referrer-Policy header' },
];

const CORS_ORIGIN = 'https://varvel-probe.invalid';

// One raw GET, same-origin pre-checked by the caller. Resolves null on any error.
function raw(u, { timeout = 1500, cap = BODY_CAP, hdrs, origin, agents } = {}) {
  return new Promise((resolve) => {
    const lib = u.protocol === 'https:' ? https : http;
    let text = '', settled = false;
    const done = (v) => { if (settled) return; settled = true; clearTimeout(deadline); resolve(v); };
    const headers = { ...(hdrs || { 'user-agent': 'VARVEL-vulncheck', accept: '*/*' }) };
    if (origin) headers.origin = origin;
    const req = lib.request({
      hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname + u.search, method: 'GET', timeout, rejectUnauthorized: false,
      agent: agents ? (u.protocol === 'https:' ? agents.httpsAgent : agents.httpAgent) : undefined, headers,
    }, (r) => {
      r.on('data', (d) => {
        if (settled) return;
        if (text.length < cap) text += d.toString('latin1', 0, Math.max(0, cap - text.length));
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

const snippet = (body, re) => {
  const m = re.exec(body);
  if (!m) return '';
  return m[0].replace(/\s+/g, ' ').slice(0, 90);
};

// base: http(s) URL. pagePaths: already-discovered paths (from crawl/webscan) to audit for
// body leaks — reuses recon the engagement already paid for instead of guessing new paths.
export async function vulnCheck(base, { timeout = 1500, maxProbes = DEFAULT_MAX_PROBES, pagePaths = [], tech = [], stealth, pacer, agents = null, pathPrefixes = null } = {}) {
  let origin;
  try { const u = new URL(base); if (!/^https?:$/.test(u.protocol)) throw new Error('proto'); origin = u.origin; }
  catch { throw new TypeError('vulnCheck: base must be an http(s) URL, got ' + JSON.stringify(base)); }

  pacer = asPacer(pacer) || (stealth ? makePacer(stealth) : null);
  // Baseline junk probes ride on top of the probe budget (counted honestly in
  // `requests`) so a tight maxProbes can't be silently eaten by the fingerprint pass.
  const budget = Math.max(3, Math.floor(maxProbes) || DEFAULT_MAX_PROBES) + 3;
  let used = 0;
  // Path-prefix scope (fail-closed): root-level audits ('/') and exposure probes
  // outside the prefix are refused BEFORE the wire and recorded honestly.
  const px = sanitizePathPrefixes(pathPrefixes);
  const scopeRefusals = [];
  const vulns = [];
  const add = (id, title, sev, path, evidence) =>
    vulns.push({ id, title, sev, path, evidence, confidence: 'confirmed', ref: 'VC-' + (vulns.length + 1) });

  async function request(path, { origin: probeOrigin } = {}) {
    if (used >= budget) return null;
    let u;
    try { u = new URL(path, origin); } catch { return null; }
    if (u.origin !== origin) return null; // same-origin, always
    if (!pathPrefixAllowed(u.pathname, px)) {
      if (!scopeRefusals.includes(u.pathname)) scopeRefusals.push(u.pathname);
      return null; // path-scope refusal — never sent
    }
    used++;
    if (pacer) await pacer.pace();
    const r = await raw(u, { timeout, hdrs: pacer && pacer.requestHeaders ? pacer.requestHeaders({ accept: '*/*' }) : undefined, origin: probeOrigin, agents });
    if (pacer && r && (r.status === 429 || r.status === 503)) pacer.penalize(2, 0);
    return r;
  }

  const ok = (r) => r && r.status >= 200 && r.status < 300;
  const audited = { headers: 0, cookies: 0, bodyPages: 0 };

  // 1) Root page: header audit + cookie flags + version disclosure + body leaks.
  const root = await request('/');
  if (ok(root)) {
    const h = root.headers;
    const isHttps = new URL(origin).protocol === 'https:';
    if (isHttps && !h['strict-transport-security']) add('hdr-hsts', 'Missing HSTS header on HTTPS service', 'low', '/', 'no strict-transport-security header');
    for (const c of HEADER_CHECKS) {
      // XFO is also satisfied by a CSP frame-ancestors directive — don't double-report.
      if (c.id === 'hdr-xfo' && h['content-security-policy'] && /frame-ancestors/i.test(h['content-security-policy'])) continue;
      if (!h[c.header]) { audited.headers++; add(c.id, c.title, c.sev, '/', 'response headers lack ' + c.header); }
    }
    const cookies = ([]).concat(h['set-cookie'] || []);
    for (const c of cookies) {
      const name = (c.split('=')[0] || '').trim() || '(unnamed)';
      const flags = [];
      if (!/httponly/i.test(c)) flags.push('HttpOnly');
      if (isHttps && !/\bsecure\b/i.test(c)) flags.push('Secure');
      if (!/samesite/i.test(c)) flags.push('SameSite');
      if (flags.length) { audited.cookies++; add('cookie-flags', `Cookie "${name}" set without ${flags.join(', ')}`, 'low', '/', 'set-cookie: ' + c.slice(0, 60)); }
    }
    const server = String(h['server'] || ''), powered = String(h['x-powered-by'] || '');
    if (server || powered) add('version-disclosure', `Version disclosure: ${[server, powered].filter(Boolean).join(' · ')}`, 'info', '/', 'advertised in response headers');
    if (/(?:Apache\/1\.|nginx\/0\.|Microsoft-IIS\/[1-6]\.|PHP\/[45]\.|OpenSSL\/1\.0)/i.test(server + ' ' + powered)) {
      add('version-outdated', `End-of-life component advertised (${[server, powered].filter(Boolean).join(' · ')}) — check for known CVEs`, 'medium', '/', 'version string in response headers');
    }
    audited.bodyPages++;
    for (const p of BODY_LEAKS) if (p.match.test(root.body)) add(p.id, p.title, p.sev, '/', 'matched: ' + snippet(root.body, p.match));
  }

  // 2) CORS: one probe Origin. Only a REFLECTED origin with credentials is a real finding;
  //    a bare wildcard without credentials is informational.
  const cors = await request('/', { origin: CORS_ORIGIN });
  if (cors) {
    const acao = String(cors.headers['access-control-allow-origin'] || '');
    const acac = String(cors.headers['access-control-allow-credentials'] || '') === 'true';
    if (acao && acao === CORS_ORIGIN && acac) add('cors-reflect-cred', 'CORS reflects an arbitrary Origin WITH credentials — cross-origin data theft possible', 'medium', '/', 'ACAO: ' + acao + ' + ACAC: true');
    else if (acao === '*') add('cors-wildcard', 'CORS wildcard (*) — any origin may read responses (no credentials)', 'info', '/', 'ACAO: *');
  }

  // 3) Exposure probes — status AND content match, so a reported item is confirmed.
  // Soft-404 baselining FIRST (engine/soft404.mjs): 3 random garbage paths fingerprint
  // the SPA fallback (status + length bucket + body simhash). Any probe response
  // matching the baseline is the fallback, NOT a finding — recorded in the soft404
  // ledger as an honest soft404.match, never silently dropped.
  const stem = (px && !px.includes('/')) ? px[0] : '/'; // baseline junk stays inside the same path-prefix scope as the probes
  const junk = () => stem + 'varvel-' + Math.random().toString(36).slice(2, 10) + '-' + Math.random().toString(36).slice(2, 10);
  const bl = makeBaseline([await request(junk()), await request(junk()), await request(junk())].filter(Boolean));
  const soft404Matches = [];
  for (const p of PROBES) {
    if (used >= budget) break;
    const r = await request(p.path);
    if (!r) continue;
    const statusOk = p.statusIn ? p.statusIn.includes(r.status) : ok(r);
    if (!statusOk) continue;
    if (matchesBaseline(r, bl)) { soft404Matches.push({ path: p.path, id: p.id, status: r.status, reason: 'soft404.match' }); continue; }
    if (p.notMatch && p.notMatch.test(r.body)) continue;
    if (p.match && !p.match.test(r.body)) continue;
    add(p.id, p.title, p.sev, p.path, p.match ? 'matched: ' + snippet(r.body, p.match) : 'HTTP ' + r.status);
  }

  // 4) Body-leak audit on already-discovered pages (stack traces behind params/404s).
  for (const pth of [...new Set(pagePaths)].slice(0, MAX_PAGE_PATHS)) {
    if (used >= budget) break;
    if (!pth || pth === '/') continue;
    const r = await request(pth);
    if (!r) continue;
    audited.bodyPages++;
    for (const p of BODY_LEAKS) if (p.match.test(r.body)) add(p.id, p.title, p.sev, pth, 'matched: ' + snippet(r.body, p.match));
  }

  // 5) Version→CVE correlation: wappalyze's fingerprinted stack drives curated packs —
  //    fires ONLY on an actual version match, confidence 'firm' (verify exploitability).
  //    Zero requests — pure correlation over recon the engagement already paid for.
  for (const c of cveCheck(tech)) {
    vulns.push({
      id: c.id, title: c.title, sev: c.sev, path: '/',
      evidence: c.evidence + (c.kev ? ' [KEV — actively exploited in the wild]' : ''),
      confidence: c.confidence, ref: 'VC-' + (vulns.length + 1),
    });
  }

  for (const v of vulns) v.soft404Baselined = bl.soft === true; // survivors may say so on the report's Validation line
  return {
    base: origin,
    vulnerabilities: vulns.sort((a, b) => sevRank(b.sev) - sevRank(a.sev) || a.path.localeCompare(b.path)),
    audited,
    probes: PROBES.length,
    requests: used,
    scopeRefusals,
    soft404: { baselined: bl.soft === true, probes: bl.probes || 0, matched: soft404Matches },
    stealth: pacer ? pacer.profile.label : null,
  };
}

const SEV_ORDER = ['info', 'low', 'medium', 'high', 'critical'];
function sevRank(s) { const i = SEV_ORDER.indexOf(String(s)); return i < 0 ? 0 : i; }
