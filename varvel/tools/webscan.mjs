// VARVEL — web content discovery + sensitive-exposure tool (authorized engagements).
//
// Lenient like RedAmon's ffuf/katana: it probes the paths it is given against the
// target it is pointed at (the ENCLAVE governs scope/egress). GET-only, rate-limited.
//
// Correctness hardening (audited): soft-404 baseline + per-signature CONTENT
// validation (no more crit findings on catch-all-200 apps), 2xx-only artifact
// flagging (3xx redirects are discovery, not exposures), same-origin enforcement
// (a `//other-host` path can never escape the target), segment-anchored signatures
// (no `.env`-inside-`.envelope` false positives), broadened classifiers
// (.git/.hg/.aws/actuator/wp-config/*.sql), 405 discovery, and a hard body cap +
// overall request deadline.
//
// Boundary: discovery + detection only. No exploitation, no credential brute force.

import http from 'node:http';
import https from 'node:https';
import { makePacer, asPacer } from '../engine/stealth.mjs';
import { confinePaths, sanitizePathPrefixes } from '../engine/scopepath.mjs';
import { makeBaseline, matchesBaseline } from '../engine/soft404.mjs';

export const DEFAULT_PATHS = [
  '/', '/robots.txt', '/sitemap.xml', '/.well-known/security.txt',
  '/admin', '/administrator', '/login', '/dashboard', '/console', '/manager',
  '/api', '/api/v1', '/api/users', '/graphql', '/swagger', '/swagger-ui', '/openapi.json',
  '/.git/HEAD', '/.git/config', '/.git/index', '/.git/logs/HEAD', '/.git/',
  '/.svn/entries', '/.hg/store/00manifest.i', '/.env', '/.env.local', '/.env.production',
  '/.aws/credentials', '/.aws/config', '/config.php', '/config.json', '/wp-config.php', '/wp-config.php.bak',
  '/web.config', '/.htaccess', '/.DS_Store',
  '/backup', '/backup.zip', '/backup.tar.gz', '/backup.sql', '/db.sql', '/dump.sql', '/database.sql',
  '/phpinfo.php', '/info.php', '/server-status', '/server-info',
  '/actuator', '/actuator/', '/actuator/health', '/actuator/env', '/actuator/heapdump', '/actuator/threaddump', '/actuator/configprops', '/actuator/mappings',
  '/metrics', '/debug', '/status', '/health',
  '/wp-admin', '/wp-login.php', '/crossdomain.xml',
];

// Signatures are anchored to the final path SEGMENT and (where useful) validated
// against the response body so a soft-404 page can't be mistaken for the artifact.
// Every class carries a content signal: the soft-404 baseline (engine/soft404.mjs) is
// the first gate, the `valid` body check is the second — a 200 HTML shell fails both.
const looksListing = (b) => /index of|directory listing/i.test(b || '');
const looksBinary = (b) => /[\x00-\x08\x0e-\x1f]/.test(String(b || '').slice(0, 256)); // control bytes = not an HTML shell
const looksHtml = (b) => /^\s*</.test(String(b || ''));
const SENSITIVE = [
  { re: /(^|\/)\.git(\/|$)/, sev: 'high', title: 'exposed .git repository', valid: (b) => /^(ref: |[0-9a-f]{40}|\[core\]|PACK)/m.test(b) || looksListing(b) },
  { re: /(^|\/)\.hg(\/|$)/, sev: 'high', title: 'exposed Mercurial metadata', valid: (b) => looksBinary(b) || /[0-9a-f]{40}/.test(b) || looksListing(b) },
  { re: /(^|\/)\.svn(\/|$)/, sev: 'high', title: 'exposed SVN metadata', valid: (b) => /(^|\n)\s*\d{1,2}\s*\n\s*dir\s*\n|svn:|wcprops|entries/i.test(b) && !looksHtml(b) || looksListing(b) },
  { re: /(^|\/)\.aws(\/|$)/, sev: 'crit', title: 'exposed AWS credentials/config', valid: (b) => /\[(default|profile )|aws_access_key_id|aws_secret/i.test(b) || looksListing(b) },
  { re: /(^|\/)\.env(\.[\w.-]+)?$/, sev: 'crit', title: 'exposed environment/secrets file', valid: (b) => /^\s*[A-Z0-9_]+\s*=/m.test(b) },
  { re: /(^|\/)wp-config\.php(\.\w+|~)?$/, sev: 'crit', title: 'exposed WordPress config (DB credentials)', valid: (b) => /<\?php/i.test(b) || /define\s*\(\s*['"]DB_/i.test(b) },
  { re: /(^|\/)(db|dump|database|data|mysql|users|backup)\.sql$/, sev: 'high', title: 'exposed database dump', valid: (b) => /CREATE\s+(TABLE|DATABASE)|INSERT\s+INTO|DROP\s+TABLE|mysqldump|pg_dump/i.test(b) },
  { re: /(^|\/)(backup|db|dump|database)(\d[\w.-]*)?\.(zip|tar\.gz|tgz|bak)$/, sev: 'high', title: 'exposed backup archive', valid: (b) => b.startsWith('PK\x03\x04') || (b.charCodeAt(0) === 0x1f && b.charCodeAt(1) === 0x8b) || b.startsWith('Rar!') || looksListing(b) },
  { re: /(^|\/)backup(\/)?$/, sev: 'high', title: 'exposed backup archive', valid: (b) => looksListing(b) },
  { re: /actuator\/(heapdump|threaddump)(\/|$)/, sev: 'high', title: 'Spring Actuator sensitive endpoint', valid: (b) => /^JAVA PROFILE/.test(b) || (looksBinary(b) && !looksHtml(b)) },
  { re: /actuator\/(env|configprops|mappings|loggers|httptrace|beans)(\/|$)/, sev: 'high', title: 'Spring Actuator sensitive endpoint', valid: (b) => /"(propertySources|systemProperties|systemEnvironment|contexts|beans|mappings|loggers|trace)"\s*:/.test(b) && !looksHtml(b) },
  { re: /actuator(\/|$)/, sev: 'med', title: 'Spring Actuator exposed', valid: (b) => /"(_links|health|metrics|info)"\s*:/.test(b) && !looksHtml(b) },
  { re: /(^|\/)(phpinfo|info)\.php$/, sev: 'med', title: 'phpinfo() exposed', valid: (b) => /phpinfo\(\)|PHP Version/i.test(b) },
  { re: /(^|\/)(server-status|server-info)$/, sev: 'med', title: 'server status/info exposed', valid: (b) => /Apache Server Status|Scoreboard|Apache Server Information/i.test(b) },
  { re: /(^|\/)metrics$/, sev: 'med', title: 'debug/metrics endpoint exposed', valid: (b) => /^#\s*(HELP|TYPE)\s+\S+/m.test(b) || /"(counters|gauges|meters)"\s*:/.test(b) && !looksHtml(b) },
  { re: /(^|\/)debug$/, sev: 'med', title: 'debug/metrics endpoint exposed', valid: (b) => /"(cmdline|memstats|goroutine)"\s*:/.test(b) || looksListing(b) },
  { re: /(^|\/)\.DS_Store$/, sev: 'low', title: 'config artifact exposed', valid: (b) => /^Bud1|^Bud2/.test(b) },
  { re: /(^|\/)web\.config$/, sev: 'low', title: 'config artifact exposed', valid: (b) => /^\s*(<\?xml|<configuration)/i.test(b) },
  { re: /(^|\/)\.htaccess$/, sev: 'low', title: 'config artifact exposed', valid: (b) => /(RewriteEngine|RewriteRule|Require all|Order allow|Deny from|AddType|Options )/i.test(b) && !looksHtml(b) },
  { re: /(^|\/)config\.php$/, sev: 'low', title: 'config file exposed', valid: (b) => /<\?php/i.test(b) },
  { re: /(^|\/)config\.json$/, sev: 'low', title: 'config file exposed', valid: (b) => /^\s*\{[\s\S]*"\w+"\s*:/.test(b) && !looksHtml(b) },
];

function classifyPath(path, body) {
  const seg = path.split('?')[0];
  if (/actuator\/health(\/|$)?$/i.test(seg)) return null; // health probe is benign, not an exposure
  for (const s of SENSITIVE) {
    if (!s.re.test(seg)) continue;
    if (s.valid && body != null && body !== '' && !s.valid(body)) continue; // content didn't match the artifact
    return s;
  }
  return null;
}

function isDirListing(body) {
  if (!body) return false;
  if (/<h1>\s*Index of\s/i.test(body)) return true;                                  // Apache autoindex
  if (/Directory listing for/i.test(body) && /<a href=/i.test(body)) return true;    // Python http.server
  if (/\[To Parent Directory\]/i.test(body)) return true;                            // IIS
  if (/<title>\s*Index of[^<]*<\/title>/i.test(body) && /<a href="\.\.?\/?"/i.test(body)) return true;
  return false;
}

// A worker pool. When `pacer` is given (stealth mode), each worker awaits the pacer's
// jittered delay before firing its next request — enforcing low-and-slow pacing in code
// rather than trusting the caller to be quiet. `stop` (optional predicate) halts ALL
// workers early — the dead-host breaker uses it so a silent-drop host stops absorbing
// full-deadline waits instead of being polled to the end of the path list.
async function pool(items, size, fn, pacer, stop) {
  const out = []; let i = 0;
  const n = Math.max(1, Math.min(Math.floor(size) || 1, items.length || 1));
  await Promise.all(Array.from({ length: n }, async () => {
    while (i < items.length && !(stop && stop())) { const idx = i++; if (pacer) await pacer.pace(); try { out[idx] = await fn(items[idx]); } catch { out[idx] = null; } }
  }));
  return out;
}

const CAP = 4096;
function get(base, path, timeout, hdrs, agents) {
  return new Promise((resolve) => {
    let u, baseOrigin;
    try { baseOrigin = new URL(base).origin; u = new URL(path, base); } catch { return resolve(null); }
    if (u.origin !== baseOrigin) return resolve(null); // same-origin only — a `//other-host` path can't escape scope
    const lib = u.protocol === 'https:' ? https : http;
    let body = '', settled = false;
    const done = (v) => { if (settled) return; settled = true; clearTimeout(deadline); resolve(v); };
    const req = lib.request({ hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80), path: u.pathname + u.search, method: 'GET', timeout, rejectUnauthorized: false, agent: agents ? (u.protocol === 'https:' ? agents.httpsAgent : agents.httpAgent) : undefined, headers: hdrs || { 'user-agent': 'VARVEL-webscan' } }, (r) => {
      r.on('data', (d) => {
        if (settled) return;
        if (body.length < CAP) body += d.toString('latin1', 0, Math.max(0, CAP - body.length));
        if (body.length >= CAP) { done({ path, status: r.statusCode, len: body.length, server: r.headers['server'], body }); try { req.destroy(); } catch {} }
      });
      r.on('end', () => done({ path, status: r.statusCode, len: Number(r.headers['content-length']) || body.length, server: r.headers['server'], body }));
    });
    const deadline = setTimeout(() => { try { req.destroy(); } catch {} done(null); }, Math.max(timeout * 3, 3000)); // overall deadline (slowloris guard)
    req.on('timeout', () => { try { req.destroy(); } catch {} done(null); });
    req.on('error', () => done(null));
    req.end();
  });
}

// Establish a soft-404 baseline by probing paths that should not exist. Routed through the
// pacer too — these random-path 404s are the canonical web-scan tell, so under stealth they
// must be spaced + counted like every other request, not fired as an un-paced burst at t0.
// The fingerprint (engine/soft404.mjs) is status + length bucket + a 64-bit simhash of the
// normalized body — an SPA fallback is caught even when its byte length drifts per path.
async function baseline(base, timeout, pacer, agents, pathPrefixes) {
  // Under a path-prefix scope the junk probes must stay IN scope too — a random
  // root path would itself be a scope violation. Probe junk UNDER the first
  // prefix instead; the soft-404 lesson is preserved inside the allowed tree.
  const px = sanitizePathPrefixes(pathPrefixes);
  const stem = (px && !px.includes('/')) ? px[0] : '/';
  const rnd = () => stem + 'varvel-' + Math.random().toString(36).slice(2, 10) + '-' + Math.random().toString(36).slice(2, 10);
  const probe = async (p) => { if (pacer) await pacer.pace(); return get(base, p, timeout, pacer && pacer.requestHeaders ? pacer.requestHeaders() : undefined, agents); };
  const rs = (await Promise.all([probe(rnd()), probe(rnd()), probe(rnd() + '.nonexistent')])).filter(Boolean);
  return makeBaseline(rs);
}

// base: e.g. 'http://10.10.2.18' or 'https://host:8443'
// `stealth`/`pacer`: optional operational-stealth. `pacer` (a shared injected pacer) wins
// over `stealth` (a profile) so one emission clock can govern a whole engagement. When set,
// concurrency + jittered spacing are ENFORCED for every request incl. the baseline, and the
// pacer backs off adaptively if the target throttles (429/503) — see engine/stealth.mjs.
export async function webScan(base, { paths = DEFAULT_PATHS, concurrency = 8, timeout = 1200, stealth, pacer, agents = null, deadAfter = 8, pathPrefixes = null } = {}) {
  let origin;
  try { const u = new URL(base); if (!/^https?:$/.test(u.protocol)) throw new Error('proto'); origin = u.origin; }
  catch { throw new TypeError('webScan: base must be an http(s) URL, got ' + JSON.stringify(base)); }

  pacer = asPacer(pacer) || (stealth ? makePacer(stealth) : null);
  const conc = pacer ? pacer.concurrency : concurrency; // stealth profile owns concurrency when active
  // Path-prefix scope (fail-closed): out-of-prefix probe paths are refused BEFORE
  // the wire and reported honestly, never sent.
  const confined = confinePaths(paths, pathPrefixes);
  const scopeRefusals = confined.refused.map((p) => String(p).split('?')[0] || '/');
  const bl = await baseline(base, timeout, pacer, agents, pathPrefixes);
  // Dead-host breaker (2026-08-30, the bykea/tripcom wedge class): against a host that
  // accepts-then-blackholes (Akamai-style silent drop), EVERY request burns its full
  // socket deadline and the tool sits out its whole watchdog budget doing nothing. After
  // `deadAfter` consecutive total misses (null = timeout/refused/wedged), stop probing:
  // the remaining requests would have timed out anyway, so the wire profile only LOSES
  // packets that could never have been answered. Reported honestly via deadHostStop.
  // Kill: deadAfter: 0. The baseline's own two probes count toward the streak.
  let misses = bl.status == null ? 2 : 0;
  let deadHostStop = false;
  const results = await pool(confined.allowed, conc, async (p) => {
    const r = await get(base, p, timeout, pacer && pacer.requestHeaders ? pacer.requestHeaders() : undefined, agents);
    // Adaptive back-off: if the target pushes back, widen the gap (quieter, not evasive).
    if (pacer && r && (r.status === 429 || r.status === 503)) pacer.penalize(2, 0);
    if (deadAfter > 0) { misses = r ? 0 : misses + 1; if (misses >= deadAfter) deadHostStop = true; }
    return r;
  }, pacer, () => deadHostStop);
  const endpoints = [];
  const findings = [];
  const soft404Matches = []; // honest debunk ledger: baseline-matched responses that a status-only check would have filed
  const add = (title, sev, path) => findings.push({ title, sev, path, ref: 'WEB-' + (findings.length + 1) });

  for (const r of results) {
    if (!r || r.status == null) continue;
    if (matchesBaseline(r, bl)) {
      // Soft-404 SPA fallback: NOT a finding. Debunked visibly (soft404.match), never silently dropped.
      const sens = classifyPath(r.path, r.body);
      if (sens) soft404Matches.push({ path: r.path, title: sens.title, status: r.status, reason: 'soft404.match' });
      else if (r.status >= 200 && r.status < 300) soft404Matches.push({ path: r.path, title: 'catch-all 200 (SPA fallback)', status: r.status, reason: 'soft404.match' });
      continue;
    }
    const exists = (r.status >= 200 && r.status < 400) || [401, 403, 405].includes(r.status);
    if (!exists) continue;
    endpoints.push({ path: r.path, status: r.status });

    // Only a genuine 2xx artifact is an exposure; 3xx/401/403 are discovery, not findings.
    if (r.status >= 200 && r.status < 300) {
      const sens = classifyPath(r.path, r.body);
      if (sens) { add(sens.title, sens.sev, r.path); continue; }
      if (isDirListing(r.body)) add('directory listing enabled', 'med', r.path);
    }
  }
  for (const f of findings) f.soft404Baselined = bl.soft === true; // survivors may say so on the report's Validation line
  return { base: origin, endpoints, findings, scanned: confined.allowed.length, scopeRefusals, deadHostStop, softHost: bl.soft, soft404: { baselined: bl.soft === true, probes: bl.probes || 0, matched: soft404Matches }, stealth: pacer ? pacer.profile.label : null, backedOff: pacer ? pacer.currentDelay() > (pacer.profile.delayMs || 0) : false };
}
