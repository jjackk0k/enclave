// VARVEL — widerecon: ROSTER-WIDE PASSIVE RECON SWEEP (wide-recon + CVE build, Tool 1).
//
// The doctrine inversion (Jack, 2026-08-31): instead of deep-hunting ONE program at a
// time, passively recon MANY signed/recorded programs and surface the BIGGEST catches —
// staging/dev/internal hostnames, version-disclosing software (the CVE lane's feedstock),
// fresh subdomains, parameterized legacy URLs (IDOR candidates), jsminer-promising hosts.
// Coverage-gated BREADTH with an explicit untested-surface ledger: this tool TESTS
// NOTHING. It enumerates and ranks; the campaign + validator own proving.
//
//   node tools/widerecon.mjs sweep [--programs zomato,semrush] [--max-programs 3]
//                                  [--out data/exports] [--json] [--no-write]
//
// PASSIVE-FIRST per program (all GETs, no payloads, no enumeration beyond public data):
//   1. crt.sh subdomain enum per in-scope root (certificate transparency — public).
//   2. Wayback CDX per root: old/forgotten hostnames + parameterized URLs.
//   3. DNS resolution check per discovered host — via DoH THROUGH the ghost chain
//      (cloudflare-dns.com/dns-query), so no local DNS of targets ever happens.
//   4. TLS cert metadata per live host (subject/issuer/SAN/validity — origin hints).
//   5. HTTP tech fingerprint (cadence-permitting): GET / headers + <meta generator> +
//      a TINY fixed version-disclosing file set (/readme.html, /CHANGELOG.md — max 2).
//      This is NOT a crawl: one front page + at most two well-known files.
//
// POLICY-AWARE (hard rules):
//   * automation:'prohibited' programs (roster) AND the hard pin list
//     PROHIBITED_PROGRAMS (udemy, wordpress, matomo) are NEVER probed — they land in
//     the report as SKIPPED-POLICY with the reason named. Zero requests. Test-pinned.
//   * human-cadence programs: concurrency 1, >=5s between TARGET-contact requests
//     (TLS/HTTP fingerprint), >=1s between third-party intel fetches (crt.sh/wayback/DoH).
//   * scope fail-closed: crt.sh/wayback names outside the program's signed roots are
//     DROPPED and counted (droppedOutOfScope) — never fingerprinted.
//
// EGRESS DOCTRINE: every external request rides the ghost chain
// (VARVEL_WIDERECON_CHAIN, default socks5://10.64.0.1:1080) via engine/ghost.mjs agents
// and carries the research header X-HackerOne: varvel — crt.sh, web.archive.org, DoH,
// NVD-class feeds included. Transports are INJECTABLE (fetchImpl/resolveImpl/tlsImpl/
// sleepImpl) — the tests are hermetic fakes; the defaults are the ghost chain.
//
// HONESTY CONTRACT: every catch carries its evidence; anything not observed stays
// UNKNOWN (a failed DNS answer is resolution:'UNKNOWN', never guessed). A version match
// is NOT exploitability — the `software` tuples this tool emits feed tools/cvelane.mjs,
// whose output is HYPOTHESES for the validator, never findings.
//
// NEVER THROWS: per-program failures land in errors[] with the stage named.

import { readFileSync, writeFileSync, existsSync, mkdirSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';
import { Ghost, parseChain, openTunnel } from '../engine/ghost.mjs';
import { loadRoster } from '../engine/bountyline.mjs';
import { scoreHost } from './targetscore.mjs';

const __dir = dirname(fileURLToPath(import.meta.url));
const VARVEL_ROOT = join(__dir, '..');

export const WIDERECON_CAPS = {
  maxRootsPerProgram: 12, maxNamesPerRoot: 500, maxHostsPerProgram: 40,
  maxFingerprintHosts: 8, maxWaybackRows: 200, maxCatchesPerProgram: 25,
  bodyBytes: 65536, requestTimeoutMs: 20000, freshDays: 120,
};
export const RESEARCH_HEADER = { 'x-hackerone': 'varvel' }; // program rule: research traffic is identified
export const GHOST_CHAIN = () => process.env.VARVEL_WIDERECON_CHAIN || 'socks5://10.64.0.1:1080';
// HARD PIN (belt-and-braces over the roster policy field): these programs' policies
// prohibit automated tooling — they are listed in every report as SKIPPED-POLICY and
// receive ZERO requests even if a roster record ever says otherwise.
export const PROHIBITED_PROGRAMS = ['udemy', 'wordpress', 'matomo'];
// The ENTIRE active fingerprint read-set beyond GET / — two well-known files, never more.
export const FINGERPRINT_FILES = ['/readme.html', '/CHANGELOG.md'];

const iso = (now) => (now === undefined ? new Date().toISOString() : (typeof now === 'number' ? new Date(now).toISOString() : String(now)));
const realSleep = (ms) => new Promise((r) => setTimeout(r, ms));

// --- policy -------------------------------------------------------------------------------
// probePolicy(rosterEntry) → the cadence ceiling for this program. Prohibited wins over
// everything (hard pin list first, then the roster's own automation field).
export function probePolicy(entry) {
  const id = String((entry && (entry.id || entry.handle)) || '').toLowerCase();
  if (PROHIBITED_PROGRAMS.includes(id)) {
    return { policy: 'prohibited', concurrency: 0, targetDelayMs: null, intelDelayMs: null, fingerprint: false, reason: `hard-pinned automation-prohibited program (${id}) — listed SKIPPED-POLICY, zero requests` };
  }
  const auto = String((entry && entry.automation) || 'human-cadence');
  if (auto === 'prohibited') {
    return { policy: 'prohibited', concurrency: 0, targetDelayMs: null, intelDelayMs: null, fingerprint: false, reason: 'roster automation: prohibited (derived from the program\'s own policy text) — listed SKIPPED-POLICY, zero requests' };
  }
  if (auto === 'human-cadence') {
    return { policy: 'human-cadence', concurrency: 1, targetDelayMs: 5000, intelDelayMs: 1000, fingerprint: true, reason: 'human-cadence ceiling: concurrency 1, >=5s between target-contact requests, >=1s between intel fetches' };
  }
  return { policy: 'full', concurrency: 2, targetDelayMs: 1500, intelDelayMs: 500, fingerprint: true, reason: 'automation full — still conservative: small fixed read-set, no crawl' };
}

// --- intake parsing (pure) ------------------------------------------------------------------
const DOMAIN_RE = /^(?:\*\.)?([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,})$/i;

// rootDomains(intake) → the program's in-scope DOMAIN roots (wildcards unwrapped).
// CIDRs, app-store ids, and non-domain 'other' assets are not reconable here — skipped.
export function rootDomains(intake) {
  const inScope = (intake && intake.inScope) || {};
  const raw = [
    ...((Array.isArray(inScope.domains) ? inScope.domains : []).map((d) => (d && d.asset) || d)),
    ...(Array.isArray(inScope.wildcards) ? inScope.wildcards : []),
  ];
  const roots = [];
  for (const a of raw) {
    const m = DOMAIN_RE.exec(String(a || '').trim());
    if (!m) continue;
    const root = m[1].toLowerCase();
    if (!roots.includes(root)) roots.push(root);
  }
  return roots.slice(0, WIDERECON_CAPS.maxRootsPerProgram);
}

// inScopeHost(host, roots) — fail-closed: a name must BE a root or live UNDER one.
export function inScopeHost(host, roots) {
  const h = String(host || '').toLowerCase().replace(/\.$/, '');
  if (!h) return false;
  return (roots || []).some((r) => h === r || h.endsWith('.' + r));
}

// --- feed parsers (pure; the tests pin these against recorded samples) ----------------------

// crt.sh ?output=json rows: { name_value: "a.com\n*.b.com", not_before, issuer_name }.
// Returns Map-ish array [{ name, firstSeen (earliest not_before), issuer }]. Wildcards kept
// as their base name. Unparsable body → null (the caller names the error, never guesses).
export function parseCrtSh(text) {
  let rows;
  try { rows = JSON.parse(text); } catch { return null; }
  if (!Array.isArray(rows)) return null;
  const byName = new Map();
  for (const r of rows.slice(0, WIDERECON_CAPS.maxNamesPerRoot * 4)) {
    if (!r || typeof r.name_value !== 'string') continue;
    for (const raw of r.name_value.split('\n')) {
      const name = raw.trim().toLowerCase().replace(/^\*\./, '').replace(/\.$/, '');
      if (!name || !DOMAIN_RE.test(name)) continue;
      const nb = typeof r.not_before === 'string' ? r.not_before : null;
      const cur = byName.get(name);
      if (!cur) byName.set(name, { name, firstSeen: nb, issuer: typeof r.issuer_name === 'string' ? r.issuer_name.slice(0, 120) : null });
      else if (nb && (!cur.firstSeen || nb < cur.firstSeen)) cur.firstSeen = nb;
    }
  }
  return [...byName.values()].slice(0, WIDERECON_CAPS.maxNamesPerRoot);
}

// Wayback CDX (output=json, fl=timestamp,original): first row MAY be the header.
// Returns [{ url, host, path, timestamp, hasParams }] — rows capped.
export function parseWaybackCdx(text) {
  let rows;
  try { rows = JSON.parse(text); } catch { return null; }
  if (!Array.isArray(rows)) return null;
  if (rows.length && Array.isArray(rows[0]) && rows[0].includes('original')) rows = rows.slice(1);
  const out = [];
  for (const r of rows.slice(0, WIDERECON_CAPS.maxWaybackRows)) {
    if (!Array.isArray(r) || r.length < 2) continue;
    const [timestamp, url] = r;
    let u;
    try { u = new URL(String(url)); } catch { continue; }
    out.push({
      url: String(url).slice(0, 300), host: u.hostname.toLowerCase(),
      path: (u.pathname + u.search).slice(0, 200),
      timestamp: String(timestamp || ''), hasParams: /\?[^=]*=/.test(u.search),
    });
  }
  return out;
}

// Wayback timestamp '20160504123456' → '2016-05-04' (crt.sh dates are already ISO-ish).
export function waybackDate(ts) {
  const m = /^(\d{4})(\d{2})(\d{2})/.exec(String(ts || ''));
  return m ? `${m[1]}-${m[2]}-${m[3]}` : null;
}

// --- version disclosure extraction (pure) ---------------------------------------------------
const SERVER_RE = /^(nginx|apache|microsoft-iis|openresty|lighttpd|caddy|tomcat|jetty|gunicorn|uvicorn|envoy|ats|varnish|kestrel|cowboy)(?:\/([0-9][\w.-]*))?/i;
const XPB_RE = /^(php|asp\.net|express|rails|django|laravel|next\.js|nuxt|servlet|jsf)(?:\/([0-9][\w.-]*))?/i;
const GENERATOR_RE = /<meta[^>]*name=["']generator["'][^>]*content=["']([^"']{1,80})["']/i;
const GENERATOR_SPLIT_RE = /^([a-z][a-z0-9 .]*?)\s+v?([0-9][\w.-]*)$/i;
const README_VERSION_RE = /<h1[^>]*>[\s\S]{0,200}?Version\s+([0-9][\w.]*)<\/h1>|Version\s+([0-9][\w.]*)/i;
const CHANGELOG_VERSION_RE = /^#{1,3}\s+\[?v?([0-9]+\.[0-9]+[\w.-]*)\]?/m;

// extractTech({ headers, body, path }) → [{ software, version|null, evidence:{source, raw} }].
// Every tuple cites WHERE it came from; a bare banner without a version is version:null
// (UNKNOWN), never invented.
export function extractTech({ headers = {}, body = '', path = '/' } = {}) {
  const out = [];
  const push = (software, version, source, raw) => {
    if (out.some((t) => t.software === software && t.version === version)) return;
    out.push({ software, version: version || null, evidence: { source, raw: String(raw || '').slice(0, 120) } });
  };
  const h = {};
  for (const [k, v] of Object.entries(headers || {})) h[String(k).toLowerCase()] = Array.isArray(v) ? v.join('; ') : String(v);
  if (h.server) {
    const m = SERVER_RE.exec(h.server.trim());
    if (m) push(m[1].toLowerCase(), m[2] || null, 'server-header', h.server);
    else if (/cloudflare|akamai|cloudfront|fastly|awselb/i.test(h.server)) push('edge:' + h.server.trim().toLowerCase().slice(0, 40), null, 'server-header', h.server);
  }
  if (h['x-powered-by']) {
    const m = XPB_RE.exec(h['x-powered-by'].trim());
    if (m) push(m[1].toLowerCase(), m[2] || null, 'x-powered-by', h['x-powered-by']);
  }
  if (path === '/') {
    const g = GENERATOR_RE.exec(body || '');
    if (g) {
      const gm = GENERATOR_SPLIT_RE.exec(g[1].trim());
      if (gm) push(gm[1].toLowerCase().replace(/\s+/g, ''), gm[2], 'generator-meta', g[1]);
      else push(g[1].trim().toLowerCase().replace(/\s+/g, '-').slice(0, 40), null, 'generator-meta', g[1]);
    }
  }
  if (path === '/readme.html') {
    const m = README_VERSION_RE.exec(body || '');
    const v = m && (m[1] || m[2]);
    if (v) push('wordpress', v, 'readme.html', `readme.html names Version ${v}`);
  }
  if (path === '/CHANGELOG.md') {
    const m = CHANGELOG_VERSION_RE.exec(body || '');
    if (m) push('changelog-version', m[1], 'CHANGELOG.md', `CHANGELOG.md top heading names v${m[1]} (software attribution UNKNOWN — the file is the app's own)`);
  }
  return out;
}

// --- ranking (pure; targetscore-style — every bump names its signal + evidence) -------------

// rankHost(ctx) — ctx: { host, firstSeen, tech[], urls[], scriptCount, cert, nowMs }.
// Reuses tools/targetscore.mjs scoreHost for the shared signals (hostname keywords,
// parameterized endpoints, edge-walled, known-buggy stacks…) and adds the wide-recon
// signals on top. Deterministic.
export function rankHost(ctx = {}) {
  const host = String(ctx.host || '');
  const techLabels = (ctx.tech || []).map((t) => t.version ? `${t.software}/${t.version}` : t.software);
  const endpoints = (ctx.urls || []).map((u) => u.path);
  const base = scoreHost({ host, endpoints, tech: techLabels, subdomains: [] });
  let score = base.score;
  const reasons = [...base.reasons];
  const kinds = [];
  const bump = (signal, points, detail, kind) => {
    score += points;
    reasons.push(`${signal} ${points >= 0 ? '+' : ''}${points} — ${detail}`);
    if (kind && !kinds.includes(kind)) kinds.push(kind);
  };
  for (const c of base.classes) kinds.push(c);

  // wide-recon signal 1: FRESH SURFACE — first-seen (crt.sh not_before / earliest wayback
  // capture) inside the fresh window: young hosts are the least-audited ones.
  const nowMs = Number.isFinite(Number(ctx.nowMs)) ? Number(ctx.nowMs) : Date.now();
  if (ctx.firstSeen) {
    const ageDays = (nowMs - Date.parse(ctx.firstSeen)) / 86400000;
    if (Number.isFinite(ageDays) && ageDays >= 0 && ageDays <= WIDERECON_CAPS.freshDays) {
      bump('fresh-subdomain', 12, `first seen ${ctx.firstSeen} (${Math.round(ageDays)}d ago, <= ${WIDERECON_CAPS.freshDays}d window) — young surface is the least audited`, 'fresh-subdomain');
    }
  }
  // wide-recon signal 2: VERSION DISCLOSED — a (software, version) tuple is cvelane
  // feedstock; a version the host TELLS us beats any guess.
  const disclosed = (ctx.tech || []).filter((t) => t.version);
  if (disclosed.length) {
    bump('version-disclosed', Math.min(20, 10 * disclosed.length), `${disclosed.length} version-disclosing tuple(s): ${disclosed.slice(0, 3).map((t) => `${t.software}/${t.version}`).join(', ')} — feed tools/cvelane.mjs`, 'version-disclosed');
  }
  // wide-recon signal 3: TLS ORIGIN HINT — a cert naming an internal/non-prod identity.
  if (ctx.cert && ctx.cert.subject && /(?:^|[.\-=, ])(admin|staging|stage|dev|internal|test|sandbox|uat|qa|corp|vpn)(?:[.\-, =]|$)/i.test(String(ctx.cert.subject))) {
    bump('tls-origin-hint', 8, `TLS subject "${String(ctx.cert.subject).slice(0, 80)}" names a non-prod/internal identity — the certificate leaks the backend's real name`, 'tls-origin-hint');
  }
  // wide-recon signal 4: JSMINER FODDER — script-dense front page / SPA shell.
  if (Number(ctx.scriptCount) >= 5) {
    bump('jsminer-fodder', 6, `${ctx.scriptCount} script srcs on the front page — jsminer territory (endpoints/secrets/sourcemaps live in the bundles)`, 'jsminer-fodder');
  }
  // wide-recon signal 5: LEGACY PARAMETERIZED URLs — old wayback captures carrying
  // ?param= on this host are IDOR-shape surface that may still answer.
  const legacy = (ctx.urls || []).filter((u) => u.hasParams);
  if (legacy.length) kinds.includes('idor-candidate') || kinds.push('idor-candidate');

  score = Math.max(0, Math.min(100, Math.round(score)));
  return { host, score, reasons, kinds, versionTuples: disclosed };
}

// --- transports (injectable; defaults ride the ghost chain) ---------------------------------

export function ghostAgents(chainStr) {
  const g = new Ghost();
  g.configure({ mode: 'on', chain: chainStr || GHOST_CHAIN() });
  return g.agents(); // { httpAgent, httpsAgent } — private dests go direct by ghost rule
}

// ghostGet(url, { agents, timeoutMs, fetchImpl, headers }) → { ok, status, headers, body } — NEVER throws.
// fetchImpl seam (hermetic tests): (url, { headers }) => Promise<{ status, headers, body } | null>.
export async function ghostGet(url, { agents, timeoutMs = WIDERECON_CAPS.requestTimeoutMs, fetchImpl, headers: extraHeaders, maxBytes } = {}) {
  const cap = Number.isFinite(Number(maxBytes)) && Number(maxBytes) > 0 ? Number(maxBytes) : WIDERECON_CAPS.bodyBytes;
  const reqHeaders = { accept: '*/*', ...(extraHeaders || {}), ...RESEARCH_HEADER };
  if (fetchImpl) {
    try {
      const r = await fetchImpl(url, { headers: reqHeaders });
      if (!r) return { ok: false, error: 'unreachable', reason: 'transport returned null (timeout/refused/reset)' };
      return { ok: true, status: r.status, headers: r.headers || {}, body: typeof r.body === 'string' ? r.body : String(r.body || '') };
    } catch (e) {
      return { ok: false, error: 'unreachable', reason: `transport threw: ${String((e && e.message) || e).slice(0, 160)}` };
    }
  }
  const u = new URL(url);
  const lib = u.protocol === 'https:' ? https : http;
  const agent = agents ? (u.protocol === 'https:' ? agents.httpsAgent : agents.httpAgent) : undefined;
  return await new Promise((resolvePromise) => {
    let settled = false;
    const done = (v) => { if (!settled) { settled = true; resolvePromise(v); } };
    const req = lib.request({
      hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname + u.search, method: 'GET', agent, timeout: timeoutMs,
      headers: { 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0', ...reqHeaders },
    }, (res) => {
      let text = '';
      res.on('data', (d) => { if (text.length < cap) text += d.toString('utf8', 0, Math.max(0, cap - text.length)); });
      res.on('end', () => done({ ok: true, status: res.statusCode, headers: res.headers, body: text }));
      res.on('error', (e) => done({ ok: false, error: 'unreachable', reason: `response stream error: ${String(e.message || e).slice(0, 160)}` }));
    });
    req.on('timeout', () => { try { req.destroy(); } catch {} done({ ok: false, error: 'unreachable', reason: `timeout after ${timeoutMs}ms` }); });
    req.on('error', (e) => done({ ok: false, error: 'unreachable', reason: `${String(e.message || e).slice(0, 160)} — is the ghost chain (${GHOST_CHAIN()}) up?` }));
    req.end();
  });
}

// DoH resolution THROUGH the chain (no local DNS of targets): cloudflare-dns.com dns-json.
// resolveImpl seam: (host) => Promise<{ addresses: string[] } | null> — null = UNKNOWN.
export async function dohResolve(host, { agents, fetchImpl } = {}) {
  const r = await ghostGet(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=A`, { agents, fetchImpl, headers: { accept: 'application/dns-json' } });
  if (!r.ok || r.status !== 200) return null; // UNKNOWN — never guessed
  try {
    const j = JSON.parse(r.body);
    const addrs = (Array.isArray(j.Answer) ? j.Answer : []).filter((a) => a && a.type === 1).map((a) => String(a.data));
    return { addresses: addrs };
  } catch { return null; }
}

// TLS cert metadata via a raw tunnel through the chain. tlsImpl seam: (host) => Promise<cert|null>.
export async function tlsCertViaChain(host, { chain, timeoutMs = 12000, tlsImpl } = {}) {
  if (tlsImpl) {
    try { return await tlsImpl(host); } catch { return null; }
  }
  const hops = parseChain(chain || GHOST_CHAIN());
  return await new Promise((resolvePromise) => {
    let settled = false;
    const done = (v) => { if (!settled) { settled = true; resolvePromise(v); } };
    const t = setTimeout(() => { try { sock && sock.destroy(); } catch {} done(null); }, timeoutMs);
    let sock = null;
    openTunnel(hops, host, 443, timeoutMs).then((s) => {
      sock = s;
      const ts = tls.connect({ socket: s, servername: host, rejectUnauthorized: false }, () => {
        clearTimeout(t);
        let c = null;
        try { c = ts.getPeerCertificate(); } catch { c = null; }
        try { ts.destroy(); } catch {}
        if (!c || !c.subject) return done(null);
        done({
          subject: c.subject.CN || null, issuer: (c.issuer && (c.issuer.O || c.issuer.CN)) || null,
          san: c.subjectaltname ? String(c.subjectaltname).slice(0, 300) : null,
          validFrom: c.valid_from || null, validTo: c.valid_to || null,
        });
      });
      ts.once('error', () => { clearTimeout(t); done(null); });
    }, () => { clearTimeout(t); done(null); });
  });
}

// --- the sweep ------------------------------------------------------------------------------

const countScripts = (body) => ((String(body || '').match(/<script[^>]+\bsrc=/gi) || []).length);

// sweepProgram(entry, intake, opts) — one program, passive-first, policy-paced. Never throws.
export async function sweepProgram(entry, intake, opts = {}) {
  const id = String(entry.id || entry.handle);
  const onLog = typeof opts.onLog === 'function' ? opts.onLog : () => {};
  const sleep = typeof opts.sleepImpl === 'function' ? opts.sleepImpl : realSleep;
  const nowMs = Number.isFinite(Number(opts.nowMs)) ? Number(opts.nowMs) : Date.now();
  // caps override seam (CLI --max-roots/--max-hosts/--max-fingerprint): smoke runs shrink
  // the breadth, never the pacing — the cadence floors are NOT overridable.
  const caps = { ...WIDERECON_CAPS, ...((opts.caps && typeof opts.caps === 'object') ? opts.caps : {}) };
  const policy = probePolicy(entry);
  const rec = {
    program: id, handle: entry.handle || id, automation: policy.policy,
    status: 'SWEPT', policyNote: policy.reason,
    roots: [], hosts: [], catches: [], errors: [], droppedOutOfScope: 0,
    requests: { intel: 0, target: 0 },
  };
  if (policy.policy === 'prohibited') {
    rec.status = 'SKIPPED-POLICY';
    rec.errors.push({ stage: 'policy', reason: policy.reason });
    onLog('widerecon.skip-policy', { program: id, reason: policy.reason });
    return rec;
  }
  const roots = rootDomains(intake).slice(0, caps.maxRootsPerProgram);
  rec.roots = roots;
  if (!roots.length) {
    rec.status = 'NO-DOMAIN-ROOTS';
    rec.errors.push({ stage: 'intake', reason: 'the intake carries no in-scope DOMAIN roots (CIDRs/app-store ids only, or nothing signed) — nothing passive to enumerate' });
    return rec;
  }

  const paceIntel = () => sleep(policy.intelDelayMs);
  const paceTarget = () => sleep(policy.targetDelayMs);

  // stage 1+2: crt.sh + wayback per root (third-party intel — public data, paced politely)
  const crtByName = new Map(); // host -> { firstSeen, issuer }
  const waybackByHost = new Map(); // host -> [{url,path,timestamp,hasParams}]
  for (const root of roots) {
    await paceIntel();
    rec.requests.intel++;
    const crt = await ghostGet(`https://crt.sh/?q=%25.${encodeURIComponent(root)}&output=json`, opts);
    if (!crt.ok) rec.errors.push({ stage: 'crt.sh', root, reason: `${crt.error}: ${crt.reason}` });
    else if (crt.status !== 200) rec.errors.push({ stage: 'crt.sh', root, reason: `HTTP ${crt.status} — names were NOT fabricated` });
    else {
      const names = parseCrtSh(crt.body);
      if (!names) rec.errors.push({ stage: 'crt.sh', root, reason: 'unparsable response body — names were NOT fabricated' });
      else for (const n of names) {
        if (!inScopeHost(n.name, roots)) { rec.droppedOutOfScope++; continue; }
        const cur = crtByName.get(n.name);
        if (!cur || (n.firstSeen && (!cur.firstSeen || n.firstSeen < cur.firstSeen))) crtByName.set(n.name, n);
      }
    }
    await paceIntel();
    rec.requests.intel++;
    const wb = await ghostGet(`https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent('*.' + root + '/*')}&output=json&fl=timestamp,original&collapse=urlkey&limit=${WIDERECON_CAPS.maxWaybackRows}&filter=statuscode:200`, opts);
    if (!wb.ok) rec.errors.push({ stage: 'wayback', root, reason: `${wb.error}: ${wb.reason}` });
    else if (wb.status !== 200) rec.errors.push({ stage: 'wayback', root, reason: `HTTP ${wb.status} — URLs were NOT fabricated` });
    else {
      const rows = parseWaybackCdx(wb.body);
      if (!rows) rec.errors.push({ stage: 'wayback', root, reason: 'unparsable CDX body — URLs were NOT fabricated' });
      else if (rows) for (const r of rows) {
        if (!inScopeHost(r.host, roots)) { rec.droppedOutOfScope++; continue; }
        const list = waybackByHost.get(r.host) || [];
        if (list.length < 40) list.push(r);
        waybackByHost.set(r.host, list);
      }
    }
  }

  // host universe: crt.sh names ∪ wayback hosts ∪ the roots themselves (capped)
  const hostSet = new Set([...crtByName.keys(), ...waybackByHost.keys(), ...roots]);
  const hosts = [...hostSet].slice(0, caps.maxHostsPerProgram);

  // stage 3: DNS check per host (DoH through the chain; failure = UNKNOWN, never guessed)
  const live = [];
  for (const host of hosts) {
    await paceIntel();
    rec.requests.intel++;
    const r = opts.resolveImpl ? await (async () => { try { return await opts.resolveImpl(host); } catch { return null; } })()
      : await dohResolve(host, opts);
    const wbUrls = waybackByHost.get(host) || [];
    const firstSeen = (crtByName.get(host) && crtByName.get(host).firstSeen)
      || (wbUrls.length ? waybackDate(wbUrls.map((u) => u.timestamp).sort()[0]) : null);
    const hrec = {
      host, resolution: r ? (r.addresses.length ? 'RESOLVES' : 'NO-A-RECORD') : 'UNKNOWN',
      addresses: r ? r.addresses.slice(0, 4) : [],
      firstSeen: firstSeen || null, crtIssuer: (crtByName.get(host) || {}).issuer || null,
      waybackUrls: wbUrls, tech: [], cert: null, scriptCount: 0, fingerprinted: false,
    };
    rec.hosts.push(hrec);
    if (hrec.resolution === 'RESOLVES') live.push(hrec);
  }

  // stage 4+5: TLS cert + tiny HTTP fingerprint on a CAPPED set of live hosts (target contact
  // — the human-cadence >=5s pacing applies HERE; prohibited programs never get this far)
  for (const hrec of live.slice(0, caps.maxFingerprintHosts)) {
    await paceTarget();
    rec.requests.target++;
    hrec.cert = await tlsCertViaChain(hrec.host, { chain: opts.chain, tlsImpl: opts.tlsImpl });
    if (!hrec.cert) hrec.certNote = 'cert UNREADABLE (no TLS listener / chain refused / timeout) — recorded UNKNOWN, not guessed';
    if (!policy.fingerprint) continue;
    await paceTarget();
    rec.requests.target++;
    const page = await ghostGet(`https://${hrec.host}/`, opts);
    if (page.ok && page.status) {
      hrec.fingerprinted = true;
      hrec.httpStatus = page.status;
      hrec.tech.push(...extractTech({ headers: page.headers, body: page.body, path: '/' }));
      hrec.scriptCount = countScripts(page.body);
      const looksWp = hrec.tech.some((t) => /word\s?press/.test(t.software)) || /wp-content|wp-includes/.test(page.body || '');
      const files = looksWp ? FINGERPRINT_FILES : FINGERPRINT_FILES.slice(0, 1); // WP-class hosts get both files; others only CHANGELOG
      for (const f of files) {
        await paceTarget();
        rec.requests.target++;
        const fr = await ghostGet(`https://${hrec.host}${f}`, opts);
        if (fr.ok && fr.status === 200) hrec.tech.push(...extractTech({ headers: fr.headers, body: fr.body, path: f }));
      }
    } else if (!page.ok) {
      hrec.fingerprintNote = `front page ${page.error}: ${page.reason} — tech stays UNKNOWN`;
    }
  }

  // rank + catch-list
  for (const hrec of rec.hosts) {
    const ranked = rankHost({
      host: hrec.host, firstSeen: hrec.firstSeen, tech: hrec.tech, urls: hrec.waybackUrls,
      scriptCount: hrec.scriptCount, cert: hrec.cert, nowMs,
    });
    hrec.score = ranked.score;
    const interesting = ranked.kinds.length > 0 || ranked.versionTuples.length > 0 || hrec.resolution === 'RESOLVES';
    if (!interesting) continue;
    rec.catches.push({
      program: id, host: hrec.host, score: ranked.score, kinds: ranked.kinds,
      resolution: hrec.resolution, firstSeen: hrec.firstSeen,
      software: ranked.versionTuples.map((t) => ({ software: t.software, version: t.version, evidence: t.evidence })),
      legacyParamUrls: hrec.waybackUrls.filter((u) => u.hasParams).slice(0, 5).map((u) => u.url),
      reasons: ranked.reasons,
      evidence: {
        crt: crtByName.has(hrec.host) ? { firstSeen: crtByName.get(hrec.host).firstSeen, issuer: crtByName.get(hrec.host).issuer } : null,
        waybackCaptures: hrec.waybackUrls.length,
        httpStatus: hrec.httpStatus || null, cert: hrec.cert,
      },
      tested: false, // widerecon TESTS NOTHING — every catch is recon output for the campaign + validator
    });
  }
  rec.catches.sort((a, b) => b.score - a.score || a.host.localeCompare(b.host));
  rec.catches = rec.catches.slice(0, WIDERECON_CAPS.maxCatchesPerProgram);
  onLog('widerecon.program-done', { program: id, hosts: rec.hosts.length, live: live.length, catches: rec.catches.length, errors: rec.errors.length });
  return rec;
}

// loadIntakes(dataDir) — roster entries joined to their <id>-program.json intake files.
export function loadIntakes(dataDir) {
  const dir = dataDir || join(process.env.VARVEL_BOUNTYLINE_DIR || join(VARVEL_ROOT, 'data', 'bountyline'));
  const roster = (() => { try { return JSON.parse(readFileSync(join(dir, 'roster.json'), 'utf8')); } catch { return loadRoster(); } })();
  const entries = Array.isArray(roster.programs) ? roster.programs : [];
  return entries.map((e) => {
    let intake = null;
    try { const p = join(dir, `${e.id}-program.json`); if (existsSync(p)) intake = JSON.parse(readFileSync(p, 'utf8')); } catch { intake = null; }
    // h1sync snapshot (scope/policy text the intake was built from) — metadata only.
    let h1sync = null;
    try { const p = join(dir, 'h1sync', `${e.handle || e.id}.json`); if (existsSync(p)) h1sync = JSON.parse(readFileSync(p, 'utf8')); } catch { h1sync = null; }
    return { entry: e, intake, h1sync };
  });
}

// sweep(opts) — the roster-wide pass. Returns the report object (never throws per-program).
export async function sweep(opts = {}) {
  const onLog = typeof opts.onLog === 'function' ? opts.onLog : () => {};
  const programsFilter = Array.isArray(opts.programs) && opts.programs.length ? opts.programs.map((p) => String(p).toLowerCase()) : null;
  let joined = loadIntakes(opts.dataDir);
  if (programsFilter) joined = joined.filter((j) => programsFilter.includes(String(j.entry.id).toLowerCase()) || programsFilter.includes(String(j.entry.handle || '').toLowerCase()));
  if (Number.isFinite(Number(opts.maxPrograms)) && Number(opts.maxPrograms) > 0) joined = joined.slice(0, Number(opts.maxPrograms));

  const agents = opts.fetchImpl || opts.resolveImpl || opts.tlsImpl ? (opts.agents || null) : ghostAgents(opts.chain);
  const shared = { ...opts, agents: opts.agents || agents, onLog };
  const programs = [];
  for (const j of joined) {
    try {
      programs.push(await sweepProgram(j.entry, j.intake || {}, shared));
    } catch (e) { // a tool that never throws still guards the batch: one bad program kills nothing
      programs.push({ program: String(j.entry.id || '?'), status: 'ERROR', errors: [{ stage: 'sweep', reason: String((e && e.message) || e).slice(0, 200) }], hosts: [], catches: [], requests: { intel: 0, target: 0 } });
    }
  }

  const catches = programs.flatMap((p) => p.catches || []).sort((a, b) => b.score - a.score || a.host.localeCompare(b.host));
  const skipped = programs.filter((p) => p.status === 'SKIPPED-POLICY').map((p) => ({ program: p.program, reason: p.policyNote }));
  // The software-tuple feedstock for tools/cvelane.mjs: (program, host, software, version, evidence).
  const softwareTuples = catches.flatMap((c) => (c.software || []).map((s) => ({
    program: c.program, host: c.host, software: s.software, version: s.version, evidence: s.evidence,
  })));
  const report = {
    tool: 'widerecon', at: iso(opts.now), chain: opts.chain || GHOST_CHAIN(),
    programs, catches, skippedPolicy: skipped, softwareTuples,
    stats: {
      programs: programs.length, swept: programs.filter((p) => p.status === 'SWEPT').length,
      skippedPolicy: skipped.length,
      hosts: programs.reduce((n, p) => n + (p.hosts || []).length, 0),
      catches: catches.length,
      requests: programs.reduce((n, p) => ({ intel: n.intel + ((p.requests || {}).intel || 0), target: n.target + ((p.requests || {}).target || 0) }), { intel: 0, target: 0 }),
    },
    untestedLedger: {
      verdict: 'NOTHING-TESTED',
      note: 'widerecon is recon-only: every catch above was ENUMERATED, never TESTED. The campaign coverage gate (engine/coverage.mjs) treats this list as QUEUED surface; a catch becomes real only through the validator path (captured bytes + differential). Unknowns are marked UNKNOWN, never guessed.',
    },
    limitations: [
      'crt.sh sees only certificate-logged names — hosts never issued a logged cert are invisible',
      'wayback CDX coverage is whatever the crawler archived — absence of a capture is NOT absence of a host',
      'a disclosed version is a HYPOTHESIS input, not a vulnerability — see tools/cvelane.mjs and the validator bar',
      'no system catches everything: this sweep trades depth for coverage-gated breadth; the per-program untested ledger is the honest remainder',
    ],
  };
  return report;
}

// renderMd(report) — the human face of the catch-list.
export function renderMd(report) {
  const L = [];
  L.push(`# widerecon catch-list — ${report.at}`);
  L.push('');
  L.push(`Chain: \`${report.chain}\` · programs swept: ${report.stats.swept}/${report.stats.programs} · hosts: ${report.stats.hosts} · catches: ${report.stats.catches} · requests: ${report.stats.requests.intel} intel / ${report.stats.requests.target} target-contact`);
  L.push('');
  L.push(`> **${report.untestedLedger.verdict}** — ${report.untestedLedger.note}`);
  L.push('');
  if (report.skippedPolicy.length) {
    L.push('## SKIPPED-POLICY (never probed — zero requests)');
    L.push('');
    for (const s of report.skippedPolicy) L.push(`- **${s.program}** — ${s.reason}`);
    L.push('');
  }
  L.push('## Ranked catches');
  L.push('');
  L.push('| score | program | host | kinds | first seen | software (version-disclosed) |');
  L.push('| --- | --- | --- | --- | --- | --- |');
  for (const c of report.catches) {
    const sw = (c.software || []).map((s) => `${s.software}/${s.version}`).join(', ') || '—';
    L.push(`| ${c.score} | ${c.program} | ${c.host} | ${c.kinds.join(', ') || '—'} | ${c.firstSeen || 'UNKNOWN'} | ${sw} |`);
  }
  if (!report.catches.length) L.push('| — | — | — | no catches surfaced (empty is an honest result) | — | — |');
  L.push('');
  L.push('## Per-program notes');
  L.push('');
  for (const p of report.programs) {
    L.push(`- **${p.program}** — ${p.status}; roots: ${(p.roots || []).join(', ') || 'none'}; hosts: ${(p.hosts || []).length}; dropped-out-of-scope: ${p.droppedOutOfScope || 0}${(p.errors || []).length ? `; errors: ${p.errors.map((e) => `${e.stage}: ${e.reason}`).join('; ')}` : ''}`);
  }
  L.push('');
  L.push('## Limitations (stated, not hidden)');
  L.push('');
  for (const l of report.limitations) L.push(`- ${l}`);
  L.push('');
  return L.join('\n');
}

// writeExports(report, { outDir, date }) → { jsonPath, mdPath } — the ONLY legal write under
// data/: new files into data/exports/ (the standing exception).
export function writeExports(report, { outDir, date } = {}) {
  const dir = outDir || process.env.VARVEL_WIDERECON_OUT || join(VARVEL_ROOT, 'data', 'exports');
  mkdirSync(dir, { recursive: true });
  const d = date || String(report.at || new Date().toISOString()).slice(0, 10);
  const jsonPath = join(dir, `widerecon-${d}.json`);
  const mdPath = join(dir, `widerecon-${d}.md`);
  writeFileSync(jsonPath, JSON.stringify(report, null, 2) + '\n');
  writeFileSync(mdPath, renderMd(report));
  return { jsonPath, mdPath };
}

// --- CLI ------------------------------------------------------------------------------------
const isMain = process.argv[1] && fileURLToPath(import.meta.url) === join(process.argv[1]);
if (isMain) {
  const args = process.argv.slice(2);
  const cmd = args[0] || 'sweep';
  const opt = (name) => { const i = args.indexOf('--' + name); return i >= 0 ? args[i + 1] : null; };
  const has = (name) => args.includes('--' + name);
  if (cmd !== 'sweep') {
    console.error('usage: node tools/widerecon.mjs sweep [--programs a,b] [--max-programs N] [--out dir] [--json] [--no-write]');
    process.exit(64);
  }
  const report = await sweep({
    programs: opt('programs') ? opt('programs').split(',') : null,
    maxPrograms: opt('max-programs') ? Number(opt('max-programs')) : null,
    caps: {
      ...(opt('max-roots') ? { maxRootsPerProgram: Number(opt('max-roots')) } : {}),
      ...(opt('max-hosts') ? { maxHostsPerProgram: Number(opt('max-hosts')) } : {}),
      ...(opt('max-fingerprint') ? { maxFingerprintHosts: Number(opt('max-fingerprint')) } : {}),
    },
    onLog: (t, o) => console.error(`[${t}] ${JSON.stringify(o)}`),
  });
  let paths = null;
  if (!has('no-write')) paths = writeExports(report, { outDir: opt('out') || undefined });
  if (has('json')) console.log(JSON.stringify(report, null, 2));
  else {
    console.log(renderMd(report));
    if (paths) console.error(`\nwrote ${paths.jsonPath}\nwrote ${paths.mdPath}`);
  }
}
