// VARVEL — gather: the recon stage's passive evidence collector (the hunt loop's
// answer to "the brain judges blind"). Per in-scope web asset it fetches REAL pages
// through the ghost chain and distills them into a bounded evidence bundle: tech +
// versions (tools/wappalyze.mjs detectOnPage — the repo's own passive fingerprint,
// reused, never reimplemented), notable headers, statuses, and endpoints from
// PASSIVE sources only (robots.txt — the universally-allowed passive path;
// third-party archive sources stay a deliberate later step, named here so nobody
// mistakes robots.txt for a crawl). Mechanical candidates then come from engine/cvepacks.mjs
// (version→CVE, firm-not-confirmed) and the brain judges on facts.
//
// THE RAILS (all tested):
//   1. OUT-OF-SCOPE NEVER RECEIVES A REQUEST. The scope guard re-filters every
//      URL before dispatch (defense-in-depth: program.mjs already filtered, we
//      filter again): out-of-scope wins, anything not positively in-scope is
//      denied, and a violation throws 'scope-violation' rather than send a byte.
//      Endpoints harvested from passive sources are filtered the same way before
//      they enter the bundle.
//   2. PACED. Caps are small, configurable, and conservative by default:
//      5 assets/opportunity, 2 target requests/asset (root + robots.txt), 25
//      requests/opportunity, 500ms between requests, a 150s whole-gather deadline —
//      the numbers are printed into the events so a program's policy text and the
//      loop's behavior can never silently disagree.
//   3. GHOST FAIL-CLOSED for every external byte (ghostFetch — the audited
//      transport; local targets stay direct by its own carve-out). No chain =
//      plain fetch, named honestly (the fixture lane).
//   4. BOUNDED: per-asset body read capped (256KB), the serialized bundle capped
//      (12KB), the brain-facing summary capped (4KB). Failures are recorded with
//      their error names — previous state is kept, nothing is invented.
//
// Zero target crawling: root + robots.txt per asset (robots.txt is passive and
// universally allowed; third-party archive sources are a deliberate LATER step,
// named here so nobody mistakes robots.txt for a crawl).

import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { detectOnPage } from './wappalyze.mjs';
import { inCidr, parseIp } from '../engine/ipaddr.mjs';
import { ghostFetch } from './ghostfetch.mjs';

const __dir = dirname(fileURLToPath(import.meta.url));

// THE CADENCE CONTRACT — conservative by default; every number rides the events.
// 2026-09-12 cadence review (opensource-recon-memo.md): 2 req/s is the floor of the
// most conservative published AI pipeline (0sec); nuclei ships 150 req/s. 500ms sits
// ON that floor and stays inside the 1–2 rps band for cautious rate-limit-language
// programs. Cross-program parallelism — not per-target heat — is the scaling axis.
export const CADENCE = {
  maxAssets: 5,            // per opportunity
  maxRequestsPerAsset: 2,  // target requests per asset (root + robots.txt)
  maxRequests: 25,         // whole-opportunity request cap (target + third-party)
  delayMs: 500,            // between requests (2 req/s — the published AI-pipeline floor)
  timeoutMs: 15000,        // per-request whole-operation timeout
  gatherDeadlineMs: 150000,// the whole gather stage fits inside the opportunity budget
  maxBodyKB: 256,          // per-response body read cap
  maxBundleKB: 12,         // persisted bundle cap
  maxBrainKB: 4,           // the brain-facing summary cap
  maxEndpointsPerAsset: 10,
};

// --- the scope guard (defense-in-depth; the trap-asset test pins this) -------------
// buildScopeGuard(intake) -> { allow(urlOrHost) -> bool, why(host) -> string }.
// Out-of-scope ALWAYS wins; anything not positively in-scope is denied. Wildcards
// match suffixes; CIDRs match IPs; domains match exactly. program.mjs's own rule,
// re-applied at the wire so a bug upstream can never become a request downstream.
export function buildScopeGuard(intake) {
  const inD = new Set((intake?.inScope?.domains || []).map((d) => String(d.asset).toLowerCase()));
  const inW = (intake?.inScope?.wildcards || []).map((w) => String(w.suffix || w.asset.replace(/^\*\./, '')).toLowerCase());
  const inC = (intake?.inScope?.cidrs || []).map((c) => String(c.asset));
  const outD = new Set((intake?.outOfScope?.domains || []).map((d) => String(d.asset).toLowerCase()));
  const outW = (intake?.outOfScope?.wildcards || []).map((w) => String(w.suffix || w.asset.replace(/^\*\./, '')).toLowerCase());
  const outC = (intake?.outOfScope?.cidrs || []).map((c) => String(c.asset));
  const hostInCidrs = (host, cidrs) => {
    const ip = parseIp(host);
    if (!ip) return false;
    return cidrs.some((c) => { try { return inCidr(host, c); } catch { return false; } });
  };
  const hostInWild = (host, wilds) => wilds.some((s) => host === s || host.endsWith('.' + s));
  const verdict = (hostRaw) => {
    const host = String(hostRaw || '').toLowerCase().replace(/^\[|\]$/g, '');
    if (!host) return { ok: false, why: 'empty host' };
    if (outD.has(host) || hostInWild(host, outW) || hostInCidrs(host, outC)) {
      return { ok: false, why: `OUT-OF-SCOPE (exclusion wins, always)` };
    }
    if (inD.has(host) || hostInWild(host, inW) || hostInCidrs(host, inC)) return { ok: true, why: 'in-scope' };
    return { ok: false, why: 'not positively in-scope (deny by default)' };
  };
  return {
    allow: (urlOrHost) => {
      let host = String(urlOrHost || '');
      try { host = new URL(host).hostname; } catch { /* already a bare host */ }
      return verdict(host).ok;
    },
    why: (host) => verdict(host).why,
    assertAllowed: (url) => {
      let host = String(url || '');
      try { host = new URL(url).hostname; } catch { /* bare */ }
      const v = verdict(host);
      if (!v.ok) {
        const e = new Error(`SCOPE GUARD REFUSED a request to ${host}: ${v.why} — out-of-scope never receives a request, by construction`);
        e.code = 'scope-violation';
        throw e;
      }
    },
  };
}

// selectAssets(intake, guard, caps) — the walk list: in-scope domains, wildcard
// APEXES (never enumerated — the doctrine), and host-route CIDRs (/32, /128),
// scope-guarded AGAIN and capped. Trap assets can never appear here.
export function selectAssets(intake, guard, { maxAssets = CADENCE.maxAssets } = {}) {
  const out = [];
  const push = (host, kind) => {
    const h = String(host || '').toLowerCase();
    if (!h || out.some((a) => a.host === h)) return;
    if (!guard.allow(h)) return; // defensive: an out-of-scope entry never becomes an asset
    out.push({ host: h, kind });
  };
  for (const d of intake?.inScope?.domains || []) push(d.asset, 'domain');
  for (const w of intake?.inScope?.wildcards || []) push(w.suffix || String(w.asset).replace(/^\*\./, ''), 'wildcard-apex');
  for (const c of intake?.inScope?.cidrs || []) {
    const a = String(c.asset);
    if (a.endsWith('/32') || a.endsWith('/128')) push(a.split('/')[0], 'host-route');
  }
  return out.slice(0, maxAssets);
}

// --- one fetch through the wire, bounded --------------------------------------------
async function guardedGet(wire, guard, url, { timeoutMs, maxBodyKB }, requests) {
  guard.assertAllowed(url); // THE RAIL — throws 'scope-violation' before any byte
  if (requests.count >= requests.cap) {
    const e = new Error(`request cap ${requests.cap} reached — no more requests this opportunity (cadence, honestly named)`);
    e.code = 'cadence-cap';
    throw e;
  }
  requests.count += 1;
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), timeoutMs);
  try {
    const res = await wire(url, { signal: ac.signal, headers: { 'user-agent': 'VARVEL-gather (passive; human-cadence; contact: program policy)' } });
    let body = '';
    if (typeof res.text === 'function') body = await res.text();
    else if (typeof res.json === 'function') body = JSON.stringify(await res.json());
    return { ok: res.ok !== false, status: res.status, headers: res.headers || {}, body: String(body).slice(0, maxBodyKB * 1024) };
  } finally {
    clearTimeout(t);
  }
}

const NOTABLE_HEADERS = ['server', 'x-powered-by', 'x-generator', 'x-aspnet-version', 'cf-ray', 'x-cache', 'via', 'strict-transport-security', 'content-security-policy', 'x-frame-options', 'x-content-type-options'];
const ROBOTS_INTERESTING = /^\/(?:wp-admin|wp-login|admin|administrator|api|graphql|debug|actuator|internal|private|backup|\.git|\.env|config)/i;

// gatherOpportunity({ intake, chain, fetchImpl, emit, dir, now, caps, sleepImpl })
// -> { ok, bundle, bundlePath, brainText, counts { assetsProbed, requestsMade, techsFound, endpointsFound, errors } }
export async function gatherOpportunity({ intake, chain, fetchImpl, emit, dir, now, caps = {}, sleepImpl } = {}) {
  const C = { ...CADENCE, ...caps };
  const guard = buildScopeGuard(intake);
  const wire = fetchImpl || (chain ? ghostFetch(chain, { timeoutMs: C.timeoutMs }) : fetch);
  const sleep = sleepImpl || ((ms) => new Promise((r) => setTimeout(r, ms)));
  const requests = { count: 0, cap: C.maxRequests };
  const counts = { assetsProbed: 0, requestsMade: 0, techsFound: 0, endpointsFound: 0, errors: 0 };
  const deadline = Date.now() + C.gatherDeadlineMs;
  const assets = selectAssets(intake, guard, C);
  const bundle = { at: now ? new Date(now).toISOString() : new Date().toISOString(), opportunity: intake?.program?.handle || null, cadence: { ...C }, assets: [] };

  const note = (ev) => { if (emit) emit.raw({ type: 'gather', ...ev }); };
  note({ state: 'active', msg: `gather: ${assets.length} asset(s) selected — cadence ${C.maxRequestsPerAsset} req/asset, ${C.delayMs}ms delay, cap ${C.maxRequests} req, deadline ${Math.round(C.gatherDeadlineMs / 1000)}s, bundle ≤${C.maxBundleKB}KB (ghost fail-closed)` });

  for (const asset of assets) {
    if (Date.now() > deadline) {
      note({ state: 'deadline', asset: asset.host, msg: `gather deadline ${Math.round(C.gatherDeadlineMs / 1000)}s reached — ${counts.assetsProbed}/${assets.length} assets probed (honest partial)` });
      break;
    }
    const rec = { host: asset.host, kind: asset.kind, status: null, techs: [], headers: {}, endpoints: [], requests: 0 };
    // request 1: the root page (tech fingerprint + notable headers)
    try {
      guard.assertAllowed(`https://${asset.host}/`);
      const r = await guardedGet(wire, guard, `https://${asset.host}/`, C, requests);
      rec.requests += 1;
      rec.status = r.status;
      for (const h of NOTABLE_HEADERS) if (r.headers[h]) rec.headers[h] = String(r.headers[h]).slice(0, 120);
      rec.techs = detectOnPage({ headers: r.headers, body: r.body })
        .map((t) => ({ id: t.id, label: t.label, version: t.version || null, evidence: t.evidence }));
      counts.techsFound += rec.techs.length;
    } catch (e) {
      rec.error = `${(e && e.code) || 'gather-error'}: ${String((e && e.message) || e).slice(0, 160)}`;
      counts.errors += 1;
    }
    counts.requestsMade = requests.count;
    counts.assetsProbed += 1;
    note({ state: 'asset', asset: asset.host, status: rec.status, msg: `${asset.host}: HTTP ${rec.status || 'ERR'} — ${rec.techs.length} tech(s)${rec.error ? ' — ' + rec.error : ''}` });
    if (Date.now() > deadline) { bundle.assets.push(rec); break; }
    await sleep(C.delayMs);

    // request 2: robots.txt (a PASSIVE, universally-allowed path with real signal)
    if (rec.status && requests.count < requests.cap) {
      try {
        guard.assertAllowed(`https://${asset.host}/robots.txt`);
        const r = await guardedGet(wire, guard, `https://${asset.host}/robots.txt`, C, requests);
        rec.requests += 1;
        if (r.status === 200 && r.body) {
          const paths = [...new Set([...r.body.matchAll(/^\s*(?:Disallow|Allow):\s*(\/[^\s#]*)/gim)].map((m) => m[1]))];
          const scoped = paths.filter((p) => guard.allow(`https://${asset.host}${p}`)); // passive harvest is scope-filtered too
          rec.endpoints.push(...scoped.filter((p) => ROBOTS_INTERESTING.test(p)).slice(0, C.maxEndpointsPerAsset).map((p) => ({ path: p, source: 'robots.txt' })));
        }
      } catch (e) {
        counts.errors += 1;
        rec.error = [rec.error, `${(e && e.code) || 'gather-error'}: ${String((e && e.message) || e).slice(0, 120)}`].filter(Boolean).join(' | ');
      }
      counts.requestsMade = requests.count;
    }
    bundle.assets.push(rec);
    await sleep(C.delayMs);
  }
  counts.endpointsFound = bundle.assets.reduce((n, a) => n + a.endpoints.length, 0);

  // The persisted bundle (capped) + the brain-facing summary (capped separately).
  let bundlePath = null;
  if (dir) {
    bundlePath = join(dir, 'evidence', 'gather', `${intake?.program?.handle || 'unknown'}-${String(Date.now())}.json`);
    let text = JSON.stringify(bundle, null, 1);
    while (text.length > C.maxBundleKB * 1024 && bundle.assets.length) {
      bundle.assets.pop(); // the cap is structural — the bundle can never grow unbounded
      text = JSON.stringify(bundle, null, 1);
      bundle.truncated = 'oldest assets dropped to fit the bundle cap';
    }
    mkdirSync(dirname(bundlePath), { recursive: true });
    writeFileSync(bundlePath, text);
  }
  const brainText = brainSummary(bundle, C);
  note({ state: 'done', msg: `gather done — ${counts.assetsProbed} asset(s) probed, ${counts.requestsMade} request(s), ${counts.techsFound} tech(s), ${counts.endpointsFound} endpoint(s), ${counts.errors} error(s)${bundlePath ? ` — bundle ${bundlePath}` : ''}` });
  return { ok: true, bundle, bundlePath, brainText, counts, guard };
}

// brainSummary(bundle, caps) — the bounded evidence text the brain judges on.
export function brainSummary(bundle, caps = CADENCE) {
  const lines = [];
  for (const a of bundle.assets || []) {
    const tech = (a.techs || []).map((t) => t.label + (t.version ? ' ' + t.version : '')).join(', ') || 'none fingerprinted';
    lines.push(`- ${a.host} [${a.kind}] HTTP ${a.status || 'ERR'} — tech: ${tech}`);
    const hs = Object.entries(a.headers || {}).map(([k, v]) => `${k}: ${v}`).join('; ');
    if (hs) lines.push(`  headers: ${hs}`);
    for (const e of (a.endpoints || [])) lines.push(`  endpoint (${e.source}): ${e.path}`);
    if (a.error) lines.push(`  error: ${a.error}`);
  }
  if (!(bundle.assets || []).length) lines.push('(no in-scope web assets could be probed — the candidate judgment runs on scope alone, and must say so)');
  let text = lines.join('\n');
  const cap = (caps.maxBrainKB || CADENCE.maxBrainKB) * 1024;
  if (text.length > cap) text = text.slice(0, cap) + '\n… (summary truncated to the 4KB cap)';
  return text;
}

// --- mechanical candidates (cvepacks: version→CVE, firm-not-confirmed) ----------------
// From the gathered fingerprint, the platform's OWN version→CVE correlation emits
// candidates in the SAME checkable contract the brain's findings use
// (title/check/expect/cleanup/verifyClean — the honesty contract). The replay check
// proves ENTAILMENT: the claimed tech+version exists in the recorded evidence. The
// evidence is INLINED into the check (≤ the bundle cap by design) so it runs on ANY
// sandbox tier — the docker tier's --network none / read-only isolation can never see
// a host path, and it never needs to.
export function mechanicalCandidates(cveMatches, { bundle } = {}) {
  const inline = JSON.stringify(JSON.stringify(bundle || { assets: [] })); // a string literal of the bundle JSON
  return (Array.isArray(cveMatches) ? cveMatches : []).map((m) => ({
    title: `${m.cve} — ${m.title}`,
    sev: m.sev || 'info',
    evidence: `${m.evidence} · ${m.note || ''} · confidence firm, not confirmed (a version match is a verification target; distro backports can carry an affected version with the fix applied)`,
    origin: 'mechanical',
    check: `const b=JSON.parse(${inline});const ok=(b.assets||[]).some(a=>(a.techs||[]).some(t=>t.id===${JSON.stringify(m.tech)}&&t.version===${JSON.stringify(m.version)}));console.log(ok?'CVE-MATCH-OK':'EVIDENCE-MISSING');`,
    expect: 'CVE-MATCH-OK',
    cleanup: `console.log('CLEANED');`,
    verifyClean: `console.log('CLEAN');`,
    cve: m.cve,
  }));
}
