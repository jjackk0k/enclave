// tools/cfride.mjs -- RIDE vaulted clearance (operator-provided or broker-minted) through the
// native web tools. cf_clearance is bound to source IP + User-Agent: every ridden request
// sends the vault's EXACT UA + cookie, paced like a human (the engagement pacer's timing
// surface is preserved; only the persona headers are pinned to the clearance binding).
//
// HONESTY GATE: a proof fetch runs FIRST and is classified by the challenge engine. If the
// zone still challenges, the ride reports clearance-failed with the evidence -- it never
// runs a challenged sweep and calls it an assessment.
//
// EGRESS PARITY GATE (2026-08-10, live-proven gap): the vault keys clearance as
// zone|egressId|sha256(ua) and cf_clearance is IP-bound, so the ride's TRANSPORT must
// match the entry's egressId -- the pre-fix default fetcher was plain global fetch
// (always DIRECT), which silently burned chain-minted entries at the edge. The default
// fetcher and the sweep tools (crawl/apisurface/vulncheck, via their `agents` seam) now
// ride the ghost chain exactly like wafbypass/lfichain do: the broker's
// resolveRideTransport maps the entry's egressId to the transport (chain-keyed => the
// armed ghost chain, canonical ids must match; 'direct' => direct, fail-closed for
// public targets under ghost 'required'; private/range => direct per ghost doctrine).
// opts.ghost / opts.ghostMode are the injectable test seams; the default reads the SAME
// Settings the mint/lookup sides read (broker.ghostRideState), so transport and vault
// key can never drift.
import http from 'node:http';
import https from 'node:https';
import { clearanceFor, resolveRideTransport, ghostRideState } from './clearance/broker.mjs';
import { isPrivateDest, scrubHeaders } from '../engine/ghost.mjs';
import { detectChallenge } from '../engine/challenge.mjs';
import { makePacer } from '../engine/stealth.mjs';
import { crawl } from './crawl.mjs';
import { apiSurface } from './apisurface.mjs';
import { vulnCheck } from './vulncheck.mjs';

const BODY_CAP = 65536;        // a challenge page is small (the cfmap/egressbench cap)
const DEFAULT_TIMEOUT = 12000; // the pre-fix fetcher's AbortSignal.timeout(12000)
const MAX_REDIRECTS = 5;       // the pre-fix fetcher ran redirect:'follow' -- keep the contract, bounded

const msg = (e) => String((e && e.message) || e);

// Default fetcher: node http(s) riding the ghost agents on a chain-keyed ride (the
// wafbypass/lfichain defaultRequester pattern), direct otherwise. Defense in depth: a
// PUBLIC target with no agents is refused IN the requester unless the gate sanctioned a
// direct ride -- a chain-bound cookie must never silently fall back to direct egress,
// whatever the gate did. Headers go through scrubHeaders with the vault's EXACT UA as
// the persona (the clearance binding must survive the scrub; VARVEL-* markers never
// ride). Resolves { status, headers, body }; network failure is DATA
// ({ status: 0, error }), never an exception.
// fullBody (the --full-body evidence-pull flag): the body is accumulated UNCAPPED.
// The challenge gate below still classifies the first BODY_CAP bytes only -- that is
// the window the classifier is calibrated on (a challenge page is small), and a full
// page can carry theme-embedded markup (e.g. a login modal's reCAPTCHA) that
// false-fires the 'captcha' kind (the ridefetch lesson, 2026-08-10).
function defaultFetcher({ agents, directPublic, hdrs, ua, method, body, timeoutMs = DEFAULT_TIMEOUT, fullBody = false }) {
  const one = (target, mth, bod, redirectsLeft) => new Promise((resolve) => {
    let u;
    try { u = new URL(String(target)); } catch { return resolve({ status: 0, error: 'unparseable request URL' }); }
    if (!isPrivateDest(u.hostname) && !agents && !directPublic) {
      return resolve({ status: 0, error: 'ghost chain unavailable -- public egress refused' });
    }
    const lib = u.protocol === 'https:' ? https : http;
    let settled = false;
    const done = (v) => { if (settled) return; settled = true; resolve(v); };
    let req;
    try {
      req = lib.request({
        hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80),
        path: u.pathname + u.search, method: mth || 'GET', timeout: timeoutMs,
        rejectUnauthorized: false,
        agent: agents ? (u.protocol === 'https:' ? agents.httpsAgent : agents.httpAgent) : undefined,
        headers: scrubHeaders(hdrs(), { ua }),
      }, (r) => {
        let text = '';
        r.on('data', (d) => {
          if (fullBody) text += d.toString('latin1');
          else if (text.length < BODY_CAP) text += d.toString('latin1', 0, Math.max(0, BODY_CAP - text.length));
        });
        r.on('end', () => {
          const status = r.statusCode || 0;
          const loc = r.headers && r.headers.location;
          // redirect:'follow' parity (bounded): 303 (and 301/302 off GET/HEAD) become
          // bodiless GETs; 307/308 keep method+body.
          if (redirectsLeft > 0 && loc && (status === 301 || status === 302 || status === 303 || status === 307 || status === 308)) {
            let next;
            try { next = new URL(loc, u).href; } catch { return done({ status, headers: r.headers, body: text }); }
            const drop = status === 303 || ((status === 301 || status === 302) && mth !== 'GET' && mth !== 'HEAD');
            one(next, drop ? 'GET' : mth, drop ? null : bod, redirectsLeft - 1).then(done);
            return;
          }
          done({ status, headers: r.headers, body: text });
        });
      });
    } catch (e) { return done({ status: 0, error: msg(e) }); }
    req.on('timeout', () => { try { req.destroy(); } catch {} done({ status: 0, error: 'request timed out (' + timeoutMs + 'ms)' }); });
    req.on('error', (e) => done({ status: 0, error: msg(e) }));
    if (bod != null) req.write(bod);
    req.end();
  });
  return (u) => one(u, method, body, MAX_REDIRECTS);
}

export async function ride(url, { tool = 'crawl', maxPages, egressId = 'direct', fetcher, method = 'GET', body, contentType, ghost, ghostMode, engagement, vaultPath, fullBody = false } = {}) {
  const c = await clearanceFor(url, { egressId, ...(vaultPath ? { vaultPath } : {}) });
  if (!c) return { ok: false, reason: 'no valid clearance in the vault for this zone -- mint (clearance mint) or provide operator clearance first' };
  const cookieHeader = (c.cookies || []).map((k) => k.name + '=' + k.value).join('; ');
  const hdrs = (accept) => {
    const h = { 'user-agent': c.ua, cookie: cookieHeader, accept: accept || 'text/html,application/xhtml+xml,*/*' };
    if (body != null) h['content-type'] = contentType || 'application/x-www-form-urlencoded';
    return h;
  };

  // EGRESS PARITY GATE: the vault entry's egressId is the binding contract -- the ride's
  // transport must match it BEFORE any request leaves (fail-closed refusals are data).
  const st = ghost ? { ghost, ghostMode: ghostMode || ghost.mode } : ghostRideState(engagement);
  let hostname = '';
  try { hostname = new URL(String(url)).hostname; } catch { /* clearanceFor above already refused unparseable URLs */ }
  const t = await resolveRideTransport({ ghost: st.ghost, ghostMode: st.ghostMode, egressId, hostname });
  if (!t.ok) return { ok: false, reason: t.reason };

  // PROOF FIRST (injectable for hermetic tests): one classified fetch before any sweep.
  const doFetch = fetcher || defaultFetcher({ agents: t.agents, directPublic: t.direct, hdrs, ua: c.ua, method, body, fullBody });
  let probe;
  try { probe = await doFetch(url); } catch (e) { probe = { status: 0, error: msg(e) }; }
  // The gate classifies the calibrated window (first BODY_CAP bytes) even when the ride
  // pulled the full body -- see the defaultFetcher note.
  const detection = detectChallenge({ status: probe.status || 0, headers: probe.headers || {}, body: (probe.body || '').slice(0, BODY_CAP) });
  if (detection.present) {
    return { ok: false, reason: 'vaulted clearance was CHALLENGED -- expired, UA mismatch (the vault UA is not what was sent), or IP drift (cf_clearance binds source IP + UA). Re-mint or refresh the operator session.', proof: { status: probe.status, detection } };
  }

  // Human-paced ride: the real pacer drives timing/back-off; headers stay pinned to the
  // clearance binding (exact UA + cookie) -- the zone sees the SAME identity it cleared.
  const base = makePacer('web-browse', {});
  const ridePacer = { ...base, requestHeaders: (opts) => hdrs(opts && opts.accept) };
  const rideMeta = { engine: c.engine || 'operator-provided', uaBound: true, expiresAt: c.expiresAt, transport: t.transport };

  // 'raw': a SINGLE proof-gated fetch (version-evidence pulls like theme style.css,
  // readme.txt, changelogs -- the reading a browser does, at ride identity). Accepts
  // method/body/contentType for POST probes (e.g. version-pinned CVE validation).
  // fullBody: the body is returned UNCAPPED for evidence pulls (default stays capped at
  // BODY_CAP); the full-body classification rides alongside the gate's when it differs,
  // so nothing is hidden (the ridefetch transparency note).
  if (tool === 'raw') {
    const result = { status: probe.status, headers: probe.headers, body: probe.body };
    if (fullBody) {
      result.bodyCapped = false;
      result.bodyBytes = (probe.body || '').length;
      const detFull = detectChallenge({ status: probe.status || 0, headers: probe.headers || {}, body: probe.body || '' });
      if (detFull.kind !== detection.kind) {
        result.fullBodyDetection = detFull;
        result.fullBodyNote = 'the UNCAPPED body classifies as "' + detFull.kind + '" vs the gate window\'s "' + detection.kind + '" -- page-embedded markup beyond the calibrated window; the gate verdict stands, reported here so nothing is hidden';
      }
    }
    return {
      ok: true,
      ride: { ...rideMeta, method },
      proof: { status: probe.status, detection },
      tool, result,
    };
  }

  // The sweep tools ride the SAME transport as the proof (their `agents` seam): a
  // chain-ridden proof followed by a direct sweep would burn the cookie one request later.
  let result;
  if (tool === 'apisurface') result = await apiSurface(url, { pacer: ridePacer, agents: t.agents });
  else if (tool === 'vulncheck') result = await vulnCheck(url, { pacer: ridePacer, agents: t.agents });
  else result = await crawl(url, { pacer: ridePacer, maxPages, agents: t.agents });

  return {
    ok: true,
    ride: { ...rideMeta, note: 'requests ride the vaulted clearance -- same egress + same UA; switching either invalidates it instantly' },
    proof: { status: probe.status, detection },
    tool, result,
  };
}
