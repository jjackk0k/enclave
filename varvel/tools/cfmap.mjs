// VARVEL — cfmap: challenge-surface mapping (the paced per-path posture map).
//
// Why it exists: on the 2026-08-05 mission-1 target every path answered a Cloudflare
// MANAGED CHALLENGE and the tooling only saw "403" — the operator's reading of
// cf-mitigated was the only signal that it was a challenge, not a block. cfmap walks a
// small set of well-known paths, ONE PACED REQUEST AT A TIME, and classifies every
// response through engine/challenge.mjs (detectChallenge), then rolls the probes up
// with summarizeSurface: which paths are challenged, which are openly served, which
// are hard-blocked (1020), rate-limited, or honeypot-suspect.
//
// LABYRINTH GUARD (governance, non-negotiable): a 'labyrinth-suspect' detection STOPS
// the map on the spot — no further requests are emitted and links from that body are
// never followed (Cloudflare's AI Labyrinth honeypot feeds bots generated mazes;
// following them is a data-integrity and governance hazard). The stop is recorded on
// the summary as summary.stopped and stated in plain language in the note.
//
// THE HONESTY CONTRACT (same doctrine as engine/challenge.mjs, tools/preflight.mjs):
// detection is EVIDENCE classification, never a bypass claim and never a vendor
// verdict. A path served WITHOUT challenge is a posture finding (per-path rule
// carve-outs are common) — an open path is surface, not a bypass. The network paths
// NEVER throw: fetcher failures come back as { status: 0, error } and land in the
// summary's errors[] — reported, never hidden.

import { detectChallenge, summarizeSurface } from '../engine/challenge.mjs';

export const DEFAULT_PATHS = ['/', '/api', '/api/health', '/robots.txt', '/sitemap.xml', '/.well-known/security.txt', '/feed', '/wp-json/', '/graphql'];

const DEFAULT_TIMEOUT = 10000; // per-request cap for the default fetcher
const DEFAULT_PACE = 1200;     // ms between request starts — managed-challenge targets rate-limit the impatient
const BODY_CAP = 256 * 1024;   // challenge markers live at the top of the body; never hold more than 256KB

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// The default fetcher: one real GET with a hard timeout, headers captured into a plain
// object (engine/challenge accepts Headers instances too, but plain objects diff and
// log better). Injected fetchers only need `async (url) => ({ status, headers, body })`.
async function defaultFetcher(url, timeoutMs) {
  const r = await fetch(url, {
    signal: AbortSignal.timeout(timeoutMs),
    redirect: 'follow',
    headers: { 'user-agent': 'VARVEL-cfmap', accept: '*/*' },
  });
  const headers = {};
  r.headers.forEach((v, k) => { headers[k] = v; });
  const text = await r.text();
  return { status: r.status, headers, body: text.length > BODY_CAP ? text.slice(0, BODY_CAP) : text };
}

// checkUrl(url) -> { url, status, detection, fetchedAt, error? }. NEVER throws:
// a fetcher failure is data, not an exception — it resolves { status: 0, error }.
export async function checkUrl(url, { fetcher, timeoutMs = DEFAULT_TIMEOUT } = {}) {
  const fetchImpl = fetcher || defaultFetcher;
  try {
    const r = await fetchImpl(String(url), timeoutMs);
    const status = Number(r && r.status) || 0;
    const detection = detectChallenge({ status, headers: (r && r.headers) || {}, body: (r && r.body) || '' });
    return { url: String(url), status, detection, fetchedAt: new Date().toISOString() };
  } catch (e) {
    const error = (e && (e.name === 'TimeoutError' || e.name === 'AbortError'))
      ? 'request timed out (' + timeoutMs + 'ms)'
      : String((e && e.message) || e);
    return { url: String(url), status: 0, detection: detectChallenge({}), fetchedAt: new Date().toISOString(), error };
  }
}

// mapSurface(baseUrl, ...) -> { baseUrl, probes, summary, pace: { paceMs }, note }.
// Probes run SEQUENTIALLY, paceMs apart measured request-start to request-start. Bad
// usage (a non-http(s) baseUrl) is a TypeError — network failure never is.
export async function mapSurface(baseUrl, { paths, paceMs = DEFAULT_PACE, fetcher, timeoutMs } = {}) {
  let origin;
  try {
    const u = new URL(String(baseUrl));
    if (!/^https?:$/.test(u.protocol)) throw new Error('proto');
    origin = u.origin;
  } catch {
    throw new TypeError('cfmap.mapSurface: baseUrl must be an http(s) URL, got ' + JSON.stringify(baseUrl));
  }
  const list = (Array.isArray(paths) && paths.length ? paths : DEFAULT_PATHS).map(String);
  const fetchImpl = fetcher || defaultFetcher;
  const pace = Math.max(0, Number(paceMs) || 0);

  const probes = [];
  let stoppedAt = null;
  let lastStart = 0;
  for (const path of list) {
    let url = null;
    try { url = new URL(path, origin); } catch { /* unparseable path */ }
    if (!url || url.origin !== origin) {
      // Scope guard (same doctrine as tools/apisurface.mjs): a '//other-host' path can
      // never pull the map off-origin. The refusal is data — an honest errors entry.
      probes.push({
        path, url: url ? url.href : null, status: 0,
        detection: detectChallenge({}), fetchedAt: new Date().toISOString(),
        error: 'off-origin path refused — same-origin scope (' + (url ? url.origin : 'unparseable path') + ')',
      });
      continue;
    }
    const wait = lastStart ? pace - (Date.now() - lastStart) : 0;
    if (wait > 0) await sleep(wait);
    lastStart = Date.now();
    const probe = { path, ...(await checkUrl(url.href, { fetcher: fetchImpl, timeoutMs })) };
    probes.push(probe);
    // LABYRINTH GUARD: stop the map on the spot — nothing further is requested.
    if (probe.detection && probe.detection.kind === 'labyrinth-suspect') { stoppedAt = path; break; }
  }

  const summary = summarizeSurface(probes);
  let note = 'paced per-path posture map (' + pace + 'ms between request starts); detection is evidence classification, never a bypass claim — an open path is surface, not a bypass';
  if (stoppedAt) {
    const stop = 'STOPPED at ' + stoppedAt + ': labyrinth-suspect detected — links from that body were NOT followed (Cloudflare AI Labyrinth honeypot feeds bots generated mazes; data-integrity + governance hazard)';
    summary.stopped = 'labyrinth-suspect';
    summary.note = stop + '. Partial map — ' + summary.note;
    note = stop;
  }
  return { baseUrl: origin, probes, summary, pace: { paceMs: pace }, note };
}
