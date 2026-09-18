// VARVEL -- preflight: the defender-view infrastructure pre-flight (the live side).
//
// Why it exists (gap#8): before an engagement, scan our OWN listeners exactly the way
// internet-wide defenders (Censys/Shodan) see them and report the exposure honestly.
// engine/selfview.mjs holds the pure classifier + the JARM prober bytes/hash; this file
// is the I/O shell: per TLS port it runs probeJa4s (REUSED from tools/fporacle.mjs),
// analyzeTls (REUSED from tools/tlsscan.mjs), and the 10 JARM handshakes; per HTTP port
// it reads GET / plus one bogus path for banners and body markers; it classifies egress
// via the FREE ipinfo.io feed and CT-log likelihood from the cert issuer alone.
//
// THE HONESTY CONTRACT (non-negotiable): NEVER throws on live paths -- every probe
// resolves { ok:false, error } on failure and the gap is REPORTED in honestGaps, never
// hidden. What could not be checked is said plainly (paid classification feeds are not
// covered; crt.sh is not queried -- CT indexing is inferred from the issuer, not
// verified). Measurement only; no evasion internals, ever.

import http from 'node:http';
import net from 'node:net';
import { probeJa4s } from './fporacle.mjs';
import { analyzeTls } from './tlsscan.mjs';
import { viewFindings, jarmProbes, readJarmResponse, jarmDigest, ctLogClass, TOOLSET_RE } from '../engine/selfview.mjs';

const DEFAULT_TIMEOUT = 2500;
const EGRESS_TIMEOUT = 3000;
const BODY_CAP = 65536; // read at most 64KB of a body when hunting markers
const BOGUS_PATH = '/varvel-preflight-bogus-404'; // one bogus path: error pages leak stacks

// One JARM handshake: send the crafted ClientHello, resolve the first full TLS record
// back (or null). jarm.py reads a single recv; we wait for the full first record, which
// is the same bytes on any real stack -- the hash inputs all live in that record.
function jarmExchange(host, port, packet, timeout) {
  return new Promise((resolve) => {
    let done = false, buf = Buffer.alloc(0);
    let sock;
    const finish = (b) => { if (!done) { done = true; try { sock.destroy(); } catch {} resolve(b); } };
    try { sock = net.connect({ host, port }); } catch { return resolve(null); }
    sock.setTimeout(timeout);
    sock.once('connect', () => { try { sock.write(packet); } catch { finish(null); } });
    sock.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      if (buf.length < 5 || buf.length < 5 + buf.readUInt16BE(3)) return; // full first record
      finish(buf);
    });
    sock.on('timeout', () => finish(null));
    sock.on('error', () => finish(null));
    sock.on('close', () => finish(buf.length ? buf : null)); // an alert arrives complete, then closes
  });
}

// One bare TCP connect: is the port open at all? A SYN-scanner's view. Never throws.
function tcpOpen(host, port, timeout) {
  return new Promise((resolve) => {
    let sock;
    const finish = (v) => { try { sock && sock.destroy(); } catch {} resolve(v); };
    try { sock = net.connect({ host, port }); } catch { return resolve(false); }
    sock.setTimeout(timeout);
    sock.once('connect', () => finish(true));
    sock.on('timeout', () => finish(false));
    sock.on('error', () => finish(false));
  });
}

// runJarm(host, port): the 10 handshakes + the 62-char digest. Never throws.
export async function runJarm(host, port, { timeout = DEFAULT_TIMEOUT } = {}) {
  try {
    const p = Number(port);
    if (!host || !Number.isInteger(p) || p <= 0 || p > 65535) return { ok: false, error: 'runJarm needs a host and a valid port' };
    const probes = jarmProbes(host);
    if (!probes.length) return { ok: false, error: 'no probes built (bad host)' };
    const results = [];
    for (const probe of probes) results.push(readJarmResponse(await jarmExchange(String(host), p, probe.packet, timeout)));
    return { ok: true, hash: jarmDigest(results), answered: results.filter((r) => r !== '|||').length };
  } catch (e) { return { ok: false, error: String((e && e.message) || e) }; }
}

// One GET, never throws: { ok, status, headers, body } or { ok:false }.
function httpGetOnce(host, port, path, timeout) {
  return new Promise((resolve) => {
    let req;
    try {
      req = http.request({ host, port, path, method: 'GET', timeout, agent: false }, (res) => {
        const chunks = [];
        let n = 0;
        res.on('data', (c) => { if (n < BODY_CAP) { chunks.push(c); n += c.length; } });
        res.on('end', () => resolve({ ok: true, status: res.statusCode, headers: res.headers || {}, body: Buffer.concat(chunks).subarray(0, BODY_CAP).toString('latin1') }));
        res.on('error', () => resolve({ ok: false }));
      });
      req.on('timeout', () => { try { req.destroy(); } catch {} resolve({ ok: false }); });
      req.on('error', () => resolve({ ok: false }));
      req.end();
    } catch { resolve({ ok: false }); }
  });
}

// Toolset markers present in a body (the actual matched strings, deduped, capped).
function bodyMarkers(body) {
  const re = new RegExp(TOOLSET_RE.source, 'gi');
  const out = [];
  for (const m of String(body || '').matchAll(re)) {
    const s = m[0].toLowerCase();
    if (!out.includes(s)) out.push(s);
    if (out.length >= 8) break;
  }
  return out;
}

// HTTP observation for one port: GET / plus one bogus path, merged. null when unanswered.
async function httpProbe(host, port, timeout) {
  const root = await httpGetOnce(host, port, '/', timeout);
  if (!root.ok) return null;
  const bogus = await httpGetOnce(host, port, BOGUS_PATH, timeout);
  const headerNames = new Set(Object.keys(root.headers));
  if (bogus.ok) for (const k of Object.keys(bogus.headers)) headerNames.add(k);
  return {
    port,
    status: root.status,
    serverHeader: root.headers.server || null,
    headers: [...headerNames],
    bodyMarkers: bodyMarkers(root.body + '\n' + (bogus.ok ? bogus.body : '')),
    bogusStatus: bogus.ok ? bogus.status : null,
  };
}

// Free egress classification (ipinfo.io, 3s cap). Never throws; offline -> ok:false.
async function egressClassify() {
  try {
    const ctl = new AbortController();
    const t = setTimeout(() => { try { ctl.abort(); } catch {} }, EGRESS_TIMEOUT);
    const r = await fetch('https://ipinfo.io/json', { signal: ctl.signal });
    clearTimeout(t);
    if (!r.ok) return { ok: false, error: 'ipinfo.io answered HTTP ' + r.status };
    const j = await r.json();
    const org = String(j.org || '');
    const m = /^(AS\d+)/.exec(org);
    return { ok: true, ip: j.ip || null, org, asn: m ? m[1] : null };
  } catch (e) {
    return { ok: false, error: (e && e.name === 'AbortError') ? 'ipinfo.io timed out (' + EGRESS_TIMEOUT + 'ms)' : String((e && e.message) || e) };
  }
}

// scanSelf({ host, ports, timeout }) -> the observations viewFindings consumes, plus a
// gaps[] ledger of everything that could not be observed. Port classification is
// measured, not assumed: a TLS ServerHello answer makes it a TLS port, an HTTP answer
// makes it an HTTP port, neither is reported as an unobserved gap. NEVER throws.
export async function scanSelf({ host = '127.0.0.1', ports = [], timeout = DEFAULT_TIMEOUT } = {}) {
  try {
    host = String(host || '').trim();
    const list = [...new Set((Array.isArray(ports) ? ports : []).map(Number).filter((p) => Number.isInteger(p) && p > 0 && p <= 65535))];
    if (!host || !list.length) return { ok: false, error: 'scanSelf needs a host and at least one valid port' };
    const gaps = [];
    const observations = { tls: [], http: [], egress: null, ctLog: 'unknown', openPorts: [], gaps };

    for (const port of list) {
      const ja = await probeJa4s(host, port, { timeout });
      if (ja.ok) {
        const tlsObs = { port, ja4s: ja.ja4s, cert: null, tlsFindings: [] };
        const an = await analyzeTls(host, port, { timeout });
        if (an.ok && an.cert) {
          tlsObs.cert = {
            selfSigned: !!an.cert.selfSigned,
            cn: an.cert.subject || null,
            san: an.cert.san || null,
            issuer: an.cert.issuer || null,
            validTo: an.cert.validTo || null,
          };
          tlsObs.tlsFindings = Array.isArray(an.findings) ? an.findings : [];
        } else {
          gaps.push('port ' + port + ': cert facts not observed (' + (an.error || 'analyzeTls failed') + ') -- JA4S/JARM still measured');
        }
        const jm = await runJarm(host, port, { timeout });
        if (jm.ok) tlsObs.jarm = jm.hash;
        else gaps.push('port ' + port + ': JARM not measured (' + (jm.error || 'unknown') + ')');
        observations.tls.push(tlsObs);
        continue;
      }
      const hp = await httpProbe(host, port, timeout);
      if (hp) observations.http.push(hp);
      else if (await tcpOpen(host, port, timeout)) {
        // TCP-open but protocol-silent to us (scope-gated, filtered, or an unidentified
        // protocol): a SYN scan still sees the listener -- report it, do not call it closed.
        observations.openPorts.push(port);
        gaps.push('port ' + port + ': TCP-open but answered neither TLS nor HTTP from this source (scope-gated or unidentified protocol); a SYN scan still sees it open');
      } else {
        gaps.push('port ' + port + ': no response -- closed or filtered from this source (nothing listening here as seen from ' + host + ')');
      }
    }

    // CT-log likelihood from the observed cert issuers (classification, not a crt.sh query).
    const classes = observations.tls.map((t) => ctLogClass(t.cert));
    observations.ctLog = classes.includes('likely-indexed') ? 'likely-indexed' : (classes.includes('not-indexed') ? 'not-indexed' : 'unknown');

    const eg = await egressClassify();
    if (eg.ok) observations.egress = { ip: eg.ip, org: eg.org, asn: eg.asn };
    else gaps.push('egress classification unavailable (' + eg.error + ') -- unobserved is NOT clean; it is unknown');

    return { ok: true, ...observations };
  } catch (e) { return { ok: false, error: String((e && e.message) || e) }; }
}

// report({ host, ports }) -> { findings, jarm: { port: hash }, observations, honestGaps }.
// The honest gaps ALWAYS carry the two standing caveats (paid feeds uncovered, crt.sh
// not queried) plus every per-probe failure from the scan. Never throws.
export async function report({ host = '127.0.0.1', ports = [], timeout = DEFAULT_TIMEOUT } = {}) {
  try {
    const obs = await scanSelf({ host, ports, timeout });
    if (!obs.ok) return obs;
    const findings = viewFindings(obs);
    const jarm = {};
    for (const t of obs.tls) if (t.jarm) jarm[t.port] = t.jarm;
    const honestGaps = [
      ...obs.gaps,
      'paid proxy/VPN classification feeds are NOT covered -- the egress class above is the free ipinfo.io tier only',
      'CT-log indexing is classified from the cert issuer only -- crt.sh was NOT queried, so indexing is inferred, never verified',
    ];
    return {
      ok: true,
      host: String(host || '127.0.0.1'),
      ports: [...new Set((Array.isArray(ports) ? ports : []).map(Number))],
      at: new Date().toISOString(),
      findings,
      jarm,
      observations: { tls: obs.tls, http: obs.http, egress: obs.egress, ctLog: obs.ctLog, openPorts: obs.openPorts },
      honestGaps,
    };
  } catch (e) { return { ok: false, error: String((e && e.message) || e) }; }
}
