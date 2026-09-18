// VARVEL — egressbench: the egress-reputation measurement harness (the egress side of
// the challenge story).
//
// Why it exists: the 2026 research verdict is that the single highest-leverage factor in
// Cloudflare's challenge decision is EGRESS IP REPUTATION (mobile CGNAT > residential
// >>> datacenter; Tor burned). So before an engagement we GRADE the egress options we
// actually have — by OBSERVED challenge rate against a consented target, never by
// assertion. Same doctrine as detoracle/preflight: we measure and report; a rate is
// evidence, never a capability claim and never a vendor verdict.
//
// How it works: for each egress spec, take `samples` paced probes of the same URL
// (sequential per egress — parallel bursts would poison the measurement with rate-limit
// pressure), classify EVERY response with engine/challenge.detectChallenge (the locked
// taxonomy — no second detector), and count challenge kinds. Fetch failures are counted
// as errors and EXCLUDED from the rate denominator — an unreachable proxy is not a 0%
// challenge rate, and the note says so.
//
// Egress specs: { id: 'direct' } — plain global fetch (on the operator host a SYSTEM-WIDE
// VPN tunnel carries this at the network layer; 'direct' means 'no app-level proxy') —
// or { id: '<label>', proxy: 'socks5://host:port' } (a single-hop chain through
// engine/ghost's parseChain + openTunnel — REUSED, not reimplemented: the SOCKS5 CONNECT
// handshake, RFC1929 auth, and DNS-by-last-proxy all come from ghost). The probe's wire
// identity (UA, request shape) is HELD CONSTANT across egresses: the egress is the only
// variable, which is what makes the rates comparable.
//
// THE HONESTY CONTRACT (non-negotiable): benchEgress NEVER throws — usage errors and
// probe failures come back as honest error objects/entries. The top-level honestNote is
// the locked label: "measured on zone Z at time T — per-zone variance is the norm; a
// challenge rate is a measurement, not a capability claim."

import tls from 'node:tls';
import { parseChain, openTunnel, isPrivateDest } from '../engine/ghost.mjs';
import { parseIp } from '../engine/ipaddr.mjs';
import { detectChallenge } from '../engine/challenge.mjs';

const BODY_CAP = 65536; // read at most 64KB of a body — a challenge page is small (preflight's cap)

// The probe's wire identity, held constant across every egress (same persona shape as
// engine/ghost's scrubHeaders UA). The egress is the only variable.
const PROBE_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36';

// ---------- default fetchers ----------
// direct: a plain global-fetch wrapper — headers captured to a plain object, abort via
// AbortSignal.timeout. 'direct' means NO APP-LEVEL PROXY: on the operator host a
// system-wide VPN tunnel may still carry this traffic at the network layer.
function directFetcher(timeoutMs) {
  return async (url) => {
    const r = await fetch(url, {
      signal: AbortSignal.timeout(timeoutMs),
      redirect: 'manual', // a redirect IS measurement data (e.g. onto a challenge page) — never auto-follow
      headers: { 'user-agent': PROBE_UA },
    });
    const headers = {};
    r.headers.forEach((v, k) => { headers[k] = v; });
    return { status: r.status, headers, body: (await r.text()).slice(0, BODY_CAP) };
  };
}

// proxied: REUSES engine/ghost — parseChain for the URL, openTunnel for the SOCKS5/CONNECT
// handshake (DNS resolved by the proxy, never locally). Over the tunnel: TLS (servername =
// target), then a plain HTTP/1.1 GET with Connection: close — enough for a measurement
// probe. Every failure raises, and benchEgress counts it as an honest error entry.
function proxiedFetcher(proxy, timeoutMs) {
  const chain = parseChain(String(proxy)); // throws TypeError on a bad proxy URL — caught per-egress below
  if (!chain.length) throw new TypeError("egress proxy '" + proxy + "' parsed to an empty chain");
  return async (url) => {
    const u = new URL(String(url));
    // ghost doctrine: a private/range target never rides a proxy — the proxy operator
    // would learn the lab exists. Measure private targets via { id: 'direct' }.
    if (isPrivateDest(u.hostname)) throw new Error("refused: proxying a private/range target leaks lab topology to the proxy operator — measure it via { id: 'direct' }");
    return httpGetViaChain(chain, u, timeoutMs);
  };
}

// One GET through the chain tunnel, resolving { status, headers, body }. Never hangs:
// an overall timer caps the whole exchange (tunnel + TLS + response).
function httpGetViaChain(chain, u, timeoutMs) {
  return new Promise((resolve, reject) => {
    const isTls = u.protocol === 'https:';
    const host = u.hostname;
    const port = Number(u.port) || (isTls ? 443 : 80);
    let sock = null, settled = false, n = 0;
    const chunks = [];
    const finish = (fn, v) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { sock && sock.destroy(); } catch {}
      fn(v);
    };
    const timer = setTimeout(() => finish(reject, new Error('proxied probe timed out (' + timeoutMs + 'ms)')), timeoutMs);
    openTunnel(chain, host, port, timeoutMs).then((raw) => {
      // no ALPN offered: the server stays on HTTP/1.1, which is all this probe speaks
      // SNI is a NAME field: never an IP literal — u.hostname keeps v6 brackets, and
      // net.isIP misses the bracketed form, so the strict parser decides instead.
      sock = isTls ? tls.connect({ socket: raw, servername: parseIp(host) ? undefined : host }) : raw;
      sock.on('data', (d) => { if (n < BODY_CAP * 4) { chunks.push(d); n += d.length; } });
      sock.once('error', (e) => finish(reject, e));
      sock.once('close', () => {
        try { finish(resolve, parseHttpResponse(Buffer.concat(chunks))); } catch (e) { finish(reject, e); }
      });
      try {
        sock.write(
          'GET ' + (u.pathname + u.search) + ' HTTP/1.1\r\n'
          + 'Host: ' + host + (u.port ? ':' + port : '') + '\r\n'
          + 'User-Agent: ' + PROBE_UA + '\r\n'
          + 'Accept: text/html,application/xhtml+xml,*/*\r\n'
          + 'Connection: close\r\n\r\n'
        );
      } catch (e) { finish(reject, e); }
    }, (e) => finish(reject, e));
  });
}

// Parse a Connection: close response: status line, headers (lowercased plain object),
// body (chunked-decoded when announced — CF interstitials are typically chunked).
function parseHttpResponse(buf) {
  const end = buf.indexOf('\r\n\r\n');
  const head = (end >= 0 ? buf.subarray(0, end) : buf).toString('latin1');
  let body = end >= 0 ? buf.subarray(end + 4) : Buffer.alloc(0);
  const lines = head.split('\r\n');
  const m = /^HTTP\/\d\.\d (\d{3})/.exec(lines[0] || '');
  if (!m) throw new Error('unparseable HTTP response head');
  const headers = {};
  for (const line of lines.slice(1)) {
    const i = line.indexOf(':');
    if (i > 0) headers[line.slice(0, i).trim().toLowerCase()] = line.slice(i + 1).trim();
  }
  if (/chunked/i.test(headers['transfer-encoding'] || '')) body = dechunk(body);
  return { status: Number(m[1]), headers, body: body.subarray(0, BODY_CAP).toString('latin1') };
}

// Minimal RFC 9112 chunk decoder — stops cleanly at the terminal 0-chunk or any damage.
function dechunk(buf) {
  const out = [];
  let i = 0;
  while (i + 2 <= buf.length) {
    const eol = buf.indexOf('\r\n', i);
    if (eol < 0) break;
    const size = parseInt(buf.subarray(i, eol).toString('latin1'), 16);
    if (!Number.isFinite(size) || size < 0) break;
    i = eol + 2;
    if (size === 0) break;
    out.push(buf.subarray(i, i + size));
    i += size + 2; // chunk data + its trailing CRLF
  }
  return Buffer.concat(out);
}

function defaultFetcherFactory(timeoutMs) {
  return (egress) => (egress && egress.proxy ? proxiedFetcher(egress.proxy, timeoutMs) : directFetcher(timeoutMs));
}

// ---------- the bench ----------
// One egress's sample series. Errors never crash the run: they are counted, kept out of
// the rate denominator, and named in the note.
async function benchOne(target, egress, { samples, paceMs, makeFetcher }) {
  const id = String(egress.id);
  const kinds = {};
  let challenged = 0, errors = 0;
  const errorNotes = [];
  let fetcher = null;
  try {
    fetcher = makeFetcher(egress);
  } catch (e) {
    // the factory itself failed (e.g. an unparseable proxy URL): every sample is an error
    errors = samples;
    errorNotes.push(String((e && e.message) || e));
  }
  if (fetcher) {
    for (let i = 0; i < samples; i++) {
      if (i > 0 && paceMs > 0) await new Promise((r) => setTimeout(r, paceMs));
      try {
        const res = await fetcher(target);
        const det = detectChallenge({ status: res && res.status, headers: res && res.headers, body: res && res.body });
        if (det.present) { challenged++; kinds[det.kind] = (kinds[det.kind] || 0) + 1; }
      } catch (e) {
        errors++;
        if (errorNotes.length < 3) errorNotes.push(String((e && e.message) || e));
      }
    }
  }
  const denom = samples - errors; // errors are EXCLUDED from the rate denominator
  const challengeRate = denom > 0 ? Math.round((challenged / denom) * 1000) / 1000 : null;
  const kindStr = Object.entries(kinds).map(([k, c]) => `${k} ×${c}`).join(', ');
  let note;
  if (denom === 0) {
    note = `no measurable samples via ${id} — all ${samples} fetch(es) errored (${errorNotes[0] || 'unknown'}); no rate measured`;
  } else {
    note = `${challenged}/${denom} challenged${kindStr ? ' (' + kindStr + ')' : ''} via ${id}`;
    if (errors > 0) note += ` — ${errors} fetch error(s) excluded from the rate denominator (${errorNotes[0] || 'unknown'})`;
  }
  return { egress: id, samples, challenged, errors, kinds, challengeRate, note };
}

/**
 * Grade egress options by OBSERVED challenge rate against a consented target.
 * NEVER throws — usage errors return { ok:false, error } and probe failures are counted.
 *
 * @param {string} url the consented target to probe
 * @param {{egresses?:Array<{id:string, proxy?:string}>, samples?:number, paceMs?:number,
 *          fetcherFactory?:(egress)=> (url)=>Promise<{status,headers,body}>, timeoutMs?:number}} opts
 * @returns {Promise<{ok:boolean, url:string, results:Array, compared:boolean, honestNote:string, at:string}>}
 */
export async function benchEgress(url, { egresses = [{ id: 'direct' }], samples = 8, paceMs = 1500, fetcherFactory, timeoutMs = 10000 } = {}) {
  const at0 = new Date().toISOString();
  try {
    const target = String(url || '').trim();
    let u;
    try { u = new URL(target); } catch {
      return { ok: false, url: target, error: "usage: benchEgress(url, ...) needs a valid http(s) URL — got '" + target + "'", at: at0 };
    }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') {
      return { ok: false, url: target, error: "usage: only http(s) targets are probeable — got scheme '" + u.protocol + "'", at: at0 };
    }
    const list = Array.isArray(egresses) ? egresses : [];
    if (!list.length) return { ok: false, url: target, error: 'usage: at least one egress spec is required ({ id: \'direct\' } is the default)', at: at0 };
    for (const e of list) {
      if (!e || !e.id) return { ok: false, url: target, error: 'usage: every egress spec needs an id ({ id: \'direct\' } or { id: \'<label>\', proxy: \'socks5://host:port\' })', at: at0 };
    }
    const n = Math.floor(Number(samples));
    if (!Number.isInteger(n) || n < 1) return { ok: false, url: target, error: 'usage: samples must be an integer >= 1 (got ' + samples + ')', at: at0 };
    const pace = Math.max(0, Number(paceMs) || 0);
    const makeFetcher = typeof fetcherFactory === 'function' ? fetcherFactory : defaultFetcherFactory(timeoutMs);

    // Sequential per egress, paced between samples: a burst would manufacture rate-limit
    // pressure and poison the very rate being measured.
    const results = [];
    for (const egress of list) results.push(await benchOne(u.href, egress, { samples: n, paceMs: pace, makeFetcher }));

    const at = new Date().toISOString();
    return {
      ok: true,
      url: target,
      results,
      compared: results.length > 1,
      honestNote: `measured on zone ${u.hostname} at ${at} — per-zone variance is the norm; a challenge rate is a measurement, not a capability claim.`,
      at,
    };
  } catch (e) {
    return { ok: false, url: String(url || ''), error: 'egressbench failed: ' + String((e && e.message) || e), at: at0 };
  }
}
