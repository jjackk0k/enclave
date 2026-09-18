// VARVEL — tlsinspect probe (the live I/O shell for engine/tlsinspect.mjs).
//
// Handshakes a REFERENCE SET (our own listener + operator-configurable well-known SaaS
// domains — settings key tlsinspect.refs) and classifies each observed chain with the
// pure engine classifier, then aggregates an egress POSTURE ('tls-inspected' | 'clean' |
// 'partial' | 'unknown'). Ghost doctrine applies exactly like verify()/exitCheck(): when
// ghost is armed, every PUBLIC reference rides the armed proxy chain (the dial is
// injected by engine/ghost.mjs); private references (our own listener — the lab) always
// dial direct. When ghost is off, everything dials direct and the posture describes the
// operator's DIRECT egress — the path the enterprise bump actually sits on.
//
// We handshake with rejectUnauthorized:false ON PURPOSE: the bump chain must be OBSERVED,
// not refused before we can read it — Node still reports its chain-policy verdict via
// sock.authorized / sock.authorizationError, which the classifier consumes as evidence.
// Never throws: any handshake failure lands as { ok:false, error } and feeds posture
// 'unknown' math, never a crash.

import tls from 'node:tls';
import net from 'node:net';
import { classifyHandshake, aggregatePosture } from '../engine/tlsinspect.mjs';
import { isPrivateDest } from '../engine/ghost.mjs';

const DEFAULT_TIMEOUT = 4000;

// Parse the reference list: 'host' / 'host:port' / 'https://host' entries, comma-separated
// string or array; explicit { host, port?, saas? } objects win. saas defaults to "public
// destination" (private refs — our own listener — never count toward posture).
export function parseRefs(input) {
  const items = Array.isArray(input) ? input : String(input || '').split(',');
  const out = [];
  for (const raw of items) {
    if (raw && typeof raw === 'object') {
      const host = String(raw.host || '').trim();
      if (!host) continue;
      const port = Number(raw.port) || 443;
      out.push({ host, port, saas: raw.saas !== undefined ? raw.saas === true : !isPrivateDest(host), ref: host + ':' + port, ca: raw.ca || undefined });
      continue;
    }
    let s = String(raw || '').trim();
    if (!s) continue;
    if (!/^[a-z]+:\/\//i.test(s)) s = 'tls://' + s;
    try {
      const u = new URL(s);
      const host = u.hostname.replace(/^\[|\]$/g, ''); // URL keeps v6 brackets; dials/SNI want the bare literal
      const port = Number(u.port) || 443;
      if (host) out.push({ host, port, saas: !isPrivateDest(host), ref: host + ':' + port });
    } catch { /* unparseable reference: skipped honestly (reported by absence) */ }
  }
  return out;
}

// Walk a tls socket's peer chain into classifier-ready entries. getPeerCertificate(true)
// returns the leaf with .issuerCertificate links; the loop terminates on self-reference.
function chainFromSocket(sock) {
  const chain = [];
  try {
    let c = sock.getPeerCertificate(true);
    const seen = new Set();
    while (c && Object.keys(c).length && !seen.has(c.fingerprint256 || c.fingerprint || c.raw)) {
      seen.add(c.fingerprint256 || c.fingerprint || c.raw);
      chain.push({
        subject: c.subject && (c.subject.CN || Object.values(c.subject)[0]),
        issuer: c.issuer && (c.issuer.CN || c.issuer.O || Object.values(c.issuer)[0]),
        selfSigned: !!(c.issuer && c.subject && JSON.stringify(c.issuer) === JSON.stringify(c.subject)),
      });
      c = c.issuerCertificate;
    }
  } catch { /* partial chain is still evidence */ }
  return chain;
}

// ONE live handshake -> a classifier observation. `dial` is INJECTED (hermetic tests;
// ghost supplies a chain-riding dial): async (host, port) => connected net.Socket.
// Default dial is a direct TCP connect. `ca` augments the trust store used for the
// authorized verdict (the observation SAYS which store verified it — evidence, always).
// Never throws.
export async function observeHandshake({ host, port = 443, dial, ca, timeout = DEFAULT_TIMEOUT } = {}) {
  try {
    if (!host || !(Number(port) > 0 && Number(port) < 65536)) return { ok: false, error: 'observeHandshake needs a host and a valid port' };
    const dialFn = typeof dial === 'function' ? dial : (h, p) => new Promise((resolve, reject) => {
      const s = net.connect({ host: h, port: p });
      const t = setTimeout(() => { try { s.destroy(); } catch {} reject(new Error('tcp connect timeout')); }, timeout);
      s.once('connect', () => { clearTimeout(t); resolve(s); });
      s.once('error', (e) => { clearTimeout(t); reject(e); });
    });
    return await new Promise((resolve) => {
      let done = false;
      let live = null;    // the TLS socket in flight
      let liveTcp = null; // the RAW tcp socket under it — destroyed on EVERY exit: a TLS
                          // parse error marks the TLSSocket destroyed but leaves the tcp
                          // socket open (sock.destroy() then no-ops on the transport),
                          // which would strand the server side of a failed probe forever
      const finish = (v) => { if (!done) { done = true; clearTimeout(timer); try { live && live.destroy(); } catch {} try { liveTcp && liveTcp.destroy(); } catch {} resolve(v); } };
      const timer = setTimeout(() => finish({ ok: false, error: 'timeout' }), timeout);
      if (timer.unref) timer.unref();
      Promise.resolve()
        .then(() => dialFn(String(host), Number(port)))
        .then((tcp) => new Promise((res) => {
          live = tcp; liveTcp = tcp;
          const sock = tls.connect({ socket: tcp, servername: net.isIP(host) ? undefined : String(host), rejectUnauthorized: false, ...(ca ? { ca } : {}) }, () => res(sock));
          live = sock;
          sock.once('error', () => res(sock)); // handshake failure: the socket still carries facts when it can
        }))
        .then((sock) => {
          if (!sock || sock.destroyed || !sock.getPeerCertificate) return finish({ ok: false, error: 'handshake failed (no TLS session)' });
          const chain = chainFromSocket(sock);
          const authorized = sock.authorized === true;
          const authorizationError = sock.authorizationError ? String(sock.authorizationError.code || sock.authorizationError) : null;
          const protocol = (() => { try { return sock.getProtocol(); } catch { return null; } })();
          if (!chain.length && !authorizationError) return finish({ ok: false, error: 'no peer certificate presented' });
          finish({ ok: true, chain, authorized, authorizationError, protocol });
        })
        .catch((e) => { finish({ ok: false, error: String((e && (e.code || e.message)) || e) }); });
    });
  } catch (e) {
    return { ok: false, error: String((e && (e.code || e.message)) || e) };
  }
}

// THE PROBE: handshake every reference, classify each, aggregate the posture.
// { refs, dial, timeout } -> { ok, posture, reason, refs: [...], at }. Never throws.
export async function probeTlsInspection({ refs, dial, timeout = DEFAULT_TIMEOUT, now, ca } = {}) {
  const parsed = parseRefs(refs);
  const results = await Promise.all(parsed.map(async (r) => {
    const obs = await observeHandshake({ host: r.host, port: r.port, dial, timeout, ca: r.ca || ca });
    if (!obs.ok) return { ref: r.ref, host: r.host, port: r.port, saas: r.saas, ok: false, verdict: 'unknown', error: obs.error };
    const c = classifyHandshake({ host: r.host, expect: r.saas ? 'saas' : 'any', chain: obs.chain, authorized: obs.authorized, authorizationError: obs.authorizationError });
    return { ref: r.ref, host: r.host, port: r.port, saas: r.saas, ok: true, verdict: c.verdict, evidence: c.evidence, summary: c.summary, protocol: obs.protocol || null };
  }));
  const agg = aggregatePosture(results);
  return {
    ok: true,
    posture: agg.posture,
    reason: agg.reason,
    refs: results,
    at: new Date(Number.isFinite(Number(now)) ? Number(now) : Date.now()).toISOString(),
  };
}

// Agent-side minimal leg (agents/sim-agent.mjs --tlsi): classify the agent's OWN channel
// handshake and report the verdict upstream as check-in metadata. A SIDEBAND observation
// of the same egress path (undici's fetch socket is not introspectable) — honest, and
// sufficient: the bump re-issues EVERY TLS handshake on the path. http URLs have no TLS
// surface: null (nothing to report), never a fabricated verdict.
export async function classifyUrlHandshake(url, { timeout = DEFAULT_TIMEOUT, dial } = {}) {
  try {
    const u = new URL(String(url || ''));
    if (u.protocol !== 'https:') return null;
    const port = Number(u.port) || 443;
    const host = u.hostname.replace(/^\[|\]$/g, ''); // URL keeps v6 brackets; dials/SNI want the bare literal
    const obs = await observeHandshake({ host, port, dial, timeout });
    if (!obs.ok) return { verdict: 'unknown', evidence: ['handshake failed: ' + obs.error] };
    return classifyHandshake({ host, expect: 'any', chain: obs.chain, authorized: obs.authorized, authorizationError: obs.authorizationError });
  } catch {
    return null; // unparseable url — nothing to say
  }
}
