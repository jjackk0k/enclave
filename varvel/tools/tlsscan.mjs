// VARVEL — TLS configuration analyzer (authorized engagements).
//
// Inspects a TLS endpoint and flags real misconfigurations: weak protocol support
// (TLS 1.0/1.1), weak ciphers (RC4/3DES/NULL/EXPORT/anon), untrusted / expired /
// not-yet-valid / self-signed / no-SAN / hostname-mismatch / overly-broad-wildcard
// certificates. It uses Node's own trust verdict (`authorized`/`authorizationError`)
// rather than re-deriving a weaker subset by hand. `tlsFindings` is a pure,
// deterministic classifier (unit-tested); `analyzeTls` does the live handshakes and
// never throws (returns `{ok:false}` on any error, incl. unsupported protocol probes).
//
// Boundary: inspection only. No downgrade attacks, no cert forgery.

import tls from 'node:tls';
import net from 'node:net';
import { parseIp } from '../engine/ipaddr.mjs';

const DAY = 86400000;
const SEV_RANK = { crit: 0, high: 1, med: 2, low: 3, info: 4 };
const WEAK_CIPHER = /RC4|_DES_|3DES|DES-CBC|NULL|EXPORT|_anon_|\bADH\b|AECDH|\bMD5\b/i;
// net.isIP alone misses the BRACKETED v6 form ('[fd00::1]'); the shared strict parser
// strips brackets and zones, and rejects garbage a bare isIP would wave through.
const isIP = (s) => net.isIP(String(s)) !== 0 || parseIp(s) !== null;
const parseDate = (s) => { const t = Date.parse(s); return Number.isNaN(t) ? null : t; };

// Does a SAN list cover `host`? Handles DNS + IP SANs, wildcards, trailing dots, case.
// IP entries compare CANONICALLY (engine/ipaddr): a v6 cert SAN in expanded form
// ('IP Address:0:0:0:0:0:0:0:1') covers '::1', and '[::1]' is the same literal.
function sanCovers(san, host) {
  const h = String(host).replace(/\.$/, '').toLowerCase();
  const hp = parseIp(h);
  const names = String(san || '').split(',').map((s) => s.trim().replace(/^(DNS|IP Address|IP):/i, '').replace(/\.$/, '').toLowerCase()).filter(Boolean);
  return names.some((n) => {
    if (n === h) return true;
    if (hp) { const np = parseIp(n); if (np) return np.text === hp.text; }
    return n.startsWith('*.') && h.endsWith(n.slice(1)) && h.split('.').length === n.split('.').length;
  });
}
function wildcardTooBroad(san) {
  return String(san || '').split(',').map((s) => s.trim().replace(/^DNS:/i, '')).some((n) => n.startsWith('*.') && n.slice(2).split('.').filter(Boolean).length <= 2);
}

// Pure classifier: TLS state -> findings (severity-ordered, deduped). Deterministic.
export function tlsFindings({ protocol, cipher, cert, weakProtocols = [], hostname = null, authorized, authorizationError, now = Date.now() } = {}) {
  const f = [];
  const add = (sev, title, ref) => f.push({ sev, title, ref });

  if (weakProtocols.length) add('high', 'weak TLS protocol supported: ' + weakProtocols.join(', '), 'TLS-PROTO');
  if (cipher && WEAK_CIPHER.test(cipher)) add('high', 'weak cipher negotiated: ' + cipher, 'TLS-CIPHER');

  const authErr = authorizationError ? String(authorizationError) : '';
  if (authorized === false && authErr) {
    if (/EXPIRED/.test(authErr)) add('high', 'certificate chain expired (' + authErr + ')', 'TLS-EXPIRED');
    else if (/SELF_SIGNED/.test(authErr)) add('med', 'self-signed certificate (' + authErr + ')', 'TLS-SELFSIGNED');
    else if (/ALTNAME/.test(authErr)) add('med', 'certificate hostname mismatch (' + authErr + ')', 'TLS-HOSTNAME');
    else add('med', 'certificate not trusted (' + authErr + ')', 'TLS-UNTRUSTED');
  } else if (cert && cert.selfSigned) {
    add('med', 'self-signed certificate', 'TLS-SELFSIGNED');
  }

  if (cert) {
    if (cert.validTo != null) {
      const exp = parseDate(cert.validTo);
      if (exp == null) add('low', 'certificate expiry date unparseable', 'TLS-BADDATE');
      else {
        const ms = exp - now;
        if (ms < 0) add('high', `expired certificate (${Math.ceil(-ms / DAY)}d ago)`, 'TLS-EXPIRED');
        else {
          const days = Math.ceil(ms / DAY);
          if (days <= 7) add('med', `certificate expiring imminently (${days}d)`, 'TLS-EXPIRING');
          else if (days <= 30) add('low', `certificate expiring soon (${days}d)`, 'TLS-EXPIRING');
        }
      }
    }
    if (cert.validFrom != null) {
      const from = parseDate(cert.validFrom);
      if (from != null && now < from) add('med', 'certificate not yet valid', 'TLS-NOTYETVALID');
    }
    if (hostname && !(authorized === false && /ALTNAME/.test(authErr))) {
      const hIsIP = isIP(hostname);
      const sanHasIP = /(^|,)\s*IP( Address)?:/i.test(cert.san || '');
      if (!cert.san) { if (!hIsIP) add('med', 'certificate has no SubjectAltName', 'TLS-NOSAN'); }
      else if (hIsIP && !sanHasIP) { /* accessed by IP, cert carries only DNS SANs -> uninformative */ }
      else if (!sanCovers(cert.san, hostname)) add('med', 'certificate hostname mismatch', 'TLS-HOSTNAME');
    }
    if (cert.san && wildcardTooBroad(cert.san)) add('med', 'overly broad wildcard certificate', 'TLS-WILDCARD-BROAD');
  }

  const seen = new Set();
  return f.sort((a, b) => (SEV_RANK[a.sev] ?? 9) - (SEV_RANK[b.sev] ?? 9)).filter((x) => (seen.has(x.ref) ? false : (seen.add(x.ref), true)));
}

// Never throws: a bad port, missing arg, or an unsupported protocol probe resolves
// to {ok:false} rather than rejecting.
function tlsConnect(host, port, { timeout = 2000, minVersion, maxVersion } = {}) {
  return new Promise((resolve) => {
    let settled = false;
    const done = (v) => { if (settled) return; settled = true; resolve(v); };
    try {
      const sock = tls.connect({ host, port, servername: isIP(host) ? undefined : host, rejectUnauthorized: false, timeout, minVersion, maxVersion }, () => {
        const c = sock.getPeerCertificate();
        const cert = c && Object.keys(c).length ? {
          subject: c.subject && (c.subject.CN || Object.values(c.subject)[0]),
          issuer: c.issuer && (c.issuer.CN || c.issuer.O),
          san: c.subjectaltname, validTo: c.valid_to, validFrom: c.valid_from,
          selfSigned: !!(c.issuer && c.subject && JSON.stringify(c.issuer) === JSON.stringify(c.subject)),
        } : null;
        const out = { ok: true, protocol: sock.getProtocol(), cipher: (sock.getCipher() || {}).name, cert, authorized: sock.authorized, authorizationError: sock.authorizationError && String(sock.authorizationError.code || sock.authorizationError) };
        try { sock.end(); } catch {}
        done(out);
      });
      sock.once('timeout', () => { try { sock.destroy(); } catch {} done({ ok: false, error: 'timeout' }); });
      sock.once('error', (e) => done({ ok: false, error: (e && e.code) || 'error' }));
    } catch (e) {
      done({ ok: false, error: (e && e.code) || 'error' }); // tls.connect throws synchronously on bad options
    }
  });
}

export async function analyzeTls(host, port, { timeout = 2000, now = Date.now() } = {}) {
  const main = await tlsConnect(host, port, { timeout });
  if (!main.ok) return { ok: false, error: main.error };
  const weakProtocols = [];
  for (const [ver, label] of [['TLSv1.1', 'TLS 1.1'], ['TLSv1', 'TLS 1.0']]) {
    const r = await tlsConnect(host, port, { timeout, minVersion: ver, maxVersion: ver });
    if (r.ok) weakProtocols.push(label);
  }
  const findings = tlsFindings({ protocol: main.protocol, cipher: main.cipher, cert: main.cert, weakProtocols, hostname: host, authorized: main.authorized, authorizationError: main.authorizationError, now });
  return { ok: true, protocol: main.protocol, cipher: main.cipher, cert: main.cert, authorized: main.authorized, weakProtocols, findings };
}
