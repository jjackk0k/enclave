// VARVEL — recon tool (authorized engagements).
//
// A real, dependency-free TCP-connect scanner + fingerprinter. LENIENT like
// RedAmon's recon: it scans what it is pointed at (the ENCLAVE governs scope).
// `ipInScope` is exported as a utility the enclave/campaign can use; the tool
// itself never refuses.
//
// Capabilities beyond RedAmon's native pipeline: TLS certificate inspection and a
// Shodan-compatible mmh3 favicon hash (KAT-verified), plus security-header +
// service/version detection. Connect scans only (no SYN-flood/masscan flooding).
//
// Correctness hardening (audited): open-port detection latches on TCP connect
// (connect-then-RST and timeout<200ms no longer report a live port as closed);
// strict dual-stack IPv4/IPv6 + CIDR validation via the shared engine/ipaddr math
// (out-of-range octets, leading zeros, and malformed masks are rejected rather than
// silently matching a different subnet; v6 literals are bracketed in URL forms);
// bounded favicon + body downloads; SNI only for hostnames.
//
// Boundary: discovers + fingerprints. It does not exploit, implant, persist, or
// evade detection.

import net from 'node:net';
import tls from 'node:tls';
import http from 'node:http';
import https from 'node:https';
import { makePacer, asPacer } from '../engine/stealth.mjs';
import { pathPrefixAllowed, sanitizePathPrefixes } from '../engine/scopepath.mjs';
import { bracketHost, inAnyCidr, parseIp } from '../engine/ipaddr.mjs';

export const COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 8971, 9200, 27017];
export const TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445, 465, 587, 636, 993, 995, 1025, 1433, 1521, 1723, 2049, 2375, 2376, 3000, 3306, 3389, 5000, 5432, 5601, 5900, 5985, 5986, 6379, 6443, 7001, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 8971, 9000, 9042, 9092, 9200, 9300, 11211, 15672, 27017, 27018];
const NAMES = { 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns', 80: 'http', 110: 'pop3', 135: 'msrpc', 139: 'netbios', 143: 'imap', 443: 'https', 445: 'smb', 993: 'imaps', 995: 'pop3s', 1433: 'mssql', 1521: 'oracle', 2049: 'nfs', 3306: 'mysql', 3389: 'rdp', 5432: 'postgres', 5900: 'vnc', 6379: 'redis', 8000: 'http-alt', 8080: 'http-alt', 8443: 'https-alt', 8971: 'http-alt', 9200: 'elasticsearch', 27017: 'mongodb' };
const WEB_PORTS = new Set([80, 443, 8000, 8080, 8443, 8971, 9200]);
const TLS_PORTS = new Set([443, 8443, 993, 995]);

// CIDR membership — a UTILITY (used by the enclave/campaign for scope logic), NOT
// enforced by recon(). v4 + v6 via the shared, audited math (engine/ipaddr):
// family-strict, '0.0.0.0/0' matches every v4, '::/0' every v6.
export function ipInScope(ip, cidrs) {
  return inAnyCidr(ip, cidrs);
}

// Address compare that understands canonicalization: '[::1]' === '::1',
// '::ffff:127.0.0.1' === '127.0.0.1'. Hostnames fall back to exact match.
function sameAddress(a, b) {
  const pa = parseIp(a), pb = parseIp(b);
  return pa && pb ? pa.text === pb.text : String(a) === String(b);
}

// ---- MurmurHash3 x86_32 (Shodan-compatible favicon hashing) — KAT-verified ----
function mul32(a, b) {
  const al = a & 0xffff, ah = a >>> 16, bl = b & 0xffff, bh = b >>> 16;
  return ((al * bl) + ((((ah * bl + al * bh) & 0xffff) << 16) >>> 0)) >>> 0;
}
const rotl32 = (x, r) => ((x << r) | (x >>> (32 - r))) >>> 0;
export function mmh3_32(key, seed = 0) {
  const c1 = 0xcc9e2d51, c2 = 0x1b873593;
  let h1 = seed >>> 0;
  const len = key.length, nblocks = len >>> 2;
  for (let i = 0; i < nblocks; i++) {
    const o = i * 4;
    let k1 = (key[o] | (key[o + 1] << 8) | (key[o + 2] << 16) | (key[o + 3] << 24)) >>> 0;
    k1 = mul32(k1, c1); k1 = rotl32(k1, 15); k1 = mul32(k1, c2);
    h1 ^= k1; h1 = rotl32(h1, 13); h1 = (mul32(h1, 5) + 0xe6546b64) >>> 0;
  }
  let k1 = 0; const tail = nblocks * 4;
  switch (len & 3) {
    case 3: k1 ^= key[tail + 2] << 16; // falls through
    case 2: k1 ^= key[tail + 1] << 8;  // falls through
    case 1: k1 ^= key[tail]; k1 = mul32(k1, c1); k1 = rotl32(k1, 15); k1 = mul32(k1, c2); h1 ^= k1;
  }
  h1 ^= len;
  h1 ^= h1 >>> 16; h1 = mul32(h1, 0x85ebca6b); h1 ^= h1 >>> 13; h1 = mul32(h1, 0xc2b2ae35); h1 ^= h1 >>> 16;
  return h1 | 0; // signed 32-bit, like Shodan's http.favicon.hash
}
function shodanFaviconHash(buf) {
  const b64 = Buffer.from(buf).toString('base64');
  let wrapped = '';
  for (let i = 0; i < b64.length; i += 76) wrapped += b64.slice(i, i + 76) + '\n';
  return mmh3_32(Buffer.from(wrapped, 'ascii'));
}

// Active service/version detection from a connect banner (nmap -sV's core idea, lite).
const BANNER_SIGS = [
  { re: /^SSH-[\d.]+-(\S+)/i, name: 'ssh' },
  { re: /^220[-\s].*(vsftpd|proftpd|pure-ftpd|filezilla)/i, name: 'ftp' },
  { re: /^220[-\s].*(e?smtp|postfix|exim|sendmail)/i, name: 'smtp' },
  { re: /^(\+PONG|-NOAUTH|-DENIED|-WRONGPASS)/i, name: 'redis' },       // NOT bare -ERR (POP3 uses that)
  { re: /redis_version:([\d.]+)/i, name: 'redis' },
  { re: /^HTTP\/[\d.]/i, name: 'http' },
  { re: /^RFB \d{3}\.\d{3}/i, name: 'vnc' },
  { re: /^\+OK.*POP3/i, name: 'pop3' },
  { re: /^\* OK.*IMAP/i, name: 'imap' },
  { re: /^220.*FTP/i, name: 'ftp' },
];
export function identifyService(port, banner) {
  if (banner) {
    for (const s of BANNER_SIGS) {
      const m = banner.match(s.re);
      if (!m) continue;
      const out = { name: s.name };
      if (s.name === 'http') return out; // protocol version != software version; the Server header is authoritative
      const tok = (m[1] && /\d/.test(m[1])) ? m[1] : banner;
      const pv = tok.match(/([A-Za-z][A-Za-z0-9.+-]*?)[ _/-]v?(\d+\.\d[\w.]*)/); // OpenSSH_8.9p1, vsFTPd 3.0.3
      if (pv) { out.product = pv[1]; out.version = pv[2]; }
      else if (m[1] && /^[\d.]+$/.test(m[1])) out.version = m[1]; // redis_version:7.0.5
      return out;
    }
  }
  return { name: NAMES[port] || 'unknown' };
}

// Latches open on the TCP handshake: an error/timeout AFTER connect still means OPEN
// (connect-then-RST, silent services, timeout<banner-wait all report correctly).
// Exported as the pre-flight probe for the campaign merge loop's reachability gate.
export function tcpProbe(ip, port, timeout) {
  return new Promise((resolve) => {
    const sock = net.connect({ host: ip, port });
    let banner = '', settled = false, connected = false;
    const done = (open) => { if (settled) return; settled = true; try { sock.destroy(); } catch {} resolve({ port, open, banner: banner.trim() || undefined }); };
    sock.setTimeout(timeout);
    sock.once('connect', () => { connected = true; setTimeout(() => done(true), Math.min(200, Math.max(1, timeout / 2))); });
    sock.on('data', (d) => { if (banner.length < 180) banner += d.toString('latin1'); });
    sock.once('timeout', () => done(connected));
    sock.once('error', () => done(connected));
  });
}

function httpFingerprint(ip, port, secure, timeout = 1400, hdrs, probePath = '/') {
  return new Promise((resolve) => {
    const lib = secure ? https : http;
    let body = '', settled = false, resp = null;
    const finish = () => {
      if (settled) return; settled = true;
      if (!resp) return resolve(null);
      const h = resp.headers;
      const title = (body.match(/<title[^>]*>([^<]{0,80})/i) || [])[1];
      const iconHref = (body.match(/<link[^>]+rel=["']?(?:shortcut\s+)?icon["']?[^>]*href=["']([^"']+)/i) || body.match(/href=["']([^"']+)["'][^>]*rel=["']?(?:shortcut\s+)?icon/i) || [])[1];
      resolve({ status: resp.statusCode, server: h['server'], powered: h['x-powered-by'], title: title && title.trim(), iconHref, security: { hsts: !!h['strict-transport-security'], csp: !!h['content-security-policy'], xfo: !!h['x-frame-options'] } });
    };
    const req = lib.request({ host: ip, port, path: probePath, method: 'GET', timeout, rejectUnauthorized: false, headers: hdrs || { 'user-agent': 'VARVEL-recon' } }, (r) => {
      resp = r;
      r.on('data', (d) => {
        if (body.length < 4096) body += d.toString('latin1', 0, Math.max(0, 4096 - body.length));
        if (body.length >= 4096) { finish(); try { req.destroy(); } catch {} } // stop downloading past the cap
      });
      r.on('end', finish);
    });
    req.on('timeout', () => { try { req.destroy(); } catch {} if (!settled) { settled = true; resolve(null); } });
    req.on('error', () => { if (!settled) { settled = true; resolve(null); } });
    req.end();
  });
}

function faviconFetch(ip, port, secure, { timeout = 1400, path = '/favicon.ico', redirects = 1 } = {}) {
  return new Promise((resolve) => {
    const lib = secure ? https : http;
    const req = lib.request({ host: ip, port, path, method: 'GET', timeout, rejectUnauthorized: false }, (r) => {
      if ([301, 302, 307, 308].includes(r.statusCode) && r.headers.location && redirects > 0) {
        r.resume();
        try {
          const loc = new URL(r.headers.location, `http${secure ? 's' : ''}://${bracketHost(ip)}:${port}`);
          if (sameAddress(loc.hostname, ip)) return resolve(faviconFetch(ip, loc.port || port, loc.protocol === 'https:', { timeout, path: loc.pathname + loc.search, redirects: redirects - 1 }));
        } catch {}
        return resolve(null); // cross-host redirect (CDN) is out of scope -> skip
      }
      if (r.statusCode !== 200) { r.resume(); return resolve(null); }
      const chunks = []; let total = 0; const MAX = 512 * 1024;
      r.on('data', (d) => { total += d.length; if (total > MAX) { try { req.destroy(); } catch {} return resolve(null); } chunks.push(d); });
      r.on('end', () => { try { resolve(shodanFaviconHash(Buffer.concat(chunks))); } catch { resolve(null); } });
      r.on('error', () => resolve(null));
    });
    req.on('timeout', () => { req.destroy(); resolve(null); });
    req.on('error', () => resolve(null));
    req.end();
  });
}

function tlsInspect(ip, port, timeout = 1600) {
  return new Promise((resolve) => {
    const sock = tls.connect({ host: ip, port, servername: net.isIP(ip) ? undefined : ip, rejectUnauthorized: false, timeout }, () => {
      const c = sock.getPeerCertificate();
      const cert = c && Object.keys(c).length ? {
        subject: c.subject && (c.subject.CN || Object.values(c.subject)[0]),
        issuer: c.issuer && (c.issuer.CN || c.issuer.O),
        san: c.subjectaltname, validTo: c.valid_to, alpn: sock.alpnProtocol || undefined,
      } : null;
      try { sock.end(); } catch {}
      resolve(cert);
    });
    sock.once('timeout', () => { try { sock.destroy(); } catch {} resolve(null); });
    sock.once('error', () => resolve(null));
  });
}

// Worker pool. When `pacer` is given (stealth mode), each worker awaits a jittered delay
// before its next probe — a low-and-slow port sweep triggers far fewer IDS thresholds
// than a fast one, so quietness is enforced in code rather than left to the caller.
async function pool(items, size, fn, pacer) {
  const out = [];
  let i = 0;
  const n = items.length ? Math.max(1, Math.min(Math.floor(size) || 1, items.length)) : 0;
  await Promise.all(Array.from({ length: n }, async () => {
    while (i < items.length) { const idx = i++; if (pacer) await pacer.pace(); try { out[idx] = await fn(items[idx]); } catch { out[idx] = null; } }
  }));
  return out;
}

// Scan one host: banner + version detection + HTTP/TLS fingerprint + favicon hash.
// `stealth`/`pacer`: optional operational-stealth. `pacer` (an injected shared pacer) wins
// over `stealth` (a profile) so ONE emission clock can govern a whole engagement. Both the
// port sweep AND the higher-loudness TLS/HTTP/favicon follow-ups are paced.
// `pathPrefixes` (2026-08-31, agoda-class path-scoped engagements): when set, the HTTP
// fingerprint probes the FIRST PREFIX instead of the root, and favicon fetches outside
// the prefix are refused-and-recorded (host.scopeRefusals), never sent.
export async function scanHost(ip, { ports = COMMON_PORTS, timeout = 900, portConcurrency = 16, webPorts = WEB_PORTS, stealth, pacer, pathPrefixes = null } = {}) {
  const literal = parseIp(ip);
  if (literal) ip = literal.text; // normalize '[::1]' / zone ids / hex case before dialing
  pacer = asPacer(pacer) || (stealth ? makePacer(stealth) : null);
  const px = sanitizePathPrefixes(pathPrefixes);
  const confined = px && !px.includes('/');
  const scopeRefusals = [];
  const open = (await pool(ports, pacer ? pacer.concurrency : portConcurrency, (p) => tcpProbe(ip, p, timeout), pacer)).filter((r) => r && r.open);
  const tech = [];
  const services = [];
  for (const o of open) {
    if (pacer) await pacer.pace(); // pace the TLS/HTTP/favicon follow-ups too — they're louder than the port probe
    let secure = o.port === 443 || o.port === 8443;
    const id = identifyService(o.port, o.banner);
    const svc = { port: o.port, proto: 'tcp', name: id.name };
    if (id.product) svc.product = id.product;
    if (id.version) svc.version = id.version;
    if (o.banner) svc.banner = o.banner;
    if (TLS_PORTS.has(o.port)) { const cert = await tlsInspect(ip, o.port); if (cert) { svc.tls = cert; secure = true; } }
    if (webPorts.has(o.port) || svc.name === 'unknown' || svc.name === 'http' || svc.name === 'https') {
      const fp = await httpFingerprint(ip, o.port, secure, 1400, pacer && pacer.requestHeaders ? pacer.requestHeaders() : undefined, confined ? px[0] : '/');
      if (fp && fp.status) {
        svc.name = secure ? 'https' : 'http';
        svc.http = fp;
        if (fp.server) { tech.push({ name: fp.server }); svc.product = fp.server; } // Server header is authoritative
        if (fp.powered) tech.push({ name: fp.powered });
        let fav = null;
        if (confined && !pathPrefixAllowed('/favicon.ico', px)) {
          if (!scopeRefusals.includes('/favicon.ico')) scopeRefusals.push('/favicon.ico');
        } else {
          fav = await faviconFetch(ip, o.port, secure);
        }
        if (fav === null && fp && fp.iconHref) { // fall back to the <link rel="icon"> path
          try {
            const p = new URL(fp.iconHref, `http${secure ? 's' : ''}://${bracketHost(ip)}:${o.port}`).pathname;
            if (p && p !== '/favicon.ico') {
              if (confined && !pathPrefixAllowed(p, px)) { if (!scopeRefusals.includes(p)) scopeRefusals.push(p); }
              else fav = await faviconFetch(ip, o.port, secure, { path: p });
            }
          } catch {}
        }
        if (fav !== null) svc.faviconHash = fav;
      }
    }
    services.push(svc);
  }
  return { ip, services, tech, scopeRefusals };
}

// Recon a list of targets. LENIENT: scans every target given (no scope refusal).
// `stealth`/`pacer`: optional operational-stealth. A single shared pacer (built here or
// injected) governs the whole sweep — every host, every follow-up — so the target-visible
// rate honors the profile across the entire engagement, not just per host.
export async function recon(targets, { ports = COMMON_PORTS, timeout = 900, concurrency = 6, webPorts = WEB_PORTS, stealth, pacer, hostBudgetMs = 240000, scanHostImpl, onHost, pathPrefixes = null } = {}) {
  pacer = asPacer(pacer) || (stealth ? makePacer(stealth) : null);
  const scan = scanHostImpl || scanHost;
  // Per-host watchdog (2026-08-29): one wedged host await (DNS stall, peer-hung socket
  // whose handlers never settle) must NOT freeze the whole sweep — trip, mark stalled,
  // move on. The stall is REPORTED, never hidden (honesty contract).
  // onHost (2026-08-31): per-host progress tap so a long paced sweep emits activity as
  // each host finishes (the campaign's stall detector keys on activity; a silent
  // multi-minute sweep would otherwise read as a freeze). Tap errors never break the sweep.
  const hosts = await pool(targets, pacer ? 1 : concurrency, async (ip) => {
    const r = await Promise.race([
      scan(ip, { ports, timeout, webPorts, pacer, pathPrefixes }),
      new Promise((resolve) => { const t = setTimeout(() => resolve(null), hostBudgetMs); if (t.unref) t.unref(); }),
    ]);
    const out = !r ? { ip, label: ip, services: [], tech: [], stalled: true } : { ip, label: ip, services: r.services, tech: r.tech, scopeRefusals: r.scopeRefusals || [] };
    if (typeof onHost === 'function') { try { onHost(out); } catch { /* progress tap must never break the sweep */ } }
    return out;
  });
  return { hosts: hosts.filter((h) => h && h.services.length), stalled: hosts.filter((h) => h && h.stalled).map((h) => h.ip), scanned: targets.length, stealth: pacer ? pacer.profile.label : null };
}
