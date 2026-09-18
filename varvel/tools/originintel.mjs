// VARVEL -- originintel: origin-server intelligence for Cloudflare-fronted
// targets (the CloudPiercer problem).
//
// Why it exists: a target fronted by Cloudflare answers EVERYTHING with the managed
// challenge -- active probing buys nothing but noise. The realistic red-team
// alternative is finding the non-Cloudflare ORIGIN server, and the doctrine here is
// absolute: origin work is PASSIVE-ONLY until a candidate is signed into the
// engagement scope. The v1 tier (originIntel) opens NO TCP connection to any
// candidate, ever. The v2 tier (originDiscover, below) keeps that passivity by
// default and adds a VERIFY mode that probes ONLY scope-signed candidates. Every
// passive byte comes from public third-party datasets (crt.sh CT logs, DNS history
// providers) or from DNS -- the protocol the world already answers for us.
//
// Sources (free only):
//   ct-log  -- crt.sh cert name_value sets (wildcards split, deduped, zone-enforced
//              by the SHARED parseCrtSh from tools/passiv.mjs -- parsed once, audited once)
//   mx      -- MX exchangers for the domain
//   spf     -- v=spf1 include:/redirect= hosts and bare ip4:/ip6: mechanisms
// Mail is the leading leak: ~32% of Cloudflare-fronted domains expose their origin
// via DNS, MX records first (CloudPiercer, CCS 2015).
//
// Classification per discovered name: live-cloudflare (every resolved address inside
// Cloudflare's published ranges), live-non-cf (RESOLVES OUTSIDE = origin CANDIDATE),
// nxdomain, unresolved, error. CIDR membership REUSES engine/ipaddr.mjs's inAnyCidr --
// scope math is the security boundary and is never re-implemented per file.
//
// THE HONESTY CONTRACT (non-negotiable): never throws. Every lookup failure is a
// labeled STATE on the host, not an exception; everything that could not be observed
// (crt.sh down, MX/TXT refused) is said in honestGaps, never hidden. Unobserved is
// NOT clean -- it is unknown.
//
// fetcher (async (url) => string|Buffer|json) and resolver ({ resolve4, resolve6,
// resolveMx, resolveTxt }) are injectable for hermetic tests; defaults are global
// fetch (crt.sh only) and node:dns/promises. timeoutMs bounds the crt.sh fetch;
// DNS timeouts are the resolver's own.
//
// =========================== originintel v2 (originDiscover) ===========================
// CF-Hero-class discovery + GOVERNED verification (full banner above the v2 section):
//  - crt.sh with UA + timeout + ONE retry; Cloudflare ranges fetched live with a
//    workspace cache and the dated hardcoded fallback (fail-closed, date named)
//  - DNS via DoH by default (dns-json API through the same egress); SPF include
//    CHAINS walked to the RFC 7208 ten-lookup budget
//  - historical DNS: viewdns.info scrape (parse drift = honest gap) + SecurityTrails
//    behind optional SECURITYTRAILS_API_KEY (absent key = clean disabled note)
//  - favicon fingerprint: inline mmh3 x86_32 over MIME-base64 favicon bytes (the
//    Shodan convention), compared apex-vs-candidate KEY-FREE -- never queried
//  - verify mode: direct HTTPS probe per candidate with TLS SNI + Host set to the
//    domain. GOVERNANCE: candidates are NOT in the signed scope by default; every
//    candidate is scope-checked with the shared inAnyCidr and out-of-scope
//    candidates are REFUSED, with the exact /32 or /128 printed in recommendedScope.

import dns from 'node:dns/promises';
import fs from 'node:fs';
import net from 'node:net';
import tls from 'node:tls';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { inAnyCidr, isPrivate, parseCidr, parseIp } from '../engine/ipaddr.mjs';
import { parseChain, openTunnel, isPrivateDest } from '../engine/ghost.mjs';
import { detectChallenge } from '../engine/challenge.mjs';
import { parseCrtSh } from './passiv.mjs';

// The scope gate is a CONSTANT string -- every consumer of this report reads the same
// sentence, and it is embedded in every candidate's signals as well.
export const SCOPE_GATE = 'PASSIVE ONLY — no TCP connection to any candidate until it is signed into the engagement scope';

// Cloudflare's published ranges (https://www.cloudflare.com/ips/): the v4 set is
// pinned by the engagement brief; the v6 set is published alongside it and included
// so a v6-only fronted name is never mis-called an origin candidate. DUAL ROLE:
// these lists are also originDiscover's DATED HARDCODED FALLBACK (pinned
// 2026-08-05, the v1 engagement build date) for when the live range fetch fails.
const CF_FALLBACK_DATE = '2026-08-05';
const CF_V4 = [
  '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
  '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
  '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
  '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
];
const CF_V6 = [
  '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
  '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
];

// The confirmation ladder. Everything that touches a candidate waits for scope
// signature; historical DNS is passive and allowed NOW (it is also the strongest
// passive confirmation, which is why it earns the exception).
const VERIFICATION_CHECKLIST = [
  'AFTER SCOPE SIGNATURE: TLS cert on candidate:443 matches a CT-logged cert for the domain (same SAN set = same infrastructure)',
  'AFTER SCOPE SIGNATURE: favicon MMH3 match -- hash /favicon.ico from candidate and fronted site and compare (the Shodan favicon-search technique)',
  'AFTER SCOPE SIGNATURE: unique body-string match -- a distinctive string from the fronted site is served by the candidate on the same vhost',
  'PASSIVE (allowed now): historical A-record convergence -- free tiers of SecurityTrails/ViewDNS show pre-Cloudflare IPs; a candidate matching historical DNS is the strongest passive confirmation',
];

// What v1 deliberately does NOT do. Standing caveats, appended after observed gaps.
const STANDING_GAPS = [
  'historical A-record databases (SecurityTrails/ViewDNS free tiers) are NOT queried -- no pre-Cloudflare IP history in this report',
  'Censys/Shodan free searches are NOT used -- no cert/banner internet-scan correlation',
  'favicon-MMH3 sweep NOT performed -- it is ACTIVE (touches the candidate) and belongs after scope signature',
  'subdomain brute force NOT performed -- only names already public in CT logs and DNS are considered',
];

const errText = (e) => String((e && (e.code || e.message)) || e);

// One awaited call that can never reject: { ok:true, value } | { ok:false, error }.
// A missing resolver method is an error, not a crash.
async function safeCall(fn, arg) {
  if (typeof fn !== 'function') return { ok: false, error: new Error('resolver method missing') };
  try { return { ok: true, value: await fn(arg) }; }
  catch (e) { return { ok: false, error: e }; }
}

// DNS failure -> honest state. NXDOMAIN (name-level, authoritative) beats a resolver
// error; a resolver error beats a mere no-data/transient failure. Generic throws
// (injected resolver bugs, timeouts without codes) are 'error'.
function dnsErrState(err) {
  const code = String((err && err.code) || '');
  if (code === 'ENOTFOUND') return 'nxdomain';
  if (code === 'ENODATA' || code === 'ESERVFAIL' || code === 'ETIMEOUT' || code === 'EAI_AGAIN' || code === 'ECONNREFUSED') return 'unresolved';
  return 'error';
}

// Human-readable evidence per discovery source.
const SOURCE_EVIDENCE = {
  'ct-log': (h) => 'ct-log: a certificate naming ' + h + ' is public in CT logs (crt.sh)',
  mx: (h, d) => 'mx: ' + h + ' is an MX exchanger for ' + d,
  spf: (h, d) => 'spf: ' + h + ' is named by the SPF policy of ' + d,
  apex: (h) => 'apex: ' + h + ' is the apex domain itself',
};

// The mail-origin signal, calibrated by where the named infrastructure lives.
// In-zone mail on the origin is the classic CloudPiercer leak; third-party hosted
// mail is still non-Cloudflare infrastructure in the domain's DNS but correlates
// with the web origin far more weakly -- the signal says which it is.
function mailSignal(host, domain, kind) {
  const base = 'mail-infrastructure: ';
  if (kind === 'spf-ip4' || kind === 'spf-ip6') return base + 'SPF ' + kind.slice(4) + ' mechanism asserts ' + host + ' handles mail for ' + domain + ' and sits outside Cloudflare -- asserted by DNS, not resolved by this tool';
  const inZone = host === domain || host.endsWith('.' + domain);
  if (inZone) return base + 'in-zone mail host resolves outside Cloudflare -- self-hosted mail on the origin is the classic leak (CloudPiercer CCS 2015: ~32% of CF-fronted domains leak origin via DNS, MX leading)';
  return base + 'third-party mail host outside Cloudflare named in DNS (likely hosted mail -- weaker origin correlation than in-zone, still non-Cloudflare infrastructure)';
}

// Default fetch adapter: real network to crt.sh ONLY. Throws on HTTP failure; the
// caller catches and records an honest gap.
async function defaultFetcher(url, timeoutMs) {
  const ctl = new AbortController();
  const t = setTimeout(() => { try { ctl.abort(); } catch {} }, timeoutMs);
  try {
    const r = await fetch(url, { signal: ctl.signal, headers: { 'user-agent': 'VARVEL-originintel-passive' } });
    if (!r.ok) throw new Error('crt.sh HTTP ' + r.status);
    return await r.text();
  } finally { clearTimeout(t); }
}

const defaultResolver = () => ({
  resolve4: (h) => dns.resolve4(h),
  resolve6: (h) => dns.resolve6(h),
  resolveMx: (h) => dns.resolveMx(h),
  resolveTxt: (h) => dns.resolveTxt(h),
});

// originIntel(domain, { fetcher, resolver, timeoutMs }) -> the passive origin report.
// NEVER throws: usage problems and runtime failures come back as honest objects.
export async function originIntel(domain, { fetcher, resolver, timeoutMs = 10000 } = {}) {
  const fetchedAt = new Date().toISOString();
  const gaps = [];
  domain = String(domain || '').trim().toLowerCase().replace(/^\*\./, '');
  const shape = (extra) => ({
    domain,
    candidates: [],
    hosts: [],
    ctNames: [],
    verificationChecklist: [...VERIFICATION_CHECKLIST],
    scopeGate: SCOPE_GATE,
    honestGaps: [...gaps, ...STANDING_GAPS],
    fetchedAt,
    ...extra,
  });
  if (!domain || !/^[a-z0-9.-]+\.[a-z]{2,}$/.test(domain)) {
    return shape({ ok: false, error: 'originIntel needs a registrable domain, got ' + JSON.stringify(domain) });
  }
  try {
    const r = resolver || defaultResolver();
    const f = fetcher || ((url) => defaultFetcher(url, timeoutMs));

    // (a) CT logs -- crt.sh. Injectable fetcher returns string|Buffer|parsed json;
    // all three normalize to text for the shared parser.
    let ctNames = [];
    try {
      const raw = await f('https://crt.sh/?q=%25.' + encodeURIComponent(domain) + '&output=json');
      const text = Buffer.isBuffer(raw) ? raw.toString('utf8') : (typeof raw === 'string' ? raw : JSON.stringify(raw));
      ctNames = parseCrtSh(text, domain);
      if (!ctNames.length) gaps.push('crt.sh answered but yielded no usable names for ' + domain + ' (new domain, or an HTML/rate-limit answer) -- the CT set may be incomplete, never assume it empty');
    } catch (e) {
      gaps.push('crt.sh fetch failed (' + errText(e) + ') -- CT-log names unobserved; the DNS/mail signals below still stand on their own');
    }

    // host -> set of sources. CT names, the apex itself, then MX/SPF-named hosts.
    const byHost = new Map();
    const addSource = (h, s) => {
      h = String(h || '').trim().toLowerCase().replace(/\.$/, '');
      if (!h) return;
      if (!byHost.has(h)) byHost.set(h, new Set());
      byHost.get(h).add(s);
    };
    for (const n of ctNames) addSource(n, 'ct-log');
    if (!byHost.has(domain)) addSource(domain, 'apex');

    // (b) mail signals: MX exchangers and SPF include/redirect hosts + bare ip4/ip6
    // mechanisms naming non-Cloudflare infrastructure (CloudPiercer's leading leak).
    const mx = await safeCall(r.resolveMx, domain);
    if (mx.ok) for (const rec of mx.value || []) addSource(rec && rec.exchange, 'mx');
    else gaps.push('MX lookup for ' + domain + ' failed (' + errText(mx.error) + ') -- the leading origin-leak signal is unobserved, not absent');

    const spfIps = new Set();
    let sawCidrMech = false;
    const txt = await safeCall(r.resolveTxt, domain);
    if (txt.ok) {
      for (const chunks of txt.value || []) {
        const rec = Array.isArray(chunks) ? chunks.join('') : String(chunks);
        if (!/^v=spf1(?:[\s;]|$)/i.test(rec)) continue;
        for (const tok of rec.split(/\s+/).slice(1)) {
          const mech = tok.replace(/^[+~?-]/, '');
          let m;
          if ((m = /^(?:include:|redirect=)(.+)$/i.exec(mech))) addSource(m[1], 'spf');
          else if ((m = /^ip4:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(mech))) { if (!inAnyCidr(m[1], CF_V4)) spfIps.add(m[1]); }
          else if ((m = /^ip6:([^/\s]+)$/i.exec(mech))) {
            // bare ip6 (no CIDR mask) names ONE host — the same leak class as bare ip4.
            // Canonical form is asserted (mixed case / compression in the zone file collapse).
            const p = parseIp(m[1]);
            if (p && p.fam === 6 && !inAnyCidr(p.text, CF_V6)) spfIps.add(p.text);
            else if (!p) sawCidrMech = true; // unparseable ip6: noted as unexpanded, never guessed
          }
          else if (/^ip[46]:/i.test(mech)) sawCidrMech = true; // CIDR-form ranges: not a host, v1 does not expand
        }
      }
    } else {
      gaps.push('TXT lookup for ' + domain + ' failed (' + errText(txt.error) + ') -- the SPF mail-origin signal is unobserved, not absent');
    }
    if (sawCidrMech) gaps.push('SPF ip4/ip6 mechanisms with CIDR ranges were seen but not expanded -- v1 asserts bare IPs only');

    // (c) classify every discovered name against Cloudflare's published ranges.
    const hosts = [];
    for (const [host, srcSet] of [...byHost.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
      const sources = [...srcSet].sort();
      const signals = sources.map((s) => (SOURCE_EVIDENCE[s] || ((hh) => s + ': seen'))(host, domain));
      const v4 = await safeCall(r.resolve4, host);
      const v6 = await safeCall(r.resolve6, host);
      const ips = new Set(), outside = [];
      if (v4.ok) for (const ip of v4.value || []) { const p = String(ip); if (ips.has(p)) continue; ips.add(p); if (!inAnyCidr(p, CF_V4)) outside.push(p); }
      if (v6.ok) for (const ip of v6.value || []) { const p = String(ip); if (ips.has(p)) continue; ips.add(p); if (!inAnyCidr(p, CF_V6)) outside.push(p); }
      let state;
      if (ips.size) {
        if (outside.length) {
          state = 'live-non-cf';
          signals.push('resolves outside Cloudflare published ranges: ' + outside.join(', ') + ' -- ORIGIN CANDIDATE (' + SCOPE_GATE + ')');
        } else {
          state = 'live-cloudflare';
          signals.push('every resolved address is inside Cloudflare published ranges -- fronted, not an origin candidate');
        }
      } else {
        const st = [v4, v6].filter((x) => !x.ok).map((x) => dnsErrState(x.error));
        state = st.includes('nxdomain') ? 'nxdomain' : (st.includes('error') ? 'error' : 'unresolved');
        if (state === 'nxdomain') signals.push('DNS says this name does not exist (NXDOMAIN) -- CT-history, not live surface');
        else if (state === 'error') signals.push('resolver error for this name (' + errText((v4.ok ? v6 : v4).error) + ') -- unknown is NOT clean');
        else signals.push('named by sources but answered no A/AAAA from here -- unresolved (no-data, SERVFAIL, or timeout)');
      }
      if (state === 'live-non-cf' && (srcSet.has('mx') || srcSet.has('spf'))) signals.push(mailSignal(host, domain, 'mail'));
      hosts.push({ host, ips: [...ips].sort(), sources, state, signals });
    }

    // SPF bare-IP assertions are candidates keyed by the literal: DNS asserted the
    // IP handles the domain's mail; this tool did not resolve (or touch) it.
    for (const ip of [...spfIps].sort()) {
      const fam = (parseIp(ip) || {}).fam;
      hosts.push({
        host: ip,
        ips: [ip],
        sources: ['spf'],
        state: 'live-non-cf',
        signals: ['spf: named by the SPF policy of ' + domain, mailSignal(ip, domain, fam === 6 ? 'spf-ip6' : 'spf-ip4')],
      });
    }

    const candidates = hosts.filter((h) => h.state === 'live-non-cf').sort((a, b) => a.host.localeCompare(b.host));
    return shape({ ok: true, candidates, hosts, ctNames });
  } catch (e) {
    return shape({ ok: false, error: String((e && e.message) || e) });
  }
}

// ============================================================================
// originintel v2 -- originDiscover: CF-Hero-class discovery + governed verification
// ============================================================================
//
// New passive sources (HTTP rides the ghost chain when a proxy is configured --
// parseChain/openTunnel/isPrivateDest from engine/ghost are REUSED, never
// reimplemented, exactly the egressbench pattern; DNS runs through a DoH resolver
// over the same egress):
//   1. crt.sh JSON with a browser-persona UA, timeout, and ONE retry.
//   2. Cloudflare ranges: https://www.cloudflare.com/ips-v4 + /ips-v6 with a
//      workspace cache (varvel/data/cf-ranges.json, 7-day freshness); on fetch
//      failure the DATED hardcoded fallback above is used and the gap names its date.
//   3. MX/TXT/SPF via DoH (default resolver speaks the dns-json API); SPF include
//      chains are walked to RFC 7208's ten-lookup budget -- include/redirect/a hosts
//      are resolved and non-Cloudflare answers flagged (the mail-origin leak, one
//      level deeper than v1).
//   4. Historical DNS: viewdns.info iphistory scrape (free, fragile HTML -- parse
//      drift is an honest gap, never silence) and SecurityTrails A-history behind
//      the optional SECURITYTRAILS_API_KEY (absent key = clean disabled note).
//   5. Favicon fingerprint: mmh3 x86_32 over MIME-base64 favicon bytes -- the Shodan
//      favicon-hash convention, used KEY-FREE: hashes are COMPARED apex-vs-candidate,
//      never queried against a search API.
//
// VERIFY MODE (active, governed): for each candidate a direct HTTPS probe with TLS
// SNI + HTTP Host set to the domain. Candidate IPs are NOT in the signed engagement
// scope by default: every candidate is checked with the SHARED inAnyCidr (cfmap
// doctrine -- the refusal is recorded as data, never thrown), and an out-of-scope
// candidate is REFUSED with the exact /32 or /128 to ask signed into scope printed
// in recommendedScope. NEVER PROBED. Confirmed-origin criteria: the response is NOT
// a CF challenge (engine/challenge, the locked taxonomy) AND (favicon hash match OR
// page title/marker match OR certificate CN/SAN match for the domain).
//
// THE HONESTY CONTRACT (unchanged from v1): originDiscover NEVER throws. Every
// source failure is a labeled gap -- "unobserved, not absent", never a negative
// finding.

const OI_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'; // the shared persona (engine/ghost scrubHeaders, egressbench): no VARVEL markers on the wire
const V2_BODY_CAP = 256 * 1024;      // same cap as cfmap: markers live at the top of the body
const DOH_SERVER = 'https://cloudflare-dns.com/dns-query';
const CF_RANGE_URLS = { v4: 'https://www.cloudflare.com/ips-v4', v6: 'https://www.cloudflare.com/ips-v6' };
const DEFAULT_CACHE_DIR = fileURLToPath(new URL('../data/', import.meta.url)); // varvel/data/
const CRT_JSON_URL = (domain) => 'https://crt.sh/?q=%25.' + encodeURIComponent(domain) + '&output=json';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const normalizeHost = (h) => String(h || '').trim().toLowerCase().replace(/\.$/, '');
const normalizeScope = (scope) => (Array.isArray(scope) ? scope : String(scope || '').split(',')).map((s) => String(s).trim()).filter(Boolean);

// ---------- mmh3 x86_32 + the favicon fingerprint ----------

// MurmurHash3 x86_32 (public-domain algorithm by Austin Appleby; reference:
// https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp). This port
// is validated against SMHasher's OWN x86_32 VerificationTest -- hashing key[i]=i
// (i = 0..255) with seed 256-i and then the concatenated 1024-byte hash array with
// seed 0 yields exactly 0xB0F57EE3 -- plus the published vectors mmh3('') = 0,
// mmh3('hello') = 613153351 (0x248bfa47), mmh3('foo') = -156908512 (all pinned in
// test/originintel2.test.mjs). Returns a SIGNED 32-bit int: the python-mmh3 / Shodan
// convention.
export function mmh3(key, seed = 0) {
  const data = Buffer.isBuffer(key) ? key : Buffer.from(String(key), 'utf8');
  let h1 = seed >>> 0;
  const c1 = 0xcc9e2d51, c2 = 0x1b873593;
  const nblocks = data.length >> 2;
  for (let i = 0; i < nblocks; i++) {
    let k1 = data.readUInt32LE(i * 4);
    k1 = Math.imul(k1, c1);
    k1 = (k1 << 15) | (k1 >>> 17);
    k1 = Math.imul(k1, c2);
    h1 ^= k1;
    h1 = (h1 << 13) | (h1 >>> 19);
    h1 = Math.imul(h1, 5) + 0xe6546b64;
  }
  let k1 = 0;
  const tail = data.length & 3, off = nblocks * 4;
  if (tail === 3) k1 ^= data[off + 2] << 16;
  if (tail >= 2) k1 ^= data[off + 1] << 8;
  if (tail >= 1) {
    k1 ^= data[off];
    k1 = Math.imul(k1, c1);
    k1 = (k1 << 15) | (k1 >>> 17);
    k1 = Math.imul(k1, c2);
    h1 ^= k1;
  }
  h1 ^= data.length;
  h1 ^= h1 >>> 16;               // fmix32
  h1 = Math.imul(h1, 0x85ebca6b);
  h1 ^= h1 >>> 13;
  h1 = Math.imul(h1, 0xc2b2ae35);
  h1 ^= h1 >>> 16;
  return h1 | 0;
}

// The Shodan favicon hash (2019 technique): mmh3 over MIME-base64 favicon bytes --
// python base64.encodebytes, i.e. 76-column lines AND a trailing newline -- signed
// 32-bit. KEY-FREE here: the hash is compared apex-vs-candidate, never queried.
export function faviconHash(buf) {
  const b64 = Buffer.from(buf || []).toString('base64');
  const wrapped = b64 ? (b64.match(/.{1,76}/g).join('\n') + '\n') : '';
  return mmh3(wrapped);
}

// ---------- wire helpers (chain-aware, Buffer bodies, cert capture) ----------

// Minimal RFC 9112 chunk decoder (same construction as egressbench's): stops cleanly
// at the terminal 0-chunk or any damage.
function dechunkBuf(buf) {
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
    i += size + 2; // chunk data + trailing CRLF
  }
  return Buffer.concat(out);
}

// Parse a Connection: close response into { status, headers(lowercased), body:Buffer }.
function parseHttpResponseBuf(buf) {
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
  if (/chunked/i.test(headers['transfer-encoding'] || '')) body = dechunkBuf(body);
  return { status: Number(m[1]), headers, body: body.subarray(0, V2_BODY_CAP) };
}

// ONE HTTP/1.1 GET over a raw or TLS socket, optionally through the ghost chain.
// rejectUnauthorized is deliberately false: origin verify OBSERVES the presented
// certificate (CN/SAN matching), it does not trust-anchor it -- origin servers
// routinely serve self-signed or default certs. Overall timer caps the exchange.
function rawHttpGet({ dialHost, dialPort, useTls, servername, path: reqPath, hostHeader, extraHeaders = {}, chain, timeoutMs = 10000 }) {
  return new Promise((resolve, reject) => {
    let sock = null, settled = false, n = 0, cert = null;
    const chunks = [];
    const finish = (fn, v) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { sock && sock.destroy(); } catch {}
      fn(v);
    };
    const timer = setTimeout(() => finish(reject, new Error('request to ' + dialHost + ':' + dialPort + ' timed out (' + timeoutMs + 'ms)')), timeoutMs);
    const writeReq = () => {
      let extra = '';
      for (const [k, v] of Object.entries(extraHeaders)) extra += k + ': ' + v + '\r\n';
      try {
        sock.write(
          'GET ' + reqPath + ' HTTP/1.1\r\n'
          + 'Host: ' + hostHeader + '\r\n'
          + 'User-Agent: ' + OI_UA + '\r\n'
          + 'Accept: */*\r\n'
          + extra
          + 'Connection: close\r\n\r\n'
        );
      } catch (e) { finish(reject, e); }
    };
    const onSocket = (raw) => {
      if (useTls) {
        sock = tls.connect({ socket: raw, servername, rejectUnauthorized: false });
        sock.once('secureConnect', () => {
          try { const c = sock.getPeerCertificate(); cert = c && c.subject ? c : null; } catch { cert = null; }
          writeReq();
        });
      } else {
        sock = raw;
        if (sock.connecting) sock.once('connect', writeReq);
        else writeReq();
      }
      sock.on('data', (d) => { if (n < V2_BODY_CAP * 4) { chunks.push(d); n += d.length; } });
      sock.once('error', (e) => finish(reject, e));
      sock.once('close', () => {
        try {
          const r = parseHttpResponseBuf(Buffer.concat(chunks));
          r.cert = cert;
          finish(resolve, r);
        } catch (e) { finish(reject, e); }
      });
    };
    const open = chain
      ? openTunnel(chain, dialHost, dialPort, timeoutMs)
      : Promise.resolve(net.connect({ host: dialHost, port: dialPort }));
    open.then(onSocket, (e) => finish(reject, e));
  });
}

// The default v2 egress: (url, { headers }) -> { status, headers, body:Buffer }.
// With a proxy spec the request rides the ghost chain (DNS by the last proxy, same
// doctrine as egressbench -- a private/range target is REFUSED, never proxied);
// without one it is a plain global fetch (on the operator host a system-wide tunnel
// may still carry it at the network layer).
function makeDefaultHttpGet({ proxy, timeoutMs }) {
  const chain = proxy ? parseChain(String(proxy)) : null;
  if (proxy && !chain.length) throw new TypeError("originintel proxy '" + proxy + "' parsed to an empty chain");
  return async (url, { headers = {} } = {}) => {
    const u = new URL(String(url));
    if (!/^https?:$/.test(u.protocol)) throw new Error('originintel httpGet: http(s) URLs only, got ' + JSON.stringify(String(url)));
    const host = u.hostname.replace(/^\[|\]$/g, ''); // URL keeps v6 brackets; sockets want the bare literal
    if (chain) {
      if (isPrivateDest(host)) throw new Error('refused: proxying a private/range target leaks lab topology to the proxy operator (egressbench doctrine)');
      return rawHttpGet({
        dialHost: host, dialPort: Number(u.port) || (u.protocol === 'https:' ? 443 : 80),
        useTls: u.protocol === 'https:', servername: net.isIP(host) ? undefined : host,
        path: u.pathname + u.search, hostHeader: u.hostname + (u.port ? ':' + u.port : ''),
        extraHeaders: headers, chain, timeoutMs,
      });
    }
    const r = await fetch(url, {
      signal: AbortSignal.timeout(timeoutMs),
      redirect: 'follow',
      headers: { 'user-agent': OI_UA, ...headers },
    });
    const h = {};
    r.headers.forEach((v, k) => { h[k] = v; });
    return { status: r.status, headers: h, body: Buffer.from(await r.arrayBuffer()) };
  };
}

// Injected fetchers answer string | Buffer | { status, headers, body } -- normalize
// to { status, headers, body:Buffer } (v1's normalization, Buffer-first).
function normalizeFetched(r) {
  if (typeof r === 'string' || Buffer.isBuffer(r)) return { status: 200, headers: {}, body: Buffer.from(r) };
  const o = r || {};
  const body = Buffer.isBuffer(o.body) ? o.body : Buffer.from(typeof o.body === 'string' ? o.body : JSON.stringify(o.body == null ? '' : o.body));
  return { status: Number(o.status) || 0, headers: o.headers || {}, body };
}

// ---------- Cloudflare ranges: live -> cache -> dated fallback ----------

// loadCfRanges({ fetchText, cacheDir, maxAgeMs, now }) -> { ok, source, v4, v6,
// fetchedAt?, gap? , note? }. NEVER throws; the fallback lists ARE v1's dated pin.
export async function loadCfRanges({ fetchText, cacheDir, maxAgeMs = 7 * 24 * 3600 * 1000, now } = {}) {
  const dir = cacheDir || DEFAULT_CACHE_DIR;
  const file = path.join(dir, 'cf-ranges.json');
  const nowMs = typeof now === 'function' ? now() : Date.now();
  const valid = (o) => !!(o && Array.isArray(o.v4) && o.v4.length && Array.isArray(o.v6) && o.v6.length
    && o.v4.every((c) => { const p = parseCidr(c); return p && p.fam === 4; })
    && o.v6.every((c) => { const p = parseCidr(c); return p && p.fam === 6; }));
  let cached = null;
  try {
    const o = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (valid(o) && Date.parse(o.fetchedAt)) cached = o;
  } catch { /* absent or damaged cache is treated as NO cache */ }
  if (cached && nowMs - Date.parse(cached.fetchedAt) < maxAgeMs) {
    return { ok: true, source: 'cache', v4: cached.v4, v6: cached.v6, fetchedAt: cached.fetchedAt };
  }
  const ft = fetchText || (async (url) => {
    const r = await fetch(url, { signal: AbortSignal.timeout(10000), headers: { 'user-agent': OI_UA } });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    return r.text();
  });
  try {
    const v4 = String(await ft(CF_RANGE_URLS.v4)).split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
    const v6 = String(await ft(CF_RANGE_URLS.v6)).split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
    const o = { v4, v6, fetchedAt: new Date(nowMs).toISOString() };
    if (!valid(o)) throw new Error('range fetch parsed to an invalid set (page shape drift?)');
    try { fs.mkdirSync(dir, { recursive: true }); fs.writeFileSync(file, JSON.stringify(o, null, 1)); } catch { /* the cache write is best-effort */ }
    return { ok: true, source: 'live', ...o };
  } catch (e) {
    if (cached) {
      return { ok: true, source: 'cache-stale', v4: cached.v4, v6: cached.v6, fetchedAt: cached.fetchedAt, note: 'live Cloudflare range fetch failed (' + errText(e) + ') -- using a stale cache from ' + cached.fetchedAt + '; refresh recommended' };
    }
    return { ok: false, source: 'fallback', v4: [...CF_V4], v6: [...CF_V6], gap: 'Cloudflare range fetch failed (' + errText(e) + ') and no cache exists -- using the dated hardcoded list of ' + CF_FALLBACK_DATE + '; live ranges unobserved, not absent' };
  }
}

// ---------- DoH (dns-json API) resolver ----------

// dohJsonResolver({ fetcher, server }) -> { resolve4, resolve6, resolveMx, resolveTxt }
// in exactly v1's resolver shape (node:dns conventions incl. ENOTFOUND/ENODATA codes),
// so v2's default DNS rides the same egress path as its HTTP. fetcher answers
// (url, { headers }) -> { status, body } with body Buffer|string|parsed json.
export function dohJsonResolver({ fetcher, server = DOH_SERVER } = {}) {
  const query = async (name, type) => {
    if (typeof fetcher !== 'function') { const e = new Error('dohJsonResolver needs a fetcher'); e.code = 'ESETUP'; throw e; }
    const u = server + (server.includes('?') ? '&' : '?') + 'name=' + encodeURIComponent(name) + '&type=' + encodeURIComponent(type);
    const r = normalizeFetched(await fetcher(u, { headers: { accept: 'application/dns-json' } }));
    if (!r.status || r.status >= 400) { const e = new Error('DoH HTTP ' + (r.status || 0)); e.code = 'ESERVFAIL'; throw e; }
    let j;
    try { j = JSON.parse(r.body.toString('utf8')); } catch { const e = new Error('DoH answer was not valid dns-json'); e.code = 'ESERVFAIL'; throw e; }
    return j || {};
  };
  const guard = (j, what) => {
    if (j.Status === 3) { const e = new Error(what + ' ENOTFOUND'); e.code = 'ENOTFOUND'; throw e; }
    if (j.Status !== 0) { const e = new Error(what + ' rcode ' + j.Status); e.code = 'ESERVFAIL'; throw e; }
  };
  const answers = (j, t) => (Array.isArray(j.Answer) ? j.Answer : []).filter((a) => a && a.type === t);
  const noData = (what) => { const e = new Error(what + ' ENODATA'); e.code = 'ENODATA'; return e; };
  return {
    async resolve4(name) {
      const j = await query(name, 'A'); guard(j, 'queryA');
      const out = answers(j, 1).map((a) => String(a.data || '')).filter((ip) => { const p = parseIp(ip); return p && p.fam === 4; });
      if (!out.length) throw noData('queryA');
      return out;
    },
    async resolve6(name) {
      const j = await query(name, 'AAAA'); guard(j, 'queryAaaa');
      const out = answers(j, 28).map((a) => String(a.data || '')).filter((ip) => { const p = parseIp(ip); return p && p.fam === 6; });
      if (!out.length) throw noData('queryAaaa');
      return out;
    },
    async resolveMx(name) {
      const j = await query(name, 'MX'); guard(j, 'queryMx');
      const out = [];
      for (const a of answers(j, 15)) {
        const m = /^(\d+)\s+(.+)$/.exec(String(a.data || '').trim());
        if (m) out.push({ priority: Number(m[1]), exchange: normalizeHost(m[2]) });
      }
      if (!out.length) throw noData('queryMx');
      return out;
    },
    async resolveTxt(name) {
      const j = await query(name, 'TXT'); guard(j, 'queryTxt');
      const out = [];
      for (const a of answers(j, 16)) {
        const data = String(a.data || '');
        const chunks = [...data.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => m[1]);
        out.push(chunks.length ? chunks : [data]);
      }
      if (!out.length) throw noData('queryTxt');
      return out;
    },
  };
}

// ---------- historical DNS parsers ----------

// Parse viewdns.info's /iphistory/ table -> [{ ip, lastSeen }] (possibly empty), or
// null when the expected markers are gone (parse drift -- the caller's honest gap).
export function parseViewDnsHistory(html) {
  const s = String(html || '');
  if (!/ip\s*history|last seen on this ip/i.test(s) || !/<table[\s>]/i.test(s)) return null;
  const out = [];
  for (const row of s.match(/<tr[\s\S]*?<\/tr>/gi) || []) {
    const cells = [...row.matchAll(/<td[^>]*>([\s\S]*?)<\/td>/gi)].map((m) => m[1].replace(/<[^>]+>/g, '').trim());
    if (!cells.length) continue;
    const p = parseIp(cells[0]);
    if (!p) continue; // header rows and non-IP rows are skipped, never coerced
    out.push({ ip: p.text, lastSeen: cells[cells.length - 1] || null });
  }
  return out;
}

// ---------- SPF include-chain walk (RFC 7208 budget) ----------

// Walk the domain's SPF policy THROUGH include:/redirect= targets (depth-capped,
// cycle-safe, RFC 7208 ten-lookup budget). Returns the hosts the policy names
// (include/redirect/a mechanisms, for resolution) and bare ip4/ip6 assertions.
async function spfChain(domain, resolver, { maxDepth = 4, maxLookups = 10 } = {}) {
  const hosts = new Set(), ips = new Set(), gaps = [];
  const seen = new Set();
  const queue = [[domain, 0]];
  let lookups = 0, failed = false, rootError = null, sawCidr = false;
  while (queue.length) {
    const [d, depth] = queue.shift();
    if (seen.has(d)) continue;
    seen.add(d);
    if (lookups >= maxLookups) {
      gaps.push('SPF include chain hit the RFC 7208 ten-lookup budget at ' + d + ' -- deeper includes unobserved, not absent');
      break;
    }
    lookups++;
    const txt = await safeCall(resolver.resolveTxt, d);
    if (!txt.ok) {
      // A leaf include target with no TXT record (ENOTFOUND/ENODATA) is an OBSERVED
      // dead branch -- policy files end like that all the time; only resolver
      // ERRORS are unobserved gaps.
      const code = String((txt.error && txt.error.code) || '');
      if (d === domain) { failed = true; rootError = txt.error; }
      else if (code !== 'ENOTFOUND' && code !== 'ENODATA') gaps.push('TXT lookup for SPF include target ' + d + ' failed (' + errText(txt.error) + ') -- that branch of the policy is unobserved, not absent');
      continue;
    }
    for (const chunks of txt.value || []) {
      const rec = Array.isArray(chunks) ? chunks.join('') : String(chunks);
      if (!/^v=spf1(?:[\s;]|$)/i.test(rec)) continue;
      for (const tok of rec.split(/\s+/).slice(1)) {
        const mech = tok.replace(/^[+~?-]/, '');
        let m;
        if ((m = /^(?:include:|redirect=)(.+)$/i.exec(mech))) {
          const target = normalizeHost(m[1]);
          if (!target) continue;
          hosts.add(target);
          if (depth + 1 <= maxDepth) queue.push([target, depth + 1]);
          else gaps.push('SPF include ' + target + ' sits beyond the depth cap (' + maxDepth + ') -- unobserved, not absent');
        } else if ((m = /^ip4:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(mech))) {
          ips.add(m[1]);
        } else if ((m = /^ip6:([^/\s]+)$/i.exec(mech))) {
          // bare ip6 (no CIDR mask) asserts ONE host — harvested like bare ip4,
          // canonicalized so case/compression variants dedupe.
          const p = parseIp(m[1]);
          if (p && p.fam === 6) ips.add(p.text);
          else if (!p) sawCidr = true; // unparseable ip6: noted as unexpanded, never guessed
        } else if (/^ip[46]:/i.test(mech)) {
          sawCidr = true; // CIDR-form ranges: asserted as ranges, not expanded into hosts
        } else if ((m = /^a:([a-z0-9][a-z0-9.-]*)$/i.exec(mech))) {
          hosts.add(normalizeHost(m[1])); // a:host names infrastructure directly
        } else if (/^a$/i.test(mech)) {
          hosts.add(d); // bare 'a' = the policy owner's own A record (often the web origin)
        }
        // bare 'mx' mechanism: the domain's MX hosts -- already covered by the MX source
      }
    }
  }
  if (sawCidr) gaps.push('SPF ip4/ip6 mechanisms with CIDR ranges were seen but not expanded -- the tool asserts bare IPs only');
  return { hosts, ips, gaps, failed, error: rootError, lookups };
}

// ---------- page / cert markers ----------

function extractTitle(html) {
  const m = /<title[^>]*>([\s\S]{0,300}?)<\/title>/i.exec(String(html || ''));
  return m ? m[1].replace(/\s+/g, ' ').trim() : null;
}

// Domain self-reference in the served page: <title> containing the domain, or an
// og:url / og:site_name / canonical tag pointing at it. Returns the marker kind or null.
function pageMarkerMatch(html, domain) {
  const s = String(html || '');
  const t = extractTitle(s);
  if (t && t.toLowerCase().includes(domain)) return 'title';
  for (const tag of s.match(/<(?:meta|link)\b[^>]*>/gi) || []) {
    if (!/og:url|og:site_name|canonical/i.test(tag)) continue;
    const m = /(?:content|href)\s*=\s*["']([^"']+)["']/i.exec(tag);
    if (m && m[1].toLowerCase().includes(domain)) return 'og/canonical';
  }
  return null;
}

function parseSan(altname) {
  return String(altname || '').split(',').map((p) => p.trim().replace(/^DNS:/i, '').toLowerCase()).filter(Boolean);
}

// CN or SAN names the domain itself or its apex wildcard.
function certMatchesDomain(cert, domain) {
  if (!cert) return false;
  const cn = cert.cn ? String(cert.cn).toLowerCase() : '';
  if (cn === domain || cn === '*.' + domain) return true;
  return (cert.san || []).some((n) => n === domain || n === '*.' + domain);
}

// ---------- the default verify prober ----------

// probeCandidateOrigin(ip, { domain, proxy, port, timeoutMs }): ONE direct HTTPS
// probe of the candidate with TLS SNI + HTTP Host set to the domain -- GET / (page,
// cert) then GET /favicon.ico (fingerprint). GOVERNANCE NOTE: the scope check is the
// CALLER's job (originDiscover's verify mode, via inAnyCidr); this function dials
// whatever it is handed. Never call it for an out-of-scope IP. Failures come back as
// { ok:false, error } -- data for the caller's honest evidence, never thrown.
export async function probeCandidateOrigin(ip, { domain, proxy, port = 443, timeoutMs = 10000 } = {}) {
  const p = parseIp(ip);
  if (!p) return { ok: false, error: 'not a parseable IP: ' + JSON.stringify(String(ip)) };
  let chain = null;
  if (proxy && !isPrivateDest(p.text)) chain = parseChain(String(proxy)); // ghost doctrine: private destinations never ride a proxy
  const base = { dialHost: p.text, dialPort: port, useTls: true, servername: domain, hostHeader: domain, chain, timeoutMs };
  let page;
  try { page = await rawHttpGet({ ...base, path: '/' }); }
  catch (e) { return { ok: false, error: 'TLS probe of ' + p.text + ':' + port + ' failed: ' + errText(e) }; }
  let fav;
  try { fav = await rawHttpGet({ ...base, path: '/favicon.ico' }); }
  catch (e) { fav = { status: 0, error: errText(e) }; }
  const cert = page.cert ? { cn: page.cert.subject && page.cert.subject.CN ? String(page.cert.subject.CN) : null, san: parseSan(page.cert.subjectaltname) } : null;
  return {
    ok: true,
    status: page.status,
    headers: page.headers,
    body: page.body,
    cert,
    favicon: fav.body && fav.status >= 200 && fav.status < 400 ? fav.body : null,
    faviconStatus: fav.status || 0,
    faviconError: fav.error || null,
  };
}

// One in-scope candidate's verdict. Injected `probe` answers the same shape as
// probeCandidateOrigin; apexFavicon (null when unobserved) gates the favicon signal.
async function verifyOne(ip, { domain, apexFavicon, probe, timeoutMs }) {
  const evidence = [];
  let r;
  try { r = await probe(ip, { domain, timeoutMs }); }
  catch (e) { r = { ok: false, error: e }; }
  if (!r || r.ok === false) {
    const msg = errText((r && r.error) || 'no result');
    return { ip, confirmed: false, error: msg, evidence: ['probe failed (' + msg + ') -- candidate unobserved, not absent'] };
  }
  const bodyText = Buffer.isBuffer(r.body) ? r.body.toString('utf8') : String(r.body || '');
  const detection = detectChallenge({ status: r.status, headers: r.headers || {}, body: bodyText.slice(0, 65536) });
  const favHash = r.favicon && r.favicon.length ? faviconHash(r.favicon) : null;
  const faviconMatch = favHash != null && apexFavicon != null && favHash === apexFavicon.hash;
  const cert = r.cert || null;
  const certMatch = certMatchesDomain(cert, domain);
  const marker = pageMarkerMatch(bodyText, domain);
  if (detection.present) {
    evidence.push('challenge evidence on the candidate (' + detection.kind + (detection.signals[0] ? ': ' + detection.signals[0] : '') + ') -- NOT a confirmed origin regardless of any other signal');
  } else {
    evidence.push('response is NOT a Cloudflare challenge (status ' + (r.status || 0) + (detection.cf.server ? ', though a server: cloudflare header is present' : ', no server: cloudflare header') + ')');
  }
  if (faviconMatch) evidence.push('favicon mmh3 ' + favHash + ' MATCHES the fronted apex favicon -- ' + ip + ' serves the same favicon as the CF edge (the Shodan favicon-hash technique, compared key-free)');
  else if (favHash != null && apexFavicon) evidence.push('favicon mmh3 ' + favHash + ' != apex ' + apexFavicon.hash + ' -- favicons differ (weak signal only: per-vhost assets can legitimately differ)');
  else if (favHash != null) evidence.push('candidate favicon mmh3 ' + favHash + ' observed, but the apex favicon was not -- comparison impossible');
  else evidence.push('no favicon served by the candidate (status ' + (r.faviconStatus || 0) + (r.faviconError ? ', ' + r.faviconError : '') + ') -- favicon signal unobserved on this candidate');
  if (certMatch) evidence.push('TLS certificate on ' + ip + ' names ' + domain + ' or *.' + domain + ' (CN/SAN) -- the vhost answers TLS for the domain');
  else if (cert) evidence.push('TLS certificate on ' + ip + ' names ' + (cert.cn || (cert.san || [])[0] || '(none)') + ' -- not ' + domain + ' (a shared-host/default cert; not proof either way)');
  if (marker) evidence.push('page markers (' + marker + ') reference ' + domain + ' -- the candidate serves content for the domain vhost');
  const confirmed = !detection.present && (faviconMatch || certMatch || !!marker);
  return {
    ip, confirmed,
    status: r.status || 0,
    detection: { present: detection.present, kind: detection.kind },
    faviconHash: favHash,
    cert: cert ? { cn: cert.cn || null, san: cert.san || [] } : null,
    title: extractTitle(bodyText),
    evidence,
  };
}

// Evidence text per discovery source (v2 aggregation is by IP; the host that led to
// the IP is named in the string).
const V2_EVIDENCE = {
  'ct-log': (h, d, ip) => 'ct-log: ' + h + ' is public in CT logs (crt.sh) and resolves to ' + ip + ', outside Cloudflare published ranges',
  mx: (h, d, ip) => 'mx: ' + h + ' is an MX exchanger for ' + d + ' and resolves to ' + ip + ' outside Cloudflare -- in-zone mail on the origin is the classic CloudPiercer leak',
  spf: (h, d, ip) => 'spf: the SPF policy chain of ' + d + ' names ' + h + ' (include/redirect/a mechanism), resolving to ' + ip + ' outside Cloudflare',
  apex: (h, d, ip) => 'apex: the apex ' + h + ' itself answers ' + ip + ' outside Cloudflare (partial CF coverage)',
};

const CONF_RANK = { high: 0, medium: 1, low: 2 };

// originDiscover(domain, opts) -> the v2 origin report. NEVER throws.
//   mode 'passive' (default) | 'verify'
//   scope            signed engagement scope CIDRs (array or comma string) --
//                    REQUIRED for verify; without it every probe is refused
//   candidates       optional IP list for verify (default: the passive candidates)
//   proxy            ghost chain spec, e.g. 'socks5://10.64.0.1:1080' (Mullvad)
//   fetcher          injectable (url, {headers}) -> string|Buffer|{status,headers,body}
//   resolver         injectable { resolve4, resolve6, resolveMx, resolveTxt }
//                    (default: DoH dns-json through the same egress)
//   prober           injectable verify probe (ip, {domain, timeoutMs}) ->
//                    probeCandidateOrigin's result shape (hermetic tests)
//   verifyPort       default prober's port (443; overridable for lab/hermetic use)
//   cacheDir         Cloudflare-range cache dir (default varvel/data/)
//   env              environment for SECURITYTRAILS_API_KEY (default process.env)
//   paceMs           delay between verify probes (cfmap pacing doctrine)
export async function originDiscover(domain, {
  mode = 'passive',
  scope,
  candidates: candidateOverride,
  proxy,
  fetcher,
  resolver,
  prober,
  verifyPort = 443,
  cacheDir,
  env,
  securityTrailsKey,
  timeoutMs = 10000,
  paceMs = 1200,
} = {}) {
  const fetchedAt = new Date().toISOString();
  const gaps = [], notes = [], verified = [], refusals = [];
  const sources = {};
  domain = normalizeHost(domain).replace(/^\*\./, '');
  const shape = (extra) => ({
    ok: true,
    domain,
    mode: mode === 'verify' ? 'verify' : 'passive',
    scopeGate: SCOPE_GATE,
    sources,
    candidates: [],
    verified,
    refusals,
    gaps,
    recommendedScope: [],
    fetchedAt,
    ...extra,
  });
  if (!domain || !/^[a-z0-9.-]+\.[a-z]{2,}$/.test(domain)) {
    return shape({ ok: false, error: 'originDiscover needs a registrable domain, got ' + JSON.stringify(domain) });
  }
  try {
    let defaultGet;
    try { defaultGet = makeDefaultHttpGet({ proxy, timeoutMs }); }
    catch (e) { return shape({ ok: false, error: String((e && e.message) || e) }); }
    const httpGet = async (url, opts = {}) => (fetcher ? normalizeFetched(await fetcher(url, opts)) : defaultGet(url, opts));
    const r = resolver || dohJsonResolver({ fetcher: httpGet });
    const environ = env || process.env;

    // (1) Cloudflare ranges: live -> cache -> dated fallback. The failure is named,
    //     never silent -- CF membership math is the candidate boundary.
    const ranges = await loadCfRanges({
      cacheDir,
      fetchText: async (u) => {
        const resp = await httpGet(u);
        if (!resp.status || resp.status >= 400) throw new Error('HTTP ' + (resp.status || 0));
        return resp.body.toString('utf8');
      },
    });
    const cfRangesInfo = { source: ranges.source, fetchedAt: ranges.fetchedAt || null, v4: ranges.v4.length, v6: ranges.v6.length };
    if (ranges.gap) gaps.push(ranges.gap);
    if (ranges.note) notes.push(ranges.note);
    sources['cf-ranges'] = ranges.source;
    const cfOf = (ip) => { const p = parseIp(ip); return p ? inAnyCidr(p.text, p.fam === 4 ? ranges.v4 : ranges.v6) : false; };

    // (2) crt.sh CT logs -- one retry, then an honest gap.
    let ctNames = [];
    {
      let raw = null, lastErr = null;
      for (let attempt = 0; attempt < 2 && raw == null; attempt++) {
        if (attempt) await sleep(Math.min(Math.max(0, Number(paceMs) || 0), 1000));
        try {
          const resp = await httpGet(CRT_JSON_URL(domain));
          if (!resp.status || resp.status >= 400) throw new Error('crt.sh HTTP ' + (resp.status || 0));
          raw = resp.body.toString('utf8');
        } catch (e) { lastErr = e; }
      }
      if (raw != null) {
        ctNames = parseCrtSh(raw, domain);
        sources['ct-log'] = ctNames.length ? 'ok' : 'empty';
        if (!ctNames.length) gaps.push('crt.sh answered but yielded no usable names for ' + domain + ' (new domain, or an HTML/rate-limit answer) -- the CT set may be incomplete, never assume it empty');
      } else {
        sources['ct-log'] = 'failed';
        gaps.push('crt.sh fetch failed after one retry (' + errText(lastErr) + ') -- CT-log names unobserved, not absent');
      }
    }

    // host -> sources (ct-log / apex / mx / spf), then per-IP aggregation below.
    const byHost = new Map();
    const addSource = (h, s) => {
      h = normalizeHost(h);
      if (!h) return;
      if (!byHost.has(h)) byHost.set(h, new Set());
      byHost.get(h).add(s);
    };
    for (const n of ctNames) addSource(n, 'ct-log');
    addSource(domain, 'apex');

    // (3) mail signals: MX exchangers + the SPF include CHAIN (v2 walks one level
    //     deeper than v1 -- the policy's own named infrastructure).
    const mx = await safeCall(r.resolveMx, domain);
    if (mx.ok) {
      sources.mx = 'ok';
      for (const rec of mx.value || []) addSource(rec && rec.exchange, 'mx');
    } else {
      sources.mx = 'failed';
      gaps.push('MX lookup for ' + domain + ' failed (' + errText(mx.error) + ') -- the leading origin-leak signal is unobserved, not absent');
    }
    const spf = await spfChain(domain, r);
    for (const h of spf.hosts) addSource(h, 'spf');
    for (const g of spf.gaps) gaps.push(g);
    if (spf.failed) {
      sources.spf = 'failed';
      gaps.push('TXT lookup for ' + domain + ' failed (' + errText(spf.error) + ') -- the SPF mail-origin signal is unobserved, not absent');
    } else {
      sources.spf = 'ok';
    }

    // (4) resolve every named host; non-Cloudflare, non-private answers aggregate
    //     into IP-keyed candidates. Private answers are DNS ANOMALIES -- noted,
    //     never candidates, never probed (a hostile zone must not aim this tool at
    //     the operator's own range).
    const byIp = new Map();
    const addIp = (ip, source, evidence, flags = {}) => {
      const p = parseIp(ip);
      if (!p) return;
      if (!byIp.has(p.text)) byIp.set(p.text, { ip: p.text, fam: p.fam, sources: new Set(), evidence: [], live: false, historical: false });
      const e = byIp.get(p.text);
      e.sources.add(source);
      if (evidence && !e.evidence.includes(evidence)) e.evidence.push(evidence);
      if (flags.live) e.live = true;
      if (flags.historical) e.historical = true;
    };
    for (const [host, srcSet] of byHost) {
      const v4 = await safeCall(r.resolve4, host);
      const v6 = await safeCall(r.resolve6, host);
      const answers = [];
      if (v4.ok) for (const ip of v4.value || []) answers.push(ip);
      if (v6.ok) for (const ip of v6.value || []) answers.push(ip);
      for (const ip of answers) {
        const p = parseIp(ip);
        if (!p) continue;
        if (isPrivate(p.text)) { notes.push('DNS anomaly: ' + host + ' answers a private/range address (' + p.text + ') -- noted, never a candidate, never probed'); continue; }
        if (cfOf(p.text)) continue; // Cloudflare-fronted: surface, not an origin lead
        for (const s of [...srcSet].sort()) addIp(p.text, s, (V2_EVIDENCE[s] || ((h, d, i) => s + ': ' + h + ' -> ' + i))(host, domain, p.text), { live: true });
      }
    }
    // SPF bare ip4/ip6 assertions: DNS-asserted (not resolved) mail infrastructure.
    for (const ip of [...spf.ips].sort()) {
      const p = parseIp(ip);
      if (!p) continue;
      if (isPrivate(p.text)) { notes.push('DNS anomaly: the SPF policy of ' + domain + ' asserts a private/range address (' + p.text + ') -- noted, never a candidate'); continue; }
      if (cfOf(p.text)) continue;
      const mech = p.fam === 6 ? 'ip6' : 'ip4';
      addIp(p.text, 'spf-' + mech, 'spf: the SPF policy of ' + domain + ' asserts ' + p.text + ' handles its mail (bare ' + mech + ' mechanism, outside Cloudflare) -- DNS-asserted, not resolved by this tool', { live: true });
    }

    // (5) historical DNS -- viewdns.info (free scrape; drift is an honest gap).
    try {
      const resp = await httpGet('https://viewdns.info/iphistory/?domain=' + encodeURIComponent(domain));
      if (!resp.status || resp.status >= 400) throw new Error('viewdns.info HTTP ' + (resp.status || 0));
      const rows = parseViewDnsHistory(resp.body.toString('utf8'));
      if (rows === null) {
        sources['history-viewdns'] = 'parse-drift';
        gaps.push('viewdns.info answered but the IP-history table was not found -- the page shape has drifted; historical IPs unobserved, not absent');
      } else if (!rows.length) {
        sources['history-viewdns'] = 'empty';
        gaps.push('viewdns.info answered but zero history rows parsed (no history on record, or row-shape drift) -- historical IPs unobserved, not absent');
      } else {
        sources['history-viewdns'] = 'ok';
        for (const row of rows) {
          const p = parseIp(row.ip);
          if (!p || isPrivate(p.text) || cfOf(p.text)) continue; // already-Cloudflare history is not an origin lead
          addIp(p.text, 'history-viewdns', 'history-viewdns: viewdns.info IP history shows ' + p.text + ' serving ' + domain + (row.lastSeen ? ' (last seen ' + row.lastSeen + ')' : '') + ' -- pre/off-Cloudflare infrastructure', { historical: true });
        }
      }
    } catch (e) {
      sources['history-viewdns'] = 'failed';
      gaps.push('viewdns.info IP-history fetch failed (' + errText(e) + ') -- historical IPs unobserved, not absent');
    }

    // (6) historical DNS -- SecurityTrails A-history (optional key; the absent-key
    //     state is a clean disabled note, not a failure).
    const stKey = securityTrailsKey || (environ && environ.SECURITYTRAILS_API_KEY) || '';
    if (!stKey) {
      sources['history-securitytrails'] = 'disabled';
      gaps.push('SecurityTrails A-history NOT queried -- SECURITYTRAILS_API_KEY is not set (a free key unlocks it); that dataset is unobserved, not absent');
    } else {
      try {
        const resp = await httpGet('https://api.securitytrails.com/v1/history/' + encodeURIComponent(domain) + '/dns/a', { headers: { apikey: stKey, accept: 'application/json' } });
        if (!resp.status || resp.status >= 400) throw new Error('SecurityTrails HTTP ' + (resp.status || 0));
        const j = JSON.parse(resp.body.toString('utf8'));
        let n = 0;
        for (const rec of (j && j.records) || []) {
          for (const v of (rec && rec.values) || []) {
            const p = parseIp(v && v.ip);
            if (!p || isPrivate(p.text) || cfOf(p.text)) continue;
            n++;
            addIp(p.text, 'history-securitytrails', 'history-securitytrails: SecurityTrails A-record history shows ' + p.text + ' for ' + domain + (v.last_seen ? ' (last seen ' + v.last_seen + ')' : '') + ' -- pre/off-Cloudflare infrastructure', { historical: true });
          }
        }
        sources['history-securitytrails'] = 'ok';
        if (!n) notes.push('SecurityTrails answered but held no non-Cloudflare A-history for ' + domain);
      } catch (e) {
        sources['history-securitytrails'] = 'failed';
        gaps.push('SecurityTrails A-history fetch failed (' + errText(e) + ') -- historical IPs unobserved, not absent');
      }
    }

    // (7) apex favicon fingerprint. This fetch targets the FRONTED EDGE (the
    //     engagement target itself -- the same request class as cfmap), NEVER a
    //     candidate; favicons are normally served unchallenged.
    let apexFavicon = null;
    try {
      const resp = await httpGet('https://' + domain + '/favicon.ico');
      if (!resp.status || resp.status >= 400) throw new Error('HTTP ' + (resp.status || 0));
      apexFavicon = { hash: faviconHash(resp.body), bytes: resp.body.length };
      sources.favicon = 'ok';
    } catch (e) {
      sources.favicon = 'failed';
      gaps.push('apex favicon fetch failed (' + errText(e) + ') -- the favicon fingerprint is unobserved, not absent; verify mode loses that confirmation signal');
    }

    // candidates: by IP, confidence = source diversity / convergence / currency.
    const candidates = [...byIp.values()].map((e) => {
      let confidence;
      if (e.sources.size >= 2 || (e.live && e.historical)) confidence = 'high';   // independent corroboration, or history converging on a live answer
      else if (e.live) confidence = 'medium';                                       // one source, live resolution/assertion
      else confidence = 'low';                                                      // history only -- stale leads age badly
      return { ip: e.ip, sources: [...e.sources].sort(), confidence, evidence: e.evidence };
    }).sort((a, b) => CONF_RANK[a.confidence] - CONF_RANK[b.confidence] || a.ip.localeCompare(b.ip));

    // recommendedScope: the exact host routes to ask signed in -- every candidate
    // not already covered by the provided scope (all candidates when no scope given).
    const scopeList = normalizeScope(scope);
    const recommendFor = (ip) => { const p = parseIp(ip); return p ? p.text + '/' + (p.fam === 4 ? '32' : '128') : null; };
    const covered = (ip) => scopeList.length > 0 && inAnyCidr(ip, scopeList);
    const recommendedScope = [...new Set(candidates.filter((c) => !covered(c.ip)).map((c) => recommendFor(c.ip)).filter(Boolean))].sort();

    // (8) VERIFY MODE -- governed active confirmation. Every candidate is
    //     scope-checked FIRST (cfmap doctrine: the refusal is data, never thrown).
    if (mode === 'verify') {
      let ips = [];
      if (candidateOverride != null) {
        for (const rawIp of [].concat(candidateOverride)) {
          const p = parseIp(rawIp);
          if (!p) { gaps.push('verify candidate ' + JSON.stringify(String(rawIp)) + ' is not a parseable IP -- skipped, never probed'); continue; }
          ips.push(p.text);
        }
        ips = [...new Set(ips)];
      } else {
        ips = candidates.map((c) => c.ip);
      }
      const probe = prober || ((ip, ctx) => probeCandidateOrigin(ip, { domain, proxy, port: verifyPort, timeoutMs: (ctx && ctx.timeoutMs) || timeoutMs }));
      if (!scopeList.length) {
        for (const ip of ips) {
          refusals.push({ ip, recommendedCidr: recommendFor(ip), reason: 'verify REFUSED -- no signed engagement scope was provided; a candidate is never probed unless it is explicitly in scope' });
        }
        if (ips.length) gaps.push('verify mode ran with NO signed scope -- all ' + ips.length + ' candidate probe(s) refused; ask for the exact CIDRs in recommendedScope to be signed into scope');
      } else {
        const pace = Math.max(0, Number(paceMs) || 0);
        let lastStart = 0;
        for (const ip of ips) {
          if (!inAnyCidr(ip, scopeList)) {
            refusals.push({ ip, recommendedCidr: recommendFor(ip), reason: 'verify REFUSED -- ' + ip + ' is not inside the signed engagement scope; ask for ' + recommendFor(ip) + ' to be signed in, exactly as written' });
            continue;
          }
          const wait = lastStart ? pace - (Date.now() - lastStart) : 0;
          if (wait > 0) await sleep(wait);
          lastStart = Date.now();
          verified.push(await verifyOne(ip, { domain, apexFavicon, probe, timeoutMs }));
        }
      }
      for (const ref of refusals) if (ref.recommendedCidr && !recommendedScope.includes(ref.recommendedCidr)) recommendedScope.push(ref.recommendedCidr);
      recommendedScope.sort();
    }

    return shape({
      cfRanges: cfRangesInfo,
      apexFavicon: apexFavicon ? { hash: apexFavicon.hash, bytes: apexFavicon.bytes } : null,
      ctNames,
      candidates,
      verified,
      refusals,
      notes,
      recommendedScope,
    });
  } catch (e) {
    return shape({ ok: false, error: String((e && e.message) || e) });
  }
}
