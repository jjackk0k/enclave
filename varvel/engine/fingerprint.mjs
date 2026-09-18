// VARVEL -- fingerprint: wire-shape self-awareness, pure logic (JA4 / JA4S / JA4H + header shape).
//
// Why it exists: a nation-grade offensive platform must MEASURE exactly what it looks like
// on the wire, never assert it. This engine parses real TLS ClientHello/ServerHello bytes
// and HTTP request header pairs into the industry's standard fingerprint formats (JA4,
// JA4S, JA4H -- FoxIO, https://github.com/FoxIO-LLC/ja4) plus the raw shape facts a
// defender's classifier would key on. It REPORTS fingerprints, shape facts, and mismatch
// flags; it never claims undetectability and it builds/suggests NO evasion internals
// (the line -- same doctrine as detoracle: we measure and report).
//
// Spec fidelity (pulled from the official repo before writing the hash logic):
//   JA4  -- technical_details/JA4.md (BSD 3-Clause) + rust/ja4/src/tls.rs test vector
//           (t13d1516h2_8daaf6152771_e5627efa2ab1) reproduced in test/fporacle.test.mjs.
//   JA4S -- NO .md exists in the repo. Implemented from the two references that agree:
//           rust tls.rs ServerStats (test vector t120400_c030_4e8089b08790) and
//           python ja4.py to_ja4s. Extensions stay in PRESENTED order and are NOT
//           GREASE-filtered (both references include GREASE here, unlike JA4).
//   JA4H -- technical_details/JA4H.md is a stub (only the header-count rule). Implemented
//           from zeek/ja4h/main.zeek + the published ja4plus-mapping.csv rows (curl:
//           ge11nn030000_fe444ad14866_000000000000_000000000000), which pin the empty
//           section convention: '000000000000', NOT sha256('') -- see hash12 below.
//   GREASE (RFC 8701, 0x?a?a with equal bytes) is filtered exactly where the specs say.
//
// Fail-closed by contract: every parser returns null on anything unexpected (never a
// guess, never a throw). The ja4* builders return null on a non-object input.

import crypto from 'node:crypto';

const sha256hex = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');

// JA4+ empty-section convention: a section with NO values is the literal '000000000000',
// never the sha256 of an empty string. (JA4.md for _b_/_c_; zeek sha256_or_null__12; the
// published CSV rows. The Rust CLI's hash12('') would give e3b0c44298fc -- spec + CSV win.)
export function hash12(s) {
  return s ? sha256hex(s).slice(0, 12) : '000000000000';
}

// GREASE (RFC 8701): the 16 values 0x0a0a, 0x1a1a, ... 0xfafa -- both bytes equal, low
// nibble 0xa in each.
export function isGrease(v) {
  return Number.isInteger(v) && (v & 0x0f0f) === 0x0a0a && (v & 0xff) === ((v >> 8) & 0xff);
}

const hex4 = (v) => v.toString(16).padStart(4, '0');

// TLS version -> JA4 2-char code (JA4.md table). TCP TLS only in this engine, so the
// DTLS codes (d1/d2/d3) are intentionally absent.
const TLS_VERSION_CODES = { 0x0304: '13', 0x0303: '12', 0x0302: '11', 0x0301: '10', 0x0300: 's3', 0x0002: 's2' };
const versionCode = (v) => TLS_VERSION_CODES[v] || '00';

// --- TLS wire parsing (record framing -> handshake framing -> hello body) ---

// The first TLS record in a buffer: { contentType, version, body } or null. Extra bytes
// after the first record are ignored (a capture may carry the next flight's records).
function firstRecord(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 5) return null;
  const len = buf.readUInt16BE(3);
  if (buf.length < 5 + len) return null;
  return { contentType: buf.readUInt8(0), version: buf.readUInt16BE(1), body: buf.subarray(5, 5 + len) };
}

// The first handshake message of `type` inside a handshake record body, or null.
function firstHandshake(body, type) {
  if (!body || body.length < 4) return null;
  if (body.readUInt8(0) !== type) return null;
  const len = body.readUIntBE(1, 3);
  if (body.length < 4 + len) return null;
  return body.subarray(4, 4 + len);
}

// Shared extension-block walk: [type(2) len(2) data]*, exact-fit required. Returns
// { types:[...], data:Map(type->Buffer) } or null. Duplicate types keep the first data.
function parseExtensions(hs, off) {
  const types = [];
  const data = new Map();
  if (off === hs.length) return { types, data };           // no extensions block (legal pre-TLS1.3)
  if (off + 2 > hs.length) return null;
  const extLen = hs.readUInt16BE(off); off += 2;
  if (off + extLen !== hs.length) return null;             // must fit exactly -- trailing junk = not ours
  const end = off + extLen;
  while (off + 4 <= end) {
    const type = hs.readUInt16BE(off), len = hs.readUInt16BE(off + 2); off += 4;
    if (off + len > end) return null;
    types.push(type);
    if (!data.has(type)) data.set(type, hs.subarray(off, off + len));
    off += len;
  }
  if (off !== end) return null;
  return { types, data };
}

// Parse a TLS ClientHello (one record's worth) into
// { version, ciphers:[int], extensions:[int], sni, alpn:[str], sigalgs:[int] } or null.
export function parseClientHello(buf) {
  const rec = firstRecord(buf);
  if (!rec || rec.contentType !== 22) return null;
  const hs = firstHandshake(rec.body, 1);                  // client_hello
  if (!hs || hs.length < 34) return null;
  let off = 0;
  const clientVersion = hs.readUInt16BE(off); off += 2;    // legacy_version
  off += 32;                                               // random
  if (off >= hs.length) return null;
  const sidLen = hs.readUInt8(off); off += 1;
  if (off + sidLen + 2 > hs.length) return null;
  off += sidLen;                                           // legacy_session_id
  const cipherLen = hs.readUInt16BE(off); off += 2;
  if (cipherLen < 2 || cipherLen % 2 !== 0 || off + cipherLen > hs.length) return null;
  const ciphers = [];
  for (let i = 0; i < cipherLen; i += 2) ciphers.push(hs.readUInt16BE(off + i));
  off += cipherLen;
  if (off >= hs.length) return null;
  const compLen = hs.readUInt8(off); off += 1;
  if (compLen < 1 || off + compLen > hs.length) return null;
  off += compLen;                                          // compression_methods
  const ext = parseExtensions(hs, off);
  if (!ext) return null;

  // SNI (0x0000): the first DNS host name, for reporting; JA4 keys on extension PRESENCE.
  let sni = null;
  const sniData = ext.data.get(0x0000);
  if (sniData) {
    if (sniData.length < 2) return null;
    const listLen = sniData.readUInt16BE(0);
    if (2 + listLen !== sniData.length) return null;
    let p = 2;
    while (p < sniData.length) {
      if (p + 3 > sniData.length) return null;
      const nameType = sniData.readUInt8(p), nameLen = sniData.readUInt16BE(p + 1); p += 3;
      if (p + nameLen > sniData.length) return null;
      if (nameType === 0 && sni === null) sni = sniData.subarray(p, p + nameLen).toString('utf8');
      p += nameLen;
    }
  }

  // ALPN (0x0010): protocol_name_list = listLen(2) [len(1) bytes]*.
  const alpn = [];
  const alpnData = ext.data.get(0x0010);
  if (alpnData) {
    if (alpnData.length < 2) return null;
    const listLen = alpnData.readUInt16BE(0);
    if (2 + listLen !== alpnData.length) return null;
    let p = 2;
    while (p < alpnData.length) {
      const l = alpnData.readUInt8(p); p += 1;
      if (p + l > alpnData.length) return null;
      alpn.push(alpnData.subarray(p, p + l).toString('latin1'));
      p += l;
    }
  }

  // supported_versions (0x002b), CLIENT form: listLen(1) + versions(2)*. True version =
  // the highest non-GREASE offer; without the extension, the legacy_version field.
  let version = clientVersion;
  const svData = ext.data.get(0x002b);
  if (svData) {
    if (svData.length < 1) return null;
    const l = svData.readUInt8(0);
    if (l < 2 || l % 2 !== 0 || 1 + l !== svData.length) return null;
    let best = null;
    for (let i = 0; i < l; i += 2) {
      const v = svData.readUInt16BE(1 + i);
      if (!isGrease(v) && (best === null || v > best)) best = v;
    }
    if (best !== null) version = best;
  }

  // signature_algorithms (0x000d): listLen(2) + algorithms(2)*.
  const sigalgs = [];
  const saData = ext.data.get(0x000d);
  if (saData) {
    if (saData.length < 2) return null;
    const l = saData.readUInt16BE(0);
    if (l < 2 || l % 2 !== 0 || 2 + l !== saData.length) return null;
    for (let i = 0; i < l; i += 2) sigalgs.push(saData.readUInt16BE(2 + i));
  }

  return { version, ciphers, extensions: ext.types, sni, alpn, sigalgs };
}

// Parse a TLS ServerHello into { version, cipher, extensions:[int], alpn } or null.
export function parseServerHello(buf) {
  const rec = firstRecord(buf);
  if (!rec || rec.contentType !== 22) return null;
  const hs = firstHandshake(rec.body, 2);                  // server_hello
  if (!hs || hs.length < 38) return null;
  let off = 0;
  const serverVersion = hs.readUInt16BE(off); off += 2;    // legacy_version
  off += 32;                                               // random
  if (off >= hs.length) return null;
  const sidLen = hs.readUInt8(off); off += 1;
  if (off + sidLen + 3 > hs.length) return null;
  off += sidLen;
  const cipher = hs.readUInt16BE(off); off += 2;           // the ONE chosen cipher
  off += 1;                                                // compression_method
  const ext = parseExtensions(hs, off);
  if (!ext) return null;

  // supported_versions (0x002b), SERVER form: exactly one 2-byte selected version.
  let version = serverVersion;
  const svData = ext.data.get(0x002b);
  if (svData) {
    if (svData.length !== 2) return null;
    version = svData.readUInt16BE(0);
  }

  // ALPN (0x0010): the server picks exactly one protocol (same list framing).
  let alpn = null;
  const alpnData = ext.data.get(0x0010);
  if (alpnData) {
    if (alpnData.length < 3) return null;
    const listLen = alpnData.readUInt16BE(0);
    if (2 + listLen !== alpnData.length) return null;
    const l = alpnData.readUInt8(2);
    if (3 + l > alpnData.length) return null;
    alpn = alpnData.subarray(3, 3 + l).toString('latin1');
  }

  return { version, cipher, extensions: ext.types, alpn };
}

// --- JA4 / JA4S (TLS fingerprints) ---

// JA4 _a_ ALPN code: first + last char of the FIRST ALPN value ('00' when absent/empty; a
// single-char value is both first and last). When either edge byte is not ASCII
// alphanumeric, JA4.md hex-encodes the value and takes the first/last hex chars instead
// (examples: 0x20 0x61 -> '21', 0x30 0x31 0xAB 0xCD -> '3d').
// AMBIGUITY (noted, corner never reached in practice): the spec's last example
// (0x30 0xAB 0xCD 0x31 -> '01') contradicts its own hex rule, which yields '31'; the Rust
// and Python references use a simpler non-ASCII -> '9' rule instead. IANA-registered ALPN
// ids are always printable ASCII, so this path is unreachable for real traffic; we follow
// the hex rule that satisfies 7 of the 8 documented examples.
export function alpnCode(first) {
  if (!first) return '00';
  const bytes = Buffer.from(String(first), 'latin1');
  const alnum = (b) => (b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x5a) || (b >= 0x61 && b <= 0x7a);
  const f = bytes[0], l = bytes[bytes.length - 1];
  if (alnum(f) && alnum(l)) return String.fromCharCode(f) + String.fromCharCode(l);
  const hex = bytes.toString('hex');
  return hex[0] + hex[hex.length - 1];
}

// JA4: t + ver(2) + sni(d/i) + cipherCount(2) + extCount(2) + alpn(2)
//      _ hash12(sorted cipher hex) _ hash12(sorted ext hex excl. SNI+ALPN '_' sigalgs as presented)
export function ja4(ch) {
  if (!ch || typeof ch !== 'object') return null;
  const ciphers = (ch.ciphers || []).filter((v) => !isGrease(v));
  const exts = (ch.extensions || []).filter((v) => !isGrease(v));
  const sigalgs = (ch.sigalgs || []).filter((v) => !isGrease(v));
  // 't' = TLS over TCP; QUIC ('q') / DTLS ('d') are out of scope -- parseClientHello only
  // ever sees a TCP TLS record.
  const a = 't'
    + versionCode(ch.version)
    + (exts.includes(0x0000) ? 'd' : 'i')                    // SNI extension present = domain
    + String(Math.min(ciphers.length, 99)).padStart(2, '0')
    + String(Math.min(exts.length, 99)).padStart(2, '0')     // count INCLUDES SNI + ALPN (JA4.md)
    + alpnCode((ch.alpn || [])[0]);
  const b = hash12(ciphers.map(hex4).sort().join(','));
  // The extension hash list EXCLUDES SNI (0000) and ALPN (0010) -- already captured in _a_.
  const extList = exts.map(hex4).sort().filter((h) => h !== '0000' && h !== '0010');
  const sigList = sigalgs.map(hex4).join(',');
  // No sigalgs -> the string ends WITHOUT the underscore (JA4.md).
  const c = hash12(extList.join(',') + (sigList ? '_' + sigList : ''));
  return a + '_' + b + '_' + c;
}

// JA4S: t + ver(2) + extCount(2, ALL extensions -- GREASE is NOT filtered server-side in
// either reference) + alpn(2) _ cipher hex(4) _ hash12(extension hex in PRESENTED order).
export function ja4s(sh) {
  if (!sh || typeof sh !== 'object') return null;
  const exts = sh.extensions || [];
  const a = 't'
    + versionCode(sh.version)
    + String(Math.min(exts.length, 99)).padStart(2, '0')
    + alpnCode(sh.alpn);
  return a + '_' + hex4(sh.cipher >>> 0) + '_' + hash12(exts.map(hex4).join(','));
}

// --- JA4H + header shape (HTTP fingerprints) ---

// JA4H (zeek main.zeek + the published CSV -- the .md stub carries only the count rule):
//   a = method(2) + version(2) + cookie(c/n) + referer(r/n) + headerCount(2) + lang(4)
//   b = hash12(header names, SENT order + SENT case, excl. Cookie + Referer)
//   c = hash12(cookie NAMES sorted)        ('000000000000' when no cookies)
//   d = hash12(cookie 'name=value' sorted) ('000000000000' when no cookies)
// headers = ordered [name, value] pairs (node's req.rawHeaders reshaped).
export function ja4h({ method, httpVersion, headers } = {}) {
  if (!Array.isArray(headers)) return null;
  const pairs = headers.filter((h) => Array.isArray(h) && h.length >= 2);
  const names = pairs.map(([n]) => String(n));
  const lower = names.map((n) => n.toLowerCase());
  const has = (n) => lower.includes(n);
  const value = (n) => { const i = lower.indexOf(n); return i < 0 ? null : String(pairs[i][1]); };

  // Method: lowercase first two chars (python ja4h.py). Zeek maps unknown methods to 'un';
  // the two agree on every standard method. Empty -> 'un' (zeek default).
  const m = method ? String(method).toLowerCase().slice(0, 2) : 'un';
  const VERSION_CODES = { '1.0': '10', 1.0: '10', 1.1: '11', '1.1': '11', 2: '20', '2.0': '20', 3: '30', '3.0': '30' };
  const v = VERSION_CODES[httpVersion] || VERSION_CODES[String(httpVersion)] || '00';
  // Cookie flag on header PRESENCE (rust http.rs); zeek uses non-empty value -- an empty
  // Cookie header is a corner that changes nothing else (no pairs -> zero hashes either way).
  const cookie = has('cookie') ? 'c' : 'n';
  const referer = has('referer') ? 'r' : 'n';

  // Primary Accept-Language: first token, hyphens stripped, lowercased, exactly 4 chars
  // zero-padded ('en-US,en;q=0.9' -> 'enus'); absent -> '0000'.
  let lang = '0000';
  const langRaw = value('accept-language');
  if (langRaw) lang = (langRaw.trimStart().split(',')[0].replace(/-/g, '').toLowerCase() + '0000').slice(0, 4);

  const kept = names.filter((n) => { const l = n.toLowerCase(); return l !== 'cookie' && l !== 'referer'; });
  const count = String(Math.min(kept.length, 99)).padStart(2, '0');
  const b = hash12(kept.join(','));

  // Cookies: split the Cookie header value(s) on ';', trim, name = before the first '='.
  let c = '000000000000', d = '000000000000';
  if (has('cookie')) {
    const raw = pairs.filter((_, i) => lower[i] === 'cookie').map((p) => String(p[1])).join('; ');
    const cookiePairs = raw.split(';').map((s) => s.trim()).filter(Boolean);
    if (cookiePairs.length) {
      c = hash12(cookiePairs.map((p) => p.split('=')[0].trim()).sort().join(','));
      d = hash12(cookiePairs.slice().sort().join(','));
    }
  }

  return m + v + cookie + referer + count + lang + '_' + b + '_' + c + '_' + d;
}

// The raw shape facts a stack classifier keys on, from ordered [name, value] pairs.
export function httpShape(headers) {
  const pairs = Array.isArray(headers) ? headers.filter((h) => Array.isArray(h) && h.length >= 2) : [];
  const orderedNames = pairs.map(([n]) => String(n));
  const lower = orderedNames.map((n) => n.toLowerCase());
  const has = (n) => lower.includes(n);
  return {
    count: pairs.length,
    hasUA: has('user-agent'),
    hasAccept: has('accept'),
    hasAcceptLanguage: has('accept-language'),
    hasExpect: has('expect'),
    customXHeaders: orderedNames.filter((n) => n.toLowerCase().startsWith('x-')),
    orderedNames,
  };
}

const BROWSER_UA = /mozilla|chrome|safari|firefox|edg\//i;

// House-style findings over one request's shape (+ optionally the UA the client CLAIMS).
// Deterministic, severity-ordered (high then med), deduped by ref. These REPORT shape
// facts; they are never a stealth verdict.
export function fingerprintFindings({ shape, claimedUA } = {}) {
  if (!shape || typeof shape !== 'object') return [];
  const findings = [];
  const seen = new Set();
  const add = (sev, ref, title) => { if (!seen.has(ref)) { seen.add(ref); findings.push({ sev, title, ref }); } };
  const browserClaim = BROWSER_UA.test(String(claimedUA || ''));
  const xHeaders = shape.customXHeaders || [];

  // high: a static minimal header set with no UA is a scripted-client signature.
  // (count 0 = no measurement at all -- a garbage req is NOT a fingerprintable client.)
  if (shape.count >= 1 && shape.count <= 5 && !shape.hasUA) {
    add('high', 'FP-HTTP-MINIMAL', 'static minimal header set (' + shape.count + ' headers, no User-Agent) -- a scripted-client shape, not a browser');
  }
  // high: claiming a browser UA while the shape lacks browser-invariant traits.
  if (browserClaim && (!shape.hasAccept || xHeaders.length > 0)) {
    const why = [
      shape.hasAccept ? null : 'no Accept header (every stock browser sends one)',
      xHeaders.length ? 'custom x-* headers no stock browser sends (' + xHeaders.join(', ') + ')' : null,
    ].filter(Boolean).join('; ');
    add('high', 'FP-UA-MISMATCH', 'claimed UA asserts a browser but the wire shape does not match one: ' + why);
  }
  // med: Expect: 100-continue on every POST is the .NET WebClient signature.
  if (shape.hasExpect) add('med', 'FP-EXPECT', 'Expect: 100-continue on POST -- the .NET System.Net.WebClient signature');
  // med: a static custom x-* set on every request is a protocol marker.
  if (xHeaders.length > 0) add('med', 'FP-XHEADERS', 'static custom x-* header set on every request: ' + xHeaders.join(', '));
  // med: a browser UA without Accept-Language is a bot tell (JA4H doctrine).
  if (browserClaim && !shape.hasAcceptLanguage) add('med', 'FP-LANG', 'browser UA without Accept-Language -- interactive browsers always send one');
  return findings;
}
