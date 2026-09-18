// VARVEL -- selfview: the defender-view self-classifier + JARM prober (pure logic).
//
// Why it exists (gap#8): before an engagement, a nation-grade platform must MEASURE its
// own infrastructure the way internet-wide defenders (Censys/Shodan) already see it --
// the cert it presents, the TLS stack shape its ServerHellos betray, the banners and
// body markers its HTTP listeners leak, and the egress ASN/org it talks from. This
// engine is the PURE half: observations in, house-style findings out, plus a faithful
// JARM (Salesforce) active TLS fingerprint prober. The I/O shell is tools/preflight.mjs.
//
// THE HONESTY CONTRACT (non-negotiable, same doctrine as detoracle/fporacle): every
// finding is a MEASUREMENT of what a scanner would observe, never a stealth verdict and
// never a claim of undetectability. Fail-closed: malformed observations classify as
// little as possible; the JARM parsers return the empty outcome on garbage, never throw.
//
// JARM spec fidelity: implemented from the reference source (salesforce/jarm jarm.py,
// BSD 3-Clause, pulled 2026-08-05): the exact 10 crafted ClientHellos (cipher lists,
// munge orders, GREASE placement, ALPN lists, extension order), the exact raw-result
// extraction (cipher | legacy version | alpn | extension-type list), and the exact
// 62-char hybrid fuzzy hash (10 x (2-char cipher index + 1-char version letter) +
// sha256(alpns+extensions)[0:32]). Deliberate quirks of the reference are reproduced
// VERBATIM where they shape the hash (unknown cipher -> index 70 '46'; the empty-result
// hash is 62 zeros; the two magic-byte extension bail-outs).

import crypto from 'node:crypto';

const sha256hex = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
const hex4 = (v) => v.toString(16).padStart(4, '0');

// ---------------------------------------------------------------------------
// Part 1: the classifier. observations -> house-style findings ({sev,title,ref},
// severity-ordered, deduped by ref). Every title carries its evidence inline.
// ---------------------------------------------------------------------------

const SEV_RANK = { crit: 0, high: 1, med: 2, low: 3, info: 4 };

// Names that fingerprint OUR toolset to any observer. 'c2' is deliberately broad: the
// point is to catch our own fingerprints (varvel, enclave, the doh lab cert, redteam
// labels) before a defender does -- a false positive here costs a finding, a miss costs
// attribution.
export const TOOLSET_RE = /varvel|enclave|doh-lab|c2|redteam/i;

// Ports a scanner considers ordinary service ports; anything else observed listening is
// an informational exposure fact (PV-PORT-OPEN).
const STANDARD_PORTS = new Set([80, 443, 853, 8080, 8443]);

// Issuer names of publicly-trusted CAs whose certs are (near-)certainly CT-logged.
// Used ONLY to classify CT-log likelihood; an unmatched issuer is 'unknown', never
// assumed private.
const PUBLIC_CA_RE = /let'?s encrypt|\bisrg\b|digicert|sectigo|comodo|globalsign|godaddy|starfield|entrust|google trust services|amazon|rapidssl|geotrust|thawte|verisign|symantec|baltimore|usertrust|zerossl|buypass|ssl\.com|certum|actalis|swisssign|identrust|harica/i;

// CT-log likelihood from the cert alone (no crt.sh query -- classification, honestly
// labeled as such): public-CA issuer -> 'likely-indexed'; self-signed -> 'not-indexed';
// anything else -> 'unknown' (fail-closed, no guessing).
export function ctLogClass(cert) {
  if (!cert || typeof cert !== 'object') return 'unknown';
  if (cert.selfSigned) return 'not-indexed';
  if (PUBLIC_CA_RE.test(String(cert.issuer || ''))) return 'likely-indexed';
  return 'unknown';
}

// The JA4S shape of a programmatic Node.js-class TLS stack answering our fixed probe:
// TLS1.3 ('t13') with a minimal (single-digit) extension count. Stock web servers
// (nginx/Apache/HAProxy) answer with larger, configuration-flavored extension sets; a
// bare node https server answers supported_versions + key_share and little else.
function nodeishJa4s(ja4s) {
  const m = /^t13(\d{2})(\d{2})/.exec(String(ja4s || ''));
  return !!m && parseInt(m[1], 10) <= 9;
}

const fmtPorts = (ports) => [...new Set(ports)].sort((a, b) => a - b).map((p) => ':' + p).join(', ');

// viewFindings(observations) -- the locked rule set:
//   observations = {
//     tls:  [ { port, ja4s, cert: { selfSigned, cn, san, issuer, validTo }, tlsFindings } ],
//     http: [ { port, status, serverHeader, headers: [names], bodyMarkers: [strings] } ],
//     egress: { ip, org, asn } | null,
//     ctLog: 'likely-indexed' | 'not-indexed' | 'unknown',
//     openPorts: [ints] -- ADDITIVE extension: ports observed TCP-open that answered
//       neither TLS nor HTTP from this source. A SYN scan (Censys) still sees them, so
//       PV-PORT-OPEN counts them; leaving them out would UNDER-report exposure.
//   }
export function viewFindings(observations = {}) {
  const obs = observations && typeof observations === 'object' ? observations : {};
  const tls = Array.isArray(obs.tls) ? obs.tls : [];
  const http = Array.isArray(obs.http) ? obs.http : [];
  const findings = [];
  const seen = new Set();
  const add = (sev, ref, title) => { if (!seen.has(ref)) { seen.add(ref); findings.push({ sev, title, ref }); } };

  // PV-CERT-CN-LEAK (high): the cert identity itself names the toolset. This WILL fire
  // on our own lab cert (CN=varvel-doh-lab.local) -- that is the point of the rule.
  const leakPorts = [], leakHits = new Set();
  for (const t of tls) {
    const c = t && t.cert;
    if (!c) continue;
    const hay = [c.cn, c.san, c.issuer].map((s) => String(s || '')).join(' ');
    const m = TOOLSET_RE.exec(hay);
    if (m) { leakPorts.push(t.port); leakHits.add(String(m[0]).toLowerCase()); }
  }
  if (leakPorts.length) {
    add('high', 'PV-CERT-CN-LEAK', 'certificate identity names the toolset (' + [...leakHits].join(', ') + ') on listener(s) ' + fmtPorts(leakPorts) + ' -- internet-wide scanners index certs; the CN/SAN alone fingerprints this infrastructure');
  }

  // PV-BANNER-TOOL (high): a response header value or a body marker names the toolset.
  const bannerPorts = [], bannerHits = new Set();
  for (const h of http) {
    if (!h) continue;
    const server = String(h.serverHeader || '');
    const m = server ? TOOLSET_RE.exec(server) : null;
    const markers = Array.isArray(h.bodyMarkers) ? h.bodyMarkers : [];
    if (m || markers.length) {
      bannerPorts.push(h.port);
      if (m) bannerHits.add('server header "' + server.slice(0, 60) + '"');
      for (const mk of markers.slice(0, 4)) bannerHits.add('body marker "' + String(mk).slice(0, 40) + '"');
    }
  }
  if (bannerPorts.length) {
    add('high', 'PV-BANNER-TOOL', 'response content names the toolset on listener(s) ' + fmtPorts(bannerPorts) + ': ' + [...bannerHits].slice(0, 5).join('; ') + ' -- a scanner matches this content with zero authentication');
  }

  // PV-CERT-SELFSIGNED (med): a self-signed cert on a listener is a Censys-visible tell.
  const ssPorts = tls.filter((t) => t && t.cert && t.cert.selfSigned).map((t) => t.port);
  if (ssPorts.length) {
    add('med', 'PV-CERT-SELFSIGNED', 'self-signed certificate on listener(s) ' + fmtPorts(ssPorts) + ' -- publicly-trusted services almost never present one; a scanner-visible tell');
  }

  // PV-JA4S-STACK (med): JA4S consistent with a Node.js-class TLS stack, not a stock
  // web server shape.
  const nodePorts = tls.filter((t) => t && nodeishJa4s(t.ja4s));
  if (nodePorts.length) {
    add('med', 'PV-JA4S-STACK', 'JA4S consistent with a programmatic Node.js-class TLS stack (TLS1.3, minimal extension set) on listener(s) ' + fmtPorts(nodePorts.map((t) => t.port)) + ' [' + nodePorts.map((t) => t.ja4s).join(', ') + '] -- not a stock web-server shape');
  }

  // PV-CTLOG (med): a public-CA cert is almost certainly CT-indexed, so the listener is
  // pre-discoverable. Self-signed -> 'not-indexed' -> NO finding. 'unknown' -> none either
  // (we never claim indexing we did not verify).
  if (obs.ctLog === 'likely-indexed') {
    const issuer = tls.map((t) => t && t.cert && t.cert.issuer).find((i) => i && PUBLIC_CA_RE.test(String(i))) || 'a public CA';
    add('med', 'PV-CTLOG', 'certificate issued by ' + issuer + ' (a public CA) -- almost certainly CT-log indexed: this listener is pre-discoverable via crt.sh/Censys before the engagement begins');
  }

  // PV-PORT-OPEN (info): non-standard listening ports observed -- scan-visible fact.
  // Includes openPorts (TCP-open but protocol-silent): a SYN scan sees those too.
  const nonStd = [...tls, ...http].map((x) => x && x.port)
    .concat(Array.isArray(obs.openPorts) ? obs.openPorts : [])
    .filter((p) => Number.isInteger(p) && !STANDARD_PORTS.has(p));
  if (nonStd.length) {
    add('info', 'PV-PORT-OPEN', 'non-standard listening port(s) observed: ' + fmtPorts(nonStd) + ' -- scan-visible fact (Censys/Shodan index these); informational');
  }

  // PV-EGRESS-CLASS (info): the free egress classification observed. ALWAYS paired with
  // the note that paid proxy/VPN classification feeds are NOT covered.
  if (obs.egress && typeof obs.egress === 'object') {
    const e = obs.egress;
    const org = String(e.org || '').trim();
    const asn = String(e.asn || '').trim();
    add('info', 'PV-EGRESS-CLASS', 'egress classification observed (free feed): ' + (e.ip || '?') + (org ? ' -- ' + org : '') + (asn && !org.includes(asn) ? ' (' + asn + ')' : '') + '. NOTE: paid proxy/VPN classification feeds are NOT covered by this check');
  }

  return findings.sort((a, b) => (SEV_RANK[a.sev] ?? 9) - (SEV_RANK[b.sev] ?? 9));
}

// ---------------------------------------------------------------------------
// Part 2: JARM -- the pure prober per the Salesforce spec.
// ---------------------------------------------------------------------------

// The two cipher lists (hex, spec order). ALL carries the TLS1.3 suites; NO1.3 omits them.
const ALL_CIPHER_HEX = '0016 0033 0067 c09e c0a2 009e 0039 006b c09f c0a3 009f 0045 00be 0088 00c4 009a c008 c009 c023 c0ac c0ae c02b c00a c024 c0ad c0af c02c c072 c073 cca9 1302 1301 cc14 c007 c012 c013 c027 c02f c014 c028 c030 c060 c061 c076 c077 cca8 1305 1304 1303 cc13 c011 000a 002f 003c c09c c0a0 009c 0035 003d c09d c0a1 009d 0041 00ba 0084 00c0 0007 0004 0005';
const NO13_CIPHER_HEX = '0016 0033 0067 c09e c0a2 009e 0039 006b c09f c0a3 009f 0045 00be 0088 00c4 009a c008 c009 c023 c0ac c0ae c02b c00a c024 c0ad c0af c02c c072 c073 cca9 cc14 c007 c012 c013 c027 c02f c014 c028 c030 c060 c061 c076 c077 cca8 cc13 c011 000a 002f 003c c09c c0a0 009c 0035 003d c09d c0a1 009d 0041 00ba 0084 00c0 0007 0004 0005';
// The sorted fuzzy table: a chosen cipher hashes to its 1-based index (hex, 2 chars).
const FUZZY_CIPHER_HEX = '0004 0005 0007 000a 0016 002f 0033 0035 0039 003c 003d 0041 0045 0067 006b 0084 0088 009a 009c 009d 009e 009f 00ba 00be 00c0 00c4 c007 c008 c009 c00a c011 c012 c013 c014 c023 c024 c027 c028 c02b c02c c02f c030 c060 c061 c072 c073 c076 c077 c09c c09d c09e c09f c0a0 c0a1 c0a2 c0a3 c0ac c0ad c0ae c0af cc13 cc14 cca8 cca9 1301 1302 1303 1304 1305';
const ALL_CIPHERS = ALL_CIPHER_HEX.split(' ');
const NO13_CIPHERS = NO13_CIPHER_HEX.split(' ');
const FUZZY_CIPHERS = FUZZY_CIPHER_HEX.split(' ');

// ALPN protocol lists (spec order, weakest to strongest). RARE removes h2 and http/1.1.
const ALPN_COMMON = ['http/0.9', 'http/1.0', 'http/1.1', 'spdy/1', 'spdy/2', 'spdy/3', 'h2', 'h2c', 'hq'];
const ALPN_RARE = ['http/0.9', 'http/1.0', 'spdy/1', 'spdy/2', 'spdy/3', 'h2c', 'hq'];

// The 10 probes, spec order. [name, tlsVersion, cipherList, cipherOrder, grease, alpnList, supportedVersions, extensionOrder]
const JARM_PROBE_SPECS = [
  ['tls1.2-forward', 'TLS_1.2', 'ALL', 'FORWARD', false, 'APLN', '1.2_SUPPORT', 'REVERSE'],
  ['tls1.2-reverse', 'TLS_1.2', 'ALL', 'REVERSE', false, 'APLN', '1.2_SUPPORT', 'FORWARD'],
  ['tls1.2-top-half', 'TLS_1.2', 'ALL', 'TOP_HALF', false, 'APLN', 'NO_SUPPORT', 'FORWARD'],
  ['tls1.2-bottom-half', 'TLS_1.2', 'ALL', 'BOTTOM_HALF', false, 'RARE_APLN', 'NO_SUPPORT', 'FORWARD'],
  ['tls1.2-middle-out', 'TLS_1.2', 'ALL', 'MIDDLE_OUT', true, 'RARE_APLN', 'NO_SUPPORT', 'REVERSE'],
  ['tls1.1-middle-out', 'TLS_1.1', 'ALL', 'FORWARD', false, 'APLN', 'NO_SUPPORT', 'FORWARD'],
  ['tls1.3-forward', 'TLS_1.3', 'ALL', 'FORWARD', false, 'APLN', '1.3_SUPPORT', 'REVERSE'],
  ['tls1.3-reverse', 'TLS_1.3', 'ALL', 'REVERSE', false, 'APLN', '1.3_SUPPORT', 'FORWARD'],
  ['tls1.3-invalid', 'TLS_1.3', 'NO1.3', 'FORWARD', false, 'APLN', '1.3_SUPPORT', 'FORWARD'],
  ['tls1.3-middle-out', 'TLS_1.3', 'ALL', 'MIDDLE_OUT', true, 'APLN', '1.3_SUPPORT', 'REVERSE'],
];

// cipher_mung, verbatim from jarm.py: REVERSE / BOTTOM_HALF / TOP_HALF / MIDDLE_OUT
// (anything else = FORWARD, the list as given). Works on any array (ciphers, ALPNs,
// supported versions).
function cipherMung(list, order) {
  const n = list.length;
  const half = Math.floor(n / 2);
  if (order === 'REVERSE') return list.slice().reverse();
  if (order === 'BOTTOM_HALF') return n % 2 === 1 ? list.slice(half + 1) : list.slice(half);
  if (order === 'TOP_HALF') {
    // Top half gets the middle cipher when odd, then the reversed list's bottom half.
    const out = n % 2 === 1 ? [list[half]] : [];
    return out.concat(cipherMung(cipherMung(list, 'REVERSE'), 'BOTTOM_HALF'));
  }
  if (order === 'MIDDLE_OUT') {
    const out = [];
    if (n % 2 === 1) {
      out.push(list[half]);
      for (let i = 1; i <= half; i++) { out.push(list[half + i]); out.push(list[half - i]); }
    } else {
      for (let i = 1; i <= half; i++) { out.push(list[half - 1 + i]); out.push(list[half - i]); }
    }
    return out;
  }
  return list.slice();
}

// RFC 8701 GREASE, chosen randomly per use exactly like jarm.py's choose_grease().
function chooseGrease() {
  const b = (crypto.randomInt(16) << 4) | 0x0a;
  return (b << 8) | b;
}

const RECORD_VERSION = { 'TLS_1.3': 0x0301, 'TLS_1.2': 0x0303, 'TLS_1.1': 0x0302, 'TLS_1': 0x0301, SSLv3: 0x0300 };
const CLIENT_VERSION = { 'TLS_1.3': 0x0303, 'TLS_1.2': 0x0303, 'TLS_1.1': 0x0302, 'TLS_1': 0x0301, SSLv3: 0x0300 };

// Build ONE crafted ClientHello (full TLS record) for a probe spec. Random fields
// (client random, session id, key share, GREASE picks) are random per call, exactly as
// the reference does -- the server's ANSWER does not depend on them, so hashes are
// stable run over run.
function buildProbePacket(host, spec) {
  const [, version, cipherList, cipherOrder, grease, alpnList, support, extOrder] = spec;
  const u16 = (v) => Buffer.from([(v >> 8) & 0xff, v & 0xff]);
  const u24 = (v) => Buffer.from([(v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff]);

  // Ciphers: munge the list, then GREASE rides position 0 when the probe calls for it.
  let ciphers = cipherMung(cipherList === 'ALL' ? ALL_CIPHERS : NO13_CIPHERS, cipherOrder);
  if (grease) ciphers = [hex4(chooseGrease()), ...ciphers];
  const cipherBytes = Buffer.from(ciphers.join(''), 'hex');

  // Extensions, spec order: GREASE?, SNI, EMS, max_fragment, renegotiation_info,
  // supported_groups, ec_point_formats, session_ticket, ALPN, sigalgs, key_share,
  // psk_modes, supported_versions (conditional).
  const exts = [];
  if (grease) exts.push(Buffer.concat([u16(chooseGrease()), u16(0)]));
  const sni = Buffer.from(String(host), 'utf8');
  exts.push(Buffer.concat([u16(0x0000), u16(sni.length + 5), u16(sni.length + 3), Buffer.from([0]), u16(sni.length), sni]));
  exts.push(Buffer.from('00170000', 'hex'));                 // extended_master_secret
  exts.push(Buffer.from('0001000101', 'hex'));               // max_fragment_length: 1
  exts.push(Buffer.from('ff01000100', 'hex'));               // renegotiation_info
  exts.push(Buffer.from('000a000a0008001d001700180019', 'hex')); // supported_groups: x25519, secp256r1, secp384r1, secp521r1
  exts.push(Buffer.from('000b00020100', 'hex'));             // ec_point_formats: uncompressed
  exts.push(Buffer.from('00230000', 'hex'));                 // session_ticket
  const alpns = cipherMung(alpnList === 'RARE_APLN' ? ALPN_RARE : ALPN_COMMON, extOrder)
    .map((p) => Buffer.concat([Buffer.from([p.length]), Buffer.from(p, 'latin1')]));
  const alpnBody = Buffer.concat(alpns);
  exts.push(Buffer.concat([u16(0x0010), u16(alpnBody.length + 2), u16(alpnBody.length), alpnBody]));
  exts.push(Buffer.from('000d00140012040308040401050308050501080606010201', 'hex')); // signature_algorithms
  const shareParts = [];
  if (grease) shareParts.push(u16(chooseGrease()), u16(1), Buffer.from([0])); // GREASE key share, 1-byte key
  shareParts.push(u16(0x001d), u16(32), crypto.randomBytes(32));              // x25519, random key
  const shareBody = Buffer.concat(shareParts);
  exts.push(Buffer.concat([u16(0x0033), u16(shareBody.length + 2), u16(shareBody.length), shareBody]));
  exts.push(Buffer.from('002d00020101', 'hex'));             // psk_key_exchange_modes: psk_dhe_ke
  if (version === 'TLS_1.3' || support === '1.2_SUPPORT') {
    let versions = support === '1.2_SUPPORT' ? ['0301', '0302', '0303'] : ['0301', '0302', '0303', '0304'];
    versions = cipherMung(versions, extOrder);
    if (grease) versions = [hex4(chooseGrease()), ...versions];
    const vBytes = Buffer.from(versions.join(''), 'hex');
    exts.push(Buffer.concat([u16(0x002b), u16(vBytes.length + 1), Buffer.from([vBytes.length]), vBytes]));
  }

  const extBytes = Buffer.concat(exts);
  const clientHello = Buffer.concat([
    u16(CLIENT_VERSION[version]),
    crypto.randomBytes(32),
    Buffer.from([32]), crypto.randomBytes(32),               // session id: 32 random bytes
    u16(cipherBytes.length), cipherBytes,
    Buffer.from([1, 0]),                                     // compression_methods: null only
    u16(extBytes.length), extBytes,
  ]);
  const handshake = Buffer.concat([Buffer.from([1]), u24(clientHello.length), clientHello]);
  return Buffer.concat([Buffer.from([22]), u16(RECORD_VERSION[version]), u16(handshake.length), handshake]);
}

// jarmProbes(host): the 10 crafted probe ClientHellos, spec order, as
// [{ name, packet }]. Empty host -> [] (fail-closed; SNI cannot be built honestly).
export function jarmProbes(host) {
  if (!host || !String(host).trim()) return [];
  return JARM_PROBE_SPECS.map((spec) => ({ name: spec[0], packet: buildProbePacket(String(host).trim(), spec) }));
}

// ALPN value extraction (reference find_extension for 0x0010): value[3:] decoded.
function extractExtensionInfo(data, counter, serverHelloLength) {
  try {
    // Verbatim jarm.py bail-outs: a Certificate message right after the hello, and the
    // two magic-byte sequences the reference special-cases.
    if (data[counter + 47] === 11) return '|';
    if (data.subarray(counter + 50, counter + 53).equals(Buffer.from('0eac0b', 'hex'))) return '|';
    if (data.subarray(82, 85).equals(Buffer.from('0ff00b', 'hex'))) return '|';
    if (counter + 42 >= serverHelloLength) return '|';
    if (data.length < counter + 49) return '|';
    let count = 49 + counter;
    const length = data.readUInt16BE(counter + 47);
    const maximum = length + count - 1;
    const types = [], values = [];
    while (count < maximum) {
      if (count + 4 > data.length) break;
      types.push(data.subarray(count, count + 2).toString('hex'));
      const extLength = data.readUInt16BE(count + 2);
      if (extLength === 0) { values.push(''); count += 4; }
      else { values.push(data.subarray(count + 4, count + 4 + extLength)); count += extLength + 4; }
    }
    // Verbatim quirk: jarm.py's find_extension returns None when the ALPN ext is absent
    // and extract_extension_info stringifies it -- the literal text "None" rides the
    // hash input. Every public JARM database was built with this behavior, so we keep it.
    let alpn = 'None';
    const ai = types.indexOf('0010');
    if (ai >= 0 && Buffer.isBuffer(values[ai])) alpn = values[ai].subarray(3).toString('latin1');
    return alpn + '|' + types.join('-');
  } catch { return '|'; }
}

// readJarmResponse(data): one ServerHello outcome as the raw "cipher|version|alpn|exts"
// string, or "|||" on alert/refusal/garbage/timeout (the reference's empty outcome).
export function readJarmResponse(data) {
  try {
    if (!Buffer.isBuffer(data) || data.length < 46) return '|||';
    if (data[0] === 21) return '|||';                        // TLS alert
    if (data[0] !== 22 || data[5] !== 2) return '|||';       // not a handshake ServerHello
    const serverHelloLength = data.readUInt16BE(3);          // record length (verbatim)
    const counter = data[43];                                // session id length
    if (data.length < counter + 47) return '|||';
    const cipher = data.subarray(counter + 44, counter + 46).toString('hex');
    const version = data.subarray(9, 11).toString('hex');    // legacy_version (verbatim)
    return cipher + '|' + version + '|' + extractExtensionInfo(data, counter, serverHelloLength);
  } catch { return '|||'; }
}

// cipher_bytes: 1-based index (hex, 2 chars) in the fuzzy table; '' -> '00'; a cipher
// NOT in the table hashes to index 70 -> '46' (verbatim jarm.py loop-end behavior).
function cipherBytes(cipher) {
  if (!cipher) return '00';
  const idx = FUZZY_CIPHERS.indexOf(String(cipher).toLowerCase());
  const count = idx >= 0 ? idx + 1 : FUZZY_CIPHERS.length + 1;
  return count.toString(16).padStart(2, '0');
}

// version_byte: 'abcdef'[4th hex char of the version]; '' or unparseable -> '0'.
function versionByte(version) {
  if (!version) return '0';
  const n = parseInt(String(version)[3], 10);
  return Number.isInteger(n) && n >= 0 && n <= 5 ? 'abcdef'[n] : '0';
}

// jarmDigest(results): the 62-char hybrid fuzzy hash from the 10 raw ServerHello
// outcomes. 30 fuzzy chars (2 cipher + 1 version per probe) + sha256(alpns+exts)[0:32].
// All ten empty -> 62 zeros (the reference's no-answer hash).
export function jarmDigest(results) {
  const raws = (Array.isArray(results) ? results : []).slice(0, 10).map((r) => String(r || '|||'));
  while (raws.length < 10) raws.push('|||');
  if (raws.every((r) => r === '|||')) return '0'.repeat(62);
  let fuzzy = '', alpnsAndExt = '';
  for (const raw of raws) {
    const c = raw.split('|');
    fuzzy += cipherBytes(c[0]) + versionByte(c[1]);
    alpnsAndExt += (c[2] || '') + (c[3] || '');
  }
  return fuzzy + sha256hex(alpnsAndExt).slice(0, 32);
}
