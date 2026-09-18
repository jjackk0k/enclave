// VARVEL — ipaddr: the platform's ONE implementation of IP parsing, classification,
// and CIDR membership.
//
// Why this module exists: scope decisions ARE the security boundary. They used to be
// re-derived per file from hand-rolled IPv4 regexes (callback's ipAllowed, ghost's
// isPrivateDest, recon's ipInScope, the enforcement seam's ipInCidr) — every copy was
// a place IPv6 either failed wrong (authorized v6 scope never matching) or was
// misclassified (ULA/link-local treated as public and proxied, leaking lab topology
// to a proxy operator). One implementation, audited once, imported everywhere.
//
// Contract:
//   · STRICT parsing. v4 dotted-quad rejects out-of-range octets and leading zeros
//     (leading-zero octets parse as OCTAL in some OS resolvers — an SSRF-class scope
//     bypass). v6 accepts full/compressed/embedded-v4 forms and strips [brackets] and
//     %zone suffixes. Anything unparseable is REJECTED, never coerced — scope math
//     that guesses is scope math that lies.
//   · v4-mapped v6 (::ffff:a.b.c.d, dotted or hex notation) IS a v4 address: fam 4.
//     It collapses to the dotted-quad canonical form, so '::ffff:10.10.0.5' is matched
//     by the v4 ring '10.10.0.0/16'.
//   · CIDR membership is FAMILY-STRICT: a v4 CIDR never matches a v6-native address
//     and vice versa. '0.0.0.0/0' is all-v4 and '::/0' is all-v6 — neither silently
//     matches everything (fail-closed: an operator who means both signs both).
//   · Bare addresses are host routes (/32, /128). A trailing slash with no mask is
//     NOT match-all — it is rejected.

// parseIp(input)  -> { fam: 4|6, text: canonical, v4?: uint32, groups?: uint16[8], mapped: bool } | null
// parseCidr(input)-> { fam, bits, v4?: uint32, groups?: uint16[8] } | null
// inCidr(ip, cidr) / inAnyCidr(ip, cidrs) -> bool   (cidrs: array OR comma string)
// isLoopback(ip) / isPrivate(ip) -> bool
// classifyIp(ip)  -> { fam, mapped, text, class } | null   (the explicit address-class API)
// bracketHost(host) -> '[::1]' for v6 literals, else unchanged (URL construction)
// extractIp(text)   -> first canonical IP literal found in free text, or null

const V4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;

// Strict dotted-quad -> uint32, or null. Octets 0-255, no leading zeros.
function parseV4(s) {
  if (!V4_RE.test(s)) return null;
  const o = s.split('.');
  for (const p of o) if (+p > 255 || (p.length > 1 && p[0] === '0')) return null;
  return (((+o[0] << 24) >>> 0) + (+o[1] << 16) + (+o[2] << 8) + (+o[3])) >>> 0;
}

const v4text = (v) => `${v >>> 24}.${(v >>> 16) & 0xff}.${(v >>> 8) & 0xff}.${v & 0xff}`;

// ':'-separated hex groups with no compression; '' -> []. null on any bad group.
function parseGroups(s) {
  if (s === '') return [];
  const parts = s.split(':');
  for (const p of parts) if (!/^[0-9a-fA-F]{1,4}$/.test(p)) return null;
  return parts.map((p) => parseInt(p, 16));
}

// -> uint16[8] or null. Handles '::' compression and an embedded dotted-quad tail
// ('::ffff:1.2.3.4', '::1.2.3.4'). Caller has already stripped brackets/zone.
function parseV6(s) {
  let tail = null;
  if (s.includes('.')) {
    const i = s.lastIndexOf(':');
    if (i < 0) return null;
    const v4 = parseV4(s.slice(i + 1));
    if (v4 === null) return null;
    tail = [(v4 >>> 16) & 0xffff, v4 & 0xffff];
    s = s.slice(0, i);
  }
  const dc = s.indexOf('::');
  if (dc >= 0) {
    if (s.indexOf('::', dc + 2) >= 0) return null; // at most ONE '::'
    const head = parseGroups(s.slice(0, dc));
    const rest = parseGroups(s.slice(dc + 2));
    if (!head || !rest) return null;
    const fill = 8 - head.length - rest.length - (tail ? 2 : 0);
    if (fill < 1) return null; // '::' must elide at least one group
    return [...head, ...Array(fill).fill(0), ...rest, ...(tail || [])];
  }
  const head = parseGroups(s);
  if (!head) return null;
  const groups = [...head, ...(tail || [])];
  return groups.length === 8 ? groups : null;
}

// Canonical v6 text (RFC 5952): lowercase, no leading zeros, the FIRST longest run
// of >=2 zero groups compresses to '::'; a single zero group never does.
function v6text(g) {
  const hex = g.map((x) => x.toString(16));
  let bestAt = -1, bestLen = 0, curAt = -1, curLen = 0;
  for (let i = 0; i < 8; i++) {
    if (g[i] === 0) { if (curAt < 0) { curAt = i; curLen = 1; } else curLen++; }
    else { if (curLen >= 2 && curLen > bestLen) { bestAt = curAt; bestLen = curLen; } curAt = -1; curLen = 0; }
  }
  if (curLen >= 2 && curLen > bestLen) { bestAt = curAt; bestLen = curLen; }
  if (bestAt < 0) return hex.join(':');
  return hex.slice(0, bestAt).join(':') + '::' + hex.slice(bestAt + bestLen).join(':');
}

export function parseIp(input) {
  if (input == null) return null;
  let s = String(input).trim();
  if (!s) return null;
  if (s[0] === '[') { // [v6] — pure bracketed form only; '[::1]:8080' is NOT an address
    const e = s.indexOf(']');
    if (e < 0 || e !== s.length - 1) return null;
    s = s.slice(1, e);
  }
  const zi = s.indexOf('%');
  if (zi >= 0) s = s.slice(0, zi); // zone id scopes the interface, not the address class
  if (!s) return null;
  const v4 = parseV4(s);
  if (v4 !== null) return { fam: 4, v4, mapped: false, text: v4text(v4) };
  if (!s.includes(':')) return null;
  const g = parseV6(s);
  if (!g) return null;
  if (g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 && g[4] === 0 && g[5] === 0xffff) {
    const mv = ((g[6] << 16) | g[7]) >>> 0; // v4-mapped: it IS the v4 address
    return { fam: 4, v4: mv, mapped: true, text: v4text(mv) };
  }
  return { fam: 6, groups: g, mapped: false, text: v6text(g) };
}

export function parseCidr(input) {
  if (input == null) return null;
  const s = String(input).trim();
  if (!s) return null;
  const slash = s.indexOf('/');
  let base = s, bits = null;
  if (slash >= 0) {
    if (s.indexOf('/', slash + 1) >= 0) return null;
    base = s.slice(0, slash);
    const bs = s.slice(slash + 1);
    if (!/^\d{1,3}$/.test(bs)) return null; // empty / non-numeric mask is NOT match-all
    bits = +bs;
  }
  const ip = parseIp(base);
  if (!ip) return null;
  if (ip.mapped) {
    // v4-mapped CIDR: the mask spans the 96-bit mapped prefix + 32 v4 bits, so
    // '/112' is '/16' in v4 terms. A mask shorter than /96 reaches into the mapped
    // prefix itself — not a v4-range statement: rejected.
    if (bits === null) bits = 32;
    else if (bits >= 96 && bits <= 128) bits -= 96;
    else return null;
  } else {
    const max = ip.fam === 4 ? 32 : 128;
    if (bits === null) bits = max; // bare address = host route
    if (bits > max) return null;
  }
  return ip.fam === 4 ? { fam: 4, bits, v4: ip.v4 } : { fam: 6, bits, groups: ip.groups };
}

const byteAt = (g, i) => (g[i >> 1] >> ((i & 1) ? 0 : 8)) & 0xff;

export function inCidr(ipInput, cidrInput) {
  const ip = parseIp(ipInput);
  const c = parseCidr(cidrInput);
  if (!ip || !c || ip.fam !== c.fam) return false; // family-strict, fail-closed
  if (ip.fam === 4) {
    const mask = c.bits === 0 ? 0 : (0xffffffff << (32 - c.bits)) >>> 0;
    return ((ip.v4 & mask) >>> 0) === ((c.v4 & mask) >>> 0);
  }
  const full = c.bits >> 3, rem = c.bits & 7;
  for (let i = 0; i < full; i++) if (byteAt(ip.groups, i) !== byteAt(c.groups, i)) return false;
  if (rem) {
    const m = (0xff << (8 - rem)) & 0xff;
    if ((byteAt(ip.groups, full) & m) !== (byteAt(c.groups, full) & m)) return false;
  }
  return true;
}

export function inAnyCidr(ip, cidrs) {
  const list = Array.isArray(cidrs) ? cidrs : String(cidrs || '').split(',');
  for (const c of list) if (inCidr(ip, c)) return true; // invalid entries never match
  return false;
}

export function isLoopback(ip) {
  const p = parseIp(ip);
  if (!p) return false;
  if (p.fam === 4) return (p.v4 >>> 24) === 127;
  return p.groups.every((g, i) => g === (i === 7 ? 1 : 0));
}

// Private = goes direct, never through an identity chain (ghost) and never treated as
// research egress (enforcement seam): RFC1918 + loopback + link-local, and the v6
// equivalents ULA fc00::/7 + link-local fe80::/10 + ::1. Documentation ranges
// (192.0.2/24, 198.51.100/24, 203.0.113/24, 2001:db8::/32) are NOT private here —
// ghost's test contract treats them as public destinations.
export function isPrivate(ip) {
  const p = parseIp(ip);
  if (!p) return false;
  if (p.fam === 4) {
    const a = p.v4 >>> 24, b = (p.v4 >>> 16) & 0xff;
    return a === 10 || a === 127 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
  }
  const b0 = p.groups[0] >>> 8, b1 = p.groups[0] & 0xff;
  return p.groups.every((g, i) => g === (i === 7 ? 1 : 0)) // ::1
    || (b0 & 0xfe) === 0xfc                                 // fc00::/7  ULA
    || (b0 === 0xfe && (b1 & 0xc0) === 0x80);               // fe80::/10 link-local
}

// Address-class classifier (the explicit-class API): ONE place that names WHAT an
// address IS, so scope/egress decisions consume a class instead of re-deriving octet
// math. Additive — the isLoopback/isPrivate booleans above are the proven contract and
// stay exactly as they are; this classifier agrees with them by construction.
//   v4: 'loopback' (127/8) | 'link-local' (169.254/16) | 'private' (RFC1918) |
//       'documentation' (192.0.2/24, 198.51.100/24, 203.0.113/24) |
//       'unspecified' (0.0.0.0) | 'global' (global unicast — everything else)
//   v6: 'loopback' (::1) | 'ula' (fc00::/7) | 'link-local' (fe80::/10) |
//       'documentation' (2001:db8::/32) | 'unspecified' (::) | 'global'
// v4-mapped v6 classifies AS the v4 address (fam 4, mapped: true — the parseIp contract:
// '::ffff:10.10.0.5' IS 10.10.0.5). 'documentation' is NOT 'private' (the ghost test
// contract treats doc ranges as public destinations) — it is named so policy can decide
// deliberately instead of mis-sorting it either way. Unparseable input: null, never a guess.
export function classifyIp(ip) {
  const p = parseIp(ip);
  if (!p) return null;
  let cls = 'global';
  if (p.fam === 4) {
    const a = p.v4 >>> 24, b = (p.v4 >>> 16) & 0xff, c = (p.v4 >>> 8) & 0xff;
    if (p.v4 === 0) cls = 'unspecified';
    else if (a === 127) cls = 'loopback';
    else if (a === 169 && b === 254) cls = 'link-local';
    else if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) cls = 'private';
    else if ((a === 192 && b === 0 && c === 2) || (a === 198 && b === 51 && c === 100) || (a === 203 && b === 0 && c === 113)) cls = 'documentation';
  } else {
    const b0 = p.groups[0] >>> 8, b1 = p.groups[0] & 0xff;
    if (p.groups.every((g) => g === 0)) cls = 'unspecified';                    // ::
    else if (p.groups.every((g, i) => g === (i === 7 ? 1 : 0))) cls = 'loopback'; // ::1
    else if ((b0 & 0xfe) === 0xfc) cls = 'ula';                                 // fc00::/7
    else if (b0 === 0xfe && (b1 & 0xc0) === 0x80) cls = 'link-local';           // fe80::/10
    else if (p.groups[0] === 0x2001 && p.groups[1] === 0x0db8) cls = 'documentation'; // 2001:db8::/32
  }
  return { fam: p.fam, mapped: p.mapped, text: p.text, class: cls };
}

// For URL construction: bracket v6 literals ('::1' -> '[::1]'), leave everything
// else (v4, hostnames) untouched.
export function bracketHost(host) {
  const p = parseIp(host);
  return p && p.fam === 6 ? `[${p.text}]` : String(host || '');
}

const V4_IN_TEXT = /\b(\d{1,3}(?:\.\d{1,3}){3})\b/g;

// Pull the first IP literal out of free text (a shell command, a URL, a check-endpoint
// body) as a canonical address, or null. v4 is scanned first (it may hug ports/paths
// and still extract cleanly — historical behavior); v6 is found by a bracket- and
// slash-splitting token scan validated by the strict parser, so parser debris never
// reaches scope math. A port never hugs a BARE v6 unambiguously — bracketed URL forms
// ('http://[fd00::1]:8080/x') extract correctly.
export function extractIp(text) {
  const s = String(text || '');
  for (const m of s.matchAll(V4_IN_TEXT)) {
    const p = parseIp(m[1]);
    if (p) return p.text;
  }
  for (const tok of s.split(/[\s\[\]"'`;,|&<>(){}=/\\]+/)) {
    if (!tok || !tok.includes(':')) continue;
    const p = parseIp(tok);
    if (p) return p.text;
  }
  return null;
}
