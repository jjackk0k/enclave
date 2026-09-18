// VARVEL — native LDAP enumeration v1 (the LdapAnalyzer slot: anonymous rootDSE walk).
//
// Material reviewed: HYDRA ServiceAnalyzers.LdapAnalyzer. Ported as a PURE-JS RFC 4511
// client — BER encoding/decoding, anonymous simple bind, base-scope rootDSE search,
// unbind. No ldapsearch wrapper, no native deps.
//
// What one anonymous rootDSE read tells you (when the directory allows it):
//   namingContexts / defaultNamingContext — the domain DN (DC=corp,DC=example)
//   domain/forest/domainController functionality levels — the AD generation (honest:
//     2016 and later ALL report 7 — we say "2016 or later", never invent a version)
//   dnsHostName / serverName — a domain controller's real hostname (internal naming intel)
//   vendorName / isGlobalCatalogReady — AD vs OpenLDAP vs 389-DS discrimination
//
// HONEST outcomes, all first-class: no service (closed), anonymous refused (hardened
// directory — that IS intel), partial data, full read. One TCP connection, three
// operations, zero writes: quieter than ldapsearch -x -s base. Noise kind 'ldap-enum'
// (loudness 1). Hermetic tests drive a mock BER-speaking server.

import net from 'node:net';

// ---------- BER codec (RFC 4511 subset) ----------
const TAG = {
  INTEGER: 0x02, OCTET: 0x04, ENUM: 0x0a, SEQ: 0x30, SET: 0x31, BOOLEAN: 0x01,
  BIND_REQ: 0x60, BIND_RES: 0x61, UNBIND: 0x42, SEARCH_REQ: 0x63,
  SEARCH_ENTRY: 0x64, SEARCH_DONE: 0x65, SIMPLE_AUTH: 0x80, FILTER_PRESENT: 0x87,
};

function berLen(n) {
  if (n < 0x80) return Buffer.from([n]);
  const bytes = [];
  let v = n;
  while (v > 0) { bytes.unshift(v & 0xff); v >>= 8; }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}
export function tlv(tag, content) { return Buffer.concat([Buffer.from([tag]), berLen(content.length), content]); }
export const berInt = (n) => tlv(TAG.INTEGER, Buffer.from(n > 0x7f ? [0, n] : [n]));
export const berEnum = (n) => tlv(TAG.ENUM, Buffer.from([n]));
export const berOctet = (s) => tlv(TAG.OCTET, Buffer.from(s, 'utf8'));
export const berSeq = (...parts) => tlv(TAG.SEQ, Buffer.concat(parts));
export const berSet = (...parts) => tlv(TAG.SET, Buffer.concat(parts));

// Read one TLV at offset → { tag, value, next } or throws on truncation.
export function readTlv(buf, offset = 0) {
  if (offset + 2 > buf.length) throw new Error('truncated');
  const tag = buf[offset];
  let len = buf[offset + 1];
  let pos = offset + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (pos + n > buf.length) throw new Error('truncated');
    len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | buf[pos + i];
    pos += n;
  }
  if (pos + len > buf.length) throw new Error('truncated');
  return { tag, value: buf.subarray(pos, pos + len), next: pos + len };
}

// Try to peel ONE complete LDAP message off a stream buffer. Null = need more bytes.
export function peelMessage(buf) {
  try {
    const m = readTlv(buf, 0);
    if (m.tag !== TAG.SEQ) throw new Error('bad envelope');
    return { message: m.value, rest: buf.subarray(m.next) };
  } catch { return null; }
}

// ---------- LDAP protocol builders ----------
export function buildBindRequest(messageId) {
  return berSeq(berInt(messageId), tlv(TAG.BIND_REQ, Buffer.concat([berInt(3), berOctet(''), tlv(TAG.SIMPLE_AUTH, Buffer.alloc(0))])));
}

export function buildRootDseSearch(messageId, attributes) {
  const attrs = berSeq(...attributes.map(berOctet));
  const body = Buffer.concat([
    berOctet(''),            // baseObject: rootDSE
    berEnum(0),               // scope: baseObject
    berEnum(0),               // derefAliases: never
    berInt(0),                // sizeLimit: none
    berInt(10),               // timeLimit: 10s server-side
    tlv(TAG.BOOLEAN, Buffer.from([0])), // typesOnly: false
    tlv(TAG.FILTER_PRESENT, Buffer.from('objectClass', 'utf8')), // (objectClass=*)
    attrs,
  ]);
  return berSeq(berInt(messageId), tlv(TAG.SEARCH_REQ, body));
}

export const buildUnbind = (messageId) => berSeq(berInt(messageId), tlv(TAG.UNBIND, Buffer.alloc(0)));

// ---------- LDAP response parsing ----------
export function parseEnvelope(message) {
  const id = readTlv(message, 0);
  const op = readTlv(message, id.next);
  return { messageId: berToInt(id.value), opTag: op.tag, opValue: op.value };
}
function berToInt(v) { let n = 0; for (const b of v) n = (n << 8) | b; return n; }

// Bind/SearchDone result: SEQUENCE { resultCode ENUM, matchedDN OCTET, diagnostic OCTET }
export function parseResult(opValue) {
  const rc = readTlv(opValue, 0);
  const dn = readTlv(opValue, rc.next);
  const diag = readTlv(opValue, dn.next);
  return { resultCode: berToInt(rc.value), matchedDN: dn.value.toString('utf8'), diagnostic: diag.value.toString('utf8') };
}

// SearchResultEntry: [APP 4] { objectName, attributes SEQ OF { type OCTET, vals SET } }
export function parseEntry(opValue) {
  const name = readTlv(opValue, 0);
  const attrs = {};
  let pos = name.next;
  const list = readTlv(opValue, pos); // SEQUENCE OF attribute
  let p = 0;
  while (p < list.value.length) {
    const one = readTlv(list.value, p); p = one.next;
    const t = readTlv(one.value, 0);
    const vals = readTlv(one.value, t.next);
    const arr = [];
    let vp = 0;
    while (vp < vals.value.length) { const v = readTlv(vals.value, vp); vp = v.next; arr.push(v.value.toString('utf8')); }
    attrs[t.value.toString('utf8')] = arr;
  }
  return { objectName: name.value.toString('utf8'), attributes: attrs };
}

// ---------- functionality level names (honest about the 2016+ plateau) ----------
const FUNC_LEVELS = { 0: 'Windows 2000', 1: 'Windows Server 2003 interim', 2: 'Windows Server 2003', 3: 'Windows Server 2008', 4: 'Windows Server 2008 R2', 5: 'Windows Server 2012', 6: 'Windows Server 2012 R2', 7: 'Windows Server 2016 or later' };

export const ROOTDSE_ATTRS = [
  'defaultNamingContext', 'namingContexts', 'domainFunctionality', 'forestFunctionality',
  'domainControllerFunctionality', 'dnsHostName', 'serverName', 'vendorName',
  'supportedLDAPVersion', 'isGlobalCatalogReady', 'rootDomainNamingContext',
];

/**
 * Anonymous rootDSE enumeration. Never throws for network/protocol failures.
 * @param {string} host
 * @param {object} [opts] { port=389, timeout=4000, connectImpl } — connectImpl(host, port, timeout)
 *   returns a duplex { write(data), end(), onData(cb), onClose(cb) } (defaults to net).
 */
export async function ldapEnum(host, opts = {}) {
  if (!host) throw new Error('ldapEnum: host is required');
  const port = opts.port ?? 389;
  const timeout = opts.timeout ?? 4000;
  const evidence = [];
  const connect = opts.connectImpl || netConnect;
  let sock;
  try {
    sock = await connect(host, port, timeout);
  } catch (e) {
    return { host, port, reachable: false, anonymous: false, verdict: 'no LDAP service (port closed or filtered)', evidence, confidence: 100 };
  }

  const state = { buf: Buffer.alloc(0), queue: [], waiters: [] };
  sock.onData((d) => {
    state.buf = Buffer.concat([state.buf, d]);
    for (;;) {
      const peeled = peelMessage(state.buf);
      if (!peeled) break;
      state.buf = peeled.rest;
      const msg = parseEnvelope(peeled.message);
      const w = state.waiters.shift();
      if (w) w(msg); else state.queue.push(msg);
    }
  });
  const next = () => new Promise((res) => {
    if (state.queue.length) return res(state.queue.shift());
    state.waiters.push(res);
    setTimeout(() => { const i = state.waiters.indexOf(res); if (i >= 0) { state.waiters.splice(i, 1); res(null); } }, timeout);
  });
  const finish = (obj) => { try { sock.end(); } catch {} return obj; };

  // 1. anonymous bind
  sock.write(buildBindRequest(1));
  const bindRes = await next();
  if (!bindRes || bindRes.opTag !== TAG.BIND_RES) return finish({ host, port, reachable: true, anonymous: false, verdict: 'malformed bind response — not an LDAP service?', evidence, confidence: 40 });
  const bind = parseResult(bindRes.opValue);
  if (bind.resultCode !== 0) {
    evidence.push(`bind refused: resultCode ${bind.resultCode} (${bind.diagnostic || 'no diagnostic'})`);
    return finish({ host, port, reachable: true, anonymous: false, verdict: 'directory refuses anonymous bind (hardened) — intel: an LDAP service lives here', evidence, confidence: 90 });
  }
  evidence.push('anonymous bind accepted');

  // 2. rootDSE base search
  sock.write(buildRootDseSearch(2, ROOTDSE_ATTRS));
  let attrs = {};
  for (;;) {
    const m = await next();
    if (!m) return finish({ host, port, reachable: true, anonymous: true, verdict: 'search timed out mid-read', evidence, confidence: 30 });
    if (m.opTag === TAG.SEARCH_ENTRY) { attrs = { ...attrs, ...parseEntry(m.opValue).attributes }; continue; }
    if (m.opTag === TAG.SEARCH_DONE) {
      const done = parseResult(m.opValue);
      if (done.resultCode !== 0) evidence.push(`search done resultCode ${done.resultCode} (${done.diagnostic || 'ok'})`);
      break;
    }
  }
  sock.write(buildUnbind(3));

  const first = (k) => attrs[k]?.[0];
  const func = {
    domain: FUNC_LEVELS[Number(first('domainFunctionality'))] ?? null,
    forest: FUNC_LEVELS[Number(first('forestFunctionality'))] ?? null,
    controller: FUNC_LEVELS[Number(first('domainControllerFunctionality'))] ?? null,
  };
  const isAD = first('domainFunctionality') != null || first('defaultNamingContext')?.includes('DC=');
  const vendorGuess = isAD ? 'active-directory' : first('vendorName') ? 'openldap-or-389ds' : 'unknown';
  if (first('defaultNamingContext')) evidence.push(`domain DN: ${first('defaultNamingContext')}`);
  if (first('dnsHostName')) evidence.push(`controller hostname: ${first('dnsHostName')}`);
  if (func.domain) evidence.push(`domain functional level: ${func.domain}`);
  if (first('domainFunctionality') === '7') evidence.push('honesty: 2016 and later ALL report level 7 — cannot discriminate 2016/2019/2022/2025 by LDAP alone');

  return finish({
    host, port, reachable: true, anonymous: true,
    namingContexts: attrs.namingContexts || [],
    defaultNamingContext: first('defaultNamingContext') || null,
    functionality: func, dnsHostName: first('dnsHostName') || null,
    vendorGuess, attributesRead: Object.keys(attrs).length,
    verdict: isAD ? 'Active Directory readable anonymously — domain intel exposed' : 'LDAP readable anonymously',
    evidence, confidence: isAD ? 95 : 70,
  });
}

function netConnect(host, port, timeout) {
  return new Promise((resolve, reject) => {
    const sock = net.connect({ host, port, timeout });
    const onErr = (e) => { reject(e); };
    sock.once('error', onErr);
    sock.on('connect', () => {
      sock.removeListener('error', onErr);
      resolve({
        write: (d) => sock.write(d),
        end: () => sock.end(),
        onData: (cb) => sock.on('data', cb),
        onClose: (cb) => sock.on('close', cb),
      });
    });
  });
}

export const __internals = { TAG, FUNC_LEVELS };
