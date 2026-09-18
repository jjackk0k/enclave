// ldapenum.test.mjs — hermetic tests for tools/ldapenum.mjs (mock BER-speaking socket).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  ldapEnum, tlv, berInt, berEnum, berOctet, berSeq, berSet,
  buildBindRequest, buildRootDseSearch, parseEnvelope, parseResult, parseEntry, peelMessage,
} from '../tools/ldapenum.mjs';

const RESULT_OK = (id, appTag) => berSeq(berInt(id), tlv(appTag, Buffer.concat([berEnum(0), berOctet(''), berOctet('')])));
const ENTRY = (id, attrs) => berSeq(berInt(id), tlv(0x64, Buffer.concat([
  berOctet(''),
  berSeq(...Object.entries(attrs).map(([k, vals]) => berSeq(berOctet(k), berSet(...vals.map(berOctet))))),
])));

// Fake duplex that plays a scripted LDAP conversation.
function mockLdapSocket(script) {
  const handlers = { data: null, close: null };
  return {
    write(buf) {
      const msg = peelMessage(buf);
      if (!msg) return;
      const env = parseEnvelope(msg.message);
      const respond = script(env.opTag);
      if (respond) {
        for (const chunk of respond) setImmediate(() => handlers.data && handlers.data(chunk));
      }
    },
    end() { handlers.close && handlers.close(); },
    onData(cb) { handlers.data = cb; },
    onClose(cb) { handlers.close = cb; },
  };
}

const AD_FIXTURE = {
  defaultNamingContext: ['DC=corp,DC=example,DC=test'],
  namingContexts: ['DC=corp,DC=example,DC=test', 'CN=Configuration,DC=corp,DC=example,DC=test'],
  domainFunctionality: ['7'],
  forestFunctionality: ['7'],
  dnsHostName: ['DC1.corp.example.test'],
};

function fullAdConversation() {
  return (opTag) => {
    if (opTag === 0x60) return [RESULT_OK(1, 0x61)];
    if (opTag === 0x63) return [ENTRY(2, AD_FIXTURE), RESULT_OK(2, 0x65)];
    return null;
  };
}

test('codec round-trips bind and search requests', () => {
  const bind = peelMessage(buildBindRequest(7));
  const env = parseEnvelope(bind.message);
  assert.equal(env.messageId, 7);
  assert.equal(env.opTag, 0x60);
  const search = peelMessage(buildRootDseSearch(9, ['defaultNamingContext']));
  assert.equal(parseEnvelope(search.message).opTag, 0x63);
});

test('peelMessage waits for fragmented frames', () => {
  const full = buildBindRequest(3);
  assert.equal(peelMessage(full.subarray(0, 2)), null); // incomplete
  assert.deepEqual(peelMessage(full).rest.length, 0);
});

test('full AD conversation yields domain intel with honest 2016+ caveat', async () => {
  const r = await ldapEnum('dc.corp.test', { connectImpl: async () => mockLdapSocket(fullAdConversation()), timeout: 500 });
  assert.equal(r.reachable, true);
  assert.equal(r.anonymous, true);
  assert.equal(r.vendorGuess, 'active-directory');
  assert.equal(r.defaultNamingContext, 'DC=corp,DC=example,DC=test');
  assert.equal(r.dnsHostName, 'DC1.corp.example.test');
  assert.equal(r.functionality.domain, 'Windows Server 2016 or later');
  assert.equal(r.confidence, 95);
  assert.ok(r.evidence.some((e) => /ALL report level 7/.test(e)));
});

test('refused anonymous bind is reported as hardening intel, not failure', async () => {
  const refuse = (opTag) => opTag === 0x60
    ? [berSeq(berInt(1), tlv(0x61, Buffer.concat([berEnum(49), berOctet(''), berOctet('80090308: LdapErr')])))]
    : null;
  const r = await ldapEnum('dc.corp.test', { connectImpl: async () => mockLdapSocket(refuse), timeout: 500 });
  assert.equal(r.reachable, true);
  assert.equal(r.anonymous, false);
  assert.match(r.verdict, /refuses anonymous bind \(hardened\)/);
  assert.match(r.evidence[0], /resultCode 49/);
});

test('closed port reports no service honestly', async () => {
  const r = await ldapEnum('10.9.9.9', { connectImpl: async () => { throw new Error('ECONNREFUSED'); }, timeout: 300 });
  assert.equal(r.reachable, false);
  assert.match(r.verdict, /no LDAP service/);
});

test('fragmented entry delivery reassembles correctly', async () => {
  const frag = (opTag) => {
    if (opTag === 0x60) return [RESULT_OK(1, 0x61)];
    if (opTag === 0x63) {
      const entry = ENTRY(2, AD_FIXTURE);
      const done = RESULT_OK(2, 0x65);
      const whole = Buffer.concat([entry, done]);
      return [whole.subarray(0, 7), whole.subarray(7, 40), whole.subarray(40)]; // byte-chopped
    }
    return null;
  };
  const r = await ldapEnum('dc.corp.test', { connectImpl: async () => mockLdapSocket(frag), timeout: 500 });
  assert.equal(r.defaultNamingContext, 'DC=corp,DC=example,DC=test');
  assert.equal(r.attributesRead >= 5, true);
});

test('parseEntry decodes multi-valued attributes', () => {
  const e = ENTRY(2, { namingContexts: ['DC=a', 'CN=Configuration,DC=a'] });
  const msg = peelMessage(e);
  const env = parseEnvelope(msg.message);
  const parsed = parseEntry(env.opValue);
  assert.deepEqual(parsed.attributes.namingContexts, ['DC=a', 'CN=Configuration,DC=a']);
});

test('host is required', async () => {
  await assert.rejects(() => ldapEnum(''), /host is required/);
});
