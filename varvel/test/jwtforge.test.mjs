// VARVEL jwtforge tests — the shelf→native port, proven against the real Axiom chain.
//   node --test varvel/test/jwtforge.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { b64uEncode, b64uDecode, decodeJwt, signHs256, verifyHs256 } from '../tools/jwtforge.mjs';

const KEY = 'axiom-auth-hs256-legacy-2019'; // the key the breach run recovered

test('base64url round-trip incl. padding-sensitive payloads', () => {
  for (const s of ['a', 'ab', 'abc', '{"alg":"HS256","typ":"JWT"}', 'øþ unicode ✓']) {
    assert.equal(b64uDecode(b64uEncode(s)), s);
  }
  assert.ok(!/=/.test(b64uEncode('abcdef')), 'JWT flavor carries no padding');
});

test('decodeJwt: a well-formed token inspects cleanly with red flags surfaced', () => {
  const token = signHs256({ sub: 'sandbox@axiom.dev', role: 'member', exp: 1 }, KEY);
  const d = decodeJwt(token);
  assert.equal(d.validShape, true);
  assert.equal(d.alg, 'HS256');
  assert.equal(d.payload.role, 'member');
  assert.equal(d.expired, true, 'exp of 1 is long past');
  assert.ok(d.issues.length === 0, 'no other flags on an ordinary token');
});

test('decodeJwt: alg=none and junk are flagged, never thrown', () => {
  const noneToken = b64uEncode(JSON.stringify({ alg: 'none', typ: 'JWT' })) + '.' + b64uEncode('{"role":"admin"}') + '.';
  const d = decodeJwt(noneToken);
  assert.ok(d.issues.some((i) => /alg=none/.test(i)), 'alg=none is a loud red flag');
  assert.equal(decodeJwt('not-a-jwt').validShape, false);
  assert.equal(decodeJwt('a.b.c').validShape, false);
  assert.equal(decodeJwt('').validShape, false);
});

test('decodeJwt: suspicious kid and missing exp are called out', () => {
  const t = b64uEncode(JSON.stringify({ alg: 'HS256', kid: '../../etc/passwd' })) + '.' + b64uEncode('{"sub":"x"}') + '.sig';
  const d = decodeJwt(t);
  assert.ok(d.issues.some((i) => /kid/.test(i)));
  assert.ok(d.issues.some((i) => /no exp/.test(i)));
});

test('signHs256 + verifyHs256: the real Axiom chain — forge admin, confirm, tamper fails', () => {
  // what the breach run did: mint role:"admin" with the leaked key
  const forged = signHs256({ sub: 'admin@axiom.dev', role: 'admin', org: 'org_axiom', iss: 'axiom-auth', iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 3600 }, KEY);
  assert.ok(verifyHs256(forged, KEY), 'the forged token verifies with the recovered key');
  // independence: matches a reference HMAC computation
  const [h, p, s] = forged.split('.');
  const ref = createHmac('sha256', KEY).update(h + '.' + p).digest('base64url');
  assert.equal(s, ref);
  // wrong key and tampered payload both fail (timing-safe path)
  assert.ok(!verifyHs256(forged, 'wrong-key'), 'wrong key rejected');
  const tampered = h + '.' + b64uEncode(JSON.stringify({ sub: 'admin@axiom.dev', role: 'admin', exp: 9999999999 })) + '.' + s;
  assert.ok(!verifyHs256(tampered, KEY), 'tampered payload rejected');
});

test('boundary discipline: no key = no signature (it is not a brute-forcer)', () => {
  assert.throws(() => signHs256({ role: 'admin' }, ''), TypeError);
  assert.throws(() => signHs256({ role: 'admin' }, null), TypeError);
  assert.throws(() => signHs256('role=admin', KEY), TypeError);
  assert.equal(verifyHs256('a.b.c', ''), false);
});
