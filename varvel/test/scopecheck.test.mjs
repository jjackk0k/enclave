// VARVEL scopecheck tests — the MANDATORY pre-filing gate (tools/submit-drive.mjs
// evaluateScope) had NO test coverage until 2026-09-17, and that blind spot was not
// theoretical: the qualifier checks were bare keyword matches, so a sentence describing a
// qualifier as ABSENT satisfied it —
//   "file upload, whitelisted extension, fixed destination path, signed-token constraints"
// returned FILE, because `path` and `extension` both appeared in the text. A gate that can be
// talked into a FILE verdict by wording is a fabrication enabler (Wordfence: 4 hallucinated
// reports = permanent ban), so the disclaimer check now runs first and always wins.
//   node --test test/scopecheck.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluateScope } from '../tools/submit-drive.mjs';

test('a qualifier cannot be satisfied by wording that DISCLAIMS it (2026-09-17 regression)', () => {
  // the real wording from the royal-elementor-addons nopriv upload — honest, and NOT a FILE
  const honest = evaluateScope({
    auth: 'unauthenticated',
    type: 'file upload',
    impact: 'whitelisted extension, fixed destination path, signed-token constraints, sanitized filename',
  });
  assert.equal(honest.verdict, 'PARK',
    'a whitelisted/fixed/hardened upload does NOT meet "full path+extension control" — got ' + honest.verdict + ' | ' + honest.rule);

  // CONTROL: the same class with the qualifier genuinely met still files
  const real = evaluateScope({
    auth: 'unauthenticated',
    type: 'arbitrary file upload',
    impact: 'full path and extension control',
  });
  assert.equal(real.verdict, 'FILE (standard)',
    'CONTROL: a genuine arbitrary upload must still FILE — got ' + real.verdict);
});

test('LFI behind an allow-list or a fixed suffix PARKS, genuine full control files', () => {
  const allow = evaluateScope({ auth: 'subscriber', type: 'local file inclusion', impact: 'path is checked against an allow-list with a fixed init.php suffix' });
  assert.equal(allow.verdict, 'PARK', 'allow-list + fixed suffix is not full control — got ' + allow.verdict);

  const full = evaluateScope({ auth: 'unauthenticated', type: 'local file inclusion with full control', impact: 'arbitrary include path' });
  assert.equal(full.verdict, 'FILE (standard)', 'CONTROL: full control over the included file files — got ' + full.verdict);
});

test('auth band: administrator is out of band, contributor is mVDP-only', () => {
  const admin = evaluateScope({ auth: 'administrator', type: 'SQL injection', impact: 'significant' });
  assert.equal(admin.verdict, 'NO-FILE', 'PR:H/administrator is out of scope — got ' + admin.verdict);

  const contribStandard = evaluateScope({ auth: 'contributor', type: 'SQL injection', impact: 'significant' });
  assert.equal(contribStandard.verdict, 'NO-FILE', 'contributor is out for a standard program — got ' + contribStandard.verdict);

  const contribMvdp = evaluateScope({ mVDP: true, auth: 'contributor', type: 'SQL injection', impact: 'significant' });
  assert.equal(contribMvdp.verdict, 'FILE (mVDP)', 'mVDP keeps contributor in scope — got ' + contribMvdp.verdict);
});

test('kill classes fire at any auth level (§4.2 / §4.6)', () => {
  const twoFa = evaluateScope({ auth: 'subscriber', type: '2FA bypass', impact: 'disable two-factor' });
  assert.equal(twoFa.verdict, 'NO-FILE', '2FA issues are OUT (§4.6) — got ' + twoFa.verdict);

  const minor = evaluateScope({ auth: 'subscriber', type: 'missing authorization', impact: 'minor', });
  assert.equal(minor.verdict, 'NO-FILE', '§4.2 minor-impact subscriber findings are OUT — got ' + minor.verdict);

  const acHigh = evaluateScope({ auth: 'unauthenticated', type: 'SQL injection', impact: 'significant', ac: 'high' });
  assert.equal(acHigh.verdict, 'NO-FILE', 'AC:H is OUT (§4.2) — got ' + acHigh.verdict);
});

// --- VOCABULARY SEAM regression (2026-09-18): the gate must speak the same language ---
// as engine/lanes.mjs (hyphen-form class tokens) and as the operator (WP jargon auth
// aliases). A legit finding must never get a FALSE NO-FILE/PARK just for vocabulary.

test('vocabulary seam: hyphen-form class tokens reach the right bucket (lanes.mjs parity)', () => {
  // 'broken-access-control' (the lanes.mjs token) must behave EXACTLY like 'broken access control'
  const hyphen = evaluateScope({ auth: 'unauthenticated', type: 'broken-access-control', impact: 'significant — attacker reads sensitive objects' });
  const space = evaluateScope({ auth: 'unauthenticated', type: 'broken access control', impact: 'significant — attacker reads sensitive objects' });
  assert.equal(hyphen.verdict, space.verdict, 'hyphen-form and space-form must agree — got ' + hyphen.verdict + ' vs ' + space.verdict);
  assert.match(hyphen.rule, /broken access control/, 'the hyphen form must land in the bac bucket, not unknown');

  // same parity for the other hyphenated lanes.mjs tokens
  assert.equal(evaluateScope({ auth: 'unauth', type: 'arbitrary-file-upload', impact: 'full path and extension control' }).verdict, 'FILE (standard)');
  assert.equal(evaluateScope({ auth: 'unauth', type: 'php-object-injection', impact: '' }).verdict, 'FILE (standard)');
});

test('vocabulary seam: WP-jargon auth aliases resolve to the standard band', () => {
  const expected = evaluateScope({ auth: 'unauthenticated', type: 'SQL injection', impact: 'significant' });
  assert.equal(expected.verdict, 'FILE (standard)', 'CONTROL: the literal band token files');
  for (const alias of ['unauth', 'nopriv', 'UNAUTH', 'un-authenticated']) {
    const r = evaluateScope({ auth: alias, type: 'SQL injection', impact: 'significant' });
    assert.equal(r.verdict, 'FILE (standard)', `auth alias '${alias}' must resolve like 'unauthenticated' — got ${r.verdict}: ${r.rule}`);
  }
  // and the FALSE NO-FILE from the salon-booking-system session is dead: the old message
  // claimed unauth was out of scope while the band includes it
  const old = evaluateScope({ auth: 'unauth', type: 'SQL injection', impact: 'significant' });
  assert.ok(!/is out of scope/.test(old.rule), 'an in-band auth alias must never render the out-of-scope message');
});
