// VARVEL submit-drive payload/scope tests — the draft parser, the type/auth
// mapping tables, and the June-2026 Patchstack scope gate (evaluateScope), all
// pure functions imported from the driver. Offline: no browser, no network.
//   node --test test/submit-drive-payload.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  parseDraft, detectAuth, mapPrereq, mapVulnClass, mapVulnType,
  buildPayload, evaluateScope, BAN_REMINDER,
} from '../tools/submit-drive.mjs';

const CFG = JSON.parse(readFileSync(new URL('../data/submit-sites/patchstack.json', import.meta.url), 'utf8'));

const DRAFT = `> **SCOPE NOTE: this stamp must not leak into the payload fields.**

# Patchstack Submission — Acme SEO Toolkit <= 2.3.0 Missing Authorization in Settings Save (subscriber+)

## Software
- **Name:** Acme SEO Toolkit (acme-seo)
- **Vendor:** Acme
- **Software type:** WordPress plugin
- **Affected versions:** <= 2.3.0 (current release at time of writing)
- **Vulnerability type:** Missing Authorization
- **CWE:** CWE-862 (Missing Authorization)
- **Proposed CVSS 3.1:** 5.4 — \`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L\`

## Summary
Acme SEO Toolkit registers acme_save_settings on admin_init with no capability check and no nonce. A subscriber-level attacker can overwrite the plugin's API key option.

## Evidence
Affected code: https://plugins.trac.wordpress.org/browser/acme-seo/tags/2.3.0/acme-seo.php (hook :42).
\`\`\`php
add_action( 'admin_init', 'acme_save_settings' );
\`\`\`

## Impact
Attacker-controlled plugin configuration.

## Honest bounds
- Only the api_key option is writable; no escalation primitive.

## Suggested remediation
Add current_user_can( 'manage_options' ) and a nonce to acme_save_settings.

## Proof of Concept (subscriber, any low-priv session)
Single POST, no nonce:
\`\`\`
POST /wp-admin/admin-post.php?action=acme_save_settings&api_key=pwnd HTTP/1.1
Cookie: <subscriber session>
\`\`\`

---
_Research method: read-only static review. No live-site testing was performed._
`;

const EDITOR_DRAFT = `# Wordfence Submission — Rank Math SEO <= 1.0.276 Missing Authorization in \`rank-math/fix-site-seo\` Ability (editor+, default config)

## Software
- **Name:** Rank Math SEO (seo-by-rank-math)
- **Vendor:** Rank Math
- **Software type:** WordPress plugin
- **Affected versions:** 1.0.271 through **1.0.276** (fixed in 1.0.277)
- **Vulnerability type:** Missing Authorization / Privilege Escalation
- **CWE:** CWE-862 (Missing Authorization)
- **Proposed CVSS 3.1:** 6.5 — \`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N\`

## Summary
An authenticated editor can invoke the ability and modify site-wide administrator settings.

## Suggested remediation
Require manage_options in check_permissions().

## Proof of Concept (editor session, WP with the Abilities API)
POST /wp-json/wp-abilities/v1/abilities/rank-math/fix-site-seo/run
`;

test('parser: software bullets, slug, version, CWE, auth', () => {
  const d = parseDraft(DRAFT);
  assert.equal(d.softwareName, 'Acme SEO Toolkit');
  assert.equal(d.slug, 'acme-seo');
  assert.equal(d.vendor, 'Acme');
  assert.equal(d.vulnVersion, '<= 2.3.0', 'version range cut at the first parenthesis');
  assert.equal(d.vulnType, 'Missing Authorization');
  assert.match(d.cwe, /CWE-862/);
  assert.equal(d.auth, 'subscriber');
  assert.match(d.authEvidence, /Proof of Concept/);
  assert.match(d.affectedCode, /Affected code: https:\/\/plugins\.trac\.wordpress\.org/);
});

test('parser: shortDescription spans Summary..Suggested remediation, excludes PoC/stamp/method', () => {
  const d = parseDraft(DRAFT);
  for (const h of ['## Summary', '## Evidence', '## Impact', '## Honest bounds', '## Suggested remediation'])
    assert.ok(d.shortDescription.includes(h), `shortDescription carries ${h}`);
  assert.ok(!d.shortDescription.includes('## Proof of Concept'), 'PoC stays out of the description');
  assert.ok(!d.shortDescription.includes('SCOPE NOTE'), 'leading blockquote stamp stays out');
  assert.ok(!d.shortDescription.includes('Research method'), 'trailing method line stays out');
  assert.match(d.poc, /^## Proof of Concept \(subscriber/);
  assert.match(d.poc, /POST \/wp-admin\/admin-post\.php/);
});

test('parser: editor-level draft — slug from parens, auth from PoC heading, compound vuln type', () => {
  const d = parseDraft(EDITOR_DRAFT);
  assert.equal(d.slug, 'seo-by-rank-math');
  assert.equal(d.auth, 'editor');
  assert.equal(d.vulnType, 'Missing Authorization / Privilege Escalation');
  assert.equal(d.vulnVersion, '1.0.271 through 1.0.276', 'markdown bold stripped from the version range');
});

test('detectAuth: CVSS PR heuristic fires when no role is stated anywhere', () => {
  const r = detectAuth('# T\n\n## Summary\nA handler misses a check.\n\nCVSS:3.1/AV:N/AC:L/PR:N/UI:N');
  assert.equal(r.auth, 'unauthenticated');
  assert.match(r.evidence, /heuristic/);
  assert.equal(detectAuth('no roles, no vector').auth, null);
});

test('mapping: Pre-requisite auth table — banked options clean, others carry a note', () => {
  assert.deepEqual(mapPrereq('subscriber'), { option: 'Subscriber', note: null });
  assert.deepEqual(mapPrereq('contributor'), { option: 'Contributor', note: null });
  assert.deepEqual(mapPrereq('editor'), { option: 'Editor', note: null });
  const un = mapPrereq('unauthenticated');
  assert.equal(un.option, 'Unauthenticated');
  assert.ok(un.note, 'unauthenticated is an unbanked option string — the guess must be loud');
  const none = mapPrereq(null);
  assert.match(none.option, /^TODO\(/);
  assert.ok(none.note);
});

test('mapping: OWASP type table returns exact banked option strings', () => {
  const opts = CFG.combos.owaspType.options;
  assert.equal(mapVulnType('Missing Authorization', opts).option, 'Bypass Vulnerability');
  assert.equal(mapVulnType('Insecure Direct Object Reference (IDOR)', opts).option, 'Insecure Direct Object References (IDOR)');
  assert.equal(mapVulnType('stored XSS', opts).option, 'Cross Site Scripting (XSS)');
  assert.equal(mapVulnType('SQL injection', opts).option, 'SQL Injection');
  // First match wins: the missing-authorization half of the compound type drives.
  assert.equal(mapVulnType('Missing Authorization / Privilege Escalation', opts).option, 'Bypass Vulnerability');
  const weird = mapVulnType('Something Entirely Novel', opts);
  assert.match(weird.option, /^TODO\(/);
  assert.ok(weird.note);
});

test('mapping: OWASP class banked only for missing-authorization shapes', () => {
  assert.deepEqual(mapVulnClass('Missing Authorization'), { option: 'A1: Broken Access Control', note: null });
  assert.deepEqual(mapVulnClass('Insecure Direct Object References (IDOR)'), { option: 'A1: Broken Access Control', note: null });
  const other = mapVulnClass('SQL Injection');
  assert.match(other.option, /^TODO\(/);
  assert.ok(other.note);
});

test('buildPayload: fieldMap/combos wired to the banked config, acceptTerms true', () => {
  const { payload, mappings, warnings } = buildPayload(parseDraft(DRAFT), CFG, { attach: ['.tmp/acme-poc.zip'] });
  assert.equal(payload.site, 'patchstack');
  assert.equal(payload.startUrl, 'https://patchstack.com/database/report/wordpress/plugin/acme-seo');
  assert.equal(payload.slug, 'acme-seo');
  assert.equal(payload.fieldMap.name, 'Varvel');
  assert.equal(payload.fieldMap.email, 'Varvel@proton.me');
  assert.equal(payload.fieldMap.comp_link, 'https://wordpress.org/plugins/acme-seo/');
  assert.equal(payload.fieldMap.vuln_version, '<= 2.3.0');
  assert.match(payload.fieldMap.shortDescription, /^## Summary/);
  assert.match(payload.fieldMap.reproduce, /^## Proof of Concept/);
  assert.match(payload.fieldMap.additional_info, /Affected code:/);
  assert.deepEqual(payload.combos.map(c => c.label), ['pre-requisite', 'vulnerability class', 'vulnerability type']);
  assert.deepEqual(payload.combos.map(c => c.option), ['Subscriber', 'A1: Broken Access Control', 'Bypass Vulnerability']);
  assert.deepEqual(payload.attach, ['.tmp/acme-poc.zip']);
  assert.equal(payload.acceptTerms, true);
  assert.ok(mappings.length >= 8, 'every mapping is reported');
  assert.deepEqual(warnings, [], 'this fixture maps clean');
});

test('buildPayload: unmappable inputs produce TODO markers plus loud warnings, never silent', () => {
  const { payload, warnings } = buildPayload(parseDraft(DRAFT.replace('**Vulnerability type:** Missing Authorization', '**Vulnerability type:** Quantum Confusion')), CFG, { attach: [] });
  assert.match(payload.combos[1].option, /^TODO\(/, 'class TODO in the JSON');
  assert.match(payload.combos[2].option, /^TODO\(/, 'type TODO in the JSON');
  assert.ok(warnings.some(w => /OWASP class/.test(w)));
  assert.ok(warnings.some(w => /OWASP type/.test(w)));
  assert.ok(warnings.some(w => /attach/.test(w)), 'missing poc zip is a printed note');
});

test('buildPayload: shortDescription over the banked 4096-char limit raises a loud warning', () => {
  assert.equal(CFG.limits.shortDescription, 4096, 'the 4096 limit stays banked in the site config');
  const fat = DRAFT.replace('## Evidence', 'x'.repeat(4500) + '\n\n## Evidence');
  const { warnings } = buildPayload(parseDraft(fat), CFG, { attach: [] });
  assert.ok(warnings.some(w => /OVER the 4096-char/.test(w)), 'over-limit warning names the limit and the trim target');
});

test('evaluateScope: the key bands', () => {
  // subscriber + SQLi + no mVDP = FILE (standard)
  assert.equal(evaluateScope({ mVDP: false, auth: 'subscriber', type: 'SQL injection' }).verdict, 'FILE (standard)');
  // contributor + IDOR + no mVDP = NO-FILE (standard auth cap)
  const c = evaluateScope({ mVDP: false, auth: 'contributor', type: 'IDOR' });
  assert.equal(c.verdict, 'NO-FILE');
  assert.match(c.rule, /contributor\+ is OUT/);
  // contributor + missing authz + mVDP = FILE (mVDP)
  const m = evaluateScope({ mVDP: true, auth: 'contributor', type: 'Missing Authorization' });
  assert.equal(m.verdict, 'FILE (mVDP)');
  assert.match(m.rule, /broken access control/);
  // editor + anything + mVDP = PARK-or-NO-FILE per the rules (we NO-FILE: mVDP extends only to contributor)
  assert.match(evaluateScope({ mVDP: true, auth: 'editor', type: 'Missing Authorization' }).verdict, /^(PARK|NO-FILE)$/);
  assert.equal(evaluateScope({ mVDP: true, auth: 'editor', type: 'SQL injection' }).verdict, 'NO-FILE');
  // contributor-stored XSS = NO-FILE at any auth
  const x = evaluateScope({ mVDP: false, auth: 'subscriber', type: 'contributor-stored XSS' });
  assert.equal(x.verdict, 'NO-FILE');
  assert.match(x.rule, /contributor-stored/);
});

test('evaluateScope: qualifiers park, qualifiers demonstrated file, rule always cited', () => {
  assert.equal(evaluateScope({ mVDP: false, auth: 'unauthenticated', type: 'SQLi' }).verdict, 'FILE (standard)');
  assert.equal(evaluateScope({ mVDP: false, auth: 'subscriber', type: 'CSRF' }).verdict, 'PARK', 'unchained CSRF is not yet fileable');
  assert.equal(evaluateScope({ mVDP: false, auth: 'subscriber', type: 'CSRF chained to an option overwrite write' }).verdict, 'FILE (standard)');
  assert.equal(evaluateScope({ mVDP: false, auth: 'subscriber', type: 'site-wide stored XSS' }).verdict, 'FILE (standard)');
  assert.equal(evaluateScope({ mVDP: true, auth: 'contributor', type: 'IDOR exposing PII of ticket orders' }).verdict, 'FILE (mVDP)', 'PII-object IDOR qualifies via the mVDP lane');
  assert.equal(evaluateScope({ mVDP: false, auth: 'subscriber', type: 'IDOR exposing PII of ticket orders' }).verdict, 'NO-FILE', 'same objects are standard-lane OUT');
  assert.equal(evaluateScope({ mVDP: false, auth: 'customer', type: 'something unlisted' }).verdict, 'PARK', 'unclassified types park, never silently file');
  for (const r of [evaluateScope({ mVDP: false, auth: 'subscriber', type: 'SQLi' }), evaluateScope({ mVDP: false, auth: 'editor', type: 'SQLi' })])
    assert.ok(r.rule.length > 20, 'every verdict cites its rule');
  assert.match(BAN_REMINDER, /one-week ban/);
});

test('evaluateScope: the GiveWP-lesson kill clauses (June 2026 §4.2/§3.9)', () => {
  // The exact GiveWP shape: subscriber + missing authz + minor impact = NO-FILE (this killed the report)
  const g = evaluateScope({ mVDP: true, auth: 'subscriber', type: 'Missing Authorization', impact: 'minor' });
  assert.equal(g.verdict, 'NO-FILE');
  assert.match(g.rule, /minor/);
  // cronjobs/scheduled tasks are OUT at any auth level, any impact
  const cr = evaluateScope({ mVDP: false, auth: 'unauthenticated', type: 'Missing Authorization on cronjob / scheduled task control' });
  assert.equal(cr.verdict, 'NO-FILE');
  assert.match(cr.rule, /cronjobs \/ scheduled tasks/);
  // unauth single-Low impact = NO-FILE
  assert.equal(evaluateScope({ mVDP: false, auth: 'unauthenticated', type: 'SQL injection', impact: 'minor' }).verdict, 'NO-FILE');
  // AC:H = NO-FILE regardless of type
  assert.equal(evaluateScope({ mVDP: false, auth: 'unauthenticated', type: 'RCE', ac: 'high' }).verdict, 'NO-FILE');
  // standard broken access control WITHOUT sensitive objects = PARK (tightened after the GiveWP rejection)
  const b = evaluateScope({ mVDP: false, auth: 'subscriber', type: 'Missing Authorization' });
  assert.equal(b.verdict, 'PARK');
  assert.match(b.rule, /significant\/sensitive objects/);
  // ...but WITH the significant-objects evidence it files
  assert.equal(evaluateScope({ mVDP: false, auth: 'subscriber', type: 'Missing Authorization exposing API keys and secrets' }).verdict, 'FILE (standard)');
  // a significant-impact subscriber finding still files
  assert.equal(evaluateScope({ mVDP: false, auth: 'subscriber', type: 'SQL injection', impact: 'significant' }).verdict, 'FILE (standard)');
});
