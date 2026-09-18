// VARVEL pocdoc tests — the disclosure-paperwork rung (engine/pocdoc.mjs). Template
// completeness against the Wordfence CNA shape, and TODO(validate) HONESTY: fields the
// candidate cannot know are marked, never fabricated.
//   node --test test/pocdoc.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { pocDoc, POCDOC_SECTIONS, TODO_MARKER } from '../engine/pocdoc.mjs';

// A validated privemap candidate (the Madara-provenance shape).
const PRIVEMAP_CANDIDATE = {
  rank: 1, sev: 'crit', score: 100,
  title: 'unauthenticated option overwrite (site-wide config) — vuln_settings_save (admin_init)',
  ref: 'wp-content/plugins/fixture/vuln.php:5',
  reachability: 'unauth',
  impactClass: 'option-overwrite',
  evidence: "update_option('vuln_settings', $opts);",
  confidence: 'high',
  taint: 'direct',
  probe: "READ-ONLY: baseline the option via a page render or REST settings GET; version-discriminate with the plugin readme 'Stable tag'.",
  hook: 'admin_init',
  handler: 'vuln_settings_save',
  mitigations: [],
  doctrineGated: false,
};

// A validated jsmap candidate (Node/JS route shape).
const JSMAP_CANDIDATE = {
  rank: 1, sev: 'crit', score: 90,
  title: 'route-registered unauthenticated OS command execution — (inline GET /ping-host@17) (GET /ping-host)',
  ref: 'app/server.js:19',
  reachability: 'unauth',
  impactClass: 'rce-exec',
  evidence: 'exec(`ping ${host}`, (err, out) => res.send(out));',
  confidence: 'high',
  taint: 'tainted-var',
  probe: 'READ-ONLY differential: send an intentionally INVALID value and grade the rejection vs baseline.',
  method: 'GET',
  route: '/ping-host',
  handler: '(inline GET /ping-host@17)',
  mitigations: [],
};

test('template completeness: every Wordfence CNA section renders for a privemap candidate', () => {
  const md = pocDoc(PRIVEMAP_CANDIDATE, { software: 'Madara Core' });
  for (const s of POCDOC_SECTIONS) {
    assert.ok(md.includes(`## ${s}`), `missing section ${s}`);
  }
  assert.match(md, /CWE-862/);
  assert.match(md, /None — the vulnerability is reachable unauthenticated/);
  assert.match(md, /admin-ajax|admin-post/, 'the ajax/admin_init repro path is derived');
  assert.match(md, /vuln_settings_save/);
  assert.match(md, /vuln\.php:5/, 'code reference carried through');
  assert.match(md, /update_option/, 'evidence carried through');
});

test('TODO honesty: unknowable fields are marked, never fabricated', () => {
  const md = pocDoc(PRIVEMAP_CANDIDATE, { software: 'Madara Core' });
  const todoCount = (md.match(/TODO\(validate\)/g) || []).length;
  assert.ok(todoCount >= 6, `expected ≥6 honest TODOs, got ${todoCount}`);
  // The affected-versions line must NOT invent a range: no version-looking token on it.
  const avLine = md.split('\n').find((l) => l.includes('Affected Versions'));
  assert.ok(avLine.includes(TODO_MARKER), 'affected versions honestly marked');
  assert.doesNotMatch(avLine, /<=\s*\d+\.\d+|version\s+\d+\.\d+/i, 'a fabricated version range leaked in');
  // The CVSS line is a TODO, not a guessed vector.
  const cvssLine = md.split('\n').find((l) => l.includes('CVSS v3.1'));
  assert.ok(cvssLine.includes(TODO_MARKER));
  assert.doesNotMatch(cvssLine, /CVSS:3\.1\/AV/, 'a fabricated CVSS vector leaked in');
  // WP/PHP requirements are TODOs unless supplied.
  assert.ok(md.split('\n').find((l) => l.includes('WordPress version requirement')).includes(TODO_MARKER));
});

test('operator-supplied fields fill in place of their TODOs', () => {
  const md = pocDoc(PRIVEMAP_CANDIDATE, {
    software: 'Madara Core', slug: 'madara-core', affectedVersions: '<= 2.0.1', researcher: 'operator-7', vendor: 'madara',
  });
  assert.match(md, /\*\*Software Slug \/ Package:\*\* madara-core/);
  assert.match(md, /\*\*Affected Versions:\*\* <= 2\.0\.1/);
  assert.match(md, /operator-7/);
  const slugLine = md.split('\n').find((l) => l.includes('Software Slug'));
  assert.ok(!slugLine.includes(TODO_MARKER));
});

test('jsmap candidates render the route-shaped repro and the right CWE', () => {
  const md = pocDoc(JSMAP_CANDIDATE, { software: 'Acme API' });
  assert.match(md, /CWE-78/);
  assert.match(md, /GET \/ping-host/, 'the route drives the repro step');
  assert.match(md, /Node\.js application/, 'software type inferred for jsmap candidates');
  assert.match(md, /UNAUTHENTICATED client/);
});

test('deterministic and total: same candidate ⇒ same document; empty candidate ⇒ all TODOs, no throw', () => {
  assert.equal(pocDoc(PRIVEMAP_CANDIDATE, { software: 'X' }), pocDoc(PRIVEMAP_CANDIDATE, { software: 'X' }), 'engine output must be deterministic');
  let md;
  assert.doesNotThrow(() => { md = pocDoc({}); });
  for (const s of POCDOC_SECTIONS) assert.ok(md.includes(`## ${s}`), `empty candidate still renders section ${s}`);
  assert.ok((md.match(/TODO\(validate\)/g) || []).length >= 8);
  assert.doesNotThrow(() => pocDoc(null));
  assert.doesNotThrow(() => pocDoc('garbage'));
});
