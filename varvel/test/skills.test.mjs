// VARVEL Agent-Skills tests — methodology playbooks + intent router.
//   node --test varvel/test/skills.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadSkills, selectSkills, skillsBriefing } from '../engine/skills.mjs';

test('loadSkills returns built-in playbooks with parsed fields', () => {
  const skills = loadSkills();
  assert.ok(skills.length >= 8, 'a substantial built-in library');
  for (const s of skills) {
    assert.ok(s.name && s.category, 'name + category');
    assert.ok(Array.isArray(s.keywords) && s.keywords.length, 'keywords');
    assert.ok(s.guidance && s.guidance.length > 40, 'real guidance body');
  }
  assert.ok(skills.some((s) => s.name === 'jwt-attacks') && skills.some((s) => s.name === 'sql-injection'));
});

test('boundary: playbooks are methodology, not weaponized payloads', () => {
  for (const s of loadSkills()) {
    const g = s.guidance.toLowerCase();
    assert.ok(!/malware|reverse shell|c2 |implant|anti-forensic|evade detection/.test(g), `${s.name} stays methodology-level`);
  }
});

test('selectSkills routes by objective + context (intent router)', () => {
  assert.ok(selectSkills('test the login form for SQL injection').some((s) => s.name === 'sql-injection'));
  assert.ok(selectSkills('assess the JWT session token').some((s) => s.name === 'jwt-attacks'));
  // context-driven: a finding about exposed .env routes to exposed-secrets
  const byFinding = selectSkills('review findings', { findings: [{ title: 'exposed .env secrets file' }] });
  assert.ok(byFinding.some((s) => s.name === 'exposed-secrets'));
  // capped at 4
  assert.ok(selectSkills('sql injection xss ssrf jwt idor path traversal command injection').length <= 4);
});

test('selectSkills is robust to empty / junk', () => {
  assert.deepEqual(selectSkills(''), []);
  assert.deepEqual(selectSkills('the quick brown fox jumped'), []);
  assert.doesNotThrow(() => selectSkills(null, null, null));
});

test('skillsBriefing produces an injectable prompt for matches, empty otherwise', () => {
  const sel = selectSkills('sql injection on the login');
  const brief = skillsBriefing(sel);
  assert.match(brief, /attack playbooks/i);
  assert.match(brief, /sql-injection/);
  assert.equal(skillsBriefing([]), '');
});
