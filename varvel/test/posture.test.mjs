// VARVEL posture + toolshelf tests — hermetic, no network, shelf writes to a temp HOME
// via SHELF isolation (index is per-repo; tests clean up after themselves).
//   node --test varvel/test/posture.test.mjs varvel/test/toolshelf.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// Isolate the shelf BEFORE importing the module under test — tests never touch the real shelf.
process.env.VARVEL_SHELF_DIR = mkdtempSync(join(tmpdir(), 'varvel-shelf-test-'));

import { scorePosture, comparePosture, postureReport, BENCHMARKS, SIGNALS } from '../engine/posture.mjs';
import { shelveTool, shelfList, shelfRead, promoteTool } from '../engine/toolshelf.mjs';

// ——— posture ———

const AXIOM_FP = {
  defenses: [{ id: 'axiom-shield', vendor: 'Axiom Shield', kind: 'waf', monitoring: 'high', signals: ['header:x-axiom-shield'] }],
  rateLimit: { limit: 120, throttled: false },
  challenge: null,
  securityHeaders: ['csp', 'hsts', 'xfo', 'xcto'],
};
const BARE_FP = { defenses: [], rateLimit: null, challenge: null, securityHeaders: [] };

test('scorePosture: a bare app scores 0/F, Axiom-class scores in the hardened band', () => {
  const bare = scorePosture(BARE_FP);
  assert.equal(bare.score, 0);
  assert.ok(bare.grade.startsWith('F'));
  const ax = scorePosture(AXIOM_FP);
  assert.ok(ax.score >= 60, 'Axiom is hardened, got ' + ax.score);
  assert.ok(/A|B/.test(ax.grade), ax.grade);
  // every earned point is attributable
  const got = ax.breakdown.filter((b) => b.got).map((b) => b.signal);
  assert.ok(got.includes('waf') && got.includes('ratelimit') && got.includes('csp'));
  assert.ok(!got.includes('challenge'), 'no bot challenge on Axiom — honest absence');
});

test('comparePosture: Axiom outranks the real marketing-site benchmarks on visible posture', () => {
  const { mine, against } = comparePosture(AXIOM_FP);
  assert.ok(mine.score >= 60);
  const stripe = against.find((a) => a.name === 'stripe.com');
  const axRef = against.find((a) => /axiom/i.test(a.name));
  assert.ok(stripe && axRef, 'both references present');
  assert.ok(mine.score >= stripe.score, 'Axiom posture >= stripe.com visible headers (documented caveat: depth differs)');
  assert.equal(axRef.delta, 0, 'Axiom matches its own recorded profile');
  // sorted hardest first
  for (let i = 1; i < against.length; i++) assert.ok(against[i - 1].score >= against[i].score);
});

test('postureReport: fingerprints from an injected response and grades honestly', () => {
  const r = postureReport({ status: 200, headers: { server: 'Axiom', 'x-axiom-shield': 'active', 'content-security-policy': "default-src 'self'", 'strict-transport-security': 'max-age=1' }, body: '<h1>ok</h1>' });
  assert.ok(r.mine.score > 0);
  assert.ok(r.fingerprint.defenses.find((d) => d.id === 'axiom-shield'));
  assert.ok(Array.isArray(r.against) && r.against.length >= 3);
});

test('benchmark hygiene: dated snapshots, valid signals, weights sum to 100', () => {
  assert.equal(SIGNALS.reduce((a, s) => a + s.points, 0), 100);
  for (const [name, b] of Object.entries(BENCHMARKS)) {
    assert.ok(/^\d{4}-\d{2}-\d{2}$/.test(b.measured), name + ' has a snapshot date');
    assert.ok(b.class && b.notes, name + ' documented');
  }
});

// ——— toolshelf ———

const PY = 'import hmac\n# JWT forger written by the agent mid-engagement\n';
let seededId = null;

test('shelveTool: stores an AI-written tool as QUARANTINED data with hashes', () => {
  const e = shelveTool({
    name: 'JWT Forge (k2.7 breach run)', kind: 'offensive', description: 'HS256 admin token forger for the Axiom chain',
    files: [{ name: 'forge.py', content: PY }],
    origin: { agent: 'kimi-k2.7-code', session: 'test-session' },
  });
  seededId = e.id;
  assert.equal(e.status, 'quarantined', 'DATA ONLY — never executed by VARVEL');
  assert.equal(e.origin.agent, 'kimi-k2.7-code');
  assert.equal(e.files[0].sha256.length, 64, 'sha256 recorded for provable review');
  const listed = shelfList().find((x) => x.id === e.id);
  assert.ok(listed, 'listed');
  assert.equal(shelfRead(e.id, 'forge.py'), PY, 'bytes are verbatim');
});

test('shelveTool: rejects unsafe names and missing files', () => {
  assert.throws(() => shelveTool({ name: '../../evil', files: [{ name: 'x', content: 'y' }] }), TypeError);
  assert.throws(() => shelveTool({ name: 'ok', files: [] }), TypeError);
  assert.throws(() => shelveTool({ name: 'ok', files: [{ name: '../x', content: 'y' }] }), TypeError);
});

test('promoteTool: a logged HUMAN decision — promotion never executes anything', () => {
  const e = promoteTool(seededId, { by: 'jack', note: 'worth a native port' });
  assert.ok(e, 'entry found');
  assert.equal(e.status, 'promoted');
  assert.equal(e.promoted.by, 'jack');
  assert.ok(e.promoted.at);
  assert.equal(promoteTool('no-such-id', {}), null);
});
