// VARVEL Deep Think tests — the structured strategic pre-step (RedAmon parity).
//   node --test varvel/test/deepthink.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { shouldDeepThink, deepThinkPrompt, parseDeepThink, isNovel } from '../engine/deepthink.mjs';

// --- shouldDeepThink: WHEN to fire ----------------------------------------

test('fires on transition INTO a high-significance phase (exploit)', () => {
  const r = shouldDeepThink({ phase: 'exploit', transitioned: true });
  assert.equal(r.fire, true);
  assert.match(r.reason, /transition|exploit/i);
  // validate and postex are high-significance too
  assert.equal(shouldDeepThink({ phase: 'validate', transitioned: true }).fire, true);
  assert.equal(shouldDeepThink({ phase: 'postex', transitioned: true }).fire, true);
});

test('does NOT fire transitioning into a low-significance phase (recon/report)', () => {
  assert.equal(shouldDeepThink({ phase: 'recon', transitioned: true }).fire, false);
  assert.equal(shouldDeepThink({ phase: 'report', transitioned: true }).fire, false);
});

test('fires when stuck >= 2 (deterministic no-growth streak), even mid-phase', () => {
  const r = shouldDeepThink({ phase: 'recon', stuck: 2 });
  assert.equal(r.fire, true);
  assert.match(r.reason, /stuck/i);
  assert.equal(shouldDeepThink({ phase: 'recon', stuck: 1 }).fire, false, 'stuck 1 < threshold 2');
});

test('does NOT fire under cooldown (too soon since the last Deep Think)', () => {
  // The trigger is present (transition into exploit) but the cooldown blocks it.
  const r = shouldDeepThink({ phase: 'exploit', transitioned: true, iterationsSince: 1 });
  assert.equal(r.fire, false);
  assert.match(r.reason, /cooldown/i);
  // Same for the stuck trigger under cooldown.
  assert.equal(shouldDeepThink({ phase: 'validate', stuck: 5, iterationsSince: 0 }).fire, false);
  // At/after the cooldown boundary it fires again.
  assert.equal(shouldDeepThink({ phase: 'exploit', transitioned: true, iterationsSince: 3 }).fire, true);
});

test('opts override stuckAt and cooldown', () => {
  assert.equal(shouldDeepThink({ stuck: 1 }, { stuckAt: 1 }).fire, true, 'lowered stuck threshold');
  assert.equal(shouldDeepThink({ phase: 'exploit', transitioned: true, iterationsSince: 4 }, { cooldown: 5 }).fire, false, 'raised cooldown');
});

test('explicit request fires immediately (bypasses cooldown)', () => {
  const r = shouldDeepThink({ request: true, iterationsSince: 0 });
  assert.equal(r.fire, true);
  assert.match(r.reason, /request/i);
});

test('shouldDeepThink never throws on junk input', () => {
  for (const bad of [undefined, null, 42, 'x', [], { phase: {} }]) {
    const r = shouldDeepThink(bad);
    assert.equal(typeof r.fire, 'boolean');
    assert.equal(typeof r.reason, 'string');
  }
});

// --- deepThinkPrompt: WHAT to ask -----------------------------------------

test('deepThinkPrompt demands >=2 competing hypotheses each with a probe', () => {
  const p = deepThinkPrompt({ phase: 'exploit', objective: 'prove the confirmed admin-panel finding' });
  assert.equal(typeof p, 'string');
  assert.match(p, /hypotheses/i);
  assert.match(p, /\btwo\b/i, 'demands at least TWO');
  assert.match(p, /probe/i, 'demands a disambiguating probe');
  // all four labeled sections present
  assert.match(p, /Situation/);
  assert.match(p, /Competing hypotheses/i);
  assert.match(p, /Recommended approach/i);
  assert.match(p, /Risks/);
  // carries the objective and stays framed as authorized, in-scope reasoning
  assert.match(p, /prove the confirmed admin-panel finding/);
  assert.match(p, /authorized|in-scope/i);
});

test('deepThinkPrompt folds in a stuck note and surface summary when present', () => {
  const p = deepThinkPrompt({ phase: 'validate', objective: 'vet services', surfaceSummary: '3 hosts, 0 findings', stuck: 3 });
  assert.match(p, /3 hosts, 0 findings/);
  assert.match(p, /3 phase/i);
  // still safe with no args
  assert.equal(typeof deepThinkPrompt(), 'string');
});

// --- parseDeepThink: read the response back -------------------------------

const SAMPLE = `**Situation** — Entering the exploit phase against web-01 with one confirmed unauth admin panel, but my first request returned a 403.

**Competing hypotheses**
1. The 403 is IP-based and the panel is reachable only from an allow-listed host. probe: retry through the validated internal jump host.
2. The panel needs a specific Host header / vhost to resolve. probe: replay the request with Host: admin.acme.internal.
3. The finding was a false positive and there is no real admin panel. probe: re-fetch the original evidence URL and diff the response.

**Recommended approach** — Pursue hypothesis 2: recon already saw the vhost, and a Host-header replay is the cheapest test that would explain a blanket 403.

**Risks** — Avoid credential brute force (noisy, out of scope for this window); do not touch hosts outside the signed /24.`;

test('parseDeepThink extracts 2+ hypotheses and the recommended approach', () => {
  const r = parseDeepThink(SAMPLE);
  assert.ok(r.hypotheses.length >= 2, `got ${r.hypotheses.length} hypotheses`);
  assert.equal(r.hypotheses.length, 3);
  assert.match(r.hypotheses[0], /403 is IP-based/);
  assert.match(r.approach, /Pursue hypothesis 2/);
  assert.match(r.sections.situation, /Entering the exploit phase/);
  assert.match(r.sections.risks, /credential brute force/i);
});

test('parseDeepThink handles a bulleted hypotheses list too', () => {
  const bulleted = `Competing hypotheses:
- Wrong target set — probe: rescan the adjacent /24.
- The service is genuinely closed — probe: TCP connect to the port.`;
  const r = parseDeepThink(bulleted);
  assert.equal(r.hypotheses.length, 2);
});

test('parseDeepThink returns the empty shape on junk / unparseable input', () => {
  for (const junk of ['', '   ', 'the quick brown fox jumps over the lazy dog', null, undefined, 12345]) {
    const r = parseDeepThink(junk);
    assert.deepEqual(r.hypotheses, []);
    assert.equal(r.approach, '');
  }
});

// --- isNovel: suppress near-duplicate Deep Thinks -------------------------

const PRIOR = 'hypothesis one wrong target set rescan the authorized range on the internal segment';

test('isNovel is FALSE for a near-duplicate Deep Think', () => {
  const nearDup = PRIOR + ' now'; // one token different -> very high Jaccard
  assert.equal(isNovel(nearDup, PRIOR), false);
});

test('isNovel is TRUE for genuinely different text', () => {
  const different = 'database host exposes default postgres credentials over an internal network connection';
  assert.equal(isNovel(different, PRIOR), true);
});

test('isNovel is TRUE when there is no prior text to compare against', () => {
  assert.equal(isNovel('anything at all', ''), true);
  assert.equal(isNovel('anything at all', undefined), true);
});

test('isNovel threshold is tunable and it never throws', () => {
  // A stricter (lower) threshold makes more things count as "not novel".
  assert.equal(isNovel('alpha beta gamma', 'alpha beta delta', 0.3), false, 'Jaccard 0.5 >= 0.3');
  assert.equal(isNovel('alpha beta gamma', 'alpha beta delta', 0.9), true, 'Jaccard 0.5 < 0.9');
  assert.equal(typeof isNovel(null, null), 'boolean');
});
