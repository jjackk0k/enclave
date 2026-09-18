// VARVEL event-driven OPSEC AI advisor tests.
//   node --test varvel/test/footprint-ai.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Opsec } from '../engine/opsec.mjs';
import { shouldAdvise, advisorPrompt, footprintAiAdvise, advisorBackend, ADVISOR_KIMI_DEFAULT } from '../engine/footprint-ai.mjs';

function loudOpsec() {
  const o = new Opsec();
  o.act({ kind: 'web-content-scan', host: '10.0.0.1' });
  o.act({ kind: 'exploit-attempt', host: '10.0.0.1' }); // loudness 5 -> high/critical
  return o.toJSON();
}
function quietOpsec() {
  const o = new Opsec();
  o.act({ kind: 'http-fingerprint', host: '10.0.0.1' }); // loudness 1
  return o.toJSON();
}

test('shouldAdvise fires on high/critical risk, not on low', () => {
  assert.equal(shouldAdvise(loudOpsec()).fire, true);
  assert.equal(shouldAdvise(quietOpsec()).fire, false);
});

test('shouldAdvise is event-driven: no re-fire without new noise', () => {
  const j = loudOpsec();
  const first = shouldAdvise(j, null);
  assert.equal(first.fire, true);
  // same action count as we just saw -> nothing new -> do not fire again
  assert.equal(shouldAdvise(j, first.actions).fire, false);
});

test('advisorPrompt is transparency-bound (no evasion vocabulary) and cites the loud activity', () => {
  const d = shouldAdvise(loudOpsec());
  const p = advisorPrompt(d.advisor, { target: '10.0.0.1' });
  assert.match(p, /needless noise/i);
  assert.match(p, /DO NOT suggest evasion/i);
  assert.match(p, /exploit|web/i, 'names a loud activity');
  // evasion terms may appear ONLY inside the explicit prohibition sentence, nowhere else.
  const withoutProhibition = p.replace(/DO NOT suggest[\s\S]*?out of scope\.?/i, '');
  assert.ok(!/anti-forensic|become undetectable|hide the source|log tamper/i.test(withoutProhibition), 'evasion vocabulary confined to the prohibition');
});

test('footprintAiAdvise runs the injected cheap model and returns advice', async () => {
  let seenSystem = '';
  const runAgent = async ({ system, messages }) => { seenSystem = system; return { text: 'Rate-limit the content discovery and prefer passive sources; the 403 pattern suggests a WAF, so slow down.' }; };
  const r = await footprintAiAdvise(loudOpsec(), { target: '10.0.0.1', runAgent });
  assert.equal(r.fired, true);
  assert.match(r.text, /rate-limit/i);
  assert.match(seenSystem, /never evasion/i, 'the system prompt bounds the model');
});

test('footprintAiAdvise does not fire without a backend or on low risk; never throws', async () => {
  assert.equal((await footprintAiAdvise(loudOpsec(), {})).fired, false); // no runAgent
  assert.equal((await footprintAiAdvise(quietOpsec(), { runAgent: async () => ({ text: 'x' }) })).fired, false); // low risk
  const bad = await footprintAiAdvise(loudOpsec(), { runAgent: async () => { throw new Error('boom'); } });
  assert.equal(bad.fired, false); assert.match(bad.error, /boom/);
});

// Backend routing pins (the 2026-08-11 403 fix): the claude-cli subprocess cached a stale,
// exhausted credential, so the DEFAULT backend is Kimi — the auto-refreshed OAuth path the
// main agent already proves alive. Claude survives only as an explicit opt-in fallback.

test('advisorBackend: default routes to Kimi, with NO claude dependency', () => {
  // kimi configured, claude ABSENT -> still enabled (the production case after the fix)
  assert.deepEqual(advisorBackend({}, { kimiUp: true, claudeUp: false }), { backend: 'kimi', model: ADVISOR_KIMI_DEFAULT, effort: 'low' });
  assert.equal(ADVISOR_KIMI_DEFAULT, 'kimi-k2.7-code', 'the cheap default is k2.7-code');
});

test('advisorBackend: a Kimi VARVEL_ADVISOR_MODEL selects that Kimi model', () => {
  assert.deepEqual(advisorBackend({ VARVEL_ADVISOR_MODEL: 'k3' }, { kimiUp: true }), { backend: 'kimi', model: 'k3', effort: 'low' });
  assert.deepEqual(advisorBackend({ VARVEL_ADVISOR_MODEL: 'kimi-k2.7-code' }, { kimiUp: true }), { backend: 'kimi', model: 'kimi-k2.7-code', effort: 'low' });
});

test('advisorBackend: a claude VARVEL_ADVISOR_MODEL is opt-in and requires the CLI', () => {
  assert.deepEqual(advisorBackend({ VARVEL_ADVISOR_MODEL: 'haiku' }, { kimiUp: true, claudeUp: true }), { backend: 'claude', model: 'haiku' });
  // CLI absent -> disabled, NEVER silently rerouted (not even back to a configured kimi)
  assert.equal(advisorBackend({ VARVEL_ADVISOR_MODEL: 'haiku' }, { kimiUp: true, claudeUp: false }), null);
});

test('advisorBackend: no credential for the routed backend -> disabled, never throws', () => {
  assert.equal(advisorBackend({}, { kimiUp: false, claudeUp: true }), null);   // default route, kimi down: claude is NOT an implicit fallback
  assert.equal(advisorBackend({}, {}), null);
});

test('advisorBackend: VARVEL_FOOTPRINT_AI=0 disables the advisor outright', () => {
  assert.equal(advisorBackend({ VARVEL_FOOTPRINT_AI: '0' }, { kimiUp: true, claudeUp: true }), null);
  assert.equal(advisorBackend({ VARVEL_FOOTPRINT_AI: '0', VARVEL_ADVISOR_MODEL: 'haiku' }, { kimiUp: true, claudeUp: true }), null);
});
