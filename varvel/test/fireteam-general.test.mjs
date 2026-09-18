// VARVEL — generalized Fireteam: decomposition + capped, source-tagged fan-out.
// Hermetic: a MOCK runAgent stands in for the governed loop — no LLM, no network.
//   node --test varvel/test/fireteam-general.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fireteam, runFireteam, reconSpecialists, specialistsFor } from '../engine/fireteam.mjs';

const SCOPE = { engagement: 'FT-GEN', signedBy: 'M.Vale L4', cidrs: ['10.20.0.0/16'] };

// A specialist mission is well-formed and independent-shaped.
const wellFormed = (m) => m && typeof m.label === 'string' && m.label &&
  typeof m.system === 'string' && m.system && typeof m.objective === 'string' && m.objective;
const uniq = (arr) => new Set(arr).size === arr.length;

// A mock governed agent that echoes the objective it was handed (so a result's
// label can be checked against the objective actually run) and returns canned
// structured JSON. Mirrors the contract: async ({ system, messages }) => { text, denials, steps }.
const echoAgent = async ({ messages }) => {
  const objective = messages[0].content;
  return { text: `RESULT for <<${objective}>>\n\`\`\`json\n{"hosts":[]}\n\`\`\``, denials: [], steps: 2 };
};

// ---------------------------------------------------------------------------
// specialistsFor — decomposition
// ---------------------------------------------------------------------------

test('specialistsFor: a recon objective decomposes into >=2 independent missions', () => {
  const missions = specialistsFor('enumerate the web attack surface', { scope: SCOPE });
  assert.ok(missions.length >= 2, 'at least two specialists');
  assert.ok(missions.length <= 5, 'no more than five (bounded)');
  for (const m of missions) assert.ok(wellFormed(m), 'each mission is {label, system, objective}');
  assert.ok(uniq(missions.map((m) => m.label)), 'labels are distinct');
  assert.ok(uniq(missions.map((m) => m.objective)), 'objectives are distinct (no shared mission)');
  // Each system carries the signed-scope preamble (governed, in-scope).
  for (const m of missions) assert.ok(m.system.includes('FT-GEN') && m.system.includes('10.20.0.0/16'), 'scope-bound brief');
});

test('specialistsFor: validate + exploit-prep objectives also decompose', () => {
  const val = specialistsFor('validate and vet the findings with disambiguating evidence', { scope: SCOPE });
  assert.ok(val.length >= 2 && val.every(wellFormed), 'validate set');
  assert.ok(uniq(val.map((m) => m.objective)), 'validate missions independent');

  const prep = specialistsFor('prepare exploitation: assess exploitability of the confirmed findings', { scope: SCOPE });
  assert.ok(prep.length >= 2 && prep.every(wellFormed), 'exploit-prep set');
  assert.ok(uniq(prep.map((m) => m.objective)), 'exploit-prep missions independent');
});

test('specialistsFor: exploit-prep is methodology-only — no weaponized payloads in briefs', () => {
  const prep = specialistsFor('exploit-prep for confirmed findings', { scope: SCOPE });
  assert.ok(prep.length >= 2, 'decomposed');
  for (const m of prep) {
    assert.match(m.system, /methodology and guidance only/i, 'brief states methodology-only');
    assert.match(m.system, /do not produce weaponized code or exploit payloads/i, 'brief forbids payloads');
    assert.match(m.system, /countersigned exploit window/i, 'brief defers real action to the gated window');
  }
});

test('specialistsFor: NULL-safe + returns [] when nothing decomposes', () => {
  assert.deepEqual(specialistsFor(null), [], 'null objective');
  assert.deepEqual(specialistsFor(undefined), [], 'undefined objective');
  assert.deepEqual(specialistsFor(''), [], 'empty objective');
  assert.deepEqual(specialistsFor('   '), [], 'whitespace objective');
  assert.deepEqual(specialistsFor(42), [], 'non-string objective');
  assert.deepEqual(specialistsFor('write the final client-ready report'), [], 'synthesis phase does not decompose');
  // Null-safe on a missing scope too (must not throw).
  assert.ok(specialistsFor('enumerate the attack surface').length >= 2, 'works with no scope/opts');
});

// ---------------------------------------------------------------------------
// fireteam — merge + source tagging
// ---------------------------------------------------------------------------

test('fireteam: merges all members and tags each result by its source label', async () => {
  const missions = specialistsFor('enumerate the web attack surface', { scope: SCOPE });
  const results = await fireteam(echoAgent, {}, missions);

  assert.equal(results.length, missions.length, 'every member is represented in the merge');
  assert.ok(uniq(results.map((r) => r.label)), 'each result carries a distinct source label');
  for (const r of results) {
    const src = missions.find((m) => m.label === r.label);
    assert.ok(src, `result label ${r.label} maps to a real specialist`);
    // The echoed objective proves this result came from THIS labelled member's run.
    assert.ok(r.text.includes(src.objective), 'result text attributed to the correct member');
    assert.equal(r.steps, 2, 'step count carried through');
    assert.ok(Array.isArray(r.denials), 'denials carried through');
  }
});

test('runFireteam alias behaves identically to fireteam', async () => {
  const missions = reconSpecialists(SCOPE);
  const results = await runFireteam(echoAgent, {}, missions);
  assert.equal(results.length, missions.length);
  assert.deepEqual(results.map((r) => r.label).sort(), missions.map((m) => m.label).sort());
});

// ---------------------------------------------------------------------------
// caps — bounded concurrency + hard fan-out cap
// ---------------------------------------------------------------------------

const many = (n) => Array.from({ length: n }, (_, i) => ({
  label: `m${i}`, system: `member ${i}`, objective: `mission ${i}`,
}));

test('fireteam: maxConcurrent runs in bounded batches — 8 members, concurrency capped at 3, none dropped', async () => {
  let live = 0, peak = 0;
  const tracked = async () => {
    live++; peak = Math.max(peak, live);
    await new Promise((r) => setTimeout(r, 5)); // force overlap within a batch
    live--;
    return { text: 'ok', denials: [], steps: 1 };
  };
  const members = many(8);
  const results = await fireteam(tracked, {}, members, { maxMembers: 8, maxConcurrent: 3 });

  assert.equal(results.length, 8, 'all 8 members completed (batched, not dropped)');
  assert.deepEqual(results.map((r) => r.label), members.map((m) => m.label), 'order + tags preserved');
  assert.ok(peak <= 3, `never exceeded the concurrency cap (peak=${peak})`);
  assert.equal(peak, 3, 'batching actually ran members in parallel up to the cap');
});

test('fireteam: maxMembers hard-caps fan-out (default 5) — extra specialists are dropped', async () => {
  const results = await fireteam(echoAgent, {}, many(8)); // default opts -> maxMembers 5
  assert.equal(results.length, 5, 'fan-out capped at the default');
  assert.deepEqual(results.map((r) => r.label), ['m0', 'm1', 'm2', 'm3', 'm4'], 'kept the first 5, tagged');
});

// ---------------------------------------------------------------------------
// resilience — a bad member never sinks the wave
// ---------------------------------------------------------------------------

test('fireteam: a member whose agent throws resolves to { error } and the wave still completes', async () => {
  const flaky = async ({ messages }) => {
    if (messages[0].content.includes('boom')) throw new Error('agent 500');
    return { text: 'ok', denials: [], steps: 1 };
  };
  const members = [
    { label: 'good-1', system: 's', objective: 'do a thing' },
    { label: 'bad', system: 's', objective: 'boom this one' },
    { label: 'good-2', system: 's', objective: 'do another thing' },
  ];
  const results = await fireteam(flaky, {}, members);

  assert.equal(results.length, 3, 'wave resolved for every member (did not reject)');
  const bad = results.find((r) => r.label === 'bad');
  assert.ok(bad && typeof bad.error === 'string' && bad.error.length, 'failed member tagged with an error string');
  assert.notEqual(bad.error, 'timeout', 'a thrown error is distinct from a timeout');
  assert.match(bad.error, /agent 500/, 'the underlying error message is surfaced');
  for (const label of ['good-1', 'good-2']) {
    const ok = results.find((r) => r.label === label);
    assert.ok(ok && !ok.error && ok.text === 'ok', `${label} still succeeded`);
  }
});

test('fireteam: a hung member hits the per-member timeout without stalling the wave', async () => {
  const mixed = async ({ messages }) => {
    if (messages[0].content.includes('hang')) return new Promise(() => {}); // never resolves
    return { text: 'fast', denials: [], steps: 1 };
  };
  const members = [
    { label: 'fast', system: 's', objective: 'quick mission' },
    { label: 'hung', system: 's', objective: 'hang forever' },
  ];
  const started = Date.now();
  const results = await fireteam(mixed, {}, members, { timeoutMs: 30 }); // tiny timeout for the test
  const elapsed = Date.now() - started;

  assert.equal(results.length, 2, 'wave resolved despite the hung member');
  assert.ok(elapsed < 5000, `wave was not stalled by the hang (took ${elapsed}ms)`);
  const hung = results.find((r) => r.label === 'hung');
  assert.equal(hung.error, 'timeout', 'hung member resolved to a timeout error, source-tagged');
  const fast = results.find((r) => r.label === 'fast');
  assert.ok(fast && !fast.error && fast.text === 'fast', 'the healthy member completed normally');
});
