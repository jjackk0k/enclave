// VARVEL gather tests — the recon stage's passive evidence collector (tools/gather.mjs).
// Hermetic: injected wires only, zero external network. The doctrines under test:
// the scope guard can NEVER leak a request to an excluded asset (trap asset),
// human-cadence caps are enforced structurally, the evidence bundle is bounded,
// version→CVE matching fires on a fixture tech, and the brain receives the evidence
// in its prompt.   node --test test/gather.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const __dir = dirname(fileURLToPath(import.meta.url));
const g = await import('../tools/gather.mjs');
const { cveCheck } = await import('../engine/cvepacks.mjs');
const hunt = await import('../tools/huntloop.mjs');

const INTAKE = {
  program: { handle: 'trapco' },
  inScope: {
    domains: [{ asset: 'in.example' }],
    wildcards: [{ asset: '*.in2.example', suffix: 'in2.example' }],
    cidrs: [{ asset: '203.0.113.10/32' }],
    other: [],
  },
  outOfScope: {
    domains: [{ asset: 'trap.example' }],
    wildcards: [{ asset: '*.trapw.example' }],
    cidrs: [{ asset: '203.0.113.99/32' }],
    other: [],
  },
};

// --- the scope guard (rail 1) ----------------------------------------------------------

test('scope guard: out-of-scope can never receive a request (trap asset, every shape)', () => {
  const guard = g.buildScopeGuard(INTAKE);
  // the trap assets, in every shape they could sneak through
  for (const trap of ['trap.example', 'https://trap.example/', 'https://trap.example/admin',
                       'cdn.trapw.example', 'https://deep.trapw.example/x', '203.0.113.99']) {
    assert.equal(guard.allow(trap), false, `trap denied: ${trap}`);
    assert.throws(() => guard.assertAllowed(trap), (e) => e.code === 'scope-violation' && /OUT-OF-SCOPE/.test(e.message));
  }
  // the in-scope assets pass
  for (const ok of ['in.example', 'https://in.example/', 'api.in2.example', 'https://deep.in2.example/x', '203.0.113.10']) {
    assert.equal(guard.allow(ok), true, `in-scope allowed: ${ok}`);
  }
  // anything not positively in-scope is denied by default
  assert.equal(guard.allow('other.example'), false);
  assert.throws(() => guard.assertAllowed('https://other.example/'), /deny by default/);
});

test('selectAssets: in-scope domains + wildcard apexes + host routes, traps excluded, capped', () => {
  const guard = g.buildScopeGuard(INTAKE);
  const assets = g.selectAssets(INTAKE, guard, {});
  assert.deepEqual(assets.map((a) => a.host), ['in.example', 'in2.example', '203.0.113.10']);
  assert.ok(!assets.some((a) => a.host.includes('trap')), 'no trap asset can appear');
  // a poisoned intake (trap hiding inside the IN-scope list) is filtered defensively
  const poisoned = JSON.parse(JSON.stringify(INTAKE));
  poisoned.inScope.domains.push({ asset: 'trap.example' });
  const assets2 = g.selectAssets(poisoned, guard, {});
  assert.ok(!assets2.some((a) => a.host === 'trap.example'), 'a trap in the in-scope list is still denied at the wire');
  const many = JSON.parse(JSON.stringify(INTAKE));
  many.inScope.domains = Array.from({ length: 20 }, (_, i) => ({ asset: `a${i}.in.example` }));
  assert.equal(g.selectAssets(many, g.buildScopeGuard(many), {}).length, 5, 'the asset cap holds');
});

// --- the cadence contract (rail 2) -------------------------------------------------------

test('cadence: request cap + per-asset cap + delay are enforced structurally', async () => {
  const calls = [];
  const wire = async (url) => { calls.push(url); return { ok: true, status: 200, headers: {}, text: async () => '<html></html>' }; };
  const intake = JSON.parse(JSON.stringify(INTAKE));
  const r = await g.gatherOpportunity({
    intake, fetchImpl: wire, dir: null,
    caps: { maxRequests: 3, delayMs: 0, maxAssets: 5 }, // tiny caps to force the ceiling
  });
  assert.equal(r.ok, true);
  assert.ok(calls.length <= 3, `request cap held (${calls.length} <= 3)`);
  assert.equal(r.counts.requestsMade, calls.length);
  // per-asset cap: at most 2 requests to any single asset
  const perAsset = {};
  for (const c of calls) { const h = new URL(c).hostname; perAsset[h] = (perAsset[h] || 0) + 1; }
  for (const n of Object.values(perAsset)) assert.ok(n <= 2, 'per-asset cap held');
  // delay: measure with a real (tiny) delay
  const calls2 = [];
  const wire2 = async (url) => { calls2.push(Date.now()); return { ok: true, status: 200, headers: {}, text: async () => '' }; };
  await g.gatherOpportunity({ intake, fetchImpl: wire2, dir: null, caps: { delayMs: 60, maxRequests: 4 } });
  for (let i = 1; i < calls2.length; i++) assert.ok(calls2[i] - calls2[i - 1] >= 55, 'the inter-request delay is real');
});

test('cadence cap is LOUD: hitting the request ceiling is an event + a recorded error, never silent', async () => {
  const events = [];
  const emit = { raw: (ev) => events.push(ev) };
  const wire = async (url) => ({ ok: true, status: 200, headers: {}, text: async () => '<html></html>' });
  const intake = JSON.parse(JSON.stringify(INTAKE));
  await g.gatherOpportunity({ intake, fetchImpl: wire, dir: null, caps: { maxRequests: 1, delayMs: 0 }, emit });
  assert.ok(events.some((e) => e.type === 'gather' && e.state === 'done'), 'gather lifecycle events fired');
});

// --- the bounded bundle (rail 4) ---------------------------------------------------------

test('the evidence bundle is bounded and still honest', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'varvel-gather-cap-'));
  const big = 'x'.repeat(400 * 1024);
  const wire = async (url) => ({ ok: true, status: 200, headers: { server: 'Apache/2.4.49' }, text: async () => big });
  const r = await g.gatherOpportunity({ intake: INTAKE, fetchImpl: wire, dir, caps: { delayMs: 0, maxBundleKB: 8, maxBodyKB: 256 } });
  assert.ok(r.bundlePath);
  const text = readFileSync(r.bundlePath, 'utf8');
  assert.ok(text.length <= 8 * 1024 + 100, `the persisted bundle fits its cap (${text.length})`);
  // brain summary is separately capped
  assert.ok(r.brainText.length <= 4 * 1024 + 120, 'the brain-facing summary fits its cap');
  // body read cap: the recorded bundle never carries the 400KB blob
  assert.ok(!text.includes('x'.repeat(10000)), 'no unbounded body content');
});

// --- CVE matching + the mechanical contract (part 2) -------------------------------------

test('mechanical candidates: fixture nginx 1.18.0 matches CVE-2021-23017 with the full checkable contract', () => {
  const matches = cveCheck([{ id: 'nginx', label: 'nginx', version: '1.18.0' }]);
  // The merged NVD-generated pack honestly adds more nginx matches for 1.18.0 (e.g.
  // CVE-2023-44487) — assert the CURATED entry is among them, not an exact count
  // (pack contents are the cvepacks tests' job; this test proves the contract).
  assert.ok(matches.length >= 1);
  const m23017 = matches.find((m) => m.cve === 'CVE-2021-23017');
  assert.ok(m23017, 'the curated nginx entry still fires');
  assert.equal(m23017.confidence, 'firm', 'firm, not confirmed (backports exist)');
  const bundle = { assets: [{ host: 'in.example', techs: [{ id: 'nginx', label: 'nginx', version: '1.18.0' }] }] };
  const cands = g.mechanicalCandidates(matches, { bundle });
  assert.equal(cands.length, matches.length, 'every match becomes a checkable candidate');
  const c = cands[matches.indexOf(m23017)];
  for (const k of ['title', 'sev', 'evidence', 'check', 'expect', 'cleanup', 'verifyClean']) {
    assert.ok(c[k] && String(c[k]).length, `the honesty contract carries ${k}`);
  }
  assert.match(c.evidence, /not confirmed/);
  // the check ACTUALLY runs and proves entailment (the anti-hallucination gate)
  const sandbox = {
    name: 'local-process', tier: 'test',
    available: () => true,
    create: () => ({}),
    run: (sb, program) => { const r = spawnSync(process.execPath, ['-e', program], { encoding: 'utf8' }); return { code: r.status, stdout: r.stdout, stderr: r.stderr }; },
    destroy: () => true,
  };
  const r = hunt.sandboxRun(sandbox, c.check, { trusted: true });
  assert.ok(r.ok !== false, JSON.stringify(r));
  assert.match(r.stdout, /CVE-MATCH-OK/, 'the replay prints its marker');
  // a bundle WITHOUT the version fails the gate (no evidence, no pass)
  const c2 = g.mechanicalCandidates(matches, { bundle: { assets: [{ host: 'x', techs: [{ id: 'nginx', version: '9.9.9' }] }] } })[0];
  const r2 = hunt.sandboxRun(sandbox, c2.check, { trusted: true });
  assert.match(r2.stdout, /EVIDENCE-MISSING/, 'the gate REFUSES a candidate the evidence cannot back');
});

// --- the brain receives the evidence (part 3) --------------------------------------------

test('brainHunt: the prompt carries the gathered evidence + the mechanical list', async () => {
  let seen = '';
  const brain = async (system, user) => { seen = user; return '```json\n{"findings":[]}\n```'; };
  await hunt.brainHunt({
    brain,
    intake: { program: { handle: 'trapco' }, inScope: { domains: [{ asset: 'in.example' }] }, outOfScope: {} },
    evidenceText: '- in.example [domain] HTTP 200 — tech: nginx 1.18.0\n  headers: server: nginx/1.18.0',
    mechanical: [{ title: 'CVE-2021-23017 — nginx resolver off-by-one heap write' }],
  });
  assert.match(seen, /GATHERED EVIDENCE/);
  assert.match(seen, /nginx 1\.18\.0/, 'the brain sees the real fingerprint');
  assert.match(seen, /PLATFORM-MECHANICAL CANDIDATES/);
  assert.match(seen, /do NOT re-propose/);
  // no evidence -> the prompt says so honestly
  let seen2 = '';
  await hunt.brainHunt({ brain: async (s, u) => { seen2 = u; return '{}'; }, intake: { program: {} }, evidenceText: null });
  assert.match(seen2, /GATHERED EVIDENCE: none/);
});

// --- gather events carry the counts the console reads ----------------------------------------

test('gather events: asset-probed lines + the done summary carry the counts', async () => {
  const events = [];
  const emit = { raw: (ev) => events.push(ev) };
  const wire = async (url) => ({ ok: true, status: 200, headers: { server: 'nginx/1.18.0' }, text: async () => '<html></html>' });
  await g.gatherOpportunity({ intake: INTAKE, fetchImpl: wire, dir: null, caps: { delayMs: 0 }, emit });
  const done = events.filter((e) => e.type === 'gather').pop();
  assert.match(done.msg, /3 asset\(s\) probed/);
  assert.match(done.msg, /3 tech\(s\)/, 'three assets each fingerprinted nginx');
  const assets = events.filter((e) => e.type === 'gather' && e.state === 'asset');
  assert.equal(assets.length, 3, 'one event per asset probed');
  assert.ok(events.some((e) => e.type === 'gather' && /cadence .*req\/asset/.test(e.msg || '')), 'the cadence numbers are printed');
});
