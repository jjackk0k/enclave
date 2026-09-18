// VARVEL huntloop tests — the 24/7 autonomous bounty-hunt engine (tools/huntloop.mjs).
// Hermetic: local fixtures + the deterministic mock brain + mkdtemp-isolated hunt and
// watcher dirs, zero external network (the brain is INJECTED — the never-submits pin
// below proves the module itself carries no network/submission code path at all).
// The doctrines under test: the loop mechanics end-to-end (all ten stages, in order,
// from real events), the automation gate (a policy-prohibited program is refused),
// replay-verification as the ONLY road to 'verified', cleanup as a VERIFIED state
// (never asserted), crash-resume via the persisted pending queue, the kernel-isolation
// gate for brain-drafted checks, and the never-submits static pin.
//   node --test test/huntloop.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync, existsSync, readdirSync, mkdirSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dir = dirname(fileURLToPath(import.meta.url));
const FIXTURE = (n) => join(__dir, 'fixtures', n);

// Every test gets its own hunt dir + watcher dir (both resolve at CALL time).
const mk = () => {
  const dir = mkdtempSync(join(tmpdir(), 'varvel-huntloop-'));
  return { dir, h1dir: join(dir, 'h1watch') };
};
const readEvents = (dir) => readFileSync(join(dir, 'events.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
const stageSeq = (events, opp) => events.filter((e) => e.type === 'stage' && (!opp || e.opp === opp)).map((e) => `${e.stage}:${e.state}`);

const hunt = await import('../tools/huntloop.mjs');
const h1 = await import('../tools/h1watch.mjs');
const { cveCheck } = await import('../engine/cvepacks.mjs');

const T1 = '2026-08-25T00:00:00.000Z';

// The injected gather wire (zero external network in tests): 'techy' serves an
// nginx/1.18.0 page (mechanical CVE matches by design — HOW MANY depends on the
// current pack: the curated 9 plus engine/cvepacks.generated.mjs, so assertions
// derive the count from cveCheck itself instead of pinning a pack snapshot);
// 'plain' serves nothing fingerprintable (0 mechanical — the brain-only cases).
const MECH_N = cveCheck([{ id: 'nginx', label: 'nginx', version: '1.18.0' }]).length;
const gatherWire = (kind) => async (url) => {
  if (kind === 'techy' && !url.endsWith('/robots.txt')) {
    return {
      ok: true, status: 200,
      headers: { server: 'nginx/1.18.0' },
      text: async () => '<html><head><title>fixture</title></head><body>fixture page</body></html>',
    };
  }
  if (kind === 'techy') return { ok: true, status: 404, headers: {}, text: async () => 'not found' };
  return { ok: true, status: 200, headers: { server: 'cloudflare' }, text: async () => '<html></html>' };
};

const fixtureLoop = async (dir, h1dir, opts = {}) => {
  process.env.VARVEL_H1WATCH_DIR = h1dir;
  const source = h1.fixtureSource(FIXTURE('h1watch-scan-1.json'));
  return hunt.runLoop({ ghost: 'skip', source, brain: hunt.mockBrain(), dir, once: true, trustedBrain: true, gatherFetch: gatherWire('techy'), ...opts });
};

// --- the never-submits pin (static scan — the same doctrine as test/bountyline.test.mjs) ---

test('the loop NEVER submits — static pin: no network/submission code path in huntloop.mjs', () => {
  const src = readFileSync(join(__dir, '..', 'tools', 'huntloop.mjs'), 'utf8');
  for (const re of [/\bfetch\s*\(/, /node:https?\b/, /\bhttps?\.\s*request\s*\(/, /XMLHttpRequest/, /\bnet\.connect/, /\.submit\s*\(/]) {
    assert.ok(!re.test(src), `the hunt loop must carry NO network/submission code path — matched ${re}`);
  }
  // The ONLY remote conversation rides engine/brain-provider.mjs (the local lane).
  const imports = [...src.matchAll(/from\s+'([^']+)'/g)].map((m) => m[1]);
  assert.ok(imports.includes('../engine/brain-provider.mjs'), 'the brain call is REUSED, never reimplemented');
  assert.ok(!imports.some((i) => /submit/.test(i)), 'no submission module is imported');
});

// --- the full dry-run (the required end-to-end mechanics proof) ------------------------------

test('dry-run: fixture + mock brain drives ALL ten stages; prohibited program gated at scope-check', async () => {
  const { dir, h1dir } = mk();
  const state = await fixtureLoop(dir, h1dir, { now: T1 });
  const events = readEvents(dir);

  // The ten board stages all fired for globex-watch, in doctrine order.
  const seq = stageSeq(events, 'globex-watch').filter((s) => s.endsWith(':active'));
  const order = seq.map((s) => s.split(':')[0]);
  for (const st of ['intake', 'scope-check', 'recon', 'testing', 'vm-verification', 'evidence', 'cleanup', 'report', 'ledger']) {
    assert.ok(order.includes(st), `stage ${st} ran — got ${order.join(', ')}`);
  }
  assert.ok(order.indexOf('testing') < order.indexOf('vm-verification'), 'testing precedes vm-verification');
  assert.ok(order.indexOf('vm-verification') < order.indexOf('evidence'), 'verification precedes evidence');
  assert.ok(order.indexOf('evidence') < order.indexOf('cleanup'), 'evidence precedes cleanup');
  assert.ok(events.some((e) => e.type === 'stage' && e.stage === 'watch' && e.state === 'done'), 'watch ran');

  // acme-watch: the automation gate refused at scope-check (its policy prohibits automation).
  const acmeGate = events.filter((e) => e.type === 'stage' && e.stage === 'scope-check' && e.opp === 'acme-watch').pop();
  assert.equal(acmeGate.state, 'failed');
  assert.match(acmeGate.msg, /PROHIBITED/);
  assert.ok(!events.some((e) => e.type === 'stage' && e.stage === 'recon' && e.opp === 'acme-watch'), 'a prohibited program is never hunted');

  // The finding VERIFIED (replay passed) and cleanup is a VERIFIED state.
  const proof = events.find((e) => e.type === 'proof');
  assert.equal(proof.verified, true);
  assert.equal(proof.recorder, 'transcript+hash', 'asciinema absent on this box — transcript+hash bundle is what shipped');
  const clean = events.find((e) => e.type === 'cleanup');
  assert.equal(clean.state, 'verified-clean', 'clean ✓ is a verified verdict, never a default');

  // Counters: seen 2 (two new-program events); MECH_N mechanical cve-matches from the
  // fixture nginx tech (the merged generated pack widened this beyond the curated 1 —
  // the count derives from cveCheck above, never pinned to a pack snapshot) + 1 brain
  // finding, all replay-VERIFIED, all drafted, all cleaned; failed 1 (acme gate).
  assert.equal(state.counters.seen, 2);
  assert.equal(state.counters.tested, MECH_N + 1);
  assert.equal(state.counters.verified, MECH_N + 1);
  assert.equal(state.counters.unverified, 0);
  assert.equal(state.counters.drafted, MECH_N + 1);
  assert.equal(state.counters.cleaned, MECH_N + 1);
  assert.equal(state.counters.failed, 1);
  assert.equal(state.counters.cveMatches, MECH_N, 'the mechanical CVEs came from the fixture nginx tech');

  // The outbox drafts exist and state the never-submits doctrine + the verdict.
  const outbox = readdirSync(join(dir, 'outbox'));
  assert.equal(outbox.length, MECH_N + 1);
  const md = readFileSync(join(dir, 'outbox', outbox[0]), 'utf8');
  assert.match(md, /HUMAN REVIEW ONLY/);
  assert.match(md, /NEVER submits/);
  // THE HEADER TELLS THE TRUTH (2026-09-18): a replay re-derives the recorded fingerprint
  // OFFLINE and never re-probes the host, so it is FIRM — never "VERIFIED", which read as
  // "a real, fileable bug" over 61 version→CVE matches that programs exclude.
  assert.match(md, /Evidence grade: FIRM/);
  assert.ok(!/Verdict: VERIFIED \(replay-verification PASSED\)/.test(md),
    'the draft header never renders a replay pass as VERIFIED');

  // The evidence bundle: transcript + environment hash + result, all real.
  const evDirs = readdirSync(join(dir, 'evidence')).filter((d) => d !== 'gather');
  const bundle = join(dir, 'evidence', evDirs[0], readdirSync(join(dir, 'evidence', evDirs[0]))[0]);
  const transcript = readFileSync(join(bundle, 'replay-transcript.txt'), 'utf8');
  assert.match(transcript, /VERDICT: VERIFIED/);
  assert.match(transcript, /VERIFY: verified-clean/);
  const env = JSON.parse(readFileSync(join(bundle, 'env.json'), 'utf8'));
  assert.equal(env.recorder, 'transcript+hash');
  assert.ok(env.snippetSha256 && env.node && env.sandbox && env.sandbox.name, 'the environment hash bundle proves WHAT ran WHERE');
  const result = JSON.parse(readFileSync(join(bundle, 'result.json'), 'utf8'));
  assert.equal(result.verified, true);

  // The findings ledger carries the verdicts (mechanical + brain, all replay-verified).
  const ledger = readFileSync(join(dir, 'findings.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
  assert.equal(ledger.length, MECH_N + 1);
  assert.ok(ledger.every((l) => l.verdict === 'verified'));
  assert.ok(ledger.every((l) => l.cleanup === 'verified-clean'));
  assert.ok(ledger.some((l) => /CVE-2021-23017/.test(l.finding)), 'the mechanical nginx CVE candidate is on the ledger');

  // THE GRADE, NOT THE REPLAY (2026-09-18, the findings-board honesty fix): a replay pass is
  // `firm` — a live fingerprint re-derived offline — and an offline replay is NEVER submittable.
  // The board/counters read these fields, so "61 verified" can never be shown again.
  assert.ok(ledger.every((l) => l.grade === 'firm'), 'a replay alone grades firm, never verified');
  assert.ok(ledger.every((l) => l.submittable === false), 'an offline replay is not submittable');
  assert.ok(ledger.every((l) => l.oracleKind === 'self-referential'),
    "bountyreport's own gate names this oracle self-referential (it reads the recorded bundle)");
  assert.equal(state.counters.firm, MECH_N + 1);
  assert.equal(state.counters.submittable, 0, 'nothing is submittable without a demonstration');
});

// --- AUTO-FORGE: confirm it on the spot (the operator's 2026-09-18 ask) ----------------------
// A replay-verified finding is forged IN THE SAME CYCLE; the grade follows the forge's own
// verdict: poc-verified -> poc-demonstrated + submittable, anything else -> firm (honest), and a
// forge that THROWS is fault-isolated (the opportunity keeps every other finding).

test('auto-forge: every verified finding is forged on the spot; poc-verified grades demonstrated', async () => {
  const { dir, h1dir } = mk();
  const forged = [];
  const forge = async ({ finding, evidenceDir }) => {
    forged.push({ title: finding.title, evidenceDir });
    return { verdictClass: 'poc-verified', reason: 'the declared impact marker appeared in the live response' };
  };
  const state = await fixtureLoop(dir, h1dir, { now: T1, forge });
  const events = readEvents(dir);
  const ledger = readFileSync(join(dir, 'findings.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l));

  assert.equal(forged.length, MECH_N + 1, 'every replay-verified finding was forged in this cycle');
  assert.ok(forged.every((f) => f.evidenceDir && existsSync(f.evidenceDir)), 'the forge gets the finding + its real evidence dir');
  assert.ok(ledger.every((l) => l.grade === 'poc-demonstrated'), 'a demonstrated PoC grades poc-demonstrated');
  assert.ok(ledger.every((l) => l.submittable === true), 'a demonstrated PoC is submittable');
  assert.ok(ledger.every((l) => l.forge && l.forge.verdictClass === 'poc-verified'), 'the forge verdict rides the ledger line');
  assert.equal(state.counters.submittable, MECH_N + 1);
  assert.equal(state.counters.firm, 0);
  const forgeSeq = stageSeq(events, 'globex-watch').filter((s) => s.startsWith('poc-forge'));
  assert.ok(forgeSeq.includes('poc-forge:active') && forgeSeq.includes('poc-forge:done'), `the board saw the forge stage — got ${forgeSeq.join(', ')}`);
  const activeOrder = stageSeq(events, 'globex-watch').filter((s) => s.endsWith(':active')).map((s) => s.split(':')[0]);
  assert.ok(activeOrder.indexOf('report') < activeOrder.indexOf('poc-forge'), 'the forge runs after the draft exists (it upgrades it on success)');
  assert.ok(activeOrder.indexOf('poc-forge') < activeOrder.indexOf('ledger'), 'the grade rides the ledger line that follows');
});

test('auto-forge: an unproven or CRASHING forge never inflates the grade (fault-isolated, never lost)', async () => {
  const { dir, h1dir } = mk();
  let n = 0;
  const forge = async () => {
    n += 1;
    if (n === 1) throw Object.assign(new Error('probe transport died'), { code: 'transport-error' });
    return { verdictClass: 'poc-unproven', reason: 'attempts exhausted — the marker never appeared' };
  };
  const state = await fixtureLoop(dir, h1dir, { now: T1, forge });
  const events = readEvents(dir);
  const ledger = readFileSync(join(dir, 'findings.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l));

  assert.equal(ledger.length, MECH_N + 1, 'a throwing forge costs NOTHING — every finding still landed');
  assert.equal(n, MECH_N + 1, 'the forge was attempted for every verified finding');
  assert.ok(ledger.every((l) => l.grade === 'firm'), 'neither an unproven nor a broken forge inflates the grade');
  assert.ok(ledger.every((l) => l.submittable === false));
  assert.equal(state.counters.submittable, 0);
  assert.equal(state.counters.firm, MECH_N + 1);
  assert.ok(ledger.some((l) => l.forge.verdictClass === 'forge-error'), 'the crash is recorded as a forge-error, named honestly');
  assert.ok(ledger.some((l) => l.forge.verdictClass === 'poc-unproven'));
  const forgeStages = stageSeq(events, 'globex-watch').filter((s) => s.startsWith('poc-forge'));
  assert.ok(forgeStages.includes('poc-forge:failed'), 'a failed forge is LOUD on the board');
});

test('makeAutoForge: VARVEL_HUNTLOOP_FORGE=off disables it; the real wire is tools/pocforge.mjs', async () => {
  assert.equal(hunt.makeAutoForge({ brain: {}, env: { VARVEL_HUNTLOOP_FORGE: 'off' } }), null);
  assert.equal(hunt.makeAutoForge({ brain: {}, env: { VARVEL_HUNTLOOP_FORGE: '0' } }), null);
  const on = hunt.makeAutoForge({ brain: {}, env: {} });
  assert.equal(typeof on, 'function', 'on by default — the operator asked for forge-on-confirm');
  // The forge reuses the ONE PoC-forge stage (never a reimplementation): the injected loader
  // resolves to the real module's pocForge export.
  let loaded = null;
  const viaLoader = hunt.makeAutoForge({ brain: {}, env: {}, importForge: async () => (loaded = await import('../tools/pocforge.mjs')) });
  const r = await viaLoader({ finding: { title: 'x' }, evidenceDir: '/nonexistent', dir: mkdtempSync(join(tmpdir(), 'varvel-forge-')), emit: { raw() {}, stage() {} }, now: Date.parse(T1), chain: null });
  assert.match(loaded.DOCTRINE, /^the PoC-forge takes a replay-verified finding/, 'it IS tools/pocforge.mjs — reused, never reimplemented');
  assert.equal(r.ok, false, 'a bundle that is not replay-verified is refused, never assumed');
  assert.ok(typeof r.error === 'string' && r.error.length, `the refusal is named (got '${r.error}')`);
  assert.ok(!/verified/i.test(String(r.error)), 'and it never claims a verification it did not make');
});

// --- crash-resume: the persisted pending queue is independent of fresh scan events ------------

test('crash-resume: a per-cycle cap leaves pending; the next cycle hunts it with ZERO new scan events', async () => {
  const { dir, h1dir } = mk();
  // Cycle 1 with a cap of 1: acme (rank 1) processed, globex stays PENDING.
  const s1 = await fixtureLoop(dir, h1dir, { now: T1, maxOpps: 1 });
  assert.equal(Object.keys(s1.processed).length, 1);
  assert.equal(Object.keys(s1.pending).length, 1, 'globex deferred into the persisted pending queue');

  // Cycle 2: the watcher state already recorded the scan — ZERO fresh events — yet
  // the pending opportunity is still hunted (crash between scan and processing loses nothing).
  const s2 = await fixtureLoop(dir, h1dir, { now: '2026-08-25T01:00:00.000Z' });
  assert.equal(s2.counters.seen, 2, 'no NEW events on the second scan');
  assert.equal(s2.counters.verified, MECH_N + 1, 'the pending opportunity was hunted from the queue (mechanical + brain, all verified)');
  assert.equal(Object.keys(s2.pending).length, 0);
  const events = readEvents(dir);
  assert.equal(events.filter((e) => e.type === 'proof').length, MECH_N + 1, 'every finding proofed exactly once across both cycles — never double-hunted');
});

test('idempotent: a fully-processed fixture re-run changes nothing', async () => {
  const { dir, h1dir } = mk();
  await fixtureLoop(dir, h1dir, { now: T1 });
  const before = readFileSync(join(dir, 'findings.jsonl'), 'utf8');
  const s2 = await fixtureLoop(dir, h1dir, { now: '2026-08-25T02:00:00.000Z' });
  assert.equal(readFileSync(join(dir, 'findings.jsonl'), 'utf8'), before, 'no duplicate ledger lines');
  assert.equal(s2.counters.tested, MECH_N + 1, 'counters are stable across restarts');
});

// --- the anti-hallucination gate: 'verified' ONLY on a replay match ---------------------------

test('verified gating: an expect that never matches stays UNVERIFIED and gets NO report', async () => {
  const { dir, h1dir } = mk();
  process.env.VARVEL_H1WATCH_DIR = h1dir;
  const source = h1.fixtureSource(FIXTURE('h1watch-scan-1.json'));
  const liar = async () => JSON.stringify({ findings: [{
    title: 'Hallucinated claim (gate test)', sev: 'high', evidence: 'claims a marker that never prints',
    check: "console.log('NOTHING-HERE');", expect: 'MARKER-WRITTEN',
    cleanup: "console.log('CLEANED');", verifyClean: "console.log('CLEAN');",
  }] });
  const state = await hunt.runLoop({ ghost: 'skip', source, brain: liar, dir, once: true, trustedBrain: true, gatherFetch: gatherWire('plain') });
  assert.equal(state.counters.tested, 1);
  assert.equal(state.counters.verified, 0, 'a claim that does not reproduce is NEVER verified');
  assert.equal(state.counters.unverified, 1);
  assert.equal(state.counters.drafted, 0, 'an unverified claim is not a draft (the honesty contract)');
  assert.ok(!existsSync(join(dir, 'outbox')) || readdirSync(join(dir, 'outbox')).length === 0, 'no outbox report for an unverified finding');
  const events = readEvents(dir);
  const gate = events.filter((e) => e.type === 'stage' && e.stage === 'vm-verification' && e.opp === 'globex-watch').pop();
  assert.equal(gate.state, 'failed');
  assert.match(gate.msg, /UNPROVEN/, 'a clean run with an absent marker is UNPROVEN — evaluated and the claim did not hold');
  assert.equal(gate.verdictClass, 'unproven', 'the three verdict classes land distinctly');
  const ledger = readFileSync(join(dir, 'findings.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
  assert.equal(ledger[0].verified, false, 'the ledger records the unverified claim HONESTLY (never dropped)');
  assert.equal(ledger[0].verdict, 'unproven', 'the ledger carries the verdict class');
});

// --- cleanup is a VERIFIED state, and residue is LOUD ------------------------------------------

test('cleanup verification: residue is named residue-found, never rendered clean', async () => {
  const { dir, h1dir } = mk();
  process.env.VARVEL_H1WATCH_DIR = h1dir;
  const source = h1.fixtureSource(FIXTURE('h1watch-scan-1.json'));
  const messy = async () => JSON.stringify({ findings: [{
    title: 'Leaves residue (cleanup gate test)', sev: 'low', evidence: 'cleanup verify says RESIDUE',
    check: "console.log('MARKER-WRITTEN');", expect: 'MARKER-WRITTEN',
    cleanup: "console.log('did nothing');", verifyClean: "console.log('RESIDUE');",
  }] });
  const state = await hunt.runLoop({ ghost: 'skip', source, brain: messy, dir, once: true, trustedBrain: true, gatherFetch: gatherWire('plain') });
  assert.equal(state.counters.cleaned, 0, 'no clean ✓ without a verified no-residue check');
  const events = readEvents(dir);
  const clean = events.find((e) => e.type === 'cleanup');
  assert.equal(clean.state, 'residue-found');
  assert.match(clean.detail, /FAILED/);
  const stage = events.filter((e) => e.type === 'stage' && e.stage === 'cleanup').pop();
  assert.equal(stage.state, 'failed');
});

// --- the brain honesty contract -----------------------------------------------------------------

test('brain honesty: unparseable/incomplete brain output is ZERO findings, loudly — and a dead brain parks the opportunity', async () => {
  const p1 = hunt.parseBrainFindings('I found seventeen criticals, trust me');
  assert.equal(p1.ok, false);
  assert.equal(p1.findings.length, 0);
  assert.match(p1.reason, /ZERO findings/);
  const p2 = hunt.parseBrainFindings('```json\n{"findings":[{"title":"x"}]}\n```');
  assert.equal(p2.findings.length, 0, 'a finding without check/expect/cleanup/verifyClean is DROPPED, never repaired');
  assert.equal(p2.dropped, 1);
  const p3 = hunt.parseBrainFindings('```json\n{"findings":[]}\n```');
  assert.equal(p3.ok, true);

  // A brain that throws: recon fails, the opportunity stays PENDING (retried next cycle).
  const { dir, h1dir } = mk();
  process.env.VARVEL_H1WATCH_DIR = h1dir;
  const source = h1.fixtureSource(FIXTURE('h1watch-scan-1.json'));
  const dead = async () => { throw new Error('OpenAI-compatible HTTP 503: lane down / training'); };
  const state = await hunt.runLoop({ ghost: 'skip', source, brain: dead, dir, once: true, trustedBrain: true, gatherFetch: gatherWire('plain') });
  const events = readEvents(dir);
  assert.ok(events.some((e) => e.type === 'brain' && e.state === 'waiting'), 'lane-down is a first-class waiting state, not a crash');
  assert.ok(events.some((e) => e.type === 'stage' && e.stage === 'recon' && e.state === 'failed'));
  const globexKey = hunt.oppKey({ handle: 'globex-watch', type: 'new-program', side: 'in', assets: ['globex.example'] });
  assert.ok(!state.processed[globexKey], 'the opportunity is NOT marked processed — the next cycle retries it');
  assert.equal(state.counters.tested, 0, 'nothing was tested without a brain');

  // resolveBrain refuses a non-openai-compatible provider for the loop (honest, before any call).
  await assert.rejects(() => hunt.brainHunt({ brain: { provider: 'kimi' }, intake: {}, env: {} }), /brain-not-openai-compatible|openai-compatible/);
});

// --- the kernel-isolation gate (rule 3) ---------------------------------------------------------

test('kernel-isolation gate: brain-drafted checks SKIP on the dev tier; trusted checks run', async () => {
  const { dir } = mk();
  const local = (await import('../../poc/isolation/providers/local-process.mjs')).default;
  const untrusted = hunt.sandboxRun(local, "console.log('MARKER-WRITTEN');", { target: join(dir, 't'), trusted: false });
  assert.equal(untrusted.skipped, 'no-kernel-isolation');
  assert.match(untrusted.reason, /dev tier/);
  const trusted = hunt.sandboxRun(local, "console.log('MARKER-WRITTEN');", { target: join(dir, 't'), trusted: true });
  assert.equal(trusted.ok, true);
  assert.match(trusted.stdout, /MARKER-WRITTEN/);
  // A finding gated this way stays UNVERIFIED with the reason named (no silent pass).
  const { dir: d2, h1dir: h2 } = mk();
  process.env.VARVEL_H1WATCH_DIR = h2;
  const source = h1.fixtureSource(FIXTURE('h1watch-scan-1.json'));
  const state = await hunt.runLoop({ ghost: 'skip', source, brain: hunt.mockBrain(), dir: d2, once: true, trustedBrain: false, provider: local, gatherFetch: gatherWire('plain') });
  assert.equal(state.counters.verified, 0);
  assert.equal(state.counters.unverified, 1, 'an untrusted finding on the dev tier is unverified, loudly');
  const events = readEvents(d2);
  assert.ok(events.some((e) => e.type === 'stage' && e.stage === 'testing' && e.state === 'failed' && /no kernel isolation|dev tier/.test(e.msg)));
});

// --- the proof recorder probe ---------------------------------------------------------------------

test('recorder probe: asciinema absent -> transcript+hash (documented); present -> asciinema', () => {
  const absent = hunt.probeRecorder(() => { throw new Error('ENOENT'); });
  assert.equal(absent.recorder, 'transcript+hash');
  assert.match(absent.note, /NOT found/);
  const present = hunt.probeRecorder(() => ({ status: 0, stdout: 'asciinema 2.4.0' }));
  assert.equal(present.recorder, 'asciinema');
});

// --- the live watch refusal is loud (h1watch doctrine, no token) ----------------------------------

test('live watch without VARVEL_H1_TOKEN refuses loudly — the loop invents nothing', async () => {
  const { dir, h1dir } = mk();
  process.env.VARVEL_H1WATCH_DIR = h1dir;
  delete process.env.VARVEL_H1_TOKEN;
  const source = h1.liveSource({});
  assert.equal(source.ok, false);
  assert.equal(source.error, 'h1-token-missing');
  const r = await hunt.runCycle({ source, brain: hunt.mockBrain(), dir, trustedBrain: true });
  assert.equal(r.ok, false);
  assert.equal(r.error, 'h1-token-missing', 'the watch stage fails with the NAMED honest error');
  const events = readEvents(dir);
  assert.ok(events.some((e) => e.type === 'stage' && e.stage === 'watch' && e.state === 'failed'));
});

// --- BUG A/B regressions: ghost wire ownership + liveness -------------------------------------

test('ghost fail-closed: a configured-but-dead chain REFUSES to start (no cycle ever runs)', async () => {
  const { dir, h1dir } = mk();
  process.env.VARVEL_H1WATCH_DIR = h1dir;
  const source = h1.fixtureSource(FIXTURE('h1watch-scan-1.json'));
  const r = await hunt.runLoop({
    source, brain: hunt.mockBrain(), dir, once: true, trustedBrain: true,
    env: { VARVEL_GHOST_CHAIN: 'socks5://127.0.0.1:9' }, // configured, dead
  });
  assert.equal(r.ghostFailed, true, 'the loop failed closed');
  const events = readEvents(dir);
  const ghost = events.find((e) => e.type === 'ghost');
  assert.equal(ghost.state, 'down');
  assert.match(ghost.msg, /refuses to start/);
  assert.ok(events.some((e) => e.type === 'error' && /ghost-chain-down/.test(e.msg)));
  assert.ok(!events.some((e) => e.type === 'stage'), 'NOT ONE stage ran — fail closed means closed');
  assert.ok(events.some((e) => e.type === 'loop' && e.state === 'stopped' && /fail closed/.test(e.msg)));
});

test('ghost in-use: a verified chain is announced (the console card reads this)', async () => {
  const { dir, h1dir } = mk();
  process.env.VARVEL_H1WATCH_DIR = h1dir;
  const source = h1.fixtureSource(FIXTURE('h1watch-scan-1.json'));
  await hunt.runLoop({
    source, brain: hunt.mockBrain(), dir, once: true, trustedBrain: true,
    env: { VARVEL_GHOST_CHAIN: 'socks5://127.0.0.1:1080' },
    ghostCheck: async () => ({ ok: true, detail: 'mock dial ok (test)' }),
    gatherFetch: gatherWire('plain'),
  });
  const ghost = readEvents(dir).find((e) => e.type === 'ghost');
  assert.equal(ghost.state, 'in-use');
  assert.equal(ghost.chain, 'socks5://127.0.0.1:1080');
  assert.match(ghost.msg, /VERIFIED by the loop's own dial/);
});

test('ghost off: no chain configured is said honestly, the fixture lane runs', async () => {
  const { dir, h1dir } = mk();
  process.env.VARVEL_H1WATCH_DIR = h1dir;
  const emptySettings = join(mkdtempSync(join(tmpdir(), 'varvel-hl-noset-')), 'settings.json');
  writeFileSync(emptySettings, '{}');
  process.env.VARVEL_SETTINGS_FILE = emptySettings;
  try {
    const source = h1.fixtureSource(FIXTURE('h1watch-scan-1.json'));
    await hunt.runLoop({ source, brain: hunt.mockBrain(), dir, once: true, trustedBrain: true, env: {}, gatherFetch: gatherWire('plain') });
  } finally {
    delete process.env.VARVEL_SETTINGS_FILE;
  }
  const events = readEvents(dir);
  const ghost = events.find((e) => e.type === 'ghost');
  assert.equal(ghost.state, 'off');
  assert.match(ghost.msg, /DIRECT/);
  assert.ok(events.some((e) => e.type === 'stage' && e.stage === 'watch' && e.state === 'done'), 'the offline lane still runs');
});

test('liveness: cycle summary on EVERY cycle (even zero-diff), heartbeats from scan progress', async () => {
  const { dir, h1dir } = mk();
  process.env.VARVEL_H1WATCH_DIR = h1dir;
  const source = h1.fixtureSource(FIXTURE('h1watch-scan-1.json'));
  await hunt.runLoop({ source, brain: hunt.mockBrain(), dir, once: true, trustedBrain: true, ghost: 'skip', heartbeatMs: 0, gatherFetch: gatherWire('plain') });
  let events = readEvents(dir);
  assert.ok(events.some((e) => e.type === 'heartbeat' && e.stage === 'watch'), 'a heartbeat fired during the scan');
  const summary = events.filter((e) => e.type === 'cycle').pop();
  assert.ok(summary, 'every cycle ends with a summary event');
  assert.match(summary.msg, /cycle 1 done — walk completed 2\/2, 2 event\(s\).*next cycle in/);

  // Second cycle against the same state: ZERO diff — the summary still lands.
  await hunt.runLoop({ source, brain: hunt.mockBrain(), dir, once: true, trustedBrain: true, ghost: 'skip', gatherFetch: gatherWire('plain') });
  events = readEvents(dir);
  const summaries = events.filter((e) => e.type === 'cycle');
  assert.equal(summaries.length, 2, 'the zero-diff cycle summarized too');
  assert.match(summaries[1].msg, /0 event\(s\), 0 opportunity\(ies\) hunted/);
});

test('stage watchdog: a hung scan is aborted and failed LOUDLY, the loop moves on', async () => {
  const { dir, h1dir } = mk();
  process.env.VARVEL_H1WATCH_DIR = h1dir;
  const wedged = { ok: true, gaps: [], listPrograms: () => new Promise(() => {}), programDoc: async () => ({ ok: false }) };
  const t0 = Date.now();
  const r = await hunt.runLoop({
    source: wedged, brain: hunt.mockBrain(), dir, once: true, trustedBrain: true,
    ghost: 'skip', watchBudgetMs: 150, // explicit cap — the computed floor (10min) is bypassed ONLY by an explicit override
  });
  assert.ok(Date.now() - t0 < 10000, 'the watchdog fired fast, not parked');
  const events = readEvents(dir);
  const watch = events.filter((e) => e.type === 'stage' && e.stage === 'watch').pop();
  assert.equal(watch.state, 'failed');
  assert.match(watch.msg, /stage-watchdog-timeout/);
  assert.ok(events.some((e) => e.type === 'cycle'), 'the cycle summary landed even on a watchdog kill');
  assert.equal(r.counters.failed, 1);
});

test('STOP honored mid-stage: the program walk stops between units', async () => {
  const { dir, h1dir } = mk();
  process.env.VARVEL_H1WATCH_DIR = h1dir;
  const source = h1.fixtureSource(FIXTURE('h1watch-scan-1.json'));
  // Write STOP the moment the first program unit completes.
  const origScan = h1; // h1watch module (scan is called by runCycle with hooks)
  void origScan;
  // drive runCycle directly so we can hook onProgress through the module seam:
  // runCycle passes shouldStop = () => existsSync(STOP) — write it from a progress
  // listener by wrapping the source's programDoc.
  const wrapped = {
    ok: true, gaps: [],
    listPrograms: source.listPrograms,
    programDoc: async (handle) => {
      const r = await source.programDoc(handle);
      writeFileSync(join(dir, 'STOP'), 'stop'); // the operator hits STOP after unit 1
      return r;
    },
  };
  await hunt.runCycle({ source: wrapped, brain: hunt.mockBrain(), dir, trustedBrain: true });
  const events = readEvents(dir);
  const watch = events.filter((e) => e.type === 'stage' && e.stage === 'watch').pop();
  assert.equal(watch.state, 'done');
  assert.match(watch.msg, /incomplete — 1\/2 unit\(s\) checkpointed/, 'the partial walk names itself a checkpoint, not a loss');
  assert.match(watch.msg, /resumes next cycle/, 'the resume is promised honestly');
});

// --- walk-mode watchdog sizing (the soak fix) ----------------------------------------------------

test('watchdog sizing: a cold baseline gets the full-cap budget and SAYS so; a complete walk gets the computed floor', async () => {
  // Cold (nothing fingerprinted, no checkpoint, no recorded total): full 40-min cap.
  const { dir, h1dir } = mk();
  process.env.VARVEL_H1WATCH_DIR = h1dir;
  const source = h1.fixtureSource(FIXTURE('h1watch-scan-1.json'));
  await hunt.runLoop({ source, brain: hunt.mockBrain(), dir, once: true, trustedBrain: true, ghost: 'skip', gatherFetch: gatherWire('plain') });
  let events = readEvents(dir);
  let wd = events.find((e) => e.type === 'watchdog');
  assert.equal(wd.mode, 'baseline', 'cold start names itself baseline');
  assert.match(wd.msg, /watch budget 40min/, 'unknown total -> full cap, computed loudly');
  // The completed small walk recorded its reality (total + observed rate) for next time.
  const st = hunt.loadState(dir);
  assert.equal(st.watch.total, 2);
  assert.ok(st.watch.unitMs >= 0);

  // Warm (the 2-unit baseline is complete in h1watch state): the budget drops to the
  // floor — remaining × rate under the 10-min floor — and the mode reads 'diff scan'.
  await hunt.runLoop({ source, brain: hunt.mockBrain(), dir, once: true, trustedBrain: true, ghost: 'skip', gatherFetch: gatherWire('plain') });
  events = readEvents(dir);
  wd = events.filter((e) => e.type === 'watchdog').pop();
  assert.equal(wd.mode, 'diff scan');
  assert.match(wd.msg, /watch budget 10min/, 'a tiny warm walk hits the floor, not the cap');
  // and the zero-diff summary stayed honest
  const summaries = events.filter((e) => e.type === 'cycle');
  assert.match(summaries[1].msg, /completed 2\/2.*0 event\(s\)/);
});

test('watchdog sizing: a resumed walk budgets the REMAINING units, not the whole directory', async () => {
  const { dir, h1dir } = mk();
  process.env.VARVEL_H1WATCH_DIR = h1dir;
  // Pre-seed a checkpoint covering 1 of 2 units + a recorded total/rate in hunt state.
  const h1 = await import('../tools/h1watch.mjs');
  const src = h1.fixtureSource(FIXTURE('h1watch-scan-1.json'));
  const doc = (await src.programDoc('acme-watch')).doc;
  mkdirSync(h1dir, { recursive: true });
  writeFileSync(join(h1dir, 'walk-checkpoint.json'), JSON.stringify({ at: Date.now(), total: 2, docs: { 'acme-watch': doc } }));
  const st = hunt.loadState(dir);
  st.watch = { total: 2, unitMs: 3000 };
  // seed hunt state via a first cheap cycle? No — write-through directly:
  const fs = await import('node:fs');
  fs.writeFileSync(join(dir, 'state.json'), JSON.stringify(st, null, 2));
  await hunt.runCycle({ source: src, brain: hunt.mockBrain(), dir, trustedBrain: true });
  const wd = readEvents(dir).find((e) => e.type === 'watchdog');
  // remaining = 1 unit × 3000ms × 1.5 = 4.5s -> floor 10min. The MESSAGE names the
  // checkpoint and the arithmetic — that is the honest budget.
  assert.match(wd.msg, /1 checkpointed \+ \d+ fingerprinted of 2 unit/);
  assert.match(wd.msg, /watch budget 10min/);
  const watch = readEvents(dir).filter((e) => e.type === 'stage' && e.stage === 'watch').pop();
  assert.match(watch.msg, /resumed from 1/);
});

// --- the 2026-09-11 evidence-path defect: intake enforcement + verdict classes ------------------

test('intake: a brain check that reads evidence from a file path is DROPPED with the named defect', () => {
  const r = hunt.parseBrainFindings('```json\n{"findings":['
    + '{"title":"reads the bundle path","sev":"low","evidence":"x","check":"const fs=require(\'node:fs\');const b=JSON.parse(fs.readFileSync(BUNDLE,\'utf8\'));console.log(\'X\');","expect":"X","cleanup":"console.log(1)","verifyClean":"console.log(\'CLEAN\')"},'
    + '{"title":"reads a gather file","sev":"low","evidence":"x","check":"const fs=require(\'node:fs\');fs.readFileSync(\'evidence/gather/x.json\',\'utf8\');console.log(\'Y\');","expect":"Y","cleanup":"console.log(1)","verifyClean":"console.log(\'CLEAN\')"},'
    + '{"title":"good EVIDENCE user","sev":"low","evidence":"x","check":"console.log(EVIDENCE.assets.length?\'Z\':\'Z\');","expect":"Z","cleanup":"console.log(1)","verifyClean":"console.log(\'CLEAN\')"}'
    + ']}\n```');
  assert.equal(r.findings.length, 1, 'only the EVIDENCE-object check survives');
  assert.equal(r.findings[0].title, 'good EVIDENCE user');
  assert.equal(r.defects.length, 2);
  assert.match(r.reason, /check-references-unreachable-evidence/);
  assert.match(r.reason, /EVIDENCE object/);
});

test('verdict classes: verified / check-defect / unproven land distinctly', () => {
  const mk = (t, r) => ({ test: t, replay: r, expect: 'M' });
  const okRun = (out) => ({ ok: true, code: 0, stdout: out, stderr: '' });
  const crashRun = { ok: true, code: 1, stdout: '', stderr: 'Error: ENOENT' };
  const timeoutRun = { ok: true, code: null, stdout: '', stderr: '' };
  assert.equal(hunt.classifyVerdict(mk(okRun('M'), okRun('M'))).verdict, 'verified');
  const defect = hunt.classifyVerdict(mk(crashRun, crashRun));
  assert.equal(defect.verdict, 'check-defect');
  assert.match(defect.reason, /NEVER EVALUATED/);
  assert.match(defect.reason, /ENOENT/);
  const tdefect = hunt.classifyVerdict(mk(timeoutRun, timeoutRun));
  assert.equal(tdefect.verdict, 'check-defect');
  assert.match(tdefect.reason, /timeout-beyond-budget/);
  const unproven = hunt.classifyVerdict(mk(okRun(''), okRun('')));
  assert.equal(unproven.verdict, 'unproven');
  assert.match(unproven.reason, /UNPROVEN/);
  // a replay crash after a clean marker-absent probe is still a defect (never evaluated)
  assert.equal(hunt.classifyVerdict(mk(okRun(''), crashRun)).verdict, 'check-defect');
});

test('evidence-inline: a brain-drafted check on the EVIDENCE object evaluates in the sandbox', async () => {
  const { dir, h1dir } = mk();
  process.env.VARVEL_H1WATCH_DIR = h1dir;
  const source = h1.fixtureSource(FIXTURE('h1watch-scan-1.json'));
  // the brain uses EVIDENCE properly (no file paths) — the gather wire fingerprints nginx
  const goodBrain = async () => JSON.stringify({ findings: [{
    title: 'nginx tech disclosed by evidence (contract-fixed brain check)',
    sev: 'low', evidence: 'the evidence bundle fingerprints nginx on the asset',
    check: "const hit=(EVIDENCE.assets||[]).find(a=>(a.techs||[]).some(t=>t.id==='nginx'));console.log(hit?'NGINX-EVIDENCED':'ABSENT');",
    expect: 'NGINX-EVIDENCED',
    cleanup: "console.log('CLEANED');", verifyClean: "console.log('CLEAN');",
  }] });
  const state = await hunt.runLoop({ ghost: 'skip', source, brain: goodBrain, dir, once: true, trustedBrain: true, gatherFetch: gatherWire('techy') });
  const events = readEvents(dir);
  const proof = events.filter((e) => e.type === 'proof').find((e) => /nginx-tech/.test(e.finding));
  assert.ok(proof, 'the brain finding was evaluated');
  assert.equal(proof.verdict, 'verified', 'a proper EVIDENCE check verifies — the defect class is gone from the healthy path');
  assert.equal(state.counters.verified, MECH_N + 1, 'mechanical nginx CVEs + the brain nginx evidence check all verify');
});

test('evidence-inline: an empty EVIDENCE object is honest (ABSENT, not a crash)', async () => {
  const { dir, h1dir } = mk();
  process.env.VARVEL_H1WATCH_DIR = h1dir;
  const source = h1.fixtureSource(FIXTURE('h1watch-scan-1.json'));
  const pessBrain = async () => JSON.stringify({ findings: [{
    title: 'expects evidence that is not there', sev: 'low', evidence: 'claims nginx',
    check: "const hit=(EVIDENCE.assets||[]).find(a=>(a.techs||[]).some(t=>t.id==='nginx'));console.log(hit?'NGINX-EVIDENCED':'ABSENT');",
    expect: 'NGINX-EVIDENCED',
    cleanup: "console.log('CLEANED');", verifyClean: "console.log('CLEAN');",
  }] });
  // plain wire: nothing fingerprintable -> EVIDENCE has assets but no nginx tech
  await hunt.runLoop({ ghost: 'skip', source, brain: pessBrain, dir, once: true, trustedBrain: true, gatherFetch: gatherWire('plain') });
  const proof = readEvents(dir).filter((e) => e.type === 'proof').find((e) => /expects-evidence/.test(e.finding));
  assert.equal(proof.verdict, 'unproven', 'evaluated, marker absent = UNPROVEN — never a defect when the check runs clean');
});

test('the check text is persisted for every finding (re-runnable forever)', async () => {
  const { dir, h1dir } = mk();
  await fixtureLoop(dir, h1dir, { now: T1 });
  const evDirs = readdirSync(join(dir, 'evidence')).filter((d) => d !== 'gather');
  const first = join(dir, 'evidence', evDirs[0], readdirSync(join(dir, 'evidence', evDirs[0]))[0]);
  const checkText = readFileSync(join(first, 'check.txt'), 'utf8');
  assert.ok(checkText.length > 20, 'the full check snippet is on disk, not just a hash');
});

// --- MID-HUNT LANE-UP: the spawn-with-no-model self-heal (the 2026-09-14 audit fix) -------------------
// A hunt started while the lane was training carries NO model id (the console only knows it
// when the lane is up AT SPAWN). Without the fix the recon stage fails every cycle FOREVER
// with 'needs a model id' — the console's "recon waits for the lane" promise is false. With
// the fix the loop asks the lane for its OWN roster the moment the lane answers; a lane that
// is still down keeps the original named refusal (nothing is invented).

const mockLane = (findings, opts = {}) => new Promise((resolve) => {
  const server = createServer((req, res) => {
    if (req.url.endsWith('/v1/models')) {
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ data: [{ id: 'lane-test-model' }] }));
      return;
    }
    if (req.url.endsWith('/v1/chat/completions')) {
      res.setHeader('content-type', 'application/json'); // one-shot, not SSE — callOpenAI accepts it honestly
      res.end(JSON.stringify({ choices: [{ message: { content: JSON.stringify({ findings }) }, finish_reason: opts.finish || 'stop' }] }));
      return;
    }
    res.statusCode = 404;
    res.end();
  });
  server.listen(0, '127.0.0.1', () => resolve(server));
});

test('brainHunt: a spawn with NO model id self-resolves from the lane roster the moment the lane answers', async () => {
  const server = await mockLane([{ title: 'T1', check: 'console.log(1)', expect: '1', cleanup: 'console.log(2)', verifyClean: 'console.log(3)' }]);
  const port = server.address().port;
  try {
    const events = [];
    const emit = { raw: (e) => events.push(e) };
    const text = await hunt.brainHunt({
      brain: { baseUrl: `http://127.0.0.1:${port}/v1`, env: { VARVEL_BRAIN_PROVIDER: 'openai-compatible' } },
      intake: { program: { handle: 'x' }, inScope: [], outOfScope: [], policy: null },
      emit, opp: { handle: 'x' },
    });
    const parsed = hunt.parseBrainFindings(text);
    assert.equal(parsed.findings.length, 1, 'the lane answer lands as findings (the recon wait is over)');
    assert.equal(parsed.findings[0].title, 'T1');
    assert.ok(events.some((e) => e.type === 'brain' && e.state === 'model-resolved'), 'the model resolution rides the event stream LOUDLY (the board shows it)');
  } finally {
    server.close();
  }
});

test('brainHunt: a lane that is still down keeps the ORIGINAL named refusal (no model invented)', async () => {
  await assert.rejects(
    hunt.brainHunt({
      brain: { baseUrl: 'http://127.0.0.1:1/v1', env: { VARVEL_BRAIN_PROVIDER: 'openai-compatible' } },
      intake: { program: { handle: 'x' }, inScope: [], outOfScope: [], policy: null },
    }),
    /needs a model id/,
  );
});

// --- 2026-09-16 (the td-bank unparseable-answer lesson): an honest ZERO must be
// distinguishable from a budget truncation. Reasoning lanes burn reasoning_content BEFORE
// the text channel, so a ceiling can truncate the JSON mid-answer (finish 'length') and
// the loop would record 'no parseable block' with no trace of WHY. The answer's SHAPE
// (text/reasoning/finish, bounded head when it looks truncated) now rides the event
// stream — diagnosis without invention; the parse contract itself is unchanged.

test('brainHunt: the answer shape (finish reason, bounded head) rides the events on a truncated-looking answer', async () => {
  const server = await mockLane([{ title: 'T1', check: 'console.log(1)', expect: '1', cleanup: 'console.log(2)', verifyClean: 'console.log(3)' }], { finish: 'length' });
  const port = server.address().port;
  try {
    const events = [];
    const emit = { raw: (e) => events.push(e) };
    const text = await hunt.brainHunt({
      brain: { baseUrl: `http://127.0.0.1:${port}/v1`, env: { VARVEL_BRAIN_PROVIDER: 'openai-compatible' } },
      intake: { program: { handle: 'x' }, inScope: [], outOfScope: [], policy: null },
      emit, opp: { handle: 'x' },
    });
    assert.ok(hunt.parseBrainFindings(text).ok, 'a complete answer still parses (observability never changes the contract)');
    const shape = events.find((e) => e.type === 'brain' && e.state === 'answer-shape');
    assert.ok(shape, 'the answer-shape event exists');
    assert.match(shape.msg, /finish=max_tokens/, 'the finish reason is named (the adapter maps OpenAI length → max_tokens)');
    assert.match(shape.msg, /text=\d+ch reasoning=\d+ch/, 'both channels are counted (reasoning lanes burn tokens invisibly otherwise)');
    const head = events.find((e) => e.type === 'brain' && e.state === 'answer-head');
    assert.ok(head, 'a length-finish carries the bounded answer head for diagnosis');
    assert.ok(head.msg.length <= 400, 'the head is bounded');
  } finally {
    server.close();
  }
});

test('a wasted recon (unparseable brain, NO mechanical candidates) parks the opportunity for a clean retry instead of burning it', async () => {
  const { dir, h1dir } = mk();
  process.env.VARVEL_H1WATCH_DIR = h1dir;
  const source = h1.fixtureSource(FIXTURE('h1watch-scan-1.json'));
  const garbage = async () => 'I looked at everything and it is all definitely vulnerable, trust me';
  const state = await hunt.runLoop({ ghost: 'skip', source, brain: garbage, dir, once: true, trustedBrain: true, gatherFetch: gatherWire('plain') });
  const events = readEvents(dir);
  const stage = events.filter((e) => e.type === 'stage' && e.stage === 'recon' && e.state === 'failed').pop();
  assert.ok(stage, 'the recon stage FAILED loudly (not a silent zero)');
  assert.match(stage.msg, /kept pending for the next cycle/);
  const globexKey = hunt.oppKey({ handle: 'globex-watch', type: 'new-program', side: 'in', assets: ['globex.example'] });
  assert.ok(!state.processed[globexKey], 'the opportunity is NOT burned — the next cycle retries it');
  assert.equal(state.counters.tested, 0, 'nothing was tested on a wasted recon');
  assert.ok(events.some((e) => e.type === 'brain' && e.state === 'waiting'), 'the brain-waiting state is visible on the board');
});

// --- 2026-09-16 (the outbox triage lesson): kill-class candidates die at INTAKE ------
// 13/38 outbox drafts were replay-verified garbage (robots.txt, header observations)
// because the loop had no doctrine filter. The gate (engine/lanes.mjs intakeGate —
// REUSED, never reimplemented) drops kill classes before the sandbox, the ledger, or
// the outbox ever see them, and PARKs qualifier-missing classes (unchained CSRF) for
// a human session. Mechanical CVE candidates bypass the gate BY DESIGN: deterministic
// fingerprint verifications of real CVEs, whose English prose the gate must not judge
// (ALPACA's description says 'TLS'; SSRF-in-mod_rewrite is a real payable CVE) —
// their FILE-or-NO-FILE verdict stays with the filing-time scopecheck + the human.

const lanes = await import('../engine/lanes.mjs');

test('intakeGate: kill-classes die, paid classes pass, park classes park, UNKNOWN classes pass (honest by construction)', () => {
  const g = (t, ev) => lanes.intakeGate({ title: t, evidence: ev || '' });
  for (const t of ['robots.txt reveals internal admin paths', 'Missing HSTS header on login page', 'Server banner discloses nginx version', 'Directory listing enabled on /backups', 'Username enumeration via login timing']) {
    assert.equal(g(t).verdict, 'kill', `kill-class: ${t}`);
    assert.ok(g(t).rule.length > 10, 'the rule is cited, never silent');
  }
  for (const t of ['SQL injection in /api/orders sort parameter', 'IDOR: order invoices readable across tenants', 'Unauthenticated admin API access via missing authz middleware']) {
    assert.equal(g(t).verdict, 'pass', `paid class: ${t}`);
  }
  assert.equal(g('CSRF on profile email update').verdict, 'park', 'unchained CSRF parks');
  assert.equal(g('CSRF chain: token flip to settings write then stored payload').verdict, 'pass', 'CHAINED CSRF passes');
  assert.equal(g('A genuinely novel class nobody named yet', 'evidence supports it').verdict === 'pass', true, 'UNKNOWN classes pass — the sandbox replay is the next gate; the gate never invents what a check does');
});

test('loop-level: a brain kill-class candidate is dropped at intake — never tested, never ledgered, never drafted; the paid candidate beside it runs; park never auto-tests', async () => {
  const { dir, h1dir } = mk();
  process.env.VARVEL_H1WATCH_DIR = h1dir;
  const source = h1.fixtureSource(FIXTURE('h1watch-scan-1.json'));
  const good = {
    title: 'Mock: unauthenticated marker write into the target scratch (loop-mechanics proof)',
    sev: 'med',
    evidence: 'paid-class mock finding: the check writes a marker into TARGET and verification replays it',
    check: "const fs=require('node:fs');fs.mkdirSync(TARGET,{recursive:true});fs.writeFileSync(require('node:path').join(TARGET,'hunt-poc-marker.txt'),'HUNT-POC '+new Date().toISOString());console.log('MARKER-WRITTEN');",
    expect: 'MARKER-WRITTEN',
    cleanup: "require('node:fs').rmSync(require('node:path').join(TARGET,'hunt-poc-marker.txt'),{force:true});console.log('CLEANED');",
    verifyClean: "console.log(require('node:fs').existsSync(require('node:path').join(TARGET,'hunt-poc-marker.txt'))?'RESIDUE':'CLEAN');",
  };
  const kill = { ...good, title: 'robots.txt discloses admin paths', sev: 'info', check: "console.log('NEVER-RUNS');", expect: 'NEVER-RUNS' };
  const park = { ...good, title: 'CSRF on the profile email update form', check: "console.log('NEVER-RUNS');", expect: 'NEVER-RUNS' };
  const brain = async () => JSON.stringify({ findings: [kill, park, good] });
  const state = await hunt.runLoop({ ghost: 'skip', source, brain, dir, once: true, trustedBrain: true, provider: (await import('../../poc/isolation/providers/local-process.mjs')).default, gatherFetch: gatherWire('plain') });
  const events = readEvents(dir);
  assert.equal(state.counters.killed, 1, 'the kill-class candidate was counted as killed');
  assert.equal(state.counters.parked, 1, 'the park-class candidate was counted as parked');
  assert.equal(state.counters.tested, 1, 'ONLY the paid candidate reached the sandbox');
  assert.equal(state.counters.verified, 1);
  assert.equal(state.counters.drafted, 1, 'only the paid candidate was drafted');
  const gateKill = events.find((e) => e.type === 'gate' && e.state === 'killed');
  assert.ok(gateKill, 'the kill rides the board LOUDLY');
  assert.match(gateKill.msg, /DOCTRINE KILL/);
  const gatePark = events.find((e) => e.type === 'gate' && e.state === 'parked');
  assert.ok(gatePark && /human session/.test(gatePark.msg), 'the park names the human-qualifier rule');
  const ledger = readFileSync(join(dir, 'findings.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
  assert.equal(ledger.length, 1, 'the ledger carries ONLY the tested candidate');
  assert.doesNotMatch(ledger[0].finding, /robots\.txt/);
  const outbox = readdirSync(join(dir, 'outbox'));
  assert.equal(outbox.length, 1, 'the outbox carries ONLY the paid draft');
});


// --- 2026-09-17 (the container-name wedge): sandbox names are NEVER reusable, and one ------
// failed sandbox must not take the rest of the opportunity down with it. Measured defect:
// the fixture opportunity produced 12 mechanical + 1 brain = 13 checkable findings, but a
// container left behind by a killed run (docker `--rm` does not reap a never-STARTED
// container) collided on the deterministic name `enclave-hunt-verify-<48-char-slug>`, so
// `docker create` threw — out of the per-finding loop, aborting the opportunity with 1 of
// 13 findings done, and it recurred on every later run (the name never changes).

test('sandbox session ids are unique per invocation — a leaked container can never wedge a run', () => {
  const seen = [];
  const provider = {
    name: 'docker', tier: 'fixture', enforces: { kernelIsolation: 'fixture' },
    create(s) { seen.push(s.session_id); return { id: s.session_id, container: 'enclave-' + s.session_id }; },
    run: () => ({ code: 0, stdout: 'MARKER', stderr: '' }),
    destroy: () => true,
  };
  for (let i = 0; i < 2; i += 1) {
    const r = hunt.sandboxRun(provider, "console.log('MARKER');", { target: 't', sessionId: 'hunt-verify-same-slug', trusted: true });
    assert.equal(r.ok, true, 'both invocations run');
  }
  assert.equal(seen.length, 2);
  assert.notEqual(seen[0], seen[1], 'the SAME caller label twice must never reuse a sandbox name');
  assert.ok(seen.every((id) => id.startsWith('hunt-verify-same-slug-')), 'the caller label stays the traceable prefix');
  assert.ok(seen.every((id) => /-[0-9a-f]{8}$/.test(id)), 'each name carries a fresh random suffix');
});

test('fault isolation: a provider failure on ONE finding leaves the other findings verified (no opportunity abort)', async () => {
  const { dir, h1dir } = mk();
  process.env.VARVEL_H1WATCH_DIR = h1dir;
  const source = h1.fixtureSource(FIXTURE('h1watch-scan-1.json'));
  const local = (await import('../../poc/isolation/providers/local-process.mjs')).default;
  // The first mechanical candidate dies EXACTLY as the leaked-container collision did —
  // at create, before any check ran.
  const wedged = {
    name: 'docker', tier: 'container (fixture wedge)', enforces: { kernelIsolation: 'namespaces + seccomp' },
    create(s) {
      if (/hunt-test-cve-2021-23017/.test(s.session_id)) throw new Error('docker create failed: Conflict. The container name "/enclave-hunt-test-..." is already in use');
      return local.create(s);
    },
    run: (sb, code) => local.run(sb, code),
    destroy: (sb) => local.destroy(sb),
  };
  const state = await hunt.runLoop({ ghost: 'skip', source, brain: hunt.mockBrain(), dir, once: true, trustedBrain: true, provider: wedged, gatherFetch: gatherWire('techy'), now: T1 });
  const events = readEvents(dir);

  // Every candidate was still ATTEMPTED — nothing was silently dropped by the wedge.
  assert.equal(state.counters.tested, MECH_N + 1, 'all checkable findings were still attempted');
  assert.equal(state.counters.unverified, 1, 'the wedged finding is UNVERIFIED, loudly — never verified, never invented');
  assert.equal(state.counters.verified, MECH_N, 'every other finding still verified (mechanical + brain)');
  assert.equal(state.counters.drafted, MECH_N, 'no draft for the unverified finding');

  // The plumbing failure is NAMED on the board with its reason.
  const fail = events.find((e) => e.type === 'stage' && e.stage === 'testing' && e.state === 'failed' && /plumbing failed/.test(e.msg || ''));
  assert.ok(fail, 'the provider failure rides the event stream with its reason');
  assert.match(fail.msg, /already in use/, 'the provider error text is quoted, not paraphrased');
  assert.match(fail.msg, /NEVER EVALUATED/, 'the verdict class is named (never evaluated, not "unproven")');

  // THE REGRESSION: the opportunity COMPLETED instead of aborting and staying pending forever.
  const globexKey = hunt.oppKey({ handle: 'globex-watch', type: 'new-program', side: 'in', assets: ['globex.example'] });
  assert.ok(state.processed[globexKey], 'the opportunity is done — one wedged sandbox no longer leaves it pending');
  assert.equal(Object.keys(state.pending).length, 0);
  assert.ok(!events.some((e) => e.type === 'stage' && e.stage === 'ledger' && e.state === 'failed' && /aborted loudly/.test(e.msg || '')), 'no whole-opportunity abort');

  // The ledger is honest about the wedge: one unverified line beside the verified ones.
  const ledger = readFileSync(join(dir, 'findings.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
  assert.equal(ledger.length, MECH_N + 1, 'every attempted finding is ledgered');
  assert.equal(ledger.filter((l) => l.verified).length, MECH_N);
  const un = ledger.find((l) => !l.verified);
  assert.match(un.reason, /plumbing failed/, 'the ledger line carries the plumbing reason');
  assert.doesNotMatch(JSON.stringify(un), /CVE-MATCH-OK/, 'no fabricated evidence on the unverified line');
});

// --- the BRAIN-FIDELITY GATE (the 300M-token lesson, 2026-09-18) ---------------------
// A real brain object must prove it can drive the platform's tool surface BEFORE the
// loop spends a cycle: a lane scoring 0.5 against the 1.0 floor burned 241 cycles for
// 0 submittable findings. Fail closed, same contract as the ghost preflight.

const fidelityLane = (handler) => new Promise((resolve) => {
  const server = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      let parsed = {};
      try { parsed = JSON.parse(body); } catch { /* tolerate */ }
      const reply = handler(parsed);
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ choices: [{ message: { content: reply.content || '', tool_calls: reply.tool_calls || [] }, finish_reason: reply.finish || (reply.tool_calls ? 'tool_calls' : 'stop') }] }));
    });
  });
  server.listen(0, '127.0.0.1', () => resolve(server));
});
const FID_TCS = [
  { scenario: 'recon-curl', tool: 'Bash', args: { command: 'curl -I http://192.168.50.10/' } },
  { scenario: 'write-evidence', tool: 'Write', args: { file_path: 'evidence/marker.txt', content: 'VVL-9f2' } },
  { scenario: 'read-notes', tool: 'Read', args: { file_path: 'notes.txt' } },
  { scenario: 'edit-notes', tool: 'Edit', args: { file_path: 'notes.txt', old_string: 'stale', new_string: 'fresh' } },
];

const whichScenario = (body) => FID_TCS.find((f) => body.messages.some((m) => String(m.content || '').includes('fidelity:' + f.scenario)));

test('brain-fidelity gate: a lane that cannot make the tool calls is REFUSED at startup (fail closed)', async () => {
  const server = await fidelityLane(() => ({ content: 'I would start by running reconnaissance on the target.' }));
  const port = server.address().port;
  try {
    const { dir, h1dir } = mk();
    process.env.VARVEL_H1WATCH_DIR = h1dir;
    const source = h1.fixtureSource(FIXTURE('h1watch-scan-1.json'));
    const r = await hunt.runLoop({ source, brain: { baseUrl: `http://127.0.0.1:${port}/v1`, model: 'flash-wannabe' }, dir, once: true, trustedBrain: true, ghost: 'skip', gatherFetch: gatherWire('plain') });
    assert.equal(r.fidelityFailed, true, 'the loop failed closed on the fidelity gate');
    const events = readEvents(dir);
    const gate = events.find((e) => e.type === 'brain-fidelity');
    assert.ok(gate, 'the gate result rides the event stream');
    assert.equal(gate.state, 'fail');
    assert.ok(gate.score < gate.floor, 'the score is below the floor and recorded');
    assert.ok(events.some((e) => e.type === 'loop' && e.state === 'stopped' && /BELOW FLOOR/.test(e.msg)), 'the stop names the fidelity refusal');
    assert.ok(!events.some((e) => e.type === 'stage' && e.stage === 'recon'), 'NOT ONE recon stage ran on the failed brain');
  } finally { server.close(); }
});

test('brain-fidelity gate: a compliant lane passes and the loop runs its cycle', async () => {
  const server = await fidelityLane((body) => {
    const f = whichScenario(body);
    // the RECON brain call after the gate has no fidelity marker — answer it with a
    // parseable findings block so the cycle completes (an unanswered request hangs chatOnce).
    if (!f) return { content: '```json\n{"findings":[]}\n```' };
    return { tool_calls: [{ id: 'call_1', type: 'function', function: { name: f.tool, arguments: JSON.stringify(f.args) } }] };
  });
  const port = server.address().port;
  try {
    const { dir, h1dir } = mk();
    process.env.VARVEL_H1WATCH_DIR = h1dir;
    const source = h1.fixtureSource(FIXTURE('h1watch-scan-1.json'));
    const r = await hunt.runLoop({ source, brain: { baseUrl: `http://127.0.0.1:${port}/v1`, model: 'compliant-lane' }, dir, once: true, trustedBrain: true, ghost: 'skip', gatherFetch: gatherWire('techy') });
    assert.ok(!r.fidelityFailed, 'the gate passed and the loop ran');
    const events = readEvents(dir);
    const gate = events.find((e) => e.type === 'brain-fidelity');
    assert.equal(gate.state, 'pass');
    assert.equal(gate.score, 1, '4/4 scenarios — the lane drives the surface');
    assert.ok(events.some((e) => e.type === 'stage' && e.stage === 'recon'), 'the cycle ran after the gate passed');
  } finally { server.close(); }
});

test('brain-fidelity gate: injected function brains (mocks/tests) skip honestly', async () => {
  const { dir, h1dir } = mk();
  process.env.VARVEL_H1WATCH_DIR = h1dir;
  const source = h1.fixtureSource(FIXTURE('h1watch-scan-1.json'));
  const r = await fixtureLoop(dir, h1dir, { now: T1 });
  assert.ok(!r.fidelityFailed, 'the mock lane is not gated (the harness has its own suites)');
  assert.ok(!readEvents(dir).some((e) => e.type === 'brain-fidelity'), 'no fidelity event for an injected brain');
});

// --- THE VALIDATOR PASS (the refuter: 2026-09-18 spec §1) ---------------------------
// Mechanical replay proves the check RUNS; the refuter is the second brain that tries
// to KILL the reasoning. refute parks (never a report); hold proceeds; unavailable
// never silently downgrades; a refutation that cites nothing in the bundle is discarded.

const refuterBrain = (fn) => async ({ finding, evidence }) => fn({ finding, evidence });

const validatorCycle = async (opts = {}) => {
  const { dir, h1dir } = mk();
  process.env.VARVEL_H1WATCH_DIR = h1dir;
  const source = h1.fixtureSource(FIXTURE('h1watch-scan-1.json'));
  const r = await hunt.runLoop({
    source, brain: hunt.mockBrain(), dir, once: true, trustedBrain: true, ghost: 'skip',
    gatherFetch: gatherWire('techy'), validate: true, refuter: refuterBrain(opts.refuter || (() => ({ ok: true, verdict: 'hold', why: 'the bundle supports the claim' }))),
    ...opts.loop,
  });
  return { r, dir, events: readEvents(dir) };
};

test('validator pass: a REFUTED candidate parks — never tested, never drafted, ledgered with the refutation', async () => {
  // The refutation CITES the bundle (the anti-vibe gate demands a checkable quote —
  // here the bundle itself, guaranteeing the citation holds and the refute lands).
  const { r, dir, events } = await validatorCycle({ refuter: ({ evidence }) => ({ ok: true, verdict: 'refute', why: 'the bundle contradicts the claim: nothing in what was gathered supports a marker write', contradiction: String(JSON.stringify(evidence)).slice(0, 200) }) });
  // the mock brain finding must NOT have reached the sandbox
  assert.equal(r.counters.tested, MECH_N, 'only the mechanical candidates were tested — the brain candidate was parked pre-sandbox');
  assert.equal(r.counters.refuted, 1, 'the refutation is counted');
  assert.ok(events.some((e) => e.type === 'validator' && e.state === 'refuted'), 'the refutation rides the event stream');
  const ledger = readFileSync(join(dir, 'findings.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
  const ref = ledger.find((l) => l.verdict === 'refuted');
  assert.ok(ref, 'the refutation is ledgered (parked, never deleted)');
  assert.match(ref.refutation, /contradicts the claim/);
  assert.ok(ref.contradiction, 'the ledger line carries the cited span');
  assert.ok(!ledger.some((l) => /Mock: unauthenticated/.test(l.finding) && l.verified), 'the refuted finding is never a verified line');
  const outbox = existsSync(join(dir, 'outbox')) ? readdirSync(join(dir, 'outbox')) : [];
  assert.equal(outbox.length, MECH_N, 'no draft for the refuted finding — only the mechanical ones');
});

test('validator pass: a HOLD proceeds normally through the sandbox and can verify', async () => {
  const { r, events } = await validatorCycle({});
  assert.equal(r.counters.verified, MECH_N + 1, 'the held brain finding verified exactly as the ungated dry-run');
  assert.ok(events.some((e) => e.type === 'validator' && e.state === 'held'), 'the hold is visible on the event stream');
});

test('validator pass: an UNAVAILABLE validator never deletes or downgrades — the finding runs UN-REFUTED, loudly', async () => {
  const { r, events } = await validatorCycle({ refuter: () => ({ ok: false, reason: 'validator lane down (mock)' }) });
  assert.equal(r.counters.verified, MECH_N + 1, 'the finding ran and verified — unavailability is not a deletion');
  const un = events.filter((e) => e.type === 'validator' && e.state === 'unavailable');
  assert.ok(un.length, 'the unavailability is on the event stream (never silent)');
  assert.match(un[0].msg, /UN-REFUTED/);
});

test('validator pass: an UNCONFIGURED refuter announces the pass is OFF (no config, no pretending)', async () => {
  const { dir, h1dir } = mk();
  process.env.VARVEL_H1WATCH_DIR = h1dir;
  const source = h1.fixtureSource(FIXTURE('h1watch-scan-1.json'));
  const r = await hunt.runLoop({ source, brain: hunt.mockBrain(), dir, once: true, trustedBrain: true, ghost: 'skip', gatherFetch: gatherWire('techy'), validate: true, refuter: null, refuterRequest: null });
  const ev = readEvents(dir).find((e) => e.type === 'validator' && e.state === 'off');
  assert.ok(ev, 'the off state is announced on the event stream');
  assert.match(ev.msg, /UN-REFUTED/);
  assert.equal(r.counters.verified, MECH_N + 1, 'the loop completes normally with the pass off');
});

test('validator unit: a vibe refutation (citation not in the bundle) is DISCARDED, not obeyed', async () => {
  const { refuteFinding, citationHolds } = await import('../tools/refuter.mjs');
  const bundle = { assets: [{ host: 'globex.example', techs: [{ id: 'nginx', version: '1.18.0' }] }], notes: 'server header is nginx/1.18.0; no auth on /admin' };
  assert.equal(citationHolds('server header is nginx/1.18.0', JSON.stringify(bundle)), true, 'a real quote holds');
  assert.equal(citationHolds('the admin panel stores plaintext passwords in logs', JSON.stringify(bundle)), false, 'an invented span does not');
  assert.equal(citationHolds('', JSON.stringify(bundle)), false, 'an empty citation never holds');
  const ref = await refuteFinding({
    finding: { title: 'T', sev: 'high', evidence: 'e', check: 'c', expect: 'x' },
    evidence: bundle,
    brain: refuterBrain(() => ({ ok: true, verdict: 'refute', why: 'the finding misreads the deployment', contradiction: 'plaintext password rotation is configured on the SaaS side' })),
  });
  assert.equal(ref.ok, false, 'the vibe refutation is discarded');
  assert.match(ref.reason, /DISCARDED/);
});

test('validator unit: strict parsing — no block, bad token, or broken json is UNAVAILABLE, never guessed', async () => {
  const { parseValidatorVerdict } = await import('../tools/refuter.mjs');
  assert.equal(parseValidatorVerdict('I think this finding is probably fine, honestly.').ok, false, 'prose without a block is not a verdict');
  assert.equal(parseValidatorVerdict('```json\n{"verdict":"maybe","why":"x"}\n```').ok, false, 'a non hold/refute token is refused');
  assert.equal(parseValidatorVerdict('```json\n{"verdict":"refute", why: broken}\n```').ok, false, 'broken json is refused');
  const good = parseValidatorVerdict('```json\n{"verdict":"hold","why":"bundle supports it","contradiction":null}\n```');
  assert.equal(good.ok && good.verdict, 'hold');
});

test('the refuter NEVER submits — static pin: no network/submission code path in refuter.mjs', async () => {
  const src = readFileSync(join(__dir, '..', 'tools', 'refuter.mjs'), 'utf8');
  for (const re of [/\bhttps?\.\s*request\s*\(/, /XMLHttpRequest/, /\bnet\.connect/, /\.submit\s*\(/]) {
    assert.ok(!re.test(src), `the refuter must carry NO submission code path — matched ${re}`);
  }
  // Its ONLY remote conversation rides engine/brain-provider.mjs (the same lane rule as
  // the loop); fetch itself is ALLOWED there exactly as in brain-provider (the local/API
  // brain call) — but no submission module may be imported and no platform URL may exist.
  const imports = [...src.matchAll(/from\s+'([^']+)'/g)].map((m) => m[1]);
  assert.ok(imports.includes('../engine/brain-provider.mjs'), 'the validator call is REUSED, never reimplemented');
  assert.ok(!imports.some((i) => /submit/.test(i)), 'no submission module is imported');
  assert.ok(!/(patchstack|hackenproof|h1\.com|yeswehack|intigriti|bugcrowd)/i.test(src), 'no bounty-platform URL in the refuter');
});
