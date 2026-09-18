// VARVEL autopilot tests — the durable wide-first scheduler (tools/autopilot.mjs).
// Hermetic: fixture corpora/bountyline dirs in tmp, injected fakes for the sweep/scan/
// miners and a fake loopback console (fetchImpl) — ZERO external network, ZERO real
// launches. The doctrines under test: the loopback-only client (refuses non-loopback
// BEFORE any request), the sweep diff, WP-lane coverage (existing .tmp/hunt-* reports
// count), adjudication candidate selection + the capped ONE brief, the launch decision
// gates (ghost-off/unverified = REFUSE; campaign-busy = SKIP; prohibited named; visa
// HARD-EXCLUDED; no record/scope = named refusal; rotation), and the never-submits
// static pin over the module file.
//   node --test test/autopilot.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const __dir = dirname(fileURLToPath(import.meta.url));
const CLI = join(__dir, '..', 'tools', 'autopilot.mjs');

// Isolation roots BEFORE the module is exercised (config getters evaluate at call time).
const ROOT = mkdtempSync(join(tmpdir(), 'varvel-autopilot-'));
const AUTO_DIR = join(ROOT, 'autopilot');
const FAKE_TMP = join(ROOT, 'fake-tmp');
const CORPUS_A = join(ROOT, 'corpus-a');
const CORPUS_B = join(ROOT, 'corpus-b');
const BOUNTY = join(ROOT, 'bountyline');
process.env.VARVEL_AUTOPILOT_DIR = AUTO_DIR;
process.env.VARVEL_BOUNTYLINE_DIR = BOUNTY;
process.env.VARVEL_AUTOPILOT_CORPUS = [CORPUS_A, CORPUS_B].join(',');

// Fixture corpus: two NEW plugins in A, one NEW in B; 'covered-plugin' has a hunt report.
for (const [dir, slugs] of [[CORPUS_A, ['new-plugin-a', 'new-plugin-b']], [CORPUS_B, ['new-plugin-c', 'covered-plugin']]]) {
  for (const s of slugs) mkdirSync(join(dir, s), { recursive: true });
}
mkdirSync(join(FAKE_TMP, 'hunt-2026-01-01', 'privemap'), { recursive: true });
writeFileSync(join(FAKE_TMP, 'hunt-2026-01-01', 'privemap', 'covered-plugin.json'), '{"candidates":[]}');

// Fixture bountyline: acme (human-cadence + signed scope), fullco (full + scope),
// visa (valid record — the HARD-EXCLUDE must win anyway), evilco (prohibited),
// noscopeco (human-cadence, NO scope on record).
const SCOPE_FX = { session_id: 'sess-t1', principal: 'marcus', workspace: 'acme', engagementScope: '10.0.0.1/32,10.0.0.2/32', sig: 'hmac-sha256:deadbeef' };
const SCOPE_PATH = join(BOUNTY, 'acme-scope-signed.json');
mkdirSync(join(BOUNTY, 'programs'), { recursive: true });
writeFileSync(SCOPE_PATH, JSON.stringify(SCOPE_FX, null, 2));
const RECS = {
  acme: { id: 'acme', engagement: 'acme-eng', automation: { policy: 'human-cadence', basis: 'operator-override', evidence: 'operator set --automation human-cadence' }, signedScopePath: SCOPE_PATH, state: 'scoped' },
  fullco: { id: 'fullco', engagement: 'fullco-eng', automation: { policy: 'full', basis: 'policy-text', evidence: 'automated scanning is allowed' }, signedScopePath: SCOPE_PATH, state: 'scoped', extraHeaders: { 'X-HackerOne': 'varvel' } },
  visa: { id: 'visa', engagement: 'visa', automation: { policy: 'human-cadence', basis: 'operator-override', evidence: 'operator ack' }, signedScopePath: SCOPE_PATH, state: 'hunted' },
  evilco: { id: 'evilco', engagement: 'evilco', automation: { policy: 'prohibited', basis: 'policy-text', evidence: 'no automated scanning' }, signedScopePath: SCOPE_PATH, state: 'imported' },
  noscopeco: { id: 'noscopeco', engagement: 'noscopeco', automation: { policy: 'human-cadence', basis: 'default-silent', evidence: 'silent' }, signedScopePath: null, state: 'imported' },
};
for (const r of Object.values(RECS)) writeFileSync(join(BOUNTY, 'programs', `${r.id}.json`), JSON.stringify(r, null, 2));
writeFileSync(join(BOUNTY, 'roster.json'), JSON.stringify({ programs: Object.values(RECS).map((r) => ({ id: r.id, handle: r.id, platform: 'hackerone', state: r.state, automation: r.automation.policy, reports: 0, updatedAt: '2026-09-01T00:00:00.000Z' })) }, null, 2));

const ap = await import('../tools/autopilot.mjs');

const T1 = '2026-09-01T00:00:00.000Z';
const GHOST_OK = { mode: 'required', verified: { ok: true, exitIp: '135.136.21.33' } };
const sweptRows = (ids) => ids.map((id) => ({ program: id, automation: 'human-cadence', status: 'SWEPT', topScore: 10 }));
const loadWith = (recs) => (id) => recs[id] || null;
const scopeOk = () => SCOPE_FX;

// --- the loopback-only client (rule 1) -----------------------------------------------------------

test('consoleReq: non-loopback hosts are refused BEFORE any request is built', async () => {
  let called = 0;
  const r = await ap.consoleReq('GET', '/api/state', undefined, { api: 'http://169.254.1.1:8971', fetchImpl: () => { called++; throw new Error('must not be called'); } });
  assert.equal(r.ok, false);
  assert.equal(r.error, 'console-host-not-allowed');
  assert.equal(called, 0, 'no request was sent');
  assert.match(r.reason, /loopback console ONLY/);
  const bad = await ap.consoleReq('GET', '/api/state', undefined, { api: 'http://127.0.0.1:8971', fetchImpl: () => { throw new Error('down'); } });
  assert.equal(bad.error, 'console-unreachable');
});

// --- sweep diff (pure) ----------------------------------------------------------------------------

test('diffSweeps: added / removed / rescored, keyed program|host', () => {
  const prev = [
    { program: 'acme', host: 'a.acme.com', score: 10 },
    { program: 'acme', host: 'b.acme.com', score: 20 },
  ];
  const cur = [
    { program: 'acme', host: 'b.acme.com', score: 35 }, // rescored
    { program: 'acme', host: 'c.acme.com', score: 5, kinds: ['fresh-subdomain'] }, // new
  ];
  const d = ap.diffSweeps(prev, cur);
  assert.deepEqual(d.added.map((x) => x.host), ['c.acme.com']);
  assert.deepEqual(d.removed.map((x) => x.host), ['a.acme.com']);
  assert.deepEqual(d.scoreChanged, [{ program: 'acme', host: 'b.acme.com', from: 20, to: 35 }]);
  assert.deepEqual(ap.diffSweeps([], []), { added: [], removed: [], scoreChanged: [] });
});

// --- corpus + coverage ----------------------------------------------------------------------------

test('corpusPlugins + coveredSlugs: directories only, .tmp/hunt-* reports count as coverage', () => {
  const plugins = ap.corpusPlugins([CORPUS_A, CORPUS_B, join(ROOT, 'no-such-root')]);
  assert.deepEqual(plugins.map((p) => p.slug), ['covered-plugin', 'new-plugin-a', 'new-plugin-b', 'new-plugin-c']);
  const covered = ap.coveredSlugs({ tmpRoot: FAKE_TMP, ownHuntDir: join(ROOT, 'no-autopilot-yet') });
  assert.ok(covered.has('covered-plugin'), 'the historical .tmp/hunt-* report covers it');
  assert.ok(!covered.has('new-plugin-a'));
  // the autopilot's own hunt dir counts too
  const ownDir = join(ROOT, 'own', 'privemap');
  mkdirSync(ownDir, { recursive: true });
  writeFileSync(join(ownDir, 'new-plugin-c.json'), '{}');
  const covered2 = ap.coveredSlugs({ tmpRoot: FAKE_TMP, ownHuntDir: ownDir });
  assert.ok(covered2.has('new-plugin-c'));
});

// --- adjudication candidates + brief --------------------------------------------------------------

test('selectAdjudicationCandidates: CONFIRMED/UNCERTAIN at unauth|subscriber only, doctrineGated dropped, newScore ranked', () => {
  const perSlug = [
    { slug: 'p1', privemap: { candidates: [{ ref: 'a.php:1', impactClass: 'meta-write' }, { ref: 'b.php:2', impactClass: 'cron-sink', doctrineGated: true }] },
      rescore: { results: [
        { ref: 'a.php:1', title: 'meta write', verdict: 'CONFIRMED', privemapReach: 'unauth', provenReach: 'UNAUTH', privemapScore: 90, newScore: 88, reason: 'proven' },
        { ref: 'b.php:2', title: 'cron sink', verdict: 'CONFIRMED', privemapReach: 'unauth', provenReach: 'UNAUTH', privemapScore: 95, newScore: 95, reason: 'doctrineGated — must be dropped' },
        { ref: 'c.php:3', title: 'admin only', verdict: 'DEGRADED', privemapReach: 'unauth', provenReach: 'ADMIN', privemapScore: 80, newScore: 20, reason: 'gated' },
        { ref: 'd.php:4', title: 'admin claimed', verdict: 'CONFIRMED', privemapReach: 'admin', provenReach: 'ADMIN', privemapScore: 70, newScore: 70, reason: 'not unauth/subscriber' },
      ] } },
    { slug: 'p2', privemap: { candidates: [{ ref: 'e.php:5', impactClass: 'option-write' }] },
      rescore: { results: [{ ref: 'e.php:5', title: 'opt write', verdict: 'UNCERTAIN', privemapReach: 'subscriber', provenReach: 'UNKNOWN', privemapScore: 60, newScore: 60, reason: 'unresolvable callback' }] } },
  ];
  const rows = ap.selectAdjudicationCandidates(perSlug, 10);
  assert.deepEqual(rows.map((r) => `${r.slug}:${r.ref}`), ['p1:a.php:1', 'p2:e.php:5']);
  assert.equal(rows[0].impactClass, 'meta-write', 'enriched from the privemap candidate');
  assert.equal(ap.selectAdjudicationCandidates(perSlug, 1).length, 1, 'the cap holds');
});

test('buildAdjudicationBrief: under the server cap, review-only doctrine, overflow honestly counted', () => {
  const cands = Array.from({ length: 40 }, (_, i) => ({ slug: `slug-${i}`, ref: `f.php:${i}`, title: 't'.repeat(120), impactClass: 'meta-write', verdict: 'CONFIRMED', privemapReach: 'unauth', provenReach: 'UNAUTH', score: 100, newScore: 100, reason: 'r'.repeat(200) }));
  const b = ap.buildAdjudicationBrief(cands, { at: T1, corpusDirs: [CORPUS_A] });
  assert.ok(b.text.length <= 4000, `the server slices at 4000 — got ${b.text.length}`);
  assert.ok(b.included > 0 && b.included < 40);
  assert.equal(b.dropped, 40 - b.included);
  assert.match(b.text, /REVIEW-ONLY: never file, never submit/);
  assert.match(b.text, /queued candidate\(s\) — next cycle/);
  const one = ap.buildAdjudicationBrief(cands.slice(0, 1), { at: T1, corpusDirs: [CORPUS_A] });
  assert.match(one.text, /slug-0 — meta-write @ f\.php:0 \[privemap unauth score 100 → reachprove CONFIRMED \(proven UNAUTH\) newScore 100\]/);
});

// --- the launch decision (pure gates) --------------------------------------------------------------

test('planLaunch: ghost gates refuse loudly — off, unverified, and status unknown', () => {
  const base = { sweepPrograms: sweptRows(['acme']), campaignStatus: 'idle', loadProgramImpl: loadWith(RECS), readScopeImpl: scopeOk };
  const off = ap.planLaunch({ ...base, ghost: { mode: 'off', verified: null } });
  assert.equal(off.decision, 'refuse');
  assert.equal(off.refusals[0].kind, 'ghost-off');
  assert.match(off.refusals[0].reason, /expose the operator's real source/);
  const unv = ap.planLaunch({ ...base, ghost: { mode: 'required', verified: { ok: false, error: 'exit equals baseline' } } });
  assert.equal(unv.decision, 'refuse');
  assert.equal(unv.refusals[0].kind, 'ghost-unverified');
  const unk = ap.planLaunch({ ...base, ghost: null });
  assert.equal(unk.decision, 'refuse');
  assert.equal(unk.refusals[0].kind, 'ghost-status-unknown');
  assert.equal(off.candidate, null, 'no candidate survives a ghost refusal');
});

test('planLaunch: a busy campaign is SKIPPED, never clobbered; the status is named', () => {
  for (const status of ['running', 'running:exploit', 'stalled:recon', 'running:interactive', 'error: boom']) {
    const d = ap.planLaunch({ sweepPrograms: sweptRows(['acme']), ghost: GHOST_OK, campaignStatus: status, loadProgramImpl: loadWith(RECS), readScopeImpl: scopeOk });
    assert.equal(d.decision, 'skip', status);
    assert.match(d.reason, new RegExp(status.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
    assert.equal(d.candidate, null);
  }
});

test('planLaunch: happy path — human-cadence knobs FORCED, scope from the signed fixture, gates parked', () => {
  const d = ap.planLaunch({ sweepPrograms: sweptRows(['acme']), ghost: GHOST_OK, campaignStatus: 'idle', loadProgramImpl: loadWith(RECS), readScopeImpl: scopeOk });
  assert.equal(d.decision, 'launch');
  assert.equal(d.candidate.id, 'acme');
  const b = d.candidate.body;
  assert.equal(b.mode, 'live');
  assert.deepEqual(b.scope, { engagement: 'acme-eng', signedBy: 'marcus', cidrs: ['10.0.0.1/32', '10.0.0.2/32'] });
  assert.equal(b.stealth, 'paranoid', 'CADENCE_MAP human-cadence');
  assert.equal(b.budget.maxSteps, 50);
  assert.deepEqual(b.reconOpts, { crawl: { maxPages: 5 }, vuln: { maxProbes: 3 } });
  assert.equal(b.approveTimeoutMs, 0, 'HITL gates park for the operator (the bykea lesson)');
  assert.equal(b.carryForward, true);
  assert.ok(!('extraHeaders' in b), 'acme carries none');
  assert.ok(d.notes.some((n) => /human-cadence ceiling FORCED/.test(n)));
});

test('planLaunch: visa is HARD-EXCLUDED even with a valid record; prohibited is named with its basis', () => {
  const d = ap.planLaunch({ sweepPrograms: sweptRows(['visa', 'evilco', 'acme']), ghost: GHOST_OK, campaignStatus: 'idle', loadProgramImpl: loadWith(RECS), readScopeImpl: scopeOk });
  assert.equal(d.decision, 'launch');
  assert.equal(d.candidate.id, 'acme', 'visa/evilco never launch');
  const visa = d.refusals.find((r) => r.program === 'visa');
  assert.equal(visa.kind, 'program-hard-excluded');
  assert.match(visa.reason, /Jack's visa rule/);
  const evil = d.refusals.find((r) => r.program === 'evilco');
  assert.equal(evil.kind, 'automation-prohibited');
  assert.match(evil.reason, /policy-text/);
  // visa alone on the roster => no launch at all
  const only = ap.planLaunch({ sweepPrograms: sweptRows(['visa']), ghost: GHOST_OK, campaignStatus: 'idle', loadProgramImpl: loadWith(RECS), readScopeImpl: scopeOk });
  assert.equal(only.decision, 'skip');
  assert.equal(only.candidate, null);
});

test('planLaunch: no record / no scope / empty scope are named refusals; full policy adds no ceiling; extraHeaders ride', () => {
  const d = ap.planLaunch({ sweepPrograms: sweptRows(['ghostco', 'noscopeco', 'fullco']), ghost: GHOST_OK, campaignStatus: 'idle', loadProgramImpl: loadWith(RECS), readScopeImpl: scopeOk });
  assert.equal(d.decision, 'launch');
  assert.equal(d.candidate.id, 'fullco');
  assert.ok(d.refusals.some((r) => r.kind === 'no-program-record' && r.program === 'ghostco'));
  assert.ok(d.refusals.some((r) => r.kind === 'no-signed-scope' && r.program === 'noscopeco'));
  const b = d.candidate.body;
  assert.ok(!('stealth' in b) && !('budget' in b) && !('reconOpts' in b), 'full: the engagement settings floor governs — no ceiling added');
  assert.deepEqual(b.extraHeaders, { 'X-HackerOne': 'varvel' }, 'program attestation headers ride the launch');
  const emptyScope = ap.planLaunch({ sweepPrograms: sweptRows(['acme']), ghost: GHOST_OK, campaignStatus: 'idle', loadProgramImpl: loadWith(RECS), readScopeImpl: () => ({ ...SCOPE_FX, engagementScope: ' ' }) });
  assert.equal(emptyScope.decision, 'skip');
  assert.ok(emptyScope.refusals.some((r) => r.kind === 'no-signed-scope' && /EMPTY engagementScope/.test(r.reason)));
});

test('planLaunch: rotation — the last-launched top candidate yields to the next eligible; a sole candidate relaunches', () => {
  const rows = [{ program: 'acme', automation: 'human-cadence', status: 'SWEPT', topScore: 50 }, { program: 'fullco', automation: 'full', status: 'SWEPT', topScore: 10 }];
  const d = ap.planLaunch({ sweepPrograms: rows, ghost: GHOST_OK, campaignStatus: 'idle', lastLaunched: 'acme', loadProgramImpl: loadWith(RECS), readScopeImpl: scopeOk });
  assert.equal(d.candidate.id, 'fullco', 'breadth over the roster');
  assert.ok(d.notes.some((n) => /rotation: acme launched most recently/.test(n)));
  const sole = ap.planLaunch({ sweepPrograms: rows.slice(0, 1), ghost: GHOST_OK, campaignStatus: 'done', lastLaunched: 'acme', loadProgramImpl: loadWith(RECS), readScopeImpl: scopeOk });
  assert.equal(sole.decision, 'launch', 'done campaigns are replaced; a sole candidate continues the hunt');
  assert.equal(sole.candidate.id, 'acme');
  const off = ap.planLaunch({ sweepPrograms: rows, ghost: GHOST_OK, campaignStatus: 'idle', launchEnabled: false, loadProgramImpl: loadWith(RECS), readScopeImpl: scopeOk });
  assert.equal(off.decision, 'skip');
  assert.match(off.reason, /VARVEL_AUTOPILOT_LAUNCH=off/);
});

// --- ONE FULL CYCLE, hermetic ---------------------------------------------------------------------

// A fake loopback console: ghost armed+verified, campaign idle, chat free; captures POSTs.
function fakeConsole(over = {}) {
  const posts = { message: [], campaign: [] };
  const fetchImpl = async (url, opts = {}) => {
    const u = new URL(url);
    const payload = over[u.pathname + ' ' + (opts.method || 'GET')] || over[u.pathname];
    const body = typeof payload === 'function' ? payload(opts) : payload;
    return { ok: true, status: 200, json: async () => body };
  };
  return { posts, fetchImpl };
}

const SWEEP_REPORT = {
  at: T1,
  programs: [
    { program: 'acme', automation: 'human-cadence', status: 'SWEPT' },
    { program: 'visa', automation: 'human-cadence', status: 'SWEPT' },
    { program: 'evilco', automation: 'prohibited', status: 'SKIPPED-POLICY' },
  ],
  catches: [{ program: 'acme', host: 'admin.acme.com', score: 42, kinds: ['fresh-subdomain'], software: [], reasons: [], evidence: {} }],
  skippedPolicy: [{ program: 'evilco', reason: 'roster automation: prohibited' }],
  stats: { programs: 3, swept: 2, skippedPolicy: 1, hosts: 9, catches: 1, requests: { intel: 20, target: 3 } },
};
const pmFake = (dir) => ({ root: dir, candidates: [{ rank: 1, title: 'unauth any-user meta write', ref: 'x.php:1', reachability: 'unauth', impactClass: 'meta-write', score: 100 }], scannedFiles: 3, skipped: [], gaps: [] });
const rsFake = (dir) => ({ root: dir, results: [{ rank: 1, title: 'unauth any-user meta write', ref: 'x.php:1', privemapReach: 'unauth', privemapScore: 100, provenReach: 'UNAUTH', verdict: 'CONFIRMED', reason: 'nopriv ajax, no gate', newScore: 100 }], summary: { CONFIRMED: 1, DEGRADED: 0, KILLED: 0, UNCERTAIN: 0 }, scannedFiles: 3, skipped: [], gaps: [] });

function cycleOpts(dir, consoleOver = {}, more = {}) {
  const { posts, fetchImpl } = fakeConsole({
    '/api/ghost': GHOST_OK,
    '/api/state': { status: 'idle', agentThinking: false },
    '/api/message POST': (opts) => { posts.message.push(JSON.parse(opts.body)); return { ok: true, thinking: true }; },
    '/api/campaign POST': (opts) => { const b = JSON.parse(opts.body); posts.campaign.push(b); return { ok: true, engagement: b.scope.engagement, status: 'running' }; },
    ...consoleOver,
  });
  const opts = {
    now: T1, dir, tmpRoot: FAKE_TMP, corpusDirs: [CORPUS_A, CORPUS_B], api: 'http://127.0.0.1:8971',
    fetchImpl, sleepImpl: async () => {}, pollMs: 1, messageWaitMs: 5000,
    sweepImpl: async () => JSON.parse(JSON.stringify(SWEEP_REPORT)),
    commitScanImpl: async () => ({ ok: true, scanned: 2, watched: 2, changesets: 1, noise: 0, leads: [{ slug: 'acme-forms', revision: 100, band: 'high', score: 75, classes: ['nonce-check-added'] }], errors: [], gaps: [] }),
    privemapImpl: pmFake, reachproveRescoreImpl: rsFake,
    verifyScopeImpl: async () => ({ ok: true, verification: 'seam-verified' }),
    ...more,
  };
  return { opts, posts };
}

test('runCycle: sweep+diff, commitwatch lead, WP-lane coverage, ONE brief, gated launch — all recorded', async () => {
  const dir = join(ROOT, 'cycle-1');
  const { opts, posts } = cycleOpts(dir);
  const cycle = await ap.runCycle(opts);
  assert.equal(cycle.errors.length, 0, JSON.stringify(cycle.errors));
  // (a) sweep: copy written, delta recorded (first cycle = every catch new)
  assert.ok(existsSync(join(dir, 'sweeps', 'widerecon-20260901-000000.json')));
  assert.ok(cycle.steps.some((s) => /widerecon: 2\/3 programs swept · 9 hosts · 1 catches · Δ \+1 new/.test(s)), cycle.steps.join('\n'));
  assert.ok(cycle.steps.some((s) => /NEW catch: acme admin\.acme\.com/.test(s)));
  assert.ok(cycle.steps.some((s) => /SKIPPED-POLICY.*evilco/.test(s)));
  // (b) commitwatch: the new lead is reported review-only
  assert.ok(cycle.steps.some((s) => /commitwatch: 2\/2 plugins scanned .* 1 NEW lead\(s\)/.test(s)));
  assert.ok(cycle.steps.some((s) => /LEAD \[high 75\] r100 acme-forms — nonce-check-added/.test(s)));
  // (c) WP lane: the 3 uncovered plugins swept, covered-plugin NOT re-swept; reports written
  assert.ok(existsSync(join(dir, 'hunt', 'privemap', 'new-plugin-a.json')));
  assert.ok(existsSync(join(dir, 'hunt', 'reachprove', 'new-plugin-c.json')));
  assert.ok(!existsSync(join(dir, 'hunt', 'privemap', 'covered-plugin.json')), 'existing hunt reports are honored');
  assert.ok(cycle.steps.some((s) => /WP lane: 3 new plugin\(s\) swept \(new-plugin-a, new-plugin-b, new-plugin-c/.test(s)), cycle.steps.join('\n'));
  // the ONE adjudication brief: posted once, names candidates, review-only, under the cap
  assert.equal(posts.message.length, 1);
  assert.ok(posts.message[0].text.length <= 4000);
  assert.match(posts.message[0].text, /new-plugin-a — meta-write @ x\.php:1/);
  assert.match(posts.message[0].text, /REVIEW-ONLY: never file, never submit/);
  assert.ok(cycle.steps.some((s) => /adjudication: brief posted \(3 candidate\(s\)\) — the agent COMPLETED/.test(s)), cycle.steps.join('\n'));
  // (d) the launch: acme (visa hard-excluded, evilco prohibited — both refused and named)
  assert.equal(posts.campaign.length, 1, 'one launch per cycle, never a clobber');
  const body = posts.campaign[0];
  assert.equal(body.scope.engagement, 'acme-eng');
  assert.deepEqual(body.scope.cidrs, ['10.0.0.1/32', '10.0.0.2/32']);
  assert.equal(body.stealth, 'paranoid');
  assert.equal(body.budget.maxSteps, 50);
  assert.equal(body.approveTimeoutMs, 0);
  assert.deepEqual(body.targets, ['admin.acme.com'], 'the sweep catch seeds the target list');
  assert.ok(cycle.refusals.some((r) => r.kind === 'program-hard-excluded' && r.program === 'visa'));
  assert.ok(cycle.steps.some((s) => /campaign: LAUNCHED acme \(human-cadence, ghost required verified exit 135\.136\.21\.33\) — engagement 'acme-eng'/.test(s)), cycle.steps.join('\n'));
  // state + digest
  const st = ap.loadState(dir);
  assert.equal(st.cycles, 1);
  assert.equal(st.launches.length, 1);
  assert.equal(st.launches[0].program, 'acme');
  assert.equal(st.launches[0].scopeVerification, 'seam-verified');
  assert.ok(st.refusals.some((r) => r.program === 'visa'));
  assert.deepEqual(Object.keys(st.wp.covered).sort(), ['new-plugin-a', 'new-plugin-b', 'new-plugin-c']);
  assert.equal(st.wp.pending.length, 0, 'the completed adjudication drains the queue');
  assert.equal(st.adjudications[0].status, 'completed');
  const digest = readFileSync(join(dir, 'digest-2026-09-01.md'), 'utf8');
  assert.match(digest, /# VARVEL autopilot digest — 2026-09-01/);
  assert.match(digest, /LAUNCHED acme/);
  assert.match(digest, /REFUSALS \(1\)/);
  assert.ok(existsSync(join(dir, 'autopilot.jsonl')), 'the run log exists');

  // SECOND cycle: coverage holds (nothing re-swept), delta is zero, rotation picks… acme again
  // (sole eligible candidate — visa/evilco stay refused), and the launch relaunches honestly.
  const posts2 = { message: [], campaign: [] };
  const c2 = await ap.runCycle({
    ...opts,
    now: '2026-09-01T04:00:00.000Z',
    fetchImpl: async (url, o = {}) => {
      const u = new URL(url);
      if (u.pathname === '/api/message' && o.method === 'POST') { posts2.message.push(JSON.parse(o.body)); return { ok: true, status: 200, json: async () => ({ ok: true, thinking: true }) }; }
      if (u.pathname === '/api/campaign' && o.method === 'POST') { posts2.campaign.push(JSON.parse(o.body)); return { ok: true, status: 200, json: async () => ({ ok: true, engagement: 'acme-eng', status: 'running' }) }; }
      if (u.pathname === '/api/ghost') return { ok: true, status: 200, json: async () => GHOST_OK };
      return { ok: true, status: 200, json: async () => ({ status: 'done', agentThinking: false }) };
    },
    commitScanImpl: async () => ({ ok: true, scanned: 2, watched: 2, changesets: 0, noise: 0, leads: [], errors: [], gaps: [] }),
  });
  assert.ok(c2.steps.some((s) => /Δ \+0 new \/ −0 gone \/ ~0 rescored/.test(s)), c2.steps.join('\n'));
  assert.ok(c2.steps.some((s) => /WP lane: 0 new plugin\(s\) swept/.test(s)), 'coverage state persisted');
  assert.equal(posts2.message.length, 0, 'no candidates, no brief');
  assert.equal(posts2.campaign.length, 1, 'status done → launchable; sole eligible candidate relaunches');
});

test('runCycle: ghost OFF refuses the launch loudly; chat-busy defers the brief and keeps the queue', async () => {
  const dir = join(ROOT, 'cycle-ghost-off');
  const { opts, posts } = cycleOpts(dir, {
    '/api/ghost': { mode: 'off', verified: null },
    '/api/message POST': () => ({ ok: true, busy: true }),
  });
  const cycle = await ap.runCycle(opts);
  assert.equal(posts.campaign.length, 0, 'ghost-off = no launches, ever');
  assert.ok(cycle.refusals.some((r) => r.kind === 'ghost-off'));
  assert.ok(cycle.steps.some((s) => /campaign: REFUSED — Ghost Mode is OFF/.test(s)), cycle.steps.join('\n'));
  assert.ok(cycle.steps.some((s) => /adjudication: DEFERRED — the chat agent is mid-turn/.test(s)));
  const st = ap.loadState(dir);
  assert.equal(st.launches.length, 0);
  assert.equal(st.wp.pending.length, 3, 'deferred candidates ride to the next cycle');
  const digest = readFileSync(join(dir, 'digest-2026-09-01.md'), 'utf8');
  assert.match(digest, /REFUSED — Ghost Mode is OFF/);
});

test('runCycle: a failed scope verification refuses the launch even after the gates pass', async () => {
  const dir = join(ROOT, 'cycle-bad-scope');
  const { opts, posts } = cycleOpts(dir, {}, { verifyScopeImpl: async () => ({ ok: false, error: 'scope-signature-invalid', reason: 'the signed scope FAILS the seam verifySession — forged/tampered' }) });
  const cycle = await ap.runCycle(opts);
  assert.equal(posts.campaign.length, 0);
  assert.ok(cycle.refusals.some((r) => r.kind === 'scope-signature-invalid' && r.program === 'acme'));
  assert.equal(ap.loadState(dir).launches.length, 0);
});

test('runCycle: a failing sweep is a named error, never fabricated; the cycle continues', async () => {
  const dir = join(ROOT, 'cycle-sweep-fail');
  const { opts } = cycleOpts(dir, {}, { sweepImpl: async () => { throw new Error('ghost chain down'); } });
  const cycle = await ap.runCycle(opts);
  assert.ok(cycle.errors.some((e) => /widerecon: ghost chain down/.test(e)));
  assert.ok(!existsSync(join(dir, 'sweeps')), 'no sweep copy was invented');
});

// --- the never-submits static pin ------------------------------------------------------------------

test('STATIC PIN: no submission path, the loopback allowlist in code, visa hard-excluded', () => {
  const src = readFileSync(CLI, 'utf8');
  assert.ok(!/from\s*'[^']*submit-drive/.test(src), 'no submit-drive import — the autopilot never files');
  assert.ok(!/\b(queueProgram|markOutcome|submitReport|signSession|signScope|scopecheck)\b/.test(src), 'no signing/submission/pipeline verbs');
  assert.ok(src.includes('console-host-not-allowed'), 'the loopback allowlist refusal exists in code');
  assert.equal((src.match(/\bfetch\s*\(/g) || []).length, 0, 'no raw fetch( call sites anywhere');
  assert.equal((src.match(/fetchImpl \|\| fetch/g) || []).length, 1, 'exactly one transport call site — injectable, inside consoleReq, behind the allowlist');
  assert.ok(!/https?:\/\/(?!127\.0\.0\.1|localhost)[a-z0-9.-]+/i.test(src.replace(/https?:\/\/127\.0\.0\.1:8971/g, '')), 'no non-loopback host literals');
  assert.ok(ap.LAUNCH_EXCLUDED_PROGRAMS.includes('visa'), "Jack's rule: visa is hard-excluded");
  for (const p of ['udemy', 'wordpress', 'matomo']) assert.ok(ap.LAUNCH_EXCLUDED_PROGRAMS.includes(p), `widerecon pin ${p} rides along`);
  assert.deepEqual(ap.LAUNCHABLE_STATUSES, ['idle', 'interactive', 'done']);
});

// --- CLI smoke -------------------------------------------------------------------------------------

test('CLI: run --once --dry prints the plan ONLY (nothing written, no requests); bad usage exits 64', () => {
  const dryDir = join(ROOT, 'cli-dry');
  // A sweep IS on record (from an earlier wet run) — dry plans from state, never from requests.
  mkdirSync(dryDir, { recursive: true });
  writeFileSync(join(dryDir, 'state.json'), JSON.stringify({
    version: 1,
    prevSweep: {
      at: '2026-08-31T20:00:00.000Z',
      programs: [
        { program: 'acme', automation: 'human-cadence', status: 'SWEPT', topScore: 42 },
        { program: 'visa', automation: 'human-cadence', status: 'SWEPT', topScore: 30 },
        { program: 'evilco', automation: 'prohibited', status: 'SKIPPED-POLICY', topScore: 0 },
      ],
      catches: [{ program: 'acme', host: 'admin.acme.com', score: 42, kinds: [] }],
    },
  }, null, 2));
  const env = { ...process.env, VARVEL_AUTOPILOT_DIR: dryDir, VARVEL_AUTOPILOT_CORPUS: [CORPUS_A, CORPUS_B].join(','), VARVEL_BOUNTYLINE_DIR: BOUNTY };
  const r = spawnSync(process.execPath, [CLI, 'run', '--once', '--dry'], { encoding: 'utf8', timeout: 30000, env });
  assert.equal(r.status, 0, r.stderr.slice(0, 400));
  const i = r.stdout.lastIndexOf('\n{\n');
  const plan = JSON.parse(i === -1 ? r.stdout : r.stdout.slice(i + 1));
  assert.equal(plan.dry, true);
  assert.ok(plan.plan.some((s) => /widerecon: DRY — would re-sweep the roster \(last sweep 2026-08-31/.test(s)), plan.plan.join('\n'));
  assert.ok(plan.plan.some((s) => /WP lane: DRY/.test(s) && /new-plugin-a/.test(s) && /new-plugin-b/.test(s)), plan.plan.join('\n'));
  assert.ok(plan.plan.some((s) => /campaign: DRY — ghost\/campaign status UNKNOWN \(not queried\)/.test(s)), 'dry names its UNKNOWNs');
  assert.ok(plan.plan.some((s) => /Standing refusals: \[program-hard-excluded\] visa/.test(s)), 'the visa exclusion is visible even in the plan');
  assert.ok(plan.plan.some((s) => /top candidate IF the gates pass: acme/.test(s)), plan.plan.join('\n'));
  assert.ok(!existsSync(join(dryDir, 'autopilot.jsonl')), 'dry logs nothing');
  const st = JSON.parse(readFileSync(join(dryDir, 'state.json'), 'utf8'));
  assert.equal(st.cycles || 0, 0, 'dry never advances the cycle counter');

  const bad = spawnSync(process.execPath, [CLI, 'bogus'], { encoding: 'utf8', timeout: 15000, env });
  assert.equal(bad.status, 64);
  assert.match(bad.stderr, /usage: node tools\/autopilot\.mjs run/);
  const badInterval = spawnSync(process.execPath, [CLI, 'run', '--once', '--interval', '0'], { encoding: 'utf8', timeout: 15000, env });
  assert.equal(badInterval.status, 64);
  assert.match(badInterval.stderr, /--interval must be hours > 0/);
});
