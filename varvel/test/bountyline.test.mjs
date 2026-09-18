// VARVEL bountyline tests — the autonomous bounty pipeline (engine/bountyline.mjs).
// Hermetic: local fixtures + tmp persistence only, zero network (the pipeline itself
// carries no network code — the never-submits pin below STATICALLY SCANS the engine).
// The state machine, the automation gate as code, the scope guard, and the
// never-convert ledger are the doctrines under test.
//   node --test test/bountyline.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { spawnSync } from 'node:child_process';

const __dir = dirname(fileURLToPath(import.meta.url));
const SEAM = join(__dir, '..', '..', 'poc', 'enforcement-seam');
const CLI = join(__dir, '..', 'tools', 'cli.mjs');
const FIX = (n) => JSON.parse(readFileSync(join(__dir, 'fixtures', n), 'utf8'));

// Isolate persistence (bountyline root + settings file) BEFORE the engine is exercised.
const ROOT = mkdtempSync(join(tmpdir(), 'varvel-bountyline-'));
process.env.VARVEL_BOUNTYLINE_DIR = ROOT;
process.env.VARVEL_SETTINGS_FILE = join(ROOT, 'settings.json');

const bl = await import('../engine/bountyline.mjs');
const seam = await import(pathToFileURL(join(SEAM, 'util.mjs')).href);

const FRESH = '2026-08-24T00:00:00.000Z'; // 4 days after the fixture's validatedAt (inside the 30-day TTL)
const ANCIENT = '2026-12-01T00:00:00.000Z'; // past the TTL — validated renders stale
const SURFACE = join(__dir, 'fixtures', 'findings-surface.json'); // 1 validated-fresh, 1 claimed, 1 refuted

let n = 0;
const tmpFile = (name, obj) => { const p = join(ROOT, `${String(++n).padStart(2, '0')}-${name}`); writeFileSync(p, typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2)); return p; };
const intakeVariant = (policy, handle) => {
  const v = FIX('bountyline-intake.json');
  v.policy = policy; v.safeHarbor = null;
  v.program.handle = handle; v.program.name = handle;
  return tmpFile(`intake-${handle}.json`, v);
};
const signFixture = (scope, workspace) => {
  const s = { session_id: 'sess-bountyline-test', principal: 'marcus', workspace: workspace || 'bug-bounty', engagementScope: scope };
  return tmpFile(`scope-${workspace || 'x'}.json`, { ...s, sig: seam.signSession(s) });
};
const run = (args, env) => {
  const r = spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', timeout: 30000, env: env || { ...process.env } });
  const i = r.stdout.lastIndexOf('\n{\n');
  let out = null;
  try { out = JSON.parse(i === -1 ? r.stdout : r.stdout.slice(i + 1)); } catch { out = { parseError: r.stdout.slice(0, 400), stderr: r.stderr.slice(0, 300) }; }
  return { status: r.status, out, text: i === -1 ? '' : r.stdout.slice(0, i) };
};

test('add: the policy text derives the automation policy — silence maps to human-cadence (operator rule 2026-08-29); the operator override is recorded as such', async () => {
  const a = await bl.addProgram({ intakePath: join(__dir, 'fixtures', 'bountyline-intake.json'), now: FRESH });
  assert.equal(a.ok, true);
  assert.equal(a.program.id, 'acme-line');
  assert.equal(a.program.state, 'imported');
  assert.equal(a.program.automation.policy, 'prohibited');
  assert.equal(a.program.automation.basis, 'policy-text');
  assert.match(a.program.automation.evidence, /automated tools are prohibited/i);

  const full = await bl.addProgram({ intakePath: intakeVariant('Safe harbor. We allow automated scanning against in-scope assets.', 'auto-full'), now: FRESH });
  assert.equal(full.program.automation.policy, 'full');
  const paced = await bl.addProgram({ intakePath: intakeVariant('Automated testing is permitted; rate limit: no more than 2 requests per second.', 'auto-paced'), now: FRESH });
  assert.equal(paced.program.automation.policy, 'human-cadence');
  assert.match(paced.program.automation.evidence, /rate limit/i);
  const silent = await bl.addProgram({ intakePath: intakeVariant('Safe harbor for good-faith research; report promptly.', 'auto-silent'), now: FRESH });
  assert.equal(silent.program.automation.policy, 'human-cadence', 'operator rule 2026-08-29: a silent policy no longer excludes — gated, scoped, human-paced AI is human-equivalent, so silence takes the conservative ceiling');
  assert.equal(silent.program.automation.basis, 'default-silent');
  assert.match(silent.program.automation.evidence, /operator rule 2026-08-29/);

  const override = await bl.addProgram({ intakePath: intakeVariant('Automated scanning is prohibited.', 'auto-override'), automation: 'full', now: FRESH });
  assert.equal(override.program.automation.policy, 'full');
  assert.equal(override.program.automation.basis, 'operator-override');
  assert.match(override.program.automation.evidence, /policy text said: prohibited/);

  const again = await bl.addProgram({ intakePath: join(__dir, 'fixtures', 'bountyline-intake.json'), now: FRESH });
  assert.equal(again.error, 'already-on-roster');
  assert.equal((await bl.addProgram({ intakePath: join(ROOT, 'no-such-file.json') })).error, 'bad-intake');
  assert.equal((await bl.addProgram({ intakePath: intakeVariant('x', 'auto-bad2'), automation: 'loud' })).error, 'unknown-automation');
});

test('scope guard: fixtures verify with the seam; forged or shapeless scopes refuse', async () => {
  const scope = signFixture('203.0.113.0/24', 'scoped-ok');
  const a = await bl.addProgram({ intakePath: intakeVariant('Safe harbor.', 'scoped-ok'), scopePath: scope, now: FRESH });
  assert.equal(a.ok, true);
  assert.equal(a.program.state, 'scoped');
  assert.equal(a.program.scopeVerification, 'seam-verified');

  const forged = JSON.parse(readFileSync(scope, 'utf8'));
  forged.engagementScope = '198.51.100.0/24'; // tampered after signing
  const forgedPath = tmpFile('scope-forged.json', forged);
  const bad = await bl.addProgram({ intakePath: intakeVariant('Safe harbor.', 'scoped-forged'), scopePath: forgedPath, now: FRESH });
  assert.equal(bad.error, 'scope-signature-invalid');
  assert.match(bad.reason, /forged\/tampered/);
  assert.equal(bl.loadProgram('scoped-forged'), null, 'a forged scope never even creates the roster entry');

  const shapeless = tmpFile('scope-shapeless.json', { session_id: 'x', sig: 'hmac-sha256:nope' });
  assert.equal((await bl.recordScope('scoped-ok', shapeless, { now: FRESH })).error, 'scope-shape-invalid');
  assert.equal((await bl.recordScope('scoped-ok', join(ROOT, 'absent.json'), { now: FRESH })).error, 'unreadable-scope');
});

test('the automation gate: prohibited refuses naming the policy; scopeless refuses; human-cadence forces the conservative map', async () => {
  const prohibited = await bl.runProgram('acme-line', { now: FRESH });
  assert.equal(prohibited.ok, false);
  assert.equal(prohibited.error, 'automation-prohibited');
  assert.match(prohibited.reason, /'prohibited'/);
  assert.match(prohibited.reason, /automated tools are prohibited/i, 'the refusal names the program\'s own policy words');

  const scopeless = await bl.runProgram('auto-full', { now: FRESH });
  assert.equal(scopeless.error, 'no-signed-scope');
  assert.match(scopeless.reason, /never runs unscoped/);

  const pacedScope = signFixture('203.0.113.0/24', 'auto-paced');
  const plan = await bl.runProgram('auto-paced', { scopePath: pacedScope, now: FRESH });
  assert.equal(plan.ok, true);
  assert.equal(plan.gated, true);
  assert.equal(plan.state, 'scoped', 'a plan without artifacts changes nothing');
  assert.deepEqual(plan.runPlan.campaign, { stealth: 'paranoid', budget: { maxSteps: 50 }, reconOpts: { crawl: { maxPages: 5 }, vuln: { maxProbes: 3 } } }, 'human-cadence forces the documented conservative ceiling');
  assert.match(plan.runPlan.note, /FORCED/);

  const fullScope = signFixture('203.0.113.0/24', 'auto-full');
  const hunt = await bl.runProgram('auto-full', { scopePath: fullScope, campaignArtifact: SURFACE, now: FRESH });
  assert.equal(hunt.ok, true);
  assert.equal(hunt.hunted, true);
  assert.equal(hunt.state, 'hunted');
  assert.equal(hunt.hunt.campaignArtifact, SURFACE);
  assert.deepEqual(hunt.runPlan.campaign, {}, 'full adds no ceiling over the engagement settings floor');
});

test('operator ack: a policy-prohibited program runs ONLY with an explicit ack, and the ack FORCES human-cadence (audited, never loosened)', async () => {
  await bl.addProgram({ intakePath: intakeVariant('Automated scanning is prohibited.', 'ack-run'), scopePath: signFixture('203.0.113.0/24', 'ack-run'), now: FRESH });
  const noAck = await bl.runProgram('ack-run', { now: FRESH });
  assert.equal(noAck.error, 'automation-prohibited', 'the code never silently overrides the program\'s literal words');

  const acked = await bl.runProgram('ack-run', { operatorAck: 'jack 2026-08-29: words reviewed, hunting human-paced and in scope', now: FRESH });
  assert.equal(acked.ok, true);
  assert.equal(acked.runPlan.policy, 'prohibited', 'the plan keeps the program\'s own policy honest');
  assert.equal(acked.runPlan.effectivePolicy, 'human-cadence');
  assert.equal(acked.runPlan.operatorAck, 'jack 2026-08-29: words reviewed, hunting human-paced and in scope', 'the ack is recorded in the run plan');
  assert.deepEqual(acked.runPlan.campaign, { stealth: 'paranoid', budget: { maxSteps: 50 }, reconOpts: { crawl: { maxPages: 5 }, vuln: { maxProbes: 3 } } }, 'an ack NEVER loosens — it pins the conservative ceiling');
  assert.match(acked.runPlan.note, /FORCED/);
});

test('illegal transitions refuse loudly, naming from -> to and the allowed set', async () => {
  const t = bl.triageProgram('auto-silent', { now: FRESH }); // imported
  assert.equal(t.error, 'illegal-transition');
  assert.match(t.reason, /'imported' — cannot move to 'triaged'/);
  assert.equal(bl.draftReports('auto-paced', { now: FRESH }).error, 'illegal-transition'); // scoped
  assert.equal(bl.queueProgram('auto-paced', { now: FRESH }).error, 'illegal-transition'); // scoped
  const rehunt = await bl.runProgram('auto-full', { campaignArtifact: SURFACE, now: FRESH }); // already hunted
  assert.equal(rehunt.error, 'illegal-transition');
  assert.match(rehunt.reason, /'hunted' — cannot move to 'hunted'/);
  const rescope = await bl.recordScope('auto-full', signFixture('203.0.113.0/24', 'auto-full-2'), { now: FRESH });
  assert.equal(rescope.error, 'illegal-transition', 're-scoping mid-pipeline is refused — a fresh round opens only from queued');
  assert.equal((await bl.runProgram('no-such-program', { now: FRESH })).error, 'unknown-program');
});

test('triage splits by validator readiness — counts only on the record', async () => {
  const r = bl.triageProgram('auto-full', { now: FRESH, staleDays: 30 });
  assert.equal(r.ok, true);
  assert.equal(r.ready, 1, 'the validated-fresh SQLi is the one ready finding');
  assert.equal(r.notReady, 2, 'claimed + refuted are not ready');
  const rec = bl.loadProgram('auto-full');
  assert.equal(rec.state, 'triaged');
  assert.deepEqual(Object.keys(rec.triage).sort(), ['at', 'notReady', 'ready', 'source', 'staleDays', 'total'], 'the record is counts only — the split is recomputed at draft');
});

test('draft writes ONE redacted bountyreport per ready finding; zero-ready refuses and stays triaged', async () => {
  const r = bl.draftReports('auto-full', { now: FRESH, staleDays: 30, researcher: 'VARVEL' });
  assert.equal(r.ok, true);
  assert.equal(r.reports.length, 1);
  const md = readFileSync(r.reports[0].path, 'utf8');
  assert.match(md, /Submission readiness: \*\*READY\*\*/);
  assert.ok(md.includes('[REDACTED]'), 'the persisted report obeys the cookie-never-reaches-report doctrine');
  assert.ok(!md.includes('hunter2') && !md.includes('4f8a2c-live-cookie-value'), 'no secret value on disk');
  assert.ok(r.reports[0].redactions >= 3);
  assert.equal(bl.loadProgram('auto-full').state, 'reported');

  // A second, all-stale hunt: triage finds zero ready -> draft refuses, state restored.
  await bl.addProgram({ intakePath: intakeVariant('We allow automated scanning.', 'stale-prog'), scopePath: signFixture('203.0.113.0/24', 'stale-prog'), now: FRESH });
  await bl.runProgram('stale-prog', { campaignArtifact: SURFACE, now: FRESH });
  const t = bl.triageProgram('stale-prog', { now: ANCIENT, staleDays: 30 });
  assert.equal(t.ready, 0);
  assert.equal(t.notReady, 3, 'stale validation is NOT ready');
  const d = bl.draftReports('stale-prog', { now: ANCIENT, staleDays: 30 });
  assert.equal(d.error, 'no-ready-findings');
  assert.equal(bl.loadProgram('stale-prog').state, 'triaged', 'a refused draft rolls the state back honestly');
});

test('queue is the end of the line — the never-submits pin (static scan of the engine)', () => {
  const src = readFileSync(join(__dir, '..', 'engine', 'bountyline.mjs'), 'utf8');
  for (const re of [/\bfetch\s*\(/, /node:https?\b/, /\bhttps?\.\s*request\s*\(/, /XMLHttpRequest/, /\bnet\.connect/, /\.submit\s*\(/]) {
    assert.ok(!re.test(src), `the pipeline engine must carry NO network/submission code path — matched ${re}`);
  }
  const r = bl.queueProgram('auto-full', { now: FRESH });
  assert.equal(r.ok, true);
  assert.equal(r.state, 'queued');
  assert.equal(r.queue.items.length, 1);
  assert.equal(r.queue.items[0].checklist.length, 6, 'the novelty gate adds ONE loud resolution line to the five-line checklist');
  assert.ok(r.queue.items[0].checklist.some((c) => /never submits/.test(c)), 'the checklist itself states the doctrine');
  assert.match(r.queue.items[0].checklist[0], /Novelty check/, 'the FIRST checklist line is the novelty-gate resolution step');
  assert.deepEqual(r.queue.items[0].novelty, { verdict: 'CLEAR' }, 'the queue item carries the gate verdict');
  assert.equal(bl.loadProgram('auto-full').state, 'queued');
});

test('mark books outcomes into the ledger; paid needs amount+currency; bad marks refuse', async () => {
  const notQueued = bl.markOutcome('auto-paced', 'submitted', { now: FRESH });
  assert.equal(notQueued.error, 'nothing-queued');

  const sub = bl.markOutcome('auto-full', 'submitted', { now: FRESH });
  assert.equal(sub.ok, true);
  assert.equal(sub.event.outcome, 'submitted');
  assert.ok(sub.event.report.endsWith('.md'), 'the single queued report is the default');
  const paidNoAmt = bl.markOutcome('auto-full', 'paid', { now: FRESH });
  assert.equal(paidNoAmt.error, 'paid-needs-amount');
  assert.equal(bl.markOutcome('auto-full', 'paid', { amount: 500, currency: 'pounds' }).error, 'paid-needs-currency');
  assert.equal(bl.markOutcome('auto-full', 'duplicate', { amount: 5, currency: 'GBP' }).error, 'amount-only-on-paid');
  assert.equal(bl.markOutcome('auto-full', 'won').error, 'unknown-outcome');
  assert.equal(bl.markOutcome('auto-full', 'submitted', { report: 'no-such-report.md' }).error, 'unknown-report');

  const gbp = bl.markOutcome('auto-full', 'paid', { amount: 500, currency: 'gbp', now: FRESH });
  assert.equal(gbp.ok, true);
  assert.equal(gbp.event.currency, 'GBP', 'currency normalizes to the ISO code');
  const usd = bl.markOutcome('auto-full', 'paid', { amount: 200, currency: 'USD', now: FRESH });
  assert.equal(usd.ok, true);

  const t = bl.ledgerTotals();
  assert.equal(t.totals.GBP, 500);
  assert.equal(t.totals.USD, 200, 'non-GBP is totaled separately — NEVER converted');
  assert.equal(t.byOutcome.submitted, 1);
  assert.equal(t.byOutcome.paid, 2);
  assert.equal(t.goal.paid, 500);
  assert.equal(t.goal.pct, 15, '500 / 3332.50 = 15% — GBP only');
  const lines = bl.ledgerLines();
  assert.ok(lines.some((l) => /goal £3332\.50 — GBP paid £500\.00 \(15%\)/.test(l)));
  assert.ok(lines.some((l) => /paid USD: 200\.00 \(NOT converted/.test(l)));
});

test('a fresh round: queued -> scoped archives the round; a late payout still books against it', async () => {
  const archivedReport = bl.loadProgram('auto-full').queue.items[0].report;
  const r = await bl.recordScope('auto-full', signFixture('203.0.113.0/24,198.51.100.7/32', 'auto-full-r2'), { now: ANCIENT });
  assert.equal(r.ok, true);
  const rec = bl.loadProgram('auto-full');
  assert.equal(rec.state, 'scoped');
  assert.equal(rec.rounds.length, 1);
  assert.equal(rec.rounds[0].queue.items[0].report, archivedReport, 'the archive keeps the queued round honest');
  assert.equal(rec.reports.length, 0, 'the new round starts clean');
  const late = bl.markOutcome('auto-full', 'paid', { amount: 1200, currency: 'GBP', report: archivedReport, now: ANCIENT });
  assert.equal(late.ok, true, 'a late payout books against the archived round');
  assert.equal(late.totals.goal.paid, 1700);
});

test('cli bountyline end-to-end: add -> run -> triage -> draft -> queue -> mark -> ledger', async () => {
  const env = { ...process.env, VARVEL_BOUNTYLINE_DIR: mkdtempSync(join(tmpdir(), 'varvel-bountyline-cli-')), VARVEL_SETTINGS_FILE: join(ROOT, 'cli-settings.json') };
  const intake = tmpFile('cli-intake.json', FIX('bountyline-intake.json'));
  const scope = signFixture('203.0.113.0/24', 'cli-e2e');

  const refused = run(['bountyline', 'add', intake], env); // prohibited by policy text
  assert.equal(refused.status, 0);
  const noGo = run(['bountyline', 'run', 'acme-line'], env);
  assert.equal(noGo.status, 2, 'a refused gate exits nonzero');
  assert.equal(noGo.out.error, 'automation-prohibited');

  const added = run(['bountyline', 'add', intakeVariant('Safe harbor.', 'cli-e2e'), '--automation', 'full', '--scope', scope], env);
  assert.equal(added.status, 0, JSON.stringify(added.out));
  assert.equal(added.out.program.state, 'scoped');
  assert.equal(added.out.program.scopeVerification, 'seam-verified');
  const hunted = run(['bountyline', 'run', 'cli-e2e', '--campaign', SURFACE], env);
  assert.equal(hunted.out.hunted, true);
  const triaged = run(['bountyline', 'triage', 'cli-e2e', '--stale-days', '30'], env);
  assert.equal(triaged.out.ready, 1);
  const drafted = run(['bountyline', 'draft', 'cli-e2e', '--researcher', 'VARVEL'], env);
  assert.equal(drafted.out.reports.length, 1);
  assert.ok(existsSync(drafted.out.reports[0].path));
  const queued = run(['bountyline', 'queue', 'cli-e2e'], env);
  assert.equal(queued.out.state, 'queued');
  assert.match(queued.text, /QUEUED-FOR-SEND/);
  const marked = run(['bountyline', 'mark', 'cli-e2e', 'paid', '--amount', '3332.50', '--currency', 'GBP'], env);
  assert.equal(marked.out.ok, true);
  const ledger = run(['bountyline', 'ledger'], env);
  assert.match(ledger.text, /goal £3332\.50 — GBP paid £3332\.50 \(100%\)/);
  assert.equal(ledger.out.goal.pct, 100);
  const list = run(['bountyline', 'list'], env);
  assert.equal(list.out.programs.length, 2);
  const show = run(['bountyline', 'show', 'cli-e2e'], env);
  assert.equal(show.out.program.state, 'queued');
  assert.equal(show.out.ledger.length, 1);
});

// ——— winner-copyables Tool 2 wiring: replayable-evidence binding in draft/queue ———
test('replay binding: a finding with captured pairs gets a replay bundle + checklist line', async () => {
  const intake = intakeVariant('Safe harbor. We allow automated scanning.', 'replay-prog');
  const scope = signFixture('203.0.113.0/24', 'replay-prog');
  assert.equal((await bl.addProgram({ intakePath: intake, scopePath: scope, now: FRESH })).ok, true);

  // a campaign surface whose validated finding carries the authzsweep evidence bundle
  const doc = FIX('findings-surface.json');
  doc.nodes.push({
    id: 'svc-6', type: 'service', label: 'https:443', host: 'host-2',
  }, {
    id: 'finding-7', type: 'finding',
    label: 'IDOR: cross-tenant object read — /api/addr/{id}',
    sev: 'high', risk: 'high', ref: 'authzsweep:/api/addr/{id}#idor',
    conf: 95, confidence: 'confirmed',
    evidence: 'differential oracle: cross-account read of the victim address book returned 200; the garbage-id control read 404ed; the unauthenticated control read was refused 401',
    validation: { state: 'validated', oracle: 'differential replay', at: '2026-08-20T10:00:00.000Z', validatedAt: '2026-08-20T10:00:00.000Z' },
    authz: {
      verdict: 'idor', template: '/api/addr/{id}',
      bundle: {
        observation: ['cross-tenant GET returned 200'], inference: ['ownership check missing'], impact: ['cross-tenant exposure'],
        pairs: [
          { label: 'read:cross(A→B)', request: { method: 'GET', path: '/api/addr/202', headers: { cookie: '<session:A>' }, body: null }, response: { status: 200, body: '{"addresses":[{"id":202,"address":"VICTIM DATA"}]}' } },
          { label: 'read:unauth-control(B)', request: { method: 'GET', path: '/api/addr/202', headers: { cookie: '<none>' }, body: null }, response: { status: 401, body: '{"message":"Unauthorized request! Please refresh the page."}' } },
        ],
      },
    },
  });
  doc.edges.push({ from: 'host-2', to: 'finding-7', kind: 'finding' });
  const artifact = tmpFile('replay-surface.json', doc);

  assert.equal((await bl.runProgram('replay-prog', { campaignArtifact: artifact, now: FRESH })).ok, true);
  assert.equal(bl.triageProgram('replay-prog', { now: FRESH, staleDays: 30 }).ready, 2, 'the fixture\'s SQLi + the IDOR both validate-ready');
  const d = bl.draftReports('replay-prog', { now: FRESH, staleDays: 30 });
  assert.equal(d.ok, true);
  const withReplay = d.reports.filter((r) => r.replay);
  assert.equal(withReplay.length, 1, 'only the pair-carrying finding earns a bundle — the SQLi has none and none is fabricated');
  const rep = withReplay[0];
  assert.ok(existsSync(join(rep.replay.dir, 'replay.json')), 'replay.json on disk');
  assert.ok(existsSync(join(rep.replay.dir, 'replay.sh')), 'replay.sh on disk');
  assert.equal(rep.replay.legs, 2);
  assert.equal(rep.replay.controls, 1, 'the unauth control is a first-class leg');
  const md = readFileSync(rep.path, 'utf8');
  assert.match(md, /## Replay bundle/);
  assert.match(md, /redacted-but-referenced/);
  const plan = JSON.parse(readFileSync(join(rep.replay.dir, 'replay.json'), 'utf8'));
  assert.ok(!JSON.stringify(plan).includes('VICTIM DATA') === false, 'captured bytes ARE bound into the plan');
  assert.equal(plan.requests[0].credential.ref, 'A', 'the session cookie is a reference, not a value');
  assert.equal(plan.base, 'https://203.0.113.10', 'base resolved from the service node (scheme+port, not guessed)');

  const q = bl.queueProgram('replay-prog', { now: FRESH });
  assert.equal(q.ok, true);
  const qItem = q.queue.items.find((i) => i.replay);
  assert.ok(qItem, 'the queue item carries the replay bundle');
  assert.ok(qItem.checklist.some((c) => /Replay the evidence bundle BEFORE the send click/.test(c)), 'the checklist gates the send click on a fresh replay');
});
