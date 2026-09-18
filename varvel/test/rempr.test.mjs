// rempr.test.mjs — the AUTO-REMEDIATION PR LOOP (roadmap #7): engine/remediate.mjs
// record lifecycle + tools/rempr.mjs governed legs + the cli remediate family.
// HERMETIC: every artifact lives under repo-local varvel/.tmp (HOUSE RULE — never
// os.tmpdir()); the GitHub API is a mock on loopback (RemPrApi's apiBase seam, the
// ghc2 test pattern); the git leg of open-pr rides an injected spawn spy — no live
// GitHub contact, no real push, anywhere. The LOCAL patch legs run against a REAL
// tiny git fixture repo built in-test under .tmp (patch-works is MEASURED there).
//
// Proves: the eligibility gate (claimed/refuted/untestable findings REFUSED, validated
//   accepted, stale flagged) · the lifecycle rail (forward-only, pr-opened only from
//   patched) · draft record shape + provenance · patch-apply+verify against the real
//   fixture (apply → probe → measured verdict → tree reverted clean) · the HITL wall
//   (every leg before open-pr spawns NOTHING network-shaped; the gates refuse BEFORE
//   any spawn) · the burner token NEVER in argv/audit/reports (negative scan, plus a
//   poisoned-stderr scrub case) · PR body completeness (finding evidence, validation
//   proof, MEASURED verify verdict, diffstat, rollback note) · idempotent open-pr and
//   push-resume · RemPrApi error mapping · the ghost-threading resolver · the cli
//   draft/list surface end-to-end.
//   node --test varvel/test/rempr.test.mjs

import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { mkdirSync, writeFileSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync, spawnSync } from 'node:child_process';
import {
  createRemediation, transitionRemediation, materializePatch, buildPrDraft, remediationCommitMessage,
  eligibleFinding, findFindingByRef, getRemediation, listRemediations, saveRemediation, REM_STATUS,
} from '../engine/remediate.mjs';
import {
  draftRemediation, verifyRemediation, openRemediationPr, resolveRemTransport, pushEnv, RemPrApi,
} from '../tools/rempr.mjs';
import { saveSurface } from '../engine/store.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const TMP = join(ROOT, '.tmp', 'rempr-test'); // HOUSE RULE: payload-class artifacts under repo-local .tmp only
const DATA = join(TMP, 'data');
const REPO = join(TMP, 'repo-fixture');
const ENG = 'rempr-test';
const PAT = 'github_pat_BURNER_REMED_FIXTURE_0123456789abcdef'; // a burner's shape — a FIXTURE, never a real token

process.env.VARVEL_DATA_DIR = DATA; // call-time read in store.mjs — hermetic record store
mkdirSync(TMP, { recursive: true });

// A validated finding's patch target: a command-injection sink. The fixture probe is a
// REPRODUCTION probe: exit 0 = the finding reproduces (sink present), nonzero = fixed.
const VULN_APP = 'module.exports = (req) => require(\'child_process\').exec(req.query.cmd); // the sink\n';
const FIXED_APP = 'module.exports = () => { throw new Error(\'removed: shell exec of client input\'); };\n';
const PROBE = 'const s = require(\'fs\').readFileSync(require(\'path\').join(__dirname, \'app.js\'), \'utf8\');\n'
  + 'process.exit(s.includes(\'exec(req.query.cmd)\') ? 0 : 1); // 0 = reproduces, 1 = no longer reproduces\n';

const NOW = new Date().toISOString();
const OLD = new Date(Date.now() - 61 * 86400e3).toISOString(); // beyond the 30d freshness window
const finding = (ref, validation) => ({
  type: 'finding', id: ref, ref, label: 'command injection in the run endpoint', sev: 'crit', confidence: 'confirmed',
  evidence: 'GET /run?cmd=id executed the command and returned uid=0 in the body',
  validation,
});
const SURFACE = {
  nodes: [
    finding('F-VALID', { state: 'validated', oracle: 'differential holds: signature specific to the real input', validatedAt: NOW }),
    finding('F-STALE', { state: 'validated', oracle: 'differential holds', validatedAt: OLD }),
    finding('F-CLAIMED', null),
    finding('F-REFUTED', { state: 'refuted', reason: 'the claim does not reproduce' }),
    finding('F-UNTESTABLE', { state: 'untestable' }),
    { type: 'host', id: 'h1', label: '10.0.0.5' },
  ],
  edges: [],
};
// Settings fake: the readRemSettings seam (Settings-shaped { get }).
const settingsWith = (over = {}) => {
  const v = { 'remediate.prEnabled': false, 'remediate.remoteAllow': false, 'remediate.ghToken': '', ...over };
  return { get: (k) => v[k] };
};
const ALL_ON = settingsWith({ 'remediate.prEnabled': true, 'remediate.remoteAllow': true, 'remediate.ghToken': PAT });

function freshRepo() {
  rmSync(REPO, { recursive: true, force: true });
  mkdirSync(REPO, { recursive: true });
  const git = (args) => execFileSync('git', ['-C', REPO, ...args], { encoding: 'utf8' });
  git(['init', '-q', '-b', 'main']);
  git(['config', 'core.autocrlf', 'false']); // deterministic bytes: no CRLF smudge on checkout
  // the fixture is its OWN package root (CommonJS default) — a probe inside the varvel
  // tree would otherwise inherit varvel's "type":"module" and die on require().
  writeFileSync(join(REPO, 'package.json'), JSON.stringify({ name: 'rempr-fixture', private: true }) + '\n');
  writeFileSync(join(REPO, 'app.js'), VULN_APP);
  writeFileSync(join(REPO, 'probe.js'), PROBE);
  git(['add', '-A']);
  git(['-c', 'user.name=Fixture', '-c', 'user.email=fixture@localhost', 'commit', '-qm', 'init']);
}
const gitOut = (args) => execFileSync('git', ['-C', REPO, ...args], { encoding: 'utf8' });

// The mock GitHub REST API (the ghc2 loopback pattern): POST /repos/:o/:r/pulls only,
// Bearer-authed, the request body captured for the PR-completeness assertions.
function mockPulls({ token = PAT, status = 201, pr = { html_url: 'https://github.com/acme/app/pull/7', number: 7 } } = {}) {
  const hits = { pulls: 0, authed: 0 };
  const bodies = [];
  const state = { status };
  const server = http.createServer((req, res) => {
    const send = (code, obj) => { res.writeHead(code, { 'content-type': 'application/json' }); res.end(JSON.stringify(obj)); };
    const m = /^\/repos\/([^/]+)\/([^/]+)\/pulls$/.exec(new URL(req.url, 'http://x').pathname);
    if (!m || req.method !== 'POST') return send(404, { message: 'Not Found' });
    hits.pulls++;
    if (req.headers.authorization !== 'Bearer ' + token) return send(401, { message: 'Bad credentials' });
    hits.authed++;
    let raw = '';
    req.on('data', (d) => { raw += d; });
    req.on('end', () => {
      try { bodies.push(JSON.parse(raw)); } catch { /* malformed test traffic */ }
      send(state.status, state.status === 201 ? pr : { message: 'mock status ' + state.status });
    });
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve({ server, hits, bodies, state, apiBase: 'http://127.0.0.1:' + server.address().port }));
  });
}

// A git-shaped spawn spy: answers like a successful git (diff/diff --stat carry canned
// output so the materialize capture step has something to measure), records EVERY
// invocation (cmd, args, env) for the HITL/token assertions. Failure injection via
// failOn ({ stage: {code, stderr} }). The probe command ('node probe.js') answers 0.
function gitSpy(failOn = {}) {
  const calls = [];
  const spy = async (cmd, args, opts = {}) => {
    calls.push({ cmd, args: [...args], env: opts.env || null, hasInput: opts.input != null });
    const rest = args.slice(2); // strip ['-C', repoDir]
    const stage = rest[0] === '-c' ? 'commit' : rest[0];
    if (failOn[stage]) return { code: failOn[stage].code, stdout: '', stderr: failOn[stage].stderr || '' };
    if (rest[0] === 'rev-parse') return { code: 0, stdout: 'true\n', stderr: '' };
    if (rest[0] === 'diff' && rest.includes('--stat')) return { code: 0, stdout: ' app.js | 2 +-\n 1 file changed, 1 insertion(+), 1 deletion(-)\n', stderr: '' };
    if (rest[0] === 'diff') return { code: 0, stdout: 'diff --git a/app.js b/app.js\n--- a/app.js\n+++ b/app.js\n@@ -1 +1 @@\n-old\n+new\n', stderr: '' };
    return { code: 0, stdout: '', stderr: '' };
  };
  spy.calls = calls;
  return spy;
}

before(() => {
  rmSync(DATA, { recursive: true, force: true }); // no record-store pollution between runs
  freshRepo();
});

/* ── 1. THE ELIGIBILITY GATE (validated-only; refuted is a first-class refusal) ── */

test('eligibility: only validator-state validated findings may enter the loop', () => {
  assert.equal(eligibleFinding(findFindingByRef(SURFACE, 'F-VALID')).ok, true);
  const claimed = eligibleFinding(findFindingByRef(SURFACE, 'F-CLAIMED'));
  assert.equal(claimed.ok, false);
  assert.match(claimed.reason, /claimed-unvalidated/);
  const refuted = eligibleFinding(findFindingByRef(SURFACE, 'F-REFUTED'));
  assert.equal(refuted.ok, false);
  assert.match(refuted.reason, /REFUTED.*does not reproduce/);
  const untestable = eligibleFinding(findFindingByRef(SURFACE, 'F-UNTESTABLE'));
  assert.equal(untestable.ok, false);
  assert.match(untestable.reason, /untestable.*only 'validated'/);
  assert.equal(eligibleFinding(null).ok, false);
});

test('eligibility: STALE validated is eligible but flagged (revalidation advised)', () => {
  const e = eligibleFinding(findFindingByRef(SURFACE, 'F-STALE'));
  assert.equal(e.ok, true);
  assert.equal(e.stale, true, 'validated beyond validator.staleDays renders stale — a rendering of validated, never a disqualifier');
});

test('intake: createRemediation enforces the gate BEFORE anything is stored', () => {
  for (const ref of ['F-CLAIMED', 'F-REFUTED', 'F-UNTESTABLE']) {
    const r = createRemediation({ engagement: ENG, surface: SURFACE, findingRef: ref });
    assert.equal(r.ok, false, ref + ' refused');
    assert.equal(r.gate, 'eligibility');
  }
  assert.equal(listRemediations({ engagement: ENG }).length, 0, 'refusals stored nothing');
  assert.equal(createRemediation({ engagement: ENG, surface: SURFACE, findingRef: 'F-NOPE' }).ok, false, 'unknown ref refused');
  assert.equal(createRemediation({ engagement: ENG, surface: SURFACE }).ok, false, 'missing ref refused');
});

test('draft record: shape, provenance, and the audit head', () => {
  const r = createRemediation({
    engagement: ENG, surface: SURFACE, findingRef: 'F-VALID',
    patch: { files: [{ path: 'app.js', content: FIXED_APP }] },
    verify: { cmd: 'node probe.js' },
  });
  assert.equal(r.ok, true);
  const rec = r.record;
  assert.match(rec.id, /^rem-[0-9a-f]{8}$/);
  assert.equal(rec.status, 'draft');
  assert.equal(rec.findingRef, 'F-VALID');
  assert.deepEqual(rec.files, []);
  assert.equal(rec.diff, null);
  assert.equal(rec.verify.expect, 'nonzero', 'the default: the reproduction probe should FAIL once the fix lands');
  assert.equal(rec.provenance.finding.ref, 'F-VALID');
  assert.equal(rec.provenance.finding.sev, 'crit');
  assert.match(rec.provenance.finding.evidence, /uid=0/);
  assert.equal(rec.provenance.finding.validation.state, 'validated');
  assert.equal(rec.provenance.stale, false);
  assert.equal(rec.audit[0].stage, 'draft');
  assert.match(rec.audit[0].detail, /VALIDATED finding F-VALID/);
  // patch/verify shape refusals are data
  assert.equal(createRemediation({ engagement: ENG, surface: SURFACE, findingRef: 'F-VALID', patch: {} }).ok, false);
  assert.equal(createRemediation({ engagement: ENG, surface: SURFACE, findingRef: 'F-VALID', verify: {} }).ok, false);
});

test('stale intake: provenance carries the staleness, the audit advises revalidation', () => {
  const r = createRemediation({ engagement: ENG, surface: SURFACE, findingRef: 'F-STALE' });
  assert.equal(r.ok, true);
  assert.equal(r.record.provenance.stale, true);
  assert.match(r.record.audit[0].detail, /STALE.*revalidation advised/);
  const draft = buildPrDraft(r.record);
  assert.match(draft.body, /STALE.*revalidation advised/);
});

/* ── 2. THE LIFECYCLE RAIL (forward-only; pr-opened ONLY from patched) ── */

test('lifecycle: the rail is enforced; terminals are terminal', () => {
  const rec = createRemediation({ engagement: ENG, surface: SURFACE, findingRef: 'F-VALID' }).record;
  assert.deepEqual(REM_STATUS, ['draft', 'patched', 'pr-opened', 'merged', 'rejected']);
  const jump = transitionRemediation({ engagement: ENG, id: rec.id, to: 'pr-opened' });
  assert.equal(jump.ok, false, 'draft -> pr-opened is NOT reachable — the PR leg needs a materialized patch');
  assert.match(jump.reason, /invalid lifecycle transition/);
  assert.equal(transitionRemediation({ engagement: ENG, id: rec.id, to: 'merged' }).ok, false);
  assert.equal(transitionRemediation({ engagement: ENG, id: rec.id, to: 'patched' }).ok, true);
  assert.equal(transitionRemediation({ engagement: ENG, id: rec.id, to: 'merged' }).ok, false, 'patched -> merged skips pr-opened: refused');
  assert.equal(transitionRemediation({ engagement: ENG, id: rec.id, to: 'pr-opened' }).ok, true);
  assert.equal(transitionRemediation({ engagement: ENG, id: rec.id, to: 'merged' }).ok, true);
  const term = transitionRemediation({ engagement: ENG, id: rec.id, to: 'rejected' });
  assert.equal(term.ok, false, 'merged is terminal');
  assert.match(term.reason, /terminal/);
  assert.equal(transitionRemediation({ engagement: ENG, id: rec.id, to: 'bogus' }).ok, false);
  assert.equal(transitionRemediation({ engagement: ENG, id: 'rem-00000000', to: 'rejected' }).ok, false);
});

/* ── 3. PATCH MATERIALIZATION + MEASURED VERIFY (real git fixture under .tmp) ── */

test('materialize: files-mode patch applies, the probe MEASURES patch-works, the tree is reverted', async () => {
  const rec = createRemediation({
    engagement: ENG, surface: SURFACE, findingRef: 'F-VALID',
    patch: { files: [{ path: 'app.js', content: FIXED_APP }, { path: 'FIX-NOTES.md', content: '# remediation notes\n' }] },
    verify: { cmd: 'node probe.js' },
  }).record;
  const m = await materializePatch(rec, { repoDir: REPO });
  assert.equal(m.ok, true);
  assert.equal(rec.status, 'patched', 'draft -> patched on materialize');
  assert.equal(m.verify.ran, true);
  assert.equal(m.verify.verdict, 'patch-works', 'the reproduction probe now FAILS against the patched tree — measured');
  assert.equal(m.verify.exit, 1);
  assert.equal(m.verify.expect, 'nonzero');
  assert.match(rec.diff, /-.*exec\(req\.query\.cmd\)/, 'the measured diff removes the sink');
  assert.match(rec.diff, /FIX-NOTES\.md/, 'the new file is captured (intent-to-add)');
  assert.match(rec.diffstat, /app\.js/);
  assert.equal(rec.files.find((f) => f.path === 'app.js').content, FIXED_APP, 'patched content captured');
  // the checkout is left EXACTLY as found
  assert.equal(gitOut(['status', '--porcelain']), '', 'working tree reverted clean');
  assert.equal(readFileSync(join(REPO, 'app.js'), 'utf8'), VULN_APP, 'the sink is back after the capture revert');
  assert.equal(existsSync(join(REPO, 'FIX-NOTES.md')), false);
  assert.ok(rec.audit.some((a) => a.stage === 'verify' && /patch-works/.test(a.detail)));
});

test('materialize: diff-mode patch applies via git apply and measures identically', async () => {
  // build a REAL unified diff against the fixture, then restore
  writeFileSync(join(REPO, 'app.js'), FIXED_APP);
  const diff = gitOut(['diff', '--', 'app.js']);
  gitOut(['checkout', '--', 'app.js']);
  assert.match(diff, /^diff --git a\/app\.js/m);
  const rec = createRemediation({
    engagement: ENG, surface: SURFACE, findingRef: 'F-VALID',
    patch: { diff }, verify: { cmd: 'node probe.js' },
  }).record;
  const m = await materializePatch(rec, { repoDir: REPO });
  assert.equal(m.ok, true);
  assert.equal(m.verify.verdict, 'patch-works');
  assert.deepEqual(m.files, ['app.js']);
  assert.equal(gitOut(['status', '--porcelain']), '');
});

test('materialize: honest verdicts — patch-fails is MEASURED, undeclared claims nothing', async () => {
  const keeps = createRemediation({
    engagement: ENG, surface: SURFACE, findingRef: 'F-VALID',
    patch: { files: [{ path: 'app.js', content: VULN_APP + '// cosmetic change, sink kept\n' }] },
    verify: { cmd: 'node probe.js' },
  }).record;
  const m1 = await materializePatch(keeps, { repoDir: REPO });
  assert.equal(m1.ok, true, 'the patch APPLIED — materialization itself succeeded');
  assert.equal(m1.verify.verdict, 'patch-fails', 'the probe still reproduces: patch-works is NOT claimed');
  assert.equal(gitOut(['status', '--porcelain']), '');

  const noProbe = createRemediation({
    engagement: ENG, surface: SURFACE, findingRef: 'F-VALID',
    patch: { files: [{ path: 'app.js', content: FIXED_APP }] },
  }).record;
  const m2 = await materializePatch(noProbe, { repoDir: REPO });
  assert.equal(m2.ok, true);
  assert.equal(m2.verify.verdict, 'undeclared');
  assert.equal(m2.verify.ran, false);
  assert.match(m2.verify.note, /NOT claimed/);
  assert.equal(gitOut(['status', '--porcelain']), '');
});

test('materialize: refusals — no patch, no repo, non-repo, path escape, empty diff, inapplicable diff', async () => {
  const noPatch = createRemediation({ engagement: ENG, surface: SURFACE, findingRef: 'F-VALID' }).record;
  assert.match((await materializePatch(noPatch, { repoDir: REPO })).reason, /carries no patch/);
  const rec = createRemediation({ engagement: ENG, surface: SURFACE, findingRef: 'F-VALID', patch: { files: [{ path: 'app.js', content: FIXED_APP }] } }).record;
  assert.match((await materializePatch(rec, {})).reason, /LOCAL checkout path.*never clones autonomously/s);
  assert.match((await materializePatch(rec, { repoDir: join(TMP, 'no-such-dir') })).reason, /not a git work tree/);
  const escape = createRemediation({ engagement: ENG, surface: SURFACE, findingRef: 'F-VALID', patch: { files: [{ path: '..\\evil.txt', content: 'x' }, { path: 'app.js', content: FIXED_APP }] } }).record;
  const er = await materializePatch(escape, { repoDir: REPO });
  assert.equal(er.ok, false);
  assert.match(er.reason, /escapes the checkout/);
  assert.equal(readFileSync(join(REPO, 'app.js'), 'utf8'), VULN_APP, 'ALL paths validated before ANY write');
  const noChange = createRemediation({ engagement: ENG, surface: SURFACE, findingRef: 'F-VALID', patch: { files: [{ path: 'app.js', content: VULN_APP }] } }).record;
  assert.match((await materializePatch(noChange, { repoDir: REPO })).reason, /NO change/);
  const badDiff = createRemediation({ engagement: ENG, surface: SURFACE, findingRef: 'F-VALID', patch: { diff: 'diff --git a/app.js b/app.js\n--- a/app.js\n+++ b/app.js\n@@ -1,1 +1,1 @@\n-totally unrelated content\n+whatever\n' } }).record;
  assert.match((await materializePatch(badDiff, { repoDir: REPO })).reason, /apply --check rejected/);
  assert.equal(gitOut(['status', '--porcelain']), '');
});

/* ── 4. THE GATES + THE HITL WALL (nothing spawns, nothing pushes, before open-pr) ── */

test('gates: prEnabled OFF refuses draft/verify/open-pr before ANY spawn', async () => {
  const spy = gitSpy();
  const d = await draftRemediation({ engagement: ENG, surface: SURFACE, findingRef: 'F-VALID', settings: settingsWith() });
  assert.equal(d.ok, false);
  assert.equal(d.gate, 'remediate.prEnabled');
  assert.match(d.reason, /DISABLED.*default/s);
  const v = await verifyRemediation({ engagement: ENG, id: 'rem-deadbeef', repoDir: REPO, settings: settingsWith(), spawn: spy });
  assert.equal(v.gate, 'remediate.prEnabled');
  const rec = createRemediation({ engagement: ENG, surface: SURFACE, findingRef: 'F-VALID' }).record; // a real id: open-pr looks the record up before the gates
  const o = await openRemediationPr({ engagement: ENG, id: rec.id, repoDir: REPO, owner: 'acme', repo: 'app', settings: settingsWith(), spawn: spy });
  assert.equal(o.gate, 'remediate.prEnabled');
  assert.equal(spy.calls.length, 0, 'gate refusals land BEFORE any spawn — the HITL wall has no pre-push');
});

test('gates: remoteAllow and the burner token are SECOND, separate refusals; lifecycle gates the push', async () => {
  const rec = createRemediation({ engagement: ENG, surface: SURFACE, findingRef: 'F-VALID', patch: { files: [{ path: 'app.js', content: FIXED_APP }] } }).record;
  const spy = gitSpy();
  const noRemote = await openRemediationPr({ engagement: ENG, id: rec.id, repoDir: REPO, owner: 'acme', repo: 'app', settings: settingsWith({ 'remediate.prEnabled': true }), spawn: spy });
  assert.equal(noRemote.gate, 'remediate.remoteAllow');
  assert.match(noRemote.reason, /SECOND, separate gate/);
  const noTok = await openRemediationPr({ engagement: ENG, id: rec.id, repoDir: REPO, owner: 'acme', repo: 'app', settings: settingsWith({ 'remediate.prEnabled': true, 'remediate.remoteAllow': true }), spawn: spy });
  assert.equal(noTok.gate, 'remediate.ghToken');
  assert.match(noTok.reason, /BURNER(.|\n)*NEVER the operator's real account/);
  const draftState = await openRemediationPr({ engagement: ENG, id: rec.id, repoDir: REPO, owner: 'acme', repo: 'app', settings: ALL_ON, spawn: spy });
  assert.equal(draftState.gate, 'lifecycle', "a 'draft' record cannot push — patched first");
  assert.match(draftState.reason, /only a PATCHED record/);
  assert.equal(spy.calls.length, 0, 'every refusal landed before a single git spawn');
});

test('HITL: the local legs spawn NOTHING network-shaped; open-pr is the sole push path in the CLI', async () => {
  // draft + verify with a spawn spy: every spawn is git or the declared probe — local only.
  const spy = gitSpy();
  const d = await draftRemediation({
    engagement: ENG, surface: SURFACE, findingRef: 'F-VALID',
    patch: { files: [{ path: 'app.js', content: FIXED_APP }] }, verify: { cmd: 'node probe.js' }, settings: ALL_ON,
  });
  assert.equal(d.ok, true);
  const v = await verifyRemediation({ engagement: ENG, id: d.record.id, repoDir: REPO, settings: ALL_ON, spawn: spy });
  assert.equal(v.ok, true);
  assert.ok(spy.calls.length > 0);
  for (const c of spy.calls) {
    assert.ok(c.cmd === 'git' || c.cmd === 'node probe.js', 'local legs spawn git/probe only, got: ' + c.cmd);
    assert.equal(c.env, null, 'no credential env on any local-leg spawn');
  }
  // structural honesty: the engine module has no network stack at all
  const engineSrc = readFileSync(join(ROOT, 'engine', 'remediate.mjs'), 'utf8');
  assert.ok(!/node:https?/.test(engineSrc), 'engine/remediate.mjs imports no http(s) — local legs CANNOT reach the network');
  assert.ok(!/api\.github\.com/.test(engineSrc));
  // and the operator surface calls the push leg from exactly ONE place
  const cliSrc = readFileSync(join(ROOT, 'tools', 'cli.mjs'), 'utf8');
  assert.equal(cliSrc.split('openRemediationPr(').length - 1, 1, 'openRemediationPr has exactly one call site: the explicit open-pr action');
});

/* ── 5. THE PR DRAFT (pure): completeness of the body the client reviews ── */

test('PR draft: finding evidence, validation proof, MEASURED verify, diffstat, rollback', async () => {
  const rec = createRemediation({
    engagement: ENG, surface: SURFACE, findingRef: 'F-VALID',
    patch: { files: [{ path: 'app.js', content: FIXED_APP }] }, verify: { cmd: 'node probe.js' },
  }).record;
  await materializePatch(rec, { repoDir: REPO });
  const d = buildPrDraft(rec);
  assert.match(d.title, /^fix: command injection in the run endpoint \[varvel rem-[0-9a-f]{8}\]$/);
  assert.match(d.body, /## Finding/);
  assert.match(d.body, /uid=0/, 'the finding evidence is in the body');
  assert.match(d.body, /## Validation proof/);
  assert.match(d.body, /Validator state: \*\*validated\*\*/);
  assert.match(d.body, /differential holds/, 'the oracle line rides as the validation proof');
  assert.match(d.body, /## Fix verification/);
  assert.match(d.body, /MEASURED \*\*patch-works\*\*: probe exit 1 \(expected nonzero\)/);
  assert.match(d.body, /## Changes/);
  assert.match(d.body, /app\.js/, 'diffstat in the body');
  assert.match(d.body, /## Rollback/);
  assert.match(d.body, /git revert/, 'the rollback note');
  assert.match(d.body, /Merge is always the client's act/);
  assert.match(d.body, new RegExp(rec.id));
  assert.match(d.body, /burner account/);
  // the patch-FAILS and undeclared drafts say so, honestly
  const fails = createRemediation({ engagement: ENG, surface: SURFACE, findingRef: 'F-VALID', patch: { files: [{ path: 'app.js', content: VULN_APP + '// kept\n' }] }, verify: { cmd: 'node probe.js' } }).record;
  await materializePatch(fails, { repoDir: REPO });
  assert.match(buildPrDraft(fails).body, /patch-FAILS.*explicit operator action/s);
  const und = createRemediation({ engagement: ENG, surface: SURFACE, findingRef: 'F-VALID', patch: { files: [{ path: 'app.js', content: FIXED_APP }] } }).record;
  await materializePatch(und, { repoDir: REPO });
  assert.match(buildPrDraft(und).body, /NOT VERIFIED(.|\n)*not\*\* claimed/);
  // house-style commit message carries provenance + the measured verdict
  const msg = remediationCommitMessage(rec);
  assert.match(msg, /^remediate: command injection in the run endpoint \[varvel /);
  assert.match(msg, /finding: F-VALID \(crit, validator validated\)/);
  assert.match(msg, /verify: patch-works \(probe exit 1, expected nonzero\)/);
  assert.equal(gitOut(['status', '--porcelain']), '');
});

/* ── 6. THE REMOTE LEG — mock git spy + loopback GitHub; token secrecy negative scan ── */

async function patchedRecord() {
  const rec = createRemediation({
    engagement: ENG, surface: SURFACE, findingRef: 'F-VALID',
    patch: { files: [{ path: 'app.js', content: FIXED_APP }] }, verify: { cmd: 'node probe.js' },
  }).record;
  const m = await materializePatch(rec, { repoDir: REPO });
  assert.equal(m.ok, true, 'patchedRecord: materialize succeeded');
  saveRemediation(rec); // open-pr loads the record from DISK — persist the patched state
  return rec;
}

test('open-pr: branch → commit → push (token in child ENV only) → REST; PR + audit, token nowhere', async () => {
  const rec = await patchedRecord();
  const gh = await mockPulls();
  const spy = gitSpy();
  try {
    const r = await openRemediationPr({
      engagement: ENG, id: rec.id, repoDir: REPO, owner: 'acme', repo: 'app',
      apiBase: gh.apiBase, settings: ALL_ON, spawn: spy,
    });
    assert.equal(r.ok, true);
    assert.equal(r.pr.number, 7);
    assert.equal(r.pr.url, 'https://github.com/acme/app/pull/7');
    assert.equal(r.pr.head, 'varvel/' + rec.id);
    assert.equal(r.token.present, true);
    assert.equal(r.token.class, 'fine-grained-pat', 'presence + class only — never the value');
    assert.match(r.transport, /private\/loopback/);

    // the git leg: branch, apply, add, transient-identity commit, push
    const stages = spy.calls.map((c) => (c.args[2] === '-c' ? 'commit' : c.args[2]));
    assert.deepEqual(stages, ['rev-parse', 'checkout', 'apply', 'add', 'commit', 'push']);
    const push = spy.calls.find((c) => c.args[2] === 'push');
    assert.ok(push.args.includes('https://github.com/acme/app.git'), 'the remote URL is token-free by construction');
    assert.equal(push.env.GIT_CONFIG_VALUE_0, 'Authorization: Bearer ' + PAT, 'the token rides the push child ENV as a transient http.extraHeader');
    assert.equal(push.env.GIT_TERMINAL_PROMPT, '0', 'fail-closed, never an interactive credential prompt');
    const commit = spy.calls.find((c) => c.args[2] === '-c');
    assert.ok(commit.args.includes('user.name=VARVEL Remediation'), 'the commit is attributable to the loop, never impersonating the operator');

    // the REST leg: exactly one authed POST, the complete body
    assert.equal(gh.hits.pulls, 1);
    assert.equal(gh.hits.authed, 1);
    const sent = gh.bodies[0];
    assert.equal(sent.head, 'varvel/' + rec.id);
    assert.equal(sent.base, 'main');
    assert.match(sent.title, /^fix: /);
    assert.match(sent.body, /## Validation proof(.|\n)*validated/);
    assert.match(sent.body, /## Rollback(.|\n)*git revert/);

    // THE NEGATIVE SCAN: the token value is in NO report and NO audit entry
    const stored = getRemediation({ engagement: ENG, id: rec.id });
    assert.equal(stored.status, 'pr-opened');
    assert.ok(stored.audit.some((a) => a.stage === 'pushed' && /present, fine-grained-pat/.test(a.detail)));
    assert.ok(stored.audit.some((a) => a.stage === 'pr-opened'));
    assert.ok(!JSON.stringify(stored).includes(PAT), 'the persisted record is token-free');
    assert.ok(!JSON.stringify(r).includes(PAT), 'the returned report is token-free');
    assert.ok(!spy.calls.some((c) => c.args.join('').includes(PAT)), 'the token never touched argv');
  } finally { gh.server.close(); }
});

test('open-pr: idempotent — a pr-opened record never re-pushes, never double-opens', async () => {
  const rec = await patchedRecord();
  const gh = await mockPulls();
  const spy = gitSpy();
  try {
    const first = await openRemediationPr({ engagement: ENG, id: rec.id, repoDir: REPO, owner: 'acme', repo: 'app', apiBase: gh.apiBase, settings: ALL_ON, spawn: spy });
    assert.equal(first.ok, true);
    const callsAfterFirst = spy.calls.length;
    const second = await openRemediationPr({ engagement: ENG, id: rec.id, repoDir: REPO, owner: 'acme', repo: 'app', apiBase: gh.apiBase, settings: ALL_ON, spawn: spy });
    assert.equal(second.ok, true);
    assert.equal(second.already, true);
    assert.equal(spy.calls.length, callsAfterFirst, 'zero git spawns on the re-run');
    assert.equal(gh.hits.pulls, 1, 'zero REST calls on the re-run');
  } finally { gh.server.close(); }
});

test('open-pr: push failure is scrubbed (poisoned stderr never leaks the token); nothing marked pushed', async () => {
  const rec = await patchedRecord();
  const gh = await mockPulls();
  const spy = gitSpy({ push: { code: 1, stderr: 'remote: Permission denied for token ' + PAT + ' — bad credentials' } });
  try {
    const r = await openRemediationPr({ engagement: ENG, id: rec.id, repoDir: REPO, owner: 'acme', repo: 'app', apiBase: gh.apiBase, settings: ALL_ON, spawn: spy });
    assert.equal(r.ok, false);
    assert.equal(r.stage, 'push');
    assert.match(r.reason, /<redacted>/, 'the git stderr is scrubbed before it can touch the report');
    assert.ok(!JSON.stringify(r).includes(PAT));
    const stored = getRemediation({ engagement: ENG, id: rec.id });
    assert.equal(stored.pushed, null, 'a failed push marks nothing — a re-run starts the git leg fresh');
    assert.equal(stored.status, 'patched');
    assert.ok(!JSON.stringify(stored).includes(PAT), 'the audit carries the scrubbed line only');
    assert.equal(gh.hits.pulls, 0, 'the REST leg never fired');
  } finally { gh.server.close(); }
});

test('open-pr: REST failure after a good push RESUMES at the PR leg (no re-push)', async () => {
  const rec = await patchedRecord();
  const gh = await mockPulls({ pr: { html_url: 'https://github.com/acme/app/pull/9', number: 9 } });
  gh.state.status = 500; // first attempt: the PR leg fails
  const spy1 = gitSpy();
  try {
    const r1 = await openRemediationPr({ engagement: ENG, id: rec.id, repoDir: REPO, owner: 'acme', repo: 'app', apiBase: gh.apiBase, settings: ALL_ON, spawn: spy1 });
    assert.equal(r1.ok, false);
    assert.equal(r1.stage, 'pr-open');
    assert.match(r1.reason, /the branch IS pushed(.|\n)*resumes at the PR leg/);
    const stored = getRemediation({ engagement: ENG, id: rec.id });
    assert.equal(stored.pushed.branch, 'varvel/' + rec.id, 'the push is journaled for resume');
    assert.equal(stored.status, 'patched', 'no premature pr-opened');

    gh.state.status = 201; // second attempt: GitHub recovers
    const spy2 = gitSpy();
    const r2 = await openRemediationPr({ engagement: ENG, id: rec.id, repoDir: REPO, owner: 'acme', repo: 'app', apiBase: gh.apiBase, settings: ALL_ON, spawn: spy2 });
    assert.equal(r2.ok, true);
    assert.equal(r2.pr.number, 9);
    assert.equal(spy2.calls.length, 0, 'no git at all on the resumed run — straight to REST');
    assert.equal(gh.hits.pulls, 2);
  } finally { gh.server.close(); }
});

test('open-pr: patch-FAILS verification opens with a loud warning (the operator override is data)', async () => {
  const rec = createRemediation({
    engagement: ENG, surface: SURFACE, findingRef: 'F-VALID',
    patch: { files: [{ path: 'app.js', content: VULN_APP + '// kept\n' }] }, verify: { cmd: 'node probe.js' },
  }).record;
  await materializePatch(rec, { repoDir: REPO });
  assert.equal(rec.verifyResult.verdict, 'patch-fails');
  saveRemediation(rec); // persist the patched state — open-pr loads from disk
  const gh = await mockPulls();
  try {
    const r = await openRemediationPr({ engagement: ENG, id: rec.id, repoDir: REPO, owner: 'acme', repo: 'app', apiBase: gh.apiBase, settings: ALL_ON, spawn: gitSpy() });
    assert.equal(r.ok, true, 'HITL: the operator MAY open with failing verify — the platform warns, never blocks the human act');
    assert.match(r.warning, /patch-FAILS/);
    assert.match(gh.bodies[0].body, /patch-FAILS/, 'the PR body itself carries the failing verdict');
  } finally { gh.server.close(); }
});

/* ── 7. RemPrApi error mapping + the ghost-threading resolver ── */

test('RemPrApi: 401/403/404/422 map to honest, token-free operator messages', async () => {
  const mk = (status, body) => new Promise((resolve) => {
    const server = http.createServer((req, res) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(body || {})); });
    server.listen(0, '127.0.0.1', () => resolve({ server, apiBase: 'http://127.0.0.1:' + server.address().port }));
  });
  for (const [status, body, re] of [
    [401, { message: 'Bad credentials' }, /token REJECTED \(401/],
    [403, {}, /forbidden \(403\)(.|\n)*lacks repo scope/],
    [404, {}, /not found \(404\)(.|\n)*cannot see acme\/app/],
    [422, { message: 'Validation Failed' }, /unprocessable \(422\)(.|\n)*Validation Failed/],
  ]) {
    const m = await mk(status, body);
    const api = new RemPrApi({ token: PAT, owner: 'acme', repo: 'app', apiBase: m.apiBase });
    const r = await api.openPr({ title: 't', body: 'b', head: 'h', base: 'main' });
    assert.equal(r.ok, false, 'HTTP ' + status);
    assert.equal(r.status, status);
    assert.match(r.error, re);
    assert.ok(!JSON.stringify(r).includes(PAT), 'error paths are token-free');
    m.server.close();
  }
});

test('resolveRemTransport: overt by default, ghost-threaded when armed, fail-closed when required', async () => {
  const priv = await resolveRemTransport({ apiBase: 'http://127.0.0.1:1' });
  assert.equal(priv.direct, true);
  assert.match(priv.transport, /lab traffic never leaves the lab/);
  const off = await resolveRemTransport({ ghostMode: 'off', apiBase: 'https://api.github.com' });
  assert.equal(off.direct, true);
  assert.match(off.transport, /overt client work/, 'remediation is OVERT — ghost off means direct, labeled honestly');
  const ghost = { mode: 'on', chain: ['http://proxy:8080'], verifiedOk: () => true, agents: () => ({ httpAgent: 'A', httpsAgent: 'B' }) };
  const on = await resolveRemTransport({ ghost, apiBase: 'https://api.github.com' });
  assert.equal(on.direct, false, 'ghost on + chain: the REST leg rides the ghost agents, same as ghc2');
  assert.deepEqual(on.agents, { httpAgent: 'A', httpsAgent: 'B' });
  const bestEffort = await resolveRemTransport({ ghost: { mode: 'on', chain: [] }, apiBase: 'https://api.github.com' });
  assert.equal(bestEffort.direct, true);
  assert.match(bestEffort.transport, /best-effort/);
  const reqNoChain = await resolveRemTransport({ ghost: { mode: 'required', chain: [] }, apiBase: 'https://api.github.com' });
  assert.equal(reqNoChain.ok, false, 'ghost required + no chain: REFUSED fail-closed');
  assert.match(reqNoChain.reason, /REQUIRED(.|\n)*REFUSED/);
  const reqUnverified = await resolveRemTransport({ ghost: { mode: 'required', chain: ['http://p:1'], verifiedOk: () => false, verify: async () => {} }, apiBase: 'https://api.github.com' });
  assert.equal(reqUnverified.ok, false);
  assert.match(reqUnverified.reason, /NOT verified(.|\n)*REFUSED/);
  assert.equal((await resolveRemTransport({ apiBase: 'not a url' })).ok, false);
});

test('pushEnv: the token shape that keeps the PAT out of the remote URL and .git/config', () => {
  const e = pushEnv(PAT);
  assert.equal(e.GIT_CONFIG_COUNT, '1');
  assert.equal(e.GIT_CONFIG_KEY_0, 'http.extraHeader');
  assert.equal(e.GIT_CONFIG_VALUE_0, 'Authorization: Bearer ' + PAT);
  assert.equal(e.GIT_TERMINAL_PROMPT, '0');
});

/* ── 8. THE OPERATOR SURFACE — cli remediate draft/list end-to-end (spawned) ── */

test('cli: draft + list run against the stored surface; default-OFF refusal names the gate', () => {
  const CLI = join(ROOT, 'tools', 'cli.mjs');
  const CLI_DATA = join(TMP, 'cli-data');
  const CLI_SETTINGS = join(TMP, 'cli-settings.json');
  rmSync(CLI_DATA, { recursive: true, force: true });
  const env = { ...process.env, VARVEL_DATA_DIR: CLI_DATA, VARVEL_SETTINGS_FILE: CLI_SETTINGS };
  // the parent writes what the engagement would have: a stored surface + the opt-in
  process.env.VARVEL_DATA_DIR = CLI_DATA; // saveSurface reads dataDir() at call time
  saveSurface(ENG, SURFACE);
  saveSurface(ENG + '-off', SURFACE);
  process.env.VARVEL_DATA_DIR = DATA;
  writeFileSync(CLI_SETTINGS, JSON.stringify({ [ENG]: { 'remediate.prEnabled': true } }));
  const fixedFile = join(TMP, 'fixed-app.js');
  writeFileSync(fixedFile, FIXED_APP);

  const run = (args) => {
    const r = spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', timeout: 30000, env });
    let out = null;
    try { out = JSON.parse(r.stdout); } catch { out = { parseError: String(r.stdout).slice(0, 300), stderr: String(r.stderr).slice(0, 300) }; }
    return { status: r.status, out };
  };

  const d = run(['remediate', 'draft', 'F-VALID', '--engagement', ENG, '--file', 'app.js:' + fixedFile, '--verify', 'node probe.js']);
  assert.equal(d.status, 0, JSON.stringify(d.out));
  assert.equal(d.out.ok, true);
  assert.match(d.out.record.id, /^rem-/);
  assert.equal(d.out.record.status, 'draft');

  const refused = run(['remediate', 'draft', 'F-REFUTED', '--engagement', ENG]);
  assert.equal(refused.out.ok, false);
  assert.equal(refused.out.gate, 'eligibility', 'the validator gate fires through the operator surface');

  const off = run(['remediate', 'draft', 'F-VALID', '--engagement', ENG + '-off']);
  assert.equal(off.out.ok, false);
  assert.equal(off.out.gate, 'remediate.prEnabled', 'default-OFF through the CLI');

  const l = run(['remediate', 'list', '--engagement', ENG]);
  assert.equal(l.status, 0);
  assert.ok(l.out.remediations.some((x) => x.id === d.out.record.id && x.status === 'draft'));
  assert.ok(!JSON.stringify(l.out).includes(PAT));
});
