// VARVEL pocforge tests — the exploit-design stage (tools/pocforge.mjs).
// Hermetic: fixture evidence dirs in mkdtemp, an INJECTED brain and an INJECTED
// wire — zero external network, zero docker (the forge's probes are host-side
// through the wire seam, exactly like gather). The doctrines under test: the
// strict brain-action contract (malformed output is rejected, never repaired),
// the scope rail (a brain asking out-of-scope is refused BEFORE any byte,
// fail-closed), the read-only proof policy (state-changing verbs, credential
// headers, canary-less POSTs never reach the wire), poc-unproven after
// exhausted attempts, check-defect when the machinery fails, give-up honesty,
// the draft upgrade filling ONLY what the proof answers (the scope attestation
// TODO stays), the never-submits static pin, and the CLI's one-JSON-line
// contract the console parses.
//   node --test test/pocforge.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync, existsSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';

const __dir = dirname(fileURLToPath(import.meta.url));
const pf = await import('../tools/pocforge.mjs');

const T1 = '2026-09-12T12:00:00.000Z';
const sha256 = (x) => createHash('sha256').update(x).digest('hex');
const mk = () => mkdtempSync(join(tmpdir(), 'varvel-pocforge-'));
const readEvents = (dir) => readFileSync(join(dir, 'events.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l));

// A gather-shaped bundle: jQuery 2.2.1 on sensei.pixiv.net (the CVE-2020-11023
// fingerprint), a clean Next.js host beside it.
const BUNDLE = {
  at: '2026-09-12T03:01:36.787Z', opportunity: 'pixiv', cadence: {},
  assets: [
    { host: 'booth.pm', kind: 'domain', status: 403, techs: [{ id: 'cloudflare', label: 'Cloudflare', version: null, evidence: 'server: cloudflare' }], headers: {}, endpoints: [], requests: 2 },
    { host: 'sensei.pixiv.net', kind: 'domain', status: 200, techs: [{ id: 'jquery', label: 'jQuery', version: '2.2.1', evidence: 'jquery-2.2.1.min.js' }, { id: 'cloudflare', label: 'Cloudflare', version: null, evidence: 'server: cloudflare' }], headers: { server: 'cloudflare' }, endpoints: [], requests: 2 },
    { host: 'comic.pixiv.net', kind: 'domain', status: 200, techs: [{ id: 'nextjs', label: 'Next.js', version: null, evidence: '/_next/static/' }], headers: {}, endpoints: [], requests: 2 },
  ],
};

const mkEvidence = (dir, { verdict = 'verified', bundle = BUNDLE } = {}) => {
  const evDir = join(dir, 'evidence', 'pixiv_new-program_in_276d4b32c458', 'cve-2020-11023-cve-2020-11023-jquery-html-inject');
  mkdirSync(evDir, { recursive: true });
  const check = `const b=JSON.parse(${JSON.stringify(JSON.stringify(bundle))});const ok=(b.assets||[]).some(a=>(a.techs||[]).some(t=>t.id==="jquery"&&t.version==="2.2.1"));console.log(ok?'CVE-MATCH-OK':'EVIDENCE-MISSING');`;
  writeFileSync(join(evDir, 'check.txt'), check);
  writeFileSync(join(evDir, 'result.json'), JSON.stringify({
    verified: verdict === 'verified', verdict, expect: 'CVE-MATCH-OK', matched: verdict === 'verified',
    stdout: 'CVE-MATCH-OK', verdictReason: 'replay-verification PASSED', at: T1,
  }));
  writeFileSync(join(evDir, 'env.json'), JSON.stringify({ recorder: 'transcript+hash', kernelIsolated: true }));
  return evDir;
};

const seedDraft = (dir, evDir) => {
  const outbox = join(dir, 'outbox');
  mkdirSync(outbox, { recursive: true });
  const file = join(outbox, 'pixiv-cve-2020-11023-jquery-html-inject.md');
  writeFileSync(file, `<!-- VARVEL huntloop draft — HUMAN REVIEW ONLY. The loop NEVER submits: this file waits in the outbox for the operator's hand. Verdict: VERIFIED (replay-verification PASSED). Evidence bundle: ${evDir} -->

# CVE-2020-11023 — jQuery HTML injection via untrusted <option> manipulation (jQuery 2.2.1 is in the affected range)

## Steps to Reproduce

1. TODO(validate) — affected host/URL (the input carried no host binding for this finding; name the exact asset from your validated session)
2. TODO(validate) — exact endpoint/parameter (the finding carries no ref; write the precise request from your validated session)
3. Reproduce the proof exactly as the validator gate did: huntloop replay-verification.
4. TODO(validate) — full impact demonstration (state-changing proof is operator sign-off territory; attach only the verified exchange)

## Impact

TODO(validate) — concrete impact statement (derive from the VERIFIED repro at suspected confidence: what does a successful exploit READ, CHANGE, or REACH? The static record does not state impact, so this report does not either)

## Scope Attestation

TODO(validate) — scope attestation (the input carried no signed scope; attach the program scope + authorization before submission — a report without an attestation reads as unscoped testing)

## Honesty — unverified gaps

- confidence is 'suspected' — the platform did not confirm this finding end-to-end
- no signed scope in the input — the attestation line could not be rendered from evidence

---
_Evidence is verbatim-minus-redactions; gaps are listed, never hidden; readiness is computed from the validator gate, never asserted._
`);
  return file;
};

// The injected brain: plays a script of raw answers (objects are JSON-stringified).
const scriptedBrain = (script) => {
  let i = 0;
  const calls = [];
  const brain = async (system, user) => {
    calls.push({ system, user });
    const a = script[Math.min(i++, script.length - 1)];
    return typeof a === 'string' ? a : JSON.stringify(a);
  };
  brain.calls = calls;
  return brain;
};

// The injected wire: records every call, answers through the handler.
const scriptedWire = (handler) => {
  const calls = [];
  const wire = async (url, opts) => {
    calls.push({ url, opts });
    return handler(url, opts);
  };
  wire.calls = calls;
  return wire;
};

const forge = (evDir, dir, { brain, wire, ...opts } = {}) => pf.pocForge({
  evidenceDir: evDir, dir, brain, fetchImpl: wire, now: T1,
  sleepImpl: async () => {},
  caps: { heartbeatMs: 0, delayMs: 0 },
  ...opts,
});

const probe = (over = {}) => ({ action: 'http-probe', method: 'GET', path: '/clean', expectMarker: 'PWN-REFLECTED', rationale: 'probe the sink', ...over });

// --- the never-submits pin (same doctrine as test/huntloop.test.mjs) -------------------------

test('the forge NEVER submits — static pin: no submission/network code path beyond the audited seams', () => {
  const src = readFileSync(join(__dir, '..', 'tools', 'pocforge.mjs'), 'utf8');
  for (const re of [/node:https?\b/, /\bhttps?\.\s*request\s*\(/, /XMLHttpRequest/, /\bnet\.connect/, /\.submit\s*\(/]) {
    assert.ok(!re.test(src), `the forge must carry NO raw network/submission code path — matched ${re}`);
  }
  const imports = [...src.matchAll(/from\s+'([^']+)'/g)].map((m) => m[1]);
  assert.ok(imports.includes('../engine/brain-provider.mjs'), 'the brain call is REUSED, never reimplemented');
  assert.ok(imports.includes('./ghostfetch.mjs'), 'target bytes ride the audited ghost transport seam');
  assert.ok(!imports.some((i) => /submit/.test(i)), 'no submission module is imported');
});

// --- evidence intake -------------------------------------------------------------------------

test('parseEvidenceBundle + fingerprint: the affected host is re-derived from check.txt\'s inline bundle', () => {
  const dir = mk();
  const evDir = mkEvidence(dir);
  const parsed = pf.parseEvidenceBundle(evDir);
  assert.equal(parsed.ok, true);
  assert.equal(parsed.bundle.assets.length, 3);
  assert.equal(parsed.result.verdict, 'verified');
  const cve = pf.deriveCve({ title: 'CVE-2020-11023 — jQuery HTML injection' }, evDir);
  assert.equal(cve, 'CVE-2020-11023');
  const fp = pf.fingerprint(parsed.bundle, cve);
  assert.deepEqual(fp.affectedHosts, ['sensei.pixiv.net'], 'the jquery 2.2.1 host is the affected one');
  assert.deepEqual(fp.probedHosts.sort(), ['booth.pm', 'comic.pixiv.net', 'sensei.pixiv.net'], 'every host that ANSWERED (any status) is probeable');
  assert.equal(fp.match.tech, 'jquery');
  assert.equal(fp.match.version, '2.2.1');
});

test('parseEvidenceBundle: no inline bundle is an honest refusal, never an invented one', () => {
  const dir = mk();
  const evDir = mkEvidence(dir);
  writeFileSync(join(evDir, 'check.txt'), 'console.log("hand-typed, no bundle");');
  const parsed = pf.parseEvidenceBundle(evDir);
  assert.equal(parsed.ok, false);
  assert.equal(parsed.error, 'bundle-not-found');
});

// --- the strict brain-action contract ---------------------------------------------------------

test('parseBrainAction: the strict contract — malformed output rejected, never repaired', () => {
  const canary = 'VARVEL-POC-INERT-deadbeef00';
  const okGet = pf.parseBrainAction(JSON.stringify(probe()), { canary });
  assert.equal(okGet.ok, true);
  assert.equal(okGet.action.method, 'GET');
  assert.equal(okGet.action.expectMarker, 'PWN-REFLECTED');
  // a fenced answer parses too
  assert.equal(pf.parseBrainAction('reasoning…\n```json\n' + JSON.stringify(probe()) + '\n```', { canary }).ok, true);
  // garbage / wrong shapes
  for (const [name, text] of [
    ['not json at all', 'I think we should try the admin panel'],
    ['unknown action', JSON.stringify({ action: 'exploit', path: '/x' })],
    ['path not root-relative', JSON.stringify(probe({ path: 'sensei.pixiv.net/x' }))],
    ['no expectMarker', JSON.stringify(probe({ expectMarker: '' }))],
    ['give-up without a reason', JSON.stringify({ action: 'give-up' })],
  ]) {
    const r = pf.parseBrainAction(text, { canary });
    assert.equal(r.ok, false, `${name} must be rejected`);
    assert.equal(r.kind, 'contract', `${name} is a contract rejection`);
  }
  // READ-ONLY POLICY cases
  for (const [name, over] of [
    ['DELETE', { method: 'DELETE' }],
    ['PUT', { method: 'PUT' }],
    ['authorization header', { headers: { authorization: 'Bearer x' } }],
    ['cookie header', { headers: { Cookie: 'session=1' } }],
    ['body on GET', { body: canary }],
    ['POST body without the canary', { method: 'POST', body: 'x=<option>y</option>' }],
  ]) {
    const r = pf.parseBrainAction(JSON.stringify(probe(over)), { canary });
    assert.equal(r.ok, false, `${name} must be rejected`);
    assert.equal(r.kind, 'policy', `${name} is a read-only-policy rejection`);
    assert.match(r.reason, /READ-ONLY POLICY/);
  }
  // POST with the canary inside is the ONE state-capable shape allowed
  const okPost = pf.parseBrainAction(JSON.stringify(probe({ method: 'POST', body: `comment=<option>x</option><!-- ${canary} -->` })), { canary });
  assert.equal(okPost.ok, true);
  assert.equal(okPost.action.body.includes(canary), true);
  // an honest give-up
  const gave = pf.parseBrainAction(JSON.stringify({ action: 'give-up', reason: 'the sink needs an authenticated session' }), { canary });
  assert.equal(gave.ok, true);
  assert.equal(gave.action.action, 'give-up');
});

// --- the scope rail ----------------------------------------------------------------------------

test('evidenceScopeGuard: only evidence hosts, deny by default', () => {
  const guard = pf.evidenceScopeGuard(['sensei.pixiv.net', 'comic.pixiv.net']);
  assert.equal(guard.allow('sensei.pixiv.net'), true);
  assert.equal(guard.allow('https://sensei.pixiv.net/x?y=1'), true);
  assert.equal(guard.allow('evil.example'), false);
  assert.equal(guard.allow('https://sub.sensei.pixiv.net/'), false, 'sub-domains are NOT implied');
  assert.throws(() => guard.assertAllowed('https://evil.example/'), (e) => e.code === 'scope-violation');
});

test('the scope rail refuses an out-of-scope probe BEFORE the wire — even when the brain insists (fail-closed)', async () => {
  const dir = mk();
  const evDir = mkEvidence(dir);
  const brain = scriptedBrain([probe({ path: 'https://evil.example/pwn' })]);
  const wire = scriptedWire(async () => ({ ok: true, status: 200, headers: {}, text: async () => 'PWN-REFLECTED' }));
  const r = await forge(evDir, dir, { brain, wire });
  assert.equal(r.ok, true);
  assert.equal(r.verdictClass, 'check-defect', 'no probe ever executed — a defect, not an evaluated claim');
  assert.equal(wire.calls.length, 0, 'NOT ONE BYTE left the box — the refusal is structural');
  assert.equal(r.probesExecuted, 0);
  const events = readEvents(dir);
  assert.ok(events.some((e) => e.type === 'poc-forge' && e.state === 'scope-refused'), 'the refusal is recorded LOUDLY');
  assert.ok(events.some((e) => e.type === 'stage' && e.stage === 'poc-forge' && e.state === 'failed' && e.verdictClass === 'check-defect'));
  // the record still lands in the evidence bundle — an unexecuted forge is part of the record
  assert.ok(existsSync(join(evDir, 'poc-result.json')));
  const transcript = readFileSync(join(evDir, 'poc-transcript.txt'), 'utf8');
  assert.match(transcript, /SCOPE REFUSAL/);
});

test('the read-only policy blocks a state-changing action before the wire', async () => {
  const dir = mk();
  const evDir = mkEvidence(dir);
  const brain = scriptedBrain([
    probe({ method: 'PUT', path: '/api/admin', expectMarker: 'OK' }),              // state-changing verb
    probe({ method: 'POST', path: '/post', body: 'no canary here' }),              // canary-less POST
    probe({ headers: { cookie: 'session=abc' } }),                                  // a credential
  ]);
  const wire = scriptedWire(async () => ({ ok: true, status: 200, headers: {}, text: async () => 'PWN-REFLECTED' }));
  const r = await forge(evDir, dir, { brain, wire });
  assert.equal(r.verdictClass, 'check-defect');
  assert.equal(wire.calls.length, 0, 'every off-policy action died at the contract parse');
  const events = readEvents(dir);
  assert.equal(events.filter((e) => e.type === 'poc-forge' && e.state === 'policy-rejected').length, 3);
});

// --- the verdict paths --------------------------------------------------------------------------

test('poc-unproven: attempts exhausted, probes executed, the marker never appeared', async () => {
  const dir = mk();
  const evDir = mkEvidence(dir);
  const brain = scriptedBrain([probe()]);
  const wire = scriptedWire(async () => ({ ok: true, status: 200, headers: { server: 'cloudflare' }, text: async () => '<html>nothing here</html>' }));
  const r = await forge(evDir, dir, { brain, wire });
  assert.equal(r.ok, true);
  assert.equal(r.verdictClass, 'poc-unproven');
  assert.equal(r.attempts, 3, 'the default budget is 3 attempts');
  assert.equal(r.probesExecuted, 3);
  assert.equal(wire.calls.length, 3);
  assert.equal(wire.calls[0].url, 'https://sensei.pixiv.net/clean', 'root-relative paths resolve against the AFFECTED host');
  assert.match(r.reason, /UNPROVEN/);
  const events = readEvents(dir);
  assert.ok(events.some((e) => e.type === 'stage' && e.stage === 'poc-forge' && e.state === 'active'), 'the stage opened');
  assert.ok(events.some((e) => e.type === 'stage' && e.stage === 'poc-forge' && e.state === 'failed' && e.verdictClass === 'poc-unproven'));
  assert.ok(!events.some((e) => e.type === 'proof'), 'no proof event without a captured marker');
  // the transcript records the evaluated probes, honestly
  const transcript = readFileSync(join(evDir, 'poc-transcript.txt'), 'utf8');
  assert.match(transcript, /marker ABSENT/);
  assert.match(transcript, /VERDICT: POC-UNPROVEN/);
});

test('an honest give-up is poc-unproven with the brain\'s reason named', async () => {
  const dir = mk();
  const evDir = mkEvidence(dir);
  const brain = scriptedBrain([
    probe(),
    { action: 'give-up', reason: 'the XSS sink requires an authenticated session — beyond read-only reach' },
  ]);
  const wire = scriptedWire(async () => ({ ok: true, status: 200, headers: {}, text: async () => '<html>clean</html>' }));
  const r = await forge(evDir, dir, { brain, wire });
  assert.equal(r.verdictClass, 'poc-unproven');
  assert.equal(r.probesExecuted, 1);
  assert.match(r.reason, /GAVE UP/);
  assert.match(r.reason, /authenticated session/);
});

test('all-malformed brain output is check-defect — the machinery failed, not the claim', async () => {
  const dir = mk();
  const evDir = mkEvidence(dir);
  const brain = scriptedBrain(['vibes, no json']);
  const wire = scriptedWire(async () => { throw new Error('must never be called'); });
  const r = await forge(evDir, dir, { brain, wire });
  assert.equal(r.verdictClass, 'check-defect');
  assert.equal(r.attempts, 3);
  assert.equal(r.probesExecuted, 0);
  assert.match(r.reason, /NEVER evaluated/);
});

// --- poc-verified: the proof record + the draft upgrade ------------------------------------------

test('poc-verified: the marker is captured, the evidence bundle gains the proof, the draft upgrades honestly', async () => {
  const dir = mk();
  const evDir = mkEvidence(dir);
  const draftFile = seedDraft(dir, evDir);
  const brain = scriptedBrain([
    probe(),
    probe({ path: '/search?x=<option>y</option>', rationale: 'the option payload reflects unencoded into the results html' }),
  ]);
  const wire = scriptedWire(async (url) => {
    if (url.includes('/search')) {
      return { ok: true, status: 200, headers: { server: 'cloudflare' }, text: async () => '<html><body>results for <option>y</option> PWN-REFLECTED</body></html>' };
    }
    return { ok: true, status: 200, headers: { server: 'cloudflare' }, text: async () => '<html>clean</html>' };
  });
  const r = await forge(evDir, dir, { brain, wire });
  assert.equal(r.ok, true);
  assert.equal(r.verdictClass, 'poc-verified');
  assert.equal(r.probesExecuted, 2, 'one miss, one capture');
  assert.equal(r.proof.host, 'sensei.pixiv.net');
  assert.equal(r.proof.method, 'GET');
  assert.equal(r.proof.marker, 'PWN-REFLECTED');
  assert.equal(r.proof.markerLocation, 'body');
  assert.match(r.proof.excerpt, /PWN-REFLECTED/);

  // the evidence bundle: transcript + result + hash, all real
  const transcript = readFileSync(join(evDir, 'poc-transcript.txt'), 'utf8');
  assert.match(transcript, /CAPTURED in body/);
  const resultDoc = JSON.parse(readFileSync(join(evDir, 'poc-result.json'), 'utf8'));
  assert.equal(resultDoc.verdictClass, 'poc-verified');
  assert.equal(resultDoc.transcriptSha256, sha256(readFileSync(join(evDir, 'poc-transcript.txt'))), 'the hash covers the real transcript');
  assert.equal(resultDoc.scopeGuard, 'evidence-derived');

  // the events: stage done + the proof event carrying the new verdict class
  const events = readEvents(dir);
  const done = events.find((e) => e.type === 'stage' && e.stage === 'poc-forge' && e.state === 'done');
  assert.equal(done.verdictClass, 'poc-verified');
  const proofEv = events.find((e) => e.type === 'proof');
  assert.equal(proofEv.verdictClass, 'poc-verified');
  assert.equal(proofEv.evidenceDir, evDir);

  // THE DRAFT UPGRADE — only what the proof answers, the rest stays honest
  const md = readFileSync(draftFile, 'utf8');
  assert.match(md, /VERIFIED \(PoC demonstrated/, 'the header names the new class');
  assert.ok(!/Verdict: VERIFIED \(replay-verification PASSED\)/.test(md), 'the old verdict line is replaced');
  assert.match(md, /1\. Affected host\/URL \(PoC-demonstrated [^)]*\): `sensei\.pixiv\.net`/, 'the affected host is written in');
  assert.match(md, /2\. Exact request \(PoC-demonstrated\): `GET \/search\?x=<option>y<\/option>` to `sensei\.pixiv\.net`/, 'the exact request is written in');
  assert.match(md, /4\. Observed impact \(read-only proof[^)]*\): HTTP 200 — the declared marker `PWN-REFLECTED` appeared in the body/, 'the marker exchange is written in');
  assert.match(md, /PoC transcript: `poc-transcript\.txt` \(sha256 [0-9a-f]{64}\)/, 'the transcript hash rides the draft');
  assert.match(md, /PoC-DEMONSTRATED \(read-only\)/, 'the impact statement is written in');
  // what is NOT answered stays a TODO — the scope attestation above all
  assert.match(md, /TODO\(validate\) — scope attestation/, 'the scope attestation TODO STAYS (no signed scope in evidence)');
  assert.equal((md.match(/TODO\(validate\)/g) || []).length, 1, 'exactly one TODO line remains');
  // the honesty section keeps the old gaps AND names what is still unproven
  assert.match(md, /confidence is 'suspected'/, 'the old gaps are never erased');
  assert.match(md, /STILL UNPROVEN after the PoC/, 'the remaining limit is named');
  assert.match(md, /PoC demonstrated .*?: `GET \/search\?x=<option>y<\/option>` on `sensei\.pixiv\.net` → HTTP 200/);
  assert.equal(r.draft.upgraded, true);
  assert.deepEqual(r.draft.keptTodo.length, 1);
});

test('upgradeDraft refuses a draft that is not in the replay-verified state — never rewrites blind', () => {
  const r = pf.upgradeDraft({
    md: '# some other draft\nno verdict header here\n',
    proof: { host: 'h', url: 'https://h/', method: 'GET', path: '/', status: 200, marker: 'M', markerLocation: 'body', excerpt: 'M' },
    at: T1, transcriptName: 'poc-transcript.txt', transcriptSha256: 'x'.repeat(64),
  });
  assert.equal(r.ok, false);
  assert.match(r.reason, /left untouched/);
});

// --- intake refusals --------------------------------------------------------------------------------

test('a non-verified finding is NOT a forge candidate — honest refusal, no proof files written', async () => {
  const dir = mk();
  const evDir = mkEvidence(dir, { verdict: 'unproven' });
  const brain = scriptedBrain([probe()]);
  const wire = scriptedWire(async () => { throw new Error('must never be called'); });
  const r = await forge(evDir, dir, { brain, wire });
  assert.equal(r.ok, false);
  assert.equal(r.error, 'not-replay-verified');
  assert.equal(wire.calls.length, 0);
  assert.ok(!existsSync(join(evDir, 'poc-result.json')), 'a refused forge writes no proof record');
  const events = readEvents(dir);
  assert.ok(events.some((e) => e.type === 'stage' && e.stage === 'poc-forge' && e.state === 'failed'));
});

// --- the CLI's one-JSON-line contract (what the console parses) --------------------------------------

test('CLI: prints ONE JSON result line; a missing brain lane is an honest check-defect, never a hang', () => {
  const dir = mk();
  const evDir = mkEvidence(dir);
  const env = {
    ...process.env,
    VARVEL_BRAIN_PROVIDER: 'kimi', // resolveBrain → not openai-compatible → brainForge refuses BEFORE any network
    VARVEL_BRAIN_BASE_URL: '',
    VARVEL_BRAIN_MODEL: '',
    VARVEL_GHOST_CHAIN: '',
    VARVEL_SETTINGS_FILE: join(dir, 'absent-settings.json'),
  };
  const r = spawnSync(process.execPath, [join(__dir, '..', 'tools', 'pocforge.mjs'), '--finding', evDir, '--dir', dir], { encoding: 'utf8', env, timeout: 60000 });
  assert.equal(r.status, 0, `exit 0 with a verdict (stderr: ${String(r.stderr).slice(0, 300)})`);
  const lines = r.stdout.trim().split('\n').filter(Boolean);
  assert.equal(lines.length, 1, 'stdout carries exactly one line — the JSON verdict the console parses');
  const doc = JSON.parse(lines[0]);
  assert.equal(doc.ok, true);
  assert.equal(doc.verdictClass, 'check-defect');
  assert.match(doc.reason, /brain-not-openai-compatible|NEVER evaluated/);
  assert.ok(existsSync(join(evDir, 'poc-result.json')), 'the record landed in the bundle');
});

test('CLI: --finding is required (usage is honest, exit 2)', () => {
  const r = spawnSync(process.execPath, [join(__dir, '..', 'tools', 'pocforge.mjs')], { encoding: 'utf8', timeout: 30000 });
  assert.equal(r.status, 2);
  const doc = JSON.parse(r.stdout.trim());
  assert.equal(doc.ok, false);
  assert.equal(doc.error, 'usage');
});
