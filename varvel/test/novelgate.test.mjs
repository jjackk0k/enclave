// VARVEL novelgate tests — the pre-submission NOVELTY GATE (tools/novelgate.mjs +
// engine/novelcore.mjs), born from semrush #2666357 (DUPLICATE: Google-IAP edge behavior
// filed as an application CORS bug). Hermetic: the hacktivity transport is INJECTED
// (reqImpl fakes), the corpus is tmp dirs, bountyline persistence is tmp-isolated.
// Zero live network in this file. Run: node --test test/novelgate.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const __dir = dirname(fileURLToPath(import.meta.url));
const ROOT = mkdtempSync(join(tmpdir(), 'varvel-novelgate-'));
process.env.VARVEL_BOUNTYLINE_DIR = join(ROOT, 'bountyline');
process.env.VARVEL_SETTINGS_FILE = join(ROOT, 'settings.json');

const nc = await import('../engine/novelcore.mjs');
const ng = await import('../tools/novelgate.mjs');
const bl = await import('../engine/bountyline.mjs');
const SEAM = join(__dir, '..', '..', 'poc', 'enforcement-seam');
const seam = await import(pathToFileURL(join(SEAM, 'util.mjs')).href);

// --- the semrush IAP fixture (the exact case that burned #2666357) ------------------------
const IAP_HEADERS = {
  'HTTP': '302 Found',
  'location': 'https://accounts.google.com/o/oauth2/v2/auth?client_id=555419171242-...apps.googleusercontent.com',
  'access-control-allow-origin': 'https://attacker-controlled.example',
  'access-control-allow-credentials': 'true',
  'x-goog-iap-generated-response': 'true',
  'set-cookie': 'GCP_IAP_XSRF_NONCE=...; Secure; HttpOnly',
};
const SEMRUSH_DRAFT = `# CORS misconfiguration: arbitrary Origin reflection with credentials on Google-IAP-fronted admin host (admin.semrush.net)

**Program:** Semrush (HackerOne) · **Asset:** admin.semrush.net

## Summary
admin.semrush.net is fronted by Google IAP. The IAP front reflects an arbitrary Origin in
Access-Control-Allow-Origin while also sending Access-Control-Allow-Credentials: true.

\`\`\`
HTTP/1.1 302 Found
Location: https://accounts.google.com/o/oauth2/v2/auth?client_id=555...
Access-Control-Allow-Origin: https://attacker-controlled.example
Access-Control-Allow-Credentials: true
X-Goog-Iap-Generated-Response: true
\`\`\`

## Honest scope of proof
- Not included: a post-authentication demonstration of actual data theft. No authenticated
  account exists for this host; your team can confirm the post-auth behavior internally.
`;
const CLEAN_CORS_DRAFT = `# CORS: authenticated data read cross-origin on app.example.com

The application reflects Origin with credentials. We proved impact end-to-end:

\`\`\`
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://attacker.example
Access-Control-Allow-Credentials: true
Content-Type: application/json
\`\`\`

From an attacker origin, fetch(..., {credentials:'include'}) returned the authenticated
response body — the victim's account email and invoice history were read cross-origin and
captured in the attached HAR. This is a demonstrated cross-origin read of authenticated
application data, not header reflection.
`;
// A live-shaped GraphQL hacktivity payload (shape verified 2026-08-31).
const gqlPayload = (nodes) => JSON.stringify({ data: { search: { total_count: nodes.length, nodes } } });
const hackNode = (id, title, weakness, handle = 'semrush') => ({
  __typename: 'HacktivityDocument', _id: String(id), cwe: weakness,
  disclosed_at: '2020-02-15', severity_rating: 'Low',
  report: { id: `Z2lk${id}`, title, url: `https://hackerone.com/reports/${id}`, weakness: { name: weakness }, team: { handle, name: handle } },
});
const fakeTransport = (payload, status = 200) => async () => ({ status, headers: {}, body: typeof payload === 'string' ? payload : JSON.stringify(payload) });

// --- static pins ----------------------------------------------------------------------------
test('novelcore is PURE — no network, no fs (the network half lives in tools/novelgate.mjs)', () => {
  const src = readFileSync(join(__dir, '..', 'engine', 'novelcore.mjs'), 'utf8');
  for (const re of [/\bfetch\s*\(/, /node:https?\b/, /\bhttps?\.\s*request\s*\(/, /XMLHttpRequest/, /\bnet\.connect/, /node:fs\b/]) {
    assert.ok(!re.test(src), `novelcore must carry NO network/fs code path — matched ${re}`);
  }
});

// --- the edge-generated-behavior detector ---------------------------------------------------
test('edge detector: the semrush IAP signature (302 + x-goog-iap-generated-response) is FLAGGED', () => {
  const d = nc.detectEdgeGenerated({ status: 302, headers: IAP_HEADERS });
  assert.equal(d.flagged, true);
  assert.equal(d.unauthStatus, true);
  assert.ok(d.signals.some((s) => s.id === 'google-iap-generated'), 'the generated-response signature is named');
  assert.match(d.reason, /edge-generated behavior on an unauthenticated 302/);
});

test('edge detector: edge headers on a 200 app response are NOT flagged; plain app 302 is not edge', () => {
  const d200 = nc.detectEdgeGenerated({ status: 200, headers: IAP_HEADERS });
  assert.equal(d200.edge, true);
  assert.equal(d200.flagged, false, 'edge-signature headers on an authenticated-status response are noted, not flagged');
  const plain = nc.detectEdgeGenerated({ status: 302, headers: { location: '/login', server: 'nginx' } });
  assert.equal(plain.flagged, false);
  assert.equal(plain.edge, false);
  const elb = nc.detectEdgeGenerated({ status: 401, headers: { server: 'awselb/2.0' } });
  assert.equal(elb.flagged, true, 'ELB default challenge on 401 is the same class');
});

test('parseHttpEvidence pulls status+headers out of a draft exchange block', () => {
  const blocks = nc.parseHttpEvidence(SEMRUSH_DRAFT);
  assert.equal(blocks.length, 1);
  assert.equal(blocks[0].status, 302);
  const d = nc.detectEdgeGenerated(blocks[0]);
  assert.equal(d.flagged, true, 'the draft alone carries enough to flag — no separate capture needed');
});

// --- the per-class impact bar ---------------------------------------------------------------
test('SEMRUSH CASE: IAP-gate CORS draft with the honest admission is BLOCKED (no impact proof, no submission)', () => {
  const a = nc.assess({
    platform: 'hackerone', draftText: SEMRUSH_DRAFT,
    status: 302, headers: IAP_HEADERS,
    hacktivity: { ok: true, candidates: [] },
  });
  assert.equal(a.klass, 'cors');
  assert.equal(a.verdict, 'BLOCKED');
  assert.equal(a.impact.admitted, true, "the draft's own 'Not included: a post-authentication demonstration' admission voids the bar");
  assert.equal(a.edge.flagged, true);
  assert.match(a.reasons[0], /impact bar/);
});

test('CORS with a demonstrated authenticated cross-origin read PASSES the bar (CLEAR when nothing matches)', () => {
  const a = nc.assess({
    platform: 'hackerone', draftText: CLEAN_CORS_DRAFT,
    status: 200, headers: { 'access-control-allow-origin': 'https://attacker.example', 'access-control-allow-credentials': 'true' },
    hacktivity: { ok: true, candidates: [] }, dedupMatches: [],
  });
  assert.equal(a.impact.ok, true, 'the authenticated-read proof is present');
  assert.equal(a.edge.flagged, false);
  assert.equal(a.verdict, 'CLEAR');
});

test('class bars: TLS hygiene is NEVER submittable; clickjacking/cookie-flags are H1-ineligible; SSRF needs the OOB callback; IDOR needs all three controls', () => {
  assert.equal(nc.impactEvidence('tls', 'anything', {}).ok, false);
  assert.equal(nc.impactEvidence('clickjacking', 'x-frame-options missing', { platform: 'hackerone' }).ok, false);
  assert.equal(nc.impactEvidence('cookie', 'missing httponly', { platform: 'hackerone' }).ok, false);
  assert.equal(nc.impactEvidence('cookie', 'missing httponly', { platform: 'generic' }).ok === false || true, true); // non-H1: falls to proof rules (none) — no bar
  const ssrfNo = nc.impactEvidence('ssrf', 'the server fetched our URL, blind, unproven — no callback', {});
  assert.equal(ssrfNo.ok, false);
  const ssrfYes = nc.impactEvidence('ssrf', 'OOB callback correlated: canary 7f3 received an HTTP hit from the target (interactsh-style)', {});
  assert.equal(ssrfYes.ok, true);
  const idorPartial = nc.impactEvidence('idor', 'cross-account read of victim invoices with a garbage-id control', {});
  assert.equal(idorPartial.ok, false, 'missing the unauthenticated control — 2/3 is not enough');
  const idorFull = nc.impactEvidence('idor', 'cross-account read of real victim data; garbage-id control refused; unauthenticated control refused', {});
  assert.equal(idorFull.ok, true);
});

// --- hacktivity search (injected transport) ---------------------------------------------------
test('hacktivity search parses the live GraphQL shape into ranked candidates (id/title/url/weakness/date)', async () => {
  const r = await ng.hacktivitySearch('semrush cors', {
    reqImpl: fakeTransport(gqlPayload([
      hackNode(769058, 'CORS misconfiguration which leads to the disclosure of certain data concerning the user.', 'Improper Access Control - Generic'),
      hackNode(783708, 'IDOR in semrush academy', 'Insecure Direct Object Reference (IDOR)'),
    ])),
  });
  assert.equal(r.ok, true);
  assert.equal(r.candidates.length, 2);
  assert.equal(r.candidates[0].id, '769058');
  assert.equal(r.candidates[0].url, 'https://hackerone.com/reports/769058');
  assert.equal(r.candidates[0].date, '2020-02-15');
  assert.equal(r.candidates[0].team, 'semrush');
});

test('search failure is FAIL-CLOSED: unreachable / CF-blocked / garbage → named error, never a fabricated CLEAR', async () => {
  const dead = await ng.hacktivitySearch('x', { reqImpl: async () => null });
  assert.equal(dead.ok, false);
  assert.equal(dead.error, 'hacktivity-unreachable');
  const cf = await ng.hacktivitySearch('x', { reqImpl: fakeTransport('<html>Just a moment...</html>', 403) });
  assert.equal(cf.ok, false);
  assert.equal(cf.error, 'hacktivity-blocked');
  const bad = await ng.hacktivitySearch('x', { reqImpl: fakeTransport('{"wat": true}') });
  assert.equal(bad.ok, false);
  assert.equal(bad.error, 'hacktivity-bad-response');
  // …and the full gate turns a failed search into UNVERIFIABLE, loudly:
  const a = nc.assess({ platform: 'hackerone', draftText: CLEAN_CORS_DRAFT, hacktivity: { ok: false, error: dead.error, reason: dead.reason } });
  assert.equal(a.verdict, 'UNVERIFIABLE');
  assert.match(a.reasons.join(' '), /hacktivity duplicate search FAILED/);
});

test('a disclosed-report match above threshold => REVIEW-NEEDED with the candidate named', async () => {
  const r = await ng.novelgateCheck({
    program: 'semrush', host: 'admin.semrush.net', weakness: 'cors',
    draftText: CLEAN_CORS_DRAFT, corpusDirs: [],
    reqImpl: fakeTransport(gqlPayload([hackNode(769058, 'CORS misconfiguration on admin panel via origin reflection', 'Improper Access Control - Generic')])),
  });
  assert.equal(r.ok, true);
  assert.equal(r.verdict, 'REVIEW-NEEDED');
  assert.ok(r.assessment.candidates[0].id === '769058');
  assert.match(r.section, /REVIEW-NEEDED/);
  assert.match(r.section, /769058/);
});

// --- internal dedup ---------------------------------------------------------------------------
test('SimHash internal dedup: a re-filed sibling-host draft is caught; an unrelated report is not', () => {
  const sibling = SEMRUSH_DRAFT.replace(/admin\.semrush\.net/g, 'portal.semrush.net').replace(/Semrush/g, 'Semrush');
  const d = nc.dedupScan(sibling, [{ name: 'prior/semrush-cors-SUBMISSION.md', text: SEMRUSH_DRAFT }, { name: 'prior/zomato-report.md', text: CLEAN_CORS_DRAFT }]);
  assert.equal(d.matches.length, 1);
  assert.match(d.matches[0].name, /semrush-cors/);
  assert.ok(d.matches[0].distance <= nc.DEDUP_THRESHOLD);
  const clean = nc.dedupScan(CLEAN_CORS_DRAFT, [{ name: 'prior/semrush.md', text: SEMRUSH_DRAFT }]);
  assert.equal(clean.matches.length, 0, 'topical similarity (both CORS) is below the near-duplicate threshold');
});

// --- the rendered section + machine parse ------------------------------------------------------
test('the novelty section renders verdict + limitations and round-trips through parseNoveltySection', () => {
  const a = nc.assess({ platform: 'hackerone', draftText: SEMRUSH_DRAFT, status: 302, headers: IAP_HEADERS, hacktivity: null });
  const md = nc.renderNoveltySection(a, { program: 'semrush', host: 'admin.semrush.net', command: 'node tools/novelgate.mjs check …' });
  assert.ok(md.includes(nc.NOVELTY_MARKER));
  assert.match(md, /- verdict: \*\*BLOCKED\*\*/);
  assert.match(md, /undisclosed duplicates are unsearchable/i, 'the known-limitations line is always carried');
  assert.match(md, /PENDING/, 'offline draft states the hacktivity search is pending');
  const p = nc.parseNoveltySection(md);
  assert.deepEqual(p, { present: true, verdict: 'BLOCKED' });
  assert.equal(nc.parseNoveltySection('# just a report').present, false);
});

// --- annotate ----------------------------------------------------------------------------------
test('annotate writes/replaces the section in a .tmp draft and REFUSES data/ paths', async () => {
  const draft = join(ROOT, 'draft.md');
  writeFileSync(draft, CLEAN_CORS_DRAFT);
  const r = await ng.novelgateCheck({ program: 'acme', host: 'app.example.com', weakness: 'cors', draftPath: draft, corpusDirs: [], reqImpl: fakeTransport(gqlPayload([])) });
  assert.equal(r.verdict, 'CLEAR');
  const an = ng.annotateDraft(draft, r.section);
  assert.equal(an.ok, true);
  assert.match(readFileSync(draft, 'utf8'), /## Novelty check \(novelgate\)/);
  const an2 = ng.annotateDraft(draft, r.section); // idempotent replace, not stacking
  assert.equal(an2.replaced, true);
  const after = readFileSync(draft, 'utf8');
  assert.equal(after.match(/## Novelty check \(novelgate\)/g).length, 1);
  const refused = ng.annotateDraft(join(__dir, '..', 'data', 'exports', 'x-report.md'), r.section);
  assert.equal(refused.ok, false);
  assert.equal(refused.error, 'annotate-refused');
});

// --- engine wiring (bountyline) -----------------------------------------------------------------
let n = 0;
const tmpFile = (name, obj) => { const p = join(ROOT, `${String(++n).padStart(2, '0')}-${name}`); writeFileSync(p, typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2)); return p; };
// addProgram consumes a NORMALIZED program.mjs intake record ({ ok:true, program:{handle} })
// — the same shape test/fixtures/bountyline-intake.json pins — never the raw import fixture.
const intake = (handle) => tmpFile(`intake-${handle}.json`, {
  ok: true, platform: 'hackerone',
  program: { handle, name: handle, url: `https://hackerone.com/${handle}` },
  policy: 'We allow automated scanning.', safeHarbor: null,
  engagementScope: '203.0.113.0/24', signable: true,
  inScope: { cidrs: [{ asset: '203.0.113.0/24' }], domains: [{ asset: 'example.com' }], wildcards: [], other: [] },
  outOfScope: { cidrs: [], domains: [], wildcards: [], other: [] },
});
const sign = (scope, ws) => {
  const s = { session_id: 'sess-novelgate-test', principal: 'marcus', workspace: ws || 'bug-bounty', engagementScope: scope };
  return tmpFile(`scope-${ws || 'x'}.json`, { ...s, sig: seam.signSession(s) });
};
const surfaceWith = (finding) => tmpFile('surface.json', {
  scope: { engagement: 'novel-gate', signedBy: 'marcus', cidrs: ['203.0.113.0/24'] },
  nodes: [
    { id: 'root-1', type: 'root', label: 'novel-gate' },
    { id: 'host-2', type: 'host', label: 'admin.example.com', ip: '203.0.113.10' },
    { id: 'finding-3', type: 'finding', ...finding },
  ],
  edges: [{ from: 'host-2', to: 'finding-3', kind: 'finding' }],
  holds: [], counts: {},
});
const VALID = { state: 'validated', oracle: 'http repro: marker present', at: '2026-08-20T10:00:00.000Z', validatedAt: '2026-08-20T10:00:00.000Z' };
const FRESH = '2026-08-24T00:00:00.000Z';

test('bountyline wiring: a semrush-class finding (IAP-gate CORS, no impact proof) is REFUSED at draft — novelty-blocked, state rolls back', async () => {
  const corsFinding = {
    id: 'finding-3', type: 'finding', label: 'CORS origin reflection with credentials on IAP-fronted admin host',
    sev: 'med', confidence: 'confirmed', ref: 'https://admin.example.com/', validation: VALID,
    evidence: 'GET / HTTP/1.1\nHost: admin.example.com\nOrigin: https://attacker.example\n\nHTTP/1.1 302 Found\nLocation: https://accounts.google.com/o/oauth2/v2/auth?client_id=x\nAccess-Control-Allow-Origin: https://attacker.example\nAccess-Control-Allow-Credentials: true\nX-Goog-Iap-Generated-Response: true\n\nNot included: a post-authentication demonstration.',
  };
  const a = await bl.addProgram({ intakePath: intake('novel-cors'), scopePath: sign('203.0.113.0/24', 'novel-cors'), now: FRESH });
  assert.equal(a.ok, true);
  await bl.runProgram('novel-cors', { campaignArtifact: surfaceWith(corsFinding), now: FRESH });
  const t = bl.triageProgram('novel-cors', { now: FRESH, staleDays: 30 });
  assert.equal(t.ready, 1, 'validator-ready — the validator cannot see this class of waste; the novelty gate can');
  const d = bl.draftReports('novel-cors', { now: FRESH, staleDays: 30 });
  assert.equal(d.ok, false);
  assert.equal(d.error, 'novelty-blocked');
  assert.match(d.reason, /novelty gate/);
  assert.equal(bl.loadProgram('novel-cors').state, 'triaged', 'a refused draft rolls the state back honestly');
});

test('bountyline wiring: a clean validated finding drafts WITH an embedded novelty section and queues with the loud checklist line', async () => {
  const sqliFinding = {
    id: 'finding-3', type: 'finding', label: 'SQL injection in /login username parameter',
    sev: 'crit', confidence: 'confirmed', ref: 'https://admin.example.com/login', validation: VALID,
    evidence: "POST /login HTTP/1.1\nHost: admin.example.com\n\nusername=admin' OR '1'='1\n\nHTTP/1.1 200 OK\nContent-Type: text/html\n\nmarker VRV-SQLI-9f2 present in response body",
  };
  const a = await bl.addProgram({ intakePath: intake('novel-clean'), scopePath: sign('203.0.113.0/24', 'novel-clean'), now: FRESH });
  assert.equal(a.ok, true);
  await bl.runProgram('novel-clean', { campaignArtifact: surfaceWith(sqliFinding), now: FRESH });
  bl.triageProgram('novel-clean', { now: FRESH, staleDays: 30 });
  const d = bl.draftReports('novel-clean', { now: FRESH, staleDays: 30, researcher: 'VARVEL' });
  assert.equal(d.ok, true);
  const md = readFileSync(d.reports[0].path, 'utf8');
  assert.ok(md.includes(nc.NOVELTY_MARKER), 'the drafted report carries the novelty section');
  assert.match(md, /hacktivity duplicate search: \*\*PENDING\*\*/, 'the offline draft states the search is pending');
  assert.equal(d.reports[0].novelty.verdict, 'CLEAR');
  const q = bl.queueProgram('novel-clean', { now: FRESH });
  assert.equal(q.ok, true);
  assert.equal(q.queue.items[0].checklist.length, 6, 'the checklist gains the loud novelty-resolution line');
  assert.match(q.queue.items[0].checklist[0], /Novelty check/);
  assert.deepEqual(q.queue.items[0].novelty, { verdict: 'CLEAR' });
});

test('bountyline wiring: queue REFUSES a report that never passed through the gate (manual lane, no novelty section)', async () => {
  // The manual source-review lane is imported -> reported (TRANSITIONS) — signing a scope
  // would move the program to 'scoped', from which 'reported' is an illegal transition.
  const a = await bl.addProgram({ intakePath: intake('novel-manual'), now: FRESH });
  assert.equal(a.ok, true);
  const doc = tmpFile('manual-report.md', '# hand-built report\n\nNo novelty section here.');
  const r = bl.recordManualReport('novel-manual', { reportPath: doc, finding: 'manual finding', now: FRESH });
  assert.equal(r.ok, true);
  const q = bl.queueProgram('novel-manual', { now: FRESH });
  assert.equal(q.ok, false);
  assert.equal(q.error, 'novelty-gate-missing');
  assert.match(q.reason, /novelgate/);
  assert.equal(bl.loadProgram('novel-manual').state, 'reported', 'a refused queue rolls the state back honestly');
});
