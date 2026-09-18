// VARVEL validator-gate v2 tests — the manhuaus doctrine, platformized:
//   (a) every reproduction falsifies its own success signature with a GARBAGE-CONTROL
//       read (hollow '200 + empty body for everything' servers are REFUTED, not believed);
//   (b) markers are collision-proof vrv tokens, asserted ONLY where the payload placed
//       them (the request-URL echo in an error page is not placement).
// Hermetic: loopback mock servers on 127.0.0.1 (ephemeral ports) + injected reRead for
// the truth table. No external network.
//   node --test varvel/test/validator-v2.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { Campaign } from '../engine/campaign.mjs';
import { Surface, CONFIRM_AT } from '../engine/surface.mjs';
import {
  validatorMarker, markerPlaced, controlUrl, oracleClass, planValidation,
  isStale, renderValidationState, annotateValidation,
  HOLLOW_REASON, REPRO_REASON,
} from '../engine/validator.mjs';
import { renderReport } from '../engine/report.mjs';
import { Settings } from '../engine/settings.mjs';

const scope = (e) => ({ engagement: e, signedBy: 'x', cidrs: ['127.0.0.0/8'] });
const noAgent = async () => ({ text: '', steps: 0 });
const DAY = 86400000;

// A hermetic mock target on loopback. seen[] records every request (and body served), so
// tests can prove BOTH reads fired and what each proved.
function mockServer(handler) {
  const seen = [];
  const srv = http.createServer((req, res) => {
    const respond = (status, body = '', headers = {}) => { seen.push({ url: req.url, status, body }); res.writeHead(status, headers); res.end(body); };
    handler(req, res, respond);
  });
  return new Promise((resolve) => srv.listen(0, '127.0.0.1', () => resolve({ srv, seen, base: `http://127.0.0.1:${srv.address().port}` })));
}

// A campaign with one loopback http host + one finding, ready for validateFinding.
function seededAt(base, finding, { eng = 'VALV2' } = {}) {
  const port = Number(base.split(':').pop());
  const c = new Campaign({ engine: {}, scope: scope(eng), runAgent: noAgent });
  const hid = c.surface.host('127.0.0.1', { label: 'web' });
  c.surface.service(hid, port, 'tcp', 'http');
  const fid = c.surface.finding(hid, { title: 'finding', sev: 'high', confidence: 'confirmed', ...finding });
  return { c, fid, node: c.surface.nodes.get(fid) };
}

/* ---------- units: marker scheme, placement assertion, control shapes, class pick ----- */

test('v2 validatorMarker: vrv + crypto-random hex — never a username, never a dictionary word', () => {
  const a = validatorMarker(), b = validatorMarker();
  assert.match(a, /^vrv[0-9a-f]{16}$/);
  assert.match(b, /^vrv[0-9a-f]{16}$/);
  assert.notEqual(a, b, 'two mints never collide');
});

test('v2 markerPlaced: the marker counts only where the payload placed it — the request-URL echo is scrubbed', () => {
  const m = 'vrv0123456789abcdef';
  assert.ok(markerPlaced('<div>you searched: vrv0123456789abcdef</div>', m, '/search?q=x'), 'genuine placement counts');
  assert.ok(!markerPlaced(`<div>Cannot GET /search?q=${m}</div>`, m, `/search?q=${m}`), 'the request-line echo is NOT placement');
  assert.ok(!markerPlaced(`<div>Cannot GET ${encodeURIComponent(`/search?q=${m}`)}</div>`, m, `/search?q=${m}`), 'the encoded echo is scrubbed too');
  assert.ok(markerPlaced(`<div>Cannot GET /search?q=${m}</div><p>reflect: ${m}</p>`, m, `/search?q=${m}`), 'echo + genuine placement still counts');
  assert.ok(!markerPlaced('<div>plain page</div>', m, '/search?q=x'), 'absent is absent');
});

test('v2 controlUrl: param shape swaps every value (keys preserved); path shape swaps the last segment (depth preserved)', () => {
  assert.equal(controlUrl('http://h/item?id=1&x=2', 'vrvGARBAGE01'), 'http://h/item?id=vrvGARBAGE01&x=vrvGARBAGE01');
  assert.equal(controlUrl('http://h/admin', 'vrvGARBAGE01', { shape: 'path' }), 'http://h/admin/vrvGARBAGE01'.replace('/admin/vrv', '/vrv'), 'queryless path: last segment');
  assert.equal(controlUrl('http://h/a/b/c', 'vrvGARBAGE01', { shape: 'path' }), 'http://h/a/b/vrvGARBAGE01', 'depth preserved');
  assert.equal(controlUrl('http://h/backup/db.sql?x=1', 'vrvGARBAGE01', { shape: 'path' }), 'http://h/backup/vrvGARBAGE01?x=1', 'path shape keeps the query');
  assert.equal(controlUrl('not a url', 'x'), null);
});

test('v2 oracleClass: per-class selection over the finding text; unknown lands on default', () => {
  assert.equal(oracleClass({ label: 'reflected XSS in search' }), 'xss');
  assert.equal(oracleClass({ label: 'SQL injection in id param' }), 'sqli');
  assert.equal(oracleClass({ label: 'LFI: path traversal in f param' }), 'lfi');
  assert.equal(oracleClass({ label: 'open redirect via next param' }), 'redirect');
  assert.equal(oracleClass({ label: 'session cookie missing HttpOnly flag' }), 'cookie');
  assert.equal(oracleClass({ label: 'missing X-Frame-Options header on admin' }), 'header');
  assert.equal(oracleClass({ label: 'exposed .git directory' }), 'exposure');
  assert.equal(oracleClass({ label: 'weak ssh password' }), 'default');
  // an unplannable class-specific probe falls back to the default oracle, never to nothing
  const p = planValidation({ label: 'missing security header', evidence: 'GET /admin returned 200' }, 'http://h/admin');
  assert.equal(p.class, 'default');
  assert.equal(planValidation({ label: 'missing X-Frame-Options header', evidence: 'no X-Frame-Options' }, 'http://h/admin').class, 'header');
});

/* ---------- THE lesson: hollow success vs genuine differential (loopback servers) ----- */

test('v2 HOLLOW SUCCESS: identical 200+empty for the real path AND garbage -> refuted with the named reason (the manhuaus lesson)', async (t) => {
  const { srv, seen, base } = await mockServer((req, res, respond) => respond(200, '')); // same for EVERYTHING
  t.after(() => srv.close());
  const { c, node } = seededAt(base, { title: 'exposed admin panel', ref: `${base}/admin`, evidence: 'GET /admin returned the console' });
  const r = await c.validateFinding(0); // REAL reRead over loopback
  assert.equal(r.state, 'refuted');
  assert.equal(r.reason, HOLLOW_REASON);
  assert.match(r.oracle, /hollow success signature \(control matched\)/);
  assert.equal(node.validation.state, 'refuted');
  assert.equal(node.confidence, 'suspected', 'a hollow claim flips back to suspected');
  assert.ok(node.conf < CONFIRM_AT);
  assert.equal(node.validation.control.matched, true, 'the control matched — that is the hollowness');
  assert.equal(node.validation.requests.length, 2, 'the record shows both requests');
  assert.equal(seen.length, 2, 'exactly one pair left the wire');
  assert.equal(seen[0].url, '/admin', 'the real read first');
  assert.match(seen[1].url, /^\/vrv[0-9a-f]{16}$/, 'then the garbage control of the same shape');
  assert.ok((node.notes || []).some((n) => /validator gate: refuted/.test(n)));
});

test('v2 hollow CACHED marker: a body that always carries the cited marker matches under control too -> refuted', async (t) => {
  const { srv, base } = await mockServer((req, res, respond) => respond(200, `<html>console vv-q7x9deadbeef</html>`));
  t.after(() => srv.close());
  const { c } = seededAt(base, { title: 'exposed admin panel', ref: `${base}/admin`, evidence: 'GET /admin returned the console; marker: vv-q7x9deadbeef' }, { eng: 'VALHC' });
  const r = await c.validateFinding(0);
  assert.equal(r.state, 'refuted');
  assert.equal(r.reason, HOLLOW_REASON, 'a marker that garbage also returns proves nothing');
});

test('v2 GENUINE DIFFERENTIAL: real matches, garbage control 404s -> validated; pair paced + charged + on record', async (t) => {
  const { srv, seen, base } = await mockServer((req, res, respond) => {
    if (req.url === '/admin') return respond(200, '<html>console</html>');
    respond(404, '');
  });
  t.after(() => srv.close());
  const { c, node } = seededAt(base, { title: 'exposed admin panel', ref: `${base}/admin`, evidence: 'GET /admin returned the console' }, { eng: 'VALGD' });
  let paced = 0;
  c.pacer = { pace: async () => { paced++; } };
  const before = c.noise.status().spent;
  const r = await c.validateFinding(0);
  assert.equal(r.state, 'validated');
  assert.equal(node.validation.class, 'exposure');
  assert.ok(r.validatedAt && node.validation.validatedAt, 'validatedAt set (the staleness clock)');
  assert.equal(node.validation.control.matched, false);
  assert.match(r.control, /^control GET http:\/\/127\.0\.0\.1:\d+\/vrv[0-9a-f]{16} → HTTP 404/, 'the validate output gains the control-read line');
  assert.equal(paced, 2, 'both reads paced');
  assert.ok(c.noise.status().spent > before, 'both reads charged to the same noise budget');
  assert.equal(seen.length, 2);
  assert.ok(c.activity.some((a) => a.kind === 'validate' && a.data.state === 'validated' && /control GET/.test(a.data.control || '')), 'the activity feed carries the control line');
});

/* ---------- collision-proof markers: the URL-echo trap ------------------------------- */

test('v2 collision trap: the page echoes the request URL and carries operator chrome — a naive marker false-positives, a vrv token does not', async (t) => {
  const { srv, seen, base } = await mockServer((req, res, respond) => {
    if (req.url.startsWith('/trap')) return respond(200, `<html><div class="err">Cannot GET ${req.url}</div><div class="chrome">logged in as operator</div></html>`);
    if (req.url.startsWith('/reflect')) {
      const q = new URL(req.url, 'http://x').searchParams.get('q') || '';
      return respond(200, `<html><div>You searched for: ${q}</div></html>`);
    }
    respond(404, '');
  });
  t.after(() => srv.close());

  // The trap: the ONLY place the marker lands is the echoed request line, and the chrome
  // carries the operator's username (the v1 collision). body.includes(marker) fires here.
  const trap = seededAt(base, { title: 'reflected XSS in search', ref: `${base}/trap?q=test`, evidence: 'GET /trap?q=test reflected the payload in the page' }, { eng: 'VALTRAP' });
  const r1 = await trap.c.validateFinding(0);
  const plantedQ = new URL(seen[0].url, 'http://x').searchParams.get('q');
  assert.match(plantedQ, /^vrv[0-9a-f]{16}$/, 'the planted marker is a vrv token — never a username');
  assert.ok(seen[0].body.includes(plantedQ), 'trap armed: the response DOES echo the marker (v1 would false-positive)');
  assert.ok(seen[0].body.includes('operator'), 'trap armed: operator chrome is present in the page');
  assert.equal(r1.state, 'refuted', 'the URL echo is not payload placement — no claim');
  assert.equal(r1.reason, REPRO_REASON);
  assert.equal(trap.node.confidence, 'suspected');

  // The genuine reflector: the marker lands where the payload placed it (outside any URL echo).
  const good = seededAt(base, { title: 'reflected XSS in search', ref: `${base}/reflect?q=test`, evidence: 'GET /reflect?q=test reflected the payload in the page' }, { eng: 'VALREFL' });
  const r2 = await good.c.validateFinding(0);
  assert.equal(r2.state, 'validated');
  assert.equal(good.node.validation.class, 'xss');
  assert.match(good.node.validation.marker, /^vrv[0-9a-f]{16}$/);
  assert.match(r2.oracle, /planted marker present/);
});

/* ---------- per-class oracles over loopback ------------------------------------------- */

test('v2 sqli oracle: SQL error under the quote-breaking payload, clean under garbage -> validated; always-error -> hollow refuted', async (t) => {
  const { srv, base } = await mockServer((req, res, respond) => {
    if (req.url.startsWith('/item') && (req.url.includes('%27') || req.url.includes("'"))) return respond(500, "You have an error in your SQL syntax near ''");
    if (req.url.startsWith('/item')) return respond(200, '<html>item page</html>');
    if (req.url.startsWith('/broken')) return respond(500, 'You have an error in your SQL syntax near garbage'); // errors on EVERYTHING
    respond(404, '');
  });
  t.after(() => srv.close());
  const ok = seededAt(base, { title: 'SQL injection in id param', ref: `${base}/item?id=1%27`, evidence: "GET /item?id=1' returned a SQL syntax error" }, { eng: 'VALSQL' });
  const r1 = await ok.c.validateFinding(0);
  assert.equal(r1.state, 'validated');
  assert.equal(ok.node.validation.class, 'sqli');
  const hollow = seededAt(base, { title: 'SQL injection in id param', ref: `${base}/broken?id=1%27`, evidence: "GET /broken?id=1' returned a SQL syntax error" }, { eng: 'VALSQLH' });
  const r2 = await hollow.c.validateFinding(0);
  assert.equal(r2.state, 'refuted');
  assert.equal(r2.reason, HOLLOW_REASON, 'an app that errors on garbage too proves nothing');
});

test('v2 lfi oracle: file-content token under the traversal, absent under garbage -> validated', async (t) => {
  const { srv, base } = await mockServer((req, res, respond) => {
    if (req.url.startsWith('/read') && req.url.includes('passwd')) return respond(200, 'root:x:0:0:root:/root:/bin/bash\ndaemon:*:1:1');
    respond(404, '');
  });
  t.after(() => srv.close());
  const { c, node } = seededAt(base, { title: 'LFI: path traversal in f param', ref: `${base}/read?f=/etc/passwd`, evidence: 'GET /read?f=/etc/passwd returned root:x:0:0 (local file read)' }, { eng: 'VALLFI' });
  const r = await c.validateFinding(0);
  assert.equal(r.state, 'validated');
  assert.equal(node.validation.class, 'lfi');
  assert.match(r.oracle, /file-content token present/);
});

test('v2 redirect oracle: Location matching the cited destination validates; a fixed redirect (login wall) refutes', async (t) => {
  const { srv, base } = await mockServer((req, res, respond) => {
    if (req.url.startsWith('/go')) {
      const next = new URL(req.url, 'http://x').searchParams.get('next') || '/';
      return respond(302, '', { location: next }); // genuine open redirector
    }
    if (req.url.startsWith('/wall')) return respond(302, '', { location: '/login' }); // fixed redirect
    respond(404, '');
  });
  t.after(() => srv.close());
  const evidence = 'redirects to https://evil.example/cb — the Location header reflects the next param';
  const ok = seededAt(base, { title: 'open redirect via next param', ref: `${base}/go?next=https://evil.example/cb`, evidence }, { eng: 'VALRED' });
  const r1 = await ok.c.validateFinding(0);
  assert.equal(r1.state, 'validated');
  assert.equal(ok.node.validation.class, 'redirect');
  const fixed = seededAt(base, { title: 'open redirect via next param', ref: `${base}/wall?next=https://evil.example/cb`, evidence }, { eng: 'VALRED2' });
  const r2 = await fixed.c.validateFinding(0);
  assert.equal(r2.state, 'refuted');
  assert.equal(r2.reason, REPRO_REASON, 'a fixed redirect never carries the cited destination');
});

test('v2 header oracle: missing-header claim on a live endpoint validates; a catch-all 200 server is hollow', async (t) => {
  const { srv, base } = await mockServer((req, res, respond) => {
    if (req.url.startsWith('/all200')) return respond(200, '<html>catch-all</html>'); // 200 everything under here, no XFO anywhere
    if (req.url === '/admin') return respond(200, '<html>panel</html>'); // no X-Frame-Options
    respond(404, '');
  });
  t.after(() => srv.close());
  const mk = (ref, eng) => seededAt(base, { title: 'missing X-Frame-Options header on admin panel', ref, evidence: 'GET /admin returned 200 with no X-Frame-Options header' }, { eng });
  const ok = mk(`${base}/admin`, 'VALHDR');
  const r1 = await ok.c.validateFinding(0);
  assert.equal(r1.state, 'validated');
  assert.equal(ok.node.validation.class, 'header');
  assert.match(r1.oracle, /x-frame-options absent as claimed/);
  const hollow = mk(`${base}/all200/admin`, 'VALHDR2');
  const r2 = await hollow.c.validateFinding(0);
  assert.equal(r2.state, 'refuted');
  assert.equal(r2.reason, HOLLOW_REASON, 'the garbage path 200s with the same posture — endpoint specificity unproven');
});

test('v2 cookie oracle: Set-Cookie without the cited flag on a live endpoint validates', async (t) => {
  const { srv, base } = await mockServer((req, res, respond) => {
    if (req.url === '/login') return respond(200, '<html>login</html>', { 'set-cookie': 'session=abc123; Path=/' }); // no HttpOnly
    respond(404, '');
  });
  t.after(() => srv.close());
  const { c, node } = seededAt(base, { title: 'session cookie missing HttpOnly flag', ref: `${base}/login`, evidence: 'Set-Cookie: session=abc123 lacks HttpOnly' }, { eng: 'VALCK' });
  const r = await c.validateFinding(0);
  assert.equal(r.state, 'validated');
  assert.equal(node.validation.class, 'cookie');
  assert.match(r.oracle, /set-cookie present without httponly/);
});

/* ---------- the verdict truth table + control failure (injected read) ----------------- */

test('v2 truth table: real x control — hit/miss=validated, hit/hit=hollow-refuted, miss/*=refuted', async () => {
  const realHit = { status: 200, body: 'console vv-deadbeef1234' };
  const realMiss = { status: 200, body: 'plain page' };
  const ctrlHit = { status: 200, body: 'console vv-deadbeef1234' };
  const ctrlMiss = { status: 404, body: '' };
  const mk = () => {
    const c = new Campaign({ engine: {}, scope: { engagement: 'VALTT', signedBy: 'x', cidrs: ['10.0.0.0/8'] }, runAgent: noAgent });
    const hid = c.surface.host('10.0.0.5', { label: 'web' });
    c.surface.service(hid, 8080, 'tcp', 'http');
    c.surface.finding(hid, { title: 'admin panel', sev: 'high', confidence: 'confirmed', ref: 'B2', evidence: 'GET /admin returned the console; marker: vv-deadbeef1234' });
    return c;
  };
  const run = async (real, ctrl) => {
    const c = mk();
    const impl = async (url) => (url.includes('/admin') ? real : ctrl);
    return c.validateFinding(0, { reReadImpl: impl });
  };
  assert.equal((await run(realHit, ctrlMiss)).state, 'validated');
  const hh = await run(realHit, ctrlHit);
  assert.equal(hh.state, 'refuted');
  assert.equal(hh.reason, HOLLOW_REASON);
  const mh = await run(realMiss, ctrlHit);
  assert.equal(mh.state, 'refuted');
  assert.equal(mh.reason, REPRO_REASON);
  assert.match(mh.oracle, /control matched/, 'a control that matched while the real missed is noted honestly');
  assert.equal((await run(realMiss, ctrlMiss)).state, 'refuted');
});

test('v2 no claim without a control: a failed control read is untestable (never a pass, never a refutation)', async () => {
  const c = new Campaign({ engine: {}, scope: { engagement: 'VALCF', signedBy: 'x', cidrs: ['10.0.0.0/8'] }, runAgent: noAgent });
  const hid = c.surface.host('10.0.0.5', { label: 'web' });
  c.surface.service(hid, 8080, 'tcp', 'http');
  const fid = c.surface.finding(hid, { title: 'admin panel', sev: 'high', confidence: 'confirmed', ref: '/admin' });
  const calls = [];
  const impl = async (url) => { calls.push(url); return url.includes('/admin') ? { status: 200, body: 'panel' } : { status: 0, error: 'timeout' }; };
  const r = await c.validateFinding(0, { reReadImpl: impl });
  assert.equal(r.state, 'untestable');
  assert.match(r.oracle, /control read .* failed.*no claim without a control/);
  assert.equal(c.surface.nodes.get(fid).confidence, 'confirmed', 'an untestable is not a refutation');
  assert.equal(calls.length, 2, 'both reads were attempted');
  assert.equal(c.surface.nodes.get(fid).validation.requests.length, 1, 'the record shows the real read that did fire');
});

/* ---------- staleness: 'stale' is a rendering of validated ----------------------------- */

test('v2 staleness boundary (fake clock): exactly TTL is fresh, TTL+1ms is stale, 0 = never, refuted never stale', () => {
  const t0 = Date.parse('2026-07-01T00:00:00Z');
  const v = { state: 'validated', at: new Date(t0).toISOString(), validatedAt: new Date(t0).toISOString() };
  assert.equal(isStale(v, { now: t0 + 30 * DAY, staleDays: 30 }), false, 'exactly TTL-days old is NOT stale yet');
  assert.equal(isStale(v, { now: t0 + 30 * DAY + 1, staleDays: 30 }), true, 'past TTL renders stale');
  assert.equal(isStale(v, { now: t0 + 365 * DAY, staleDays: 0 }), false, 'staleDays 0 = never stale');
  assert.equal(isStale({ state: 'refuted', at: v.at }, { now: t0 + 365 * DAY, staleDays: 30 }), false, 'only validated stales');
  assert.equal(isStale({ state: 'validated', at: v.at }, { now: t0 + 31 * DAY, staleDays: 30 }), true, 'v1 records without validatedAt fall back to at');
  assert.equal(renderValidationState(v, { now: t0 + 31 * DAY, staleDays: 30 }), 'stale');
  assert.equal(renderValidationState(v, { now: t0, staleDays: 30 }), 'validated');
  assert.equal(renderValidationState(null), null);
  assert.equal(Settings.for('VALV2-SETTINGS').get('validator.staleDays'), 30, 'the settings key exists with default 30');
});

test('v2 staleness in the report: STALE renders with revalidation advice + the v2 verdict detail flows through', () => {
  const t0 = Date.parse('2026-07-01T00:00:00Z');
  const mkSurface = () => {
    const s = new Surface(scope('VALSTALE'));
    const h = s.host('10.0.0.5', { label: 'web' });
    const f = s.nodes.get(s.finding(h, { title: 'proven one', sev: 'high', confidence: 'confirmed', evidence: 'GET /x returned it' }));
    f.validation = {
      state: 'validated', oracle: 'exposure oracle: real GET http://10.0.0.5/x → HTTP 200; endpoint responds', at: new Date(t0).toISOString(), validatedAt: new Date(t0).toISOString(),
      class: 'exposure', marker: 'vrv0123456789abcdef',
      control: { url: 'http://10.0.0.5/vrvdeadbeef01234567', status: 404, matched: false, line: 'control GET http://10.0.0.5/vrvdeadbeef01234567 → HTTP 404; endpoint does NOT respond' },
    };
    return s;
  };
  const fresh = renderReport(mkSurface().toJSON(), { now: t0 + 10 * DAY, staleDays: 30 });
  assert.match(fresh, /\*\*VALIDATED\*\* — exposure oracle/, 'fresh validated renders as validated');
  assert.match(fresh, /control GET http:\/\/10\.0\.0\.5\/vrvdeadbeef01234567 → HTTP 404/, 'the control read renders');
  assert.match(fresh, /marker `vrv0123456789abcdef`/, 'the marker renders');
  assert.match(fresh, /validatedAt 2026-07-01/, 'validatedAt renders');
  assert.match(fresh, /1 validated · 0 claimed-unvalidated · 0 refuted · 0 untestable/, 'no stale suffix when nothing is stale');

  const stale = renderReport(mkSurface().toJSON(), { now: t0 + 31 * DAY, staleDays: 30 });
  assert.match(stale, /\*\*STALE\*\* — validated 2026-07-01T00:00:00.000Z, older than the 30-day TTL — revalidation advised/, 'stale is a rendering of validated');
  assert.match(stale, /1 validated \(1 stale\) · 0 claimed-unvalidated/, 'the summary counts stale');

  const never = renderReport(mkSurface().toJSON(), { now: t0 + 365 * DAY, staleDays: 0 });
  assert.match(never, /\*\*VALIDATED\*\*/, 'staleDays 0 = never stale');
  assert.ok(!never.includes('**STALE**'), 'no STALE pill renders when the TTL is disabled');
});

test('v2 console-API annotation: stale + display land on NEW node objects; the stored state is never mutated', () => {
  const t0 = Date.parse('2026-07-01T00:00:00Z');
  const nodes = [
    { id: 'f1', type: 'finding', label: 'a', validation: { state: 'validated', at: new Date(t0).toISOString(), validatedAt: new Date(t0).toISOString() } },
    { id: 'f2', type: 'finding', label: 'b', validation: { state: 'refuted', at: new Date(t0).toISOString() } },
    { id: 'h1', type: 'host', label: 'web' },
  ];
  const out = annotateValidation(nodes, { now: t0 + 31 * DAY, staleDays: 30 });
  assert.equal(out[0].validation.stale, true);
  assert.equal(out[0].validation.display, 'stale');
  assert.equal(out[0].validation.state, 'validated', 'the stored vocabulary is untouched — stale is a rendering');
  assert.equal(out[1].validation.stale, false);
  assert.equal(out[1].validation.display, 'refuted');
  assert.equal(out[2], nodes[2], 'non-findings pass through');
  assert.equal(nodes[0].validation.stale, undefined, 'the live surface object is never mutated');
});
