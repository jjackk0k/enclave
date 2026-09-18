// VARVEL h1watch tests — the HackerOne opportunity watcher (tools/h1watch.mjs).
// Hermetic: local fixtures + a 127.0.0.1 loopback mock for the thin client layer, zero
// external network. The doctrines under test: the diff engine (first scan = all
// new-program, second = silence, every change class), the fresh-ground ranking, the
// outbox = program.mjs's intake contract (PROVEN by feeding an emitted file through the
// real normalizer), the honesty refusals (no token / 401 / 429 / garbage / unreachable
// — never fabricated data), and the never-signs/never-runs static pin.
//   node --test test/h1watch.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync, readdirSync, existsSync, rmSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { createServer } from 'node:http';

const __dir = dirname(fileURLToPath(import.meta.url));
const CLI = join(__dir, '..', 'tools', 'cli.mjs');
const FIXTURE = (n) => join(__dir, 'fixtures', n);

// Isolate persistence (watcher state + outbox) BEFORE the module is exercised.
const ROOT = mkdtempSync(join(tmpdir(), 'varvel-h1watch-'));
process.env.VARVEL_H1WATCH_DIR = ROOT;

const h1 = await import('../tools/h1watch.mjs');
const { normalizeProgram } = await import('../tools/program.mjs');

const T1 = '2026-08-25T00:00:00.000Z';
const T2 = '2026-08-25T01:00:00.000Z';
const run = (args) => {
  const env = { ...process.env }; // VARVEL_H1WATCH_DIR rides the ambient (CLI tests point it at per-test dirs)
  delete env.VARVEL_H1_TOKEN; delete env.VARVEL_H1_USER; // the offline refusal must not depend on the host env
  const r = spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', timeout: 30000, env });
  const i = r.stdout.lastIndexOf('\n{\n');
  let out = null;
  try { out = JSON.parse(i === -1 ? r.stdout : r.stdout.slice(i + 1)); } catch { out = { parseError: r.stdout.slice(0, 400), stderr: r.stderr.slice(0, 300) }; }
  return { status: r.status, out, text: i === -1 ? '' : r.stdout.slice(0, i) };
};

// --- the readers -------------------------------------------------------------------------

test('readers: JSON:API and plain shapes parse to ONE canonical form; junk lands empty with named gaps', () => {
  const gaps = [];
  const jsonapi = h1.parseDirectory({ data: [{ id: '1', type: 'program', attributes: { handle: 'acme', name: 'Acme', offers_bounties: true } }], links: { next: '/programs?page=2' } }, gaps);
  assert.deepEqual(jsonapi.programs, [{ handle: 'acme', name: 'Acme', offersBounties: true, url: 'https://hackerone.com/acme' }]);
  assert.equal(jsonapi.next, '/programs?page=2');
  const plain = h1.parseDirectory([{ handle: 'globex' }], gaps);
  assert.equal(plain.programs[0].offersBounties, null, 'absent offers_bounties is UNKNOWN, never false-by-assumption');
  const junk = h1.parseDirectory({ nope: true }, gaps);
  assert.deepEqual(junk.programs, []);
  assert.ok(gaps.some((g) => /unrecognized shape/.test(g)));

  const g2 = [];
  const doc = h1.docFromResponses('acme',
    { data: { attributes: { name: 'Acme', policy: 'p', bounty_table: [{ severity: 'critical', bounty: '$1' }] } } },
    { data: [{ attributes: { asset_identifier: 'acme.example', asset_type: 'DOMAIN', eligible_for_submission: true } }] }, g2);
  assert.equal(doc.name, 'Acme');
  assert.equal(doc.structured_scopes.length, 1);
  assert.equal(doc.structured_scopes[0].asset_identifier, 'acme.example');
  // plain + inline fallback (no scopes response at all)
  const inline = h1.docFromResponses('init', { handle: 'init', structured_scopes: [{ asset_identifier: 'init.example', eligible_for_submission: false }] }, undefined, g2);
  assert.equal(inline.structured_scopes[0].eligible_for_submission, false, 'eligible_for_submission:false rides through verbatim');
  // unrecognized scopes shape: EMPTY with a named gap — never guessed
  const weird = h1.docFromResponses('w', null, { wrong: 1 }, g2);
  assert.deepEqual(weird.structured_scopes, []);
  assert.ok(g2.some((g) => /unrecognized shape/.test(g)));
});

// --- the diff engine ----------------------------------------------------------------------

test('diff: first scan = new-program per program, bountied ranked first; second scan = silence', async () => {
  const src = h1.fixtureSource(FIXTURE('h1watch-scan-1.json'));
  const one = await h1.scan({ source: src, now: T1 });
  assert.equal(one.ok, true);
  assert.equal(one.scanned, 2);
  assert.deepEqual(one.events.map((e) => e.type), ['new-program', 'new-program']);
  assert.equal(one.ranked[0].handle, 'acme-watch', 'rank 1: new-program + offers-bounties');
  assert.equal(one.ranked[0].rank, 1);
  assert.equal(one.ranked[1].handle, 'globex-watch');
  assert.equal(one.ranked[1].rank, 4, 'VDP new-program ranks behind bountied');
  assert.deepEqual(one.ranked[0].assets, ['*.api.watch.example.com', '203.0.113.0/24', 'watch.example.com'], 'new-program lists the in-scope assets (sorted)');
  assert.equal(one.ranked[0].automation.policy, 'prohibited', 'policy text says prohibited');
  assert.equal(one.ranked[0].automation.basis, 'policy-text');
  assert.equal(one.doctrine, h1.DOCTRINE, 'the doctrine line rides the output');

  const st = h1.loadState();
  assert.equal(st.programs['acme-watch'].firstSeen, T1);
  assert.equal(st.programs['acme-watch'].lastChanged, T1);
  assert.ok(st.programs['acme-watch'].lastSeenScopeHash.startsWith('sha256:'));

  const two = await h1.scan({ source: h1.fixtureSource(FIXTURE('h1watch-scan-1.json')), now: T2 });
  assert.equal(two.ok, true);
  assert.equal(two.events.length, 0, 'an unchanged snapshot emits NOTHING');
  const st2 = h1.loadState();
  assert.equal(st2.programs['acme-watch'].lastChanged, T1, 'a silent scan never moves lastChanged');
  assert.equal(st2.programs['acme-watch'].lastScan, T2);
  assert.equal(st2.lastScan.events, 0);
});

test('diff: scope-added lists the fresh assets; removal, exclusion-add, policy flip, bounty move all land', async () => {
  const r = await h1.scan({ source: h1.fixtureSource(FIXTURE('h1watch-scan-2.json')), now: T2 });
  assert.equal(r.ok, true);
  assert.equal(r.scanned, 3);
  const byType = (t, side) => r.events.filter((e) => e.type === t && (side === undefined || e.side === side));
  assert.deepEqual(byType('new-program').map((e) => e.handle), ['initech-bounty']);
  const added = byType('scope-added', 'in');
  assert.equal(added.length, 1);
  assert.equal(added[0].handle, 'acme-watch');
  assert.deepEqual(added[0].assets, ['app.watch.example.com'], 'the fresh ground, listed');
  assert.equal(added[0].rank ?? h1.rankEvent(added[0]), 2, 'scope-added on a bountied program ranks 2');
  const removed = byType('scope-removed', 'in');
  assert.deepEqual(removed[0].assets, ['203.0.113.0/24']);
  const exclusion = byType('scope-added', 'out');
  assert.equal(exclusion.length, 1);
  assert.deepEqual(exclusion[0].assets, ['internal.watch.example.com']);
  assert.match(exclusion[0].note, /NEW EXCLUSION/, 'a new exclusion is loud — never hidden by the diff');
  const pol = byType('policy-changed');
  assert.equal(pol.length, 1);
  assert.equal(pol[0].automation.from.policy, 'prohibited');
  assert.equal(pol[0].automation.to.policy, 'human-cadence', 'rate-limit language derives human-cadence — bountyline vocabulary, reused');
  const bounty = byType('bounty-table-changed');
  assert.equal(bounty.length, 1);
  // globex-watch unchanged end to end
  assert.ok(!r.events.some((e) => e.handle === 'globex-watch'), 'an untouched program emits nothing');
  // ranking: new bountied program first, then the bountied scope-add
  assert.equal(r.ranked[0].handle, 'initech-bounty');
  assert.equal(r.ranked[0].rank, 1);
  assert.equal(r.ranked[1].type, 'scope-added');
  assert.equal(r.ranked[1].rank, 2);
  const st = h1.loadState();
  assert.equal(st.programs['acme-watch'].lastChanged, T2);
  assert.equal(st.programs['acme-watch'].automation.policy, 'human-cadence');
  assert.equal(st.programs['globex-watch'].lastChanged, T1, 'unchanged program keeps its lastChanged');
});

test('diffProgram unit: unchanged snapshot is silent; an offers_bounties flip reads bounty-table-changed', () => {
  const gaps = [];
  const docA = h1.docFromResponses('x', { handle: 'x', policy: 'Automated scanning is prohibited.' }, [{ asset_identifier: 'x.example', eligible_for_submission: true }], gaps);
  const snapA = h1.snapshotDoc(docA, { directory: { offersBounties: true } });
  const old = { handle: 'x', scope: { in: snapA.inScope, out: snapA.outScope }, lastSeenScopeHash: snapA.scopeHash, policyHash: snapA.policyHash, bountyHash: snapA.bountyHash, offersBounties: true, automation: snapA.automation };
  assert.deepEqual(h1.diffProgram(old, snapA, { now: T1 }), [], 'identical hashes emit nothing');
  const snapB = { ...snapA, offersBounties: false };
  const evs = h1.diffProgram(old, snapB, { now: T1 });
  assert.equal(evs.length, 1);
  assert.equal(evs[0].type, 'bounty-table-changed');
  assert.deepEqual(evs[0].offersBounties, { from: true, to: false });
});

// --- state / honesty -----------------------------------------------------------------------

test('honesty: a FAILED scope fetch keeps the previous state and records a named error — never an empty scope', async () => {
  const before = h1.loadState().programs['acme-watch'].lastSeenScopeHash;
  const dying = {
    ok: true, gaps: [],
    listPrograms: async () => ({ ok: true, programs: [{ handle: 'acme-watch', name: 'Acme Watch Bounty', offersBounties: true }] }),
    programDoc: async () => ({ ok: false, error: 'h1-unreachable', reason: 'GET https://api.hackerone.com/v1/programs/acme-watch/structured_scopes failed (ECONNREFUSED)' }),
  };
  const r = await h1.scan({ source: dying, now: T2 });
  assert.equal(r.ok, true);
  assert.equal(r.scanned, 0);
  assert.equal(r.events.length, 0);
  assert.equal(r.errors.length, 1);
  assert.equal(r.errors[0].error, 'h1-unreachable');
  const after = h1.loadState();
  assert.equal(after.programs['acme-watch'].lastSeenScopeHash, before, 'state untouched — a failed fetch is not a scope-removal');
  assert.equal(after.lastScan.errors.length, 1);
});

test('offline honesty: live scan without the token env var refuses h1-token-missing BEFORE any fetch', async () => {
  let fetches = 0;
  const spy = async () => { fetches++; throw new Error('must never be called'); };
  const src = h1.liveSource({ env: {}, fetchImpl: spy });
  assert.equal(src.ok, false);
  assert.equal(src.error, 'h1-token-missing');
  assert.match(src.reason, /VARVEL_H1_TOKEN/, 'the refusal names the env var — the NAME, never a value');
  const r = await h1.scan({ source: src });
  assert.equal(r.ok, false);
  assert.equal(r.error, 'h1-token-missing');
  assert.equal(r.doctrine, h1.DOCTRINE);
  assert.equal(fetches, 0, 'no token => no request was ever attempted');
});

test('loopback client: auth header sent, pagination followed, 401/429/garbage/unreachable are named errors', async () => {
  const seen = [];
  const scopeDoc = (h) => ({ data: [{ id: 'a', type: 'structured-scope', attributes: { asset_identifier: h + '.example', asset_type: 'DOMAIN', eligible_for_submission: true, eligible_for_bounty: true } }] });
  const server = createServer((req, res) => {
    seen.push({ url: req.url, auth: req.headers.authorization || null });
    const send = (code, obj) => { res.writeHead(code, { 'content-type': 'application/json' }); res.end(typeof obj === 'string' ? obj : JSON.stringify(obj)); };
    const u = new URL(req.url, 'http://x');
    if (u.pathname === '/v1/hackers/programs' && !u.search.includes('page=2')) return send(200, { data: [{ id: '1', type: 'program', attributes: { handle: 'loop-one', name: 'Loop One', offers_bounties: true } }], links: { next: '/v1/hackers/programs?page=2' } });
    if (u.pathname === '/v1/hackers/programs' && u.search.includes('page=2')) return send(200, { data: [{ id: '2', type: 'program', attributes: { handle: 'loop-two', name: 'Loop Two', offers_bounties: true } }], links: { next: null } });
    if (u.pathname === '/v1/hackers/programs/loop-one') return send(200, { data: { attributes: { handle: 'loop-one', name: 'Loop One', policy: 'Automated scanning is prohibited.' } } });
    if (u.pathname === '/v1/hackers/programs/loop-two') return send(200, { data: { attributes: { handle: 'loop-two', name: 'Loop Two', policy: 'Safe harbor.' } } });
    if (u.pathname === '/v1/hackers/programs/loop-one/structured_scopes') return send(200, scopeDoc('loop-one'));
    if (u.pathname === '/v1/hackers/programs/loop-two/structured_scopes') return send(200, scopeDoc('loop-two'));
    if (u.pathname === '/v1/auth-denied') return send(401, { errors: [{ detail: 'bad credentials' }] });
    if (u.pathname === '/v1/throttled') return send(429, { errors: [{ detail: 'slow down' }] });
    if (u.pathname === '/v1/garbage') return send(200, '<html>not json</html>');
    return send(404, { errors: [{ detail: 'nope' }] });
  });
  await new Promise((res) => server.listen(0, '127.0.0.1', res));
  const base = `http://127.0.0.1:${server.address().port}/v1`;
  try {
    const env = { VARVEL_H1_TOKEN: 'unit-test-token', VARVEL_H1_USER: 'unit-tester' };
    const src = h1.liveSource({ base, env, timeoutMs: 5000 });
    assert.equal(src.ok, true);
    const r = await h1.scan({ source: src, now: T2 });
    assert.equal(r.ok, true);
    assert.equal(r.scanned, 2, 'both pages of the directory were followed');
    assert.deepEqual(r.events.map((e) => e.handle).sort(), ['loop-one', 'loop-two']);
    assert.equal(r.errors.length, 0);
    const wantAuth = 'Basic ' + Buffer.from('unit-tester:unit-test-token').toString('base64');
    assert.ok(seen.length >= 6, `directory x2 + detail x2 + scopes x2 (saw ${seen.length})`);
    assert.ok(seen.every((s) => s.auth === wantAuth), 'every request carried the Basic identifier:token header');
    // named-error mapping through the SAME client
    for (const [path, err] of [['/auth-denied', 'h1-auth'], ['/throttled', 'h1-rate-limited'], ['/garbage', 'h1-bad-response'], ['/missing', 'h1-http-error']]) {
      const e = await h1.h1Get({ url: base + path, auth: 'Basic x', timeoutMs: 5000 });
      assert.equal(e.ok, false);
      assert.equal(e.error, err, `${path} => ${err}`);
      assert.doesNotMatch(e.reason, /unit-test-token/, 'an error reason NEVER carries the token value');
    }
    const dead = await h1.h1Get({ url: 'http://127.0.0.1:1/v1/programs', auth: 'Basic x', timeoutMs: 3000 });
    assert.equal(dead.error, 'h1-unreachable');
  } finally {
    server.close();
  }
});

// --- the intake bridge ---------------------------------------------------------------------

test('emit-intake: every outbox file IS program.mjs intake — proven through the real normalizer', () => {
  const outbox = join(ROOT, 'outbox-test');
  const gaps = [];
  const doc = h1.docFromResponses('acme-watch', JSON.parse(readFileSync(FIXTURE('h1watch-scan-1.json'), 'utf8')).programs['acme-watch'], JSON.parse(readFileSync(FIXTURE('h1watch-scan-1.json'), 'utf8')).scopes['acme-watch'], gaps);
  const snap = h1.snapshotDoc(doc, { directory: { offersBounties: true } });
  const evs = h1.diffProgram(null, snap, { now: T1 });
  const r = h1.emitIntake(evs, { 'acme-watch': snap }, { outboxDir: outbox, now: T1 });
  assert.equal(r.ok, true);
  assert.equal(r.written.length, 1);
  assert.equal(r.note, h1.DOCTRINE, 'the doctrine line rides the outbox result');
  const payload = JSON.parse(readFileSync(r.written[0].file, 'utf8'));
  assert.equal(payload._h1watch.note, h1.DOCTRINE, 'the doctrine line is embedded in every outbox file');
  assert.equal(payload._h1watch.event.type, 'new-program');
  assert.match(payload._h1watch.next, /program import/, 'the file names the operator\'s next step — the watcher never runs it');
  // THE CONTRACT PROOF: the emitted file feeds program.mjs's normalizer verbatim.
  const n = normalizeProgram(payload, { platform: 'hackerone' });
  assert.equal(n.ok, true);
  assert.equal(n.program.handle, 'acme-watch');
  assert.deepEqual(n.inScope.cidrs.map((c) => c.asset), ['203.0.113.0/24']);
  assert.deepEqual(n.inScope.domains.map((d) => d.asset), ['watch.example.com']);
  assert.deepEqual(n.inScope.wildcards.map((w) => w.asset), ['*.api.watch.example.com']);
  assert.deepEqual(n.outOfScope.domains.map((d) => d.asset), ['status.watch.example.com']);
  assert.match(n.policy, /safe harbor/i);
});

// --- the never-signs / never-runs pin --------------------------------------------------------

test('static pin: the watcher imports no signing or pipeline verbs — eyes, never hands', () => {
  const src = readFileSync(join(__dir, '..', 'tools', 'h1watch.mjs'), 'utf8');
  assert.ok(!/from\s*'\.\/program\.mjs'/.test(src), 'no import of program.mjs — the normalizer is fed, never duplicated or driven');
  assert.ok(!/\bsignSession\b|\bsignScope\b/.test(src), 'no signing primitive anywhere in the watcher');
  for (const verb of ['addProgram', 'runProgram', 'queueProgram', 'markOutcome', 'draftReports', 'triageProgram']) {
    assert.ok(!new RegExp('\\b' + verb + '\\s*\\(').test(src), `the watcher never calls bountyline's ${verb}`);
  }
  const blImport = src.match(/import\s*\{([^}]*)\}\s*from\s*'\.\.\/engine\/bountyline\.mjs'/);
  assert.ok(blImport, 'the automation vocabulary IS reused from bountyline');
  assert.equal(blImport[1].trim(), 'deriveAutomation', 'and ONLY deriveAutomation is imported');
});

// --- CLI smoke --------------------------------------------------------------------------------

test('CLI: scan --fixture (all new-program), rescan silent, report ranks, show reads state — doctrine printed throughout', () => {
  const d1 = join(ROOT, 'cli-1'); process.env.VARVEL_H1WATCH_DIR = d1;
  const one = run(['h1watch', 'scan', '--fixture', FIXTURE('h1watch-scan-1.json')]);
  assert.equal(one.status, 0, JSON.stringify(one.out).slice(0, 300));
  assert.equal(one.out.ok, true);
  assert.equal(one.out.events.length, 2);
  assert.match(one.text, new RegExp(h1.DOCTRINE.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')), 'the CLI prints the doctrine line');
  assert.match(one.text, /\[rank 1\] \S+ new-program acme-watch/);

  const two = run(['h1watch', 'scan', '--fixture', FIXTURE('h1watch-scan-1.json')]);
  assert.equal(two.out.events.length, 0, 'second scan over the same fixture is silent');

  const rep = run(['h1watch', 'report']);
  assert.equal(rep.status, 0);
  assert.equal(rep.out.ok, true);
  assert.equal(rep.out.events.length, 0, 'report defaults to the most recent scan (silent)');
  const repAll = run(['h1watch', 'report', '--all']);
  assert.equal(repAll.out.events.length, 2, '--all ranks the recorded ring');
  assert.equal(repAll.out.events[0].rank, 1);

  const show = run(['h1watch', 'show', 'acme-watch']);
  assert.equal(show.out.ok, true);
  assert.equal(show.out.program.handle, 'acme-watch');
  assert.ok(show.out.program.lastSeenScopeHash.startsWith('sha256:'));
  assert.equal(show.out.program.automation.policy, 'prohibited');
  const nope = run(['h1watch', 'show', 'no-such-program']);
  assert.equal(nope.status, 2);
  assert.equal(nope.out.error, 'unknown-program');
  process.env.VARVEL_H1WATCH_DIR = ROOT;
});

test('CLI: scan --emit-intake writes one intake file per event into the outbox', () => {
  const d2 = join(ROOT, 'cli-2');
  const outbox = join(ROOT, 'cli-outbox');
  process.env.VARVEL_H1WATCH_DIR = d2;
  run(['h1watch', 'scan', '--fixture', FIXTURE('h1watch-scan-1.json')]);
  const r = run(['h1watch', 'scan', '--fixture', FIXTURE('h1watch-scan-2.json'), '--emit-intake', '--outbox', outbox]);
  assert.equal(r.status, 0, JSON.stringify(r.out).slice(0, 300));
  assert.equal(r.out.ok, true);
  assert.ok(r.out.events.length >= 5, `diff events present (got ${r.out.events.length})`);
  assert.equal(r.out.outbox.written.length, r.out.events.length, 'ONE intake file per event');
  assert.match(r.text, /outbox:/);
  const files = readdirSync(outbox).filter((f) => f.endsWith('.json'));
  assert.equal(files.length, r.out.events.length);
  assert.ok(files.some((f) => /acme-watch-scope-added-\d/.test(f) || /acme-watch-scope-added-2/.test(f)), 'the scope-added file is named for its event');
  assert.ok(files.some((f) => f.includes('scope-added-exclusion')), 'the exclusion event file is named loudly');
  // every emitted file normalizes through program.mjs
  for (const f of files) {
    const n = normalizeProgram(JSON.parse(readFileSync(join(outbox, f), 'utf8')), { platform: 'hackerone' });
    assert.equal(n.ok, true, `${f} feeds the normalizer`);
  }
  // report right after the diff scan lists ITS events (the pinned scan timestamp — a live
  // run's events and lastScan.at agree exactly, never milliseconds apart)
  const rep = run(['h1watch', 'report']);
  assert.equal(rep.out.events.length, r.out.events.length, 'report defaults to the most recent scan and finds its events');
  assert.equal(rep.out.events[0].rank, 1);
  process.env.VARVEL_H1WATCH_DIR = ROOT;
});

test('CLI: live scan with no token refuses loudly and never touches the network', () => {
  const r = run(['h1watch', 'scan']);
  assert.equal(r.status, 2, 'a named refusal exits nonzero');
  assert.equal(r.out.ok, false);
  assert.equal(r.out.error, 'h1-token-missing');
  assert.match(r.out.reason, /VARVEL_H1_TOKEN/);
  assert.equal(r.out.doctrine, h1.DOCTRINE);
});

// --- the 2026-09-09 stall + liveness regressions -------------------------------------------

test('h1Get: a headers-then-silence body dies at the deadline as h1-timeout (the live wedge)', async () => {
  // The exact live shape: the server sends response HEADERS and never a body.
  const srv = createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.flushHeaders();
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  try {
    const t0 = Date.now();
    const r = await h1.h1Get({ url: `http://127.0.0.1:${srv.address().port}/x`, auth: 'none', timeoutMs: 400 });
    assert.equal(r.ok, false);
    assert.equal(r.error, 'h1-timeout', 'the stall is NAMED, not parked');
    assert.match(r.reason, /whole-operation deadline/);
    assert.ok(Date.now() - t0 < 4000, 'the deadline actually fired');
  } finally {
    srv.close();
  }
});

test('h1Get: an outer abort signal (the loop watchdog) kills an in-flight GET', async () => {
  const srv = createServer(() => { /* never answers */ });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  try {
    const ctl = new AbortController();
    setTimeout(() => ctl.abort(), 300);
    const t0 = Date.now();
    const r = await h1.h1Get({ url: `http://127.0.0.1:${srv.address().port}/x`, auth: 'none', timeoutMs: 30000, signal: ctl.signal });
    assert.equal(r.ok, false);
    assert.equal(r.error, 'h1-timeout');
    assert.ok(Date.now() - t0 < 3000, 'the outer abort won long before the 30s timeout');
  } finally {
    srv.close();
  }
});

test('scan: onProgress fires per program unit; shouldStop stops the walk mid-scan, honestly partial', async () => {
  const dir1 = mkdtempSync(join(tmpdir(), 'varvel-h1w-prog-'));
  process.env.VARVEL_H1WATCH_DIR = dir1;
  const src = h1.fixtureSource(FIXTURE('h1watch-scan-1.json'));
  const progress = [];
  const r = await h1.scan({ source: src, now: T1, onProgress: (p) => progress.push(p) });
  assert.equal(r.ok, true);
  assert.equal(progress.length, 2, 'one progress event per program unit');
  assert.equal(progress[1].scanned, 2);
  assert.equal(progress[1].total, 2);

  const dir2 = mkdtempSync(join(tmpdir(), 'varvel-h1w-stop-'));
  process.env.VARVEL_H1WATCH_DIR = dir2;
  const src2 = h1.fixtureSource(FIXTURE('h1watch-scan-1.json'));
  let calls = 0;
  const r2 = await h1.scan({ source: src2, now: T2, shouldStop: () => { calls += 1; return calls > 1; } });
  assert.equal(r2.ok, true);
  assert.equal(r2.stopped, true, 'the partial scan names itself');
  assert.equal(r2.scanned, 1, 'one program scanned before the stop');
  assert.ok(r2.gaps.some((g) => /STOPPED by the caller/.test(g)));
  process.env.VARVEL_H1WATCH_DIR = ROOT;
});

test('liveSource: a ghost chain in env re-wires the default wire (local targets still direct)', async () => {
  const env = { VARVEL_H1_TOKEN: 'x', VARVEL_GHOST_CHAIN: 'socks5://10.64.0.1:1080' };
  const src = h1.liveSource({ env });
  assert.equal(src.ok, true);
  assert.ok(src.ghost && src.ghost.chain === 'socks5://10.64.0.1:1080', 'the source carries its chain');
  assert.ok(src.gaps.some((g) => /rides the chain, FAIL CLOSED/.test(g)), 'the wire is NAMED in gaps');
  // A chain-armed source still answers a LOCAL mock directly (the carve-out).
  const mock = createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ data: [{ id: '1', type: 'program', attributes: { handle: 'local-mock' } }] }));
  });
  await new Promise((r) => mock.listen(0, '127.0.0.1', r));
  try {
    const local = h1.liveSource({ env, base: `http://127.0.0.1:${mock.address().port}` });
    const listed = await local.listPrograms();
    assert.equal(listed.ok, true, 'the local carve-out answered with the chain armed');
    assert.equal(listed.programs[0].handle, 'local-mock');
  } finally {
    mock.close();
  }
  const noChain = h1.liveSource({ env: { VARVEL_H1_TOKEN: 'x' } });
  // (this box's real settings.json arms chains — the no-chain case pins an EMPTY store)
  const emptySettings = join(mkdtempSync(join(tmpdir(), 'varvel-h1w-noset-')), 'settings.json');
  writeFileSync(emptySettings, '{}');
  process.env.VARVEL_SETTINGS_FILE = emptySettings;
  const noChain2 = h1.liveSource({ env: { VARVEL_H1_TOKEN: 'x' } });
  delete process.env.VARVEL_SETTINGS_FILE;
  void noChain;
  assert.equal(noChain2.ghost, null);
  assert.ok(noChain2.gaps.some((g) => /goes DIRECT/.test(g)), 'no chain = direct, said out loud');
});

// --- the resumable walk (the 2026-09-10 soak fix) ----------------------------------------------

test('walk checkpoint: an aborted walk RESUMES from the unscanned remainder — no re-fetch of fingerprinted units', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'varvel-h1w-walk-'));
  process.env.VARVEL_H1WATCH_DIR = dir;

  // Walk 1: STOP after the first of two units — the checkpoint holds exactly one doc.
  const src1 = h1.fixtureSource(FIXTURE('h1watch-scan-1.json'));
  let calls1 = 0;
  const fetches1 = [];
  const counting1 = { ok: true, gaps: [], listPrograms: src1.listPrograms, programDoc: async (hd) => { fetches1.push(hd); const r = await src1.programDoc(hd); if (++calls1 >= 1) writeStop(); return r; } };
  const stopFile = join(dir, 'WALK-STOP');
  const writeStop = () => writeFileSync(stopFile, 'x');
  const r1 = await h1.scan({ source: counting1, now: T1, shouldStop: () => existsSync(stopFile) });
  assert.equal(r1.stopped, true);
  assert.equal(r1.baseline.complete, false);
  assert.equal(r1.baseline.done, 1);
  assert.equal(fetches1.length, 1);
  assert.equal(r1.events.length, 0, 'a partial walk diffs NOTHING (checkpoint material, never a misleading partial diff)');
  const cp = h1.loadWalkCheckpoint();
  assert.ok(cp && cp.done === 1, 'the checkpoint persisted to disk (restart-safe)');

  // Walk 2 (a NEW scan — the 'process restart' case: state on disk, memory gone):
  // the fingerprinted unit is NOT re-fetched; the walk completes and diffs ONCE.
  rmSync(stopFile, { force: true });
  const src2 = h1.fixtureSource(FIXTURE('h1watch-scan-1.json'));
  const fetches2 = [];
  const counting2 = { ok: true, gaps: [], listPrograms: src2.listPrograms, programDoc: async (hd) => { fetches2.push(hd); return src2.programDoc(hd); } };
  const r2 = await h1.scan({ source: counting2, now: T2 });
  assert.equal(r2.baseline.complete, true);
  assert.equal(r2.resumedFrom, 1, 'one unit came from the checkpoint');
  assert.equal(fetches2.length, 1, 'ONLY the unscanned remainder was fetched');
  assert.deepEqual(fetches2, fetches1[0] === 'acme-watch' ? ['globex-watch'] : ['acme-watch'], 'the OTHER unit was fetched');
  assert.equal(r2.events.length, 2, 'the completed walk diffs the full set exactly once (two new-program events)');
  assert.equal(h1.loadWalkCheckpoint(), null, 'a completed walk clears its checkpoint');

  // Walk 3 (steady state): full re-fetch (change detection needs fresh docs) — zero diff.
  const src3 = h1.fixtureSource(FIXTURE('h1watch-scan-1.json'));
  const fetches3 = [];
  const counting3 = { ok: true, gaps: [], listPrograms: src3.listPrograms, programDoc: async (hd) => { fetches3.push(hd); return src3.programDoc(hd); } };
  const r3 = await h1.scan({ source: counting3, now: '2026-08-25T03:00:00.000Z' });
  assert.equal(fetches3.length, 2, 'a completed walk re-walks everything next time (that IS the change detection)');
  assert.equal(r3.events.length, 0, 'zero diff, honestly');
  process.env.VARVEL_H1WATCH_DIR = ROOT;
});

test('walk checkpoint: a failed unit is marked done-with-error so the walk completes (and is retried next walk)', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'varvel-h1w-walkerr-'));
  process.env.VARVEL_H1WATCH_DIR = dir;
  const src = h1.fixtureSource(FIXTURE('h1watch-scan-1.json'));
  const failing = { ok: true, gaps: [], listPrograms: src.listPrograms,
    programDoc: async (hd) => hd === 'acme-watch' ? { ok: false, error: 'h1-http-error', reason: 'HTTP 500' } : src.programDoc(hd) };
  const r = await h1.scan({ source: failing, now: T1 });
  assert.equal(r.baseline.complete, true, 'the walk completes around the failed unit');
  assert.equal(r.errors.length, 1);
  assert.equal(r.errors[0].handle, 'acme-watch');
  assert.equal(h1.loadWalkCheckpoint(), null);
  const st = h1.loadState();
  assert.ok(st.programs['globex-watch'], 'the good unit fingerprinted');
  assert.ok(!st.programs['acme-watch'], 'the failed unit keeps NO invented state');
  process.env.VARVEL_H1WATCH_DIR = ROOT;
});
