// statestore.test.mjs — the EXTERNAL STATE STORE: structured, provenance-tracked engagement
// knowledge, selectively injected into the agent's brief. Pins the upsert/dedup contract,
// the briefSlice priority order + hard char budget, and the absolute OPSEC rule: secrets
// NEVER leak into the brief or the /api/statestore wire shape.
//   node --test varvel/test/statestore.test.mjs

import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { mkdtempSync, rmSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { upsert, get, query, stateCounts, addNote, redact, redactState, loadState, briefSlice, REDACTED } from '../engine/statestore.mjs';

// Isolate persistence to this process (parallel test files must not share the dir).
const DATA = mkdtempSync(join(tmpdir(), 'varvel-state-'));
process.env.VARVEL_DATA_DIR = DATA;
const prov = (sourceTool, ts, actor = 'tool') => ({ sourceTool, ts, actor });

test('upsert dedups a host by ip: firstSeen kept, lastSeen bumped, lists union', () => {
  const eng = 'SS-HOST';
  upsert(eng, 'hosts', { ip: '10.0.0.5', label: 'web', services: ['80/http'], tech: ['nginx'] }, prov('recon', '2026-08-01T00:00:00.000Z'));
  const b = upsert(eng, 'hosts', { ip: '10.0.0.5', services: ['443/https', '80/http'], tech: ['php'] }, prov('webscan', '2026-08-02T00:00:00.000Z'));
  assert.equal(query(eng, 'hosts').length, 1, 'same ip = same host');
  assert.equal(b.firstSeen, '2026-08-01T00:00:00.000Z', 'firstSeen preserved from the first sighting');
  assert.equal(b.lastSeen, '2026-08-02T00:00:00.000Z', 'lastSeen bumped to the latest sighting');
  assert.deepEqual(b.services, ['80/http', '443/https'], 'services accumulate across scans');
  assert.deepEqual(b.tech, ['nginx', 'php']);
  assert.equal(b.label, 'web', 'absent fields on update do not erase prior values');
});

test('provenance records the LATEST writer (and every entity carries it)', () => {
  const eng = 'SS-HOST';
  const h = get(eng, 'hosts', '10.0.0.5');
  assert.equal(h.provenance.engagement, eng);
  assert.equal(h.provenance.sourceTool, 'webscan', 'the last writer is of record');
  assert.equal(h.provenance.actor, 'tool');
  assert.equal(h.provenance.ts, '2026-08-02T00:00:00.000Z');
  const c = upsert(eng, 'creds', { kind: 'wp-login', principal: 'admin', secret: 'x', scope: 'https://t/wp-admin' }, prov('lfichain', '2026-08-03T00:00:00.000Z'));
  assert.equal(c.provenance.sourceTool, 'lfichain');
  const c2 = upsert(eng, 'creds', { kind: 'wp-login', principal: 'admin', secret: 'y' }, { actor: 'operator', ts: '2026-08-04T00:00:00.000Z' });
  assert.equal(c2.provenance.actor, 'operator', 'latest writer wins, ai is the default');
  assert.equal(c2.firstSeen, '2026-08-03T00:00:00.000Z');
});

test('cred dedups on kind+principal: a rotation updates in place, one entity survives', () => {
  const eng = 'SS-CRED';
  upsert(eng, 'creds', { kind: 'ssh', principal: 'root', secret: 'old-secret', scope: '10.1.1.1' }, prov('operator', '2026-08-01T00:00:00.000Z', 'operator'));
  const r = upsert(eng, 'creds', { kind: 'ssh', principal: 'root', secret: 'new-secret', scope: '10.1.1.1' }, prov('postex', '2026-08-02T00:00:00.000Z'));
  assert.equal(query(eng, 'creds').length, 1);
  assert.equal(r.secret, 'new-secret', 'the store holds the current secret (reveal is CLI-only)');
  assert.equal(get(eng, 'creds', 'ssh|root').firstSeen, '2026-08-01T00:00:00.000Z');
  assert.equal(get(eng, 'creds', 'ssh|nosuch'), null, 'key lookups are exact');
});

test('finding dedups by ref when present, else by title+host; validation defaults to claimed', () => {
  const eng = 'SS-FIND';
  upsert(eng, 'findings', { title: 'Reflected XSS', sev: 'high', host: 'h1', ref: 'F-01' });
  const b = upsert(eng, 'findings', { title: 'Reflected XSS (renamed)', sev: 'critical', host: 'h1', ref: 'F-01' });
  assert.equal(query(eng, 'findings').length, 1, 'the ref is the identity, not the title');
  assert.equal(b.sev, 'critical');
  assert.equal(b.validation, 'claimed', 'a finding is claimed until the validator gate says otherwise');
  upsert(eng, 'findings', { title: 'LFI', host: 'h1' });
  upsert(eng, 'findings', { title: 'LFI', host: 'h1' });
  upsert(eng, 'findings', { title: 'LFI', host: 'h2' });
  assert.equal(query(eng, 'findings').length, 3, 'no ref => title+host dedups; a distinct host is distinct');
  assert.throws(() => upsert(eng, 'findings', { title: 'bad', validation: 'proven' }), /validation must be one of/, 'off-vocabulary states are refused');
});

test('briefSlice orders tiers: live sessions > creds > validated > claimed > hosts', () => {
  const eng = 'SS-BRIEF';
  upsert(eng, 'hosts', { ip: '10.2.0.5', label: 'web', services: ['443/https'] }, prov('recon', '2026-08-01T00:00:00.000Z'));
  upsert(eng, 'findings', { title: 'Possible LFI at /download', sev: 'medium', host: '10.2.0.5' });
  upsert(eng, 'findings', { title: 'Reflected XSS on /search', sev: 'high', host: '10.2.0.5', validation: 'validated' });
  upsert(eng, 'creds', { kind: 'wp-login', principal: 'admin', secret: 's3cret', scope: 'https://t/wp-admin' }, prov('lfichain', '2026-08-01T00:00:00.000Z'));
  upsert(eng, 'sessions', { kind: 'cf_clearance', subject: 't.example', token: 'tok', egress: 'direct' }, prov('clearance', '2026-08-01T00:00:00.000Z'));
  const out = briefSlice(eng, 5000);
  const ix = (re) => out.search(re);
  assert.ok(ix(/session cf_clearance/) >= 0 && ix(/session cf_clearance/) < ix(/cred wp-login/), 'live sessions first');
  assert.ok(ix(/cred wp-login/) < ix(/\[validated\]/), 'creds before validated findings');
  assert.ok(ix(/\[validated\]/) < ix(/\[claimed\]/), 'validated before claimed');
  assert.ok(ix(/\[claimed\]/) < ix(/host 10\.2\.0\.5/), 'hosts summary last');
  assert.match(out, /\[source:clearance\]/, 'provenance tags ride every line');
  const refuted = upsert(eng, 'findings', { title: 'Disproven SQLi', host: '10.2.0.5', validation: 'refuted' });
  assert.ok(!briefSlice(eng, 5000).includes(refuted.title), 'refuted findings stay OUT of the brief (the gate is the point)');
});

test('briefSlice hard-stops at the char budget and names the omitted tier in the trailer', () => {
  const eng = 'SS-BUDGET';
  for (let i = 0; i < 30; i++) upsert(eng, 'hosts', { ip: `10.3.0.${i}`, services: ['80/http'] }, prov('recon', `2026-08-01T00:00:${String(i).padStart(2, '0')}.000Z`));
  const out = briefSlice(eng, 300);
  assert.ok(out.length <= 300, `hard stop: ${out.length} <= 300`);
  const m = out.match(/\+(\d+) more \(use: state hosts\)$/);
  assert.ok(m, 'trailer counts the omitted and points at `state hosts`');
  const shown = (out.match(/\n/g) || []).length; // lines before the trailer
  assert.equal(Number(m[1]), 30 - shown, 'the trailer count is exact');
  assert.equal(briefSlice(eng, 0), '', 'a zero budget yields nothing, never a throw');
});

test('OPSEC: secrets never leak into the brief; redact() is the only external shape', () => {
  const eng = 'SS-OPSEC';
  upsert(eng, 'creds', { kind: 'wp-login', principal: 'admin', secret: 'hunter2-SUPERSECRET', scope: 'https://t/wp-admin' }, prov('lfichain', '2026-08-01T00:00:00.000Z'));
  upsert(eng, 'sessions', { kind: 'cf_clearance', subject: 't.example', token: 'tok-TOPSECRET', egress: 'direct' }, prov('clearance', '2026-08-01T00:00:00.000Z'));
  const brief = briefSlice(eng, 5000);
  assert.ok(!brief.includes('hunter2-SUPERSECRET') && !brief.includes('tok-TOPSECRET'), 'no secret material in the brief');
  assert.match(brief, /cred wp-login\/admin \(scope: https:\/\/t\/wp-admin\)/, 'cred META still shows');
  assert.match(brief, /--reveal/, 'the brief says where a secret can be lawfully retrieved');
  const rc = redact(get(eng, 'creds', 'wp-login|admin'));
  assert.equal(rc.secret, REDACTED);
  assert.equal(rc.principal, 'admin', 'redaction blanks the secret, not the entity');
  const wire = JSON.stringify(redactState(loadState(eng)));
  assert.ok(!wire.includes('hunter2-SUPERSECRET') && !wire.includes('tok-TOPSECRET'), 'the API shape carries no secrets');
  assert.ok(wire.includes(REDACTED), 'withholding is visible, not silent');
});

test('query filters: field-equality objects and predicates', () => {
  const eng = 'SS-QUERY';
  upsert(eng, 'findings', { title: 'A', sev: 'high', host: 'h1', validation: 'validated' });
  upsert(eng, 'findings', { title: 'B', sev: 'low', host: 'h1' });
  upsert(eng, 'findings', { title: 'C', sev: 'medium', host: 'h2' });
  assert.equal(query(eng, 'findings', { validation: 'validated' }).length, 1);
  assert.equal(query(eng, 'findings', { validation: 'claimed' }).length, 2, 'the default state is queryable');
  assert.equal(query(eng, 'findings', (f) => f.sev === 'medium' && f.host === 'h2').length, 1);
  assert.equal(query(eng, 'findings').length, 3, 'no filter returns the collection');
  assert.throws(() => query(eng, 'passwords'), /unknown state kind/, 'unknown kinds are refused, not silently empty');
});

test('an untouched engagement reads honestly empty', () => {
  const eng = 'SS-EMPTY';
  assert.equal(briefSlice(eng, 1200), '', 'empty slice => the server injects no STATE section');
  assert.deepEqual(stateCounts(eng), { hosts: 0, creds: 0, sessions: 0, findings: 0, notes: 0 });
  assert.deepEqual(query(eng, 'hosts'), []);
  assert.equal(get(eng, 'creds', 'x|y'), null);
  assert.equal(loadState(eng), null);
  assert.equal(redactState(null), null, 'redactState tolerates the empty case');
});

test('dead or expired sessions leave the live tier; live ones stay', () => {
  const eng = 'SS-SESS';
  upsert(eng, 'sessions', { kind: 'agent', subject: 'box-dead', alive: false }, prov('postex', '2026-08-01T00:00:00.000Z'));
  upsert(eng, 'sessions', { kind: 'wp-session', subject: 'box-expired', expiresAt: '2020-01-01T00:00:00.000Z' }, prov('sessride', '2026-08-01T00:01:00.000Z'));
  upsert(eng, 'sessions', { kind: 'cf_clearance', subject: 'box-live', expiresAt: '2099-01-01T00:00:00.000Z' }, prov('clearance', '2026-08-01T00:02:00.000Z'));
  const out = briefSlice(eng, 5000);
  assert.match(out, /box-live/);
  assert.ok(!out.includes('box-dead') && !out.includes('box-expired'), 'only LIVE sessions are briefed');
  assert.equal(query(eng, 'sessions').length, 3, 'dead sessions stay queryable — the store forgets nothing');
});

test('operator notes append, bounded and counted', () => {
  const eng = 'SS-NOTE';
  addNote(eng, 'scope widened to /24 by the operator', { sourceTool: 'cli' });
  addNote(eng, 'second note');
  assert.equal(stateCounts(eng).notes, 2);
  const st = loadState(eng);
  assert.equal(st.notes[0].provenance.actor, 'operator', 'notes default to the operator actor');
  assert.match(st.notes[0].text, /scope widened/);
  assert.ok(!briefSlice(eng, 5000).includes('scope widened'), 'notes are not a brief tier');
});

// The API shape, over the REAL server (house pattern: flowscore/agentsig/selfview boot
// server.mjs on a dedicated test port). Proves the wire carries the REDACTED store only.
test('GET /api/statestore answers the engagement state REDACTED (secret never on the wire)', async () => {
  const eng = 'SS-API';
  upsert(eng, 'creds', { kind: 'ssh', principal: 'root', secret: 'ssh-secret-NEVERWIRE', scope: '10.9.9.9' }, prov('postex', '2026-08-01T00:00:00.000Z'));
  upsert(eng, 'findings', { title: 'Validated XSS', sev: 'high', host: '10.9.9.9', validation: 'validated' });
  const serverFile = join(dirname(fileURLToPath(import.meta.url)), '..', 'server.mjs');
  const port = 39221;
  const proc = spawn(process.execPath, [serverFile], {
    env: { ...process.env, VARVEL_PORT: String(port), VARVEL_DEMO_PORT: '39222', VARVEL_HARD_PORT: '39223' },
    stdio: ['ignore', 'pipe', 'ignore'],
  });
  try {
    await new Promise((resolve, reject) => {
      const to = setTimeout(() => reject(new Error('server.mjs did not report listening within 25s')), 25000);
      let buf = '';
      proc.stdout.on('data', (d) => {
        buf += d;
        if (buf.includes('VARVEL service on')) { clearTimeout(to); resolve(); }
      });
      proc.on('exit', () => reject(new Error('server.mjs exited before listening: ' + buf.slice(0, 200))));
    });
    // retry briefly: the log line precedes the demo-target boot, give routes a moment
    let r = null;
    for (let i = 0; i < 20; i++) {
      try {
        r = await fetch(`http://127.0.0.1:${port}/api/statestore?engagement=${encodeURIComponent(eng)}`);
        if (r.ok) break;
      } catch { await new Promise((x) => setTimeout(x, 250)); }
    }
    assert.ok(r && r.ok, 'route answered');
    const wire = await r.text();
    assert.ok(!wire.includes('ssh-secret-NEVERWIRE'), 'the cred secret never leaves the store over the API');
    assert.ok(wire.includes(REDACTED), 'the withholding mark is on the wire instead');
    const body = JSON.parse(wire);
    assert.equal(body.engagement, eng);
    assert.equal(body.counts.creds, 1);
    assert.equal(body.state.creds[0].principal, 'root', 'cred META is served');
    assert.equal(body.state.creds[0].secret, REDACTED);
    assert.equal(body.state.findings[0].validation, 'validated', 'validation vocabulary survives to the console');
    const e = await (await fetch(`http://127.0.0.1:${port}/api/statestore?engagement=SS-API-EMPTY`)).json();
    assert.equal(e.state, null, 'an untouched engagement is honestly null');
    assert.equal(e.counts.findings, 0);
  } finally { proc.kill(); }
});

// Teardown grace: on win32, --test-force-exit can fire while sockets are still closing
// (libuv UV_HANDLE_CLOSING assert). Same guard as transportfail/dnstransport/flowscore.
test('teardown grace for socket drain (win32 libuv assert guard)', async () => {
  await new Promise((r) => setTimeout(r, 600));
});

after(() => { try { rmSync(DATA, { recursive: true, force: true }); } catch {} });
