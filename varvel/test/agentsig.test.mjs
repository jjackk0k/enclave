// agentsig.test.mjs - gap#7: the agent-tradecraft oracle tier. Every published
// signature unit-tested (fires on a matching stream, silent on a clean one), the
// fail-closed band, cadence honesty (fired:null without real timestamps, never
// fabricated), preflight/fetchLive error shape, and the /api/channel/tradecraft route
// over a real armed channel. The honesty contract is pinned: insufficient data gets NO
// grade, and everything reported is signature evidence, never a vendor verdict.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeCommandStream } from '../engine/agentsig.mjs';
import { preflight, fetchLive } from '../tools/tradecraft.mjs';

const CLEAN = ['whoami', 'ipconfig', 'net user', 'ver', 'hostname'];
const sig = (r, id) => r.signatures.find((s) => s.id === id);
const series = (gaps) => { const t = [0]; for (const g of gaps) t.push(t[t.length - 1] + g); return t; };

// ---------- fail-closed band ----------
test('fewer than 5 commands -> insufficient-data, score null, no signatures', () => {
  const r = analyzeCommandStream(['whoami', 'ver', 'hostname', 'ipconfig']);
  assert.equal(r.band, 'insufficient-data');
  assert.equal(r.score, null);
  assert.equal(r.signatures, null);
  assert.deepEqual(r.flagged, []);
  assert.match(r.note, /fewer than 5 commands/);
});

// ---------- each signature: fires on a matching stream, silent otherwise ----------
test('separators: delimiter echo fires, with the exact matched text as evidence', () => {
  const r = analyzeCommandStream(['whoami', "echo '---'; ipconfig", 'net user', 'ver', 'hostname']);
  assert.equal(sig(r, 'separators').fired, true);
  assert.match(sig(r, 'separators').evidence, /echo '---'/);
  assert.ok(r.flagged.some((f) => /delimiter echos/.test(f)), JSON.stringify(r.flagged));
  const clean = analyzeCommandStream(CLEAN);
  assert.equal(sig(clean, 'separators').fired, false);
  assert.equal(sig(clean, 'separators').evidence, null);
});

test('bounded captures: 2>&1 piped to head -N fires', () => {
  const r = analyzeCommandStream(['whoami', 'ipconfig', 'net user', 'dir C:\\Users 2>&1 | head -5', 'hostname']);
  assert.equal(sig(r, 'bounded-captures').fired, true);
  assert.match(sig(r, 'bounded-captures').evidence, /2>&1 \| head -5/);
  assert.equal(sig(analyzeCommandStream(CLEAN), 'bounded-captures').fired, false);
});

test('error suppression: fires at a high ratio of 2>/dev/null, silent below it', () => {
  const high = analyzeCommandStream(['whoami 2>/dev/null', 'ipconfig 2>/dev/null', 'net user', 'ver', 'hostname']);
  assert.equal(sig(high, 'error-suppression').fired, true);
  assert.match(sig(high, 'error-suppression').evidence, /40%/);
  const low = analyzeCommandStream(['whoami 2>/dev/null', 'ipconfig', 'net user', 'ver', 'hostname']);
  assert.equal(sig(low, 'error-suppression').fired, false); // 20% is not blanket suppression
  assert.equal(sig(analyzeCommandStream(CLEAN), 'error-suppression').fired, false);
});

test('non-interactive flags: --no-pager fires', () => {
  const r = analyzeCommandStream(['whoami', 'ipconfig', 'git --no-pager log', 'ver', 'hostname']);
  assert.equal(sig(r, 'non-interactive').fired, true);
  assert.match(sig(r, 'non-interactive').evidence, /--no-pager/);
  assert.equal(sig(analyzeCommandStream(CLEAN), 'non-interactive').fired, false);
});

test('bundling: && chains at density fire; a lone short pipe stream stays silent', () => {
  const r = analyzeCommandStream(['whoami && ver', 'ipconfig', 'net user', 'dir && ver', 'hostname']);
  assert.equal(sig(r, 'bundling').fired, true);
  assert.match(sig(r, 'bundling').evidence, /40% of lines bundled/);
  assert.equal(sig(analyzeCommandStream(CLEAN), 'bundling').fired, false);
});

test('comments: an explanatory shell comment fires (planning leakage)', () => {
  const r = analyzeCommandStream(['whoami', 'ipconfig', 'net user # list all local users', 'ver', 'hostname']);
  assert.equal(sig(r, 'comments').fired, true);
  assert.match(sig(r, 'comments').evidence, /# list all local users/);
  assert.equal(sig(analyzeCommandStream(CLEAN), 'comments').fired, false);
});

test('cadence: uniform sub-1s gaps fire; irregular human pacing does not', () => {
  const machine = analyzeCommandStream(CLEAN, { times: series([100, 100, 100, 100]) });
  assert.equal(sig(machine, 'cadence').fired, true);
  assert.match(sig(machine, 'cadence').evidence, /gapCV 0/);
  assert.match(sig(machine, 'cadence').evidence, /100% sub-1s gaps/);
  const human = analyzeCommandStream(CLEAN, { times: series([3500, 8200, 2100, 15000]) });
  assert.equal(sig(human, 'cadence').fired, false);
  assert.equal(sig(human, 'cadence').evidence, null);
});

test('cadence is NEVER fabricated: times omitted (or mismatched) -> fired:null + no timing evidence note', () => {
  const noTimes = analyzeCommandStream(CLEAN);
  assert.equal(sig(noTimes, 'cadence').fired, null);
  assert.match(sig(noTimes, 'cadence').evidence, /no timing evidence/);
  assert.match(noTimes.note, /never rescaled, never fabricated/);
  const mismatched = analyzeCommandStream(CLEAN, { times: [1, 2] });
  assert.equal(sig(mismatched, 'cadence').fired, null);
});

// ---------- the comparison the tier exists for ----------
test('a deliberately agent-shaped stream scores strictly higher than a human-ish one', () => {
  const agent = analyzeCommandStream([
    "echo '---'; whoami",
    'ipconfig /all 2>/dev/null',
    'net user 2>/dev/null',
    'dir C:\\Users 2>&1 | head -5',
    "echo '---'; systeminfo | findstr /B /C:'OS'",
    '# list all local users next',
    'netstat -ano 2>/dev/null && tasklist',
  ], { times: series([120, 90, 110, 100, 95, 105]) });
  const human = analyzeCommandStream(
    ['whoami', 'ipconfig', 'net user', 'dir C:\\Users', "systeminfo | findstr /B /C:'OS'", 'netstat -ano', 'tasklist'],
    { times: series([3500, 8200, 2100, 15000, 6400, 11000]) });
  assert.equal(agent.band, 'agent-shaped');
  assert.ok(agent.score >= 70, 'agent-shaped stream scores ' + agent.score);
  assert.equal(human.band, 'human-like');
  assert.ok(agent.score > human.score, 'agent ' + agent.score + ' > human ' + human.score);
  assert.match(agent.note, /never a vendor verdict/);
  assert.match(agent.note, /NOT a claim of undetectability/);
});

// ---------- tools/tradecraft: preflight + fetchLive error shape ----------
test('preflight grades a planned list locally; bad input gets an honest error', () => {
  const r = preflight(['whoami', "echo '---'; ipconfig", 'net user 2>/dev/null', 'ver 2>/dev/null', 'hostname']);
  assert.equal(r.ok, true);
  assert.equal(r.planned, 5);
  assert.equal(sig(r, 'separators').fired, true);
  assert.equal(sig(r, 'cadence').fired, null, 'a planned list has no real timestamps');
  const bad = preflight('whoami');
  assert.equal(bad.ok, false);
  assert.match(bad.error, /array of command strings/);
  assert.equal(preflight(['whoami', 42]).ok, false);
});

test('fetchLive: unreachable api surfaces an honest error object, not a crash', async () => {
  const r = await fetchLive('agent-x', 'http://127.0.0.1:1');
  assert.equal(r.ok, false);
  assert.match(r.error, /unreachable/);
  await assert.rejects(() => fetchLive(), TypeError);
});

// ---------- the route: a real armed channel, evidence matches ----------
test('GET /api/channel/tradecraft grades the ledger stream; 404 on unknown agent', async () => {
  const serverFile = join(dirname(fileURLToPath(import.meta.url)), '..', 'server.mjs');
  const port = 39201;
  const proc = spawn(process.execPath, [serverFile], {
    env: { ...process.env, VARVEL_PORT: String(port), VARVEL_DEMO_PORT: '39202', VARVEL_HARD_PORT: '39203' },
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
    const api = `http://127.0.0.1:${port}`;
    let agentId = null;
    for (let i = 0; i < 20 && !agentId; i++) {
      try {
        const arm = await fetch(api + '/api/channel/arm', { method: 'POST' });
        if (arm.ok) {
          const reg = await (await fetch(api + '/api/channel/agent', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ action: 'register', label: 'tradecraft' }) })).json();
          agentId = reg.agentId;
        }
      } catch { await new Promise((x) => setTimeout(x, 250)); }
    }
    assert.ok(agentId, 'agent registered on the armed channel');
    const stream = [
      "echo '---'; whoami",
      'ipconfig /all 2>/dev/null',
      'net user 2>/dev/null',
      'dir C:\\Users 2>&1 | head -5',
      "echo '---'; hostname",
      '# enumerate local users next',
      'git --no-pager log 2>/dev/null',
      'netstat -ano && tasklist 2>/dev/null',
    ];
    for (const data of stream) {
      const t = await (await fetch(api + '/api/channel/task', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ agentId, kind: 'shell', data }) })).json();
      assert.equal(t.ok, true, 'task queued: ' + data);
    }
    const r = await fetch(api + '/api/channel/tradecraft?agent=' + agentId);
    assert.equal(r.status, 200);
    const body = await r.json();
    assert.equal(body.agentId, agentId);
    assert.equal(body.shellTasks, stream.length);
    assert.equal(body.band, 'agent-shaped', JSON.stringify(body.signatures));
    assert.match(sig(body, 'separators').evidence, /echo '---'/);
    assert.match(sig(body, 'bounded-captures').evidence, /2>&1 \| head -5/);
    assert.equal(sig(body, 'cadence').fired, true, 'burst-queued tasks are machine-paced, honestly reported');
    // unknown agent -> 404, honestly
    const missing = await fetch(api + '/api/channel/tradecraft?agent=no-such-agent');
    assert.equal(missing.status, 404);
    assert.match((await missing.json()).error, /no such agent/);
  } finally { proc.kill(); }
});

// Teardown grace: on win32, --test-force-exit can fire while sockets are still closing
// (libuv UV_HANDLE_CLOSING assert). Same guard as transportfail/dnstransport/flowscore.
test('teardown grace for socket drain (win32 libuv assert guard)', async () => {
  await new Promise((r) => setTimeout(r, 600));
});
