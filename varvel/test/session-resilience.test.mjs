// VARVEL session resilience tests (documented gap #2) — HERMETIC: a scripted MOCK Kimi
// backend that can die mid-stream N times; no network, no wall-clock waits (backoff sleep
// + jitter are injected). Proves: transient stream death is retried and the mission
// completes with NO duplicate tool execution; permanent (4xx auth/quota) fails fast;
// backoff caps hold; checkpoint → simulated crash → resume; split preserves failed
// hypotheses + state refs; every retry emits an audit event.
//   node --test varvel/test/session-resilience.test.mjs

import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// Isolate persistence to this process BEFORE any engine call (dataDir is read at call time).
const DATA = join(tmpdir(), 'varvel-resil-' + process.pid);
process.env.VARVEL_DATA_DIR = DATA;

const { makeKimiAgent, classifyBackendError, retryPolicy, backoffDelay } = await import('../engine/kimi-runagent.mjs');
const { listMissions, loadCheckpoint, saveCheckpoint, splitMission, shouldSplit } = await import('../engine/missions.mjs');
const { recordFailures } = await import('../engine/store.mjs');
const { upsert } = await import('../engine/statestore.mjs');
const { DEMO_SESSION } = await import('../engine/live.mjs');

const ws = mkdtempSync(join(tmpdir(), 'varvel-resil-ws-'));
const ENV = { KIMI_API_KEY: 'sk-test-resilience', KIMI_MODEL: 'k3', VARVEL_DATA_DIR: DATA };

// --- scripted mock backend --------------------------------------------------
const enc = new TextEncoder();
const sse = (events) => enc.encode(events.map((e) => 'data: ' + JSON.stringify(e) + '\n\n').join(''));
const okStream = (events) => {
  const bytes = sse(events);
  return { ok: true, status: 200, body: { getReader: () => { let sent = false; return { read: async () => (sent ? { done: true } : ((sent = true), { done: false, value: bytes })) }; } } };
};
// Dies MID-STREAM: delivers partial SSE, then the socket throws (the real field failure).
const dyingStream = (events, err) => {
  const chunks = events.map((e) => enc.encode('data: ' + JSON.stringify(e) + '\n\n'));
  return { ok: true, status: 200, body: { getReader: () => { let i = 0; return { read: async () => { if (i < chunks.length) return { done: false, value: chunks[i++] }; throw err; } }; } } };
};
const textEvents = (text) => [
  { type: 'content_block_start', index: 0, content_block: { type: 'text' } },
  { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text } },
  { type: 'message_delta', delta: { stop_reason: 'end_turn' } },
];
const toolEvents = (calls) => {
  const evs = [];
  calls.forEach((c, i) => {
    evs.push({ type: 'content_block_start', index: i, content_block: { type: 'tool_use', id: c.id, name: c.name } });
    evs.push({ type: 'content_block_delta', index: i, delta: { type: 'input_json_delta', partial_json: JSON.stringify(c.input) } });
  });
  evs.push({ type: 'message_delta', delta: { stop_reason: 'tool_use' } });
  return evs;
};
// script: array of (call) => response | throws. Replays the last step if over-run.
function mockBackend(script) {
  const calls = [];
  const prev = globalThis.fetch;
  globalThis.fetch = async (url, opts) => {
    const call = { url, body: opts && opts.body ? JSON.parse(opts.body) : null, signal: opts && opts.signal };
    calls.push(call);
    const step = script[Math.min(calls.length - 1, script.length - 1)];
    return step(call);
  };
  return { calls, restore: () => { globalThis.fetch = prev; } };
}
// A stream that never answers — but honors the caller's AbortSignal (undici semantics:
// aborting errors the pending read, which is what VARVEL_KIMI_CALL_TIMEOUT_MS relies on).
const hangingStream = (call) => ({
  ok: true, status: 200,
  body: { getReader: () => ({ read: () => new Promise((_, rej) => {
    const sig = call && call.signal;
    const timeout = () => rej(new DOMException('The operation timed out', 'TimeoutError'));
    if (!sig) return; // truly silent hang (no timeout configured)
    if (sig.aborted) return timeout();
    sig.addEventListener('abort', timeout, { once: true });
  }) }) },
});
// Execution seam: counts firings per tool_use input; governance still crosses the real hook.
const countingExec = () => {
  const fired = [];
  const exec = async (name, input) => { fired.push({ name, input: JSON.stringify(input || {}) }); return 'OK: mock-exec ' + name; };
  return { fired, exec };
};
const fakeClock = () => {
  const sleeps = [];
  return { sleeps, sleep: async (ms) => { sleeps.push(ms); }, rand: () => 0.5 };
};
const mkAgent = (extra = {}) => makeKimiAgent({ sessionFile: DEMO_SESSION, wsDir: ws, model: 'k3', effort: 'low', env: ENV, ...extra });

let backend = null;
after(() => { try { backend && backend.restore(); } catch {} try { rmSync(DATA, { recursive: true, force: true }); } catch {} try { rmSync(ws, { recursive: true, force: true }); } catch {} });

// ---------------------------------------------------------------------------
test('taxonomy: transient stream deaths vs permanent 4xx auth/quota', () => {
  const http = (status) => Object.assign(new Error('Kimi HTTP ' + status + ': x'), { status });
  for (const e of [new Error('terminated'), new TypeError('fetch failed'), new Error('socket hang up'), new Error('read ECONNRESET'), new Error('connect ETIMEDOUT'), new Error('The operation timed out'), new Error('This operation was aborted'), http(500), http(502), http(503), http(504), http(408), http(429)])
    assert.equal(classifyBackendError(e).transient, true, 'transient: ' + e.message);
  for (const e of [http(400), http(401), http(403), http(404), http(422), new Error('no usable Kimi credential (env / kimi-code OAuth / ~/.kimicode/config.json)')])
    assert.equal(classifyBackendError(e).transient, false, 'permanent: ' + e.message);
  assert.equal(classifyBackendError(http(403)).kind, 'http-403', 'the usage-limit 403 is permanent — never retried');
});

test('backoff: jittered exponential growth, cap ALWAYS honored (fake clock, no wall time)', () => {
  const pol = retryPolicy(ENV, { attempts: 4, baseMs: 1500, capMs: 20000, rand: () => 0.5 });
  assert.equal(pol.attempts, 4);
  assert.deepEqual([backoffDelay(1, pol), backoffDelay(2, pol), backoffDelay(3, pol)], [1125, 2250, 4500], '1.5s base doubling at 0.5 jitter');
  const hi = retryPolicy(ENV, { baseMs: 1500, capMs: 20000, rand: () => 1 });
  for (let a = 1; a <= 14; a++) assert.ok(backoffDelay(a, hi) <= 20000, 'cap holds at attempt ' + a);
  assert.equal(backoffDelay(14, hi), 20000, 'post-jitter cap is exact at the ceiling');
  const envPol = retryPolicy({ VARVEL_KIMI_RETRY_ATTEMPTS: '6', VARVEL_KIMI_RETRY_BASE_MS: '500', VARVEL_KIMI_RETRY_CAP_MS: '4000' });
  assert.deepEqual([envPol.attempts, envPol.baseMs, envPol.capMs], [6, 500, 4000], 'env-configurable');
});

test('transient mid-stream death: retried, mission completes, tool fired EXACTLY once, retry audited', async () => {
  const { fired, exec } = countingExec();
  const clock = fakeClock();
  backend = mockBackend([
    () => okStream(toolEvents([{ id: 'toolu_a', name: 'Write', input: { file_path: 'a.txt', content: 'x' } }])),
    () => dyingStream([{ type: 'content_block_start', index: 0, content_block: { type: 'text' } }], new Error('terminated')), // partial SSE, then the socket dies
    () => { throw new TypeError('fetch failed'); }, // connection-level death
    () => okStream(textEvents('mission complete')),
  ]);
  const agent = mkAgent({ execTool: exec, retry: { attempts: 4, baseMs: 1000, capMs: 5000, sleep: clock.sleep, rand: clock.rand } });
  const r = await agent({ system: 'sys', messages: [{ role: 'user', content: 'run the mission' }] });
  assert.equal(r.text, 'mission complete');
  assert.equal(backend.calls.length, 4, 'died twice, retried twice, succeeded');
  assert.equal(fired.length, 1, 'the tool call fired EXACTLY once across all retries');
  assert.equal(r.retries, 2);
  assert.deepEqual(clock.sleeps, [750, 1500], 'jittered backoff at rand=0.5, no wall-clock wait');
  const retrySteps = r.stepLog.filter((s) => s.kind === 'retry');
  assert.equal(retrySteps.length, 2, 'AUDIT: one retry event per retry — never silent');
  assert.deepEqual(retrySteps.map((s) => s.attempt), [1, 2]);
  assert.ok(retrySteps.every((s) => s.error === 'stream-death' && s.waitMs > 0));
  const cp = loadCheckpoint(r.missionId);
  assert.equal(cp.status, 'awaiting-input');
  assert.equal(cp.ledger.length, 1, 'executed call ledgered with a result digest');
  assert.match(cp.ledger[0].resultDigest, /^sha256:/);
  assert.equal(cp.retries.length, 2, 'retries persisted in the checkpoint audit trail');
  backend.restore(); backend = null;
});

test('permanent error (403 quota) fails LOUD and fast — no retry, no backoff, mission marked failed', async () => {
  const clock = fakeClock();
  backend = mockBackend([() => { throw Object.assign(new Error('Kimi HTTP 403: usage limit exceeded'), { status: 403 }); }]);
  const agent = mkAgent({ execTool: countingExec().exec, retry: { attempts: 4, baseMs: 1000, capMs: 5000, sleep: clock.sleep, rand: clock.rand } });
  const r = await agent({ system: 'sys', messages: [{ role: 'user', content: 'go' }] });
  assert.equal(backend.calls.length, 1, 'a 403 is NEVER retried');
  assert.equal(clock.sleeps.length, 0, 'no backoff spent on a permanent error');
  assert.match(r.text, /backend error: Kimi HTTP 403/);
  assert.match(r.text, /not retried/);
  assert.equal(loadCheckpoint(r.missionId).status, 'failed');
  backend.restore(); backend = null;
});

test('transient exhaustion keeps the mission RESUMABLE and says so (no silent orphan)', async () => {
  const clock = fakeClock();
  backend = mockBackend([() => { throw new Error('terminated'); }]);
  const agent = mkAgent({ execTool: countingExec().exec, retry: { attempts: 2, baseMs: 1000, capMs: 5000, sleep: clock.sleep, rand: clock.rand } });
  const r = await agent({ system: 'sys', messages: [{ role: 'user', content: 'go' }] });
  assert.equal(backend.calls.length, 2, 'bounded at the configured attempts');
  assert.match(r.text, new RegExp('resume ' + r.missionId));
  assert.equal(loadCheckpoint(r.missionId).status, 'running', 'still resumable — not orphaned');
  backend.restore(); backend = null;
});

test('checkpoint → simulated crash (new agent instance) → resume completes, ZERO re-fire', async () => {
  const { fired, exec } = countingExec();
  const clock = fakeClock();
  const missionId = 'msn-crash-test';
  // Phase 1: two tool calls execute, then the network dies transiently with attempts=1
  // (the process is abandoned mid-mission — the field failure that orphaned four turns).
  backend = mockBackend([
    () => okStream(toolEvents([
      { id: 'toolu_1', name: 'Write', input: { file_path: 'a.txt', content: 'one' } },
      { id: 'toolu_2', name: 'Write', input: { file_path: 'b.txt', content: 'two' } },
    ])),
    () => dyingStream([], new Error('terminated')),
  ]);
  const first = mkAgent({ execTool: exec, retry: { attempts: 1, sleep: clock.sleep, rand: clock.rand } });
  const r1 = await first({ system: 'sys', messages: [{ role: 'user', content: 'crash mission objective' }], resumeId: missionId });
  assert.match(r1.text, /backend error/);
  assert.equal(fired.length, 2, 'both tool calls executed before the crash');
  const cpCrash = loadCheckpoint(missionId);
  assert.equal(cpCrash.status, 'running', 'crash leaves a running checkpoint');
  assert.equal(cpCrash.ledger.length, 2);
  // Phase 2: a NEW agent instance (process restart) resumes from the checkpoint.
  backend.restore();
  backend = mockBackend([() => okStream(textEvents('resumed and finished'))]);
  const second = mkAgent({ execTool: exec, retry: { attempts: 1, sleep: clock.sleep, rand: clock.rand } });
  const r2 = await second({ system: 'sys', messages: [{ role: 'user', content: 'continue' }], resumeId: missionId, resume: true });
  assert.equal(r2.text, 'resumed and finished');
  assert.equal(r2.reconstructed, true);
  assert.equal(fired.length, 2, 'NO tool call re-fired across the crash/resume');
  assert.ok(r2.stepLog.some((s) => s.kind === 'checkpoint' && /resumed/.test(s.text)), 'resume is an audited event');
  assert.equal(loadCheckpoint(missionId).ledger.length, 2, 'ledger unchanged — replay, not re-execution');
  backend.restore(); backend = null;
});

test('crash MID-BATCH: ledgered call is replayed (result reused), unledgered call executes', async () => {
  const { fired, exec } = countingExec();
  const clock = fakeClock();
  const missionId = 'msn-midbatch-test';
  // Simulate the exact checkpoint a crash between tool call 1 and 2 leaves behind:
  // assistant emitted a 2-call batch; call 1 is ledgered (with its result), call 2 never ran.
  const now = new Date().toISOString();
  saveCheckpoint({
    missionId, engagement: null, created: now, status: 'running', model: 'k3', effort: 'low',
    sessionFile: DEMO_SESSION, wsDir: ws, container: '', objective: 'mid-batch objective',
    turnsTotal: 1, bytes: 0,
    msgs: [
      { role: 'user', content: 'mid-batch objective' },
      { role: 'assistant', content: [
        { type: 'tool_use', id: 'toolu_done', name: 'Write', input: { file_path: 'done.txt', content: 'd' } },
        { type: 'tool_use', id: 'toolu_pending', name: 'Write', input: { file_path: 'pending.txt', content: 'p' } },
      ] },
    ],
    ledger: [{ seq: 1, id: 'toolu_done', name: 'Write', inputDigest: 'sha256:x', status: 'done', resultDigest: 'sha256:y',
      result: { type: 'tool_result', tool_use_id: 'toolu_done', content: 'PRE-CRASH RESULT' }, truncated: false, at: now }],
    retries: [], denials: [], gates: [], splits: 0, finalText: null,
  });
  backend = mockBackend([() => okStream(textEvents('batch reconciled, mission done'))]);
  const agent = mkAgent({ execTool: exec, retry: { attempts: 1, sleep: clock.sleep, rand: clock.rand } });
  const r = await agent({ system: 'sys', messages: [{ role: 'user', content: 'continue' }], resumeId: missionId, resume: true });
  assert.equal(r.text, 'batch reconciled, mission done');
  assert.equal(fired.length, 1, 'only the UNLEDGERED call executed');
  assert.deepEqual(JSON.parse(fired[0].input), { file_path: 'pending.txt', content: 'p' });
  assert.ok(r.stepLog.some((s) => s.replayed === true), 'the replay is audited as a replay');
  // The replayed result must reach the model — inspect the actual resume request payload.
  const resumeMsgs = backend.calls[0].body.messages;
  const resultMsg = resumeMsgs.find((m) => m.role === 'user' && Array.isArray(m.content) && m.content.some((b) => b.type === 'tool_result'));
  const replayed = resultMsg.content.find((b) => b.tool_use_id === 'toolu_done');
  assert.equal(replayed.content, 'PRE-CRASH RESULT', 'the model sees the ledgered result verbatim');
  backend.restore(); backend = null;
});

test('stream timeout (opt-in) classifies transient and is retried', async () => {
  const clock = fakeClock();
  backend = mockBackend([(call) => hangingStream(call), () => okStream(textEvents('after timeout'))]);
  const agent = mkAgent({ execTool: countingExec().exec, timeoutMs: 50, retry: { attempts: 2, baseMs: 10, capMs: 20, sleep: clock.sleep, rand: clock.rand } });
  const r = await agent({ system: 'sys', messages: [{ role: 'user', content: 'go' }] });
  assert.equal(r.text, 'after timeout');
  assert.equal(backend.calls.length, 2);
  assert.equal(r.stepLog.filter((s) => s.kind === 'retry').length, 1, 'timeout death audited');
  backend.restore(); backend = null;
});

test('split suggestion: fires ONCE at a turn boundary — never mid-tool-call — and persists', async () => {
  const { exec } = countingExec();
  const clock = fakeClock();
  process.env.VARVEL_SPLIT_TURNS = '2';
  try {
    backend = mockBackend([
      () => okStream(toolEvents([{ id: 'toolu_s1', name: 'Write', input: { file_path: 's1.txt', content: '1' } }])),
      () => okStream(toolEvents([{ id: 'toolu_s2', name: 'Write', input: { file_path: 's2.txt', content: '2' } }])),
      () => okStream(textEvents('long mission done')),
    ]);
    const agent = mkAgent({ execTool: exec, retry: { attempts: 1, sleep: clock.sleep, rand: clock.rand } });
    const r = await agent({ system: 'sys', messages: [{ role: 'user', content: 'long mission' }] });
    assert.equal(r.text, 'long mission done');
    assert.equal(r.splitSuggested, true);
    const splitSteps = r.stepLog.filter((s) => s.kind === 'split');
    assert.equal(splitSteps.length, 1, 'suggested exactly once');
    assert.match(splitSteps[0].text, /SUGGESTED/);
    // Never mid-tool-call: the suggestion lands AFTER the last tool result of the prior turn.
    const kinds = r.stepLog.map((s) => s.kind);
    const lastResult = kinds.lastIndexOf('result');
    const splitAt = kinds.indexOf('split');
    assert.ok(splitAt > lastResult, 'the suggestion fired at a turn boundary, not between a tool call and its result');
    assert.ok(loadCheckpoint(r.missionId).splitSuggestedAt, 'suggestion persisted — survives resume');
  } finally { delete process.env.VARVEL_SPLIT_TURNS; }
  backend.restore(); backend = null;
});

test('shouldSplit thresholds: turns AND bytes, env/opts-tunable', () => {
  assert.equal(shouldSplit({ turns: 30 }).split, true);
  assert.equal(shouldSplit({ bytes: 150000 }).split, true);
  assert.equal(shouldSplit({ turns: 5, bytes: 100 }).split, false);
  assert.match(shouldSplit({ turns: 31 }).reason, /turns/);
  assert.equal(shouldSplit({ turns: 5 }, { turns: 3 }).split, true, 'opts override');
  assert.equal(shouldSplit({ turns: 5 }, { env: { VARVEL_SPLIT_TURNS: '99' } }).split, false, 'env override');
});

test('split handoff: failed hypotheses SURVIVE, state travels by REF, secrets never cross', async () => {
  const eng = 'RESIL-SPLIT';
  recordFailures(eng, [{ phase: 'exploit', kind: 'failed-exploit', approach: 'SQLi on /login' }]);
  upsert(eng, 'findings', { title: 'apache path traversal', host: '10.0.0.5', ref: 'CVE-2021-41773', sev: 'high', validation: 'refuted' });
  upsert(eng, 'hosts', { ip: '10.0.0.5', services: ['http:80'] });
  upsert(eng, 'creds', { kind: 'http-basic', principal: 'admin', secret: 'hunter2-SECRET', scope: '/admin' });
  const now = new Date().toISOString();
  saveCheckpoint({
    missionId: 'msn-split-test', engagement: eng, created: now, status: 'awaiting-input', model: 'k3', effort: 'low',
    sessionFile: DEMO_SESSION, wsDir: ws, container: '', objective: 'breach acme corp',
    turnsTotal: 41, bytes: 5000,
    msgs: [{ role: 'user', content: 'breach acme corp' }, { role: 'assistant', content: [{ type: 'text', text: 'found the admin panel; exploit chain next' }] }],
    ledger: [], retries: [], denials: [], gates: [{ phase: 'exploit', id: 'g1' }], splits: 0, finalText: 'found the admin panel; exploit chain next',
  });
  const out = splitMission('msn-split-test', { note: 'operator-driven split' });
  const h = out.handoff;
  // PROOF STANDARD: both failure-ledger approaches AND refuted findings survive the split.
  assert.ok(h.failedHypotheses.some((f) => /SQLi on \/login/.test(f.approach || '')), 'failure-ledger approach carried');
  assert.ok(h.failedHypotheses.some((f) => f.kind === 'refuted-finding' && f.ref === 'CVE-2021-41773'), 'refuted finding carried');
  // State by REFERENCE: engagement + counts, no entity copies, and NEVER a secret.
  assert.deepEqual(h.stateRefs.counts, { hosts: 1, creds: 1, sessions: 0, findings: 1, notes: 0 });
  assert.ok(!h.hosts && !h.creds && !h.findings, 'refs not copies');
  assert.ok(!JSON.stringify(h).includes('hunter2-SECRET'), 'cred secret never crosses the split');
  assert.deepEqual(h.pendingGates, [{ phase: 'exploit', id: 'g1' }]);
  assert.match(h.summary, /admin panel/);
  // The seed text a fresh session starts from.
  assert.match(out.seed, /FAILED HYPOTHESES[\s\S]*do NOT retry/);
  assert.match(out.seed, /SQLi on \/login/);
  assert.match(out.seed, /host 10\.0\.0\.5/, 'statestore briefSlice seeds the fresh context');
  assert.match(out.seed, /PENDING GATES/);
  // Both checkpoints: old sealed 'split', fresh seeded and resumable.
  assert.equal(loadCheckpoint('msn-split-test').status, 'split');
  const fresh = loadCheckpoint(h.newMission);
  assert.equal(fresh.status, 'awaiting-input');
  assert.equal(fresh.splitFrom, 'msn-split-test');
  assert.equal(fresh.msgs.length, 1, 'fresh context = the handoff seed, not the old history');
  // A split mission refuses to run and points at its successor.
  const clock = fakeClock();
  backend = mockBackend([() => okStream(textEvents('should never run'))]);
  const r = await mkAgent({ execTool: countingExec().exec, retry: { attempts: 1, sleep: clock.sleep, rand: clock.rand } })({ system: 's', messages: [{ role: 'user', content: 'continue' }], resumeId: 'msn-split-test', resume: true });
  assert.equal(r.successor, h.newMission);
  assert.equal(backend.calls.length, 0, 'a split mission never hits the backend');
  backend.restore(); backend = null;
});

test('missions listing: summaries only (no conversation bodies), statuses visible', () => {
  const list = listMissions();
  assert.ok(list.length >= 3, 'the missions created above are listed');
  const crash = list.find((m) => m.missionId === 'msn-crash-test');
  assert.ok(crash && crash.status === 'awaiting-input' && crash.toolCalls === 2);
  for (const m of list) { assert.ok(!m.msgs && !m.ledger, 'summaries never leak conversation/tool bodies'); }
});

test('cli surface: missions lists, resume of an unknown id errors honestly, split needs an id', async () => {
  const { spawnSync } = await import('node:child_process');
  const { fileURLToPath } = await import('node:url');
  const { dirname } = await import('node:path');
  const CLI = join(dirname(fileURLToPath(import.meta.url)), '..', 'tools', 'cli.mjs');
  const run = (args) => {
    const r = spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', timeout: 30000 }); // inherits VARVEL_DATA_DIR
    let out = null;
    try { out = JSON.parse(r.stdout); } catch { out = { parseError: (r.stdout || '').slice(0, 200), stderr: (r.stderr || '').slice(0, 200) }; }
    return { status: r.status, out };
  };
  const list = run(['missions']);
  assert.equal(list.status, 0);
  assert.ok(Array.isArray(list.out.missions) && list.out.missions.some((m) => m.missionId === 'msn-crash-test'), 'cli missions sees the checkpoint store');
  const bad = run(['resume', 'msn-does-not-exist']);
  assert.equal(bad.status, 2);
  assert.match(bad.out.error, /no checkpoint/, 'unknown mission is an honest error, not a crash');
  const noArg = run(['split']);
  assert.equal(noArg.status, 2);
  assert.match(noArg.out.error, /split needs <missionId>/);
});
