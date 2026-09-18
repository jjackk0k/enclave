// VARVEL local-brain provider tests — HERMETIC. The openai-compatible backend is exercised
// against an in-test node:http server on 127.0.0.1 (no real network); the Kimi default path
// is pinned byte-identical via fetch interception (its base URL has no env override — same
// technique as session-resilience.test.mjs). Proves: default path unchanged, adapter happy
// path incl. tool-call round-trip, 403/usage-limit surfacing per provider, timeout,
// malformed responses fail loudly, unknown-provider refusal, config validation pins,
// selection precedence, and key-value secret hygiene.
//   node --test varvel/test/brain-provider.test.mjs

import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

// Isolate persistence + settings BEFORE any engine call (both read their env at call time).
const DATA = join(tmpdir(), 'varvel-brain-' + process.pid);
process.env.VARVEL_DATA_DIR = DATA;
process.env.VARVEL_SETTINGS_FILE = join(DATA, 'settings.json');

const { makeKimiAgent } = await import('../engine/kimi-runagent.mjs');
const { resolveBrain, callOpenAI, toOpenAIMessages, toOpenAITools, BRAIN_PROVIDERS } = await import('../engine/brain-provider.mjs');
const { Settings } = await import('../engine/settings.mjs');
const { loadCheckpoint } = await import('../engine/missions.mjs');
const { DEMO_SESSION } = await import('../engine/live.mjs');

const ws = mkdtempSync(join(tmpdir(), 'varvel-brain-ws-'));
const ENV_KIMI = { KIMI_API_KEY: 'sk-test-brain', KIMI_MODEL: 'k3', VARVEL_DATA_DIR: DATA };
const servers = [];
after(() => {
  for (const s of servers) { try { for (const sock of s.sockets) sock.destroy(); s.server.close(); } catch {} }
  try { rmSync(DATA, { recursive: true, force: true }); } catch {}
  try { rmSync(ws, { recursive: true, force: true }); } catch {}
});

// --- in-test mock HTTP server (loopback only) --------------------------------
function mockHttp(handler) {
  const requests = [], sockets = new Set();
  const server = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => { requests.push({ method: req.method, url: req.url, headers: req.headers, body }); handler({ method: req.method, url: req.url, headers: req.headers, body }, res); });
  });
  server.on('connection', (s) => { sockets.add(s); s.on('close', () => sockets.delete(s)); });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => {
    const entry = { server, requests, sockets, baseUrl: 'http://127.0.0.1:' + server.address().port + '/v1' };
    servers.push(entry); resolve(entry);
  }));
}
const oaiSse = (chunks) => chunks.map((c) => 'data: ' + JSON.stringify(c) + '\n\n').join('') + 'data: [DONE]\n\n';
const sendSse = (res, payload) => { res.writeHead(200, { 'content-type': 'text/event-stream' }); res.end(payload); };
const oaiTextChunks = (text) => [
  { choices: [{ index: 0, delta: { role: 'assistant', content: text }, finish_reason: null }] },
  { choices: [{ index: 0, delta: {}, finish_reason: 'stop' }] },
];
// A Write tool_call whose arguments arrive SPLIT across two chunks (the vLLM/llama.cpp shape).
const oaiToolChunks = (id, name, args) => [
  { choices: [{ index: 0, delta: { role: 'assistant', tool_calls: [{ index: 0, id, function: { name, arguments: args.slice(0, 12) } }] }, finish_reason: null }] },
  { choices: [{ index: 0, delta: { tool_calls: [{ index: 0, function: { arguments: args.slice(12) } }] }, finish_reason: null }] },
  { choices: [{ index: 0, delta: {}, finish_reason: 'tool_calls' }] },
];
const fakeClock = () => { const c = { sleeps: [], sleep: async (ms) => { c.sleeps.push(ms); }, rand: () => 0.5 }; return c; };

// --- fetch interception for the Kimi default path (no network, exact wire pin) -----------
const enc = new TextEncoder();
const anthropicTextStream = (text) => {
  const bytes = enc.encode([
    { type: 'content_block_start', index: 0, content_block: { type: 'text' } },
    { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text } },
    { type: 'message_delta', delta: { stop_reason: 'end_turn' } },
  ].map((e) => 'data: ' + JSON.stringify(e) + '\n\n').join(''));
  return { ok: true, status: 200, headers: { get: () => 'text/event-stream' }, body: { getReader: () => { let sent = false; return { read: async () => (sent ? { done: true } : ((sent = true), { done: false, value: bytes })) }; } } };
};
function interceptFetch(fn) {
  const calls = []; const prev = globalThis.fetch;
  globalThis.fetch = async (url, opts) => { calls.push({ url: String(url), opts }); return fn({ url: String(url), opts }, calls.length); };
  return { calls, restore: () => { globalThis.fetch = prev; } };
}

// The Kimi tool schema as shipped today — an INDEPENDENT copy, so a change to the brain's
// tool surface breaks this pin loudly (that is the point of a regression pin).
const TOOLS_PIN = [
  { name: 'Bash', description: 'Run a shell command in the workspace; returns stdout+stderr. Use curl/HTTP to reach in-scope targets.', input_schema: { type: 'object', properties: { command: { type: 'string' } }, required: ['command'] } },
  { name: 'Read', description: 'Read a text file in the workspace.', input_schema: { type: 'object', properties: { file_path: { type: 'string' } }, required: ['file_path'] } },
  { name: 'Write', description: 'Write (overwrite) a text file in the workspace.', input_schema: { type: 'object', properties: { file_path: { type: 'string' }, content: { type: 'string' } }, required: ['file_path', 'content'] } },
  { name: 'Edit', description: 'Exact string replace in a workspace file.', input_schema: { type: 'object', properties: { file_path: { type: 'string' }, old_string: { type: 'string' }, new_string: { type: 'string' } }, required: ['file_path', 'old_string', 'new_string'] } },
];

// ---------------------------------------------------------------------------
test('REGRESSION PIN: default path (no provider configured) is byte-identical to today', async () => {
  const spy = interceptFetch(() => anthropicTextStream('kimi answer'));
  const agent = makeKimiAgent({ sessionFile: DEMO_SESSION, wsDir: ws, model: 'k3', effort: 'low', env: ENV_KIMI, execTool: async () => 'unused', retry: { attempts: 1, sleep: async () => {}, rand: () => 0.5 } });
  const r = await agent({ system: 'sys', messages: [{ role: 'user', content: 'go' }] });
  assert.equal(spy.calls.length, 1);
  const call = spy.calls[0];
  assert.equal(call.url, 'https://api.kimi.com/coding/v1/messages', 'the Kimi wire endpoint is unchanged');
  const h = call.opts.headers;
  assert.equal(h['anthropic-version'], '2023-06-01');
  assert.equal(h['x-api-key'], 'sk-test-brain');
  assert.equal(h['authorization'], 'Bearer sk-test-brain');
  assert.equal(h['content-type'], 'application/json');
  // Byte-identical body: exact key order + values of the serialized request.
  const expected = JSON.stringify({ model: 'k3', max_tokens: 16000, system: 'sys', tools: TOOLS_PIN, messages: [{ role: 'user', content: 'go' }], stream: true, reasoning_effort: 'low' });
  assert.equal(call.opts.body, expected, 'the default request body is byte-identical');
  assert.equal(r.text, 'kimi answer');
  assert.equal(r.provider, 'kimi', 'the result names its brain');
  assert.ok(!('notes' in r), 'no degrade notes on the unchanged path');
  spy.restore();
});

test('REGRESSION PIN: a Kimi 403 usage-limit still surfaces with the kimi label, unretried', async () => {
  const spy = interceptFetch(() => { throw Object.assign(new Error('Kimi HTTP 403: usage limit exceeded'), { status: 403 }); });
  const agent = makeKimiAgent({ sessionFile: DEMO_SESSION, wsDir: ws, model: 'k3', env: ENV_KIMI, execTool: async () => 'unused', retry: { attempts: 4, sleep: async () => { throw new Error('must never sleep on a permanent error'); }, rand: () => 0.5 } });
  const r = await agent({ system: 'sys', messages: [{ role: 'user', content: 'go' }] });
  assert.equal(spy.calls.length, 1);
  assert.match(r.text, /^\(kimi backend error: Kimi HTTP 403: usage limit exceeded — permanent \(http-403\), not retried\)$/);
  spy.restore();
});

test('adapter happy path: streamed tool_call round-trips and completes; effort degrade is LOUD', async () => {
  const toolArgs = JSON.stringify({ file_path: 'a.txt', content: 'hi' });
  const mock = await mockHttp((req, res) => {
    const n = req.body ? JSON.parse(req.body) : {};
    const isFollowup = n.messages && n.messages.some((m) => m.role === 'tool');
    sendSse(res, oaiSse(isFollowup ? oaiTextChunks('LOCAL DONE') : oaiToolChunks('call_1', 'Write', toolArgs)));
  });
  const fired = [];
  const exec = async (name, input) => { fired.push({ name, input }); return 'OK: mock-exec ' + name; };
  const env = { VARVEL_LOCAL_BRAIN_KEY: 'sk-local-SECRET', VARVEL_DATA_DIR: DATA };
  const agent = makeKimiAgent({ sessionFile: DEMO_SESSION, wsDir: ws, model: 'unused', env, execTool: exec, retry: { attempts: 1, sleep: async () => {}, rand: () => 0.5 },
    provider: { provider: 'openai-compatible', baseUrl: mock.baseUrl, model: 'qwen3-test', apiKeyEnv: 'VARVEL_LOCAL_BRAIN_KEY' } });
  const r = await agent({ system: 'sys', messages: [{ role: 'user', content: 'write a file' }] });

  assert.equal(r.text, 'LOCAL DONE');
  assert.equal(r.provider, 'openai-compatible');
  assert.equal(mock.requests.length, 2, 'one tool turn + one follow-up');
  // Request shape: OpenAI chat-completions, function tools, NO Kimi/Anthropic fields.
  const first = mock.requests[0];
  assert.equal(first.url, '/v1/chat/completions');
  assert.equal(first.headers['authorization'], 'Bearer sk-local-SECRET', 'key resolved from the NAMED env var');
  assert.ok(!first.headers['x-api-key'] && !first.headers['anthropic-version'], 'no Anthropic headers leak onto the local wire');
  const b1 = JSON.parse(first.body);
  assert.equal(b1.model, 'qwen3-test');
  assert.equal(b1.stream, true);
  assert.ok(!('reasoning_effort' in b1), 'effort is NOT sent to an endpoint that cannot express it');
  assert.deepEqual(b1.messages, [{ role: 'system', content: 'sys' }, { role: 'user', content: 'write a file' }]);
  assert.equal(b1.tools.length, 4, 'all four governed tools cross as OpenAI functions');
  assert.ok(b1.tools.every((t) => t.type === 'function'));
  assert.equal(b1.tools[0].function.name, 'Bash');
  assert.deepEqual(b1.tools[0].function.parameters, TOOLS_PIN[0].input_schema, 'input_schema crosses as parameters verbatim');
  // The tool-call ROUND TRIP: split argument chunks reassembled, executed once, result returned.
  assert.equal(fired.length, 1);
  assert.deepEqual(fired[0], { name: 'Write', input: { file_path: 'a.txt', content: 'hi' } });
  const b2 = JSON.parse(mock.requests[1].body);
  assert.deepEqual(b2.messages.slice(2), [
    { role: 'assistant', content: '', tool_calls: [{ id: 'call_1', type: 'function', function: { name: 'Write', arguments: toolArgs } }] },
    { role: 'tool', tool_call_id: 'call_1', content: 'OK: mock-exec Write' },
  ], 'Anthropic tool_use/tool_result blocks map to OpenAI assistant.tool_calls + role:tool');
  // HONEST DEGRADE: default effort 'high' cannot cross — it is announced in stream AND result.
  assert.ok(r.stepLog.some((s) => s.kind === 'note' && /reasoning effort "high"/.test(s.text)), 'the degrade is a step-stream event');
  assert.ok(Array.isArray(r.notes) && /NOT sent/.test(r.notes[0]), 'the degrade rides the result');
  // SECRET HYGIENE: the key value appears NOWHERE in the operator-visible surfaces.
  assert.ok(!JSON.stringify(r).includes('sk-local-SECRET'), 'result never carries the key value');
});

test('adapter: no apiKeyEnv → NO authorization header (the common local-server case)', async () => {
  const mock = await mockHttp((req, res) => sendSse(res, oaiSse(oaiTextChunks('no auth needed'))));
  const agent = makeKimiAgent({ sessionFile: DEMO_SESSION, wsDir: ws, model: 'x', env: { VARVEL_DATA_DIR: DATA }, execTool: async () => 'unused', retry: { attempts: 1, sleep: async () => {}, rand: () => 0.5 },
    provider: { provider: 'openai-compatible', baseUrl: mock.baseUrl, model: 'gpt-oss-120b' } });
  const r = await agent({ system: 's', messages: [{ role: 'user', content: 'hi' }] });
  assert.equal(r.text, 'no auth needed');
  assert.ok(!('authorization' in mock.requests[0].headers), 'no key configured → no auth header at all');
});

test('403 usage-limit from the LOCAL brain surfaces with the openai-compatible label, unretried', async () => {
  const mock = await mockHttp((req, res) => { res.writeHead(403, { 'content-type': 'application/json' }); res.end(JSON.stringify({ error: { message: 'usage limit exceeded' } })); });
  const clock = fakeClock();
  const agent = makeKimiAgent({ sessionFile: DEMO_SESSION, wsDir: ws, model: 'x', env: { VARVEL_DATA_DIR: DATA }, execTool: async () => 'unused', retry: { attempts: 4, baseMs: 1000, capMs: 5000, sleep: clock.sleep, rand: clock.rand },
    provider: { provider: 'openai-compatible', baseUrl: mock.baseUrl, model: 'qwen3-test' } });
  const r = await agent({ system: 's', messages: [{ role: 'user', content: 'go' }] });
  assert.equal(mock.requests.length, 1, 'a 403 is NEVER retried — same taxonomy as the Kimi path');
  assert.equal(clock.sleeps.length, 0);
  assert.match(r.text, /^\(openai-compatible backend error: OpenAI-compatible HTTP 403:/, 'the operator sees WHICH brain failed');
  assert.match(r.text, /usage limit exceeded/);
  assert.match(r.text, /not retried\)$/);
  assert.equal(loadCheckpoint(r.missionId).status, 'failed');
});

test('timeout: a hung local server classifies transient and is retried (same policy as Kimi)', async () => {
  const mock = await mockHttp((req, res) => {
    if (mock.requests.length >= 2) return sendSse(res, oaiSse(oaiTextChunks('after the hang')));
    // first call hangs forever — the per-call ceiling (timeoutMs) is what kills it
  });
  const clock = fakeClock();
  const agent = makeKimiAgent({ sessionFile: DEMO_SESSION, wsDir: ws, model: 'x', env: { VARVEL_DATA_DIR: DATA }, execTool: async () => 'unused', timeoutMs: 60, retry: { attempts: 2, baseMs: 10, capMs: 20, sleep: clock.sleep, rand: clock.rand },
    provider: { provider: 'openai-compatible', baseUrl: mock.baseUrl, model: 'qwen3-test' } });
  const r = await agent({ system: 's', messages: [{ role: 'user', content: 'go' }] });
  assert.equal(r.text, 'after the hang');
  assert.equal(mock.requests.length, 2, 'timed out once, retried once, succeeded');
  assert.equal(r.stepLog.filter((s) => s.kind === 'retry').length, 1, 'the timeout retry is audited');
});

test('malformed stream: fails LOUD and unretried, never silently empty', async () => {
  const mock = await mockHttp((req, res) => sendSse(res, 'data: {this is not json\n\ndata: [DONE]\n\n'));
  const agent = makeKimiAgent({ sessionFile: DEMO_SESSION, wsDir: ws, model: 'x', env: { VARVEL_DATA_DIR: DATA }, execTool: async () => 'unused', retry: { attempts: 3, sleep: async () => { throw new Error('must not retry'); }, rand: () => 0.5 },
    provider: { provider: 'openai-compatible', baseUrl: mock.baseUrl, model: 'qwen3-test' } });
  const r = await agent({ system: 's', messages: [{ role: 'user', content: 'go' }] });
  assert.equal(mock.requests.length, 1, 'an unparseable stream is permanent — unknown shapes are never retried');
  assert.match(r.text, /openai-compatible backend error: OpenAI-compatible backend: unparseable response stream/);
  assert.match(r.text, /not retried\)$/);
});

test('a non-streaming one-shot JSON completion is accepted honestly (llama.cpp configs)', async () => {
  const mock = await mockHttp((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ choices: [{ index: 0, message: { role: 'assistant', content: 'ONE-SHOT' }, finish_reason: 'stop' }] }));
  });
  const agent = makeKimiAgent({ sessionFile: DEMO_SESSION, wsDir: ws, model: 'x', env: { VARVEL_DATA_DIR: DATA }, execTool: async () => 'unused', retry: { attempts: 1, sleep: async () => {}, rand: () => 0.5 },
    provider: { provider: 'openai-compatible', baseUrl: mock.baseUrl, model: 'qwen3-test' } });
  const r = await agent({ system: 's', messages: [{ role: 'user', content: 'go' }] });
  assert.equal(r.text, 'ONE-SHOT');
});

test('unknown provider is REFUSED with the valid set named — at resolution AND at agent build', () => {
  assert.deepEqual(BRAIN_PROVIDERS, ['kimi', 'openai-compatible']);
  assert.throws(() => resolveBrain({ env: {}, engagement: 'brain-unk-' + process.pid, request: { provider: 'vllm' } }),
    /unknown brain provider: vllm — valid: kimi, openai-compatible/);
  assert.throws(() => makeKimiAgent({ sessionFile: DEMO_SESSION, wsDir: ws, model: 'k3', env: ENV_KIMI, provider: 'bogus' }),
    /unknown brain provider: bogus — valid: kimi, openai-compatible/);
});

test('incomplete local-brain config refuses at BUILD time with the missing knob named', () => {
  const eng = 'brain-incomplete-' + process.pid;
  assert.throws(() => resolveBrain({ env: {}, engagement: eng, request: 'openai-compatible' }), /needs a base URL/);
  assert.throws(() => resolveBrain({ env: {}, engagement: eng, request: { provider: 'openai-compatible', baseUrl: 'http://x/v1' } }), /needs a model id/);
  assert.throws(() => resolveBrain({ env: {}, engagement: eng, request: { provider: 'openai-compatible', baseUrl: 'ftp://x', model: 'm' } }), /must be a valid http\(s\) URL/);
  assert.throws(() => makeKimiAgent({ sessionFile: DEMO_SESSION, wsDir: ws, model: 'x', env: { VARVEL_DATA_DIR: DATA },
    provider: { provider: 'openai-compatible', baseUrl: 'http://127.0.0.1:1/v1', model: 'm', apiKeyEnv: 'VARVEL_TEST_UNSET_KEY' } }),
    /apiKeyEnv VARVEL_TEST_UNSET_KEY names an env var that is not set/);
});

test('selection precedence: per-request > VARVEL_BRAIN_* env > engagement settings > platform default', () => {
  const eng = 'brain-prec-' + process.pid;
  Settings.for(eng).set('brain.provider', 'openai-compatible');
  Settings.for(eng).set('brain.baseUrl', 'http://settings-layer:1/v1');
  Settings.for(eng).set('brain.model', 'settings-model');
  const dflt = resolveBrain({ env: {}, engagement: 'brain-fresh-' + process.pid });
  assert.deepEqual([dflt.provider, dflt.source], ['kimi', 'default'], 'the platform default is Kimi, unchanged');
  const fromSettings = resolveBrain({ env: {}, engagement: eng });
  assert.deepEqual([fromSettings.provider, fromSettings.baseUrl, fromSettings.model, fromSettings.source], ['openai-compatible', 'http://settings-layer:1/v1', 'settings-model', 'settings']);
  const envBeatsSettings = resolveBrain({ env: { VARVEL_BRAIN_PROVIDER: 'kimi' }, engagement: eng });
  assert.deepEqual([envBeatsSettings.provider, envBeatsSettings.source], ['kimi', 'env']);
  const reqBeatsAll = resolveBrain({ env: { VARVEL_BRAIN_PROVIDER: 'kimi' }, engagement: eng, request: { provider: 'openai-compatible', baseUrl: 'http://request-layer:2/v1', model: 'req-model' } });
  assert.deepEqual([reqBeatsAll.provider, reqBeatsAll.baseUrl, reqBeatsAll.model, reqBeatsAll.source], ['openai-compatible', 'http://request-layer:2/v1', 'req-model', 'request']);
});

test('config validation pins: enum/range/unknown-key refusals + apiKeyEnv renders as a NAME', () => {
  const eng = 'brain-validate-' + process.pid;
  assert.throws(() => Settings.for(eng).set('brain.provider', 'vllm'), /must be one of kimi, openai-compatible/);
  assert.throws(() => Settings.for(eng).set('brain.timeoutMs', 600001), RangeError);
  assert.throws(() => Settings.for(eng).set('brain.timeoutMs', -1), RangeError);
  assert.throws(() => Settings.for(eng).set('brain.apiKey', 'sk-x'), /unknown setting/, 'a raw key VALUE has no home in config');
  Settings.for(eng).set('brain.apiKeyEnv', 'VARVEL_LOCAL_BRAIN_KEY');
  assert.equal(Settings.for(eng).toJSON().values['brain.apiKeyEnv'], 'VARVEL_LOCAL_BRAIN_KEY', 'the env-var NAME is not secret; the value never enters config');
  // resolveBrain never surfaces a key value even when the env var is set.
  process.env.VARVEL_LOCAL_BRAIN_KEY = 'sk-local-SECRET';
  try {
    const b = resolveBrain({ env: process.env, engagement: eng, request: { provider: 'openai-compatible', baseUrl: 'http://127.0.0.1:1/v1', model: 'm' } });
    assert.ok(!JSON.stringify(b).includes('sk-local-SECRET'));
  } finally { delete process.env.VARVEL_LOCAL_BRAIN_KEY; }
});

test('message/tool mapping units: Anthropic blocks ↔ OpenAI chat shape', () => {
  const msgs = [
    { role: 'user', content: 'objective' },
    { role: 'assistant', content: [{ type: 'thinking', thinking: 'hmm' }, { type: 'text', text: 'working' }, { type: 'tool_use', id: 't1', name: 'Bash', input: { command: 'ls' } }] },
    { role: 'user', content: [{ type: 'tool_result', tool_use_id: 't1', content: 'files' }, { type: 'text', text: 'noted' }] },
  ];
  assert.deepEqual(toOpenAIMessages('sys', msgs), [
    { role: 'system', content: 'sys' },
    { role: 'user', content: 'objective' },
    { role: 'assistant', content: 'working', tool_calls: [{ id: 't1', type: 'function', function: { name: 'Bash', arguments: '{"command":"ls"}' } }] }, // thinking never crosses
    { role: 'tool', tool_call_id: 't1', content: 'files' },
    { role: 'user', content: 'noted' },
  ]);
  assert.deepEqual(toOpenAITools([{ name: 'Bash', description: 'd', input_schema: { type: 'object', properties: {} } }]),
    [{ type: 'function', function: { name: 'Bash', description: 'd', parameters: { type: 'object', properties: {} } } }]);
  assert.equal(toOpenAITools([]), undefined, 'no tools → the field is omitted, not an empty array');
});

// --- Enclave /api/varvel/open passthrough contract pins (2026-08-25) ----------------------
// The Enclave side (../../server.mjs — VARVEL lives inside the Enclave checkout) has no
// test rig of its own and its process is LIVE, so the passthrough is pinned here as a
// source contract: the open body may carry a `brain` object whose fields cross to the
// spawned VARVEL as VARVEL_BRAIN_* env (the env precedence layer documented above), the
// reuse key must include the brain (a brain change forces a fresh spawn), and the
// load-bearing kimi default open (persona/model/effort fallback chain) stays untouched.
test('Enclave open passthrough: brain fields -> VARVEL_BRAIN_* env; kimi default untouched', () => {
  const src = readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'server.mjs'), 'utf8');
  assert.ok(src.includes('normalizeBrain'), 'the brain normalizer exists');
  for (const envName of ['VARVEL_BRAIN_PROVIDER', 'VARVEL_BRAIN_BASE_URL', 'VARVEL_BRAIN_MODEL', 'VARVEL_BRAIN_API_KEY_ENV', 'VARVEL_BRAIN_TIMEOUT_MS']) {
    assert.ok(src.includes(envName), envName + ' is forwarded');
  }
  assert.ok(/openVarvel\(persona, model, effort, brain\)/.test(src), 'the open handler passes the brain object through');
  assert.ok(src.includes('varvelBrain'), 'the reuse key tracks the brain config (a brain change must respawn)');
  // The load-bearing defaults, byte-anchored: persona falls back to 'red', effort to
  // 'high', model to the console default — WITHOUT them `open {}` would spawn sonnet.
  assert.ok(src.includes("PERSONA[personaKey] ? personaKey : 'red'"), 'persona default red intact');
  assert.ok(src.includes("KIMI_EFFORTS.includes(effort) ? effort : 'high'"), 'effort default high intact');
  assert.ok(src.includes('MODEL_ALIAS[model] || model || MODEL'), 'model fallback chain intact');
  // Secret hygiene: apiKeyEnv crosses as a NAME — no key VALUE field is ever forwarded.
  assert.ok(!/VARVEL_BRAIN_API_KEY\b(?!\w)/.test(src.replace(/VARVEL_BRAIN_API_KEY_ENV/g, '')), 'no raw key env ever crosses');
});

// --- runtime keyring (2026-09-17): the console card's run-time endpoint key -----------------
// The operator can paste an OpenAI-endpoint key into the console (Settings -> Brain / API key)
// instead of exporting it in a shell. Three things must hold, or the feature is a liability:
// env still wins (the durable, auditable path), the value is memory-only (never persisted to
// settings.json or any checkpoint), and every API answer reports PRESENCE ONLY.
test('runtime keyring: env wins, memory-only, presence-only, never persisted', async () => {
  const { setRuntimeKey, runtimeKeyPresent, brainKey } = await import('../engine/brain-provider.mjs');

  // 1. a runtime key satisfies a previously dangling name
  assert.equal(setRuntimeKey('VARVEL_TEST_BRAIN_KEY', 'sk-runtime-secret'), true, 'set reports presence');
  assert.equal(brainKey('VARVEL_TEST_BRAIN_KEY', {}), 'sk-runtime-secret', 'the key reaches the wire builder');
  assert.equal(runtimeKeyPresent('VARVEL_TEST_BRAIN_KEY', {}), true, 'presence is true');

  // 2. the environment WINS over the keyring (an exported key is the durable path)
  assert.equal(brainKey('VARVEL_TEST_BRAIN_KEY', { VARVEL_TEST_BRAIN_KEY: 'sk-from-env' }), 'sk-from-env', 'env precedence');

  // 3. an empty value clears it; a name that was never set is not "present"
  assert.equal(setRuntimeKey('VARVEL_TEST_BRAIN_KEY', ''), false, 'clear reports absence');
  assert.equal(brainKey('VARVEL_TEST_BRAIN_KEY', {}), '', 'cleared -> empty');
  assert.equal(runtimeKeyPresent('VARVEL_TEST_BRAIN_KEY', {}), false, 'cleared -> not present');
  assert.equal(runtimeKeyPresent('VARVEL_TEST_NEVER_SET', {}), false, 'unset name is not present');
  assert.throws(() => setRuntimeKey('', 'x'), /needs an env var name/, 'a key without a name refuses loudly');

  // 4. NEVER persisted: force a settings write (the durable half of the card) and prove the
  //    key VALUE is nowhere in the file — only the env var NAME, which is the schema's contract.
  Settings.for('keyring-engagement').set('brain.apiKeyEnv', 'VARVEL_TEST_BRAIN_KEY');
  setRuntimeKey('VARVEL_TEST_BRAIN_KEY', 'sk-runtime-secret');
  const persisted = readFileSync(process.env.VARVEL_SETTINGS_FILE, 'utf8');
  assert.ok(!persisted.includes('sk-runtime-secret'), 'the key value never lands on disk');
  assert.ok(persisted.includes('VARVEL_TEST_BRAIN_KEY'), 'only the env var NAME is persisted');

  // 5. the wire path and the API echo are pinned as source contracts: the agent reads through
  //    brainKey() (so a pasted key actually works) and the server echoes presence only.
  const root = join(dirname(fileURLToPath(import.meta.url)), '..');
  const runSrc = readFileSync(join(root, 'engine', 'kimi-runagent.mjs'), 'utf8');
  assert.ok(runSrc.includes('key: brainKey(brain.apiKeyEnv, env)'), 'the agent call reads the key through brainKey()');
  assert.ok(runSrc.includes('!brainKey(brain.apiKeyEnv, env)'), 'the dangling-name refusal consults the keyring too');
  const srvSrc = readFileSync(join(root, 'server.mjs'), 'utf8'); // the console server start-varvel.bat runs (varvel/server.mjs)
  assert.ok(srvSrc.includes('setRuntimeKey(envName'), 'the server route sets the runtime key');
  assert.ok(srvSrc.includes('key: { env: envName, present }'), 'the response echoes presence, never the value');

  // cleanup so later tests in this file see no stray key
  setRuntimeKey('VARVEL_TEST_BRAIN_KEY', '');
});

