// VARVEL tool-CLI tests — the agent-facing command surface, hermetic.
//   node --test varvel/test/cli.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, spawn } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { writeFileSync, rmSync, mkdirSync, readFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';

const CLI = join(dirname(fileURLToPath(import.meta.url)), '..', 'tools', 'cli.mjs');
const run = (args, env) => {
  const r = spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', timeout: 30000, ...(env ? { env } : {}) });
  let out = null;
  try { out = JSON.parse(r.stdout); } catch { out = { parseError: r.stdout.slice(0, 200), stderr: r.stderr.slice(0, 200) }; }
  return { status: r.status, out };
};

// The mock must be a SEPARATE process: spawnSync(CLI) blocks this process's event loop,
// so an in-process server would never answer the CLI's requests.
function spawnMockServer() {
  const file = join(tmpdir(), 'varvel-cli-mock-' + process.pid + '.mjs');
  writeFileSync(file, `import http from 'node:http';
http.createServer((req, res) => {
  res.writeHead(200, { 'content-type': 'text/html', server: 'nginx/1.24.0' });
  if (req.url === '/') return res.end('<a href="/admin">a</a><form action="/login" method="post"><input name="u"><input type="password" name="p"></form>');
  if (req.url === '/admin') return res.end('ok');
  res.statusCode = 404; res.end();
}).listen(0, '127.0.0.1', function () { console.log(this.address().port); });`);
  const proc = spawn(process.execPath, [file], { stdio: ['ignore', 'pipe', 'ignore'] });
  return new Promise((resolve) => {
    let buf = '';
    proc.stdout.on('data', (d) => {
      buf += d;
      const port = parseInt(buf, 10);
      if (port > 0) resolve({ proc, port, file });
    });
  });
}

test('cli jwt-forge + jwt-verify round-trip; wrong key fails', () => {
  const f = run(['jwt-forge', '{"sub":"u","role":"admin","iss":"x","exp":9999999999}', 'k1']);
  assert.equal(f.status, 0);
  assert.ok(f.out.token.split('.').length === 3);
  assert.equal(run(['jwt-verify', f.out.token, 'k1']).out.valid, true);
  assert.equal(run(['jwt-verify', f.out.token, 'k2']).out.valid, false);
});

test('cli jwt-decode: claims + red flags surface; junk exits 2 with error json', () => {
  const f = run(['jwt-forge', '{"sub":"u","exp":1}', 'k1']);
  const d = run(['jwt-decode', f.out.token]);
  assert.equal(d.out.validShape, true);
  assert.equal(d.out.payload.sub, 'u');
  assert.equal(d.out.expired, true);
  const bad = run(['jwt-decode', 'junk']);
  assert.equal(bad.status, 0, 'decode reports invalid shape without crashing');
  assert.equal(bad.out.validShape, false);
  const usage = run(['bogus']);
  assert.equal(usage.status, 2);
  assert.ok(usage.out.error);
});

test('cli crawl: real crawl through the command surface (mock in a separate process)', async () => {
  const { proc, port, file } = await spawnMockServer();
  try {
    const r = run(['crawl', `http://127.0.0.1:${port}`]);
    assert.equal(r.status, 0);
    assert.ok(r.out.endpoints.some((e) => e.path === '/admin'), 'endpoint discovered via CLI');
    assert.ok(r.out.forms.length === 1, 'form mapped via CLI');
    assert.ok(r.out.tech.some((t) => t.id === 'nginx'), 'tech fingerprint via CLI');
    assert.ok(r.out.findings.some((f) => /cleartext/i.test(f.title)), 'cleartext-password finding via CLI');
  } finally { try { proc.kill(); } catch {} rmSync(file, { force: true }); }
});

// --- clearance/cfride CLI-surface pins (2026-08-12) -------------------------------------
// (a) 'clearance mint' engagement resolution order — the live operator-miss fix:
//     explicit --engagement > the ARMED engagement (VARVEL_ENGAGEMENT, else the signed
//     Enclave session's workspace) > the legacy 'default' bucket. Hermetic: a temp
//     VARVEL_SETTINGS_FILE arms ghost 'required' with NO chain for every bucket in play,
//     so each mint REFUSES fail-closed inside resolveMintEgress — no browser ever
//     launches, no network, and the refusal JSON NAMES the resolved bucket.
// (b) the cfride flag-slot fix: a flag in the raw jsonOpts positional no longer hits
//     JSON.parse; --engagement threads to the ride (result names the bucket + the
//     vault-lookup egress id). The '{}' positional form is pinned backward compatible.
//     cfride runs against a zone that can never be in any vault, so it exits BEFORE any
//     fetch — nothing leaves the box.

// A scrubbed env: the operator shell's VARVEL_ENGAGEMENT / ENCLAVE_SESSION must never
// leak into a hermetic run.
const cleanEnv = (extra = {}) => {
  const env = { ...process.env };
  delete env.VARVEL_ENGAGEMENT;
  delete env.ENCLAVE_SESSION;
  delete env.VARVEL_SETTINGS_FILE;
  return { ...env, ...extra };
};
const tmpSettings = (buckets) => {
  const file = join(tmpdir(), 'varvel-cli-settings-' + process.pid + '-' + Math.random().toString(36).slice(2) + '.json');
  writeFileSync(file, JSON.stringify(buckets));
  return file;
};
// The demo-SIGNED Enclave session fixture (verified offline, as in identity.test.mjs):
// workspace 'pentest-northwind' is the engagement it arms. CHECKED-IN copy — the live
// session dir is mutable engagement state (a re-scoped live marcus.json failed this
// test 2026-08-26); the fixture is signed with the seam's own demo key, so the
// resolution path still proves the real seam contract.
const MARCUS_SESSION = join(dirname(fileURLToPath(import.meta.url)), 'fixtures', 'identity-marcus.json');

test('cli clearance mint: engagement resolution is explicit flag > armed engagement > legacy default', () => {
  const file = tmpSettings({
    'flag-eng': { 'ghost.mode': 'required' },
    'armed-eng': { 'ghost.mode': 'required' },
    'pentest-northwind': { 'ghost.mode': 'required' },
    default: { 'ghost.mode': 'required' },
  });
  try {
    const url = 'http://127.0.0.1:9/x'; // unreachable is fine: the refusal precedes any launch
    // 1. the explicit flag beats the armed engagement
    let r = run(['clearance', 'mint', url, '--engagement', 'flag-eng'], cleanEnv({ VARVEL_SETTINGS_FILE: file, VARVEL_ENGAGEMENT: 'armed-eng' }));
    assert.equal(r.status, 0, 'a fail-closed refusal is data, not a crash: ' + JSON.stringify(r.out));
    assert.equal(r.out.refused, true, 'required + no chain refuses BEFORE any browser launches');
    assert.equal(r.out.engagement, 'flag-eng', 'the explicit flag wins over the armed engagement');
    // 2. no flag: the ARMED engagement becomes the default bucket (env arm)…
    r = run(['clearance', 'mint', url], cleanEnv({ VARVEL_SETTINGS_FILE: file, VARVEL_ENGAGEMENT: 'armed-eng' }));
    assert.equal(r.out.refused, true);
    assert.equal(r.out.engagement, 'armed-eng', 'absent the flag, the armed engagement is the bucket (the operator-miss fix)');
    // 2b. …or the SIGNED Enclave session's workspace when no env arm exists
    r = run(['clearance', 'mint', url], cleanEnv({ VARVEL_SETTINGS_FILE: file, ENCLAVE_SESSION: MARCUS_SESSION }));
    assert.equal(r.out.refused, true);
    assert.equal(r.out.engagement, 'pentest-northwind', "the signed session's workspace arms the bucket");
    // 3. nothing armed anywhere: the legacy 'default' bucket, honestly NAMED in the result
    r = run(['clearance', 'mint', url], cleanEnv({ VARVEL_SETTINGS_FILE: file }));
    assert.equal(r.out.refused, true);
    assert.equal(r.out.engagement, 'default', 'nothing armed -> the legacy default bucket (pre-fix behavior), never a silent guess');
  } finally { rmSync(file, { force: true }); }
});

test('cli cfride: a flag in the raw jsonOpts slot parses cleanly and --engagement threads to the ride', () => {
  // ghost ON + chain under 'flag-eng': the threaded engagement must drive the
  // vault-lookup id (rideEgressId) — observable proof the flag reached ghostSettings.
  const file = tmpSettings({ 'flag-eng': { 'ghost.mode': 'on', 'ghost.chain': 'socks5://127.0.0.1:1080' } });
  try {
    const url = 'http://zone-no-clearance.invalid/'; // in no vault -> ok:false BEFORE any fetch
    // the pre-fix crash shape: '--engagement' sat in the JSON.parsed positional slot
    let r = run(['cfride', url, 'raw', '--engagement', 'flag-eng'], cleanEnv({ VARVEL_SETTINGS_FILE: file }));
    assert.equal(r.status, 0, 'parses cleanly — no JSON.parse crash: ' + JSON.stringify(r.out));
    assert.equal(r.out.ok, false);
    assert.match(r.out.reason, /no valid clearance/);
    assert.equal(r.out.engagement, 'flag-eng', '--engagement threads to the ride result');
    assert.equal(r.out.egressId, 'socks5://127.0.0.1:1080', "the threaded engagement's ghost chain drives the vault-lookup id");
    // a non-raw tool + a trailing flag: the flag is not mistaken for maxPages either
    r = run(['cfride', url, 'crawl', '--engagement', 'flag-eng'], cleanEnv({ VARVEL_SETTINGS_FILE: file }));
    assert.equal(r.status, 0);
    assert.equal(r.out.engagement, 'flag-eng');
    assert.match(r.out.reason, /no valid clearance/);
  } finally { rmSync(file, { force: true }); }
});

test("cli cfride: the '{}' raw-opts positional keeps working (backward compatible)", () => {
  // Hermetic ghost-OFF store: the operator box's real default store has ghost armed
  // (the live hunt chain) and must not leak the armed egressId into this legacy-path run.
  const file = tmpSettings({ default: { 'ghost.mode': 'off' } });
  try {
    const r = run(['cfride', 'http://zone-no-clearance.invalid/', 'raw', '{}', '--full-body'], cleanEnv({ VARVEL_SETTINGS_FILE: file }));
    assert.equal(r.status, 0, 'the legacy {} positional still parses: ' + JSON.stringify(r.out));
    assert.equal(r.out.ok, false);
    assert.match(r.out.reason, /no valid clearance/);
    assert.equal(r.out.engagement, 'default', 'nothing armed -> legacy default bucket');
    assert.equal(r.out.egressId, 'direct');
  } finally { rmSync(file, { force: true }); }
});

// --- teardown pin (2026-08-25, the libuv assertion) --------------------------------------
// `h1watch scan ... --emit-intake` against a live source aborted at process exit with
// 'Assertion failed: !(handle->flags & UV_HANDLE_CLOSING), file src\win\async.c'
// (exit 127): process.exit() raced undici's keep-alive socket teardown. The cli now
// drains via exitCode (+ an unref'd stuck-handle watchdog). This test runs the exact
// repro hermetically — a loopback H1-shaped mock, three sequential fetches — and pins
// a clean exit with NO assertion string on stderr.
function spawnMockH1() {
  const file = join(tmpdir(), 'varvel-cli-mock-h1-' + process.pid + '.mjs');
  writeFileSync(file, `import http from 'node:http';
http.createServer((req, res) => {
  res.writeHead(200, { 'content-type': 'application/json' });
  if (req.url.startsWith('/hackers/programs/')) {
    if (req.url.endsWith('/structured_scopes')) return res.end(JSON.stringify({ data: [{ attributes: { asset_identifier: 'example.com', asset_type: 'DOMAIN' } }] }));
    return res.end(JSON.stringify({ data: { id: '1', attributes: { handle: 'acme', name: 'Acme', policy: 'no automated testing', offers_bounties: true } } }));
  }
  res.end(JSON.stringify({ data: [{ id: '1', type: 'program', attributes: { handle: 'acme', name: 'Acme', offers_bounties: true } }], links: {} }));
}).listen(0, '127.0.0.1', function () { console.log(this.address().port); });`);
  const proc = spawn(process.execPath, [file], { stdio: ['ignore', 'pipe', 'ignore'] });
  return new Promise((resolve) => {
    let buf = '';
    proc.stdout.on('data', (d) => {
      buf += d;
      const port = parseInt(buf, 10);
      if (port > 0) resolve({ proc, port, file });
    });
  });
}

test('cli teardown: h1watch scan exits clean — no libuv UV_HANDLE_CLOSING assertion', async () => {
  const { proc, port, file } = await spawnMockH1();
  const stateDir = join(tmpdir(), 'varvel-cli-h1watch-' + process.pid + '-' + Math.random().toString(36).slice(2));
  try {
    const r = spawnSync(process.execPath, [CLI, 'h1watch', 'scan', '--base', 'http://127.0.0.1:' + port, '--emit-intake'],
      { encoding: 'utf8', timeout: 30000, env: { ...process.env, VARVEL_H1WATCH_DIR: stateDir, VARVEL_H1_TOKEN: 'test-token', VARVEL_H1_USER: 'test-user' } });
    assert.equal(r.status, 0, 'clean exit (was 127/assert-abort): ' + (r.stderr || '').slice(0, 200));
    assert.ok(!(r.stderr || '').includes('Assertion failed'), 'no libuv assertion on stderr');
    assert.ok(!(r.stderr || '').includes('UV_HANDLE_CLOSING'), 'no closing-handle race at teardown');
    const out = JSON.parse(r.stdout.slice(r.stdout.indexOf('{'))); // the scan case prints human lines before the JSON result
    assert.equal(out.ok, true, 'the scan itself completed: ' + r.stdout.slice(0, 200));
    assert.ok(out.outbox && out.outbox.written.length >= 1, '--emit-intake wrote the reviewable intake file');
  } finally { try { proc.kill(); } catch {} rmSync(file, { force: true }); rmSync(stateDir, { recursive: true, force: true }); }
});

// --- brain passthrough pin (2026-08-25, the local-brain seam) ------------------------------
// `resume <id> --brain openai-compatible [--brain-url u] [--brain-model m]` maps onto the
// existing provider opts (engine/brain-provider.mjs) and lands the resumed mission on the
// openai-compatible endpoint. Hermetic: the mock brain is a SEPARATE process (spawnSync
// blocks this loop), answering one SSE end_turn; the checkpoint is minted through
// engine/missions.mjs itself. Also pinned: the flag VALUE never leaks into the
// instruction text, and an absent --brain keeps the default Kimi path (build refusal
// without a credential proves --brain did not silently reroute).
function spawnMockBrain(hitsFile) {
  const file = join(tmpdir(), 'varvel-cli-mock-brain-' + process.pid + '.mjs');
  writeFileSync(file, `import http from 'node:http';
import { appendFileSync } from 'node:fs';
const enc = (o) => 'data: ' + JSON.stringify(o) + '\\n\\n';
http.createServer((req, res) => {
  let body = '';
  req.on('data', (c) => (body += c));
  req.on('end', () => {
    appendFileSync(${JSON.stringify(hitsFile)}, JSON.stringify({ url: req.url, model: (JSON.parse(body || '{}') || {}).model }) + '\\n');
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    res.end(enc({ choices: [{ index: 0, delta: { role: 'assistant', content: 'RESUMED-ON-LOCAL-BRAIN' }, finish_reason: null }] })
      + enc({ choices: [{ index: 0, delta: {}, finish_reason: 'stop' }] }) + 'data: [DONE]\\n\\n');
  });
}).listen(0, '127.0.0.1', function () { console.log(this.address().port); });`);
  const proc = spawn(process.execPath, [file], { stdio: ['ignore', 'pipe', 'ignore'] });
  return new Promise((resolve) => {
    let buf = '';
    proc.stdout.on('data', (d) => {
      buf += d;
      const port = parseInt(buf, 10);
      if (port > 0) resolve({ proc, port, file });
    });
  });
}

test('cli resume --brain: the mission resumes onto the openai-compatible provider, flags threaded', async () => {
  const dataDir = join(tmpdir(), 'varvel-cli-brain-' + process.pid + '-' + Math.random().toString(36).slice(2));
  const wsDir = join(dataDir, 'ws');
  const hitsFile = join(dataDir, 'hits.jsonl');
  mkdirSync(wsDir, { recursive: true });
  // A real checkpoint via the engine's own writer (the resume contract's input shape).
  process.env.VARVEL_DATA_DIR = dataDir;
  const { saveCheckpoint } = await import('../engine/missions.mjs');
  saveCheckpoint({ missionId: 'msn-brain-cli', status: 'awaiting-input', wsDir, msgs: [{ role: 'user', content: 'the objective' }], ledger: [], retries: [], turnsTotal: 1 });
  const { proc, port, file } = await spawnMockBrain(hitsFile);
  try {
    const r = run(['resume', 'msn-brain-cli', 'carry on', '--brain', 'openai-compatible', '--brain-url', 'http://127.0.0.1:' + port + '/v1', '--brain-model', 'qwen3-test'], cleanEnv({ VARVEL_DATA_DIR: dataDir }));
    assert.equal(r.status, 0, JSON.stringify(r.out).slice(0, 300));
    assert.equal(r.out.provider, 'openai-compatible', 'the result names the brain it ran on');
    assert.equal(r.out.text, 'RESUMED-ON-LOCAL-BRAIN', 'the local brain answered the resumed mission');
    assert.equal(r.out.reconstructed, true, 'the checkpoint conversation was reconstructed');
    const hits = readFileSync(hitsFile, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    assert.equal(hits.length, 1, 'exactly one completion call');
    assert.equal(hits[0].url, '/v1/chat/completions');
    assert.equal(hits[0].model, 'qwen3-test', '--brain-model threaded to the wire');
    // The flag value must NOT leak into the instruction text (the filter gap):
    const missionFile = join(dataDir, readdirSync(dataDir).find((f) => f.endsWith('.mission.json')));
    const msgs = JSON.parse(readFileSync(missionFile, 'utf8')).msgs;
    const lastUser = [...msgs].reverse().find((m) => m.role === 'user');
    const lastText = typeof lastUser.content === 'string' ? lastUser.content : JSON.stringify(lastUser.content);
    assert.ok(!lastText.includes('openai-compatible') && !lastText.includes('qwen3-test'), 'flag values stayed out of the instruction: ' + lastText.slice(0, 120));
    assert.ok(lastText.includes('carry on'), 'the instruction itself survived');
  } finally { try { proc.kill(); } catch {} rmSync(file, { force: true }); rmSync(dataDir, { recursive: true, force: true }); }
});

test('cli resume WITHOUT --brain: the default path is untouched (Kimi credential refusal, no reroute)', async () => {
  const dataDir = join(tmpdir(), 'varvel-cli-brain-def-' + process.pid + '-' + Math.random().toString(36).slice(2));
  const wsDir = join(dataDir, 'ws');
  mkdirSync(wsDir, { recursive: true });
  process.env.VARVEL_DATA_DIR = dataDir;
  const { saveCheckpoint } = await import('../engine/missions.mjs');
  saveCheckpoint({ missionId: 'msn-brain-default', status: 'awaiting-input', wsDir, msgs: [{ role: 'user', content: 'the objective' }], ledger: [], retries: [], turnsTotal: 1 });
  // HOME/USERPROFILE pointed at the empty tmp dir: no OAuth pair, no legacy key ->
  // the UNCHANGED default path refuses at agent build, proving --brain is what reroutes.
  const env = cleanEnv({ VARVEL_DATA_DIR: dataDir, HOME: dataDir, USERPROFILE: dataDir, KIMI_API_KEY: '', VARVEL_BRAIN_PROVIDER: '', VARVEL_BRAIN_BASE_URL: '', VARVEL_BRAIN_MODEL: '' });
  const r = run(['resume', 'msn-brain-default'], env);
  try {
    assert.equal(r.status, 2, 'a build refusal is an {error} result (cli maps errors to exit 2)');
    assert.match(String(r.out.error || ''), /Kimi credential/, 'the default path refuses exactly as before: ' + JSON.stringify(r.out).slice(0, 200));
    assert.equal(r.out.provider, undefined, 'no provider reroute without --brain');
  } finally { rmSync(dataDir, { recursive: true, force: true }); }
});

test('cli brainharness: an unknown --suite refuses LOUDLY (exit 2) — never a vacuous PASS over zero gates', () => {
  // Pre-fix repro: --suite fideltiy ran ZERO gates and printed pass:true with exit 0
  // (a grader that passes nothing grades nothing — the harness's own main() refuses).
  // Hermetic: planBrain succeeds from env, the bogus suite must fail BEFORE any fetch
  // (the base URL is the discard port — unreachable by construction).
  const dataDir = join(tmpdir(), 'varvel-cli-bh-' + process.pid + '-' + Math.random().toString(36).slice(2));
  mkdirSync(dataDir, { recursive: true });
  const env = cleanEnv({
    VARVEL_DATA_DIR: dataDir,
    VARVEL_SETTINGS_FILE: join(dataDir, 'settings.json'),
    VARVEL_BRAIN_PROVIDER: 'openai-compatible',
    VARVEL_BRAIN_BASE_URL: 'http://127.0.0.1:9/v1',
    VARVEL_BRAIN_MODEL: 'm',
  });
  try {
    const r = run(['brainharness', '--suite', 'fideltiy'], env);
    assert.equal(r.status, 2, 'a typo\'d suite is a usage error, not a grading run: ' + JSON.stringify(r.out).slice(0, 200));
    assert.match(String(r.out.error || ''), /bad --suite/, 'the refusal names the bad flag');
    assert.match(String(r.out.error || ''), /fidelity/, 'the refusal names the valid set');
  } finally { rmSync(dataDir, { recursive: true, force: true }); }
});
