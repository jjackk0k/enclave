// VARVEL — governed Kimi K3 backend (a `runAgent` the campaign uses, crossing the Enclave hook).
//
// `claude -p` HANGS against Kimi's endpoint, so VARVEL cannot drive Kimi through the Claude CLI.
// This backend talks to Kimi's Anthropic-compatible API directly (api.kimi.com/coding/v1/
// messages — the raw path that WORKS), runs a host-side tool loop (Bash/Read/Write/Edit), and —
// critically — routes EVERY tool call through the SAME Enclave PreToolUse hook the Claude path
// uses. So a Kimi-driven campaign is governed IDENTICALLY: signed scope, Cedar PDP, workspace
// confinement, hash-chained audit. It authorizes nothing itself; the hook is the sole authority.
//
// Returns `{ text, steps, denials, stepLog }` — a drop-in for makeClaudeAgent so the campaign
// uses it unchanged. This is the "VARVEL keeps running on Kimi after the Claude window" backend.
//
// SESSION RESILIENCE (documented gap #2): the stream can DIE mid-turn on a flaky operator
// network ('terminated', 'fetch failed', socket resets, 5xx, timeouts) — each death used to
// orphan the mission and burn the turn. Now: backend errors are CLASSIFIED (transient vs
// permanent), transients auto-retry with jittered exponential backoff (audited per retry —
// a silent retry would falsify the noise record), permanents fail loudly on first sight.
// Every tool-call boundary is CHECKPOINTED (engine/missions.mjs) with an executed-call
// ledger, so a crash/kill resumes from the last boundary instead of restarting — and a
// resumed mission NEVER re-fires a tool call that already executed (skip/reuse via the
// ledger; see the reconcile path in kimiAgent). Turn/byte thresholds SUGGEST a session
// split (never forced, never mid-tool-call); the split itself is cli/server-triggered.

import { spawnSync, spawn } from 'node:child_process';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { join, resolve, isAbsolute, relative } from 'node:path';
import { homedir } from 'node:os';
import { createHash } from 'node:crypto';
import { HOOK_PATH } from './live.mjs';
import { loadCheckpoint, saveCheckpoint, newMissionId, shouldSplit } from './missions.mjs';
import { resolveBrain, callOpenAI, brainKey } from './brain-provider.mjs';

// Resolve the Kimi backend from ~/.kimicode/config.json (the coding-subscription key + base).
// Credential precedence (2026-08-05 fix): env keys -> kimi-code OAuth (the operator's CURRENT
// subscription, auto-refreshed) -> cfg.apiKey (legacy static key). The old order let an
// exhausted legacy key shadow the live OAuth subscription (the HTTP 403 usage-limit Jack hit).
const OAUTH_FILE = join(homedir(), '.kimi-code', 'credentials', 'kimi-code.json');
const OAUTH_TOKEN_URL = 'https://auth.kimi.com/api/oauth/token';
const OAUTH_CLIENT_ID = '17e5f671-d194-4dfb-9706-5516cb48c098'; // kimi-code public client id (from the CLI binary)

function readOAuthFile() {
  try { const j = JSON.parse(readFileSync(OAUTH_FILE, 'utf8')); return j && j.access_token ? j : null; } catch { return null; }
}
export function kimiConfig(env = process.env) {
  let cfg = {}; try { cfg = JSON.parse(readFileSync(join(homedir(), '.kimicode', 'config.json'), 'utf8')) || {}; } catch { /* none */ }
  const oauth = readOAuthFile();
  const okKey = (k) => !!k && !/PASTE_YOUR/.test(k);
  const key = env.KIMI_API_KEY || env.MOONSHOT_API_KEY || (oauth ? oauth.access_token : '') || cfg.apiKey || '';
  const base = (cfg.baseUrl || 'https://api.kimi.com/coding').replace(/\/+$/, '');
  let model = env.KIMI_MODEL || (cfg.models && cfg.models.main) || 'k3';
  model = String(model).replace(/\s*\[1m\]\s*$/i, ''); if (/^kimi-k3$/i.test(model)) model = 'k3'; // raw API wants base id
  return { key, cfgKey: cfg.apiKey || '', base, model, oauth: !!oauth, ok: okKey(env.KIMI_API_KEY || env.MOONSHOT_API_KEY) || !!oauth || okKey(cfg.apiKey) };
}

// The OAuth access_token lives 15 min (expires_in 900) — a mission runs for hours, so the key
// is re-resolved on EVERY model call: fresh file token -> refresh (write-back = the CLI's own
// flow, serialized so concurrent agents never double-refresh) -> legacy static key as last resort.
let refreshing = null;
async function refreshOAuth() {
  if (refreshing) return refreshing;
  refreshing = (async () => {
    const cur = readOAuthFile();
    if (!cur || !cur.refresh_token) throw new Error('no kimi-code OAuth credentials');
    const res = await fetch(OAUTH_TOKEN_URL, {
      method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: OAUTH_CLIENT_ID, grant_type: 'refresh_token', refresh_token: cur.refresh_token }),
    });
    if (!res.ok) throw new Error('OAuth refresh HTTP ' + res.status);
    const j = await res.json();
    const next = { access_token: j.access_token, refresh_token: j.refresh_token || cur.refresh_token,
      expires_at: Math.floor(Date.now() / 1000) + (j.expires_in || 900), expires_in: j.expires_in || 900,
      scope: j.scope || cur.scope, token_type: j.token_type || cur.token_type || 'Bearer' };
    writeFileSync(OAUTH_FILE, JSON.stringify(next, null, 2) + '\n');
    return next.access_token;
  })().finally(() => { refreshing = null; });
  return refreshing;
}
async function resolveKimiKey(env, cfgKey) {
  const envKey = env.KIMI_API_KEY || env.MOONSHOT_API_KEY;
  if (envKey) return envKey;
  const fresh = () => { const o = readOAuthFile(); return (o && Number(o.expires_at || 0) - Math.floor(Date.now() / 1000) > 120) ? o.access_token : null; };
  const cur = fresh();
  if (cur) return cur;
  if (readOAuthFile()) {
    try { return await refreshOAuth(); } catch {
      const rotated = fresh(); // the CLI may have rotated the pair for us in the meantime
      if (rotated) return rotated;
    }
  }
  if (cfgKey) return cfgKey;
  throw new Error('no usable Kimi credential (env / kimi-code OAuth / ~/.kimicode/config.json)');
}
// Kimi coding models selectable in the picker, with their effort modes (K3 supports reasoning
// effort; both accept the same low|medium|high scale on the API — high = deepest).
export const KIMI_MODELS = ['k3', 'kimi-k2.7-code'];
export const KIMI_EFFORTS = ['low', 'medium', 'high'];
export const isKimiModel = (m) => KIMI_MODELS.includes(String(m || '')) || /^(k3|kimi-k)/i.test(String(m || ''));

const TOOLS = [
  { name: 'Bash', description: 'Run a shell command in the workspace; returns stdout+stderr. Use curl/HTTP to reach in-scope targets.', input_schema: { type: 'object', properties: { command: { type: 'string' } }, required: ['command'] } },
  { name: 'Read', description: 'Read a text file in the workspace.', input_schema: { type: 'object', properties: { file_path: { type: 'string' } }, required: ['file_path'] } },
  { name: 'Write', description: 'Write (overwrite) a text file in the workspace.', input_schema: { type: 'object', properties: { file_path: { type: 'string' }, content: { type: 'string' } }, required: ['file_path', 'content'] } },
  { name: 'Edit', description: 'Exact string replace in a workspace file.', input_schema: { type: 'object', properties: { file_path: { type: 'string' }, old_string: { type: 'string' }, new_string: { type: 'string' } }, required: ['file_path', 'old_string', 'new_string'] } },
];

// Cross the Enclave PreToolUse hook for one tool call — same contract Claude Code uses.
// Fails CLOSED (deny) on any hook error. `env` is inherited so ENCLAVE_APPROVAL (the campaign's
// countersigned-exploit bridge) reaches the hook.
export function hookDecision(name, input, { sessionFile, wsDir, container, env = process.env }) {
  const payload = JSON.stringify({ tool_name: name, tool_input: input || {}, cwd: wsDir });
  try {
    const r = spawnSync('node', ['--no-warnings', HOOK_PATH], {
      input: payload, encoding: 'utf8', timeout: 20000, windowsHide: true, // no console flash per governed call
      env: { ...env, ENCLAVE_SESSION: sessionFile, ENCLAVE_WORKSPACE_DIR: wsDir, ENCLAVE_CONTAINER: container || '' },
    });
    const out = JSON.parse(r.stdout || '{}');
    const d = out.hookSpecificOutput || {};
    return { allow: d.permissionDecision === 'allow', reason: d.permissionDecisionReason || '', action: d.mappedAction };
  } catch (e) { return { allow: false, reason: 'hook error (fail-closed): ' + (e && e.message || e) }; }
}

const CAP = 60000;
// Shell selection: the model emits POSIX; cmd.exe mangles it (the 2026-08-05 manhuaus run
// burned its opening turns on "'head' is not recognized"). Prefer Git Bash on Windows when
// present (VARVEL_BASH overrides); fall back to the cmd behavior everywhere else.
const BASH = (() => {
  if (process.platform !== 'win32') return null;
  for (const p of [process.env.VARVEL_BASH, 'C:/Program Files/Git/bin/bash.exe', 'C:/Program Files (x86)/Git/bin/bash.exe'])
    if (p && existsSync(p)) return p;
  return null;
})();
// Async so a long Bash tool call (curl/scan) never BLOCKS the node event loop / VARVEL server.
async function execTool(name, input, wsDir, extraEnv = {}) {
  // Enforcement-layer confinement (mirrors agent-backend.mjs): the hook is the sole authority,
  // but file tools ALSO refuse any path that resolves outside the sealed workspace — so an
  // absolute path at the operator's memory/profile/credential trees is dead on arrival even in
  // a defense-in-depth failure. Note wsDir itself may be reached via an absolute path; the
  // check is on the RESOLVED relative position, not on string shape.
  const root = resolve(wsDir);
  // Git-Bash/POSIX drive form (/c/Users → C:/Users) — the model on Windows emits these;
  // normalize before confinement AND execution or the workspace's own files die on ENOENT.
  const normDrive = (p) => { const s = String(p); const m = /^\/(?:mnt\/)?([a-zA-Z])(?=\/|$)/.exec(s); return m ? m[1].toUpperCase() + ':' + s.slice(m[0].length) : s; };
  const abspath = (p) => {
    const q = normDrive(p);
    const abs = isAbsolute(q) ? resolve(q) : resolve(root, q);
    const rel = relative(root, abs);
    if (rel.split(/[\\/]/)[0] === '..' || isAbsolute(rel)) throw new Error('path outside the sealed workspace');
    return abs;
  };
  try {
    if (name === 'Bash') {
      return await new Promise((res) => {
        const child = BASH
          ? spawn(BASH, ['-c', String(input.command || '')], { cwd: wsDir, windowsHide: true, env: { ...process.env, ...extraEnv } })
          : spawn(String(input.command || ''), { cwd: wsDir, shell: true, windowsHide: true, env: { ...process.env, ...extraEnv } });
        let out = '', done = false;
        const fin = (extra = '') => { if (done) return; done = true; clearTimeout(t); res(((out + extra).slice(0, CAP)) || '(no output)'); };
        const t = setTimeout(() => { try { child.kill(); } catch {} fin('\n(timeout)'); }, 180000);
        child.stdout.on('data', (d) => { if (out.length < CAP) out += d; });
        child.stderr.on('data', (d) => { if (out.length < CAP) out += d; });
        child.on('close', () => fin());
        child.on('error', (e) => fin('\nERROR: ' + e.message));
      });
    }
    if (name === 'Read') { const p = abspath(input.file_path); if (!existsSync(p)) return 'ERROR: no such file'; const c = readFileSync(p, 'utf8'); return c.length > CAP ? c.slice(0, CAP) + '\n…[truncated]' : c; }
    if (name === 'Write') { writeFileSync(abspath(input.file_path), String(input.content ?? '')); return 'OK: wrote ' + input.file_path; }
    if (name === 'Edit') { const p = abspath(input.file_path); if (!existsSync(p)) return 'ERROR: no such file'; let c = readFileSync(p, 'utf8'); const os = String(input.old_string ?? ''); if (!c.includes(os)) return 'ERROR: old_string not found'; writeFileSync(p, c.replace(os, String(input.new_string ?? ''))); return 'OK: edited ' + input.file_path; }
    return 'ERROR: unknown tool ' + name;
  } catch (e) { return 'ERROR: ' + (e && e.message || e); }
}

// ---------------------------------------------------------------------------
// BACKEND ERROR TAXONOMY. Two classes, decided ONCE here so the retry loop never guesses:
//   TRANSIENT — the stream/connection died or the backend is temporarily unable:
//     undici socket deaths ('terminated', 'fetch failed'), socket resets
//     (ECONNRESET/EPIPE/ECONNREFUSED/ETIMEDOUT/EAI_AGAIN), read timeouts/aborts,
//     HTTP 408 / 429 (throttling — backoff is exactly what 429 asks for) / any 5xx.
//   PERMANENT — retrying cannot help and must NOT be attempted: 4xx auth/quota
//     (401/403 — the Kimi 403 usage-limit Jack hit), 400/404/422, missing credentials.
// classifyBackendError never throws; an unrecognized shape reads PERMANENT (fail loudly,
// never burn turns retrying an unknown error class).
export function classifyBackendError(e) {
  const msg = String((e && e.message) || e || '');
  const status = Number(e && e.status) || null;
  if (status) {
    if (status === 408 || status === 429 || status >= 500) return { transient: true, kind: 'http-' + status, status };
    return { transient: false, kind: 'http-' + status, status };
  }
  if (/terminated|fetch failed|socket hang up|econnreset|epipe|econnrefused|etimedout|eai_again|enetunreach|ehostunreach|network|timed?\s*out|timeout|aborted|abort/i.test(msg))
    return { transient: true, kind: 'stream-death', status: null };
  if (/\bhttp[_ ]?5\d\d\b/i.test(msg)) return { transient: true, kind: 'http-5xx', status: null };
  if (/\bhttp[_ ]?(4\d\d)\b/i.test(msg)) return { transient: false, kind: 'http-4xx', status: null };
  return { transient: false, kind: 'unknown', status: null };
}

// Bounded retry with JITTERED EXPONENTIAL BACKOFF. Defaults (field-tuned): 4 attempts,
// 1.5s base, 20s cap — env-tunable (VARVEL_KIMI_RETRY_ATTEMPTS / _BASE_MS / _CAP_MS),
// and every knob injectable (tests pass a fake sleep + rand: no wall-clock waits).
export function retryPolicy(env = process.env, overrides = {}) {
  const num = (v, d) => { const n = Number(v); return Number.isFinite(n) && n > 0 ? n : d; };
  return {
    attempts: Math.max(1, Math.min(10, Math.floor(num(overrides.attempts ?? env.VARVEL_KIMI_RETRY_ATTEMPTS, 4)))),
    baseMs: num(overrides.baseMs ?? env.VARVEL_KIMI_RETRY_BASE_MS, 1500),
    capMs: num(overrides.capMs ?? env.VARVEL_KIMI_RETRY_CAP_MS, 20000),
    sleep: typeof overrides.sleep === 'function' ? overrides.sleep : (ms) => new Promise((r) => setTimeout(r, ms)),
    rand: typeof overrides.rand === 'function' ? overrides.rand : Math.random,
  };
}

// delay before attempt (attempt+1): base * 2^(attempt-1), capped, then jittered DOWN to
// [50%, 100%] of that — thundering-herd-safe, and the cap ALWAYS holds (post-jitter).
export function backoffDelay(attempt, pol) {
  const exp = Math.min(pol.capMs, pol.baseMs * 2 ** (Math.max(1, attempt) - 1));
  return Math.floor(exp * (0.5 + 0.5 * pol.rand()));
}

const sha256 = (s) => createHash('sha256').update(String(s)).digest('hex');
// Ledger entries bound the stored result body (8KB) — full digest keeps it honest.
const LEDGER_RESULT_CAP = 8000;

// One streaming Kimi call → { content:[blocks], stop_reason }. (fetch + SSE, like the CLI adapter.)
async function callKimi({ base, key, model, effort, system, tools, messages, maxTokens = 16000, timeoutMs = 0 }) {
  const payload = { model, max_tokens: maxTokens, system, tools, messages, stream: true };
  if (effort && effort !== 'off') payload.reasoning_effort = effort;
  // Opt-in per-call inactivity ceiling (VARVEL_KIMI_CALL_TIMEOUT_MS; default 0 = off —
  // the field failures were stream DEATHS, not hangs). An abort classifies transient.
  const signal = Number(timeoutMs) > 0 ? AbortSignal.timeout(Number(timeoutMs)) : undefined;
  const res = await fetch(base + '/v1/messages', { method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer ' + key, 'x-api-key': key, 'anthropic-version': '2023-06-01' }, body: JSON.stringify(payload), signal });
  if (!res.ok) { const t = await res.text().catch(() => ''); const e = new Error('Kimi HTTP ' + res.status + ': ' + t.slice(0, 300)); e.status = res.status; e.text = t; throw e; }
  const reader = res.body.getReader(); const dec = new TextDecoder(); let buf = ''; const blocks = []; let stop = null;
  while (true) {
    const { done, value } = await reader.read(); if (done) break;
    buf += dec.decode(value, { stream: true }); let i;
    while ((i = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, i).replace(/\r$/, ''); buf = buf.slice(i + 1);
      if (!line.startsWith('data:')) continue; const d = line.slice(5).trim(); if (!d || d === '[DONE]') continue;
      let ev; try { ev = JSON.parse(d); } catch { continue; }
      if (ev.type === 'content_block_start') { const b = ev.content_block || {}; blocks[ev.index] = { type: b.type, text: '', thinking: '', signature: '', id: b.id, name: b.name, inputJson: '' }; }
      else if (ev.type === 'content_block_delta') { const b = blocks[ev.index]; if (!b) continue; const dl = ev.delta || {}; if (dl.type === 'text_delta') b.text += dl.text || ''; else if (dl.type === 'thinking_delta') b.thinking += dl.thinking || ''; else if (dl.type === 'input_json_delta') b.inputJson += dl.partial_json || ''; else if (dl.type === 'signature_delta') b.signature += dl.signature || ''; }
      else if (ev.type === 'message_delta') { if (ev.delta && ev.delta.stop_reason) stop = ev.delta.stop_reason; }
    }
  }
  const content = [];
  for (const b of blocks) { if (!b) continue; if (b.type === 'thinking') { const t = { type: 'thinking', thinking: b.thinking }; if (b.signature) t.signature = b.signature; content.push(t); } else if (b.type === 'text') content.push({ type: 'text', text: b.text }); else if (b.type === 'tool_use') { let input = {}; try { input = b.inputJson ? JSON.parse(b.inputJson) : {}; } catch {} content.push({ type: 'tool_use', id: b.id, name: b.name, input }); } }
  return { content, stop_reason: stop };
}

// Build the governed Kimi runAgent. `sessionFile` = signed session, `wsDir` = sealed workspace,
// `model`/`effort` from the picker. Returns a runAgent({ system, messages, onStep, resumeId, resume }).
// Session resilience opts: `engagement` (statestore refs + split handoffs), `retry` (policy
// overrides, incl. injectable sleep/rand for tests), `execTool` (execution seam for tests —
// governance is untouched: every call still crosses the hook first), `timeoutMs` (per-call
// stream ceiling; default env VARVEL_KIMI_CALL_TIMEOUT_MS or 0 = off).
// `provider` (ADDITIVE local-brain seam): per-request brain override — a provider name or
// partial { provider, baseUrl, model, apiKeyEnv, timeoutMs }, resolved by
// engine/brain-provider.mjs (request > VARVEL_BRAIN_* env > brain.* engagement settings >
// platform default 'kimi'). The Kimi path is byte-identical to before; 'openai-compatible'
// points the SAME governed loop (hook, ledger, checkpoint, retry) at a local
// OpenAI-compatible endpoint (vLLM / llama.cpp server).
export function makeKimiAgent({ sessionFile, wsDir, model, effort = 'high', container = '', maxTurns = 24, env = process.env, extraEnv = {}, engagement = null, retry = null, execTool: execOverride = null, timeoutMs = null, provider = null } = {}) {
  const c = kimiConfig(env);
  const brain = resolveBrain({ env, engagement: engagement || env.VARVEL_ENGAGEMENT || null, request: provider }); // unknown provider refuses HERE, never mid-mission
  if (brain.provider === 'kimi' && !c.ok) throw new Error('no Kimi credential (kimi-code OAuth or ~/.kimicode/config.json)');
  // The key VALUE never enters config — apiKeyEnv NAMES the env var. A key exported in the
  // environment or pasted into the console's runtime keyring (this process's memory only)
  // both satisfy it; a dangling NAME with neither refuses here, never mid-mission.
  if (brain.provider !== 'kimi' && brain.apiKeyEnv && !brainKey(brain.apiKeyEnv, env)) throw new Error('openai-compatible brain: apiKeyEnv ' + brain.apiKeyEnv + ' names an env var that is not set and no runtime key was entered for it');
  const useModel = brain.provider === 'kimi' ? (isKimiModel(model) ? String(model).replace(/\s*\[1m\]\s*$/i, '') : c.model) : brain.model;
  mkdirSync(wsDir, { recursive: true });
  if (!existsSync(join(wsDir, 'README.enclave.md'))) writeFileSync(join(wsDir, 'README.enclave.md'), '# VARVEL sealed workspace (Kimi backend)\nGoverned by the Enclave PreToolUse hook.\n');
  const callTimeoutMs = timeoutMs != null ? Number(timeoutMs) : (brain.timeoutMs || Number(env.VARVEL_KIMI_CALL_TIMEOUT_MS) || 0);

  return async function kimiAgent({ system, messages, onStep, resumeId, resume = false }) {
    const pol = retryPolicy(env, retry || {});
    const missionId = resumeId || newMissionId(); // every call is checkpointed; the id rides back as sessionId
    const eng = engagement || env.VARVEL_ENGAGEMENT || null;
    const runTool = execOverride || execTool;

    // HONEST DEGRADES: what this provider cannot express is announced, never dropped silently.
    const brainNotes = [];
    if (brain.provider !== 'kimi' && effort && effort !== 'off')
      brainNotes.push('reasoning effort "' + effort + '" is a Kimi-API field — NOT sent to the openai-compatible endpoint (no reasoning_effort there); the local model runs at its own default reasoning posture');

    // Full conversation history (was: only messages[0] — a "continue" after the turn cap
    // restarted blind). Normalize roles, fold consecutive same-role (the API requires
    // alternation), and never send an empty content block.
    const src = Array.isArray(messages) && messages.length ? messages : [{ role: 'user', content: '' }];
    const incoming = [];
    for (const m of src) {
      const role = m && m.role === 'assistant' ? 'assistant' : 'user';
      const content = String((m && m.content) ?? '').trim() || '(…)';
      const last = incoming[incoming.length - 1];
      if (last && last.role === role) last.content += '\n\n' + content;
      else incoming.push({ role, content });
    }
    if (incoming[0].role !== 'user') incoming.unshift({ role: 'user', content: '(context)' });

    const denials = [], stepLog = []; let turns = 0, finalText = '', retriesThisCall = 0;
    const emit = (s) => { stepLog.push(s); if (onStep) { try { onStep(s); } catch {} } };
    for (const n of brainNotes) emit({ kind: 'note', text: n }); // degrade notes are step-stream events, audited like everything else

    // ---- mission state: checkpoint resume or fresh start -------------------------
    let cp = null; try { cp = loadCheckpoint(missionId); } catch { /* unreadable — start fresh */ }
    let msgs, ledger = [], missionRetries = [], turnsTotal = 0, gates = [], splitFrom = null, splits = 0, reconstructed = false;
    let objective = cp && cp.objective ? cp.objective : '';
    let splitSuggested = !!(cp && cp.splitSuggestedAt);

    const checkpoint = (status, extra = {}) => {
      // A checkpoint failure must never kill the mission — resilience degrades, honestly noted.
      try {
        saveCheckpoint({ missionId, engagement: eng, created: (cp && cp.created) || new Date().toISOString(),
          status, model: useModel, effort, provider: brain.provider, sessionFile: sessionFile || null, wsDir, container,
          objective: String(objective || '').slice(0, 500), turnsTotal, bytes: Buffer.byteLength(JSON.stringify(msgs || [])),
          msgs, ledger, retries: missionRetries, denials, gates, splitFrom, splits,
          splitSuggestedAt: splitSuggested ? ((cp && cp.splitSuggestedAt) || new Date().toISOString()) : null,
          finalText: finalText || null, ...extra });
      } catch { /* store down — the run continues uncheckpointed */ }
    };

    // A 'split' mission is sealed: its successor carries the context. Refuse honestly.
    if (cp && cp.status === 'split' && cp.handoff && cp.handoff.newMission) {
      return { text: '(mission ' + missionId + ' was split — resume its successor ' + cp.handoff.newMission + ' instead)', steps: 1, denials: [], stepLog, model: useModel, hitTurnCap: false, maxTurns, missionId, sessionId: missionId, retries: 0, retriesTotal: missionRetries.length, split: true, successor: cp.handoff.newMission, reconstructed: false };
    }

    const ledgerEntry = (tu, resultBlock, status) => {
      const full = String(resultBlock.content ?? '');
      return { seq: ledger.length + 1, id: tu.id, name: tu.name,
        inputDigest: 'sha256:' + sha256(JSON.stringify(tu.input || {})), inputPreview: JSON.stringify(tu.input || {}).slice(0, 200),
        status, resultDigest: 'sha256:' + sha256(full),
        result: { ...resultBlock, content: full.slice(0, LEDGER_RESULT_CAP) }, truncated: full.length > LEDGER_RESULT_CAP,
        at: new Date().toISOString() };
    };
    const replayResult = (entry) => {
      const rb = { ...entry.result };
      if (entry.truncated) rb.content = String(rb.content) + '\n[checkpoint-replay — full result truncated at ' + LEDGER_RESULT_CAP + ' chars; ' + entry.resultDigest + ']';
      return rb;
    };
    // One GOVERNED tool execution (hook first, then run) + ledger + checkpoint. Shared by
    // the live loop and the crash-reconcile path so both leave the SAME audit trail.
    const runOne = async (tu) => {
      const dec = hookDecision(tu.name, tu.input, { sessionFile, wsDir, container, env });
      if (!dec.allow) {
        denials.push(tu.name);
        emit({ kind: 'result', text: 'DENIED: ' + dec.reason, denied: true });
        const rb = { type: 'tool_result', tool_use_id: tu.id, content: 'DENIED by the enclave: ' + dec.reason, is_error: true };
        ledger.push(ledgerEntry(tu, rb, 'denied'));
        checkpoint('running');
        return rb;
      }
      const out = String(await runTool(tu.name, tu.input, wsDir, extraEnv));
      emit({ kind: 'result', text: out.replace(/\s+/g, ' ').slice(0, 300) });
      const rb = { type: 'tool_result', tool_use_id: tu.id, content: out };
      ledger.push(ledgerEntry(tu, rb, 'done'));
      checkpoint('running'); // EVERY tool-call boundary persists — a crash here loses nothing
      return rb;
    };
    // CRASH MID-BATCH recovery: the checkpoint ends at an assistant tool_use turn whose
    // results never made it back. Ledgered calls are REPLAYED (skip/reuse — a re-fire is
    // the double-execution bug this ledger exists to prevent); unledgered calls execute
    // now, governed as always.
    const reconcileTrailingBatch = async () => {
      const last = msgs[msgs.length - 1];
      if (!last || last.role !== 'assistant' || !Array.isArray(last.content)) return;
      const tus = last.content.filter((b) => b && b.type === 'tool_use' && b.id);
      if (!tus.length) return;
      const results = [];
      for (const tu of tus) {
        const done = ledger.find((l) => l.id === tu.id);
        if (done) {
          emit({ kind: 'result', text: '(checkpoint) ' + done.name + ' already executed — replayed, not re-fired [' + done.resultDigest.slice(7, 19) + ']', replayed: true });
          results.push(replayResult(done));
          continue;
        }
        emit({ kind: 'tool', name: tu.name, detail: JSON.stringify(tu.input || {}).slice(0, 200), resumed: true });
        results.push(await runOne(tu));
      }
      msgs.push({ role: 'user', content: results });
      checkpoint('running');
    };
    const tailUserText = () => {
      const last = msgs[msgs.length - 1];
      if (!last || last.role !== 'user') return '';
      if (Array.isArray(last.content)) return last.content.filter((b) => b && b.type === 'text').map((b) => String(b.text || '')).join('\n').trim();
      return String(last.content || '').trim();
    };
    const foldAppend = (text) => {
      const last = msgs[msgs.length - 1];
      if (last && last.role === 'user') {
        if (Array.isArray(last.content)) last.content.push({ type: 'text', text });
        else last.content = String(last.content) + '\n\n' + text;
      } else msgs.push({ role: 'user', content: text });
    };

    if (cp && Array.isArray(cp.msgs) && cp.msgs.length && (cp.status === 'running' || resume === true)) {
      // RECONSTRUCT: the checkpoint is authoritative (a mid-turn death left the incoming
      // history stale/truncated; an explicit resume asks for the full-fidelity context).
      reconstructed = true;
      msgs = cp.msgs;
      ledger = cp.ledger || [];
      missionRetries = cp.retries || [];
      turnsTotal = cp.turnsTotal || 0;
      gates = cp.gates || []; splitFrom = cp.splitFrom || null; splits = cp.splits || 0;
      emit({ kind: 'checkpoint', text: 'resumed mission ' + missionId + ' from checkpoint (turn ' + turnsTotal + ', ' + ledger.length + ' ledgered tool call(s), ' + missionRetries.length + ' prior retr' + (missionRetries.length === 1 ? 'y' : 'ies') + ')' });
      // Reconcile FIRST: a trailing tool_use batch must resolve into tool_results before any
      // new instruction joins the conversation (the API requires results for every tool_use).
      await reconcileTrailingBatch();
      const lastIn = incoming[incoming.length - 1];
      const newText = lastIn && lastIn.role === 'user' ? lastIn.content.trim() : '';
      if (newText && tailUserText() !== newText && !tailUserText().endsWith('\n\n' + newText)) foldAppend(newText);
    } else {
      msgs = incoming;
      if (!objective) objective = (incoming.find((m) => m.role === 'user') || {}).content || '';
      checkpoint('running');
    }

    let endState = 'ok';
    for (let t = 0; t < maxTurns; t++) {
      // SPLIT SUGGESTION at a turn boundary ONLY (never mid-tool-call), once per mission.
      if (!splitSuggested) {
        const verdict = shouldSplit({ turns: turnsTotal, bytes: Buffer.byteLength(JSON.stringify(msgs)) });
        if (verdict.split) {
          splitSuggested = true;
          emit({ kind: 'split', text: 'session split SUGGESTED: ' + verdict.reason + ' — cli: split ' + missionId + ', then resume the new mission' });
          checkpoint('running');
        }
      }
      let resp = null, callErr = null;
      for (let attempt = 1; attempt <= pol.attempts; attempt++) {
        try {
          resp = brain.provider === 'kimi'
            ? await callKimi({ base: c.base, key: await resolveKimiKey(env, c.cfgKey), model: /^kimi-k/i.test(useModel) || useModel === 'k3' ? useModel : 'k3', effort, system, tools: TOOLS, messages: msgs, timeoutMs: callTimeoutMs })
            : await callOpenAI({ baseUrl: brain.baseUrl, key: brainKey(brain.apiKeyEnv, env), model: useModel, system, tools: TOOLS, messages: msgs, timeoutMs: callTimeoutMs }); // key re-read per call (env, then the runtime keyring), never logged
          callErr = null;
          break;
        } catch (e) {
          callErr = e;
          const cls = classifyBackendError(e);
          if (!cls.transient || attempt >= pol.attempts) break; // PERMANENT: fail loudly, never retried
          const waitMs = backoffDelay(attempt, pol);
          retriesThisCall++;
          missionRetries.push({ attempt, maxAttempts: pol.attempts, kind: cls.kind, error: String((e && e.message) || e).slice(0, 200), waitMs, at: new Date().toISOString() });
          // AUDIT/FOOTPRINT: every retry is an emitted, checkpointed event — a silent
          // retry would falsify the mission's noise record.
          emit({ kind: 'retry', attempt, maxAttempts: pol.attempts, waitMs, error: cls.kind, detail: String((e && e.message) || e).slice(0, 200) });
          checkpoint('running');
          await pol.sleep(waitMs);
        }
      }
      if (!resp) {
        const cls = classifyBackendError(callErr);
        // The operator must always know WHICH brain failed — the label is the provider id.
        if (cls.transient) {
          // Transient death past the bound: the mission STAYS resumable ('running') —
          // completed tool calls are ledgered; resume continues without re-firing them.
          finalText = '(' + brain.provider + ' backend error: ' + ((callErr && callErr.message) || callErr) + ' — ' + pol.attempts + ' attempt(s) exhausted; the mission is checkpointed: resume ' + missionId + ' to continue without redoing completed work)';
          checkpoint('running', { error: String((callErr && callErr.message) || callErr).slice(0, 300) });
        } else {
          finalText = '(' + brain.provider + ' backend error: ' + ((callErr && callErr.message) || callErr) + ' — permanent (' + cls.kind + '), not retried)';
          checkpoint('failed', { error: String((callErr && callErr.message) || callErr).slice(0, 300) });
        }
        endState = 'error';
        break;
      }
      turns++; turnsTotal++;
      for (const b of resp.content) { if (b.type === 'text' && b.text.trim()) emit({ kind: 'text', text: b.text }); else if (b.type === 'tool_use') emit({ kind: 'tool', name: b.name, detail: JSON.stringify(b.input || {}).slice(0, 200) }); }
      const toolUses = resp.content.filter((b) => b.type === 'tool_use');
      if (resp.stop_reason === 'tool_use' && toolUses.length) {
        msgs.push({ role: 'assistant', content: resp.content });
        const results = [];
        for (const tu of toolUses) {
          // IDEMPOTENT: a tool_use id already on the ledger is replayed, never re-fired.
          const dup = ledger.find((l) => l.id === tu.id);
          if (dup) { results.push(replayResult(dup)); continue; }
          results.push(await runOne(tu));
        }
        msgs.push({ role: 'user', content: results });
        checkpoint('running');
        continue;
      }
      finalText = resp.content.filter((b) => b.type === 'text').map((b) => b.text).join('\n');
      break;
    }
    if (endState === 'ok') checkpoint('awaiting-input'); // the mission rests, fully reconstructable
    // Honest ending: if the loop exhausted its turn budget mid-work (the last stop was
    // tool_use, not a text close), SAY so — the caller can surface "hit the turn cap,
    // say continue" instead of a hollow '(no summary)'.
    const hitTurnCap = turns >= maxTurns;
    const out = { text: finalText, steps: turns || 1, denials, stepLog, model: useModel, hitTurnCap, maxTurns, missionId, sessionId: missionId, retries: retriesThisCall, retriesTotal: missionRetries.length, splitSuggested, reconstructed, provider: brain.provider };
    if (brainNotes.length) out.notes = brainNotes; // honest degrades ride the result, not just the step stream
    return out;
  };
}
