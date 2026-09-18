// VARVEL — brain provider resolution + the OpenAI-compatible adapter (the LOCAL-MODEL seam).
//
// ADDITIVE by design: the platform default brain is Kimi and this module changes NOTHING
// unless a provider is deliberately selected. Selection precedence (highest first):
//   1. per-request override  — makeKimiAgent({ provider }) / POST /api/model {provider}
//      (the Enclave open call forces the same layer via VARVEL_BRAIN_* env)
//   2. environment           — VARVEL_BRAIN_PROVIDER / _BASE_URL / _MODEL / _API_KEY_ENV / _TIMEOUT_MS
//   3. engagement default    — the brain.* settings (engine/settings.mjs schema)
//   4. platform default      — 'kimi'
// An unknown provider value is REFUSED with the valid set named; a missing baseUrl/model
// for the openai-compatible provider fails at agent BUILD time, never mid-mission.
//
// TOKEN DOCTRINE: brain.apiKeyEnv names the ENV VAR holding the endpoint key — the key
// VALUE never enters config, checkpoints, logs, or API echoes (local servers commonly need
// no key at all; then no authorization header is sent).
//
// HONEST DEGRADES: VARVEL concepts an OpenAI chat-completions endpoint cannot express are
// DROPPED LOUDLY, never silently — reasoning effort tiers (a Kimi-API field) surface as a
// note in the agent's step stream + result. Thinking streams arrive as `reasoning_content`
// deltas (vLLM convention) and are mapped to Anthropic-style thinking blocks.

import { Settings } from './settings.mjs';

export const BRAIN_PROVIDERS = ['kimi', 'openai-compatible'];

// ---- RUNTIME KEYRING (2026-09-17) ------------------------------------------------------
// The console's "Brain / API key" card lets the operator paste an endpoint key at RUN time
// instead of exporting it in a shell before launch. The value lives in THIS process's memory
// only: it is never written to data/settings.json, never to a checkpoint, never to a log, and
// never echoed by any API (presence-only, exactly like secret-class settings). The env var
// remains the durable path — brain.apiKeyEnv still NAMES it, and the keyring is consulted
// only when that env var is unset, so an exported key always wins.
const runtimeKeys = new Map(); // envVarName -> value (memory only)

export function setRuntimeKey(name, value) {
  const k = String(name || '').trim();
  if (!k) throw new TypeError('brain key needs an env var name (brain.apiKeyEnv)');
  const v = value == null ? '' : String(value);
  if (v === '') runtimeKeys.delete(k); else runtimeKeys.set(k, v);
  return v !== '';
}

// Presence only — this is the ONLY thing any API/console layer may render.
export function runtimeKeyPresent(name, env = process.env) {
  const k = String(name || '').trim();
  if (!k) return false;
  return runtimeKeys.has(k) || !!(env && env[k]);
}

// The single read point for a key value. Precedence: environment first (the durable,
// auditable path), then the runtime keyring. Never logged by callers.
export function brainKey(apiKeyEnv, env = process.env) {
  const k = String(apiKeyEnv || '').trim();
  if (!k) return '';
  const fromEnv = env && env[k];
  if (fromEnv !== undefined && fromEnv !== null && fromEnv !== '') return String(fromEnv);
  return runtimeKeys.has(k) ? runtimeKeys.get(k) : '';
}


// Resolve the effective brain config. `request` is the per-request override (a provider
// name string or a partial { provider, baseUrl, model, apiKeyEnv, timeoutMs }). Returns
// { provider, baseUrl, model, apiKeyEnv, timeoutMs, source } — for 'kimi' the local-endpoint
// fields stay empty. NEVER returns or logs a key value.
export function resolveBrain({ env = process.env, engagement = null, request = null } = {}) {
  const req = typeof request === 'string' ? { provider: request } : (request || {});
  let st = {};
  try {
    const s = Settings.for(engagement);
    st = { provider: s.get('brain.provider'), baseUrl: s.get('brain.baseUrl'), model: s.get('brain.model'), apiKeyEnv: s.get('brain.apiKeyEnv'), timeoutMs: s.get('brain.timeoutMs') };
  } catch { /* settings store unreadable — env/request layers still work */ }
  const envV = (k) => (env && env[k] !== undefined && env[k] !== '' ? env[k] : undefined);
  const pick = (rk, ek, sv, dflt) => (req[rk] !== undefined && req[rk] !== null && req[rk] !== '' ? req[rk] : undefined) ?? envV(ek) ?? (sv !== undefined && sv !== '' ? sv : undefined) ?? dflt;
  const provider = String(pick('provider', 'VARVEL_BRAIN_PROVIDER', st.provider, 'kimi'));
  if (!BRAIN_PROVIDERS.includes(provider)) throw new TypeError('unknown brain provider: ' + provider + ' — valid: ' + BRAIN_PROVIDERS.join(', '));
  const source = req.provider ? 'request' : (envV('VARVEL_BRAIN_PROVIDER') ? 'env' : (st.provider && st.provider !== 'kimi' ? 'settings' : 'default'));
  if (provider === 'kimi') return { provider, baseUrl: '', model: '', apiKeyEnv: '', timeoutMs: 0, source };

  const baseUrl = String(pick('baseUrl', 'VARVEL_BRAIN_BASE_URL', st.baseUrl, '')).replace(/\/+$/, '');
  const model = String(pick('model', 'VARVEL_BRAIN_MODEL', st.model, ''));
  const apiKeyEnv = String(pick('apiKeyEnv', 'VARVEL_BRAIN_API_KEY_ENV', st.apiKeyEnv, ''));
  const tRaw = pick('timeoutMs', 'VARVEL_BRAIN_TIMEOUT_MS', st.timeoutMs, 0);
  const timeoutMs = Math.floor(Number(tRaw));
  if (!baseUrl) throw new TypeError('openai-compatible brain needs a base URL (request baseUrl / VARVEL_BRAIN_BASE_URL / setting brain.baseUrl)');
  let u = null; try { u = new URL(baseUrl); } catch { /* validated below */ }
  if (!u || !/^https?:$/.test(u.protocol)) throw new TypeError('brain.baseUrl must be a valid http(s) URL, got: ' + baseUrl);
  if (!model) throw new TypeError('openai-compatible brain needs a model id (request model / VARVEL_BRAIN_MODEL / setting brain.model)');
  if (!Number.isFinite(timeoutMs) || timeoutMs < 0 || timeoutMs > 600000) throw new RangeError('brain.timeoutMs must be 0..600000 (0 = off)');
  return { provider, baseUrl, model, apiKeyEnv, timeoutMs, source };
}

// ---- Anthropic-shaped internals → OpenAI chat-completions wire shape -------------------
// The governed agent loop (engine/kimi-runagent.mjs) keeps ONE internal conversation shape
// (Anthropic content blocks: text / thinking / tool_use / tool_result). These mappers are
// the ENTIRE impedance match — the loop, hook, checkpointing, and retry taxonomy never see
// which provider is on the wire.
export function toOpenAIMessages(system, msgs) {
  const out = [];
  if (system) out.push({ role: 'system', content: String(system) });
  for (const m of (Array.isArray(msgs) ? msgs : [])) {
    const role = m && m.role === 'assistant' ? 'assistant' : 'user';
    if (!Array.isArray(m && m.content)) { out.push({ role, content: String((m && m.content) ?? '') }); continue; }
    if (role === 'assistant') {
      const text = m.content.filter((b) => b && b.type === 'text').map((b) => String(b.text || '')).join('\n');
      const calls = m.content.filter((b) => b && b.type === 'tool_use' && b.id)
        .map((b) => ({ id: String(b.id), type: 'function', function: { name: String(b.name || ''), arguments: JSON.stringify(b.input || {}) } }));
      const msg = { role: 'assistant', content: text };
      if (calls.length) msg.tool_calls = calls;
      out.push(msg); // thinking blocks are Anthropic-side state — never sent upstream
    } else {
      // tool_result blocks MUST become role:'tool' messages (one per tool_call_id); text
      // blocks stay user text. Order preserved — results immediately follow their call.
      for (const b of m.content) {
        if (b && b.type === 'tool_result') out.push({ role: 'tool', tool_call_id: String(b.tool_use_id || b.tool_call_id || ''), content: String(b.content ?? '') });
        else if (b && b.type === 'text') out.push({ role: 'user', content: String(b.text || '') });
      }
    }
  }
  return out;
}
export const toOpenAITools = (tools) => (Array.isArray(tools) && tools.length
  ? tools.map((t) => ({ type: 'function', function: { name: t.name, description: t.description, parameters: t.input_schema || { type: 'object', properties: {} } } }))
  : undefined);

const OPENAI_FINISH = { stop: 'end_turn', tool_calls: 'tool_use', length: 'max_tokens' };
// One OpenAI completion (choice.message or accumulated choice.delta) → the internal
// Anthropic-ish { content, stop_reason } the agent loop consumes.
function fromOpenAIChoice({ text, thinking, calls, finish }) {
  const content = [];
  if (thinking) content.push({ type: 'thinking', thinking });
  if (text) content.push({ type: 'text', text });
  for (const c of calls) {
    if (!c) continue;
    let input = {}; try { input = c.args ? JSON.parse(c.args) : {}; } catch { /* malformed args -> empty input, the tool runner errors honestly */ }
    content.push({ type: 'tool_use', id: c.id || ('call_' + content.length), name: c.name, input });
  }
  return { content, stop_reason: OPENAI_FINISH[finish] || finish || null };
}

// One streaming OpenAI-compatible call → { content:[blocks], stop_reason } — the SAME
// contract callKimi honors, so timeout/retry/classify behave identically. Errors carry the
// provider name ('OpenAI-compatible HTTP 403: …') so the operator always knows WHICH brain
// failed; HTTP status rides .status into the same transient/permanent taxonomy.
export async function callOpenAI({ baseUrl, key, model, system, tools, messages, maxTokens = 16000, timeoutMs = 0 }) {
  const payload = { model, max_tokens: maxTokens, messages: toOpenAIMessages(system, messages), stream: true };
  const otools = toOpenAITools(tools); if (otools) payload.tools = otools;
  // Opt-in per-call inactivity ceiling — same semantics as the Kimi path (default 0 = off).
  const signal = Number(timeoutMs) > 0 ? AbortSignal.timeout(Number(timeoutMs)) : undefined;
  const headers = { 'content-type': 'application/json' };
  if (key) headers.authorization = 'Bearer ' + key; // absent entirely for the common no-auth local server
  const res = await fetch(String(baseUrl).replace(/\/+$/, '') + '/chat/completions', { method: 'POST', headers, body: JSON.stringify(payload), signal });
  if (!res.ok) { const t = await res.text().catch(() => ''); const e = new Error('OpenAI-compatible HTTP ' + res.status + ': ' + t.slice(0, 300)); e.status = res.status; e.text = t; throw e; }

  const ctype = String(res.headers && typeof res.headers.get === 'function' ? (res.headers.get('content-type') || '') : '');
  if (!/text\/event-stream/i.test(ctype)) {
    // A non-streaming answer to a stream:true request (some llama.cpp configs): accept it
    // honestly — parse the one-shot JSON completion instead of dying on the content-type.
    let j = null; try { j = await res.json(); } catch { /* falls through to malformed */ }
    const ch = j && Array.isArray(j.choices) && j.choices[0];
    if (!ch || !ch.message) throw new Error('OpenAI-compatible backend: unparseable response (not SSE, not a chat completion)');
    const msg = ch.message;
    return fromOpenAIChoice({
      text: typeof msg.content === 'string' ? msg.content : '',
      thinking: typeof msg.reasoning_content === 'string' ? msg.reasoning_content : '',
      calls: (msg.tool_calls || []).map((tc) => ({ id: tc.id, name: tc.function && tc.function.name, args: tc.function && tc.function.arguments })),
      finish: ch.finish_reason,
    });
  }

  const reader = res.body.getReader(); const dec = new TextDecoder(); let buf = '';
  let text = '', thinking = '', finish = null, saw = 0; const calls = [];
  while (true) {
    const { done, value } = await reader.read(); if (done) break;
    buf += dec.decode(value, { stream: true }); let i;
    while ((i = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, i).replace(/\r$/, ''); buf = buf.slice(i + 1);
      if (!line.startsWith('data:')) continue; const d = line.slice(5).trim(); if (!d || d === '[DONE]') continue;
      let ev; try { ev = JSON.parse(d); } catch { continue; }
      const ch = ev && Array.isArray(ev.choices) && ev.choices[0]; if (!ch) continue; saw++;
      const dl = ch.delta || {};
      if (typeof dl.content === 'string') text += dl.content;
      if (typeof dl.reasoning_content === 'string') thinking += dl.reasoning_content;
      for (const tc of (dl.tool_calls || [])) {
        const idx = Number.isInteger(tc.index) ? tc.index : 0;
        calls[idx] = calls[idx] || { id: '', name: '', args: '' };
        if (tc.id) calls[idx].id += tc.id;
        if (tc.function) { if (tc.function.name) calls[idx].name += tc.function.name; if (tc.function.arguments) calls[idx].args += tc.function.arguments; }
      }
      if (ch.finish_reason) finish = ch.finish_reason;
    }
  }
  if (!saw) throw new Error('OpenAI-compatible backend: unparseable response stream (no valid completion chunks)');
  return fromOpenAIChoice({ text, thinking, calls, finish });
}

// listOpenAIModels({ baseUrl, timeoutMs }) — the lane's OWN model roster. This module
// owns the lane conversation, so the hunt's mid-hunt lane-up case (a spawn that
// carried no model id because the lane was training) asks HERE, never in the loop.
// Returns the FIRST id, or null on ANY failure — a lane that is still down is a
// null (the caller keeps its original named refusal), never a throw.
export async function listOpenAIModels({ baseUrl, timeoutMs = 10000 } = {}) {
  if (!baseUrl) return null;
  try {
    const res = await fetch(String(baseUrl).replace(/\/+$/, '') + '/models', { signal: AbortSignal.timeout(Number(timeoutMs) || 10000) });
    if (!res.ok) return null;
    const j = await res.json();
    const ids = Array.isArray(j && j.data) ? j.data.map((m) => m && m.id).filter(Boolean).map(String) : [];
    return ids[0] || null;
  } catch { return null; }
}
