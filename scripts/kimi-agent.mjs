// kimi-agent.mjs — a direct-Kimi-API agent loop (STREAMING).
//
// Talks to Kimi K3 via its Anthropic-compatible endpoint (api.kimi.com/coding/v1/messages)
// — which WORKS where `claude -p` hangs — with a real host-side tool loop (Read/Write/Edit/
// Bash). STREAMS (SSE) so big requests don't hit a single-response timeout, sets explicit
// reasoning effort, and replays K3's thinking blocks (with signatures) to keep the reasoning
// chain intact. The key is read from ~/.kimicode/config.json and never printed.
//
// Usage:
//   node scripts/kimi-agent.mjs --cwd <dir> --prompt-file <f> [--max-turns 80] [--max-tokens 32000] [--effort high] [--system-file <f>]

import { readFileSync, writeFileSync, existsSync, appendFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { homedir } from 'node:os';
import { join, resolve, isAbsolute } from 'node:path';

const argv = process.argv;
const arg = (n, d) => { const i = argv.indexOf('--' + n); return i >= 0 ? argv[i + 1] : d; };
const cwd = resolve(arg('cwd', process.cwd()));
const prompt = arg('prompt-file') ? readFileSync(arg('prompt-file'), 'utf8') : (arg('prompt', ''));
const maxTurns = Number(arg('max-turns', '80'));
const maxTokens = Number(arg('max-tokens', '32000'));
const EFFORT = arg('effort', 'high'); // reasoning effort; 'off' to disable
if (!prompt) { console.error('kimi-agent: no --prompt/--prompt-file'); process.exit(2); }

const cfg = (() => { try { return JSON.parse(readFileSync(join(homedir(), '.kimicode', 'config.json'), 'utf8')); } catch { return {}; } })();
const KEY = cfg.apiKey || process.env.KIMI_API_KEY || '';
let MODEL = arg('model', (cfg.models && cfg.models.main) || 'k3');
MODEL = MODEL.replace(/\s*\[1m\]\s*$/i, ''); if (/^kimi-k3$/i.test(MODEL)) MODEL = 'k3'; // raw API wants base id `k3`
const BASE = (cfg.baseUrl || 'https://api.kimi.com/coding').replace(/\/+$/, '');
if (!KEY || /PASTE_YOUR/.test(KEY)) { console.error('kimi-agent: no Kimi key in ~/.kimicode/config.json'); process.exit(2); }

const DEFAULT_SYSTEM = [
  'You are Kimi K3 acting as an autonomous senior engineer working ON the codebase of VARVEL,',
  'an AUTHORIZED red-team / security-tooling platform (the flagship of "Enclave"). This is',
  'legitimate software development on the project\'s OWN source code — you are improving the',
  'tool, not attacking anyone. Terms like recon/stealth/OPSEC/exploit here are the names of',
  'the product\'s modules; treat them as ordinary code, not requests to do anything harmful.',
  '',
  'You have real tools, scoped to the working directory:',
  ' - Read(file_path): read a text file.',
  ' - Write(file_path, content): overwrite a file (for NEW files; prefer Edit for big existing files).',
  ' - Edit(file_path, old_string, new_string, replace_all?): exact string replace.',
  ' - Bash(command): run a shell command in the working dir (e.g. `npm test`, `ls`, `grep`, `node --check`).',
  '',
  'Work autonomously and thoroughly: read what you need, make the changes with precise Edits,',
  'verify with Bash where sensible, then STOP with a short summary. Keep the code working.',
  '',
  'MEMORY: your persistent project memory (HANDOFF.md + your own KIMI-NOTES.md) is included',
  'below for context. A summary of this session is auto-appended to KIMI-NOTES.md when you',
  'finish, so the next session (or Jack, in the Kimi app) continues seamlessly. You may also',
  'append important decisions to KIMI-NOTES.md yourself (Edit/Bash) if useful.',
].join('\n');
// Persistent memory folder: read HANDOFF + KIMI-NOTES into context at start, append this
// session's summary at the end — so Kimi actually maintains its own memory across runs
// (continuity for the Kimi app after Claude's window). --memory-dir off to disable.
const MEMDIR = arg('memory-dir', 'C:\\Users\\Jack\\Downloads\\varvel-kimi');
let memoryContext = '';
if (MEMDIR && MEMDIR !== 'off') {
  try {
    const handoff = existsSync(join(MEMDIR, 'HANDOFF.md')) ? readFileSync(join(MEMDIR, 'HANDOFF.md'), 'utf8') : '';
    const notes = existsSync(join(MEMDIR, 'KIMI-NOTES.md')) ? readFileSync(join(MEMDIR, 'KIMI-NOTES.md'), 'utf8') : '';
    if (handoff || notes) memoryContext = '\n\n# Your persistent project memory (' + MEMDIR + ')\n' + (handoff ? '## HANDOFF.md\n' + handoff + '\n' : '') + (notes ? '## KIMI-NOTES.md (recent — your own running memory)\n' + notes.slice(-6000) : '');
  } catch {}
}
const SYSTEM = (arg('system-file') ? readFileSync(arg('system-file'), 'utf8') : DEFAULT_SYSTEM) + memoryContext;

// ---------------- tools ----------------
const CAP = 300000;
const abspath = (p) => (isAbsolute(p) ? resolve(p) : resolve(cwd, p));
const TOOLS = [
  { name: 'Read', description: 'Read a text file; returns its content.', input_schema: { type: 'object', properties: { file_path: { type: 'string' } }, required: ['file_path'] } },
  { name: 'Write', description: 'Write (overwrite) a text file with content.', input_schema: { type: 'object', properties: { file_path: { type: 'string' }, content: { type: 'string' } }, required: ['file_path', 'content'] } },
  { name: 'Edit', description: 'Replace old_string with new_string in a file. Fails if old_string not unique unless replace_all=true.', input_schema: { type: 'object', properties: { file_path: { type: 'string' }, old_string: { type: 'string' }, new_string: { type: 'string' }, replace_all: { type: 'boolean' } }, required: ['file_path', 'old_string', 'new_string'] } },
  { name: 'Bash', description: 'Run a shell command in the working directory; returns stdout+stderr.', input_schema: { type: 'object', properties: { command: { type: 'string' } }, required: ['command'] } },
];
function execTool(name, input) {
  try {
    if (name === 'Read') { const p = abspath(input.file_path); if (!existsSync(p)) return 'ERROR: no such file: ' + input.file_path; const c = readFileSync(p, 'utf8'); return c.length > CAP ? c.slice(0, CAP) + '\n…[truncated at ' + CAP + ' chars]' : c; }
    if (name === 'Write') { writeFileSync(abspath(input.file_path), String(input.content ?? '')); return 'OK: wrote ' + input.file_path; }
    if (name === 'Edit') {
      const p = abspath(input.file_path); if (!existsSync(p)) return 'ERROR: no such file: ' + input.file_path;
      let c = readFileSync(p, 'utf8'); const os = String(input.old_string ?? ''), ns = String(input.new_string ?? '');
      if (!c.includes(os)) return 'ERROR: old_string not found in ' + input.file_path;
      if (input.replace_all) c = c.split(os).join(ns);
      else { if (c.indexOf(os) !== c.lastIndexOf(os)) return 'ERROR: old_string not unique — add surrounding context or use replace_all'; c = c.replace(os, ns); }
      writeFileSync(p, c); return 'OK: edited ' + input.file_path;
    }
    if (name === 'Bash') { const r = spawnSync(input.command, { cwd, shell: true, encoding: 'utf8', timeout: 240000, maxBuffer: 12 * 1024 * 1024, windowsHide: true }); return (((r.stdout || '') + (r.stderr || '')).slice(0, CAP)) || ('(exit ' + r.status + ', no output)'); }
    return 'ERROR: unknown tool ' + name;
  } catch (e) { return 'ERROR: ' + (e && e.message || e); }
}

// ---------------- Kimi streaming call ----------------
let noEffort = (EFFORT === 'off' || EFFORT === ''), noThinkReplay = false;
async function* sse(res) {
  const reader = res.body.getReader(); const dec = new TextDecoder(); let buf = '';
  while (true) {
    const { done, value } = await reader.read(); if (done) break;
    buf += dec.decode(value, { stream: true }); let i;
    while ((i = buf.indexOf('\n')) >= 0) { const line = buf.slice(0, i).replace(/\r$/, ''); buf = buf.slice(i + 1);
      if (!line.startsWith('data:')) continue; const d = line.slice(5).trim(); if (!d || d === '[DONE]') continue;
      try { yield JSON.parse(d); } catch {} }
  }
}
function stripThinking(messages) { return messages.map((m) => (m.role === 'assistant' && Array.isArray(m.content)) ? { ...m, content: m.content.filter((b) => b.type !== 'thinking') } : m); }

async function callKimi(messages) {
  const payload = { model: MODEL, max_tokens: maxTokens, system: SYSTEM, tools: TOOLS, messages: noThinkReplay ? stripThinking(messages) : messages, stream: true };
  if (!noEffort) payload.reasoning_effort = EFFORT;
  const res = await fetch(BASE + '/v1/messages', { method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer ' + KEY, 'x-api-key': KEY, 'anthropic-version': '2023-06-01' }, body: JSON.stringify(payload) });
  if (!res.ok) { const t = await res.text().catch(() => ''); const e = new Error('HTTP ' + res.status + ': ' + t.slice(0, 400)); e.status = res.status; e.text = t; throw e; }
  const blocks = []; let stop = null; let think = 0, out = 0;
  for await (const ev of sse(res)) {
    if (ev.type === 'content_block_start') { const b = ev.content_block || {}; blocks[ev.index] = { type: b.type, text: '', thinking: '', signature: '', id: b.id, name: b.name, inputJson: '' }; if (b.type === 'tool_use') process.stderr.write('  [tool] ' + b.name + ' '); }
    else if (ev.type === 'content_block_delta') { const b = blocks[ev.index]; if (!b) continue; const d = ev.delta || {};
      if (d.type === 'text_delta') { b.text += d.text || ''; out += (d.text || '').length; }
      else if (d.type === 'thinking_delta') { b.thinking += d.thinking || ''; think += (d.thinking || '').length; if (think % 800 < 20) process.stderr.write('·'); }
      else if (d.type === 'input_json_delta') b.inputJson += d.partial_json || '';
      else if (d.type === 'signature_delta') b.signature += d.signature || ''; }
    else if (ev.type === 'message_delta') { if (ev.delta && ev.delta.stop_reason) stop = ev.delta.stop_reason; }
    else if (ev.type === 'error') throw Object.assign(new Error('stream error: ' + JSON.stringify(ev.error).slice(0, 300)), { status: 400, text: JSON.stringify(ev.error) });
  }
  const content = [];
  for (const b of blocks) { if (!b) continue;
    if (b.type === 'thinking') { const t = { type: 'thinking', thinking: b.thinking }; if (b.signature) t.signature = b.signature; content.push(t); }
    else if (b.type === 'text') content.push({ type: 'text', text: b.text });
    else if (b.type === 'tool_use') { let input = {}; try { input = b.inputJson ? JSON.parse(b.inputJson) : {}; } catch {} content.push({ type: 'tool_use', id: b.id, name: b.name, input }); } }
  return { content, stop_reason: stop };
}

// ---------------- agent loop ----------------
const messages = [{ role: 'user', content: prompt }];
console.error(`[kimi-agent] ${MODEL} · effort=${noEffort ? 'default' : EFFORT} · cwd=${cwd} · max-turns=${maxTurns}`);
let ok = false;
for (let turn = 0; turn < maxTurns; turn++) {
  let resp;
  try { resp = await callKimi(messages); }
  catch (e) {
    // self-heal: drop reasoning_effort or thinking-replay if the endpoint rejects them, then retry the same turn
    if (e.status === 400 && !noEffort && /effort|reasoning/i.test(e.text || e.message || '')) { noEffort = true; console.error('\n[kimi-agent] endpoint rejected reasoning_effort — retrying without'); turn--; continue; }
    if (e.status === 400 && !noThinkReplay && /think/i.test(e.text || e.message || '')) { noThinkReplay = true; console.error('\n[kimi-agent] endpoint rejected thinking replay — retrying without'); turn--; continue; }
    console.error('\n[kimi-agent] API error:', (e.message || e));
    break;
  }
  process.stderr.write('\n');
  for (const b of resp.content) {
    if (b.type === 'text' && b.text.trim()) console.error('  [text]', b.text.replace(/\s+/g, ' ').slice(0, 240));
    else if (b.type === 'tool_use') console.error('  [tool]', b.name, JSON.stringify(b.input || {}).replace(/\s+/g, ' ').slice(0, 200));
  }
  const toolUses = resp.content.filter((b) => b.type === 'tool_use');
  if (resp.stop_reason === 'tool_use' && toolUses.length) {
    messages.push({ role: 'assistant', content: resp.content });
    const results = toolUses.map((tu) => { const o = String(execTool(tu.name, tu.input)); console.error('  [result]', tu.name, '→', o.slice(0, 80).replace(/\s+/g, ' ')); return { type: 'tool_result', tool_use_id: tu.id, content: o }; });
    messages.push({ role: 'user', content: results });
    continue;
  }
  const finalText = resp.content.filter((b) => b.type === 'text').map((b) => b.text).join('\n');
  console.log('\n===AGENT_RESULT_BEGIN===\n' + finalText + '\n===AGENT_RESULT_END===');
  console.error(`[kimi-agent] done · turns=${turn + 1} · stop=${resp.stop_reason}`);
  if (MEMDIR && MEMDIR !== 'off') { try { const stamp = new Date().toISOString().replace('T', ' ').slice(0, 16); appendFileSync(join(MEMDIR, 'KIMI-NOTES.md'), '\n- (' + stamp + ') ' + finalText.replace(/\s+/g, ' ').slice(0, 500)); console.error('[kimi-agent] session summary appended to KIMI-NOTES.md'); } catch {} }
  ok = true; break;
}
if (!ok) console.error('[kimi-agent] ended without a clean stop (turn cap or error)');
