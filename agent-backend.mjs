// agent-backend.mjs — a GOVERNED agent loop for any model k3 can reach:
//   * OpenAI shape   — api.moonshot.ai/v1, OpenRouter (your current free tier), Ollama
//   * Anthropic shape — api.kimi.com/coding (your Kimi MEMBERSHIP/subscription)
//
// This is what makes Enclave model-agnostic WITHOUT giving up the guardrails.
// Claude Code has tool-use + the PreToolUse hook built in; other models don't —
// so here we run the loop ourselves and route EVERY tool call through the exact
// same Enclave hook (classify -> Cedar -> allow/deny), execute allowed tools in
// the sealed workspace/container, and feed the result back. Governance is
// identical to the Claude path; only the brain changes. Reuses your k3 login.

import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { join, isAbsolute, relative } from 'node:path';

// the sealed toolset, provider-neutral; formatted per API shape below
const TOOLDEFS = [
  { name: 'Read',  description: 'Read a file inside the enclave workspace.', schema: { type: 'object', properties: { file_path: { type: 'string' } }, required: ['file_path'] } },
  { name: 'Write', description: 'Create/overwrite a file inside the workspace.', schema: { type: 'object', properties: { file_path: { type: 'string' }, content: { type: 'string' } }, required: ['file_path', 'content'] } },
  { name: 'Edit',  description: 'Replace old_string with new_string in a workspace file.', schema: { type: 'object', properties: { file_path: { type: 'string' }, old_string: { type: 'string' }, new_string: { type: 'string' } }, required: ['file_path', 'old_string', 'new_string'] } },
  { name: 'Bash',  description: 'Run a shell command INSIDE the sealed workload container (the toolchain — nmap/vol/gdb/nuclei/… — is on PATH; the workspace is /work). Every command runs in the container, never on the host.', schema: { type: 'object', properties: { command: { type: 'string' } }, required: ['command'] } },
  { name: 'Grep',  description: 'Search file contents (ripgrep) in the workspace.', schema: { type: 'object', properties: { pattern: { type: 'string' }, path: { type: 'string' } }, required: ['pattern'] } },
  { name: 'Glob',  description: 'List files matching a glob in the workspace.', schema: { type: 'object', properties: { pattern: { type: 'string' } }, required: ['pattern'] } },
];
const toolsFor = (apiType) => apiType === 'anthropic'
  ? TOOLDEFS.map(t => ({ name: t.name, description: t.description, input_schema: t.schema }))
  : TOOLDEFS.map(t => ({ type: 'function', function: { name: t.name, description: t.description, parameters: t.schema } }));

// Govern one tool call via the REAL Enclave hook (same binary Claude Code uses).
function govern(hookPath, toolName, toolInput, sessionFile, wsDir) {
  const payload = JSON.stringify({ tool_name: toolName, tool_input: toolInput, cwd: wsDir });
  const r = spawnSync('node', ['--no-warnings', hookPath], {
    input: payload, encoding: 'utf8', windowsHide: true, // no console flash per governed call
    env: { ...process.env, ENCLAVE_SESSION: sessionFile, ENCLAVE_WORKSPACE_DIR: wsDir, NODE_NO_WARNINGS: '1' },
  });
  try { const j = JSON.parse(r.stdout).hookSpecificOutput; return { allow: j.permissionDecision === 'allow', reason: j.permissionDecisionReason || '' }; }
  catch { return { allow: false, reason: 'policy hook error — fail-closed' }; }
}

// Execute an ALLOWED tool. File ops are confined to the mounted workspace (which IS the
// container's /work — the same bytes over the bind mount, and within() blocks any path
// outside it). ALL shell/search (Bash/Grep/Glob) is forced INSIDE the sealed container via
// `docker exec` — there is NO host-shell path, so a command the model runs without the
// enclave-shell wrapper can no longer touch the host. If no container is running for this
// workload, shell is refused (fail-closed) instead of dropping to the host.
function execTool(toolName, args, wsDir, container, _binPath) {
  const within = p => {
    // Git-Bash/POSIX drive form (/c/Users → C:/Users) — normalize before the confinement check
    const s0 = String(p); const m = /^\/(?:mnt\/)?([a-zA-Z])(?=\/|$)/.exec(s0);
    const q = m ? m[1].toUpperCase() + ':' + s0.slice(m[0].length) : s0;
    const abs = isAbsolute(q) ? q : join(wsDir, q);
    const rel = relative(wsDir, abs);
    if (rel.split(/[\\/]/)[0] === '..' || isAbsolute(rel)) throw new Error('path outside the sealed workspace');
    return abs;
  };
  // run argv INSIDE the sealed container; never fall back to the host.
  const dexec = (argv, timeout = 150000) => {
    if (!container) return 'ERROR: shell/search is disabled for this workload — no sealed container is running (start Docker and pick a workload that has a built image). Nothing is executed on the host.';
    const r = spawnSync('docker', ['exec', '-i', '-w', '/work', container, ...argv], { encoding: 'utf8', timeout, windowsHide: true });
    if (r.error) return 'ERROR: could not enter the sealed container: ' + r.error.message;
    return ((r.stdout || '') + (r.stderr || '')).slice(0, 8000) || '(no output)';
  };
  try {
    if (toolName === 'Read') return readFileSync(within(args.file_path), 'utf8').slice(0, 20000);
    if (toolName === 'Write') { writeFileSync(within(args.file_path), args.content ?? ''); return 'wrote ' + args.file_path; }
    if (toolName === 'Edit') {
      const f = within(args.file_path); let c = readFileSync(f, 'utf8');
      if (!c.includes(args.old_string)) return 'ERROR: old_string not found in ' + args.file_path;
      writeFileSync(f, c.replace(args.old_string, args.new_string)); return 'edited ' + args.file_path;
    }
    // ripgrep runs as direct argv (no shell → no injection); even an out-of-workspace path
    // only ever sees the container's filesystem, not the host's.
    if (toolName === 'Grep') return dexec(['rg', '-n', String(args.pattern), String(args.path || '.')]);
    // glob needs shell expansion; any injection stays sealed inside the disposable container.
    if (toolName === 'Glob') return dexec(['bash', '-lc', 'ls -1 ' + String(args.pattern) + ' 2>/dev/null || true']);
    // the wrapper is now applied HERE (the enforcement layer), not by the model: strip a
    // leading `enclave-shell` if the model still emits it, then run in the container regardless.
    if (toolName === 'Bash') return dexec(['bash', '-lc', String(args.command).replace(/^\s*enclave-shell\s+/i, '')]);
    return 'unknown tool ' + toolName;
  } catch (e) { return 'ERROR: ' + e.message; }
}

// Kimi's raw coding API (Anthropic shape) accepts only BASE model ids — `k3`, `kimi-k2.7-code`.
// The k3 CLI config stores the DISPLAY id `kimi-k3[1m]`, and sending that verbatim is a 401
// ("Your model id does not exist, recognized as other:kimi-k3[1m]"). Normalize at the API
// chokepoint so no caller can ever ship a display id to the wire. Non-Kimi ids pass through
// untouched (the [1m]-strip only matches that literal suffix).
export function normalizeKimiModel(m) {
  let s = String(m || '').replace(/\s*\[1m\]\s*$/i, '').trim();
  if (/^kimi-k3$/i.test(s)) s = 'k3';
  return s || 'k3';
}

// One completion call. Returns a NORMALIZED { assistantMsg, text, toolCalls:[{id,name,args}] }.
// fetchImpl is injectable for unit tests.
async function chat({ apiBase, apiKey, apiType, model, system, convo, effort, fetchImpl = fetch }) {
  const base = apiBase.replace(/\/$/, '');
  if (apiType === 'anthropic') {
    const body = { model: normalizeKimiModel(model), max_tokens: 8192, system, messages: convo, tools: toolsFor('anthropic') };
    if (effort) body.reasoning_effort = effort;
    const r = await fetchImpl(base + '/v1/messages', { method: 'POST',
      headers: { 'content-type': 'application/json', 'x-api-key': apiKey, authorization: 'Bearer ' + apiKey, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify(body) });
    if (!r.ok) throw new Error('kimi(anthropic) ' + r.status + ': ' + (await r.text()).slice(0, 300));
    const j = await r.json();
    const content = j.content || [];
    const text = content.filter(b => b.type === 'text').map(b => b.text).join('');
    const toolCalls = content.filter(b => b.type === 'tool_use').map(b => ({ id: b.id, name: b.name, args: b.input || {} }));
    return { assistantMsg: { role: 'assistant', content }, text, toolCalls };
  }
  // OpenAI shape (moonshot platform / OpenRouter / Ollama)
  const body = { model, messages: convo, tools: toolsFor('openai'), tool_choice: 'auto', temperature: 0.3 };
  if (effort) body.reasoning_effort = effort;
  const r = await fetchImpl(base + '/chat/completions', { method: 'POST',
    headers: { 'content-type': 'application/json', authorization: 'Bearer ' + apiKey },
    body: JSON.stringify(body) });
  if (!r.ok) throw new Error('kimi(openai) ' + r.status + ': ' + (await r.text()).slice(0, 300));
  const j = await r.json();
  const m = (j.choices && j.choices[0] && j.choices[0].message) || {};
  const toolCalls = (m.tool_calls || []).map(tc => { let a = {}; try { a = JSON.parse(tc.function.arguments || '{}'); } catch {} return { id: tc.id, name: tc.function.name, args: a }; });
  return { assistantMsg: m, text: m.content || '', toolCalls };
}

// The governed agent loop. Returns { text, denials, steps }.
export async function runGovernedAgent(opts) {
  const { apiBase, apiKey, apiType = 'openai', model, system, messages, hookPath, sessionFile, wsDir, container, binPath, effort, maxSteps = 14, fetchImpl } = opts;
  const denials = [];
  let convo = apiType === 'anthropic'
    ? messages.map(m => ({ role: m.role === 'assistant' ? 'assistant' : 'user', content: m.content }))
    : [{ role: 'system', content: system }, ...messages];
  for (let step = 0; step < maxSteps; step++) {
    const norm = await chat({ apiBase, apiKey, apiType, model, system, convo, effort, fetchImpl });
    convo.push(norm.assistantMsg);
    if (!norm.toolCalls.length) return { text: norm.text || '', denials, steps: step + 1 };
    const results = [];
    for (const tc of norm.toolCalls) {
      const decision = govern(hookPath, tc.name, tc.args, sessionFile, wsDir);
      const out = decision.allow ? execTool(tc.name, tc.args, wsDir, container, binPath)
                                 : ('DENIED by the Enclave policy hook: ' + decision.reason);
      if (!decision.allow) denials.push(tc.name);
      results.push({ id: tc.id, content: String(out).slice(0, 8000) });
    }
    if (apiType === 'anthropic') {
      convo.push({ role: 'user', content: results.map(r => ({ type: 'tool_result', tool_use_id: r.id, content: r.content })) });
    } else {
      for (const r of results) convo.push({ role: 'tool', tool_call_id: r.id, content: r.content });
    }
  }
  return { text: '(agent reached the step limit)', denials, steps: maxSteps };
}
