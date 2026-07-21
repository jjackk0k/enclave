// agent-backend.mjs — a GOVERNED agent loop for any OpenAI-compatible model
// (Kimi K3 / Moonshot, a local Ollama model, etc.).
//
// This is what makes Enclave model-agnostic WITHOUT giving up the guardrails.
// Claude Code has tool-use + the PreToolUse hook built in; other models don't —
// so here we run the loop ourselves and route EVERY tool call through the exact
// same Enclave hook (classify -> Cedar -> allow/deny), execute allowed tools in
// the sealed workspace/container, and feed the result back. The governance is
// identical to the Claude path; only the brain changes.

import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { join, isAbsolute, relative } from 'node:path';

// the sealed toolset, described to the model in OpenAI function-calling format
const TOOLS = [
  { type: 'function', function: { name: 'Read', description: 'Read a file inside the enclave workspace.', parameters: { type: 'object', properties: { file_path: { type: 'string' } }, required: ['file_path'] } } },
  { type: 'function', function: { name: 'Write', description: 'Create/overwrite a file inside the workspace.', parameters: { type: 'object', properties: { file_path: { type: 'string' }, content: { type: 'string' } }, required: ['file_path', 'content'] } } },
  { type: 'function', function: { name: 'Edit', description: 'Replace old_string with new_string in a workspace file.', parameters: { type: 'object', properties: { file_path: { type: 'string' }, old_string: { type: 'string' }, new_string: { type: 'string' } }, required: ['file_path', 'old_string', 'new_string'] } } },
  { type: 'function', function: { name: 'Bash', description: 'Run a shell command in the workspace. To use the sealed workload toolchain (nmap/vol/gdb/nuclei/…) run: enclave-shell <command>', parameters: { type: 'object', properties: { command: { type: 'string' } }, required: ['command'] } } },
  { type: 'function', function: { name: 'Grep', description: 'Search file contents (ripgrep) in the workspace.', parameters: { type: 'object', properties: { pattern: { type: 'string' }, path: { type: 'string' } }, required: ['pattern'] } } },
  { type: 'function', function: { name: 'Glob', description: 'List files matching a glob in the workspace.', parameters: { type: 'object', properties: { pattern: { type: 'string' } }, required: ['pattern'] } } },
];

// Govern one tool call via the REAL Enclave hook (same binary Claude Code uses).
function govern(hookPath, toolName, toolInput, sessionFile, wsDir) {
  const payload = JSON.stringify({ tool_name: toolName, tool_input: toolInput, cwd: wsDir });
  const r = spawnSync('node', ['--no-warnings', hookPath], {
    input: payload, encoding: 'utf8',
    env: { ...process.env, ENCLAVE_SESSION: sessionFile, ENCLAVE_WORKSPACE_DIR: wsDir, NODE_NO_WARNINGS: '1' },
  });
  try { const j = JSON.parse(r.stdout).hookSpecificOutput; return { allow: j.permissionDecision === 'allow', reason: j.permissionDecisionReason || '' }; }
  catch { return { allow: false, reason: 'policy hook error — fail-closed' }; }
}

// Execute an ALLOWED tool. File ops are confined to the workspace; Bash runs on the
// host in the workspace (enclave-shell inside the command routes to the sealed container).
function execTool(toolName, args, wsDir, container, binPath) {
  const within = p => {
    const abs = isAbsolute(String(p)) ? String(p) : join(wsDir, String(p));
    const rel = relative(wsDir, abs);
    if (rel.split(/[\\/]/)[0] === '..' || isAbsolute(rel)) throw new Error('path outside the sealed workspace');
    return abs;
  };
  const env = { ...process.env, ENCLAVE_CONTAINER: container || '', PATH: binPath + (process.platform === 'win32' ? ';' : ':') + (process.env.PATH || '') };
  try {
    if (toolName === 'Read') return readFileSync(within(args.file_path), 'utf8').slice(0, 20000);
    if (toolName === 'Write') { writeFileSync(within(args.file_path), args.content ?? ''); return 'wrote ' + args.file_path; }
    if (toolName === 'Edit') {
      const f = within(args.file_path); let c = readFileSync(f, 'utf8');
      if (!c.includes(args.old_string)) return 'ERROR: old_string not found in ' + args.file_path;
      writeFileSync(f, c.replace(args.old_string, args.new_string)); return 'edited ' + args.file_path;
    }
    if (toolName === 'Grep') { const r = spawnSync('rg', ['-n', String(args.pattern), String(args.path || '.')], { cwd: wsDir, encoding: 'utf8', env }); return (r.stdout || r.stderr || 'no matches').slice(0, 8000); }
    if (toolName === 'Glob') { const r = spawnSync('bash', ['-lc', 'ls -1 ' + String(args.pattern) + ' 2>/dev/null || true'], { cwd: wsDir, encoding: 'utf8', env }); return (r.stdout || 'no matches').slice(0, 8000); }
    if (toolName === 'Bash') { const r = spawnSync('bash', ['-c', String(args.command)], { cwd: wsDir, encoding: 'utf8', timeout: 150000, env }); return ((r.stdout || '') + (r.stderr || '')).slice(0, 8000) || '(no output)'; }
    return 'unknown tool ' + toolName;
  } catch (e) { return 'ERROR: ' + e.message; }
}

// one chat-completions call against an OpenAI-compatible endpoint. `fetchImpl` is
// injectable so this is unit-testable against a mock.
async function chat(apiBase, apiKey, model, messages, effort, fetchImpl = fetch) {
  const body = { model, messages, tools: TOOLS, tool_choice: 'auto', temperature: 0.3 };
  if (effort) body.reasoning_effort = effort;   // honored by models that support it; ignored otherwise
  const r = await fetchImpl(apiBase.replace(/\/$/, '') + '/chat/completions', {
    method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer ' + apiKey }, body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error('model API ' + r.status + ': ' + (await r.text()).slice(0, 300));
  return r.json();
}

// The governed agent loop. Returns { text, denials, steps } — same shape the console expects.
export async function runGovernedAgent(opts) {
  const { apiBase, apiKey, model, system, messages, hookPath, sessionFile, wsDir, container, binPath, effort, maxSteps = 14, fetchImpl } = opts;
  const convo = [{ role: 'system', content: system }, ...messages];
  const denials = [];
  for (let step = 0; step < maxSteps; step++) {
    const resp = await chat(apiBase, apiKey, model, convo, effort, fetchImpl);
    const msg = (resp.choices && resp.choices[0] && resp.choices[0].message) || {};
    convo.push(msg);
    const calls = msg.tool_calls || [];
    if (!calls.length) return { text: msg.content || '', denials, steps: step + 1 };
    for (const tc of calls) {
      let args = {}; try { args = JSON.parse(tc.function.arguments || '{}'); } catch {}
      const name = tc.function.name;
      const decision = govern(hookPath, name, args, sessionFile, wsDir);
      const result = decision.allow ? execTool(name, args, wsDir, container, binPath)
                                    : ('DENIED by the Enclave policy hook: ' + decision.reason);
      if (!decision.allow) denials.push(name);
      convo.push({ role: 'tool', tool_call_id: tc.id, content: String(result).slice(0, 8000) });
    }
  }
  return { text: '(agent reached the step limit)', denials, steps: maxSteps };
}
