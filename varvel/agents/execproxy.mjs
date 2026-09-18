// VARVEL — the SIGNED-PROXY EXECUTION TIER, AGENT side (Node): governed
// 'execproxy-run' / 'execproxy-remove' / 'execproxy-status'.
//
// The Node agent delegates to a persistent PowerShell host (agents/execproxy-host.ps1)
// the honest way, mirroring agents/persist.mjs: the host is a reviewed repo file,
// jobs ride its STDIN as JSON lines, results come back as single JSON lines. The
// plant set (sideload host copy + DLL-as-name) SURVIVES the host process BY DESIGN
// (a blocking VarvelRun leg is the point of the tier) — the REMOVAL MANIFEST on
// disk (agent sandbox: varvel-execproxy-manifest.json) is what makes that
// survivable state accountable: every planted file is recorded with its sha256, so
// remove can always prove it left nothing behind.
//
// THE RUNNER IS THE INJECTABLE SEAM (hermetic tests inject a fake):
//   runner(jobJson:string) -> Promise<{ stdout, stderr?, error? }>
//   - stdout: the host's single JSON result line
//     run/remove: {"op","pid","state","names":{"<name>":{...evidence...}},"at"}
//     status:     {"op":"status","pid","state","clean":bool,"entries":[...],"open":[...],"at"}
//   - error: set when the host never produced a result (spawn failure, timeout-kill)
//   - runner.close() kills the host (called from SimAgent.stop())
//
// RESULT CONTRACT (what rides the governed result path):
//   - Governance refusals are PLAIN LOUD TEXT starting 'execproxy-* REFUSED/REJECTED'
//     (nothing planted, nothing executed, nothing removed).
//   - An actual attempt ALWAYS returns ONE JSON string with op FIRST — the channel
//     intake parses exactly this shape into the execproxy.ran / execproxy.removed /
//     execproxy.remove-failed / execproxy.status audit events (engine/execproxy.mjs).

import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { parseExecProxySpec } from '../engine/execproxy.mjs';

export const EXECPROXY_HOST_PATH = fileURLToPath(new URL('./execproxy-host.ps1', import.meta.url));
export const HOST_OP_TIMEOUT_MS = 45000; // a stuck host op kills the host — the task loop survives (a blocking VarvelRun leg is HOST-side, not REPL-side)
const MAX_HOST_STDERR = 200 * 1024;

// The real runner: lazily spawn ONE powershell REPL child running the execproxy
// host and keep it alive across ops. Jobs are FIFO: one JSON line in, one JSON line
// out — the agent task loop is serial, so at most one op is in flight in practice.
// Host death is honest (pending ops resolve with an error) and does NOT undo
// planted files: the on-disk manifest still names every one, so the next host (or
// a relaunched agent) can remove-verifiably exactly what was planted.
export function powerShellExecProxyRunner({ helperPath = EXECPROXY_HOST_PATH, spawnFn = spawn, exe = 'powershell.exe', timeoutMs = HOST_OP_TIMEOUT_MS } = {}) {
  let child = null;
  let lineBuf = '';
  let errBuf = '';
  const pending = []; // { resolve, timer }

  const flushPending = (error) => {
    while (pending.length) {
      const p = pending.shift();
      clearTimeout(p.timer);
      p.resolve({ stdout: '', stderr: errBuf, error });
    }
  };
  const killChild = () => { try { if (child) child.kill(); } catch {} };
  const ensure = () => { // returns null on success, an error string on spawn failure
    if (child) return null;
    lineBuf = ''; errBuf = '';
    try {
      child = spawnFn(exe, ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', helperPath], { windowsHide: true });
    } catch (e) {
      child = null;
      return 'powershell spawn failed: ' + ((e && e.message) || e);
    }
    child.on('error', (e) => { child = null; flushPending('powershell spawn failed: ' + ((e && e.message) || e)); });
    child.on('close', () => { child = null; flushPending('execproxy host exited — planted files (if any) SURVIVE by design; the on-disk removal manifest still names every one for a verified remove') });
    child.stdout.on('data', (d) => {
      lineBuf += d;
      let i;
      while ((i = lineBuf.indexOf('\n')) >= 0) {
        const line = lineBuf.slice(0, i).trim();
        lineBuf = lineBuf.slice(i + 1);
        if (!line) continue;
        const p = pending.shift();
        if (p) { clearTimeout(p.timer); p.resolve({ stdout: line, stderr: '' }); }
      }
    });
    child.stderr.on('data', (d) => { if (errBuf.length < MAX_HOST_STDERR) errBuf += d; });
    child.stdin.on('error', () => {}); // EPIPE when the host died mid-write
    return null;
  };

  const runner = (jobJson) => new Promise((resolve) => {
    const spawnErr = ensure();
    if (spawnErr) return resolve({ stdout: '', stderr: '', error: spawnErr });
    const timer = setTimeout(() => {
      killChild();
      resolve({ stdout: '', stderr: errBuf, error: 'execproxy host op timeout after ' + timeoutMs + 'ms — host killed; the task loop survives (planted state, if any, is still manifest-recorded for a later verified remove)' });
    }, timeoutMs);
    if (timer.unref) timer.unref();
    pending.push({ resolve, timer });
    try { child.stdin.write(jobJson + '\n'); } catch (e) {
      clearTimeout(timer);
      const idx = pending.findIndex((p) => p.timer === timer);
      if (idx >= 0) pending.splice(idx, 1);
      resolve({ stdout: '', stderr: errBuf, error: 'execproxy host stdin write failed: ' + ((e && e.message) || e) });
    }
  });
  runner.close = () => { const c = child; child = null; flushPending('execproxy host closed by agent shutdown'); try { if (c) c.kill(); } catch {} };
  return runner;
}

// Execute one execproxy task payload. kind = 'execproxy-run'|'execproxy-remove'|
// 'execproxy-status', data = the task data string (JSON spec).
//   sandboxDir   — the agent's sandbox (the ONLY place plants may land; the host
//                  resolves the sideload plant dir under it).
//   manifestPath — the on-disk removal manifest (agent sandbox).
//   defaultName  — the deterministic name handle ('VARVEL-<sha8>') when the spec
//                  gives no explicit name.
// Returns the result body string per the contract above. Never throws.
export async function runExecProxyTask(kind, data, { runner, sandboxDir = '', manifestPath = '', defaultName = '' } = {}) {
  kind = String(kind || 'execproxy');
  let spec;
  try { spec = parseExecProxySpec(kind, data); } catch (e) {
    return kind + ' REJECTED: ' + ((e && e.message) || e);
  }
  if (typeof runner !== 'function') {
    return kind + ' REFUSED: this agent has no execproxy host runner (nothing planted, nothing executed, nothing removed)';
  }
  const op = kind.slice('execproxy-'.length);
  // The name handle: run REQUIRES one (the deterministic default derives it);
  // status with no name is the full sweep; remove uses name XOR all:true.
  const name = op === 'run' ? (spec.name || defaultName || null) : (spec.name || null);
  if (op === 'run' && !name) {
    return kind + ' REJECTED: no name handle resolvable (pass one explicitly, or run once so the default is derivable) — the manifest key must be deterministic';
  }
  const job = { op };
  if (name) job.name = name;
  if (op === 'run') {
    job.technique = spec.technique;
    job.dll = spec.dll;
    if (spec.export) job.export = spec.export;
    if (spec.args) job.args = spec.args;
    if (spec.host) job.host = spec.host;
    if (spec.as) job.as = spec.as;
  }
  if (op === 'remove') job.all = spec.all === true;
  if (sandboxDir) job.sandbox = String(sandboxDir);
  if (manifestPath) job.manifestPath = String(manifestPath);
  const jobJson = JSON.stringify(job);
  let r;
  try { r = await runner(jobJson); } catch (e) { r = { stdout: '', stderr: '', error: 'runner threw: ' + ((e && e.message) || e) }; }
  r = r || {};
  if (r.error) {
    return JSON.stringify({ op, pid: null, state: 'failed', names: {}, error: String(r.error).slice(0, 2000), at: new Date().toISOString() });
  }
  return String(r.stdout || '').trim() || JSON.stringify({ op, pid: null, state: 'failed', names: {}, error: 'execproxy host produced no result line', at: new Date().toISOString() });
}
