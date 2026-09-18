// VARVEL — the EVASION INTERNALS TIER (stage 1), AGENT side (Node): governed
// 'evasion-enable' / 'evasion-restore' / 'evasion-status'.
//
// The Node agent cannot patch its own PowerShell-less process memory usefully (the
// recipes target amsi.dll/ntdll.dll export entry points — a Windows native concern),
// so it delegates to a PERSISTENT PowerShell host process (agents/evasion-host.ps1)
// the honest way, mirroring agents/inlineexec.mjs: the host is a reviewed repo file,
// jobs ride its STDIN as JSON lines, results come back as single JSON lines. The host
// is PERSISTENT (one REPL child per agent) because the whole point of the tier is
// process-scoped state: enable patches THE HOST'S OWN process, status reads it,
// restore puts the original bytes back — all inside one process that dies with the
// agent. BY CONSTRUCTION THE PATCH IS IN-MEMORY AND OWN-PROCESS-ONLY: if the host
// process exits for any reason, every patch vanishes with it (self-cleaning).
//
// THE RUNNER IS THE INJECTABLE SEAM (hermetic tests inject a fake):
//   runner(jobJson:string) -> Promise<{ stdout, stderr?, error? }>
//   - stdout: the host's single JSON result line
//     {"op","pid","state","techniques":{...},"at"}
//   - error: set when the host never produced a result (spawn failure, timeout-kill)
//   - runner.close() kills the host (called from SimAgent.stop())
//
// RESULT CONTRACT (what rides the governed result path):
//   - Governance refusals are PLAIN LOUD TEXT starting 'evasion-* REFUSED/REJECTED'
//     (nothing ran; no patch state exists to report).
//   - An actual attempt ALWAYS returns ONE JSON string with op FIRST:
//     {"op","pid","state","techniques":{"amsi":{"state","originalSha256",
//     "patchedSha256","byteVerified","restoreVerified","verify":{...}}},"at"}
//     — the channel intake parses exactly this shape into the evasion.applied /
//     evasion.restored / evasion.status audit events (engine/evasion.mjs).

import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { parseEvasionSpec } from '../engine/evasion.mjs';

export const EVASION_HOST_PATH = fileURLToPath(new URL('./evasion-host.ps1', import.meta.url));
export const HOST_OP_TIMEOUT_MS = 30000; // a stuck host op kills the host — the loop survives
const MAX_HOST_STDERR = 200 * 1024;

// The real runner: lazily spawn ONE powershell REPL child running the evasion host and
// keep it alive across ops (enable -> status -> restore must observe ONE process's
// patch state). Jobs are FIFO: one JSON line in, one JSON line out — the agent task
// loop is serial, so at most one op is in flight in practice. On host death every
// pending op resolves with an honest error; the next op spawns a fresh host (a fresh
// process is UNPATCHED by construction — process exit is the ultimate restore).
export function powerShellEvasionRunner({ helperPath = EVASION_HOST_PATH, spawnFn = spawn, exe = 'powershell.exe', timeoutMs = HOST_OP_TIMEOUT_MS } = {}) {
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
    child.on('close', () => { child = null; flushPending('evasion host exited — any patch it held died with the process (in-memory, own-process only)'); });
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
      resolve({ stdout: '', stderr: errBuf, error: 'evasion host op timeout after ' + timeoutMs + 'ms — host killed; its patch state (if any) died with the process, the task loop survives' });
    }, timeoutMs);
    if (timer.unref) timer.unref();
    pending.push({ resolve, timer });
    try { child.stdin.write(jobJson + '\n'); } catch (e) {
      clearTimeout(timer);
      const idx = pending.findIndex((p) => p.timer === timer);
      if (idx >= 0) pending.splice(idx, 1);
      resolve({ stdout: '', stderr: errBuf, error: 'evasion host stdin write failed: ' + ((e && e.message) || e) });
    }
  });
  runner.close = () => { const c = child; child = null; flushPending('evasion host closed by agent shutdown'); try { if (c) c.kill(); } catch {} };
  return runner;
}

// Execute one evasion task payload. kind = 'evasion-enable'|'evasion-restore'|'evasion-status',
// data = the task data string (JSON spec). Returns the result body string per the
// contract above. Never throws.
export async function runEvasionTask(kind, data, { runner } = {}) {
  kind = String(kind || 'evasion');
  let spec;
  try { spec = parseEvasionSpec(kind, data); } catch (e) {
    return kind + ' REJECTED: ' + ((e && e.message) || e);
  }
  if (typeof runner !== 'function') {
    return kind + ' REFUSED: this agent has no evasion host runner (nothing patched, nothing restored)';
  }
  const op = kind.slice('evasion-'.length);
  const jobJson = JSON.stringify({ op, techniques: spec.techniques });
  let r;
  try { r = await runner(jobJson); } catch (e) { r = { stdout: '', stderr: '', error: 'runner threw: ' + ((e && e.message) || e) }; }
  r = r || {};
  if (r.error) {
    return JSON.stringify({ op, pid: null, state: 'failed', techniques: {}, error: String(r.error).slice(0, 2000), at: new Date().toISOString() });
  }
  // The host's last non-empty stdout line is the result JSON (forgiving of host noise).
  const lines = String(r.stdout || '').split(/\r?\n/).filter((l) => l.trim().length > 0);
  let parsed = null;
  for (let i = lines.length - 1; i >= 0 && !parsed; i--) { try { parsed = JSON.parse(lines[i]); } catch {} }
  if (!parsed || typeof parsed !== 'object' || typeof parsed.op !== 'string' || !parsed.techniques) {
    return JSON.stringify({ op, pid: null, state: 'failed', techniques: {}, error: 'evasion host output unparseable as result JSON' + (r.stderr ? ' — host stderr: ' + String(r.stderr).slice(0, 2000) : ''), raw: String(r.stdout || '').slice(0, 2000), at: new Date().toISOString() });
  }
  // Normalize: op leads (the 120-char ledger preview always carries op+state), the
  // per-technique evidence passes through verbatim — it IS the audit payload.
  return JSON.stringify({
    op: parsed.op,
    pid: Number.isInteger(parsed.pid) ? parsed.pid : null,
    state: String(parsed.state || 'unknown'),
    techniques: parsed.techniques,
    at: typeof parsed.at === 'string' ? parsed.at : new Date().toISOString(),
  });
}
