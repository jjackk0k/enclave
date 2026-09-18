// VARVEL — the GOVERNED PERSISTENCE TIER (roadmap #8), AGENT side (Node):
// governed 'persist-install' / 'persist-status' / 'persist-remove' / 'persist-audit'.
//
// The Node agent cannot write its own PS-side registry/task/lnk state usefully through
// one-liners (and MUST not: the cleanup-proof machinery — pre-install snapshot, clobber
// journal, verified removal — wants ONE reviewed code path), so it delegates to a
// persistent PowerShell host (agents/persist-host.ps1) the honest way, mirroring
// agents/evasion.mjs: the host is a reviewed repo file, jobs ride its STDIN as JSON
// lines, results come back as single JSON lines. Unlike the evasion host, persistence
// state SURVIVES the host process BY DESIGN (that is the point of the tier) — the
// REMOVAL MANIFEST on disk (agent sandbox: varvel-persist-manifest.json) is what makes
// that survivable state accountable: every installed location is recorded with its
// pre-install snapshot, so remove can always prove it put the host back.
//
// THE RUNNER IS THE INJECTABLE SEAM (hermetic tests inject a fake):
//   runner(jobJson:string) -> Promise<{ stdout, stderr?, error? }>
//   - stdout: the host's single JSON result line
//     {"op","pid","state","techniques":{...},"at"}  (audit: {"op":"audit","clean",...})
//   - error: set when the host never produced a result (spawn failure, timeout-kill)
//   - runner.close() kills the host (called from SimAgent.stop())
//
// RESULT CONTRACT (what rides the governed result path):
//   - Governance refusals are PLAIN LOUD TEXT starting 'persist-* REFUSED/REJECTED'
//     (nothing installed, nothing removed).
//   - An actual attempt ALWAYS returns ONE JSON string with op FIRST:
//     {"op","pid","state","techniques":{"runkey":{"state","location","targetSha256",
//     "installVerified","removalVerified",...}},"at"}
//     — the channel intake parses exactly this shape into the persist.installed /
//     persist.removed / persist.remove-failed / persist.status / persist.sweep audit
//     events (engine/persist.mjs).

import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { parsePersistSpec } from '../engine/persist.mjs';

export const PERSIST_HOST_PATH = fileURLToPath(new URL('./persist-host.ps1', import.meta.url));
export const HOST_OP_TIMEOUT_MS = 30000; // a stuck host op kills the host — the task loop survives
const MAX_HOST_STDERR = 200 * 1024;

// The real runner: lazily spawn ONE powershell REPL child running the persist host and
// keep it alive across ops. Jobs are FIFO: one JSON line in, one JSON line out — the
// agent task loop is serial, so at most one op is in flight in practice. Host death is
// honest (pending ops resolve with an error) and — unlike the evasion host — does NOT
// undo installed persistence: the on-disk manifest still names every location, so the
// next host (or a relaunched agent) can remove-verifiably exactly what was installed.
export function powerShellPersistRunner({ helperPath = PERSIST_HOST_PATH, spawnFn = spawn, exe = 'powershell.exe', timeoutMs = HOST_OP_TIMEOUT_MS } = {}) {
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
    child.on('close', () => { child = null; flushPending('persist host exited — installed persistence (if any) SURVIVES by design; the on-disk removal manifest still names every location for a verified remove') });
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
      resolve({ stdout: '', stderr: errBuf, error: 'persist host op timeout after ' + timeoutMs + 'ms — host killed; the task loop survives (installed state, if any, is still manifest-recorded for a later verified remove)' });
    }, timeoutMs);
    if (timer.unref) timer.unref();
    pending.push({ resolve, timer });
    try { child.stdin.write(jobJson + '\n'); } catch (e) {
      clearTimeout(timer);
      const idx = pending.findIndex((p) => p.timer === timer);
      if (idx >= 0) pending.splice(idx, 1);
      resolve({ stdout: '', stderr: errBuf, error: 'persist host stdin write failed: ' + ((e && e.message) || e) });
    }
  });
  runner.close = () => { const c = child; child = null; flushPending('persist host closed by agent shutdown'); try { if (c) c.kill(); } catch {} };
  return runner;
}

// Execute one persist task payload. kind = 'persist-install'|'persist-status'|
// 'persist-remove'|'persist-audit', data = the task data string (JSON spec).
//   target       — the agent's OWN relaunch line, captured agent-side (the channel
//                  never ships it). Required for install.
//   manifestPath — the on-disk removal manifest (agent sandbox).
//   defaultName  — the deterministic name handle ('VARVEL-<sha8>') when the spec gives
//                  no explicit name.
// Returns the result body string per the contract above. Never throws.
export async function runPersistTask(kind, data, { runner, target = '', manifestPath = '', defaultName = '' } = {}) {
  kind = String(kind || 'persist');
  let spec;
  try { spec = parsePersistSpec(kind, data); } catch (e) {
    return kind + ' REJECTED: ' + ((e && e.message) || e);
  }
  if (typeof runner !== 'function') {
    return kind + ' REFUSED: this agent has no persistence host runner (nothing installed, nothing removed)';
  }
  const op = kind.slice('persist-'.length);
  if (op === 'install' && !String(target || '').trim()) {
    return kind + ' REJECTED: no relaunch target captured agent-side — persistence must relaunch the SAME agent with the SAME config; without a captured launch line there is nothing honest to install';
  }
  const job = { op, techniques: spec.techniques };
  if (String(target || '').trim()) job.target = String(target); // every op: status/remove compare against it; the manifest also records it
  if (op === 'install') { job.overwrite = spec.overwrite === true; job.name = spec.name || defaultName || null; }
  else { job.name = spec.name || defaultName || null; }
  if (op === 'remove') job.all = spec.all === true;
  if (spec.deep) job.deep = spec.deep; // deep technique params (clsid+dll / host+as+dll+trigger) — validated by the spec gate
  if (op === 'status' && spec.prove === true) job.prove = true; // the benign resolve-proof (comhijack: throwaway-child instantiation)
  if (manifestPath) job.manifestPath = String(manifestPath);
  const jobJson = JSON.stringify(job);
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
  if (!parsed || typeof parsed !== 'object' || typeof parsed.op !== 'string' || (parsed.op !== 'audit' && !parsed.techniques)) {
    return JSON.stringify({ op, pid: null, state: 'failed', techniques: {}, error: 'persist host output unparseable as result JSON' + (r.stderr ? ' — host stderr: ' + String(r.stderr).slice(0, 2000) : ''), raw: String(r.stdout || '').slice(0, 2000), at: new Date().toISOString() });
  }
  // Normalize: op leads (the 120-char ledger preview always carries op+state); the
  // per-technique evidence / sweep payload passes through verbatim — it IS the audit.
  const out = {
    op: parsed.op,
    pid: Number.isInteger(parsed.pid) ? parsed.pid : null,
    state: String(parsed.state || 'unknown'),
    at: typeof parsed.at === 'string' ? parsed.at : new Date().toISOString(),
  };
  if (parsed.op === 'audit') {
    out.clean = parsed.clean === true;
    out.entries = Array.isArray(parsed.entries) ? parsed.entries : [];
    out.open = Array.isArray(parsed.open) ? parsed.open : [];
    if (typeof parsed.note === 'string') out.note = parsed.note; // the sweep's verdict sentence is part of the audit
  } else {
    out.techniques = parsed.techniques;
  }
  return JSON.stringify(out);
}
