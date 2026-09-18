// VARVEL wedge-guard tests — the channel agent's task-loop survival contract
// (agents/varvel-agent.ps1, the ==WEDGE-GUARD== harness). Two layers:
//
//   1. STATIC PINS (always): the harness section exists, the shell task kind routes
//      through it (no raw Start-Process left in the case), the main loop wraps
//      Invoke-Task in the loop guard, mid-task heartbeat tasks queue locally, and the
//      hard>=soft+margin invariant is enforced at init.
//   2. BEHAVIORAL (skipped when powershell.exe is unavailable): the guard section is
//      EXTRACTED from the agent verbatim (the markers are the contract) and run against
//      REAL wedging children — the catalogue classes:
//        a. normal fast command            -> output, no markers
//        b. child that never exits         -> soft timeout, tree killed, none left over
//        c. start /b pipe-orphan           -> clean exit STILL sweeps the orphan
//        d. child tree AV-killed mid-stream (external taskkill) -> partial output, survives
//        e. inner guard wedged past soft   -> the HARD outer cap Stop()s + kills outer-side
//        f. heartbeat cadence              -> beats fire while a task is running
//      Hermetic: local processes only, zero network.
//   node --test test/wedge-guard.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const AGENT = join(dirname(fileURLToPath(import.meta.url)), '..', 'agents', 'varvel-agent.ps1');
const SRC = readFileSync(AGENT, 'utf8');

// --- static pins -------------------------------------------------------------------------------
test('static: the harness section exists and the shell kind routes through it', () => {
  assert.match(SRC, /==WEDGE-GUARD== begin/);
  assert.match(SRC, /==WEDGE-GUARD== end/);
  const shellCase = SRC.slice(SRC.indexOf("'shell' {"), SRC.indexOf("'fetch' {"));
  assert.ok(shellCase.includes('Invoke-VvShellGuarded'), 'the shell kind runs inside the harness');
  assert.ok(!shellCase.includes('Start-Process cmd.exe'), 'no raw unguarded spawn left in the shell kind');
  for (const fn of ['Get-VvDescendantIds', 'Stop-VvProcessTree', 'Invoke-VvShellGuarded', 'Invoke-VvTaskHeartbeat']) {
    assert.ok(SRC.includes('function ' + fn), fn + ' is defined');
  }
});

test('static: the loop guard + heartbeat queue + timeout knobs + invariant are wired', () => {
  assert.ok(SRC.includes('task fault (caught by the loop guard'), 'Invoke-Task is wrapped in the loop guard');
  assert.ok(SRC.includes('$script:PendingTasks'), 'heartbeat-delivered tasks queue locally');
  assert.ok(SRC.includes('pulledThisCycle'), 'local-queue drain skips the pull+failover leg honestly');
  assert.ok(SRC.includes('[int]$TaskHardTimeoutSec'), 'the hard wall-clock knob exists');
  assert.ok(SRC.includes('[int]$TaskHeartbeatSec'), 'the heartbeat knob exists');
  assert.match(SRC, /\$TaskHardTimeoutSec -lt \$TaskTimeoutSec \+ 15/, 'the hard>=soft+margin invariant is enforced at init');
  assert.ok(SRC.includes('${function:Invoke-VvTaskHeartbeat}'), 'the shell harness beats on the channel heartbeat');
});

// --- behavioral (real PowerShell, real wedging children) ---------------------------------------
const hasPs = (() => {
  try { return spawnSync('powershell.exe', ['-NoProfile', '-Command', '1'], { encoding: 'utf8', timeout: 15000 }).status === 0; }
  catch { return false; }
})();

// Extract the guard section VERBATIM (the markers are the contract) and wrap it in a
// spec-driven runner: one JSON spec in, one VVJSON result line out.
function buildHarness() {
  const dir = mkdtempSync(join(tmpdir(), 'varvel-wedge-'));
  const section = SRC.slice(SRC.indexOf('# ==WEDGE-GUARD== begin'), SRC.indexOf('# ==WEDGE-GUARD== end'));
  const harness = [
    'param([string]$SpecPath)',
    section,
    `$ErrorActionPreference = 'Continue'`,
    '$spec = Get-Content -LiteralPath $SpecPath -Raw | ConvertFrom-Json',
    '$script:beats = 0',
    '$beat = { $script:beats++ }',
    '$sync = [hashtable]::Synchronized(@{ Pid = 0; Note = \'\' })',
    '$killer = $null',
    'if ([int]$spec.killChildAfterMs -gt 0) {',
    '  $killer = [powershell]::Create().AddScript({',
    '    param($S, $Ms)',
    '    $deadline = (Get-Date).AddSeconds(60)',
    '    while ([int]$S.Pid -le 0 -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 100 }',
    '    Start-Sleep -Milliseconds $Ms',
    '    if ([int]$S.Pid -gt 0) { try { & taskkill /PID ([int]$S.Pid) /T /F 2>&1 | Out-Null } catch {} }',
    '  }.ToString()).AddArgument($sync).AddArgument([int]$spec.killChildAfterMs)',
    '  [void]$killer.BeginInvoke()',
    '}',
    '$sw = [Diagnostics.Stopwatch]::StartNew()',
    '$out = Invoke-VvShellGuarded ([string]$spec.command) ([int]$spec.timeoutSec) ([int]$spec.hardSec) ([int]$spec.heartbeatSec) $beat $sync',
    '$leftover = -1',
    'if ($spec.leftoverMatch) {',
    '  $leftover = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -and $_.CommandLine.Contains([string]$spec.leftoverMatch) }).Count',
    '}',
    '$r = @{ out = $out; beats = $script:beats; elapsedMs = [int]$sw.Elapsed.TotalMilliseconds; pid = [int]$sync.Pid; leftover = $leftover }',
    "[Console]::Out.Write('VVJSON:' + ($r | ConvertTo-Json -Compress))",
  ].join('\r\n');
  const file = join(dir, 'wedge-harness.ps1');
  writeFileSync(file, harness);
  return { dir, file };
}

function runGuard(h, spec) {
  const specFile = join(h.dir, 'spec-' + Math.random().toString(36).slice(2) + '.json');
  writeFileSync(specFile, JSON.stringify(spec));
  const r = spawnSync('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', h.file, '-SpecPath', specFile], { encoding: 'utf8', timeout: 120000 });
  assert.equal(r.status, 0, 'harness exited clean: ' + (r.stderr || '').slice(0, 400));
  const m = /VVJSON:(\{.*\})/.exec(r.stdout || '');
  assert.ok(m, 'the harness emitted its result line: ' + (r.stdout || '').slice(0, 400));
  return JSON.parse(m[1]);
}

test('behavioral: the guard survives every wedge class of the catalogue', { skip: !hasPs && 'powershell.exe unavailable', timeout: 240000 }, () => {
  const h = buildHarness();

  // a. normal fast command: output captured, no markers, quick.
  const a = runGuard(h, { command: 'echo WEDGE-OK', timeoutSec: 10, hardSec: 30, heartbeatSec: 0 });
  assert.ok(a.out.includes('WEDGE-OK'), 'output captured: ' + a.out.slice(0, 200));
  assert.ok(!/TIMEOUT|orphan sweep|FAULT|fault/.test(a.out), 'no guard markers on a clean run: ' + a.out.slice(0, 200));
  assert.ok(a.elapsedMs < 20000, 'fast task stays fast (' + a.elapsedMs + 'ms)');

  // b. child that never exits: soft timeout fires, the tree is REALLY dead.
  const b = runGuard(h, { command: 'powershell -NoProfile -Command Start-Sleep -Seconds 610', timeoutSec: 3, hardSec: 40, heartbeatSec: 0, leftoverMatch: 'Start-Sleep -Seconds 610' });
  assert.ok(b.out.includes('TASK TIMEOUT after 3s'), 'soft timeout marker: ' + b.out.slice(0, 200));
  assert.ok(b.elapsedMs < 30000, 'the loop got its answer promptly (' + b.elapsedMs + 'ms)');
  assert.equal(b.leftover, 0, 'the wedged child tree is actually dead (orphan sweep verified)');

  // c. start /b pipe-orphan: cmd exits clean, the background child must STILL be swept.
  const c = runGuard(h, { command: 'start /b powershell -NoProfile -Command Start-Sleep -Seconds 611', timeoutSec: 10, hardSec: 40, heartbeatSec: 0, leftoverMatch: 'Start-Sleep -Seconds 611' });
  assert.ok(c.out.includes('[orphan sweep:'), 'the orphan sweep reported: ' + c.out.slice(0, 300));
  assert.equal(c.leftover, 0, 'the pipe-orphan is dead');

  // d. AV-kill shape: the child tree is taskkilled EXTERNALLY mid-stream (Defender did
  //    this to the tasked child on the range). Partial output returns, no wedge.
  const d = runGuard(h, { command: 'echo PARTIAL-MARK & powershell -NoProfile -Command Start-Sleep -Seconds 612', timeoutSec: 30, hardSec: 90, heartbeatSec: 0, killChildAfterMs: 1500, leftoverMatch: 'Start-Sleep -Seconds 612' });
  assert.ok(d.elapsedMs < 60000, 'an externally-killed child never wedges the guard (' + d.elapsedMs + 'ms)');
  assert.ok(!/TASK TIMEOUT|TASK HARD TIMEOUT/.test(d.out), 'a dead child is not a timeout: ' + d.out.slice(0, 300));
  assert.equal(d.leftover, 0, 'nothing survived');
  assert.ok(d.pid > 0, 'the child pid was published through the sync seam');

  // e. the inner guard blown past: hard < soft, the OUTER net fires and kills from outside.
  const e = runGuard(h, { command: 'powershell -NoProfile -Command Start-Sleep -Seconds 613', timeoutSec: 30, hardSec: 5, heartbeatSec: 0, leftoverMatch: 'Start-Sleep -Seconds 613' });
  assert.ok(e.out.includes('TASK HARD TIMEOUT after 5s'), 'the outer net marker: ' + e.out.slice(0, 300));
  assert.ok(e.elapsedMs < 45000, 'the hard cap held (' + e.elapsedMs + 'ms)');
  assert.equal(e.leftover, 0, 'the outer-side tree-kill worked');

  // f. heartbeat: beats fire while a task runs (the channel checkin contract).
  const f = runGuard(h, { command: 'powershell -NoProfile -Command Start-Sleep -Seconds 614', timeoutSec: 8, hardSec: 40, heartbeatSec: 1, leftoverMatch: 'Start-Sleep -Seconds 614' });
  assert.ok(f.beats >= 5, 'heartbeats fired during the task (' + f.beats + ' beats in ~8s)');
  assert.ok(f.out.includes('TASK TIMEOUT after 8s'), 'the soft guard still fired');
});
