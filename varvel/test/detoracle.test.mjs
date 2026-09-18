// detoracle.test.mjs — hermetic: snapshot parse, verdict classification, and the full
// assess flow with a scripted taskAgent (no channel, no guest). The honesty contract
// is pinned: unmonitored is never clean, clean is never a claim.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildSnapshotCommand, parseSnapshot, classify, assess } from '../tools/detoracle.mjs';

test('parseSnapshot: good line parses; garbage fails closed', () => {
  assert.deepEqual(parseSnapshot('DETOR T3 D5 B1 R1'), { threats: 3, d1116: 5, d1117: 1, rtp: true });
  assert.deepEqual(parseSnapshot('noise\nDETOR T0 D0 B0 R0 trailing'), { threats: 0, d1116: 0, d1117: 0, rtp: false });
  assert.equal(parseSnapshot(''), null);
  assert.equal(parseSnapshot('DETOR Tx D0 B0 R1'), null);
  assert.equal(parseSnapshot(undefined), null);
});

test('snapshot command carries the Defender cmdlets and stays compact', () => {
  const c = buildSnapshotCommand();
  assert.match(c, /Get-MpThreatDetection/);
  assert.match(c, /Id=1116/);
  assert.match(c, /Id=1117/);
  assert.match(c, /RealTimeProtectionEnabled/);
});

test('classify: the full verdict matrix, honestly', () => {
  const b = { threats: 1, d1116: 2, d1117: 0, rtp: true };
  assert.equal(classify(b, { ...b }, {}).verdict, 'clean');
  assert.match(classify(b, { ...b }, {}).note, /NOT a claim of undetectability/);
  assert.equal(classify(b, { ...b, threats: 2 }, {}).verdict, 'detected');       // threat list grew
  assert.equal(classify(b, { ...b, d1116: 3 }, {}).verdict, 'detected');          // 1116 grew
  assert.equal(classify(b, { ...b, d1117: 1 }, {}).verdict, 'blocked');           // action taken
  assert.equal(classify(b, { ...b, d1116: 3 }, { probeAlive: false }).verdict, 'blocked'); // detection + probe died
  assert.equal(classify(b, { ...b }, { probeAlive: false }).verdict, 'detected'); // silent behavior-kill shape
  assert.equal(classify(b, { ...b, rtp: false, threats: 9 }, {}).verdict, 'unmonitored'); // sensor off, NOT clean
  assert.match(classify(b, { ...b, rtp: false }, {}).note, /NOT clean/);
  assert.equal(classify(null, b, {}).verdict, 'unknown');                         // fail-closed
});

test('assess: snapshots bracket the probe, verdict reflects the diff', async () => {
  const calls = [];
  const snapGood = 'DETOR T1 D2 B0 R1';
  const snapHit = 'DETOR T2 D2 B0 R1';
  const taskAgent = async (agentId, cmd) => {
    calls.push(cmd);
    if (cmd === buildSnapshotCommand()) return calls.filter((c) => c === buildSnapshotCommand()).length === 1 ? snapGood : snapHit;
    return 'probe-output';
  };
  const v = await assess({ taskAgent, agentId: 'agent-x', command: 'do-the-thing', settleMs: 5 });
  assert.equal(v.verdict, 'detected');
  assert.equal(v.newDetections, 1);
  // ordering: snapshot BEFORE the probe, snapshot AFTER it
  assert.equal(calls[0], buildSnapshotCommand());
  assert.equal(calls[1], 'do-the-thing');
  assert.equal(calls[2], buildSnapshotCommand());
  assert.equal(v.evidence.before, snapGood);
  assert.equal(v.evidence.after, snapHit);
});

test('assess: liveness check maps probe death into the verdict', async () => {
  const snap = 'DETOR T0 D0 B0 R1';
  const taskAgent = async (_a, cmd) => (cmd === buildSnapshotCommand() ? snap : cmd.startsWith('check:') ? 'GONE' : 'ok');
  const v = await assess({ taskAgent, agentId: 'x', command: 'run-probe', checkCommand: 'check:probe', settleMs: 5 });
  assert.equal(v.probeAlive, false);
  assert.equal(v.verdict, 'detected');
  assert.match(v.note, /behavior-kill/);
});

test('assess: input validation', async () => {
  await assert.rejects(() => assess({ agentId: 'x', command: 'y' }), TypeError);
  await assert.rejects(() => assess({ taskAgent: async () => '', command: 'y' }), TypeError);
});

// ── THE EICAR CALIBRATION GATE (field finding 2026-08: the range's customized-soft
// Defender did not flag a byte-perfect EICAR file — the oracle must refuse to call
// itself calibrated on such a baseline) ─────────────────────────────────────
import { calibrate, calibrationGate, buildEicarProbeCommand, buildEicarDropScript, buildEicarWmiDropCommand, EICAR_STRING, CALIBRATION_FAILED_PHRASE } from '../tools/detoracle.mjs';

test('buildEicarProbeCommand: carries the official EICAR string to disk', () => {
  const c = buildEicarProbeCommand();
  assert.ok(c.includes(EICAR_STRING));
  assert.match(c, /Set-Content/);
});

// ── DETACHED EICAR DROP CARRIER (range day #2, 2026-08-24): a FIRING sensor wedges
// the stale image agent on the inline drop (the intercepted child holds the agent's
// pipe), so calibrate() gained an opt-in staged + WMI-detached drop. The pins: the
// script is the byte-exact control, the launch is fire-and-forget (no pipe, no
// inherited handle), and EVERY carrier failure reads 'unknown' — never 'clean'.
test('buildEicarDropScript: the byte-exact control, one Set-Content line', () => {
  const s = buildEicarDropScript();
  assert.ok(s.includes(EICAR_STRING)); // literal, unmangled — no obfuscation, ever
  assert.match(s, /^Set-Content -Path 'C:\\Windows\\Temp\\eicar-cal\.tmp' -Value '/);
  assert.equal(s.trim().split('\n').length, 1);
});

test('buildEicarWmiDropCommand: fire-and-forget, no cmd pipe metacharacters', () => {
  const c = buildEicarWmiDropCommand();
  assert.match(c, /Win32_Process/);
  assert.ok(c.includes('eicar-drop.ps1'));
  assert.match(c, /LAUNCHED:/); // the launch proof the gate checks
  assert.ok(!c.includes('|'), 'a pipe inside the tasked command can wedge the stale carrier');
});

// Scripted detached-carrier channel: stage ok, WMI launch ok, snapshots behave like
// calibScript — the post-EICAR snapshot grows only when the sensor fires.
function calibDetached({ eicarFires, stageOk = true, launchOk = true }) {
  const snapCmd = buildSnapshotCommand();
  const wmiCmd = buildEicarWmiDropCommand();
  let snaps = 0;
  const staged = [];
  return {
    staged,
    stageFile: async (_a, name, buf) => {
      staged.push({ name, body: String(buf) });
      return stageOk ? 'staged ' + name + ' (' + String(buf).length + ' bytes, sha256 verified)' : 'stage REJECTED: sha256 mismatch';
    },
    taskAgent: async (_a, cmd) => {
      if (cmd === snapCmd) { snaps++; return eicarFires && snaps === 4 ? 'DETOR T1 D1 B0 R1' : 'DETOR T0 D0 B0 R1'; }
      if (cmd === wmiCmd) return launchOk ? 'LAUNCHED:0' : 'LAUNCHED:2';
      if (cmd.includes('del ')) return 'CLEANED';
      return 'ok';
    },
  };
}

test('calibrate (detached carrier): firing sensor calibrates; the drop never wedges the carrier', async () => {
  const s = calibDetached({ eicarFires: true });
  const c = await calibrate({ taskAgent: s.taskAgent, stageFile: s.stageFile, agentId: 'range-1', settleMs: 5 });
  assert.equal(c.calibrated, true);
  assert.equal(c.eicar.verdict, 'detected');
  assert.equal(s.staged.length, 1);
  assert.equal(s.staged[0].name, 'eicar-drop.ps1');
  assert.ok(s.staged[0].body.includes(EICAR_STRING)); // the literal control, staged
});

test('calibrate (detached carrier): a refused stage reads unknown-with-reason, never clean', async () => {
  const s = calibDetached({ eicarFires: true, stageOk: false });
  const c = await calibrate({ taskAgent: s.taskAgent, stageFile: s.stageFile, agentId: 'range-1', settleMs: 5 });
  assert.equal(c.calibrated, false);
  assert.equal(c.eicar.verdict, 'unknown');
  assert.match(c.reasons.join(' '), /carrier failed at stage/);
  assert.match(c.eicar.note, /carrier failed at stage/);
});

test('calibrate (detached carrier): a failed WMI launch reads unknown-with-reason, never clean', async () => {
  const s = calibDetached({ eicarFires: true, launchOk: false });
  const c = await calibrate({ taskAgent: s.taskAgent, stageFile: s.stageFile, agentId: 'range-1', settleMs: 5 });
  assert.equal(c.calibrated, false);
  assert.equal(c.eicar.verdict, 'unknown');
  assert.match(c.eicar.note, /carrier failed at launch/);
});

// Scripted channel for calibrate(): benign stays flat, the EICAR drop either
// fires (snapshots grow) or reads flat (the customized-soft field finding).
function calibScript({ eicarFires }) {
  const snapCmd = buildSnapshotCommand();
  let snaps = 0;
  const deleted = [];
  return {
    deleted,
    taskAgent: async (_a, cmd) => {
      if (cmd === snapCmd) {
        snaps++;
        // calibrate runs benign assess (2 snapshots) then EICAR assess (2 more);
        // only the post-EICAR snapshot grows when the sensor works.
        return eicarFires && snaps === 4 ? 'DETOR T1 D1 B0 R1' : 'DETOR T0 D0 B0 R1';
      }
      if (cmd.includes('del ')) { deleted.push(cmd); return 'CLEANED'; }
      return 'ok';
    },
  };
}

test('calibrate: a working sensor (EICAR fires) is calibrated, artifact cleaned up', async () => {
  const s = calibScript({ eicarFires: true });
  const c = await calibrate({ taskAgent: s.taskAgent, agentId: 'range-1', settleMs: 5 });
  assert.equal(c.calibrated, true);
  assert.equal(c.baselineTrusted, true);
  assert.equal(c.benign.verdict, 'clean');
  assert.equal(c.eicar.verdict, 'detected');
  assert.deepEqual(c.reasons, []);
  assert.ok(s.deleted.length === 1); // cleanup doctrine: the EICAR file is deleted
});

test('calibrate: EICAR reading CLEAN means customized-soft — the oracle refuses calibration', async () => {
  const s = calibScript({ eicarFires: false });
  const c = await calibrate({ taskAgent: s.taskAgent, agentId: 'range-1', settleMs: 5 });
  assert.equal(c.calibrated, false);
  assert.equal(c.baselineTrusted, false);
  assert.equal(c.eicar.verdict, 'clean');
  assert.match(c.reasons.join(' '), /customized-soft/);
  assert.match(c.note, new RegExp(CALIBRATION_FAILED_PHRASE.replace(/[()]/g, (m) => '\\' + m)));
  assert.match(c.note, /rangehard/); // the refusal points at the hardening path
});

test('calibrate: RTP off during the window is a calibration failure, not a pass', async () => {
  const snapCmd = buildSnapshotCommand();
  const taskAgent = async (_a, cmd) => (cmd === snapCmd ? 'DETOR T0 D0 B0 R0' : 'ok');
  const c = await calibrate({ taskAgent, agentId: 'x', settleMs: 5 });
  assert.equal(c.calibrated, false);
  assert.match(c.reasons.join(' '), /real-time protection is OFF/);
});

test('calibrationGate: failed calibration stamps baselineTrusted:false without touching the measured verdict', () => {
  const measured = { verdict: 'clean', newDetections: 0, note: 'no detection observed in this window' };
  const gated = calibrationGate(measured, { calibrated: false, reasons: ['EICAR clean'] });
  assert.equal(gated.verdict, 'clean'); // the measurement is kept, honestly
  assert.equal(gated.baselineTrusted, false);
  assert.match(gated.note, /UNCALIBRATED BASELINE/);
  assert.match(gated.note, /no detection observed in this window/); // measured note preserved
  assert.deepEqual(gated.calibrationReasons, ['EICAR clean']);
  const trusted = calibrationGate(measured, { calibrated: true });
  assert.equal(trusted.baselineTrusted, true);
  assert.equal(trusted.note, measured.note);
  // non-object inputs pass through untouched
  assert.equal(calibrationGate(measured, null), measured);
});

test('assess: a handed-in failed calibration gates the returned verdict', async () => {
  const snap = 'DETOR T0 D0 B0 R1';
  const taskAgent = async () => snap;
  const v = await assess({ taskAgent, agentId: 'x', command: 'run-probe', settleMs: 5, calibration: { calibrated: false, reasons: ['EICAR clean'] } });
  assert.equal(v.verdict, 'clean');
  assert.equal(v.baselineTrusted, false);
  assert.match(v.note, /UNCALIBRATED BASELINE/);
  const u = await assess({ taskAgent, agentId: 'x', command: 'run-probe', settleMs: 5 });
  assert.equal(u.baselineTrusted, undefined); // no calibration handed in -> no stamp at all
});

// ── CLI WIRING PIN (field finding 2026-08-24, live range day): the calibrate
// sub-command used to hand the 3-arg mkChannelTasker(agentId, kind, data) straight
// to detoracle.calibrate, whose contract is the 2-ARG taskAgent(agentId, command).
// The snapshot command rode the wire as the task KIND; the agent answered
// 'unknown task kind'; every snapshot parsed null; the EICAR gate failed CLOSED on
// a healthy sensor. This pin drives the REAL cli.mjs against a stub channel and
// asserts every queued task is kind 'shell' with the command as data — and that a
// firing EICAR control reads calibrated:true end to end.
import http from 'node:http';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';

test('cli wiring: detoracle calibrate tasks kind shell (2-arg contract), EICAR fire calibrates', { timeout: 120000 }, async () => {
  const snapCmd = buildSnapshotCommand();
  const wmiCmd = buildEicarWmiDropCommand();
  const tasked = []; // every POST /api/channel/task body, verbatim
  const stages = []; // every POST /api/channel/stage body, verbatim
  let snaps = 0;
  const answers = new Map(); // taskId -> result body
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    if (req.method === 'POST' && u.pathname === '/api/channel/task') {
      let s = ''; req.on('data', (d) => (s += d)); req.on('end', () => {
        const b = JSON.parse(s);
        tasked.push(b);
        const taskId = 't-' + tasked.length;
        if (b.data === snapCmd) { snaps++; answers.set(taskId, snaps >= 4 ? 'DETOR T1 D1 B0 R1' : 'DETOR T0 D0 B0 R1'); }
        else if (b.data === wmiCmd) answers.set(taskId, 'LAUNCHED:0');
        else if (String(b.data || '').includes('del ')) answers.set(taskId, 'CLEANED');
        else answers.set(taskId, 'ok');
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ ok: true, taskId }));
      });
      return;
    }
    if (req.method === 'POST' && u.pathname === '/api/channel/stage') {
      let s = ''; req.on('data', (d) => (s += d)); req.on('end', () => {
        const b = JSON.parse(s);
        stages.push(b);
        const taskId = 'st-' + stages.length;
        answers.set(taskId, 'staged ' + b.name + ' (1 bytes, sha256 verified)');
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ ok: true, taskId, artifactId: 'a-1', sha256: 'x' }));
      });
      return;
    }
    if (req.method === 'GET' && u.pathname === '/api/channel/results') {
      const taskId = u.searchParams.get('taskId');
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ results: answers.has(taskId) ? [{ taskId, data: answers.get(taskId) }] : [] }));
      return;
    }
    res.writeHead(404); res.end('{}');
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const api = 'http://127.0.0.1:' + srv.address().port;
  const cliPath = join(dirname(fileURLToPath(import.meta.url)), '..', 'tools', 'cli.mjs');
  try {
    const out = await new Promise((resolve, reject) => {
      const p = spawn(process.execPath, [cliPath, 'detoracle', 'calibrate', 'agent-1', api], { stdio: ['ignore', 'pipe', 'pipe'] });
      let so = '', se = '';
      p.stdout.on('data', (d) => (so += d)); p.stderr.on('data', (d) => (se += d));
      // the exit code is NOT asserted: node's undici teardown on Windows can abort the
      // process after stdout is complete (UV_HANDLE_CLOSING assertion) — the contract
      // under test is the wire shape + the printed verdict, both captured below.
      p.on('error', reject); p.on('close', () => resolve(so + '\n' + se));
    });
    assert.ok(tasked.length >= 5, 'expected the calibrate task sequence, got ' + tasked.length);
    for (const b of tasked) assert.equal(b.kind, 'shell', 'task queued with wrong kind: ' + JSON.stringify(b).slice(0, 120));
    assert.ok(tasked.some((b) => b.data === snapCmd), 'the snapshot command must ride as task data');
    assert.ok(tasked.some((b) => b.data === wmiCmd), 'the detached WMI drop must ride as task data');
    // range day #2: the EICAR control now rides the STAGE (literal, unmangled) and the
    // drop is WMI-detached — the inline Set-Content task wedged the carrier on a
    // firing sensor. Assert exactly one stage, carrying the byte-exact dropper.
    assert.equal(stages.length, 1);
    assert.equal(stages[0].name, 'eicar-drop.ps1');
    assert.ok(Buffer.from(String(stages[0].b64 || ''), 'base64').toString('utf8').includes(EICAR_STRING));
    assert.ok(!tasked.some((b) => String(b.data || '').includes(EICAR_STRING)), 'the inline EICAR drop must NOT be tasked on the detached carrier');
    assert.match(out, /"calibrated": true/);
  } finally {
    srv.close();
  }
});

// ── THE OFFLINE CALIBRATION MODE (2026-08-25, the sealed-net finding — measured by
// controlled A/B on two offline images + an online host control): current Defender
// does NOT convict an EICAR write via on-access RTP OFFLINE; on-demand MpCmdRun
// custom scan DOES convict from local signatures. These pins lock the honest shape:
// channels reported separately, never merged; the scan leg rides the detached
// carrier (a direct MpCmdRun shell task wedged even the wedge-guarded agent);
// bounded poll => 'unknown', never a hang; carrier failures never read 'clean'.
import { buildEicarScanScript, buildScanResultCommand, parseScanResult, OFFLINE_RATIONALE, ONACCESS_NOT_GRADED_PHRASE } from '../tools/detoracle.mjs';

test('buildEicarScanScript: the on-demand control — custom scan of the staged drop, result-line contract', () => {
  const s = buildEicarScanScript();
  assert.match(s, /-Scan -ScanType 3 -File 'C:\\Windows\\Temp\\eicar-cal\.tmp'/); // MpCmdRun custom scan of the staged drop
  assert.match(s, /Id=1116/);
  assert.match(s, /Id=1117/);
  assert.match(s, /\$pre = 0; if \(Test-Path/); // the drop-existence guard (a vanished file is never misread as a quarantine)
  assert.match(s, /Set-Content -Path 'C:\\Windows\\Temp\\eicar-scan-result\.txt'/); // the detached leg's only report channel
  assert.match(s, /DETSCAN exit=/);
  assert.match(s, /MpCmdRun\.exe/); // located under the current Platform dir with the classic fallback
  assert.ok(!s.includes(EICAR_STRING), 'the scanner script carries the PATH only — script-scan surfaces must see a benign invocation');
});

test('buildScanResultCommand + parseScanResult: the bounded poll read, fail-closed parse', () => {
  const c = buildScanResultCommand();
  assert.match(c, /Test-Path 'C:\\Windows\\Temp\\eicar-scan-result\.txt'/);
  assert.match(c, /PENDING/);
  assert.ok(!c.includes('|'), 'no cmd-level pipes (wedge-catalogue safe)');
  assert.deepEqual(parseScanResult('DETSCAN exit=0 found=1 d1116=1 b1117=1 pre=1 file=0'), { exit: 0, found: 1, d1116: 1, b1117: 1, pre: 1, file: 0 });
  assert.equal(parseScanResult('PENDING'), null);
  assert.equal(parseScanResult(''), null);
  assert.equal(parseScanResult('DETSCAN exit=x found=1 d1116=1 b1117=1 pre=1 file=0'), null);
  assert.equal(parseScanResult(undefined), null);
});

// Scripted offline-mode channel: benign stays flat; the write leg's post-drop
// snapshot (snap #4) grows only when the sensor fires on-access; the scan leg's
// result file answers per the script. Task order per run: 4 snapshots + WMI drop,
// stale-result del, 2 stages (drop + scan scripts), WMI scan launch, result polls,
// final cleanup del.
function offlineScript({ scanConvicts = true, dropFires = false, stageOk = true, dropLaunchOk = true, scanLaunchOk = true, scanAnswers = true, dropLandsPre = true }) {
  const snapCmd = buildSnapshotCommand();
  const wmiDrop = buildEicarWmiDropCommand();
  const wmiScan = buildEicarWmiDropCommand('C:\\Windows\\System32\\agentbox\\eicar-scan.ps1');
  const resultCmd = buildScanResultCommand();
  let snaps = 0;
  const staged = [];
  const tasked = [];
  return {
    staged, tasked,
    stageFile: async (_a, name, buf) => {
      staged.push({ name, body: String(buf) });
      return stageOk ? 'staged ' + name + ' (' + String(buf).length + ' bytes, sha256 verified)' : 'stage REJECTED: sha256 mismatch';
    },
    taskAgent: async (_a, cmd) => {
      tasked.push(cmd);
      if (cmd === snapCmd) { snaps++; return dropFires && snaps === 4 ? 'DETOR T1 D1 B0 R1' : 'DETOR T0 D0 B0 R1'; }
      if (cmd === wmiDrop) return dropLaunchOk ? 'LAUNCHED:0' : 'LAUNCHED:2';
      if (cmd === wmiScan) return scanLaunchOk ? 'LAUNCHED:0' : 'LAUNCHED:2';
      if (cmd === resultCmd) {
        if (!scanAnswers) return 'PENDING'; // the wedge path: the scan never reports
        if (!dropLandsPre) return 'DETSCAN exit=0 found=0 d1116=0 b1117=0 pre=0 file=0'; // the drop never landed
        return scanConvicts ? 'DETSCAN exit=0 found=1 d1116=1 b1117=1 pre=1 file=0' : 'DETSCAN exit=0 found=0 d1116=0 b1117=0 pre=1 file=1';
      }
      if (cmd.includes('del ')) return 'CLEANED';
      return 'ok';
    },
  };
}

test('calibrate offline: on-demand convicts + on-access silent -> mode-calibrated WITH the not-graded label, on-access stays uncalibrated', async () => {
  const s = offlineScript({ scanConvicts: true, dropFires: false }); // the measured sealed-net reality
  const c = await calibrate({ taskAgent: s.taskAgent, stageFile: s.stageFile, agentId: 'range-1', settleMs: 5, offlineControl: true, scanTimeoutMs: 1000, scanPollMs: 2 });
  // the channel-separated verdict shape — both lanes, independent, never merged
  assert.equal(c.offline, true);
  assert.deepEqual(c.channels, { onDemandConviction: true, onAccessWrite: 'silent' });
  assert.equal(c.calibrated, true);                  // the ON-DEMAND lane proved conviction
  assert.equal(c.calibratedOnAccessWrite, false);    // the on-access lane did NOT — stays false
  assert.deepEqual(c.baselineTrusted, { onDemand: true, onAccessWrite: false }); // split per channel, never a bare bool
  assert.equal(c.rationale, OFFLINE_RATIONALE);
  assert.equal(c.gradingLabel, ONACCESS_NOT_GRADED_PHRASE);
  assert.match(c.note, /on-access write layer NOT graded \(offline cloud-conviction gap\)/);
  assert.match(c.note, /offline baseline: on-demand conviction proven from local signatures/);
  // 'silent' on an exercised lane is EVIDENCE — reported as such, loudly
  assert.match(c.reasons.join(' '), /on-access write leg exercised and read SILENT/);
  assert.match(c.reasons.join(' '), /on-access write layer NOT graded/);
  // the scan evidence, verbatim
  assert.equal(c.scan.conviction, true);
  assert.equal(c.scan.d1116, 1);
  assert.equal(c.scan.pre, 1);
  assert.equal(c.scan.file, 0); // quarantined
  assert.match(c.scan.note, /CONVICTED.*from local signatures/);
  // the mechanics: the drop AND the scanner both rode the staged+WMI detached carrier
  assert.deepEqual(s.staged.map((x) => x.name), ['eicar-drop.ps1', 'eicar-scan.ps1']);
  assert.match(s.staged[1].body, /-ScanType 3/);
  assert.ok(!s.staged[1].body.includes(EICAR_STRING));
  const wmiScan = buildEicarWmiDropCommand('C:\\Windows\\System32\\agentbox\\eicar-scan.ps1');
  assert.ok(s.tasked.includes(wmiScan), 'the MpCmdRun leg must ride the detached WMI launch, never a direct shell task');
  // cleanup doctrine: the drop and the result artifact are both deleted afterwards
  assert.ok(s.tasked.some((cmd) => cmd.includes('del ') && cmd.includes('eicar-cal.tmp') && cmd.includes('eicar-scan-result.txt')));
});

test('calibrate offline: on-demand convicted + on-access UNPROVEN (write-leg snapshots unreadable) -> mode-calibrated true WITH the label everywhere it matters', async () => {
  const snapCmd = buildSnapshotCommand();
  const wmiDrop = buildEicarWmiDropCommand();
  const wmiScan = buildEicarWmiDropCommand('C:\\Windows\\System32\\agentbox\\eicar-scan.ps1');
  const resultCmd = buildScanResultCommand();
  let snaps = 0;
  const taskAgent = async (_a, cmd) => {
    if (cmd === snapCmd) { snaps++; return snaps <= 2 ? 'DETOR T0 D0 B0 R1' : 'garbage — the post-drop snapshots failed closed'; } // benign readable, write-leg unreadable
    if (cmd === wmiDrop || cmd === wmiScan) return 'LAUNCHED:0';
    if (cmd === resultCmd) return 'DETSCAN exit=0 found=1 d1116=1 b1117=1 pre=1 file=0';
    if (cmd.includes('del ')) return 'CLEANED';
    return 'ok';
  };
  const stageFile = async (_a, name) => 'staged ' + name + ' (1 bytes, sha256 verified)';
  const c = await calibrate({ taskAgent, stageFile, agentId: 'range-1', settleMs: 5, offlineControl: true, scanTimeoutMs: 1000, scanPollMs: 2 });
  assert.equal(c.calibrated, true); // the on-demand lane proved conviction — the MODE is calibrated
  assert.equal(c.calibratedOnAccessWrite, false);
  assert.deepEqual(c.channels, { onDemandConviction: true, onAccessWrite: 'unproven-offline' });
  assert.deepEqual(c.baselineTrusted, { onDemand: true, onAccessWrite: false });
  assert.equal(c.gradingLabel, ONACCESS_NOT_GRADED_PHRASE);
  assert.match(c.note, /on-access write layer NOT graded \(offline cloud-conviction gap\)/);
  assert.match(c.note, /offline baseline: on-demand conviction proven from local signatures/);
  assert.match(c.reasons.join(' '), /not proven offline/); // the write leg ran but proved nothing — said, never inferred
});

test('calibrate offline: an on-access CONVICTION grades both lanes trusted (no label needed)', async () => {
  const s = offlineScript({ scanConvicts: true, dropFires: true }); // the write leg fired (e.g. the host came online)
  const c = await calibrate({ taskAgent: s.taskAgent, stageFile: s.stageFile, agentId: 'range-1', settleMs: 5, offlineControl: true, scanTimeoutMs: 1000, scanPollMs: 2 });
  assert.deepEqual(c.channels, { onDemandConviction: true, onAccessWrite: 'convicted' });
  assert.equal(c.calibrated, true);
  assert.equal(c.calibratedOnAccessWrite, true);
  assert.deepEqual(c.baselineTrusted, { onDemand: true, onAccessWrite: true });
  assert.equal(c.gradingLabel, undefined);
  assert.ok(!/NOT graded/.test(c.note));
});

test('calibrate offline: drop carrier stage-refused -> write leg unproven-offline, on-demand unknown-with-cause, never clean', async () => {
  const s = offlineScript({ stageOk: false });
  const c = await calibrate({ taskAgent: s.taskAgent, stageFile: s.stageFile, agentId: 'range-1', settleMs: 5, offlineControl: true, scanTimeoutMs: 1000, scanPollMs: 2 });
  assert.equal(c.calibrated, false);
  assert.equal(c.calibratedOnAccessWrite, false);
  assert.deepEqual(c.channels, { onDemandConviction: 'unknown', onAccessWrite: 'unproven-offline' });
  assert.match(c.scan.note, /drop carrier failed/); // the scan leg never ran — nothing on disk to scan
  assert.match(c.reasons.join(' '), /carrier failed at stage/);
  assert.match(c.reasons.join(' '), /unproven-offline|not proven offline/);
  assert.match(c.reasons.join(' '), /on-access write layer NOT graded/);
  assert.equal(s.staged.length, 1); // the scanner stage was never attempted after the drop failed
});

test('calibrate offline: the scan leg never answers (the wedge path) -> unknown inside the bound, NEVER a hang', { timeout: 10000 }, async () => {
  const s = offlineScript({ scanAnswers: false });
  const started = Date.now();
  const c = await calibrate({ taskAgent: s.taskAgent, stageFile: s.stageFile, agentId: 'range-1', settleMs: 5, offlineControl: true, scanTimeoutMs: 60, scanPollMs: 5 });
  assert.ok(Date.now() - started < 5000, 'the bounded poll must return well inside its deadline, not hang');
  assert.equal(c.channels.onDemandConviction, 'unknown');
  assert.equal(c.calibrated, false);
  assert.match(c.scan.note, /never reported within 60ms/);
  assert.match(c.scan.note, /does NOT hang/);
  assert.ok(!/clean/i.test(c.scan.note), 'a wedged scan leg is unknown, never clean');
});

test('calibrate offline: a completed scan that does NOT convict fails the whole baseline (no lane proven)', async () => {
  const s = offlineScript({ scanConvicts: false });
  const c = await calibrate({ taskAgent: s.taskAgent, stageFile: s.stageFile, agentId: 'range-1', settleMs: 5, offlineControl: true, scanTimeoutMs: 1000, scanPollMs: 2 });
  assert.equal(c.channels.onDemandConviction, false);
  assert.equal(c.calibrated, false);
  assert.deepEqual(c.baselineTrusted, { onDemand: false, onAccessWrite: false });
  assert.match(c.scan.note, /did NOT convict/);
  assert.match(c.reasons.join(' '), /NO offline grading lane is calibrated/);
  assert.match(c.note, /UNCALIBRATED BASELINE/);
});

test('calibrate offline: a drop that never landed (pre=0) is unknown — a vanished file is never misread as a quarantine', async () => {
  const s = offlineScript({ dropLandsPre: false });
  const c = await calibrate({ taskAgent: s.taskAgent, stageFile: s.stageFile, agentId: 'range-1', settleMs: 5, offlineControl: true, scanTimeoutMs: 1000, scanPollMs: 2 });
  assert.equal(c.channels.onDemandConviction, 'unknown');
  assert.equal(c.calibrated, false);
  assert.match(c.scan.note, /ABSENT when the scan ran \(pre=0\)/);
});

test('calibrate offline: the mode REQUIRES the detached carrier (never the inline drop)', async () => {
  await assert.rejects(() => calibrate({ taskAgent: async () => 'ok', agentId: 'x', offlineControl: true }), TypeError);
  await assert.rejects(() => calibrate({ taskAgent: async () => 'ok', agentId: 'x', offlineControl: true, stageFile: 'not-a-function' }), TypeError);
});

test('calibrate default-mode regression: no offlineControl -> legacy shape, no offline keys, no scan leg', async () => {
  const s = calibDetached({ eicarFires: true });
  const c = await calibrate({ taskAgent: s.taskAgent, stageFile: s.stageFile, agentId: 'range-1', settleMs: 5 }); // no offlineControl
  assert.equal(c.calibrated, true);
  assert.equal(typeof c.baselineTrusted, 'boolean'); // the legacy scalar, untouched
  assert.equal(c.offline, undefined);
  assert.equal(c.channels, undefined);
  assert.equal(c.scan, undefined);
  assert.equal(c.rationale, undefined);
  assert.equal(s.staged.length, 1); // the drop script only — the scan leg must NOT run in default mode
});

test('calibrationGate: an offline calibration splits trust per channel and labels every grade, honestly', () => {
  const measured = { verdict: 'clean', newDetections: 0, note: 'no detection observed in this window' };
  const offCal = { offline: true, calibrated: true, calibratedOnAccessWrite: false, baselineTrusted: { onDemand: true, onAccessWrite: false }, channels: { onDemandConviction: true, onAccessWrite: 'silent' }, reasons: ['on-access silent'] };
  const g = calibrationGate(measured, offCal);
  assert.equal(g.verdict, 'clean'); // the measurement is kept, honestly
  assert.deepEqual(g.baselineTrusted, { onDemand: true, onAccessWrite: false }); // split — never merged into a bare pass
  assert.equal(g.calibratedOnAccessWrite, false);
  assert.equal(g.gradingLabel, ONACCESS_NOT_GRADED_PHRASE);
  assert.equal(g.rationale, OFFLINE_RATIONALE);
  assert.match(g.note, /on-access write layer NOT graded \(offline cloud-conviction gap\)/);
  assert.match(g.note, /no detection observed in this window/); // the measured note survives
  // both lanes proven -> trusted, no label
  const full = calibrationGate(measured, { offline: true, calibrated: true, calibratedOnAccessWrite: true, baselineTrusted: { onDemand: true, onAccessWrite: true }, channels: { onDemandConviction: true, onAccessWrite: 'convicted' } });
  assert.deepEqual(full.baselineTrusted, { onDemand: true, onAccessWrite: true });
  assert.equal(full.calibratedOnAccessWrite, true);
  assert.equal(full.gradingLabel, undefined);
  // the on-demand lane unproven -> NO lane calibrated, loudly
  const bad = calibrationGate(measured, { offline: true, calibrated: false, calibratedOnAccessWrite: false, baselineTrusted: { onDemand: false, onAccessWrite: false }, channels: { onDemandConviction: 'unknown', onAccessWrite: 'unproven-offline' }, reasons: ['scan never reported'] });
  assert.deepEqual(bad.baselineTrusted, { onDemand: false, onAccessWrite: false });
  assert.match(bad.note, /UNCALIBRATED BASELINE/);
  assert.match(bad.note, /on-demand lane did not prove conviction/);
  assert.deepEqual(bad.calibrationReasons, ['scan never reported']);
});

test('assess: a handed-in offline calibration stamps the verdict per channel (the evasion-grade path)', async () => {
  const snap = 'DETOR T0 D0 B0 R1';
  const taskAgent = async () => snap;
  const v = await assess({ taskAgent, agentId: 'x', command: 'run-probe', settleMs: 5, calibration: { offline: true, calibrated: true, calibratedOnAccessWrite: false, baselineTrusted: { onDemand: true, onAccessWrite: false }, channels: { onDemandConviction: true, onAccessWrite: 'silent' }, reasons: [] } });
  assert.equal(v.verdict, 'clean');
  assert.deepEqual(v.baselineTrusted, { onDemand: true, onAccessWrite: false });
  assert.equal(v.gradingLabel, ONACCESS_NOT_GRADED_PHRASE);
  assert.match(v.note, /on-access write layer NOT graded/);
});

test('cli wiring: detoracle calibrate --offline runs the on-demand control, prints the split verdict + rationale', { timeout: 120000 }, async () => {
  const snapCmd = buildSnapshotCommand();
  const wmiDrop = buildEicarWmiDropCommand();
  const wmiScan = buildEicarWmiDropCommand('C:\\Windows\\System32\\agentbox\\eicar-scan.ps1');
  const resultCmd = buildScanResultCommand();
  const tasked = []; // every POST /api/channel/task body, verbatim
  const stages = []; // every POST /api/channel/stage body, verbatim
  let snaps = 0;
  const answers = new Map(); // taskId -> result body
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    if (req.method === 'POST' && u.pathname === '/api/channel/task') {
      let s = ''; req.on('data', (d) => (s += d)); req.on('end', () => {
        const b = JSON.parse(s);
        tasked.push(b);
        const taskId = 't-' + tasked.length;
        if (b.data === snapCmd) { snaps++; answers.set(taskId, 'DETOR T0 D0 B0 R1'); } // on-access silent — the sealed-net reality
        else if (b.data === wmiDrop || b.data === wmiScan) answers.set(taskId, 'LAUNCHED:0');
        else if (b.data === resultCmd) answers.set(taskId, 'DETSCAN exit=0 found=1 d1116=1 b1117=1 pre=1 file=0');
        else if (String(b.data || '').includes('del ')) answers.set(taskId, 'CLEANED');
        else answers.set(taskId, 'ok');
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ ok: true, taskId }));
      });
      return;
    }
    if (req.method === 'POST' && u.pathname === '/api/channel/stage') {
      let s = ''; req.on('data', (d) => (s += d)); req.on('end', () => {
        const b = JSON.parse(s);
        stages.push(b);
        const taskId = 'st-' + stages.length;
        answers.set(taskId, 'staged ' + b.name + ' (1 bytes, sha256 verified)');
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ ok: true, taskId, artifactId: 'a-1', sha256: 'x' }));
      });
      return;
    }
    if (req.method === 'GET' && u.pathname === '/api/channel/results') {
      const taskId = u.searchParams.get('taskId');
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ results: answers.has(taskId) ? [{ taskId, data: answers.get(taskId) }] : [] }));
      return;
    }
    res.writeHead(404); res.end('{}');
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const api = 'http://127.0.0.1:' + srv.address().port;
  const cliPath = join(dirname(fileURLToPath(import.meta.url)), '..', 'tools', 'cli.mjs');
  try {
    const out = await new Promise((resolve, reject) => {
      const p = spawn(process.execPath, [cliPath, 'detoracle', 'calibrate', 'agent-1', api, '--offline'], { stdio: ['ignore', 'pipe', 'pipe'] });
      let so = '', se = '';
      p.stdout.on('data', (d) => (so += d)); p.stderr.on('data', (d) => (se += d));
      // the exit code is NOT asserted (Windows undici teardown can abort post-stdout —
      // see the legacy wiring pin); the contract is the wire shape + the printed verdict.
      p.on('error', reject); p.on('close', () => resolve(so + '\n' + se));
    });
    for (const b of tasked) assert.equal(b.kind, 'shell', 'task queued with wrong kind: ' + JSON.stringify(b).slice(0, 120));
    // the wire shape: BOTH scripts staged, the scan launched DETACHED, the result polled
    assert.deepEqual(stages.map((b) => b.name), ['eicar-drop.ps1', 'eicar-scan.ps1']);
    assert.ok(Buffer.from(String(stages[1].b64 || ''), 'base64').toString('utf8').includes('-ScanType 3'));
    assert.ok(!Buffer.from(String(stages[1].b64 || ''), 'base64').toString('utf8').includes(EICAR_STRING));
    assert.ok(tasked.some((b) => b.data === wmiScan), 'MpCmdRun must never ride a direct shell task — detached WMI only');
    assert.ok(tasked.some((b) => b.data === resultCmd), 'the bounded result poll must be tasked');
    assert.ok(!tasked.some((b) => String(b.data || '').includes('MpCmdRun')), 'no direct MpCmdRun shell task on the wire (the wedge path)');
    // the printed verdict: split channels, mode-calibrated, on-access labeled, rationale printed
    assert.match(out, /"offline": true/);
    assert.match(out, /"onDemandConviction": true/);
    assert.match(out, /"onAccessWrite": "silent"/);
    assert.match(out, /"calibrated": true/);
    assert.match(out, /"calibratedOnAccessWrite": false/);
    assert.match(out, /"onDemand": true/);
    assert.match(out, /"onAccessWrite": false/);
    assert.match(out, /on-access write layer NOT graded \(offline cloud-conviction gap\)/);
    assert.match(out, /offline baseline: on-demand conviction proven from local signatures; on-access EICAR conviction requires Defender cloud reachability \(measured 2026-08-24\)/);
  } finally {
    srv.close();
  }
});
