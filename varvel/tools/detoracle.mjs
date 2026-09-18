// VARVEL — detoracle: the detection oracle (structured "did the defender see it?").
//
// Why it exists: a nation-grade offensive platform must MEASURE its own detectability,
// never assert it. Every technique VARVEL runs against a defended target should be able
// to answer one question honestly: did the defender log, alert, or block that? Today
// that answer is hand-rolled per engagement (we literally queried Get-MpThreatDetection
// by hand during the ICMP range work). This tool makes it a first-class, repeatable
// primitive over the governed channel.
//
// How it works (snapshot/diff/classify, all over the existing task channel — no new
// guest code, no EDR tampering, ever):
//   1. snapshot BEFORE: Defender threat-detection count, Operational 1116 (detection)
//      and 1117 (action taken) event counts, real-time-protection state — one compact
//      line, well under the channel's 120-char preview cap.
//   2. run the probe command (the technique being graded).
//   3. settle, then snapshot AFTER (+ optional liveness check for staged probes).
//   4. classify the diff into a structured verdict.
//
// Verdict tiers: 'clean' | 'detected' | 'blocked' | 'unmonitored'.
// THE HONESTY CONTRACT (non-negotiable, same doctrine as liveVerified): 'clean' means
// "no detection observed in this window, on this host, with this Defender config" —
// it is NEVER a claim of undetectability. 'unmonitored' means the sensor was off, so
// NO verdict about detectability is possible at all — reported loudly, never as clean.
// We measure and report. (Doctrine 2026-08-12: evasion internals now ship as their own
// double-gated, patch-verified, restorable tier — engine/evasion.mjs. When an agent has
// neutralized its own monitoring path, the verdict from that window is NOT 'clean': it
// is 'unmonitored', phrased exactly as MONITORING_NEUTRALIZED_PHRASE — see
// honestVerdict below and tools/evasion.mjs.)
//
// CALIBRATION GATE (field finding 2026-08): the range image's Defender proved
// CUSTOMIZED SOFT — it did not flag a byte-perfect EICAR file. So the oracle
// carries its own control: calibrate() requires benign -> 'clean' AND the EICAR
// test string -> 'detected'/'blocked' with RTP on, else calibrated:false and
// every gated verdict is stamped baselineTrusted:false (calibrationGate owns
// the phrasing). The oracle REFUSES to call itself calibrated on a baseline
// that fails EICAR — harden the baseline first (tools/rangehard.mjs).
//
// OFFLINE CALIBRATION MODE (opt-in, 2026-08-25 — the sealed-net finding, proven by
// controlled A/B on two independent offline images + an online host control): current
// Defender (platform 4.18.26070.9, engine 1.1.26070.7, sigs current) does NOT convict
// a byte-exact EICAR write via on-access RTP when the host is OFFLINE (zero 1116/1117,
// the file persists) — the SAME write convicts instantly ONLINE with cloud-protection
// lookups. On-DEMAND custom scan (MpCmdRun -ScanType 3) DOES convict offline from
// local signatures. So on a sealed lab the legacy EICAR-as-write gate can never go
// green and the honest control is the on-demand channel. calibrate({offlineControl:true})
// therefore grades the channels SEPARATELY and never merges them: the on-demand scan
// is the PRIMARY control, the on-access write leg is reported as its own lane
// ('convicted' | 'silent' | 'unproven-offline'), and when on-access did not convict,
// every grade gated on this calibration carries ONACCESS_NOT_GRADED_PHRASE. 'silent'
// on an exercised lane is EVIDENCE (reported as such), never a failure to hide and
// never a bare 'clean'. The MpCmdRun leg rides the staged-script + WMI-detached
// carrier on purpose: a direct channel shell task of MpCmdRun wedged even the
// wedge-guarded agent (delivered-forever, range-builder 2026-08-25).

export const SETTLE_MS = 6000; // static detections are near-instant; behavior needs a few s

// The EXACT report phrase for a window measured while the agent's own scan/report path
// was patched (stage-1 evasion tier, enable-verified before the probe and restored
// after). 'monitoring neutralized' is a self-reported, patch-verified state — it must
// NEVER be rendered as 'clean' anywhere (report, console, ledger).
export const MONITORING_NEUTRALIZED_PHRASE = 'monitoring neutralized (self-reported, patch-verified)';

// The phrasing contract, enforced in one place. honestVerdict(v, {monitoringNeutralized:true})
// rewrites a verdict measured under active neutralization:
//   'clean'       -> 'unmonitored' with the neutralized phrase (a quiet window whose
//                    sensor was patched is NOT clean — this is the line)
//   'unmonitored' -> stays 'unmonitored', note prefixed with the phrase
//   'detected' / 'blocked' -> PASS THROUGH UNTOUCHED: the patch covers the agent's own
//                    process, not every sensor on the box — a detection that still fired
//                    is still a detection, honestly reported (the patch's coverage is
//                    measured by exactly this)
//   'unknown'     -> passes through
// The raw verdict is preserved under .rawVerdict for the evidence trail.
export function honestVerdict(v, { monitoringNeutralized = false } = {}) {
  if (!v || typeof v !== 'object') return v;
  if (!monitoringNeutralized) return v;
  if (v.verdict === 'clean' || v.verdict === 'unmonitored') {
    return {
      ...v,
      verdict: 'unmonitored',
      rawVerdict: v.verdict,
      note: MONITORING_NEUTRALIZED_PHRASE + ' — the agent\'s own in-process scan/report path was patched during this window (stage-1 evasion tier: enabled, verified, restored). '
        + (v.verdict === 'clean' ? 'The quiet diff below is the patch working, NOT a clean detectability result — this window must never be reported as clean.' : String(v.note || '')),
    };
  }
  return v;
}

// One compact snapshot: DETOR T<threats> D<1116s> B<1117s> R<0|1>
export function buildSnapshotCommand() {
  return 'powershell -NoProfile -Command "'
    + "$t=(Get-MpThreatDetection -ErrorAction SilentlyContinue | Measure-Object).Count;"
    + "$d=(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1116} -MaxEvents 50 -ErrorAction SilentlyContinue | Measure-Object).Count;"
    + "$b=(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1117} -MaxEvents 50 -ErrorAction SilentlyContinue | Measure-Object).Count;"
    + "$r=0; $cs=Get-MpComputerStatus -ErrorAction SilentlyContinue; if ($cs -and $cs.RealTimeProtectionEnabled) { $r=1 };"
    + "Write-Output ('DETOR T' + $t + ' D' + $d + ' B' + $b + ' R' + $r)"
    + '"';
}

// Parse a snapshot line. Fail-closed: anything unexpected -> null (never guess state).
export function parseSnapshot(text) {
  const m = /DETOR T(\d+) D(\d+) B(\d+) R([01])/.exec(String(text || ''));
  if (!m) return null;
  return { threats: Number(m[1]), d1116: Number(m[2]), d1117: Number(m[3]), rtp: Number(m[4]) === 1 };
}

// Classify a before/after diff into a structured verdict.
// opts.probeAlive: true/false when a liveness check ran, undefined when not checked.
export function classify(before, after, { probeAlive } = {}) {
  if (!before || !after) {
    return { verdict: 'unknown', newDetections: 0, newActions: 0, note: 'snapshot unreadable — no verdict possible (fail-closed)' };
  }
  const newDetections = Math.max(0, (after.threats - before.threats) + (after.d1116 - before.d1116));
  const newActions = Math.max(0, after.d1117 - before.d1117);
  const base = { newDetections, newActions };
  if (!after.rtp) return { ...base, verdict: 'unmonitored', note: 'real-time protection is OFF on this host — no detectability verdict possible (this is NOT clean)' };
  if (newActions > 0 || (newDetections > 0 && probeAlive === false)) {
    return { ...base, verdict: 'blocked', note: 'Defender took action (1117/remediation' + (probeAlive === false ? ' + probe process died' : '') + ')' };
  }
  if (newDetections > 0) return { ...base, verdict: 'detected', note: 'Defender logged/alerted a detection (threat list or 1116 grew)' };
  if (probeAlive === false) return { ...base, verdict: 'detected', note: 'probe process died without a logged detection (behavior-kill shape) — treated as detected, honestly' };
  return { ...base, verdict: 'clean', note: 'no detection observed in this window, on this host, with this Defender config — NOT a claim of undetectability' };
}

// Orchestrate a full assessment over the governed channel.
// taskAgent(agentId, command) -> resultPreview string (the postex pattern — injectable).
// Returns the verdict object plus the raw evidence.
// opts.calibration: a calibrate() result — when present and calibrated!==true the
// verdict is stamped baselineTrusted:false with the gate phrase (never hidden).
export async function assess({ taskAgent, agentId, command, settleMs = SETTLE_MS, checkCommand, calibration }) {
  if (typeof taskAgent !== 'function') throw new TypeError('detoracle.assess needs a taskAgent(agentId, command)');
  if (!agentId || !command) throw new TypeError('detoracle.assess needs agentId and a probe command');
  const snapCmd = buildSnapshotCommand();
  const beforeRaw = await taskAgent(agentId, snapCmd);
  const before = parseSnapshot(beforeRaw);
  const probeResult = await taskAgent(agentId, command);
  await new Promise((r) => setTimeout(r, settleMs));
  const afterRaw = await taskAgent(agentId, snapCmd);
  const after = parseSnapshot(afterRaw);
  let probeAlive;
  if (checkCommand) {
    const aliveRaw = await taskAgent(agentId, checkCommand);
    probeAlive = /ALIVE/i.test(String(aliveRaw || ''));
  }
  const v = classify(before, after, { probeAlive });
  const gated = calibration ? calibrationGate(v, calibration) : v;
  return {
    ...gated,
    probeAlive,
    evidence: { before: beforeRaw, after: afterRaw, probeResult: String(probeResult || '').slice(0, 200) },
    settleMs,
    at: new Date().toISOString(),
  };
}

// ── THE EICAR CALIBRATION GATE ──────────────────────────────────────────────
// Why it exists (field finding 2026-08): the Enclave range's Defender was found
// CUSTOMIZED SOFT — a byte-perfect EICAR file did not fire and the image carried
// build-time config drift. Evasion graded against a neutered baseline proves
// NOTHING. So the oracle REFUSES to call itself calibrated on a baseline that
// fails the EICAR control, and any verdict handed a failed calibration is
// stamped baselineTrusted:false — loudly, in the note, never as a footnote.
//
// The control (all over the existing governed channel, cleanup doctrine held —
// the test file is deleted afterwards): a benign command MUST classify 'clean'
// and the official EICAR standard AV test string written to disk MUST classify
// 'detected' or 'blocked' with real-time protection on. Anything else means the
// sensor is not a trustworthy grading surface, and the oracle says exactly why.

// The official EICAR standard anti-virus test string (harmless by design —
// every working AV flags it; that is its entire purpose).
export const EICAR_STRING = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';

export const CALIBRATION_FAILED_PHRASE = 'UNCALIBRATED BASELINE (EICAR control failed)';

// The EICAR drop probe (written under the range's Temp, deleted by calibrate()).
export function buildEicarProbeCommand(path = 'C:\\Windows\\Temp\\eicar-cal.tmp') {
  return "powershell -NoProfile -Command \"Set-Content -Path '" + path + "' -Value '" + EICAR_STRING + "'\"";
}

// DETACHED EICAR DROP CARRIER (field finding 2026-08-24, range day #2): on a FIRING
// sensor the inline drop is intercepted mid-write and the blocked child holds the
// delivery agent's output pipe open — the agent wedges and the post-drop snapshot can
// never run, so the gate read 'unknown' on a HEALTHY, current-signature sensor. The
// detached carrier moves the write behind a fire-and-forget Win32_Process launch of a
// staged script: the tasked process returns immediately (the agent never blocks) and
// Defender eats the DETACHED child if it fires. The gate logic is untouched — the same
// before/after snapshot diff + RTP check + benign control — and a failed launch reads
// 'unknown' with the carrier failure named, NEVER 'clean'. The staged script carries
// the literal EICAR string on purpose: a sensor that quarantines the STAGE fired the
// control early, and that is reported, not worked around (no obfuscation, ever).
export function buildEicarDropScript(path = 'C:\\Windows\\Temp\\eicar-cal.tmp') {
  return "Set-Content -Path '" + path + "' -Value '" + EICAR_STRING + "'\n";
}

// The detached launch: Win32_Process.Create of powershell -File <staged script> — no
// inherited handles, nothing for the delivery agent to wait on. Echoes the WMI
// ReturnValue so the caller can prove the launch happened (0 = process created).
export function buildEicarWmiDropCommand(scriptPath = 'C:\\Windows\\System32\\agentbox\\eicar-drop.ps1') {
  return 'powershell -NoProfile -Command "'
    + "$r=Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine='powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File " + scriptPath + "'};"
    + "Write-Output ('LAUNCHED:' + $r.ReturnValue)"
    + '"';
}

// ── THE OFFLINE CONTROL: on-demand conviction from LOCAL signatures ─────────
// The one-line rationale, printed in every offline-mode verdict and stamped on every
// grade gated on an offline calibration — the measured fact this mode exists to honor.
export const OFFLINE_RATIONALE = 'offline baseline: on-demand conviction proven from local signatures; on-access EICAR conviction requires Defender cloud reachability (measured 2026-08-24)';

// The exact label every evasion grade must carry when the on-access write lane did
// not convict in offline mode. Grading against a lane whose sensor is unproven is
// noise; the label says so everywhere the grade travels.
export const ONACCESS_NOT_GRADED_PHRASE = 'on-access write layer NOT graded (offline cloud-conviction gap)';

// Bounded-poll knobs for the detached MpCmdRun leg. A direct channel shell task of
// `MpCmdRun -Scan -ScanType 3` wedged even the wedge-guarded agent (delivered-forever,
// 2026-08-25), so the scan runs detached and the oracle polls for its result file —
// the deadline below means the oracle reports 'unknown' and NEVER hangs.
export const SCAN_TIMEOUT_MS = 120000; // a single-file custom scan is seconds; 2 min is generous
export const SCAN_POLL_MS = 4000;      // one channel round-trip is ~2s on the range

// The on-demand scan leg as a STAGED script (never a direct shell task — see above):
// locate the current platform's MpCmdRun, snapshot the 1116/1117 counts, run the
// custom scan of the staged EICAR drop SYNCHRONOUSLY, re-read the counts, and write
// ONE compact result line. pre= records the drop's existence BEFORE the scan, so a
// vanished-file reading can never be mistaken for a quarantine when the drop leg
// itself failed. The script contains no EICAR bytes (the path only) — script-scan
// surfaces see a benign scanner invocation.
export function buildEicarScanScript(scanPath = 'C:\\Windows\\Temp\\eicar-cal.tmp', resultPath = 'C:\\Windows\\Temp\\eicar-scan-result.txt') {
  return "$mp = Join-Path $env:ProgramFiles 'Windows Defender\\MpCmdRun.exe'\n"
    + "$plat = Get-ChildItem (Join-Path $env:ProgramData 'Microsoft\\Windows Defender\\Platform') -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1\n"
    + "if ($plat) { $cand = Join-Path $plat.FullName 'MpCmdRun.exe'; if (Test-Path $cand) { $mp = $cand } }\n"
    + "$log = 'Microsoft-Windows-Windows Defender/Operational'\n"
    + "$b16 = @(Get-WinEvent -FilterHashtable @{LogName=$log; Id=1116} -MaxEvents 100 -ErrorAction SilentlyContinue).Count\n"
    + "$b17 = @(Get-WinEvent -FilterHashtable @{LogName=$log; Id=1117} -MaxEvents 100 -ErrorAction SilentlyContinue).Count\n"
    + "$pre = 0; if (Test-Path '" + scanPath + "') { $pre = 1 }\n"
    + "$out = & $mp -Scan -ScanType 3 -File '" + scanPath + "' 2>&1 | Out-String\n"
    + "$code = $LASTEXITCODE\n"
    + "Start-Sleep -Seconds 2\n" // let the 1116/1117 flush land before the re-read
    + "$a16 = @(Get-WinEvent -FilterHashtable @{LogName=$log; Id=1116} -MaxEvents 100 -ErrorAction SilentlyContinue).Count\n"
    + "$a17 = @(Get-WinEvent -FilterHashtable @{LogName=$log; Id=1117} -MaxEvents 100 -ErrorAction SilentlyContinue).Count\n"
    + "$found = -1; $m = [regex]::Match($out, 'found\\s+(\\d+)\\s+threat'); if ($m.Success) { $found = [int]$m.Groups[1].Value }\n"
    + "$post = 0; if (Test-Path '" + scanPath + "') { $post = 1 }\n"
    + "Set-Content -Path '" + resultPath + "' -Value ('DETSCAN exit=' + $code + ' found=' + $found + ' d1116=' + ($a16 - $b16) + ' b1117=' + ($a17 - $b17) + ' pre=' + $pre + ' file=' + $post)\n";
}

// The bounded poll's read: the result file's body once it exists, 'PENDING' until then.
// A single-line powershell command, no cmd-level pipes (wedge-catalogue safe).
export function buildScanResultCommand(resultPath = 'C:\\Windows\\Temp\\eicar-scan-result.txt') {
  return 'powershell -NoProfile -Command "'
    + "if (Test-Path '" + resultPath + "') { Get-Content -Path '" + resultPath + "' -Raw } else { Write-Output 'PENDING' }"
    + '"';
}

// Parse a scan-result line. Fail-closed, same doctrine as parseSnapshot: anything
// unexpected -> null (a PENDING body, a wedge-garbled preview, a half-written file).
export function parseScanResult(text) {
  const m = /DETSCAN exit=(-?\d+) found=(-?\d+) d1116=(-?\d+) b1117=(-?\d+) pre=([01]) file=([01])/.exec(String(text || ''));
  if (!m) return null;
  return { exit: Number(m[1]), found: Number(m[2]), d1116: Number(m[3]), b1117: Number(m[4]), pre: Number(m[5]), file: Number(m[6]) };
}

// Run the calibration control. Returns { calibrated, baselineTrusted, benign,
// eicar, reasons[] } — calibrated is true ONLY when benign reads 'clean' AND
// EICAR reads 'detected'/'blocked' AND real-time protection was on for both
// windows. Every failure is enumerated in reasons, honestly (a 'clean' EICAR
// means the file-signature layer is customized-soft — say exactly that).
//
// opts.offlineControl (2026-08-25, the sealed-net finding): grade the channels
// SEPARATELY for an OFFLINE host. The on-demand MpCmdRun custom scan of the staged
// drop is the PRIMARY control (it convicts from local signatures without the cloud);
// the on-access write leg is reported as its own lane and can NEVER be proven on a
// sealed net (measured: it needs Defender cloud reachability). Returns
// { calibrated, calibratedOnAccessWrite, baselineTrusted:{onDemand,onAccessWrite},
//   channels:{onDemandConviction, onAccessWrite}, benign, eicar, scan, reasons[],
//   offline:true, rationale, gradingLabel? } — 'calibrated' covers ONLY the on-demand
// lane; when on-access did not convict, calibratedOnAccessWrite stays false and
// ONACCESS_NOT_GRADED_PHRASE rides the result AND every grade gated on it. A 'silent'
// write leg is evidence, reported loudly; 'unproven-offline' when the leg never ran.
// Offline mode REQUIRES the detached carrier (stageFile) — the inline drop wedges a
// firing sensor and the scan leg wedges a direct shell task; both ride staged+WMI.
export async function calibrate({ taskAgent, agentId, settleMs = SETTLE_MS, eicarPath = 'C:\\Windows\\Temp\\eicar-cal.tmp', stageFile = null, dropScriptPath = 'C:\\Windows\\System32\\agentbox\\eicar-drop.ps1', offlineControl = false, scanScriptPath = 'C:\\Windows\\System32\\agentbox\\eicar-scan.ps1', scanResultPath = 'C:\\Windows\\Temp\\eicar-scan-result.txt', scanTimeoutMs = SCAN_TIMEOUT_MS, scanPollMs = SCAN_POLL_MS }) {
  if (typeof taskAgent !== 'function') throw new TypeError('detoracle.calibrate needs a taskAgent(agentId, command)');
  if (!agentId) throw new TypeError('detoracle.calibrate needs agentId');
  if (offlineControl && typeof stageFile !== 'function') throw new TypeError('detoracle.calibrate offlineControl needs the detached carrier: stageFile(agentId, name, buf) -> result string (the offline control never rides the inline drop)');
  const benign = await assess({ taskAgent, agentId, command: 'hostname', settleMs });
  let eicar;
  let dropLanded = false; // offline mode: did the byte-exact write leg actually run?
  if (stageFile == null) {
    eicar = await assess({ taskAgent, agentId, command: buildEicarProbeCommand(eicarPath), settleMs });
    dropLanded = true; // the write was tasked inline (offline mode never takes this path)
  } else {
    // Detached carrier (see buildEicarDropScript): stage the dropper, launch it behind
    // Win32_Process, and only then grade the snapshot diff. Every carrier failure is
    // loud and 'unknown' — a drop that never happened must never read 'clean'.
    if (typeof stageFile !== 'function') throw new TypeError('detoracle.calibrate stageFile must be stageFile(agentId, name, buf) -> result string');
    const staged = String(await stageFile(agentId, 'eicar-drop.ps1', Buffer.from(buildEicarDropScript(eicarPath), 'utf8')) || '');
    if (!/sha256 verified/i.test(staged)) {
      eicar = { verdict: 'unknown', newDetections: 0, newActions: 0, note: 'EICAR drop carrier failed at stage: ' + staged.slice(0, 160) };
    } else {
      eicar = await assess({ taskAgent, agentId, command: buildEicarWmiDropCommand(dropScriptPath), settleMs });
      if (!/LAUNCHED:0/.test(String(eicar.evidence && eicar.evidence.probeResult || ''))) {
        eicar = { ...eicar, verdict: 'unknown', note: 'EICAR drop carrier failed at launch (WMI ReturnValue != 0 or unreadable): ' + String(eicar.evidence && eicar.evidence.probeResult).slice(0, 160) };
      } else dropLanded = true; // the detached write leg ran; the diff above grades what the sensor did with it
    }
  }
  if (!offlineControl) {
    // cleanup doctrine: the calibration artifact does not outlive the control.
    try { await taskAgent(agentId, 'cmd /c del /f /q "' + eicarPath + '" 2>nul & echo CLEANED'); } catch { /* cleanup is best-effort; the file is inert text */ }

    const reasons = [];
    if (benign.verdict === 'unknown') reasons.push('benign control unreadable (snapshot failed closed) — the channel or the sensor did not answer');
    else if (benign.verdict === 'unmonitored') reasons.push('real-time protection is OFF during the benign control — the sensor is not watching');
    else if (benign.verdict !== 'clean') reasons.push(`benign control classified '${benign.verdict}' (expected 'clean') — the baseline flags harmless activity; grading against it would be noise`);
    if (eicar.verdict === 'clean') reasons.push('EICAR control classified CLEAN — a byte-perfect EICAR test file did not fire: the file-signature layer is customized-soft (the field finding); do NOT grade evasion against this baseline until hardened (tools/rangehard.mjs)');
    else if (eicar.verdict === 'unmonitored') reasons.push('real-time protection is OFF during the EICAR control — the sensor is not watching');
    else if (eicar.verdict === 'unknown') reasons.push(eicar.note || 'EICAR control unreadable (snapshot failed closed) — no calibration verdict possible');
    const calibrated = reasons.length === 0;
    return {
      calibrated, baselineTrusted: calibrated,
      benign: { verdict: benign.verdict, newDetections: benign.newDetections, newActions: benign.newActions },
      eicar: { verdict: eicar.verdict, newDetections: eicar.newDetections, newActions: eicar.newActions, ...(eicar.note ? { note: eicar.note } : {}) },
      reasons,
      note: calibrated
        ? 'calibrated — benign read clean and the EICAR control fired: this baseline is a trustworthy grading sensor'
        : CALIBRATION_FAILED_PHRASE + ' — ' + reasons.join(' | '),
      at: new Date().toISOString(),
    };
  }

  // ── OFFLINE CONTROL MODE: channels graded separately, NEVER merged ─────────
  // The on-access write leg already ran above (the same staged+WMI drop the legacy
  // gate uses — its snapshot diff is the on-access channel's evidence). Map it into
  // the offline vocabulary: 'convicted' | 'silent' | 'unproven-offline'.
  const onAccessWrite = !dropLanded ? 'unproven-offline' // the write leg never ran — say so, never infer
    : (eicar.verdict === 'detected' || eicar.verdict === 'blocked') ? 'convicted'
    : eicar.verdict === 'clean' ? 'silent' // exercised, landed, zero 1116/1117 — the measured gap
    : 'unproven-offline'; // 'unmonitored' (RTP off) or 'unknown' (unreadable): nothing proven

  // The PRIMARY control: on-demand conviction. Stage the scanner, launch it detached
  // (a DIRECT MpCmdRun shell task wedges even the wedge-guarded agent — 2026-08-25),
  // then poll for the result file with a hard deadline. Every carrier failure reads
  // 'unknown' with the cause named — never 'clean', never a hang.
  let onDemandConviction = 'unknown';
  let scan;
  if (!dropLanded) {
    scan = { note: 'on-demand leg skipped — the EICAR drop carrier failed (' + String(eicar.note || 'cause above') + '); nothing on disk to scan' };
  } else {
    // a stale result file from an earlier run must never be read as THIS run's verdict
    try { await taskAgent(agentId, 'cmd /c del /f /q "' + scanResultPath + '" 2>nul & echo CLEANED'); } catch { /* best-effort */ }
    const stagedScan = String(await stageFile(agentId, 'eicar-scan.ps1', Buffer.from(buildEicarScanScript(eicarPath, scanResultPath), 'utf8')) || '');
    if (!/sha256 verified/i.test(stagedScan)) {
      scan = { note: 'on-demand scan carrier failed at stage: ' + stagedScan.slice(0, 160) };
    } else {
      const launch = String(await taskAgent(agentId, buildEicarWmiDropCommand(scanScriptPath)) || '');
      if (!/LAUNCHED:0/.test(launch)) {
        scan = { note: 'on-demand scan carrier failed at launch (WMI ReturnValue != 0 or unreadable): ' + launch.slice(0, 160) };
      } else {
        const deadline = Date.now() + scanTimeoutMs;
        let raw = '';
        while (Date.now() < deadline) {
          await new Promise((r) => setTimeout(r, scanPollMs));
          raw = String(await taskAgent(agentId, buildScanResultCommand(scanResultPath)) || '');
          if (/DETSCAN/.test(raw)) break;
        }
        const parsed = parseScanResult(raw);
        if (!parsed) {
          scan = { note: 'on-demand scan never reported within ' + scanTimeoutMs + 'ms (bounded poll — the oracle does NOT hang; the detached scan leg is the suspect, not the channel): ' + raw.slice(0, 120) };
        } else if (parsed.pre === 0) {
          scan = { ...parsed, note: 'the staged EICAR was ABSENT when the scan ran (pre=0) — the drop leg did not land; no on-demand conviction verdict possible (never read a vanished file as a quarantine here)' };
        } else if (parsed.d1116 > 0 || parsed.b1117 > 0 || parsed.file === 0) {
          onDemandConviction = true;
          scan = { ...parsed, note: 'MpCmdRun custom scan CONVICTED the staged EICAR from local signatures (d1116 +' + parsed.d1116 + ', b1117 +' + parsed.b1117 + (parsed.file === 0 ? ', file quarantined' : '') + ') — the offline primary control passed' };
        } else {
          onDemandConviction = false;
          scan = { ...parsed, note: 'MpCmdRun custom scan completed but did NOT convict the staged EICAR (exit ' + parsed.exit + ', found ' + parsed.found + ', zero new 1116/1117, file still present) — the local signature layer failed the offline control; NO offline grading lane is calibrated' };
        }
      }
    }
  }
  // cleanup doctrine: the drop AND the scan-result artifact do not outlive the control.
  try { await taskAgent(agentId, 'cmd /c del /f /q "' + eicarPath + '" "' + scanResultPath + '" 2>nul & echo CLEANED'); } catch { /* cleanup is best-effort; the artifacts are inert text */ }

  const reasons = [];
  if (benign.verdict === 'unknown') reasons.push('benign control unreadable (snapshot failed closed) — the channel or the sensor did not answer');
  else if (benign.verdict === 'unmonitored') reasons.push('real-time protection is OFF during the benign control — the sensor is not watching');
  else if (benign.verdict !== 'clean') reasons.push(`benign control classified '${benign.verdict}' (expected 'clean') — the baseline flags harmless activity; grading against it would be noise`);
  if (onDemandConviction !== true) reasons.push(scan.note); // the primary control's failure/absence, cause named — never 'clean'
  if (onAccessWrite === 'silent') reasons.push('on-access write leg exercised and read SILENT: the byte-exact EICAR write landed and persisted with zero new 1116/1117 — evidence of the offline cloud-conviction gap (measured 2026-08-24), NOT a clean bill. ' + ONACCESS_NOT_GRADED_PHRASE);
  else if (onAccessWrite === 'unproven-offline') reasons.push('on-access write leg not proven offline (' + (dropLanded ? "write-leg verdict '" + eicar.verdict + "'" + (eicar.note ? ': ' + eicar.note : '') : 'the drop carrier failed — the leg never ran') + '). ' + ONACCESS_NOT_GRADED_PHRASE);

  const benignClean = benign.verdict === 'clean';
  const onDemandTrusted = benignClean && onDemandConviction === true;
  const onAccessTrusted = benignClean && onAccessWrite === 'convicted';
  const calibrated = onDemandTrusted; // 'calibrated' covers ONLY the on-demand lane in this mode
  const calibratedOnAccessWrite = onAccessTrusted; // stays FALSE unless the write leg convicted
  return {
    calibrated,
    calibratedOnAccessWrite,
    baselineTrusted: { onDemand: onDemandTrusted, onAccessWrite: onAccessTrusted }, // split per channel — never a bare bool
    channels: { onDemandConviction, onAccessWrite },
    benign: { verdict: benign.verdict, newDetections: benign.newDetections, newActions: benign.newActions },
    eicar: { verdict: eicar.verdict, newDetections: eicar.newDetections, newActions: eicar.newActions, ...(eicar.note ? { note: eicar.note } : {}) },
    scan: { conviction: onDemandConviction, ...scan },
    reasons,
    offline: true,
    rationale: OFFLINE_RATIONALE,
    ...(calibratedOnAccessWrite ? {} : { gradingLabel: ONACCESS_NOT_GRADED_PHRASE }), // every grade gated on this result carries the label
    note: (calibrated
      ? 'offline-calibrated — the on-demand lane proved conviction from local signatures; this calibration covers the ON-DEMAND grading lane only'
      : CALIBRATION_FAILED_PHRASE + ' — ' + reasons.join(' | '))
      + ' — ' + OFFLINE_RATIONALE
      + (calibratedOnAccessWrite ? '' : ' — ' + ONACCESS_NOT_GRADED_PHRASE),
    at: new Date().toISOString(),
  };
}

// The gate itself: stamp a verdict with the calibration state. A failed (or
// absent-failed) calibration NEVER changes the measured verdict — 'detected'
// stays 'detected' — but it is stamped baselineTrusted:false with the gate
// phrase prepended, so no consumer can mistake a soft-baseline reading for a
// trustworthy grade. rawVerdict is preserved only when absent (never clobbers
// honestVerdict's own trail). An OFFLINE calibration (offline:true) splits the
// stamp per channel — baselineTrusted:{onDemand,onAccessWrite} — and grades whose
// on-access lane did not convict carry ONACCESS_NOT_GRADED_PHRASE, never a bare pass.
export function calibrationGate(v, calibration) {
  if (!v || typeof v !== 'object' || !calibration || typeof calibration !== 'object') return v;
  // OFFLINE CALIBRATION (2026-08-25, the sealed-net finding): channels NEVER merge.
  // The measured verdict is always kept honestly; what changes is the stamp — trust
  // splits per channel, and a grade whose on-access lane did not convict carries
  // ONACCESS_NOT_GRADED_PHRASE (every evasion grade in this mode, by contract).
  if (calibration.offline === true) {
    const bt = calibration.baselineTrusted && typeof calibration.baselineTrusted === 'object'
      ? calibration.baselineTrusted
      : { onDemand: calibration.calibrated === true, onAccessWrite: calibration.calibratedOnAccessWrite === true };
    const onDemand = bt.onDemand === true;
    const onAccessWrite = bt.onAccessWrite === true;
    const stamped = { ...v, offline: true, rationale: OFFLINE_RATIONALE, baselineTrusted: { onDemand, onAccessWrite } };
    if (!onDemand) {
      return {
        ...stamped,
        calibratedOnAccessWrite: false,
        gradingLabel: ONACCESS_NOT_GRADED_PHRASE,
        calibrationReasons: Array.isArray(calibration.reasons) ? calibration.reasons : [],
        note: CALIBRATION_FAILED_PHRASE + ' — the offline control failed: even the on-demand lane did not prove conviction from local signatures, so NO grading lane is calibrated on this baseline. Measured verdict kept honestly: ' + String(v.note || ''),
      };
    }
    if (!onAccessWrite) {
      return {
        ...stamped,
        calibratedOnAccessWrite: false,
        gradingLabel: ONACCESS_NOT_GRADED_PHRASE,
        note: ONACCESS_NOT_GRADED_PHRASE + ' — this grade covers the on-demand/local-signature lane ONLY (' + OFFLINE_RATIONALE + '). Measured verdict kept honestly: ' + String(v.note || ''),
      };
    }
    return { ...stamped, calibratedOnAccessWrite: true };
  }
  const trusted = calibration.calibrated === true;
  if (trusted) return { ...v, baselineTrusted: true };
  return {
    ...v,
    baselineTrusted: false,
    calibrationReasons: Array.isArray(calibration.reasons) ? calibration.reasons : [],
    note: CALIBRATION_FAILED_PHRASE + ' — the Defender baseline on this host failed its EICAR control, so this verdict is a measurement against an UNTRUSTWORTHY sensor (harden it first: tools/rangehard.mjs). Measured verdict kept honestly: ' + String(v.note || ''),
  };
}
