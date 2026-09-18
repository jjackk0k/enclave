// VARVEL — rangehard: RANGE BASELINE HARDENING (audit + journaled restore).
//
// Why it exists (field finding 2026-08): the Enclave range's Defender was found
// CUSTOMIZED SOFT — a byte-perfect EICAR file did not fire, the image's posture
// differed from a default-hard baseline at build time, and lifetime detections
// read zero. Evasion measured against a neutered baseline proves NOTHING. This
// tool makes the baseline itself a governed, measurable object:
//
//   audit : read-only posture query (Get-MpPreference + Get-MpComputerStatus +
//           ASR rule states) over the EXISTING governed channel (kind 'shell' —
//           no new guest code, no new admin path), classified against a
//           DEFAULT-HARD baseline model into a gap report.
//   apply : operator-invoked ONLY (never automatic, never from a campaign):
//           re-enables what the baseline expects and removes exclusions — every
//           single change journaled with before/after values + a ready revert
//           command, per the platform's cleanup doctrine. The journal IS the
//           reversibility contract: `revert` replays it backwards and re-audits.
//   revert: replay a journal backwards (restore the recorded before-values).
//
// THE HONESTY CONTRACT (same doctrine as detoracle):
//   - apply REFUSES when the range isn't reachable or the posture can't be
//     parsed — a posture we cannot read is reported as unreadable, never
//     assumed hard and never silently "fixed".
//   - Tamper Protection cannot be restored over this channel on an unmanaged
//     client (it is portal/Intune-guarded BY DESIGN — Set-MpPreference has no
//     switch for it). It is audited and, when off, reported as a MANUAL gap —
//     flagged for the operator, never silently skipped, never faked.
//   - Signature updates on an internet-isolated range may fail; the journal
//     records what actually happened (verified true/false), not what was hoped.
//   - Every change rides the governed channel, so the channel's own ledger is
//     the audit-of-record; the journal file is the reversibility trail.
//
// taskAgent(agentId, kind, data) -> result-preview/full-body string — injectable
// (the detoracle/evasion pattern): the CLI wires it to the live channel API,
// tests wire a script.

// Signatures older than this are stale for a grading baseline.
export const SIGNATURE_STALE_DAYS = 7;

// The recommended ASR baseline set (well-known Microsoft GUIDs). The baseline
// contract is "block, or at least audit" — audit() accepts either; apply() sets
// the recorded `baseline` action (block) and journals it.
export const ASR_BASELINE = [
  { id: '56a863a9-875e-4185-98a7-b882c64b5ce5', name: 'block-abuse-of-exploited-vulnerable-signed-drivers' },
  { id: '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c', name: 'block-adobe-reader-child-process' },
  { id: 'd4f940ab-401b-4efc-aadc-ad5f3c50688a', name: 'block-office-child-process' },
  { id: '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2', name: 'block-credential-theft-from-lsass' },
  { id: 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550', name: 'block-executable-content-from-email-and-webmail' },
  { id: '01443614-cd74-433a-b99e-2ecdc07bfc25', name: 'block-exe-unless-prevalent-age-or-trusted-list' },
  { id: '5beb7efe-fd9a-4556-801d-275e5ffc04cc', name: 'block-script-obfuscation' },
  { id: 'd3e037e1-3eb8-44c8-a917-57927947596d', name: 'block-js-vbs-from-launching-downloaded-content' },
  { id: '3b576869-a4ec-4529-8536-b80a7769e899', name: 'block-office-executable-content-creation' },
  { id: '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84', name: 'block-office-injection-into-other-processes' },
  { id: '26190899-1602-49e8-8b27-eb1d0a1ce869', name: 'block-office-communication-child-process' },
  { id: 'e6db77e5-3df2-4cf1-b95a-636979351e5b', name: 'block-persistence-through-wmi-event-subscription' },
  { id: 'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4', name: 'block-untrusted-unsigned-processes-from-usb' },
  { id: '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b', name: 'block-win32-api-calls-from-office-macros' },
  { id: 'c1db55ab-c21a-4637-bb3f-a12568109d35', name: 'use-advanced-ransomware-protection' },
  { id: 'a8f5898e-1dc8-49a9-9878-85004b8a61e6', name: 'block-webshell-creation-for-servers' },
];

// ASR action vocabulary (Get/Set-MpPreference AttackSurfaceReductionRules_Actions).
export const ASR_ACTION = { off: 0, block: 1, audit: 2, warn: 6 };

// ── the range query ─────────────────────────────────────────────────────────
// One compact posture snapshot as a single marker-prefixed JSON line. PS 5.1
// ConvertTo-Json quirks (single-element arrays unrolling to scalars) are
// absorbed parser-side by asArray() — the wire shape is never trusted.
export function buildAuditCommand() {
  return 'powershell -NoProfile -Command "'
    + "$p=Get-MpPreference; $cs=Get-MpComputerStatus; $o=@{"
    + 'rtp=(-not $p.DisableRealtimeMonitoring);'
    + 'rtpStatus=($cs.RealTimeProtectionEnabled -eq $true);'
    + 'maps=([int]$p.MAPSReporting);'
    + 'pua=([int]$p.PUAProtection);'
    + 'behavior=(-not $p.DisableBehaviorMonitoring);'
    + 'ioav=(-not $p.DisableIOAVProtection);'
    + 'scriptScan=(-not $p.DisableScriptScanning);'
    + 'tamper=$cs.IsTamperProtected;'
    + 'exclPaths=@($p.ExclusionPath);'
    + 'exclExts=@($p.ExclusionExtension);'
    + 'exclProcs=@($p.ExclusionProcess);'
    + 'asrIds=@($p.AttackSurfaceReductionRules_Ids);'
    + 'asrActions=@($p.AttackSurfaceReductionRules_Actions);'
    + 'sigVersion=$cs.AntivirusSignatureVersion;'
    + 'sigAgeDays=([int]$cs.AntivirusSignatureAge)'
    + '}; Write-Output (\'RANGEHARD \' + ($o | ConvertTo-Json -Compress))'
    + '"';
}

const asArray = (v) => (v == null ? [] : Array.isArray(v) ? v : [v]);

// UNELEVATED Get-MpPreference quirk (measured on the wire): exclusion/ASR list
// properties come back as the STRING 'N/A: Must be an administrator to view ...'
// (or null) instead of a list. That is an UNREADABLE axis, never an exclusion
// entry — treating the sentinel as data would fabricate gaps. The range agent
// runs as SYSTEM so lists read real there; the guard keeps unelevated reads honest.
const NA_RE = /^N\/A:/i;
const isSentinel = (x) => x == null || NA_RE.test(String(x));

// Parse the RANGEHARD line. Fail-closed: no marker / bad JSON -> null (never
// guess posture). Array-or-scalar ambiguity normalized here, once.
export function parsePosture(text) {
  const m = /RANGEHARD (\{.*\})/s.exec(String(text || ''));
  if (!m) return null;
  let o;
  try { o = JSON.parse(m[1]); } catch { return null; }
  if (!o || typeof o !== 'object') return null;
  const rawIds = asArray(o.asrIds);
  const asrReadable = !rawIds.some(isSentinel);
  const ids = rawIds.filter((x) => !isSentinel(x) && String(x) !== '').map((s) => String(s).toLowerCase());
  const acts = asArray(o.asrActions).map((n) => Number(n));
  const asr = ids.map((id, i) => ({ id, action: Number.isFinite(acts[i]) ? acts[i] : 0 }));
  const rawExcl = { paths: asArray(o.exclPaths), extensions: asArray(o.exclExts), processes: asArray(o.exclProcs) };
  const exclusionsReadable = !Object.values(rawExcl).some((l) => l.some(isSentinel));
  return {
    rtp: o.rtp === true, rtpStatus: o.rtpStatus === true,
    maps: Number(o.maps) || 0,
    pua: Number(o.pua) || 0,
    behavior: o.behavior === true, ioav: o.ioav === true, scriptScan: o.scriptScan === true,
    tamper: o.tamper === true ? true : o.tamper === false ? false : null, // null = unreadable
    exclusionsReadable,
    exclusions: {
      paths: rawExcl.paths.filter((x) => !isSentinel(x)).map(String),
      extensions: rawExcl.extensions.filter((x) => !isSentinel(x)).map(String),
      processes: rawExcl.processes.filter((x) => !isSentinel(x)).map(String),
    },
    asrReadable,
    asr,
    signature: { version: o.sigVersion == null ? null : String(o.sigVersion), ageDays: Number.isFinite(Number(o.sigAgeDays)) ? Number(o.sigAgeDays) : null },
  };
}

// ── the DEFAULT-HARD baseline model + gap classifier ────────────────────────
// A gap: { id, severity, current, expected, fixable, note, fixCommand? }.
// fixable:false means NO command exists (tamper protection — by design) and the
// operator must act by hand; it still appears in the report, loudly.
const PSQ = (s) => String(s).replace(/'/g, "''");
const ps = (body) => 'powershell -NoProfile -Command "' + body + '"';

export function auditBaseline(posture) {
  if (!posture || typeof posture !== 'object') {
    return { grade: 'unreadable', gaps: [], note: 'posture unreadable — no baseline verdict possible (fail-closed; this is NOT default-hard)' };
  }
  const gaps = [];
  const gap = (id, severity, current, expected, note, fixCommand) =>
    gaps.push({ id, severity, current, expected, fixable: !!fixCommand, note, ...(fixCommand ? { fixCommand } : {}) });

  if (!(posture.rtp && posture.rtpStatus)) {
    gap('rtp-off', 'crit', `DisableRealtimeMonitoring=${!posture.rtp} / status=${posture.rtpStatus}`, 'real-time protection ON',
      'real-time protection is OFF — the sensor cannot see anything at rest or in motion; every detoracle verdict on this host is void until fixed',
      ps('Set-MpPreference -DisableRealtimeMonitoring $false; Write-Output \'FIXED rtp-off\''));
  }
  if (posture.maps < 1) {
    gap('cloud-off', 'high', `MAPSReporting=${posture.maps}`, 'MAPSReporting >= 1 (cloud-delivered protection ON)',
      'cloud protection (MAPS) is OFF — no cloud lookup/Block-at-First-Sight; the local signature set alone is the whole sensor',
      ps('Set-MpPreference -MAPSReporting 2 -SubmitSamplesConsent 1; Write-Output \'FIXED cloud-off\''));
  }
  if (posture.pua !== 1) {
    gap('pua-off', 'med', `PUAProtection=${posture.pua}`, 'PUAProtection = 1 (block)',
      'PUA protection is not blocking — hacktool/greyware class payloads install silently',
      ps('Set-MpPreference -PUAProtection 1; Write-Output \'FIXED pua-off\''));
  }
  if (!posture.behavior) {
    gap('behavior-off', 'crit', 'DisableBehaviorMonitoring=True', 'behavior monitoring ON',
      'behavior monitoring is OFF — the post-execution detection layer is blind (only static signatures remain)',
      ps('Set-MpPreference -DisableBehaviorMonitoring $false; Write-Output \'FIXED behavior-off\''));
  }
  if (!posture.ioav) {
    gap('ioav-off', 'high', 'DisableIOAVProtection=True', 'on-access scanning ON',
      'on-access (IOAV) protection is OFF — files are not scanned as they arrive',
      ps('Set-MpPreference -DisableIOAVProtection $false; Write-Output \'FIXED ioav-off\''));
  }
  if (!posture.scriptScan) {
    gap('scriptscan-off', 'med', 'DisableScriptScanning=True', 'script scanning ON',
      'script scanning is OFF — .ps1/.vbs/.js content is not signature-scanned at rest',
      ps('Set-MpPreference -DisableScriptScanning $false; Write-Output \'FIXED scriptscan-off\''));
  }
  if (posture.tamper !== true) {
    gap('tamper-off', 'med', posture.tamper === null ? 'unreadable' : 'IsTamperProtected=False', 'tamper protection ON (where possible)',
      'tamper protection is OFF and CANNOT be restored over this channel: on an unmanaged client it is portal/Intune-guarded by design (Set-MpPreference has no switch). MANUAL action: enable it in Windows Security on the range console. Reported, never silently skipped.');
  }
  const unaudited = [];
  if (posture.exclusionsReadable === false) {
    unaudited.push('exclusions (elevation required — the lists read as N/A sentinels, NOT audited as empty)');
  } else {
    for (const [kind, list, idPrefix, removeCmd] of [
      ['path', posture.exclusions.paths, 'exclusion-path:', 'Remove-MpPreference -ExclusionPath'],
      ['extension', posture.exclusions.extensions, 'exclusion-ext:', 'Remove-MpPreference -ExclusionExtension'],
      ['process', posture.exclusions.processes, 'exclusion-proc:', 'Remove-MpPreference -ExclusionProcess'],
    ]) {
      for (const entry of list) {
        gap(idPrefix + entry, 'high', `exclusion ${kind} '${entry}'`, 'no exclusions on a grading baseline',
          'an exclusion blinds the sensor to everything under it — on a baseline used to GRADE evasion, ANY exclusion is a gap (the field-finding agentbox exclusion is exactly this shape)',
          ps(`${removeCmd} '${PSQ(entry)}'; Write-Output 'FIXED ${idPrefix}${PSQ(entry)}'`));
      }
    }
  }
  if (posture.asrReadable === false) {
    unaudited.push('ASR rule states (elevation required — read as N/A sentinels, NOT audited as absent)');
  } else {
    for (const rule of ASR_BASELINE) {
      const cur = posture.asr.find((a) => a.id === rule.id);
      const action = cur ? cur.action : 0;
      if (action !== ASR_ACTION.block && action !== ASR_ACTION.audit) {
        gap('asr-' + rule.name, 'med', cur ? `action=${action}` : 'not-configured', 'block (or at least audit)',
          `ASR rule '${rule.name}' is ${cur ? 'off' : 'absent'} — the baseline wants block or at least audit so the telemetry story exists`,
          ps(`Set-MpPreference -AttackSurfaceReductionRules_Ids ${rule.id} -AttackSurfaceReductionRules_Actions ${ASR_ACTION.block}; Write-Output 'FIXED asr-${rule.name}'`));
      }
    }
  }
  if (posture.signature.ageDays == null || posture.signature.ageDays > SIGNATURE_STALE_DAYS) {
    gap('signature-stale', 'high', posture.signature.ageDays == null ? 'age unreadable' : `age ${posture.signature.ageDays}d (v${posture.signature.version || '?'})`, `signatures <= ${SIGNATURE_STALE_DAYS}d old`,
      'signatures are stale — a grading baseline must be current; on an internet-isolated range this may need an offline definition drop (the update attempt is journaled and verified honestly)',
      ps('Update-MpSignature; Write-Output \'FIXED signature-stale\''));
  }
  return {
    grade: gaps.length ? 'weakened' : 'default-hard',
    gaps,
    unaudited,
    note: (gaps.length
      ? `${gaps.length} gap(s) vs the default-hard baseline — evasion graded against THIS posture proves nothing until hardened (see the field finding)`
      : 'posture matches the default-hard baseline — this sensor is fit to grade against')
      + (unaudited.length ? `; UNAUDITED AXES: ${unaudited.join('; ')}` : ''),
  };
}

// ── the journal (reversibility contract) ────────────────────────────────────
// One entry per change: what, before, after, the exact forward command, the
// exact revert command, and whether the post-apply re-audit proved it took.
// buildRevertPlan(journal) replays entries BACKWARDS (reverse order — last
// change out first) into the exact restore commands.
export function journalEntry({ gapId, before, after, command, revertCommand, verified, evidence }) {
  return {
    gapId: String(gapId),
    before, after,
    command: String(command || ''),
    revertCommand: String(revertCommand || ''),
    verified: verified === true,
    evidence: String(evidence || '').slice(0, 200),
    at: new Date().toISOString(),
  };
}

// Derive the revert command for a fix, given the gap id and the before-value
// recorded in the posture at apply time. Pure — never throws.
export function buildRevertCommand(gapId, posture) {
  const id = String(gapId || '');
  const simple = {
    'rtp-off': 'Set-MpPreference -DisableRealtimeMonitoring $true',
    'cloud-off': `Set-MpPreference -MAPSReporting ${posture ? Number(posture.maps) || 0 : 0} -SubmitSamplesConsent 2`,
    'pua-off': `Set-MpPreference -PUAProtection ${posture ? Number(posture.pua) || 0 : 0}`,
    'behavior-off': 'Set-MpPreference -DisableBehaviorMonitoring $true',
    'ioav-off': 'Set-MpPreference -DisableIOAVProtection $true',
    'scriptscan-off': 'Set-MpPreference -DisableScriptScanning $true',
    'signature-stale': null, // nothing to revert — an update is not undoable; journaled as such
  };
  if (id in simple) {
    const body = simple[id];
    return body ? ps(`${body}; Write-Output 'REVERTED ${id}'`) : null;
  }
  let m;
  if ((m = /^exclusion-path:(.*)$/s.exec(id))) return ps(`Add-MpPreference -ExclusionPath '${PSQ(m[1])}'; Write-Output 'REVERTED ${id}'`);
  if ((m = /^exclusion-ext:(.*)$/s.exec(id))) return ps(`Add-MpPreference -ExclusionExtension '${PSQ(m[1])}'; Write-Output 'REVERTED ${id}'`);
  if ((m = /^exclusion-proc:(.*)$/s.exec(id))) return ps(`Add-MpPreference -ExclusionProcess '${PSQ(m[1])}'; Write-Output 'REVERTED ${id}'`);
  if ((m = /^asr-(.*)$/.exec(id))) {
    const rule = ASR_BASELINE.find((r) => r.name === m[1]);
    if (!rule) return null;
    const before = posture ? (posture.asr.find((a) => a.id === rule.id) || {}).action : undefined;
    // Rule was absent before -> remove it entirely; otherwise restore the recorded action.
    const body = before == null
      ? `Remove-MpPreference -AttackSurfaceReductionRules_Ids ${rule.id}`
      : `Set-MpPreference -AttackSurfaceReductionRules_Ids ${rule.id} -AttackSurfaceReductionRules_Actions ${Number(before) || 0}`;
    return ps(`${body}; Write-Output 'REVERTED ${id}'`);
  }
  return null;
}

// The exact restore plan for a journal, newest change first.
export function buildRevertPlan(journal) {
  const entries = journal && Array.isArray(journal.entries) ? journal.entries : [];
  return entries
    .slice()
    .reverse()
    .filter((e) => e.revertCommand)
    .map((e) => ({ gapId: e.gapId, revertCommand: e.revertCommand }));
}

// ── orchestration over the governed channel ─────────────────────────────────
// taskAgent(agentId, kind, data) -> string | null (null = unreachable/refused).
export async function auditRange({ taskAgent, agentId }) {
  if (typeof taskAgent !== 'function') throw new TypeError('rangehard.auditRange needs a taskAgent(agentId, kind, data)');
  if (!agentId) throw new TypeError('rangehard.auditRange needs agentId');
  const raw = await taskAgent(agentId, 'shell', buildAuditCommand());
  if (raw == null) {
    return { reachable: false, posture: null, report: null, note: 'range unreachable — no posture read, nothing classified (fail-closed)', evidence: null, at: new Date().toISOString() };
  }
  const posture = parsePosture(raw);
  if (!posture) {
    return { reachable: true, posture: null, report: null, note: 'posture unreadable (no parseable RANGEHARD line) — fail-closed, NOT assumed hard', evidence: String(raw).slice(0, 400), at: new Date().toISOString() };
  }
  return { reachable: true, posture, report: auditBaseline(posture), note: auditBaseline(posture).note, evidence: String(raw).slice(0, 400), at: new Date().toISOString() };
}

// Operator-invoked hardening. REFUSES (loudly, with zero changes) when the
// range isn't reachable or the posture can't be parsed. Every change is
// journaled BEFORE the next one is attempted, then a post-apply re-audit
// verifies each gap closed — the journal records what was PROVEN, not hoped.
export async function applyHardening({ taskAgent, agentId }) {
  if (typeof taskAgent !== 'function') throw new TypeError('rangehard.applyHardening needs a taskAgent(agentId, kind, data)');
  if (!agentId) throw new TypeError('rangehard.applyHardening needs agentId');

  const first = await auditRange({ taskAgent, agentId });
  if (!first.reachable || !first.posture) {
    return {
      applied: 0, refused: true, journal: null, revertPlan: [], verification: null,
      note: 'REFUSED: ' + first.note + ' — apply is operator-invoked and never touches a range it cannot read',
      at: new Date().toISOString(),
    };
  }
  const fixable = first.report.gaps.filter((g) => g.fixable);
  const manual = first.report.gaps.filter((g) => !g.fixable);
  if (!fixable.length) {
    return {
      applied: 0, refused: false,
      journal: { op: 'rangehard-apply', agentId, at: new Date().toISOString(), entries: [], manualGaps: manual.map((g) => g.id) },
      revertPlan: [], verification: { gradeAfter: first.report.grade, remainingGaps: manual.map((g) => g.id) },
      note: first.report.grade === 'default-hard'
        ? 'already default-hard — nothing to apply'
        : `no automatically-fixable gaps; ${manual.length} gap(s) need MANUAL action (${manual.map((g) => g.id).join(', ')})`,
      at: new Date().toISOString(),
    };
  }

  const entries = [];
  for (const g of fixable) {
    const evidence = await taskAgent(agentId, 'shell', g.fixCommand);
    entries.push(journalEntry({
      gapId: g.id,
      before: g.current, after: g.expected,
      command: g.fixCommand,
      revertCommand: buildRevertCommand(g.id, first.posture),
      verified: /FIXED /.test(String(evidence || '')),
      evidence,
    }));
  }

  // Post-apply re-audit: verification is a fresh read, never the fix's echo.
  const second = await auditRange({ taskAgent, agentId });
  const remaining = second.report ? second.report.gaps.map((g) => g.id) : ['(re-audit unreadable)'];
  for (const e of entries) {
    // verified = fix echoed AND the gap no longer appears in the re-audit.
    e.verified = e.verified && !!second.report && !second.report.gaps.some((g) => g.id === e.gapId);
  }
  const journal = {
    op: 'rangehard-apply', agentId, at: new Date().toISOString(),
    entries, manualGaps: manual.map((g) => g.id),
    verification: {
      gradeBefore: first.report.grade, gradeAfter: second.report ? second.report.grade : 'unreadable',
      remainingGaps: remaining,
    },
  };
  const unproven = entries.filter((e) => !e.verified);
  return {
    applied: entries.length, refused: false, journal, revertPlan: buildRevertPlan(journal),
    verification: journal.verification,
    note: `${entries.length} change(s) applied and journaled; grade ${journal.verification.gradeBefore} -> ${journal.verification.gradeAfter}`
      + (remaining.length ? `; remaining gap(s): ${remaining.join(', ')}` : '; no remaining gaps')
      + (unproven.length ? `; LOUD: ${unproven.length} change(s) did NOT verify on re-audit (${unproven.map((e) => e.gapId).join(', ')}) — treat them as not-taken and investigate` : '; every change verified on re-audit')
      + (manual.length ? `; MANUAL: ${manual.map((g) => g.id).join(', ')}` : ''),
    at: new Date().toISOString(),
  };
}

// Replay a journal backwards (operator-invoked): restore every recorded
// before-value, then re-audit and report what the posture looks like now.
export async function revertHardening({ taskAgent, agentId, journal }) {
  if (typeof taskAgent !== 'function') throw new TypeError('rangehard.revertHardening needs a taskAgent(agentId, kind, data)');
  if (!agentId || !journal || !Array.isArray(journal.entries)) throw new TypeError('rangehard.revertHardening needs agentId and a journal {entries[]}');
  const plan = buildRevertPlan(journal);
  const skipped = journal.entries.filter((e) => !e.revertCommand).map((e) => e.gapId);
  const done = [];
  for (const step of plan) {
    const evidence = await taskAgent(agentId, 'shell', step.revertCommand);
    done.push({ gapId: step.gapId, confirmed: /REVERTED /.test(String(evidence || '')), evidence: String(evidence || '').slice(0, 200) });
  }
  const after = await auditRange({ taskAgent, agentId });
  return {
    reverted: done.filter((d) => d.confirmed).length,
    failed: done.filter((d) => !d.confirmed),
    skipped, // entries with no revert path (e.g. signature-stale) — said, not hidden
    postureAfter: after.posture, reportAfter: after.report,
    note: `${done.filter((d) => d.confirmed).length}/${plan.length} revert(s) confirmed` + (skipped.length ? `; ${skipped.length} entrie(s) have no revert path and were skipped (${skipped.join(', ')})` : ''),
    at: new Date().toISOString(),
  };
}
