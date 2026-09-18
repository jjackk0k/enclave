// rangehard.test.mjs — hermetic: posture parse (incl. PS5.1 array quirks), the
// baseline-gap classifier over fixture Get-MpPreference/Get-MpComputerStatus JSON
// (weak vs hard), apply/refuse flow over a scripted taskAgent, and the
// journal/reversibility contract. The LAST test is the GUARDED LIVE leg (house
// pattern): set VARVEL_LIVE_RANGE=1 and VARVEL_RANGE_AGENT=<agentId> to run a
// READ-ONLY audit against the live range; default skip. Everything written lives
// under repo-local .tmp — never os.tmpdir() (house rule).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildAuditCommand, parsePosture, auditBaseline, buildRevertCommand, buildRevertPlan,
  auditRange, applyHardening, revertHardening, ASR_BASELINE, SIGNATURE_STALE_DAYS,
} from '../tools/rangehard.mjs';

// ── fixtures ────────────────────────────────────────────────────────────────
// A DEFAULT-HARD range: every feature on, no exclusions, ASR in block, fresh sigs.
const HARD = {
  rtp: true, rtpStatus: true, maps: 2, pua: 1, behavior: true, ioav: true, scriptScan: true,
  tamper: true, exclPaths: [], exclExts: [], exclProcs: [],
  asrIds: ASR_BASELINE.map((r) => r.id), asrActions: ASR_BASELINE.map(() => 1),
  sigVersion: '1.417.0.0', sigAgeDays: 1,
};
// The field-finding shape: customized-soft — cloud off, PUA off, the agentbox
// exclusion, no ASR, stale signatures, tamper off. RTP itself reads on (that is
// what made it treacherous: the sensor LOOKED alive).
const WEAK = {
  rtp: true, rtpStatus: true, maps: 0, pua: 0, behavior: true, ioav: true, scriptScan: true,
  tamper: false, exclPaths: ['C:\\Windows\\System32\\agentbox'], exclExts: [], exclProcs: [],
  asrIds: [], asrActions: [],
  sigVersion: '1.381.0.0', sigAgeDays: 45,
};
const wire = (o) => 'noise\nRANGEHARD ' + JSON.stringify(o) + '\ntrailing';

test('buildAuditCommand: carries the Defender cmdlets + the marker, stays one line', () => {
  const c = buildAuditCommand();
  assert.match(c, /Get-MpPreference/);
  assert.match(c, /Get-MpComputerStatus/);
  assert.match(c, /AttackSurfaceReductionRules_Ids/);
  assert.match(c, /RANGEHARD /);
  assert.ok(!c.includes('\n'));
});

test('parsePosture: good line parses; PS5.1 scalar-array quirk normalized; garbage fails closed', () => {
  const p = parsePosture(wire(HARD));
  assert.equal(p.rtp, true);
  assert.equal(p.maps, 2);
  assert.deepEqual(p.exclusions.paths, []);
  assert.equal(p.asr.length, ASR_BASELINE.length);
  assert.equal(p.asr[0].action, 1);
  assert.equal(p.signature.ageDays, 1);
  // single exclusion arrives as a SCALAR (PS5.1 ConvertTo-Json unrolls 1-element arrays)
  const w1 = parsePosture(wire({ ...WEAK, asrIds: ASR_BASELINE[0].id, asrActions: 2 }));
  assert.deepEqual(w1.exclusions.paths, ['C:\\Windows\\System32\\agentbox']);
  assert.deepEqual(w1.asr, [{ id: ASR_BASELINE[0].id, action: 2 }]);
  // tamper null (unreadable) is preserved as null, never guessed
  assert.equal(parsePosture(wire({ ...HARD, tamper: null })).tamper, null);
  assert.equal(parsePosture(''), null);
  assert.equal(parsePosture('RANGEHARD {not json'), null);
  assert.equal(parsePosture(undefined), null);
});

test('auditBaseline: hard fixture grades default-hard with zero gaps', () => {
  const r = auditBaseline(parsePosture(wire(HARD)));
  assert.equal(r.grade, 'default-hard');
  assert.equal(r.gaps.length, 0);
  assert.match(r.note, /fit to grade/);
});

test('auditBaseline: the field-finding weak fixture produces the expected gap set', () => {
  const r = auditBaseline(parsePosture(wire(WEAK)));
  assert.equal(r.grade, 'weakened');
  const ids = r.gaps.map((g) => g.id);
  assert.ok(ids.includes('cloud-off'));
  assert.ok(ids.includes('pua-off'));
  assert.ok(ids.includes('exclusion-path:C:\\Windows\\System32\\agentbox'));
  assert.ok(ids.includes('signature-stale'));
  assert.ok(ids.includes('tamper-off'));
  for (const rule of ASR_BASELINE) assert.ok(ids.includes('asr-' + rule.name), 'missing ASR gap ' + rule.name);
  // tamper protection is a MANUAL gap by design (no channel command exists)
  const tamper = r.gaps.find((g) => g.id === 'tamper-off');
  assert.equal(tamper.fixable, false);
  assert.match(tamper.note, /MANUAL/);
  // every other gap carries a fix command
  for (const g of r.gaps.filter((x) => x.id !== 'tamper-off')) {
    assert.equal(g.fixable, true, g.id + ' should be fixable');
    assert.match(g.fixCommand, /FIXED /);
  }
  // audit mode accepts block OR audit for ASR (the baseline contract)
  const auditMode = parsePosture(wire({ ...HARD, asrActions: ASR_BASELINE.map(() => 2) }));
  assert.equal(auditBaseline(auditMode).grade, 'default-hard');
  // signature boundary: exactly SIGNATURE_STALE_DAYS is current, +1 is stale
  assert.equal(auditBaseline(parsePosture(wire({ ...HARD, sigAgeDays: SIGNATURE_STALE_DAYS }))).grade, 'default-hard');
  assert.ok(auditBaseline(parsePosture(wire({ ...HARD, sigAgeDays: SIGNATURE_STALE_DAYS + 1 }))).gaps.some((g) => g.id === 'signature-stale'));
});

test('auditBaseline: unreadable posture is fail-closed, never assumed hard', () => {
  const r = auditBaseline(null);
  assert.equal(r.grade, 'unreadable');
  assert.match(r.note, /NOT default-hard/);
});

test('parsePosture: the unelevated N/A sentinel is UNREADABLE, never a fabricated gap', () => {
  // measured on the wire: unelevated Get-MpPreference returns exclusion/ASR list
  // properties as 'N/A: Must be an administrator ...' strings (or null).
  const p = parsePosture(wire({
    ...HARD,
    exclPaths: 'N/A: Must be an administrator to view exclusions', exclExts: null, exclProcs: [],
    asrIds: [null], asrActions: [],
  }));
  assert.equal(p.exclusionsReadable, false);
  assert.equal(p.asrReadable, false);
  assert.deepEqual(p.exclusions.paths, []); // the sentinel is NOT an exclusion entry
  const r = auditBaseline(p);
  assert.ok(!r.gaps.some((g) => g.id.startsWith('exclusion-')), 'no exclusion gaps from an unreadable axis');
  assert.ok(!r.gaps.some((g) => g.id.startsWith('asr-')), 'no ASR gaps from an unreadable axis');
  assert.match(r.note, /UNAUDITED AXES/);
  assert.match(r.note, /NOT audited/);
});

test('applyHardening: full scripted loop — audit, journaled fixes, verified re-audit', async () => {
  let audits = 0;
  const calls = [];
  const HARD_BUT_TAMPER = { ...HARD, tamper: false }; // apply cannot fix tamper — the manual gap must SURVIVE the re-audit
  const taskAgent = async (_a, kind, cmd) => {
    calls.push(cmd);
    if (cmd === buildAuditCommand()) { audits++; return wire(audits === 1 ? WEAK : HARD_BUT_TAMPER); }
    if (cmd.includes('FIXED ')) return cmd.match(/FIXED [^']+/)[0];
    return '';
  };
  const r = await applyHardening({ taskAgent, agentId: 'range-1' });
  assert.equal(r.refused, false);
  const fixableGaps = auditBaseline(parsePosture(wire(WEAK))).gaps.filter((g) => g.fixable).length;
  assert.equal(r.applied, fixableGaps);
  assert.equal(r.verification.gradeBefore, 'weakened');
  assert.equal(r.verification.gradeAfter, 'weakened'); // tamper-off survives: apply cannot reach default-hard while the manual gap stands
  assert.deepEqual(r.verification.remainingGaps, ['tamper-off']); // manual gap remains, loudly
  assert.match(r.note, /MANUAL: tamper-off/);
  // journal: every entry has before/after + forward and revert commands, verified
  assert.equal(r.journal.op, 'rangehard-apply');
  assert.equal(r.journal.entries.length, fixableGaps);
  for (const e of r.journal.entries) {
    assert.ok(e.command && e.revertCommand !== undefined, e.gapId);
    assert.equal(e.verified, true, e.gapId + ' should verify against the hardened re-audit');
    assert.ok(e.before && e.after);
  }
  // the exclusion fix rode the channel BEFORE the re-audit (ordering)
  const fixIdx = calls.findIndex((c) => c.includes('Remove-MpPreference'));
  assert.ok(fixIdx > 0 && calls.slice(fixIdx + 1).some((c) => c === buildAuditCommand()));
  // revert plan is newest-first over the entries that HAVE a revert path
  assert.equal(r.revertPlan.length, r.journal.entries.filter((e) => e.revertCommand).length);
  const lastRevertable = [...r.journal.entries].reverse().find((e) => e.revertCommand);
  assert.equal(r.revertPlan[0].gapId, lastRevertable.gapId);
});

test('applyHardening: refuses when the range is unreachable — zero changes, loud report', async () => {
  const r = await applyHardening({ taskAgent: async () => null, agentId: 'gone' });
  assert.equal(r.refused, true);
  assert.equal(r.applied, 0);
  assert.equal(r.journal, null);
  assert.match(r.note, /REFUSED/);
  assert.match(r.note, /unreachable/);
});

test('applyHardening: refuses when posture is unparseable (fail-closed)', async () => {
  const r = await applyHardening({ taskAgent: async () => 'garbage, no marker', agentId: 'x' });
  assert.equal(r.refused, true);
  assert.equal(r.applied, 0);
  assert.match(r.note, /unreadable/);
});

test('applyHardening: already default-hard applies nothing (no churn)', async () => {
  const r = await applyHardening({ taskAgent: async (_a, _k, cmd) => (cmd === buildAuditCommand() ? wire(HARD) : ''), agentId: 'x' });
  assert.equal(r.applied, 0);
  assert.equal(r.refused, false);
  assert.match(r.note, /already default-hard/);
});

test('revert contract: revert commands restore the recorded before-values exactly', () => {
  const weak = parsePosture(wire(WEAK));
  // exclusion: revert re-adds the exact path
  assert.match(buildRevertCommand('exclusion-path:C:\\Windows\\System32\\agentbox', weak), /Add-MpPreference -ExclusionPath 'C:\\Windows\\System32\\agentbox'/);
  // cloud: revert restores the recorded MAPSReporting=0 (not a guessed value)
  assert.match(buildRevertCommand('cloud-off', weak), /-MAPSReporting 0/);
  // ASR rule absent before -> revert removes it entirely
  assert.match(buildRevertCommand('asr-block-office-child-process', weak), /Remove-MpPreference -AttackSurfaceReductionRules_Ids d4f940ab-401b-4efc-aadc-ad5f3c50688a/);
  // ASR rule in audit before -> revert restores audit (2), not block
  const audited = parsePosture(wire({ ...HARD, asrIds: ['d4f940ab-401b-4efc-aadc-ad5f3c50688a'], asrActions: [2] }));
  assert.match(buildRevertCommand('asr-block-office-child-process', audited), /-AttackSurfaceReductionRules_Actions 2/);
  // signature update has no revert path — said, not hidden
  assert.equal(buildRevertCommand('signature-stale', weak), null);
  assert.equal(buildRevertCommand('tamper-off', weak), null);
});

test('revertHardening: replays the journal backwards and re-audits honestly', async () => {
  const weak = parsePosture(wire(WEAK));
  const gaps = auditBaseline(weak).gaps.filter((g) => g.fixable);
  const journal = {
    op: 'rangehard-apply', agentId: 'range-1', at: new Date().toISOString(),
    entries: gaps.map((g) => ({
      gapId: g.id, before: g.current, after: g.expected, command: g.fixCommand,
      revertCommand: buildRevertCommand(g.id, weak), verified: true, evidence: 'FIXED', at: new Date().toISOString(),
    })),
  };
  const revertedCmds = [];
  const taskAgent = async (_a, _k, cmd) => {
    if (cmd === buildAuditCommand()) return wire(WEAK); // back at the weak baseline
    if (cmd.includes('REVERTED ')) { revertedCmds.push(cmd); return 'REVERTED ok'; }
    return '';
  };
  const r = await revertHardening({ taskAgent, agentId: 'range-1', journal });
  const withRevert = journal.entries.filter((e) => e.revertCommand).length;
  assert.equal(r.reverted, withRevert);
  assert.equal(r.failed.length, 0);
  assert.deepEqual(r.skipped, ['signature-stale']); // no revert path — surfaced
  assert.equal(r.reportAfter.grade, 'weakened'); // the re-audit proves the restore
  // newest-first replay order: the first reverted command names the last revertable entry
  const lastRevertable = [...journal.entries].reverse().find((e) => e.revertCommand);
  assert.ok(revertedCmds[0].includes(lastRevertable.gapId));
});

test('auditRange: unreachable vs unreadable vs classified', async () => {
  const gone = await auditRange({ taskAgent: async () => null, agentId: 'x' });
  assert.equal(gone.reachable, false);
  assert.match(gone.note, /unreachable/);
  const noise = await auditRange({ taskAgent: async () => 'host noise', agentId: 'x' });
  assert.equal(noise.reachable, true);
  assert.equal(noise.posture, null);
  const good = await auditRange({ taskAgent: async () => wire(WEAK), agentId: 'x' });
  assert.equal(good.report.grade, 'weakened');
});

// ---------------- GUARDED LIVE: READ-ONLY audit against the real range ----------------
// house pattern: opt-in via env, default skip. APPLY IS NEVER TESTED LIVE HERE.
const LIVE = process.env.VARVEL_LIVE_RANGE === '1' && !!process.env.VARVEL_RANGE_AGENT;

test('LIVE (guarded): auditRange reads the real range posture (read-only)', async (t) => {
  if (!LIVE) return t.skip('guarded live test — set VARVEL_LIVE_RANGE=1 and VARVEL_RANGE_AGENT=<agentId> to run (read-only audit)');
  const api = process.env.VARVEL_API || 'http://127.0.0.1:8971';
  const agentId = process.env.VARVEL_RANGE_AGENT;
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const taskAgent = async (id, _kind, data) => {
    const r = await (await fetch(api + '/api/channel/task', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ agentId: id, kind: 'shell', data }) })).json();
    if (!r || !r.taskId) return null;
    for (let i = 0; i < 30; i++) {
      await sleep(2000);
      const full = await (await fetch(api + '/api/channel/results?agent=' + id + '&taskId=' + r.taskId)).json().catch(() => null);
      if (full && Array.isArray(full.results) && full.results.length) return String(full.results[0].data ?? '');
      const { tasks } = await (await fetch(api + '/api/channel/tasks?agent=' + id)).json();
      const x = (tasks || []).find((y) => y.taskId === r.taskId);
      if (x && x.status === 'resulted') return x.resultPreview || '';
    }
    return null;
  };
  const r = await auditRange({ taskAgent, agentId });
  if (!r.reachable) return t.skip('range agent not reachable right now — honestly skipped, not failed');
  assert.ok(r.posture, 'posture must parse off the live range');
  assert.ok(['default-hard', 'weakened'].includes(r.report.grade));
  assert.equal(typeof r.report.note, 'string');
});
