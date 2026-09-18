// VARVEL tracetap tests — the fine-tune trace harvester (tools/tracetap.mjs). Hermetic:
// fixture records in tmp dirs only, zero network. The doctrines under test: real record
// shapes in -> fine-tune JSONL out (conversations stay conversations, everything else is
// an honest 'event' record — never dropped, never dressed up), the redaction receipt is
// counted (never the values), --validated-only keeps only gate-passing chains, and the
// summary's gaps[] names every expected store that is missing or unparseable.
//   node --test test/tracetap.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, copyFileSync, mkdtempSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { harvest } from '../tools/tracetap.mjs';

const __dir = dirname(fileURLToPath(import.meta.url));
const TRACETAP = join(__dir, '..', 'tools', 'tracetap.mjs');
const NOW = Date.parse('2026-08-24T00:00:00.000Z');

// A complete little harvest world: one conversation checkpoint (+ one broken one), one
// statestore, one campaign surface, one failure ledger, one hash-chained audit ledger,
// one tool audit log.
function makeWorld() {
  const data = mkdtempSync(join(tmpdir(), 'varvel-tracetap-data-'));
  const tools = mkdtempSync(join(tmpdir(), 'varvel-tracetap-tools-'));
  copyFileSync(join(__dir, 'fixtures', 'tracetap-mission.json'), join(data, 'mission_demo-aaa111.mission.json'));
  writeFileSync(join(data, 'mission_broken-bbb222.mission.json'), JSON.stringify({
    missionId: 'msn-trace-broken', engagement: 'trace-eng', status: 'running',
    created: '2026-08-20T11:00:00.000Z', updated: '2026-08-20T11:30:00.000Z',
    msgs: 'garbage — the conversation did not survive',
  }));
  writeFileSync(join(data, 'trace-eng-ccc333.state.json'), JSON.stringify({
    hosts: [], creds: [], sessions: [], notes: [],
    findings: [
      { key: 'https://www.example.com/login', title: 'SQL injection in /login', sev: 'crit', ref: 'https://www.example.com/login', validation: 'validated', secret: 'statestore-secret-value', firstSeen: '2026-08-20T10:00:00.000Z', lastSeen: '2026-08-20T10:00:00.000Z', provenance: { engagement: 'trace-eng', sourceTool: 'vulncheck', ts: '2026-08-20T10:00:00.000Z', actor: 'tool' } },
      { key: '/search', title: 'Reflected XSS', sev: 'med', ref: '/search', validation: 'claimed', firstSeen: '2026-08-20T10:00:00.000Z', lastSeen: '2026-08-20T10:00:00.000Z', provenance: { engagement: 'trace-eng', sourceTool: 'crawl', ts: '2026-08-20T10:00:00.000Z', actor: 'ai' } },
    ],
  }));
  writeFileSync(join(data, 'trace-eng-ddd444.surface.json'), JSON.stringify({
    scope: { engagement: 'trace-eng', signedBy: 'marcus', cidrs: ['203.0.113.0/24'] },
    nodes: [
      { id: 'f1', type: 'finding', label: 'SQLi fresh', sev: 'crit', ref: '/login', evidence: 'HTTP/1.1 200 OK\nCookie: session=4f8a2c-surface-cookie', validation: { state: 'validated', oracle: 'marker present', validatedAt: '2026-08-20T10:00:00.000Z' } },
      { id: 'f2', type: 'finding', label: 'SQLi stale', sev: 'high', ref: '/login2', validation: { state: 'validated', oracle: 'marker present', validatedAt: '2026-06-01T10:00:00.000Z' } },
      { id: 'f3', type: 'finding', label: 'RCE refuted', sev: 'high', ref: '/render', validation: { state: 'refuted', oracle: 'control matched', at: '2026-08-21T09:00:00.000Z' } },
      { id: 'h1', type: 'host', label: 'www.example.com', ip: '203.0.113.10' },
    ],
    edges: [], holds: [], counts: {},
  }));
  writeFileSync(join(data, 'trace-eng-eee555.failures.json'), JSON.stringify([
    { phase: 'exploit', kind: 'failure', approach: 'error-based SQLi — WAF 403', at: '2026-08-20T09:59:00.000Z' },
  ]));
  const seam = join(mkdtempSync(join(tmpdir(), 'varvel-tracetap-seam-')), 'audit-ledger.jsonl');
  copyFileSync(join(__dir, 'fixtures', 'tracetap-audit.jsonl'), seam);
  writeFileSync(join(tools, 'wafbypass-audit.jsonl'), '{"ts":"2026-08-20T10:03:00.000Z","tool":"wafbypass","url":"http://203.0.113.10/","ok":true,"passing":3}\n');
  // The oracle verdict stores (engine/oraclelog.mjs — persisted since 2026-08-25): one
  // calibration verdict (channels inside), one assessment verdict, one shapegrade score.
  mkdirSync(join(tools, 'oracle'), { recursive: true });
  writeFileSync(join(tools, 'oracle', 'detoracle-verdicts.jsonl'), [
    JSON.stringify({ ts: '2026-08-20T10:04:00.000Z', tool: 'detoracle', op: 'calibrate', agentId: 'agent-72', engagement: 'trace-eng', program: null, verdict: { calibrated: true, baselineTrusted: true, benign: { verdict: 'clean' }, eicar: { verdict: 'detected', newDetections: 1 }, reasons: [], at: '2026-08-20T10:04:00.000Z' } }),
    JSON.stringify({ ts: '2026-08-20T10:05:00.000Z', tool: 'detoracle', op: 'assess', agentId: 'agent-72', engagement: 'trace-eng', program: null, verdict: { verdict: 'blocked', newDetections: 1, newActions: 1, evidence: { probeResult: 'ok', token: 'oracle-token-value' } } }),
  ].join('\n') + '\n');
  writeFileSync(join(tools, 'oracle', 'shapegrade-scores.jsonl'), [
    JSON.stringify({ ts: '2026-08-20T10:06:00.000Z', tool: 'shapegrade', op: 'gradeLive', agentId: 'agent-72', engagement: 'trace-eng', program: null, grade: { ok: true, profile: 'cdn-asset', verdict: 'divergent', divergent: ['JA4H DIVERGENCE: claimed ge11nn12enus_x measured po11nn14enus_y'], preFlight: { band: 'cdn-assets', score: 92 }, flow: { band: 'web-browse', score: 78 } } }),
  ].join('\n') + '\n');
  return { data, tools, seam };
}

test('harvest: every store becomes units — conversations stay conversations, the rest are honest event records', () => {
  const w = makeWorld();
  const { units, summary } = harvest({ dataDir: w.data, seamLedger: w.seam, toolDataDir: w.tools, now: NOW, staleDays: 30 });
  assert.equal(summary.ok, true);

  const mission = units.find((u) => u.kind === 'mission');
  assert.ok(mission, 'the checkpointed conversation is a mission unit');
  assert.equal(mission.meta.missionId, 'msn-trace-demo');
  assert.equal(mission.meta.campaignId, 'trace-eng');
  assert.equal(mission.labels.validated, true, 'the engagement has a gate-passing finding');
  const blocks = mission.messages.flatMap((m) => (Array.isArray(m.content) ? m.content : []));
  assert.ok(blocks.some((b) => b.type === 'tool_use'), 'tool_use blocks survive');
  assert.ok(blocks.some((b) => b.type === 'tool_result'), 'tool_result blocks survive');

  const broken = units.find((u) => u.meta && u.meta.missionId === 'msn-trace-broken');
  assert.equal(broken.kind, 'event', 'unrecoverable messages export as an event record — never silently dropped');
  assert.equal(broken.eventType, 'mission-checkpoint');

  const findings = units.filter((u) => u.eventType === 'finding');
  assert.equal(findings.length, 5, '2 statestore + 3 surface findings');
  const fresh = findings.find((u) => u.event.ref === '/login');
  assert.deepEqual([fresh.labels.validated, fresh.labels.stale, fresh.labels.severity], [true, false, 'crit']);
  const stale = findings.find((u) => u.event.ref === '/login2');
  assert.deepEqual([stale.labels.validated, stale.labels.stale], [false, true], 'stale validation is NOT gate-passing');
  const stateFinding = findings.find((u) => u.source === 'statestore-finding' && u.event.ref === 'https://www.example.com/login');
  assert.equal(stateFinding.labels.validated, true);
  assert.equal(stateFinding.labels.staleKnown, false, 'statestore records carry no validatedAt — staleness is honestly unknown');

  assert.equal(units.filter((u) => u.eventType === 'failure').length, 1);
  const audit = units.filter((u) => u.eventType === 'audit');
  assert.equal(audit.length, 4, '3 chained seam lines + 1 tool log line');
  assert.equal(audit.filter((u) => u.meta.hashChained).length, 3);
  assert.equal(summary.sources.missions, 2);

  // The oracle stores (persisted since 2026-08-25) harvest as labeled event units —
  // the flywheel's labels.oracleScores slot — and the two old always-true gaps are GONE.
  const verdicts = units.filter((u) => u.eventType === 'oracle-verdict');
  assert.equal(verdicts.length, 2, 'the calibration + the assessment verdict both harvested');
  const calUnit = verdicts.find((u) => u.labels.oracleScores.op === 'calibrate');
  assert.equal(calUnit.labels.oracleScores.verdict, null, 'calibrations carry calibrated/baselineTrusted, not a probe verdict');
  assert.equal(calUnit.labels.oracleScores.calibrated, true);
  assert.equal(calUnit.meta.agentId, 'agent-72');
  assert.equal(calUnit.meta.campaignId, 'trace-eng');
  const assessUnit = verdicts.find((u) => u.labels.oracleScores.op === 'assess');
  assert.equal(assessUnit.labels.oracleScores.verdict, 'blocked');
  const shapes = units.filter((u) => u.eventType === 'shape-grade');
  assert.equal(shapes.length, 1);
  assert.equal(shapes[0].labels.oracleScores.profile, 'cdn-asset');
  assert.equal(shapes[0].labels.oracleScores.verdict, 'divergent');
  assert.equal(shapes[0].labels.oracleScores.divergent, 1);
  assert.equal(shapes[0].labels.oracleScores.flowBand, 'web-browse');
  assert.equal(summary.sources.oracleVerdicts, 2);
  assert.equal(summary.sources.shapeScores, 1);
  assert.ok(!summary.gaps.some((g) => /detoracle|shapegrade/.test(g)), 'no detoracle/shapegrade gaps when the stores exist');
});

test('redaction: the values never reach the JSONL — the counts are the receipt', () => {
  const w = makeWorld();
  const { units, summary } = harvest({ dataDir: w.data, seamLedger: w.seam, toolDataDir: w.tools, now: NOW });
  const jsonl = units.map((u) => JSON.stringify(u)).join('\n');
  for (const secret of ['hunter2', '4f8a2c-live-cookie-value', '4f8a2c-surface-cookie', 'sess-cookie-value-must-redact', 'statestore-secret-value', 'eyJhbGciOiJIUzI1NiJ9', 'oracle-token-value']) {
    assert.ok(!jsonl.includes(secret), `secret '${secret.slice(0, 12)}…' never reaches the export`);
  }
  assert.ok(jsonl.includes('[REDACTED]'));
  assert.ok(summary.redactions.total >= 6, `counted the withholdings (got ${summary.redactions.total})`);
  const missionFile = Object.keys(summary.redactions.perFile).find((f) => f.includes('mission_demo'));
  assert.ok(summary.redactions.perFile[missionFile] >= 4, 'per-file counts: cookie header + authorization header + JWT shape + key=value + secret field');
});

test('--validated-only keeps only gate-passing chains (the gold SFT rows)', () => {
  const w = makeWorld();
  const { units, summary } = harvest({ dataDir: w.data, seamLedger: w.seam, toolDataDir: w.tools, now: NOW, staleDays: 30, validatedOnly: true });
  assert.equal(units.length, 4, 'the two mission chains (one recovered as an event record) + the fresh-validated surface finding + the validated statestore finding');
  assert.ok(units.every((u) => u.labels && u.labels.validated === true));
  assert.equal(units.filter((u) => u.kind === 'mission').length, 1, 'the chain behind a validated finding is the gold row');
  assert.ok(summary.dropped.validatedOnly > 0, 'claimed/refuted/stale findings and plain events are dropped, counted');
});

test('--since and --campaign filter, and the drops are counted', () => {
  const w = makeWorld();
  const since = harvest({ dataDir: w.data, seamLedger: w.seam, toolDataDir: w.tools, now: NOW, since: '2026-08-20T10:02:30.000Z' });
  assert.ok(since.units.every((u) => Date.parse(u.ts) >= Date.parse('2026-08-20T10:02:30.000Z')));
  assert.ok(since.summary.dropped.since >= 3, 'older audit lines + failures + findings drop, counted');

  const byCampaign = harvest({ dataDir: w.data, seamLedger: w.seam, toolDataDir: w.tools, now: NOW, campaign: 'trace-eng' });
  assert.ok(byCampaign.units.every((u) => (u.meta && (u.meta.campaignId === 'trace-eng' || u.meta.missionId === 'trace-eng'))));
  assert.ok(byCampaign.units.some((u) => u.kind === 'mission'));
  assert.ok(byCampaign.summary.dropped.campaign >= 4, 'audit lines and the failure ledger carry no campaign — dropped, counted');
});

test('gaps[] honesty: missing and unparseable stores are named, never fabricated around', () => {
  const empty = mkdtempSync(join(tmpdir(), 'varvel-tracetap-empty-'));
  const { units, summary } = harvest({ dataDir: empty, seamLedger: join(empty, 'no-seam.jsonl'), toolDataDir: join(empty, 'no-tools'), oracleDir: join(empty, 'no-oracle'), now: NOW });
  assert.equal(units.length, 0);
  assert.ok(summary.gaps.some((g) => /no hash-chained audit ledger/.test(g)));
  assert.ok(summary.gaps.some((g) => /no tool data dir/.test(g)));
  assert.ok(summary.gaps.some((g) => /no oracle verdict store/.test(g)), 'the absent oracle store is a named gap, not a fabricated row');

  // Store dir present but one store file missing: the MISSING file is the named gap.
  const partial = mkdtempSync(join(tmpdir(), 'varvel-tracetap-partial-'));
  mkdirSync(join(partial, 'oracle'), { recursive: true });
  writeFileSync(join(partial, 'oracle', 'detoracle-verdicts.jsonl'), JSON.stringify({ ts: '2026-08-20T10:04:00.000Z', tool: 'detoracle', op: 'assess', agentId: 'a', engagement: null, program: null, verdict: { verdict: 'clean' } }) + '\n');
  const rp = harvest({ dataDir: empty, seamLedger: join(empty, 'no-seam.jsonl'), toolDataDir: join(empty, 'no-tools'), oracleDir: join(partial, 'oracle'), now: NOW });
  assert.ok(rp.summary.gaps.some((g) => /no shapegrade-scores\.jsonl/.test(g)), 'the missing shapegrade store is named');
  assert.ok(!rp.summary.gaps.some((g) => /no detoracle-verdicts\.jsonl/.test(g)), 'the present detoracle store is NOT gapped');
  assert.equal(rp.summary.sources.oracleVerdicts, 1);

  const w = makeWorld();
  writeFileSync(join(w.data, 'mission_corrupt-zzz999.mission.json'), '{ not json');
  const r2 = harvest({ dataDir: w.data, seamLedger: w.seam, toolDataDir: w.tools, now: NOW });
  assert.ok(r2.summary.gaps.some((g) => /mission_corrupt-zzz999\.mission\.json is unparseable/.test(g)), 'a corrupt checkpoint is a named gap, not a silent skip');
});

test('direct-run: --out writes valid JSONL and prints the summary; without --out stdout stays JSONL', () => {
  const w = makeWorld();
  const out = join(w.tools, 'traces.jsonl');
  // --seam-ledger/--tools point the harvest at the world (the direct run must never
  // couple to REAL store sizes — real growth past the spawn buffer broke this test
  // environmentally on 2026-08-26, not on a code change).
  const env = { ...process.env, VARVEL_DATA_DIR: w.data };
  const r = spawnSync(process.execPath, [TRACETAP, '--out', out, '--validated-only', '--seam-ledger', w.seam, '--tools', w.tools], { encoding: 'utf8', timeout: 30000, env });
  assert.equal(r.status, 0, r.stderr.slice(0, 300));
  const summary = JSON.parse(r.stdout);
  assert.equal(summary.ok, true);
  assert.equal(summary.units, 4);
  const lines = readFileSync(out, 'utf8').trim().split('\n');
  assert.equal(lines.length, 4);
  for (const l of lines) assert.ok(JSON.parse(l).kind, 'every line parses as a unit');

  const r2 = spawnSync(process.execPath, [TRACETAP, '--seam-ledger', w.seam, '--tools', w.tools], { encoding: 'utf8', timeout: 30000, env });
  assert.equal(r2.status, 0);
  const lines2 = r2.stdout.trim().split('\n');
  assert.ok(lines2.length >= 10, 'the full world exports to stdout as JSONL');
  for (const l of lines2) JSON.parse(l);
  const errSummary = JSON.parse(r2.stderr);
  assert.equal(errSummary.ok, true, 'the summary rides stderr so stdout stays valid JSONL');
});
