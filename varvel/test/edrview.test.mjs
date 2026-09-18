// edrview.test.mjs — hermetic: event normalization (Get-WinEvent JSON shapes incl.
// the PS5.1 \/Date\/ quirk), marker matching, the verdict classifier over fixture
// event-log exports (recorded / clean-in-telemetry / telemetry-absent phrasing
// contracts pinned EXACTLY), wire parse, and the assess flow over a scripted
// taskAgent. The LAST test is the GUARDED LIVE leg (house pattern): set
// VARVEL_LIVE_RANGE=1 and VARVEL_RANGE_AGENT=<agentId> for a read-only telemetry
// collect against the live range; default skip.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { LOGS, SIGNALS, normalizeEvent, matchMarkers, classifyTelemetry } from '../engine/edrview.mjs';
import { buildEventQueryCommand, parseEventExport, assessEdrView } from '../tools/edrview.mjs';

// ── fixtures ────────────────────────────────────────────────────────────────
const T0 = '2026-08-18T10:00:00.000Z';
const WIN = { start: '2026-08-18T10:00:00.000Z', end: '2026-08-18T10:05:00.000Z' };
const MARKERS = ['agentbox', '192.168.50.130'];

// The Defender/Operational 1116 detection our staged file caused.
const DEF_1116 = { Id: 1116, Time: '2026-08-18T10:01:12.0000000Z', Message: 'Microsoft Defender Antivirus has detected malware or other potentially unwanted software.\n Path: C:\\Windows\\System32\\agentbox\\staged.exe' };
// A Sysmon process-create naming our sandbox.
const SYS_1 = { Id: 1, Time: '2026-08-18T10:01:30.0000000Z', Message: 'Process Create:\nImage: C:\\Windows\\System32\\agentbox\\varvel-agent.exe\nCommandLine: varvel-agent.exe -Url http://192.168.50.130:8971' };
// A Security logon from our SMB touch (no marker -> telemetry, but not OURS).
const SEC_4624_FOREIGN = { Id: 4624, Time: '2026-08-18T10:02:00.0000000Z', Message: 'An account was successfully logged on. Account Name: TARGET$' };
// A Sysmon network-connect OUTSIDE the window.
const SYS_3_EARLY = { Id: 3, Time: '2026-08-18T09:00:00.0000000Z', Message: 'Network connection detected: DestinationIp: 192.168.50.130' };

const exportText = (defEvents, sysLine, secEvents) => [
  'EDRVIEW|' + LOGS.defender + '|' + JSON.stringify(defEvents),
  sysLine,
  'EDRVIEW|' + LOGS.security + '|' + JSON.stringify(secEvents),
].join('\n');

test('normalizeEvent: the Get-WinEvent JSON shapes parse; garbage fails closed', () => {
  const a = normalizeEvent(DEF_1116, LOGS.defender);
  assert.equal(a.id, 1116);
  assert.equal(a.log, LOGS.defender);
  assert.equal(a.time, '2026-08-18T10:01:12.000Z');
  // PS 5.1 ConvertTo-Json DateTime quirk
  const b = normalizeEvent({ Id: 4624, TimeCreated: '/Date(1755691200000)/', Message: 'x' }, LOGS.security);
  assert.equal(b.ms, 1755691200000);
  // TimeCreated as ISO also accepted
  assert.equal(normalizeEvent({ EventId: 1, TimeCreated: T0, Message: '' }, LOGS.sysmon).id, 1);
  assert.equal(normalizeEvent({ Message: 'no id' }, LOGS.sysmon), null);
  assert.equal(normalizeEvent({ Id: 1, Time: 'not-a-time' }, LOGS.sysmon), null); // no timestamp -> cannot window
  assert.equal(normalizeEvent(null), null);
  assert.equal(normalizeEvent('junk'), null);
});

test('matchMarkers: case-insensitive over the rendered text; empty markers match nothing', () => {
  const ev = normalizeEvent(SYS_1, LOGS.sysmon);
  assert.deepEqual(matchMarkers(ev, MARKERS), ['agentbox', '192.168.50.130']);
  assert.deepEqual(matchMarkers(ev, ['AGENTBOX']), ['AGENTBOX']);
  assert.deepEqual(matchMarkers(ev, ['not-present']), []);
  assert.deepEqual(matchMarkers(ev, []), []);
});

test('classifyTelemetry: recorded — event IDs and signals are cited', () => {
  const events = [DEF_1116, SYS_1, SEC_4624_FOREIGN].map((e, i) => normalizeEvent(e, [LOGS.defender, LOGS.sysmon, LOGS.security][i]));
  const v = classifyTelemetry({ events, logsRead: [LOGS.defender, LOGS.sysmon, LOGS.security], logsUnavailable: [], window: WIN, markers: MARKERS });
  assert.equal(v.verdict, 'recorded');
  assert.equal(v.matches.length, 2); // the foreign 4624 matches no marker — never cited
  assert.match(v.note, /Defender\/Operational event 1116 \(detection\)/);
  assert.match(v.note, /Sysmon\/Operational event 1 \(process-create\)/);
  assert.equal(v.matches[0].markers.includes('agentbox'), true);
});

test('classifyTelemetry: window discipline — outside the bracket is not ours', () => {
  const events = [normalizeEvent(SYS_3_EARLY, LOGS.sysmon)];
  const v = classifyTelemetry({ events, logsRead: [LOGS.sysmon], logsUnavailable: [], window: WIN, markers: MARKERS });
  assert.equal(v.verdict, 'clean-in-telemetry');
  assert.equal(v.matches.length, 0);
});

test('classifyTelemetry: clean-in-telemetry phrasing contract — never "undetected"', () => {
  const v = classifyTelemetry({ events: [], logsRead: [LOGS.defender, LOGS.security], logsUnavailable: [], window: WIN, markers: MARKERS });
  assert.equal(v.verdict, 'clean-in-telemetry');
  assert.match(v.note, /no record found in/);
  assert.match(v.note, new RegExp(LOGS.defender.replace(/[/]/g, '\\/')));
  assert.match(v.note, /NOT undetectability/);
  assert.doesNotMatch(v.note, /undetected/);
});

test('classifyTelemetry: telemetry-absent says WHAT could not be checked and why', () => {
  const v = classifyTelemetry({
    events: [], logsRead: [],
    logsUnavailable: [{ log: LOGS.sysmon, reason: 'The specified channel could not be found' }, { log: LOGS.defender, reason: 'The specified channel could not be found' }, { log: LOGS.security, reason: 'access denied' }],
    window: WIN, markers: MARKERS,
  });
  assert.equal(v.verdict, 'telemetry-absent');
  assert.match(v.note, /Sysmon\/Operational/);
  assert.match(v.note, /could not be read/);
  assert.match(v.note, /not a clean reading/);
  // partial absence: readable logs carry the verdict, the absent one is still named
  const partial = classifyTelemetry({ events: [], logsRead: [LOGS.defender], logsUnavailable: [{ log: LOGS.sysmon, reason: 'channel not found' }], window: WIN, markers: MARKERS });
  assert.equal(partial.verdict, 'clean-in-telemetry');
  assert.match(partial.note, /Sysmon\/Operational.*could not be read/s);
});

test('classifyTelemetry: no window or no markers is refused as guesswork', () => {
  const noWin = classifyTelemetry({ events: [], logsRead: [LOGS.defender], logsUnavailable: [], markers: MARKERS });
  assert.equal(noWin.verdict, 'telemetry-absent');
  assert.match(noWin.note, /time window/);
  const noMarkers = classifyTelemetry({ events: [], logsRead: [LOGS.defender], logsUnavailable: [], window: WIN, markers: [] });
  assert.equal(noMarkers.verdict, 'telemetry-absent');
  assert.match(noMarkers.note, /markers/);
});

test('SIGNALS vocabulary covers the contract classes', () => {
  assert.equal(SIGNALS[LOGS.defender][1116], 'detection');
  assert.equal(SIGNALS[LOGS.defender][1117], 'action-taken');
  assert.equal(SIGNALS[LOGS.sysmon][1], 'process-create');
  assert.equal(SIGNALS[LOGS.sysmon][3], 'network-connect');
  assert.equal(SIGNALS[LOGS.sysmon][7], 'image-load');
  assert.equal(SIGNALS[LOGS.security][4624], 'logon');
  assert.equal(SIGNALS[LOGS.security][5140], 'network-share-access');
});

test('buildEventQueryCommand: all three logs, read-only Get-WinEvent, ISO window', () => {
  const c = buildEventQueryCommand({ sinceISO: T0 });
  for (const log of Object.values(LOGS)) assert.ok(c.includes(log), log);
  assert.match(c, /Get-WinEvent -FilterHashtable/);
  assert.match(c, /EDRVIEW\|/);
  assert.match(c, /EDRVIEW-ABSENT\|/);
  assert.ok(!c.includes('\n'));
});

test('parseEventExport: full wire shape parses; absent log recorded with reason', () => {
  const text = exportText([DEF_1116], 'EDRVIEW-ABSENT|' + LOGS.sysmon + '|The specified channel could not be found', [SEC_4624_FOREIGN]);
  const p = parseEventExport(text);
  assert.deepEqual(p.logsRead, [LOGS.defender, LOGS.security]);
  assert.equal(p.logsUnavailable.length, 1);
  assert.equal(p.logsUnavailable[0].log, LOGS.sysmon);
  assert.match(p.logsUnavailable[0].reason, /channel could not be found/);
  assert.equal(p.events.length, 2);
  assert.equal(p.events[0].id, 1116);
  assert.equal(p.events[0].log, LOGS.defender);
});

test('parseEventExport: garbage fails closed — every queried log honestly unreadable', () => {
  const p = parseEventExport('total noise\nEDRVIEW|broken|{not json');
  assert.equal(p.events.length, 0);
  assert.equal(p.logsUnavailable.length, 3); // all three logs accounted for
});

test('assessEdrView: probe → collect → recorded, over a scripted channel', async () => {
  const calls = [];
  const taskAgent = async (_a, _k, cmd) => {
    calls.push(cmd);
    if (cmd === 'run-the-probe') return 'probe-output';
    return exportText([DEF_1116], 'EDRVIEW-ABSENT|' + LOGS.sysmon + '|channel not found', []);
  };
  const v = await assessEdrView({ taskAgent, agentId: 'range-1', command: 'run-the-probe', markers: MARKERS, since: WIN.start, settleMs: 5 });
  assert.equal(v.verdict, 'recorded');
  assert.equal(v.matches.length, 1);
  assert.equal(v.matches[0].signal, 'detection');
  assert.equal(calls[0], 'run-the-probe'); // probe rides BEFORE the collect
  assert.equal(v.unavailable[0].log, LOGS.sysmon);
  assert.equal(v.probe.command, 'run-the-probe');
});

test('assessEdrView: unreachable range is telemetry-absent, never a clean reading', async () => {
  const v = await assessEdrView({ taskAgent: async () => null, agentId: 'gone', command: 'x', markers: MARKERS, since: WIN.start, settleMs: 5 });
  assert.equal(v.verdict, 'telemetry-absent');
  assert.match(v.note, /did not answer/);
  const v2 = await assessEdrView({ taskAgent: async () => null, agentId: 'gone', markers: MARKERS, since: WIN.start });
  assert.equal(v2.verdict, 'telemetry-absent');
});

test('assessEdrView: collect-only mode + marker-free refusal are honest', async () => {
  const taskAgent = async () => exportText([], 'EDRVIEW-ABSENT|' + LOGS.sysmon + '|channel not found', []);
  const clean = await assessEdrView({ taskAgent, agentId: 'x', markers: MARKERS, since: WIN.start });
  assert.equal(clean.verdict, 'clean-in-telemetry');
  assert.match(clean.note, /no record found in/);
  const refused = await assessEdrView({ taskAgent, agentId: 'x', markers: [], since: WIN.start });
  assert.equal(refused.verdict, 'telemetry-absent');
  assert.match(refused.note, /markers/);
});

// ---------------- GUARDED LIVE: read-only telemetry collect on the real range ----------------
const LIVE = process.env.VARVEL_LIVE_RANGE === '1' && !!process.env.VARVEL_RANGE_AGENT;

test('LIVE (guarded): edrview collects the real range telemetry (read-only)', async (t) => {
  if (!LIVE) return t.skip('guarded live test — set VARVEL_LIVE_RANGE=1 and VARVEL_RANGE_AGENT=<agentId> to run (read-only collect)');
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
  const v = await assessEdrView({ taskAgent, agentId, markers: ['agentbox', 'varvel'], settleMs: 5 });
  assert.ok(['recorded', 'clean-in-telemetry', 'telemetry-absent'].includes(v.verdict));
  assert.equal(typeof v.note, 'string');
  if (v.verdict === 'clean-in-telemetry') assert.match(v.note, /no record found in/);
});
