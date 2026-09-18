// VARVEL — edrview: the EDR SELF-VIEW oracle tier (the I/O shell).
//
//   (optional probe)  →  settle  →  collect the DEFENDER-VISIBLE record  →  classify
//
// After a probe/action on the range, this reads what the defender's telemetry
// RECORDED about it: Windows Defender/Operational (detections, behavior blocks,
// config changes), Sysmon/Operational IF installed (process-create,
// network-connect, image-load, file-create matching our markers), and the
// Security log's logon/share events our SMB/WMI touches cause. All of it rides
// the EXISTING governed channel (kind 'shell', Get-WinEvent only — read-only
// telemetry queries, zero new guest code, zero new admin paths).
//
// The verdict contract lives in engine/edrview.mjs (pure): 'recorded' (event
// IDs cited), 'clean-in-telemetry' ("no record found in X logs" — NEVER
// 'undetected'), 'telemetry-absent' (says WHAT could not be checked).
// Correlation is time-window + markers, not guesswork; a query without both
// is refused by the classifier.
//
// taskAgent(agentId, kind, data) -> result string | null — injectable (the
// detoracle pattern): the CLI wires it to the live channel API (full-body
// results path — event JSON never fits the 120-char ledger preview), tests
// wire a script.

import { LOGS, normalizeEvent, classifyTelemetry } from '../engine/edrview.mjs';

export { LOGS, normalizeEvent, classifyTelemetry };

// Events at most this far back are collected when no explicit window is given.
export const DEFAULT_LOOKBACK_MS = 10 * 60 * 1000;
const MAX_EVENTS_PER_LOG = 150;

// One PS query per log, emitting either (pipe-delimited — log names contain spaces):
//   EDRVIEW|<logName>|<json-array-of-{Id,Time,Message}>   (log read OK)
//   EDRVIEW-ABSENT|<logName>|<reason>                     (log missing/unreadable)
// Time is emitted as round-trip ISO ('o') so PS5.1's \/Date(...)\/ JSON quirk
// never reaches the parser. Messages are truncated to 800 chars — markers
// (paths/process names/IPs) live in the leading properties; the cap keeps the
// payload inside the channel's result ceiling. A log that READS CLEAN (zero
// matching events — Get-WinEvent THROWS "No events were found" on an empty
// result, which is NOT an absence) still emits EDRVIEW|<log>|[] — an empty
// array is a readable log, and the classifier must see it as such.
export function buildEventQueryCommand({ sinceISO } = {}) {
  const since = sinceISO || new Date(Date.now() - DEFAULT_LOOKBACK_MS).toISOString();
  const perLog = (log) =>
    `$l='${log}'; try { $null=Get-WinEvent -ListLog $l -ErrorAction Stop; `
    + `$st=[DateTimeOffset]::Parse('${since}').LocalDateTime; `
    + `try { `
    + `$e=Get-WinEvent -FilterHashtable @{LogName=$l; StartTime=$st} -MaxEvents ${MAX_EVENTS_PER_LOG} -ErrorAction Stop | `
    + `Select-Object Id, @{n='Time';e={$_.TimeCreated.ToUniversalTime().ToString('o')}}, @{n='Message';e={ if ($_.Message.Length -gt 800) { $_.Message.Substring(0,800) } else { $_.Message } }}; `
    + `Write-Output ('EDRVIEW|' + $l + '|' + (ConvertTo-Json -InputObject @($e) -Compress -Depth 4)) `
    + `} catch { if ($_.Exception.Message -match 'No events were found') { Write-Output ('EDRVIEW|' + $l + '|[]') } else { Write-Output ('EDRVIEW-ABSENT|' + $l + '|' + ($_.Exception.Message -replace '[\\r\\n]+',' ')) } } `
    + `} catch { Write-Output ('EDRVIEW-ABSENT|' + $l + '|' + ($_.Exception.Message -replace '[\\r\\n]+',' ')) }`;
  return 'powershell -NoProfile -Command "'
    + [LOGS.defender, LOGS.sysmon, LOGS.security].map(perLog).join('; ')
    + '"';
}

// Parse one query result into { events, logsRead, logsUnavailable }.
// Fail-closed: unparseable lines and bad JSON are skipped, never thrown on;
// a result with NO markers at all reports every log unreadable honestly.
export function parseEventExport(text) {
  const events = [], logsRead = [], logsUnavailable = [];
  const seen = new Set();
  for (const line of String(text || '').split(/\r?\n/)) {
    let m = /^EDRVIEW-ABSENT\|([^|]+)\|?(.*)$/s.exec(line);
    if (m) {
      seen.add(m[1].trim());
      logsUnavailable.push({ log: m[1].trim(), reason: (m[2] || 'unavailable').trim().slice(0, 160) || 'unavailable' });
      continue;
    }
    m = /^EDRVIEW\|([^|]+)\|(\[.*\])\s*$/s.exec(line);
    if (!m) continue;
    seen.add(m[1].trim());
    logsRead.push(m[1].trim());
    let arr;
    try { arr = JSON.parse(m[2]); } catch { continue; }
    for (const raw of Array.isArray(arr) ? arr : [arr]) {
      const ev = normalizeEvent(raw, m[1].trim());
      if (ev) events.push(ev);
    }
  }
  // Any queried log that produced NO marker at all is honestly 'unreadable',
  // not silently dropped from the checked list.
  for (const log of [LOGS.defender, LOGS.sysmon, LOGS.security]) {
    if (!seen.has(log)) logsUnavailable.push({ log, reason: 'no result line (truncation or host noise)' });
  }
  return { events, logsRead, logsUnavailable };
}

// Orchestrate one self-view read over the governed channel.
//   command — optional probe/action to run first (the thing being measured);
//             when omitted this is a collect-only read of the window.
//   markers — the action's markers (paths, process names, IPs). REQUIRED for a
//             real verdict; without them the classifier refuses (guesswork).
//   since / window — the correlation bracket; window defaults to
//             [since, collection time] so a probe run here is always inside it.
export async function assessEdrView({ taskAgent, agentId, command = null, markers = [], since = null, settleMs = 4000 }) {
  if (typeof taskAgent !== 'function') throw new TypeError('edrview.assessEdrView needs a taskAgent(agentId, kind, data)');
  if (!agentId) throw new TypeError('edrview.assessEdrView needs agentId');
  const start = since || new Date(Date.now() - DEFAULT_LOOKBACK_MS).toISOString();

  let probeResult = null;
  if (command) {
    probeResult = await taskAgent(agentId, 'shell', String(command));
    if (probeResult == null) {
      return { verdict: 'telemetry-absent', matches: [], checked: [], unavailable: [], note: 'telemetry-absent — the range did not answer the probe task (unreachable or tasking refused); nothing was collected, no verdict possible', evidence: null, at: new Date().toISOString() };
    }
    await new Promise((r) => setTimeout(r, settleMs));
  }

  const queryRaw = await taskAgent(agentId, 'shell', buildEventQueryCommand({ sinceISO: start }));
  if (queryRaw == null) {
    return { verdict: 'telemetry-absent', matches: [], checked: [], unavailable: [], note: 'telemetry-absent — the range did not answer the telemetry query (unreachable or tasking refused); no verdict possible', evidence: null, at: new Date().toISOString() };
  }
  const end = new Date().toISOString();
  const parsed = parseEventExport(queryRaw);
  const v = classifyTelemetry({
    events: parsed.events, logsRead: parsed.logsRead, logsUnavailable: parsed.logsUnavailable,
    window: { start, end }, markers,
  });
  return {
    ...v,
    window: { start, end },
    markers: markers.map(String),
    probe: command ? { command: String(command).slice(0, 300), result: String(probeResult || '').slice(0, 300) } : null,
    evidence: String(queryRaw).slice(0, 600),
    at: new Date().toISOString(),
  };
}
