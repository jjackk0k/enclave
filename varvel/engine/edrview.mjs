// VARVEL — edrview: the EDR SELF-VIEW oracle tier (PURE classifier).
//
// Why it exists: detoracle answers "did Defender DETECT it?" (threat list,
// 1116/1117). One layer down sits the question a nation-grade platform must
// also answer honestly: "what did the defender's TELEMETRY RECORD about us?" —
// detections aside, did the operational logs capture the process we spawned,
// the network connection we made, the logon our SMB/WMI touch caused? This
// engine is that answer: raw event-log exports + the action's markers in,
// a structured verdict out. The I/O shell (range query over the governed
// channel) is tools/edrview.mjs.
//
// Sources classified (read where present, ABSENT said plainly where not):
//   Microsoft-Windows-Windows Defender/Operational — detections (1116),
//     actions taken (1117), behavior detections (1115), RTP/config changes
//     (5001/5007) that OUR activity may have caused.
//   Microsoft-Windows-Sysmon/Operational — process-create (1), network-connect
//     (3), image-load (7), file-create (11), DNS query (22) — IF Sysmon is
//     installed; when it isn't, that is 'telemetry-absent', said as such.
//   Security — logon (4624), failed logon (4625), explicit credentials (4648),
//     share access (5140/5145): the footprint of our SMB/WMI touches.
//
// CORRELATION IS BY TIME-WINDOW + MARKERS, NOT GUESSWORK: an event counts only
// when (a) its timestamp falls inside the action's window AND (b) its rendered
// text contains at least one of the action's markers (case-insensitive). An
// event that matches no marker is telemetry, but not OURS — never cited.
//
// THE HONESTY CONTRACT (non-negotiable, same doctrine as detoracle):
//   'recorded'            — telemetry captured us; the event IDs/logs are cited.
//   'clean-in-telemetry'  — phrased EXACTLY as "no record found in <logs> ..."
//                           — absence of telemetry is NEVER 'undetected' and
//                           never a claim of undetectability.
//   'telemetry-absent'    — a sensor could not be read (Sysmon not installed,
//                           log unavailable); the verdict says WHAT could not
//                           be checked. Never masquerades as clean.
//
// Pure functions, fully unit-tested. Fail-closed: malformed events are skipped,
// never thrown on; unparseable timestamps cannot satisfy the window.

export const LOGS = {
  defender: 'Microsoft-Windows-Windows Defender/Operational',
  sysmon: 'Microsoft-Windows-Sysmon/Operational',
  security: 'Security',
};

// Signal vocabulary per log: event id -> what it means to a defender.
export const SIGNALS = {
  [LOGS.defender]: {
    1115: 'behavior-detection', 1116: 'detection', 1117: 'action-taken',
    5001: 'real-time-protection-disabled', 5007: 'configuration-change',
    5000: 'real-time-protection-enabled', 5010: 'scanning-disabled',
  },
  [LOGS.sysmon]: {
    1: 'process-create', 2: 'file-create-time', 3: 'network-connect', 5: 'process-terminated',
    7: 'image-load', 8: 'create-remote-thread', 10: 'process-access',
    11: 'file-create', 12: 'registry-create-delete', 13: 'registry-value-set',
    22: 'dns-query', 23: 'file-delete', 26: 'file-delete-detected',
  },
  [LOGS.security]: {
    4624: 'logon', 4625: 'logon-failure', 4648: 'explicit-credentials',
    4672: 'special-privileges-assigned', 4688: 'process-creation',
    5140: 'network-share-access', 5145: 'network-share-object-access',
    // THE AD TIER'S VOCABULARY (the governed roast/lateral/cred rungs): Kerberos
    // ticket traffic on the DC (4768 TGT, 4769 service-ticket — the kerberoast
    // signature, 4770 renew, 4771 pre-auth-failed), NTLM credential validation
    // (4776 — the lateral logon's local half), and the object-access trail an
    // LSASS touch leaves where SACLs are set (4656/4658/4663).
    4768: 'kerberos-tgt-requested', 4769: 'kerberos-service-ticket-requested',
    4770: 'kerberos-service-ticket-renewed', 4771: 'kerberos-preauth-failed',
    4776: 'credential-validation',
    4656: 'handle-requested', 4658: 'handle-closed', 4663: 'object-access',
  },
};

// Normalize one exported event. Accepts the shapes Get-WinEvent | ConvertTo-Json
// produces (Id/EventId, TimeCreated as ISO/'o' string or PS5.1 \/Date(ms)\/,
// Message) plus a minimal {log,id,time,message}. Returns null on garbage —
// fail-closed, one bad event never poisons the batch.
export function normalizeEvent(raw, fallbackLog) {
  if (!raw || typeof raw !== 'object') return null;
  const id = Number(raw.Id ?? raw.id ?? raw.EventId);
  if (!Number.isFinite(id)) return null;
  const log = String(raw.LogName ?? raw.log ?? raw.ContainerLog ?? fallbackLog ?? '');
  if (!log) return null;
  let t = raw.Time ?? raw.time ?? raw.TimeCreated;
  if (typeof t === 'string') {
    const dm = /^\/Date\((-?\d+)\)\/$/.exec(t.trim()); // PS 5.1 ConvertTo-Json shape
    if (dm) t = Number(dm[1]);
  }
  const ms = typeof t === 'number' ? t : Date.parse(String(t ?? ''));
  if (!Number.isFinite(ms)) return null; // no timestamp -> cannot satisfy a window
  return { log, id, time: new Date(ms).toISOString(), ms, message: String(raw.Message ?? raw.message ?? '') };
}

// Which markers appear in an event's rendered text (case-insensitive). Pure.
export function matchMarkers(event, markers) {
  if (!event || !Array.isArray(markers) || !markers.length) return [];
  const hay = (event.message + ' ' + event.log + ' ' + event.id).toLowerCase();
  return markers.map((m) => String(m)).filter((m) => m.length && hay.includes(m.toLowerCase()));
}

// THE VERDICT. Inputs:
//   events         — normalized event objects (normalizeEvent output)
//   logsRead       — logs that answered the query (array of log names)
//   logsUnavailable— logs that could not be read, with reasons: [{log, reason}]
//   window         — { start: ISO, end: ISO } the action's bracket (both required)
//   markers        — the action's markers (paths, process names, IPs, strings)
// Fail-closed: no usable window or no markers -> 'telemetry-absent' saying why
// (correlation without a window or markers WOULD be guesswork — refused).
export function classifyTelemetry({ events = [], logsRead = [], logsUnavailable = [], window: win, markers = [] } = {}) {
  const start = win && Date.parse(String(win.start || ''));
  const end = win && Date.parse(String(win.end || ''));
  const logsChecked = logsRead.map(String);
  const unavailable = logsUnavailable.map((l) => (typeof l === 'string' ? { log: l, reason: 'unavailable' } : l)).filter((l) => l && l.log);
  const unavNote = unavailable.length ? ` ${unavailable.map((l) => `'${l.log}' could not be read (${l.reason})`).join('; ')}.` : '';

  if (!Number.isFinite(start) || !Number.isFinite(end) || start > end) {
    return { verdict: 'telemetry-absent', matches: [], checked: logsChecked, unavailable, note: `telemetry-absent — no usable time window was supplied; correlation without a window would be guesswork, refused.${unavNote}`.trim() };
  }
  if (!Array.isArray(markers) || !markers.filter((m) => String(m).length).length) {
    return { verdict: 'telemetry-absent', matches: [], checked: logsChecked, unavailable, note: `telemetry-absent — no action markers were supplied; correlation without markers would be guesswork, refused.${unavNote}`.trim() };
  }

  const matches = [];
  for (const ev of events) {
    if (!ev || typeof ev !== 'object') continue;
    if (!(ev.ms >= start && ev.ms <= end)) continue; // outside the action's window — not ours
    const hit = matchMarkers(ev, markers);
    if (!hit.length) continue; // telemetry, but not ours — never cited
    const signal = (SIGNALS[ev.log] || {})[ev.id] || null;
    matches.push({ log: ev.log, id: ev.id, time: ev.time, signal, markers: hit });
  }

  if (matches.length) {
    const cited = [...new Set(matches.map((m) => `${shortLog(m.log)} event ${m.id}${m.signal ? ` (${m.signal})` : ''}`))];
    return {
      verdict: 'recorded', matches, checked: logsChecked, unavailable,
      note: `recorded — defender telemetry captured ${matches.length} event(s) matching this action's markers inside the window: ${cited.join(', ')}.${unavNote}`.trim(),
    };
  }
  if (logsChecked.length) {
    return {
      verdict: 'clean-in-telemetry', matches: [], checked: logsChecked, unavailable,
      note: `clean-in-telemetry — no record found in ${logsChecked.map((l) => `'${l}'`).join(', ')} between ${new Date(start).toISOString()} and ${new Date(end).toISOString()} matching this action's markers. Absence of telemetry is NOT undetectability: sensors not read, not installed, or outside this window may still have seen it.${unavNote}`.trim(),
    };
  }
  return {
    verdict: 'telemetry-absent', matches: [], checked: [], unavailable,
    note: `telemetry-absent — no queried log could be read, so NO telemetry verdict is possible (this is not a clean reading).${unavNote}`.trim(),
  };
}

const shortLog = (log) => (log === LOGS.defender ? 'Defender/Operational' : log === LOGS.sysmon ? 'Sysmon/Operational' : log);
