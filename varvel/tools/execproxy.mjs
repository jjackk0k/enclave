// VARVEL — execproxy: the SIGNED-PROXY EXECUTION TIER's discovery + EDR-PAIRING
// operator loop (the I/O shell over engine/execproxy.mjs).
//
// TWO legs, both riding the EXISTING governed channel (taskAgent(agentId, kind,
// data) — injectable, the detoracle/edrview pattern; the CLI wires it to the live
// channel API, tests wire a script):
//
//   1. HOST CANDIDATE DISCOVERY (RECON ONLY — never auto-plants): a read-only
//      Get-AuthenticodeSignature sweep over the registry's candidate signed hosts
//      (engine/execproxy.mjs EXECPROXY_HOST_CANDIDATES) plus the rundll32/regsvr32
//      system hosts, ranked by the PURE classifier (rankHostCandidates): present +
//      Valid signature + Microsoft signer + stage-1 hijack names. Output is a
//      RANKED CANDIDATE LIST with signature status — a hypothesis set for the
//      measured plant/run loop, never a claim of hijackability.
//
//   2. THE EDR PAIRING LOOP (the point of the platform — capability measured
//      against the hardened range baseline):
//
//        execproxy-run  →  edrview verdict (what did Defender/Sysmon record)  →
//        execproxy-remove (verified)  →  execproxy-status sweep (verify clean)
//
//      in ONE governed motion. A signed-proxy run is exactly where the range's
//      telemetry gets its best look (image loads of the DLL into rundll32.exe,
//      process-create command lines with the LOLBin shape) — so the platform
//      never runs blind, and the cleanup-proof doctrine is enforced in code:
//      cleanupVerified aggregates ONLY a removal proven by re-read; a run whose
//      removal did not verify is reported as a loud loose end (treat the host as
//      STILL PLANTED), never a quiet pass.
//
// HONESTY CONTRACT (same as edrview's): 'clean-in-telemetry' means "no record
// found in these logs, in this window, on this host" — NEVER 'undetected'. A
// REFUSED run (engagement gate off, agent flag off, bad spec) is refused:true —
// no run happened, so no detectability claim exists.

import {
  EXECPROXY_HOST_CANDIDATES, EXECPROXY_TECHNIQUES, EXECPROXY_EXPORTS,
  rankHostCandidates, parseExecProxySpec, execProxyTag,
} from '../engine/execproxy.mjs';
import { assessEdrView } from './edrview.mjs';

export { rankHostCandidates };

const SYSTEM_HOSTS = ['%SystemRoot%\\System32\\rundll32.exe', '%SystemRoot%\\System32\\regsvr32.exe'];

// ——— leg 1: discovery ———

// One PS sweep emitting, per candidate host (pipe-delimited — paths contain no pipes):
//   PROXYSIG|<expanded-path>|<present 0|1>|<sigStatus>|<signer>|<hijackNames-csv>
// Read-only: Test-Path + Get-AuthenticodeSignature only.
export function buildDiscoveryCommand(extraHosts = []) {
  const rows = [];
  for (const h of SYSTEM_HOSTS) rows.push({ host: h, names: [] });
  for (const c of EXECPROXY_HOST_CANDIDATES) rows.push({ host: c.host, names: c.names });
  for (const h of extraHosts) rows.push({ host: String(h), names: [] });
  const perRow = rows.map((r, i) => {
    const names = r.names.join(',');
    return `$p${i}=[Environment]::ExpandEnvironmentVariables('${r.host}'); `
      + `if (Test-Path -LiteralPath $p${i} -PathType Leaf) { `
      + `$s${i}=Get-AuthenticodeSignature -LiteralPath $p${i}; $sg${i}=''; if ($s${i}.SignerCertificate) { $sg${i}=$s${i}.SignerCertificate.Subject }; `
      + `Write-Output ('PROXYSIG|' + $p${i} + '|1|' + $s${i}.Status + '|' + ($sg${i} -replace '\\|',';') + '|${names}') `
      + `} else { Write-Output ('PROXYSIG|' + $p${i} + '|0|absent||${names}') }`;
  });
  return 'powershell -NoProfile -Command "' + perRow.join('; ') + '"';
}

// Parse a discovery sweep into rows for the ranker. Fail-closed: unparseable lines
// are skipped, never thrown on.
export function parseDiscoveryExport(text) {
  const rows = [];
  for (const line of String(text || '').split(/\r?\n/)) {
    const m = /^PROXYSIG\|([^|]+)\|([01])\|([^|]*)\|([^|]*)\|([^|]*)\s*$/.exec(line.trim());
    if (!m) continue;
    rows.push({
      path: m[1].trim(),
      present: m[2] === '1',
      sigStatus: m[3].trim() || null,
      signer: m[4].trim() || null,
      hijackNames: m[5] ? m[5].split(',').map((s) => s.trim()).filter(Boolean) : [],
    });
  }
  return rows;
}

// Orchestrate one discovery sweep over the governed channel. RECON ONLY — the
// result is a ranked candidate list; nothing is planted, ever.
export async function discoverHostCandidates({ taskAgent, agentId, extraHosts = [] } = {}) {
  if (typeof taskAgent !== 'function') throw new TypeError('execproxy.discoverHostCandidates needs a taskAgent(agentId, kind, data)');
  if (!agentId) throw new TypeError('execproxy.discoverHostCandidates needs agentId');
  const raw = await taskAgent(agentId, 'shell', buildDiscoveryCommand(extraHosts));
  if (raw == null) {
    return { ok: false, candidates: [], note: 'the range did not answer the discovery sweep (unreachable or tasking refused); no candidates ranked', evidence: null, at: new Date().toISOString() };
  }
  const rows = parseDiscoveryExport(raw);
  const ranked = rankHostCandidates(rows);
  return {
    ok: ranked.length > 0,
    candidates: ranked,
    note: ranked.length === 0
      ? 'no discovery rows parsed (truncation or host noise) — nothing ranked'
      : ranked.filter((c) => c.verdict === 'candidate').length + ' candidate(s) ranked of ' + ranked.length + ' host(s) swept — RECON ONLY: a candidate is a hypothesis for the measured plant/run/edrview loop, never a claim',
    evidence: String(raw).slice(0, 600),
    at: new Date().toISOString(),
  };
}

// ——— leg 2: the EDR pairing loop ———

// A refusal is loud plain text by contract (agents/execproxy.mjs, the PS agent
// cases, and the channel gate's THROWN GOVERNANCE error which the API task path surfaces).
const REFUSED_RE = /(?:^|\b)(?:TASKING REFUSED|execproxy-\w+ (?:REFUSED|REJECTED)|execproxy-\w+ refused)/i;

// Parse an agent execproxy result body. Returns the evidence object, or null when
// the body is not the evidence JSON (refusal text, truncation, foreign body).
export function parseExecProxyResult(raw) {
  try {
    const p = JSON.parse(String(raw || ''));
    if (p && typeof p === 'object' && typeof p.op === 'string' && (p.op === 'status' ? Array.isArray(p.entries) : p.names && typeof p.names === 'object')) return p;
  } catch { /* refusal text / truncated preview — carried raw in evidence */ }
  return null;
}

// The full governed motion: plant/run -> edrview verdict -> verified remove -> sweep.
//   technique — rundll32 | regsvr32 | sideload (stage 1)
//   dll       — the payload DLL path on the range host (staged beforehand; sha256 audited)
//   export/args/host/as — per-technique spec fields (see engine/execproxy.mjs)
//   name      — the plant handle (default: deterministic VARVEL-<sha8> from agentId+dll)
// Returns the assessment; never throws on a governed refusal.
export async function assessExecProxy({ taskAgent, agentId, technique, dll, export: exp, args = '', host = null, as = null, name = null, settleMs = 4000 } = {}) {
  if (typeof taskAgent !== 'function') throw new TypeError('execproxy.assessExecProxy needs a taskAgent(agentId, kind, data)');
  if (!agentId) throw new TypeError('execproxy.assessExecProxy needs agentId');
  const at = new Date().toISOString();
  // The same spec gate the channel runs — refuse a bad spec BEFORE any task rides.
  let spec;
  try {
    spec = parseExecProxySpec('execproxy-run', JSON.stringify({ technique, dll, export: exp, args, host, as, name }));
  } catch (e) {
    return { refused: true, reason: (e && e.message) || String(e), verdict: 'unknown', at, note: 'spec refused pre-flight — nothing ran, no detectability claim exists' };
  }
  const runName = spec.name || execProxyTag(agentId + '|' + spec.dll);
  const runSpec = { ...spec, name: runName };

  // 1. RUN (the plant + the signed-host execution).
  const since = new Date().toISOString();
  const runRaw = await taskAgent(agentId, 'execproxy-run', JSON.stringify(runSpec));
  if (runRaw == null || REFUSED_RE.test(String(runRaw))) {
    return { refused: true, reason: String(runRaw == null ? 'no result (channel offline or tasking refused)' : runRaw).slice(0, 300), verdict: 'unknown', at, note: 'the run was REFUSED — nothing executed, no detectability claim exists' };
  }
  const run = parseExecProxyResult(runRaw);
  const runEv = run && run.names ? run.names[runName] : null;

  // 2. EDRVIEW VERDICT: what did the range's telemetry record about it? Markers =
  //    the payload path, the plant dir, the signed host's process name.
  const markers = [String(spec.dll), 'execproxy-' + runName];
  if (spec.technique === 'rundll32') markers.push('rundll32.exe');
  if (spec.technique === 'regsvr32') markers.push('regsvr32.exe');
  if (spec.technique === 'sideload' && spec.host) markers.push(String(spec.host).split(/[\\/]/).pop());
  const edr = await assessEdrView({ taskAgent, agentId, command: null, markers, since, settleMs });

  // 3. REMOVE (mandatory, verified) — the cleanup-proof half, always attempted
  //    after a non-refused run, even when the run evidence is partial.
  const remRaw = await taskAgent(agentId, 'execproxy-remove', JSON.stringify({ name: runName }));
  const rem = parseExecProxyResult(remRaw);
  const remEv = rem && rem.names ? rem.names[runName] : null;

  // 4. THE SWEEP: status must say clean before 'cleanupVerified' is true.
  const stRaw = await taskAgent(agentId, 'execproxy-status', '{}');
  const st = parseExecProxyResult(stRaw);
  const sweepClean = !!(st && st.clean === true);

  const removalVerified = !!(remEv && remEv.removalVerified === true);
  const cleanupVerified = removalVerified && sweepClean;
  return {
    refused: false,
    technique: spec.technique,
    name: runName,
    at,
    ran: runEv ? {
      state: runEv.state, command: runEv.command || null,
      dllSha256: runEv.dllSha256 || null, hostSha256: runEv.hostSha256 || null,
      hostSigStatus: runEv.hostSigStatus || null, hostSigner: runEv.hostSigner || null,
      exitCode: runEv.exitCode ?? null, markerVerified: runEv.markerVerified === true, stillRunning: runEv.stillRunning === true,
    } : null,
    verdict: edr.verdict,
    edr: { matches: edr.matches, checked: edr.checked, unavailable: edr.unavailable, note: edr.note },
    removal: remEv ? { state: remEv.state, removalVerified } : { state: 'no-evidence', removalVerified: false },
    sweep: st ? { clean: sweepClean, open: st.open || [] } : { clean: false, open: ['status evidence unparseable'] },
    cleanupVerified,
    note: cleanupVerified
      ? 'signed-proxy run measured (edrview verdict: ' + edr.verdict + ') and the plant is verified gone — the honest loop is closed'
      : 'CLEANUP UNVERIFIED — treat the host as STILL PLANTED (removalVerified=' + removalVerified + ', sweepClean=' + sweepClean + '); run execproxy-remove + execproxy-status until the sweep is clean',
    evidence: { run: String(runRaw).slice(0, 300), remove: String(remRaw).slice(0, 300), status: String(stRaw).slice(0, 300) },
  };
}

export const EXECPROXY_TECHNIQUES_FOR_CLI = EXECPROXY_TECHNIQUES;
export const EXECPROXY_EXPORTS_FOR_CLI = EXECPROXY_EXPORTS;
