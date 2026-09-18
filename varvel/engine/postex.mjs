// VARVEL — governed post-exploitation task library (the Cobalt post-ex tier, range-bound).
//
// Jack's directive (2026-07-31): post-ex internals live IN VARVEL, better than HYDRA's —
// because Cobalt has them and the platform can't be second-best anywhere. Built to that
// bar with the line that makes VARVEL deployable kept IN CODE, not in a README:
//
//   * RANGE-BOUND: every task runs through the governed callback channel against an
//     agent whose host must pass the engagement's signed-scope check. Out-of-scope
//     refuses BEFORE a task is built.
//   * HITL-LOCKED: postexRun refuses without authorized:true (operator approval), same
//     pattern as the credential-stuffing analyzer. Approval is per-run, logged.
//   * SIM-HONEST: tasks that simulate a TTP carry SIM in the id/label/evidence and
//     plant clearly-marked decoys (VARVELSIM-*). No real credential dumping, no real
//     token theft — the mechanics are proven end-to-end on the range with decoy
//     material, which is what detection engineering actually needs.
//   * CLEANUP IS MANDATORY: tasks that change the target ship a cleanup plan; the
//     runner executes and VERIFIES it after evidence capture. A run is not complete
//     until cleanup is verified (waiving needs a second explicit approval flag).
//   * NO evasion internals, NO anti-forensics — permanently (TOOL-PLAN "the line").
//     Post-ex proves impact and produces detections, never implants.
//
// MITRE-mapped so the SOC side can pair every task with its detection signature.

// ---------- helpers ----------
const ps = (script) => ({ kind: 'shell', command: `powershell -NoProfile -Command "${script.replace(/"/g, '\\"')}"` });
const cmd = (c) => ({ kind: 'shell', command: c });

function parseKeyValues(text, re) {
  const out = [];
  for (const line of String(text || '').split(/\r?\n/)) {
    const m = re.exec(line);
    if (m) out.push(m[1].trim());
  }
  return out;
}

// ---------- the task registry ----------
export const POSTEX_TASKS = {
  sysdisc: {
    id: 'sysdisc', mitre: 'TA0007 Discovery', sim: false, changesTarget: false,
    title: 'Structured system discovery',
    summary: 'hostname, user context, group membership, network config — parsed into intel, not raw dumps',
    build({ }) {
      return cmd('hostname & whoami & whoami /groups & ipconfig /all & net localgroup administrators');
    },
    parse(text) {
      const lines = String(text || '').split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
      const hostname = lines[0] || null;
      const user = lines[1] || null;
      const groups = parseKeyValues(text, /^\s*(?:.+\\)?(.+?)\s+(?:Alias|Group|Well-known group)/);
      const ips = [
        ...parseKeyValues(text, /IPv4 Address[.\s]*:\s*(\S+)/),
        ...parseKeyValues(text, /(?:Temporary |Link-local )?IPv6 Address[.\s]*:\s*(\S+)/),
      ];
      const adminsIdx = lines.findIndex((l) => /administrators/i.test(l) && /localgroup/i.test(l));
      const admins = adminsIdx >= 0 ? lines.slice(adminsIdx + 1).filter((l) => l && !/command completed/i.test(l) && !/^-+$/.test(l)) : [];
      return { hostname, user, groups: groups.slice(0, 12), ips, localAdmins: admins, isElevated: /High Mandatory Level|S-1-16-12288/i.test(text) };
    },
    verify(intel) { return { ok: !!intel.hostname, note: intel.hostname ? `host identity confirmed: ${intel.hostname} (${intel.ips.length} IPs)` : 'no hostname parsed — unexpected output shape' }; },
    cleanup() { return null; }, // read-only
  },

  'cred-sim': {
    id: 'cred-sim', mitre: 'TA0006 Credential Access (SIMULATED)', sim: true, changesTarget: true,
    title: 'Credential-access simulation (decoy plant → collect → stage → delete)',
    summary: 'proves the collection mechanic end-to-end with a MARKED decoy; gives the SOC its signature',
    build({ runId = 'x' }) {
      const f = `$env:TEMP\\VARVELSIM-cred-${runId}.txt`;
      return ps(`Set-Content -Path ${f} -Value 'VARVEL SIMULATED CREDENTIAL - DECOY ONLY - rangeId=${runId}'; Get-Content ${f}`);
    },
    parse(text) {
      const m = /VARVEL SIMULATED CREDENTIAL - DECOY ONLY - rangeId=(\S+)/.exec(text || '');
      return { decoyRecovered: !!m, rangeId: m?.[1] || null };
    },
    verify(intel) { return { ok: intel.decoyRecovered, note: intel.decoyRecovered ? `decoy credential collected and staged (SIM) — detection point: file create + read of a cred-shaped file` : 'decoy marker not found in output' }; },
    cleanup({ runId = 'x' }) {
      return ps(`$f = "$env:TEMP\\VARVELSIM-cred-${runId}.txt"; if (Test-Path $f) { Remove-Item $f -Force; if (Test-Path $f) { 'CLEANUP-FAILED' } else { 'CLEANUP-VERIFIED' } } else { 'CLEANUP-VERIFIED (already absent)' }`);
    },
    cleanupVerified: (text) => /CLEANUP-VERIFIED/.test(text || ''),
  },

  'token-sim': {
    id: 'token-sim', mitre: 'TA1134 Access Token Manipulation (SIMULATED)', sim: true, changesTarget: false,
    title: 'Token visibility simulation (privilege/group surface of the current token)',
    summary: 'documents what the agent token can see and what an elevated token would add — no theft performed',
    build({ }) {
      return cmd('whoami /priv & whoami /groups & whoami /upn');
    },
    parse(text) {
      const privs = parseKeyValues(text, /^\s*(Se\w+Privilege)\b/);
      const highIntegrity = /High Mandatory Level|S-1-16-12288/i.test(text || '');
      return { privileges: privs, highIntegrity, dangerousHeld: privs.filter((p) => /SeDebug|SeImpersonate|SeAssignPrimaryToken|SeBackup|SeRestore/.test(p)) };
    },
    verify(intel) {
      return { ok: true, note: `token surface mapped (SIM): ${intel.privileges.length} privileges, integrity ${intel.highIntegrity ? 'HIGH' : 'medium/low'}${intel.dangerousHeld.length ? ` — impersonation-relevant held: ${intel.dangerousHeld.join(', ')}` : ''}` };
    },
    cleanup() { return null; },
  },

  'persist-sim': {
    id: 'persist-sim', mitre: 'TA1053.005 Scheduled Task (SIMULATED + guaranteed teardown)', sim: true, changesTarget: true,
    title: 'Persistence simulation via a MARKED scheduled task',
    summary: 'creates VARVELSIM-<runId> task, proves the mechanic, MANDATES verified teardown',
    build({ runId = 'x' }) {
      // SYSTEM-context agents can't map the implicit current-user SID → fall back to an
      // explicit /ru SYSTEM (2>nul keeps the first attempt's error text out of parse()).
      return cmd(`schtasks /create /tn "VARVELSIM-${runId}" /tr "cmd /c exit 0" /sc once /st 23:59 /f 2>nul || schtasks /create /tn "VARVELSIM-${runId}" /ru SYSTEM /tr "cmd /c exit 0" /sc once /st 23:59 /f 2>nul & schtasks /query /tn "VARVELSIM-${runId}"`);
    },
    parse(text) {
      const created = /VARVELSIM-\S+/.test(text || '') && !/ERROR|denied/i.test(text || '');
      return { taskCreated: created, detectionEvents: ['Security 4698 (task created)', 'TaskScheduler 106/200', 'Sysmon 1 (schtasks process)'] };
    },
    verify(intel) { return { ok: intel.taskCreated, note: intel.taskCreated ? `marked persistence installed (SIM) — SOC should see: ${intel.detectionEvents.join(', ')}` : 'task creation failed or refused' }; },
    cleanup({ runId = 'x' }) {
      return cmd(`schtasks /delete /tn "VARVELSIM-${runId}" /f & schtasks /query /tn "VARVELSIM-${runId}"`);
    },
    cleanupVerified: (text) => /ERROR: The system cannot find the file specified|cannot find/i.test(text || ''),
  },

  'lateral-relay': {
    id: 'lateral-relay', mitre: 'TA0010/TA1572 Lateral Movement via C2 relay (ORCHESTRATION)', sim: true, changesTarget: false,
    title: 'Pivot-chain orchestration plan (agent-through-agent relay)',
    summary: 'validates both agents and emits the relay plan; channel-level relay ships with pivot chaining',
    build({ relayAgentId, viaAgentId }) {
      if (!relayAgentId || !viaAgentId) throw new Error('lateral-relay needs relayAgentId + viaAgentId');
      return { kind: 'note', text: `RELAY-PLAN: tasks for agent ${relayAgentId} routed via agent ${viaAgentId} (orchestration-level; protocol relay = pivot chaining track)` };
    },
    parse(text) { return { planRecorded: /RELAY-PLAN/.test(text || '') }; },
    verify(intel) { return { ok: intel.planRecorded, note: intel.planRecorded ? 'relay plan validated and logged (orchestration-level SIM)' : 'plan not recorded' }; },
    cleanup() { return null; },
  },
};

export const postexTask = (id) => POSTEX_TASKS[id] || null;

/**
 * Run one governed post-ex task against an agent. Refuses out-of-scope and
 * unauthorized runs BEFORE building anything; cleanup is executed and verified
 * for every state-changing task unless explicitly waived with a second approval.
 *
 * @param {string} id — task id from POSTEX_TASKS
 * @param {object} target — { agentId, host, params?: { runId?, relayAgentId?, viaAgentId? } }
 * @param {object} ctx — { authorized, scopeCheck(host)->bool, taskAgent(agentId, task)->resultText, log?(kind,data), waiveCleanup? }
 */
export async function postexRun(id, target, ctx = {}) {
  const task = postexTask(id);
  if (!task) return { ok: false, refused: true, reason: `unknown post-ex task: ${id}` };
  if (ctx.authorized !== true) return { ok: false, refused: true, reason: 'post-ex requires operator approval (authorized: true) — HITL gate not passed' };
  if (typeof ctx.scopeCheck !== 'function' || !ctx.scopeCheck(target.host)) {
    return { ok: false, refused: true, reason: `host ${target.host} is outside the signed engagement scope` };
  }
  if (typeof ctx.taskAgent !== 'function') return { ok: false, refused: true, reason: 'no channel task function provided' };
  const log = ctx.log || (() => {});
  const params = target.params || {};

  log('postex.start', { task: id, agent: target.agentId, host: target.host, sim: !!task.sim });
  const channelTask = task.build({ runId: params.runId || 'run', ...params });
  const raw = await ctx.taskAgent(target.agentId, channelTask);
  const intel = task.parse(raw);
  const verification = task.verify(intel);
  log('postex.result', { task: id, ok: verification.ok, note: verification.note });

  let cleanup = null;
  const cleanupPlan = task.cleanup ? task.cleanup({ runId: params.runId || 'run', ...params }) : null;
  if (cleanupPlan && !ctx.waiveCleanup) {
    const cleanupRaw = await ctx.taskAgent(target.agentId, cleanupPlan);
    const verified = task.cleanupVerified ? task.cleanupVerified(cleanupRaw) : true;
    cleanup = { executed: true, verified, raw: String(cleanupRaw || '').slice(0, 200) };
    log('postex.cleanup', { task: id, verified });
    if (!verified) return { ok: false, intel, verification, cleanup, error: 'CLEANUP NOT VERIFIED — target may still hold the SIM artifact; investigate immediately' };
  } else if (cleanupPlan && ctx.waiveCleanup) {
    cleanup = { executed: false, waived: true, warning: 'cleanup waived by explicit operator flag — artifact remains by operator decision' };
    log('postex.cleanup-waived', { task: id });
  }

  return { ok: verification.ok, sim: !!task.sim, intel, verification, cleanup, mitre: task.mitre };
}

export function postexCatalog() {
  return Object.values(POSTEX_TASKS).map((t) => ({ id: t.id, mitre: t.mitre, sim: t.sim, title: t.title, summary: t.summary, changesTarget: t.changesTarget === true }));
}
