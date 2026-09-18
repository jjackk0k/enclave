// VARVEL — the GOVERNED AD TIER, rung 2: LATERAL EXEC ADAPTERS (PURE planner + the
// cleanup-proof state machine). The standard lateral-movement trio every C2 ships
// (CS's psexec/wmi/winrm jump-exec), built the VARVEL way: default-OFF, double-gated,
// scope-checked, fully audited, and CLEANUP-PROOF.
//
//   wmi     — Win32_Process.Create over a CIM/WMI session with the operator-supplied
//             creds; result capture rides a wrapped command's output file on the
//             target, read back over ADMIN$. Runs as the SUPPLIED user.
//   winrm   — Invoke-Command / WS-Man psremoting with the supplied creds; native
//             stdout capture, NO persistent artifacts (the honest profile: the
//             defender-visible trail is the 4624/4672 logon pair, nothing on disk).
//   psexec  — the PsExec class: a temporary service (Win32_Service.Create over CIM)
//             running the wrapped command, output to a file read back over ADMIN$,
//             then the service is stopped and deleted. Runs as SYSTEM on the target
//             (that is the class's point — stated, never hidden).
//
// SCOPE DISCIPLINE (absolute — the channel/seam CIDR rule): the target must be an IP
// LITERAL inside the engagement's signed CIDR ring. Hostnames cannot be scope-
// verified, so they are refused at the spec gate; an IP outside the ring is a loud
// GOVERNANCE refusal at queue time. Out-of-scope lateral movement simply never queues.
//
// THE SIGNATURE DOCTRINE, enforced exactly as in engine/persist.mjs /
// engine/execproxy.mjs: an artifact that cannot prove its own removal is never
// left behind. Mechanically: exec() pre-probes every artifact it would create
// (a foreign service/file already sitting at our planned name is a loud
// 'refused-clobber', never a silent takeover), executes through the injected
// backend, captures the result, then REMOVES every created artifact and PROVES
// absence by re-read. The manifest records every artifact (services created, files
// dropped, shares touched) with its verification booleans; lateral-remove takes
// back anything that lingered (a mid-exec crash), and the lateral-status sweep
// refuses 'clean' while artifacts persist. Removal failure is LOUD and escalated
// ('lateral.remove-failed'), never a quiet lie.
//
// CREDENTIAL DOCTRINE: operator-supplied creds ride the task data to the agent over
// the governed channel (same doctrine as the persist tier's relaunch token). The
// password is NEVER pinned, logged, previewed, or emitted: specSha256 pins the
// ORDER (adapter/target/user/command-sha256), audit events carry adapter + target +
// user + artifact sha/booleans, and parseLateralEvidence strips output tails from
// the audit stream. Secret-negative tests pin this.
//
// Governance (three seams, all fail-closed):
//   1. ENGAGEMENT GATE — settings key 'ad.lateral' (default OFF) + the agent's own
//      -AllowLateral launch flag. Refusals are loud and audited (task.refused).
//   2. SPEC GATE + SCOPE — known kind/adapter, IP-literal target, capped command;
//      remove requires an explicit scope (name XOR all:true). Refused BEFORE queueing.
//   3. AUDIT — 'lateral.task' at queue (specSha256), then 'lateral.ran' /
//      'lateral.removed' / 'lateral.remove-failed' / 'lateral.status' at intake with
//      the artifact manifest and every verification boolean.

import { createHash } from 'node:crypto';
import { Settings } from './settings.mjs';
import { parseIp, inAnyCidr } from './ipaddr.mjs';

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

export const LATERAL_KIND_EXEC = 'lateral-exec';
export const LATERAL_KIND_REMOVE = 'lateral-remove';
export const LATERAL_KIND_STATUS = 'lateral-status';
export const LATERAL_KINDS = new Set([LATERAL_KIND_EXEC, LATERAL_KIND_REMOVE, LATERAL_KIND_STATUS]);

export const LATERAL_ADAPTERS = ['wmi', 'winrm', 'psexec'];
export const LATERAL_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,39}$/;

export function lateralTag(seed) {
  return 'vx-' + sha256(String(seed ?? '')).slice(0, 8);
}

// The adapter registry. artifacts() is the PURE plan: exactly what the agent leg will
// create/touch on the target — the manifest records exactly this, the cleanup-proof
// removes exactly this, and the audit trail pins exactly this.
export const LATERAL_REGISTRY = {
  wmi: {
    adapter: 'wmi',
    resultCapture: 'file', // win32_process create returns a PID, not output
    runsAs: 'supplied-user',
    summary: 'Win32_Process.Create over CIM with the operator-supplied creds; the wrapped command redirects to %SystemRoot%\\Temp\\<tag>.out on the target (a path ADMIN$ reaches — a per-user %TEMP% would not), read back over the share. Runs as the supplied user.',
    artifacts(tag) {
      return [
        { kind: 'file', role: 'result-capture', path: '%SystemRoot%\\Temp\\' + tag + '.out' },
        { kind: 'share', role: 'result-read', name: 'ADMIN$' }, // touched, never created — recorded for audit, nothing to remove
      ];
    },
  },
  winrm: {
    adapter: 'winrm',
    resultCapture: 'native', // Invoke-Command returns stdout
    runsAs: 'supplied-user',
    summary: 'WS-Man psremoting (Invoke-Command) with the operator-supplied creds; native stdout capture. Creates NO persistent artifacts on the target — the defender-visible trail is the logon telemetry (4624/4672), graded by edrview.',
    artifacts() { return []; },
  },
  psexec: {
    adapter: 'psexec',
    resultCapture: 'file',
    runsAs: 'SYSTEM', // the class's point, stated plainly
    summary: 'PsExec class: a temporary service (Win32_Service.Create over CIM) runs the wrapped command as SYSTEM, output to %SystemRoot%\\Temp\\<tag>.out read back over ADMIN$; the service is then stopped+deleted and the file removed — all verified by re-read.',
    artifacts(tag) {
      return [
        { kind: 'service', role: 'exec-host', name: tag },
        { kind: 'file', role: 'result-capture', path: '%SystemRoot%\\Temp\\' + tag + '.out' },
        { kind: 'share', role: 'result-read', name: 'ADMIN$' },
      ];
    },
  },
};

const MAX_COMMAND = 800;
const MAX_FIELD = 260;

// ——— SPEC GATE ———
export function parseLateralSpec(kind, data) {
  kind = String(kind || '');
  if (!LATERAL_KINDS.has(kind)) throw new TypeError('lateralexec: unknown kind ' + JSON.stringify(kind) + ' (want one of ' + [...LATERAL_KINDS].join(', ') + ')');
  const raw = String(data ?? '').trim();
  const parseObj = (k, want) => {
    let spec;
    try { spec = JSON.parse(raw); } catch { throw new TypeError(k + ': task data is not valid JSON (want ' + want + ')'); }
    if (!spec || typeof spec !== 'object' || Array.isArray(spec)) throw new TypeError(k + ': task data must be a JSON object');
    return spec;
  };
  const nameFrom = (spec, k) => {
    if (spec.name === undefined || spec.name === null || String(spec.name).trim() === '') return null;
    const name = String(spec.name).trim();
    if (!LATERAL_NAME_RE.test(name)) throw new TypeError(k + ': name ' + JSON.stringify(name) + ' is not a safe artifact handle (want ' + LATERAL_NAME_RE + ' — it becomes the temporary service name and the result-file base name on the target)');
    return name;
  };
  if (kind === LATERAL_KIND_STATUS) {
    if (!raw || raw === '{}') return { kind, name: null };
    const spec = parseObj(kind, '{"name":"vx-xxxxxxxx"}');
    return { kind, name: nameFrom(spec, kind) };
  }
  if (kind === LATERAL_KIND_REMOVE) {
    if (!raw || raw === '{}') throw new TypeError('lateral-remove needs an explicit scope: {"name":"..."} or {"all":true} — removal is never ambiguous');
    const spec = parseObj(kind, '{"name":"..."} or {"all":true}');
    const all = spec.all === true;
    const name = nameFrom(spec, kind);
    if (all && name) throw new TypeError('lateral-remove: give name OR all:true, not both — the removal scope must be unambiguous');
    if (!all && !name) throw new TypeError('lateral-remove needs an explicit scope: {"name":"..."} or {"all":true}');
    return { kind, name, all };
  }
  // lateral-exec
  const spec = parseObj(kind, '{"target":"<range-ip>","adapter":"wmi|winrm|psexec","command":"<cmd>","user":"...","password":"..."}');
  const target = String(spec.target || '').trim();
  if (!target || target.length > 60) throw new TypeError(kind + ': target is required (an IP literal inside the signed scope ring)');
  if (!parseIp(target)) {
    throw new TypeError(kind + ': target ' + JSON.stringify(target.slice(0, 60)) + ' is not an IP literal — hostnames cannot be verified against the signed CIDR ring, so they are refused (fail-closed). Supply the range IP.');
  }
  const adapter = String(spec.adapter || '').toLowerCase().trim();
  if (!LATERAL_ADAPTERS.includes(adapter)) {
    throw new TypeError(kind + ': unknown adapter ' + JSON.stringify(spec.adapter) + ' (stage 1 ships ' + LATERAL_ADAPTERS.join(', ') + ' — wmi win32_process create, winrm psremoting, psexec-class service+pipe)');
  }
  const command = String(spec.command ?? '');
  if (!command.trim()) throw new TypeError(kind + ': command is required (the wrapped remote command line)');
  if (command.length > MAX_COMMAND) throw new RangeError(kind + ': command exceeds the ' + MAX_COMMAND + '-char cap');
  const out = {
    kind, target, adapter, command,
    name: nameFrom(spec, kind),
    user: spec.user == null ? null : String(spec.user).slice(0, MAX_FIELD),
    domain: spec.domain == null ? null : String(spec.domain).slice(0, 104),
    // SECRET: rides the task data to the agent over the governed channel; NEVER
    // pinned, logged, previewed, or emitted in an audit event (see lateralSpecSha256
    // and parseLateralEvidence — secret-negative tests pin this).
    password: spec.password == null ? null : String(spec.password).slice(0, 400),
  };
  return out;
}

// The engagement gate. Fail-CLOSED on any settings-layer error.
export function lateralGate(engagement) {
  let on = false;
  try { on = Settings.for(engagement || 'default').get('ad.lateral') === true; } catch { on = false; }
  if (!on) {
    return {
      ok: false,
      reason: "engagement setting 'ad.lateral' is OFF — the lateral execution tier is disabled. "
        + "An operator must explicitly enable it for engagement '" + (engagement || 'default') + "' "
        + "(POST /api/settings {key:'ad.lateral', value:true}) before lateral tasks will queue, and the agent must "
        + "have been launched with its own lateral flag. Nothing executed, nothing created on any target.",
    };
  }
  return { ok: true };
}

// THE SCOPE CHECK (the channel/seam CIDR discipline, fail-closed): the target must
// sit inside the signed ring. Used by the channel gate for lateral targets AND for
// the roast collector's DC. Returns { ok: true } or { ok: false, reason }.
export function lateralScopeCheck(target, cidrs, what = 'target') {
  const ip = parseIp(String(target || ''));
  if (!ip) return { ok: false, reason: what + ' ' + JSON.stringify(String(target || '').slice(0, 60)) + ' is not an IP literal — it cannot be verified against the signed scope ring (fail-closed)' };
  if (!inAnyCidr(ip.text, cidrs || [])) {
    return { ok: false, reason: what + ' ' + ip.text + ' is OUTSIDE the signed scope ring (' + (cidrs || []).join(', ') + ') — REFUSED loudly: nothing was queued, nothing left the governed channel' };
  }
  return { ok: true };
}

// The sha256 of the normalized ORDER — pinned into 'lateral.task' at queue time.
// The password is NEVER part of the pin; the command is pinned by its sha256 only.
export function lateralSpecSha256(spec) {
  return sha256(JSON.stringify({
    kind: spec.kind, adapter: spec.adapter || null, target: spec.target || null,
    user: spec.user || null, domain: spec.domain || null,
    commandSha256: spec.command ? sha256(spec.command) : null,
    name: spec.name || null, all: spec.all === true,
  }));
}

// ——— LateralStore ———
// The PURE state-machine twin of the agent-side ==LATERAL-LIB== machinery, run over
// an INJECTED backend so the cleanup-proof contract pins hermetically:
//
// backend = {
//   run(job) -> { code:number, output:string }   // execute via the adapter agent-side
//                                                // (job = {adapter, target, command, user,
//                                                //  domain, password, tag, artifacts})
//   probe(artifact) -> { present:boolean }       // re-read the target's state
//   remove(artifact) -> void                     // delete ONE artifact (service|file)
// }
// A test backend is a Map; the real backend is the range, driven by the PS twin.
export class LateralStore {
  constructor({ backend, name, now } = {}) {
    if (!backend || typeof backend.run !== 'function' || typeof backend.probe !== 'function' || typeof backend.remove !== 'function') {
      throw new TypeError('LateralStore needs an injected backend { run, probe, remove } — real targets are NEVER touched from Node');
    }
    if (!name || !LATERAL_NAME_RE.test(String(name))) throw new TypeError('LateralStore needs a valid name handle (the manifest key / artifact base name)');
    this.backend = backend;
    this.name = String(name);
    this._now = typeof now === 'function' ? now : () => new Date().toISOString();
    this.manifest = { version: 1, name: this.name, createdAt: this._now(), entries: {} };
  }

  _evidence(adapter, target) {
    return {
      state: 'failed', adapter: adapter || null, target: target || null,
      exitCode: null, outputTail: null,
      artifacts: [], // { kind, role, name|path, host, present, created, removalVerified, note }
      note: null, error: null,
    };
  }

  // exec(): pre-probe FIRST (a foreign artifact at our planned name is a loud
  // refusal, never a takeover), run through the backend, capture the result, then
  // REMOVE every created artifact and PROVE absence by re-read. Share-kind artifacts
  // are touches (ADMIN$ is not ours to remove) — recorded for audit only.
  exec(spec) {
    const reg = LATERAL_REGISTRY[spec.adapter];
    if (!reg) throw new TypeError('lateral-exec: unknown adapter ' + JSON.stringify(spec.adapter));
    const ev = this._evidence(spec.adapter, spec.target);
    ev.note = reg.summary;
    const planned = reg.artifacts(this.name).map((a) => ({ ...a, host: spec.target }));

    // 1. PRE-PROBE: never clobber or hijack a foreign artifact.
    for (const a of planned) {
      if (a.kind === 'share') { ev.artifacts.push({ ...a, present: null, created: false, removalVerified: null, note: 'share touch recorded for audit — nothing is created on the share, nothing to remove' }); continue; }
      let pre;
      try { pre = this.backend.probe(a); } catch (e) {
        ev.error = 'pre-exec probe failed for ' + (a.name || a.path) + ': ' + ((e && e.message) || e) + ' — nothing executed (cleanup doctrine: no snapshot, no exec)';
        ev.artifacts.push({ ...a, present: null, created: false, removalVerified: null });
        return ev;
      }
      if (pre && pre.present === true) {
        const ours = (this.manifest.entries[this.name] || {}).artifacts || [];
        const isOurs = ours.some((x) => x.kind === a.kind && (x.name || null) === (a.name || null) && (x.path || null) === (a.path || null));
        if (!isOurs) {
          ev.state = 'refused-clobber';
          ev.error = 'planned ' + a.kind + ' artifact already EXISTS on the target (' + (a.name || a.path) + ') and is NOT ours — REFUSED to clobber or hijack it. Pick another name handle, or lateral-remove ours first.';
          ev.artifacts.push({ ...a, present: true, created: false, removalVerified: null });
          return ev;
        }
      }
      ev.artifacts.push({ ...a, present: false, created: false, removalVerified: null });
    }

    // 2. EXECUTE through the adapter (agent-side backend; result capture per the registry).
    let r;
    try {
      r = this.backend.run({ adapter: spec.adapter, target: spec.target, command: spec.command, user: spec.user || null, domain: spec.domain || null, password: spec.password || null, tag: this.name, artifacts: planned });
    } catch (e) {
      ev.error = 'adapter exec failed: ' + ((e && e.message) || e);
      this._cleanup(ev, planned);
      this._recordEntry(ev, spec, planned, 'failed');
      return ev;
    }
    r = r || {};
    ev.exitCode = typeof r.code === 'number' ? r.code : null;
    ev.outputTail = String(r.output || '').slice(-800); // the full body rides the results path; the AUDIT event strips it
    ev.state = 'ran';
    for (const rec of ev.artifacts) if (rec.kind !== 'share') rec.created = true;

    // 3. CLEANUP-PROOF: remove every created artifact, verify absence by re-read.
    this._cleanup(ev, planned);
    this._recordEntry(ev, spec, planned, ev.state);
    return ev;
  }

  _cleanup(ev, planned) {
    for (const a of planned) {
      if (a.kind === 'share') continue;
      const rec = ev.artifacts.find((x) => x.kind === a.kind && x.name === a.name && x.path === a.path);
      try {
        this.backend.remove(a);
        const post = this.backend.probe(a);
        const gone = !!(post && post.present === false);
        if (rec) { rec.removalVerified = gone; rec.present = !gone; }
        if (!gone) {
          ev.error = (ev.error ? ev.error + ' ' : '') + 'CLEANUP-PROOF FAILED: ' + a.kind + ' ' + (a.name || a.path) + ' is STILL PRESENT on re-read after removal (loud, escalated; the engagement cannot be called clean)';
          ev.state = 'removal-failed';
        }
      } catch (e) {
        if (rec) rec.removalVerified = false;
        ev.error = (ev.error ? ev.error + ' ' : '') + 'artifact removal failed for ' + (a.name || a.path) + ': ' + ((e && e.message) || e) + ' — removal UNVERIFIED (LOUD; escalate)';
        ev.state = 'removal-failed';
      }
    }
  }

  _recordEntry(ev, spec, planned, state) {
    const prev = this.manifest.entries[this.name];
    this.manifest.entries[this.name] = {
      name: this.name, adapter: spec.adapter, target: spec.target,
      user: spec.user || null, domain: spec.domain || null,
      commandSha256: sha256(spec.command || ''),
      artifacts: planned.map((a) => ({ kind: a.kind, role: a.role, name: a.name || null, path: a.path || null, host: a.host })),
      state,
      exitCode: ev.exitCode,
      ranAt: (prev && prev.ranAt) || this._now(),
      removedAt: ev.state === 'removal-failed' ? null : this._now(),
      removalVerified: ev.artifacts.filter((a) => a.kind !== 'share').every((a) => a.removalVerified === true),
    };
  }

  // status(): LIVE re-read of every manifest artifact, measured now — never remembered.
  status() {
    const entry = this.manifest.entries[this.name];
    const ev = this._evidence(entry && entry.adapter, entry && entry.target);
    if (!entry) {
      ev.state = 'absent';
      ev.note = 'no manifest entry for this name handle — nothing was ever executed under it (measured now)';
      return ev;
    }
    let anyPresent = false;
    let anyUnknown = false;
    for (const a of entry.artifacts) {
      if (a.kind === 'share') { ev.artifacts.push({ ...a, present: null, removalVerified: null, note: 'share touch (audit record only)' }); continue; }
      let cur = null;
      try { cur = this.backend.probe(a); } catch { cur = null; }
      if (cur === null) { anyUnknown = true; ev.artifacts.push({ ...a, present: null, removalVerified: null, note: 'probe failed — never assume absence' }); continue; }
      if (cur.present) anyPresent = true;
      ev.artifacts.push({ ...a, present: cur.present === true, removalVerified: cur.present === false, note: cur.present ? 'STILL PRESENT at live re-read' : 'verified absent at live re-read' });
    }
    if (anyPresent) { ev.state = 'present'; ev.note = 'artifact(s) from this name handle are STILL PRESENT on the target — run lateral-remove; the engagement is NOT clean'; }
    else if (anyUnknown) { ev.state = 'unknown'; ev.note = 'a probe failed — never assume absence'; }
    else { ev.state = 'clean'; ev.note = 'every artifact from this name handle is verified absent at live re-read'; }
    return ev;
  }

  // remove(): the standing cleanup leg — take back anything that lingered, verify by
  // re-read. A foreign... there is no foreign case here: remove only ever touches
  // artifacts this store's manifest recorded. A removal that cannot verify is
  // 'removal-failed' — LOUD, escalated channel-side.
  remove() {
    const entry = this.manifest.entries[this.name];
    const ev = this._evidence(entry && entry.adapter, entry && entry.target);
    if (!entry) {
      ev.state = 'removed';
      ev.note = 'nothing was ever executed under this name handle — verified clean (no manifest entry)';
      return ev;
    }
    let failed = false;
    for (const a of entry.artifacts) {
      if (a.kind === 'share') { ev.artifacts.push({ ...a, present: null, removalVerified: null, note: 'share touch (audit record only) — nothing to remove' }); continue; }
      const rec = { ...a, present: null, removalVerified: null };
      let pre;
      try { pre = this.backend.probe(a); } catch (e) {
        rec.removalVerified = false; failed = true;
        ev.artifacts.push(rec);
        ev.error = 'pre-remove probe failed for ' + (a.name || a.path) + ': ' + ((e && e.message) || e) + ' — removal UNVERIFIED (LOUD; escalate)';
        continue;
      }
      if (pre && pre.present === true) {
        try { this.backend.remove(a); } catch (e) {
          rec.present = true; rec.removalVerified = false; failed = true;
          ev.artifacts.push(rec);
          ev.error = 'remove failed for ' + (a.name || a.path) + ': ' + ((e && e.message) || e) + ' — removal UNVERIFIED (LOUD; escalate)';
          continue;
        }
      }
      let post;
      try { post = this.backend.probe(a); } catch { post = null; }
      rec.present = post ? post.present === true : null;
      rec.removalVerified = post ? post.present === false : false;
      if (!rec.removalVerified) {
        failed = true;
        ev.error = 'remove executed but ' + a.kind + ' ' + (a.name || a.path) + ' is STILL PRESENT on re-read — CLEANUP-PROOF FAILED (loud, escalated; the engagement cannot be called clean)';
      }
      ev.artifacts.push(rec);
    }
    ev.state = failed ? 'removal-failed' : 'removed';
    if (!failed) {
      ev.note = 'every recorded artifact is verified absent — the target provably holds nothing of ours under this name handle';
      entry.state = 'removed'; entry.removalVerified = true; entry.removedAt = this._now();
    } else {
      entry.state = 'removal-failed'; entry.removalVerified = false;
    }
    return ev;
  }

  // audit(): the sweep over THIS store's manifest. clean === true ONLY with zero
  // artifacts still present / removal-unverified — an engagement with unverified
  // lateral artifacts is never clean.
  audit() {
    const entry = this.manifest.entries[this.name];
    if (!entry) return { state: 'clean', clean: true, entries: [], open: [], note: 'nothing was ever executed under this name handle (empty manifest) — clean' };
    const st = this.status();
    const openArtifacts = st.artifacts.filter((a) => a.kind !== 'share' && a.removalVerified !== true);
    const rec = { name: this.name, adapter: entry.adapter, target: entry.target, state: st.state, removalVerified: openArtifacts.length === 0, ranAt: entry.ranAt, removedAt: entry.removedAt || null };
    const open = openArtifacts.length ? [rec] : [];
    return {
      state: open.length ? 'unclean' : 'clean',
      clean: open.length === 0,
      entries: [rec], open,
      note: open.length
        ? 'artifact(s) still present or removal-unverified under this name handle — the engagement CANNOT be called clean; run lateral-remove and re-audit'
        : 'every lateral artifact under this name handle is verified removed — clean',
    };
  }
}

// ——— INTAKE: agent result body -> the audit event. The output tail is STRIPPED from
// the audit stream (it rides the full-body results path only); the password was never
// in the body at all (the agent never echoes it). No event is fabricated from
// unverifiable data. ———
export function parseLateralEvidence(body) {
  let p;
  try { p = JSON.parse(String(body || '')); } catch { return null; }
  if (!p || typeof p !== 'object' || typeof p.op !== 'string') return null;
  if (p.op === 'status' || p.op === 'audit') {
    if (typeof p.clean !== 'boolean' || !Array.isArray(p.entries)) return null;
    return {
      event: 'lateral.status',
      fields: {
        op: 'status', state: String(p.state || (p.clean ? 'clean' : 'unclean')), clean: p.clean, pid: p.pid ?? null,
        entries: p.entries.filter((e) => e && typeof e === 'object').map((e) => ({
          name: String(e.name || ''), adapter: e.adapter || null, target: e.target || null, state: String(e.state || 'unknown'), removalVerified: e.removalVerified === true,
        })),
        open: Array.isArray(p.open) ? p.open.filter((e) => e && typeof e === 'object').map((e) => ({ name: String(e.name || ''), adapter: e.adapter || null, target: e.target || null, state: String(e.state || 'unknown') })) : [],
      },
    };
  }
  const event = p.op === 'ran' ? 'lateral.ran' : null;
  if (!p.names || typeof p.names !== 'object') return null;
  const names = {};
  let anyRemovalFailed = false;
  for (const [name, ev] of Object.entries(p.names)) {
    if (!ev || typeof ev !== 'object') continue;
    const state = String(ev.state || 'unknown');
    if (state === 'removal-failed' || state === 'refused-clobber') anyRemovalFailed = true;
    names[name] = {
      state,
      adapter: ev.adapter || null,
      target: ev.target || null,
      exitCode: typeof ev.exitCode === 'number' ? ev.exitCode : null,
      outputSha256: ev.outputSha256 || null,
      artifacts: Array.isArray(ev.artifacts) ? ev.artifacts.filter((a) => a && typeof a === 'object').map((a) => ({
        kind: a.kind || null, role: a.role || null, name: a.name || null, path: a.path || null, host: a.host || null,
        present: a.present === true, removalVerified: a.removalVerified === true,
      })) : [],
      removalVerified: ev.removalVerified === true,
    };
  }
  if (Object.keys(names).length === 0) return null; // NO EVIDENCE, NO EVENT
  const removeEvent = p.op === 'remove' ? (anyRemovalFailed ? 'lateral.remove-failed' : 'lateral.removed') : null;
  const finalEvent = event || removeEvent;
  if (!finalEvent) return null;
  return {
    event: finalEvent,
    fields: {
      op: p.op, state: String(p.state || 'unknown'), pid: p.pid ?? null, names,
      escalated: finalEvent === 'lateral.remove-failed',
    },
  };
}

// The engagement-end sweep over the channel's audit stream: 'clean' ONLY when every
// lateral exec (per agent + name handle) left ZERO unverified artifacts, or was later
// closed by a verified removal / clean sweep. Anything else keeps the engagement
// UNCLEAN. Pure: pass the collected onEvent objects in order.
export function assessLateralClean(events) {
  const open = new Map(); // agentId|name -> { agentId, name, adapter, target, escalated }
  const closed = [];
  const key = (agentId, name) => String(agentId) + '|' + String(name || '');
  for (const e of events || []) {
    if (!e || typeof e !== 'object') continue;
    if (e.type === 'lateral.ran' && e.names) {
      for (const [n, t] of Object.entries(e.names)) {
        if (!t) continue;
        const unverified = (t.artifacts || []).some((a) => a && a.kind !== 'share' && a.removalVerified !== true);
        if (t.state === 'ran' && unverified) open.set(key(e.agentId, n), { agentId: e.agentId, name: n, adapter: t.adapter || null, target: t.target || null, escalated: true });
        else if (t.state === 'removal-failed') open.set(key(e.agentId, n), { agentId: e.agentId, name: n, adapter: t.adapter || null, target: t.target || null, escalated: true });
        else if (t.state === 'ran') closed.push({ agentId: e.agentId, name: n, via: 'verified-autoclean' });
        // refused-clobber / failed-with-nothing-created open nothing
      }
    } else if ((e.type === 'lateral.removed' || e.type === 'lateral.remove-failed') && e.names) {
      for (const [n, t] of Object.entries(e.names)) {
        if (!t) continue;
        const k = key(e.agentId, n);
        if (e.type === 'lateral.removed') {
          if (open.delete(k)) closed.push({ agentId: e.agentId, name: n });
          else closed.push({ agentId: e.agentId, name: n, untracked: true });
        } else {
          const rec = open.get(k) || { agentId: e.agentId, name: n, adapter: t.adapter || null, target: t.target || null };
          rec.escalated = true;
          open.set(k, rec);
        }
      }
    } else if (e.type === 'lateral.status' && e.clean === true) {
      for (const [k, rec] of [...open.entries()]) if (rec.agentId === e.agentId) { open.delete(k); closed.push({ ...rec, via: 'sweep' }); }
    } else if (e.type === 'lateral.status' && e.clean === false && Array.isArray(e.open)) {
      for (const t of e.open) {
        if (!t) continue;
        open.set(key(e.agentId, t.name), { agentId: e.agentId, name: t.name || null, adapter: t.adapter || null, target: t.target || null, escalated: true });
      }
    }
  }
  const openList = [...open.values()];
  return {
    clean: openList.length === 0,
    open: openList,
    closed,
    note: openList.length === 0
      ? 'no unverified lateral artifacts remain — the engagement MAY be called clean'
      : openList.length + ' lateral execution(s) left artifacts present or removal-unverified — the engagement CANNOT be called clean (lateral-remove + lateral-status until this set is empty)',
  };
}

// The graph hand-off: normalize a lateral.ran event's per-name fields into the item
// engine/graphquery.mjs ingests (source host -> target host 'reachable-via' edges).
export function lateralGraphItems(name, fields, srcHost) {
  return {
    srcHost: srcHost || null,
    target: fields.target || null,
    adapter: fields.adapter || null,
    ok: fields.state === 'ran',
    exitCode: typeof fields.exitCode === 'number' ? fields.exitCode : null,
  };
}
