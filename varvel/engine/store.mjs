// VARVEL — cross-session engagement memory (file-backed).
// Persists per-engagement surface snapshots AND an accumulating findings ledger so
// engagement knowledge survives across sessions. Keys are collision-safe: distinct
// raw engagement names map to distinct files (a short hash disambiguates names that
// would otherwise sanitize to the same string), preventing cross-engagement bleed.
//
// NOTE: the tamper-evident AUDIT is the Enclave's responsibility, not VARVEL's — so
// there is deliberately no audit persistence here.

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createHash } from 'node:crypto';

const __dir = dirname(fileURLToPath(import.meta.url));
// Stable per-install data dir by default (cross-session memory must survive restarts);
// overridable via VARVEL_DATA_DIR so parallel test processes get isolated storage.
// Evaluated at call time so a test can set the env var before the first store call.
export const dataDir = () => process.env.VARVEL_DATA_DIR || join(__dir, '..', '.data');
const ensure = () => { const DIR = dataDir(); if (!existsSync(DIR)) mkdirSync(DIR, { recursive: true }); return DIR; };
const key = (s) => String(s || 'engagement').replace(/[^a-z0-9._-]/gi, '_').slice(0, 40) + '-' + createHash('sha1').update(String(s || 'engagement')).digest('hex').slice(0, 8);
const readJson = (p, fb) => { try { return existsSync(p) ? JSON.parse(readFileSync(p, 'utf8')) : fb; } catch { return fb; } };

export function saveSurface(engagement, surfaceJSON) {
  const DIR = ensure();
  const p = join(DIR, key(engagement) + '.surface.json');
  writeFileSync(p, JSON.stringify(surfaceJSON, null, 2));
  return p;
}

export function loadSurface(engagement) {
  return readJson(join(dataDir(), key(engagement) + '.surface.json'), null);
}

// Accumulating findings ledger: deduped by (ref|label), persists across runs so a
// new session inherits ALL prior findings (the per-session surface snapshot does not).
export function priorFindings(engagement) {
  return readJson(join(dataDir(), key(engagement) + '.findings.json'), []);
}

export function recordFindings(engagement, findings) {
  const DIR = ensure();
  const p = join(DIR, key(engagement) + '.findings.json');
  const acc = readJson(p, []);
  const seen = new Set(acc.map((f) => (f.ref || '') + '|' + (f.label || '')));
  for (const f of Array.isArray(findings) ? findings : []) {
    if (!f) continue;
    const k = (f.ref || '') + '|' + (f.label || '');
    if (!seen.has(k)) { seen.add(k); acc.push({ label: f.label, sev: f.sev, ref: f.ref }); }
  }
  writeFileSync(p, JSON.stringify(acc, null, 2));
  return acc;
}

// Failure ledger (EvoGraph-class): the approaches that did NOT work — held actions,
// failed exploits, dead-end phases. A new session inherits these so it does not repeat
// what already failed. Deduped by (phase|approach); capped so it can't grow unbounded.
export function priorFailures(engagement) {
  return readJson(join(dataDir(), key(engagement) + '.failures.json'), []);
}

export function recordFailures(engagement, failures) {
  const DIR = ensure();
  const p = join(DIR, key(engagement) + '.failures.json');
  const acc = readJson(p, []);
  const norm = (f) => (f.phase || '') + '|' + String(f.approach || f.note || '').trim().toLowerCase().slice(0, 160);
  const seen = new Set(acc.map(norm));
  for (const f of Array.isArray(failures) ? failures : []) {
    if (!f || !(f.approach || f.note)) continue;
    const k = norm(f);
    if (!seen.has(k)) { seen.add(k); acc.push({ phase: f.phase || null, kind: f.kind || 'failure', approach: String(f.approach || f.note).slice(0, 200), at: f.at || null }); }
  }
  const capped = acc.slice(-100); // keep the most recent lessons
  writeFileSync(p, JSON.stringify(capped, null, 2));
  return capped;
}
