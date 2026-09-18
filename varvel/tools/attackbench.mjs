// VARVEL — attackbench: the ATT&CK coverage benchmark harness (the offline half of the
// lab-validation track, research/SOTA-VALIDATION-2026-08-25.md §3.2/§4). This is the
// fs-backed shell over engine/attackbench.mjs (PURE): it reads the local data files
// (data/attackbench/techniques.json — the §2.5 priority matrix; data/attackbench/map.json
// — the capability map), injects the REPO-ANCHORED fileExists the honesty gate needs,
// and returns the report / layer / map views.
//
// HARD RULES:
//   1. ZERO NETWORK. The catalog ships local by design — no STIX/TAXII, no fetch, no
//      URL anywhere in this file. The benchmark scope is a reviewed data file.
//   2. HONESTY GATE: a map entry claims 'capability exists' only when its modules exist
//      on disk IN THIS REPO (validateMap checks each via the injected fileExists); a
//      nonexistent module fails loudly ('invalid-map' naming entry + module). Planned
//      entries carry no modules and a documented basis. test/attackbench.test.mjs pins
//      the gate against the real files.
//   3. LOUD REFUSALS, never guessed data: an unreadable/malformed catalog or map is a
//      NAMED error ('unreadable-catalog' | 'invalid-catalog' | 'unreadable-map' |
//      'invalid-map') — a benchmark run on a guessed scope is a fabricated benchmark.
//   4. NON-CLAIM: every output carries the doctrine + non-claim (NOT MITRE-affiliated,
//      NOT 'MITRE-tested'; capability, never detection) — engine/attackbench.mjs
//      DOCTRINE / NONCLAIM, unchanged here.

import { readFileSync, existsSync } from 'node:fs';
import { join, dirname, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateCatalog, validateMap, buildReport, buildLayer, DOCTRINE, NONCLAIM } from '../engine/attackbench.mjs';

const __dir = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dir, '..');

// Data root: varvel/data/attackbench (the h1watch/commitwatch ROOT() discipline),
// evaluated at call time so tests isolate via VARVEL_ATTACKBENCH_DIR.
const ROOT = () => process.env.VARVEL_ATTACKBENCH_DIR || join(REPO_ROOT, 'data', 'attackbench');
const CATALOG_FILE = () => join(ROOT(), 'techniques.json');
const MAP_FILE = () => join(ROOT(), 'map.json');

// The injected honesty-gate check: repo-relative path -> exists on disk INSIDE the repo.
// The engine's MODULE_PATH_RE already refuses traversal/absolute forms; this resolves
// defensively and confirms containment anyway (the gate checks the repo, nowhere else).
export function repoFileExists(repoRel) {
  const p = resolve(REPO_ROOT, String(repoRel));
  if (p !== REPO_ROOT && !p.startsWith(REPO_ROOT.endsWith(sep) ? REPO_ROOT : REPO_ROOT + sep)) return false;
  return existsSync(p);
}

const readJson = (p) => { try { return { ok: true, json: JSON.parse(readFileSync(p, 'utf8')) }; } catch (e) { return { ok: false, reason: `cannot read/parse ${p}: ${(e && e.message) || e}` }; } };
const iso = (now) => (now === undefined ? new Date().toISOString() : (typeof now === 'number' ? new Date(now).toISOString() : String(now)));

// loadCatalog(file) -> { ok, file, techniques, meta } | { ok:false, error, reason|errors }
export function loadCatalog(file) {
  const p = file || CATALOG_FILE();
  const r = readJson(p);
  if (!r.ok) return { ok: false, error: 'unreadable-catalog', reason: `${r.reason} — the benchmark scope is data-driven and LOCAL; restore ${p} or pass --catalog <file>`, doctrine: DOCTRINE, nonClaim: NONCLAIM };
  const v = validateCatalog(r.json);
  if (!v.ok) return { ok: false, error: 'invalid-catalog', file: p, errors: v.errors, doctrine: DOCTRINE, nonClaim: NONCLAIM };
  return { ok: true, file: p, techniques: v.techniques, meta: v.meta };
}

// loadMap(file, { catalogIds }) -> { ok, file, entries, meta } | named error.
// catalogIds come from the validated catalog so in-catalog vs out-of-catalog is computed
// against the REAL scope, never a hand-maintained copy.
export function loadMap(file, { catalogIds = [] } = {}) {
  const p = file || MAP_FILE();
  const r = readJson(p);
  if (!r.ok) return { ok: false, error: 'unreadable-map', reason: `${r.reason} — the capability map is data-driven and LOCAL; restore ${p} or pass --map <file>`, doctrine: DOCTRINE, nonClaim: NONCLAIM };
  const v = validateMap(r.json, { catalogIds, fileExists: repoFileExists });
  if (!v.ok) return { ok: false, error: 'invalid-map', file: p, errors: v.errors, entries: v.entries, doctrine: DOCTRINE, nonClaim: NONCLAIM };
  return { ok: true, file: p, entries: v.entries, meta: v.meta };
}

// loadBoth({ catalogFile, mapFile }) — the shared front half of every view: catalog
// first (the scope), then the map validated against it + the repo's real files.
export function loadBoth({ catalogFile, mapFile } = {}) {
  const cat = loadCatalog(catalogFile);
  if (!cat.ok) return cat;
  const map = loadMap(mapFile, { catalogIds: cat.techniques.map((t) => t.id) });
  if (!map.ok) return map;
  return { ok: true, catalog: cat, map };
}

// report({ catalogFile, mapFile, now }) — the coverage view: mapped vs planned-only vs
// gap over the priority catalog, the per-tactic rollup, the gap list with each ID's
// priority basis, and the out-of-catalog surface (mapped honestly, counted nowhere).
export function report({ catalogFile, mapFile, now } = {}) {
  const both = loadBoth({ catalogFile, mapFile });
  if (!both.ok) return both;
  return buildReport({
    catalog: both.catalog,
    map: both.map,
    at: iso(now),
    files: { catalog: both.catalog.file, map: both.map.file },
  });
}

// layer({ catalogFile, mapFile, now, name }) — the Navigator-compatible layer JSON.
// Returned as data (the CLI prints it; --out writes it) — this module writes nothing.
export function layer({ catalogFile, mapFile, now, name } = {}) {
  const both = loadBoth({ catalogFile, mapFile });
  if (!both.ok) return both;
  const lay = buildLayer({ catalog: both.catalog, map: both.map, at: iso(now), name });
  return { ok: true, layer: lay, doctrine: DOCTRINE, nonClaim: NONCLAIM };
}

// mapView({ catalogFile, mapFile }) — the capability map itself, post-validation: every
// entry with its status, modules, techniques (in-catalog flagged), and the honest note.
export function mapView({ catalogFile, mapFile } = {}) {
  const both = loadBoth({ catalogFile, mapFile });
  if (!both.ok) return both;
  return {
    ok: true,
    file: both.map.file,
    entries: both.map.entries,
    exists: both.map.entries.filter((e) => e.status === 'exists').length,
    planned: both.map.entries.filter((e) => e.status === 'planned').length,
    scopeNote: (both.map.meta && both.map.meta.scopeNote) || null,
    doctrine: DOCTRINE,
    nonClaim: NONCLAIM,
  };
}
