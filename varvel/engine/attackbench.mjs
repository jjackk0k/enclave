// VARVEL — attackbench ENGINE: the ATT&CK coverage benchmark harness (the offline half
// of the lab-validation track, research/SOTA-VALIDATION-2026-08-25.md §3.2/§4). Three
// jobs, all offline, all honest:
//   1. VALIDATE the local technique catalog (data/attackbench/techniques.json — the §2.5
//      priority matrix, 24 IDs) and the capability map (data/attackbench/map.json).
//   2. COMPUTE coverage: which priority technique IDs have EXISTING emulation capability,
//      which have only a documented PLAN, and which are GAPS — plus the per-tactic rollup.
//   3. EXPORT a Navigator-compatible layer JSON ({techniques:[{techniqueID, score,
//      comment}], ...}) so the coverage map renders in ATT&CK Navigator later.
//
// PURE MODULE: no fs, no network, no import-time side effects — the tools wrapper
// (tools/attackbench.mjs) reads the data files and injects fileExists(). The catalog
// ships LOCAL by design: no STIX/TAXII fetch, ever (the benchmark scope is a reviewed
// data file, not a live pull).
//
// THE HONESTY GATE (the whole point): a map entry claims 'capability exists' ONLY when
// the code exists — every module path in a status:'exists' entry is checked against the
// real filesystem by the injected fileExists; a nonexistent module FAILS validation
// loudly. A status:'planned' entry carries NO modules and a `basis` naming where the
// plan is documented (docs/NATIVE.md etc.) — a planned capability claims no code.
// A capability map that overstates is worse than none; this engine refuses to build one.
//
// THE NON-CLAIM (carried on every output — the doc's §4 item 4, applied to ourselves):
//   coverage here is EMULATION CAPABILITY (VARVEL can produce the behavior on the
//   governed range), never a detection result, and never a MITRE claim: VARVEL is not
//   affiliated with, endorsed by, or tested by MITRE, and nothing here is
//   'MITRE-tested'. Detection evidence is the lab-execution track (doc §3.3) — a
//   separate, operator-decided phase this harness only scaffolds.
//
// SCORE SEMANTICS in the layer export: 1 = capability exists; 0 = planned or gap.
// Scores record CAPABILITY, never detection outcomes — the layer says so in its
// description, legend, and metadata, so a screenshot can never be misread as a
// detection claim.

// --- THE CONSTANTS --------------------------------------------------------------------------
export const DOCTRINE = 'coverage maps are honest capability statements, not detection claims — a technique is mapped only where code exists, planned only where a build is documented, else a named gap.';
export const NONCLAIM = "VARVEL is NOT affiliated with, endorsed by, or tested by MITRE; this is a private benchmark scope and nothing here is or may be called 'MITRE-tested'. ATT&CK technique IDs/tactic names are used as the industry-standard vocabulary only.";
export const CATALOG_CAVEAT = "catalog IDs are the standard ATT&CK mappings of the documented behaviors (SOTA-VALIDATION §2.5), NOT lifted verbatim from each advisory's own ATT&CK table — per-advisory verification against the advisory PDFs is an OPERATOR STEP before any published coverage claim.";

// The 14 Enterprise tactic shortnames (Navigator's own vocabulary) — a catalog entry
// carrying anything else fails validation (a typo'd tactic silently corrupts the rollup).
export const TACTICS = [
  'reconnaissance', 'resource-development', 'initial-access', 'execution', 'persistence',
  'privilege-escalation', 'defense-evasion', 'credential-access', 'discovery',
  'lateral-movement', 'collection', 'command-and-control', 'exfiltration', 'impact',
];

export const TECHNIQUE_ID_RE = /^T\d{4}(\.\d{3})?$/;
export const MAP_STATUS = ['exists', 'planned'];

// Layer palette (also the legend): green exists / amber planned / red gap.
export const LAYER_COLORS = { exists: '#7ee787', planned: '#f5d76b', gap: '#e06c75' };

// --- small pure helpers -----------------------------------------------------------------------
const isObj = (x) => !!x && typeof x === 'object' && !Array.isArray(x);
const isNonEmptyStr = (x) => typeof x === 'string' && x.trim().length > 0;
// Repo-relative path discipline for map modules: forward slashes, no traversal, no
// absolute/drive forms — the honesty gate checks paths INSIDE the repo, nowhere else.
const MODULE_PATH_RE = /^(?!\/)(?!.{0,2}:)[\w./-]+$/;

// --- CATALOG VALIDATION -------------------------------------------------------------------------
// validateCatalog(raw) -> { ok, error?, errors, techniques, meta }
// Shape: { "techniques": [...] } or a bare array. Each technique: id (T####[.###]), name,
// tactics (⊆ TACTICS, non-empty), why, sources (optional, strings). Duplicate IDs and an
// empty catalog FAIL — a benchmark with a guessed/empty scope is not a benchmark.
export function validateCatalog(raw) {
  const errors = [];
  const list = Array.isArray(raw) ? raw : (isObj(raw) && Array.isArray(raw.techniques) ? raw.techniques : null);
  const meta = isObj(raw) && isObj(raw._attackbench) ? raw._attackbench : null;
  if (!list) return { ok: false, error: 'invalid-catalog', errors: ['catalog is not a technique array ({ "techniques": [...] } or [...]) — the benchmark scope was not guessed'], techniques: [], meta };
  const seen = new Set();
  const techniques = [];
  for (const [i, t] of list.entries()) {
    const where = `techniques[${i}]`;
    if (!isObj(t)) { errors.push(`${where}: not an object — skipped entries are never invented`); continue; }
    if (!isNonEmptyStr(t.id) || !TECHNIQUE_ID_RE.test(t.id)) { errors.push(`${where}: id ${JSON.stringify(t.id)} is not a well-formed ATT&CK technique id (T#### or T####.###)`); continue; }
    if (seen.has(t.id)) { errors.push(`${where}: duplicate id ${t.id} — one entry per technique id`); continue; }
    seen.add(t.id);
    if (!isNonEmptyStr(t.name)) errors.push(`${where} (${t.id}): name is required (the ATT&CK technique name)`);
    if (!Array.isArray(t.tactics) || !t.tactics.length) errors.push(`${where} (${t.id}): tactics must be a non-empty array of tactic shortnames`);
    else for (const tac of t.tactics) if (!TACTICS.includes(tac)) errors.push(`${where} (${t.id}): unknown tactic ${JSON.stringify(tac)} — valid: ${TACTICS.join(', ')}`);
    if (!isNonEmptyStr(t.why)) errors.push(`${where} (${t.id}): why is required (the priority basis from the source matrix)`);
    if (t.sources !== undefined && !(Array.isArray(t.sources) && t.sources.every(isNonEmptyStr))) errors.push(`${where} (${t.id}): sources, when present, must be non-empty strings`);
    techniques.push({
      id: t.id,
      name: String(t.name || ''),
      tactics: Array.isArray(t.tactics) ? t.tactics.filter((x) => TACTICS.includes(x)) : [],
      why: String(t.why || ''),
      sources: Array.isArray(t.sources) ? t.sources.filter(isNonEmptyStr) : [],
    });
  }
  if (!techniques.length) errors.push('the catalog names ZERO usable techniques — an empty scope measures nothing; refusing');
  return errors.length ? { ok: false, error: 'invalid-catalog', errors, techniques, meta } : { ok: true, errors: [], techniques, meta };
}

// --- MAP VALIDATION (the honesty gate) ----------------------------------------------------------
// validateMap(raw, { catalogIds, fileExists }) -> { ok, error?, errors, entries, meta }
// fileExists(repoRelPath) -> boolean is INJECTED by the caller and REQUIRED: without it
// the honesty gate cannot run, so validation REFUSES rather than trusting module paths.
//   status 'exists'  — >=1 module, every module a repo-relative path that fileExists()
//                      confirms; a nonexistent module is a loud error naming both.
//   status 'planned' — ZERO modules (a planned capability claims no code) plus a basis
//                      naming where the plan is documented.
// Techniques: well-formed ids, non-empty per entry. Ids OUTSIDE the catalog are allowed
// (the platform's surface is wider than the benchmark scope) — coverage() reports them
// as out-of-catalog, never as catalog coverage.
export function validateMap(raw, { catalogIds = [], fileExists } = {}) {
  const errors = [];
  const meta = isObj(raw) && isObj(raw._attackbenchMap) ? raw._attackbenchMap : null;
  if (typeof fileExists !== 'function') {
    return { ok: false, error: 'invalid-map', errors: ['validateMap needs an injected fileExists(repoRelPath) — the honesty gate (modules exist on disk) cannot run without it; refusing to trust paths blindly'], entries: [], meta };
  }
  const list = Array.isArray(raw) ? raw : (isObj(raw) && Array.isArray(raw.capabilities) ? raw.capabilities : null);
  if (!list) return { ok: false, error: 'invalid-map', errors: ['map is not a capability array ({ "capabilities": [...] } or [...]) — the capability map was not guessed'], entries: [], meta };
  const catalogSet = new Set(catalogIds);
  const seen = new Set();
  const entries = [];
  for (const [i, e] of list.entries()) {
    const where = `capabilities[${i}]`;
    if (!isObj(e)) { errors.push(`${where}: not an object`); continue; }
    const id = isNonEmptyStr(e.id) ? e.id : null;
    if (!id) { errors.push(`${where}: id is required`); continue; }
    const at = `${where} ('${id}')`;
    if (seen.has(id)) { errors.push(`${at}: duplicate capability id`); continue; }
    seen.add(id);
    if (!isNonEmptyStr(e.title)) errors.push(`${at}: title is required`);
    if (!MAP_STATUS.includes(e.status)) { errors.push(`${at}: status ${JSON.stringify(e.status)} is not one of ${MAP_STATUS.join(' | ')} — a capability either exists in code or is honestly planned`); continue; }
    if (!Array.isArray(e.techniques) || !e.techniques.length) errors.push(`${at}: techniques must be a non-empty array of ATT&CK ids the capability maps to`);
    else for (const tid of e.techniques) if (!isNonEmptyStr(tid) || !TECHNIQUE_ID_RE.test(tid)) errors.push(`${at}: technique ${JSON.stringify(tid)} is not a well-formed ATT&CK id`);
    if (!isNonEmptyStr(e.note)) errors.push(`${at}: note is required — every claim carries its honest scope`);
    const modules = e.modules === undefined ? [] : e.modules;
    if (!Array.isArray(modules) || !modules.every(isNonEmptyStr)) { errors.push(`${at}: modules, when present, must be non-empty path strings`); continue; }
    for (const m of modules) {
      if (!MODULE_PATH_RE.test(m) || m.includes('..')) errors.push(`${at}: module ${JSON.stringify(m)} is not a repo-relative path (forward slashes, no '..', no absolute/drive forms)`);
    }
    if (e.status === 'exists') {
      if (!modules.length) errors.push(`${at}: status 'exists' requires >=1 module — a capability that names no code claims nothing`);
      for (const m of modules) {
        if (MODULE_PATH_RE.test(m) && !m.includes('..') && !fileExists(m)) {
          errors.push(`${at}: module '${m}' does NOT EXIST on disk — the honesty gate: an 'exists' entry may only claim code that exists (fix the path or mark the entry 'planned')`);
        }
      }
    } else { // planned
      if (modules.length) errors.push(`${at}: status 'planned' carries NO modules — a planned capability claims no code (move existing paths to an 'exists' entry or drop them)`);
      if (!isNonEmptyStr(e.basis)) errors.push(`${at}: status 'planned' requires a basis naming WHERE the plan is documented (file/section) — undocumented plans are wishes, not plans`);
    }
    entries.push({
      id,
      title: String(e.title || ''),
      status: e.status,
      modules: modules.filter((m) => MODULE_PATH_RE.test(m) && !m.includes('..')),
      techniques: (Array.isArray(e.techniques) ? e.techniques : []).filter((t) => isNonEmptyStr(t) && TECHNIQUE_ID_RE.test(t)),
      inCatalog: (Array.isArray(e.techniques) ? e.techniques : []).filter((t) => catalogSet.has(t)),
      note: String(e.note || ''),
      ...(isNonEmptyStr(e.basis) ? { basis: e.basis } : {}),
    });
  }
  if (!entries.length) errors.push('the map names ZERO usable capabilities — an empty map covers nothing; refusing');
  return errors.length ? { ok: false, error: 'invalid-map', errors, entries, meta } : { ok: true, errors: [], entries, meta };
}

// --- COVERAGE -------------------------------------------------------------------------------------
// coverage(techniques, entries) -> the honest mapped/planned/gap split over the catalog.
//   mapped:      catalog ids with >=1 'exists' capability
//   plannedOnly: catalog ids with ONLY 'planned' capabilities (claims nothing today)
//   gaps:        catalog ids with NEITHER — the priority behaviors nobody can emulate
//   byTactic:    per-tactic rollup in TACTICS order (a multi-tactic technique counts in
//                each of its tactics — documented, never summed across tactics)
//   outOfCatalog: map techniques beyond the benchmark scope, named with their entries
export function coverage(techniques, entries) {
  const existsBy = new Map();
  const plannedBy = new Map();
  const out = new Map(); // technique -> { entries: [ids], statuses: Set }
  const catalogSet = new Set(techniques.map((t) => t.id));
  for (const e of entries || []) {
    for (const tid of e.techniques || []) {
      if (catalogSet.has(tid)) {
        const bucket = e.status === 'exists' ? existsBy : plannedBy;
        if (!bucket.has(tid)) bucket.set(tid, []);
        bucket.get(tid).push(e.id);
      } else {
        if (!out.has(tid)) out.set(tid, { technique: tid, entries: [], statuses: new Set() });
        out.get(tid).entries.push(e.id);
        out.get(tid).statuses.add(e.status);
      }
    }
  }
  const mapped = [];
  const plannedOnly = [];
  const gaps = [];
  for (const t of techniques || []) {
    if (existsBy.has(t.id)) mapped.push({ id: t.id, name: t.name, entries: existsBy.get(t.id) });
    else if (plannedBy.has(t.id)) plannedOnly.push({ id: t.id, name: t.name, entries: plannedBy.get(t.id) });
    else gaps.push(t);
  }
  const byTactic = [];
  for (const tactic of TACTICS) {
    const inTac = (techniques || []).filter((t) => (t.tactics || []).includes(tactic));
    if (!inTac.length) continue;
    byTactic.push({
      tactic,
      total: inTac.length,
      mapped: inTac.filter((t) => existsBy.has(t.id)).length,
      plannedOnly: inTac.filter((t) => !existsBy.has(t.id) && plannedBy.has(t.id)).length,
      gaps: inTac.filter((t) => !existsBy.has(t.id) && !plannedBy.has(t.id)).map((t) => t.id),
    });
  }
  const outOfCatalog = [...out.values()]
    .map((o) => ({ technique: o.technique, entries: o.entries, statuses: [...o.statuses].sort() }))
    .sort((a, b) => a.technique.localeCompare(b.technique));
  return {
    total: (techniques || []).length,
    mappedCount: mapped.length,
    plannedOnlyCount: plannedOnly.length,
    gapCount: gaps.length,
    mapped,
    plannedOnly,
    gaps,
    byTactic,
    outOfCatalog,
  };
}

// --- THE REPORT -------------------------------------------------------------------------------------
// buildReport({ catalog, map, at, files }) — the coverage view + gap list, ready to print.
// catalog/map are the VALIDATED results ({ techniques, meta } / { entries, meta }).
export function buildReport({ catalog, map, at = null, files = {} } = {}) {
  const cov = coverage(catalog.techniques, map.entries);
  return {
    ok: true,
    at,
    scope: {
      file: files.catalog || null,
      techniques: cov.total,
      source: (catalog.meta && catalog.meta.source) || null,
      caveat: (catalog.meta && catalog.meta.caveat) || CATALOG_CAVEAT,
    },
    capabilities: {
      file: files.map || null,
      entries: map.entries.length,
      exists: map.entries.filter((e) => e.status === 'exists').length,
      planned: map.entries.filter((e) => e.status === 'planned').length,
    },
    coverage: {
      total: cov.total,
      mapped: cov.mappedCount,
      plannedOnly: cov.plannedOnlyCount,
      gaps: cov.gapCount,
      mappedIds: cov.mapped.map((m) => m.id),
      plannedOnlyIds: cov.plannedOnly.map((m) => m.id),
      gapIds: cov.gaps.map((g) => g.id),
      byTactic: cov.byTactic,
    },
    mapped: cov.mapped,
    planned: cov.plannedOnly,
    gapList: cov.gaps.map((g) => ({ id: g.id, name: g.name, tactics: g.tactics, why: g.why, sources: g.sources })),
    outOfCatalog: cov.outOfCatalog,
    doctrine: DOCTRINE,
    nonClaim: NONCLAIM,
  };
}

// --- THE NAVIGATOR LAYER EXPORT ---------------------------------------------------------------------
// buildLayer({ catalog, map, at, name }) — an ATT&CK Navigator-compatible layer JSON
// (the standard { techniques: [{ techniqueID, score, comment, ... }], ... } shape).
// EVERY catalog id appears exactly once: exists -> score 1 (green), planned-only ->
// score 0 (amber), gap -> score 0 (red). Scores record CAPABILITY, never detection —
// the description/legend/metadata say so, so the export can never be misread as a
// detection result or a MITRE artifact.
export function buildLayer({ catalog, map, at = null, name } = {}) {
  const cov = coverage(catalog.techniques, map.entries);
  const entryBy = new Map();
  for (const e of map.entries || []) for (const tid of e.techniques || []) {
    if (!entryBy.has(tid)) entryBy.set(tid, []);
    entryBy.get(tid).push(e);
  }
  const techniques = (catalog.techniques || []).map((t) => {
    const exists = (entryBy.get(t.id) || []).filter((e) => e.status === 'exists');
    const planned = (entryBy.get(t.id) || []).filter((e) => e.status === 'planned');
    let score; let color; let comment;
    if (exists.length) {
      score = 1; color = LAYER_COLORS.exists;
      const mods = [...new Set(exists.flatMap((e) => e.modules))];
      comment = `EMULATION CAPABILITY EXISTS — ${exists.map((e) => `${e.id} (${e.title})`).join('; ')}. Modules: ${mods.join(', ')}. Priority basis: ${t.why}.`;
    } else if (planned.length) {
      score = 0; color = LAYER_COLORS.planned;
      comment = `PLANNED — not built, claims nothing today: ${planned.map((e) => e.id).join('; ')}. Basis: ${(planned[0].basis || '').slice(0, 220)}`;
    } else {
      score = 0; color = LAYER_COLORS.gap;
      comment = `GAP — no VARVEL capability emulates this behavior (benchmark scope v1${at ? ', ' + String(at).slice(0, 10) : ''}). Priority basis: ${t.why}${t.sources && t.sources.length ? ` [${t.sources.join('; ')}]` : ''}.`;
    }
    return { techniqueID: t.id, score, color, comment, enabled: true, metadata: [], links: [], showSubtechniques: false };
  });
  return {
    name: name || 'VARVEL attackbench — emulation capability coverage (benchmark scope v1)',
    versions: { layer: '4.5', navigator: '4.8.0' },
    domain: 'enterprise-attack',
    description: `Honest EMULATION-CAPABILITY coverage of VARVEL's benchmark scope v1 (SOTA-VALIDATION-2026-08-25 §2.5, ${cov.total} technique ids): score 1 = capability exists in code (modules named per technique), score 0 = planned (amber) or gap (red). Scores record CAPABILITY, never detection outcomes — detection evidence is the separate lab-execution track. ${NONCLAIM} ${(catalog.meta && catalog.meta.caveat) || CATALOG_CAVEAT}`,
    techniques,
    gradient: { colors: [LAYER_COLORS.gap, LAYER_COLORS.planned, LAYER_COLORS.exists], minValue: 0, maxValue: 1 },
    legendItems: [
      { label: 'emulation capability EXISTS (code-grounded; modules named in the comment)', color: LAYER_COLORS.exists },
      { label: 'PLANNED — a documented build, no code today (claims nothing)', color: LAYER_COLORS.planned },
      { label: 'GAP — no VARVEL capability emulates this behavior', color: LAYER_COLORS.gap },
    ],
    metadata: [
      { name: 'generated-by', value: `varvel attackbench (offline harness)${at ? ' at ' + at : ''}` },
      { name: 'score-semantics', value: '1 = emulation capability exists; 0 = planned or gap. CAPABILITY, never detection outcomes.' },
      { name: 'non-claim', value: NONCLAIM },
      { name: 'attack-version', value: 'unpinned (offline build) — Navigator loads the layer against its current ATT&CK; ids/names come from the §2.5 matrix and carry the per-advisory verification caveat' },
      { name: 'coverage', value: `${cov.mappedCount} mapped / ${cov.plannedOnlyCount} planned-only / ${cov.gapCount} gaps of ${cov.total}` },
    ],
    showTacticRowBackground: false,
  };
}
