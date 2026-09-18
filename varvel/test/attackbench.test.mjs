// VARVEL attackbench tests — the ATT&CK coverage benchmark harness (engine/attackbench.mjs
// + tools/attackbench.mjs + data/attackbench/{techniques,map}.json). Hermetic: ZERO
// network anywhere (the harness ships a LOCAL catalog by design — no STIX/TAXII). The
// doctrines under test: catalog validation (shape, id format, tactic vocabulary, dup
// detection, empty-scope refusal), THE HONESTY GATE (an 'exists' map entry pointing at a
// nonexistent module FAILS loudly; 'planned' carries no modules + a documented basis;
// validateMap refuses to run without an injected fileExists), the coverage math (mapped
// / planned-only / gap / per-tactic rollup / out-of-catalog), the Navigator layer shape
// (every catalog id exactly once, capability-not-detection score semantics, legend +
// metadata), the shipped data files validating against the REAL repo files (the gate
// against reality), the CLI surface (report|layer|map, --out, loud refusals), and the
// static pins: the engine is PURE, the wrapper never fetches, and every artifact carries
// the non-claim (NOT MITRE-affiliated, never 'MITRE-tested').
//   node --test test/attackbench.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const __dir = dirname(fileURLToPath(import.meta.url));
const CLI = join(__dir, '..', 'tools', 'cli.mjs');
const FIXTURE = (n) => join(__dir, 'fixtures', n);
const DATA = (n) => join(__dir, '..', 'data', 'attackbench', n);

const eng = await import('../engine/attackbench.mjs');
const ab = await import('../tools/attackbench.mjs');

const run = (args) => {
  const r = spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', timeout: 30000, env: { ...process.env } });
  const i = r.stdout.lastIndexOf('\n{\n');
  let out = null;
  try { out = JSON.parse(i === -1 ? r.stdout : r.stdout.slice(i + 1)); } catch { out = { parseError: r.stdout.slice(0, 400), stderr: r.stderr.slice(0, 300) }; }
  return { status: r.status, out, text: i === -1 ? '' : r.stdout.slice(0, i) };
};

const SHIPPED_MAPPED = ['T1078', 'T1003', 'T1059.001', 'T1059.003', 'T1047', 'T1087', 'T1069', 'T1018', 'T1105', 'T1090', 'T1572', 'T1190', 'T1133', 'T1550'];
const SHIPPED_GAPS = ['T1490', 'T1070', 'T1219', 'T1528', 'T1621', 'T1557', 'T1098', 'T1136', 'T1486', 'T1567.002'];

// --- catalog validation -------------------------------------------------------------------------

test('catalog: the fixture catalog validates (meta carried); shipped catalog validates 24 ids', () => {
  const fx = JSON.parse(readFileSync(FIXTURE('attackbench-catalog.json'), 'utf8'));
  const v = eng.validateCatalog(fx);
  assert.equal(v.ok, true);
  assert.equal(v.techniques.length, 4);
  assert.equal(v.meta.source, 'test fixture');
  assert.deepEqual(v.techniques[0], { id: 'T1078', name: 'Valid Accounts', tactics: ['initial-access'], why: 'fixture: legitimate creds used maliciously', sources: ['FX-001'] });

  const shipped = ab.loadCatalog(DATA('techniques.json'));
  assert.equal(shipped.ok, true, JSON.stringify(shipped.errors || []).slice(0, 400));
  assert.equal(shipped.techniques.length, 24, 'the §2.5 matrix splits to 24 distinct technique ids');
  assert.ok(shipped.meta.caveat.includes('OPERATOR STEP'), 'the per-advisory verification caveat rides the shipped catalog');
  assert.ok(new Set(shipped.techniques.map((t) => t.id)).size === 24, 'no duplicate ids');
});

test('catalog: malformed shapes fail LOUDLY with named errors; empty scope refuses', () => {
  const bad = eng.validateCatalog(JSON.parse(readFileSync(FIXTURE('attackbench-catalog-bad.json'), 'utf8')));
  assert.equal(bad.ok, false);
  assert.equal(bad.error, 'invalid-catalog');
  assert.ok(bad.errors.some((e) => /not a well-formed ATT&CK technique id/.test(e) && /T107/.test(e)), 'bad id shape named');
  assert.ok(bad.errors.some((e) => /duplicate id T1078/.test(e)), 'duplicate id named');
  assert.ok(bad.errors.some((e) => /unknown tactic "made-up-tactic"/.test(e)), 'unknown tactic named');
  assert.ok(bad.errors.some((e) => /why is required/.test(e)), 'missing why named');
  assert.ok(bad.errors.some((e) => /not an object/.test(e)), 'non-object entry named');
  assert.equal(eng.validateCatalog([]).ok, false, 'an empty array is an empty scope — refused');
  assert.equal(eng.validateCatalog({ nope: true }).ok, false, 'a non-array shape is not guessed into a scope');
  assert.equal(eng.validateCatalog(null).ok, false);
});

// --- map validation: THE HONESTY GATE ------------------------------------------------------------

test('map: validateMap REFUSES without an injected fileExists — the gate cannot be skipped', () => {
  const r = eng.validateMap({ capabilities: [{ id: 'x', title: 'x', status: 'exists', modules: ['engine/attackbench.mjs'], techniques: ['T1078'], note: 'x' }] });
  assert.equal(r.ok, false);
  assert.equal(r.error, 'invalid-map');
  assert.ok(r.errors.some((e) => /fileExists/.test(e)), 'the refusal names the missing gate input');
});

test('map: the fixture map validates with an all-true stub; in-catalog split computed from the real catalog ids', () => {
  const fx = JSON.parse(readFileSync(FIXTURE('attackbench-map.json'), 'utf8'));
  const v = eng.validateMap(fx, { catalogIds: ['T1078', 'T1003', 'T1490', 'T1105'], fileExists: () => true });
  assert.equal(v.ok, true, JSON.stringify(v.errors));
  assert.equal(v.entries.length, 3);
  assert.deepEqual(v.entries.find((e) => e.id === 'fake-creds').inCatalog.sort(), ['T1003', 'T1078']);
  assert.deepEqual(v.entries.find((e) => e.id === 'fake-channel').inCatalog, [], 'out-of-catalog techniques flagged honestly');
});

test('map: HONESTY GATE — a map entry pointing at a nonexistent module FAILS LOUDLY against the real repo', () => {
  const fx = JSON.parse(readFileSync(FIXTURE('attackbench-map-bad.json'), 'utf8'));
  const v = eng.validateMap(fx, { catalogIds: ['T1078', 'T1003'], fileExists: ab.repoFileExists });
  assert.equal(v.ok, false);
  assert.equal(v.error, 'invalid-map');
  assert.ok(v.errors.some((e) => /'ghost-entry'/.test(e) && /engine\/no-such-module\.mjs/.test(e) && /does NOT EXIST/.test(e)), 'the missing module is named with its entry');
  assert.ok(v.errors.some((e) => /'planned-with-code'/.test(e) && /planned.*carries NO modules/i.test(e)), 'a planned capability claims no code');
  assert.ok(v.errors.some((e) => /'bad-status'/.test(e) && /exists \| planned/.test(e)), 'an invented status is refused');
  assert.ok(v.errors.some((e) => /'bad-tech'/.test(e) && /TX99/.test(e)), 'a malformed technique id is refused');
  assert.ok(v.errors.some((e) => /'no-note'/.test(e) && /note is required/.test(e)), 'every claim carries its honest scope');
  assert.ok(v.errors.some((e) => /'traversal'/.test(e) && /not a repo-relative path/.test(e)), "traversal/absolute module paths are refused");
});

test('map: the SHIPPED capability map validates against the repo\'s REAL files — 23 entries, 20 exists, 3 planned', () => {
  const cat = ab.loadCatalog(DATA('techniques.json'));
  const m = ab.loadMap(DATA('map.json'), { catalogIds: cat.techniques.map((t) => t.id) });
  assert.equal(m.ok, true, JSON.stringify(m.errors || []).slice(0, 600));
  assert.equal(m.entries.length, 23);
  assert.equal(m.entries.filter((e) => e.status === 'exists').length, 20);
  assert.equal(m.entries.filter((e) => e.status === 'planned').length, 3);
  for (const e of m.entries.filter((x) => x.status === 'exists')) {
    assert.ok(e.modules.length >= 1 && e.modules.every((mod) => ab.repoFileExists(mod)), `${e.id}: every claimed module exists on disk`);
  }
  for (const e of m.entries.filter((x) => x.status === 'planned')) {
    assert.equal(e.modules.length, 0, `${e.id}: planned claims no code`);
    assert.ok(e.basis, `${e.id}: planned carries a documented basis`);
  }
});

// --- coverage math ----------------------------------------------------------------------------------

test('coverage: fixture math pinned — mapped 2, planned-only 1, gap 1, per-tactic rollup, out-of-catalog named', () => {
  const cat = eng.validateCatalog(JSON.parse(readFileSync(FIXTURE('attackbench-catalog.json'), 'utf8')));
  const map = eng.validateMap(JSON.parse(readFileSync(FIXTURE('attackbench-map.json'), 'utf8')), { catalogIds: cat.techniques.map((t) => t.id), fileExists: () => true });
  const cov = eng.coverage(cat.techniques, map.entries);
  assert.equal(cov.total, 4);
  assert.equal(cov.mappedCount, 2);
  assert.equal(cov.plannedOnlyCount, 1);
  assert.equal(cov.gapCount, 1);
  assert.deepEqual(cov.mapped.map((m) => m.id), ['T1078', 'T1003']);
  assert.deepEqual(cov.mapped[0].entries, ['fake-creds']);
  assert.deepEqual(cov.plannedOnly.map((m) => m.id), ['T1490']);
  assert.deepEqual(cov.gaps.map((g) => g.id), ['T1105'], 'T1105 has no capability — a named gap');
  assert.deepEqual(cov.byTactic, [
    { tactic: 'initial-access', total: 1, mapped: 1, plannedOnly: 0, gaps: [] },
    { tactic: 'credential-access', total: 1, mapped: 1, plannedOnly: 0, gaps: [] },
    { tactic: 'command-and-control', total: 1, mapped: 0, plannedOnly: 0, gaps: ['T1105'] },
    { tactic: 'impact', total: 1, mapped: 0, plannedOnly: 1, gaps: [] },
  ]);
  assert.deepEqual(cov.outOfCatalog, [{ technique: 'T1071.001', entries: ['fake-channel'], statuses: ['exists'] }]);
});

// --- the report (shipped data, real files) -----------------------------------------------------------

test('report: shipped catalog+map produce the honest coverage summary — 24 scope / 14 mapped / 0 planned-only / 10 gaps', () => {
  const r = ab.report({ now: '2026-08-26T00:00:00.000Z' });
  assert.equal(r.ok, true, JSON.stringify(r.errors || r.reason || '').slice(0, 400));
  assert.equal(r.coverage.total, 24);
  assert.equal(r.coverage.mapped, 14);
  assert.equal(r.coverage.plannedOnly, 0);
  assert.equal(r.coverage.gaps, 10);
  assert.deepEqual(r.coverage.mappedIds, SHIPPED_MAPPED);
  assert.deepEqual(r.coverage.gapIds, SHIPPED_GAPS);
  assert.equal(r.mapped.find((m) => m.id === 'T1003').entries.join(','), 'cred-dump-comsvcs');
  assert.ok(r.mapped.find((m) => m.id === 'T1090').entries.includes('ghost-egress'), 'ghost egress covers Proxy');
  const impact = r.coverage.byTactic.find((t) => t.tactic === 'impact');
  assert.deepEqual(impact, { tactic: 'impact', total: 2, mapped: 0, plannedOnly: 0, gaps: ['T1490', 'T1486'] });
  assert.equal(r.gapList.length, 10);
  assert.ok(r.gapList.every((g) => g.why && g.sources.length), 'every gap carries its priority basis — a gap is a finding, not silence');
  assert.ok(r.outOfCatalog.some((o) => o.technique === 'T1071.001' && o.entries.includes('channel-core')));
  assert.equal(r.doctrine, eng.DOCTRINE);
  assert.equal(r.nonClaim, eng.NONCLAIM);
  assert.equal(r.at, '2026-08-26T00:00:00.000Z');
});

// --- the Navigator layer export ------------------------------------------------------------------------

test('layer: fixture layer — every catalog id exactly once, capability-not-detection scores, PLANNED/GAP comments', () => {
  const cat = eng.validateCatalog(JSON.parse(readFileSync(FIXTURE('attackbench-catalog.json'), 'utf8')));
  const map = eng.validateMap(JSON.parse(readFileSync(FIXTURE('attackbench-map.json'), 'utf8')), { catalogIds: cat.techniques.map((t) => t.id), fileExists: () => true });
  const layer = eng.buildLayer({ catalog: cat, map, at: '2026-08-26T00:00:00.000Z' });
  assert.equal(layer.domain, 'enterprise-attack');
  assert.equal(layer.techniques.length, 4);
  assert.deepEqual([...new Set(layer.techniques.map((t) => t.techniqueID))].sort(), ['T1003', 'T1078', 'T1105', 'T1490']);
  const byId = Object.fromEntries(layer.techniques.map((t) => [t.techniqueID, t]));
  assert.equal(byId['T1078'].score, 1);
  assert.equal(byId['T1078'].color, eng.LAYER_COLORS.exists);
  assert.match(byId['T1078'].comment, /fake-creds/);
  assert.match(byId['T1078'].comment, /engine\/attackbench\.mjs/, 'the exists comment names the modules — the claim is checkable');
  assert.equal(byId['T1490'].score, 0);
  assert.equal(byId['T1490'].color, eng.LAYER_COLORS.planned);
  assert.match(byId['T1490'].comment, /PLANNED/);
  assert.match(byId['T1490'].comment, /docs\/nowhere\.md/, 'the planned comment carries the documented basis');
  assert.equal(byId['T1105'].score, 0);
  assert.equal(byId['T1105'].color, eng.LAYER_COLORS.gap);
  assert.match(byId['T1105'].comment, /GAP/);
  assert.match(byId['T1105'].comment, /fixture: LOTL downloads/, 'the gap comment carries the priority basis');
  assert.equal(layer.legendItems.length, 3);
  assert.match(layer.description, /CAPABILITY, never detection/);
  assert.match(layer.description, /NOT affiliated with, endorsed by, or tested by MITRE/);
  assert.ok(layer.metadata.some((m) => m.name === 'score-semantics' && /never detection/.test(m.value)));
  assert.ok(layer.metadata.some((m) => m.name === 'coverage' && m.value === '2 mapped / 1 planned-only / 1 gaps of 4'));
  assert.equal(layer.versions.layer, '4.5');
  assert.equal(layer.versions.attack, undefined, 'ATT&CK version stays unpinned offline — named in metadata, never guessed');
});

test('layer: shipped data exports 24 technique entries — exists/gap colors and honest comments throughout', () => {
  const r = ab.layer({ now: '2026-08-26T00:00:00.000Z' });
  assert.equal(r.ok, true);
  const layer = r.layer;
  assert.equal(layer.techniques.length, 24);
  assert.equal(new Set(layer.techniques.map((t) => t.techniqueID)).size, 24, 'every catalog id exactly once');
  const byId = Object.fromEntries(layer.techniques.map((t) => [t.techniqueID, t]));
  for (const id of SHIPPED_MAPPED) assert.equal(byId[id].score, 1, `${id} mapped`);
  for (const id of SHIPPED_GAPS) { assert.equal(byId[id].score, 0, `${id} gap`); assert.equal(byId[id].color, eng.LAYER_COLORS.gap); assert.match(byId[id].comment, /GAP/); }
  assert.match(byId['T1003'].comment, /engine\/credaccess\.mjs/);
  assert.match(byId['T1490'].comment, /GAP/);
  assert.ok(r.nonClaim.includes('MITRE-tested'), 'the non-claim rides the layer output');
});

// --- CLI ------------------------------------------------------------------------------------------------

test('CLI: report prints the coverage summary + doctrine + non-claim; JSON carries the counts', () => {
  const r = run(['attackbench', 'report']);
  assert.equal(r.status, 0, JSON.stringify(r.out).slice(0, 300));
  assert.equal(r.out.ok, true);
  assert.equal(r.out.coverage.total, 24);
  assert.equal(r.out.coverage.mapped, 14);
  assert.equal(r.out.coverage.gaps, 10);
  assert.match(r.text, /24 technique id\(s\) — 14 mapped, 0 planned-only, 10 gap/);
  assert.match(r.text, /\[GAP\] T1486 Data Encrypted for Impact/);
  assert.match(r.text, /\[mapped\] T1003 OS Credential Dumping — via cred-dump-comsvcs/);
  assert.match(r.text, /out-of-catalog surface.*T1071\.001/);
  assert.match(r.text, /NOT affiliated with, endorsed by, or tested by MITRE/);
});

test('CLI: layer prints + --out writes a parseable Navigator layer; map prints validated entries', () => {
  const dir = mkdtempSync(join(tmpdir(), 'varvel-attackbench-'));
  const outFile = join(dir, 'layer.json');
  const l = run(['attackbench', 'layer', '--out', outFile]);
  assert.equal(l.status, 0, JSON.stringify(l.out).slice(0, 300));
  assert.equal(l.out.ok, true);
  assert.equal(l.out.layer.techniques.length, 24);
  assert.match(l.text, /Navigator layer written to/);
  const written = JSON.parse(readFileSync(outFile, 'utf8'));
  assert.equal(written.domain, 'enterprise-attack');
  assert.equal(written.techniques.length, 24);
  assert.ok(Array.isArray(written.legendItems) && written.legendItems.length === 3);

  const m = run(['attackbench', 'map']);
  assert.equal(m.status, 0);
  assert.equal(m.out.entries.length, 23);
  assert.match(m.text, /23 entries \(20 exists, 3 planned\)/);
  assert.match(m.text, /\[planned\] native-stage2/);
});

test('CLI: --catalog/--map overrides pin to the fixture math (4/2/1/1)', () => {
  const r = run(['attackbench', 'report', '--catalog', FIXTURE('attackbench-catalog.json'), '--map', FIXTURE('attackbench-map.json')]);
  assert.equal(r.status, 0, JSON.stringify(r.out).slice(0, 300));
  assert.equal(r.out.coverage.total, 4);
  assert.equal(r.out.coverage.mapped, 2);
  assert.equal(r.out.coverage.plannedOnly, 1);
  assert.equal(r.out.coverage.gaps, 1);
  assert.deepEqual(r.out.coverage.gapIds, ['T1105']);
});

test('CLI: loud refusals — unknown/missing sub-command, unreadable catalog, invalid map', () => {
  const noSub = run(['attackbench']);
  assert.equal(noSub.status, 2);
  assert.match(noSub.out.error, /attackbench needs report \| layer/);
  const bogus = run(['attackbench', 'bogus']);
  assert.equal(bogus.status, 2);
  assert.match(bogus.out.error, /attackbench needs report \| layer/);
  const missing = run(['attackbench', 'report', '--catalog', FIXTURE('no-such-catalog.json')]);
  assert.equal(missing.status, 2);
  assert.equal(missing.out.error, 'unreadable-catalog');
  assert.match(missing.out.reason, /never fabricated|data-driven|LOCAL/);
  const badMap = run(['attackbench', 'report', '--catalog', FIXTURE('attackbench-catalog.json'), '--map', FIXTURE('attackbench-map-bad.json')]);
  assert.equal(badMap.status, 2);
  assert.equal(badMap.out.error, 'invalid-map');
  assert.ok(badMap.out.errors.some((e) => /engine\/no-such-module\.mjs/.test(e)), 'the honesty gate fires through the CLI too');
});

// --- static pins -------------------------------------------------------------------------------------------

test('static pin: the engine is PURE (no node: imports, no fetch) and the wrapper never touches the network', () => {
  const engineSrc = readFileSync(join(__dir, '..', 'engine', 'attackbench.mjs'), 'utf8');
  assert.ok(!/from\s*'node:/.test(engineSrc), 'the engine imports no node: modules — fs comes from the caller (fileExists is injected)');
  assert.ok(!/\bfetch\s*\(/.test(engineSrc), 'the engine never fetches');
  assert.ok(!/https?:\/\//.test(engineSrc), 'the engine carries no URLs');
  const toolsSrc = readFileSync(join(__dir, '..', 'tools', 'attackbench.mjs'), 'utf8');
  assert.ok(!/\bfetch\s*\(/.test(toolsSrc), 'the wrapper never fetches — the catalog ships local, no STIX/TAXII ever');
  assert.ok(!/from\s*'node:(https?|net|tls|dgram)'/.test(toolsSrc), 'the wrapper imports no network modules');
  assert.ok(!/https?:\/\//.test(toolsSrc), 'the wrapper carries no URLs');
});

test('static pin: every attackbench artifact carries the non-claim — never MITRE-affiliated, never MITRE-tested', () => {
  const engineSrc = readFileSync(join(__dir, '..', 'engine', 'attackbench.mjs'), 'utf8');
  assert.match(engineSrc, /NOT affiliated with, endorsed by, or tested by MITRE/);
  assert.match(engineSrc, /never a detection result|never detection/);
  for (const f of ['techniques.json', 'map.json']) {
    const data = readFileSync(DATA(f), 'utf8');
    assert.match(data, /NOT affiliated with, endorsed by, or tested by MITRE|NOT MITRE-affiliated/, `${f} carries the non-claim`);
    assert.match(data, /MITRE-tested/, `${f} names the 'MITRE-tested' non-claim explicitly`);
  }
  // And the invariant phrasing is never inverted anywhere in the new artifacts:
  for (const f of ['engine/attackbench.mjs', 'tools/attackbench.mjs']) {
    const src = readFileSync(join(__dir, '..', f), 'utf8');
    assert.ok(!/affiliated with MITRE(?!\s*[,;])/.test(src.replace(/NOT affiliated with, endorsed by, or tested by MITRE/g, '')), `${f}: no bare affiliation claim survives removing the negation`);
    assert.ok(!/MITRE[- ]tested(?![\s']*(?:status|non-claim|claim|'|\.))/.test(src.replace(/never[^.\n]*MITRE-tested/gi, '').replace(/is NOT affiliated[^.]*MITRE-tested[^.]*\./g, '')), `${f}: no positive 'MITRE-tested' claim`);
  }
});
