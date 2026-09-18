// VARVEL commitwatch tests — the WP-plugin commit-diff watcher (tools/commitwatch.mjs +
// engine/commitwatch.mjs). Hermetic: recorded fixtures + a stubbed fetchImpl for the
// gated live path — ZERO external network (the host allowlist is pinned to refuse even
// a loopback mock). The doctrines under test: the diff parser (Trac + git shapes, junk
// lands empty), the classifier bands (nonce-added = high, cap-tightened = high,
// prepare-added = med, typo-only = noise floor, removed-gate = high+public), the scan
// state machine (first sight = baseline/no backfill, rescan silent, failed fetch keeps
// state), the honesty refusals (live-not-requested / host-not-allowed / unreachable /
// unreadable targets — never fabricated data), and the never-hunts/never-submits
// static pin over BOTH module files.
//   node --test test/commitwatch.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const __dir = dirname(fileURLToPath(import.meta.url));
const CLI = join(__dir, '..', 'tools', 'cli.mjs');
const FIXTURE = (n) => join(__dir, 'fixtures', n);

// Isolate persistence (watcher state) BEFORE the module is exercised; the data-driven
// watch set rides a targets file INSIDE the isolated root (TARGETS_FILE() convention).
const ROOT = mkdtempSync(join(tmpdir(), 'varvel-commitwatch-'));
process.env.VARVEL_COMMITWATCH_DIR = ROOT;
const TARGETS = { targets: [
  { slug: 'acme-forms', note: 'test target' },
  { slug: 'cap-shops' },
  { slug: 'initech-ai' },
  { slug: 'globex-seo' },
] };
writeFileSync(join(ROOT, 'targets.json'), JSON.stringify(TARGETS, null, 2));

const eng = await import('../engine/commitwatch.mjs');
const cw = await import('../tools/commitwatch.mjs');

const T1 = '2026-08-25T00:00:00.000Z';
const T2 = '2026-08-25T01:00:00.000Z';
const T3 = '2026-08-25T02:00:00.000Z';
const run = (args) => {
  const r = spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', timeout: 30000, env: { ...process.env } });
  const i = r.stdout.lastIndexOf('\n{\n');
  let out = null;
  try { out = JSON.parse(i === -1 ? r.stdout : r.stdout.slice(i + 1)); } catch { out = { parseError: r.stdout.slice(0, 400), stderr: r.stderr.slice(0, 300) }; }
  return { status: r.status, out, text: i === -1 ? '' : r.stdout.slice(0, i) };
};

// --- the readers -----------------------------------------------------------------------------

test('readers: trunk index parses the CONFIRMED Revision marker; log RSS parses changeset links; junk lands empty with named gaps', () => {
  const gaps = [];
  assert.equal(cw.parseTrunkIndex('<html><head><title> - Revision 3666159: /akismet/trunk</title></head>', gaps, 'akismet'), 3666159);
  assert.equal(cw.parseTrunkIndex('<html>no marker</html>', gaps, 'akismet'), null, 'a moved shape is a gap, never a guessed head');
  assert.ok(gaps.some((g) => /no "Revision <N>:" marker/.test(g)));
  const g2 = [];
  assert.deepEqual(cw.parseLogRss('<rss><item><link>https://plugins.trac.wordpress.org/changeset/1251/acme-forms</link></item><item><link>https://plugins.trac.wordpress.org/changeset/1250/acme-forms</link></item></rss>', g2, 'acme-forms'), [1251, 1250]);
  assert.deepEqual(cw.parseLogRss('<html>oops</html>', g2, 'x'), []);
  assert.ok(g2.some((g) => /no \/changeset\/<N>\/ links/.test(g)));
  const g3 = [];
  assert.equal(cw.parseStableTag('=== Acme ===\nContributors: x\nStable tag: 1.4.2\n', g3, 'acme-forms'), '1.4.2', 'the readme stable tag parses');
  assert.equal(cw.parseStableTag('no such line\n', g3, 'acme-forms'), null, 'no Stable tag line = a named gap, never guessed');
  assert.ok(g3.some((g) => /no "Stable tag:" line/.test(g)));
});

test('parser: Trac Index: and git-style diffs both yield per-file +/- lines; junk yields an empty list', () => {
  const diff = JSON.parse(readFileSync(FIXTURE('commitwatch-scan-2.json'), 'utf8')).plugins['acme-forms'].changesets[0].diff;
  const files = eng.parseChangesetDiff(diff);
  assert.equal(files.length, 1);
  assert.equal(files[0].file, 'trunk/includes/ajax.php');
  assert.ok(files[0].added.some((l) => /check_ajax_referer/.test(l)), 'the added nonce line, verbatim');
  assert.ok(files[0].context.some((l) => /update_option/.test(l)), 'the sink rides as context');
  const git = eng.parseChangesetDiff('diff --git a/x.php b/x.php\n--- a/x.php\n+++ b/x.php\n@@ -1 +1 @@\n-old\n+new\n');
  assert.equal(git[0].file, 'x.php');
  assert.deepEqual(git[0].removed, ['old']);
  assert.deepEqual(git[0].added, ['new']);
  assert.deepEqual(eng.parseChangesetDiff('not a diff at all'), []);
  assert.deepEqual(eng.parseChangesetDiff(null), []);
});

// --- THE CLASSIFIER (the money part) — the four pinned bands --------------------------------

test('classifier: nonce check ADDED around an option-write sink = HIGH', () => {
  const files = eng.parseChangesetDiff(JSON.parse(readFileSync(FIXTURE('commitwatch-scan-2.json'), 'utf8')).plugins['acme-forms'].changesets[0].diff);
  const c = eng.classifyFileDiff(files[0]);
  assert.equal(c.band, 'high');
  assert.equal(c.score, 75, 'nonce-added 60 + sink-context 15');
  assert.ok(c.hits.some((h) => h.id === 'nonce-check-added'));
  assert.ok(c.contexts.some((x) => x.id === 'sink-context'));
});

test('classifier: capability check tightened (open permission_callback closed) = HIGH, public-route context named', () => {
  const files = eng.parseChangesetDiff(JSON.parse(readFileSync(FIXTURE('commitwatch-scan-2.json'), 'utf8')).plugins['cap-shops'].changesets[0].diff);
  const c = eng.classifyFileDiff(files[0]);
  assert.equal(c.band, 'high');
  assert.equal(c.score, 70, 'capability-check-added 60 (folded, never double-counted) + nopriv-context 10');
  assert.equal(c.hits.filter((h) => h.id === 'capability-check-added').length, 1, 'one capability hit even though both the callback fold-in and current_user_can fired');
  assert.ok(c.contexts.some((x) => x.id === 'nopriv-context'));
});

test('classifier: $wpdb->prepare ADDED on a raw query = MEDIUM', () => {
  const files = eng.parseChangesetDiff(JSON.parse(readFileSync(FIXTURE('commitwatch-scan-2.json'), 'utf8')).plugins['initech-ai'].changesets[0].diff);
  const c = eng.classifyFileDiff(files[0]);
  assert.equal(c.band, 'medium');
  assert.equal(c.score, 45, 'prepare-added 30 + sink-context 15');
});

test('classifier: typo-only churn = NOISE FLOOR (not a lead, even in a .php file)', () => {
  const files = eng.parseChangesetDiff(JSON.parse(readFileSync(FIXTURE('commitwatch-scan-2.json'), 'utf8')).plugins['globex-seo'].changesets[0].diff);
  assert.equal(files.length, 2, 'readme.txt AND globex-seo.php parsed');
  const lead = eng.buildLead({ slug: 'globex-seo', revision: 311, message: 'typo', fileDiffs: files, at: T1 });
  assert.equal(lead, null, 'no signal lines in any PHP file = no lead');
});

test('classifier: a nonce check REMOVED from a public handler = HIGH with the regression wording', () => {
  const files = eng.parseChangesetDiff(JSON.parse(readFileSync(FIXTURE('commitwatch-scan-3.json'), 'utf8')).plugins['globex-seo'].changesets[0].diff);
  const lead = eng.buildLead({ slug: 'globex-seo', revision: 312, message: 'refactor', fileDiffs: files, at: T3 });
  assert.ok(lead, 'a removed gate IS a lead');
  assert.equal(lead.band, 'high');
  assert.equal(lead.score, 95, 'nonce-removed 70 + sink-context 15 + nopriv-context 10');
  assert.match(lead.why, /REMOVES/);
  assert.match(lead.why, /reachable without authentication/);
});

test('lead shape: classes hit, honest affected-range wording, a BY-HAND suggested seed, doctrine on scan output', () => {
  const files = eng.parseChangesetDiff(JSON.parse(readFileSync(FIXTURE('commitwatch-scan-2.json'), 'utf8')).plugins['acme-forms'].changesets[0].diff);
  const lead = eng.buildLead({ slug: 'acme-forms', revision: 1251, message: 'add nonce', fileDiffs: files, at: T2 });
  assert.deepEqual(lead.classesHit, ['nonce-check-added']);
  assert.match(lead.why, /every tag shipped before r1251/, 'the affected range is stated as what we KNOW');
  assert.match(lead.why, /UNENUMERATED/, 'never a fabricated version list');
  assert.match(lead.why, /sibling-hunt/);
  assert.equal(lead.suggestedSeed.tool, 'variantsweep');
  assert.equal(lead.suggestedSeed.kind, 'class');
  assert.equal(lead.suggestedSeed.class, 'option-overwrite', 'the privemap sink-class id rides as a STRING — fed by hand');
  assert.equal(lead.suggestedSeed.anchors.mitigationFree, true, 'the pre-fix shape = the sink WITHOUT its gate');
  assert.match(lead.suggestedSeed.basis, /NEVER hunts/);
});

// --- the scan state machine -------------------------------------------------------------------

test('scan: FIRST SIGHT records the baseline and emits NOTHING — history is never backfilled', async () => {
  const r = await cw.scan({ source: cw.fixtureSource(FIXTURE('commitwatch-scan-1.json')), now: T1 });
  assert.equal(r.ok, true);
  assert.equal(r.watched, 4, 'the watch set came from the data file, not code');
  assert.equal(r.scanned, 4);
  assert.equal(r.changesets, 0);
  assert.equal(r.leads.length, 0, 'no backfill on first sight');
  assert.ok(r.gaps.some((g) => /first sight at r1250/.test(g)), 'the no-backfill decision is a named gap');
  assert.equal(r.doctrine, cw.DOCTRINE);
  const st = cw.loadState();
  assert.equal(st.plugins['acme-forms'].lastSeenRev, 1250);
  assert.equal(st.plugins['acme-forms'].firstSeen, T1);
});

test('scan: moved heads yield ranked leads (2 high + 1 med), typo churn counted as noise, state advances', async () => {
  const r = await cw.scan({ source: cw.fixtureSource(FIXTURE('commitwatch-scan-2.json')), now: T2 });
  assert.equal(r.ok, true);
  assert.equal(r.changesets, 4);
  assert.equal(r.leads.length, 3);
  assert.equal(r.noise, 1, 'the typo changeset is counted, never emitted');
  assert.equal(r.ranked[0].slug, 'acme-forms', 'high band first, score desc inside it (75 > 70)');
  assert.equal(r.ranked[0].band, 'high');
  assert.equal(r.ranked[1].slug, 'cap-shops');
  assert.equal(r.ranked[2].slug, 'initech-ai');
  assert.equal(r.ranked[2].band, 'medium');
  const st = cw.loadState();
  assert.equal(st.plugins['acme-forms'].lastSeenRev, 1251);
  assert.equal(st.plugins['acme-forms'].lastChanged, T2);
  assert.equal(st.leads.length, 3, 'the lead ring persists');
  const rep = cw.report();
  assert.equal(rep.leads.length, 3, 'report defaults to the most recent scan');
  assert.equal(rep.watched, 4);
  const repAll = cw.report({ all: true });
  assert.equal(repAll.leads.length, 3);
});

test('scan: regression fixture adds the removed-gate lead; a SILENT rescan changes nothing', async () => {
  const r = await cw.scan({ source: cw.fixtureSource(FIXTURE('commitwatch-scan-3.json')), now: T3 });
  assert.equal(r.ok, true);
  assert.equal(r.leads.length, 1);
  assert.equal(r.leads[0].classesHit[0], 'nonce-check-removed');
  const again = await cw.scan({ source: cw.fixtureSource(FIXTURE('commitwatch-scan-3.json')), now: '2026-08-25T03:00:00.000Z' });
  assert.equal(again.changesets, 0, 'heads unchanged = silence');
  assert.equal(again.leads.length, 0);
  assert.equal(cw.report().leads.length, 0, 'report defaults to the latest (silent) scan');
  assert.equal(cw.report({ all: true }).leads.length, 4, 'the ring holds the whole history');
  assert.equal(cw.loadState().plugins['globex-seo'].lastSeenRev, 312);
});

// --- honesty ------------------------------------------------------------------------------------

test('honesty: a FAILED head fetch keeps the previous state and records a named error — never a frozen-plugin guess', async () => {
  const before = cw.loadState().plugins['acme-forms'].lastSeenRev;
  const heads = { 'acme-forms': null, 'cap-shops': 48, 'initech-ai': 89, 'globex-seo': 312 };
  const dying = {
    ok: true, gaps: [],
    headRevision: async (slug) => heads[slug] === null
      ? { ok: false, error: 'wporg-unreachable', reason: 'GET https://plugins.svn.wordpress.org/acme-forms/trunk/ failed (ECONNREFUSED)' }
      : { ok: true, revision: heads[slug] }, // the healthy three report their CURRENT heads — silence, no changesets
    logRevisions: async () => ({ ok: true, revisions: [] }),
    changeset: async () => ({ ok: false, error: 'wporg-unreachable', reason: 'unreachable' }),
  };
  const r = await cw.scan({ source: dying, now: T3 });
  assert.equal(r.ok, true);
  assert.equal(r.scanned, 3, 'the other three still scanned');
  assert.equal(r.errors.length, 1);
  assert.equal(r.errors[0].error, 'wporg-unreachable');
  assert.equal(cw.loadState().plugins['acme-forms'].lastSeenRev, before, 'state untouched — a failed fetch is not a frozen plugin');
  assert.equal(cw.loadState().lastScan.errors.length, 1);
});

test('honesty: the live path REFUSES without the gate, and the host allowlist is enforced in code', async () => {
  let fetches = 0;
  const spy = async () => { fetches++; throw new Error('must never be called'); };
  const denied = cw.liveSource({ allow: false, fetchImpl: spy });
  assert.equal(denied.ok, false);
  assert.equal(denied.error, 'commitwatch-live-not-requested');
  assert.match(denied.reason, /--live/);
  const r = await cw.scan({ source: denied });
  assert.equal(r.ok, false);
  assert.equal(r.error, 'commitwatch-live-not-requested');
  assert.equal(fetches, 0, 'no opt-in => no request was ever attempted');
  for (const bad of ['https://evil.example.com/x', 'https://plugins.svn.wordpress.org.evil.example.com/x', 'not-a-url']) {
    const e = await cw.wpOrgGet({ url: bad, fetchImpl: spy });
    assert.equal(e.ok, false);
    assert.equal(e.error, 'commitwatch-host-not-allowed', `${bad} refused BEFORE any request`);
  }
  assert.equal(fetches, 0, 'wordpress.org hosts ONLY — enforced, not doctrined');
});

test('live path (stubbed fetch, zero network): head -> log -> changeset through the SAME readers; 429/404/garbage are named errors', async () => {
  const seen = [];
  const stub = async (url) => {
    seen.push(url);
    const ok = (text) => ({ ok: true, status: 200, text: async () => text });
    if (url === 'https://plugins.svn.wordpress.org/acme-forms/trunk/') return ok('<html><head><title> - Revision 1260: /acme-forms/trunk</title></head>');
    if (url === 'https://plugins.trac.wordpress.org/log/acme-forms/trunk?format=rss') return ok('<rss><item><link>https://plugins.trac.wordpress.org/changeset/1260/acme-forms</link></item></rss>');
    if (url === 'https://plugins.trac.wordpress.org/changeset/1260/acme-forms?format=diff') return ok(JSON.parse(readFileSync(FIXTURE('commitwatch-scan-2.json'), 'utf8')).plugins['acme-forms'].changesets[0].diff);
    if (url.endsWith('/missing/trunk/')) return { ok: false, status: 404, text: async () => 'nope' };
    if (url.endsWith('/throttled/trunk/')) return { ok: false, status: 429, text: async () => 'slow down' };
    throw new Error('unexpected URL: ' + url);
  };
  const src = cw.liveSource({ allow: true, fetchImpl: stub });
  assert.equal(src.ok, true);
  assert.deepEqual(await src.headRevision('acme-forms'), { ok: true, revision: 1260 });
  assert.deepEqual(await src.logRevisions('acme-forms'), { ok: true, revisions: [1260] });
  const cs = await src.changeset('acme-forms', 1260);
  assert.equal(cs.ok, true);
  assert.ok(cs.diff.includes('check_ajax_referer'), 'the diff text rides verbatim');
  assert.equal(seen.length, 3, 'three read-only GETs, all wordpress.org');
  assert.ok(seen.every((u) => cw.ALLOWED_HOSTS.includes(new URL(u).hostname)));
  const dead = await cw.liveSource({ allow: true, fetchImpl: async () => { throw new Error('ECONNREFUSED'); } });
  assert.equal((await dead.headRevision('acme-forms')).error, 'wporg-unreachable');
  const nf = await src.headRevision('missing');
  assert.equal(nf.error, 'wporg-http-error');
  assert.equal(nf.status, 404);
  const th = await src.headRevision('throttled');
  assert.equal(th.error, 'wporg-rate-limited');
});

test('honesty: a missing/malformed targets file is a NAMED refusal — the watch set is never guessed', async () => {
  const r = await cw.scan({ source: cw.fixtureSource(FIXTURE('commitwatch-scan-1.json')), targetsFile: join(ROOT, 'no-such-targets.json') });
  assert.equal(r.ok, false);
  assert.equal(r.error, 'unreadable-targets');
  assert.match(r.reason, /not guessed|data-driven/);
  const bad = join(ROOT, 'bad-targets.json');
  writeFileSync(bad, JSON.stringify({ targets: [{ noslug: true }] }));
  const r2 = await cw.scan({ source: cw.fixtureSource(FIXTURE('commitwatch-scan-1.json')), targetsFile: bad });
  assert.equal(r2.ok, false, 'zero usable slugs = a refusal, not an empty scan');
  assert.equal(r2.error, 'unreadable-targets');
});

// --- the never-hunts / never-submits pin ---------------------------------------------------------

test('static pin: neither module imports hunt/submission machinery — eyes, never hands', () => {
  for (const f of ['tools/commitwatch.mjs', 'engine/commitwatch.mjs']) {
    const src = readFileSync(join(__dir, '..', f), 'utf8');
    assert.ok(!/from\s*'[^']*(privemap|variantsweep)\.mjs'/.test(src), `${f}: no import of privemap/variantsweep — the seed vocabulary rides as strings`);
    assert.ok(!/\bminePrivesc\s*\(|\bsweepVariants\s*\(/.test(src), `${f}: no hunt execution calls`);
    assert.ok(!/method:\s*['"]POST['"]/.test(src), `${f}: read-only GETs only — no POST anywhere`);
    assert.ok(!/\b(signSession|signScope|submitReport|queueProgram|markOutcome)\b/.test(src), `${f}: no signing/submission/pipeline verbs`);
  }
  const engineSrc = readFileSync(join(__dir, '..', 'engine', 'commitwatch.mjs'), 'utf8');
  assert.ok(!/from\s*'node:/.test(engineSrc), 'the engine is PURE — no node:fs/net/crypto imports');
  assert.ok(!/\bfetch\s*\(/.test(engineSrc), 'the engine never fetches');
  const toolsSrc = readFileSync(join(__dir, '..', 'tools', 'commitwatch.mjs'), 'utf8');
  assert.ok(toolsSrc.includes('ALLOWED_HOSTS'), 'the host allowlist exists in code, not just doctrine');
});

// --- CLI smoke -------------------------------------------------------------------------------------

test('CLI: scan --fixture baseline, diff scan ranks leads, report/show/targets read state — doctrine printed throughout', () => {
  const d1 = join(ROOT, 'cli-1');
  mkdirSync(d1, { recursive: true });
  writeFileSync(join(d1, 'targets.json'), JSON.stringify(TARGETS));
  process.env.VARVEL_COMMITWATCH_DIR = d1;
  const one = run(['commitwatch', 'scan', '--fixture', FIXTURE('commitwatch-scan-1.json')]);
  assert.equal(one.status, 0, JSON.stringify(one.out).slice(0, 300));
  assert.equal(one.out.ok, true);
  assert.equal(one.out.leads.length, 0);
  assert.match(one.text, new RegExp(cw.DOCTRINE.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')), 'the CLI prints the doctrine line');

  const two = run(['commitwatch', 'scan', '--fixture', FIXTURE('commitwatch-scan-2.json')]);
  assert.equal(two.out.leads.length, 3);
  assert.match(two.text, /\[high 75\] r1251 acme-forms — nonce-check-added/, 'the lead line names band, score, revision, slug, classes');

  const rep = run(['commitwatch', 'report']);
  assert.equal(rep.status, 0);
  assert.equal(rep.out.leads.length, 3);
  assert.match(rep.text, /why: r1251/, 'the why-interesting line prints');
  assert.match(rep.text, /variantsweep <corpus> --sig/, 'the BY-HAND seed prints');
  assert.match(rep.text, /BY HAND — the watcher never hunts/);

  const show = run(['commitwatch', 'show', 'acme-forms']);
  assert.equal(show.out.ok, true);
  assert.equal(show.out.plugin.lastSeenRev, 1251);
  assert.equal(show.out.leads.length, 1);
  const nope = run(['commitwatch', 'show', 'no-such-plugin']);
  assert.equal(nope.status, 2);
  assert.equal(nope.out.error, 'unknown-plugin');

  const tt = run(['commitwatch', 'targets']);
  assert.equal(tt.status, 0);
  assert.equal(tt.out.targets.length, 4);
  assert.match(tt.text, /acme-forms — test target/);
  process.env.VARVEL_COMMITWATCH_DIR = ROOT;
});

test('CLI: scan with neither --fixture nor --live refuses BEFORE any fetch; --targets overrides the watch set', () => {
  const r = run(['commitwatch', 'scan']);
  assert.equal(r.status, 2, 'a named refusal exits nonzero');
  assert.equal(r.out.ok, false);
  assert.equal(r.out.error, 'commitwatch-live-not-requested');
  assert.equal(r.out.doctrine, cw.DOCTRINE);
  const d2 = join(ROOT, 'cli-2');
  mkdirSync(d2, { recursive: true });
  const t2 = join(d2, 'one-target.json');
  writeFileSync(t2, JSON.stringify({ targets: ['acme-forms'] }));
  const r2 = run(['commitwatch', 'scan', '--fixture', FIXTURE('commitwatch-scan-1.json'), '--targets', t2]);
  assert.equal(r2.out.watched, 1, 'the flag overrode the data file');
  assert.equal(r2.out.scanned, 1);
});


// --- the SVN fallback (trac 403 → plugins.svn.wordpress.org HTML indexes) ---------

test('fallback readers: parseSvnIndex reads the CONFIRMED index shape; sortTagsDesc is numeric not lexical; junk lands null with a named gap', () => {
  const gaps = [];
  const idx = cw.parseSvnIndex('<html><head><title> - Revision 3666159: /acme-forms</title></head><body><ul><li><a href="../">../</a></li><li><a href="trunk/">trunk/</a></li><li><a href="tags/">tags/</a></li><li><a href="readme.txt">readme.txt</a></li></ul>', gaps, 'acme-forms');
  assert.equal(idx.revision, 3666159);
  assert.deepEqual(idx.dirs, ['trunk', 'tags']);
  assert.deepEqual(idx.files, ['readme.txt']);
  const g2 = [];
  assert.equal(cw.parseSvnIndex('<html>nothing here</html>', g2, 'x'), null, 'a moved shape is a gap, never a guessed index');
  assert.ok(g2.some((g) => /no "Revision <N>:" marker and no entries/.test(g)));
  assert.deepEqual(cw.sortTagsDesc(['trunk', '1.9', '1.10', '2.0', '0.9-rc1']), ['2.0', '1.10', '1.9', '0.9-rc1'], '1.10 > 1.9 — lexical order would lie');
  const ops = cw.lcsDiff(['a', 'b', 'c'], ['a', 'x', 'c']);
  assert.deepEqual(ops, [{ t: ' ', line: 'a' }, { t: '-', line: 'b' }, { t: '+', line: 'x' }, { t: ' ', line: 'c' }], 'LCS emits the minimal line change');
});

test('SVN fallback: trac 403 switches to tag-to-tag diffs (stubbed fetch, zero network); trac healthy = fallback never engages', async () => {
  const OLD = '<?php\nfunction svn_forms_save() {\n  update_option(\'svn_forms\', $_POST[\'v\']);\n}\n';
  const NEW = '<?php\nfunction svn_forms_save() {\n  check_ajax_referer(\'svn_forms_save\');\n  update_option(\'svn_forms\', $_POST[\'v\']);\n}\n';
  const idx = (rev, entries) => `<html><head><title> - Revision ${rev}: /svn-forms</title></head><body><ul>${entries.map((e) => `<li><a href="${e}">${e}</a></li>`).join('')}</ul>`;
  let tracUrls = 0;
  const stub = async (url) => {
    const ok = (text) => ({ ok: true, status: 200, text: async () => text });
    const forbidden = () => ({ ok: false, status: 403, text: async () => 'forbidden' });
    if (url.startsWith(cw.WPORG.TRAC_BASE)) { tracUrls++; return forbidden(); }
    if (url === 'https://plugins.svn.wordpress.org/svn-forms/trunk/') return ok('<html><head><title> - Revision 1301: /svn-forms/trunk</title></head>');
    if (url === 'https://plugins.svn.wordpress.org/svn-forms/trunk/readme.txt') return ok('=== SVN Forms ===\nStable tag: 1.1\n');
    if (url === 'https://plugins.svn.wordpress.org/svn-forms/') return ok(idx(1301, ['trunk/', 'tags/']));
    if (url === 'https://plugins.svn.wordpress.org/svn-forms/tags/') return ok(idx(1301, ['1.0/', '1.1/']));
    if (url === 'https://plugins.svn.wordpress.org/svn-forms/tags/1.0/') return ok(idx(1290, ['svn-forms.php']));
    if (url === 'https://plugins.svn.wordpress.org/svn-forms/tags/1.1/') return ok(idx(1301, ['svn-forms.php']));
    if (url === 'https://plugins.svn.wordpress.org/svn-forms/tags/1.0/svn-forms.php') return ok(OLD);
    if (url === 'https://plugins.svn.wordpress.org/svn-forms/tags/1.1/svn-forms.php') return ok(NEW);
    throw new Error('unexpected URL: ' + url);
  };
  // Seed: first sight at r1300 (readme stable 1.0 — the seed source carries it).
  const seedStub = async (url) => {
    const ok = (text) => ({ ok: true, status: 200, text: async () => text });
    if (url === 'https://plugins.svn.wordpress.org/svn-forms/trunk/') return ok('<html><head><title> - Revision 1300: /svn-forms/trunk</title></head>');
    if (url === 'https://plugins.svn.wordpress.org/svn-forms/trunk/readme.txt') return ok('=== SVN Forms ===\nStable tag: 1.0\n');
    throw new Error('unexpected URL: ' + url);
  };
  const d3 = join(ROOT, 'fallback-targets.json');
  writeFileSync(d3, JSON.stringify({ targets: ['svn-forms'] }));
  const base = await cw.scan({ source: cw.liveSource({ allow: true, fetchImpl: seedStub }), targetsFile: d3, now: '2026-08-26T00:00:00.000Z' });
  assert.equal(base.ok, true);
  assert.equal(cw.loadState().plugins['svn-forms'].lastSeenRev, 1300, 'baseline recorded, no backfill');
  assert.equal(cw.loadState().plugins['svn-forms'].lastStableTag, '1.0', 'first sight baselines the release signal too');

  // The bump r1300 -> r1301 with the stable tag ALSO moving 1.0 -> 1.1: the
  // release-gated fallback synthesizes the exact version-transition diff.
  const src = cw.liveSource({ allow: true, fetchImpl: stub });
  assert.equal(src.ok, true);
  const r = await cw.scan({ source: src, targetsFile: d3, now: '2026-08-26T01:00:00.000Z' });
  assert.equal(r.ok, true);
  assert.equal(r.leads.length, 1, 'the tag-to-tag delta carries the fix signal');
  assert.equal(r.leads[0].band, 'high', 'nonce check ADDED + option-write sink context');
  assert.match(r.leads[0].message, /tag-to-tag diff 1\.0 → 1\.1/, 'the lead names the EXACT version transition');
  assert.match(r.leads[0].message, /RELEASE-PAIR/, 'the lead NAMES its granularity — never dressed as per-commit');
  assert.ok(src.gaps.some((g) => /trac log answered HTTP 403/.test(g)), 'the 403 fallback is a named event on the source gap list');
  assert.equal(cw.loadState().plugins['svn-forms'].lastStableTag, '1.1', 'a landed diff advances the release baseline');
  const tracAfterBlock = tracUrls;
  await src.logRevisions('svn-forms');
  await src.changeset('svn-forms', 1301);
  assert.equal(tracUrls, tracAfterBlock, 'once blocked, trac is not hammered again this scan');

  // madara-core shape: a 404 on the plugin root is expected and named, never a crash.
  const dead = await cw.liveSource({ allow: true, fetchImpl: async () => ({ ok: false, status: 404, text: async () => 'not here' }) });
  const nf = await dead.changeset('gone-forms', 5);
  assert.equal(nf.ok, false);
  assert.equal(nf.error, 'wporg-http-error');
  assert.equal(nf.status, 404);

  // Healthy trac: the fallback must NOT engage (trac stays primary when it works).
  const seen = [];
  const healthy = cw.liveSource({ allow: true, fetchImpl: async (url) => {
    seen.push(url);
    const ok = (text) => ({ ok: true, status: 200, text: async () => text });
    if (url === 'https://plugins.trac.wordpress.org/log/svn-forms/trunk?format=rss') return ok('<rss><item><link>https://plugins.trac.wordpress.org/changeset/1301/svn-forms</link></item></rss>');
    throw new Error('unexpected URL: ' + url);
  } });
  const log = await healthy.logRevisions('svn-forms');
  assert.deepEqual(log.revisions, [1301]);
  assert.ok(!log.svnFallback, 'trac primary — no fallback flag');
  assert.ok(seen.every((u) => u.startsWith(cw.WPORG.TRAC_BASE)), 'no SVN tag fetches when trac answers');

  // One tag only: EMPTY with a named gap, never a fabricated pair.
  const oneTag = cw.liveSource({ allow: true, fetchImpl: async (url) => {
    const ok = (text) => ({ ok: true, status: 200, text: async () => text });
    const forbidden = () => ({ ok: false, status: 403, text: async () => 'forbidden' });
    if (url.startsWith(cw.WPORG.TRAC_BASE)) return forbidden();
    if (url === 'https://plugins.svn.wordpress.org/lonely/') return ok(idx(9, ['trunk/', 'tags/']));
    if (url === 'https://plugins.svn.wordpress.org/lonely/tags/') return ok(idx(9, ['1.0/']));
    throw new Error('unexpected URL: ' + url);
  } });
  const gapsBefore = oneTag.gaps.length;
  const cs = await oneTag.changeset('lonely', 9);
  assert.equal(cs.ok, true);
  assert.equal(cs.diff, '', 'no tag pair = EMPTY, never fabricated');
  assert.ok(oneTag.gaps.slice(gapsBefore).some((g) => /tag-PAIR is required/.test(g)));
});

test('release gating: unchanged stable tag NEVER diffs on a global-revision bump; missing readme = named gap; pre-fix state baselines silently', async () => {
  const idx = (rev, entries) => `<html><head><title> - Revision ${rev}: /x</title></head><body><ul>${entries.map((e) => `<li><a href="${e}">${e}</a></li>`).join('')}</ul>`;
  const d4 = join(ROOT, 'gating-targets.json');
  writeFileSync(d4, JSON.stringify({ targets: ['still-forms', 'noreadme-forms'] }));
  // Seed both targets at r2000 with stable 3.0.
  const seed = async (url) => {
    const ok = (text) => ({ ok: true, status: 200, text: async () => text });
    if (url.endsWith('/trunk/')) return ok('<html><head><title> - Revision 2000: /x/trunk</title></head>');
    if (url === 'https://plugins.svn.wordpress.org/still-forms/trunk/readme.txt') return ok('=== Still ===\nStable tag: 3.0\n');
    if (url === 'https://plugins.svn.wordpress.org/noreadme-forms/trunk/readme.txt') return { ok: false, status: 404, text: async () => 'no' };
    if (url === 'https://plugins.svn.wordpress.org/noreadme-forms/trunk/README.txt') return { ok: false, status: 404, text: async () => 'no' };
    throw new Error('unexpected URL: ' + url);
  };
  const s0 = await cw.scan({ source: cw.liveSource({ allow: true, fetchImpl: seed }), targetsFile: d4, now: '2026-08-26T02:00:00.000Z' });
  assert.equal(s0.ok, true);
  assert.equal(cw.loadState().plugins['still-forms'].lastStableTag, '3.0');

  // Global HEAD bumps 2000 -> 2001 with trac 403, but the stable tag is STILL 3.0:
  // repo-global revision is not a plugin release signal — no diff, no tag fetches.
  const fetched = [];
  const bump = async (url) => {
    fetched.push(url);
    const ok = (text) => ({ ok: true, status: 200, text: async () => text });
    const forbidden = () => ({ ok: false, status: 403, text: async () => 'forbidden' });
    if (url.startsWith(cw.WPORG.TRAC_BASE)) return forbidden();
    if (url.endsWith('/trunk/')) return ok('<html><head><title> - Revision 2001: /x/trunk</title></head>');
    if (url === 'https://plugins.svn.wordpress.org/still-forms/trunk/readme.txt') return ok('=== Still ===\nStable tag: 3.0\n');
    if (url === 'https://plugins.svn.wordpress.org/noreadme-forms/trunk/readme.txt') return { ok: false, status: 404, text: async () => 'no' };
    if (url === 'https://plugins.svn.wordpress.org/noreadme-forms/trunk/README.txt') return { ok: false, status: 404, text: async () => 'no' };
    throw new Error('unexpected URL: ' + url);
  };
  const r = await cw.scan({ source: cw.liveSource({ allow: true, fetchImpl: bump }), targetsFile: d4, now: '2026-08-26T03:00:00.000Z' });
  assert.equal(r.ok, true);
  assert.equal(r.leads.length, 0, 'unchanged stable tag = NO diff, even with HEAD moved');
  assert.equal(r.changesets, 0);
  assert.ok(r.gaps.some((g) => /still-forms: global HEAD moved r2000 -> r2001 but stable tag unchanged \(3\.0\)/.test(g)), 'the suppression is a named, reasoned gap');
  assert.ok(r.gaps.some((g) => /noreadme-forms: neither trunk\/readme.txt nor trunk\/README.txt exists/.test(g)), 'missing readme = named gap, never guessed');
  assert.ok(!fetched.some((u) => u.includes('/tags/')), 'no tag-to-tag work happens without a release signal');

  // Pre-fix state shape: an entry with lastSeenRev but NO lastStableTag baselines
  // SILENTLY on its first gated run (the 17-target stale-fire fix) — no diff.
  const st = cw.loadState();
  delete st.plugins['still-forms'].lastStableTag; // simulate the pre-fix state record
  st.plugins['still-forms'].lastSeenRev = 2000;   // rewind so the bump re-triggers
  writeFileSync(join(ROOT, 'state.json'), JSON.stringify(st, null, 2) + '\n');
  const r2 = await cw.scan({ source: cw.liveSource({ allow: true, fetchImpl: bump }), targetsFile: d4, now: '2026-08-26T04:00:00.000Z' });
  assert.equal(r2.ok, true);
  assert.equal(r2.leads.length, 0, 'baselining never fires a diff');
  assert.ok(r2.gaps.some((g) => /still-forms: stable tag baselined at 3\.0 \(first run with release gating — NO diff/.test(g)));
  assert.equal(cw.loadState().plugins['still-forms'].lastStableTag, '3.0', 'the baseline is recorded for the next cron');
  assert.equal(cw.loadState().plugins['still-forms'].lastSeenRev, 2001, 'HEAD stays a liveness record');
});

test('fallback pairing: tag-RELATIVE keys — byte-identical files vanish from the diff/leads; only genuine deltas and added files appear (the AIOSEO false-positive)', async () => {
  const IDENT = '<?php\nif ( ! current_user_can( \'administrator\' ) ) {\n  return;\n}\n';
  const CHANGED_OLD = '<?php\nfunction pair_save() {\n  update_option( \'pair\', $_POST[\'v\'] );\n}\n';
  const CHANGED_NEW = '<?php\nfunction pair_save() {\n  check_ajax_referer( \'pair_save\' );\n  update_option( \'pair\', $_POST[\'v\'] );\n}\n';
  const ADDED = '<?php\nfunction pair_new_helper() {\n  return true;\n}\n';
  const idx = (rev, entries) => `<html><head><title> - Revision ${rev}: /pair-forms</title></head><body><ul>${entries.map((e) => `<li><a href="${e}">${e}</a></li>`).join('')}</ul>`;
  const stub = async (url) => {
    const ok = (text) => ({ ok: true, status: 200, text: async () => text });
    const forbidden = () => ({ ok: false, status: 403, text: async () => 'forbidden' });
    if (url.startsWith(cw.WPORG.TRAC_BASE)) return forbidden();
    if (url === 'https://plugins.svn.wordpress.org/pair-forms/') return ok(idx(42, ['trunk/', 'tags/']));
    if (url === 'https://plugins.svn.wordpress.org/pair-forms/tags/') return ok(idx(42, ['2.0/', '2.1/']));
    if (url === 'https://plugins.svn.wordpress.org/pair-forms/tags/2.0/') return ok(idx(40, ['identical.php', 'changed.php']));
    if (url === 'https://plugins.svn.wordpress.org/pair-forms/tags/2.1/') return ok(idx(42, ['identical.php', 'changed.php', 'added.php']));
    if (url === 'https://plugins.svn.wordpress.org/pair-forms/tags/2.0/identical.php') return ok(IDENT);
    if (url === 'https://plugins.svn.wordpress.org/pair-forms/tags/2.1/identical.php') return ok(IDENT);
    if (url === 'https://plugins.svn.wordpress.org/pair-forms/tags/2.0/changed.php') return ok(CHANGED_OLD);
    if (url === 'https://plugins.svn.wordpress.org/pair-forms/tags/2.1/changed.php') return ok(CHANGED_NEW);
    if (url === 'https://plugins.svn.wordpress.org/pair-forms/tags/2.1/added.php') return ok(ADDED);
    throw new Error('unexpected URL: ' + url);
  };
  const src = cw.liveSource({ allow: true, fetchImpl: stub });
  const cs = await src.changeset('pair-forms', 42, { fromTag: '2.0', toTag: '2.1' });
  assert.equal(cs.ok, true);
  assert.match(cs.diff, /changed\.php/, '(b) the genuinely changed file appears');
  assert.match(cs.diff, /check_ajax_referer/, '…with its delta (the added nonce line)');
  assert.match(cs.diff, /added\.php/, '(c) the genuinely added file appears as added');
  assert.ok(!/identical\.php/.test(cs.diff), '(a) a byte-identical file must NOT appear in the synthesized diff at all');
  assert.match(cs.message, /2\/2 common files content-compared/, 'both common files were content-compared (pairing works)');

  // Lead level: the classifier never sees the identical file, and the lead carries
  // only the real delta (nonce-added + option-write sink = high).
  const files = eng.parseChangesetDiff(cs.diff);
  assert.equal(files.length, 2, 'changed.php + added.php only');
  const lead = eng.buildLead({ slug: 'pair-forms', revision: 42, message: cs.message, fileDiffs: files, at: '2026-08-26T05:00:00.000Z' });
  assert.ok(lead, 'the real delta is a lead');
  assert.equal(lead.band, 'high');
  assert.ok(lead.files.every((f) => f.file !== 'identical.php'), 'no security-shaped lines from byte-identical files — the AIOSEO FP shape is dead');
  assert.ok(lead.files.some((f) => f.file === 'changed.php' && f.hits.some((h) => h.id === 'nonce-check-added')));
});
