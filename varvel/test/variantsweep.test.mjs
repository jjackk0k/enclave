// VARVEL variantsweep tests — signature-driven same-shape sweeps over a local WP-plugin
// corpus (engine/variantsweep.mjs + tools/variantsweep.mjs), with the build's PROOF
// OBLIGATION pinned: the two signatures seeded from our own Madara history MUST
// rediscover the known sinks when swept over the local madara-site mirror, and the
// negative-control fixture MUST produce zero hits.
//   node --test test/variantsweep.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { sweepVariants, pluginOf } from '../engine/variantsweep.mjs';
import { variantsweep } from '../tools/variantsweep.mjs';
import { sinkClasses } from '../engine/privemap.mjs';

const PHP_OPEN = '<?php\n';

// (a) The Madara option-overwrite shape, re-homed in a synthetic "other" plugin:
// admin_init-registered handler, update_option of request-derived data, no nonce/cap.
const MADARA_SHAPE = PHP_OPEN + `
add_action('admin_init', 'clone_settings_save');
function clone_settings_save() {
    if (isset($_POST['clone_opts'])) {
        $opts = $_POST['clone_opts'];
        update_option('clone_settings', $opts);
    }
}
`;

// (b) The imgur _get_token init shape: request-driven init handler writing an option
// from $_GET — plus a bootstrap-only init handler that must NOT be modeled.
const IMGUR_SHAPE = PHP_OPEN + `
add_action('init', 'clone_get_token');
function clone_get_token() {
    if (isset($_GET['access_token'])) {
        update_option('clone_refreshToken', $_GET['access_token']);
    }
}

add_action('init', 'clone_bootstrap');
function clone_bootstrap() {
    update_option('clone_booted', 1);
}
`;

// (c) NEGATIVE CONTROL: a synthetic clean plugin — nonce + capability + login checks on
// a wp_ajax handler, sanitized value, no admin_init/init request-driven handler at all.
const CLEAN_PLUGIN = PHP_OPEN + `
add_action('wp_ajax_clean_save', 'clean_save');
function clean_save() {
    check_ajax_referer('clean_save_nonce');
    if (!current_user_can('manage_options')) {
        wp_die('nope');
    }
    update_option('clean_key', sanitize_text_field($_POST['val']));
}
`;

const rec = (name, content) => ({ path: `wp-content/plugins/fixture/${name}`, content });

// The two signatures seeded from our own confirmed history (the proof obligation):
// (1) Madara option-overwrite: update_option/add_option inside an admin_init-registered
//     handler (settings.php:126 + wp-manga.php:789 in madara-core).
const SIG_MADARA = {
  kind: 'pattern',
  id: 'madara-option-overwrite',
  label: 'admin_init settings-save option overwrite, no nonce/capability check (the Madara wp_manga_settings shape)',
  match: String.raw`(?<![\w$>:-])(?:update_option|add_option)\s*\(`,
  anchors: { hooks: ['admin_init'] },
};
// (2) imgur _get_token: request-driven init handler writing an option (imgur-upload.php:39).
const SIG_IMGUR = {
  kind: 'pattern',
  id: 'imgur-token-init',
  label: 'request-driven init handler writing an option from $_GET (the Madara imgur _get_token shape)',
  match: String.raw`(?<![\w$>:-])update_option\s*\(`,
  anchors: { hooks: ['init'] },
};
// (3) A class signature reusing privemap's named sink class.
const SIG_CLASS = { kind: 'class', id: 'class-option-overwrite', class: 'option-overwrite' };

test('pattern signature: madara shape confirmed with full hit record; status left blank', () => {
  const r = sweepVariants([rec('madara.php', MADARA_SHAPE), rec('imgur.php', IMGUR_SHAPE), rec('clean.php', CLEAN_PLUGIN)], SIG_MADARA);
  assert.equal(r.errors.length, 0);
  assert.equal(r.stats.inputFiles, 3);
  // All three fixtures contain the literal sink token, so the loose prefilter keeps all
  // three — the CONFIRM pass (registration + anchor analysis) is what cuts clean.php.
  assert.equal(r.stats.prefilteredFiles, 3);
  assert.equal(r.hits.length, 1, JSON.stringify(r.hits.map((h) => [h.ref, h.hook])));
  const h = r.hits[0];
  assert.equal(h.rank, 1);
  assert.equal(h.plugin, 'fixture');
  assert.match(h.ref, /madara\.php:\d+$/);
  assert.equal(h.class, 'option-overwrite');
  assert.equal(h.hook, 'admin_init');
  assert.equal(h.handler, 'clone_settings_save');
  assert.equal(h.reachability, 'unauth');
  assert.equal(h.confidence, 'high');
  assert.equal(h.status, '', 'novelty/CVE status is left blank for the operator — never claimed');
  assert.match(h.evidence, /update_option/);
  assert.ok(typeof h.score === 'number' && h.score > 0);
});

test('pattern signature: imgur shape confirmed under the init anchor only', () => {
  const r = sweepVariants([rec('madara.php', MADARA_SHAPE), rec('imgur.php', IMGUR_SHAPE), rec('clean.php', CLEAN_PLUGIN)], SIG_IMGUR);
  assert.equal(r.errors.length, 0);
  assert.equal(r.hits.length, 1, JSON.stringify(r.hits.map((h) => [h.ref, h.hook, h.handler])));
  const h = r.hits[0];
  assert.match(h.ref, /imgur\.php:\d+$/);
  assert.equal(h.hook, 'init');
  assert.equal(h.handler, 'clone_get_token');
  assert.equal(h.reachability, 'unauth');
  assert.equal(h.status, '');
  // The bootstrap-only init handler (no request channel) is not modeled by privemap and
  // must not surface — the sweep inherits that behavior honestly.
  assert.ok(!r.hits.some((x) => x.handler === 'clone_bootstrap'));
});

test('class signature: a named privemap sink class as the sweep query', () => {
  const r = sweepVariants([rec('madara.php', MADARA_SHAPE), rec('imgur.php', IMGUR_SHAPE), rec('clean.php', CLEAN_PLUGIN)], SIG_CLASS);
  assert.equal(r.errors.length, 0);
  assert.equal(r.signature.class, 'option-overwrite');
  const madara = r.hits.find((h) => /madara\.php/.test(h.ref));
  assert.ok(madara, 'madara shape found via the class query');
  assert.equal(madara.class, 'option-overwrite');
  const imgur = r.hits.find((h) => /imgur\.php/.test(h.ref));
  assert.ok(imgur, 'imgur shape found via the class query');
  // The clean plugin's gated write DOES surface under a bare class query — honestly, at
  // admin-gated reachability; anchors are what cut it (see the negative-control pin).
  const clean = r.hits.find((h) => /clean\.php/.test(h.ref));
  assert.ok(clean && clean.reachability === 'admin-gated', 'gated carrier reported at admin-gated reachability');
  for (let i = 0; i < r.hits.length; i++) {
    assert.equal(r.hits[i].rank, i + 1);
    if (i) assert.ok(r.hits[i - 1].score >= r.hits[i].score, 'hits ranked by score');
  }
});

test('NEGATIVE CONTROL: synthetic clean plugin produces ZERO hits under both seeded pattern signatures', () => {
  for (const sig of [SIG_MADARA, SIG_IMGUR]) {
    const r = sweepVariants([rec('clean.php', CLEAN_PLUGIN)], sig);
    assert.equal(r.hits.length, 0, `${sig.id} must produce zero hits on the clean fixture; got ${JSON.stringify(r.hits)}`);
    assert.equal(r.errors.length, 0);
  }
});

test('anchors cut: mitigationFree drops the gated carrier from the class query', () => {
  const r = sweepVariants([rec('madara.php', MADARA_SHAPE), rec('clean.php', CLEAN_PLUGIN)],
    { ...SIG_CLASS, anchors: { mitigationFree: true } });
  assert.ok(r.hits.some((h) => /madara\.php/.test(h.ref)), 'ungated carrier kept');
  assert.ok(!r.hits.some((h) => /clean\.php/.test(h.ref)), 'nonce+capability-gated carrier cut by the mitigationFree anchor');
});

test('bad signatures never throw — honest errors[], zero hits', () => {
  for (const [label, sig] of [
    ['null', null],
    ['not an object', 42],
    ['unknown kind', { kind: 'grep', match: 'x' }],
    ['unknown sink class', { kind: 'class', class: 'rce-everything' }],
    ['invalid pattern regex', { kind: 'pattern', match: '(unclosed' }],
    ['empty match', { kind: 'pattern', match: '' }],
    ['unknown anchor key (typo guard)', { kind: 'pattern', match: 'update_option', anchors: { hook: ['init'] } }],
    ['bad reachability value', { kind: 'pattern', match: 'update_option', anchors: { reachability: ['root'] } }],
    ['bad taint value', { kind: 'pattern', match: 'update_option', anchors: { taint: ['maybe'] } }],
  ]) {
    const r = sweepVariants([rec('madara.php', MADARA_SHAPE)], sig);
    assert.deepEqual(r.hits, [], label);
    assert.ok(r.errors.length >= 1, `${label}: error reported`);
    assert.equal(r.signature, null, label);
  }
  // Unknown sink class error lists the known classes (operator self-service).
  const r = sweepVariants([], { kind: 'class', class: 'nope' });
  for (const cls of sinkClasses()) assert.match(r.errors[0], new RegExp(cls.id));
});

test('garbage records never throw; empty/whitespace records are not files', () => {
  for (const junk of [null, undefined, 'string', 42, {}]) {
    const r = sweepVariants(junk, SIG_MADARA);
    assert.deepEqual(r.hits, []);
    assert.equal(r.stats.inputFiles, 0);
  }
  const r = sweepVariants([rec('empty.php', ''), rec('ws.php', '  \n '), { path: 'x.php' }, { content: '<?php' }], SIG_MADARA);
  assert.deepEqual(r.hits, []);
  assert.equal(r.stats.inputFiles, 1, 'the bare-<?php record has content and counts; empty/contentless ones do not');
});

test('pluginOf: wp-content shape yields the slug; other shapes fall back honestly', () => {
  assert.equal(pluginOf('wp-content/plugins/madara-core/inc/settings.php'), 'madara-core');
  assert.equal(pluginOf('wp-content/themes/madara/functions.php'), 'madara');
  assert.equal(pluginOf('C:/mirror/wp-content/plugins/x/a.php'), 'x');
  assert.equal(pluginOf('corpus/some-plugin/b.php'), 'corpus');
  assert.equal(pluginOf('bare.php'), '(root)');
});

test('tool wrapper: never throws on a missing root; honest skipped[] and errors[]', () => {
  const missing = variantsweep(join('.tmp', 'variantsweep-no-such-dir-' + process.pid), SIG_MADARA);
  assert.deepEqual(missing.hits, []);
  assert.equal(missing.scannedFiles, 0);
  assert.ok(missing.skipped.length >= 1, 'unreadable root reported in skipped[]');

  const badSig = variantsweep(join('.tmp', 'variantsweep-no-such-dir-' + process.pid), '{not json');
  assert.deepEqual(badSig.hits, []);
  assert.ok(badSig.errors.some((e) => /not valid JSON/.test(e)), 'bad JSON signature reported, not thrown');
});

test('tool wrapper: fs walk into a fixture tree, root-relative refs, signature as JSON string', () => {
  const dir = join('.tmp', 'variantsweep-test-' + process.pid);
  try {
    mkdirSync(join(dir, 'wp-content', 'plugins', 'madara-clone'), { recursive: true });
    mkdirSync(join(dir, 'wp-content', 'plugins', 'clean-one'), { recursive: true });
    writeFileSync(join(dir, 'wp-content', 'plugins', 'madara-clone', 'clone.php'), MADARA_SHAPE);
    writeFileSync(join(dir, 'wp-content', 'plugins', 'clean-one', 'clean.php'), CLEAN_PLUGIN);
    writeFileSync(join(dir, 'wp-content', 'plugins', 'clean-one', 'note.txt'), 'update_option(\'x\', $_POST[\'y\']);'); // not .php — ignored
    const report = variantsweep(dir, JSON.stringify(SIG_MADARA));
    assert.equal(report.errors.length, 0);
    assert.equal(report.scannedFiles, 2);
    assert.equal(report.hits.length, 1, JSON.stringify(report.hits));
    const h = report.hits[0];
    assert.equal(h.plugin, 'madara-clone');
    assert.equal(h.ref.startsWith('wp-content/plugins/'), true, 'refs are root-relative');
    assert.equal(h.status, '');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// --- PROOF OBLIGATION: seeded signatures over the local madara-site mirror ------------
// Skips gracefully when the mirror is absent (CI/other hosts); on the research host the
// sweeps MUST rediscover the known sinks at their pinned refs, and the prefilter must
// genuinely narrow the corpus (a vacuous pass proves nothing).
const MIRROR = 'C:/Users/Jack/Downloads/varvel-kimi/research/madara-site';
const mirrorSkip = { skip: !existsSync(MIRROR) && 'madara-site mirror not present on this host' };

test('PROOF 1: Madara option-overwrite signature rediscovers both known sinks in the mirror', mirrorSkip, () => {
  const report = variantsweep(MIRROR, SIG_MADARA);
  assert.equal(report.errors.length, 0, JSON.stringify(report.errors));
  assert.ok(report.scannedFiles > 2000, `mirror really scanned (${report.scannedFiles} files) — a vacuous pass proves nothing`);
  assert.ok(report.stats.prefilteredFiles < report.scannedFiles,
    `prefilter narrows the corpus (${report.stats.prefilteredFiles}/${report.scannedFiles})`);
  const refs = report.hits.map((h) => h.ref);
  assert.ok(
    refs.includes('wp-content/plugins/madara-core/inc/settings.php:126'),
    'known sink inc/settings.php:126 rediscovered; got hits:\n' + report.hits.map((h) => `${h.rank} ${h.plugin} ${h.ref}`).join('\n'),
  );
  assert.ok(
    refs.includes('wp-content/plugins/madara-core/wp-manga.php:789'),
    'known sink wp-manga.php:789 rediscovered; got hits:\n' + report.hits.map((h) => `${h.rank} ${h.plugin} ${h.ref}`).join('\n'),
  );
  for (const h of report.hits) {
    assert.equal(h.status, '', 'novelty/CVE status left blank for the operator on every hit');
    assert.equal(h.class, 'option-overwrite');
    assert.equal(h.hook, 'admin_init');
  }
});

test('PROOF 2: imgur _get_token init signature rediscovers imgur-upload.php:39 in the mirror', mirrorSkip, () => {
  const report = variantsweep(MIRROR, SIG_IMGUR);
  assert.equal(report.errors.length, 0, JSON.stringify(report.errors));
  const refs = report.hits.map((h) => h.ref);
  assert.ok(
    refs.includes('wp-content/plugins/madara-core/inc/upload/imgur-upload.php:39'),
    'known sink inc/upload/imgur-upload.php:39 rediscovered; got hits:\n' + report.hits.map((h) => `${h.rank} ${h.plugin} ${h.ref}`).join('\n'),
  );
  for (const h of report.hits) assert.equal(h.hook, 'init');
});

test('PROOF 3: negative-control fixture dropped into the mirror shape still yields zero hits', mirrorSkip, () => {
  // The clean plugin, written into a wp-content-shaped tree of its own and swept with
  // both seeded signatures — zero hits even when the corpus shape is WordPress-native.
  const dir = join('.tmp', 'variantsweep-negctl-' + process.pid);
  try {
    mkdirSync(join(dir, 'wp-content', 'plugins', 'clean-one'), { recursive: true });
    writeFileSync(join(dir, 'wp-content', 'plugins', 'clean-one', 'clean.php'), CLEAN_PLUGIN);
    for (const sig of [SIG_MADARA, SIG_IMGUR]) {
      const report = variantsweep(dir, sig);
      assert.equal(report.scannedFiles, 1);
      assert.equal(report.hits.length, 0, `${sig.id}: zero hits on the clean plugin; got ${JSON.stringify(report.hits)}`);
      assert.equal(report.errors.length, 0);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
