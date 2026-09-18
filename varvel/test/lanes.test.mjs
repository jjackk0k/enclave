// VARVEL lanes tests — hermetic unit + integration tests for bounty-lane classification
// (engine/lanes.mjs, stamped on privemap candidates and reachprove rescore results),
// the riskLevel roll-up on findings (engine/severity.mjs riskLevelForScore), and the
// AIOSEO two-tier capability lineage in reachprove (engine/reachability.mjs).
//   node --test test/lanes.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classifyLane, reachTier } from '../engine/lanes.mjs';
import { riskLevelForScore } from '../engine/severity.mjs';
import { minePrivesc } from '../engine/privemap.mjs';
import { buildReachabilityModel, analyzeAll, rescoreCandidates } from '../engine/reachability.mjs';

const PHP_OPEN = '<?php\n';
const rec = (name, content) => ({ path: `wp-content/plugins/fixture/${name}`, content });

// --- classifyLane: the verified program rules, one decision at a time -------------

test('lane: fully-qualified unauth sqli finding is wordfence-eligible + patchstack standard', () => {
  const l = classifyLane({ reach: 'unauth', impactClass: 'sqli', installs: 120000, cvss: 6.5 });
  assert.equal(l.wordfenceEligible, true);
  assert.equal(l.patchstack, 'standard');
  assert.ok(l.reasons.some((r) => /install count 120000 >= 50000/.test(r)), 'install rule named');
  assert.ok(l.reasons.some((r) => /not on the excluded list/.test(r)), 'class rule named');
  assert.ok(l.reasons.some((r) => /consequential CIA impact/.test(r)), 'impact rule named');
  assert.ok(l.reasons.some((r) => /CVSS 6\.5 >= 4/.test(r)), 'cvss rule named');
  assert.ok(l.reasons.some((r) => /vendor-program-status needs scopecheck/.test(r)), 'scopecheck reason rides the class-based value');
});

test('lane: unknown installs make wordfence ineligible (noted, never assumed) — patchstack unaffected', () => {
  const l = classifyLane({ reach: 'unauth', impactClass: 'sqli' });
  assert.equal(l.wordfenceEligible, false);
  assert.ok(l.reasons.some((r) => /install count UNKNOWN/.test(r)), 'the unknown-installs note is the failure');
  assert.equal(l.patchstack, 'standard', 'patchstack has no install-count rule');
  const below = classifyLane({ reach: 'unauth', impactClass: 'sqli', installs: 49999 });
  assert.equal(below.wordfenceEligible, false);
  assert.ok(below.reasons.some((r) => /49999 < 50000/.test(r)), 'below-floor count named');
});

test('lane: contributor reach — wordfence excluded (mid-level); patchstack mvdp only for BAC/IDOR', () => {
  const bac = classifyLane({ reach: 'CONTRIBUTOR', impactClass: 'token-compare', installs: 100000 });
  assert.equal(bac.wordfenceEligible, false);
  assert.ok(bac.reasons.some((r) => /mid-level auth reach is excluded/.test(r)), 'contributor/author exclusion named');
  assert.equal(bac.patchstack, 'mvdp');
  assert.ok(bac.reasons.some((r) => /vendor-program-status needs scopecheck/.test(r)), 'mVDP membership flagged for scopecheck');

  const sqli = classifyLane({ reach: 'contributor', impactClass: 'sqli', installs: 100000 });
  assert.equal(sqli.patchstack, 'none', 'sqli at contributor reach files nowhere (standard is low-priv only, mVDP takes BAC/IDOR only)');
  assert.ok(sqli.reasons.some((r) => /not one of the mVDP contributor classes/.test(r)));
});

test('lane: privileged reach (admin-gated/editor) is excluded everywhere with the PR:H reason', () => {
  const l = classifyLane({ reach: 'admin-gated', impactClass: 'option-overwrite', installs: 100000 });
  assert.equal(l.wordfenceEligible, false);
  assert.ok(l.reasons.some((r) => /PR:H/.test(r)), 'editor/admin/shop-manager = PR:H exclusion named');
  assert.equal(l.patchstack, 'none');
  assert.ok(l.reasons.some((r) => /direct vendor disclosure/.test(r)));
});

test('lane: unproven reach classifies as patchstack unknown — never dropped, never guessed', () => {
  const l = classifyLane({ reach: 'unknown', impactClass: 'sqli', installs: 100000 });
  assert.equal(l.wordfenceEligible, false);
  assert.equal(l.patchstack, 'unknown');
  assert.ok(l.reasons.some((r) => /reach is unproven/.test(r)));
});

test('lane: wordfence excluded classes fail with the list named (ssrf/dos/cors/open-redirect/api-key-update/clickjacking/username-enumeration)', () => {
  const l = classifyLane({ reach: 'unauth', vulnClass: 'ssrf', installs: 100000 });
  assert.equal(l.wordfenceEligible, false);
  assert.ok(l.reasons.some((r) => /excluded list/.test(r) && /ssrf/.test(r)));
  assert.equal(l.patchstack, 'none', 'ssrf is not a patchstack accepted class either');
});

test('lane: miner-degraded writes (fixed-value/self-only, the 0.3 degrade) are not consequential', () => {
  const l = classifyLane({ reach: 'unauth', impactClass: 'option-overwrite', installs: 100000, degraded: "fixed-value write (value is a literal/constant '1' — the primitive is bounded to a constant)" });
  assert.equal(l.wordfenceEligible, false);
  assert.ok(l.reasons.some((r) => /NOT consequential/.test(r) && /bounded primitives/.test(r)), 'the degrade rule named');
});

test('lane: missing-authz exposure classes carry no consequential sink of their own', () => {
  const l = classifyLane({ reach: 'unauth', impactClass: 'ai-endpoint', installs: 100000 });
  assert.equal(l.wordfenceEligible, false);
  assert.ok(l.reasons.some((r) => /missing-authz\/exposure finding counts only when its sink is consequential/.test(r)));
  assert.equal(l.patchstack, 'standard', 'broken-access-control IS a patchstack accepted class — the lanes are independent');
});

test('lane: proposed CVSS applies only when computable', () => {
  const low = classifyLane({ reach: 'unauth', impactClass: 'sqli', installs: 100000, cvss: 3.9 });
  assert.equal(low.wordfenceEligible, false);
  assert.ok(low.reasons.some((r) => /CVSS 3\.9 < 4/.test(r)));
  const none = classifyLane({ reach: 'unauth', impactClass: 'sqli', installs: 100000 });
  assert.ok(none.reasons.some((r) => /no CVSS computable/.test(r) && /NOT a CVSS score/.test(r)), 'absence is a note, not a failure');
  assert.equal(none.wordfenceEligible, true);
});

test('lane: garbage input never throws — classified with reasons, never dropped', () => {
  for (const junk of [undefined, null, {}, { reach: 42, impactClass: null }]) {
    const l = classifyLane(junk);
    assert.equal(typeof l.wordfenceEligible, 'boolean');
    assert.ok(['standard', 'mvdp', 'none', 'unknown'].includes(l.patchstack));
    assert.ok(Array.isArray(l.reasons) && l.reasons.length > 0, 'every decision carries reasons');
  }
});

test('reachTier: privemap + reachprove vocabularies collapse to one ladder', () => {
  assert.equal(reachTier('UNAUTH'), 'unauth');
  assert.equal(reachTier('customer'), 'subscriber');
  assert.equal(reachTier('admin-gated'), 'admin');
  assert.equal(reachTier('SERVER'), 'server');
  assert.equal(reachTier('nonsense'), 'unknown');
});

// --- riskLevelForScore: the documented band mapping --------------------------------

test('riskLevelForScore: score bands, stepped down one level for contributor+ reach', () => {
  assert.equal(riskLevelForScore(50, 'unauth'), 'high');
  assert.equal(riskLevelForScore(49.99, 'subscriber'), 'medium');
  assert.equal(riskLevelForScore(9.9, 'unauth'), 'info');
  assert.equal(riskLevelForScore(80, 'admin-gated'), 'medium', 'high stepped down one level');
  assert.equal(riskLevelForScore(25, 'CONTRIBUTOR'), 'info', 'medium stepped down one level');
  assert.equal(riskLevelForScore(5, 'admin'), 'info', 'info stays info');
  assert.equal(riskLevelForScore(80, 'unknown'), 'high', 'unproven reach never adjusts (never penalize what cannot be proven)');
  assert.equal(riskLevelForScore(undefined, 'unauth'), 'info', 'garbage score floors to info');
});

// --- privemap integration: every candidate carries lane + riskLevel -----------------

const LANE_PLUGIN = PHP_OPEN + `
add_action('admin_init', 'lane_settings_save');
function lane_settings_save() {
    if (isset($_POST['lane_opts'])) {
        $opts = $_POST['lane_opts'];
        update_option('lane_settings', $opts);
    }
}

add_action('wp_ajax_nopriv_lane_fixed', 'lane_fixed');
function lane_fixed() {
    update_option('lane_built', 1);
    wp_die();
}

add_action('wp_ajax_lane_capped', 'lane_capped');
function lane_capped() {
    if (!current_user_can('manage_options')) {
        wp_die();
    }
    update_option('lane_cap', sanitize_text_field($_POST['v']));
}
`;

test('privemap: every candidate is lane-classified + risk-leveled (classify, never filter)', () => {
  const r = minePrivesc([rec('lane.php', LANE_PLUGIN)]);
  assert.ok(r.candidates.length >= 3, 'all three sinks surface');
  for (const c of r.candidates) {
    assert.ok(c.lane && typeof c.lane.wordfenceEligible === 'boolean', `lane on ${c.handler}`);
    assert.ok(['standard', 'mvdp', 'none', 'unknown'].includes(c.lane.patchstack), `patchstack value on ${c.handler}`);
    assert.ok(c.lane.reasons.length > 0, `reasons on ${c.handler}`);
    assert.ok(['high', 'medium', 'info'].includes(c.riskLevel), `riskLevel on ${c.handler}`);
  }

  const unauth = r.candidates.find((c) => c.handler === 'lane_settings_save');
  assert.equal(unauth.reachability, 'unauth');
  assert.equal(unauth.riskLevel, 'high', 'score-100 unauth finding bands high');
  assert.equal(unauth.lane.patchstack, 'standard', 'arbitrary-settings-change is accepted at unauth reach');
  assert.equal(unauth.lane.wordfenceEligible, false, 'installs unknown at mine time — ineligible until supplied');
  assert.ok(unauth.lane.reasons.some((x) => /install count UNKNOWN/.test(x)), 'the ONLY failing rule is the install floor');
  assert.ok(unauth.lane.reasons.some((x) => /consequential CIA impact/.test(x)), 'impact rule passed and named');

  const fixed = r.candidates.find((c) => c.handler === 'lane_fixed');
  assert.ok(fixed.degraded, 'fixed-value write still degraded by the miner');
  assert.equal(fixed.lane.wordfenceEligible, false);
  assert.ok(fixed.lane.reasons.some((x) => /NOT consequential/.test(x)), 'lane sees the degrade');
  assert.equal(fixed.riskLevel, 'medium', '13.5 bands medium; unauth reach does not step');

  const capped = r.candidates.find((c) => c.handler === 'lane_capped');
  assert.equal(capped.reachability, 'admin-gated');
  assert.equal(capped.lane.patchstack, 'none');
  assert.equal(capped.lane.wordfenceEligible, false);
  assert.ok(capped.lane.reasons.some((x) => /PR:H/.test(x)));
  assert.equal(capped.riskLevel, 'info', 'score-25 medium band stepped down for privileged reach');
});

// --- reachprove rescore integration: lane re-grades on the PROVEN reach -------------

test('reachprove rescore: results carry lane (proven reach) + riskLevel (penalized band)', () => {
  const model = buildReachabilityModel([
    rec('a.php', PHP_OPEN + `add_action('wp_ajax_nopriv_a', 'a_h');
function a_h() { update_option('a_opt', $_GET['v']); }
`),
    rec('c.php', PHP_OPEN + `add_action('wp_ajax_c2', 'c2_h');
function c2_h() {
    if (!current_user_can('edit_posts')) { wp_die(); }
    update_option('c2_opt', $_POST['v']);
}
`),
  ]);
  const out = rescoreCandidates(model, [
    { rank: 1, title: 'unauth option overwrite — a_h', ref: 'a.php:2', hook: 'wp_ajax_nopriv_a', handler: 'a_h', reachability: 'unauth', score: 50, impactClass: 'option-overwrite' },
    { rank: 2, title: 'unauth token-only gate — c2_h', ref: 'c.php:4', hook: 'wp_ajax_c2', handler: 'c2_h', reachability: 'unauth', score: 50, impactClass: 'token-compare' },
    { rank: 3, title: 'unlocatable — ghost', ref: 'g.php:1', hook: 'wp_ajax_ghost', handler: 'ghost', reachability: 'unauth', score: 50, impactClass: 'sqli' },
  ]);
  const byHandler = (h) => out.results.find((x) => x.handler === h);

  const confirmed = byHandler('a_h');
  assert.equal(confirmed.verdict, 'CONFIRMED');
  assert.equal(confirmed.riskLevel, 'high', 'score-50 unauth-confirmed bands high');
  assert.equal(confirmed.lane.patchstack, 'standard');
  assert.equal(confirmed.lane.wordfenceEligible, false, 'installs unknown — noted');
  assert.ok(confirmed.lane.reasons.length > 0);

  const contributor = byHandler('c2_h');
  assert.equal(contributor.verdict, 'DEGRADED');
  assert.equal(contributor.provenReach, 'CONTRIBUTOR');
  assert.equal(contributor.lane.patchstack, 'mvdp', 'lane re-grades on the PROVEN reach: contributor + broken-access-control → mVDP');
  assert.ok(contributor.lane.reasons.some((x) => /vendor-program-status needs scopecheck/.test(x)));
  assert.equal(contributor.riskLevel, 'info', 'penalized 22.5 bands medium, stepped down for contributor+ proven reach');

  const ghost = byHandler('ghost');
  assert.equal(ghost.verdict, 'UNCERTAIN');
  assert.equal(ghost.lane.patchstack, 'unknown', 'unproven reach — lane undecidable, still classified');
  assert.equal(ghost.lane.wordfenceEligible, false);
  assert.equal(ghost.riskLevel, 'high', 'score untouched and reach unproven — raw band, no step');
});

// --- AIOSEO two-tier capability lineage ----------------------------------------------

test('reachprove: AIOSEO lineage — aioseo_page_* is contributor-floor, other aioseo_* admin-floor, both CERTAIN', () => {
  const model = buildReachabilityModel([rec('aioseo.php', PHP_OPEN + `
add_action('wp_ajax_aioseo_save_page', 'aioseo_save_page');
function aioseo_save_page() {
    if (!current_user_can('aioseo_page_settings')) { wp_die(); }
    update_option('aioseo_page', $_POST['v']);
}

add_action('wp_ajax_aioseo_save_global', 'aioseo_save_global');
function aioseo_save_global() {
    if (!current_user_can('aioseo_manage_options')) { wp_die(); }
    update_option('aioseo_global', $_POST['v']);
}

add_action('wp_ajax_acme_custom', 'acme_custom');
function acme_custom() {
    if (!current_user_can('acme_custom_cap')) { wp_die(); }
    update_option('acme', $_POST['v']);
}
`)]);
  const entries = analyzeAll(model);
  const byHandler = (h) => entries.find((e) => e.entry.handler === h);

  // aioseo_page_*: granted to all edit_posts roles → CONTRIBUTOR, no longer uncertain.
  const page = byHandler('aioseo_save_page');
  assert.equal(page.verdict, 'CONTRIBUTOR', 'aioseo_page_* caps ride the edit_posts role map');
  const pageGate = page.evidenceChain.find((x) => x.kind === 'gate' && x.cap === 'aioseo_page_settings');
  assert.ok(pageGate, 'page-cap gate evidence present');
  assert.equal(pageGate.uncertain, false, 'lineaged cap is no longer ADMIN-uncertain');
  assert.match(pageGate.note, /AIOSEO two-tier capability lineage/, 'evidence names the lineage');
  assert.match(pageGate.note, /edit_posts roles/);

  // Any OTHER aioseo_* cap: the Access.php isAdmin short-circuit → ADMIN, certain.
  const global_ = byHandler('aioseo_save_global');
  assert.equal(global_.verdict, 'ADMIN');
  const globalGate = global_.evidenceChain.find((x) => x.kind === 'gate' && x.cap === 'aioseo_manage_options');
  assert.ok(globalGate);
  assert.equal(globalGate.uncertain, false);
  assert.match(globalGate.note, /isAdmin short-circuit/);

  // Control: an unmapped custom cap keeps the old ADMIN-uncertain fallback.
  const custom = byHandler('acme_custom');
  assert.equal(custom.verdict, 'ADMIN');
  const customGate = custom.evidenceChain.find((x) => x.kind === 'gate' && x.cap === 'acme_custom_cap');
  assert.equal(customGate.uncertain, true, 'unmapped caps stay flagged, never silently trusted');
});

test('lanes: patchstack dead classes + degraded primitives are program-wide OUT (GiveWP lesson)', () => {
  // A cronjob/scheduled-task class dies at any reach, even unauth with a big install count.
  const dead = classifyLane({ reach: 'unauth', vulnClass: 'cronjob-manipulation', installs: 500000, cvss: 6.5 });
  assert.equal(dead.patchstack, 'none');
  assert.ok(dead.reasons.some((r) => /§4\.2/.test(r) && /GiveWP/.test(r)));
  // A miner-degraded primitive (fixed-value/self-only) lands in the minor-impact band §4.2 rejects.
  const deg = classifyLane({ reach: 'subscriber', impactClass: 'option-overwrite', installs: 100000, degraded: 'fixed-value' });
  assert.equal(deg.patchstack, 'none');
  assert.ok(deg.reasons.some((r) => /miner-degraded/.test(r) && /§4\.2/.test(r)));
  // Control: the same shape undegraded still lands on the standard lane.
  const ok = classifyLane({ reach: 'subscriber', impactClass: 'option-overwrite', installs: 100000 });
  assert.equal(ok.patchstack, 'standard');
});
