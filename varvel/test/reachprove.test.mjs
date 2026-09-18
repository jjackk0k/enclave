// VARVEL reachprove tests — hermetic fixtures for the mechanical reachability
// adjudicator (engine/reachability.mjs + tools/reachprove.mjs): the fix for
// privemap's heuristic reachability burning AI adjudication on dead candidates.
// Verdicts are asserted MECHANICALLY from fixtures under test/fixtures/reachprove/ —
// UNKNOWN is a first-class verdict, KILLED requires never-remote proof.
//   node --test test/reachprove.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildReachabilityModel, analyzeAll, analyzeRegistration, findEntries, rescoreCandidates } from '../engine/reachability.mjs';
import { reachprove, reachproveEntry, reachproveRescore } from '../tools/reachprove.mjs';

const FIXTURES = 'test/fixtures/reachprove';

// Tool-level report (fs walk over the fixture dir), reused across tests.
const report = reachprove(FIXTURES);
const byHook = (hook, handler) => report.entries.find((e) => e.entry.hook === hook && (!handler || e.entry.handler === handler));

test('reachprove: wp_ajax_nopriv_* floor is UNAUTH with the registration in evidence', () => {
  const e = byHook('wp_ajax_nopriv_fixture_ping');
  assert.ok(e, 'entry found');
  assert.equal(e.verdict, 'UNAUTH');
  assert.equal(e.confidence, 'high');
  const reg = e.evidenceChain.find((x) => x.kind === 'registration');
  assert.ok(reg && /nopriv-ajax\.php:\d+$/.test(reg.ref), `registration evidence carries file:line — got ${reg && reg.ref}`);
});

test('reachprove: wp_ajax_* floor is SUBSCRIBER (authenticated, any role)', () => {
  const e = byHook('wp_ajax_fixture_save_note');
  assert.ok(e, 'entry found');
  assert.equal(e.verdict, 'SUBSCRIBER');
  assert.equal(e.confidence, 'high');
});

test('reachprove: admin_init + current_user_can(manage_options) degrades to ADMIN with gate evidence', () => {
  const e = byHook('admin_init');
  assert.ok(e, 'entry found');
  assert.equal(e.verdict, 'ADMIN');
  const gate = e.evidenceChain.find((x) => x.kind === 'gate' && x.cap === 'manage_options');
  assert.ok(gate, 'capability gate evidence present');
  assert.match(gate.note, /capability floor ADMIN/);
  assert.ok(/admin-init-capped\.php:\d+$/.test(gate.ref), `gate evidence carries file:line — got ${gate.ref}`);
});

test('reachprove: REST route with __return_true permission_callback is UNAUTH', () => {
  const e = byHook('rest_route', 'fixture_rest_ping');
  assert.ok(e, 'entry found');
  assert.equal(e.verdict, 'UNAUTH');
  assert.equal(e.confidence, 'high');
  assert.equal(e.entry.route, 'fixture/v1/public-ping');
  const pc = e.evidenceChain.find((x) => x.kind === 'permission-callback');
  assert.ok(pc && /__return_true/.test(pc.note), 'permission_callback evidence names __return_true');
});

test('reachprove: REST route with an is_user_logged_in closure gate is SUBSCRIBER', () => {
  const e = byHook('rest_route', 'fixture_rest_members');
  assert.ok(e, 'entry found');
  assert.equal(e.verdict, 'SUBSCRIBER');
  assert.equal(e.confidence, 'high');
  const pc = e.evidenceChain.find((x) => x.kind === 'permission-callback');
  assert.ok(pc && /closure/.test(pc.note), 'closure gate evidence present');
});

test('reachprove: cron-scheduled hook is SERVER (never remote) at high confidence', () => {
  const e = byHook('fixture_daily_cleanup');
  assert.ok(e, 'entry found');
  assert.equal(e.verdict, 'SERVER');
  assert.equal(e.confidence, 'high');
  assert.match(e.reason, /wp-cron scheduled-event hook/);
});

test('reachprove: ability with an inline manage_options permission_callback closure is ADMIN', () => {
  const e = byHook('wp_register_ability');
  assert.ok(e, 'entry found');
  assert.equal(e.verdict, 'ADMIN');
  assert.equal(e.entry.ability, 'fixture/regenerate-site');
  const pc = e.evidenceChain.find((x) => /current_user_can\('manage_options'\)/.test(x.note));
  assert.ok(pc, 'closure capability gate evidence present');
});

test('reachprove: unresolved external callback is UNKNOWN with the reason named (never fabricated)', () => {
  const e = byHook('wp_ajax_fixture_external');
  assert.ok(e, 'entry found');
  assert.equal(e.verdict, 'UNKNOWN');
  assert.match(e.reason, /not found in scanned sources/);
  assert.match(e.reason, /dynamic name|variable callback|outside the scanned tree/);
});

test('reachprove: tool wrapper reports stats/skipped/gaps without throwing on a missing dir', () => {
  const missing = reachprove('test/fixtures/reachprove-does-not-exist');
  assert.equal(missing.entries.length, 0);
  assert.ok(missing.skipped.length >= 1, 'unreadable root named in skipped[]');
  assert.ok(report.stats.registrations >= 9, `fixture registrations counted — got ${report.stats.registrations}`);
  assert.equal(report.stats.cronHooks, 1);
});

test('reachproveEntry: --entry by hook and by file:line locate the same registration', () => {
  const byName = reachproveEntry(FIXTURES, 'wp_ajax_nopriv_fixture_ping');
  assert.equal(byName.entries.length, 1);
  assert.equal(byName.entries[0].verdict, 'UNAUTH');
  const regRef = byName.entries[0].entry.registration; // root-relative by tool contract
  const byRef = reachproveEntry(FIXTURES, regRef);
  assert.equal(byRef.entries.length, 1);
  assert.equal(byRef.entries[0].verdict, 'UNAUTH');
  const unknown = reachproveEntry(FIXTURES, 'wp_ajax_no_such_hook');
  assert.equal(unknown.entries.length, 0);
  assert.match(unknown.notFound, /no registration matches/);
});

// --- rescore mode ---------------------------------------------------------------

test('rescore: dead candidates are DEGRADED/KILLED with penalized re-rank; honest ones CONFIRMED; unlocatable UNCERTAIN', () => {
  // A synthetic privemap report over the fixture tree (same candidate shape the
  // miner emits: ref/hook/handler/reachability/score).
  const privemapReport = {
    candidates: [
      { rank: 1, title: 'unauthenticated option overwrite — fixture_admin_settings_save (admin_init)', ref: 'admin-init-capped.php:8', hook: 'admin_init', handler: 'fixture_admin_settings_save', reachability: 'unauth', score: 90 },
      { rank: 2, title: 'unauthenticated arbitrary file delete — fixture_daily_cleanup_run (fixture_daily_cleanup)', ref: 'cron.php:6', hook: 'fixture_daily_cleanup', handler: 'fixture_daily_cleanup_run', reachability: 'unauth', score: 85 },
      { rank: 3, title: 'unauthenticated option overwrite — fixture_ping (wp_ajax_nopriv_fixture_ping)', ref: 'nopriv-ajax.php:4', hook: 'wp_ajax_nopriv_fixture_ping', handler: 'fixture_ping', reachability: 'unauth', score: 80 },
      { rank: 4, title: 'any-authenticated-user meta write — fixture_save_note (wp_ajax_fixture_save_note)', ref: 'ajax-auth.php:6', hook: 'wp_ajax_fixture_save_note', handler: 'fixture_save_note', reachability: 'subscriber', score: 40 },
      { rank: 5, title: 'unauthenticated option overwrite — dispatch (wp_ajax_fixture_external)', ref: 'external-callback.php:3', hook: 'wp_ajax_fixture_external', handler: 'dispatch', reachability: 'unauth', score: 70 },
    ],
  };
  const out = reachproveRescore(FIXTURES, privemapReport);
  const byHandler = (h) => out.results.find((r) => r.handler === h);

  // admin_init + manage_options: claimed unauth, proven ADMIN → DEGRADED, score cut.
  const adminInit = byHandler('fixture_admin_settings_save');
  assert.equal(adminInit.verdict, 'DEGRADED');
  assert.equal(adminInit.provenReach, 'ADMIN');
  assert.ok(adminInit.newScore < adminInit.privemapScore, `penalty applied (${adminInit.privemapScore}→${adminInit.newScore})`);
  assert.ok(adminInit.evidenceChain.some((x) => x.kind === 'gate'), 'evidence chain names the gate');

  // cron: never remote → KILLED, score collapsed to noise.
  const cron = byHandler('fixture_daily_cleanup_run');
  assert.equal(cron.verdict, 'KILLED');
  assert.equal(cron.provenReach, 'SERVER');
  assert.ok(cron.newScore <= 85 * 0.05 + 0.01, `killed score decayed (${cron.newScore})`);

  // nopriv ajax: claim matches proof → CONFIRMED, score intact.
  const ping = byHandler('fixture_ping');
  assert.equal(ping.verdict, 'CONFIRMED');
  assert.equal(ping.provenReach, 'UNAUTH');
  assert.equal(ping.newScore, ping.privemapScore);

  // subscriber ajax: claim matches → CONFIRMED.
  assert.equal(byHandler('fixture_save_note').verdict, 'CONFIRMED');

  // external callback: registration found but callback unresolvable → UNCERTAIN,
  // reason named, score untouched (never penalize what we cannot prove).
  const ext = byHandler('dispatch');
  assert.equal(ext.verdict, 'UNCERTAIN');
  assert.match(ext.reason, /not found in scanned sources/);
  assert.equal(ext.newScore, ext.privemapScore);

  // Summary + honest re-rank: the killed cron candidate falls out of the top.
  assert.deepEqual(out.summary, { CONFIRMED: 2, DEGRADED: 1, KILLED: 1, UNCERTAIN: 1 });
  assert.equal(out.results[0].handler, 'fixture_ping', 'confirmed nopriv candidate now ranks first');
  assert.equal(out.results[0].newRank, 1);
  assert.ok(byHandler('fixture_daily_cleanup_run').newRank > 3, 'killed candidate re-ranked to the bottom');
});

test('rescore: engine-level rescoreCandidates tolerates garbage input without throwing', () => {
  const model = buildReachabilityModel([{ path: 'wp-content/plugins/x/a.php', content: '<?php\nadd_action(\'wp_ajax_nopriv_a\', \'a_h\');\nfunction a_h() { update_option(\'a\', $_GET[\'v\']); }\n' }]);
  const out = rescoreCandidates(model, [{ hook: 'wp_ajax_nopriv_a', handler: 'a_h', reachability: 'unauth', score: 50, ref: 'a.php:3', rank: 1 }]);
  assert.equal(out.results[0].verdict, 'CONFIRMED');
  const empty = rescoreCandidates(model, null);
  assert.deepEqual(empty.summary, { CONFIRMED: 0, DEGRADED: 0, KILLED: 0, UNCERTAIN: 0 });
});

test('engine: analyzeAll over in-memory records (no fs) — CRLF tolerated, refs normalized', () => {
  const src = '<?php\r\nadd_action(\'wp_ajax_c\', \'c_h\');\r\nfunction c_h() {\r\n    if (!current_user_can(\'edit_posts\')) { wp_die(); }\r\n    update_option(\'c\', $_POST[\'v\']);\r\n}\r\n';
  const model = buildReachabilityModel([{ path: 'wp-content\\plugins\\c\\c.php', content: src }]);
  const entries = analyzeAll(model);
  assert.equal(entries.length, 1);
  assert.equal(entries[0].verdict, 'CONTRIBUTOR', 'wp_ajax_ + edit_posts gate → CONTRIBUTOR floor');
  assert.ok(!/\\/.test(entries[0].entry.registration), 'registration ref path normalized to forward slashes');
});

test('engine: PHP7 return-typed closure gates (static function (): bool) are parsed — the WP-core ability idiom', () => {
  const src = '<?php\nwp_register_ability(\'core/get-site-info\', array(\n    \'label\' => \'Get Site Info\',\n    \'execute_callback\' => static function ( $input ) {\n        return array();\n    },\n    \'permission_callback\' => static function (): bool {\n        return current_user_can( \'manage_options\' );\n    },\n));\n';
  const model = buildReachabilityModel([{ path: 'wp-includes/abilities.php', content: src }]);
  const [e] = analyzeAll(model);
  assert.equal(e.verdict, 'ADMIN', 'return-typed closure gate resolves to ADMIN, not absent');
  assert.match(e.reason, /closure enforces ADMIN/);
});

test('engine: unknown capability maps to ADMIN flagged uncertain; dynamic cap named honestly', () => {
  const model = buildReachabilityModel([{ path: 'wp-content/plugins/d/d.php', content: '<?php\nadd_action(\'wp_ajax_d\', \'d_h\');\nfunction d_h() {\n    if (current_user_can(\'acme_custom_cap\')) { update_option(\'d\', $_POST[\'v\']); }\n}\n' }]);
  const [e] = analyzeAll(model);
  assert.equal(e.verdict, 'ADMIN');
  const gate = e.evidenceChain.find((x) => x.kind === 'gate');
  assert.ok(gate.uncertain, 'custom cap flagged uncertain');
  assert.match(gate.note, /custom\/unmapped capability/);
});

// --- string static-method callbacks ('\FQN\Class::method') — the gosmtp/siteseo ---

test('reachprove: (a) ability gate as string static ref with leading backslash, same-file def -> ADMIN', () => {
  const e = report.entries.find((x) => x.entry.ability === 'acme/manage-settings');
  assert.ok(e, 'entry found');
  assert.equal(e.verdict, 'ADMIN');
  assert.equal(e.confidence, 'high');
  const cls = e.evidenceChain.find((x) => x.kind === 'permission-callback' && /class AbilityGate/.test(x.note));
  assert.ok(cls, 'class-resolution evidence present');
  assert.match(cls.note, /namespace Acme\\Tools/);
  const gate = e.evidenceChain.find((x) => x.kind === 'gate' && x.cap === 'manage_options');
  assert.ok(gate && /ability-static-string\.php:\d+$/.test(gate.ref), `gate evidence carries file:line — got ${gate && gate.ref}`);
});

test('reachprove: (b) REST permission_callback as bare string static ref, cross-file def -> CONTRIBUTOR', () => {
  const e = report.entries.find((x) => x.entry.route === 'fixture/v1/guarded');
  assert.ok(e, 'entry found');
  assert.equal(e.verdict, 'CONTRIBUTOR');
  assert.equal(e.confidence, 'high');
  const cls = e.evidenceChain.find((x) => x.kind === 'permission-callback' && /class PostGuard/.test(x.note));
  assert.ok(cls && /rest-static-ref-guard\.php:\d+$/.test(cls.ref), `class resolved cross-file — got ${cls && cls.ref}`);
  const gate = e.evidenceChain.find((x) => x.kind === 'gate' && x.cap === 'edit_posts');
  assert.ok(gate, 'edit_posts gate evidence present');
});

test('reachprove: (c) present-but-unresolvable string static gate is UNKNOWN — NEVER UNAUTH', () => {
  const e = report.entries.find((x) => x.entry.ability === 'acme/external-gated');
  assert.ok(e, 'entry found');
  assert.equal(e.verdict, 'UNKNOWN', 'a present-but-unreadable gate must never grade as public');
  assert.match(e.reason, /not found in scanned sources/);
  assert.match(e.reason, /Missing\\Vendor\\Gate/);
  // Rescore doctrine: the UNKNOWN proof maps to UNCERTAIN, score untouched.
  const out = reachproveRescore(FIXTURES, { candidates: [
    { rank: 1, title: 'unauthenticated option overwrite — acme_external_gated_run (wp_register_ability)', ref: 'ability-missing-gate.php:10', hook: 'wp_register_ability', handler: 'acme/external-gated', ability: 'acme/external-gated', reachability: 'unauth', score: 80 },
  ] });
  assert.equal(out.results[0].verdict, 'UNCERTAIN');
  assert.equal(out.results[0].newScore, 80, 'never penalize what cannot be proven');
});

test('reachprove: (d) REST permission_callback as a global-function string -> graded by its body (AUTHOR)', () => {
  const e = report.entries.find((x) => x.entry.route === 'fixture/v1/fn-gated');
  assert.ok(e, 'entry found');
  assert.equal(e.verdict, 'AUTHOR');
  assert.equal(e.confidence, 'high');
  const gate = e.evidenceChain.find((x) => x.kind === 'gate' && x.cap === 'upload_files');
  assert.ok(gate && /rest-gate-fn-def\.php:\d+$/.test(gate.ref), `cross-file function gate evidence — got ${gate && gate.ref}`);
});

test('reachprove: (item 5) add_action with a string static-method callback resolves class-oriented', () => {
  const e = byHook('wp_ajax_fixture_static');
  assert.ok(e, 'entry found');
  assert.equal(e.verdict, 'SUBSCRIBER', 'wp_ajax_ floor, no gates in the resolved method');
  const cls = e.evidenceChain.find((x) => x.kind === 'callback-def' && /class StaticHandler/.test(x.note));
  assert.ok(cls, 'class-resolution evidence present for the hook handler');
});

test('reachprove: unresolved string static handler on a hook is UNKNOWN with the class named', () => {
  const model = buildReachabilityModel([{ path: 'wp-content/plugins/s/s.php', content: '<?php\nadd_action(\'wp_ajax_s\', \'\\Acme\\Nope\\Handler::run\');\n' }]);
  const [e] = analyzeAll(model);
  assert.equal(e.verdict, 'UNKNOWN');
  assert.match(e.reason, /class 'Acme\\Nope\\Handler' not found in scanned sources/);
});


// --- nonce provenance (who can OBTAIN the nonce) — the second adjudication lesson ---

test('provenance (a): nonce-only ajax + nonce localized inside a manage_options-fenced enqueue -> ADMIN high', () => {
  const e = byHook('wp_ajax_fixture_np_save');
  assert.ok(e, 'entry found');
  assert.equal(e.verdict, 'ADMIN');
  assert.equal(e.confidence, 'high');
  // Full chain: registration → nonce check → emission site → emission guard.
  const check = e.evidenceChain.find((x) => x.kind === 'gate' && x.nonce);
  assert.ok(check && check.action === 'fixture_np_save', 'nonce check line carries the action');
  const emit = e.evidenceChain.find((x) => x.kind === 'nonce-emission');
  assert.ok(emit && /nonce-admin-enqueue\.php:\d+$/.test(emit.ref), `emission site evidence — got ${emit && emit.ref}`);
  const guard = e.evidenceChain.find((x) => x.kind === 'nonce-emission-guard' && /manage_options/.test(x.note));
  assert.ok(guard, 'emission guard evidence names manage_options');
});

test('provenance (b): nonce-only admin_post + wp_nonce_field template rendered only by a manage_options menu page -> ADMIN', () => {
  const e = byHook('admin_post_fixture_np_template_save');
  assert.ok(e, 'entry found');
  assert.equal(e.verdict, 'ADMIN');
  assert.equal(e.confidence, 'high');
  const emit = e.evidenceChain.find((x) => x.kind === 'nonce-emission');
  assert.ok(emit && /nonce-menu-template\.php:\d+$/.test(emit.ref), `template emission site — got ${emit && emit.ref}`);
  const referrer = e.evidenceChain.find((x) => x.kind === 'nonce-emission-guard' && /rendered from fixture_np_render_page/.test(x.note));
  assert.ok(referrer, 'template referrer evidence present');
  const menuGuard = e.evidenceChain.find((x) => x.kind === 'nonce-emission-guard' && /menu page 'fixture-np'.*manage_options/.test(x.note));
  assert.ok(menuGuard, 'menu capability evidence present');
});

test('provenance (c): nonce-only ajax + nonce emitted on wp_footer -> stays SUBSCRIBER with ANY-AUTH note', () => {
  const e = byHook('wp_ajax_fixture_np_public');
  assert.ok(e, 'entry found');
  assert.equal(e.verdict, 'SUBSCRIBER');
  assert.ok((e.notes || []).some((n) => /provenance ANY-AUTH/.test(n)), 'ANY-AUTH provenance note attached');
  assert.ok(e.evidenceChain.some((x) => x.kind === 'nonce-emission' && /nonce-frontend\.php/.test(x.ref)), 'emission evidence attached');
});

test('provenance (d): custom cap granted only to administrator fencing the localize -> ADMIN', () => {
  const e = byHook('wp_ajax_fixture_np_tpl');
  assert.ok(e, 'entry found');
  assert.equal(e.verdict, 'ADMIN');
  const guard = e.evidenceChain.find((x) => x.kind === 'nonce-emission-guard' && /manage_fixture_templates/.test(x.note));
  assert.ok(guard, 'custom-cap guard evidence present');
  assert.match(guard.note, /add_cap index/);
});

test('provenance (e): nonce emission not found in tree -> verdict unchanged + unresolved note (never penalized)', () => {
  const e = byHook('wp_ajax_nopriv_fixture_np_missing');
  assert.ok(e, 'entry found');
  assert.equal(e.verdict, 'SUBSCRIBER', 'nopriv + nonce-only doctrine floor, unchanged by unproven provenance');
  assert.ok((e.notes || []).some((n) => /provenance unresolved/.test(n) && /emission not found in-tree/.test(n)), 'unresolved note attached');
  assert.ok(!e.evidenceChain.some((x) => x.kind === 'nonce-emission'), 'no fabricated emission site');
});

test('provenance (f): nonce-only ajax + block-editor enqueue, no extra guard -> CONTRIBUTOR floor, not ADMIN', () => {
  const e = byHook('wp_ajax_fixture_np_block');
  assert.ok(e, 'entry found');
  assert.equal(e.verdict, 'CONTRIBUTOR');
  assert.ok((e.notes || []).some((n) => /ROLE-GATED provenance/.test(n)), 'ROLE-GATED provenance note attached');
});

test('provenance (g): screen-guarded enqueue + helper-indirection menu cap -> ADMIN (the wpmm shape)', () => {
  const e = byHook('wp_ajax_fixture_np_wizard');
  assert.ok(e, 'entry found');
  assert.equal(e.verdict, 'ADMIN');
  assert.equal(e.confidence, 'high');
  const screen = e.evidenceChain.find((x) => x.kind === 'nonce-emission-guard' && /menu page 'fixture-wizard'/.test(x.note));
  assert.ok(screen, 'screen-guard → menu capability evidence present');
});

test('provenance: rescore degrades a privemap subscriber candidate to ADMIN with the provenance chain', () => {
  const out = reachproveRescore(FIXTURES, { candidates: [
    { rank: 1, title: 'any-authenticated-user option overwrite — fixture_np_save (wp_ajax_fixture_np_save)', ref: 'nonce-admin-enqueue.php:7', hook: 'wp_ajax_fixture_np_save', handler: 'fixture_np_save', reachability: 'subscriber', score: 55 },
  ] });
  const r = out.results[0];
  assert.equal(r.verdict, 'DEGRADED');
  assert.equal(r.provenReach, 'ADMIN');
  assert.ok(r.newScore < r.privemapScore, 'penalty applied');
  assert.ok(r.evidenceChain.some((x) => x.kind === 'nonce-emission-guard'), 'rescore carries the provenance chain');
});

// --- registration-window regressions on the ADJUDICATOR side ---------------------------
// privemap ranks; reachprove convicts. These pin the mechanical adjudicator's honest
// behaviour where the miner's window can no longer see a gate: ignorance must resolve to
// UNKNOWN (UNCERTAIN, score untouched), never to the absent/public doctrine.

test('reachprove: a gate beyond the registration window resolves UNKNOWN — rescore stays UNCERTAIN, never penalized', () => {
  // The execute_callback is readable early; the permission_callback sits far past the
  // current window. The registration is ANALYZED (so no "not analyzed" shortcut), and the
  // gate's unreadability must surface as UNPARSED rather than as an absent gate.
  const pad = Array.from({ length: 520 }, (_, i) => `        'schema_${i}' => array('type' => 'string'),`).join('\n');
  const src = '<?php\n' + `
function fixture_shadow_register() {
    wp_register_ability('fixture/shadow', array(
        'execute_callback' => 'fixture_shadow_run',
${pad}
        'permission_callback' => 'fixture_shadow_gate',
    ));
}
function fixture_shadow_run($input) { update_option('fixture_shadow_value', $input['v']); }
function fixture_shadow_gate() { return current_user_can('manage_options'); }
`;
  const model = buildReachabilityModel([{ path: 'wp-content/plugins/shadow/shadow.php', content: src }]);
  const [e] = analyzeAll(model);

  assert.equal(e.verdict, 'UNKNOWN',
    'a window that cannot reach the gate is ignorance — never the absent/public doctrine');
  assert.notEqual(e.verdict, 'UNAUTH', 'NEVER UNAUTH: the gate is present, we simply could not read it');
  assert.match(e.reason, /not a resolvable callable literal|not found in scanned sources|present/,
    'the reason names the unreadable gate; got: ' + e.reason);

  // Rescore doctrine: UNKNOWN → UNCERTAIN with the score untouched (never penalize what
  // cannot be proven) — the fabricated unauth claim survives as a candidate but is not
  // mechanically elevated, so it can never reach a report as CONFIRMED.
  const out = rescoreCandidates(model, [{
    hook: 'wp_register_ability', handler: 'fixture/shadow', ability: 'fixture/shadow',
    reachability: 'unauth', score: 85, ref: 'wp-content/plugins/shadow/shadow.php:3', rank: 1,
  }]);
  assert.equal(out.results[0].verdict, 'UNCERTAIN');
  assert.equal(out.results[0].newScore, 85, 'UNKNOWN never penalizes');
});

test('reachprove: (window) a string-static gate proves its floor — the claim is DEGRADED, not merely UNCERTAIN', () => {
  // The teeth for the \FQN\Class::method parse: when the gate IS read, the adjudicator can
  // DEGRADE a fabricated unauth claim to the real floor. When it cannot be read, the same
  // claim stays UNCERTAIN (above). The difference is what makes the parse load-bearing.
  const src = '<?php\n' + String.raw`
function fixture_static_register() {
    wp_register_ability('fixture/static-gated', array(
        'label' => 'Static gate',
        'execute_callback' => '\Fixture\StaticGate::run',
        'permission_callback' => '\Fixture\StaticGate::can_edit',
        'meta' => array('mcp' => array('public' => true)),
    ));
}
`;
  const cls = '<?php\n' + String.raw`
namespace Fixture;
class StaticGate {
    public static function run($input) { update_option('fixture_static_value', $input['v']); }
    public static function can_edit() { return current_user_can('edit_posts'); }
}
`;
  const model = buildReachabilityModel([
    { path: 'wp-content/plugins/fixture/static-reg.php', content: src },
    { path: 'wp-content/plugins/fixture/static-gate.php', content: cls },
  ]);
  const out = rescoreCandidates(model, [{
    hook: 'wp_register_ability', handler: 'fixture/static-gated', ability: 'fixture/static-gated',
    reachability: 'unauth', score: 85, ref: 'wp-content/plugins/fixture/static-reg.php:2', rank: 1,
  }]);

  assert.equal(out.results[0].verdict, 'DEGRADED', 'a READ gate degrades the fabricated unauth claim');
  assert.equal(out.results[0].provenReach, 'CONTRIBUTOR', "edit_posts floor is proven from the string-static gate");
  assert.ok(out.results[0].newScore < 85, 'the claim is penalized to the proven floor');
  assert.match(out.results[0].reason, /enforces CONTRIBUTOR|prove CONTRIBUTOR/);
});

test('reachprove: the reason never contradicts a RAISED verdict (in-handler gates)', () => {
  // Measured defect: an __return_true route whose handler required a nonce reported
  // "route gate is __return_true — publicly reachable" while the VERDICT was SUBSCRIBER.
  // The base-gate reason describes the permission_callback ALONE, so passing it through
  // verbatim contradicted the verdict — an overclaim in the filing direction.
  const src = '<?php\n' + `
add_action('rest_api_init', 'fixture_register_raised');
function fixture_register_raised() {
    register_rest_route('fixture/v1', '/raised', array(
        'methods' => 'POST',
        'callback' => 'fixture_raised_handler',
        'permission_callback' => '__return_true',
    ));
}
function fixture_raised_handler($request) {
    if (!wp_verify_nonce($request->get_param('_wpnonce'), 'fixture_action')) {
        return new WP_Error('bad_nonce', 'nope', array('status' => 403));
    }
    update_option('fixture_raised_value', $request->get_param('value'));
}
`;
  const model = buildReachabilityModel([{ path: 'wp-content/plugins/raised/raised.php', content: src }]);
  const route = model.regs.find((r) => r.kind === 'rest');
  assert.ok(route, 'the REST route registration is found');
  const e = analyzeRegistration(model, route);

  assert.equal(e.verdict, 'SUBSCRIBER', 'the in-handler nonce raises the UNAUTH floor to SUBSCRIBER');
  assert.ok(!/publicly reachable/.test(e.reason),
    'a reason claiming public reachability must never ride a raised (non-UNAUTH) verdict; got: ' + e.reason);
  assert.match(e.reason, /RAISE|SUBSCRIBER/, 'the reason reflects the raised floor; got: ' + e.reason);
  // The base gate's detail is not lost — it stays in the evidence chain.
  const pc = e.evidenceChain.find((x) => x.kind === 'permission-callback');
  assert.ok(pc && /__return_true/.test(pc.note), 'the base gate remains in the evidence chain');
});

test('rescore: a non-CONFIRMED verdict supersedes the title claim (the report headline)', () => {
  // A report's headline is `label || title` (tools/bountyreport.mjs), so a DEGRADED
  // candidate whose title still opens "unauthenticated …" keeps asserting the reach the
  // verdict just refuted. Measured on ai-engine: the rescored #1 was a SUBSCRIBER verdict
  // under the headline "unauthenticated option overwrite (site-wide config)".
  const src = '<?php\n' + `
add_action('rest_api_init', 'fixture_register_two');
function fixture_register_two() {
    register_rest_route('fixture/v1', '/raised', array(
        'methods' => 'POST',
        'callback' => 'fixture_two_raised',
        'permission_callback' => '__return_true',
    ));
    register_rest_route('fixture/v1', '/open', array(
        'methods' => 'POST',
        'callback' => 'fixture_two_open',
        'permission_callback' => '__return_true',
    ));
}
function fixture_two_raised($request) {
    if (!wp_verify_nonce($request->get_param('_wpnonce'), 'fixture_two')) {
        return new WP_Error('bad_nonce', 'nope', array('status' => 403));
    }
    update_option('fixture_two_value', $request->get_param('value'));
}
function fixture_two_open($request) {
    update_option('fixture_two_open_value', $request->get_param('value'));
}
`;
  const model = buildReachabilityModel([{ path: 'wp-content/plugins/two/two.php', content: src }]);
  const RAISED = 'unauthenticated option overwrite — fixture_two_raised (rest_route)';
  const OPEN = 'unauthenticated option overwrite — fixture_two_open (rest_route)';
  const out = rescoreCandidates(model, [
    { rank: 1, title: RAISED, ref: 'wp-content/plugins/two/two.php:2', hook: 'rest_route', handler: 'fixture_two_raised', reachability: 'unauth', score: 60, impactClass: 'option-overwrite' },
    { rank: 2, title: OPEN, ref: 'wp-content/plugins/two/two.php:8', hook: 'rest_route', handler: 'fixture_two_open', reachability: 'unauth', score: 55, impactClass: 'option-overwrite' },
  ]);
  const raised = out.results.find((r) => r.handler === 'fixture_two_raised');
  const open = out.results.find((r) => r.handler === 'fixture_two_open');
  assert.ok(raised && open, 'both routes adjudicate');

  assert.equal(raised.verdict, 'DEGRADED', 'the nonce raises the floor, so the unauth claim degrades');
  assert.match(raised.title, /^\[DEGRADED: proven reach SUBSCRIBER, privemap claimed 'unauth'\]/,
    'the headline leads with the adjudication, not the refuted claim; got: ' + raised.title);
  assert.ok(raised.title.includes(RAISED), 'the original claim text is retained verbatim for traceability');

  // Mirror control: a genuinely unauth verdict keeps its title untouched — the marker is
  // not blanket, so it still MEANS something when it appears.
  assert.equal(open.verdict, 'CONFIRMED', 'the ungated route stays CONFIRMED unauth');
  assert.equal(open.title, OPEN, 'a CONFIRMED verdict never rewrites the title');
});

test('reachprove: the OBJECT-form capability check user_can($requester, …) is a real gate', () => {
  // Measured on SureTriggers 1.x (100k+ installs, src/Controllers/RestController.php:89): a
  // __return_true REST route whose handler self-authenticates and then demands an
  // administrator, adjudicated as CONFIRMED / UNAUTH / high — "unauthenticated option
  // overwrite (site-wide config)", the exact gold shape a triager accepts. The code:
  //     $user = wp_authenticate_application_password( null, $u, $p );
  //     if ( ! user_can( $user, 'administrator' ) ) return 403;
  // user_can( $user, 'cap' ) is WP's object form of current_user_can — it was simply not in
  // the gate vocabulary, so the floor stayed at the route's __return_true.
  const src = '<?php\n' + `
add_action('rest_api_init', 'fixture_register_obj');
function fixture_register_obj() {
    register_rest_route('fixture/v1', '/connect', array(
        'methods' => 'POST',
        'callback' => 'fixture_obj_connect',
        'permission_callback' => '__return_true',
    ));
    register_rest_route('fixture/v1', '/chosen', array(
        'methods' => 'POST',
        'callback' => 'fixture_obj_chosen',
        'permission_callback' => '__return_true',
    ));
    register_rest_route('fixture/v1', '/own', array(
        'methods' => 'POST',
        'callback' => 'fixture_obj_own',
        'permission_callback' => '__return_true',
    ));
}
function fixture_obj_connect($request) {
    $username = $request->get_param('u');
    $password = $request->get_param('p');
    $user = wp_authenticate_application_password( null, $username, $password );
    if ( ! user_can( $user, 'administrator' ) ) {
        return new WP_Error('nope', 'nope', array('status' => 403));
    }
    update_option('fixture_obj_value', $request->get_param('v'));
}
function fixture_obj_chosen($request) {
    $target = $request->get_param('uid');
    if ( ! user_can( $target, 'administrator' ) ) {
        return new WP_Error('nope', 'nope', array('status' => 403));
    }
    update_option('fixture_chosen_value', $request->get_param('v'));
}
function fixture_obj_own($request) {
    $me = wp_get_current_user();
    if ( ! user_can( $me, 'edit_posts' ) ) {
        return new WP_Error('nope', 'nope', array('status' => 403));
    }
    update_option('fixture_own_value', $request->get_param('v'));
}
`;
  const model = buildReachabilityModel([{ path: 'wp-content/plugins/ob/ob.php', content: src }]);
  const byHandler = (h) => analyzeAll(model).find((e) => e.entry.handler === h);

  // (1) requester resolved from the request's own credentials → a real role gate.
  const connect = byHandler('fixture_obj_connect');
  assert.equal(connect.verdict, 'ADMIN',
    'user_can($user, …) with $user from wp_authenticate_application_password gates the REQUEST');
  assert.match(connect.reason, /user_can\('administrator'\)/,
    'the reason names the object FORM it read, not current_user_can(); got: ' + connect.reason);

  // (2) MIRROR CONTROL — the same call against a CHOSEN id is NOT a gate on the requester:
  // checking someone else's capability must never be credited as if the caller needed it
  // (that would be a false negative hiding a real unauth write).
  const chosen = byHandler('fixture_obj_chosen');
  assert.equal(chosen.verdict, 'UNAUTH',
    'user_can(<attacker-chosen id>, …) is not a requester gate — the floor stays UNAUTH');

  // (3) MIRROR CONTROL — the current-user object resolves the requester too, and role names
  // map through the capability table (edit_posts → CONTRIBUTOR), not to ADMIN-uncertain.
  const own = byHandler('fixture_obj_own');
  assert.equal(own.verdict, 'CONTRIBUTOR', 'wp_get_current_user() + user_can($me, edit_posts) → CONTRIBUTOR');

  // End-to-end: the miner's UNAUTH claim is now DEGRADED by the adjudicator instead of
  // confirmed — the filing-grade false positive is gone.
  const out = rescoreCandidates(model, [{
    rank: 1, title: 'unauthenticated option overwrite — fixture_obj_connect (rest_route)',
    ref: 'wp-content/plugins/ob/ob.php:2', hook: 'rest_route', handler: 'fixture_obj_connect',
    reachability: 'unauth', score: 90, impactClass: 'option-overwrite',
  }]);
  assert.equal(out.results[0].verdict, 'DEGRADED', 'the unauth claim no longer resolves');
  assert.equal(out.results[0].provenReach, 'ADMIN');
  assert.ok(out.results[0].newScore < 90, 'and it is penalized to the proven floor');
});
