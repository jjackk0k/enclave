// VARVEL privemap tests — hermetic fixtures for the privesc/impact-primitive miner
// (engine/privemap.mjs + tools/privemap.mjs), plus a calibration soak over the Madara
// mirror: the method's acceptance test is that the three hand-found madara-core sinks
// (unauth option overwrite, unauth unlink, any-user meta write) rank in the TOP 10.
//   node --test test/privemap.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, writeFileSync, rmSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { minePrivesc } from '../engine/privemap.mjs';
import { privemap } from '../tools/privemap.mjs';

const PHP_OPEN = '<?php\n';

// (a) The vulnerable-plugin fixture: the three provenance classes in one file.
const VULN_PLUGIN = PHP_OPEN + `
add_action('admin_init', 'vuln_settings_save');
function vuln_settings_save() {
    if (isset($_POST['vuln_opts'])) {
        $opts = $_POST['vuln_opts'];
        update_option('vuln_settings', $opts);
    }
}

add_action('wp_ajax_nopriv_vuln_delete_zip', 'vuln_delete_zip');
function vuln_delete_zip() {
    $target = $_POST['zipPath'];
    unlink($target);
    wp_die();
}

add_action('wp_ajax_vuln_save_player', 'vuln_save_player');
function vuln_save_player() {
    $ids = array($_POST['playerID']);
    update_user_meta($_POST['userID'], '_player_id', $ids);
    wp_send_json_success();
}
`;

// (b) The safe-plugin fixture: nonce + capability + login checks everywhere.
const SAFE_PLUGIN = PHP_OPEN + `
add_action('wp_ajax_safe_save', 'safe_save');
function safe_save() {
    check_ajax_referer('safe_save_nonce');
    if (!current_user_can('manage_options')) {
        wp_die('nope');
    }
    update_option('safe_key', sanitize_text_field($_POST['val']));
}

add_action('wp_ajax_safe_profile', 'safe_profile');
function safe_profile() {
    if (!is_user_logged_in()) {
        wp_die();
    }
    check_ajax_referer('safe_profile_nonce');
    $uid = get_current_user_id();
    update_user_meta($uid, '_last_seen', time());
}
`;

// (c) Mitigation-downgrade fixture: same sink, three shielding levels.
const MITIGATION_PLUGIN = PHP_OPEN + `
add_action('wp_ajax_nopriv_m_open', 'm_open');
function m_open() {
    $f = $_POST['f'];
    unlink($f);
}

add_action('wp_ajax_nopriv_m_nonce', 'm_nonce');
function m_nonce() {
    check_ajax_referer('m_nonce');
    $f = $_POST['f'];
    unlink($f);
}

add_action('wp_ajax_nopriv_m_cap', 'm_cap');
function m_cap() {
    if (!current_user_can('manage_options')) {
        wp_die();
    }
    $f = $_POST['f'];
    unlink($f);
}
`;

const rec = (name, content) => ({ path: `wp-content/plugins/fixture/${name}`, content });

// --- AI-feature attack surface fixtures (the AI Engine MCP-endpoint bounty class) ----

// (d) MCP SSE bridge with a stdio spawn + an agent REST route gated ONLY by a bearer
// token compared ==/strcmp against an option-stored key (the $2,145 AI Engine shape).
const AI_PLUGIN = PHP_OPEN + `
register_rest_route('mcp/v1', '/sse', array(
    'methods' => 'GET',
    'callback' => 'mcp_sse_bridge',
    'permission_callback' => '__return_true',
));
function mcp_sse_bridge() {
    header('Content-Type: text/event-stream');
    $method = $_POST['method'];
    if ($method === 'tools/call') {
        $descriptors = array();
        $proc = proc_open($_POST['server_cmd'], $descriptors, $pipes);
    }
    echo "data: {}\\n\\n";
}

register_rest_route('ai/v1', '/agent/chat', array(
    'methods' => 'POST',
    'callback' => 'ai_agent_chat',
    'permission_callback' => 'ai_agent_check_key',
));
function ai_agent_check_key() {
    $token = isset($_SERVER['HTTP_AUTHORIZATION']) ? $_SERVER['HTTP_AUTHORIZATION'] : '';
    $token = trim(str_replace('Bearer', '', $token));
    if (strcmp($token, get_option('ai_agent_api_key')) === 0) {
        return true;
    }
    return false;
}
function ai_agent_chat() {
    $prompt = $_POST['prompt'];
    update_option('ai_agent_last_prompt', $prompt);
    wp_send_json_success();
}
`;

// (e) Safe AI surface: capability-checked permission callback, plus a hash_equals gate
// (timing-safe token comparison is deliberately NOT flagged).
const AI_SAFE_PLUGIN = PHP_OPEN + `
register_rest_route('ai/v1', '/admin/models', array(
    'callback' => 'ai_admin_models',
    'permission_callback' => 'ai_admin_check',
));
function ai_admin_check() {
    return current_user_can('manage_options');
}
function ai_admin_models() {
    update_option('ai_models', sanitize_text_field($_POST['models']));
}

register_rest_route('ai/v1', '/hashcheck/ping', array(
    'callback' => 'ai_hashcheck_ping',
    'permission_callback' => 'ai_hashcheck_key',
));
function ai_hashcheck_key($request) {
    $presented = $request->get_header('x-api-key');
    return hash_equals(get_option('ai_hashcheck_key'), $presented);
}
function ai_hashcheck_ping() {
    update_option('ai_hashcheck_seen', $request->get_param('n'));
}
`;

// (f) Closure permission_callback returning true (modern open-gate shape) writing a
// credential-named option.
const AI_CLOSURE_PLUGIN = PHP_OPEN + `
register_rest_route('agent/v1', '/config', array(
    'callback' => 'agent_config',
    'permission_callback' => function () { return true; },
));
function agent_config() {
    $key = $_POST['api_key'];
    update_option('agent_api_key', $key);
}
`;

// (g) init-hook reachability: a request-driven init handler (the Madara imgur
// _get_token shape) versus a bootstrap-only init handler (not attack surface).
const INIT_PLUGIN = PHP_OPEN + `
add_action('init', 'plugin_get_token');
function plugin_get_token() {
    if (isset($_GET['access_token'])) {
        update_option('plugin_refreshToken', $_GET['access_token']);
    }
}

add_action('init', 'plugin_bootstrap');
function plugin_bootstrap() {
    update_option('plugin_bootstrapped', 1);
}
`;

// --- WP 6.9 Abilities-API / MCP-Adapter fixtures (the WP-native layer of the AI Engine
// bounty class: the adapter exposes meta.mcp.public abilities as MCP tools and gates ONLY
// on each ability's own permission_callback) -------------------------------------------

// (h) The full gate/exposure matrix in one plugin: open gate unexposed, open+mcp.public,
// absent gate+mcp.public, token-only gate+mcp.public, SOUND gate+mcp.public (not flagged),
// show_in_rest+return-true closure, and a closure execute_callback (gate flagged from the
// registration args alone).
const ABILITY_PLUGIN = PHP_OPEN + `
add_action('wp_abilities_api_init', 'fixture_register_abilities');
function fixture_register_abilities() {
    wp_register_ability('fixture/write-setting', array(
        'label' => 'Write setting',
        'description' => 'Writes an option.',
        'category' => 'site',
        'input_schema' => array('type' => 'object'),
        'output_schema' => array('type' => 'object'),
        'execute_callback' => 'fixture_ability_write_setting',
        'permission_callback' => '__return_true',
    ));
    wp_register_ability('fixture/delete-file', array(
        'label' => 'Delete file',
        'description' => 'Deletes a file.',
        'category' => 'site',
        'execute_callback' => 'fixture_ability_delete_file',
        'permission_callback' => '__return_true',
        'meta' => array(
            'mcp' => array('public' => true),
        ),
    ));
    wp_register_ability('fixture/spawn-task', array(
        'label' => 'Spawn',
        'description' => 'Spawns a task.',
        'category' => 'site',
        'execute_callback' => 'fixture_ability_spawn',
        'meta' => array('mcp' => array('public' => true)),
    ));
    wp_register_ability('fixture/run-prompt', array(
        'label' => 'Run prompt',
        'description' => 'Runs a prompt.',
        'category' => 'site',
        'execute_callback' => 'fixture_ability_prompt',
        'permission_callback' => 'fixture_ability_check_token',
        'meta' => array('mcp' => array('public' => true)),
    ));
    wp_register_ability('fixture/admin-info', array(
        'label' => 'Admin info',
        'description' => 'Admin only.',
        'category' => 'site',
        'execute_callback' => 'fixture_ability_admin_info',
        'permission_callback' => 'fixture_ability_admin_gate',
        'meta' => array('mcp' => array('public' => true)),
    ));
    wp_register_ability('fixture/rest-exposed', array(
        'label' => 'Rest exposed',
        'description' => 'REST run endpoint.',
        'category' => 'site',
        'execute_callback' => 'fixture_ability_rest',
        'permission_callback' => function () { return true; },
        'meta' => array('show_in_rest' => true),
    ));
    wp_register_ability('fixture/closure-exec', array(
        'label' => 'Closure exec',
        'description' => 'Closure executor.',
        'category' => 'site',
        'execute_callback' => function ($input) { update_option('fixture_closure', $input['v']); },
        'permission_callback' => '__return_true',
        'meta' => array('mcp' => array('public' => true)),
    ));
}
function fixture_ability_write_setting($input) {
    update_option('fixture_setting', $input['value']);
}
function fixture_ability_delete_file($input) {
    $path = $input['path'];
    unlink($path);
}
function fixture_ability_spawn($input) {
    $descriptors = array();
    $proc = proc_open($input['cmd'], $descriptors, $pipes);
}
function fixture_ability_check_token() {
    $token = isset($_SERVER['HTTP_AUTHORIZATION']) ? $_SERVER['HTTP_AUTHORIZATION'] : '';
    if (strcmp(trim(str_replace('Bearer', '', $token)), get_option('fixture_mcp_key')) === 0) {
        return true;
    }
    return false;
}
function fixture_ability_prompt($input) {
    update_option('fixture_last_prompt', $input['prompt']);
}
function fixture_ability_admin_gate() {
    return current_user_can('manage_options');
}
function fixture_ability_admin_info($input) {
    update_option('fixture_admin_seen', $input['n']);
}
function fixture_ability_rest($input) {
    update_option('fixture_rest', $input['v']);
}
`;

// (i) REST short-array callbacks: `[ $this, 'method' ]` handler + gate resolved and
// credited, `[ self::class, 'm' ]` / `[ Gate::class, 'm' ]` class-const forms, and an
// INDIRECT named gate (has_permission → FA_Helper::has_cap → current_user_can, the
// Rank Math content-ai idiom) credited through the bounded gate descent.
const SHORT_ARRAY_PLUGIN = PHP_OPEN + `
class FA_Rest_Controller {
    public function register_routes() {
        register_rest_route('fixture/v1', '/short-array', array(
            'callback' => [ $this, 'save_setting' ],
            'permission_callback' => [ $this, 'can_manage' ],
        ));
        register_rest_route('fixture/v1', '/class-const', array(
            'callback' => [ self::class, 'do_class_thing' ],
            'permission_callback' => [ FA_Gate::class, 'gate_class_thing' ],
        ));
        register_rest_route('fixture/v1', '/indirect', array(
            'callback' => [ $this, 'save_indirect' ],
            'permission_callback' => [ $this, 'has_permission' ],
        ));
    }
    public function save_setting() {
        update_option('fa_short', sanitize_text_field($_POST['v']));
    }
    public function can_manage() {
        return current_user_can('manage_options');
    }
    public function do_class_thing() {
        update_option('fa_class', sanitize_text_field($_POST['v']));
    }
    public function save_indirect() {
        update_option('fa_indirect', sanitize_text_field($_POST['v']));
    }
    public function has_permission() {
        if ( ! FA_Helper::has_cap( 'things' ) ) {
            return false;
        }
        return true;
    }
}
class FA_Gate {
    public static function gate_class_thing() {
        return current_user_can('edit_posts');
    }
}
class FA_Helper {
    public static function has_cap( $cap ) {
        return current_user_can( 'manage_options' );
    }
}
`;

// (j) Inline closure permission gates: capability-bearing function/arrow closures are
// credited like named callbacks; a return-true arrow closure stays open; an opaque
// closure is reported 'not analyzed' instead of misread as absent.
const CLOSURE_GATE_PLUGIN = PHP_OPEN + `
register_rest_route('fixture/v1', '/closure-cap', array(
    'callback' => 'fc_cap_handler',
    'permission_callback' => function () { return current_user_can( 'manage_options' ); },
));
function fc_cap_handler() {
    update_option('fc_cap', sanitize_text_field($_POST['v']));
}

register_rest_route('fixture/v1', '/closure-arrow', array(
    'callback' => 'fc_arrow_handler',
    'permission_callback' => fn() => current_user_can('edit_posts'),
));
function fc_arrow_handler() {
    update_option('fc_arrow', sanitize_text_field($_POST['v']));
}

register_rest_route('fixture/v1', '/closure-open', array(
    'callback' => 'fc_open_handler',
    'permission_callback' => fn() => true,
));
function fc_open_handler() {
    update_option('fc_open', sanitize_text_field($_POST['v']));
}

register_rest_route('fixture/v1', '/closure-unknown', array(
    'callback' => 'fc_unknown_handler',
    'permission_callback' => function () { return fc_custom_check(); },
));
function fc_unknown_handler() {
    update_option('fc_unknown', sanitize_text_field($_POST['v']));
}
function fc_custom_check() {
    return get_option('fc_toggle') === 'yes';
}

register_rest_route('fixture/v1', '/unresolvable', array(
    'callback' => [ $this, $method ],
    'permission_callback' => '__return_true',
));
`;

test('REST short-array callbacks: [ $this, m ] / [ Class::class, m ] resolved, scanned, gate-credited', () => {
  const r = minePrivesc([rec('short.php', SHORT_ARRAY_PLUGIN)]);

  const short = r.candidates.find((c) => c.route === 'fixture/v1/short-array');
  assert.ok(short, 'short-array handler sink surfaces');
  assert.equal(short.impactClass, 'option-overwrite');
  assert.equal(short.handler, 'save_setting', '[ $this, \'save_setting\' ] resolves to the method name');
  assert.equal(short.reachability, 'admin-gated', '[ $this, \'can_manage\' ] gate resolves and credits current_user_can');
  assert.ok(short.mitigations.some((m) => /permission_callback current_user_can/.test(m)));

  const klass = r.candidates.find((c) => c.route === 'fixture/v1/class-const');
  assert.ok(klass, 'class-const handler sink surfaces');
  assert.equal(klass.handler, 'do_class_thing', '[ self::class, \'m\' ] resolves to the method name');
  assert.equal(klass.reachability, 'admin-gated', '[ FA_Gate::class, \'m\' ] gate resolves and credits');
  assert.ok(klass.mitigations.some((m) => /permission_callback current_user_can/.test(m)));

  const indirect = r.candidates.find((c) => c.route === 'fixture/v1/indirect');
  assert.ok(indirect, 'indirect-gate handler sink surfaces');
  assert.equal(indirect.reachability, 'admin-gated', 'has_permission -> FA_Helper::has_cap -> current_user_can credits the gate');
  assert.ok(indirect.mitigations.some((m) => /permission_callback current_user_can \(via has_permission -> has_cap\)/.test(m)),
    'descended credit names the chain; got: ' + JSON.stringify(indirect.mitigations));

  assert.ok(!r.gaps.some((g) => /short\.php/.test(g.ref)), 'no gaps for resolvable short-array registrations');
});

test('REST closure permission gates: capability closures credited, return-true stays open, opaque stays unknown', () => {
  const r = minePrivesc([rec('closure.php', CLOSURE_GATE_PLUGIN)]);

  const cap = r.candidates.find((c) => c.route === 'fixture/v1/closure-cap');
  assert.ok(cap);
  assert.equal(cap.reachability, 'admin-gated', 'function(){ return current_user_can(...) } closure gates the route');
  assert.ok(cap.mitigations.some((m) => /permission_callback current_user_can/.test(m)));

  const arrow = r.candidates.find((c) => c.route === 'fixture/v1/closure-arrow');
  assert.ok(arrow);
  assert.equal(arrow.reachability, 'admin-gated', 'fn() => current_user_can(...) arrow closure gates the route');

  const open = r.candidates.find((c) => c.route === 'fixture/v1/closure-open');
  assert.ok(open);
  assert.equal(open.reachability, 'unauth', 'fn() => true closure is an open gate (agent-92 behavior kept)');
  assert.ok(open.mitigations.some((m) => /closure returns true/.test(m)));

  const unknown = r.candidates.find((c) => c.route === 'fixture/v1/closure-unknown');
  assert.ok(unknown);
  assert.equal(unknown.reachability, 'unknown', 'opaque closure gate is not graded');
  assert.ok(unknown.mitigations.some((m) => /inline gate not analyzed/.test(m)),
    'honest note, not "absent": ' + JSON.stringify(unknown.mitigations));

  // Unresolvable callback shapes are an honest gap, never a crash.
  assert.ok(r.gaps.some((g) => /closure\.php:\d+/.test(g.ref) && /closure\/unresolvable callback/.test(g.reason)),
    '[ $this, $method ] reports as a gap');
  const restGaps = r.gaps.filter((g) => /closure\.php/.test(g.ref));
  assert.equal(restGaps.length, 1, 'exactly the one unresolvable registration gaps');
});


test('vulnerable fixture: ranks option-overwrite > unlink > meta-write, with expected reachability/class', () => {
  const r = minePrivesc([rec('vuln.php', VULN_PLUGIN)]);
  assert.equal(r.candidates.length, 3, JSON.stringify(r.candidates.map((c) => [c.impactClass, c.handler])));

  const [a, b, c] = r.candidates;
  assert.equal(a.rank, 1);
  assert.equal(a.impactClass, 'option-overwrite');
  assert.equal(a.reachability, 'unauth'); // admin_init fires for unauthenticated admin-ajax.php requests
  assert.equal(a.sev, 'crit');
  assert.equal(a.handler, 'vuln_settings_save');
  assert.match(a.ref, /vuln\.php:\d+$/);
  assert.match(a.evidence, /update_option/);

  assert.equal(b.rank, 2);
  assert.equal(b.impactClass, 'file-delete');
  assert.equal(b.reachability, 'unauth'); // wp_ajax_nopriv_*
  assert.equal(b.sev, 'crit');
  assert.equal(b.doctrineGated, true, 'destructive classes are doctrine-gated');

  assert.equal(c.rank, 3);
  assert.equal(c.impactClass, 'meta-write');
  assert.equal(c.reachability, 'subscriber'); // wp_ajax_* — any authenticated role
  assert.match(c.title, /any-user meta write/, 'attacker-chosen user id is called out');
  assert.equal(c.sev, 'high');

  // Probes are read-only/version-discriminator suggestions, NEVER payloads.
  for (const cand of r.candidates) {
    assert.match(cand.probe, /READ-ONLY|DOCTRINE-GATED|LOW-PRIV/i);
    assert.doesNotMatch(cand.probe, /unlink\(|DROP TABLE|UNION SELECT/i);
  }
  assert.ok(a.score > b.score && b.score > c.score, 'rank scores strictly ordered');
});

test('safe fixture: nonces + capability checks suppress crit/high and gate reachability', () => {
  const r = minePrivesc([rec('safe.php', SAFE_PLUGIN)]);
  assert.ok(r.candidates.length >= 1, 'sinks still surface, floor-ranked');
  for (const c of r.candidates) {
    assert.ok(['med', 'low', 'info'].includes(c.sev), `no high/crit from a gated handler, got ${c.sev} (${c.handler})`);
    assert.notEqual(c.reachability, 'unauth', 'nothing reads unauthenticated');
  }
  const optWrite = r.candidates.find((c) => c.impactClass === 'option-overwrite');
  assert.equal(optWrite.reachability, 'admin-gated', 'current_user_can gates the option write');
  assert.ok(optWrite.mitigations.some((m) => m.startsWith('current_user_can')));
  assert.ok(optWrite.mitigations.some((m) => m.startsWith('check_ajax_referer')));
  const metaWrite = r.candidates.find((c) => c.impactClass === 'meta-write');
  assert.ok(!/any-user/.test(metaWrite.title), 'self-write is not upgraded to any-user');
});

test('mitigation downgrade: bare nopriv > nonce-checked nopriv > capability-checked nopriv', () => {
  const r = minePrivesc([rec('mit.php', MITIGATION_PLUGIN)]);
  const byHandler = Object.fromEntries(r.candidates.map((c) => [c.handler, c]));
  assert.equal(byHandler.m_open.reachability, 'unauth');
  assert.equal(byHandler.m_nonce.reachability, 'subscriber', 'nonce check requires an authenticated session');
  assert.ok(byHandler.m_nonce.mitigations.some((m) => m.startsWith('check_ajax_referer')));
  assert.equal(byHandler.m_cap.reachability, 'admin-gated', 'capability check gates the handler');
  assert.ok(byHandler.m_open.score > byHandler.m_nonce.score, 'nonce downgrades score');
  assert.ok(byHandler.m_nonce.score > byHandler.m_cap.score, 'capability downgrades further');
});

test('AI MCP endpoint: unauth SSE bridge ranks exposure + stdio spawn, surface-tagged', () => {
  const r = minePrivesc([rec('ai.php', AI_PLUGIN)]);
  const mcp = r.candidates.filter((c) => c.handler === 'mcp_sse_bridge');

  const spawn = mcp.find((c) => c.impactClass === 'cmd-spawn');
  assert.ok(spawn, 'proc_open stdio bridge surfaces');
  assert.equal(spawn.reachability, 'unauth'); // permission_callback __return_true
  assert.equal(spawn.taint, 'direct', 'command argument comes straight from $_POST');
  assert.equal(spawn.sev, 'crit');
  assert.equal(spawn.doctrineGated, true, 'command spawn is doctrine-gated');
  assert.equal(spawn.surface, 'ai', 'candidate carries the AI surface tag');
  assert.equal(spawn.route, 'mcp/v1/sse');

  const exposure = mcp.find((c) => c.impactClass === 'ai-endpoint');
  assert.ok(exposure, 'MCP-speaking handler ranks the endpoint exposure itself');
  assert.equal(exposure.reachability, 'unauth');
  assert.equal(exposure.sev, 'high');
  assert.match(exposure.evidence, /route mcp\/v1\/sse/);
  for (const cand of mcp) assert.match(cand.probe, /READ-ONLY|DOCTRINE-GATED/i);
});

test('AI agent route: named bearer-only permission_callback is resolved, scanned, upgraded', () => {
  const r = minePrivesc([rec('ai.php', AI_PLUGIN)]);
  const chat = r.candidates.filter((c) => c.hook === 'rest_route' && c.route === 'ai/v1/agent/chat');
  assert.ok(chat.length >= 3, `exposure + bearer + compare + handler sink, got ${chat.map((c) => c.impactClass)}`);

  // The token gate is evaluated, not shrugged at: no WP session behind it => subscriber reach.
  const compare = chat.find((c) => c.impactClass === 'token-compare');
  assert.ok(compare, 'strcmp against get_option in the permission callback is flagged');
  assert.match(compare.title, /token-only authz gate/, 'upgraded to the weak-token label/weight');
  assert.equal(compare.reachability, 'subscriber', 'token-only gate: any visitor presenting the string passes');
  assert.match(compare.evidence, /permission_callback/, 'attributed to the permission callback chain');
  assert.ok(compare.mitigations.some((m) => /token-only permission gate/.test(m)));

  const bearer = chat.find((c) => c.impactClass === 'bearer-intake');
  assert.ok(bearer, 'HTTP_AUTHORIZATION read in the permission callback is flagged');
  assert.match(bearer.title, /token-only authz gate/);
  assert.equal(bearer.taint, 'direct');

  // The route callback's own sink inherits the token-only reachability.
  const optWrite = chat.find((c) => c.impactClass === 'option-overwrite');
  assert.ok(optWrite, 'handler sink still ranks');
  assert.equal(optWrite.reachability, 'subscriber');

  const exposure = chat.find((c) => c.impactClass === 'ai-endpoint');
  assert.ok(exposure, 'AI-named route with no capability gate ranks the exposure');
});

test('AI safe route: capability permission_callback gates; hash_equals is NOT flagged', () => {
  const r = minePrivesc([rec('aisafe.php', AI_SAFE_PLUGIN)]);
  const models = r.candidates.filter((c) => c.route === 'ai/v1/admin/models');
  const optWrite = models.find((c) => c.impactClass === 'option-overwrite');
  assert.ok(optWrite, 'sink still surfaces, floor-ranked');
  assert.equal(optWrite.reachability, 'admin-gated', 'current_user_can in the resolved permission_callback gates the route');
  assert.ok(optWrite.mitigations.some((m) => /permission_callback current_user_can/.test(m)));
  assert.ok(!models.some((c) => c.impactClass === 'ai-endpoint'), 'no exposure candidate behind a real capability gate');

  const hashcheck = r.candidates.filter((c) => c.route === 'ai/v1/hashcheck/ping');
  assert.ok(!hashcheck.some((c) => c.impactClass === 'token-compare' || /token-only/.test(c.title)),
    'hash_equals comparison is timing-safe — not a weak-token finding');
});

test('closure permission_callback returning true reads unauth; credential option annotated', () => {
  const r = minePrivesc([rec('aiclosure.php', AI_CLOSURE_PLUGIN)]);
  const optWrite = r.candidates.find((c) => c.impactClass === 'option-overwrite');
  assert.ok(optWrite);
  assert.equal(optWrite.reachability, 'unauth', 'inline return-true closure is an open gate');
  assert.ok(optWrite.mitigations.some((m) => /closure returns true/.test(m)));
  assert.match(optWrite.title, /\[credential-named option\]/, 'api-key option write is called out for triage');
  assert.equal(optWrite.sev, 'crit');
  const exposure = r.candidates.find((c) => c.impactClass === 'ai-endpoint');
  assert.ok(exposure, 'agent/v1 route surface-tagged even without protocol markers');
  assert.equal(exposure.surface, 'ai');
});

test('init hook: request-driven handler modeled; bootstrap-only handler skipped', () => {
  const r = minePrivesc([rec('init.php', INIT_PLUGIN)]);
  const token = r.candidates.find((c) => c.handler === 'plugin_get_token');
  assert.ok(token, 'the imgur _get_token shape (unauth $_GET -> option write on init) ranks');
  assert.equal(token.impactClass, 'option-overwrite');
  assert.equal(token.reachability, 'unauth');
  assert.match(token.title, /\[credential-named option\]/, 'refreshToken option is credential-named');
  assert.ok(!r.candidates.some((c) => c.handler === 'plugin_bootstrap'),
    'bootstrap-only init handler (no request channel) is not attack surface');
  assert.ok(r.stats.initBootstrapSkipped >= 1, 'skipped bootstrap init handlers are counted honestly');
});

test('abilities: open gate + meta.mcp.public ranks the unauth-via-MCP-adapter exposure and the dangerous executor', () => {
  const r = minePrivesc([rec('abilities.php', ABILITY_PLUGIN)]);

  // The anchor class: public ability + open gate — the adapter is the transport, the
  // ability's own permission_callback is the (absent) gate. Ranked below the Madara
  // option-overwrite family, at the file-write band.
  const pub = r.candidates.filter((c) => c.impactClass === 'mcp-public-ability');
  const del = pub.find((c) => c.ability === 'fixture/delete-file');
  assert.ok(del, 'meta.mcp.public + __return_true ability is flagged');
  assert.equal(del.reachability, 'unauth');
  assert.equal(del.sev, 'crit');
  assert.ok(del.score < 90, 'slots below the option-overwrite/account-control family');
  assert.equal(del.confidence, 'high', 'gate proven open at parse level');
  assert.match(del.evidence, /meta\.mcp\.public=true/, 'evidence names the exposure flag');
  assert.match(del.evidence, /adapter gates ONLY on this callback/, 'report keeps adapter-as-transport reasoning straight');
  assert.equal(del.surface, 'ai');
  assert.match(del.probe, /READ-ONLY/i);

  // The dangerous executor behind the weak gate is ranked high: $input is caller-controlled
  // (schema types, not intent) and propagates into the sink.
  const unlink = r.candidates.find((c) => c.ability === 'fixture/delete-file' && c.impactClass === 'file-delete');
  assert.ok(unlink, 'execute_callback sink surfaces');
  assert.equal(unlink.reachability, 'unauth');
  assert.equal(unlink.taint, 'tainted-var', "$path = $input['path'] propagates the seeded caller input");
  assert.equal(unlink.sev, 'crit');
  assert.equal(unlink.doctrineGated, true);

  // Weak gate WITHOUT exposure flags: the ability-weak-gate class at subscriber reach,
  // and the dangerous executor is ranked high (the brief's class-1 shape).
  const write = r.candidates.filter((c) => c.ability === 'fixture/write-setting');
  const weakGate = write.find((c) => c.impactClass === 'ability-weak-gate');
  assert.ok(weakGate, 'unexposed weak-gated ability is flagged as ability-weak-gate');
  assert.equal(weakGate.reachability, 'subscriber', 'PHP/JS-only exposure — a privesc-ladder rung, not proven external surface');
  assert.ok(!write.some((c) => c.impactClass === 'mcp-public-ability'), 'no MCP exposure without the public flag');
  const optWrite = write.find((c) => c.impactClass === 'option-overwrite');
  assert.equal(optWrite.sev, 'high', 'dangerous executor + weak gate ranks high');
  assert.equal(optWrite.taint, 'direct', "$input['value'] on the sink line is caller-direct");

  // show_in_rest (no mcp.public): weak-gate class, evidence names the REST run endpoint.
  const rest = r.candidates.filter((c) => c.ability === 'fixture/rest-exposed');
  const restGate = rest.find((c) => c.impactClass === 'ability-weak-gate');
  assert.ok(restGate, 'closure return-true gate with show_in_rest is flagged');
  assert.match(restGate.evidence, /show_in_rest=true/);
  assert.equal(restGate.reachability, 'subscriber', 'wp-abilities REST namespace requires an authenticated user');

  // Ability registrations never collect the generic ai-endpoint hit (dedicated classes).
  assert.ok(!r.candidates.some((c) => c.impactClass === 'ai-endpoint'),
    'ability regs carry their own exposure classes, not the generic endpoint one');
});

test('abilities: absent permission_callback flags at medium confidence; token-only gate mirrors the weak-token upgrade', () => {
  const r = minePrivesc([rec('abilities.php', ABILITY_PLUGIN)]);

  // Absent gate (required arg) + mcp.public: flagged with the registration-succeeds caveat.
  const spawn = r.candidates.filter((c) => c.ability === 'fixture/spawn-task');
  const absent = spawn.find((c) => c.impactClass === 'mcp-public-ability');
  assert.ok(absent, 'absent permission_callback + mcp.public is the anchor class too');
  assert.equal(absent.reachability, 'unauth');
  assert.equal(absent.confidence, 'medium', 'absent = required arg; ranked as if the registration succeeds');
  assert.match(absent.evidence, /absent permission_callback/);
  assert.ok(absent.mitigations.some((m) => /permission_callback absent/.test(m)));
  const cmd = spawn.find((c) => c.impactClass === 'cmd-spawn');
  assert.ok(cmd, 'dangerous executor surfaces behind the absent gate');
  assert.equal(cmd.sev, 'crit');
  assert.equal(cmd.doctrineGated, true);

  // Token-only named gate + mcp.public: pc is resolved, scanned, weak-token upgraded —
  // and the exposure finding says the gate is token-only, at subscriber reach (mirrors
  // the REST doctrine: not proven-unauth, token provenance is a dynamic question).
  const prompt = r.candidates.filter((c) => c.ability === 'fixture/run-prompt');
  const compare = prompt.find((c) => c.impactClass === 'token-compare');
  assert.ok(compare, 'strcmp against get_option in the ability permission_callback is flagged');
  assert.match(compare.title, /token-only authz gate/, 'WEAK_TOKEN_WEIGHT upgrade applies to ability gates');
  assert.equal(compare.reachability, 'subscriber');
  assert.match(compare.evidence, /permission_callback/);
  const bearer = prompt.find((c) => c.impactClass === 'bearer-intake');
  assert.ok(bearer, 'HTTP_AUTHORIZATION intake in the ability permission_callback is flagged');
  assert.match(bearer.title, /token-only authz gate/);
  const exposure = prompt.find((c) => c.impactClass === 'mcp-public-ability');
  assert.ok(exposure, 'public ability behind a token-only gate is still the exposure class');
  assert.match(exposure.evidence, /token-only permission_callback/);
  assert.equal(exposure.reachability, 'subscriber', 'token-only: any visitor presenting the string passes — not proven unauth');
  assert.ok(exposure.mitigations.some((m) => /token-only permission gate/.test(m)));
});

test('abilities: sound capability gate suppresses exposure; closure executor still flagged from registration args', () => {
  const r = minePrivesc([rec('abilities.php', ABILITY_PLUGIN)]);

  // Public-with-sound-gate = NOT flagged: current_user_can in the resolved
  // permission_callback gates every transport.
  const admin = r.candidates.filter((c) => c.ability === 'fixture/admin-info');
  assert.ok(!admin.some((c) => c.impactClass === 'mcp-public-ability' || c.impactClass === 'ability-weak-gate'),
    'mcp.public behind a sound capability gate is not an exposure finding');
  const adminWrite = admin.find((c) => c.impactClass === 'option-overwrite');
  assert.ok(adminWrite, 'sink still surfaces, floor-ranked');
  assert.equal(adminWrite.reachability, 'admin-gated');
  assert.ok(adminWrite.mitigations.some((m) => /permission_callback current_user_can/.test(m)));

  // Closure execute_callback: the gate finding attaches to the registration args (the
  // exposure class needs no executor body), with an honest gap for the unscanned body.
  const closure = r.candidates.find((c) => c.impactClass === 'mcp-public-ability' && c.ability === 'fixture/closure-exec');
  assert.ok(closure, 'closure executor + open gate + mcp.public still flagged');
  assert.equal(closure.handler, 'fixture/closure-exec', 'dedupe-safe handler slot falls back to the ability name');
  assert.equal(closure.reachability, 'unauth');
  assert.ok(r.gaps.some((g) => /execute_callback is a closure/.test(g.reason) && /registration args/.test(g.reason)),
    'unscanned closure executor is an honest gap');
});

test('malformed/binary/empty records never throw', () => {
  for (const junk of [null, undefined, 'string', 42, {}]) {
    const r = minePrivesc(junk);
    assert.deepEqual(r.candidates, []);
  }
  const r = minePrivesc([
    rec('empty.php', ''),
    rec('whitespace.php', '   \n  '),
    rec('null.php', null),
    rec('bin.php', 'not really php ' + String.fromCharCode(0)),
    rec('unbalanced.php', '<?php\nfunction broken( {\n if ($a) {\n update_option("a", $_POST["b"]);\n'),
    rec('braces.php', '{{{'), // not PHP at all
  ]);
  assert.ok(Array.isArray(r.candidates));
  assert.ok(r.gaps.some((g) => /unbalanced braces/.test(g.reason)), 'unbalanced function body is reported as a gap');
});

test('tool wrapper: never throws on a missing root; honest skipped[] on binary/oversized', () => {
  const missing = privemap(join(tmpdir(), 'varvel-privemap-no-such-dir-' + process.pid));
  assert.deepEqual(missing.candidates, []);
  assert.equal(missing.scannedFiles, 0);
  assert.ok(missing.skipped.length >= 1, 'unreadable root reported in skipped[]');

  const dir = join(tmpdir(), 'varvel-privemap-' + process.pid);
  try {
    mkdirSync(join(dir, 'sub'), { recursive: true });
    writeFileSync(join(dir, 'vuln.php'), VULN_PLUGIN);
    writeFileSync(join(dir, 'sub', 'binary.php'), '<?php blob ' + String.fromCharCode(0) + ' trailing'); // NUL byte in body
    writeFileSync(join(dir, 'sub', 'note.txt'), 'update_option(\'x\', $_POST[\'y\']);'); // not .php — ignored
    const report = privemap(dir, { maxFileBytes: 64 * 1024 });
    assert.equal(report.scannedFiles, 1, 'only the real PHP source scanned');
    assert.ok(report.candidates.some((c) => c.impactClass === 'file-delete'), 'sink found through the wrapper');
    assert.ok(report.candidates.every((c) => !c.ref.startsWith(report.root.replace(/\\/g, '/'))), 'refs are root-relative');
    assert.ok(report.skipped.some((s) => /binary/.test(s.reason) && /binary\.php/.test(s.path)), 'binary file honestly skipped');
    // oversized cap honored
    const capped = privemap(dir, { maxFileBytes: 100 });
    assert.ok(capped.skipped.some((s) => /oversized/.test(s.reason)), 'oversized file honestly skipped');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// --- calibration soak: the method's acceptance test on the real mirror ----------------
// Skips gracefully when the mirror is absent (CI/other hosts); on the research host it
// MUST rediscover the hand-found madara-core sinks — the brief's guard: the unauth
// option overwrite pair (settings.php, wp-manga.php) and the imgur-upload.php token
// overwrite rank TOP 6; the unlink + any-user meta write rank top 10.
const MIRROR = 'C:/Users/Jack/Downloads/varvel-kimi/research/madara-site';

test('calibration soak: madara-site mirror rediscovers the three known sinks in top 10', { skip: !existsSync(MIRROR) && 'madara-site mirror not present on this host' }, () => {
  const report = privemap(MIRROR);
  assert.ok(report.scannedFiles > 2000, `mirror really scanned (${report.scannedFiles} files) — a vacuous pass proves nothing`);
  const top = report.candidates.slice(0, 10);
  const brief = top.map((c) => `${c.rank} ${c.impactClass} ${c.handler} ${c.ref}`).join('\n');

  // (a) unauthenticated option overwrite of wp_manga_settings via admin_init (the CVE candidate)
  assert.ok(
    top.some((c) => c.impactClass === 'option-overwrite' && c.reachability === 'unauth' && /madara-core\/(wp-manga\.php|inc\/settings\.php):\d+$/.test(c.ref)),
    'sink (a) unauth option overwrite in top 10 by ref substring; got:\n' + brief,
  );
  // (b) wp-manga-delete-zip: unauth arbitrary unlink (CVE-2025-7712's handler)
  assert.ok(
    top.some((c) => c.impactClass === 'file-delete' && /madara-core\/inc\/ajax\/frontend\.php:\d+$/.test(c.ref)),
    'sink (b) unauth unlink in top 10 by ref substring; got:\n' + brief,
  );
  // (c) save_user_player_id: any-user meta write reachable by low-priv users
  assert.ok(
    top.some((c) => c.impactClass === 'meta-write' && /madara-core\/inc\/ajax\/frontend\.php:\d+$/.test(c.ref) && /save_user_player_id/.test(c.handler)),
    'sink (c) any-user meta write in top 10 by ref substring; got:\n' + brief,
  );

  // Calibration guard (AI-surface extension): the brief's three named sinks hold TOP 6 —
  // including the imgur-upload.php token overwrite (the unauth $_GET-driven refreshToken
  // write on the init hook), which the AI/token patterns must surface without dilution.
  const top6 = report.candidates.slice(0, 6);
  const brief6 = report.candidates.slice(0, 10).map((c) => `${c.rank} ${c.impactClass} ${c.handler} ${c.ref}`).join('\n');
  assert.ok(
    top6.some((c) => c.impactClass === 'option-overwrite' && /madara-core\/inc\/settings\.php:\d+$/.test(c.ref)),
    'guard (a) settings.php admin_init option overwrite in top 6; got:\n' + brief6,
  );
  assert.ok(
    top6.some((c) => c.impactClass === 'option-overwrite' && /madara-core\/wp-manga\.php:\d+$/.test(c.ref)),
    'guard (b) wp-manga.php settings handler in top 6; got:\n' + brief6,
  );
  assert.ok(
    top6.some((c) => c.impactClass === 'option-overwrite' && /madara-core\/inc\/upload\/imgur-upload\.php:\d+$/.test(c.ref)),
    'guard (c) imgur-upload.php token overwrite in top 6; got:\n' + brief6,
  );

  // Known-in-tree, expected to rank lower (not top 10, but present):
  assert.ok(
    report.candidates.some((c) => c.handler === 'widget_text_save_callback' && c.impactClass === 'option-overwrite'),
    'ct_save_widget_text-class option write (madara-shortcodes) ranks somewhere',
  );
  assert.ok(
    report.candidates.some((c) => c.handler === 'chapter_navigate_page' && c.impactClass === 'sqli' && c.confidence === 'low'),
    'chapter_navigate_page addslashes-not-prepare SQLi ranks at low confidence',
  );
});

// --- 2026-08-26 FP fixes: core query classes excluded from sqli; fixed/self-only writes degraded ---

// (e) sydney shapes: a WP_Query ->query() is core-parameterized (NOT a sqli sink);
// a fixed-value option write and a self-only user-meta write are bounded primitives.
const CORE_QUERY_AND_BOUNDED_PLUGIN = PHP_OPEN + `
add_action('wp_ajax_nopriv_s_conditions', 's_conditions');
function s_conditions() {
    $args = array( 'post_type' => 'post' );
    $q = new WP_Query( $args );
    $q->query( $args );
    wp_die();
}

add_action('wp_ajax_nopriv_s_raw', 's_raw');
function s_raw() {
    global $wpdb;
    $id = $_GET['id'];
    $wpdb->query( "SELECT * FROM x WHERE id = " . $id );
    wp_die();
}

add_action('wp_ajax_nopriv_s_font', 's_font');
function s_font() {
    update_option( 'fontawesome', '5' );
    wp_die();
}

add_action('wp_ajax_nopriv_s_layout', 's_layout');
function s_layout() {
    update_option( 'layout', $_POST['l'] );
    wp_die();
}

add_action('wp_ajax_s_seen', 's_seen');
function s_seen() {
    $uid = get_current_user_id();
    update_user_meta( $uid, '_notifications_seen', 1 );
    wp_die();
}

add_action('wp_ajax_s_other', 's_other');
function s_other() {
    update_user_meta( $_POST['uid'], '_notifications_seen', 1 );
    wp_die();
}
`;

test('sqli sink: WP_Query/WP_Term_Query/WP_User_Query ->query() is excluded (core-parameterized); raw $wpdb->query still fires', () => {
  const r = minePrivesc([rec('coreq.php', CORE_QUERY_AND_BOUNDED_PLUGIN)]);
  assert.ok(!r.candidates.some((c) => c.handler === 's_conditions' && c.impactClass === 'sqli'),
    'WP_Query->query() is not a sqli candidate — the sydney display_conditions FP');
  const raw = r.candidates.find((c) => c.handler === 's_raw' && c.impactClass === 'sqli');
  assert.ok(raw, 'a tainted raw $wpdb->query is still flagged');
});

test('sink-value weighting: fixed-value option writes and self-only user-meta writes auto-degrade; dynamic writes do not', () => {
  const r = minePrivesc([rec('bounded.php', CORE_QUERY_AND_BOUNDED_PLUGIN)]);
  const byHandler = Object.fromEntries(r.candidates.map((c) => [c.handler, c]));
  const fixed = byHandler.s_font;
  const dynamic = byHandler.s_layout;
  assert.ok(fixed && dynamic, 'both option writes surface');
  assert.match(fixed.degraded || '', /fixed-value write/, 'literal value provably bounded');
  assert.ok(!dynamic.degraded, 'a superglobal-driven value is never degraded (conservative)');
  assert.equal(fixed.reachability, dynamic.reachability, 'same reachability class — the degrade is the score, not the reach');
  assert.ok(dynamic.score > fixed.score, 'dynamic value outranks the provably-fixed one');
  assert.ok(Math.abs(fixed.score - 100 * 1.0 * 0.45 * 0.3) < 0.01, `unauth fixed write = weight×reach×taint(none)×0.3, got ${fixed.score}`);

  const selfOnly = byHandler.s_seen;
  const anyUser = byHandler.s_other;
  assert.ok(selfOnly && anyUser, 'both meta writes surface');
  assert.match(selfOnly.degraded || '', /self-only user meta write/, 'the caller-own row is provably bounded');
  assert.ok(!anyUser.degraded, 'attacker-chosen user id is NOT self-only');
  assert.match(anyUser.title, /any-user meta write/, 'any-user upgrade unchanged');
  assert.ok(anyUser.score > selfOnly.score, 'any-user outranks self-only');
});

// --- 2026-09-17 FP fixes: the 3-argument option write, and unproven cross-function dataflow ---
//
// (f) The THREE-argument option write. `update_option( 'name', CONST, true )` is ordinary
// WP usage (the autoload flag). The old last-argument regex read `CONST, true` as the value,
// failed the literal test, and left a bounded primitive ranked as a top unauth option
// overwrite — the real shape being AI Engine's check_db() → update_option(
// 'mwai_db_version_discussions', MWAI_VERSION, true ), which sat at rank #1 with the
// evidence on the same line showing a constant name and a constant value.
//
// Every case is DIFFERENTIAL: aa_dynamic is the live mirror of the same 3-arg shape with a
// caller-chosen value, so the degrade is attributable to the value being provably fixed —
// not to the argument reader failing on the extra argument.
const ARG_SHAPE_PLUGIN = PHP_OPEN + `
add_action('wp_ajax_nopriv_aa_const3', 'aa_const3');
function aa_const3() {
    update_option( 'aa_db_version', AA_FIXTURE_VERSION, true );
    wp_die();
}

add_action('wp_ajax_nopriv_aa_const2', 'aa_const2');
function aa_const2() {
    update_option( 'aa_layout', '5' );
    wp_die();
}

add_action('wp_ajax_nopriv_aa_dynamic', 'aa_dynamic');
function aa_dynamic() {
    update_option( 'aa_layout', $_POST['l'], true );
    wp_die();
}

add_action('wp_ajax_nopriv_aa_nested', 'aa_nested');
function aa_nested() {
    update_option( 'aa_opts', array( 'a' => $_POST['x'], 'b' => 1 ) );
    wp_die();
}
`;

test('3-argument option writes: a constant value still auto-degrades (the autoload arg is not the value)', () => {
  const r = minePrivesc([rec('argshape.php', ARG_SHAPE_PLUGIN)]);
  const byHandler = Object.fromEntries(r.candidates.map((c) => [c.handler, c]));
  const const3 = byHandler.aa_const3;
  const const2 = byHandler.aa_const2;
  const dynamic = byHandler.aa_dynamic;
  const nested = byHandler.aa_nested;
  assert.ok(const3 && const2 && dynamic && nested, 'all four option writes surface');

  assert.match(const3.degraded || '', /fixed-value write/, 'the 3-arg constant write is provably bounded');
  assert.match(const3.degraded || '', /AA_FIXTURE_VERSION/, 'the degrade names the constant it read');
  assert.match(const2.degraded || '', /fixed-value write/, 'the 2-arg literal path is unchanged');
  assert.ok(!nested.degraded, 'an array value is never read as a fixed literal (no blind comma split)');

  // The mirror control: same 3-arg shape, caller-chosen value — never degraded, and it
  // outranks the bounded write. Without this, a broken argument reader that found nothing
  // would look identical to a correct one that found a constant.
  assert.ok(!dynamic.degraded, 'a caller-chosen value in the 3-arg form is never degraded');
  assert.ok(dynamic.score > const3.score, 'the dynamic write outranks the constant one');

  // The filing-safety consequence: the bounded primitive is out of BOTH lanes, the dynamic
  // one is still lane-visible. This is the property that keeps a constant cache-buster out
  // of a bounty form.
  assert.equal(const3.lane.patchstack, 'none', 'a miner-degraded write is out of the Patchstack lane (§4.2 minor-impact band)');
  assert.equal(const3.lane.wordfenceEligible, false, 'a bounded primitive carries no consequential CIA sink');
  assert.equal(dynamic.lane.patchstack, 'standard', 'the dynamic write stays lane-visible — the classify is not blanket');
});
// --- 2026-09-17 honesty fix: cross-function hits with NO traced dataflow must not be TITLED
// as the vulnerability class. bodyTaint is single-function by construction, so a hop>0 hit
// whose sink line carries no request-derived value has no demonstrated input path — the
// superglobal, if any, would live in the CALLER. The candidate stays ranked (classified,
// never filtered) but the title carries the uncertainty. The real shape: AI Engine's
// rest_discussions_ui_truncate → check_db() produced a rank-3 "unauthenticated SQL injection
// candidate" over `SHOW TABLES LIKE '$this->table_chats'` — the plugin's own schema check.
//
// DIFFERENTIAL: df_traced is the live mirror — the same sink class with the request value
// traced INTO the call at hop 0 — so the qualifier is attributable to the untraced
// dataflow, not to the sink or the class.
const DATAFLOW_PLUGIN = PHP_OPEN + `
add_action('wp_ajax_nopriv_df_boot', 'df_boot');
function df_boot() {
    df_ensure_schema();
    wp_die();
}

function df_ensure_schema() {
    global $wpdb;
    $wpdb->get_var( "SHOW TABLES LIKE 'df_chats'" );
    update_option( 'df_db_version', DF_FIXTURE_VERSION, true );
}

add_action('wp_ajax_nopriv_df_traced', 'df_traced');
function df_traced() {
    global $wpdb;
    $id = $_GET['id'];
    $wpdb->get_var( "SELECT * FROM df WHERE id = " . $id );
    wp_die();
}
`;

test('unproven cross-function dataflow: the candidate is qualified, never silently titled as a vuln', () => {
  const r = minePrivesc([rec('dataflow.php', DATAFLOW_PLUGIN)]);
  const bootSqli = r.candidates.find((c) => c.handler === 'df_boot' && c.impactClass === 'sqli');
  const bootOpt = r.candidates.find((c) => c.handler === 'df_boot' && c.impactClass === 'option-overwrite');
  const traced = r.candidates.find((c) => c.handler === 'df_traced' && c.impactClass === 'sqli');
  assert.ok(bootSqli && bootOpt && traced, 'both callee-derived hits and the traced mirror surface');

  // The callee-derived hits are flagged and say why, naming the hop chain.
  for (const [name, cand] of [['sqli', bootSqli], ['option-overwrite', bootOpt]]) {
    assert.equal(cand.dataflowUnproven, true, `${name}: hop>0 with no traced value is marked`);
    assert.equal(cand.taint, 'none', `${name}: the sink line genuinely carries no request value`);
    assert.match(cand.title, /\[dataflow unproven: sink reached via df_boot -> df_ensure_schema/,
      `${name}: the title names the indirection instead of asserting the class`);
  }
  // The ai-engine shape in one fixture: the constant 3-arg write in a callee is BOTH
  // unproven-dataflow AND a bounded primitive.
  assert.match(bootOpt.degraded || '', /fixed-value write/, 'the constant callee write is also bounded');
  assert.match(bootOpt.degraded || '', /DF_FIXTURE_VERSION/, 'and it names the constant');
  assert.equal(bootOpt.lane.patchstack, 'none', 'so it is out of the Patchstack lane');

  // Mirror control: the same sink class with the value traced in at hop 0 carries no
  // qualifier and keeps full weight — the honesty marker is not blanket.
  assert.ok(!traced.dataflowUnproven, 'a hop-0 traced query is NOT marked unproven');
  assert.doesNotMatch(traced.title, /dataflow unproven/, 'and its title keeps the plain claim');
  assert.ok(traced.score > bootSqli.score, 'the traced query outranks the untraced one');
});

// --- 2026-09-17 (cont.): meta-WRITE row provenance -------------------------------------
// The class label "user meta write (privesc ladder rung)" is alarming but says nothing about
// WHOSE row is written. Two measured shapes made that a false-positive carrier:
//   · SureForms 2.x (inc/payments/front-end.php:1465): a nopriv AJAX endpoint reaching
//     update_user_meta( $user->ID, … ) inside a callee — the row is a PARAMETER, fed by the
//     caller's wp_get_current_user(), and the branch itself is login-gated. Ranked
//     "unauthenticated user meta write (privesc ladder rung)".
//   · the same call written as update_user_meta( $current->ID, … ) directly after
//     $current = wp_get_current_user() — provably the caller's OWN row (bounded primitive).
// Both directions are guarded: the object idiom degrades (self-only), and an unresolvable row
// is NAMED rather than assumed. DIFFERENTIAL: so_other is the live mirror — an
// attacker-chosen row must stay un-degraded and keep the any-user label.
const META_ROW_PLUGIN = PHP_OPEN + `
add_action('wp_ajax_so_self', 'so_self');
function so_self() {
    $current = wp_get_current_user();
    update_user_meta( $current->ID, 'so_last_seen', time() );
    wp_die();
}

add_action('wp_ajax_nopriv_so_guest', 'so_guest');
function so_guest() {
    $current = wp_get_current_user();
    if ( $current->ID > 0 ) {
        so_write_customer( $current );
    }
    wp_die();
}

function so_write_customer( $user ) {
    update_user_meta( $user->ID, 'so_customer_id', 'abc' );
}

add_action('wp_ajax_so_other', 'so_other');
function so_other() {
    update_user_meta( $_POST['uid'], 'so_last_seen', 1 );
    wp_die();
}
`;

test('meta writes: the object row idiom is self-only; an unresolvable row is named, never assumed', () => {
  const r = minePrivesc([rec('metarow.php', META_ROW_PLUGIN)]);
  const byHandler = Object.fromEntries(r.candidates.map((c) => [c.handler, c]));
  const self = byHandler.so_self;
  const guest = byHandler.so_guest;
  const other = byHandler.so_other;
  assert.ok(self && guest && other, 'all three meta writes surface');

  // $current = wp_get_current_user(); update_user_meta( $current->ID, … ) — the caller's own row.
  assert.match(self.degraded || '', /self-only user meta write/, 'the object row idiom is bounded');
  assert.ok(!self.rowUnresolved, 'a resolved own-row is not flagged unresolved');
  assert.equal(self.lane.patchstack, 'none', 'so it is out of the Patchstack lane (§4.2 minor-impact band)');

  // The same write reached through a parameter: the row cannot be tied to the caller, so it is
  // named — and the candidate is NOT degraded (we do not guess in either direction).
  assert.equal(guest.dataflowUnproven, true, 'no request-derived value traced into the callee call');
  assert.equal(guest.rowUnresolved, true, 'the written row is neither own-row nor attacker-chosen');
  assert.match(guest.title, /\[row provenance unresolved:/, 'the headline carries the unproven part');
  assert.ok(!guest.degraded, 'an unresolved row is never silently degraded');

  // Mirror control: an attacker-chosen row keeps the any-user label and is never "unresolved".
  assert.match(other.title, /any-user meta write/, 'the any-user upgrade still applies');
  assert.ok(!other.rowUnresolved && !other.degraded, 'the any-user row is neither unresolved nor bounded');
});

// --- registration-window regressions (the two false-UNAUTH fabricators) ---------------
// Both defects produced the SAME wrong output — a PRESENT permission_callback mis-read as
// ABSENT, which the engine escalates to an 'unauth' broken-access-control candidate. That
// is an overclaim in the filing direction (a rejected report costs account rate; a parked
// finding costs nothing), so each gets its own guard. Every case is DIFFERENTIAL: an
// ungated mirror of the same shape proves the surface is live, so the gated fixture's
// silence is attributable to the gate being READ rather than to an inert fixture.
//
// Backslash note: FQN gates are built from one-backslash components by interpolation.
// Writing them literally inside a template literal is a double-escape trap that silently
// yields a two-backslash FQN — a string PHP never produces.
const BS = '\\';
const fqn = (cls, method) => `${BS}Fixture${BS}${cls}::${method}`;

// 70 pad lines → the gate lands ~72 lines below the registration, i.e. PAST the old fixed
// 60-line budget (the measured real-world case: siteseo/main/abilitiesregister.php
// registers at line 222 and puts its permission_callback 63 lines down).
const abilityPad = (n, prefix) => Array.from({ length: n }, (_, i) =>
  `        '${prefix}${String(i).padStart(3, '0')}' => array('type' => 'string'),`).join('\n');

// Shared shape: an mcp.public ability (so an ungated one IS a live unauth candidate).
const longArgsAbility = (name, gated) => PHP_OPEN + `
function fixture_register_${name}() {
    wp_register_ability('fixture/${name}', array(
        'label' => 'Long args',
        'category' => 'site',
        'input_schema' => array(
            'type' => 'object',
            'properties' => array(
${abilityPad(70, 'pad')}
            ),
        ),
        'execute_callback' => '${fqn('LongAbility', 'run')}',
${gated ? `        'permission_callback' => '${fqn('LongAbility', 'can_manage')}',\n` : ''}        'meta' => array('mcp' => array('public' => true)),
    ));
}
`;
// The gate class lives in a second file, exactly like gosmtp/siteseo.
const LONG_ABILITY_GATE_CLASS = PHP_OPEN + `
namespace Fixture;
class LongAbility {
    public static function run($input) { update_option('fixture_long_value', $input['v']); }
    public static function can_manage() { return current_user_can('manage_options'); }
}
`;

test('ability window: a permission_callback PAST the old fixed 60-line budget is read (differential)', () => {
  const gated = minePrivesc([
    rec('long-gated.php', longArgsAbility('long-gated', true)),
    rec('long-gate.php', LONG_ABILITY_GATE_CLASS),
  ]);
  const mirror = minePrivesc([
    rec('long-ungated.php', longArgsAbility('long-ungated', false)),
    rec('long-gate.php', LONG_ABILITY_GATE_CLASS),
  ]);

  // The mirror proves the fixture shape is live: without a gate the same ability IS an
  // unauth candidate. So the gated run's silence can only mean the gate was READ.
  const mirrorHit = mirror.candidates.find((c) => c.ability === 'fixture/long-ungated');
  assert.ok(mirrorHit, 'CONTROL: the ungated mirror is a live unauth candidate');
  assert.equal(mirrorHit.reachability, 'unauth', 'CONTROL: ungated mcp.public ability is unauth');

  // The regression: the old fixed 60-line window cut before the gate, so the gate read
  // ABSENT and this emitted a false unauth candidate (~72 lines down).
  const falsePos = gated.candidates.find((c) => c.ability === 'fixture/long-gated');
  assert.equal(falsePos, undefined,
    'a present gate 72 lines down must NOT be reported absent — got: ' + JSON.stringify(falsePos && falsePos.title));
  assert.equal(gated.candidates.filter((c) => c.reachability === 'unauth').length, 0,
    'no unauth candidate for the gated registration — the gate was read');
});

test('ability window: a safety-bound truncation is UNPARSED, never absent (differential)', () => {
  // REGRESSION (the siteseo/gosmtp shape at its worst): the execute_callback is readable
  // EARLY and resolvable, while the permission_callback sits far past the safety bound.
  // Pre-fix the fixed 60-line window cut before the gate, so the gate read ABSENT and this
  // fabricated an unauth candidate at the WRONG floor (subscriber). The window's inability
  // to reach the gate is ignorance and must surface as such.
  const runaway = PHP_OPEN + `
function fixture_runaway_register() {
    wp_register_ability('fixture/runaway', array(
        'execute_callback' => 'fixture_runaway_run',
${abilityPad(520, 'schema')}
        'permission_callback' => '${fqn('RunawayGate', 'can_manage')}',
    ));
}
function fixture_runaway_run($input) { update_option('fixture_runaway_value', $input['v']); }
`;
  const RUNAWAY_GATE_CLASS = PHP_OPEN + `
namespace Fixture;
class RunawayGate {
    public static function can_manage() { return current_user_can('manage_options'); }
}
`;
  // CONTROL: the identical shape with the required permission_callback genuinely omitted
  // IS a candidate — so the test cannot pass merely because the fixture is inert.
  const absent = PHP_OPEN + `
function fixture_absent_register() {
    wp_register_ability('fixture/absent', array(
        'label' => 'Absent gate',
        'category' => 'site',
        'execute_callback' => 'fixture_absent_run',
        'meta' => array('mcp' => array('public' => true)),
    ));
}
function fixture_absent_run($input) { update_option('fixture_absent_value', $input['v']); }
`;
  const control = minePrivesc([rec('absent.php', absent)]);
  const controlHit = control.candidates.find((c) => c.ability === 'fixture/absent');
  assert.ok(controlHit, 'CONTROL: a genuinely absent permission_callback IS a candidate');
  assert.equal(controlHit.reachability, 'unauth', 'CONTROL: absent gate -> unauth');
  assert.equal(controlHit.confidence, 'medium', 'absent is medium confidence (the _doing_it_wrong caveat)');

  // The regression: pre-fix this fabricated a false candidate; now it must not.
  const r = minePrivesc([rec('runaway.php', runaway), rec('runaway-gate.php', RUNAWAY_GATE_CLASS)]);
  const fabricated = r.candidates.find((c) => c.ability === 'fixture/runaway');
  assert.equal(fabricated, undefined,
    'a gate beyond the safety bound must NEVER become a finding — got: ' + JSON.stringify(fabricated && fabricated.title));
  assert.equal(r.candidates.filter((c) => c.reachability === 'unauth').length, 0,
    'no unauth candidate may be manufactured from a window we could not read');
});

// --- engine hygiene: a deliberately-buggy mutant engine must never ship --------------
// The teeth technique (proving a regression test FAILS pre-fix) builds throwaway mutant
// copies of engine/privemap.mjs INSIDE engine/, because relative imports like ./severity.mjs
// only resolve from there. On 2026-09-17 a cleanup raced a fresh mutant build and left two
// 75KB pre-fix engines in place. A mutant engine is a fabrication factory with a friendly
// name: it re-emits the exact false UNAUTH/high verdicts the E–K fixes removed, so anything
// that imports it produces a filing-grade hallucination. Fail loudly instead.
test('engine/ carries no throwaway mutant engines (teeth work is cleaned up)', () => {
  const engineDir = join(dirname(fileURLToPath(import.meta.url)), '..', 'engine');
  const stray = readdirSync(engineDir).filter((f) => /mutant/i.test(f));
  assert.deepEqual(stray, [],
    'mutant engine(s) present in engine/: ' + stray.join(', ') + ' — run `node .tmp/make-mutants.mjs --clean`; '
    + 'a mutant re-emits pre-fix fabricated verdicts (see docs/WP-HUNT-PLAYBOOK.md §8.3)');
});


// --- defect L: a capability gate in the MIDDLE of the descent chain ------------------
// The dispatcher idiom is everywhere in WP plugin code (user-role-editor, 1M+ installs:
// `add_action('wp_ajax_ure_ajax', [$this,'ure_ajax'])` -> $this->dispatch() ->
// `if ( !$this->valid_nonce() || !$this->user_can() ) { die; }` -> _dispatch() -> sink).
// The miner read mitigations from the HANDLER body only, credited nothing, and titled an
// add_role() sink "any-authenticated-user account control" — a filing-shaped over-claim in
// a million-install plugin. reachability.mjs scanned gates deep and returned ADMIN all
// along, so the two engines were silently NOT in lock-step.
const DISPATCHER_PLUGIN = PHP_OPEN + `
class Fixture_Ajax_Processor {
    protected function user_can() {
        $capability = $this->get_required_cap();
        if ( ! current_user_can( $capability ) ) { return false; }
        return true;
    }
    protected function get_required_cap() { return 'edit_users'; }
    protected function _dispatch() {
        $this->add_role();
    }
    protected function add_role() {
        update_option( 'fixture_role_list', $_POST['roles'] );
    }
    public function dispatch() {
        if ( ! $this->valid_nonce() || ! $this->user_can() ) { die; }
        $this->_dispatch();
    }
    protected function valid_nonce() {
        return isset( $_POST['wp_nonce'] ) && wp_verify_nonce( $_POST['wp_nonce'], 'fixture' );
    }
}
function fixture_ure_ajax() {
    $processor = new Fixture_Ajax_Processor();
    $processor->dispatch();
}
`;
const DISPATCHER_REG = PHP_OPEN + `
add_action( 'wp_ajax_fixture_ure_ajax', 'fixture_ure_ajax' );
`;

// CONTROL: the identical sink and chain with NO capability check anywhere on the path.
// The candidate must still rank (classified, never filtered) but must carry the explicit
// gate-unproven qualifier instead of reading as an unqualified vulnerability claim.
const UNGATED_DISPATCHER_PLUGIN = PHP_OPEN + `
class Fixture_Open_Processor {
    protected function _dispatch() {
        $this->add_role();
    }
    protected function add_role() {
        update_option( 'fixture_open_roles', $_POST['roles'] );
    }
    public function dispatch() {
        $this->_dispatch();
    }
}
function fixture_open_ajax() {
    $processor = new Fixture_Open_Processor();
    $processor->dispatch();
}
`;
const UNGATED_DISPATCHER_REG = PHP_OPEN + `
add_action( 'wp_ajax_nopriv_fixture_open_ajax', 'fixture_open_ajax' );
`;

test('gate in the MIDDLE of the descent chain is credited (dispatcher idiom, defect L)', () => {
  const r = minePrivesc([
    rec('dispatcher.php', DISPATCHER_PLUGIN),
    rec('dispatcher-reg.php', DISPATCHER_REG),
  ]);
  const hit = r.candidates.find((c) => c.impactClass === 'option-overwrite');
  assert.ok(hit, 'the sink is still classified and ranked (never filtered) — got: ' + JSON.stringify(r.candidates.map((c) => c.title)));
  assert.equal(hit.reachability, 'admin-gated',
    'a current_user_can() on the descent chain gates the sink — got: ' + hit.reachability + ' | ' + hit.title);
  assert.notEqual(hit.sev, 'high', 'a gated sink must not rank as high — got ' + hit.sev);
  assert.ok(hit.mitigations.some((m) => /current_user_can/.test(m) && /chain/.test(m)),
    'the credited gate names its chain location — got: ' + JSON.stringify(hit.mitigations));
});

test('an UNGATED hop>0 sink is titled gate-unproven, not as a finding (differential control)', () => {
  const r = minePrivesc([
    rec('open-dispatcher.php', UNGATED_DISPATCHER_PLUGIN),
    rec('open-reg.php', UNGATED_DISPATCHER_REG),
  ]);
  const hit = r.candidates.find((c) => c.impactClass === 'option-overwrite');
  assert.ok(hit, 'an ungated nopriv chain IS a candidate — the fix must not filter it');
  assert.ok(hit.gateUnproven === true, 'the gate-unproven marker must be set — got: ' + JSON.stringify(hit.gateUnproven));
  assert.ok(/\[gate unproven:/.test(hit.title),
    'the headline must carry the qualifier, because the headline is what a triager reads — got: ' + hit.title);
});


// --- defect M: a container accessor named query() is not a SQL sink ------------------
// `$post_data = UM()->query()->post_data( $form_id );` (ultimate-member, 200k+ installs)
// matched the raw-query regex `->(?:query|get_results|...)` on the `->query(` inside the
// SINGLETON GETTER and was titled "SQL injection candidate (query without ->prepare)".
// post_data() (class-query.php:428) reads post meta via get_post_custom — no SQL at all.
// A raw-query sink now needs SQL evidence: a db-handle receiver or SQL keywords.
const ACCESSOR_PLUGIN = PHP_OPEN + `
add_action( 'wp_ajax_nopriv_fixture_accessor', 'fixture_accessor_handler' );
function fixture_accessor_handler() {
    $form_id = $_POST['form_id'];
    $post_data = Fixture_Query()->query()->post_data( $form_id );
    wp_send_json_success( $post_data );
}
`;
const REAL_SQLI_PLUGIN = PHP_OPEN + `
add_action( 'wp_ajax_nopriv_fixture_real_sqli', 'fixture_real_sqli_handler' );
function fixture_real_sqli_handler() {
    global $wpdb;
    $email = $_POST['email'];
    $rows = $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}users WHERE user_email = '$email'" );
    wp_send_json_success( $rows );
}
`;

test('a container accessor ->query() is NOT a SQLi candidate; a real $wpdb query still is (defect M)', () => {
  const accessor = minePrivesc([rec('accessor.php', ACCESSOR_PLUGIN)]);
  const fabricated = accessor.candidates.filter((c) => c.impactClass === 'sqli');
  assert.deepEqual(fabricated.map((c) => c.title), [],
    'UM()->query() is a singleton getter, not a query — no sqli candidate may be manufactured');

// --- defect N: a php://memory stream is not a file write -----------------------------
// instagram-feed's settings export builds a download in memory:
//   $file = fopen( 'php://memory', 'w' ); fwrite( $file, $feed ); ... fpassthru( $file );
// and the miner titled it "arbitrary file write/upload" (sink weight 85) in a 100k+ install
// plugin — where no disk write exists at all. Stream wrappers are not paths.
const STREAM_EXPORT_PLUGIN = PHP_OPEN + `
add_action( 'wp_ajax_fixture_export', 'fixture_export' );
function fixture_export() {
    $feed = SBI_Feed_Saver_Manager::get_export_json( filter_var( $_GET['feed_id'], FILTER_SANITIZE_NUMBER_INT ) );
    $file = fopen( 'php://memory', 'w' );
    fwrite( $file, $feed );
    fseek( $file, 0 );
    fpassthru( $file );
    exit;
}
`;
const REAL_FILE_WRITE_PLUGIN = PHP_OPEN + `
add_action( 'wp_ajax_nopriv_fixture_write', 'fixture_write' );
function fixture_write() {
    $path = $_POST['path'];
    $body = $_POST['body'];
    file_put_contents( $path, $body );
}
`;

test('a php://memory stream is NOT a file write; a real path write still is (defect N)', () => {
  const stream = minePrivesc([rec('export.php', STREAM_EXPORT_PLUGIN)]);
  const fabricated = stream.candidates.filter((c) => c.impactClass === 'file-write');
  assert.deepEqual(fabricated.map((c) => c.title), [],
    'fwrite() on a php://memory handle writes to memory — no file-write candidate may exist');

  const control = minePrivesc([rec('real-write.php', REAL_FILE_WRITE_PLUGIN)]);
  const real = control.candidates.find((c) => c.impactClass === 'file-write');

// --- sensitive-read: the accepted READ class (§3.9) ----------------------------------
// Calibrated on known-knowns per docs/RESEARCH.md rule 2: a detector that has never caught a
// known instance of its class is a hypothesis. Positive = a credential-named read emitted to
// the request; negatives = the same read behind a capability gate, and a NON-credential read.
const DISCLOSURE_PLUGIN = PHP_OPEN + `
add_action( 'wp_ajax_nopriv_fixture_disclose', 'fixture_disclose' );
function fixture_disclose() {
    $api_key = get_option( 'acme_payment_api_key' );
    wp_send_json_success( array( 'key' => $api_key ) );
}
`;
const GATED_DISCLOSURE_PLUGIN = PHP_OPEN + `
add_action( 'wp_ajax_fixture_disclose_gated', 'fixture_disclose_gated' );
function fixture_disclose_gated() {
    if ( ! current_user_can( 'manage_options' ) ) { wp_die(); }
    $api_key = get_option( 'acme_payment_api_key' );
    wp_send_json_success( array( 'key' => $api_key ) );
}
`;
const INNOCENT_READ_PLUGIN = PHP_OPEN + `
add_action( 'wp_ajax_nopriv_fixture_innocent', 'fixture_innocent' );
function fixture_innocent() {
    $title = get_option( 'acme_plugin_title' );
    wp_send_json_success( array( 'title' => $title ) );
}
`;

test('sensitive-read fires on a disclosure, gates when capability-checked, ignores non-secrets', () => {
  const hit = minePrivesc([rec('disclose.php', DISCLOSURE_PLUGIN)]).candidates.find((c) => c.impactClass === 'sensitive-read');
  assert.ok(hit, 'POSITIVE: a credential-named option read emitted to the request is a candidate');
  assert.equal(hit.reachability, 'unauth', 'POSITIVE: the nopriv handler keeps unauth reach — got ' + hit.reachability);
  assert.match(hit.title, /sensitive-value disclosure/);

  const gated = minePrivesc([rec('gated.php', GATED_DISCLOSURE_PLUGIN)]).candidates.find((c) => c.impactClass === 'sensitive-read');
  assert.ok(gated, 'CONTROL: the same code behind a capability check is still CLASSIFIED (ranked, never filtered)');
  assert.equal(gated.reachability, 'admin-gated',
    'CONTROL: a current_user_can on the path must gate the reach — got ' + gated.reachability);

  const innocent = minePrivesc([rec('innocent.php', INNOCENT_READ_PLUGIN)]).candidates.filter((c) => c.impactClass === 'sensitive-read');
  assert.deepEqual(innocent.map((c) => c.title), [],
    'CONTROL: a non-credential option echoed is NOT a disclosure — name matching, never guessing');

// --- admin-page registrations: the capability argument IS the gate --------------------
// The settings screens that echo credential-named options are registered via
// add_menu_page()/add_submenu_page(), not add_action — so before 2026-09-17 no registration
// covered them and the reads were never scanned. A page registered with 'read' is reachable by
// ANY logged-in user; with 'manage_options' it is admin-gated. Calibrated on both.

// --- sensitive-read, source kind 2: a sensitive QUERY RESULT emitted in a response ------
// The shape plugin REST surfaces actually use (persian-woocommerce's customer/users &
// revenue/orders; CVE-2024-0761 "Sensitive Information Exposure" is this class). The
// option-read source cannot see it, and an unauth/subscriber route returning user or order
// rows is exactly what doctrine §3.9 accepts.
const QUERY_DISCLOSURE_PLUGIN = PHP_OPEN + `
add_action( 'wp_ajax_nopriv_fixture_rows', 'fixture_rows' );
function fixture_rows() {
    global $wpdb;
    $rows = $wpdb->get_results( "SELECT user_login, user_email FROM {$wpdb->prefix}users LIMIT 10" );
    wp_send_json_success( $rows );
}
`;
const GATED_QUERY_DISCLOSURE_PLUGIN = PHP_OPEN + `
add_action( 'wp_ajax_fixture_rows_gated', 'fixture_rows_gated' );
function fixture_rows_gated() {
    if ( ! current_user_can( 'manage_options' ) ) { wp_die(); }
    global $wpdb;
    $rows = $wpdb->get_results( "SELECT user_login, user_email FROM {$wpdb->prefix}users LIMIT 10" );
    wp_send_json_success( $rows );
}
`;
const INNOCENT_QUERY_PLUGIN = PHP_OPEN + `
add_action( 'wp_ajax_nopriv_fixture_posts', 'fixture_posts' );
function fixture_posts() {
    global $wpdb;
    $rows = $wpdb->get_results( "SELECT post_title FROM {$wpdb->prefix}posts LIMIT 10" );
    wp_send_json_success( $rows );
}
`;

test('sensitive-read: a sensitive query result in a response is a candidate; gates and non-sensitive reads are not', () => {
  const hit = minePrivesc([rec('rows.php', QUERY_DISCLOSURE_PLUGIN)]).candidates.find((c) => c.impactClass === 'sensitive-read');

// --- defect P: a helper's return is not an emission, and an aggregate is not a row ------
// First run of the query-disclosure source flagged two shapes that are NOT disclosures:
//   wp-file-manager  fm_download_backup -> fm_get_key()  `return get_option('fm_key')`
//     (the caller COMPARES the key — nothing is sent to the requester)
//   ultimate-member  `SELECT COUNT(*) FROM wp_users` -> wp_send_json_success( count )
//     (a user COUNT is not a sensitive object)
// Both are pinned here so a future edit cannot quietly re-introduce them.
const HELPER_RETURN_PLUGIN = PHP_OPEN + `
add_action( 'wp_ajax_nopriv_fixture_backup', 'fixture_backup' );
function fixture_backup() {
    $key = fixture_get_key();
    if ( base64_encode( site_url() . $key ) === $_POST['key'] ) {
        wp_send_json_success( 'ok' );
    }
}
function fixture_get_key() {
    return get_option( 'fixture_secret_key' );
}
`;
const AGGREGATE_COUNT_PLUGIN = PHP_OPEN + `
add_action( 'wp_ajax_nopriv_fixture_count', 'fixture_count' );
function fixture_count() {
    global $wpdb;
    $count = $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}users" );
    wp_send_json_success( array( 'count' => $count ) );
}
`;

test('a helper return and an aggregate COUNT are NOT disclosures (defect P)', () => {
  const helper = minePrivesc([rec('helper.php', HELPER_RETURN_PLUGIN)]).candidates.filter((c) => c.impactClass === 'sensitive-read');
  assert.deepEqual(helper.map((c) => c.title), [],
    'a hop>0 `return get_option(...secret...)` feeds a comparison, not the response — no candidate');

  const agg = minePrivesc([rec('agg.php', AGGREGATE_COUNT_PLUGIN)]).candidates.filter((c) => c.impactClass === 'sensitive-read');
  assert.deepEqual(agg.map((c) => c.title), [],
    'SELECT COUNT(*) is an aggregate, not a readable row — no candidate');
});

  assert.ok(hit, 'POSITIVE: a nopriv handler returning user rows is a disclosure candidate');
  assert.equal(hit.reachability, 'unauth', 'POSITIVE: nopriv keeps unauth reach — got ' + hit.reachability);

  const gated = minePrivesc([rec('rows-gated.php', GATED_QUERY_DISCLOSURE_PLUGIN)]).candidates.find((c) => c.impactClass === 'sensitive-read');
  assert.ok(gated, 'CONTROL: classified even when gated (ranked, never filtered)');

// --- two accepted classes that were NOT MODELED AT ALL until now ------------------------
// Auditing privemap's class list against the doctrine's gold shapes + scopecheck's accepted
// types found two gaps: `unserialize` appeared only in NO_DESCEND, and dynamic invocation
// appeared nowhere — yet both are accepted (`object-injection`, RCE/ACE). Calibrated here with
// request-derived positive + fixed-target controls, because both classes must stay silent on
// internal plumbing.
const OBJECT_INJECTION_PLUGIN = PHP_OPEN + `
add_action( 'wp_ajax_nopriv_fixture_unser', 'fixture_unser' );
function fixture_unser() {
    $payload = $_POST['data'];
    $obj = unserialize( $payload );
    wp_send_json_success( is_object( $obj ) );
}
`;
const DYNAMIC_CALL_PLUGIN = PHP_OPEN + `
add_action( 'wp_ajax_nopriv_fixture_dyn', 'fixture_dyn' );
function fixture_dyn() {
    $cb = $_GET['cb'];
    call_user_func( $cb, 1 );
}
`;
const FIXED_TARGETS_PLUGIN = PHP_OPEN + `
add_action( 'wp_ajax_nopriv_fixture_fixed', 'fixture_fixed' );
function fixture_fixed() {
    $obj = unserialize( 'a:1:{i:0;s:3:"abc";}' );
    call_user_func( 'sanitize_text_field', 'x' );
    wp_send_json_success( $obj );
}
`;

test('object-injection and dynamic-call fire on request-derived targets only', () => {
  const oi = minePrivesc([rec('oi.php', OBJECT_INJECTION_PLUGIN)]).candidates.find((c) => c.impactClass === 'object-injection');
  assert.ok(oi, 'POSITIVE: unserialize($_POST-derived) is an object-injection candidate');

// --- file-read: the download primitive (third unmodeled accepted class) -----------------
// The engine had file-delete/file-write/lfi but nothing for a READ — while scopecheck accepts
// `file-dl-del` and the doctrine lists arbitrary file download as a gold shape. `readfile` on a
// request-derived path is the classic unauthenticated high/crit (wp-config.php → DB creds).
const FILE_READ_PLUGIN = PHP_OPEN + `
add_action( 'wp_ajax_nopriv_fixture_dl', 'fixture_dl' );
function fixture_dl() {
    $path = $_GET['file'];
    header( 'Content-Type: application/octet-stream' );
    readfile( $path );
    exit;
}
`;
const FIXED_READ_PLUGIN = PHP_OPEN + `
add_action( 'wp_ajax_nopriv_fixture_dl_fixed', 'fixture_dl_fixed' );
function fixture_dl_fixed() {
    readfile( __DIR__ . '/assets/readme.txt' );
}
`;

test('file-read fires on a request-derived path and stays silent on a fixed one', () => {
  const hit = minePrivesc([rec('dl.php', FILE_READ_PLUGIN)]).candidates.find((c) => c.impactClass === 'file-read');
  assert.ok(hit, 'POSITIVE: readfile($_GET-derived) is a file-read candidate');
  assert.equal(hit.reachability, 'unauth', 'POSITIVE: nopriv keeps unauth — got ' + hit.reachability);

  const fixed = minePrivesc([rec('dl-fixed.php', FIXED_READ_PLUGIN)]).candidates.filter((c) => c.impactClass === 'file-read');
  assert.deepEqual(fixed.map((c) => c.title), [],
    'CONTROL: a fixed path is not an arbitrary read — no candidate');
});

  assert.equal(oi.reachability, 'unauth', 'POSITIVE: nopriv keeps unauth — got ' + oi.reachability);

  const dyn = minePrivesc([rec('dyn.php', DYNAMIC_CALL_PLUGIN)]).candidates.find((c) => c.impactClass === 'dynamic-call');

// an uploaded temp path is not an arbitrary read (PHP assigns it; the attacker does not choose it)
const UPLOAD_TMP_READ_PLUGIN = PHP_OPEN + `
add_action( 'wp_ajax_fixture_import', 'fixture_import' );
function fixture_import() {
    $json = file_get_contents( $_FILES['panels_import_data']['tmp_name'] );
    update_option( 'fixture_imported', json_decode( $json, true ) );
}
`;

test('an uploaded tmp_name read is not an arbitrary file read (control)', () => {
  const hits = minePrivesc([rec('import.php', UPLOAD_TMP_READ_PLUGIN)]).candidates
    .filter((c) => c.impactClass === 'file-read');
  assert.deepEqual(hits.map((c) => c.title), [],
    'reading $_FILES[...][tmp_name] is how every import handler works — not an arbitrary read');
});

  assert.ok(dyn, 'POSITIVE: call_user_func($_GET-derived) is a dynamic-call candidate');
  assert.equal(dyn.reachability, 'unauth', 'POSITIVE: nopriv keeps unauth — got ' + dyn.reachability);

  const fixed = minePrivesc([rec('fixed.php', FIXED_TARGETS_PLUGIN)]).candidates
    .filter((c) => c.impactClass === 'object-injection' || c.impactClass === 'dynamic-call');
  assert.deepEqual(fixed.map((c) => c.title), [],
    'CONTROL: a constant serialized string and a fixed callable are internal plumbing — no candidate');
});

  assert.equal(gated.reachability, 'admin-gated', 'CONTROL: the capability check gates it — got ' + gated.reachability);

  const innocent = minePrivesc([rec('posts.php', INNOCENT_QUERY_PLUGIN)]).candidates.filter((c) => c.impactClass === 'sensitive-read');
  assert.deepEqual(innocent.map((c) => c.title), [],
    'CONTROL: post titles are not a sensitive object — no candidate');
});

const LOWCAP_PAGE_PLUGIN = PHP_OPEN + `
add_action( 'admin_menu', 'fixture_register_page' );
function fixture_register_page() {
    add_menu_page( 'Fixture', 'Fixture', 'read', 'fixture-page', 'fixture_render_page' );
}
function fixture_render_page() {
    $api_key = get_option( 'fixture_payment_api_key' );
    echo '<input value="' . esc_attr( $api_key ) . '">';
}
`;
const ADMINCAP_PAGE_PLUGIN = PHP_OPEN + `
add_action( 'admin_menu', 'fixture_register_admin_page' );
function fixture_register_admin_page() {
    add_menu_page( 'Fixture', 'Fixture', 'manage_options', 'fixture-admin-page', 'fixture_render_admin_page' );
}
function fixture_render_admin_page() {
    $api_key = get_option( 'fixture_payment_api_key' );
    echo '<input value="' . esc_attr( $api_key ) . '">';
}
`;

test('an admin page with a LOW capability exposes the read; manage_options gates it', () => {
  const low = minePrivesc([rec('lowcap.php', LOWCAP_PAGE_PLUGIN)]).candidates.find((c) => c.impactClass === 'sensitive-read');
  assert.ok(low, 'POSITIVE: a page registered with capability "read" that echoes an API key IS a candidate');
  assert.equal(low.reachability, 'subscriber',
    'the page capability is the gate — "read" means any logged-in user reaches it — got ' + low.reachability);

  const adm = minePrivesc([rec('admincap.php', ADMINCAP_PAGE_PLUGIN)]).candidates.find((c) => c.impactClass === 'sensitive-read');
  assert.ok(adm, 'CONTROL: the same page under manage_options is still CLASSIFIED (ranked, never filtered)');
  assert.equal(adm.reachability, 'admin-gated',
    'CONTROL: manage_options must gate the reach — got ' + adm.reachability);
});

});

  assert.ok(real, 'CONTROL: file_put_contents() on a request-derived path MUST still be a candidate — got: '
    + JSON.stringify(control.candidates.map((c) => c.impactClass)));
});


  const control = minePrivesc([rec('real-sqli.php', REAL_SQLI_PLUGIN)]);
  const real = control.candidates.find((c) => c.impactClass === 'sqli');
  assert.ok(real, 'CONTROL: a real $wpdb query with tainted input MUST still be a candidate — got: '
    + JSON.stringify(control.candidates.map((c) => c.impactClass)));
  assert.equal(real.reachability, 'unauth', 'CONTROL: the nopriv handler keeps unauth reach');
});
