// VARVEL — privemap: static privilege-escalation / impact-primitive miner for
// WordPress-flavored PHP source trees.
//
// PROVENANCE: a hand-done source review of the Madara theme/madara-core plugin found a
// subscriber→site-wide impact path (unauthenticated option overwrite via an admin_init
// handler with no nonce/capability check — a verified-novel CVE candidate) plus the
// CVE-2025-7712 unauthenticated arbitrary unlink. That review was artisanal; this module
// productizes the METHOD: given [{ path, content }] source records, rank the handlers an
// operator should look at FIRST instead of reading 50k lines by hand.
//
// LINE-BASED HEURISTICS, NOT AN AST (zero-dep rule). Precision is stated per candidate
// via `confidence` — this miner ranks, it does not convict. Known blind spots are
// documented at the bottom of this file and in the tool report's gaps[].
//
// MODEL: reachability comes from WordPress request registrations (wp_ajax_nopriv_*,
// wp_ajax_*, admin_init, init, admin_post_*, register_rest_route, add_shortcode); impact
// comes from sink calls inside the registered handler's body (with bounded same-plugin
// transitive descent, ≤3 hops, because the real sink often lives in a model method the
// handler calls). RANK = impact class weight × effective reachability × attacker-control
// (taint) factor, decayed 0.75 per descent hop; mitigations (current_user_can / nonce /
// is_user_logged_in / is_admin) downgrade reachability. Destructive classes (file
// delete/write) are marked doctrineGated — probes are read-only/version-discriminator
// suggestions, NEVER payloads.
//
// AI-FEATURE SURFACE (2026 bounty class — AI Engine ≤3.1.3's exposed MCP-endpoint bearer
// token paid $2,145 and the class is under-reviewed): AI/MCP-named routes and hooks are
// tagged surface:'ai'; MCP-protocol handlers (tools/call, text/event-stream) and AI
// endpoints without a capability gate are ranked as exposure candidates; bearer/API-key
// intake and ==/strcmp stored-credential comparisons are sink classes of their own, and a
// named REST permission_callback is RESOLVED and scanned — when its only check is a
// stored-token comparison the route is token-only authz (ranked at the file-write band).
//
// WP 6.9 ABILITIES-API / MCP-ADAPTER SURFACE (adapter shipped Feb 2026 — the WP-native
// layer of the same bounty class): wp_register_ability() registrations are parsed for
// their permission_callback gate (absent / __return_true / return-true closure / token-only
// comparison vs a sound capability check) and their exposure flags — meta.mcp.public=true
// turns the ability into an MCP tool on the adapter's default server, meta.show_in_rest=true
// exposes it under the authenticated wp-abilities REST namespace. BOTH transports defer to
// the ability's OWN permission_callback, so the finding is always the ability's gate, never
// the transport. A public ability behind an open/absent gate is the unauth-via-MCP-adapter
// anchor class (the AI Engine $2,145 shape, WP-native); the execute_callback is sink-scanned
// like any handler, with its $input argument treated as caller-controlled (input_schema
// validates types, not intent).

import { riskLevelForScore } from './severity.mjs';
import { classifyLane } from './lanes.mjs';

// --- tuning tables -----------------------------------------------------------

const REACH_W = { unauth: 1.0, subscriber: 0.55, shortcode: 0.5, 'admin-gated': 0.25, unknown: 0.15 };
const REACH_TITLE = {
  unauth: 'unauthenticated',
  subscriber: 'any-authenticated-user',
  shortcode: 'second-order',
  'admin-gated': 'admin-gated',
  unknown: 'unknown-context',
};

const SUPERGLOBAL = /\$_(?:POST|GET|REQUEST|COOKIE|FILES)\b/;

// AI-feature surface classification. Tested against HOOK names and REST route paths only
// (never file paths or arbitrary strings — 'agent' would match user-agent handling and
// bare 'ai' matches 'main'/'mail'/'again', hence the anchored alternatives).
const AI_SURFACE = /(?:\bmcp\b|mcp[_-]|\bagent\b|\bchat\b|chatbot|completion|openai|anthropic|\bclaude\b|\bgemini\b|\bllms?\b|copilot|assistant|\bai\b|\bai[_-])/i;
// MCP protocol markers are string LITERALS — tested against the original handler body
// (the sanitizer blanks string contents, which is right for code tokens but hides these).
const MCP_PROTOCOL = /tools\/(?:call|list)|text\/event-stream|\bjsonrpc\b|protocolVersion/i;
// Attacker-controlled channels beyond the classic superglobals: the Authorization /
// X-...-Key / X-...-Token headers (bearer intake) and the WP_REST_Request accessors used
// by REST route + permission callbacks. Both are taint sources for REST-era handlers.
const AUTH_HEADER = /\$_SERVER\s*\[\s*['"](?:HTTP_AUTHORIZATION|REDIRECT_HTTP_AUTHORIZATION|HTTP_X_[A-Z0-9_]*(?:API_?KEY|TOKEN|AUTH)[A-Z0-9_]*)['"]\s*\]|\bgetallheaders\s*\(|\bapache_request_headers\s*\(/;
const REST_REQUEST = /\$[A-Za-z_]\w*->(?:get_param|get_json_params|get_body|get_header|get_headers)\s*\(/;
// Credential-flavored option names: overwriting one of these is token handling, not
// generic config churn — the label is annotated so triage sees it first.
const CRED_OPTION = /key|token|secret|credential|passw/i;

// Attacker-control multiplier on the impact weight: a sink whose ARGUMENTS the caller
// cannot steer is a lesser primitive — an unauth handler flipping a constant flag
// (update_option('x_built', 1)) is a nuisance, the same handler writing $_POST-derived
// values is site-wide config injection. Taint is line-heuristic (see blind spots).
const TAINT_FACTOR = { direct: 1, 'tainted-var': 0.9, ambient: 0.65, none: 0.45 };

// Impact classes, most-severe first by weight. `gated` = destructive under engagement
// doctrine: the report never suggests detonating these.
const SINK_DEFS = [
  { id: 'option-overwrite', weight: 100, label: 'option overwrite (site-wide config)',
    re: /(?<![\w$>:-])(update_option|add_option)\s*\(/,
    probe: "READ-ONLY: baseline the option via a page render or REST settings GET; version-discriminate with the plugin readme 'Stable tag'. The overwrite POST itself is change territory — operator sign-off required, never fired by the miner." },
  { id: 'account-control', weight: 95, label: 'account control (user create/update/password/role)',
    re: /(?<![\w$>:-])(wp_insert_user|wp_update_user|wp_set_password)\s*\(|->(?:set_role|add_role)\s*\(/,
    probe: 'READ-ONLY: enumerate the endpoint with an unauthenticated/authenticated differential only; any account mutation is operator-approved change territory.' },
  { id: 'file-delete', weight: 90, label: 'arbitrary file delete', gated: true,
    re: /(?<![\w$>:-])(unlink|rmdir)\s*\(/,
    probe: 'DOCTRINE-GATED: response differential between an existing and a guaranteed-absent path ONLY (read-only); never point it at a real target file.' },
  { id: 'cmd-spawn', weight: 88, label: 'command spawn (subprocess / MCP stdio bridge)', gated: true,
    re: /(?<![\w$>:-])(proc_open|popen)\s*\(/,
    probe: 'DOCTRINE-GATED: prove reachability with an intentionally INVALID command and grade the error differential only; never spawn a real payload.' },
  { id: 'file-write', weight: 85, label: 'arbitrary file write/upload', gated: true,
    re: /(?<![\w$>:-])(file_put_contents|move_uploaded_file|fwrite|copy|rename)\s*\(/,
    probe: 'DOCTRINE-GATED: submit an intentionally INVALID/empty file and grade the rejection — proves reachability without writing content.' },
  { id: 'lfi', weight: 75, label: 'local file inclusion (tainted include/require)',
    re: /(?<![\w$>:-])(?:include|include_once|require|require_once)\s*\(?\s*\$([A-Za-z_]\w*)/, taintedOnly: true,
    probe: 'READ-ONLY: request a path KNOWN to exist and benign (e.g. the plugin readme.txt) and observe the inclusion differential; no /etc/passwd pulls without scope sign-off.' },
  { id: 'sqli', weight: 70, label: 'SQL injection candidate (query without ->prepare)',
    re: /->(?:query|get_results|get_var|get_row|get_col)\s*\(/, sqli: true,
    probe: 'READ-ONLY differential: single-quote error split or a benign ORDER BY permutation; no UNION/exfil, no writes. addslashes/charset caveats apply when confidence is low.' },
  // TWO ACCEPTED CLASSES THAT WERE NOT MODELED AT ALL (2026-09-17 — found by auditing the
  // class list against the doctrine's gold shapes and scopecheck's accepted types):
  // `unserialize` appeared ONLY in NO_DESCEND, and dynamic invocation appeared nowhere,
  // yet submit-drive accepts both (`case 'object-injection'`, RCE/ACE) and AGENT-GUIDE lists
  // "PHP object injection" as a gold shape. Both require REQUEST-DERIVED input to be a hit
  // (taintedOnly), so a fixed internal callable or a constant serialized string is silent.
  { id: 'object-injection', weight: 88, label: 'PHP object injection (unserialize on request-derived data)', gated: true, taintedOnly: true,
    re: /(?<![\w$>:-])unserialize\s*\(\s*\$([A-Za-z_]\w*)/,
    probe: 'DOCTRINE-GATED: prove the deserialization path with a benign serialized object of a class already present in the plugin; never chain a destructive POP gadget.' },
  { id: 'dynamic-call', weight: 86, label: 'dynamic invocation on a request-derived callable (RCE surface)', gated: true, taintedOnly: true,
    re: /(?<![\w$>:-])(?:call_user_func(?:_array)?|eval)\s*\(\s*\$([A-Za-z_]\w*)/,
    probe: 'DOCTRINE-GATED: demonstrate the callable reaches the request with a BENIGN target only; never spawn a real payload.' },
  // THIRD unmodeled accepted class (2026-09-17): arbitrary file READ / download. The engine had
  // file-DELETE, file-WRITE and lfi, but nothing for a download primitive — while scopecheck
  // accepts `file-dl-del` and AGENT-GUIDE lists "arbitrary file ... download" as a gold shape.
  // `readfile( $_GET['file'] )` on wp-config.php is the classic unauthenticated high/crit.
  { id: 'file-read', weight: 84, label: 'arbitrary file read/download (request-derived path)', gated: true, taintedOnly: true,
    re: /(?<![\w$>:-])(?:readfile|file_get_contents|highlight_file|show_source|readgzfile|fpassthru|file)\s*\(\s*\$([A-Za-z_]\w*)/,
    probe: 'DOCTRINE-GATED: request a path KNOWN to exist and benign (the plugin readme) and grade the content differential; never pull wp-config.php or /etc/passwd without operator sign-off.' },
  // The READ class (doctrine §3.9: broken access control reaching significant/sensitive
  // objects — API keys, tokens, password hashes). Added 2026-09-17 after auditing the miner's
  // own class list: EVERY class it had was a write/execute class, so the accepted read class —
  // and the 8.9% of unauthenticated WP-plugin CVEs in the pinned snapshot that are C:H I:N A:N —
  // was invisible to it. Matched by the dedicated source+emit scan in scanSinks (both sides
  // required in the same function); the regex below is deliberately inert.
  { id: 'sensitive-read', weight: 85, label: 'sensitive-value disclosure (credential-named option/user-meta read emitted in a response)',
    re: /(?!)/,
    probe: 'READ-ONLY: request the endpoint as the lowest-privilege role and check whether the RESPONSE BODY carries the value (not just a set/unset boolean). NEVER transcribe a live secret into a report — redact it and describe its type.' },
  // Token-handling sinks (AI-feature class): a stored credential compared ==/strcmp (or a
  // bearer header read) is only an authz gate when no WP capability/session check backs
  // it — then the route's whole security IS the token, and the token lives in an option.
  { id: 'token-compare', weight: 65, label: 'stored-credential comparison as authz (==/strcmp against an option-stored key — absent or non-hash_equals bearer validation)',
    re: /(?<![\w$>:-])(?:strcmp|strcasecmp|strncasecmp)\s*\([^)]*(?:get_option|key|token|secret|credential)|\$[A-Za-z_]\w*\s*(?:===|!==|==|!=)\s*get_option\s*\(|get_option\s*\([^)]*\)\s*(?:===|!==|==|!=)\s*(?:\$[A-Za-z_]|strtolower\s*\(\s*\$|trim\s*\(\s*\$|strtoupper\s*\(\s*\$)|(?:===|!==|==|!=)\s*(?:strtolower|strtoupper|trim)\s*\(\s*\$[A-Za-z_]\w*(?:_key|_token|_secret|Key|Token|Secret)\w*/i,
    probe: "READ-ONLY: establish the token's provenance — default/empty option value, guessable, or disclosed by another endpoint (the AI Engine MCP shape). An empty stored token compared == against an absent presented token is an unauthenticated bypass; never submit a real credential." },
  { id: 'meta-write', weight: 55, label: 'user meta write (privesc ladder rung)',
    re: /(?<![\w$>:-])(update_user_meta|delete_user_meta|wp_delete_user)\s*\(/,
    probe: 'As a LOW-PRIV test user, write a marker meta to YOUR OWN account id and read it back on your own profile; never another user id.' },
  { id: 'bearer-intake', weight: 55, label: 'bearer/API-key intake from request headers (a presented token is the authz credential)',
    re: AUTH_HEADER,
    probe: 'READ-ONLY: present a deliberately WRONG bearer token and grade the rejection differential against presenting none; identical responses mean the token is never actually verified.' },
];
const SINK_BY_ID = Object.fromEntries(SINK_DEFS.map((s) => [s.id, s]));

// The named sink classes, exposed for variantsweep's class signatures (fresh copies of
// the regexes — the tuning table itself stays internal and unshared).
export function sinkClasses() {
  return SINK_DEFS.map((s) => ({ id: s.id, label: s.label, weight: s.weight, re: new RegExp(s.re.source, s.re.flags) }));
}

// meta-write with an ATTACKER-CHOSEN user id (update_user_meta($_POST['userID'], …)) is a
// different animal from a self-service write: usermeta holds wp_capabilities, so the
// primitive is one attacker-reachable key away from role escalation — and wp_delete_user
// in the same class is outright account removal. Rank it with account-control (95).
const ANY_USER_META_WEIGHT = 95;
const ANY_USER_META_LABEL = 'any-user meta write (attacker-chosen user id — privesc ladder rung)';

// Sink-value weighting: a write whose value is PROVABLY fixed from static evidence
// (update_option('x', 1) — a literal/constant, the sydney fontawesome shape) or a
// user-meta write PROVABLY self-only (update_user_meta(get_current_user_id(), …) —
// the sydney notifications marker) is a bounded primitive: kept on the board but
// auto-degraded out of the top. Only literal/certain shapes qualify — anything
// dynamic scores exactly as before (conservative: never degrade a maybe).
const FIXED_WRITE_FACTOR = 0.3;

// A bearer/API-key comparison with NO capability/session check behind it is token-only
// authz: any visitor presenting the string passes, and the string lives in an option
// (one read/overwrite primitive away from bypass — the AI Engine MCP-endpoint shape).
// Rank such hits at the file-write band instead of their bare weight.
const WEAK_TOKEN_WEIGHT = 80;
const WEAK_TOKEN_LABEL = 'token-only authz gate (stored credential compared ==/strcmp — no WP capability/session check behind it)';

// The exposed endpoint itself is the finding for AI/MCP surface (the $2,145 AI Engine
// class): ranked when an AI-named route/hook or an MCP-speaking handler has no
// capability gate. Emitted as a special-case hit, like the shortcode second-order one.
const AI_ENDPOINT = { id: 'ai-endpoint', weight: 65, label: 'AI/MCP endpoint exposure (agent/MCP surface without a capability gate)',
  probe: 'READ-ONLY: enumerate the endpoint unauthenticated (OPTIONS/GET) and list the tools/methods it advertises; invoking agent tools that mutate state is change territory.' };

// WP 6.9 Abilities-API / MCP-Adapter classes (the WP-native layer of the AI Engine
// anchor). Weights slot BELOW the Madara option-overwrite family (100/95/90), in the
// cmd-spawn/ai-endpoint band; a token-only ability gate upgrades through the shared
// WEAK_TOKEN_WEIGHT machinery like any REST route.
// The MCP-adapter public ability is the flagship: meta.mcp.public=true registers the
// ability as an MCP tool on the adapter's default server, and the adapter gates ONLY on
// the ability's own permission_callback — the adapter is the transport, the weak gate is
// the vulnerability. Ranked at the file-write band.
const MCP_PUBLIC_ABILITY = { id: 'mcp-public-ability', weight: 85, label: 'MCP-adapter public ability without a sound permission_callback (meta.mcp.public=true — exposed as an MCP tool; the adapter gates ONLY on the ability permission_callback)',
  probe: "READ-ONLY: enumerate what the adapter exposes (the mcp-adapter-discover-abilities tool, or GET /wp-json/wp-abilities/v1/abilities as the LOWEST-privilege role) and confirm the ability is listed and its gate state; invoking a state-changing ability is change territory — operator sign-off required." };
// The weak gate itself, without MCP-public exposure (REST-exposed or PHP/JS-only — a
// privesc-ladder rung reachable once any second bug executes abilities). Ranked with
// ai-endpoint.
const ABILITY_WEAK_GATE = { id: 'ability-weak-gate', weight: 65, label: 'Abilities-API registration without a sound permission_callback (ability executable with no capability gate — PHP/JS/REST/MCP all defer to this one callback)',
  probe: 'READ-ONLY: GET /wp-json/wp-abilities/v1/{namespace}/{ability} as the lowest-privilege role and grade the metadata differential; check meta.show_in_rest / meta.mcp.public for actual exposure. Executing a state-changing ability is change territory.' };

const SECOND_ORDER = { id: 'second-order-injection', weight: 30, label: 'second-order injection (shortcode attribute → markup)',
  probe: 'Preview a draft containing the shortcode as the lowest-privilege role and inspect the emitted markup; stored payloads on production need operator sign-off.' };

// Mitigations: presence in the HANDLER body downgrades reachability. current_user_can is
// strong (→ admin-gated); nonce/login checks only prove an authenticated session
// (unauth → subscriber). is_admin() is listed per doctrine but is a WEAK signal — it is
// true during admin-ajax.php, so it gates nothing there; we keep the note attached.
const MITIGATIONS = [
  { id: 'current_user_can', re: /(?<![\w$>:-])current_user_can\s*\(/, strong: true },
  { id: 'check_ajax_referer', re: /(?<![\w$>:-])check_ajax_referer\s*\(/ },
  { id: 'wp_verify_nonce', re: /(?<![\w$>:-])wp_verify_nonce\s*\(/ },
  { id: 'check_admin_referer', re: /(?<![\w$>:-])check_admin_referer\s*\(/ },
  { id: 'is_user_logged_in', re: /(?<![\w$>:-])is_user_logged_in\s*\(/ },
  { id: 'is_admin', re: /(?<![\w$>:-])is_admin\s*\(\s*\)/, note: 'weak: true during admin-ajax.php — does not by itself gate ajax reachability' },
  // user_can( $user, 'cap' ) — WP's OBJECT-form capability check. It gates the REQUEST only
  // when $user is provably the requester: resolved in the SAME body from the request's own
  // credentials or the current-user object (the SureTriggers shape —
  // $user = wp_authenticate_application_password( null, $u, $p ); then
  // user_can( $user, 'administrator' ); which sat at the floor as a confirmed UNAUTH before
  // this existed). A check against a chosen/ambient id is not a gate on the requester and is
  // credited nothing, in either direction. Kept in lock-step with reachability's GATE_RES.
  { id: 'user_can', re: /(?<![\w$>:-])user_can\s*\(\s*\$([A-Za-z_]\w*)\s*,\s*['"]([^'"]+)['"]/, strong: true, objectForm: true },
];

// The requester-resolution rule for the object-form capability check — the same rule and the
// same resolver list as engine/reachability.mjs (the two engines' gate vocabularies must not
// drift, or verdicts stop matching the report they adjudicate).
const REQUESTER_RESOLVERS = [
  'wp_authenticate_application_password\\s*\\(',
  '(?<![\\w$>:-])wp_authenticate\\s*\\(',
  '(?<![\\w$>:-])wp_get_current_user\\s*\\(',
];
function requesterResolved(lines, varName) {
  for (const r of REQUESTER_RESOLVERS) {
    const re = new RegExp(`\\$${varName}\\s*=[^;]*${r}`);
    if (lines.some((l) => re.test(l))) return true;
  }
  return false;
}

// Names we never descend into during transitive resolution (language constructs, the
// sink/mitigation functions themselves, and the noisy WP/stdlib surface).
const NO_DESCEND = new Set([
  'isset', 'empty', 'unset', 'array', 'echo', 'print', 'exit', 'die', 'list', 'eval', 'include', 'include_once', 'require', 'require_once',
  'function', 'if', 'for', 'foreach', 'while', 'switch', 'catch', 'return', 'new', 'clone', 'static', 'global', 'fn',
  'add_action', 'add_filter', 'apply_filters', 'do_action', 'add_shortcode', 'register_rest_route',
  'wp_send_json_success', 'wp_send_json_error', 'wp_die', 'wp_redirect', 'wp_parse_args', 'wp_kses', 'wp_kses_post',
  'get_option', 'get_post', 'get_post_meta', 'update_post_meta', 'delete_post_meta', 'get_user_meta', 'get_current_user_id',
  'esc_attr', 'esc_html', 'esc_url', 'esc_textarea', 'esc_js', 'esc_sql', 'sanitize_text_field', 'sanitize_title', 'absint', 'intval',
  '__', '_e', '_x', '_n', 'sprintf', 'printf', 'number_format', 'date', 'time',
  'is_array', 'is_string', 'is_numeric', 'is_object', 'is_wp_error', 'count', 'strlen', 'strpos', 'substr', 'trim', 'ltrim', 'rtrim',
  'implode', 'explode', 'json_encode', 'json_decode', 'serialize', 'unserialize', 'urldecode', 'urlencode', 'rawurlencode',
  'array_merge', 'array_keys', 'array_values', 'array_map', 'array_filter', 'array_slice', 'in_array', 'array_key_exists',
  'preg_match', 'preg_replace', 'preg_match_all', 'str_replace', 'strtolower', 'strtoupper', 'md5', 'sha1', 'hash',
  'get_instance', 'get_wpdb',
  'wp_register_ability', 'wp_unregister_ability', 'wp_get_ability', 'wp_get_abilities', 'wp_has_ability', 'wp_register_ability_category',
  ...SINK_DEFS.flatMap((s) => (s.re.source.match(/[a-z_][a-z0-9_]+/gi) || [])),
  ...MITIGATIONS.map((m) => m.id),
]);

// --- structural parsing (line-based; comments/strings blanked for brace math) --------

// Blank comments and string CONTENTS so brace counting and call detection are not fooled
// by '{', '}' or 'function(' inside a string literal or comment. Heredoc/nowdoc bodies
// are NOT understood (documented blind spot).
function structureLines(src) {
  const out = [];
  let inBlock = false;
  for (const raw of String(src).split('\n')) {
    let s = '';
    let i = 0;
    while (i < raw.length) {
      if (inBlock) {
        const e = raw.indexOf('*/', i);
        if (e === -1) { i = raw.length; } else { inBlock = false; i = e + 2; }
        continue;
      }
      const two = raw.slice(i, i + 2);
      if (two === '/*') { inBlock = true; i += 2; continue; }
      if (two === '//' || raw[i] === '#') break;
      if (raw[i] === "'" || raw[i] === '"') {
        const q = raw[i];
        i++;
        while (i < raw.length && raw[i] !== q) { if (raw[i] === '\\') i++; i++; }
        i++;
        s += ' ';
        continue;
      }
      s += raw[i];
      i++;
    }
    out.push(s);
  }
  return out;
}

// Comment-only lines (docblock bodies, // lines) never register anything — a phpDoc
// `@see register_rest_route()` or an example `wp_register_ability()` inside a docblock
// must not trigger a parse, nor bound a window.
const COMMENT_LINE = /^\s*(?:\*|\/\/)/;

// Runaway guards for a registration's argument array — a SAFETY bound, never the
// parser. The next registration of the same kind always cuts the window first.
const ABILITY_WINDOW_MAX = 400;
const REST_WINDOW_MAX = 200;

// Registration argument window: the registration line through the line where its
// ARGUMENT LIST closes (paren/bracket depth back to zero on comment/string-blanked
// text), or to the next registration of the same kind, whichever comes first.
//
// WHY NOT A FIXED LINE BUDGET: WP 6.9 ability args are routinely 60+ lines (typed
// input/output schemas), so a flat `i + 60` window truncates the permission_callback
// and mis-reads a PRESENT gate as ABSENT — the one error direction that manufactures a
// false unauthenticated finding (measured: siteseo/main/abilitiesregister.php:222 puts
// its gate 63 lines down). Returns { lines, truncated }; `truncated` means the safety
// bound bit before the args closed, so the caller must report gate state as UNPARSED,
// never absent.
function argsWindow(orig, san, start, { maxLines = REST_WINDOW_MAX, isNext } = {}) {
  const limit = Math.min(orig.length, start + maxLines);
  let depth = 0;
  let opened = false;
  for (let j = start; j < limit; j++) {
    if (j > start && !COMMENT_LINE.test(orig[j]) && isNext && isNext(orig[j])) return { lines: orig.slice(start, j), truncated: false };
    let closed = false;
    for (const ch of san[j] || '') {
      if (ch === '(' || ch === '[') { depth++; opened = true; }
      else if (ch === ')' || ch === ']') { depth--; if (opened && depth <= 0) closed = true; }
    }
    if (opened && depth <= 0 && closed) return { lines: orig.slice(start, j + 1), truncated: false };
  }
  return { lines: orig.slice(start, limit), truncated: true };
}

const FN_RE = /\bfunction\s+&?\s*([A-Za-z_]\w*)\s*\(/;

// Extract named functions/methods with brace-matched bodies (original + sanitized text).
function extractFunctions(path, orig, san, gaps) {
  const fns = [];
  for (let i = 0; i < san.length; i++) {
    const m = san[i].match(FN_RE);
    if (!m) continue;
    let depth = 0;
    let opened = false;
    let end = -1;
    for (let j = i; j < san.length; j++) {
      for (const ch of san[j]) {
        if (ch === '{') { depth++; opened = true; } else if (ch === '}') { depth--; }
      }
      if (opened && depth <= 0) { end = j; break; }
      if (!opened && j - i > 6) break; // interface/abstract declaration, no body
    }
    if (!opened) continue;
    const unbalanced = end === -1;
    if (unbalanced) {
      end = san.length - 1;
      if (gaps.length < 60) gaps.push({ ref: `${path}:${i + 1}`, reason: `unbalanced braces in function ${m[1]} — body taken to EOF (heuristic)` });
    }
    fns.push({ name: m[1], path, line: i + 1, end, body: orig.slice(i, end + 1), san: san.slice(i, end + 1) });
    i = end; // do not double-collect nested declarations
  }
  return fns;
}

// Callback of add_action/add_shortcode: string form `'cb'` or array form
// `array($this, 'cb')` / `array('Class','cb')` / `[ $this, 'cb' ]` / `[ Class::class, 'cb' ]`
// (the method is the LAST quoted id). Multi-line array(/[ forms are joined before parsing.
// Closures are reported unresolved.
function parseCallback(expr) {
  if (/^\s*(function\b|fn\s*\()/.test(expr)) return { closure: true };
  const ids = [...expr.matchAll(/['"]([A-Za-z_]\w*)['"]/g)].map((x) => x[1]);
  if (/array\s*\(|\[/.test(expr)) return { name: ids[ids.length - 1] };
  return { name: ids[0] };
}

// Args-array callback value for `key`: `array($this,'m')` / `array('C','m')`, the
// short-array forms `[ $this, 'm' ]` / ` [ C::class, 'm' ]` / `[ 'C', 'm' ]` (the method
// is the LAST quoted id — resolution stays name-based, so $this/self::class/Class all
// collapse to the same method lookup), a plain string `'m'`, or a STRING STATIC-method
// reference `'C::m'` / `'\A\B\C::m'` (the gosmtp/siteseo ability-gate shape; method =
// the id after '::'). Match with the method name in [1], or null — a null is
// "unreadable", never "absent" (see the ability gate's pcUnparseable).
function cbMatch(win, key) {
  const k = `['"]${key}['"]\\s*=>\\s*`;
  return win.match(new RegExp(k + `array\\([^)]{0,200}?,\\s*['"]([A-Za-z_]\\w*)['"]\\s*\\)`))
      || win.match(new RegExp(k + `\\[[^\\]]{0,200}?,\\s*['"]([A-Za-z_]\\w*)['"]\\s*\\]`))
      || win.match(new RegExp(k + `['"](?:\\\\?[A-Za-z_]\\w*(?:\\\\[A-Za-z_]\\w*)*)::([A-Za-z_]\\w*)['"]`))
      || win.match(new RegExp(k + `['"]([A-Za-z_]\\w*)['"]`));
}

// Inline closure value of an args key: `function (...) { ... }` (optionally `static`,
// optional `use (...)`) — body brace-matched within the window — or `fn (...) => expr`
// (single expression: cut at the first depth-0 ',', ')' or newline). Returns the closure
// TEXT for mitigation scanning, or null when the value is not a closure literal. Brace
// math runs on raw text (strings containing '{' inside a gate closure can fool it —
// documented blind spot).
function closureValue(win, key) {
  const m = win.match(new RegExp(`['"]${key}['"]\\s*=>\\s*((?:static\\s+)?function\\s*\\([^)]*\\)\\s*(?:use\\s*\\([^)]*\\)\\s*)?\\{|fn\\s*\\([^)]*\\)\\s*=>)`));
  if (!m) return null;
  const rest = win.slice(m.index + m[0].length);
  if (m[1].endsWith('{')) {
    let depth = 1;
    for (let i = 0; i < rest.length; i++) {
      if (rest[i] === '{') depth++;
      else if (rest[i] === '}' && --depth === 0) return rest.slice(0, i);
    }
    return rest; // unbalanced — bounded by the registration window itself
  }
  let depth = 0;
  for (let i = 0; i < rest.length; i++) {
    const ch = rest[i];
    if (ch === '(' || ch === '[') depth++;
    else if (ch === ')' || ch === ']') { if (depth === 0) return rest.slice(0, i); depth--; }
    else if ((ch === ',' || ch === '\n') && depth === 0) return rest.slice(0, i);
  }
  return rest;
}

// Mitigations found in a closure's text (same ids/labels as findMitigations).
function closureMits(text) {
  const found = MITIGATIONS.filter((mit) => mit.re.test(text)).map((mit) => (mit.note ? `${mit.id} (${mit.note})` : mit.id));
  return found.length ? found : null;
}

function hookReach(hook) {
  if (/^wp_ajax_nopriv_/.test(hook)) return { base: 'unauth', kind: 'ajax-nopriv' };
  if (/^wp_ajax_/.test(hook)) return { base: 'subscriber', kind: 'ajax' };
  if (hook === 'admin_init') return { base: 'unauth', kind: 'admin_init', note: 'admin_init fires on unauthenticated admin-ajax.php/admin-post.php requests' };
  if (hook === 'init') return { base: 'unauth', kind: 'init', note: 'init fires on EVERY request, front-end included — request-driven sinks in init handlers are unauthenticated' };
  if (/^admin_post_nopriv/.test(hook)) return { base: 'unauth', kind: 'admin-post-nopriv' };
  if (/^admin_post(?:_|$)/.test(hook)) return { base: 'subscriber', kind: 'admin-post' };
  return null;
}

function extractRegistrations(path, orig, san) {
  const regs = [];
  // Comment-only lines are skipped via the module-level COMMENT_LINE (see above).
  for (let i = 0; i < orig.length; i++) {
    const line = orig[i];
    if (COMMENT_LINE.test(line)) continue;
    let m = line.match(/\badd_action\(\s*['"]([^'"]+)['"]\s*,\s*(.*)$/);
    if (m) {
      const reach = hookReach(m[1]);
      if (reach) {
        let expr = m[2];
        if (/array\s*\([^)]*$/.test(expr) || /\[[^\]]*$/.test(expr)) expr = orig.slice(i, i + 4).join(' ').replace(/^[^(]*\(\s*['"][^'"]+['"]\s*,\s*/, '');
        regs.push({ path, line: i + 1, hook: m[1], ...reach, ...parseCallback(expr), ...(AI_SURFACE.test(m[1]) ? { surface: 'ai' } : {}) });
      }
      continue;
    }
    m = line.match(/\badd_shortcode\(\s*['"]([^'"]+)['"]\s*,\s*(.*)$/);
    if (m) {
      let expr = m[2];
      if (/array\s*\([^)]*$/.test(expr) || /\[[^\]]*$/.test(expr)) expr = orig.slice(i, i + 4).join(' ').replace(/^[^(]*\(\s*['"][^'"]+['"]\s*,\s*/, '');
      regs.push({ path, line: i + 1, hook: `shortcode:${m[1]}`, base: 'shortcode', kind: 'shortcode', ...parseCallback(expr), ...(AI_SURFACE.test(m[1]) ? { surface: 'ai' } : {}) });
      continue;
    }
    // ADMIN-PAGE REGISTRATIONS (add_menu_page & friends) — added 2026-09-17 for the
    // sensitive-read class. The screens where credential-named options are echoed
    // (`value="<?php echo esc_attr( get_option( 'x_api_key' ) ) ?>"`) are registered HERE, not
    // via add_action, so no registration covered them and the reads were never scanned
    // (measured: royal-elementor-addons, forminator, translatepress, broken-link-checker all
    // echo such values on settings screens the miner could not see). The CAPABILITY is the
    // gate: 'read'/'edit_posts' means a non-admin reaches the page — that is a real finding;
    // 'manage_options' means admin-gated, which is correct and boring.
    m = line.match(/\b(add_menu_page|add_submenu_page|add_options_page|add_plugins_page|add_theme_page|add_users_page|add_dashboard_page|add_management_page|add_posts_page|add_comments_page|add_media_page|add_pages_page)\s*\(/);
    if (m) {
      const { lines: pgWin } = argsWindow(orig, san, i, {
        maxLines: 8,
        isNext: (l) => /add_(?:menu|submenu|options|plugins|theme|users|dashboard|management|posts|comments|media|pages)_page\s*\(/.test(l),
      });
      const pgText = pgWin.join(' ');
      const pArgs = callArgs(pgText, pgText.indexOf('('));
      // add_menu_page( $page_title, $menu_title, $capability, $menu_slug, $callback, … )  → cap 3rd, cb 5th
      // add_submenu_page( $parent, $page_title, $menu_title, $capability, $slug, $callback ) → cap 4th, cb 6th
      const isSub = m[1] === 'add_submenu_page';
      const capArg = (pArgs[isSub ? 3 : 2] || '').trim();
      const cbArg = (pArgs[isSub ? 5 : 4] || '').trim();
      const cap = /^['"][^'"]*['"]$/.test(capArg) ? capArg.replace(/^['"]|['"]$/g, '') : '';
      // CAPABILITY → REACH, per the WordPress capability model. Only `read` (and the
      // legacy `exist`) is held by EVERY logged-in user, so only those are 'subscriber'.
      // Contributor and above are privileged tiers: mapping them to 'subscriber' was an
      // OVER-CLAIM (this exact bug shipped for ten minutes — `edit_others_posts` was bucketed
      // as subscriber and produced a fabricated "any-authenticated-user file write" on
      // broken-link-checker's Editor page). The engine has no contributor tier, and the safe
      // direction is to under-claim: contributor-and-above reads as 'admin-gated' WITH the
      // capability named in the note, so a human aiming at an mVDP target can still see it.
      // (A dedicated contributor tier is the correct future refinement.)
      const SUBSCRIBER_CAP = /^(?:read|exist)$/;
      const base = SUBSCRIBER_CAP.test(cap) ? 'subscriber'
        : cap === '' ? 'unknown' : 'admin-gated';
      regs.push({
        path, line: i + 1, hook: `admin-page:${cap || 'dynamic'}`, base, kind: 'admin-page',
        ...parseCallback(cbArg),
        note: `admin page registered with capability '${cap || capArg.slice(0, 30)}'`,
      });
      continue;
    }
    if (/\bregister_rest_route\s*\(/.test(line)) {
      // Depth-aware window (args through their closing bracket), cut at the NEXT
      // register_rest_route so a dense block of registrations never bleeds the
      // following route's callback/gate values into this one.
      const { lines: restLines, truncated: restTruncated } = argsWindow(orig, san, i, {
        maxLines: REST_WINDOW_MAX,
        isNext: (l) => /\bregister_rest_route\s*\(/.test(l),
      });
      const win = restLines.join('\n');
      // callback/permission_callback shapes: plain string, array( form or short-array
      // [ $this, 'm' ] / [ C::class, 'm' ] form (method = LAST quoted id, resolved
      // name-based), or an inline closure (return-true = open gate; a capability-bearing
      // closure is credited from its body like a named callback — see pcClosureMits).
      const cb = cbMatch(win, 'callback');
      const pc = cbMatch(win, 'permission_callback');
      // Inline closure gates: extract the closure attached to THIS key (window-wide
      // regexes bleed into the next registration). return-true = open gate (function
      // body `return true;` / arrow `=> true`); any other closure is mitigation-scanned
      // and credited like a named callback (pcClosureMits), or reported not-analyzed.
      const pcClosureText = !pc ? closureValue(win, 'permission_callback') : null;
      const pcOpenClosure = pcClosureText != null && /^(?:return\s+true\s*;|true\b)/.test(pcClosureText.trim());
      const pcClosureMitigations = !pcOpenClosure && pcClosureText ? closureMits(pcClosureText) : null;
      const rm = win.match(/register_rest_route\s*\(\s*['"]([^'"]+)['"]\s*,\s*['"]([^'"]+)['"]/);
      const route = rm ? `${rm[1]}${rm[2]}` : undefined;
      const surface = route && AI_SURFACE.test(route) ? 'ai' : undefined;
      // Truncated window: a gate key we cannot see must never read as absent.
      const pcKeyPresent = /['"]permission_callback['"]\s*=>/.test(win);
      const pcUnparseable = !pc && !pcClosureText && (pcKeyPresent || restTruncated || !argsInline(nThArgExpr(win, 2)));
      // WP ≥5.5: an ABSENT permission_callback is a _doing_it_wrong notice, not a gate —
      // the route stays publicly reachable. Treated as open for AI surface (the exposure
      // is the finding class there); elsewhere the historical 'unknown' stands. A closure
      // gate we cannot grade is NOT absent — 'unknown' with an honest note either way.
      const base = (pc && pc[1] === '__return_true') || pcOpenClosure || (!pc && !pcClosureText && !pcUnparseable && surface) ? 'unauth' : 'unknown';
      regs.push({
        path, line: i + 1, hook: 'rest_route', kind: 'rest', base,
        name: cb ? cb[1] : undefined,
        closure: !cb,
        route,
        ...(surface ? { surface } : {}),
        permissionCallback: pc && pc[1] !== '__return_true' ? pc[1] : undefined,
        ...(pcClosureMitigations ? { pcClosureMits: pcClosureMitigations } : {}),
        ...(pcUnparseable ? { pcUnparseable: true } : {}),
        preMitigation: pcUnparseable ? 'permission_callback present but NOT READ — the registration window hit its safety bound mid-args (reported unparsed, never absent)' :
          pc && pc[1] !== '__return_true' ? `permission_callback:${pc[1]} (resolved+scanned when in-tree)` :
          (pcOpenClosure ? 'permission_callback closure returns true' :
            (pcClosureMitigations ? `permission_callback closure (${pcClosureMitigations.join(', ')})` :
              (pcClosureText ? 'permission_callback closure — inline gate not analyzed' :
                (!pc ? (surface ? 'permission_callback absent — public since WP 5.5' : 'permission_callback absent') : null)))),
      });
      continue;
    }
    // WP 6.9 Abilities API: wp_register_ability('ns/name', array(...)). Args are long
    // (typed schemas) — window-parse ≤60 lines, cut at the next registration so a
    // missing key never reads the NEXT ability's value. The GATE is the ability's own
    // permission_callback; the EXPOSURE is meta.mcp.public (MCP-adapter default-server
    // tool) / meta.show_in_rest (authenticated wp-abilities REST namespace). A function
    // DEFINITION line (the polyfill shape) is not a registration.
    if (/(?<![\w$>:-])wp_register_ability\s*\(/.test(line) && !/^\s*function\s/.test(line)) {
      // Depth-aware window (see argsWindow): ability args carry typed schemas and run
      // well past 60 lines, so a fixed budget truncates the permission_callback and
      // manufactures a false unauth. Cut at the next registration, never mid-args.
      const { lines: abLines, truncated } = argsWindow(orig, san, i, {
        maxLines: ABILITY_WINDOW_MAX,
        isNext: (l) => /(?<![\w$>:-])wp_register_ability\s*\(/.test(l) && !/^\s*function\s/.test(l),
      });
      const win = abLines.join('\n');
      const nm = win.match(/(?<![\w$>:-])wp_register_ability\s*\(\s*['"]([^'"]+)['"]/);
      const ec = cbMatch(win, 'execute_callback');
      const pc = cbMatch(win, 'permission_callback');
      const pcClosureText = !pc ? closureValue(win, 'permission_callback') : null;
      const pcOpenClosure = pcClosureText != null && /^(?:return\s+true\s*;|true\b)/.test(pcClosureText.trim());
      const pcClosureMitigations = !pcOpenClosure && pcClosureText ? closureMits(pcClosureText) : null;
      const pcClosure = !pc && !pcOpenClosure && !!pcClosureText;
      // A key present inside a TRUNCATED window cannot be graded — we cut mid-args, so
      // "key not found" is ignorance, not absence. So is a DATA-DRIVEN registration: when
      // the args argument is a variable, this window never contained the args at all.
      const pcKeyPresent = /['"]permission_callback['"]\s*=>/.test(win);
      const pcUnparseable = !pc && !pcClosureText && (pcKeyPresent || truncated || !argsInline(nThArgExpr(win, 1)));
      const mcpPublic = /['"]mcp['"]\s*=>\s*(?:array\s*\(|\[)[^\])]{0,160}?['"]public['"]\s*=>\s*true/.test(win);
      const showInRest = /['"]show_in_rest['"]\s*=>\s*true/.test(win);
      // gate: named (resolved+scanned in-tree) | open (__return_true / return-true
      // closure) | closure (inline gate — a capability-bearing one is credited from its
      // body via pcClosureMits; an unanalyzable one is reported, not graded) | absent
      // (a required arg — if the registration still succeeds there is NO gate; flagged
      // at medium confidence with that caveat attached) | unparsed (present, but the
      // window's safety bound cut the args before we could read it — NEVER absent).
      const gate = pc && pc[1] !== '__return_true' ? 'named' : (pc && pc[1] === '__return_true') || pcOpenClosure ? 'open' : pcClosure ? 'closure' : pcUnparseable ? 'unparsed' : 'absent';
      // mcp.public + open/absent gate = the unauth-via-MCP-adapter anchor class (the
      // adapter's default server exposes the ability as a tool; the ONLY authz is this
      // callback). show_in_rest runs over the AUTHENTICATED wp-abilities namespace →
      // any-role ('subscriber'). No exposure flag: PHP/JS-executable only — ranked as a
      // privesc-ladder rung, not proven external surface.
      const base = gate === 'open' || gate === 'absent' ? (mcpPublic ? 'unauth' : 'subscriber') : 'unknown';
      regs.push({
        path, line: i + 1, hook: 'wp_register_ability', kind: 'ability', base,
        name: ec ? ec[1] : undefined,
        closure: !ec,
        ability: nm ? nm[1] : undefined,
        surface: 'ai', // the Abilities API exists to feed AI agents/MCP — always AI surface
        permissionCallback: gate === 'named' ? pc[1] : undefined,
        ...(pcClosureMitigations ? { pcClosureMits: pcClosureMitigations } : {}),
        ...(pcUnparseable ? { pcUnparseable: true } : {}),
        abilityGate: gate, mcpPublic, showInRest,
        preMitigation: gate === 'named' ? `permission_callback:${pc[1]} (resolved+scanned when in-tree)` :
          pcOpenClosure ? 'permission_callback closure returns true' :
            gate === 'closure' ? (pcClosureMitigations ? `permission_callback closure (${pcClosureMitigations.join(', ')})` : 'permission_callback closure — inline gate not analyzed') :
              gate === 'unparsed' ? 'permission_callback present but NOT READ — the registration window hit its safety bound mid-args (reported unparsed, never absent)' :
                gate === 'absent' ? 'permission_callback absent (required arg — if the registration succeeds there is no gate)' : null,
      });
    }
  }
  return regs;
}

// --- body analysis -----------------------------------------------------------

// Taint: superglobal reads, auth-header/bearer intake, WP_REST_Request accessors, foreach
// sources, and array-element writes, plus one propagation pass through simple
// `$a = ... $b ...` assignments (the `$zip_dir = $_POST['zipDir']; … unlink($zip_dir)`
// shape). Element writes taint the array var ($opts[$k] = trim($v) ⇒ $opts tainted) — the
// settings-save idiom. `seed` pre-taints names up front (an ability execute_callback's
// $input — caller-controlled through the MCP/REST transport) so the propagation pass
// follows `$path = $input['path']` too.
function bodyTaint(body, seed) {
  const vars = new Set(seed || []);
  const TAINT_SOURCE = (expr) => SUPERGLOBAL.test(expr) || AUTH_HEADER.test(expr) || REST_REQUEST.test(expr);
  const taintedExpr = (expr) => TAINT_SOURCE(expr) || [...vars].some((v) => new RegExp(`\\$${v}\\b`).test(expr));
  const FOREACH_RE = /\bforeach\s*\(\s*(.+?)\s+as\s+(?:\$([A-Za-z_]\w*)\s*=>\s*)?\$([A-Za-z_]\w*)\s*\)/;
  const ASSIGN_RE = /^\s*\$([A-Za-z_]\w*)\s*=\s*(.+);/;
  const ELEM_RE = /^\s*\$([A-Za-z_]\w*)\s*\[[^\]]*\]\s*=\s*(.+);/;
  for (const line of body) {
    const m = line.match(ASSIGN_RE);
    if (m && TAINT_SOURCE(m[2])) vars.add(m[1]);
    const fm = line.match(FOREACH_RE);
    if (fm && TAINT_SOURCE(fm[1])) { if (fm[2]) vars.add(fm[2]); vars.add(fm[3]); }
  }
  for (const line of body) {
    const m = line.match(ASSIGN_RE);
    if (m && !vars.has(m[1]) && taintedExpr(m[2])) vars.add(m[1]);
    const em = line.match(ELEM_RE);
    if (em && !vars.has(em[1]) && taintedExpr(em[2])) vars.add(em[1]);
    const fm = line.match(FOREACH_RE);
    if (fm) { if (fm[2] && taintedExpr(fm[1])) vars.add(fm[2]); if (taintedExpr(fm[1])) vars.add(fm[3]); }
  }
  return vars;
}

function lineTaint(line, taintVars, bodyHasSuperglobal, directVars) {
  if (SUPERGLOBAL.test(line) || AUTH_HEADER.test(line) || REST_REQUEST.test(line)) return 'direct';
  // Seeded caller-controlled params (an ability execute_callback's $input) read DIRECT:
  // the transport hands the caller the whole array, type-validated only — `$input['path']`
  // on the sink line is exactly as steerable as `$_POST['path']`.
  if (directVars) for (const v of directVars) if (new RegExp(`\\$${v}\\b`).test(line)) return 'direct';
  for (const v of taintVars) if (new RegExp(`\\$${v}\\b`).test(line)) return 'tainted-var';
  return bodyHasSuperglobal ? 'ambient' : 'none';
}

function findMitigations(fn) {
  const found = [];
  for (const mit of MITIGATIONS) {
    const line = fn.body.find((l) => mit.re.test(l));
    if (line == null) continue;
    if (mit.objectForm) {
      // Only a requester-resolved user expression makes user_can() a gate on the REQUEST.
      const m = line.match(mit.re);
      if (!m || !requesterResolved(fn.body, m[1])) continue;
    }
    found.push(mit.note ? `${mit.id} (${mit.note})` : mit.id);
  }
  return found;
}

// findMitigations with bounded same-plugin descent (≤2 hops, ≤8 functions): a
// REST/ability permission_callback routinely delegates — `has_permission` →
// `Helper::has_cap` → current_user_can — so hop-0-only scanning under-credits real
// gates. Follows calleesOf()'s $this->/bare-name shapes PLUS Class::method() static
// calls (the helper-class idiom). Callee finds are tagged with the hop chain so the
// report keeps the indirection visible. Same name-based resolution rules (and their
// over/under-reach caveats) as the handler BFS.
function findMitigationsDeep(startFn, resolve, root, maxHops = 2, maxCallees = 8) {
  const found = new Map(); // mitigation id -> label
  const seen = new Set([startFn]);
  const queue = [{ fn: startFn, hops: 0, chain: [] }];
  const STATIC_CALLEE = /\b(?!self\b|static\b)[A-Za-z_]\w*::([A-Za-z_]\w*)\s*\(/g;
  while (queue.length) {
    const { fn, hops, chain } = queue.shift();
    for (const m of findMitigations(fn)) {
      const id = m.replace(/ \(.*$/, '');
      if (!found.has(id)) found.set(id, hops === 0 ? m : `${m} (via ${[...chain, fn.name].join(' -> ')})`);
    }
    if (hops >= maxHops || seen.size >= maxCallees) continue;
    const names = new Set(calleesOf(fn));
    for (const line of fn.san) for (const mm of line.matchAll(STATIC_CALLEE)) names.add(mm[1]);
    for (const n of names) {
      const c = resolve(n, fn.path, root);
      if (c && !seen.has(c)) { seen.add(c); queue.push({ fn: c, hops: hops + 1, chain: [...chain, fn.name] }); }
    }
  }
  return [...found.values()];
}

// Read a call's argument list as TOP-LEVEL arguments. `openIdx` is the index of the '('.
// Depth-aware over ()/[]/{} and quote-aware (with backslash escapes), so a nested array —
// or a trailing third argument — cannot defeat an argument read. This exists because the
// single-regex form required the value to be the LAST thing before ')', so the three-
// argument idiom `update_option('name', CONST, true)` (the autoload flag) escaped every
// argument-shape read: AI Engine's check_db() → update_option('mwai_db_version_…',
// MWAI_VERSION, true) ranked #1 as an unauthenticated option overwrite while the evidence
// on the same line showed a constant name and a constant value.
function callArgs(text, openIdx) {
  const args = [];
  let depth = 0;
  let cur = '';
  let q = null;
  for (let i = openIdx + 1; i < text.length; i++) {
    const ch = text[i];
    if (q) {
      if (ch === '\\') { cur += ch + (text[i + 1] ?? ''); i++; continue; }
      cur += ch;
      if (ch === q) q = null;
      continue;
    }
    if (ch === "'" || ch === '"') { q = ch; cur += ch; continue; }
    if (ch === '(' || ch === '[' || ch === '{') { depth++; cur += ch; continue; }
    if (ch === ')' || ch === ']' || ch === '}') {
      if (depth === 0 && ch === ')') { args.push(cur.trim()); return args; }
      depth = Math.max(0, depth - 1);
      cur += ch;
      continue;
    }
    if (ch === ',' && depth === 0) { args.push(cur.trim()); cur = ''; continue; }
    cur += ch;
  }
  args.push(cur.trim());
  return args;
}

// The n-th top-level argument of the registration call in `text`, or null when it cannot be
// read. Separates a DATA-DRIVEN registration from an inline one:
//   register_rest_route( $ns, $route, $args ) — args are argument #3
//   wp_register_ability( $name, $args )       — args are argument #2
// When that argument is a VARIABLE the window never contained the args, so a missing
// permission_callback key is IGNORANCE, never absence. Measured: Everest Forms 3.x registers
// every ability in a loop from $def['args'] (each definition carrying its own
// permission_callback) and the loop site was graded an ungated UNAUTH ability.
function nThArgExpr(text, idx) {
  const m = text.match(/(?<![\w$>:-])(?:wp_register_ability|register_rest_route)\s*\(/);
  if (!m) return null;
  const args = callArgs(text, m.index + m[0].length - 1);
  return args.length > idx ? args[idx] : null;
}
// True only when the args argument IS an inline array literal whose keys we could have read.
function argsInline(expr) {
  return expr != null && /^(?:array\s*\(|\[)/.test(expr.trim());
}

// Scan one function body for impact sinks. Returns raw hits. `directVars` names params
// the caller controls wholesale (ability execute_callback $input) — direct taint.
function scanSinks(fn, taintVars, directVars) {
  const hits = [];
  const bodyJoined = fn.body.join('\n');
  const hasPrepare = /->prepare\s*\(/.test(bodyJoined);
  const bodyHasSuperglobal = SUPERGLOBAL.test(bodyJoined);
  for (let k = 0; k < fn.body.length; k++) {
    const orig = fn.body[k];
    const san = fn.san[k];
    if (/\bfunction\b/.test(san)) continue; // a definition line, not a call
    for (const def of SINK_DEFS) {
      const m = orig.match(def.re);
      if (!m) continue;
      let token = def.id === 'lfi' ? m[0].replace(/[($\s].*$/, '') : (m[1] || m[0]).replace(/[^\w>].*$/, '');
      if (def.id === 'token-compare') {
        // An equality/strcmp match is only a credential CHECK when the line carries
        // credential vocabulary or a request channel — otherwise `get_option('stylesheet')
        // === $x`-class config reads and `'1' === get_option(...)` probes false-fire.
        if (!/(?:key|token|secret|credential|bearer|auth)/i.test(orig) && !SUPERGLOBAL.test(orig) && !AUTH_HEADER.test(orig) && !REST_REQUEST.test(orig)) continue;
        if (!token) {
          // Equality-operator matches start with a non-word char ('===') — anchor the
          // commented-out check on the credential/compared token in the line instead.
          const tm = orig.match(/strcmp|strcasecmp|strncasecmp|get_option|[A-Za-z_]\w*(?:_key|_token|_secret|Key|Token|Secret)\w*/i);
          token = tm ? tm[0] : '';
          if (!token) continue;
        }
      }
      if (!san.includes(def.id === 'sqli' ? m[0].slice(0, 6) : token.replace(/^->/, '').slice(0, 6))) continue; // commented-out/string-only match
      if (def.sqli) {
        // Core query classes are core-parameterized: WP_Query / WP_Term_Query /
        // WP_User_Query ->query() is NOT a raw-query sink (the sydney
        // display_conditions false positive, 2026-08-26). Excluded when the line
        // names the class, the object is a core global, or the variable is
        // provably assigned `new WP_*Query` in this body — and (2026-09-17) for the
        // get_results/get_var/get_row/get_col variants too: ultimate-member's
        // `$users_query->get_results()` on a WP_User_Query matched the get_results
        // branch and was titled "SQL injection candidate" in a 200k-install plugin.
        if (/\bWP_(?:Query|Term_Query|User_Query)\b/.test(orig)) continue;
        const qv = orig.match(/\$([A-Za-z_]\w*)->(?:query|get_results|get_var|get_row|get_col)\s*\(/);
        if (qv && (/^(?:wp_query|wp_the_query)$/.test(qv[1]) ||
          // `new \WP_User_Query(...)` — the leading namespace backslash is REAL code
          // (ultimate-member includes/ajax/class-users.php:38) and an exclusion that
          // misses it is not an exclusion.
          new RegExp(`\\$${qv[1]}\\s*=\\s*new\\s+\\\\?WP_[A-Za-z_]*Query\\b`).test(bodyJoined))) continue;
        // A container/DAO ACCESSOR is not a query (defect M, 2026-09-17):
        // `$post_data = UM()->query()->post_data( $form_id );` — a singleton getter that
        // returns the query class — matched `->query(` and was titled "SQL injection
        // candidate (query without ->prepare)" in ultimate-member, a 200k-install plugin.
        // `post_data()` (class-query.php:428) contains no ->query/$wpdb call and no SQL.
        //
        // DISCRIMINATOR, structural (the first attempt at this used "db-handle receiver or
        // SQL keywords on the line" and the calibration soak caught it dropping the
        // hand-verified madara `chapter_navigate_page` sink, which executes through a
        // METHOD-CHAIN receiver: `$this->get_wpdb()->get_results( $query )` — the token
        // before `->get_results(` is `)`, so no name to match). A sink whose result is
        // IMMEDIATELY DEREFERENCED (`->query()->post_data(`) is an accessor chain, not an
        // execution — unless the receiver is a real db handle, which always wins.
        const recv = orig.match(/([A-Za-z_$][\w$]*)\s*->(?:query|get_results|get_var|get_row|get_col)\s*\(/);
        const recvName = recv ? recv[1].replace(/^\$/, '') : '';
        const dbHandle = /\b(?:wpdb|db|dbh|dbi|database|sql|mysqli|pdo|conn|connection|get_wpdb)\b/i.test(recvName);
        const accessorChain = /->(?:query|get_results|get_var|get_row|get_col)\s*\([^)]*\)\s*->/.test(orig);
        if (!dbHandle && accessorChain) continue;
      }
      if (def.sqli && hasPrepare) continue; // body prepares its statements (heuristic: whole-body)
      if (def.id === 'file-write') {
        // A PHP stream wrapper is not a filesystem path (defect N, 2026-09-17):
        // instagram-feed's settings EXPORT does
        //     $file = fopen( 'php://memory', 'w' ); fwrite( $file, $feed ); ... fpassthru( $file );
        // — a download built in memory — and was titled "arbitrary file write/upload" at the
        // crit-weight 85 sink class in a 100k+ install plugin (it also carries a nonce gate
        // and a capability gate on the same handler). No disk write exists to exploit.
        if (/php:\/\/|data:\/\//i.test(orig)) continue;
        const hm = orig.match(/(?<![\w$>:-])(?:file_put_contents|fwrite)\s*\(\s*\$([A-Za-z_]\w*)/);
        if (hm && new RegExp(`\\$${hm[1]}\\s*=\\s*fopen\\s*\\(\\s*['"]php://`, 'i').test(bodyJoined)) continue;
      }
      let taint = lineTaint(orig, taintVars, bodyHasSuperglobal, directVars);
      if (def.taintedOnly) {
        // lfi / object-injection / dynamic-call / file-read all share one rule: a fixed target
        // is not a primitive. `include 'fixed.php'`, `unserialize('a:1:{}')`,
        // `call_user_func('wp_function')` and `readfile(__DIR__.'/x')` are internal plumbing;
        // only a request-derived variable (direct superglobal or a var fed by one in this body)
        // is a candidate.
        //
        // UPLOAD TEMP PATHS are excluded (2026-09-17): `file_get_contents( $_FILES['f']['tmp_name'] )`
        // is how EVERY import handler reads its upload — PHP assigns that path, the attacker does
        // not choose it, so it is not an arbitrary read. Measured: 3 of the 4 first file-read hits
        // were exactly this (instagram-feed, simple-author-box, siteorigin-panels).
        if (def.id === 'file-read' && /\[['"]tmp_name['"]\]/.test(orig)) continue;
        const v = m[1];
        const lt = /^_(POST|GET|REQUEST|COOKIE|FILES)$/.test(v) ? 'direct' : (taintVars.has(v) ? 'tainted-var' : 'none');
        if (lt === 'none') continue;
        taint = lt;
      }
      const hit = { def, line: fn.line + k, text: orig.trim().slice(0, 160), taint };
      // Sink-value weighting, conservative: a write whose VALUE is provably fixed
      // from static evidence (literal/constant), or a user-meta write provably
      // self-only (the caller's own row), auto-degrades the candidate below — it
      // is ranked, never top. Only literal/certain shapes qualify; anything
      // dynamic is left alone.
      const callText = fn.body.slice(k, k + 3).join(' ');
      if (def.id === 'option-overwrite') {
        // The VALUE must be read as the SECOND argument, whatever follows it. A third
        // `$autoload` argument is normal WP usage and does NOT make a constant write
        // dynamic — the old last-argument regex read `MWAI_VERSION, true` as the value,
        // failed the literal test, and left a bounded primitive ranked as a top
        // unauth option overwrite (ai-engine check_db). The option NAME must still be
        // a literal: a variable name is the real arbitrary-option primitive.
        const om = callText.match(/(?<![\w$>:-])(?:update_option|add_option)\s*\(/);
        if (om) {
          const args = callArgs(callText, om.index + om[0].length - 1);
          const name = (args[0] || '').trim();
          const value = (args[1] || '').trim();
          if (/^(?:'[^']*'|"[^"]*")$/.test(name) && /^(?:'[^']*'|"[^"]*"|-?\d+(?:\.\d+)?|true|false|null|[A-Z_][A-Z0-9_]*)$/.test(value)) {
            hit.fixedValue = value.slice(0, 40);
          }
        }
      }
      if (def.id === 'meta-write') {
        const um = callText.match(/(?:update_user_meta|delete_user_meta)\s*\(\s*([^,]{0,60}),/);
        if (um) {
          const first = um[1].trim();
          if (/^get_current_user_id\s*\(\s*\)$/.test(first)) hit.selfOnly = true;
          else {
            const vm = first.match(/^\$([A-Za-z_]\w*)$/);
            if (vm && new RegExp(`\\$${vm[1]}\\s*=\\s*get_current_user_id\\s*\\(`).test(bodyJoined)) hit.selfOnly = true;
            // The OBJECT idiom: `$user = wp_get_current_user(); … update_user_meta( $user->ID, … )`.
            // The row is provably the caller's own account, so the primitive is bounded exactly
            // like the get_current_user_id() form. Measured: SureForms 2.x
            // inc/payments/front-end.php:1465 writes srfm_stripe_customer_id through
            // get_or_create_stripe_customer()'s $current_user->ID behind a wp_get_current_user()
            // id check, and was ranked "unauthenticated user meta write (privesc ladder rung)".
            const om = first.match(/^\$([A-Za-z_]\w*)\s*->\s*ID$/);
            if (om && requesterResolved(fn.body, om[1])) hit.selfOnly = true;
          }
        }
      }
      // any-user meta write: the FIRST argument (the user id) is superglobal/tainted —
      // the caller picks the victim account, not just their own.
      if (def.id === 'meta-write') {
        const am = orig.match(/(?:update_user_meta|delete_user_meta|wp_delete_user)\s*\(\s*\$([A-Za-z_]\w*)/);
        if (am && (/^_(POST|GET|REQUEST|COOKIE)$/.test(am[1]) || taintVars.has(am[1]))) hit.anyUser = true;
        // ROW provenance. Unless the row is the caller's own (selfOnly) or a traced
        // attacker-chosen id (anyUser), the first argument tells us nothing about WHOSE
        // account is written: it is routinely a parameter filled from the caller. The class
        // label alone ("user meta write (privesc ladder rung)") reads as a privesc, so the
        // unproven part is named instead of assumed — measured on SureForms 2.x, where the
        // row is `$user->ID`, a parameter of the writing method, fed by the caller's
        // wp_get_current_user(); the endpoint is nopriv but the write is login-gated and
        // self-directed.
        if (!hit.selfOnly && !hit.anyUser) hit.rowUnresolved = true;
      }
      // Credential-named option writes (API keys, tokens, secrets) are token-handling
      // impact, not generic config churn — annotate so triage sees them first.
      if (def.id === 'option-overwrite') {
        const on = orig.match(/(?:update_option|add_option)\s*\(\s*['"]([^'"]+)['"]/);
        if (on && CRED_OPTION.test(on[1])) hit.credOption = true;
      }
      hits.push(hit);
    }
  }

  // --- sensitive-read (disclosure): the accepted READ class (§3.9) ---------------------
  // Two sides required IN THE SAME FUNCTION, both by NAME (never by guess):
  //   source: get_option/get_site_option/get_user_meta/get_user_option on a name matching
  //           CRED_OPTION (key|token|secret|credential|passw)
  //   emit:   echo/print/printf/print_r/var_dump/wp_send_json*/wp_die/wp_json_encode carrying
  //           either the source inline or a variable assigned from it
  // A sensitive read that stays inside the function (comparison, arithmetic, logging) is not a
  // hit — only an EMISSION to the request is. The human step is the probe: confirm the response
  // BODY carries the value rather than a set/unset boolean, then redact it in the report.
  {
    const SOURCE = /(?:get_option|get_site_option|get_blog_option|get_user_meta|get_user_option)\s*\(\s*(?:\$[A-Za-z_]\w*\s*,\s*)?['"]([^'"]+)['"]/;
    const EMIT = /(?<![\w$>:-])(?:echo|print|printf|print_r|var_dump|wp_send_json(?:_success|_error)?|wp_die|wp_json_encode|return)\s*[\(\s]/;
    const sensitive = new Map(); // $var -> the credential-ish name it was read from
    // SECOND SOURCE KIND (2026-09-17): a SELECT over a SENSITIVE TABLE/COLUMN SET, emitted
    // in the response. This is the shape the plugin REST surfaces actually use —
    // persian-woocommerce's `customer/users` / `revenue/orders` return query results — and
    // the option-read source above cannot see it. Doctrine §3.9 accepts broken access control
    // that reaches significant/sensitive objects; a user/order/token row returned to an
    // unauth or subscriber caller is exactly that, and it is Wordfence-payable
    // (CVE-2024-0761 "Sensitive Information Exposure" is this class).
    const QSENS = /\b(?:user_pass|user_activation_key|session_tokens|user_email|meta_value)\b|from\s+[^\s;]*\b(?:users|usermeta)\b/i;
    const qVars = new Map(); // $var -> the sensitive marker that made it sensitive
    // AGGREGATES ARE NOT DISCLOSURES (2026-09-17): the first run of this source flagged
    // ultimate-member's `wp_send_json_success( array( 'count' => $count ) )` where $count came
    // from `SELECT COUNT(*) FROM wp_users` — a user COUNT is not a sensitive object. Any query
    // whose only projection is an aggregate returns no row/field an attacker can read.
    const AGG_ONLY = /select\s+count\s*\([^)]*\)\s*(?:as\s+\w+\s*)?from/i;
    for (let k = 0; k < fn.body.length; k++) {
      const line = fn.body[k];
      const stmt = fn.body.slice(k, k + 3).join(' ');
      const qm = line.match(/(\$[A-Za-z_]\w*)\s*=[^;]*->(?:get_results|get_row|get_var|get_col)\s*\(/);
      if (qm && QSENS.test(stmt) && !AGG_ONLY.test(stmt)) qVars.set(qm[1], (stmt.match(QSENS) || ['sensitive table/column'])[0].slice(0, 30));
      const sm = line.match(SOURCE);
      if (sm && CRED_OPTION.test(sm[1])) {
        const av = line.match(/(\$[A-Za-z_]\w*)\s*=/);
        if (av) sensitive.set(av[1], sm[1]);
      }
      if (!EMIT.test(line)) continue;
      const def = SINK_BY_ID['sensitive-read'];
      // A HELPER `return` IS NOT A DISCLOSURE: when the sensitive value is returned from a
      // function the handler CALLED (hop > 0), the caller decides what to do with it — the
      // first run of this source flagged wp-file-manager's `fm_download_backup -> fm_get_key`
      // (`return get_option('fm_key')`), where the caller only *compares* the key. Tag the
      // emit kind and drop return-emits below hop 0 in the scoring loop.
      const isReturnEmit = /(?<![\w$>:-])return\s+/.test(line);
      if (sm && CRED_OPTION.test(sm[1])) {
        hits.push({ def, line: fn.line + k, text: line.trim().slice(0, 160), taint: 'ambient', sensitiveName: sm[1], ...(isReturnEmit ? { emitReturn: true } : {}) });
        continue;
      }
      // inline sensitive query emitted directly
      if (/->(?:get_results|get_row|get_var|get_col)\s*\(/.test(line) && QSENS.test(stmt) && !AGG_ONLY.test(stmt)) {
        hits.push({ def, line: fn.line + k, text: line.trim().slice(0, 160), taint: 'ambient', sensitiveName: (stmt.match(QSENS) || ['sensitive query'])[0].slice(0, 30), ...(isReturnEmit ? { emitReturn: true } : {}) });
        continue;
      }
      let pushed = false;
      for (const [v, name] of sensitive) {
        if (new RegExp(`\\${v}\\b`).test(line)) {
          hits.push({ def, line: fn.line + k, text: line.trim().slice(0, 160), taint: 'ambient', sensitiveName: name, ...(isReturnEmit ? { emitReturn: true } : {}) });
          pushed = true;
          break;
        }
      }
      if (pushed) continue;
      for (const [v, name] of qVars) {
        if (new RegExp(`\\${v}\\b`).test(line)) {
          hits.push({ def, line: fn.line + k, text: line.trim().slice(0, 160), taint: 'ambient', sensitiveName: `query result (${name})`, ...(isReturnEmit ? { emitReturn: true } : {}) });
          break;
        }
      }
    }
  }
  return hits;
}

// Callees worth descending into (same-plugin model methods): $this->…, $obj->… property
// calls (the real sink routinely lives in a model class the handler delegates to — e.g.
// chapter_navigate_page → $wp_manga_chapter->get_chapter_by_slug → get_chapters → get),
// static::…, and bare names. Resolution stays name-based against the scanned index — no
// stdlib/WP-core descent (NO_DESCEND + same-root rule).
function calleesOf(fn) {
  const names = new Set();
  for (const line of fn.san) {
    for (const m of line.matchAll(/\$[A-Za-z_]\w*->([A-Za-z_]\w*)\s*\(/g)) names.add(m[1]);
    for (const m of line.matchAll(/\b(?:self|static)::([A-Za-z_]\w*)\s*\(/g)) names.add(m[1]);
    for (const m of line.matchAll(/(?<![\w$>:-])([a-z_]\w*)\s*\(/g)) {
      if (!NO_DESCEND.has(m[1])) names.add(m[1]);
    }
  }
  return names;
}

// The vendor boundary for transitive resolution: a handler in wp-content/plugins/X only
// descends into X (never into wp-includes/wp-admin or a sibling plugin). Trees without
// the wp-content shape fall back to the handler's own directory.
function pluginRoot(p) {
  const m = String(p).replace(/\\/g, '/').match(/^(.*wp-content\/(?:plugins|themes)\/[^/]+\/)/);
  if (m) return m[1];
  const i = String(p).replace(/\\/g, '/').lastIndexOf('/');
  return i === -1 ? '' : String(p).replace(/\\/g, '/').slice(0, i + 1);
}

// --- the miner ----------------------------------------------------------------

// records: [{ path, content }]. Pure: no fs, no network, no import-time side effects.
export function minePrivesc(records, { maxDepth = 3, maxCallees = 30 } = {}) {
  const gaps = [];
  const fns = [];
  const regs = [];
  for (const rec of Array.isArray(records) ? records : []) {
    try {
      const content = String(rec && rec.content != null ? rec.content : '').replace(/\r\n?/g, '\n');
      // Normalize path separators too: same-plugin callee resolution compares prefixes —
      // a Windows backslash path never startsWith the forward-slash plugin root, silently
      // confining descent to same-file callees. Refs print normalized (file:line).
      const path = String(rec && rec.path != null ? rec.path : '?').replace(/\\/g, '/');
      if (!content.trim()) continue;
      // Normalize CRLF/CR to LF once (above): line-anchored regexes ((.*)$ registrations)
      // silently never match on CRLF sources — a Windows-mirrored tree read as empty.
      const orig = content.split('\n');
      const san = structureLines(content);
      fns.push(...extractFunctions(path, orig, san, gaps));
      regs.push(...extractRegistrations(path, orig, san));
    } catch (e) {
      gaps.push({ ref: String(rec && rec.path), reason: 'parse failed: ' + ((e && e.message) || e) });
    }
  }

  const byName = new Map();
  for (const f of fns) {
    if (!byName.has(f.name)) byName.set(f.name, []);
    byName.get(f.name).push(f);
  }
  const resolve = (name, fromPath, fromRoot) => {
    const cands = byName.get(name) || [];
    return cands.find((f) => f.path === fromPath) || cands.find((f) => f.path.startsWith(fromRoot)) || null;
  };
  // Gate-credit-only resolver: a permission_callback's delegate chain legitimately crosses
  // directories within one plugin (modules/… → helpers/…), and loose scan roots (a bare
  // plugin dir, no wp-content shape) shrink pluginRoot() to the handler's own directory.
  // Handler sink descent keeps the strict vendor boundary; crediting a GATE one level
  // wider only ever downgrades a candidate, and the chain is printed in the mitigation
  // note for audit. Over-credit risk is name-collision — same caveat as resolve() itself.
  const resolveGate = (name, fromPath, fromRoot) =>
    resolve(name, fromPath, fromRoot) || (byName.get(name) || [])[0] || null;

  const candidates = [];
  let initBootstrapSkipped = 0;

  // Abilities-API exposure evidence: name the gate state and every exposure flag — the
  // report text must keep the reasoning straight that the MCP adapter / wp-abilities REST
  // endpoint is only the TRANSPORT; the ability's own permission_callback is the gate.
  const abilityEvidence = (reg, gateDesc) =>
    `${reg.ability ? `ability ${reg.ability} — ` : ''}${gateDesc} permission_callback${reg.mcpPublic ? ' + meta.mcp.public=true (exposed as an MCP tool on the MCP-adapter default server — the adapter gates ONLY on this callback)' : ''}${reg.showInRest ? ' + meta.show_in_rest=true (executable via the authenticated wp-abilities REST run endpoint)' : ''}`;

  // The exposure finding attaches to the REGISTRATION args (gate + meta flags), so it is
  // emitted even when the execute_callback won't resolve — unlike sink findings, it does
  // not need the executor body. ref = the registration line, where the weak gate lives.
  const abilityGateCandidate = (reg, def, gateDesc, reach, confidence, mitigations) => {
    const score = Math.round(def.weight * (REACH_W[reach] ?? REACH_W.unknown) * 100) / 100;
    return {
      sev: score >= 80 ? 'crit' : score >= 50 ? 'high' : score >= 25 ? 'med' : score >= 10 ? 'low' : 'info',
      // riskLevel band mapping (score bands, stepped down for contributor+ reach):
      // documented at engine/severity.mjs riskLevelForScore. Lane rules: engine/lanes.mjs.
      riskLevel: riskLevelForScore(score, reach),
      lane: classifyLane({ reach, impactClass: def.id }),
      title: `${REACH_TITLE[reach]} ${def.label} — ${reg.name || reg.ability || '(unresolved executor)'} (${reg.hook})`,
      ref: `${reg.path}:${reg.line}`,
      reachability: reach,
      mitigations,
      impactClass: def.id,
      evidence: abilityEvidence(reg, gateDesc),
      confidence,
      taint: 'direct',
      probe: def.probe,
      surface: 'ai',
      ...(reg.ability ? { ability: reg.ability } : {}),
      hook: reg.hook,
      // ability names are unique per site — keeps the handler+class dedupe from merging
      // distinct closure-executor abilities into one finding.
      handler: reg.name || reg.ability || '(unresolved executor)',
      score,
    };
  };

  for (const reg of regs) {
    const regRef = `${reg.path}:${reg.line}`;
    if (reg.closure || !reg.name) {
      // An ability whose execute_callback is a closure/unresolvable still yields the gate
      // finding from its registration args (gate + meta flags are parse-level); only the
      // executor sink scan needs the body. Core's own abilities use closure executors.
      if (reg.kind === 'ability' && (reg.abilityGate === 'open' || reg.abilityGate === 'absent')) {
        const def = reg.mcpPublic ? MCP_PUBLIC_ABILITY : ABILITY_WEAK_GATE;
        candidates.push(abilityGateCandidate(reg, def, reg.abilityGate,
          reg.mcpPublic ? 'unauth' : 'subscriber', reg.abilityGate === 'absent' ? 'medium' : 'high',
          reg.preMitigation ? [reg.preMitigation] : []));
        gaps.push({ ref: regRef, reason: `${reg.hook} execute_callback is a closure/unresolvable — ${def.id} flagged from registration args; executor body not scanned for sinks` });
      } else {
        gaps.push({ ref: regRef, reason: `${reg.hook} registered with a closure/unresolvable callback — not analyzed` });
      }
      continue;
    }
    const root = pluginRoot(reg.path);
    const handler = resolve(reg.name, reg.path, root);
    if (!handler) {
      gaps.push({ ref: regRef, reason: `callback '${reg.name}' not found in scanned sources (dynamic name or file outside the tree)` });
      continue;
    }

    // init is a BOOTSTRAP hook: it fires for every request, but a handler that never
    // touches a request channel is plugin/core initialization, not attack surface — and
    // name-based descent from bootstrap fans out across the whole codebase (pure noise).
    // Model only REQUEST-DRIVEN init handlers, hop-0 only (the imgur _get_token shape:
    // an unauth $_GET-driven option write directly in the init handler body).
    if (reg.kind === 'init') {
      const joined = handler.body.join('\n');
      if (!SUPERGLOBAL.test(joined) && !AUTH_HEADER.test(joined) && !REST_REQUEST.test(joined)) {
        initBootstrapSkipped++;
        continue;
      }
    }
    const regMaxDepth = reg.kind === 'init' ? 0 : maxDepth;

    const mitigations = findMitigations(handler);
    let realMitCount = mitigations.length; // actual checks, not preMitigation notes
    if (reg.preMitigation) mitigations.push(reg.preMitigation);

    // Evaluate a NAMED permission_callback (same-plugin resolution) instead of
    // shrugging at it: its own checks credit the route/ability, and its body is where
    // bearer / API-key gates live (the AI Engine MCP shape). A permission callback whose
    // ONLY check is a stored-token comparison is token-only authz — no WP session behind
    // it. Identical semantics for REST routes and WP 6.9 ability registrations — the
    // MCP adapter and the wp-abilities REST endpoint both defer to this one callback.
    let pcFn = null;
    let pcHits = [];
    let pcHasCap = false;
    let pcTokenOnly = false;
    if ((reg.kind === 'rest' || reg.kind === 'ability') && reg.permissionCallback) {
      pcFn = resolveGate(reg.permissionCallback, reg.path, root);
      if (pcFn) {
        const pcMits = findMitigationsDeep(pcFn, resolveGate, root);
        pcHasCap = pcMits.some((x) => x.startsWith('current_user_can') || x.startsWith('user_can'));
        realMitCount += pcMits.length;
        for (const pm of pcMits) mitigations.push(`permission_callback ${pm}`);
        pcHits = scanSinks(pcFn, bodyTaint(pcFn.body));
        pcTokenOnly = pcMits.length === 0 && pcHits.some((h) => h.def.id === 'token-compare' || h.def.id === 'bearer-intake');
      }
    }

    // Inline closure permission gate (never a return-true one — those never get here):
    // credit the checks its body actually makes, exactly as a resolved named callback's.
    if ((reg.kind === 'rest' || reg.kind === 'ability') && reg.pcClosureMits) {
      for (const pm of reg.pcClosureMits) mitigations.push(`permission_callback ${pm}`);
      realMitCount += reg.pcClosureMits.length;
      if (reg.pcClosureMits.some((x) => x.startsWith('current_user_can') || x.startsWith('user_can'))) pcHasCap = true;
    }

    const strong = mitigations.some((x) => x.startsWith('current_user_can') || x.startsWith('user_can')) || pcHasCap;
    let reach = reg.base;
    if (strong && reach !== 'shortcode') reach = 'admin-gated';
    else if (realMitCount > 0 && reach === 'unauth') reach = 'subscriber';
    // Token-only permission gate: any visitor presenting the string passes — more
    // reachable than 'unknown' implies, but NOT proven-unauth (the token's provenance is
    // beyond line heuristics). Ranked at subscriber with the caveat attached.
    if (pcTokenOnly && reach === 'unknown') {
      reach = 'subscriber';
      mitigations.push('token-only permission gate — no WP session/capability check; verify token provenance/storage');
    }

    // BFS descent: handler body (hop 0) → same-plugin callees (≤ maxDepth).
    const seen = new Map(); // fn -> hops
    const queue = [{ fn: handler, hops: 0, chain: [reg.name] }];
    const chainOf = new Map([[handler, [reg.name]]]);
    let addslashesInChain = false;
    const hits = [];
    while (queue.length) {
      const { fn, hops } = queue.shift();
      if (seen.has(fn)) continue;
      seen.set(fn, hops);
      const chain = chainOf.get(fn);
      if (fn.body.some((l) => /(?<![\w$>:-])addslashes\s*\(/.test(l))) addslashesInChain = true;
      // Ability execute_callback($input): the MCP/REST/PHP caller controls $input, and
      // input_schema validates TYPES, not intent — seed the first param as tainted at
      // hop 0 so `$path = $input['path']; unlink($path)` propagates.
      let abilitySeed;
      if (reg.kind === 'ability' && hops === 0) {
        const pm = fn.body.slice(0, 4).join(' ').match(/function\s+&?\s*[A-Za-z_]\w*\s*\(\s*\$([A-Za-z_]\w*)/);
        if (pm) abilitySeed = [pm[1]];
      }
      const taintVars = bodyTaint(fn.body, abilitySeed);
      for (const h of scanSinks(fn, taintVars, abilitySeed)) hits.push({ ...h, hops, chain, fnPath: fn.path });
      if (hops < regMaxDepth && seen.size < maxCallees) {
        for (const calleeName of calleesOf(fn)) {
          const callee = resolve(calleeName, fn.path, root);
          if (callee && !seen.has(callee) && !chainOf.has(callee)) {
            chainOf.set(callee, [...chain, calleeName]);
            queue.push({ fn: callee, hops: hops + 1 });
          }
        }
      }
    }

    // Shortcode second-order injection: attribute-derived markup without escaping.
    if (reg.base === 'shortcode') {
      const joined = handler.body.join('\n');
      if ((/\$atts\s*\[/.test(joined) || /shortcode_atts\s*\(/.test(joined)) &&
          /\b(?:echo|return)\b[^;]*\.\s*\$/.test(joined) &&
          !/esc_(?:attr|html|url|textarea|js)\s*\(|wp_kses/.test(joined)) {
        hits.push({ def: SECOND_ORDER, line: handler.line, text: handler.body[0].trim().slice(0, 160), taint: 'direct', hops: 0, chain: [reg.name] });
      }
    }

    // Permission-callback sinks (bearer intake / token comparison) attach at hop 0 with
    // the authz chain named — the gate's weakness belongs to the route it protects.
    for (const h of pcHits) hits.push({ ...h, hops: 0, chain: [reg.permissionCallback], fnPath: pcFn.path, fromPc: true });

    // AI/MCP endpoint exposure: an AI-named route/hook or an MCP-protocol-speaking
    // handler with no capability gate behind it. The endpoint itself is the finding.
    // Ability registrations are EXCLUDED here — they carry dedicated gate/exposure
    // classes below (an ability would otherwise double-collect the generic exposure hit).
    if (!strong && reg.kind !== 'ability' && (reg.surface === 'ai' || MCP_PROTOCOL.test(handler.body.join('\n')))) {
      hits.push({ def: AI_ENDPOINT, line: handler.line, taint: 'direct', hops: 0, chain: [reg.name],
        text: `${reg.route ? `route ${reg.route} — ` : ''}${handler.body[0].trim().slice(0, 140)}` });
    }

    // Abilities-API exposure (WP 6.9 + MCP Adapter, Feb 2026): meta.mcp.public turns the
    // ability into an MCP tool on the adapter's default server; meta.show_in_rest exposes
    // it on the authenticated wp-abilities REST namespace. BOTH transports defer to the
    // ability's own permission_callback — the finding is always the ability's gate, never
    // the transport. Only PROVEN-weak gates fire (open / absent / token-only); a named
    // gate that doesn't resolve in-tree can't be graded and collects no exposure hit.
    if (reg.kind === 'ability' && !strong) {
      const gateDesc = pcTokenOnly ? 'token-only' : reg.abilityGate;
      if (pcTokenOnly || reg.abilityGate === 'open' || reg.abilityGate === 'absent') {
        const def = reg.mcpPublic ? MCP_PUBLIC_ABILITY : ABILITY_WEAK_GATE;
        candidates.push(abilityGateCandidate(reg, def, gateDesc, reach,
          gateDesc === 'open' ? 'high' : 'medium', mitigations));
      }
    }

    // Chain-gate lookups are cached per (chain|path): one registration usually yields
    // several sinks and they share chains. Scoped here so the map never outlives the mine.
    const chainMitCache = new Map();

    for (const h of hits) {
      // A helper's `return` hands the value to CALLER code, not to the request: only a
      // hop-0 return (the registered handler itself) is an emission. (defect P, 2026-09-17)
      if (h.emitReturn && h.hops > 0) continue;
      // GATE ON THE SINK'S OWN PATH (defect L). The registered handler is not always where
      // the check lives: the dispatcher idiom — handler -> $this->dispatch() ->
      // _dispatch() -> sink — performs the capability check in the MIDDLE of the chain.
      // Reading mitigations only from the handler body credited nothing and produced a
      // filing-shaped over-claim (user-role-editor, 1M+ installs: `dispatch()` gates every
      // action with `!$this->valid_nonce() || !$this->user_can()` before routing, yet the
      // miner titled an add_role sink "any-authenticated-user account control"). The chain
      // to THIS sink is descent evidence, so a check found on it is a gate on the path.
      // Cash per (name|path) because one registration usually yields several sinks.
      const chainMit = (() => {
        const cacheKey = `${h.chain.join('>')}|${h.fnPath || handler.path}`;
        const cached = chainMitCache.get(cacheKey);
        if (cached) return cached;
        const out = [];
        for (const name of h.chain) {
          if (!name || name === reg.permissionCallback) continue;
          const f = resolve(name, h.fnPath || handler.path, root);
          if (!f) continue;
          for (const m of findMitigationsDeep(f, resolve, root, 1, 5)) {
            if (!out.includes(m)) out.push(m);
          }
        }
        chainMitCache.set(cacheKey, out);
        return out;
      })();
      const chainCap = chainMit.some((x) => x.startsWith('current_user_can') || x.startsWith('user_can'));
      const chainNonce = chainMit.some((x) => x.startsWith('check_') || x.startsWith('wp_verify_nonce'));
      const capGated = (strong || pcHasCap || chainCap);
      // The reach THIS sink is entitled to: a capability check on the path outranks the
      // registration's base reach; a nonce-only check downgrades unauth to subscriber
      // (session evidence, never proof of protection).
      let hitReach = reach;
      if (capGated && hitReach !== 'shortcode') hitReach = 'admin-gated';
      else if (chainNonce && hitReach === 'unauth') hitReach = 'subscriber';
      const hitMitigations = chainMit.length ? [...mitigations, ...chainMit.map((m) => `${m} (on the sink's chain ${h.chain.join(' -> ')})`)] : mitigations;
      // Gate UNPROVEN is its own honesty marker, exactly like dataflowUnproven below: a
      // hop>0 sink with no capability check located anywhere on its chain, and no other
      // gate on the registration, must not be TITLED as the class it has not shown. It
      // still ranks (classified, never filtered) — it just stops reading as a finding.
      const gateUnproven = h.hops > 0 && !capGated;

      // Bearer/token evidence with NO capability check behind it (in the handler, or in
      // the permission callback it came from) ranks as token-only authz, not bare weight.
      const weakToken = (h.def.id === 'token-compare' || h.def.id === 'bearer-intake') && !capGated;
      const w = h.anyUser ? ANY_USER_META_WEIGHT : weakToken ? WEAK_TOKEN_WEIGHT : h.def.weight;
      // Cross-function dataflow is unproven past hop 0 — the superglobal lives in the
      // CALLER. Don't double-penalize depth: treat hop>0 untainted as ambient.
      const effTaint = h.hops > 0 && h.taint === 'none' ? 'ambient' : h.taint;
      let score = w * (REACH_W[hitReach] ?? REACH_W.unknown) * Math.pow(0.75, h.hops) * (TAINT_FACTOR[effTaint] ?? TAINT_FACTOR.none);
      let confidence;
      if (h.hops > 0) confidence = 'low';
      else if (h.def.sqli) confidence = h.taint === 'direct' || h.taint === 'tainted-var' ? 'medium' : 'low';
      else confidence = h.taint === 'direct' || h.taint === 'tainted-var' ? 'high' : (h.taint === 'ambient' ? 'medium' : 'low');
      if (h.def.sqli && addslashesInChain) {
        score *= 0.8; // escaped with addslashes, not ->prepare: charset/GBK-class caveats
        confidence = 'low';
      }
      // Fixed-value / self-only writes auto-degrade (the primitive is provably
      // bounded from static evidence — ranked, never top; see FIXED_WRITE_FACTOR).
      const degraded = h.fixedValue
        ? `fixed-value write (value is a literal/constant '${h.fixedValue}' — the primitive is bounded to a constant)`
        : h.selfOnly
          ? `self-only user meta write (the user id is provably the caller's own account)`
          : null;
      if (degraded) score *= FIXED_WRITE_FACTOR;
      // Cross-function dataflow is UNPROVEN, by construction: bodyTaint is single-function
      // (documented blind spot), so a hop>0 hit whose sink line carries no request-derived
      // value has no traced input path — the superglobal, if any, would live in the CALLER.
      // The candidate stays ranked (classified, never filtered), but it must not be TITLED
      // as the vulnerability class it has not begun to show: an unqualified
      // "SQL injection candidate" over `SHOW TABLES LIKE '$this->table_chats'`-class
      // internal queries is the kind of claim that gets a filing rejected as hallucinated.
      const dataflowUnproven = h.hops > 0 && h.taint === 'none';
      score = Math.round(score * 100) / 100;
      candidates.push({
        sev: score >= 80 ? 'crit' : score >= 50 ? 'high' : score >= 25 ? 'med' : score >= 10 ? 'low' : 'info',
        // riskLevel band mapping (score bands, stepped down for contributor+ reach):
        // documented at engine/severity.mjs riskLevelForScore. Lane rules: engine/lanes.mjs
        // — classified, never filtered; installs/CVSS are unknown at mine time and the
        // lane reasons say so (supply them downstream to re-grade wordfenceEligible).
        riskLevel: riskLevelForScore(score, hitReach),
        lane: classifyLane({ reach: hitReach, impactClass: h.def.id, degraded }),
        title: `${REACH_TITLE[hitReach]} ${h.anyUser ? ANY_USER_META_LABEL : weakToken ? WEAK_TOKEN_LABEL : h.def.label}${h.credOption ? ' [credential-named option]' : ''}${h.rowUnresolved ? " [row provenance unresolved: the written row is neither the caller's own account nor a traced attacker-chosen id]" : ''}${dataflowUnproven ? ` [dataflow unproven: sink reached via ${h.chain.join(' -> ')} with no request-derived value traced into the call]` : ''}${gateUnproven ? ` [gate unproven: sink reached via ${h.chain.join(' -> ')} with no capability check located anywhere on that path — not a finding until one is read or ruled out]` : ''} — ${reg.name} (${reg.hook})`,
        ref: `${h.fnPath || handler.path}:${h.line}`,
        reachability: hitReach,
        mitigations: hitMitigations,
        impactClass: h.def.id,
        evidence: h.hops > 0 ? `${h.text}  [via ${h.chain.join(' -> ')}]` : (h.fromPc ? `${h.text}  [in permission_callback ${h.chain[0]}]` : h.text),
        ...(degraded ? { degraded } : {}),
        ...(dataflowUnproven ? { dataflowUnproven: true } : {}),
        ...(gateUnproven ? { gateUnproven: true } : {}),
        ...(h.rowUnresolved ? { rowUnresolved: true } : {}),
        confidence,
        taint: h.taint,
        probe: h.def.probe,
        ...(h.def.gated ? { doctrineGated: true } : {}),
        ...(reg.surface ? { surface: reg.surface } : {}),
        ...(reg.route ? { route: reg.route } : {}),
        ...(reg.ability ? { ability: reg.ability } : {}),
        hook: reg.hook,
        handler: reg.name,
        score,
      });
    }
  }

  // Dedupe: one candidate per handler+class, then one per sink ref+class (the same model
  // method reached from two handlers is ONE finding, kept at its best score).
  const dedupe = (keyFn) => {
    const best = new Map();
    for (const c of candidates) {
      const k = keyFn(c);
      const cur = best.get(k);
      if (!cur || c.score > cur.score) best.set(k, c);
    }
    return [...best.values()];
  };
  let out = dedupe((c) => `${c.handler}::${c.impactClass}`);
  out = dedupe2(out);

  function dedupe2(list) {
    const best = new Map();
    for (const c of list) {
      const k = `${c.ref}::${c.impactClass}`;
      const cur = best.get(k);
      if (!cur || c.score > cur.score) best.set(k, c);
    }
    return [...best.values()];
  }

  const reachOrder = Object.keys(REACH_W);
  out.sort((a, b) => b.score - a.score || (SINK_BY_ID[b.impactClass]?.weight || 0) - (SINK_BY_ID[a.impactClass]?.weight || 0) ||
    reachOrder.indexOf(a.reachability) - reachOrder.indexOf(b.reachability) || (a.ref < b.ref ? -1 : a.ref > b.ref ? 1 : 0));
  out.forEach((c, i) => { c.rank = i + 1; });

  return {
    candidates: out,
    gaps: gaps.slice(0, 60),
    stats: { functions: fns.length, registrations: regs.length, unresolvedCallbacks: gaps.length, initBootstrapSkipped },
  };
}

// DOCUMENTED BLIND SPOTS (precision honesty — this miner ranks, it does not convict):
//  - Dynamic hook names (`add_action('wp_ajax_nopriv_' . $var, …)`): the registration is
//    seen but the action name is a prefix; callbacks still resolve and rank.
//  - Handlers registered through wrappers (e.g. a plugin's own add_ajax_action helper) or
//    reached only via direct-URL PHP files with no ABSPATH guard: not modeled.
//  - Mitigations are read from the HANDLER body, PLUS the sink's own descent chain
//    (defect L, 2026-09-17): the dispatcher idiom — handler -> $this->dispatch() ->
//    _dispatch() -> sink — puts current_user_can() in the middle of the chain, and a
//    hop>0 sink with no gate found anywhere on its path is titled with an explicit
//    `[gate unproven: …]` qualifier (the reach claim is not made). Still NOT credited:
//    a gate in a callee that is *not* on the sink's chain, and early-exit guards that
//    live in a sibling branch. is_admin() is near-meaningless on ajax.
//  - ->prepare() anywhere in a body suppresses that body's SQLi candidates even if only
//    some statements are prepared; heredoc/nowdoc string bodies defeat the sanitizer.
//  - Sink lines inside a COLLAPSED one-line function body (`function f() { update_option(…); }`)
//    are not matched by the line-anchored sink scan (found 2026-09-17 while writing the
//    defect-L control fixture, which silently produced zero candidates for that reason).
//    Real plugin code is overwhelmingly multi-line, so the practical recall cost is small —
//    but a fixture written in collapsed style proves nothing, and neither does a control.
//  - AI surface is classified by hook/route NAME (mcp|agent|chat|completion|openai|…):
//    an MCP endpoint under an unremarkable route name is missed unless its handler
//    speaks the protocol literally (tools/call, text/event-stream); conversely a
//    well-gated AI route can still collect the exposure candidate if its gate uses an
//    unresolvable permission_callback. Token-only reachability is modeled as
//    'subscriber' — whether the credential is default/empty/leaked is a dynamic question.
//    hash_equals() comparisons are deliberately NOT flagged (timing-safe done right).
//  - Ability registrations (WP 6.9): multi-line wp_register_ability() args are
//    window-parsed (≤60 lines, cut at the next registration) — a permission_callback or
//    meta flag built from variables/constants is missed, and args beyond the window are
//    unseen. A NAMED permission_callback that doesn't resolve in-tree collects no exposure
//    finding (the gate can't be graded — precision over recall); a closure execute_callback
//    still yields the gate finding from the registration args but no executor sink scan.
//    An ABSENT permission_callback is ranked as if the registration succeeds (core lists
//    it as a required arg — whether the ability then registers gate-less is a runtime
//    question, hence medium confidence). The wp_register_ability_args FILTER shape (a
//    plugin flipping meta.mcp.public on core/another plugin's abilities) is not modeled.
//    Token-only ability gates follow the REST doctrine: 'subscriber', never proven-unauth.
//  - REST/ability callback values understand string, array(...) and short-array
//    ([ $this, 'm' ] / [ C::class, 'm' ]) forms — all resolved NAME-based, so two
//    same-named methods in one plugin can mis-credit either way. A permission_callback
//    that is a CALL expression (e.g. Permissions::gate( fn() => … )) is not a literal
//    closure and is not extracted — it reports as absent/unresolvable. Inline closure
//    gates are brace/paren-matched on RAW text within the registration window: a string
//    literal containing '{'/')' inside the closure can truncate or overrun the scan, and
//    an arrow-fn gate is assumed single-expression. Closure bodies are mitigation-scanned
//    flat (no callee descent); named callbacks get the ≤2-hop findMitigationsDeep credit.
//  - Taint is single-function, one propagation pass: cross-object dataflow (option read
//    back out later, global $wpdb churn) is beyond line heuristics. Callee descent is
//    NAME-based — two same-named methods in one plugin resolve to the first scanned, and
//    $obj->method() calls are followed without knowing the object's class (over- AND
//    under-reach both possible; confidence stays 'low' past hop 0 for that reason).
//  - CRLF/CR sources are normalized to LF at ingestion; line numbers refer to the
//    normalized text (same numbering for well-formed files).
