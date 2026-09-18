// VARVEL — reachprove engine: MECHANICAL reachability adjudication for WordPress
// entry points, with file:line evidence, BEFORE any AI adjudication burns a token.
//
// PROVENANCE: privemap's `reachability` field is a heuristic. A hand adjudication of
// ~30 ranked candidates found most were DEAD — an "unauth option overwrite" on
// admin_init that in fact requires manage_options, a REST route whose
// permission_callback requires edit_posts, an ability whose gate is an inline closure
// the miner cannot evaluate. This module decides reachability in CODE: it parses the
// same registrations privemap sees (add_action/add_filter, add_shortcode,
// register_rest_route, wp_register_ability), resolves the callback to its definition,
// reads the in-handler / permission-callback gates, and emits ONE verdict per entry
// point with the evidence chain that decided it.
//
// LINE-BASED HEURISTICS, NOT AN AST (zero-dep rule) — same parsing style as
// engine/privemap.mjs (comments/string contents blanked for brace math, name-based
// callback resolution). UNKNOWN is a first-class verdict: when a callback, gate or
// hook cannot be graded mechanically the entry reports UNKNOWN with the named reason,
// never a fabricated floor. KILLED (rescore) is reserved for never-remote surface
// proven with HIGH confidence (cron-scheduled hooks, admin-render hooks).
//
// VERDICT VOCABULARY: UNAUTH | SUBSCRIBER | CONTRIBUTOR | AUTHOR | EDITOR | ADMIN |
// SERVER (cron/never-remote) | UNKNOWN (reason named). Verdicts state who can cause
// the handler to EXECUTE; whether its inputs are attacker-steerable is privemap's
// taint question, out of scope here.

import { riskLevelForScore } from './severity.mjs';
import { classifyLane } from './lanes.mjs';

// --- the role ladder + capability map -----------------------------------------

export const ROLE_RANK = { UNAUTH: 0, SUBSCRIBER: 1, CONTRIBUTOR: 2, AUTHOR: 3, EDITOR: 4, ADMIN: 5 };

// WordPress capability → minimum role, conservative stock-WP map. Anything not
// listed (custom caps, variable cap names) maps to ADMIN with `uncertain: true` —
// the flag is surfaced, the floor is the safe direction for a kill-decision.
const CAP_ROLE = {
  read: 'SUBSCRIBER',
  edit_posts: 'CONTRIBUTOR',
  delete_posts: 'CONTRIBUTOR',
  list_users: 'CONTRIBUTOR', // engagement-spec default (stock WP grants editors; lower is the non-killing direction)
  upload_files: 'AUTHOR',
  publish_posts: 'AUTHOR',
  edit_published_posts: 'AUTHOR',
  delete_published_posts: 'AUTHOR',
  edit_pages: 'EDITOR',
  edit_others_posts: 'EDITOR',
  edit_others_pages: 'EDITOR',
  publish_pages: 'EDITOR',
  delete_pages: 'EDITOR',
  delete_others_posts: 'EDITOR',
  delete_published_pages: 'EDITOR',
  moderate_comments: 'EDITOR',
  unfiltered_html: 'EDITOR', // admin/super-admin only on multisite — note attached
  manage_options: 'ADMIN',
  activate_plugins: 'ADMIN',
  install_plugins: 'ADMIN', // super-admin on multisite
  update_plugins: 'ADMIN',
  delete_plugins: 'ADMIN',
  edit_plugins: 'ADMIN',
  edit_themes: 'ADMIN',
  edit_files: 'ADMIN',
  switch_themes: 'ADMIN',
  edit_theme_options: 'ADMIN',
  update_core: 'ADMIN',
  update_themes: 'ADMIN',
  edit_users: 'ADMIN',
  create_users: 'ADMIN',
  delete_users: 'ADMIN',
  promote_users: 'ADMIN',
  remove_users: 'ADMIN',
  manage_network: 'ADMIN',
  manage_network_options: 'ADMIN',
  customize: 'ADMIN',
  // ROLE NAMES double as capabilities in WordPress: user_can( $user, 'administrator' )
  // is the documented idiom (roles are reachable through the capability machinery), so
  // the map carries them. Without this, every role-name check lands in the
  // "custom/unmapped → ADMIN (uncertain)" bucket and drags a needless uncertainty flag.
  administrator: 'ADMIN',
  editor: 'EDITOR',
  author: 'AUTHOR',
  contributor: 'CONTRIBUTOR',
  subscriber: 'SUBSCRIBER',
};

// VERIFIED VENDOR CAPABILITY LINEAGE — per-plugin grant knowledge proven against
// source, each entry naming its evidence. Stock caps live in CAP_ROLE above; a cap
// matched here is no longer "custom/unmapped → ADMIN uncertain": the floor is
// lineaged, the uncertain flag clears. Order matters — first match wins.
//   AIOSEO (All in One SEO) two-tier rule, verified against Access.php: capabilities
//   named aioseo_page_* are granted to ALL edit_posts roles (contributor-reachable
//   by default); every OTHER aioseo_* capability sits behind the Access.php isAdmin
//   short-circuit → admin-floor.
const VENDOR_CAP_LINEAGE = [
  { re: /^aioseo_page_/, role: 'CONTRIBUTOR', via: 'AIOSEO two-tier capability lineage — aioseo_page_* caps are granted to all edit_posts roles by default (Access.php)' },
  { re: /^aioseo_/, role: 'ADMIN', via: 'AIOSEO two-tier capability lineage — non-page aioseo_* caps sit behind the Access.php isAdmin short-circuit' },
];

// Capability → role from VERIFIED lineage only (stock map, then the vendor table).
// Returns { role, via } or null when unmapped — callers apply their own fallback
// (the add_cap grant index, then ADMIN-uncertain), same as before.
function capLineage(cap) {
  if (CAP_ROLE[cap]) return { role: CAP_ROLE[cap], via: 'stock cap→role map' };
  for (const v of VENDOR_CAP_LINEAGE) if (v.re.test(cap)) return { role: v.role, via: v.via };
  return null;
}

// Gate regexes (per-line, run on ORIGINAL lines like privemap's findMitigations).
const GATE_RES = [
  { id: 'current_user_can', re: /(?<![\w$>:-])current_user_can\s*\(\s*['"]([^'"]+)['"]/, cap: true },
  { id: 'current_user_can', re: /(?<![\w$>:-])current_user_can\s*\(/, cap: false }, // variable/dynamic cap
  { id: 'check_admin_referer', re: /(?<![\w$>:-])check_admin_referer\s*\(/, nonce: true },
  { id: 'check_ajax_referer', re: /(?<![\w$>:-])check_ajax_referer\s*\(/, nonce: true },
  { id: 'wp_verify_nonce', re: /(?<![\w$>:-])wp_verify_nonce\s*\(/, nonce: true },
  { id: 'is_user_logged_in', re: /(?<![\w$>:-])is_user_logged_in\s*\(/, login: true },
  // user_can( $user, 'cap' ) — WP's OBJECT form of the capability check. It gates the
  // REQUEST only when $user is provably the requester, i.e. resolved from the request's own
  // credentials (or the current-user object) in the SAME body — the SureTriggers shape:
  //   $user = wp_authenticate_application_password( null, $u, $p );
  //   if ( ! user_can( $user, 'administrator' ) ) return 403;
  // A user_can() against a chosen/ambient id (user_can( $id, 'cap' ) with $id from $_POST)
  // checks SOMEONE ELSE's capability — it is not a gate on the requester and is deliberately
  // credited NOTHING here, exactly as before (never guessed in either direction).
  { id: 'user_can', re: /(?<![\w$>:-])user_can\s*\(\s*\$([A-Za-z_]\w*)\s*,\s*['"]([^'"]+)['"]/, cap: true, objectForm: true },
];

// Is $var provably the REQUESTER in this body? True only when it was assigned from a call
// that resolves identity FROM THE REQUEST: an in-band credential verification (application
// passwords, wp_authenticate) or the current-user object. Anything else — a chosen id, an
// ambient global, an unresolvable expression — is false, and the object-form gate is then
// credited nothing at all (the honest middle: neither a gate nor a fabricated unauth).
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

// Both capability-gate FORMS count toward a floor: current_user_can( 'cap' ) and the object
// form user_can( $requester, 'cap' ) (credited only for a requester-resolved $user — see
// requesterResolved). ONE predicate so the four floor sites cannot drift apart, and one
// describer so a reason string never mislabels the form it read.
const isCapGate = (g) => g.id === 'current_user_can' || g.id === 'user_can';
const describeCapGate = (g) => `${g.id}(${g.cap ? `'${g.cap}'` : 'dynamic'})`;

// Admin-render hooks: render-side surface, fires only inside authenticated admin
// pages — never a remote input channel. High-confidence KILL territory in rescore.
const ADMIN_RENDER_HOOKS = new Set([
  'admin_notices', 'network_admin_notices', 'user_admin_notices', 'all_admin_notices',
  'admin_menu', 'network_admin_menu', 'user_admin_menu', 'admin_enqueue_scripts',
  'admin_head', 'admin_footer', 'in_admin_header', 'wp_dashboard_setup',
]);

// Superglobal / request-channel reads (a front-loaded hook's handler is only
// REQUEST-DRIVEN when it reads one — same doctrine as privemap's init modeling).
const REQUEST_CHANNEL = /\$_(?:POST|GET|REQUEST|COOKIE|FILES)\b|\$[A-Za-z_]\w*->(?:get_param|get_json_params|get_body|get_header|get_headers)\s*\(/;

// --- structural parsing (same conventions as engine/privemap.mjs) --------------

// Blank comments and string CONTENTS so brace counting and call detection are not
// fooled by '{', '}' or 'function(' inside a string literal or comment. Heredoc/
// nowdoc bodies are NOT understood (documented blind spot).
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

const FN_RE = /\bfunction\s+&?\s*([A-Za-z_]\w*)\s*\(/;

// Extract named functions/methods with brace-matched bodies (original + sanitized).
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
    i = end;
  }
  return fns;
}

// --- class index (string static-callback resolution: 'C::m' / '\A\B\C::m') -------

const CLASS_RE = /\b(?:class|trait)\s+([A-Za-z_]\w*)/;
const NS_RE = /^\s*namespace\s+([A-Za-z_]\w*(?:\\[A-Za-z_]\w*)*)\s*;/;
// Trait use-inside-class: `use TraitA, \Ns\TraitB;` (closure `use ($x)` has parens,
// never matches). One level only — traits using traits are not chased.
const TRAIT_USE_RE = /^\s*use\s+([A-Za-z_][\w\\]*(?:\s*,\s*\\?[A-Za-z_][\w\\]*)*)\s*;/;

// Extract class/trait declarations with brace-matched bodies: name, file namespace
// (one `namespace` statement per file assumed — multiple blocks are a documented
// blind spot), declared methods, and used traits. Anonymous `new class` skipped.
function extractClasses(path, orig, san) {
  const classes = [];
  let namespace = '';
  for (let i = 0; i < san.length; i++) {
    const ns = san[i].match(NS_RE);
    if (ns) namespace = ns[1];
    const m = san[i].match(CLASS_RE);
    if (!m || /\bnew\s+(?:class|trait)\b/.test(san[i])) continue;
    let depth = 0;
    let opened = false;
    let end = -1;
    for (let j = i; j < san.length; j++) {
      for (const ch of san[j]) {
        if (ch === '{') { depth++; opened = true; } else if (ch === '}') { depth--; }
      }
      if (opened && depth <= 0) { end = j; break; }
      if (!opened && j - i > 6) break; // interface declaration, no body
    }
    if (!opened) continue;
    if (end === -1) end = san.length - 1; // unbalanced — to EOF (same heuristic as fns)
    const methods = new Map();
    const traits = [];
    for (let j = i; j <= end; j++) {
      const fm = san[j].match(FN_RE);
      if (fm && !methods.has(fm[1])) methods.set(fm[1], j + 1);
      const tu = orig[j].match(TRAIT_USE_RE);
      if (tu) for (const t of tu[1].split(',')) traits.push(t.trim().replace(/^\\/, '').split('\\').pop());
    }
    classes.push({ name: m[1], namespace, path, line: i + 1, end, methods, traits });
    i = end;
  }
  return classes;
}

// Resolve a string static-method reference { fqn, className, method } against the
// class index. Namespace matching: a fully-qualified prefix must equal or suffix-
// match the declaring namespace ('A\B\C::m' → namespace A\B + class C; 'C::m' is
// namespace-agnostic). Methods are found on the class or ONE level of used traits.
// Returns { fn, classInfo } or { error } — ambiguity is UNCERTAIN, never guessed.
function resolveStatic(model, ref) {
  const ns = ref.fqn.includes('\\') ? ref.fqn.slice(0, ref.fqn.lastIndexOf('\\')) : '';
  const cands = model.classes.filter((c) => c.name === ref.className &&
    (!ns || c.namespace === ns || c.namespace.endsWith('\\' + ns) || (c.namespace && ns.endsWith(c.namespace))));
  const hits = [];
  for (const c of cands) {
    let line = c.methods.get(ref.method);
    let via = null;
    if (line == null) {
      for (const t of c.traits) {
        const trait = model.classes.find((x) => x.name === t && (!x.namespace || !c.namespace || x.namespace === c.namespace));
        if (trait && trait.methods.get(ref.method) != null) { line = trait.methods.get(ref.method); via = ` (via trait ${trait.name})`; break; }
      }
    }
    if (line != null) {
      const fn = (model.byName.get(ref.method) || []).find((f) => f.path === c.path && f.line === line);
      hits.push({ classInfo: c, via, fn: fn || { name: ref.method, path: c.path, line, body: [], san: [] } });
    }
  }
  if (hits.length === 1) return hits[0];
  if (hits.length > 1) {
    return { error: `static callback '${ref.fqn}::${ref.method}' is ambiguous — ${hits.length} in-tree classes named ${ref.className} define it (${hits.map((h) => `${h.fn.path}:${h.fn.line}`).join(', ')}) — UNCERTAIN, never guessed` };
  }
  return { error: cands.length
    ? `method '${ref.method}' not found on class ${ref.className} in scanned sources (magic __callStatic or definition outside the tree) — gate ungraded`
    : `class '${ref.fqn}' not found in scanned sources (vendor/external definition) — gate ungraded` };
}

// Callback of add_action/add_filter/add_shortcode: string `'cb'`, string static
// form `'C::m'` / `'\FQN\C::m'`, or array forms `array($this,'cb')` /
// `array('Class','cb')` / `[ $this, 'cb' ]` / `[ C::class, 'cb' ]` (array method =
// LAST quoted id — resolution stays name-based). Closures flagged.
function parseCallback(expr) {
  if (/^\s*(function\b|fn\s*\(|static\s+function\b)/.test(expr)) return { closure: true };
  const sm = expr.match(/^\s*['"](\\?[A-Za-z_]\w*(?:\\[A-Za-z_]\w*)*)::([A-Za-z_]\w*)['"]/);
  if (sm) {
    const fqn = sm[1].replace(/^\\/, '');
    return { staticRef: { fqn, className: fqn.split('\\').pop(), method: sm[2] }, name: sm[2] };
  }
  const ids = [...expr.matchAll(/['"]([A-Za-z_]\w*)['"]/g)].map((x) => x[1]);
  if (/array\s*\(|\[/.test(expr)) return { name: ids[ids.length - 1] };
  return { name: ids[0] };
}

// Args-array callable value for `key`: array forms (`array($this,'m')`,
// `[ C::class, 'm' ]` — method = LAST quoted id, name-based as before), a STRING
// static-method reference (`'C::m'` / `'A\B\C::m'` / `'\A\B\C::m'` — class-oriented
// resolution via the class index), or a plain string function name. Returns
// { name } | { staticRef:{ fqn, className, method } } | null.
function callableValue(win, key) {
  const k = `['"]${key}['"]\\s*=>\\s*`;
  const am = win.match(new RegExp(k + `array\\([^)]{0,200}?,\\s*['"]([A-Za-z_]\\w*)['"]\\s*\\)`))
      || win.match(new RegExp(k + `\\[[^\\]]{0,200}?,\\s*['"]([A-Za-z_]\\w*)['"]\\s*\\]`));
  if (am) return { name: am[1] };
  const sm = win.match(new RegExp(k + `['"](\\\\?[A-Za-z_]\\w*(?:\\\\[A-Za-z_]\\w*)*)::([A-Za-z_]\\w*)['"]`));
  if (sm) {
    const fqn = sm[1].replace(/^\\/, '');
    return { staticRef: { fqn, className: fqn.split('\\').pop(), method: sm[2] } };
  }
  const fm = win.match(new RegExp(k + `['"]([A-Za-z_]\\w*)['"]`));
  return fm ? { name: fm[1] } : null;
}

// Read a call's arguments as TOP-LEVEL arguments (depth-aware over ()/[]/{} , quote-aware
// with backslash escapes). Deliberate duplicate of privemap's helper: the two engines'
// registration reads must stay in lock-step or verdicts stop matching the report.
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
// read. This is what separates a DATA-DRIVEN registration from an inline one:
//   register_rest_route( $ns, $route, $args )      — args are argument #3
//   wp_register_ability( $name, $args )            — args are argument #2
// When that argument is a VARIABLE, the window never contained the args at all, so a missing
// permission_callback key is IGNORANCE — never absence. Measured: Everest Forms 3.x
// (includes/abilities/class-evf-abilities.php:170) registers every ability in a loop from
// $def['args'], each definition carrying its own permission_callback, and the loop site was
// graded an ungated UNAUTH ability executable with no capability gate.
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

// Inline closure value of an args key: `function (...) { ... }` body brace-matched
// within the window, or `fn (...) => expr` (single expression). PHP 7 return types
// (`static function (): bool {`, `function () use ($x): bool {`) are understood —
// WP core's own ability gates use them. Returns the closure TEXT or null. Brace math
// on raw text (strings containing '{' can fool it — documented blind spot).
function closureValue(win, key) {
  const m = win.match(new RegExp(`['"]${key}['"]\\s*=>\\s*((?:static\\s+)?function\\s*\\([^)]*\\)\\s*(?:use\\s*\\([^)]*\\)\\s*)?(?::\\s*[\\w\\\\|&?]+\\s*)?\\{|fn\\s*\\([^)]*\\)\\s*(?::\\s*[\\w\\\\|&?]+\\s*)?=>)`));
  if (!m) return null;
  const rest = win.slice(m.index + m[0].length);
  if (m[1].endsWith('{')) {
    let depth = 1;
    for (let i = 0; i < rest.length; i++) {
      if (rest[i] === '{') depth++;
      else if (rest[i] === '}' && --depth === 0) return rest.slice(0, i);
    }
    return rest;
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

// An inline closure HANDLER (add_action('hook', function () { ... })): extract the
// closure text starting at the registration line. Same brace-math caveats.
function inlineClosureText(win) {
  const m = win.match(/(?:static\s+)?function\s*\([^)]*\)\s*(?:use\s*\([^)]*\)\s*)?(?::\s*[\w\\|&?]+\s*)?\{|fn\s*\([^)]*\)\s*(?::\s*[\w\\|&?]+\s*)?=>/);
  if (!m) return null;
  const rest = win.slice(m.index + m[0].length);
  if (m[0].endsWith('{')) {
    let depth = 1;
    for (let i = 0; i < rest.length; i++) {
      if (rest[i] === '{') depth++;
      else if (rest[i] === '}' && --depth === 0) return rest.slice(0, i);
    }
    return rest;
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

// --- registration parsing -------------------------------------------------------

// Hook → base classification. Cron detection needs the tree-wide scheduled-hook set,
// so classify() takes it. Base floors are stated with the reason that sets them —
// gates only ever RAISE a floor from here.
function classifyHook(hook, cronHooks) {
  if (cronHooks.has(hook)) {
    return { floor: 'SERVER', kind: 'cron', confidence: 'high',
      reason: `'${hook}' is a wp-cron scheduled-event hook (a wp_schedule_event/wp_next_scheduled reference exists in-tree) — server-side only, NOT remote-reachable` };
  }
  if (/^wp_ajax_nopriv_/.test(hook)) return { floor: 'UNAUTH', kind: 'ajax-nopriv', confidence: 'high', reason: 'wp_ajax_nopriv_* fires for unauthenticated admin-ajax.php requests' };
  if (/^wp_ajax_/.test(hook)) return { floor: 'SUBSCRIBER', kind: 'ajax', confidence: 'high', reason: 'wp_ajax_* requires an authenticated session, any role' };
  if (/^admin_post_nopriv/.test(hook)) return { floor: 'UNAUTH', kind: 'admin-post-nopriv', confidence: 'high', reason: 'admin_post_nopriv_* fires for unauthenticated admin-post.php requests' };
  if (/^admin_post(?:_|$)/.test(hook)) return { floor: 'SUBSCRIBER', kind: 'admin-post', confidence: 'high', reason: 'admin_post_* requires an authenticated session, any role' };
  if (hook === 'admin_init') {
    return { floor: 'SUBSCRIBER', kind: 'admin_init', confidence: 'medium',
      reason: 'admin_init fires on EVERY wp-admin request (any authenticated role); it also fires on unauthenticated admin-ajax.php/admin-post.php loads, so a handler reading request channels at hop 0 is unauth-reachable — see handler note' };
  }
  if (/^(?:init|plugins_loaded|rest_api_init|wp_loaded|after_setup_theme|setup_theme)$/.test(hook)) {
    return { floor: 'UNAUTH', kind: 'bootstrap', confidence: 'medium',
      reason: `'${hook}' is a front-loaded bootstrap hook — fires for every request including unauthenticated` };
  }
  if (ADMIN_RENDER_HOOKS.has(hook)) {
    return { floor: 'ADMIN', kind: 'admin-render', confidence: 'high',
      reason: `'${hook}' is an admin render-side hook — fires only inside authenticated admin pages, never a remote input channel` };
  }
  return null; // unclassified — the caller emits UNKNOWN with the hook named
}

const COMMENT_LINE = /^\s*(?:\*|\/\/)/;

// Runaway guards for a registration's argument array — a SAFETY bound, never the
// parser. The next registration of the same kind always cuts the window first.
const ABILITY_WINDOW_MAX = 400;
const REST_WINDOW_MAX = 200;

// Registration argument window (same helper as engine/privemap.mjs — the two engines
// MUST see the same registration args, or rescore verdicts drift from the report they
// adjudicate). The registration line through the line where its ARGUMENT LIST closes
// (paren/bracket depth back to zero on comment/string-blanked text), or to the next
// registration of the same kind, whichever comes first.
//
// WHY NOT A FIXED LINE BUDGET: WP 6.9 ability args run well past 60 lines (typed
// schemas), so a flat `i + 60` truncates the permission_callback and mis-reads a
// PRESENT gate as ABSENT — the one error direction that fabricates an unauthenticated
// verdict (measured: siteseo/main/abilitiesregister.php:222 gates 63 lines down).
// Returns { lines, truncated }; `truncated` = the safety bound bit before the args
// closed, so gate state must report UNPARSED, never absent.
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

function extractRegistrations(path, orig, san) {
  const regs = [];
  for (let i = 0; i < orig.length; i++) {
    const line = orig[i];
    if (COMMENT_LINE.test(line)) continue;
    let m = line.match(/\badd_(?:action|filter)\(\s*['"]([^'"]+)['"]\s*,\s*(.*)$/);
    if (m) {
      let expr = m[2];
      let closureText = null;
      if (/array\s*\([^)]*$/.test(expr) || /\[[^\]]*$/.test(expr)) expr = orig.slice(i, i + 4).join(' ').replace(/^[^(]*\(\s*['"][^'"]+['"]\s*,\s*/, '');
      const cb = parseCallback(expr);
      if (cb.closure) closureText = inlineClosureText(orig.slice(i, i + 40).join('\n'));
      regs.push({ path, line: i + 1, kind: 'hook', hook: m[1], ...cb, ...(closureText != null ? { closureText } : {}) });
      continue;
    }
    m = line.match(/\badd_shortcode\(\s*['"]([^'"]+)['"]\s*,\s*(.*)$/);
    if (m) {
      let expr = m[2];
      let closureText = null;
      if (/array\s*\([^)]*$/.test(expr) || /\[[^\]]*$/.test(expr)) expr = orig.slice(i, i + 4).join(' ').replace(/^[^(]*\(\s*['"][^'"]+['"]\s*,\s*/, '');
      const cb = parseCallback(expr);
      if (cb.closure) closureText = inlineClosureText(orig.slice(i, i + 40).join('\n'));
      regs.push({ path, line: i + 1, kind: 'shortcode', hook: `shortcode:${m[1]}`, shortcode: m[1], ...cb, ...(closureText != null ? { closureText } : {}) });
      continue;
    }
    if (/\bregister_rest_route\s*\(/.test(line)) {
      // Depth-aware window (args through their closing bracket), cut at the NEXT
      // register_rest_route (same idiom as privemap).
      const { lines: restLines } = argsWindow(orig, san, i, {
        maxLines: REST_WINDOW_MAX,
        isNext: (l) => /\bregister_rest_route\s*\(/.test(l),
      });
      const win = restLines.join('\n');
      const cb = callableValue(win, 'callback');
      const pc = callableValue(win, 'permission_callback');
      const pcClosureText = !pc ? closureValue(win, 'permission_callback') : null;
      // Present-but-unparseable gate (expression/constant/call, or a string form we do
      // not understand): NEVER the absent doctrine — UNCERTAIN, never public. A
      // DATA-DRIVEN registration (args in a variable) counts: the window never contained
      // the args, so "key not found" is ignorance, not absence.
      const pcUnparseable = !pc && pcClosureText == null
        && (/['"]permission_callback['"]\s*=>/.test(win) || !argsInline(nThArgExpr(win, 2)));
      const rm = win.match(/register_rest_route\s*\(\s*['"]([^'"]+)['"]\s*,\s*['"]([^'"]+)['"]/);
      regs.push({
        path, line: i + 1, kind: 'rest', hook: 'rest_route',
        route: rm ? `${rm[1]}${rm[2]}` : undefined,
        name: cb ? (cb.name || cb.staticRef.method) : undefined,
        ...(cb && cb.staticRef ? { cbRef: cb.staticRef } : {}),
        closure: !cb,
        permissionCallback: pc ? (pc.name || `${pc.staticRef.fqn}::${pc.staticRef.method}`) : undefined,
        ...(pc && pc.staticRef ? { pcRef: pc.staticRef } : {}),
        pcNamed: !!pc,
        ...(pcUnparseable ? { pcUnparseable } : {}),
        ...(pcClosureText != null ? { pcClosureText } : {}),
      });
      continue;
    }
    // WP 6.9 Abilities API (same depth-aware window idiom as privemap: args through
    // their closing bracket, cut at the next registration, safety-bounded — NEVER a
    // fixed line budget, which truncates 60+ line ability args and turns a present
    // permission_callback into a fabricated UNAUTH verdict).
    if (/(?<![\w$>:-])wp_register_ability\s*\(/.test(line) && !/^\s*function\s/.test(line)) {
      const { lines: abLines, truncated } = argsWindow(orig, san, i, {
        maxLines: ABILITY_WINDOW_MAX,
        isNext: (l) => /(?<![\w$>:-])wp_register_ability\s*\(/.test(l) && !/^\s*function\s/.test(l),
      });
      const win = abLines.join('\n');
      const nm = win.match(/(?<![\w$>:-])wp_register_ability\s*\(\s*['"]([^'"]+)['"]/);
      const ec = callableValue(win, 'execute_callback');
      const pc = callableValue(win, 'permission_callback');
      const pcClosureText = !pc ? closureValue(win, 'permission_callback') : null;
      // A gate we cannot READ is not a gate that is ABSENT: a truncated window is
      // ignorance, and so is a DATA-DRIVEN registration (args in a variable — the window
      // never contained the args). Either way the absent doctrine below would fabricate
      // public reachability.
      const pcKeyPresent = /['"]permission_callback['"]\s*=>/.test(win);
      const pcUnparseable = !pc && pcClosureText == null
        && (pcKeyPresent || truncated || !argsInline(nThArgExpr(win, 1)));
      regs.push({
        path, line: i + 1, kind: 'ability', hook: 'wp_register_ability',
        ability: nm ? nm[1] : undefined,
        name: ec ? (ec.name || ec.staticRef.method) : undefined,
        ...(ec && ec.staticRef ? { cbRef: ec.staticRef } : {}),
        closure: !ec,
        permissionCallback: pc ? (pc.name || `${pc.staticRef.fqn}::${pc.staticRef.method}`) : undefined,
        ...(pc && pc.staticRef ? { pcRef: pc.staticRef } : {}),
        pcNamed: !!pc,
        ...(pcUnparseable ? { pcUnparseable } : {}),
        ...(pcClosureText != null ? { pcClosureText } : {}),
      });
    }
  }
  return regs;
}

// wp-cron scheduled-event hook names referenced anywhere in the tree
// (wp_schedule_event/wp_schedule_single_event/wp_next_scheduled/wp_unschedule_event).
// Hook-first schedulers take the hook as the FIRST quoted arg;
// wp_schedule_event/wp_unschedule_event take it as the THIRD ($timestamp, $recurrence, $hook).
const CRON_RE = [
  /\b(?:wp_schedule_single_event|wp_next_scheduled|wp_clear_scheduled_hook)\s*\(\s*[^,)]*,?\s*['"]([A-Za-z_]\w*)['"]/g,
  /\b(?:wp_schedule_event|wp_unschedule_event)\s*\([^)]*?,[^)]*?,\s*['"]([A-Za-z_]\w*)['"]/g,
];
function collectCronHooks(recs) {
  const hooks = new Set();
  for (const { orig } of recs) {
    for (const line of orig) {
      if (COMMENT_LINE.test(line)) continue;
      for (const re of CRON_RE) for (const m of line.matchAll(re)) hooks.add(m[1]);
    }
  }
  return hooks;
}

// --- nonce provenance (who can OBTAIN the nonce, not just who can present it) ----
//
// The adjudication lesson, round two: a handler whose ONLY gate is a nonce check is
// SUBSCRIBER-reachable on paper, but dead in practice when the nonce is emitted
// exclusively on admin screens (wp_localize_script inside a manage_options-gated
// enqueue, wp_nonce_field on a manage_options-registered menu page). This index
// collects emission SITES (wp_create_nonce / wp_nonce_field with literal actions)
// and grades each site's guard context: enclosing function's early-return
// current_user_can, the hook the emitter is attached to, the menu-page capability
// for render callbacks (helper-indirection resolved when it literally returns a cap
// string), and add_cap grant patterns for custom caps. Best-effort by design —
// UNKNOWN is emitted with the reason, never a fabricated emission site.

// Nonce emission sites with literal action names: action → [{ path, line, kind, fn }].
// Forms: wp_create_nonce('a') and wp_nonce_field('a', ...) single-line;
// wp_nonce_url(<url>, 'a') window-parsed (the action is the SECOND top-level arg —
// the URL expression itself routinely nests add_query_arg arrays).
function collectNonceEmissions(parsed, fns) {
  const emissions = new Map();
  const RE = [/\bwp_create_nonce\s*\(\s*['"]([^'"]+)['"]/, /\bwp_nonce_field\s*\(\s*['"]([^'"]+)['"]/];
  const add = (action, site) => {
    if (!emissions.has(action)) emissions.set(action, []);
    emissions.get(action).push(site);
  };
  for (const { path, orig } of parsed) {
    for (let i = 0; i < orig.length; i++) {
      if (COMMENT_LINE.test(orig[i])) continue;
      // Smallest enclosing function (methods are flat, so any match is the one).
      // Mixed PHP/HTML template files defeat brace math — fall back to the nearest
      // PRECEDING function declaration, flagged approximate (never silent).
      let fn = fns.find((f) => f.path === path && i + 1 >= f.line && i + 1 <= f.end) || null;
      let fnApprox = false;
      if (!fn) {
        const prior = fns.filter((f) => f.path === path && f.line <= i + 1).sort((a, b) => b.line - a.line)[0];
        if (prior) { fn = prior; fnApprox = true; }
      }
      for (const re of RE) {
        const m = orig[i].match(re);
        if (!m) continue;
        add(m[1], { path, line: i + 1, kind: re === RE[0] ? 'wp_create_nonce' : 'wp_nonce_field', fn, ...(fnApprox ? { fnApprox } : {}) });
      }
      if (/\bwp_nonce_url\s*\(/.test(orig[i])) {
        // Multi-line calls are the norm (add_query_arg arrays) — window ≤12 lines.
        const win = orig.slice(i, i + 12).join('\n');
        const mm = win.match(/\bwp_nonce_url\s*\(([^;]{0,400}?)\)\s*;/);
        if (mm) {
          const args = splitTopLevel(mm[1]);
          const q = args[1] && args[1].match(/^['"]([^'"]+)['"]/);
          if (q) add(q[1], { path, line: i + 1, kind: 'wp_nonce_url', fn, ...(fnApprox ? { fnApprox } : {}) });
        }
      }
    }
  }
  return emissions;
}

// Split an args string on top-level commas (paren/bracket depth 0).
function splitTopLevel(args) {
  const out = [];
  let depth = 0;
  let cur = '';
  for (const ch of args) {
    if (ch === '(' || ch === '[') depth++;
    else if (ch === ')' || ch === ']') depth--;
    if (ch === ',' && depth === 0) { out.push(cur); cur = ''; } else cur += ch;
  }
  if (cur.trim()) out.push(cur);
  return out.map((s) => s.trim());
}

// Menu/screen registrations: add_menu_page / add_submenu_page → { slug, cap,
// callback, path, line }. The capability argument may be a quoted string OR a
// single-helper indirection (`$this->get_cap()`) — resolved when the helper body
// literally `return 'cap';`s, else capUnknown (honest).
function collectMenuPages(parsed, byName) {
  const pages = [];
  const RE = /\b(add_menu_page|add_submenu_page)\s*\(/;
  for (const { path, orig } of parsed) {
    for (let i = 0; i < orig.length; i++) {
      if (COMMENT_LINE.test(orig[i]) || !RE.test(orig[i])) continue;
      // Multi-line registrations are the norm — window ≤12 lines.
      const win = orig.slice(i, i + 12).join('\n');
      const mm = win.match(/\b(add_menu_page|add_submenu_page)\s*\(([^;]{0,600}?)\)\s*;/);
      if (!mm) continue;
      const args = splitTopLevel(mm[2]);
      // Non-anchored: args routinely carry trailing `// comment` notes — which
      // top-level splitting attaches to the FOLLOWING arg, so strip leading
      // comment lines before reading the literal.
      const quoted = (a) => {
        if (!a) return null;
        const clean = a.replace(/^(\s*\/\/[^\n]*(\n|$))+/, '').trim();
        const q = clean.match(/^['"]([^'"]+)['"]/);
        return q ? q[1] : null;
      };
      const capArg = mm[1] === 'add_menu_page' ? args[2] : args[3];
      const slugArg = mm[1] === 'add_menu_page' ? args[3] : args[4];
      const cbArg = mm[1] === 'add_menu_page' ? args[4] : args[5];
      let cap = quoted(capArg);
      let capViaFilter = false;
      if (!cap && capArg) {
        // Helper indirection: `$this->wpmm_get_capability()` /
        // `wpmm_get_capability('settings')` — credited only when exactly one
        // in-tree function by that name literally returns a quoted capability
        // string, either directly or as an apply_filters DEFAULT (flagged — a
        // filter could still change it at runtime).
        const hm = capArg.match(/(?:->|::)?([A-Za-z_]\w*)\s*\(/);
        const cands = hm ? (byName.get(hm[1]) || []) : [];
        if (hm && cands.length === 1) {
          const body = cands[0].body.join('\n');
          const rm = body.match(/return\s+['"]([a-z_][a-z0-9_]*)['"]\s*;/)
                  || body.match(/return\s+apply_filters\s*\([\s\S]{0,200}?,\s*['"]([a-z_][a-z0-9_]*)['"]\s*\)/);
          if (rm) { cap = rm[1]; capViaFilter = /apply_filters/.test(rm[0]); }
        }
      }
      const cb = cbArg ? parseCallback(cbArg) : {};
      pages.push({
        path, line: i + 1,
        slug: quoted(slugArg) || null,
        cap: cap || null,
        ...(capViaFilter ? { capViaFilter } : {}),
        callback: cb.name || (cb.staticRef && cb.staticRef.method) || null,
        capUnknown: !cap,
      });
    }
  }
  return pages;
}

// Custom-capability grants: `$role = get_role('editor'); $role->add_cap('cap')`
// (same-function association) and the two-arg forms `wp_roles()->add_cap('role',
// 'cap')` / `$wp_roles->add_cap('role', 'cap')`. cap → Set of granted role slugs.
function collectCapGrants(fns) {
  const grants = new Map();
  const grant = (cap, role) => {
    if (!grants.has(cap)) grants.set(cap, new Set());
    grants.get(cap).add(role);
  };
  for (const fn of fns) {
    const rolesInFn = new Set();
    for (const l of fn.body) {
      const gm = l.match(/\bget_role\s*\(\s*['"]([a-z_]\w*)['"]/);
      if (gm) rolesInFn.add(gm[1]);
      const dm = l.match(/(?:\bwp_roles\s*\(\s*\)|\$wp_roles)\s*->\s*add_cap\s*\(\s*['"]([a-z_]\w*)['"]\s*,\s*['"]([a-z_]\w*)['"]/);
      if (dm) grant(dm[2], dm[1]);
      const am = l.match(/->add_cap\s*\(\s*['"]([a-z_]\w*)['"]\s*\)/);
      if (am && !dm) for (const r of rolesInFn) grant(am[1], r);
    }
  }
  return grants;
}

const GRANT_ROLE_FLOOR = { subscriber: 'SUBSCRIBER', contributor: 'CONTRIBUTOR', author: 'AUTHOR', editor: 'EDITOR', administrator: 'ADMIN' };

// Capability → role for PROVENANCE guards: stock map + verified vendor lineage
// first, then the add_cap grant index (a custom cap granted only to 'administrator'
// is an ADMIN fence; granted to a lower role, that role is the floor). Unknown and
// ungranted → ADMIN uncertain.
function provenanceRoleForCap(model, cap) {
  const lin = capLineage(cap);
  if (lin) return { role: lin.role, uncertain: false, via: lin.via };
  const g = model.capGrants.get(cap);
  if (g && g.size) {
    let floor = null;
    for (const r of g) {
      const f = GRANT_ROLE_FLOOR[r];
      if (!f) return { role: 'ADMIN', uncertain: true, via: `custom cap granted to unmapped role '${r}' — flagged` };
      if (!floor || ROLE_RANK[f] < ROLE_RANK[floor]) floor = f;
    }
    return { role: floor, uncertain: floor !== 'ADMIN', via: `custom cap granted to ${[...g].join(', ')} (add_cap index)` };
  }
  return { role: 'ADMIN', uncertain: true, via: 'custom/unmapped capability, no in-tree add_cap grant — treated as ADMIN (flagged)' };
}

// Early-return capability guard idiom inside an emission function:
// `if (!current_user_can('x')) return/wp_die/exit;` (the return may sit on the next
// line — standard WP brace style). A body-wide current_user_can is NOT credited
// here: provenance feeds kill-decisions, so the guard must be the strict idiom and
// must precede the emission line. Returns [{ cap, line }] (possibly several).
function earlyReturnCapGuards(fn, beforeLine = Infinity) {
  const guards = [];
  for (let k = 0; k < fn.body.length; k++) {
    const l = fn.body[k];
    const m = l.match(/!\s*current_user_can\s*\(\s*['"]([^'"]+)['"]/);
    if (!m) continue;
    const lineNo = fn.line + k;
    if (lineNo > beforeLine) continue;
    if (/\b(?:return|wp_die|exit|die)\b/.test(l)) { guards.push({ cap: m[1], line: lineNo }); continue; }
    // Guard opens a block whose first statement exits (next two lines).
    const tail = fn.body.slice(k + 1, k + 3).join(' ');
    if (/\b(?:return|wp_die|exit|die)\b/.test(tail)) guards.push({ cap: m[1], line: lineNo });
  }
  return guards;
}

// Frontend emission contexts: any visitor (unauthenticated included) sees these.
const FRONTEND_HOOKS = new Set(['wp_footer', 'wp_head', 'wp_enqueue_scripts', 'login_enqueue_scripts', 'login_head', 'login_form', 'login_form_', 'register_form', 'comment_form', 'get_footer']);

// The guard context of one emission site's enclosing function:
// { floor, evidence, reason } — floor null = UNRESOLVED (named in reason).
function fnContextGuard(model, fn, siteLine, evidence) {
  // 1. Strict early-return body guard — decisive wherever the function is attached.
  const guards = earlyReturnCapGuards(fn, siteLine);
  if (guards.length) {
    let floor = 'SUBSCRIBER';
    const vias = [];
    for (const g of guards) {
      const r = provenanceRoleForCap(model, g.cap);
      if (ROLE_RANK[r.role] > ROLE_RANK[floor]) floor = r.role;
      vias.push(r.via);
      evidence.push({ ref: `${fn.path}:${g.line}`, kind: 'nonce-emission-guard', note: `early-return guard current_user_can('${g.cap}') → ${r.role} (${r.via})` });
    }
    return { floor, reason: `emission function ${fn.name} is fenced by an early-return capability guard → ${floor}` };
  }
  // 2. Hook attachments of the emission function.
  const attached = model.regs.filter((r) => (r.name && r.name === fn.name) || (r.staticRef && r.staticRef.method === fn.name && r.path === fn.path));
  const contexts = [];
  for (const r of attached) {
    const hook = r.hook;
    if (FRONTEND_HOOKS.has(hook) || [...FRONTEND_HOOKS].some((h) => hook.startsWith(h))) {
      contexts.push({ floor: 'UNAUTH', note: `emitted on '${hook}' — frontend/login context, unauthenticated visitors receive this nonce` });
    } else if (hook === 'enqueue_block_editor_assets') {
      contexts.push({ floor: 'CONTRIBUTOR', note: `emitted via enqueue_block_editor_assets — the block editor loads for any role with edit_posts (contributor and up)` });
    } else if (hook === 'admin_enqueue_scripts') {
      // Screen-guard refinement: an early return keyed on the admin page hook/slug
      // fences the enqueue to that screen — the screen's menu capability applies.
      const slugGuard = screenSlugGuard(fn, model);
      if (slugGuard) contexts.push(slugGuard);
      else if (/get_current_screen|hook_suffix|->id\b|\$hook(?:_suffix)?\b/.test(fn.body.join('\n'))) {
        contexts.push({ floor: null, note: `admin_enqueue_scripts function references screen/hook state but the guard is not statically resolvable — UNKNOWN, never guessed (a guessed SUBSCRIBER here would fabricate exposure)` });
      } else contexts.push({ floor: 'SUBSCRIBER', note: `emitted via admin_enqueue_scripts with no capability/screen guard — fires on EVERY admin screen including the subscriber profile` });
    } else if (hook === 'admin_init' || hook === 'init' || hook === 'admin_post' || /^wp_ajax/.test(hook)) {
      contexts.push({ floor: null, note: `emission function attached to '${hook}' — request-hook context does not bound who sees the emitted nonce` });
    } else {
      contexts.push({ floor: null, note: `emission function attached to '${hook}' — unclassified emission context` });
    }
  }
  // 3. Menu-page render callback: the page's registered capability gates the view.
  // Same-file matching only — callback names collide across files (a second
  // 'tf_options_page' elsewhere must not import its menu's unknown capability).
  for (const p of model.menuPages) {
    if (p.path === fn.path && p.callback && p.callback === fn.name) {
      contexts.push(p.cap
        ? menuCapContext(model, p)
        : { floor: null, note: `renders menu page '${p.slug || '?'}' whose capability argument is not statically resolvable — guard unknown` });
    }
  }
  if (!contexts.length) {
    return { floor: null, reason: `emission function ${fn.name} is not attached to any classified hook or menu screen in-tree — guard unresolvable` };
  }
  let weakest = null;
  for (const c of contexts) {
    evidence.push({ ref: `${fn.path}:${fn.line}`, kind: 'nonce-emission-guard', note: c.note });
    if (c.floor == null) return { floor: null, reason: c.note };
    if (!weakest || ROLE_RANK[c.floor] < ROLE_RANK[weakest]) weakest = c.floor;
  }
  return { floor: weakest, reason: `emission context floor ${weakest} (weakest of ${contexts.length} attachment${contexts.length === 1 ? '' : 's'})` };
}

// A menu capability argument → context. Helper-indirection was resolved at index
// time when literal; custom caps go through the grant index.
function menuCapContext(model, p) {
  const r = provenanceRoleForCap(model, p.cap);
  return { floor: r.role, note: `renders menu page '${p.slug || '?'}' registered with capability '${p.cap}' → ${r.role} (${r.via})${p.capViaFilter ? ' — capability arrives via an apply_filters DEFAULT literal; a filter could change it at runtime (flagged)' : ''}` };
}

// define()d path constants (WEGLOT_TEMPLATES_PAGES . '/settings.php' idiom):
// NAME → concatenated quoted literal parts (one level — constant-in-constant is
// not chased; the literal tail is usually enough for suffix matching).
function collectPhpConstants(parsed) {
  const consts = new Map();
  for (const { orig } of parsed) {
    for (const line of orig) {
      if (COMMENT_LINE.test(line)) continue;
      const m = line.match(/\bdefine\s*\(\s*['"]([A-Z_][A-Z0-9_]*)['"]\s*,\s*([^)]*)\)/);
      if (!m) continue;
      const lits = [...m[2].matchAll(/['"]([^'"]*)['"]/g)].map((x) => x[1]).filter((s) => s.includes('/'));
      if (lits.length) consts.set(m[1], lits.join(''));
    }
  }
  return consts;
}

// Screen-guard idiom inside an admin_enqueue_scripts function:
// `if ($hook !== 'toplevel_page_x') return;` where x is a registered menu slug —
// the enqueue is then fenced to that screen and the screen's capability applies.
// Property form: `$this->hook_suffix === $screen->id` — the property is traced to
// its `->prop = add_(menu|submenu)_page(...)` assignment and THAT registration's
// capability applies.
function screenSlugGuard(fn, model) {
  for (let k = 0; k < fn.body.length; k++) {
    const l = fn.body[k];
    if (!/!==|!=|===|==/.test(l)) continue;
    // Early-return idiom only (the return may open a block on the next line) —
    // except the pure screen-if form `$screen = get_current_screen(); if (x === y->id)`
    // where the guarded block IS the emission (no return needed).
    const isReturnGuard = /\breturn\b/.test(l) || /\breturn\b/.test(fn.body.slice(k + 1, k + 3).join(' '));
    // Property form: `$this->prop === $screen->id` (either order).
    const pm = l.match(/\$this->(\w+)\s*(?:===|!==)\s*\$\w+->id\b/) || l.match(/\$\w+->id\b\s*(?:===|!==)\s*\$this->(\w+)/);
    if (pm) {
      for (const f2 of model.fns) {
        for (let j = 0; j < f2.body.length; j++) {
          if (!new RegExp(`->${pm[1]}\\s*=\\s*add_(?:menu|submenu)_page\\s*\\(`).test(f2.body[j])) continue;
          const page = model.menuPages.find((p) => p.path === f2.path && Math.abs(p.line - (f2.line + j)) <= 1);
          if (page) {
            return page.cap
              ? menuCapContext(model, page)
              : { floor: null, note: `screen-guarded enqueue ($this->${pm[1]} screen check) whose menu capability is not statically resolvable` };
          }
        }
      }
      return { floor: null, note: `screen-guarded enqueue ($this->${pm[1]} screen check) — property assignment not traced to a menu registration` };
    }
    if (!isReturnGuard) continue;
    for (const q of l.matchAll(/['"]([^'"]+)['"]/g)) {
      for (const p of model.menuPages) {
        if (!p.slug) continue;
        if (q[1] === p.slug || q[1].endsWith('_' + p.slug)) {
          return p.cap
            ? menuCapContext(model, p)
            : { floor: null, note: `screen-guarded enqueue for menu '${p.slug}' whose capability is not statically resolvable` };
        }
      }
    }
  }
  return null;
}

// One-level include/render association for TEMPLATE-level emissions (a
// wp_nonce_field at file top level): who includes this template, and what is THEIR
// guard? Referrers resolve literal paths, define()d-constant prefixes, and
// same-function variable assignments ($tpl = CONST . '/dir/file.php'; include $tpl;).
// A referrer that is itself never called in-tree is a DEAD render path (orphan —
// excluded with the note attached); unresolvable DYNAMIC includes keep it UNKNOWN.
function templateReferrerGuard(model, site, evidence) {
  const REF_RE = /\b(?:include|include_once|require|require_once|get_template_part|load_template)\b|->(?:render|load_view|template|view|display)\s*\(/;
  // A reference line's effective path suffix: CONST . '/x.php' → constant tail +
  // literal; bare '/x.php' → the literal; 'x.php' relative → basename. A bare
  // '.php' concat tail is not a path (dynamic filename) — rejected.
  const suffixOf = (expr) => {
    const cm = expr.match(/([A-Z_][A-Z0-9_]*)\s*\.\s*['"]([^'"]+\.php)['"]/);
    if (cm && model.phpConstants.has(cm[1])) return model.phpConstants.get(cm[1]) + cm[2];
    const qm = expr.match(/['"]([^'"]+\.php)['"]/);
    return qm ? qm[1] : null;
  };
  const matches = (suffix) => suffix && (site.path.endsWith(suffix) || site.path.endsWith(suffix.replace(/^\//, '')) || (`/${site.path}`).endsWith(suffix));
  const refs = [];
  let dynamic = false;
  for (const fn of model.fns) {
    const assigns = new Map();
    for (const l of fn.body) {
      const am = l.match(/\$([A-Za-z_]\w*)\s*=\s*(.+);/);
      if (am) {
        const s = suffixOf(am[2]);
        if (s) assigns.set(am[1], s);
      }
    }
    for (let k = 0; k < fn.body.length; k++) {
      const l = fn.body[k];
      if (!REF_RE.test(l)) continue;
      const direct = suffixOf(l);
      const vm = l.match(/\$([A-Za-z_]\w*)/);
      const varPath = vm && assigns.get(vm[1]);
      if ((direct && matches(direct)) || (varPath && matches(varPath))) {
        refs.push({ fn, line: fn.line + k });
        break; // one referrer per function is enough for the guard question
      }
      // An include whose target we cannot resolve to a literal path is only
      // evidence against THIS template when its quoted fragments don't exclude it:
      // `require $dir . '/data/patterns/' . $lang . '.php'` renders a known-other
      // family — it says nothing about our template and must not poison orphans.
      if (!direct && /\$/.test(l) && !varPath) {
        const frags = [...l.matchAll(/['"]([^'"]+)['"]/g)].map((x) => x[1].replace(/^(\.\.\/|\.\/)+/, '')).filter((f) => f.includes('/') || f.endsWith('.php'));
        if (!frags.length || frags.some((f) => f !== '.php' && site.path.includes(f))) dynamic = true;
      }
    }
  }
  if (!refs.length) {
    if (dynamic) return { floor: null, reason: `template-level emission (${site.path.split('/').pop()}) — no static referrer and the tree contains unresolvable dynamic includes — guard unresolvable` };
    return { floor: 'ORPHAN', reason: `template ${site.path.split('/').pop()} has no in-tree render path (static, constant-prefixed and variable-path includes checked) — treated as a non-emission (dead template path); flagged, not hidden` };
  }
  let weakest = null;
  for (const r of refs.slice(0, 20)) {
    const g = fnContextGuard(model, r.fn, r.line, evidence);
    if (g.floor == null) {
      // Dead render path: the referrer itself is never called anywhere in-tree.
      // Excluded like an orphan template, with the chain kept visible.
      if (/not attached to any classified hook or menu screen/.test(g.reason) && !isCalledInTree(model, r.fn)) {
        evidence.push({ ref: `${r.fn.path}:${r.line}`, kind: 'nonce-emission-guard', note: `template rendered from ${r.fn.name}() which has NO in-tree caller — dead render path, excluded (flagged, not hidden)` });
        continue;
      }
      evidence.push({ ref: `${r.fn.path}:${r.line}`, kind: 'nonce-emission-guard', note: `template rendered from ${r.fn.name}() — guard evaluated there` });
      return { floor: null, reason: `template referrer ${r.fn.name} — ${g.reason}` };
    }
    evidence.push({ ref: `${r.fn.path}:${r.line}`, kind: 'nonce-emission-guard', note: `template rendered from ${r.fn.name}() — guard evaluated there` });
    if (!weakest || ROLE_RANK[g.floor] < ROLE_RANK[weakest]) weakest = g.floor;
  }
  if (!weakest) return { floor: 'ORPHAN', reason: `all render paths for ${site.path.split('/').pop()} are dead (no in-tree callers)` };
  return { floor: weakest, reason: `template ${site.path.split('/').pop()} rendered only from ${weakest}-gated context${refs.length === 1 ? '' : 's'}` };
}

// Is fn ever CALLED in-tree (bare name or ->method(), excluding its own body)?
// Name-based, same caveat as all resolution here.
function isCalledInTree(model, fn) {
  const callRe = new RegExp(`(?:->|::)?\\b${fn.name}\\s*\\(`);
  for (const f2 of model.fns) {
    if (f2 === fn) continue;
    for (const l of f2.body) {
      if (callRe.test(l) && !new RegExp(`function\\s+&?\\s*${fn.name}\\s*\\(`).test(l)) return true;
    }
  }
  return false;
}

// Provenance verdict for ONE nonce action.
// class: ADMIN-ONLY | EDITOR-PLUS | ROLE-GATED | ANY-AUTH | UNKNOWN (+ floor).
function nonceProvenance(model, action) {
  const sites = model.nonceEmissions.get(action) || [];
  if (!sites.length) {
    return { class: 'UNKNOWN', floor: null, evidence: [], reason: `nonce action '${action}' emission not found in-tree (created dynamically, concatenated action name, or emitted by core/another plugin)` };
  }
  const evidence = [];
  let weakest = null;
  let live = 0;
  for (const site of sites) {
    evidence.push({ ref: `${site.path}:${site.line}`, kind: 'nonce-emission', note: `nonce action '${action}' emitted here (${site.kind})${site.fn ? ` inside ${site.fn.name}()${site.fnApprox ? ' — enclosing function APPROXIMATED (mixed PHP/HTML file; brace matching unreliable)' : ''}` : ' at template top level'}` });
    const g = site.fn ? fnContextGuard(model, site.fn, site.line, evidence) : templateReferrerGuard(model, site, evidence);
    if (g.floor === 'ORPHAN') {
      evidence.push({ ref: `${site.path}:${site.line}`, kind: 'nonce-emission-guard', note: g.reason });
      continue;
    }
    live++;
    if (g.floor == null) return { class: 'UNKNOWN', floor: null, evidence, reason: g.reason };
    if (!weakest || ROLE_RANK[g.floor] < ROLE_RANK[weakest]) weakest = g.floor;
  }
  if (!live) return { class: 'UNKNOWN', floor: null, evidence, reason: `no live emission path for '${action}' in-tree (all sites are orphan templates or unrenderable)` };
  const cls = weakest === 'ADMIN' ? 'ADMIN-ONLY' : weakest === 'EDITOR' ? 'EDITOR-PLUS' : weakest === 'UNAUTH' || weakest === 'SUBSCRIBER' ? 'ANY-AUTH' : 'ROLE-GATED';
  return { class: cls, floor: weakest, evidence, reason: `${live} live emission site${live === 1 ? '' : 's'}${live < sites.length ? ` (+${sites.length - live} orphan)` : ''}, weakest guard ${weakest} → ${cls}` };
}

// Verdict integration: when the handler's effective gate set is NONCE-ONLY (no
// capability gate anywhere in the credited chain), combine with emission
// provenance. Degrades only on PROVEN role-gated provenance; UNKNOWN and ANY-AUTH
// never move the floor. Returns [floor, confidenceOverride|null].
function applyNonceProvenance(model, floor, gates, evidence, notes) {
  if (gates.some(isCapGate)) return [floor, null]; // a real role gate decides
  const nonceGates = gates.filter((g) => g.nonce);
  if (!nonceGates.length) return [floor, null];
  if (nonceGates.some((g) => !g.action && !g.actions)) {
    notes.push('nonce check with a non-literal action name — provenance unresolved (verdict unchanged, never penalized)');
    return [floor, null];
  }
  const actions = [...new Set(nonceGates.flatMap((g) => g.actions || [g.action]))];
  let weakest = null;
  for (const a of actions) {
    const p = nonceProvenance(model, a);
    for (const e of p.evidence) evidence.push(e);
    if (p.class === 'UNKNOWN') {
      notes.push(`nonce '${a}' provenance unresolved — ${p.reason} (verdict unchanged, never penalized)`);
      return [floor, null];
    }
    if (!weakest || ROLE_RANK[p.floor] < ROLE_RANK[weakest.floor]) weakest = p;
  }
  if (weakest.class === 'ANY-AUTH') {
    notes.push(`nonce '${actions[0]}' provenance ANY-AUTH — emitted where low-privilege (or unauthenticated) visitors receive it; reachability unchanged`);
    return [floor, null];
  }
  if (ROLE_RANK[weakest.floor] > ROLE_RANK[floor]) {
    notes.push(`nonce-only gate with ${weakest.class} provenance — every live emission site for '${actions.join("', '")}' is gated ${weakest.floor} or stronger, so a lower-privilege user can never obtain the nonce; floor raised to ${weakest.floor} (high confidence, evidence above)`);
    return [weakest.floor, 'high'];
  }
  return [floor, null];
}

// --- the model ------------------------------------------------------------------

// The vendor boundary for same-plugin resolution (same rule as privemap's
// pluginRoot): wp-content/(plugins|themes)/X/… descends within X; loose trees fall
// back to the handler's own directory.
function pluginRoot(p) {
  const m = String(p).replace(/\\/g, '/').match(/^(.*wp-content\/(?:plugins|themes)\/[^/]+\/)/);
  if (m) return m[1];
  const i = String(p).replace(/\\/g, '/').lastIndexOf('/');
  return i === -1 ? '' : String(p).replace(/\\/g, '/').slice(0, i + 1);
}

// records: [{ path, content }]. Pure: no fs, no network, no import-time side effects.
export function buildReachabilityModel(records) {
  const gaps = [];
  const fns = [];
  const regs = [];
  const classes = [];
  const parsed = [];
  for (const rec of Array.isArray(records) ? records : []) {
    try {
      // Normalize CRLF/CR to LF once (trunk mirrors are CRLF — line-anchored regexes
      // silently never match otherwise) and normalize path separators for prefix
      // comparisons. Refs print normalized (file:line).
      const content = String(rec && rec.content != null ? rec.content : '').replace(/\r\n?/g, '\n');
      const path = String(rec && rec.path != null ? rec.path : '?').replace(/\\/g, '/');
      if (!content.trim()) continue;
      const orig = content.split('\n');
      const san = structureLines(content);
      parsed.push({ path, orig, san });
      fns.push(...extractFunctions(path, orig, san, gaps));
      classes.push(...extractClasses(path, orig, san));
      regs.push(...extractRegistrations(path, orig, san));
    } catch (e) {
      gaps.push({ ref: String(rec && rec.path), reason: 'parse failed: ' + ((e && e.message) || e) });
    }
  }
  const cronHooks = collectCronHooks(parsed);
  const byName = new Map();
  for (const f of fns) {
    if (!byName.has(f.name)) byName.set(f.name, []);
    byName.get(f.name).push(f);
  }
  const nonceEmissions = collectNonceEmissions(parsed, fns);
  const menuPages = collectMenuPages(parsed, byName);
  const capGrants = collectCapGrants(fns);
  const phpConstants = collectPhpConstants(parsed);
  const resolve = (name, fromPath, fromRoot) => {
    const cands = byName.get(name) || [];
    return cands.find((f) => f.path === fromPath) || cands.find((f) => f.path.startsWith(fromRoot)) || null;
  };
  // Gate-credit resolver (privemap's resolveGate doctrine): a permission_callback's
  // delegate chain legitimately crosses directories inside one plugin; crediting a
  // GATE wider only ever downgrades reachability. Over-credit risk is name-collision
  // — same caveat as name-based resolution everywhere here.
  const resolveGate = (name, fromPath, fromRoot) =>
    resolve(name, fromPath, fromRoot) || (byName.get(name) || [])[0] || null;

  return {
    regs, fns, byName, classes, cronHooks, gaps, resolve, resolveGate, nonceEmissions, menuPages, capGrants, phpConstants,
    stats: { functions: fns.length, registrations: regs.length, cronHooks: cronHooks.size, classes: classes.length, nonceActions: nonceEmissions.size, menuPages: menuPages.length },
  };
}

// --- gate scanning ---------------------------------------------------------------

// A wp_verify_nonce(…, $var) whose action is a VARIABLE: resolve it when the same
// body constrains the variable to a literal set — `$v = … in_array($x, array('a',
// 'b')) ? $x : …` or `if (!in_array($v, array('a','b'))) die;`. Returns the
// candidate action list or null (never guessed).
function resolveNonceVar(lines, varName) {
  for (const bl of lines) {
    const am = bl.match(new RegExp(`\\$${varName}\\s*=\\s*(.+)`));
    if (am && /\?[\s\S]*:/.test(am[1])) {
      const im = am[1].match(/in_array\s*\([^,]+,\s*array\s*\(([^)]*)\)/) || am[1].match(/in_array\s*\([^,]+,\s*\[([^\]]*)\]/);
      if (im) {
        const acts = [...im[1].matchAll(/['"]([^'"]+)['"]/g)].map((x) => x[1]);
        if (acts.length) return acts;
      }
    }
    const cm = bl.match(new RegExp(`in_array\\s*\\(\\s*\\$${varName}\\b[^,]*,\\s*array\\s*\\(([^)]*)\\)`));
    if (cm) {
      const acts = [...cm[1].matchAll(/['"]([^'"]+)['"]/g)].map((x) => x[1]);
      if (acts.length) return acts;
    }
  }
  return null;
}

// Scan a function body (or closure text) for gates, returning evidence entries.
// `ref` is the location printed for each hit. Bounded same-tree descent (≤2 hops,
// ≤8 functions) follows $this->/bare-name/Class::method callees — a permission
// callback routinely delegates (has_permission → Helper::has_cap →
// current_user_can); the hop chain stays visible in the note.
function scanGates(model, body, ref, { fromPath = null, maxHops = 2, maxCallees = 8, startFn = null } = {}) {
  const found = [];
  const scanBody = (lines, atRef, chain) => {
    for (let k = 0; k < lines.length; k++) {
      const l = lines[k];
      for (const g of GATE_RES) {
        const m = l.match(g.re);
        if (!m) continue;
        const lineNo = atRef.line != null ? atRef.line + k : null;
        const via = chain.length ? ` (via ${chain.join(' -> ')})` : '';
        if (g.objectForm) {
          // user_can( $user, 'cap' ) — two captures: the user expression and the capability
          // literal. Credited ONLY for a requester-resolved $user (see requesterResolved).
          const varName = m[1];
          const cap = m[2];
          if (!requesterResolved(lines, varName)) continue;
          const lin = capLineage(cap);
          found.push({
            kind: 'gate', id: g.id, cap, role: lin ? lin.role : 'ADMIN', uncertain: !lin,
            ref: lineNo != null ? `${atRef.path}:${lineNo}` : atRef.ref,
            note: lin
              ? `user_can($${varName}, '${cap}') with $${varName} resolved from the request's own credentials → capability floor ${lin.role}${via}`
              : `user_can($${varName}, '${cap}') with $${varName} resolved from the request's own credentials → custom/unmapped capability, treated as ADMIN (uncertain — flagged, not trusted)${via}`,
          });
          continue;
        }
        if (g.cap && m[1]) {
          const lin = capLineage(m[1]); // stock map, then verified vendor lineage; null = unmapped
          found.push({
            kind: 'gate', id: g.id, cap: m[1],
            role: lin ? lin.role : 'ADMIN', uncertain: !lin,
            ref: lineNo != null ? `${atRef.path}:${lineNo}` : atRef.ref,
            note: lin
              ? `current_user_can('${m[1]}') → capability floor ${lin.role}${lin.via === 'stock cap→role map' ? '' : ` (${lin.via})`}${m[1] === 'unfiltered_html' ? ' (admin/super-admin on multisite)' : ''}${via}`
              : `current_user_can('${m[1]}') → custom/unmapped capability, treated as ADMIN (uncertain — flagged, not trusted)${via}`,
          });
        } else if (g.cap === false && g.id === 'current_user_can' && !g.nonce && !g.login) {
          // The no-literal variant: only record when the literal variant didn't
          // already fire on this line (a literal match consumes it).
          if (!/current_user_can\s*\(\s*['"]/.test(l)) {
            found.push({
              kind: 'gate', id: g.id, cap: null, role: 'ADMIN', uncertain: true,
              ref: lineNo != null ? `${atRef.path}:${lineNo}` : atRef.ref,
              note: `current_user_can(<dynamic expression>) → unresolvable capability, treated as ADMIN (uncertain — flagged, not trusted)${via}`,
            });
          }
        } else if (g.nonce) {
          // Capture the nonce ACTION literal where statically visible — the
          // nonce-provenance pass (below) keys its emission search on it. A
          // variable action is resolved when the body constrains it to a
          // literal set (in_array idiom); otherwise unresolvable, named.
          const am = l.match(/check_(?:ajax|admin)_referer\s*\(\s*['"]([^'"]+)['"]/)
                  || l.match(/wp_verify_nonce\s*\(\s*[^,]+?,\s*['"]([^'"]+)['"]/);
          const vm = !am && l.match(/wp_verify_nonce\s*\(\s*[^,]+?,\s*\$([A-Za-z_]\w*)\s*\)/);
          const varActs = vm ? resolveNonceVar(lines, vm[1]) : null;
          found.push({
            kind: 'gate', id: g.id, nonce: true,
            ...(am ? { action: am[1] } : varActs ? { actions: varActs } : { action: null }),
            ref: lineNo != null ? `${atRef.path}:${lineNo}` : atRef.ref,
            note: `${g.id}${am ? `('${am[1]}')` : varActs ? `($${vm[1]} — variable action constrained by in_array to {${varActs.map((a) => `'${a}'`).join(', ')}})` : '(<dynamic action>)'} — nonce required (exploit-class note: a nonce blocks drive-by unauth CSRF but is NOT a role gate; any authenticated user who can fetch a nonce still reaches this — noted, not killed)${via}`,
          });
        } else if (g.login) {
          found.push({
            kind: 'gate', id: g.id, login: true, role: 'SUBSCRIBER',
            ref: lineNo != null ? `${atRef.path}:${lineNo}` : atRef.ref,
            note: `is_user_logged_in() → authenticated-session floor (SUBSCRIBER)${via}`,
          });
        }
      }
    }
  };
  scanBody(body, startFn ? { path: startFn.path, line: startFn.line } : { ref }, []);
  if (!startFn || maxHops <= 0) return dedupeGates(found);
  // Bounded descent for gate credit only.
  const seen = new Set([startFn]);
  const queue = [{ fn: startFn, hops: 0, chain: [startFn.name] }];
  const root = pluginRoot(startFn.path);
  const STATIC_CALLEE = /\b(?!self\b|static\b)[A-Za-z_]\w*::([A-Za-z_]\w*)\s*\(/g;
  while (queue.length) {
    const { fn, hops, chain } = queue.shift();
    if (hops >= maxHops || seen.size >= maxCallees) continue;
    const names = new Set();
    for (const line of fn.san) {
      for (const mm of line.matchAll(/\$[A-Za-z_]\w*->([A-Za-z_]\w*)\s*\(/g)) names.add(mm[1]);
      for (const mm of line.matchAll(/\b(?:self|static)::([A-Za-z_]\w*)\s*\(/g)) names.add(mm[1]);
      for (const mm of line.matchAll(STATIC_CALLEE)) names.add(mm[1]);
    }
    for (const n of names) {
      const c = model.resolveGate(n, fn.path, root);
      if (c && !seen.has(c)) {
        seen.add(c);
        scanBody(c.body, { path: c.path, line: c.line }, [...chain, n]);
        queue.push({ fn: c, hops: hops + 1, chain: [...chain, n] });
      }
    }
  }
  return dedupeGates(found);
}

function dedupeGates(gates) {
  const seen = new Set();
  return gates.filter((g) => {
    const k = `${g.id}:${g.cap || ''}:${g.ref}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

// A permission_callback / gate closure text scanned flat (no descent — the closure
// is inline by definition). Same evidence shape as scanGates.
function scanClosureGates(text, ref) {
  const pseudo = { resolveGate: () => null, resolve: () => null };
  return scanGates(pseudo, String(text).split('\n'), ref, { maxHops: 0 });
}

// --- verdict machinery -----------------------------------------------------------

function verdictRecord(reg, verdict, confidence, reason, evidence, notes) {
  return {
    entry: {
      kind: reg.kind,
      hook: reg.hook,
      ...(reg.route ? { route: reg.route } : {}),
      ...(reg.ability ? { ability: reg.ability } : {}),
      ...(reg.shortcode ? { shortcode: reg.shortcode } : {}),
      handler: reg.name || (reg.closure ? '(inline closure)' : '(unresolved)'),
      registration: `${reg.path}:${reg.line}`,
    },
    verdict,
    confidence,
    reason,
    evidenceChain: evidence,
    ...(notes && notes.length ? { notes } : []),
  };
}

// Raise `floor` to `role` when role ranks higher. Returns [newFloor, raised].
function raise(floor, role) {
  return ROLE_RANK[role] > ROLE_RANK[floor] ? [role, true] : [floor, false];
}

// Analyze ONE registration → a verdict record. This is the mechanical adjudicator.
export function analyzeRegistration(model, reg) {
  const evidence = [];
  const notes = [];
  const regRef = `${reg.path}:${reg.line}`;

  // --- REST routes and Abilities: the verdict IS the permission_callback ---------
  if (reg.kind === 'rest' || reg.kind === 'ability') {
    const what = reg.kind === 'rest' ? `REST route ${reg.route || '(route unparsed)'}` : `ability ${reg.ability || '(name unparsed)'}`;
    evidence.push({ ref: regRef, kind: 'registration', note: `${what} registered here; the gate is its permission_callback` });
    const gate = gradePermissionCallback(model, reg, evidence);
    if (gate.unknown) return verdictRecord(reg, 'UNKNOWN', 'high', gate.reason, evidence, notes);
    // In-handler gates RAISE the permission floor further (a route open to
    // subscribers whose handler re-checks manage_options is admin-floor).
    let floor = gate.floor;
    let handler = null;
    if (reg.cbRef) {
      const r = resolveStatic(model, reg.cbRef);
      if (r.fn) handler = r.fn;
      else notes.push(`handler '${reg.cbRef.fqn}::${reg.cbRef.method}' — ${r.error} — verdict reflects the permission_callback gate alone`);
    } else if (reg.name) {
      handler = model.resolveGate(reg.name, reg.path, pluginRoot(reg.path));
    }
    if (handler) {
      evidence.push({ ref: `${handler.path}:${handler.line}`, kind: 'callback-def', note: `handler ${handler.name} defined here — scanned for in-handler gates (≤2-hop delegate credit)` });
      const gates = scanGates(model, handler.body, null, { startFn: handler });
      floor = applyGates(floor, gates, evidence, notes);
      const prov = applyNonceProvenance(model, floor, gates, evidence, notes);
      floor = prov[0];
      // The base-gate reason describes the permission_callback ALONE. When in-handler
      // gates raised the floor, passing it through verbatim would contradict the verdict
      // (measured: an __return_true route whose handler requires a nonce reported
      // "publicly reachable" at a SUBSCRIBER verdict — an overclaim in the filing
      // direction). Compose the reason from both steps, as the hook path does. The base
      // gate's detail stays in the evidence chain, so nothing is lost by not repeating its
      // verdict-shaped wording here. The gates that DID the raising are named, so the
      // reason never leaves the reader to guess which check produced the floor — and the
      // FORM is named too (current_user_can vs the object-form user_can).
      const raised = ROLE_RANK[floor] > ROLE_RANK[gate.floor];
      const raising = raised
        ? gates.filter((g) => isCapGate(g) || g.login || g.nonce)
          .map((g) => (isCapGate(g) ? describeCapGate(g) : g.id)).slice(0, 3)
        : [];
      return verdictRecord(reg, floor, prov[1] || gate.confidence,
        raised ? `${what} permission gate resolves to ${gate.floor}; in-handler gates RAISE the floor to ${floor}${raising.length ? ` (${raising.join(', ')})` : ''}` : gate.reason,
        evidence, notes);
    } else if (reg.name && !reg.cbRef) {
      notes.push(`handler '${reg.name}' not resolved in-tree — verdict reflects the permission_callback gate alone`);
    }
    return verdictRecord(reg, floor, gate.confidence, gate.reason, evidence, notes);
  }

  // --- shortcodes ----------------------------------------------------------------
  if (reg.kind === 'shortcode') {
    evidence.push({ ref: regRef, kind: 'registration', note: `shortcode [${reg.shortcode}] registered here — renders wherever post content renders (subscriber-authored content in stock WP reaches it; some render paths are unauth — second-order surface)` });
    let floor = 'SUBSCRIBER';
    const handler = reg.name ? model.resolve(reg.name, reg.path, pluginRoot(reg.path)) : null;
    if (handler) {
      evidence.push({ ref: `${handler.path}:${handler.line}`, kind: 'callback-def', note: `shortcode handler ${handler.name} defined here` });
      const gates = scanGates(model, handler.body, null, { startFn: handler });
      floor = applyGates(floor, gates, evidence, notes);
      return verdictRecord(reg, floor, 'medium', `shortcode render surface with gates resolved to ${floor}`, evidence, notes);
    }
    if (reg.closureText != null) {
      const gates = scanClosureGates(reg.closureText, regRef);
      floor = applyGates(floor, gates, evidence, notes);
      return verdictRecord(reg, floor, 'medium', `shortcode with an inline closure handler — gates scanned flat`, evidence, notes);
    }
    return verdictRecord(reg, 'UNKNOWN', 'high', `shortcode callback '${reg.name || '(variable)'}' not resolved in-tree (dynamic name, external file, or variable callback) — reachability unproven`, evidence, notes);
  }

  // --- action/filter hooks --------------------------------------------------------
  const cls = classifyHook(reg.hook, model.cronHooks);
  if (!cls) {
    evidence.push({ ref: regRef, kind: 'registration', note: `add_action/add_filter('${reg.hook}', …) registered here` });
    return verdictRecord(reg, 'UNKNOWN', 'high', `hook '${reg.hook}' has no mechanical remote-reachability classification (custom/internal hook — fired by do_action/apply_filters from code paths this analyzer does not trace)`, evidence, notes);
  }
  evidence.push({ ref: regRef, kind: 'registration', note: `add_action/add_filter('${reg.hook}', …) — ${cls.reason}` });
  if (cls.floor === 'SERVER' || cls.kind === 'admin-render') {
    // Never-remote surface: the floor is the verdict, no handler analysis needed.
    return verdictRecord(reg, cls.floor === 'SERVER' ? 'SERVER' : 'ADMIN', 'high', cls.reason, evidence, notes);
  }

  let floor = cls.floor;
  let confidence = cls.confidence;
  let handler = null;
  if (reg.staticRef) {
    const r = resolveStatic(model, reg.staticRef);
    if (r.error) {
      return verdictRecord(reg, 'UNKNOWN', 'high', `hook '${reg.hook}' static callback '${reg.staticRef.fqn}::${reg.staticRef.method}' — ${r.error}`, evidence, notes);
    }
    handler = r.fn;
    evidence.push({ ref: `${r.classInfo.path}:${r.classInfo.line}`, kind: 'callback-def', note: `callback class ${r.classInfo.name} defined here${r.classInfo.namespace ? ` (namespace ${r.classInfo.namespace})` : ''}${r.via || ''}` });
  } else if (reg.name) {
    handler = model.resolve(reg.name, reg.path, pluginRoot(reg.path));
  }
  if (handler) {
    evidence.push({ ref: `${handler.path}:${handler.line}`, kind: 'callback-def', note: `handler ${handler.name} defined here — scanned for gates (≤2-hop delegate credit)` });
    const gates = scanGates(model, handler.body, null, { startFn: handler });
    floor = applyGates(floor, gates, evidence, notes);
    const prov = applyNonceProvenance(model, floor, gates, evidence, notes);
    floor = prov[0];
    if (prov[1]) confidence = prov[1];
    // admin_init unauth nuance: a hop-0 handler reading request channels is reachable
    // via unauthenticated admin-ajax.php/admin-post.php loads (admin_init fires there).
    if (cls.kind === 'admin_init' && handler.body.some((l) => REQUEST_CHANNEL.test(l))) {
      notes.push('handler reads request channels at hop 0 — admin_init also fires on UNAUTHENTICATED admin-ajax.php/admin-post.php loads, so unauth reach is plausible wherever no gate blocks it; gates found are decisive, absence of gates keeps the SUBSCRIBER floor (unauth steering not statically provable)');
    }
    if (cls.kind === 'bootstrap' && !handler.body.some((l) => REQUEST_CHANNEL.test(l))) {
      notes.push(`bootstrap hook fires for every request but the handler reads no request channel at hop 0 — execution is unauthenticated; request-steering unproven (likely initialization, not attack surface)`);
    }
  } else if (reg.closureText != null) {
    const gates = scanClosureGates(reg.closureText, regRef);
    floor = applyGates(floor, gates, evidence, notes);
    const prov = applyNonceProvenance(model, floor, gates, evidence, notes);
    floor = prov[0];
    if (prov[1]) confidence = prov[1];
    notes.push('inline closure handler — gates scanned flat, no callee descent');
  } else if (reg.closure) {
    return verdictRecord(reg, 'UNKNOWN', 'high', `hook '${reg.hook}' registered with a closure callback that could not be extracted for scanning — reachability unproven`, evidence, notes);
  } else {
    return verdictRecord(reg, 'UNKNOWN', 'high', `callback '${reg.name || '(variable)'}' not found in scanned sources (dynamic name, variable callback, or definition outside the scanned tree) — reachability unproven`, evidence, notes);
  }
  const gated = evidence.some((e) => e.kind === 'gate');
  return verdictRecord(reg, floor, gated && confidence === 'medium' ? 'medium' : confidence,
    gated ? `${cls.kind} entry point; gates resolve the floor to ${floor}` : cls.reason, evidence, notes);
}

// Grade a REST/ability permission_callback → { floor, confidence, reason } or
// { unknown: true, reason }.
function gradePermissionCallback(model, reg, evidence) {
  const regRef = `${reg.path}:${reg.line}`;
  const what = reg.kind === 'rest' ? 'route' : 'ability';
  const pc = reg.permissionCallback;
  if (pc === '__return_true') {
    evidence.push({ ref: regRef, kind: 'permission-callback', note: `permission_callback = '__return_true' — the gate passes EVERY caller including unauthenticated` });
    return { floor: 'UNAUTH', confidence: 'high', reason: `${what} gate is __return_true — publicly reachable` };
  }
  if (pc === '__return_false') {
    return { unknown: true, reason: `permission_callback is __return_false — the ${what} denies every caller (dead surface; reported UNKNOWN rather than killed because a filter could still override it)` };
  }
  if (pc === 'is_user_logged_in') {
    evidence.push({ ref: regRef, kind: 'permission-callback', note: `permission_callback = 'is_user_logged_in' — any authenticated role passes` });
    return { floor: 'SUBSCRIBER', confidence: 'high', reason: `${what} gate is is_user_logged_in — any authenticated role` };
  }
  if (pc) {
    // Named or static-method callback: resolve cross-file and scan its body (with
    // delegate descent). A present-but-unresolvable gate is UNKNOWN — NEVER the
    // absent/public doctrine.
    let fn = null;
    if (reg.pcRef) {
      const r = resolveStatic(model, reg.pcRef);
      if (r.error) return { unknown: true, reason: `permission_callback '${pc}' — ${r.error}` };
      fn = r.fn;
      evidence.push({ ref: `${r.classInfo.path}:${r.classInfo.line}`, kind: 'permission-callback', note: `permission_callback '${pc}' — class ${r.classInfo.name} defined here${r.classInfo.namespace ? ` (namespace ${r.classInfo.namespace})` : ''}${r.via || ''}` });
    } else {
      fn = model.resolveGate(pc, reg.path, pluginRoot(reg.path));
      if (!fn) {
        return { unknown: true, reason: `permission_callback '${pc}' not found in scanned sources (core/WP function, dynamic name, or definition outside the tree) — gate ungraded` };
      }
    }
    evidence.push({ ref: `${fn.path}:${fn.line}`, kind: 'permission-callback', note: `permission_callback '${pc}' defined here — body scanned (≤2-hop delegate credit)` });
    const gates = scanGates(model, fn.body, null, { startFn: fn });
    for (const g of gates) evidence.push(g);
    const capGates = gates.filter(isCapGate);
    const loginGates = gates.filter((g) => g.login);
    if (capGates.length) {
      const floor = strongestFloor(capGates);
      return { floor, confidence: capGates.some((g) => g.uncertain) ? 'medium' : 'high', reason: `${what} permission_callback enforces ${floor} (${capGates.map(describeCapGate).join(', ')})` };
    }
    if (loginGates.length) {
      return { floor: 'SUBSCRIBER', confidence: 'high', reason: `${what} permission_callback checks is_user_logged_in — any authenticated role` };
    }
    if (gates.some((g) => g.nonce)) {
      return { floor: 'SUBSCRIBER', confidence: 'medium', reason: `${what} permission_callback checks only a nonce — no role gate; reachable by any authenticated role that can fetch the nonce (unauth reach depends on nonce exposure — flagged, not proven)` };
    }
    return { unknown: true, reason: `permission_callback '${pc}' resolved to ${fn.path}:${fn.line} but contains no recognizable gate (current_user_can / is_user_logged_in / nonce) — custom authz logic, ungraded` };
  }
  if (reg.pcClosureText != null) {
    const text = reg.pcClosureText.trim();
    evidence.push({ ref: regRef, kind: 'permission-callback', note: `permission_callback is an inline closure — body scanned flat` });
    if (/^(?:return\s+true\s*;|true\b)/.test(text)) {
      evidence.push({ ref: regRef, kind: 'permission-callback', note: `closure body returns true unconditionally — open gate` });
      return { floor: 'UNAUTH', confidence: 'high', reason: `${what} permission_callback closure returns true — publicly reachable` };
    }
    const gates = scanClosureGates(text, regRef);
    for (const g of gates) evidence.push(g);
    const capGates = gates.filter(isCapGate);
    if (capGates.length) {
      const floor = strongestFloor(capGates);
      return { floor, confidence: capGates.some((g) => g.uncertain) ? 'medium' : 'high', reason: `${what} permission_callback closure enforces ${floor} (${capGates.map(describeCapGate).join(', ')})` };
    }
    const loginGates = gates.filter((g) => g.login);
    if (loginGates.length) return { floor: 'SUBSCRIBER', confidence: 'high', reason: `${what} permission_callback closure checks is_user_logged_in — any authenticated role` };
    return { unknown: true, reason: `permission_callback closure at ${regRef} contains no recognizable gate (current_user_can / is_user_logged_in) — inline gate ungraded, never guessed` };
  }
  // Present-but-unparseable (expression, constant, call, or an unrecognized string
  // form): the gate EXISTS, we just cannot read it. UNCERTAIN — never the absent/
  // public doctrine; a present-but-unreadable gate must never grade as public.
  if (reg.pcUnparseable) {
    return { unknown: true, reason: `permission_callback is present at ${regRef} but its value is not a resolvable callable literal (expression, constant, or call) — gate ungraded; NEVER treated as public` };
  }
  // Absent: a _doing_it_wrong notice since WP 5.5 — the route registers PUBLIC in
  // practice. Proven-unauth would overclaim the runtime; UNAUTH at medium confidence
  // with the semantics named.
  evidence.push({ ref: regRef, kind: 'permission-callback', note: `permission_callback ABSENT — a _doing_it_wrong notice since WP 5.5; a route/ability registered without a gate is publicly reachable in practice` });
  return { floor: 'UNAUTH', confidence: 'medium', reason: `${what} has no permission_callback — public in practice (WP 5.5+ _doing_it_wrong, gate absent)` };
}

// The decisive floor among current_user_can gates: the STRONGEST cap found. The
// common idiom is a single early-exit guard; with multiple distinct caps an OR-chain
// would make the weaker one sufficient — flagged in confidence, never silently.
function strongestFloor(capGates) {
  let floor = 'SUBSCRIBER';
  for (const g of capGates) floor = ROLE_RANK[g.role] > ROLE_RANK[floor] ? g.role : floor;
  return floor;
}

// Apply handler-body gates to a base floor. Returns the raised floor; appends gate
// evidence and nonce notes.
function applyGates(floor, gates, evidence, notes) {
  for (const g of gates) evidence.push(g);
  const capGates = gates.filter(isCapGate);
  if (capGates.length) {
    const strong = strongestFloor(capGates);
    floor = ROLE_RANK[strong] > ROLE_RANK[floor] ? strong : floor;
    const distinct = new Set(capGates.map((g) => g.cap));
    if (distinct.size > 1) notes.push(`multiple distinct capabilities checked (${[...distinct].join(', ')}) — floor set to the STRONGEST; an OR-chained check would make the weaker sufficient (line heuristics cannot separate && from || — flagged)`);
  }
  if (gates.some((g) => g.login)) floor = ROLE_RANK.SUBSCRIBER > ROLE_RANK[floor] ? 'SUBSCRIBER' : floor;
  // privemap doctrine: an unauth-floor handler with a nonce check and no capability
  // gate reads as subscriber-floor (the nonce blocks drive-by unauth CSRF; any
  // authenticated role that can fetch the nonce still reaches it).
  if (floor === 'UNAUTH' && gates.some((g) => g.nonce) && !capGates.length) {
    floor = 'SUBSCRIBER';
    notes.push('nonce check with no capability gate — floor raised UNAUTH→SUBSCRIBER (unauth reach would need a nonce exposed to visitors — flagged, not killed)');
  }
  return floor;
}

// --- entry-point lookup + full analysis -------------------------------------------

// Find the registration an --entry spec points at: a 'file:line' ref, or a hook name
// (exact hook match; rest routes match on 'rest_route' or the route string; abilities
// on the ability name).
export function findEntries(model, spec) {
  const s = String(spec || '').trim();
  // file:line form (path separators or a .php suffix disambiguate from a hook name —
  // ability names contain '/', so a trailing :<digits> alone is required too).
  const fl = s.match(/^(.*):(\d+)$/);
  if (fl && (/[/\\]/.test(fl[1]) || /\.php$/i.test(fl[1]))) {
    const file = fl[1].replace(/\\/g, '/');
    const line = Number(fl[2]);
    return model.regs.filter((r) => r.path === file && r.line === line)
      .concat(model.regs.filter((r) => r.path.endsWith(file) && r.line === line && r.path !== file));
  }
  return model.regs.filter((r) =>
    r.hook === s || r.route === s || r.ability === s || r.shortcode === s ||
    (s.startsWith('wp_ajax') && r.hook === s));
}

// Analyze every registration in the tree (deduped by ref — one verdict per
// registration site).
export function analyzeAll(model) {
  return model.regs.map((reg) => analyzeRegistration(model, reg));
}

// --- rescore mode ---------------------------------------------------------------

// privemap reachability vocabulary → proven-verdict rank (null = no claim).
const CLAIMED = { unauth: 'UNAUTH', subscriber: 'SUBSCRIBER', shortcode: 'SUBSCRIBER', 'admin-gated': 'ADMIN', unknown: null };
// Score weights for the penalty: proven-reach weight over claimed-reach weight.
const PROVEN_W = { UNAUTH: 1.0, SUBSCRIBER: 0.55, CONTRIBUTOR: 0.45, AUTHOR: 0.4, EDITOR: 0.3, ADMIN: 0.25 };
const CLAIMED_W = { unauth: 1.0, subscriber: 0.55, shortcode: 0.5, 'admin-gated': 0.25, unknown: 0.15 };
const KILLED_PENALTY = 0.05; // never-remote surface: score decays to noise, re-ranked honestly

// Locate the registration a privemap candidate was mined from. Match on hook +
// handler (ability candidates match on ability name); the candidate's ref file is a
// tiebreak. Returns null with the reason when nothing matches — UNCERTAIN, never
// a guessed registration.
export function locateRegistration(model, cand) {
  const hook = cand && cand.hook;
  const handler = cand && cand.handler;
  const refFile = cand && cand.ref ? String(cand.ref).replace(/\\/g, '/').replace(/:\d+$/, '') : null;
  let pool = model.regs;
  if (hook) pool = pool.filter((r) => r.hook === hook);
  if (!pool.length) return { reg: null, reason: `no registration with hook '${hook}' in the scanned tree (dynamic hook name or the registration lives outside srcDir)` };
  let m = pool.filter((r) => (handler && (r.name === handler || r.ability === handler)) || (cand.ability && r.ability === cand.ability) || (cand.route && r.route === cand.route));
  if (!m.length && refFile) {
    // The miner's candidate file is the SINK file for descended chains, not the
    // registration — try the registration whose own file matches too.
    m = pool.filter((r) => r.path === refFile || r.path.endsWith(refFile));
  }
  if (!m.length && handler && handler !== '(unresolved executor)') {
    // Dynamic-hook fallback: privemap registers prefixed actions under the literal
    // name it saw; match the handler across ALL hooks and name it honestly.
    m = model.regs.filter((r) => r.name === handler || r.ability === handler);
    if (m.length) return { reg: preferFile(m, refFile), fuzz: `hook '${hook}' not matched — handler '${handler}' located under hook '${preferFile(m, refFile).hook}' (dynamic/prefixed hook name likely)` };
  }
  if (!m.length) return { reg: null, reason: `registration for handler '${handler}' on hook '${hook}' not located (closure executor, dynamic name, or file outside the scanned tree)` };
  return { reg: preferFile(m, refFile) };
}

function preferFile(regs, refFile) {
  if (refFile) {
    const exact = regs.find((r) => r.path === refFile || r.path.endsWith(refFile));
    if (exact) return exact;
  }
  return regs[0];
}

// A non-CONFIRMED verdict SUPERSEDES privemap's reach claim, and a report's headline is
// `label || title` (tools/bountyreport.mjs), so a title that still opens with
// "unauthenticated option overwrite" over a SUBSCRIBER verdict keeps asserting exactly the
// reach the adjudicator just refuted — the fabricated-UNAUTH direction that gets a filing
// rejected (Wordfence: 4 AI-hallucinated reports = permanent ban). The claim is retained
// verbatim AFTER the marker, so nothing is lost and substring matching still works.
function adjudicatedTitle(cand, verdict, provenReach) {
  if (verdict === 'CONFIRMED') return cand.title;
  return `[${verdict}: proven reach ${provenReach}, privemap claimed '${cand.reachability ?? 'unknown'}'] ${cand.title}`;
}

// Rescore one privemap report against the model. candidates: privemap JSON's
// candidates array. Returns per-candidate verdicts + a re-ranked honest top list.
export function rescoreCandidates(model, candidates) {
  const results = [];
  for (const cand of Array.isArray(candidates) ? candidates : []) {
    const base = {
      rank: cand.rank, title: cand.title, ref: cand.ref, hook: cand.hook, handler: cand.handler,
      privemapReach: cand.reachability, privemapScore: cand.score,
    };
    const loc = locateRegistration(model, cand);
    if (!loc.reg) {
      // Unlocatable registration: reach is unproven — the lane classifies the finding
      // at UNKNOWN reach (never dropped), riskLevel is the raw band (no reach step).
      results.push({ ...base, title: adjudicatedTitle(cand, 'UNCERTAIN', 'UNKNOWN'), provenReach: 'UNKNOWN', verdict: 'UNCERTAIN', reason: loc.reason, evidenceChain: [], newScore: cand.score,
        riskLevel: riskLevelForScore(cand.score, 'UNKNOWN'),
        lane: classifyLane({ reach: 'UNKNOWN', impactClass: cand.impactClass, vulnClass: cand.vulnClass, installs: cand.installs, degraded: cand.degraded, cvss: cand.cvss }) });
      continue;
    }
    const proven = analyzeRegistration(model, loc.reg);
    const provenRank = ROLE_RANK[proven.verdict];
    const claimedRank = cand.reachability === 'unknown' ? null : ROLE_RANK[CLAIMED[cand.reachability]];
    let verdict;
    let reason;
    let newScore = cand.score;
    if (proven.verdict === 'UNKNOWN') {
      verdict = 'UNCERTAIN';
      reason = proven.reason;
    } else if (proven.verdict === 'SERVER') {
      verdict = 'KILLED'; // cron-scheduled: never remote — high confidence by construction
      reason = proven.reason;
      newScore = Math.round(cand.score * KILLED_PENALTY * 100) / 100;
    } else if (proven.entry.kind === 'hook' && ADMIN_RENDER_HOOKS.has(proven.entry.hook)) {
      verdict = 'KILLED'; // admin render-side: never a remote input channel
      reason = proven.reason;
      newScore = Math.round(cand.score * KILLED_PENALTY * 100) / 100;
    } else if (claimedRank == null) {
      verdict = 'CONFIRMED'; // privemap had no reach claim; reachprove supplies one
      reason = `privemap reachability was 'unknown' — reachprove proves ${proven.verdict}: ${proven.reason}`;
    } else if (provenRank > claimedRank) {
      verdict = 'DEGRADED';
      reason = `privemap claimed ${cand.reachability} but gates prove ${proven.verdict}: ${proven.reason}`;
      const ratio = PROVEN_W[proven.verdict] / (CLAIMED_W[cand.reachability] || CLAIMED_W.unknown);
      newScore = Math.round(cand.score * Math.min(1, ratio) * 100) / 100;
    } else {
      verdict = 'CONFIRMED';
      reason = provenRank < claimedRank
        ? `reachprove proves ${proven.verdict} — MORE reachable than privemap's '${cand.reachability}' claim: ${proven.reason}`
        : `reachprove confirms ${proven.verdict}: ${proven.reason}`;
    }
    results.push({
      ...base,
      title: adjudicatedTitle(cand, verdict, proven.verdict),
      provenReach: proven.verdict,
      provenConfidence: proven.confidence,
      verdict,
      reason,
      ...(loc.fuzz ? { locateNote: loc.fuzz } : {}),
      evidenceChain: proven.evidenceChain,
      ...(proven.notes ? { notes: proven.notes } : []),
      newScore,
      // riskLevel band mapping (penalized-score bands, stepped down for contributor+
      // PROVEN reach): documented at engine/severity.mjs riskLevelForScore. The lane
      // re-classifies on the PROVEN reach, not privemap's claim (engine/lanes.mjs).
      riskLevel: riskLevelForScore(newScore, proven.verdict),
      lane: classifyLane({ reach: proven.verdict, impactClass: cand.impactClass, vulnClass: cand.vulnClass, installs: cand.installs, degraded: cand.degraded, cvss: cand.cvss }),
    });
  }
  // Re-rank on the penalized score — the honest top-N.
  const reranked = [...results].sort((a, b) => b.newScore - a.newScore);
  reranked.forEach((r, i) => { r.newRank = i + 1; });
  const summary = { CONFIRMED: 0, DEGRADED: 0, KILLED: 0, UNCERTAIN: 0 };
  for (const r of results) summary[r.verdict]++;
  return { results: reranked, summary };
}
