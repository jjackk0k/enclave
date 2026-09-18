// VARVEL — commitwatch ENGINE: the security-relevance classifier at the heart of the
// commit-diff watcher (research/SOTA-VULN-DISCOVERY-2026-08-25.md §6 item 3, the
// Big-Sleep method: a commit ADDING a nonce/capability/sanitization check reveals
// (a) the vuln class, (b) that every version shipped before it carries the bug,
// (c) the sibling code paths the fix probably missed — first-to-file beats n-day).
//
// PURE MODULE: no fs, no network, no import-time side effects — the tools wrapper
// (tools/commitwatch.mjs) feeds it recorded/fetched changeset text. It imports NOTHING
// from privemap/variantsweep: the suggested-seed vocabulary (class ids like
// 'option-overwrite') is carried as STRINGS for the operator to feed those tools by
// hand — the watcher NEVER hunts. test/commitwatch.test.mjs pins this statically.
//
// THE DOCTRINE LINE (carried on every lead):
//   "a fix commit is a map to a bug class, not a finding — leads are review-only;
//    nothing is hunted, probed, or filed from here."
//
// THE SIGNAL MODEL (v1, documented and honest):
//   Signals are line-level regexes over a unified diff's ADDED (+) and REMOVED (-)
//   lines. A check APPEARING in + lines means the old code lacked it; a check
//   DISAPPEARING in - lines means the new code lost it (a regression — the strongest
//   signal there is). Scores are additive per changed file, then bucketed:
//     nonce/capability check REMOVED      70  — a gate just came off a live path
//     nonce/capability check ADDED        60  — a missing-authz/CSRF fix; pre-fix = vuln
//     $wpdb->prepare ADDED                30  — a SQLi fix signal
//     sanitize_*/esc_*/absint ADDED       25  — an injection/XSS fix signal
//     sink context in the hunk           +15  — update_option/eval/file ops/query nearby
//     nopriv/public route context        +10  — wp_ajax_nopriv_/register_rest_route in file
//   BANDS: score >= 60 high | 25–59 medium | 1–24 low | 0 noise (NOT a lead — counted).
//   Pinned by fixtures: nonce-added = high, cap-tightened = high, prepare-added = med,
//   typo-only = noise floor. Weights are a tuning table: the classifier never claims a
//   vulnerability — it ranks diffs for OPERATOR review, and says so on every lead.

// --- THE SIGNAL TABLE (the tuning surface — change THIS, not the engine) ----------------
// Each: id, score, re (tested against one diff line), side ('+' added | '-' removed),
// label (operator-facing). Order in this table is the classesHit order in leads.
export const SIGNALS = [
  { id: 'nonce-check-removed', score: 70, side: '-', label: 'a nonce check was REMOVED — a CSRF gate just came off a live path',
    re: /(?<![\w])(wp_verify_nonce|check_admin_referer|check_ajax_referer)\s*\(/ },
  { id: 'capability-check-removed', score: 70, side: '-', label: 'a capability check was REMOVED — an authz gate just came off a live path',
    re: /(?<![\w])(current_user_can|current_user_can_for_blog)\s*\(/ },
  { id: 'nonce-check-added', score: 60, side: '+', label: 'a nonce check was ADDED — the pre-fix shape is a missing-CSRF handler',
    re: /(?<![\w])(wp_verify_nonce|check_admin_referer|check_ajax_referer)\s*\(/ },
  { id: 'capability-check-added', score: 60, side: '+', label: 'a capability check was ADDED/tightened — the pre-fix shape is missing authorization',
    re: /(?<![\w])(current_user_can|current_user_can_for_blog)\s*\(/ },
  { id: 'prepare-added', score: 30, side: '+', label: '$wpdb->prepare was ADDED — the pre-fix shape is an unprepared query (SQLi class)',
    re: /->prepare\s*\(/ },
  { id: 'sanitization-added', score: 25, side: '+', label: 'sanitization/escaping was ADDED — the pre-fix shape passed raw input (injection/XSS class)',
    re: /(?<![\w])(sanitize_[a-z_]+|esc_(?:attr|html|url|js|textarea|sql)\b|absint)\s*\(/ },
];
// Context signals (any line side, scored once per file when present anywhere in its hunks):
export const CONTEXT_SIGNALS = [
  { id: 'sink-context', score: 15, label: 'the hunk touches a sink (option write / file op / eval / raw query / account op) — the check guards a real primitive',
    re: /(?<![\w])(update_option|add_option|delete_option|unlink|rmdir|file_put_contents|move_uploaded_file|fwrite|eval|wp_insert_user|wp_update_user|wp_set_password|wp_delete_user)\s*\(|->(?:query|get_results|get_var|get_row|get_col)\s*\(/ },
  { id: 'nopriv-context', score: 10, label: 'the file exposes a public route (wp_ajax_nopriv_/register_rest_route) — the pre-fix hole was reachable unauthenticated',
    re: /wp_ajax_nopriv_|register_rest_route\s*\(/ },
];
// permission_callback tightening is a capability-class signal with a different shape: a
// REMOVED __return_true/open-closure callback is the fix's "before" picture.
const OPEN_CALLBACK_REMOVED = /['"]permission_callback['"]\s*=>\s*(?:['"]__return_true['"]|function\s*\([^)]*\)\s*\{\s*return\s+true)/;

export const BANDS = [
  { id: 'high', min: 60 },
  { id: 'medium', min: 25 },
  { id: 'low', min: 1 },
  { id: 'noise', min: 0 }, // 0 = not a lead: counted, never emitted
];

// The vuln-class vocabulary a lead NAMES (maps signal classes -> the pre-fix bug shape).
// Values are variantsweep/privemap sink-class ids AS STRINGS (the operator feeds them by
// hand — this module never runs those tools).
export const CLASS_MAP = {
  'nonce-check-added': { bugClass: 'missing CSRF/nonce check', seedClass: 'option-overwrite' },
  'capability-check-added': { bugClass: 'missing authorization/capability check', seedClass: 'option-overwrite' },
  'nonce-check-removed': { bugClass: 'CSRF regression (gate removed)', seedClass: 'option-overwrite' },
  'capability-check-removed': { bugClass: 'authorization regression (gate removed)', seedClass: 'option-overwrite' },
  'prepare-added': { bugClass: 'SQL injection (unprepared query)', seedClass: 'sqli' },
  'sanitization-added': { bugClass: 'injection/XSS (unsanitized input)', seedClass: 'sqli' },
};

// --- THE DIFF PARSER ----------------------------------------------------------------------
// parseChangesetDiff(text) -> [{ file, added: [lines], removed: [lines], context: [lines] }]
// Tolerates the shapes wp.org serves: Trac changeset downloads (Index: <path> + ---/+++
// headers) and git-style diffs (diff --git a/x b/y). Hunk bodies are collected under the
// CURRENT file; only .php files carry classifier weight (the caller filters — the parser
// stays format-pure). Garbage in -> empty list out, never a throw.
export function parseChangesetDiff(text) {
  const files = [];
  if (typeof text !== 'string' || !text) return files;
  let cur = null;
  const push = (name) => {
    if (!name) return;
    cur = { file: String(name).replace(/^b\//, ''), added: [], removed: [], context: [] };
    files.push(cur);
  };
  for (const raw of text.split('\n')) {
    const line = raw.endsWith('\r') ? raw.slice(0, -1) : raw;
    let m;
    if ((m = line.match(/^Index:\s+(.+)$/))) { push(m[1].trim()); continue; }
    if ((m = line.match(/^diff --git a\/(.+?) b\/(.+)$/))) { push(m[2].trim()); continue; }
    if ((m = line.match(/^\+\+\+\s+(?:b\/)?(\S+)/))) {
      if (!cur) push(m[1]); // a header with no Index:/diff line — still a file
      else if (cur.file === '(unknown)') cur.file = m[1];
      continue;
    }
    if (!cur) continue;
    if (/^---\s/.test(line) || /^@@/.test(line) || /^\\/.test(line)) continue;
    if (line.startsWith('+')) { cur.added.push(line.slice(1)); continue; }
    if (line.startsWith('-')) { cur.removed.push(line.slice(1)); continue; }
    if (line.startsWith(' ')) cur.context.push(line.slice(1));
  }
  return files.filter((f) => f.file && f.file !== '/dev/null' && (f.added.length || f.removed.length || f.context.length));
}

// --- THE CLASSIFIER ------------------------------------------------------------------------
// classifyFileDiff(fileDiff) -> { score, band, hits: [{id, score, label, lines}], contexts }
// Each signal scores AT MOST once per file (evidence lines capped at 3, quoted verbatim —
// the operator judges from the actual code, never from our paraphrase).
export function classifyFileDiff(fileDiff) {
  const hits = [];
  let score = 0;
  for (const sig of SIGNALS) {
    const pool = sig.side === '+' ? fileDiff.added : fileDiff.removed;
    const lines = pool.filter((l) => { sig.re.lastIndex = 0; return sig.re.test(l); }).slice(0, 3);
    if (lines.length) { hits.push({ id: sig.id, score: sig.score, label: sig.label, lines }); score += sig.score; }
  }
  // permission_callback tightening: an open callback in the REMOVED lines with the route
  // still present = the fix closed a public callback. Same band as capability-check-added,
  // folded in as a hit (never double-counted: the check itself may also appear).
  const openRemoved = fileDiff.removed.filter((l) => OPEN_CALLBACK_REMOVED.test(l)).slice(0, 3);
  if (openRemoved.length && !hits.some((h) => h.id === 'capability-check-added')) {
    hits.push({ id: 'capability-check-added', score: 60, label: "an OPEN permission_callback ('__return_true') was removed — the route was public before this fix", lines: openRemoved });
    score += 60;
  }
  const contexts = [];
  const all = [...fileDiff.added, ...fileDiff.removed, ...fileDiff.context];
  for (const cs of CONTEXT_SIGNALS) {
    const lines = all.filter((l) => { cs.re.lastIndex = 0; return cs.re.test(l); }).slice(0, 2);
    if (lines.length) { contexts.push({ id: cs.id, score: cs.score, label: cs.label, lines }); score += cs.score; }
  }
  return { score, band: bandOf(score), hits, contexts };
}

export function bandOf(score) {
  for (const b of BANDS) if (score >= b.min) return b.id;
  return 'noise';
}

// --- THE LEAD BUILDER ----------------------------------------------------------------------
// buildLead({ slug, revision, message, fileDiffs, at }) — one changeset -> a lead or null
// (noise floor). A lead is a REVIEW artifact: the classes hit, the human why-interesting,
// and a suggested-seed the operator may feed variantsweep/privemap BY HAND. The affected
// range is stated as what we KNOW: every tag cut from trunk before this revision carries
// the pre-fix shape (tags are immutable snapshots) — never a fabricated version list.
export function buildLead({ slug, revision, message, fileDiffs, at }) {
  const scored = [];
  for (const fd of Array.isArray(fileDiffs) ? fileDiffs : []) {
    if (!fd || typeof fd.file !== 'string') continue;
    if (!/\.php$/i.test(fd.file)) continue; // readme/txt/js churn carries no classifier weight in v1
    const c = classifyFileDiff(fd);
    if (c.score > 0) scored.push({ file: fd.file, ...c });
  }
  const total = scored.reduce((a, f) => a + f.score, 0);
  const band = bandOf(total);
  // The lead floor: only medium/high become leads. Low (a bare sink touch, score < 25)
  // and noise (0) are counted by the caller, never emitted — churn is not a lead.
  if (band === 'noise' || band === 'low') return null;
  const classesHit = [];
  for (const f of scored) for (const h of f.hits) if (!classesHit.includes(h.id)) classesHit.push(h.id);
  const primary = classesHit[0];
  const mapped = CLASS_MAP[primary] || null;
  const files = scored.map((f) => f.file);
  const removed = /-removed$/.test(primary);
  const unauth = scored.some((f) => f.contexts.some((c) => c.id === 'nopriv-context'));
  const why = [
    `r${revision} ${removed ? 'REMOVES' : 'adds'} a ${mapped ? mapped.bugClass : primary} signal in ${files.length} PHP file(s) (${files.slice(0, 3).join(', ')}${files.length > 3 ? ` +${files.length - 3} more` : ''})`,
    `every tag shipped before r${revision} carries the ${removed ? 'fixed' : 'pre-fix'} shape — the affected range is real but UNENUMERATED here (operator step: list plugins.svn.wordpress.org/${slug}/tags/)`,
    unauth ? 'the file exposes a PUBLIC route — the pre-fix hole was reachable without authentication' : null,
    'the sibling-hunt question: what other handlers in this file/directory still lack the check that was just added?',
  ].filter(Boolean).join(' — ');
  return {
    at: at || null,
    slug,
    revision: Number(revision),
    message: typeof message === 'string' ? message.slice(0, 300) : '',
    band,
    score: total,
    files: scored.map((f) => ({ file: f.file, score: f.score, band: f.band, hits: f.hits, contexts: f.contexts })),
    classesHit,
    why,
    suggestedSeed: mapped ? {
      tool: 'variantsweep', // fed BY HAND: node tools/cli.mjs variantsweep <corpus> --sig '<json>'
      kind: 'class',
      class: mapped.seedClass,
      anchors: { mitigationFree: true }, // the pre-fix shape = the sink WITHOUT its gate
      basis: `the fix at r${revision} names the class ('${mapped.bugClass}'); the sibling sweep looks for the same sink shape missing the check — operator review first, the watcher NEVER hunts`,
    } : null,
  };
}

// rankLeads(leads) — documented order: high band first, then score desc, then newest
// revision first (a same-band tiebreak: fresher fix = fewer filings on it yet).
export function rankLeads(leads) {
  const order = { high: 0, medium: 1, low: 2 };
  return (Array.isArray(leads) ? leads : []).slice()
    .sort((a, b) => (order[a.band] ?? 3) - (order[b.band] ?? 3) || b.score - a.score || b.revision - a.revision || String(a.slug).localeCompare(String(b.slug)));
}
