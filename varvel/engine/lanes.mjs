// VARVEL — lanes: bounty-program lane classification for hunting findings.
//
// PROVENANCE: the week of 2026-08-27 the hunting engine (privemap/reachprove/
// commitwatch) produced 5 verified WordPress plugin vulnerabilities, 2 of them
// submitted to bug bounty programs. Lane triage was hand-done against the live
// program rules; this module encodes those VERIFIED rules as data so every future
// finding knows its lane at emission time. The tables below are the Wordfence and
// Patchstack (standard / mVDP) rules as verified against the live programs this
// week — do NOT re-derive them from memory; update the tables when a program
// republishes its scope.
//
// CLASSIFY, NEVER FILTER: every finding gets a lane object with human-readable
// reasons naming each rule that passed or failed. A finding that fails every lane
// is still classified and emitted with the why — nothing is silently dropped.
//
// ZERO-DEP + PURE (house rule): no fs, no network, no import-time side effects.

// --- the verified rule tables ---------------------------------------------------

// Wordfence: minimum active-install floor. Installs are not knowable from a source
// tree — unknown installs count as INELIGIBLE (noted, never assumed).
export const WORDFENCE_MIN_INSTALLS = 50000;

// Wordfence: vulnerability classes the program does NOT accept (any auth level).
export const WORDFENCE_EXCLUDED_CLASSES = new Set([
  'ssrf', 'dos', 'cors', 'open-redirect', 'api-key-update', 'clickjacking', 'username-enumeration',
]);

// Wordfence: proposed CVSS floor, applied only when a CVSS is actually computable
// (the static rank score is NOT a CVSS score — pocdoc doctrine).
export const WORDFENCE_MIN_CVSS = 4.0;

// Patchstack: accepted classes for the standard lane (auth reach unauthenticated /
// subscriber / customer). Verified list: SQLi, arbitrary file upload/deletion/
// download, RCE, PHP object injection, arbitrary settings change, privesc to
// contributor+, LFI/RFI, broken access control with sensitive objects, IDOR with
// significant impact, CSRF chained to a write, sitewide stored XSS, reflected XSS
// with JS execution, whole-site DoS.
export const PATCHSTACK_ACCEPTED_CLASSES = new Set([
  'sqli', 'arbitrary-file-upload', 'arbitrary-file-deletion', 'arbitrary-file-download',
  'rce', 'php-object-injection', 'arbitrary-settings-change', 'privesc-to-contributor',
  'lfi-rfi', 'broken-access-control', 'idor', 'csrf-chained-to-write',
  'sitewide-stored-xss', 'reflected-xss-with-js', 'whole-site-dos',
]);

// Patchstack: contributor-level reach files ONLY through the mVDP lane, and only
// for broken-access-control / IDOR classes (measurable impact). Everything else at
// contributor reach is 'none' (direct vendor disclosure territory).
export const PATCHSTACK_MVDP_CONTRIBUTOR_CLASSES = new Set(['broken-access-control', 'idor']);

// Patchstack: program-wide OUT classes (June 2026 §4.x, verified after the GiveWP
// rejection 2026-08-27). These fire at ANY auth level, mVDP included.
export const PATCHSTACK_DEAD_CLASSES = new Set([
  'cronjob-manipulation', 'scheduled-task', 'cache-clear', 'data-reorder', 'notice-dismissal',
  'open-redirect', 'full-path-disclosure', 'username-enumeration', 'rate-limit-absence',
  'captcha-bypass', 'ip-spoofing', '2fa-bypass', 'blind-ssrf', 'csv-injection',
  'css-injection', 'clickjacking', 'draft-post-disclosure', 'ai-token-exhaustion',
]);

// privemap impact-class id → program vulnerability-class token. Deliberately a
// small, honest map: a finding whose true class the map does not know resolves to
// 'unknown' and the lane reasons say so — re-classify with an explicit vulnClass
// when downstream triage knows better (e.g. an api-key-update finding).
export const IMPACT_TO_CLASS = {
  'option-overwrite': 'arbitrary-settings-change',
  'account-control': 'privesc-to-contributor',
  'file-delete': 'arbitrary-file-deletion',
  'cmd-spawn': 'rce',
  'file-write': 'arbitrary-file-upload',
  lfi: 'lfi-rfi',
  sqli: 'sqli',
  'token-compare': 'broken-access-control',
  'bearer-intake': 'broken-access-control',
  'meta-write': 'privesc-to-contributor', // usermeta holds wp_capabilities — privesc ladder rung
  'ai-endpoint': 'broken-access-control',
  'mcp-public-ability': 'broken-access-control',
  'ability-weak-gate': 'broken-access-control',
  'second-order-injection': 'second-order-xss',
};

// Sink classes with CONSEQUENTIAL CIA impact (the Wordfence impact rule). The
// exposure/gate classes (ai-endpoint, ability-weak-gate, second-order-injection)
// are missing-authz/exposure findings: they count ONLY when a paired sink finding
// is consequential, so they are not in this set. mcp-public-ability IS here: a
// public ability behind an open gate is directly executable with caller-controlled
// input — the exposure itself is the consequential primitive. Any class in this
// set stops counting the moment the miner degrades it (fixed-value / self-only
// writes, FIXED_WRITE_FACTOR 0.3 — bounded primitives, generally not consequential).
export const CONSEQUENTIAL_CLASSES = new Set([
  'option-overwrite', 'account-control', 'file-delete', 'cmd-spawn', 'file-write',
  'lfi', 'sqli', 'meta-write', 'token-compare', 'bearer-intake', 'mcp-public-ability',
]);

// Auth-reach normalization: privemap's vocabulary (unauth/subscriber/shortcode/
// admin-gated/unknown) and reachprove's verdicts (UNAUTH…SERVER/UNKNOWN) collapse
// to one tier ladder. customer folds to subscriber-level; shop-manager to admin
// (PR:H). Anything unrecognized is 'unknown' — never guessed.
const REACH_TIERS = {
  unauth: 'unauth', unauthenticated: 'unauth',
  subscriber: 'subscriber', customer: 'subscriber',
  contributor: 'contributor', author: 'author', editor: 'editor',
  admin: 'admin', 'admin-gated': 'admin', 'shop-manager': 'admin',
  server: 'server', shortcode: 'shortcode', unknown: 'unknown',
};

export function reachTier(reach) {
  return REACH_TIERS[String(reach ?? '').trim().toLowerCase()] || 'unknown';
}

// Classify ONE finding into its bounty lanes.
//   in:  { reach, impactClass, vulnClass, installs, degraded, cvss }
//     reach       — privemap reachability or a reachprove verdict (normalized above)
//     impactClass — a privemap sink/exposure class id (mapped through IMPACT_TO_CLASS)
//     vulnClass   — explicit program class token; wins over the map when supplied
//     installs    — active install count when known (number); unknown otherwise
//     degraded    — the miner's degrade note (fixed-value/self-only), falsy when clean
//     cvss        — a proposed CVSS base score when one exists (number)
//   out: { wordfenceEligible: boolean, patchstack: 'standard'|'mvdp'|'none'|'unknown',
//          reasons: string[] } — every rule verdict named, pass or fail.
export function classifyLane(opts = {}) {
  const { reach, impactClass, vulnClass, installs, degraded, cvss } = opts || {};
  const reasons = [];
  const tier = reachTier(reach);
  const cls = typeof vulnClass === 'string' && vulnClass.trim()
    ? vulnClass.trim()
    : IMPACT_TO_CLASS[impactClass] || 'unknown';
  const reachLabel = String(reach ?? 'unknown');

  // --- Wordfence: ALL rules must pass ------------------------------------------
  let wf = true;

  // Rule 1 — auth reach: unauthenticated or subscriber/customer-level ONLY
  // (contributor/author are mid-level, EXCLUDED; editor/admin/shop-manager are
  // PR:H, EXCLUDED).
  if (tier === 'unauth' || tier === 'subscriber') {
    reasons.push(`wordfence: auth reach '${reachLabel}' is in the eligible tier (unauthenticated / subscriber / customer)`);
  } else {
    wf = false;
    const why = tier === 'contributor' || tier === 'author' ? 'mid-level auth reach is excluded (contributor/author)'
      : tier === 'admin' ? 'privileged reach is excluded (editor/admin/shop-manager = PR:H)'
        : tier === 'server' ? 'server-side surface is never remotely reachable'
          : tier === 'shortcode' ? 'second-order reach — who renders the content is not proven low-privilege'
            : 'auth reach is unproven';
    reasons.push(`wordfence: auth reach '${reachLabel}' is NOT eligible — ${why}`);
  }

  // Rule 2 — install count >= 50,000 when known; UNKNOWN installs are ineligible
  // (the floor cannot be verified — noted, never assumed).
  if (typeof installs === 'number' && Number.isFinite(installs)) {
    if (installs >= WORDFENCE_MIN_INSTALLS) {
      reasons.push(`wordfence: install count ${installs} >= ${WORDFENCE_MIN_INSTALLS}`);
    } else {
      wf = false;
      reasons.push(`wordfence: install count ${installs} < ${WORDFENCE_MIN_INSTALLS} — below the program floor`);
    }
  } else {
    wf = false;
    reasons.push(`wordfence: install count UNKNOWN — the >= ${WORDFENCE_MIN_INSTALLS}-install rule cannot be verified, so the finding is ineligible until installs are supplied (noted, never assumed)`);
  }

  // Rule 3 — class not on the excluded list.
  if (WORDFENCE_EXCLUDED_CLASSES.has(cls)) {
    wf = false;
    reasons.push(`wordfence: class '${cls}' is on the program's excluded list (${[...WORDFENCE_EXCLUDED_CLASSES].join(', ')})`);
  } else {
    reasons.push(`wordfence: class '${cls}' is not on the excluded list`);
  }

  // Rule 4 — consequential CIA sink. A miner-degraded write (fixed-value /
  // self-only, the 0.3 degrade) is a bounded primitive and generally does NOT
  // count; a missing-authz finding counts only when its sink is consequential.
  if (degraded) {
    wf = false;
    reasons.push(`wordfence: sink is NOT consequential — ${degraded} (fixed-value/self-only writes degraded by the miner are bounded primitives, not CIA impact)`);
  } else if (!CONSEQUENTIAL_CLASSES.has(impactClass)) {
    wf = false;
    reasons.push(`wordfence: '${impactClass ?? cls}' carries no consequential CIA sink of its own — a missing-authz/exposure finding counts only when its sink is consequential (triage against the paired sink finding)`);
  } else {
    reasons.push(`wordfence: sink class '${impactClass}' carries consequential CIA impact`);
  }

  // Rule 5 — proposed CVSS >= 4.0, only when computable. Static signals produce
  // no CVSS (the rank score is NOT a CVSS score), so absence never fails the rule.
  if (typeof cvss === 'number' && Number.isFinite(cvss)) {
    if (cvss >= WORDFENCE_MIN_CVSS) {
      reasons.push(`wordfence: proposed CVSS ${cvss} >= ${WORDFENCE_MIN_CVSS}`);
    } else {
      wf = false;
      reasons.push(`wordfence: proposed CVSS ${cvss} < ${WORDFENCE_MIN_CVSS} — below the program floor`);
    }
  } else {
    reasons.push(`wordfence: no CVSS computable from static signals — the >= ${WORDFENCE_MIN_CVSS} rule is not applied here; verify at writeup (the static rank score is NOT a CVSS score)`);
  }

  // --- Patchstack ---------------------------------------------------------------
  // Vendor-program membership is NOT knowable offline: when the class/auth call is
  // 'standard' or 'mvdp', the value is class-based and the scopecheck reason rides
  // with it instead of a guess.
  // Program-wide kill clauses first (June 2026 §4.x — the GiveWP rejection taught
  // this the hard way): cronjob/scheduled-task manipulation, cache clearing, data
  // re-ordering, and notice dismissal are OUT at any auth level; a miner-degraded
  // (fixed-value/self-only) primitive is a bounded effect that lands in the
  // minor-impact band §4.2 rejects for subscriber/unauth findings.
  let ps;
  if (PATCHSTACK_DEAD_CLASSES.has(cls)) {
    return { wordfenceEligible: wf, patchstack: 'none', reasons: [...reasons, `patchstack: class '${cls}' is program-wide OUT (June 2026 §4.2 — cronjobs/scheduled tasks, cache clearing, data re-ordering, notice dismissal; this is the clause that killed the GiveWP report)`] };
  }
  if (degraded) {
    return { wordfenceEligible: wf, patchstack: 'none', reasons: [...reasons, `patchstack: sink is miner-degraded (${degraded}) — a bounded/fixed-value primitive lands in the minor-impact band §4.2 rejects for subscriber/unauthenticated findings; not filing-grade without a demonstrated significant impact`] };
  }
  if (tier === 'unauth' || tier === 'subscriber') {
    if (PATCHSTACK_ACCEPTED_CLASSES.has(cls)) {
      ps = 'standard';
      reasons.push(`patchstack: class '${cls}' is on the accepted list at '${tier}' reach → standard program lane`);
      reasons.push('patchstack: vendor-program-status needs scopecheck — paid-program membership is not knowable offline; confirm the vendor runs a Patchstack standard program before filing');
    } else {
      ps = 'none';
      reasons.push(`patchstack: class '${cls}' is NOT on the accepted list (sqli, arbitrary-file-upload/deletion/download, rce, php-object-injection, arbitrary-settings-change, privesc-to-contributor+, lfi/rfi, broken-access-control, idor, csrf-chained-to-write, sitewide-stored-xss, reflected-xss-with-js, whole-site-dos)`);
    }
  } else if (tier === 'contributor') {
    if (PATCHSTACK_MVDP_CONTRIBUTOR_CLASSES.has(cls)) {
      ps = 'mvdp';
      reasons.push(`patchstack: contributor-level reach with a '${cls}' class (measurable impact) files only via the mVDP lane`);
      reasons.push('patchstack: vendor-program-status needs scopecheck — mVDP membership is not knowable offline; confirm the vendor is an mVDP before filing');
    } else {
      ps = 'none';
      reasons.push(`patchstack: contributor-level reach is out of scope for standard programs, and class '${cls}' is not one of the mVDP contributor classes (broken-access-control, idor)`);
    }
  } else if (tier === 'unknown') {
    ps = 'unknown';
    reasons.push(`patchstack: auth reach is unproven — lane undecidable until reachability adjudicates (classified, not dropped)`);
  } else {
    ps = 'none';
    reasons.push(`patchstack: auth reach '${reachLabel}' is out of scope — standard accepts unauthenticated/subscriber/customer, mVDP adds contributor; author/editor/admin/server findings go to direct vendor disclosure`);
  }

  return { wordfenceEligible: wf, patchstack: ps, reasons };
}

// --- the June-2026 WEB-program kill-class gate (huntloop candidate intake) -------------
// The hunt loop (H1 web programs) had no doctrine filter: whatever the brain or the
// mechanical lane proposed went straight to the sandbox and, if replay-verified, to
// the outbox — so worthless-but-true classes (robots.txt, banner/CSP observations,
// missing headers) piled up as drafts that would COST rate if a human ever filed
// them (the 2026-09-16 outbox triage: 13/38 drafts NO-FILE). This gate is the
// doctrine in code at INTAKE: a kill-class candidate is dropped before it burns a
// sandbox run, a ledger line, or a draft — named, never silent. Wordfence/Patchstack
// lane shape stays in classifyLane; this evaluator answers ONE question:
// 'may this candidate spend a sandbox run?'

// Never-paywall classes for H1-style web programs (the June-2026 doctrine, AGENTS.md
// §3, extended with the 2026-09-16 triage kill list). match(text) tests lowercase.
export const WEB_KILL_CLASSES = [
  { re: /robots\.txt|sitemap\.xml|\.well-known/, why: 'informational disclosure — robots/sitemap contents are never payable by themselves' },
  { re: /\bhttpx? (insecure|missing|strict)|\bhsts\b/, why: 'missing HSTS / header-hygiene observations are informational, not a vulnerability' },
  { re: /cookie (without|missing) (secure|httponly|samesite)|missing (secure|httponly|samesite) cookie/, why: 'cookie-flag absence without demonstrated session compromise is informational' },
  { re: /security header|csp (style|report|observation)|style-only csp|missing csp|content-security-policy (absent|missing|observation)/, why: 'CSP/header best-practice gaps are out (observation-only, no demonstrated impact)' },
  { re: /cache control|cache-control/, why: 'caching-header observations are informational' },
  { re: /version (disclos|expos|fingerpr)|software version (disclos|expos|fingerpr)|banner (disclos|grab|fingerpr)|server header/, why: 'tech/version fingerprint alone has no demonstrated impact' },
  { re: /directory listing|autoindex/, why: 'directory listing is a fingerprint-class finding; pay only with demonstrated sensitive content' },
  { re: /http (options|methods)|allow header|trace method/, why: 'HTTP method enumeration is informational without a demonstrated write/impact' },
  { re: /email (address|harvest|enumerat)|user(name)? enumerat/, why: 'enumeration-only findings are out (June 2026 §4.4)' },
  { re: /open redirect/, why: 'open redirect is inherently out (June 2026 §4.9)' },
  { re: /full path disclosure|\bfpd\b/, why: 'full path disclosure is out (June 2026 §4.4)' },
  { re: /rate[\s-]*limit|brute[\s-]*force|captcha|ip spoof|\b2fa\b|two[\s-]*factor/, why: 'rate-limit/brute-force/CAPTCHA/IP-spoof/2FA classes are out (June 2026 §4.6)' },
  { re: /\bssrf\b/, why: 'blind SSRF is out without demonstrated concrete impact (June 2026 §4.10)' },
  { re: /csv injection|css injection|clickjack/, why: 'CSV/CSS injection and clickjacking are out (June 2026 §4.3/§4.5)' },
  { re: /crons?\b|scheduled task|cache (clear|purge)|re-?order/, why: 'cronjob/scheduled-task/cache/reorder sinks are out (June 2026 §4.2)' },
  { re: /attack complexity:? high|\bac:?h\b/, why: 'Attack Complexity: High is out (June 2026 §4.2)' },
  { re: /subdomain (takeover|enumerat)|\bdns (misconfig|zone transfer)\b|zone transfer/, why: 'subdomain-enumeration/DNS-config classes are informational unless takeover is DEMONSTRATED (named subdomain + serving content)' },
  { re: /ssl|tls|certificat/, why: 'TLS/certificate config observations are informational (no demonstrated crypto break)' },
  { re: /reverse proxy|path traversal\s*\(?informational|404 (fingerprint|page)/, why: 'proxy/404 fingerprint observations are informational' },
  { re: /token exhaustion|ai feature/, why: 'AI feature token exhaustion is out (June 2026 §4.10)' },
  { re: /private (post|page)|draft post|password[\s-]*protected post/, why: 'private/draft/password-protected post disclosure is out (June 2026 §4.4)' },
];

/** The intake gate for huntloop candidates (web programs).
 *  In:  { title, evidence?, sev?, check?, ... } — any candidate shape.
 *  Out: { verdict: 'pass'|'kill'|'park', rule } —
 *    kill  = a never-payable kill class (robots.txt, headers, fingerprints): dropped
 *            at intake — it must never reach the sandbox, ledger, or outbox.
 *    park  = plausibly real but the doctrine demands a demonstrated qualifier first
 *            (CSRF chained, DoS scope, privesc ladder): kept as a HUMAN cue, never
 *            auto-tested — the qualifier is a human session's job.
 *    pass  = a paid class (authn/authz break, injection with a sink, sensitive read).
 *  Pure text heuristic over the candidate's own claims — HONEST by construction:
 *  unknown classes PASS (the sandbox replay is the next gate; nothing is invented
 *  about what a check does), known kill-classes can never buy a sandbox run.
 */
export function intakeGate(candidate = {}) {
  const t = `${String(candidate.title || '')} ${String(candidate.evidence || '')}`.toLowerCase();
  for (const k of WEB_KILL_CLASSES) {
    if (k.re.test(t)) return { verdict: 'kill', rule: k.why };
  }
  if (/\bcsrf\b/.test(t) && !/chain/.test(t)) return { verdict: 'park', rule: 'CSRF is payable only chained to an accepted write — demonstrate the chain first (human session)' };
  if (/\bdos\b|denial of service/.test(t) && !/whole[\s-]*site|crash/.test(t)) return { verdict: 'park', rule: 'DoS is payable only whole-site crash/deface — scope the impact first (human session)' };
  if (/privilege escalation|privesc/.test(t) && !/contributor|author|editor|admin/.test(t)) return { verdict: 'park', rule: 'privilege escalation is payable only to contributor+ capabilities — name the ladder rung first (human session)' };
  return { verdict: 'pass', rule: 'paid class (authn/authz break, injection with a sink, sensitive read) — the sandbox replay is the next gate' };
}
