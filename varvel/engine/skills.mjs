// VARVEL — Agent Skills (attack methodology playbooks).
//
// RedAmon's headline "it knows how to attack" feature. Skills are METHODOLOGY PLAYBOOKS
// — structured guidance the authorized agent reads: where to look, which STANDARD tools
// to orchestrate (curl/nmap/nuclei/sqlmap/ffuf/jwt_tool…), and how to CONFIRM a finding.
// They are the kind of guidance in any pentest methodology doc (OWASP WSTG). They are
// NOT exploit code / payloads / malware / evasion — they reference authorized tools and
// describe the professional approach. An Intent Router selects the relevant skills for a
// phase and injects their guidance into the agent's prompt.
//
// Built-ins are embedded below; extra user skills can be dropped as markdown into a dir
// (frontmatter: name/category/keywords, then the guidance body) and loaded alongside.

import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

// Methodology playbooks. `guidance` is professional approach + standard tooling, no payloads.
const BUILTIN = [
  { name: 'sql-injection', category: 'injection', keywords: ['sql', 'sqli', 'injection', 'login', 'database', 'query', 'auth', 'id parameter'],
    description: 'SQL injection detection + confirmation methodology.',
    guidance: 'Where: any parameter reaching a DB (login, search, id/sort/filter, headers). Detect: submit a single quote and look for a SQL/DB error or a 500; try boolean pairs (`\' AND 1=1` vs `\' AND 1=2`) for a content/status delta; try time-based (a sleep function) for a measurable delay. Confirm: use sqlmap against the exact request/parameter (`--batch`, capture the request first). For a login, the classic auth-bypass tell is a comment (`admin\'--`) or tautology returning a session. Grade by impact (data read vs auth bypass). Note the DBMS from error strings.' },
  { name: 'xss', category: 'injection', keywords: ['xss', 'cross-site', 'script', 'reflected', 'stored', 'dom', 'input', 'comment'],
    description: 'Cross-site scripting detection methodology.',
    guidance: 'Where: any reflected/stored user input (search, profile, comments, error messages, headers). Detect: inject a unique canary and find where it lands (HTML body / attribute / JS / URL); confirm the context is not encoded. Use dalfox or a headless browser (Playwright) to verify execution rather than assuming. Distinguish reflected vs stored vs DOM. Report the exact sink + context; do not weaponize beyond a benign proof (e.g. a marker), and note CSP if present.' },
  { name: 'ssrf', category: 'server-side', keywords: ['ssrf', 'server-side request', 'url', 'fetch', 'webhook', 'proxy', 'import', 'redirect', 'callback'],
    description: 'Server-side request forgery methodology.',
    guidance: 'Where: any feature that fetches a URL you control (webhooks, url= params, PDF/image import, link preview). Detect: point it at a collaborator/interactsh host and watch for the callback (confirms outbound). Then test reachability of internal-only targets (loopback, RFC1918, cloud metadata 169.254.169.254). Confirm with the response differential (timing/size/error) — do not exfiltrate real secrets; a reachability proof is enough. Note filters (scheme/host allowlists) and any redirect-based bypasses.' },
  { name: 'jwt-attacks', category: 'auth', keywords: ['jwt', 'token', 'json web token', 'session', 'bearer', 'auth', 'signature', 'hs256', 'rs256'],
    description: 'JWT/session token weaknesses methodology.',
    guidance: 'Where: any bearer/cookie session that is a JWT (3 base64url parts). Enumerate: decode the header/claims (alg, kid, iss, role/scope). Check for: `alg:none` acceptance; weak/guessable HMAC secret (test with jwt_tool/hashcat against a wordlist — often a leaked or default key); key confusion (RS256→HS256 using the public key as the HMAC secret); `kid` path/SQL injection. Confirm by minting a token with elevated claims (e.g. role=admin) and using it against an admin endpoint. Look for the signing key leaking in JS bundles, git history, or config. Confirmation = an admin action succeeds with the forged token. ADAPTIVE DEFENSE: if your forged token dies mid-use (401/302 after success), the defender rotated or revoked — switch to credential-death-response immediately; do not hammer a dead key.' },
  { name: 'auth-bypass', category: 'auth', keywords: ['auth', 'authentication', 'bypass', 'login', 'access control', 'forbidden', '403', 'admin', 'privilege'],
    description: 'Authentication / access-control bypass methodology.',
    guidance: 'Where: gated routes (/admin, /api/*), role-differentiated features. Test: direct object/URL access without auth; forced browsing to admin paths; HTTP method/verb tampering (GET vs POST vs PUT); header tricks (X-Forwarded-For, X-Original-URL, referer); role/parameter tampering (role=admin, isAdmin=true) — mass-assignment. Confirm with a concrete privileged action performed as a lower/no-privilege principal. Map exactly which control failed (missing check vs client-side-only enforcement).' },
  { name: 'idor', category: 'access-control', keywords: ['idor', 'insecure direct object', 'access control', 'id', 'uuid', 'ownership', 'tenant', 'account'],
    description: 'Insecure direct object reference methodology.',
    guidance: 'Where: any resource keyed by an id in the URL/body (/users/123, ?order=456). Test: increment/decrement/swap ids across two accounts; try predictable vs UUID ids; check read AND write (can you edit another tenant\'s object?). Confirm by retrieving/modifying a resource you do not own with a second test account. Report the endpoint + missing ownership check; never touch real user data — use your own test objects.' },
  { name: 'path-traversal', category: 'injection', keywords: ['path traversal', 'lfi', 'directory traversal', 'file', 'download', 'include', 'read', 'download='],
    description: 'Path traversal / local file read methodology.',
    guidance: 'Where: file/download/include/template params (?file=, ?page=, ?template=). Test: `../` sequences (and encoded `%2e%2e%2f`, double-encoding, null bytes on old stacks) to escape the intended dir; target a known-safe marker file to prove read (a benign file, not secrets). Confirm the traversal with a controlled read; note the base dir + any filter. Do not exfiltrate real credentials — proving arbitrary read is the finding.' },
  { name: 'exposed-secrets', category: 'recon', keywords: ['exposed', 'secret', 'dotenv', '.env', '.git', 'backup', 'config', 'credential', 'leak', 'disclosure', 'source'],
    description: 'Exposed files / secret disclosure discovery.',
    guidance: 'Where: web root + common paths. Probe (GET): /.env, /.git/HEAD + /.git/config (walkable repo), /backup/ + *.sql/*.tar.gz, /config.json, /wp-config.php, /.aws/credentials, /server-status, /actuator/*. Read linked JS bundles for inlined keys/endpoints. Confirm by fetching the artifact and validating it contains real secrets (KEY=value, private keys, DB creds). Flag by severity (live secret = critical). This is discovery — do not use recovered secrets beyond confirming validity within scope.' },
  { name: 'command-injection', category: 'injection', keywords: ['command injection', 'rce', 'os command', 'shell', 'exec', 'ping', 'system', 'code execution'],
    description: 'OS command injection detection methodology.',
    guidance: 'Where: params that feed a shell/system call (ping/dns tools, converters, exports). Detect: append shell metacharacters (`;`, `|`, `&&`, backticks, `$()`) with a BENIGN, observable command (a controlled DNS/HTTP callback via interactsh, or a timing sleep) — never a destructive one. Confirm via the out-of-band callback or timing delta. Tools: commix can automate detection. Report the exact param + separator; keep the proof benign and reversible.' },
  { name: 'broken-access-control', category: 'access-control', keywords: ['access control', 'authorization', 'privilege', 'vertical', 'horizontal', 'function level', 'admin api'],
    description: 'Function-level authorization gaps methodology.',
    guidance: 'Where: admin/privileged functions + APIs. Test vertical (low-priv → admin function) and horizontal (user A → user B data) escalation; enumerate hidden admin endpoints (from JS, docs, /api schemas); replay privileged requests with a lower-priv token. Confirm with a privileged operation as an unauthorized principal. This underlies IDOR, forced-browsing, and mass-assignment — cross-reference those skills.' },
  { name: 'credential-death-response', category: 'adaptivity', keywords: ['rotation', 'token died', 'key rotation', 'session invalid', '401 after success', 'credential expired', 'adaptive defense', 'technique stopped working'],
    description: 'What to do when a working credential suddenly dies mid-engagement (the rotation lesson).',
    guidance: 'A credential that worked and now fails (401/302-to-login/403 after prior success) means the DEFENDER ADAPTED — do NOT repeat the dead credential louder; every retry is another alert. Triage in order: (1) STOP using it immediately. (2) Verify liveness once, cheaply (jwt-verify the key against a fresh token, or one benign authenticated request) — confirm dead vs transient. (3) Re-check the SOURCE you got it from (re-fetch the bundle/config: is the key still the same value? If it changed or your key no longer validates → the defender ROTATED. If the source is unchanged but tokens die → you are blacklisted/session-revoked. If everything 429s → rate-limited; back off, do not escalate). (4) Respond to the CLASS: rotation → re-derive from the new source if it is still exposed, otherwise abandon this chain and switch to a different weakness class; blacklisting → the technique is burned for this engagement, switch class; rate-limit → reduce cadence drastically and continue later. (5) Record the adaptation in your notes — "defender rotates signing keys on anomaly #N" is engagement intel worth a finding. The losing move is hammering a dead key; the winning move is diagnosing the adaptation and routing around it.' },
  { name: 'defender-adaptation', category: 'adaptivity', keywords: ['waf', 'soc', 'blue team', 'defender', 'rate limit', 'ban', 'lockout', 'adaptive', 'monitored', 'detected', 'caught'],
    description: 'Operating against an actively-defended target (SOC playbook discipline).',
    guidance: 'Assume the target is watched: every action has a noise cost and the defender responds to patterns, not single requests. Discipline: (1) MINIMAL CONTACT — prove impact with the fewest privileged actions possible (one write + one revert beats five writes; a change-and-revert pair inside the defender\'s reaction window usually completes before thresholds trip). (2) READ THE DEFENSE — 429/Retry-After = rate limiting (back off and pace slower); sudden uniform 403s with a reference id = WAF/ban (change shape or stop; repeating identical requests deepens the ban); account lockouts = STOP that auth path entirely (do not lock out real users); a working technique dying = rotation/revocation (see credential-death-response). (3) STAY BELOW THRESHOLDS — defenders trigger on counts per window: spread actions over time, vary nothing-else, and never let a scanner\'s cadence be your tell. (4) KNOW WHEN YOU\'RE BURNED — if the defender has clearly adapted to you specifically, name it in the report honestly; a detected engagement is a result, not a failure. The goal is to be the red team the SOC writes up as hard to catch, not the one in their alert feed.' },
];

function parseMarkdownSkill(text, fallbackName) {
  const m = String(text || '').match(/^---\s*([\s\S]*?)\s*---\s*([\s\S]*)$/);
  const fm = {}, body = m ? m[2].trim() : String(text || '').trim();
  if (m) for (const line of m[1].split(/\r?\n/)) { const kv = line.match(/^([\w-]+)\s*:\s*(.+)$/); if (kv) fm[kv[1].trim().toLowerCase()] = kv[2].trim(); }
  const keywords = (fm.keywords || '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
  return { name: fm.name || fallbackName, category: fm.category || 'user', keywords, description: fm.description || '', guidance: body };
}

// Load built-in skills + any user markdown skills from `userDir`. Robust to a missing dir.
export function loadSkills({ userDir } = {}) {
  const skills = BUILTIN.map((s) => ({ ...s, keywords: s.keywords.slice() }));
  if (userDir && existsSync(userDir)) {
    try {
      for (const f of readdirSync(userDir)) {
        if (!/\.md$/i.test(f)) continue;
        try { skills.push(parseMarkdownSkill(readFileSync(join(userDir, f), 'utf8'), f.replace(/\.md$/i, ''))); } catch { /* skip bad file */ }
      }
    } catch { /* unreadable dir */ }
  }
  return skills;
}

const words = (s) => String(s || '').toLowerCase().match(/[a-z0-9.+_-]{2,}/g) || [];

// Intent Router: pick the skills relevant to the objective + surface context, ranked by
// match strength, capped. Never throws.
export function selectSkills(objective, context = {}, skills = loadSkills()) {
  const ctx = context || {};
  const hay = new Set([
    ...words(objective),
    ...((ctx.findings || []).flatMap((f) => words(f && (f.title || f.label)))),
    ...((ctx.services || []).flatMap((s) => words(s && s.name))),
    ...((ctx.endpoints || []).flatMap((e) => words(e && (e.path || e.url || e.label)))),
  ]);
  const scored = [];
  for (const sk of (Array.isArray(skills) ? skills : [])) {
    let hits = 0;
    for (const kw of (sk.keywords || [])) { for (const t of words(kw)) if (hay.has(t)) { hits++; break; } }
    if (hits > 0) scored.push({ sk, hits });
  }
  scored.sort((a, b) => b.hits - a.hits);
  return scored.slice(0, 4).map((x) => x.sk);
}

// Compact prompt block injecting the selected skills' methodology for the agent.
export function skillsBriefing(selected) {
  if (!Array.isArray(selected) || !selected.length) return '';
  const L = ['## Relevant attack playbooks (methodology — orchestrate standard authorized tools, stay in scope)'];
  for (const s of selected) { L.push(`### ${s.name}${s.category ? ' [' + s.category + ']' : ''}`); L.push(s.guidance || s.description || ''); }
  return L.join('\n');
}
