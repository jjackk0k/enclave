// VARVEL — pocdoc: the disclosure-paperwork rung of the zero-day pipeline. Fills the
// Wordfence CNA submission template from a VALIDATED miner candidate (privemap or
// jsmap shape) into submission-ready Markdown.
//
// HONESTY CONTRACT (the point of the rung): fields the candidate cannot know are
// marked TODO(validate) with the reason — NEVER fabricated. Affected-version ranges,
// fixed versions, WP/PHP requirements, and CVSS vectors are guessed by NOBODY here:
// they come from --software/--versions operator input or they stay TODO. The repro
// section is derived from the candidate's hook/route + its read-only probe; anything
// beyond the probe's doctrine is marked as requiring operator validation.
//
// Pure: no fs, no network, no wall-clock (deterministic — the same candidate fills the
// same document; the CLI may stamp a date at print time, the engine does not).

// impact class → CWE mapping (both miner families). The primary CWE only — Wordfence's
// form takes one; nuance goes in the description.
const CWE = {
  // privemap (WordPress/PHP) classes
  'option-overwrite': { id: 'CWE-862', name: 'Missing Authorization' },
  'account-control': { id: 'CWE-269', name: 'Improper Privilege Management' },
  'file-delete': { id: 'CWE-73', name: 'External Control of File Name or Path' },
  'file-write': { id: 'CWE-434', name: 'Unrestricted Upload of File with Dangerous Type' },
  'lfi': { id: 'CWE-98', name: 'Improper Control of Filename for Include/Require Statement in PHP Program' },
  'sqli': { id: 'CWE-89', name: 'SQL Injection' },
  'meta-write': { id: 'CWE-639', name: 'Authorization Bypass Through User-Controlled Key' },
  'second-order-injection': { id: 'CWE-79', name: 'Cross-site Scripting (Stored)' },
  // jsmap (Node/JS) classes
  'rce-exec': { id: 'CWE-78', name: 'OS Command Injection' },
  'code-eval': { id: 'CWE-95', name: 'Improper Neutralization of Directives in Dynamically Evaluated Code (Eval Injection)' },
  'deser-unsafe': { id: 'CWE-502', name: 'Deserialization of Untrusted Data' },
  'proto-pollution': { id: 'CWE-1321', name: 'Improperly Controlled Modification of Object Prototype Attributes (Prototype Pollution)' },
  'path-traversal': { id: 'CWE-22', name: 'Path Traversal' },
  'ssrf': { id: 'CWE-918', name: 'Server-Side Request Forgery' },
  'jwt-alg-unpinned': { id: 'CWE-347', name: 'Improper Verification of Cryptographic Signature' },
  'secret-compare': { id: 'CWE-208', name: 'Observable Timing Discrepancy' },
  'middleware-gap': { id: 'CWE-862', name: 'Missing Authorization' },
};

// reachability → Wordfence "authentication required" answer.
const AUTH_LEVEL = {
  unauth: 'None — the vulnerability is reachable unauthenticated.',
  subscriber: 'Yes — any authenticated user (lowest-privilege role, e.g. Subscriber).',
  authed: 'Yes — an authenticated session is required (see mitigations for the gate).',
  shortcode: 'Yes — an authenticated role able to author content (second-order via shortcode).',
  'admin-gated': 'Yes — a privileged (admin-capable) account.',
  internal: 'Unknown — no request route to this code was found by static analysis (latent primitive).',
  unknown: 'TODO(validate) — reachability could not be determined statically.',
};

const todo = (what, why) => `TODO(validate) — ${what} (${why})`;

// One repro step block per miner family, derived from what the candidate ACTUALLY
// carries. Read-only per the probe doctrine; change-territory proof is the operator's
// call and is marked as such.
function reproSteps(f) {
  const steps = [];
  if (f.hook) {
    // privemap candidate: WordPress request registration.
    steps.push('Install and activate a vulnerable version of the software on a clean WordPress test instance ' + todo('exact version', 'the affected range must be confirmed against the plugin changelog/readme, never assumed') + '.');
    if (/^wp_ajax_nopriv_|^wp_ajax_/.test(f.hook || '')) {
      const action = String(f.hook).replace(/^wp_ajax_(?:nopriv_)?/, '');
      steps.push(`As ${f.reachability === 'unauth' ? 'an UNAUTHENTICATED visitor' : 'a lowest-privilege authenticated user'}, send a POST to \`/wp-admin/admin-ajax.php\` with \`action=${action}\` and the parameters the handler reads (see the code reference below).`);
    } else if (f.hook === 'admin_init') {
      steps.push('As an UNAUTHENTICATED visitor, POST the handler\'s expected fields to `/wp-admin/admin-post.php` (or any admin-ajax endpoint) — `admin_init` fires for unauthenticated requests on those routes.');
    } else if (f.hook === 'rest_route') {
      steps.push('Send the route\'s HTTP verb to its REST path as an unauthenticated/low-privilege client (the registration shows the permission_callback posture).');
    } else if (/^shortcode:/.test(f.hook || '')) {
      steps.push(`As the lowest-privilege role able to author content, preview a draft containing \`[${String(f.hook).slice(10)}]\` with the attribute the handler reflects.`);
    } else {
      steps.push(`Reach the handler through its \`${f.hook}\` registration (see the code reference for the exact registration).`);
    }
  } else if (f.route || f.method) {
    // jsmap candidate: Node/JS route registration.
    steps.push('Check out the affected version of the application and start it with a minimal configuration ' + todo('exact version/commit', 'the affected range must be confirmed against the project\'s release history, never assumed') + '.');
    steps.push(`As ${f.reachability === 'unauth' ? 'an UNAUTHENTICATED client' : 'an authenticated low-privilege client'}, issue \`${f.method || 'GET'} ${f.route || '(the registered path)'}\` with the request-derived input the sink consumes (see the code reference below).`);
  } else {
    steps.push(todo('repro entry point', 'the candidate names no hook/route — the reachable path must be established before submission'));
  }
  steps.push(`Safe validation probe (READ-ONLY doctrine): ${f.probe || todo('probe', 'no safe probe was recorded on the candidate')}`);
  steps.push(todo('full impact demonstration', 'any state-changing/destructive proof is operator sign-off territory — attach the verified exchange only after doctrine sign-off'));
  return steps.map((s, i) => `${i + 1}. ${s}`);
}

// pocDoc(candidate, opts) → Markdown string.
//   candidate: a privemap/jsmap candidate ({ impactClass, reachability, title, ref,
//              evidence, confidence, probe, hook|route, handler, mitigations }).
//   opts:      { software, slug, softwareType, affectedVersions, fixedVersion,
//                wpRequires, phpRequires, nodeRequires, researcher, vendor } — every
//              one optional; absence renders TODO(validate), never a guess.
export function pocDoc(candidate, opts = {}) {
  const f = candidate && typeof candidate === 'object' ? candidate : {};
  const o = opts && typeof opts === 'object' ? opts : {};
  const cwe = CWE[f.impactClass] || { id: todo('CWE', `no mapping for impact class '${f.impactClass}'`), name: '' };
  const isJs = !!(f.route || f.method) && !f.hook;
  const todos = [];

  const field = (value, what, why) => {
    if (value != null && String(value).trim()) return String(value);
    todos.push(what);
    return todo(what, why);
  };

  const software = field(o.software, 'software name', 'not derivable from static analysis — the operator names the product');
  const slug = o.slug ? String(o.slug) : todo('software slug', 'the wordpress.org slug / package name must be confirmed');
  const softwareType = o.softwareType || (f.hook ? 'WordPress plugin/theme' : 'Node.js application');
  const affected = field(o.affectedVersions, 'affected versions', 'confirm via changelog/readme "Stable tag" and version-discrimination probes — never extrapolate');
  const fixed = o.fixedVersion ? String(o.fixedVersion) : 'None known at submission time ' + todo('fixed version', 'verify whether a patched release exists');
  const requires = isJs
    ? (o.nodeRequires || todo('Node.js version requirement', 'check the project\'s package.json engines field'))
    : (o.wpRequires || todo('WordPress version requirement', 'check the plugin readme "Requires at least" header'));

  const sevLine = f.sev ? `${String(f.sev).toUpperCase()} (static rank score ${f.score ?? 'n/a'} — analyzer-internal, NOT a CVSS score)` : todo('severity', 'no rank on the candidate');
  const cvss = todo('CVSS v3.1 vector', 'derive from the VERIFIED repro: AV/AC/PR/UI/S/C/I/A per the confirmed impact — the static rank is not a CVSS score');

  const mit = Array.isArray(f.mitigations) && f.mitigations.length ? f.mitigations.map((m) => `- ${m}`).join('\n') : '- None observed in the analyzed code.';

  const md = `# Wordfence CNA Vulnerability Submission

> Filled by VARVEL pocdoc from a validated static-analysis candidate. Every
> TODO(validate) is a field the analysis CANNOT know — it is marked, not fabricated.

## Software

- **Software Name:** ${software}
- **Software Slug / Package:** ${slug}
- **Software Type:** ${softwareType}
- **Vendor:** ${o.vendor ? String(o.vendor) : todo('vendor', 'confirm the software vendor/author of record')}
- **Affected Versions:** ${affected}
- **Fixed Version:** ${fixed}
- **Requirements:** ${requires}${!isJs ? `\n- **PHP Requirement:** ${o.phpRequires || todo('PHP version requirement', 'check the plugin header/readme')}` : ''}

## Vulnerability

- **Title:** ${f.title || todo('title', 'candidate carried no title')}
- **Vulnerability Type (CWE):** ${typeof cwe === 'object' ? `${cwe.id} — ${cwe.name}` : cwe}
- **Authentication Required:** ${AUTH_LEVEL[f.reachability] || AUTH_LEVEL.unknown}
- **Researcher-estimated Severity:** ${sevLine}
- **CVSS v3.1:** ${cvss}
- **Analysis Confidence:** ${f.confidence || 'not recorded'} (static-analysis confidence in the candidate itself, per the miner's honesty contract)

## Description

${f.title ? `Static analysis of the software identified: ${f.title}.` : todo('description', 'candidate carried no title')}
The impact class is \`${f.impactClass || 'unclassified'}\`${f.taint ? ` with attacker control assessed as \`${f.taint}\` (line-heuristic taint)` : ''}.
${f.doctrineGated ? 'The impact primitive is destructive-class; validation stayed within read-only doctrine.' : ''}

## Steps to Reproduce (from a fresh install)

${reproSteps(f).join('\n')}

## Proof of Concept

\`\`\`text
${todo('PoC artifact', 'attach the captured request/response exchange from the VERIFIED repro here — the miner\'s safe probe above is the detection shape, not the proof')}
\`\`\`

## Code References

- **Location:** \`${f.ref || todo('code reference', 'candidate carried no ref')}\`
- **Handler:** \`${f.handler || 'unresolved'}\`${f.hook ? ` — registered via \`${f.hook}\`` : ''}${f.route ? ` — route \`${f.method || ''} ${f.route}\`` : ''}
- **Evidence (as scanned):**
\`\`\`
${f.evidence || todo('evidence', 'candidate carried no evidence line')}
\`\`\`
- **Mitigations observed in code:**
${mit}

## Impact

${todo('impact statement', `state the concrete impact of a confirmed ${f.impactClass || 'vulnerability'} at ${f.reachability || 'unknown'} reachability — derived from the VERIFIED repro, not the static rank`)}

## Researcher

- **Name / Handle:** ${o.researcher || todo('researcher credit', 'the operator/researcher of record')}
- **Disclosure Notes:** Candidate produced by VARVEL static mining (${f.hook ? 'privemap' : 'jsmap'}); oracle-verified reproduction and this paperwork are the pipeline\'s disclosure rung. All validation probes were read-only per engagement doctrine.
`;

  return md;
}

// For tests/CLI honesty checks: the list of template sections and the TODO marker.
export const POCDOC_SECTIONS = Object.freeze(['Software', 'Vulnerability', 'Description', 'Steps to Reproduce', 'Proof of Concept', 'Code References', 'Impact', 'Researcher']);
export const TODO_MARKER = 'TODO(validate)';
