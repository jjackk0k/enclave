// VARVEL — Fireteam: parallel specialist sub-agents (Scatter-Gather ReAct).
// Fans one decomposable objective into N specialist governed loops that run
// concurrently. Every sub-agent still goes through the SAME governed runAgent,
// so each one's tool calls are enforced by the Enclave and land in the audit
// chain — parallel speed without giving up the single safety guarantee.
//
// Orchestration + methodology only: this schedules governed loops and hands each
// a mission brief. It contains NO offensive logic and NO weaponized payloads; a
// specialist's capability comes entirely from the authorized tools it calls, and
// those calls are governed underneath by the Enclave hook.
//
// Hard caps (RedAmon parity): a wave is bounded on total fan-out (maxMembers),
// on how many run at once (maxConcurrent — bounded batches, not unbounded
// Promise.all), and per-member wall-clock (timeoutMs) so one hung specialist
// can't stall the fan-in. Every member result is source-tagged with its label;
// a member that throws or times out resolves to an { error } result rather than
// rejecting the wave.

const DEFAULTS = { maxMembers: 5, maxConcurrent: 5, timeoutMs: 600000 };

function capInt(v, dflt, min) {
  const n = Number(v);
  if (!Number.isFinite(n) || n < min) return dflt;
  return Math.floor(n);
}

// Run ONE specialist as a governed loop, always resolving to a label-tagged
// result. Races the governed call against a per-member timeout so a hung member
// can't stall the wave. The timer is cleared the instant the race settles, so a
// fast member never leaves a dangling long timeout holding the event loop open.
function runMember(runAgent, engine, sp, timeoutMs) {
  const label = (sp && sp.label) || 'specialist';
  let timer;
  const call = Promise.resolve()
    .then(() => runAgent({ ...engine, system: sp && sp.system, messages: [{ role: 'user', content: (sp && sp.objective) || '' }] }))
    .then((r) => ({ label, text: (r && r.text) || '', denials: (r && r.denials) || [], steps: (r && r.steps) || 0 }))
    .catch((e) => ({ label, text: '', denials: [], steps: 0, error: String((e && e.message) || e) }));
  const timeout = new Promise((resolve) => {
    timer = setTimeout(() => resolve({ label, text: '', denials: [], steps: 0, error: 'timeout' }), timeoutMs);
  });
  return Promise.race([call, timeout]).finally(() => clearTimeout(timer));
}

// fireteam(runAgent, engine, specialists[, opts]) — fan out, fan in.
// Backward-compatible: the 3-arg form behaves exactly as before for any set that
// fits under the default caps (which reconSpecialists' 3 members do). opts:
//   maxMembers    hard cap on fan-out (default 5) — extra specialists are dropped
//   maxConcurrent members in flight at once (default 5) — bounded batches
//   timeoutMs     per-member wall-clock (default 600000)
// Returns an array of label-tagged results, in the input specialist order. Never
// rejects: a thrown/timed-out member surfaces as { label, error, ... }.
export async function fireteam(runAgent, engine, specialists, opts = {}) {
  const o = opts || {};
  const maxMembers = capInt(o.maxMembers, DEFAULTS.maxMembers, 1);
  const maxConcurrent = capInt(o.maxConcurrent, DEFAULTS.maxConcurrent, 1);
  const timeoutMs = capInt(o.timeoutMs, DEFAULTS.timeoutMs, 1);

  const members = (Array.isArray(specialists) ? specialists : []).slice(0, maxMembers);
  const out = [];
  // Bounded batches — cap concurrency without dropping any (kept) member.
  for (let i = 0; i < members.length; i += maxConcurrent) {
    const batch = members.slice(i, i + maxConcurrent);
    const settled = await Promise.all(batch.map((sp) => runMember(runAgent, engine, sp, timeoutMs)));
    out.push(...settled);
  }
  return out;
}

// Descriptive alias for the capped fan-out (same function). Either name works.
export const runFireteam = fireteam;

// ---------------------------------------------------------------------------
// Convenience: build recon specialists that each sweep the scope a different way
// (RedAmon's multi-modal recon, but governed). Each is blind to the others.
// PRESERVED verbatim — the original recon fan-out contract.
export function reconSpecialists(scope) {
  const s = (role, how) => ({
    label: role,
    system: `You are VARVEL's ${role} on authorized engagement "${scope.engagement}" (scope ${scope.cidrs.join(', ')}, signed by ${scope.signedBy}). ${how} Stay inside the signed scope. End with a fenced json block: {"hosts":[{"ip":"","label":"","services":[{"port":0,"proto":"","name":""}]}]}`,
    objective: `Enumerate the scope via ${role}.`,
  });
  return [
    s('port-sweeper', 'Find live hosts and open ports/services across the ranges.'),
    s('web-prober', 'Fingerprint exposed HTTP(S) services and their technologies.'),
    s('surface-mapper', 'Discover subdomains, virtual hosts, and adjacent assets in scope.'),
  ];
}

// ---------------------------------------------------------------------------
// specialistsFor(objective, { scope, surface }) — general decomposition.
//
// Turn a free-text phase objective into 2–5 GENUINELY INDEPENDENT specialist
// missions (each { label, system, objective }). Independence is the whole point:
// no mission depends on another's output and none share mutable state, so the
// wave can run them fully in parallel and merge by source tag. Returns [] when
// the objective doesn't decompose (e.g. a synthesis/report phase, or an empty
// objective) — the caller then runs a single governed loop instead.
//
// The mission briefs are ORCHESTRATION + METHODOLOGY only. The exploit-prep set
// in particular is planning guidance, never weaponized code: it points at
// standard authorized tooling and approaches, and any real action later happens
// only under a countersigned window with every tool call governed by the Enclave.
export function specialistsFor(objective, { scope, surface } = {}) {
  const o = (typeof objective === 'string' ? objective : '').toLowerCase();
  if (!o.trim()) return [];

  const phase = classifyObjective(o);
  const ctx = scopeCtx(scope);
  const note = surfaceNote(surface);

  if (phase === 'recon') return reconSet(ctx);
  if (phase === 'validate') return validateSet(ctx, note);
  if (phase === 'exploit-prep') return exploitPrepSet(ctx, note);
  return [];
}

// Objective -> phase. Signals are matched at word-start boundaries (so "report"
// is NOT read as "port", "recon" is not a substring accident, etc.). Strict
// most-specific-intent priority: exploit-prep > validate > recon. That ordering
// also correctly keeps a validate/exploit objective that happens to mention
// recon words ("services", "scope") in its own phase. No signal -> null, meaning
// the objective is treated as non-decomposable (a single loop runs instead).
function classifyObjective(o) {
  const hit = (keys) => keys.some((k) => new RegExp('\\b' + k).test(o));
  const exploit = ['exploit', 'access control', 'access-control', 'authoriz', 'privilege', 'injection', 'foothold', 'weaponiz', 'proof of concept'];
  const validate = ['validat', 'vet', 'verif', 'triage', 'disambiguat', 'evidence', 'confirm', 'finding'];
  const recon = ['recon', 'enumerat', 'discover', 'attack surface', 'surface', 'subdomain', 'port', 'service', 'perimeter', 'footprint', 'fingerprint', 'inventory', 'map the', 'scope', 'asset'];
  if (hit(exploit)) return 'exploit-prep';
  if (hit(validate)) return 'validate';
  if (hit(recon)) return 'recon';
  return null;
}

// Null-safe scope preamble pieces (scope or any field may be missing).
function scopeCtx(scope) {
  const s = scope || {};
  const eng = s.engagement || 'the authorized engagement';
  const cidrs = Array.isArray(s.cidrs) && s.cidrs.length ? s.cidrs.join(', ') : 'the signed scope';
  const by = s.signedBy || 'the engagement owner';
  return { eng, cidrs, by };
}

// Optional read-only context from the current surface (never mutated, never a
// dependency between missions) — a short hint so specialists act on what's known.
function surfaceNote(surface) {
  try {
    const c = surface && typeof surface.counts === 'function' ? surface.counts() : (surface && surface.counts) || null;
    if (!c) return '';
    return ` Known so far: ${c.hosts || 0} host(s), ${c.findings || 0} finding(s).`;
  } catch { return ''; }
}

const preamble = (role, ctx) =>
  `You are VARVEL's ${role} on authorized engagement "${ctx.eng}" (scope ${ctx.cidrs}, countersigned by ${ctx.by}). ` +
  `Stay strictly inside the signed scope; the platform holds anything outside it at the boundary, so spend no effort there. ` +
  `Use only the authorized tools in your enclave shell.`;

// RECON — the multi-modal sweep, each specialist a different discovery modality.
// Independent: DNS/subdomain, web surface, ports/services, and client-JS refs
// never depend on one another.
function reconSet(ctx) {
  const schema = `End with a fenced json block: {"hosts":[{"ip":"","label":"","services":[{"port":0,"proto":"","name":""}],"subdomains":[],"endpoints":[{"url":"","method":""}],"tech":[{"name":"","version":""}]}]}`;
  const mk = (role, how, objective) => ({ label: role, system: `${preamble(role, ctx)} ${how} ${schema}`, objective });
  return [
    mk('subdomain-mapper', 'Discover subdomains, virtual hosts, and adjacent in-scope assets via passive and active DNS enumeration.',
      'Enumerate in-scope subdomains and adjacent assets via subdomain-mapper.'),
    mk('web-surface', 'Fingerprint exposed HTTP(S) services: technologies, server headers, and reachable endpoints/paths.',
      'Fingerprint the in-scope web surface, technologies, and endpoints via web-surface.'),
    mk('port-service', 'Sweep the ranges for live hosts and enumerate open ports and the services/versions behind them.',
      'Enumerate live hosts, open ports, and services via port-service.'),
    mk('js-hunter', 'Harvest client-side JavaScript from in-scope web apps and extract referenced endpoints, API routes, and hostnames — record references only, never exfiltrate secrets.',
      'Extract endpoints and hosts referenced by in-scope client JavaScript via js-hunter.'),
  ];
}

// VALIDATE — one evidence-gatherer per finding class. Each holds two competing
// hypotheses for its class and keeps only what a disambiguating probe confirms.
// Independent: web/app, network-service, and exposure/misconfig classes don't
// share state.
function validateSet(ctx, note) {
  const schema = `Mark each finding confidence "confirmed" (a disambiguating probe verified it — include the evidence) or "suspected". Do not inflate confidence. End with a fenced json block: {"findings":[{"host":"","title":"","sev":"info|low|med|high|crit","confidence":"confirmed","evidence":"","ref":""}]}`;
  const mk = (role, klass, objective) => ({
    label: role,
    system: `${preamble(role, ctx)}${note} Gather disambiguating evidence for ${klass}. For each candidate hold TWO competing hypotheses and keep only what one probe resolves. ${schema}`,
    objective,
  });
  return [
    mk('web-evidence', 'web/application findings (authentication, access-control, and injection surfaces)',
      'Gather disambiguating evidence for web and application findings via web-evidence.'),
    mk('service-evidence', 'network-service findings (exposed services, versions, and reachable default/weak-credential surfaces)',
      'Gather disambiguating evidence for network-service findings via service-evidence.'),
    mk('config-evidence', 'exposure and misconfiguration findings (open indexes, backups, verbose errors, exposed metadata)',
      'Gather disambiguating evidence for exposure and misconfiguration findings via config-evidence.'),
  ];
}

// EXPLOIT-PREP — angle-by-angle test PLANNING for the confirmed findings.
// METHODOLOGY AND GUIDANCE ONLY: no weaponized code, no exploit payloads. Each
// angle produces a prioritized plan referencing standard authorized tools; the
// real action, if any, happens later only under a countersigned window with every
// tool call governed by the Enclave. Independent: authz, injection, and
// secrets/config angles are separate lenses on the same confirmed set.
function exploitPrepSet(ctx, note) {
  const boundary = `Methodology and guidance ONLY — do not produce weaponized code or exploit payloads. Reference standard authorized tools and approaches. Any actual exploitation happens later, only under a countersigned exploit window, with every tool call governed by the Enclave.`;
  const schema = `End with a fenced json block: {"plans":[{"angle":"","finding":"","approach":"","tools":[],"risk":"","gate":"requires countersigned exploit window"}]}`;
  const mk = (role, angle, objective) => ({
    label: role,
    system: `${preamble(role, ctx)}${note} ${boundary} Assess ${angle} against the confirmed findings and produce a prioritized, least-invasive test plan. ${schema}`,
    objective,
  });
  return [
    mk('access-control-angle', 'authentication and authorization weaknesses (broken access control, authorization-boundary and object-reference checks)',
      'Plan the authentication and access-control testing angle via access-control-angle.'),
    mk('injection-angle', 'injection-class exposure (unsafe input handling and missing parameterization), described at a detection-methodology level',
      'Plan the injection testing angle via injection-angle.'),
    mk('secrets-config-angle', 'secrets and configuration exposure (leaked credentials or tokens, insecure defaults, misconfiguration) — record references only, never exfiltrate secrets',
      'Plan the secrets and configuration exposure angle via secrets-config-angle.'),
  ];
}
