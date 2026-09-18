// VARVEL — TLS-inspection detection: the pure classifier behind deliberate egress policy
// (documented lose-point #5 vs a nation-level enterprise: corporate egress at that tier
// does TLS inspection — SSL-bump with an enterprise root CA pushed to endpoints — and a
// platform this class must DETECT the bump, DECIDE deliberately per transport, and ADAPT
// the wire plan instead of failing in accidental, uncontrolled ways).
//
// WHAT THIS IS: given a handshake OBSERVATION (the peer's certificate chain plus Node's
// own chain-policy facts — `authorized` / `authorizationError` from the tls socket), this
// module classifies the path as 'inspected' | 'clean' | 'unknown' and ALWAYS carries the
// evidence (issuer strings, auth errors) — never a bare boolean. The live probe shell is
// tools/tlsinspect.mjs; the ranking adaptation lives in engine/transport-grade.mjs.
//
// THE HONESTY CONTRACT (non-negotiable):
//   · An inspected channel is reported as exactly that: "TLS-inspected: content visible
//     to the enterprise egress proxy". Nothing here ever claims the inspection away.
//   · Detection is HEURISTIC. The signals are issuer identity vs expectation, known
//     bump-product issuer naming, self-signed/enterprise-root markers, and Node's trust
//     verdict. A bump that re-issues through a root the client trusts (an enterprise
//     root in the node's own trust store — e.g. NODE_EXTRA_CA_CERTS) can present as
//     `authorized:true`; the evidence says which store fact was used, and posture
//     aggregation says when the reference set could not conclude ('unknown').
//   · 'inspection-COMPATIBLE' (ghc/stg-class wires) is never 'inspection-PROOF': the
//     proxy sees SaaS-shaped traffic, which is the design — not a claim of invisibility.
//
// The classifier is PURE: no I/O, no clock, no throw — garbage in, 'unknown' out.

// Known enterprise TLS-inspection products: issuer/subject naming seen on bump
// (re-issued) certificates. SMALL AND HONEST — these are the widely deployed SSL-bump
// stacks whose re-issued chains name themselves; absence from this list never means
// "no inspection", it means "no positive match" (verdict falls to the trust signals).
const KNOWN_INSPECTORS = [
  ['Zscaler', /zscaler/i],
  ['Netskope', /netskope/i],
  ['Palo Alto (PAN-DB/GlobalProtect)', /palo\s*alto|pan-db|globalprotect/i],
  ['Broadcom/Symantec (Blue Coat ProxySG)', /blue\s*coat|proxysg|broadcom.*(proxy|ssl)|symantec.*(proxy|ssl)/i],
  ['Forcepoint', /forcepoint|websense/i],
  ['McAfee/Trellix Web Gateway', /mcafee|trellix|skyhigh/i],
  ['Cisco (Umbrella/WSA)', /cisco.*(umbrella|wsa|web security)|umbrella/i],
  ['Fortinet (FortiGate)', /fortinet|fortigate|forti-ca/i],
  ['Sophos', /sophos/i],
  ['Check Point', /check\s*point/i],
  ['Barracuda', /barracuda/i],
  ['iboss', /iboss/i],
  ['Menlo Security', /menlo\s*security/i],
];

// Common public CA issuer naming (leaf issuer or root) — the EXPECTATION for a well-known
// SaaS domain on a clean wire. Modest list by design: it only ever SUPPORTS a 'clean'
// verdict together with Node's authorized:true; it never vetoes one.
const PUBLIC_CAS = /digicert|let'?s encrypt|isrg|google trust services|google internet authority|\bgts\b|globalsign|sectigo|comodo|usertrust|entrust|amazon|microsoft (ca|azure|corporation.*tls)|godaddy|starfield|cloudflare|geotrust|thawte|rapidssl|verisign|identrust|baltimore|zerossl|buypass|ssl\.com|harica|certum|actalis/i;

// Node chain-policy error codes that say "this chain roots in something my trust store
// does not know" — the shape an enterprise bump presents to a stock Node client (whose
// bundled Mozilla store does NOT carry the enterprise root).
const UNTRUSTED_ROOT = /SELF_SIGNED|UNABLE_TO_GET_ISSUER|UNABLE_TO_VERIFY|DEPTH_ZERO|UNTRUSTED|ISSUER/i;

// Wires whose channel CONTENT is legible to an inspecting egress proxy: direct TLS wires
// to the listener (or plain HTTP — even more legible). Under fail-closed these refuse;
// under adapt they are deprioritized. smb is deliberately NEUTRAL: it is an internal
// pivot-mesh relay — the egress proxy never sees that segment.
export const DIRECT_TLS_WIRES = new Set(['http', 'doh', 'ws']);
// Inspection-COMPATIBLE wires: ghc rides normal api.github.com traffic (SaaS-shaped by
// design), stg's image envelopes are content-shaped cover, dns/icmp bypass the bump path
// entirely (when armed). COMPATIBLE, never PROOF — the proxy still sees the traffic.
export const INSPECTION_TOLERANT_WIRES = new Set(['ghc', 'stg', 'dns', 'icmp']);

export const TLSI_VERDICTS = new Set(['inspected', 'clean', 'unknown']);
export const TLSI_POSTURES = new Set(['tls-inspected', 'clean', 'partial', 'unknown']);
export const TLSI_POLICIES = new Set(['fail-closed', 'adapt', 'ignore']);

// One chain entry -> a flat comparable fact set. Accepts Node getPeerCertificate(true)
// entries ({ subject, issuer } objects) OR plain { subject, issuer, selfSigned } strings.
function certFacts(entry) {
  if (!entry || typeof entry !== 'object') return null;
  const flat = (v) => {
    if (v == null) return '';
    if (typeof v === 'string') return v;
    if (typeof v === 'object') return [v.CN, v.O, v.OU].filter(Boolean).join(' / ') || Object.values(v).filter((x) => typeof x === 'string').join(' / ');
    return String(v);
  };
  const subject = flat(entry.subject);
  const issuer = flat(entry.issuer);
  if (!subject && !issuer) return null;
  const selfSigned = entry.selfSigned === true || (subject !== '' && subject === issuer);
  return { subject, issuer, selfSigned };
}

// THE CLASSIFIER. observation = {
//   host?,            // reference host (evidence label only)
//   expect?,          // 'saas' = a well-known SaaS domain (a public CA is EXPECTED) | 'any'
//   chain?,           // [leaf..root] entries (see certFacts)
//   authorized?,      // Node tls socket chain-policy verdict (boolean)
//   authorizationError?, // Node's error code/string when authorized === false
// }
// -> { verdict, evidence: [...], summary } — evidence always, never a bare boolean.
export function classifyHandshake(obs = {}) {
  try {
    const evidence = [];
    const host = obs && obs.host ? String(obs.host) : null;
    const expect = obs && obs.expect === 'saas' ? 'saas' : 'any';
    const chain = (Array.isArray(obs && obs.chain) ? obs.chain : []).map(certFacts).filter(Boolean);
    const authorized = obs && obs.authorized === true ? true : obs && obs.authorized === false ? false : null;
    const authErr = obs && obs.authorizationError ? String(obs.authorizationError) : '';

    if (!chain.length) {
      return { verdict: 'unknown', evidence: ['no peer certificate chain observed' + (host ? ' from ' + host : '')], summary: 'unknown — no handshake facts to classify' };
    }

    const leaf = chain[0];
    const root = chain[chain.length - 1];
    evidence.push('leaf: subject=' + (leaf.subject || '?') + ' issuer=' + (leaf.issuer || '?'));
    if (chain.length > 1) evidence.push('root: subject=' + (root.subject || '?') + (root.selfSigned ? ' (self-signed)' : ''));

    // Signal 1: known-inspector naming anywhere in the chain — the strongest signal.
    for (const c of chain) {
      for (const [name, re] of KNOWN_INSPECTORS) {
        if (re.test(c.issuer) || re.test(c.subject)) {
          evidence.push('KNOWN INSPECTOR: "' + (re.test(c.issuer) ? c.issuer : c.subject) + '" matches ' + name + ' (enterprise bump re-issues certificates in its own name)');
          return { verdict: 'inspected', evidence, summary: 'TLS-inspected: content visible to the enterprise egress proxy (' + name + ' issuer on the presented chain)' };
        }
      }
    }

    // Signal 2: public-CA expectation facts.
    const publicHit = chain.some((c) => PUBLIC_CAS.test(c.issuer) || PUBLIC_CAS.test(c.subject));
    if (publicHit) evidence.push('issuer naming matches a common public CA');
    const untrustedRoot = root.selfSigned || chain.some((c) => c.selfSigned);
    if (untrustedRoot) evidence.push('self-signed marker in chain (enterprise/private root shape)');

    // Signal 3: Node's own chain-policy verdict.
    if (authorized === true) {
      evidence.push('Node chain policy: authorized (chain roots in this client\'s trust store — a managed trust store carrying an enterprise root can mask a bump; see docs)');
      return { verdict: 'clean', evidence, summary: 'clean — the presented chain validates against the client trust store' + (publicHit ? ' and names a public CA' : '') };
    }
    if (authorized === false) {
      evidence.push('Node chain policy: NOT authorized (' + (authErr || 'no error string') + ')');
      if (UNTRUSTED_ROOT.test(authErr)) {
        // The bump shape: a re-issued chain rooted somewhere the stock client cannot know.
        if (expect === 'saas') {
          evidence.push('expectation violation: ' + (host || 'this reference') + ' is a well-known SaaS — a public CA was EXPECTED, the wire presented an unknown/enterprise root instead');
          return { verdict: 'inspected', evidence, summary: 'TLS-inspected: content visible to the enterprise egress proxy (a SaaS reference presented an untrusted, non-public chain — the signature of SSL-bump re-issue)' };
        }
        evidence.push('untrusted root on a non-SaaS reference — could be inspection, a private PKI, or a self-signed lab cert; not attributable');
        return { verdict: 'unknown', evidence, summary: 'unknown — untrusted chain, not attributable (private PKI and SSL-bump look alike without a public-CA expectation)' };
      }
      // Expired / hostname-mismatch / other cert problems are NOT bump evidence.
      evidence.push('certificate problem without unknown-root shape — more likely misconfiguration than SSL-bump (a bump re-issues valid-looking certs)');
      return { verdict: 'unknown', evidence, summary: 'unknown — chain rejected for ' + (authErr || 'unspecified reasons') + '; not an inspection signature' };
    }

    evidence.push('no trust verdict available (authorized flag absent)');
    return { verdict: 'unknown', evidence, summary: 'unknown — chain observed but no trust verdict was captured' };
  } catch (e) {
    return { verdict: 'unknown', evidence: ['classifier error: ' + String((e && e.message) || e)], summary: 'unknown — classification failed safely' };
  }
}

// Reference-set aggregation -> the platform's egress POSTURE. refs: per-reference results
// [{ ref, saas, ok, verdict }]. Posture is computed over the SaaS references only — our
// own listener rides the private path by design, so its verdict is reported per-reference
// but cannot speak for the enterprise egress. Mixed SaaS verdicts are REAL (per-domain
// bypass policies exist) and are reported as 'partial', said plainly.
export function aggregatePosture(refs = []) {
  const list = Array.isArray(refs) ? refs : [];
  const saas = list.filter((r) => r && r.saas === true);
  const inspected = saas.filter((r) => r.verdict === 'inspected');
  const clean = saas.filter((r) => r.verdict === 'clean');
  const inconclusive = saas.filter((r) => r.verdict !== 'inspected' && r.verdict !== 'clean');

  if (!saas.length) return { posture: 'unknown', reason: 'no SaaS references configured — the reference set cannot measure the enterprise egress' };
  if (inspected.length && clean.length) {
    return { posture: 'partial', reason: inspected.length + ' of ' + saas.length + ' SaaS references present a bumped chain while ' + clean.length + ' validate clean — consistent with a per-domain inspection policy (selective SSL-bump); treat inspected domains as visible to the enterprise egress proxy' };
  }
  if (inspected.length) {
    return { posture: 'tls-inspected', reason: (inconclusive.length ? inspected.length + ' of ' + saas.length + ' SaaS references bumped (' + inconclusive.length + ' inconclusive)' : 'every SaaS reference (' + inspected.length + ') presents a re-issued/enterprise-rooted chain') + ' — content on direct TLS wires is visible to the enterprise egress proxy' };
  }
  if (clean.length) {
    return { posture: 'clean', reason: clean.length + ' of ' + saas.length + ' SaaS references validate against public CAs with no bump markers' + (inconclusive.length ? ' (' + inconclusive.length + ' reference(s) inconclusive — coverage is partial)' : '') };
  }
  return { posture: 'unknown', reason: 'no reference produced a conclusive verdict (' + inconclusive.length + ' of ' + saas.length + ' inconclusive) — no inspection claim either way' };
}

// Validate an agent-REPORTED verdict (check-in metadata, x-varvel-tlsi). The listener
// cannot verify the agent's egress path — this is the agent's own observation, stored
// and surfaced as such. Garbage normalizes to null (ignored), never throws.
export function normalizeTlsVerdict(v) {
  const s = String(v || '').trim().toLowerCase();
  return TLSI_VERDICTS.has(s) ? s : null;
}
