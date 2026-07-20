// tiers.mjs — the Enclave plan model. Each tier maps to real capabilities the
// platform enforces (isolation strength, identity, compliance), so a plan is a
// config the backend can gate on — not just a marketing table.
//
// Pricing is INDICATIVE — a starting point to pressure-test, not a committed sheet.

export const TIERS = [
  {
    id: 'community', name: 'Community', price: 'Free', tagline: 'Try the workflow, solo.',
    limits: { seats: 1, isolation: 'process (dev)', egress: 'deny-all + basic allowlist' },
    features: [
      'Single operator',
      'Process-tier sandbox (dev isolation)',
      'Bring your own Claude key',
      'All workspace presets',
      'Hash-chained audit (local)',
      'Community support',
    ],
    cta: 'Start free',
  },
  {
    id: 'team', name: 'Team', price: '$—/seat·mo', priceNote: 'indicative', featured: true,
    tagline: 'For a security team adopting AI.',
    limits: { seats: 'up to 25', isolation: 'micro-VM per session', egress: 'deny-all + per-workspace allowlist' },
    features: [
      'Everything in Community, plus:',
      'Hardware micro-VM isolation per session',
      'SSO (OIDC) · role / clearance / licenses',
      'Clearance + qualification enforcement (Cedar PDP)',
      'Tool-dev workload + curated tool shelf',
      'Exportable audit trail',
      'Email support',
    ],
    cta: 'Request access',
  },
  {
    id: 'enterprise', name: 'Enterprise', price: 'Contact us', tagline: 'Regulated, on-prem, at scale.',
    limits: { seats: 'unlimited', isolation: 'dedicated / single-tenant', egress: 'scoped + dedicated egress IPs' },
    features: [
      'Everything in Team, plus:',
      'Single-tenant / on-prem deployment',
      'SOC 2 / ISO 27001 compliance package',
      'SD-JWT clearances · DPoP · SPIFFE workload identity',
      'WORM + Merkle audit anchoring',
      'Red-team engagement scoping + HITL approvals',
      'Windows isolation tier (Hyper-V)',
      'SSO / SCIM · priority support · SLA',
    ],
    cta: 'Talk to us',
  },
];

// The backend gate: does a tier permit a requested capability?
export const CAPABILITY_MIN_TIER = {
  'isolation:micro-vm': 'team',
  'sso:oidc': 'team',
  'workload:tool-dev': 'team',
  'audit:export': 'team',
  'deploy:on-prem': 'enterprise',
  'compliance:soc2': 'enterprise',
  'identity:spiffe': 'enterprise',
  'audit:worm-anchoring': 'enterprise',
  'isolation:windows-hyperv': 'enterprise',
  'redteam:engagement-scoping': 'enterprise',
};

const ORDER = ['community', 'team', 'enterprise'];
export function tierAllows(tierId, capability) {
  const need = CAPABILITY_MIN_TIER[capability];
  if (!need) return true; // ungated capability
  return ORDER.indexOf(tierId) >= ORDER.indexOf(need);
}
