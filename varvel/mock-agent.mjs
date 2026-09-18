// VARVEL — mock governed agent for offline demo/testing.
// Mirrors the runGovernedAgent contract: async ({ messages }) => { text, denials, steps }.
// Returns canned, structured phase output (now rich: subdomains, endpoints, tech,
// CVEs, creds, footholds, pivot routes) so the campaign FSM + graph can run with no
// API key and no real tools. Swap for the real runGovernedAgent to go live.

const jb = (o) => '\n```json\n' + JSON.stringify(o) + '\n```';

export async function mockAgent({ messages }) {
  const obj = messages[0].content;

  if (obj.includes('via port-sweeper')) return { text: 'Port sweep complete.' + jb({ hosts: [
    { ip: '10.10.2.18', label: 'web-01', services: [{ port: 443, proto: 'tcp', name: 'https' }, { port: 22, proto: 'tcp', name: 'ssh' }] },
    { ip: '10.10.2.20', label: 'db-01', services: [{ port: 5432, proto: 'tcp', name: 'postgres' }] } ] }), denials: ['egress:8.8.8.8'], steps: 3 };
  if (obj.includes('via web-prober')) return { text: 'Web probe complete.' + jb({ hosts: [
    { ip: '10.10.2.18', label: 'web-01', endpoints: [{ url: '/admin', method: 'GET' }, { url: '/api/v1/users', method: 'GET' }], tech: [{ name: 'nginx', version: '1.24' }, { name: 'Node.js', version: '18' }] } ] }), denials: [], steps: 3 };
  if (obj.includes('via surface-mapper')) return { text: 'Surface map complete.' + jb({ hosts: [
    { ip: '10.10.2.18', label: 'web-01', subdomains: ['admin.acme.internal', 'api.acme.internal'] } ] }), denials: [], steps: 2 };
  if (obj.startsWith('Enumerate')) return {
    text: 'Enumerated 10.10.0.0/16; the platform held one out-of-scope egress probe.' + jb({ hosts: [
      {
        ip: '10.10.2.18', label: 'web-01',
        services: [{ port: 443, proto: 'tcp', name: 'https' }, { port: 22, proto: 'tcp', name: 'ssh' }],
        subdomains: ['admin.acme.internal', 'api.acme.internal'],
        endpoints: [{ url: '/admin', method: 'GET' }, { url: '/api/v1/users', method: 'GET' }],
        tech: [{ name: 'nginx', version: '1.24' }, { name: 'Node.js', version: '18' }],
      },
      {
        ip: '10.10.2.20', label: 'db-01',
        services: [{ port: 5432, proto: 'tcp', name: 'postgres' }],
        tech: [{ name: 'PostgreSQL', version: '14' }],
      },
    ] }),
    denials: ['egress:8.8.8.8'], steps: 6,
  };

  if (obj.startsWith('Vet')) return {
    text: 'Two findings confirmed with disambiguating probes.' + jb({ findings: [
      { host: 'web-01', title: 'unauthenticated admin panel', sev: 'crit', cve: 'CVE-2025-14190', cvss: 9.8, ref: 'F-01', confidence: 'confirmed', evidence: 'GET /admin returned a 200 management console with no auth' },
      { host: 'db-01', title: 'weak postgres credentials', sev: 'high', ref: 'F-02', confidence: 'confirmed', evidence: 'authenticated with a weak/default credential pair; the post-auth read-back returned the server banner (PostgreSQL 14)' },
    ] }),
    denials: [], steps: 5,
  };

  if (obj.startsWith('Under a countersigned')) return {
    text: 'Proved the admin-panel path under the signed window; recovered a service credential.' + jb({ exploits: [
      { finding: 'unauthenticated admin panel', title: 'auth bypass -> RCE', result: 'proved', ref: 'X-01', host: 'web-01', cred: 'svc_web@web-01', credKind: 'token', foothold: 'www-data shell' },
    ] }),
    denials: [], steps: 4,
  };

  if (obj.startsWith('Establish')) return {
    text: 'Minimal proof of impact; one controlled pivot to db-01; one artifact recorded for cleanup.' + jb({
      routes: [{ from: 'web-01', to: 'db-01', via: 'reused svc credential' }],
      artifacts: [{ host: 'web-01', kind: 'file', path: '/tmp/varvel_poc', cleanup: 'rm -f /tmp/varvel_poc' }],
    }),
    denials: [], steps: 3,
  };

  return {
    text: 'Engagement summary: scope honored (10.10.0.0/16). 2 findings (1 critical, 1 high), 1 proved exploit chain with a controlled pivot to db-01, 1 governance hold (out-of-scope egress). Remediation: enforce auth on the admin panel; rotate postgres credentials.',
    denials: [], steps: 2,
  };
}
