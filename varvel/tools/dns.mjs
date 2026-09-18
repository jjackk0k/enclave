// VARVEL — DNS reconnaissance (authorized engagements).
//
// Record enumeration (A/AAAA/MX/TXT/NS/CNAME/SOA/CAA/SRV) + subdomain discovery
// by resolving a wordlist. Passive/standard recon; the resolver is injectable so
// it is fully testable offline and so the enclave can route DNS through a governed
// resolver. Native, dependency-free equivalent of subfinder-brute.
//
// Correctness hardening (audited): wildcard-DNS baseline filtering, IPv6-only
// discovery, error classification (transient errors are surfaced, not treated as
// "absent"), pool-size clamping, resolver validation, and IDN/punycode + trailing
// -dot normalization.
//
// Boundary: resolution + enumeration only. No cache poisoning, no zone-transfer
// abuse, no amplification.

import { promises as dnsp } from 'node:dns';
import { randomBytes } from 'node:crypto';
import { domainToASCII } from 'node:url';

export const DEFAULT_SUBDOMAINS = [
  'www', 'mail', 'webmail', 'smtp', 'imap', 'pop', 'ns1', 'ns2', 'mx', 'ftp', 'sftp',
  'api', 'api-dev', 'api-staging', 'app', 'apps', 'web', 'portal', 'dashboard',
  'admin', 'login', 'sso', 'auth', 'id', 'account', 'secure', 'vpn', 'remote',
  'dev', 'staging', 'stage', 'test', 'qa', 'uat', 'beta', 'demo', 'sandbox', 'prod',
  'git', 'gitlab', 'jenkins', 'ci', 'cd', 'db', 'database', 'sql', 'redis', 'cache',
  'internal', 'intranet', 'corp', 'monitor', 'grafana', 'kibana', 'status', 'metrics',
  'docs', 'wiki', 'support', 'help', 'blog', 'shop', 'store', 'pay', 'payment',
  'cdn', 'static', 'assets', 'media', 'img', 'files', 'download', 's3', 'backup',
  'old', 'legacy', 'new', 'm', 'mobile',
];

// Normalize to an ASCII A-label (IDN/punycode), drop a trailing dot, lowercase.
const toAscii = (d) => {
  const clean = String(d || '').trim().replace(/\.$/, '').toLowerCase();
  return domainToASCII(clean) || clean;
};
const isAbsent = (code) => code === 'ENOTFOUND' || code === 'ENODATA';

// Resolve a set of record types for a domain (best-effort). Missing records are
// skipped; transient lookup failures (SERVFAIL/timeout/...) are surfaced in `errors`.
export async function dnsRecon(domain, { resolver = dnsp } = {}) {
  domain = toAscii(domain);
  const records = {};
  const errors = {};
  const types = [
    ['A', 'resolve4'], ['AAAA', 'resolve6'], ['MX', 'resolveMx'], ['TXT', 'resolveTxt'],
    ['NS', 'resolveNs'], ['CNAME', 'resolveCname'], ['SOA', 'resolveSoa'], ['CAA', 'resolveCaa'], ['SRV', 'resolveSrv'],
  ];
  await Promise.all(types.map(async ([name, fn]) => {
    if (typeof resolver[fn] !== 'function') return;
    try { const r = await resolver[fn](domain); if (r && (!Array.isArray(r) || r.length)) records[name] = r; }
    catch (e) { if (!isAbsent(e && e.code)) errors[name] = (e && e.code) || 'ERROR'; }
  }));
  return { domain, records, ...(Object.keys(errors).length ? { errors } : {}) };
}

// Detect a wildcard zone by resolving random labels that should not exist. Both
// families are probed when the resolver has resolve6: an AAAA-only wildcard is still
// a wildcard, and its answers must poison the baseline the same way A answers do.
async function wildcardBaseline(domain, resolver, probes = 3) {
  const ips = new Set();
  let isWildcard = false;
  const has6 = typeof resolver.resolve6 === 'function';
  for (let n = 0; n < probes; n++) {
    const label = `${randomBytes(8).toString('hex')}.${domain}`;
    try {
      const r = await resolver.resolve4(label);
      if (r && r.length) { isWildcard = true; r.forEach((ip) => ips.add(ip)); }
    } catch { /* NXDOMAIN — expected for a non-wildcard zone */ }
    if (has6) {
      try {
        const r = await resolver.resolve6(label);
        if (r && r.length) { isWildcard = true; r.forEach((ip) => ips.add(ip)); }
      } catch { /* NXDOMAIN/ENODATA — expected for a non-wildcard zone */ }
    }
  }
  return { isWildcard, ips };
}

// Discover live subdomains. Filters wildcard-DNS false positives, finds IPv6-only
// hosts (ENODATA on A -> AAAA), and surfaces transient errors instead of hiding them.
export async function subdomainScan(domain, { words = DEFAULT_SUBDOMAINS, resolver = dnsp, concurrency = 12 } = {}) {
  if (typeof resolver.resolve4 !== 'function') throw new TypeError('subdomainScan: resolver.resolve4 is required');
  domain = toAscii(domain);
  const wc = await wildcardBaseline(domain, resolver);
  const notWildcard = (ips) => !wc.isWildcard || ips.some((ip) => !wc.ips.has(ip));

  const found = [];
  const errors = [];
  const pool = Math.max(1, Math.min(Math.floor(concurrency) || 1, words.length || 1));
  let i = 0;
  const worker = async () => {
    while (i < words.length) {
      const host = `${words[i++]}.${domain}`;
      try {
        const ips = await resolver.resolve4(host);
        if (Array.isArray(ips) && ips.length && notWildcard(ips)) found.push({ name: host, ips });
      } catch (e) {
        const code = e && e.code;
        if (code === 'ENODATA' && typeof resolver.resolve6 === 'function') {
          // exists but no A record -> try AAAA (IPv6-only host); the wildcard
          // baseline filters v6 answers exactly like v4 (a v6 wildcard is a wildcard)
          try {
            const v6 = await resolver.resolve6(host);
            if (Array.isArray(v6) && v6.length && notWildcard(v6)) found.push({ name: host, ips: v6, v6: true });
          }
          catch (e2) { if (!isAbsent(e2 && e2.code)) errors.push({ host, code: (e2 && e2.code) || 'ERROR' }); }
        } else if (!isAbsent(code)) {
          errors.push({ host, code: code || 'ERROR' });
        }
      }
    }
  };
  await Promise.all(Array.from({ length: pool }, worker));
  found.sort((a, b) => a.name.localeCompare(b.name)); // stable, diffable order

  return {
    domain, subdomains: found, tried: words.length, wildcard: wc.isWildcard,
    ...(wc.isWildcard ? { wildcardIps: [...wc.ips] } : {}),
    ...(errors.length ? { errors } : {}),
  };
}
