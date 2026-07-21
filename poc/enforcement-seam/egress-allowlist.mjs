// egress-allowlist.mjs — the research egress policy data + helpers for the PEP.
//
// A sealed enclave is deny-all by default. But security work needs CURRENT
// material — CVEs, advisories, ATT&CK, exploit references, package registries,
// language/framework docs, PoC code on GitHub. So we open ONE governed channel:
// read-only fetch/search to an ALLOWLISTED set of reputable knowledge sources,
// with the request DLP-checked so the model can PULL knowledge but never PUSH
// your data out. Everything is logged. Non-allowlisted hosts stay denied.
//
// (This is the policy layer. In the container/Firecracker tier the same allowlist
// is enforced at the network edge by the egress broker — see ../../poc/egress-broker;
// here it is enforced by the PreToolUse hook so it also holds in the local tier.)

// Curated for security + development research. Match is by domain suffix.
export const WEBRESEARCH_ALLOW = [
  // vulnerability / threat intelligence
  'nvd.nist.gov', 'nist.gov', 'cve.org', 'cve.mitre.org', 'attack.mitre.org', 'mitre.org',
  'cisa.gov', 'first.org', 'exploit-db.com', 'packetstormsecurity.com', 'osv.dev',
  'owasp.org', 'snyk.io', 'rapid7.com', 'tenable.com', 'abuse.ch', 'virustotal.com',
  // source + package registries (latest code / deps)
  'github.com', 'githubusercontent.com', 'gitlab.com', 'bitbucket.org',
  'npmjs.com', 'registry.npmjs.org', 'pypi.org', 'files.pythonhosted.org',
  'crates.io', 'pkg.go.dev', 'proxy.golang.org', 'go.dev', 'rubygems.org',
  'packagist.org', 'nuget.org', 'maven.org', 'repo1.maven.org',
  // language / framework / platform docs
  'developer.mozilla.org', 'docs.python.org', 'python.org', 'readthedocs.io',
  'devdocs.io', 'learn.microsoft.com', 'microsoft.com', 'docs.oracle.com',
  'kubernetes.io', 'hashicorp.com', 'rust-lang.org', 'nodejs.org', 'postgresql.org',
  // references
  'stackoverflow.com', 'stackexchange.com', 'wikipedia.org',
  // distro / package mirrors (so installs during tool-dev resolve)
  'debian.org', 'ubuntu.com', 'archlinux.org', 'alpinelinux.org', 'fedoraproject.org', 'kernel.org',
];

// Pull the first http(s) host out of a URL or a shell command; null if none.
export function extractHost(s) {
  const m = /https?:\/\/([^\/\s"'`)]+)/i.exec(String(s || ''));
  if (!m) return null;
  return m[1].replace(/^[^@]*@/, '').replace(/:\d+$/, '').toLowerCase(); // strip userinfo + port
}

export function hostAllowed(host) {
  if (!host) return false;
  host = String(host).toLowerCase();
  return WEBRESEARCH_ALLOW.some(d => host === d || host.endsWith('.' + d));
}

// DLP on the request itself: the model may PULL, not PUSH. Reject requests that
// look like they are smuggling data out (over-long, encoded blobs, secret-looking
// values in the URL). This is deliberately conservative — research URLs are short.
export function urlClean(url) {
  const u = String(url || '');
  if (u.length > 2048) return false;                                   // over-long → likely exfil
  if (/[A-Za-z0-9+/]{120,}={0,2}/.test(u)) return false;               // long base64-ish blob
  if (/-----BEGIN|\bAKIA[0-9A-Z]{12,}|\bsk-[A-Za-z0-9]{16,}|\bghp_[A-Za-z0-9]{20,}/.test(u)) return false; // secrets
  if (/([?&](token|key|secret|password|passwd|authorization)=)[^&\s]{16,}/i.test(u)) return false;        // creds in query
  return true;
}

// Shell commands that reach the network (so a Bash egress attempt is gated by the
// same allowlist, not just the WebFetch tool). Package managers are intentionally
// NOT here — they resolve against the registry hosts already on the allowlist.
export function isEgressCommand(cmd) {
  return /\b(curl|wget|nc|ncat|telnet|Invoke-WebRequest|iwr|scp|sftp|rsync)\b/i.test(String(cmd || ''))
      && /https?:\/\//i.test(String(cmd || ''));
}
