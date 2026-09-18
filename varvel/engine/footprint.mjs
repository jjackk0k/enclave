// VARVEL — detection-footprint knowledge base + scoring.
//
// Every action on an engagement leaves a trace. This module makes that trace
// EXPLICIT for both the operator and the agent: for each activity VARVEL performs,
// what a defender (blue team) would observe, what it exposes about the operator, how
// loud it is, and the lower-noise professional alternative.
//
// This is tradecraft TRANSPARENCY, for authorized engagements only. It describes what
// is *detectable* — it never implements evasion or anti-forensics. The "quieter"
// guidance is professional courtesy (don't needlessly flood a client's SIEM), not a
// way to hide activity: on a signed engagement everything is logged and attributable
// by design, and the Enclave keeps a tamper-evident audit regardless.
//
// Loudness scale (1–5): 1 = near-invisible in normal traffic · 3 = shows up in logs a
// reviewer would notice · 5 = trips real-time alerts / active response.

export const FOOTPRINTS = {
  'tcp-scan': {
    label: 'TCP port scan (connect)', category: 'recon', loudness: 3, attribution: 'high',
    signals: [
      'One completed TCP handshake per open port (full connect, not a half-open SYN scan) — appears in firewall/flow logs and the service’s own connection log',
      'Connections to many closed ports in a short window from one source — the classic horizontal-scan shape',
    ],
    detectedBy: ['Firewall / NetFlow / Zeek conn.log', 'IDS scan detectors (e.g. Snort sfPortscan)', 'Per-service connection logs'],
    exposes: ['Source IP', 'Scan timing / fan-out pattern', 'Sequential or tool-default port ordering'],
    quieter: 'Scan only the ports the engagement needs, spread over time, from the authorized source; avoid full-range sweeps when a targeted set will do.',
  },
  'service-probe': {
    label: 'Service / version detection (banner grab)', category: 'recon', loudness: 2, attribution: 'med',
    signals: ['A connection that reads the service banner then disconnects', 'Occasionally a malformed/probe payload the service logs as a protocol error'],
    detectedBy: ['Service application logs', 'IDS protocol-anomaly rules'],
    exposes: ['Source IP', 'Probe fingerprint (which strings you send)'],
    quieter: 'Prefer the banner the service already volunteers; don’t send aggressive version-probe payloads unless the version genuinely matters.',
  },
  'http-fingerprint': {
    label: 'HTTP fingerprint (headers + favicon)', category: 'recon', loudness: 1, attribution: 'low',
    signals: ['A couple of ordinary GET requests (/, /favicon.ico) — indistinguishable from a normal visitor at low volume'],
    detectedBy: ['Web access logs (only under correlation)'],
    exposes: ['Source IP', 'User-Agent'],
    quieter: 'Already low. A realistic User-Agent keeps it in the noise floor of ordinary traffic.',
  },
  'web-content-scan': {
    label: 'Web content discovery (path brute-force)', category: 'recon', loudness: 4, attribution: 'high',
    signals: [
      'A burst of 404s (and the occasional 200/403) for paths a normal user never requests',
      'High request rate from one source — the dominant web-scan tell',
      'Requests for known-sensitive paths (/.git, /.env, /wp-config.php) that WAFs carry signatures for',
    ],
    detectedBy: ['Web server access logs (404 flood)', 'WAF path/rate signatures', 'SIEM rate-of-request rules'],
    exposes: ['Source IP', 'User-Agent', 'Wordlist / tool fingerprint', 'Request cadence'],
    quieter: 'Use a focused wordlist seeded from robots.txt / sitemap / observed links, add jitter, and respect the app’s rate limits instead of hammering it.',
  },
  'web-crawl': {
    label: 'Web crawl (following the site’s own links)', category: 'recon', loudness: 2, attribution: 'med',
    signals: [
      'Ordinary GETs for real, linked pages — no 404 flood (that’s the brute-force tell), but the volume and cadence from one source stand out under review',
      'Full traversal of the navigable site in a short window, including deep paths real users rarely open',
    ],
    detectedBy: ['Web access logs (rate + coverage correlation)', 'WAF rate / session-behavior rules'],
    exposes: ['Source IP', 'User-Agent', 'Crawl cadence and coverage pattern'],
    quieter: 'Cap pages and depth, pace requests with jitter, and let robots/sitemap seed the queue — a link-following crawl is already far quieter than path brute-force.',
  },
  'vuln-check': {
    label: 'Vulnerability checks (known-exposure probes)', category: 'recon', loudness: 3, attribution: 'high',
    signals: [
      'Requests for known-sensitive paths (/.git/HEAD, /.env, /actuator/env) — WAFs and SOC playbooks carry EXACT signatures for these, so each hit is conspicuous even at low volume',
      'A probe Origin in the CORS check — uncommon from real browsers',
    ],
    detectedBy: ['WAF path signatures', 'Web access logs (sensitive-path alerts)', 'SIEM correlation with scan behavior'],
    exposes: ['Source IP', 'User-Agent', 'The specific exposures you tested for (reveals intent)'],
    quieter: 'Keep the probe list curated and high-signal (content-verified), pace requests, and let page audits ride on pages already fetched instead of adding volume.',
  },
  'tls-probe': {
    label: 'TLS configuration inspection', category: 'recon', loudness: 1, attribution: 'low',
    signals: ['One or a few TLS handshakes — ordinary unless you enumerate many cipher suites'],
    detectedBy: ['Load-balancer / TLS-terminator logs (rarely reviewed)'],
    exposes: ['Source IP', 'ClientHello fingerprint (JA3)'],
    quieter: 'A single handshake to read the negotiated config is plenty; skip exhaustive cipher enumeration unless required.',
  },
  'os-fingerprint': {
    label: 'OS fingerprint (SMB negotiate + banner reads)', category: 'recon', loudness: 2, attribution: 'med',
    signals: [
      'One SMB2 NEGOTIATE — identical to any Windows client handshake, but a workstation negotiating with a server it has no business with stands out under correlation',
      'A few banner reads (SSH/HTTP) right after a port scan — the version-detection shape',
    ],
    detectedBy: ['Per-service connection logs', 'IDS protocol-anomaly rules (unexpected SMB client)'],
    exposes: ['Source IP', 'Probe timing relative to the scan'],
    quieter: 'Fingerprint only hosts where recon already earned the signal (445 open); one negotiate, no nmap -O probe battery (~16 packets of stack oddities).',
  },
  'ldap-enum': {
    label: 'LDAP rootDSE read (anonymous)', category: 'recon', loudness: 1, attribution: 'med',
    signals: ['One TCP connection: anonymous bind + base-scope rootDSE search + unbind — the same shape as any LDAP client startup'],
    detectedBy: ['Directory access logs (1644/4662 events)', 'LDAP query-anomaly analytics'],
    exposes: ['Source IP', 'The fact you know a directory is there'],
    quieter: 'Already minimal — one connection, three operations, no content search. Don\'t walk the tree anonymously; rootDSE carries the domain intel.',
  },
  'dns-enum': {
    label: 'DNS record enumeration', category: 'recon', loudness: 2, attribution: 'low',
    signals: ['Queries for many record types / names, often to the authoritative server', 'A failed AXFR zone-transfer attempt is explicitly logged'],
    detectedBy: ['Authoritative DNS query logs', 'Passive DNS providers'],
    exposes: ['Resolver / source IP', 'The names you already know to ask for'],
    quieter: 'Lean on passive DNS and certificate transparency first; reserve active queries for gaps.',
  },
  'subdomain-brute': {
    label: 'Subdomain brute-force', category: 'recon', loudness: 3, attribution: 'med',
    signals: ['A flood of DNS queries for non-existent names (NXDOMAIN) against one zone'],
    detectedBy: ['Authoritative DNS logs', 'DNS analytics (NXDOMAIN-rate anomaly)'],
    exposes: ['Resolver / source IP', 'Wordlist fingerprint'],
    quieter: 'Prefer certificate transparency + passive sources; brute-force only the zones those miss, at a modest rate.',
  },
  'http-methods': {
    label: 'HTTP method / CORS / header probe', category: 'recon', loudness: 2, attribution: 'med',
    signals: ['OPTIONS requests and cross-origin GETs — uncommon from real browsers, so they stand out under review', 'Requests carrying an unusual Origin header (CORS test)'],
    detectedBy: ['Web access logs', 'WAF (anomalous method / Origin rules)'],
    exposes: ['Source IP', 'Test Origin values you send'],
    quieter: 'A handful of targeted probes reveals the config; no need to sweep every method on every path.',
  },
  'exploit-attempt': {
    label: 'Active exploitation attempt', category: 'exploit', loudness: 5, attribution: 'high',
    signals: [
      'Malformed / injection payloads in requests (SQLi, traversal, deserialization) that WAFs and app logs capture verbatim',
      'Application errors / stack traces / 500s spiking around the attempt',
      'On success, an anomalous process, request, or auth event on the target',
    ],
    detectedBy: ['WAF (payload signatures)', 'Application error logs', 'EDR / host telemetry', 'SIEM correlation'],
    exposes: ['Source IP', 'Exact payloads (fully attributable)', 'Target + technique'],
    quieter: 'Gate on a HIGH-confidence, confirmed finding; land the minimum proof rather than spraying payloads. This phase is HITL-gated for exactly this reason.',
  },
  'auth-attempt': {
    label: 'Authentication attempt (credential use)', category: 'exploit', loudness: 4, attribution: 'high',
    signals: ['Authentication events — successes and especially failures — in the app / OS / IdP logs', 'Repeated failures trip lockout and brute-force alerts'],
    detectedBy: ['Auth logs (Windows 4625/4624, SSH, app login)', 'IdP / SIEM brute-force rules', 'Account-lockout policies'],
    exposes: ['Source IP', 'Usernames tried', 'Credential source'],
    quieter: 'Use credentials you have legitimately recovered against the specific account; avoid spraying, which is the loudest possible auth pattern and risks locking out real users.',
  },
  'file-drop': {
    label: 'Artifact written to a target host', category: 'post-ex', loudness: 4, attribution: 'high',
    signals: ['A new file on disk (EDR file-create event)', 'If executed, a new process lineage'],
    detectedBy: ['EDR / AV (file + process)', 'File-integrity monitoring', 'Host audit logs'],
    exposes: ['The artifact itself (recoverable forensic evidence)', 'Path, timestamp, and content'],
    quieter: 'Drop the smallest possible proof, in an agreed location, and record it for cleanup immediately — VARVEL’s OPSEC ledger tracks it so it is removed on disengagement.',
  },
  'content-modify': {
    label: 'Target content / data modification', category: 'post-ex', loudness: 4, attribution: 'high',
    signals: ['A write/PUT/POST/DELETE that changes state', 'The changed content itself, plus its access-log entry and any app audit trail'],
    detectedBy: ['Application audit logs', 'File-integrity / change monitoring', 'The change being visible to users'],
    exposes: ['Exact change made (fully attributable)', 'Source IP', 'Timestamp'],
    quieter: 'Make the minimum reversible change needed to prove impact (e.g. a benign marker), record the original + a revert step, and clean it up. Never touch real user data.',
  },
  'pivot': {
    label: 'Lateral movement / pivot', category: 'post-ex', loudness: 5, attribution: 'high',
    signals: ['A new internal connection between hosts that don’t normally talk', 'Remote-exec / new-session events on the second host'],
    detectedBy: ['Internal NetFlow / east-west monitoring', 'EDR (remote-exec, new logon)', 'SIEM lateral-movement correlation'],
    exposes: ['Both host IPs', 'The reused credential / route', 'Timing linking the two'],
    quieter: 'Pivot only when the engagement objective requires proving reach; document the single route rather than exploring broadly.',
  },
  'egress': {
    label: 'Outbound connection from a target', category: 'post-ex', loudness: 4, attribution: 'high',
    signals: ['An outbound connection to an external IP from a host that normally has none', 'Beacon-like periodic timing if repeated'],
    detectedBy: ['Egress firewall / proxy logs', 'NetFlow beacon analytics', 'DNS exfil detection'],
    exposes: ['The external endpoint (your infrastructure)', 'Timing pattern'],
    quieter: 'On a governed engagement, egress is deny-by-default at the Enclave; keep proof of exfil to a minimal, in-scope demonstration.',
  },
};

// Map a raw activity kind (as logged by the campaign) to a footprint id.
const ALIAS = {
  recon: 'tcp-scan', scan: 'tcp-scan', 'port-scan': 'tcp-scan',
  webscan: 'web-content-scan', 'web-scan': 'web-content-scan', content: 'web-content-scan',
  crawl: 'web-crawl', spider: 'web-crawl',
  vuln: 'vuln-check', vulncheck: 'vuln-check', nuclei: 'vuln-check',
  fingerprint: 'http-fingerprint', http: 'http-fingerprint',
  tls: 'tls-probe', dns: 'dns-enum', subdomain: 'subdomain-brute',
  methods: 'http-methods', cors: 'http-methods',
  exploit: 'exploit-attempt', auth: 'auth-attempt', login: 'auth-attempt',
  drop: 'file-drop', artifact: 'file-drop', modify: 'content-modify', write: 'content-modify',
  route: 'pivot', lateral: 'pivot', out: 'egress',
};

export function footprintFor(kind) {
  if (!kind) return null;
  const k = String(kind).toLowerCase();
  const id = FOOTPRINTS[k] ? k : ALIAS[k];
  return id && FOOTPRINTS[id] ? { id, ...FOOTPRINTS[id] } : null;
}

const RISK = (n) => (n >= 4.5 ? 'critical' : n >= 3.5 ? 'high' : n >= 2.5 ? 'elevated' : n >= 1.5 ? 'moderate' : 'low');

// Roll a list of recorded footprint events into an overall detection picture.
// events: [{ id | kind, count?, host? }]
export function scoreFootprint(events) {
  const norm = (Array.isArray(events) ? events : [])
    .map((e) => ({ fp: footprintFor(e.id || e.kind), count: Math.max(1, Number(e.count) || 1), host: e.host }))
    .filter((e) => e.fp);

  if (!norm.length) {
    return { events: 0, peakLoudness: 0, risk: 'none', weighted: 0, detectedBy: [], exposes: [], loudest: [], byCategory: {} };
  }

  const totalCount = norm.reduce((s, e) => s + e.count, 0);
  // Your LOUDEST action sets the exposure floor, so the peak leads; the weighted mean
  // (busier activities count more) modulates it. A single level-5 exploit reads as high
  // risk even amid quiet recon — it can't be hidden by a pile of quiet pings.
  const weightedMean = norm.reduce((s, e) => s + e.fp.loudness * e.count, 0) / totalCount;
  const peak = Math.max(...norm.map((e) => e.fp.loudness));
  const weighted = Math.min(5, peak * 0.55 + weightedMean * 0.45);

  const detectedBy = [...new Set(norm.flatMap((e) => e.fp.detectedBy))];
  const exposes = [...new Set(norm.flatMap((e) => e.fp.exposes))];
  const byCategory = {};
  for (const e of norm) byCategory[e.fp.category] = (byCategory[e.fp.category] || 0) + e.count;

  // Loudest distinct activities, most conspicuous first — each carries its full
  // profile so the report and console can render per-activity detail directly.
  const agg = new Map();
  for (const e of norm) {
    const cur = agg.get(e.fp.id) || { id: e.fp.id, label: e.fp.label, loudness: e.fp.loudness, count: 0, category: e.fp.category, attribution: e.fp.attribution, signals: e.fp.signals, detectedBy: e.fp.detectedBy, exposes: e.fp.exposes, quieter: e.fp.quieter };
    cur.count += e.count; agg.set(e.fp.id, cur);
  }
  const loudest = [...agg.values()].sort((a, b) => b.loudness - a.loudness || b.count - a.count);

  return {
    events: norm.length,
    actions: totalCount,
    peakLoudness: peak,
    weighted: Math.round(weighted * 10) / 10,
    risk: RISK(weighted),
    detectedBy,
    exposes,
    byCategory,
    loudest,
  };
}
