# VARVEL recon tooling

VARVEL ships native, dependency-free recon tools. They are **lenient** (they scan
what they are pointed at — the Enclave governs scope/egress, not the tool) and are
the *integration* layer: everything they find feeds one governed attack-surface.
VARVEL can also orchestrate best-in-class external tools (nmap/nuclei/masscan/etc.)
when deeper coverage is wanted; the native tools guarantee a clean, fast baseline
with fingerprinting many quick scanners lack.

## QA process — adversarial probe audits

Every tool is hardened by an **adversarial probe audit**: a separate agent reads the
tool + its tests, tries to break it with live evidence, and reports concrete bugs +
missing test cases. We fix each confirmed defect and lock it with a regression test.
This is why the tools are trustworthy on real, messy targets — the failure modes
that quick scanners get wrong have been hunted and closed.

| Tool | Audited defects fixed (with regression tests) |
|---|---|
| recon | mmh3 KAT-verified Shodan-compatible; open-port detection latches on connect (connect-then-RST + `timeout<200ms` no longer report live ports closed); dual-stack IPv4/IPv6 targets (bracketed URL forms, canonical redirect compare); strict CIDR validation via shared `engine/ipaddr` (out-of-range octets, leading-zero octal, trailing-slash "match-all", non-numeric mask, family-strict); bounded favicon/body downloads; POP3/redis/HTTP fingerprint fixes |
| webscan | soft-404 baseline + per-signature content validation (no phantom crits on catch-all-200 apps); 2xx-only artifact flagging (3xx redirects are discovery, not exposures); **same-origin enforcement** (a `//other-host` path can't escape the target); segment-anchored signatures (no `.env`-in-`.envelope`); broadened `.git`/`.hg`/`.aws`/actuator/wp-config/`*.sql`; 405 discovery; hard body cap + request deadline |
| dns | **wildcard-DNS baseline filtering** (no more every-guess-is-a-hit on parked/CDN zones); IPv6-only discovery; transient errors surfaced, not hidden as "absent"; pool clamping; resolver validation; IDN/punycode |
| tlsscan | deterministic classifier unit-tested across expired / expiring / self-signed / weak-protocol / hostname-mismatch / wildcard-SAN |

## recon.mjs

TCP-connect scanner + fingerprinter. Capabilities: connect scan (open latched on
handshake), banner grab, **service/version detection** from banner signatures
(nmap `-sV`-lite: ssh/ftp/smtp/redis/http/vnc/pop3/imap + product/version), HTTP
fingerprint (Server/X-Powered-By/title + HSTS/CSP/X-Frame-Options), **TLS certificate
inspection**, and a **Shodan-compatible mmh3 favicon hash** (byte-identical to
`mmh3.hash(base64.encodebytes(favicon))`, KAT-verified). `TOP_PORTS` for deeper
sweeps. `ipInScope(ip, cidrs)` is an exported scope utility.

- **vs nmap:** matches `-sV` for common-service ID; adds favicon-mmh3 + integrated
  surface feed that nmap has natively. Does not reimplement full NSE/OS-detection.
- **Boundary:** discovers + fingerprints. No exploit/implant/evasion. Connect-only
  (no SYN-flood/masscan-style flooding).

## webscan.mjs

Web content discovery + sensitive-exposure detection (`.git`, `.env`, `.aws`,
backups, `wp-config.php`, Spring Actuator, `*.sql`, directory listing). Soft-404
aware, content-validated, same-origin enforced. Comparable to gobuster/ffuf for the
exposure use-case, but feeds the surface directly (they emit raw lists).

## dns.mjs

`dnsRecon(domain)` (A/AAAA/MX/TXT/NS/CNAME/SOA/CAA/SRV) and `subdomainScan(domain)`
(wordlist brute with wildcard filtering + IPv6-only discovery). Injectable resolver
so the enclave can route DNS through a governed resolver. subfinder-brute-class.

## tlsscan.mjs

`analyzeTls(host, port)` negotiates the best protocol, probes for TLS 1.0/1.1
support, and classifies the certificate. `tlsFindings(state)` is a pure, deterministic
classifier. testssl.sh-lite, native.

## httpmethods.mjs

`analyzeHttp(base)` enumerates allowed methods (OPTIONS/Allow), flags dangerous
methods (PUT/DELETE/TRACE/CONNECT/PATCH) + Cross-Site Tracing, detects CORS
misconfigurations (wildcard-with-credentials, arbitrary-origin reflection), and notes
missing security headers. `httpFindings(state)` is a pure classifier. Read-only
probes only (OPTIONS + benign GET; no state-changing method is invoked).

## Wiring

`Campaign` runs the native tools deterministically in `tooledRecon`: port scan →
service/version → HTTP fingerprint → **web content discovery** → **TLS analysis** on
https → **subdomain discovery** (when a domain is given), all feeding the surface.
Reachable via `POST /api/campaign { tooledRecon:true, targets, reconOpts }`.
