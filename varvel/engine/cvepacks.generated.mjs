// VARVEL — GENERATED version→CVE correlation pack (merged by engine/cvepacks.mjs).
//
// /!\ GENERATED FILE — DO NOT HAND-EDIT. It is a versioned build artifact on
// purpose: the repo pins the exact NVD/KEV snapshot the engine reasons over, so
// findings reproduce and pack changes review as ordinary diffs. Regenerate:
//     node tools/cvepack-import.mjs            (cached feeds; monthly refresh)
//     node tools/cvepack-import.mjs --refresh  (re-download the feeds)
//
// Generated: 2026-09-16T22:21:44.608Z by tools/cvepack-import.mjs --years 2016- --max-per-product 200
// Sources (raw bytes cached under data/cvepack-cache/, sha256 in manifest.json):
//   · NVD JSON 2.0 yearly feeds 2016–2026 (11 files), fetched 2026-09-12T13:00:12.856Z (all from cache)
//   · CISA KEV catalog 2026.09.11 (released 2026-09-11T19:32:16.8993Z), fetched 2026-09-12T12:50:38.341Z
//
// Same honesty contract as the curated pack: entries fire ONLY on a fingerprinted
// version, and a version match is confidence firm, never confirmed. Rules enforced
// by the generator (tools/cvepack-import.mjs documents them in full): KEV always
// kept; otherwise CVSS v3 ≥ 7.0 (v2 fallback); ranges come ONLY from NVD CPE match
// nodes — vulnerable:false skipped, negated skipped, unbounded-both-sides skipped,
// non dotted-numeric versions skipped (a range is never guessed); ≤200 entries per
// product, KEV pinned, newest first.
// Entries: 774 across 17 products.

export const GENERATED_CVE_PACKS = {
  "angular": [
    {
      "cve": "CVE-2026-54268",
      "sev": "high",
      "kev": false,
      "title": "Angular is a development platform for building mobile and desktop web applications…",
      "ranges": [
        {
          "lte": "19.2.25"
        },
        {
          "gte": "20.0.0",
          "lt": "20.3.25"
        },
        {
          "gte": "21.0.0",
          "lt": "21.2.17"
        },
        {
          "gte": "22.0.0",
          "lt": "22.0.1"
        }
      ],
      "note": "NVD: Angular is a development platform for building mobile and desktop web applications using TypeScript/JavaScript and other languages."
    },
    {
      "cve": "CVE-2026-50170",
      "sev": "high",
      "kev": false,
      "title": "Angular is a development platform for building mobile and desktop web applications…",
      "ranges": [
        {
          "lte": "18.2.14"
        },
        {
          "gte": "19.0.0",
          "lt": "19.2.23"
        },
        {
          "gte": "20.0.0",
          "lt": "20.3.22"
        },
        {
          "gte": "21.0.0",
          "lt": "21.2.15"
        },
        {
          "eq": "22.0.0"
        }
      ],
      "note": "NVD: Angular is a development platform for building mobile and desktop web applications using TypeScript/JavaScript and other languages."
    },
    {
      "cve": "CVE-2026-50168",
      "sev": "high",
      "kev": false,
      "title": "Angular is a development platform for building mobile and desktop web applications…",
      "ranges": [
        {
          "gte": "2.0.0",
          "lte": "18.2.14"
        },
        {
          "gte": "19.0.0",
          "lt": "19.2.23"
        },
        {
          "gte": "20.0.0",
          "lt": "20.3.22"
        },
        {
          "gte": "21.0.0",
          "lt": "21.2.15"
        },
        {
          "eq": "22.0.0"
        }
      ],
      "note": "NVD: Angular is a development platform for building mobile and desktop web applications using TypeScript/JavaScript and other languages."
    }
  ],
  "apache": [
    {
      "cve": "CVE-2026-49975",
      "sev": "high",
      "kev": false,
      "title": "Memory Allocation with Excessive Size Value vulnerability in Apache HTTP Server's…",
      "ranges": [
        {
          "gte": "2.4.17",
          "lt": "2.4.68"
        }
      ],
      "note": "NVD: Memory Allocation with Excessive Size Value vulnerability in Apache HTTP Server's mod_http leads to denial of service via malicious HTTP requests."
    },
    {
      "cve": "CVE-2026-48913",
      "sev": "high",
      "kev": false,
      "title": "Use After Free vulnerability in Apache HTTP Server module mod_http2 when file handles…",
      "ranges": [
        {
          "gte": "2.4.55",
          "lt": "2.4.68"
        }
      ],
      "note": "NVD: Use After Free vulnerability in Apache HTTP Server module mod_http2 when file handles are already exhausted."
    },
    {
      "cve": "CVE-2026-44631",
      "sev": "critical",
      "kev": false,
      "title": "Buffer Underwrite vulnerability in Apache HTTP Server on crafted regular expressions…",
      "ranges": [
        {
          "gte": "2.4.0",
          "lt": "2.4.68"
        }
      ],
      "note": "NVD: Buffer Underwrite vulnerability in Apache HTTP Server on crafted regular expressions in the configuration."
    },
    {
      "cve": "CVE-2026-44186",
      "sev": "high",
      "kev": false,
      "title": "Loop with Unreachable Exit Condition ('Infinite Loop') vulnerability in the…",
      "ranges": [
        {
          "gte": "2.4.0",
          "lt": "2.4.68"
        }
      ],
      "note": "NVD: Loop with Unreachable Exit Condition ('Infinite Loop') vulnerability in the mod_proxy_ftp module in Apache HTTP Server with an attacker controlled backend FTP…"
    },
    {
      "cve": "CVE-2026-44185",
      "sev": "high",
      "kev": false,
      "title": "Buffer Over-read vulnerability in Apache HTTP Server via outbound OCSP requests to an…",
      "ranges": [
        {
          "gte": "2.4.0",
          "lt": "2.4.68"
        }
      ],
      "note": "NVD: Buffer Over-read vulnerability in Apache HTTP Server via outbound OCSP requests to an attacker controlled OCSP server This issue affects Apache HTTP Server: from…"
    },
    {
      "cve": "CVE-2026-42536",
      "sev": "high",
      "kev": false,
      "title": "Heap-based Buffer Overflow vulnerability in Apache HTTP Server with mod_xml2enc,…",
      "ranges": [
        {
          "gte": "2.4.0",
          "lt": "2.4.68"
        }
      ],
      "note": "NVD: Heap-based Buffer Overflow vulnerability in Apache HTTP Server with mod_xml2enc, xml2StartParse, and untrusted content This issue affects Apache HTTP Server: from…"
    },
    {
      "cve": "CVE-2026-42535",
      "sev": "critical",
      "kev": false,
      "title": "A path handling issue in mod_dav_fs in Apache 2.4.67 and earlier allows a WebDAV…",
      "ranges": [
        {
          "lt": "2.4.68"
        }
      ],
      "note": "NVD: A path handling issue in mod_dav_fs in Apache 2.4.67 and earlier allows a WebDAV content author to directly manipulate trusted DAV property databases, potentially…"
    },
    {
      "cve": "CVE-2026-34356",
      "sev": "high",
      "kev": false,
      "title": "Heap-based Buffer Overflow vulnerability in Apache HTTP Server with malicious backend…",
      "ranges": [
        {
          "gte": "2.4.0",
          "lt": "2.4.68"
        }
      ],
      "note": "NVD: Heap-based Buffer Overflow vulnerability in Apache HTTP Server with malicious backend servers and ProxyPassReverseCookie* This issue affects Apache HTTP Server:…"
    },
    {
      "cve": "CVE-2026-34355",
      "sev": "high",
      "kev": false,
      "title": "A buffer overflow in mod_proxy_html in Apache HTTP Server 2.4.67 and earlier allows an…",
      "ranges": [
        {
          "gte": "2.4.0",
          "lt": "2.4.68"
        }
      ],
      "note": "NVD: A buffer overflow in mod_proxy_html in Apache HTTP Server 2.4.67 and earlier allows an attack by an untrusted backend."
    },
    {
      "cve": "CVE-2026-34059",
      "sev": "high",
      "kev": false,
      "title": "Buffer Over-read vulnerability in Apache HTTP Server.",
      "ranges": [
        {
          "lt": "2.4.67"
        }
      ],
      "note": "NVD: Buffer Over-read vulnerability in Apache HTTP Server."
    },
    {
      "cve": "CVE-2026-29169",
      "sev": "high",
      "kev": false,
      "title": "A NULL pointer dereference in mod_dav_lock in Apache HTTP Server 2.4.66 and earlier…",
      "ranges": [
        {
          "lt": "2.4.67"
        }
      ],
      "note": "NVD: A NULL pointer dereference in mod_dav_lock in Apache HTTP Server 2.4.66 and earlier may allow an attacker to crash the server with a malicious request.mod_dav_lock…"
    },
    {
      "cve": "CVE-2026-29168",
      "sev": "high",
      "kev": false,
      "title": "Allocation of Resources Without Limits or Throttling vulnerability in Apache HTTP…",
      "ranges": [
        {
          "gte": "2.4.30",
          "lt": "2.4.67"
        }
      ],
      "note": "NVD: Allocation of Resources Without Limits or Throttling vulnerability in Apache HTTP Server's mod_md via OCSP response data."
    },
    {
      "cve": "CVE-2026-29167",
      "sev": "critical",
      "kev": false,
      "title": "Use After Free vulnerability in Apache HTTP Server with mod_ldap in per-directory…",
      "ranges": [
        {
          "gte": "2.4.0",
          "lt": "2.4.68"
        }
      ],
      "note": "NVD: Use After Free vulnerability in Apache HTTP Server with mod_ldap in per-directory configuration This issue affects Apache HTTP Server: from 2.4.0 through 2.4.67."
    },
    {
      "cve": "CVE-2026-28780",
      "sev": "critical",
      "kev": false,
      "title": "Heap-based Buffer Overflow vulnerability in mod_proxy_ajp of Apache HTTP Server.",
      "ranges": [
        {
          "lt": "2.4.67"
        }
      ],
      "note": "NVD: Heap-based Buffer Overflow vulnerability in mod_proxy_ajp of Apache HTTP Server."
    },
    {
      "cve": "CVE-2026-24072",
      "sev": "high",
      "kev": false,
      "title": "An escalation of privilege bug in various modules in Apache HTTP 2.4.66 and earlier…",
      "ranges": [
        {
          "lt": "2.4.67"
        }
      ],
      "note": "NVD: An escalation of privilege bug in various modules in Apache HTTP 2.4.66 and earlier allows local .htaccess authors to read files with the privileges of the httpd…"
    },
    {
      "cve": "CVE-2026-23918",
      "sev": "high",
      "kev": false,
      "title": "Double Free and possible RCE vulnerability in Apache HTTP Server with the HTTP/2…",
      "ranges": [
        {
          "eq": "2.4.66"
        }
      ],
      "note": "NVD: Double Free and possible RCE vulnerability in Apache HTTP Server with the HTTP/2 protocol."
    },
    {
      "cve": "CVE-2025-59775",
      "sev": "high",
      "kev": false,
      "title": "Server-Side Request Forgery (SSRF) vulnerability in Apache HTTP Server on Windows with…",
      "ranges": [
        {
          "gte": "2.4.0",
          "lt": "2.4.66"
        }
      ],
      "note": "NVD: Server-Side Request Forgery (SSRF) vulnerability in Apache HTTP Server on Windows with AllowEncodedSlashes On and MergeSlashes Off allows to potentially leak NTLM…"
    },
    {
      "cve": "CVE-2025-58098",
      "sev": "high",
      "kev": false,
      "title": "Apache HTTP Server 2.4.65 and earlier with Server Side Includes (SSI) enabled and…",
      "ranges": [
        {
          "lt": "2.4.66"
        }
      ],
      "note": "NVD: Apache HTTP Server 2.4.65 and earlier with Server Side Includes (SSI) enabled and mod_cgid (but not mod_cgi) passes the shell-escaped query string to #exec…"
    },
    {
      "cve": "CVE-2025-55753",
      "sev": "high",
      "kev": false,
      "title": "An integer overflow in the case of failed ACME certificate renewal leads, after a…",
      "ranges": [
        {
          "gte": "2.4.30",
          "lt": "2.4.66"
        }
      ],
      "note": "NVD: An integer overflow in the case of failed ACME certificate renewal leads, after a number of failures (~30 days in default configurations), to the backoff timer…"
    },
    {
      "cve": "CVE-2025-53020",
      "sev": "high",
      "kev": false,
      "title": "Late Release of Memory after Effective Lifetime vulnerability in Apache HTTP Server.",
      "ranges": [
        {
          "gte": "2.4.17",
          "lt": "2.4.64"
        }
      ],
      "note": "NVD: Late Release of Memory after Effective Lifetime vulnerability in Apache HTTP Server."
    },
    {
      "cve": "CVE-2025-49812",
      "sev": "high",
      "kev": false,
      "title": "In some mod_ssl configurations on Apache HTTP Server versions through to 2.4.63, an…",
      "ranges": [
        {
          "lt": "2.4.64"
        }
      ],
      "note": "NVD: In some mod_ssl configurations on Apache HTTP Server versions through to 2.4.63, an HTTP desynchronisation attack allows a man-in-the-middle attacker to hijack an…"
    },
    {
      "cve": "CVE-2025-49630",
      "sev": "high",
      "kev": false,
      "title": "In certain proxy configurations, a denial of service attack against Apache HTTP Server…",
      "ranges": [
        {
          "gte": "2.4.26",
          "lt": "2.4.64"
        }
      ],
      "note": "NVD: In certain proxy configurations, a denial of service attack against Apache HTTP Server versions 2.4.26 through to 2.4.63 can be triggered by untrusted clients…"
    },
    {
      "cve": "CVE-2025-23048",
      "sev": "critical",
      "kev": false,
      "title": "In some mod_ssl configurations on Apache HTTP Server 2.4.35 through to 2.4.63, an…",
      "ranges": [
        {
          "gte": "2.4.35",
          "lt": "2.4.64"
        }
      ],
      "note": "NVD: In some mod_ssl configurations on Apache HTTP Server 2.4.35 through to 2.4.63, an access control bypass by trusted clients is possible using TLS 1.3 session…"
    },
    {
      "cve": "CVE-2024-47252",
      "sev": "high",
      "kev": false,
      "title": "Insufficient escaping of user-supplied data in mod_ssl in Apache HTTP Server 2.4.63…",
      "ranges": [
        {
          "gte": "2.4.0",
          "lt": "2.4.64"
        }
      ],
      "note": "NVD: Insufficient escaping of user-supplied data in mod_ssl in Apache HTTP Server 2.4.63 and earlier allows an untrusted SSL/TLS client to insert escape characters into…"
    },
    {
      "cve": "CVE-2024-43394",
      "sev": "high",
      "kev": false,
      "title": "Server-Side Request Forgery (SSRF) in Apache HTTP Server on Windows allows to…",
      "ranges": [
        {
          "gte": "2.4.0",
          "lt": "2.4.64"
        }
      ],
      "note": "NVD: Server-Side Request Forgery (SSRF) in Apache HTTP Server on Windows allows to potentially leak NTLM hashes to a malicious server via mod_rewrite or apache…"
    },
    {
      "cve": "CVE-2024-43204",
      "sev": "high",
      "kev": false,
      "title": "SSRF in Apache HTTP Server with mod_proxy loaded allows an attacker to send outbound…",
      "ranges": [
        {
          "gte": "2.4.0",
          "lt": "2.4.64"
        }
      ],
      "note": "NVD: SSRF in Apache HTTP Server with mod_proxy loaded allows an attacker to send outbound proxy requests to a URL controlled by the attacker."
    },
    {
      "cve": "CVE-2024-42516",
      "sev": "high",
      "kev": false,
      "title": "HTTP response splitting in the core of Apache HTTP Server allows an attacker who can…",
      "ranges": [
        {
          "gte": "2.4.0",
          "lt": "2.4.64"
        }
      ],
      "note": "NVD: HTTP response splitting in the core of Apache HTTP Server allows an attacker who can manipulate the Content-Type response headers of applications hosted or proxied…"
    },
    {
      "cve": "CVE-2024-40898",
      "sev": "high",
      "kev": false,
      "title": "SSRF in Apache HTTP Server on Windows with mod_rewrite in server/vhost context, allows…",
      "ranges": [
        {
          "lt": "2.4.62"
        }
      ],
      "note": "NVD: SSRF in Apache HTTP Server on Windows with mod_rewrite in server/vhost context, allows to potentially leak NTML hashes to a malicious server via SSRF and malicious…"
    },
    {
      "cve": "CVE-2024-39573",
      "sev": "high",
      "kev": false,
      "title": "Potential SSRF in mod_rewrite in Apache HTTP Server 2.4.59 and earlier allows an…",
      "ranges": [
        {
          "gte": "2.4.0",
          "lt": "2.4.60"
        }
      ],
      "note": "NVD: Potential SSRF in mod_rewrite in Apache HTTP Server 2.4.59 and earlier allows an attacker to cause unsafe RewriteRules to unexpectedly setup URL's to be handled by…"
    },
    {
      "cve": "CVE-2024-38477",
      "sev": "high",
      "kev": false,
      "title": "null pointer dereference in mod_proxy in Apache HTTP Server 2.4.59 and earlier allows…",
      "ranges": [
        {
          "gte": "2.4.0",
          "lt": "2.4.60"
        }
      ],
      "note": "NVD: null pointer dereference in mod_proxy in Apache HTTP Server 2.4.59 and earlier allows an attacker to crash the server via a malicious request."
    },
    {
      "cve": "CVE-2024-38476",
      "sev": "critical",
      "kev": false,
      "title": "Vulnerability in core of Apache HTTP Server 2.4.59 and earlier are vulnerably to…",
      "ranges": [
        {
          "gte": "2.4.0",
          "lt": "2.4.60"
        }
      ],
      "note": "NVD: Vulnerability in core of Apache HTTP Server 2.4.59 and earlier are vulnerably to information disclosure, SSRF or local script execution via backend applications…"
    },
    {
      "cve": "CVE-2024-38475",
      "sev": "critical",
      "kev": true,
      "title": "Improper escaping of output in mod_rewrite in Apache HTTP Server 2.4.59 and earlier…",
      "ranges": [
        {
          "gte": "2.4.0",
          "lt": "2.4.60"
        }
      ],
      "note": "NVD: Improper escaping of output in mod_rewrite in Apache HTTP Server 2.4.59 and earlier allows an attacker to map URLs to filesystem… — CISA KEV (actively exploited)"
    },
    {
      "cve": "CVE-2024-38474",
      "sev": "critical",
      "kev": false,
      "title": "Substitution encoding issue in mod_rewrite in Apache HTTP Server 2.4.59 and earlier…",
      "ranges": [
        {
          "gte": "2.4.0",
          "lt": "2.4.60"
        }
      ],
      "note": "NVD: Substitution encoding issue in mod_rewrite in Apache HTTP Server 2.4.59 and earlier allows attacker to execute scripts in directories permitted by the…"
    },
    {
      "cve": "CVE-2024-38473",
      "sev": "high",
      "kev": false,
      "title": "Encoding problem in mod_proxy in Apache HTTP Server 2.4.59 and earlier allows request…",
      "ranges": [
        {
          "gte": "2.4.0",
          "lt": "2.4.60"
        }
      ],
      "note": "NVD: Encoding problem in mod_proxy in Apache HTTP Server 2.4.59 and earlier allows request URLs with incorrect encoding to be sent to backend services, potentially…"
    },
    {
      "cve": "CVE-2024-38472",
      "sev": "high",
      "kev": false,
      "title": "SSRF in Apache HTTP Server on Windows allows to potentially leak NTLM hashes to a…",
      "ranges": [
        {
          "gte": "2.4.0",
          "lt": "2.4.60"
        }
      ],
      "note": "NVD: SSRF in Apache HTTP Server on Windows allows to potentially leak NTLM hashes to a malicious server via SSRF and malicious requests or content Users are recommended…"
    },
    {
      "cve": "CVE-2024-27316",
      "sev": "high",
      "kev": false,
      "title": "HTTP/2 incoming headers exceeding the limit are temporarily buffered in nghttp2 in…",
      "ranges": [
        {
          "gte": "2.4.17",
          "lt": "2.4.59"
        }
      ],
      "note": "NVD: HTTP/2 incoming headers exceeding the limit are temporarily buffered in nghttp2 in order to generate an informative HTTP 413 response."
    },
    {
      "cve": "CVE-2023-43622",
      "sev": "high",
      "kev": false,
      "title": "An attacker, opening a HTTP/2 connection with an initial window size of 0, was able to…",
      "ranges": [
        {
          "gte": "2.4.55",
          "lt": "2.4.58"
        }
      ],
      "note": "NVD: An attacker, opening a HTTP/2 connection with an initial window size of 0, was able to block handling of that connection indefinitely in Apache HTTP Server."
    },
    {
      "cve": "CVE-2023-38709",
      "sev": "high",
      "kev": false,
      "title": "Faulty input validation in the core of Apache allows malicious or exploitable…",
      "ranges": [
        {
          "lt": "2.4.59"
        }
      ],
      "note": "NVD: Faulty input validation in the core of Apache allows malicious or exploitable backend/content generators to split HTTP responses."
    },
    {
      "cve": "CVE-2023-31122",
      "sev": "high",
      "kev": false,
      "title": "Out-of-bounds Read vulnerability in mod_macro of Apache HTTP Server.This issue affects…",
      "ranges": [
        {
          "lt": "2.4.58"
        }
      ],
      "note": "NVD: Out-of-bounds Read vulnerability in mod_macro of Apache HTTP Server.This issue affects Apache HTTP Server: through 2.4.57."
    },
    {
      "cve": "CVE-2023-27522",
      "sev": "high",
      "kev": false,
      "title": "HTTP Response Smuggling vulnerability in Apache HTTP Server via mod_proxy_uwsgi.",
      "ranges": [
        {
          "gte": "2.4.30",
          "lt": "2.4.56"
        }
      ],
      "note": "NVD: HTTP Response Smuggling vulnerability in Apache HTTP Server via mod_proxy_uwsgi."
    },
    {
      "cve": "CVE-2023-25690",
      "sev": "critical",
      "kev": false,
      "title": "Some mod_proxy configurations on Apache HTTP Server versions 2.4.0 through 2.4.55…",
      "ranges": [
        {
          "gte": "2.4.0",
          "lte": "2.4.55"
        }
      ],
      "note": "NVD: Some mod_proxy configurations on Apache HTTP Server versions 2.4.0 through 2.4.55 allow a HTTP Request Smuggling attack."
    },
    {
      "cve": "CVE-2022-36760",
      "sev": "critical",
      "kev": false,
      "title": "Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling') vulnerability…",
      "ranges": [
        {
          "gte": "2.4.0",
          "lt": "2.4.55"
        }
      ],
      "note": "NVD: Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling') vulnerability in mod_proxy_ajp of Apache HTTP Server allows an attacker to smuggle requests…"
    },
    {
      "cve": "CVE-2022-31813",
      "sev": "critical",
      "kev": false,
      "title": "Apache HTTP Server 2.4.53 and earlier may not send the X-Forwarded-* headers to the…",
      "ranges": [
        {
          "lt": "2.4.54"
        }
      ],
      "note": "NVD: Apache HTTP Server 2.4.53 and earlier may not send the X-Forwarded-* headers to the origin server based on client side Connection header hop-by-hop mechanism."
    },
    {
      "cve": "CVE-2022-30556",
      "sev": "high",
      "kev": false,
      "title": "Apache HTTP Server 2.4.53 and earlier may return lengths to applications calling…",
      "ranges": [
        {
          "lt": "2.4.54"
        }
      ],
      "note": "NVD: Apache HTTP Server 2.4.53 and earlier may return lengths to applications calling r:wsread() that point past the end of the storage allocated for the buffer."
    },
    {
      "cve": "CVE-2022-30522",
      "sev": "high",
      "kev": false,
      "title": "If Apache HTTP Server 2.4.53 is configured to do transformations with mod_sed in…",
      "ranges": [
        {
          "eq": "2.4.53"
        }
      ],
      "note": "NVD: If Apache HTTP Server 2.4.53 is configured to do transformations with mod_sed in contexts where the input to mod_sed may be very large, mod_sed may make…"
    },
    {
      "cve": "CVE-2022-29404",
      "sev": "high",
      "kev": false,
      "title": "In Apache HTTP Server 2.4.53 and earlier, a malicious request to a lua script that…",
      "ranges": [
        {
          "lte": "2.4.53"
        }
      ],
      "note": "NVD: In Apache HTTP Server 2.4.53 and earlier, a malicious request to a lua script that calls r:parsebody(0) may cause a denial of service due to no default limit on…"
    },
    {
      "cve": "CVE-2022-28615",
      "sev": "critical",
      "kev": false,
      "title": "Apache HTTP Server 2.4.53 and earlier may crash or disclose information due to a read…",
      "ranges": [
        {
          "lt": "2.4.54"
        }
      ],
      "note": "NVD: Apache HTTP Server 2.4.53 and earlier may crash or disclose information due to a read beyond bounds in ap_strcmp_match() when provided with an extremely large…"
    },
    {
      "cve": "CVE-2022-26377",
      "sev": "high",
      "kev": false,
      "title": "Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling') vulnerability…",
      "ranges": [
        {
          "gte": "2.4.0",
          "lt": "2.4.54"
        }
      ],
      "note": "NVD: Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling') vulnerability in mod_proxy_ajp of Apache HTTP Server allows an attacker to smuggle requests…"
    },
    {
      "cve": "CVE-2022-23943",
      "sev": "critical",
      "kev": false,
      "title": "Out-of-bounds Write vulnerability in mod_sed of Apache HTTP Server allows an attacker…",
      "ranges": [
        {
          "gte": "2.4.0",
          "lt": "2.4.53"
        }
      ],
      "note": "NVD: Out-of-bounds Write vulnerability in mod_sed of Apache HTTP Server allows an attacker to overwrite heap memory with possibly attacker provided data."
    },
    {
      "cve": "CVE-2022-22721",
      "sev": "critical",
      "kev": false,
      "title": "If LimitXMLRequestBody is set to allow request bodies larger than 350MB (defaults to…",
      "ranges": [
        {
          "lte": "2.4.52"
        }
      ],
      "note": "NVD: If LimitXMLRequestBody is set to allow request bodies larger than 350MB (defaults to 1M) on 32 bit systems an integer overflow happens which later causes out of…"
    },
    {
      "cve": "CVE-2022-22720",
      "sev": "critical",
      "kev": false,
      "title": "Apache HTTP Server 2.4.52 and earlier fails to close inbound connection when errors…",
      "ranges": [
        {
          "lte": "2.4.52"
        }
      ],
      "note": "NVD: Apache HTTP Server 2.4.52 and earlier fails to close inbound connection when errors are encountered discarding the request body, exposing the server to HTTP…"
    },
    {
      "cve": "CVE-2022-22719",
      "sev": "high",
      "kev": false,
      "title": "A carefully crafted request body can cause a read to a random memory area which could…",
      "ranges": [
        {
          "lte": "2.4.52"
        }
      ],
      "note": "NVD: A carefully crafted request body can cause a read to a random memory area which could cause the process to crash."
    },
    {
      "cve": "CVE-2021-44790",
      "sev": "critical",
      "kev": false,
      "title": "A carefully crafted request body can cause a buffer overflow in the mod_lua multipart…",
      "ranges": [
        {
          "lt": "2.4.52"
        }
      ],
      "note": "NVD: A carefully crafted request body can cause a buffer overflow in the mod_lua multipart parser (r:parsebody() called from Lua scripts)."
    },
    {
      "cve": "CVE-2021-44224",
      "sev": "high",
      "kev": false,
      "title": "A crafted URI sent to httpd configured as a forward proxy (ProxyRequests on) can cause…",
      "ranges": [
        {
          "gte": "2.4.7",
          "lt": "2.4.52"
        }
      ],
      "note": "NVD: A crafted URI sent to httpd configured as a forward proxy (ProxyRequests on) can cause a crash (NULL pointer dereference) or, for configurations mixing forward and…"
    },
    {
      "cve": "CVE-2021-42013",
      "sev": "critical",
      "kev": true,
      "title": "It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was…",
      "ranges": [
        {
          "eq": "2.4.49"
        },
        {
          "eq": "2.4.50"
        }
      ],
      "note": "NVD: It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. — CISA KEV (actively exploited)"
    },
    {
      "cve": "CVE-2021-41773",
      "sev": "critical",
      "kev": true,
      "title": "A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49.",
      "ranges": [
        {
          "eq": "2.4.49"
        }
      ],
      "note": "NVD: A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. — CISA KEV (actively exploited)"
    },
    {
      "cve": "CVE-2021-41524",
      "sev": "high",
      "kev": false,
      "title": "While fuzzing the 2.4.49 httpd, a new null pointer dereference was detected during…",
      "ranges": [
        {
          "eq": "2.4.49"
        }
      ],
      "note": "NVD: While fuzzing the 2.4.49 httpd, a new null pointer dereference was detected during HTTP/2 request processing, allowing an external source to DoS the server."
    },
    {
      "cve": "CVE-2021-40438",
      "sev": "critical",
      "kev": true,
      "title": "A crafted request uri-path can cause mod_proxy to forward the request to an origin…",
      "ranges": [
        {
          "lte": "2.4.48"
        }
      ],
      "note": "NVD: A crafted request uri-path can cause mod_proxy to forward the request to an origin server choosen by the remote user. — CISA KEV (actively exploited)"
    },
    {
      "cve": "CVE-2021-39275",
      "sev": "critical",
      "kev": false,
      "title": "ap_escape_quotes() may write beyond the end of a buffer when given malicious input.",
      "ranges": [
        {
          "lt": "2.4.49"
        }
      ],
      "note": "NVD: ap_escape_quotes() may write beyond the end of a buffer when given malicious input."
    },
    {
      "cve": "CVE-2021-36160",
      "sev": "high",
      "kev": false,
      "title": "A carefully crafted request uri-path can cause mod_proxy_uwsgi to read above the…",
      "ranges": [
        {
          "gte": "2.4.30",
          "lt": "2.4.49"
        }
      ],
      "note": "NVD: A carefully crafted request uri-path can cause mod_proxy_uwsgi to read above the allocated memory and crash (DoS)."
    },
    {
      "cve": "CVE-2021-34798",
      "sev": "high",
      "kev": false,
      "title": "Malformed requests may cause the server to dereference a NULL pointer.",
      "ranges": [
        {
          "lte": "2.4.48"
        }
      ],
      "note": "NVD: Malformed requests may cause the server to dereference a NULL pointer."
    },
    {
      "cve": "CVE-2021-33193",
      "sev": "high",
      "kev": false,
      "title": "A crafted method sent through HTTP/2 will bypass validation and be forwarded by…",
      "ranges": [
        {
          "gte": "2.4.17",
          "lt": "2.4.49"
        }
      ],
      "note": "NVD: A crafted method sent through HTTP/2 will bypass validation and be forwarded by mod_proxy, which can lead to request splitting or cache poisoning."
    },
    {
      "cve": "CVE-2021-31618",
      "sev": "high",
      "kev": false,
      "title": "Apache HTTP Server protocol handler for the HTTP/2 protocol checks received request…",
      "ranges": [
        {
          "eq": "1.15.17"
        },
        {
          "eq": "2.4.47"
        }
      ],
      "note": "NVD: Apache HTTP Server protocol handler for the HTTP/2 protocol checks received request headers against the size limitations as configured for the server and used for…"
    },
    {
      "cve": "CVE-2021-26691",
      "sev": "critical",
      "kev": false,
      "title": "In Apache HTTP Server versions 2.4.0 to 2.4.46 a specially crafted SessionHeader sent…",
      "ranges": [
        {
          "gte": "2.4.0",
          "lte": "2.4.46"
        }
      ],
      "note": "NVD: In Apache HTTP Server versions 2.4.0 to 2.4.46 a specially crafted SessionHeader sent by an origin server could cause a heap overflow"
    },
    {
      "cve": "CVE-2021-26690",
      "sev": "high",
      "kev": false,
      "title": "Apache HTTP Server versions 2.4.0 to 2.4.46 A specially crafted Cookie header handled…",
      "ranges": [
        {
          "gte": "2.4.0",
          "lte": "2.4.46"
        }
      ],
      "note": "NVD: Apache HTTP Server versions 2.4.0 to 2.4.46 A specially crafted Cookie header handled by mod_session can cause a NULL pointer dereference and crash, leading to a…"
    },
    {
      "cve": "CVE-2020-35452",
      "sev": "high",
      "kev": false,
      "title": "Apache HTTP Server versions 2.4.0 to 2.4.46 A specially crafted Digest nonce can cause…",
      "ranges": [
        {
          "gte": "2.4.0",
          "lte": "2.4.46"
        }
      ],
      "note": "NVD: Apache HTTP Server versions 2.4.0 to 2.4.46 A specially crafted Digest nonce can cause a stack overflow in mod_auth_digest."
    },
    {
      "cve": "CVE-2020-13950",
      "sev": "high",
      "kev": false,
      "title": "Apache HTTP Server versions 2.4.41 to 2.4.46 mod_proxy_http can be made to crash (NULL…",
      "ranges": [
        {
          "gte": "2.4.41",
          "lte": "2.4.46"
        }
      ],
      "note": "NVD: Apache HTTP Server versions 2.4.41 to 2.4.46 mod_proxy_http can be made to crash (NULL pointer dereference) with specially crafted requests using both…"
    },
    {
      "cve": "CVE-2020-11993",
      "sev": "high",
      "kev": false,
      "title": "Apache HTTP Server versions 2.4.20 to 2.4.43 When trace/debug was enabled for the…",
      "ranges": [
        {
          "gte": "2.4.20",
          "lt": "2.4.44"
        }
      ],
      "note": "NVD: Apache HTTP Server versions 2.4.20 to 2.4.43 When trace/debug was enabled for the HTTP/2 module and on certain traffic edge patterns, logging statements were made…"
    },
    {
      "cve": "CVE-2020-11984",
      "sev": "critical",
      "kev": false,
      "title": "Apache HTTP server 2.4.32 to 2.4.44 mod_proxy_uwsgi info disclosure and possible RCE",
      "ranges": [
        {
          "gte": "2.4.32",
          "lte": "2.4.43"
        }
      ],
      "note": "NVD: Apache HTTP server 2.4.32 to 2.4.44 mod_proxy_uwsgi info disclosure and possible RCE"
    },
    {
      "cve": "CVE-2020-9490",
      "sev": "high",
      "kev": false,
      "title": "Apache HTTP Server versions 2.4.20 to 2.4.43.",
      "ranges": [
        {
          "gte": "2.4.20",
          "lt": "2.4.46"
        }
      ],
      "note": "NVD: Apache HTTP Server versions 2.4.20 to 2.4.43."
    },
    {
      "cve": "CVE-2019-10097",
      "sev": "high",
      "kev": false,
      "title": "In Apache HTTP Server 2.4.32-2.4.39, when mod_remoteip was configured to use a trusted…",
      "ranges": [
        {
          "eq": "2.4.33"
        },
        {
          "eq": "2.4.34"
        },
        {
          "eq": "2.4.35"
        },
        {
          "eq": "2.4.37"
        },
        {
          "eq": "2.4.38"
        }
      ],
      "note": "NVD: In Apache HTTP Server 2.4.32-2.4.39, when mod_remoteip was configured to use a trusted intermediary proxy server using the \"PROXY\" protocol, a specially crafted…"
    },
    {
      "cve": "CVE-2019-10082",
      "sev": "critical",
      "kev": false,
      "title": "In Apache HTTP Server 2.4.18-2.4.39, using fuzzed network input, the http/2 session…",
      "ranges": [
        {
          "gte": "2.4.18",
          "lte": "2.4.39"
        }
      ],
      "note": "NVD: In Apache HTTP Server 2.4.18-2.4.39, using fuzzed network input, the http/2 session handling could be made to read memory after being freed, during connection…"
    },
    {
      "cve": "CVE-2019-10081",
      "sev": "high",
      "kev": false,
      "title": "HTTP/2 (2.4.20 through 2.4.39) very early pushes, for example configured with…",
      "ranges": [
        {
          "gte": "2.4.20",
          "lte": "2.4.39"
        }
      ],
      "note": "NVD: HTTP/2 (2.4.20 through 2.4.39) very early pushes, for example configured with \"H2PushResource\", could lead to an overwrite of memory in the pushing request's pool,…"
    },
    {
      "cve": "CVE-2019-9517",
      "sev": "high",
      "kev": false,
      "title": "Some HTTP/2 implementations are vulnerable to unconstrained interal data buffering,…",
      "ranges": [
        {
          "gte": "2.4.20",
          "lt": "2.4.40"
        }
      ],
      "note": "NVD: Some HTTP/2 implementations are vulnerable to unconstrained interal data buffering, potentially leading to a denial of service."
    },
    {
      "cve": "CVE-2019-0217",
      "sev": "high",
      "kev": false,
      "title": "In Apache HTTP Server 2.4 release 2.4.38 and prior, a race condition in…",
      "ranges": [
        {
          "gte": "2.4.0",
          "lte": "2.4.38"
        }
      ],
      "note": "NVD: In Apache HTTP Server 2.4 release 2.4.38 and prior, a race condition in mod_auth_digest when running in a threaded server could allow a user with valid credentials…"
    },
    {
      "cve": "CVE-2019-0215",
      "sev": "high",
      "kev": false,
      "title": "In Apache HTTP Server 2.4 releases 2.4.37 and 2.4.38, a bug in mod_ssl when using…",
      "ranges": [
        {
          "eq": "2.4.37"
        },
        {
          "eq": "2.4.38"
        }
      ],
      "note": "NVD: In Apache HTTP Server 2.4 releases 2.4.37 and 2.4.38, a bug in mod_ssl when using per-location client certificate verification with TLSv1.3 allowed a client to…"
    },
    {
      "cve": "CVE-2019-0211",
      "sev": "high",
      "kev": true,
      "title": "In Apache HTTP Server 2.4 releases 2.4.17 to 2.4.38, with MPM event, worker or…",
      "ranges": [
        {
          "gte": "2.4.17",
          "lte": "2.4.38"
        }
      ],
      "note": "NVD: In Apache HTTP Server 2.4 releases 2.4.17 to 2.4.38, with MPM event, worker or prefork, code executing in less-privileged child… — CISA KEV (actively exploited)"
    },
    {
      "cve": "CVE-2019-0190",
      "sev": "high",
      "kev": false,
      "title": "A bug exists in the way mod_ssl handled client renegotiations.",
      "ranges": [
        {
          "eq": "2.4.37"
        }
      ],
      "note": "NVD: A bug exists in the way mod_ssl handled client renegotiations."
    },
    {
      "cve": "CVE-2018-17199",
      "sev": "high",
      "kev": false,
      "title": "In Apache HTTP Server 2.4 release 2.4.37 and prior, mod_session checks the session…",
      "ranges": [
        {
          "gte": "2.4.0",
          "lte": "2.4.37"
        }
      ],
      "note": "NVD: In Apache HTTP Server 2.4 release 2.4.37 and prior, mod_session checks the session expiry time before decoding the session."
    },
    {
      "cve": "CVE-2018-8011",
      "sev": "high",
      "kev": false,
      "title": "By specially crafting HTTP requests, the mod_md challenge handler would dereference a…",
      "ranges": [
        {
          "eq": "2.4.33"
        }
      ],
      "note": "NVD: By specially crafting HTTP requests, the mod_md challenge handler would dereference a NULL pointer and cause the child process to segfault."
    },
    {
      "cve": "CVE-2018-1333",
      "sev": "high",
      "kev": false,
      "title": "By specially crafting HTTP/2 requests, workers would be allocated 60 seconds longer…",
      "ranges": [
        {
          "gte": "2.4.18",
          "lte": "2.4.30"
        },
        {
          "eq": "2.4.33"
        }
      ],
      "note": "NVD: By specially crafting HTTP/2 requests, workers would be allocated 60 seconds longer than necessary, leading to worker exhaustion and a denial of service."
    },
    {
      "cve": "CVE-2018-1312",
      "sev": "critical",
      "kev": false,
      "title": "In Apache httpd 2.2.0 to 2.4.29, when generating an HTTP Digest authentication…",
      "ranges": [
        {
          "eq": "2.4.1"
        },
        {
          "eq": "2.4.2"
        },
        {
          "eq": "2.4.3"
        },
        {
          "eq": "2.4.4"
        },
        {
          "eq": "2.4.6"
        },
        {
          "eq": "2.4.7"
        },
        {
          "eq": "2.4.9"
        },
        {
          "eq": "2.4.10"
        },
        {
          "eq": "2.4.12"
        },
        {
          "eq": "2.4.16"
        },
        {
          "eq": "2.4.17"
        },
        {
          "eq": "2.4.18"
        },
        {
          "eq": "2.4.20"
        },
        {
          "eq": "2.4.23"
        },
        {
          "eq": "2.4.25"
        },
        {
          "eq": "2.4.26"
        },
        {
          "eq": "2.4.27"
        },
        {
          "eq": "2.4.28"
        },
        {
          "eq": "2.4.29"
        }
      ],
      "note": "NVD: In Apache httpd 2.2.0 to 2.4.29, when generating an HTTP Digest authentication challenge, the nonce sent to prevent reply attacks was not correctly generated using…"
    },
    {
      "cve": "CVE-2018-1303",
      "sev": "high",
      "kev": false,
      "title": "A specially crafted HTTP request header could have crashed the Apache HTTP Server…",
      "ranges": [
        {
          "lte": "2.4.29"
        }
      ],
      "note": "NVD: A specially crafted HTTP request header could have crashed the Apache HTTP Server prior to version 2.4.30 due to an out of bound read while preparing data to be…"
    },
    {
      "cve": "CVE-2017-15715",
      "sev": "high",
      "kev": false,
      "title": "In Apache httpd 2.4.0 to 2.4.29, the expression specified in <FilesMatch> could match…",
      "ranges": [
        {
          "gte": "2.4.0",
          "lte": "2.4.29"
        }
      ],
      "note": "NVD: In Apache httpd 2.4.0 to 2.4.29, the expression specified in <FilesMatch> could match '$' to a newline character in a malicious filename, rather than matching only…"
    },
    {
      "cve": "CVE-2017-15710",
      "sev": "high",
      "kev": false,
      "title": "In Apache httpd 2.0.23 to 2.0.65, 2.2.0 to 2.2.34, and 2.4.0 to 2.4.29,…",
      "ranges": [
        {
          "eq": "2.4.1"
        },
        {
          "eq": "2.4.2"
        },
        {
          "eq": "2.4.3"
        },
        {
          "eq": "2.4.4"
        },
        {
          "eq": "2.4.6"
        },
        {
          "eq": "2.4.7"
        },
        {
          "eq": "2.4.9"
        },
        {
          "eq": "2.4.10"
        },
        {
          "eq": "2.4.12"
        },
        {
          "eq": "2.4.16"
        },
        {
          "eq": "2.4.17"
        },
        {
          "eq": "2.4.18"
        },
        {
          "eq": "2.4.20"
        },
        {
          "eq": "2.4.23"
        },
        {
          "eq": "2.4.25"
        },
        {
          "eq": "2.4.26"
        },
        {
          "eq": "2.4.27"
        },
        {
          "eq": "2.4.28"
        },
        {
          "eq": "2.4.29"
        }
      ],
      "note": "NVD: In Apache httpd 2.0.23 to 2.0.65, 2.2.0 to 2.2.34, and 2.4.0 to 2.4.29, mod_authnz_ldap, if configured with AuthLDAPCharsetConfig, uses the Accept-Language header…"
    },
    {
      "cve": "CVE-2017-9798",
      "sev": "high",
      "kev": false,
      "title": "Apache httpd allows remote attackers to read secret data from process memory if the…",
      "ranges": [
        {
          "lte": "2.2.34"
        },
        {
          "eq": "2.4.0"
        },
        {
          "eq": "2.4.1"
        },
        {
          "eq": "2.4.2"
        },
        {
          "eq": "2.4.3"
        },
        {
          "eq": "2.4.4"
        },
        {
          "eq": "2.4.6"
        },
        {
          "eq": "2.4.7"
        },
        {
          "eq": "2.4.9"
        },
        {
          "eq": "2.4.10"
        },
        {
          "eq": "2.4.12"
        },
        {
          "eq": "2.4.16"
        },
        {
          "eq": "2.4.17"
        },
        {
          "eq": "2.4.18"
        },
        {
          "eq": "2.4.20"
        },
        {
          "eq": "2.4.23"
        },
        {
          "eq": "2.4.25"
        },
        {
          "eq": "2.4.26"
        },
        {
          "eq": "2.4.27"
        }
      ],
      "note": "NVD: Apache httpd allows remote attackers to read secret data from process memory if the Limit directive can be set in a user's .htaccess file, or if httpd.conf has…"
    },
    {
      "cve": "CVE-2017-9789",
      "sev": "high",
      "kev": false,
      "title": "When under stress, closing many connections, the HTTP/2 handling code in Apache httpd…",
      "ranges": [
        {
          "eq": "2.4.26"
        }
      ],
      "note": "NVD: When under stress, closing many connections, the HTTP/2 handling code in Apache httpd 2.4.26 would sometimes access memory after it has been freed, resulting in…"
    },
    {
      "cve": "CVE-2017-9788",
      "sev": "critical",
      "kev": false,
      "title": "In Apache httpd before 2.2.34 and 2.4.x before 2.4.27, the value placeholder in…",
      "ranges": [
        {
          "lte": "2.2.33"
        },
        {
          "gte": "2.4.0",
          "lte": "2.4.26"
        }
      ],
      "note": "NVD: In Apache httpd before 2.2.34 and 2.4.x before 2.4.27, the value placeholder in [Proxy-]Authorization headers of type 'Digest' was not initialized or reset before…"
    },
    {
      "cve": "CVE-2017-7679",
      "sev": "critical",
      "kev": false,
      "title": "In Apache httpd 2.2.x before 2.2.33 and 2.4.x before 2.4.26, mod_mime can read one…",
      "ranges": [
        {
          "gte": "2.2.0",
          "lt": "2.2.33"
        },
        {
          "gte": "2.4.0",
          "lt": "2.4.26"
        }
      ],
      "note": "NVD: In Apache httpd 2.2.x before 2.2.33 and 2.4.x before 2.4.26, mod_mime can read one byte past the end of a buffer when sending a malicious Content-Type response…"
    },
    {
      "cve": "CVE-2017-7668",
      "sev": "high",
      "kev": false,
      "title": "The HTTP strict parsing changes added in Apache httpd 2.2.32 and 2.4.24 introduced a…",
      "ranges": [
        {
          "eq": "2.2.32"
        },
        {
          "eq": "2.4.24"
        },
        {
          "eq": "2.4.25"
        }
      ],
      "note": "NVD: The HTTP strict parsing changes added in Apache httpd 2.2.32 and 2.4.24 introduced a bug in token list parsing, which allows ap_find_token() to search past the end…"
    },
    {
      "cve": "CVE-2017-7659",
      "sev": "high",
      "kev": false,
      "title": "A maliciously constructed HTTP/2 request could cause mod_http2 in Apache HTTP Server…",
      "ranges": [
        {
          "eq": "2.4.24"
        },
        {
          "eq": "2.4.25"
        }
      ],
      "note": "NVD: A maliciously constructed HTTP/2 request could cause mod_http2 in Apache HTTP Server 2.4.24, 2.4.25 to dereference a NULL pointer and crash the server process."
    },
    {
      "cve": "CVE-2017-3167",
      "sev": "critical",
      "kev": false,
      "title": "In Apache httpd 2.2.x before 2.2.33 and 2.4.x before 2.4.26, use of the…",
      "ranges": [
        {
          "gte": "2.2.0",
          "lt": "2.2.33"
        },
        {
          "gte": "2.4.0",
          "lt": "2.4.26"
        }
      ],
      "note": "NVD: In Apache httpd 2.2.x before 2.2.33 and 2.4.x before 2.4.26, use of the ap_get_basic_auth_pw() by third-party modules outside of the authentication phase may lead…"
    },
    {
      "cve": "CVE-2016-8743",
      "sev": "high",
      "kev": false,
      "title": "Apache HTTP Server, in all releases prior to 2.2.32 and 2.4.25, was liberal in the…",
      "ranges": [
        {
          "gte": "2.2.0",
          "lte": "2.2.31"
        },
        {
          "gte": "2.4.1",
          "lte": "2.4.23"
        }
      ],
      "note": "NVD: Apache HTTP Server, in all releases prior to 2.2.32 and 2.4.25, was liberal in the whitespace accepted from requests and sent in response lines and headers."
    },
    {
      "cve": "CVE-2016-8740",
      "sev": "high",
      "kev": false,
      "title": "The mod_http2 module in the Apache HTTP Server 2.4.17 through 2.4.23, when the…",
      "ranges": [
        {
          "eq": "2.4.17"
        },
        {
          "eq": "2.4.18"
        },
        {
          "eq": "2.4.19"
        },
        {
          "eq": "2.4.20"
        },
        {
          "eq": "2.4.21"
        },
        {
          "eq": "2.4.22"
        },
        {
          "eq": "2.4.23"
        }
      ],
      "note": "NVD: The mod_http2 module in the Apache HTTP Server 2.4.17 through 2.4.23, when the Protocols configuration includes h2 or h2c, does not restrict request-header length,…"
    },
    {
      "cve": "CVE-2016-5387",
      "sev": "high",
      "kev": false,
      "title": "The Apache HTTP Server through 2.4.23 follows RFC 3875 section 4.1.18 and therefore…",
      "ranges": [
        {
          "gte": "2.2.0",
          "lte": "2.2.31"
        },
        {
          "gte": "2.4.1",
          "lte": "2.4.23"
        }
      ],
      "note": "NVD: The Apache HTTP Server through 2.4.23 follows RFC 3875 section 4.1.18 and therefore does not protect applications from the presence of untrusted client data in the…"
    },
    {
      "cve": "CVE-2016-4979",
      "sev": "high",
      "kev": false,
      "title": "The Apache HTTP Server 2.4.18 through 2.4.20, when mod_http2 and mod_ssl are enabled,…",
      "ranges": [
        {
          "eq": "2.4.18"
        },
        {
          "eq": "2.4.19"
        },
        {
          "eq": "2.4.20"
        }
      ],
      "note": "NVD: The Apache HTTP Server 2.4.18 through 2.4.20, when mod_http2 and mod_ssl are enabled, does not properly recognize the \"SSLVerifyClient require\" directive for…"
    },
    {
      "cve": "CVE-2016-2161",
      "sev": "high",
      "kev": false,
      "title": "In Apache HTTP Server versions 2.4.0 to 2.4.23, malicious input to mod_auth_digest can…",
      "ranges": [
        {
          "eq": "2.4.0"
        },
        {
          "eq": "2.4.1"
        },
        {
          "eq": "2.4.2"
        },
        {
          "eq": "2.4.3"
        },
        {
          "eq": "2.4.6"
        },
        {
          "eq": "2.4.7"
        },
        {
          "eq": "2.4.8"
        },
        {
          "eq": "2.4.9"
        },
        {
          "eq": "2.4.10"
        },
        {
          "eq": "2.4.12"
        },
        {
          "eq": "2.4.14"
        },
        {
          "eq": "2.4.16"
        },
        {
          "eq": "2.4.19"
        },
        {
          "eq": "2.4.20"
        },
        {
          "eq": "2.4.21"
        },
        {
          "eq": "2.4.22"
        },
        {
          "eq": "2.4.23"
        }
      ],
      "note": "NVD: In Apache HTTP Server versions 2.4.0 to 2.4.23, malicious input to mod_auth_digest can cause the server to crash, and each instance continues to crash even for…"
    },
    {
      "cve": "CVE-2016-0736",
      "sev": "high",
      "kev": false,
      "title": "In Apache HTTP Server versions 2.4.0 to 2.4.23, mod_session_crypto was encrypting its…",
      "ranges": [
        {
          "eq": "2.4.0"
        },
        {
          "eq": "2.4.1"
        },
        {
          "eq": "2.4.2"
        },
        {
          "eq": "2.4.3"
        },
        {
          "eq": "2.4.6"
        },
        {
          "eq": "2.4.7"
        },
        {
          "eq": "2.4.8"
        },
        {
          "eq": "2.4.9"
        },
        {
          "eq": "2.4.10"
        },
        {
          "eq": "2.4.12"
        },
        {
          "eq": "2.4.14"
        },
        {
          "eq": "2.4.16"
        },
        {
          "eq": "2.4.19"
        },
        {
          "eq": "2.4.20"
        },
        {
          "eq": "2.4.21"
        },
        {
          "eq": "2.4.22"
        },
        {
          "eq": "2.4.23"
        }
      ],
      "note": "NVD: In Apache HTTP Server versions 2.4.0 to 2.4.23, mod_session_crypto was encrypting its data/cookie using the configured ciphers with possibly either CBC or ECB…"
    }
  ],
  "django": [
    {
      "cve": "CVE-2026-33034",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in 6.0 before 6.0.4, 5.2 before 5.2.13, and 4.2 before 4.2.30.",
      "ranges": [
        {
          "gte": "4.2",
          "lt": "4.2.30"
        },
        {
          "gte": "5.2",
          "lt": "5.2.13"
        },
        {
          "gte": "6.0",
          "lt": "6.0.4"
        }
      ],
      "note": "NVD: An issue was discovered in 6.0 before 6.0.4, 5.2 before 5.2.13, and 4.2 before 4.2.30."
    },
    {
      "cve": "CVE-2026-25673",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in 6.0 before 6.0.3, 5.2 before 5.2.12, and 4.2 before 4.2.29.",
      "ranges": [
        {
          "gte": "4.2.0",
          "lt": "4.2.29"
        },
        {
          "gte": "5.2",
          "lt": "5.2.12"
        },
        {
          "gte": "6.0",
          "lt": "6.0.3"
        }
      ],
      "note": "NVD: An issue was discovered in 6.0 before 6.0.3, 5.2 before 5.2.12, and 4.2 before 4.2.29."
    },
    {
      "cve": "CVE-2026-15307",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in Django 5.2 before 5.2.17 and 6.0 before 6.0.8.",
      "ranges": [
        {
          "lt": "5.2.17"
        },
        {
          "gte": "6.0",
          "lt": "6.0.8"
        }
      ],
      "note": "NVD: An issue was discovered in Django 5.2 before 5.2.17 and 6.0 before 6.0.8."
    },
    {
      "cve": "CVE-2026-4277",
      "sev": "critical",
      "kev": false,
      "title": "An issue was discovered in 6.0 before 6.0.4, 5.2 before 5.2.13, and 4.2 before 4.2.30.",
      "ranges": [
        {
          "gte": "4.2",
          "lt": "4.2.30"
        },
        {
          "gte": "5.2",
          "lt": "5.2.13"
        },
        {
          "gte": "6.0",
          "lt": "6.0.4"
        }
      ],
      "note": "NVD: An issue was discovered in 6.0 before 6.0.4, 5.2 before 5.2.13, and 4.2 before 4.2.30."
    },
    {
      "cve": "CVE-2026-3902",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in 6.0 before 6.0.4, 5.2 before 5.2.13, and 4.2 before 4.2.30.",
      "ranges": [
        {
          "gte": "4.2",
          "lt": "4.2.30"
        },
        {
          "gte": "5.2",
          "lt": "5.2.13"
        },
        {
          "gte": "6.0",
          "lt": "6.0.4"
        }
      ],
      "note": "NVD: An issue was discovered in 6.0 before 6.0.4, 5.2 before 5.2.13, and 4.2 before 4.2.30."
    },
    {
      "cve": "CVE-2026-1285",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in 6.0 before 6.0.2, 5.2 before 5.2.11, and 4.2 before 4.2.28.",
      "ranges": [
        {
          "gte": "4.2",
          "lt": "4.2.28"
        },
        {
          "gte": "5.2",
          "lt": "5.2.11"
        },
        {
          "gte": "6.0",
          "lt": "6.0.2"
        }
      ],
      "note": "NVD: An issue was discovered in 6.0 before 6.0.2, 5.2 before 5.2.11, and 4.2 before 4.2.28."
    },
    {
      "cve": "CVE-2025-64460",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in 5.2 before 5.2.9, 5.1 before 5.1.15, and 4.2 before 4.2.27.",
      "ranges": [
        {
          "gte": "4.2",
          "lt": "4.2.27"
        },
        {
          "gte": "5.1",
          "lt": "5.1.15"
        },
        {
          "gte": "5.2",
          "lt": "5.2.9"
        }
      ],
      "note": "NVD: An issue was discovered in 5.2 before 5.2.9, 5.1 before 5.1.15, and 4.2 before 4.2.27."
    },
    {
      "cve": "CVE-2025-64459",
      "sev": "critical",
      "kev": false,
      "title": "An issue was discovered in 5.1 before 5.1.14, 4.2 before 4.2.26, and 5.2 before 5.2.8.",
      "ranges": [
        {
          "gte": "4.2",
          "lt": "4.2.26"
        },
        {
          "gte": "5.1",
          "lt": "5.1.14"
        },
        {
          "gte": "5.2",
          "lt": "5.2.8"
        }
      ],
      "note": "NVD: An issue was discovered in 5.1 before 5.1.14, 4.2 before 4.2.26, and 5.2 before 5.2.8."
    },
    {
      "cve": "CVE-2025-64458",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in 5.1 before 5.1.14, 4.2 before 4.2.26, and 5.2 before 5.2.8.",
      "ranges": [
        {
          "gte": "4.2",
          "lt": "4.2.26"
        },
        {
          "gte": "5.1",
          "lt": "5.1.14"
        },
        {
          "gte": "5.2",
          "lt": "5.2.8"
        }
      ],
      "note": "NVD: An issue was discovered in 5.1 before 5.1.14, 4.2 before 4.2.26, and 5.2 before 5.2.8."
    },
    {
      "cve": "CVE-2025-59681",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in Django 4.2 before 4.2.25, 5.1 before 5.1.13, and 5.2 before…",
      "ranges": [
        {
          "gte": "4.2",
          "lt": "4.2.25"
        },
        {
          "gte": "5.1",
          "lt": "5.1.13"
        },
        {
          "gte": "5.2",
          "lt": "5.2.7"
        }
      ],
      "note": "NVD: An issue was discovered in Django 4.2 before 4.2.25, 5.1 before 5.1.13, and 5.2 before 5.2.7."
    },
    {
      "cve": "CVE-2025-57833",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in Django 4.2 before 4.2.24, 5.1 before 5.1.12, and 5.2 before…",
      "ranges": [
        {
          "gte": "4.2",
          "lt": "4.2.24"
        },
        {
          "gte": "5.1",
          "lt": "5.1.12"
        },
        {
          "gte": "5.2",
          "lt": "5.2.6"
        }
      ],
      "note": "NVD: An issue was discovered in Django 4.2 before 4.2.24, 5.1 before 5.1.12, and 5.2 before 5.2.6."
    },
    {
      "cve": "CVE-2025-14550",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in 6.0 before 6.0.2, 5.2 before 5.2.11, and 4.2 before 4.2.28.",
      "ranges": [
        {
          "gte": "4.2",
          "lt": "4.2.28"
        },
        {
          "gte": "5.2",
          "lt": "5.2.11"
        },
        {
          "gte": "6.0",
          "lt": "6.0.2"
        }
      ],
      "note": "NVD: An issue was discovered in 6.0 before 6.0.2, 5.2 before 5.2.11, and 4.2 before 4.2.28."
    },
    {
      "cve": "CVE-2024-53908",
      "sev": "critical",
      "kev": false,
      "title": "An issue was discovered in Django 5.1 before 5.1.4, 5.0 before 5.0.10, and 4.2 before…",
      "ranges": [
        {
          "gte": "4.2",
          "lt": "4.2.17"
        },
        {
          "gte": "5.0",
          "lt": "5.0.10"
        },
        {
          "gte": "5.1",
          "lt": "5.1.4"
        }
      ],
      "note": "NVD: An issue was discovered in Django 5.1 before 5.1.4, 5.0 before 5.0.10, and 4.2 before 4.2.17."
    },
    {
      "cve": "CVE-2024-53907",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in Django 5.1 before 5.1.4, 5.0 before 5.0.10, and 4.2 before…",
      "ranges": [
        {
          "gte": "4.2",
          "lt": "4.2.17"
        },
        {
          "gte": "5.0",
          "lt": "5.0.10"
        },
        {
          "gte": "5.1",
          "lt": "5.1.4"
        }
      ],
      "note": "NVD: An issue was discovered in Django 5.1 before 5.1.4, 5.0 before 5.0.10, and 4.2 before 4.2.17."
    },
    {
      "cve": "CVE-2024-45230",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in Django 5.1 before 5.1.1, 5.0 before 5.0.9, and 4.2 before…",
      "ranges": [
        {
          "gte": "4.2.0",
          "lt": "4.2.16"
        },
        {
          "gte": "5.0",
          "lt": "5.0.9"
        },
        {
          "eq": "5.1"
        }
      ],
      "note": "NVD: An issue was discovered in Django 5.1 before 5.1.1, 5.0 before 5.0.9, and 4.2 before 4.2.16."
    },
    {
      "cve": "CVE-2024-42005",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in Django 5.0 before 5.0.8 and 4.2 before 4.2.15.",
      "ranges": [
        {
          "gte": "4.2",
          "lt": "4.2.15"
        },
        {
          "gte": "5.0",
          "lt": "5.0.8"
        }
      ],
      "note": "NVD: An issue was discovered in Django 5.0 before 5.0.8 and 4.2 before 4.2.15."
    },
    {
      "cve": "CVE-2024-41991",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in Django 5.0 before 5.0.8 and 4.2 before 4.2.15.",
      "ranges": [
        {
          "gte": "4.2",
          "lt": "4.2.15"
        },
        {
          "gte": "5.0",
          "lt": "5.0.8"
        }
      ],
      "note": "NVD: An issue was discovered in Django 5.0 before 5.0.8 and 4.2 before 4.2.15."
    },
    {
      "cve": "CVE-2024-41990",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in Django 5.0 before 5.0.8 and 4.2 before 4.2.15.",
      "ranges": [
        {
          "gte": "4.2",
          "lt": "4.2.15"
        },
        {
          "gte": "5.0",
          "lt": "5.0.8"
        }
      ],
      "note": "NVD: An issue was discovered in Django 5.0 before 5.0.8 and 4.2 before 4.2.15."
    },
    {
      "cve": "CVE-2024-41989",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in Django 5.0 before 5.0.8 and 4.2 before 4.2.15.",
      "ranges": [
        {
          "gte": "4.2",
          "lt": "4.2.15"
        },
        {
          "gte": "5.0",
          "lt": "5.0.8"
        }
      ],
      "note": "NVD: An issue was discovered in Django 5.0 before 5.0.8 and 4.2 before 4.2.15."
    },
    {
      "cve": "CVE-2024-39614",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in Django 5.0 before 5.0.7 and 4.2 before 4.2.14.",
      "ranges": [
        {
          "gte": "4.2",
          "lt": "4.2.14"
        },
        {
          "gte": "5.0",
          "lt": "5.0.7"
        }
      ],
      "note": "NVD: An issue was discovered in Django 5.0 before 5.0.7 and 4.2 before 4.2.14."
    },
    {
      "cve": "CVE-2024-38875",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in Django 4.2 before 4.2.14 and 5.0 before 5.0.7.",
      "ranges": [
        {
          "gte": "4.2",
          "lt": "4.2.14"
        },
        {
          "gte": "5.0",
          "lt": "5.0.7"
        }
      ],
      "note": "NVD: An issue was discovered in Django 4.2 before 4.2.14 and 5.0 before 5.0.7."
    },
    {
      "cve": "CVE-2024-24680",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in Django 3.2 before 3.2.24, 4.2 before 4.2.10, and Django 5.0…",
      "ranges": [
        {
          "gte": "3.2",
          "lt": "3.2.24"
        },
        {
          "gte": "4.2",
          "lt": "4.2.10"
        },
        {
          "gte": "5.0",
          "lt": "5.0.2"
        }
      ],
      "note": "NVD: An issue was discovered in Django 3.2 before 3.2.24, 4.2 before 4.2.10, and Django 5.0 before 5.0.2."
    },
    {
      "cve": "CVE-2023-46695",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in Django 3.2 before 3.2.23, 4.1 before 4.1.13, and 4.2 before…",
      "ranges": [
        {
          "gte": "3.2",
          "lt": "3.2.23"
        },
        {
          "gte": "4.1",
          "lt": "4.1.13"
        }
      ],
      "note": "NVD: An issue was discovered in Django 3.2 before 3.2.23, 4.1 before 4.1.13, and 4.2 before 4.2.7."
    },
    {
      "cve": "CVE-2023-43665",
      "sev": "high",
      "kev": false,
      "title": "In Django 3.2 before 3.2.22, 4.1 before 4.1.12, and 4.2 before 4.2.6, the…",
      "ranges": [
        {
          "gte": "3.2",
          "lt": "3.2.22"
        },
        {
          "gte": "4.1",
          "lt": "4.1.12"
        },
        {
          "gte": "4.2",
          "lt": "4.2.6"
        }
      ],
      "note": "NVD: In Django 3.2 before 3.2.22, 4.1 before 4.1.12, and 4.2 before 4.2.6, the django.utils.text.Truncator chars() and words() methods (when used with html=True) are…"
    },
    {
      "cve": "CVE-2023-41164",
      "sev": "high",
      "kev": false,
      "title": "In Django 3.2 before 3.2.21, 4.1 before 4.1.11, and 4.2 before 4.2.5,…",
      "ranges": [
        {
          "gte": "3.2",
          "lt": "3.2.21"
        },
        {
          "gte": "4.1",
          "lt": "4.1.11"
        },
        {
          "gte": "4.2",
          "lt": "4.2.5"
        }
      ],
      "note": "NVD: In Django 3.2 before 3.2.21, 4.1 before 4.1.11, and 4.2 before 4.2.5, django.utils.encoding.uri_to_iri() is subject to a potential DoS (denial of service) attack…"
    },
    {
      "cve": "CVE-2023-36053",
      "sev": "high",
      "kev": false,
      "title": "In Django 3.2 before 3.2.20, 4 before 4.1.10, and 4.2 before 4.2.3, EmailValidator and…",
      "ranges": [
        {
          "gte": "3.2",
          "lt": "3.2.20"
        },
        {
          "gte": "4.0",
          "lt": "4.1.10"
        },
        {
          "gte": "4.2",
          "lt": "4.2.3"
        }
      ],
      "note": "NVD: In Django 3.2 before 3.2.20, 4 before 4.1.10, and 4.2 before 4.2.3, EmailValidator and URLValidator are subject to a potential ReDoS (regular expression denial of…"
    },
    {
      "cve": "CVE-2023-31047",
      "sev": "critical",
      "kev": false,
      "title": "In Django 3.2 before 3.2.19, 4.x before 4.1.9, and 4.2 before 4.2.1, it was possible…",
      "ranges": [
        {
          "gte": "3.2",
          "lt": "3.2.19"
        },
        {
          "gte": "4.0",
          "lt": "4.1.9"
        },
        {
          "eq": "4.2"
        }
      ],
      "note": "NVD: In Django 3.2 before 3.2.19, 4.x before 4.1.9, and 4.2 before 4.2.1, it was possible to bypass validation when using one form field to upload multiple files."
    },
    {
      "cve": "CVE-2023-24580",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in the Multipart Request Parser in Django 3.2 before 3.2.18,…",
      "ranges": [
        {
          "gte": "3.2",
          "lt": "3.2.18"
        },
        {
          "gte": "4.0",
          "lt": "4.0.10"
        },
        {
          "gte": "4.1",
          "lt": "4.1.7"
        }
      ],
      "note": "NVD: An issue was discovered in the Multipart Request Parser in Django 3.2 before 3.2.18, 4.0 before 4.0.10, and 4.1 before 4.1.7."
    },
    {
      "cve": "CVE-2023-23969",
      "sev": "high",
      "kev": false,
      "title": "In Django 3.2 before 3.2.17, 4.0 before 4.0.9, and 4.1 before 4.1.6, the parsed values…",
      "ranges": [
        {
          "gte": "3.2",
          "lt": "3.2.17"
        },
        {
          "gte": "4.0",
          "lt": "4.0.9"
        },
        {
          "gte": "4.1",
          "lt": "4.1.6"
        }
      ],
      "note": "NVD: In Django 3.2 before 3.2.17, 4.0 before 4.0.9, and 4.1 before 4.1.6, the parsed values of Accept-Language headers are cached in order to avoid repetitive parsing."
    },
    {
      "cve": "CVE-2022-41323",
      "sev": "high",
      "kev": false,
      "title": "In Django 3.2 before 3.2.16, 4.0 before 4.0.8, and 4.1 before 4.1.2, internationalized…",
      "ranges": [
        {
          "gte": "3.2",
          "lt": "3.2.16"
        },
        {
          "gte": "4.0",
          "lt": "4.0.8"
        },
        {
          "gte": "4.1",
          "lt": "4.1.2"
        }
      ],
      "note": "NVD: In Django 3.2 before 3.2.16, 4.0 before 4.0.8, and 4.1 before 4.1.2, internationalized URLs were subject to a potential denial of service attack via the locale…"
    },
    {
      "cve": "CVE-2022-36359",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in the HTTP FileResponse class in Django 3.2 before 3.2.15 and…",
      "ranges": [
        {
          "gte": "3.2",
          "lt": "3.2.15"
        },
        {
          "gte": "4.0",
          "lt": "4.0.7"
        }
      ],
      "note": "NVD: An issue was discovered in the HTTP FileResponse class in Django 3.2 before 3.2.15 and 4.0 before 4.0.7."
    },
    {
      "cve": "CVE-2022-34265",
      "sev": "critical",
      "kev": false,
      "title": "An issue was discovered in Django 3.2 before 3.2.14 and 4.0 before 4.0.6.",
      "ranges": [
        {
          "gte": "3.2",
          "lt": "3.2.14"
        },
        {
          "gte": "4.0",
          "lt": "4.0.6"
        }
      ],
      "note": "NVD: An issue was discovered in Django 3.2 before 3.2.14 and 4.0 before 4.0.6."
    },
    {
      "cve": "CVE-2022-28347",
      "sev": "critical",
      "kev": false,
      "title": "A SQL injection issue was discovered in QuerySet.explain() in Django 2.2 before…",
      "ranges": [
        {
          "gte": "2.2",
          "lt": "2.2.28"
        },
        {
          "gte": "3.2",
          "lt": "3.2.13"
        },
        {
          "gte": "4.0",
          "lt": "4.0.4"
        }
      ],
      "note": "NVD: A SQL injection issue was discovered in QuerySet.explain() in Django 2.2 before 2.2.28, 3.2 before 3.2.13, and 4.0 before 4.0.4."
    },
    {
      "cve": "CVE-2022-28346",
      "sev": "critical",
      "kev": false,
      "title": "An issue was discovered in Django 2.2 before 2.2.28, 3.2 before 3.2.13, and 4.0 before…",
      "ranges": [
        {
          "gte": "2.2",
          "lt": "2.2.28"
        },
        {
          "gte": "3.2",
          "lt": "3.2.13"
        },
        {
          "gte": "4.0",
          "lt": "4.0.4"
        }
      ],
      "note": "NVD: An issue was discovered in Django 2.2 before 2.2.28, 3.2 before 3.2.13, and 4.0 before 4.0.4."
    },
    {
      "cve": "CVE-2022-23833",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in MultiPartParser in Django 2.2 before 2.2.27, 3.2 before…",
      "ranges": [
        {
          "gte": "2.2",
          "lt": "2.2.27"
        },
        {
          "gte": "3.2",
          "lt": "3.2.12"
        },
        {
          "gte": "4.0",
          "lt": "4.0.2"
        }
      ],
      "note": "NVD: An issue was discovered in MultiPartParser in Django 2.2 before 2.2.27, 3.2 before 3.2.12, and 4.0 before 4.0.2."
    },
    {
      "cve": "CVE-2021-45116",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in Django 2.2 before 2.2.26, 3.2 before 3.2.11, and 4.0 before…",
      "ranges": [
        {
          "gte": "2.2",
          "lt": "2.2.26"
        },
        {
          "gte": "3.2",
          "lt": "3.2.11"
        },
        {
          "gte": "4.0",
          "lt": "4.0.1"
        }
      ],
      "note": "NVD: An issue was discovered in Django 2.2 before 2.2.26, 3.2 before 3.2.11, and 4.0 before 4.0.1."
    },
    {
      "cve": "CVE-2021-45115",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in Django 2.2 before 2.2.26, 3.2 before 3.2.11, and 4.0 before…",
      "ranges": [
        {
          "gte": "2.2",
          "lt": "2.2.26"
        },
        {
          "gte": "3.2",
          "lt": "3.2.11"
        },
        {
          "gte": "4.0",
          "lt": "4.0.1"
        }
      ],
      "note": "NVD: An issue was discovered in Django 2.2 before 2.2.26, 3.2 before 3.2.11, and 4.0 before 4.0.1."
    },
    {
      "cve": "CVE-2021-44420",
      "sev": "high",
      "kev": false,
      "title": "In Django 2.2 before 2.2.25, 3.1 before 3.1.14, and 3.2 before 3.2.10, HTTP requests…",
      "ranges": [
        {
          "gte": "2.2",
          "lt": "2.2.25"
        },
        {
          "gte": "3.1",
          "lt": "3.1.14"
        },
        {
          "gte": "3.2",
          "lt": "3.2.10"
        }
      ],
      "note": "NVD: In Django 2.2 before 2.2.25, 3.1 before 3.1.14, and 3.2 before 3.2.10, HTTP requests for URLs with trailing newlines could bypass upstream access control based on…"
    },
    {
      "cve": "CVE-2021-35042",
      "sev": "critical",
      "kev": false,
      "title": "Django 3.1.x before 3.1.13 and 3.2.x before 3.2.5 allows QuerySet.order_by SQL…",
      "ranges": [
        {
          "gte": "3.1",
          "lt": "3.1.13"
        },
        {
          "gte": "3.2",
          "lt": "3.2.5"
        }
      ],
      "note": "NVD: Django 3.1.x before 3.1.13 and 3.2.x before 3.2.5 allows QuerySet.order_by SQL injection if order_by is untrusted input from a client of a web application."
    },
    {
      "cve": "CVE-2021-33571",
      "sev": "high",
      "kev": false,
      "title": "In Django 2.2 before 2.2.24, 3.x before 3.1.12, and 3.2 before 3.2.4, URLValidator,…",
      "ranges": [
        {
          "gte": "2.2",
          "lt": "2.2.24"
        },
        {
          "gte": "3.0",
          "lt": "3.1.12"
        },
        {
          "gte": "3.2",
          "lt": "3.2.4"
        }
      ],
      "note": "NVD: In Django 2.2 before 2.2.24, 3.x before 3.1.12, and 3.2 before 3.2.4, URLValidator, validate_ipv4_address, and validate_ipv46_address do not prohibit leading zero…"
    },
    {
      "cve": "CVE-2021-31542",
      "sev": "high",
      "kev": false,
      "title": "In Django 2.2 before 2.2.21, 3.1 before 3.1.9, and 3.2 before 3.2.1, MultiPartParser,…",
      "ranges": [
        {
          "gte": "2.2",
          "lt": "2.2.21"
        },
        {
          "gte": "3.1",
          "lt": "3.1.9"
        },
        {
          "gte": "3.2",
          "lt": "3.2.1"
        }
      ],
      "note": "NVD: In Django 2.2 before 2.2.21, 3.1 before 3.1.9, and 3.2 before 3.2.1, MultiPartParser, UploadedFile, and FieldFile allowed directory traversal via uploaded files…"
    },
    {
      "cve": "CVE-2020-24584",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in Django 2.2 before 2.2.16, 3.0 before 3.0.10, and 3.1 before…",
      "ranges": [
        {
          "gte": "2.2",
          "lt": "2.2.16"
        },
        {
          "gte": "3.0",
          "lt": "3.0.10"
        },
        {
          "gte": "3.1",
          "lt": "3.1.1"
        }
      ],
      "note": "NVD: An issue was discovered in Django 2.2 before 2.2.16, 3.0 before 3.0.10, and 3.1 before 3.1.1 (when Python 3.7+ is used)."
    },
    {
      "cve": "CVE-2020-24583",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in Django 2.2 before 2.2.16, 3.0 before 3.0.10, and 3.1 before…",
      "ranges": [
        {
          "gte": "2.2",
          "lt": "2.2.16"
        },
        {
          "gte": "3.0",
          "lt": "3.0.10"
        },
        {
          "gte": "3.1",
          "lt": "3.1.1"
        }
      ],
      "note": "NVD: An issue was discovered in Django 2.2 before 2.2.16, 3.0 before 3.0.10, and 3.1 before 3.1.1 (when Python 3.7+ is used)."
    },
    {
      "cve": "CVE-2020-9402",
      "sev": "high",
      "kev": false,
      "title": "Django 1.11 before 1.11.29, 2.2 before 2.2.11, and 3.0 before 3.0.4 allows SQL…",
      "ranges": [
        {
          "gte": "1.11",
          "lt": "1.11.29"
        },
        {
          "gte": "2.2",
          "lt": "2.2.11"
        },
        {
          "gte": "3.0",
          "lt": "3.0.4"
        }
      ],
      "note": "NVD: Django 1.11 before 1.11.29, 2.2 before 2.2.11, and 3.0 before 3.0.4 allows SQL Injection if untrusted data is used as a tolerance parameter in GIS functions and…"
    },
    {
      "cve": "CVE-2020-7471",
      "sev": "critical",
      "kev": false,
      "title": "Django 1.11 before 1.11.28, 2.2 before 2.2.10, and 3.0 before 3.0.3 allows SQL…",
      "ranges": [
        {
          "gte": "1.11",
          "lt": "1.11.28"
        },
        {
          "gte": "2.2",
          "lt": "2.2.10"
        },
        {
          "gte": "3.0",
          "lt": "3.0.3"
        }
      ],
      "note": "NVD: Django 1.11 before 1.11.28, 2.2 before 2.2.10, and 3.0 before 3.0.3 allows SQL Injection if untrusted data is used as a StringAgg delimiter (e.g., in Django…"
    },
    {
      "cve": "CVE-2019-19844",
      "sev": "critical",
      "kev": false,
      "title": "Django before 1.11.27, 2.x before 2.2.9, and 3.x before 3.0.1 allows account takeover.",
      "ranges": [
        {
          "lt": "1.11.27"
        },
        {
          "gte": "2.2",
          "lt": "2.2.9"
        },
        {
          "eq": "3.0"
        }
      ],
      "note": "NVD: Django before 1.11.27, 2.x before 2.2.9, and 3.x before 3.0.1 allows account takeover."
    },
    {
      "cve": "CVE-2019-14235",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in Django 1.11.x before 1.11.23, 2.1.x before 2.1.11, and…",
      "ranges": [
        {
          "gte": "1.11",
          "lt": "1.11.23"
        },
        {
          "gte": "2.1",
          "lt": "2.1.11"
        },
        {
          "gte": "2.2",
          "lt": "2.2.4"
        }
      ],
      "note": "NVD: An issue was discovered in Django 1.11.x before 1.11.23, 2.1.x before 2.1.11, and 2.2.x before 2.2.4."
    },
    {
      "cve": "CVE-2019-14234",
      "sev": "critical",
      "kev": false,
      "title": "An issue was discovered in Django 1.11.x before 1.11.23, 2.1.x before 2.1.11, and…",
      "ranges": [
        {
          "gte": "1.11",
          "lt": "1.11.23"
        },
        {
          "gte": "2.1",
          "lt": "2.1.11"
        },
        {
          "gte": "2.2",
          "lt": "2.2.4"
        }
      ],
      "note": "NVD: An issue was discovered in Django 1.11.x before 1.11.23, 2.1.x before 2.1.11, and 2.2.x before 2.2.4."
    },
    {
      "cve": "CVE-2019-14233",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in Django 1.11.x before 1.11.23, 2.1.x before 2.1.11, and…",
      "ranges": [
        {
          "gte": "1.11",
          "lt": "1.11.23"
        },
        {
          "gte": "2.1",
          "lt": "2.1.11"
        },
        {
          "gte": "2.2",
          "lt": "2.2.4"
        }
      ],
      "note": "NVD: An issue was discovered in Django 1.11.x before 1.11.23, 2.1.x before 2.1.11, and 2.2.x before 2.2.4."
    },
    {
      "cve": "CVE-2019-14232",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in Django 1.11.x before 1.11.23, 2.1.x before 2.1.11, and…",
      "ranges": [
        {
          "gte": "1.11",
          "lt": "1.11.23"
        },
        {
          "gte": "2.1",
          "lt": "2.1.11"
        },
        {
          "gte": "2.2",
          "lt": "2.2.4"
        }
      ],
      "note": "NVD: An issue was discovered in Django 1.11.x before 1.11.23, 2.1.x before 2.1.11, and 2.2.x before 2.2.4."
    },
    {
      "cve": "CVE-2019-6975",
      "sev": "high",
      "kev": false,
      "title": "Django 1.11.x before 1.11.19, 2.0.x before 2.0.11, and 2.1.x before 2.1.6 allows…",
      "ranges": [
        {
          "gte": "1.11.0",
          "lt": "1.11.19"
        },
        {
          "gte": "2.0.0",
          "lt": "2.0.11"
        },
        {
          "gte": "2.1.0",
          "lt": "2.1.6"
        }
      ],
      "note": "NVD: Django 1.11.x before 1.11.19, 2.0.x before 2.0.11, and 2.1.x before 2.1.6 allows Uncontrolled Memory Consumption via a malicious attacker-supplied value to the…"
    },
    {
      "cve": "CVE-2018-6188",
      "sev": "high",
      "kev": false,
      "title": "django.contrib.auth.forms.AuthenticationForm in Django 2.0 before 2.0.2, and 1.11.8…",
      "ranges": [
        {
          "eq": "1.11.8"
        },
        {
          "eq": "1.11.9"
        },
        {
          "eq": "2.0"
        },
        {
          "eq": "2.0.1"
        }
      ],
      "note": "NVD: django.contrib.auth.forms.AuthenticationForm in Django 2.0 before 2.0.2, and 1.11.8 and 1.11.9, allows remote attackers to obtain potentially sensitive information…"
    },
    {
      "cve": "CVE-2016-9014",
      "sev": "high",
      "kev": false,
      "title": "Django before 1.8.x before 1.8.16, 1.9.x before 1.9.11, and 1.10.x before 1.10.3, when…",
      "ranges": [
        {
          "eq": "1.8"
        },
        {
          "eq": "1.8.1"
        },
        {
          "eq": "1.8.2"
        },
        {
          "eq": "1.8.3"
        },
        {
          "eq": "1.8.4"
        },
        {
          "eq": "1.8.5"
        },
        {
          "eq": "1.8.6"
        },
        {
          "eq": "1.8.7"
        },
        {
          "eq": "1.8.8"
        },
        {
          "eq": "1.8.9"
        },
        {
          "eq": "1.8.10"
        },
        {
          "eq": "1.8.11"
        },
        {
          "eq": "1.8.12"
        },
        {
          "eq": "1.8.13"
        },
        {
          "eq": "1.8.14"
        },
        {
          "eq": "1.8.15"
        },
        {
          "eq": "1.10"
        },
        {
          "eq": "1.10.1"
        },
        {
          "eq": "1.10.2"
        },
        {
          "eq": "1.9"
        },
        {
          "eq": "1.9.1"
        },
        {
          "eq": "1.9.2"
        },
        {
          "eq": "1.9.3"
        },
        {
          "eq": "1.9.4"
        },
        {
          "eq": "1.9.5"
        },
        {
          "eq": "1.9.6"
        },
        {
          "eq": "1.9.7"
        },
        {
          "eq": "1.9.8"
        },
        {
          "eq": "1.9.9"
        },
        {
          "eq": "1.9.10"
        }
      ],
      "note": "NVD: Django before 1.8.x before 1.8.16, 1.9.x before 1.9.11, and 1.10.x before 1.10.3, when settings.DEBUG is True, allow remote attackers to conduct DNS rebinding…"
    },
    {
      "cve": "CVE-2016-9013",
      "sev": "critical",
      "kev": false,
      "title": "Django 1.8.x before 1.8.16, 1.9.x before 1.9.11, and 1.10.x before 1.10.3 use a…",
      "ranges": [
        {
          "eq": "1.10"
        },
        {
          "eq": "1.10.1"
        },
        {
          "eq": "1.10.2"
        },
        {
          "eq": "1.9"
        },
        {
          "eq": "1.9.1"
        },
        {
          "eq": "1.9.2"
        },
        {
          "eq": "1.9.3"
        },
        {
          "eq": "1.9.4"
        },
        {
          "eq": "1.9.5"
        },
        {
          "eq": "1.9.6"
        },
        {
          "eq": "1.9.7"
        },
        {
          "eq": "1.9.8"
        },
        {
          "eq": "1.9.9"
        },
        {
          "eq": "1.9.10"
        },
        {
          "eq": "1.8"
        },
        {
          "eq": "1.8.1"
        },
        {
          "eq": "1.8.2"
        },
        {
          "eq": "1.8.3"
        },
        {
          "eq": "1.8.4"
        },
        {
          "eq": "1.8.5"
        },
        {
          "eq": "1.8.6"
        },
        {
          "eq": "1.8.7"
        },
        {
          "eq": "1.8.8"
        },
        {
          "eq": "1.8.9"
        },
        {
          "eq": "1.8.10"
        },
        {
          "eq": "1.8.11"
        },
        {
          "eq": "1.8.12"
        },
        {
          "eq": "1.8.13"
        },
        {
          "eq": "1.8.14"
        },
        {
          "eq": "1.8.15"
        }
      ],
      "note": "NVD: Django 1.8.x before 1.8.16, 1.9.x before 1.9.11, and 1.10.x before 1.10.3 use a hardcoded password for a temporary database user created when running tests with an…"
    },
    {
      "cve": "CVE-2016-7401",
      "sev": "high",
      "kev": false,
      "title": "The cookie parsing code in Django before 1.8.15 and 1.9.x before 1.9.10, when used on…",
      "ranges": [
        {
          "lte": "1.8.14"
        },
        {
          "eq": "1.9.0"
        },
        {
          "eq": "1.9.1"
        },
        {
          "eq": "1.9.2"
        },
        {
          "eq": "1.9.3"
        },
        {
          "eq": "1.9.4"
        },
        {
          "eq": "1.9.5"
        },
        {
          "eq": "1.9.6"
        },
        {
          "eq": "1.9.7"
        },
        {
          "eq": "1.9.8"
        },
        {
          "eq": "1.9.9"
        }
      ],
      "note": "NVD: The cookie parsing code in Django before 1.8.15 and 1.9.x before 1.9.10, when used on a site with Google Analytics, allows remote attackers to bypass an intended…"
    },
    {
      "cve": "CVE-2016-2512",
      "sev": "high",
      "kev": false,
      "title": "The utils.http.is_safe_url function in Django before 1.8.10 and 1.9.x before 1.9.3…",
      "ranges": [
        {
          "eq": "1.8.9"
        },
        {
          "eq": "1.9"
        },
        {
          "eq": "1.9.1"
        },
        {
          "eq": "1.9.2"
        }
      ],
      "note": "NVD: The utils.http.is_safe_url function in Django before 1.8.10 and 1.9.x before 1.9.3 allows remote attackers to redirect users to arbitrary web sites and conduct…"
    }
  ],
  "drupal": [
    {
      "cve": "CVE-2026-9082",
      "sev": "critical",
      "kev": true,
      "title": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')…",
      "ranges": [
        {
          "gte": "8.9.0",
          "lt": "10.4.10"
        },
        {
          "gte": "10.5.0",
          "lt": "10.5.10"
        },
        {
          "gte": "10.6.0",
          "lt": "10.6.9"
        },
        {
          "gte": "11.0.0",
          "lt": "11.1.10"
        },
        {
          "gte": "11.2.0",
          "lt": "11.2.12"
        },
        {
          "gte": "11.3.0",
          "lt": "11.3.10"
        }
      ],
      "note": "NVD: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in Drupal Drupal core allows SQL… — CISA KEV (actively exploited)"
    },
    {
      "cve": "CVE-2025-31674",
      "sev": "high",
      "kev": false,
      "title": "Improperly Controlled Modification of Dynamically-Determined Object Attributes…",
      "ranges": [
        {
          "gte": "8.0.0",
          "lt": "10.3.13"
        },
        {
          "gte": "10.4.0",
          "lt": "10.4.3"
        },
        {
          "gte": "11.0.0",
          "lt": "11.0.12"
        },
        {
          "gte": "11.1.0",
          "lt": "11.1.3"
        }
      ],
      "note": "NVD: Improperly Controlled Modification of Dynamically-Determined Object Attributes vulnerability in Drupal Drupal core allows Object Injection.This issue affects…"
    },
    {
      "cve": "CVE-2024-55638",
      "sev": "critical",
      "kev": false,
      "title": "Deserialization of Untrusted Data vulnerability in Drupal Core allows Object…",
      "ranges": [
        {
          "gte": "7.0",
          "lt": "7.102"
        },
        {
          "gte": "8.0.0",
          "lt": "10.2.11"
        },
        {
          "gte": "10.3.0",
          "lt": "10.3.9"
        }
      ],
      "note": "NVD: Deserialization of Untrusted Data vulnerability in Drupal Core allows Object Injection.This issue affects Drupal Core: from 7.0 before 7.102, from 8.0.0 before…"
    },
    {
      "cve": "CVE-2024-55637",
      "sev": "critical",
      "kev": false,
      "title": "Deserialization of Untrusted Data vulnerability in Drupal Core allows Object…",
      "ranges": [
        {
          "gte": "8.0.0",
          "lt": "10.2.11"
        },
        {
          "gte": "10.3.0",
          "lt": "10.3.9"
        },
        {
          "gte": "11.0.0",
          "lt": "11.0.8"
        }
      ],
      "note": "NVD: Deserialization of Untrusted Data vulnerability in Drupal Core allows Object Injection.This issue affects Drupal Core: from 8.0.0 before 10.2.11, from 10.3.0…"
    },
    {
      "cve": "CVE-2024-55636",
      "sev": "critical",
      "kev": false,
      "title": "Deserialization of Untrusted Data vulnerability in Drupal Core allows Object…",
      "ranges": [
        {
          "gte": "8.0.0",
          "lt": "10.2.11"
        },
        {
          "gte": "10.3.0",
          "lt": "10.3.9"
        },
        {
          "gte": "11.0.0",
          "lt": "11.0.8"
        }
      ],
      "note": "NVD: Deserialization of Untrusted Data vulnerability in Drupal Core allows Object Injection.This issue affects Drupal Core: from 8.0.0 before 10.2.11, from 10.3.0…"
    },
    {
      "cve": "CVE-2024-55634",
      "sev": "high",
      "kev": false,
      "title": "A vulnerability in Drupal Core allows Privilege Escalation.This issue affects Drupal…",
      "ranges": [
        {
          "gte": "8.0.0",
          "lt": "10.2.11"
        },
        {
          "gte": "10.3.0",
          "lt": "10.3.9"
        },
        {
          "gte": "11.0.0",
          "lt": "11.0.8"
        }
      ],
      "note": "NVD: A vulnerability in Drupal Core allows Privilege Escalation.This issue affects Drupal Core: from 8.0.0 before 10.2.11, from 10.3.0 before 10.3.9, from 11.0.0 before…"
    },
    {
      "cve": "CVE-2024-22362",
      "sev": "high",
      "kev": false,
      "title": "Drupal contains a vulnerability with improper handling of structural elements.",
      "ranges": [
        {
          "eq": "9.3.6"
        }
      ],
      "note": "NVD: Drupal contains a vulnerability with improper handling of structural elements."
    },
    {
      "cve": "CVE-2024-11941",
      "sev": "high",
      "kev": false,
      "title": "A vulnerability in Drupal Core allows Excessive Allocation.This issue affects Drupal…",
      "ranges": [
        {
          "gte": "8.0.0",
          "lt": "10.1.8"
        },
        {
          "gte": "10.2.0",
          "lt": "10.2.2"
        }
      ],
      "note": "NVD: A vulnerability in Drupal Core allows Excessive Allocation.This issue affects Drupal Core: from 10.2.0 before 10.2.2, from 10.1.0 before 10.1.8."
    },
    {
      "cve": "CVE-2023-5256",
      "sev": "high",
      "kev": false,
      "title": "In certain scenarios, Drupal's JSON:API module will output error backtraces.",
      "ranges": [
        {
          "gte": "8.7.0",
          "lt": "9.5.11"
        },
        {
          "gte": "10.0.0",
          "lt": "10.0.11"
        },
        {
          "gte": "10.1.0",
          "lt": "10.1.4"
        }
      ],
      "note": "NVD: In certain scenarios, Drupal's JSON:API module will output error backtraces."
    },
    {
      "cve": "CVE-2022-39261",
      "sev": "high",
      "kev": false,
      "title": "Twig is a template language for PHP.",
      "ranges": [
        {
          "gte": "8.0.0",
          "lt": "9.3.22"
        },
        {
          "gte": "9.4.0",
          "lt": "9.4.7"
        }
      ],
      "note": "NVD: Twig is a template language for PHP."
    },
    {
      "cve": "CVE-2022-31043",
      "sev": "high",
      "kev": false,
      "title": "Guzzle is an open source PHP HTTP client.",
      "ranges": [
        {
          "gte": "9.2.0",
          "lt": "9.2.21"
        },
        {
          "gte": "9.3.0",
          "lt": "9.3.16"
        },
        {
          "eq": "9.4.0"
        }
      ],
      "note": "NVD: Guzzle is an open source PHP HTTP client."
    },
    {
      "cve": "CVE-2022-31042",
      "sev": "high",
      "kev": false,
      "title": "Guzzle is an open source PHP HTTP client.",
      "ranges": [
        {
          "gte": "9.2.0",
          "lt": "9.2.21"
        },
        {
          "gte": "9.3.0",
          "lt": "9.3.16"
        },
        {
          "eq": "9.4.0"
        }
      ],
      "note": "NVD: Guzzle is an open source PHP HTTP client."
    },
    {
      "cve": "CVE-2022-29248",
      "sev": "high",
      "kev": false,
      "title": "Guzzle is a PHP HTTP client.",
      "ranges": [
        {
          "gte": "9.2.0",
          "lt": "9.2.20"
        },
        {
          "gte": "9.3.0",
          "lt": "9.3.14"
        }
      ],
      "note": "NVD: Guzzle is a PHP HTTP client."
    },
    {
      "cve": "CVE-2022-25277",
      "sev": "high",
      "kev": false,
      "title": "Drupal core sanitizes filenames with dangerous extensions upon upload (reference:…",
      "ranges": [
        {
          "gte": "8.0.0",
          "lt": "9.3.19"
        },
        {
          "gte": "9.4.0",
          "lt": "9.4.3"
        }
      ],
      "note": "NVD: Drupal core sanitizes filenames with dangerous extensions upon upload (reference: SA-CORE-2020-012) and strips leading and trailing dots from filenames to prevent…"
    },
    {
      "cve": "CVE-2022-25275",
      "sev": "high",
      "kev": false,
      "title": "In some situations, the Image module does not correctly check access to image files…",
      "ranges": [
        {
          "gte": "7.0",
          "lt": "7.91"
        },
        {
          "gte": "8.0.0",
          "lt": "9.3.19"
        },
        {
          "gte": "9.4.0",
          "lt": "9.4.3"
        }
      ],
      "note": "NVD: In some situations, the Image module does not correctly check access to image files not stored in the standard public files directory when generating derivative…"
    },
    {
      "cve": "CVE-2022-25273",
      "sev": "high",
      "kev": false,
      "title": "Drupal core's form API has a vulnerability where certain contributed or custom…",
      "ranges": [
        {
          "gte": "8.0.0",
          "lt": "9.2.18"
        },
        {
          "gte": "9.3.0",
          "lt": "9.3.12"
        }
      ],
      "note": "NVD: Drupal core's form API has a vulnerability where certain contributed or custom modules' forms may be vulnerable to improper input validation."
    },
    {
      "cve": "CVE-2022-25271",
      "sev": "high",
      "kev": false,
      "title": "Drupal core's form API has a vulnerability where certain contributed or custom…",
      "ranges": [
        {
          "gte": "7.0.0",
          "lt": "7.88"
        },
        {
          "gte": "9.2.0",
          "lt": "9.2.13"
        },
        {
          "gte": "9.3.0",
          "lt": "9.3.6"
        }
      ],
      "note": "NVD: Drupal core's form API has a vulnerability where certain contributed or custom modules' forms may be vulnerable to improper input validation."
    },
    {
      "cve": "CVE-2022-24775",
      "sev": "high",
      "kev": false,
      "title": "guzzlehttp/psr7 is a PSR-7 HTTP message library.",
      "ranges": [
        {
          "gte": "8.0.0",
          "lt": "9.2.16"
        },
        {
          "gte": "9.3.0",
          "lt": "9.3.9"
        }
      ],
      "note": "NVD: guzzlehttp/psr7 is a PSR-7 HTTP message library."
    },
    {
      "cve": "CVE-2021-41165",
      "sev": "high",
      "kev": false,
      "title": "CKEditor4 is an open source WYSIWYG HTML editor.",
      "ranges": [
        {
          "gte": "8.9.0",
          "lt": "8.9.20"
        },
        {
          "gte": "9.1.0",
          "lt": "9.1.14"
        },
        {
          "gte": "9.2.0",
          "lt": "9.2.9"
        }
      ],
      "note": "NVD: CKEditor4 is an open source WYSIWYG HTML editor."
    },
    {
      "cve": "CVE-2021-41164",
      "sev": "high",
      "kev": false,
      "title": "CKEditor4 is an open source WYSIWYG HTML editor.",
      "ranges": [
        {
          "gte": "8.9.0",
          "lt": "8.9.20"
        },
        {
          "gte": "9.1.0",
          "lt": "9.1.14"
        },
        {
          "gte": "9.2.0",
          "lt": "9.2.9"
        }
      ],
      "note": "NVD: CKEditor4 is an open source WYSIWYG HTML editor."
    },
    {
      "cve": "CVE-2020-36193",
      "sev": "high",
      "kev": true,
      "title": "Tar.php in Archive_Tar through 1.4.11 allows write operations with Directory Traversal…",
      "ranges": [
        {
          "gte": "7.0",
          "lt": "7.78"
        },
        {
          "gte": "8.9.0",
          "lt": "8.9.13"
        },
        {
          "gte": "9.0.0",
          "lt": "9.0.11"
        },
        {
          "gte": "9.1.0",
          "lt": "9.1.3"
        }
      ],
      "note": "NVD: Tar.php in Archive_Tar through 1.4.11 allows write operations with Directory Traversal due to inadequate checking of symbolic… — CISA KEV (actively exploited)"
    },
    {
      "cve": "CVE-2020-28949",
      "sev": "high",
      "kev": true,
      "title": "Archive_Tar through 1.4.10 has :// filename sanitization only to address phar attacks,…",
      "ranges": [
        {
          "gte": "7.0",
          "lt": "7.75"
        },
        {
          "gte": "8.0.0",
          "lt": "8.9.10"
        },
        {
          "gte": "8.8.0",
          "lt": "8.8.12"
        },
        {
          "gte": "9.0.0",
          "lt": "9.0.9"
        }
      ],
      "note": "NVD: Archive_Tar through 1.4.10 has :// filename sanitization only to address phar attacks, and thus any other stream-wrapper attack… — CISA KEV (actively exploited)"
    },
    {
      "cve": "CVE-2020-28948",
      "sev": "high",
      "kev": false,
      "title": "Archive_Tar through 1.4.10 allows an unserialization attack because phar: is blocked…",
      "ranges": [
        {
          "gte": "7.0",
          "lt": "7.75"
        },
        {
          "gte": "8.0.0",
          "lt": "8.9.10"
        },
        {
          "gte": "8.8.0",
          "lt": "8.8.12"
        },
        {
          "gte": "9.0.0",
          "lt": "9.0.9"
        }
      ],
      "note": "NVD: Archive_Tar through 1.4.10 allows an unserialization attack because phar: is blocked but PHAR: is not blocked."
    },
    {
      "cve": "CVE-2020-13677",
      "sev": "high",
      "kev": false,
      "title": "Under some circumstances, the Drupal core JSON:API module does not properly restrict…",
      "ranges": [
        {
          "gte": "8.0.0",
          "lt": "8.9.19"
        },
        {
          "gte": "9.1.0",
          "lt": "9.1.13"
        },
        {
          "gte": "9.2.0",
          "lt": "9.2.6"
        }
      ],
      "note": "NVD: Under some circumstances, the Drupal core JSON:API module does not properly restrict access to certain content, which may result in unintended access bypass."
    },
    {
      "cve": "CVE-2020-13675",
      "sev": "critical",
      "kev": false,
      "title": "Drupal's JSON:API and REST/File modules allow file uploads through their HTTP APIs.",
      "ranges": [
        {
          "gte": "8.0.0",
          "lt": "8.9.19"
        },
        {
          "gte": "9.1.0",
          "lt": "9.1.13"
        },
        {
          "gte": "9.2.0",
          "lt": "9.2.6"
        }
      ],
      "note": "NVD: Drupal's JSON:API and REST/File modules allow file uploads through their HTTP APIs."
    },
    {
      "cve": "CVE-2020-13671",
      "sev": "high",
      "kev": true,
      "title": "Drupal core does not properly sanitize certain filenames on uploaded files, which can…",
      "ranges": [
        {
          "gte": "7.0",
          "lt": "7.74"
        },
        {
          "gte": "8.8.0",
          "lt": "8.8.11"
        },
        {
          "gte": "8.9.0",
          "lt": "8.9.9"
        },
        {
          "gte": "9.0.0",
          "lt": "9.0.8"
        }
      ],
      "note": "NVD: Drupal core does not properly sanitize certain filenames on uploaded files, which can lead to files being interpreted as the… — CISA KEV (actively exploited)"
    },
    {
      "cve": "CVE-2020-13670",
      "sev": "high",
      "kev": false,
      "title": "Information Disclosure vulnerability in file module of Drupal Core allows an attacker…",
      "ranges": [
        {
          "gte": "8.8.0",
          "lt": "8.8.10"
        },
        {
          "gte": "8.9.0",
          "lt": "8.9.6"
        },
        {
          "gte": "9.0.0",
          "lt": "9.0.6"
        }
      ],
      "note": "NVD: Information Disclosure vulnerability in file module of Drupal Core allows an attacker to gain access to the file metadata of a permanent private file that they do…"
    },
    {
      "cve": "CVE-2020-13665",
      "sev": "critical",
      "kev": false,
      "title": "Access bypass vulnerability in Drupal Core allows JSON:API when JSON:API is in…",
      "ranges": [
        {
          "gte": "8.8.0",
          "lt": "8.8.8"
        },
        {
          "gte": "8.9.0",
          "lt": "8.9.1"
        },
        {
          "gte": "9.0.0",
          "lt": "9.0.1"
        }
      ],
      "note": "NVD: Access bypass vulnerability in Drupal Core allows JSON:API when JSON:API is in read/write mode."
    },
    {
      "cve": "CVE-2020-13664",
      "sev": "high",
      "kev": false,
      "title": "Arbitrary PHP code execution vulnerability in Drupal Core under certain circumstances.",
      "ranges": [
        {
          "gte": "8.8.0",
          "lt": "8.8.8"
        },
        {
          "gte": "8.9.0",
          "lt": "8.9.1"
        },
        {
          "gte": "9.0.0",
          "lt": "9.0.1"
        }
      ],
      "note": "NVD: Arbitrary PHP code execution vulnerability in Drupal Core under certain circumstances."
    },
    {
      "cve": "CVE-2020-13663",
      "sev": "high",
      "kev": false,
      "title": "Cross Site Request Forgery vulnerability in Drupal Core Form API does not properly…",
      "ranges": [
        {
          "gte": "7.0",
          "lt": "7.72"
        },
        {
          "gte": "8.8.0",
          "lt": "8.8.8"
        },
        {
          "gte": "8.9.0",
          "lt": "8.9.1"
        },
        {
          "gte": "9.0.0",
          "lt": "9.0.1"
        }
      ],
      "note": "NVD: Cross Site Request Forgery vulnerability in Drupal Core Form API does not properly handle certain form input from cross-site requests, which can lead to other…"
    },
    {
      "cve": "CVE-2020-11023",
      "sev": "medium",
      "kev": true,
      "title": "In jQuery versions greater than or equal to 1.0.3 and before 3.5.0, passing HTML…",
      "ranges": [
        {
          "gte": "7.0",
          "lt": "7.70"
        },
        {
          "gte": "8.7.0",
          "lt": "8.7.14"
        },
        {
          "gte": "8.8.0",
          "lt": "8.8.6"
        }
      ],
      "note": "NVD: In jQuery versions greater than or equal to 1.0.3 and before 3.5.0, passing HTML containing <option> elements from untrusted… — CISA KEV (actively exploited)"
    },
    {
      "cve": "CVE-2019-11831",
      "sev": "critical",
      "kev": false,
      "title": "The PharStreamWrapper (aka phar-stream-wrapper) package 2.x before 2.1.1 and 3.x…",
      "ranges": [
        {
          "gte": "7.0",
          "lt": "7.67"
        },
        {
          "gte": "8.6.0",
          "lt": "8.6.16"
        },
        {
          "gte": "8.7.0",
          "lt": "8.7.1"
        }
      ],
      "note": "NVD: The PharStreamWrapper (aka phar-stream-wrapper) package 2.x before 2.1.1 and 3.x before 3.1.1 for TYPO3 does not prevent directory traversal, which allows…"
    },
    {
      "cve": "CVE-2019-10911",
      "sev": "high",
      "kev": false,
      "title": "In Symfony before 2.7.51, 2.8.x before 2.8.50, 3.x before 3.4.26, 4.x before 4.1.12,…",
      "ranges": [
        {
          "gte": "8.5.0",
          "lt": "8.5.15"
        },
        {
          "gte": "8.6.0",
          "lt": "8.6.15"
        }
      ],
      "note": "NVD: In Symfony before 2.7.51, 2.8.x before 2.8.50, 3.x before 3.4.26, 4.x before 4.1.12, and 4.2.x before 4.2.7, a vulnerability would allow an attacker to…"
    },
    {
      "cve": "CVE-2019-10910",
      "sev": "critical",
      "kev": false,
      "title": "In Symfony before 2.7.51, 2.8.x before 2.8.50, 3.x before 3.4.26, 4.x before 4.1.12,…",
      "ranges": [
        {
          "gte": "8.5.0",
          "lt": "8.5.15"
        },
        {
          "gte": "8.6.0",
          "lt": "8.6.15"
        }
      ],
      "note": "NVD: In Symfony before 2.7.51, 2.8.x before 2.8.50, 3.x before 3.4.26, 4.x before 4.1.12, and 4.2.x before 4.2.7, when service ids allow user input, this could allow…"
    },
    {
      "cve": "CVE-2019-6342",
      "sev": "critical",
      "kev": false,
      "title": "An access bypass vulnerability exists when the experimental Workspaces module in…",
      "ranges": [
        {
          "eq": "8.7.4"
        }
      ],
      "note": "NVD: An access bypass vulnerability exists when the experimental Workspaces module in Drupal 8 core is enabled."
    },
    {
      "cve": "CVE-2019-6340",
      "sev": "high",
      "kev": true,
      "title": "Some field types do not properly sanitize data from non-form sources in Drupal 8.5.x…",
      "ranges": [
        {
          "gte": "8.5.0",
          "lt": "8.5.11"
        },
        {
          "gte": "8.6.0",
          "lt": "8.6.10"
        }
      ],
      "note": "NVD: Some field types do not properly sanitize data from non-form sources in Drupal 8.5.x before 8.5.11 and Drupal 8.6.x before 8.6.10. — CISA KEV (actively exploited)"
    },
    {
      "cve": "CVE-2019-6339",
      "sev": "critical",
      "kev": false,
      "title": "In Drupal Core versions 7.x prior to 7.62, 8.6.x prior to 8.6.6 and 8.5.x prior to…",
      "ranges": [
        {
          "gte": "7.0",
          "lt": "7.62"
        },
        {
          "gte": "8.5.0",
          "lt": "8.5.9"
        },
        {
          "gte": "8.6.0",
          "lt": "8.6.6"
        }
      ],
      "note": "NVD: In Drupal Core versions 7.x prior to 7.62, 8.6.x prior to 8.6.6 and 8.5.x prior to 8.5.9; A remote code execution vulnerability exists in PHP's built-in phar…"
    },
    {
      "cve": "CVE-2019-6338",
      "sev": "high",
      "kev": false,
      "title": "In Drupal Core versions 7.x prior to 7.62, 8.6.x prior to 8.6.6 and 8.5.x prior to…",
      "ranges": [
        {
          "gte": "7.0",
          "lt": "7.62"
        },
        {
          "gte": "8.5.0",
          "lt": "8.5.9"
        },
        {
          "gte": "8.6.0",
          "lt": "8.6.6"
        }
      ],
      "note": "NVD: In Drupal Core versions 7.x prior to 7.62, 8.6.x prior to 8.6.6 and 8.5.x prior to 8.5.9; Drupal core uses the third-party PEAR Archive_Tar library."
    },
    {
      "cve": "CVE-2018-7602",
      "sev": "critical",
      "kev": true,
      "title": "A remote code execution vulnerability exists within multiple subsystems of Drupal 7.x…",
      "ranges": [
        {
          "gte": "7.0",
          "lt": "7.59"
        },
        {
          "gte": "8.4.0",
          "lt": "8.4.8"
        },
        {
          "gte": "8.5.0",
          "lt": "8.5.3"
        }
      ],
      "note": "NVD: A remote code execution vulnerability exists within multiple subsystems of Drupal 7.x and 8.x. — CISA KEV (actively exploited)"
    },
    {
      "cve": "CVE-2018-7600",
      "sev": "critical",
      "kev": true,
      "title": "Drupal before 7.58, 8.x before 8.3.9, 8.4.x before 8.4.6, and 8.5.x before 8.5.1…",
      "ranges": [
        {
          "lte": "7.57"
        },
        {
          "gte": "8.0.0",
          "lt": "8.3.9"
        },
        {
          "gte": "8.4.0",
          "lt": "8.4.6"
        },
        {
          "gte": "8.5.0",
          "lt": "8.5.1"
        }
      ],
      "note": "NVD: Drupal before 7.58, 8.x before 8.3.9, 8.4.x before 8.4.6, and 8.5.x before 8.5.1 allows remote attackers to execute arbitrary code… — CISA KEV (actively exploited)"
    },
    {
      "cve": "CVE-2017-6930",
      "sev": "high",
      "kev": false,
      "title": "In Drupal versions 8.4.x versions before 8.4.5 when using node access controls with a…",
      "ranges": [
        {
          "gte": "8.4.0",
          "lt": "8.4.5"
        }
      ],
      "note": "NVD: In Drupal versions 8.4.x versions before 8.4.5 when using node access controls with a multilingual site, Drupal marks the untranslated version of a node as the…"
    },
    {
      "cve": "CVE-2017-6926",
      "sev": "high",
      "kev": false,
      "title": "In Drupal versions 8.4.x versions before 8.4.5 users with permission to post comments…",
      "ranges": [
        {
          "gte": "8.4.0",
          "lt": "8.4.5"
        }
      ],
      "note": "NVD: In Drupal versions 8.4.x versions before 8.4.5 users with permission to post comments are able to view content and comments they do not have access to, and are…"
    },
    {
      "cve": "CVE-2017-6925",
      "sev": "critical",
      "kev": false,
      "title": "In versions of Drupal 8 core prior to 8.3.7; There is a vulnerability in the entity…",
      "ranges": [
        {
          "gte": "8.0.0",
          "lt": "8.3.7"
        }
      ],
      "note": "NVD: In versions of Drupal 8 core prior to 8.3.7; There is a vulnerability in the entity access system that could allow unwanted access to view, create, update, or…"
    },
    {
      "cve": "CVE-2017-6924",
      "sev": "high",
      "kev": false,
      "title": "In Drupal 8 prior to 8.3.7; When using the REST API, users without the correct…",
      "ranges": [
        {
          "gte": "8.0.0",
          "lt": "8.3.7"
        }
      ],
      "note": "NVD: In Drupal 8 prior to 8.3.7; When using the REST API, users without the correct permission can post comments via REST that are approved even if the user does not…"
    },
    {
      "cve": "CVE-2017-6920",
      "sev": "critical",
      "kev": false,
      "title": "Drupal core 8 before versions 8.3.4 allows remote attackers to execute arbitrary code…",
      "ranges": [
        {
          "gte": "8.0.0",
          "lt": "8.3.4"
        }
      ],
      "note": "NVD: Drupal core 8 before versions 8.3.4 allows remote attackers to execute arbitrary code due to the PECL YAML parser not handling PHP objects safely during certain…"
    },
    {
      "cve": "CVE-2017-6919",
      "sev": "high",
      "kev": false,
      "title": "Drupal 8 before 8.2.8 and 8.3 before 8.3.1 allows critical access bypass by…",
      "ranges": [
        {
          "eq": "8.0.0"
        },
        {
          "eq": "8.0.1"
        },
        {
          "eq": "8.0.2"
        },
        {
          "eq": "8.0.3"
        },
        {
          "eq": "8.0.4"
        },
        {
          "eq": "8.0.5"
        },
        {
          "eq": "8.0.6"
        },
        {
          "eq": "8.1.0"
        },
        {
          "eq": "8.1.1"
        },
        {
          "eq": "8.1.2"
        },
        {
          "eq": "8.1.3"
        },
        {
          "eq": "8.1.4"
        },
        {
          "eq": "8.1.5"
        },
        {
          "eq": "8.1.6"
        },
        {
          "eq": "8.1.7"
        },
        {
          "eq": "8.1.8"
        },
        {
          "eq": "8.1.9"
        },
        {
          "eq": "8.1.10"
        },
        {
          "eq": "8.2.0"
        },
        {
          "eq": "8.2.1"
        },
        {
          "eq": "8.2.2"
        },
        {
          "eq": "8.2.3"
        },
        {
          "eq": "8.2.4"
        },
        {
          "eq": "8.2.5"
        },
        {
          "eq": "8.2.6"
        },
        {
          "eq": "8.2.7"
        },
        {
          "eq": "8.3.0"
        }
      ],
      "note": "NVD: Drupal 8 before 8.2.8 and 8.3 before 8.3.1 allows critical access bypass by authenticated users if the RESTful Web Services (rest) module is enabled and the site…"
    },
    {
      "cve": "CVE-2017-6381",
      "sev": "high",
      "kev": false,
      "title": "A 3rd party development library including with Drupal 8 development dependencies is…",
      "ranges": [
        {
          "eq": "8.0.0"
        },
        {
          "eq": "8.0.1"
        },
        {
          "eq": "8.0.2"
        },
        {
          "eq": "8.0.3"
        },
        {
          "eq": "8.0.4"
        },
        {
          "eq": "8.0.5"
        },
        {
          "eq": "8.0.6"
        },
        {
          "eq": "8.1.0"
        },
        {
          "eq": "8.1.1"
        },
        {
          "eq": "8.1.2"
        },
        {
          "eq": "8.1.3"
        },
        {
          "eq": "8.1.4"
        },
        {
          "eq": "8.1.5"
        },
        {
          "eq": "8.1.6"
        },
        {
          "eq": "8.1.7"
        },
        {
          "eq": "8.1.8"
        },
        {
          "eq": "8.1.9"
        },
        {
          "eq": "8.1.10"
        },
        {
          "eq": "8.2.0"
        },
        {
          "eq": "8.2.1"
        }
      ],
      "note": "NVD: A 3rd party development library including with Drupal 8 development dependencies is vulnerable to remote code execution."
    },
    {
      "cve": "CVE-2017-6379",
      "sev": "high",
      "kev": false,
      "title": "Some administrative paths in Drupal 8.2.x before 8.2.7 did not include protection for…",
      "ranges": [
        {
          "eq": "8.2.0"
        },
        {
          "eq": "8.2.1"
        },
        {
          "eq": "8.2.2"
        },
        {
          "eq": "8.2.3"
        },
        {
          "eq": "8.2.4"
        },
        {
          "eq": "8.2.5"
        },
        {
          "eq": "8.2.6"
        }
      ],
      "note": "NVD: Some administrative paths in Drupal 8.2.x before 8.2.7 did not include protection for CSRF."
    },
    {
      "cve": "CVE-2017-6377",
      "sev": "high",
      "kev": false,
      "title": "When adding a private file via the editor in Drupal 8.2.x before 8.2.7, the editor…",
      "ranges": [
        {
          "eq": "8.2.0"
        },
        {
          "eq": "8.2.1"
        },
        {
          "eq": "8.2.2"
        },
        {
          "eq": "8.2.3"
        },
        {
          "eq": "8.2.4"
        },
        {
          "eq": "8.2.5"
        },
        {
          "eq": "8.2.6"
        }
      ],
      "note": "NVD: When adding a private file via the editor in Drupal 8.2.x before 8.2.7, the editor will not correctly check access for the file being attached, resulting in an…"
    },
    {
      "cve": "CVE-2016-9450",
      "sev": "high",
      "kev": false,
      "title": "The user password reset form in Drupal 8.x before 8.2.3 allows remote attackers to…",
      "ranges": [
        {
          "eq": "8.0.0"
        },
        {
          "eq": "8.0.1"
        },
        {
          "eq": "8.0.2"
        },
        {
          "eq": "8.0.3"
        },
        {
          "eq": "8.0.4"
        },
        {
          "eq": "8.0.5"
        },
        {
          "eq": "8.0.6"
        },
        {
          "eq": "8.1.0"
        },
        {
          "eq": "8.1.1"
        },
        {
          "eq": "8.1.2"
        },
        {
          "eq": "8.1.3"
        },
        {
          "eq": "8.1.4"
        },
        {
          "eq": "8.1.5"
        },
        {
          "eq": "8.1.6"
        },
        {
          "eq": "8.1.7"
        },
        {
          "eq": "8.1.8"
        },
        {
          "eq": "8.1.9"
        },
        {
          "eq": "8.1.10"
        },
        {
          "eq": "8.2.0"
        },
        {
          "eq": "8.2.1"
        },
        {
          "eq": "8.2.2"
        }
      ],
      "note": "NVD: The user password reset form in Drupal 8.x before 8.2.3 allows remote attackers to conduct cache poisoning attacks by leveraging failure to specify a correct cache…"
    },
    {
      "cve": "CVE-2016-5385",
      "sev": "high",
      "kev": false,
      "title": "PHP through 7.0.8 does not attempt to address RFC 3875 section 4.1.18 namespace…",
      "ranges": [
        {
          "gte": "8.0.0",
          "lt": "8.1.7"
        }
      ],
      "note": "NVD: PHP through 7.0.8 does not attempt to address RFC 3875 section 4.1.18 namespace conflicts and therefore does not protect applications from the presence of…"
    }
  ],
  "express": [
    {
      "cve": "CVE-2022-24999",
      "sev": "high",
      "kev": false,
      "title": "qs before 6.10.3, as used in Express before 4.17.3 and other products, allows…",
      "ranges": [
        {
          "lt": "4.17.3"
        }
      ],
      "note": "NVD: qs before 6.10.3, as used in Express before 4.17.3 and other products, allows attackers to cause a Node process hang for an Express application because an __…"
    }
  ],
  "iis": [
    {
      "cve": "CVE-2017-7269",
      "sev": "critical",
      "kev": true,
      "title": "Buffer overflow in the ScStoragePathFromUrl function in the WebDAV service in Internet…",
      "ranges": [
        {
          "eq": "6.0"
        }
      ],
      "note": "NVD: Buffer overflow in the ScStoragePathFromUrl function in the WebDAV service in Internet Information Services (IIS) 6.0 in Microsoft… — CISA KEV (actively exploited)"
    }
  ],
  "joomla": [
    {
      "cve": "CVE-2026-73373",
      "sev": "critical",
      "kev": false,
      "title": "Joomla! Core - [20260810] - Unrestricted uploads of SHTML files in Joomla 1.0.0-5.4.7,…",
      "ranges": [
        {
          "gte": "1.0.0",
          "lt": "5.4.8"
        },
        {
          "gte": "6.0.0",
          "lt": "6.1.3"
        }
      ],
      "note": "NVD: Joomla! Core - [20260810] - Unrestricted uploads of SHTML files in Joomla 1.0.0-5.4.7, 6.0.0-6.1.2 - The default list of dangerous files did not include SHTML files."
    },
    {
      "cve": "CVE-2026-73337",
      "sev": "high",
      "kev": false,
      "title": "Joomla! Core - [20260807] - MFA Authentication Bypass in Joomla 4.0.0-5.4.7 and…",
      "ranges": [
        {
          "gte": "4.0.0",
          "lt": "5.4.8"
        },
        {
          "gte": "6.0.0",
          "lt": "6.1.3"
        }
      ],
      "note": "NVD: Joomla! Core - [20260807] - MFA Authentication Bypass in Joomla 4.0.0-5.4.7 and 6.0.0-6.1.2 - Insufficient state checks lead to a vector that allows to bypass 2FA…"
    },
    {
      "cve": "CVE-2026-71573",
      "sev": "high",
      "kev": false,
      "title": "Joomla! Core - [20260802] - Improper CORS origin validation in Joomla 4.0.0-5.4.7,…",
      "ranges": [
        {
          "gte": "4.0.0",
          "lt": "5.4.8"
        },
        {
          "gte": "6.0.0",
          "lt": "6.1.3"
        }
      ],
      "note": "NVD: Joomla! Core - [20260802] - Improper CORS origin validation in Joomla 4.0.0-5.4.7, 6.0.0-6.1.2 - An improper implementation prevented configured CORS origins from…"
    },
    {
      "cve": "CVE-2026-48958",
      "sev": "high",
      "kev": false,
      "title": "An improper access check allows unauthorized users to create custom fields via…",
      "ranges": [
        {
          "gte": "4.0.0",
          "lt": "5.4.7"
        },
        {
          "gte": "6.0.0",
          "lt": "6.1.2"
        }
      ],
      "note": "NVD: An improper access check allows unauthorized users to create custom fields via webservices endpoints."
    },
    {
      "cve": "CVE-2026-48957",
      "sev": "high",
      "kev": false,
      "title": "An improper access check allows unauthorized users to access com_privacy datasets.",
      "ranges": [
        {
          "gte": "4.0.0",
          "lt": "5.4.7"
        },
        {
          "gte": "6.0.0",
          "lt": "6.1.2"
        }
      ],
      "note": "NVD: An improper access check allows unauthorized users to access com_privacy datasets."
    },
    {
      "cve": "CVE-2026-48948",
      "sev": "high",
      "kev": false,
      "title": "An improper access check allows user to download vcard exports of com_contact contacts…",
      "ranges": [
        {
          "gte": "3.0.0",
          "lt": "5.4.7"
        },
        {
          "gte": "6.0.0",
          "lt": "6.1.2"
        }
      ],
      "note": "NVD: An improper access check allows user to download vcard exports of com_contact contacts that are inaccessible."
    },
    {
      "cve": "CVE-2026-48904",
      "sev": "critical",
      "kev": false,
      "title": "An improper access check allows privelege escalation through the com_users group…",
      "ranges": [
        {
          "gte": "4.0.0",
          "lt": "5.4.6"
        },
        {
          "gte": "6.0.0",
          "lt": "6.1.1"
        }
      ],
      "note": "NVD: An improper access check allows privelege escalation through the com_users group editing webservice endpoint."
    },
    {
      "cve": "CVE-2026-48902",
      "sev": "critical",
      "kev": false,
      "title": "The password and username reset features created plain http links for https…",
      "ranges": [
        {
          "gte": "3.0.0",
          "lt": "5.4.6"
        },
        {
          "gte": "6.0.0",
          "lt": "6.1.1"
        }
      ],
      "note": "NVD: The password and username reset features created plain http links for https connections if the \"Force SSL\" flag wasn't explicitly set."
    },
    {
      "cve": "CVE-2026-48901",
      "sev": "high",
      "kev": false,
      "title": "The InputFilter::getInstance() method omitted a security sensitive parameter from the…",
      "ranges": [
        {
          "gte": "4.0.0",
          "lt": "5.4.6"
        },
        {
          "gte": "6.0.0",
          "lt": "6.1.1"
        }
      ],
      "note": "NVD: The InputFilter::getInstance() method omitted a security sensitive parameter from the instance cache key."
    },
    {
      "cve": "CVE-2026-48899",
      "sev": "critical",
      "kev": false,
      "title": "An improper access check allows privilege escalation through the com_users batch task.",
      "ranges": [
        {
          "gte": "4.0.0",
          "lt": "5.4.6"
        },
        {
          "gte": "6.0.0",
          "lt": "6.1.1"
        }
      ],
      "note": "NVD: An improper access check allows privilege escalation through the com_users batch task."
    },
    {
      "cve": "CVE-2026-48898",
      "sev": "critical",
      "kev": false,
      "title": "An improper access check allows privilege escalation through the com_users batch task.",
      "ranges": [
        {
          "gte": "4.0.0",
          "lt": "5.4.6"
        },
        {
          "gte": "6.0.0",
          "lt": "6.1.1"
        }
      ],
      "note": "NVD: An improper access check allows privilege escalation through the com_users batch task."
    },
    {
      "cve": "CVE-2026-48897",
      "sev": "high",
      "kev": false,
      "title": "Insufficient state checks lead to a vector that allows to bypass 2FA checks.",
      "ranges": [
        {
          "gte": "4.0.0",
          "lt": "5.4.6"
        },
        {
          "gte": "6.0.0",
          "lt": "6.1.1"
        }
      ],
      "note": "NVD: Insufficient state checks lead to a vector that allows to bypass 2FA checks."
    },
    {
      "cve": "CVE-2026-48896",
      "sev": "high",
      "kev": false,
      "title": "Insufficient state checks lead to a vector that allows to bypass 2FA checks.",
      "ranges": [
        {
          "gte": "4.0.0",
          "lt": "5.4.6"
        },
        {
          "gte": "6.0.0",
          "lt": "6.1.1"
        }
      ],
      "note": "NVD: Insufficient state checks lead to a vector that allows to bypass 2FA checks."
    },
    {
      "cve": "CVE-2026-40384",
      "sev": "high",
      "kev": false,
      "title": "An improper validation of the search parameter of the com_media files API endpoint…",
      "ranges": [
        {
          "gte": "4.0.0",
          "lt": "5.4.6"
        },
        {
          "gte": "6.0.0",
          "lt": "6.1.1"
        }
      ],
      "note": "NVD: An improper validation of the search parameter of the com_media files API endpoint leads to a path traversal vulnerability."
    },
    {
      "cve": "CVE-2026-40383",
      "sev": "critical",
      "kev": false,
      "title": "An improper validation of user-supplied input leads to a local file inclusion…",
      "ranges": [
        {
          "gte": "3.2.1",
          "lt": "5.4.6"
        },
        {
          "gte": "6.0.0",
          "lt": "6.1.1"
        }
      ],
      "note": "NVD: An improper validation of user-supplied input leads to a local file inclusion vulnerability."
    },
    {
      "cve": "CVE-2026-35223",
      "sev": "critical",
      "kev": false,
      "title": "An improper access check allows unauthorized access to com_config webservice endpoints.",
      "ranges": [
        {
          "gte": "4.0.0",
          "lt": "5.4.6"
        },
        {
          "gte": "6.0.0",
          "lt": "6.1.1"
        }
      ],
      "note": "NVD: An improper access check allows unauthorized access to com_config webservice endpoints."
    },
    {
      "cve": "CVE-2026-35222",
      "sev": "critical",
      "kev": false,
      "title": "Improperly validated order clauses lead to a SQL injection vulnerability in com_tags.",
      "ranges": [
        {
          "gte": "3.0.0",
          "lt": "5.4.6"
        },
        {
          "gte": "6.0.0",
          "lt": "6.1.1"
        }
      ],
      "note": "NVD: Improperly validated order clauses lead to a SQL injection vulnerability in com_tags."
    },
    {
      "cve": "CVE-2026-35221",
      "sev": "critical",
      "kev": false,
      "title": "Improperly built filter clauses lead to a SQL injection vulnerability in the search…",
      "ranges": [
        {
          "gte": "3.0.0",
          "lt": "5.4.6"
        },
        {
          "gte": "6.0.0",
          "lt": "6.1.1"
        }
      ],
      "note": "NVD: Improperly built filter clauses lead to a SQL injection vulnerability in the search query for com_finder."
    },
    {
      "cve": "CVE-2026-23899",
      "sev": "high",
      "kev": false,
      "title": "An improper access check allows unauthorized access to webservice endpoints.",
      "ranges": [
        {
          "gte": "3.0.0",
          "lt": "5.4.4"
        },
        {
          "gte": "6.0.0",
          "lt": "6.0.4"
        }
      ],
      "note": "NVD: An improper access check allows unauthorized access to webservice endpoints."
    },
    {
      "cve": "CVE-2026-23898",
      "sev": "high",
      "kev": false,
      "title": "Lack of input validation leads to an arbitrary file deletion vulnerability in the…",
      "ranges": [
        {
          "gte": "3.0.0",
          "lt": "5.4.4"
        },
        {
          "gte": "6.0.0",
          "lt": "6.0.4"
        }
      ],
      "note": "NVD: Lack of input validation leads to an arbitrary file deletion vulnerability in the autoupdate server mechanism."
    },
    {
      "cve": "CVE-2026-21630",
      "sev": "high",
      "kev": false,
      "title": "Improperly built order clauses lead to a SQL injection vulnerability in the articles…",
      "ranges": [
        {
          "gte": "3.0.0",
          "lt": "5.4.4"
        },
        {
          "gte": "6.0.0",
          "lt": "6.0.4"
        }
      ],
      "note": "NVD: Improperly built order clauses lead to a SQL injection vulnerability in the articles webservice endpoint."
    },
    {
      "cve": "CVE-2026-21629",
      "sev": "high",
      "kev": false,
      "title": "The ajax component was excluded from the default logged-in-user check in the…",
      "ranges": [
        {
          "gte": "3.0.0",
          "lt": "5.4.4"
        },
        {
          "gte": "6.0.0",
          "lt": "6.0.4"
        }
      ],
      "note": "NVD: The ajax component was excluded from the default logged-in-user check in the administrative area."
    },
    {
      "cve": "CVE-2025-25227",
      "sev": "high",
      "kev": false,
      "title": "Insufficient state checks lead to a vector that allows to bypass 2FA checks.",
      "ranges": [
        {
          "gte": "4.0.0",
          "lt": "4.4.13"
        },
        {
          "gte": "5.0.0",
          "lt": "5.2.6"
        }
      ],
      "note": "NVD: Insufficient state checks lead to a vector that allows to bypass 2FA checks."
    },
    {
      "cve": "CVE-2025-25226",
      "sev": "critical",
      "kev": false,
      "title": "Improper handling of identifiers lead to a SQL injection vulnerability in the…",
      "ranges": [
        {
          "gte": "1.0.0",
          "lt": "2.2.0"
        },
        {
          "gte": "3.0.0",
          "lt": "3.4.0"
        }
      ],
      "note": "NVD: Improper handling of identifiers lead to a SQL injection vulnerability in the quoteNameStr method of the database package."
    },
    {
      "cve": "CVE-2024-40749",
      "sev": "high",
      "kev": false,
      "title": "Improper Access Controls allows access to protected views.",
      "ranges": [
        {
          "gte": "3.9.0",
          "lt": "3.10.20"
        },
        {
          "gte": "4.0.0",
          "lt": "4.4.10"
        },
        {
          "gte": "5.0.0",
          "lt": "5.2.3"
        }
      ],
      "note": "NVD: Improper Access Controls allows access to protected views."
    },
    {
      "cve": "CVE-2024-40748",
      "sev": "high",
      "kev": false,
      "title": "Lack of output escaping in the id attribute of menu lists.",
      "ranges": [
        {
          "gte": "3.9.0",
          "lt": "3.10.20"
        },
        {
          "gte": "4.0.0",
          "lt": "4.4.10"
        },
        {
          "gte": "5.0.0",
          "lt": "5.2.3"
        }
      ],
      "note": "NVD: Lack of output escaping in the id attribute of menu lists."
    },
    {
      "cve": "CVE-2024-27187",
      "sev": "high",
      "kev": false,
      "title": "Improper Access Controls allows backend users to overwrite their username when…",
      "ranges": [
        {
          "gte": "4.0.0",
          "lt": "4.4.7"
        },
        {
          "gte": "5.0.0",
          "lt": "5.1.3"
        }
      ],
      "note": "NVD: Improper Access Controls allows backend users to overwrite their username when disallowed."
    },
    {
      "cve": "CVE-2024-27185",
      "sev": "critical",
      "kev": false,
      "title": "The pagination class includes arbitrary parameters in links, leading to cache…",
      "ranges": [
        {
          "gte": "3.0.0",
          "lt": "3.10.17"
        },
        {
          "gte": "4.0.0",
          "lt": "4.4.7"
        },
        {
          "gte": "5.0.0",
          "lt": "5.1.3"
        }
      ],
      "note": "NVD: The pagination class includes arbitrary parameters in links, leading to cache poisoning attack vectors."
    },
    {
      "cve": "CVE-2023-40626",
      "sev": "high",
      "kev": false,
      "title": "The language file parsing process could be manipulated to expose environment variables.",
      "ranges": [
        {
          "gte": "1.6.0",
          "lt": "3.10.14"
        },
        {
          "gte": "4.0.0",
          "lt": "4.4.1"
        },
        {
          "eq": "5.0.0"
        }
      ],
      "note": "NVD: The language file parsing process could be manipulated to expose environment variables."
    },
    {
      "cve": "CVE-2023-23755",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in Joomla! 4.2.0 through 4.3.1.",
      "ranges": [
        {
          "gte": "4.2.0",
          "lt": "4.3.2"
        }
      ],
      "note": "NVD: An issue was discovered in Joomla! 4.2.0 through 4.3.1."
    },
    {
      "cve": "CVE-2023-23752",
      "sev": "medium",
      "kev": true,
      "title": "An issue was discovered in Joomla! 4.0.0 through 4.2.7.",
      "ranges": [
        {
          "gte": "4.0.0",
          "lt": "4.2.8"
        }
      ],
      "note": "NVD: An issue was discovered in Joomla! 4.0.0 through 4.2.7. — CISA KEV (actively exploited)"
    },
    {
      "cve": "CVE-2022-23799",
      "sev": "critical",
      "kev": false,
      "title": "An issue was discovered in Joomla! 4.0.0 through 4.1.0.",
      "ranges": [
        {
          "gte": "4.0.0",
          "lte": "4.1.0"
        }
      ],
      "note": "NVD: An issue was discovered in Joomla! 4.0.0 through 4.1.0."
    },
    {
      "cve": "CVE-2022-23797",
      "sev": "critical",
      "kev": false,
      "title": "An issue was discovered in Joomla! 3.0.0 through 3.10.6 & 4.0.0 through 4.1.0.",
      "ranges": [
        {
          "gte": "3.0.0",
          "lte": "3.10.6"
        },
        {
          "gte": "4.0.0",
          "lte": "4.1.0"
        }
      ],
      "note": "NVD: An issue was discovered in Joomla! 3.0.0 through 3.10.6 & 4.0.0 through 4.1.0."
    },
    {
      "cve": "CVE-2022-23795",
      "sev": "critical",
      "kev": false,
      "title": "An issue was discovered in Joomla! 2.5.0 through 3.10.6 & 4.0.0 through 4.1.0.",
      "ranges": [
        {
          "gte": "2.5.0",
          "lte": "3.10.6"
        },
        {
          "gte": "4.0.0",
          "lte": "4.1.0"
        }
      ],
      "note": "NVD: An issue was discovered in Joomla! 2.5.0 through 3.10.6 & 4.0.0 through 4.1.0."
    },
    {
      "cve": "CVE-2022-23793",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in Joomla! 3.0.0 through 3.10.6 & 4.0.0 through 4.1.0.",
      "ranges": [
        {
          "gte": "3.0.0",
          "lte": "3.10.6"
        },
        {
          "gte": "4.0.0",
          "lte": "4.1.0"
        }
      ],
      "note": "NVD: An issue was discovered in Joomla! 3.0.0 through 3.10.6 & 4.0.0 through 4.1.0."
    },
    {
      "cve": "CVE-2021-26040",
      "sev": "critical",
      "kev": false,
      "title": "An issue was discovered in Joomla! 4.0.0.",
      "ranges": [
        {
          "eq": "4.0.0"
        }
      ],
      "note": "NVD: An issue was discovered in Joomla! 4.0.0."
    },
    {
      "cve": "CVE-2021-26038",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in Joomla! 2.5.0 through 3.9.27.",
      "ranges": [
        {
          "gte": "2.5.0",
          "lte": "3.9.27"
        }
      ],
      "note": "NVD: An issue was discovered in Joomla! 2.5.0 through 3.9.27."
    },
    {
      "cve": "CVE-2021-26036",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in Joomla! 2.5.0 through 3.9.27.",
      "ranges": [
        {
          "gte": "2.5.0",
          "lte": "3.9.27"
        }
      ],
      "note": "NVD: An issue was discovered in Joomla! 2.5.0 through 3.9.27."
    },
    {
      "cve": "CVE-2021-23132",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in Joomla! 3.0.0 through 3.9.24.",
      "ranges": [
        {
          "gte": "3.0.0",
          "lt": "3.9.25"
        }
      ],
      "note": "NVD: An issue was discovered in Joomla! 3.0.0 through 3.9.24."
    },
    {
      "cve": "CVE-2021-23131",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in Joomla! 3.2.0 through 3.9.24.",
      "ranges": [
        {
          "gte": "3.2.0",
          "lt": "3.9.25"
        }
      ],
      "note": "NVD: An issue was discovered in Joomla! 3.2.0 through 3.9.24."
    },
    {
      "cve": "CVE-2021-23128",
      "sev": "critical",
      "kev": false,
      "title": "An issue was discovered in Joomla! 3.2.0 through 3.9.24.",
      "ranges": [
        {
          "gte": "3.2.0",
          "lt": "3.9.25"
        }
      ],
      "note": "NVD: An issue was discovered in Joomla! 3.2.0 through 3.9.24."
    },
    {
      "cve": "CVE-2021-23127",
      "sev": "critical",
      "kev": false,
      "title": "An issue was discovered in Joomla! 3.2.0 through 3.9.24.",
      "ranges": [
        {
          "gte": "3.2.0",
          "lt": "3.9.25"
        }
      ],
      "note": "NVD: An issue was discovered in Joomla! 3.2.0 through 3.9.24."
    },
    {
      "cve": "CVE-2020-35616",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in Joomla! 1.7.0 through 3.9.22.",
      "ranges": [
        {
          "gte": "1.7.0",
          "lte": "3.9.22"
        }
      ],
      "note": "NVD: An issue was discovered in Joomla! 1.7.0 through 3.9.22."
    },
    {
      "cve": "CVE-2020-35613",
      "sev": "critical",
      "kev": false,
      "title": "An issue was discovered in Joomla! 3.0.0 through 3.9.22.",
      "ranges": [
        {
          "gte": "3.0.0",
          "lte": "3.9.22"
        }
      ],
      "note": "NVD: An issue was discovered in Joomla! 3.0.0 through 3.9.22."
    },
    {
      "cve": "CVE-2020-35612",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in Joomla! 2.5.0 through 3.9.22.",
      "ranges": [
        {
          "gte": "2.5.0",
          "lte": "3.9.22"
        }
      ],
      "note": "NVD: An issue was discovered in Joomla! 2.5.0 through 3.9.22."
    },
    {
      "cve": "CVE-2020-35611",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in Joomla! 2.5.0 through 3.9.22.",
      "ranges": [
        {
          "gte": "2.5.0",
          "lte": "3.9.22"
        }
      ],
      "note": "NVD: An issue was discovered in Joomla! 2.5.0 through 3.9.22."
    },
    {
      "cve": "CVE-2020-35610",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in Joomla! 2.5.0 through 3.9.22.",
      "ranges": [
        {
          "gte": "2.5.0",
          "lte": "3.9.22"
        }
      ],
      "note": "NVD: An issue was discovered in Joomla! 2.5.0 through 3.9.22."
    },
    {
      "cve": "CVE-2020-13763",
      "sev": "high",
      "kev": false,
      "title": "In Joomla! before 3.9.19, the default settings of the global textfilter configuration…",
      "ranges": [
        {
          "gte": "2.5.1",
          "lt": "3.9.19"
        },
        {
          "eq": "2.5.0"
        }
      ],
      "note": "NVD: In Joomla! before 3.9.19, the default settings of the global textfilter configuration do not block HTML inputs for Guest users."
    },
    {
      "cve": "CVE-2020-13760",
      "sev": "high",
      "kev": false,
      "title": "In Joomla! before 3.9.19, missing token checks in com_postinstall lead to CSRF.",
      "ranges": [
        {
          "gte": "3.7.1",
          "lt": "3.9.19"
        },
        {
          "eq": "3.7.0"
        }
      ],
      "note": "NVD: In Joomla! before 3.9.19, missing token checks in com_postinstall lead to CSRF."
    },
    {
      "cve": "CVE-2020-10243",
      "sev": "critical",
      "kev": false,
      "title": "An issue was discovered in Joomla! before 3.9.16.",
      "ranges": [
        {
          "gte": "1.7.0",
          "lt": "3.9.16"
        }
      ],
      "note": "NVD: An issue was discovered in Joomla! before 3.9.16."
    },
    {
      "cve": "CVE-2020-10241",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in Joomla! before 3.9.16.",
      "ranges": [
        {
          "gte": "3.2.0",
          "lt": "3.9.16"
        }
      ],
      "note": "NVD: An issue was discovered in Joomla! before 3.9.16."
    },
    {
      "cve": "CVE-2020-10239",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in Joomla! before 3.9.16.",
      "ranges": [
        {
          "gte": "3.7.0",
          "lt": "3.9.16"
        }
      ],
      "note": "NVD: An issue was discovered in Joomla! before 3.9.16."
    },
    {
      "cve": "CVE-2020-10238",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in Joomla! before 3.9.16.",
      "ranges": [
        {
          "gte": "2.5.0",
          "lt": "3.9.16"
        }
      ],
      "note": "NVD: An issue was discovered in Joomla! before 3.9.16."
    },
    {
      "cve": "CVE-2020-8420",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in Joomla! before 3.9.15.",
      "ranges": [
        {
          "gte": "3.0.0",
          "lt": "3.9.15"
        }
      ],
      "note": "NVD: An issue was discovered in Joomla! before 3.9.15."
    },
    {
      "cve": "CVE-2020-8419",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in Joomla! before 3.9.15.",
      "ranges": [
        {
          "gte": "3.0.0",
          "lt": "3.9.15"
        }
      ],
      "note": "NVD: An issue was discovered in Joomla! before 3.9.15."
    },
    {
      "cve": "CVE-2019-19846",
      "sev": "critical",
      "kev": false,
      "title": "In Joomla! before 3.9.14, the lack of validation of configuration parameters used in…",
      "ranges": [
        {
          "gte": "2.5.0",
          "lte": "3.9.14"
        }
      ],
      "note": "NVD: In Joomla! before 3.9.14, the lack of validation of configuration parameters used in SQL queries caused various SQL injection vectors."
    },
    {
      "cve": "CVE-2019-18650",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in Joomla! before 3.9.13.",
      "ranges": [
        {
          "gte": "3.2.0",
          "lte": "3.9.12"
        }
      ],
      "note": "NVD: An issue was discovered in Joomla! before 3.9.13."
    },
    {
      "cve": "CVE-2019-14654",
      "sev": "high",
      "kev": false,
      "title": "In Joomla! 3.9.7 and 3.9.8, inadequate filtering allows users authorised to create…",
      "ranges": [
        {
          "eq": "3.9.7"
        },
        {
          "eq": "3.9.8"
        }
      ],
      "note": "NVD: In Joomla! 3.9.7 and 3.9.8, inadequate filtering allows users authorised to create custom fields to manipulate the filtering options and inject an unvalidated…"
    },
    {
      "cve": "CVE-2019-12765",
      "sev": "critical",
      "kev": false,
      "title": "An issue was discovered in Joomla! before 3.9.7.",
      "ranges": [
        {
          "gte": "3.9.0",
          "lte": "3.9.6"
        }
      ],
      "note": "NVD: An issue was discovered in Joomla! before 3.9.7."
    },
    {
      "cve": "CVE-2019-11831",
      "sev": "critical",
      "kev": false,
      "title": "The PharStreamWrapper (aka phar-stream-wrapper) package 2.x before 2.1.1 and 3.x…",
      "ranges": [
        {
          "gte": "3.9.3",
          "lte": "3.9.5"
        }
      ],
      "note": "NVD: The PharStreamWrapper (aka phar-stream-wrapper) package 2.x before 2.1.1 and 3.x before 3.1.1 for TYPO3 does not prevent directory traversal, which allows…"
    },
    {
      "cve": "CVE-2019-10946",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in Joomla! before 3.9.5.",
      "ranges": [
        {
          "gte": "3.2.0",
          "lte": "3.9.4"
        }
      ],
      "note": "NVD: An issue was discovered in Joomla! before 3.9.5."
    },
    {
      "cve": "CVE-2019-10945",
      "sev": "critical",
      "kev": false,
      "title": "An issue was discovered in Joomla! before 3.9.5.",
      "ranges": [
        {
          "gte": "1.5.0",
          "lte": "3.9.4"
        }
      ],
      "note": "NVD: An issue was discovered in Joomla! before 3.9.5."
    },
    {
      "cve": "CVE-2019-9713",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in Joomla! before 3.9.4.",
      "ranges": [
        {
          "gte": "3.8.0",
          "lt": "3.9.4"
        }
      ],
      "note": "NVD: An issue was discovered in Joomla! before 3.9.4."
    },
    {
      "cve": "CVE-2019-7743",
      "sev": "critical",
      "kev": false,
      "title": "An issue was discovered in Joomla! before 3.9.3.",
      "ranges": [
        {
          "gte": "2.5.0",
          "lte": "3.9.2"
        }
      ],
      "note": "NVD: An issue was discovered in Joomla! before 3.9.3."
    },
    {
      "cve": "CVE-2018-17858",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in Joomla! before 3.8.13.",
      "ranges": [
        {
          "gte": "2.5.0",
          "lt": "3.8.13"
        }
      ],
      "note": "NVD: An issue was discovered in Joomla! before 3.8.13."
    },
    {
      "cve": "CVE-2018-17856",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in Joomla! before 3.8.13.",
      "ranges": [
        {
          "gte": "2.5.4",
          "lt": "3.8.13"
        }
      ],
      "note": "NVD: An issue was discovered in Joomla! before 3.8.13."
    },
    {
      "cve": "CVE-2018-17855",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in Joomla! before 3.8.13.",
      "ranges": [
        {
          "gte": "1.5.0",
          "lt": "3.8.13"
        }
      ],
      "note": "NVD: An issue was discovered in Joomla! before 3.8.13."
    },
    {
      "cve": "CVE-2018-15882",
      "sev": "critical",
      "kev": false,
      "title": "An issue was discovered in Joomla! before 3.8.12.",
      "ranges": [
        {
          "lt": "3.8.12"
        }
      ],
      "note": "NVD: An issue was discovered in Joomla! before 3.8.12."
    },
    {
      "cve": "CVE-2018-15881",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in Joomla! before 3.8.12.",
      "ranges": [
        {
          "lt": "3.8.12"
        }
      ],
      "note": "NVD: An issue was discovered in Joomla! before 3.8.12."
    },
    {
      "cve": "CVE-2018-12712",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in Joomla! 2.5.0 through 3.8.8 before 3.8.9.",
      "ranges": [
        {
          "gte": "2.5.0",
          "lte": "3.8.8"
        }
      ],
      "note": "NVD: An issue was discovered in Joomla! 2.5.0 through 3.8.8 before 3.8.9."
    },
    {
      "cve": "CVE-2018-11325",
      "sev": "critical",
      "kev": false,
      "title": "An issue was discovered in Joomla! Core before 3.8.8.",
      "ranges": [
        {
          "lt": "3.8.8"
        }
      ],
      "note": "NVD: An issue was discovered in Joomla! Core before 3.8.8."
    },
    {
      "cve": "CVE-2018-11323",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in Joomla! Core before 3.8.8.",
      "ranges": [
        {
          "lt": "3.8.8"
        }
      ],
      "note": "NVD: An issue was discovered in Joomla! Core before 3.8.8."
    },
    {
      "cve": "CVE-2018-11322",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in Joomla! Core before 3.8.8.",
      "ranges": [
        {
          "lt": "3.8.8"
        }
      ],
      "note": "NVD: An issue was discovered in Joomla! Core before 3.8.8."
    },
    {
      "cve": "CVE-2018-8045",
      "sev": "high",
      "kev": false,
      "title": "In Joomla! 3.5.0 through 3.8.5, the lack of type casting of a variable in a SQL…",
      "ranges": [
        {
          "gte": "3.5.0",
          "lte": "3.8.5"
        }
      ],
      "note": "NVD: In Joomla! 3.5.0 through 3.8.5, the lack of type casting of a variable in a SQL statement leads to a SQL injection vulnerability in the User Notes list view."
    },
    {
      "cve": "CVE-2018-6376",
      "sev": "critical",
      "kev": false,
      "title": "In Joomla! before 3.8.4, the lack of type casting of a variable in a SQL statement…",
      "ranges": [
        {
          "lt": "3.8.4"
        }
      ],
      "note": "NVD: In Joomla! before 3.8.4, the lack of type casting of a variable in a SQL statement leads to a SQL injection vulnerability in the Hathor postinstall message."
    },
    {
      "cve": "CVE-2017-16634",
      "sev": "critical",
      "kev": false,
      "title": "In Joomla! before 3.8.2, a bug allowed third parties to bypass a user's 2-factor…",
      "ranges": [
        {
          "gte": "3.2.0",
          "lte": "3.8.1"
        }
      ],
      "note": "NVD: In Joomla! before 3.8.2, a bug allowed third parties to bypass a user's 2-factor authentication method."
    },
    {
      "cve": "CVE-2017-8917",
      "sev": "critical",
      "kev": false,
      "title": "SQL injection vulnerability in Joomla! 3.7.x before 3.7.1 allows attackers to execute…",
      "ranges": [
        {
          "eq": "3.7.0"
        }
      ],
      "note": "NVD: SQL injection vulnerability in Joomla! 3.7.x before 3.7.1 allows attackers to execute arbitrary SQL commands via unspecified vectors."
    },
    {
      "cve": "CVE-2016-10045",
      "sev": "critical",
      "kev": false,
      "title": "The isMail transport in PHPMailer before 5.2.20 might allow remote attackers to pass…",
      "ranges": [
        {
          "gte": "1.5.0",
          "lte": "3.6.5"
        }
      ],
      "note": "NVD: The isMail transport in PHPMailer before 5.2.20 might allow remote attackers to pass extra parameters to the mail command and consequently execute arbitrary code…"
    },
    {
      "cve": "CVE-2016-10033",
      "sev": "critical",
      "kev": true,
      "title": "The mailSend function in the isMail transport in PHPMailer before 5.2.18 might allow…",
      "ranges": [
        {
          "gte": "1.5.0",
          "lte": "3.6.5"
        }
      ],
      "note": "NVD: The mailSend function in the isMail transport in PHPMailer before 5.2.18 might allow remote attackers to pass extra parameters to… — CISA KEV (actively exploited)"
    },
    {
      "cve": "CVE-2016-9838",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in components/com_users/models/registration.php in Joomla!…",
      "ranges": [
        {
          "lte": "3.6.4"
        }
      ],
      "note": "NVD: An issue was discovered in components/com_users/models/registration.php in Joomla! before 3.6.5."
    },
    {
      "cve": "CVE-2016-9837",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in templates/beez3/html/com_content/article/default.php in…",
      "ranges": [
        {
          "lte": "3.6.4"
        }
      ],
      "note": "NVD: An issue was discovered in templates/beez3/html/com_content/article/default.php in Joomla! before 3.6.5."
    },
    {
      "cve": "CVE-2016-9836",
      "sev": "critical",
      "kev": false,
      "title": "The file scanning mechanism of JFilterInput::isFileSafe() in Joomla! CMS before 3.6.5…",
      "ranges": [
        {
          "lte": "3.6.4"
        }
      ],
      "note": "NVD: The file scanning mechanism of JFilterInput::isFileSafe() in Joomla! CMS before 3.6.5 does not consider alternative PHP file extensions when checking uploaded…"
    },
    {
      "cve": "CVE-2016-9081",
      "sev": "critical",
      "kev": false,
      "title": "Joomla! 3.4.4 through 3.6.3 allows attackers to reset username, password, and user…",
      "ranges": [
        {
          "eq": "3.4.4"
        },
        {
          "eq": "3.4.5"
        },
        {
          "eq": "3.4.6"
        },
        {
          "eq": "3.4.7"
        },
        {
          "eq": "3.4.8"
        },
        {
          "eq": "3.5.0"
        },
        {
          "eq": "3.5.1"
        },
        {
          "eq": "3.6.0"
        },
        {
          "eq": "3.6.1"
        },
        {
          "eq": "3.6.2"
        },
        {
          "eq": "3.6.3"
        }
      ],
      "note": "NVD: Joomla! 3.4.4 through 3.6.3 allows attackers to reset username, password, and user group assignments and possibly perform other user account modifications via…"
    },
    {
      "cve": "CVE-2016-8870",
      "sev": "high",
      "kev": false,
      "title": "The register method in the UsersModelRegistration class in controllers/user.php in the…",
      "ranges": [
        {
          "lte": "3.6.3"
        }
      ],
      "note": "NVD: The register method in the UsersModelRegistration class in controllers/user.php in the Users component in Joomla! before 3.6.4, when registration has been…"
    },
    {
      "cve": "CVE-2016-8869",
      "sev": "critical",
      "kev": false,
      "title": "The register method in the UsersModelRegistration class in controllers/user.php in the…",
      "ranges": [
        {
          "lte": "3.6.3"
        }
      ],
      "note": "NVD: The register method in the UsersModelRegistration class in controllers/user.php in the Users component in Joomla! before 3.6.4 allows remote attackers to gain…"
    }
  ],
  "jquery": [
    {
      "cve": "CVE-2020-11023",
      "sev": "medium",
      "kev": true,
      "title": "In jQuery versions greater than or equal to 1.0.3 and before 3.5.0, passing HTML…",
      "ranges": [
        {
          "gte": "1.0.3",
          "lt": "3.5.0"
        }
      ],
      "note": "NVD: In jQuery versions greater than or equal to 1.0.3 and before 3.5.0, passing HTML containing <option> elements from untrusted… — CISA KEV (actively exploited)"
    },
    {
      "cve": "CVE-2016-10707",
      "sev": "high",
      "kev": false,
      "title": "jQuery 3.0.0-rc.1 is vulnerable to Denial of Service (DoS) due to removing a logic…",
      "ranges": [
        {
          "eq": "3.0.0"
        }
      ],
      "note": "NVD: jQuery 3.0.0-rc.1 is vulnerable to Denial of Service (DoS) due to removing a logic that lowercased attribute names."
    }
  ],
  "laravel": [
    {
      "cve": "CVE-2025-27515",
      "sev": "critical",
      "kev": false,
      "title": "Laravel is a web application framework.",
      "ranges": [
        {
          "lt": "11.44.1"
        },
        {
          "gte": "12.0.0",
          "lt": "12.1.1"
        }
      ],
      "note": "NVD: Laravel is a web application framework."
    },
    {
      "cve": "CVE-2024-52301",
      "sev": "high",
      "kev": false,
      "title": "Laravel is a web application framework.",
      "ranges": [
        {
          "lt": "6.20.45"
        },
        {
          "gte": "7.0.0",
          "lt": "7.30.7"
        },
        {
          "gte": "8.0.0",
          "lt": "8.83.28"
        },
        {
          "gte": "9.0.0",
          "lt": "9.52.17"
        },
        {
          "gte": "10.0.0",
          "lt": "10.48.23"
        },
        {
          "gte": "11.0.0",
          "lt": "11.31.0"
        }
      ],
      "note": "NVD: Laravel is a web application framework."
    },
    {
      "cve": "CVE-2024-13919",
      "sev": "high",
      "kev": false,
      "title": "The Laravel framework versions between 11.9.0 and 11.35.1 are susceptible to reflected…",
      "ranges": [
        {
          "gte": "11.9.0",
          "lt": "11.36.0"
        }
      ],
      "note": "NVD: The Laravel framework versions between 11.9.0 and 11.35.1 are susceptible to reflected cross-site scripting due to an improper encoding of route parameters in the…"
    },
    {
      "cve": "CVE-2024-13918",
      "sev": "high",
      "kev": false,
      "title": "The Laravel framework versions between 11.9.0 and 11.35.1 are susceptible to reflected…",
      "ranges": [
        {
          "gte": "11.9.0",
          "lt": "11.36.0"
        }
      ],
      "note": "NVD: The Laravel framework versions between 11.9.0 and 11.35.1 are susceptible to reflected cross-site scripting due to an improper encoding of request parameters in…"
    },
    {
      "cve": "CVE-2021-43617",
      "sev": "critical",
      "kev": false,
      "title": "Laravel Framework through 8.70.2 does not sufficiently block the upload of executable…",
      "ranges": [
        {
          "lte": "8.70.2"
        }
      ],
      "note": "NVD: Laravel Framework through 8.70.2 does not sufficiently block the upload of executable PHP content because Illuminate/Validation/Concerns/ValidatesAttributes.php…"
    },
    {
      "cve": "CVE-2021-28254",
      "sev": "critical",
      "kev": false,
      "title": "A deserialization vulnerability in the destruct() function of Laravel v8.5.9 allows…",
      "ranges": [
        {
          "eq": "8.5.9"
        }
      ],
      "note": "NVD: A deserialization vulnerability in the destruct() function of Laravel v8.5.9 allows attackers to execute arbitrary commands."
    },
    {
      "cve": "CVE-2021-21263",
      "sev": "high",
      "kev": false,
      "title": "Laravel is a web application framework.",
      "ranges": [
        {
          "gte": "6.0.0",
          "lt": "6.20.11"
        },
        {
          "gte": "7.0.0",
          "lt": "7.30.2"
        },
        {
          "gte": "8.0.0",
          "lt": "8.22.1"
        }
      ],
      "note": "NVD: Laravel is a web application framework."
    },
    {
      "cve": "CVE-2020-24941",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in Laravel before 6.18.35 and 7.x before 7.24.0.",
      "ranges": [
        {
          "lt": "6.18.35"
        },
        {
          "gte": "7.0.0",
          "lt": "7.24.0"
        }
      ],
      "note": "NVD: An issue was discovered in Laravel before 6.18.35 and 7.x before 7.24.0."
    },
    {
      "cve": "CVE-2020-24940",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in Laravel before 6.18.34 and 7.x before 7.23.2.",
      "ranges": [
        {
          "lt": "6.18.34"
        },
        {
          "gte": "7.0.0",
          "lt": "7.23.2"
        }
      ],
      "note": "NVD: An issue was discovered in Laravel before 6.18.34 and 7.x before 7.23.2."
    },
    {
      "cve": "CVE-2020-19316",
      "sev": "high",
      "kev": false,
      "title": "OS Command injection vulnerability in function link in Filesystem.php in Laravel…",
      "ranges": [
        {
          "lt": "5.8.17"
        }
      ],
      "note": "NVD: OS Command injection vulnerability in function link in Filesystem.php in Laravel Framework before 5.8.17."
    },
    {
      "cve": "CVE-2018-15133",
      "sev": "high",
      "kev": true,
      "title": "In Laravel Framework through 5.5.40 and 5.6.x through 5.6.29, remote code execution…",
      "ranges": [
        {
          "lte": "5.5.40"
        },
        {
          "gte": "5.6.0",
          "lte": "5.6.29"
        }
      ],
      "note": "NVD: In Laravel Framework through 5.5.40 and 5.6.x through 5.6.29, remote code execution might occur as a result of an unserialize call… — CISA KEV (actively exploited)"
    },
    {
      "cve": "CVE-2018-6330",
      "sev": "high",
      "kev": false,
      "title": "Laravel 5.4.15 is vulnerable to Error based SQL injection in save.php via dhx_user and…",
      "ranges": [
        {
          "eq": "5.4.15"
        }
      ],
      "note": "NVD: Laravel 5.4.15 is vulnerable to Error based SQL injection in save.php via dhx_user and dhx_version parameters."
    },
    {
      "cve": "CVE-2017-16894",
      "sev": "high",
      "kev": false,
      "title": "In Laravel framework through 5.5.21, remote attackers can obtain sensitive information…",
      "ranges": [
        {
          "lte": "5.5.21"
        }
      ],
      "note": "NVD: In Laravel framework through 5.5.21, remote attackers can obtain sensitive information (such as externally usable passwords) via a direct request for the /.env URI."
    }
  ],
  "nextjs": [
    {
      "cve": "CVE-2026-64642",
      "sev": "high",
      "kev": false,
      "title": "Next.js is a React framework for building full-stack web applications.",
      "ranges": [
        {
          "gte": "16.0.0",
          "lt": "16.2.11"
        }
      ],
      "note": "NVD: Next.js is a React framework for building full-stack web applications."
    },
    {
      "cve": "CVE-2026-64641",
      "sev": "high",
      "kev": false,
      "title": "Next.js is a React framework for building full-stack web applications.",
      "ranges": [
        {
          "gte": "13.0.0",
          "lt": "15.5.21"
        },
        {
          "gte": "16.0.0",
          "lt": "16.2.11"
        }
      ],
      "note": "NVD: Next.js is a React framework for building full-stack web applications."
    },
    {
      "cve": "CVE-2026-45109",
      "sev": "high",
      "kev": false,
      "title": "Next.js is a React framework for building full-stack web applications.",
      "ranges": [
        {
          "gte": "15.2.0",
          "lt": "15.5.18"
        },
        {
          "gte": "16.0.0",
          "lt": "16.2.6"
        }
      ],
      "note": "NVD: Next.js is a React framework for building full-stack web applications."
    },
    {
      "cve": "CVE-2026-44579",
      "sev": "high",
      "kev": false,
      "title": "Next.js is a React framework for building full-stack web applications.",
      "ranges": [
        {
          "gte": "15.0.0",
          "lt": "15.5.16"
        },
        {
          "gte": "16.0.0",
          "lt": "16.2.5"
        }
      ],
      "note": "NVD: Next.js is a React framework for building full-stack web applications."
    },
    {
      "cve": "CVE-2026-44578",
      "sev": "high",
      "kev": false,
      "title": "Next.js is a React framework for building full-stack web applications.",
      "ranges": [
        {
          "gte": "13.4.13",
          "lt": "15.5.16"
        },
        {
          "gte": "16.0.0",
          "lt": "16.2.5"
        }
      ],
      "note": "NVD: Next.js is a React framework for building full-stack web applications."
    },
    {
      "cve": "CVE-2026-44575",
      "sev": "high",
      "kev": false,
      "title": "Next.js is a React framework for building full-stack web applications.",
      "ranges": [
        {
          "gte": "15.2.0",
          "lt": "15.5.16"
        },
        {
          "gte": "16.0.0",
          "lt": "16.2.5"
        }
      ],
      "note": "NVD: Next.js is a React framework for building full-stack web applications."
    },
    {
      "cve": "CVE-2026-44574",
      "sev": "high",
      "kev": false,
      "title": "Next.js is a React framework for building full-stack web applications.",
      "ranges": [
        {
          "gte": "15.4.0",
          "lt": "15.5.16"
        },
        {
          "gte": "16.0.0",
          "lt": "16.2.5"
        }
      ],
      "note": "NVD: Next.js is a React framework for building full-stack web applications."
    },
    {
      "cve": "CVE-2026-44573",
      "sev": "high",
      "kev": false,
      "title": "Next.js is a React framework for building full-stack web applications.",
      "ranges": [
        {
          "gte": "12.2.0",
          "lt": "15.5.16"
        },
        {
          "gte": "16.0.0",
          "lt": "16.2.5"
        }
      ],
      "note": "NVD: Next.js is a React framework for building full-stack web applications."
    },
    {
      "cve": "CVE-2026-27980",
      "sev": "high",
      "kev": false,
      "title": "Next.js is a React framework for building full-stack web applications.",
      "ranges": [
        {
          "gte": "10.0.0",
          "lt": "16.1.7"
        }
      ],
      "note": "NVD: Next.js is a React framework for building full-stack web applications."
    },
    {
      "cve": "CVE-2026-27979",
      "sev": "high",
      "kev": false,
      "title": "Next.js is a React framework for building full-stack web applications.",
      "ranges": [
        {
          "gte": "16.0.1",
          "lt": "16.1.7"
        }
      ],
      "note": "NVD: Next.js is a React framework for building full-stack web applications."
    },
    {
      "cve": "CVE-2025-67779",
      "sev": "high",
      "kev": false,
      "title": "It was found that the fix addressing CVE-2025-55184 in React Server Components was…",
      "ranges": [
        {
          "gte": "13.3.0",
          "lt": "14.2.35"
        },
        {
          "gte": "15.0.0",
          "lt": "15.0.7"
        },
        {
          "gte": "15.1.0",
          "lt": "15.1.11"
        },
        {
          "gte": "15.2.0",
          "lt": "15.2.8"
        },
        {
          "gte": "15.3.0",
          "lt": "15.3.8"
        },
        {
          "gte": "15.4.0",
          "lt": "15.4.10"
        },
        {
          "gte": "15.5.0",
          "lt": "15.5.9"
        },
        {
          "gte": "16.0.0",
          "lt": "16.0.10"
        },
        {
          "eq": "15.6.0"
        },
        {
          "eq": "16.1.0"
        }
      ],
      "note": "NVD: It was found that the fix addressing CVE-2025-55184 in React Server Components was incomplete and does not prevent a denial of service attack in a specific case."
    },
    {
      "cve": "CVE-2025-55184",
      "sev": "high",
      "kev": false,
      "title": "A pre-authentication denial of service vulnerability exists in React Server Components…",
      "ranges": [
        {
          "gte": "13.3.0",
          "lt": "14.2.35"
        },
        {
          "gte": "15.0.0",
          "lt": "15.0.7"
        },
        {
          "gte": "15.1.0",
          "lt": "15.1.11"
        },
        {
          "gte": "15.2.0",
          "lt": "15.2.8"
        },
        {
          "gte": "15.3.0",
          "lt": "15.3.8"
        },
        {
          "gte": "15.4.0",
          "lt": "15.4.10"
        },
        {
          "gte": "15.5.0",
          "lt": "15.5.9"
        },
        {
          "gte": "16.0.0",
          "lt": "16.0.10"
        },
        {
          "eq": "15.6.0"
        },
        {
          "eq": "16.1.0"
        }
      ],
      "note": "NVD: A pre-authentication denial of service vulnerability exists in React Server Components versions 19.0.0, 19.0.1 19.1.0, 19.1.1, 19.1.2, 19.2.0 and 19.2.1, including…"
    },
    {
      "cve": "CVE-2025-55182",
      "sev": "critical",
      "kev": true,
      "title": "A pre-authentication remote code execution vulnerability exists in React Server…",
      "ranges": [
        {
          "gte": "15.0.0",
          "lt": "15.0.5"
        },
        {
          "gte": "15.1.0",
          "lt": "15.1.9"
        },
        {
          "gte": "15.2.0",
          "lt": "15.2.6"
        },
        {
          "gte": "15.3.0",
          "lt": "15.3.6"
        },
        {
          "gte": "15.4.0",
          "lt": "15.4.8"
        },
        {
          "gte": "15.5.0",
          "lt": "15.5.7"
        },
        {
          "gte": "16.0.0",
          "lt": "16.0.7"
        },
        {
          "eq": "14.3.0"
        },
        {
          "eq": "15.6.0"
        },
        {
          "eq": "16.0.0"
        }
      ],
      "note": "NVD: A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and… — CISA KEV (actively exploited)"
    },
    {
      "cve": "CVE-2025-49826",
      "sev": "high",
      "kev": false,
      "title": "Next.js is a React framework for building full-stack web applications.",
      "ranges": [
        {
          "gt": "15.0.4",
          "lt": "15.1.8"
        },
        {
          "eq": "15.0.4"
        }
      ],
      "note": "NVD: Next.js is a React framework for building full-stack web applications."
    },
    {
      "cve": "CVE-2025-29927",
      "sev": "critical",
      "kev": false,
      "title": "Next.js is a React framework for building full-stack web applications.",
      "ranges": [
        {
          "gte": "11.1.4",
          "lt": "12.3.5"
        },
        {
          "gte": "13.0.0",
          "lt": "13.5.9"
        },
        {
          "gte": "14.0.0",
          "lt": "14.2.25"
        },
        {
          "gte": "15.0.0",
          "lt": "15.2.3"
        }
      ],
      "note": "NVD: Next.js is a React framework for building full-stack web applications."
    },
    {
      "cve": "CVE-2024-51479",
      "sev": "high",
      "kev": false,
      "title": "Next.js is a React framework for building full-stack web applications.",
      "ranges": [
        {
          "gte": "9.5.5",
          "lt": "14.2.15"
        }
      ],
      "note": "NVD: Next.js is a React framework for building full-stack web applications."
    },
    {
      "cve": "CVE-2024-46982",
      "sev": "high",
      "kev": false,
      "title": "Next.js is a React framework for building full-stack web applications.",
      "ranges": [
        {
          "gte": "13.5.1",
          "lt": "13.5.7"
        },
        {
          "gte": "14.0.0",
          "lt": "14.2.10"
        }
      ],
      "note": "NVD: Next.js is a React framework for building full-stack web applications."
    },
    {
      "cve": "CVE-2024-39693",
      "sev": "high",
      "kev": false,
      "title": "Next.js is a React framework.",
      "ranges": [
        {
          "gte": "13.3.1",
          "lt": "13.5.0"
        }
      ],
      "note": "NVD: Next.js is a React framework."
    },
    {
      "cve": "CVE-2024-34351",
      "sev": "high",
      "kev": false,
      "title": "Next.js is a React framework that can provide building blocks to create web…",
      "ranges": [
        {
          "gte": "13.4.0",
          "lt": "14.1.1"
        }
      ],
      "note": "NVD: Next.js is a React framework that can provide building blocks to create web applications."
    },
    {
      "cve": "CVE-2024-34350",
      "sev": "high",
      "kev": false,
      "title": "Next.js is a React framework that can provide building blocks to create web…",
      "ranges": [
        {
          "gte": "13.4.0",
          "lt": "13.5.1"
        }
      ],
      "note": "NVD: Next.js is a React framework that can provide building blocks to create web applications."
    },
    {
      "cve": "CVE-2023-46298",
      "sev": "high",
      "kev": false,
      "title": "Next.js before 13.4.20-canary.13 lacks a cache-control header and thus empty prefetch…",
      "ranges": [
        {
          "lt": "13.4.20"
        },
        {
          "eq": "13.4.20"
        }
      ],
      "note": "NVD: Next.js before 13.4.20-canary.13 lacks a cache-control header and thus empty prefetch responses may sometimes be cached by a CDN, causing a denial of service to…"
    },
    {
      "cve": "CVE-2021-43803",
      "sev": "high",
      "kev": false,
      "title": "Next.js is a React framework.",
      "ranges": [
        {
          "gte": "11.1.0",
          "lt": "11.1.3"
        },
        {
          "gte": "12.0.0",
          "lt": "12.0.5"
        }
      ],
      "note": "NVD: Next.js is a React framework."
    },
    {
      "cve": "CVE-2021-39178",
      "sev": "high",
      "kev": false,
      "title": "Next.js is a React framework.",
      "ranges": [
        {
          "gte": "10.0.0",
          "lt": "11.1.1"
        }
      ],
      "note": "NVD: Next.js is a React framework."
    },
    {
      "cve": "CVE-2018-6184",
      "sev": "high",
      "kev": false,
      "title": "ZEIT Next.js 4 before 4.2.3 has Directory Traversal under the /_next request namespace.",
      "ranges": [
        {
          "eq": "4.0.0"
        },
        {
          "eq": "4.0.1"
        },
        {
          "eq": "4.0.2"
        },
        {
          "eq": "4.0.3"
        },
        {
          "eq": "4.0.4"
        },
        {
          "eq": "4.0.5"
        },
        {
          "eq": "4.1.0"
        },
        {
          "eq": "4.1.1"
        },
        {
          "eq": "4.1.2"
        },
        {
          "eq": "4.1.3"
        },
        {
          "eq": "4.1.4"
        },
        {
          "eq": "4.2.0"
        },
        {
          "eq": "4.2.1"
        },
        {
          "eq": "4.2.2"
        }
      ],
      "note": "NVD: ZEIT Next.js 4 before 4.2.3 has Directory Traversal under the /_next request namespace."
    },
    {
      "cve": "CVE-2017-16877",
      "sev": "high",
      "kev": false,
      "title": "ZEIT Next.js before 2.4.1 has directory traversal under the /_next and /static request…",
      "ranges": [
        {
          "lt": "2.4.1"
        }
      ],
      "note": "NVD: ZEIT Next.js before 2.4.1 has directory traversal under the /_next and /static request namespace, allowing attackers to obtain sensitive information."
    }
  ],
  "nginx": [
    {
      "cve": "CVE-2026-60005",
      "sev": "high",
      "kev": false,
      "title": "NGINX Plus and NGINX Open Source have a vulnerability in the ngx_http_slice_module…",
      "ranges": [
        {
          "gte": "1.30.0",
          "lt": "1.30.4"
        },
        {
          "eq": "1.31.2"
        }
      ],
      "note": "NVD: NGINX Plus and NGINX Open Source have a vulnerability in the ngx_http_slice_module module."
    },
    {
      "cve": "CVE-2026-42945",
      "sev": "high",
      "kev": false,
      "title": "NGINX Plus and NGINX Open Source have a vulnerability in the ngx_http_rewrite_module…",
      "ranges": [
        {
          "gte": "0.6.27",
          "lte": "1.30.0"
        }
      ],
      "note": "NVD: NGINX Plus and NGINX Open Source have a vulnerability in the ngx_http_rewrite_module module."
    },
    {
      "cve": "CVE-2026-42530",
      "sev": "high",
      "kev": false,
      "title": "NGINX Open Source has a vulnerability in the ngx_http_v3_module module.",
      "ranges": [
        {
          "gte": "1.31.0",
          "lt": "1.31.2"
        }
      ],
      "note": "NVD: NGINX Open Source has a vulnerability in the ngx_http_v3_module module."
    },
    {
      "cve": "CVE-2026-42055",
      "sev": "high",
      "kev": false,
      "title": "NGINX Plus and NGINX Open Source have a vulnerability in the ngx_http_proxy_v2_module…",
      "ranges": [
        {
          "gte": "1.0.0",
          "lte": "1.30.2"
        },
        {
          "gte": "1.31.0",
          "lte": "1.31.1"
        }
      ],
      "note": "NVD: NGINX Plus and NGINX Open Source have a vulnerability in the ngx_http_proxy_v2_module and ngx_http_grpc_module modules."
    },
    {
      "cve": "CVE-2026-32647",
      "sev": "high",
      "kev": false,
      "title": "NGINX Open Source and NGINX Plus have a vulnerability in the ngx_http_mp4_module…",
      "ranges": [
        {
          "gte": "1.1.19",
          "lt": "1.28.3"
        },
        {
          "gte": "1.29.0",
          "lt": "1.29.7"
        }
      ],
      "note": "NVD: NGINX Open Source and NGINX Plus have a vulnerability in the ngx_http_mp4_module module, which might allow an attacker to trigger a buffer over-read or over-write…"
    },
    {
      "cve": "CVE-2026-27784",
      "sev": "high",
      "kev": false,
      "title": "The 32-bit implementation of NGINX Open Source has a vulnerability in the…",
      "ranges": [
        {
          "gte": "1.1.19",
          "lt": "1.28.3"
        },
        {
          "gte": "1.29.0",
          "lt": "1.29.7"
        }
      ],
      "note": "NVD: The 32-bit implementation of NGINX Open Source has a vulnerability in the ngx_http_mp4_module module, which might allow an attacker to over-read or over-write…"
    },
    {
      "cve": "CVE-2026-27654",
      "sev": "high",
      "kev": false,
      "title": "NGINX Open Source and NGINX Plus have a vulnerability in the ngx_http_dav_module…",
      "ranges": [
        {
          "gte": "0.5.13",
          "lte": "0.9.7"
        },
        {
          "gte": "1.0.0",
          "lt": "1.28.3"
        },
        {
          "gte": "1.29.0",
          "lt": "1.29.7"
        }
      ],
      "note": "NVD: NGINX Open Source and NGINX Plus have a vulnerability in the ngx_http_dav_module module that might allow an attacker to trigger a buffer overflow to the NGINX…"
    },
    {
      "cve": "CVE-2026-27651",
      "sev": "high",
      "kev": false,
      "title": "When the ngx_mail_auth_http_module module is enabled on NGINX Plus or NGINX Open…",
      "ranges": [
        {
          "gte": "0.5.15",
          "lte": "0.9.7"
        },
        {
          "gte": "1.0.0",
          "lt": "1.28.3"
        },
        {
          "gte": "1.29.0",
          "lt": "1.29.7"
        }
      ],
      "note": "NVD: When the ngx_mail_auth_http_module module is enabled on NGINX Plus or NGINX Open Source, undisclosed requests can cause worker processes to terminate."
    },
    {
      "cve": "CVE-2026-9256",
      "sev": "high",
      "kev": false,
      "title": "NGINX Plus and NGINX Open Source have a vulnerability in the ngx_http_rewrite_module…",
      "ranges": [
        {
          "gte": "0.1.17",
          "lte": "0.9.7"
        },
        {
          "gte": "1.0.0",
          "lt": "1.30.2"
        },
        {
          "eq": "1.31.0"
        }
      ],
      "note": "NVD: NGINX Plus and NGINX Open Source have a vulnerability in the ngx_http_rewrite_module module."
    },
    {
      "cve": "CVE-2024-24990",
      "sev": "high",
      "kev": false,
      "title": "When NGINX Plus or NGINX OSS are configured to use the HTTP/3 QUIC module, undisclosed…",
      "ranges": [
        {
          "gte": "1.25.0",
          "lt": "1.25.4"
        }
      ],
      "note": "NVD: When NGINX Plus or NGINX OSS are configured to use the HTTP/3 QUIC module, undisclosed requests can cause NGINX worker processes to terminate."
    },
    {
      "cve": "CVE-2024-24989",
      "sev": "high",
      "kev": false,
      "title": "When NGINX Plus or NGINX OSS are configured to use the HTTP/3 QUIC module, undisclosed…",
      "ranges": [
        {
          "eq": "1.25.3"
        }
      ],
      "note": "NVD: When NGINX Plus or NGINX OSS are configured to use the HTTP/3 QUIC module, undisclosed requests can cause NGINX worker processes to terminate."
    },
    {
      "cve": "CVE-2023-44487",
      "sev": "high",
      "kev": true,
      "title": "The HTTP/2 protocol allows a denial of service (server resource consumption) because…",
      "ranges": [
        {
          "gte": "1.9.5",
          "lte": "1.25.2"
        }
      ],
      "note": "NVD: The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams… — CISA KEV (actively exploited)"
    },
    {
      "cve": "CVE-2022-41742",
      "sev": "high",
      "kev": false,
      "title": "NGINX Open Source before versions 1.23.2 and 1.22.1, NGINX Open Source Subscription…",
      "ranges": [
        {
          "gte": "1.1.3",
          "lte": "1.22.0"
        },
        {
          "eq": "1.23.0"
        },
        {
          "eq": "1.23.1"
        }
      ],
      "note": "NVD: NGINX Open Source before versions 1.23.2 and 1.22.1, NGINX Open Source Subscription before versions R2 P1 and R1 P1, and NGINX Plus before versions R27 P1 and R26…"
    },
    {
      "cve": "CVE-2022-41741",
      "sev": "high",
      "kev": false,
      "title": "NGINX Open Source before versions 1.23.2 and 1.22.1, NGINX Open Source Subscription…",
      "ranges": [
        {
          "gte": "1.1.3",
          "lte": "1.22.0"
        },
        {
          "eq": "1.23.0"
        },
        {
          "eq": "1.23.1"
        }
      ],
      "note": "NVD: NGINX Open Source before versions 1.23.2 and 1.22.1, NGINX Open Source Subscription before versions R2 P1 and R1 P1, and NGINX Plus before versions R27 P1 and R26…"
    },
    {
      "cve": "CVE-2021-23017",
      "sev": "high",
      "kev": false,
      "title": "A security issue in nginx resolver was identified, which might allow an attacker who…",
      "ranges": [
        {
          "gte": "0.6.18",
          "lt": "1.20.1"
        }
      ],
      "note": "NVD: A security issue in nginx resolver was identified, which might allow an attacker who is able to forge UDP packets from the DNS server to cause 1-byte memory…"
    },
    {
      "cve": "CVE-2021-3618",
      "sev": "high",
      "kev": false,
      "title": "ALPACA is an application layer protocol content confusion attack, exploiting TLS…",
      "ranges": [
        {
          "lt": "1.21.0"
        }
      ],
      "note": "NVD: ALPACA is an application layer protocol content confusion attack, exploiting TLS servers implementing different protocols but using compatible certificates, such…"
    },
    {
      "cve": "CVE-2019-9513",
      "sev": "high",
      "kev": false,
      "title": "Some HTTP/2 implementations are vulnerable to resource loops, potentially leading to a…",
      "ranges": [
        {
          "gte": "1.9.5",
          "lt": "1.16.1"
        },
        {
          "gte": "1.17.0",
          "lte": "1.17.2"
        }
      ],
      "note": "NVD: Some HTTP/2 implementations are vulnerable to resource loops, potentially leading to a denial of service."
    },
    {
      "cve": "CVE-2019-9511",
      "sev": "high",
      "kev": false,
      "title": "Some HTTP/2 implementations are vulnerable to window size manipulation and stream…",
      "ranges": [
        {
          "gte": "1.9.5",
          "lt": "1.16.1"
        },
        {
          "gte": "1.17.0",
          "lte": "1.17.2"
        }
      ],
      "note": "NVD: Some HTTP/2 implementations are vulnerable to window size manipulation and stream prioritization manipulation, potentially leading to a denial of service."
    },
    {
      "cve": "CVE-2018-16844",
      "sev": "high",
      "kev": false,
      "title": "nginx before versions 1.15.6 and 1.14.1 has a vulnerability in the implementation of…",
      "ranges": [
        {
          "gte": "1.9.5",
          "lt": "1.14.1"
        },
        {
          "gte": "1.15.0",
          "lt": "1.15.6"
        }
      ],
      "note": "NVD: nginx before versions 1.15.6 and 1.14.1 has a vulnerability in the implementation of HTTP/2 that can allow for excessive CPU usage."
    },
    {
      "cve": "CVE-2018-16843",
      "sev": "high",
      "kev": false,
      "title": "nginx before versions 1.15.6 and 1.14.1 has a vulnerability in the implementation of…",
      "ranges": [
        {
          "gt": "1.9.5",
          "lt": "1.14.1"
        },
        {
          "gt": "1.15.0",
          "lt": "1.15.6"
        }
      ],
      "note": "NVD: nginx before versions 1.15.6 and 1.14.1 has a vulnerability in the implementation of HTTP/2 that can allow for excessive memory consumption."
    },
    {
      "cve": "CVE-2017-20005",
      "sev": "critical",
      "kev": false,
      "title": "NGINX before 1.13.6 has a buffer overflow for years that exceed four digits, as…",
      "ranges": [
        {
          "lt": "1.13.6"
        }
      ],
      "note": "NVD: NGINX before 1.13.6 has a buffer overflow for years that exceed four digits, as demonstrated by a file with a modification date in 1969 that causes an integer…"
    },
    {
      "cve": "CVE-2017-7529",
      "sev": "high",
      "kev": false,
      "title": "Nginx versions since 0.5.6 up to and including 1.13.2 are vulnerable to integer…",
      "ranges": [
        {
          "gte": "0.5.6",
          "lte": "1.12.1"
        },
        {
          "gte": "1.13.0",
          "lte": "1.13.2"
        }
      ],
      "note": "NVD: Nginx versions since 0.5.6 up to and including 1.13.2 are vulnerable to integer overflow vulnerability in nginx range filter module resulting into leak of…"
    },
    {
      "cve": "CVE-2016-4450",
      "sev": "high",
      "kev": false,
      "title": "os/unix/ngx_files.c in nginx before 1.10.1 and 1.11.x before 1.11.1 allows remote…",
      "ranges": [
        {
          "gte": "1.3.9",
          "lt": "1.10.1"
        },
        {
          "eq": "1.11.0"
        }
      ],
      "note": "NVD: os/unix/ngx_files.c in nginx before 1.10.1 and 1.11.x before 1.11.1 allows remote attackers to cause a denial of service (NULL pointer dereference and worker…"
    },
    {
      "cve": "CVE-2016-1247",
      "sev": "high",
      "kev": false,
      "title": "The nginx package before 1.6.2-5+deb8u3 on Debian jessie, the nginx packages before…",
      "ranges": [
        {
          "lte": "1.10.1"
        },
        {
          "lte": "1.10.0"
        },
        {
          "lte": "1.6.2"
        },
        {
          "lte": "1.4.3"
        }
      ],
      "note": "NVD: The nginx package before 1.6.2-5+deb8u3 on Debian jessie, the nginx packages before 1.4.6-1ubuntu3.6 on Ubuntu 14.04 LTS, before 1.10.0-0ubuntu0.16.04.3 on Ubuntu…"
    },
    {
      "cve": "CVE-2016-0746",
      "sev": "critical",
      "kev": false,
      "title": "Use-after-free vulnerability in the resolver in nginx 0.6.18 through 1.8.0 and 1.9.x…",
      "ranges": [
        {
          "gte": "0.6.18",
          "lte": "1.8.0"
        },
        {
          "gte": "1.9.0",
          "lt": "1.9.10"
        }
      ],
      "note": "NVD: Use-after-free vulnerability in the resolver in nginx 0.6.18 through 1.8.0 and 1.9.x before 1.9.10 allows remote attackers to cause a denial of service (worker…"
    },
    {
      "cve": "CVE-2016-0742",
      "sev": "high",
      "kev": false,
      "title": "The resolver in nginx before 1.8.1 and 1.9.x before 1.9.10 allows remote attackers to…",
      "ranges": [
        {
          "gte": "0.6.18",
          "lt": "1.8.1"
        },
        {
          "gte": "1.9.0",
          "lt": "1.9.10"
        }
      ],
      "note": "NVD: The resolver in nginx before 1.8.1 and 1.9.x before 1.9.10 allows remote attackers to cause a denial of service (invalid pointer dereference and worker process…"
    }
  ],
  "php": [
    {
      "cve": "CVE-2026-17544",
      "sev": "critical",
      "kev": false,
      "title": "Attacker-provided inputs to bccomp() could lead to an out-of-bounds write with stack…",
      "ranges": [
        {
          "gte": "8.4.0",
          "lt": "8.4.24"
        },
        {
          "gte": "8.5.0",
          "lt": "8.5.9"
        }
      ],
      "note": "NVD: Attacker-provided inputs to bccomp() could lead to an out-of-bounds write with stack and heap corruption in PHP versions from 8.4.* before 8.4.24 and from 8.5.*…"
    },
    {
      "cve": "CVE-2026-17543",
      "sev": "critical",
      "kev": false,
      "title": "Improper escaping of backslashes in attacker-provided parameters would allow for…",
      "ranges": [
        {
          "gte": "8.2.0",
          "lt": "8.2.33"
        },
        {
          "gte": "8.3.0",
          "lt": "8.3.33"
        },
        {
          "gte": "8.4.0",
          "lt": "8.4.24"
        },
        {
          "gte": "8.5.0",
          "lt": "8.5.9"
        }
      ],
      "note": "NVD: Improper escaping of backslashes in attacker-provided parameters would allow for trivial SQL injection in PHP versions from 8.2.* before 8.2.33, from 8.3.* before…"
    },
    {
      "cve": "CVE-2026-7568",
      "sev": "high",
      "kev": false,
      "title": "In PHP versions 8.2.* before 8.2.31, 8.3.* before 8.3.31, 8.4.* before 8.4.21, and…",
      "ranges": [
        {
          "gte": "8.2.0",
          "lt": "8.2.31"
        },
        {
          "gte": "8.3.0",
          "lt": "8.3.31"
        },
        {
          "gte": "8.4.0",
          "lt": "8.4.21"
        },
        {
          "gte": "8.5.0",
          "lt": "8.5.6"
        }
      ],
      "note": "NVD: In PHP versions 8.2.* before 8.2.31, 8.3.* before 8.3.31, 8.4.* before 8.4.21, and 8.5.* before 8.5.6, the metaphone() function in ext/standard/metaphone.c uses a…"
    },
    {
      "cve": "CVE-2026-7263",
      "sev": "high",
      "kev": false,
      "title": "In PHP versions 8.4.* before 8.4.21 and 8.5.* before 8.5.6, DOMNode::C14N() method may…",
      "ranges": [
        {
          "gte": "8.4.0",
          "lt": "8.4.21"
        },
        {
          "gte": "8.5.0",
          "lt": "8.5.6"
        }
      ],
      "note": "NVD: In PHP versions 8.4.* before 8.4.21 and 8.5.* before 8.5.6, DOMNode::C14N() method may process the XML data incorrectly, causing a circular linked list in the data…"
    },
    {
      "cve": "CVE-2026-7262",
      "sev": "high",
      "kev": false,
      "title": "In PHP versions 8.2.* before 8.2.31, 8.3.* before 8.3.31, 8.4.* before 8.4.21, and…",
      "ranges": [
        {
          "gte": "8.2.0",
          "lt": "8.2.31"
        },
        {
          "gte": "8.3.0",
          "lt": "8.3.31"
        },
        {
          "gte": "8.4.0",
          "lt": "8.4.21"
        },
        {
          "gte": "8.5.0",
          "lt": "8.5.6"
        }
      ],
      "note": "NVD: In PHP versions 8.2.* before 8.2.31, 8.3.* before 8.3.31, 8.4.* before 8.4.21, and 8.5.* before 8.5.6, when a SOAP server has a typemap configured, the decoding…"
    },
    {
      "cve": "CVE-2026-7261",
      "sev": "critical",
      "kev": false,
      "title": "In PHP versions 8.2.* before 8.2.31, 8.3.* before 8.3.31, 8.4.* before 8.4.21, and…",
      "ranges": [
        {
          "gte": "8.2.0",
          "lt": "8.2.31"
        },
        {
          "gte": "8.3.0",
          "lt": "8.3.31"
        },
        {
          "gte": "8.4.0",
          "lt": "8.4.21"
        },
        {
          "gte": "8.5.0",
          "lt": "8.5.6"
        }
      ],
      "note": "NVD: In PHP versions 8.2.* before 8.2.31, 8.3.* before 8.3.31, 8.4.* before 8.4.21, and 8.5.* before 8.5.6, when SoapServer is configured with SOAP_PERSISTENCE_SESSION,…"
    },
    {
      "cve": "CVE-2026-7258",
      "sev": "high",
      "kev": false,
      "title": "In PHP versions 8.2.* before 8.2.31, 8.3.* before 8.3.31, 8.4.* before 8.4.21, and…",
      "ranges": [
        {
          "gte": "8.2.0",
          "lt": "8.2.21"
        },
        {
          "gte": "8.3.0",
          "lt": "8.3.31"
        },
        {
          "gte": "8.4.0",
          "lt": "8.4.21"
        },
        {
          "gte": "8.5.0",
          "lt": "8.5.6"
        }
      ],
      "note": "NVD: In PHP versions 8.2.* before 8.2.31, 8.3.* before 8.3.31, 8.4.* before 8.4.21, and 8.5.* before 8.5.6, some functions, including urldecode(), pass signed char to…"
    },
    {
      "cve": "CVE-2026-6722",
      "sev": "critical",
      "kev": false,
      "title": "In PHP versions 8.2.* before 8.2.31, 8.3.* before 8.3.31, 8.4.* before 8.4.21, and…",
      "ranges": [
        {
          "gte": "8.2.0",
          "lt": "8.2.31"
        },
        {
          "gte": "8.3.0",
          "lt": "8.3.31"
        },
        {
          "gte": "8.4.0",
          "lt": "8.4.21"
        },
        {
          "gte": "8.5.0",
          "lt": "8.5.6"
        }
      ],
      "note": "NVD: In PHP versions 8.2.* before 8.2.31, 8.3.* before 8.3.31, 8.4.* before 8.4.21, and 8.5.* before 8.5.6, the SOAP extension's object deduplication mechanism stores…"
    },
    {
      "cve": "CVE-2026-6104",
      "sev": "critical",
      "kev": false,
      "title": "In PHP versions 8.4.* before 8.4.21 and 8.5.* before 8.5.6, when an encoding name…",
      "ranges": [
        {
          "gte": "8.4.0",
          "lt": "8.4.21"
        },
        {
          "gte": "8.5.0",
          "lt": "8.5.6"
        }
      ],
      "note": "NVD: In PHP versions 8.4.* before 8.4.21 and 8.5.* before 8.5.6, when an encoding name containing an embedded NUL byte is passed to mb_convert_encoding() or related…"
    },
    {
      "cve": "CVE-2025-14180",
      "sev": "high",
      "kev": false,
      "title": "In PHP versions 8.1.* before 8.1.34, 8.2.* before 8.2.30, 8.3.* before 8.3.29, 8.4.*…",
      "ranges": [
        {
          "gte": "8.1.0",
          "lt": "8.1.34"
        },
        {
          "gte": "8.2.0",
          "lt": "8.2.30"
        },
        {
          "gte": "8.3.0",
          "lt": "8.3.29"
        },
        {
          "gte": "8.4.0",
          "lt": "8.4.16"
        },
        {
          "gte": "8.5.0",
          "lt": "8.5.1"
        }
      ],
      "note": "NVD: In PHP versions 8.1.* before 8.1.34, 8.2.* before 8.2.30, 8.3.* before 8.3.29, 8.4.* before 8.4.16, 8.5.* before 8.5.1 when using the PDO PostgreSQL driver with…"
    },
    {
      "cve": "CVE-2025-14179",
      "sev": "critical",
      "kev": false,
      "title": "In PHP versions 8.2.* before 8.2.31, 8.3.* before 8.3.31, 8.4.* before 8.4.21, and…",
      "ranges": [
        {
          "gte": "8.2.0",
          "lt": "8.2.31"
        },
        {
          "gte": "8.3.0",
          "lt": "8.3.31"
        },
        {
          "gte": "8.4.0",
          "lt": "8.4.21"
        },
        {
          "gte": "8.5.0",
          "lt": "8.5.6"
        }
      ],
      "note": "NVD: In PHP versions 8.2.* before 8.2.31, 8.3.* before 8.3.31, 8.4.* before 8.4.21, and 8.5.* before 8.5.6, the PDO Firebird driver improperly handles NUL bytes when…"
    },
    {
      "cve": "CVE-2025-14177",
      "sev": "high",
      "kev": false,
      "title": "In PHP versions:8.1.* before 8.1.34, 8.2.* before 8.2.30, 8.3.* before 8.3.29, 8.4.*…",
      "ranges": [
        {
          "gte": "8.1.0",
          "lt": "8.1.34"
        },
        {
          "gte": "8.2.0",
          "lt": "8.2.30"
        },
        {
          "gte": "8.3.0",
          "lt": "8.3.29"
        },
        {
          "gte": "8.4.0",
          "lt": "8.4.16"
        },
        {
          "eq": "8.5.0"
        }
      ],
      "note": "NVD: In PHP versions:8.1.* before 8.1.34, 8.2.* before 8.2.30, 8.3.* before 8.3.29, 8.4.* before 8.4.16, 8.5.* before 8.5.1, the getimagesize() function may leak…"
    },
    {
      "cve": "CVE-2025-1861",
      "sev": "critical",
      "kev": false,
      "title": "In PHP from 8.1.* before 8.1.32, from 8.2.* before 8.2.28, from 8.3.* before 8.3.19,…",
      "ranges": [
        {
          "gte": "8.1.0",
          "lt": "8.1.31"
        },
        {
          "gte": "8.2.0",
          "lt": "8.2.26"
        },
        {
          "gte": "8.3.0",
          "lt": "8.3.14"
        },
        {
          "gte": "8.4.0",
          "lt": "8.4.5"
        }
      ],
      "note": "NVD: In PHP from 8.1.* before 8.1.32, from 8.2.* before 8.2.28, from 8.3.* before 8.3.19, from 8.4.* before 8.4.5, when parsing HTTP redirect in the response to an HTTP…"
    },
    {
      "cve": "CVE-2025-1736",
      "sev": "high",
      "kev": false,
      "title": "In PHP from 8.1.* before 8.1.32, from 8.2.* before 8.2.28, from 8.3.* before 8.3.19,…",
      "ranges": [
        {
          "gte": "8.1.0",
          "lt": "8.1.32"
        },
        {
          "gte": "8.2.0",
          "lt": "8.2.28"
        },
        {
          "gte": "8.3.0",
          "lt": "8.3.19"
        },
        {
          "gte": "8.4.0",
          "lt": "8.4.5"
        }
      ],
      "note": "NVD: In PHP from 8.1.* before 8.1.32, from 8.2.* before 8.2.28, from 8.3.* before 8.3.19, from 8.4.* before 8.4.5, when user-supplied headers are sent, the insufficient…"
    },
    {
      "cve": "CVE-2024-11236",
      "sev": "critical",
      "kev": false,
      "title": "In PHP versions 8.1.* before 8.1.31, 8.2.* before 8.2.26, 8.3.* before 8.3.14,…",
      "ranges": [
        {
          "gte": "8.1.0",
          "lt": "8.1.31"
        },
        {
          "gte": "8.2.0",
          "lt": "8.2.26"
        },
        {
          "gte": "8.3.0",
          "lt": "8.3.14"
        }
      ],
      "note": "NVD: In PHP versions 8.1.* before 8.1.31, 8.2.* before 8.2.26, 8.3.* before 8.3.14, uncontrolled long string inputs to ldap_escape() function on 32-bit systems can…"
    },
    {
      "cve": "CVE-2024-11235",
      "sev": "high",
      "kev": false,
      "title": "In PHP versions 8.3.* before 8.3.19 and 8.4.* before 8.4.5, a code sequence involving…",
      "ranges": [
        {
          "gte": "8.3.0",
          "lt": "8.3.19"
        },
        {
          "gte": "8.4.0",
          "lt": "8.4.5"
        }
      ],
      "note": "NVD: In PHP versions 8.3.* before 8.3.19 and 8.4.* before 8.4.5, a code sequence involving __set handler or ??= operator and exceptions can lead to a use-after-free…"
    },
    {
      "cve": "CVE-2024-8932",
      "sev": "critical",
      "kev": false,
      "title": "In PHP versions 8.1.* before 8.1.31, 8.2.* before 8.2.26, 8.3.* before 8.3.14,…",
      "ranges": [
        {
          "gte": "8.1.0",
          "lt": "8.1.31"
        },
        {
          "gte": "8.2.0",
          "lt": "8.2.26"
        },
        {
          "gte": "8.3.0",
          "lt": "8.3.14"
        }
      ],
      "note": "NVD: In PHP versions 8.1.* before 8.1.31, 8.2.* before 8.2.26, 8.3.* before 8.3.14, uncontrolled long string inputs to ldap_escape() function on 32-bit systems can…"
    },
    {
      "cve": "CVE-2024-8927",
      "sev": "high",
      "kev": false,
      "title": "In PHP versions 8.1.* before 8.1.30, 8.2.* before 8.2.24, 8.3.* before 8.3.12,…",
      "ranges": [
        {
          "gte": "8.1.0",
          "lt": "8.1.30"
        },
        {
          "gte": "8.2.0",
          "lt": "8.2.24"
        },
        {
          "gte": "8.3.0",
          "lt": "8.3.12"
        }
      ],
      "note": "NVD: In PHP versions 8.1.* before 8.1.30, 8.2.* before 8.2.24, 8.3.* before 8.3.12, HTTP_REDIRECT_STATUS variable is used to check whether or not CGI binary is being…"
    },
    {
      "cve": "CVE-2024-8926",
      "sev": "high",
      "kev": false,
      "title": "In PHP versions 8.1.* before 8.1.30, 8.2.* before 8.2.24, 8.3.* before 8.3.12, when…",
      "ranges": [
        {
          "gte": "8.1.0",
          "lt": "8.1.30"
        },
        {
          "gte": "8.2.0",
          "lt": "8.2.24"
        },
        {
          "gte": "8.3.0",
          "lt": "8.3.12"
        }
      ],
      "note": "NVD: In PHP versions 8.1.* before 8.1.30, 8.2.* before 8.2.24, 8.3.* before 8.3.12, when using a certain non-standard configurations of Windows codepages, the fixes for…"
    },
    {
      "cve": "CVE-2024-5585",
      "sev": "high",
      "kev": false,
      "title": "In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, the fix…",
      "ranges": [
        {
          "gte": "8.1.0",
          "lt": "8.1.29"
        },
        {
          "gte": "8.2.0",
          "lt": "8.2.20"
        },
        {
          "gte": "8.3.0",
          "lt": "8.3.8"
        }
      ],
      "note": "NVD: In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, the fix for CVE-2024-1874 does not work if the command name includes trailing spaces."
    },
    {
      "cve": "CVE-2024-4577",
      "sev": "critical",
      "kev": true,
      "title": "In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when…",
      "ranges": [
        {
          "gte": "8.1.0",
          "lt": "8.1.29"
        },
        {
          "gte": "8.2.0",
          "lt": "8.2.20"
        },
        {
          "gte": "8.3.0",
          "lt": "8.3.8"
        }
      ],
      "note": "NVD: In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the… — CISA KEV (actively exploited)"
    },
    {
      "cve": "CVE-2024-3566",
      "sev": "critical",
      "kev": false,
      "title": "A command inject vulnerability allows an attacker to perform command injection on…",
      "ranges": [
        {
          "lt": "8.1.28"
        },
        {
          "gte": "8.2.0",
          "lt": "8.2.18"
        },
        {
          "gte": "8.3.0",
          "lt": "8.3.6"
        }
      ],
      "note": "NVD: A command inject vulnerability allows an attacker to perform command injection on Windows applications that indirectly depend on the CreateProcess function when…"
    },
    {
      "cve": "CVE-2024-2757",
      "sev": "high",
      "kev": false,
      "title": "In PHP 8.3.* before 8.3.5, function mb_encode_mimeheader() runs endlessly for some…",
      "ranges": [
        {
          "gte": "8.3.0",
          "lt": "8.3.5"
        }
      ],
      "note": "NVD: In PHP 8.3.* before 8.3.5, function mb_encode_mimeheader() runs endlessly for some inputs that contain long strings of non-space characters followed by a space."
    },
    {
      "cve": "CVE-2024-1874",
      "sev": "critical",
      "kev": false,
      "title": "In PHP versions 8.1.* before 8.1.28, 8.2.* before 8.2.18, 8.3.* before 8.3.5, when…",
      "ranges": [
        {
          "gte": "8.1.0",
          "lt": "8.1.28"
        },
        {
          "gte": "8.2.0",
          "lt": "8.2.18"
        },
        {
          "gte": "8.3.0",
          "lt": "8.3.5"
        }
      ],
      "note": "NVD: In PHP versions 8.1.* before 8.1.28, 8.2.* before 8.2.18, 8.3.* before 8.3.5, when using proc_open() command with array syntax, due to insufficient escaping, if…"
    },
    {
      "cve": "CVE-2023-3824",
      "sev": "critical",
      "kev": false,
      "title": "In PHP version 8.0.* before 8.0.30, 8.1.* before 8.1.22, and 8.2.* before 8.2.8, when…",
      "ranges": [
        {
          "gte": "8.0.0",
          "lt": "8.0.30"
        },
        {
          "gte": "8.1.0",
          "lt": "8.1.22"
        },
        {
          "gte": "8.2.0",
          "lt": "8.2.9"
        }
      ],
      "note": "NVD: In PHP version 8.0.* before 8.0.30, 8.1.* before 8.1.22, and 8.2.* before 8.2.8, when loading phar file, while reading PHAR directory entries, insufficient length…"
    },
    {
      "cve": "CVE-2023-3823",
      "sev": "high",
      "kev": false,
      "title": "In PHP versions 8.0.* before 8.0.30, 8.1.* before 8.1.22, and 8.2.* before 8.2.8…",
      "ranges": [
        {
          "gte": "8.0.0",
          "lt": "8.0.30"
        },
        {
          "gte": "8.1.0",
          "lt": "8.1.22"
        },
        {
          "gte": "8.2.0",
          "lt": "8.2.9"
        }
      ],
      "note": "NVD: In PHP versions 8.0.* before 8.0.30, 8.1.* before 8.1.22, and 8.2.* before 8.2.8 various XML functions rely on libxml global state to track configuration…"
    },
    {
      "cve": "CVE-2023-0662",
      "sev": "high",
      "kev": false,
      "title": "In PHP 8.0.X before 8.0.28, 8.1.X before 8.1.16 and 8.2.X before 8.2.3, excessive…",
      "ranges": [
        {
          "gte": "8.0.0",
          "lt": "8.0.28"
        },
        {
          "gte": "8.1.0",
          "lt": "8.1.16"
        },
        {
          "gte": "8.2.0",
          "lt": "8.2.3"
        }
      ],
      "note": "NVD: In PHP 8.0.X before 8.0.28, 8.1.X before 8.1.16 and 8.2.X before 8.2.3, excessive number of parts in HTTP form upload can cause high resource consumption and…"
    },
    {
      "cve": "CVE-2023-0568",
      "sev": "high",
      "kev": false,
      "title": "In PHP 8.0.X before 8.0.28, 8.1.X before 8.1.16 and 8.2.X before 8.2.3, core path…",
      "ranges": [
        {
          "gte": "8.0.0",
          "lt": "8.0.28"
        },
        {
          "gte": "8.1.0",
          "lt": "8.1.16"
        },
        {
          "gte": "8.2.0",
          "lt": "8.2.3"
        }
      ],
      "note": "NVD: In PHP 8.0.X before 8.0.28, 8.1.X before 8.1.16 and 8.2.X before 8.2.3, core path resolution function allocate buffer one byte too small."
    },
    {
      "cve": "CVE-2023-0567",
      "sev": "high",
      "kev": false,
      "title": "In PHP 8.0.X before 8.0.28, 8.1.X before 8.1.16 and 8.2.X before 8.2.3,…",
      "ranges": [
        {
          "gte": "8.0.0",
          "lt": "8.0.28"
        },
        {
          "gte": "8.1.0",
          "lt": "8.1.16"
        },
        {
          "gte": "8.2.0",
          "lt": "8.2.3"
        }
      ],
      "note": "NVD: In PHP 8.0.X before 8.0.28, 8.1.X before 8.1.16 and 8.2.X before 8.2.3, password_verify() function may accept some invalid Blowfish hashes as valid."
    },
    {
      "cve": "CVE-2022-37454",
      "sev": "critical",
      "kev": false,
      "title": "The Keccak XKCP SHA-3 reference implementation before fdc6fef has an integer overflow…",
      "ranges": [
        {
          "gte": "7.2.0",
          "lt": "7.4.33"
        },
        {
          "gte": "8.0.0",
          "lt": "8.0.25"
        },
        {
          "gte": "8.1.0",
          "lt": "8.1.12"
        }
      ],
      "note": "NVD: The Keccak XKCP SHA-3 reference implementation before fdc6fef has an integer overflow and resultant buffer overflow that allows attackers to execute arbitrary code…"
    },
    {
      "cve": "CVE-2022-31631",
      "sev": "critical",
      "kev": false,
      "title": "In PHP versions 8.0.* before 8.0.27, 8.1.* before 8.1.15, 8.2.* before 8.2.2 when…",
      "ranges": [
        {
          "gte": "8.0.0",
          "lt": "8.0.27"
        },
        {
          "gte": "8.1.0",
          "lt": "8.1.15"
        },
        {
          "gte": "8.2.0",
          "lt": "8.2.2"
        }
      ],
      "note": "NVD: In PHP versions 8.0.* before 8.0.27, 8.1.* before 8.1.15, 8.2.* before 8.2.2 when using PDO::quote() function to quote user-supplied data for SQLite, supplying an…"
    },
    {
      "cve": "CVE-2022-31627",
      "sev": "high",
      "kev": false,
      "title": "In PHP versions 8.1.x below 8.1.8, when fileinfo functions, such as finfo_buffer, due…",
      "ranges": [
        {
          "gte": "8.1.0",
          "lt": "8.1.8"
        }
      ],
      "note": "NVD: In PHP versions 8.1.x below 8.1.8, when fileinfo functions, such as finfo_buffer, due to incorrect patch applied to the third party code from libmagic, incorrect…"
    },
    {
      "cve": "CVE-2022-31626",
      "sev": "high",
      "kev": false,
      "title": "In PHP versions 7.4.x below 7.4.30, 8.0.x below 8.0.20, and 8.1.x below 8.1.7, when…",
      "ranges": [
        {
          "gte": "7.4.0",
          "lt": "7.4.30"
        },
        {
          "gte": "8.0.0",
          "lt": "8.0.20"
        },
        {
          "gte": "8.1.0",
          "lt": "8.1.7"
        }
      ],
      "note": "NVD: In PHP versions 7.4.x below 7.4.30, 8.0.x below 8.0.20, and 8.1.x below 8.1.7, when pdo_mysql extension with mysqlnd driver, if the third party is allowed to…"
    },
    {
      "cve": "CVE-2022-31625",
      "sev": "high",
      "kev": false,
      "title": "In PHP versions 7.4.x below 7.4.30, 8.0.x below 8.0.20, and 8.1.x below 8.1.7, when…",
      "ranges": [
        {
          "gte": "7.4.0",
          "lt": "7.4.30"
        },
        {
          "gte": "8.0.0",
          "lt": "8.0.20"
        },
        {
          "gte": "8.1.0",
          "lt": "8.1.7"
        }
      ],
      "note": "NVD: In PHP versions 7.4.x below 7.4.30, 8.0.x below 8.0.20, and 8.1.x below 8.1.7, when using Postgres database extension, supplying invalid parameters to the…"
    },
    {
      "cve": "CVE-2021-21708",
      "sev": "high",
      "kev": false,
      "title": "In PHP versions 7.4.x below 7.4.28, 8.0.x below 8.0.16, and 8.1.x below 8.1.3, when…",
      "ranges": [
        {
          "gte": "7.4.0",
          "lt": "7.4.28"
        },
        {
          "gte": "8.0.0",
          "lt": "8.0.16"
        },
        {
          "gte": "8.1.0",
          "lt": "8.1.3"
        }
      ],
      "note": "NVD: In PHP versions 7.4.x below 7.4.28, 8.0.x below 8.0.16, and 8.1.x below 8.1.3, when using filter functions with FILTER_VALIDATE_FLOAT filter and min/max limits, if…"
    },
    {
      "cve": "CVE-2021-21703",
      "sev": "high",
      "kev": false,
      "title": "In PHP versions 7.3.x up to and including 7.3.31, 7.4.x below 7.4.25 and 8.0.x below…",
      "ranges": [
        {
          "gte": "7.3.0",
          "lte": "7.3.31"
        },
        {
          "gte": "7.4.0",
          "lt": "7.4.25"
        },
        {
          "gte": "8.0.0",
          "lt": "8.0.12"
        }
      ],
      "note": "NVD: In PHP versions 7.3.x up to and including 7.3.31, 7.4.x below 7.4.25 and 8.0.x below 8.0.12, when running PHP FPM SAPI with main FPM daemon process running as root…"
    },
    {
      "cve": "CVE-2020-7067",
      "sev": "high",
      "kev": false,
      "title": "In PHP versions 7.2.x below 7.2.30, 7.3.x below 7.3.17 and 7.4.x below 7.4.5, if PHP…",
      "ranges": [
        {
          "gte": "7.2.0",
          "lt": "7.2.30"
        },
        {
          "gte": "7.3.0",
          "lt": "7.3.17"
        },
        {
          "gte": "7.4.0",
          "lt": "7.4.5"
        }
      ],
      "note": "NVD: In PHP versions 7.2.x below 7.2.30, 7.3.x below 7.3.17 and 7.4.x below 7.4.5, if PHP is compiled with EBCDIC support (uncommon), urldecode() function can be made…"
    },
    {
      "cve": "CVE-2020-7065",
      "sev": "high",
      "kev": false,
      "title": "In PHP versions 7.3.x below 7.3.16 and 7.4.x below 7.4.4, while using mb_strtolower()…",
      "ranges": [
        {
          "gte": "7.3.0",
          "lt": "7.3.16"
        },
        {
          "gte": "7.4.0",
          "lt": "7.4.4"
        }
      ],
      "note": "NVD: In PHP versions 7.3.x below 7.3.16 and 7.4.x below 7.4.4, while using mb_strtolower() function with UTF-32LE encoding, certain invalid strings could cause PHP to…"
    },
    {
      "cve": "CVE-2020-7062",
      "sev": "high",
      "kev": false,
      "title": "In PHP versions 7.2.x below 7.2.28, 7.3.x below 7.3.15 and 7.4.x below 7.4.3, when…",
      "ranges": [
        {
          "gte": "7.2.0",
          "lte": "7.2.27"
        },
        {
          "gte": "7.3.0",
          "lte": "7.3.14"
        },
        {
          "gte": "7.4.0",
          "lte": "7.4.2"
        }
      ],
      "note": "NVD: In PHP versions 7.2.x below 7.2.28, 7.3.x below 7.3.15 and 7.4.x below 7.4.3, when using file upload functionality, if upload progress tracking is enabled, but…"
    },
    {
      "cve": "CVE-2019-19246",
      "sev": "high",
      "kev": false,
      "title": "Oniguruma through 6.9.3, as used in PHP 7.3.x and other products, has a heap-based…",
      "ranges": [
        {
          "gte": "7.3.0",
          "lt": "7.3.10"
        }
      ],
      "note": "NVD: Oniguruma through 6.9.3, as used in PHP 7.3.x and other products, has a heap-based buffer over-read in str_lower_case_match in regexec.c."
    },
    {
      "cve": "CVE-2019-13224",
      "sev": "critical",
      "kev": false,
      "title": "A use-after-free in onig_new_deluxe() in regext.c in Oniguruma 6.9.2 allows attackers…",
      "ranges": [
        {
          "gte": "7.1.0",
          "lt": "7.1.32"
        },
        {
          "gte": "7.2.0",
          "lt": "7.2.23"
        },
        {
          "gte": "7.3.0",
          "lt": "7.3.9"
        }
      ],
      "note": "NVD: A use-after-free in onig_new_deluxe() in regext.c in Oniguruma 6.9.2 allows attackers to potentially cause information disclosure, denial of service, or possibly…"
    },
    {
      "cve": "CVE-2019-11043",
      "sev": "high",
      "kev": true,
      "title": "In PHP versions 7.1.x below 7.1.33, 7.2.x below 7.2.24 and 7.3.x below 7.3.11 in…",
      "ranges": [
        {
          "gte": "7.1.0",
          "lt": "7.1.33"
        },
        {
          "gte": "7.2.0",
          "lt": "7.2.24"
        },
        {
          "gte": "7.3.0",
          "lt": "7.3.11"
        }
      ],
      "note": "NVD: In PHP versions 7.1.x below 7.1.33, 7.2.x below 7.2.24 and 7.3.x below 7.3.11 in certain configurations of FPM setup it is possible… — CISA KEV (actively exploited)"
    },
    {
      "cve": "CVE-2019-11042",
      "sev": "high",
      "kev": false,
      "title": "When PHP EXIF extension is parsing EXIF information from an image, e.g.",
      "ranges": [
        {
          "gte": "7.1.0",
          "lt": "7.1.31"
        },
        {
          "gte": "7.2.0",
          "lt": "7.2.21"
        },
        {
          "gte": "7.3.0",
          "lt": "7.3.8"
        }
      ],
      "note": "NVD: When PHP EXIF extension is parsing EXIF information from an image, e.g."
    },
    {
      "cve": "CVE-2019-11041",
      "sev": "high",
      "kev": false,
      "title": "When PHP EXIF extension is parsing EXIF information from an image, e.g.",
      "ranges": [
        {
          "gte": "7.1.0",
          "lt": "7.1.31"
        },
        {
          "gte": "7.2.0",
          "lt": "7.2.21"
        },
        {
          "gte": "7.3.0",
          "lt": "7.3.8"
        }
      ],
      "note": "NVD: When PHP EXIF extension is parsing EXIF information from an image, e.g."
    },
    {
      "cve": "CVE-2019-11040",
      "sev": "critical",
      "kev": false,
      "title": "When PHP EXIF extension is parsing EXIF information from an image, e.g.",
      "ranges": [
        {
          "gte": "7.1.0",
          "lt": "7.1.30"
        },
        {
          "gte": "7.2.0",
          "lt": "7.2.19"
        },
        {
          "gte": "7.3.0",
          "lt": "7.3.6"
        }
      ],
      "note": "NVD: When PHP EXIF extension is parsing EXIF information from an image, e.g."
    },
    {
      "cve": "CVE-2019-11039",
      "sev": "critical",
      "kev": false,
      "title": "Function iconv_mime_decode_headers() in PHP versions 7.1.x below 7.1.30, 7.2.x below…",
      "ranges": [
        {
          "gte": "7.1.0",
          "lt": "7.1.30"
        },
        {
          "gte": "7.2.0",
          "lt": "7.2.19"
        },
        {
          "gte": "7.3.0",
          "lt": "7.3.6"
        }
      ],
      "note": "NVD: Function iconv_mime_decode_headers() in PHP versions 7.1.x below 7.1.30, 7.2.x below 7.2.19 and 7.3.x below 7.3.6 may perform out-of-buffer read due to integer…"
    },
    {
      "cve": "CVE-2019-11036",
      "sev": "critical",
      "kev": false,
      "title": "When processing certain files, PHP EXIF extension in versions 7.1.x below 7.1.29,…",
      "ranges": [
        {
          "gte": "7.1.0",
          "lt": "7.1.29"
        },
        {
          "gte": "7.2.0",
          "lt": "7.2.18"
        },
        {
          "gte": "7.3.0",
          "lt": "7.3.5"
        }
      ],
      "note": "NVD: When processing certain files, PHP EXIF extension in versions 7.1.x below 7.1.29, 7.2.x below 7.2.18 and 7.3.x below 7.3.5 can be caused to read past allocated…"
    },
    {
      "cve": "CVE-2019-11035",
      "sev": "critical",
      "kev": false,
      "title": "When processing certain files, PHP EXIF extension in versions 7.1.x below 7.1.28,…",
      "ranges": [
        {
          "gte": "7.1.0",
          "lt": "7.1.28"
        },
        {
          "gte": "7.2.9",
          "lt": "7.2.17"
        },
        {
          "gte": "7.3.0",
          "lt": "7.3.4"
        }
      ],
      "note": "NVD: When processing certain files, PHP EXIF extension in versions 7.1.x below 7.1.28, 7.2.x below 7.2.17 and 7.3.x below 7.3.4 can be caused to read past allocated…"
    },
    {
      "cve": "CVE-2019-11034",
      "sev": "critical",
      "kev": false,
      "title": "When processing certain files, PHP EXIF extension in versions 7.1.x below 7.1.28,…",
      "ranges": [
        {
          "gte": "7.1.0",
          "lt": "7.1.28"
        },
        {
          "gte": "7.2.9",
          "lt": "7.2.17"
        },
        {
          "gte": "7.3.0",
          "lt": "7.3.4"
        }
      ],
      "note": "NVD: When processing certain files, PHP EXIF extension in versions 7.1.x below 7.1.28, 7.2.x below 7.2.17 and 7.3.x below 7.3.4 can be caused to read past allocated…"
    },
    {
      "cve": "CVE-2019-9675",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in PHP 7.x before 7.1.27 and 7.3.x before 7.3.3.",
      "ranges": [
        {
          "gte": "7.0.0",
          "lt": "7.1.27"
        },
        {
          "gte": "7.3.0",
          "lt": "7.3.3"
        }
      ],
      "note": "NVD: An issue was discovered in PHP 7.x before 7.1.27 and 7.3.x before 7.3.3."
    },
    {
      "cve": "CVE-2019-9641",
      "sev": "critical",
      "kev": false,
      "title": "An issue was discovered in the EXIF component in PHP before 7.1.27, 7.2.x before…",
      "ranges": [
        {
          "lt": "7.1.27"
        },
        {
          "gte": "7.2.0",
          "lt": "7.2.16"
        },
        {
          "gte": "7.3.0",
          "lt": "7.3.3"
        }
      ],
      "note": "NVD: An issue was discovered in the EXIF component in PHP before 7.1.27, 7.2.x before 7.2.16, and 7.3.x before 7.3.3."
    },
    {
      "cve": "CVE-2019-9640",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in the EXIF component in PHP before 7.1.27, 7.2.x before…",
      "ranges": [
        {
          "gte": "7.1.0",
          "lt": "7.1.27"
        },
        {
          "gte": "7.2.0",
          "lt": "7.2.16"
        },
        {
          "gte": "7.3.0",
          "lt": "7.3.3"
        }
      ],
      "note": "NVD: An issue was discovered in the EXIF component in PHP before 7.1.27, 7.2.x before 7.2.16, and 7.3.x before 7.3.3."
    },
    {
      "cve": "CVE-2019-9639",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in the EXIF component in PHP before 7.1.27, 7.2.x before…",
      "ranges": [
        {
          "lt": "7.1.27"
        },
        {
          "gte": "7.2.0",
          "lt": "7.2.16"
        },
        {
          "gte": "7.3.0",
          "lt": "7.3.3"
        }
      ],
      "note": "NVD: An issue was discovered in the EXIF component in PHP before 7.1.27, 7.2.x before 7.2.16, and 7.3.x before 7.3.3."
    },
    {
      "cve": "CVE-2019-9638",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in the EXIF component in PHP before 7.1.27, 7.2.x before…",
      "ranges": [
        {
          "lt": "7.1.27"
        },
        {
          "gte": "7.2.0",
          "lt": "7.2.16"
        },
        {
          "gte": "7.3.0",
          "lt": "7.3.3"
        }
      ],
      "note": "NVD: An issue was discovered in the EXIF component in PHP before 7.1.27, 7.2.x before 7.2.16, and 7.3.x before 7.3.3."
    },
    {
      "cve": "CVE-2019-9637",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in PHP before 7.1.27, 7.2.x before 7.2.16, and 7.3.x before…",
      "ranges": [
        {
          "lt": "7.1.27"
        },
        {
          "gte": "7.2.0",
          "lt": "7.2.16"
        },
        {
          "gte": "7.3.0",
          "lt": "7.3.3"
        }
      ],
      "note": "NVD: An issue was discovered in PHP before 7.1.27, 7.2.x before 7.2.16, and 7.3.x before 7.3.3."
    },
    {
      "cve": "CVE-2019-9025",
      "sev": "critical",
      "kev": false,
      "title": "An issue was discovered in PHP 7.3.x before 7.3.1.",
      "ranges": [
        {
          "gte": "7.3.0",
          "lt": "7.3.1"
        }
      ],
      "note": "NVD: An issue was discovered in PHP 7.3.x before 7.3.1."
    },
    {
      "cve": "CVE-2019-9024",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in PHP before 5.6.40, 7.x before 7.1.26, 7.2.x before 7.2.14,…",
      "ranges": [
        {
          "lt": "5.6.40"
        },
        {
          "gte": "7.0.0",
          "lt": "7.1.26"
        },
        {
          "gte": "7.2.0",
          "lt": "7.2.14"
        },
        {
          "gte": "7.3.0",
          "lt": "7.3.1"
        }
      ],
      "note": "NVD: An issue was discovered in PHP before 5.6.40, 7.x before 7.1.26, 7.2.x before 7.2.14, and 7.3.x before 7.3.1."
    },
    {
      "cve": "CVE-2019-9023",
      "sev": "critical",
      "kev": false,
      "title": "An issue was discovered in PHP before 5.6.40, 7.x before 7.1.26, 7.2.x before 7.2.14,…",
      "ranges": [
        {
          "lt": "5.6.40"
        },
        {
          "gte": "7.0.0",
          "lt": "7.1.26"
        },
        {
          "gte": "7.2.0",
          "lt": "7.2.14"
        },
        {
          "gte": "7.3.0",
          "lt": "7.3.1"
        }
      ],
      "note": "NVD: An issue was discovered in PHP before 5.6.40, 7.x before 7.1.26, 7.2.x before 7.2.14, and 7.3.x before 7.3.1."
    },
    {
      "cve": "CVE-2019-9022",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in PHP 7.x before 7.1.26, 7.2.x before 7.2.14, and 7.3.x…",
      "ranges": [
        {
          "gte": "7.0.0",
          "lt": "7.1.26"
        },
        {
          "gte": "7.2.0",
          "lt": "7.2.14"
        },
        {
          "gte": "7.3.0",
          "lt": "7.3.2"
        }
      ],
      "note": "NVD: An issue was discovered in PHP 7.x before 7.1.26, 7.2.x before 7.2.14, and 7.3.x before 7.3.2."
    },
    {
      "cve": "CVE-2019-9021",
      "sev": "critical",
      "kev": false,
      "title": "An issue was discovered in PHP before 5.6.40, 7.x before 7.1.26, 7.2.x before 7.2.14,…",
      "ranges": [
        {
          "lt": "5.6.40"
        },
        {
          "gte": "7.0.0",
          "lt": "7.1.26"
        },
        {
          "gte": "7.2.0",
          "lt": "7.2.14"
        },
        {
          "gte": "7.3.0",
          "lt": "7.3.1"
        }
      ],
      "note": "NVD: An issue was discovered in PHP before 5.6.40, 7.x before 7.1.26, 7.2.x before 7.2.14, and 7.3.x before 7.3.1."
    },
    {
      "cve": "CVE-2019-9020",
      "sev": "critical",
      "kev": false,
      "title": "An issue was discovered in PHP before 5.6.40, 7.x before 7.1.26, 7.2.x before 7.2.14,…",
      "ranges": [
        {
          "lt": "5.6.40"
        },
        {
          "gte": "7.0.0",
          "lt": "7.1.26"
        },
        {
          "gte": "7.2.0",
          "lt": "7.2.14"
        },
        {
          "gte": "7.3.0",
          "lt": "7.3.1"
        }
      ],
      "note": "NVD: An issue was discovered in PHP before 5.6.40, 7.x before 7.1.26, 7.2.x before 7.2.14, and 7.3.x before 7.3.1."
    },
    {
      "cve": "CVE-2019-6977",
      "sev": "high",
      "kev": false,
      "title": "gdImageColorMatch in gd_color_match.c in the GD Graphics Library (aka LibGD) 2.2.5, as…",
      "ranges": [
        {
          "lt": "5.6.40"
        },
        {
          "gte": "7.0.0",
          "lt": "7.1.26"
        },
        {
          "gte": "7.2.0",
          "lt": "7.2.14"
        },
        {
          "eq": "7.3.0"
        }
      ],
      "note": "NVD: gdImageColorMatch in gd_color_match.c in the GD Graphics Library (aka LibGD) 2.2.5, as used in the imagecolormatch function in PHP before 5.6.40, 7.x before…"
    },
    {
      "cve": "CVE-2018-20783",
      "sev": "high",
      "kev": false,
      "title": "In PHP before 5.6.39, 7.x before 7.0.33, 7.1.x before 7.1.25, and 7.2.x before 7.2.13,…",
      "ranges": [
        {
          "lt": "5.6.39"
        },
        {
          "gte": "7.0.0",
          "lt": "7.0.33"
        },
        {
          "gte": "7.1.0",
          "lt": "7.1.25"
        },
        {
          "gte": "7.2.0",
          "lt": "7.2.13"
        }
      ],
      "note": "NVD: In PHP before 5.6.39, 7.x before 7.0.33, 7.1.x before 7.1.25, and 7.2.x before 7.2.13, a buffer over-read in PHAR reading functions may allow an attacker to read…"
    },
    {
      "cve": "CVE-2018-19935",
      "sev": "high",
      "kev": false,
      "title": "ext/imap/php_imap.c in PHP 5.x and 7.x before 7.3.0 allows remote attackers to cause a…",
      "ranges": [
        {
          "gte": "5.6.0",
          "lt": "5.6.39"
        },
        {
          "gte": "7.0.0",
          "lt": "7.0.33"
        },
        {
          "gte": "7.1.0",
          "lt": "7.1.26"
        },
        {
          "gte": "7.2.0",
          "lt": "7.2.14"
        }
      ],
      "note": "NVD: ext/imap/php_imap.c in PHP 5.x and 7.x before 7.3.0 allows remote attackers to cause a denial of service (NULL pointer dereference and application crash) via an…"
    },
    {
      "cve": "CVE-2018-19520",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in SDCMS 1.6 with PHP 5.x.",
      "ranges": [
        {
          "gte": "5.0.0",
          "lte": "5.6.38"
        }
      ],
      "note": "NVD: An issue was discovered in SDCMS 1.6 with PHP 5.x."
    },
    {
      "cve": "CVE-2018-19518",
      "sev": "high",
      "kev": false,
      "title": "University of Washington IMAP Toolkit 2007f on UNIX, as used in imap_open() in PHP and…",
      "ranges": [
        {
          "gte": "5.6.0",
          "lte": "5.6.38"
        },
        {
          "gte": "7.0.0",
          "lte": "7.0.32"
        },
        {
          "gte": "7.1.0",
          "lte": "7.1.24"
        },
        {
          "gte": "7.2.0",
          "lte": "7.2.12"
        }
      ],
      "note": "NVD: University of Washington IMAP Toolkit 2007f on UNIX, as used in imap_open() in PHP and other products, launches an rsh command (by means of the imap_rimap function…"
    },
    {
      "cve": "CVE-2018-19396",
      "sev": "high",
      "kev": false,
      "title": "ext/standard/var_unserializer.c in PHP 5.x through 7.1.24 allows attackers to cause a…",
      "ranges": [
        {
          "gte": "5.0.0",
          "lte": "7.1.24"
        }
      ],
      "note": "NVD: ext/standard/var_unserializer.c in PHP 5.x through 7.1.24 allows attackers to cause a denial of service (application crash) via an unserialize call for the com,…"
    },
    {
      "cve": "CVE-2018-19395",
      "sev": "high",
      "kev": false,
      "title": "ext/standard/var.c in PHP 5.x through 7.1.24 on Windows allows attackers to cause a…",
      "ranges": [
        {
          "gte": "5.0.0",
          "lte": "7.1.24"
        }
      ],
      "note": "NVD: ext/standard/var.c in PHP 5.x through 7.1.24 on Windows allows attackers to cause a denial of service (NULL pointer dereference and application crash) because com…"
    },
    {
      "cve": "CVE-2018-15132",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in ext/standard/link_win32.c in PHP before 5.6.37, 7.0.x…",
      "ranges": [
        {
          "lt": "5.6.37"
        },
        {
          "gte": "7.0.0",
          "lt": "7.0.31"
        },
        {
          "gte": "7.1.0",
          "lt": "7.1.20"
        },
        {
          "gte": "7.2.0",
          "lt": "7.2.8"
        }
      ],
      "note": "NVD: An issue was discovered in ext/standard/link_win32.c in PHP before 5.6.37, 7.0.x before 7.0.31, 7.1.x before 7.1.20, and 7.2.x before 7.2.8."
    },
    {
      "cve": "CVE-2018-14884",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in PHP 7.0.x before 7.0.27, 7.1.x before 7.1.13, and 7.2.x…",
      "ranges": [
        {
          "gte": "7.0.0",
          "lt": "7.0.27"
        },
        {
          "gte": "7.1.0",
          "lt": "7.1.13"
        },
        {
          "gte": "7.2.0",
          "lt": "7.2.1"
        }
      ],
      "note": "NVD: An issue was discovered in PHP 7.0.x before 7.0.27, 7.1.x before 7.1.13, and 7.2.x before 7.2.1."
    },
    {
      "cve": "CVE-2018-14883",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in PHP before 5.6.37, 7.0.x before 7.0.31, 7.1.x before…",
      "ranges": [
        {
          "lt": "5.6.37"
        },
        {
          "gte": "7.0.0",
          "lt": "7.0.31"
        },
        {
          "gte": "7.1.0",
          "lt": "7.1.20"
        },
        {
          "gte": "7.2.0",
          "lt": "7.2.8"
        }
      ],
      "note": "NVD: An issue was discovered in PHP before 5.6.37, 7.0.x before 7.0.31, 7.1.x before 7.1.20, and 7.2.x before 7.2.8."
    },
    {
      "cve": "CVE-2018-12882",
      "sev": "critical",
      "kev": false,
      "title": "exif_read_from_impl in ext/exif/exif.c in PHP 7.2.x through 7.2.7 allows attackers to…",
      "ranges": [
        {
          "gte": "7.2.0",
          "lte": "7.2.7"
        }
      ],
      "note": "NVD: exif_read_from_impl in ext/exif/exif.c in PHP 7.2.x through 7.2.7 allows attackers to trigger a use-after-free (in exif_read_from_file) because it closes a stream…"
    },
    {
      "cve": "CVE-2018-10549",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in PHP before 5.6.36, 7.0.x before 7.0.30, 7.1.x before…",
      "ranges": [
        {
          "lt": "5.6.36"
        },
        {
          "gte": "7.0.0",
          "lt": "7.0.30"
        },
        {
          "gte": "7.1.0",
          "lt": "7.1.17"
        },
        {
          "gte": "7.2.0",
          "lt": "7.2.5"
        }
      ],
      "note": "NVD: An issue was discovered in PHP before 5.6.36, 7.0.x before 7.0.30, 7.1.x before 7.1.17, and 7.2.x before 7.2.5."
    },
    {
      "cve": "CVE-2018-10548",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in PHP before 5.6.36, 7.0.x before 7.0.30, 7.1.x before…",
      "ranges": [
        {
          "lt": "5.6.36"
        },
        {
          "gte": "7.0.0",
          "lt": "7.0.30"
        },
        {
          "gte": "7.1.0",
          "lt": "7.1.17"
        },
        {
          "gte": "7.2.0",
          "lt": "7.2.5"
        }
      ],
      "note": "NVD: An issue was discovered in PHP before 5.6.36, 7.0.x before 7.0.30, 7.1.x before 7.1.17, and 7.2.x before 7.2.5."
    },
    {
      "cve": "CVE-2018-10546",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in PHP before 5.6.36, 7.0.x before 7.0.30, 7.1.x before…",
      "ranges": [
        {
          "lt": "5.6.36"
        },
        {
          "gte": "7.0.0",
          "lt": "7.0.30"
        },
        {
          "gte": "7.1.0",
          "lt": "7.1.17"
        },
        {
          "gte": "7.2.0",
          "lt": "7.2.5"
        }
      ],
      "note": "NVD: An issue was discovered in PHP before 5.6.36, 7.0.x before 7.0.30, 7.1.x before 7.1.17, and 7.2.x before 7.2.5."
    },
    {
      "cve": "CVE-2018-7584",
      "sev": "critical",
      "kev": false,
      "title": "In PHP through 5.6.33, 7.0.x before 7.0.28, 7.1.x through 7.1.14, and 7.2.x through…",
      "ranges": [
        {
          "lte": "5.6.33"
        },
        {
          "gte": "7.0.0",
          "lt": "7.0.28"
        },
        {
          "gte": "7.1.0",
          "lte": "7.1.14"
        },
        {
          "gte": "7.2.0",
          "lte": "7.2.2"
        }
      ],
      "note": "NVD: In PHP through 5.6.33, 7.0.x before 7.0.28, 7.1.x through 7.1.14, and 7.2.x through 7.2.2, there is a stack-based buffer under-read while parsing an HTTP response…"
    },
    {
      "cve": "CVE-2017-16642",
      "sev": "high",
      "kev": false,
      "title": "In PHP before 5.6.32, 7.x before 7.0.25, and 7.1.x before 7.1.11, an error in the date…",
      "ranges": [
        {
          "lt": "5.6.32"
        },
        {
          "gte": "7.0.0",
          "lt": "7.0.25"
        },
        {
          "gte": "7.1.0",
          "lt": "7.1.11"
        }
      ],
      "note": "NVD: In PHP before 5.6.32, 7.x before 7.0.25, and 7.1.x before 7.1.11, an error in the date extension's timelib_meridian handling of 'front of' and 'back of' directives…"
    },
    {
      "cve": "CVE-2017-12934",
      "sev": "high",
      "kev": false,
      "title": "ext/standard/var_unserializer.re in PHP 7.0.x before 7.0.21 and 7.1.x before 7.1.7 is…",
      "ranges": [
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        },
        {
          "eq": "7.0.2"
        },
        {
          "eq": "7.0.3"
        },
        {
          "eq": "7.0.4"
        },
        {
          "eq": "7.0.5"
        },
        {
          "eq": "7.0.6"
        },
        {
          "eq": "7.0.7"
        },
        {
          "eq": "7.0.8"
        },
        {
          "eq": "7.0.9"
        },
        {
          "eq": "7.0.10"
        },
        {
          "eq": "7.0.11"
        },
        {
          "eq": "7.0.12"
        },
        {
          "eq": "7.0.13"
        },
        {
          "eq": "7.0.14"
        },
        {
          "eq": "7.0.15"
        },
        {
          "eq": "7.0.16"
        },
        {
          "eq": "7.0.17"
        },
        {
          "eq": "7.0.18"
        },
        {
          "eq": "7.0.19"
        },
        {
          "eq": "7.0.20"
        },
        {
          "eq": "7.1.0"
        },
        {
          "eq": "7.1.1"
        },
        {
          "eq": "7.1.2"
        },
        {
          "eq": "7.1.3"
        },
        {
          "eq": "7.1.4"
        },
        {
          "eq": "7.1.5"
        },
        {
          "eq": "7.1.6"
        }
      ],
      "note": "NVD: ext/standard/var_unserializer.re in PHP 7.0.x before 7.0.21 and 7.1.x before 7.1.7 is prone to a heap use after free while unserializing untrusted data, related to…"
    },
    {
      "cve": "CVE-2017-12933",
      "sev": "critical",
      "kev": false,
      "title": "The finish_nested_data function in ext/standard/var_unserializer.re in PHP before…",
      "ranges": [
        {
          "lte": "5.6.30"
        },
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        },
        {
          "eq": "7.0.2"
        },
        {
          "eq": "7.0.3"
        },
        {
          "eq": "7.0.4"
        },
        {
          "eq": "7.0.5"
        },
        {
          "eq": "7.0.6"
        },
        {
          "eq": "7.0.7"
        },
        {
          "eq": "7.0.8"
        },
        {
          "eq": "7.0.9"
        },
        {
          "eq": "7.0.10"
        },
        {
          "eq": "7.0.11"
        },
        {
          "eq": "7.0.12"
        },
        {
          "eq": "7.0.13"
        },
        {
          "eq": "7.0.14"
        },
        {
          "eq": "7.0.15"
        },
        {
          "eq": "7.0.16"
        },
        {
          "eq": "7.0.17"
        },
        {
          "eq": "7.0.18"
        },
        {
          "eq": "7.0.19"
        },
        {
          "eq": "7.0.20"
        },
        {
          "eq": "7.1.0"
        },
        {
          "eq": "7.1.1"
        },
        {
          "eq": "7.1.2"
        },
        {
          "eq": "7.1.3"
        },
        {
          "eq": "7.1.4"
        },
        {
          "eq": "7.1.5"
        },
        {
          "eq": "7.1.6"
        }
      ],
      "note": "NVD: The finish_nested_data function in ext/standard/var_unserializer.re in PHP before 5.6.31, 7.0.x before 7.0.21, and 7.1.x before 7.1.7 is prone to a buffer…"
    },
    {
      "cve": "CVE-2017-12932",
      "sev": "critical",
      "kev": false,
      "title": "ext/standard/var_unserializer.re in PHP 7.0.x through 7.0.22 and 7.1.x through 7.1.8…",
      "ranges": [
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        },
        {
          "eq": "7.0.2"
        },
        {
          "eq": "7.0.3"
        },
        {
          "eq": "7.0.4"
        },
        {
          "eq": "7.0.5"
        },
        {
          "eq": "7.0.6"
        },
        {
          "eq": "7.0.7"
        },
        {
          "eq": "7.0.8"
        },
        {
          "eq": "7.0.9"
        },
        {
          "eq": "7.0.10"
        },
        {
          "eq": "7.0.11"
        },
        {
          "eq": "7.0.12"
        },
        {
          "eq": "7.0.13"
        },
        {
          "eq": "7.0.14"
        },
        {
          "eq": "7.0.15"
        },
        {
          "eq": "7.0.16"
        },
        {
          "eq": "7.0.17"
        },
        {
          "eq": "7.0.18"
        },
        {
          "eq": "7.0.19"
        },
        {
          "eq": "7.0.20"
        },
        {
          "eq": "7.0.21"
        },
        {
          "eq": "7.0.22"
        },
        {
          "eq": "7.1.0"
        },
        {
          "eq": "7.1.1"
        },
        {
          "eq": "7.1.2"
        },
        {
          "eq": "7.1.3"
        },
        {
          "eq": "7.1.4"
        },
        {
          "eq": "7.1.5"
        },
        {
          "eq": "7.1.6"
        },
        {
          "eq": "7.1.7"
        },
        {
          "eq": "7.1.8"
        }
      ],
      "note": "NVD: ext/standard/var_unserializer.re in PHP 7.0.x through 7.0.22 and 7.1.x through 7.1.8 is prone to a heap use after free while unserializing untrusted data, related…"
    },
    {
      "cve": "CVE-2017-11628",
      "sev": "high",
      "kev": false,
      "title": "In PHP before 5.6.31, 7.x before 7.0.21, and 7.1.x before 7.1.7, a stack-based buffer…",
      "ranges": [
        {
          "lte": "5.6.30"
        },
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        },
        {
          "eq": "7.0.2"
        },
        {
          "eq": "7.0.3"
        },
        {
          "eq": "7.0.4"
        },
        {
          "eq": "7.0.5"
        },
        {
          "eq": "7.0.6"
        },
        {
          "eq": "7.0.7"
        },
        {
          "eq": "7.0.8"
        },
        {
          "eq": "7.0.9"
        },
        {
          "eq": "7.0.10"
        },
        {
          "eq": "7.0.11"
        },
        {
          "eq": "7.0.12"
        },
        {
          "eq": "7.0.13"
        },
        {
          "eq": "7.0.14"
        },
        {
          "eq": "7.0.15"
        },
        {
          "eq": "7.0.16"
        },
        {
          "eq": "7.0.17"
        },
        {
          "eq": "7.0.18"
        },
        {
          "eq": "7.0.19"
        },
        {
          "eq": "7.0.20"
        },
        {
          "eq": "7.1.0"
        },
        {
          "eq": "7.1.1"
        },
        {
          "eq": "7.1.2"
        },
        {
          "eq": "7.1.3"
        },
        {
          "eq": "7.1.4"
        },
        {
          "eq": "7.1.5"
        },
        {
          "eq": "7.1.6"
        }
      ],
      "note": "NVD: In PHP before 5.6.31, 7.x before 7.0.21, and 7.1.x before 7.1.7, a stack-based buffer overflow in the zend_ini_do_op() function in Zend/zend_ini_parser.c could…"
    },
    {
      "cve": "CVE-2017-11362",
      "sev": "critical",
      "kev": false,
      "title": "In PHP 7.x before 7.0.21 and 7.1.x before 7.1.7, ext/intl/msgformat/msgformat_parse.c…",
      "ranges": [
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        },
        {
          "eq": "7.0.2"
        },
        {
          "eq": "7.0.3"
        },
        {
          "eq": "7.0.4"
        },
        {
          "eq": "7.0.5"
        },
        {
          "eq": "7.0.6"
        },
        {
          "eq": "7.0.7"
        },
        {
          "eq": "7.0.8"
        },
        {
          "eq": "7.0.9"
        },
        {
          "eq": "7.0.10"
        },
        {
          "eq": "7.0.11"
        },
        {
          "eq": "7.0.12"
        },
        {
          "eq": "7.0.13"
        },
        {
          "eq": "7.0.14"
        },
        {
          "eq": "7.0.15"
        },
        {
          "eq": "7.0.16"
        },
        {
          "eq": "7.0.17"
        },
        {
          "eq": "7.0.18"
        },
        {
          "eq": "7.0.19"
        },
        {
          "eq": "7.0.20"
        },
        {
          "eq": "7.1.0"
        },
        {
          "eq": "7.1.1"
        },
        {
          "eq": "7.1.2"
        },
        {
          "eq": "7.1.3"
        },
        {
          "eq": "7.1.4"
        },
        {
          "eq": "7.1.5"
        },
        {
          "eq": "7.1.6"
        }
      ],
      "note": "NVD: In PHP 7.x before 7.0.21 and 7.1.x before 7.1.7, ext/intl/msgformat/msgformat_parse.c does not restrict the locale length, which allows remote attackers to cause a…"
    },
    {
      "cve": "CVE-2017-11147",
      "sev": "critical",
      "kev": false,
      "title": "In PHP before 5.6.30 and 7.x before 7.0.15, the PHAR archive handler could be used by…",
      "ranges": [
        {
          "lt": "5.6.30"
        },
        {
          "gte": "7.0.0",
          "lt": "7.0.15"
        },
        {
          "gte": "7.1.0",
          "lt": "7.1.1"
        }
      ],
      "note": "NVD: In PHP before 5.6.30 and 7.x before 7.0.15, the PHAR archive handler could be used by attackers supplying malicious archive files to crash the PHP interpreter or…"
    },
    {
      "cve": "CVE-2017-11145",
      "sev": "high",
      "kev": false,
      "title": "In PHP before 5.6.31, 7.x before 7.0.21, and 7.1.x before 7.1.7, an error in the date…",
      "ranges": [
        {
          "lte": "5.6.30"
        },
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        },
        {
          "eq": "7.0.2"
        },
        {
          "eq": "7.0.3"
        },
        {
          "eq": "7.0.4"
        },
        {
          "eq": "7.0.5"
        },
        {
          "eq": "7.0.6"
        },
        {
          "eq": "7.0.7"
        },
        {
          "eq": "7.0.8"
        },
        {
          "eq": "7.0.9"
        },
        {
          "eq": "7.0.10"
        },
        {
          "eq": "7.0.11"
        },
        {
          "eq": "7.0.12"
        },
        {
          "eq": "7.0.13"
        },
        {
          "eq": "7.0.14"
        },
        {
          "eq": "7.0.15"
        },
        {
          "eq": "7.0.16"
        },
        {
          "eq": "7.0.17"
        },
        {
          "eq": "7.0.18"
        },
        {
          "eq": "7.0.19"
        },
        {
          "eq": "7.0.20"
        },
        {
          "eq": "7.1.0"
        },
        {
          "eq": "7.1.1"
        },
        {
          "eq": "7.1.2"
        },
        {
          "eq": "7.1.3"
        },
        {
          "eq": "7.1.4"
        },
        {
          "eq": "7.1.5"
        },
        {
          "eq": "7.1.6"
        }
      ],
      "note": "NVD: In PHP before 5.6.31, 7.x before 7.0.21, and 7.1.x before 7.1.7, an error in the date extension's timelib_meridian parsing code could be used by attackers able to…"
    },
    {
      "cve": "CVE-2017-11144",
      "sev": "high",
      "kev": false,
      "title": "In PHP before 5.6.31, 7.x before 7.0.21, and 7.1.x before 7.1.7, the openssl extension…",
      "ranges": [
        {
          "lte": "5.6.30"
        },
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        },
        {
          "eq": "7.0.2"
        },
        {
          "eq": "7.0.3"
        },
        {
          "eq": "7.0.4"
        },
        {
          "eq": "7.0.5"
        },
        {
          "eq": "7.0.6"
        },
        {
          "eq": "7.0.7"
        },
        {
          "eq": "7.0.8"
        },
        {
          "eq": "7.0.9"
        },
        {
          "eq": "7.0.10"
        },
        {
          "eq": "7.0.11"
        },
        {
          "eq": "7.0.12"
        },
        {
          "eq": "7.0.13"
        },
        {
          "eq": "7.0.14"
        },
        {
          "eq": "7.0.15"
        },
        {
          "eq": "7.0.16"
        },
        {
          "eq": "7.0.17"
        },
        {
          "eq": "7.0.18"
        },
        {
          "eq": "7.0.19"
        },
        {
          "eq": "7.0.20"
        },
        {
          "eq": "7.1.0"
        },
        {
          "eq": "7.1.1"
        },
        {
          "eq": "7.1.2"
        },
        {
          "eq": "7.1.3"
        },
        {
          "eq": "7.1.4"
        },
        {
          "eq": "7.1.5"
        },
        {
          "eq": "7.1.6"
        }
      ],
      "note": "NVD: In PHP before 5.6.31, 7.x before 7.0.21, and 7.1.x before 7.1.7, the openssl extension PEM sealing code did not check the return value of the OpenSSL sealing…"
    },
    {
      "cve": "CVE-2017-11143",
      "sev": "high",
      "kev": false,
      "title": "In PHP before 5.6.31, an invalid free in the WDDX deserialization of boolean…",
      "ranges": [
        {
          "lte": "5.6.30"
        }
      ],
      "note": "NVD: In PHP before 5.6.31, an invalid free in the WDDX deserialization of boolean parameters could be used by attackers able to inject XML for deserialization to crash…"
    },
    {
      "cve": "CVE-2017-11142",
      "sev": "high",
      "kev": false,
      "title": "In PHP before 5.6.31, 7.x before 7.0.17, and 7.1.x before 7.1.3, remote attackers…",
      "ranges": [
        {
          "lte": "5.6.30"
        },
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        },
        {
          "eq": "7.0.2"
        },
        {
          "eq": "7.0.3"
        },
        {
          "eq": "7.0.4"
        },
        {
          "eq": "7.0.5"
        },
        {
          "eq": "7.0.6"
        },
        {
          "eq": "7.0.7"
        },
        {
          "eq": "7.0.8"
        },
        {
          "eq": "7.0.9"
        },
        {
          "eq": "7.0.10"
        },
        {
          "eq": "7.0.11"
        },
        {
          "eq": "7.0.12"
        },
        {
          "eq": "7.0.13"
        },
        {
          "eq": "7.0.14"
        },
        {
          "eq": "7.0.15"
        },
        {
          "eq": "7.0.16"
        },
        {
          "eq": "7.1.0"
        },
        {
          "eq": "7.1.1"
        },
        {
          "eq": "7.1.2"
        }
      ],
      "note": "NVD: In PHP before 5.6.31, 7.x before 7.0.17, and 7.1.x before 7.1.3, remote attackers could cause a CPU consumption denial of service attack by injecting long form…"
    },
    {
      "cve": "CVE-2017-9229",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in Oniguruma 6.2.0, as used in Oniguruma-mod in Ruby through…",
      "ranges": [
        {
          "lte": "7.1.5"
        },
        {
          "gte": "5.6.0",
          "lt": "5.6.31"
        },
        {
          "gte": "7.0.0",
          "lt": "7.0.21"
        },
        {
          "gte": "7.1.0",
          "lt": "7.1.7"
        }
      ],
      "note": "NVD: An issue was discovered in Oniguruma 6.2.0, as used in Oniguruma-mod in Ruby through 2.4.1 and mbstring in PHP through 7.1.5."
    },
    {
      "cve": "CVE-2017-9228",
      "sev": "critical",
      "kev": false,
      "title": "An issue was discovered in Oniguruma 6.2.0, as used in Oniguruma-mod in Ruby through…",
      "ranges": [
        {
          "gte": "5.6.0",
          "lt": "5.6.31"
        },
        {
          "gte": "7.0.0",
          "lt": "7.0.21"
        },
        {
          "gte": "7.1.0",
          "lt": "7.1.7"
        }
      ],
      "note": "NVD: An issue was discovered in Oniguruma 6.2.0, as used in Oniguruma-mod in Ruby through 2.4.1 and mbstring in PHP through 7.1.5."
    },
    {
      "cve": "CVE-2017-9227",
      "sev": "critical",
      "kev": false,
      "title": "An issue was discovered in Oniguruma 6.2.0, as used in Oniguruma-mod in Ruby through…",
      "ranges": [
        {
          "gte": "5.6.0",
          "lt": "5.6.31"
        },
        {
          "gte": "7.0.0",
          "lt": "7.0.21"
        },
        {
          "gte": "7.1.0",
          "lt": "7.1.7"
        }
      ],
      "note": "NVD: An issue was discovered in Oniguruma 6.2.0, as used in Oniguruma-mod in Ruby through 2.4.1 and mbstring in PHP through 7.1.5."
    },
    {
      "cve": "CVE-2017-9226",
      "sev": "critical",
      "kev": false,
      "title": "An issue was discovered in Oniguruma 6.2.0, as used in Oniguruma-mod in Ruby through…",
      "ranges": [
        {
          "lt": "5.6.31"
        },
        {
          "gte": "7.0.0",
          "lt": "7.0.21"
        },
        {
          "gte": "7.1.0",
          "lt": "7.1.7"
        }
      ],
      "note": "NVD: An issue was discovered in Oniguruma 6.2.0, as used in Oniguruma-mod in Ruby through 2.4.1 and mbstring in PHP through 7.1.5."
    },
    {
      "cve": "CVE-2017-9225",
      "sev": "critical",
      "kev": false,
      "title": "An issue was discovered in Oniguruma 6.2.0, as used in Oniguruma-mod in Ruby through…",
      "ranges": [
        {
          "lte": "7.1.5"
        }
      ],
      "note": "NVD: An issue was discovered in Oniguruma 6.2.0, as used in Oniguruma-mod in Ruby through 2.4.1 and mbstring in PHP through 7.1.5."
    },
    {
      "cve": "CVE-2017-9224",
      "sev": "critical",
      "kev": false,
      "title": "An issue was discovered in Oniguruma 6.2.0, as used in Oniguruma-mod in Ruby through…",
      "ranges": [
        {
          "lt": "5.6.31"
        },
        {
          "gte": "7.0.0",
          "lt": "7.0.21"
        },
        {
          "gte": "7.1.0",
          "lt": "7.1.7"
        }
      ],
      "note": "NVD: An issue was discovered in Oniguruma 6.2.0, as used in Oniguruma-mod in Ruby through 2.4.1 and mbstring in PHP through 7.1.5."
    },
    {
      "cve": "CVE-2017-9120",
      "sev": "critical",
      "kev": false,
      "title": "PHP 7.x through 7.1.5 allows remote attackers to cause a denial of service (buffer…",
      "ranges": [
        {
          "gte": "7.0.0",
          "lte": "7.1.5"
        },
        {
          "gte": "7.4.0",
          "lt": "7.4.23"
        },
        {
          "gte": "8.0.0",
          "lt": "8.0.10"
        }
      ],
      "note": "NVD: PHP 7.x through 7.1.5 allows remote attackers to cause a denial of service (buffer overflow and application crash) or possibly have unspecified other impact via a…"
    },
    {
      "cve": "CVE-2017-9119",
      "sev": "critical",
      "kev": false,
      "title": "The i_zval_ptr_dtor function in Zend/zend_variables.h in PHP 7.1.5 allows attackers to…",
      "ranges": [
        {
          "eq": "7.1.5"
        }
      ],
      "note": "NVD: The i_zval_ptr_dtor function in Zend/zend_variables.h in PHP 7.1.5 allows attackers to cause a denial of service (memory consumption and application crash) or…"
    },
    {
      "cve": "CVE-2017-9118",
      "sev": "high",
      "kev": false,
      "title": "PHP 7.1.5 has an Out of bounds access in php_pcre_replace_impl via a crafted…",
      "ranges": [
        {
          "gte": "7.4.0",
          "lt": "7.4.27"
        },
        {
          "gte": "8.0.0",
          "lt": "8.0.14"
        },
        {
          "gte": "8.1.0",
          "lt": "8.1.1"
        },
        {
          "eq": "7.1.5"
        }
      ],
      "note": "NVD: PHP 7.1.5 has an Out of bounds access in php_pcre_replace_impl via a crafted preg_replace call."
    },
    {
      "cve": "CVE-2017-9067",
      "sev": "high",
      "kev": false,
      "title": "In MODX Revolution before 2.5.7, when PHP 5.3.3 is used, an attacker is able to…",
      "ranges": [
        {
          "eq": "5.3.3"
        }
      ],
      "note": "NVD: In MODX Revolution before 2.5.7, when PHP 5.3.3 is used, an attacker is able to include and execute arbitrary files on the web server due to insufficient…"
    },
    {
      "cve": "CVE-2017-8923",
      "sev": "critical",
      "kev": false,
      "title": "The zend_string_extend function in Zend/zend_string.h in PHP through 7.1.5 does not…",
      "ranges": [
        {
          "lt": "7.4.24"
        },
        {
          "gte": "8.0.0",
          "lt": "8.0.11"
        }
      ],
      "note": "NVD: The zend_string_extend function in Zend/zend_string.h in PHP through 7.1.5 does not prevent changes to string objects that result in a negative length, which…"
    },
    {
      "cve": "CVE-2017-7963",
      "sev": "high",
      "kev": false,
      "title": "The GNU Multiple Precision Arithmetic Library (GMP) interfaces for PHP through 7.1.4…",
      "ranges": [
        {
          "lte": "7.1.4"
        }
      ],
      "note": "NVD: The GNU Multiple Precision Arithmetic Library (GMP) interfaces for PHP through 7.1.4 allow attackers to cause a denial of service (memory consumption and…"
    },
    {
      "cve": "CVE-2017-7272",
      "sev": "high",
      "kev": false,
      "title": "PHP through 7.1.11 enables potential SSRF in applications that accept an fsockopen or…",
      "ranges": [
        {
          "lte": "7.1.3"
        }
      ],
      "note": "NVD: PHP through 7.1.11 enables potential SSRF in applications that accept an fsockopen or pfsockopen hostname argument with an expectation that the port number is…"
    },
    {
      "cve": "CVE-2017-7189",
      "sev": "high",
      "kev": false,
      "title": "main/streams/xp_socket.c in PHP 7.x before 2017-03-07 misparses fsockopen calls, such…",
      "ranges": [
        {
          "gte": "7.0.0",
          "lt": "7.0.16"
        }
      ],
      "note": "NVD: main/streams/xp_socket.c in PHP 7.x before 2017-03-07 misparses fsockopen calls, such as by interpreting fsockopen('127.0.0.1:80', 443) as if the address/port were…"
    },
    {
      "cve": "CVE-2017-6441",
      "sev": "high",
      "kev": false,
      "title": "The _zval_get_long_func_ex in Zend/zend_operators.c in PHP 7.1.2 allows attackers to…",
      "ranges": [
        {
          "eq": "7.1.2"
        }
      ],
      "note": "NVD: The _zval_get_long_func_ex in Zend/zend_operators.c in PHP 7.1.2 allows attackers to cause a denial of service (NULL pointer dereference and application crash) via…"
    },
    {
      "cve": "CVE-2017-5340",
      "sev": "critical",
      "kev": false,
      "title": "Zend/zend_hash.c in PHP before 7.0.15 and 7.1.x before 7.1.1 mishandles certain cases…",
      "ranges": [
        {
          "gte": "7.0.0",
          "lt": "7.0.15"
        },
        {
          "gte": "7.1.0",
          "lt": "7.1.1"
        }
      ],
      "note": "NVD: Zend/zend_hash.c in PHP before 7.0.15 and 7.1.x before 7.1.1 mishandles certain cases that require large array allocations, which allows remote attackers to…"
    },
    {
      "cve": "CVE-2016-10712",
      "sev": "high",
      "kev": false,
      "title": "In PHP before 5.5.32, 5.6.x before 5.6.18, and 7.x before 7.0.3, all of the return…",
      "ranges": [
        {
          "lte": "5.5.31"
        },
        {
          "gte": "5.6.0",
          "lte": "5.6.17"
        },
        {
          "gte": "7.0.0",
          "lte": "7.0.2"
        }
      ],
      "note": "NVD: In PHP before 5.5.32, 5.6.x before 5.6.18, and 7.x before 7.0.3, all of the return values of stream_get_meta_data can be controlled if the input can be controlled…"
    },
    {
      "cve": "CVE-2016-10397",
      "sev": "high",
      "kev": false,
      "title": "In PHP before 5.6.28 and 7.x before 7.0.13, incorrect handling of various URI…",
      "ranges": [
        {
          "lte": "5.6.27"
        },
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        },
        {
          "eq": "7.0.2"
        },
        {
          "eq": "7.0.3"
        },
        {
          "eq": "7.0.4"
        },
        {
          "eq": "7.0.5"
        },
        {
          "eq": "7.0.6"
        },
        {
          "eq": "7.0.7"
        },
        {
          "eq": "7.0.8"
        },
        {
          "eq": "7.0.9"
        },
        {
          "eq": "7.0.10"
        },
        {
          "eq": "7.0.11"
        },
        {
          "eq": "7.0.12"
        }
      ],
      "note": "NVD: In PHP before 5.6.28 and 7.x before 7.0.13, incorrect handling of various URI components in the URL parser could be used by attackers to bypass hostname-specific…"
    },
    {
      "cve": "CVE-2016-10162",
      "sev": "high",
      "kev": false,
      "title": "The php_wddx_pop_element function in ext/wddx/wddx.c in PHP 7.0.x before 7.0.15 and…",
      "ranges": [
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        },
        {
          "eq": "7.0.2"
        },
        {
          "eq": "7.0.3"
        },
        {
          "eq": "7.0.4"
        },
        {
          "eq": "7.0.5"
        },
        {
          "eq": "7.0.6"
        },
        {
          "eq": "7.0.7"
        },
        {
          "eq": "7.0.8"
        },
        {
          "eq": "7.0.9"
        },
        {
          "eq": "7.0.10"
        },
        {
          "eq": "7.0.11"
        },
        {
          "eq": "7.0.12"
        },
        {
          "eq": "7.0.13"
        },
        {
          "eq": "7.0.14"
        },
        {
          "eq": "7.1.0"
        }
      ],
      "note": "NVD: The php_wddx_pop_element function in ext/wddx/wddx.c in PHP 7.0.x before 7.0.15 and 7.1.x before 7.1.1 allows remote attackers to cause a denial of service (NULL…"
    },
    {
      "cve": "CVE-2016-10161",
      "sev": "high",
      "kev": false,
      "title": "The object_common1 function in ext/standard/var_unserializer.c in PHP before 5.6.30,…",
      "ranges": [
        {
          "lte": "5.6.29"
        },
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        },
        {
          "eq": "7.0.2"
        },
        {
          "eq": "7.0.3"
        },
        {
          "eq": "7.0.4"
        },
        {
          "eq": "7.0.5"
        },
        {
          "eq": "7.0.6"
        },
        {
          "eq": "7.0.7"
        },
        {
          "eq": "7.0.8"
        },
        {
          "eq": "7.0.9"
        },
        {
          "eq": "7.0.10"
        },
        {
          "eq": "7.0.11"
        },
        {
          "eq": "7.0.12"
        },
        {
          "eq": "7.0.13"
        },
        {
          "eq": "7.0.14"
        },
        {
          "eq": "7.1.0"
        }
      ],
      "note": "NVD: The object_common1 function in ext/standard/var_unserializer.c in PHP before 5.6.30, 7.0.x before 7.0.15, and 7.1.x before 7.1.1 allows remote attackers to cause a…"
    },
    {
      "cve": "CVE-2016-10160",
      "sev": "critical",
      "kev": false,
      "title": "Off-by-one error in the phar_parse_pharfile function in ext/phar/phar.c in PHP before…",
      "ranges": [
        {
          "gte": "5.6.0",
          "lt": "5.6.30"
        },
        {
          "gte": "7.0.0",
          "lt": "7.0.15"
        },
        {
          "gte": "7.1.0",
          "lt": "7.1.1"
        }
      ],
      "note": "NVD: Off-by-one error in the phar_parse_pharfile function in ext/phar/phar.c in PHP before 5.6.30 and 7.0.x before 7.0.15 allows remote attackers to cause a denial of…"
    },
    {
      "cve": "CVE-2016-10159",
      "sev": "high",
      "kev": false,
      "title": "Integer overflow in the phar_parse_pharfile function in ext/phar/phar.c in PHP before…",
      "ranges": [
        {
          "lte": "5.6.29"
        },
        {
          "gte": "7.0.0",
          "lt": "7.0.15"
        },
        {
          "eq": "7.1.0"
        }
      ],
      "note": "NVD: Integer overflow in the phar_parse_pharfile function in ext/phar/phar.c in PHP before 5.6.30 and 7.0.x before 7.0.15 allows remote attackers to cause a denial of…"
    },
    {
      "cve": "CVE-2016-10158",
      "sev": "high",
      "kev": false,
      "title": "The exif_convert_any_to_int function in ext/exif/exif.c in PHP before 5.6.30, 7.0.x…",
      "ranges": [
        {
          "lte": "5.6.29"
        },
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        },
        {
          "eq": "7.0.2"
        },
        {
          "eq": "7.0.3"
        },
        {
          "eq": "7.0.4"
        },
        {
          "eq": "7.0.5"
        },
        {
          "eq": "7.0.6"
        },
        {
          "eq": "7.0.7"
        },
        {
          "eq": "7.0.8"
        },
        {
          "eq": "7.0.9"
        },
        {
          "eq": "7.0.10"
        },
        {
          "eq": "7.0.11"
        },
        {
          "eq": "7.0.12"
        },
        {
          "eq": "7.0.13"
        },
        {
          "eq": "7.0.14"
        },
        {
          "eq": "7.1.0"
        }
      ],
      "note": "NVD: The exif_convert_any_to_int function in ext/exif/exif.c in PHP before 5.6.30, 7.0.x before 7.0.15, and 7.1.x before 7.1.1 allows remote attackers to cause a denial…"
    },
    {
      "cve": "CVE-2016-9936",
      "sev": "critical",
      "kev": false,
      "title": "The unserialize implementation in ext/standard/var.c in PHP 7.x before 7.0.14 allows…",
      "ranges": [
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        },
        {
          "eq": "7.0.2"
        },
        {
          "eq": "7.0.3"
        },
        {
          "eq": "7.0.4"
        },
        {
          "eq": "7.0.5"
        },
        {
          "eq": "7.0.6"
        },
        {
          "eq": "7.0.7"
        },
        {
          "eq": "7.0.8"
        },
        {
          "eq": "7.0.9"
        },
        {
          "eq": "7.0.10"
        },
        {
          "eq": "7.0.11"
        },
        {
          "eq": "7.0.12"
        },
        {
          "eq": "7.0.13"
        }
      ],
      "note": "NVD: The unserialize implementation in ext/standard/var.c in PHP 7.x before 7.0.14 allows remote attackers to cause a denial of service (use-after-free) or possibly…"
    },
    {
      "cve": "CVE-2016-9935",
      "sev": "critical",
      "kev": false,
      "title": "The php_wddx_push_element function in ext/wddx/wddx.c in PHP before 5.6.29 and 7.x…",
      "ranges": [
        {
          "lte": "5.6.28"
        },
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        },
        {
          "eq": "7.0.2"
        },
        {
          "eq": "7.0.3"
        },
        {
          "eq": "7.0.4"
        },
        {
          "eq": "7.0.5"
        },
        {
          "eq": "7.0.6"
        },
        {
          "eq": "7.0.7"
        },
        {
          "eq": "7.0.8"
        },
        {
          "eq": "7.0.9"
        },
        {
          "eq": "7.0.10"
        },
        {
          "eq": "7.0.11"
        },
        {
          "eq": "7.0.12"
        },
        {
          "eq": "7.0.13"
        }
      ],
      "note": "NVD: The php_wddx_push_element function in ext/wddx/wddx.c in PHP before 5.6.29 and 7.x before 7.0.14 allows remote attackers to cause a denial of service…"
    },
    {
      "cve": "CVE-2016-9934",
      "sev": "high",
      "kev": false,
      "title": "ext/wddx/wddx.c in PHP before 5.6.28 and 7.x before 7.0.13 allows remote attackers to…",
      "ranges": [
        {
          "lte": "5.6.27"
        },
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        },
        {
          "eq": "7.0.2"
        },
        {
          "eq": "7.0.3"
        },
        {
          "eq": "7.0.4"
        },
        {
          "eq": "7.0.5"
        },
        {
          "eq": "7.0.6"
        },
        {
          "eq": "7.0.7"
        },
        {
          "eq": "7.0.8"
        },
        {
          "eq": "7.0.9"
        },
        {
          "eq": "7.0.10"
        },
        {
          "eq": "7.0.11"
        },
        {
          "eq": "7.0.12"
        }
      ],
      "note": "NVD: ext/wddx/wddx.c in PHP before 5.6.28 and 7.x before 7.0.13 allows remote attackers to cause a denial of service (NULL pointer dereference) via crafted serialized…"
    },
    {
      "cve": "CVE-2016-9138",
      "sev": "critical",
      "kev": false,
      "title": "PHP through 5.6.27 and 7.x through 7.0.12 mishandles property modification during…",
      "ranges": [
        {
          "lte": "5.6.27"
        },
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        },
        {
          "eq": "7.0.2"
        },
        {
          "eq": "7.0.3"
        },
        {
          "eq": "7.0.4"
        },
        {
          "eq": "7.0.5"
        },
        {
          "eq": "7.0.6"
        },
        {
          "eq": "7.0.7"
        },
        {
          "eq": "7.0.8"
        },
        {
          "eq": "7.0.9"
        },
        {
          "eq": "7.0.10"
        },
        {
          "eq": "7.0.11"
        },
        {
          "eq": "7.0.12"
        }
      ],
      "note": "NVD: PHP through 5.6.27 and 7.x through 7.0.12 mishandles property modification during __wakeup processing, which allows remote attackers to cause a denial of service…"
    },
    {
      "cve": "CVE-2016-9137",
      "sev": "critical",
      "kev": false,
      "title": "Use-after-free vulnerability in the CURLFile implementation in ext/curl/curl_file.c in…",
      "ranges": [
        {
          "lte": "5.6.26"
        },
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        },
        {
          "eq": "7.0.2"
        },
        {
          "eq": "7.0.3"
        },
        {
          "eq": "7.0.4"
        },
        {
          "eq": "7.0.5"
        },
        {
          "eq": "7.0.6"
        },
        {
          "eq": "7.0.7"
        },
        {
          "eq": "7.0.8"
        },
        {
          "eq": "7.0.9"
        },
        {
          "eq": "7.0.10"
        },
        {
          "eq": "7.0.11"
        }
      ],
      "note": "NVD: Use-after-free vulnerability in the CURLFile implementation in ext/curl/curl_file.c in PHP before 5.6.27 and 7.x before 7.0.12 allows remote attackers to cause a…"
    },
    {
      "cve": "CVE-2016-7568",
      "sev": "critical",
      "kev": false,
      "title": "Integer overflow in the gdImageWebpCtx function in gd_webp.c in the GD Graphics…",
      "ranges": [
        {
          "gte": "5.6.0",
          "lte": "5.6.26"
        },
        {
          "gte": "7.0.0",
          "lte": "7.0.11"
        }
      ],
      "note": "NVD: Integer overflow in the gdImageWebpCtx function in gd_webp.c in the GD Graphics Library (aka libgd) through 2.2.3, as used in PHP through 7.0.11, allows remote…"
    },
    {
      "cve": "CVE-2016-7480",
      "sev": "critical",
      "kev": false,
      "title": "The SplObjectStorage unserialize implementation in ext/spl/spl_observer.c in PHP…",
      "ranges": [
        {
          "gte": "7.0.0",
          "lt": "7.0.11"
        }
      ],
      "note": "NVD: The SplObjectStorage unserialize implementation in ext/spl/spl_observer.c in PHP before 7.0.12 does not verify that a key is an object, which allows remote…"
    },
    {
      "cve": "CVE-2016-7479",
      "sev": "critical",
      "kev": false,
      "title": "In all versions of PHP 7, during the unserialization process, resizing the…",
      "ranges": [
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        },
        {
          "eq": "7.0.2"
        },
        {
          "eq": "7.0.3"
        },
        {
          "eq": "7.0.4"
        },
        {
          "eq": "7.0.5"
        },
        {
          "eq": "7.0.6"
        },
        {
          "eq": "7.0.7"
        },
        {
          "eq": "7.0.8"
        },
        {
          "eq": "7.0.9"
        },
        {
          "eq": "7.0.10"
        },
        {
          "eq": "7.0.11"
        },
        {
          "eq": "7.0.12"
        },
        {
          "eq": "7.0.14"
        },
        {
          "eq": "7.1.0"
        }
      ],
      "note": "NVD: In all versions of PHP 7, during the unserialization process, resizing the 'properties' hash table of a serialized object may lead to use-after-free."
    },
    {
      "cve": "CVE-2016-7418",
      "sev": "high",
      "kev": false,
      "title": "The php_wddx_push_element function in ext/wddx/wddx.c in PHP before 5.6.26 and 7.x…",
      "ranges": [
        {
          "lte": "5.6.25"
        },
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        },
        {
          "eq": "7.0.2"
        },
        {
          "eq": "7.0.3"
        },
        {
          "eq": "7.0.4"
        },
        {
          "eq": "7.0.5"
        },
        {
          "eq": "7.0.6"
        },
        {
          "eq": "7.0.7"
        },
        {
          "eq": "7.0.8"
        },
        {
          "eq": "7.0.9"
        },
        {
          "eq": "7.0.10"
        }
      ],
      "note": "NVD: The php_wddx_push_element function in ext/wddx/wddx.c in PHP before 5.6.26 and 7.x before 7.0.11 allows remote attackers to cause a denial of service (invalid…"
    },
    {
      "cve": "CVE-2016-7417",
      "sev": "critical",
      "kev": false,
      "title": "ext/spl/spl_array.c in PHP before 5.6.26 and 7.x before 7.0.11 proceeds with SplArray…",
      "ranges": [
        {
          "lte": "5.6.25"
        },
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        },
        {
          "eq": "7.0.2"
        },
        {
          "eq": "7.0.3"
        },
        {
          "eq": "7.0.4"
        },
        {
          "eq": "7.0.5"
        },
        {
          "eq": "7.0.6"
        },
        {
          "eq": "7.0.7"
        },
        {
          "eq": "7.0.8"
        },
        {
          "eq": "7.0.9"
        },
        {
          "eq": "7.0.10"
        }
      ],
      "note": "NVD: ext/spl/spl_array.c in PHP before 5.6.26 and 7.x before 7.0.11 proceeds with SplArray unserialization without validating a return value and data type, which allows…"
    },
    {
      "cve": "CVE-2016-7416",
      "sev": "high",
      "kev": false,
      "title": "ext/intl/msgformat/msgformat_format.c in PHP before 5.6.26 and 7.x before 7.0.11 does…",
      "ranges": [
        {
          "lte": "5.6.25"
        },
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        },
        {
          "eq": "7.0.2"
        },
        {
          "eq": "7.0.3"
        },
        {
          "eq": "7.0.4"
        },
        {
          "eq": "7.0.5"
        },
        {
          "eq": "7.0.6"
        },
        {
          "eq": "7.0.7"
        },
        {
          "eq": "7.0.8"
        },
        {
          "eq": "7.0.9"
        },
        {
          "eq": "7.0.10"
        }
      ],
      "note": "NVD: ext/intl/msgformat/msgformat_format.c in PHP before 5.6.26 and 7.x before 7.0.11 does not properly restrict the locale length provided to the Locale class in the…"
    },
    {
      "cve": "CVE-2016-7414",
      "sev": "critical",
      "kev": false,
      "title": "The ZIP signature-verification feature in PHP before 5.6.26 and 7.x before 7.0.11 does…",
      "ranges": [
        {
          "lte": "5.6.25"
        },
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        },
        {
          "eq": "7.0.2"
        },
        {
          "eq": "7.0.3"
        },
        {
          "eq": "7.0.4"
        },
        {
          "eq": "7.0.5"
        },
        {
          "eq": "7.0.6"
        },
        {
          "eq": "7.0.7"
        },
        {
          "eq": "7.0.8"
        },
        {
          "eq": "7.0.9"
        },
        {
          "eq": "7.0.10"
        }
      ],
      "note": "NVD: The ZIP signature-verification feature in PHP before 5.6.26 and 7.x before 7.0.11 does not ensure that the uncompressed_filesize field is large enough, which…"
    },
    {
      "cve": "CVE-2016-7413",
      "sev": "critical",
      "kev": false,
      "title": "Use-after-free vulnerability in the wddx_stack_destroy function in ext/wddx/wddx.c in…",
      "ranges": [
        {
          "lte": "5.6.25"
        },
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        },
        {
          "eq": "7.0.2"
        },
        {
          "eq": "7.0.3"
        },
        {
          "eq": "7.0.4"
        },
        {
          "eq": "7.0.5"
        },
        {
          "eq": "7.0.6"
        },
        {
          "eq": "7.0.7"
        },
        {
          "eq": "7.0.8"
        },
        {
          "eq": "7.0.9"
        },
        {
          "eq": "7.0.10"
        }
      ],
      "note": "NVD: Use-after-free vulnerability in the wddx_stack_destroy function in ext/wddx/wddx.c in PHP before 5.6.26 and 7.x before 7.0.11 allows remote attackers to cause a…"
    },
    {
      "cve": "CVE-2016-7412",
      "sev": "high",
      "kev": false,
      "title": "ext/mysqlnd/mysqlnd_wireprotocol.c in PHP before 5.6.26 and 7.x before 7.0.11 does not…",
      "ranges": [
        {
          "lte": "5.6.25"
        },
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        },
        {
          "eq": "7.0.2"
        },
        {
          "eq": "7.0.3"
        },
        {
          "eq": "7.0.4"
        },
        {
          "eq": "7.0.5"
        },
        {
          "eq": "7.0.6"
        },
        {
          "eq": "7.0.7"
        },
        {
          "eq": "7.0.8"
        },
        {
          "eq": "7.0.9"
        },
        {
          "eq": "7.0.10"
        }
      ],
      "note": "NVD: ext/mysqlnd/mysqlnd_wireprotocol.c in PHP before 5.6.26 and 7.x before 7.0.11 does not verify that a BIT field has the UNSIGNED_FLAG flag, which allows remote…"
    },
    {
      "cve": "CVE-2016-7411",
      "sev": "critical",
      "kev": false,
      "title": "ext/standard/var_unserializer.re in PHP before 5.6.26 mishandles…",
      "ranges": [
        {
          "lte": "5.6.25"
        }
      ],
      "note": "NVD: ext/standard/var_unserializer.re in PHP before 5.6.26 mishandles object-deserialization failures, which allows remote attackers to cause a denial of service…"
    },
    {
      "cve": "CVE-2016-7134",
      "sev": "critical",
      "kev": false,
      "title": "ext/curl/interface.c in PHP 7.x before 7.0.10 does not work around a libcurl integer…",
      "ranges": [
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        },
        {
          "eq": "7.0.2"
        },
        {
          "eq": "7.0.3"
        },
        {
          "eq": "7.0.4"
        },
        {
          "eq": "7.0.5"
        },
        {
          "eq": "7.0.6"
        },
        {
          "eq": "7.0.7"
        },
        {
          "eq": "7.0.8"
        },
        {
          "eq": "7.0.9"
        }
      ],
      "note": "NVD: ext/curl/interface.c in PHP 7.x before 7.0.10 does not work around a libcurl integer overflow, which allows remote attackers to cause a denial of service…"
    },
    {
      "cve": "CVE-2016-7133",
      "sev": "high",
      "kev": false,
      "title": "Zend/zend_alloc.c in PHP 7.x before 7.0.10, when open_basedir is enabled, mishandles…",
      "ranges": [
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        },
        {
          "eq": "7.0.2"
        },
        {
          "eq": "7.0.3"
        },
        {
          "eq": "7.0.4"
        },
        {
          "eq": "7.0.5"
        },
        {
          "eq": "7.0.6"
        },
        {
          "eq": "7.0.7"
        },
        {
          "eq": "7.0.8"
        },
        {
          "eq": "7.0.9"
        }
      ],
      "note": "NVD: Zend/zend_alloc.c in PHP 7.x before 7.0.10, when open_basedir is enabled, mishandles huge realloc operations, which allows remote attackers to cause a denial of…"
    },
    {
      "cve": "CVE-2016-7132",
      "sev": "high",
      "kev": false,
      "title": "ext/wddx/wddx.c in PHP before 5.6.25 and 7.x before 7.0.10 allows remote attackers to…",
      "ranges": [
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        },
        {
          "eq": "7.0.2"
        },
        {
          "eq": "7.0.3"
        },
        {
          "eq": "7.0.4"
        },
        {
          "eq": "7.0.5"
        },
        {
          "eq": "7.0.6"
        },
        {
          "eq": "7.0.7"
        },
        {
          "eq": "7.0.8"
        },
        {
          "eq": "7.0.9"
        },
        {
          "lte": "5.6.24"
        }
      ],
      "note": "NVD: ext/wddx/wddx.c in PHP before 5.6.25 and 7.x before 7.0.10 allows remote attackers to cause a denial of service (NULL pointer dereference and application crash) or…"
    },
    {
      "cve": "CVE-2016-7131",
      "sev": "high",
      "kev": false,
      "title": "ext/wddx/wddx.c in PHP before 5.6.25 and 7.x before 7.0.10 allows remote attackers to…",
      "ranges": [
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        },
        {
          "eq": "7.0.2"
        },
        {
          "eq": "7.0.3"
        },
        {
          "eq": "7.0.4"
        },
        {
          "eq": "7.0.5"
        },
        {
          "eq": "7.0.6"
        },
        {
          "eq": "7.0.7"
        },
        {
          "eq": "7.0.8"
        },
        {
          "eq": "7.0.9"
        },
        {
          "lte": "5.6.24"
        }
      ],
      "note": "NVD: ext/wddx/wddx.c in PHP before 5.6.25 and 7.x before 7.0.10 allows remote attackers to cause a denial of service (NULL pointer dereference and application crash) or…"
    },
    {
      "cve": "CVE-2016-7130",
      "sev": "high",
      "kev": false,
      "title": "The php_wddx_pop_element function in ext/wddx/wddx.c in PHP before 5.6.25 and 7.x…",
      "ranges": [
        {
          "lte": "5.6.24"
        },
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        },
        {
          "eq": "7.0.2"
        },
        {
          "eq": "7.0.3"
        },
        {
          "eq": "7.0.4"
        },
        {
          "eq": "7.0.5"
        },
        {
          "eq": "7.0.6"
        },
        {
          "eq": "7.0.7"
        },
        {
          "eq": "7.0.8"
        },
        {
          "eq": "7.0.9"
        }
      ],
      "note": "NVD: The php_wddx_pop_element function in ext/wddx/wddx.c in PHP before 5.6.25 and 7.x before 7.0.10 allows remote attackers to cause a denial of service (NULL pointer…"
    },
    {
      "cve": "CVE-2016-7129",
      "sev": "critical",
      "kev": false,
      "title": "The php_wddx_process_data function in ext/wddx/wddx.c in PHP before 5.6.25 and 7.x…",
      "ranges": [
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        },
        {
          "eq": "7.0.2"
        },
        {
          "eq": "7.0.3"
        },
        {
          "eq": "7.0.4"
        },
        {
          "eq": "7.0.5"
        },
        {
          "eq": "7.0.6"
        },
        {
          "eq": "7.0.7"
        },
        {
          "eq": "7.0.8"
        },
        {
          "eq": "7.0.9"
        },
        {
          "lte": "5.6.24"
        }
      ],
      "note": "NVD: The php_wddx_process_data function in ext/wddx/wddx.c in PHP before 5.6.25 and 7.x before 7.0.10 allows remote attackers to cause a denial of service (segmentation…"
    },
    {
      "cve": "CVE-2016-7127",
      "sev": "critical",
      "kev": false,
      "title": "The imagegammacorrect function in ext/gd/gd.c in PHP before 5.6.25 and 7.x before…",
      "ranges": [
        {
          "lte": "5.6.24"
        },
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        },
        {
          "eq": "7.0.2"
        },
        {
          "eq": "7.0.3"
        },
        {
          "eq": "7.0.4"
        },
        {
          "eq": "7.0.5"
        },
        {
          "eq": "7.0.6"
        },
        {
          "eq": "7.0.7"
        },
        {
          "eq": "7.0.8"
        },
        {
          "eq": "7.0.9"
        }
      ],
      "note": "NVD: The imagegammacorrect function in ext/gd/gd.c in PHP before 5.6.25 and 7.x before 7.0.10 does not properly validate gamma values, which allows remote attackers to…"
    },
    {
      "cve": "CVE-2016-7126",
      "sev": "critical",
      "kev": false,
      "title": "The imagetruecolortopalette function in ext/gd/gd.c in PHP before 5.6.25 and 7.x…",
      "ranges": [
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        },
        {
          "eq": "7.0.2"
        },
        {
          "eq": "7.0.3"
        },
        {
          "eq": "7.0.4"
        },
        {
          "eq": "7.0.5"
        },
        {
          "eq": "7.0.6"
        },
        {
          "eq": "7.0.7"
        },
        {
          "eq": "7.0.8"
        },
        {
          "eq": "7.0.9"
        },
        {
          "lte": "5.6.24"
        }
      ],
      "note": "NVD: The imagetruecolortopalette function in ext/gd/gd.c in PHP before 5.6.25 and 7.x before 7.0.10 does not properly validate the number of colors, which allows remote…"
    },
    {
      "cve": "CVE-2016-7125",
      "sev": "high",
      "kev": false,
      "title": "ext/session/session.c in PHP before 5.6.25 and 7.x before 7.0.10 skips invalid session…",
      "ranges": [
        {
          "lte": "5.6.24"
        },
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        },
        {
          "eq": "7.0.2"
        },
        {
          "eq": "7.0.3"
        },
        {
          "eq": "7.0.4"
        },
        {
          "eq": "7.0.5"
        },
        {
          "eq": "7.0.6"
        },
        {
          "eq": "7.0.7"
        },
        {
          "eq": "7.0.8"
        },
        {
          "eq": "7.0.9"
        }
      ],
      "note": "NVD: ext/session/session.c in PHP before 5.6.25 and 7.x before 7.0.10 skips invalid session names in a way that triggers incorrect parsing, which allows remote…"
    },
    {
      "cve": "CVE-2016-7124",
      "sev": "critical",
      "kev": false,
      "title": "ext/standard/var_unserializer.c in PHP before 5.6.25 and 7.x before 7.0.10 mishandles…",
      "ranges": [
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        },
        {
          "eq": "7.0.2"
        },
        {
          "eq": "7.0.3"
        },
        {
          "eq": "7.0.4"
        },
        {
          "eq": "7.0.5"
        },
        {
          "eq": "7.0.6"
        },
        {
          "eq": "7.0.7"
        },
        {
          "eq": "7.0.8"
        },
        {
          "eq": "7.0.9"
        },
        {
          "lte": "5.6.24"
        }
      ],
      "note": "NVD: ext/standard/var_unserializer.c in PHP before 5.6.25 and 7.x before 7.0.10 mishandles certain invalid objects, which allows remote attackers to cause a denial of…"
    },
    {
      "cve": "CVE-2016-6296",
      "sev": "critical",
      "kev": false,
      "title": "Integer signedness error in the simplestring_addn function in simplestring.c in…",
      "ranges": [
        {
          "lte": "5.5.37"
        },
        {
          "eq": "5.6.0"
        },
        {
          "eq": "5.6.1"
        },
        {
          "eq": "5.6.2"
        },
        {
          "eq": "5.6.3"
        },
        {
          "eq": "5.6.4"
        },
        {
          "eq": "5.6.5"
        },
        {
          "eq": "5.6.6"
        },
        {
          "eq": "5.6.7"
        },
        {
          "eq": "5.6.8"
        },
        {
          "eq": "5.6.9"
        },
        {
          "eq": "5.6.10"
        },
        {
          "eq": "5.6.11"
        },
        {
          "eq": "5.6.12"
        },
        {
          "eq": "5.6.13"
        },
        {
          "eq": "5.6.14"
        },
        {
          "eq": "5.6.15"
        },
        {
          "eq": "5.6.16"
        },
        {
          "eq": "5.6.17"
        },
        {
          "eq": "5.6.18"
        },
        {
          "eq": "5.6.19"
        },
        {
          "eq": "5.6.20"
        },
        {
          "eq": "5.6.21"
        },
        {
          "eq": "5.6.22"
        },
        {
          "eq": "5.6.23"
        },
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        },
        {
          "eq": "7.0.2"
        },
        {
          "eq": "7.0.3"
        },
        {
          "eq": "7.0.4"
        },
        {
          "eq": "7.0.5"
        },
        {
          "eq": "7.0.8"
        }
      ],
      "note": "NVD: Integer signedness error in the simplestring_addn function in simplestring.c in xmlrpc-epi through 0.54.2, as used in PHP before 5.5.38, 5.6.x before 5.6.24, and…"
    },
    {
      "cve": "CVE-2016-6295",
      "sev": "critical",
      "kev": false,
      "title": "ext/snmp/snmp.c in PHP before 5.5.38, 5.6.x before 5.6.24, and 7.x before 7.0.9…",
      "ranges": [
        {
          "lte": "5.5.37"
        },
        {
          "eq": "5.6.0"
        },
        {
          "eq": "5.6.1"
        },
        {
          "eq": "5.6.2"
        },
        {
          "eq": "5.6.3"
        },
        {
          "eq": "5.6.4"
        },
        {
          "eq": "5.6.5"
        },
        {
          "eq": "5.6.6"
        },
        {
          "eq": "5.6.7"
        },
        {
          "eq": "5.6.8"
        },
        {
          "eq": "5.6.9"
        },
        {
          "eq": "5.6.10"
        },
        {
          "eq": "5.6.11"
        },
        {
          "eq": "5.6.12"
        },
        {
          "eq": "5.6.13"
        },
        {
          "eq": "5.6.14"
        },
        {
          "eq": "5.6.15"
        },
        {
          "eq": "5.6.16"
        },
        {
          "eq": "5.6.17"
        },
        {
          "eq": "5.6.18"
        },
        {
          "eq": "5.6.19"
        },
        {
          "eq": "5.6.20"
        },
        {
          "eq": "5.6.21"
        },
        {
          "eq": "5.6.22"
        },
        {
          "eq": "5.6.23"
        },
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        },
        {
          "eq": "7.0.2"
        },
        {
          "eq": "7.0.3"
        },
        {
          "eq": "7.0.4"
        },
        {
          "eq": "7.0.5"
        },
        {
          "eq": "7.0.8"
        }
      ],
      "note": "NVD: ext/snmp/snmp.c in PHP before 5.5.38, 5.6.x before 5.6.24, and 7.x before 7.0.9 improperly interacts with the unserialize implementation and garbage collection,…"
    },
    {
      "cve": "CVE-2016-6294",
      "sev": "critical",
      "kev": false,
      "title": "The locale_accept_from_http function in ext/intl/locale/locale_methods.c in PHP before…",
      "ranges": [
        {
          "lte": "5.5.37"
        },
        {
          "eq": "5.6.0"
        },
        {
          "eq": "5.6.1"
        },
        {
          "eq": "5.6.2"
        },
        {
          "eq": "5.6.3"
        },
        {
          "eq": "5.6.4"
        },
        {
          "eq": "5.6.5"
        },
        {
          "eq": "5.6.6"
        },
        {
          "eq": "5.6.7"
        },
        {
          "eq": "5.6.8"
        },
        {
          "eq": "5.6.9"
        },
        {
          "eq": "5.6.10"
        },
        {
          "eq": "5.6.11"
        },
        {
          "eq": "5.6.12"
        },
        {
          "eq": "5.6.13"
        },
        {
          "eq": "5.6.14"
        },
        {
          "eq": "5.6.15"
        },
        {
          "eq": "5.6.16"
        },
        {
          "eq": "5.6.17"
        },
        {
          "eq": "5.6.18"
        },
        {
          "eq": "5.6.19"
        },
        {
          "eq": "5.6.20"
        },
        {
          "eq": "5.6.21"
        },
        {
          "eq": "5.6.22"
        },
        {
          "eq": "5.6.23"
        },
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        },
        {
          "eq": "7.0.2"
        },
        {
          "eq": "7.0.3"
        },
        {
          "eq": "7.0.4"
        },
        {
          "eq": "7.0.5"
        },
        {
          "eq": "7.0.8"
        }
      ],
      "note": "NVD: The locale_accept_from_http function in ext/intl/locale/locale_methods.c in PHP before 5.5.38, 5.6.x before 5.6.24, and 7.x before 7.0.9 does not properly restrict…"
    },
    {
      "cve": "CVE-2016-6291",
      "sev": "critical",
      "kev": false,
      "title": "The exif_process_IFD_in_MAKERNOTE function in ext/exif/exif.c in PHP before 5.5.38,…",
      "ranges": [
        {
          "lte": "5.5.37"
        },
        {
          "eq": "5.6.0"
        },
        {
          "eq": "5.6.1"
        },
        {
          "eq": "5.6.2"
        },
        {
          "eq": "5.6.3"
        },
        {
          "eq": "5.6.4"
        },
        {
          "eq": "5.6.5"
        },
        {
          "eq": "5.6.6"
        },
        {
          "eq": "5.6.7"
        },
        {
          "eq": "5.6.8"
        },
        {
          "eq": "5.6.9"
        },
        {
          "eq": "5.6.10"
        },
        {
          "eq": "5.6.11"
        },
        {
          "eq": "5.6.12"
        },
        {
          "eq": "5.6.13"
        },
        {
          "eq": "5.6.14"
        },
        {
          "eq": "5.6.15"
        },
        {
          "eq": "5.6.16"
        },
        {
          "eq": "5.6.17"
        },
        {
          "eq": "5.6.18"
        },
        {
          "eq": "5.6.19"
        },
        {
          "eq": "5.6.20"
        },
        {
          "eq": "5.6.21"
        },
        {
          "eq": "5.6.22"
        },
        {
          "eq": "5.6.23"
        },
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        },
        {
          "eq": "7.0.2"
        },
        {
          "eq": "7.0.3"
        },
        {
          "eq": "7.0.4"
        },
        {
          "eq": "7.0.5"
        },
        {
          "eq": "7.0.8"
        }
      ],
      "note": "NVD: The exif_process_IFD_in_MAKERNOTE function in ext/exif/exif.c in PHP before 5.5.38, 5.6.x before 5.6.24, and 7.x before 7.0.9 allows remote attackers to cause a…"
    },
    {
      "cve": "CVE-2016-6290",
      "sev": "critical",
      "kev": false,
      "title": "ext/session/session.c in PHP before 5.5.38, 5.6.x before 5.6.24, and 7.x before 7.0.9…",
      "ranges": [
        {
          "lte": "5.5.37"
        },
        {
          "eq": "5.6.0"
        },
        {
          "eq": "5.6.1"
        },
        {
          "eq": "5.6.2"
        },
        {
          "eq": "5.6.3"
        },
        {
          "eq": "5.6.4"
        },
        {
          "eq": "5.6.5"
        },
        {
          "eq": "5.6.6"
        },
        {
          "eq": "5.6.7"
        },
        {
          "eq": "5.6.8"
        },
        {
          "eq": "5.6.9"
        },
        {
          "eq": "5.6.10"
        },
        {
          "eq": "5.6.11"
        },
        {
          "eq": "5.6.12"
        },
        {
          "eq": "5.6.13"
        },
        {
          "eq": "5.6.14"
        },
        {
          "eq": "5.6.15"
        },
        {
          "eq": "5.6.16"
        },
        {
          "eq": "5.6.17"
        },
        {
          "eq": "5.6.18"
        },
        {
          "eq": "5.6.19"
        },
        {
          "eq": "5.6.20"
        },
        {
          "eq": "5.6.21"
        },
        {
          "eq": "5.6.22"
        },
        {
          "eq": "5.6.23"
        },
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        },
        {
          "eq": "7.0.2"
        },
        {
          "eq": "7.0.3"
        },
        {
          "eq": "7.0.4"
        },
        {
          "eq": "7.0.5"
        },
        {
          "eq": "7.0.8"
        }
      ],
      "note": "NVD: ext/session/session.c in PHP before 5.5.38, 5.6.x before 5.6.24, and 7.x before 7.0.9 does not properly maintain a certain hash data structure, which allows remote…"
    },
    {
      "cve": "CVE-2016-6289",
      "sev": "high",
      "kev": false,
      "title": "Integer overflow in the virtual_file_ex function in TSRM/tsrm_virtual_cwd.c in PHP…",
      "ranges": [
        {
          "lte": "5.5.37"
        },
        {
          "eq": "5.6.0"
        },
        {
          "eq": "5.6.1"
        },
        {
          "eq": "5.6.2"
        },
        {
          "eq": "5.6.3"
        },
        {
          "eq": "5.6.4"
        },
        {
          "eq": "5.6.5"
        },
        {
          "eq": "5.6.6"
        },
        {
          "eq": "5.6.7"
        },
        {
          "eq": "5.6.8"
        },
        {
          "eq": "5.6.9"
        },
        {
          "eq": "5.6.10"
        },
        {
          "eq": "5.6.11"
        },
        {
          "eq": "5.6.12"
        },
        {
          "eq": "5.6.13"
        },
        {
          "eq": "5.6.14"
        },
        {
          "eq": "5.6.15"
        },
        {
          "eq": "5.6.16"
        },
        {
          "eq": "5.6.17"
        },
        {
          "eq": "5.6.18"
        },
        {
          "eq": "5.6.19"
        },
        {
          "eq": "5.6.20"
        },
        {
          "eq": "5.6.21"
        },
        {
          "eq": "5.6.22"
        },
        {
          "eq": "5.6.23"
        },
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        },
        {
          "eq": "7.0.2"
        },
        {
          "eq": "7.0.3"
        },
        {
          "eq": "7.0.4"
        },
        {
          "eq": "7.0.5"
        },
        {
          "eq": "7.0.8"
        }
      ],
      "note": "NVD: Integer overflow in the virtual_file_ex function in TSRM/tsrm_virtual_cwd.c in PHP before 5.5.38, 5.6.x before 5.6.24, and 7.x before 7.0.9 allows remote attackers…"
    },
    {
      "cve": "CVE-2016-6288",
      "sev": "critical",
      "kev": false,
      "title": "The php_url_parse_ex function in ext/standard/url.c in PHP before 5.5.38 allows remote…",
      "ranges": [
        {
          "lte": "5.5.37"
        }
      ],
      "note": "NVD: The php_url_parse_ex function in ext/standard/url.c in PHP before 5.5.38 allows remote attackers to cause a denial of service (buffer over-read) or possibly have…"
    },
    {
      "cve": "CVE-2016-6174",
      "sev": "high",
      "kev": false,
      "title": "applications/core/modules/front/system/content.php in Invision Power Services IPS…",
      "ranges": [
        {
          "lte": "5.4.23"
        },
        {
          "eq": "5.5.0"
        },
        {
          "eq": "5.5.1"
        },
        {
          "eq": "5.5.2"
        },
        {
          "eq": "5.5.3"
        },
        {
          "eq": "5.5.4"
        },
        {
          "eq": "5.5.5"
        },
        {
          "eq": "5.5.6"
        },
        {
          "eq": "5.5.7"
        }
      ],
      "note": "NVD: applications/core/modules/front/system/content.php in Invision Power Services IPS Community Suite (aka Invision Power Board, IPB, or Power Board) before 4.1.13,…"
    },
    {
      "cve": "CVE-2016-5772",
      "sev": "critical",
      "kev": false,
      "title": "Double free vulnerability in the php_wddx_process_data function in wddx.c in the WDDX…",
      "ranges": [
        {
          "lt": "5.5.37"
        },
        {
          "gte": "5.6.0",
          "lt": "5.6.23"
        },
        {
          "gte": "7.0.0",
          "lt": "7.0.8"
        }
      ],
      "note": "NVD: Double free vulnerability in the php_wddx_process_data function in wddx.c in the WDDX extension in PHP before 5.5.37, 5.6.x before 5.6.23, and 7.x before 7.0.8…"
    },
    {
      "cve": "CVE-2016-5771",
      "sev": "critical",
      "kev": false,
      "title": "spl_array.c in the SPL extension in PHP before 5.5.37 and 5.6.x before 5.6.23…",
      "ranges": [
        {
          "lt": "5.5.37"
        },
        {
          "gte": "5.6.0",
          "lt": "5.6.23"
        },
        {
          "gte": "7.0.0",
          "lt": "7.0.8"
        }
      ],
      "note": "NVD: spl_array.c in the SPL extension in PHP before 5.5.37 and 5.6.x before 5.6.23 improperly interacts with the unserialize implementation and garbage collection,…"
    },
    {
      "cve": "CVE-2016-5770",
      "sev": "critical",
      "kev": false,
      "title": "Integer overflow in the SplFileObject::fread function in spl_directory.c in the SPL…",
      "ranges": [
        {
          "lt": "5.5.37"
        },
        {
          "gte": "5.6.0",
          "lt": "5.6.23"
        },
        {
          "gte": "7.0.0",
          "lt": "7.0.8"
        }
      ],
      "note": "NVD: Integer overflow in the SplFileObject::fread function in spl_directory.c in the SPL extension in PHP before 5.5.37 and 5.6.x before 5.6.23 allows remote attackers…"
    },
    {
      "cve": "CVE-2016-5769",
      "sev": "critical",
      "kev": false,
      "title": "Multiple integer overflows in mcrypt.c in the mcrypt extension in PHP before 5.5.37,…",
      "ranges": [
        {
          "lte": "5.5.36"
        },
        {
          "eq": "5.6.0"
        },
        {
          "eq": "5.6.1"
        },
        {
          "eq": "5.6.2"
        },
        {
          "eq": "5.6.3"
        },
        {
          "eq": "5.6.4"
        },
        {
          "eq": "5.6.5"
        },
        {
          "eq": "5.6.6"
        },
        {
          "eq": "5.6.7"
        },
        {
          "eq": "5.6.8"
        },
        {
          "eq": "5.6.9"
        },
        {
          "eq": "5.6.10"
        },
        {
          "eq": "5.6.11"
        },
        {
          "eq": "5.6.12"
        },
        {
          "eq": "5.6.13"
        },
        {
          "eq": "5.6.14"
        },
        {
          "eq": "5.6.15"
        },
        {
          "eq": "5.6.16"
        },
        {
          "eq": "5.6.17"
        },
        {
          "eq": "5.6.18"
        },
        {
          "eq": "5.6.19"
        },
        {
          "eq": "5.6.20"
        },
        {
          "eq": "5.6.21"
        },
        {
          "eq": "5.6.22"
        },
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        },
        {
          "eq": "7.0.2"
        },
        {
          "eq": "7.0.3"
        },
        {
          "eq": "7.0.4"
        },
        {
          "eq": "7.0.5"
        },
        {
          "eq": "7.0.6"
        },
        {
          "eq": "7.0.7"
        }
      ],
      "note": "NVD: Multiple integer overflows in mcrypt.c in the mcrypt extension in PHP before 5.5.37, 5.6.x before 5.6.23, and 7.x before 7.0.8 allow remote attackers to cause a…"
    },
    {
      "cve": "CVE-2016-5768",
      "sev": "critical",
      "kev": false,
      "title": "Double free vulnerability in the _php_mb_regex_ereg_replace_exec function in…",
      "ranges": [
        {
          "lte": "5.5.36"
        },
        {
          "eq": "5.6.0"
        },
        {
          "eq": "5.6.1"
        },
        {
          "eq": "5.6.2"
        },
        {
          "eq": "5.6.3"
        },
        {
          "eq": "5.6.4"
        },
        {
          "eq": "5.6.5"
        },
        {
          "eq": "5.6.6"
        },
        {
          "eq": "5.6.7"
        },
        {
          "eq": "5.6.8"
        },
        {
          "eq": "5.6.9"
        },
        {
          "eq": "5.6.10"
        },
        {
          "eq": "5.6.11"
        },
        {
          "eq": "5.6.12"
        },
        {
          "eq": "5.6.13"
        },
        {
          "eq": "5.6.14"
        },
        {
          "eq": "5.6.15"
        },
        {
          "eq": "5.6.16"
        },
        {
          "eq": "5.6.17"
        },
        {
          "eq": "5.6.18"
        },
        {
          "eq": "5.6.19"
        },
        {
          "eq": "5.6.20"
        },
        {
          "eq": "5.6.21"
        },
        {
          "eq": "5.6.22"
        },
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        },
        {
          "eq": "7.0.2"
        },
        {
          "eq": "7.0.3"
        },
        {
          "eq": "7.0.4"
        },
        {
          "eq": "7.0.5"
        },
        {
          "eq": "7.0.6"
        },
        {
          "eq": "7.0.7"
        }
      ],
      "note": "NVD: Double free vulnerability in the _php_mb_regex_ereg_replace_exec function in php_mbregex.c in the mbstring extension in PHP before 5.5.37, 5.6.x before 5.6.23, and…"
    },
    {
      "cve": "CVE-2016-5399",
      "sev": "high",
      "kev": false,
      "title": "The bzread function in ext/bz2/bz2.c in PHP before 5.5.38, 5.6.x before 5.6.24, and…",
      "ranges": [
        {
          "lte": "5.5.37"
        },
        {
          "gte": "5.6.0",
          "lt": "5.6.24"
        },
        {
          "gte": "7.0.0",
          "lt": "7.0.9"
        }
      ],
      "note": "NVD: The bzread function in ext/bz2/bz2.c in PHP before 5.5.38, 5.6.x before 5.6.24, and 7.x before 7.0.9 allows remote attackers to cause a denial of service…"
    },
    {
      "cve": "CVE-2016-5385",
      "sev": "high",
      "kev": false,
      "title": "PHP through 7.0.8 does not attempt to address RFC 3875 section 4.1.18 namespace…",
      "ranges": [
        {
          "gte": "5.5.0",
          "lt": "5.5.38"
        },
        {
          "gte": "5.6.0",
          "lt": "5.6.24"
        },
        {
          "gte": "7.0.0",
          "lte": "7.0.8"
        }
      ],
      "note": "NVD: PHP through 7.0.8 does not attempt to address RFC 3875 section 4.1.18 namespace conflicts and therefore does not protect applications from the presence of…"
    },
    {
      "cve": "CVE-2016-5114",
      "sev": "critical",
      "kev": false,
      "title": "sapi/fpm/fpm/fpm_log.c in PHP before 5.5.31, 5.6.x before 5.6.17, and 7.x before 7.0.2…",
      "ranges": [
        {
          "lte": "5.5.30"
        },
        {
          "eq": "5.6.0"
        },
        {
          "eq": "5.6.1"
        },
        {
          "eq": "5.6.2"
        },
        {
          "eq": "5.6.3"
        },
        {
          "eq": "5.6.4"
        },
        {
          "eq": "5.6.5"
        },
        {
          "eq": "5.6.6"
        },
        {
          "eq": "5.6.7"
        },
        {
          "eq": "5.6.8"
        },
        {
          "eq": "5.6.9"
        },
        {
          "eq": "5.6.10"
        },
        {
          "eq": "5.6.11"
        },
        {
          "eq": "5.6.12"
        },
        {
          "eq": "5.6.13"
        },
        {
          "eq": "5.6.14"
        },
        {
          "eq": "5.6.15"
        },
        {
          "eq": "5.6.16"
        },
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        }
      ],
      "note": "NVD: sapi/fpm/fpm/fpm_log.c in PHP before 5.5.31, 5.6.x before 5.6.17, and 7.x before 7.0.2 misinterprets the semantics of the snprintf return value, which allows…"
    },
    {
      "cve": "CVE-2016-5096",
      "sev": "high",
      "kev": false,
      "title": "Integer overflow in the fread function in ext/standard/file.c in PHP before 5.5.36 and…",
      "ranges": [
        {
          "lte": "5.5.35"
        },
        {
          "eq": "5.6.0"
        },
        {
          "eq": "5.6.1"
        },
        {
          "eq": "5.6.2"
        },
        {
          "eq": "5.6.3"
        },
        {
          "eq": "5.6.4"
        },
        {
          "eq": "5.6.5"
        },
        {
          "eq": "5.6.6"
        },
        {
          "eq": "5.6.7"
        },
        {
          "eq": "5.6.8"
        },
        {
          "eq": "5.6.9"
        },
        {
          "eq": "5.6.10"
        },
        {
          "eq": "5.6.11"
        },
        {
          "eq": "5.6.12"
        },
        {
          "eq": "5.6.13"
        },
        {
          "eq": "5.6.14"
        },
        {
          "eq": "5.6.15"
        },
        {
          "eq": "5.6.16"
        },
        {
          "eq": "5.6.17"
        },
        {
          "eq": "5.6.18"
        },
        {
          "eq": "5.6.19"
        },
        {
          "eq": "5.6.20"
        },
        {
          "eq": "5.6.21"
        }
      ],
      "note": "NVD: Integer overflow in the fread function in ext/standard/file.c in PHP before 5.5.36 and 5.6.x before 5.6.22 allows remote attackers to cause a denial of service or…"
    },
    {
      "cve": "CVE-2016-5095",
      "sev": "high",
      "kev": false,
      "title": "Integer overflow in the php_escape_html_entities_ex function in ext/standard/html.c in…",
      "ranges": [
        {
          "lte": "5.5.35"
        },
        {
          "eq": "5.6.0"
        },
        {
          "eq": "5.6.1"
        },
        {
          "eq": "5.6.2"
        },
        {
          "eq": "5.6.3"
        },
        {
          "eq": "5.6.4"
        },
        {
          "eq": "5.6.5"
        },
        {
          "eq": "5.6.6"
        },
        {
          "eq": "5.6.7"
        },
        {
          "eq": "5.6.8"
        },
        {
          "eq": "5.6.9"
        },
        {
          "eq": "5.6.10"
        },
        {
          "eq": "5.6.11"
        },
        {
          "eq": "5.6.12"
        },
        {
          "eq": "5.6.13"
        },
        {
          "eq": "5.6.14"
        },
        {
          "eq": "5.6.15"
        },
        {
          "eq": "5.6.16"
        },
        {
          "eq": "5.6.17"
        },
        {
          "eq": "5.6.18"
        },
        {
          "eq": "5.6.19"
        },
        {
          "eq": "5.6.20"
        },
        {
          "eq": "5.6.21"
        }
      ],
      "note": "NVD: Integer overflow in the php_escape_html_entities_ex function in ext/standard/html.c in PHP before 5.5.36 and 5.6.x before 5.6.22 allows remote attackers to cause a…"
    },
    {
      "cve": "CVE-2016-5094",
      "sev": "high",
      "kev": false,
      "title": "Integer overflow in the php_html_entities function in ext/standard/html.c in PHP…",
      "ranges": [
        {
          "lte": "5.5.36"
        },
        {
          "eq": "5.6.0"
        },
        {
          "eq": "5.6.1"
        },
        {
          "eq": "5.6.2"
        },
        {
          "eq": "5.6.3"
        },
        {
          "eq": "5.6.4"
        },
        {
          "eq": "5.6.5"
        },
        {
          "eq": "5.6.6"
        },
        {
          "eq": "5.6.7"
        },
        {
          "eq": "5.6.8"
        },
        {
          "eq": "5.6.9"
        },
        {
          "eq": "5.6.10"
        },
        {
          "eq": "5.6.11"
        },
        {
          "eq": "5.6.12"
        },
        {
          "eq": "5.6.13"
        },
        {
          "eq": "5.6.14"
        },
        {
          "eq": "5.6.15"
        },
        {
          "eq": "5.6.16"
        },
        {
          "eq": "5.6.17"
        },
        {
          "eq": "5.6.18"
        },
        {
          "eq": "5.6.19"
        },
        {
          "eq": "5.6.20"
        },
        {
          "eq": "5.6.21"
        }
      ],
      "note": "NVD: Integer overflow in the php_html_entities function in ext/standard/html.c in PHP before 5.5.36 and 5.6.x before 5.6.22 allows remote attackers to cause a denial of…"
    },
    {
      "cve": "CVE-2016-5093",
      "sev": "high",
      "kev": false,
      "title": "The get_icu_value_internal function in ext/intl/locale/locale_methods.c in PHP before…",
      "ranges": [
        {
          "lte": "5.5.35"
        },
        {
          "eq": "5.6.0"
        },
        {
          "eq": "5.6.1"
        },
        {
          "eq": "5.6.2"
        },
        {
          "eq": "5.6.3"
        },
        {
          "eq": "5.6.4"
        },
        {
          "eq": "5.6.5"
        },
        {
          "eq": "5.6.6"
        },
        {
          "eq": "5.6.7"
        },
        {
          "eq": "5.6.8"
        },
        {
          "eq": "5.6.9"
        },
        {
          "eq": "5.6.10"
        },
        {
          "eq": "5.6.11"
        },
        {
          "eq": "5.6.12"
        },
        {
          "eq": "5.6.13"
        },
        {
          "eq": "5.6.14"
        },
        {
          "eq": "5.6.15"
        },
        {
          "eq": "5.6.16"
        },
        {
          "eq": "5.6.17"
        },
        {
          "eq": "5.6.18"
        },
        {
          "eq": "5.6.19"
        },
        {
          "eq": "5.6.20"
        },
        {
          "eq": "5.6.21"
        },
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        },
        {
          "eq": "7.0.2"
        },
        {
          "eq": "7.0.3"
        },
        {
          "eq": "7.0.4"
        },
        {
          "eq": "7.0.5"
        },
        {
          "eq": "7.0.6"
        }
      ],
      "note": "NVD: The get_icu_value_internal function in ext/intl/locale/locale_methods.c in PHP before 5.5.36, 5.6.x before 5.6.22, and 7.x before 7.0.7 does not ensure the…"
    },
    {
      "cve": "CVE-2016-4544",
      "sev": "critical",
      "kev": false,
      "title": "The exif_process_TIFF_in_JPEG function in ext/exif/exif.c in PHP before 5.5.35, 5.6.x…",
      "ranges": [
        {
          "gte": "5.5.0",
          "lt": "5.5.35"
        },
        {
          "gte": "5.6.0",
          "lt": "5.6.21"
        },
        {
          "gte": "7.0.0",
          "lt": "7.0.6"
        }
      ],
      "note": "NVD: The exif_process_TIFF_in_JPEG function in ext/exif/exif.c in PHP before 5.5.35, 5.6.x before 5.6.21, and 7.x before 7.0.6 does not validate TIFF start data, which…"
    },
    {
      "cve": "CVE-2016-4543",
      "sev": "critical",
      "kev": false,
      "title": "The exif_process_IFD_in_JPEG function in ext/exif/exif.c in PHP before 5.5.35, 5.6.x…",
      "ranges": [
        {
          "lte": "5.5.34"
        },
        {
          "eq": "5.6.0"
        },
        {
          "eq": "5.6.1"
        },
        {
          "eq": "5.6.2"
        },
        {
          "eq": "5.6.3"
        },
        {
          "eq": "5.6.4"
        },
        {
          "eq": "5.6.5"
        },
        {
          "eq": "5.6.6"
        },
        {
          "eq": "5.6.7"
        },
        {
          "eq": "5.6.8"
        },
        {
          "eq": "5.6.9"
        },
        {
          "eq": "5.6.10"
        },
        {
          "eq": "5.6.11"
        },
        {
          "eq": "5.6.12"
        },
        {
          "eq": "5.6.13"
        },
        {
          "eq": "5.6.14"
        },
        {
          "eq": "5.6.15"
        },
        {
          "eq": "5.6.16"
        },
        {
          "eq": "5.6.17"
        },
        {
          "eq": "5.6.18"
        },
        {
          "eq": "5.6.19"
        },
        {
          "eq": "5.6.20"
        },
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        },
        {
          "eq": "7.0.2"
        },
        {
          "eq": "7.0.3"
        },
        {
          "eq": "7.0.4"
        },
        {
          "eq": "7.0.5"
        }
      ],
      "note": "NVD: The exif_process_IFD_in_JPEG function in ext/exif/exif.c in PHP before 5.5.35, 5.6.x before 5.6.21, and 7.x before 7.0.6 does not validate IFD sizes, which allows…"
    },
    {
      "cve": "CVE-2016-4542",
      "sev": "critical",
      "kev": false,
      "title": "The exif_process_IFD_TAG function in ext/exif/exif.c in PHP before 5.5.35, 5.6.x…",
      "ranges": [
        {
          "lte": "5.5.34"
        },
        {
          "eq": "5.6.0"
        },
        {
          "eq": "5.6.1"
        },
        {
          "eq": "5.6.2"
        },
        {
          "eq": "5.6.3"
        },
        {
          "eq": "5.6.4"
        },
        {
          "eq": "5.6.5"
        },
        {
          "eq": "5.6.6"
        },
        {
          "eq": "5.6.7"
        },
        {
          "eq": "5.6.8"
        },
        {
          "eq": "5.6.9"
        },
        {
          "eq": "5.6.10"
        },
        {
          "eq": "5.6.11"
        },
        {
          "eq": "5.6.12"
        },
        {
          "eq": "5.6.13"
        },
        {
          "eq": "5.6.14"
        },
        {
          "eq": "5.6.15"
        },
        {
          "eq": "5.6.16"
        },
        {
          "eq": "5.6.17"
        },
        {
          "eq": "5.6.18"
        },
        {
          "eq": "5.6.19"
        },
        {
          "eq": "5.6.20"
        },
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        },
        {
          "eq": "7.0.2"
        },
        {
          "eq": "7.0.3"
        },
        {
          "eq": "7.0.4"
        },
        {
          "eq": "7.0.5"
        }
      ],
      "note": "NVD: The exif_process_IFD_TAG function in ext/exif/exif.c in PHP before 5.5.35, 5.6.x before 5.6.21, and 7.x before 7.0.6 does not properly construct spprintf…"
    },
    {
      "cve": "CVE-2016-4541",
      "sev": "critical",
      "kev": false,
      "title": "The grapheme_strpos function in ext/intl/grapheme/grapheme_string.c in PHP before…",
      "ranges": [
        {
          "lte": "5.5.34"
        },
        {
          "eq": "5.6.0"
        },
        {
          "eq": "5.6.1"
        },
        {
          "eq": "5.6.2"
        },
        {
          "eq": "5.6.3"
        },
        {
          "eq": "5.6.4"
        },
        {
          "eq": "5.6.5"
        },
        {
          "eq": "5.6.6"
        },
        {
          "eq": "5.6.7"
        },
        {
          "eq": "5.6.8"
        },
        {
          "eq": "5.6.9"
        },
        {
          "eq": "5.6.10"
        },
        {
          "eq": "5.6.11"
        },
        {
          "eq": "5.6.12"
        },
        {
          "eq": "5.6.13"
        },
        {
          "eq": "5.6.14"
        },
        {
          "eq": "5.6.15"
        },
        {
          "eq": "5.6.16"
        },
        {
          "eq": "5.6.17"
        },
        {
          "eq": "5.6.18"
        },
        {
          "eq": "5.6.19"
        },
        {
          "eq": "5.6.20"
        },
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        },
        {
          "eq": "7.0.2"
        },
        {
          "eq": "7.0.3"
        },
        {
          "eq": "7.0.4"
        },
        {
          "eq": "7.0.5"
        }
      ],
      "note": "NVD: The grapheme_strpos function in ext/intl/grapheme/grapheme_string.c in PHP before 5.5.35, 5.6.x before 5.6.21, and 7.x before 7.0.6 allows remote attackers to…"
    },
    {
      "cve": "CVE-2016-4540",
      "sev": "critical",
      "kev": false,
      "title": "The grapheme_stripos function in ext/intl/grapheme/grapheme_string.c in PHP before…",
      "ranges": [
        {
          "lte": "5.5.34"
        },
        {
          "eq": "5.6.0"
        },
        {
          "eq": "5.6.1"
        },
        {
          "eq": "5.6.2"
        },
        {
          "eq": "5.6.3"
        },
        {
          "eq": "5.6.4"
        },
        {
          "eq": "5.6.5"
        },
        {
          "eq": "5.6.6"
        },
        {
          "eq": "5.6.7"
        },
        {
          "eq": "5.6.8"
        },
        {
          "eq": "5.6.9"
        },
        {
          "eq": "5.6.10"
        },
        {
          "eq": "5.6.11"
        },
        {
          "eq": "5.6.12"
        },
        {
          "eq": "5.6.13"
        },
        {
          "eq": "5.6.14"
        },
        {
          "eq": "5.6.15"
        },
        {
          "eq": "5.6.16"
        },
        {
          "eq": "5.6.17"
        },
        {
          "eq": "5.6.18"
        },
        {
          "eq": "5.6.19"
        },
        {
          "eq": "5.6.20"
        },
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        },
        {
          "eq": "7.0.2"
        },
        {
          "eq": "7.0.3"
        },
        {
          "eq": "7.0.4"
        },
        {
          "eq": "7.0.5"
        }
      ],
      "note": "NVD: The grapheme_stripos function in ext/intl/grapheme/grapheme_string.c in PHP before 5.5.35, 5.6.x before 5.6.21, and 7.x before 7.0.6 allows remote attackers to…"
    },
    {
      "cve": "CVE-2016-4539",
      "sev": "critical",
      "kev": false,
      "title": "The xml_parse_into_struct function in ext/xml/xml.c in PHP before 5.5.35, 5.6.x before…",
      "ranges": [
        {
          "lte": "5.5.34"
        },
        {
          "eq": "5.6.0"
        },
        {
          "eq": "5.6.1"
        },
        {
          "eq": "5.6.2"
        },
        {
          "eq": "5.6.3"
        },
        {
          "eq": "5.6.4"
        },
        {
          "eq": "5.6.5"
        },
        {
          "eq": "5.6.6"
        },
        {
          "eq": "5.6.7"
        },
        {
          "eq": "5.6.8"
        },
        {
          "eq": "5.6.9"
        },
        {
          "eq": "5.6.10"
        },
        {
          "eq": "5.6.11"
        },
        {
          "eq": "5.6.12"
        },
        {
          "eq": "5.6.13"
        },
        {
          "eq": "5.6.14"
        },
        {
          "eq": "5.6.15"
        },
        {
          "eq": "5.6.16"
        },
        {
          "eq": "5.6.17"
        },
        {
          "eq": "5.6.18"
        },
        {
          "eq": "5.6.19"
        },
        {
          "eq": "5.6.20"
        },
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        },
        {
          "eq": "7.0.2"
        },
        {
          "eq": "7.0.3"
        },
        {
          "eq": "7.0.4"
        },
        {
          "eq": "7.0.5"
        }
      ],
      "note": "NVD: The xml_parse_into_struct function in ext/xml/xml.c in PHP before 5.5.35, 5.6.x before 5.6.21, and 7.x before 7.0.6 allows remote attackers to cause a denial of…"
    },
    {
      "cve": "CVE-2016-4538",
      "sev": "critical",
      "kev": false,
      "title": "The bcpowmod function in ext/bcmath/bcmath.c in PHP before 5.5.35, 5.6.x before…",
      "ranges": [
        {
          "lte": "5.5.33"
        },
        {
          "eq": "5.6.0"
        },
        {
          "eq": "5.6.1"
        },
        {
          "eq": "5.6.2"
        },
        {
          "eq": "5.6.3"
        },
        {
          "eq": "5.6.4"
        },
        {
          "eq": "5.6.5"
        },
        {
          "eq": "5.6.6"
        },
        {
          "eq": "5.6.7"
        },
        {
          "eq": "5.6.8"
        },
        {
          "eq": "5.6.9"
        },
        {
          "eq": "5.6.10"
        },
        {
          "eq": "5.6.11"
        },
        {
          "eq": "5.6.12"
        },
        {
          "eq": "5.6.13"
        },
        {
          "eq": "5.6.14"
        },
        {
          "eq": "5.6.15"
        },
        {
          "eq": "5.6.16"
        },
        {
          "eq": "5.6.17"
        },
        {
          "eq": "5.6.18"
        },
        {
          "eq": "5.6.19"
        },
        {
          "eq": "5.6.20"
        },
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        },
        {
          "eq": "7.0.2"
        },
        {
          "eq": "7.0.3"
        },
        {
          "eq": "7.0.4"
        },
        {
          "eq": "7.0.5"
        }
      ],
      "note": "NVD: The bcpowmod function in ext/bcmath/bcmath.c in PHP before 5.5.35, 5.6.x before 5.6.21, and 7.x before 7.0.6 modifies certain data structures without considering…"
    },
    {
      "cve": "CVE-2016-4537",
      "sev": "critical",
      "kev": false,
      "title": "The bcpowmod function in ext/bcmath/bcmath.c in PHP before 5.5.35, 5.6.x before…",
      "ranges": [
        {
          "lte": "5.5.34"
        },
        {
          "eq": "5.6.0"
        },
        {
          "eq": "5.6.1"
        },
        {
          "eq": "5.6.2"
        },
        {
          "eq": "5.6.3"
        },
        {
          "eq": "5.6.4"
        },
        {
          "eq": "5.6.5"
        },
        {
          "eq": "5.6.6"
        },
        {
          "eq": "5.6.7"
        },
        {
          "eq": "5.6.8"
        },
        {
          "eq": "5.6.9"
        },
        {
          "eq": "5.6.10"
        },
        {
          "eq": "5.6.11"
        },
        {
          "eq": "5.6.12"
        },
        {
          "eq": "5.6.13"
        },
        {
          "eq": "5.6.14"
        },
        {
          "eq": "5.6.15"
        },
        {
          "eq": "5.6.16"
        },
        {
          "eq": "5.6.17"
        },
        {
          "eq": "5.6.18"
        },
        {
          "eq": "5.6.19"
        },
        {
          "eq": "5.6.20"
        },
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        },
        {
          "eq": "7.0.2"
        },
        {
          "eq": "7.0.3"
        },
        {
          "eq": "7.0.4"
        },
        {
          "eq": "7.0.5"
        }
      ],
      "note": "NVD: The bcpowmod function in ext/bcmath/bcmath.c in PHP before 5.5.35, 5.6.x before 5.6.21, and 7.x before 7.0.6 accepts a negative integer for the scale argument,…"
    },
    {
      "cve": "CVE-2016-4473",
      "sev": "critical",
      "kev": false,
      "title": "/ext/phar/phar_object.c in PHP 7.0.7 and 5.6.x allows remote attackers to execute…",
      "ranges": [
        {
          "eq": "5.6.0"
        },
        {
          "eq": "5.6.1"
        },
        {
          "eq": "5.6.2"
        },
        {
          "eq": "5.6.3"
        },
        {
          "eq": "5.6.4"
        },
        {
          "eq": "5.6.5"
        },
        {
          "eq": "5.6.6"
        },
        {
          "eq": "5.6.7"
        },
        {
          "eq": "5.6.8"
        },
        {
          "eq": "5.6.9"
        },
        {
          "eq": "5.6.10"
        },
        {
          "eq": "5.6.11"
        },
        {
          "eq": "5.6.12"
        },
        {
          "eq": "5.6.13"
        },
        {
          "eq": "5.6.14"
        },
        {
          "eq": "5.6.15"
        },
        {
          "eq": "5.6.16"
        },
        {
          "eq": "5.6.17"
        },
        {
          "eq": "5.6.18"
        },
        {
          "eq": "5.6.19"
        },
        {
          "eq": "5.6.20"
        },
        {
          "eq": "5.6.21"
        },
        {
          "eq": "5.6.22"
        },
        {
          "eq": "7.0.7"
        }
      ],
      "note": "NVD: /ext/phar/phar_object.c in PHP 7.0.7 and 5.6.x allows remote attackers to execute arbitrary code."
    },
    {
      "cve": "CVE-2016-4346",
      "sev": "critical",
      "kev": false,
      "title": "Integer overflow in the str_pad function in ext/standard/string.c in PHP before 7.0.4…",
      "ranges": [
        {
          "gte": "7.0.0",
          "lt": "7.0.4"
        }
      ],
      "note": "NVD: Integer overflow in the str_pad function in ext/standard/string.c in PHP before 7.0.4 allows remote attackers to cause a denial of service or possibly have…"
    },
    {
      "cve": "CVE-2016-4345",
      "sev": "critical",
      "kev": false,
      "title": "Integer overflow in the php_filter_encode_url function in…",
      "ranges": [
        {
          "gte": "7.0.0",
          "lt": "7.0.4"
        }
      ],
      "note": "NVD: Integer overflow in the php_filter_encode_url function in ext/filter/sanitizing_filters.c in PHP before 7.0.4 allows remote attackers to cause a denial of service…"
    },
    {
      "cve": "CVE-2016-4344",
      "sev": "critical",
      "kev": false,
      "title": "Integer overflow in the xml_utf8_encode function in ext/xml/xml.c in PHP before 7.0.4…",
      "ranges": [
        {
          "gte": "7.0.0",
          "lt": "7.0.4"
        }
      ],
      "note": "NVD: Integer overflow in the xml_utf8_encode function in ext/xml/xml.c in PHP before 7.0.4 allows remote attackers to cause a denial of service or possibly have…"
    },
    {
      "cve": "CVE-2016-4343",
      "sev": "high",
      "kev": false,
      "title": "The phar_make_dirstream function in ext/phar/dirstream.c in PHP before 5.6.18 and 7.x…",
      "ranges": [
        {
          "lt": "5.5.36"
        },
        {
          "gte": "5.6.0",
          "lt": "5.6.18"
        },
        {
          "gte": "7.0.0",
          "lt": "7.0.3"
        }
      ],
      "note": "NVD: The phar_make_dirstream function in ext/phar/dirstream.c in PHP before 5.6.18 and 7.x before 7.0.3 mishandles zero-size ././@LongLink files, which allows remote…"
    },
    {
      "cve": "CVE-2016-4342",
      "sev": "high",
      "kev": false,
      "title": "ext/phar/phar_object.c in PHP before 5.5.32, 5.6.x before 5.6.18, and 7.x before 7.0.3…",
      "ranges": [
        {
          "lte": "5.5.31"
        },
        {
          "eq": "5.6.0"
        },
        {
          "eq": "5.6.1"
        },
        {
          "eq": "5.6.2"
        },
        {
          "eq": "5.6.3"
        },
        {
          "eq": "5.6.4"
        },
        {
          "eq": "5.6.5"
        },
        {
          "eq": "5.6.6"
        },
        {
          "eq": "5.6.7"
        },
        {
          "eq": "5.6.8"
        },
        {
          "eq": "5.6.9"
        },
        {
          "eq": "5.6.10"
        },
        {
          "eq": "5.6.11"
        },
        {
          "eq": "5.6.12"
        },
        {
          "eq": "5.6.13"
        },
        {
          "eq": "5.6.14"
        },
        {
          "eq": "5.6.15"
        },
        {
          "eq": "5.6.16"
        },
        {
          "eq": "5.6.17"
        },
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        },
        {
          "eq": "7.0.2"
        }
      ],
      "note": "NVD: ext/phar/phar_object.c in PHP before 5.5.32, 5.6.x before 5.6.18, and 7.x before 7.0.3 mishandles zero-length uncompressed data, which allows remote attackers to…"
    },
    {
      "cve": "CVE-2016-4070",
      "sev": "high",
      "kev": false,
      "title": "Integer overflow in the php_raw_url_encode function in ext/standard/url.c in PHP…",
      "ranges": [
        {
          "lte": "5.5.33"
        },
        {
          "eq": "5.6.0"
        },
        {
          "eq": "5.6.1"
        },
        {
          "eq": "5.6.2"
        },
        {
          "eq": "5.6.3"
        },
        {
          "eq": "5.6.4"
        },
        {
          "eq": "5.6.5"
        },
        {
          "eq": "5.6.6"
        },
        {
          "eq": "5.6.7"
        },
        {
          "eq": "5.6.8"
        },
        {
          "eq": "5.6.9"
        },
        {
          "eq": "5.6.10"
        },
        {
          "eq": "5.6.11"
        },
        {
          "eq": "5.6.12"
        },
        {
          "eq": "5.6.13"
        },
        {
          "eq": "5.6.14"
        },
        {
          "eq": "5.6.15"
        },
        {
          "eq": "5.6.16"
        },
        {
          "eq": "5.6.17"
        },
        {
          "eq": "5.6.18"
        },
        {
          "eq": "5.6.19"
        },
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        },
        {
          "eq": "7.0.2"
        },
        {
          "eq": "7.0.3"
        },
        {
          "eq": "7.0.4"
        }
      ],
      "note": "NVD: Integer overflow in the php_raw_url_encode function in ext/standard/url.c in PHP before 5.5.34, 5.6.x before 5.6.20, and 7.x before 7.0.5 allows remote attackers…"
    },
    {
      "cve": "CVE-2016-3142",
      "sev": "high",
      "kev": false,
      "title": "The phar_parse_zipfile function in zip.c in the PHAR extension in PHP before 5.5.33…",
      "ranges": [
        {
          "lte": "5.5.32"
        },
        {
          "eq": "5.6.0"
        },
        {
          "eq": "5.6.1"
        },
        {
          "eq": "5.6.2"
        },
        {
          "eq": "5.6.3"
        },
        {
          "eq": "5.6.4"
        },
        {
          "eq": "5.6.5"
        },
        {
          "eq": "5.6.6"
        },
        {
          "eq": "5.6.7"
        },
        {
          "eq": "5.6.8"
        },
        {
          "eq": "5.6.9"
        },
        {
          "eq": "5.6.10"
        },
        {
          "eq": "5.6.11"
        },
        {
          "eq": "5.6.12"
        },
        {
          "eq": "5.6.13"
        },
        {
          "eq": "5.6.14"
        },
        {
          "eq": "5.6.15"
        },
        {
          "eq": "5.6.16"
        },
        {
          "eq": "5.6.17"
        },
        {
          "eq": "5.6.18"
        }
      ],
      "note": "NVD: The phar_parse_zipfile function in zip.c in the PHAR extension in PHP before 5.5.33 and 5.6.x before 5.6.19 allows remote attackers to obtain sensitive information…"
    },
    {
      "cve": "CVE-2016-3141",
      "sev": "critical",
      "kev": false,
      "title": "Use-after-free vulnerability in wddx.c in the WDDX extension in PHP before 5.5.33 and…",
      "ranges": [
        {
          "lte": "5.5.32"
        },
        {
          "eq": "5.6.0"
        },
        {
          "eq": "5.6.1"
        },
        {
          "eq": "5.6.2"
        },
        {
          "eq": "5.6.3"
        },
        {
          "eq": "5.6.4"
        },
        {
          "eq": "5.6.5"
        },
        {
          "eq": "5.6.6"
        },
        {
          "eq": "5.6.7"
        },
        {
          "eq": "5.6.8"
        },
        {
          "eq": "5.6.9"
        },
        {
          "eq": "5.6.10"
        },
        {
          "eq": "5.6.11"
        },
        {
          "eq": "5.6.12"
        },
        {
          "eq": "5.6.13"
        },
        {
          "eq": "5.6.14"
        },
        {
          "eq": "5.6.15"
        },
        {
          "eq": "5.6.16"
        },
        {
          "eq": "5.6.17"
        },
        {
          "eq": "5.6.18"
        }
      ],
      "note": "NVD: Use-after-free vulnerability in wddx.c in the WDDX extension in PHP before 5.5.33 and 5.6.x before 5.6.19 allows remote attackers to cause a denial of service…"
    },
    {
      "cve": "CVE-2016-3132",
      "sev": "critical",
      "kev": false,
      "title": "Double free vulnerability in the SplDoublyLinkedList::offsetSet function in…",
      "ranges": [
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        },
        {
          "eq": "7.0.2"
        },
        {
          "eq": "7.0.3"
        },
        {
          "eq": "7.0.4"
        },
        {
          "eq": "7.0.5"
        }
      ],
      "note": "NVD: Double free vulnerability in the SplDoublyLinkedList::offsetSet function in ext/spl/spl_dllist.c in PHP 7.x before 7.0.6 allows remote attackers to execute…"
    },
    {
      "cve": "CVE-2016-3078",
      "sev": "critical",
      "kev": false,
      "title": "Multiple integer overflows in php_zip.c in the zip extension in PHP before 7.0.6 allow…",
      "ranges": [
        {
          "gte": "7.0.0",
          "lt": "7.0.6"
        }
      ],
      "note": "NVD: Multiple integer overflows in php_zip.c in the zip extension in PHP before 7.0.6 allow remote attackers to cause a denial of service (heap-based buffer overflow…"
    },
    {
      "cve": "CVE-2016-3074",
      "sev": "critical",
      "kev": false,
      "title": "Integer signedness error in GD Graphics Library 2.1.1 (aka libgd or libgd2) allows…",
      "ranges": [
        {
          "gte": "5.5.0",
          "lt": "5.5.35"
        },
        {
          "gte": "5.6.0",
          "lt": "5.6.21"
        },
        {
          "gte": "7.0.0",
          "lt": "7.0.6"
        }
      ],
      "note": "NVD: Integer signedness error in GD Graphics Library 2.1.1 (aka libgd or libgd2) allows remote attackers to cause a denial of service (crash) or potentially execute…"
    },
    {
      "cve": "CVE-2016-2554",
      "sev": "critical",
      "kev": false,
      "title": "Stack-based buffer overflow in ext/phar/tar.c in PHP before 5.5.32, 5.6.x before…",
      "ranges": [
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        },
        {
          "eq": "7.0.2"
        },
        {
          "lte": "5.5.31"
        },
        {
          "eq": "5.6.0"
        },
        {
          "eq": "5.6.1"
        },
        {
          "eq": "5.6.2"
        },
        {
          "eq": "5.6.3"
        },
        {
          "eq": "5.6.4"
        },
        {
          "eq": "5.6.5"
        },
        {
          "eq": "5.6.6"
        },
        {
          "eq": "5.6.7"
        },
        {
          "eq": "5.6.8"
        },
        {
          "eq": "5.6.9"
        },
        {
          "eq": "5.6.10"
        },
        {
          "eq": "5.6.11"
        },
        {
          "eq": "5.6.12"
        },
        {
          "eq": "5.6.13"
        },
        {
          "eq": "5.6.14"
        },
        {
          "eq": "5.6.15"
        },
        {
          "eq": "5.6.16"
        },
        {
          "eq": "5.6.17"
        }
      ],
      "note": "NVD: Stack-based buffer overflow in ext/phar/tar.c in PHP before 5.5.32, 5.6.x before 5.6.18, and 7.x before 7.0.3 allows remote attackers to cause a denial of service…"
    },
    {
      "cve": "CVE-2016-1904",
      "sev": "high",
      "kev": false,
      "title": "Multiple integer overflows in ext/standard/exec.c in PHP 7.x before 7.0.2 allow remote…",
      "ranges": [
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        }
      ],
      "note": "NVD: Multiple integer overflows in ext/standard/exec.c in PHP 7.x before 7.0.2 allow remote attackers to cause a denial of service or possibly have unspecified other…"
    },
    {
      "cve": "CVE-2016-1903",
      "sev": "critical",
      "kev": false,
      "title": "The gdImageRotateInterpolated function in ext/gd/libgd/gd_interpolation.c in PHP…",
      "ranges": [
        {
          "lte": "5.5.30"
        },
        {
          "eq": "5.6.0"
        },
        {
          "eq": "5.6.1"
        },
        {
          "eq": "5.6.2"
        },
        {
          "eq": "5.6.3"
        },
        {
          "eq": "5.6.4"
        },
        {
          "eq": "5.6.5"
        },
        {
          "eq": "5.6.6"
        },
        {
          "eq": "5.6.7"
        },
        {
          "eq": "5.6.8"
        },
        {
          "eq": "5.6.9"
        },
        {
          "eq": "5.6.10"
        },
        {
          "eq": "5.6.11"
        },
        {
          "eq": "5.6.12"
        },
        {
          "eq": "5.6.13"
        },
        {
          "eq": "5.6.14"
        },
        {
          "eq": "5.6.15"
        },
        {
          "eq": "5.6.16"
        },
        {
          "eq": "7.0.0"
        },
        {
          "eq": "7.0.1"
        }
      ],
      "note": "NVD: The gdImageRotateInterpolated function in ext/gd/libgd/gd_interpolation.c in PHP before 5.5.31, 5.6.x before 5.6.17, and 7.x before 7.0.2 allows remote attackers…"
    },
    {
      "cve": "CVE-2016-1283",
      "sev": "critical",
      "kev": false,
      "title": "The pcre_compile2 function in pcre_compile.c in PCRE 8.38 mishandles the…",
      "ranges": [
        {
          "gte": "5.6.0",
          "lt": "5.6.32"
        },
        {
          "gte": "7.0.0",
          "lt": "7.0.25"
        },
        {
          "gte": "7.1.0",
          "lt": "7.1.11"
        }
      ],
      "note": "NVD: The pcre_compile2 function in pcre_compile.c in PCRE 8.38 mishandles the /((?:F?+(?:^(?(R)a+\\\"){99}-))(?J)(?'R'(?'R'<((?'RR'(?'R'\\){97)?J)?J)(?'R'(?'R'\\){99|(:(?|(?…"
    }
  ],
  "phpmyadmin": [
    {
      "cve": "CVE-2020-26935",
      "sev": "critical",
      "kev": false,
      "title": "An issue was discovered in SearchController in phpMyAdmin before 4.9.6 and 5.x before…",
      "ranges": [
        {
          "gte": "4.9.0",
          "lt": "4.9.6"
        },
        {
          "gte": "5.0.0",
          "lt": "5.0.3"
        }
      ],
      "note": "NVD: An issue was discovered in SearchController in phpMyAdmin before 4.9.6 and 5.x before 5.0.3."
    },
    {
      "cve": "CVE-2020-22452",
      "sev": "critical",
      "kev": false,
      "title": "SQL Injection vulnerability in function getTableCreationQuery in CreateAddField.php in…",
      "ranges": [
        {
          "gte": "5.0.0",
          "lt": "5.2.0"
        }
      ],
      "note": "NVD: SQL Injection vulnerability in function getTableCreationQuery in CreateAddField.php in phpMyAdmin 5.x before 5.2.0 via the tbl_storage_engine or tbl_collation…"
    },
    {
      "cve": "CVE-2020-22278",
      "sev": "high",
      "kev": false,
      "title": "phpMyAdmin through 5.0.2 allows CSV injection via Export Section.",
      "ranges": [
        {
          "lte": "5.0.2"
        }
      ],
      "note": "NVD: phpMyAdmin through 5.0.2 allows CSV injection via Export Section."
    },
    {
      "cve": "CVE-2020-10804",
      "sev": "high",
      "kev": false,
      "title": "In phpMyAdmin 4.x before 4.9.5 and 5.x before 5.0.2, a SQL injection vulnerability was…",
      "ranges": [
        {
          "gte": "4.0.0",
          "lt": "4.9.5"
        },
        {
          "gte": "5.0.0",
          "lt": "5.0.2"
        }
      ],
      "note": "NVD: In phpMyAdmin 4.x before 4.9.5 and 5.x before 5.0.2, a SQL injection vulnerability was found in retrieval of the current username (in…"
    },
    {
      "cve": "CVE-2020-10802",
      "sev": "high",
      "kev": false,
      "title": "In phpMyAdmin 4.x before 4.9.5 and 5.x before 5.0.2, a SQL injection vulnerability has…",
      "ranges": [
        {
          "gte": "4.0.0",
          "lt": "4.9.5"
        },
        {
          "gte": "5.0.0",
          "lt": "5.0.2"
        }
      ],
      "note": "NVD: In phpMyAdmin 4.x before 4.9.5 and 5.x before 5.0.2, a SQL injection vulnerability has been discovered where certain parameters are not properly escaped when…"
    },
    {
      "cve": "CVE-2020-5504",
      "sev": "high",
      "kev": false,
      "title": "In phpMyAdmin 4 before 4.9.4 and 5 before 5.0.1, SQL injection exists in the user…",
      "ranges": [
        {
          "gte": "4.0.0",
          "lt": "4.9.4"
        },
        {
          "gte": "5.0.0",
          "lt": "5.0.1"
        }
      ],
      "note": "NVD: In phpMyAdmin 4 before 4.9.4 and 5 before 5.0.1, SQL injection exists in the user accounts page."
    },
    {
      "cve": "CVE-2019-19617",
      "sev": "critical",
      "kev": false,
      "title": "phpMyAdmin before 4.9.2 does not escape certain Git information, related to…",
      "ranges": [
        {
          "lt": "4.9.2"
        }
      ],
      "note": "NVD: phpMyAdmin before 4.9.2 does not escape certain Git information, related to libraries/classes/Display/GitRevision.php and libraries/classes/Footer.php."
    },
    {
      "cve": "CVE-2019-18622",
      "sev": "critical",
      "kev": false,
      "title": "An issue was discovered in phpMyAdmin before 4.9.2.",
      "ranges": [
        {
          "lt": "4.9.2"
        }
      ],
      "note": "NVD: An issue was discovered in phpMyAdmin before 4.9.2."
    },
    {
      "cve": "CVE-2019-11768",
      "sev": "critical",
      "kev": false,
      "title": "An issue was discovered in phpMyAdmin before 4.9.0.1.",
      "ranges": [
        {
          "lt": "4.9.0.1"
        }
      ],
      "note": "NVD: An issue was discovered in phpMyAdmin before 4.9.0.1."
    },
    {
      "cve": "CVE-2019-6798",
      "sev": "critical",
      "kev": false,
      "title": "An issue was discovered in phpMyAdmin before 4.8.5.",
      "ranges": [
        {
          "gte": "4.5.0",
          "lte": "4.8.4"
        }
      ],
      "note": "NVD: An issue was discovered in phpMyAdmin before 4.8.5."
    },
    {
      "cve": "CVE-2018-19969",
      "sev": "high",
      "kev": false,
      "title": "phpMyAdmin 4.7.x and 4.8.x versions prior to 4.8.4 are affected by a series of CSRF…",
      "ranges": [
        {
          "gte": "4.7.0",
          "lte": "4.7.6"
        },
        {
          "gte": "4.8.0",
          "lt": "4.8.4"
        }
      ],
      "note": "NVD: phpMyAdmin 4.7.x and 4.8.x versions prior to 4.8.4 are affected by a series of CSRF flaws."
    },
    {
      "cve": "CVE-2018-12613",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in phpMyAdmin 4.8.x before 4.8.2, in which an attacker can…",
      "ranges": [
        {
          "gte": "4.8.0",
          "lt": "4.8.2"
        }
      ],
      "note": "NVD: An issue was discovered in phpMyAdmin 4.8.x before 4.8.2, in which an attacker can include (view and potentially execute) files on the server."
    },
    {
      "cve": "CVE-2018-10188",
      "sev": "high",
      "kev": false,
      "title": "phpMyAdmin 4.8.0 before 4.8.0-1 has CSRF, allowing an attacker to execute arbitrary…",
      "ranges": [
        {
          "eq": "4.8.0"
        }
      ],
      "note": "NVD: phpMyAdmin 4.8.0 before 4.8.0-1 has CSRF, allowing an attacker to execute arbitrary SQL statements, related to js/db_operations.js, js/tbl_operations.js,…"
    },
    {
      "cve": "CVE-2017-1000499",
      "sev": "high",
      "kev": false,
      "title": "phpMyAdmin versions 4.7.x (prior to 4.7.6.1/4.7.7) are vulnerable to a CSRF weakness.",
      "ranges": [
        {
          "gte": "4.7.0",
          "lt": "4.7.7"
        }
      ],
      "note": "NVD: phpMyAdmin versions 4.7.x (prior to 4.7.6.1/4.7.7) are vulnerable to a CSRF weakness."
    },
    {
      "cve": "CVE-2017-1000018",
      "sev": "high",
      "kev": false,
      "title": "phpMyAdmin 4.0, 4.4., and 4.6 are vulnerable to a DOS attack in the replication status…",
      "ranges": [
        {
          "gte": "4.0.0",
          "lt": "4.0.10.19"
        },
        {
          "gte": "4.4.0",
          "lt": "4.4.15.10"
        },
        {
          "gte": "4.6.0",
          "lt": "4.6.6"
        }
      ],
      "note": "NVD: phpMyAdmin 4.0, 4.4., and 4.6 are vulnerable to a DOS attack in the replication status by using a specially crafted table name"
    },
    {
      "cve": "CVE-2017-1000017",
      "sev": "high",
      "kev": false,
      "title": "phpMyAdmin 4.0, 4.4 and 4.6 are vulnerable to a weakness where a user with appropriate…",
      "ranges": [
        {
          "gte": "4.0.0",
          "lt": "4.0.10.19"
        },
        {
          "gte": "4.4.0",
          "lte": "4.4.15.10"
        },
        {
          "gte": "4.6.0",
          "lte": "4.6.6"
        }
      ],
      "note": "NVD: phpMyAdmin 4.0, 4.4 and 4.6 are vulnerable to a weakness where a user with appropriate permissions is able to connect to an arbitrary MySQL server"
    },
    {
      "cve": "CVE-2017-1000016",
      "sev": "high",
      "kev": false,
      "title": "A weakness was discovered where an attacker can inject arbitrary values in to the…",
      "ranges": [
        {
          "eq": "4.6.0"
        },
        {
          "eq": "4.6.1"
        },
        {
          "eq": "4.6.2"
        },
        {
          "eq": "4.6.3"
        },
        {
          "eq": "4.6.4"
        },
        {
          "eq": "4.6.5"
        },
        {
          "eq": "4.6.5.1"
        },
        {
          "eq": "4.6.5.2"
        }
      ],
      "note": "NVD: A weakness was discovered where an attacker can inject arbitrary values in to the browser cookies."
    },
    {
      "cve": "CVE-2017-18264",
      "sev": "critical",
      "kev": false,
      "title": "An issue was discovered in libraries/common.inc.php in phpMyAdmin 4.0 before…",
      "ranges": [
        {
          "gte": "4.0.0",
          "lt": "4.0.10.20"
        },
        {
          "gte": "4.4.0",
          "lte": "4.4.15.10"
        },
        {
          "gte": "4.6.0",
          "lte": "4.6.6"
        },
        {
          "eq": "4.7.0"
        }
      ],
      "note": "NVD: An issue was discovered in libraries/common.inc.php in phpMyAdmin 4.0 before 4.0.10.20, 4.4.x, 4.6.x, and 4.7.0 prereleases."
    },
    {
      "cve": "CVE-2016-9863",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in phpMyAdmin.",
      "ranges": [
        {
          "eq": "4.6.0"
        },
        {
          "eq": "4.6.1"
        },
        {
          "eq": "4.6.2"
        },
        {
          "eq": "4.6.3"
        },
        {
          "eq": "4.6.4"
        }
      ],
      "note": "NVD: An issue was discovered in phpMyAdmin."
    },
    {
      "cve": "CVE-2016-9862",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in phpMyAdmin.",
      "ranges": [
        {
          "eq": "4.6.0"
        },
        {
          "eq": "4.6.1"
        },
        {
          "eq": "4.6.2"
        },
        {
          "eq": "4.6.3"
        },
        {
          "eq": "4.6.4"
        }
      ],
      "note": "NVD: An issue was discovered in phpMyAdmin."
    },
    {
      "cve": "CVE-2016-6617",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in phpMyAdmin.",
      "ranges": [
        {
          "eq": "4.6.0"
        },
        {
          "eq": "4.6.1"
        },
        {
          "eq": "4.6.2"
        },
        {
          "eq": "4.6.3"
        }
      ],
      "note": "NVD: An issue was discovered in phpMyAdmin."
    },
    {
      "cve": "CVE-2016-6616",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in phpMyAdmin.",
      "ranges": [
        {
          "eq": "4.4.0"
        },
        {
          "eq": "4.4.1"
        },
        {
          "eq": "4.4.1.1"
        },
        {
          "eq": "4.4.2"
        },
        {
          "eq": "4.4.3"
        },
        {
          "eq": "4.4.4"
        },
        {
          "eq": "4.4.5"
        },
        {
          "eq": "4.4.6"
        },
        {
          "eq": "4.4.6.1"
        },
        {
          "eq": "4.4.7"
        },
        {
          "eq": "4.4.8"
        },
        {
          "eq": "4.4.9"
        },
        {
          "eq": "4.4.10"
        },
        {
          "eq": "4.4.11"
        },
        {
          "eq": "4.4.12"
        },
        {
          "eq": "4.4.13"
        },
        {
          "eq": "4.4.13.1"
        },
        {
          "eq": "4.4.14.1"
        },
        {
          "eq": "4.4.15"
        },
        {
          "eq": "4.4.15.1"
        },
        {
          "eq": "4.4.15.2"
        },
        {
          "eq": "4.4.15.3"
        },
        {
          "eq": "4.4.15.4"
        },
        {
          "eq": "4.4.15.5"
        },
        {
          "eq": "4.4.15.6"
        },
        {
          "eq": "4.4.15.7"
        },
        {
          "eq": "4.6.0"
        },
        {
          "eq": "4.6.1"
        },
        {
          "eq": "4.6.2"
        },
        {
          "eq": "4.6.3"
        }
      ],
      "note": "NVD: An issue was discovered in phpMyAdmin."
    },
    {
      "cve": "CVE-2016-5703",
      "sev": "critical",
      "kev": false,
      "title": "SQL injection vulnerability in libraries/central_columns.lib.php in phpMyAdmin 4.4.x…",
      "ranges": [
        {
          "eq": "4.4.0"
        },
        {
          "eq": "4.4.1"
        },
        {
          "eq": "4.4.1.1"
        },
        {
          "eq": "4.4.2"
        },
        {
          "eq": "4.4.3"
        },
        {
          "eq": "4.4.4"
        },
        {
          "eq": "4.4.5"
        },
        {
          "eq": "4.4.6"
        },
        {
          "eq": "4.4.6.1"
        },
        {
          "eq": "4.4.7"
        },
        {
          "eq": "4.4.8"
        },
        {
          "eq": "4.4.9"
        },
        {
          "eq": "4.4.10"
        },
        {
          "eq": "4.4.11"
        },
        {
          "eq": "4.4.12"
        },
        {
          "eq": "4.4.13"
        },
        {
          "eq": "4.4.13.1"
        },
        {
          "eq": "4.4.14.1"
        },
        {
          "eq": "4.4.15"
        },
        {
          "eq": "4.4.15.1"
        },
        {
          "eq": "4.4.15.2"
        },
        {
          "eq": "4.4.15.3"
        },
        {
          "eq": "4.4.15.4"
        },
        {
          "eq": "4.4.15.5"
        },
        {
          "eq": "4.4.15.6"
        },
        {
          "eq": "4.6.0"
        },
        {
          "eq": "4.6.1"
        },
        {
          "eq": "4.6.2"
        }
      ],
      "note": "NVD: SQL injection vulnerability in libraries/central_columns.lib.php in phpMyAdmin 4.4.x before 4.4.15.7 and 4.6.x before 4.6.3 allows remote attackers to execute…"
    }
  ],
  "rails": [
    {
      "cve": "CVE-2026-33202",
      "sev": "critical",
      "kev": false,
      "title": "Active Storage allows users to attach cloud and local files in Rails applications.",
      "ranges": [
        {
          "lt": "7.2.3.1"
        },
        {
          "gte": "8.0.0",
          "lt": "8.0.4.1"
        },
        {
          "gte": "8.1.0",
          "lt": "8.1.2.1"
        }
      ],
      "note": "NVD: Active Storage allows users to attach cloud and local files in Rails applications."
    },
    {
      "cve": "CVE-2026-33195",
      "sev": "critical",
      "kev": false,
      "title": "Active Storage allows users to attach cloud and local files in Rails applications.",
      "ranges": [
        {
          "lt": "7.2.3.1"
        },
        {
          "gte": "8.0.0",
          "lt": "8.0.4.1"
        },
        {
          "gte": "8.1.0",
          "lt": "8.1.2.1"
        }
      ],
      "note": "NVD: Active Storage allows users to attach cloud and local files in Rails applications."
    },
    {
      "cve": "CVE-2026-33176",
      "sev": "high",
      "kev": false,
      "title": "Active Support is a toolkit of support libraries and Ruby core extensions extracted…",
      "ranges": [
        {
          "lt": "7.2.3.1"
        },
        {
          "gte": "8.0.0",
          "lt": "8.0.4.1"
        },
        {
          "gte": "8.1.0",
          "lt": "8.1.2.1"
        }
      ],
      "note": "NVD: Active Support is a toolkit of support libraries and Ruby core extensions extracted from the Rails framework."
    },
    {
      "cve": "CVE-2026-33174",
      "sev": "high",
      "kev": false,
      "title": "Active Storage allows users to attach cloud and local files in Rails applications.",
      "ranges": [
        {
          "lt": "7.2.3.1"
        },
        {
          "gte": "8.0.0",
          "lt": "8.0.4.1"
        },
        {
          "gte": "8.1.0",
          "lt": "8.1.2.1"
        }
      ],
      "note": "NVD: Active Storage allows users to attach cloud and local files in Rails applications."
    },
    {
      "cve": "CVE-2024-26142",
      "sev": "high",
      "kev": false,
      "title": "Rails is a web-application framework.",
      "ranges": [
        {
          "gte": "7.1.0",
          "lt": "7.1.3.1"
        }
      ],
      "note": "NVD: Rails is a web-application framework."
    },
    {
      "cve": "CVE-2023-22795",
      "sev": "high",
      "kev": false,
      "title": "A regular expression based DoS vulnerability in Action Dispatch <6.1.7.1 and <7.0.4.1…",
      "ranges": [
        {
          "lt": "6.1.7.1"
        },
        {
          "gte": "7.0.0",
          "lt": "7.0.4.1"
        }
      ],
      "note": "NVD: A regular expression based DoS vulnerability in Action Dispatch <6.1.7.1 and <7.0.4.1 related to the If-None-Match header."
    },
    {
      "cve": "CVE-2023-22792",
      "sev": "high",
      "kev": false,
      "title": "A regular expression based DoS vulnerability in Action Dispatch <6.0.6.1,< 6.1.7.1,…",
      "ranges": [
        {
          "gte": "3.0.0",
          "lt": "6.0.6.1"
        },
        {
          "gte": "6.1.0",
          "lt": "6.1.7.1"
        },
        {
          "gte": "7.0.0",
          "lt": "7.0.4.1"
        }
      ],
      "note": "NVD: A regular expression based DoS vulnerability in Action Dispatch <6.0.6.1,< 6.1.7.1, and <7.0.4.1."
    },
    {
      "cve": "CVE-2022-23634",
      "sev": "high",
      "kev": false,
      "title": "Puma is a Ruby/Rack web server built for parallelism.",
      "ranges": [
        {
          "gte": "5.0.0",
          "lt": "5.2.6.2"
        },
        {
          "gte": "6.0.0",
          "lt": "6.0.4.6"
        },
        {
          "gte": "6.1.0",
          "lt": "6.1.4.6"
        },
        {
          "gte": "7.0.0",
          "lt": "7.0.2.2"
        }
      ],
      "note": "NVD: Puma is a Ruby/Rack web server built for parallelism."
    },
    {
      "cve": "CVE-2022-23633",
      "sev": "high",
      "kev": false,
      "title": "Action Pack is a framework for handling and responding to web requests.",
      "ranges": [
        {
          "gte": "5.0.0",
          "lt": "5.2.6.2"
        },
        {
          "gte": "6.0.0",
          "lt": "6.0.4.6"
        },
        {
          "gte": "6.1.0",
          "lt": "6.1.4.6"
        },
        {
          "gte": "7.0.0",
          "lt": "7.0.2.2"
        }
      ],
      "note": "NVD: Action Pack is a framework for handling and responding to web requests."
    },
    {
      "cve": "CVE-2021-22904",
      "sev": "high",
      "kev": false,
      "title": "The actionpack ruby gem before 6.1.3.2, 6.0.3.7, 5.2.4.6, 5.2.6 suffers from a…",
      "ranges": [
        {
          "lt": "5.2.4.6"
        },
        {
          "gte": "5.2.5",
          "lt": "5.2.6"
        },
        {
          "gte": "6.0.0",
          "lt": "6.0.3.7"
        },
        {
          "gte": "6.1.0",
          "lt": "6.1.3.2"
        }
      ],
      "note": "NVD: The actionpack ruby gem before 6.1.3.2, 6.0.3.7, 5.2.4.6, 5.2.6 suffers from a possible denial of service vulnerability in the Token Authentication logic in Action…"
    },
    {
      "cve": "CVE-2021-22902",
      "sev": "high",
      "kev": false,
      "title": "The actionpack ruby gem (a framework for handling and responding to web requests in…",
      "ranges": [
        {
          "gte": "6.0.0",
          "lt": "6.0.3.7"
        },
        {
          "gte": "6.1.0",
          "lt": "6.1.0.2"
        }
      ],
      "note": "NVD: The actionpack ruby gem (a framework for handling and responding to web requests in Rails) before 6.0.3.7, 6.1.3.2 suffers from a possible denial of service…"
    },
    {
      "cve": "CVE-2021-22885",
      "sev": "high",
      "kev": false,
      "title": "A possible information disclosure / unintended method execution vulnerability in…",
      "ranges": [
        {
          "gte": "5.2.0.0",
          "lt": "5.2.4.6"
        },
        {
          "gte": "6.0.0.0",
          "lt": "6.0.3.7"
        },
        {
          "gte": "6.1.0.0",
          "lt": "6.1.3.1"
        }
      ],
      "note": "NVD: A possible information disclosure / unintended method execution vulnerability in Action Pack >= 2.0.0 when using the `redirect_to` or `polymorphic_url`helper with…"
    },
    {
      "cve": "CVE-2021-22880",
      "sev": "high",
      "kev": false,
      "title": "The PostgreSQL adapter in Active Record before 6.1.2.1, 6.0.3.5, 5.2.4.5 suffers from…",
      "ranges": [
        {
          "gte": "4.2.0",
          "lt": "5.2.4.5"
        },
        {
          "gte": "6.0.0",
          "lt": "6.0.3.5"
        },
        {
          "gte": "6.1.0",
          "lt": "6.1.2.1"
        }
      ],
      "note": "NVD: The PostgreSQL adapter in Active Record before 6.1.2.1, 6.0.3.5, 5.2.4.5 suffers from a regular expression denial of service (REDoS) vulnerability."
    },
    {
      "cve": "CVE-2020-8165",
      "sev": "critical",
      "kev": false,
      "title": "A deserialization of untrusted data vulnernerability exists in rails < 5.2.4.3, rails…",
      "ranges": [
        {
          "lt": "5.2.4.3"
        },
        {
          "gte": "6.0.0",
          "lt": "6.0.3.1"
        }
      ],
      "note": "NVD: A deserialization of untrusted data vulnernerability exists in rails < 5.2.4.3, rails < 6.0.3.1 that can allow an attacker to unmarshal user-provided objects in…"
    },
    {
      "cve": "CVE-2020-8164",
      "sev": "high",
      "kev": false,
      "title": "A deserialization of untrusted data vulnerability exists in rails < 5.2.4.3, rails <…",
      "ranges": [
        {
          "lt": "5.2.4.3"
        },
        {
          "gte": "6.0.0",
          "lt": "6.0.3.1"
        }
      ],
      "note": "NVD: A deserialization of untrusted data vulnerability exists in rails < 5.2.4.3, rails < 6.0.3.1 which can allow an attacker to supply information can be inadvertently…"
    },
    {
      "cve": "CVE-2020-8163",
      "sev": "high",
      "kev": false,
      "title": "The is a code injection vulnerability in versions of Rails prior to 5.0.1 that…",
      "ranges": [
        {
          "lt": "5.0.1"
        }
      ],
      "note": "NVD: The is a code injection vulnerability in versions of Rails prior to 5.0.1 that wouldallow an attacker who controlled the `locals` argument of a `render` call to…"
    },
    {
      "cve": "CVE-2020-8162",
      "sev": "high",
      "kev": false,
      "title": "A client side enforcement of server side security vulnerability exists in rails <…",
      "ranges": [
        {
          "lt": "5.2.4.2"
        },
        {
          "gte": "6.0.0",
          "lt": "6.0.3.1"
        }
      ],
      "note": "NVD: A client side enforcement of server side security vulnerability exists in rails < 5.2.4.2 and rails < 6.0.3.1 ActiveStorage's S3 adapter that allows the…"
    },
    {
      "cve": "CVE-2019-5420",
      "sev": "critical",
      "kev": false,
      "title": "A remote code execution vulnerability in development mode Rails <5.2.2.1, <6.0.0.beta3…",
      "ranges": [
        {
          "lt": "5.2.2.1"
        },
        {
          "eq": "6.0.0"
        }
      ],
      "note": "NVD: A remote code execution vulnerability in development mode Rails <5.2.2.1, <6.0.0.beta3 can allow an attacker to guess the automatically generated development mode…"
    },
    {
      "cve": "CVE-2019-5419",
      "sev": "high",
      "kev": false,
      "title": "There is a possible denial of service vulnerability in Action View (Rails) <5.2.2.1,…",
      "ranges": [
        {
          "lt": "4.2.11.1"
        },
        {
          "gte": "5.0.0",
          "lt": "5.0.7.2"
        },
        {
          "gte": "5.1.0",
          "lt": "5.1.6.2"
        },
        {
          "gte": "5.2.0",
          "lt": "5.2.2.1"
        }
      ],
      "note": "NVD: There is a possible denial of service vulnerability in Action View (Rails) <5.2.2.1, <5.1.6.2, <5.0.7.2, <4.2.11.1 where specially crafted accept headers can cause…"
    },
    {
      "cve": "CVE-2019-5418",
      "sev": "high",
      "kev": true,
      "title": "There is a File Content Disclosure vulnerability in Action View <5.2.2.1, <5.1.6.2,…",
      "ranges": [
        {
          "gte": "3.0.0",
          "lt": "4.2.11.1"
        },
        {
          "gte": "5.0.0",
          "lt": "5.0.7.2"
        },
        {
          "gte": "5.1.0",
          "lt": "5.1.6.2"
        },
        {
          "gte": "5.2.0",
          "lt": "5.2.2.1"
        }
      ],
      "note": "NVD: There is a File Content Disclosure vulnerability in Action View <5.2.2.1, <5.1.6.2, <5.0.7.2, <4.2.11.1 and v3 where specially… — CISA KEV (actively exploited)"
    },
    {
      "cve": "CVE-2018-16476",
      "sev": "high",
      "kev": false,
      "title": "A Broken Access Control vulnerability in Active Job versions >= 4.2.0 allows an…",
      "ranges": [
        {
          "gte": "4.2.0",
          "lt": "4.2.11"
        },
        {
          "gte": "5.0.0",
          "lt": "5.0.7.1"
        },
        {
          "gte": "5.1.0",
          "lt": "5.1.6.1"
        },
        {
          "gte": "5.2.0",
          "lt": "5.2.1.1"
        }
      ],
      "note": "NVD: A Broken Access Control vulnerability in Active Job versions >= 4.2.0 allows an attacker to craft user input which can cause Active Job to deserialize it using…"
    },
    {
      "cve": "CVE-2017-17920",
      "sev": "high",
      "kev": false,
      "title": "SQL injection vulnerability in the 'reorder' method in Ruby on Rails 5.1.4 and earlier…",
      "ranges": [
        {
          "lte": "5.1.4"
        }
      ],
      "note": "NVD: SQL injection vulnerability in the 'reorder' method in Ruby on Rails 5.1.4 and earlier allows remote attackers to execute arbitrary SQL commands via the 'name'…"
    },
    {
      "cve": "CVE-2017-17919",
      "sev": "high",
      "kev": false,
      "title": "SQL injection vulnerability in the 'order' method in Ruby on Rails 5.1.4 and earlier…",
      "ranges": [
        {
          "lte": "5.1.4"
        }
      ],
      "note": "NVD: SQL injection vulnerability in the 'order' method in Ruby on Rails 5.1.4 and earlier allows remote attackers to execute arbitrary SQL commands via the 'id desc'…"
    },
    {
      "cve": "CVE-2017-17917",
      "sev": "high",
      "kev": false,
      "title": "SQL injection vulnerability in the 'where' method in Ruby on Rails 5.1.4 and earlier…",
      "ranges": [
        {
          "lte": "5.1.4"
        }
      ],
      "note": "NVD: SQL injection vulnerability in the 'where' method in Ruby on Rails 5.1.4 and earlier allows remote attackers to execute arbitrary SQL commands via the 'id'…"
    },
    {
      "cve": "CVE-2017-17916",
      "sev": "high",
      "kev": false,
      "title": "SQL injection vulnerability in the 'find_by' method in Ruby on Rails 5.1.4 and earlier…",
      "ranges": [
        {
          "lte": "5.1.4"
        }
      ],
      "note": "NVD: SQL injection vulnerability in the 'find_by' method in Ruby on Rails 5.1.4 and earlier allows remote attackers to execute arbitrary SQL commands via the 'name'…"
    },
    {
      "cve": "CVE-2016-6317",
      "sev": "high",
      "kev": false,
      "title": "Action Record in Ruby on Rails 4.2.x before 4.2.7.1 does not properly consider…",
      "ranges": [
        {
          "eq": "4.2.0"
        },
        {
          "eq": "4.2.1"
        },
        {
          "eq": "4.2.2"
        },
        {
          "eq": "4.2.3"
        },
        {
          "eq": "4.2.4"
        },
        {
          "eq": "4.2.5"
        },
        {
          "eq": "4.2.5.1"
        },
        {
          "eq": "4.2.5.2"
        },
        {
          "eq": "4.2.6"
        },
        {
          "eq": "4.2.7"
        }
      ],
      "note": "NVD: Action Record in Ruby on Rails 4.2.x before 4.2.7.1 does not properly consider differences in parameter handling between the Active Record component and the JSON…"
    },
    {
      "cve": "CVE-2016-0752",
      "sev": "high",
      "kev": true,
      "title": "Directory traversal vulnerability in Action View in Ruby on Rails before 3.2.22.1,…",
      "ranges": [
        {
          "lt": "3.2.22.1"
        },
        {
          "gte": "4.0.0",
          "lt": "4.1.14.1"
        },
        {
          "gte": "4.2.0",
          "lt": "4.2.5.1"
        },
        {
          "eq": "5.0.0"
        }
      ],
      "note": "NVD: Directory traversal vulnerability in Action View in Ruby on Rails before 3.2.22.1, 4.0.x and 4.1.x before 4.1.14.1, 4.2.x before… — CISA KEV (actively exploited)"
    }
  ],
  "spring": [
    {
      "cve": "CVE-2026-59313",
      "sev": "critical",
      "kev": false,
      "title": "Spring MVC applications using the functional web framework are vulnerable to stream…",
      "ranges": [
        {
          "gte": "5.3.0",
          "lte": "5.3.49"
        },
        {
          "gte": "6.0.0",
          "lte": "6.0.30"
        },
        {
          "gte": "6.1.0",
          "lte": "6.1.28"
        },
        {
          "gte": "6.2.0",
          "lte": "6.2.19"
        },
        {
          "gte": "7.0.0",
          "lte": "7.0.8"
        }
      ],
      "note": "NVD: Spring MVC applications using the functional web framework are vulnerable to stream corruption when using Server-Sent Events (SSE)."
    },
    {
      "cve": "CVE-2026-59283",
      "sev": "critical",
      "kev": false,
      "title": "Applications that evaluate Spring Expression Language (SpEL) expressions using…",
      "ranges": [
        {
          "lt": "5.2.26"
        },
        {
          "gte": "5.3.0",
          "lt": "5.3.50"
        },
        {
          "gte": "6.0.0",
          "lt": "6.0.31"
        },
        {
          "gte": "6.1.0",
          "lt": "6.1.29"
        },
        {
          "gte": "6.2.0",
          "lt": "6.2.20"
        },
        {
          "gte": "7.0.0",
          "lt": "7.0.8.1"
        }
      ],
      "note": "NVD: Applications that evaluate Spring Expression Language (SpEL) expressions using SimpleEvaluationContext may be vulnerable to a safety guard bypass when the SpEL…"
    },
    {
      "cve": "CVE-2026-59282",
      "sev": "high",
      "kev": false,
      "title": "Spring Framework applications that use Spring's data binding infrastructure to apply…",
      "ranges": [
        {
          "lt": "5.2.26"
        },
        {
          "gte": "5.3.0",
          "lt": "5.3.50"
        },
        {
          "gte": "6.0.0",
          "lt": "6.0.31"
        },
        {
          "gte": "6.1.0",
          "lt": "6.1.29"
        },
        {
          "gte": "6.2.0",
          "lt": "6.2.20"
        },
        {
          "gte": "7.0.0",
          "lt": "7.0.8.1"
        }
      ],
      "note": "NVD: Spring Framework applications that use Spring's data binding infrastructure to apply user-supplied property paths onto a target object may be vulnerable to a…"
    },
    {
      "cve": "CVE-2026-47893",
      "sev": "high",
      "kev": false,
      "title": "A Spring WebFlux application that supports WebSocket connections may expose indirectly…",
      "ranges": [
        {
          "lt": "5.2.26"
        },
        {
          "gte": "5.3.0",
          "lt": "5.3.50"
        },
        {
          "gte": "6.0.0",
          "lt": "6.0.31"
        },
        {
          "gte": "6.1.0",
          "lt": "6.1.29"
        },
        {
          "gte": "6.2.0",
          "lt": "6.2.20"
        },
        {
          "gte": "7.0.0",
          "lt": "7.0.8.1"
        }
      ],
      "note": "NVD: A Spring WebFlux application that supports WebSocket connections may expose indirectly sensitive user information by including request headers in an exception…"
    },
    {
      "cve": "CVE-2026-47892",
      "sev": "critical",
      "kev": false,
      "title": "A WebFlux application using functional endpoints and deployed with DispatcherServlet…",
      "ranges": [
        {
          "gte": "5.2.5",
          "lt": "5.2.26"
        },
        {
          "gte": "5.3.0",
          "lt": "5.3.50"
        },
        {
          "gte": "6.0.0",
          "lt": "6.0.31"
        },
        {
          "gte": "6.1.0",
          "lt": "6.1.29"
        },
        {
          "gte": "6.2.0",
          "lt": "6.2.20"
        },
        {
          "gte": "7.0.0",
          "lt": "7.0.8.1"
        }
      ],
      "note": "NVD: A WebFlux application using functional endpoints and deployed with DispatcherServlet may be vulnerable to a header predicate bypass in a pre-flight request."
    },
    {
      "cve": "CVE-2026-47891",
      "sev": "critical",
      "kev": false,
      "title": "A Spring WebFlux application that relies on the Aalto XML processor to parse XML input…",
      "ranges": [
        {
          "lt": "5.2.26"
        },
        {
          "gte": "5.3.0",
          "lt": "5.3.50"
        },
        {
          "gte": "6.0.0",
          "lt": "6.0.31"
        },
        {
          "gte": "6.1.0",
          "lt": "6.1.29"
        },
        {
          "gte": "6.2.0",
          "lt": "6.2.20"
        },
        {
          "gte": "7.0.0",
          "lt": "7.0.8.1"
        }
      ],
      "note": "NVD: A Spring WebFlux application that relies on the Aalto XML processor to parse XML input does not correctly enforce the maxInMemorySize limit."
    },
    {
      "cve": "CVE-2026-47890",
      "sev": "critical",
      "kev": false,
      "title": "Spring MVC and WebFlux applications are vulnerable to stream corruption when using…",
      "ranges": [
        {
          "gte": "6.2.0",
          "lt": "6.2.20"
        },
        {
          "gte": "7.0.0",
          "lt": "7.0.8.1"
        }
      ],
      "note": "NVD: Spring MVC and WebFlux applications are vulnerable to stream corruption when using Server-Sent Events (SSE) with view fragments."
    },
    {
      "cve": "CVE-2026-47889",
      "sev": "high",
      "kev": false,
      "title": "A WebFlux application running on the Jetty 12 Core reactive adapter serializes…",
      "ranges": [
        {
          "gte": "6.2.0",
          "lt": "6.2.20"
        },
        {
          "gte": "7.0.0",
          "lt": "7.0.8.1"
        }
      ],
      "note": "NVD: A WebFlux application running on the Jetty 12 Core reactive adapter serializes response cookies without the sameSite attribute."
    },
    {
      "cve": "CVE-2026-47888",
      "sev": "high",
      "kev": false,
      "title": "A Spring RSocket application is exposed to a memory leak via a malformed SETUP frame.",
      "ranges": [
        {
          "gte": "5.2.0",
          "lt": "5.2.26"
        },
        {
          "gte": "5.3.0",
          "lt": "5.3.50"
        },
        {
          "gte": "6.0.0",
          "lt": "6.0.31"
        },
        {
          "gte": "6.1.0",
          "lt": "6.1.29"
        },
        {
          "gte": "6.2.0",
          "lt": "6.2.20"
        },
        {
          "gte": "7.0.0",
          "lt": "7.0.8.1"
        }
      ],
      "note": "NVD: A Spring RSocket application is exposed to a memory leak via a malformed SETUP frame."
    },
    {
      "cve": "CVE-2026-47886",
      "sev": "high",
      "kev": false,
      "title": "Applications that evaluate user-supplied Spring Expression Language (SpEL) expressions…",
      "ranges": [
        {
          "lt": "5.2.26"
        },
        {
          "gte": "5.3.0",
          "lt": "5.3.50"
        },
        {
          "gte": "6.0.0",
          "lt": "6.0.31"
        },
        {
          "gte": "6.1.0",
          "lt": "6.1.29"
        },
        {
          "gte": "6.2.0",
          "lt": "6.2.20"
        },
        {
          "gte": "7.0.0",
          "lt": "7.0.8.1"
        }
      ],
      "note": "NVD: Applications that evaluate user-supplied Spring Expression Language (SpEL) expressions may be vulnerable to a Denial of Service (DoS) attack when the power…"
    },
    {
      "cve": "CVE-2026-47885",
      "sev": "high",
      "kev": false,
      "title": "The PartEventHttpMessageReader in Spring WebFlux does not enforce the maxPartSize…",
      "ranges": [
        {
          "gte": "6.1.0",
          "lt": "6.1.29"
        },
        {
          "gte": "6.2.0",
          "lt": "6.2.20"
        },
        {
          "gte": "7.0.0",
          "lt": "7.0.8.1"
        }
      ],
      "note": "NVD: The PartEventHttpMessageReader in Spring WebFlux does not enforce the maxPartSize limit when maxInMemorySize is set to -1."
    },
    {
      "cve": "CVE-2026-47884",
      "sev": "critical",
      "kev": false,
      "title": "Use of XsltView in a Spring MVC application can result in SSRF and RCE attack if the…",
      "ranges": [
        {
          "lt": "5.2.26"
        },
        {
          "gte": "5.3.0",
          "lt": "5.3.50"
        },
        {
          "gte": "6.0.0",
          "lt": "6.0.31"
        },
        {
          "gte": "6.1.0",
          "lt": "6.1.29"
        },
        {
          "gte": "6.2.0",
          "lt": "6.2.20"
        },
        {
          "gte": "7.0.0",
          "lt": "7.0.8.1"
        }
      ],
      "note": "NVD: Use of XsltView in a Spring MVC application can result in SSRF and RCE attack if the application has an \"/**\" mapping that results in view rendering, and where the…"
    },
    {
      "cve": "CVE-2026-41855",
      "sev": "high",
      "kev": false,
      "title": "In an untrusted JMS environment, org.springframework.jms.support.converter.MappingJacks…",
      "ranges": [
        {
          "gte": "5.3.0",
          "lt": "5.3.49"
        },
        {
          "gte": "6.1.0",
          "lt": "6.1.28"
        },
        {
          "gte": "6.2.0",
          "lt": "6.2.18.1"
        },
        {
          "gte": "7.0.0",
          "lt": "7.0.7.1"
        }
      ],
      "note": "NVD: In an untrusted JMS environment, org.springframework.jms.support.converter.MappingJackson2MessageConverter and…"
    },
    {
      "cve": "CVE-2026-41850",
      "sev": "high",
      "kev": false,
      "title": "Applications that evaluate user-supplied Spring Expression Language (SpEL) expressions…",
      "ranges": [
        {
          "gte": "5.3.0",
          "lt": "5.3.49"
        },
        {
          "gte": "6.1.0",
          "lt": "6.1.28"
        },
        {
          "gte": "6.2.0",
          "lt": "6.2.18.1"
        },
        {
          "gte": "7.0.0",
          "lt": "7.0.7.1"
        }
      ],
      "note": "NVD: Applications that evaluate user-supplied Spring Expression Language (SpEL) expressions are vulnerable to an Algorithmic Denial of Service (DoS)."
    },
    {
      "cve": "CVE-2026-41849",
      "sev": "high",
      "kev": false,
      "title": "An integer overflow vulnerability exists in the evaluation logic of the Spring…",
      "ranges": [
        {
          "gte": "5.3.0",
          "lt": "5.3.49"
        }
      ],
      "note": "NVD: An integer overflow vulnerability exists in the evaluation logic of the Spring Expression Language (SpEL)."
    },
    {
      "cve": "CVE-2026-41845",
      "sev": "high",
      "kev": false,
      "title": "Due to incorrect escaping, the use of JavaScriptUtils.javaScriptEscape() may lead to…",
      "ranges": [
        {
          "gte": "5.3.0",
          "lt": "5.3.49"
        },
        {
          "gte": "6.1.0",
          "lt": "6.1.28"
        },
        {
          "gte": "6.2.0",
          "lt": "6.2.18.1"
        },
        {
          "gte": "7.0.0",
          "lt": "7.0.7.1"
        }
      ],
      "note": "NVD: Due to incorrect escaping, the use of JavaScriptUtils.javaScriptEscape() may lead to JavaScript code injection in the browser, potentially resulting in a…"
    },
    {
      "cve": "CVE-2026-41842",
      "sev": "high",
      "kev": false,
      "title": "Spring MVC and WebFlux applications are vulnerable to Denial of Service (DoS) attacks…",
      "ranges": [
        {
          "gte": "5.3.0",
          "lt": "5.3.49"
        },
        {
          "gte": "6.1.0",
          "lt": "6.1.28"
        },
        {
          "gte": "6.2.0",
          "lt": "6.2.18.1"
        },
        {
          "gte": "7.0.0",
          "lt": "7.0.7.1"
        }
      ],
      "note": "NVD: Spring MVC and WebFlux applications are vulnerable to Denial of Service (DoS) attacks when resolving static resources."
    },
    {
      "cve": "CVE-2024-22259",
      "sev": "high",
      "kev": false,
      "title": "Applications that use UriComponentsBuilder in Spring Framework to parse an externally…",
      "ranges": [
        {
          "lt": "5.3.33"
        },
        {
          "gte": "6.0.0",
          "lt": "6.0.18"
        },
        {
          "gte": "6.1.0",
          "lt": "6.1.5"
        }
      ],
      "note": "NVD: Applications that use UriComponentsBuilder in Spring Framework to parse an externally provided URL (e.g."
    },
    {
      "cve": "CVE-2024-22233",
      "sev": "high",
      "kev": false,
      "title": "In Spring Framework versions 6.0.15 and 6.1.2, it is possible for a user to provide…",
      "ranges": [
        {
          "eq": "6.0.15"
        },
        {
          "eq": "6.1.2"
        }
      ],
      "note": "NVD: In Spring Framework versions 6.0.15 and 6.1.2, it is possible for a user to provide specially crafted HTTP requests that may cause a denial-of-service (DoS)…"
    },
    {
      "cve": "CVE-2023-20860",
      "sev": "high",
      "kev": false,
      "title": "Spring Framework running version 6.0.0 - 6.0.6 or 5.3.0 - 5.3.25 using \"**\" as a…",
      "ranges": [
        {
          "gte": "5.3.0",
          "lt": "5.3.26"
        },
        {
          "gte": "6.0.0",
          "lt": "6.0.7"
        }
      ],
      "note": "NVD: Spring Framework running version 6.0.0 - 6.0.6 or 5.3.0 - 5.3.25 using \"**\" as a pattern in Spring Security configuration with the mvcRequestMatcher creates a…"
    },
    {
      "cve": "CVE-2022-22965",
      "sev": "critical",
      "kev": true,
      "title": "A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to…",
      "ranges": [
        {
          "lt": "5.2.20"
        },
        {
          "gte": "5.3.0",
          "lt": "5.3.18"
        }
      ],
      "note": "NVD: A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. — CISA KEV (actively exploited)"
    },
    {
      "cve": "CVE-2021-22118",
      "sev": "high",
      "kev": false,
      "title": "In Spring Framework, versions 5.2.x prior to 5.2.15 and versions 5.3.x prior to 5.3.7,…",
      "ranges": [
        {
          "gte": "5.2.0",
          "lt": "5.2.15"
        },
        {
          "gte": "5.3.0",
          "lt": "5.3.7"
        }
      ],
      "note": "NVD: In Spring Framework, versions 5.2.x prior to 5.2.15 and versions 5.3.x prior to 5.3.7, a WebFlux application is vulnerable to a privilege escalation: by…"
    },
    {
      "cve": "CVE-2020-5398",
      "sev": "high",
      "kev": false,
      "title": "In Spring Framework, versions 5.2.x prior to 5.2.3, versions 5.1.x prior to 5.1.13,…",
      "ranges": [
        {
          "gte": "5.0.0",
          "lt": "5.0.16"
        },
        {
          "gte": "5.1.0",
          "lt": "5.1.13"
        },
        {
          "gte": "5.2.0",
          "lt": "5.2.3"
        }
      ],
      "note": "NVD: In Spring Framework, versions 5.2.x prior to 5.2.3, versions 5.1.x prior to 5.1.13, and versions 5.0.x prior to 5.0.16, an application is vulnerable to a reflected…"
    },
    {
      "cve": "CVE-2018-15801",
      "sev": "high",
      "kev": false,
      "title": "Spring Security versions 5.1.x prior to 5.1.2 contain an authorization bypass…",
      "ranges": [
        {
          "gte": "5.1.0",
          "lt": "5.1.2"
        }
      ],
      "note": "NVD: Spring Security versions 5.1.x prior to 5.1.2 contain an authorization bypass vulnerability during JWT issuer validation."
    },
    {
      "cve": "CVE-2018-15756",
      "sev": "high",
      "kev": false,
      "title": "Spring Framework, version 5.1, versions 5.0.x prior to 5.0.10, versions 4.3.x prior to…",
      "ranges": [
        {
          "gte": "4.2.0",
          "lt": "4.3.20"
        },
        {
          "gte": "5.0.0",
          "lt": "5.0.10"
        },
        {
          "eq": "5.1.0"
        }
      ],
      "note": "NVD: Spring Framework, version 5.1, versions 5.0.x prior to 5.0.10, versions 4.3.x prior to 4.3.20, and older unsupported versions on the 4.2.x branch provide support…"
    },
    {
      "cve": "CVE-2018-11040",
      "sev": "high",
      "kev": false,
      "title": "Spring Framework, versions 5.0.x prior to 5.0.7 and 4.3.x prior to 4.3.18 and older…",
      "ranges": [
        {
          "lt": "4.3.18"
        },
        {
          "gte": "5.0.0",
          "lt": "5.0.7"
        }
      ],
      "note": "NVD: Spring Framework, versions 5.0.x prior to 5.0.7 and 4.3.x prior to 4.3.18 and older unsupported versions, allows web applications to enable cross-domain requests…"
    },
    {
      "cve": "CVE-2018-1275",
      "sev": "critical",
      "kev": false,
      "title": "Spring Framework, versions 5.0 prior to 5.0.5 and versions 4.3 prior to 4.3.16 and…",
      "ranges": [
        {
          "gte": "4.3.0",
          "lt": "4.3.16"
        },
        {
          "gte": "5.0.0",
          "lt": "5.0.5"
        }
      ],
      "note": "NVD: Spring Framework, versions 5.0 prior to 5.0.5 and versions 4.3 prior to 4.3.16 and older unsupported versions, allow applications to expose STOMP over WebSocket…"
    },
    {
      "cve": "CVE-2018-1272",
      "sev": "high",
      "kev": false,
      "title": "Spring Framework, versions 5.0 prior to 5.0.5 and versions 4.3 prior to 4.3.15 and…",
      "ranges": [
        {
          "gte": "4.3.0",
          "lt": "4.3.15"
        },
        {
          "gte": "5.0",
          "lt": "5.0.5"
        }
      ],
      "note": "NVD: Spring Framework, versions 5.0 prior to 5.0.5 and versions 4.3 prior to 4.3.15 and older unsupported versions, provide client-side support for multipart requests."
    },
    {
      "cve": "CVE-2018-1270",
      "sev": "critical",
      "kev": false,
      "title": "Spring Framework, versions 5.0 prior to 5.0.5 and versions 4.3 prior to 4.3.15 and…",
      "ranges": [
        {
          "lt": "4.3.16"
        },
        {
          "gte": "5.0.0",
          "lt": "5.0.5"
        }
      ],
      "note": "NVD: Spring Framework, versions 5.0 prior to 5.0.5 and versions 4.3 prior to 4.3.15 and older unsupported versions, allow applications to expose STOMP over WebSocket…"
    },
    {
      "cve": "CVE-2018-1258",
      "sev": "high",
      "kev": false,
      "title": "Spring Framework version 5.0.5 when used in combination with any versions of Spring…",
      "ranges": [
        {
          "eq": "5.0.5"
        }
      ],
      "note": "NVD: Spring Framework version 5.0.5 when used in combination with any versions of Spring Security contains an authorization bypass when using method security."
    },
    {
      "cve": "CVE-2016-1000027",
      "sev": "critical",
      "kev": false,
      "title": "Pivotal Spring Framework through 5.3.16 suffers from a potential remote code execution…",
      "ranges": [
        {
          "lt": "6.0.0"
        }
      ],
      "note": "NVD: Pivotal Spring Framework through 5.3.16 suffers from a potential remote code execution (RCE) issue if used for Java deserialization of untrusted data."
    },
    {
      "cve": "CVE-2016-9878",
      "sev": "high",
      "kev": false,
      "title": "An issue was discovered in Pivotal Spring Framework before 3.2.18, 4.2.x before 4.2.9,…",
      "ranges": [
        {
          "lte": "3.2.0"
        },
        {
          "eq": "4.2.0"
        },
        {
          "eq": "4.3.0"
        },
        {
          "eq": "3.2.1"
        },
        {
          "eq": "3.2.2"
        },
        {
          "eq": "3.2.3"
        },
        {
          "eq": "3.2.4"
        },
        {
          "eq": "3.2.5"
        },
        {
          "eq": "3.2.6"
        },
        {
          "eq": "3.2.7"
        },
        {
          "eq": "3.2.8"
        },
        {
          "eq": "3.2.9"
        },
        {
          "eq": "3.2.10"
        },
        {
          "eq": "3.2.11"
        },
        {
          "eq": "3.2.12"
        },
        {
          "eq": "3.2.13"
        },
        {
          "eq": "3.2.14"
        },
        {
          "eq": "3.2.15"
        },
        {
          "eq": "3.2.16"
        },
        {
          "eq": "3.2.17"
        },
        {
          "eq": "4.2.1"
        },
        {
          "eq": "4.2.2"
        },
        {
          "eq": "4.2.3"
        },
        {
          "eq": "4.2.4"
        },
        {
          "eq": "4.2.5"
        },
        {
          "eq": "4.2.6"
        },
        {
          "eq": "4.2.7"
        },
        {
          "eq": "4.2.8"
        },
        {
          "eq": "4.3.1"
        },
        {
          "eq": "4.3.2"
        },
        {
          "eq": "4.3.3"
        },
        {
          "eq": "4.3.4"
        }
      ],
      "note": "NVD: An issue was discovered in Pivotal Spring Framework before 3.2.18, 4.2.x before 4.2.9, and 4.3.x before 4.3.5."
    }
  ],
  "tomcat": [
    {
      "cve": "CVE-2026-68763",
      "sev": "high",
      "kev": false,
      "title": "Uncontrolled Resource Consumption vulnerability in Apache Tomcat via an allocation…",
      "ranges": [
        {
          "gte": "8.5.59",
          "lt": "9.0.121"
        },
        {
          "gte": "10.1.0",
          "lt": "10.1.58"
        },
        {
          "gte": "11.0.0",
          "lt": "11.0.25"
        }
      ],
      "note": "NVD: Uncontrolled Resource Consumption vulnerability in Apache Tomcat via an allocation leak in the HTTP/2 backlog tracking when a stream is reset This issue affects…"
    },
    {
      "cve": "CVE-2026-68569",
      "sev": "high",
      "kev": false,
      "title": "Improper Authentication vulnerability in Apache Tomcat meant that in some…",
      "ranges": [
        {
          "gte": "7.0.0",
          "lte": "7.0.109"
        },
        {
          "gte": "8.5.0",
          "lt": "9.0.121"
        },
        {
          "gte": "10.1.0",
          "lt": "10.1.58"
        },
        {
          "gte": "11.0.0",
          "lt": "11.0.25"
        }
      ],
      "note": "NVD: Improper Authentication vulnerability in Apache Tomcat meant that in some circumstances (e.g."
    },
    {
      "cve": "CVE-2026-68525",
      "sev": "critical",
      "kev": false,
      "title": "Incorrect Authorization vulnerability in Apache Tomcat's FORM authentication process…",
      "ranges": [
        {
          "gte": "7.0.0",
          "lte": "7.0.109"
        },
        {
          "gte": "8.5.0",
          "lt": "9.0.121"
        },
        {
          "gte": "10.1.0",
          "lt": "10.1.58"
        },
        {
          "gte": "11.0.0",
          "lt": "11.0.25"
        }
      ],
      "note": "NVD: Incorrect Authorization vulnerability in Apache Tomcat's FORM authentication process allows the bypassing of a security constraint that limits user has access to a…"
    },
    {
      "cve": "CVE-2026-66422",
      "sev": "high",
      "kev": false,
      "title": "Improper Authorization vulnerability in Apache Tomcat cause by security-role-ref…",
      "ranges": [
        {
          "gte": "7.0.97",
          "lte": "7.0.109"
        },
        {
          "gte": "8.5.46",
          "lt": "9.0.121"
        },
        {
          "gte": "10.1.0",
          "lt": "10.1.58"
        },
        {
          "gte": "11.0.0",
          "lt": "11.0.25"
        }
      ],
      "note": "NVD: Improper Authorization vulnerability in Apache Tomcat cause by security-role-ref definitions being incorrectly used as role aliases within the Realm in additional…"
    },
    {
      "cve": "CVE-2026-65927",
      "sev": "high",
      "kev": false,
      "title": "Off-by-one Error vulnerability in Apache Tomcat impacting the [N] flag on the rewrite…",
      "ranges": [
        {
          "gte": "8.5.0",
          "lt": "9.0.121"
        },
        {
          "gte": "10.1.0",
          "lt": "10.1.58"
        },
        {
          "gte": "11.0.0",
          "lt": "11.0.25"
        }
      ],
      "note": "NVD: Off-by-one Error vulnerability in Apache Tomcat impacting the [N] flag on the rewrite valves causes rewrite processing to restart at the second rule rather than…"
    },
    {
      "cve": "CVE-2026-65905",
      "sev": "critical",
      "kev": false,
      "title": "Authentication Bypass by Capture-replay vulnerability in Apache Tomcat's DIGEST…",
      "ranges": [
        {
          "gte": "7.0.30",
          "lte": "7.0.109"
        },
        {
          "gte": "8.5.0",
          "lt": "9.0.121"
        },
        {
          "gte": "10.1.0",
          "lt": "10.1.58"
        },
        {
          "gte": "11.0.0",
          "lt": "11.0.25"
        }
      ],
      "note": "NVD: Authentication Bypass by Capture-replay vulnerability in Apache Tomcat's DIGEST authenticator."
    },
    {
      "cve": "CVE-2026-65637",
      "sev": "critical",
      "kev": false,
      "title": "Improper Input Validation vulnerability in Apache Tomcat due to incomplete fix for…",
      "ranges": [
        {
          "gte": "9.0.115",
          "lt": "9.0.121"
        },
        {
          "gte": "10.1.53",
          "lt": "10.1.58"
        },
        {
          "gte": "11.0.20",
          "lt": "11.0.25"
        }
      ],
      "note": "NVD: Improper Input Validation vulnerability in Apache Tomcat due to incomplete fix for CVE-2026-32990."
    },
    {
      "cve": "CVE-2026-65183",
      "sev": "high",
      "kev": false,
      "title": "Time-of-check Time-of-use (TOCTOU) Race Condition vulnerability in Apache Tomcat when…",
      "ranges": [
        {
          "gte": "9.0.42",
          "lt": "9.0.121"
        },
        {
          "gte": "10.1.0",
          "lt": "10.1.58"
        },
        {
          "gte": "11.0.0",
          "lt": "11.0.25"
        }
      ],
      "note": "NVD: Time-of-check Time-of-use (TOCTOU) Race Condition vulnerability in Apache Tomcat when creating unix domain sockets allows an unauthorised local user to access the…"
    },
    {
      "cve": "CVE-2026-65182",
      "sev": "critical",
      "kev": false,
      "title": "Improper Access Control, Incorrect Authorization vulnerability in Apache Tomcat leads…",
      "ranges": [
        {
          "gte": "7.0.0",
          "lte": "7.0.109"
        },
        {
          "gte": "8.5.0",
          "lt": "9.0.121"
        },
        {
          "gte": "10.1.0",
          "lt": "10.1.58"
        },
        {
          "gte": "11.0.0",
          "lt": "11.0.25"
        }
      ],
      "note": "NVD: Improper Access Control, Incorrect Authorization vulnerability in Apache Tomcat leads to security constraint bypass if a constraint for a longer path is specified…"
    },
    {
      "cve": "CVE-2026-59084",
      "sev": "critical",
      "kev": false,
      "title": "Insufficient Technical Documentation vulnerability in Apache Tomcat since the…",
      "ranges": [
        {
          "gte": "7.0.100",
          "lte": "7.0.109"
        },
        {
          "gte": "8.5.38",
          "lte": "8.5.100"
        },
        {
          "gte": "9.0.13",
          "lte": "9.0.119"
        },
        {
          "gte": "10.1.0",
          "lte": "10.1.56"
        },
        {
          "gte": "11.0.0",
          "lte": "11.0.23"
        }
      ],
      "note": "NVD: Insufficient Technical Documentation vulnerability in Apache Tomcat since the requirements to securely configure the EncryptInterceptor were not clearly documented."
    },
    {
      "cve": "CVE-2026-59083",
      "sev": "critical",
      "kev": false,
      "title": "Improper Handling of URL Encoding (Hex Encoding) vulnerability in Apache Tomcat's…",
      "ranges": [
        {
          "lte": "8.0.0"
        },
        {
          "gte": "8.5.0",
          "lte": "8.5.100"
        },
        {
          "gte": "9.0.0",
          "lte": "9.0.119"
        },
        {
          "gte": "10.1.0",
          "lte": "10.1.56"
        },
        {
          "gte": "11.0.0",
          "lte": "11.0.23"
        }
      ],
      "note": "NVD: Improper Handling of URL Encoding (Hex Encoding) vulnerability in Apache Tomcat's rewrite valve allowed security constraint bypass for some configurations."
    },
    {
      "cve": "CVE-2026-55957",
      "sev": "high",
      "kev": false,
      "title": "Missing Critical Step in Authentication vulnerability in Apache Tomcat when the…",
      "ranges": [
        {
          "lt": "9.0.101"
        },
        {
          "gte": "10.1.0",
          "lt": "10.1.37"
        },
        {
          "gte": "11.0.0",
          "lt": "11.0.5"
        }
      ],
      "note": "NVD: Missing Critical Step in Authentication vulnerability in Apache Tomcat when the JNDIRealm was configured to authenticate binds using GSSAPI allowed attackers to…"
    },
    {
      "cve": "CVE-2026-55276",
      "sev": "critical",
      "kev": false,
      "title": "Always-Incorrect Control Flow Implementation vulnerability in Apache Tomcat meant that…",
      "ranges": [
        {
          "lt": "9.0.119"
        },
        {
          "gte": "10.1.0",
          "lt": "10.1.56"
        },
        {
          "gte": "11.0.0",
          "lt": "11.0.23"
        }
      ],
      "note": "NVD: Always-Incorrect Control Flow Implementation vulnerability in Apache Tomcat meant that special roles and empty authorisation constraints were not included when the…"
    },
    {
      "cve": "CVE-2026-53434",
      "sev": "critical",
      "kev": false,
      "title": "Detection of Error Condition Without Action vulnerability in Apache Tomcat when…",
      "ranges": [
        {
          "gte": "9.0.83",
          "lt": "9.0.119"
        },
        {
          "gte": "10.1.0",
          "lt": "10.1.56"
        },
        {
          "gte": "11.0.0",
          "lt": "11.0.23"
        }
      ],
      "note": "NVD: Detection of Error Condition Without Action vulnerability in Apache Tomcat when configuring CRLs for a FFM based connector."
    },
    {
      "cve": "CVE-2026-53404",
      "sev": "high",
      "kev": false,
      "title": "Always-Incorrect Control Flow Implementation vulnerability in Apache Tomcat's rewrite…",
      "ranges": [
        {
          "gte": "8.5.0",
          "lte": "8.5.100"
        },
        {
          "gte": "9.0.0",
          "lt": "9.0.119"
        },
        {
          "gte": "10.1.0",
          "lt": "10.1.56"
        },
        {
          "gte": "11.0.0",
          "lt": "11.0.23"
        }
      ],
      "note": "NVD: Always-Incorrect Control Flow Implementation vulnerability in Apache Tomcat's rewrite valve meant that if the first condition in an OR chain matched, subsequent…"
    },
    {
      "cve": "CVE-2026-43515",
      "sev": "critical",
      "kev": false,
      "title": "Improper Authorization vulnerability when multiple method constraints define an HTTP…",
      "ranges": [
        {
          "gte": "7.0.0",
          "lte": "7.0.109"
        },
        {
          "gte": "8.5.0",
          "lte": "8.5.100"
        },
        {
          "gte": "9.0.0",
          "lt": "9.0.118"
        },
        {
          "gte": "10.1.0",
          "lt": "10.1.55"
        },
        {
          "gte": "11.0.0",
          "lt": "11.0.22"
        }
      ],
      "note": "NVD: Improper Authorization vulnerability when multiple method constraints define an HTTP method for the same extension in Apache Tomcat."
    },
    {
      "cve": "CVE-2026-43513",
      "sev": "high",
      "kev": false,
      "title": "Improper Handling of Case Sensitivity vulnerability in LockOutRealm in Apache Tomcat.",
      "ranges": [
        {
          "gte": "7.0.0",
          "lte": "7.0.109"
        },
        {
          "gte": "8.5.0",
          "lte": "8.5.100"
        },
        {
          "gte": "9.0.0",
          "lt": "9.0.118"
        },
        {
          "gte": "10.1.0",
          "lt": "10.1.55"
        },
        {
          "gte": "11.0.0",
          "lt": "11.0.22"
        }
      ],
      "note": "NVD: Improper Handling of Case Sensitivity vulnerability in LockOutRealm in Apache Tomcat."
    },
    {
      "cve": "CVE-2026-43512",
      "sev": "critical",
      "kev": false,
      "title": "DEPRECATED: Authentication Bypass Issues vulnerability in digest authentication in…",
      "ranges": [
        {
          "gte": "7.0.0",
          "lte": "7.0.109"
        },
        {
          "gte": "8.5.0",
          "lte": "8.5.100"
        },
        {
          "gte": "9.0.0",
          "lt": "9.0.118"
        },
        {
          "gte": "10.1.0",
          "lt": "10.1.55"
        },
        {
          "gte": "11.0.0",
          "lt": "11.0.22"
        }
      ],
      "note": "NVD: DEPRECATED: Authentication Bypass Issues vulnerability in digest authentication in Apache Tomcat."
    },
    {
      "cve": "CVE-2026-42498",
      "sev": "high",
      "kev": false,
      "title": "Exposure of HTTP Authentication Header to unexpected hosts during WebSocket…",
      "ranges": [
        {
          "gte": "7.0.0",
          "lte": "7.0.109"
        },
        {
          "gte": "8.5.0",
          "lte": "8.5.100"
        },
        {
          "gte": "9.0.0",
          "lt": "9.0.118"
        },
        {
          "gte": "10.1.0",
          "lt": "10.1.55"
        },
        {
          "gte": "11.0.0",
          "lt": "11.0.22"
        }
      ],
      "note": "NVD: Exposure of HTTP Authentication Header to unexpected hosts during WebSocket authentication vulnerability in Apache Tomcat."
    },
    {
      "cve": "CVE-2026-41293",
      "sev": "critical",
      "kev": false,
      "title": "Improper Input Validation vulnerability in Apache Tomcat.",
      "ranges": [
        {
          "gte": "8.5.0",
          "lte": "8.5.100"
        },
        {
          "gte": "9.0.0",
          "lt": "9.0.118"
        },
        {
          "gte": "10.0.0",
          "lte": "10.0.27"
        },
        {
          "gte": "10.1.0",
          "lt": "10.1.55"
        },
        {
          "gte": "11.0.0",
          "lt": "11.0.22"
        }
      ],
      "note": "NVD: Improper Input Validation vulnerability in Apache Tomcat."
    },
    {
      "cve": "CVE-2026-41284",
      "sev": "high",
      "kev": false,
      "title": "Allocation of Resources Without Limits or Throttling vulnerability in Apache Tomcat.",
      "ranges": [
        {
          "gte": "4.0.0",
          "lte": "7.0.109"
        },
        {
          "gte": "8.5.0",
          "lte": "8.5.100"
        },
        {
          "gte": "9.0.0",
          "lt": "9.0.118"
        },
        {
          "gte": "10.0.0",
          "lte": "10.0.27"
        },
        {
          "gte": "10.1.0",
          "lt": "10.1.55"
        },
        {
          "gte": "11.0.0",
          "lt": "11.0.22"
        }
      ],
      "note": "NVD: Allocation of Resources Without Limits or Throttling vulnerability in Apache Tomcat."
    },
    {
      "cve": "CVE-2026-34487",
      "sev": "high",
      "kev": false,
      "title": "Insertion of Sensitive Information into Log File vulnerability in the cloud membership…",
      "ranges": [
        {
          "gte": "9.0.13",
          "lt": "9.0.117"
        },
        {
          "gte": "10.1.0",
          "lt": "10.1.54"
        },
        {
          "gte": "11.0.0",
          "lt": "11.0.21"
        }
      ],
      "note": "NVD: Insertion of Sensitive Information into Log File vulnerability in the cloud membership for clustering component of Apache Tomcat exposed the Kubernetes bearer token."
    },
    {
      "cve": "CVE-2026-34486",
      "sev": "high",
      "kev": true,
      "title": "Missing Encryption of Sensitive Data vulnerability in Apache Tomcat due to the fix for…",
      "ranges": [
        {
          "eq": "9.0.116"
        },
        {
          "eq": "10.1.53"
        },
        {
          "eq": "11.0.20"
        }
      ],
      "note": "NVD: Missing Encryption of Sensitive Data vulnerability in Apache Tomcat due to the fix for CVE-2026-29146 allowing the bypass of the… — CISA KEV (actively exploited)"
    },
    {
      "cve": "CVE-2026-34483",
      "sev": "high",
      "kev": false,
      "title": "Improper Encoding or Escaping of Output vulnerability in the JsonAccessLogValve…",
      "ranges": [
        {
          "gte": "9.0.40",
          "lt": "9.0.117"
        },
        {
          "gte": "10.1.0",
          "lt": "10.1.54"
        },
        {
          "gte": "11.0.0",
          "lt": "11.0.21"
        }
      ],
      "note": "NVD: Improper Encoding or Escaping of Output vulnerability in the JsonAccessLogValve component of Apache Tomcat."
    },
    {
      "cve": "CVE-2026-29146",
      "sev": "high",
      "kev": false,
      "title": "Padding Oracle vulnerability in Apache Tomcat's EncryptInterceptor with default…",
      "ranges": [
        {
          "gte": "7.0.100",
          "lte": "7.0.109"
        },
        {
          "gte": "8.5.38",
          "lte": "8.5.100"
        },
        {
          "gte": "9.0.13",
          "lt": "9.0.116"
        },
        {
          "gte": "10.0.0",
          "lt": "10.1.53"
        },
        {
          "gte": "11.0.0",
          "lt": "11.0.20"
        }
      ],
      "note": "NVD: Padding Oracle vulnerability in Apache Tomcat's EncryptInterceptor with default configuration."
    },
    {
      "cve": "CVE-2026-29145",
      "sev": "critical",
      "kev": false,
      "title": "CLIENT_CERT authentication does not fail as expected for some scenarios when soft fail…",
      "ranges": [
        {
          "gte": "9.0.83",
          "lt": "9.0.116"
        },
        {
          "gte": "10.1.1",
          "lt": "10.1.53"
        },
        {
          "gte": "11.0.0",
          "lt": "11.0.20"
        },
        {
          "eq": "10.1.0"
        }
      ],
      "note": "NVD: CLIENT_CERT authentication does not fail as expected for some scenarios when soft fail is disabled vulnerability in Apache Tomcat, Apache Tomcat Native."
    },
    {
      "cve": "CVE-2026-29129",
      "sev": "high",
      "kev": false,
      "title": "Configured cipher preference order not preserved vulnerability in Apache Tomcat.",
      "ranges": [
        {
          "gte": "9.0.114",
          "lt": "9.0.116"
        },
        {
          "gte": "10.1.51",
          "lt": "10.1.53"
        },
        {
          "gte": "11.0.16",
          "lt": "11.0.20"
        }
      ],
      "note": "NVD: Configured cipher preference order not preserved vulnerability in Apache Tomcat."
    },
    {
      "cve": "CVE-2026-24880",
      "sev": "high",
      "kev": false,
      "title": "Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')…",
      "ranges": [
        {
          "gte": "9.0.0",
          "lt": "9.0.116"
        },
        {
          "gte": "10.1.0",
          "lt": "10.1.53"
        },
        {
          "gte": "11.0.0",
          "lt": "11.0.20"
        }
      ],
      "note": "NVD: Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling') vulnerability in Apache Tomcat via invalid chunk extension."
    },
    {
      "cve": "CVE-2026-24734",
      "sev": "high",
      "kev": false,
      "title": "Improper Input Validation vulnerability in Apache Tomcat Native, Apache Tomcat.",
      "ranges": [
        {
          "gte": "9.0.83",
          "lt": "9.0.115"
        },
        {
          "gte": "10.1.1",
          "lt": "10.1.52"
        },
        {
          "gte": "11.0.1",
          "lt": "11.0.18"
        },
        {
          "eq": "10.1.0"
        },
        {
          "eq": "11.0.0"
        }
      ],
      "note": "NVD: Improper Input Validation vulnerability in Apache Tomcat Native, Apache Tomcat."
    },
    {
      "cve": "CVE-2025-66614",
      "sev": "critical",
      "kev": false,
      "title": "Improper Input Validation vulnerability.",
      "ranges": [
        {
          "gte": "9.0.1",
          "lt": "9.0.113"
        },
        {
          "gte": "10.1.1",
          "lt": "10.1.50"
        },
        {
          "gte": "11.0.1",
          "lt": "11.0.15"
        },
        {
          "eq": "9.0.0"
        },
        {
          "eq": "10.1.0"
        },
        {
          "eq": "11.0.0"
        }
      ],
      "note": "NVD: Improper Input Validation vulnerability."
    },
    {
      "cve": "CVE-2025-55754",
      "sev": "critical",
      "kev": false,
      "title": "Improper Neutralization of Escape, Meta, or Control Sequences vulnerability in Apache…",
      "ranges": [
        {
          "gte": "8.5.60",
          "lte": "8.5.100"
        },
        {
          "gte": "9.0.40",
          "lt": "9.0.109"
        },
        {
          "gte": "10.0.0",
          "lt": "10.0.27"
        },
        {
          "gte": "10.1.0",
          "lt": "10.1.45"
        },
        {
          "gte": "11.0.0",
          "lt": "11.0.11"
        }
      ],
      "note": "NVD: Improper Neutralization of Escape, Meta, or Control Sequences vulnerability in Apache Tomcat."
    },
    {
      "cve": "CVE-2025-55752",
      "sev": "high",
      "kev": false,
      "title": "Relative Path Traversal vulnerability in Apache Tomcat.",
      "ranges": [
        {
          "gte": "8.5.6",
          "lte": "8.5.100"
        },
        {
          "gte": "9.0.1",
          "lt": "9.0.109"
        },
        {
          "gte": "10.0.0",
          "lt": "10.0.27"
        },
        {
          "gte": "10.1.0",
          "lt": "10.1.45"
        },
        {
          "gte": "11.0.0",
          "lt": "11.0.11"
        },
        {
          "eq": "9.0.0"
        }
      ],
      "note": "NVD: Relative Path Traversal vulnerability in Apache Tomcat."
    },
    {
      "cve": "CVE-2025-53506",
      "sev": "high",
      "kev": false,
      "title": "Uncontrolled Resource Consumption vulnerability in Apache Tomcat if an HTTP/2 client…",
      "ranges": [
        {
          "gte": "9.0.0",
          "lte": "9.0.106"
        },
        {
          "gte": "10.1.0",
          "lte": "10.1.42"
        },
        {
          "gte": "11.0.0",
          "lte": "11.0.8"
        }
      ],
      "note": "NVD: Uncontrolled Resource Consumption vulnerability in Apache Tomcat if an HTTP/2 client did not acknowledge the initial settings frame that reduces the maximum…"
    },
    {
      "cve": "CVE-2025-52520",
      "sev": "high",
      "kev": false,
      "title": "For some unlikely configurations of multipart upload, an Integer Overflow…",
      "ranges": [
        {
          "gte": "9.0.0",
          "lt": "9.0.107"
        },
        {
          "gte": "10.1.0",
          "lt": "10.1.43"
        },
        {
          "gte": "11.0.0",
          "lt": "11.0.9"
        }
      ],
      "note": "NVD: For some unlikely configurations of multipart upload, an Integer Overflow vulnerability in Apache Tomcat could lead to a DoS via bypassing of size limits."
    },
    {
      "cve": "CVE-2025-52434",
      "sev": "high",
      "kev": false,
      "title": "Concurrent Execution using Shared Resource with Improper Synchronization ('Race…",
      "ranges": [
        {
          "gte": "9.0.0",
          "lt": "9.0.107"
        }
      ],
      "note": "NVD: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') vulnerability in Apache Tomcat when using the APR/Native connector."
    },
    {
      "cve": "CVE-2025-49125",
      "sev": "high",
      "kev": false,
      "title": "Authentication Bypass Using an Alternate Path or Channel vulnerability in Apache Tomcat.",
      "ranges": [
        {
          "gte": "9.0.0",
          "lt": "9.0.106"
        },
        {
          "gte": "10.1.0",
          "lt": "10.1.42"
        },
        {
          "gte": "11.0.0",
          "lt": "11.0.8"
        }
      ],
      "note": "NVD: Authentication Bypass Using an Alternate Path or Channel vulnerability in Apache Tomcat."
    },
    {
      "cve": "CVE-2025-49124",
      "sev": "high",
      "kev": false,
      "title": "Untrusted Search Path vulnerability in Apache Tomcat installer for Windows.",
      "ranges": [
        {
          "gte": "9.0.23",
          "lt": "9.0.106"
        },
        {
          "gte": "10.1.0",
          "lt": "10.1.42"
        },
        {
          "gte": "11.0.0",
          "lt": "11.0.8"
        }
      ],
      "note": "NVD: Untrusted Search Path vulnerability in Apache Tomcat installer for Windows."
    },
    {
      "cve": "CVE-2025-48989",
      "sev": "high",
      "kev": false,
      "title": "Improper Resource Shutdown or Release vulnerability in Apache Tomcat made Tomcat…",
      "ranges": [
        {
          "gte": "9.0.1",
          "lt": "9.0.108"
        },
        {
          "gte": "10.0.0",
          "lt": "10.1.44"
        },
        {
          "gte": "11.0.0",
          "lt": "11.0.10"
        },
        {
          "eq": "9.0.0"
        }
      ],
      "note": "NVD: Improper Resource Shutdown or Release vulnerability in Apache Tomcat made Tomcat vulnerable to the made you reset attack."
    },
    {
      "cve": "CVE-2025-48988",
      "sev": "high",
      "kev": false,
      "title": "Allocation of Resources Without Limits or Throttling vulnerability in Apache Tomcat.",
      "ranges": [
        {
          "gte": "9.0.0",
          "lt": "9.0.106"
        },
        {
          "gte": "10.1.0",
          "lt": "10.1.42"
        },
        {
          "gte": "11.0.0",
          "lt": "11.0.8"
        }
      ],
      "note": "NVD: Allocation of Resources Without Limits or Throttling vulnerability in Apache Tomcat."
    },
    {
      "cve": "CVE-2025-46701",
      "sev": "high",
      "kev": false,
      "title": "Improper Handling of Case Sensitivity vulnerability in Apache Tomcat's GCI servlet…",
      "ranges": [
        {
          "gte": "9.0.0",
          "lt": "9.0.105"
        },
        {
          "gte": "10.1.0",
          "lt": "10.1.41"
        },
        {
          "gte": "11.0.0",
          "lt": "11.0.7"
        }
      ],
      "note": "NVD: Improper Handling of Case Sensitivity vulnerability in Apache Tomcat's GCI servlet allows security constraint bypass of security constraints that apply to the…"
    },
    {
      "cve": "CVE-2025-31651",
      "sev": "critical",
      "kev": false,
      "title": "Improper Neutralization of Escape, Meta, or Control Sequences vulnerability in Apache…",
      "ranges": [
        {
          "gte": "9.0.0",
          "lt": "9.0.104"
        },
        {
          "gte": "10.1.0",
          "lt": "10.1.40"
        },
        {
          "gte": "11.0.0",
          "lt": "11.0.6"
        }
      ],
      "note": "NVD: Improper Neutralization of Escape, Meta, or Control Sequences vulnerability in Apache Tomcat."
    },
    {
      "cve": "CVE-2025-31650",
      "sev": "high",
      "kev": false,
      "title": "Improper Input Validation vulnerability in Apache Tomcat.",
      "ranges": [
        {
          "gte": "9.0.76",
          "lt": "9.0.104"
        },
        {
          "gte": "10.1.10",
          "lt": "10.1.40"
        },
        {
          "gte": "11.0.1",
          "lt": "11.0.6"
        },
        {
          "eq": "11.0.0"
        }
      ],
      "note": "NVD: Improper Input Validation vulnerability in Apache Tomcat."
    },
    {
      "cve": "CVE-2025-24813",
      "sev": "critical",
      "kev": true,
      "title": "Path Equivalence: 'file.Name' (Internal Dot) leading to Remote Code Execution and/or…",
      "ranges": [
        {
          "lt": "9.0.99"
        },
        {
          "gte": "10.1.1",
          "lt": "10.1.35"
        },
        {
          "gte": "11.0.1",
          "lt": "11.0.3"
        },
        {
          "eq": "10.1.0"
        },
        {
          "eq": "11.0.0"
        }
      ],
      "note": "NVD: Path Equivalence: 'file.Name' (Internal Dot) leading to Remote Code Execution and/or Information disclosure and/or malicious… — CISA KEV (actively exploited)"
    },
    {
      "cve": "CVE-2024-56337",
      "sev": "critical",
      "kev": false,
      "title": "Time-of-check Time-of-use (TOCTOU) Race Condition vulnerability in Apache Tomcat.",
      "ranges": [
        {
          "gte": "9.0.0",
          "lt": "9.0.98"
        },
        {
          "gte": "10.1.0",
          "lt": "10.1.34"
        },
        {
          "gte": "11.0.0",
          "lt": "11.0.2"
        }
      ],
      "note": "NVD: Time-of-check Time-of-use (TOCTOU) Race Condition vulnerability in Apache Tomcat."
    },
    {
      "cve": "CVE-2024-52316",
      "sev": "critical",
      "kev": false,
      "title": "Unchecked Error Condition vulnerability in Apache Tomcat.",
      "ranges": [
        {
          "gte": "9.0.0",
          "lt": "9.0.96"
        },
        {
          "gte": "10.1.0",
          "lt": "10.1.31"
        },
        {
          "eq": "11.0.0"
        }
      ],
      "note": "NVD: Unchecked Error Condition vulnerability in Apache Tomcat."
    },
    {
      "cve": "CVE-2024-50379",
      "sev": "critical",
      "kev": false,
      "title": "Time-of-check Time-of-use (TOCTOU) Race Condition vulnerability during JSP compilation…",
      "ranges": [
        {
          "gte": "9.0.0",
          "lt": "9.0.98"
        },
        {
          "gte": "10.1.0",
          "lt": "10.1.34"
        },
        {
          "gte": "11.0.0",
          "lt": "11.0.2"
        }
      ],
      "note": "NVD: Time-of-check Time-of-use (TOCTOU) Race Condition vulnerability during JSP compilation in Apache Tomcat permits an RCE on case insensitive file systems when the…"
    },
    {
      "cve": "CVE-2024-38286",
      "sev": "high",
      "kev": false,
      "title": "Allocation of Resources Without Limits or Throttling vulnerability in Apache Tomcat.",
      "ranges": [
        {
          "gte": "9.0.13",
          "lt": "9.0.90"
        },
        {
          "gte": "10.1.1",
          "lt": "10.1.25"
        },
        {
          "eq": "10.1.0"
        },
        {
          "eq": "11.0.0"
        }
      ],
      "note": "NVD: Allocation of Resources Without Limits or Throttling vulnerability in Apache Tomcat."
    },
    {
      "cve": "CVE-2024-34750",
      "sev": "high",
      "kev": false,
      "title": "Improper Handling of Exceptional Conditions, Uncontrolled Resource Consumption…",
      "ranges": [
        {
          "gte": "9.0.0",
          "lt": "9.0.90"
        },
        {
          "gte": "10.1.0",
          "lt": "10.1.25"
        },
        {
          "eq": "11.0.0"
        }
      ],
      "note": "NVD: Improper Handling of Exceptional Conditions, Uncontrolled Resource Consumption vulnerability in Apache Tomcat."
    },
    {
      "cve": "CVE-2024-24549",
      "sev": "high",
      "kev": false,
      "title": "Denial of Service due to improper input validation vulnerability for HTTP/2 requests…",
      "ranges": [
        {
          "gte": "8.5.0",
          "lt": "8.5.99"
        },
        {
          "gte": "9.0.0",
          "lt": "9.0.86"
        },
        {
          "gte": "10.1.0",
          "lt": "10.1.19"
        },
        {
          "eq": "11.0.0"
        }
      ],
      "note": "NVD: Denial of Service due to improper input validation vulnerability for HTTP/2 requests in Apache Tomcat."
    },
    {
      "cve": "CVE-2023-46589",
      "sev": "high",
      "kev": false,
      "title": "Improper Input Validation vulnerability in Apache Tomcat.Tomcat from 11.0.0-M1 through…",
      "ranges": [
        {
          "gte": "8.5.0",
          "lt": "8.5.96"
        },
        {
          "gte": "9.0.0",
          "lt": "9.0.83"
        },
        {
          "gte": "10.1.0",
          "lt": "10.1.16"
        },
        {
          "eq": "11.0.0"
        }
      ],
      "note": "NVD: Improper Input Validation vulnerability in Apache Tomcat.Tomcat from 11.0.0-M1 through 11.0.0-M10, from 10.1.0-M1 through 10.1.15, from 9.0.0-M1 through 9.0.82 and…"
    },
    {
      "cve": "CVE-2023-44487",
      "sev": "high",
      "kev": true,
      "title": "The HTTP/2 protocol allows a denial of service (server resource consumption) because…",
      "ranges": [
        {
          "gte": "8.5.0",
          "lte": "8.5.93"
        },
        {
          "gte": "9.0.0",
          "lte": "9.0.80"
        },
        {
          "gte": "10.1.0",
          "lte": "10.1.13"
        },
        {
          "eq": "11.0.0"
        }
      ],
      "note": "NVD: The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams… — CISA KEV (actively exploited)"
    },
    {
      "cve": "CVE-2023-34981",
      "sev": "high",
      "kev": false,
      "title": "A regression in the fix for bug 66512 in Apache Tomcat 11.0.0-M5, 10.1.8, 9.0.74 and…",
      "ranges": [
        {
          "eq": "8.5.88"
        },
        {
          "eq": "9.0.74"
        },
        {
          "eq": "10.1.8"
        },
        {
          "eq": "11.0.0"
        }
      ],
      "note": "NVD: A regression in the fix for bug 66512 in Apache Tomcat 11.0.0-M5, 10.1.8, 9.0.74 and 8.5.88 meant that, if a response did not include any HTTP headers no AJP…"
    },
    {
      "cve": "CVE-2023-28709",
      "sev": "high",
      "kev": false,
      "title": "The fix for CVE-2023-24998 was incomplete for Apache Tomcat 11.0.0-M2 to 11.0.0-M4,…",
      "ranges": [
        {
          "gte": "8.5.85",
          "lte": "8.5.87"
        },
        {
          "gte": "9.0.71",
          "lte": "9.0.73"
        },
        {
          "gte": "10.1.5",
          "lte": "10.1.7"
        },
        {
          "eq": "11.0.0"
        }
      ],
      "note": "NVD: The fix for CVE-2023-24998 was incomplete for Apache Tomcat 11.0.0-M2 to 11.0.0-M4, 10.1.5 to 10.1.7, 9.0.71 to 9.0.73 and 8.5.85 to 8.5.87."
    },
    {
      "cve": "CVE-2022-45143",
      "sev": "high",
      "kev": false,
      "title": "The JsonErrorReportValve in Apache Tomcat 8.5.83, 9.0.40 to 9.0.68 and 10.1.0-M1 to…",
      "ranges": [
        {
          "gte": "9.0.40",
          "lt": "9.0.69"
        },
        {
          "eq": "8.5.83"
        },
        {
          "eq": "10.1.0"
        },
        {
          "eq": "10.1.1"
        }
      ],
      "note": "NVD: The JsonErrorReportValve in Apache Tomcat 8.5.83, 9.0.40 to 9.0.68 and 10.1.0-M1 to 10.1.1 did not escape the type, message or description values."
    },
    {
      "cve": "CVE-2022-42252",
      "sev": "high",
      "kev": false,
      "title": "If Apache Tomcat 8.5.0 to 8.5.82, 9.0.0-M1 to 9.0.67, 10.0.0-M1 to 10.0.26 or…",
      "ranges": [
        {
          "gte": "8.5.0",
          "lt": "8.5.83"
        },
        {
          "gte": "9.0.0",
          "lt": "9.0.68"
        },
        {
          "gte": "10.0.0",
          "lt": "10.0.27"
        },
        {
          "gte": "10.1.0",
          "lt": "10.1.1"
        }
      ],
      "note": "NVD: If Apache Tomcat 8.5.0 to 8.5.82, 9.0.0-M1 to 9.0.67, 10.0.0-M1 to 10.0.26 or 10.1.0-M1 to 10.1.0 was configured to ignore invalid HTTP headers via setting…"
    },
    {
      "cve": "CVE-2022-29885",
      "sev": "high",
      "kev": false,
      "title": "The documentation of Apache Tomcat 10.1.0-M1 to 10.1.0-M14, 10.0.0-M1 to 10.0.20,…",
      "ranges": [
        {
          "gte": "8.5.38",
          "lte": "8.5.78"
        },
        {
          "gte": "9.0.13",
          "lte": "9.0.62"
        },
        {
          "gte": "10.0.0",
          "lte": "10.0.20"
        },
        {
          "eq": "10.1.0"
        }
      ],
      "note": "NVD: The documentation of Apache Tomcat 10.1.0-M1 to 10.1.0-M14, 10.0.0-M1 to 10.0.20, 9.0.13 to 9.0.62 and 8.5.38 to 8.5.78 for the EncryptInterceptor incorrectly…"
    },
    {
      "cve": "CVE-2022-25762",
      "sev": "high",
      "kev": false,
      "title": "If a web application sends a WebSocket message concurrently with the WebSocket…",
      "ranges": [
        {
          "gte": "8.5.0",
          "lt": "8.5.76"
        },
        {
          "gte": "9.0.0",
          "lt": "9.0.21"
        }
      ],
      "note": "NVD: If a web application sends a WebSocket message concurrently with the WebSocket connection closing when running on Apache Tomcat 8.5.0 to 8.5.75 or Apache Tomcat…"
    },
    {
      "cve": "CVE-2022-23181",
      "sev": "high",
      "kev": false,
      "title": "The fix for bug CVE-2020-9484 introduced a time of check, time of use vulnerability…",
      "ranges": [
        {
          "gte": "8.5.55",
          "lte": "8.5.73"
        },
        {
          "gte": "9.0.35",
          "lte": "9.0.56"
        },
        {
          "gte": "10.0.1",
          "lte": "10.0.14"
        },
        {
          "eq": "10.0.0"
        },
        {
          "eq": "10.1.0"
        }
      ],
      "note": "NVD: The fix for bug CVE-2020-9484 introduced a time of check, time of use vulnerability into Apache Tomcat 10.1.0-M1 to 10.1.0-M8, 10.0.0-M5 to 10.0.14, 9.0.35 to…"
    },
    {
      "cve": "CVE-2021-42340",
      "sev": "high",
      "kev": false,
      "title": "The fix for bug 63362 present in Apache Tomcat 10.1.0-M1 to 10.1.0-M5, 10.0.0-M1 to…",
      "ranges": [
        {
          "gte": "8.5.60",
          "lt": "8.5.72"
        },
        {
          "gte": "9.0.40",
          "lt": "9.0.54"
        },
        {
          "gte": "10.0.1",
          "lt": "10.0.12"
        },
        {
          "eq": "10.0.0"
        },
        {
          "eq": "10.1.0"
        }
      ],
      "note": "NVD: The fix for bug 63362 present in Apache Tomcat 10.1.0-M1 to 10.1.0-M5, 10.0.0-M1 to 10.0.11, 9.0.40 to 9.0.53 and 8.5.60 to 8.5.71 introduced a memory leak."
    },
    {
      "cve": "CVE-2021-41079",
      "sev": "high",
      "kev": false,
      "title": "Apache Tomcat 8.5.0 to 8.5.63, 9.0.0-M1 to 9.0.43 and 10.0.0-M1 to 10.0.2 did not…",
      "ranges": [
        {
          "gte": "8.5.0",
          "lt": "8.5.64"
        },
        {
          "gte": "9.0.0",
          "lt": "9.0.44"
        },
        {
          "gte": "10.0.0",
          "lte": "10.0.2"
        }
      ],
      "note": "NVD: Apache Tomcat 8.5.0 to 8.5.63, 9.0.0-M1 to 9.0.43 and 10.0.0-M1 to 10.0.2 did not properly validate incoming TLS packets."
    },
    {
      "cve": "CVE-2021-30639",
      "sev": "high",
      "kev": false,
      "title": "A vulnerability in Apache Tomcat allows an attacker to remotely trigger a denial of…",
      "ranges": [
        {
          "eq": "8.5.64"
        },
        {
          "eq": "9.0.44"
        },
        {
          "eq": "10.0.3"
        },
        {
          "eq": "10.0.4"
        }
      ],
      "note": "NVD: A vulnerability in Apache Tomcat allows an attacker to remotely trigger a denial of service."
    },
    {
      "cve": "CVE-2021-25329",
      "sev": "high",
      "kev": false,
      "title": "The fix for CVE-2020-9484 was incomplete.",
      "ranges": [
        {
          "gte": "7.0.0",
          "lte": "7.0.107"
        },
        {
          "gte": "8.5.0",
          "lte": "8.5.61"
        },
        {
          "gte": "9.0.0",
          "lte": "9.0.41"
        },
        {
          "eq": "9.0.0"
        },
        {
          "eq": "10.0.0"
        }
      ],
      "note": "NVD: The fix for CVE-2020-9484 was incomplete."
    },
    {
      "cve": "CVE-2021-25122",
      "sev": "high",
      "kev": false,
      "title": "When responding to new h2c connection requests, Apache Tomcat versions 10.0.0-M1 to…",
      "ranges": [
        {
          "gte": "8.5.0",
          "lte": "8.5.61"
        },
        {
          "gte": "9.0.0",
          "lte": "9.0.41"
        },
        {
          "eq": "9.0.0"
        },
        {
          "eq": "10.0.0"
        }
      ],
      "note": "NVD: When responding to new h2c connection requests, Apache Tomcat versions 10.0.0-M1 to 10.0.0, 9.0.0.M1 to 9.0.41 and 8.5.0 to 8.5.61 could duplicate request headers…"
    },
    {
      "cve": "CVE-2020-17527",
      "sev": "high",
      "kev": false,
      "title": "While investigating bug 64830 it was discovered that Apache Tomcat 10.0.0-M1 to…",
      "ranges": [
        {
          "gte": "8.5.1",
          "lte": "8.5.59"
        },
        {
          "gte": "9.0.1",
          "lte": "9.0.35"
        },
        {
          "eq": "9.0.0"
        },
        {
          "eq": "9.0.36"
        },
        {
          "eq": "9.0.37"
        },
        {
          "eq": "9.0.38"
        },
        {
          "eq": "9.0.39"
        },
        {
          "eq": "10.0.0"
        }
      ],
      "note": "NVD: While investigating bug 64830 it was discovered that Apache Tomcat 10.0.0-M1 to 10.0.0-M9, 9.0.0-M1 to 9.0.39 and 8.5.0 to 8.5.59 could re-use an HTTP request…"
    },
    {
      "cve": "CVE-2020-13935",
      "sev": "high",
      "kev": false,
      "title": "The payload length in a WebSocket frame was not correctly validated in Apache Tomcat…",
      "ranges": [
        {
          "gte": "7.0.27",
          "lte": "7.0.104"
        },
        {
          "gte": "8.5.0",
          "lte": "8.5.56"
        },
        {
          "gte": "9.0.1",
          "lte": "9.0.36"
        },
        {
          "eq": "9.0.0"
        },
        {
          "eq": "10.0.0"
        }
      ],
      "note": "NVD: The payload length in a WebSocket frame was not correctly validated in Apache Tomcat 10.0.0-M1 to 10.0.0-M6, 9.0.0.M1 to 9.0.36, 8.5.0 to 8.5.56 and 7.0.27 to…"
    },
    {
      "cve": "CVE-2020-13934",
      "sev": "high",
      "kev": false,
      "title": "An h2c direct connection to Apache Tomcat 10.0.0-M1 to 10.0.0-M6, 9.0.0.M5 to 9.0.36…",
      "ranges": [
        {
          "gte": "8.5.1",
          "lte": "8.5.56"
        },
        {
          "gte": "9.0.1",
          "lte": "9.0.36"
        },
        {
          "eq": "9.0.0"
        },
        {
          "eq": "10.0.0"
        }
      ],
      "note": "NVD: An h2c direct connection to Apache Tomcat 10.0.0-M1 to 10.0.0-M6, 9.0.0.M5 to 9.0.36 and 8.5.1 to 8.5.56 did not release the HTTP/1.1 processor after the upgrade…"
    },
    {
      "cve": "CVE-2020-11996",
      "sev": "high",
      "kev": false,
      "title": "A specially crafted sequence of HTTP/2 requests sent to Apache Tomcat 10.0.0-M1 to…",
      "ranges": [
        {
          "gte": "8.5.0",
          "lte": "8.5.55"
        },
        {
          "gte": "9.0.0",
          "lte": "9.0.35"
        },
        {
          "eq": "9.0.0"
        },
        {
          "eq": "10.0.0"
        }
      ],
      "note": "NVD: A specially crafted sequence of HTTP/2 requests sent to Apache Tomcat 10.0.0-M1 to 10.0.0-M5, 9.0.0.M1 to 9.0.35 and 8.5.0 to 8.5.55 could trigger high CPU usage…"
    },
    {
      "cve": "CVE-2020-9484",
      "sev": "high",
      "kev": false,
      "title": "When using Apache Tomcat versions 10.0.0-M1 to 10.0.0-M4, 9.0.0.M1 to 9.0.34, 8.5.0 to…",
      "ranges": [
        {
          "gte": "7.0.0",
          "lt": "7.0.108"
        },
        {
          "gte": "8.5.0",
          "lt": "8.5.63"
        },
        {
          "gte": "9.0.1",
          "lt": "9.0.43"
        },
        {
          "eq": "9.0.0"
        },
        {
          "eq": "10.0.0"
        }
      ],
      "note": "NVD: When using Apache Tomcat versions 10.0.0-M1 to 10.0.0-M4, 9.0.0.M1 to 9.0.34, 8.5.0 to 8.5.54 and 7.0.0 to 7.0.103 if a) an attacker is able to control the…"
    },
    {
      "cve": "CVE-2020-1938",
      "sev": "critical",
      "kev": true,
      "title": "When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming…",
      "ranges": [
        {
          "gte": "7.0.0",
          "lt": "7.0.100"
        },
        {
          "gte": "8.5.0",
          "lt": "8.5.51"
        },
        {
          "gte": "9.0.0",
          "lt": "9.0.31"
        }
      ],
      "note": "NVD: When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. — CISA KEV (actively exploited)"
    },
    {
      "cve": "CVE-2019-17563",
      "sev": "high",
      "kev": false,
      "title": "When using FORM authentication with Apache Tomcat 9.0.0.M1 to 9.0.29, 8.5.0 to 8.5.49…",
      "ranges": [
        {
          "gte": "7.0.0",
          "lte": "7.0.98"
        },
        {
          "gte": "8.5.0",
          "lte": "8.5.49"
        },
        {
          "gte": "9.0.0",
          "lte": "9.0.29"
        }
      ],
      "note": "NVD: When using FORM authentication with Apache Tomcat 9.0.0.M1 to 9.0.29, 8.5.0 to 8.5.49 and 7.0.0 to 7.0.98 there was a narrow window where an attacker could perform…"
    },
    {
      "cve": "CVE-2019-12418",
      "sev": "high",
      "kev": false,
      "title": "When Apache Tomcat 9.0.0.M1 to 9.0.28, 8.5.0 to 8.5.47, 7.0.0 and 7.0.97 is configured…",
      "ranges": [
        {
          "gte": "7.0.0",
          "lte": "7.0.97"
        },
        {
          "gte": "8.5.0",
          "lte": "8.5.47"
        },
        {
          "gte": "9.0.0",
          "lte": "9.0.28"
        }
      ],
      "note": "NVD: When Apache Tomcat 9.0.0.M1 to 9.0.28, 8.5.0 to 8.5.47, 7.0.0 and 7.0.97 is configured with the JMX Remote Lifecycle Listener, a local attacker without access to…"
    },
    {
      "cve": "CVE-2019-10072",
      "sev": "high",
      "kev": false,
      "title": "The fix for CVE-2019-0199 was incomplete and did not address HTTP/2 connection window…",
      "ranges": [
        {
          "gte": "8.5.0",
          "lte": "8.5.40"
        },
        {
          "gte": "9.0.1",
          "lte": "9.0.19"
        },
        {
          "eq": "9.0.0"
        }
      ],
      "note": "NVD: The fix for CVE-2019-0199 was incomplete and did not address HTTP/2 connection window exhaustion on write in Apache Tomcat versions 9.0.0.M1 to 9.0.19 and 8.5.0 to…"
    },
    {
      "cve": "CVE-2019-0232",
      "sev": "high",
      "kev": false,
      "title": "When running on Windows with enableCmdLineArguments enabled, the CGI Servlet in Apache…",
      "ranges": [
        {
          "gte": "7.0.0",
          "lte": "7.0.93"
        },
        {
          "gte": "8.5.0",
          "lte": "8.5.39"
        },
        {
          "gte": "9.0.1",
          "lte": "9.0.17"
        },
        {
          "eq": "9.0.0"
        }
      ],
      "note": "NVD: When running on Windows with enableCmdLineArguments enabled, the CGI Servlet in Apache Tomcat 9.0.0.M1 to 9.0.17, 8.5.0 to 8.5.39 and 7.0.0 to 7.0.93 is vulnerable…"
    },
    {
      "cve": "CVE-2019-0199",
      "sev": "high",
      "kev": false,
      "title": "The HTTP/2 implementation in Apache Tomcat 9.0.0.M1 to 9.0.14 and 8.5.0 to 8.5.37…",
      "ranges": [
        {
          "gte": "8.5.0",
          "lte": "8.5.37"
        },
        {
          "gte": "9.0.1",
          "lte": "9.0.14"
        },
        {
          "eq": "9.0.0"
        }
      ],
      "note": "NVD: The HTTP/2 implementation in Apache Tomcat 9.0.0.M1 to 9.0.14 and 8.5.0 to 8.5.37 accepted streams with excessive numbers of SETTINGS frames and also permitted…"
    },
    {
      "cve": "CVE-2018-8034",
      "sev": "high",
      "kev": false,
      "title": "The host name verification when using TLS with the WebSocket client was missing.",
      "ranges": [
        {
          "gte": "7.0.35",
          "lte": "7.0.88"
        },
        {
          "gte": "8.0.0",
          "lte": "8.0.52"
        },
        {
          "gte": "8.5.0",
          "lte": "8.5.31"
        },
        {
          "gte": "9.0.1",
          "lte": "9.0.9"
        },
        {
          "eq": "8.0.0"
        },
        {
          "eq": "9.0.0"
        }
      ],
      "note": "NVD: The host name verification when using TLS with the WebSocket client was missing."
    },
    {
      "cve": "CVE-2018-8014",
      "sev": "critical",
      "kev": false,
      "title": "The defaults settings for the CORS filter provided in Apache Tomcat 9.0.0.M1 to 9.0.8,…",
      "ranges": [
        {
          "gte": "7.0.41",
          "lte": "7.0.88"
        },
        {
          "gte": "8.0.0",
          "lte": "8.0.52"
        },
        {
          "gte": "8.5.0",
          "lte": "8.5.31"
        },
        {
          "gte": "9.0.0",
          "lte": "9.0.8"
        },
        {
          "eq": "8.0.0"
        },
        {
          "eq": "9.0.0"
        }
      ],
      "note": "NVD: The defaults settings for the CORS filter provided in Apache Tomcat 9.0.0.M1 to 9.0.8, 8.5.0 to 8.5.31, 8.0.0.RC1 to 8.0.52, 7.0.41 to 7.0.88 are insecure and…"
    },
    {
      "cve": "CVE-2018-1336",
      "sev": "high",
      "kev": false,
      "title": "An improper handing of overflow in the UTF-8 decoder with supplementary characters can…",
      "ranges": [
        {
          "gte": "7.0.28",
          "lte": "7.0.86"
        },
        {
          "gte": "8.0.0",
          "lte": "8.0.51"
        },
        {
          "gte": "8.5.0",
          "lte": "8.5.30"
        },
        {
          "gte": "9.0.1",
          "lte": "9.0.7"
        },
        {
          "eq": "8.0.0"
        },
        {
          "eq": "9.0.0"
        }
      ],
      "note": "NVD: An improper handing of overflow in the UTF-8 decoder with supplementary characters can lead to an infinite loop in the decoder causing a Denial of Service."
    },
    {
      "cve": "CVE-2017-12617",
      "sev": "high",
      "kev": true,
      "title": "When running Apache Tomcat versions 9.0.0.M1 to 9.0.0, 8.5.0 to 8.5.22, 8.0.0.RC1 to…",
      "ranges": [
        {
          "gte": "7.0.0",
          "lt": "7.0.82"
        },
        {
          "gte": "8.0",
          "lt": "8.0.47"
        },
        {
          "gte": "8.5.0",
          "lt": "8.5.23"
        },
        {
          "gte": "9.0.0",
          "lt": "9.0.1"
        }
      ],
      "note": "NVD: When running Apache Tomcat versions 9.0.0.M1 to 9.0.0, 8.5.0 to 8.5.22, 8.0.0.RC1 to 8.0.46 and 7.0.0 to 7.0.81 with HTTP PUTs… — CISA KEV (actively exploited)"
    },
    {
      "cve": "CVE-2017-12615",
      "sev": "high",
      "kev": true,
      "title": "When running Apache Tomcat 7.0.0 to 7.0.79 on Windows with HTTP PUTs enabled (e.g.",
      "ranges": [
        {
          "gte": "7.0.0",
          "lte": "7.0.79"
        }
      ],
      "note": "NVD: When running Apache Tomcat 7.0.0 to 7.0.79 on Windows with HTTP PUTs enabled (e.g. — CISA KEV (actively exploited)"
    },
    {
      "cve": "CVE-2017-7675",
      "sev": "high",
      "kev": false,
      "title": "The HTTP/2 implementation in Apache Tomcat 9.0.0.M1 to 9.0.0.M21 and 8.5.0 to 8.5.15…",
      "ranges": [
        {
          "eq": "8.5.0"
        },
        {
          "eq": "8.5.1"
        },
        {
          "eq": "8.5.2"
        },
        {
          "eq": "8.5.3"
        },
        {
          "eq": "8.5.4"
        },
        {
          "eq": "8.5.5"
        },
        {
          "eq": "8.5.6"
        },
        {
          "eq": "8.5.7"
        },
        {
          "eq": "8.5.8"
        },
        {
          "eq": "8.5.9"
        },
        {
          "eq": "8.5.10"
        },
        {
          "eq": "8.5.11"
        },
        {
          "eq": "8.5.12"
        },
        {
          "eq": "8.5.13"
        },
        {
          "eq": "8.5.14"
        },
        {
          "eq": "8.5.15"
        },
        {
          "eq": "9.0.0"
        }
      ],
      "note": "NVD: The HTTP/2 implementation in Apache Tomcat 9.0.0.M1 to 9.0.0.M21 and 8.5.0 to 8.5.15 bypassed a number of security checks that prevented directory traversal attacks."
    },
    {
      "cve": "CVE-2017-5651",
      "sev": "critical",
      "kev": false,
      "title": "In Apache Tomcat 9.0.0.M1 to 9.0.0.M18 and 8.5.0 to 8.5.12, the refactoring of the…",
      "ranges": [
        {
          "eq": "8.5.0"
        },
        {
          "eq": "8.5.1"
        },
        {
          "eq": "8.5.2"
        },
        {
          "eq": "8.5.3"
        },
        {
          "eq": "8.5.4"
        },
        {
          "eq": "8.5.5"
        },
        {
          "eq": "8.5.6"
        },
        {
          "eq": "8.5.7"
        },
        {
          "eq": "8.5.8"
        },
        {
          "eq": "8.5.9"
        },
        {
          "eq": "8.5.10"
        },
        {
          "eq": "8.5.11"
        },
        {
          "eq": "8.5.12"
        },
        {
          "eq": "9.0.0"
        }
      ],
      "note": "NVD: In Apache Tomcat 9.0.0.M1 to 9.0.0.M18 and 8.5.0 to 8.5.12, the refactoring of the HTTP connectors introduced a regression in the send file processing."
    },
    {
      "cve": "CVE-2017-5650",
      "sev": "high",
      "kev": false,
      "title": "In Apache Tomcat 9.0.0.M1 to 9.0.0.M18 and 8.5.0 to 8.5.12, the handling of an HTTP/2…",
      "ranges": [
        {
          "eq": "8.5.0"
        },
        {
          "eq": "8.5.1"
        },
        {
          "eq": "8.5.2"
        },
        {
          "eq": "8.5.3"
        },
        {
          "eq": "8.5.4"
        },
        {
          "eq": "8.5.5"
        },
        {
          "eq": "8.5.6"
        },
        {
          "eq": "8.5.7"
        },
        {
          "eq": "8.5.8"
        },
        {
          "eq": "8.5.9"
        },
        {
          "eq": "8.5.10"
        },
        {
          "eq": "8.5.11"
        },
        {
          "eq": "8.5.12"
        },
        {
          "eq": "9.0.0"
        }
      ],
      "note": "NVD: In Apache Tomcat 9.0.0.M1 to 9.0.0.M18 and 8.5.0 to 8.5.12, the handling of an HTTP/2 GOAWAY frame for a connection did not close streams associated with that…"
    },
    {
      "cve": "CVE-2016-9775",
      "sev": "high",
      "kev": false,
      "title": "The postrm script in the tomcat6 package before 6.0.45+dfsg-1~deb7u3 on Debian wheezy,…",
      "ranges": [
        {
          "eq": "6.0"
        },
        {
          "eq": "7.0"
        },
        {
          "eq": "8.0"
        }
      ],
      "note": "NVD: The postrm script in the tomcat6 package before 6.0.45+dfsg-1~deb7u3 on Debian wheezy, before 6.0.45+dfsg-1~deb8u1 on Debian jessie, before 6.0.35-1ubuntu3.9 on…"
    },
    {
      "cve": "CVE-2016-9774",
      "sev": "high",
      "kev": false,
      "title": "The postinst script in the tomcat6 package before 6.0.45+dfsg-1~deb7u4 on Debian…",
      "ranges": [
        {
          "eq": "6.0"
        },
        {
          "eq": "7.0"
        },
        {
          "eq": "8.0"
        }
      ],
      "note": "NVD: The postinst script in the tomcat6 package before 6.0.45+dfsg-1~deb7u4 on Debian wheezy, before 6.0.35-1ubuntu3.9 on Ubuntu 12.04 LTS and on Ubuntu 14.04 LTS; the…"
    },
    {
      "cve": "CVE-2016-8747",
      "sev": "high",
      "kev": false,
      "title": "An information disclosure issue was discovered in Apache Tomcat 8.5.7 to 8.5.9 and…",
      "ranges": [
        {
          "gte": "8.5.7",
          "lt": "8.5.10"
        },
        {
          "eq": "9.0.0"
        }
      ],
      "note": "NVD: An information disclosure issue was discovered in Apache Tomcat 8.5.7 to 8.5.9 and 9.0.0.M11 to 9.0.0.M15 in reverse-proxy configurations."
    },
    {
      "cve": "CVE-2016-8735",
      "sev": "critical",
      "kev": true,
      "title": "Remote code execution is possible with Apache Tomcat before 6.0.48, 7.x before 7.0.73,…",
      "ranges": [
        {
          "lt": "6.0.48"
        },
        {
          "gte": "7.0.0",
          "lt": "7.0.73"
        },
        {
          "gte": "8.0",
          "lt": "8.0.39"
        },
        {
          "gte": "8.5.0",
          "lt": "8.5.7"
        },
        {
          "eq": "9.0.0"
        }
      ],
      "note": "NVD: Remote code execution is possible with Apache Tomcat before 6.0.48, 7.x before 7.0.73, 8.x before 8.0.39, 8.5.x before 8.5.7, and… — CISA KEV (actively exploited)"
    },
    {
      "cve": "CVE-2016-6817",
      "sev": "high",
      "kev": false,
      "title": "The HTTP/2 header parser in Apache Tomcat 9.0.0.M1 to 9.0.0.M11 and 8.5.0 to 8.5.6…",
      "ranges": [
        {
          "eq": "8.5.0"
        },
        {
          "eq": "8.5.1"
        },
        {
          "eq": "8.5.2"
        },
        {
          "eq": "8.5.3"
        },
        {
          "eq": "8.5.4"
        },
        {
          "eq": "8.5.5"
        },
        {
          "eq": "8.5.6"
        },
        {
          "eq": "9.0.0"
        }
      ],
      "note": "NVD: The HTTP/2 header parser in Apache Tomcat 9.0.0.M1 to 9.0.0.M11 and 8.5.0 to 8.5.6 entered an infinite loop if a header was received that was larger than the…"
    },
    {
      "cve": "CVE-2016-6797",
      "sev": "high",
      "kev": false,
      "title": "The ResourceLinkFactory implementation in Apache Tomcat 9.0.0.M1 to 9.0.0.M9, 8.5.0 to…",
      "ranges": [
        {
          "gte": "6.0.0",
          "lte": "6.0.45"
        },
        {
          "gte": "7.0.0",
          "lte": "7.0.70"
        },
        {
          "gte": "8.0",
          "lte": "8.0.36"
        },
        {
          "gte": "8.5.0",
          "lte": "8.5.4"
        },
        {
          "eq": "9.0.0"
        }
      ],
      "note": "NVD: The ResourceLinkFactory implementation in Apache Tomcat 9.0.0.M1 to 9.0.0.M9, 8.5.0 to 8.5.4, 8.0.0.RC1 to 8.0.36, 7.0.0 to 7.0.70 and 6.0.0 to 6.0.45 did not…"
    },
    {
      "cve": "CVE-2016-6796",
      "sev": "high",
      "kev": false,
      "title": "A malicious web application running on Apache Tomcat 9.0.0.M1 to 9.0.0.M9, 8.5.0 to…",
      "ranges": [
        {
          "gte": "6.0.0",
          "lte": "6.0.45"
        },
        {
          "gte": "7.0.0",
          "lte": "7.0.70"
        },
        {
          "gte": "8.0",
          "lte": "8.0.36"
        },
        {
          "gte": "8.5.0",
          "lte": "8.5.4"
        },
        {
          "eq": "9.0.0"
        }
      ],
      "note": "NVD: A malicious web application running on Apache Tomcat 9.0.0.M1 to 9.0.0.M9, 8.5.0 to 8.5.4, 8.0.0.RC1 to 8.0.36, 7.0.0 to 7.0.70 and 6.0.0 to 6.0.45 was able to…"
    },
    {
      "cve": "CVE-2016-5388",
      "sev": "high",
      "kev": false,
      "title": "Apache Tomcat 7.x through 7.0.70 and 8.x through 8.5.4, when the CGI Servlet is…",
      "ranges": [
        {
          "gte": "6.0",
          "lte": "6.0.45"
        },
        {
          "gte": "7.0",
          "lte": "7.0.70"
        },
        {
          "gte": "8.0",
          "lte": "8.5.4"
        }
      ],
      "note": "NVD: Apache Tomcat 7.x through 7.0.70 and 8.x through 8.5.4, when the CGI Servlet is enabled, follows RFC 3875 section 4.1.18 and therefore does not protect…"
    },
    {
      "cve": "CVE-2016-5018",
      "sev": "critical",
      "kev": false,
      "title": "In Apache Tomcat 9.0.0.M1 to 9.0.0.M9, 8.5.0 to 8.5.4, 8.0.0.RC1 to 8.0.36, 7.0.0 to…",
      "ranges": [
        {
          "gte": "6.0.0",
          "lte": "6.0.45"
        },
        {
          "gte": "7.0.0",
          "lte": "7.0.70"
        },
        {
          "gte": "8.0",
          "lte": "8.0.36"
        },
        {
          "gte": "8.5.0",
          "lte": "8.5.4"
        },
        {
          "eq": "9.0.0"
        }
      ],
      "note": "NVD: In Apache Tomcat 9.0.0.M1 to 9.0.0.M9, 8.5.0 to 8.5.4, 8.0.0.RC1 to 8.0.36, 7.0.0 to 7.0.70 and 6.0.0 to 6.0.45 a malicious web application was able to bypass a…"
    },
    {
      "cve": "CVE-2016-1240",
      "sev": "high",
      "kev": false,
      "title": "The Tomcat init script in the tomcat7 package before 7.0.56-3+deb8u4 and tomcat8…",
      "ranges": [
        {
          "eq": "6.0"
        },
        {
          "eq": "7.0"
        },
        {
          "eq": "8.0"
        }
      ],
      "note": "NVD: The Tomcat init script in the tomcat7 package before 7.0.56-3+deb8u4 and tomcat8 package before 8.0.14-1+deb8u3 on Debian jessie and the tomcat6 and…"
    }
  ],
  "wordpress": [
    {
      "cve": "CVE-2026-63030",
      "sev": "critical",
      "kev": true,
      "title": "WordPress 6.9.x before 6.9.5 and 7.0.x before 7.0.2 is affected by a REST API batch…",
      "ranges": [
        {
          "gte": "6.9",
          "lt": "6.9.5"
        },
        {
          "gte": "7.0",
          "lt": "7.0.2"
        }
      ],
      "note": "NVD: WordPress 6.9.x before 6.9.5 and 7.0.x before 7.0.2 is affected by a REST API batch endpoint route confusion issue which, combined… — CISA KEV (actively exploited)"
    },
    {
      "cve": "CVE-2026-60137",
      "sev": "medium",
      "kev": true,
      "title": "WordPress 6.8.x before 6.8.6, 6.9.x before 6.9.5, and 7.0.x before 7.0.2 does not…",
      "ranges": [
        {
          "gte": "6.8",
          "lt": "6.8.6"
        },
        {
          "gte": "6.9",
          "lt": "6.9.5"
        },
        {
          "gte": "7.0",
          "lt": "7.0.2"
        }
      ],
      "note": "NVD: WordPress 6.8.x before 6.8.6, 6.9.x before 6.9.5, and 7.0.x before 7.0.2 does not properly sanitise the author__not_in parameter of… — CISA KEV (actively exploited)"
    },
    {
      "cve": "CVE-2024-31210",
      "sev": "high",
      "kev": false,
      "title": "WordPress is an open publishing platform for the Web.",
      "ranges": [
        {
          "lt": "4.1.40"
        },
        {
          "gte": "4.2",
          "lt": "4.2.37"
        },
        {
          "gte": "4.3",
          "lt": "4.3.33"
        },
        {
          "gte": "4.4",
          "lt": "4.4.32"
        },
        {
          "gte": "4.5",
          "lt": "4.5.31"
        },
        {
          "gte": "4.6",
          "lt": "4.6.28"
        },
        {
          "gte": "4.7",
          "lt": "4.7.28"
        },
        {
          "gte": "4.8",
          "lt": "4.8.24"
        },
        {
          "gte": "4.9",
          "lt": "4.9.25"
        },
        {
          "gte": "5.0",
          "lt": "5.0.21"
        },
        {
          "gte": "5.1",
          "lt": "5.1.18"
        },
        {
          "gte": "5.2",
          "lt": "5.2.20"
        },
        {
          "gte": "5.3",
          "lt": "5.3.17"
        },
        {
          "gte": "5.4",
          "lt": "5.4.15"
        },
        {
          "gte": "5.5",
          "lt": "5.5.14"
        },
        {
          "gte": "5.6",
          "lt": "5.6.13"
        },
        {
          "gte": "5.7",
          "lt": "5.7.11"
        },
        {
          "gte": "5.8",
          "lt": "5.8.9"
        },
        {
          "gte": "5.9",
          "lt": "5.9.9"
        },
        {
          "gte": "6.0",
          "lt": "6.0.7"
        },
        {
          "gte": "6.1",
          "lt": "6.1.5"
        },
        {
          "gte": "6.2",
          "lt": "6.2.4"
        },
        {
          "gte": "6.3",
          "lt": "6.3.3"
        },
        {
          "gte": "6.4.0",
          "lt": "6.4.3"
        }
      ],
      "note": "NVD: WordPress is an open publishing platform for the Web."
    },
    {
      "cve": "CVE-2024-4439",
      "sev": "high",
      "kev": false,
      "title": "WordPress Core is vulnerable to Stored Cross-Site Scripting via user display names in…",
      "ranges": [
        {
          "gte": "6.0",
          "lte": "6.0.7"
        },
        {
          "gte": "6.1",
          "lte": "6.1.5"
        },
        {
          "gte": "6.2",
          "lte": "6.2.4"
        },
        {
          "gte": "6.3",
          "lte": "6.3.3"
        },
        {
          "gte": "6.4.0",
          "lte": "6.4.3"
        },
        {
          "gte": "6.5",
          "lte": "6.5.1"
        }
      ],
      "note": "NVD: WordPress Core is vulnerable to Stored Cross-Site Scripting via user display names in the Avatar block in various versions up to 6.5.2 due to insufficient output…"
    },
    {
      "cve": "CVE-2022-21664",
      "sev": "high",
      "kev": false,
      "title": "WordPress is a free and open-source content management system written in PHP and…",
      "ranges": [
        {
          "lt": "5.8.3"
        }
      ],
      "note": "NVD: WordPress is a free and open-source content management system written in PHP and paired with a MariaDB database."
    },
    {
      "cve": "CVE-2022-21662",
      "sev": "high",
      "kev": false,
      "title": "WordPress is a free and open-source content management system written in PHP and…",
      "ranges": [
        {
          "lt": "5.8.3"
        }
      ],
      "note": "NVD: WordPress is a free and open-source content management system written in PHP and paired with a MariaDB database."
    },
    {
      "cve": "CVE-2022-21661",
      "sev": "high",
      "kev": false,
      "title": "WordPress is a free and open-source content management system written in PHP and…",
      "ranges": [
        {
          "gte": "3.7",
          "lt": "3.7.37"
        },
        {
          "gte": "3.8",
          "lt": "3.8.37"
        },
        {
          "gte": "3.9",
          "lt": "3.9.35"
        },
        {
          "gte": "4.0",
          "lt": "4.0.34"
        },
        {
          "gte": "4.1",
          "lt": "4.1.34"
        },
        {
          "gte": "4.2",
          "lt": "4.2.31"
        },
        {
          "gte": "4.3",
          "lt": "4.3.27"
        },
        {
          "gte": "4.4",
          "lt": "4.4.26"
        },
        {
          "gte": "4.5",
          "lt": "4.5.25"
        },
        {
          "gte": "4.6",
          "lt": "4.6.22"
        },
        {
          "gte": "4.7",
          "lt": "4.7.22"
        },
        {
          "gte": "4.8",
          "lt": "4.8.18"
        },
        {
          "gte": "4.9",
          "lt": "4.9.19"
        },
        {
          "gte": "5.0",
          "lt": "5.0.15"
        },
        {
          "gte": "5.1",
          "lt": "5.1.12"
        },
        {
          "gte": "5.2",
          "lt": "5.2.14"
        },
        {
          "gte": "5.3",
          "lt": "5.3.11"
        },
        {
          "gte": "5.4",
          "lt": "5.4.9"
        },
        {
          "gte": "5.5",
          "lt": "5.5.8"
        },
        {
          "gte": "5.6",
          "lt": "5.6.7"
        },
        {
          "gte": "5.7",
          "lt": "5.7.5"
        },
        {
          "gte": "5.8",
          "lt": "5.8.3"
        }
      ],
      "note": "NVD: WordPress is a free and open-source content management system written in PHP and paired with a MariaDB database."
    },
    {
      "cve": "CVE-2021-44223",
      "sev": "high",
      "kev": false,
      "title": "WordPress before 5.8 lacks support for the Update URI plugin header.",
      "ranges": [
        {
          "lt": "5.8"
        }
      ],
      "note": "NVD: WordPress before 5.8 lacks support for the Update URI plugin header."
    },
    {
      "cve": "CVE-2021-39202",
      "sev": "high",
      "kev": false,
      "title": "WordPress is a free and open-source content management system written in PHP and…",
      "ranges": [
        {
          "eq": "5.8"
        }
      ],
      "note": "NVD: WordPress is a free and open-source content management system written in PHP and paired with a MySQL or MariaDB database."
    },
    {
      "cve": "CVE-2021-39201",
      "sev": "high",
      "kev": false,
      "title": "WordPress is a free and open-source content management system written in PHP and…",
      "ranges": [
        {
          "gte": "5.0",
          "lt": "5.8"
        }
      ],
      "note": "NVD: WordPress is a free and open-source content management system written in PHP and paired with a MySQL or MariaDB database."
    },
    {
      "cve": "CVE-2021-29447",
      "sev": "high",
      "kev": false,
      "title": "Wordpress is an open source CMS.",
      "ranges": [
        {
          "gte": "5.6.0",
          "lt": "5.7.1"
        }
      ],
      "note": "NVD: Wordpress is an open source CMS."
    },
    {
      "cve": "CVE-2020-36326",
      "sev": "critical",
      "kev": false,
      "title": "PHPMailer 6.1.8 through 6.4.0 allows object injection through Phar Deserialization via…",
      "ranges": [
        {
          "gte": "3.7",
          "lt": "3.7.36"
        },
        {
          "gte": "3.8",
          "lt": "3.8.36"
        },
        {
          "gte": "3.9",
          "lt": "3.9.34"
        },
        {
          "gte": "4.0",
          "lt": "4.0.33"
        },
        {
          "gte": "4.1",
          "lt": "4.1.33"
        },
        {
          "gte": "4.2",
          "lt": "4.2.30"
        },
        {
          "gte": "4.3",
          "lt": "4.3.26"
        },
        {
          "gte": "4.4",
          "lt": "4.4.25"
        },
        {
          "gte": "4.5",
          "lt": "4.5.24"
        },
        {
          "gte": "4.6",
          "lt": "4.6.21"
        },
        {
          "gte": "4.7",
          "lt": "4.7.21"
        },
        {
          "gte": "4.8",
          "lt": "4.8.17"
        },
        {
          "gte": "4.9",
          "lt": "4.9.18"
        },
        {
          "gte": "5.0",
          "lt": "5.0.13"
        },
        {
          "gte": "5.1",
          "lt": "5.1.10"
        },
        {
          "gte": "5.2",
          "lt": "5.2.11"
        },
        {
          "gte": "5.3",
          "lt": "5.3.8"
        },
        {
          "gte": "5.4",
          "lt": "5.4.6"
        },
        {
          "gte": "5.5",
          "lt": "5.5.5"
        },
        {
          "gte": "5.6",
          "lt": "5.6.4"
        },
        {
          "gte": "5.7",
          "lt": "5.7.2"
        }
      ],
      "note": "NVD: PHPMailer 6.1.8 through 6.4.0 allows object injection through Phar Deserialization via addAttachment with a UNC pathname."
    },
    {
      "cve": "CVE-2020-28039",
      "sev": "critical",
      "kev": false,
      "title": "is_protected_meta in wp-includes/meta.php in WordPress before 5.5.2 allows arbitrary…",
      "ranges": [
        {
          "lt": "5.5.2"
        }
      ],
      "note": "NVD: is_protected_meta in wp-includes/meta.php in WordPress before 5.5.2 allows arbitrary file deletion because it does not properly determine whether a meta key is…"
    },
    {
      "cve": "CVE-2020-28037",
      "sev": "critical",
      "kev": false,
      "title": "is_blog_installed in wp-includes/functions.php in WordPress before 5.5.2 improperly…",
      "ranges": [
        {
          "lt": "5.5.2"
        }
      ],
      "note": "NVD: is_blog_installed in wp-includes/functions.php in WordPress before 5.5.2 improperly determines whether WordPress is already installed, which might allow an…"
    },
    {
      "cve": "CVE-2020-28036",
      "sev": "critical",
      "kev": false,
      "title": "wp-includes/class-wp-xmlrpc-server.php in WordPress before 5.5.2 allows attackers to…",
      "ranges": [
        {
          "lt": "5.5.2"
        }
      ],
      "note": "NVD: wp-includes/class-wp-xmlrpc-server.php in WordPress before 5.5.2 allows attackers to gain privileges by using XML-RPC to comment on a post."
    },
    {
      "cve": "CVE-2020-28035",
      "sev": "critical",
      "kev": false,
      "title": "WordPress before 5.5.2 allows attackers to gain privileges via XML-RPC.",
      "ranges": [
        {
          "lt": "5.5.2"
        }
      ],
      "note": "NVD: WordPress before 5.5.2 allows attackers to gain privileges via XML-RPC."
    },
    {
      "cve": "CVE-2020-28033",
      "sev": "high",
      "kev": false,
      "title": "WordPress before 5.5.2 mishandles embeds from disabled sites on a multisite network,…",
      "ranges": [
        {
          "lt": "5.5.2"
        }
      ],
      "note": "NVD: WordPress before 5.5.2 mishandles embeds from disabled sites on a multisite network, as demonstrated by allowing a spam embed."
    },
    {
      "cve": "CVE-2020-28032",
      "sev": "critical",
      "kev": false,
      "title": "WordPress before 5.5.2 mishandles deserialization requests in…",
      "ranges": [
        {
          "lt": "5.5.2"
        }
      ],
      "note": "NVD: WordPress before 5.5.2 mishandles deserialization requests in wp-includes/Requests/Utility/FilteredIterator.php."
    },
    {
      "cve": "CVE-2020-11026",
      "sev": "high",
      "kev": false,
      "title": "In affected versions of WordPress, files with a specially crafted name when uploaded…",
      "ranges": [
        {
          "gte": "3.7",
          "lt": "3.7.33"
        },
        {
          "gte": "3.8",
          "lt": "3.8.33"
        },
        {
          "gte": "3.9",
          "lt": "3.9.31"
        },
        {
          "gte": "4.0",
          "lt": "4.0.30"
        },
        {
          "gte": "4.1",
          "lt": "4.1.30"
        },
        {
          "gte": "4.2",
          "lt": "4.2.27"
        },
        {
          "gte": "4.3",
          "lt": "4.3.23"
        },
        {
          "gte": "4.4",
          "lt": "4.4.22"
        },
        {
          "gte": "4.5",
          "lt": "4.5.21"
        },
        {
          "gte": "4.6",
          "lt": "4.6.18"
        },
        {
          "gte": "4.7",
          "lt": "4.7.17"
        },
        {
          "gte": "4.8",
          "lt": "4.8.13"
        },
        {
          "gte": "4.9",
          "lt": "4.9.14"
        },
        {
          "gte": "5.0",
          "lt": "5.0.9"
        },
        {
          "gte": "5.1",
          "lt": "5.1.5"
        },
        {
          "gte": "5.2",
          "lt": "5.2.6"
        },
        {
          "gte": "5.3",
          "lt": "5.3.3"
        },
        {
          "eq": "5.4"
        }
      ],
      "note": "NVD: In affected versions of WordPress, files with a specially crafted name when uploaded to the Media section can lead to script execution upon accessing the file."
    },
    {
      "cve": "CVE-2019-20041",
      "sev": "critical",
      "kev": false,
      "title": "wp_kses_bad_protocol in wp-includes/kses.php in WordPress before 5.3.1 mishandles the…",
      "ranges": [
        {
          "lt": "5.3.1"
        }
      ],
      "note": "NVD: wp_kses_bad_protocol in wp-includes/kses.php in WordPress before 5.3.1 mishandles the HTML5 colon named entity, allowing attackers to bypass input sanitization, as…"
    },
    {
      "cve": "CVE-2019-17675",
      "sev": "high",
      "kev": false,
      "title": "WordPress before 5.2.4 does not properly consider type confusion during validation of…",
      "ranges": [
        {
          "lt": "5.2.4"
        }
      ],
      "note": "NVD: WordPress before 5.2.4 does not properly consider type confusion during validation of the referer in the admin pages, possibly leading to CSRF."
    },
    {
      "cve": "CVE-2019-17673",
      "sev": "high",
      "kev": false,
      "title": "WordPress before 5.2.4 is vulnerable to poisoning of the cache of JSON GET requests…",
      "ranges": [
        {
          "lt": "5.2.4"
        }
      ],
      "note": "NVD: WordPress before 5.2.4 is vulnerable to poisoning of the cache of JSON GET requests because certain requests lack a Vary: Origin header."
    },
    {
      "cve": "CVE-2019-17670",
      "sev": "critical",
      "kev": false,
      "title": "WordPress before 5.2.4 has a Server Side Request Forgery (SSRF) vulnerability because…",
      "ranges": [
        {
          "lt": "5.2.4"
        }
      ],
      "note": "NVD: WordPress before 5.2.4 has a Server Side Request Forgery (SSRF) vulnerability because Windows paths are mishandled during certain validation of relative URLs."
    },
    {
      "cve": "CVE-2019-17669",
      "sev": "critical",
      "kev": false,
      "title": "WordPress before 5.2.4 has a Server Side Request Forgery (SSRF) vulnerability because…",
      "ranges": [
        {
          "lt": "5.2.4"
        }
      ],
      "note": "NVD: WordPress before 5.2.4 has a Server Side Request Forgery (SSRF) vulnerability because URL validation does not consider the interpretation of a name as a series of…"
    },
    {
      "cve": "CVE-2019-9787",
      "sev": "high",
      "kev": false,
      "title": "WordPress before 5.1.1 does not properly filter comment content, leading to Remote…",
      "ranges": [
        {
          "lt": "5.1.1"
        }
      ],
      "note": "NVD: WordPress before 5.1.1 does not properly filter comment content, leading to Remote Code Execution by unauthenticated users in a default configuration."
    },
    {
      "cve": "CVE-2019-8942",
      "sev": "high",
      "kev": false,
      "title": "WordPress before 4.9.9 and 5.x before 5.0.1 allows remote code execution because an…",
      "ranges": [
        {
          "lt": "4.9.9"
        },
        {
          "eq": "5.0"
        }
      ],
      "note": "NVD: WordPress before 4.9.9 and 5.x before 5.0.1 allows remote code execution because an _wp_attached_file Post Meta entry can be changed to an arbitrary string, such…"
    },
    {
      "cve": "CVE-2018-1000773",
      "sev": "high",
      "kev": false,
      "title": "WordPress version 4.9.8 and earlier contains a CWE-20 Input Validation vulnerability…",
      "ranges": [
        {
          "lte": "4.9.8"
        }
      ],
      "note": "NVD: WordPress version 4.9.8 and earlier contains a CWE-20 Input Validation vulnerability in thumbnail processing that can result in remote code execution due to an…"
    },
    {
      "cve": "CVE-2018-20151",
      "sev": "high",
      "kev": false,
      "title": "In WordPress before 4.9.9 and 5.x before 5.0.1, the user-activation page could be read…",
      "ranges": [
        {
          "lt": "4.9.9"
        },
        {
          "gte": "5.0",
          "lt": "5.0.1"
        }
      ],
      "note": "NVD: In WordPress before 4.9.9 and 5.x before 5.0.1, the user-activation page could be read by a search engine's web crawler if an unusual configuration were chosen."
    },
    {
      "cve": "CVE-2018-20148",
      "sev": "critical",
      "kev": false,
      "title": "In WordPress before 4.9.9 and 5.x before 5.0.1, contributors could conduct PHP object…",
      "ranges": [
        {
          "lt": "4.9.9"
        },
        {
          "gte": "5.0",
          "lt": "5.0.1"
        }
      ],
      "note": "NVD: In WordPress before 4.9.9 and 5.x before 5.0.1, contributors could conduct PHP object injection attacks via crafted metadata in a wp.getMediaItem XMLRPC call."
    },
    {
      "cve": "CVE-2018-19296",
      "sev": "high",
      "kev": false,
      "title": "PHPMailer before 5.2.27 and 6.x before 6.0.6 is vulnerable to an object injection…",
      "ranges": [
        {
          "gte": "3.7",
          "lte": "5.7"
        }
      ],
      "note": "NVD: PHPMailer before 5.2.27 and 6.x before 6.0.6 is vulnerable to an object injection attack."
    },
    {
      "cve": "CVE-2018-14028",
      "sev": "high",
      "kev": false,
      "title": "In WordPress 4.9.7, plugins uploaded via the admin area are not verified as being ZIP…",
      "ranges": [
        {
          "eq": "4.9.7"
        }
      ],
      "note": "NVD: In WordPress 4.9.7, plugins uploaded via the admin area are not verified as being ZIP files."
    },
    {
      "cve": "CVE-2018-12895",
      "sev": "high",
      "kev": false,
      "title": "WordPress through 4.9.6 allows Author users to execute arbitrary code by leveraging…",
      "ranges": [
        {
          "lt": "4.9.7"
        }
      ],
      "note": "NVD: WordPress through 4.9.6 allows Author users to execute arbitrary code by leveraging directory traversal in the wp-admin/post.php thumb parameter, which is passed…"
    },
    {
      "cve": "CVE-2018-6389",
      "sev": "high",
      "kev": false,
      "title": "In WordPress through 4.9.2, unauthenticated attackers can cause a denial of service…",
      "ranges": [
        {
          "lte": "4.9.2"
        }
      ],
      "note": "NVD: In WordPress through 4.9.2, unauthenticated attackers can cause a denial of service (resource consumption) by using the large list of registered .js files (from…"
    },
    {
      "cve": "CVE-2017-1001000",
      "sev": "high",
      "kev": false,
      "title": "The register_routes function in wp-includes/rest-api/endpoints/class-wp-rest-posts-cont…",
      "ranges": [
        {
          "eq": "4.7"
        },
        {
          "eq": "4.7.1"
        },
        {
          "eq": "4.7.2"
        }
      ],
      "note": "NVD: The register_routes function in wp-includes/rest-api/endpoints/class-wp-rest-posts-controller.php in the REST API in WordPress 4.7.x before 4.7.2 does not require…"
    },
    {
      "cve": "CVE-2017-1000600",
      "sev": "high",
      "kev": false,
      "title": "WordPress version <4.9 contains a CWE-20 Input Validation vulnerability in thumbnail…",
      "ranges": [
        {
          "lt": "4.9"
        }
      ],
      "note": "NVD: WordPress version <4.9 contains a CWE-20 Input Validation vulnerability in thumbnail processing that can result in remote code execution."
    },
    {
      "cve": "CVE-2017-17091",
      "sev": "high",
      "kev": false,
      "title": "wp-admin/user-new.php in WordPress before 4.9.1 sets the newbloguser key to a string…",
      "ranges": [
        {
          "lte": "4.9"
        }
      ],
      "note": "NVD: wp-admin/user-new.php in WordPress before 4.9.1 sets the newbloguser key to a string that can be directly derived from the user ID, which allows remote attackers…"
    },
    {
      "cve": "CVE-2017-16510",
      "sev": "critical",
      "kev": false,
      "title": "WordPress before 4.8.3 is affected by an issue where $wpdb->prepare() can create…",
      "ranges": [
        {
          "lte": "4.8.2"
        }
      ],
      "note": "NVD: WordPress before 4.8.3 is affected by an issue where $wpdb->prepare() can create unexpected and unsafe queries leading to potential SQL injection (SQLi) in plugins…"
    },
    {
      "cve": "CVE-2017-14723",
      "sev": "critical",
      "kev": false,
      "title": "Before version 4.8.2, WordPress mishandled % characters and additional placeholder…",
      "ranges": [
        {
          "lte": "4.8.1"
        }
      ],
      "note": "NVD: Before version 4.8.2, WordPress mishandled % characters and additional placeholder values in $wpdb->prepare, and thus did not properly address the possibility of…"
    },
    {
      "cve": "CVE-2017-14722",
      "sev": "high",
      "kev": false,
      "title": "Before version 4.8.2, WordPress allowed a Directory Traversal attack in the Customizer…",
      "ranges": [
        {
          "eq": "4.7"
        },
        {
          "eq": "4.7.1"
        },
        {
          "eq": "4.7.2"
        },
        {
          "eq": "4.7.3"
        },
        {
          "eq": "4.7.4"
        },
        {
          "eq": "4.7.5"
        },
        {
          "eq": "4.8"
        },
        {
          "eq": "4.8.1"
        }
      ],
      "note": "NVD: Before version 4.8.2, WordPress allowed a Directory Traversal attack in the Customizer component via a crafted theme filename."
    },
    {
      "cve": "CVE-2017-9066",
      "sev": "high",
      "kev": false,
      "title": "In WordPress before 4.7.5, there is insufficient redirect validation in the HTTP…",
      "ranges": [
        {
          "lte": "4.7.4"
        }
      ],
      "note": "NVD: In WordPress before 4.7.5, there is insufficient redirect validation in the HTTP class, leading to SSRF."
    },
    {
      "cve": "CVE-2017-9065",
      "sev": "high",
      "kev": false,
      "title": "In WordPress before 4.7.5, there is a lack of capability checks for post meta data in…",
      "ranges": [
        {
          "lte": "4.7.4"
        }
      ],
      "note": "NVD: In WordPress before 4.7.5, there is a lack of capability checks for post meta data in the XML-RPC API."
    },
    {
      "cve": "CVE-2017-9064",
      "sev": "high",
      "kev": false,
      "title": "In WordPress before 4.7.5, a Cross Site Request Forgery (CSRF) vulnerability exists in…",
      "ranges": [
        {
          "lte": "4.7.4"
        }
      ],
      "note": "NVD: In WordPress before 4.7.5, a Cross Site Request Forgery (CSRF) vulnerability exists in the filesystem credentials dialog because a nonce is not required for…"
    },
    {
      "cve": "CVE-2017-9062",
      "sev": "high",
      "kev": false,
      "title": "In WordPress before 4.7.5, there is improper handling of post meta data values in the…",
      "ranges": [
        {
          "lte": "4.7.4"
        }
      ],
      "note": "NVD: In WordPress before 4.7.5, there is improper handling of post meta data values in the XML-RPC API."
    },
    {
      "cve": "CVE-2017-5611",
      "sev": "critical",
      "kev": false,
      "title": "SQL injection vulnerability in wp-includes/class-wp-query.php in WP_Query in WordPress…",
      "ranges": [
        {
          "lte": "4.7.1"
        }
      ],
      "note": "NVD: SQL injection vulnerability in wp-includes/class-wp-query.php in WP_Query in WordPress before 4.7.2 allows remote attackers to execute arbitrary SQL commands by…"
    },
    {
      "cve": "CVE-2017-5493",
      "sev": "high",
      "kev": false,
      "title": "wp-includes/ms-functions.php in the Multisite WordPress API in WordPress before 4.7.1…",
      "ranges": [
        {
          "lte": "4.7"
        }
      ],
      "note": "NVD: wp-includes/ms-functions.php in the Multisite WordPress API in WordPress before 4.7.1 does not properly choose random numbers for keys, which makes it easier for…"
    },
    {
      "cve": "CVE-2017-5492",
      "sev": "high",
      "kev": false,
      "title": "Cross-site request forgery (CSRF) vulnerability in the widget-editing…",
      "ranges": [
        {
          "lte": "4.7"
        }
      ],
      "note": "NVD: Cross-site request forgery (CSRF) vulnerability in the widget-editing accessibility-mode feature in WordPress before 4.7.1 allows remote attackers to hijack the…"
    },
    {
      "cve": "CVE-2017-5489",
      "sev": "high",
      "kev": false,
      "title": "Cross-site request forgery (CSRF) vulnerability in WordPress before 4.7.1 allows…",
      "ranges": [
        {
          "lte": "4.7"
        }
      ],
      "note": "NVD: Cross-site request forgery (CSRF) vulnerability in WordPress before 4.7.1 allows remote attackers to hijack the authentication of unspecified victims via vectors…"
    },
    {
      "cve": "CVE-2016-10045",
      "sev": "critical",
      "kev": false,
      "title": "The isMail transport in PHPMailer before 5.2.20 might allow remote attackers to pass…",
      "ranges": [
        {
          "lte": "4.7"
        }
      ],
      "note": "NVD: The isMail transport in PHPMailer before 5.2.20 might allow remote attackers to pass extra parameters to the mail command and consequently execute arbitrary code…"
    },
    {
      "cve": "CVE-2016-10033",
      "sev": "critical",
      "kev": true,
      "title": "The mailSend function in the isMail transport in PHPMailer before 5.2.18 might allow…",
      "ranges": [
        {
          "lte": "4.7"
        }
      ],
      "note": "NVD: The mailSend function in the isMail transport in PHPMailer before 5.2.18 might allow remote attackers to pass extra parameters to… — CISA KEV (actively exploited)"
    },
    {
      "cve": "CVE-2016-6896",
      "sev": "high",
      "kev": false,
      "title": "Directory traversal vulnerability in the wp_ajax_update_plugin function in…",
      "ranges": [
        {
          "eq": "4.5.3"
        }
      ],
      "note": "NVD: Directory traversal vulnerability in the wp_ajax_update_plugin function in wp-admin/includes/ajax-actions.php in WordPress 4.5.3 allows remote authenticated users…"
    },
    {
      "cve": "CVE-2016-6635",
      "sev": "high",
      "kev": false,
      "title": "Cross-site request forgery (CSRF) vulnerability in the wp_ajax_wp_compression_test…",
      "ranges": [
        {
          "lte": "4.4.2"
        }
      ],
      "note": "NVD: Cross-site request forgery (CSRF) vulnerability in the wp_ajax_wp_compression_test function in wp-admin/includes/ajax-actions.php in WordPress before 4.5 allows…"
    },
    {
      "cve": "CVE-2016-5839",
      "sev": "high",
      "kev": false,
      "title": "WordPress before 4.5.3 allows remote attackers to bypass the sanitize_file_name…",
      "ranges": [
        {
          "lte": "4.5.2"
        }
      ],
      "note": "NVD: WordPress before 4.5.3 allows remote attackers to bypass the sanitize_file_name protection mechanism via unspecified vectors."
    },
    {
      "cve": "CVE-2016-5838",
      "sev": "high",
      "kev": false,
      "title": "WordPress before 4.5.3 allows remote attackers to bypass intended password-change…",
      "ranges": [
        {
          "lte": "4.5.2"
        }
      ],
      "note": "NVD: WordPress before 4.5.3 allows remote attackers to bypass intended password-change restrictions by leveraging knowledge of a cookie."
    },
    {
      "cve": "CVE-2016-5837",
      "sev": "high",
      "kev": false,
      "title": "WordPress before 4.5.3 allows remote attackers to bypass intended access restrictions…",
      "ranges": [
        {
          "lte": "4.5.2"
        }
      ],
      "note": "NVD: WordPress before 4.5.3 allows remote attackers to bypass intended access restrictions and remove a category attribute from a post via unspecified vectors."
    },
    {
      "cve": "CVE-2016-5836",
      "sev": "high",
      "kev": false,
      "title": "The oEmbed protocol implementation in WordPress before 4.5.3 allows remote attackers…",
      "ranges": [
        {
          "lte": "4.5.2"
        }
      ],
      "note": "NVD: The oEmbed protocol implementation in WordPress before 4.5.3 allows remote attackers to cause a denial of service via unspecified vectors."
    },
    {
      "cve": "CVE-2016-5835",
      "sev": "high",
      "kev": false,
      "title": "WordPress before 4.5.3 allows remote attackers to obtain sensitive revision-history…",
      "ranges": [
        {
          "lte": "4.5.2"
        }
      ],
      "note": "NVD: WordPress before 4.5.3 allows remote attackers to obtain sensitive revision-history information by leveraging the ability to read a post, related to…"
    },
    {
      "cve": "CVE-2016-5832",
      "sev": "high",
      "kev": false,
      "title": "The customizer in WordPress before 4.5.3 allows remote attackers to bypass intended…",
      "ranges": [
        {
          "lte": "4.5.2"
        }
      ],
      "note": "NVD: The customizer in WordPress before 4.5.3 allows remote attackers to bypass intended redirection restrictions via unspecified vectors."
    },
    {
      "cve": "CVE-2016-4029",
      "sev": "high",
      "kev": false,
      "title": "WordPress before 4.5 does not consider octal and hexadecimal IP address formats when…",
      "ranges": [
        {
          "lt": "4.5"
        }
      ],
      "note": "NVD: WordPress before 4.5 does not consider octal and hexadecimal IP address formats when determining an intranet address, which allows remote attackers to bypass an…"
    },
    {
      "cve": "CVE-2016-2222",
      "sev": "high",
      "kev": false,
      "title": "The wp_http_validate_url function in wp-includes/http.php in WordPress before 4.4.2…",
      "ranges": [
        {
          "eq": "4.4.1"
        }
      ],
      "note": "NVD: The wp_http_validate_url function in wp-includes/http.php in WordPress before 4.4.2 allows remote attackers to conduct server-side request forgery (SSRF) attacks…"
    },
    {
      "cve": "CVE-2016-2221",
      "sev": "high",
      "kev": false,
      "title": "Open redirect vulnerability in the wp_validate_redirect function in…",
      "ranges": [
        {
          "lte": "4.4.1"
        }
      ],
      "note": "NVD: Open redirect vulnerability in the wp_validate_redirect function in wp-includes/pluggable.php in WordPress before 4.4.2 allows remote attackers to redirect users…"
    }
  ]
};
