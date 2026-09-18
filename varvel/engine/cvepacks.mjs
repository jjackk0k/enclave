// VARVEL — curated version→CVE correlation packs (the real Nuclei-killer).
//
// Nuclei's model: 9,000 templates, fire them all, sort out the noise afterwards.
// VARVEL's model: wappalyze tells us the EXACT stack + version (from pages the crawl
// already fetched), and this pack answers the only question that matters — "is THIS
// version in a known-affected range?" Targeted, version-evidenced, zero extra requests.
//
// HONESTY CONTRACT (load-bearing, do not soften):
//   · A pack entry fires ONLY when a version was actually fingerprinted — never on
//     tech presence alone ("runs nginx" says nothing; "runs nginx 1.18.0" does).
//   · Version-matched CVEs are confidence 'firm', NOT 'confirmed': a version in an
//     affected range means "verify exploitability", not "exploitable". Backports mean
//     a distro package can carry an affected version number with the fix applied —
//     the evidence string says exactly why it fired so verification is one step.
//   · Every entry is a real, well-documented CVE with an honest affected range.
//     If the range isn't publicly established, the CVE does not go in the pack.
//
// Ranges: OR semantics over { gte, gt, lte, lt } clauses on dotted-numeric versions.
//
// TWO SOURCES, ONE PACK: the hand-reviewed entries below (CURATED_CVE_PACKS) are
// merged with engine/cvepacks.generated.mjs — the NVD/KEV-derived pack built by
// tools/cvepack-import.mjs (a versioned build artifact; see its header). Merge rule:
// a curated entry for the same (tech, cve) ALWAYS wins — a hand-tuned range or note
// is never silently overwritten by a generated one. cveCheck and the CVE_PACKS export
// are unchanged in shape; the pack is simply wider.

import { GENERATED_CVE_PACKS } from './cvepacks.generated.mjs';

// ——— version utilities (exported for tests) ———
// Parse a dotted-numeric version prefix: '1.18.0-alpine' → [1,18,0]. null if none.
export function parseVersion(s) {
  const m = /^(\d+(?:\.\d+)*)/.exec(String(s || '').trim());
  return m ? m[1].split('.').map(Number) : null;
}
// Compare two version arrays: -1 / 0 / +1 (missing components = 0).
export function compareVersions(a, b) {
  const va = parseVersion(a), vb = parseVersion(b);
  if (!va || !vb) return null;
  const n = Math.max(va.length, vb.length);
  for (let i = 0; i < n; i++) {
    const d = (va[i] || 0) - (vb[i] || 0);
    if (d) return d < 0 ? -1 : 1;
  }
  return 0;
}
export function inRange(version, range) {
  const v = parseVersion(version);
  if (!v) return false;
  if (range.gte && compareVersions(version, range.gte) < 0) return false;
  if (range.gt && compareVersions(version, range.gt) <= 0) return false;
  if (range.lte && compareVersions(version, range.lte) > 0) return false;
  if (range.lt && compareVersions(version, range.lt) >= 0) return false;
  if (range.eq && compareVersions(version, range.eq) !== 0) return false;
  return true;
}
export function inRanges(version, ranges) { return (ranges || []).some((r) => inRange(version, r)); }

// ——— the curated packs: keyed by wappalyze tech id (hand-reviewed; exported for audits) ———
// kev: in CISA's Known Exploited Vulnerabilities catalog (active exploitation in the wild).
export const CURATED_CVE_PACKS = {
  apache: [
    { cve: 'CVE-2021-41773', sev: 'critical', kev: true, title: 'Apache httpd path traversal → RCE (CGI enabled)',
      ranges: [{ eq: '2.4.49' }],
      note: 'Actively exploited in the wild (KEV). Path normalization flaw allows traversal; RCE when CGI is enabled.' },
    { cve: 'CVE-2021-42013', sev: 'critical', kev: true, title: 'Apache httpd path traversal → RCE (incomplete 41773 fix)',
      ranges: [{ eq: '2.4.50' }],
      note: 'The 2.4.50 fix for CVE-2021-41773 was incomplete. KEV.' },
    { cve: 'CVE-2023-25690', sev: 'critical', kev: false, title: 'Apache httpd HTTP request smuggling',
      ranges: [{ lt: '2.4.56' }],
      note: 'mod_proxy request splitting/smuggling; can bypass access controls on proxied backends.' },
  ],
  nginx: [
    { cve: 'CVE-2021-23017', sev: 'high', kev: false, title: 'nginx resolver off-by-one heap write',
      ranges: [{ gte: '0.6.18', lte: '1.20.0' }],
      note: 'DNS resolver flaw; RCE possible when nginx resolves attacker-influenced names.' },
  ],
  iis: [
    { cve: 'CVE-2017-7269', sev: 'critical', kev: true, title: 'IIS 6.0 WebDAV ScStoragePathFromUrl RCE',
      ranges: [{ lt: '7.0' }],
      note: 'Windows Server 2003 / IIS 6.0 WebDAV buffer overflow. KEV — exploited since 2017.' },
  ],
  php: [
    { cve: 'CVE-2024-4577', sev: 'critical', kev: true, title: 'PHP-CGI argument injection → RCE (Windows, CJK locales)',
      ranges: [{ lt: '8.1.29' }, { gte: '8.2.0', lt: '8.2.20' }, { gte: '8.3.0', lt: '8.3.8' }],
      note: 'PHP-CGI on Windows bypasses the CVE-2012-1823 fix. KEV — exploited within days of disclosure.' },
  ],
  tomcat: [
    { cve: 'CVE-2020-1938', sev: 'critical', kev: false, title: 'Tomcat AJP Ghostcat — file read/inclusion via AJP connector',
      ranges: [{ lt: '7.0.100' }, { gte: '8.0.0', lt: '8.5.51' }, { gte: '9.0.0', lt: '9.0.31' }],
      note: 'AJP connector (default :8009) exposed → read webapp files; RCE when file upload exists.' },
    { cve: 'CVE-2025-24813', sev: 'critical', kev: true, title: 'Tomcat partial PUT → deserialization RCE',
      ranges: [{ gte: '11.0.0', lt: '11.0.3' }, { gte: '10.1.0', lt: '10.1.35' }, { gte: '9.0.0', lt: '9.0.99' }],
      note: 'Partial PUT + default servlet write enabled → session persistence deserialization. KEV 2025.' },
  ],
  jquery: [
    { cve: 'CVE-2020-11023', sev: 'medium', kev: false, title: 'jQuery HTML injection via untrusted <option> manipulation',
      ranges: [{ lt: '3.5.0' }],
      note: 'XSS via HTML containing crafted <option> elements passed to DOM methods.' },
  ],
};

// Merge curated + generated packs per (tech, cve). Curated wins on conflict (the
// header contract above); generated entries for new CVEs/techs are appended after the
// curated ones. Inputs are not mutated. Exported for tests.
export function mergePacks(curated, generated) {
  const out = {};
  for (const [tech, packs] of Object.entries(curated || {})) out[tech] = packs.slice();
  for (const [tech, packs] of Object.entries(generated || {})) {
    const cur = out[tech] || (out[tech] = []);
    const have = new Set(cur.map((p) => p.cve));
    for (const p of packs || []) {
      if (have.has(p.cve)) continue; // hand-tuned beats generated, silently by design
      cur.push(p);
      have.add(p.cve);
    }
  }
  return out;
}

// The pack the engine actually reasons over: curated 9 + the NVD-generated hundreds.
export const CVE_PACKS = mergePacks(CURATED_CVE_PACKS, GENERATED_CVE_PACKS);

// Correlate a wappalyze fingerprint list against the packs.
// techList: [{ id, label, version, ... }] — entries WITHOUT a version can never fire.
// Returns vulncheck-shaped findings (id/title/sev/path/evidence/confidence/ref assigned by caller).
export function cveCheck(techList) {
  const out = [];
  for (const t of Array.isArray(techList) ? techList : []) {
    const packs = CVE_PACKS[t && t.id];
    if (!packs || !t.version) continue; // no version → no version-based claim, ever
    for (const p of packs) {
      if (!inRanges(t.version, p.ranges)) continue;
      out.push({
        id: 'cve-' + p.cve.toLowerCase(),
        cve: p.cve,
        title: `${p.cve} — ${p.title} (${t.label} ${t.version} is in the affected range)`,
        sev: p.sev,
        kev: !!p.kev,
        tech: t.id,
        version: t.version,
        evidence: `${t.label} ${t.version} fingerprinted; affected ${p.ranges.map((r) => Object.entries(r).map(([k, v]) => k + ' ' + v).join(' ')).join(' OR ')}`,
        note: p.note,
        // firm, not confirmed — a version match is a verification target, not a proved exploit
        confidence: 'firm',
        verify: 'Confirm exploitability before treating as exploitable (distro backports can carry an affected version with the fix applied).',
      });
    }
  }
  return out;
}
