// VARVEL — canary & deception detection (stealth insurance nobody else ships).
//
// Material reviewed: HYDRA CanaryDetector (known canary domains / IP prefixes / UUID
// patterns / honey-file indicators + DNS A/CNAME/TXT/MX + common-subdomain checks).
// Ported governed and honest: this tool produces a SUSPICION SCORE, never an accusation —
// deception artifacts are heuristics, and a real org's "backup" subdomain is not a trap.
//
// Why it exists: a platform that sells enforced stealth must detect the traps that burn
// stealth. Touching a canary token silently pages the defender; a red team that can't see
// deception walks into it. RedAmon, Nuclei, and nmap ship nothing here; HYDRA's detector
// was the right shape — ours adds confidence honesty and rides VARVEL's data flow
// (dns.mjs results, crawl paths, SMB share names) instead of re-scanning.
//
// Sources (all injectable; DNS queries go to the resolver — zero target contact):
//   1. DNS answers  — known canary-service domains (canarytokens.com, canary.tools,
//      Thinkst infra), canary token UUID/hex shapes in labels, TXT-token markers, MX bait.
//   2. Bait subdomains — admin/backup/test/dev/... present AND resolving like everything
//      else (wildcard shape) or to canary infra. Low weight alone — real orgs have these.
//   3. Honey paths — data-fed from crawl/vulncheck: root-level bait files (passwords.*,
//      secret.*, do-not-open…). Classic deception-farm shape.
//   4. Honey shares — data-fed from SMB enum: bait share names (backup$, passwords$…).
//
// Verdict bands: ≥70 'deception likely', ≥35 'possible', ≥1 'unlikely (artifacts noted)',
// 0 'clean shape'. Every artifact carries kind/where/evidence/weight. Read-only by
// construction; makes NO requests to the target itself.

import dns from 'node:dns/promises';

export const WEIGHTS = {
  'known-canary-domain': 70,
  'canary-token-shape': 45,
  'canary-ip-prefix': 30,
  'honey-path': 25,
  'honey-share': 20,
  'bait-subdomain': 15,
};

// Known canary/deception service domains (suffix match). Thinkst Canarytokens + console
// infra; operators self-host too — customPatterns covers those.
const KNOWN_CANARY_DOMAINS = ['canarytokens.com', 'canary.tools', 'thinkst.com', 'canarytokens.net'];

// Canary token label shapes: 16-hex (canarytokens.com token) or UUID as a DNS label.
const TOKEN_16HEX = /^[0-9a-f]{16}$/i;
const TOKEN_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// Bait subdomain labels (low weight alone — real orgs have these; score on clusters).
const BAIT_SUBDOMAINS = ['admin', 'backup', 'backups', 'test', 'dev', 'staging', 'stage', 'vpn', 'git', 'gitlab', 'jenkins', 'ci', 'internal', 'intranet', 'portal', 'secure', 'files', 'fileshare'];

// Honey-file / honey-share bait names.
const HONEY_PATH = /(?:^|\/)(?:passwords?|passw|credentials?|secrets?|confidential|do[-_]?not[-_]?open|private[-_]?keys?|wallet|salary|salaries|backup[-_]?(?:pass|cred)|admin[-_]?login)(?:\.|\/|$)/i;
const HONEY_SHARE = /^(?:backup|backups|secret|secrets|passwords|credentials|confidential|private|hr|finance|salary|it[-_]?docs?)\$?$/i;

export function labelIsTokenShape(label) {
  return TOKEN_16HEX.test(label) || TOKEN_UUID.test(label);
}

function matchKnownCanary(name, custom = []) {
  const n = String(name).toLowerCase().replace(/\.$/, '');
  for (const d of [...KNOWN_CANARY_DOMAINS, ...custom.map((x) => x.toLowerCase())]) {
    if (n === d || n.endsWith('.' + d)) return d;
  }
  return null;
}

/**
 * Deception surface scan. Data-fed: pass prior tool outputs OR let it resolve DNS live.
 * @param {object} input { target, dnsData?, paths?, shares?, subdomains?, customPatterns?, resolveImpl? }
 *   dnsData: { a?: string[], cname?: string[], txt?: string[], mx?: string[], subs?: {name,ips[]}[] }
 *   resolveImpl(host, rrtype) => string[] — live DNS override (default: node dns).
 * @returns {Promise<{target, suspicion, verdict, artifacts: Array, caveats: string[]}>}
 */
export async function canaryScan(input = {}) {
  const { target } = input;
  if (!target) throw new Error('canaryScan: target is required');
  const custom = input.customPatterns || [];
  const artifacts = [];
  const caveats = [];
  const add = (kind, where, evidence, weight) => artifacts.push({ kind, where, evidence, weight: weight ?? WEIGHTS[kind] ?? 10 });

  // ---- 1. DNS records (data-fed or live via resolver) ----
  const resolve = input.resolveImpl || defaultResolve;
  let dnsData = input.dnsData;
  if (!dnsData) {
    dnsData = { a: [], cname: [], txt: [], mx: [] };
    for (const [key, rr] of [['a', 'A'], ['cname', 'CNAME'], ['txt', 'TXT'], ['mx', 'MX']]) {
      try { dnsData[key] = await resolve(target, rr); } catch (e) { caveats.push(`${rr} lookup: ${e.code || e.message}`); }
    }
  }
  const allDnsNames = [...(dnsData.cname || []), ...(dnsData.mx || []), ...(dnsData.txt || []), ...(dnsData.subs || []).map((s) => s.name)];
  for (const name of allDnsNames) {
    const hit = matchKnownCanary(name, custom);
    if (hit) add('known-canary-domain', 'dns', `${name} matches known canary infrastructure (${hit})`);
    for (const label of String(name).toLowerCase().split('.')) {
      if (labelIsTokenShape(label)) add('canary-token-shape', 'dns', `token-shaped label "${label}" in ${name} (canary token format)`);
    }
  }
  for (const ip of [...(dnsData.a || []), ...(dnsData.subs || []).flatMap((s) => s.ips || [])]) {
    if (input.canaryIpPrefixes?.some((p) => ip.startsWith(p))) {
      add('canary-ip-prefix', 'dns', `${ip} inside an operator-declared canary prefix`);
    }
  }

  // ---- 2. bait subdomains (cluster-scored, honest about false positives) ----
  const subs = (dnsData.subs || []).map((s) => s.name.toLowerCase());
  const baitHits = subs.filter((n) => BAIT_SUBDOMAINS.includes(n.split('.')[0]));
  if (baitHits.length >= 2) {
    add('bait-subdomain', 'dns', `bait-named subdomains cluster: ${baitHits.slice(0, 6).join(', ')}${baitHits.length > 6 ? ` (+${baitHits.length - 6})` : ''} — common deception-farm shape, but also common in real estates`);
    caveats.push('bait-subdomain names occur in real estates too — weight kept low deliberately');
  }

  // ---- 3. honey paths (data-fed from crawl/vulncheck) ----
  for (const p of input.paths || []) {
    if (HONEY_PATH.test(p)) add('honey-path', 'web', `bait-shaped path ${p} — classic honey-file placement`);
  }

  // ---- 4. honey shares (data-fed from SMB enum) ----
  for (const s of input.shares || []) {
    if (HONEY_SHARE.test(s)) add('honey-share', 'smb', `bait-shaped share "${s}"`);
  }

  const suspicion = Math.min(100, artifacts.reduce((a, x) => a + x.weight, 0));
  const verdict = suspicion >= 70 ? 'deception likely' : suspicion >= 35 ? 'deception possible' : suspicion >= 1 ? 'unlikely (artifacts noted)' : 'clean shape';
  if (suspicion >= 70) caveats.push('treat reachable data as bait; assume active monitoring on every touch');
  return { target, suspicion, verdict, artifacts, caveats };
}

async function defaultResolve(host, rr) {
  try {
    const r = await dns.resolve(host, rr);
    return r.map((x) => (typeof x === 'string' ? x : x.exchange || x.name || String(Array.isArray(x) ? x.join('') : x)));
  } catch { return []; }
}

export const __internals = { KNOWN_CANARY_DOMAINS, BAIT_SUBDOMAINS, HONEY_PATH, HONEY_SHARE, matchKnownCanary };
