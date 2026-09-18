// VARVEL — program: bug-bounty program scope intake. Normalizes a program's PUBLISHED
// scope (HackerOne structured-scope, Bugcrowd target-groups, or a generic documented
// JSON) into VARVEL's signed-scope fixture format — the session-file shape the Enclave
// enforcement seam and engine/identity.mjs consume:
//   { session_id, principal, workspace, engagementScope: "<cidr,cidr,...>", sig }
//
// WHY THIS RUNG EXISTS: bounty revenue needs scope discipline the platform already
// enforces (CIDR-signed engagement scope, fail-closed) — but programs publish scope as
// DOMAINS/wildcards/URLs, not CIDRs. This tool is the honest bridge: it normalizes what
// the program published, applies the safe-harbor rules as CODE, and hands the operator a
// signable fixture. It NEVER touches the network (zero target contact; domain resolution
// is the operator's VPN-on act via scripts/scope-sign.mjs or --sign after resolution).
//
// HARD RULES (bounty safe-harbor is law):
//   1. Out-of-scope ALWAYS wins over in-scope on overlap — the exclusion is applied and
//      RECORDED (overlaps[]), never silent either way.
//   2. Wildcards are carried as wildcards with a gap noting they were NOT expanded —
//      offline intake never pretends to enumerate subdomains.
//   3. A scope that resolves to EMPTY in-scope is refused with a named reason
//      ('scope-resolves-empty').
//   4. The program's safe-harbor/policy text and reward table ride through as metadata.
//   5. No out-of-scope entry is ever dropped — exclusions land in outOfScope verbatim.
//   6. Domains are NOT signable into a CIDR scope offline: they are carried in
//      inScope.domains with a gap naming the resolution step; --sign refuses a scope
//      with zero CIDRs ('no-cidrs-to-sign') rather than sign an empty engagementScope.
//
// THE GENERIC FORMAT (documented contract for hand-written program files):
//   { "program": "Acme BBP", "handle": "acme", "url": "https://hackerone.com/acme",
//     "policy": "…program policy / safe-harbor text…",
//     "rewards": [ { "severity": "critical", "bounty": "$5,000–$15,000" } ],
//     "in_scope":  [ "example.com", "*.api.example.com", "203.0.113.0/24",
//                    "https://app.example.com/login", { "asset": "198.51.100.7", "type": "ip" } ],
//     "out_of_scope": [ "status.example.com", "203.0.113.99/32" ] }
//
// ADAPTER ASSUMPTIONS (no internet — shapes modeled from the platforms' documented
// exports; every assumption is ALSO recorded in the result's gaps[] at import time):
//   HackerOne: entries live in `structured_scopes[]` ({ asset_identifier, asset_type,
//     eligible_for_submission, eligible_for_bounty, instruction, max_severity });
//     `eligible_for_submission === false` marks an OUT-of-scope entry; an explicit
//     top-level `out_of_scope[]` string list is honored verbatim when present.
//   Bugcrowd: entries live in `target_groups[]` (or `program.target_groups[]`), each
//     { name, in_scope?, targets: [{ name, uri, category }] }. A group's `in_scope`
//     boolean wins; absent it, the group NAME decides (/out of scope/i vs /in scope/i);
//     an unnamed/ambiguous group is treated as OUT-of-scope (safe direction) and the
//     gap names it. Target asset = `uri` when present, else `name`.

import { readFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';
import { parseIp, parseCidr, inCidr } from '../engine/ipaddr.mjs';

const __dir = dirname(fileURLToPath(import.meta.url));
// The Enclave enforcement seam — SAME location identity.mjs verifies sessions from.
// Overridable in tests; the sign path imports the seam's own signSession/verifySession
// (reuse, never reimplement — the fixture must verify under the hook's code).
const SEAM = join(__dir, '..', '..', 'poc', 'enforcement-seam');

export const PLATFORMS = ['hackerone', 'bugcrowd', 'generic'];

// --- asset classification ---------------------------------------------------------
// One classifier for every adapter's entries: cidr | ip | url | wildcard | domain | other.
// IPs become host routes (/32, /128) so the signed engagementScope stays pure CIDR — the
// exact strings the hook's inAnyCidr enforcement already parses.
const DOMAIN_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;

function classifyAsset(raw, typeHint) {
  const asset = String(raw || '').trim();
  const hint = String(typeHint || '').trim().toUpperCase();
  if (!asset) return { kind: 'other', asset, note: 'empty asset entry' };
  if (hint === 'WILDCARD' || asset.startsWith('*.')) {
    const suffix = asset.replace(/^\*\./, '');
    if (DOMAIN_RE.test(suffix)) return { kind: 'wildcard', asset: '*.' + suffix.toLowerCase(), suffix: suffix.toLowerCase() };
    return { kind: 'other', asset, note: 'wildcard with a non-domain suffix — not signable' };
  }
  if (parseCidr(asset)) return { kind: 'cidr', asset: canonicalCidr(asset) };
  const ip = parseIp(asset);
  if (ip) return { kind: 'cidr', asset: ip.text + (ip.fam === 4 ? '/32' : '/128'), note: asset.includes('/') ? undefined : 'bare IP normalized to a host route' };
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(asset)) {
    let host = null;
    try { host = new URL(asset).hostname; } catch { return { kind: 'other', asset, note: 'unparseable URL' }; }
    host = host.replace(/^\[|\]$/g, ''); // URL.hostname keeps v6 brackets
    const hip = parseIp(host);
    if (hip) return { kind: 'cidr', asset: hip.text + (hip.fam === 4 ? '/32' : '/128'), note: `URL host is an IP literal — path-level scope of ${asset} is not expressible in a CIDR scope` };
    if (DOMAIN_RE.test(host)) return { kind: 'domain', asset: host.toLowerCase(), note: `URL scoped to its host only — the path (${new URL(asset).pathname}) is not expressible in a CIDR scope` };
    return { kind: 'other', asset, note: 'URL host is neither an IP nor a domain' };
  }
  if (DOMAIN_RE.test(asset)) return { kind: 'domain', asset: asset.toLowerCase() };
  // HARDWARE / MOBILE_APPLICATION / SOURCE_CODE / EXECUTABLE / OTHER and friends:
  // carried, never dropped — they are simply not expressible in a CIDR engagement scope.
  return { kind: 'other', asset, note: hint ? `asset_type ${hint} is not a network asset` : 'not a network asset' };
}

// Canonical CIDR text via the platform's ONE parser (bare base = host route, per parseCidr).
function canonicalCidr(cidr) {
  const c = parseCidr(cidr);
  if (!c) return String(cidr).trim();
  if (c.fam === 4) {
    const v = c.v4 >>> 0;
    return [(v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255].join('.') + '/' + c.bits;
  }
  const ip = parseIp(String(cidr).split('/')[0]); // normalized v6 text (compressed, lowercased)
  return (ip ? ip.text : String(cidr).split('/')[0]) + '/' + c.bits;
}

// --- adapters (documented shapes -> ONE entry list) ---------------------------------
// Every adapter returns { meta: { name, handle, url, policy, safeHarbor, rewards },
// entries: [{ asset, type, inScope, note? }], assumptions: [] } — the normalizer is
// adapter-agnostic; assumptions are copied into the result's gaps[] verbatim.

function adaptHackerOne(doc) {
  const assumptions = [
    "HackerOne adapter: modeled on the documented structured-scope export — entries in structured_scopes[] with eligible_for_submission:false treated as OUT-of-scope; a top-level out_of_scope[] list, when present, is honored verbatim",
  ];
  const scopes = Array.isArray(doc.structured_scopes) ? doc.structured_scopes : [];
  if (!scopes.length) assumptions.push('no structured_scopes[] found — if this program exports scope differently, the import sees nothing (refuses empty rather than guessing)');
  const entries = [];
  for (const s of scopes) {
    if (!s || s.asset_identifier == null) continue;
    entries.push({
      asset: String(s.asset_identifier),
      type: s.asset_type || '',
      inScope: s.eligible_for_submission !== false, // documented out-of-scope marker
      note: s.instruction ? String(s.instruction).slice(0, 300) : undefined,
      bounty: s.eligible_for_bounty === false ? false : true,
      maxSeverity: s.max_severity || undefined,
    });
  }
  for (const raw of Array.isArray(doc.out_of_scope) ? doc.out_of_scope : []) {
    entries.push({ asset: typeof raw === 'string' ? raw : String(raw && raw.asset || ''), type: (raw && raw.type) || '', inScope: false });
  }
  const rewards = Array.isArray(doc.bounty_table) ? doc.bounty_table : (Array.isArray(doc.rewards) ? doc.rewards : null);
  if (!rewards) assumptions.push('no bounty_table/rewards in the export — HackerOne reward ranges live on the program page; carry them by hand if the export omits them');
  return {
    meta: {
      name: doc.name || doc.handle || null,
      handle: doc.handle || null,
      url: doc.url || (doc.handle ? `https://hackerone.com/${doc.handle}` : null),
      policy: doc.policy || null,
      safeHarbor: doc.safe_harbor || null,
      rewards,
    },
    entries,
    assumptions,
  };
}

function adaptBugcrowd(doc) {
  const assumptions = [
    'Bugcrowd adapter: modeled on the documented target-groups export — target_groups[] (or program.target_groups[]) of { name, in_scope?, targets[] }; a group with no in_scope flag is classified by name, and an ambiguous name falls to OUT-of-scope (the safe direction) with the group named below',
  ];
  const root = doc.program && typeof doc.program === 'object' ? doc.program : doc;
  const groups = Array.isArray(root.target_groups) ? root.target_groups : [];
  if (!groups.length) assumptions.push('no target_groups[] found — if this program exports scope differently, the import sees nothing (refuses empty rather than guessing)');
  const entries = [];
  for (const g of groups) {
    if (!g) continue;
    const name = String(g.name || '');
    let inScope;
    if (typeof g.in_scope === 'boolean') inScope = g.in_scope;
    else if (/out[\s_-]*of[\s_-]*scope/i.test(name)) inScope = false;
    else if (/in[\s_-]*scope/i.test(name)) inScope = true;
    else { inScope = false; assumptions.push(`target group '${name || '(unnamed)'}' carries no in_scope flag and an ambiguous name — treated as OUT-of-scope (safe direction); flip the group only after reading the program brief`); }
    for (const t of Array.isArray(g.targets) ? g.targets : []) {
      if (!t) continue;
      const asset = t.uri || t.name;
      if (asset == null || asset === '') continue;
      entries.push({ asset: String(asset), type: t.category || '', inScope, note: t.uri && t.name ? `target name: ${t.name}` : undefined });
    }
  }
  const rewards = Array.isArray(root.rewards) ? root.rewards : (Array.isArray(doc.rewards) ? doc.rewards : null);
  if (!rewards) assumptions.push('no rewards table in the export — Bugcrowd reward ranges live on the program brief; carry them by hand if the export omits them');
  return {
    meta: {
      name: root.name || root.title || null,
      handle: root.handle || root.code || null,
      url: root.url || (root.handle ? `https://bugcrowd.com/${root.handle}` : null),
      policy: root.policy || root.brief || null,
      safeHarbor: root.safe_harbor || null,
      rewards,
    },
    entries,
    assumptions,
  };
}

function adaptGeneric(doc) {
  const entries = [];
  for (const raw of Array.isArray(doc.in_scope) ? doc.in_scope : []) {
    entries.push(typeof raw === 'string' ? { asset: raw, type: '', inScope: true } : { asset: String(raw && raw.asset || ''), type: (raw && raw.type) || '', inScope: true, note: raw && raw.note });
  }
  for (const raw of Array.isArray(doc.out_of_scope) ? doc.out_of_scope : []) {
    entries.push(typeof raw === 'string' ? { asset: raw, type: '', inScope: false } : { asset: String(raw && raw.asset || ''), type: (raw && raw.type) || '', inScope: false, note: raw && raw.note });
  }
  return {
    meta: {
      name: doc.program || doc.name || null,
      handle: doc.handle || null,
      url: doc.url || null,
      policy: doc.policy || null,
      safeHarbor: doc.safe_harbor || null,
      rewards: Array.isArray(doc.rewards) ? doc.rewards : null,
    },
    entries,
    assumptions: [],
  };
}

const ADAPTERS = { hackerone: adaptHackerOne, bugcrowd: adaptBugcrowd, generic: adaptGeneric };

// --- the ONE normalizer --------------------------------------------------------------
// Entries -> classified in/out lists with safe-harbor precedence applied. Pure.
export function normalizeEntries(entries, { assumptions = [] } = {}) {
  const gaps = [...assumptions];
  const klass = { cidr: [], domain: [], wildcard: [], other: [] };
  const out = { cidr: [], domain: [], wildcard: [], other: [] };
  const overlaps = [];

  for (const e of Array.isArray(entries) ? entries : []) {
    // A blank entry is junk, not an asset — skipped with a gap naming the side (never
    // silently), so an all-blank scope still refuses as empty instead of arming 'other'.
    if (e == null || !String(e.asset || '').trim()) { gaps.push(`empty asset entry ignored (${e && e.inScope === false ? 'out-of-scope' : 'in-scope'} side of the export)`); continue; }
    const c = classifyAsset(e.asset, e.type);
    const rec = { asset: c.asset, ...(c.suffix ? { suffix: c.suffix } : {}), ...(e.note || c.note ? { note: [e.note, c.note].filter(Boolean).join(' · ') } : {}), ...(e.inScope && e.bounty === false ? { bounty: false } : {}), ...(e.maxSeverity ? { maxSeverity: e.maxSeverity } : {}) };
    (e.inScope ? klass : out)[c.kind].push(rec);
  }

  // RULE 1 — out-of-scope wins. CIDR: an in-scope CIDR fully contained in an
  // out-of-scope CIDR is EXCLUDED (recorded). Partial/containing overlaps cannot be
  // expressed in the signed CSV — they become LOUD gaps because the signed scope would
  // then cover excluded ground.
  const keptCidrs = [];
  for (const c of klass.cidr) {
    const pc = parseCidr(c.asset);
    const covering = out.cidr.filter((o) => {
      const po = parseCidr(o.asset);
      return po && pc && po.fam === pc.fam && po.bits <= pc.bits && inCidr(c.asset.split('/')[0], o.asset);
    });
    if (covering.length) {
      overlaps.push({ asset: c.asset, direction: 'in-scope CIDR excluded', by: covering.map((o) => o.asset), rule: 'out-of-scope wins' });
      out.cidr.push({ ...c, note: [c.note, `EXCLUDED by out-of-scope ${covering.map((o) => o.asset).join(', ')} (overlap precedence)`].filter(Boolean).join(' · ') });
      continue;
    }
    for (const o of out.cidr) {
      const po = parseCidr(o.asset);
      if (!po || !pc || po.fam !== pc.fam) continue;
      const oBaseInC = inCidr(o.asset.split('/')[0], c.asset); // out base inside in-scope CIDR
      const cBaseInO = inCidr(c.asset.split('/')[0], o.asset); // (full containment handled above)
      if (oBaseInC || cBaseInO) gaps.push(`OVERLAP: out-of-scope ${o.asset} overlaps in-scope ${c.asset} — the excluded range is NOT testable even though ${c.asset} is signed; VARVEL's CIDR scope cannot express the subtraction, so the operator MUST honor the exclusion by hand (or split the CIDR before signing)`);
    }
    keptCidrs.push(c);
  }
  klass.cidr = keptCidrs;

  // Domains: exact out-of-scope match, or coverage by an out-of-scope wildcard. For
  // EXCLUSIONS a wildcard is read conservatively as covering its apex too ('*.example.com'
  // out-of-scope excludes 'example.com') — over-exclusion is the safe direction, and the
  // overlap record says exactly what happened.
  const keptDomains = [];
  for (const d of klass.domain) {
    const exact = out.domain.find((o) => o.asset === d.asset);
    const wild = out.wildcard.find((o) => d.asset === o.suffix || d.asset.endsWith('.' + o.suffix));
    if (exact || wild) {
      const by = exact ? exact.asset : wild.asset;
      overlaps.push({ asset: d.asset, direction: 'in-scope domain excluded', by: [by], rule: 'out-of-scope wins' });
      out.domain.push({ ...d, note: [d.note, `EXCLUDED by out-of-scope ${by} (overlap precedence)`].filter(Boolean).join(' · ') });
      continue;
    }
    keptDomains.push(d);
  }
  klass.domain = keptDomains;

  // Wildcards are never expanded (offline honesty) — but an out-of-scope entry falling
  // UNDER an in-scope wildcard is a gap the operator must honor by hand.
  for (const w of klass.wildcard) {
    gaps.push(`wildcard ${w.asset} NOT expanded — offline intake never enumerates subdomains; the signed scope carries no entry for it until the operator resolves and signs concrete /32s+/128s`);
    for (const o of [...out.domain, ...out.wildcard]) {
      const oName = o.asset.replace(/^\*\./, '');
      if (oName === w.suffix || oName.endsWith('.' + w.suffix) || w.suffix.endsWith('.' + oName)) {
        gaps.push(`OVERLAP: out-of-scope ${o.asset} falls under in-scope wildcard ${w.asset} — ${o.asset} is EXCLUDED; wildcards are never enumerated, so the operator MUST honor this exclusion by hand`);
      }
    }
  }
  for (const d of klass.domain) {
    const wild = klass.wildcard.find((w) => d.asset === w.suffix || d.asset.endsWith('.' + w.suffix));
    if (wild) overlaps.push({ asset: d.asset, direction: 'domain also covered by in-scope wildcard', by: [wild.asset], rule: 'kept once (explicit entry wins; no duplicate testing)' });
  }
  if (klass.domain.length) gaps.push(`${klass.domain.length} in-scope domain(s) are NOT in the signed CIDR scope — VARVEL's enforcement is CIDR-based and offline intake never resolves; resolve them (VPN on) and sign the /32s+/128s before any contact`);
  for (const o of klass.other) gaps.push(`non-network asset '${o.asset}' carried as metadata only — not expressible in a CIDR engagement scope (${o.note || 'no detail'})`);
  for (const o of out.other) gaps.push(`out-of-scope non-network asset '${o.asset}' carried verbatim — never dropped, never contacted`);

  const inCount = klass.cidr.length + klass.domain.length + klass.wildcard.length + klass.other.length;
  if (!inCount) {
    return {
      ok: false,
      error: 'scope-resolves-empty',
      reason: `in-scope resolves to EMPTY after out-of-scope precedence (${overlaps.length} overlap exclusion(s)) — refusing to normalize an empty scope; signing one would arm nothing (or worse, read as unscoped)`,
      overlaps, gaps,
      inScope: { cidrs: [], domains: [], wildcards: [], other: [] },
      outOfScope: { cidrs: out.cidr, domains: out.domain, wildcards: out.wildcard, other: out.other },
    };
  }

  return {
    ok: true,
    inScope: { cidrs: klass.cidr, domains: klass.domain, wildcards: klass.wildcard, other: klass.other },
    outOfScope: { cidrs: out.cidr, domains: out.domain, wildcards: out.wildcard, other: out.other },
    engagementScope: klass.cidr.map((c) => c.asset).join(','),
    signable: klass.cidr.length > 0,
    overlaps,
    gaps,
  };
}

// normalizeProgram(doc, { platform }) → the full intake record (pure, no I/O).
export function normalizeProgram(doc, { platform = 'generic' } = {}) {
  const adapter = ADAPTERS[platform];
  if (!adapter) return { ok: false, error: 'unknown-platform', reason: `platform must be one of ${PLATFORMS.join('|')}` };
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) return { ok: false, error: 'bad-input', reason: 'expected a program JSON object' };
  const { meta, entries, assumptions } = adapter(doc);
  const n = normalizeEntries(entries, { assumptions });
  if (!n.ok) return { ...n, platform, program: { name: meta.name, handle: meta.handle, url: meta.url } };
  return {
    ok: true,
    platform,
    program: { name: meta.name, handle: meta.handle, url: meta.url },
    // The program's own words ride through untouched — safe-harbor text is law on the
    // submission side too, and the reward table is what makes the finding PAYABLE.
    policy: meta.policy || null,
    safeHarbor: meta.safeHarbor || null,
    rewards: meta.rewards || null,
    inScope: n.inScope,
    outOfScope: n.outOfScope,
    engagementScope: n.engagementScope,
    signable: n.signable,
    overlaps: n.overlaps,
    gaps: n.gaps,
  };
}

// --- the signing path (reuse, never reimplement) --------------------------------------
// Mirrors scripts/scope-sign.mjs: build the canonical session fields, sign with the
// seam's own signSession, SELF-VERIFY before anything is written, and keep identity
// continuity with the principal's existing fixture (session_id/workspace carry over
// unless the operator overrides). NEVER writes by itself — the CLI owns --out.
export async function signScope(normalized, { principal = 'marcus', workspace, sessionId, seamDir = SEAM } = {}) {
  if (!normalized || !normalized.ok) return { ok: false, error: 'not-importable', reason: `cannot sign a scope that did not normalize (${(normalized && normalized.error) || 'no scope'})` };
  const cidrs = normalized.inScope.cidrs.map((c) => c.asset);
  if (!cidrs.length) {
    return {
      ok: false,
      error: 'no-cidrs-to-sign',
      reason: `the in-scope list carries ${normalized.inScope.domains.length} domain(s) and ${normalized.inScope.wildcards.length} wildcard(s) but ZERO CIDRs — offline intake never resolves; resolve the domains (VPN on) and re-import, or add the resolved /32s+/128s to the fixture`,
    };
  }
  let util;
  try { util = await import(pathToFileURL(join(seamDir, 'util.mjs')).href); }
  catch (e) { return { ok: false, error: 'seam-absent', reason: `the Enclave seam util is not importable (${(e && e.message) || e}) — cannot sign` }; }
  let prior = null;
  try { prior = JSON.parse(readFileSync(join(seamDir, 'session', principal + '.json'), 'utf8')); } catch {}
  const s = {
    session_id: sessionId || (prior && prior.session_id) || 'sess-bounty',
    principal,
    workspace: workspace || (normalized.program && normalized.program.handle) || (prior && prior.workspace) || 'bug-bounty',
    engagementScope: cidrs.join(','),
  };
  const fixture = { ...s, sig: util.signSession(s) };
  if (!util.verifySession(fixture)) return { ok: false, error: 'self-verify-failed', reason: 'self-verify failed — not writing (the scope-sign.mjs discipline)' };
  return { ok: true, fixture, carriedIdentity: !!prior };
}

// CLI helper: read + normalize a fixture file. Read errors are data, not crashes.
export function importProgram(file, { platform } = {}) {
  let doc;
  try { doc = JSON.parse(readFileSync(file, 'utf8')); }
  catch (e) { return { ok: false, error: 'unreadable-fixture', reason: `cannot read/parse ${file}: ${(e && e.message) || e}` }; }
  return normalizeProgram(doc, { platform });
}
