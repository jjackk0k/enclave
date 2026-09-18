// VARVEL -- egresscheck: the pre-engagement EXIT measurement leg of Ghost Mode.
//
// Why it exists (the 2026-08 field lesson): cf_clearance binds to exit IP + User-Agent.
// During an engagement the mint browser and the verify fetch exited through DIFFERENT
// Mullvad IPs (rotation), so the cookies were "issued but unproven" and every follow-up
// request was challenged. The operator must know BEFORE an engagement: (1) is my exit
// STABLE, (2) what CLASS is it (datacenter exits score low with Cloudflare), (3) does
// it match the exit I pinned for this engagement.
//
// Three measurements, all honest and all additive to the ghost check result:
//   STABILITY -- sample the exit IP through the configured chain N times (~1s apart):
//     'stable' (all identical) or 'rotating' (all distinct exits listed, with the
//     cf_clearance IP-binding warning and the fix: pin ONE specific Mullvad server).
//   CLASS -- best-effort org/ASN via the FREE ipinfo.io feed, the SAME approach as
//     tools/preflight.mjs's egressClassify (3s AbortController cap, never throws,
//     skipped silently when offline), plus an org-name heuristic labelled as such.
//   PIN -- VARVEL_GHOST_EXPECT_EXIT / ghost.expectExit names the one expected exit.
//     Default: a mismatch is a LOUD warning. Strict (ghost.pinStrict === true): a
//     mismatch fails the check CLOSED (ok:false) and drops ghost verification, so
//     'required' mode refuses public egress. Default-off.
//
// THE HONESTY CONTRACT (same doctrine as selfview/preflight): this module NEVER throws.
// Every failure is reported in the result, nothing is hidden, and the classification is
// always labelled a free-feed HEURISTIC (paid proxy/VPN classification feeds are NOT
// covered -- the zero-spend boundary). Sampler/fetch/sleep are all injectable so the
// tests are hermetic.

import { parseIp } from './ipaddr.mjs';

// normalizeExitSet(input) -> { list: [canonicalIp...], dropped: [rawEntry...] }.
// The operator's ROTATION SET: the declared list of exits an engagement may use (the
// frontegg lesson, 2026-08-30 — a WAF-blocked pinned exit with no rotation policy meant
// a stalled engagement and a manual re-pin). Array or comma-string in; canonical IPs out
// (v6 forms collapse, mapped v4 collapses — same doctrine as pin matching). Unparseable
// entries are DROPPED and NAMED — a dropped entry can never match anything, and the drop
// is surfaced so a typo'd set is never silently narrower than the operator believes.
export function normalizeExitSet(input) {
  const raw = Array.isArray(input) ? input : String(input || '').split(',');
  const list = [], dropped = [];
  for (const e of raw) {
    const s = String(e == null ? '' : e).trim();
    if (!s) continue;
    const p = parseIp(s);
    if (p) list.push(p.text); else dropped.push(s);
  }
  return { list: [...new Set(list)], dropped };
}

// Org-name heuristics. Order matters: a Mullvad exit often presents the HOSTING
// provider's org (M247, Datacamp) rather than "Mullvad" -- but when the VPN brand IS
// visible it wins, since that is the more specific fact. Anything unmatched is
// 'unknown' (fail-closed: we never claim a class we did not observe).
const ORG_CLASS = [
  ['vpn', /mullvad|proton\s?vpn|nordvpn|expressvpn|surfshark|\bivpn\b|windscribe|private internet access|\bvpn\b/i],
  ['datacenter', /datacamp|m247|hosting|data\s?center|cloud|amazon|aws|google|microsoft|azure|ovh|hetzner|digitalocean|linode|akamai|vultr|oracle|leaseweb|choopa|packet|alibaba|tencent|scaleway|contabo/i],
  ['residential-ish', /telecom|vodafone|comcast|verizon|at&t|deutsche telekom|broadband|cable|fiber|virgin media|\bisp\b|residential|orange s\.a|british telecommunications/i],
];

// classifyEgressOrg(org) -> 'vpn' | 'datacenter' | 'residential-ish' | 'unknown'.
// PURE heuristic on the ipinfo org string; callers must label it as such.
export function classifyEgressOrg(org) {
  const s = String(org || '');
  if (!s.trim()) return 'unknown';
  for (const [cls, re] of ORG_CLASS) if (re.test(s)) return cls;
  return 'unknown';
}

// Free egress classification through the chain: ipinfo.io/json with a hard 3s cap,
// the same approach as tools/preflight.mjs egressClassify() (AbortController, never
// throws, offline -> ok:false). fetchImpl injectable for hermetic tests. The chain's
// HTTP-proxy agents are passed so the classification measures the EXIT, not the
// operator's real egress (undici fetch accepts a dispatcher; with plain node fetch we
// rely on the caller to have routed, or accept direct -- callers pass agents when they
// can, and the result honestly reports which path measured it).
export async function ipinfoClassify({ fetchImpl, timeoutMs = 3000, dispatcher } = {}) {
  try {
    const f = fetchImpl || ((...a) => fetch(...a));
    const ctl = new AbortController();
    const t = setTimeout(() => { try { ctl.abort(); } catch {} }, timeoutMs);
    let r;
    try { r = await f('https://ipinfo.io/json', dispatcher ? { signal: ctl.signal, dispatcher } : { signal: ctl.signal }); }
    finally { clearTimeout(t); }
    if (!r || !r.ok) return { ok: false, error: 'ipinfo.io answered HTTP ' + (r ? r.status : '?') };
    const j = await r.json();
    const org = String(j.org || '');
    const m = /^(AS\d+)/.exec(org);
    return { ok: true, ip: j.ip || null, org, asn: m ? m[1] : null, class: classifyEgressOrg(org), heuristic: true };
  } catch (e) {
    return { ok: false, error: (e && e.name === 'AbortError') ? 'ipinfo.io timed out (' + timeoutMs + 'ms)' : String((e && e.message) || e) };
  }
}

// runEgressCheck({ sampler, samples, spacingMs, sleep, expectExit, pinStrict, classify, fetchImpl })
//   sampler   -- injectable async () => exitIpString|null (null = chain/check unreachable).
//   samples   -- N exit measurements (default 3); spacingMs between them (default 1000).
//   expectExit-- the one pinned exit IP (VARVEL_GHOST_EXPECT_EXIT / ghost.expectExit).
//   expectExitSet-- the operator's ROTATION SET (array or comma-string): every sampled
//     exit must be a member; a pin outside the set is a named policy violation.
//     Result gains expectExitSet / setDropped / setMatch (true|false|null=unproven).
//   pinStrict -- true: mismatch or unprovable pin/set FAILS the check CLOSED (ok:false).
// NEVER throws. Result shape:
//   { ok, verdict: 'stable'|'rotating'|'unknown', exits, distinct, sampled, failed,
//     expectExit, pinMatch: true|false|null, pinStrict,
//     egress: { ok, ip?, org?, asn?, class?, heuristic:true, error? } | { ok:false, skipped?, error? },
//     warnings: [..], reason?: string (ok:false only), at }
export async function runEgressCheck({
  sampler, samples = 3, spacingMs = 1000, sleep,
  expectExit = null, expectExitSet = null, pinStrict = false, classify = true, fetchImpl,
} = {}) {
  const nap = sleep || ((ms) => new Promise((r) => setTimeout(r, ms)));
  const warnings = [];
  const { list: setList, dropped: setDropped } = normalizeExitSet(expectExitSet);
  const result = {
    ok: true, verdict: 'unknown', exits: [], distinct: [], sampled: 0, failed: 0,
    expectExit: expectExit || null, pinMatch: null, pinStrict: !!pinStrict,
    expectExitSet: setList.length ? setList : null, setDropped, setMatch: null,
    egress: null, warnings, at: new Date().toISOString(),
  };
  if (setDropped.length) {
    warnings.push('rotation set: ' + setDropped.length + ' entr' + (setDropped.length === 1 ? 'y was' : 'ies were') + ' not parseable IPs and were DROPPED (' + setDropped.join(', ') + ') — a dropped entry can never match; the set is NARROWER than configured until fixed');
  }

  // ---- 1. STABILITY ----
  const n = Math.max(1, Math.floor(Number(samples) || 3));
  if (typeof sampler === 'function') {
    for (let i = 0; i < n; i++) {
      if (i > 0) await nap(spacingMs);
      let ip = null;
      try { ip = await sampler(); } catch { ip = null; } // a sampler must never break the check
      // An exit sample only counts when it IS an IP literal (canonical form: a v4-mapped
      // exit collapses to its embedded v4, mixed-case/compressed v6 dedupe). A garbage
      // "exit" is a FAILED measurement — it can never claim the chain is 'stable'
      // (fail-closed: unknown, never silently covered).
      const p = ip === null ? null : parseIp(ip);
      if (ip !== null && !p) warnings.push('an exit sample was not a parseable IP literal (' + String(ip).slice(0, 64) + ') -- counted as a failed sample, not as coverage');
      ip = p ? p.text : null;
      result.exits.push(ip);
      if (ip) result.sampled++;
      else result.failed++;
    }
  } else {
    result.failed = n;
    result.exits = Array.from({ length: n }, () => null);
    warnings.push('no exit sampler available -- stability not measured (chain not configured?)');
  }
  result.distinct = [...new Set(result.exits.filter(Boolean))];
  if (result.failed > 0 && result.sampled > 0) {
    warnings.push(result.failed + ' of ' + n + ' exit samples failed (chain or check endpoint unreachable at sample time) -- the verdict below is from the ' + result.sampled + ' answer(s) that did arrive');
  }
  if (result.distinct.length === 1) {
    result.verdict = 'stable';
  } else if (result.distinct.length > 1) {
    result.verdict = 'rotating';
    warnings.push('exit ROTATING -- ' + n + ' samples through the chain produced ' + result.distinct.length + ' distinct exits (' + result.distinct.join(', ') + '). cf_clearance binds to exit IP + User-Agent: a clearance minted on one Mullvad exit is CHALLENGED from another (the 2026-08 mint/verify split-IP lesson, 24/24 follow-ups challenged). For clearance-class engagements pin ONE specific Mullvad server in the app (a named server, not just a city); rotation is acceptable only for non-CF ops.');
  } else {
    result.verdict = 'unknown';
    warnings.push('no exit sample succeeded -- the chain is unreachable or the check endpoint is down; stability/pin could not be measured (fail-closed ghost.verify() remains the gate for required mode)');
  }

  // ---- 2. CLASS (best-effort, heuristic, never fatal) ----
  if (classify) {
    result.egress = await ipinfoClassify({ fetchImpl });
    if (result.egress.ok) {
      if (result.egress.class === 'datacenter') {
        warnings.push('egress class is DATACENTER (' + (result.egress.org || 'unknown org') + (result.egress.asn ? ', ' + result.egress.asn : '') + ') [free-feed heuristic] -- Cloudflare-class defenses score datacenter exits low; expect challenges on CF-class engagements. Residential egress is a paid capability outside the zero-spend boundary (accepted platform limitation).');
      }
    }
    // offline / timeout: skipped silently -- the gap is visible only in egress.error, by design
    // (same doctrine as preflight: unobserved is reported, never thrown).
  }

  // ---- 3. PIN ----
  if (result.expectExit) {
    // Compare in CANONICAL form (samples above are canonicalized already): a pin of
    // '::ffff:203.0.113.7' IS a pin of 203.0.113.7, and '2001:DB8::1' is '2001:db8::1'.
    // An unparseable pin compares as its raw string, which a canonical sample never
    // equals — the pin is then UNPROVEN (fail-closed, same doctrine as before).
    const pin = (parseIp(result.expectExit) || {}).text || result.expectExit;
    const actual = result.distinct.length === 1 ? result.distinct[0] : null;
    result.pinMatch = actual !== null && result.distinct.every((ip) => ip === pin) && actual === pin
      ? true
      : (result.distinct.length === 0 ? null : false);
    if (result.pinMatch === true) {
      // pinned and proven -- the good path, no warning
    } else {
      const what = result.distinct.length === 0
        ? 'no exit could be sampled, so the pin is UNPROVEN'
        : 'expected exit ' + result.expectExit + ' but the chain exits via ' + result.distinct.join(', ');
      if (result.pinStrict) {
        result.ok = false;
        result.reason = 'ghost pinStrict: ' + what + ' -- check FAIL-CLOSED. Public egress in required mode is refused until the chain exits via the pinned IP. Fix: pin Mullvad server for exit ' + result.expectExit + ', or update VARVEL_GHOST_EXPECT_EXIT / ghost.expectExit.';
      } else {
        warnings.push('EXIT MISMATCH (pin not enforced) -- ' + what + '. Set ghost.pinStrict=true to make this fail-closed, or re-pin the Mullvad app to the expected server.');
      }
    }
  }

  // ---- 4. ROTATION SET (the operator-declared exit policy) ----
  // The set marks WHICH exits an engagement may use. A stable/rotating chain whose exits
  // are all members is in-policy; any sampled exit outside the set is named loudly, and
  // under pinStrict the check FAILS CLOSED (can only ever close the gate, never open it).
  if (result.expectExitSet) {
    const set = result.expectExitSet;
    // A pin must be a MEMBER of the set — campaign launch may pin any one of the declared
    // exits, nothing outside the operator's policy. A pin outside the set is a
    // contradiction: named loudly, fail-closed under pinStrict (even when the pin itself
    // matches the observed exit — the policy violation is the point).
    if (result.expectExit) {
      const pin = (parseIp(result.expectExit) || {}).text || result.expectExit;
      if (!set.includes(pin)) {
        const what = 'pinned exit ' + result.expectExit + ' is NOT A MEMBER OF THE ROTATION SET (' + set.join(', ') + ') — an engagement may pin any one of the declared exits, nothing outside the set';
        if (result.pinStrict) {
          result.ok = false;
          result.reason = (result.reason ? result.reason + ' ALSO: ' : 'ghost pinStrict: ') + what + ' — check FAIL-CLOSED.';
        } else {
          warnings.push('PIN OUTSIDE POLICY (not enforced) — ' + what + '.');
        }
      }
    }
    const outside = result.distinct.filter((ip) => !set.includes(ip));
    result.setMatch = result.distinct.length === 0 ? null : outside.length === 0;
    if (result.setMatch === false) {
      const what = 'the chain exits via ' + outside.join(', ') + ' — OUTSIDE THE ROTATION SET (' + set.join(', ') + ')';
      if (result.pinStrict) {
        result.ok = false;
        result.reason = (result.reason ? result.reason + ' ALSO: ' : 'ghost pinStrict: ') + what + ' — check FAIL-CLOSED. Public egress in required mode is refused until the chain exits via an operator-declared exit. Fix: rotate Mullvad onto a declared server, or update the set (VARVEL_GHOST_EXIT_SET).';
      } else {
        warnings.push('EXIT OUTSIDE THE ROTATION SET (not enforced) — ' + what + '. Rotate the Mullvad app onto a declared server, or update the set. Set ghost.pinStrict=true to make this fail-closed.');
      }
    } else if (result.setMatch === null && result.pinStrict) {
      result.ok = false;
      result.reason = (result.reason ? result.reason + ' ALSO: ' : 'ghost pinStrict: ') + 'the rotation set is UNPROVEN — no exit could be sampled, so membership could not be verified — check FAIL-CLOSED.';
    }
  }

  return result;
}
