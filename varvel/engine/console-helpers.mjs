// VARVEL — console-helpers: the PURE mapping logic behind the app-v6 console's
// budget/ghost/fresh-ground surfaces. The console is a single self-contained HTML file
// (no module loader), so app-v6.html carries a MIRROR block with these same functions —
// test/console-helpers.test.mjs extracts the mirror from the HTML and runs the SAME
// assertions against both copies, so the two can never drift silently.
//
// Why these three:
//   budgetReadout — the 2026-08-25 live bug: the signal strip showed 'Turns 0/40' while
//     another surface showed the campaign '0/200' for what looked like ONE budget. They
//     are TWO budgets (the interactive agent's governed tool-turn cap vs the pipeline
//     campaign's step counter) and this function is now the ONE readout both surfaces
//     render, with the source named on each so they can never be confused again.
//   ghostChip — the header ghost indicator and the settings ghost card disagreed
//     (OFF at top while armed). Both now render THIS mapping of the SAME status object
//     (GET /api/ghost's truth — a POST arm can return an empty body yet land, so the
//     console always re-fetches; see the verify-by-GET note in app-v6.html armGhost()).
//   freshGroundView — h1watch's ranked fresh ground for the console: a display cap that
//     NEVER cuts an exclusion move (side 'out') — the honor-before-any-contact weight.
//   jsq — the console interpolates server ids into SINGLE-QUOTED js string literals inside
//     double-quoted inline onclick attributes; esc() covers only the HTML/attribute layer
//     and leaves ' \ and line breaks live, so a quote in an id would break the handler.
//
// Pure data in, pure data out — no DOM, no fetch, no HTML. The console renders; tests pin.

export const MAXTURNS_FALLBACK = 40; // matches engine/settings.mjs agent.maxTurns default

// budgetReadout(s, maxTurns) -> ONE of:
//   { kind:'none' }                                   — idle / no campaign budget at all
//   { kind:'turns', used, max, pct, ... }             — interactive: GOVERNED TOOL TURNS
//   { kind:'steps', used, max, pct, ... }             — pipeline campaign: STEP BUDGET
// `used` for turns is derived exactly the way the console always has (the latest agent
// message's step entries pair into turns, ceil(n/2)); `max` is the agent.maxTurns
// setting (the console syncs it at boot; the fallback is the settings default).
export function budgetReadout(s, maxTurns) {
  const status = (s && s.status) || 'idle';
  const mt = (Number.isFinite(Number(maxTurns)) && Number(maxTurns) > 0) ? Number(maxTurns) : MAXTURNS_FALLBACK;
  if (!s || status === 'idle' || !s.budget) return { kind: 'none' };
  if (/interactive/.test(status)) {
    const msgs = Array.isArray(s.messages) ? s.messages : [];
    const am = [...msgs].reverse().find((m) => (m.who || m.role) === 'agent');
    const used = am && Array.isArray(am.steps) ? Math.ceil(am.steps.length / 2) : 0;
    return {
      kind: 'turns', used, max: mt,
      pct: mt ? Math.min(100, Math.round((used / mt) * 100)) : 0,
      chipKey: 'Turns', unit: 'tool turns', source: 'agent.maxTurns',
      hint: 'Interactive session — this meter is the agent’s governed tool-turn budget (the agent.maxTurns setting, '
        + mt + '). The pipeline campaign step counter is a DIFFERENT budget and only appears here while a pipeline campaign runs.',
    };
  }
  const used = (s.budget && s.budget.usedSteps) || 0;
  const max = (s.budget && s.budget.maxSteps) || 0;
  return {
    kind: 'steps', used, max,
    pct: max ? Math.min(100, Math.round((used / max) * 100)) : 0,
    chipKey: 'Steps', unit: 'steps', source: 'campaign budget.maxSteps', hint: null,
  };
}

// ghostChip(st) -> { state, label, cls, title } — THE one mapping of a ghost.status()
// object to the chip vocabulary. state: 'off' | 'ok' | 'bad' | 'unverified'; cls is the
// console's ck-ok/ck-no class or ''. Never throws on a partial status object.
export function ghostChip(st) {
  if (!st || st.mode === 'off') {
    return { state: 'off', label: 'off', cls: '', title: 'Ghost Mode off — egress is direct (operator source exposed to targets)' };
  }
  const hops = st.hops || 0;
  const hopWord = hops === 1 ? ' hop' : ' hops';
  const title = 'chain: ' + ((st.chain || []).join(' → ') || '—') + ' · dns: ' + (st.dns || '');
  if (st.verified && st.verified.ok) {
    return { state: 'ok', label: st.mode + ' · ' + hops + hopWord + ' · exit ' + (st.verified.exitIp || '?'), cls: 'ck-ok', title };
  }
  if (st.verified) {
    return { state: 'bad', label: st.mode + ' · NOT HIDDEN', cls: 'ck-no', title: title + ' · ' + (st.verified.error || 'verification failed') };
  }
  return { state: 'unverified', label: st.mode + ' · ' + hops + hopWord + ' · unverified', cls: '', title };
}

// freshGroundView(events, cap) -> { shown, hiddenByCap, total } — display-trim the
// watcher's ranked ring, but an EXCLUSION move (side 'out' — the off-limits list moved)
// is never cut by the cap: it is safety-critical and stays visible with its weight.
export function freshGroundView(events, cap = 30) {
  const ranked = Array.isArray(events) ? events : [];
  const head = ranked.slice(0, cap);
  const kept = ranked.slice(cap).filter((e) => e && e.side === 'out');
  return { shown: [...head, ...kept], hiddenByCap: ranked.length - head.length - kept.length, total: ranked.length };
}

// RANK_WEIGHT: the documented h1watch rank order as operator-facing one-liners
// (mirrors the ranking comment in tools/h1watch.mjs — rankEvent is the code truth).
export const RANK_WEIGHT = {
  1: 'new bountied program — untouched ground that pays',
  2: 'fresh in-scope surface on a bountied program',
  3: 'bounty table moved on a bountied program — the reward math changed',
  4: 'new VDP program — reputation ground, no bounties',
  5: 'fresh in-scope surface, no bounties',
  6: 'EXCLUSION/policy move — honor before any contact',
  7: 'informational',
};

// eventSummary(e) -> one plain-text line per event (the console esc()s it). Asset and
// exclusion arrays are COUNTED with a short preview, never dumped whole.
export function eventSummary(e) {
  if (!e || !e.type) return '—';
  const list = (a) => (Array.isArray(a) ? a : []);
  const preview = (a) => { const l = list(a); return l.length ? ' — ' + l.slice(0, 3).join(', ') + (l.length > 3 ? ' …' : '') : ''; };
  switch (e.type) {
    case 'new-program':
      return (e.name || e.handle) + ' [' + e.handle + '] — ' + (e.offersBounties === true ? 'bountied' : e.offersBounties === false ? 'VDP (no bounties)' : 'bounties unknown')
        + ' · ' + list(e.assets).length + ' in-scope, ' + list(e.exclusions).length + ' excluded' + preview(e.assets);
    case 'scope-added':
      return e.handle + ' — ' + list(e.assets).length + ' ' + (e.side === 'out' ? 'NEW EXCLUSION(S)' : 'new in-scope asset(s)') + preview(e.assets);
    case 'scope-removed':
      return e.handle + ' — ' + list(e.assets).length + ' ' + (e.side === 'out' ? 'exclusion(s) LIFTED (signed scope still governs until re-signed)' : 'asset(s) left scope') + preview(e.assets);
    case 'policy-changed': {
      const from = (e.automation && e.automation.from && e.automation.from.policy) || '?';
      const to = (e.automation && e.automation.to && e.automation.to.policy) || '?';
      return e.handle + ' — policy changed · automation ' + from + ' → ' + to;
    }
    case 'bounty-table-changed': {
      const flip = e.offersBounties ? ' · bounties ' + String(e.offersBounties.from) + ' → ' + String(e.offersBounties.to) : '';
      return e.handle + ' — bounty table changed' + flip;
    }
    default:
      return e.handle ? e.handle + ' — ' + e.type : e.type;
  }
}

// goalReadout(goal) -> { paidText, targetText, pctText, widthPct } for the £3332.50
// ledger bar. widthPct is clamped for the bar; pctText keeps the true value (a payout
// past the goal reads honestly, the bar just fills). GBP counts toward the goal ONLY —
// the engine never converts currencies, and the console never pretends to either.
export function goalReadout(goal) {
  if (!goal || !Number.isFinite(Number(goal.target)) || Number(goal.target) <= 0) {
    return { paidText: '£0.00', targetText: '£3332.50', pctText: '0%', widthPct: 0 };
  }
  const paid = Number(goal.paid) || 0;
  const pct = Number.isFinite(Number(goal.pct)) ? Number(goal.pct) : (paid / Number(goal.target)) * 100;
  return {
    paidText: '£' + paid.toFixed(2),
    targetText: '£' + Number(goal.target).toFixed(2),
    pctText: (Math.round(pct * 100) / 100) + '%',
    widthPct: Math.max(0, Math.min(100, Math.round(pct))),
  };
}

// moneyText(amount, currency) — display-only currency glyph; NEVER a conversion.
export function moneyText(amount, currency) {
  const sym = { GBP: '£', USD: '$', EUR: '€' }[String(currency || '').toUpperCase()];
  const n = Number(amount);
  const v = Number.isFinite(n) ? n.toFixed(2) : String(amount);
  return (sym || (String(currency || '?') + ' ')) + v;
}

// jsq(s) — quote a value for interpolation into a SINGLE-QUOTED js string literal inside
// a DOUBLE-QUOTED inline handler attribute (onclick="fn('...')"). Two layers in one pass:
// the JS layer first (\ → \\, ' → \', CR/LF → \r/\n — a raw ' or line break terminates the
// literal and breaks the handler), then the HTML-attribute layer (the same & < > " entity
// mapping as the console's esc(), so the attribute itself can't be broken out of either).
// The layers never interfere: the JS layer introduces no & < > " chars to double-escape.
export function jsq(s) {
  return String(s == null ? '' : s)
    .replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\r/g, '\\r').replace(/\n/g, '\\n')
    .replace(/[&<>"]/g, (m) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[m]));
}
