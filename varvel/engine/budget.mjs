// VARVEL — enforced stealth budget.
//
// RedAmon has NO equivalent. Its stealth is a prompt paragraph with no measurement, no
// cap, and no proof of what it actually emitted ("the LLM is responsible" — their words).
// VARVEL's budget is a QUANTIFIED, ENFORCED noise ceiling for an authorized engagement:
// the agent proposes an action, the budget says whether it fits under the remaining noise
// allowance AND the peak-loudness ceiling, and anything over-budget must escalate to HITL
// rather than fire silently. At disengagement VARVEL can PROVE "we stayed under X" — a
// measurable guarantee, not a vibe.
//
// Currency = "noise points": each activity costs loudness(1–5) × count, straight from the
// detection-footprint model (footprint.mjs) — so the budget is grounded in the same model
// the operator already sees. This is operational stealth for AUTHORIZED engagements (stay
// under a defender's detection threshold), NOT evasion or anti-forensics: the Enclave
// still records every action in its tamper-evident audit. Quiet to the target, fully
// accountable to governance.

import { footprintFor, scoreFootprint } from './footprint.mjs';

// Activities are discrete: floor a count to a positive integer (rejects NaN/Infinity/≤0).
const normCount = (c) => { const n = Math.floor(Number(c)); return Number.isFinite(n) && n >= 1 ? n : 1; };

// Budget postures keyed to the stealth profiles (engine/stealth.mjs). `maxNoise` = the
// cumulative loudness×count allowed for the engagement; `peakCeiling` = the loudest single
// activity permitted before it must escalate to HITL.
export const BUDGET_PRESETS = {
  loud: { label: 'loud', maxNoise: Infinity, peakCeiling: 5, note: 'no stealth ceiling — authorized noisy engagement' },
  normal: { label: 'normal', maxNoise: 120, peakCeiling: 5, note: 'generous — exploitation allowed (still HITL-gated)' },
  quiet: { label: 'quiet', maxNoise: 40, peakCeiling: 3, note: 'recon-loud only; louder actions must escalate to HITL' },
  paranoid: { label: 'paranoid', maxNoise: 16, peakCeiling: 2, note: 'minimal footprint — near-passive only' },
};

export function budgetPreset(name) {
  if (name && typeof name === 'object') return { ...BUDGET_PRESETS.normal, ...name };
  return BUDGET_PRESETS[name] || BUDGET_PRESETS.normal;
}

// Cost of one activity in noise points (0 for an unknown/untracked kind).
export function noiseCost(kind, count = 1) {
  const fp = footprintFor(kind);
  return fp ? fp.loudness * normCount(count) : 0;
}

// Per-phase reserve: recon may consume at most RECON_SHARE of the cumulative noise
// budget; the remainder is RESERVED for the validate+exploit phases (today's bug:
// a 30-host wildcard recon exhausted the 'normal' 120 and validate ran
// no-progress). Advisory like check() — an over-reserve action flags escalate for
// HITL, it is never silently dropped.
export const PHASE_RESERVE = {
  reconShare: 0.7,
  reconPhases: ['recon'],
  note: 'recon is capped at 70% of the noise budget; 30% is reserved for validate+exploit',
};

export class StealthBudget {
  constructor(preset = 'normal') {
    const p = budgetPreset(preset);
    this.label = p.label;
    this.maxNoise = p.maxNoise;
    this.peakCeiling = p.peakCeiling;
    this.note = p.note;
    this.events = []; // committed { id, count, cost, loudness, override, at }
    this.untracked = 0; // actions under a kind the footprint model doesn't score (surfaced honestly)
  }

  spent() { return this.events.reduce((s, e) => s + e.cost, 0); }
  remaining() { return this.maxNoise === Infinity ? Infinity : Math.max(0, this.maxNoise - this.spent()); }

  // Preflight: would this activity fit the budget? Returns a verdict WITHOUT recording it.
  // An over-ceiling or over-budget action is not refused outright — it is flagged
  // `escalate:true` so the caller routes it through HITL (the human can authorize the
  // extra noise), exactly the enforcement point RedAmon's autonomous agent lacks.
  check(kind, count = 1) {
    const fp = footprintFor(kind);
    const spent = this.spent();
    const remaining = this.remaining();
    if (!fp) return { ok: true, cost: 0, unknown: true, spent, remaining, reason: 'untracked activity — no footprint cost' };
    const cost = fp.loudness * normCount(count);
    const overCeiling = fp.loudness > this.peakCeiling;
    const overBudget = this.maxNoise !== Infinity && cost > remaining;
    const ok = !overCeiling && !overBudget;
    let reason = 'within budget';
    if (overCeiling) reason = `${fp.label} is loudness ${fp.loudness}, above the ${this.label} ceiling of ${this.peakCeiling} — escalate to HITL to proceed`;
    else if (overBudget) reason = `${fp.label} costs ${cost} noise pts but only ${remaining} remain in the ${this.label} budget — escalate to HITL, or quieten/slow down`;
    return { ok, cost, loudness: fp.loudness, label: fp.label, spent, remaining, overCeiling, overBudget, escalate: !ok, reason };
  }

  // Phase-aware preflight: check() PLUS the per-phase reserve (PHASE_RESERVE). A
  // recon-phase action that would push recon spend past 70% of the budget is
  // flagged overReserve + escalate — validate+exploit keep their 30% reserve.
  // Non-recon phases and unlimited budgets are check() verbatim.
  checkPhase(kind, count = 1, phaseId = null) {
    const v = this.check(kind, count);
    if (this.maxNoise === Infinity || !phaseId || !PHASE_RESERVE.reconPhases.includes(phaseId) || v.unknown) return v;
    const cap = this.maxNoise * PHASE_RESERVE.reconShare;
    const after = this.spent() + v.cost;
    if (after > cap) {
      return { ...v, ok: false, escalate: true, overReserve: true, reserveCap: cap,
        reason: `${v.label || kind} would push recon-phase noise to ${after}/${this.maxNoise} — recon is capped at ${Math.round(PHASE_RESERVE.reconShare * 100)}% (${cap}) so validate+exploit keep their reserve — escalate to HITL, or trim the sweep` };
    }
    return v;
  }

  // Record an activity as spent. Call after it runs (or after a HITL override authorizes
  // over-budget noise — recorded with override:true so the after-action report is honest).
  record(kind, count = 1, { override = false } = {}) {
    const fp = footprintFor(kind);
    if (!fp) { this.untracked += 1; return null; } // count it so the proof can't imply silence
    const c = normCount(count);
    const ev = { id: fp.id, count: c, cost: fp.loudness * c, loudness: fp.loudness, override: !!override, at: new Date().toISOString() };
    this.events.push(ev);
    return ev;
  }

  // Live status for the console + after-action proof. HONEST by construction: it reports
  // the ACTUAL peak loudness emitted and whether the ceiling was truly honored — never a
  // "we stayed at ≤ Z" claim when a louder action actually fired. Ceiling breaches are
  // split into HITL-authorized (override) vs un-approved so the report can't overstate
  // restraint in either direction.
  status() {
    const spent = this.spent();
    const detection = scoreFootprint(this.events);
    const overspent = this.maxNoise === Infinity ? 0 : Math.max(0, spent - this.maxNoise);
    const underBudget = overspent === 0;
    const pctRaw = this.maxNoise === Infinity ? 0 : Math.round((spent / this.maxNoise) * 100);
    const pct = Math.min(100, pctRaw); // clamped for the UI meter; pctRaw can exceed 100
    const state = this.maxNoise === Infinity ? 'unlimited' : pct >= 100 ? 'exhausted' : pct >= 80 ? 'critical' : pct >= 50 ? 'warn' : 'ok';
    const overrides = this.events.filter((e) => e.override).length;
    const actualPeak = this.events.reduce((m, e) => Math.max(m, e.loudness), 0);
    const breaches = this.events.filter((e) => e.loudness > this.peakCeiling);
    const authorizedBreaches = breaches.filter((e) => e.override).length;
    const unauthorizedBreaches = breaches.length - authorizedBreaches;
    const ceilingHonored = actualPeak <= this.peakCeiling;
    const untracked = this.untracked || 0;
    // The proof requires BOTH invariants to claim restraint: the peak-loudness ceiling AND
    // the cumulative noise budget. A budget you can exceed while reporting "stayed under" is
    // worse than no budget — so each dimension is reported honestly on its own.
    let proof;
    if (this.maxNoise === Infinity) {
      proof = `Noisy engagement (no budget). Emitted ${spent} noise pts across ${this.events.length} activities (peak loudness ${actualPeak}/5)${untracked ? `, +${untracked} untracked` : ''}.`;
    } else if (ceilingHonored && underBudget) {
      proof = `Stayed under the ${this.label} budget: ${spent}/${this.maxNoise} noise pts (${pct}%), peak loudness ${actualPeak}/5 ≤ ceiling ${this.peakCeiling}${overrides ? `, ${overrides} HITL-authorized override(s)` : ''}.`;
    } else if (ceilingHonored && !underBudget) {
      proof = `Peak loudness ${actualPeak}/5 stayed ≤ ceiling ${this.peakCeiling}, but cumulative noise reached ${spent}/${this.maxNoise} noise pts — ${overspent} OVER the ${this.label} budget${overrides ? ` (${overrides} HITL-authorized)` : ''}.`;
    } else {
      const bc = underBudget ? `${spent}/${this.maxNoise} noise pts (${pct}%) under the ${this.label} budget`
        : `${spent}/${this.maxNoise} noise pts — ${overspent} OVER the ${this.label} budget`;
      proof = `${bc}, but peak loudness ${actualPeak}/5 exceeded the ${this.peakCeiling} ceiling — ${authorizedBreaches} HITL-authorized, ${unauthorizedBreaches} un-approved.`;
    }
    return {
      profile: this.label, maxNoise: this.maxNoise, peakCeiling: this.peakCeiling,
      spent, remaining: this.remaining(), pct, pctRaw, overspent, underBudget, state,
      actions: this.events.length, overrides, risk: detection.risk, note: this.note,
      actualPeak, ceilingHonored, breaches: breaches.length, authorizedBreaches, unauthorizedBreaches, untracked,
      proof,
    };
  }
}
