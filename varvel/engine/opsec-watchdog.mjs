// VARVEL — OPSEC watchdog: the footprint section's reflex arc.
//
// Jack's ask: an always-on watcher over the noise budget that RESPONDS when the number
// climbs — not a post-mortem, a reflex. It watches every noise event as it's charged,
// reacts on state escalations (ok → warn → critical → exhausted), and can apply a
// bounded FIX on the spot: widening the engagement's emission gap (auto-throttle) when
// the budget goes critical. Everything it does is logged with the reason — the watchdog
// quiets the target-visible cadence; it never hides anything from the ledger.
//
// What it is NOT: an LLM in the loop. It's deterministic, instant, and free — the
// event-driven AI advisor (engine/footprint-ai.mjs) gives the prose; this gives the
// reflex. Both report through the same state surface.
//
// Also watches the one exposure no amount of pacing fixes: every activity in the
// footprint model exposes the SOURCE IP. The watchdog's advice names it — pacing
// changes WHEN you're seen; the source changes WHO is seen. Routing decisions (which
// authorized source the engagement runs from) belong to the operator, and the watchdog
// keeps that visible instead of pretending stealth is only about timing.

const RANK = { ok: 0, unlimited: 0, warn: 1, critical: 2, exhausted: 3 };

const SOURCE_IP_NOTE = 'Reminder: every activity exposes the source IP to the target — pacing changes WHEN you\'re seen, the source changes WHO is seen. Confirm the engagement is running from its authorized source.';

export class OpsecWatchdog {
  // budget: a StealthBudget. pacer: () => the engagement's pacer (or null) — a getter so
  // 'auto'-calibrated pacers (built after construction) are still reached. onEvent: audit
  // tap. autoThrottle: when true, entering 'critical' widens the emission gap once.
  constructor({ budget, pacer = () => null, onEvent, autoThrottle = true } = {}) {
    if (!budget) throw new Error('OpsecWatchdog: a noise budget is required');
    this.budget = budget;
    this.pacer = typeof pacer === 'function' ? pacer : () => pacer;
    this.onEvent = typeof onEvent === 'function' ? onEvent : () => {};
    this.autoThrottle = !!autoThrottle;
    this._rank = -1;              // last state rank seen (-1 = first check)
    this._breaches = 0;           // last unauthorized-breach count seen
    this._throttled = false;      // auto-throttle fires once per engagement (bounded)
    this._latest = null;          // latest advice, for /api/state
  }

  latest() { return this._latest; }

  _emit(type, obj) { try { this.onEvent(type, obj); } catch { /* audit tap must never break the watchdog */ } }

  // Call after every noise event. Emits advice ONLY on escalations (never spams).
  check() {
    const s = this.budget.status();
    const rank = RANK[s.state] ?? 0;
    const breaches = s.unauthorizedBreaches || 0;

    // Un-approved ceiling breach — fires independently of state, each time the count grows.
    if (breaches > this._breaches) {
      this._breaches = breaches;
      this._latest = {
        level: 'critical', kind: 'ceiling-breach', at: new Date().toISOString(),
        text: `${breaches} un-approved loud action(s) fired above the ${s.peakCeiling}/5 peak ceiling (actual peak ${s.actualPeak}/5). Something bypassed the gate — review before continuing. The after-action proof will report this honestly.`,
      };
      this._emit('opsec.watchdog', { level: 'critical', kind: 'ceiling-breach', breaches });
      return this._latest;
    }

    if (rank <= this._rank) return null; // no escalation → silence
    this._rank = rank;

    let advice = null;
    if (s.state === 'warn') {
      advice = {
        level: 'warn', kind: 'budget-warn', at: new Date().toISOString(),
        text: `Noise at ${s.pct}% of the ${s.profile} budget (${s.spent}/${s.maxNoise} pts). Shift weight to the quiet kinds — passive sources, crawl, apisurface — and keep brute-force kinds (content discovery, vuln probes) for confirmed leads only. ${SOURCE_IP_NOTE}`,
      };
    } else if (s.state === 'critical') {
      let fix = '';
      if (this.autoThrottle && !this._throttled) {
        const p = this.pacer();
        if (p && typeof p.penalize === 'function') {
          p.penalize(2, 0); // widen the emission gap — a real, bounded fix, logged with its reason
          this._throttled = true;
          fix = ` FIX APPLIED: auto-throttled — the shared emission gap widened to ~${p.currentDelay()}ms so the remaining recon emits slower.`;
          this._emit('opsec.watchdog.throttle', { newDelayMs: p.currentDelay() });
        }
      }
      advice = {
        level: 'critical', kind: 'budget-critical', at: new Date().toISOString(),
        text: `Noise at ${s.pct}% of budget (${s.spent}/${s.maxNoise} pts) — loud kinds stop now; reserve what remains for high-value, confirmed-target actions.${fix} ${SOURCE_IP_NOTE}`,
        throttled: this._throttled,
      };
    } else if (s.state === 'exhausted') {
      advice = {
        level: 'exhausted', kind: 'budget-exhausted', at: new Date().toISOString(),
        text: `Noise budget SPENT (${s.spent}/${s.maxNoise} pts). Any further loud action breaches the mandate — escalate to HITL for an authorized override or wrap to the report. The proof will state the overshoot honestly. ${SOURCE_IP_NOTE}`,
      };
    }

    if (advice) {
      this._latest = advice;
      this._emit('opsec.watchdog', { level: advice.level, kind: advice.kind, pct: s.pct, throttled: !!advice.throttled });
    }
    return advice;
  }
}
