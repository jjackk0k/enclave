// VARVEL — coverage: the COVERAGE-COMPLETION GATE (winner-copyables build, Tool 3).
// PURE CORE — zero network, zero fs (pinned by a static scan in the test).
//
// The verified-earner pattern (research/2026-08-31-ai-hunter-practitioner-brief.md
// §2/§5.2 — `confirm_testing_complete()`): the campaign may not call itself "done-clean"
// while QUEUED in-scope surface is untested. Today's honest "skipped with named reasons"
// becomes an explicit untested-surface LEDGER:
//
//   queue({kind, key, host, source}) — recon harvest registers every surfaced endpoint /
//     param / object-id template it puts on the attack surface.
//   mark(key, lane)                  — a lane (oracle | oob | browseragent | aisurface |
//     jsminer | manual) records that it ACTUALLY EXERCISED the item. Marks against
//     unknown keys are kept visible as orphans (a lane claiming coverage of surface the
//     ledger never queued is a discrepancy, not a silent success).
//   gate()                           — the completion verdict:
//       NO-SURFACE-QUEUED   — recon harvested nothing; "clean" is vacuous, said so
//       DONE-CLEAN          — every queued item was exercised by ≥1 lane
//       COVERAGE-INCOMPLETE — the remaining queue, itemized, is the deliverable
//
// ORACLE CONTRACT: coverage measures EXERCISE, not bugs — a lane marks an item when it
// sent its governed requests at it, whatever they proved. The gate never claims the
// target is safe; it claims the queue was drained, or names what wasn't.

export const COVERAGE_LANES = ['oracle', 'jsminer', 'oob', 'browseragent', 'aisurface', 'manual'];
export const COVERAGE_KINDS = ['endpoint', 'param', 'object-id'];
export const COVERAGE_CAPS = { maxItems: 5000, maxKeyLen: 512 };

const iso = (now) => (now === undefined ? new Date().toISOString() : (typeof now === 'number' ? new Date(now).toISOString() : String(now)));

// classify a surface endpoint label: '/path?param=' is a param, '/x/{id}' an object-id
// template, anything else a plain endpoint.
export function kindOfLabel(label) {
  const s = String(label || '');
  if (s.includes('{id}')) return 'object-id';
  if (/\?[^=]*=/.test(s)) return 'param';
  return 'endpoint';
}

export class CoverageLedger {
  constructor({ now } = {}) {
    this._now = now;
    this._items = new Map(); // key -> { kind, key, host, source, queuedAt, testedBy: [{lane, at, note}] }
    this._orphans = [];      // marks against keys the ledger never queued — kept VISIBLE
    this._overflow = 0;      // items refused past the cap — counted, never silent
  }

  // queue an item; dedupe by kind+key. Returns true when newly queued.
  queue({ kind, key, host = null, source = null } = {}) {
    const k = String(key || '').slice(0, COVERAGE_CAPS.maxKeyLen);
    const kd = COVERAGE_KINDS.includes(kind) ? kind : kindOfLabel(k);
    if (!k) return false;
    const id = kd + '|' + k;
    if (this._items.has(id)) return false;
    if (this._items.size >= COVERAGE_CAPS.maxItems) { this._overflow++; return false; }
    this._items.set(id, { kind: kd, key: k, host: host ? String(host) : null, source: source ? String(source) : null, queuedAt: iso(this._now && this._now()), testedBy: [] });
    return true;
  }

  has(key, kind) {
    const k = String(key || '');
    if (kind) return this._items.has(kind + '|' + k);
    for (const kd of COVERAGE_KINDS) if (this._items.has(kd + '|' + k)) return true;
    return false;
  }

  // mark a queued item exercised by a lane. Unknown lane or unknown key is NOT silent:
  // the lane is clamped to 'manual' with the original named, unknown keys land in the
  // orphan list. Returns true when a queued item was marked.
  mark(key, lane, { note } = {}) {
    const k = String(key || '').slice(0, COVERAGE_CAPS.maxKeyLen);
    const ln = COVERAGE_LANES.includes(lane) ? lane : 'manual';
    const at = iso(this._now && this._now());
    for (const kd of COVERAGE_KINDS) {
      const it = this._items.get(kd + '|' + k);
      if (it) {
        if (!it.testedBy.some((t) => t.lane === ln)) it.testedBy.push({ lane: ln, at, note: note ? String(note).slice(0, 160) : null, ...(ln !== lane ? { claimedLane: String(lane) } : {}) });
        return true;
      }
    }
    this._orphans.push({ key: k, lane: ln, at, note: 'marked by a lane but never queued by recon — a coverage discrepancy, kept visible' });
    return false;
  }

  untested() {
    return [...this._items.values()].filter((i) => !i.testedBy.length);
  }

  status() {
    const items = [...this._items.values()];
    const byLane = {};
    for (const i of items) for (const t of i.testedBy) byLane[t.lane] = (byLane[t.lane] || 0) + 1;
    const untested = items.filter((i) => !i.testedBy.length);
    return {
      queued: items.length,
      tested: items.length - untested.length,
      untested: untested.map((i) => ({ kind: i.kind, key: i.key, host: i.host, source: i.source, queuedAt: i.queuedAt })),
      byLane,
      orphans: this._orphans.slice(),
      overflow: this._overflow,
    };
  }

  // THE GATE. done-clean is EARNED: every queued item exercised. Anything else reports
  // COVERAGE-INCOMPLETE with the remaining queue itemized (capped; overflow counted).
  gate({ maxRemaining = 50 } = {}) {
    const s = this.status();
    if (s.queued === 0) {
      return { verdict: 'NO-SURFACE-QUEUED', queued: 0, tested: 0, remaining: [], orphans: s.orphans, note: 'recon queued no testable surface — a clean bill here is vacuous and is said to be vacuous' };
    }
    if (!s.untested.length) {
      return { verdict: 'DONE-CLEAN', queued: s.queued, tested: s.tested, remaining: [], byLane: s.byLane, orphans: s.orphans, note: 'every queued in-scope surface item was exercised by at least one lane (exercise, not safety — the findings carry what the lanes PROVED)' };
    }
    return {
      verdict: 'COVERAGE-INCOMPLETE',
      queued: s.queued, tested: s.tested,
      remaining: s.untested.slice(0, maxRemaining),
      remainingTotal: s.untested.length,
      truncated: s.untested.length > maxRemaining,
      byLane: s.byLane, orphans: s.orphans,
      note: `${s.untested.length} queued in-scope surface item(s) were NEVER exercised — the campaign is NOT done-clean; the remaining queue is the next run's worklist`,
    };
  }
}
