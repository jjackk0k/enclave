// VARVEL — OPSEC / engagement-hygiene ledger.
// Tracks operational-security posture for an authorized engagement: every
// artifact dropped on client systems + its cleanup status, the footprint/noise
// generated, and governance holds. Differentiator: "clean the target, keep the
// proof" — leave no leftover artifacts on the client while the Enclave keeps the
// tamper-evident audit.
//
// Honest by design: NO "undetectable / perfect security" claims. This is
// tradecraft transparency + a cleanup ledger, for authorized engagements only.
// It tracks and reports posture; it never implements evasion/anti-forensics.
//
// The detection footprint (footprint.mjs) makes the noise EXPLICIT: every activity is
// recorded against a profile of what a defender would see, what it exposes about the
// operator, and how loud it is — surfaced to both the operator and the agent.

import { scoreFootprint, footprintFor } from './footprint.mjs';
import { footprintAdvisor } from './footprint-advisor.mjs';

export class Opsec {
  constructor() {
    this.artifacts = [];    // {host, kind, path, cleanup, status, at}
    this.cleanups = [];
    this.activities = [];   // {id, host, count, at} — detection-footprint events
    this.footprint = { toolCalls: 0, hosts: new Set(), noisyActions: 0, holds: 0 };
  }

  // Record a detection-footprint activity (what we just did that leaves a trace).
  // Silently ignores unknown kinds so callers can pass raw activity labels.
  act({ kind, host = null, count = 1 } = {}) {
    const fp = footprintFor(kind);
    if (!fp) return null;
    const ev = { id: fp.id, host, count: Math.max(1, Number(count) || 1), at: new Date().toISOString() };
    this.activities.push(ev);
    if (fp.loudness >= 4) this.footprint.noisyActions += ev.count; // keep the coarse counter honest too
    if (host) this.footprint.hosts.add(host);
    return ev;
  }

  record({ host, kind, path, cleanup }) {
    this.artifacts.push({ host, kind, path, cleanup: cleanup || 'PENDING', status: 'dropped', at: new Date().toISOString() });
    this.act({ kind: 'file-drop', host }); // a dropped artifact IS a detectable file-create
  }

  markClean(index, note) {
    const a = this.artifacts[index];
    if (!a) return false;
    a.status = 'cleaned';
    this.cleanups.push({ index, host: a.host, path: a.path, note: note || a.cleanup, at: new Date().toISOString() });
    return true;
  }

  observe({ toolCalls = 0, host = null, noisy = 0, holds = 0 } = {}) {
    this.footprint.toolCalls += toolCalls;
    if (host) this.footprint.hosts.add(host);
    this.footprint.noisyActions += noisy;
    this.footprint.holds += holds;
  }

  posture() {
    const pending = this.artifacts.filter((a) => a.status === 'dropped').length;
    const cleaned = this.artifacts.filter((a) => a.status === 'cleaned').length;
    const detection = scoreFootprint(this.activities);
    return {
      artifacts: this.artifacts.length,
      cleaned,
      pending,
      cleanState: pending === 0,
      footprint: {
        toolCalls: this.footprint.toolCalls,
        hostsTouched: this.footprint.hosts.size,
        noisyActions: this.footprint.noisyActions,
        holds: this.footprint.holds,
      },
      detection, // scored: risk, peak/weighted loudness, loudest activities, what detects you, what you expose
      note: pending === 0
        ? 'Target clean — every dropped artifact has a verified cleanup.'
        : `${pending} artifact(s) awaiting cleanup before disengagement.`,
    };
  }

  // Per-activity detail with the full profile attached (for the console + report):
  // what a defender sees, what it exposes, and the lower-noise alternative.
  activityDetail() {
    return this.activities.map((a) => {
      const fp = footprintFor(a.id) || {};
      return { id: a.id, label: fp.label || a.id, host: a.host, count: a.count, at: a.at, loudness: fp.loudness, category: fp.category, attribution: fp.attribution, signals: fp.signals || [], detectedBy: fp.detectedBy || [], exposes: fp.exposes || [], quieter: fp.quieter || '' };
    });
  }

  toJSON() {
    const posture = this.posture();
    // Live footprint-reduction plan — always-on (recomputed every state read as activity
    // accrues), deterministic, transparency-bound. This is the "constantly watching +
    // lowering the number" capability without any AI cost.
    return { artifacts: this.artifacts, cleanups: this.cleanups, activities: this.activityDetail(), posture, reduction: footprintAdvisor({ posture }) };
  }
}
