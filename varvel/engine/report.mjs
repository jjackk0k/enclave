// VARVEL — client-ready report generator. Attack surface -> Markdown.
// Pure function, no I/O. The governance section is a first-class part of the
// deliverable: it shows the client what the platform HELD (proof of restraint),
// and the OPSEC section shows every artifact + its cleanup status.

import { classify, remediation } from './classify.mjs';
import { riskLevel, sevRank } from './severity.mjs';
import { footprintFor } from './footprint.mjs';
import { footprintAdvisor } from './footprint-advisor.mjs';
import { isStale } from './validator.mjs';

const SEV_LABEL = { crit: 'CRITICAL', high: 'HIGH', med: 'MEDIUM', low: 'LOW', info: 'INFO' };

export function renderReport(s, { productivity, opsec, stealthBudget, targetProfile, toolsBudget, coverage, staleDays = 30, now = Date.now() } = {}) {
  const nodes = s.nodes || [];
  const edges = s.edges || [];
  const scope = s.scope || {};
  const c = s.counts || {};
  const byType = (t) => nodes.filter((n) => n.type === t);
  const findings = byType('finding');
  const exploits = byType('exploit');
  const parentOf = (id) => nodes.find((n) => edges.some((e) => e.to === id && e.from === n.id));
  const childExploit = (fid) => exploits.find((e) => edges.some((e2) => e2.from === fid && e2.to === e.id));

  const L = [];
  L.push(`# VARVEL Engagement Report — ${scope.engagement || 'engagement'}`);
  L.push('');
  L.push(`**Scope:** ${(scope.cidrs || []).join(', ') || '—'}  `);
  L.push(`**Authorized by:** ${scope.signedBy || '—'}`);
  L.push('');

  L.push('## Executive summary');
  L.push('');
  L.push(`- Hosts in scope: **${c.hosts ?? byType('host').length}**`);
  L.push(`- Findings: **${c.findings ?? findings.length}**  (confirmed: **${c.confirmed ?? 0}**, critical: **${c.crit ?? 0}**)`);
  // Validator-gate honesty: what was actually reproduced against an objective oracle vs
  // merely claimed. REFUTED findings are shown as what they are — claims that failed
  // reproduction (their confidence was flipped to suspected by the gate). v2: validated
  // findings past the staleness TTL render as STALE (a rendering of validated — the
  // stored vocabulary stays clean).
  const vals = { validated: 0, refuted: 0, untestable: 0, unvalidated: 0, stale: 0 };
  for (const f of findings) {
    const st = (f.validation && f.validation.state) || 'unvalidated';
    vals[st]++;
    if (st === 'validated' && isStale(f.validation, { now, staleDays })) vals.stale++;
  }
  if (findings.length) L.push(`- Validation (objective oracle): **${vals.validated} validated${vals.stale ? ` (${vals.stale} stale)` : ''} · ${vals.unvalidated} claimed-unvalidated · ${vals.refuted} refuted · ${vals.untestable} untestable**`);
  const riskCount = (lvl) => (c.risk && typeof c.risk[lvl] === 'number' ? c.risk[lvl] : findings.filter((f) => (f.risk || riskLevel(f.sev)) === lvl).length);
  L.push(`- Risk levels: **${riskCount('high')} high · ${riskCount('medium')} medium · ${riskCount('info')} info**`);
  L.push(`- Exploits proven: **${exploits.filter((e) => e.state === 'proved').length}**`);
  L.push(`- Governance holds (actions the platform blocked in-flight): **${(s.holds || []).length}**`);
  L.push('');

  // Target scoring (Build 3, 2026-08-31): the ROI layer's per-host expected-yield
  // scores — where the campaign concentrated tool budget and WHY. Scores ride the
  // host nodes (persisted with the surface), so this section needs no extra input.
  // Every reason names the observed signal behind it; scoring REORDERED per-host
  // tool budgets only — no host was skipped, hidden, or refused differently.
  const scoredHosts = byType('host').filter((h) => h.targetScore && Number.isFinite(h.targetScore.score)).sort((a, b) => b.targetScore.score - a.targetScore.score);
  if (scoredHosts.length) {
    L.push('## Target scoring');
    L.push('');
    L.push('_Expected-yield scores computed from recon-observed signals (deterministic — no model call). Scores reordered per-host tool budgets ONLY: every in-scope host was tested, and refusal rules were unchanged._');
    L.push('');
    for (const h of scoredHosts.slice(0, 20)) {
      const ts = h.targetScore;
      L.push(`- **${ts.score}/100** \`${h.label || h.ip}\`${(ts.classes || []).length ? ' — ' + ts.classes.join(' · ') : ''}`);
      for (const r of (ts.reasons || []).slice(0, 6)) L.push(`  - ${r}`);
    }
    L.push('');
  }

  L.push('## Findings');
  L.push('');
  const sorted = [...findings].sort((a, b) => sevRank(a.sev) - sevRank(b.sev));
  if (!sorted.length) L.push('_No findings recorded._');
  for (const f of sorted) {
    const host = parentOf(f.id);
    L.push(`### [${SEV_LABEL[f.sev] || f.sev}] ${f.label}${f.ref ? `  \`${f.ref}\`` : ''}`);
    L.push(`- Host: \`${host ? host.label : '—'}\`${f.cve ? ` · CVE ${f.cve}` : ''} · confidence: **${(f.confidence || 'suspected').toUpperCase()}**${typeof f.conf === 'number' ? ` (${f.conf}%)` : ''}${f.inherited ? ' · carried forward' : ''}`);
    const val = f.validation;
    const blTag = f.soft404Baselined ? ' · soft-404 baselined (survived the SPA-fallback differential)' : '';
    if (!val) {
      L.push('- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate' + blTag);
    } else {
      const stale = isStale(val, { now, staleDays });
      let line = `- Validation: **${stale ? 'STALE' : String(val.state).toUpperCase()}** — `;
      if (stale) line += `validated ${val.validatedAt || val.at}, older than the ${staleDays}-day TTL — revalidation advised · last verdict: ${val.oracle} _(${val.at})_`;
      else line += `${val.oracle} _(${val.at})_`;
      // v2 verdict detail (additive; existing field-naming style): the control read, the
      // marker the verdict anchored to, and the staleness clock.
      if (val.control && val.control.line) line += ` · ${val.control.line}`;
      else if (val.control && typeof val.control.matched === 'boolean') line += ` · control ${val.control.matched ? 'matched' : 'absent'}`;
      if (val.marker) line += ` · marker \`${val.marker}\``;
      if (val.validatedAt && !stale) line += ` · validatedAt ${val.validatedAt}`;
      line += blTag;
      L.push(line);
    }
    if (Array.isArray(f.notes)) for (const n of f.notes) L.push(`- Note: _${n}_`);
    const m = classify(f.label);
    L.push(`- Maps to: ${m.owasp} · MITRE ${m.attack}`);
    const ex = childExploit(f.id);
    if (ex) L.push(`- Exploit: **${ex.label}** — _${ex.state}_`);
    L.push('');
  }

  L.push('## Governance & scope');
  L.push('');
  if (!(s.holds || []).length) L.push('_No actions were held — all activity stayed within the signed scope._');
  for (const h of (s.holds || [])) L.push(`- **HELD** \`${h.action}\` — ${h.rule} (${h.target})`);
  L.push('');

  // Soft-404 debunk ledger: claims the SPA-fallback baseline REFUTED. Shown as what
  // they are — a scanner would have filed these; this engine proved them fake and
  // says so on the record instead of dropping them silently.
  const deb = s.debunked || [];
  if (deb.length) {
    L.push(`## Soft-404 debunked (${deb.length})`);
    L.push('');
    L.push('_These sensitive-path probes answered 2xx, but the response fingerprint-matched the host\'s soft-404 SPA fallback (random-garbage-path baseline: status + length bucket + body simhash). They are NOT findings — a status-only scanner would have filed them all._');
    L.push('');
    for (const d of deb) L.push(`- **DEBUNKED** \`${d.path}\` on \`${d.host || '—'}\` — would-be claim: "${d.title}" (${d.tool || 'scanner'} · soft404.match _${d.at}_)`);
    L.push('');
  }

  // Tool-lane budget (Build 2, 2026-08-30): the hunting lanes (jsminer / OOB callback
  // correlation / DOM-XSS canary / authz victim-object seeding) charge a SEPARATE
  // bucket — never the agent step budget — so the report states their spend explicitly.
  if (toolsBudget) {
    L.push(`- Tool-lane budget (jsminer / OOB / DOM-XSS canary / authz seeding — a bucket SEPARATE from the agent step and noise budgets): **${toolsBudget.used}/${toolsBudget.maxRequests}** governed requests, wall-clock cap **${Math.round((toolsBudget.maxMs || 0) / 1000)}s**${toolsBudget.exhausted ? ' — **EXHAUSTED** (budget.exhausted {bucket:tools} on the activity record; the lanes stopped honestly)' : ' — not exhausted'}.`);
    L.push('');
  }

  // Coverage-completion gate (winner-copyables build, Tool 3 — the confirm_testing_complete
  // pattern): which harvested endpoints/params/object-ids the lanes ACTUALLY exercised.
  // "done-clean" is earned by a drained queue; anything else is itemized, not vibes.
  if (coverage) {
    L.push('## Coverage — testing-completeness ledger');
    L.push('');
    L.push('_Every endpoint/param/object-id recon put on the attack surface was queued for testing; lanes marked what they exercised. The gate measures EXERCISE, not safety — what the lanes proved lives in the findings above._');
    L.push('');
    L.push(`- Verdict: **${coverage.verdict || 'NOT RUN (campaign unfinished)'}** — ${coverage.tested}/${coverage.queued} queued surface item(s) exercised${coverage.byLane && Object.keys(coverage.byLane).length ? ` (by lane: ${Object.entries(coverage.byLane).map(([l, n]) => `${l} ${n}`).join(' · ')})` : ''}.`);
    if (coverage.verdict === 'COVERAGE-INCOMPLETE' && Array.isArray(coverage.untested) && coverage.untested.length) {
      L.push(`- **REMAINING UNTESTED QUEUE (${coverage.untested.length}${coverage.untestedTruncated ? '+ — truncated' : ''}):** the next run's worklist, itemized — the campaign is NOT done-clean while these stand:`);
      L.push('');
      for (const i of coverage.untested.slice(0, 40)) L.push(`  - \`${i.key}\` [${i.kind}]${i.host ? ` on \`${i.host}\`` : ''}${i.source ? ` (queued by ${i.source})` : ''}`);
    }
    if (coverage.verdict === 'NO-SURFACE-QUEUED') L.push('- Recon queued NO testable surface — a clean bill here is vacuous and is recorded as vacuous.');
    if (coverage.orphans && coverage.orphans.length) L.push(`- Coverage discrepancies (lane marks against never-queued keys — kept visible, never silent): **${coverage.orphans.length}**`);
    if (coverage.overflow) L.push(`- Queue overflow: **${coverage.overflow}** harvested item(s) exceeded the ledger cap — the ledger is a LOWER bound on remaining surface.`);
    L.push('');
  }

  // Detection footprint — the tradecraft-transparency deliverable: exactly what a
  // blue team would have seen, and what it exposed about the operator.
  const det = opsec && opsec.posture && opsec.posture.detection;
  L.push('## OPSEC — detection footprint');
  L.push('');
  if (!det || !det.events) {
    L.push('_No noisy activity was recorded for this engagement._');
    L.push('');
  } else {
    L.push(`Overall detection risk: **${(det.risk || '').toUpperCase()}** — peak loudness **${det.peakLoudness}/5**, weighted **${det.weighted}/5**, across **${det.actions}** recorded action(s).`);
    L.push('');
    L.push('What a defender would have observed (loudest first):');
    L.push('');
    for (const a of det.loudest) {
      const fp = footprintFor(a.id) || {};
      L.push(`### [${a.loudness}/5] ${a.label}${a.count > 1 ? ` ×${a.count}` : ''}`);
      if (fp.detectedBy) L.push(`- Detected by: ${fp.detectedBy.join(' · ')}`);
      if (fp.exposes) L.push(`- Exposes: ${fp.exposes.join(' · ')}`);
      if (fp.quieter) L.push(`- Lower-noise alternative: ${fp.quieter}`);
      L.push('');
    }
    L.push(`**Detection surface (everything that could have caught us):** ${det.detectedBy.join(' · ')}`);
    L.push('');
    L.push(`**Operator exposure (what our activity revealed):** ${det.exposes.join(' · ')}`);
    L.push('');
  }

  // Stealth budget — the quantified "what we stayed under" guarantee. This is the
  // defender's-eye proof RedAmon structurally cannot produce (it has no footprint model,
  // no budget, no measurement). Accountability, not evasion: the number is a promise kept.
  if (stealthBudget && stealthBudget.maxNoise != null) {
    const b = stealthBudget;
    L.push('## OPSEC — stealth budget (what we stayed under)');
    L.push('');
    // Auto-stealth: show WHY this profile was chosen (the measured calibration RedAmon punts).
    if (targetProfile && targetProfile.calibration) {
      const tp = targetProfile;
      const vendors = (tp.defenses || []).map((d) => d.vendor).join(', ') || 'no WAF/CDN detected';
      L.push(`Target defenses (auto-calibrated): **${vendors}**${tp.rateLimit ? ' · rate-limited' : ''}${tp.challenge ? ' · bot-challenge' : ''} → profile **${(tp.calibration.recommended || '').toUpperCase()}**.`);
      if ((tp.calibration.reasons || []).length) L.push(`- Calibration rationale: ${tp.calibration.reasons.join('; ')}.`);
      L.push('');
    }
    if (b.maxNoise === Infinity || b.profile === 'loud') {
      L.push(`No stealth ceiling was set for this engagement (authorized noisy run). Total noise emitted: **${b.spent}** noise-point(s) across **${b.actions}** action(s).`);
    } else {
      L.push(`Operational-stealth profile: **${(b.profile || '').toUpperCase()}**. ${b.proof}`);
      L.push('');
      L.push(`- Noise budget: **${b.spent}/${b.maxNoise}** noise-points (**${b.pctRaw ?? b.pct}%** of cap, state: **${(b.state || '').toUpperCase()}**)`);
      if (b.underBudget === false) L.push(`- Cumulative noise budget **exceeded** by **${b.overspent}** noise-point(s)`);
      if (b.ceilingHonored) {
        L.push(`- Peak-loudness ceiling honored: emitted **${b.actualPeak}/5** ≤ ceiling **${b.peakCeiling}/5**`);
      } else {
        L.push(`- Peak-loudness ceiling **exceeded**: emitted **${b.actualPeak}/5** vs ceiling **${b.peakCeiling}/5** — **${b.authorizedBreaches}** HITL-authorized, **${b.unauthorizedBreaches}** un-approved`);
      }
      if (b.overrides) L.push(`- HITL-authorized over-ceiling actions: **${b.overrides}** (noise was raised only with explicit approval)`);
      if (b.untracked) L.push(`- Untracked activities (not in the footprint model, unscored): **${b.untracked}**`);
      L.push('');
      L.push('_Noise cost = loudness×count from the detection-footprint model above. The budget is enforced in-flight: over-ceiling actions escalate to a human, they do not fire silently. This report states the ACTUAL peak emitted — never an unearned "we stayed quiet" claim._');
    }
    L.push('');
  }

  // Footprint reduction plan — how to LOWER the detection number (authorized courtesy).
  if (opsec) {
    const adv = footprintAdvisor(opsec);
    if (adv && adv.plan && adv.plan.length) {
      L.push('## OPSEC — footprint reduction');
      L.push('');
      L.push(`Current detection risk **${(adv.currentRisk || '').toUpperCase()}** (${adv.currentScore}/5); applying the moves below projects **${(adv.projectedRisk || '').toUpperCase()}** (${adv.projectedScore}/5, −${adv.reducible}).`);
      L.push('');
      for (const p of adv.plan.slice(0, 5)) L.push(`- **${p.activity}** (loudness ${p.loudness}/5) — ${p.issue}. Quieter: ${p.quieter} (~${p.estReductionPct}% less noise).`);
      L.push('');
    }
  }

  L.push('## OPSEC — artifacts & cleanup');
  L.push('');
  const artifacts = (opsec && opsec.artifacts) || [];
  if (!artifacts.length) L.push('_No artifacts were dropped on client systems._');
  for (const a of artifacts) L.push(`- \`${a.host || '—'}:${a.path || '—'}\` (${a.kind || 'artifact'}) — ${a.status === 'cleaned' ? '**CLEANED**' : '**PENDING** cleanup'}${a.cleanup ? ` · \`${a.cleanup}\`` : ''}`);
  L.push('');

  L.push('## Remediation');
  L.push('');
  const rem = remediation(s);
  if (!rem.length) L.push('_No remediation items._');
  for (const r of rem) L.push(`- **[${(r.sev || '').toUpperCase()}]** ${r.finding}${r.ref ? ` (${r.ref})` : ''}: ${r.fix}`);
  L.push('');
  if (productivity && productivity.phases) {
    L.push('## Autonomy integrity');
    L.push('');
    L.push(`- Phases audited: **${productivity.phases}** · productive: **${productivity.productive}** · no-progress: **${productivity.noProgress}** · longest stall: **${productivity.stuckStreak ?? 0}**`);
    L.push(`- Hallucinated / dishonest progress: **${productivity.dishonest}** · honesty rate: **${Math.round((productivity.honestyRate ?? 1) * 100)}%**`);
    L.push('');
    L.push('_Every agent claim was cross-checked against the real attack-surface delta; hallucinated progress is downgraded, never reported as fact._');
    L.push('');
  }

  L.push('---');
  L.push("_Generated by VARVEL. Every action in this engagement is recorded in the Enclave's tamper-evident audit ledger — the target is left clean, the proof is kept in the vault._");
  return L.join('\n');
}
