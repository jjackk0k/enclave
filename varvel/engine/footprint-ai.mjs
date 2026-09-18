// VARVEL — event-driven OPSEC AI advisor (the "AI watching the footprint" layer).
//
// The deterministic footprint-advisor (footprint-advisor.mjs) is the always-on core: it
// scores the footprint and lists quieter alternatives for free. THIS layer adds an AI
// only where the fixed model can't reach — ENGAGEMENT-SPECIFIC reasoning (infer the
// defensive stack from the responses, tailor advice to this exact situation) — and only
// when it's worth it: it fires ONLY on high/critical risk AND only when the footprint
// actually grew (event-driven, never a wasteful timer poll). A cheap model is enough.
//
// STRICTLY transparency-bound: it advises reducing NEEDLESS noise on the CLIENT'S systems
// (professional courtesy + the defender's own view of what is loud). It does NOT do
// evasion, anti-forensics, log tampering, or "becoming undetectable" — everything stays
// fully logged and attributable in the Enclave audit. The prompt says so and a test
// asserts the advice-prompt carries no evasion vocabulary.

import { footprintAdvisor } from './footprint-advisor.mjs';
import { isKimiModel } from './kimi-runagent.mjs';

const HIGH = new Set(['high', 'critical']);

// Backend routing for the advisor (2026-08-11 fix). The claude-cli subprocess authenticates
// with a STALE cached credential — an old, exhausted subscription — and died in production
// with a 403 "usage limit". The DEFAULT is therefore the Kimi backend, the same auto-refreshed
// OAuth subscription the main agent path already proves alive. VARVEL_ADVISOR_MODEL routing:
//   unset            → Kimi at ADVISOR_KIMI_DEFAULT (cheap: k2.7-code, low effort — a few
//                      concrete sentences of advice needs no deep reasoning),
//   a Kimi model     → Kimi at that model,
//   a claude model   → the claude-cli path, ONLY as this explicit opt-in AND only with the
//                      CLI present (never an implicit fallback).
// Returns { backend, model, effort? } or null when the routed backend is unavailable.
// VARVEL_FOOTPRINT_AI=0 disables the advisor outright (null, whatever the backends).
export const ADVISOR_KIMI_DEFAULT = 'kimi-k2.7-code';
export function advisorBackend(env = {}, { kimiUp = false, claudeUp = false } = {}) {
  if (env.VARVEL_FOOTPRINT_AI === '0') return null;
  const m = env.VARVEL_ADVISOR_MODEL;
  if (!m || isKimiModel(m)) return kimiUp ? { backend: 'kimi', model: m ? String(m) : ADVISOR_KIMI_DEFAULT, effort: 'low' } : null;
  return claudeUp ? { backend: 'claude', model: String(m) } : null;
}

function detectionOf(opsecJSON) {
  const o = opsecJSON || {};
  return o.detection || (o.posture && o.posture.detection) || {};
}

// Decide WHEN to fire: high/critical risk AND the footprint has grown since last check.
// `lastActions` is the recorded-action count at the previous advise (null = first time).
export function shouldAdvise(opsecJSON, lastActions = null) {
  const adv = footprintAdvisor(opsecJSON);
  const actions = detectionOf(opsecJSON).actions || 0;
  if (!HIGH.has(adv.currentRisk)) return { fire: false, actions, risk: adv.currentRisk };
  if (lastActions != null && actions <= lastActions) return { fire: false, actions, risk: adv.currentRisk }; // no new noise → nothing to add
  return { fire: true, actions, risk: adv.currentRisk, advisor: adv };
}

// The bounded prompt handed to the cheap model.
export function advisorPrompt(adv, { target } = {}) {
  const plan = (adv && adv.plan) || [];
  return [
    'You are VARVEL\'s OPSEC advisor on an AUTHORIZED engagement (signed scope, everything logged).',
    `The detection footprint is ${String(adv.currentRisk || '').toUpperCase()} (${adv.currentScore}/5)${target ? ' against ' + target : ''}. Loudest activities:`,
    ...plan.slice(0, 4).map((p) => `- ${p.activity} (loudness ${p.loudness}/5): ${p.issue}. Standard quieter option: ${p.quieter}`),
    '',
    'Give 2-3 SPECIFIC, professional recommendations to reduce NEEDLESS noise on the CLIENT\'S',
    'systems for THIS exact situation — e.g. rate-limit, narrow the scope, prefer passive',
    'sources, spread requests over time, or infer the defensive stack from the responses seen',
    '(a 403/429/WAF-page spike means a WAF is active → slow down and reduce request volume).',
    'This is professional courtesy so we do not flood the client\'s SIEM, and it doubles as the',
    'DEFENDER\'S view of what is loud. It stays fully logged and attributable.',
    'DO NOT suggest evasion, anti-forensics, log/audit tampering, hiding the source, or any way',
    'to become undetectable — that is out of scope. Keep it to a few concrete sentences.',
  ].join('\n');
}

// Fire the advisor with an injected cheap-model runAgent ({system,messages}=>{text}).
// Returns { fired, text?, risk, actions }. Never throws.
export async function footprintAiAdvise(opsecJSON, { target, runAgent, lastActions = null } = {}) {
  const d = shouldAdvise(opsecJSON, lastActions);
  if (!d.fire || typeof runAgent !== 'function') return { fired: false, risk: d.risk, actions: d.actions };
  try {
    const r = await runAgent({
      system: 'You are a concise OPSEC advisor for an authorized penetration test. Transparency and professional noise-reduction only — never evasion or anti-forensics.',
      messages: [{ role: 'user', content: advisorPrompt(d.advisor, { target }) }],
    });
    return { fired: true, risk: d.risk, actions: d.actions, text: String((r && r.text) || '').trim() };
  } catch (e) { return { fired: false, risk: d.risk, actions: d.actions, error: String((e && e.message) || e) }; }
}
