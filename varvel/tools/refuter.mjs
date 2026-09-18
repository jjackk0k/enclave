// VARVEL — refuter: the validator pass (XBOW's "validators", applied to reasoning).
//
// Spec: docs/builds/2026-09-18-spark-loop-upgrades.md §1. The loop verifies
// MECHANICALLY (does the marker replay?) but never asks a second brain to KILL the
// reasoning. This module is that second opinion: one call to a DIFFERENT brain config
// whose only job is refutation. Findings that survive refutation AND replay are the
// only ones worth the operator's click.
//
// Contract (the spec's, verbatim in spirit):
//   SYSTEM: you are the VARVEL validator. You do not propose. You refute.
//   INPUT:  the candidate finding, its evidence quotes, its check/expect pair, and the
//           raw evidence bundle.
//   OUTPUT: one fenced json block — { "verdict": "hold|refute", "why": "...",
//           "contradiction": "<quote from the bundle the finding misreads, or null>" }
//   RULES:  default to refute when the evidence does not directly support the claim;
//           a finding whose severity depends on an unquoted assumption is refuted;
//           refutation must cite the bundle — a vibe refutation is discarded, not obeyed.
//
// Semantics that keep the anti-hallucination doctrine intact (enforced by the CALLER
// in tools/huntloop.mjs):
//   - `refute` PARKS the candidate (ledger line with the refutation text); it is never
//     deleted, and it never becomes a report.
//   - The validator being unavailable leaves the finding UNVERIFIED — never promoted.
//   - The validator never sees the outbox and has no submission path (NEVER-SUBMITS
//     unaffected — this file talks ONLY to the brain lane through engine/brain-provider).
//   - Cost control: the caller validates only candidates that passed the intake gate,
//     capped at one refutation attempt.

import { callOpenAI } from '../engine/brain-provider.mjs';

export const VALIDATOR_SYSTEM = [
  'You are the VARVEL validator. You do not propose. You refute.',
  'You are given ONE candidate security finding (title, severity, evidence claim, and its check/expect pair) plus the raw evidence bundle that was actually gathered from the target.',
  'Your default verdict is REFUTE: any finding the bundle does not DIRECTLY support is refuted. A finding whose severity depends on an assumption the bundle does not show is refuted. A finding that misreads or overstates the bundle is refuted.',
  'Hold ONLY when the bundle itself directly supports the finding as written.',
  'A refutation MUST cite the bundle: put the exact span from the bundle that the finding misreads (or fails to contain) in "contradiction". A refutation that cites nothing checkable is worthless and will be discarded.',
  'Answer with ONE fenced json block and nothing else:',
  '```json',
  '{ "verdict": "hold|refute", "why": "<one tight paragraph>", "contradiction": "<exact quote from the bundle, or null>" }',
  '```',
].join('\n');

// Resolve the validator's brain config from env (+ optional explicit request fields).
// Deliberately SEPARATE from the author brain: self-review is not review (spec §0.3 —
// "validator: a different model than the author"). Returns null when unconfigured —
// the loop then runs legacy (un-refuted) and says so on its event stream.
//   VARVEL_REFUTER_BASE_URL   e.g. https://openrouter.ai/api/v1  (or a local lane)
//   VARVEL_REFUTER_MODEL      e.g. z-ai/glm-5.3-flash
//   VARVEL_REFUTER_API_KEY    the key itself (or VARVEL_REFUTER_API_KEY_ENV names one)
//   VARVEL_REFUTER_TIMEOUT_MS per-call ceiling (default 120000)
export function resolveRefuter({ env = process.env, request = null } = {}) {
  const baseUrl = (request && request.baseUrl) || env.VARVEL_REFUTER_BASE_URL || '';
  const model = (request && request.model) || env.VARVEL_REFUTER_MODEL || '';
  if (!baseUrl || !model) return null;
  const keyEnvName = (request && request.apiKeyEnv) || env.VARVEL_REFUTER_API_KEY_ENV || 'VARVEL_REFUTER_API_KEY';
  const key = (request && request.key) || (keyEnvName ? (env && env[keyEnvName]) || '' : '') || '';
  const timeoutMs = Number(env.VARVEL_REFUTER_TIMEOUT_MS) > 0 ? Number(env.VARVEL_REFUTER_TIMEOUT_MS) : 120000;
  return { baseUrl, model, key, timeoutMs };
}

const norm = (s) => String(s == null ? '' : s).toLowerCase().replace(/\s+/g, ' ').trim();

// The anti-vibe check (spec: "refutation must cite the bundle — a vibe refutation is
// discarded, not obeyed"). The cited span must literally appear in the bundle text
// (case/whitespace-normalized). Short or absent citations never hold.
export function citationHolds(quote, bundleText) {
  const q = norm(quote);
  if (q.length < 12) return false;
  return norm(bundleText).includes(q);
}

// Parse the validator's answer. STRICT: no fenced block, or a verdict token that is not
// exactly hold/refute, is UNAVAILABLE (the caller records unverified) — never guessed.
export function parseValidatorVerdict(text) {
  const m = /```(?:json)?\s*([\s\S]*?)```/.exec(String(text || ''));
  if (!m || !m[1].trim()) return { ok: false, reason: 'validator returned no parseable json block' };
  let j;
  try { j = JSON.parse(m[1]); } catch (e) { return { ok: false, reason: `validator json unparseable: ${(e && e.message) || e}` }; }
  const verdict = String(j.verdict || '').toLowerCase().trim();
  if (verdict !== 'hold' && verdict !== 'refute') return { ok: false, reason: `verdict token is not hold|refute: ${JSON.stringify(String(j.verdict || '')).slice(0, 60)}` };
  return { ok: true, verdict, why: String(j.why || '').slice(0, 2000), contradiction: j.contradiction == null ? null : String(j.contradiction).slice(0, 2000) };
}

// One refutation attempt. brain: { baseUrl, model, key?, timeoutMs? } OR an injected
// async ({ finding, evidence }) => verdict object (tests / a wired lane adapter).
// Returns:
//   { ok: true,  verdict: 'refute', why, contradiction }  — the caller PARKS the finding
//   { ok: true,  verdict: 'hold',   why }                 — the finding proceeds to the sandbox
//   { ok: false, reason }                                 — validator UNAVAILABLE (unverified, never promoted)
export async function refuteFinding({ finding, evidence, brain }) {
  const bundleText = typeof evidence === 'string' ? evidence : JSON.stringify(evidence ?? null);
  let res;
  if (typeof brain === 'function') {
    // Injected validator (tests / a platform adapter): it returns the parsed verdict
    // object directly. The citation gate below applies to THIS path too — the
    // anti-vibe rule is about the VERDICT, not the transport (a function refuter that
    // cites nothing checkable is discarded exactly like a chatty lane's would be).
    res = await brain({ finding, evidence });
    if (!res || typeof res !== 'object') return { ok: false, reason: 'validator returned no verdict object' };
  } else {
    if (!brain || !brain.baseUrl || !brain.model) return { ok: false, reason: 'validator not configured (no baseUrl/model)' };
    const user = [
    'CANDIDATE FINDING (to refute):',
    JSON.stringify({
      title: finding && finding.title,
      sev: finding && finding.sev,
      evidence: finding && finding.evidence,
      check: finding && finding.check,
      expect: finding && finding.expect,
    }, null, 1),
    '',
    'RAW EVIDENCE BUNDLE (the only ground truth — judge against THIS, not the claim):',
    bundleText && bundleText.length ? bundleText.slice(0, 60000) : '(the bundle is EMPTY — nothing was gathered; per your rules, a severity that rests on anything not shown here is refuted)',
    '',
    'One fenced json block: verdict hold|refute, why, contradiction (exact bundle quote for a refute).',
  ].join('\n');
    const r = await callOpenAI({
      baseUrl: brain.baseUrl,
      model: brain.model,
      key: brain.key || '',
      system: VALIDATOR_SYSTEM,
      messages: [{ role: 'user', content: user }],
      maxTokens: 2048,
      timeoutMs: brain.timeoutMs !== undefined ? brain.timeoutMs : 120000,
    });
    const text = (r.content || []).filter((b) => b && b.type === 'text').map((b) => b.text).join('\n');
    res = parseValidatorVerdict(text);
    if (!res.ok) return res;
  }
  // THE ANTI-VIBE GATE (both paths): a refute that cites nothing checkable is discarded,
  // not obeyed — the finding proceeds and the event stream says the validator was unavailable.
  if (res.verdict === 'refute') {
    const quote = res.contradiction || res.why || '';
    if (!citationHolds(quote, bundleText)) {
      return { ok: false, reason: `refutation DISCARDED — its citation is not in the bundle (a vibe refutation is not obeyed): ${String(quote).slice(0, 140)}` };
    }
  }
  return res;
}
