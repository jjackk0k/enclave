// VARVEL — Deep Think: a structured strategic pre-step (RedAmon parity).
//
// Before the agent acts at a decisive moment, force it to reason: lay out at
// least TWO competing hypotheses (each with a one-line disambiguating probe),
// pick the strongest, and name the risks. This is the fuller counterpart to the
// auditor's `replanHint(tier>=2)` deep-think nudge — here as its own decide-WHEN
// + build-the-PROMPT module.
//
// Pure functions, no I/O, no LLM calls. This module decides WHEN a Deep Think is
// worthwhile and produces the PROMPT; the campaign makes the actual agent call
// and feeds the response back through `parseDeepThink` / `isNovel`.
//
// The reasoning it asks for is guidance only — authorized and in-scope. It grants
// no new capability; the Enclave's signed scope / HITL gate / audit still bind
// every real action underneath.

// Phases where entering is significant enough to reason first. Uses the phase
// ids from phases.mjs (recon, validate, exploit, postex, report); the discovery
// and impact-bearing phases (validate/exploit/postex) are the high-significance
// ones. 'post-ex' is accepted as an alias for robustness.
const HIGH_SIGNIFICANCE = new Set(['validate', 'exploit', 'postex', 'post-ex']);

const DEFAULT_STUCK_AT = 2; // fire once the deterministic no-growth streak reaches this
const DEFAULT_COOLDOWN = 3; // min iterations since the last Deep Think before another auto-fires

// ---------------------------------------------------------------------------
// Decide WHEN. Pure, deterministic, never throws.
//
//   state.phase          current/target phase id
//   state.stuck          consecutive no-growth phases (campaign.stuck)
//   state.transitioned   true when this call is a fresh phase transition
//   state.iterationsSince iterations since the last Deep Think (default: large)
//   state.request        explicit operator request (fires immediately)
//   state.lastText       last Deep Think's text — reserved for the caller's
//                        post-generation novelty gate (see isNovel); not used
//                        to gate the decision itself.
//
//   opts.stuckAt   stuck threshold (default 2)
//   opts.cooldown  min iterations since last Deep Think (default 3)
//
// Fires when a transition INTO a high-significance phase OR stuck >= stuckAt,
// AND the cooldown is satisfied. An explicit request fires immediately.
export function shouldDeepThink(state, opts) {
  try {
    const s = state || {};
    const o = opts || {};
    const stuckAt = Number(o.stuckAt ?? DEFAULT_STUCK_AT);
    const cooldown = Number(o.cooldown ?? DEFAULT_COOLDOWN);

    // Explicit operator ask is deliberate — honor it now, past the cooldown.
    if (s.request === true) return { fire: true, reason: 'explicit request' };

    const phase = String(s.phase ?? '').toLowerCase();
    const stuck = Number(s.stuck) || 0;
    const transitioned = s.transitioned === true;
    const rawSince = Number(s.iterationsSince);
    const iterationsSince = Number.isFinite(rawSince) ? rawSince : 99;

    const onTransition = transitioned && HIGH_SIGNIFICANCE.has(phase);
    const onStuck = stuck >= stuckAt;

    if (!onTransition && !onStuck) {
      return { fire: false, reason: 'no trigger: not a high-significance transition and not stuck' };
    }
    // Both triggers are rate-limited by the cooldown so Deep Think stays a
    // pre-step, not a per-iteration tax.
    if (iterationsSince < cooldown) {
      return { fire: false, reason: `cooldown: ${iterationsSince} < ${cooldown} iteration(s) since last deep-think` };
    }

    const reason = onStuck
      ? `stuck ${stuck} >= ${stuckAt} (consecutive no-growth phase(s))`
      : `transition into high-significance phase "${phase}"`;
    return { fire: true, reason };
  } catch {
    return { fire: false, reason: 'error (suppressed)' };
  }
}

// ---------------------------------------------------------------------------
// Build the PROMPT. Returns a string that instructs the agent to emit a short,
// labeled analysis (Situation / Competing hypotheses / Recommended approach /
// Risks) BEFORE acting, then proceed with the recommended approach.
export function deepThinkPrompt(args) {
  const a = args || {};
  const ph = a.phase ? String(a.phase) : 'this phase';
  const obj = a.objective ? String(a.objective).trim() : 'the current objective';
  const surf = a.surfaceSummary ? String(a.surfaceSummary).trim() : '';
  const stuck = Number(a.stuck) || 0;

  const surfLine = surf ? `\nWhat is known so far: ${surf}` : '';
  const stuckLine = stuck > 0
    ? `\nNo new progress for ${stuck} phase(s) in a row — treat "the approach is wrong" and "there is genuinely nothing here" as LIVE hypotheses, not just "try harder".`
    : '';

  return `[deep-think · ${ph}] Before you act, stop and reason strategically. This is an authorized, in-scope planning step for the objective:
"${obj}".${surfLine}${stuckLine}

Emit a SHORT structured analysis with exactly these labeled sections, then proceed:

**Situation** — 1-2 sentences: where you are and what you are trying to achieve right now.

**Competing hypotheses** — list at least TWO distinct, mutually-competing explanations or approaches for how to make progress. Number them. For EACH, add a one-line "probe:" — the single cheapest disambiguating check that would confirm or refute it. Do not commit yet; hold the alternatives side by side.

**Recommended approach** — pick the SINGLE strongest hypothesis and state in one line why it beats the others (which evidence or probe result tips it).

**Risks** — what could go wrong, what to avoid, and any action that would be noisy, destructive, or out of scope.

Keep the whole analysis concise — a few lines per section, not an essay. This is reasoning only and authorizes nothing new. Then immediately act on your Recommended approach.`;
}

// ---------------------------------------------------------------------------
// Parse the agent's Deep Think response (best-effort). Never throws.
// Returns { hypotheses: string[], approach, sections: { situation, risks } }.
// On unparseable input, returns { hypotheses: [], approach: '' }.
export function parseDeepThink(text) {
  try {
    const src = String(text ?? '');
    if (!src.trim()) return { hypotheses: [], approach: '' };

    const sec = splitSections(src);
    const hypotheses = sec.hypotheses ? extractItems(sec.hypotheses) : [];
    const approach = cleanBlock(sec.approach);
    const situation = cleanBlock(sec.situation);
    const risks = cleanBlock(sec.risks);

    // No recognizable structure at all -> treat as unparseable.
    if (!hypotheses.length && !approach && !situation && !risks) {
      return { hypotheses: [], approach: '' };
    }
    return { hypotheses, approach, sections: { situation, risks } };
  } catch {
    return { hypotheses: [], approach: '' };
  }
}

// Section header patterns. The label must be at the START of the line (after
// optional markdown heading hashes / bold markers), so numbered hypothesis lines
// or mid-sentence keywords are never mistaken for headers.
const SECTION_PATTERNS = [
  { key: 'situation', re: /^\**\s*situation\s*\**\s*[:\-–—]?\s*/i },
  { key: 'hypotheses', re: /^\**\s*(?:competing\s+)?hypothes[ei]s\s*\**\s*[:\-–—]?\s*/i },
  { key: 'approach', re: /^\**\s*(?:recommended\s+)?(?:approach|recommendation)\s*\**\s*[:\-–—]?\s*/i },
  { key: 'risks', re: /^\**\s*risks?\s*\**\s*[:\-–—]?\s*/i },
];

function matchHeader(raw) {
  const t = String(raw).replace(/^\s*#{1,6}\s*/, '').trim(); // drop markdown heading hashes
  if (!t) return null;
  for (const { key, re } of SECTION_PATTERNS) {
    const m = t.match(re);
    if (m) {
      const rest = t.slice(m[0].length).replace(/^\**\s*/, '').replace(/\**\s*$/, '').trim();
      return { key, rest };
    }
  }
  return null;
}

function splitSections(src) {
  const buf = {};
  let cur = null;
  for (const raw of String(src).split(/\r?\n/)) {
    const h = matchHeader(raw);
    if (h) {
      cur = h.key;
      if (!buf[cur]) buf[cur] = [];
      if (h.rest) buf[cur].push(h.rest);
      continue;
    }
    if (cur) buf[cur].push(raw);
  }
  const out = {};
  for (const k of Object.keys(buf)) out[k] = buf[k].join('\n').trim();
  return out;
}

// Pull hypotheses from numbered/bulleted lines; fall back to non-empty lines.
// Sub-lines that are only a "probe:" are dropped (they belong to a hypothesis,
// they are not one).
function extractItems(block) {
  const lines = String(block).split(/\r?\n/);
  const marked = [];
  for (const raw of lines) {
    const line = raw.trim();
    if (!line) continue;
    const m = line.match(/^(?:\(?\d+[.)]|[-*•–—])\s+(.*)$/);
    if (m && m[1].trim()) marked.push(cleanInline(m[1]));
  }
  const items = marked.length
    ? marked
    : lines.map((l) => cleanInline(l)).filter(Boolean);
  return items.filter((it) => it && !/^probe\b/i.test(it));
}

function cleanInline(s) {
  return String(s).replace(/[*`_]+/g, '').replace(/\s+/g, ' ').trim();
}

function cleanBlock(s) {
  if (!s) return '';
  return String(s)
    .split(/\r?\n/)
    .map((l) => l.replace(/[*`_]+/g, '').trim())
    .filter(Boolean)
    .join(' ')
    .trim();
}

// ---------------------------------------------------------------------------
// Novelty check: token-Jaccard over lowercased word sets. Returns FALSE when
// `text` is too similar to `priorText` (Jaccard >= threshold) so a caller can
// suppress a near-duplicate Deep Think; TRUE otherwise, or when priorText is
// empty (nothing to compare against). Never throws.
export function isNovel(text, priorText, threshold = 0.6) {
  try {
    const prior = String(priorText ?? '');
    if (!prior.trim()) return true;
    const a = tokenSet(text);
    const b = tokenSet(prior);
    const union = new Set([...a, ...b]).size;
    if (union === 0) return false; // both empty -> identical, not novel
    let inter = 0;
    for (const t of a) if (b.has(t)) inter++;
    const jaccard = inter / union;
    return jaccard < Number(threshold);
  } catch {
    return true;
  }
}

function tokenSet(s) {
  return new Set(String(s ?? '').toLowerCase().match(/[a-z0-9]+/g) || []);
}
