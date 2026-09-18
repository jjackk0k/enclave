// VARVEL — enforced operational-stealth executor.
//
// RedAmon's "Stealth Mode" is PROMPT-LEVEL: it asks the LLM to pick -T1/-T2 nmap flags
// and go easy. That leaves quietness to the model's discretion. VARVEL ENFORCES it in
// code — a stealth profile sets concurrency, inter-request delay, and jitter, and our
// native tools pace every request through it. Quietness is a guarantee, not a hope.
//
// The pacer uses a SHARED emission clock: request STARTS are spaced ≥ delay (± jitter)
// apart as the *target* sees them, regardless of how many workers run concurrently. So
// `concurrency` only overlaps slow responses (latency hiding) — it never multiplies the
// target-visible rate into the burst shape a horizontal-scan detector keys on. A static,
// prompt-level competitor cannot express a global emission rate at all.
//
// This is LEGITIMATE authorized-engagement tradecraft: reduce your detection footprint
// against an active blue team (low-and-slow, spread over time). It is NOT evasion or
// anti-forensics — nothing here hides, tampers with, or deletes any record. Every request
// VARVEL makes is still in the Enclave's tamper-evident audit: quiet against the target,
// fully accountable to governance.

export const STEALTH_PROFILES = {
  loud: { label: 'loud', concurrency: 16, delayMs: 0, jitterMs: 0, note: 'fastest — authorized noisy sweeps where speed beats subtlety' },
  normal: { label: 'normal', concurrency: 8, delayMs: 40, jitterMs: 30, note: 'balanced default — gap ~10–70ms' },
  quiet: { label: 'quiet', concurrency: 3, delayMs: 300, jitterMs: 150, note: 'low-and-slow — gap ~150–450ms, reduce footprint vs an active blue team' },
  paranoid: { label: 'paranoid', concurrency: 1, delayMs: 900, jitterMs: 400, note: 'minimal footprint — one request in flight, gap ~500–1300ms' },
};

export function stealthProfile(name) {
  // An object profile is a custom one: label it 'custom' (not 'normal') so the report never
  // names a profile whose numbers it isn't actually running, unless the caller gave a label.
  if (name && typeof name === 'object') return { label: 'custom', ...STEALTH_PROFILES.normal, ...name };
  return STEALTH_PROFILES[name] || STEALTH_PROFILES.normal;
}

// Clamp concurrency to a finite integer ≥ 1 (rejects 0 / NaN / negative / Infinity).
function clampConcurrency(v) { const n = Math.floor(Number(v)); return Number.isFinite(n) && n >= 1 ? n : 1; }

// ---------- ghost-level traffic shaper ----------
// The GHOST shaper (2026-09-01, vs an ISP-level adversary): an operator-armed POLICY the
// shared pacer consults. It can only ever make governed traffic SLOWER/more uniform than
// the engagement profile — a floor, never an accelerator. Two knobs:
//   minDelayMs/jitterMs — a MINIMUM emission gap (minDelay + rand*jitter) the pacer's own
//     delay is floored at. This polices the timing pattern the operator's ISP observes on
//     the operator→first-hop flow.
//   padTo: 'mtu' — request headers carry an ADMITTED padding header (x-pad) sized toward
//     a ~1460-byte envelope, blunting coarse size-based flow features.
// THE HONEST CEILING, stated wherever this is reported: TRUE constant-rate padding (fixed
// inter-packet timing + fixed cell size, traffic-analysis-resistant) is IMPOSSIBLE at the
// app layer — it requires VPN-layer shaping (Mullvad's DAITA does exactly this, operator
// side). The shaper raises correlation cost; it does NOT defeat a national adversary's
// flow correlation, and nothing here may claim otherwise.
export const SHAPER_MTU_TARGET = 1460; // classic 1500-MTU payload budget — a coarse app-layer target

// normalizeShaperConfig(cfg) -> { minDelayMs, jitterMs, padTo } | null. Throws (LOUD) on
// malformed config — a shaper that silently mis-parses would be a claimed control that
// isn't running. An empty/null config is null: no shaper, never a pretend one.
export function normalizeShaperConfig(cfg) {
  if (cfg == null || cfg === false) return null;
  if (typeof cfg !== 'object' || Array.isArray(cfg)) throw new TypeError('ghost shaper must be an object {minDelayMs?, jitterMs?, padTo?} or null');
  const min = Number(cfg.minDelayMs) || 0;
  const jit = Number(cfg.jitterMs) || 0;
  if (!Number.isFinite(min) || min < 0) throw new TypeError('ghost shaper minDelayMs must be a finite number >= 0');
  if (!Number.isFinite(jit) || jit < 0) throw new TypeError('ghost shaper jitterMs must be a finite number >= 0');
  const padTo = cfg.padTo == null ? null : String(cfg.padTo);
  if (padTo !== null && padTo !== 'mtu') throw new TypeError("ghost shaper padTo must be null or 'mtu' — true constant-rate padding is NOT possible at the app layer (that is VPN-layer, e.g. Mullvad DAITA); refused, not approximated silently");
  if (!min && !jit && !padTo) return null;
  return { minDelayMs: min, jitterMs: jit, padTo };
}

// The shaper's floor gap for one emission: minDelayMs + rand*jitterMs. rand injectable.
export function shaperGap(cfg, rand = Math.random) {
  const c = normalizeShaperConfig(cfg);
  if (!c) return 0;
  return c.minDelayMs + Math.round(rand() * c.jitterMs);
}

// Padding length toward the MTU-ish envelope for padTo:'mtu'. baseEstimate = the caller's
// coarse guess of request-line+header bytes (default 300); capped at 4096. 0 when no padTo.
export function shaperPadLen(cfg, baseEstimate = 300) {
  const c = normalizeShaperConfig(cfg);
  if (!c || c.padTo !== 'mtu') return 0;
  return Math.max(0, Math.min(4096, SHAPER_MTU_TARGET - Math.max(0, Number(baseEstimate) || 0)));
}

// A pacer enforces a profile. `concurrency` bounds in-flight requests; `pace()` awaits so
// that request STARTS are globally spaced by delay ± jitter (shared clock — see header).
// `rand` and `now` are injectable for deterministic tests.
export function makePacer(profile, { rand = Math.random, now = Date.now, extraHeaders, maxWaitMs, shaper: shaperOpt } = {}) {
  const p = stealthProfile(profile);
  const concurrency = clampConcurrency(p.concurrency);
  const base = Math.max(0, Number(p.delayMs) || 0);
  let jit = Math.max(0, Number(p.jitterMs) || 0);
  let delay = base;                 // mutable so penalize() can widen it on target push-back
  let nextAt = 0;                   // ONE emission clock shared by every worker on this pacer
  // 2026-08-31 live-stall fix: a wedged tool that loses its watchdog race is NEVER
  // cancelled — it keeps pacing and drags the shared emission clock into the future
  // (bykea/tripcom froze on exactly this). maxWaitMs caps any single pace() sleep and
  // resyncs the clock; forward spacing is still enforced (nextAt = slot + gap).
  const mw = Number(maxWaitMs);
  const maxWait = Number.isFinite(mw) && mw > 0 ? mw : 120000;
  const persona = pickPersona(rand); // ONE realistic browser identity for the whole engagement
  // Ghost-level shaper (operator policy, engine/ghost.mjs arms it): the pacer is POLICED —
  // the emission gap is floored at the shaper's gap, and padTo:'mtu' adds admitted padding
  // to the request headers. It can only make traffic slower/more uniform, never faster.
  const shaper = normalizeShaperConfig(shaperOpt); // throws LOUD on malformed policy
  // Per-engagement attestation headers a program REQUIRES on all test traffic (e.g.
  // HackerOne's `X-Hackerone: <handle>`). Merged into every request this pacer headers —
  // declared on the pacer, so the report states exactly what was sent. Lowercased keys to
  // match the ghost scrub's canonical form; never an x-varvel*/UA override (scrub owns those).
  const extra = {};
  for (const [k, v] of Object.entries(extraHeaders && typeof extraHeaders === 'object' ? extraHeaders : {})) {
    const lk = String(k).toLowerCase();
    if (lk.startsWith('x-varvel') || lk === 'user-agent') continue;
    extra[lk] = String(v);
  }
  return {
    profile: p,
    concurrency,
    persona,
    maxWaitMs: maxWait, // the backlog ceiling (introspectable; tests assert the bound)
    shaper, // the ghost-level shaping policy this pacer is policed by (null = none)
    extraHeaders: Object.keys(extra).length ? { ...extra } : null,
    // Header set for target-visible requests: the engagement's shared browser persona,
    // plus any program-required attestation headers, plus the shaper's ADMITTED padding
    // header (x-pad — declared, never hidden; the honest app-layer approximation of size
    // shaping, NOT constant-rate padding).
    requestHeaders(opts) {
      const h = { ...personaHeaders(persona, opts), ...extra };
      if (shaper && shaper.padTo === 'mtu') {
        const n = shaperPadLen(shaper, (opts && opts.padBase) || 300);
        if (n > 0) h['x-pad'] = 'x'.repeat(n);
      }
      return h;
    },
    // The gap before the next emission: base ± jitter, floored at 0 — and floored AGAIN at
    // the ghost shaper's gap when one is armed (the shaper can slow, never speed up).
    nextDelay() {
      const g = Math.max(0, delay + Math.round(((rand() * 2) - 1) * jit));
      return shaper ? Math.max(g, shaperGap(shaper, rand)) : g;
    },
    // Reserve the next global slot, then await it. The read-modify-write of nextAt is
    // synchronous (no await between), so Node's single thread serializes it race-free.
    async pace() {
      const gap = this.nextDelay();
      const t = now();
      let slot = Math.max(t, nextAt);
      // Backlog clamp: without it, zombie (watchdog-race-losing) tools keep extending
      // nextAt and every later pace() sleeps the whole accumulated backlog — an
      // unwatched, unbounded await. Slot clamps to now+maxWait; the gap still spaces
      // the NEXT emission, so the target-visible cadence guarantee is preserved.
      if (slot - t > maxWait) slot = t + maxWait;
      nextAt = slot + gap;
      const wait = slot - t;
      if (wait > 0) await new Promise((r) => setTimeout(r, wait));
    },
    // Adaptive back-off: when the target pushes back (429/503/Retry-After), widen the gap.
    // This makes us QUIETER/gentler in response to a live signal — in-bounds tradecraft,
    // not evasion. Capped so a hostile Retry-After can't stall the engagement indefinitely.
    penalize(mult = 2, ms = 0) {
      const widened = Math.max(delay * (Number(mult) || 2), delay + (Number(ms) || 0));
      delay = Math.min(60_000, widened > 0 ? widened : 250); // from a 0-delay (loud) profile, back off to a sane floor
    },
    currentDelay() { return delay; },
  };
}

// Accept a profile name/object OR an already-built pacer, so one shared pacer can be
// threaded through a whole engagement (or a per-call profile used standalone).
export function asPacer(x, opts) {
  if (!x) return null;
  return typeof x.pace === 'function' ? x : makePacer(x, opts);
}

// Request realism — a per-ENGAGEMENT browser persona. Real traffic is browsers, and a tool
// that announces itself ("VARVEL-webscan", or RedAmon's nuclei/nmap defaults) signs every
// target log; a persona that ROTATES per request is just as loud (no human cycles browsers
// mid-session). So ONE consistent realistic identity is chosen per engagement and shared by
// every tool on the pacer. This is presentation realism for authorized traffic — the persona
// is recorded on the pacer (`.persona`) so the report can state exactly what was sent; it
// hides nothing from the Enclave's audit.
export const PERSONAS = [
  { id: 'chrome-win',  ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36', lang: 'en-US,en;q=0.9' },
  { id: 'firefox-win', ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0', lang: 'en-US,en;q=0.5' },
  { id: 'safari-mac',  ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15', lang: 'en-US,en;q=0.9' },
  { id: 'edge-win',    ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0', lang: 'en-US,en;q=0.9' },
];

// Pick one persona for an engagement. `rand` injectable for deterministic tests.
export function pickPersona(rand = Math.random) {
  return PERSONAS[Math.min(PERSONAS.length - 1, Math.floor(rand() * PERSONAS.length))];
}

// Realistic header set for a persona. `accept` is per-tool overridable (a crawler asks for
// HTML; a descriptor probe takes anything). No forged Referer — an invented chain of pages
// is a fabrication the target's logs can contradict, and VARVEL stays honest by design.
export function personaHeaders(persona, { accept } = {}) {
  const p = persona || PERSONAS[0];
  return {
    'user-agent': p.ua,
    accept: accept || 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'accept-language': p.lang,
    'accept-encoding': 'identity',
  };
}

// Rough wall-time (ms) of a paced sweep of `n` requests. With the shared clock, emissions
// are serialized, so it's ≈ n × delay (concurrency hides latency, not spacing).
export function estimateDuration(profile, n) {
  const per = Math.max(0, Number(stealthProfile(profile).delayMs) || 0);
  const count = Math.max(0, Number(n) || 0);
  return Number.isFinite(count) ? Math.round(count * per) : Infinity;
}
