// VARVEL — captchaassist: the HUMAN-IN-THE-LOOP CAPTCHA HANDOFF rail.
//
// Signup automation (semrush today, any recipe-driven program tomorrow) hits
// image challenges — reCAPTCHA "select all images", hCaptcha, Cloudflare
// Turnstile — that we NEVER auto-solve and NEVER bypass. This module is the
// clean handoff: the pausable flow runner detects the challenge by
// iframe/selector/text signatures, leaves the HEADED Firefox window visible,
// writes a loud status file (.tmp/captcha-needed-<program>.json), and polls
// the page until the OPERATOR (Jack) solves it in the browser. On a verified
// solve the recipe resumes automatically; on the operator deadline (default
// 10 min) it closes cleanly with OPERATOR-TIMEOUT.
//
// HONESTY CONTRACT (pinned in test/captchaassist.test.mjs): a handoff is
// reported RESOLVED only when the challenge signature is gone AND at least one
// corroborating signal verifies the solve — URL changed since the handoff
// began, a configured success marker appears in the page text, or a submit
// control that was disabled at handoff time is re-enabled. A challenge that
// merely stops rendering (page error, redirect back, renderer crash) is NOT a
// solve: the runner keeps waiting and times out honestly. A probe failure is
// DETECTION-FAILED, never "no challenge".
//
// GOVERNANCE: all target traffic rides the ghost chain — the CLI builds its
// browser through acctfactory's playwrightDriverFactory (headless:false,
// persistent profile, socks5://10.64.0.1:1080, X-HackerOne: varvel). mail.tm
// is infrastructure (direct). Post-solve sessions are registered in
// tools/sessionbroker.mjs with a HARVESTED canary endpoint. Every function
// returns structured results and NEVER throws. Tests inject fake drivers,
// fake clocks, and a mock broker — no live network, no real browser.
//
// usage:
//   import { captchaHandoff, runHandoffFlow, listHandoffs } from './tools/captchaassist.mjs';
//   const handoff = captchaHandoff({ program: 'semrush', label: 'a' });
//   const r = await runHandoffFlow(recipe, { driver, mailtm, program: 'semrush', label: 'a', register });
// CLI:
//   node tools/captchaassist.mjs run --program semrush --label a --recipe recipes/semrush-signup.json
//   node tools/captchaassist.mjs status

import { readFileSync, writeFileSync, existsSync, mkdirSync, readdirSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';

const __dir = dirname(fileURLToPath(import.meta.url));
const REPO = join(__dir, '..');

export const CAPTCHA_CAPS = {
  operatorTimeoutMs: 600000,   // default operator deadline: 10 minutes
  maxTimeoutMs: 1800000,       // hard ceiling: 30 minutes
  pollMs: 3000,                // solve-signal poll cadence
  maxPollMs: 30000,
  maxSteps: 32,
  maxStepSleepMs: 30000,
  maxHints: 8,
  maxMailWaitMs: 300000,
};

// Status files live in .tmp/ by default; tests isolate via VARVEL_CAPTCHA_DIR
// or an explicit dir option.
const STATUS_DIR = () => process.env.VARVEL_CAPTCHA_DIR || join(REPO, '.tmp');

const realSleep = (ms) => new Promise((r) => setTimeout(r, ms));
const logTo = (onLog, obj) => { if (typeof onLog === 'function') { try { onLog(obj); } catch { /* observer never breaks the rail */ } } };

// ——— challenge signatures (detection is heuristic and says so) ———
// INERT vs INTERACTIVE: reCAPTCHA renders an `anchor` iframe (the "I'm not a
// robot" checkbox) on load on many pages — present but NOT a challenge. The
// actual image challenge is the `bframe` dialog, and only when VISIBLE.
// hCaptcha/Cloudflare iframes count interactively when visible. Text markers
// are limited to ACTIVE-challenge language ("select all images"…) — the
// checkbox label "i'm not a robot" is deliberately excluded (inert).
const RECAPTCHA_SRC_RE = /(google\.com\/recaptcha|recaptcha\.net|recaptcha\/(api2|enterprise))/i;
const ACTIVE_TEXT_RE = /select all (?:the )?(?:images|squares)|verify you are human|checking your browser|review the security of your connection/i;

// kept exported for reference/documentation of the signature families
export const CHALLENGE_SIGNATURES = {
  recaptcha: { iframeRe: RECAPTCHA_SRC_RE, bframeRe: /bframe/i, anchorRe: /anchor/i },
  hcaptcha: { iframeRe: /hcaptcha\.com/i },
  cloudflare: { iframeRe: /(challenges\.cloudflare\.com|cf-chl)/i, textRe: ACTIVE_TEXT_RE },
};

const DEFAULT_SUCCESS_RE = /check your (inbox|email)|verify your email|confirmation (email|link)|welcome|dashboard|you'?re (all set|signed up)/i;

// challengePageProbe — runs INSIDE the page (playwright page.evaluate). Must
// stay self-contained: no closures, no imports. opts.progressHints: hint
// strings — if a visible input matches one, the page has moved PAST the
// challenge to the next step (a solve/progress signal).
export function challengePageProbe(opts) {
  const hints = (opts && Array.isArray(opts.progressHints) ? opts.progressHints : []).slice(0, 8)
    .map((h) => String(h).replace(/["\\]/g, '')).filter(Boolean);
  const iframes = [...document.querySelectorAll('iframe')].map((f) => {
    let r = null; try { r = f.getBoundingClientRect(); } catch { r = null; }
    return { src: f.src || '', visible: !!(r && r.width > 10 && r.height > 10) };
  }).filter((f) => f.src);
  const bodySample = document.body ? String(document.body.innerText || '').slice(0, 4000) : '';
  // a visible submit/continue control that is currently DISABLED is a classic
  // "waiting for the captcha token" posture — its re-enablement is a solve signal.
  const ctrls = [...document.querySelectorAll('button, input[type=submit]')].filter((e) => !!(e.offsetWidth || e.offsetHeight));
  const disabledSubmit = ctrls.some((e) => e.disabled || e.getAttribute('aria-disabled') === 'true');
  const progressSignals = [];
  for (const h of hints) {
    try {
      const sel = `input[name*="${h}" i], input[id*="${h}" i], input[placeholder*="${h}" i], input[aria-label*="${h}" i]`;
      if ([...document.querySelectorAll(sel)].some((e) => !!(e.offsetWidth || e.offsetHeight))) progressSignals.push(h);
    } catch { /* a bad hint never breaks the probe */ }
  }
  return { url: location.href, iframes, bodySample, disabledSubmit, progressSignals };
}

// classifyProbe(raw, { successRe }) →
//   { found, interactive, vendor, signals, url, disabledSubmit, successMarker,
//     progress, progressSignals } | null
// found      = any challenge signature present (inert anchor iframe counts).
// interactive = a REAL challenge UI is up: visible reCAPTCHA bframe dialog,
//               visible hCaptcha/Cloudflare frame, or active-challenge text.
// null ONLY when raw itself is missing/malformed (a probe failure is honest,
// never read as "no challenge").
export function classifyProbe(raw, { successRe } = {}) {
  if (!raw || typeof raw !== 'object') return null;
  // legacy probes reported iframes as bare src strings — treat as visible
  const iframes = (Array.isArray(raw.iframes) ? raw.iframes : [])
    .map((f) => (typeof f === 'string' ? { src: f, visible: true } : f))
    .filter((f) => f && typeof f.src === 'string');
  const body = typeof raw.bodySample === 'string' ? raw.bodySample : '';
  const signals = [];
  let vendor = null;
  let interactive = false;

  const rc = iframes.filter((f) => RECAPTCHA_SRC_RE.test(f.src));
  if (rc.length) {
    signals.push('iframe:recaptcha');
    vendor = vendor || 'recaptcha';
    const bframe = rc.find((f) => /bframe/i.test(f.src));
    if (bframe && bframe.visible) { interactive = true; signals.push('iframe:recaptcha-bframe-visible'); }
  }
  const hc = iframes.filter((f) => /hcaptcha\.com/i.test(f.src));
  if (hc.length) {
    signals.push('iframe:hcaptcha');
    vendor = vendor || 'hcaptcha';
    if (hc.some((f) => f.visible)) { interactive = true; signals.push('iframe:hcaptcha-visible'); }
  }
  const cf = iframes.filter((f) => /(challenges\.cloudflare\.com|cf-chl)/i.test(f.src));
  if (cf.length) {
    signals.push('iframe:cloudflare');
    vendor = vendor || 'cloudflare';
    if (cf.some((f) => f.visible)) { interactive = true; signals.push('iframe:cloudflare-visible'); }
  }
  if (ACTIVE_TEXT_RE.test(body)) {
    signals.push('text:active-challenge');
    interactive = true;
    vendor = vendor || 'unknown';
  }
  let successRe_ = DEFAULT_SUCCESS_RE;
  if (typeof successRe === 'string') { try { successRe_ = new RegExp(successRe, 'i'); } catch { /* keep default */ } }
  else if (successRe instanceof RegExp) successRe_ = successRe;
  const progressSignals = Array.isArray(raw.progressSignals) ? raw.progressSignals : [];
  return {
    found: signals.length > 0,
    interactive,
    vendor,
    signals,
    url: typeof raw.url === 'string' ? raw.url : null,
    disabledSubmit: raw.disabledSubmit === true,
    successMarker: successRe_.test(body),
    progress: progressSignals.length > 0,
    progressSignals,
  };
}

// ——— the operator-facing status file ———
// .tmp/captcha-needed-<program>.json — { v, program, label, step, state,
// since, url, vendor, signals, resolvedAt?, signal?, timedOutAt? }.
// state: NEEDED → RESOLVED | OPERATOR-TIMEOUT. Never throws.
const SLUG = /^[a-z0-9][a-z0-9._-]{0,63}$/i;
const statusFileFor = (dir, program) => join(dir || STATUS_DIR(), `captcha-needed-${String(program).toLowerCase().replace(/[^a-z0-9._-]/g, '-')}.json`);

function writeHandoffStatus(rec, { dir } = {}) {
  try {
    const file = statusFileFor(dir, rec.program);
    mkdirSync(dirname(file), { recursive: true });
    const prev = existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')) : {};
    writeFileSync(file, JSON.stringify({ v: 1, ...prev, ...rec, updatedAt: new Date().toISOString() }, null, 1) + '\n');
    return file;
  } catch { return null; }
}

// listHandoffs({ dir }) → the operator's pending/resolved board. Never throws.
export function listHandoffs({ dir } = {}) {
  const d = dir || STATUS_DIR();
  let files = [];
  try { files = readdirSync(d).filter((f) => /^captcha-needed-.+\.json$/.test(f)); } catch { return { ok: true, dir: d, pending: [], resolved: [], timedOut: [] }; }
  const out = { ok: true, dir: d, pending: [], resolved: [], timedOut: [] };
  for (const f of files) {
    let rec = null;
    try { rec = JSON.parse(readFileSync(join(d, f), 'utf8')); } catch { continue; }
    if (!rec || rec.v !== 1) continue;
    const row = { program: rec.program, label: rec.label || null, step: rec.step, state: rec.state, since: rec.since, url: rec.url, vendor: rec.vendor || null, signal: rec.signal || null, file: join(d, f) };
    if (rec.state === 'NEEDED') out.pending.push(row);
    else if (rec.state === 'RESOLVED') out.resolved.push(row);
    else if (rec.state === 'OPERATOR-TIMEOUT') out.timedOut.push(row);
  }
  return out;
}

// ——— the handoff itself ———
// handoffOnce(driver, opts) → NEVER throws. States:
//   NO-CHALLENGE      {ok:true}  — no challenge signature at all; proceed.
//   INERT-CHALLENGE   {ok:true}  — signatures present but NOT interactive (e.g.
//                                  the reCAPTCHA anchor checkbox rendered on
//                                  load). An inert widget never pauses the flow.
//   RESOLVED          {ok:true}  — operator solve verified (signal named).
//   OPERATOR-TIMEOUT  {ok:false} — no verified solve before the deadline.
//   DETECTION-FAILED  {ok:false} — the probe produced nothing classifiable.
//   UNSUPPORTED       {ok:false} — the driver cannot detect challenges at all.
//
// GATING: a handoff pauses the flow ONLY on an INTERACTIVE challenge (visible
// reCAPTCHA bframe dialog, visible hCaptcha/Cloudflare frame, or active-
// challenge text). mode:'auto' (the per-step sweep) checks once; mode:
// 'explicit' (the recipe's captcha step, post-submit) allows a grace window
// (graceMs, default 15s) for the challenge dialog to render after a submit.
// Legacy drivers whose probe has no `interactive` field: found ⇒ interactive.
//
// SOLVE DETECTION (any one is sufficient — the operator may have solved the
// challenge OR driven the page forward manually):
//   'url-change'        — the page navigated away from the handoff URL
//   'progress-elements' — the recipe's next-step inputs appeared
//   'success-marker'    — interactive challenge gone AND success text present
//   'submit-re-enabled' — interactive challenge gone AND a disabled control re-enabled
// An interactive challenge that merely stops rendering with NO navigation,
// progress, or success signal is NEVER claimed as solved (the pin stands).
export async function handoffOnce(driver, {
  program = 'unknown', label = '', step = 'captcha',
  timeoutMs = CAPTCHA_CAPS.operatorTimeoutMs, pollMs = CAPTCHA_CAPS.pollMs,
  dir = null, onLog = null, now = null, sleepMs = null, successRe = null,
  announce = null, mode = 'auto', graceMs = 15000, progressHints = null,
} = {}) {
  const nowFn = typeof now === 'function' ? now : Date.now;
  const sleepFn = typeof sleepMs === 'function' ? sleepMs : realSleep;
  const say = typeof announce === 'function' ? announce : (line) => console.log(line);
  if (!driver || typeof driver.detectChallenge !== 'function') {
    return { ok: false, state: 'UNSUPPORTED', reason: 'the driver exposes no detectChallenge() probe — the handoff cannot run blind' };
  }
  const hints = Array.isArray(progressHints) ? progressHints : [];
  const detect = async () => { try { return await driver.detectChallenge({ successRe, progressHints: hints }); } catch { return null; } };
  const isInteractive = (c) => (c && c.interactive !== undefined ? c.interactive : !!(c && c.found)); // legacy probes: found ⇒ interactive

  const timeout = Math.min(Math.max(1000, Number(timeoutMs) || CAPTCHA_CAPS.operatorTimeoutMs), CAPTCHA_CAPS.maxTimeoutMs);
  const poll = Math.min(Math.max(1, Number(pollMs) || CAPTCHA_CAPS.pollMs), CAPTCHA_CAPS.maxPollMs);

  let first = await detect();
  if (!first) return { ok: false, state: 'DETECTION-FAILED', reason: 'the challenge probe returned nothing — the page state is UNKNOWN, not challenge-free' };

  // grace window (explicit captcha steps only, and only when SOME signature is
  // already present): the submit just fired against a page carrying an inert
  // widget — give a real challenge dialog a beat to render before declaring
  // the coast clear. A page with zero challenge presence proceeds immediately.
  if (!isInteractive(first) && first.found && mode === 'explicit' && graceMs > 0) {
    const graceDeadline = nowFn() + Math.min(graceMs, 60000);
    while (!isInteractive(first) && nowFn() < graceDeadline) {
      await sleepFn(poll);
      const g = await detect();
      if (g) first = g;
    }
  }

  if (!isInteractive(first)) {
    const state = first.found ? 'INERT-CHALLENGE' : 'NO-CHALLENGE';
    if (first.found) logTo(onLog, { type: 'captchaassist.inert', program, label, step, vendor: first.vendor, signals: first.signals, note: 'challenge signatures present but NOT interactive (inert widget on load) — flow proceeds' });
    return { ok: true, state };
  }

  const since = new Date(nowFn()).toISOString();
  writeHandoffStatus({ program, label, step, state: 'NEEDED', since, url: first.url, vendor: first.vendor, signals: first.signals }, { dir });
  say(`[CAPTCHA-HANDOFF] OPERATOR NEEDED — ${program}${label ? '/' + label : ''} step '${step}' hit an INTERACTIVE ${first.vendor || 'captcha'} challenge (${first.signals.join(', ')}). The headed Firefox window is waiting — solve it there. Deadline ${Math.round(timeout / 60000)} min. Status: ${statusFileFor(dir, program)}`);
  logTo(onLog, { type: 'captchaassist.needed', program, label, step, vendor: first.vendor, signals: first.signals, url: first.url, since });

  const startUrl = first.url;
  const deadline = nowFn() + timeout;
  let notedUnverified = false;
  while (nowFn() < deadline) {
    await sleepFn(poll);
    const cur = await detect();
    if (!cur) continue;                       // transient probe failure — keep waiting, decide nothing
    const urlChanged = !!(startUrl && cur.url && cur.url !== startUrl);
    const progressed = cur.progress === true;
    const interactiveGone = !isInteractive(cur);
    const reEnabled = first.disabledSubmit && !cur.disabledSubmit;
    // disjunctive solve signals: navigation or next-step progress count on
    // their own (the operator may have driven the page forward manually);
    // a silent clear still requires a success marker or a re-enabled control.
    const signal = urlChanged ? 'url-change'
      : progressed ? 'progress-elements'
      : (interactiveGone && cur.successMarker) ? 'success-marker'
      : (interactiveGone && reEnabled) ? 'submit-re-enabled'
      : null;
    if (signal) {
      writeHandoffStatus({ program, label, step, state: 'RESOLVED', since, url: cur.url, signal, resolvedAt: new Date(nowFn()).toISOString() }, { dir });
      say(`[CAPTCHA-HANDOFF] RESOLVED — ${program}${label ? '/' + label : ''} step '${step}' (signal: ${signal}). Resuming the recipe.`);
      logTo(onLog, { type: 'captchaassist.resolved', program, label, step, signal, url: cur.url });
      return { ok: true, state: 'RESOLVED', signal, waitedMs: nowFn() - Date.parse(since) };
    }
    if (interactiveGone && !notedUnverified) {
      notedUnverified = true;
      logTo(onLog, { type: 'captchaassist.unverified-clear', program, label, step, reason: 'challenge UI cleared but no corroborating signal (url unchanged, no progress elements, no success marker, submit still disabled) — NOT claiming a solve' });
    }
  }
  writeHandoffStatus({ program, label, step, state: 'OPERATOR-TIMEOUT', since, url: startUrl, timedOutAt: new Date(nowFn()).toISOString() }, { dir });
  say(`[CAPTCHA-HANDOFF] OPERATOR-TIMEOUT — ${program}${label ? '/' + label : ''} step '${step}': no verified solve within ${Math.round(timeout / 60000)} min. Closing cleanly; re-run to retry.`);
  logTo(onLog, { type: 'captchaassist.timeout', program, label, step, timeoutMs: timeout });
  return { ok: false, state: 'OPERATOR-TIMEOUT', reason: `no verified operator solve within ${timeout}ms — the session was NOT harvested and nothing was claimed` };
}

// captchaHandoff(defaults) → (driver, stepCtx) => handoffOnce(driver, merged)
// The injectable acctfactory recipe primitive: provisionAccount calls the
// returned function as handoff(driver, { step }) after the signup submit.
export function captchaHandoff(defaults = {}) {
  return (driver, stepCtx = {}) => {
    const merged = { ...defaults };
    for (const [k, v] of Object.entries(stepCtx)) if (v !== undefined) merged[k] = v;
    return handoffOnce(driver, merged);
  };
}

// ——— the pausable flow recipe (declarative — new programs are config) ———
const asHints = (x) => (Array.isArray(x) ? x : []).filter((h) => typeof h === 'string' && h).slice(0, CAPTCHA_CAPS.maxHints);

// sanitizeFlowRecipe(x) → normalized recipe or null. Never throws.
// steps: goto | fill | click | sleep | captcha | waitMail | verify | screenshot.
export function sanitizeFlowRecipe(x) {
  if (!x || typeof x !== 'object') return null;
  if (!Array.isArray(x.steps) || !x.steps.length || x.steps.length > CAPTCHA_CAPS.maxSteps) return null;
  const steps = [];
  for (const s of x.steps) {
    if (!s || typeof s !== 'object') return null;
    if (typeof s.goto === 'string' && /^https?:\/\//i.test(s.goto)) { steps.push({ op: 'goto', url: s.goto }); continue; }
    if (s.fill && typeof s.fill === 'object') {
      const f = s.fill;
      const hints = asHints(f.hints);
      if (!hints.length) return null;
      const from = f.from === 'email' || f.from === 'password' ? f.from : (typeof f.value === 'string' ? 'literal' : null);
      if (!from) return null;
      steps.push({ op: 'fill', hints, from, value: from === 'literal' ? f.value : null, optional: f.optional === true });
      continue;
    }
    if (s.click && typeof s.click === 'object') {
      const texts = Array.isArray(s.click.text) ? s.click.text.filter((t) => typeof t === 'string') : (typeof s.click.text === 'string' ? [s.click.text] : []);
      if (!texts.length) return null;
      steps.push({ op: 'click', text: texts, optional: s.click.optional === true });
      continue;
    }
    if (Number.isFinite(s.sleep)) { steps.push({ op: 'sleep', ms: Math.min(Math.max(0, s.sleep | 0), CAPTCHA_CAPS.maxStepSleepMs) }); continue; }
    if (s.captcha === 'handoff' || (s.captcha && typeof s.captcha === 'object' && s.captcha.mode === 'handoff')) {
      const c = typeof s.captcha === 'object' ? s.captcha : {};
      steps.push({ op: 'captcha', timeoutMs: Number.isFinite(c.timeoutMs) ? c.timeoutMs : null, pollMs: Number.isFinite(c.pollMs) ? c.pollMs : null, graceMs: Number.isFinite(c.graceMs) ? c.graceMs : null, progressHints: asHints(c.progressHints) });
      continue;
    }
    if (s.waitMail && typeof s.waitMail === 'object' && typeof s.waitMail.pattern === 'string') {
      try { new RegExp(s.waitMail.pattern); } catch { return null; }
      steps.push({ op: 'waitMail', pattern: s.waitMail.pattern, maxMs: Math.min(Number.isFinite(s.waitMail.maxMs) ? s.waitMail.maxMs : CAPTCHA_CAPS.maxMailWaitMs, CAPTCHA_CAPS.maxMailWaitMs), gotoOnMatch: s.waitMail.gotoOnMatch !== false });
      continue;
    }
    if (s.verify && typeof s.verify === 'object' && typeof s.verify.url === 'string' && /^https?:\/\//i.test(s.verify.url)) {
      steps.push({ op: 'verify', url: s.verify.url, bodyIncludes: typeof s.verify.bodyIncludes === 'string' ? s.verify.bodyIncludes : null, urlDenyRe: typeof s.verify.urlDenyRe === 'string' ? s.verify.urlDenyRe : null });
      continue;
    }
    if (typeof s.screenshot === 'string' && s.screenshot) { steps.push({ op: 'screenshot', tag: s.screenshot.slice(0, 40) }); continue; }
    return null; // unknown step — reject the whole recipe honestly
  }
  const scIn = x.sessionCapture && typeof x.sessionCapture === 'object' ? x.sessionCapture : {};
  const cnIn = x.canary && typeof x.canary === 'object' ? x.canary : null;
  return {
    program: typeof x.program === 'string' && SLUG.test(x.program) ? x.program.toLowerCase() : null,
    inbox: x.inbox === 'mailtm' ? 'mailtm' : null,
    autoHandoff: x.autoHandoff !== false, // detection sweeps after EVERY step by default
    steps,
    sessionCapture: {
      cookieDomains: Array.isArray(scIn.cookieDomains) ? scIn.cookieDomains.filter((d) => typeof d === 'string').slice(0, 8) : [],
      bearerFrom: typeof scIn.bearerFrom === 'string' ? scIn.bearerFrom : null,
    },
    canary: cnIn && typeof cnIn.url === 'string' && /^https?:\/\//i.test(cnIn.url) ? {
      url: cnIn.url,
      method: typeof cnIn.method === 'string' ? cnIn.method : 'GET',
      auth: cnIn.auth === 'bearer' ? 'bearer' : 'cookie',
      expectStatus: Array.isArray(cnIn.expectStatus) ? cnIn.expectStatus : [200],
      denyStatus: Array.isArray(cnIn.denyStatus) ? cnIn.denyStatus : [401, 403],
      denyBodyRe: typeof cnIn.denyBodyRe === 'string' ? cnIn.denyBodyRe : null,
      note: typeof cnIn.note === 'string' ? cnIn.note : null,
    } : null,
  };
}

// ——— runHandoffFlow: the pausable runner ———
// runHandoffFlow(recipeIn, { program, label, driver, mailtm, inbox, email,
//   password, dir, now, sleepMs, onLog, handoff, register, reloginCommand,
//   resultPath, successRe })
// → { ok, program, label, account?, steps, handoffs, registered, step?, error? }
// NEVER throws. ok requires: every step landed, every handoff verified, the
// verify oracle (when present) passed, and session material was captured.
// register() (sessionbroker.registerSession shape) runs ONLY on a verified ok.
export async function runHandoffFlow(recipeIn, {
  program = null, label = 'a', driver, mailtm = null, inbox = null,
  email = null, password = null, dir = null, now = null, sleepMs = null,
  onLog = null, handoff = null, register = null, reloginCommand = null,
  resultPath = null, successRe = null, timeoutMs = null, pollMs = null,
  announce = null,
} = {}) {
  const steps = [];
  const handoffs = [];
  const fail = (step, error, extra = {}) => ({ ok: false, program: prog, label, step, error, steps, handoffs, ...extra });
  const recipe = sanitizeFlowRecipe(recipeIn);
  if (!recipe) return { ok: false, program: String(program || 'unknown'), label, step: 'validate', error: 'recipe rejected by sanitizeFlowRecipe (need 1..' + CAPTCHA_CAPS.maxSteps + ' known steps)', steps, handoffs };
  const prog = String(program || recipe.program || 'unknown').toLowerCase();
  if (!driver || typeof driver.goto !== 'function') return fail('validate', 'a browser driver implementing the driver interface is required');
  // CYCLE-BREAK (observed live 2026-08-31): the playwright driver's default
  // detectChallenge dynamically imports THIS module. When captchaassist.mjs is
  // the CLI entry, its top level is still awaiting this very flow — the import
  // can never resolve and the first post-goto sweep deadlocks forever. Rebind
  // detection against the raw page handle with this module's own functions.
  if (driver._page && typeof driver._page.evaluate === 'function') {
    driver.detectChallenge = async (opts = {}) => {
      let raw = null;
      try { raw = await driver._page.evaluate(challengePageProbe, { progressHints: (opts && opts.progressHints) || [] }); } catch { return null; }
      return classifyProbe(raw, opts);
    };
  }
  const hf = handoff || captchaHandoff({ program: prog, label, dir, onLog, now, sleepMs, successRe, announce, timeoutMs: timeoutMs || undefined, pollMs: pollMs || undefined });
  const sleepFn = typeof sleepMs === 'function' ? sleepMs : realSleep;
  const mailStart = Date.now();

  try {
    // ——— inbox (infrastructure, not target traffic) ———
    let box = inbox;
    if (recipe.inbox === 'mailtm' && !box) {
      if (!mailtm || typeof mailtm.createAccount !== 'function') return fail('inbox', 'recipe wants a mail.tm inbox but no MailTmClient was provided');
      logTo(onLog, { type: 'captchaassist.inbox-start', program: prog, label, at: new Date().toISOString() });
      box = await mailtm.createAccount(`${prog}-${label}`);
      if (!box) {        // never a bare "creation failed" — surface the client's lastError (op + HTTP status + body)
        const e = mailtm.lastError;
        return fail('inbox', 'mail.tm account creation failed' + (e
          ? ` (${e.op} → ${e.status == null ? 'transport failure' : 'HTTP ' + e.status}${e.reason ? ': ' + e.reason : ''}${e.bodySnippet ? ': ' + String(e.bodySnippet).slice(0, 120) : ''}${e.attempt ? `, attempt ${e.attempt}` : ''})`
          : ''));
      }
      steps.push({ step: 'inbox', ok: true, email: box.address });
    }
    const ctxEmail = email || (box && box.address) || null;
    const ctxPassword = password || ('Vv!' + randomBytes(9).toString('base64url') + 'xZ9');
    let lastMailMatch = null;

    // progress hints for solve-detection: the inputs the NEXT step expects.
    // If they appear, the page moved past the challenge — that IS the solve.
    const deriveHints = (ns) => {
      if (!ns) return [];
      if (ns.op === 'fill') return ns.hints;
      if (ns.op === 'waitMail') return ['code', 'otp', 'verification'];
      return [];
    };
    // run one handoff sweep; records and fails the flow on a timeout.
    // mode 'auto' (per-step sweep): hands off ONLY on an interactive challenge,
    // checked once. mode 'explicit' (the recipe's captcha step): short grace
    // window for a post-submit challenge dialog to render.
    const sweep = async (stepName, captchaStep = null, nextStep = null) => {
      const h = await hf(driver, {
        step: stepName,
        mode: captchaStep ? 'explicit' : 'auto',
        timeoutMs: captchaStep && captchaStep.timeoutMs ? captchaStep.timeoutMs : undefined,
        pollMs: captchaStep && captchaStep.pollMs ? captchaStep.pollMs : undefined,
        graceMs: captchaStep && captchaStep.graceMs ? captchaStep.graceMs : undefined,
        progressHints: captchaStep && captchaStep.progressHints && captchaStep.progressHints.length ? captchaStep.progressHints : deriveHints(nextStep),
      });
      handoffs.push({ step: stepName, ...h });
      logTo(onLog, { type: 'captchaassist.sweep', program: prog, label, step: stepName, state: h.state, signal: h.signal || null });
      return h;
    };

    let verified = null; // the verify oracle's verdict (null = recipe has none)
    for (let i = 0; i < recipe.steps.length; i++) {
      const s = recipe.steps[i];
      const name = `${i}:${s.op}`;
      logTo(onLog, { type: 'captchaassist.step', program: prog, label, step: name, at: new Date().toISOString() });
      if (s.op === 'goto') {
        const landed = await driver.goto(s.url);
        if (!landed || landed.ok === false) return fail(name, 'goto did not load: ' + s.url, { partial: { email: ctxEmail } });
      } else if (s.op === 'fill') {
        const value = s.from === 'email' ? ctxEmail : s.from === 'password' ? ctxPassword : s.value;
        if (value == null) return fail(name, `fill step needs '${s.from}' but no value is in context`, {});
        const okFill = await driver.fillByHints(s.hints, value);
        if (!okFill && !s.optional) return fail(name, 'fill found no input (hints: ' + s.hints.join(',') + ')', { partial: { email: ctxEmail } });
        steps.push({ step: name, ok: !!okFill });
      } else if (s.op === 'click') {
        const okClick = await driver.clickByText(s.text);
        if (!okClick && !s.optional) return fail(name, 'click found no control (' + s.text.join('/') + ')', { partial: { email: ctxEmail } });
        steps.push({ step: name, ok: !!okClick });
      } else if (s.op === 'sleep') {
        await sleepFn(s.ms);
      } else if (s.op === 'captcha') {
        const h = await sweep(name, s, recipe.steps[i + 1]);
        if (!h.ok) return fail('captcha', `${h.state}: ${h.reason || 'operator handoff did not verify'}`, { partial: { email: ctxEmail } });
        steps.push({ step: name, ok: true, state: h.state, signal: h.signal || null });
        continue; // the explicit sweep already ran — skip the auto sweep for this step
      } else if (s.op === 'waitMail') {
        if (!box || !mailtm) return fail(name, 'waitMail needs a mail.tm inbox (recipe.inbox or an injected inbox)');
        const re = new RegExp(s.pattern, 'i');
        const got = await mailtm.waitForMatch({ token: box.token, notBefore: mailStart - 60000, pattern: re, maxMs: s.maxMs });
        if (!got) return fail(name, 'no matching mail arrived before the deadline', { partial: { email: ctxEmail } });
        lastMailMatch = got.match;
        steps.push({ step: name, ok: true, subject: got.subject || null });
        if (s.gotoOnMatch && /^https?:\/\//i.test(got.match)) {
          const nav = await driver.goto(got.match);
          if (!nav || nav.ok === false) return fail(name, 'the mailed link did not load', { partial: { email: ctxEmail } });
        }
      } else if (s.op === 'verify') {
        const nav = await driver.goto(s.url);
        if (!nav || nav.ok === false) return fail(name, 'verify endpoint did not load: ' + s.url, { partial: { email: ctxEmail } });
        const landedUrl = typeof driver.currentUrl === 'function' ? driver.currentUrl() : (nav.url || null);
        if (s.urlDenyRe && landedUrl && new RegExp(s.urlDenyRe, 'i').test(landedUrl)) {
          verified = { ok: false, reason: `verify landed on '${landedUrl}' which matches the deny pattern /${s.urlDenyRe}/ — the session is NOT authenticated` };
        } else if (s.bodyIncludes) {
          const needle = s.bodyIncludes === '$email' ? String(ctxEmail || '') : s.bodyIncludes;
          let body = typeof driver.bodyText === 'function' ? await driver.bodyText() : null;
          if (body == null && typeof driver.findText === 'function') {
            const esc = needle.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            const found = await driver.findText(['body', 'html', 'main'], new RegExp('(' + esc + ')', 'i'));
            body = found ? needle : '';
          }
          if (body == null) return fail(name, 'the driver can neither read body text nor findText — the verify oracle cannot run blind', { partial: { email: ctxEmail } });
          verified = String(body).toLowerCase().includes(needle.toLowerCase())
            ? { ok: true, url: landedUrl, matched: needle === ctxEmail ? '$email' : needle }
            : { ok: false, reason: `verify page body does not contain '${needle === ctxEmail ? '$email' : needle}' — not authenticated as the provisioned identity` };
        } else {
          verified = { ok: true, url: landedUrl };
        }
        steps.push({ step: name, ok: verified.ok, ...(verified.ok ? { url: verified.url } : { reason: verified.reason }) });
        if (!verified.ok) return fail('verify', verified.reason, { partial: { email: ctxEmail } });
      } else if (s.op === 'screenshot') {
        if (typeof driver.screenshot === 'function') await driver.screenshot(`${prog}-${label}-${s.tag}`);
      }
      // ——— auto handoff sweep after every step — INTERACTIVE challenges only;
      // an inert anchor iframe on load never pauses the flow. (An exotic
      // challenge that slips the signatures still stalls the NEXT step, which
      // fails honestly by name.) ———
      if (recipe.autoHandoff && s.op !== 'sleep' && s.op !== 'screenshot') {
        const h = await sweep(name, null, recipe.steps[i + 1]);
        if (!h.ok) return fail('captcha', `${h.state} after step '${name}': ${h.reason || 'operator handoff did not verify'}`, { partial: { email: ctxEmail } });
        if (h.state !== 'NO-CHALLENGE' && h.state !== 'INERT-CHALLENGE') steps.push({ step: name + ':handoff', ok: true, state: h.state, signal: h.signal || null });
      }
    }

    // ——— session harvest — the oracle contract: no session, no account ———
    const cookies = (typeof driver.cookies === 'function' ? await driver.cookies(recipe.sessionCapture.cookieDomains) : []) || [];
    let bearer = null;
    if (recipe.sessionCapture.bearerFrom && typeof driver.readStorage === 'function') {
      const m = recipe.sessionCapture.bearerFrom.match(/^(localStorage|sessionStorage):(.+)$/);
      if (m) bearer = await driver.readStorage(m[1], m[2]);
    }
    if (!cookies.length && !bearer) {
      return fail('capture', 'post-solve session harvest is empty — no cookies, no bearer; the flow may have completed but there is NO session to broker', { partial: { email: ctxEmail, verified } });
    }
    const account = {
      label, email: ctxEmail,
      password: ctxPassword,
      cookies: cookies.map((c) => ({ name: c.name, value: c.value, domain: c.domain })),
      bearer,
      finalUrl: typeof driver.currentUrl === 'function' ? driver.currentUrl() : null,
      provisionedAt: new Date().toISOString(),
    };
    steps.push({ step: 'capture', ok: true, cookies: account.cookies.length, bearer: !!bearer });

    // ——— broker registration (only on a verified flow; a canary is required) ———
    let registered = false, registrationError = null;
    if (typeof register === 'function' && recipe.canary) {
      const reg = register({
        program: prog, label,
        session: { cookies: account.cookies, headers: bearer ? { authorization: 'Bearer ' + bearer } : null },
        canary: {
          method: recipe.canary.method, url: recipe.canary.url, auth: recipe.canary.auth,
          expectStatus: recipe.canary.expectStatus, denyStatus: recipe.canary.denyStatus,
          denyBodyRe: recipe.canary.denyBodyRe,
          harvestedFrom: `captchaassist flow ${prog}/${label} (${verified && verified.ok ? 'verify oracle at ' + recipe.steps.find((s) => s.op === 'verify').url : 'recipe-declared'})`,
          note: recipe.canary.note,
        },
        relogin: reloginCommand ? { kind: 'script', command: reloginCommand, resultPath: resultPath || `.tmp/${prog}-signup-${label}-result.json`, note: 'headed Firefox signup through the ghost chain; PAUSES for the operator on any captcha challenge — we never auto-solve' } : { kind: 'manual', note: 're-run the captchaassist recipe by hand; it pauses for the operator on challenges' },
        notes: `provisioned by tools/captchaassist.mjs (${ctxEmail || 'email unknown'})`,
      }, { replace: true });
      registered = !!(reg && reg.ok);
      if (!registered) registrationError = (reg && (reg.reason || reg.error)) || 'register returned no result';
      logTo(onLog, { type: 'captchaassist.registered', program: prog, label, ok: registered, error: registrationError });
    }
    logTo(onLog, { type: 'captchaassist.provisioned', program: prog, label, email: ctxEmail, cookies: account.cookies.length, bearer: !!bearer, registered });
    return { ok: true, program: prog, label, account, steps, handoffs, verified, registered, registrationError };
  } catch (e) {
    return fail('exception', String((e && e.message) || e));
  }
}

// ——— the CLI's recipe loader (exported so tests drive the EXACT CLI path) ———
// Reads a recipe file, parses JSON, sanitizes the RAW shape ONCE.
// runHandoffFlow sanitizes internally — callers must hand it the RAW recipe,
// never the normalized one (normalized steps use {op:…} keys the raw parser
// rightly rejects; sanitizeFlowRecipe is deliberately NOT idempotent).
// loadFlowRecipe(path) → { ok, raw, recipe, error } — never throws.
export function loadFlowRecipe(recipePath) {
  let raw = null;
  try { raw = JSON.parse(readFileSync(resolve(REPO, recipePath), 'utf8')); }
  catch (e) { return { ok: false, raw: null, recipe: null, error: 'recipe unreadable: ' + String((e && e.message) || e) }; }
  const recipe = sanitizeFlowRecipe(raw);
  if (!recipe) return { ok: false, raw: null, recipe: null, error: 'recipe rejected by sanitizeFlowRecipe' };
  return { ok: true, raw, recipe, error: null };
}

// applyOperatorTimeout(rawRecipe, timeoutMs) — the CLI's --timeout becomes the
// default deadline for every explicit captcha step that doesn't set its own.
// Mutates the RAW recipe shape (string 'handoff' → {mode, timeoutMs}).
export function applyOperatorTimeout(rawRecipe, timeoutMs) {
  if (!(Number(timeoutMs) > 0) || !rawRecipe || !Array.isArray(rawRecipe.steps)) return rawRecipe;
  for (const s of rawRecipe.steps) {
    if (!s || typeof s !== 'object' || s.captcha == null) continue;
    if (typeof s.captcha === 'string') s.captcha = { mode: s.captcha, timeoutMs };
    else if (typeof s.captcha === 'object' && !Number.isFinite(s.captcha.timeoutMs)) s.captcha.timeoutMs = timeoutMs;
  }
  return rawRecipe;
}

// ——— CLI ———
//   node tools/captchaassist.mjs run --program semrush --label a --recipe recipes/semrush-signup.json [--email x] [--password y] [--timeout 600000]
//   node tools/captchaassist.mjs status
const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) {
  const args = process.argv.slice(2);
  const cmd = args[0];
  const opt = (name) => { const i = args.indexOf('--' + name); return i >= 0 ? args[i + 1] : null; };
  const out = (o) => console.log(JSON.stringify(o, null, 1));

  if (cmd === 'status') {
    const r = listHandoffs({ dir: opt('dir') || undefined });
    out(r);
    process.exit(r.pending.length ? 2 : 0);
  }

  if (cmd === 'run') {
    const program = opt('program'), label = opt('label') || 'a', recipePath = opt('recipe');
    if (!program || !recipePath) { console.error('usage: captchaassist.mjs run --program <p> --label <l> --recipe <path> [--email x] [--password y] [--timeout ms] [--inbox addr --inbox-pass pw]'); process.exit(1); }
    const loaded = loadFlowRecipe(recipePath);
    if (!loaded.ok) { console.error(loaded.error); process.exit(1); }
    const { raw: recipeRaw, recipe } = loaded;

    const { MailTmClient, playwrightDriverFactory, curlJsonTransport } = await import('./acctfactory.mjs');
    const { registerSession } = await import('./sessionbroker.mjs');
    const { execFileSync } = await import('node:child_process');

    const profileDir = join(REPO, '.tmp', `ff-${program}-${label}`);
    mkdirSync(profileDir, { recursive: true });
    let driver = null;
    try {
      driver = await playwrightDriverFactory({
        profileDir,
        proxy: process.env.VARVEL_BROWSER_PROXY || 'socks5://10.64.0.1:1080',
        headless: false, // the operator must SEE the window — never headless on the handoff rail
        extraHTTPHeaders: { 'X-HackerOne': 'varvel' },
        onLog: (o) => console.error(JSON.stringify(o)), // lock-cleanup / reaper / quarantine events belong in the trail
      });
    } catch (e) {
      console.error('[captchaassist] BROWSER-LAUNCH-FAILED: ' + String((e && e.message) || e).slice(0, 300));
      console.error('[captchaassist] the profile ' + profileDir + ' may be held by a leftover firefox.exe — close it and re-fire (the rail reaps exact-profile holders pre-launch, but an unkillable one is reported, never forced past)');
      process.exit(3);
    }
    // mail.tm throttles Node's TLS fingerprint on POST /accounts (bug #2 live
    // evidence); curl rides clean. Fall back to the node transport with a loud
    // note if curl is absent — never silently.
    let mailtm = null;
    if (recipe.inbox === 'mailtm') {
      let haveCurl = false;
      try { execFileSync('curl', ['--version'], { stdio: 'pipe', timeout: 5000 }); haveCurl = true; } catch { /* no curl */ }
      if (haveCurl) {
        mailtm = new MailTmClient({ transport: curlJsonTransport() });
        console.error(JSON.stringify({ type: 'captchaassist.mailtm-transport', transport: 'curl' }));
      } else {
        mailtm = new MailTmClient({});
        console.error(JSON.stringify({ type: 'captchaassist.mailtm-transport', transport: 'node', warning: 'curl not found — mail.tm may fingerprint-throttle account creation from this stack' }));
      }
    }
    const reloginCommand = `node tools/captchaassist.mjs run --program ${program} --label ${label} --recipe ${recipePath}`;
    const resultPath = `.tmp/${program}-signup-${label}-result.json`;

    // ——— pre-provisioned inbox (skips the flaky account-creation leg entirely) ———
    // --inbox <address> --inbox-pass <password>: only a token call is needed —
    // creation is the fingerprint-throttled step, polling is not.
    let prebox = null;
    const inboxAddr = opt('inbox'), inboxPass = opt('inbox-pass');
    if (inboxAddr || inboxPass) {
      if (!inboxAddr || !inboxPass) { console.error('--inbox and --inbox-pass come as a pair'); process.exit(1); }
      if (!mailtm) mailtm = new MailTmClient({ transport: curlJsonTransport() });
      const token = await mailtm.token(inboxAddr, inboxPass);
      if (!token) {
        const e = mailtm.lastError;
        console.error('[captchaassist] pre-provisioned inbox token failed' + (e ? ` (${e.op} → ${e.status == null ? 'transport failure' : 'HTTP ' + e.status})` : ''));
        process.exit(3);
      }
      prebox = { address: inboxAddr, password: inboxPass, token };
      console.error(JSON.stringify({ type: 'captchaassist.inbox-preprovisioned', address: inboxAddr }));
    }

    // an explicit captcha step's default timeout follows --timeout (raw shape —
    // runHandoffFlow re-sanitizes it; passing the normalized recipe here was the
    // 2026-08-31 double-sanitize bug)
    applyOperatorTimeout(recipeRaw, Number(opt('timeout')) > 0 ? Number(opt('timeout')) : undefined);

    const r = await runHandoffFlow(recipeRaw, {
      program, label, driver, mailtm,
      inbox: prebox,
      email: opt('email') || (prebox && prebox.address), password: opt('password'),
      register: registerSession, reloginCommand, resultPath,
      onLog: (o) => console.error(JSON.stringify(o)),
    });
    const safe = {
      ...r,
      account: r.account ? { ...r.account, cookies: r.account.cookies.map((c) => `${c.name}=${c.value}`), cookieNames: r.account.cookies.map((c) => c.name), password: r.ok ? r.account.password : undefined } : undefined,
    };
    try { writeFileSync(join(REPO, resultPath), JSON.stringify(safe, null, 1) + '\n'); } catch { /* the result file is evidence, not the contract */ }
    console.log(`[captchaassist] ${program}/${label} ok=${r.ok} registered=${!!r.registered} → ${resultPath}`);
    if (typeof driver.close === 'function') await driver.close();
    process.exit(r.ok ? 0 : (r.step === 'captcha' ? 4 : 3));
  }

  console.error('usage: captchaassist.mjs run --program <p> --label <l> --recipe <path> [--timeout ms] [--inbox addr --inbox-pass pw] | status [--dir d]');
  process.exit(1);
}
