// VARVEL captchaassist tests — hermetic: fake drivers, fake clocks, a mock
// broker. No live network, no real browser, no captcha is ever solved by code.
//   node --test test/captchaassist.test.mjs
//
// Pins: detection fires on reCAPTCHA/hCaptcha/Cloudflare signatures; the status
// file is written; a VERIFIED solve resumes the flow; a challenge that merely
// stops rendering is NEVER claimed as solved; OPERATOR-TIMEOUT on no response;
// broker registration only on a verified flow; the acctfactory recipe primitive
// ('captcha: handoff') pauses after signup submit.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  classifyProbe, handoffOnce, listHandoffs,
  sanitizeFlowRecipe, runHandoffFlow, loadFlowRecipe, applyOperatorTimeout,
} from '../tools/captchaassist.mjs';
import { provisionAccount, sanitizeRecipe } from '../tools/acctfactory.mjs';

const tmp = () => mkdtempSync(join(tmpdir(), 'captchaassist-'));
const noSleep = async () => {};
const silent = () => {};

// ——— pure: signature classification ———
test('classifyProbe: reCAPTCHA / hCaptcha / Cloudflare signatures fire; benign pages do not', () => {
  const rc = classifyProbe({ url: 'https://t.test/signup', iframes: ['https://www.google.com/recaptcha/api2/bframe'], bodySample: '', disabledSubmit: true });
  assert.equal(rc.found, true); assert.equal(rc.vendor, 'recaptcha'); assert.ok(rc.signals.includes('iframe:recaptcha'));
  assert.equal(rc.interactive, true, 'legacy string-form iframes are treated as visible — a bframe is interactive');
  // the checkbox LABEL text alone is NOT a challenge — that was the 2026-08-31
  // inert-iframe false positive that paused the rail on a blank form
  const rcText = classifyProbe({ url: 'https://t.test/s', iframes: [], bodySample: "Please confirm I'm not a robot to continue", disabledSubmit: false });
  assert.equal(rcText.found, false, "the inert checkbox label 'i'm not a robot' is not a challenge");
  const hc = classifyProbe({ url: 'https://t.test/s', iframes: ['https://newassets.hcaptcha.com/captcha/v1/x'], bodySample: '', disabledSubmit: false });
  assert.equal(hc.found, true); assert.equal(hc.vendor, 'hcaptcha'); assert.equal(hc.interactive, true);
  const cf = classifyProbe({ url: 'https://t.test/s', iframes: ['https://challenges.cloudflare.com/turnstile/v0/x'], bodySample: 'Verify you are human', disabledSubmit: false });
  assert.equal(cf.found, true); assert.equal(cf.vendor, 'cloudflare');
  const benign = classifyProbe({ url: 'https://t.test/s', iframes: ['https://www.youtube.com/embed/x'], bodySample: 'Create your free account', disabledSubmit: false });
  assert.equal(benign.found, false); assert.equal(benign.vendor, null);
  assert.equal(classifyProbe(null), null, 'a failed probe is honest null, never "no challenge"');
});

test('classifyProbe: inert anchor vs interactive bframe discrimination', () => {
  // the reCAPTCHA ANCHOR (checkbox widget) renders on page load — present, visible, INERT
  const anchor = classifyProbe({ url: 'https://t.test/signup', iframes: [{ src: 'https://www.google.com/recaptcha/api2/anchor?k=x', visible: true }], bodySample: '', disabledSubmit: false });
  assert.equal(anchor.found, true);
  assert.equal(anchor.interactive, false, 'a visible anchor checkbox is an inert widget, not a challenge');
  // the BFRAME is the image-challenge dialog — interactive ONLY when visible
  const bframeVisible = classifyProbe({ url: 'https://t.test/signup', iframes: [{ src: 'https://www.google.com/recaptcha/api2/anchor?k=x', visible: true }, { src: 'https://www.google.com/recaptcha/api2/bframe?k=x', visible: true }], bodySample: '', disabledSubmit: true });
  assert.equal(bframeVisible.interactive, true, 'visible bframe = the challenge dialog is OPEN');
  assert.ok(bframeVisible.signals.includes('iframe:recaptcha-bframe-visible'));
  const bframeHidden = classifyProbe({ url: 'https://t.test/signup', iframes: [{ src: 'https://www.google.com/recaptcha/api2/bframe?k=x', visible: false }], bodySample: '', disabledSubmit: false });
  assert.equal(bframeHidden.found, true);
  assert.equal(bframeHidden.interactive, false, 'an invisible bframe is dormant, not a challenge');
  // active-challenge text is interactive regardless of iframes
  const activeText = classifyProbe({ url: 'https://t.test/s', iframes: [], bodySample: 'Select all images with traffic lights', disabledSubmit: false });
  assert.equal(activeText.interactive, true);
});

test('classifyProbe: success marker is a configured solve signal, never the absence of one', () => {
  const hit = classifyProbe({ url: 'https://t.test/next', iframes: [], bodySample: 'Thanks! Check your email to verify the account.', disabledSubmit: false });
  assert.equal(hit.successMarker, true);
  const custom = classifyProbe({ url: 'https://t.test/next', iframes: [], bodySample: 'Wilkommen im Kundenkonto', disabledSubmit: false }, { successRe: 'wilkommen' });
  assert.equal(custom.successMarker, true);
  const miss = classifyProbe({ url: 'https://t.test/next', iframes: [], bodySample: 'Something went wrong', disabledSubmit: false });
  assert.equal(miss.successMarker, false);
});

// ——— a scriptable fake driver (the acctfactory driver interface + probe) ———
function makeDriver({ solveMode = 'url-change', solveAfterPolls = 2, neverSolve = false } = {}) {
  const d = {
    url: 'about:blank', email: null, password: null, clicks: 0, polls: 0,
    challenge: false, authed: false, gotSession: false, visits: [],
    async goto(u) {
      d.visits.push(u);
      d.url = d.authed ? u : (u.includes('/accounts/profile') ? 'https://target.test/login' : u);
      return { ok: true, url: d.url };
    },
    async fillByHints(hints, value) {
      if (hints.some((h) => /mail|email|@/.test(h))) { d.email = value; return true; }
      if (hints.some((h) => /password/.test(h))) { d.password = value; return true; }
      return false;
    },
    async clickByText() { d.clicks++; if (d.clicks === 1) d.challenge = true; return true; },
    async detectChallenge() {
      if (d.challenge) {
        d.polls++;
        if (!neverSolve && d.polls > solveAfterPolls) {
          d.challenge = false;
          if (solveMode === 'url-change') { d.url = 'https://target.test/check-your-email'; d.authed = true; d.gotSession = true; }
          if (solveMode === 'silent-clear') { /* the challenge vanished with NO corroboration — a renderer crash, not a solve */ }
        }
        return { found: true, vendor: 'recaptcha', signals: ['iframe:recaptcha'], url: d.url, disabledSubmit: true, successMarker: false };
      }
      return { found: false, vendor: null, signals: [], url: d.url, disabledSubmit: !d.authed, successMarker: false };
    },
    currentUrl() { return d.url; },
    async bodyText() { return d.authed ? `Profile — ${d.email}` : ''; },
    async cookies() { return d.gotSession ? [{ name: 'sid', value: 'sess-abc', domain: '.target.test' }] : []; },
    async readStorage() { return null; },
    async close() {},
  };
  return d;
}

const FLOW_RECIPE = {
  program: 'target', autoHandoff: true,
  steps: [
    { goto: 'https://target.test/signup' },
    { fill: { hints: ['email'], from: 'email' } },
    { fill: { hints: ['password'], from: 'password' } },
    { click: { text: ['Create account'] } },
    { captcha: 'handoff' },
    { verify: { url: 'https://target.test/accounts/profile/', bodyIncludes: '$email', urlDenyRe: 'login|signup' } },
  ],
  sessionCapture: { cookieDomains: ['target.test'] },
  canary: { url: 'https://target.test/accounts/profile/', auth: 'cookie', expectStatus: [200], denyStatus: [401, 403], denyBodyRe: 'login' },
};

// ——— the handoff state machine ———
test('handoff: detection writes the NEEDED status file and announces once, clearly', async () => {
  const dir = tmp();
  const lines = [];
  const d = makeDriver({});
  d.clicks = 1; d.challenge = true; // challenge already on screen
  const r = await handoffOnce(d, { program: 'semrush', label: 'a', step: 'signup', dir, sleepMs: noSleep, announce: (l) => lines.push(l), timeoutMs: 5000, pollMs: 1 });
  assert.equal(r.ok, true); assert.equal(r.state, 'RESOLVED'); assert.equal(r.signal, 'url-change');
  const file = join(dir, 'captcha-needed-semrush.json');
  assert.ok(existsSync(file), 'status file written');
  const st = JSON.parse(readFileSync(file, 'utf8'));
  assert.equal(st.state, 'RESOLVED');
  assert.equal(st.program, 'semrush'); assert.equal(st.step, 'signup');
  assert.ok(st.since && st.resolvedAt && st.signal === 'url-change');
  assert.equal(st.vendor, 'recaptcha');
  assert.equal(lines.length, 2, 'one NEEDED line + one RESOLVED line');
  assert.match(lines[0], /OPERATOR NEEDED/); assert.match(lines[0], /semrush\/a/);
});

test('handoff: PIN — a challenge that silently clears is NEVER claimed as solved', async () => {
  const dir = tmp();
  const d = makeDriver({ solveMode: 'silent-clear' });
  d.clicks = 1; d.challenge = true;
  const r = await handoffOnce(d, { program: 'semrush', label: 'b', step: 'signup', dir, sleepMs: noSleep, announce: silent, timeoutMs: 120, pollMs: 1 });
  assert.equal(r.ok, false);
  assert.equal(r.state, 'OPERATOR-TIMEOUT', 'challenge gone without corroboration keeps waiting and dies honest');
  assert.match(r.reason, /NOT/);
  const st = JSON.parse(readFileSync(join(dir, 'captcha-needed-semrush.json'), 'utf8'));
  assert.equal(st.state, 'OPERATOR-TIMEOUT');
});

test('handoff: operator no-show → OPERATOR-TIMEOUT, clean state, nothing claimed', async () => {
  const dir = tmp();
  const d = makeDriver({ neverSolve: true });
  d.clicks = 1; d.challenge = true;
  const r = await handoffOnce(d, { program: 'wolt', label: 'a', step: 'signup', dir, sleepMs: noSleep, announce: silent, timeoutMs: 150, pollMs: 1 });
  assert.equal(r.ok, false); assert.equal(r.state, 'OPERATOR-TIMEOUT');
  const st = JSON.parse(readFileSync(join(dir, 'captcha-needed-wolt.json'), 'utf8'));
  assert.equal(st.state, 'OPERATOR-TIMEOUT');
  assert.ok(st.timedOutAt);
});

test('handoff: honest negatives — no probe support, probe failure, no challenge', async () => {
  const dir = tmp();
  const unsupported = await handoffOnce({}, { program: 'x', dir, announce: silent });
  assert.equal(unsupported.state, 'UNSUPPORTED');
  const dead = await handoffOnce({ async detectChallenge() { return null; } }, { program: 'x', dir, announce: silent });
  assert.equal(dead.state, 'DETECTION-FAILED', 'a dead probe is UNKNOWN, never challenge-free');
  const clear = await handoffOnce(makeDriver({}), { program: 'x', dir, announce: silent });
  assert.equal(clear.ok, true); assert.equal(clear.state, 'NO-CHALLENGE');
});

// ——— the pausable flow runner ———
test('runHandoffFlow: captcha pauses, operator solve resumes, session harvested + brokered with canary', async () => {
  const dir = tmp();
  const d = makeDriver({});
  const registrations = [];
  const register = (entry, opts) => { registrations.push({ entry, opts }); return { ok: true, file: 'x' }; };
  const r = await runHandoffFlow(FLOW_RECIPE, {
    program: 'semrush', label: 'a', driver: d,
    email: 'op@lab.test', password: 'Pw!test123',
    dir, sleepMs: noSleep, announce: silent, register,
    reloginCommand: 'node tools/captchaassist.mjs run --program semrush --label a --recipe recipes/semrush-signup.json',
    resultPath: '.tmp/semrush-signup-a-result.json',
  });
  assert.equal(r.ok, true, r.error);
  assert.equal(r.account.cookies[0].name, 'sid');
  assert.equal(r.verified.ok, true, 'the post-solve verify oracle passed');
  const captchaSteps = r.handoffs.filter((h) => h.state !== 'NO-CHALLENGE');
  assert.ok(captchaSteps.length >= 1, 'a real handoff happened');
  assert.equal(captchaSteps[0].state, 'RESOLVED');
  assert.equal(r.registered, true);
  assert.equal(registrations.length, 1);
  const e = registrations[0].entry;
  assert.equal(e.program, 'semrush'); assert.equal(e.label, 'a');
  assert.equal(e.canary.url, 'https://target.test/accounts/profile/');
  assert.ok(e.canary.harvestedFrom.includes('captchaassist'), 'canary provenance recorded');
  assert.equal(e.relogin.kind, 'script');
  assert.match(e.relogin.command, /captchaassist\.mjs run/);
  assert.equal(e.session.cookies[0].value, 'sess-abc');
});

test('runHandoffFlow: OPERATOR-TIMEOUT fails the flow honestly and registers NOTHING', async () => {
  const dir = tmp();
  const d = makeDriver({ neverSolve: true });
  let registered = 0;
  const r = await runHandoffFlow(FLOW_RECIPE, {
    program: 'semrush', label: 'a', driver: d,
    email: 'op@lab.test', dir, sleepMs: noSleep, announce: silent,
    register: () => { registered++; return { ok: true }; },
    timeoutMs: 100,
  });
  assert.equal(r.ok, false);
  assert.equal(r.step, 'captcha');
  assert.match(r.error, /OPERATOR-TIMEOUT/);
  assert.equal(registered, 0, 'no broker entry for an unsolved flow');
});

test('runHandoffFlow: verify oracle failure is honest — flow not ok, nothing brokered', async () => {
  const dir = tmp();
  const d = makeDriver({});
  // the solve verifies (url-change signal) but the account never authenticates:
  // the profile page redirects to login even after the handoff
  d.goto = async (u) => { d.url = u.includes('/accounts/profile') ? 'https://target.test/login' : u; d.visits.push(u); return { ok: true, url: d.url }; };
  let registered = 0;
  const r = await runHandoffFlow(FLOW_RECIPE, {
    program: 'semrush', label: 'a', driver: d, email: 'op@lab.test',
    dir, sleepMs: noSleep, announce: silent, register: () => { registered++; return { ok: true }; },
  });
  assert.equal(r.ok, false);
  assert.equal(r.step, 'verify');
  assert.match(r.error, /deny pattern/);
  assert.equal(registered, 0, 'an unverified session is never brokered');
});

test('sanitizeFlowRecipe: shape validation, unknown steps rejected honestly', () => {
  assert.equal(sanitizeFlowRecipe(null), null);
  assert.equal(sanitizeFlowRecipe({ steps: [] }), null);
  assert.equal(sanitizeFlowRecipe({ steps: [{ teleport: 'mars' }] }), null);
  assert.equal(sanitizeFlowRecipe({ steps: [{ waitMail: { pattern: '([' } }] }), null, 'bad regex rejected');
  const r = sanitizeFlowRecipe(FLOW_RECIPE);
  assert.equal(r.program, 'target');
  assert.equal(r.autoHandoff, true);
  assert.equal(r.steps[4].op, 'captcha');
  assert.equal(r.canary.auth, 'cookie');
});

// ——— regression: the 2026-08-31 double-sanitize bug ———
// The CLI sanitized the recipe and then handed the NORMALIZED shape to
// runHandoffFlow, which sanitizes internally and rightly rejected the {op:…}
// steps: ok=false step 'validate' on the shipped semrush recipe. The loader +
// raw-passthrough is the fix; this test drives the EXACT CLI code path from disk.
test('regression: CLI loads recipes/semrush-signup.json from disk and runHandoffFlow accepts the raw recipe', async () => {
  const loaded = loadFlowRecipe('recipes/semrush-signup.json'); // the CLI's loader, repo-relative
  assert.equal(loaded.ok, true, loaded.error);
  assert.equal(loaded.recipe.steps.length, 11);
  assert.equal(loaded.recipe.steps[7].op, 'captcha', 'the handoff step survived sanitization');
  assert.equal(loaded.recipe.canary.url, 'https://www.semrush.com/accounts/profile/');
  // the exact CLI sequence: --timeout patches the RAW recipe, then RAW goes to the runner
  applyOperatorTimeout(loaded.raw, 60000);
  assert.equal(loaded.raw.steps[7].captcha.timeoutMs, 60000, 'string handoff step upgraded to {mode, timeoutMs}');
  const r = await runHandoffFlow(loaded.raw, { program: 'semrush', label: 'a', driver: null, sleepMs: noSleep, announce: silent });
  assert.equal(r.ok, false);
  assert.equal(r.step, 'validate');
  assert.match(r.error, /driver/, 'the recipe PASSED sanitization — only the injected null driver is refused');
});

test('regression pin: the sanitizer is deliberately NOT idempotent — callers pass raw, never normalized', async () => {
  const normalized = sanitizeFlowRecipe(FLOW_RECIPE);
  assert.ok(normalized);
  const r = await runHandoffFlow(normalized, { program: 'semrush', label: 'a', driver: null, sleepMs: noSleep, announce: silent });
  assert.equal(r.ok, false);
  assert.match(r.error, /rejected by sanitizeFlowRecipe/, 'feeding a normalized recipe back in fails loudly, not silently');
});

test('loadFlowRecipe: honest errors for missing/broken files', () => {
  const missing = loadFlowRecipe('recipes/does-not-exist.json');
  assert.equal(missing.ok, false);
  assert.match(missing.error, /unreadable/);
});

// ——— the operator board ———
test('listHandoffs: pending/resolved/timedOut buckets from status files', async () => {
  const dir = tmp();
  // one RESOLVED
  const a = makeDriver({}); a.clicks = 1; a.challenge = true;
  await handoffOnce(a, { program: 'semrush', label: 'a', step: 'signup', dir, sleepMs: noSleep, announce: silent, timeoutMs: 5000, pollMs: 1 });
  // one OPERATOR-TIMEOUT
  const b = makeDriver({ neverSolve: true }); b.clicks = 1; b.challenge = true;
  await handoffOnce(b, { program: 'wolt', label: 'a', step: 'signup', dir, sleepMs: noSleep, announce: silent, timeoutMs: 100, pollMs: 1 });
  // one PENDING — parked on a controllable sleep gate until we release it
  let release;
  const gate = () => new Promise((r) => { release = r; });
  const c = makeDriver({ solveAfterPolls: 0 }); c.clicks = 1; c.challenge = true;
  const p = handoffOnce(c, { program: 'zomato', label: 'a', step: 'signup', dir, sleepMs: gate, announce: silent, timeoutMs: 60000, pollMs: 1 });
  for (let i = 0; i < 100 && !existsSync(join(dir, 'captcha-needed-zomato.json')); i++) await new Promise((r) => setTimeout(r, 5));
  const board = listHandoffs({ dir });
  assert.equal(board.resolved.length, 1);
  assert.equal(board.resolved[0].program, 'semrush');
  assert.equal(board.timedOut.length, 1);
  assert.equal(board.timedOut[0].program, 'wolt');
  assert.equal(board.pending.length, 1);
  assert.equal(board.pending[0].program, 'zomato');
  assert.equal(board.pending[0].state, 'NEEDED');
  release(); // the operator "solves" — the parked handoff verifies and lands
  const rp = await p;
  assert.equal(rp.state, 'RESOLVED');
});

// ——— acctfactory wiring: the 'captcha: handoff' recipe primitive ———
const mailStub = {
  async createAccount() { return { address: 'x@lab.test', password: 'p', token: 't' }; },
  async waitForCode() { return { match: '123456' }; },
  async waitForLink() { return null; },
};

const ACCT_DRIVER = () => ({
  async goto(url) { return { ok: true, url }; },
  async fillByHints() { return true; },
  async clickByText() { return true; },
  async cookies() { return [{ name: 'sid', value: 's1', domain: 'target.test' }]; },
  async readStorage() { return null; },
  currentUrl() { return 'https://target.test/app'; },
  async close() {},
});

test('acctfactory: sanitizeRecipe accepts the captcha handoff primitive', () => {
  const r = sanitizeRecipe({ signupUrl: 'https://x.test/s', captcha: 'handoff' });
  assert.equal(r.captcha.mode, 'handoff');
  assert.deepEqual(r.captcha.after, ['signup']);
  const r2 = sanitizeRecipe({ signupUrl: 'https://x.test/s', captcha: { mode: 'handoff', timeoutMs: 300000, after: ['signup', 'activate'] } });
  assert.equal(r2.captcha.timeoutMs, 300000);
  assert.deepEqual(r2.captcha.after, ['signup', 'activate']);
  assert.equal(sanitizeRecipe({ signupUrl: 'https://x.test/s' }).captcha, null, 'no captcha key → no primitive');
  assert.equal(sanitizeRecipe({ signupUrl: 'https://x.test/s', captcha: 'auto-solve' }).captcha, null, 'only handoff mode exists — there is no auto-solve');
});

test('acctfactory: captcha handoff pauses after signup submit; timeout fails step captcha honestly', async () => {
  const recipe = { signupUrl: 'https://target.test/signup', captcha: 'handoff', sessionCapture: { cookieDomains: ['target.test'] } };
  const calls = [];
  const okHandoff = async (driver, ctx) => { calls.push(ctx); return { ok: true, state: 'RESOLVED', signal: 'url-change' }; };
  const r = await provisionAccount(recipe, { label: 'owner', mailtm: mailStub, driver: ACCT_DRIVER(), handoff: okHandoff, program: 'semrush' });
  assert.equal(r.ok, true, r.error);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].step, 'signup');
  assert.ok(r.steps.some((s) => s.step === 'captcha' && s.state === 'RESOLVED'));

  const timeoutHandoff = async () => ({ ok: false, state: 'OPERATOR-TIMEOUT', reason: 'no verified operator solve' });
  const r2 = await provisionAccount(recipe, { label: 'owner', mailtm: mailStub, driver: ACCT_DRIVER(), handoff: timeoutHandoff });
  assert.equal(r2.ok, false);
  assert.equal(r2.step, 'captcha');
  assert.match(r2.error, /OPERATOR-TIMEOUT/);
  assert.match(r2.error, /nothing claimed/);
});

// ——— bug #2 pin: the flow runner's inbox step surfaces the mail.tm status ———
test('runHandoffFlow: inbox failure names the mail.tm HTTP status (never a bare "creation failed")', async () => {
  const mailtm = {
    lastError: { op: 'POST /accounts', status: 429, bodySnippet: '{"error":"rate limited"}', attempt: 3 },
    async createAccount() { return null; },
    async waitForMatch() { return null; },
  };
  const r = await runHandoffFlow({ ...FLOW_RECIPE, inbox: 'mailtm' }, {
    program: 'semrush', label: 'a', driver: makeDriver({}), mailtm,
    dir: tmp(), sleepMs: noSleep, announce: silent,
  });
  assert.equal(r.ok, false);
  assert.equal(r.step, 'inbox');
  assert.match(r.error, /HTTP 429/);
  assert.match(r.error, /POST \/accounts/);
});

// ——— pre-provisioned inbox: account creation is the flaky leg — skip it ———
test('runHandoffFlow: a pre-provisioned inbox skips mail.tm account creation entirely', async () => {
  const dir = tmp();
  let createCalls = 0;
  const mailtm = {
    lastError: null,
    async createAccount() { createCalls++; return null; }, // must NEVER be called
    async waitForMatch() { return { match: 'https://target.test/confirm/abc123', subject: 'Confirm' }; },
  };
  const recipe = {
    program: 'target', inbox: 'mailtm', autoHandoff: true,
    steps: [
      { goto: 'https://target.test/signup' },
      { fill: { hints: ['email'], from: 'email' } },
      { fill: { hints: ['password'], from: 'password' } },
      { click: { text: ['Create account'] } },
      { captcha: 'handoff' },
      { waitMail: { pattern: '(https://[^\s]+confirm[^\s]*)', gotoOnMatch: true } },
      { verify: { url: 'https://target.test/accounts/profile/', bodyIncludes: '$email', urlDenyRe: 'login|signup' } },
    ],
    sessionCapture: { cookieDomains: ['target.test'] },
    canary: { url: 'https://target.test/accounts/profile/', auth: 'cookie' },
  };
  const regs = [];
  const r = await runHandoffFlow(recipe, {
    program: 'semrush', label: 'a', driver: makeDriver({}),
    mailtm, inbox: { address: 'pre@lab.test', password: 'p', token: 'tok-pre' },
    dir, sleepMs: noSleep, announce: silent,
    register: (e) => { regs.push(e); return { ok: true }; },
  });
  assert.equal(createCalls, 0, 'account creation skipped — the flaky leg never ran');
  assert.equal(r.ok, true, r.error);
  assert.equal(r.account.email, 'pre@lab.test', 'the pre-provisioned address is the account identity');
  assert.ok(regs.length === 1, 'session brokered');
});

test('runHandoffFlow: without a pre-provisioned inbox, creation still runs (default path intact)', async () => {
  const dir = tmp();
  let createCalls = 0;
  const mailtm = {
    lastError: null,
    async createAccount() { createCalls++; return { address: 'minted@lab.test', password: 'p', token: 't' }; },
    async waitForMatch() { return { match: 'https://target.test/confirm/x', subject: 'Confirm' }; },
  };
  const recipe = { ...FLOW_RECIPE, inbox: 'mailtm' };
  const r = await runHandoffFlow(recipe, {
    program: 'semrush', label: 'a', driver: makeDriver({}), mailtm,
    dir, sleepMs: noSleep, announce: silent, register: () => ({ ok: true }),
  });
  assert.equal(createCalls, 1, 'no pre-provisioned inbox → creation runs as before');
  assert.equal(r.ok, true, r.error);
});

// ——— cycle-break pin: when captchaassist.mjs is the CLI entry, the driver's
// default detectChallenge (dynamic import of THIS module) deadlocks on the
// top-level await. The runner must rebind detection via driver._page. ———
test('runHandoffFlow: driver with _page gets detectChallenge rebound — the import-based detector is never called', async () => {
  const d = makeDriver({});
  let originalCalled = false;
  d.detectChallenge = async () => { originalCalled = true; return null; }; // stands in for the deadlocking import path
  d._page = {
    async evaluate() {
      if (d.challenge) {
        d.polls++;
        if (d.polls > 2) { d.challenge = false; d.url = 'https://target.test/check-your-email'; d.authed = true; d.gotSession = true; }
        return { url: d.url, iframes: ['https://www.google.com/recaptcha/api2/bframe'], bodySample: '', disabledSubmit: true };
      }
      return { url: d.url, iframes: [], bodySample: '', disabledSubmit: !d.authed };
    },
  };
  const r = await runHandoffFlow(FLOW_RECIPE, {
    program: 'semrush', label: 'a', driver: d, email: 'op@lab.test',
    dir: tmp(), sleepMs: noSleep, announce: silent, register: () => ({ ok: true }),
  });
  assert.equal(originalCalled, false, 'the deadlocking dynamic-import detector was never used');
  assert.equal(r.ok, true, r.error);
  assert.ok(r.handoffs.some((h) => h.state === 'RESOLVED' && h.signal === 'url-change'), 'the handoff verified through the rebound detector');
});

// ——— inert-iframe discrimination + broadened solve detection (2026-08-31 live bug) ———
// A scriptable probe driver carrying the NEW classification shape.
function probeDriver(states) {
  let i = 0;
  return {
    calls: 0,
    async detectChallenge() { const s = states[Math.min(i++, states.length - 1)]; this.calls++; return typeof s === 'function' ? s() : s; },
    currentUrl() { return this._url || 'https://t.test/signup'; },
  };
}
const INERT_ANCHOR = { found: true, interactive: false, vendor: 'recaptcha', signals: ['iframe:recaptcha'], url: 'https://t.test/signup', disabledSubmit: false, successMarker: false, progress: false, progressSignals: [] };
const ACTIVE_BFRAME = { found: true, interactive: true, vendor: 'recaptcha', signals: ['iframe:recaptcha', 'iframe:recaptcha-bframe-visible'], url: 'https://t.test/signup', disabledSubmit: true, successMarker: false, progress: false, progressSignals: [] };

test('handoff: inert anchor iframe on load does NOT pause an auto sweep (the live bug)', async () => {
  const dir = tmp();
  const d = probeDriver([INERT_ANCHOR]);
  const r = await handoffOnce(d, { program: 'semrush', label: 'a', step: '0:goto', mode: 'auto', dir, sleepMs: noSleep, announce: silent });
  assert.equal(r.ok, true);
  assert.equal(r.state, 'INERT-CHALLENGE');
  assert.equal(d.calls, 1, 'auto mode checks once — no grace polling');
  assert.ok(!existsSync(join(dir, 'captcha-needed-semrush.json')), 'no NEEDED status file for an inert widget');
});

test('handoff: visible bframe DOES trigger the handoff; explicit mode grace catches a dialog that renders a beat late', async () => {
  const dir = tmp();
  // explicit: inert, inert, then the dialog opens inside the grace window, then solved via url-change
  let calls = 0;
  const d = {
    async detectChallenge() {
      calls++;
      if (calls <= 2) return { ...INERT_ANCHOR };
      if (calls === 3) return { ...ACTIVE_BFRAME };
      return { ...ACTIVE_BFRAME, interactive: false, url: 'https://t.test/check-email' };
    },
  };
  const lines = [];
  const r = await handoffOnce(d, { program: 'semrush', label: 'a', step: '7:captcha', mode: 'explicit', dir, sleepMs: noSleep, announce: (l) => lines.push(l), timeoutMs: 5000, pollMs: 1 });
  assert.equal(r.ok, true);
  assert.equal(r.state, 'RESOLVED');
  assert.equal(r.signal, 'url-change');
  assert.ok(lines.some((l) => /OPERATOR NEEDED/.test(l)), 'the interactive challenge paused for the operator');
  const st = JSON.parse(readFileSync(join(dir, 'captcha-needed-semrush.json'), 'utf8'));
  assert.equal(st.state, 'RESOLVED');
});

test('handoff: PIN — inert-only at an explicit step proceeds after grace, never claims a challenge', async () => {
  const dir = tmp();
  const d = probeDriver([INERT_ANCHOR]);
  const r = await handoffOnce(d, { program: 'semrush', label: 'a', step: '7:captcha', mode: 'explicit', graceMs: 30, dir, sleepMs: noSleep, announce: silent, pollMs: 1 });
  assert.equal(r.ok, true);
  assert.equal(r.state, 'INERT-CHALLENGE');
  assert.ok(!existsSync(join(dir, 'captcha-needed-semrush.json')), 'no handoff was opened');
});

test('handoff: next-step progress elements count as a solve even with the challenge still up (manual drive-forward)', async () => {
  const dir = tmp();
  let calls = 0;
  const d = {
    async detectChallenge() {
      calls++;
      if (calls === 1) return { ...ACTIVE_BFRAME };
      // challenge UI still rendered, but the verification-code input appeared —
      // the operator (or the site itself) moved the flow forward
      return { ...ACTIVE_BFRAME, interactive: true, progress: true, progressSignals: ['code'] };
    },
  };
  const r = await handoffOnce(d, { program: 'semrush', label: 'a', step: '7:captcha', mode: 'explicit', dir, sleepMs: noSleep, announce: silent, timeoutMs: 5000, pollMs: 1, progressHints: ['code'] });
  assert.equal(r.ok, true);
  assert.equal(r.state, 'RESOLVED');
  assert.equal(r.signal, 'progress-elements');
});

test('handoff: URL navigation away from the signup page counts even if an inert anchor lingers (manual submit)', async () => {
  const dir = tmp();
  let calls = 0;
  const d = {
    async detectChallenge() {
      calls++;
      if (calls === 1) return { ...ACTIVE_BFRAME };
      // Jack submitted by hand: page navigated, the inert anchor iframe is still in the DOM
      return { ...INERT_ANCHOR, url: 'https://t.test/signup/done' };
    },
  };
  const r = await handoffOnce(d, { program: 'semrush', label: 'a', step: '7:captcha', mode: 'explicit', dir, sleepMs: noSleep, announce: silent, timeoutMs: 5000, pollMs: 1 });
  assert.equal(r.ok, true);
  assert.equal(r.state, 'RESOLVED');
  assert.equal(r.signal, 'url-change');
});
