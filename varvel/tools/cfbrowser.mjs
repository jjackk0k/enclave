// tools/cfbrowser.mjs — INTERACT as the vaulted identity: one-shot browser actions
// (open / forms / fill-submit / probe-comment) inside a REAL headed Chrome, riding the
// operator-provided (or broker-minted) cf_clearance from the clearance vault.
//
// Why it exists: tools/cfride.mjs proved cheap HTTP can RIDE a clearance, but the real
// breach paths need INTERACTION as the cleared identity — submitting the site's public
// registration form, measuring comment-form sanitization for a stored-content path,
// reading the authenticated surface. Cheap HTTP cannot click. This is the
// browser-interaction tier; it keeps the broker's launch doctrine (patchright-core
// dynamically imported from tools/clearance/node_modules, launchPersistentContext with
// executablePath from resolveChrome, viewport:null, headed by default) and the ride's
// identity binding (the vault's EXACT UA + cookies — cf_clearance is bound to source
// IP + UA, so drifting either invalidates it instantly).
//
// HONESTY CONTRACT (non-negotiable, same as the broker's): NEVER throws — every failure
// resolves { ok:false, reason }. No clearance, no real browser, launch failure, a
// mid-interaction challenge: all honestly reported, never acted through. THE NAV GATE:
// after EVERY navigation the served document is classified by engine/challenge; a
// challenge-DOMINATED page aborts the action ('clearance challenged mid-interaction —
// expired/UA/IP drift'). Nothing inside a challenged page counts as interaction.
//
// reCAPTCHA ON A SERVED PAGE IS NOT A CLEARANCE FAILURE: detectChallenge also fires on
// embedded captcha/Turnstile widgets ('captcha'/'turnstile' kinds), and the
// registration form this tool is built to submit CARRIES one. The gate therefore
// distinguishes a challenge INTERSTITIAL (a thin, challenge-dominated document —
// abort) from a full served page merely EMBEDDING a widget (proceed, flagged
// embeddedInteractive). The widget itself is solved by the OPERATOR in the visible
// window — human-in-the-loop by design: the tool POLLS the widget's response field
// patiently (never aborting early on an intermediate challenge state — the broker's
// blank-document doctrine) and proceeds only once a human tick lands, or fails
// honestly when the time budget runs out.
//
// OPERATOR NOTE: headless:false (the default) means the browser window IS VISIBLE on
// the operator's machine — that is intended; the operator watches every interaction
// and ticks interactive challenges. headless:true is allowed but measurably weaker
// against 2026 bot gates.
//
// INJECTABLE SEAMS (hermetic tests — no real browser, no network): all page
// interaction lives behind a THIN DRIVER (opts.driverFactory) with one method per
// browser primitive (goto/readDocument/fill/clickAndSettle/...); the default factory
// wraps a Patchright page. opts.launcher, opts.clearanceLookup and
// opts.chromePath/env/exists mirror the broker's seams; opts.ghost/opts.ghostMode
// mirror the ride tools' transport seams (below).
//
// EGRESS PARITY (2026-08-10, live-proven gap): the pre-fix defaultLauncher took NO
// proxy, so a chain-minted (IP-bound) clearance was ridden DIRECT and challenged at
// the edge. The vault entry's egressId is the binding contract: cfbrowse resolves it
// through the broker's resolveRideTransport BEFORE any window opens — a chain-keyed
// entry launches the context with the chain as its single-hop proxy (the exact
// proxy {server, username?, password?} shape of the broker's mint leg; a multi-hop
// chain is refused fail-closed — a browser rides exactly ONE hop), a 'direct' entry
// stays direct (fail-closed for public targets under ghost 'required'), private/range
// is always direct. The default ghost state comes from the SAME Settings the
// mint/lookup sides read (ghostRideState), so transport and vault key never drift.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { clearanceFor, resolveChrome, resolveRideTransport, ghostRideState } from './clearance/broker.mjs';
import { detectChallenge } from '../engine/challenge.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DATA_DIR = path.join(HERE, '..', 'data');
// SHARED with Patchright mints on purpose: the same real profile carries the mint-time
// storage/fingerprint forward — the strongest identity continuity. CAVEAT (same as the
// broker's nodriver note): one live Chrome per profile dir — do not run an interaction
// CONCURRENTLY with a mint, or Chrome's profile lock deadlocks. opts.userDataDir
// overrides when parallel sessions are genuinely needed.
const PROFILE_DIR = path.join(DATA_DIR, 'clearance-profile');
const POLL_MS = 1000;
const ACTIONS = new Set(['open', 'forms', 'fill-submit', 'probe-comment']);
// Kinds that ALWAYS mean the clearance itself was challenged (an interstitial, never a
// served page): a full WordPress page does not carry these markers.
const INTERSTITIAL_KINDS = new Set(['managed-js', 'block-1020', 'rate-limit', 'labyrinth-suspect']);
// Below this much visible text, a captcha/turnstile hit is a thin challenge SHELL, not
// a served page embedding a widget.
const EMBED_MIN_CHARS = 600;

const msg = (e) => String((e && e.message) || e);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function zoneOf(url) {
  try {
    const u = new URL(String(url));
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    return u.host || null;
  } catch { return null; }
}

// --- pure, hermetically testable pieces -------------------------------------------

// The broker's blank-document doctrine, verbatim in spirit: a page mid-navigation
// (evaluate failed -> html null), an about:blank/srcdoc, or a near-empty DOM is a
// LOADING state — never a classification input.
export function classifyDocument({ url = '', html = null } = {}) {
  if (html == null) return { readable: false, kind: 'navigation-in-flight' };
  if (/^about:(blank|srcdoc)/i.test(String(url || ''))) return { readable: false, kind: 'document-loading' };
  const text = String(html).replace(/<[^>]+>|\s+/g, '');
  if (text.length < 40) return { readable: false, kind: 'document-loading' };
  return { readable: true, kind: 'document' };
}

// Visible-text mass of a document (scripts/styles stripped first): the discriminator
// between a challenge SHELL and a served page that embeds a widget.
function thinVisibleText(html) {
  return String(html || '')
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

// True when the detection means the CLEARANCE was challenged (interstitial/thin shell)
// rather than a served page carrying an interactive widget.
export function isChallengeInterstitial(detection, html) {
  if (!detection || detection.present !== true) return false;
  if (INTERSTITIAL_KINDS.has(detection.kind)) return true;
  // captcha/turnstile: an interstitial only when the document is challenge-dominated
  return thinVisibleText(html).length < EMBED_MIN_CHARS;
}

// navGate({ status, url, html }) — THE classification after a navigation. Pass: the
// page was SERVED (clean, or a full page merely embedding an interactive widget).
// Fail 'challenged': the clearance was challenged mid-interaction — abort, never act
// inside it. Fail 'unreadable': the page never rendered a readable document — refuse
// to call anything interaction on a blank/loading page. Never throws.
export function navGate({ status = null, url = '', html = null } = {}) {
  const detection = detectChallenge({ status: status == null ? 0 : status, headers: {}, body: String(html || '') });
  if (detection.present && isChallengeInterstitial(detection, html)) {
    return {
      pass: false,
      gate: 'challenged',
      detection,
      reason: 'clearance challenged mid-interaction — expired/UA/IP drift (detection: ' + detection.kind + '); re-mint or refresh the operator session — acting inside a challenged page is not interaction',
    };
  }
  const cls = classifyDocument({ url, html });
  if (!cls.readable) {
    return {
      pass: false,
      gate: 'unreadable',
      detection,
      reason: 'page never rendered a readable document after navigation (' + cls.kind + ') — refusing to report interaction on a blank/loading page',
    };
  }
  // A full served page that embeds a widget passes — flagged, never silently.
  return { pass: true, detection, embeddedInteractive: detection.present === true };
}

// classifyForm(raw, { pageHtml }) — normalize one in-page form dump and attach the two
// doctrine flags: hasPasswordField (drives the operator gate on submit) and
// hasRecaptcha (a widget inside THIS form, or page-level script/sitekey markers).
export function classifyForm(raw, { pageHtml = '' } = {}) {
  const f = raw && typeof raw === 'object' ? raw : {};
  const inputs = (Array.isArray(f.inputs) ? f.inputs : []).map((i) => ({
    name: String((i && i.name) || ''),
    type: String((i && i.type) || 'text').toLowerCase(),
    id: String((i && i.id) || ''),
    placeholder: String((i && i.placeholder) || ''),
    required: !!(i && i.required === true),
  }));
  const pageRecaptcha = /grecaptcha|g-recaptcha|recaptcha\/api\.js|data-sitekey|cf-turnstile|challenges\.cloudflare\.com\/turnstile|h-captcha/i.test(String(pageHtml || ''));
  return {
    action: String(f.action || ''),
    method: String(f.method || 'get').toLowerCase(),
    inputs,
    hasPasswordField: inputs.some((i) => i.type === 'password'),
    hasRecaptcha: f.recaptchaWidget === true || pageRecaptcha,
  };
}

// fillCandidates(nameOrCss) — name-then-css fallback, ordered. A bare identifier tries
// [name="x"], then #x, then x as a raw selector; anything already css-shaped goes as-is.
export function fillCandidates(nameOrCss) {
  const s = String(nameOrCss || '').trim();
  if (!s) return [];
  if (/^[A-Za-z_][A-Za-z0-9_-]*$/.test(s)) return ['[name="' + s + '"]', '#' + s, s];
  return [s];
}

// fieldsTouchPassword(forms, fields) — true when any field being filled names (by
// input name, or by id / '#id') a password-typed input in any enumerated form. Paired
// with the driver's closest-form probe for the submit control; either fires the guard.
export function fieldsTouchPassword(forms, fields) {
  const keys = Object.keys(fields || {});
  if (!keys.length) return false;
  for (const f of (Array.isArray(forms) ? forms : [])) {
    for (const i of (f && f.inputs) || []) {
      if (String(i.type).toLowerCase() !== 'password') continue;
      for (const k of keys) {
        if ((i.name && k === i.name) || (i.id && (k === i.id || k === '#' + i.id))) return true;
      }
    }
  }
  return false;
}

// seedCookies(cookies, zone) — vault cookie objects -> Playwright addCookies shape.
// Domain is dot-prefixed ('.<zone>') so subdomains ride the same clearance; a session
// cookie's expires:-1 (as context.cookies() reports it) is dropped rather than fed
// back to addCookies.
export function seedCookies(cookies, zone) {
  const z = String(zone || '');
  return (Array.isArray(cookies) ? cookies : [])
    .filter((c) => c && c.name != null && c.value != null)
    .map((c) => {
      const out = { ...c, name: String(c.name), value: String(c.value) };
      const d = out.domain ? String(out.domain) : z;
      out.domain = d.startsWith('.') ? d : '.' + d;
      out.path = out.path || '/';
      delete out.url; // Playwright wants url XOR domain+path
      if (out.expires != null && (!Number.isFinite(out.expires) || out.expires <= 0)) delete out.expires;
      return out;
    });
}

// --- probe-comment: the sanitization MEASUREMENT. Three BENIGN fragments + a unique
// marker; never a javascript: URL, never a <script> — we measure what the sanitizer
// keeps verbatim, we do not fire payloads. Marker embedded in each fragment so a
// verbatim match can never be pre-existing page content.
export function probeFragments(marker) {
  const m = String(marker || 'varvel-probe');
  return {
    plain: 'VARVEL benign sanitization probe ' + m,
    bTag: '<b>bold ' + m + '</b>',
    styleTag: '<style>body{background:#000}/*' + m + '*/</style>',
    marker: m,
  };
}

export function probeCommentBody(marker) {
  const f = probeFragments(marker);
  return [f.plain, f.bTag, f.styleTag, f.marker].join('\n');
}

// survivalDiff(html, marker) — which fragments came back VERBATIM in the re-served
// page. markerFound:false with all-survived:false honestly reads as "held for
// moderation or fully stripped", not as a tool failure.
export function survivalDiff(html, marker) {
  const f = probeFragments(marker);
  const h = String(html || '');
  return {
    survived: {
      plain: h.includes(f.plain),
      bTag: h.includes(f.bTag),
      styleTag: h.includes(f.styleTag),
    },
    markerFound: h.includes(f.marker),
  };
}

// --- the default (real-browser) driver --------------------------------------------

// makePlaywrightDriver(page) — the THIN driver over a Patchright page. One method per
// browser primitive; everything above the driver stays browser-free and testable.
// Every method degrades honestly (catch -> empty/null), never throws upward.
function makePlaywrightDriver(page) {
  return {
    async goto(url, { timeoutMs }) {
      // A rejected goto is not fatal here (redirect chains under us); the settle poll
      // below is the arbiter, same as the broker's mint leg.
      const res = await page.goto(String(url), { waitUntil: 'domcontentloaded', timeout: Math.max(1000, timeoutMs || 120000) }).catch(() => null);
      const status = res && typeof res.status === 'function' ? res.status() : null;
      let body = res && typeof res.text === 'function' ? await res.text().catch(() => '') : '';
      if (!body) body = await page.evaluate(() => (document.documentElement ? document.documentElement.outerHTML : '')).catch(() => '');
      return { status, body };
    },
    async readDocument() {
      let url = ''; try { url = String(page.url() || ''); } catch {}
      const html = await page.evaluate(() => document.title + '\n' + (document.documentElement ? document.documentElement.outerHTML : '')).catch(() => null);
      return { url, html };
    },
    async currentUrl() { try { return String(page.url() || ''); } catch { return ''; } },
    async title() { return page.title().catch(() => ''); },
    async visibleText(maxChars) {
      const t = await page.evaluate(() => (document.body ? document.body.innerText : '')).catch(() => '');
      return String(t || '').slice(0, Math.max(1, maxChars || 2048));
    },
    async links(max) {
      const ls = await page.evaluate(() => [...document.querySelectorAll('a[href]')].map((a) => ({ href: a.href, text: String(a.innerText || a.textContent || '').replace(/\s+/g, ' ').trim() }))).catch(() => []);
      return (Array.isArray(ls) ? ls : []).slice(0, Math.max(1, max || 50));
    },
    async formsRaw() {
      const raw = await page.evaluate(() => {
        const forms = [...document.querySelectorAll('form')].map((f) => ({
          action: f.getAttribute('action') || '',
          method: (f.getAttribute('method') || 'get').toLowerCase(),
          recaptchaWidget: !!f.querySelector('.g-recaptcha, .cf-turnstile, .h-captcha, [data-sitekey]'),
          inputs: [...f.querySelectorAll('input, textarea, select')].map((el) => ({
            name: el.getAttribute('name') || '',
            type: (el.getAttribute('type') || (el.tagName.toLowerCase() === 'input' ? 'text' : el.tagName.toLowerCase())),
            id: el.id || '',
            placeholder: el.getAttribute('placeholder') || '',
            required: !!el.required,
          })),
        }));
        return { forms, pageHtml: document.documentElement ? document.documentElement.outerHTML : '' };
      }).catch(() => ({ forms: [], pageHtml: '' }));
      return raw && typeof raw === 'object' ? raw : { forms: [], pageHtml: '' };
    },
    async fill(nameOrCss, value) {
      const tried = fillCandidates(nameOrCss);
      for (const sel of tried) {
        const el = await page.$(sel).catch(() => null);
        if (!el) continue;
        const tag = await el.evaluate((e) => e.tagName.toLowerCase()).catch(() => '');
        if (tag === 'select') {
          const ok = await el.selectOption({ label: String(value) }).then(() => true).catch(() => false);
          if (!ok) await el.selectOption({ value: String(value) }).catch(() => {});
          return { ok: true, via: sel };
        }
        const ok = await el.fill(String(value)).then(() => true).catch(() => false);
        if (!ok) {
          // Odd widgets (contenteditable, JS-bound inputs): set the value and dispatch
          // the events a human typist would have produced.
          await el.evaluate((e, v) => { e.value = v; e.dispatchEvent(new Event('input', { bubbles: true })); e.dispatchEvent(new Event('change', { bubbles: true })); }, String(value)).catch(() => {});
        }
        return { ok: true, via: sel };
      }
      return { ok: false, reason: 'no element matched (tried ' + (tried.join(', ') || 'nothing') + ')' };
    },
    async submitInsidePasswordForm(selector) {
      // null = the selector matched nothing (unknown); the click will fail honestly later.
      return page.evaluate((sel) => {
        const el = document.querySelector(sel);
        if (!el) return null;
        const form = el.closest('form');
        return form ? !!form.querySelector('input[type="password"]') : false;
      }, String(selector)).catch(() => null);
    },
    async interactiveState() {
      return page.evaluate(() => {
        const RESPONSES = 'textarea[name="g-recaptcha-response"], textarea[name="cf-turnstile-response"], textarea[name="h-captcha-response"]';
        const widget = document.querySelector('.g-recaptcha, .cf-turnstile, .h-captcha, [data-sitekey], iframe[src*="recaptcha"], iframe[src*="challenges.cloudflare.com"], iframe[src*="hcaptcha"]');
        const solved = [...document.querySelectorAll(RESPONSES)].some((t) => t.value && t.value.length > 0);
        return { present: !!(widget || document.querySelector(RESPONSES)), solved };
      }).catch(() => ({ present: false, solved: false }));
    },
    async clickAndSettle(selector, { timeoutMs }) {
      // Navigation may or may not happen (JS-driven submits) — race it, then a
      // networkidle-ish settle; both are allowed to time out quietly.
      const nav = page.waitForNavigation({ waitUntil: 'domcontentloaded', timeout: Math.max(1000, timeoutMs || 20000) }).catch(() => null);
      const clicked = await page.click(String(selector), { timeout: 10000 }).then(() => true).catch(() => false);
      if (!clicked) return { ok: false, reason: 'no clickable element matched ' + JSON.stringify(String(selector)) };
      await nav;
      await page.waitForLoadState('networkidle', { timeout: Math.min(Math.max(1000, timeoutMs || 20000), 10000) }).catch(() => null);
      return { ok: true };
    },
    async html() { return page.content().catch(() => ''); },
  };
}

async function defaultDriverFactory({ context }) {
  const page = (context.pages && context.pages()[0]) || await context.newPage();
  return makePlaywrightDriver(page);
}

// Default launcher: patchright-core dynamically imported from tools/clearance/
// node_modules (the isolation doctrine — VARVEL core stays dependency-free, and this
// module still loads without it), driving REAL Chrome through a persistent context.
// executablePath is the binary we resolved; viewport:null avoids the fixed
// automation-viewport tell; userAgent is the vault's EXACT mint-time UA.
// proxy (optional): the chain's canonical single-hop URL from resolveRideTransport,
// applied as the context proxy in the EXACT shape of the broker's mint leg
// ({ server, username?, password? }) — the ride exits the same egress the clearance
// is bound to.
async function defaultLauncher({ chromePath: exe, headless, userDataDir, userAgent, proxy, proxyAuth }) {
  let chromium;
  try {
    ({ chromium } = await import(pathToFileURL(path.join(HERE, 'clearance', 'node_modules', 'patchright-core', 'index.mjs')).href));
  } catch (e) {
    throw new Error('patchright-core is missing at tools/clearance/node_modules -- run: cd tools/clearance && npm install --omit=dev (' + msg(e) + ')');
  }
  const dir = userDataDir || PROFILE_DIR;
  fs.mkdirSync(dir, { recursive: true });
  return chromium.launchPersistentContext(dir, {
    headless,
    executablePath: exe,
    viewport: null,
    userAgent,
    ...(proxy ? { proxy: { server: proxy, ...(proxyAuth || {}) } } : {}),
  });
}

// --- navigation + patience ---------------------------------------------------------

async function readDoc(driver) {
  const d = await driver.readDocument().catch(() => ({ url: '', html: null }));
  return d && typeof d === 'object' ? d : { url: '', html: null };
}

// settleAndClassify — poll until the document is READABLE and either clean or a full
// page embedding a widget. Blank/loading states AND challenge-dominated documents keep
// polling until the deadline: an interstitial may auto-resolve under us, and reading
// early is the broker's 2026-08-05 flash-close bug (it robbed the operator's tick).
// Only the deadline ends the wait; classification happens ONCE, at the end.
async function settleAndClassify(driver, { status = null, navSettleMs }) {
  const deadline = Date.now() + Math.max(200, Number(navSettleMs) || 15000);
  let doc = await readDoc(driver);
  for (;;) {
    const cls = classifyDocument(doc);
    const det = detectChallenge({ status: status == null ? 0 : status, headers: {}, body: String(doc.html || '') });
    const settled = cls.readable && (!det.present || !isChallengeInterstitial(det, doc.html));
    if (settled || Date.now() >= deadline) break;
    await sleep(Math.min(POLL_MS, Math.max(1, deadline - Date.now())));
    doc = await readDoc(driver);
  }
  return { doc, gate: navGate({ status, url: doc.url, html: doc.html }) };
}

// navAndGate — one navigation + the NAV GATE. Shared by every action and by
// probe-comment's re-navigation. Never throws.
async function navAndGate(driver, url, budget) {
  const nav = await driver.goto(url, { timeoutMs: budget.timeoutMs }).catch((e) => ({ error: msg(e) }));
  if (!nav || nav.error) return { ok: false, reason: 'navigation failed (' + ((nav && nav.error) || 'no response') + ')' };
  const s = await settleAndClassify(driver, { status: nav.status, navSettleMs: budget.navSettleMs });
  const status = nav.status == null ? null : nav.status;
  if (!s.gate.pass) return { ok: false, status, gate: s.gate.gate, reason: s.gate.reason, detection: s.gate.detection };
  return { ok: true, status, detection: s.gate.detection, embeddedInteractive: s.gate.embeddedInteractive === true };
}

// Post-submit gate: the response status is not capturable after a click-driven
// navigation, so the classification runs on the rendered document (status null).
async function postNavGate(driver, budget, what) {
  const s = await settleAndClassify(driver, { status: null, navSettleMs: budget.navSettleMs });
  if (!s.gate.pass) return { ok: false, reason: s.gate.reason + ' (' + what + ')', gate: s.gate.gate, detection: s.gate.detection };
  return { ok: true, detection: s.gate.detection, embedded: s.gate.embeddedInteractive === true };
}

// waitForInteractiveSolve — the HUMAN-IN-THE-LOOP wait. An embedded reCAPTCHA /
// Turnstile / hCaptcha widget is solved by the OPERATOR in the VISIBLE window; the
// tool polls the widget's hidden response field once a second and proceeds the moment
// a tick lands. It NEVER aborts early on an intermediate state; an expired budget is
// an honest failure that says exactly what to do.
async function waitForInteractiveSolve(driver, actionDeadline) {
  let state = await driver.interactiveState().catch(() => ({ present: false, solved: false }));
  if (!state || state.present !== true) return { ok: true, present: false };
  for (;;) {
    if (state.solved === true) return { ok: true, present: true, solved: true };
    const remaining = actionDeadline - Date.now();
    if (remaining <= 0) {
      return {
        ok: false,
        present: true,
        reason: 'interactive challenge (reCAPTCHA/Turnstile) present but not solved inside opts.timeoutMs — human-in-the-loop by design: the operator ticks it in the VISIBLE window while the tool polls; re-run and tick promptly, or pass a larger opts.timeoutMs',
      };
    }
    await sleep(Math.min(POLL_MS, remaining));
    state = await driver.interactiveState().catch(() => ({ present: true, solved: false }));
  }
}

// --- the actions -------------------------------------------------------------------

async function runAction(action, url, driver, clearance, opts, budget) {
  const identity = {
    engine: clearance.engine || 'operator-provided',
    uaBound: true,
    expiresAt: clearance.expiresAt,
    transport: clearance.rideTransport, // the egress this interaction actually took (the parity gate's decision)
    note: 'the browser rides the vaulted clearance — exact UA + cookies + egress; switching egress IP or UA invalidates it instantly',
  };

  // FIRST navigation + NAV GATE (shared by every action).
  const nav = await navAndGate(driver, url, budget);
  if (!nav.ok) return { ok: false, reason: nav.reason, gate: nav.gate || null, status: nav.status, detection: nav.detection || null };

  if (action === 'open') {
    return {
      ok: true,
      status: nav.status,
      title: await driver.title().catch(() => ''),
      textSnippet: await driver.visibleText(2048).catch(() => ''),
      links: await driver.links(50).catch(() => []),
      embeddedInteractive: nav.embeddedInteractive,
      identity,
      detection: nav.detection,
    };
  }

  if (action === 'forms') {
    const raw = await driver.formsRaw().catch(() => ({ forms: [], pageHtml: '' }));
    const forms = (Array.isArray(raw.forms) ? raw.forms : []).map((f) => classifyForm(f, raw));
    return { ok: true, status: nav.status, forms, embeddedInteractive: nav.embeddedInteractive, identity, detection: nav.detection };
  }

  if (action === 'fill-submit') {
    const fields = (opts.fields && typeof opts.fields === 'object') ? opts.fields : {};
    if (!Object.keys(fields).length) return { ok: false, reason: 'fill-submit needs opts.fields = {selectorOrName: value} — nothing to fill' };
    if (!opts.submitSelector) return { ok: false, reason: 'fill-submit needs opts.submitSelector (css of the submit control)' };
    const raw = await driver.formsRaw().catch(() => ({ forms: [], pageHtml: '' }));
    const forms = (Array.isArray(raw.forms) ? raw.forms : []).map((f) => classifyForm(f, raw));
    // THE PASSWORD GUARD: a form carrying a password field establishes a PRIVILEGED
    // session (a login, or a registration that logs straight in). Automation never
    // self-authorizes that — the operator reviews target + fields and the CLI passes
    // operatorApproved:true through. Guarded BEFORE anything is typed.
    const insidePwd = await driver.submitInsidePasswordForm(opts.submitSelector).catch(() => null);
    const passwordInvolved = fieldsTouchPassword(forms, fields) || insidePwd === true;
    if (passwordInvolved && opts.operatorApproved !== true) {
      return {
        ok: false,
        reason: 'REFUSED: the target form carries a password field — auto-submitting it would establish a PRIVILEGED session, which is operator-gated by doctrine. Review target + fields, then re-run with operatorApproved:true.',
        passwordInvolved: true,
        forms,
        status: nav.status,
        detection: nav.detection,
      };
    }
    const fills = [];
    for (const [k, v] of Object.entries(fields)) {
      const r = await driver.fill(k, v).catch((e) => ({ ok: false, reason: msg(e) }));
      fills.push({ field: k, via: r.via || null, ok: r.ok === true, ...(r.ok === true ? {} : { reason: r.reason || 'fill failed' }) });
    }
    const failed = fills.filter((f) => !f.ok);
    if (failed.length) {
      return { ok: false, reason: 'could not fill ' + failed.length + ' field(s): ' + failed.map((f) => f.field + ' (' + f.reason + ')').join('; '), fills, forms, status: nav.status, detection: nav.detection };
    }
    // HUMAN-IN-THE-LOOP: an interactive widget guarding the form is ticked by the
    // operator in the visible window; the tool polls patiently, never aborts early.
    const solve = await waitForInteractiveSolve(driver, budget.actionDeadline);
    if (!solve.ok) return { ok: false, reason: solve.reason, fills, forms, status: nav.status, detection: nav.detection };
    const before = await driver.currentUrl().catch(() => url);
    const click = await driver.clickAndSettle(opts.submitSelector, { timeoutMs: budget.submitSettleMs }).catch((e) => ({ ok: false, reason: msg(e) }));
    if (!click.ok) return { ok: false, reason: 'submit click failed: ' + click.reason, fills, forms, status: nav.status, detection: nav.detection };
    const post = await postNavGate(driver, budget, 'post-submit navigation');
    const after = await driver.currentUrl().catch(() => '');
    if (!post.ok) return { ok: false, reason: post.reason, gate: post.gate || null, before, after, fills, detection: post.detection || null };
    return {
      ok: true,
      before,
      after,
      statusText: await driver.visibleText(2048).catch(() => ''),
      fills,
      forms,
      embeddedInteractive: nav.embeddedInteractive || post.embedded,
      identity,
      detection: post.detection,
    };
  }

  // 'probe-comment' — the sanitization MEASUREMENT (never an exploit: the body is
  // three benign fragments + a unique marker; no javascript: URLs, no <script>).
  const marker = opts.marker ? String(opts.marker) : ('varvel-probe-' + Date.now());
  if (!opts.fieldSelector) return { ok: false, reason: 'probe-comment needs opts.fieldSelector (css/name of the comment textarea)' };
  if (!opts.submitSelector) return { ok: false, reason: 'probe-comment needs opts.submitSelector (css of the comment submit control)' };
  const raw = await driver.formsRaw().catch(() => ({ forms: [], pageHtml: '' }));
  const forms = (Array.isArray(raw.forms) ? raw.forms : []).map((f) => classifyForm(f, raw));
  // The password guard runs here too: a comment form has no password field, but
  // pointing this action at a login form must not slip a privileged submit through.
  const insidePwd = await driver.submitInsidePasswordForm(opts.submitSelector).catch(() => null);
  if ((fieldsTouchPassword(forms, { body: probeCommentBody(marker) }) || insidePwd === true) && opts.operatorApproved !== true) {
    return {
      ok: false,
      reason: 'REFUSED: the submit control sits on a password-carrying form — privileged session establishment is operator-gated. Re-run with operatorApproved:true if the operator approves.',
      passwordInvolved: true,
      forms,
      status: nav.status,
      detection: nav.detection,
    };
  }
  const body = probeCommentBody(marker);
  const fill = await driver.fill(opts.fieldSelector, body).catch((e) => ({ ok: false, reason: msg(e) }));
  if (!fill.ok) return { ok: false, reason: 'could not fill the comment field ' + JSON.stringify(String(opts.fieldSelector)) + ' (' + (fill.reason || 'fill failed') + ')', marker, forms, status: nav.status, detection: nav.detection };
  const solve = await waitForInteractiveSolve(driver, budget.actionDeadline);
  if (!solve.ok) return { ok: false, reason: solve.reason, marker, status: nav.status, detection: nav.detection };
  const click = await driver.clickAndSettle(opts.submitSelector, { timeoutMs: budget.submitSettleMs }).catch((e) => ({ ok: false, reason: msg(e) }));
  if (!click.ok) return { ok: false, reason: 'comment submit click failed: ' + click.reason, marker, status: nav.status, detection: nav.detection };
  const post = await postNavGate(driver, budget, 'post-comment navigation');
  if (!post.ok) return { ok: false, reason: post.reason, gate: post.gate || null, marker, detection: post.detection || null };
  // RE-NAVIGATE the page and diff the re-served HTML for verbatim fragments.
  const renav = await navAndGate(driver, url, budget);
  if (!renav.ok) return { ok: false, reason: renav.reason, gate: renav.gate || null, marker, detection: renav.detection || null };
  const html = await driver.html().catch(() => '');
  const diff = survivalDiff(html, marker);
  return {
    ok: true,
    marker,
    survived: diff.survived,
    markerFound: diff.markerFound,
    note: diff.markerFound
      ? 'sanitization measured on the re-served page — survived{} says which benign fragments came back verbatim'
      : 'marker NOT found on the re-served page — the comment is likely HELD FOR MODERATION (WordPress default for fresh identities) or fully stripped; that is an honest measurement, not a tool failure',
    identity,
    detection: renav.detection,
  };
}

// cfbrowse(action, url, opts) — one browser-interaction action as the vaulted
// identity. Never throws; the browser context ALWAYS closes.
export async function cfbrowse(action, url, opts = {}) {
  const o = opts || {};
  const {
    egressId = 'direct',
    vaultPath,
    clearanceLookup,
    chromePath,
    env,
    exists,
    launcher,
    driverFactory,
    ghost,
    ghostMode,
    engagement,
    headless = false, // default = VISIBLE window on the operator's machine; headless:true is allowed but measurably weaker against 2026 bot gates
    timeoutMs = 120000, // generous on purpose: most of it is reserved for the operator's human-in-the-loop tick
    navSettleMs = 15000, // patience window for loading/blank/auto-solving intermediate states
    submitSettleMs = 20000, // post-click navigation/networkidle-ish settle
    userDataDir,
  } = o;
  try {
    if (!ACTIONS.has(action)) {
      return { ok: false, reason: 'unknown action ' + JSON.stringify(String(action)) + ' — expected open | forms | fill-submit | probe-comment' };
    }
    const zone = zoneOf(url);
    if (!zone) return { ok: false, reason: 'cfbrowse needs an absolute http(s) URL — got ' + JSON.stringify(String(url)) };

    // 1) THE VAULTED IDENTITY — no valid clearance, no interaction.
    const lookup = clearanceLookup || clearanceFor;
    const c = await lookup(String(url), { egressId, ...(vaultPath ? { vaultPath } : {}) }).catch(() => null);
    if (!c) return { ok: false, reason: 'no valid clearance in the vault for this zone — mint (clearance mint) or provide operator clearance first' };
    if (!c.ua) return { ok: false, reason: 'the vault entry carries no UA — cf_clearance is bound to the exact mint-time User-Agent, so an entry without one cannot be ridden faithfully' };

    // 1b) THE EGRESS PARITY GATE — the browser must exit the SAME egress the vaulted
    // clearance is bound to (cf_clearance is IP-bound). Resolved BEFORE any window
    // opens; refusals are fail-closed and honest. A chain-keyed entry maps to the
    // chain's single-hop context proxy; a multi-hop chain is unrideable by a browser.
    const st = ghost ? { ghost, ghostMode: ghostMode || ghost.mode } : ghostRideState(engagement);
    const rideT = await resolveRideTransport({ ghost: st.ghost, ghostMode: st.ghostMode, egressId, hostname: new URL(String(url)).hostname });
    if (!rideT.ok) return { ok: false, reason: rideT.reason };
    if (rideT.multiHop) {
      return { ok: false, reason: 'the vaulted clearance is bound to a multi-hop ghost chain (egressId "' + egressId + '") but a browser rides exactly ONE proxy hop -- launching through only the first hop would bind the session to the WRONG exit IP. REFUSED (fail-closed): configure a single-hop chain, or re-mint with --direct-egress.' };
    }

    // 2) A REAL BROWSER BINARY — the interaction must run in the same browser class
    // the clearance was minted in; a bundled Chromium is a different, weaker tell.
    const chrome = (env !== undefined || exists !== undefined) ? resolveChrome({ chromePath, env, exists }) : resolveChrome({ chromePath });
    if (!chrome) {
      return { ok: false, reason: 'no REAL Chrome/Edge binary found (checked opts.chromePath, env CHROME_PATH, both well-known Chrome paths, both well-known Edge paths) — interaction as the cleared identity needs a real browser, not a bundled Chromium; install Chrome or pass chromePath' };
    }

    // 3) LAUNCH, SEED, DRIVE — the context closes no matter what happens below. The
    // launch rides the gate's transport: proxy/proxyAuth set on a chain-keyed entry,
    // absent on a direct one.
    const launch = launcher || defaultLauncher;
    let context;
    try {
      context = await launch({ chromePath: chrome.p, chromeVia: chrome.via, headless, userDataDir, userAgent: c.ua, proxy: rideT.proxy, proxyAuth: rideT.proxyAuth });
    } catch (e) {
      return { ok: false, reason: 'browser launch failed via ' + chrome.via + ' (' + chrome.p + '): ' + msg(e) };
    }
    try {
      const cookies = seedCookies(c.cookies, zone);
      if (cookies.length) {
        if (typeof context.addCookies !== 'function') throw new Error('the launched context exposes no addCookies');
        await context.addCookies(cookies).catch((e) => { throw new Error('vault cookies could not be seeded into the context (' + msg(e) + ')'); });
      }
      const mkDriver = driverFactory || defaultDriverFactory;
      const driver = await mkDriver({ context, timeoutMs });
      const budget = { timeoutMs, navSettleMs, submitSettleMs, actionDeadline: Date.now() + Math.max(1000, timeoutMs) };
      return await runAction(action, String(url), driver, { ...c, rideTransport: rideT.transport }, o, budget);
    } finally {
      await Promise.resolve(context.close && context.close()).catch(() => {});
    }
  } catch (e) {
    return { ok: false, reason: 'cfbrowse failed: ' + msg(e) };
  }
}
