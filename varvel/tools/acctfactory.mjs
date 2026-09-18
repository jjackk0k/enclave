// VARVEL — acctfactory: the ACCOUNT FACTORY (hunting-tools build, Tool 1).
//
// Bug-bounty auth oracles (tools/authzsweep.mjs) starve without provisioned
// accounts on distinct tenants. This engine turns account provisioning into
// CONFIG, not code: a declarative RECIPE ({signupUrl, selector hints, activation
// type, mfa, sessionCapture}) drives the pipeline
//
//   inbox (mail.tm REST) → signup (browser driver) → activation (email-code /
//   email-link) → TOTP MFA enrollment (RFC6238, zero-dep) → session capture
//
// and emits an account record {label, email, password?, totpSecret, cookies,
// bearer, provisionedAt}. mintRoleMatrix() runs N recipes and assigns the
// 4-ROLE MATRIX ['owner','member','lowpriv','unauth-control']; toAuthzAccounts()
// folds the result into the exact account shapes sanitizeAuthzCfg consumes
// ({label,cookie} | {label,headers} | {label,login}).
//
// ORACLE CONTRACT: an account is only 'provisioned' when session capture returns
// at least one cookie OR a bearer token — a signup that cannot produce a session
// is reported as ok:false with the failing step named, never as a half-account.
//
// GOVERNANCE: mail.tm is INFRASTRUCTURE (temp inbox), not target traffic — its
// client goes direct by default but accepts `agents`. All TARGET traffic (the
// browser) rides the ghost chain: the playwright driver factory pins
// proxy socks5://10.64.0.1:1080. Every function returns structured results and
// NEVER throws. Budget {maxRequests, maxMs} honored — exhaustion logs
// 'budget.exhausted' via onLog and stops the run honestly.
//
// CAPS: ACCT_CAPS. Browser access is behind an injectable driver interface so
// tests run a fake; the real driver (playwrightDriverFactory) is the .tmp/
// fe-login.mjs pattern productized (headless:false, persistent profile,
// shadow-DOM-tolerant selectors).
//
// usage:
//   import { provisionAccount, mintRoleMatrix, MailTmClient } from './tools/acctfactory.mjs';
//   const r = await provisionAccount(recipe, { mailtm: new MailTmClient({}), driver, onLog });
//   const m = await mintRoleMatrix(recipe, { count: 4, mailtmFactory, driverFactory });
//   const cfg = sanitizeAuthzCfg({ accounts: toAuthzAccounts(m.accounts), writes: true });

import http from 'node:http';
import https from 'node:https';
import { execFile } from 'node:child_process';
import { existsSync, unlinkSync, renameSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { randomBytes, createHmac } from 'node:crypto';

export const ACCT_CAPS = { maxAccounts: 8, maxHints: 8, maxPollMs: 120000, pollMs: 3000, bodySnippet: 400, maxCookieDomains: 8 };

export const ROLE_MATRIX = ['owner', 'member', 'lowpriv', 'unauth-control'];

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const logTo = (onLog, obj) => { if (typeof onLog === 'function') { try { onLog(obj); } catch { /* observer never breaks the factory */ } } };

// ——— budget discipline (house contract — every tool carries one) ———
function makeBudget(budget, onLog) {
  const b = { maxRequests: Number.isFinite(budget && budget.maxRequests) ? budget.maxRequests : Infinity, maxMs: Number.isFinite(budget && budget.maxMs) ? budget.maxMs : Infinity, used: 0, t0: Date.now() };
  return {
    spend(what) {
      const elapsed = Date.now() - b.t0;
      if (b.used >= b.maxRequests || elapsed >= b.maxMs) {
        logTo(onLog, { type: 'budget.exhausted', tool: 'acctfactory', what, used: b.used, maxRequests: b.maxRequests, elapsedMs: elapsed, maxMs: b.maxMs });
        return false;
      }
      b.used += 1;
      return true;
    },
    state: () => ({ used: b.used, maxRequests: b.maxRequests, elapsedMs: Date.now() - b.t0, maxMs: b.maxMs }),
  };
}

// ——— TOTP (RFC 6238, HMAC-SHA1, 30s step, 6 digits) — zero deps ———
// Verified against the RFC 6238 Appendix B vectors (SHA-1 column, mod 10^6) in
// test/acctfactory.test.mjs. Reused verbatim from .tmp/fe-login.mjs (proven
// against frontegg's enrollment flow).
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export function b32dec(s) {
  const clean = String(s || '').replace(/=+$/g, '').replace(/[\s-]/g, '').toUpperCase();
  let bits = 0, val = 0; const out = [];
  for (const c of clean) {
    const i = B32.indexOf(c);
    if (i < 0) return null; // honest: not base32
    val = (val << 5) | i; bits += 5;
    if (bits >= 8) { out.push((val >> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(out);
}
export function totp(secret, when = Date.now()) {
  const key = b32dec(secret);
  if (!key || !key.length) return null;
  const buf = Buffer.alloc(8); buf.writeBigUInt64BE(BigInt(Math.floor(when / 30000)));
  const h = createHmac('sha1', key).update(buf).digest();
  const off = h[h.length - 1] & 0xf;
  return String((h.readUInt32BE(off) & 0x7fffffff) % 1e6).padStart(6, '0');
}
// RFC 4648 base32 encode — the mock MFA site in tests mints setup keys with it.
export function b32enc(buf) {
  let bits = 0, val = 0, out = '';
  for (const byte of buf) { val = (val << 8) | byte; bits += 8; while (bits >= 5) { out += B32[(val >> (bits - 5)) & 31]; bits -= 5; } }
  if (bits > 0) out += B32[(val << (5 - bits)) & 31];
  return out;
}

// ——— transport (never throws) — the authzsweep fire() shape, JSON-aware ———
// agents: { http, https } — ghost-riding agents from engine/ghost.mjs agents()
// (wired by the campaign; mail.tm defaults to direct because the inbox is OUR
// infrastructure, not the target).
function fireJson(url, { method = 'GET', body = null, token = null, timeout = 15000, agents = null } = {}) {
  return new Promise((resolve) => {
    let u;
    try { u = new URL(url); } catch { return resolve(null); }
    const lib = u.protocol === 'https:' ? https : http;
    const headers = { 'user-agent': 'VARVEL-acctfactory' };
    if (body != null) headers['content-type'] = 'application/json';
    if (token) headers.authorization = 'Bearer ' + token;
    const req = lib.request({ hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80), path: u.pathname + u.search, method, timeout, headers, agent: agents ? agents[u.protocol === 'https:' ? 'https' : 'http'] : undefined }, (res) => {
      let b = ''; res.on('data', (d) => { if (b.length < 262144) b += d; });
      res.on('end', () => { let json = null; try { json = JSON.parse(b); } catch { /* non-JSON is fine — honest null */ } resolve({ status: res.statusCode, headers: res.headers, json, body: b }); });
    });
    req.on('error', () => resolve(null)); req.on('timeout', () => { req.destroy(); resolve(null); });
    if (body != null) req.write(typeof body === 'string' ? body : JSON.stringify(body));
    req.end();
  });
}

// ——— curl transport (live-path workaround for fingerprint throttling) ———
// mail.tm's edge rate-limits Node's TLS/HTTP fingerprint on POST /accounts
// (verified 2026-08-31: curl POST → 201 while BOTH undici and https.request
// POST → 429/504 from the same IP in the same minute; GETs unaffected). The
// library default stays the zero-dep node transport (tests, healthy networks);
// the CLI injects this one. Never throws; null on any transport failure.
export function curlJsonTransport({ bin = 'curl' } = {}) {
  return (url, { method = 'GET', body = null, token = null, timeout = 15000 } = {}) => new Promise((resolvePromise) => {
    const args = ['-sS', '-m', String(Math.max(1, Math.ceil(timeout / 1000))), '-X', method,
      '-H', 'user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0'];
    if (body != null) args.push('-H', 'content-type: application/json');
    if (token) args.push('-H', 'authorization: Bearer ' + token);
    if (body != null) args.push('--data-binary', typeof body === 'string' ? body : JSON.stringify(body));
    args.push('-w', '\n%{http_code}', url);
    execFile(bin, args, { timeout: timeout + 5000, maxBuffer: 1024 * 1024 }, (err, stdout) => {
      const out = String(stdout || '');
      const m = /\n(\d{3})\s*$/.exec(out);
      if (!m) return resolvePromise(null); // curl itself failed or output malformed — honest null
      const text = out.slice(0, out.length - m[0].length);
      let json = null; try { json = JSON.parse(text); } catch { /* non-JSON is fine — honest null */ }
      resolvePromise({ status: Number(m[1]), headers: {}, json, body: text });
    });
  });
}

// ——— mail.tm REST client (API shape ported from .tmp/mailtm-helper.py) ———
// GET  /domains              → { 'hydra:member': [{ domain, isActive }] }
// POST /accounts             → { address, password } → { id }
// POST /token                → { address, password } → { token }
// GET  /messages             → (Bearer) { 'hydra:member': [{ id, from, subject, createdAt, intro }] }
// GET  /messages/{id}        → (Bearer) { text, html: [] }
export class MailTmClient {
  constructor({ baseUrl = 'https://api.mail.tm', agents = null, timeout = 15000, pacer = null, budget = null, onLog = null, retry = null, sleepMs = null, transport = null } = {}) {
    this.baseUrl = String(baseUrl).replace(/\/$/, '');
    this.agents = agents; this.timeout = timeout; this.pacer = pacer;
    this.budget = makeBudget(budget, onLog); this.onLog = onLog;
    this.transport = transport; // injectable (e.g. curlJsonTransport for the fingerprint-throttled live path); default: zero-dep node fireJson
    // bounded retry on 429/5xx/transport (mail.tm rate-limits account creation
    // per IP); default 3 tries with 30s+ backoff. sleepMs injectable for tests.
    this.retry = { max: retry && Number.isFinite(retry.max) ? Math.max(1, retry.max) : 3, backoffMs: retry && Array.isArray(retry.backoffMs) && retry.backoffMs.length ? retry.backoffMs : [30000, 60000, 120000] };
    this.sleepMs = typeof sleepMs === 'function' ? sleepMs : sleep;
    // failure detail is NEVER swallowed: the last failing op, its HTTP status,
    // and a body snippet land here for callers to name in their errors.
    this.lastError = null;
  }
  _retryable(r) { return !r || r.status === 429 || r.status >= 500; }
  _backoff(attempt) { return this.retry.backoffMs[Math.min(attempt, this.retry.backoffMs.length - 1)]; }
  _recordError(op, r, attempt, reason = null) {
    this.lastError = { op, status: r && Number.isFinite(r.status) ? r.status : null, bodySnippet: r && typeof r.body === 'string' ? r.body.slice(0, ACCT_CAPS.bodySnippet) : null, attempt, reason };
  }
  async _req(method, path, body, token) {
    if (this.pacer && typeof this.pacer.pace === 'function') await this.pacer.pace();
    if (!this.budget.spend('mailtm:' + method + ' ' + path)) return null;
    if (this.transport) return this.transport(this.baseUrl + path, { method, body, token, timeout: this.timeout });
    return fireJson(this.baseUrl + path, { method, body, token, timeout: this.timeout, agents: this.agents });
  }
  async domains() {
    const r = await this._req('GET', '/domains');
    const members = r && r.json && r.json['hydra:member'];
    return Array.isArray(members) ? members.filter((d) => d && d.isActive && d.domain).map((d) => d.domain) : [];
  }
  // createAccount(localPart) → { address, password, token } | null (honest).
  // EVERY attempt mints a FRESH random address — a stored/deterministic address
  // that is already registered is the classic 409 trap. A 409 is NOT fatal:
  // the address exists and we hold the password, so we proceed to the token.
  // 429/5xx/transport failures retry with backoff (this.retry); a final failure
  // leaves lastError naming the op + HTTP status + body snippet.
  async createAccount(localPart = 'varvel') {
    this.lastError = null;
    const doms = await this.domains();
    if (!doms.length) { this.lastError = { op: 'GET /domains', status: null, attempt: 0, reason: 'no active mail.tm domains' }; return null; }
    for (let attempt = 0; attempt < this.retry.max; attempt++) {
      if (attempt > 0) await this.sleepMs(this._backoff(attempt - 1));
      const local = String(localPart).replace(/[^a-z0-9-]/gi, '').toLowerCase().slice(0, 24) + '-' + randomBytes(3).toString('hex');
      const address = `${local}@${doms[0]}`;
      const password = 'Vv!' + randomBytes(9).toString('base64url') + 'xZ9';
      const a = await this._req('POST', '/accounts', { address, password });
      if (a && (a.status < 400 || a.status === 409)) {
        if (a.status === 409) logTo(this.onLog, { type: 'acctfactory.mailtm-409', address, note: 'address already registered — proceeding to token with the password we hold' });
        const t = await this._tokenWithRetry(address, password);
        if (t) return { address, password, token: t };
        return null; // _tokenWithRetry set lastError
      }
      this._recordError('POST /accounts', a, attempt + 1);
      if (!this._retryable(a) || attempt === this.retry.max - 1) return null;
      logTo(this.onLog, { type: 'acctfactory.mailtm-retry', op: 'POST /accounts', status: a ? a.status : null, attempt: attempt + 1, nextBackoffMs: this._backoff(attempt) });
    }
    return null;
  }
  async _tokenWithRetry(address, password) {
    for (let attempt = 0; attempt < this.retry.max; attempt++) {
      if (attempt > 0) await this.sleepMs(this._backoff(attempt - 1));
      const t = await this._req('POST', '/token', { address, password });
      if (t && t.json && t.json.token) return t.json.token;
      this._recordError('POST /token', t, attempt + 1);
      if (!this._retryable(t)) return null;
    }
    return null;
  }
  async token(address, password) {
    // retry-backed like createAccount's token leg — the pre-provisioned-inbox
    // path depends on this surviving a transient 429/5xx
    return this._tokenWithRetry(address, password);
  }
  async messages(token) {
    const r = await this._req('GET', '/messages', null, token);
    const members = r && r.json && r.json['hydra:member'];
    return Array.isArray(members) ? members : [];
  }
  async message(id, token) {
    const r = await this._req('GET', '/messages/' + encodeURIComponent(id), null, token);
    if (!r || !r.json) return null;
    return { subject: r.json.subject || '', text: r.json.text || '', html: Array.isArray(r.json.html) ? r.json.html.join('\n') : '' };
  }
  // waitForMatch — poll the inbox until a message newer than notBefore carries
  // a match for `pattern` (RegExp with one capture group). Null on deadline.
  async waitForMatch({ token, notBefore = 0, pattern, maxMs = ACCT_CAPS.maxPollMs, pollMs = ACCT_CAPS.pollMs } = {}) {
    const end = Date.now() + Math.min(maxMs, ACCT_CAPS.maxPollMs);
    while (Date.now() < end) {
      const msgs = await this.messages(token);
      for (const m of msgs) {
        if (m.createdAt && new Date(m.createdAt).getTime() < notBefore) continue;
        const full = await this.message(m.id, token);
        if (!full) continue;
        const hit = (full.text + '\n' + full.html).match(pattern);
        if (hit) return { match: hit[1] || hit[0], subject: full.subject, messageId: m.id };
      }
      await sleep(pollMs);
    }
    return null;
  }
  waitForCode(opts) { return this.waitForMatch({ ...opts, pattern: (opts && opts.pattern) || /\b(\d{4,8})\b/ }); }
  waitForLink(opts) { return this.waitForMatch({ ...opts, pattern: (opts && opts.pattern) || /(https?:\/\/[^\s"'<>]+)/ }); }
}

// ——— the recipe (declarative — new targets are config, not code) ———
// mailTmError(m) — render a MailTmClient's lastError into an error string.
// The house rule: an inbox failure NAMES the op and the HTTP status; a bare
// "creation failed" is a swallowed diagnostic and a bug.
export function mailTmError(m) {
  const e = m && m.lastError;
  if (!e) return ' (no active domain, or the API refused without detail)';
  return ` (${e.op} → ${e.status == null ? 'transport failure' : 'HTTP ' + e.status}${e.reason ? ': ' + e.reason : ''}${e.bodySnippet ? ': ' + String(e.bodySnippet).slice(0, 120) : ''}${e.attempt ? `, attempt ${e.attempt}` : ''})`;
}
const hints = (x, dflt) => {
  const arr = (Array.isArray(x) ? x : dflt).filter((h) => typeof h === 'string' && h).map((h) => h.toLowerCase()).slice(0, ACCT_CAPS.maxHints);
  return arr.length ? arr : dflt;
};
// sanitizeRecipe(x) → normalized recipe or null. Never throws.
export function sanitizeRecipe(x) {
  if (!x || typeof x !== 'object') return null;
  if (typeof x.signupUrl !== 'string' || !/^https?:\/\//i.test(x.signupUrl)) return null;
  const actIn = x.activation && typeof x.activation === 'object' ? x.activation : {};
  const activation = ['email-code', 'email-link'].includes(actIn.type) ? {
    type: actIn.type,
    codeInputHints: hints(actIn.codeInputHints, ['code', 'otp', 'verification']),
    linkPattern: typeof actIn.linkPattern === 'string' ? actIn.linkPattern : null,
    activateButtonText: actIn.activateButtonText || ['Verify', 'Continue', 'Confirm'],
  } : null;
  const mfaIn = x.mfa && typeof x.mfa === 'object' ? x.mfa : {};
  const mfa = mfaIn.required ? {
    required: true, strategy: 'totp', // totp only — sms/voice are out of lane
    setupKeyHints: hints(mfaIn.setupKeyHints, ['setup-key', 'secret', 'otpauth']),
    codeInputHints: hints(mfaIn.codeInputHints, ['code', 'otp', 'mfa', 'authenticator']),
  } : { required: false };
  const scIn = x.sessionCapture && typeof x.sessionCapture === 'object' ? x.sessionCapture : {};
  // ——— the 'captcha: handoff' primitive ———
  // recipe.captcha: 'handoff' | { mode:'handoff', timeoutMs, pollMs, after:['signup','activate'] }.
  // The flow PAUSES for the operator on a detected challenge (tools/captchaassist.mjs);
  // we never auto-solve. after defaults to ['signup'].
  const capIn = x.captcha;
  let captcha = null;
  if (capIn === 'handoff' || (capIn && typeof capIn === 'object' && capIn.mode === 'handoff')) {
    const c = typeof capIn === 'object' ? capIn : {};
    const after = (Array.isArray(c.after) ? c.after : ['signup']).filter((a) => a === 'signup' || a === 'activate');
    captcha = {
      mode: 'handoff',
      timeoutMs: Number.isFinite(c.timeoutMs) ? c.timeoutMs : null,
      pollMs: Number.isFinite(c.pollMs) ? c.pollMs : null,
      after: after.length ? [...new Set(after)] : ['signup'],
    };
  }
  return {
    signupUrl: x.signupUrl,
    emailSelectorHints: hints(x.emailSelectorHints, ['email', '@', 'e-mail']),
    passwordSelectorHints: hints(x.passwordSelectorHints, ['password']),
    submitButtonText: x.submitButtonText || ['Sign up', 'Create account', 'Register', 'Continue'],
    activation, mfa, captcha,
    sessionCapture: {
      cookieDomains: Array.isArray(scIn.cookieDomains) ? scIn.cookieDomains.filter((d) => typeof d === 'string').slice(0, ACCT_CAPS.maxCookieDomains) : [],
      bearerFrom: typeof scIn.bearerFrom === 'string' ? scIn.bearerFrom : null, // 'localStorage:<key>'
    },
  };
}

// ——— the browser driver interface (injectable — tests run a fake) ———
//   goto(url)                       → { ok, url }
//   fillByHints(hints, value)       → bool   (placeholder/name/type/label match)
//   clickByText(texts)              → bool   (texts: string | string[])
//   enterCode(hints, code)          → bool   (single box OR per-digit boxes)
//   findText(hints, regex)          → string | null  (hint-scoped elements, then body)
//   cookies(domains)                → [{ name, value, domain }]
//   readStorage(area, key)          → string | null  (area: 'localStorage'|'sessionStorage')
//   currentUrl()                    → string
//   screenshot?(tag)                → optional evidence hook
//   close()                         → void
// The real implementation is playwrightDriverFactory() below; the .tmp/
// fe-login.mjs run proved every one of these moves against a live shadow-DOM SPA.

// ——— provisionAccount: the recipe state machine ———
// provisionAccount(recipe, { label, mailtm, driver, pacer, budget, onLog, password })
// → { ok, account?, step?, error?, steps } — NEVER throws. steps[] records every
// state transition with its status so a failure names exactly where it died.
export async function provisionAccount(recipeIn, { label = 'acct', mailtm, driver, pacer = null, budget = null, onLog = null, password = null, handoff = null, program = null } = {}) {
  const steps = [];
  const fail = (step, error, extra = {}) => ({ ok: false, step, error, steps, ...extra });
  const recipe = sanitizeRecipe(recipeIn);
  if (!recipe) return fail('validate', 'recipe rejected by sanitizeRecipe (need signupUrl http(s)://; activation.type email-code|email-link when activation set)');
  if (!mailtm || typeof mailtm.createAccount !== 'function') return fail('validate', 'a MailTmClient (or compatible) is required');
  if (!driver || typeof driver.goto !== 'function') return fail('validate', 'a browser driver implementing the driver interface is required');
  const bd = makeBudget(budget, onLog);
  const pace = async () => { if (pacer && typeof pacer.pace === 'function') await pacer.pace(); };
  // the captcha handoff rail — injected in tests; lazily the real captchaassist
  // primitive otherwise. Called as handoff(driver, { step, timeoutMs, pollMs }).
  const getHandoff = async () => {
    if (handoff) return handoff;
    const m = await import('./captchaassist.mjs');
    return m.captchaHandoff({ program: program || 'acctfactory', label, onLog });
  };
  const runHandoff = async (stepName) => {
    const hf = await getHandoff();
    // post-submit/post-activation handoffs are EXPLICIT gates: short grace for
    // the challenge dialog to render, and inert anchor widgets never pause.
    const h = await hf(driver, { step: stepName, mode: 'explicit', timeoutMs: recipe.captcha.timeoutMs || undefined, pollMs: recipe.captcha.pollMs || undefined });
    if (!h.ok) return h;
    steps.push({ step: 'captcha', ok: true, at: stepName, state: h.state, signal: h.signal || null });
    logTo(onLog, { type: 'acctfactory.captcha', label, at: stepName, state: h.state, signal: h.signal || null });
    return h;
  };

  try {
    // ——— state: INBOX — temp mailbox (infrastructure, not target traffic) ———
    if (!bd.spend('inbox')) return fail('inbox', 'budget exhausted before the inbox was minted');
    const inbox = await mailtm.createAccount(label);
    if (!inbox) return fail('inbox', 'mail.tm account creation failed' + mailTmError(mailtm));
    const email = inbox.address;
    steps.push({ step: 'inbox', ok: true, email });
    logTo(onLog, { type: 'acctfactory.inbox', label, email });

    // ——— state: SIGNUP — drive the target's signup form (target traffic) ———
    if (!bd.spend('signup')) return fail('signup', 'budget exhausted before signup', { partial: { email } });
    await pace();
    const landed = await driver.goto(recipe.signupUrl);
    if (!landed || landed.ok === false) return fail('signup', 'signup page did not load', { partial: { email } });
    if (!await driver.fillByHints(recipe.emailSelectorHints, email)) return fail('signup', 'email input not found (hints: ' + recipe.emailSelectorHints.join(',') + ')', { partial: { email } });
    const acctPassword = password || ('Vv!' + randomBytes(9).toString('base64url') + 'xZ9');
    const wantsPassword = await driver.fillByHints(recipe.passwordSelectorHints, acctPassword); // passwordless flows have no field — not fatal
    await pace();
    if (!await driver.clickByText(recipe.submitButtonText)) return fail('signup', 'submit button not found (' + [].concat(recipe.submitButtonText).join('/') + ')', { partial: { email } });
    steps.push({ step: 'signup', ok: true, passwordFields: !!wantsPassword });
    logTo(onLog, { type: 'acctfactory.signup', label, url: recipe.signupUrl });

    // ——— state: CAPTCHA HANDOFF (post-submit) — the operator solves, we wait ———
    if (recipe.captcha && recipe.captcha.after.includes('signup')) {
      const h = await runHandoff('signup');
      if (!h.ok) return fail('captcha', `${h.state} after signup submit: ${h.reason || 'operator handoff did not verify'} — no session harvested, nothing claimed`, { partial: { email } });
    }

    // ——— state: ACTIVATE — email-code or email-link ———
    const mailStart = Date.now();
    if (recipe.activation) {
      if (!bd.spend('activate')) return fail('activate', 'budget exhausted before activation', { partial: { email, password: wantsPassword ? acctPassword : null } });
      if (recipe.activation.type === 'email-code') {
        const got = await mailtm.waitForCode({ token: inbox.token, notBefore: mailStart - 60000 });
        if (!got) return fail('activate', 'no activation code arrived before the deadline', { partial: { email } });
        if (!await driver.enterCode(recipe.activation.codeInputHints, got.match)) return fail('activate', 'code input not found (hints: ' + recipe.activation.codeInputHints.join(',') + ')', { partial: { email } });
        await driver.clickByText(recipe.activation.activateButtonText); // some flows auto-submit — not fatal
        steps.push({ step: 'activate', ok: true, via: 'email-code' });
      } else { // email-link
        const pattern = recipe.activation.linkPattern ? new RegExp('(' + recipe.activation.linkPattern + ')') : null;
        const got = await mailtm.waitForLink({ token: inbox.token, notBefore: mailStart - 60000, pattern: pattern || undefined });
        if (!got) return fail('activate', 'no activation link arrived before the deadline', { partial: { email } });
        await pace();
        const nav = await driver.goto(got.match);
        if (!nav || nav.ok === false) return fail('activate', 'activation link did not load', { partial: { email } });
        steps.push({ step: 'activate', ok: true, via: 'email-link' });
      }
      logTo(onLog, { type: 'acctfactory.activated', label, via: recipe.activation.type });
      // ——— state: CAPTCHA HANDOFF (post-activation) — same rail, second gate ———
      if (recipe.captcha && recipe.captcha.after.includes('activate')) {
        const h = await runHandoff('activate');
        if (!h.ok) return fail('captcha', `${h.state} after activation: ${h.reason || 'operator handoff did not verify'} — no session harvested, nothing claimed`, { partial: { email } });
      }
    }

    // ——— state: MFA — TOTP enrollment (RFC6238 local codes) ———
    let totpSecret = null;
    if (recipe.mfa.required) {
      if (!bd.spend('mfa')) return fail('mfa', 'budget exhausted before MFA enrollment', { partial: { email } });
      // the setup key is rendered as an input value OR styled shadow-DOM text —
      // the driver searches hint-scoped elements first, then the whole body
      totpSecret = await driver.findText(recipe.mfa.setupKeyHints, /\b([A-Z2-7]{16,64})\b/);
      if (!totpSecret) return fail('mfa', 'no TOTP setup key found (hints: ' + recipe.mfa.setupKeyHints.join(',') + ')', { partial: { email } });
      const code = totp(totpSecret);
      if (!code) return fail('mfa', 'setup key is not valid base32', { partial: { email } });
      if (!await driver.enterCode(recipe.mfa.codeInputHints, code)) return fail('mfa', 'MFA code input not found', { partial: { email } });
      await driver.clickByText(['Verify', 'Continue', 'Enroll', 'Next']);
      steps.push({ step: 'mfa', ok: true, strategy: 'totp' });
      logTo(onLog, { type: 'acctfactory.mfa', label, strategy: 'totp', keyChars: totpSecret.length });
    }

    // ——— state: CAPTURE — the oracle contract: no session, no account ———
    if (!bd.spend('capture')) return fail('capture', 'budget exhausted before session capture', { partial: { email } });
    const cookies = (await driver.cookies(recipe.sessionCapture.cookieDomains)) || [];
    let bearer = null;
    if (recipe.sessionCapture.bearerFrom) {
      const m = recipe.sessionCapture.bearerFrom.match(/^(localStorage|sessionStorage):(.+)$/);
      if (m) bearer = await driver.readStorage(m[1], m[2]);
    }
    if (!cookies.length && !bearer) return fail('capture', 'session capture empty — no cookies, no bearer; the signup cannot back an oracle account', { partial: { email } });

    const account = {
      label, email,
      password: wantsPassword ? acctPassword : null,
      totpSecret,
      cookies: cookies.map((c) => ({ name: c.name, value: c.value, domain: c.domain })),
      bearer,
      finalUrl: typeof driver.currentUrl === 'function' ? driver.currentUrl() : null,
      provisionedAt: new Date().toISOString(),
    };
    steps.push({ step: 'capture', ok: true, cookies: account.cookies.length, bearer: !!bearer });
    logTo(onLog, { type: 'acctfactory.provisioned', label, email, cookies: account.cookies.length, bearer: !!bearer });
    return { ok: true, account, steps, budget: bd.state() };
  } catch (e) {
    // the factory NEVER throws — a driver bug lands as an honest failure
    return fail('exception', String((e && e.message) || e));
  }
}

// ——— the 4-role matrix ———
// mintRoleMatrix(recipe, { count, roles, mailtmFactory, driverFactory, ...opts })
// Runs `count` recipe provisions (sequential — paced), assigns roles in order.
// 'unauth-control' is the no-auth CONTROL: it gets a placeholder entry with NO
// session (authzsweep's unauth control is the null-cookie send — minting a real
// account for it would be waste and confusion). Never throws.
export async function mintRoleMatrix(recipe, { count = ROLE_MATRIX.length, roles = ROLE_MATRIX, mailtmFactory, driverFactory, ...opts } = {}) {
  const out = { ok: true, accounts: [], failed: [], roles: roles.slice(0, ACCT_CAPS.maxAccounts) };
  const n = Math.min(Math.max(1, count | 0), ACCT_CAPS.maxAccounts);
  for (let i = 0; i < n; i++) {
    const role = out.roles[i] || ('role-' + i);
    const label = role;
    if (role === 'unauth-control') {
      out.accounts.push({ label, role, cookie: null, headers: null, control: true, note: 'unauthenticated control — no session by design; authzsweep fires it as the null-cookie send' });
      continue;
    }
    const mailtm = typeof mailtmFactory === 'function' ? mailtmFactory(i) : null;
    const driver = typeof driverFactory === 'function' ? await driverFactory(i) : null;
    const r = await provisionAccount(recipe, { ...opts, label, mailtm, driver });
    if (r.ok) {
      out.accounts.push({ ...r.account, role });
    } else {
      out.failed.push({ role, step: r.step, error: r.error });
      logTo(opts.onLog, { type: 'acctfactory.role-failed', role, step: r.step, error: r.error });
    }
    if (driver && typeof driver.close === 'function') { try { await driver.close(); } catch { /* closing is best-effort */ } }
  }
  if (!out.accounts.some((a) => a.cookies && a.cookies.length) && !out.accounts.some((a) => a.bearer)) {
    out.ok = false;
    out.error = 'no provisioned account carries a session — the matrix cannot back an authz oracle';
  }
  return out;
}

// toAuthzAccounts(accounts) → the exact account shapes sanitizeAuthzCfg
// consumes: cookies → { label, cookie }, bearer → { label, headers:
// { authorization } }. The unauth-control placeholder is dropped — the sweep's
// control is the null-cookie send, not an account. Never throws.
export function toAuthzAccounts(accounts) {
  const out = [];
  for (const a of accounts || []) {
    if (!a || a.control) continue;
    if (Array.isArray(a.cookies) && a.cookies.length) {
      out.push({ label: a.label || 'account', cookie: a.cookies.map((c) => `${c.name}=${c.value}`).join('; ') });
    } else if (a.bearer) {
      out.push({ label: a.label || 'account', headers: { authorization: 'Bearer ' + a.bearer } });
    }
  }
  return out;
}

// ——— stale Firefox profile lock cleanup ———
// A crashed or killed run leaves parent.lock (Windows) / .parentlock (POSIX) /
// .startup-incomplete behind, and the next launchPersistentContext then hangs
// for minutes. Remove stale locks pre-launch. The OS REFUSING the delete
// (EBUSY/EPERM/EACCES) is the live-process signal — that lock is kept, logged,
// never forced. Never throws.
export function cleanStaleProfileLocks(profileDir, { onLog = null } = {}) {
  const out = { removed: [], kept: [], missing: [] };
  if (!profileDir) return out;
  for (const name of ['parent.lock', '.parentlock', '.startup-incomplete']) {
    const p = join(profileDir, name);
    if (!existsSync(p)) { out.missing.push(name); continue; }
    try {
      unlinkSync(p);
      out.removed.push(name);
      logTo(onLog, { type: 'acctfactory.stale-lock-removed', profileDir, lock: name });
    } catch (e) {
      out.kept.push({ lock: name, reason: String((e && e.code) || e) });
      logTo(onLog, { type: 'acctfactory.lock-kept', profileDir, lock: name, reason: String((e && e.code) || e) });
    }
  }
  return out;
}

// ——— stale profile-holder reaping ———
// cleanStaleProfileLocks removes lock FILES; but a crashed/killed run can also
// leave a live firefox.exe whose -profile argument IS our automation profile —
// that process holds the profile and the next launchPersistentContext hangs
// until its 180s timeout (observed 2026-08-31, ff-semrush-a). Reap ONLY
// processes whose command line names OUR exact profile dir — the operator's
// own browser is never touched. listProcesses/killProcess injectable for
// tests. Never throws.
export async function killProfileHolders(profileDir, { onLog = null, listProcesses = null, killProcess = null } = {}) {
  const out = { killed: [], skipped: [], scanned: 0 };
  if (!profileDir) return out;
  const needle = String(profileDir).toLowerCase();
  const list = listProcesses || (async () => {
    if (process.platform === 'win32') {
      const { stdout } = await new Promise((res) => {
        execFile('powershell', ['-NoProfile', '-Command', "Get-CimInstance Win32_Process -Filter \"Name='firefox.exe'\" | ForEach-Object { \"$($_.ProcessId)`t$($_.CommandLine)\" }"], { timeout: 20000 }, (err, stdout) => res({ stdout: stdout || '' }));
      });
      return stdout.split(/\r?\n/).map((line) => {
        const m = /^(\d+)\t(.*)$/.exec(line);
        return m ? { pid: Number(m[1]), commandLine: m[2] } : null;
      }).filter(Boolean);
    }
    const { stdout } = await new Promise((res) => {
      execFile('ps', ['-eo', 'pid,args'], { timeout: 10000 }, (err, stdout) => res({ stdout: stdout || '' }));
    });
    return stdout.split(/\r?\n/).map((line) => {
      const m = /^\s*(\d+)\s+(.*)$/.exec(line);
      return m ? { pid: Number(m[1]), commandLine: m[2] } : null;
    }).filter(Boolean);
  });
  const kill = killProcess || (async (pid) => {
    if (process.platform === 'win32') {
      return new Promise((res) => { execFile('taskkill', ['/F', '/PID', String(pid)], { timeout: 10000 }, (err) => res(!err)); });
    }
    try { process.kill(pid, 'SIGKILL'); return true; } catch { return false; }
  });
  let procs = [];
  try { procs = (await list()) || []; } catch (e) { logTo(onLog, { type: 'acctfactory.process-scan-failed', reason: String((e && e.message) || e) }); return out; }
  out.scanned = procs.length;
  for (const p of procs) {
    const cl = String(p.commandLine || '').toLowerCase();
    if (!/firefox/.test(cl) || !cl.includes(needle)) { out.skipped.push(p.pid); continue; }
    const okKill = await kill(p.pid);
    if (okKill) { out.killed.push(p.pid); logTo(onLog, { type: 'acctfactory.profile-holder-killed', profileDir, pid: p.pid }); }
    else logTo(onLog, { type: 'acctfactory.profile-holder-unkillable', profileDir, pid: p.pid });
  }
  return out;
}

// ——— corrupt-profile quarantine ———
// Repeated hard kills can wedge an automation profile so launchPersistentContext
// hangs until timeout even with locks cleaned (observed live 2026-08-31 on
// ff-semrush-a; a fresh profile launches in ~2s). Automation profiles are
// disposable — harvested sessions live in the broker, not the profile — so on
// launch failure the rail renames the profile aside and retries ONCE fresh.
// Rename, never delete: the evidence survives. Never throws.
export function quarantineProfile(profileDir, { onLog = null } = {}) {
  try {
    if (!profileDir || !existsSync(profileDir)) return { quarantined: null };
    const dest = profileDir + '.quarantine-' + new Date().toISOString().replace(/[:.]/g, '-');
    renameSync(profileDir, dest);
    logTo(onLog, { type: 'acctfactory.profile-quarantined', profileDir, to: dest });
    return { quarantined: dest };
  } catch (e) {
    logTo(onLog, { type: 'acctfactory.profile-quarantine-failed', profileDir, reason: String((e && e.message) || e) });
    return { quarantined: null, error: String((e && e.message) || e) };
  }
}

// ——— the real driver: playwright-core Firefox, ghost-proxied ———
// The .tmp/fe-login.mjs pattern productized: persistent profile, headless:false
// (WAF-proofing), proxy pinned to the ghost chain. Lazy import — the module
// loads zero-dep; playwright is only touched when a real browser is requested.
// MANUAL smoke only (needs a Firefox binary + the chain); tests use a fake.
export async function playwrightDriverFactory({ profileDir, proxy = 'socks5://10.64.0.1:1080', headless = false, extraHTTPHeaders = null, onLog = null, launchTimeoutMs = 60000 } = {}) {
  cleanStaleProfileLocks(profileDir, { onLog });        // a stale lock file hangs the launch
  await killProfileHolders(profileDir, { onLog });      // a zombie firefox holding the profile hangs it too
  const { firefox } = await import('playwright-core');
  const launchOpts = {
    headless,
    proxy: proxy ? { server: proxy } : undefined,
    extraHTTPHeaders: extraHTTPHeaders || undefined,
    viewport: { width: 1280, height: 900 },
    timeout: launchTimeoutMs, // fail in 60s, not playwright's 180s default
  };
  let ctx;
  try {
    ctx = await firefox.launchPersistentContext(profileDir, launchOpts);
  } catch (e1) {
    // wedged profile → reap the just-timed-out attempt's OWN lingering firefox
    // (it holds the dir and would block the quarantine rename), THEN rename the
    // profile aside and retry ONCE with a fresh one.
    logTo(onLog, { type: 'acctfactory.launch-failed', profileDir, error: String((e1 && e1.message) || e1).slice(0, 200) });
    await killProfileHolders(profileDir, { onLog });
    cleanStaleProfileLocks(profileDir, { onLog });
    const q = quarantineProfile(profileDir, { onLog });
    if (!q.quarantined) throw e1; // could not move it aside — honest propagate
    mkdirSync(profileDir, { recursive: true });
    ctx = await firefox.launchPersistentContext(profileDir, launchOpts); // a second failure propagates honestly
  }
  const page = ctx.pages()[0] || (await ctx.newPage());
  const asArray = (x) => [].concat(x);
  return {
    async goto(url) {
      const t0 = Date.now();
      logTo(onLog, { type: 'acctfactory.goto-start', url });
      try { await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 90000 }); await sleep(3000); logTo(onLog, { type: 'acctfactory.goto-done', url: page.url(), ms: Date.now() - t0 }); return { ok: true, url: page.url() }; }
      catch (e) { logTo(onLog, { type: 'acctfactory.goto-failed', url, ms: Date.now() - t0, error: String(e && e.message || e).slice(0, 200) }); return { ok: false, url, error: String(e && e.message || e) }; }
    },
    // shadow-DOM tolerant: playwright's node-side selectors pierce shadow roots
    async fillByHints(hnt, value) {
      for (const h of asArray(hnt)) {
        const el = await page.$(`input[placeholder*="${h}" i], input[name*="${h}" i], input[id*="${h}" i], input[aria-label*="${h}" i]${h.includes('@') || h.includes('email') ? ', input[type=email]' : ''}${h.includes('password') ? ', input[type=password]' : ''}`);
        if (el) { await el.fill(value); return true; }
      }
      return false;
    },
    async clickByText(texts) {
      for (const t of asArray(texts)) {
        try { await page.click(`button:has-text("${t}"), [role=button]:has-text("${t}"), input[type=submit][value*="${t}" i]`, { timeout: 5000 }); return true; } catch { /* try the next label */ }
      }
      return false;
    },
    // single 6-digit box OR the per-digit box farm (the fe-login pattern)
    async enterCode(hnt, code) {
      for (const h of asArray(hnt)) {
        const single = await page.$(`input[name*="${h}" i], input[id*="${h}" i], input[placeholder*="${h}" i], input[maxlength="${String(code).length}"], input[inputmode=numeric]`);
        if (single) { await single.fill(code); return true; }
      }
      const boxes = await page.$$('input[maxlength="1"]');
      if (boxes.length >= String(code).length) {
        for (let i = 0; i < String(code).length; i++) await boxes[i].fill(String(code)[i]);
        return true;
      }
      return false;
    },
    // hint-scoped inputs first, then a shadow-root deep-walk of leaf text nodes
    async findText(hnt, regex) {
      for (const h of asArray(hnt)) {
        const el = await page.$(`[class*="${h}"], [id*="${h}"], input[name*="${h}" i]`);
        if (el) {
          const v = ((await el.evaluate((e) => e.innerText || e.value || '')).trim()).replace(/[\s-]/g, '');
          const m = v.match(regex);
          if (m) return m[1] || m[0];
        }
      }
      const r = await page.evaluate((reSrc) => {
        const re = new RegExp(reSrc);
        const texts = [];
        const walk = (root) => {
          for (const el of root.querySelectorAll('*')) {
            if (el.shadowRoot) walk(el.shadowRoot);
            if (!el.children || el.children.length === 0) {
              const t = (el.textContent || '').trim().replace(/[\s-]/g, '');
              if (t && t.length >= 12 && t.length <= 80) texts.push(t);
            }
          }
        };
        walk(document);
        const hit = texts.find((t) => re.test(t));
        return hit ? (hit.match(re)[1] || hit.match(re)[0]) : null;
      }, regex.source);
      return r;
    },
    async cookies(domains) {
      const all = await ctx.cookies();
      const ds = asArray(domains);
      return all.filter((c) => !ds.length || ds.some((d) => String(c.domain).includes(d))).map((c) => ({ name: c.name, value: c.value, domain: c.domain }));
    },
    async readStorage(area, key) {
      try { return await page.evaluate(([a, k]) => (a === 'sessionStorage' ? sessionStorage : localStorage).getItem(k), [area, key]); } catch { return null; }
    },
    // captcha-handoff probe (tools/captchaassist.mjs): raw in-page observations
    // classified node-side. null on probe failure — never read as "no challenge".
    async detectChallenge(opts = {}) {
      try {
        const { challengePageProbe, classifyProbe } = await import('./captchaassist.mjs');
        const raw = await page.evaluate(challengePageProbe, { progressHints: (opts && opts.progressHints) || [] });
        return classifyProbe(raw, opts);
      } catch { return null; }
    },
    async bodyText() {
      try { return await page.evaluate(() => (document.body ? String(document.body.innerText || '').slice(0, 8000) : '')); } catch { return null; }
    },
    currentUrl() { return page.url(); },
    // escape hatch: the raw page handle. captchaassist's runner rebinds
    // detectChallenge against this when it is the CLI entry module — see the
    // top-level-await deadlock note in runHandoffFlow.
    _page: page,
    async screenshot(tag) { try { return await page.screenshot({ path: `${profileDir}/acctfactory-${tag}.png` }); } catch { return null; } },
    async close() { try { await ctx.close(); } catch { /* best-effort */ } },
  };
}
