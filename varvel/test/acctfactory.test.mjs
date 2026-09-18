// VARVEL acctfactory tests — RFC6238 vectors, mail.tm against a local mock, the
// recipe state machine against a fake-driver mock signup site, the 4-role matrix,
// budget honesty. No live network, no real browser.
//   node --test varvel/test/acctfactory.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { randomBytes } from 'node:crypto';
import { b32dec, b32enc, totp, MailTmClient, sanitizeRecipe, provisionAccount, mintRoleMatrix, toAuthzAccounts, cleanStaleProfileLocks, mailTmError } from '../tools/acctfactory.mjs';
import { sanitizeAuthzCfg } from '../tools/authzsweep.mjs';

// ——— pure: TOTP against the RFC 6238 Appendix B published vectors ———
// SHA-1 column, secret = ASCII '12345678901234567890' (base32 GEZDGNBV…);
// our 6-digit window is the published 8-digit value mod 10^6.
test('totp: RFC 6238 Appendix B SHA-1 vectors (mod 10^6)', () => {
  const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
  assert.equal(totp(secret, 59000), '287082');        // T=59s      → 94287082
  assert.equal(totp(secret, 1111111109000), '081804'); // T=1111111109 → 07081804
  assert.equal(totp(secret, 1111111111000), '050471'); // T=1111111111 → 14050471
  assert.equal(totp(secret, 1234567890000), '005924'); // T=1234567890 → 89005924
  assert.equal(totp(secret, 2000000000000), '279037'); // T=2000000000 → 69279037
});

test('b32dec/b32enc: roundtrip + honest rejection of non-base32', () => {
  assert.deepEqual(b32dec('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'), Buffer.from('12345678901234567890'));
  const key = b32enc(randomBytes(10));
  assert.match(key, /^[A-Z2-7]{16}$/);
  assert.equal(totp(key), totp(key), 'deterministic');
  assert.equal(b32dec('not!base32!'), null);
  assert.equal(totp('!!!'), null, 'invalid secret → null, not a crash');
});

// ——— a local mock mail.tm (the API shape from .tmp/mailtm-helper.py) ———
function createMockMailTm() {
  const accounts = new Map(); // address → { password, token }
  const inbox = new Map();    // token → [messages]
  const chaos = { accountFail: null }; // { times, status, registerOn409 } — fault injection
  let seq = 0;
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    let body = '';
    req.on('data', (d) => { body += d; });
    req.on('end', () => {
      const json = (code, obj) => { res.writeHead(code, { 'content-type': 'application/json' }); res.end(JSON.stringify(obj)); };
      if (u.pathname === '/domains') return json(200, { 'hydra:member': [{ domain: 'lab.test', isActive: true }, { domain: 'dead.test', isActive: false }] });
      if (u.pathname === '/accounts' && req.method === 'POST') {
        const { address, password } = JSON.parse(body || '{}');
        // fault injection: force N failing responses (429/5xx/…); a 409 with
        // registerOn409 models "address already exists AND we hold the password"
        if (chaos.accountFail && chaos.accountFail.times > 0) {
          chaos.accountFail.times--;
          if (chaos.accountFail.status === 409 && chaos.accountFail.registerOn409) {
            const token = 'tok-' + (++seq);
            accounts.set(address, { password, token });
            inbox.set(token, []);
          }
          return json(chaos.accountFail.status, { error: 'chaos-injected', code: chaos.accountFail.status });
        }
        if (accounts.has(address)) return json(409, { error: 'Account already exists' });
        const token = 'tok-' + (++seq);
        accounts.set(address, { password, token });
        inbox.set(token, []);
        return json(201, { id: 'acct-' + seq, address });
      }
      if (u.pathname === '/token' && req.method === 'POST') {
        const { address, password } = JSON.parse(body || '{}');
        const a = accounts.get(address);
        return a && a.password === password ? json(200, { token: a.token }) : json(401, {});
      }
      const token = String(req.headers.authorization || '').replace(/^Bearer /, '');
      if (u.pathname === '/messages' && req.method === 'GET') {
        if (!inbox.has(token)) return json(401, {});
        return json(200, { 'hydra:member': inbox.get(token).map((m) => ({ id: m.id, from: m.from, subject: m.subject, createdAt: m.createdAt, intro: m.text.slice(0, 40) })) });
      }
      const mm = u.pathname.match(/^\/messages\/([\w-]+)$/);
      if (mm && req.method === 'GET') {
        const msg = (inbox.get(token) || []).find((m) => m.id === mm[1]);
        return msg ? json(200, { subject: msg.subject, text: msg.text, html: [] }) : json(404, {});
      }
      // test-side injection: deliver a message to an address
      if (u.pathname === '/_inject' && req.method === 'POST') {
        const { address, text, subject } = JSON.parse(body || '{}');
        const a = accounts.get(address);
        if (!a) return json(404, { error: 'unknown address' });
        inbox.get(a.token).push({ id: 'msg-' + (++seq), from: { address: 'noreply@target.test' }, subject: subject || 'Your code', createdAt: new Date().toISOString(), text });
        return json(200, { ok: true });
      }
      // test-side fault injection control
      if (u.pathname === '/_chaos' && req.method === 'POST') {
        chaos.accountFail = JSON.parse(body || '{}').accountFail || null;
        return json(200, { ok: true });
      }
      json(404, { error: 'not found' });
    });
  });
  srv.on('clientError', (e, sock) => { try { sock.destroy(); } catch {} });
  return srv;
}

async function withMockMail(fn) {
  const srv = createMockMailTm();
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  const inject = async (address, text, subject) => {
    await fetch(base + '/_inject', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ address, text, subject }) });
  };
  try { return await fn(base, inject); }
  finally { await new Promise((r) => srv.close(r)); }
}

test('MailTmClient: create → token → inject → waitForCode, all against the local mock', () => withMockMail(async (base, inject) => {
  const c = new MailTmClient({ baseUrl: base, timeout: 2000 });
  const acct = await c.createAccount('varvel-test');
  assert.ok(acct && acct.address.endsWith('@lab.test') && acct.token, 'account minted on the active domain');
  await inject(acct.address, 'Hello! Your verification code is 482913. It expires soon.');
  const got = await c.waitForCode({ token: acct.token, notBefore: Date.now() - 5000, pollMs: 50, maxMs: 2000 });
  assert.equal(got.match, '482913');
  const none = await c.waitForCode({ token: acct.token, notBefore: Date.now() + 60000, pollMs: 50, maxMs: 300 });
  assert.equal(none, null, 'no fresh message → honest null on deadline');
}));

// ——— the fake browser driver: a mock signup site behind the driver interface ———
class FakeDriver {
  constructor(mailBase) {
    this.mailBase = mailBase;
    this.stage = 'signup';       // signup → verify → mfa → done
    this.values = {};
    this.setupKey = b32enc(randomBytes(10));
    this.expectedCode = null;
    this.email = null;
    this.visits = [];
  }
  async goto(url) { this.visits.push(url); return { ok: url.includes('target.test'), url }; }
  async fillByHints(hints, value) {
    const field = this.stage === 'signup'
      ? ['email', 'password'].find((f) => hints.some((h) => f.includes(h) || (f === 'email' && h === '@')))
      : null;
    if (!field) return false;
    this.values[field] = value;
    if (field === 'email') this.email = value;
    return true;
  }
  async clickByText(texts) {
    const labels = [].concat(texts);
    if (this.stage === 'signup' && labels.includes('Sign up')) {
      // the mock site "sends" the activation email via the mock mail.tm
      this.expectedCode = String(100000 + (randomBytes(4).readUInt32BE(0) % 900000));
      await fetch(this.mailBase + '/_inject', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ address: this.email, text: `Your verification code is ${this.expectedCode}.` }) });
      this.stage = 'verify';
      return true;
    }
    if (this.stage === 'verify' && labels.some((t) => ['Verify', 'Continue', 'Confirm'].includes(t))) {
      if (this.values.code !== this.expectedCode) return true; // wrong code: site stays put
      this.stage = 'mfa';
      return true;
    }
    if (this.stage === 'mfa' && labels.some((t) => ['Verify', 'Continue', 'Enroll', 'Next'].includes(t))) {
      if (this.values.mfacode === totp(this.setupKey)) this.stage = 'done';
      return true;
    }
    return false;
  }
  async enterCode(hints, code) {
    if (this.stage === 'verify') { this.values.code = code; return true; }
    if (this.stage === 'mfa') { this.values.mfacode = code; return true; }
    return false;
  }
  async findText(hints, regex) {
    if (this.stage !== 'mfa') return null;
    const text = `Scan the QR or enter setup key ${this.setupKey} manually`;
    const m = text.match(regex);
    return m ? (m[1] || m[0]) : null;
  }
  async cookies(domains) {
    return this.stage === 'done' ? [{ name: 'sid', value: 'sess-' + this.email, domain: 'target.test' }] : [];
  }
  async readStorage(area, key) {
    return this.stage === 'done' && area === 'localStorage' && key === 'token' ? 'bearer-' + this.email.split('@')[0] : null;
  }
  currentUrl() { return this.stage === 'done' ? 'https://target.test/app' : 'https://target.test/' + this.stage; }
  async close() {}
}

const RECIPE = {
  signupUrl: 'https://target.test/signup',
  emailSelectorHints: ['email', '@'],
  passwordSelectorHints: ['password'],
  submitButtonText: 'Sign up',
  activation: { type: 'email-code', codeInputHints: ['code'], activateButtonText: 'Verify' },
  mfa: { required: true, strategy: 'totp', setupKeyHints: ['setup key'], codeInputHints: ['code'] },
  sessionCapture: { cookieDomains: ['target.test'], bearerFrom: 'localStorage:token' },
};

test('sanitizeRecipe: shape validation, defaults, honest nulls', () => {
  assert.equal(sanitizeRecipe(null), null);
  assert.equal(sanitizeRecipe({}), null);
  assert.equal(sanitizeRecipe({ signupUrl: 'ftp://x' }), null);
  const r = sanitizeRecipe(RECIPE);
  assert.equal(r.activation.type, 'email-code');
  assert.equal(r.mfa.strategy, 'totp');
  assert.deepEqual(sanitizeRecipe({ signupUrl: 'https://x.test/s' }).activation, null, 'activation optional (passwordless-instant sites)');
  assert.equal(sanitizeRecipe({ signupUrl: 'https://x.test/s' }).mfa.required, false);
});

test('provisionAccount: full recipe state machine — inbox → signup → code → TOTP → session', () => withMockMail(async (mailBase) => {
  const mailtm = new MailTmClient({ baseUrl: mailBase, timeout: 2000 });
  const driver = new FakeDriver(mailBase);
  const r = await provisionAccount(RECIPE, { label: 'owner', mailtm, driver });
  assert.equal(r.ok, true, r.error);
  assert.ok(r.account.email.endsWith('@lab.test'));
  assert.equal(r.account.totpSecret, driver.setupKey, 'the enrolled TOTP secret is captured');
  assert.ok(r.account.password, 'password-carrying recipe records the password');
  assert.equal(r.account.cookies[0].name, 'sid');
  assert.ok(r.account.bearer, 'bearer captured from localStorage');
  assert.deepEqual(r.steps.map((s) => s.step), ['inbox', 'signup', 'activate', 'mfa', 'capture']);
  // the oracle's acceptance gate: the record feeds sanitizeAuthzCfg
  const cfg = sanitizeAuthzCfg({ accounts: [...toAuthzAccounts([r.account]), { label: 'b', cookie: 'x=1' }] });
  assert.ok(cfg && cfg.accounts.length === 2, 'authzsweep accepts the minted account shape');
}));

test('provisionAccount: honest failure names the dying step — never throws', () => withMockMail(async (mailBase) => {
  const mailtm = new MailTmClient({ baseUrl: mailBase, timeout: 2000 });
  // driver whose signup page has no email field
  const dead = { async goto() { return { ok: true, url: 'x' }; }, async fillByHints() { return false; }, async clickByText() { return false; } };
  const r = await provisionAccount(RECIPE, { label: 'doomed', mailtm, driver: dead });
  assert.equal(r.ok, false);
  assert.equal(r.step, 'signup');
  assert.match(r.error, /email input not found/);
  // driver that explodes mid-flow → honest exception record, not a throw
  const boom = { async goto() { throw new Error('renderer crashed'); } };
  const r2 = await provisionAccount(RECIPE, { label: 'boom', mailtm, driver: boom });
  assert.equal(r2.ok, false);
  assert.equal(r2.step, 'exception');
  assert.match(r2.error, /renderer crashed/);
  // bad inputs rejected before any network
  const r3 = await provisionAccount({}, {});
  assert.equal(r3.ok, false);
  assert.equal(r3.step, 'validate');
}));

test('mintRoleMatrix: 4-role matrix, unauth-control is a sessionless placeholder, shapes feed authzsweep', () => withMockMail(async (mailBase) => {
  const m = await mintRoleMatrix(RECIPE, {
    count: 4,
    mailtmFactory: () => new MailTmClient({ baseUrl: mailBase, timeout: 2000 }),
    driverFactory: async () => new FakeDriver(mailBase),
  });
  assert.equal(m.ok, true, m.error);
  assert.equal(m.accounts.length, 4);
  assert.deepEqual(m.accounts.map((a) => a.role), ['owner', 'member', 'lowpriv', 'unauth-control']);
  const ctl = m.accounts.find((a) => a.role === 'unauth-control');
  assert.equal(ctl.control, true);
  assert.equal(ctl.cookie, null, 'the unauth control carries NO session by design');
  const authz = toAuthzAccounts(m.accounts);
  assert.equal(authz.length, 3, 'placeholder dropped — the sweep fires its own null-cookie control');
  const cfg = sanitizeAuthzCfg({ accounts: authz, writes: true });
  assert.ok(cfg, 'the matrix backs the two-account oracle directly');
  assert.ok(cfg.accounts.every((a) => a.cookie || a.headers));
}));

test('budget: exhaustion stops the run honestly and logs budget.exhausted', () => withMockMail(async (mailBase) => {
  const logs = [];
  const mailtm = new MailTmClient({ baseUrl: mailBase, timeout: 2000 });
  const driver = new FakeDriver(mailBase);
  const r = await provisionAccount(RECIPE, { label: 'poor', mailtm, driver, budget: { maxRequests: 1 }, onLog: (l) => logs.push(l) });
  assert.equal(r.ok, false);
  assert.equal(r.step, 'signup', 'one request bought the inbox; signup was refused by the budget');
  assert.ok(logs.some((l) => l.type === 'budget.exhausted' && l.tool === 'acctfactory'));
}));

// ——— bug #2 regressions (2026-08-31): the captchaassist rail's inbox step ———
// Symptom was a bare "mail.tm account creation failed". Pins: 409 → proceed to
// token; 429 → bounded retry with backoff then success; failure surfaces the
// HTTP status; stale Firefox profile locks are cleaned pre-launch.

test('MailTmClient: 409 already-registered proceeds to the token (we hold the password)', () => withMockMail(async (base) => {
  await fetch(base + '/_chaos', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ accountFail: { times: 1, status: 409, registerOn409: true } }) });
  const c = new MailTmClient({ baseUrl: base, timeout: 2000, retry: { max: 2, backoffMs: [5] }, sleepMs: async () => {} });
  const acct = await c.createAccount('varvel-409');
  assert.ok(acct && acct.token, '409 was treated as already-exists → token succeeded');
  assert.equal(c.lastError, null, 'a recovered handoff leaves no error behind');
}));

test('MailTmClient: 429 retries with backoff, then succeeds; attempt log is emitted', () => withMockMail(async (base) => {
  await fetch(base + '/_chaos', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ accountFail: { times: 2, status: 429 } }) });
  const logs = [];
  const c = new MailTmClient({ baseUrl: base, timeout: 2000, retry: { max: 3, backoffMs: [5, 5] }, sleepMs: async () => {}, onLog: (l) => logs.push(l) });
  const acct = await c.createAccount('varvel-429');
  assert.ok(acct && acct.token, 'third attempt succeeded after two 429s');
  assert.equal(logs.filter((l) => l.type === 'acctfactory.mailtm-retry').length, 2, 'each 429 logged with its status');
  assert.ok(logs.every((l) => l.status === 429));
}));

test('MailTmClient: unrecoverable refusal surfaces the HTTP status in lastError — never swallowed', () => withMockMail(async (base) => {
  await fetch(base + '/_chaos', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ accountFail: { times: 10, status: 422 } }) });
  const c = new MailTmClient({ baseUrl: base, timeout: 2000, retry: { max: 3, backoffMs: [5] }, sleepMs: async () => {} });
  const none = await c.createAccount('varvel-422');
  assert.equal(none, null);
  assert.equal(c.lastError.op, 'POST /accounts');
  assert.equal(c.lastError.status, 422, 'the refusal status is named');
  assert.ok(String(mailTmError(c)).includes('HTTP 422'));
  // and a retryable status that never recovers also names itself after the last try
  await fetch(base + '/_chaos', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ accountFail: { times: 10, status: 429 } }) });
  const c2 = new MailTmClient({ baseUrl: base, timeout: 2000, retry: { max: 2, backoffMs: [5] }, sleepMs: async () => {} });
  assert.equal(await c2.createAccount('varvel-429x'), null);
  assert.equal(c2.lastError.status, 429);
  assert.equal(c2.lastError.attempt, 2, 'the final attempt number is recorded');
}));

test('provisionAccount: inbox failure names the mail.tm HTTP status (bug #2 symptom pin)', () => withMockMail(async (base) => {
  await fetch(base + '/_chaos', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ accountFail: { times: 10, status: 429 } }) });
  const c = new MailTmClient({ baseUrl: base, timeout: 2000, retry: { max: 2, backoffMs: [5] }, sleepMs: async () => {} });
  const r = await provisionAccount(RECIPE, { label: 'doomed', mailtm: c, driver: new FakeDriver(base) });
  assert.equal(r.ok, false);
  assert.equal(r.step, 'inbox');
  assert.match(r.error, /HTTP 429/, 'the status rides the error — no more bare "creation failed"');
}));

test('cleanStaleProfileLocks: stale parent.lock/.startup-incomplete removed, missing tolerated, never throws', async () => {
  const { mkdtempSync, writeFileSync, existsSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const dir = mkdtempSync(join(tmpdir(), 'ffprof-'));
  writeFileSync(join(dir, 'parent.lock'), 'pid 1234');
  writeFileSync(join(dir, '.startup-incomplete'), '1');
  const logs = [];
  const r = cleanStaleProfileLocks(dir, { onLog: (l) => logs.push(l) });
  assert.deepEqual([...r.removed].sort(), ['.startup-incomplete', 'parent.lock']);
  assert.ok(!existsSync(join(dir, 'parent.lock')), 'stale lock gone');
  assert.ok(!existsSync(join(dir, '.startup-incomplete')), 'startup-incomplete gone');
  assert.deepEqual(r.missing, ['.parentlock']);
  assert.equal(logs.filter((l) => l.type === 'acctfactory.stale-lock-removed').length, 2);
  // a profile dir that does not exist at all → honest empty result, no throw
  const r2 = cleanStaleProfileLocks(join(dir, 'does-not-exist'));
  assert.deepEqual(r2.removed, []);
  assert.deepEqual(r2.kept, []);
  assert.equal(cleanStaleProfileLocks(null).removed.length, 0);
});

test('MailTmClient + curlJsonTransport: the fingerprint-throttled live path works against the local mock', () => withMockMail(async (base, inject) => {
  const { curlJsonTransport } = await import('../tools/acctfactory.mjs');
  const c = new MailTmClient({ baseUrl: base, timeout: 5000, transport: curlJsonTransport() });
  const acct = await c.createAccount('varvel-curl');
  assert.ok(acct && acct.address.endsWith('@lab.test') && acct.token, 'createAccount rides the curl transport end-to-end');
  await inject(acct.address, 'Your verification code is 735190.');
  const got = await c.waitForCode({ token: acct.token, notBefore: Date.now() - 5000, pollMs: 50, maxMs: 3000 });
  assert.equal(got.match, '735190', 'authenticated GETs ride the same transport');
}));

test('killProfileHolders: reaps ONLY firefox processes holding OUR exact profile; operator browser untouched', async () => {
  const { killProfileHolders } = await import('../tools/acctfactory.mjs');
  const killed = [];
  const listProcesses = async () => [
    { pid: 111, commandLine: 'C:/Firefox/firefox.exe -profile C:/repo/.tmp/ff-semrush-a -juggler-pipe about:blank' },
    { pid: 222, commandLine: 'C:/Firefox/firefox.exe -profile C:/repo/.tmp/ff-semrush-b about:blank' }, // different label — not ours
    { pid: 333, commandLine: 'C:/Firefox/firefox.exe' },                                                 // the operator's own browser
    { pid: 444, commandLine: 'C:/other/notepad.exe C:/repo/.tmp/ff-semrush-a/notes.txt' },               // not firefox
  ];
  const r = await killProfileHolders('C:/repo/.tmp/ff-semrush-a', {
    listProcesses,
    killProcess: async (pid) => { killed.push(pid); return true; },
  });
  assert.deepEqual(r.killed, [111], 'only the exact-profile firefox was reaped');
  assert.ok(r.skipped.includes(222) && r.skipped.includes(333) && r.skipped.includes(444));
  assert.equal(r.scanned, 4);
  // scan failure → honest empty result, never throws
  const r2 = await killProfileHolders('C:/x', { listProcesses: async () => { throw new Error('wmi gone'); } });
  assert.deepEqual(r2.killed, []);
});

test('quarantineProfile: a wedged automation profile is renamed aside, never deleted', async () => {
  const { quarantineProfile } = await import('../tools/acctfactory.mjs');
  const { mkdtempSync, writeFileSync, existsSync, mkdirSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const base = mkdtempSync(join(tmpdir(), 'ffq-'));
  const prof = join(base, 'ff-prog-a');
  mkdirSync(prof, { recursive: true });
  writeFileSync(join(prof, 'cookies.sqlite'), 'evidence');
  const logs = [];
  const r = quarantineProfile(prof, { onLog: (l) => logs.push(l) });
  assert.ok(r.quarantined && r.quarantined.startsWith(prof + '.quarantine-'), 'renamed aside with a timestamp');
  assert.ok(existsSync(join(r.quarantined, 'cookies.sqlite')), 'the wedged profile survives for evidence');
  assert.ok(!existsSync(prof), 'the original path is free for a fresh profile');
  assert.ok(logs.some((l) => l.type === 'acctfactory.profile-quarantined'));
  // missing dir → honest no-op, never throws
  assert.equal(quarantineProfile(join(base, 'nope')).quarantined, null);
});
