// cfbrowser.test.mjs — hermetic pins for the browser-interaction tier: NO real
// browser, NO network. Every cfbrowse run goes through injected seams (clearanceLookup
// / launcher / driverFactory); the pure pieces (nav gate, form classification, fill
// candidates, password guard, cookie seeding, probe survival diff) are pinned
// directly. Covers: (a) clearance-absent honesty, (b) no-browser honesty, (c) the NAV
// GATE aborting before any form action on a challenged page, (d) forms enumeration on
// a scripted DOM, (e) probe-comment survival-diff on fixture HTML, (f) the
// operatorApproved password guard.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { Ghost, chainEgressId } from '../engine/ghost.mjs';
import {
  cfbrowse,
  classifyDocument,
  navGate,
  isChallengeInterstitial,
  classifyForm,
  fillCandidates,
  fieldsTouchPassword,
  seedCookies,
  probeFragments,
  probeCommentBody,
  survivalDiff,
} from '../tools/cfbrowser.mjs';

const THIS_FILE = fileURLToPath(import.meta.url); // an existing file: stands in for chrome.exe at resolution time
const FAKE_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
const URL1 = 'https://zone-one.example/register';

const CF_CHALLENGE_BODY = '<html><title>Just a moment...</title><script src="/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1"></script></html>';
const REAL_PAGE = '<html><head><title>Zone One — Register</title></head><body><header>Zone One</header><main><h1>Create your account</h1><p>'
  + 'welcome to the zone, pull up a chair '.repeat(30)
  + '</p><form method="post" action="/register"><input name="alias"><input name="email" type="email"></form></main></body></html>';

const CLEARANCE = {
  cookies: [{ name: 'cf_clearance', value: 'op-provided', domain: 'zone-one.example', path: '/', expires: -1 }],
  ua: FAKE_UA,
  expiresAt: '2027-01-01T00:00:00Z',
};
const okClearance = async () => CLEARANCE;
const noClearance = async () => null;

// A minimal BrowserContext stand-in: records seeded cookies and the close.
function fakeContext() {
  const state = { cookies: null, closed: false };
  return {
    state,
    ctx: {
      addCookies: async (cs) => { state.cookies = cs; },
      pages: () => [],
      newPage: async () => ({}),
      close: async () => { state.closed = true; },
    },
  };
}

// A scripted thin driver: the same interface makePlaywrightDriver implements, with
// counters so tests can prove what was (and was NOT) touched. script.interactive may
// be a function for stateful human-in-the-loop simulations.
function fakeDriver(script = {}) {
  const s = { gotos: [], fills: [], clicks: [], formsCalls: 0, docHtml: script.docHtml ?? null, afterUrl: undefined };
  return {
    state: s,
    async goto(u) { s.gotos.push(u); return { status: script.status ?? 200, body: s.docHtml ?? '' }; },
    async readDocument() { return { url: script.pageUrl ?? URL1, html: s.docHtml }; },
    async currentUrl() { return s.afterUrl ?? (script.pageUrl ?? URL1); },
    async title() { return script.title ?? 'Zone One — Register'; },
    async visibleText(n) { return String(script.visibleText ?? 'the visible text of the served page').slice(0, n); },
    async links(max) { return (script.links ?? []).slice(0, max); },
    async formsRaw() { s.formsCalls++; return { forms: script.forms ?? [], pageHtml: script.pageHtml ?? '' }; },
    async fill(nameOrCss, value) {
      s.fills.push({ nameOrCss, value });
      return script.fillOk === false ? { ok: false, reason: 'no element matched' } : { ok: true, via: '[name="' + nameOrCss + '"]' };
    },
    async submitInsidePasswordForm() { return script.insidePasswordForm ?? null; },
    async interactiveState() { return typeof script.interactive === 'function' ? script.interactive() : (script.interactive ?? { present: false, solved: false }); },
    async clickAndSettle(sel) {
      s.clicks.push(sel);
      if (script.postHtml != null) s.docHtml = script.postHtml;
      if (script.afterUrl != null) s.afterUrl = script.afterUrl;
      return script.clickOk === false ? { ok: false, reason: 'no clickable element matched' } : { ok: true };
    },
    async html() { return s.docHtml ?? ''; },
  };
}

// Wire a fully-injected cfbrowse call: real resolveChrome against THIS_FILE, fake
// context, scripted driver. ghost: new Ghost() (OFF) keeps every run hermetic — the
// default ghost state reads the real Settings store, which on a ghost-armed host would
// trip the egress parity gate; transport tests override it via opts.extra.
function injected(script, opts = {}) {
  const { state, ctx } = fakeContext();
  const driver = fakeDriver(script);
  const launchArgs = [];
  const run = cfbrowse(opts.action || 'open', opts.url || URL1, {
    clearanceLookup: opts.clearanceLookup || okClearance,
    chromePath: THIS_FILE,
    ghost: new Ghost(),
    launcher: async (a) => { launchArgs.push(a); return ctx; },
    driverFactory: async () => driver,
    navSettleMs: opts.navSettleMs ?? 300,
    timeoutMs: opts.timeoutMs ?? 8000,
    ...opts.extra,
  });
  return { run, state, driver, launchArgs };
}

// --- (a) clearance-absent honesty ---------------------------------------------------

test('no valid clearance: honest { ok:false }, the browser is never launched', async () => {
  let launched = false;
  const r = await cfbrowse('open', URL1, {
    clearanceLookup: noClearance,
    chromePath: THIS_FILE,
    launcher: async () => { launched = true; return fakeContext().ctx; },
  });
  assert.equal(r.ok, false);
  assert.match(r.reason, /no valid clearance/);
  assert.equal(launched, false);
});

// --- (b) no-browser honesty ---------------------------------------------------------

test('no real Chrome anywhere: honest { ok:false }, nothing launches', async () => {
  let launched = false;
  const r = await cfbrowse('open', URL1, {
    clearanceLookup: okClearance,
    chromePath: 'C:/no/such/chrome-' + process.pid + '.exe',
    env: {},               // injected: CHROME_PATH unset
    exists: () => false,   // injected: nothing on disk — deterministic on any host
    ghost: new Ghost(),    // injected: ghost OFF — hermetic on a ghost-armed host
    launcher: async () => { launched = true; return fakeContext().ctx; },
  });
  assert.equal(r.ok, false);
  assert.match(r.reason, /no REAL Chrome\/Edge binary found/);
  assert.equal(launched, false);
});

test('launch failure: a rejecting launcher resolves { ok:false }, never throws', async () => {
  const r = await cfbrowse('open', URL1, {
    clearanceLookup: okClearance,
    chromePath: THIS_FILE,
    ghost: new Ghost(),
    launcher: async () => { throw new Error('spawn exploded'); },
  });
  assert.equal(r.ok, false);
  assert.match(r.reason, /browser launch failed/);
  assert.match(r.reason, /spawn exploded/);
});

// --- (c) the NAV GATE aborts before any form action on a challenged page -------------

test('NAV GATE: a challenged page aborts "forms" before enumeration; context still closes', async () => {
  const { run, state, driver } = injected(
    { status: 403, docHtml: CF_CHALLENGE_BODY },
    { action: 'forms', navSettleMs: 300 },
  );
  const r = await run;
  assert.equal(r.ok, false);
  assert.equal(r.gate, 'challenged');
  assert.match(r.reason, /clearance challenged mid-interaction — expired\/UA\/IP drift/);
  assert.equal(r.detection.kind, 'managed-js');
  assert.equal(r.status, 403);
  assert.equal(driver.state.formsCalls, 0);   // no form action inside a challenged page
  assert.equal(driver.state.fills.length, 0);
  assert.equal(driver.state.clicks.length, 0);
  assert.equal(driver.state.gotos.length, 1); // exactly one navigation
  assert.equal(state.closed, true);           // the browser ALWAYS closes
});

test('navGate (pure): thin challenge shell => challenged; full page embedding reCAPTCHA => pass + embeddedInteractive', () => {
  const thin = navGate({ status: 403, url: URL1, html: CF_CHALLENGE_BODY });
  assert.equal(thin.pass, false);
  assert.equal(thin.gate, 'challenged');
  assert.equal(thin.detection.kind, 'managed-js');
  assert.equal(isChallengeInterstitial(thin.detection, CF_CHALLENGE_BODY), true);
  // the registration page we are built for: a FULL served page with a reCAPTCHA widget
  const withWidget = REAL_PAGE + '<div class="g-recaptcha" data-sitekey="6LcAbcd"></div>';
  const embedded = navGate({ status: 200, url: URL1, html: withWidget });
  assert.equal(embedded.pass, true);
  assert.equal(embedded.embeddedInteractive, true);
  assert.equal(embedded.detection.kind, 'captcha'); // reported, not aborted
  const clean = navGate({ status: 200, url: URL1, html: REAL_PAGE });
  assert.equal(clean.pass, true);
  assert.equal(clean.detection.present, false);
  const blank = navGate({ status: null, url: 'about:blank', html: '' });
  assert.equal(blank.pass, false);
  assert.equal(blank.gate, 'unreadable');
});

test('classifyDocument (pure): the blank-document doctrine', () => {
  assert.equal(classifyDocument({ url: 'about:blank', html: '' }).readable, false);
  assert.equal(classifyDocument({ url: URL1, html: '<html><body></body></html>' }).readable, false);
  assert.equal(classifyDocument({ url: URL1, html: null }).kind, 'navigation-in-flight');
  assert.equal(classifyDocument({ url: URL1, html: REAL_PAGE }).readable, true);
});

// --- open: the read path, identity binding, cookie seeding ---------------------------

test('open: serves title/snippet/links as the vaulted identity; cookies seeded dot-prefixed; UA + headed passed to the launcher', async () => {
  const links = Array.from({ length: 60 }, (_, i) => ({ href: URL1 + '/' + i, text: 'link ' + i }));
  const { run, state, launchArgs } = injected({ docHtml: REAL_PAGE, links, visibleText: 'x'.repeat(5000) });
  const r = await run;
  assert.equal(r.ok, true);
  assert.equal(r.status, 200);
  assert.equal(r.title, 'Zone One — Register');
  assert.equal(r.textSnippet.length, 2048);          // first 2KB of visible text
  assert.equal(r.links.length, 50);                  // first 50 links
  assert.equal(r.identity.uaBound, true);
  assert.equal(r.identity.expiresAt, CLEARANCE.expiresAt);
  assert.equal(launchArgs.length, 1);
  assert.equal(launchArgs[0].userAgent, FAKE_UA);    // the vault's EXACT UA
  assert.equal(launchArgs[0].headless, false);       // headed default — the visible window IS the doctrine
  assert.equal(state.cookies.length, 1);
  assert.equal(state.cookies[0].domain, '.zone-one.example'); // .<zone> so subdomains ride
  assert.equal(state.cookies[0].expires, undefined); // session-cookie expires:-1 dropped
  assert.equal(state.closed, true);
});

// --- (d) forms enumeration on a scripted DOM -----------------------------------------

test('forms: classification of a scripted DOM — recaptcha widget, page-level markers, password detection, input normalization', async () => {
  const forms = [
    {
      action: '/wp-login.php?action=register', method: 'POST', recaptchaWidget: true,
      inputs: [
        { name: 'user_login', type: 'TEXT', id: 'user_login', placeholder: 'Username', required: true },
        { name: 'user_email', type: 'email', id: 'user_email', placeholder: 'Email', required: true },
      ],
    },
    {
      action: '/wp-login.php', method: 'post', recaptchaWidget: false,
      inputs: [
        { name: 'log', type: 'text', id: 'user_login', placeholder: '', required: false },
        { name: 'pwd', type: 'password', id: 'user_pass', placeholder: '', required: false },
      ],
    },
  ];
  const pageHtml = '<script src="https://www.google.com/recaptcha/api.js" async></script>'; // page-level marker
  const { run, driver } = injected({ docHtml: REAL_PAGE, forms, pageHtml }, { action: 'forms' });
  const r = await run;
  assert.equal(r.ok, true);
  assert.equal(driver.state.formsCalls, 1);
  assert.equal(r.forms.length, 2);
  assert.equal(r.forms[0].method, 'post');            // normalized lowercase
  assert.equal(r.forms[0].hasRecaptcha, true);        // widget inside the form
  assert.equal(r.forms[0].hasPasswordField, false);
  assert.deepEqual(r.forms[0].inputs[0], { name: 'user_login', type: 'text', id: 'user_login', placeholder: 'Username', required: true });
  assert.equal(r.forms[1].hasPasswordField, true);    // drives the operator gate
  assert.equal(r.forms[1].hasRecaptcha, true);        // page-level script marker applies
  // pure pin: no markers anywhere => hasRecaptcha false
  assert.equal(classifyForm({ inputs: [] }, { pageHtml: '<p>no widgets here</p>' }).hasRecaptcha, false);
});

// --- pure helpers --------------------------------------------------------------------

test('pure helpers: fillCandidates name-then-css order, fieldsTouchPassword matching, seedCookies shape', () => {
  assert.deepEqual(fillCandidates('email'), ['[name="email"]', '#email', 'email']);
  assert.deepEqual(fillCandidates('form .field-x'), ['form .field-x']); // already css
  assert.deepEqual(fillCandidates(''), []);
  const formsPwd = [{ inputs: [{ name: 'log', type: 'text' }, { name: 'pwd', type: 'password', id: 'user_pass' }] }];
  assert.equal(fieldsTouchPassword(formsPwd, { log: 'u', pwd: 'p' }), true);   // by name
  assert.equal(fieldsTouchPassword(formsPwd, { '#user_pass': 'p' }), true);    // by #id
  assert.equal(fieldsTouchPassword(formsPwd, { log: 'u' }), false);            // no password field touched
  assert.equal(fieldsTouchPassword(formsPwd, {}), false);
  const seeded = seedCookies([{ name: 'cf_clearance', value: 'v', expires: -1 }, { name: 'x', value: 'y', domain: '.zone-one.example' }], 'zone-one.example');
  assert.equal(seeded[0].domain, '.zone-one.example');
  assert.equal(seeded[0].path, '/');
  assert.equal(seeded[0].expires, undefined);
  assert.equal(seeded[1].domain, '.zone-one.example'); // already dotted — untouched
});

// --- (f) the operatorApproved password guard ------------------------------------------

test('password guard: a password-carrying form is REFUSED without operatorApproved — nothing typed, nothing clicked', async () => {
  const forms = [{ action: '/wp-login.php', method: 'post', inputs: [{ name: 'log', type: 'text' }, { name: 'pwd', type: 'password' }] }];
  const { run, driver, state } = injected(
    { docHtml: REAL_PAGE, forms },
    { action: 'fill-submit', extra: { fields: { log: 'operator', pwd: 's3cret' }, submitSelector: '#wp-submit' } },
  );
  const r = await run;
  assert.equal(r.ok, false);
  assert.equal(r.passwordInvolved, true);
  assert.match(r.reason, /operator-gated/);
  assert.match(r.reason, /operatorApproved:true/);
  assert.equal(driver.state.fills.length, 0);  // guarded BEFORE anything is typed
  assert.equal(driver.state.clicks.length, 0);
  assert.equal(state.closed, true);
});

test('password guard: the driver closest-form probe blocks even when fields do not map by name', async () => {
  const { run, driver } = injected(
    { docHtml: REAL_PAGE, forms: [], insidePasswordForm: true }, // enumeration missed it; the submit control sits in a password form
    { action: 'fill-submit', extra: { fields: { '#q': 'search' }, submitSelector: '#go' } },
  );
  const r = await run;
  assert.equal(r.ok, false);
  assert.equal(r.passwordInvolved, true);
  assert.equal(driver.state.clicks.length, 0);
});

test('password guard: operatorApproved:true passes the gate and submits', async () => {
  const forms = [{ action: '/wp-login.php', method: 'post', inputs: [{ name: 'log', type: 'text' }, { name: 'pwd', type: 'password' }] }];
  const THANKS = '<html><body><main>' + 'welcome back, operator '.repeat(10) + '</main></body></html>';
  const { run, driver } = injected(
    { docHtml: REAL_PAGE, forms, postHtml: THANKS, afterUrl: 'https://zone-one.example/wp-admin/' },
    { action: 'fill-submit', extra: { fields: { log: 'operator', pwd: 's3cret' }, submitSelector: '#wp-submit', operatorApproved: true } },
  );
  const r = await run;
  assert.equal(r.ok, true);
  assert.deepEqual(driver.state.clicks, ['#wp-submit']);
  assert.equal(r.before, URL1);
  assert.equal(r.after, 'https://zone-one.example/wp-admin/');
  assert.equal(r.fills.length, 2);
  assert.ok(r.statusText.length > 0);
  assert.equal(r.detection.present, false);
});

test('fill-submit: no widget, no password — fills by name, clicks, reports before/after', async () => {
  const forms = [{ action: '/register', method: 'post', inputs: [{ name: 'alias', type: 'text' }, { name: 'email', type: 'email' }] }];
  const THANKS = '<html><body><main>' + 'check your inbox to confirm '.repeat(10) + '</main></body></html>';
  const { run, driver } = injected(
    { docHtml: REAL_PAGE, forms, postHtml: THANKS, afterUrl: 'https://zone-one.example/register?checkemail=1' },
    { action: 'fill-submit', extra: { fields: { alias: 'varvel-op', email: 'op@example.com' }, submitSelector: 'input[type=submit]' } },
  );
  const r = await run;
  assert.equal(r.ok, true);
  assert.deepEqual(driver.state.fills.map((f) => f.nameOrCss), ['alias', 'email']);
  assert.deepEqual(driver.state.clicks, ['input[type=submit]']);
  assert.equal(r.after, 'https://zone-one.example/register?checkemail=1');
});

// --- human-in-the-loop interactive waiting --------------------------------------------

test('interactive solve: the tool POLLS patiently and proceeds once the operator tick lands', async () => {
  let polls = 0;
  const forms = [{ action: '/register', method: 'post', inputs: [{ name: 'alias', type: 'text' }] }];
  const THANKS = '<html><body><main>' + 'registered '.repeat(12) + '</main></body></html>';
  const { run, driver } = injected(
    {
      docHtml: REAL_PAGE, forms, postHtml: THANKS, afterUrl: URL1 + '?done=1',
      interactive: () => { polls++; return { present: true, solved: polls >= 2 }; }, // the human tick lands on the 2nd poll
    },
    { action: 'fill-submit', extra: { fields: { alias: 'varvel-op' }, submitSelector: '#go' } },
  );
  const r = await run;
  assert.equal(r.ok, true);
  assert.ok(polls >= 2);                       // it waited for the human
  assert.deepEqual(driver.state.clicks, ['#go']);
});

test('interactive solve: an unticked widget burns the budget and fails honestly — never aborts early', async () => {
  const forms = [{ action: '/register', method: 'post', inputs: [{ name: 'alias', type: 'text' }] }];
  const { run, driver } = injected(
    { docHtml: REAL_PAGE, forms, interactive: { present: true, solved: false } },
    { action: 'fill-submit', timeoutMs: 2500, extra: { fields: { alias: 'varvel-op' }, submitSelector: '#go' } },
  );
  const r = await run;
  assert.equal(r.ok, false);
  assert.match(r.reason, /not solved/);
  assert.match(r.reason, /human-in-the-loop/);
  assert.equal(driver.state.clicks.length, 0); // never submitted through an unsolved widget
});

// --- (e) probe-comment survival-diff on fixture HTML -----------------------------------

test('survivalDiff (pure): style tag present vs stripped vs held-for-moderation', () => {
  const marker = 'varvel-probe-1700000000000';
  const f = probeFragments(marker);
  const servedAll = '<html><body><div class="comment">' + f.plain + '<br>' + f.bTag + '<br>' + f.styleTag + '</div></body></html>';
  const d1 = survivalDiff(servedAll, marker);
  assert.deepEqual(d1.survived, { plain: true, bTag: true, styleTag: true });
  assert.equal(d1.markerFound, true);
  // WordPress kses-style stripping: <b> escaped, <style> removed entirely
  const servedStripped = '<html><body><div class="comment">' + f.plain + '<br>&lt;b&gt;bold ' + marker + '&lt;/b&gt;</div></body></html>';
  const d2 = survivalDiff(servedStripped, marker);
  assert.deepEqual(d2.survived, { plain: true, bTag: false, styleTag: false });
  assert.equal(d2.markerFound, true); // marker rides inside the surviving plain fragment
  // held for moderation: nothing of ours on the re-served page
  const d3 = survivalDiff('<html><body><p>Your comment is awaiting moderation.</p></body></html>', marker);
  assert.deepEqual(d3.survived, { plain: false, bTag: false, styleTag: false });
  assert.equal(d3.markerFound, false);
});

test('probe-comment: benign body submitted, re-navigation diffs survival, never any <script>/javascript: payload', async () => {
  const marker = 'varvel-probe-999';
  const f = probeFragments(marker);
  const POST_PAGE = '<html><body><article>' + 'zone content '.repeat(20)
    + '<div class="comment">' + f.plain + ' ' + f.bTag + '</div>' // style stripped by the sanitizer
    + '</article></body></html>';
  const { run, driver, state } = injected(
    { docHtml: REAL_PAGE, forms: [{ action: '/wp-comments-post.php', method: 'post', inputs: [{ name: 'comment', type: 'textarea' }] }], postHtml: POST_PAGE },
    { action: 'probe-comment', extra: { marker, fieldSelector: '#comment', submitSelector: '#submit' } },
  );
  const r = await run;
  assert.equal(r.ok, true);
  assert.equal(r.marker, marker);
  assert.deepEqual(r.survived, { plain: true, bTag: true, styleTag: false }); // the MEASUREMENT
  assert.equal(r.markerFound, true);
  assert.equal(driver.state.gotos.length, 2);  // initial nav + the re-navigation
  assert.equal(driver.state.fills.length, 1);
  const body = driver.state.fills[0].value;
  assert.equal(body, probeCommentBody(marker));
  assert.ok(body.includes('<b>bold ' + marker + '</b>'));
  assert.ok(body.includes('<style>body{background:#000}'));
  assert.ok(!/<script|javascript:/i.test(body)); // measurement payloads are benign, always
  assert.deepEqual(driver.state.clicks, ['#submit']);
  assert.equal(state.closed, true);
});

test('probe-comment: a moderated comment reports markerFound:false as an honest measurement', async () => {
  const MODERATED = '<html><body><article>' + 'zone content '.repeat(20) + '<p>Your comment is awaiting moderation.</p></article></body></html>';
  const { run } = injected(
    { docHtml: REAL_PAGE, forms: [], postHtml: MODERATED },
    { action: 'probe-comment', extra: { marker: 'varvel-probe-111', fieldSelector: '#comment', submitSelector: '#submit' } },
  );
  const r = await run;
  assert.equal(r.ok, true);
  assert.equal(r.markerFound, false);
  assert.deepEqual(r.survived, { plain: false, bTag: false, styleTag: false });
  assert.match(r.note, /HELD FOR MODERATION/);
});

test('cfbrowse: unknown action and bad URL are honest errors, never throws', async () => {
  const r1 = await cfbrowse('exfil', URL1, { clearanceLookup: okClearance, chromePath: THIS_FILE });
  assert.equal(r1.ok, false);
  assert.match(r1.reason, /unknown action/);
  const r2 = await cfbrowse('open', 'not-a-url', { clearanceLookup: okClearance, chromePath: THIS_FILE });
  assert.equal(r2.ok, false);
  assert.match(r2.reason, /absolute http\(s\) URL/);
});

// --- (d)/(e) the egress parity gate (2026-08-10): the launcher rides the chain when the
// vault entry is chain-keyed, stays direct when it is not, and refuses fail-closed when
// the two cannot be matched -- all BEFORE any window opens ----------------------------

const GHOST_CHAIN = 'socks5://alice:s3cret@127.0.0.1:1080';
const GHOST_ID = 'socks5://127.0.0.1:1080'; // the canonical creds-stripped egress id

const armedGhost = (chain = GHOST_CHAIN, mode = 'on') => {
  const g = new Ghost();
  g.configure({ mode, chain });
  return g;
};

test('chain-keyed entry: the launcher receives the chain as a single-hop context proxy (creds via proxyAuth, never in the URL)', async () => {
  const { run, launchArgs, state } = injected(
    { docHtml: REAL_PAGE },
    { extra: { egressId: GHOST_ID, ghost: armedGhost() } },
  );
  const r = await run;
  assert.equal(r.ok, true, r.reason);
  assert.equal(launchArgs.length, 1);
  assert.equal(launchArgs[0].proxy, GHOST_ID);                        // creds stripped from the URL
  assert.deepEqual(launchArgs[0].proxyAuth, { username: 'alice', password: 's3cret' }); // the broker's mint-leg shape
  assert.ok(!String(launchArgs[0].proxy).includes('s3cret'));         // secrets never ride the proxy id
  assert.match(r.identity.transport, /ghost chain \(1 hop/);          // the result names the egress it took
  assert.equal(state.closed, true);
});

test('multi-hop chain entry: refused fail-closed BEFORE any window opens (a browser rides exactly ONE hop)', async () => {
  const twoHop = 'socks5://127.0.0.1:1080,http://127.0.0.1:8080';
  let launched = false;
  const r = await cfbrowse('open', URL1, {
    clearanceLookup: okClearance,
    chromePath: THIS_FILE,
    egressId: chainEgressId(twoHop),
    ghost: armedGhost(twoHop),
    launcher: async () => { launched = true; return fakeContext().ctx; },
  });
  assert.equal(r.ok, false);
  assert.match(r.reason, /ONE proxy hop/);
  assert.match(r.reason, /fail-closed/);
  assert.equal(launched, false);
});

test('fail-closed: direct-keyed entry + ghost REQUIRED + public target refuses before launch', async () => {
  let launched = false;
  const r = await cfbrowse('open', URL1, {
    clearanceLookup: okClearance,
    chromePath: THIS_FILE,
    egressId: 'direct',
    ghost: new Ghost(),        // the unarmable state: settings said required, no chain
    ghostMode: 'required',
    launcher: async () => { launched = true; return fakeContext().ctx; },
  });
  assert.equal(r.ok, false);
  assert.match(r.reason, /REQUIRED/);
  assert.match(r.reason, /fail-closed/);
  assert.equal(launched, false);
});

test('fail-closed: chain-keyed entry with ghost NOT armed refuses before launch (never a silent direct ride)', async () => {
  let launched = false;
  const r = await cfbrowse('open', URL1, {
    clearanceLookup: okClearance,
    chromePath: THIS_FILE,
    egressId: GHOST_ID,
    ghost: new Ghost(), // off
    launcher: async () => { launched = true; return fakeContext().ctx; },
  });
  assert.equal(r.ok, false);
  assert.match(r.reason, /not armed with a chain/);
  assert.match(r.reason, /fail-closed/);
  assert.equal(launched, false);
});

test('direct-keyed entry keeps DIRECT transport: no proxy reaches the launcher (ghost off AND ghost on+chain)', async () => {
  for (const g of [new Ghost(), armedGhost()]) {
    const { run, launchArgs } = injected(
      { docHtml: REAL_PAGE },
      { extra: { egressId: 'direct', ghost: g } },
    );
    const r = await run;
    assert.equal(r.ok, true, r.reason);
    assert.equal(launchArgs.length, 1);
    assert.equal(launchArgs[0].proxy, null);     // the gate's direct verdict: no proxy...
    assert.equal(launchArgs[0].proxyAuth, null); // ...and no proxy creds reach the launcher
    assert.match(r.identity.transport, /^direct/);
  }
});
