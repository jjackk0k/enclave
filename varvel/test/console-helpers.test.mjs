// VARVEL console-helpers tests — the pure mapping logic behind the app-v6 console's
// budget / ghost / fresh-ground / ledger surfaces (engine/console-helpers.mjs) AND its
// byte-mirrored copy inside app-v6.html. Console JS cannot be unit-tested hermetically
// in place (one classic <script>, no imports), so the honest discipline is:
//   1. the pure logic lives here-covered in engine/console-helpers.mjs;
//   2. app-v6.html carries a marked MIRROR block with the same function source;
//   3. this file runs the SAME behavior assertions against both copies, pins the mirror
//      byte-for-byte (drift = red), and compiles the console's whole embedded script
//      (vm.Script = the extraction syntax check).
//   node --test test/console-helpers.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';

const __dir = dirname(fileURLToPath(import.meta.url));
const HELPERS = join(__dir, '..', 'engine', 'console-helpers.mjs');
const APP = join(__dir, '..', 'app-v6.html');

const H = await import('../engine/console-helpers.mjs');

// --- the mirror discipline ----------------------------------------------------------------
const BEGIN = '/* === CONSOLE-HELPERS MIRROR BEGIN';
const END = '/* === CONSOLE-HELPERS MIRROR END === */';

function engineSource() {
  const src = readFileSync(HELPERS, 'utf8');
  const ix = src.indexOf('export const MAXTURNS_FALLBACK');
  assert.ok(ix > 0, 'engine/console-helpers.mjs exports start at MAXTURNS_FALLBACK (header comment above)');
  return src.slice(ix).replace(/^export /gm, '').trim();
}
function mirrorSource() {
  const html = readFileSync(APP, 'utf8');
  const b = html.indexOf(BEGIN), e = html.indexOf(END);
  assert.ok(b !== -1 && e !== -1 && e > b, 'app-v6.html carries the marked CONSOLE-HELPERS MIRROR block');
  const open = html.indexOf('*/', b) + 2; // the BEGIN marker comment may span lines — the mirror starts after it closes
  return html.slice(html.slice(open).startsWith('\r\n') ? open + 2 : open + 1, e).trim();
}
function mirrorFns() {
  const ctx = { globalThis: null };
  ctx.globalThis = ctx;
  vm.createContext(ctx);
  vm.runInContext(mirrorSource() + '\n;globalThis.__M = { MAXTURNS_FALLBACK, budgetReadout, ghostChip, freshGroundView, RANK_WEIGHT, eventSummary, goalReadout, moneyText, jsq };', ctx);
  return ctx.__M;
}

test('mirror: app-v6.html carries the helpers BYTE-IDENTICAL to engine/console-helpers.mjs', () => {
  assert.equal(mirrorSource(), engineSource(),
    'the console mirror block drifted from engine/console-helpers.mjs — re-copy the functions into the marked block in app-v6.html');
});

test('mirror: the console embedded script still compiles after carrying the block', () => {
  const html = readFileSync(APP, 'utf8');
  const m = html.match(/<script>([\s\S]*)<\/script>/);
  assert.ok(m, 'one embedded script block');
  new vm.Script(m[1], { filename: 'app-v6.html#script' }); // compile-only: SyntaxError throws here
});

// --- shared behavior assertions (run against BOTH copies) ---------------------------------
function behaviorSuite(X, tag) {
  const J = (o) => JSON.parse(JSON.stringify(o)); // the mirror copy runs in a vm realm — normalize prototypes for deepEqual
  // THE 0/40 vs 0/200 bug: two genuinely different budgets, one readout, distinctly labeled.
  const interactive = { status: 'interactive', budget: { maxSteps: 200, usedSteps: 0 }, messages: [] };
  const r1 = X.budgetReadout(interactive, 40);
  assert.equal(r1.kind, 'turns', tag + ': interactive session renders the TURN budget, not the dummy campaign counter');
  assert.equal(r1.used, 0); assert.equal(r1.max, 40);
  assert.equal(r1.chipKey, 'Turns'); assert.equal(r1.source, 'agent.maxTurns');
  assert.ok(!/0\/200/.test(r1.hint), tag + ': the interactive hint never prints a fabricated 0/200 reading (the old hardcoded string Jack saw)');
  const r2 = X.budgetReadout({ status: 'running:recon', budget: { maxSteps: 200, usedSteps: 12 } }, 40);
  assert.equal(r2.kind, 'steps', tag + ': a pipeline campaign renders the STEP budget');
  assert.equal(r2.used, 12); assert.equal(r2.max, 200); assert.equal(r2.pct, 6);
  assert.equal(r2.chipKey, 'Steps'); assert.equal(r2.source, 'campaign budget.maxSteps');
  const r3 = X.budgetReadout({ status: 'running:interactive', budget: { maxSteps: 200, usedSteps: 0 }, messages: [{ who: 'agent', steps: [1, 2, 3, 4, 5] }] }, 40);
  assert.equal(r3.kind, 'turns'); assert.equal(r3.used, 3, 'steps pair into turns (ceil 5/2)');
  assert.equal(X.budgetReadout({ status: 'idle' }, 40).kind, 'none');
  assert.equal(X.budgetReadout(null, 40).kind, 'none');
  assert.equal(X.budgetReadout({ status: 'interactive', budget: {}, messages: [] }, undefined).max, 40, 'maxTurns fallback = the settings default');
  assert.equal(X.budgetReadout({ status: 'interactive', budget: {}, messages: [] }, 80).max, 80, 'a retuned agent.maxTurns is honored');

  // ghostChip: ONE mapping for the header chip AND the card (the OFF-while-armed split).
  assert.deepEqual(X.ghostChip(null).state, 'off');
  assert.equal(X.ghostChip({ mode: 'off' }).state, 'off');
  const armed = X.ghostChip({ mode: 'required', hops: 1, chain: ['socks5://10.64.0.1:1080'], dns: 'd', verified: { ok: true, exitIp: '45.66.219.208' } });
  assert.equal(armed.state, 'ok'); assert.equal(armed.cls, 'ck-ok');
  assert.ok(/required · 1 hop · exit 45\.66\.219\.208/.test(armed.label));
  const failed = X.ghostChip({ mode: 'required', hops: 1, chain: ['x'], verified: { ok: false, error: 'chain did not reach the check endpoint' } });
  assert.equal(failed.state, 'bad'); assert.equal(failed.cls, 'ck-no');
  assert.ok(/NOT HIDDEN/.test(failed.label));
  const unv = X.ghostChip({ mode: 'on', hops: 2, chain: ['a', 'b'], verified: null });
  assert.equal(unv.state, 'unverified');
  assert.ok(/2 hops · unverified/.test(unv.label), 'hop pluralization');

  // freshGroundView: the display cap NEVER cuts an exclusion move (side 'out').
  const evs = [];
  for (let i = 0; i < 40; i++) evs.push({ at: 't', type: 'new-program', handle: 'p' + i, rank: 4 });
  evs.push({ at: 't', type: 'scope-added', side: 'out', handle: 'late-exclusion', rank: 6 });
  const v = X.freshGroundView(evs, 30);
  assert.equal(v.total, 41);
  assert.equal(v.shown.length, 31, '30 capped + the one exclusion move');
  assert.ok(v.shown.some((e) => e.handle === 'late-exclusion'), 'the exclusion move survives the cap — honor before any contact');
  assert.equal(v.hiddenByCap, 10);
  assert.deepEqual(J(X.freshGroundView(null, 30)), { shown: [], hiddenByCap: 0, total: 0 });
  const v2 = X.freshGroundView(evs.slice(0, 10), 30);
  assert.equal(v2.shown.length, 10); assert.equal(v2.hiddenByCap, 0);

  // eventSummary: counts, never dumps; the exclusion weight is in the words.
  const s1 = X.eventSummary({ type: 'new-program', handle: 'acme', name: 'Acme', offersBounties: true, assets: ['a', 'b', 'c', 'd'], exclusions: ['x'] });
  assert.ok(/Acme \[acme\] — bountied · 4 in-scope, 1 excluded — a, b, c …/.test(s1), s1);
  const s2 = X.eventSummary({ type: 'scope-added', side: 'out', handle: 'acme', assets: ['offlimits.example'] });
  assert.ok(/NEW EXCLUSION/.test(s2));
  const s3 = X.eventSummary({ type: 'policy-changed', handle: 'acme', automation: { from: { policy: 'prohibited' }, to: { policy: 'human-cadence' } } });
  assert.ok(/automation prohibited → human-cadence/.test(s3));
  assert.equal(X.eventSummary(null), '—');

  // goalReadout: GBP-only goal progress, clamped bar, honest overshoot text.
  const g = X.goalReadout({ currency: 'GBP', target: 3332.5, paid: 0, pct: 0 });
  assert.deepEqual(J(g), { paidText: '£0.00', targetText: '£3332.50', pctText: '0%', widthPct: 0 });
  const g2 = X.goalReadout({ currency: 'GBP', target: 3332.5, paid: 5000, pct: 150.02 });
  assert.equal(g2.widthPct, 100, 'the bar clamps');
  assert.equal(g2.pctText, '150.02%', 'the text stays honest past the goal');
  assert.equal(X.moneyText(120, 'GBP'), '£120.00');
  assert.equal(X.moneyText(120, 'USD'), '$120.00');
  assert.equal(X.moneyText(120, 'SEK'), 'SEK 120.00', 'no glyph invented for unknown currencies');
  assert.equal(X.MAXTURNS_FALLBACK, 40);

  // jsq: two-layer quoting for ids inside onclick="fn('...')" — the JS-string layer first
  // (\, ', CR/LF), then the same HTML-attribute entity layer as the console's esc(). A
  // quote or line break in a server id must be able to break NEITHER the handler NOR the
  // attribute (the blMark/chanKill/approve interpolation gap).
  assert.equal(X.jsq('plain-id_1'), 'plain-id_1', 'safe slugs pass through untouched');
  assert.equal(X.jsq("o'hara"), "o\\'hara", 'single quote escaped for the JS-string layer');
  assert.equal(X.jsq('a\\b'), 'a\\\\b', 'backslash escaped FIRST, so later escapes are not doubled');
  assert.equal(X.jsq('l1\nl2'), 'l1\\nl2', 'a line break cannot terminate the string literal');
  assert.equal(X.jsq('a"b'), 'a&quot;b', 'double quote entity-escaped for the attribute layer');
  assert.equal(X.jsq('<b>&'), '&lt;b&gt;&amp;', 'HTML-layer parity with esc()');
  assert.equal(X.jsq("x'onmouseover=\"y"), "x\\'onmouseover=&quot;y", 'handler-breakout payload is inert on both layers');
  assert.equal(X.jsq(null), '');
  assert.equal(X.jsq(undefined), '');
}

test('behavior: budget/ghost/fresh-ground/ledger mapping (engine copy)', () => behaviorSuite(H, 'engine'));
test('behavior: the SAME assertions against the console mirror copy', () => behaviorSuite(mirrorFns(), 'mirror'));
