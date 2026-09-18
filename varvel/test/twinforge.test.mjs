// twinforge.test.mjs — the defender digital-twin loop, proven against the REAL Axiom SOC.
//   recordDefense(live Axiom) → profile → createTwin(profile) → fidelityCheck → ≥90.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { recordDefense, createTwin, fidelityCheck, TWINFORGE_SCHEMA } from '../engine/twinforge.mjs';
import { createHardTarget } from '../targets/premium-hard.mjs';

const quiet = (srv) => { srv.on('clientError', (e, s) => { try { s.destroy(); } catch {} }); return srv; };
const listen = async (srv) => { await new Promise((r) => srv.listen(0, '127.0.0.1', r)); return `http://127.0.0.1:${srv.address().port}`; };

process.env.AXIOM_SOC_LAG_MS = '30000'; // rotation lag irrelevant to recording; keep the SOC calm

test('twinforge: records the REAL Axiom SOC into a portable defense profile', async () => {
  const axiom = quiet(createHardTarget());
  const base = await listen(axiom);
  try {
    const profile = await recordDefense(base, { rateCap: 70, loginCap: 10 });
    assert.equal(profile.schema, TWINFORGE_SCHEMA);
    assert.equal(profile.verdict, 'defended-shape');
    assert.ok(profile.sha256, 'profile is hashed');
    // empirically verified 2026-07-31 against live Axiom SOC v2 (probe-axiom.mjs):
    assert.equal(profile.rateLimit.loginPerMin, 6, 'login limit read exactly');
    // strict mode (budget/3 ≈ 40) engages after the WAF battery trips 3+ blocks — the
    // recorder honestly captures the ADAPTED threshold, boundary ±4
    assert.ok(profile.rateLimit.observed, 'global rate limit observed');
    assert.ok(profile.rateLimit.globalPerMin >= 36 && profile.rateLimit.globalPerMin <= 48, `strict-adjusted threshold (got ${profile.rateLimit.globalPerMin})`);
    assert.equal(profile.rateLimit.retryAfter, '20');
    assert.equal(profile.rateLimit.headers, true);
    // all four WAF classes trip 403 on Axiom (raw/UNION variants are what its signatures match)
    for (const cls of ['traversal', 'xss', 'sqli', 'scanner-ua']) {
      const w = profile.waf.find((x) => x.class === cls);
      assert.ok(w && w.trips && w.status === 403, `${cls} trips 403`);
      assert.ok(w.path, `${cls} keeps its tripped variant for verbatim replay`);
    }
    // session shapes: Axiom redirects BOTH no-auth and malformed-token to login
    assert.equal(profile.session.adminNoAuthStatus, 302);
    assert.equal(profile.session.malformedTokenStatus, 302);
    assert.equal(profile.session.redirectsToLogin, true);
    // persona: Axiom announces itself
    assert.equal(profile.persona.server, 'Axiom');
    assert.equal(profile.persona.extra?.['x-axiom-shield'], 'active');

    // ---- synthesize the twin and prove behavioral fidelity ----
    const twin = quiet(createTwin(profile));
    const twinBase = await listen(twin);
    try {
      const f = await fidelityCheck(profile, twinBase);
      assert.ok(f.fidelity >= 90, `fidelity ≥90 (got ${f.fidelity}; misses: ${JSON.stringify(f.misses)})`);
      assert.equal(f.misses.length, 0, 'zero fidelity misses against the profile');
    } finally { twin.close(); }
  } finally { axiom.close(); }
});

test('twinforge: honest undefended-shape for a bare server (no fabricated shield)', async () => {
  const bare = quiet(http.createServer((req, res) => { res.writeHead(200); res.end('ok'); }));
  const base = await listen(bare);
  try {
    const profile = await recordDefense(base, { rateCap: 25, loginCap: 5 });
    assert.equal(profile.verdict, 'undefended-shape');
    assert.equal(profile.rateLimit.observed, false);
    assert.ok(profile.waf.every((w) => !w.trips), 'no fabricated WAF trips');
    assert.equal(profile.session.adminNoAuthStatus, 200);
  } finally { bare.close(); }
});

test('twinforge: hand-authored profile twin replays limits exactly', async () => {
  const profile = {
    schema: TWINFORGE_SCHEMA, recordedFrom: 'hand', at: new Date().toISOString(),
    persona: { server: 'twin-nginx' }, timing: { p50: 1, p95: 1 },
    rateLimit: { observed: true, globalPerMin: 8, loginPerMin: 3, retryAfter: '60', headers: true, bodyShape: 'textual' },
    waf: [{ class: 'scanner-ua', status: 403, trips: true, bodyMarker: 'blocked' }],
    session: { adminNoAuthStatus: 302, malformedTokenStatus: 403, redirectsToLogin: true },
    verdict: 'defended-shape', evidence: [], loginPath: '/login',
  };
  const twin = quiet(createTwin(profile));
  const base = await listen(twin);
  try {
    // direct behavioral spot-checks FIRST (the fidelity ramp fills the rate window by design)
    const waf = await fetch(base + '/', { headers: { 'user-agent': 'sqlmap/1.7' } });
    assert.equal(waf.status, 403);
    const noauth = await fetch(base + '/admin', { redirect: 'manual' });
    assert.equal(noauth.status, 302);
    const f = await fidelityCheck(profile, base);
    assert.equal(f.fidelity, 100, `hand profile fidelity 100 (misses: ${JSON.stringify(f.misses)})`);
  } finally { twin.close(); }
});

test('twinforge: governance + honesty guards', async () => {
  // scope refusal
  const r = await recordDefense('http://10.9.9.9', { scopeCheck: () => false });
  assert.equal(r.refused, true);
  assert.match(r.reason, /outside the signed engagement scope/);
  // wrong profile schema rejected
  assert.throws(() => createTwin({ schema: 'something/else' }), /twinforge\/1/);
});
