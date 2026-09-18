// range-iso logiclab lab — the T3 calibrate-on-known-knowns HARNESS.
//
// The T3 question, measured: can candidate business-logic invariants be EXTRACTED
// from the API's own OpenAPI description and PROVEN against the server, to the
// platform's standard (control request + state readback, never status-only)?
//
//   EXTRACTION    — engine/logicinvariants.mjs reads the live /openapi.json and
//                   derives candidates (violation values come from schema bounds,
//                   enums, x-flows, x-state-machines — never from the fixture).
//   PROOF         — tools/logicprobe.mjs runs control → violation → readback per
//                   candidate. Verdicts: violated / enforced / inconclusive.
//   GATES         — recall ≥6/8 on the planted violations; ZERO violated claims
//                   on the /api/safe/* control surface; the accepted-but-ignored
//                   price DECOY must be cleared by the readback (naive flags it).
//   COMPOSITION   — chaincompose invariant-violation family composes with
//                   published-creds-login and executes through chainrun to
//                   impact-proven findings (safe variants fail honestly).
//
// Loopback only. No external calls, no writes to live state.
// Run:  node varvel/deploy/range-iso/logiclab/run.mjs   (writes last-verdict.json beside it)

import http from 'node:http';
import { writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createLogiclabTarget, TENANT_USER, TENANT_PASS, LOGIC_CANARY } from '../../../targets/logiclab.mjs';
import { extractInvariants } from '../../../engine/logicinvariants.mjs';
import { runLogicProbe } from '../../../tools/logicprobe.mjs';
import { composeChains, findingFromChain } from '../../../engine/chaincompose.mjs';
import { hasObjectiveOracle } from '../../../engine/validator.mjs';
import { runChain } from '../../../tools/chainrun.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));

function get(base, path) {
  return new Promise((resolve) => {
    http.get(new URL(path, base), (res) => { let b = ''; res.on('data', (d) => { b += d; }); res.on('end', () => resolve({ status: res.statusCode, body: b })); })
      .on('error', () => resolve(null));
  });
}

export async function runLogicLab({ clock = () => new Date().toISOString() } = {}) {
  const srv = createLogiclabTarget();
  srv.on('clientError', (e, sock) => { try { sock.destroy(); } catch {} });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${srv.address().port}`;

  try {
    // ── 1. EXTRACTION from the live spec ──
    const specRes = await get(base, '/openapi.json');
    const spec = JSON.parse(specRes.body);
    const extraction = extractInvariants(spec);

    // ── 2. PROOF — every candidate, vuln + safe, with reset between ──
    const cookie = await new Promise((resolve) => {
      const req = http.request(base + '/login', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' } }, (res) => {
        res.resume(); res.on('end', () => resolve(String(res.headers['set-cookie'] || '').split(';')[0]));
      });
      req.end(`user=${TENANT_USER}&pass=${TENANT_PASS}`);
    });

    const probes = [];
    for (const c of extraction.candidates) {
      const r = await runLogicProbe(base, c, { headers: { cookie }, resetPath: '/lab/revert' });
      probes.push({ candidate: c.id, kind: c.kind, safe: c.path.startsWith('/api/safe/'), ...{ verdict: r.verdict, naiveWouldFlag: r.naiveWouldFlag, controlOk: r.controlOk, violationStatus: r.violationStatus, effectMatch: r.effectMatch, detail: r.detail } });
    }
    const vuln = probes.filter((p) => !p.safe);
    const safe = probes.filter((p) => p.safe);
    const recall = { hit: vuln.filter((p) => p.verdict === 'violated').length, total: vuln.length, gate: '≥6/8' };
    const control = { claims: safe.filter((p) => p.verdict === 'violated').length, total: safe.length, gate: '0 claims' };
    const decoy = probes.find((p) => p.candidate === 'createSafeOrder');

    // ── 3. COMPOSITION + EXECUTION through chainrun ──
    const endpoints = ['/login', '/docs', '/openapi.json',
      '/api/payments', '/api/orders', '/api/bookings', '/api/checkout/confirm',
      '/api/coupons/apply', '/api/rides/RIDE1/status', '/api/orders/ORD-x/cancel', '/api/referrals',
      '/api/safe/orders', '/api/safe/payments'].map((p) => ({ path: p, method: 'GET' }));
    const composed = await composeChains({ endpoints, findings: [], material: {} });
    const attempts = [];
    const winners = [];
    for (const chain of composed.chains) {
      const run = await runChain({ ...chain, base });
      const inv = run.steps.find((s) => s.invariant);
      attempts.push({
        chain: chain.name, stepsOk: run.stepsCompleted === run.stepsTotal,
        impactOk: !!(run.impact && run.impact.ok), verdict: inv ? inv.invariant.verdict : null,
        canaryReached: run.steps.some((s) => s.evidence && s.evidence.includes(LOGIC_CANARY)),
        error: run.ok ? null : ((run.steps.find((s) => !s.ok) || {}).error || (run.impact && run.impact.detail) || null),
      });
      if (run.ok && run.impact && run.impact.ok && inv && inv.invariant.verdict === 'violated') winners.push({ chain: chain.name, run });
    }
    const findings = winners.map((w) => {
      const f = findingFromChain(w.run, { title: w.chain });
      return { chain: w.chain, error: f.error || null, passesOracleGate: !f.error && hasObjectiveOracle(f) };
    });

    return {
      lab: 'range-iso/logiclab (T3 round)',
      at: clock(),
      fixture: { target: 'targets/logiclab.mjs', base },
      extraction: {
        candidates: extraction.candidates.length,
        dropped: extraction.dropped,
        kinds: [...new Set(extraction.candidates.map((c) => c.kind))],
      },
      recall, control,
      decoyFate: decoy ? { naiveWouldFlag: decoy.naiveWouldFlag, verdict: decoy.verdict, detail: decoy.detail } : null,
      probes,
      composition: {
        candidates: composed.chains.map((c) => c.name),
        winners: winners.map((w) => w.chain),
        findings,
        attempts,
      },
      verdict: {
        extract: `${extraction.candidates.length} candidates extracted from the live spec (${extraction.dropped.length} honestly dropped)`,
        recall: `${recall.hit}/${recall.total} planted violations proven (gate ${recall.gate}) — ${recall.hit >= 6 && recall.total === 8 ? 'PASS' : 'FAIL'}`,
        control: `${control.claims}/${control.total} violated-claims on the clean control surface (gate 0) — ${control.claims === 0 ? 'PASS' : 'FAIL'}`,
        decoy: decoy && decoy.naiveWouldFlag && decoy.verdict === 'enforced'
          ? 'PASS — accepted-but-ignored price decoy: naive flags, readback oracle clears'
          : 'see probes',
        compose: winners.length ? `${winners.length} composed invariant chains impact-proven; findings pass oracle gate: ${findings.every((f) => f.passesOracleGate)}` : 'no composed winner — see attempts',
      },
    };
  } finally {
    await new Promise((r) => srv.close(r));
  }
}

const invokedAsMain = process.argv[1] && /run\.mjs$/i.test(process.argv[1].replace(/\\/g, '/'));
if (invokedAsMain) {
  runLogicLab().then((v) => {
    const file = join(HERE, 'last-verdict.json');
    writeFileSync(file, JSON.stringify(v, null, 2));
    console.log('logiclab verdict (T3) -> ' + file);
    console.log('  EXTRACTION:  ' + v.verdict.extract);
    console.log('  RECALL:      ' + v.verdict.recall);
    console.log('  CONTROL:     ' + v.verdict.control);
    console.log('  DECOY:       ' + v.verdict.decoy);
    console.log('  COMPOSITION: ' + v.verdict.compose);
    for (const p of v.probes) console.log(`    ${p.safe ? 'safe' : 'vuln'} ${p.candidate} [${p.kind}] → ${p.verdict} (naive:${p.naiveWouldFlag})`);
  }).catch((e) => { console.error('lab run failed: ' + String((e && e.stack) || e)); process.exitCode = 1; });
}
