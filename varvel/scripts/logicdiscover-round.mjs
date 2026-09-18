// T3b round harness — invariant discovery from OBSERVED HTTP TRAFFIC ALONE.
//
// The T3b question, measured: with NO API spec and NO x-invariant annotations,
// can candidate business-logic invariants be DISCOVERED from ordinary observed
// traffic (journeys a client would generate) and PROVEN against the server, to
// the platform's standard (control request + state readback, never status-only)?
//
//   RECORDING     — test/fixtures/logictraffic.mjs drives logiclab through normal
//                   user journeys (wallet, order lifecycle, bookings, coupons,
//                   referrals) and records {seq, session, method, path, status,
//                   req, res}. It NEVER requests /openapi.json.
//   DISCOVERY     — engine/logicdiscover.mjs derives candidates from the traffic
//                   (violation values from sign/capacity correlations, observed
//                   vocabularies, refusals — never from the fixture source).
//   PROOF         — tools/logicprobe.mjs runs control → violation → readback per
//                   candidate against a FRESH lab. Same verdict oracle as T3.
//   GATES         — recall ≥6/8 on the planted violations; ZERO violated claims
//                   on the /api/safe/* control surface; the accepted-but-ignored
//                   price DECOY must be cleared by the readback (naive flags it).
//
// Loopback only. No external calls, no writes to live state.
// Run:  node varvel/scripts/logicdiscover-round.mjs
// Writes: deploy/range-iso/logiclab/last-discovery-verdict.json
//         test/fixtures/logiclab-traffic.json (the recorded traffic snapshot)

import http from 'node:http';
import { writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createLogiclabTarget, TENANT_USER, TENANT_PASS } from '../targets/logiclab.mjs';
import { recordLogicTraffic } from '../test/fixtures/logictraffic.mjs';
import { discoverInvariants } from '../engine/logicdiscover.mjs';
import { runLogicProbe } from '../tools/logicprobe.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));

function req(base, method, path, { body, cookie } = {}) {
  return new Promise((resolve) => {
    const u = new URL(path, base);
    const headers = {};
    if (cookie) headers.cookie = cookie;
    const r = http.request({ hostname: u.hostname, port: u.port, path: u.pathname + u.search, method, headers, timeout: 3000 }, (res) => {
      let b = ''; res.on('data', (d) => { b += d; }); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: b }));
    });
    r.on('error', () => resolve(null));
    if (body != null) r.write(typeof body === 'string' ? body : JSON.stringify(body));
    r.end();
  });
}

// ——— 1. record traffic (its own ephemeral lab) ———
const { observations, close } = await recordLogicTraffic();
await close();
writeFileSync(join(HERE, '../test/fixtures/logiclab-traffic.json'), JSON.stringify({ at: new Date().toISOString(), observations }, null, 2));

// ——— 2. discover from traffic alone ———
const { candidates, dropped, stats } = discoverInvariants(observations);

// ——— 3. prove against a FRESH lab ———
const srv = createLogiclabTarget();
srv.on('clientError', (e, sock) => { try { sock.destroy(); } catch {} });
await new Promise((r) => srv.listen(0, '127.0.0.1', r));
const base = `http://127.0.0.1:${srv.address().port}`;
try {
  const login = await req(base, 'POST', '/login', { body: new URLSearchParams({ user: TENANT_USER, pass: TENANT_PASS }).toString() });
  const cookie = login && login.status === 302 ? String(login.headers['set-cookie']).split(';')[0] : null;
  if (!cookie) throw new Error('login failed');

  const results = [];
  for (const c of candidates) {
    const pr = await runLogicProbe(base, c, { headers: { cookie }, resetPath: '/lab/revert', timeout: 4000 });
    results.push({
      id: c.id, kind: c.kind, path: c.path, param: c.param,
      surface: c.path.startsWith('/api/safe/') ? 'safe' : 'vuln',
      derived: c.derived, verdict: pr.verdict, naiveWouldFlag: pr.naiveWouldFlag, detail: pr.detail,
    });
  }

  const vuln = results.filter((r) => r.surface === 'vuln');
  const safe = results.filter((r) => r.surface === 'safe');
  const hit = vuln.filter((r) => r.verdict === 'violated').length;
  const claims = safe.filter((r) => r.verdict === 'violated').length;
  const decoy = results.find((r) => r.kind === 'server-authoritative' && r.surface === 'safe');

  const verdict = {
    lab: 'range-iso/logiclab (T3b discovery round)',
    at: new Date().toISOString(),
    mode: 'traffic-only discovery — NO spec, NO x-invariant annotations',
    fixture: { target: 'targets/logiclab.mjs', base, recording: 'test/fixtures/logiclab-traffic.json' },
    discovery: {
      observations: stats.observations, candidates: candidates.length,
      kinds: [...new Set(candidates.map((c) => c.kind))],
      dropped: dropped.map((d) => ({ rule: d.rule, target: d.target, reason: d.reason })),
    },
    recall: { hit, total: vuln.length, gate: '≥6/8' },
    control: { claims, total: safe.length, gate: '0 claims' },
    decoy: decoy ? { verdict: decoy.verdict, naiveWouldFlag: decoy.naiveWouldFlag, cleared: decoy.verdict === 'enforced' && decoy.naiveWouldFlag === true } : null,
    pass: hit >= 6 && claims === 0 && !!(decoy && decoy.verdict === 'enforced'),
    results,
  };
  writeFileSync(join(HERE, '../deploy/range-iso/logiclab/last-discovery-verdict.json'), JSON.stringify(verdict, null, 2));
  console.log(`T3b discovery round: recall ${hit}/${vuln.length} (gate ≥6), safe-mirror claims ${claims} (gate 0), decoy ${decoy && decoy.verdict} (naive=${decoy && decoy.naiveWouldFlag})`);
  console.log(`candidates: ${candidates.length} from ${stats.observations} observations; dropped: ${dropped.length}`);
  for (const r of results) console.log(' ', r.verdict.padEnd(12), r.surface.padEnd(5), r.kind.padEnd(20), r.path);
  console.log(verdict.pass ? 'ROUND PASS → deploy/range-iso/logiclab/last-discovery-verdict.json' : 'ROUND FAIL');
  process.exitCode = verdict.pass ? 0 : 1;
} finally {
  await new Promise((r) => srv.close(r));
}
