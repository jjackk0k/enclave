// VARVEL — live-stall regression pins (2026-08-31 — the tripcom :8971 / bykea :8975
// silent-freeze report). Two production campaigns stalled 80+ min with ZERO events:
//
//   Signature 1 (tripcom): a wedged await with NO watchdog coverage in the per-host
//     recon loop — ghost.assertEgress, passiveRecon, subdomainScan, canaryScan and the
//     overall sweep were all awaited bare (try/catch does nothing for a hung promise).
//     Worse, makePacer.pace() had an UNBOUNDED wait: wedged tools that lost their
//     _withBudget race were never cancelled and kept pacing, dragging the shared
//     emission clock's nextAt into the future; the next legit pace() (notably
//     _preflight's, which sat OUTSIDE its own race) slept the whole backlog.
//   Signature 2 (bykea): noise-budget exhaustion produced a bare "escalate to HITL"
//     LOG LINE — no pendingApproval, no budgetExhausted marking, no completion path.
//
//   Plus fix C: a campaign-level stall detector — no activity for stallAfterMs parks
//   the campaign VISIBLY as stalled:<phase> (silent freezing is a banned failure mode),
//   without false-firing on legit long tool runs or HITL gate waits.
//
// Run:  node --test varvel/test/recon-stall.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Campaign } from '../engine/campaign.mjs';
import { makePacer } from '../engine/stealth.mjs';

// Keep autogate's file seams pointed at nowhere (never touch the real data/ dir).
process.env.VARVEL_AUTOGATE_FILE = join(tmpdir(), 'varvel-test-no-such-autogate.json');
process.env.VARVEL_AUTOGATE_LOG = join(tmpdir(), 'varvel-test-autogate-log.jsonl');

const mockRunAgent = async () => ({ text: 'ok', steps: 1, denials: [] });
const wedged = () => new Promise(() => {}); // never settles, never rejects — the production wedge
const withTimeout = (p, ms, what) => Promise.race([
  p,
  new Promise((_, rej) => setTimeout(() => rej(new Error(`FROZE: ${what} did not settle within ${ms}ms`)), ms)),
]);

const SCOPE = { engagement: 'T-stall', signedBy: 'tester', cidrs: ['127.0.0.0/8', '10.0.0.0/8'] };
// A scanHost fixture: every target presents one http service (no TLS stage, no smb/ldap).
const httpHost = (ip, port) => ({ ip, services: [{ port, proto: 'tcp', name: 'http' }], tech: [] });

test('signature 1: a wedged ghost-egress await is watchdog-tripped and BOTH hosts still complete (tripcom continuation)', async () => {
  const c = new Campaign({
    engine: {}, scope: { ...SCOPE, engagement: 'T-stall-ghost' },
    runAgent: mockRunAgent, targets: ['10.1.0.1', '10.1.0.2'], tooledRecon: true, reconOnly: true, maxReplan: 0,
    ghost: { assertEgress: wedged }, // the wedge: a hung identity-chain assertion
    reconOpts: {
      scanHostImpl: async (ip) => httpHost(ip, 80),
      ghostGateMs: 100, preflight: false, toolWatchdogMs: 300,
    },
  });
  await withTimeout(c.run(), 8000, 'campaign with a wedged ghost gate'); // pre-fix: hangs forever on the bare await
  assert.equal(c.status, 'done');
  const trips = c.activity.filter((e) => e.kind === 'recon.watchdog' && String(e.data && e.data.tool || '').startsWith('ghost-egress:'));
  assert.ok(trips.length >= 2, `each host's wedged gate tripped the watchdog (got ${trips.length})`);
  const hostsSeen = c.activity.filter((e) => e.kind === 'recon.host').map((e) => e.data.host);
  assert.deepEqual(hostsSeen.sort(), ['10.1.0.1', '10.1.0.2'], 'the host AFTER the wedged one was still processed — no continuation hang');
  assert.ok(c.activity.some((e) => e.kind === 'recon.skip' && /wedged/.test(e.data.reason || '')), 'the skip is logged honestly');
  assert.ok(c.activity.some((e) => e.kind === 'recon.sweep.host'), 'the sweep emits per-host heartbeats (stall detector sees progress)');
});

test('signature 1b: wedged passive/subdomain/canary awaits are watchdog-tripped with honest fallbacks', async () => {
  const c = new Campaign({
    engine: {}, scope: { ...SCOPE, engagement: 'T-stall-passive' },
    runAgent: mockRunAgent, targets: ['10.1.0.9'], tooledRecon: true, reconOnly: true, maxReplan: 0,
    reconOpts: {
      domain: 'example.test',
      passiveImpl: wedged, dnsImpl: wedged, canaryImpl: wedged,
      passiveWatchdogMs: 100, dnsWatchdogMs: 100, canaryWatchdogMs: 100,
      scanHostImpl: async (ip) => httpHost(ip, 80), preflight: false, toolWatchdogMs: 300,
    },
  });
  await withTimeout(c.run(), 8000, 'campaign with wedged passive/dns/canary'); // pre-fix: hangs on the first bare await
  assert.equal(c.status, 'done');
  for (const tool of ['passive:example.test', 'subdomain:example.test', 'canary:example.test']) {
    assert.ok(c.activity.some((e) => e.kind === 'recon.watchdog' && e.data && e.data.tool === tool), `${tool} tripped the watchdog`);
  }
});

test('signature 1c: the pacer backlog is CLAMPED — zombie race-losers cannot drag the shared clock into an unbounded wait', async () => {
  const p = makePacer({ label: 't', concurrency: 1, delayMs: 200, jitterMs: 0 }, { maxWaitMs: 500 });
  assert.equal(p.maxWaitMs, 500);
  for (let i = 0; i < 20; i++) { p.pace(); } // wedged tools that lost their watchdog race keep reserving — ~4s of backlog
  const t0 = Date.now();
  await p.pace(); // pre-fix: sleeps the whole ~4s backlog
  const dt = Date.now() - t0;
  assert.ok(dt < 2000, `the wait is clamped to ~maxWaitMs (took ${dt}ms)`);
  // forward spacing is still enforced once the backlog sits under the clamp (the normal
  // production regime: maxWaitMs 120s >> any penalized gap ≤ 60s)
  const t1 = Date.now();
  await p.pace();
  assert.ok(Date.now() - t1 >= 150, 'the next emission still honors the profile gap');
  // default bound exists even when the caller passes nothing
  assert.equal(makePacer('quiet').maxWaitMs, 120000);
});

test('signature 2: noise-budget exhaustion marks the host budgetExhausted, escalates through the REAL gate, and recon COMPLETES to validate (bykea)', async () => {
  const srv = http.createServer((req, res) => { res.writeHead(200, { server: 'test' }); res.end('<title>t</title>'); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const port = srv.address().port;
  try {
    const c = new Campaign({
      engine: {}, scope: { ...SCOPE, engagement: 'T-stall-budget' },
      runAgent: mockRunAgent, targets: ['127.0.0.1', '127.0.0.2'], tooledRecon: true, maxReplan: 0,
      stealth: { label: 'testfast', concurrency: 2, delayMs: 1, jitterMs: 0 }, // paced but fast
      budget: { maxNoise: 6, maxSteps: 50 }, // tiny ceiling: host 1 fits, host 2 is spent
      // no hooks.approve — the gate fails CLOSED, exactly like an operator who never answers
      reconOpts: {
        scanHostImpl: async (ip) => httpHost(ip, port),
        preflight: false, toolWatchdogMs: 3000,
        web: { paths: ['/'] }, api: {}, crawl: { maxPages: 1 }, vuln: { maxProbes: 1 },
      },
    });
    await withTimeout(c.run(), 20000, 'budget-exhausted campaign');
    assert.equal(c.status, 'done');
    // the escalation MATERIALIZED as a real countersign gate attempt (live mode: this is
    // what surfaces as state.pendingApproval with the console's approve path)
    assert.ok(c.activity.some((e) => e.kind === 'gate.request' && e.data && e.data.phase === 'budget-override'), 'HITL escalation went through the real gate, not a bare log line');
    assert.ok(c.activity.some((e) => e.kind === 'gate.decision' && e.data && e.data.phase === 'budget-override' && e.data.signed === false), 'fail-closed decision is logged');
    // the exhausted host is MARKED, logged, and skipped — honestly
    const be = c.activity.find((e) => e.kind === 'recon.budget' && e.data && e.data.budgetExhausted === true);
    assert.ok(be, 'recon.budget event with budgetExhausted:true');
    assert.equal(be.data.host, '127.0.0.2');
    const nodes = [...c.surface.nodes.values()];
    const h1 = nodes.find((n) => n.type === 'host' && n.ip === '127.0.0.1');
    const h2 = nodes.find((n) => n.type === 'host' && n.ip === '127.0.0.2');
    assert.ok(h1 && h2, 'both swept hosts are on the surface');
    assert.ok(!h1.budgetExhausted, 'the in-budget host is not marked');
    assert.equal(h2.budgetExhausted, true, 'the exhausted host carries the mark');
    // recon COMPLETED and the campaign advanced — validate actually ran
    const phases = c.activity.filter((e) => e.kind === 'phase.start').map((e) => e.data.phase);
    assert.ok(phases.includes('recon') && phases.includes('validate'), `recon completed and the phase advanced to validate (saw: ${phases.join(',')})`);
    assert.ok(c.activity.some((e) => e.kind === 'campaign.done'), 'the campaign ran to done');
  } finally { srv.close(); }
});

test('signature 2b: an operator GRANT through the approve hook lifts the gate — tooling continues, no budgetExhausted mark', async () => {
  const srv = http.createServer((req, res) => { res.writeHead(200, { server: 'test' }); res.end('<title>t</title>'); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const port = srv.address().port;
  const seen = [];
  try {
    const c = new Campaign({
      engine: {}, scope: { ...SCOPE, engagement: 'T-stall-budget-ok' },
      runAgent: mockRunAgent, targets: ['127.0.0.1', '127.0.0.2'], tooledRecon: true, maxReplan: 0,
      stealth: { label: 'testfast', concurrency: 2, delayMs: 1, jitterMs: 0 },
      budget: { maxNoise: 6, maxSteps: 50 },
      hooks: { approve: async (phase) => { seen.push(phase.id); return true; } }, // the operator countersigns
      reconOpts: {
        scanHostImpl: async (ip) => httpHost(ip, port),
        preflight: false, toolWatchdogMs: 3000,
        web: { paths: ['/'] }, api: {}, crawl: { maxPages: 1 }, vuln: { maxProbes: 1 },
      },
    });
    await withTimeout(c.run(), 20000, 'override-approved campaign');
    assert.equal(c.status, 'done');
    assert.ok(seen.includes('budget-override'), 'the approve hook was called with the budget-override phase (the real approve path)');
    assert.ok(!c.activity.some((e) => e.kind === 'recon.budget' && e.data && e.data.budgetExhausted), 'no host was marked budgetExhausted under the override');
    const h2 = [...c.surface.nodes.values()].find((n) => n.type === 'host' && n.ip === '127.0.0.2');
    assert.ok(h2 && !h2.budgetExhausted);
  } finally { srv.close(); }
});

test('fix C: the stall detector parks stalled:<phase> on silence — and never false-fires on legit work or HITL waits (fake clock)', async () => {
  let t = 1_000_000;
  const c = new Campaign({
    engine: {}, scope: { ...SCOPE, engagement: 'T-stall-detector' }, runAgent: mockRunAgent,
    stallAfterMs: 600, stallCheckMs: 0, now: () => t, // manual drive: no interval, fake clock
  });
  c.status = 'running:recon'; c.phaseIndex = 0;
  c._log('recon.tool', { host: '10.9.9.9', port: 8443, name: 'https' }); // bykea's last event shape
  t += 599;
  assert.equal(c._checkStall(), null, 'under the threshold: a legit long tool run does NOT fire');
  t += 2; // now 601ms of silence
  const s = c._checkStall();
  assert.ok(s, 'past the threshold: fires');
  assert.equal(c.status, 'stalled:recon', 'parked VISIBLE as stalled:<phase>');
  assert.equal(s.phase, 'recon');
  assert.equal(s.lastEvent.kind, 'recon.tool', 'the stall record carries the last event as await context');
  assert.match(s.reason, /no activity/, 'reason names the silence');
  assert.ok(c.activity.some((e) => e.kind === 'campaign.stall'), 'campaign.stall is in the activity feed');
  assert.equal(c.getState().stall.reason, s.reason, 'the stall is visible in getState()');
  // parked, not spamming: repeated checks while wedged log nothing new
  const n = c.activity.filter((e) => e.kind === 'campaign.stall').length;
  t += 60000; c._checkStall();
  assert.equal(c.activity.filter((e) => e.kind === 'campaign.stall').length, n, 'no refire while parked');
  // activity resumes (the wedged await finally settled): the park clears and status restores
  c._log('recon.watchdog', { tool: 'webscan:10.9.9.9' });
  assert.equal(c.stall, null);
  assert.equal(c.status, 'running:recon');
  // a HITL gate wait is a LEGIT park — never a stall
  t += 60000; c._awaitingApproval = 1;
  assert.equal(c._checkStall(), null, 'no fire while parked at a countersign gate');
  c._awaitingApproval = 0;
  // terminal statuses never fire
  c.status = 'done'; t += 60000;
  assert.equal(c._checkStall(), null, 'done campaigns never stall');
});
