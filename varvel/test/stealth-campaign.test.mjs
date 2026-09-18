// VARVEL stealth integration — the campaign ENFORCES the profile end-to-end.
//   node --test varvel/test/stealth-campaign.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { Campaign } from '../engine/campaign.mjs';
import { mockAgent } from '../mock-agent.mjs';
import { renderReport } from '../engine/report.mjs';

test('a stealth profile threads into reconOpts + the native tools pace + the budget accrues', async () => {
  const srv = http.createServer((req, res) => {
    if (req.url === '/') { res.writeHead(200, { server: 'nginx' }); return res.end('<title>T</title>'); }
    res.writeHead(404); res.end();
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const port = srv.address().port;
  try {
    const c = new Campaign({
      engine: {}, scope: { engagement: 'T-stealth', signedBy: 'x', cidrs: ['127.0.0.0/8'] },
      runAgent: mockAgent, targets: ['127.0.0.1'], tooledRecon: true, stealth: 'quiet',
      reconOpts: { ports: [port], webPorts: new Set([port]), timeout: 900, web: { paths: ['/', '/admin'] } },
    });
    // the profile is resolved + threaded into the tool options
    assert.equal(c.stealthName, 'quiet');
    assert.equal(c.reconOpts.stealth, 'quiet', 'recon tool gets the profile');
    assert.equal(c.reconOpts.web.stealth, 'quiet', 'webscan gets the profile');

    await c.tooledRecon();
    const st = c.getState();
    assert.equal(st.stealth, 'quiet');
    // tcp-scan (loudness 3) + http fingerprint(s) charged the noise budget
    assert.ok(st.stealthBudget.spent > 0, 'noise budget accrued from the recon activity');
    assert.equal(st.stealthBudget.profile, 'quiet');
    assert.ok(st.stealthBudget.maxNoise <= 40, 'quiet budget cap applied');
    assert.match(st.stealthBudget.proof, /budget/i, 'an after-action proof line is produced');
  } finally { srv.close(); }
});

test('no stealth profile → unlimited budget, tools run at full speed (backward-compatible)', async () => {
  const c = new Campaign({
    engine: {}, scope: { engagement: 'T-none', signedBy: 'x', cidrs: ['127.0.0.0/8'] },
    runAgent: mockAgent, targets: ['127.0.0.1'],
  });
  assert.equal(c.stealthName, null);
  assert.equal(c.reconOpts.stealth, undefined, 'no profile threaded when none set');
  const st = c.getState();
  assert.equal(st.stealth, null);
  assert.equal(st.stealthBudget.maxNoise, Infinity, 'unlimited budget with no profile');
});

test('a quiet campaign flags an over-ceiling activity as a budget-exceed event', async () => {
  const c = new Campaign({
    engine: {}, scope: { engagement: 'T-exceed', signedBy: 'x', cidrs: ['127.0.0.0/8'] },
    runAgent: mockAgent, targets: ['127.0.0.1'], stealth: 'quiet', // ceiling 3
  });
  c._noise({ kind: 'exploit-attempt', host: '127.0.0.1' }); // loudness 5 > ceiling 3
  assert.ok(c.activity.some((e) => e.kind === 'budget.exceed'), 'over-ceiling noise logged as a budget event');
  // it is still recorded (charged) so the after-action proof is honest, not hidden
  assert.ok(c.getState().stealthBudget.spent >= 5);
});

test('auto-stealth: the campaign fingerprints a WAF target and calibrates the profile before recon', async () => {
  const srv = http.createServer((req, res) => {
    res.writeHead(req.url === '/' ? 200 : 404, { server: 'cloudflare', 'cf-ray': '82abc123', 'cf-cache-status': 'DYNAMIC' });
    res.end(req.url === '/' ? '<title>t</title>' : 'nope');
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const port = srv.address().port;
  try {
    const c = new Campaign({
      engine: {}, scope: { engagement: 'T-auto', signedBy: 'x', cidrs: ['127.0.0.0/8'] },
      runAgent: mockAgent, targets: ['127.0.0.1'], stealth: 'auto',
      reconOpts: { ports: [port], webPorts: new Set([port]), timeout: 800 },
    });
    assert.equal(c.autoStealth, true);
    assert.equal(c.stealthName, 'auto', 'unresolved until run start');
    assert.equal(c.reconOpts.stealth, undefined, 'not threaded until calibrated');

    await c._calibrateStealth();
    assert.equal(c.stealthName, 'quiet', 'Cloudflare WAF → calibrated to quiet');
    assert.ok(c.targetProfile && c.targetProfile.defenses.some((d) => d.id === 'cloudflare'), 'WAF fingerprinted');
    assert.equal(c.reconOpts.stealth, 'quiet', 'calibrated profile threaded into the tools');
    assert.equal(c.getState().stealthBudget.profile, 'quiet');
    assert.ok(c.activity.some((e) => e.kind === 'stealth.calibrate'), 'calibration logged');
  } finally { srv.close(); }
});

test('auto-stealth: an unreachable target falls back to normal, never throws', async () => {
  const c = new Campaign({
    engine: {}, scope: { engagement: 'T-auto2', signedBy: 'x', cidrs: ['127.0.0.0/8'] },
    runAgent: mockAgent, targets: ['127.0.0.1'], stealth: 'auto',
    reconOpts: { ports: [1], webPorts: new Set([1]), timeout: 300 }, // nothing listening
  });
  await c._calibrateStealth();
  assert.equal(c.stealthName, 'normal', 'safe fallback');
  assert.equal(c.reconOpts.stealth, 'normal');
});

test('the report renders the defender\'s-eye "what we stayed under" stealth-budget section', () => {
  const c = new Campaign({
    engine: {}, scope: { engagement: 'T-report', signedBy: 'x', cidrs: ['127.0.0.0/8'] },
    runAgent: mockAgent, targets: ['127.0.0.1'], stealth: 'quiet',
  });
  c._noise({ kind: 'tcp-scan', host: '127.0.0.1' });        // loudness 3
  c._noise({ kind: 'http-fingerprint', host: '127.0.0.1' }); // loudness 1
  const md = renderReport(c.surface.toJSON(), { opsec: c.opsec.toJSON(), stealthBudget: c.noise.status() });
  assert.match(md, /stealth budget \(what we stayed under\)/i);
  assert.match(md, /QUIET/);
  assert.match(md, /noise-points/);
  assert.match(md, /Peak-loudness ceiling honored/);
  // an unlimited (loud/no-profile) engagement omits the ceiling framing
  const loud = new Campaign({ engine: {}, scope: { engagement: 'T-loud', signedBy: 'x', cidrs: ['127.0.0.0/8'] }, runAgent: mockAgent });
  loud._noise({ kind: 'tcp-scan', host: '127.0.0.1' });
  const md2 = renderReport(loud.surface.toJSON(), { opsec: loud.opsec.toJSON(), stealthBudget: loud.noise.status() });
  assert.match(md2, /No stealth ceiling was set/i);
});

// ---------- engagement egress audit (2026-09-01): the ledger records WHICH ghost
// exit each engagement uses, and the shared pacer is policed by the ghost shaper.

test('campaign records WHICH ghost exit the engagement uses (ghost.engagement audit event)', async () => {
  const { Ghost } = await import('../engine/ghost.mjs');
  const ghost = new Ghost();
  ghost.configure({ mode: 'required', chain: 'socks5://10.64.0.1:1080' }); // never dialed — constructor audit only
  ghost._verified = { ok: true, baselineIp: '198.51.100.3', exitIp: '135.136.21.33', at: 't' };
  ghost._pin = { expectExit: '135.136.21.33', exitSet: ['135.136.21.33', '135.136.21.34'], at: 't' };
  const c = new Campaign({
    engine: {}, scope: { engagement: 'T-ghostaudit', signedBy: 'x', cidrs: ['127.0.0.0/8'] },
    runAgent: mockAgent, targets: ['127.0.0.1'], ghost,
  });
  const e = c.activity.find((a) => a.kind === 'ghost.engagement');
  assert.ok(e, 'the egress identity is recorded at campaign build');
  assert.equal(e.data.mode, 'required');
  assert.equal(e.data.egress, 'socks5://10.64.0.1:1080', 'canonical creds-stripped egress id');
  assert.equal(e.data.exitIp, '135.136.21.33', 'WHICH exit this engagement used');
  assert.equal(e.data.verified, true);
  assert.deepEqual(e.data.pin.exitSet, ['135.136.21.33', '135.136.21.34']);
  assert.equal(JSON.stringify(e.data).includes('198.51.100.3'), false, 'operator baseline never enters the ledger');

  const off = new Campaign({
    engine: {}, scope: { engagement: 'T-ghostoff', signedBy: 'x', cidrs: ['127.0.0.0/8'] },
    runAgent: mockAgent, targets: ['127.0.0.1'], ghost: new Ghost(),
  });
  assert.equal(off.activity.some((a) => a.kind === 'ghost.engagement'), false, 'ghost off = no egress record (direct is the default posture, nothing to pin)');
});

test('the engagement pacer is POLICED by the ghost shaper when one is armed', async () => {
  const { Ghost } = await import('../engine/ghost.mjs');
  const ghost = new Ghost();
  ghost.configure({ mode: 'on', chain: 'socks5://10.64.0.1:1080', shaper: { minDelayMs: 5000, jitterMs: 0 } });
  const c = new Campaign({
    engine: {}, scope: { engagement: 'T-ghostshaper', signedBy: 'x', cidrs: ['127.0.0.0/8'] },
    runAgent: mockAgent, targets: ['127.0.0.1'], stealth: 'normal', ghost,
  });
  assert.ok(c.pacer, 'a concrete profile still builds the shared pacer');
  assert.ok(c.pacer.nextDelay() >= 5000, 'the ghost shaper floors the engagement cadence');
  assert.deepEqual(c.pacer.shaper, { minDelayMs: 5000, jitterMs: 0, padTo: null });

  const plain = new Campaign({
    engine: {}, scope: { engagement: 'T-ghostshaper-off', signedBy: 'x', cidrs: ['127.0.0.0/8'] },
    runAgent: mockAgent, targets: ['127.0.0.1'], stealth: 'normal', ghost: new Ghost(),
  });
  assert.equal(plain.pacer.shaper, null, 'no shaper armed -> the pacer is unchanged (backward-compatible)');
});
