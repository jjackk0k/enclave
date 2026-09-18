// recon-wiring.test.mjs — hermetic tests for the campaign wiring of osfp/ldapenum/canary.
// Uses the reconOpts seams (smbPorts/ldapPorts + *Impl) so fixtures stand in for 445/389.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { Campaign } from '../engine/campaign.mjs';
import { mockAgent } from '../mock-agent.mjs';

function listeningSocket() {
  return new Promise((resolve) => {
    const srv = net.createServer((c) => c.end());
    srv.listen(0, '127.0.0.1', () => resolve(srv));
  });
}

test('tooledRecon: osfp fires ONLY on the SMB-signal port and writes OS tech to the surface', async () => {
  const srv = await listeningSocket();
  const port = srv.address().port;
  const calls = [];
  try {
    const c = new Campaign({
      engine: {}, scope: { engagement: 'T-osfp', signedBy: 'x', cidrs: ['127.0.0.0/8'] },
      runAgent: mockAgent, targets: ['127.0.0.1'], tooledRecon: true,
      reconOpts: {
        ports: [port], webPorts: new Set(), timeout: 900,
        smbPorts: [port],
        osfpImpl: async (host, opts) => { calls.push({ host, opts }); return { host, family: 'windows', version: 'Windows 10/11 / Server 2016+', confidence: 55, signals: [], caveats: [] }; },
      },
    });
    await c.tooledRecon();
    const s = c.surface.toJSON();
    assert.equal(calls.length, 1, 'osfp called exactly once for the SMB host');
    assert.equal(calls[0].host, '127.0.0.1');
    assert.ok(s.nodes.some((n) => n.type === 'tech' && /OS:windows/.test(n.label)), 'OS tech node on surface');
    assert.ok(c.activity.some((a) => a.kind === 'recon.tool' && a.data?.osFamily === 'windows'), 'recon.tool log carries the verdict');
  } finally { srv.close(); }
});

test('tooledRecon: osfp skipped when no SMB port (no wasted packets)', async () => {
  const srv = await listeningSocket();
  const port = srv.address().port;
  let called = 0;
  try {
    const c = new Campaign({
      engine: {}, scope: { engagement: 'T-osfp2', signedBy: 'x', cidrs: ['127.0.0.0/8'] },
      runAgent: mockAgent, targets: ['127.0.0.1'], tooledRecon: true,
      reconOpts: { ports: [port], webPorts: new Set(), timeout: 900, osfpImpl: async () => { called++; return { family: 'unknown', signals: [], caveats: [] }; } },
    });
    await c.tooledRecon();
    assert.equal(called, 0, 'no 445-class port → osfp never fires');
  } finally { srv.close(); }
});

test('tooledRecon: ldap enum fires on the directory port and surfaces the domain DN', async () => {
  const srv = await listeningSocket();
  const port = srv.address().port;
  try {
    const c = new Campaign({
      engine: {}, scope: { engagement: 'T-ldap', signedBy: 'x', cidrs: ['127.0.0.0/8'] },
      runAgent: mockAgent, targets: ['127.0.0.1'], tooledRecon: true,
      reconOpts: {
        ports: [port], webPorts: new Set(), timeout: 900,
        ldapPorts: [port],
        ldapImpl: async () => ({ reachable: true, anonymous: true, defaultNamingContext: 'DC=corp,DC=example,DC=test', functionality: { domain: 'Windows Server 2016 or later' }, vendorGuess: 'active-directory', verdict: 'AD readable anonymously' }),
      },
    });
    await c.tooledRecon();
    const s = c.surface.toJSON();
    assert.ok(s.nodes.some((n) => n.type === 'tech' && /LDAP:active-directory/.test(n.label)), 'LDAP vendor tech node');
    assert.ok(c.surface.phaseLog.some((n) => /DC=corp,DC=example,DC=test/.test(n.summary)), 'domain DN noted in phase log');
  } finally { srv.close(); }
});

test('tooledRecon: deception verdict from data-fed subdomains lands on state', async () => {
  const live = new Set(['admin.acme.test', 'backup.acme.test']);
  const resolver = { resolve4: async (h) => { if (live.has(h)) return ['10.0.0.5']; throw new Error('ENOTFOUND'); } };
  const c = new Campaign({
    engine: {}, scope: { engagement: 'T-dec', signedBy: 'x', cidrs: ['10.0.0.0/8'] },
    runAgent: mockAgent, targets: [], tooledRecon: true,
    reconOpts: { domain: 'acme.test', words: ['admin', 'backup'], resolver, passive: false },
  });
  await c.tooledRecon();
  const st = c.getState();
  assert.ok(st.deception, 'deception verdict present on state');
  assert.ok(st.deception.suspicion > 0, 'bait-subdomain cluster scored');
  assert.ok(st.deception.artifacts.some((a) => a.kind === 'bait-subdomain'));
  assert.ok(c.surface.phaseLog.some((n) => n.phase === 'deception' && /suspicion/.test(n.summary)), 'deception note in phase log');
});

test('tooledRecon: canary kill switch honored', async () => {
  const live = new Set(['admin.acme.test', 'backup.acme.test']);
  const resolver = { resolve4: async (h) => { if (live.has(h)) return ['10.0.0.5']; throw new Error('ENOTFOUND'); } };
  const c = new Campaign({
    engine: {}, scope: { engagement: 'T-dec2', signedBy: 'x', cidrs: ['10.0.0.0/8'] },
    runAgent: mockAgent, targets: [], tooledRecon: true,
    reconOpts: { domain: 'acme.test', words: ['admin', 'backup'], resolver, passive: false, canary: false },
  });
  await c.tooledRecon();
  assert.equal(c.getState().deception, null);
});
