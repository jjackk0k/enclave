// VARVEL tooled-recon integration test — hermetic (own local server), localhost only.
//   node --test varvel/test/tooled.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { Campaign } from '../engine/campaign.mjs';
import { mockAgent } from '../mock-agent.mjs';

test('tooledRecon: native scan + content discovery populate the surface', async () => {
  const srv = http.createServer((req, res) => {
    if (req.url === '/') { res.writeHead(200, { server: 'nginx/1.25' }); return res.end('<title>Target</title>'); }
    if (req.url === '/.git/HEAD') { res.writeHead(200); return res.end('ref: refs/heads/main'); }
    if (req.url === '/admin') { res.writeHead(200); return res.end('admin'); }
    res.writeHead(404); res.end();
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const port = srv.address().port;
  try {
    const c = new Campaign({
      engine: {}, scope: { engagement: 'T-tool', signedBy: 'x', cidrs: ['127.0.0.0/8'] },
      runAgent: mockAgent, targets: ['127.0.0.1'], tooledRecon: true,
      reconOpts: { ports: [port], webPorts: new Set([port]), timeout: 900 },
    });
    await c.tooledRecon();
    const s = c.surface.toJSON();
    assert.ok(s.counts.hosts >= 1, 'host discovered by scanner');
    assert.ok(s.counts.svcs >= 1, 'service discovered');
    assert.ok(s.counts.tech >= 1, 'tech fingerprinted (Server header)');
    assert.ok(s.counts.endpoints >= 1, 'endpoints from content discovery');
    assert.ok(s.counts.findings >= 1, 'sensitive exposure recorded as finding');
    assert.ok(s.nodes.some((n) => n.type === 'finding' && /git/i.test(n.label)), '.git exposure flagged');
  } finally {
    srv.close();
  }
});

test('tooledRecon: domain subdomain discovery feeds the surface (mock resolver)', async () => {
  const live = new Set(['www.acme.test', 'vpn.acme.test']);
  const resolver = { resolve4: async (h) => { if (live.has(h)) return ['10.0.0.5']; throw new Error('ENOTFOUND'); } };
  // Passive sources are mocked too — hermetic suite, never real provider traffic.
  const passiveFetch = async (url) => url.includes('crt.sh')
    ? { ok: true, status: 200, text: async () => JSON.stringify([{ name_value: 'ftp.acme.test\nwww.acme.test' }]) }
    : { ok: true, status: 200, text: async () => JSON.stringify([['original'], ['http://static.acme.test/old-admin?page=1']]) };
  const c = new Campaign({
    engine: {}, scope: { engagement: 'T-dom', signedBy: 'x', cidrs: ['10.0.0.0/8'] },
    runAgent: mockAgent, targets: [], tooledRecon: true,
    reconOpts: { domain: 'acme.test', words: ['www', 'vpn', 'nope'], resolver, passive: { fetchImpl: passiveFetch } },
  });
  await c.tooledRecon();
  const s = c.surface.toJSON();
  assert.ok(s.counts.subdomains >= 2, 'subdomains discovered via DNS');
  const names = s.nodes.filter((n) => n.type === 'subdomain').map((n) => n.label);
  assert.ok(names.includes('ftp.acme.test'), 'passive CT-log subdomain merged');
  assert.ok(s.nodes.some((n) => n.type === 'endpoint' && /old-admin/.test(n.label)), 'passive archive endpoint merged');
});
