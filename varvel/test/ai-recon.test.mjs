// VARVEL Adversarial-AI-Recon tests — hermetic mock AI services, localhost only.
//   node --test varvel/test/ai-recon.test.mjs

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { aiFingerprint, aiRecon, AI_PORTS, AI_PORTS_GENERIC } from '../tools/ai-recon.mjs';

// A mock "Ollama": /api/tags returns a model list; / is a plain page.
function mockOllama(routes) {
  const srv = http.createServer((req, res) => {
    const r = routes[req.url] || { status: 404, body: 'nope' };
    res.writeHead(r.status, r.headers || { 'content-type': 'application/json' });
    res.end(r.body || '');
  });
  return srv;
}

let ollama, plain, ollamaPort, plainPort;
before(async () => {
  ollama = mockOllama({
    '/': { status: 200, headers: { 'content-type': 'text/html' }, body: '<html>Ollama is running</html>' },
    '/api/tags': { status: 200, body: '{"models":[{"name":"llama3:8b"},{"name":"qwen2.5:7b"}]}' },
    '/api/version': { status: 200, body: '{"version":"0.1.44"}' },
  });
  plain = mockOllama({ '/': { status: 200, headers: { 'content-type': 'text/html' }, body: '<html>Just a website</html>' } });
  await new Promise((r) => ollama.listen(0, '127.0.0.1', r));
  await new Promise((r) => plain.listen(0, '127.0.0.1', r));
  ollamaPort = ollama.address().port; plainPort = plain.address().port;
});
after(() => { ollama && ollama.close(); plain && plain.close(); });

test('aiFingerprint detects an exposed Ollama by its endpoints', async () => {
  const fp = await aiFingerprint('127.0.0.1', ollamaPort, { timeout: 1500 });
  assert.ok(fp, 'AI service detected');
  const clss = fp.services.map((s) => s.cls);
  assert.ok(clss.includes('ollama'), 'classified as ollama');
  const ol = fp.services.find((s) => s.cls === 'ollama');
  assert.match(ol.evidence, /api\/(tags|version)|model/i);
});

test('aiFingerprint returns null for a plain website', async () => {
  const fp = await aiFingerprint('127.0.0.1', plainPort, { timeout: 1500 });
  assert.equal(fp, null);
});

test('aiRecon flags exposed AI data endpoints as findings', async () => {
  const r = await aiRecon('127.0.0.1', { ports: [ollamaPort, plainPort], timeout: 1500 });
  assert.equal(r.aiHosts.length, 1, 'only the AI host is reported');
  assert.ok(r.findings.some((f) => /Ollama|ollama|AI infrastructure/i.test(f.title)), 'exposed model list is a finding');
  assert.ok(r.findings[0].sev === 'high');
});

test('AI_PORTS catalog: strong ports flag alone; generic web ports need corroboration', () => {
  assert.equal(AI_PORTS[11434], 'ollama');
  assert.equal(AI_PORTS[6333], 'qdrant');
  assert.ok(Object.keys(AI_PORTS).length >= 8);
  // the 8080 class of false positives: generic web ports no longer flag AI from the
  // port number alone — a Tomcat/dev-server on 8080 is not "AI infrastructure"
  for (const p of [8080, 5000, 3000, 8000]) assert.equal(AI_PORTS[p], undefined, `generic port ${p} out of the strong catalog`);
  assert.equal(AI_PORTS_GENERIC[8080], 'ai-gateway');
  assert.equal(AI_PORTS_GENERIC[5000], 'ai-app');
  assert.equal(AI_PORTS_GENERIC[3000], 'ai-frontend');
  assert.equal(AI_PORTS_GENERIC[8000], 'ai-api');
});

test('generic-port hosts still detect when endpoints corroborate', async () => {
  // the mock Ollama sits on an ephemeral (uncatalogued) port: detection comes from
  // /api/tags + /api/version — proof that signature evidence, not the port number,
  // carries the classification on non-strong ports
  const fp = await aiFingerprint('127.0.0.1', ollamaPort, { timeout: 1500 });
  assert.ok(fp.services.every((s) => s.via !== 'port'), 'no port-only detection on a non-strong port');
});
