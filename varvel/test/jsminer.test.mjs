// VARVEL jsminer tests — endpoint/secret extraction (pure), the sourcemap
// second pass, the fail-closed scope gate, budget honesty, and the OPT-IN
// secret oracle against a local mock STS. No live network.
//   node --test varvel/test/jsminer.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { extractEndpoints, extractSecrets, endpointsToCandidates, shannon, mine, verifySecret, hostAllowed } from '../tools/jsminer.mjs';
import { harvestExchanges, synthesizeCandidates } from '../tools/authzsweep.mjs';

// ——— pure: extraction ———

test('extractEndpoints: quoted paths + absolute URLs, assets and placeholders skipped', () => {
  const js = `fetch("/api/users/1042"); const u='/v2/orders/ORD-99'; const c="/static/app.css";
    const ext="https://api.acme-corp.io/v2/keys"; const doc="https://docs.example.com/x"; const bad="//cdn.x.io/a.js";`;
  const eps = extractEndpoints(js);
  assert.ok(eps.paths.includes('/api/users/1042') && eps.paths.includes('/v2/orders/ORD-99'));
  assert.ok(!eps.paths.includes('/static/app.css'), 'static assets are not endpoints');
  assert.ok(!eps.paths.includes('/cdn.x.io/a.js'), 'protocol-relative is not a path');
  assert.ok(eps.urls.includes('https://api.acme-corp.io/v2/keys'));
  assert.ok(!eps.urls.some((x) => x.includes('docs.example.com')), 'doc placeholder TLDs are not surface');
  assert.deepEqual(extractEndpoints(''), { paths: [], urls: [] });
});

test('extractSecrets: the trufflehog/gitleaks set, entropy gate, placeholder denylist', () => {
  const js = `
    const aws = "AKIAIOSFODNN7EXAMPLE";
    const g = "AIzaSyD4iE2jKXvQ3mVbN8cL0pR1tY5uI7oP9aQ";
    const gh = "ghp_${'aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3x'}";
    const key = "-----BEGIN PRIVATE KEY-----\\nMIIEvg\\n-----END PRIVATE KEY-----";
    const api_secret = "g7K2pX9wQ4vZ8nR1tB6yU3mA5cE0fH7jL";
    const decoy_low = "aaaaaaaaaaaaaaaaaaaaaaaa"; const api_key_low = "aaaaaaaaaaaaaaaaaaaaaaaa";
    const placeholder = "your-api-key-here"; const apiKey2 = "your-api-key-here";`;
  const secs = extractSecrets(js);
  const types = secs.map((s) => s.type);
  assert.ok(types.includes('aws-access-key-id'));
  assert.ok(types.includes('google-api-key'));
  assert.ok(types.includes('github-token'));
  assert.ok(types.includes('private-key-block'));
  assert.ok(types.includes('generic-high-entropy'), 'high-entropy assignment caught');
  assert.ok(secs.every((s) => s.value !== 'aaaaaaaaaaaaaaaaaaaaaaaa'), 'low-entropy decoy excluded (Shannon gate)');
  assert.ok(secs.every((s) => s.value !== 'your-api-key-here'), 'placeholder denylisted');
  assert.ok(secs.every((s) => s.status === 'candidate'), 'extraction NEVER verifies — everything stays a candidate');
  assert.ok(secs.every((s) => !s.redacted.includes(s.value.slice(8))), 'redacted form does not leak the whole secret');
  assert.ok(shannon('g7K2pX9wQ4vZ8nR1tB6yU3mA5cE0fH7jL') > 3.5 && shannon('aaaaaaaaaaaaaaaaaaaaaaaa') < 1);
});

test('endpointsToCandidates: {id} folding in the synthesizeCandidates shape', () => {
  const cands = endpointsToCandidates(['/api/users/1042', '/api/users/ORD-1042', '/api/health']);
  assert.deepEqual(cands.map((c) => c.path), ['/api/users/{id}'], 'concrete ids fold, deduped, plain paths stay out');
  assert.deepEqual(cands[0].refs, { a: [], b: [] });
  // the authzsweep oracle consumes them directly as templates
  const out = synthesizeCandidates(harvestExchanges([]), cands);
  assert.ok(out.some((c) => c.path === '/api/users/{id}' && c.configured), 'synthesizeCandidates accepts the shape');
});

test('hostAllowed: fail-closed semantics', () => {
  assert.equal(hostAllowed('api.acme.io', { hosts: ['acme.io'] }), true);
  assert.equal(hostAllowed('evil.io', { hosts: ['acme.io'] }), false);
  assert.equal(hostAllowed('anything.io', null), true, 'no scope = no host constraint (lab default)');
});

// ——— live (127.0.0.1): the governed mine ———

const APP_JS = `
fetch("/api/users/1042");
const order = '/api/orders/ORD-99';
const ext = "https://api.acme-corp.io/v2/keys";
const aws = "AKIAIOSFODNN7EXAMPLE";
const g = "AIzaSyD4iE2jKXvQ3mVbN8cL0pR1tY5uI7oP9aQ";
const k = "-----BEGIN PRIVATE KEY-----";
const api_secret = "g7K2pX9wQ4vZ8nR1tB6yU3mA5cE0fH7jL";
//# sourceMappingURL=/app.js.map
`;
const APP_MAP = JSON.stringify({
  version: 3,
  sources: ['webpack:///src/hidden.js'],
  sourcesContent: [`const route = '/api/internal/invoices/INV-7781';\nconst backup = "AKIAJX7YQ2W3E4R5T6U7";`],
});
const INDEX_HTML = `<html><head><script src="/app.js"></script><script src="http://evil-cdn.io/x.js"></script><script src="/out/scope.js"></script></head><body>hi</body></html>`;

function createTarget(hits) {
  const srv = http.createServer((req, res) => {
    hits.push(req.url);
    if (req.url === '/') { res.writeHead(200, { 'content-type': 'text/html' }); return res.end(INDEX_HTML); }
    if (req.url === '/app.js') { res.writeHead(200, { 'content-type': 'application/javascript' }); return res.end(APP_JS); }
    if (req.url === '/app.js.map') { res.writeHead(200, { 'content-type': 'application/json' }); return res.end(APP_MAP); }
    if (req.url === '/out/scope.js') { res.writeHead(200); return res.end('// out of prefix'); }
    res.writeHead(404); res.end();
  });
  srv.on('clientError', (e, sock) => { try { sock.destroy(); } catch {} });
  return srv;
}

async function withTarget(fn) {
  const hits = [];
  const srv = createTarget(hits);
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  try { return await fn(base, hits); }
  finally { await new Promise((r) => srv.close(r)); }
}

test('mine: HTML → scripts → sourcemap → sourcesContent; verify stays OPT-IN', () => withTarget(async (base, hits) => {
  const r = await mine(base + '/', { pathPrefixes: ['/app'] });
  assert.equal(r.ok, true, r.error);
  assert.deepEqual(hits.filter((h) => h === '/'), ['/'], 'the page was fetched once');
  assert.ok(hits.includes('/app.js') && hits.includes('/app.js.map'), 'script + sourcemap fetched');
  assert.ok(!hits.includes('/out/scope.js'), 'out-of-prefix script refused before the wire');
  assert.ok(r.refusals.some((x) => x.url === 'http://evil-cdn.io/x.js' && x.reason === 'out-of-scope-host'), 'cross-host script refused');
  assert.ok(r.refusals.some((x) => x.reason === 'out-of-scope-path'));
  // endpoints from BOTH the shipped JS and the reconstructed sourcesContent
  assert.ok(r.endpoints.paths.includes('/api/users/1042'));
  assert.ok(r.endpoints.paths.includes('/api/internal/invoices/INV-7781'), 'sourcemap sourceContent mined');
  assert.ok(r.endpoints.urls.includes('https://api.acme-corp.io/v2/keys'));
  // candidates in the authzsweep shape, incl. the sourcemap-only route
  const paths = r.candidates.map((c) => c.path);
  assert.ok(paths.includes('/api/users/{id}') && paths.includes('/api/internal/invoices/{id}'));
  assert.ok(r.candidates.every((c) => c.path.includes('{id}') && c.refs && c.source === 'jsminer'));
  // secrets from both passes; NONE verified — the oracle never fires uninvited
  assert.ok(r.secrets.filter((s) => s.type === 'aws-access-key-id').length === 2, 'both AKIA keys (JS + map)');
  assert.ok(r.secrets.every((s) => s.status === 'candidate'));
  assert.equal(r.verification.attempted, false, 'verify is opt-in and was NOT invited');
  assert.equal(r.sourcemaps[0].mined, true);
}));

test('mine: FAIL-CLOSED outside a signed scope — refusal, zero requests', () => withTarget(async (base, hits) => {
  const r = await mine(base + '/', { scope: { hosts: ['acme.io'] } });
  assert.equal(r.ok, false);
  assert.match(r.error, /outside the signed scope/);
  assert.equal(r.refusals[0].reason, 'out-of-scope-host');
  assert.equal(hits.length, 0, 'nothing was dialed');
}));

test('mine: budget exhaustion stops honestly and logs budget.exhausted', () => withTarget(async (base, hits) => {
  const logs = [];
  const r = await mine(base + '/', { budget: { maxRequests: 1 }, onLog: (l) => logs.push(l) });
  assert.equal(r.ok, true);
  assert.deepEqual(hits, ['/'], 'one request bought the HTML; scripts starved');
  assert.ok(logs.some((l) => l.type === 'budget.exhausted' && l.tool === 'jsminer'));
}));

// ——— the secret oracle, opt-in, against a LOCAL mock STS ———

function createMockSts(hits) {
  const srv = http.createServer((req, res) => {
    hits.push(req.url);
    res.writeHead(403, { 'content-type': 'text/xml' });
    // the differential: known key id → SignatureDoesNotMatch; unknown → InvalidClientTokenId
    res.end(decodeURIComponent(req.url).includes('AKIAIOSFODNN7EXAMPLE')
      ? '<ErrorResponse><Error><Code>SignatureDoesNotMatch</Code></Error></ErrorResponse>'
      : '<ErrorResponse><Error><Code>InvalidClientTokenId</Code></Error></ErrorResponse>');
  });
  srv.on('clientError', (e, sock) => { try { sock.destroy(); } catch {} });
  return srv;
}

test('verifySecret: the STS differential proves the key exists — exactly one governed request each', async () => {
  const hits = [];
  const sts = createMockSts(hits);
  await new Promise((r) => sts.listen(0, '127.0.0.1', r));
  const ep = { aws: `http://127.0.0.1:${sts.address().port}` };
  try {
    const live = await verifySecret({ type: 'aws-access-key-id', value: 'AKIAIOSFODNN7EXAMPLE', redacted: 'AKIAIO…LE' }, { endpoints: ep });
    assert.equal(live.verified, true);
    assert.match(live.detail, /KNOWN to AWS/);
    const dead = await verifySecret({ type: 'aws-access-key-id', value: 'AKIAJX7YQ2W3E4R5T6U7', redacted: 'AKIAJX…U7' }, { endpoints: ep });
    assert.equal(dead.verified, false);
    assert.match(dead.detail, /does not know/);
    assert.equal(hits.length, 2, 'one request per verification, no more');
    const unhandled = await verifySecret({ type: 'slack-token', value: 'xoxb-1234567890-abcdefghijkl' }, { endpoints: ep });
    assert.equal(unhandled.verified, false);
    assert.match(unhandled.reason, /no verifier/);
    assert.equal(hits.length, 2, 'no verifier = no request');
    // unreachable verifier → honest, never throws
    const off = await verifySecret({ type: 'aws-access-key-id', value: 'AKIAIOSFODNN7EXAMPLE' }, { endpoints: { aws: 'http://127.0.0.1:1' }, timeout: 250 });
    assert.equal(off.verified, false);
    assert.match(off.reason, /unreachable/);
  } finally { await new Promise((r) => sts.close(r)); }
});

test('mine with verify:true: graduates only the live key, through the local verifier', () => withTarget(async (base) => {
  const sts = createMockSts([]);
  await new Promise((r) => sts.listen(0, '127.0.0.1', r));
  try {
    const r = await mine(base + '/', { verify: true, verifyEndpoints: { aws: `http://127.0.0.1:${sts.address().port}` } });
    assert.equal(r.verification.attempted, true);
    const aws = r.secrets.filter((s) => s.type === 'aws-access-key-id');
    assert.equal(aws.find((s) => s.value === 'AKIAIOSFODNN7EXAMPLE').status, 'verified', 'the live key graduated by live use');
    assert.equal(aws.find((s) => s.value === 'AKIAJX7YQ2W3E4R5T6U7').status, 'candidate', 'the dead key honestly stays a candidate');
  } finally { await new Promise((r) => sts.close(r)); }
}));
