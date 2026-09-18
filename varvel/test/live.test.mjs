// VARVEL live-mode config tests — backend + governance assembly + readiness.
// Hermetic: env is injected, no real API calls, no network.
//   node --test varvel/test/live.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { readBackend, governance, liveEngine, liveReadiness, operatingBrief, wireModelId, HOOK_PATH, DEMO_SESSION } from '../engine/live.mjs';

test('readBackend honors an env key override and returns a full shape', () => {
  const b = readBackend({ VARVEL_API_KEY: 'k-test-123' });
  assert.equal(b.apiKey, 'k-test-123');
  assert.ok(b.apiBase && b.apiType && b.model, 'apiBase/apiType/model present');
});

test('readBackend: no key + no config -> empty key, source none', () => {
  const b = readBackend({ KIMICODE_HOME: 'C:/nonexistent-varvel-test-dir-xyz' });
  assert.equal(b.apiKey, '');
  assert.equal(b.source, 'none');
});

test('governance: sessionFile override beats env; hookPath is the seam hook', () => {
  const g = governance({ ENCLAVE_SESSION: '/env/session.json' }, { sessionFile: '/override.json' });
  assert.equal(g.sessionFile, '/override.json');
  assert.equal(g.hookPath, HOOK_PATH);
  assert.equal(governance({ ENCLAVE_SESSION: '/env/session.json' }).sessionFile, '/env/session.json');
});

test('liveEngine assembles exactly what runGovernedAgent needs', () => {
  const e = liveEngine({ VARVEL_API_KEY: 'k', ENCLAVE_SESSION: DEMO_SESSION });
  for (const k of ['model', 'apiBase', 'apiKey', 'apiType', 'hookPath', 'sessionFile', 'wsDir', 'container', 'maxSteps']) assert.ok(k in e, 'has ' + k);
  assert.equal(e.apiKey, 'k');
  assert.equal(e.sessionFile, DEMO_SESSION);
  assert.equal(e.hookPath, HOOK_PATH);
});

test('liveReadiness: demo session present -> ready; bogus session -> not, with a note', () => {
  const r = liveReadiness({ VARVEL_API_KEY: 'k' }, { sessionFile: DEMO_SESSION });
  assert.equal(r.backend, true);
  assert.equal(r.hook, existsSync(HOOK_PATH));
  assert.equal(r.session, true);
  assert.equal(r.ready, r.backend && r.hook && r.session);

  const r2 = liveReadiness({ VARVEL_API_KEY: 'k' }, { sessionFile: 'C:/nope-xyz.json' });
  assert.equal(r2.session, false);
  assert.ok(r2.notes.some((n) => /signed session/i.test(n)), 'explains the missing session');

  // No Kimi key AND CLI disabled -> no backend (VARVEL_NO_CLI forces off the host CLI).
  const r3 = liveReadiness({ KIMICODE_HOME: 'C:/nonexistent-xyz', VARVEL_NO_CLI: '1' }, { sessionFile: DEMO_SESSION });
  assert.equal(r3.backend, false);
  assert.equal(r3.backendKind, 'none');
  assert.ok(r3.notes.some((n) => /backend/i.test(n)), 'explains the missing backend');
});

test('readiness prefers the Claude CLI backend when present (host-side, no container)', () => {
  // Hermetic: force an empty ~/.kimicode so this doesn't read the operator's real Kimi config.
  const r = liveReadiness({ KIMICODE_HOME: 'C:/nonexistent-varvel-test-dir-xyz' }, { sessionFile: DEMO_SESSION });
  if (r.backendKind === 'claude-cli') {
    assert.ok(!r.notes.some((n) => /container/i.test(n)), 'CLI backend needs no container');
  }
  assert.ok(['claude-cli', 'claude-cli-kimi', 'kimi', 'none'].includes(r.backendKind));
});

test('the bundled demo session exists (minted + loopback-scoped)', () => {
  assert.ok(existsSync(DEMO_SESSION), 'demo.json present');
});

test('wireModelId: k3 config display ids never reach the wire (the kimi-k3[1m] 401 regression)', () => {
  // The raw coding API 401s on the display id the k3 CLI stores in ~/.kimicode/config.json.
  assert.equal(wireModelId('kimi-k3[1m]', 'anthropic'), 'k3');
  assert.equal(wireModelId('kimi-k3', 'anthropic'), 'k3');
  assert.equal(wireModelId('k3', 'anthropic'), 'k3');
  assert.equal(wireModelId('kimi-k2.7-code', 'anthropic'), 'kimi-k2.7-code');
  // OpenAI-shape backends keep their own ids; only the [1m] tag is stripped.
  assert.equal(wireModelId('qwen/qwen3-coder:free', 'openai'), 'qwen/qwen3-coder:free');
  assert.equal(wireModelId('kimi-k3[1m]', 'openai'), 'kimi-k3');
});

test('readBackend normalizes an env-supplied display id on the anthropic path', () => {
  const b = readBackend({
    KIMICODE_HOME: 'C:/nonexistent-varvel-test-dir-xyz',
    VARVEL_API_KEY: 'k', KIMI_APITYPE: 'anthropic', KIMI_BASE_URL: 'https://api.kimi.com/coding',
    KIMI_MODEL: 'kimi-k3[1m]',
  });
  assert.equal(b.model, 'k3');
});

test('operatingBrief states the contract, governance, OPSEC and boundary', () => {
  const b = operatingBrief().toLowerCase();
  assert.ok(b.includes('json'), 'output contract');
  assert.ok(b.includes('confidence'), 'confidence is load-bearing');
  assert.ok(b.includes('denial') && b.includes('final'), 'denials are final');
  assert.ok(b.includes('scope'), 'stay in scope');
  assert.ok(b.includes('clean'), 'record + clean up');
  assert.ok(b.includes('minimum'), 'minimum force');
});

test('operatingBrief names the platform arsenal (the AI must know what it owns)', () => {
  const b = operatingBrief().toLowerCase();
  for (const tool of ['detoracle', 'fporacle', 'floworacle', 'tradecraft', 'preflight']) {
    assert.ok(b.includes(tool), 'arsenal names ' + tool);
  }
  for (const tool of ['cfride', 'sessride', 'cfbrowser', 'rendercheck']) {
    assert.ok(b.includes(tool), 'arsenal names ' + tool);
  }
  assert.ok(b.includes('http/dns/icmp/doh/ws'), 'arsenal names the five transports');
  assert.ok(b.includes('never assert'), 'oracle honesty doctrine carried');
});

test('operatingBrief carries the validator doctrine (proof vs belief)', () => {
  const b = operatingBrief().toLowerCase();
  assert.ok(b.includes('proof standard'), 'doctrine section present');
  assert.ok(b.includes('objective oracle'), 'success needs an objective oracle');
  assert.ok(b.includes('falsify yourself'), 'self-falsification before reporting');
  assert.ok(b.includes('collision-proof'), 'collision-proof markers');
  assert.ok(b.includes('untested'), 'absence of evidence reported as untested');
  assert.ok(b.includes('pivot'), 'difficulty discipline / forced pivot');
  assert.ok(b.includes('validate'), 'validator gate: the validate command is carried');
});

test('operatingBrief carries the chains doctrine (compose → execute → impact-or-failed)', () => {
  const b = operatingBrief().toLowerCase();
  assert.ok(b.includes('compos'), 'engine composes candidate chains');
  assert.ok(b.includes('chainrun'), 'chainrun is the executor');
  assert.ok(b.includes('impact assertion'), 'a chain is proved only when impact passes');
  assert.ok(b.includes('hollow'), 'hollow successes are failures, never proved');
});
