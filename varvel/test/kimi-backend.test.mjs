// VARVEL Kimi-backend routing tests — hermetic (env-injected, no real key, no CLI needed).
// Model assertions expect the WIRE id `k3`: the raw coding API rejects display ids like
// `kimi-k3` / `kimi-k3[1m]` with a 401 — readBackend normalizes them (see live.mjs wireModelId).
//   node --test varvel/test/kimi-backend.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { kimiBackend, freshOauthToken, exemptApiHostFromProxy } from '../engine/claude-cli.mjs';
import { liveReadiness } from '../engine/live.mjs';

// Force an empty credential environment: no ~/.kimicode config AND no kimi-code OAuth login
// (KIMI_OAUTH_FILE — without it a developer machine's LIVE login would leak into the tests).
const NOHOME = { KIMICODE_HOME: '/nonexistent-kimicode-xyz', KIMI_OAUTH_FILE: '/nonexistent-kimi-oauth-xyz' };

test('kimiBackend: routes the CLI at Kimi when a Kimi key + anthropic endpoint are configured', () => {
  const env = { ...NOHOME, KIMI_API_KEY: 'sk-test-123', KIMI_APITYPE: 'anthropic', KIMI_BASE_URL: 'https://api.kimi.com/coding', KIMI_MODEL: 'kimi-k3' };
  const k = kimiBackend(env);
  assert.ok(k, 'routed');
  assert.equal(k.model, 'k3');
  assert.equal(k.env.ANTHROPIC_BASE_URL, 'https://api.kimi.com/coding');
  assert.equal(k.env.ANTHROPIC_AUTH_TOKEN, 'sk-test-123');
  // aliases VARVEL passes via --model all map onto the Kimi model
  assert.equal(k.env.ANTHROPIC_DEFAULT_SONNET_MODEL, 'k3');
  assert.equal(k.env.ANTHROPIC_DEFAULT_OPUS_MODEL, 'k3');
  assert.equal(k.env.ENABLE_TOOL_SEARCH, 'false', 'Kimi endpoint gotcha handled');
});

test('kimiBackend: also routes the moonshot /anthropic platform endpoint', () => {
  const env = { ...NOHOME, MOONSHOT_API_KEY: 'sk-m', KIMI_BASE_URL: 'https://api.moonshot.ai/anthropic', KIMI_APITYPE: 'anthropic' };
  const k = kimiBackend(env);
  assert.ok(k);
  assert.equal(k.env.ANTHROPIC_BASE_URL, 'https://api.moonshot.ai/anthropic');
});

test('kimiBackend: null when no Kimi key — the CLI stays on the ambient Anthropic account', () => {
  assert.equal(kimiBackend({ ...NOHOME }), null);
});

test('SECURITY: a bare ANTHROPIC_API_KEY is NEVER routed to Kimi (no Kimi-scoped key → no route)', () => {
  // The operator runs their own Claude Code via ANTHROPIC_API_KEY; a Kimi endpoint is configured
  // but NO Kimi-scoped key is present. Must NOT ship the real Anthropic key to Kimi's servers.
  const env = { ...NOHOME, ANTHROPIC_API_KEY: 'sk-ant-REAL-operator-key', KIMI_APITYPE: 'anthropic', KIMI_BASE_URL: 'https://api.kimi.com/coding' };
  assert.equal(kimiBackend(env), null, 'refuses to route the operator Anthropic key to Kimi');
});

test('SECURITY: with BOTH keys set, Kimi gets the Kimi key — never the Anthropic key', () => {
  const env = { ...NOHOME, ANTHROPIC_API_KEY: 'sk-ant-REAL', KIMI_API_KEY: 'sk-kimi-scoped', KIMI_APITYPE: 'anthropic', KIMI_BASE_URL: 'https://api.kimi.com/coding' };
  const k = kimiBackend(env);
  assert.ok(k, 'routes with the Kimi-scoped key present');
  assert.equal(k.env.ANTHROPIC_AUTH_TOKEN, 'sk-kimi-scoped');
  assert.notEqual(k.env.ANTHROPIC_AUTH_TOKEN, 'sk-ant-REAL', 'the Anthropic key is not leaked to Kimi');
});

test('kimiBackend: a Kimi-typed key against a NON-Kimi host does not route (tight host check)', () => {
  // apiType=anthropic but the base is an OpenAI-style / non-Kimi host → must not hijack the CLI.
  const env = { ...NOHOME, KIMI_API_KEY: 'sk-x', KIMI_APITYPE: 'anthropic', KIMI_BASE_URL: 'https://api.moonshot.ai/v1' };
  assert.equal(kimiBackend(env), null, 'moonshot /v1 (OpenAI-shape) is not an Anthropic Kimi endpoint');
  const evil = { ...NOHOME, KIMI_API_KEY: 'sk-x', KIMI_APITYPE: 'anthropic', KIMI_BASE_URL: 'https://not-kimi.com.evil.example/anthropic' };
  assert.equal(kimiBackend(evil), null, 'lookalike host rejected by the anchored host check');
});

test('kimiBackend: does NOT route a plain OpenAI/OpenRouter config onto the Anthropic CLI', () => {
  // openai type + a non-Kimi base → must not hijack the Claude CLI
  const env = { ...NOHOME, OPENROUTER_API_KEY: 'or-key', KIMI_BASE_URL: 'https://openrouter.ai/api/v1', KIMI_APITYPE: 'openai' };
  assert.equal(kimiBackend(env), null);
});

test('liveReadiness reflects Kimi routing (cliOnKimi + model) when a Kimi key is present', () => {
  // Note: cli presence depends on the host having `claude`; assert the Kimi-specific fields
  // that are computed from the backend config regardless of CLI presence.
  const env = { ...NOHOME, KIMI_API_KEY: 'sk-test', KIMI_APITYPE: 'anthropic', KIMI_BASE_URL: 'https://api.kimi.com/coding', KIMI_MODEL: 'kimi-k3' };
  const r = liveReadiness(env, {});
  if (r.backendKind === 'claude-cli-kimi') {
    assert.equal(r.cliOnKimi, true);
    assert.equal(r.model, 'k3');
    assert.ok(r.notes.some((n) => /routed at Kimi/i.test(n)));
  } else {
    // no claude CLI on this host → falls back to the api backend, still Kimi-sourced
    assert.equal(r.backendKind, 'kimi');
    assert.equal(r.model, 'k3');
  }
});

// --- 2026-09-02 regressions: the claude-cli child env must not kill the CLI's own API ---

// A temp credential set: kimicode config with a STALE static key + a kimi-code OAuth file.
function credFixture({ oauthExpiresIn = 900 } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'varvel-kimi-backend-'));
  const kimiHome = join(dir, 'kimicode');
  mkdirSync(kimiHome, { recursive: true });
  writeFileSync(join(kimiHome, 'config.json'), JSON.stringify({ apiKey: 'sk-STALE-static', baseUrl: 'https://api.kimi.com/coding', apiType: 'anthropic' }));
  const oauthFile = join(dir, 'oauth.json');
  const now = Math.floor(Date.now() / 1000);
  writeFileSync(oauthFile, JSON.stringify({ access_token: 'oauth-LIVE-token', refresh_token: 'r', expires_at: now + oauthExpiresIn }));
  return { kimiHome, oauthFile };
}

test('kimiBackend: a FRESH kimi-code OAuth token beats a stale static cfg key (kimi-runagent precedence)', () => {
  // Verified live 2026-09-02: the static cfg key 500s every call while the OAuth token
  // returns 200 — the static key must never shadow the live subscription again.
  const { kimiHome, oauthFile } = credFixture();
  const k = kimiBackend({ KIMICODE_HOME: kimiHome, KIMI_OAUTH_FILE: oauthFile });
  assert.ok(k, 'routed');
  assert.equal(k.env.ANTHROPIC_AUTH_TOKEN, 'oauth-LIVE-token', 'live OAuth token wins over the stale static key');
});

test('kimiBackend: an EXPIRED OAuth token falls back to the static cfg key (honest degrade)', () => {
  const { kimiHome, oauthFile } = credFixture({ oauthExpiresIn: -3600 });
  const k = kimiBackend({ KIMICODE_HOME: kimiHome, KIMI_OAUTH_FILE: oauthFile });
  assert.ok(k, 'still routed');
  assert.equal(k.env.ANTHROPIC_AUTH_TOKEN, 'sk-STALE-static');
});

test('kimiBackend: an explicit env key beats the OAuth token (operator override stays on top)', () => {
  const { kimiHome, oauthFile } = credFixture();
  const k = kimiBackend({ KIMICODE_HOME: kimiHome, KIMI_OAUTH_FILE: oauthFile, KIMI_API_KEY: 'sk-explicit-env' });
  assert.ok(k, 'routed');
  assert.equal(k.env.ANTHROPIC_AUTH_TOKEN, 'sk-explicit-env');
});

test('freshOauthToken: fresh file -> token; missing/stale file -> null', () => {
  const { oauthFile } = credFixture();
  assert.equal(freshOauthToken({ KIMI_OAUTH_FILE: oauthFile }), 'oauth-LIVE-token');
  assert.equal(freshOauthToken({ KIMI_OAUTH_FILE: '/nonexistent-oauth-xyz' }), null);
  const now = Math.floor(Date.now() / 1000);
  assert.equal(freshOauthToken({ KIMI_OAUTH_FILE: oauthFile }, now + 100000), null, 'expired at this clock read');
});

test('exemptApiHostFromProxy: ghost socks vars keep the shell route but exempt the model API host', () => {
  // The 2026-09-02 alsco zero-surface defect: the CLI's own API connection died on the
  // socks5 scheme ('UnsupportedProxyProtocol') — 1 empty step per phase, 0 hosts.
  const env = {
    HTTPS_PROXY: 'socks5://10.64.0.1:1080', https_proxy: 'socks5://10.64.0.1:1080',
    ALL_PROXY: 'socks5://10.64.0.1:1080',
    NO_PROXY: '127.0.0.1,localhost', no_proxy: '127.0.0.1,localhost',
  };
  exemptApiHostFromProxy(env, 'https://api.kimi.com/coding');
  assert.deepEqual(env.NO_PROXY.split(','), ['127.0.0.1', 'localhost', 'api.kimi.com']);
  assert.deepEqual(env.no_proxy.split(','), ['127.0.0.1', 'localhost', 'api.kimi.com']);
  assert.equal(env.HTTPS_PROXY, 'socks5://10.64.0.1:1080', 'shell tools still ride the chain');
});

test('exemptApiHostFromProxy: no proxy vars -> NO_PROXY not invented; missing base -> anthropic default', () => {
  const clean = {};
  exemptApiHostFromProxy(clean, 'https://api.kimi.com/coding');
  assert.equal(clean.NO_PROXY, undefined);
  assert.equal(clean.no_proxy, undefined);
  const env = { ALL_PROXY: 'socks5://10.64.0.1:1080' };
  exemptApiHostFromProxy(env, undefined);
  assert.ok(env.NO_PROXY.includes('api.anthropic.com'));
  exemptApiHostFromProxy(env, 'https://api.kimi.com/coding');
  assert.equal(env.NO_PROXY.split(',').filter((h) => h === 'api.kimi.com').length, 1, 'no duplicate host');
});
