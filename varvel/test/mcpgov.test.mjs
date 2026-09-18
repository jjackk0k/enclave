// mcpgov.test.mjs — the governance bridge verdict matrix (engine/mcpgov.mjs).
// Pure verdict logic + the audit-entry shape; the one impure sink is exercised
// against varvel/.tmp per the house rule.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, readFileSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  VERDICT, POLICY_CLASS, judgeCall, externalPolicy, normalizeTargetHost, extractTargets,
  redactArgs, makeAuditEntry, fileAuditSink,
} from '../engine/mcpgov.mjs';

const TMP = join(dirname(fileURLToPath(import.meta.url)), '..', '.tmp', 'mcpgov-test');
mkdirSync(TMP, { recursive: true });

const SCOPE = { cidrs: ['127.0.0.0/8', '192.168.50.0/24'] };
const TARGET_URL = { class: POLICY_CLASS.TARGET, targetFields: ['url'] };
const GHOST_DOWN = { mode: 'required', verifiedOk: false };
const GHOST_UP = { mode: 'required', verifiedOk: true };
const judge = (over) => judgeCall({ direction: 'server', tool: 'varvel_crawl', args: { url: 'http://127.0.0.1:8000/' }, policy: TARGET_URL, scope: SCOPE, ...over });

// ── direction A (inbound to VARVEL tools) ────────────────────────────────────

test('read-only tool: always allow, even ghost-required-down', () => {
  const ro = { class: POLICY_CLASS.READONLY, targetFields: [] };
  assert.equal(judge({ tool: 'varvel_ghost_status', args: {}, policy: ro }).verdict, VERDICT.ALLOW);
  assert.equal(judge({ tool: 'varvel_ghost_status', args: {}, policy: ro, ghost: GHOST_DOWN }).verdict, VERDICT.ALLOW);
});

test('in-scope IP target -> allow; out-of-scope private IP -> DENY (final)', () => {
  assert.equal(judge().verdict, VERDICT.ALLOW);
  const lab = judge({ args: { url: 'http://192.168.50.130/' } });
  assert.equal(lab.verdict, VERDICT.ALLOW);
  const out = judge({ args: { url: 'http://10.9.9.9/' } });
  assert.equal(out.verdict, VERDICT.DENY);
  assert.match(out.reason, /outside the signed scope/);
});

test('IPv6 target: in-scope ULA allows; outside the ring denies', () => {
  const v6 = { cidrs: ['fd00::/7'] };
  assert.equal(judge({ args: { url: 'http://[fd00::1]/' }, scope: v6 }).verdict, VERDICT.ALLOW);
  assert.equal(judge({ args: { url: 'http://[fd00::1]/' }, scope: SCOPE }).verdict, VERDICT.DENY);
});

test('empty scope grants nothing (fail-closed)', () => {
  assert.equal(judge({ scope: { cidrs: [] } }).verdict, VERDICT.DENY);
  assert.equal(judge({ scope: undefined }).verdict, VERDICT.DENY);
});

test('hostname: engagement-surfaced name allows; unsurfaced name HOLDS (operator-resolvable)', () => {
  const known = judge({ args: { url: 'http://web01.lab.local/' }, knownHosts: ['web01.lab.local'] });
  assert.equal(known.verdict, VERDICT.ALLOW);
  const unknown = judge({ args: { url: 'http://web02.lab.local/' }, knownHosts: ['web01.lab.local'] });
  assert.equal(unknown.verdict, VERDICT.HOLD);
  assert.match(unknown.reason, /held for the operator/);
});

test('ghost required + unverified: target-touching DENIED; verified again -> allow', () => {
  const down = judge({ ghost: GHOST_DOWN });
  assert.equal(down.verdict, VERDICT.DENY);
  assert.match(down.reason, /identity chain is unverified/);
  assert.equal(judge({ ghost: GHOST_UP }).verdict, VERDICT.ALLOW);
  assert.equal(judge({ ghost: { mode: 'on', verifiedOk: false } }).verdict, VERDICT.ALLOW); // advisory mode never closes
});

test('no policy / no legible target / illegible target: all fail closed', () => {
  assert.equal(judge({ policy: null }).verdict, VERDICT.DENY);
  assert.equal(judge({ args: {}, }).verdict, VERDICT.DENY); // target-touching, no target field
  const bad = judge({ args: { url: 'http:///' } }); // scheme, no host at all — truly illegible
  assert.equal(bad.verdict, VERDICT.DENY);
  assert.match(bad.reason, /illegible/);
});

// ── direction B (outbound to external servers) ───────────────────────────────

const ext = (args, over = {}) => judgeCall({ direction: 'external', tool: 'some_community_tool', args, policy: externalPolicy(), scope: SCOPE, externalAllowed: true, ...over });

test('external: mcp.allowExternal=false denies before anything else', () => {
  const r = ext({ url: 'http://127.0.0.1/' }, { externalAllowed: false });
  assert.equal(r.verdict, VERDICT.DENY);
  assert.match(r.reason, /mcp\.allowExternal=false/);
});

test('external: in-scope IP allows; out-of-scope IP denies', () => {
  assert.equal(ext({ url: 'http://127.0.0.1:9000/api' }).verdict, VERDICT.ALLOW);
  assert.equal(ext({ host: '192.168.50.130' }).verdict, VERDICT.ALLOW);
  assert.equal(ext({ url: 'http://172.16.9.9/' }).verdict, VERDICT.DENY);
});

test('external: research-allowlisted public host is governed egress; other public hosts DENY', () => {
  assert.equal(ext({ url: 'https://github.com/some/poc' }).verdict, VERDICT.ALLOW);
  assert.equal(ext({ url: 'https://nvd.nist.gov/vuln/detail/CVE-2025-1' }).verdict, VERDICT.ALLOW);
  const r = ext({ url: 'https://pastebin-equality.example.org/x' });
  assert.equal(r.verdict, VERDICT.DENY);
  assert.match(r.reason, /allowlist/);
});

test('external: NO legible target -> HOLD, never dispatch blind', () => {
  const r = ext({ path: '/etc/passwd' });
  assert.equal(r.verdict, VERDICT.HOLD);
  assert.match(r.reason, /held for the operator/);
});

test('external: ghost-required-down denies network-touching external calls', () => {
  assert.equal(ext({ url: 'http://127.0.0.1/' }, { ghost: GHOST_DOWN }).verdict, VERDICT.DENY);
});

// ── target normalization (the seam's canonical-address doctrine) ─────────────

test('normalizeTargetHost: URLs, host:port, brackets, case, and debris', () => {
  assert.equal(normalizeTargetHost('http://User:pass@Example.COM:8080/p?q=1'), 'example.com');
  assert.equal(normalizeTargetHost('10.0.0.5:9000'), '10.0.0.5');
  assert.equal(normalizeTargetHost('[::1]:8080'), '::1');
  assert.equal(normalizeTargetHost('http://127.0.0.1:8973$p/x'), '127.0.0.1'); // shell debris hugs the port
  assert.equal(normalizeTargetHost('not a host!!'), '');
  assert.equal(normalizeTargetHost(''), '');
  const ts = extractTargets({ url: 'http://192.168.50.130:8080/x', other: 'ignored' }, ['url']);
  assert.deepEqual(ts.map((t) => [t.host, t.ip]), [['192.168.50.130', '192.168.50.130']]);
});

// ── the audit trail ──────────────────────────────────────────────────────────

test('audit entry: sha256 digest + REDACTED preview — secret arg VALUES never land', () => {
  const verdict = judge({ args: { url: 'http://10.9.9.9/' } });
  const e = makeAuditEntry({ direction: 'server', tool: 'varvel_crawl', args: { url: 'http://10.9.9.9/', token: 'TOPSECRET-VALUE' }, verdict, at: '2026-08-18T00:00:00Z' });
  assert.equal(e.kind, 'mcp.call');
  assert.equal(e.direction, 'server');
  assert.match(e.argsDigest, /^sha256:[0-9a-f]{64}$/);
  assert.ok(!JSON.stringify(e).includes('TOPSECRET-VALUE'), 'secret leaked into the audit entry');
  assert.match(e.argsPreview, /REDACTED/);
  assert.equal(e.verdict, 'deny');
  assert.equal(e.targets[0].host, '10.9.9.9');
});

test('redactArgs: nested secrets redacted, depth-capped, long strings capped', () => {
  const r = redactArgs({ a: { password: 'x', nested: [{ api_key: 'y' }] }, s: 'z'.repeat(1000) });
  assert.equal(r.a.password, '[REDACTED]');
  assert.equal(r.a.nested[0].api_key, '[REDACTED]');
  assert.ok(r.s.length < 320);
});

test('fileAuditSink: append-only JSONL under varvel/.tmp (house rule), never throws', () => {
  const f = join(TMP, 'audit-' + process.pid + '.jsonl');
  rmSync(f, { force: true });
  const sink = fileAuditSink(f);
  const v = judge();
  sink(makeAuditEntry({ direction: 'server', tool: 'varvel_crawl', args: { url: 'http://127.0.0.1/' }, verdict: v, at: '2026-08-18T00:00:00Z' }));
  sink(makeAuditEntry({ direction: 'server', tool: 'varvel_webscan', args: { url: 'http://127.0.0.1/', secret: 'HIDDEN' }, verdict: v, at: '2026-08-18T00:00:01Z' }));
  const lines = readFileSync(f, 'utf8').trim().split('\n').map(JSON.parse);
  assert.equal(lines.length, 2);
  assert.equal(sink.lastError, null);
  assert.ok(lines.every((l) => l.kind === 'mcp.call' && /^sha256:/.test(l.argsDigest)));
  assert.ok(!readFileSync(f, 'utf8').includes('HIDDEN'));
  sink(makeAuditEntry({})); // garbage in, still no throw
  assert.ok(f.replace(/\\/g, '/').includes('/.tmp/'), 'ledger must live under varvel/.tmp in tests');
});
