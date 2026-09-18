// postex.test.mjs — hermetic tests for engine/postex.mjs (mock channel, scripted agents).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { POSTEX_TASKS, postexRun, postexCatalog } from '../engine/postex.mjs';

const sysdiscOutput = [
  'RANGE-PC', 'range\\operator', '',
  'Mandatory Label\\High Mandatory Level  Alias   S-1-16-12288',
  'Everyone  Well-known group  S-1-1-0', '',
  'IPv4 Address. . . . . . . . . . . : 192.168.50.130', '',
  'IPv6 Address. . . . . . . . . . . : fd00::130', '',
  'Link-local IPv6 Address . . . . . : fe80::9%11', '',
  'Administrators', '---------------', 'Administrator', 'operator', 'The command completed successfully.',
].join('\r\n');

function mockCtx(over = {}) {
  const calls = [];
  return {
    calls,
    authorized: true,
    scopeCheck: (h) => h === '192.168.50.130',
    taskAgent: async (agentId, task) => { calls.push({ agentId, task }); return over.responder ? over.responder(task) : (over.raw ?? ''); },
    log: () => {},
    ...over.ctx,
  };
}

test('refuses without operator approval (HITL gate in code)', async () => {
  const ctx = mockCtx(); ctx.authorized = false;
  const r = await postexRun('sysdisc', { agentId: 'a1', host: '192.168.50.130' }, ctx);
  assert.equal(r.refused, true);
  assert.match(r.reason, /operator approval/);
  assert.equal(ctx.calls.length, 0, 'nothing tasked before the gate');
});

test('refuses out-of-scope hosts before building the task', async () => {
  const ctx = mockCtx();
  const r = await postexRun('sysdisc', { agentId: 'a1', host: '10.9.9.9' }, ctx);
  assert.equal(r.refused, true);
  assert.match(r.reason, /outside the signed engagement scope/);
  assert.equal(ctx.calls.length, 0);
});

test('unknown task is an honest refusal, not a throw', async () => {
  const r = await postexRun('mimikatz', { agentId: 'a1', host: '192.168.50.130' }, mockCtx());
  assert.equal(r.refused, true);
  assert.match(r.reason, /unknown post-ex task/);
});

test('sysdisc parses raw Windows output into structured intel', async () => {
  const ctx = mockCtx({ raw: sysdiscOutput });
  const r = await postexRun('sysdisc', { agentId: 'a1', host: '192.168.50.130' }, ctx);
  assert.equal(r.ok, true);
  assert.equal(r.sim, false);
  assert.equal(r.intel.hostname, 'RANGE-PC');
  assert.deepEqual(r.intel.ips, ['192.168.50.130', 'fd00::130', 'fe80::9%11']);
  assert.equal(r.intel.isElevated, true);
  assert.equal(ctx.calls.length, 1, 'read-only task: exactly one call, no cleanup');
});

test('cred-sim round-trips the decoy and verifies cleanup', async () => {
  const ctx = mockCtx({
    responder: (task) => /Set-Content/.test(task.command)
      ? 'VARVEL SIMULATED CREDENTIAL - DECOY ONLY - rangeId=t7'
      : 'CLEANUP-VERIFIED',
  });
  const r = await postexRun('cred-sim', { agentId: 'a1', host: '192.168.50.130', params: { runId: 't7' } }, ctx);
  assert.equal(r.ok, true);
  assert.equal(r.sim, true);
  assert.equal(r.intel.decoyRecovered, true);
  assert.equal(r.cleanup.executed, true);
  assert.equal(r.cleanup.verified, true);
  assert.equal(ctx.calls.length, 2, 'collect + cleanup');
  assert.match(ctx.calls[1].task.command, /Remove-Item/, 'second call is the teardown');
});

test('persist-sim creates the marked task then MANDATES teardown', async () => {
  const seen = [];
  const ctx = mockCtx({
    responder: (task) => {
      seen.push(task.command);
      if (/schtasks \/create/.test(task.command)) return 'SUCCESS\nVARVELSIM-t9';
      return 'SUCCESS\nERROR: The system cannot find the file specified.';
    },
  });
  const r = await postexRun('persist-sim', { agentId: 'a1', host: '192.168.50.130', params: { runId: 't9' } }, ctx);
  assert.equal(r.ok, true);
  assert.match(r.verification.note, /SOC should see/);
  assert.equal(r.cleanup.verified, true);
  assert.match(seen[1], /schtasks \/delete/, 'teardown always follows evidence capture');
});

test('failed cleanup fails the run loudly', async () => {
  const ctx = mockCtx({
    responder: (task) => /schtasks \/create/.test(task.command) ? 'VARVELSIM-t9' : 'ACCESS DENIED',
  });
  const r = await postexRun('persist-sim', { agentId: 'a1', host: '192.168.50.130', params: { runId: 't9' } }, ctx);
  assert.equal(r.ok, false);
  assert.match(r.error, /CLEANUP NOT VERIFIED/);
});

test('cleanup waive requires the explicit second flag and warns', async () => {
  const ctx = mockCtx({
    responder: () => 'VARVELSIM-t9',
    ctx: { waiveCleanup: true },
  });
  const r = await postexRun('persist-sim', { agentId: 'a1', host: '192.168.50.130', params: { runId: 't9' } }, ctx);
  assert.equal(r.cleanup.waived, true);
  assert.match(r.cleanup.warning, /operator decision/);
});

test('token-sim maps privilege surface and flags impersonation-relevant privs', async () => {
  const ctx = mockCtx({
    raw: 'SeDebugPrivilege\nSeImpersonatePrivilege\nMandatory Label\\High Mandatory Level  S-1-16-12288',
  });
  const r = await postexRun('token-sim', { agentId: 'a1', host: '192.168.50.130' }, ctx);
  assert.equal(r.ok, true);
  assert.deepEqual(r.intel.dangerousHeld.sort(), ['SeDebugPrivilege', 'SeImpersonatePrivilege'].sort());
  assert.match(r.verification.note, /SIM/);
});

test('lateral-relay validates agent ids and records the plan', async () => {
  assert.throws(() => POSTEX_TASKS['lateral-relay'].build({}), /relayAgentId/);
  const ctx = mockCtx({ raw: 'RELAY-PLAN: tasks for agent b2 routed via agent a1' });
  const r = await postexRun('lateral-relay', { agentId: 'a1', host: '192.168.50.130', params: { relayAgentId: 'b2', viaAgentId: 'a1' } }, ctx);
  assert.equal(r.ok, true);
  assert.equal(ctx.calls[0].task.kind, 'note');
});

test('catalog is honest about what changes the target', () => {
  const cat = postexCatalog();
  assert.equal(cat.find((t) => t.id === 'persist-sim').changesTarget, true);
  assert.equal(cat.find((t) => t.id === 'sysdisc').changesTarget, false);
  assert.ok(cat.every((t) => t.mitre && t.summary));
});
