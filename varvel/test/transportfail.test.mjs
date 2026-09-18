// transportfail.test.mjs - gap#5: transport grading ladder, channel transport tagging,
// channel-assigned transport switching. Hermetic (loopback only), same harness style as
// callback.test.mjs / dnstransport.test.mjs.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { CallbackChannel } from '../engine/callback.mjs';
import { gradeAgentTransports } from '../engine/transport-grade.mjs';
import { DnsTransport } from '../agents/dns-client.mjs';

const SCOPE = { engagement: 'test', signedBy: 'test', cidrs: ['127.0.0.0/8'] };
const hmac = (token, msg) => crypto.createHmac('sha256', token).update(msg).digest('hex');

async function armed(extra = {}) {
  const events = [];
  const ch = new CallbackChannel({ scope: SCOPE, onEvent: (t, o) => events.push({ type: t, ...o }), ...extra });
  await ch.arm(0);
  return { ch, port: ch.port, events };
}
// Minimal HTTP pull check-in, same shape as callback.test.mjs.
async function httpCheckin(port, agentId, token, seq) {
  const r = await fetch(`http://127.0.0.1:${port}/c`, {
    headers: { 'x-agent': agentId, 'x-seq': String(seq), 'x-auth': hmac(token, agentId + ':' + seq + ':pull') },
  });
  const buf = Buffer.from(await r.arrayBuffer());
  return { status: r.status, assignedHeader: r.headers.get('x-varvel-transport'), task: buf.length ? JSON.parse(buf.toString()) : null };
}

// ---------- grader (pure logic, no I/O) ----------
test('grader ladder: unknown -> healthy -> suspect -> failed on missed windows', () => {
  const now = 1_000_000_000;
  const E = 5000;
  const da = { transportLastSeen: {}, lastTransport: null };
  let g = gradeAgentTransports(da, { now, expectedMs: E });
  for (const t of ['http', 'dns', 'icmp']) {
    assert.equal(g.perTransport[t].health, 'unknown', t + ': never-seen = unknown (no missed math)');
    assert.equal(g.perTransport[t].lastSeen, null);
  }
  assert.equal(g.current, null);
  assert.notEqual(g.recommendation.action, 'switch', 'nothing observed - no switch possible');

  da.transportLastSeen = { http: now - 1000 };
  g = gradeAgentTransports(da, { now, expectedMs: E });
  assert.equal(g.perTransport.http.health, 'healthy', 'within the window = healthy');
  assert.equal(g.perTransport.http.missedWindows, 0);

  da.transportLastSeen = { http: now - 3 * E };
  g = gradeAgentTransports(da, { now, expectedMs: E });
  assert.equal(g.perTransport.http.health, 'suspect', 'at suspectAfter missed windows = suspect');
  assert.equal(g.perTransport.http.missedWindows, 3);

  da.transportLastSeen = { http: now - 6 * E };
  g = gradeAgentTransports(da, { now, expectedMs: E });
  assert.equal(g.perTransport.http.health, 'failed', 'at failedAfter missed windows = failed');
  assert.equal(g.perTransport.http.missedWindows, 6);
});

test('grader recommendation: stay / watch / switch - and NEVER switch to unknown or failed', () => {
  const now = 1_000_000_000;
  const E = 5000;
  // current healthy -> stay
  let da = { transportLastSeen: { http: now - 100, dns: now - 200 }, lastTransport: 'http' };
  let g = gradeAgentTransports(da, { now, expectedMs: E });
  assert.equal(g.recommendation.action, 'stay');
  assert.equal(g.recommendation.to, undefined);
  // current suspect -> watch (degrading, not dead)
  da = { transportLastSeen: { http: now - 4 * E, dns: now - 200 }, lastTransport: 'http' };
  g = gradeAgentTransports(da, { now, expectedMs: E });
  assert.equal(g.recommendation.action, 'watch');
  assert.match(g.recommendation.reason, /suspect/);
  // current failed -> switch to the most recently seen viable (healthy/suspect) alternative
  da = { transportLastSeen: { http: now - 9 * E, dns: now - 200, icmp: now - 400 }, lastTransport: 'http' };
  g = gradeAgentTransports(da, { now, expectedMs: E });
  assert.equal(g.recommendation.action, 'switch');
  assert.equal(g.recommendation.to, 'dns', 'most recently seen viable alternative wins');
  // current failed, alternatives never observed -> NO switch (never to unknown)
  da = { transportLastSeen: { http: now - 9 * E }, lastTransport: 'http' };
  g = gradeAgentTransports(da, { now, expectedMs: E });
  assert.notEqual(g.recommendation.action, 'switch');
  assert.equal(g.recommendation.to, undefined);
  // current failed, only alternative ALSO failed -> NO switch (never to failed)
  da = { transportLastSeen: { http: now - 9 * E, dns: now - 8 * E }, lastTransport: 'http' };
  g = gradeAgentTransports(da, { now, expectedMs: E });
  assert.notEqual(g.recommendation.action, 'switch');
  // a suspect alternative IS an acceptable switch target
  da = { transportLastSeen: { http: now - 9 * E, dns: now - 4 * E }, lastTransport: 'http' };
  g = gradeAgentTransports(da, { now, expectedMs: E });
  assert.equal(g.recommendation.action, 'switch');
  assert.equal(g.recommendation.to, 'dns');
});

// ---------- channel tagging ----------
test('channel tags observed checkins per transport (http / dns-codec->dns / icmp) + lastTransport', async () => {
  const { ch, port } = await armed();
  try {
    const { agentId, token } = ch.registerAgent({ label: 'tagging' });
    // fresh record: zeroed buckets, nothing assigned
    let view = ch.agentsView()[0];
    assert.deepEqual(view.transportCheckins, { http: 0, dns: 0, icmp: 0 });
    assert.equal(view.lastTransport, null);
    assert.equal(view.assignedTransport, null);
    // http checkin -> http bucket
    const r1 = await httpCheckin(port, agentId, token, 1);
    assert.equal(r1.status, 204);
    view = ch.agentsView()[0];
    assert.equal(view.transportCheckins.http, 1);
    assert.equal(view.transportCheckins.dns, 0);
    assert.equal(view.transportCheckins.icmp, 0);
    assert.equal(view.lastTransport, 'http');
    assert.ok(view.transportLastSeen.http > 0);
    // dns checkin over the /d carrier -> transport param 'dns-codec' normalizes to 'dns'.
    // The DnsTransport client tracks its own seq - continue the agent-global sequence.
    const dns = new DnsTransport({ url: `http://127.0.0.1:${port}`, agentId, token });
    dns.seq = 1;
    assert.equal(await dns.pull(), null); // idle, but an OBSERVED checkin
    dns.close();
    view = ch.agentsView()[0];
    assert.equal(view.transportCheckins.dns, 1);
    assert.equal(view.transportCheckins.http, 1);
    assert.equal(view.lastTransport, 'dns');
    // icmp shares the _dnsPayload intake with transport param 'icmp' (bridge path)
    const s = ch.agents.get(agentId).seq + 1;
    ch._dnsPayload({ a: agentId, s, h: hmac(token, agentId + ':' + s + ':pull') }, '127.0.0.1', 'icmp');
    view = ch.agentsView()[0];
    assert.equal(view.transportCheckins.icmp, 1);
    assert.equal(view.lastTransport, 'icmp');
    // graded at read time: every transport just seen -> healthy (default 5000ms window)
    assert.equal(view.transportGrade.perTransport.http.health, 'healthy');
    assert.equal(view.transportGrade.perTransport.dns.health, 'healthy');
    assert.equal(view.transportGrade.perTransport.icmp.health, 'healthy');
    assert.equal(view.transportGrade.current, 'icmp');
    assert.equal(view.transportGrade.recommendation.action, 'stay');
  } finally { await ch.disarm(); }
});

test('agentsView grades against the agent malleable profile intervalMs when known', async () => {
  const { ch, port } = await armed();
  try {
    const { agentId, token } = ch.registerAgent({});
    ch.setProfile(agentId, 'streaming'); // intervalMs 1200
    await httpCheckin(port, agentId, token, 1);
    // 4000ms after the checkin: 4000/1200 = 3 missed windows -> suspect (default 5000 would be healthy)
    const later = ch.agentsView({ now: Date.now() + 4000 })[0];
    assert.equal(later.transportGrade.perTransport.http.health, 'suspect');
    assert.equal(later.transportGrade.recommendation.action, 'watch');
    const now = ch.agentsView({ now: Date.now() })[0];
    assert.equal(now.transportGrade.perTransport.http.health, 'healthy');
  } finally { await ch.disarm(); }
});

// ---------- channel-assigned transport (soft switch) ----------
test('assignment: header on /c + setTransport key on dns replies; active ONLY after a checkin on the assigned transport', async () => {
  const { ch, port, events } = await armed();
  try {
    const { agentId, token } = ch.registerAgent({ label: 'assign' });
    // validation: unknown agent / bad transport name refused honestly
    assert.equal(ch.setTransport('no-such-agent', 'dns'), null);
    assert.equal(ch.setTransport(agentId, 'carrier-pigeon'), null);
    const asg = ch.setTransport(agentId, 'dns');
    assert.equal(asg.transport, 'dns');
    assert.equal(asg.state, 'assigned');
    assert.ok(events.some((e) => e.type === 'agent.transport' && e.transport === 'dns'));
    // the next /c reply carries x-varvel-transport (mirrors the x-varvel-profile pattern)...
    const r1 = await httpCheckin(port, agentId, token, 1);
    assert.equal(r1.assignedHeader, 'dns');
    // ...but a checkin on the OLD transport must NOT flip the state - never before the wire proves it
    assert.equal(ch.agentsView()[0].assignedTransport.state, 'assigned');
    // dns task replies carry the setTransport key (queue a task so the reply is non-empty)
    const taskId = ch.task(agentId, 'note', 'hello');
    const dns = new DnsTransport({ url: `http://127.0.0.1:${port}`, agentId, token });
    dns.seq = 1; // continue the agent-global sequence (seq 1 used by the http checkin)
    const task = await dns.pull();
    dns.close();
    assert.equal(task.taskId, taskId);
    assert.equal(task.setTransport, 'dns');
    // the observed dns checkin flips assigned -> active (and only that could)
    const view = ch.agentsView()[0];
    assert.equal(view.assignedTransport.transport, 'dns');
    assert.equal(view.assignedTransport.state, 'active');
    assert.ok(events.some((e) => e.type === 'agent.transport-active' && e.transport === 'dns'));
    assert.equal(view.lastTransport, 'dns');
  } finally { await ch.disarm(); }
});

// Teardown grace: on win32, --test-force-exit can fire while sockets are still closing
// (libuv UV_HANDLE_CLOSING assert). Same guard as dnstransport/callback-v2.
test('teardown grace for socket drain (win32 libuv assert guard)', async () => {
  await new Promise((r) => setTimeout(r, 600));
});
