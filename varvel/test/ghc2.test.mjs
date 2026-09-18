// ghc2.test.mjs — the cloud/SaaS dead-drop C2 transport ('ghc', GitHub gist-comment
// mailbox). HERMETIC: a mock GitHub REST API on loopback (Ghc2Api's apiBase is the
// injectable seam), the REAL callback channel intake (_dnsPayload) doing governance,
// the REAL agent-side Ghc2Transport on the other leg. No live GitHub contact anywhere.
//
// Proves: envelope round-trip through the real intake · cursor advance (no
// double-delivery) · chunk reassembly · kill-list enforcement riding the channel ·
// ghost-chain threading (injected agent + the fail-closed resolver) · rate-limit
// honesty (headers surfaced, 401 arm refusal) · the token NEVER in audit events
// (negative assertion scan) · default-OFF refusal.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import crypto from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { CallbackChannel } from '../engine/callback.mjs';
import { Ghc2Api, GHC2_RATE, wrapEnvelope, unwrapEnvelope, upsFromComments, downsFromComments, tokenMeta, pullPayload } from '../engine/ghc2.mjs';
import { Ghc2Transport } from '../agents/ghc2-client.mjs';
import { armGhc, resolveGhcTransport } from '../tools/ghc2.mjs';
import { Settings, SETTINGS_SCHEMA } from '../engine/settings.mjs';

const SCOPE = { engagement: 'test', signedBy: 'test', cidrs: ['127.0.0.0/8'] };
const PAT = 'github_pat_BURNER_TEST_TOKEN_0123456789abcdef'; // a burner's shape — a FIXTURE, never a real token
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const hmac = (key, m) => crypto.createHmac('sha256', key).update(m).digest('hex');

// --- the mock GitHub REST API: monotonic comment ids, Bearer auth, rate headers on
// every response, /rate_limit free (GitHub: it is NOT charged against the core budget).
function mockGitHub({ token = PAT, remaining = 4999 } = {}) {
  const comments = [];
  let nextId = 1;
  const hits = { rateLimit: 0, list: 0, create: 0, authed: 0 };
  const server = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    const rateHeaders = {
      'x-ratelimit-limit': '5000', 'x-ratelimit-remaining': String(remaining),
      'x-ratelimit-used': '1', 'x-ratelimit-reset': String(Math.floor(Date.now() / 1000) + 1800),
    };
    const send = (code, obj) => {
      const b = Buffer.from(JSON.stringify(obj), 'utf8');
      res.writeHead(code, { 'content-type': 'application/json', ...rateHeaders });
      res.end(b);
    };
    const authed = req.headers.authorization === 'Bearer ' + token;
    if (authed) hits.authed++;
    if (u.pathname === '/rate_limit') {
      hits.rateLimit++;
      if (!authed) return send(401, { message: 'Bad credentials' });
      return send(200, { resources: { core: { limit: 5000, remaining, reset: Math.floor(Date.now() / 1000) + 1800 } } });
    }
    const m = /^\/gists\/([^/]+)\/comments$/.exec(u.pathname);
    if (m) {
      if (!authed) return send(401, { message: 'Bad credentials' });
      if (req.method === 'GET') { hits.list++; return send(200, comments); }
      if (req.method === 'POST') {
        hits.create++;
        let raw = '';
        req.on('data', (d) => { raw += d; });
        req.on('end', () => {
          let b = null;
          try { b = JSON.parse(raw).body; } catch { /* falls to the 400 below */ }
          if (typeof b !== 'string') return send(400, { message: 'Invalid body' });
          const c = { id: nextId++, body: b, user: { login: 'burner-op' } };
          comments.push(c);
          send(201, c);
        });
        return;
      }
    }
    send(404, { message: 'Not Found' });
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      resolve({
        server, port, comments, hits,
        apiBase: 'http://127.0.0.1:' + port,
        api: () => new Ghc2Api({ token, gistId: 'deadbeefgist', apiBase: 'http://127.0.0.1:' + port }),
        close: () => new Promise((r) => server.close(r)),
      });
    });
  });
}

function makeChannel(extra = {}) {
  const events = [];
  const ch = new CallbackChannel({ scope: SCOPE, onEvent: (t, o) => events.push({ type: t, ...o }), ...extra });
  return { ch, events };
}

// Settings stub: real schema defaults, per-test overrides (never the persisted store).
const stubSettings = (vals = {}) => ({ get: (k) => (k in vals ? vals[k] : SETTINGS_SCHEMA[k].default) });

test('envelope codec: wrap/unwrap round-trip; malformed is null; the 65536 cap throws', () => {
  const body = wrapEnvelope({ v: 1, d: 'up', p: { a: 'x', s: 1, h: 'abc' } });
  assert.match(body, /<!-- ghc1:[A-Za-z0-9_-]+ -->/);
  assert.ok(!body.includes('"v"'), 'the envelope rides base64url inside an HTML comment, not plaintext JSON');
  const env = unwrapEnvelope(body);
  assert.equal(env.d, 'up');
  assert.deepEqual(env.p, { a: 'x', s: 1, h: 'abc' });
  // malformed shapes are simply not envelopes (fail-closed)
  assert.equal(unwrapEnvelope('just a human comment'), null);
  assert.equal(unwrapEnvelope('<!-- ghc1:!!!notb64!!! -->'), null);
  assert.equal(unwrapEnvelope('<!-- ghc1:' + Buffer.from('{"v":2}').toString('base64url') + ' -->'), null);
  // GitHub's hard comment-body cap is enforced BEFORE posting
  assert.throws(() => wrapEnvelope({ v: 1, d: 'up', p: { big: 'x'.repeat(90000) } }), /65536/);
});

test('cursor bookkeeping: human/foreign comments advance the cursor, never double-deliver', () => {
  const mk = (id, env) => ({ id, body: env ? wrapEnvelope(env) : 'totally ordinary developer chatter' });
  const page = [
    mk(1, null),
    mk(2, { v: 1, d: 'up', p: pullPayload({ agentId: 'a1', token: 'tok', seq: 1 }) }),
    mk(3, null),
  ];
  const first = upsFromComments(page, 0);
  assert.equal(first.ups.length, 1);
  assert.equal(first.ups[0].id, 2);
  assert.equal(first.cursor, 3, 'the cursor ran to the newest comment id, envelopes or not');
  const again = upsFromComments(page, first.cursor);
  assert.equal(again.ups.length, 0, 'nothing re-delivers');
  assert.equal(again.cursor, 3);
});

test('down envelopes: a forged signature is skipped, counted, and the cursor passes it', () => {
  const good = wrapEnvelope({ v: 1, d: 'down', a: 'me', p: 'QQ', t: hmac('tok', 'ghc-down:me:QQ') });
  const bad = wrapEnvelope({ v: 1, d: 'down', a: 'me', p: 'QQ', t: hmac('WRONG', 'ghc-down:me:QQ') });
  const other = wrapEnvelope({ v: 1, d: 'down', a: 'someone-else', p: 'QQ', t: hmac('tok', 'ghc-down:someone-else:QQ') });
  const r = downsFromComments([{ id: 1, body: bad }, { id: 2, body: other }, { id: 3, body: good }], 0, { agentId: 'me', token: 'tok' });
  assert.equal(r.replies.length, 1);
  assert.equal(r.replies[0].id, 3);
  assert.equal(r.forged, 1, 'the forgery attempt is honestly counted');
  assert.equal(r.cursor, 3);
});

test('tokenMeta: presence + class only, the value never appears', () => {
  assert.deepEqual(tokenMeta(''), { present: false, class: 'absent' });
  assert.deepEqual(tokenMeta(PAT), { present: true, class: 'fine-grained-pat' });
  assert.deepEqual(tokenMeta('ghp_classic'), { present: true, class: 'classic-pat' });
  assert.ok(!JSON.stringify(tokenMeta(PAT)).includes(PAT));
});

test('full round-trip through the REAL intake: task down, result up, audited with bytes', async () => {
  const gh = await mockGitHub();
  const { ch, events } = makeChannel();
  try {
    ch.attachGhc({ client: gh.api(), intervalSec: 0 }); // 0 = manual: the test drives cadence
    const { agentId, token } = ch.registerAgent({ label: 'ghc-agent' });
    const taskId = ch.task(agentId, 'note', 'hello-ghc');
    const agent = new Ghc2Transport({ api: gh.api(), agentId, token, replyWaitMs: 8000, replyPollMs: 40 });

    const pullP = agent.pull();
    await sleep(120); // let the up-comment land in the mailbox
    const poll = await ch.ghcPollNow();
    assert.equal(poll.ok, true);
    assert.equal(poll.delivered, 1);
    const task = await pullP;
    assert.equal(task.taskId, taskId);
    assert.equal(task.kind, 'note');
    assert.equal(task.data, 'hello-ghc');

    // result push: one comment, reassembled by the shared intake
    assert.equal(await agent.push(taskId, 'result-body-ghc'), true);
    await ch.ghcPollNow();
    const res = ch.results(agentId);
    assert.equal(res.length, 1);
    assert.equal(res[0].taskId, taskId);
    assert.equal(res[0].data, 'result-body-ghc');

    // governance events rode the channel, tagged on the ghc bucket, byte-counted
    assert.ok(events.some((e) => e.type === 'agent.checkin' && e.transport === 'ghc' && e.agentId === agentId));
    assert.ok(events.some((e) => e.type === 'task.delivered' && e.transport === 'ghc' && e.taskId === taskId));
    assert.ok(events.some((e) => e.type === 'task.resulted' && e.transport === 'ghc' && e.taskId === taskId));
    const up = events.find((e) => e.type === 'ghc.up');
    assert.ok(up && up.bytes > 0 && up.commentId > 0);
    const down = events.find((e) => e.type === 'ghc.down');
    assert.ok(down && down.bytes > 0 && down.commentId > 0);
    const pollEv = events.find((e) => e.type === 'ghc.poll');
    assert.equal(pollEv.rateRemaining, 4999, 'rate-limit headers surface in the audit stream');
    assert.equal(ch.agentsView()[0].transportCheckins.ghc >= 1, true);
  } finally { ch.detachGhc(); await gh.close(); }
});

test('cursor advance: a second channel poll re-delivers NOTHING', async () => {
  const gh = await mockGitHub();
  const { ch, events } = makeChannel();
  try {
    ch.attachGhc({ client: gh.api(), intervalSec: 0 });
    const { agentId, token } = ch.registerAgent({});
    const agent = new Ghc2Transport({ api: gh.api(), agentId, token, replyWaitMs: 500, replyPollMs: 40 });
    const pullP = agent.pull(); // idle: no task queued
    await sleep(120);
    await ch.ghcPollNow();
    await pullP;
    const checkins = events.filter((e) => e.type === 'agent.checkin').length;
    const cursor = ch.ghcStatus().cursor;
    const second = await ch.ghcPollNow();
    assert.equal(second.ok, true);
    assert.equal(second.ups, 0, 'the cursor filtered the re-read page');
    assert.equal(events.filter((e) => e.type === 'agent.checkin').length, checkins, 'no double check-in');
    assert.equal(ch.ghcStatus().cursor, cursor, 'cursor stable on an empty drain');
  } finally { ch.detachGhc(); await gh.close(); }
});

test('chunk reassembly: a >8KB result rides 3 chunk-comments and lands whole', async () => {
  const gh = await mockGitHub();
  const { ch, events } = makeChannel();
  try {
    ch.attachGhc({ client: gh.api(), intervalSec: 0 });
    const { agentId, token } = ch.registerAgent({});
    const taskId = ch.task(agentId, 'shell', 'type big.txt');
    // deliver the task first so the ledger has it (pushes bind to the ledger entry)
    const agent = new Ghc2Transport({ api: gh.api(), agentId, token, replyWaitMs: 8000, replyPollMs: 40 });
    const pullP = agent.pull();
    await sleep(120);
    await ch.ghcPollNow();
    await pullP;

    const body = 'A'.repeat(GHC2_RATE.chunkBytes * 2 + 500); // 3 chunks at the 4092 default
    assert.equal(await agent.push(taskId, body), true);
    await ch.ghcPollNow();
    const res = ch.results(agentId);
    assert.equal(res.length, 1);
    assert.equal(res[0].data, body);
    const pushes = events.filter((e) => e.type === 'agent.push' && e.transport === 'ghc');
    assert.equal(pushes.length, 3, 'three per-chunk events, one per comment');
    assert.equal(events.filter((e) => e.type === 'task.resulted').length, 1);
  } finally { ch.detachGhc(); await gh.close(); }
});

test('kill-list enforcement rides the channel: a killed agent is denied at the intake', async () => {
  const gh = await mockGitHub();
  const { ch, events } = makeChannel();
  try {
    ch.attachGhc({ client: gh.api(), intervalSec: 0 });
    const { agentId, token } = ch.registerAgent({});
    ch.kill(agentId);
    const agent = new Ghc2Transport({ api: gh.api(), agentId, token, replyWaitMs: 1200, replyPollMs: 40 });
    const pullP = agent.pull();
    await sleep(120);
    await ch.ghcPollNow();
    const task = await pullP;
    assert.equal(task, null, 'killed ≡ idle to the agent (the 204-uniform doctrine, dead-drop-shaped)');
    assert.ok(events.some((e) => e.type === 'checkin.rejected'), 'the denial is loud in the ledger');
    assert.ok(!events.some((e) => e.type === 'ghc.down'), 'no down-comment is ever posted for a killed agent');
    assert.ok(!events.some((e) => e.type === 'agent.checkin'));
  } finally { ch.detachGhc(); await gh.close(); }
});

test('ghost threading: the api client rides an injected agent; the resolver fails closed', async () => {
  const gh = await mockGitHub();
  try {
    // injected-agent proof: every request leaves through the supplied http.Agent
    class CountingAgent extends http.Agent {
      constructor() { super(); this.connections = 0; }
      createConnection(...args) { this.connections++; return super.createConnection(...args); }
    }
    const counting = new CountingAgent();
    const api = new Ghc2Api({ token: PAT, gistId: 'deadbeefgist', apiBase: gh.apiBase, agents: { httpAgent: counting, httpsAgent: counting } });
    const rl = await api.rateLimit();
    assert.equal(rl.ok, true);
    assert.ok(counting.connections > 0, 'the request rode the injected (ghost-chain) agent');
    counting.destroy();

    // the resolver's decision table
    const pub = 'https://api.github.com';
    const ghostReqBad = { mode: 'required', chain: [{ scheme: 'socks5', host: '10.0.0.9', port: 1080 }], verifiedOk: () => false, verify: async () => {} };
    const refused = await resolveGhcTransport({ ghost: ghostReqBad, apiBase: pub });
    assert.equal(refused.ok, false, 'required + unverified + public SaaS = fail-closed refusal');
    assert.match(refused.reason, /REQUIRED/);
    const lab = await resolveGhcTransport({ ghost: ghostReqBad, apiBase: gh.apiBase });
    assert.equal(lab.ok, true, 'loopback api base is direct even under required (lab doctrine)');
    assert.equal(lab.direct, true);
    const agents = { httpAgent: 'A', httpsAgent: 'B' };
    const ghostReqGood = { mode: 'required', chain: [{ scheme: 'socks5', host: '10.0.0.9', port: 1080 }], verifiedOk: () => true, agents: () => agents };
    const ridden = await resolveGhcTransport({ ghost: ghostReqGood, apiBase: pub });
    assert.equal(ridden.ok, true);
    assert.equal(ridden.direct, false);
    assert.equal(ridden.agents, agents, 'the ghost chain agents thread to the mailbox leg');
    const off = await resolveGhcTransport({ ghost: { mode: 'off', chain: [] }, apiBase: pub });
    assert.equal(off.ok, true);
    assert.equal(off.direct, true);
    const reqNoChain = await resolveGhcTransport({ ghost: { mode: 'required', chain: [] }, apiBase: pub });
    assert.equal(reqNoChain.ok, false, 'required + NO chain = refused, never a silent direct arm');
  } finally { await gh.close(); }
});

test('rate-limit honesty: budget surfaces on arm; a dead token refuses the arm loudly', async () => {
  const gh = await mockGitHub({ remaining: 4817 });
  const { ch } = makeChannel();
  try {
    const api = gh.api();
    const rl = await api.rateLimit();
    assert.equal(rl.ok, true);
    assert.equal(rl.core.limit, 5000);
    assert.equal(rl.core.remaining, 4817);
    assert.ok(rl.core.secondsToReset > 0);
    assert.deepEqual(rl.token, { present: true, class: 'fine-grained-pat' });

    const badApi = new Ghc2Api({ token: 'github_pat_DEAD', gistId: 'deadbeefgist', apiBase: gh.apiBase });
    const badRl = await badApi.rateLimit();
    assert.equal(badRl.ok, false);
    assert.equal(badRl.status, 401);
    assert.match(badRl.error, /burner PAT/);

    const armed = await armGhc({
      engagement: 't', channel: ch,
      settings: stubSettings({ 'ghc2.enabled': true, 'ghc2.token': PAT, 'ghc2.repo': 'deadbeefgist' }),
      client: api,
    });
    assert.equal(armed.ok, true);
    assert.equal(armed.budget.remaining, 4817);
    assert.equal(armed.intervalSec, 60, 'the SLOW default cadence holds');
    assert.equal(ch.ghcStatus().configured, true);

    const refused = await armGhc({
      engagement: 't', channel: ch,
      settings: stubSettings({ 'ghc2.enabled': true, 'ghc2.token': 'github_pat_DEAD', 'ghc2.repo': 'deadbeefgist' }),
      client: badApi,
    });
    assert.equal(refused.ok, false);
    assert.match(refused.reason, /401/);
  } finally { ch.detachGhc(); await gh.close(); }
});

test('default-OFF refusal: no ghc2.enabled, no arm — the refusal names the opt-in', async () => {
  const { ch } = makeChannel();
  const r = await armGhc({ engagement: 't', channel: ch, settings: stubSettings({}) });
  assert.equal(r.ok, false);
  assert.match(r.reason, /ghc2\.enabled/);
  assert.equal(ch.ghcStatus().configured, false);
  // enabled but no burner token: refused with the doctrine in the message
  const noTok = await armGhc({ engagement: 't', channel: ch, settings: stubSettings({ 'ghc2.enabled': true }) });
  assert.equal(noTok.ok, false);
  assert.match(noTok.reason, /BURNER/);
  // enabled + token but no dead-drop gist: refused
  const noGist = await armGhc({ engagement: 't', channel: ch, settings: stubSettings({ 'ghc2.enabled': true, 'ghc2.token': PAT }) });
  assert.equal(noGist.ok, false);
  assert.match(noGist.reason, /ghc2\.repo/);
});

test('the token NEVER reaches the audit stream (negative assertion over every event)', async () => {
  const gh = await mockGitHub();
  const { ch, events } = makeChannel();
  try {
    ch.attachGhc({ client: gh.api(), intervalSec: 0 });
    const { agentId, token } = ch.registerAgent({});
    const taskId = ch.task(agentId, 'note', 'audit-scan');
    const agent = new Ghc2Transport({ api: gh.api(), agentId, token, replyWaitMs: 8000, replyPollMs: 40 });
    const pullP = agent.pull();
    await sleep(120);
    await ch.ghcPollNow();
    await pullP;
    await agent.push(taskId, 'scan-me');
    await ch.ghcPollNow();
    const armed = await armGhc({
      engagement: 't', channel: ch,
      settings: stubSettings({ 'ghc2.enabled': true, 'ghc2.token': PAT, 'ghc2.repo': 'deadbeefgist' }),
      client: gh.api(),
    });
    const everything = JSON.stringify(events) + JSON.stringify(armed) + JSON.stringify(ch.ghcStatus());
    assert.ok(!everything.includes(PAT), 'the burner PAT appears in NO event, report, or status view');
    // and the mock PROVES the token really did ride the wire (auth-gated endpoints answered)
    assert.ok(gh.hits.authed > 0, 'requests were Bearer-authenticated — the token went to the API, not the ledger');
  } finally { ch.detachGhc(); await gh.close(); }
});

test('secret-class settings: the real Settings.toJSON redacts ghc2.token to presence only', () => {
  process.env.VARVEL_SETTINGS_FILE = join(mkdtempSync(join(tmpdir(), 'vghc-')), 's.json');
  assert.equal(SETTINGS_SCHEMA['ghc2.token'].secret, true);
  assert.equal(SETTINGS_SCHEMA['ghc2.enabled'].default, false, 'default OFF — the engagement must opt in');
  assert.equal(SETTINGS_SCHEMA['ghc2.intervalSec'].default, 60);
  assert.equal(SETTINGS_SCHEMA['ghc2.intervalSec'].min, GHC2_RATE.minIntervalSec);
  const eng = 'eng-ghc-' + Date.now();
  const s = Settings.for(eng);
  s.set('ghc2.token', PAT);
  assert.equal(s.get('ghc2.token'), PAT, 'the raw value stays retrievable for the arm path');
  const j = s.toJSON();
  assert.equal(j.values['ghc2.token'], '<redacted:set>', 'the API/console view renders presence only');
  assert.ok(!JSON.stringify(j).includes(PAT), 'the token value is in NO serialization of the settings view');
});
