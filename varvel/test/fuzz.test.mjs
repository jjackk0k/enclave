// VARVEL fuzz + settings tests.
//   node --test varvel/test/fuzz.test.mjs varvel/test/settings.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fuzz, FUZZ_VALUES } from '../tools/fuzz.mjs';
import { Settings, SETTINGS_SCHEMA } from '../engine/settings.mjs';
import { Campaign } from '../engine/campaign.mjs';
import { mockAgent } from '../mock-agent.mjs';

// SETTINGS ISOLATION (the house rule, same as settings/adroast tests): this
// suite's Settings.set(...) calls WRITE-THROUGH to disk (engine/settings.mjs
// saveAll) — point them at .tmp, NEVER the operator's real data/settings.json.
// (Leaked writes from THIS file persisted test engagement keys into the real
// settings store — the door is closed by this line.)
const __dir = dirname(fileURLToPath(import.meta.url));
mkdirSync(join(__dir, '..', '.tmp'), { recursive: true });
process.env.VARVEL_SETTINGS_FILE = join(__dir, '..', '.tmp', 'fuzz-test-settings.json');

const quiet = (srv) => { srv.on('clientError', (e, s) => { try { s.destroy(); } catch {} }); return srv; };

// ——— fuzz ———

test('fuzz: crash-class + error text produce firm findings; a safe endpoint stays silent', async () => {
  const srv = quiet(http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    const id = u.searchParams.get('id') || '';
    if (id.includes('%x')) { res.writeHead(200); return res.end('error: format string exception at 0xdeadbeef'); }
    if (id === '99999999999999999999') { res.writeHead(500); return res.end('overflow'); }
    res.writeHead(200); res.end('item page for id=' + id.slice(0, 10));
  }));
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  try {
    const res = await fuzz(base + '/item?id={FUZZ}', { timeout: 700 });
    const crash = res.findings.find((f) => f.id === 'int-over');
    assert.ok(crash && crash.kind === 'crash-class' && crash.sev === 'medium', 'overflow crash detected');
    const fmt = res.findings.find((f) => f.id === 'fmt-x');
    assert.ok(fmt && fmt.kind === 'crash-class', 'format-string leak detected');
    assert.ok(!res.findings.some((f) => f.id === 'int-zero'), 'ordinary values stay silent');
  } finally { srv.close(); }
});

test('fuzz: safe endpoint → zero findings; placeholder required', async () => {
  const srv = quiet(http.createServer((req, res) => { res.writeHead(200); res.end('ok'); }));
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  try {
    const res = await fuzz(base + '/x?v={FUZZ}', { timeout: 700 });
    assert.equal(res.findings.length, 0, 'honest negative');
    assert.ok(res.requests >= 4, 'baseline + control + probes happened');
  } finally { srv.close(); }
  await assert.rejects(() => fuzz('http://x/no-placeholder', { timeout: 300 }), TypeError);
});

test('fuzz: WAF-blocked payload classes are reported as defender intel, not vulnerabilities', async () => {
  const srv = quiet(http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    if ((u.searchParams.get('v') || '').includes('..')) { res.writeHead(403); return res.end('blocked'); }
    res.writeHead(200); res.end('ok');
  }));
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  try {
    const res = await fuzz(base + '/x?v={FUZZ}', { timeout: 700 });
    const waf = res.findings.find((f) => f.kind === 'waf-block');
    assert.ok(waf, 'WAF-block recorded');
    assert.equal(waf.sev, 'info');
    assert.ok(/WAF-blocked/.test(waf.evidence));
  } finally { srv.close(); }
});

test('fuzz: agents opt — every probe rides the injected agent (ghost plumbing)', async () => {
  const srv = quiet(http.createServer((req, res) => { res.writeHead(200); res.end('ok'); }));
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  try {
    let dialed = 0;
    class RecAgent extends http.Agent {
      createConnection(opts, cb) { dialed++; cb(null, net.connect({ host: opts.host, port: opts.port })); }
    }
    const res = await fuzz(base + '/x?v={FUZZ}', { timeout: 700, agents: { httpAgent: new RecAgent(), httpsAgent: null } });
    assert.ok(res.requests >= 4, 'probes happened');
    assert.equal(dialed, res.requests, 'EVERY request went through the injected agent');
  } finally { srv.close(); }
});

// ——— settings ———

test('settings: schema validation — types, ranges, enums, unknown keys', () => {
  const s = new Settings('T');
  assert.equal(s.get('recon.maxPages'), 25, 'default');
  assert.equal(s.set('recon.maxPages', 50), 50);
  assert.equal(s.get('recon.maxPages'), 50);
  assert.equal(s.set('stealth.autoThrottle', 'false'), false, 'bool coercion');
  assert.equal(s.set('stealth.profile', 'paranoid'), 'paranoid');
  assert.throws(() => s.set('recon.maxPages', 0), RangeError);
  assert.throws(() => s.set('recon.maxPages', 5000), RangeError);
  assert.throws(() => s.set('stealth.profile', 'sneaky'), TypeError);
  assert.throws(() => s.set('made.up.key', 1), TypeError);
  assert.throws(() => s.get('made.up.key'), TypeError);
  assert.ok(SETTINGS_SCHEMA['stealth.profile'].values.includes('auto'));
});

test('settings: per-engagement registry isolates overrides; toJSON is complete', () => {
  const a = Settings.for('ENG-A-1');
  const b = Settings.for('ENG-B-1');
  a.set('agent.maxTurns', 12);
  assert.equal(Settings.for('ENG-A-1').get('agent.maxTurns'), 12);
  assert.equal(b.get('agent.maxTurns'), 40, 'other engagements keep the default');
  const j = a.toJSON();
  assert.equal(j.engagement, 'ENG-A-1');
  assert.ok(j.overrides.includes('agent.maxTurns'));
  assert.ok(Object.keys(j.values).length === Object.keys(SETTINGS_SCHEMA).length);
});

test('settings: campaign consumes them as DEFAULTS, explicit reconOpts still win', () => {
  Settings.for('ENG-C-1').set('recon.maxPages', 7);
  Settings.for('ENG-C-1').set('stealth.autoThrottle', false);
  const c1 = new Campaign({ engine: {}, scope: { engagement: 'ENG-C-1', signedBy: 'x', cidrs: ['127.0.0.0/8'] }, runAgent: mockAgent });
  assert.equal(c1.reconOpts.crawl.maxPages, 7, 'settings floor applied');
  assert.equal(c1.watchdog.autoThrottle, false, 'watchdog honors the setting');
  const c2 = new Campaign({ engine: {}, scope: { engagement: 'ENG-C-1', signedBy: 'x', cidrs: ['127.0.0.0/8'] }, runAgent: mockAgent, reconOpts: { crawl: { maxPages: 99 }, watchdog: { autoThrottle: true } } });
  assert.equal(c2.reconOpts.crawl.maxPages, 99, 'explicit option beats the settings floor');
  assert.equal(c2.watchdog.autoThrottle, true, 'explicit watchdog option wins');
});
