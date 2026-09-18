// VARVEL h1watch API tests — GET /api/h1watch (server.mjs) over the REAL server on a
// dedicated loopback test port (house pattern: statestore/flowscore/agentsig/selfview
// boot server.mjs the same way). Proves: the wire carries the persisted state.json
// summary (latest scan time + the event ring ranked by h1watch's OWN report() order),
// ?all=1 widens to the whole ring, the doctrine line rides verbatim — and the H1
// credential (VARVEL_H1_TOKEN) is NEVER reflected, even when set in the server env.
// Hermetic: the watcher state is an isolated fixture dir; the route reads no network.
//   node --test test/h1watch-api.test.mjs

import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';

const __dir = dirname(fileURLToPath(import.meta.url));
const DATA = mkdtempSync(join(tmpdir(), 'varvel-h1api-'));

// A crafted watcher state: five event classes across the documented ranks, all pinned
// to the scan timestamp (the default report filter), plus one OLDER ring event that
// only ?all=1 may surface.
const T1 = '2026-08-25T00:00:00.000Z';
const T0 = '2026-08-24T00:00:00.000Z';
const mk = (handle, offersBounties) => ({ handle, name: handle, url: 'https://hackerone.com/' + handle, offersBounties, lastSeenScopeHash: 'sha256:x', scope: { in: [], out: [] }, policyHash: 'sha256:p', bountyHash: 'sha256:b', automation: { policy: 'prohibited', basis: 'default-silent', evidence: '…' }, firstSeen: T1, lastChanged: T1, lastScan: T1 });
writeFileSync(join(DATA, 'state.json'), JSON.stringify({
  programs: { acme: mk('acme', true), globex: mk('globex', false), initech: mk('initech', true) },
  events: [
    { at: T1, type: 'scope-removed', side: 'in', handle: 'initech', assets: ['old.initech.example'] },          // rank 7
    { at: T1, type: 'new-program', handle: 'globex', name: 'Globex', offersBounties: false, assets: [], exclusions: [], automation: { policy: 'prohibited' } }, // rank 4
    { at: T1, type: 'scope-added', side: 'out', handle: 'acme', assets: ['offlimits.acme.example'], note: 'NEW EXCLUSION — this ground is now OFF LIMITS; honor it before any contact' }, // rank 6
    { at: T1, type: 'new-program', handle: 'acme', name: 'Acme', offersBounties: true, assets: ['acme.example'], exclusions: [], automation: { policy: 'full' } }, // rank 1
    { at: T1, type: 'scope-added', side: 'in', handle: 'initech', offersBounties: true, assets: ['new.initech.example'] }, // rank 2
    { at: T0, type: 'policy-changed', handle: 'globex', automation: { from: { policy: 'prohibited' }, to: { policy: 'human-cadence' } } }, // older scan — ring only
  ],
  lastScan: { at: T1, programs: 3, events: 5, errors: [] },
}, null, 2));

const DOCTRINE = 'fresh ground found is an opportunity list, not authorization — scope must be signed before any contact.';
const SENTINEL = 'h1-token-SENTINEL-never-on-the-wire';

let proc = null, port = 39231, base = null;
async function boot() {
  const serverFile = join(__dir, '..', 'server.mjs');
  proc = spawn(process.execPath, [serverFile], {
    env: {
      ...process.env,
      VARVEL_PORT: String(port), VARVEL_DEMO_PORT: '39232', VARVEL_HARD_PORT: '39233',
      VARVEL_H1WATCH_DIR: DATA,
      VARVEL_H1_TOKEN: SENTINEL, VARVEL_H1_USER: 'sentinel-user', // present in env — the route must never read or reflect it
    },
    stdio: ['ignore', 'pipe', 'ignore'],
  });
  await new Promise((resolve, reject) => {
    const to = setTimeout(() => reject(new Error('server.mjs did not report listening within 25s')), 25000);
    let buf = '';
    proc.stdout.on('data', (d) => { buf += d; if (buf.includes('VARVEL service on')) { clearTimeout(to); resolve(); } });
    proc.on('exit', () => reject(new Error('server.mjs exited before listening: ' + buf.slice(0, 200))));
  });
  base = `http://127.0.0.1:${port}`;
  for (let i = 0; i < 20; i++) { // the log line precedes the demo-target boot — give routes a moment
    try { const r = await fetch(base + '/api/h1watch'); if (r.ok) return; } catch { await new Promise((x) => setTimeout(x, 250)); }
  }
  throw new Error('route never answered');
}

test('GET /api/h1watch serves the persisted watcher summary, ranked exactly as report() ranks', async () => {
  await boot();
  const r = await fetch(base + '/api/h1watch');
  assert.ok(r.ok, 'route answered');
  const wire = await r.text();
  assert.ok(!wire.includes(SENTINEL), 'the H1 token never leaves the server over this route');
  assert.ok(!wire.includes('sentinel-user'), 'the H1 user identifier is not reflected either');
  const body = JSON.parse(wire);
  assert.equal(body.ok, true);
  assert.equal(body.at, T1, 'latest scan time');
  assert.equal(body.tracked, 3);
  assert.equal(body.doctrine, DOCTRINE, 'the doctrine line rides verbatim');
  assert.equal(body.events.length, 5, 'default = the latest scan’s events (the older ring event stays out)');
  assert.deepEqual(body.events.map((e) => e.rank), [1, 2, 4, 6, 7], 'new+bountied first … exclusion moves before informational');
  assert.equal(body.events[0].handle, 'acme');
  const excl = body.events.find((e) => e.side === 'out');
  assert.ok(excl && /honor it before any contact/.test(excl.note || ''), 'the exclusion move carries its honor-before-any-contact weight');
});

test('GET /api/h1watch?all=1 widens to the whole event ring', async () => {
  const r = await fetch(base + '/api/h1watch?all=1');
  const body = JSON.parse(r.ok ? await r.text() : '{}');
  assert.equal(body.events.length, 6, 'the older ring event joins');
  assert.ok(body.events.some((e) => e.at === T0));
});

// Teardown grace: on win32, --test-force-exit can fire while sockets are still closing
// (libuv UV_HANDLE_CLOSING assert). Same guard as transportfail/dnstransport/flowscore.
test('teardown grace for socket drain (win32 libuv assert guard)', async () => {
  await new Promise((r) => setTimeout(r, 600));
});

after(() => {
  try { if (proc) proc.kill(); } catch {}
  try { rmSync(DATA, { recursive: true, force: true }); } catch {}
});
