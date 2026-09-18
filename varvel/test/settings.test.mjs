// settings.test.mjs — hermetic tests for engine/settings.mjs write-through persistence.
// VARVEL_SETTINGS_FILE points at a temp file per test; engagement names are unique per
// test because the module-level registry caches per engagement for the process lifetime.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Settings } from '../engine/settings.mjs';

function tempFile(name) {
  const p = join(mkdtempSync(join(tmpdir(), 'vset-')), name);
  process.env.VARVEL_SETTINGS_FILE = p;
  return p;
}

test('set() writes through and a fresh Settings.for() restores it', () => {
  tempFile('s.json');
  const eng = 'eng-persist-' + Date.now();
  Settings.for(eng).set('ghost.mode', 'required');
  Settings.for(eng).set('ghost.chain', 'socks5://10.64.0.1:1080');
  // wipe the in-memory registry entry to simulate a restart
  // (registry is module-private; a NEW engagement name would not prove restore, so we
  //  reload the module fresh via a dynamic import with a cache-busting query)
  return import('../engine/settings.mjs?fresh=' + Date.now()).then((m) => {
    const s = m.Settings.for(eng);
    assert.equal(s.get('ghost.mode'), 'required');
    assert.equal(s.get('ghost.chain'), 'socks5://10.64.0.1:1080');
  });
});

test('corrupt settings file -> defaults, never throws', () => {
  const p = tempFile('s.json');
  writeFileSync(p, '{not json!!');
  const s = Settings.for('eng-corrupt-' + Date.now());
  assert.equal(s.get('ghost.mode'), 'off'); // schema default
  assert.equal(s.get('agent.maxTurns'), 40);
});

test('invalid/unknown stored values are dropped on load, valid ones kept', async () => {
  const p = tempFile('s.json');
  const eng = 'eng-filter-' + Date.now();
  writeFileSync(p, JSON.stringify({ [eng]: { 'ghost.mode': 'bogus-mode', 'agent.maxTurns': 12, 'not.a.key': 'x' } }));
  const m = await import('../engine/settings.mjs?fresh=' + Date.now());
  const s = m.Settings.for(eng);
  assert.equal(s.get('ghost.mode'), 'off'); // bogus enum dropped -> default
  assert.equal(s.get('agent.maxTurns'), 12); // valid value kept
});

test('schema defaults hold when nothing is stored; toJSON reports overrides only', async () => {
  const p = tempFile('s.json');
  const m = await import('../engine/settings.mjs?fresh=' + Date.now());
  const eng = 'eng-json-' + Date.now();
  m.Settings.for(eng).set('stealth.profile', 'quiet');
  const j = m.Settings.for(eng).toJSON();
  assert.equal(j.values['stealth.profile'], 'quiet');
  assert.equal(j.values['recon.maxPages'], 25);
  assert.deepEqual(j.overrides, ['stealth.profile']);
  // and the file on disk carries only the override
  const onDisk = JSON.parse(readFileSync(p, 'utf8'));
  assert.deepEqual(Object.keys(onDisk[eng]), ['stealth.profile']);
});
