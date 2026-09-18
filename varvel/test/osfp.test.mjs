// osfp.test.mjs — hermetic tests for tools/osfp.mjs (every signal injectable).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { osFingerprint, __internals, SIGNAL_WEIGHTS } from '../tools/osfp.mjs';

const { parseSshBanner, parseHttpServer, familyFromTtl } = __internals;

// --- unit: parsers ---
test('ssh banner parser pins distro-tagged OpenSSH', () => {
  assert.deepEqual(parseSshBanner('SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6')?.family, 'linux');
  assert.match(parseSshBanner('SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6')?.version, /Ubuntu 22\.04/);
  assert.equal(parseSshBanner('SSH-2.0-OpenSSH_for_Windows_8.1')?.family, 'windows');
  assert.equal(parseSshBanner('SSH-2.0-OpenSSH_9.2p1 Debian-2')?.family, 'linux');
  assert.equal(parseSshBanner('SSH-2.0-dropbear_2020.81') ?? null, null);
});

test('http Server parser pins IIS bands and distro Apache', () => {
  assert.equal(parseHttpServer('Microsoft-IIS/10.0')?.family, 'windows');
  assert.match(parseHttpServer('Microsoft-IIS/10.0')?.version, /2016/);
  assert.equal(parseHttpServer('Apache/2.4.52 (Ubuntu)')?.family, 'linux');
  assert.equal(parseHttpServer('nginx') ?? null, null); // honest: nginx alone says nothing
});

test('TTL family mapping rounds to initial TTL', () => {
  assert.equal(familyFromTtl(117)?.family, 'windows');  // ~128 minus hops
  assert.equal(familyFromTtl(52)?.family, 'linux');     // ~64
  assert.equal(familyFromTtl(240)?.family, 'network-device'); // ~255
});

// --- integration: correlation over injected signals ---
test('smb dialect pins Windows with the strongest weight', async () => {
  const r = await osFingerprint('10.0.0.5', {
    signals: ['smb'],
    smbImpl: async () => ({ dialectRevision: 0x0311, signingRequired: true }),
  });
  assert.equal(r.family, 'windows');
  assert.match(r.version, /Windows 10\/11/);
  assert.equal(r.confidence, SIGNAL_WEIGHTS.smb);
  assert.match(r.signals[0].evidence, /signing required/);
});

test('3.0.2 answer is honestly labeled as the client ceiling, not the OS version', async () => {
  const r = await osFingerprint('10.0.0.5', {
    signals: ['smb'],
    smbImpl: async () => ({ dialectRevision: 0x0302 }),
  });
  assert.match(r.version, /or later \(answered at the client dialect ceiling\)/);
});

test('ttl-only gives family with a weak-evidence caveat', async () => {
  const r = await osFingerprint('10.0.0.5', {
    signals: ['ttl'],
    execImpl: async () => 128,
  });
  assert.equal(r.family, 'windows');
  assert.equal(r.confidence, SIGNAL_WEIGHTS.ttl);
  assert.ok(r.caveats.some((c) => /weak evidence/.test(c)));
});

test('agreeing signals sum weights and cap at 95', async () => {
  const r = await osFingerprint('10.0.0.5', {
    signals: ['smb', 'ttl', 'banner'],
    smbImpl: async () => ({ dialectRevision: 0x0311 }),
    execImpl: async () => 127,
    bannerImpl: async () => [{ port: 22, text: 'SSH-2.0-OpenSSH_for_Windows_9.5' }],
  });
  assert.equal(r.family, 'windows');
  assert.equal(r.confidence, 95); // 55+25+35 = 115 → capped
});

test('conflicting families halve confidence and surface a caveat', async () => {
  const r = await osFingerprint('10.0.0.5', {
    signals: ['smb', 'ttl'],
    smbImpl: async () => ({ dialectRevision: 0x0311 }),       // windows w55
    execImpl: async () => 64,                                  // linux w25
  });
  assert.equal(r.family, 'windows'); // majority vote
  assert.equal(r.confidence, Math.floor(55 / 2));
  assert.ok(r.caveats.some((c) => /conflicting signals/.test(c)));
});

test('signal failures degrade honestly, never throw', async () => {
  const r = await osFingerprint('10.0.0.5', {
    signals: ['smb', 'ttl', 'banner'],
    smbImpl: async () => { throw new Error('connection refused'); },
    execImpl: async () => null,
    bannerImpl: async () => [],
  });
  assert.equal(r.family, 'unknown');
  assert.equal(r.confidence, 0);
  assert.ok(r.caveats.some((c) => /no OS signal observable/.test(c)));
  assert.ok(r.caveats.some((c) => /smb: connection refused/.test(c)));
});

test('banner evidence selects SSH over HTTP when both exist', async () => {
  const r = await osFingerprint('10.0.0.5', {
    signals: ['banner'],
    bannerImpl: async () => [
      { port: 22, text: 'SSH-2.0-OpenSSH_9.2p1 Debian-2' },
      { port: 80, text: 'HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0' },
    ],
  });
  assert.equal(r.family, 'linux'); // SSH banner is checked first and pins Debian
});

test('host is required', async () => {
  await assert.rejects(() => osFingerprint(''), /host is required/);
});
