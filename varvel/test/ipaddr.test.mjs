// ipaddr.test.mjs — hermetic unit tests for engine/ipaddr.mjs (no sockets, no I/O).
// Scope math is the security boundary: every parse/match/classify rule is pinned here.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseIp, parseCidr, inCidr, inAnyCidr, isLoopback, isPrivate, classifyIp, bracketHost, extractIp } from '../engine/ipaddr.mjs';

test('parseIp: strict IPv4', () => {
  assert.deepEqual(parseIp('10.0.0.5'), { fam: 4, v4: 0x0a000005, mapped: false, text: '10.0.0.5' });
  assert.equal(parseIp('0.0.0.0').v4, 0);
  assert.equal(parseIp('255.255.255.255').v4, 0xffffffff);
  assert.equal(parseIp(' 10.0.0.5 ').text, '10.0.0.5'); // trimmed (comma-list hygiene)
  for (const bad of ['010.0.0.1', '1.2.3.300', '1.2.3', '1.2.3.4.5', '1.2.3.04', '', null, 'garbage', '1.2.3.4:8080'])
    assert.equal(parseIp(bad), null, bad);
});

test('parseIp: IPv6 full/compressed/canonical', () => {
  assert.equal(parseIp('::1').text, '::1');
  assert.equal(parseIp('fd00::1').text, 'fd00::1');
  assert.equal(parseIp('FE80::9').text, 'fe80::9'); // canonical lowercase
  assert.equal(parseIp('2001:0db8:0000:0000:0000:0000:0000:0001').text, '2001:db8::1');
  assert.equal(parseIp('2001:db8:0:0:1:0:0:1').text, '2001:db8::1:0:0:1'); // tie: first run wins
  assert.equal(parseIp('2001:db8:0:1:1:1:1:1').text, '2001:db8:0:1:1:1:1:1'); // single zero group never compresses
  assert.equal(parseIp('1:2:3:4:5:6:7:8').text, '1:2:3:4:5:6:7:8');
  assert.equal(parseIp('::').text, '::');
  assert.equal(parseIp('[::1]').text, '::1');          // brackets stripped
  assert.equal(parseIp('fe80::1%eth0').text, 'fe80::1'); // zone stripped
  for (const bad of ['1:2:3:4:5:6:7:8:9', '1::2::3', '12345::', '::ffff:999.1.1.1', '[::1]:8080', '[::1', ':8080'])
    assert.equal(parseIp(bad), null, bad);
});

test('parseIp: v4-mapped v6 collapses to fam 4', () => {
  assert.deepEqual(parseIp('::ffff:10.0.0.5'), { fam: 4, v4: 0x0a000005, mapped: true, text: '10.0.0.5' });
  assert.equal(parseIp('::ffff:0a00:0005').text, '10.0.0.5'); // hex notation maps too
  assert.equal(parseIp('::ffff:127.0.0.1').text, '127.0.0.1');
});

test('parseCidr: forms + strict masks', () => {
  assert.deepEqual(parseCidr('10.0.0.0/8'), { fam: 4, bits: 8, v4: 0x0a000000 });
  assert.equal(parseCidr('10.0.0.5').bits, 32);   // bare v4 = host route
  assert.equal(parseCidr('fd00::/8').fam, 6);
  assert.equal(parseCidr('fd00::1').bits, 128);   // bare v6 = host route
  for (const bad of ['10.0.0.0/', '10.0.0.0/33', '10.0.0.0/abc', 'fd00::/129', 'a/b/c', '/', ''])
    assert.equal(parseCidr(bad), null, bad);
});

test('inCidr: v4 membership + boundary masks', () => {
  assert.equal(inCidr('10.10.0.5', '10.10.0.0/16'), true);
  assert.equal(inCidr('10.11.0.5', '10.10.0.0/16'), false);
  assert.equal(inCidr('8.8.8.8', '0.0.0.0/0'), true);
  assert.equal(inCidr('10.0.0.5', '10.0.0.4/30'), true);
  assert.equal(inCidr('10.0.0.8', '10.0.0.4/30'), false);
  assert.equal(inCidr('192.168.1.300', '0.0.0.0/0'), false); // invalid ip never matches
  assert.equal(inCidr('010.0.0.1', '10.0.0.0/8'), false);    // leading-zero octal ambiguity refused
  assert.equal(inCidr('1.2.3.4', '1.2.3.4/33'), false);      // out-of-range mask refused
});

test('inCidr: v6 membership + rem-bit masks', () => {
  assert.equal(inCidr('fd00::5', 'fd00::/8'), true);
  assert.equal(inCidr('fd00::1', 'fd00::/64'), true);
  assert.equal(inCidr('fd00:0:0:1::5', 'fd00::/64'), false);
  assert.equal(inCidr('fd7f::1', 'fd00::/9'), true);   // non-byte-aligned mask
  assert.equal(inCidr('fd80::1', 'fd00::/9'), false);
  assert.equal(inCidr('2001:db8::1', '::/0'), true);
  assert.equal(inCidr('fe80::1%eth0', 'fe80::/10'), true); // zone ignored
});

test('inCidr: family-strict — no silent cross-family match', () => {
  assert.equal(inCidr('10.0.0.5', '::/0'), false);        // all-v6 is NOT match-all
  assert.equal(inCidr('2001:db8::1', '0.0.0.0/0'), false); // all-v4 is NOT match-all
  assert.equal(inCidr('::ffff:10.10.0.5', '10.10.0.0/16'), true); // mapped collapses to v4
  assert.equal(inCidr('10.10.0.5', '::ffff:10.10.0.0/112'), true); // mapped CIDR base collapses too
});

test('inAnyCidr: arrays and comma strings, invalid entries skipped', () => {
  assert.equal(inAnyCidr('10.0.0.5', ['192.168.0.0/16', 'garbage', '10.0.0.0/8']), true);
  assert.equal(inAnyCidr('fd00::5', '192.168.0.0/16, fd00::/8'), true);
  assert.equal(inAnyCidr('10.0.0.5', ''), false);
  assert.equal(inAnyCidr('10.0.0.5', null), false);
});

test('isLoopback / isPrivate: classification', () => {
  for (const ip of ['127.0.0.1', '127.0.0.99', '::1', '::ffff:127.0.0.1']) assert.equal(isLoopback(ip), true, ip);
  for (const ip of ['10.0.0.1', '::', '128.0.0.1']) assert.equal(isLoopback(ip), false, ip);
  for (const ip of ['10.0.0.5', '172.16.0.9', '172.31.255.1', '192.168.1.1', '169.254.1.1', '127.0.0.1',
    '::1', 'fd00::1', 'fc00::1', 'fdff::', 'fe80::1', 'febf::1', '[fd00::1]', '::ffff:192.168.1.5'])
    assert.equal(isPrivate(ip), true, ip);
  for (const ip of ['8.8.8.8', '172.32.0.1', '203.0.113.7', '2001:4860:4860::8888', 'fec0::1', 'example.com', '', '2001:db8::1'])
    assert.equal(isPrivate(ip), false, ip); // documentation ranges stay PUBLIC (ghost contract)
});

test('classifyIp: explicit v4 classes with boundary honesty', () => {
  assert.deepEqual(classifyIp('127.0.0.1'), { fam: 4, mapped: false, text: '127.0.0.1', class: 'loopback' });
  assert.equal(classifyIp('127.0.0.99').class, 'loopback'); // ALL of 127/8
  assert.equal(classifyIp('169.254.1.1').class, 'link-local');
  for (const ip of ['10.0.0.5', '172.16.0.9', '172.31.255.1', '192.168.1.1']) assert.equal(classifyIp(ip).class, 'private', ip);
  for (const ip of ['192.0.2.9', '198.51.100.9', '203.0.113.9']) assert.equal(classifyIp(ip).class, 'documentation', ip);
  assert.equal(classifyIp('0.0.0.0').class, 'unspecified');
  for (const ip of ['8.8.8.8', '172.32.0.1', '192.0.3.1', '203.0.114.1']) assert.equal(classifyIp(ip).class, 'global', ip); // just outside each boundary
});

test('classifyIp: explicit v6 classes — loopback, ULA, link-local, documentation, global', () => {
  assert.deepEqual(classifyIp('::1'), { fam: 6, mapped: false, text: '::1', class: 'loopback' });
  assert.equal(classifyIp('::').class, 'unspecified');
  for (const ip of ['fc00::1', 'fd00::1', 'fdff::']) assert.equal(classifyIp(ip).class, 'ula', ip);                    // fc00::/7
  for (const ip of ['fe80::1', 'febf::1', 'FE80::9%eth0']) assert.equal(classifyIp(ip).class, 'link-local', ip);     // fe80::/10
  for (const ip of ['2001:db8::1', '2001:db8:ffff::ff']) assert.equal(classifyIp(ip).class, 'documentation', ip);    // 2001:db8::/32
  for (const ip of ['2001:db9::1', '2001:4860:4860::8888', 'fec0::1']) assert.equal(classifyIp(ip).class, 'global', ip);
});

test('classifyIp: v4-mapped classifies AS the v4 address; invalid input is null', () => {
  assert.deepEqual(classifyIp('::ffff:10.0.0.5'), { fam: 4, mapped: true, text: '10.0.0.5', class: 'private' });
  assert.equal(classifyIp('::ffff:127.0.0.1').class, 'loopback');
  assert.equal(classifyIp('::ffff:203.0.113.7').class, 'documentation');
  for (const bad of ['', null, 'garbage', 'example.com', '1.2.3.300', '1::2::3']) assert.equal(classifyIp(bad), null, bad);
});

test('classifyIp agrees with the isLoopback/isPrivate booleans (one math, two views)', () => {
  const PRIVATE_CLASSES = new Set(['loopback', 'link-local', 'private', 'ula']);
  for (const ip of ['127.0.0.1', '10.0.0.5', '172.16.0.9', '192.168.1.1', '169.254.1.1', '::1', 'fc00::1', 'fd00::1', 'fe80::1',
    '8.8.8.8', '172.32.0.1', '192.0.2.9', '203.0.113.7', '2001:db8::1', '2001:4860:4860::8888', '::ffff:192.168.1.5']) {
    const cls = classifyIp(ip).class;
    assert.equal(isLoopback(ip), cls === 'loopback', ip);
    assert.equal(isPrivate(ip), PRIVATE_CLASSES.has(cls), ip + ' -> ' + cls); // documentation stays PUBLIC (ghost contract)
  }
});

test('bracketHost: v6 bracketed for URLs, others untouched', () => {
  assert.equal(bracketHost('::1'), '[::1]');
  assert.equal(bracketHost('FE80::1'), '[fe80::1]');
  assert.equal(bracketHost('[fd00::1]'), '[fd00::1]');
  assert.equal(bracketHost('10.0.0.5'), '10.0.0.5');
  assert.equal(bracketHost('example.com'), 'example.com');
});

test('extractIp: clean literals out of command/URL text', () => {
  assert.equal(extractIp('nmap -sV 10.0.0.5'), '10.0.0.5');
  assert.equal(extractIp('curl http://10.0.0.5:8080/x'), '10.0.0.5');
  assert.equal(extractIp('curl http://[fd00::1]:8080/x'), 'fd00::1');
  assert.equal(extractIp('curl http://[::1]:8971/api'), '::1');
  assert.equal(extractIp('nmap fd00::5'), 'fd00::5');
  assert.equal(extractIp('curl http://user:pass@[2001:db8::1]/'), '2001:db8::1');
  assert.equal(extractIp('{"ip":"203.0.113.9"}'), '203.0.113.9');
  assert.equal(extractIp('nmap --version'), null);
  assert.equal(extractIp('999.999.1.1'), null);
  assert.equal(extractIp('no addresses here'), null);
});
