// egressbench.test.mjs — hermetic ONLY (no live network): every probe rides a scripted
// fetcherFactory. Pinned: per-egress rates, the kinds histogram, throwing fetchers count
// as errors without crashing, errors stay OUT of the rate denominator (and the note says
// so), pacing is honored, and the locked honesty label is present.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import tls from 'node:tls';
import { benchEgress } from '../tools/egressbench.mjs';
import { TLSI_SELF, TLSI_SELF_KEY } from './tlsi-fixtures.mjs';

const CHALLENGED = {
  status: 403,
  headers: { server: 'cloudflare', 'cf-mitigated': 'challenge', 'cf-ray': '8f00abc-x' },
  body: '<html><head><title>Just a moment...</title></head><body>challenge-platform</body></html>',
};
const CLEAN = {
  status: 200,
  headers: { server: 'cloudflare', 'cf-ray': '8f00def-y' },
  body: '<html><body>hello world</body></html>',
};

// Scripted factory: map egress id -> response object, or a function(callIndex) that may
// return a response or throw. Records call timestamps per egress for the pacing test.
function scriptedFactory(map, stamps = {}) {
  return (egress) => {
    const behavior = map[egress.id];
    assert.ok(behavior, 'no scripted behavior for egress ' + egress.id);
    let calls = 0;
    return async () => {
      (stamps[egress.id] = stamps[egress.id] || []).push(Date.now());
      calls++;
      return typeof behavior === 'function' ? behavior(calls) : behavior;
    };
  };
}

test('benchEgress: per-egress challenge rates are measured, not asserted', async () => {
  const r = await benchEgress('https://consented.example/', {
    egresses: [{ id: 'always' }, { id: 'never' }],
    samples: 6,
    paceMs: 0,
    fetcherFactory: scriptedFactory({ always: CHALLENGED, never: CLEAN }),
  });
  assert.equal(r.ok, true);
  assert.equal(r.compared, true);
  assert.equal(r.results.length, 2);
  const [a, n] = r.results;
  assert.equal(a.egress, 'always');
  assert.equal(a.challenged, 6);
  assert.equal(a.errors, 0);
  assert.equal(a.challengeRate, 1);
  assert.equal(a.note, '6/6 challenged (managed-js ×6) via always');
  assert.equal(n.egress, 'never');
  assert.equal(n.challenged, 0);
  assert.equal(n.challengeRate, 0);
  assert.equal(n.note, '0/6 challenged via never');
});

test('benchEgress: the kinds histogram is populated per egress', async () => {
  const r = await benchEgress('https://consented.example/', {
    egresses: [{ id: 'always' }, { id: 'never' }],
    samples: 4,
    paceMs: 0,
    fetcherFactory: scriptedFactory({ always: CHALLENGED, never: CLEAN }),
  });
  assert.deepEqual(r.results[0].kinds, { 'managed-js': 4 });
  assert.deepEqual(r.results[1].kinds, {});
});

test('benchEgress: a throwing fetcher increments errors and never crashes the run', async () => {
  const r = await benchEgress('https://consented.example/', {
    egresses: [{ id: 'dead' }, { id: 'never' }],
    samples: 5,
    paceMs: 0,
    fetcherFactory: scriptedFactory({
      dead: () => { throw new Error('socks5 127.0.0.1:9050 refused CONNECT (code 5)'); },
      never: CLEAN,
    }),
  });
  assert.equal(r.ok, true); // the run survived a fully-dead egress
  const dead = r.results[0];
  assert.equal(dead.errors, 5);
  assert.equal(dead.challenged, 0);
  assert.equal(dead.challengeRate, null); // no measurable denominator -> no rate, honestly
  assert.match(dead.note, /no measurable samples via dead/);
  assert.match(dead.note, /refused CONNECT/);
  assert.equal(r.results[1].challengeRate, 0); // the healthy egress still measured fine
});

test('benchEgress: errors are excluded from the rate denominator and the note says so', async () => {
  // 6 samples: 2 challenged, 2 clean, 2 thrown -> rate is 2/4 = 0.5, never 2/6.
  const r = await benchEgress('https://consented.example/', {
    egresses: [{ id: 'flaky' }],
    samples: 6,
    paceMs: 0,
    fetcherFactory: scriptedFactory({
      flaky: (call) => {
        if (call === 2 || call === 5) throw new Error('probe timed out (10000ms)');
        return (call === 1 || call === 4) ? CHALLENGED : CLEAN;
      },
    }),
  });
  assert.equal(r.ok, true);
  assert.equal(r.compared, false); // a lone egress is a measurement, not a comparison
  const f = r.results[0];
  assert.equal(f.challenged, 2);
  assert.equal(f.errors, 2);
  assert.equal(f.challengeRate, 0.5); // 2 / (6-2) — errors excluded from the denominator
  assert.deepEqual(f.kinds, { 'managed-js': 2 });
  assert.match(f.note, /2\/4 challenged \(managed-js ×2\) via flaky/);
  assert.match(f.note, /2 fetch error\(s\) excluded from the rate denominator/);
  assert.match(f.note, /probe timed out/);
});

test('benchEgress: pacing is honored between samples (timestamps)', async () => {
  const stamps = {};
  const t0 = Date.now();
  const r = await benchEgress('https://consented.example/', {
    egresses: [{ id: 'always' }],
    samples: 3,
    paceMs: 40,
    fetcherFactory: scriptedFactory({ always: CHALLENGED }, stamps),
  });
  assert.equal(r.ok, true);
  const ts = stamps.always;
  assert.equal(ts.length, 3);
  assert.ok(ts[1] - ts[0] >= 35, 'gap 1->2 honors paceMs (got ' + (ts[1] - ts[0]) + 'ms)');
  assert.ok(ts[2] - ts[1] >= 35, 'gap 2->3 honors paceMs (got ' + (ts[2] - ts[1]) + 'ms)');
  assert.ok(Date.now() - t0 >= 70, 'the run actually took the paced time');
});

test('benchEgress: the locked honesty label rides every run', async () => {
  const r = await benchEgress('https://consented.example/path?q=1', {
    egresses: [{ id: 'never' }],
    samples: 2,
    paceMs: 0,
    fetcherFactory: scriptedFactory({ never: CLEAN }),
  });
  assert.equal(r.ok, true);
  assert.match(r.honestNote, /^measured on zone consented\.example at /);
  assert.match(r.honestNote, /per-zone variance is the norm; a challenge rate is a measurement, not a capability claim\.$/);
  assert.ok(!Number.isNaN(Date.parse(r.at)), 'at is an ISO timestamp');
  assert.equal(r.url, 'https://consented.example/path?q=1');
  assert.deepEqual(Object.keys(r.results[0]).sort(), ['challenged', 'egress', 'errors', 'kinds', 'note', 'challengeRate', 'samples'].sort());
});

test('benchEgress: usage errors are honest objects, never throws', async () => {
  const bad1 = await benchEgress('not-a-url');
  assert.equal(bad1.ok, false);
  assert.match(bad1.error, /valid http\(s\) URL/);
  const bad2 = await benchEgress('gopher://x/', {});
  assert.equal(bad2.ok, false);
  assert.match(bad2.error, /http\(s\) targets/);
  const bad3 = await benchEgress('https://consented.example/', { egresses: [] });
  assert.equal(bad3.ok, false);
  assert.match(bad3.error, /at least one egress/);
  const bad4 = await benchEgress('https://consented.example/', { egresses: [{ proxy: 'socks5://h:1' }] });
  assert.equal(bad4.ok, false);
  assert.match(bad4.error, /needs an id/);
  const bad5 = await benchEgress('https://consented.example/', { samples: 0 });
  assert.equal(bad5.ok, false);
  assert.match(bad5.error, /samples must be an integer >= 1/);
});

test('benchEgress: a factory that throws per-egress fails honestly, all samples errored', async () => {
  const r = await benchEgress('https://consented.example/', {
    egresses: [{ id: 'broken' }],
    samples: 3,
    paceMs: 0,
    fetcherFactory: () => { throw new TypeError("egress proxy ':::' parsed to an empty chain"); },
  });
  assert.equal(r.ok, true);
  const b = r.results[0];
  assert.equal(b.errors, 3);
  assert.equal(b.challengeRate, null);
  assert.match(b.note, /no measurable samples via broken/);
});

test('benchEgress: a v6-literal target through a chain tunnels with a BRACKETED CONNECT and NO SNI (IP literals carry no SNI)', async () => {
  // Local CONNECT mock: captures the authority line, tunnels to a loopback TLS echo.
  let connectLine = null;
  const proxy = net.createServer((sock) => {
    let head = '';
    sock.on('data', function onData(d) {
      head += d.toString('latin1');
      if (head.includes('\r\n\r\n')) {
        connectLine = head.split('\r\n')[0];
        sock.off('data', onData);
        const port = Number(/\[?[0-9a-f:.]+\]?:(\d+)$/i.exec(connectLine.replace(/^CONNECT /, '').replace(/ HTTP.*$/, ''))[1]);
        const up = net.connect({ host: '127.0.0.1', port }, () => {
          sock.write('HTTP/1.1 200 OK\r\n\r\n');
          sock.pipe(up); up.pipe(sock);
        });
        up.on('error', () => sock.destroy());
      }
    });
  });
  await new Promise((r) => proxy.listen(0, '127.0.0.1', r));
  const pport = proxy.address().port;
  // TLS echo that RECORDS any SNI the client offers (SNICallback fires only when SNI is sent)
  const sniSeen = [];
  const echo = tls.createServer({
    cert: TLSI_SELF, key: TLSI_SELF_KEY,
    SNICallback: (sn, cb) => { sniSeen.push(sn); cb(null, tls.createSecureContext({ cert: TLSI_SELF, key: TLSI_SELF_KEY })); },
  }, (s) => s.on('data', () => s.end('HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok')));
  await new Promise((r) => echo.listen(0, '127.0.0.1', r));
  const eport = echo.address().port;
  try {
    const r = await benchEgress('https://[2001:db8::9]:' + eport + '/', {
      egresses: [{ id: 'v6-chain', proxy: 'http://127.0.0.1:' + pport }],
      samples: 1, paceMs: 0, timeoutMs: 3000,
    });
    assert.equal(r.ok, true, 'the v6-literal chain run completes (TLS auth to a self-signed echo fails honestly, counted as an error)');
    assert.equal(r.results[0].errors, 1, 'untrusted self-signed echo: an honest error entry, not a crash');
    assert.ok(connectLine && connectLine.startsWith('CONNECT [2001:db8::9]:' + eport + ' '), 'CONNECT authority bracketed — got ' + connectLine);
    assert.deepEqual(sniSeen, [], 'no SNI offered for an IP literal (net.isIP misses the bracketed form; the strict parser catches it)');
  } finally {
    echo.close(); proxy.close();
  }
});
