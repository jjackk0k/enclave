// shape-observe.mjs — the JA4H PARITY harness for the native agent's shaped wire
// (the JA4 counterpart of capture-hello.mjs; the shapegrade contract closed over the
// Go emission path).
//
// THE MEASUREMENT: a request's JA4H (engine/fingerprint.mjs) hashes the header NAMES
// IN WIRE ORDER. The Go agent emits shaped requests through its purpose ordered
// emitter (agents/native/shapehttp.go — net/http sorts headers, so it cannot). This
// harness fingerprints what the Go side ACTUALLY put on the wire and asserts it
// BYTE-EQUAL against the profile's claim (engine/malleable.expectedJa4h) — both
// computed by the SAME Node modules, so the comparison is the platform's own
// claimed-vs-measured contract, one implementation, no re-implementation drift.
//
// Modes:
//   judge <profile> <capture.json>
//     capture.json = { method, httpVersion, path, headers: [[name, value], ...] } —
//     one observed request in WIRE ORDER (the Go test captures the raw bytes off a
//     loopback listener and writes this). Prints
//       { ok, profile, method, observed, claimed, match, note }
//     exit 1 on mismatch (a divergence report, never smoothed).
//   run <varvel-agent.exe> <profile>
//     Spawns the COMPILED agent (-shape <profile> -once) against a bare stub server
//     that records rawHeaders (Node preserves wire order+case there), delivers one
//     echo task so a shaped PUSH fires too, then judges both requests. Prints the
//     full report. This is the binary-end-to-end leg (the governed-channel version
//     runs in test/native-agent.test.mjs).
//
// Honest scope: a match is string equality between the platform's claim and the
// platform's measurement of THIS wire — never a detectability verdict.
import http from 'node:http';
import { spawn } from 'node:child_process';
import { readFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ja4h } from '../../../engine/fingerprint.mjs';
import { expectedJa4h, shapeProfile } from '../../../engine/malleable.mjs';

const pairsToList = (rawHeaders) => {
  const out = [];
  for (let i = 0; i + 1 < rawHeaders.length; i += 2) out.push([String(rawHeaders[i]), String(rawHeaders[i + 1])]);
  return out;
};

// judgeOne fingerprints one observed request and compares it against the claim.
export function judgeOne(profile, { method, httpVersion = '1.1', headers }) {
  const claimed = expectedJa4h(profile, { method, ja4hFn: ja4h });
  const observed = ja4h({ method, httpVersion, headers });
  return {
    profile, method, observed, claimed,
    match: observed != null && observed === claimed,
    note: 'claimed = engine/malleable.expectedJa4h (the template order); observed = engine/fingerprint.ja4h over the Go wire bytes. String equality on the platform\'s own oracle — never a detectability verdict.',
  };
}

function judge(profile, captureFile) {
  const cap = JSON.parse(readFileSync(captureFile, 'utf8'));
  const rep = judgeOne(profile, cap);
  console.log(JSON.stringify({ ok: rep.match, ...rep }, null, 1));
  process.exit(rep.match ? 0 : 1);
}

// run: the compiled binary against a rawHeaders-recording stub (one pull carrying a
// task, one push of its echo result), then judge both legs.
export async function observeAgentShape(binary, profile, { timeout = 20000 } = {}) {
  if (!shapeProfile(profile) || !shapeProfile(profile).http) {
    return { ok: false, error: "profile '" + profile + "' has no http template (known: cdn-asset, software-update, telemetry-beacon)" };
  }
  const dir = mkdtempSync(join(tmpdir(), 'varvel-shape-'));
  const seen = [];
  const server = http.createServer((req, res) => {
    const entry = { method: req.method, httpVersion: req.httpVersion, path: req.url, route: req.url.split('?')[0], headers: pairsToList(req.rawHeaders || []) };
    seen.push(entry);
    if (req.method === 'GET') {
      res.writeHead(200, { 'content-type': 'application/octet-stream' });
      res.end(JSON.stringify({ taskId: 'shape-probe-task', kind: 'echo', data: 'shape-probe' }));
      return;
    }
    req.resume();
    req.on('end', () => { res.writeHead(200); res.end(); });
  });
  return await new Promise((resolve) => {
    let child = null;
    const finish = (out) => {
      try { if (child) child.kill(); } catch {}
      try { server.close(); } catch {}
      resolve(out);
    };
    server.on('error', (e) => finish({ ok: false, error: String((e && e.message) || e), seen }));
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      let stderr = '';
      child = spawn(binary, [
        '-url', `http://127.0.0.1:${port}`, '-id', 'ja4hprobe', '-token', 'observe-leg-only',
        '-shape', profile, '-once', '-interval', '200', '-jitter', '0', '-dir', dir,
      ], { windowsHide: true });
      child.stderr.on('data', (d) => { stderr += d; });
      const timer = setTimeout(() => finish({ ok: false, error: 'timeout waiting for the shaped pull+push', seen, stderr: stderr.trim() }), timeout);
      if (timer.unref) timer.unref();
      child.on('exit', () => {
        clearTimeout(timer);
        const pull = seen.find((r) => r.method === 'GET');
        const push = seen.find((r) => r.method === 'POST');
        if (!pull || !push) {
          return finish({ ok: false, error: 'stub saw ' + seen.length + ' request(s), want the shaped pull AND push', seen, stderr: stderr.trim() });
        }
        const s = shapeProfile(profile);
        const pullRep = { ...judgeOne(profile, pull), routeOk: s.http.pullPaths.includes(pull.route), queryKey: pull.path.includes('?' + s.http.queryKey + '=') };
        const pushRep = { ...judgeOne(profile, push), routeOk: s.http.pushPaths.includes(push.route) };
        finish({
          ok: pullRep.match && pushRep.match && pullRep.routeOk && pullRep.queryKey && pushRep.routeOk,
          profile, pull: pullRep, push: pushRep, stderr: stderr.trim().split('\n')[0] || '',
        });
      });
    });
  });
}

// CLI
if (process.argv[1] && import.meta.url === new URL('file://' + process.argv[1].replace(/\\/g, '/')).href) {
  const [mode, a1, a2] = process.argv.slice(2);
  if (mode === 'judge' && a1 && a2) {
    judge(a1, a2);
  } else if (mode === 'run' && a1 && a2) {
    const r = await observeAgentShape(a1, a2);
    console.log(JSON.stringify(r, null, 2));
    process.exit(r.ok ? 0 : 1);
  } else {
    console.error('usage: shape-observe.mjs judge <profile> <capture.json> | run <varvel-agent.exe> <profile>');
    process.exit(2);
  }
}
