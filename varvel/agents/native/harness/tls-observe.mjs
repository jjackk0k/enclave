// tls-observe.mjs — the negotiated-protocol observer leg: a REAL TLS server (the
// platform's static lab cert, engine/doh-labcert.mjs) that completes the handshake
// with the native agent and records what actually got negotiated and spoken:
//   · ALPN result (socket.getProtocol())   — h2, http/1.1, or none
//   · TLS version + cipher                 — socket.getTLSVersion() / getCipher()
//   · the HTTP version of the request line — h2 (Http2ServerRequest) vs 1.1
//   · the channel headers riding the wire  — x-agent/x-seq/x-auth present and intact
//
// The server is HTTP/2-capable WITH allowHTTP1, so the client's true preference is
// what shows up. Any GET is answered 204 (the channel's idle shape) so the agent
// completes one honest pull (-once).
//
// CLI:  node agents/native/harness/tls-observe.mjs <path-to-varvel-agent.exe> <profile>
// LIB:  import { observeAgentTls } from './tls-observe.mjs'

import http2 from 'node:http2';
import { spawn } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DOH_LAB_CERT, DOH_LAB_KEY } from '../../../engine/doh-labcert.mjs';

export async function observeAgentTls(binary, profile, { timeout = 15000 } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'varvel-native-'));
  const seen = [];
  const server = http2.createSecureServer({ cert: DOH_LAB_CERT, key: DOH_LAB_KEY, allowHTTP1: true }, (req, res) => {
    const sock = req.socket;
    seen.push({
      alpn: sock.alpnProtocol || null,                 // negotiated ALPN (h2 / http/1.1 / false)
      tlsVersion: sock.getProtocol ? sock.getProtocol() : null, // e.g. 'TLSv1.3'
      cipher: sock.getCipher ? (sock.getCipher().name || null) : null,
      httpVersion: req.httpVersion,                    // '2.0' (h2) or '1.1'
      method: req.method,
      path: req.url,
      channelHeaders: {                                // the governed wire, intact over TLS
        'x-agent': req.headers['x-agent'] || null,
        'x-seq': req.headers['x-seq'] || null,
        'x-auth': typeof req.headers['x-auth'] === 'string' && /^[0-9a-f]{64}$/.test(req.headers['x-auth']),
      },
    });
    res.statusCode = 204; // the channel's idle shape
    res.end();
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
        '-url', `https://localhost:${port}`,
        '-id', 'ja4probe', '-token', 'observe-leg-only',
        '-tls-profile', profile, '-tls-insecure', '-once', '-dir', dir,
      ], { windowsHide: true });
      child.stderr.on('data', (d) => { stderr += d; });
      const timer = setTimeout(() => finish({ ok: false, error: 'timeout waiting for the agent pull', seen, stderr: stderr.trim() }), timeout);
      if (timer.unref) timer.unref();
      child.on('exit', (code) => {
        clearTimeout(timer);
        finish({ ok: code === 0 && seen.length > 0, exitCode: code, seen, stderr: stderr.trim() });
      });
    });
  });
}

// CLI
if (process.argv[1] && import.meta.url === new URL('file://' + process.argv[1].replace(/\\/g, '/')).href) {
  const [binary, profile = 'chrome'] = process.argv.slice(2);
  if (!binary) { console.error('usage: node tls-observe.mjs <varvel-agent.exe> [chrome|go-native]'); process.exit(2); }
  const r = await observeAgentTls(binary, profile);
  console.log(JSON.stringify(r, null, 2));
  process.exit(r.ok ? 0 : 1);
}
