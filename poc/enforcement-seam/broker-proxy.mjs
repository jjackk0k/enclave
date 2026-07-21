// broker-proxy.mjs — the enclave egress broker (runs as its own container).
//
// Enclave containers sit on an --internal Docker network (NO direct route to the
// internet). Their ONLY way out is this forward proxy, which permits a connection
// ONLY to a host on the research allowlist (egress-allowlist.mjs) and refuses the
// rest. So the container's tools can pull CURRENT material from approved sources
// (CVE/NVD, ATT&CK, GitHub, package registries, docs) but can't exfiltrate to an
// arbitrary host — the same "pull, don't push" rule as the model's WebFetch, now
// enforced at the network edge for the whole container. Every decision is logged.
//
// (HTTPS is tunnelled via CONNECT, so the host allowlist is enforced but the
// encrypted body isn't inspected — full TLS-terminating DLP is the production tier.)

import http from 'node:http';
import net from 'node:net';
import { hostAllowed } from './egress-allowlist.mjs';

const PORT = Number(process.env.BROKER_PORT) || 8888;
const log = (decision, host, extra = '') => console.log(`[broker] ${decision.padEnd(5)} ${host} ${extra}`);

// plain HTTP proxying (GET/POST/…): inspect the target host against the allowlist
const server = http.createServer((req, res) => {
  let host = '';
  try { host = new URL(req.url).hostname; } catch { res.writeHead(400); return res.end('bad request\n'); }
  if (!hostAllowed(host)) { log('DENY', host, '(off-allowlist)'); res.writeHead(403); return res.end('enclave-broker: host not on the research allowlist\n'); }
  log('ALLOW', host, req.method);
  const u = new URL(req.url);
  const up = http.request({ hostname: u.hostname, port: u.port || 80, path: u.pathname + u.search, method: req.method, headers: req.headers },
    pr => { res.writeHead(pr.statusCode || 502, pr.headers); pr.pipe(res); });
  up.on('error', () => { if (!res.headersSent) res.writeHead(502); res.end(); });
  req.pipe(up);
});

// HTTPS: CONNECT tunnel, gated on the host (SNI host = req.url host:port)
server.on('connect', (req, client, head) => {
  const host = String(req.url).split(':')[0];
  const port = Number(String(req.url).split(':')[1]) || 443;
  if (!hostAllowed(host)) { log('DENY', host, '(CONNECT off-allowlist)'); client.write('HTTP/1.1 403 Forbidden\r\n\r\n'); return client.end(); }
  log('ALLOW', host, 'CONNECT');
  const upstream = net.connect(port, host, () => {
    client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    upstream.write(head); upstream.pipe(client); client.pipe(upstream);
  });
  upstream.on('error', () => client.end());
  client.on('error', () => upstream.end());
});

server.listen(PORT, () => console.log(`[broker] enclave egress broker on :${PORT} — allowlist-enforced (pull-only)`));
