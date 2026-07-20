// sandbox-agent.mjs — runs INSIDE the sandbox container, which sits on an INTERNAL
// docker network (no internet route) and holds NO credential. Its only reachable
// peer is the broker. It probes what it can and can't do, and prints the result.
import http from 'node:http';
import net from 'node:net';

const BROKER = process.env.BROKER_URL || 'http://enclave-fs-broker:8080';

function viaBroker(host, extraHeaders = {}) {
  return new Promise(resolve => {
    const u = new URL(BROKER);
    const data = Buffer.from(JSON.stringify({ prompt: 'hello' }));
    const req = http.request({ host: u.hostname, port: u.port, path: '/v1/messages', method: 'POST',
      headers: { 'content-type': 'application/json', 'content-length': data.length, 'x-egress-host': host, ...extraHeaders } },
      r => { let b = ''; r.on('data', c => (b += c)); r.on('end', () => { let j; try { j = JSON.parse(b); } catch { j = {}; } resolve({ status: r.statusCode, json: j }); }); });
    req.on('error', e => resolve({ status: 0, json: { error: e.code || e.message } }));
    req.end(data);
  });
}
function directConnect(host, port) {
  return new Promise(resolve => {
    const s = net.connect(port, host);
    s.setTimeout(2500);
    s.on('connect', () => { resolve('REACHED'); s.destroy(); });
    s.on('error', e => resolve('blocked:' + (e.code || 'err')));
    s.on('timeout', () => { resolve('blocked:timeout'); s.destroy(); });
  });
}
async function retryBroker(host, extra, tries = 12) {
  for (let i = 0; i < tries; i++) { const r = await viaBroker(host, extra); if (r.status !== 0) return r; await new Promise(x => setTimeout(x, 500)); }
  return { status: 0, json: { error: 'broker unreachable' } };
}

(async () => {
  const out = {};
  out.sandboxHasKey = !!process.env.ANTHROPIC_API_KEY;
  out.viaBrokerAnthropic = await retryBroker('api.anthropic.com');            // allowed → key injected by broker
  out.viaBrokerExfil = (await viaBroker('pastebin.com')).json;               // off-allowlist → 403
  out.directAnthropic = await directConnect('api.anthropic.com', 443);        // no route even to the allowed host
  out.directInternet = await directConnect('1.1.1.1', 443);                   // no internet at all
  out.smuggle = await viaBroker('api.anthropic.com', { 'x-api-key': 'sk-SANDBOX-STOLEN' }); // stripped by broker
  console.log('RESULT:' + JSON.stringify(out));
})();
