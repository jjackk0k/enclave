import tls from 'node:tls';
import https from 'node:https';

const HOSTS = ['sandbox.securegateway.com', 'sandbox-royal.securegateway.com'];
const IP = '188.34.187.32';
const PORT = 443;
const VHOSTS = ['admin', 'manager', 'api', 'dashboard', 'console', 'graphql', 'swagger'];

function tlsConnect(host, port, servername) {
  return new Promise((resolve) => {
    let settled = false;
    const done = (v) => { if (!settled) { settled = true; resolve(v); } };
    try {
      const sock = tls.connect({ host: IP, port, servername, rejectUnauthorized: false, timeout: 5000 }, () => {
        const c = sock.getPeerCertificate();
        const cert = c && Object.keys(c).length ? {
          subject: c.subject,
          issuer: c.issuer,
          san: c.subjectaltname,
          validTo: c.valid_to,
          validFrom: c.valid_from,
        } : null;
        done({ ok: true, cert, protocol: sock.getProtocol(), cipher: (sock.getCipher() || {}).name });
        try { sock.end(); } catch {}
      });
      sock.once('timeout', () => { try { sock.destroy(); } catch {} done({ ok: false, error: 'timeout' }); });
      sock.once('error', (e) => done({ ok: false, error: e.code || 'error' }));
    } catch (e) { done({ ok: false, error: e.code || 'error' }); }
  });
}

function request(host, path, headers = {}) {
  return new Promise((resolve) => {
    const req = https.request({ hostname: host, path, port: 443, method: 'GET', headers, rejectUnauthorized: false, timeout: 5000 }, (res) => {
      let body = '';
      res.on('data', (d) => { body += d; if (body.length > 128 * 1024) req.destroy(); });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
    });
    req.on('error', () => resolve(null));
    req.on('timeout', () => { try { req.destroy(); } catch {} resolve(null); });
    req.end();
  });
}

async function main() {
  const report = { hosts: [], vhostProbes: [], impact: null };

  for (const host of HOSTS) {
    const conn = await tlsConnect(IP, PORT, host);
    if (!conn.ok) {
      report.hosts.push({ host, ok: false, error: conn.error });
      continue;
    }
    const sanList = String(conn.cert?.san || '').split(',').map(s => s.trim()).filter(Boolean);
    const wildcardBroad = sanList.some(s => {
      const n = s.replace(/^DNS:/i, '');
      return n.startsWith('*.') && n.slice(2).split('.').filter(Boolean).length <= 2;
    });
    report.hosts.push({ host, ok: true, protocol: conn.protocol, cipher: conn.cipher, san: sanList, wildcardBroad });
  }

  // If a broad wildcard is confirmed, probe vhost-based access to privileged paths
  const broad = report.hosts.find(h => h.wildcardBroad);
  if (broad) {
    for (const vhost of VHOSTS) {
      const targetHost = `${vhost}.securegateway.com`;
      const r = await request(targetHost, '/admin', { Host: targetHost });
      report.vhostProbes.push({ vhost: targetHost, path: '/admin', status: r?.status, bodySnippet: r?.body?.slice(0, 200) });
      if (r && r.status === 200 && /admin|dashboard|console/i.test(r.body)) {
        report.impact = { vhost: targetHost, path: '/admin', evidence: 'privileged interface reachable under wildcard vhost' };
      }
    }
  }

  console.log(JSON.stringify(report, null, 2));
}

main().catch(e => { console.error(String(e)); process.exit(1); });
