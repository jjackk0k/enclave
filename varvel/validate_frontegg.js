const https = require('https');
const tls = require('tls');
const dns = require('dns').promises;
const fs = require('fs');

const targets = [
  'api.frontegg.com',
  'portal.frontegg.com',
  'api.au.frontegg.com',
  'portal.au.frontegg.com'
];

const scopeCIDRs = [
  '13.227.173.119/32',
  '13.227.173.30/32',
  '13.227.173.33/32',
  '13.227.173.87/32',
  '52.222.169.118/32',
  '52.222.169.36/32',
  '52.222.169.75/32',
  '52.222.169.98/32'
];

function ipToLong(ip) {
  return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}

function isInCidr(ip, cidr) {
  const [range, bits] = cidr.split('/');
  const mask = -1 << (32 - parseInt(bits, 10));
  return (ipToLong(ip) & mask) === (ipToLong(range) & mask);
}

function isInScope(ip) {
  return scopeCIDRs.some(cidr => isInCidr(ip, cidr));
}

function fetch(url, opts = {}) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers: { ...opts.headers, 'User-Agent': 'VARVEL-Validator/1.0' }, timeout: 10000 }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
  });
}

function getCert(host) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({ host, port: 443, servername: host, timeout: 10000 }, () => {
      const cert = socket.getPeerCertificate(true);
      socket.end();
      resolve(cert);
    });
    socket.on('error', reject);
    socket.on('timeout', () => { socket.destroy(); reject(new Error('timeout')); });
  });
}

async function validate() {
  const findings = [];
  for (const host of targets) {
    let ips;
    try {
      ips = await dns.resolve4(host);
    } catch (e) {
      console.error(`DNS failed for ${host}: ${e.message}`);
      continue;
    }
    const inScope = ips.some(isInScope);
    if (!inScope) {
      console.log(`${host} resolves to ${ips.join(', ')} — OUT OF SCOPE`);
      continue;
    }
    console.log(`\n=== ${host} (${ips.join(', ')}) ===`);

    // TLS wildcard check
    try {
      const cert = await getCert(host);
      const cn = cert.subject?.CN || '';
      const sans = cert.subjectaltname || '';
      const hasWildcard = cn.startsWith('*.') || sans.includes('DNS:*.');
      if (hasWildcard) {
        findings.push({ host, title: 'TLS: overly broad wildcard certificate', sev: 'med', confidence: 'confirmed', evidence: `CN=${cn} SANs=${sans}`, ref: 'TLS-WILD' });
        console.log('  [+] Wildcard TLS confirmed');
      }
    } catch (e) {
      console.error(`  [-] TLS check failed: ${e.message}`);
    }

    // Header and endpoint checks
    const paths = ['/', '/config.json', '/.env', '/robots.txt', '/admin', '/api/v1', '/swagger', '/openapi.json', '/.git/HEAD'];
    for (const path of paths) {
      try {
        const url = `https://${host}${path}`;
        const res = await fetch(url);
        const h = res.headers;
        const sevMap = [];
        if (!h['strict-transport-security']) sevMap.push({ title: 'Missing HSTS header on HTTPS service', sev: 'low', ref: 'HDR-HSTS' });
        if (!h['content-security-policy']) sevMap.push({ title: 'Missing Content-Security-Policy header', sev: 'low', ref: 'HDR-CSP' });
        if (!h['x-content-type-options']) sevMap.push({ title: 'Missing X-Content-Type-Options: nosniff', sev: 'info', ref: 'HDR-CTO' });
        if (!h['referrer-policy']) sevMap.push({ title: 'Missing Referrer-Policy header', sev: 'info', ref: 'HDR-RP' });
        const srv = (h['server'] || h['x-powered-by'] || '').toLowerCase();
        if (srv.includes('express')) sevMap.push({ title: 'Version disclosure: Express', sev: 'info', ref: 'HDR-EXP' });

        for (const item of sevMap) {
          // dedupe per host/ref
          if (!findings.some(f => f.host === host && f.ref === item.ref)) {
            findings.push({ host, ...item, confidence: 'confirmed', evidence: `Observed on ${path} (status ${res.status})` });
            console.log(`  [+] ${item.title} confirmed on ${path}`);
          }
        }

        if (path === '/config.json' && res.status === 200 && res.body.length > 0) {
          findings.push({ host, title: 'config file exposed', sev: 'low', confidence: 'confirmed', evidence: `GET ${path} returned ${res.body.length} bytes`, ref: 'CFG-EXPOSED' });
          console.log(`  [+] Config exposed confirmed`);
        }
        if (path === '/.env' && res.status === 200 && res.body.includes('=')) {
          findings.push({ host, title: '.env file exposed', sev: 'crit', confidence: 'confirmed', evidence: `GET ${path} returned key-value pairs`, ref: 'ENV-EXPOSED' });
          console.log(`  [+] .env exposed confirmed`);
        }
      } catch (e) {
        console.error(`  [-] ${path} error: ${e.message}`);
      }
    }
  }

  fs.writeFileSync('validate_results.json', JSON.stringify({ findings }, null, 2));
  console.log('\nResults written to validate_results.json');
}

validate().catch(console.error);
