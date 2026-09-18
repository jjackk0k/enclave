const https = require('https');
const http = require('http');

const targets = [
  { host: 'api.mergify.com', ports: [80, 443, 8080, 8443] },
  { host: 'dashboard.mergify.com', ports: [80, 443, 8080, 8443] }
];

const paths = [
  '/',
  '/robots.txt',
  '/.well-known/security.txt',
  '/admin',
  '/api',
  '/api/v1',
  '/api/users',
  '/graphql',
  '/swagger',
  '/swagger-ui',
  '/openapi.json',
  '/.git/HEAD',
  '/actuator/health',
  '/config.json',
  '/.env'
];

function fetch(host, port, path) {
  return new Promise((resolve) => {
    const proto = port === 443 || port === 8443 ? https : http;
    const options = {
      hostname: host,
      port: port,
      path: path,
      method: 'GET',
      headers: {
        'User-Agent': 'curl/8.0.0',
        'Accept': '*/*',
        'Host': host
      },
      timeout: 8000,
      rejectUnauthorized: false
    };

    const req = proto.request(options, (res) => {
      let body = '';
      res.on('data', (chunk) => { body += chunk; });
      res.on('end', () => {
        resolve({ host, port, path, status: res.statusCode, headers: res.headers, bodySnippet: body.slice(0, 500) });
      });
    });

    req.on('error', (e) => resolve({ host, port, path, error: e.message }));
    req.on('timeout', () => { req.destroy(); resolve({ host, port, path, error: 'timeout' }); });
    req.end();
  });
}

(async () => {
  const results = [];
  for (const t of targets) {
    for (const p of t.ports) {
      for (const path of paths) {
        const r = await fetch(t.host, p, path);
        results.push(r);
        console.log(JSON.stringify(r));
      }
    }
  }
  require('fs').writeFileSync('probe-results.json', JSON.stringify(results, null, 2));
})();
