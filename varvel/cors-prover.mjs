import https from 'node:https';

const targets = [
  { host: 'app.moderntreasury.com', paths: ['/api/users', '/dashboard', '/admin', '/openapi.json'] },
  { host: 'cdn.moderntreasury.com', paths: ['/'] },
];

function probe(host, path) {
  return new Promise((resolve) => {
    const req = https.request({ hostname: host, path, method: 'GET', headers: { 'Origin': 'https://attacker.invalid' } }, (res) => {
      let body = '';
      res.on('data', (d) => { body += d; });
      res.on('end', () => {
        resolve({
          host,
          path,
          status: res.statusCode,
          acao: res.headers['access-control-allow-origin'],
          acac: res.headers['access-control-allow-credentials'],
          body: body.slice(0, 4096),
        });
      });
    });
    req.on('error', (e) => resolve({ host, path, error: e.message }));
    req.end();
  });
}

(async () => {
  for (const t of targets) {
    for (const p of t.paths) {
      const r = await probe(t.host, p);
      console.log(JSON.stringify(r));
    }
  }
})();
