// VARVEL — demo target: "Acme Robotics" corporate site.
//
// An AUTHORIZED, self-contained test target (localhost only) for exercising VARVEL's
// recon/discovery tooling. It looks like an ordinary small-company site but carries
// the realistic exposures a sloppy real deployment leaks — an exposed .git repo, an
// .env secrets file, a backup directory listing with a DB dump, an unauth admin
// panel, an over-permissive CORS API, and missing security headers. Nothing here is
// an exploit; it is a deliberately-imperfect *target* so we can prove the scanner
// finds what a real one would.
//
//   node varvel/targets/demo-corp.mjs        # standalone on :8972 (or DEMO_PORT)
//   import { createDemoTarget } from './targets/demo-corp.mjs'  # for tests

import http from 'node:http';
import { pathToFileURL } from 'node:url';

const page = (title, body) => `<!doctype html><html><head><title>${title} · Acme Robotics</title>
<!-- TODO(devops): rotate the staging creds in /.env before the public launch. also kill /backup listing. -->
<style>body{font:15px/1.6 system-ui;margin:0;color:#12202b}header{background:#0d1b2a;color:#fff;padding:18px 40px}
nav a{color:#cfe3ff;margin-right:18px;text-decoration:none}main{max-width:820px;margin:0 auto;padding:32px 24px}
.hero{background:#f0f5fa;padding:28px;border-radius:8px}footer{color:#5b6b78;padding:24px 40px;border-top:1px solid #e2e8ee}</style></head>
<body><header><b>ACME ROBOTICS</b> &nbsp; <nav><a href="/">Home</a><a href="/products">Products</a><a href="/about">About</a><a href="/careers">Careers</a><a href="/admin">Portal</a></nav></header>
<main>${body}</main><footer>© Acme Robotics Inc. · <a href="/.well-known/security.txt">security.txt</a></footer></body></html>`;

const DEFAULT_BANNER = 'Industrial automation, done right.';

const ROUTES = {
  '/products': () => ({ status: 200, body: page('Products', '<h1>Products</h1><p>R-9 actuator, X-series controllers, the Acme Fleet dashboard.</p>') }),
  '/about': () => ({ status: 200, body: page('About', '<h1>About</h1><p>Founded 2009. 400 people. HQ in Portland.</p>') }),
  '/careers': () => ({ status: 200, body: page('Careers', '<h1>Careers</h1><p>We\'re hiring backend + controls engineers.</p>') }),

  // --- realistic exposures a real sloppy deploy leaks (what VARVEL should find) ---
  '/robots.txt': () => ({ status: 200, ct: 'text/plain', body: 'User-agent: *\nDisallow: /admin\nDisallow: /backup\nDisallow: /internal\nDisallow: /.git\n' }),
  '/.git/HEAD': () => ({ status: 200, ct: 'text/plain', body: 'ref: refs/heads/main\n' }),
  '/.git/config': () => ({ status: 200, ct: 'text/plain', body: '[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = git@github.com:acme-robotics/site.git\n' }),
  '/.env': () => ({ status: 200, ct: 'text/plain', body: 'APP_ENV=production\nDB_HOST=10.0.5.20\nDB_USER=acme_app\nDB_PASSWORD=S3cr3t-Staging-2024!\nSTRIPE_KEY=sk_live_51Hxxxxx\nJWT_SECRET=change-me-please\n' }),
  '/config.json': () => ({ status: 200, ct: 'application/json', body: JSON.stringify({ app: 'acme-site', debug: false, adminToken: 'tok_9f2a1c', internalApi: 'http://10.0.5.30/api' }, null, 2) }),
  '/backup/': () => ({ status: 200, body: '<html><head><title>Index of /backup</title></head><body><h1>Index of /backup</h1><pre><a href="../">../</a>\n<a href="db.sql">db.sql</a>            2024-09-11 03:14   4.2M\n<a href="site.tar.gz">site.tar.gz</a>       2024-09-11 03:14   18M</pre></body></html>' }),
  '/backup/db.sql': () => ({ status: 200, ct: 'application/sql', body: '-- MySQL dump\nINSERT INTO users VALUES (1,\'admin\',\'$2y$10$abcdef...\',\'admin@acme.example\');\n' }),
  // The portal page leaks its own content API in a comment — a realistic breadcrumb to
  // the broken-access-control write below (no auth on POST /admin/api/banner).
  '/admin': () => ({ status: 200, body: page('Portal', '<h1>Employee Portal</h1><!-- content API: GET/POST /admin/api/banner {"banner": "..."} — TODO: require auth before launch -->\n<form><label>User <input name=u></label> <label>Pass <input type=password name=p></label> <button>Sign in</button></form><p style="color:#888">v2.3.1 — build 4471</p>') }),
  '/.well-known/security.txt': () => ({ status: 200, ct: 'text/plain', body: 'Contact: mailto:security@acme.example\n' }),
};

// /api/* leaks user data and reflects any Origin with credentials (CORS hole).
function apiHandler(req, res) {
  const origin = req.headers.origin;
  const h = { 'content-type': 'application/json' };
  if (origin) { h['access-control-allow-origin'] = origin; h['access-control-allow-credentials'] = 'true'; }
  if (req.url === '/api/users') { res.writeHead(200, h); return res.end(JSON.stringify([{ id: 1, user: 'admin', email: 'admin@acme.example', role: 'superuser' }, { id: 2, user: 'jdoe', email: 'jdoe@acme.example', role: 'staff' }])); }
  res.writeHead(200, h); res.end('{"ok":true}');
}

export function createDemoTarget() {
  // Per-instance mutable state so a breach can PROVE impact by changing site content —
  // and cleanly revert it. `original` is what a cleanup restores.
  const state = { banner: DEFAULT_BANNER, original: DEFAULT_BANNER };
  const home = () => page('Home', `<div class="hero"><h1>${state.banner}</h1><p>Acme Robotics builds the arms behind the world's factories.</p></div><h2>Latest</h2><ul><li>Q3 fulfillment up 40%</li><li>New R-9 actuator line ships</li></ul>`);

  return http.createServer((req, res) => {
    const path = req.url.split('?')[0];

    // --- broken access control: unauthenticated content write (the "change something"
    // surface). GET reads the banner; POST/PUT changes it with NO auth check. A benign,
    // reversible way to prove write access on an authorized engagement.
    if (path === '/admin/api/banner') {
      if (req.method === 'GET') { res.writeHead(200, { 'content-type': 'application/json' }); return res.end(JSON.stringify({ banner: state.banner, original: state.original, modified: state.banner !== state.original })); }
      if (req.method === 'POST' || req.method === 'PUT') {
        let b = ''; req.on('data', (c) => { b += c; if (b.length > 4096) req.destroy(); });
        req.on('end', () => {
          let banner; try { banner = JSON.parse(b || '{}').banner; } catch {}
          if (typeof banner !== 'string') { res.writeHead(400, { 'content-type': 'application/json' }); return res.end('{"error":"banner (string) required"}'); }
          const previous = state.banner; state.banner = banner.slice(0, 200);
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ ok: true, previous, banner: state.banner, revert: { method: 'POST', path: '/admin/api/banner', body: { banner: state.original } } }));
        });
        return;
      }
      res.writeHead(405, { 'content-type': 'application/json', allow: 'GET, POST, PUT' }); return res.end('{"error":"method not allowed"}');
    }

    if (path === '/' || path === '') { res.writeHead(200, { 'content-type': 'text/html', server: 'nginx/1.18.0' }); return res.end(home()); }
    if (path.startsWith('/api/')) return apiHandler(req, res);
    const r = ROUTES[path];
    if (!r) { res.writeHead(404, { 'content-type': 'text/html' }); return res.end(page('Not found', '<h1>404</h1>')); }
    const out = r();
    // NOTE: no Content-Security-Policy, X-Frame-Options, or HSTS -> VARVEL flags the gaps.
    res.writeHead(out.status, { 'content-type': out.ct || 'text/html', server: 'nginx/1.18.0' });
    res.end(out.body);
  });
}

// standalone (robust across Windows file:// vs file:/// normalization)
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const port = Number(process.env.DEMO_PORT || 8972);
  createDemoTarget().listen(port, () => console.log(`Acme Robotics demo target on http://localhost:${port}`));
}
