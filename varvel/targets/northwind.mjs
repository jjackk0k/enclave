// VARVEL — HARD demo target: "Northwind Traders — Partner Portal".
//
// An AUTHORIZED, self-contained practice target that is deliberately HARDER than the
// Acme demo: the obvious exposures are locked down (no /.env, no /.git, security headers
// present, generic 404s), and changing content requires ACTUAL EXPLOITATION — an
// authentication bypass via SQL injection on the login, yielding an admin session that
// can rewrite the homepage. A realistic multi-step chain, not a freebie.
//
// It is a TARGET, not an exploit: the injectable query is the app's own (bad) code, the
// kind a pentest is meant to find. Everything is localhost + reversible.
//
//   node varvel/targets/northwind.mjs        # standalone on :8973 (or HARD_PORT)
//   import { createHardTarget } from './targets/northwind.mjs'

import http from 'node:http';
import { pathToFileURL } from 'node:url';
import { randomBytes } from 'node:crypto';

const DEFAULT_HEADLINE = 'Northwind Traders — global logistics, delivered.';
// A password no one guesses; the intended path in is the SQLi auth bypass, not brute force.
const ADMIN_PW = 'Nw!' + randomBytes(9).toString('base64').replace(/[^a-zA-Z0-9]/g, '') + 'X7';
const USERS = [
  { username: 'admin', password: ADMIN_PW, role: 'admin' },
  { username: 'partner', password: 'partner-portal-2024', role: 'partner' },
];

// Security headers on every response — this site is NOT missing them (harder than normal).
const SEC = { 'content-security-policy': "default-src 'self'", 'x-frame-options': 'DENY', 'x-content-type-options': 'nosniff', 'strict-transport-security': 'max-age=31536000', 'referrer-policy': 'no-referrer', server: 'nginx' };

const page = (title, body) => `<!doctype html><html><head><title>${title} · Northwind Traders</title>
<style>body{font:15px/1.6 system-ui;margin:0;color:#0f1b24;background:#f6f8fa}header{background:#0b2740;color:#fff;padding:16px 40px}
nav a{color:#bcd3e8;margin-right:18px;text-decoration:none}main{max-width:820px;margin:0 auto;padding:30px 24px}
.hero{background:#fff;border:1px solid #e2e8ee;padding:26px;border-radius:8px}label{display:block;margin:8px 0 3px}input{padding:7px;width:240px}
.btn{background:#0b2740;color:#fff;border:0;padding:8px 16px;border-radius:5px;cursor:pointer;margin-top:12px}</style></head>
<body><header><b>NORTHWIND TRADERS</b> &nbsp; <nav><a href="/">Home</a><a href="/products">Products</a><a href="/about">About</a><a href="/login">Partner login</a></nav></header>
<main>${body}</main></body></html>`;

// --- the (deliberately) injectable auth. Simulates: SELECT * FROM users WHERE
// username='<u>' AND password='<p>'  — with the classic bypasses a pentest finds. ---
function login(u, p) {
  const raw = String(u == null ? '' : u);
  const pw = String(p == null ? '' : p);
  // `admin'-- ` comments out the password check → log in as the named user.
  const dashComment = raw.match(/^([^']*)'\s*(--|#)/);
  if (dashComment) {
    const name = dashComment[1] || 'admin';
    const user = USERS.find((x) => x.username === name) || USERS.find((x) => x.role === 'admin');
    if (user) return { ok: true, user };
  }
  // `' OR '1'='1` / `' OR 1=1-- ` in either field → tautology, returns the first (admin) row.
  if (/'\s*or\s+.*(=|like)/i.test(raw + ' ' + pw)) { const admin = USERS.find((x) => x.role === 'admin'); if (admin) return { ok: true, user: admin }; }
  // an unbalanced quote produces a SQL error — a realistic tell that the field is injectable.
  const qc = (raw.match(/'/g) || []).length + (pw.match(/'/g) || []).length;
  if (qc % 2 === 1) return { ok: false, sqlError: `SQL syntax error near "${raw.slice(0, 24)}" — check the manual for your MySQL server version` };
  // otherwise a normal credential check.
  const user = USERS.find((x) => x.username === raw && x.password === pw);
  return user ? { ok: true, user } : { ok: false };
}

const PORTAL_JS = `// Northwind Partner Portal bundle
// login() posts {username,password} to /login (form-encoded).
// TODO(SEC-1421): migrate /login off the legacy raw-SQL query builder before GA — it
// concatenates the username straight into the WHERE clause. Ticket owner: dba@northwind.
// Admin content management lives at POST /admin/content {"content":"..."} (session required).
export function login(u,p){ return fetch('/login',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:'username='+encodeURIComponent(u)+'&password='+encodeURIComponent(p)}); }
`;

function parseCookies(req) {
  const out = {}; const c = req.headers.cookie || '';
  for (const kv of c.split(';')) { const i = kv.indexOf('='); if (i > 0) out[kv.slice(0, i).trim()] = kv.slice(i + 1).trim(); }
  return out;
}
const readBody = (req) => new Promise((r) => { let d = ''; req.on('data', (c) => { d += c; if (d.length > 8192) req.destroy(); }); req.on('end', () => r(d)); });

export function createHardTarget() {
  const state = { headline: DEFAULT_HEADLINE, original: DEFAULT_HEADLINE };
  const sessions = new Map(); // token -> { username, role }
  const send = (res, status, body, ct = 'text/html') => { res.writeHead(status, { 'content-type': ct, ...SEC }); res.end(body); };

  return http.createServer(async (req, res) => {
    const path = req.url.split('?')[0];
    const cookies = parseCookies(req);
    const sess = cookies.sid ? sessions.get(cookies.sid) : null;

    // locked-down: the obvious exposures return a clean 404 (not present).
    if (/^\/(\.env|\.git|\.aws|backup|config\.json|wp-config)/.test(path)) return send(res, 404, page('Not found', '<h1>404</h1>'));

    if (path === '/' || path === '') return send(res, 200, page('Home', `<div class="hero"><h1>${state.headline}</h1><p>Freight, warehousing, and last-mile across 40 countries.</p></div><h2>Partners</h2><p>Existing partners: <a href="/login">sign in to the portal</a>.</p>`));
    if (path === '/products') return send(res, 200, page('Products', '<h1>Services</h1><p>FTL/LTL freight, cold-chain, customs brokerage.</p>'));
    if (path === '/about') return send(res, 200, page('About', '<h1>About</h1><p>Northwind Traders, since 1996.</p>'));
    if (path === '/assets/portal.js') return send(res, 200, PORTAL_JS, 'application/javascript');
    if (path === '/api/health') return send(res, 200, '{"status":"ok"}', 'application/json');
    if (path === '/robots.txt') return send(res, 200, 'User-agent: *\nDisallow: /admin\n', 'text/plain');
    if (path === '/.well-known/security.txt') return send(res, 200, 'Contact: mailto:security@northwind.example\n', 'text/plain');

    if (path === '/login') {
      if (req.method === 'GET') return send(res, 200, page('Partner login', '<h1>Partner login</h1><form method="POST" action="/login"><label>Username</label><input name="username"><label>Password</label><input name="password" type="password"><button class="btn">Sign in</button></form><p style="color:#8a97a3">Trouble? See <a href="/assets/portal.js">portal.js</a>.</p>'));
      if (req.method === 'POST') {
        const body = await readBody(req); const params = new URLSearchParams(body);
        const r = login(params.get('username'), params.get('password'));
        if (r.ok) {
          const token = randomBytes(16).toString('hex'); sessions.set(token, { username: r.user.username, role: r.user.role });
          res.writeHead(302, { 'set-cookie': `sid=${token}; HttpOnly; Path=/`, location: '/portal', ...SEC }); return res.end();
        }
        if (r.sqlError) return send(res, 500, page('Error', `<h1>Server error</h1><pre>${r.sqlError}</pre>`)); // realistic verbose-error leak
        return send(res, 401, page('Partner login', '<h1>Partner login</h1><p style="color:#b00">Invalid credentials.</p><form method="POST" action="/login"><label>Username</label><input name="username"><label>Password</label><input name="password" type="password"><button class="btn">Sign in</button></form>'));
      }
    }

    if (path === '/portal') {
      if (!sess) { res.writeHead(302, { location: '/login', ...SEC }); return res.end(); }
      return send(res, 200, page('Portal', `<h1>Partner portal</h1><p>Signed in as <b>${sess.username}</b> (${sess.role}).</p>${sess.role === 'admin' ? '<p><a href="/admin/content">Content management</a> (admin)</p>' : '<p>Standard partner access.</p>'}`));
    }

    // The "change something" surface — requires an ADMIN session (reached via the SQLi bypass).
    if (path === '/admin/content') {
      if (!sess || sess.role !== 'admin') return send(res, 403, page('Forbidden', '<h1>403</h1><p>Admin session required.</p>'));
      if (req.method === 'GET') return send(res, 200, page('Content', `<h1>Homepage content</h1><p>Current: <b>${state.headline}</b></p><p>POST JSON {"content":"..."} here to update it.</p>`));
      if (req.method === 'POST') {
        const body = await readBody(req); let content;
        try { content = JSON.parse(body).content; } catch { content = new URLSearchParams(body).get('content'); }
        if (typeof content !== 'string') return send(res, 400, '{"error":"content (string) required"}', 'application/json');
        const previous = state.headline; state.headline = content.slice(0, 200);
        return send(res, 200, JSON.stringify({ ok: true, previous, headline: state.headline, revert: { content: state.original } }), 'application/json');
      }
    }

    return send(res, 404, page('Not found', '<h1>404</h1>'));
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const port = Number(process.env.HARD_PORT || 8973);
  createHardTarget().listen(port, () => console.log(`Northwind (HARD) target on http://localhost:${port}  — breach via SQLi auth bypass -> admin -> POST /admin/content`));
}
