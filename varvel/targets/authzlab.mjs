// VARVEL — authzlab: the planted TWO-ACCOUNT AUTHORIZATION garden (Build 1 proof lane).
//
// An AUTHORIZED, self-contained practice target (localhost only) for calibrating the
// two-account authorization oracle (tools/authzsweep.mjs). Two provisioned accounts on
// DISTINCT tenants (alice/tenant-a, bob/tenant-b) own distinct objects; the vulnerable
// surface checks AUTHENTICATION but never OWNERSHIP, and the clean control surface
// under /api/safe/* enforces every one of those checks. Shapes planted:
//
//   A1 GET    /api/documents/<id>   cross-tenant READ (auth checked, ownership not)
//   A2 PATCH  /api/documents/<id>   cross-tenant WRITE (title field, no ownership check)
//   A3 DELETE /api/documents/<id>   cross-tenant DELETE (no ownership check)
//   A4 GET    /api/users/<pid>      cross-tenant PROFILE read (role/email/tenant leak)
//   A5 PATCH  /api/users/<pid>      MASS ASSIGNMENT: no field whitelist — role/email/
//                                 password persist straight onto the profile (the
//                                 Synack-class IDOR→ATO escalation)
//   P1 GET    /api/documents/PUB-1  PUBLIC decoy: 200 unauth, identical body — the
//                                 shape naive scanners flag and the control kills
//   S1..S5    /api/safe/*           the ENFORCED mirror family. /api/safe/users/<pid>
//                                 PATCH is the mass-assignment DECOY: accepts extra
//                                 fields (200) but IGNORES them — only a readback
//                                 oracle clears it.
//
// Run:  node varvel/targets/authzlab.mjs    # standalone on :8973 (or AUTHZLAB_PORT)
//   import { createAuthzlabTarget } from '../targets/authzlab.mjs'   # tests/lab

import http from 'node:http';
import { randomBytes } from 'node:crypto';
import { pathToFileURL } from 'node:url';

export const AUTHZ_CANARY = 'AUTHZ-CANARY-5c2f1a';
export const TENANT_A = { user: 'alice', pass: 'alice-demo-2026', profileId: 'USR-A1' };
export const TENANT_B = { user: 'bob', pass: 'bob-demo-2026', profileId: 'USR-B1' };

const readBody = (req, cap = 4096) => new Promise((resolve) => {
  let b = ''; req.on('data', (c) => { b += c; if (b.length > cap) req.destroy(); });
  req.on('end', () => resolve(b));
});

function freshState() {
  return {
    users: {
      alice: { pass: TENANT_A.pass, profileId: TENANT_A.profileId, role: 'user', email: 'alice@tenant-a.example', tenant: 'tenant-a', displayName: 'Alice' },
      bob: { pass: TENANT_B.pass, profileId: TENANT_B.profileId, role: 'user', email: 'bob@tenant-b.example', tenant: 'tenant-b', displayName: 'Bob' },
    },
    docs: {
      'DOC-A1': { id: 'DOC-A1', owner: 'alice', tenant: 'tenant-a', title: 'Alice lease agreement', body: 'tenant-a confidential: lease terms', marker: AUTHZ_CANARY },
      'DOC-B1': { id: 'DOC-B1', owner: 'bob', tenant: 'tenant-b', title: 'Bob payroll export', body: 'tenant-b confidential: payroll PII', marker: AUTHZ_CANARY },
      'PUB-1': { id: 'PUB-1', public: true, title: 'Public brochure', body: 'public marketing copy' },
    },
    safeDocs: {
      'SDOC-A1': { id: 'SDOC-A1', owner: 'alice', tenant: 'tenant-a', title: 'Alice safe notes', body: 'enforced tenant-a data' },
      'SDOC-B1': { id: 'SDOC-B1', owner: 'bob', tenant: 'tenant-b', title: 'Bob safe notes', body: 'enforced tenant-b data' },
    },
  };
}

export function createAuthzlabTarget() {
  let state = freshState();
  const sessions = new Map(); // sid -> user (survives /lab/revert: fixture resets must not kill probing sessions)

  const json = (res, status, obj) => {
    res.writeHead(status, { 'content-type': 'application/json' });
    res.end(JSON.stringify(obj));
  };
  const profile = (u) => ({ profileId: u.profileId, role: u.role, email: u.email, tenant: u.tenant, displayName: u.displayName, marker: AUTHZ_CANARY });
  const byProfileId = (pid) => Object.entries(state.users).find(([, u]) => u.profileId === pid);

  return http.createServer(async (req, res) => {
    const u = new URL(req.url, 'http://localhost');
    const path = u.pathname;
    const me = () => {
      const sid = (req.headers.cookie || '').split(';').map((s) => s.trim()).find((s) => s.startsWith('az_sess='));
      return (sid && sessions.get(sid.slice(8))) || null;
    };

    // --- lab hygiene: restore planted state (sessions survive on purpose) ----------
    if (path === '/lab/revert' && req.method === 'POST') {
      state = freshState();
      return json(res, 200, { ok: true, reverted: true });
    }

    // --- identity ------------------------------------------------------------------
    if (path === '/login' && req.method === 'POST') {
      const b = new URLSearchParams(await readBody(req));
      const usr = state.users[b.get('user')];
      if (!usr || usr.pass !== b.get('pass')) return json(res, 403, { error: 'bad credentials' });
      const sid = 'sess_' + randomBytes(6).toString('hex');
      sessions.set(sid, b.get('user'));
      res.writeHead(200, { 'content-type': 'application/json', 'set-cookie': `az_sess=${sid}; Path=/; SameSite=Strict; HttpOnly` });
      return res.end(JSON.stringify({ ok: true, user: b.get('user') }));
    }
    if (path === '/api/me') {
      const user = me();
      if (!user) return json(res, 401, { error: 'authentication required' });
      return json(res, 200, { user, ...profile(state.users[user]) });
    }

    // === vulnerable surface (authentication checked, OWNERSHIP never) ================

    // harvest source: the caller's own document index (+ the public doc reference)
    if (path === '/api/documents' && req.method === 'GET') {
      const user = me(); if (!user) return json(res, 401, { error: 'authentication required' });
      const own = Object.values(state.docs).filter((d) => d.owner === user).map((d) => ({ id: d.id, title: d.title }));
      return json(res, 200, { documents: own, public: [{ id: 'PUB-1', title: state.docs['PUB-1'].title }], marker: AUTHZ_CANARY });
    }
    let m = /^\/api\/documents\/([\w-]+)$/.exec(path);
    if (m && !path.startsWith('/api/safe/')) {
      const doc = state.docs[m[1]];
      if (!doc) return json(res, 404, { error: 'not found' });
      if (req.method === 'GET') { // A1 / P1: public doc readable by anyone; the rest auth-only, NO ownership check
        if (doc.public) return json(res, 200, doc);
        const user = me(); if (!user) return json(res, 401, { error: 'authentication required' });
        return json(res, 200, doc); // <-- planted bug: no doc.owner === user check
      }
      const user = me(); if (!user) return json(res, 401, { error: 'authentication required' });
      if (doc.public) return json(res, 403, { error: 'public document is read-only' });
      if (req.method === 'PATCH') { // A2: cross-tenant WRITE — no ownership check
        const b = JSON.parse((await readBody(req)) || '{}');
        if (typeof b.title === 'string') doc.title = b.title;
        return json(res, 200, { ok: true, id: doc.id, title: doc.title, marker: AUTHZ_CANARY }); // <-- planted bug
      }
      if (req.method === 'DELETE') { // A3: cross-tenant DELETE — no ownership check
        delete state.docs[doc.id];
        return json(res, 200, { ok: true, deleted: doc.id, marker: AUTHZ_CANARY }); // <-- planted bug
      }
      return json(res, 405, { error: 'method not allowed' });
    }

    // A4/A5: profile objects keyed by opaque profileId (the mass-assignment garden)
    m = /^\/api\/users\/([\w-]+)$/.exec(path);
    if (m && !path.startsWith('/api/safe/')) {
      const user = me(); if (!user) return json(res, 401, { error: 'authentication required' });
      const hit = byProfileId(m[1]);
      if (!hit) return json(res, 404, { error: 'not found' });
      const [, target] = hit;
      if (req.method === 'GET') {
        // <-- planted bug: any tenant reads any profile; and because the handler binds
        // EVERYTHING (see PATCH), the read exposes everything assigned — extras included.
        const full = { ...target }; delete full.pass; full.marker = AUTHZ_CANARY;
        return json(res, 200, full);
      }
      if (req.method === 'PATCH') {
        const b = JSON.parse((await readBody(req)) || '{}');
        for (const [k, v] of Object.entries(b)) { // <-- planted bug: NO whitelist — role/email/password persist
          if (k === 'pass' || k === 'password') target.pass = String(v);
          else if (k !== 'profileId' && typeof v !== 'object') target[k] = v;
        }
        return json(res, 200, { ok: true, ...profile(target) });
      }
      return json(res, 405, { error: 'method not allowed' });
    }

    // === clean control surface: same intent, every check ENFORCED ====================

    if (path === '/api/safe/documents' && req.method === 'GET') {
      const user = me(); if (!user) return json(res, 401, { error: 'authentication required' });
      const own = Object.values(state.safeDocs).filter((d) => d.owner === user).map((d) => ({ id: d.id, title: d.title }));
      return json(res, 200, { documents: own });
    }
    m = /^\/api\/safe\/documents\/([\w-]+)$/.exec(path);
    if (m) {
      const user = me(); if (!user) return json(res, 401, { error: 'authentication required' });
      const doc = state.safeDocs[m[1]];
      if (!doc || doc.owner !== user) return json(res, 404, { error: 'not found' }); // enforced: cross-tenant indistinguishable from a miss
      if (req.method === 'GET') return json(res, 200, doc);
      if (req.method === 'PATCH') {
        const b = JSON.parse((await readBody(req)) || '{}');
        if (typeof b.title === 'string') doc.title = b.title;
        return json(res, 200, { ok: true, id: doc.id, title: doc.title });
      }
      if (req.method === 'DELETE') { delete state.safeDocs[doc.id]; return json(res, 200, { ok: true, deleted: doc.id }); }
      return json(res, 405, { error: 'method not allowed' });
    }

    m = /^\/api\/safe\/users\/([\w-]+)$/.exec(path);
    if (m) {
      const user = me(); if (!user) return json(res, 401, { error: 'authentication required' });
      const hit = byProfileId(m[1]);
      if (!hit || hit[0] !== user) return json(res, 404, { error: 'not found' }); // enforced ownership
      const [, target] = hit;
      if (req.method === 'GET') return json(res, 200, profile(target));
      if (req.method === 'PATCH') { // DECOY: accepts extra fields (200) but IGNORES them — whitelist enforced
        const b = JSON.parse((await readBody(req)) || '{}');
        if (typeof b.displayName === 'string') target.displayName = b.displayName;
        return json(res, 200, { ok: true, ...profile(target) }); // 200 either way — status cannot see the enforcement
      }
      return json(res, 405, { error: 'method not allowed' });
    }

    if (path === '/' || path === '') {
      res.writeHead(200, { 'content-type': 'text/html' });
      return res.end('<!doctype html><title>Authzlab</title><h1>Authzlab two-account garden</h1><p>Two tenants (alice/bob), object APIs under /api/*, enforced mirror under /api/safe/*.</p>');
    }
    res.writeHead(404, { 'content-type': 'application/json' });
    res.end('{"error":"not found"}');
  });
}

// standalone (robust across Windows file:// vs file:/// normalization)
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const port = Number(process.env.AUTHZLAB_PORT || 8973);
  createAuthzlabTarget().listen(port, '127.0.0.1', () => console.log(`Authzlab two-account garden on http://127.0.0.1:${port}`));
}
