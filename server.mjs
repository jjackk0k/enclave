#!/usr/bin/env node
// server.mjs — run the Enclave console LIVE:  node server.mjs
//
// Serves the console (index.html / app.html) on localhost AND acts as the egress
// broker for the chat: the browser sends messages with NO key; this server injects
// the Anthropic key (from the environment) and calls Claude. The key never reaches
// the browser — same pattern as poc/egress-broker, wired to the real UI.
//
//   ANTHROPIC_API_KEY=sk-ant-…  node server.mjs      # live AI
//   node server.mjs                                  # no key -> console stays scripted

import http from 'node:http';
import https from 'node:https';
import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, extname, normalize } from 'node:path';

const ROOT = dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT) || 8977;
const MODEL = process.env.ENCLAVE_MODEL || 'claude-sonnet-5';
const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.svg': 'image/svg+xml', '.md': 'text/markdown' };

const send = (res, code, body, type = 'application/json') => { res.writeHead(code, { 'content-type': type }); res.end(body); };

// The broker hop: inject the key server-side and forward to Claude. The only host
// this server will egress to is api.anthropic.com; the key is never returned.
function callClaude({ system, messages }) {
  return new Promise((resolve, reject) => {
    const key = process.env.ANTHROPIC_API_KEY;
    if (!key) return reject(Object.assign(new Error('no ANTHROPIC_API_KEY set on the server'), { code: 'NO_KEY' }));
    const payload = JSON.stringify({ model: MODEL, max_tokens: 1024, system, messages });
    const req = https.request({ hostname: 'api.anthropic.com', path: '/v1/messages', method: 'POST',
      headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload), 'x-api-key': key, 'anthropic-version': '2023-06-01' } },
      r => { let b = ''; r.on('data', c => (b += c)); r.on('end', () => { try { const j = JSON.parse(b); if (j.error) return reject(new Error(j.error.message || 'api error')); resolve((j.content || []).map(x => x.text).filter(Boolean).join('\n')); } catch (e) { reject(e); } }); });
    req.on('error', reject); req.write(payload); req.end();
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');

  if (url.pathname === '/api/health') {
    return send(res, 200, JSON.stringify({ live: true, keyPresent: !!process.env.ANTHROPIC_API_KEY, model: MODEL }));
  }
  if (url.pathname === '/api/chat' && req.method === 'POST') {
    let body = '';
    req.on('data', c => (body += c));
    req.on('end', async () => {
      try {
        const { system, messages } = JSON.parse(body || '{}');
        if (!Array.isArray(messages) || !messages.length) return send(res, 400, JSON.stringify({ error: 'no messages' }));
        const text = await callClaude({ system, messages });
        console.log(`[chat] ${messages.length} msgs -> ${text.length}b`);
        send(res, 200, JSON.stringify({ text }));
      } catch (e) { send(res, e.code === 'NO_KEY' ? 400 : 502, JSON.stringify({ error: e.message, code: e.code || 'ERR' })); }
    });
    return;
  }

  // static files (repo root), path-traversal guarded
  const p = url.pathname === '/' ? '/index.html' : url.pathname;
  const filePath = normalize(join(ROOT, decodeURIComponent(p)));
  if (!filePath.startsWith(ROOT)) return send(res, 403, 'forbidden', 'text/plain');
  if (!existsSync(filePath)) return send(res, 404, 'not found', 'text/plain');
  try { send(res, 200, await readFile(filePath), MIME[extname(filePath)] || 'application/octet-stream'); }
  catch { send(res, 500, 'error', 'text/plain'); }
});

server.listen(PORT, '127.0.0.1', () => {
  const key = process.env.ANTHROPIC_API_KEY ? 'present ✓' : 'NOT set — console stays scripted';
  console.log(`Enclave console live at http://localhost:${PORT}`);
  console.log(`  model: ${MODEL}   ·   ANTHROPIC_API_KEY: ${key}`);
});
