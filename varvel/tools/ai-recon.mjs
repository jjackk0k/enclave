// VARVEL — Adversarial AI Recon (authorized): fingerprint AI/LLM infrastructure.
//
// RedAmon's freshest differentiator + a natural fit for Enclave's AI-security brand.
// Given an in-scope host, it identifies AI runtimes, vector DBs, model gateways, and
// LLM frontends by their well-known ports + HTTP signatures + endpoints — the AI attack
// surface (an exposed Ollama, an open vector DB, an unauthenticated model gateway).
//
// DISCOVERY + DETECTION ONLY: non-destructive GET probes (and a benign OPTIONS). It does
// not send prompt-injection payloads or exercise the models — that would be the governed
// exploit phase / the (separate, boundary-flagged) AI-Gauntlet, not this.

import http from 'node:http';
import https from 'node:https';

// Well-known AI-infra ports → the service they usually indicate. STRONG signals only:
// an open port here is, by itself, evidence of AI infrastructure.
export const AI_PORTS = {
  11434: 'ollama', 6333: 'qdrant', 6334: 'qdrant-grpc', 8001: 'weaviate', 19530: 'milvus',
  7860: 'gradio', 8501: 'streamlit', 1234: 'lm-studio', 11235: 'localai',
};

// Generic web ports that OFTEN front AI services but prove NOTHING alone — 8080 is the
// most common non-80 web port on earth (Tomcat, proxies, dev servers), 5000 is Flask-
// anything, 3000 every Node dev server, 8000 http-alt. Probed for signatures/endpoints
// exactly like the strong ports, but the port number ALONE never flags AI:
// corroboration (a root-page hint or an endpoint signature) is required.
export const AI_PORTS_GENERIC = { 5000: 'ai-app', 8080: 'ai-gateway', 3000: 'ai-frontend', 8000: 'ai-api' };

// Signature probes: path → how to recognize an AI service from the response.
const AI_PROBES = [
  { path: '/api/tags', re: /"models"\s*:\s*\[/, cls: 'ollama', tag: 'ai-runtime', note: 'Ollama model list exposed' },
  { path: '/api/version', re: /"version"/, cls: 'ollama', tag: 'ai-runtime', note: 'Ollama version endpoint' },
  { path: '/v1/models', re: /"(object|data)"\s*:/, cls: 'openai-compatible', tag: 'ai-gateway', note: 'OpenAI-compatible /v1/models (model gateway)' },
  { path: '/collections', re: /"(result|collections|status)"/, cls: 'qdrant', tag: 'ai-vector-db', note: 'Qdrant collections endpoint' },
  { path: '/v1/.well-known/ready', re: /true|ready/i, cls: 'weaviate', tag: 'ai-vector-db', note: 'Weaviate readiness' },
  { path: '/config', re: /gradio|"components"\s*:/i, cls: 'gradio', tag: 'ai-frontend', note: 'Gradio app config' },
  { path: '/_stcore/health', re: /ok/i, cls: 'streamlit', tag: 'ai-frontend', note: 'Streamlit health' },
  { path: '/healthz', re: /ok|healthy/i, cls: 'ai-service', tag: 'ai-runtime', note: 'AI service health' },
  { path: '/docs', re: /swagger|openapi|fastapi/i, cls: 'ai-api', tag: 'ai-api', note: 'API docs (possible model API)' },
];

// Header/title hints that flag an AI service on the root page.
const AI_HINTS = [
  [/ollama/i, 'ollama'], [/gradio/i, 'gradio'], [/streamlit/i, 'streamlit'],
  [/text-generation-webui|oobabooga/i, 'text-gen-webui'], [/jupyter/i, 'jupyter'],
  [/x-ollama|x-litellm|openai-organization|anthropic-version/i, 'ai-gateway'],
];

const CAP = 4096;
function get(host, port, path, secure, timeout) {
  return new Promise((resolve) => {
    const lib = secure ? https : http;
    let body = '', done = false;
    const fin = (v) => { if (!done) { done = true; clearTimeout(t); resolve(v); } };
    const req = lib.request({ host, port, path, method: 'GET', timeout, rejectUnauthorized: false, headers: { 'user-agent': 'VARVEL-airecon', accept: '*/*' } }, (r) => {
      r.on('data', (d) => { if (body.length < CAP) body += d.toString('latin1', 0, Math.max(0, CAP - body.length)); });
      r.on('end', () => fin({ status: r.statusCode, headers: r.headers, body }));
    });
    const t = setTimeout(() => { try { req.destroy(); } catch {} fin(null); }, timeout);
    req.on('timeout', () => { try { req.destroy(); } catch {} fin(null); });
    req.on('error', () => fin(null));
    req.end();
  });
}

// Fingerprint one host:port for AI infrastructure. Returns null if nothing AI-ish.
export async function aiFingerprint(host, port, { secure = false, timeout = 1500 } = {}) {
  const detected = [];
  // 1) root page header/title hints
  const root = await get(host, port, '/', secure, timeout);
  if (root && root.status != null) {
    const hay = `${JSON.stringify(root.headers || {})} ${root.body || ''}`;
    for (const [re, cls] of AI_HINTS) if (re.test(hay)) detected.push({ cls, via: 'header/title', tag: 'ai-frontend', evidence: 'root page/headers match' });
    if (AI_PORTS[port]) detected.push({ cls: AI_PORTS[port], via: 'port', tag: 'ai-runtime', evidence: `well-known AI port ${port}` });
  } else if (AI_PORTS[port]) {
    detected.push({ cls: AI_PORTS[port], via: 'port', tag: 'ai-runtime', evidence: `well-known AI port ${port} open` });
  }
  // 2) signature endpoints (only a few, non-destructive)
  for (const p of AI_PROBES) {
    const r = await get(host, port, p.path, secure, timeout);
    if (r && r.status >= 200 && r.status < 300 && p.re.test(r.body || '')) {
      detected.push({ cls: p.cls, via: p.path, tag: p.tag, note: p.note, evidence: `${p.path} → ${p.note}`, exposure: /model|collection|tags/.test(p.path) ? 'unauthenticated AI data/endpoint exposed' : undefined });
    }
  }
  if (!detected.length) return null;
  // dedup by cls, keeping the STRONGEST evidence: a matched endpoint > header/title hint > open port.
  const rank = (d) => (d.via && d.via.startsWith('/') ? 3 : d.via === 'port' ? 1 : 2);
  const byCls = new Map();
  for (const d of detected) { const prev = byCls.get(d.cls); if (!prev || rank(d) > rank(prev)) byCls.set(d.cls, d); }
  return { host, port, secure, services: [...byCls.values()] };
}

// Scan a host across the AI-port catalog (+ any extra ports given).
export async function aiRecon(host, { ports, timeout = 1500 } = {}) {
  const list = ports && ports.length ? ports : [...Object.keys(AI_PORTS), ...Object.keys(AI_PORTS_GENERIC)].map(Number);
  const out = [];
  for (const port of list) {
    const secure = port === 443 || port === 8443;
    try { const fp = await aiFingerprint(host, port, { secure, timeout }); if (fp) out.push(fp); } catch { /* skip */ }
  }
  const findings = [];
  for (const h of out) for (const s of h.services) if (s.exposure) findings.push({ host: `${host}:${h.port}`, title: `Exposed AI infrastructure: ${s.cls} (${s.tag}) — ${s.exposure}`, sev: 'high', ref: `AI-${h.port}`, evidence: s.evidence });
  return { host, aiHosts: out, findings, scanned: list.length };
}
