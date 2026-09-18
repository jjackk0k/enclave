// VARVEL — MCP (Model Context Protocol) JSON-RPC 2.0 core. PURE: no I/O, no clock,
// no globals — every function takes its inputs and returns a value, so the whole
// protocol layer is unit-testable without a process.
//
// MCP stdio transport (per the MCP spec, "stdio" transport): messages are
// newline-delimited JSON — ONE JSON-RPC message per line, UTF-8, no embedded
// newlines. (The Content-Length header framing belongs to LSP, NOT to MCP stdio;
// implementing header framing here would be a spec violation, so we don't.)
//
// Scope of this module: framing (encode/decode), message validation, the method
// router, the initialize handshake (protocol-version negotiation), and the
// tools/list + tools/call result shapes. Governance of what a tool call MAY do
// lives in engine/mcpgov.mjs — this file just moves well-formed messages.

// Pinned protocol identity. 2025-06-18 is the documented revision VARVEL speaks
// natively (structuredContent on tool results, title fields); the two earlier
// dated revisions are accepted for older clients (their tool-result shape is a
// subset — plain `content` blocks — which we always emit anyway).
export const MCP_PROTOCOL_VERSION = '2025-06-18';
export const SUPPORTED_PROTOCOL_VERSIONS = ['2025-06-18', '2025-03-26', '2024-11-05'];

// JSON-RPC 2.0 error codes (the only codes MCP defines at the transport layer).
export const RPC = {
  PARSE_ERROR: -32700,      // malformed JSON
  INVALID_REQUEST: -32600,  // valid JSON, not a valid JSON-RPC message
  METHOD_NOT_FOUND: -32601, // method unknown
  INVALID_PARAMS: -32602,   // params fail the method's expectations (incl. unknown tool)
  INTERNAL_ERROR: -32603,   // handler threw
};

const MAX_FRAME_BYTES = 1 << 20; // 1 MiB per message — generous for tool args, stops a runaway peer

// ── framing ─────────────────────────────────────────────────────────────────

// One message -> one wire line (JSON + '\n'). Throws only on a non-object message
// (a programming error on OUR side — peers can never reach this).
export function encodeMessage(msg) {
  if (!msg || typeof msg !== 'object' || Array.isArray(msg)) throw new TypeError('MCP message must be an object');
  return JSON.stringify(msg) + '\n';
}

// Parse ONE wire line into a message. Never throws: returns
//   { msg }                       — parsed (shape NOT yet validated; see validateMessage)
//   { error: {code,message}, raw } — unparseable
export function parseFrame(line) {
  const raw = String(line == null ? '' : line);
  const trimmed = raw.trim();
  if (!trimmed) return { error: null, raw, empty: true }; // blank lines are ignored by the decoder, never an error
  let msg;
  try { msg = JSON.parse(trimmed); }
  catch { return { error: { code: RPC.PARSE_ERROR, message: 'Parse error: line is not valid JSON' }, raw }; }
  if (Array.isArray(msg)) {
    // MCP does not use JSON-RPC batching — say so plainly instead of half-serving it.
    return { error: { code: RPC.INVALID_REQUEST, message: 'Invalid Request: JSON-RPC batches are not part of MCP' }, raw };
  }
  if (!msg || typeof msg !== 'object') {
    return { error: { code: RPC.INVALID_REQUEST, message: 'Invalid Request: message must be a JSON object' }, raw };
  }
  return { msg, raw };
}

// Byte/stream decoder: push arbitrary chunks, get whole messages out. Newline
// framing means a chunk can split a message anywhere; the decoder holds the
// partial tail. Oversized frames are an error (and the buffer is dropped), never
// a memory sink. `onMessage(msg, raw)` receives parsed messages; `onError(err, raw)`
// receives {code,message} for bad frames — both already shaped for errorResponse().
export function createFrameDecoder({ onMessage, onError, maxBytes = MAX_FRAME_BYTES } = {}) {
  let buf = '';
  const fire = (line) => {
    const r = parseFrame(line);
    if (r.empty) return;
    if (r.error) { try { onError && onError(r.error, r.raw); } catch { /* tap must never break the loop */ } }
    else { try { onMessage && onMessage(r.msg, r.raw); } catch { /* same */ } }
  };
  return {
    push(chunk) {
      buf += typeof chunk === 'string' ? chunk : chunk.toString('utf8');
      let i;
      while ((i = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, i).replace(/\r$/, '');
        buf = buf.slice(i + 1);
        if (line.length > maxBytes) { try { onError && onError({ code: RPC.INVALID_REQUEST, message: 'Invalid Request: frame exceeds ' + maxBytes + ' bytes' }, ''); } catch { /* */ } continue; }
        fire(line);
      }
      if (buf.length > maxBytes) { // a frame with no newline that already exceeds the cap
        try { onError && onError({ code: RPC.INVALID_REQUEST, message: 'Invalid Request: frame exceeds ' + maxBytes + ' bytes' }, ''); } catch { /* */ }
        buf = '';
      }
    },
    // Half-open stream ended: flush anything buffered (a final unterminated line still counts).
    end() { if (buf.trim()) fire(buf.replace(/\r$/, '')); buf = ''; },
    pendingBytes() { return buf.length; },
  };
}

// ── message shape ───────────────────────────────────────────────────────────

// Classify a parsed message: request (has id + method), notification (method, no id),
// response (id + result/error — we route only requests/notifications; a response
// arriving at a server is reported so the caller can ignore it explicitly).
export function validateMessage(msg) {
  if (!msg || typeof msg !== 'object' || Array.isArray(msg)) return { kind: 'invalid', error: { code: RPC.INVALID_REQUEST, message: 'Invalid Request: not an object' } };
  if (msg.jsonrpc !== '2.0') return { kind: 'invalid', id: msg.id ?? null, error: { code: RPC.INVALID_REQUEST, message: 'Invalid Request: jsonrpc must be "2.0"' } };
  if (msg.method !== undefined) {
    if (typeof msg.method !== 'string' || !msg.method) return { kind: 'invalid', id: msg.id ?? null, error: { code: RPC.INVALID_REQUEST, message: 'Invalid Request: method must be a non-empty string' } };
    const hasId = Object.prototype.hasOwnProperty.call(msg, 'id');
    if (!hasId || msg.id === null) return { kind: 'notification', method: msg.method, params: msg.params };
    if (!['string', 'number'].includes(typeof msg.id)) return { kind: 'invalid', id: null, error: { code: RPC.INVALID_REQUEST, message: 'Invalid Request: id must be a string or number' } };
    return { kind: 'request', id: msg.id, method: msg.method, params: msg.params };
  }
  if (msg.result !== undefined || msg.error !== undefined) return { kind: 'response', id: msg.id ?? null };
  return { kind: 'invalid', id: msg.id ?? null, error: { code: RPC.INVALID_REQUEST, message: 'Invalid Request: no method, result, or error' } };
}

export function resultResponse(id, result) {
  return { jsonrpc: '2.0', id, result: result === undefined ? {} : result };
}

export function errorResponse(id, code, message, data) {
  const err = { code, message: String(message || 'error') };
  if (data !== undefined) err.data = data;
  return { jsonrpc: '2.0', id: id === undefined ? null : id, error: err };
}

// Throw this inside a handler to answer with a specific JSON-RPC error (instead of
// the generic INTERNAL_ERROR a plain Error becomes).
export function rpcError(code, message, data) {
  const e = new Error(String(message));
  e.rpcCode = code;
  if (data !== undefined) e.rpcData = data;
  return e;
}

// ── initialize handshake ────────────────────────────────────────────────────

// Version negotiation per the MCP spec: if the client's requested revision is one
// we support, echo it; otherwise answer with OUR preferred revision — the client
// then decides whether it can continue (and disconnects if not). Never throws.
export function negotiateVersion(clientVersion) {
  const v = String(clientVersion || '');
  return SUPPORTED_PROTOCOL_VERSIONS.includes(v) ? v : MCP_PROTOCOL_VERSION;
}

// The initialize RESULT object. `capabilities` is the server's declared surface —
// VARVEL speaks tools only (no resources/prompts this wave), so that is all we claim.
export function initializeResult({ clientVersion, serverName = 'varvel-mcp', serverVersion = '0.1.0', instructions } = {}) {
  const result = {
    protocolVersion: negotiateVersion(clientVersion),
    capabilities: { tools: { listChanged: false } },
    serverInfo: { name: serverName, version: serverVersion },
  };
  if (instructions) result.instructions = String(instructions);
  return result;
}

// ── the router ──────────────────────────────────────────────────────────────

// A method router shaped for MCP servers. `handlers` maps method -> async
// (params, ctx) => result; throw rpcError(...) for a specific JSON-RPC error, any
// other throw becomes INTERNAL_ERROR (the loop never dies on a handler failure).
// `onNotification(method, params, ctx)` taps notifications (initialized/cancelled).
// Returns async (msg, ctx) => responseObject | null  — null for notifications and
// for responses-addressed-to-us (nothing to send back).
export function createRouter({ handlers = {}, onNotification } = {}) {
  return async function route(msg, ctx) {
    const v = validateMessage(msg);
    if (v.kind === 'invalid') return errorResponse(v.id, v.error.code, v.error.message);
    if (v.kind === 'response') return null; // we are a server; a stray response needs no answer
    if (v.kind === 'notification') {
      if (typeof onNotification === 'function') { try { onNotification(v.method, v.params, ctx); } catch { /* tap never breaks the loop */ } }
      return null;
    }
    const handler = handlers[v.method];
    if (typeof handler !== 'function') return errorResponse(v.id, RPC.METHOD_NOT_FOUND, 'Method not found: ' + v.method);
    try {
      const result = await handler(v.params === undefined ? {} : v.params, ctx);
      return resultResponse(v.id, result);
    } catch (e) {
      if (e && typeof e.rpcCode === 'number') return errorResponse(v.id, e.rpcCode, e.message, e.rpcData);
      return errorResponse(v.id, RPC.INTERNAL_ERROR, 'Internal error: ' + String((e && e.message) || e));
    }
  };
}

// ── MCP tool surface shapes ─────────────────────────────────────────────────

// tools/list result: descriptors are { name, description, inputSchema } (JSON Schema).
export function toolsListResult(tools) {
  return {
    tools: (Array.isArray(tools) ? tools : []).map((t) => ({
      name: String(t.name),
      description: String(t.description || ''),
      inputSchema: t.inputSchema && typeof t.inputSchema === 'object' ? t.inputSchema : { type: 'object', properties: {} },
    })),
  };
}

// tools/call result per MCP: content blocks + isError flag; structuredContent rides
// alongside for 2025-06-18 clients (older revisions ignore it and read the text).
// `value` is the tool's native return; it is JSON-fenced into the text block so a
// text-only client still receives the full payload.
export function toolCallResult(value, { isError = false } = {}) {
  const text = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
  const out = { content: [{ type: 'text', text }] };
  if (value && typeof value === 'object' && !Array.isArray(value)) out.structuredContent = value;
  if (isError) out.isError = true;
  return out;
}

// Validate tools/call params: { name, arguments? }. Returns { name, args } or throws
// rpcError(INVALID_PARAMS) — unknown-tool is INVALID_PARAMS per the MCP spec.
export function parseToolCall(params, knownToolNames) {
  const p = params && typeof params === 'object' ? params : {};
  if (typeof p.name !== 'string' || !p.name) throw rpcError(RPC.INVALID_PARAMS, 'tools/call needs params.name (string)');
  if (Array.isArray(knownToolNames) && !knownToolNames.includes(p.name)) throw rpcError(RPC.INVALID_PARAMS, 'unknown tool: ' + p.name);
  const args = p.arguments === undefined ? {} : p.arguments;
  if (!args || typeof args !== 'object' || Array.isArray(args)) throw rpcError(RPC.INVALID_PARAMS, 'tools/call arguments must be an object');
  return { name: p.name, args };
}
