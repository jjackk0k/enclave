// mcprpc.test.mjs — pure tests for the MCP JSON-RPC 2.0 core (engine/mcprpc.mjs).
// No I/O, no processes: framing, handshake negotiation, router behavior, tool shapes.
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  MCP_PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS, RPC,
  encodeMessage, parseFrame, createFrameDecoder, validateMessage,
  resultResponse, errorResponse, rpcError, negotiateVersion, initializeResult,
  createRouter, toolsListResult, toolCallResult, parseToolCall,
} from '../engine/mcprpc.mjs';

test('framing: encode -> decode round-trip, including frames split mid-message', () => {
  const got = [];
  const dec = createFrameDecoder({ onMessage: (m) => got.push(m), onError: (e) => { throw new Error('unexpected frame error: ' + e.message); } });
  const wire = encodeMessage({ jsonrpc: '2.0', id: 1, method: 'ping' }) + encodeMessage({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
  for (const ch of [wire.slice(0, 7), wire.slice(7, 40), wire.slice(40)]) dec.push(ch); // split at arbitrary points
  assert.equal(got.length, 2);
  assert.equal(got[0].method, 'ping');
  assert.equal(got[1].id, 2);
});

test('framing: blank lines ignored; CRLF tolerated; unterminated tail flushes on end()', () => {
  const got = [];
  const dec = createFrameDecoder({ onMessage: (m) => got.push(m), onError: () => {} });
  dec.push('\r\n\n' + encodeMessage({ jsonrpc: '2.0', id: 9, method: 'ping' }).replace('\n', '\r\n'));
  dec.push(JSON.stringify({ jsonrpc: '2.0', id: 10, method: 'ping' })); // no trailing newline
  assert.equal(got.length, 1);
  dec.end();
  assert.equal(got.length, 2);
  assert.equal(got[1].id, 10);
});

test('framing: malformed JSON -> PARSE_ERROR; batch array -> INVALID_REQUEST; non-object -> INVALID_REQUEST', () => {
  const errs = [];
  const dec = createFrameDecoder({ onMessage: () => {}, onError: (e) => errs.push(e) });
  dec.push('{not json!!\n');
  dec.push('[{"jsonrpc":"2.0","id":1,"method":"ping"}]\n');
  dec.push('42\n');
  assert.deepEqual(errs.map((e) => e.code), [RPC.PARSE_ERROR, RPC.INVALID_REQUEST, RPC.INVALID_REQUEST]);
  assert.match(errs[1].message, /batch/i);
});

test('framing: an oversized frame is an error, never a memory sink', () => {
  const errs = [];
  const dec = createFrameDecoder({ onMessage: () => {}, onError: (e) => errs.push(e), maxBytes: 64 });
  dec.push('x'.repeat(500)); // no newline, already over cap
  assert.equal(errs.length, 1);
  assert.match(errs[0].message, /exceeds/);
  assert.equal(dec.pendingBytes(), 0);
});

test('validateMessage: request / notification / response / invalid classified exactly', () => {
  assert.equal(validateMessage({ jsonrpc: '2.0', id: 1, method: 'm' }).kind, 'request');
  assert.equal(validateMessage({ jsonrpc: '2.0', method: 'notifications/initialized' }).kind, 'notification');
  assert.equal(validateMessage({ jsonrpc: '2.0', id: 1, result: {} }).kind, 'response');
  assert.equal(validateMessage({ id: 1, method: 'm' }).kind, 'invalid');           // jsonrpc missing
  assert.equal(validateMessage({ jsonrpc: '2.0', id: {}, method: 'm' }).kind, 'invalid'); // bad id type
  assert.equal(validateMessage({ jsonrpc: '2.0' }).kind, 'invalid');               // nothing at all
});

test('initialize negotiation: supported client versions echo; unknown falls back to the pinned version', () => {
  for (const v of SUPPORTED_PROTOCOL_VERSIONS) assert.equal(negotiateVersion(v), v);
  assert.equal(negotiateVersion('1999-01-01'), MCP_PROTOCOL_VERSION);
  assert.equal(negotiateVersion(undefined), MCP_PROTOCOL_VERSION);
  const r = initializeResult({ clientVersion: '2025-03-26', serverName: 'varvel-mcp' });
  assert.equal(r.protocolVersion, '2025-03-26');
  assert.equal(r.serverInfo.name, 'varvel-mcp');
  assert.ok(r.capabilities.tools); // the only capability family VARVEL claims this wave
});

test('router: unknown method -> METHOD_NOT_FOUND; handler throw -> INTERNAL_ERROR; rpcError passes through', async () => {
  const route = createRouter({
    handlers: {
      ok: async () => ({ fine: true }),
      boom: async () => { throw new Error('kaboom'); },
      coded: async () => { throw rpcError(RPC.INVALID_PARAMS, 'bad params', { field: 'x' }); },
    },
  });
  const nf = await route({ jsonrpc: '2.0', id: 1, method: 'nope' });
  assert.equal(nf.error.code, RPC.METHOD_NOT_FOUND);
  const ok = await route({ jsonrpc: '2.0', id: 2, method: 'ok' });
  assert.deepEqual(ok.result, { fine: true });
  const boom = await route({ jsonrpc: '2.0', id: 3, method: 'boom' });
  assert.equal(boom.error.code, RPC.INTERNAL_ERROR);
  assert.match(boom.error.message, /kaboom/);
  const coded = await route({ jsonrpc: '2.0', id: 4, method: 'coded' });
  assert.equal(coded.error.code, RPC.INVALID_PARAMS);
  assert.deepEqual(coded.error.data, { field: 'x' });
});

test('router: notifications get no response but reach the tap; stray responses are ignored', async () => {
  const taps = [];
  const route = createRouter({ handlers: {}, onNotification: (m, p) => taps.push([m, p]) });
  assert.equal(await route({ jsonrpc: '2.0', method: 'notifications/initialized', params: { a: 1 } }), null);
  assert.equal(await route({ jsonrpc: '2.0', id: 5, result: {} }), null);
  assert.deepEqual(taps, [['notifications/initialized', { a: 1 }]]);
});

test('router: a malformed request still gets a well-formed error response (never a crash)', async () => {
  const route = createRouter({ handlers: {} });
  const r = await route({ id: 1, method: 'ping' }); // jsonrpc missing
  assert.equal(r.error.code, RPC.INVALID_REQUEST);
  assert.equal(r.id, 1);
});

test('tools/list shape: only name/description/inputSchema — governance policy is never exposed', () => {
  const r = toolsListResult([{ name: 't1', description: 'd', inputSchema: { type: 'object' }, policy: { class: 'target-touching' }, run: () => {} }]);
  assert.equal(r.tools.length, 1);
  assert.deepEqual(Object.keys(r.tools[0]).sort(), ['description', 'inputSchema', 'name']);
});

test('tools/call result shape: fenced text + structuredContent for objects; isError flag honored', () => {
  const obj = toolCallResult({ endpoints: ['/a'] });
  assert.equal(obj.content[0].type, 'text');
  assert.match(obj.content[0].text, /\/a/);
  assert.deepEqual(obj.structuredContent, { endpoints: ['/a'] });
  assert.equal(obj.isError, undefined);
  const err = toolCallResult('DENIED: out of scope', { isError: true });
  assert.equal(err.isError, true);
  assert.equal(err.structuredContent, undefined);
});

test('parseToolCall: name required; arguments must be an object; unknown tool -> INVALID_PARAMS', () => {
  assert.deepEqual(parseToolCall({ name: 'x', arguments: { a: 1 } }, ['x']), { name: 'x', args: { a: 1 } });
  assert.throws(() => parseToolCall({}, ['x']), (e) => e.rpcCode === RPC.INVALID_PARAMS);
  assert.throws(() => parseToolCall({ name: 'y' }, ['x']), (e) => e.rpcCode === RPC.INVALID_PARAMS && /unknown tool/.test(e.message));
  assert.throws(() => parseToolCall({ name: 'x', arguments: [1] }, ['x']), (e) => e.rpcCode === RPC.INVALID_PARAMS);
});

test('result/error response shapes are spec-exact', () => {
  assert.deepEqual(resultResponse(1, { a: 1 }), { jsonrpc: '2.0', id: 1, result: { a: 1 } });
  assert.deepEqual(errorResponse(2, RPC.PARSE_ERROR, 'nope'), { jsonrpc: '2.0', id: 2, error: { code: RPC.PARSE_ERROR, message: 'nope' } });
  assert.equal(errorResponse(undefined, RPC.PARSE_ERROR, 'x').id, null); // parse errors have no id to echo
});
