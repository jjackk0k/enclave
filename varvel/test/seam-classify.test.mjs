// seam-classify.test.mjs — pins the enforcement-seam classifier's treatment of PROXY specs.
// Regression: 2026-08-05 manhuaus mission — `curl --proxy socks5h://10.64.0.1:1080 https://…`
// was classified as target traffic TO the proxy (10.64.0.1 "outside the signed scope"),
// denying the ghost self-verify. The proxy is egress infrastructure; the DESTINATION governs.
import test from 'node:test';
import assert from 'node:assert/strict';
import { classify } from '../../poc/enforcement-seam/classify.mjs';

test('seam classify: proxied curl classifies by DESTINATION, never the proxy IP', () => {
  const r = classify('Bash', { command: 'curl -s --max-time 20 --proxy socks5h://10.64.0.1:1080 https://api.ipify.org' });
  assert.equal(r.action, 'webResearch');           // public destination -> research gate, not scope gate
  assert.notEqual(r.targetIp, '10.64.0.1');        // the proxy must never become "the target"
});

test('seam classify: -x short form and joined -xhttp:// form both stripped', () => {
  const a = classify('Bash', { command: 'curl -s -x socks5://10.64.0.1:1080 https://example.com' });
  assert.equal(a.action, 'webResearch');
  const b = classify('Bash', { command: 'curl -s -xhttp://10.64.0.1:8080 https://example.com' });
  assert.equal(b.action, 'webResearch');
});

test('seam classify: inline proxy env assignment is stripped before classification', () => {
  const r = classify('Bash', { command: 'https_proxy=http://10.64.0.1:8080 curl -s https://example.com' });
  assert.equal(r.action, 'webResearch');
});

test('seam classify: a PRIVATE destination through a proxy is still scope-gated target traffic', () => {
  const r = classify('Bash', { command: 'curl -s --proxy socks5h://10.64.0.1:1080 http://192.168.50.130/' });
  assert.equal(r.action, 'networkScan');
  assert.equal(r.targetIp, '192.168.50.130');      // destination IP governs, not the proxy
});

test('seam classify: direct curl to a private IP is unchanged (loopback stays scope-gated)', () => {
  const r = classify('Bash', { command: 'curl -s http://127.0.0.1:8971/api/ghost' });
  assert.equal(r.action, 'networkScan');
  assert.equal(r.targetIp, '127.0.0.1');
});
