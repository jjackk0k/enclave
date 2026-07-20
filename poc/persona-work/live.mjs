// live.mjs — the live-Claude path. The persona's read-only context becomes the
// system prompt (so Claude tailors the deliverable to who they are), and the task
// is the user turn. Returns Markdown.
//
// NOTE: in production this call egresses THROUGH the broker (poc/egress-broker),
// which injects the key outside the sandbox. For this standalone demo it calls
// api.anthropic.com directly with the key from the environment — same request,
// minus the broker hop. Only ever runs when ANTHROPIC_API_KEY is set + --live.

import https from 'node:https';

const SYSTEM_SUFFIX =
  '\n\nYou are the operator\'s AI assistant inside this sealed enclave. Produce a concise, ' +
  'role-appropriate deliverable in Markdown. Stay strictly within the operator\'s authorization ' +
  'above — propose only what they may do, and flag anything beyond their remit for escalation.';

export function generateLive({ context, task, key, model = 'claude-sonnet-5' }) {
  const payload = JSON.stringify({
    model,
    max_tokens: 1200,
    system: context + SYSTEM_SUFFIX,
    messages: [{ role: 'user', content: task }],
  });
  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: 'api.anthropic.com', path: '/v1/messages', method: 'POST',
      headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload),
        'x-api-key': key, 'anthropic-version': '2023-06-01' },
    }, res => {
      let b = '';
      res.on('data', c => (b += c));
      res.on('end', () => {
        try {
          const j = JSON.parse(b);
          if (j.error) return reject(new Error(j.error.message || 'anthropic api error'));
          const text = (j.content || []).map(x => x.text).filter(Boolean).join('\n');
          resolve({ title: 'Deliverable (live)', filename: 'DELIVERABLE.md', markdown: text || '(empty response)' });
        } catch (e) { reject(new Error('bad response: ' + e.message)); }
      });
    });
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}
