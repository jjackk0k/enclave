// merkle.mjs — a Merkle tree over audit-ledger entries, using the RFC 6962
// (Certificate Transparency) hashing convention with domain separation:
//   leaf  = SHA-256(0x00 || data)
//   node  = SHA-256(0x01 || left || right)
// Domain separation (the 0x00 / 0x01 prefixes) prevents second-preimage attacks
// where a leaf could be passed off as an internal node. Odd nodes are promoted.

import { createHash } from 'node:crypto';

const sha = b => createHash('sha256').update(b).digest();
export const hashLeaf = data => sha(Buffer.concat([Buffer.from([0x00]), Buffer.from(typeof data === 'string' ? data : JSON.stringify(data))]));
const hashNode = (l, r) => sha(Buffer.concat([Buffer.from([0x01]), l, r]));

/** Build the tree. Returns { root, levels, leaves } (root is a Buffer). */
export function buildTree(entries) {
  const leaves = entries.map(hashLeaf);
  if (leaves.length === 0) return { root: sha(Buffer.alloc(0)), levels: [[]], leaves };
  const levels = [leaves];
  let cur = leaves;
  while (cur.length > 1) {
    const next = [];
    for (let i = 0; i < cur.length; i += 2) {
      next.push(i + 1 < cur.length ? hashNode(cur[i], cur[i + 1]) : cur[i]); // promote odd
    }
    levels.push(next);
    cur = next;
  }
  return { root: cur[0], levels, leaves };
}

/** Inclusion proof for the leaf at `index`: [{ hash, right }] audit path. */
export function inclusionProof(levels, index) {
  const proof = [];
  let idx = index;
  for (let l = 0; l < levels.length - 1; l++) {
    const level = levels[l];
    const sib = idx ^ 1;
    if (sib < level.length) proof.push({ hash: level[sib].toString('hex'), right: sib > idx });
    // else: promoted odd node, no sibling at this level
    idx = Math.floor(idx / 2);
  }
  return proof;
}

/** Verify that `leafData` is included under `rootHex` via `proof`. */
export function verifyInclusion(leafData, proof, rootHex) {
  let h = hashLeaf(leafData);
  for (const step of proof) {
    const sib = Buffer.from(step.hash, 'hex');
    h = step.right ? hashNode(h, sib) : hashNode(sib, h);
  }
  return h.toString('hex') === rootHex;
}
