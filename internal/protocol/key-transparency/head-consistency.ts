/**
 * The rules that a new tree head must meet against the last head that the
 * client verified, and the head that the client keeps after it.
 *
 * - No last head: the consistency proof must be empty.
 * - A smaller size is refused.
 * - The same size: the roots must be equal and the proof must be empty. The
 *   time can be earlier or later than the last time. The Relay signs the
 *   head of an unchanged tree again each hour, and two reads can get the
 *   two signatures in either order.
 * - A last head of the empty tree: the proof must be empty.
 * - Otherwise the proof must verify (RFC 9162 section 2.1.4.2). The time can
 *   be earlier than the last time.
 *
 * The size, the root, and the proof decide. The head time is not ordered.
 * The freshness rule against the local clock applies to each new head.
 */
import { equalBytes } from '@noble/curves/utils.js';

import { KeyTransparencyVerificationError } from './errors';
import { verifyConsistency } from './merkle';
import type { IdentityLogHead } from './tree-head';

function inconsistent(message: string): KeyTransparencyVerificationError {
  return new KeyTransparencyVerificationError('TREE_HEAD_INCONSISTENT', message);
}

/** Throws `TREE_HEAD_INCONSISTENT` when `current` does not extend `last`. */
export function verifyIdentityLogHeadConsistency(
  last: IdentityLogHead | undefined,
  current: IdentityLogHead,
  proof: readonly Uint8Array[]
): void {
  if (last === undefined) {
    if (proof.length !== 0) throw inconsistent('A consistency proof came without a last head');
    return;
  }
  if (current.treeSize < last.treeSize) {
    throw inconsistent('The identity log head is smaller than the last head');
  }
  if (current.treeSize === last.treeSize) {
    if (!equalBytes(current.root, last.root)) {
      throw inconsistent('The identity log head has a new root for the same size');
    }
    if (proof.length !== 0) throw inconsistent('A consistency proof came for the same size');
    return;
  }
  if (last.treeSize === 0) {
    if (proof.length !== 0) throw inconsistent('A consistency proof came for an empty last head');
    return;
  }
  if (!verifyConsistency(last.treeSize, current.treeSize, last.root, current.root, proof)) {
    throw inconsistent('The consistency proof does not verify');
  }
}

/**
 * The head to keep after `current` passed the consistency rules against
 * `last`. At the same size, the head with the later time stays, and `last`
 * stays at an equal time. A larger head replaces `last`.
 */
export function retainedIdentityLogHead(
  last: IdentityLogHead | undefined,
  current: IdentityLogHead
): IdentityLogHead {
  if (last === undefined || current.treeSize > last.treeSize) return current;
  return current.timestamp > last.timestamp ? current : last;
}
