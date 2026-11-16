/**
 * Proof checks for the SHA-256 Merkle log of RFC 9162 section 2.1, the tree
 * of the identity log.
 *
 * A leaf hash is SHA-256(0x00 || leaf). An interior hash is SHA-256(0x01 ||
 * left || right). The functions use arithmetic, not bit operations, so each
 * safe integer size works.
 */
import { equalBytes } from '@noble/curves/utils.js';
import { sha256 } from '@noble/hashes/sha2.js';

/** The bytes of one log hash. */
export const LOG_HASH_BYTES = 32;

const LEAF_PREFIX = Uint8Array.of(0);
const NODE_PREFIX = Uint8Array.of(1);

/** Returns SHA-256(0x00 || leaf). */
export function leafHash(leaf: Uint8Array): Uint8Array {
  return sha256.create().update(LEAF_PREFIX).update(leaf).digest();
}

/** Returns SHA-256(0x01 || left || right). */
export function nodeHash(left: Uint8Array, right: Uint8Array): Uint8Array {
  return sha256.create().update(NODE_PREFIX).update(left).update(right).digest();
}

function odd(value: number): boolean {
  return value % 2 === 1;
}

function half(value: number): number {
  return Math.floor(value / 2);
}

function validSize(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0;
}

function validPath(path: readonly Uint8Array[]): boolean {
  return path.every((hash) => hash.length === LOG_HASH_BYTES);
}

/**
 * Verifies an inclusion proof (RFC 9162 section 2.1.3.2): the leaf hash at
 * `position`, with the audit path that has the hash nearest the leaf first,
 * gives `root` for the tree of `treeSize` leaves.
 */
export function verifyInclusion(
  position: number,
  treeSize: number,
  leaf: Uint8Array,
  path: readonly Uint8Array[],
  root: Uint8Array
): boolean {
  if (!validSize(position) || !validSize(treeSize) || position >= treeSize) return false;
  if (leaf.length !== LOG_HASH_BYTES || root.length !== LOG_HASH_BYTES || !validPath(path)) {
    return false;
  }
  let fn = position;
  let sn = treeSize - 1;
  let r = leaf;
  for (const p of path) {
    if (sn === 0) return false;
    if (odd(fn) || fn === sn) {
      r = nodeHash(p, r);
      if (!odd(fn)) {
        while (!odd(fn) && fn !== 0) {
          fn = half(fn);
          sn = half(sn);
        }
      }
    } else {
      r = nodeHash(r, p);
    }
    fn = half(fn);
    sn = half(sn);
  }
  return sn === 0 && equalBytes(r, root);
}

/**
 * Verifies a consistency proof (RFC 9162 section 2.1.4.2) from the tree of
 * `oldSize` leaves to the tree of `newSize` leaves, for 0 < oldSize <
 * newSize. Equal sizes and an empty old tree have no proof, so the caller
 * decides them.
 */
export function verifyConsistency(
  oldSize: number,
  newSize: number,
  oldRoot: Uint8Array,
  newRoot: Uint8Array,
  proof: readonly Uint8Array[]
): boolean {
  if (!validSize(oldSize) || !validSize(newSize) || oldSize < 1 || oldSize >= newSize) return false;
  if (
    oldRoot.length !== LOG_HASH_BYTES ||
    newRoot.length !== LOG_HASH_BYTES ||
    proof.length === 0 ||
    !validPath(proof)
  ) {
    return false;
  }
  // An old tree that is a perfect subtree is the first node of the path.
  let exactPowerOfTwo = oldSize;
  while (exactPowerOfTwo % 2 === 0) exactPowerOfTwo /= 2;
  const path = exactPowerOfTwo === 1 ? [oldRoot, ...proof] : [...proof];
  let fn = oldSize - 1;
  let sn = newSize - 1;
  while (odd(fn)) {
    fn = half(fn);
    sn = half(sn);
  }
  let fr = path[0]!;
  let sr = path[0]!;
  for (const c of path.slice(1)) {
    if (sn === 0) return false;
    if (odd(fn) || fn === sn) {
      fr = nodeHash(c, fr);
      sr = nodeHash(c, sr);
      if (!odd(fn)) {
        while (!odd(fn) && fn !== 0) {
          fn = half(fn);
          sn = half(sn);
        }
      }
    } else {
      sr = nodeHash(sr, c);
    }
    fn = half(fn);
    sn = half(sn);
  }
  return sn === 0 && equalBytes(fr, oldRoot) && equalBytes(sr, newRoot);
}
