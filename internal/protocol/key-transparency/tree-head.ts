/**
 * The signed tree head of a project identity log.
 *
 * The signature is Ed25519 over:
 *
 *   u8 label length || "identity-log-tree-head-v1" || u16be scope length ||
 *   scope (UTF-8) || u64be tree size || root (32 bytes) || u64be time
 *   (milliseconds)
 *
 * The scope is the project scope string of the connection, so a head of one
 * project does not verify for another. The client rebuilds these bytes from
 * the head fields and its own scope.
 */
import { ed25519 } from '@noble/curves/ed25519.js';

import { KeyTransparencyVerificationError } from './errors';
import { LOG_HASH_BYTES } from './merkle';

/** The values of a tree head. */
export interface IdentityLogHead {
  readonly treeSize: number;
  readonly root: Uint8Array;
  /** The signing time, Unix milliseconds. */
  readonly timestamp: number;
}

/** A tree head with its signature. */
export interface SignedIdentityLogHead extends IdentityLogHead {
  readonly signature: Uint8Array;
}

/** The bytes of an Ed25519 head signature. */
export const TREE_HEAD_SIGNATURE_BYTES = 64;
/** The bytes of an Ed25519 head public key. */
export const TREE_HEAD_PUBLIC_KEY_BYTES = 32;
/**
 * The largest difference between the head time and the local clock that a
 * head can have. A difference of exactly this value is accepted.
 */
export const TREE_HEAD_MAXIMUM_AGE_MILLISECONDS = 24 * 60 * 60 * 1_000;

const LABEL = new TextEncoder().encode('identity-log-tree-head-v1');
const MAXIMUM_SCOPE_BYTES = 255;

/** Returns the signed bytes of a head, or `null` when a field cannot be encoded. */
export function encodeIdentityLogHead(scope: string, head: IdentityLogHead): Uint8Array | null {
  const scopeBytes = new TextEncoder().encode(scope);
  if (
    scopeBytes.length < 1 ||
    scopeBytes.length > MAXIMUM_SCOPE_BYTES ||
    !Number.isSafeInteger(head.treeSize) ||
    head.treeSize < 0 ||
    head.root.length !== LOG_HASH_BYTES ||
    !Number.isSafeInteger(head.timestamp) ||
    head.timestamp < 0
  ) {
    return null;
  }
  const bytes = new Uint8Array(1 + LABEL.length + 2 + scopeBytes.length + 8 + LOG_HASH_BYTES + 8);
  const view = new DataView(bytes.buffer);
  let offset = 0;
  bytes[offset] = LABEL.length;
  offset += 1;
  bytes.set(LABEL, offset);
  offset += LABEL.length;
  view.setUint16(offset, scopeBytes.length, false);
  offset += 2;
  bytes.set(scopeBytes, offset);
  offset += scopeBytes.length;
  view.setBigUint64(offset, BigInt(head.treeSize), false);
  offset += 8;
  bytes.set(head.root, offset);
  offset += LOG_HASH_BYTES;
  view.setBigUint64(offset, BigInt(head.timestamp), false);
  return bytes;
}

/**
 * Throws `TREE_HEAD_SIGNATURE_INVALID` unless one of the pinned head keys
 * signed the head for the scope. Decoding follows RFC 8032 strictly.
 */
export function verifyIdentityLogHeadSignature(
  headPublicKeys: readonly Uint8Array[],
  scope: string,
  head: SignedIdentityLogHead
): void {
  const message = encodeIdentityLogHead(scope, head);
  const signed =
    message !== null &&
    head.signature.length === TREE_HEAD_SIGNATURE_BYTES &&
    headPublicKeys.some((key) => {
      if (key.length !== TREE_HEAD_PUBLIC_KEY_BYTES) return false;
      try {
        return ed25519.verify(head.signature, message, key, { zip215: false });
      } catch {
        return false;
      }
    });
  if (!signed) {
    throw new KeyTransparencyVerificationError(
      'TREE_HEAD_SIGNATURE_INVALID',
      'No pinned head key signed the identity log head'
    );
  }
}

/**
 * Throws `TREE_HEAD_STALE` when the head time is more than 24 hours before or
 * after `now`, the local clock.
 */
export function verifyIdentityLogHeadFreshness(head: IdentityLogHead, now: number): void {
  if (Math.abs(now - head.timestamp) > TREE_HEAD_MAXIMUM_AGE_MILLISECONDS) {
    throw new KeyTransparencyVerificationError(
      'TREE_HEAD_STALE',
      'The identity log head time is more than 24 hours from the local clock'
    );
  }
}
