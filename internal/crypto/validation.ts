/**
 * Key Pair Validation for Signal Protocol
 *
 * Validates that X25519 private keys derive to their stored public keys.
 * CRITICAL: Call after retrieving keys from storage to detect corruption.
 *
 * This module addresses Bug #7: MAC verification failures due to key pair
 * mismatch. If storage corruption or race conditions occur, the receiver
 * may use a private key that does not match the public key the sender used.
 * The shared secrets then differ, and MAC verification fails permanently.
 *
 * @see https://signal.org/docs/specifications/x3dh/ - X3DH key exchange
 */

import { x25519 } from '@noble/curves/ed25519.js';
import { base64ToBytes, constantTimeEqual, secureZeroBytes } from './utils';
import { EncryptionError, EncryptionErrorCode } from '../../types/errors';
import type { Base64 } from '../../types';

/**
 * Validates that a private key derives to the expected public key.
 *
 * This is a critical integrity check for X25519 key pairs. When keys are
 * retrieved from storage, corruption or race conditions could result in
 * a private key that does not correspond to the stored public key.
 *
 * If this validation fails:
 * - The stored keys are corrupted or mismatched
 * - Any X3DH computation using these keys would fail with MAC errors
 * - The sender's shared secret would differ from the receiver's
 *
 * @param publicKey Base64-encoded public key from storage
 * @param privateKey Base64-encoded private key from storage
 * @param context Description for error message (e.g., "signedPreKey:42537")
 * @throws {EncryptionError} If keys do not form a valid pair
 *
 * @example
 * ```typescript
 * const signedPreKey = await keyStorage.getSignedPreKey(keyId);
 * validateX25519KeyPair(
 *   signedPreKey.publicKey,
 *   signedPreKey.privateKey,
 *   `signedPreKey:${keyId}`
 * );
 * // Now safe to use for X3DH
 * ```
 */
export {};
export function validateX25519KeyPair(
  publicKey: Base64,
  privateKey: Base64,
  context: string
): void {
  const privateBytes = base64ToBytes(privateKey);

  try {
    const derivedPublicBytes = x25519.getPublicKey(privateBytes);
    const publicBytes = base64ToBytes(publicKey);

    // L1: Use best-effort full-scan equality for defense in depth.
    // Prevents timing attacks even though this is a corruption check
    if (!constantTimeEqual(derivedPublicBytes, publicBytes)) {
      throw new EncryptionError(
        `Key pair validation failed (${context}): private key does not derive to stored public key`,
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        {
          context,
          // Security: Do not include key prefixes in error context
          keyLengthExpected: publicBytes.length,
          keyLengthActual: derivedPublicBytes.length,
        }
      );
    }
  } finally {
    secureZeroBytes(privateBytes);
  }
}
