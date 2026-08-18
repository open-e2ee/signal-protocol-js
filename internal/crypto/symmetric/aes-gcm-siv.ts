/**
 * AES-256-GCM-SIV (Misuse-Resistant Authenticated Encryption)
 *
 * Used by Sealed Sender V2 for multi-recipient encryption.
 * GCM-SIV is nonce-misuse resistant (RFC 8452), making it safe
 * to use with a constant zero nonce when keys are single-use.
 *
 * The reference implementation uses this in V2 sealed sender because:
 * 1. Each message derives a unique symmetric key from random M
 * 2. Zero nonce is safe since key is never reused
 * 3. Provides authenticated encryption in a single pass
 *
 * @see RFC 8452 - AES-GCM-SIV: Nonce Misuse-Resistant Authenticated Encryption
 */

import { gcmsiv } from '@noble/ciphers/aes.js';

// ============================================================================
// Constants
// ============================================================================

/**
 * AES-256-GCM-SIV key size in bytes
 */
export {};
export const AES_GCM_SIV_KEY_BYTES = 32;

/**
 * AES-GCM-SIV nonce size in bytes
 */
export const AES_GCM_SIV_NONCE_BYTES = 12;

/**
 * AES-GCM-SIV authentication tag size in bytes
 */
export const AES_GCM_SIV_TAG_BYTES = 16;

/**
 * Pre-allocated zero nonce for single-use key scenarios.
 * Safe to reuse because it is immutable and only used when key is single-use.
 * GCM-SIV is nonce-misuse resistant (RFC 8452).
 */
const ZERO_NONCE = new Uint8Array(AES_GCM_SIV_NONCE_BYTES);

// ============================================================================
// AES-256-GCM-SIV Encryption/Decryption
// ============================================================================

/**
 * Encrypt data using AES-256-GCM-SIV
 *
 * GCM-SIV is misuse-resistant: even if the same nonce is reused with
 * the same key, only identical plaintexts will produce identical ciphertexts.
 * No key recovery or forgery is possible.
 *
 * For Sealed Sender V2, we use a zero nonce because the key is derived
 * from random M and is never reused.
 *
 * @param key 32-byte AES-256 key
 * @param nonce 12-byte nonce (can be zeros for single-use keys)
 * @param plaintext Data to encrypt
 * @param aad Optional additional authenticated data
 * @returns Ciphertext with appended authentication tag
 */
export function aesGcmSivEncrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad?: Uint8Array
): Uint8Array {
  if (key.length !== AES_GCM_SIV_KEY_BYTES) {
    throw new Error('AES-GCM-SIV key must be 32 bytes');
  }
  if (nonce.length !== AES_GCM_SIV_NONCE_BYTES) {
    throw new Error('AES-GCM-SIV nonce must be 12 bytes');
  }

  const cipher = gcmsiv(key, nonce, aad);
  return cipher.encrypt(plaintext);
}

/**
 * Decrypt data using AES-256-GCM-SIV
 *
 * @param key 32-byte AES-256 key
 * @param nonce 12-byte nonce
 * @param ciphertext Encrypted data with appended authentication tag
 * @param aad Optional additional authenticated data (must match encryption)
 * @returns Decrypted plaintext
 * @throws Error if authentication fails (tag mismatch)
 */
export function aesGcmSivDecrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  aad?: Uint8Array
): Uint8Array {
  if (key.length !== AES_GCM_SIV_KEY_BYTES) {
    throw new Error('AES-GCM-SIV key must be 32 bytes');
  }
  if (nonce.length !== AES_GCM_SIV_NONCE_BYTES) {
    throw new Error('AES-GCM-SIV nonce must be 12 bytes');
  }

  const cipher = gcmsiv(key, nonce, aad);
  try {
    return cipher.decrypt(ciphertext);
  } catch {
    // Normalize error message to prevent information leakage
    throw new Error('Authentication failed');
  }
}

/**
 * Encrypt with zero nonce (for single-use keys)
 *
 * Convenience function for Sealed Sender V2 where the symmetric key
 * is derived from random M and is never reused.
 *
 * @param key 32-byte single-use AES-256 key
 * @param plaintext Data to encrypt
 * @param aad Optional additional authenticated data
 * @returns Ciphertext with appended authentication tag
 */
export function aesGcmSivEncryptZeroNonce(
  key: Uint8Array,
  plaintext: Uint8Array,
  aad?: Uint8Array
): Uint8Array {
  return aesGcmSivEncrypt(key, ZERO_NONCE, plaintext, aad);
}

/**
 * Decrypt with zero nonce (for single-use keys)
 *
 * @param key 32-byte single-use AES-256 key
 * @param ciphertext Encrypted data with appended authentication tag
 * @param aad Optional additional authenticated data
 * @returns Decrypted plaintext
 */
export function aesGcmSivDecryptZeroNonce(
  key: Uint8Array,
  ciphertext: Uint8Array,
  aad?: Uint8Array
): Uint8Array {
  return aesGcmSivDecrypt(key, ZERO_NONCE, ciphertext, aad);
}
