/**
 * Profile Key Cryptography
 *
 * Pure cryptographic functions for profile key operations.
 * No database or storage dependencies - fully testable.
 *
 * Blob format (reference pattern):
 * ```
 * [nonce (12 bytes) || ciphertext || auth_tag (16 bytes)]
 * ```
 *
 */

import {
  generateRandomBytes,
  aesGcmEncryptWithIVBytes,
  aesGcmDecryptWithIVBytes,
  bytesToBase64,
  base64ToBytes,
  AES_256_KEY_BYTES,
  AES_GCM_IV_BYTES,
  AES_GCM_TAG_BYTES,
} from '../internal/crypto';
import { asBase64 } from '../types/utils';

// ============================================================================
// Constants
// ============================================================================

/** Profile key size in bytes (AES-256) */
export {};
export const PROFILE_KEY_SIZE = AES_256_KEY_BYTES; // 32 bytes

/** Nonce size for AES-GCM */
export const NONCE_SIZE = AES_GCM_IV_BYTES; // 12 bytes

/** Auth tag size for AES-GCM */
export const AUTH_TAG_SIZE = AES_GCM_TAG_BYTES; // 16 bytes

// ============================================================================
// Profile Key Generation
// ============================================================================

/**
 * Generate a new 32-byte profile key
 *
 * @returns New profile key as Uint8Array
 */
export async function generateProfileKey(): Promise<Uint8Array> {
  return generateRandomBytes(PROFILE_KEY_SIZE);
}

// ============================================================================
// Profile data encryption
// ============================================================================

/**
 * Encrypt profile data with an embedded IV.
 *
 * Format: [nonce (12) || ciphertext || tag (16)]
 *
 * General-purpose [nonce||ct||tag] encryption used for avatars and profile fields.
 * The IV is embedded in the output, not stored separately.
 *
 * @param profileKey - 32-byte AES key
 * @param plaintext - Plain data as Uint8Array
 * @returns Encrypted data as [nonce || ciphertext || tag]
 *
 */
export async function encryptProfileData(
  profileKey: Uint8Array,
  plaintext: Uint8Array
): Promise<Uint8Array> {
  const nonce = await generateRandomBytes(NONCE_SIZE);
  const ciphertextAndTag = await aesGcmEncryptWithIVBytes(profileKey, plaintext, nonce);
  // ciphertextAndTag is already [ciphertext || tag(16)]
  const combined = new Uint8Array(NONCE_SIZE + ciphertextAndTag.length);
  combined.set(nonce, 0);
  combined.set(ciphertextAndTag, NONCE_SIZE);
  return combined;
}

/**
 * Decrypt profile data with an embedded IV.
 *
 * Extracts the nonce from the start of the data, then decrypts.
 *
 * @param profileKey - 32-byte AES key
 * @param encryptedData - Encrypted data as [nonce || ciphertext || tag]
 * @returns Decrypted data
 *
 */
export async function decryptProfileData(
  profileKey: Uint8Array,
  encryptedData: Uint8Array
): Promise<Uint8Array> {
  const minSize = NONCE_SIZE + 1 + AUTH_TAG_SIZE;
  if (encryptedData.length < minSize) {
    throw new Error(`Encrypted data too small: ${encryptedData.length} < ${minSize}`);
  }
  const nonce = encryptedData.slice(0, NONCE_SIZE);
  const ciphertextAndTag = encryptedData.slice(NONCE_SIZE); // [ciphertext || tag(16)]
  return aesGcmDecryptWithIVBytes(profileKey, ciphertextAndTag, nonce);
}

/**
 * Convert profile key bytes to base64 string
 *
 * @param key - Profile key as Uint8Array
 * @returns Base64-encoded profile key
 */
export function profileKeyToBase64(key: Uint8Array): string {
  return bytesToBase64(key);
}

/**
 * Convert base64 string to profile key bytes
 *
 * @param base64 - Base64-encoded profile key
 * @returns Profile key as Uint8Array
 */
export function base64ToProfileKey(base64: string): Uint8Array {
  return base64ToBytes(asBase64(base64));
}
