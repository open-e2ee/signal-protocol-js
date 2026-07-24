/**
 * AES-256-CTR Encryption
 *
 * Provides AES-256-CTR (Counter Mode) encryption/decryption for Sealed Sender.
 *
 * Uses @noble/ciphers for implementation:
 * - Audited by cure53 (September 2024)
 * - Pure JavaScript, tree-shakeable
 * - Consistent with other @noble libraries used in this codebase
 *
 * Why CTR mode for Sealed Sender:
 * - No padding required (stream cipher mode)
 * - Parallelizable encryption/decryption
 * - The sealed-sender envelope format requires length-preserving encryption
 *
 * @see https://github.com/paulmillr/noble-ciphers
 */

import { ctr } from '@noble/ciphers/aes.js';
import type { Base64 } from '../../../types';
import { bytesToBase64, base64ToBytes } from '../utils';

// ============================================================================
// Constants
// ============================================================================

/**
 * AES-256 key size in bytes
 */
export {};
export const AES_CTR_KEY_BYTES = 32;

/**
 * AES-CTR IV/nonce size in bytes (full 128-bit counter)
 */
export const AES_CTR_IV_BYTES = 16;

// ============================================================================
// AES-256-CTR Encryption
// ============================================================================

/**
 * Encrypt data using AES-256-CTR
 *
 * CTR mode is a stream cipher mode that:
 * - Produces ciphertext of same length as plaintext (no padding)
 * - Is parallelizable for performance
 * - Requires unique IV for each encryption with the same key
 *
 * @param key 32-byte (256-bit) encryption key
 * @param iv 16-byte initialization vector (counter initial value)
 * @param plaintext Data to encrypt
 * @returns Ciphertext as Uint8Array
 * @throws Error if key is not 32 bytes
 * @throws Error if IV is not 16 bytes
 */
export function aesCtrEncrypt(key: Uint8Array, iv: Uint8Array, plaintext: Uint8Array): Uint8Array {
  if (key.length !== AES_CTR_KEY_BYTES) {
    throw new Error(`Key must be ${AES_CTR_KEY_BYTES} bytes`);
  }
  if (iv.length !== AES_CTR_IV_BYTES) {
    throw new Error(`IV must be ${AES_CTR_IV_BYTES} bytes`);
  }

  const cipher = ctr(key, iv);
  return cipher.encrypt(plaintext);
}

/**
 * Decrypt data using AES-256-CTR
 *
 * @param key 32-byte (256-bit) decryption key
 * @param iv 16-byte initialization vector (same as used for encryption)
 * @param ciphertext Data to decrypt
 * @returns Decrypted plaintext as Uint8Array
 * @throws Error if key is not 32 bytes
 * @throws Error if IV is not 16 bytes
 */
export function aesCtrDecrypt(key: Uint8Array, iv: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  if (key.length !== AES_CTR_KEY_BYTES) {
    throw new Error(`Key must be ${AES_CTR_KEY_BYTES} bytes`);
  }
  if (iv.length !== AES_CTR_IV_BYTES) {
    throw new Error(`IV must be ${AES_CTR_IV_BYTES} bytes`);
  }

  const cipher = ctr(key, iv);
  return cipher.decrypt(ciphertext);
}

// ============================================================================
// Base64 Variants (for API consistency with other AES functions)
// ============================================================================

/**
 * Encrypt data using AES-256-CTR, returning Base64
 *
 * @param key 32-byte encryption key
 * @param iv 16-byte initialization vector
 * @param plaintext Data to encrypt
 * @returns Base64-encoded ciphertext
 */
export function aesCtrEncryptToBase64(
  key: Uint8Array,
  iv: Uint8Array,
  plaintext: Uint8Array
): Base64 {
  return bytesToBase64(aesCtrEncrypt(key, iv, plaintext));
}

/**
 * Decrypt Base64 data using AES-256-CTR
 *
 * @param key 32-byte decryption key
 * @param iv 16-byte initialization vector
 * @param ciphertext Base64-encoded ciphertext
 * @returns Decrypted plaintext as Uint8Array
 */
export function aesCtrDecryptFromBase64(
  key: Uint8Array,
  iv: Uint8Array,
  ciphertext: Base64
): Uint8Array {
  return aesCtrDecrypt(key, iv, base64ToBytes(ciphertext));
}
