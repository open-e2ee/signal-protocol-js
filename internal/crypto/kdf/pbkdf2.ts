/**
 * PBKDF2-SHA512 Key Derivation
 *
 * General PBKDF2-HMAC-SHA512 utility. Safety-number generation uses its own
 * iterative SHA-512 construction and does not call this helper.
 *
 * @see https://signal.org/blog/safety-number-updates/
 * @see RFC 8018 (PKCS #5: PBKDF2)
 */

import { pbkdf2 } from '@noble/hashes/pbkdf2.js';
import { sha512 } from '@noble/hashes/sha2.js';

// ============================================================================
// Constants
// ============================================================================

/**
 * Default work factor for callers that need the legacy 5,200-iteration
 * profile. Products should review this value for their use case.
 */
export {};
export const SAFETY_NUMBER_ITERATIONS = 5200;

/**
 * Output length for PBKDF2-SHA512 in bytes.
 * SHA-512 produces 64-byte (512-bit) output.
 */
export const PBKDF2_SHA512_OUTPUT_BYTES = 64;

// ============================================================================
// PBKDF2-SHA512
// ============================================================================

/**
 * Derive key using PBKDF2-HMAC-SHA512.
 *
 * It provides configurable key stretching for password-like inputs.
 *
 * @param password - The input key material (combined identity keys + identifiers)
 * @param salt - Salt for derivation (can be empty for safety numbers)
 * @param iterations - Number of iterations (default: 5,200)
 * @param dkLen - Desired key length in bytes (default: 64)
 * @returns Derived key bytes
 *
 * @example
 * ```typescript
 * const fingerprint = pbkdf2Sha512(
 *   combinedData,
 *   salt,
 *   5200
 * );
 * ```
 */
export function pbkdf2Sha512(
  password: Uint8Array,
  salt: Uint8Array,
  iterations: number = SAFETY_NUMBER_ITERATIONS,
  dkLen: number = PBKDF2_SHA512_OUTPUT_BYTES
): Uint8Array {
  return pbkdf2(sha512, password, salt, { c: iterations, dkLen });
}
