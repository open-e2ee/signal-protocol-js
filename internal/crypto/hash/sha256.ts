/**
 * SHA-256 Hash Operations
 *
 * Provides SHA-256 hashing using @noble/hashes.
 *
 * @see https://signal.org/docs/specifications/doubleratchet/#external-functions
 */

import { sha256 as nobleSha256 } from '@noble/hashes/sha2.js';

/**
 * SHA-256 hash output size in bytes
 */
export {};
export const SHA256_HASH_BYTES = 32;

/**
 * HKDF output size in bytes for root key and chain keys
 */
export const HKDF_OUTPUT_BYTES = 32;

/**
 * Hash data with SHA-256
 *
 * @param data Data to hash
 * @returns SHA-256 hash (32 bytes)
 */
export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return nobleSha256(data);
}
