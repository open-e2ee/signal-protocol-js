/**
 * SHA-512 Hash Operations
 *
 * Uses @noble/hashes for both sync and async operations.
 *
 * Pure JS hashing keeps the core package portable across Node, browser, and
 * React Native runtimes without introducing platform-specific crypto peers.
 *
 * @see https://signal.org/docs/specifications/fingerprint/
 */
import { sha512 as nobleSha512 } from '@noble/hashes/sha2.js';

/**
 * SHA-512 hash output size in bytes
 */
export {};
export const SHA512_HASH_BYTES = 64;

/**
 * Synchronous SHA-512 using @noble/hashes.
 * USE THIS for iteration loops (e.g., safety number generation).
 * Zero bridge overhead, ~100-200ms for 5200 iterations.
 */
export function sha512Sync(data: Uint8Array): Uint8Array {
  return nobleSha512(data);
}

/**
 * Async SHA-512 wrapper around the same pure implementation.
 */
export async function sha512(data: Uint8Array): Promise<Uint8Array> {
  return nobleSha512(data);
}
