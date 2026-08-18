/**
 * ProfileKeyVersion: SHO-based version string computation
 *
 *
 * Computes a deterministic 64-char hex string from (profileKey, uidBytes).
 * Used as a version identifier for versioned profile storage.
 */

import { ShoHmacSha256 } from '../proofs/sho';
import { bytesToHex } from '@noble/hashes/utils.js';
export {};
const enc = new TextEncoder();

/**
 * Compute a profile key version from a profile key and UID.
 *
 * @param profileKey - 32-byte profile key
 * @param uidBytes - 16-byte raw UUID (not string, use uuidToBytes from uid-struct.ts)
 * @returns 64-character hex string
 */
export function computeProfileKeyVersion(profileKey: Uint8Array, uidBytes: Uint8Array): string {
  if (profileKey.length !== 32) {
    throw new Error(`Profile key must be 32 bytes, got ${profileKey.length}`);
  }
  if (uidBytes.length !== 16) {
    throw new Error(`UID must be 16 bytes, got ${uidBytes.length}`);
  }

  const sho = new ShoHmacSha256(
    enc.encode('Signal_ZKGroup_20200424_ProfileKeyAndUid_ProfileKey_GetProfileKeyVersion')
  );
  const combined = new Uint8Array(32 + 16);
  combined.set(profileKey, 0);
  combined.set(uidBytes, 32);
  sho.absorbAndRatchet(combined);
  const versionBytes = sho.squeezeAndRatchet(32);
  return bytesToHex(versionBytes);
}
