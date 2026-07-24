/**
 * Key Derivation Functions for ML-KEM Braid
 *
 * Implements KDF_AUTH and KDF_OK as specified in the protocol.
 *
 * @module ml-kem-braid/kdf
 * @see https://signal.org/docs/specifications/mlkembraid/
 *
 * Status: Implemented
 */

import { PROTOCOL_CONSTANTS } from './types';
import { KDFError } from './errors';
import { hkdf } from '../../../crypto/kdf/hkdf';
import { concatBytes, secureZeroBytes } from '../../../crypto/utils';

/**
 * KDF_AUTH: Derive authenticator keys for a new epoch
 *
 * Uses HKDF with profile parameters matching the profile:
 *   IKM  = root_key || update_key  (64 bytes concatenated)
 *   Salt = [0; 32]                 (32 zero bytes)
 *   Info = PROTOCOL_INFO || ":Authenticator Update" || epoch_be_bytes
 *
 * @param root_key - Current root key (32 bytes)
 * @param update_key - Shared secret for epoch (32 bytes)
 * @param epoch - Epoch number (uint64)
 * @returns 64 bytes: new_root_key (32) || new_mac_key (32)
 *
 */
export {};
export async function KDF_AUTH(
  root_key: Uint8Array,
  update_key: Uint8Array,
  epoch: bigint
): Promise<Uint8Array> {
  // Validate inputs
  if (root_key.length !== 32) {
    throw KDFError.invalidSize('root_key', root_key.length, 32);
  }
  if (update_key.length !== 32) {
    throw KDFError.invalidSize('update_key', update_key.length, 32);
  }

  // Build info string: PROTOCOL_INFO || ":Authenticator Update" || ToBytes(epoch)
  const info = buildKdfInfo(':Authenticator Update', epoch);

  // Per profile:
  //   IKM  = root_key || update_key (concatenated)
  //   Salt = [0u8; 32] (32 zero bytes)
  const ikm = concatBytes(root_key, update_key);
  const salt = new Uint8Array(32);

  try {
    // Output: 64 bytes = new_root_key (32) || new_mac_key (32)
    return await hkdf(ikm, salt, info, 64);
  } finally {
    secureZeroBytes(ikm);
    secureZeroBytes(salt);
  }
}

/**
 * KDF_OK: Derive output key from shared secret
 *
 * Uses HKDF-Expand with zero salt and profile info string.
 *
 * @param shared_secret - ML-KEM shared secret (32 bytes)
 * @param epoch - Epoch number (uint64)
 * @returns 32-byte output key material
 *
 */
export async function KDF_OK(shared_secret: Uint8Array, epoch: bigint): Promise<Uint8Array> {
  // Validate input
  if (shared_secret.length !== 32) {
    throw KDFError.invalidSize('shared_secret', shared_secret.length, 32);
  }

  // Build info string: PROTOCOL_INFO || ":SCKA Key" || ToBytes(epoch)
  const info = buildKdfInfo(':SCKA Key', epoch);

  // Zero-filled salt (hash output length)
  const salt = new Uint8Array(32);

  try {
    // HKDF: IKM = shared_secret, Salt = zeros
    // Output: 32 bytes output key material
    return await hkdf(shared_secret, salt, info, 32);
  } finally {
    secureZeroBytes(salt);
  }
}

// =============================================================================
// Helper functions
// =============================================================================

/**
 * Build KDF info string with protocol info and epoch
 *
 * @param domain - Domain separator (e.g., ":Authenticator Update")
 * @param epoch - Epoch number
 * @returns Concatenated info bytes
 */
function buildKdfInfo(domain: string, epoch: bigint): Uint8Array {
  const protocolInfo = new TextEncoder().encode(PROTOCOL_CONSTANTS.PROTOCOL_INFO);
  const domainBytes = new TextEncoder().encode(domain);
  const epochBytes = uint64ToBytes(epoch);

  // Concatenate: PROTOCOL_INFO || domain || epoch
  const result = new Uint8Array(protocolInfo.length + domainBytes.length + epochBytes.length);

  let offset = 0;
  result.set(protocolInfo, offset);
  offset += protocolInfo.length;
  result.set(domainBytes, offset);
  offset += domainBytes.length;
  result.set(epochBytes, offset);

  return result;
}

/**
 * Convert uint64 to big-endian bytes
 *
 * @param value - BigInt to convert
 * @returns 8-byte big-endian representation
 */
export function uint64ToBytes(value: bigint): Uint8Array {
  const bytes = new Uint8Array(8);
  for (let i = 7; i >= 0; i--) {
    bytes[i] = Number(value & 0xffn);
    value = value >> 8n;
  }
  return bytes;
}

/**
 * Parse big-endian bytes to uint64
 *
 * @param bytes - 8-byte big-endian representation
 * @returns BigInt
 */
export function bytesToUint64(bytes: Uint8Array): bigint {
  if (bytes.length !== 8) {
    throw new Error(`Invalid bytes length: ${bytes.length}, expected 8`);
  }

  let result = 0n;
  for (let i = 0; i < 8; i++) {
    result = (result << 8n) | BigInt(bytes[i]);
  }
  return result;
}
