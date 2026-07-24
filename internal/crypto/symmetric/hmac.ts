/**
 * HMAC-SHA256 Operations
 *
 * Provides HMAC (Hash-based Message Authentication Code) using SHA-256.
 *
 * Uses @noble/hashes instead of Web Crypto API because:
 * - react-native-quick-crypto does NOT support HMAC in crypto.subtle.sign()
 * - @noble/hashes is audited (6 audits: Cure53, Trail of Bits, Kudelski)
 * - Zero dependencies, pure TypeScript, RFC 2104 compliant
 * - Funded by Ethereum Foundation, used by ProtonMail, MetaMask, ethers.js
 * - Performance: 600k+ ops/sec (more than sufficient for Signal Protocol)
 *
 * @see https://signal.org/docs/specifications/doubleratchet/#external-functions
 */

import { hmac as nobleHmac } from '@noble/hashes/hmac.js';
import { sha256 as nobleSha256 } from '@noble/hashes/sha2.js';

/**
 * HMAC-SHA256
 *
 * IMPORTANT: This uses proper HMAC (Hash-based Message Authentication Code),
 * not simple concatenation + hashing which would be insecure.
 *
 * Used for:
 * - HKDF-Extract step
 * - KDF_CK chain key derivation
 * - Message authentication in AES-CBC mode
 *
 * @param key HMAC key
 * @param data Data to authenticate
 * @returns 32-byte HMAC
 */
export {};
export function hmac(key: Uint8Array, data: Uint8Array): Uint8Array {
  return nobleHmac(nobleSha256, key, data);
}
