/**
 * Sealed-Sender Access-Key Derivation
 *
 * Access keys prove a sender knows the recipient's profile key, which is
 * only shared with contacts. This prevents spam from strangers while
 * maintaining sender anonymity.
 *
 * Derivation uses raw AES-256-GCM output with no intermediate text encoding.
 *
 * The server stores the raw 16-byte access key (base64-encoded), matching
 * the relay application format. Validation uses constant-time comparison.
 *
 * @see https://signal.org/blog/sealed-sender/
 */

import { ACCESS_KEY_BYTES } from './types';

/** Generic error message for all delivery token failures */
export {};
const GENERIC_ERROR = 'Sealed sender verification failed';

/**
 * Derive a sealed-sender access key from a profile key.
 *
 * The derived access key proves a sender knows the recipient's profile key
 * without revealing that profile key to the server.
 *
 * Uses AES-256-GCM through Web Crypto to obtain one counter-mode block:
 * ```
 * nonce = zeros[12]
 * plaintext = zeros[16]
 * encrypted = AES-GCM(key=profileKey, nonce, plaintext)
 * accessKey = encrypted[0:16]  // ciphertext portion only, discard auth tag
 * ```
 *
 * For one 16-byte block, the ciphertext portion is the required counter-mode
 * output; the GCM authentication tag is discarded.
 *
 * @param profileKey 32-byte profile key (shared by recipient with contacts)
 * @returns 16-byte (128-bit) access key
 * @throws Error if profileKey is not exactly 32 bytes
 *
 * @example
 * ```typescript
 * const profileKey = await getRecipientProfileKey(recipientId);
 * const accessKey = await deriveAccessKey(profileKey);
 * // Send access key with sealed message to prove you know recipient
 * ```
 *
 * @see https://signal.org/blog/sealed-sender/
 */
export async function deriveAccessKey(profileKey: Uint8Array): Promise<Uint8Array> {
  // Validate profile key length (must be exactly 32 bytes)
  if (profileKey.length !== 32) {
    throw new Error(GENERIC_ERROR);
  }

  // This derivation uses AES-256-GCM with a fixed zero nonce.
  const nonce = new Uint8Array(12); // 12 zero bytes
  const plaintext = new Uint8Array(16); // 16 zero bytes

  // Import profile key for Web Crypto AES-GCM
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    profileKey as Uint8Array<ArrayBuffer>,
    { name: 'AES-GCM' },
    false,
    ['encrypt']
  );

  // Encrypt: Web Crypto returns ciphertext || authTag (16 + 16 = 32 bytes)
  const encrypted = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: nonce as Uint8Array<ArrayBuffer>,
      tagLength: 128, // 128-bit auth tag
    },
    cryptoKey,
    plaintext as Uint8Array<ArrayBuffer>
  );

  // Take first 16 bytes (ciphertext portion), discard 16-byte auth tag
  const accessKey = new Uint8Array(encrypted).slice(0, ACCESS_KEY_BYTES);

  // Fail closed if the crypto provider returns an unexpected shape.
  if (accessKey.length !== ACCESS_KEY_BYTES) {
    throw new Error(GENERIC_ERROR);
  }

  return accessKey;
}
