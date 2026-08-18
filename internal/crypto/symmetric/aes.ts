/**
 * AES Encryption Operations
 *
 * Provides AES-256-GCM and AES-256-CBC + HMAC-SHA256 encryption/decryption.
 *
 * Signal Protocol uses two modes:
 * - AES-256-CBC + HMAC-SHA256: For message encryption (spec-compliant)
 * - AES-256-GCM: For modern applications where performance is critical
 *
 * @see https://signal.org/docs/specifications/doubleratchet/#external-functions - ENCRYPT(mk, plaintext, associated_data)
 * @see https://signal.org/docs/specifications/doubleratchet/#recommended-cryptographic-algorithms - AES-256-CBC + HMAC-SHA256
 */

import type { Base64 } from '../../../types';
import { generateRandomBytes } from '../random';
import { bytesToBase64, base64ToBytes, concatBytes, constantTimeEqual } from '../utils';
import { hmac } from './hmac';

// ============================================================================
// Type Utilities
// ============================================================================

/**
 * Narrow Uint8Array<ArrayBufferLike> to Uint8Array<ArrayBuffer> for Web Crypto API.
 *
 * TypeScript 5.x widens Uint8Array to Uint8Array<ArrayBufferLike> which includes
 * SharedArrayBuffer. Web Crypto expects BufferSource backed by ArrayBuffer only.
 * At runtime, our code never creates SharedArrayBuffer, so this cast is safe.
 */
export {};
function buf(value: Uint8Array): Uint8Array<ArrayBuffer>;
function buf(value: Uint8Array | undefined): Uint8Array<ArrayBuffer> | undefined;
function buf(value: Uint8Array | undefined): Uint8Array<ArrayBuffer> | undefined {
  return value as Uint8Array<ArrayBuffer> | undefined;
}

/**
 * AES-GCM parameters for Web Crypto, with the AAD left out when there is none.
 *
 * Omitting an optional dictionary member and setting it to `undefined` are not
 * the same thing here. Node's Web Crypto converts the parameters through WebIDL,
 * where an `undefined` member is absent, and accepts it. Chrome parses them by
 * hand: a present `additionalData` key must be a BufferSource whatever its
 * value, so the call fails with `AeadParams: additionalData: Not a BufferSource`.
 *
 * Every AES-GCM caller that passes no AAD therefore worked under Node and threw
 * in a browser. Device provisioning and device transfer are two such callers,
 * and neither passes AAD at all. Building the parameters in one place is what
 * keeps the next call site from reintroducing it.
 */
function gcmParams(iv: Uint8Array, additionalData?: Uint8Array): AesGcmParams {
  return {
    name: 'AES-GCM',
    iv: buf(iv),
    tagLength: 128, // 128-bit auth tag
    ...(additionalData ? { additionalData: buf(additionalData) } : {}),
  };
}

// ============================================================================
// Constants
// ============================================================================

/**
 * AES-256 key size in bytes
 */
export const AES_256_KEY_BYTES = 32;

/**
 * AES-GCM IV (initialization vector) size in bytes
 */
export const AES_GCM_IV_BYTES = 12;

/**
 * AES-GCM authentication tag size in bytes
 */
export const AES_GCM_TAG_BYTES = 16;

/**
 * AES-CBC IV size in bytes
 */
export const AES_CBC_IV_BYTES = 16;

// ============================================================================
// AES-256-GCM (Modern Mode)
// ============================================================================

/**
 * Encrypt data using AES-256-GCM
 *
 * @param key 256-bit encryption key
 * @param plaintext Data to encrypt
 * @param additionalData Optional additional authenticated data
 * @returns {ciphertext, iv, authTag} as Base64 strings
 */
export async function aesGcmEncrypt(
  key: Uint8Array,
  plaintext: Uint8Array,
  additionalData?: Uint8Array
): Promise<{
  ciphertext: Base64;
  iv: Base64;
  authTag: Base64;
}> {
  // Generate random IV (12 bytes optimal for GCM)
  const iv = await generateRandomBytes(AES_GCM_IV_BYTES);

  // Import key for Web Crypto API
  const cryptoKey = await crypto.subtle.importKey('raw', buf(key), { name: 'AES-GCM' }, false, [
    'encrypt',
  ]);

  // Encrypt
  const encrypted = await crypto.subtle.encrypt(
    gcmParams(iv, additionalData),
    cryptoKey,
    buf(plaintext)
  );

  // Split ciphertext and auth tag
  const encryptedBytes = new Uint8Array(encrypted);
  const ciphertext = encryptedBytes.slice(0, -16); // All but last 16 bytes
  const authTag = encryptedBytes.slice(-16); // Last 16 bytes

  return {
    ciphertext: bytesToBase64(ciphertext),
    iv: bytesToBase64(iv),
    authTag: bytesToBase64(authTag),
  };
}

/**
 * Encrypt data using AES-256-GCM with a pre-generated IV
 *
 * Use this when you need to control the IV generation (e.g., for storage adapters
 * that need to prepend the IV to the ciphertext).
 *
 * @param key 256-bit encryption key
 * @param plaintext Data to encrypt
 * @param iv Pre-generated 12-byte IV
 * @param additionalData Optional additional authenticated data
 * @returns {ciphertext, iv, authTag} as Base64 strings
 */
export async function aesGcmEncryptWithIV(
  key: Uint8Array,
  plaintext: Uint8Array,
  iv: Uint8Array,
  additionalData?: Uint8Array
): Promise<{
  ciphertext: Base64;
  iv: Base64;
  authTag: Base64;
}> {
  // Import key for Web Crypto API
  const cryptoKey = await crypto.subtle.importKey('raw', buf(key), { name: 'AES-GCM' }, false, [
    'encrypt',
  ]);

  // Encrypt
  const encrypted = await crypto.subtle.encrypt(
    gcmParams(iv, additionalData),
    cryptoKey,
    buf(plaintext)
  );

  // Split ciphertext and auth tag
  const encryptedBytes = new Uint8Array(encrypted);
  const ciphertext = encryptedBytes.slice(0, -16); // All but last 16 bytes
  const authTag = encryptedBytes.slice(-16); // Last 16 bytes

  return {
    ciphertext: bytesToBase64(ciphertext),
    iv: bytesToBase64(iv),
    authTag: bytesToBase64(authTag),
  };
}

/**
 * Decrypt data using AES-256-GCM
 *
 * @param key 256-bit decryption key
 * @param ciphertext Encrypted data (Base64)
 * @param iv Initialization vector (Base64)
 * @param authTag Authentication tag (Base64)
 * @param additionalData Optional additional authenticated data
 * @returns Decrypted plaintext
 */
export async function aesGcmDecrypt(
  key: Uint8Array,
  ciphertext: Base64,
  iv: Base64,
  authTag: Base64,
  additionalData?: Uint8Array
): Promise<Uint8Array> {
  const ciphertextBytes = base64ToBytes(ciphertext);
  const ivBytes = base64ToBytes(iv);
  const authTagBytes = base64ToBytes(authTag);

  // Combine ciphertext and auth tag
  const encrypted = new Uint8Array(ciphertextBytes.length + authTagBytes.length);
  encrypted.set(ciphertextBytes, 0);
  encrypted.set(authTagBytes, ciphertextBytes.length);

  // Import key
  const cryptoKey = await crypto.subtle.importKey('raw', buf(key), { name: 'AES-GCM' }, false, [
    'decrypt',
  ]);

  // Decrypt
  const decrypted = await crypto.subtle.decrypt(
    gcmParams(ivBytes, additionalData),
    cryptoKey,
    buf(encrypted)
  );

  return new Uint8Array(decrypted);
}

// ============================================================================
// AES-256-CBC + HMAC-SHA256 (Signal Protocol Specification)
// ============================================================================

/**
 * Encrypt data using AES-256-CBC + HMAC-SHA256 (Signal Protocol)
 *
 * Uses encrypt-then-MAC construction as specified by Signal Protocol:
 * 1. Encrypt plaintext with AES-256-CBC
 * 2. Compute HMAC-SHA256 over (ciphertext || additionalData)
 * 3. Return {ciphertext, mac}
 *
 * This is preferred over AES-GCM for Signal Protocol compliance.
 *
 * @param encryptionKey 32-byte AES-256 encryption key
 * @param authKey 32-byte HMAC-SHA256 authentication key
 * @param iv 16-byte initialization vector
 * @param plaintext Data to encrypt
 * @param additionalData Optional additional authenticated data (e.g., message header)
 * @returns {ciphertext, mac} as Base64 strings
 *
 * @see https://signal.org/docs/specifications/doubleratchet/#external-functions - ENCRYPT(mk, plaintext, associated_data)
 * @see https://signal.org/docs/specifications/doubleratchet/#recommended-cryptographic-algorithms - AES-256-CBC + HMAC-SHA256
 */
export async function aesCbcHmacEncrypt(
  encryptionKey: Uint8Array,
  authKey: Uint8Array,
  iv: Uint8Array,
  plaintext: Uint8Array,
  additionalData?: Uint8Array
): Promise<{
  ciphertext: Base64;
  mac: Base64;
}> {
  // Step 1: Encrypt with AES-256-CBC
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    buf(encryptionKey),
    { name: 'AES-CBC' },
    false,
    ['encrypt']
  );

  const encrypted = await crypto.subtle.encrypt(
    {
      name: 'AES-CBC',
      iv: buf(iv),
    },
    cryptoKey,
    buf(plaintext)
  );

  const ciphertextBytes = new Uint8Array(encrypted);

  // Step 2: Compute MAC over (ciphertext || additionalData)
  const macInput = additionalData ? concatBytes(ciphertextBytes, additionalData) : ciphertextBytes;

  const macBytes = hmac(authKey, macInput);

  return {
    ciphertext: bytesToBase64(ciphertextBytes),
    mac: bytesToBase64(macBytes),
  };
}

/**
 * Decrypt data using AES-256-CBC + HMAC-SHA256 (Signal Protocol)
 *
 * Uses verify-then-decrypt pattern as specified by Signal Protocol:
 * 1. Verify HMAC-SHA256 over (ciphertext || additionalData)
 * 2. If valid, decrypt with AES-256-CBC
 * 3. Return plaintext
 *
 * Uses the best-effort full-scan comparison helper for equal-length MACs.
 * JavaScript/JIT execution has no hard constant-time guarantee.
 *
 * @param encryptionKey 32-byte AES-256 decryption key
 * @param authKey 32-byte HMAC-SHA256 authentication key
 * @param iv 16-byte initialization vector
 * @param ciphertext Encrypted data (Base64)
 * @param mac Message authentication code (Base64)
 * @param additionalData Optional additional authenticated data
 * @returns Decrypted plaintext
 * @throws Error with generic "Authentication failed" message (prevents fingerprinting)
 *
 * @see https://signal.org/docs/specifications/doubleratchet/#external-functions - DECRYPT(mk, ciphertext, associated_data)
 * @see https://signal.org/docs/specifications/doubleratchet/#recommended-cryptographic-algorithms - AES-256-CBC + HMAC-SHA256
 * @see https://signal.org/docs/specifications/doubleratchet/#implementation-fingerprinting - Error message handling
 */
export async function aesCbcHmacDecrypt(
  encryptionKey: Uint8Array,
  authKey: Uint8Array,
  iv: Uint8Array,
  ciphertext: Base64,
  mac: Base64,
  additionalData?: Uint8Array
): Promise<Uint8Array> {
  const ciphertextBytes = base64ToBytes(ciphertext);
  const macBytes = base64ToBytes(mac);

  // Step 1: Verify MAC (verify-then-decrypt pattern)
  const macInput = additionalData ? concatBytes(ciphertextBytes, additionalData) : ciphertextBytes;

  const expectedMac = hmac(authKey, macInput);

  // Best-effort full-scan comparison for the fixed-size MAC.
  if (!constantTimeEqual(macBytes, expectedMac)) {
    // Generic error - do not reveal that MAC verification failed specifically
    // This prevents implementation fingerprinting (Section 8.7)
    throw new Error('Authentication failed');
  }

  // Step 2: Decrypt with AES-256-CBC
  try {
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      buf(encryptionKey),
      { name: 'AES-CBC' },
      false,
      ['decrypt']
    );

    const decrypted = await crypto.subtle.decrypt(
      {
        name: 'AES-CBC',
        iv: buf(iv),
      },
      cryptoKey,
      buf(ciphertextBytes)
    );

    return new Uint8Array(decrypted);
  } catch {
    // Normalize all decryption errors to prevent distinguishing failure modes
    // This prevents implementation fingerprinting (Section 8.7)
    throw new Error('Authentication failed');
  }
}

/**
 * AES-256-CBC encryption without MAC computation
 *
 * Use this when MAC is computed separately (e.g., identity-bound MAC in Section 3).
 * The caller is responsible for computing and appending the MAC.
 *
 * @param encryptionKey 256-bit encryption key
 * @param iv 128-bit initialization vector
 * @param plaintext Data to encrypt
 * @returns Base64-encoded ciphertext
 */
export async function aesCbcEncrypt(
  encryptionKey: Uint8Array,
  iv: Uint8Array,
  plaintext: Uint8Array
): Promise<Base64> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    buf(encryptionKey),
    { name: 'AES-CBC' },
    false,
    ['encrypt']
  );

  const encrypted = await crypto.subtle.encrypt(
    {
      name: 'AES-CBC',
      iv: buf(iv),
    },
    cryptoKey,
    buf(plaintext)
  );

  return bytesToBase64(new Uint8Array(encrypted));
}

/**
 * AES-256-CBC decryption without MAC verification
 *
 * Use this when MAC verification is done separately (e.g., identity-bound MAC).
 * The caller is responsible for verifying the MAC before calling this function.
 *
 * @param encryptionKey 256-bit encryption key
 * @param iv 128-bit initialization vector
 * @param ciphertext Base64-encoded ciphertext
 * @returns Decrypted plaintext bytes
 */
export async function aesCbcDecrypt(
  encryptionKey: Uint8Array,
  iv: Uint8Array,
  ciphertext: Base64
): Promise<Uint8Array> {
  try {
    // Decode inside the try so malformed Base64 normalizes to the same
    // "Decryption failed" error rather than leaking a distinguishable message.
    const ciphertextBytes = base64ToBytes(ciphertext);

    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      buf(encryptionKey),
      { name: 'AES-CBC' },
      false,
      ['decrypt']
    );

    const decrypted = await crypto.subtle.decrypt(
      {
        name: 'AES-CBC',
        iv: buf(iv),
      },
      cryptoKey,
      buf(ciphertextBytes)
    );

    return new Uint8Array(decrypted);
  } catch {
    // Normalize all decryption errors to prevent distinguishing failure modes
    throw new Error('Decryption failed');
  }
}

// ============================================================================
// Raw Bytes AES-CBC (for Username Link Encryption)
// ============================================================================

/**
 * AES-256-CBC encryption without MAC, returning raw bytes.
 *
 * Unlike aesCbcEncrypt which returns Base64, this returns raw ciphertext bytes
 * (with PKCS#7 padding applied by Web Crypto).
 *
 * Used by username link encryption where MAC is computed separately over [IV || ciphertext].
 *
 * @param encryptionKey 256-bit encryption key
 * @param iv 128-bit initialization vector
 * @param plaintext Data to encrypt
 * @returns Raw ciphertext bytes
 */
export async function aesCbcEncryptBytes(
  encryptionKey: Uint8Array,
  iv: Uint8Array,
  plaintext: Uint8Array
): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    buf(encryptionKey),
    { name: 'AES-CBC' },
    false,
    ['encrypt']
  );

  const encrypted = await crypto.subtle.encrypt(
    {
      name: 'AES-CBC',
      iv: buf(iv),
    },
    cryptoKey,
    buf(plaintext)
  );

  return new Uint8Array(encrypted);
}

/**
 * AES-256-CBC decryption without MAC, from raw bytes.
 *
 * Unlike aesCbcDecrypt which accepts Base64, this accepts raw ciphertext bytes
 * and returns raw plaintext bytes (PKCS#7 padding stripped by Web Crypto).
 *
 * Used by username link decryption where MAC is verified separately before calling this.
 *
 * @param encryptionKey 256-bit decryption key
 * @param iv 128-bit initialization vector
 * @param ciphertext Raw ciphertext bytes
 * @returns Decrypted plaintext bytes
 */
export async function aesCbcDecryptBytes(
  encryptionKey: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array
): Promise<Uint8Array> {
  try {
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      buf(encryptionKey),
      { name: 'AES-CBC' },
      false,
      ['decrypt']
    );

    const decrypted = await crypto.subtle.decrypt(
      {
        name: 'AES-CBC',
        iv: buf(iv),
      },
      cryptoKey,
      buf(ciphertext)
    );

    return new Uint8Array(decrypted);
  } catch {
    throw new Error('Decryption failed');
  }
}

// ============================================================================
// Raw Bytes API (for Streaming AEAD)
// ============================================================================

/**
 * Encrypt data using AES-256-GCM with explicit IV, returning raw bytes
 *
 * Unlike aesGcmEncryptWithIV which returns Base64 strings, this returns
 * the raw ciphertext || authTag concatenated as Uint8Array.
 *
 * Used by streaming AEAD where we control the nonce and need raw bytes.
 *
 * @param key 256-bit encryption key
 * @param plaintext Data to encrypt
 * @param iv 12-byte IV/nonce
 * @param additionalData Optional additional authenticated data
 * @returns Ciphertext || authTag as raw bytes
 */
export async function aesGcmEncryptWithIVBytes(
  key: Uint8Array,
  plaintext: Uint8Array,
  iv: Uint8Array,
  additionalData?: Uint8Array
): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey('raw', buf(key), { name: 'AES-GCM' }, false, [
    'encrypt',
  ]);

  const encrypted = await crypto.subtle.encrypt(
    gcmParams(iv, additionalData),
    cryptoKey,
    buf(plaintext)
  );

  return new Uint8Array(encrypted); // ciphertext || authTag (16 bytes)
}

/**
 * Decrypt data using AES-256-GCM with explicit IV, from raw bytes
 *
 * Input is ciphertext || authTag concatenated as Uint8Array.
 * Used by streaming AEAD where we control the nonce.
 *
 * @param key 256-bit decryption key
 * @param ciphertext Encrypted data || authTag (16 bytes) as raw bytes
 * @param iv 12-byte IV/nonce
 * @param additionalData Optional additional authenticated data
 * @returns Decrypted plaintext
 * @throws Error if decryption or authentication fails
 */
export async function aesGcmDecryptWithIVBytes(
  key: Uint8Array,
  ciphertext: Uint8Array,
  iv: Uint8Array,
  additionalData?: Uint8Array
): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey('raw', buf(key), { name: 'AES-GCM' }, false, [
    'decrypt',
  ]);

  const decrypted = await crypto.subtle.decrypt(
    gcmParams(iv, additionalData),
    cryptoKey,
    buf(ciphertext)
  );

  return new Uint8Array(decrypted);
}

// Spec-compliant aliases (uppercase for specification matching)
export const ENCRYPT = aesCbcHmacEncrypt;
export const DECRYPT = aesCbcHmacDecrypt;

// Note: The Signal Protocol Section 3 ENCRYPT/DECRYPT functions include
// identity-bound MAC (AD includes sender/receiver identity keys). The raw
// aesCbcHmacEncrypt/aesCbcHmacDecrypt functions are primitives that do not
// include this binding. Use the cipher layer for full protocol compliance.
