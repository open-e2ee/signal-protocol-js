/**
 * X25519 Elliptic Curve Diffie-Hellman
 *
 * Provides X25519 (Curve25519) key generation and shared secret computation.
 * X25519 is the standard ECDH function used throughout the Signal Protocol.
 *
 * Libraries:
 * - @noble/curves/ed25519 - X25519
 *
 * @see https://signal.org/docs/specifications/doubleratchet/#external-functions - GENERATE_DH()
 * @see https://signal.org/docs/specifications/x3dh/#cryptographic-notation - DH function definition
 */

import { x25519 } from '@noble/curves/ed25519.js';
import type { PublicKey, PrivateKey } from '../../../keys';
import type { Base64 } from '../../../types/utils';
import { generateRandomBytes } from '../random';
import { bytesToBase64, base64ToBytes, secureZeroBytes, constantTimeEqual } from '../utils';
import { validateX25519KeyPair } from '../validation';

// ============================================================================
// ECDH Shared Secret Branded Type
// ============================================================================
export {};
declare const __brand_ecdh_shared: unique symbol;

/**
 * ECDH shared secret from X25519 key agreement.
 *
 * Security: This is RAW key material. MUST be passed through KDF (HKDF)
 * before use as an encryption key.
 *
 * Size: 32 bytes (X25519 output)
 *
 * @see https://signal.org/docs/specifications/doubleratchet/#external-functions - DH(dh_pair, dh_pub)
 */
export type ECDHSharedSecret = Uint8Array & {
  readonly [__brand_ecdh_shared]: true;
};

/**
 * Size of ECDH shared secret in bytes (X25519)
 */
export const ECDH_SHARED_SECRET_BYTES = 32;

/**
 * Assert raw bytes as ECDH shared secret.
 *
 * @param bytes - Raw bytes from X25519 computation (must be 32 bytes)
 * @returns Branded ECDHSharedSecret
 * @throws Error if bytes are not 32 bytes
 */
export function asECDHSharedSecret(bytes: Uint8Array): ECDHSharedSecret {
  if (bytes.length !== 32) {
    throw new Error(`ECDH shared secret must be 32 bytes, got ${bytes.length}`);
  }
  return bytes as ECDHSharedSecret;
}

/**
 * Check if a value could be an ECDH shared secret (32 bytes).
 *
 * Note: This only validates length, not cryptographic properties.
 */
export function isValidECDHLength(bytes: Uint8Array): boolean {
  return bytes.length === 32;
}

// ============================================================================
// X25519 Key Generation and Exchange
// ============================================================================

/**
 * X25519 key size in bytes
 * Used for Diffie-Hellman key exchange
 */
export const X25519_KEY_BYTES = 32;

/**
 * Generate ECDH key pair for key exchange using X25519 (Curve25519)
 *
 * Uses X25519 from @noble/curves for Signal Protocol compliance.
 * X25519 is the standard elliptic curve Diffie-Hellman function using Curve25519.
 *
 * Key sizes:
 * - Private key: 32 bytes
 * - Public key: 32 bytes
 *
 * @returns {publicKey, privateKey} as branded types
 *
 * @see https://signal.org/docs/specifications/doubleratchet/#external-functions - GENERATE_DH()
 * @see https://signal.org/docs/specifications/x3dh/#cryptographic-notation - DH function definition
 */
export async function generateECDHKeyPair(): Promise<{
  publicKey: PublicKey;
  privateKey: PrivateKey;
}> {
  // Generate 32 random bytes for private key
  const privateKeyBytes = await generateRandomBytes(32);

  try {
    // Derive public key from private key using X25519
    const publicKeyBytes = x25519.getPublicKey(privateKeyBytes);

    const publicKey = bytesToBase64(publicKeyBytes) as PublicKey;
    const privateKey = bytesToBase64(privateKeyBytes) as PrivateKey;

    // Sanity check: validate key pair before returning
    // Should never fail unless crypto library has bug or memory corruption
    validateX25519KeyPair(publicKey, privateKey, 'generateECDHKeyPair');

    return { publicKey, privateKey };
  } finally {
    secureZeroBytes(privateKeyBytes);
  }
}

/**
 * Perform ECDH key agreement to compute shared secret using X25519
 *
 * Computes the shared secret between our private key and their public key.
 * This is the core of the Diffie-Hellman key exchange.
 *
 * Security Note: The returned ECDHSharedSecret is RAW key material and MUST
 * be passed through a KDF (HKDF) before use as an encryption key.
 *
 * @param privateKeyB64 Our private key (32 bytes, base64-encoded)
 * @param publicKeyB64 Their public key (32 bytes, base64-encoded)
 * @returns Branded ECDHSharedSecret (32 bytes)
 *
 * @see https://signal.org/docs/specifications/doubleratchet/#external-functions - DH(dh_pair, dh_pub)
 * @see https://signal.org/docs/specifications/x3dh/#cryptographic-notation - DH function definition
 */
export async function computeSharedSecret(
  privateKeyB64: Base64,
  publicKeyB64: Base64
): Promise<ECDHSharedSecret> {
  const privateKeyBytes = base64ToBytes(privateKeyB64);

  try {
    const publicKeyBytes = base64ToBytes(publicKeyB64);

    // Validate key sizes (X25519 requires exactly 32 bytes)
    if (privateKeyBytes.length !== X25519_KEY_BYTES) {
      throw new Error(
        `Invalid X25519 private key: expected ${X25519_KEY_BYTES} bytes, got ${privateKeyBytes.length}`
      );
    }
    if (publicKeyBytes.length !== X25519_KEY_BYTES) {
      throw new Error(
        `Invalid X25519 public key: expected ${X25519_KEY_BYTES} bytes, got ${publicKeyBytes.length}`
      );
    }

    // Perform X25519 key agreement
    const sharedSecret = x25519.getSharedSecret(privateKeyBytes, publicKeyBytes);

    // Reject an invalid all-zero shared secret after a full byte scan.
    if (constantTimeEqual(sharedSecret, new Uint8Array(X25519_KEY_BYTES))) {
      throw new Error('Invalid X25519 key agreement output: all-zero shared secret');
    }

    return asECDHSharedSecret(sharedSecret);
  } finally {
    secureZeroBytes(privateKeyBytes);
  }
}

// Spec-compliant aliases (uppercase for specification matching)
export const GENERATE_DH = generateECDHKeyPair;
export const DH = computeSharedSecret;
