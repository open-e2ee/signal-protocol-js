/**
 * Ed25519 Digital Signatures
 *
 * Provides Ed25519 key generation, signing, and verification.
 * This SDK's independent profile uses a separate Ed25519 identity component.
 * These functions do not implement XEdDSA.
 *
 * Libraries:
 * - @noble/curves/ed25519 - Ed25519
 *
 * @see https://www.rfc-editor.org/rfc/rfc8032
 */

import { ed25519 } from '@noble/curves/ed25519.js';
import type { PublicKey, PrivateKey, Signature } from '../../../keys';
import { generateRandomBytes } from '../random';
import { bytesToBase64, base64ToBytes, secureZeroBytes } from '../utils';

/**
 * Ed25519 signature size in bytes
 * Used for identity key signatures and prekey signatures
 */
export {};
export const ED25519_SIGNATURE_BYTES = 64;

/**
 * Ed25519 public/private key size in bytes
 */
export const ED25519_KEY_BYTES = 32;

/**
 * Generate signing key pair using Ed25519
 *
 * Ed25519 is a modern EdDSA signature scheme, using Curve25519 as its curve.
 * It provides deterministic signatures (no nonce reuse risk) and
 * is the signing algorithm selected by this SDK's composite-identity profile.
 *
 * Key sizes:
 * - Private key: 32 bytes
 * - Public key: 32 bytes
 *
 * Note: Ed25519 private keys are sometimes represented as 64 bytes, a 32-byte
 * seed plus the 32-byte public key. The `@noble/curves` implementation uses
 * 32-byte private keys, with the public key derived on demand.
 *
 * @returns {publicKey, privateKey} as branded types
 *
 * @see https://www.rfc-editor.org/rfc/rfc8032
 */
export async function generateSigningKeyPair(): Promise<{
  publicKey: PublicKey;
  privateKey: PrivateKey;
}> {
  // Generate 32 random bytes for private key
  const privateKeyBytes = await generateRandomBytes(32);

  try {
    // Derive public key from private key using Ed25519
    const publicKeyBytes = ed25519.getPublicKey(privateKeyBytes);

    return {
      publicKey: bytesToBase64(publicKeyBytes) as PublicKey,
      privateKey: bytesToBase64(privateKeyBytes) as PrivateKey,
    };
  } finally {
    secureZeroBytes(privateKeyBytes);
  }
}

/**
 * Sign data with Ed25519 private key
 *
 * Creates a deterministic digital signature over the provided data.
 * Ed25519 signatures are 64 bytes long and include the message hash.
 *
 * @param privateKeyB64 Ed25519 private key (32 bytes, branded PrivateKey)
 * @param data Data to sign
 * @returns Signature (64 bytes, branded Signature)
 *
 * @see https://www.rfc-editor.org/rfc/rfc8032
 */
export async function sign(privateKeyB64: PrivateKey, data: Uint8Array): Promise<Signature> {
  const privateKeyBytes = base64ToBytes(privateKeyB64);

  try {
    // Sign data with Ed25519 (deterministic, no randomness needed)
    const signature = ed25519.sign(data, privateKeyBytes);

    return bytesToBase64(signature) as Signature;
  } finally {
    secureZeroBytes(privateKeyBytes);
  }
}

/**
 * Verify an Ed25519 signature
 *
 * Verifies that a signature was created by the holder of the private key
 * corresponding to the provided public key.
 *
 * Verification processes public key/signature inputs. JavaScript and the JIT do
 * not provide a hard constant-time contract. Malformed encodings return false.
 * No timing-equivalence claim is made for malformed and valid-but-wrong inputs.
 *
 * @param publicKeyB64 Ed25519 public key (32 bytes, branded PublicKey)
 * @param data Data that was signed
 * @param signatureB64 Signature to verify (64 bytes, branded Signature)
 * @returns true if signature is valid, false otherwise
 *
 * @see https://www.rfc-editor.org/rfc/rfc8032
 */
export async function verify(
  publicKeyB64: PublicKey,
  data: Uint8Array,
  signatureB64: Signature
): Promise<boolean> {
  try {
    const publicKeyBytes = base64ToBytes(publicKeyB64);
    const signatureBytes = base64ToBytes(signatureB64);

    // Verify Ed25519 signature
    const isValid = ed25519.verify(signatureBytes, data, publicKeyBytes);

    return isValid;
  } catch {
    // Return false on any error (invalid key format, etc.)
    return false;
  }
}
