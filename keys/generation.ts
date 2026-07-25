/**
 * Signal Protocol Key Generation
 *
 * Pure functions for generating Signal Protocol keys.
 * These are stateless and don't interact with storage.
 *
 * @see https://signal.org/docs/specifications/x3dh/#keys
 */

import {
  generateECDHKeyPair,
  generateSigningKeyPair,
  generateMlKem1024KeyPair,
  generateRandomBytes,
  base64ToBytes,
  bytesToBase64,
  secureZeroBytes,
} from '../internal/crypto';
import type {
  IdentityKeyPair,
  EcSignedPreKey,
  EcOneTimePreKey,
  KyberPreKey,
  KemOneTimePreKey,
} from './types';
import type { PublicKey, PrivateKey, Signature } from './branded';
import {
  PREKEY_ALGORITHM_ML_KEM_1024,
  PREKEY_ALGORITHM_X25519,
  signPreKey,
} from './prekey-signature';

/**
 * Generate random registration ID
 *
 * Range: 1 to 16383, the largest value that survives the 14-bit `0x3FFF` mask
 * the multi-recipient sealed sender format applies to registration IDs. A
 * generated 16384 would mask to 0 on the wire, so the range excludes it.
 *
 * Uses CSPRNG (generateRandomBytes) instead of Math.random() for
 * cryptographic security.
 */
export {};
export async function generateRegistrationId(): Promise<number> {
  const bytes = await generateRandomBytes(2);
  return (((bytes[0]! << 8) | bytes[1]!) % 16383) + 1;
}

/**
 * Generate identity key pair
 *
 * Creates the long-lived identity key pair consisting of:
 * - DH key pair for X3DH/PQXDH key agreement
 * - Signing key pair for prekey signatures
 * - Registration ID for session reset detection
 *
 * @see https://signal.org/docs/specifications/x3dh/#keys
 */
export async function generateIdentityKeyPair(): Promise<IdentityKeyPair> {
  // Generate ECDH key for key exchange
  const dhKeyPair = await generateECDHKeyPair();

  // Generate signing key for prekey signatures
  const signingKeyPair = await generateSigningKeyPair();

  return {
    dhKey: dhKeyPair,
    signingKey: signingKeyPair,
    registrationId: await generateRegistrationId(),
  };
}

/**
 * Generate EC signed prekey ID
 *
 * Returns a random ID for EC signed prekeys.
 * Range: 0 to 999,999
 *
 * Uses CSPRNG (generateRandomBytes) instead of Math.random() for
 * cryptographic security.
 */
export async function generateEcSignedPreKeyId(): Promise<number> {
  const bytes = await generateRandomBytes(3);
  return ((bytes[0]! << 16) | (bytes[1]! << 8) | bytes[2]!) % 1000000;
}

/**
 * Generate EC signed prekey
 *
 * Creates an EC signed prekey that includes:
 * - ECDH key pair for key agreement
 * - Signature over public key using identity signing key
 * - Timestamp for rotation tracking
 *
 * @param identityKeyPair Complete composite identity key pair for contextual signing
 * @param id Optional prekey ID (random if not provided)
 *
 * @see https://signal.org/docs/specifications/x3dh/#keys
 * @see https://signal.org/docs/specifications/x3dh/#publishing-keys
 */
export async function generateEcSignedPreKey(
  identityKeyPair: IdentityKeyPair,
  id?: number
): Promise<EcSignedPreKey> {
  // Generate ECDH key pair for the prekey
  const prekeyPair = await generateECDHKeyPair();

  const keyId = id ?? (await generateEcSignedPreKeyId());
  const publicKeyBytes = base64ToBytes(prekeyPair.publicKey);
  const signature = await signPreKey(
    identityKeyPair,
    PREKEY_ALGORITHM_X25519,
    keyId,
    publicKeyBytes
  );

  // Zero intermediate copy of public key bytes after signing
  secureZeroBytes(publicKeyBytes);

  return {
    keyId,
    publicKey: prekeyPair.publicKey,
    privateKey: prekeyPair.privateKey,
    signature,
    timestamp: Date.now(),
  };
}

/**
 * Generate batch of EC one-time prekeys
 *
 * Creates multiple EC one-time prekeys for X3DH.
 * Each key can only be used once for forward secrecy.
 *
 * @param count Number of prekeys to generate
 * @param startId Starting ID for sequential assignment
 *
 * @see https://signal.org/docs/specifications/x3dh/#keys
 * @see https://signal.org/docs/specifications/x3dh/#publishing-keys
 */
export async function generateEcOneTimePreKeys(
  count: number,
  startId: number = 0
): Promise<EcOneTimePreKey[]> {
  const prekeys: EcOneTimePreKey[] = [];

  for (let i = 0; i < count; i++) {
    // Generate ECDH key pair for each one-time prekey
    const keyPair = await generateECDHKeyPair();

    prekeys.push({
      keyId: startId + i,
      publicKey: keyPair.publicKey,
      privateKey: keyPair.privateKey,
    });
  }

  return prekeys;
}

/**
 * Generate Kyber prekey for PQXDH
 *
 * Creates a post-quantum prekey using ML-KEM-1024 (Kyber).
 * Per PQXDH spec Section 3.2, this is a "signed last-resort" prekey
 * that rotates periodically, always using ID 1.
 *
 * @param identityKeyPair Complete composite identity key pair for contextual signing
 * @param id Optional prekey ID (default: 1 per PQXDH spec)
 *
 * @see https://signal.org/docs/specifications/pqxdh/
 */
export async function generateKyberLastResortPreKey(
  identityKeyPair: IdentityKeyPair,
  id: number = 1
): Promise<KyberPreKey> {
  // Generate Kyber keypair
  const kyberKeyPair = await generateMlKem1024KeyPair();
  try {
    // Sign Kyber public key with identity signing key
    const signature = await signPreKey(
      identityKeyPair,
      PREKEY_ALGORITHM_ML_KEM_1024,
      id,
      kyberKeyPair.publicKey
    );

    // Convert to Base64 for storage (creates immutable JS strings).
    return {
      keyId: id,
      publicKey: bytesToBase64(kyberKeyPair.publicKey) as PublicKey,
      privateKey: bytesToBase64(kyberKeyPair.privateKey) as PrivateKey,
      signature: signature as Signature,
      timestamp: Date.now(),
    };
  } finally {
    // Best-effort JS cleanup on success and every signing/encoding failure.
    secureZeroBytes(kyberKeyPair.publicKey);
    secureZeroBytes(kyberKeyPair.privateKey);
  }
}

/**
 * Generate batch of KEM one-time prekeys (post-quantum)
 *
 * Creates multiple one-time Kyber prekeys for PQXDH.
 * Each key can only be used once for per-session post-quantum forward secrecy.
 *
 * Per PQXDH spec Section 3.2, these are signed one-time pqkem prekeys
 * that the server prefers over the last-resort KEM prekey.
 *
 * Uses the same batch size as EC one-time prekeys (the reference implementation uses 100 for both).
 *
 * @param identityKeyPair Complete composite identity key pair for contextual signing
 * @param count Number of prekeys to generate
 * @param startId Starting ID for sequential assignment
 *
 * @see https://signal.org/docs/specifications/pqxdh/#sending-the-initial-message
 */
export async function generateKemOneTimePreKeys(
  identityKeyPair: IdentityKeyPair,
  count: number,
  startId: number = 0
): Promise<KemOneTimePreKey[]> {
  const prekeys: KemOneTimePreKey[] = [];
  const now = Date.now();

  for (let i = 0; i < count; i++) {
    // Generate Kyber keypair (ML-KEM-1024)
    const kyberKeyPair = await generateMlKem1024KeyPair();
    try {
      // Sign Kyber public key with identity signing key
      const keyId = startId + i;
      const signature = await signPreKey(
        identityKeyPair,
        PREKEY_ALGORITHM_ML_KEM_1024,
        keyId,
        kyberKeyPair.publicKey
      );

      // Convert to Base64 for storage (creates immutable JS strings).
      prekeys.push({
        keyId,
        publicKey: bytesToBase64(kyberKeyPair.publicKey) as PublicKey,
        privateKey: bytesToBase64(kyberKeyPair.privateKey) as PrivateKey,
        signature: signature as Signature,
        timestamp: now,
      });
    } finally {
      // Best-effort JS cleanup on success and every signing/encoding failure.
      secureZeroBytes(kyberKeyPair.publicKey);
      secureZeroBytes(kyberKeyPair.privateKey);
    }
  }

  return prekeys;
}
