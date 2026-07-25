/**
 * ML-KEM Post-Quantum Cryptography (Tiered Security Model)
 *
 * The reference implementation uses different ML-KEM variants for different protocols:
 *
 * | Protocol | Variant      | NIST Level | Usage              |
 * |----------|--------------|------------|--------------------|
 * | PQXDH    | ML-KEM-1024  | 5 (256-bit)| Initial key exchange |
 * | SPQR     | ML-KEM-768   | 3 (192-bit)| Continuous ratchet |
 *
 * Rationale:
 * - PQXDH: Session establishment happens once - maximum security preferred
 * - SPQR: Continuous ratchet every ~50 messages - bandwidth efficiency critical
 *   (ML-KEM-768: 2,272 bytes/ratchet vs ML-KEM-1024: 3,136 bytes)
 *
 * Libraries:
 * - @noble/post-quantum - ML-KEM-768 and ML-KEM-1024 (NIST FIPS 203)
 *
 * @see https://signal.org/docs/specifications/pqxdh/ - PQXDH specification
 * @see https://signal.org/blog/spqr/ - SPQR specification
 * @see https://csrc.nist.gov/pubs/fips/203/final - NIST FIPS 203
 */

import { ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js';

// ============================================================================
// Kyber Shared Secret Branded Type
// ============================================================================
export {};
declare const __brand_kyber_shared: unique symbol;

/**
 * Kyber shared secret from ML-KEM-1024 encapsulation/decapsulation.
 *
 * Security: This is RAW key material. MUST be passed through KDF (HKDF)
 * before use as an encryption key, typically combined with ECDH output
 * for hybrid security.
 *
 * Size: 32 bytes (ML-KEM-1024 shared secret)
 *
 * @see https://signal.org/docs/specifications/pqxdh/ - Kyber shared secret
 * @see https://csrc.nist.gov/pubs/fips/203/final - NIST FIPS 203
 */
export type KyberSharedSecret = Uint8Array & {
  readonly [__brand_kyber_shared]: true;
};

/**
 * Assert raw bytes as Kyber shared secret.
 *
 * @param bytes - Raw bytes from Kyber encapsulation/decapsulation (must be 32 bytes)
 * @returns Branded KyberSharedSecret
 * @throws Error if bytes are not 32 bytes
 */
export function asKyberSharedSecret(bytes: Uint8Array): KyberSharedSecret {
  if (bytes.length !== 32) {
    throw new Error(`Kyber shared secret must be 32 bytes, got ${bytes.length}`);
  }
  return bytes as KyberSharedSecret;
}

/**
 * Check if a value could be a Kyber shared secret (32 bytes).
 *
 * Note: This only validates length, not cryptographic properties.
 */
export function isValidKyberLength(bytes: Uint8Array): boolean {
  return bytes.length === 32;
}

// ============================================================================
// Constants
// ============================================================================

/**
 * ML-KEM-1024 (CRYSTALS-Kyber-1024) public key size in bytes
 * @see https://csrc.nist.gov/pubs/fips/203/final
 */
export const ML_KEM_1024_RAW_PUBLIC_KEY_BYTES = 1568;
export const ML_KEM_1024_ALGORITHM_TAG = 0x0a;
export const ML_KEM_1024_PUBLIC_KEY_BYTES = 1 + ML_KEM_1024_RAW_PUBLIC_KEY_BYTES;

/**
 * ML-KEM-1024 private/secret key size in bytes
 * @see https://csrc.nist.gov/pubs/fips/203/final
 */
export const ML_KEM_1024_PRIVATE_KEY_BYTES = 3168;

/**
 * ML-KEM-1024 ciphertext size in bytes
 * @see https://csrc.nist.gov/pubs/fips/203/final
 */
export const ML_KEM_1024_RAW_CIPHERTEXT_BYTES = 1568;
export const ML_KEM_1024_CIPHERTEXT_BYTES = 1 + ML_KEM_1024_RAW_CIPHERTEXT_BYTES;

/**
 * ML-KEM-1024 shared secret size in bytes
 */
export const ML_KEM_1024_SHARED_SECRET_BYTES = 32;

// ============================================================================
// ML-KEM-768 Constants (for SPQR)
// ============================================================================

/**
 * ML-KEM-768 public key size in bytes
 * Used for SPQR continuous ratchet (bandwidth-efficient)
 * @see https://csrc.nist.gov/pubs/fips/203/final
 */
export const KYBER_768_PUBLIC_KEY_BYTES = 1184;

/**
 * ML-KEM-768 private/secret key size in bytes
 * @see https://csrc.nist.gov/pubs/fips/203/final
 */
export const KYBER_768_SECRET_KEY_BYTES = 2400;

/**
 * ML-KEM-768 ciphertext size in bytes
 * @see https://csrc.nist.gov/pubs/fips/203/final
 */
export const KYBER_768_CIPHERTEXT_BYTES = 1088;

/**
 * ML-KEM-768 shared secret size in bytes (same as 1024)
 */
export const KYBER_768_SHARED_SECRET_BYTES = 32;

// ============================================================================
// ML-KEM-1024 Key Generation (for PQXDH)
// ============================================================================

/**
 * Generate Kyber-1024 key pair for post-quantum security
 *
 * Uses @noble/post-quantum implementation of ML-KEM-1024 (NIST FIPS 203).
 * Uses the standardized ML-KEM-1024 parameter set. This package is not a
 * FIPS-validated module and makes no standalone end-to-end security claim.
 *
 * Key Sizes:
 * - Public key: 0x0A tag plus 1568 raw bytes
 * - Private key (secretKey): 3168 raw bytes
 *
 * @returns {publicKey, privateKey} as Uint8Arrays
 *
 * @see https://signal.org/docs/specifications/pqxdh/ - PQXDH specification
 * @see https://signal.org/docs/specifications/pqxdh/#key-types - Kyber-1024 key format
 */
export function serializeMlKem1024PublicKey(rawPublicKey: Uint8Array): Uint8Array {
  if (rawPublicKey.length !== ML_KEM_1024_RAW_PUBLIC_KEY_BYTES) {
    throw new Error(
      `ML-KEM-1024 raw public key must be ${ML_KEM_1024_RAW_PUBLIC_KEY_BYTES} bytes`
    );
  }
  return new Uint8Array([ML_KEM_1024_ALGORITHM_TAG, ...rawPublicKey]);
}

export function parseMlKem1024PublicKey(serialized: Uint8Array): Uint8Array {
  if (serialized.length !== ML_KEM_1024_PUBLIC_KEY_BYTES) {
    throw new Error(
      `ML-KEM-1024 public key must be tagged and contain ${ML_KEM_1024_PUBLIC_KEY_BYTES} bytes`
    );
  }
  if (serialized[0] !== ML_KEM_1024_ALGORITHM_TAG) {
    throw new Error(`Unsupported ML-KEM-1024 public-key tag: ${String(serialized[0])}`);
  }
  return serialized.slice(1);
}

export function serializeMlKem1024Ciphertext(rawCiphertext: Uint8Array): Uint8Array {
  if (rawCiphertext.length !== ML_KEM_1024_RAW_CIPHERTEXT_BYTES) {
    throw new Error(
      `ML-KEM-1024 raw ciphertext must be ${ML_KEM_1024_RAW_CIPHERTEXT_BYTES} bytes`
    );
  }
  return new Uint8Array([ML_KEM_1024_ALGORITHM_TAG, ...rawCiphertext]);
}

export function parseMlKem1024Ciphertext(serialized: Uint8Array): Uint8Array {
  if (serialized.length !== ML_KEM_1024_CIPHERTEXT_BYTES) {
    throw new Error(
      `ML-KEM-1024 ciphertext must be tagged and contain ${ML_KEM_1024_CIPHERTEXT_BYTES} bytes`
    );
  }
  if (serialized[0] !== ML_KEM_1024_ALGORITHM_TAG) {
    throw new Error(`Unsupported ML-KEM-1024 ciphertext tag: ${String(serialized[0])}`);
  }
  return serialized.slice(1);
}

export async function generateMlKem1024KeyPair(): Promise<{
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}> {
  // Generate ML-KEM-1024 keypair
  // Note: ml_kem1024.keygen() accepts optional 64-byte seed for deterministic generation
  const keyPair = ml_kem1024.keygen();

  return {
    publicKey: serializeMlKem1024PublicKey(keyPair.publicKey),
    privateKey: keyPair.secretKey,
  };
}

// ============================================================================
// KEM Operations
// ============================================================================

/**
 * Kyber KEM Encapsulation
 *
 * Performs ML-KEM-1024 encapsulation to derive shared secret.
 * Used by initiator (Alice) to establish shared secret with responder (Bob).
 *
 * Security Note: The returned KyberSharedSecret is RAW key material and MUST
 * be combined with ECDH output via KDF for hybrid security.
 *
 * @param kyberPublicKey Partner's Kyber public key (1568 bytes)
 * @returns Branded KyberSharedSecret (32 bytes) and ciphertext (1568 bytes)
 *
 * @see https://signal.org/docs/specifications/pqxdh/ - PQXDH specification
 * @see https://signal.org/docs/specifications/pqxdh/#the-pqxdh-protocol - Encapsulation step
 */
export async function mlKem1024Encapsulate(serializedPublicKey: Uint8Array): Promise<{
  sharedSecret: KyberSharedSecret;
  ciphertext: Uint8Array;
}> {
  const rawPublicKey = parseMlKem1024PublicKey(serializedPublicKey);
  const result = ml_kem1024.encapsulate(rawPublicKey);

  return {
    sharedSecret: asKyberSharedSecret(result.sharedSecret), // 32 bytes
    ciphertext: serializeMlKem1024Ciphertext(result.cipherText),
  };
}

/**
 * Kyber KEM Decapsulation
 *
 * Performs ML-KEM-1024 decapsulation to recover shared secret.
 * Used by responder (Bob) to recover shared secret from initiator's ciphertext.
 *
 * Security Note: The returned KyberSharedSecret is RAW key material and MUST
 * be combined with ECDH output via KDF for hybrid security.
 *
 * @param ciphertext Ciphertext from encapsulation (1568 bytes)
 * @param kyberPrivateKey Our Kyber private/secret key (3168 bytes)
 * @returns Branded KyberSharedSecret (32 bytes)
 *
 * @see https://signal.org/docs/specifications/pqxdh/ - PQXDH specification
 * @see https://signal.org/docs/specifications/pqxdh/#the-pqxdh-protocol - Decapsulation step
 */
export async function mlKem1024Decapsulate(
  serializedCiphertext: Uint8Array,
  privateKey: Uint8Array
): Promise<KyberSharedSecret> {
  const ciphertext = parseMlKem1024Ciphertext(serializedCiphertext);
  if (privateKey.length !== ML_KEM_1024_PRIVATE_KEY_BYTES) {
    throw new Error(
      `Invalid ML-KEM-1024 private key: expected ${ML_KEM_1024_PRIVATE_KEY_BYTES} bytes, got ${privateKey.length}`
    );
  }

  // Perform ML-KEM-1024 decapsulation
  const sharedSecret = ml_kem1024.decapsulate(ciphertext, privateKey);

  return asKyberSharedSecret(sharedSecret); // 32 bytes
}

// ============================================================================
// ML-KEM-768 Key Generation (for SPQR)
// ============================================================================

/**
 * Generate ML-KEM-768 key pair for SPQR post-quantum ratchet
 *
 * Uses @noble/post-quantum implementation of ML-KEM-768 (NIST FIPS 203).
 * Provides NIST Level 3 (192-bit) security against quantum computers.
 *
 * Key Sizes:
 * - Public key: KYBER_768_PUBLIC_KEY_BYTES (1184 bytes)
 * - Private key (secretKey): KYBER_768_SECRET_KEY_BYTES (2400 bytes)
 *
 * @returns {publicKey, privateKey} as Uint8Arrays
 *
 * @see https://signal.org/blog/spqr/ - SPQR specification
 * @see https://csrc.nist.gov/pubs/fips/203/final - NIST FIPS 203
 */
export async function generateKyber768KeyPair(): Promise<{
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}> {
  // Generate ML-KEM-768 keypair
  const keyPair = ml_kem768.keygen();

  return {
    publicKey: keyPair.publicKey, // KYBER_768_PUBLIC_KEY_BYTES (1184)
    privateKey: keyPair.secretKey, // KYBER_768_SECRET_KEY_BYTES (2400)
  };
}

// ============================================================================
// ML-KEM-768 KEM Operations (for SPQR)
// ============================================================================

/**
 * ML-KEM-768 KEM Encapsulation for SPQR
 *
 * Performs ML-KEM-768 encapsulation to derive shared secret.
 * Used by SPQR initiator during post-quantum ratchet step.
 *
 * Bandwidth: 1088 bytes ciphertext (vs 1568 for ML-KEM-1024)
 *
 * Security Note: The returned shared secret is RAW key material and MUST
 * be combined with EC output via KDF for hybrid security in SPQR.
 *
 * @param kyberPublicKey Partner's Kyber-768 public key (1184 bytes)
 * @returns Branded KyberSharedSecret (32 bytes) and ciphertext (1088 bytes)
 *
 * @see https://signal.org/blog/spqr/ - SPQR specification
 */
export async function kyber768Encapsulate(kyberPublicKey: Uint8Array): Promise<{
  sharedSecret: KyberSharedSecret;
  ciphertext: Uint8Array;
}> {
  // Validate public key size (ML-KEM-768 requires exactly 1184 bytes)
  if (kyberPublicKey.length !== KYBER_768_PUBLIC_KEY_BYTES) {
    throw new Error(
      `Invalid Kyber-768 public key: expected ${KYBER_768_PUBLIC_KEY_BYTES} bytes, got ${kyberPublicKey.length}`
    );
  }

  // Perform ML-KEM-768 encapsulation
  const result = ml_kem768.encapsulate(kyberPublicKey);

  return {
    sharedSecret: asKyberSharedSecret(result.sharedSecret), // 32 bytes
    ciphertext: result.cipherText, // 1088 bytes
  };
}

/**
 * ML-KEM-768 KEM Decapsulation for SPQR
 *
 * Performs ML-KEM-768 decapsulation to recover shared secret.
 * Used by SPQR responder to recover shared secret from ratchet ciphertext.
 *
 * Security Note: The returned shared secret is RAW key material and MUST
 * be combined with EC output via KDF for hybrid security in SPQR.
 *
 * @param ciphertext Ciphertext from encapsulation (1088 bytes)
 * @param kyberPrivateKey Our Kyber-768 private/secret key (2400 bytes)
 * @returns Branded KyberSharedSecret (32 bytes)
 *
 * @see https://signal.org/blog/spqr/ - SPQR specification
 */
export async function kyber768Decapsulate(
  ciphertext: Uint8Array,
  kyberPrivateKey: Uint8Array
): Promise<KyberSharedSecret> {
  // Validate ciphertext size (ML-KEM-768 requires exactly 1088 bytes)
  if (ciphertext.length !== KYBER_768_CIPHERTEXT_BYTES) {
    throw new Error(
      `Invalid Kyber-768 ciphertext: expected ${KYBER_768_CIPHERTEXT_BYTES} bytes, got ${ciphertext.length}`
    );
  }

  // Validate private key size (ML-KEM-768 requires exactly 2400 bytes)
  if (kyberPrivateKey.length !== KYBER_768_SECRET_KEY_BYTES) {
    throw new Error(
      `Invalid Kyber-768 private key: expected ${KYBER_768_SECRET_KEY_BYTES} bytes, got ${kyberPrivateKey.length}`
    );
  }

  // Perform ML-KEM-768 decapsulation
  const sharedSecret = ml_kem768.decapsulate(ciphertext, kyberPrivateKey);

  return asKyberSharedSecret(sharedSecret); // 32 bytes
}

// ============================================================================
// PQXDH Key Agreement
// ============================================================================

/**
 * Concatenate X3DH IKM and Kyber shared secret for PQXDH.
 *
 * Per PQXDH specification: IKM = F || DH1 || DH2 || DH3 || [DH4] || SS
 * This function appends the Kyber shared secret (SS) to the existing IKM.
 *
 * IMPORTANT: Caller MUST pass the result to HKDF. This function only
 * performs concatenation - the final key derivation is the caller's
 * responsibility to ensure single-step KDF per spec.
 *
 * Security: The hybrid approach provides security if EITHER X25519 OR
 * Kyber-1024 remains secure - a "belt and suspenders" defense.
 *
 * @param x3dhIKM Input key material from X3DH (F || DH1 || DH2 || DH3 || [DH4])
 * @param kyberSharedSecret Shared secret from Kyber KEM (SS, 32 bytes)
 * @returns Combined IKM for final HKDF derivation
 *
 * @see https://signal.org/docs/specifications/pqxdh/ - PQXDH specification
 * @see https://signal.org/docs/specifications/pqxdh/#the-pqxdh-protocol - Key combination
 */
export function concatPQXDHSecrets(x3dhIKM: Uint8Array, kyberSharedSecret: Uint8Array): Uint8Array {
  // Concatenate: IKM || SS per PQXDH spec
  const combined = new Uint8Array(x3dhIKM.length + kyberSharedSecret.length);
  combined.set(x3dhIKM, 0);
  combined.set(kyberSharedSecret, x3dhIKM.length);
  return combined;
}
