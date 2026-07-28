/**
 * Cryptographic Primitives
 *
 * @layer 6 - Domain/Crypto (Foundation)
 * @pure No I/O, no external dependencies except crypto libs
 *
 * This module provides the package's internal cryptographic primitives.
 *
 * Cryptographic Primitives:
 * - X25519 (Curve25519) for ECDH key exchange
 * - Ed25519 for digital signatures
 * - AES-256-CBC + HMAC-SHA256 for authenticated encryption (Signal Protocol spec)
 * - AES-256-GCM for modern applications
 * - AES-256-CTR for Sealed Sender envelope encryption
 * - HKDF-SHA256 for key derivation
 * - ML-KEM-1024 (Kyber) for post-quantum key exchange (PQXDH)
 * - ML-KEM-768 (Kyber) for post-quantum continuous ratchet (SPQR)
 *
 * Libraries:
 * - @noble/curves/ed25519 - X25519 & Ed25519
 * - @noble/post-quantum - ML-KEM-768 & ML-KEM-1024 (NIST FIPS 203)
 * - @noble/hashes - HMAC-SHA256, HKDF (6 security audits, RFC 2104 compliant)
 * - @noble/ciphers - AES-256-CTR (cure53 audited, Sep 2024)
 * - expo-crypto - Secure random number generation
 * - Web Crypto API - AES-CBC/GCM encryption/decryption
 *
 * Signal Protocol Specification Mapping:
 * Core protocol functions use SCREAMING_SNAKE_CASE (matches spec exactly) internally.
 * Public API exports provide camelCase wrappers for JavaScript convention.
 *
 *   Spec Function    | Public Export (camelCase)     | Section
 *   -----------------|-------------------------------|----------
 *   GENERATE_DH()    | generateECDHKeyPair()         | 2.1
 *   DH(dh_pair, key) | computeSharedSecret()         | 2.1
 *   KDF_RK(rk, dh)   | kdfRootKey()                  | 2.2
 *   KDF_CK(ck)       | kdfChainKey()                 | 2.3
 *   ENCRYPT(mk, pt)  | aesCbcHmacEncrypt() [note 1]  | 2.4
 *   DECRYPT(mk, ct)  | aesCbcHmacDecrypt() [note 1]  | 2.4
 *   KDF_HYBRID(ec,pq)| kdfHybrid()                   | 6.3
 *
 * [note 1] These are raw primitives. Signal Protocol Section 3 ENCRYPT/DECRYPT
 *          include identity-bound MAC in AD. Use cipher layer for full compliance.
 *
 * See docs/E2EE.md for complete security analysis.
 */

// ============================================================================
// Elliptic Curve (ec/)
// ============================================================================
export {};
export {
  // X25519 ECDH
  type ECDHSharedSecret,
  asECDHSharedSecret,
  isValidECDHLength,
  ECDH_SHARED_SECRET_BYTES,
  X25519_KEY_BYTES,
  generateECDHKeyPair,
  computeSharedSecret,
  GENERATE_DH,
  DH,
  // Ed25519 Signatures
  ED25519_SIGNATURE_BYTES,
  ED25519_KEY_BYTES,
  generateSigningKeyPair,
  sign,
  verify,
  // X25519 Validation
  isCanonicalX25519Point,
  validateX25519PublicKey,
} from './ec';

// ============================================================================
// Post-Quantum (pq/)
// ============================================================================
export {
  // ML-KEM-1024 (for PQXDH)
  type KyberSharedSecret,
  asKyberSharedSecret,
  isValidKyberLength,
  ML_KEM_1024_RAW_PUBLIC_KEY_BYTES,
  ML_KEM_1024_ALGORITHM_TAG,
  ML_KEM_1024_PUBLIC_KEY_BYTES,
  ML_KEM_1024_PRIVATE_KEY_BYTES,
  ML_KEM_1024_RAW_CIPHERTEXT_BYTES,
  ML_KEM_1024_CIPHERTEXT_BYTES,
  ML_KEM_1024_SHARED_SECRET_BYTES,
  serializeMlKem1024PublicKey,
  parseMlKem1024PublicKey,
  serializeMlKem1024Ciphertext,
  parseMlKem1024Ciphertext,
  generateMlKem1024KeyPair,
  mlKem1024Encapsulate,
  mlKem1024Decapsulate,
  concatPQXDHSecrets,
  // ML-KEM-768 (for SPQR)
  KYBER_768_PUBLIC_KEY_BYTES,
  KYBER_768_SECRET_KEY_BYTES,
  KYBER_768_CIPHERTEXT_BYTES,
  KYBER_768_SHARED_SECRET_BYTES,
  generateKyber768KeyPair,
  kyber768Encapsulate,
  kyber768Decapsulate,
} from './pq';

// ============================================================================
// Symmetric Encryption (symmetric/)
// ============================================================================
export {
  // AES-256-CBC + HMAC
  AES_256_KEY_BYTES,
  AES_GCM_IV_BYTES,
  AES_GCM_TAG_BYTES,
  AES_CBC_IV_BYTES,
  aesGcmEncrypt,
  aesGcmEncryptWithIV,
  aesGcmDecrypt,
  aesCbcHmacEncrypt,
  aesCbcHmacDecrypt,
  aesCbcEncrypt,
  aesCbcDecrypt,
  aesCbcEncryptBytes,
  aesCbcDecryptBytes,
  ENCRYPT,
  DECRYPT,
  aesGcmEncryptWithIVBytes,
  aesGcmDecryptWithIVBytes,
  // AES-256-CTR
  AES_CTR_KEY_BYTES,
  AES_CTR_IV_BYTES,
  aesCtrEncrypt,
  aesCtrDecrypt,
  aesCtrEncryptToBase64,
  aesCtrDecryptFromBase64,
  // AES-256-GCM-SIV
  AES_GCM_SIV_KEY_BYTES,
  AES_GCM_SIV_NONCE_BYTES,
  AES_GCM_SIV_TAG_BYTES,
  aesGcmSivEncrypt,
  aesGcmSivDecrypt,
  aesGcmSivEncryptZeroNonce,
  aesGcmSivDecryptZeroNonce,
  // HMAC
  hmac,
  // Message MAC and Header Serialization
  MESSAGE_VERSION_BYTE,
  MAC_LENGTH_BYTES,
  DJB_KEY_TYPE,
  serializeHeader,
  deserializeHeader,
  computeMessageMac,
  verifyMessageMac,
  computeProtobufMessageMac,
  verifyProtobufMessageMac,
  // Padding
  PADDING_BUCKET_SIZE,
  padMessage,
  unpadMessage,
  // Streaming AEAD
  streamingEncrypt,
  streamingDecrypt,
  type StreamingEncryptResult,
  type StreamingDecryptOptions,
  STREAMING_HEADER_LENGTH,
  STREAMING_SALT_LENGTH,
  STREAMING_NONCE_PREFIX_LENGTH,
  STREAMING_AUTH_TAG_LENGTH,
  STREAMING_NONCE_LENGTH,
  DEFAULT_SEGMENT_SIZE,
  MIN_SEGMENT_SIZE,
} from './symmetric';

// ============================================================================
// Key Derivation (kdf/)
// ============================================================================
export {
  type DerivedKey,
  asDerivedKey,
  DERIVED_KEY_BYTES,
  hkdf,
  hkdfExpand,
  kdfRootKey,
  kdfChainKey,
  expandMessageKey,
  kdfHybrid,
  SPQR_INFO_STRINGS,
  resolveSPQRInfoStrings,
  type ResolvedSPQRInfoStrings,
  kdfChainKeySPQR,
  kdfSpqrInit,
  kdfSpqrEpoch,
  KDF_RK,
  KDF_CK,
  KDF_HYBRID,
  KDF_CK_SPQR,
  KDF_SPQR_INIT,
  KDF_SPQR_EPOCH,
  TR_PROTOCOL_INFO,
} from './kdf';

export { SAFETY_NUMBER_ITERATIONS, PBKDF2_SHA512_OUTPUT_BYTES, pbkdf2Sha512 } from './kdf';

// ============================================================================
// Hash Functions (hash/)
// ============================================================================
export { SHA256_HASH_BYTES, HKDF_OUTPUT_BYTES, sha256 } from './hash';

export { SHA512_HASH_BYTES, sha512, sha512Sync } from './hash';

// SHA3-256 (for ML-KEM Braid hek commitment)
export { sha3_256 } from '@noble/hashes/sha3.js';

// ============================================================================
// Random Number Generation
// ============================================================================
export { generateRandomBytes, generateUuidV4 } from './random';

// ============================================================================
// Encoding/Decoding & Memory Management
// ============================================================================
export {
  bytesToBase64,
  bytesToUrlSafeBase64,
  base64ToUrlSafe,
  urlSafeToBase64,
  base64ToBytes,
  stringToBytes,
  bytesToString,
  concatBytes,
  constantTimeEqual,
  cloneProtocolState,
  secureZero,
  secureZeroBytes,
} from './utils';

// ============================================================================
// Key Prefix Utilities (Signal Protocol key serialization format)
// ============================================================================
export {
  X25519_RAW_KEY_BYTES,
  X25519_SERIALIZED_KEY_BYTES,
  serializePublicKey,
  deserializePublicKey,
  isSerializedPublicKey,
  ensureSerializedPublicKey,
  ensureRawPublicKey,
} from './key-prefix';

// ============================================================================
// Key Pair Validation
// ============================================================================
export { validateX25519KeyPair } from './validation';

// ============================================================================
// Hex Encoding (re-export from @noble/hashes for consistent API)
// ============================================================================
export { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
