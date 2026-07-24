/**
 * Signal Protocol Keys Module
 *
 * @layer 5 - Domain/Keys
 * @pure No I/O, provides key types and generation
 *
 * Consolidated key types and generation functions for the Signal Protocol.
 *
 * Key types:
 * - Identity Key: Long-lived, per-user (DH + Signing)
 * - Signed Prekey: Medium-lived, rotates weekly
 * - One-Time Prekeys: Single-use, replenished regularly
 * - Kyber Prekey: Post-quantum prekey for PQXDH
 *
 * @see https://signal.org/docs/specifications/x3dh/#keys
 * @see https://signal.org/docs/specifications/pqxdh/
 */

// Branded types (compile-time type safety)
export {};
export type { PublicKey, PrivateKey, Signature, Ciphertext, KeyPair } from './branded';

// Key types
export type {
  IdentityType,
  CompositeIdentityV1,
  ContactIdentityRecord,
  IdentityTrustState,
  IdentityCandidateStatus,
  IdentityKeyPair,
  EcSignedPreKey,
  EcOneTimePreKey,
  KyberPreKey,
  KemOneTimePreKey,
  PreKeyBundle,
} from './types';

export {
  COMPOSITE_IDENTITY_V1_LENGTH,
  COMPOSITE_IDENTITY_V1_VERSION,
  COMPOSITE_IDENTITY_V1_X25519_TAG,
  COMPOSITE_IDENTITY_V1_ED25519_TAG,
  IDENTITY_COMMITMENT_V1_DOMAIN,
  createCompositeIdentityV1,
  encodeCompositeIdentityV1,
  decodeCompositeIdentityV1,
  deriveIdentityCommitment,
  assertIdentityCommitment,
  compositeIdentitiesEqual,
  validateContactIdentityRecord,
  evaluateContactIdentityCandidate,
  createUnverifiedContactIdentityRecord,
  acceptContactIdentityRotation,
  verifyContactIdentityRecord,
} from './identity';

export {
  PREKEY_SIGNATURE_V1_DOMAIN,
  PREKEY_ALGORITHM_X25519,
  PREKEY_ALGORITHM_ML_KEM_1024,
  createPreKeySignatureContext,
  signPreKey,
  verifyPreKeySignature,
  signMlKem1024PreKey,
  verifyMlKem1024PreKey,
} from './prekey-signature';

// Key generation functions
export {
  generateRegistrationId,
  generateIdentityKeyPair,
  generateEcSignedPreKeyId,
  generateEcSignedPreKey,
  generateEcOneTimePreKeys,
  generateKyberLastResortPreKey,
  generateKemOneTimePreKeys,
} from './generation';
