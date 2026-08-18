/**
 * Signal Protocol Key Types
 *
 * Consolidated key type definitions used across the Signal Protocol implementation.
 * These are protocol-agnostic - the same key types work in X3DH, PQXDH, and future protocols.
 *
 * @see https://signal.org/docs/specifications/x3dh/#keys
 * @see https://signal.org/docs/specifications/pqxdh/
 */

import type { PublicKey, PrivateKey, Signature, KeyPair } from './branded';

/** Signal Protocol identity type: ACI (account) or PNI (discoverable identifier). */
export {};
export type IdentityType = 'aci' | 'pni';

/** Canonical identity profile selected by this SDK. */
export interface CompositeIdentityV1 {
  /** Canonical tuple version. Encoded as `0x01`. */
  readonly version: 1;
  /** Standard X25519 public key used by X3DH/PQXDH. */
  readonly x25519PublicKey: PublicKey;
  /** Standard Ed25519 public key used to authenticate prekeys. */
  readonly ed25519PublicKey: PublicKey;
}

export type IdentityTrustState = 'UNVERIFIED_TOFU' | 'VERIFIED';

/** Authoritative persisted trust record. Commitments are deliberately absent. */
export interface ContactIdentityRecord {
  readonly identity: CompositeIdentityV1;
  readonly trustState: IdentityTrustState;
  readonly firstSeenAt: number;
  readonly lastSeenAt: number;
  readonly verifiedAt?: number;
  readonly revision: number;
  /** Canonical tuples retained solely for rollback detection. */
  readonly retiredIdentities: readonly CompositeIdentityV1[];
}

export type IdentityCandidateStatus = 'NEW' | 'MATCH' | 'CHANGED' | 'ROLLBACK';

/**
 * Identity key pair (long-lived, per-user)
 *
 * The SDK's independent composite profile deliberately uses separate standard
 * keys for DH and signatures:
 * - dhKey: Used for X3DH key exchange (DH1 operation)
 * - signingKey: Used for signing prekeys
 * - registrationId: Random ID generated once per app install
 */
export interface IdentityKeyPair {
  /** X25519 key pair for Diffie-Hellman */
  dhKey: KeyPair;
  /** Ed25519 signing key pair for signatures */
  signingKey: KeyPair;
  /**
   * Registration ID - Random 16-bit integer generated once per app install.
   *
   * Used to detect session resets when a device reinstalls the app.
   * Changes on reinstall to invalidate old sessions and prevent replay attacks.
   *
   * From Signal Protocol:
   * "Registration IDs help detect stale sessions from previous installations"
   *
   * @see https://signal.org/docs/specifications/x3dh/#registration-id
   */
  registrationId: number;
}

/**
 * EC signed prekey (rotates weekly)
 *
 */
export interface EcSignedPreKey {
  keyId: number; // Protocol key identifier
  publicKey: PublicKey;
  privateKey: PrivateKey;
  signature: Signature;
  timestamp: number;
}

/**
 * EC one-time prekey (consumed on use)
 */
export interface EcOneTimePreKey {
  keyId: number; // Protocol key identifier
  publicKey: PublicKey;
  privateKey: PrivateKey;
}

/**
 * ML-KEM-1024 prekey (historical public name, rotates weekly)
 *
 * `KyberPreKey` survives as an API identifier, but the bytes are standard
 * ML-KEM-1024 with the profile's mandatory `0x0A` serialization.
 */
export interface KyberPreKey {
  keyId: number; // Protocol key identifier
  publicKey: PublicKey; // Base64-encoded 0x0A || raw ML-KEM-1024 public key
  privateKey: PrivateKey; // Stored locally only
  signature: Signature; // Signed with identity signing key
  timestamp: number;
}

/**
 * KEM one-time prekey (consumed on use, post-quantum)
 *
 * Per PQXDH spec Section 3.2, the identity key signs these one-time pqkem prekeys
 * that provide per-session post-quantum forward secrecy.
 * Server prefers these over the last-resort KEM prekey.
 */
export interface KemOneTimePreKey {
  keyId: number; // Protocol key identifier
  publicKey: PublicKey; // Base64-encoded ML-KEM-1024 public key
  privateKey: PrivateKey; // Stored locally only, deleted after consumption
  signature: Signature; // Signed with identity signing key (per spec)
  timestamp: number;
}

/**
 * PreKey Bundle - Public keys for establishing an encrypted session
 *
 * Contains all public information needed for X3DH/PQXDH key exchange.
 * Fetched from the server when initiating a session with a new device.
 *
 * ## Key Exchange Flow (PQXDH)
 *
 * Alice fetches Bob's PreKeyBundle and computes:
 * ```
 * DH1 = DH(Alice_IK, Bob_SPK)      // Identity to Signed PreKey
 * DH2 = DH(Alice_EK, Bob_IK)       // Ephemeral to Identity
 * DH3 = DH(Alice_EK, Bob_SPK)      // Ephemeral to Signed PreKey
 * DH4 = DH(Alice_EK, Bob_OPK)      // Ephemeral to One-Time PreKey (if available)
 * KEM = Encaps(Bob_MLKEM1024_PK)   // Standardized ML-KEM-1024
 *
 * SK = KDF(DH1 || DH2 || DH3 || DH4 || KEM_SS)
 * ```
 *
 * ## Bundle Contents
 *
 * | Field              | Type        | Purpose                              | Lifetime       |
 * |--------------------|-------------|--------------------------------------|----------------|
 * | registrationId     | number      | Detect app reinstalls                | Per install    |
 * | deviceId           | number      | Identify device (1=primary, 2-5)     | Per device     |
 * | identity           | CompositeV1 | Per-user DH + signing trust object   | Permanent      |
 * | ecSignedPreKey     | X25519+sig  | Medium-term DH key (SPK)             | Rotates weekly |
 * | ecOneTimePreKey    | X25519      | Single-use forward secrecy (OPK)     | Consumed once  |
 * | kemLastResortPreKey| ML-KEM-1024 | Post-quantum protection (PQSPK)      | Rotates weekly |
 *
 * ## Security Properties
 *
 * These inputs support the profile's conditional hybrid-security and
 * one-time-prekey properties. See `docs/SECURITY.md` for their assumptions and
 * limits. This data shape alone is not a security proof.
 *
 * @see https://signal.org/docs/specifications/pqxdh/
 * @see https://signal.org/docs/specifications/x3dh/
 */
export interface PreKeyBundle {
  /**
   * Registration ID - Random 16-bit integer generated on app install.
   *
   * Changes when user reinstalls app, allowing peers to detect stale sessions
   * and re-establish encryption. Prevents replay of messages from old installs.
   */
  registrationId: number;

  /**
   * Device ID within this user's device set.
   *
   * - Primary device: 1
   * - Linked devices: 2-5 (max 5 devices per user)
   *
   * Used for multi-device fanout. The client encrypts messages separately
   * for each of the recipient's devices.
   */
  deviceId: number;

  /**
   * Versioned per-user identity trust object. ACI and PNI are independent.
   * Linked devices expose the same tuple. Registration IDs and prekeys remain
   * device-specific. Consumers derive commitments locally.
   */
  identity: CompositeIdentityV1;

  /**
   * EC Signed PreKey (X25519 + Ed25519 signature).
   *
   * Medium-term key that rotates weekly. Signed by identitySigningKey
   * to prove authenticity. Used for DH1 and DH3 in X3DH.
   *
   * The signature covers the composite identity commitment, algorithm tag, key
   * ID, and public key in the profile's domain-separated context.
   */
  ecSignedPreKey: {
    /** Key ID for tracking which key the session used */
    keyId: number;
    /** X25519 public key (32 bytes, base64) */
    publicKey: PublicKey;
    /** Ed25519 signature over publicKey bytes (64 bytes, base64) */
    signature: Signature;
  };

  /**
   * EC One-Time PreKey (X25519, optional).
   *
   * Single-use key consumed atomically on fetch. Provides additional
   * forward secrecy - if compromised, only affects one session.
   *
   * May be null/undefined if the server exhausted the prekey pool.
   * Session establishment still works without it (degraded to 3-DH).
   */
  ecOneTimePreKey?: {
    /** Key ID for tracking which key the session consumed */
    keyId: number;
    /** X25519 public key (32 bytes, base64) */
    publicKey: PublicKey;
  } | null;

  /**
   * Last-resort KEM PreKey for PQXDH (ML-KEM-1024 + Ed25519 signature, optional).
   *
   * Post-quantum key encapsulation mechanism. Provides protection against
   * "harvest now, decrypt later" attacks from quantum computers.
   *
   * Reusable KEM prekey used when the server exhausted the one-time KEM pool.
   * Server and relay adapters must not place one-time KEM material in this field.
   * Use `kemOneTimePreKey` for consumed one-time KEM material.
   *
   * - Public key: 1569 bytes (`0x0A` plus 1568 raw bytes, base64 encoded)
   * - Ciphertext: 1569 bytes (`0x0A` plus 1568 raw bytes)
   * - Shared secret: 32 bytes
   *
   * The signature covers the complete tagged public key plus identity
   * commitment, algorithm tag, and key ID in a domain-separated context.
   *
   * @see https://signal.org/docs/specifications/pqxdh/
   */
  kemLastResortPreKey?: {
    /** Key ID */
    keyId: number;
    /** Tagged ML-KEM-1024 public key (1569 bytes, base64) */
    publicKey: PublicKey;
    /** Ed25519 signature over the profile's complete prekey context */
    signature: Signature;
  } | null;

  /**
   * KEM One-Time PreKey (ML-KEM-1024 + Ed25519 signature, optional).
   *
   * Per PQXDH spec Section 3.2, the identity key signs these one-time pqkem prekeys
   * that provide per-session post-quantum forward secrecy.
   *
   * Server prefers these over the last-resort KEM prekey. Consumed atomically on
   * fetch (like EC one-time prekeys). A bundle should contain either this field
   * or `kemLastResortPreKey` as the selected KEM material for PQXDH.
   *
   * May be null/undefined if the server exhausted the prekey pool.
   * Session establishment still works without it (falls back to last-resort).
   *
   * @see https://signal.org/docs/specifications/pqxdh/#sending-the-initial-message
   */
  kemOneTimePreKey?: {
    /** Key ID for tracking which key the session consumed */
    keyId: number;
    /** Tagged ML-KEM-1024 public key (1569 bytes, base64) */
    publicKey: PublicKey;
    /** Ed25519 signature over the profile's complete prekey context */
    signature: Signature;
  } | null;
}
