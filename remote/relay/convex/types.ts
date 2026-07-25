/**
 * Convex database type definitions for Signal Protocol key distribution
 *
 * These types are used by the client adapter (relay.ts) for type-safe
 * communication with the Signal Protocol component at the application backend
 *
 * Component Tables (9 total):
 * - devices
 * - identityKeys
 * - ecPreKeys
 * - ecSignedPreKeys
 * - kemOneTimePreKeys
 * - kemLastResortPreKeys
 * - messages
 * - provisioningSessions
 * - prekeyBundleFetches
 */

/**
 * Identity key record from the Signal Protocol component
 * Component table: identityKeys
 */
export {};
export interface ConvexIdentityKey {
  _id: string;
  userId: string;
  deviceId: number;
  publicKey: string; // Base64-encoded X25519 public key
  createdAt: number;
}

/**
 * EC signed prekey record from the Signal Protocol component
 * Component table: ecSignedPreKeys
 *
 * Note: Old keys are DELETED when rotated, not marked deprecated
 */
export interface ConvexEcSignedPreKey {
  _id: string;
  userId: string;
  deviceId: number;
  keyId: number;
  publicKey: string; // Base64-encoded EC public key
  signature: string; // Base64-encoded signature
  uploadedAt: number;
}

/**
 * EC one-time prekey record from the Signal Protocol component
 * Component table: ecPreKeys
 *
 * Note: Keys are DELETED when consumed, not marked
 */
export interface ConvexEcPreKey {
  _id: string;
  userId: string;
  deviceId: number;
  keyId: number;
  publicKey: string; // Base64-encoded EC public key
  uploadedAt: number;
}

/**
 * KEM one-time prekey record from the Signal Protocol component (post-quantum)
 * Component table: kemOneTimePreKeys
 *
 * Note: Keys are DELETED when consumed, not marked
 */
export interface ConvexKemPreKey {
  _id: string;
  userId: string;
  deviceId: number;
  keyId: number;
  publicKey: string; // Base64-encoded Kyber-1024 public key (~1.5KB)
  signature: string; // Ed25519 signature from identity key (PQXDH spec requirement)
  uploadedAt: number;
}

/**
 * KEM last-resort prekey record from the Signal Protocol component (post-quantum fallback)
 * Component table: kemLastResortPreKeys
 *
 * Reusable when one-time KEM keys exhausted
 */
export interface ConvexKemLastResortPreKey {
  _id: string;
  userId: string;
  deviceId: number;
  keyId: number;
  publicKey: string; // Base64-encoded Kyber-1024 public key
  signature: string; // Base64-encoded signature from identity key
  uploadedAt: number;
}

/**
 * Prekey bundle response from the Signal Protocol component
 * Returned by fetchPreKeyBundle query
 */
export interface FetchedPreKeyBundle {
  deviceId: number;
  compositeIdentity: string; // Base64-encoded canonical CompositeIdentityV1
  signedPreKey: {
    keyId: number;
    publicKey: string;
    signature: string;
  };
  oneTimePreKey?: {
    keyId: number;
    publicKey: string;
  } | null;
  kyberPreKey?: {
    keyId: number;
    publicKey: string;
    signature: string;
  } | null;
}
