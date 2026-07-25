/**
 * Canonical composite identity profile for this SDK.
 *
 * The tuple, not either component and not a supplied commitment, is the
 * identity trust object. Commitments are always derived locally from validated
 * canonical tuple bytes.
 */

import { sha256 } from '@noble/hashes/sha2.js';

import { base64ToBytes, bytesToBase64, concatBytes, constantTimeEqual } from '../internal/crypto/utils';
import type { PublicKey } from './branded';
import type {
  CompositeIdentityV1,
  ContactIdentityRecord,
  IdentityCandidateStatus,
  IdentityKeyPair,
} from './types';

export const COMPOSITE_IDENTITY_V1_VERSION = 0x01;
export const COMPOSITE_IDENTITY_V1_X25519_TAG = 0x01;
export const COMPOSITE_IDENTITY_V1_ED25519_TAG = 0x02;
export const COMPOSITE_IDENTITY_V1_LENGTH = 67;
export const IDENTITY_COMMITMENT_V1_DOMAIN = 'signal-protocol-js composite identity v1';

const PUBLIC_KEY_LENGTH = 32;
const DOMAIN_BYTES = new TextEncoder().encode(IDENTITY_COMMITMENT_V1_DOMAIN);

function decodeCanonicalPublicKey(publicKey: PublicKey, label: string): Uint8Array {
  let decoded: Uint8Array;
  try {
    decoded = base64ToBytes(publicKey);
  } catch (error) {
    throw new Error(`${label} must be canonical base64`, { cause: error });
  }
  if (decoded.length !== PUBLIC_KEY_LENGTH) {
    throw new Error(`${label} must contain exactly ${PUBLIC_KEY_LENGTH} bytes`);
  }
  if (bytesToBase64(decoded) !== publicKey) {
    throw new Error(`${label} must use canonical padded base64`);
  }
  return decoded;
}

export function createCompositeIdentityV1(
  identity: Pick<IdentityKeyPair, 'dhKey' | 'signingKey'>
): CompositeIdentityV1 {
  const composite: CompositeIdentityV1 = {
    version: 1,
    x25519PublicKey: identity.dhKey.publicKey,
    ed25519PublicKey: identity.signingKey.publicKey,
  };
  // Validate at construction rather than allowing an invalid branded string to
  // reach a relay, trust store, transcript, or signature context.
  encodeCompositeIdentityV1(composite);
  return composite;
}

export function encodeCompositeIdentityV1(identity: CompositeIdentityV1): Uint8Array {
  if (identity.version !== COMPOSITE_IDENTITY_V1_VERSION) {
    throw new Error(`Unsupported composite identity version: ${String(identity.version)}`);
  }

  const x25519 = decodeCanonicalPublicKey(identity.x25519PublicKey, 'X25519 public key');
  const ed25519 = decodeCanonicalPublicKey(identity.ed25519PublicKey, 'Ed25519 public key');
  const encoded = new Uint8Array(COMPOSITE_IDENTITY_V1_LENGTH);
  encoded[0] = COMPOSITE_IDENTITY_V1_VERSION;
  encoded[1] = COMPOSITE_IDENTITY_V1_X25519_TAG;
  encoded.set(x25519, 2);
  encoded[34] = COMPOSITE_IDENTITY_V1_ED25519_TAG;
  encoded.set(ed25519, 35);
  return encoded;
}

export function decodeCompositeIdentityV1(encoded: Uint8Array): CompositeIdentityV1 {
  if (encoded.length !== COMPOSITE_IDENTITY_V1_LENGTH) {
    throw new Error(
      `CompositeIdentityV1 must contain exactly ${COMPOSITE_IDENTITY_V1_LENGTH} bytes`
    );
  }
  if (encoded[0] !== COMPOSITE_IDENTITY_V1_VERSION) {
    throw new Error(`Unsupported composite identity version: ${String(encoded[0])}`);
  }
  if (encoded[1] !== COMPOSITE_IDENTITY_V1_X25519_TAG) {
    throw new Error(`Unsupported X25519 algorithm tag: ${String(encoded[1])}`);
  }
  if (encoded[34] !== COMPOSITE_IDENTITY_V1_ED25519_TAG) {
    throw new Error(`Unsupported Ed25519 algorithm tag: ${String(encoded[34])}`);
  }

  return {
    version: 1,
    x25519PublicKey: bytesToBase64(encoded.slice(2, 34)) as PublicKey,
    ed25519PublicKey: bytesToBase64(encoded.slice(35, 67)) as PublicKey,
  };
}

export function deriveIdentityCommitment(identity: CompositeIdentityV1): Uint8Array {
  return sha256(concatBytes(DOMAIN_BYTES, encodeCompositeIdentityV1(identity)));
}

/** Reject a redundant relay/cache assertion that disagrees with the tuple. */
export function assertIdentityCommitment(
  identity: CompositeIdentityV1,
  suppliedCommitment: Uint8Array
): void {
  const derived = deriveIdentityCommitment(identity);
  if (!constantTimeEqual(derived, suppliedCommitment)) {
    throw new Error('Supplied identity commitment does not match canonical composite identity');
  }
}

export function compositeIdentitiesEqual(
  left: CompositeIdentityV1,
  right: CompositeIdentityV1
): boolean {
  return constantTimeEqual(encodeCompositeIdentityV1(left), encodeCompositeIdentityV1(right));
}

/**
 * SESAME `DeviceRecord.identityKey` bytes for a device whose composite identity
 * has not been observed yet.
 *
 * Zero length is the only representation of "not pinned". It must stay distinct
 * from a pinned tuple so that first contact performs a TOFU pin rather than
 * reporting an identity change, and it must never be a partial key: pinning
 * only the X25519 half would silently accept a peer that kept its DH key and
 * swapped its Ed25519 signing key.
 */
export const UNPINNED_DEVICE_IDENTITY_KEY: Uint8Array = new Uint8Array(0);

/**
 * Whether `bytes` is a well-formed `DeviceRecord.identityKey`: either unpinned
 * or exactly one canonical composite tuple.
 */
export function isValidDeviceIdentityKey(bytes: Uint8Array): boolean {
  if (bytes.length === 0) return true;
  try {
    decodeCompositeIdentityV1(bytes);
    return true;
  } catch {
    return false;
  }
}

/**
 * Reduce `DeviceRecord.identityKey` bytes to their canonical form, rejecting
 * any other encoding at the storage boundary.
 *
 * Every producer of device identity bytes goes through here so that a single
 * encoding reaches storage and comparison. Without it, two producers using two
 * encodings of the same key compare unequal and forge an identity-change event.
 */
export function canonicalizeDeviceIdentityKey(bytes: Uint8Array, label: string): Uint8Array {
  if (bytes.length === 0) return UNPINNED_DEVICE_IDENTITY_KEY;
  try {
    return encodeCompositeIdentityV1(decodeCompositeIdentityV1(bytes));
  } catch (error) {
    throw new Error(`${label} is not a canonical composite identity tuple`, { cause: error });
  }
}

/**
 * Compare two `DeviceRecord.identityKey` values.
 *
 * Returns `'unpinned'` when no identity has been observed for the device yet,
 * which is first contact (a TOFU pin) and not a change.
 */
export function compareDeviceIdentityKeys(
  pinned: Uint8Array,
  incoming: Uint8Array
): 'unpinned' | 'same' | 'changed' {
  if (pinned.length === 0) return 'unpinned';
  return constantTimeEqual(pinned, incoming) ? 'same' : 'changed';
}

function cloneIdentity(identity: CompositeIdentityV1): CompositeIdentityV1 {
  return decodeCompositeIdentityV1(encodeCompositeIdentityV1(identity));
}

function assertTimestamp(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${label} must be a non-negative safe integer`);
  }
}

export function validateContactIdentityRecord(record: ContactIdentityRecord): void {
  encodeCompositeIdentityV1(record.identity);
  if (record.trustState !== 'UNVERIFIED_TOFU' && record.trustState !== 'VERIFIED') {
    throw new Error(`Unsupported identity trust state: ${String(record.trustState)}`);
  }
  assertTimestamp(record.firstSeenAt, 'firstSeenAt');
  assertTimestamp(record.lastSeenAt, 'lastSeenAt');
  if (record.lastSeenAt < record.firstSeenAt) {
    throw new Error('lastSeenAt cannot precede firstSeenAt');
  }
  if (!Number.isSafeInteger(record.revision) || record.revision < 1) {
    throw new Error('Identity revision must be a positive safe integer');
  }
  if (record.trustState === 'VERIFIED') {
    if (record.verifiedAt === undefined) {
      throw new Error('A verified identity must include verifiedAt');
    }
    assertTimestamp(record.verifiedAt, 'verifiedAt');
  } else if (record.verifiedAt !== undefined) {
    throw new Error('An unverified identity cannot include verifiedAt');
  }
  if (!Array.isArray(record.retiredIdentities)) {
    throw new Error('retiredIdentities must be an array');
  }
  for (let index = 0; index < record.retiredIdentities.length; index += 1) {
    const retired = record.retiredIdentities[index]!;
    encodeCompositeIdentityV1(retired);
    if (compositeIdentitiesEqual(record.identity, retired)) {
      throw new Error('Current identity cannot also be retired');
    }
    for (let previous = 0; previous < index; previous += 1) {
      if (compositeIdentitiesEqual(retired, record.retiredIdentities[previous]!)) {
        throw new Error('Duplicate retired identity');
      }
    }
  }
}

export function evaluateContactIdentityCandidate(
  record: ContactIdentityRecord | null,
  candidate: CompositeIdentityV1,
  suppliedCommitment?: Uint8Array
): IdentityCandidateStatus {
  encodeCompositeIdentityV1(candidate);
  if (suppliedCommitment !== undefined) {
    assertIdentityCommitment(candidate, suppliedCommitment);
  }
  if (record === null) return 'NEW';
  validateContactIdentityRecord(record);
  if (compositeIdentitiesEqual(record.identity, candidate)) return 'MATCH';
  if (record.retiredIdentities.some((retired) => compositeIdentitiesEqual(retired, candidate))) {
    return 'ROLLBACK';
  }
  return 'CHANGED';
}

export function createUnverifiedContactIdentityRecord(
  identity: CompositeIdentityV1,
  now: number
): ContactIdentityRecord {
  assertTimestamp(now, 'now');
  return {
    identity: cloneIdentity(identity),
    trustState: 'UNVERIFIED_TOFU',
    firstSeenAt: now,
    lastSeenAt: now,
    revision: 1,
    retiredIdentities: [],
  };
}

/** Explicit user/application acceptance path; automatic save must not call this. */
export function acceptContactIdentityRotation(
  record: ContactIdentityRecord,
  candidate: CompositeIdentityV1,
  now: number,
  suppliedCommitment?: Uint8Array
): ContactIdentityRecord {
  assertTimestamp(now, 'now');
  const status = evaluateContactIdentityCandidate(record, candidate, suppliedCommitment);
  if (status === 'ROLLBACK') {
    throw new Error('Refusing previously retired identity as a rollback');
  }
  if (status === 'MATCH') {
    return { ...record, lastSeenAt: Math.max(record.lastSeenAt, now) };
  }
  if (status !== 'CHANGED') {
    throw new Error(`Identity rotation requires an existing different identity, got ${status}`);
  }
  return {
    identity: cloneIdentity(candidate),
    trustState: 'UNVERIFIED_TOFU',
    firstSeenAt: now,
    lastSeenAt: now,
    revision: record.revision + 1,
    retiredIdentities: [
      ...record.retiredIdentities.map(cloneIdentity),
      cloneIdentity(record.identity),
    ],
  };
}

export function verifyContactIdentityRecord(
  record: ContactIdentityRecord,
  candidate: CompositeIdentityV1,
  now: number,
  suppliedCommitment?: Uint8Array
): ContactIdentityRecord {
  assertTimestamp(now, 'now');
  const status = evaluateContactIdentityCandidate(record, candidate, suppliedCommitment);
  if (status !== 'MATCH') {
    throw new Error(`Authenticated identity comparison requires the current tuple, got ${status}`);
  }
  return {
    ...record,
    trustState: 'VERIFIED',
    lastSeenAt: Math.max(record.lastSeenAt, now),
    verifiedAt: now,
  };
}
