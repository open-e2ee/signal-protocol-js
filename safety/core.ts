/**
 * Core Safety Number Functions
 *
 * Implements the fingerprint specification's iterative SHA-512 construction
 * plus an independently versioned composite-identity construction.
 *
 */

import {
  sha512Sync,
  base64ToBytes,
  concatBytes,
  bytesToHex,
  constantTimeEqual,
  serializePublicKey,
  X25519_RAW_KEY_BYTES,
} from '../internal/crypto';
import type { PublicKey } from '../keys';
import type { CompositeIdentityV1, IdentityType } from '../keys';
import { deriveIdentityCommitment } from '../keys/identity';

// ============================================================================
// Constants
// ============================================================================

/**
 * Number of SHA-512 iterations for fingerprint generation.
 * The fingerprint specification uses exactly 5,200 iterations.
 */
export {};
export const FINGERPRINT_ITERATIONS = 5200;

/**
 * Version prefix for fingerprint hash (0x0000).
 * Versions the fingerprint hash input.
 */
const FINGERPRINT_VERSION_PREFIX = new Uint8Array([0x00, 0x00]);

/**
 * Fingerprint format version for QR codes.
 * Version 2 is the single-key fingerprint format.
 */
export const FINGERPRINT_VERSION = 2;

/** Independent composite-identity QR/safety-number profile version. */
export const COMPOSITE_FINGERPRINT_VERSION = 3;

const COMPOSITE_FINGERPRINT_DOMAIN = new TextEncoder().encode(
  'signal-protocol-js composite safety number v1'
);

/**
 * Size of the scannable fingerprint in bytes.
 * First 32 bytes of the SHA-512 hash are used for QR codes.
 */
export const SCANNABLE_FINGERPRINT_BYTES = 32;

/**
 * Size of the full fingerprint in bytes.
 * Full 64-byte SHA-512 hash is used for numeric display.
 */
export const FULL_FINGERPRINT_BYTES = 64;

// ============================================================================
// Types
// ============================================================================

export interface IndividualFingerprint {
  /** First 32 bytes for QR code / protobuf */
  scannable: Uint8Array;
  /** Full 64 bytes for displayable numeric */
  full: Uint8Array;
}

export interface FingerprintPair {
  /** Local user's fingerprint */
  localFingerprint: IndividualFingerprint;
  /** Remote user's fingerprint */
  remoteFingerprint: IndividualFingerprint;
  /** 60-digit displayable number (sorted, combined) */
  displayable: string;
  /** Hex representation of combined hash */
  hex: string;
}

// ============================================================================
// Encoding Utilities
// ============================================================================

/**
 * Convert bytes to number (big-endian)
 */
export function bytesToNumber(bytes: Uint8Array): number {
  let result = 0;
  for (const byte of bytes) {
    result = result * 256 + byte;
  }
  return result;
}

// ============================================================================
// Core Fingerprint Algorithm
// ============================================================================

/**
 * Compute individual fingerprint for one user.
 *
 * Algorithm:
 * 1. hash = version (0x0000) + identityKey + userId
 * 2. for i in 0..<iterations: hash = SHA512(hash + identityKey)
 * 3. Return first 32 bytes for scannable, full 64 for displayable
 *
 * @param identityKey - User's identity public key (base64 PublicKey)
 * @param userId - User's identifier string
 * @param iterations - Number of SHA-512 iterations (default: 5200)
 * @returns Individual fingerprint with scannable and full bytes
 */
export function computeIndividualFingerprint(
  identityKey: PublicKey,
  userId: string,
  iterations: number = FINGERPRINT_ITERATIONS
): IndividualFingerprint {
  const rawKeyBytes = base64ToBytes(identityKey);

  // Validate: storage returns 32-byte raw X25519 keys
  if (rawKeyBytes.length !== X25519_RAW_KEY_BYTES) {
    throw new Error(
      `Invalid identity key: expected ${X25519_RAW_KEY_BYTES}-byte raw key from storage, got ${rawKeyBytes.length}`
    );
  }

  // Fingerprint inputs use the serialized 0x05 || X25519 public-key form.
  const keyBytes = serializePublicKey(rawKeyBytes);

  const idBytes = new TextEncoder().encode(userId);

  // Initial hash: version + key + id
  let hash = concatBytes(FINGERPRINT_VERSION_PREFIX, keyBytes, idBytes);

  // Iterate: hash = SHA512(hash + key)
  for (let i = 0; i < iterations; i++) {
    hash = sha512Sync(concatBytes(hash, keyBytes));
  }

  return {
    scannable: hash.slice(0, SCANNABLE_FINGERPRINT_BYTES),
    full: hash,
  };
}

/**
 * Compute fingerprint pair for two users.
 * Returns separate local and remote fingerprints (NOT combined).
 *
 * The displayable 60-digit number is created by:
 * 1. Computing individual fingerprints for both users
 * 2. Sorting by user identifier (lexicographical)
 * 3. Converting each to 30 digits and concatenating
 *
 * @param localKey - Local user's identity public key
 * @param remoteKey - Remote user's identity public key
 * @param localId - Local user's identifier
 * @param remoteId - Remote user's identifier
 * @returns FingerprintPair with local, remote, and displayable
 */
export function computeFingerprintPair(
  localKey: PublicKey,
  remoteKey: PublicKey,
  localId: string,
  remoteId: string
): FingerprintPair {
  // Compute individual fingerprints
  const localFingerprint = computeIndividualFingerprint(localKey, localId);
  const remoteFingerprint = computeIndividualFingerprint(remoteKey, remoteId);

  // Sort by identifier for deterministic ordering
  const localFirst = localId.localeCompare(remoteId) <= 0;

  const first = localFirst ? localFingerprint : remoteFingerprint;
  const second = localFirst ? remoteFingerprint : localFingerprint;

  // Generate 30 digits from each fingerprint (60 total)
  const firstDigits = generateNumericFromFingerprint(first.full, 30);
  const secondDigits = generateNumericFromFingerprint(second.full, 30);
  const displayable = formatNumeric(firstDigits + secondDigits);

  // Combine for hex representation
  // Use first 32 bytes from each fingerprint (64 bytes total = 128 hex chars)
  const combinedHex = bytesToHex(first.scannable) + bytesToHex(second.scannable);

  return {
    localFingerprint,
    remoteFingerprint,
    displayable,
    hex: combinedHex, // 32 + 32 bytes = 128 hex chars
  };
}

function encodeUint32BE(value: number): Uint8Array {
  const result = new Uint8Array(4);
  new DataView(result.buffer).setUint32(0, value, false);
  return result;
}

function encodeCompositeSafetyIdentifier(userId: string, identityType: IdentityType): Uint8Array {
  const userIdBytes = new TextEncoder().encode(userId);
  if (userIdBytes.length === 0) throw new Error('Safety-number userId cannot be empty');
  return concatBytes(
    new Uint8Array([identityType === 'aci' ? 0x01 : 0x02]),
    encodeUint32BE(userIdBytes.length),
    userIdBytes
  );
}

/**
 * Compute one side of the independently versioned composite safety number.
 * The input is the locally derived commitment to both identity components, not
 * either raw component and not a relay-supplied commitment.
 */
export function computeCompositeIndividualFingerprint(
  identity: CompositeIdentityV1,
  userId: string,
  identityType: IdentityType,
  iterations: number = FINGERPRINT_ITERATIONS
): IndividualFingerprint {
  const commitment = deriveIdentityCommitment(identity);
  const identifier = encodeCompositeSafetyIdentifier(userId, identityType);
  let hash = concatBytes(COMPOSITE_FINGERPRINT_DOMAIN, identifier, commitment);
  for (let i = 0; i < iterations; i++) {
    hash = sha512Sync(concatBytes(hash, commitment));
  }
  return { scannable: hash.slice(0, SCANNABLE_FINGERPRINT_BYTES), full: hash };
}

/** Symmetric relationship fingerprint over two canonical composite identities. */
export function computeCompositeFingerprintPair(
  localIdentity: CompositeIdentityV1,
  remoteIdentity: CompositeIdentityV1,
  localId: string,
  remoteId: string,
  identityType: IdentityType = 'aci',
  iterations: number = FINGERPRINT_ITERATIONS
): FingerprintPair {
  const localFingerprint = computeCompositeIndividualFingerprint(
    localIdentity,
    localId,
    identityType,
    iterations
  );
  const remoteFingerprint = computeCompositeIndividualFingerprint(
    remoteIdentity,
    remoteId,
    identityType,
    iterations
  );
  const localFirst = localId.localeCompare(remoteId) <= 0;
  const first = localFirst ? localFingerprint : remoteFingerprint;
  const second = localFirst ? remoteFingerprint : localFingerprint;
  const displayable = formatNumeric(
    generateNumericFromFingerprint(first.full, 30) +
      generateNumericFromFingerprint(second.full, 30)
  );
  return {
    localFingerprint,
    remoteFingerprint,
    displayable,
    hex: bytesToHex(first.scannable) + bytesToHex(second.scannable),
  };
}

/**
 * Generate numeric digits from fingerprint hash.
 *
 * Take consecutive five-byte chunks from the hash, reduce each modulo 100000,
 * and format it as five digits.
 *
 * For 30 digits: uses bytes 0-4, 5-9, 10-14, 15-19, 20-24, 25-29
 * No re-hashing needed - the 64-byte hash has enough entropy.
 *
 *
 * @param hash - Fingerprint hash bytes (64 bytes from SHA-512)
 * @param digitCount - Number of digits to generate (max 60 from 64 bytes)
 * @returns Numeric string
 */
function generateNumericFromFingerprint(hash: Uint8Array, digitCount: number): string {
  let result = '';
  const chunksNeeded = Math.ceil(digitCount / 5);

  for (let i = 0; i < chunksNeeded && result.length < digitCount; i++) {
    const offset = i * 5;
    const chunk = hash.slice(offset, offset + 5);
    const num = bytesToNumber(chunk);
    const digits = (num % 100000).toString().padStart(5, '0');
    result += digits;
  }

  return result.slice(0, digitCount);
}

// ============================================================================
// Emoji Fingerprint
// ============================================================================

/**
 * Emoji set for fingerprint representation.
 * Uses easily distinguishable emojis from different categories.
 */
const FINGERPRINT_EMOJIS = [
  '😀',
  '😃',
  '😄',
  '😁',
  '😆',
  '😅',
  '🤣',
  '😂', // Smileys
  '🙂',
  '🙃',
  '😉',
  '😊',
  '😇',
  '🥰',
  '😍',
  '🤩', // Positive faces
  '😘',
  '😗',
  '😚',
  '😙',
  '🥲',
  '😋',
  '😛',
  '😜', // Playful
  '🤪',
  '😝',
  '🤑',
  '🤗',
  '🤭',
  '🤫',
  '🤔',
  '🤐', // Thinking
  '🤨',
  '😐',
  '😑',
  '😶',
  '😏',
  '😒',
  '🙄',
  '😬', // Neutral
  '🤥',
  '😌',
  '😔',
  '😪',
  '🤤',
  '😴',
  '😷',
  '🤒', // Sleepy
  '🤕',
  '🤢',
  '🤮',
  '🤧',
  '🥵',
  '🥶',
  '😵',
  '🤯', // Sick
  '🤠',
  '🥳',
  '😎',
  '🤓',
  '🧐',
  '😕',
  '😟',
  '🙁', // Expressions
];

/**
 * Generate emoji fingerprint (30 emojis).
 *
 * Uses consecutive bytes from the 64-byte SHA-512 hash.
 * No re-hashing needed - the hash has more than enough entropy.
 */
export function generateEmojiFingerprint(hash: Uint8Array): string {
  let result = '';

  // Generate 30 emojis from the first 30 bytes
  for (let i = 0; i < 30 && i < hash.length; i++) {
    const byte = hash[i] ?? 0;
    const index = byte % FINGERPRINT_EMOJIS.length;
    result += FINGERPRINT_EMOJIS[index];
  }

  return result;
}

// ============================================================================
// Formatting
// ============================================================================

/**
 * Format numeric fingerprint with spaces (groups of 5).
 */
export function formatNumeric(numeric: string): string {
  return numeric.match(/.{1,5}/g)?.join(' ') || numeric;
}

/**
 * Format emoji fingerprint with spaces (groups of 5).
 */
export function formatEmojis(emojis: string): string {
  // Split into array of individual emojis (handles multi-byte emojis)
  const emojiArray = Array.from(emojis);
  const groups: string[] = [];

  for (let i = 0; i < emojiArray.length; i += 5) {
    groups.push(emojiArray.slice(i, i + 5).join(''));
  }

  return groups.join(' ');
}

// Re-export constantTimeEqual for use by other modules
export { constantTimeEqual };
