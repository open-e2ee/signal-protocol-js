/**
 * Safety Number Generation
 *
 * Safety numbers (also called "fingerprints" or "verification codes") allow users
 * to verify they're communicating with the intended person and detect
 * man-in-the-middle attacks.
 *
 * Implementation follows Signal Protocol's safety number specification:
 * - Computes individual fingerprints for each user using SHA-512 iteration
 * - Uses deterministic ordering (lexicographical by user ID)
 * - Uses SHA-512 with 5,200 iterations for this Signal Protocol profile
 * - Generates a 60-digit number (easier to compare than hex)
 * - Also provides emoji representation for easier visual verification
 * - QR codes use protobuf format with cross-verification swap logic
 *
 * @see https://signal.org/blog/safety-number-updates/
 *
 * @example
 * ```typescript
 * import { safety } from '../index';
 *
 * const safetyNum = safety.generateCompositeSafetyNumber(
 *   myCompositeIdentity,
 *   partnerCompositeIdentity,
 *   myUserId,
 *   partnerUserId
 * );
 *
 * console.log(`Safety Number: ${safetyNum.numeric}`);
 * console.log(`Emojis: ${safetyNum.emojis}`);
 *
 * // For QR scanning verification
 * const result = safetyNum.scannable.compare(scannedData);
 * if (result === 'match') {
 *   // Identity verified!
 * }
 * ```
 */

// Import core functions from shared module
import {
  computeFingerprintPair,
  computeCompositeFingerprintPair,
  COMPOSITE_FINGERPRINT_VERSION,
  formatEmojis,
  FINGERPRINT_ITERATIONS,
  FINGERPRINT_VERSION,
  generateEmojiFingerprint,
} from './core';
import { base64ToBytes } from '../internal/crypto';
import type { CompositeIdentityV1, IdentityType, PublicKey } from '../keys';
import { ScannableFingerprint } from './fingerprint';

// ============================================================================
// Fingerprint Cache (LRU with 50-entry limit)
// ============================================================================

/**
 * Maximum number of cached safety numbers.
 * Each entry is ~500 bytes, so 50 entries = ~25KB max.
 */
export {};
const CACHE_MAX_SIZE = 50;

/**
 * LRU cache for computed safety numbers.
 * SHA-512 with 5,200 iterations takes ~100-200ms on mobile,
 * so caching is important for performance.
 *
 * Uses Map's insertion-order guarantee for LRU eviction:
 * - On hit: delete and re-insert to move to end (most recent)
 * - On set: if size exceeds limit, delete first entry (oldest)
 */
const fingerprintCache = new Map<string, SafetyNumber>();

/**
 * Generate cache key from inputs
 */
function getCacheKey(
  user1IdentityKey: string,
  user2IdentityKey: string,
  user1Identifier: string,
  user2Identifier: string
): string {
  // Sort to ensure same key regardless of argument order
  const sorted = [
    `${user1Identifier}:${user1IdentityKey}`,
    `${user2Identifier}:${user2IdentityKey}`,
  ].sort();
  return sorted.join('|');
}

/**
 * Get from cache with LRU update (moves entry to end)
 */
function cacheGet(key: string): SafetyNumber | undefined {
  const value = fingerprintCache.get(key);
  if (value !== undefined) {
    // Move to end (most recently used)
    fingerprintCache.delete(key);
    fingerprintCache.set(key, value);
  }
  return value;
}

/**
 * Set in cache with LRU eviction
 */
function cacheSet(key: string, value: SafetyNumber): void {
  // Delete first if exists (to update position)
  fingerprintCache.delete(key);

  // Evict oldest if at capacity
  if (fingerprintCache.size >= CACHE_MAX_SIZE) {
    const oldestKey = fingerprintCache.keys().next().value;
    if (oldestKey !== undefined) {
      fingerprintCache.delete(oldestKey);
    }
  }

  fingerprintCache.set(key, value);
}

/**
 * Clear the fingerprint cache for controlled local resets.
 */
export function clearFingerprintCache(): void {
  fingerprintCache.clear();
}

// ============================================================================
// Safety Number Interface
// ============================================================================

/**
 * Safety number result with multiple representations
 */
export interface SafetyNumber {
  /** 60-digit number formatted in groups of 5 */
  numeric: string;
  /** Emoji representation (30 emojis) */
  emojis: string;
  /** Raw hex fingerprint */
  hex: string;
  /** QR code data as base64 (protobuf format) */
  qrData: string;
  /** ScannableFingerprint instance for verification */
  scannable: ScannableFingerprint;
}

// ============================================================================
// Main API
// ============================================================================

/**
 * Generate a reference single-key fingerprint for two users.
 *
 * This low-level primitive does not authenticate the package's complete
 * X25519 + Ed25519 composite identity and MUST NOT be used for contact identity
 * verification. Applications must use SignalProtocolClient.verify(), or the explicitly
 * composite generateCompositeSafetyNumber() helper.
 *
 * Uses SHA-512 iteration with 5,200 iterations per Signal Protocol spec.
 * Results are cached for performance since the iteration is computationally expensive.
 *
 * @param user1IdentityKey - User 1's identity public key (PublicKey branded type)
 * @param user2IdentityKey - User 2's identity public key (PublicKey branded type)
 * @param user1Identifier - User 1's identifier (e.g., username or ID)
 * @param user2Identifier - User 2's identifier
 * @returns Safety number in multiple formats
 */
export function generateSingleKeyReferenceSafetyNumber(
  user1IdentityKey: PublicKey,
  user2IdentityKey: PublicKey,
  user1Identifier: string,
  user2Identifier: string
): SafetyNumber {
  // Check cache first (SHA-512 iterations are expensive: ~100-200ms on mobile)
  const cacheKey = getCacheKey(
    user1IdentityKey,
    user2IdentityKey,
    user1Identifier,
    user2Identifier
  );
  const cached = cacheGet(cacheKey);
  if (cached) {
    return cached;
  }

  // Compute both parties' single-key fingerprints.
  const pair = computeFingerprintPair(
    user1IdentityKey,
    user2IdentityKey,
    user1Identifier,
    user2Identifier
  );

  // Create ScannableFingerprint with protobuf encoding
  const scannable = new ScannableFingerprint(
    pair.localFingerprint.scannable,
    pair.remoteFingerprint.scannable,
    FINGERPRINT_VERSION
  );

  // Generate emojis from the first user's fingerprint (sorted order)
  const firstFingerprint =
    user1Identifier.localeCompare(user2Identifier) <= 0
      ? pair.localFingerprint
      : pair.remoteFingerprint;
  const emojis = formatEmojis(generateEmojiFingerprint(firstFingerprint.full));

  const result: SafetyNumber = {
    numeric: pair.displayable, // Already formatted with spaces
    emojis,
    hex: pair.hex,
    qrData: scannable.toBase64(),
    scannable,
  };

  // Cache the result (with LRU eviction if needed)
  cacheSet(cacheKey, result);

  return result;
}

/**
 * Generate the composite-identity safety number from both
 * canonical composite identities. This is deliberately distinct from the
 * lower-level single-key fingerprint API.
 */
export function generateCompositeSafetyNumber(
  localIdentity: CompositeIdentityV1,
  remoteIdentity: CompositeIdentityV1,
  localIdentifier: string,
  remoteIdentifier: string,
  identityType: IdentityType = 'aci'
): SafetyNumber {
  const pair = computeCompositeFingerprintPair(
    localIdentity,
    remoteIdentity,
    localIdentifier,
    remoteIdentifier,
    identityType
  );
  const scannable = new ScannableFingerprint(
    pair.localFingerprint.scannable,
    pair.remoteFingerprint.scannable,
    COMPOSITE_FINGERPRINT_VERSION
  );
  const firstFingerprint =
    localIdentifier.localeCompare(remoteIdentifier) <= 0
      ? pair.localFingerprint
      : pair.remoteFingerprint;
  return {
    numeric: pair.displayable,
    emojis: formatEmojis(generateEmojiFingerprint(firstFingerprint.full)),
    hex: pair.hex,
    qrData: scannable.toBase64(),
    scannable,
  };
}

/**
 * Compare two safety numbers (case-insensitive, ignores spaces)
 */
export function compareSafetyNumbers(a: string, b: string): boolean {
  const cleanA = a.replace(/\s/g, '').toLowerCase();
  const cleanB = b.replace(/\s/g, '').toLowerCase();
  return cleanA === cleanB;
}

/**
 * Validate safety number format
 */
export function isValidSafetyNumber(numeric: string): boolean {
  const cleaned = numeric.replace(/\s/g, '');
  return /^\d{60}$/.test(cleaned);
}

// ============================================================================
// Core Helpers (exported for use by Fingerprint class)
// ============================================================================

/**
 * Export core helper functions for reuse by Fingerprint class.
 * This avoids code duplication between the function-based and class-based APIs.
 */
export { generateEmojiFingerprint, base64ToBytes, FINGERPRINT_ITERATIONS, FINGERPRINT_VERSION };

// ============================================================================
// Class-based fingerprint API
// ============================================================================

/**
 * Re-export fingerprint classes from fingerprint.ts
 *
 * These provide a class-based API over the fingerprint primitives.
 * Use when you need:
 * - Object-oriented fingerprint manipulation
 * - Structured display and QR comparison
 * - Advanced operations (QR code scanning, etc.)
 *
 * These classes expose single-key fingerprint primitives. Composite contact
 * verification must use SignalProtocolClient.verify() so both composite components and
 * the locally pinned trust record are authenticated.
 */
export {
  Fingerprint,
  DisplayableFingerprint,
  ScannableFingerprint,
  createFingerprintData,
  type FingerprintData,
  type CompareResult,
} from './fingerprint';

// ============================================================================
// URL Utilities (Deep Link Support)
// ============================================================================

/**
 * Re-export URL utilities for safety number deep links.
 *
 * These enable QR codes to work with native camera apps (iOS/Android).
 * When scanned outside the app, the URL opens to the verification screen.
 *
 * @example
 * ```typescript
 * import { generateVerifyUrl, extractQrData } from './';
 *
 * // Generate URL for QR code display
 * const url = generateVerifyUrl({
 *   otherUserId: 'abc123',
 *   contextType: 'dm',
 *   contextId: 'xyz789',
 *   qrData: safetyNumber.qrData,
 * });
 *
 * // Extract QR data from scanned URL or legacy format
 * const data = extractQrData(scannedString);
 * ```
 */
export {
  generateVerifyUrl,
  generateVerifySchemeUrl,
  isVerifyUrl,
  parseVerifyUrl,
  extractQrData,
  DEFAULT_VERIFY_LINK_CONFIG,
  VERIFY_BASE_URL,
  VERIFY_SCHEME_URL,
  type VerifyLinkConfig,
  type VerifyUrlParams,
} from './url';
