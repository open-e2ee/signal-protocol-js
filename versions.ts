/**
 * Signal Protocol Version Constants
 *
 * Separates Signal Protocol specification versions from
 * wire format versions (our serialization format for that spec).
 *
 * References:
 * - Signal Protocol: https://signal.org/docs/
 * - NIST FIPS 203 (ML-KEM): https://csrc.nist.gov/pubs/fips/203/final
 */

// =============================================================================
// Specification Versions
// =============================================================================
// Which Signal Protocol specification versions the SDK implements.
// These are for documentation/clarity - they don't go in wire messages.

/** Signal Protocol X3DH key-agreement specification */
export {};
export const X3DH_SPEC = 'v1';

/** Signal Protocol PQXDH (post-quantum) key-agreement specification */
export const PQXDH_SPEC = 'v1';

/** Signal Protocol Double Ratchet specification */
export const DOUBLE_RATCHET_SPEC = 'v1';

/** Signal Protocol Sender Keys profile (Group Protocol V2) */
export const SENDER_KEY_SPEC = 'v2';

/** Signal Protocol SESAME multi-device specification */
export const SESAME_SPEC = 'v1';

/** ML-KEM Braid (SPQR/Triple Ratchet) specification */
export const ML_KEM_BRAID_SPEC = 'v1';

// =============================================================================
// Wire Format Versions
// =============================================================================
// Our implementation's serialization format. These ARE embedded in messages
// and used for compatibility checking. Can evolve independently of specs.

/** Wire format for RatchetMessage and PreKeyMessage */
export const MESSAGE_FORMAT = 'v2';

/** Persisted format for composite-identity session records */
export const SESSION_FORMAT = 'v4';

/** Wire format for SenderKeyState */
export const SENDER_KEY_FORMAT = 'v1';

/**
 * Sender Key Message version byte
 *
 * Format: ((message_version & 0xF) << 4) | senderkey_message_version
 * Current: (3 << 4) | 3 = 0x33
 *
 * This byte prefixes signed message data for:
 * - Version detection and future migration
 * - Consistent version detection across message codecs
 *
 */
export const SENDER_KEY_MESSAGE_VERSION = 0x33;

// =============================================================================
// Version Utilities
// =============================================================================

/**
 * Parse a version string to extract the numeric version.
 * @param version - Version string (e.g., 'v1', 'v2')
 * @returns Numeric version
 * @throws If version format is invalid
 */
export function parseVersion(version: string): number {
  const match = version.match(/^v(\d+)$/);
  if (!match || match[1] === undefined) {
    throw new Error(`Invalid version format: ${version}. Expected 'v1', 'v2', etc.`);
  }
  return parseInt(match[1], 10);
}

/**
 * Check if a version is compatible (>= minimum).
 * @param current - Current version string
 * @param minimum - Minimum required version string
 * @returns true if current >= minimum
 */
export function isCompatible(current: string, minimum: string): boolean {
  return parseVersion(current) >= parseVersion(minimum);
}

/**
 * Create a version string from a number.
 * @param num - Version number
 * @returns Version string (e.g., 'v1')
 */
export function formatVersion(num: number): string {
  return `v${num}`;
}
