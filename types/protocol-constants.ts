/**
 * Signal Protocol Constants
 *
 * Protocol-level constants for device IDs, registration IDs, and message limits.
 * Version constants are now in the public package
 */

// ============================================================================
// Wire Format Versions (re-exported from versions.ts)
// ============================================================================
export {};
export { MESSAGE_FORMAT, SESSION_FORMAT, SENDER_KEY_FORMAT } from '../versions';

// ============================================================================
// Device and Registration IDs
// ============================================================================

/**
 * Default device ID for primary device
 * Signal Protocol supports multi-device, but most implementations use a single device
 */
export const DEFAULT_DEVICE_ID = 1;

/**
 * Minimum registration ID value
 * The client generates registration IDs randomly in range [1, 16380]
 * @see https://signal.org/docs/specifications/x3dh/
 */
export const MIN_REGISTRATION_ID = 1;

/**
 * Maximum registration ID value
 * The client generates registration IDs randomly in range [1, 16380]
 * @see https://signal.org/docs/specifications/x3dh/
 */
export const MAX_REGISTRATION_ID = 16380;

// ============================================================================
// Message and Session Limits
// ============================================================================

/**
 * Batch size for one-time prekeys (both EC and KEM)
 *
 * The reference implementation uses 100 for both EC and KEM one-time prekeys to maintain
 * protocol symmetry. This balances key availability with storage/upload costs.
 *
 * Per PQXDH specification, KEM one-time prekeys follow the same
 * replenishment pattern as EC one-time prekeys.
 *
 * @see https://signal.org/docs/specifications/pqxdh/#sending-the-initial-message
 */
export const ONE_TIME_PREKEY_BATCH_SIZE = 100;

// ============================================================================
// HKDF Key Derivation Constants
// ============================================================================

/**
 * Total bytes derived from X3DH/PQXDH HKDF.
 *
 * X3DH derives 96 bytes total:
 * - Bytes 0-32: Shared secret (SK) / root key
 * - Bytes 32-64: Reserved / receiving chain key placeholder (Alice) or sending (Bob)
 * - Bytes 64-96: Sending chain key placeholder (Alice) or receiving (Bob)
 *
 * @see https://signal.org/docs/specifications/x3dh/
 */
export const HKDF_OUTPUT_SIZE = 96;

/**
 * HKDF output byte ranges for X3DH/PQXDH key derivation.
 *
 * These ranges are relative to the 96-byte HKDF output.
 * For `additionalDerivedBytes` (bytes 32-96), subtract 32 from each range.
 *
 * @example
 * ```typescript
 * // Full HKDF output
 * const sharedSecret = derivedKeys.slice(HKDF_RANGES.SK.start, HKDF_RANGES.SK.end);
 *
 * // From additionalDerivedBytes (already has SK removed)
 * const pqrKey = additionalDerivedBytes.slice(0, 32);    // INITIAL_PQR_KEY - SK offset
 * const chainKey = additionalDerivedBytes.slice(32, 64); // CK - SK offset
 * ```
 */
export const HKDF_RANGES = {
  /** Shared secret / root key (32 bytes, positions 0-32) */
  SK: { start: 0, end: 32 },
  /**
   * Initial PQR key (32 bytes, positions 32-64).
   *
   * Used as the SPQR initial-state authenticator key. Provides authentication
   * binding between the X3DH/PQXDH shared secret and SPQR state.
   *
   * Named "RESERVED" in older documentation but actively used for SPQR.
   */
  INITIAL_PQR_KEY: { start: 32, end: 64 },
  /** Primary chain key (32 bytes, positions 64-96) */
  CK: { start: 64, end: 96 },
} as const;

/**
 * HKDF byte ranges relative to additionalDerivedBytes (SK already removed).
 *
 * When using `additionalDerivedBytes` from X3DH/PQXDH results,
 * use these offsets since the first 32 bytes (SK) are separate.
 *
 * @example
 * ```typescript
 * const { sharedSecret, additionalDerivedBytes } = x3dhResult;
 * // sharedSecret is bytes 0-32 (SK)
 * // additionalDerivedBytes is bytes 32-96, so use ADDITIONAL_RANGES
 * const pqrKey = additionalDerivedBytes.slice(
 *   HKDF_ADDITIONAL_RANGES.INITIAL_PQR_KEY.start,
 *   HKDF_ADDITIONAL_RANGES.INITIAL_PQR_KEY.end
 * );
 * ```
 */
export const HKDF_ADDITIONAL_RANGES = {
  /**
   * Initial PQR key (positions 0-32 within additionalDerivedBytes).
   *
   * Used as the SPQR initial-state authenticator key.
   */
  INITIAL_PQR_KEY: { start: 0, end: 32 },
  /** Primary chain key (positions 32-64 within additionalDerivedBytes) */
  CK: { start: 32, end: 64 },
} as const;
