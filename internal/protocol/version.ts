/**
 * Triple Ratchet Version Negotiation
 *
 * @module triple/version
 *
 * Handles SPQR version lock-in for the Triple Ratchet.
 * SPQR v1 is required; legacy EC-only v0 is rejected.
 *
 * ## Negotiation Flow
 *
 * 1. Both parties initialize with their supported version range
 * 2. Version capability is sent in first message(s)
 * 3. Peer version must be v1
 * 4. Once complete, version is locked for session lifetime
 *
 * ## Why Version Negotiation Lives in Triple Ratchet
 *
 * The version determines whether SPQR is called at all. This is a
 * Triple Ratchet concern because:
 * - SPQR v1 runs in parallel with EC Double Ratchet
 * - The version decision affects both EC and PQ paths
 *
 * @see https://signal.org/docs/specifications/doubleratchet/#triple-ratchet
 */

import { EncryptionError, EncryptionErrorCode } from '../../types/errors';

// ============================================================================
// Types
// ============================================================================

/**
 * SPQR Protocol Version
 *
 * - `'v1'`: SPQR active with ML-KEM-768
 */
export {};
export type SPQRVersion = 'v1';
type PeerSPQRVersion = SPQRVersion | 'v0';

/**
 * Version Negotiation State
 *
 * Tracks the version negotiation process between two parties.
 * Transitions from StillNegotiating to NegotiationComplete exactly once.
 *
 * With the binary wire format, version is implicit in byte 0 of every
 * message, so negotiation completes on first message received from the
 * peer. No separate capability exchange is needed.
 *
 * @example
 * ```typescript
 * // Initialize in negotiating state
 * const versionNegotiation: VersionNegotiationState = {
 *   status: 'negotiating',
 *   maxVersion: 'v1',
 *   minVersion: 'v1',
 * };
 *
 * // After receiving peer's first message with version byte
 * processVersionFromByte(versionNegotiation, peerVersionByte);
 * // versionNegotiation.status === 'complete'
 * // versionNegotiation.negotiatedVersion === 'v1'
 * ```
 */
export interface VersionNegotiationState {
  /**
   * Current negotiation status.
   *
   * - `'negotiating'`: Waiting for peer's first message
   * - `'complete'`: Version agreed and locked for session
   */
  status: 'negotiating' | 'complete';

  /**
   * Our maximum supported version.
   *
   * Advertised to peer; negotiated version will be min(ours, theirs).
   */
  maxVersion: SPQRVersion;

  /**
   * Our minimum acceptable version.
   *
   * If peer's max version is below this, negotiation fails.
   * Set to 'v1' to require post-quantum security.
   */
  minVersion: SPQRVersion;

  /**
   * Negotiated version (set when status === 'complete').
   *
   * The agreed-upon version for this session. Once set, cannot change.
   */
  negotiatedVersion?: SPQRVersion;

  /**
   * Peer's advertised maximum version (received from them).
   *
   * Used to calculate negotiated version.
   */
  peerVersion?: SPQRVersion;
}

/**
 * Version capability for wire protocol.
 */
export interface VersionCapability {
  maxVersion: SPQRVersion;
  minVersion: SPQRVersion;
}

/**
 * JSON-serializable version negotiation state.
 */
export interface VersionNegotiationStateJSON {
  status: 'negotiating' | 'complete';
  maxVersion: SPQRVersion;
  minVersion: SPQRVersion;
  negotiatedVersion?: SPQRVersion;
  peerVersion?: SPQRVersion;
}

// ============================================================================
// Version Ordering
// ============================================================================

// ============================================================================
// Version Lock-In Functions
// ============================================================================

/**
 * Initialize version negotiation state.
 *
 * Creates a new negotiation state with the specified version constraints.
 *
 * @param maxVersion - Maximum supported version (default: 'v1')
 * @param minVersion - Minimum acceptable version (default: 'v1')
 * @returns Initialized version negotiation state
 *
 * @example
 * ```typescript
 * const state = initVersionNegotiation();
 * // state = { status: 'negotiating', maxVersion: 'v1', minVersion: 'v1' }
 * ```
 */
export function initVersionNegotiation(
  maxVersion: SPQRVersion = 'v1',
  minVersion: SPQRVersion = 'v1'
): VersionNegotiationState {
  return {
    status: 'negotiating',
    maxVersion,
    minVersion,
  };
}

/**
 * Process peer's version capability and finalize negotiation.
 *
 * Validates that the peer supports v1 and locks the state to v1.
 *
 * @param state - Version negotiation state to update
 * @param peerMaxVersion - Peer's maximum supported version
 * @returns v1, or throws if incompatible
 * @throws Error if peer only supports legacy v0
 *
 * @example
 * ```typescript
 * // Both parties support v1
 * const version = processVersionCapability(versionState, 'v1');
 * // version = 'v1', state.status = 'complete'
 *
 * processVersionCapability(versionState, 'v0');
 * // throws Error: Version negotiation failed
 * ```
 */
export function processVersionCapability(
  state: VersionNegotiationState,
  peerMaxVersion: PeerSPQRVersion
): SPQRVersion {
  // Already complete - ignore late version messages
  if (state.status === 'complete') {
    return state.negotiatedVersion!;
  }

  if (peerMaxVersion !== 'v1') {
    throw new EncryptionError(
      `Version negotiation failed: peer supports ${peerMaxVersion}, but we require at least ${state.minVersion}`,
      EncryptionErrorCode.SPQR_VERSION_MISMATCH,
      {
        operation: 'processVersionCapability',
        peerVersion: peerMaxVersion,
        minVersion: state.minVersion,
      }
    );
  }

  // Finalize negotiation
  state.status = 'complete';
  state.negotiatedVersion = 'v1';
  state.peerVersion = peerMaxVersion;

  return 'v1';
}

/**
 * Check if version negotiation is complete.
 *
 * @param state - Version negotiation state to check
 * @returns true if negotiation is complete
 */
export function isVersionNegotiationComplete(state: VersionNegotiationState | undefined): boolean {
  return state?.status === 'complete';
}

/**
 * Get the negotiated version, or the max version if still negotiating.
 *
 * During negotiation, returns the max version (optimistic).
 * After negotiation, returns the agreed version.
 *
 * @param state - Version negotiation state
 * @returns Negotiated version or max version
 */
export function getNegotiatedVersion(state: VersionNegotiationState | undefined): SPQRVersion {
  if (state?.status === 'complete') {
    return state.negotiatedVersion!;
  }
  // During negotiation, use optimistic version (max supported)
  return state?.maxVersion ?? 'v1';
}

// ============================================================================
// Binary Wire Format Helpers
// ============================================================================

/**
 * Process version from SPQR wire format byte 0.
 *
 * The version is implicit in the first byte of `pq_ratchet` data.
 * This package accepts only v1.
 *
 * This replaces the JSON versionCapability exchange. Both sides see the version
 * byte on every message, so negotiation completes on first message received.
 *
 * @param state - Version negotiation state to update
 * @param peerVersionByte - Byte 0 of the peer's pq_ratchet data (0x00 or 0x01)
 */
export function processVersionFromByte(
  state: VersionNegotiationState,
  peerVersionByte: number
): void {
  const peerVersion: PeerSPQRVersion = peerVersionByte === 1 ? 'v1' : 'v0';
  processVersionCapability(state, peerVersion);
}

// ============================================================================
// Serialization
// ============================================================================

/**
 * Serialize version negotiation state to JSON.
 */
export function serializeVersionNegotiation(
  state: VersionNegotiationState
): VersionNegotiationStateJSON {
  return {
    status: state.status,
    maxVersion: state.maxVersion,
    minVersion: state.minVersion,
    negotiatedVersion: state.negotiatedVersion,
    peerVersion: state.peerVersion,
  };
}

/**
 * Deserialize version negotiation state from JSON.
 */
export function deserializeVersionNegotiation(
  json: VersionNegotiationStateJSON
): VersionNegotiationState {
  return {
    status: json.status,
    maxVersion: json.maxVersion,
    minVersion: json.minVersion,
    negotiatedVersion: json.negotiatedVersion,
    peerVersion: json.peerVersion,
  };
}
