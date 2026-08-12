/**
 * SPQR (Sparse Post-Quantum Ratchet) - Layer 3: Ratcheting (Post-Quantum)
 *
 * Implements the Signal Protocol SPQR specification for continuous
 * post-quantum security.
 * SPQR runs in parallel with the EC Double Ratchet to provide post-quantum
 * security via ML-KEM-768 (Kyber) key agreement.
 *
 * ## SCKA Modes
 *
 * Two modes are available for SPQR key exchange:
 *
 * - **ML-KEM Braid** (default): the SPQR v1 SCKA
 *   - ~32 bytes × 76 chunks spread across messages
 *   - Packet loss resilience (20-40%), blocking resistance
 *
 * - **Direct SCKA**: Explicit direct ML-KEM-768 encapsulation
 *   - 1,088 bytes per ratchet step
 *   - Single round-trip, minimal complexity
 *   - Non-canonical local mode for product-reviewed constraints
 *
 * ## Tiered ML-KEM Model
 *
 * - PQXDH (session setup): ML-KEM-1024 for maximum security
 * - SPQR (continuous ratchet): ML-KEM-768 for bandwidth efficiency
 *
 * @see https://signal.org/blog/spqr/ - the SPQR specification
 * @see https://signal.org/docs/specifications/mlkembraid/ - ML-KEM Braid spec
 */

import type { SCKAMode, SPQRState } from './spqr';

// Core SPQR functions
export {};
export {
  initializeSPQRState,
  performSPQRRatchetStep,
  processSPQRReceivedCiphertext,
  deriveSPQRSendKey,
  deriveSPQRReceiveKey,
  tryGetSkippedSPQRKey,
  cleanupSPQRState,
  isSpqrBootstrapComplete,
  SPQR_CONFIG,
  // Black-box API
  spqrSend,
  spqrRecv,
} from './spqr';

// Validation functions
export { validateSPQRState, trimSkippedKeys } from './validate';

// Serialization functions
export { serializeSPQRState, deserializeSPQRState } from './serialize';

// Version negotiation re-exports removed — use triple-ratchet barrel or import ../version directly.
// These are re-exported via ./triple-ratchet to avoid TS2308 duplicate export errors.

// Core types
export type {
  KDFChain,
  EpochChains,
  SkippedSPQRKey,
  SCKAState,
  SPQRState,
  SPQRRatchetResult,
  SPQRKeyResult,
  SPQRChunkResult,
  SCKAMode,
  // Black-box API result types
  SPQRSendResult,
  SPQRRecvResult,
} from './spqr';

// Serialization types
// Note: VersionNegotiationStateJSON is re-exported via triple-ratchet/version to avoid TS2308
export type {
  KDFChainJSON,
  EpochChainsJSON,
  SkippedSPQRKeyJSON,
  SCKAStateJSON,
  SPQRStateJSON,
  PendingBraidMessageJSON,
} from './serialize';

// Version types (SPQRVersion, VersionNegotiationState) re-exported via triple-ratchet barrel.

// Re-export braid types for convenience
// Note: VersionCapability is re-exported via triple-ratchet/version to avoid TS2308
export type { MLKEMBraidAgentState, MLKEMBraidMessage, OutputKey } from './ml-kem-braid/types';

// Braid mode operations
export {
  initializeSPQRBraid,
  spqrBraidSend,
  spqrBraidReceive,
  getNextBraidChunk,
  hasPendingBraidChunks,
  isBraidMode,
  getBraidStateName,
  getBraidEpoch,
} from './braid';

// Braid serialization
export { serializeBraidAgentState, deserializeBraidAgentState } from './braid-serialize';

// Braid serialization types
export type {
  EncoderStateJSON,
  DecoderStateJSON,
  MLKEMBraidAgentStateJSON,
} from './braid-serialize';

// Message header integration
export {
  createSPQRHeader,
  headerToBraidMessage,
  hasSPQRHeader,
  getMessageTypeName,
  // Protobuf serialization with version capability
  serializeSPQRHeaderProto,
  deserializeSPQRHeaderProto,
  // JSON serialization (for debugging)
  serializeSPQRHeaderJSON,
  deserializeSPQRHeaderJSON,
  createEmptySPQRHeader,
  getSPQRHeaderSize,
  embedSPQRInHeader,
  extractSPQRFromHeader,
} from './message';

export type { SPQRMessageHeader, SPQRMessageHeaderJSON } from './message';

// =============================================================================
// Mode-Aware SPQR Initialization
// =============================================================================

import type { SPQRVersion } from '../version';
import { initVersionNegotiation } from '../version';
import { resolveSPQRInfoStrings } from '../../crypto';
import type { SPQRInfoStrings, SPQRLimits } from '../../../types/protocol-config';
import { resolveSPQRLimits } from '../../../types/protocol-config';

// Re-export limits types for convenience
export type { SPQRLimits, ResolvedSPQRLimits } from '../../../types/protocol-config';
export { SPQR_LIMITS_DEFAULTS, resolveSPQRLimits } from '../../../types/protocol-config';

/**
 * Options for initializing SPQR state.
 */
export interface SPQRInitOptions {
  /** SCKA mode: 'braid' (default) or explicit 'direct' */
  mode: SCKAMode;
  /** Initial root key from PQXDH key agreement */
  initialRootKey: Uint8Array;
  /** Communication direction ('A2B' for Alice, 'B2A' for Bob) */
  direction: 'A2B' | 'B2A';
  /** Our initial Kyber private key (Base64) */
  ourKyberPrivateKey?: string | null;
  /** Their initial Kyber public key (Base64) */
  theirKyberPublicKey?: string | null;

  // =========================================================================
  // Version Negotiation Options
  // =========================================================================

  /**
   * Maximum SPQR version we support.
   *
   * Advertised to peer during negotiation. The negotiated version will be
   * min(our maxVersion, their maxVersion).
   *
   * @default 'v1'
   */
  maxVersion?: SPQRVersion;

  /**
   * Minimum SPQR version we accept.
   *
   * If peer's maxVersion is below this, negotiation fails with an error.
   * Set to 'v1' to require post-quantum security.
   *
   * @default 'v1'
   */
  minVersion?: SPQRVersion;

  // =========================================================================
  // HKDF Info Strings (Customization)
  // =========================================================================

  /**
   * Custom SPQR HKDF info strings for domain separation.
   *
   * The default chain-start value is
   * `"Signal PQ Ratchet V1 Chain  Start"` (two spaces before "Start").
   * That byte sequence is pinned because changing it changes derived keys.
   *
   * **Default behavior**: Uses the pinned profile strings.
   *
   * **With custom prefix**: Derives clean strings without the quirk.
   *
   * @example Using prefix (derives clean strings)
   * ```typescript
   * spqrInfoStrings: {
   *   prefix: 'MyProtocol V2 Chain '
   *   // Results in:
   *   // chainStart: 'MyProtocol V2 Chain Start'      // single space
   *   // chainAddEpoch: 'MyProtocol V2 Chain Add Epoch'
   *   // chainNext: 'MyProtocol V2 Chain Next'
   * }
   * ```
   *
   * @example Override individual string
   * ```typescript
   * spqrInfoStrings: {
   *   chainStart: 'Custom Init String'  // Only override this one
   * }
   * ```
   */
  spqrInfoStrings?: SPQRInfoStrings;

  // =========================================================================
  // Security Limits (Customization)
  // =========================================================================

  /**
   * Custom security limits for SPQR operations.
   *
   * Controls DoS protection limits, epoch retention, and refresh thresholds.
   * Defaults are defined by `SPQR_LIMITS_DEFAULTS`.
   *
   * @example Lower limits for constrained local development
   * ```typescript
   * spqrLimits: {
   *   maxMessageJump: 100,     // Default: 25000
   *   maxOutOfOrderKeys: 50,   // Default: 2000
   * }
   * ```
   *
   */
  spqrLimits?: SPQRLimits;
}

/**
 * Initialize SPQR state with the selected SCKA mode.
 *
 * This is the recommended entry point for SPQR initialization as it handles
 * mode dispatch automatically:
 *
 * - `'braid'`: Uses the specification-defined ML-KEM Braid profile (braid.ts)
 * - `'direct'`: Uses explicit direct ML-KEM-768 encapsulation (spqr.ts)
 *
 * @param options - Initialization options including mode selection
 * @returns Initialized SPQR state
 *
 * @example Braid mode (default)
 * ```typescript
 * const spqrState = await initializeSPQR({
 *   mode: 'braid',
 *   initialRootKey: SKscka,
 *   direction: 'A2B',
 *   ourKyberPrivateKey,
 *   theirKyberPublicKey
 * });
 * ```
 *
 * @example Explicit direct mode
 * ```typescript
 * const spqrState = await initializeSPQR({
 *   mode: 'direct',
 *   initialRootKey: SKscka,
 *   direction: 'A2B',
 *   ourKyberPrivateKey,
 *   theirKyberPublicKey
 * });
 * ```
 */
export async function initializeSPQR(options: SPQRInitOptions): Promise<SPQRState> {
  const {
    mode,
    initialRootKey,
    direction,
    ourKyberPrivateKey,
    theirKyberPublicKey,
    maxVersion = 'v1',
    minVersion = 'v1',
    spqrInfoStrings,
    spqrLimits,
  } = options;

  // Resolve info strings (use provided or pinned-reference defaults)
  const resolvedInfoStrings = resolveSPQRInfoStrings(spqrInfoStrings);

  // Resolve security limits (use provided or profile defaults)
  const resolvedLimits = resolveSPQRLimits(spqrLimits);

  if (mode === 'braid') {
    // Use the specification-defined ML-KEM Braid state machine.
    const { initializeSPQRBraid } = await import('./braid');
    const braidState = await initializeSPQRBraid(options);
    // Ensure info strings and limits are set for braid mode too
    return {
      ...braidState,
      infoStrings: resolvedInfoStrings,
      limits: resolvedLimits,
      versionNegotiation: initVersionNegotiation(maxVersion, minVersion),
    };
  }

  // Explicit direct SCKA mode.
  const { initializeSPQRState } = await import('./spqr');
  const state = await initializeSPQRState(
    initialRootKey,
    direction,
    ourKyberPrivateKey,
    theirKyberPublicKey,
    resolvedInfoStrings,
    resolvedLimits
  );

  // Add mode and version negotiation to state
  return {
    ...state,
    mode: 'direct',
    versionNegotiation: initVersionNegotiation(maxVersion, minVersion),
  };
}
