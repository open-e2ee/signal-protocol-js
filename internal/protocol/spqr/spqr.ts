/**
 * SPQR (Sparse Post-Quantum Ratchet) Operations
 *
 * @module spqr/spqr
 *
 * Signal Protocol Section 5 & 6 implementation for Triple Ratchet.
 * Provides post-quantum security through ML-KEM-768 (CRYSTALS-Kyber)
 * key encapsulation mechanism, protecting against "harvest now, decrypt later"
 * quantum computer attacks.
 *
 * ## Tiered ML-KEM Security Model
 *
 * Signal uses different ML-KEM variants for different protocols:
 *
 * | Protocol | ML-KEM Variant | NIST Level | Usage                |
 * |----------|----------------|------------|----------------------|
 * | PQXDH    | ML-KEM-1024    | 5 (256-bit)| Initial key exchange |
 * | SPQR     | ML-KEM-768     | 3 (192-bit)| Continuous ratchet   |
 *
 * **Rationale for ML-KEM-768 in SPQR:**
 * - Continuous ratchet sends key material every ~50 messages
 * - ML-KEM-768: 1,088 bytes/ratchet vs ML-KEM-1024: 1,568 bytes
 * - Hybrid mode (EC + PQ) provides defense-in-depth anyway
 * - NIST recommends Level 3 for general-purpose use
 *
 * ## Overview
 *
 * SPQR runs in parallel with the EC Double Ratchet, providing a second layer
 * of key agreement using post-quantum cryptography. The message keys from both
 * ratchets are combined via KDF_HYBRID to produce the final encryption keys.
 *
 * ## Architecture
 *
 * ```
 * ┌────────────────────────────────────────────────────────────┐
 * │                    Triple Ratchet                          │
 * ├─────────────────────────┬──────────────────────────────────┤
 * │   EC Double Ratchet     │        SPQR (This Module)        │
 * │  ┌─────────────────┐    │    ┌─────────────────────────┐   │
 * │  │ X25519 DH       │    │    │ ML-KEM-768 (Kyber)      │   │
 * │  │ Ratchet Keys    │    │    │ Encapsulation           │   │
 * │  └────────┬────────┘    │    └───────────┬─────────────┘   │
 * │           │             │                │                 │
 * │           v             │                v                 │
 * │  ┌─────────────────┐    │    ┌─────────────────────────┐   │
 * │  │ EC KDF Chain    │    │    │ SPQR KDF Chain          │   │
 * │  │ (per DH step)   │    │    │ (per epoch)             │   │
 * │  └────────┬────────┘    │    └───────────┬─────────────┘   │
 * │           │             │                │                 │
 * │           v             │                v                 │
 * │  ┌─────────────────┐    │    ┌─────────────────────────┐   │
 * │  │ EC Message Key  │────┼───>│ KDF_HYBRID              │   │
 * │  └─────────────────┘    │    │ (combine EC + PQ keys)  │   │
 * │                         │    └───────────┬─────────────┘   │
 * │                         │                │                 │
 * │                         │                v                 │
 * │                         │    ┌─────────────────────────┐   │
 * │                         │    │ Final Message Key       │   │
 * │                         │    └─────────────────────────┘   │
 * └─────────────────────────┴──────────────────────────────────┘
 * ```
 *
 * ## Key Concepts
 *
 * - **Epoch**: Incremented with each DH ratchet step (synchronized)
 * - **SCKA State**: Symmetric Continuous Key Agreement state (ML-KEM keys)
 * - **KDF Chains**: Per-epoch send/receive chains for message keys
 * - **Output Reordering**: Alice uses (CKs, CKr), Bob uses (CKr, CKs)
 *
 * ## HKDF Info Strings (Profile)
 *
 * - `'Signal PQ Ratchet V1 Chain  Start'` - Initial chain setup (96 bytes, note double space)
 * - `'Signal PQ Ratchet V1 Chain Add Epoch'` - Epoch advancement (96 bytes)
 * - `'Signal PQ Ratchet V1 Chain Next'` - Per-message advancement (64 bytes)
 *
 * ## Security Properties
 *
 * - **Post-Quantum Contribution**: standardized ML-KEM-768 feeds each eligible
 *   epoch; the end-to-end claim remains conditional on the full protocol
 * - **Forward Secrecy**: Old state is pruned and owned byte buffers are cleared
 *   on a best-effort basis; JavaScript cannot guarantee physical erasure
 * - **Hybrid intent**: a later EC break alone should not recover epochs whose
 *   ML-KEM contribution and surrounding protocol assumptions remain secure
 * - **Sparse Ratcheting**: Only ratchets on DH steps (reduces overhead)
 *
 * ## Specification References
 *
 * @see https://signal.org/blog/spqr/ - Signal SPQR specification
 * @see https://csrc.nist.gov/pubs/fips/203/final - NIST FIPS 203 (ML-KEM)
 *
 * @example Initialize SPQR state
 * ```typescript
 * const spqrState = await initializeSPQRState(
 *   initialRootKey,    // From PQXDH key agreement
 *   'A2B',             // Alice is initiator
 *   ourKyberPrivKey,   // Our ML-KEM-768 private key
 *   theirKyberPubKey   // Their ML-KEM-768 public key
 * );
 * ```
 */

import {
  base64ToBytes,
  bytesToBase64,
  // ML-KEM-768 functions (for SPQR continuous ratchet)
  generateKyber768KeyPair,
  kyber768Decapsulate,
  kyber768Encapsulate,
  // SPQR-specific KDF functions (profile)
  kdfSpqrInit,
  kdfSpqrEpoch,
  kdfChainKeySPQR,
  secureZeroBytes,
  // Info string resolution
  resolveSPQRInfoStrings,
  type ResolvedSPQRInfoStrings,
} from '../../crypto';
import { defaultSignalLogger, type ILogger } from '../../../logger';

// SPQR limits configuration (profile protocol defaults)
import { type ResolvedSPQRLimits, SPQR_LIMITS_DEFAULTS } from '../../../types/protocol-config';
import { EncryptionError, EncryptionErrorCode } from '../../../types/errors';
import { asBase64, type Base64 } from '../../../types/utils';
// SCKAState is the canonical type from session.ts - imported here for internal use
import type { SCKAState } from '../../../types/session';

// Braid mode types (imported dynamically to avoid circular deps when not used)
import type { MLKEMBraidAgentState, MLKEMBraidMessage, OutputKey } from './ml-kem-braid/types';
import { KDF_OK } from './ml-kem-braid/kdf';

// Version negotiation (owned by Triple Ratchet)
import type { VersionNegotiationState } from '../version';
import {
  initVersionNegotiation,
  isVersionNegotiationComplete,
  processVersionFromByte,
} from '../version';

// Validation functions (extracted for modularity)
import { validateSPQRState, trimSkippedKeys } from './validate';

// SPQR wire format serialization (no circular dependency — pure encode/decode module)
import {
  encodeSPQRWire,
  decodeSPQRWire,
  spqrInternalEpochToWireEpoch,
  spqrWireEpochToInternalEpoch,
  spqrWireEpochToBigInt,
} from '../../encoding/proto/pq-ratchet-serialize';

// ============================================================================
// SPQR Constants
// ============================================================================

/**
 * Zeroed chain key sentinel (32 zero bytes, base64-encoded).
 *
 * Used to clear chain keys for forward secrecy instead of empty strings.
 * A 32-byte zero key is the correct sentinel for a cleared 32-byte chain key.
 */
export {};
const ZEROED_CHAIN_KEY = bytesToBase64(new Uint8Array(32));
const SPQR_EPOCH_SECRET_LENGTH = 32;

function getNextSPQREpoch(spqrState: SPQRState, operation: string): number {
  validateSPQRState(spqrState, operation);
  if (!Number.isSafeInteger(spqrState.epoch) || spqrState.epoch >= Number.MAX_SAFE_INTEGER) {
    throw new EncryptionError(
      `Cannot advance SPQR epoch safely from ${spqrState.epoch}`,
      EncryptionErrorCode.SPQR_EPOCH_OUT_OF_RANGE,
      { operation, epoch: spqrState.epoch }
    );
  }
  return spqrState.epoch + 1;
}

// ============================================================================
// SPQR Types
// ============================================================================

/**
 * KDF chain for message key derivation
 */
export interface KDFChain {
  /** Current chain key (Base64) */
  CK: Base64;
  /** Message counter */
  N: number;
}

/**
 * Epoch chains (send and receive)
 */
export interface EpochChains {
  /** Sending chain */
  send: KDFChain;
  /** Receiving chain */
  receive: KDFChain;
}

/**
 * Skipped SPQR message key
 */
export interface SkippedSPQRKey {
  /** Message key (Base64) */
  key: Base64;
  /** Timestamp when stored */
  timestamp: number;
}

// SCKAState type is imported from ../../../types/session (single source of truth).
// Re-export here to keep SPQR call sites local to this module.
export type { SCKAState } from '../../../types/session';

/**
 * SCKA (Symmetric Continuous Key Agreement) mode.
 *
 * - `'braid'`: specification-defined ML-KEM Braid profile (default)
 * - `'direct'`: Explicit direct ML-KEM-768 encapsulation mode
 */
export type SCKAMode = 'direct' | 'braid';

// Re-export version types so SPQR callers do not import from the version module directly.
export type { SPQRVersion, VersionNegotiationState } from '../version';

/**
 * SPQR (Sparse Post-Quantum Ratchet) State
 *
 * Runs in parallel with EC Double Ratchet to provide
 * post-quantum security via ML-KEM-768 (Kyber).
 */
export interface SPQRState {
  /** Current SPQR root key (Base64) */
  RK: Base64;
  /** Current epoch number */
  epoch: number;
  /**
   * Latest epoch used for sending.
   *
   * Tracks the most recent epoch from which a send key was derived.
   * When this advances, old send chain keys for earlier epochs are cleared
   * per `SPQR`'s the profile()` pattern. This provides forward secrecy
   * for sent messages while preserving receive chains for in-flight messages.
   *
   */
  sendEpoch?: number;
  /** KDF chains indexed by epoch */
  kdfChains: Record<number, EpochChains>;
  /** Skipped message keys indexed by "epoch:index" (per Signal SPQR naming) */
  MKSKIPPED: Record<string, SkippedSPQRKey>;
  /** Communication direction */
  direction: 'A2B' | 'B2A';
  /** SCKA state for Kyber key management */
  sckaState: SCKAState;
  /**
   * SCKA mode used for this session.
   *
   * - `'braid'` (default): specification-defined ML-KEM Braid profile
   * - `'direct'`: Explicit direct ML-KEM-768 encapsulation mode
   *
   * Once set during session establishment, the mode is fixed for the
   * lifetime of the session to ensure protocol consistency.
   *
   * @default 'braid'
   */
  mode: SCKAMode;

  // =========================================================================
  // Braid Mode State (only present when mode === 'braid')
  // =========================================================================

  /**
   * ML-KEM Braid agent state (Alice or Bob).
   *
   * Contains the 11-state machine state, encoders/decoders, and key material.
   * Only present when mode === 'braid'.
   */
  braidState?: MLKEMBraidAgentState;

  /**
   * Pending outgoing chunks for braid mode.
   *
   * When braid mode generates chunks, they are queued here for embedding
   * in Double Ratchet message headers. The message layer pops chunks
   * from this queue using getNextBraidChunk().
   */
  pendingOutgoingChunks?: MLKEMBraidMessage[];

  // =========================================================================
  // Version Negotiation State
  // =========================================================================

  /**
   * Version negotiation state for this session.
   *
   * Tracks the negotiation process with the peer to agree on a protocol version.
   * Once negotiation completes, the version is locked for the session lifetime.
   *
   * @see VersionNegotiationState
   */
  versionNegotiation?: VersionNegotiationState;

  // =========================================================================
  // HKDF Info Strings (Customizable)
  // =========================================================================

  /**
   * Resolved HKDF info strings for KDF operations.
   *
   * These strings provide domain separation for SPQR key derivation.
   * The default CHAIN_START byte sequence includes a pinned double space.
   *
   * Customizable via SignalProtocolClient config for non-Signal deployments.
   *
   * @see ResolvedSPQRInfoStrings
   */
  infoStrings?: ResolvedSPQRInfoStrings;

  /**
   * Resolved security limits for SPQR operations.
   *
   * Controls DoS protection limits, epoch retention, and refresh thresholds.
   * Defaults are defined by `SPQR_LIMITS_DEFAULTS`.
   *
   * Customizable via SignalProtocolClient config for diagnostics and reviewed product limits.
   *
   * @see ResolvedSPQRLimits
   */
  limits?: ResolvedSPQRLimits;

  /**
   * Flag: next spqrSend() should do full KEM ratchet.
   *
   * Set to true by spqrRecv() after decapsulating kyber ciphertext,
   * and during bootstrap. Cleared by spqrSend() after performing the
   * encapsulation/keypair generation.
   *
   * `send()` decides whether to perform a KEM exchange from its own state.
   */
  needsSendRatchet?: boolean;
}

/**
 * Result of SPQR ratchet step
 */
export interface SPQRRatchetResult {
  /** Kyber ciphertext to send to partner (direct mode only) */
  kyberCiphertextToSend: Uint8Array | null;

  /** New Kyber public key to send (so receiver can encapsulate to us next ratchet) */
  kyberPublicKeyToSend: Uint8Array | null;

  // =========================================================================
  // Braid Mode Results (only present when mode === 'braid')
  // =========================================================================

  /**
   * Chunks to embed in message headers (braid mode only).
   *
   * These chunks should be transmitted via Double Ratchet message headers.
   * The receiver processes them with processSPQRBraidReceive().
   */
  braidChunks?: MLKEMBraidMessage[];

  /**
   * Output key from braid epoch completion (braid mode only).
   *
   * Present when a braid epoch completes and a shared secret is derived.
   * This key should be mixed with the EC Double Ratchet key via KDF_HYBRID.
   */
  outputKey?: OutputKey;
}

/**
 * Result of SPQR chunk processing (braid mode)
 */
export interface SPQRChunkResult {
  /** Chunks generated for transmission */
  chunks: MLKEMBraidMessage[];
  /** Output key when epoch completes */
  outputKey?: OutputKey;
  /** Current epoch (sending for spqrBraidSend, receiving for spqrBraidReceive) */
  epoch: bigint;
}

/**
 * Result of SPQR message key derivation
 */
export interface SPQRKeyResult {
  /** Derived message key (32 bytes) */
  messageKey: Uint8Array;
  /** Message index within this epoch (per Signal SPQR naming) */
  index: number;
  /** Epoch number */
  epoch: number;
}

// ============================================================================
// SPQR Configuration Constants (profile)
// ============================================================================

/**
 * SPQR Configuration Constants
 *
 * Security/policy limits are sourced from SPQR_LIMITS_DEFAULTS (DRY).
 * ML-KEM sizes and internal limits remain hardcoded (not configurable).
 *
 */
/**
 * Epochs to retain prior to send epoch.
 *
 * This is a protocol constant, not configurable. Signal hardcodes this value
 * as `EPOCHS_TO_KEEP_PRIOR_TO_SEND_EPOCH: usize = 1` in the profile.
 * Keeping 1 previous epoch means current epoch + 1 previous = 2 total epochs
 * in memory, providing fast forward secrecy while allowing in-flight messages
 * from the previous epoch to be decrypted.
 */
const EPOCHS_TO_KEEP_PRIOR_TO_SEND_EPOCH = 1;

export const SPQR_CONFIG = {
  // ===== Security Limits =====
  // Sourced from SPQR_LIMITS_DEFAULTS for single source of truth

  /** Maximum message number jump allowed (prevents DoS via skipped keys) */
  MAX_MESSAGE_JUMP: SPQR_LIMITS_DEFAULTS.maxMessageJump,

  /** Maximum out-of-order keys to store (limits memory usage) */
  MAX_OOO_KEYS: SPQR_LIMITS_DEFAULTS.maxOutOfOrderKeys,

  /** Maximum old epochs to keep prior to send epoch */
  MAX_EPOCHS_TO_KEEP: EPOCHS_TO_KEEP_PRIOR_TO_SEND_EPOCH,

  // ===== Internal Limits (not configurable) =====

  /**
   * Maximum index per epoch before overflow.
   *
   * Counter should never reach this - triggers epoch rotation.
   */
  MAX_INDEX: 1000000,

  /** Maximum age for skipped keys before cleanup (7 days) */
  MAX_SKIPPED_KEY_AGE: 7 * 24 * 60 * 60 * 1000,

  // ===== ML-KEM-768 Sizes (NIST FIPS 203) =====
  // Note: SPQR uses ML-KEM-768 for bandwidth efficiency
  // PQXDH uses ML-KEM-1024 for maximum security (see crypto/kyber.ts)
  // Values are literals to ensure `as const` works correctly for module exports

  /** ML-KEM-768 ciphertext size in bytes */
  MLKEM768_CIPHERTEXT_SIZE: 1088,

  /** ML-KEM-768 public key size in bytes */
  MLKEM768_PUBLIC_KEY_SIZE: 1184,

  /** ML-KEM-768 secret key size in bytes */
  MLKEM768_SECRET_KEY_SIZE: 2400,

  /** ML-KEM-768 shared secret size in bytes */
  MLKEM768_SHARED_SECRET_SIZE: 32,
};

// ============================================================================
// SPQR Bootstrap Completeness (Section 3.10)
// ============================================================================

/**
 * Check if SPQR bootstrap is complete (profile).
 *
 * The SPQR protocol "locks in" after receiving the first message from
 * the remote party. This is tracked via version negotiation completion, since
 * version capability and Kyber material arrive in the same message.
 *
 * SPQR bootstrap is considered **complete** when:
 * 1. `theirKyberPublicKey` is set (we can encapsulate TO them)
 * 2. Version negotiation is complete (we've received their first message)
 *
 * When bootstrap is incomplete, SPQR key derivation functions return `null`,
 * and the Triple Ratchet uses bootstrap EC keys until SPQR can contribute.
 *
 * @param spqrState - Current SPQR state
 * @returns true if SPQR can derive matching keys on both sides
 *
 * @see https://signal.org/blog/spqr/
 */
export function isSpqrBootstrapComplete(spqrState: SPQRState): boolean {
  if (spqrState.mode === 'braid') {
    return !!spqrState.braidState && isVersionNegotiationComplete(spqrState.versionNegotiation);
  }

  // Need their public key to encapsulate TO them
  if (spqrState.sckaState.theirKyberPublicKey === null) {
    return false;
  }

  // Version negotiation complete = received first message from peer
  // = bidirectional exchange confirmed (the SPQR "locked in" state)
  return isVersionNegotiationComplete(spqrState.versionNegotiation);
}

// ============================================================================
// SPQR State Initialization
// ============================================================================

/**
 * Initialize SPQR state for a new session.
 *
 * Called during session establishment (X3DH/PQXDH) to set up the
 * Sparse Post-Quantum Ratchet state alongside the EC Double Ratchet.
 *
 * @param initialRootKey - Initial root key (from PQXDH)
 * @param direction - Communication direction ('A2B' or 'B2A')
 * @param ourKyberPrivateKey - Our initial Kyber private key (optional)
 * @param theirKyberPublicKey - Their initial Kyber public key (optional)
 * @param infoStrings - Custom HKDF info strings (optional, defaults to pinned reference)
 * @param limits - Custom security limits (optional, defaults to profile)
 * @returns Initialized SPQR state
 */
export async function initializeSPQRState(
  initialRootKey: Uint8Array,
  direction: 'A2B' | 'B2A',
  ourKyberPrivateKey?: string | null,
  theirKyberPublicKey?: string | null,
  infoStrings?: ResolvedSPQRInfoStrings,
  limits?: ResolvedSPQRLimits
): Promise<SPQRState> {
  // Initialize SCKA state
  const sckaState: SCKAState = {
    epoch: 0,
    direction,
    ourKyberPrivateKey: ourKyberPrivateKey ? asBase64(ourKyberPrivateKey) : null,
    theirKyberPublicKey: theirKyberPublicKey ? asBase64(theirKyberPublicKey) : null,
    lastRefreshTimestamp: Date.now(),
    lastRefreshMessageCount: 0,
  };

  // Resolve info strings (use provided or pinned-reference defaults)
  const resolvedInfoStrings = infoStrings ?? resolveSPQRInfoStrings();

  // Per Signal SPQR spec: Initialize chains using profile KDF
  // Uses info string "Signal PQ Ratchet V1 Chain  Start" (TWO spaces) with 96-byte output:
  // [0:32] = new root key, [32:64] = A2B chain, [64:96] = B2A chain
  const {
    rootKey: newRootKey,
    a2bChainKey,
    b2aChainKey,
  } = await kdfSpqrInit(initialRootKey, resolvedInfoStrings.chainStart);

  // Per Signal Protocol Section 5.4 (Output Reordering):
  // - Alice (A2B): send = A2B, receive = B2A (natural order)
  // - Bob (B2A): send = B2A, receive = A2B (swapped order)
  // This ensures Alice's send chain = Bob's receive chain (same bytes)
  const sendChainKey = direction === 'A2B' ? a2bChainKey : b2aChainKey;
  const receiveChainKey = direction === 'A2B' ? b2aChainKey : a2bChainKey;
  let encodedRootKey: Base64;
  let encodedSendChainKey: Base64;
  let encodedReceiveChainKey: Base64;
  try {
    encodedRootKey = bytesToBase64(newRootKey);
    encodedSendChainKey = bytesToBase64(sendChainKey);
    encodedReceiveChainKey = bytesToBase64(receiveChainKey);
  } finally {
    secureZeroBytes(newRootKey);
    secureZeroBytes(a2bChainKey);
    secureZeroBytes(b2aChainKey);
  }

  // Initialize SPQR state with epoch 0 chains
  // Note: RK is updated to newRootKey from kdfSpqrInit (not initial root key)
  const spqrState: SPQRState = {
    RK: encodedRootKey,
    epoch: 0,
    sendEpoch: 0,
    kdfChains: {
      0: {
        send: {
          CK: encodedSendChainKey,
          N: 0,
        },
        receive: {
          CK: encodedReceiveChainKey,
          N: 0,
        },
      },
    },
    MKSKIPPED: {},
    direction,
    sckaState,
    mode: 'direct', // Default mode for direct initialization
    // Version negotiation initialized with v1-only defaults
    // Note: This can be overridden by initializeSPQR() if different options provided
    versionNegotiation: initVersionNegotiation('v1', 'v1'),
    // Store resolved info strings for use in subsequent KDF operations
    infoStrings: resolvedInfoStrings,
    // Store resolved limits for use in SPQR operations (DoS protection, epoch retention)
    limits: limits ?? SPQR_LIMITS_DEFAULTS,
  };

  return spqrState;
}

// ============================================================================
// SPQR Epoch Advancement
// ============================================================================

/**
 * Add an already-derived SCKA epoch secret to the SPQR chain.
 *
 * This helper deliberately does not apply the `:SCKA Key` KDF. ML-KEM Braid
 * applies that KDF inside its state machine before returning OutputKey.
 *
 * Per `SPQR` the profile add_epoch()`.
 *
 * @param spqrState - SPQR state (mutated)
 * @param epochSecret - Already-derived SCKA epoch secret
 * @param chains - Which chains to initialize: 'both' | 'receive'
 */
async function addSPQREpochSecret(
  spqrState: SPQRState,
  epochSecret: Uint8Array,
  chains: 'both' | 'receive',
  expectedEpoch: number
): Promise<void> {
  const currentEpoch = spqrState.epoch;
  const nextEpoch = getNextSPQREpoch(spqrState, 'addSPQREpochSecret');
  if (expectedEpoch !== nextEpoch) {
    throw new EncryptionError(
      `SPQR epoch changed before chain-add: expected ${expectedEpoch}, got ${nextEpoch}`,
      EncryptionErrorCode.INVALID_STATE,
      { operation: 'addSPQREpochSecret', expectedEpoch, actualEpoch: nextEpoch }
    );
  }
  if (spqrState.sckaState.epoch !== spqrState.epoch) {
    throw new EncryptionError(
      `SCKA epoch ${spqrState.sckaState.epoch} does not match SPQR epoch ${spqrState.epoch}`,
      EncryptionErrorCode.INVALID_STATE,
      {
        operation: 'addSPQREpochSecret',
        spqrEpoch: spqrState.epoch,
        sckaEpoch: spqrState.sckaState.epoch,
      }
    );
  }
  if (epochSecret.length !== SPQR_EPOCH_SECRET_LENGTH) {
    throw new EncryptionError(
      `SPQR epoch secret must be ${SPQR_EPOCH_SECRET_LENGTH} bytes, got ${epochSecret.length}`,
      EncryptionErrorCode.INVALID_STATE,
      {
        operation: 'addSPQREpochSecret',
        expectedLength: SPQR_EPOCH_SECRET_LENGTH,
        actualLength: epochSecret.length,
      }
    );
  }

  const currentRootKeyBase64 = spqrState.RK;
  const currentRootKey = base64ToBytes(currentRootKeyBase64);
  const ownedDerivedKeys: Uint8Array[] = [];
  try {
    if (currentRootKey.length !== 32) {
      throw new EncryptionError(
        `SPQR root key must decode to 32 bytes, got ${currentRootKey.length}`,
        EncryptionErrorCode.INVALID_STATE,
        {
          operation: 'addSPQREpochSecret',
          expectedLength: 32,
          actualLength: currentRootKey.length,
        }
      );
    }

    // Derive and encode every candidate before mutating live state. A validation,
    // KDF, or encoding failure therefore leaves the complete state unchanged.
    const {
      rootKey: newRootKey,
      a2bChainKey,
      b2aChainKey,
    } = await kdfSpqrEpoch(epochSecret, currentRootKey, spqrState.infoStrings?.chainAddEpoch);
    ownedDerivedKeys.push(newRootKey, a2bChainKey, b2aChainKey);

    const sendChainKey = spqrState.direction === 'A2B' ? a2bChainKey : b2aChainKey;
    const receiveChainKey = spqrState.direction === 'A2B' ? b2aChainKey : a2bChainKey;
    const candidateRootKey = bytesToBase64(newRootKey);
    const candidateSendChainKey = bytesToBase64(sendChainKey);
    const candidateReceiveChainKey = bytesToBase64(receiveChainKey);
    const existingNextEpoch = spqrState.kdfChains[nextEpoch];
    const candidateChains: EpochChains =
      chains === 'both'
        ? {
            send: { CK: candidateSendChainKey, N: 0 },
            receive: { CK: candidateReceiveChainKey, N: 0 },
          }
        : {
            send: existingNextEpoch
              ? { ...existingNextEpoch.send }
              : { CK: ZEROED_CHAIN_KEY, N: 0 },
            receive: { CK: candidateReceiveChainKey, N: 0 },
          };
    const candidateRefreshTimestamp = Date.now();

    if (
      spqrState.epoch !== currentEpoch ||
      spqrState.sckaState.epoch !== currentEpoch ||
      spqrState.RK !== currentRootKeyBase64
    ) {
      throw new EncryptionError(
        'SPQR state changed during chain-add derivation',
        EncryptionErrorCode.INVALID_STATE,
        {
          operation: 'addSPQREpochSecret',
          expectedEpoch: currentEpoch,
          actualEpoch: spqrState.epoch,
        }
      );
    }

    // Commit only after the complete candidate exists. The epoch secret is not
    // retained: the chain-add output is the sole persisted authority for it.
    spqrState.RK = candidateRootKey;
    spqrState.kdfChains[nextEpoch] = candidateChains;
    spqrState.epoch = nextEpoch;
    spqrState.sckaState.epoch = nextEpoch;
    spqrState.sckaState.lastRefreshTimestamp = candidateRefreshTimestamp;
  } finally {
    secureZeroBytes(currentRootKey);
    for (const key of ownedDerivedKeys) secureZeroBytes(key);
  }
}

/**
 * Advance direct ML-KEM mode from raw KEM output.
 *
 * Direct mode does not have a Braid state machine to apply KDF_OK, so it must
 * derive the epoch secret here before invoking the chain-add operation.
 *
 * @internal Deterministic epoch-transition seam; not part of the public API.
 */
export async function advanceSPQREpochFromRawSecret(
  spqrState: SPQRState,
  rawSharedSecret: Uint8Array,
  chains: 'both' | 'receive'
): Promise<void> {
  const nextEpoch = getNextSPQREpoch(spqrState, 'advanceSPQREpochFromRawSecret');
  const epochSecret = await KDF_OK(rawSharedSecret, BigInt(nextEpoch));

  try {
    await addSPQREpochSecret(spqrState, epochSecret, chains, nextEpoch);
  } finally {
    secureZeroBytes(epochSecret);
  }
}

/**
 * Consume an OutputKey produced by ML-KEM Braid without applying KDF_OK again.
 *
 * Ownership transfers to this function. The caller must not reuse
 * `outputKey.epoch_secret`; it is cleared on both success and failure after the
 * epoch check and candidate derivation have completed.
 *
 * @internal Deterministic epoch-transition seam; not part of the public API.
 */
export async function addSPQRBraidEpoch(
  spqrState: SPQRState,
  outputKey: OutputKey,
  chains: 'both' | 'receive' = 'both'
): Promise<void> {
  try {
    const expectedEpoch = getNextSPQREpoch(spqrState, 'addSPQRBraidEpoch');
    if (outputKey.epoch !== BigInt(expectedEpoch)) {
      throw new EncryptionError(
        `Braid output epoch ${outputKey.epoch} does not match next SPQR epoch ${expectedEpoch}`,
        EncryptionErrorCode.INVALID_STATE,
        {
          operation: 'addSPQRBraidEpoch',
          expectedEpoch: expectedEpoch.toString(),
          actualEpoch: outputKey.epoch.toString(),
        }
      );
    }

    await addSPQREpochSecret(spqrState, outputKey.epoch_secret, chains, expectedEpoch);
  } finally {
    secureZeroBytes(outputKey.epoch_secret);
  }
}

// ============================================================================
// SPQR Ratchet Step (Section 5 & 6)
// ============================================================================

/**
 * Perform SPQR ratchet step in parallel with DH ratchet.
 *
 * Signal Protocol Section 6 -
 * "The Triple Ratchet performs DH ratchet and SPQR ratchet in parallel.
 * When the DH ratchet steps (new DH key pair), the SPQR also steps
 * (new Kyber key pair and epoch increment)."
 *
 * This function dispatches based on mode:
 * - **Direct mode**: ML-KEM-768 encapsulation, returns full ciphertext
 * - **Braid mode**: Generates chunks via state machine, returns chunk array
 *
 * @param spqrState - Current SPQR state
 * @returns Updated SPQR state and Kyber ciphertext/chunks to send
 */
export async function performSPQRRatchetStep(spqrState: SPQRState): Promise<SPQRRatchetResult> {
  // Validate state before operation
  validateSPQRState(spqrState, 'performSPQRRatchetStep');

  // Mode dispatch: braid mode uses the ML-KEM Braid state machine
  if (spqrState.mode === 'braid') {
    // Import braid operations (lazy to avoid circular deps)
    const { spqrBraidSend } = await import('./braid');
    const result = await spqrBraidSend(spqrState);

    return {
      kyberCiphertextToSend: null, // No single ciphertext in braid mode
      kyberPublicKeyToSend: null, // Braid mode handles key exchange differently
      braidChunks: result.chunks,
      outputKey: result.outputKey,
    };
  }

  // Direct mode: standard ML-KEM-768 encapsulation

  // Step 1: Generate new ML-KEM-768 key pair for receiving
  // Note: SPQR uses ML-KEM-768 for bandwidth efficiency (vs ML-KEM-1024 in PQXDH)
  const newKyberKeyPair = await generateKyber768KeyPair();
  try {
    spqrState.sckaState.ourKyberPrivateKey = bytesToBase64(newKyberKeyPair.privateKey);
  } finally {
    // The persisted base64 string is immutable; clear the temporary byte key.
    secureZeroBytes(newKyberKeyPair.privateKey);
  }

  // Step 2: Perform ML-KEM-768 encapsulation if we have remote party's public key
  let kyberCiphertextToSend: Uint8Array | null = null;
  let kyberSharedSecret: Uint8Array | null = null;

  try {
    if (spqrState.sckaState.theirKyberPublicKey) {
      const theirPubKeyBytes = base64ToBytes(spqrState.sckaState.theirKyberPublicKey);
      const { sharedSecret, ciphertext } = await kyber768Encapsulate(theirPubKeyBytes);

      kyberSharedSecret = sharedSecret;
      kyberCiphertextToSend = ciphertext;
    }

    // Step 3: Advance epoch with shared secret
    if (!kyberSharedSecret) {
      throw new EncryptionError(
        'SPQR ratchet step requires Kyber shared secret from SCKA',
        EncryptionErrorCode.SPQR_INVALID_CIPHERTEXT,
        { operation: 'performSPQRRatchetStep' }
      );
    }

    await advanceSPQREpochFromRawSecret(spqrState, kyberSharedSecret, 'both');

    return {
      kyberCiphertextToSend,
      kyberPublicKeyToSend: newKyberKeyPair.publicKey,
    };
  } finally {
    if (kyberSharedSecret) secureZeroBytes(kyberSharedSecret);
  }
}

/**
 * Process received Kyber ciphertext during SPQR ratchet.
 *
 * Called when receiving a message with a Kyber ciphertext to:
 * 1. Decapsulate the ciphertext to recover shared secret
 * 2. Update remote party's Kyber public key for next ratchet
 * 3. Derive new receiving chain key
 *
 * @param spqrState - Current SPQR state
 * @param receivedKyberCiphertext - Ciphertext from remote party
 */
export async function processSPQRReceivedCiphertext(
  spqrState: SPQRState,
  receivedKyberCiphertext: Uint8Array
): Promise<void> {
  // Validate state before operation
  validateSPQRState(spqrState, 'processSPQRReceivedCiphertext');

  // Mode dispatch: braid mode uses chunk-by-chunk processing via spqrBraidReceive
  if (spqrState.mode === 'braid') {
    throw new EncryptionError(
      'Braid mode does not use processSPQRReceivedCiphertext. Use spqrBraidReceive() for chunk-by-chunk processing.',
      EncryptionErrorCode.INVALID_STATE,
      {
        operation: 'processSPQRReceivedCiphertext',
        mode: spqrState.mode,
        hint: 'Import spqrBraidReceive from ./braid and call it with each received MLKEMBraidMessage chunk',
      }
    );
  }

  // Validate ciphertext size before processing (defense-in-depth)
  // Note: ML-KEM decapsulation also validates, but early checks provide better errors.
  if (receivedKyberCiphertext.length !== SPQR_CONFIG.MLKEM768_CIPHERTEXT_SIZE) {
    throw new EncryptionError(
      `Invalid ML-KEM-768 ciphertext size: ${receivedKyberCiphertext.length} (expected ${SPQR_CONFIG.MLKEM768_CIPHERTEXT_SIZE})`,
      EncryptionErrorCode.SPQR_INVALID_CIPHERTEXT,
      {
        receivedSize: receivedKyberCiphertext.length,
        expectedSize: SPQR_CONFIG.MLKEM768_CIPHERTEXT_SIZE,
        operation: 'processSPQRReceivedCiphertext',
      }
    );
  }

  if (!spqrState.sckaState.ourKyberPrivateKey) {
    throw new EncryptionError(
      'No Kyber private key available for decapsulation',
      EncryptionErrorCode.SPQR_INVALID_CIPHERTEXT,
      { operation: 'processSPQRReceivedCiphertext' }
    );
  }

  // Decapsulate to recover shared secret using ML-KEM-768
  const ourPrivKeyBytes = base64ToBytes(spqrState.sckaState.ourKyberPrivateKey);
  let sharedSecret: Uint8Array | undefined;
  try {
    sharedSecret = await kyber768Decapsulate(receivedKyberCiphertext, ourPrivKeyBytes);
    // Advance epoch with shared secret (receive chain only)
    await advanceSPQREpochFromRawSecret(spqrState, sharedSecret, 'receive');
  } finally {
    secureZeroBytes(ourPrivKeyBytes);
    if (sharedSecret) secureZeroBytes(sharedSecret);
  }
}

// ============================================================================
// SPQR Message Key Derivation
// ============================================================================

/**
 * Derive next message key from SPQR sending chain.
 *
 * Called when encrypting a message to derive the PQ message key
 * that will be combined with the EC message key via KDF_HYBRID.
 *
 * @param spqrState - Current SPQR state
 * @returns Message key (32 bytes) and updated message number
 */
export async function deriveSPQRSendKey(
  spqrState: SPQRState,
  logger: Required<ILogger> = defaultSignalLogger,
  epochOverride?: number
): Promise<SPQRKeyResult | null> {
  // Validate state before operation
  validateSPQRState(spqrState, 'deriveSPQRSendKey');

  // Bootstrap completeness check (Section 3.10):
  // During the bootstrap window (before first successful epoch advancement),
  // SPQR cannot derive matching keys on both sides. Return null so the Triple
  // Ratchet keeps using its bootstrap EC key.
  if (!isSpqrBootstrapComplete(spqrState)) {
    logger.debug('SPQR bootstrap incomplete, using bootstrap EC key', {
      category: 'E2EE',
      data: {
        operation: 'deriveSPQRSendKey',
        hasTheirKyber: !!spqrState.sckaState.theirKyberPublicKey,
        currentEpoch: spqrState.epoch,
        reason: 'Bootstrap incomplete - waiting for first epoch advancement',
      },
    });
    return null;
  }

  // Log bootstrap complete state (symmetric with "bootstrap incomplete" log above)
  // Uses debug level for consistency - both states logged at same verbosity
  logger.debug('SPQR bootstrap complete, deriving hybrid EC+PQ key', {
    category: 'E2EE',
    data: {
      operation: 'spqr-key-derivation',
      keyMode: 'KDF_HYBRID',
      epoch: spqrState.epoch,
      mode: spqrState.mode,
    },
  });

  const epoch = epochOverride ?? spqrState.epoch;

  // Get send chain for current epoch
  if (!spqrState.kdfChains[epoch]) {
    throw new EncryptionError(
      `No KDF chain for epoch ${epoch}`,
      EncryptionErrorCode.SPQR_EPOCH_OUT_OF_RANGE,
      { epoch, operation: 'deriveSPQRSendKey' }
    );
  }

  // Guard against sending from a decreasing epoch (defense-in-depth)
  // Per `SPQR` the profile: reject epoch < send_epoch
  const previousSendEpoch = spqrState.sendEpoch ?? 0;
  if (epoch < previousSendEpoch) {
    throw new EncryptionError(
      'SPQR send epoch decreased',
      EncryptionErrorCode.SPQR_EPOCH_OUT_OF_RANGE,
      { epoch, sendEpoch: previousSendEpoch, operation: 'deriveSPQRSendKey' }
    );
  }

  // M13: Track send_epoch and handle epoch cleanup on advancement.
  // When the send epoch advances, delete old epochs and clear previous send
  // chain keys immediately.
  if (epoch > previousSendEpoch) {
    spqrState.sendEpoch = epoch;

    const oldestToKeep = Math.max(0, epoch - EPOCHS_TO_KEEP_PRIOR_TO_SEND_EPOCH);

    for (const epochStr of Object.keys(spqrState.kdfChains)) {
      const e = parseInt(epochStr, 10);
      if (e < oldestToKeep) {
        // Delete epochs outside the retention window.
        delete spqrState.kdfChains[e];
      } else if (e < epoch) {
        // Clear send chain keys (forward secrecy) but keep receive chains
        // for in-flight message decryption
        spqrState.kdfChains[e].send.CK = ZEROED_CHAIN_KEY;
        spqrState.kdfChains[e].send.N = 0;
      }
    }

    logger.debug('SPQR send epoch advanced, old epochs pruned', {
      category: 'E2EE',
      data: {
        operation: 'spqr-send-epoch-advance',
        previousSendEpoch,
        newSendEpoch: epoch,
        oldestEpochKept: oldestToKeep,
      },
    });
  }

  const sendChain = spqrState.kdfChains[epoch].send;

  // Counter overflow check
  if (sendChain.N >= SPQR_CONFIG.MAX_INDEX) {
    throw new EncryptionError(
      `SPQR index overflow in epoch ${epoch} (index: ${sendChain.N})`,
      EncryptionErrorCode.SPQR_COUNTER_OVERFLOW,
      { epoch, index: sendChain.N, operation: 'deriveSPQRSendKey' }
    );
  }

  const currentChainKey = base64ToBytes(sendChain.CK);
  let newChainKey: Uint8Array | undefined;
  let messageKey: Uint8Array | undefined;
  let committed = false;
  try {
    // Pre-increment logically before KDF,
    // but commit the counter only after derivation and encoding succeed.
    const currentIndex = sendChain.N + 1;
    const result = await kdfChainKeySPQR(
      currentChainKey,
      currentIndex,
      spqrState.infoStrings?.chainNext
    );
    newChainKey = result.chainKey;
    messageKey = result.messageKey;
    const encodedChainKey = bytesToBase64(newChainKey);

    sendChain.CK = encodedChainKey;
    sendChain.N = currentIndex;
    committed = true;

    return {
      messageKey,
      index: currentIndex,
      epoch,
    };
  } finally {
    secureZeroBytes(currentChainKey);
    if (newChainKey) secureZeroBytes(newChainKey);
    if (!committed && messageKey) secureZeroBytes(messageKey);
  }
}

/**
 * Derive message key from SPQR receiving chain.
 *
 * Called when decrypting a message to derive the PQ message key
 * that will be combined with the EC message key via KDF_HYBRID.
 *
 * @param spqrState - Current SPQR state
 * @param index - Message index from header (per Signal SPQR naming)
 * @param epoch - Epoch from header
 * @returns Message key (32 bytes)
 */
export async function deriveSPQRReceiveKey(
  spqrState: SPQRState,
  index: number,
  epoch: number,
  logger: Required<ILogger> = defaultSignalLogger
): Promise<Uint8Array | null> {
  // Validate state before operation
  validateSPQRState(spqrState, 'deriveSPQRReceiveKey');

  // Bootstrap completeness check (Section 3.10):
  // During the bootstrap window, SPQR cannot derive matching keys on both sides.
  // Return null so the Triple Ratchet keeps using its bootstrap EC key.
  //
  // This handles the asymmetric bootstrap scenario after device reset where
  // one party might have advanced their SPQR state but the other hasn't.
  if (!isSpqrBootstrapComplete(spqrState)) {
    logger.debug('SPQR bootstrap incomplete, using bootstrap EC key for decryption', {
      category: 'E2EE',
      data: {
        operation: 'deriveSPQRReceiveKey',
        hasTheirKyber: !!spqrState.sckaState.theirKyberPublicKey,
        currentEpoch: spqrState.epoch,
        requestedEpoch: epoch,
        index,
        reason: 'Bootstrap incomplete - using bootstrap EC key',
      },
    });
    return null;
  }

  // Log bootstrap complete state (symmetric with "bootstrap incomplete" log above)
  logger.debug('SPQR bootstrap complete, deriving hybrid EC+PQ key for decryption', {
    category: 'E2EE',
    data: {
      operation: 'spqr-key-derivation',
      keyMode: 'KDF_HYBRID',
      epoch: spqrState.epoch,
      requestedEpoch: epoch,
      index,
    },
  });

  // Check MKSKIPPED first - if this key was already derived and stored (out-of-order),
  // return it directly instead of re-advancing the chain (which would fail for old indices).
  const skipKey = `${epoch}:${index}`;
  if (spqrState.MKSKIPPED[skipKey]) {
    const storedKey = base64ToBytes(spqrState.MKSKIPPED[skipKey].key);
    delete spqrState.MKSKIPPED[skipKey];
    return storedKey;
  }

  // Validate index is non-negative integer
  if (index < 0 || !Number.isInteger(index)) {
    throw new EncryptionError(
      `Invalid index: ${index}`,
      EncryptionErrorCode.SPQR_MESSAGE_JUMP_TOO_LARGE,
      { epoch, index, operation: 'deriveSPQRReceiveKey' }
    );
  }

  // Validate epoch bounds - cannot request future epochs
  if (epoch > spqrState.epoch) {
    throw new EncryptionError(
      `Future epoch requested: ${epoch} > current ${spqrState.epoch}`,
      EncryptionErrorCode.SPQR_EPOCH_OUT_OF_RANGE,
      { requestedEpoch: epoch, currentEpoch: spqrState.epoch, operation: 'deriveSPQRReceiveKey' }
    );
  }

  // Counter overflow check (mirrors send path at line 895)
  // The sender's send path rejects at N >= MAX_INDEX, so a legitimate sender
  // can never produce an index > MAX_INDEX. Reject early to prevent advancing
  // the receive chain past the limit the sender could never reach.
  if (index > SPQR_CONFIG.MAX_INDEX) {
    throw new EncryptionError(
      `SPQR index overflow: requested index ${index} exceeds MAX_INDEX ${SPQR_CONFIG.MAX_INDEX}`,
      EncryptionErrorCode.SPQR_COUNTER_OVERFLOW,
      { epoch, index, maxIndex: SPQR_CONFIG.MAX_INDEX, operation: 'deriveSPQRReceiveKey' }
    );
  }

  // Validate epoch bounds - cannot request epochs too far in the past
  const oldestEpoch = Math.max(0, spqrState.epoch - EPOCHS_TO_KEEP_PRIOR_TO_SEND_EPOCH);
  if (epoch < oldestEpoch) {
    throw new EncryptionError(
      `Epoch too old: ${epoch} < oldest kept ${oldestEpoch}`,
      EncryptionErrorCode.SPQR_EPOCH_OUT_OF_RANGE,
      { requestedEpoch: epoch, oldestEpoch, operation: 'deriveSPQRReceiveKey' }
    );
  }

  // Check if we have this epoch's chains
  if (!spqrState.kdfChains[epoch]) {
    throw new EncryptionError(
      `No KDF chain for epoch ${epoch}`,
      EncryptionErrorCode.SPQR_EPOCH_OUT_OF_RANGE,
      { epoch, operation: 'deriveSPQRReceiveKey' }
    );
  }

  const receiveChain = spqrState.kdfChains[epoch].receive;
  const indexGap = index - receiveChain.N;

  // Prevent message jump attacks (Signal max_jump pattern)
  const maxMessageJump = spqrState.limits?.maxMessageJump ?? SPQR_CONFIG.MAX_MESSAGE_JUMP;
  if (indexGap > maxMessageJump) {
    throw new EncryptionError(
      `Index jump too large: ${indexGap} exceeds max ${maxMessageJump}`,
      EncryptionErrorCode.SPQR_MESSAGE_JUMP_TOO_LARGE,
      {
        epoch,
        index,
        currentN: receiveChain.N,
        gap: indexGap,
        operation: 'deriveSPQRReceiveKey',
      }
    );
  }

  let currentChainKey = base64ToBytes(receiveChain.CK);
  let currentN = receiveChain.N;

  // Advance chain to target index using profile SPQR KDF
  // Counter is 1-indexed
  let messageKey: Uint8Array | null = null;
  const pendingSkipped: Array<[string, { key: Base64; timestamp: number }]> = [];
  let committed = false;
  try {
    while (currentN < index) {
      currentN++;
      const result = await kdfChainKeySPQR(
        currentChainKey,
        currentN,
        spqrState.infoStrings?.chainNext
      );
      secureZeroBytes(currentChainKey);
      currentChainKey = result.chainKey;

      if (currentN === index) {
        messageKey = result.messageKey;
      } else {
        const skipKey = `${epoch}:${currentN}`;
        try {
          pendingSkipped.push([
            skipKey,
            { key: bytesToBase64(result.messageKey) as Base64, timestamp: Date.now() },
          ]);
        } finally {
          secureZeroBytes(result.messageKey);
        }
      }
    }

    if (!messageKey) {
      throw new EncryptionError(
        `Failed to derive message key for epoch ${epoch}, index ${index}`,
        EncryptionErrorCode.DECRYPTION_FAILED,
        { epoch, index, operation: 'deriveSPQRReceiveKey' }
      );
    }

    const encodedChainKey = bytesToBase64(currentChainKey);
    const maxOOOKeys = spqrState.limits?.maxOutOfOrderKeys ?? SPQR_CONFIG.MAX_OOO_KEYS;
    if (Object.keys(spqrState.MKSKIPPED).length >= maxOOOKeys) {
      trimSkippedKeys(spqrState);
    }
    for (const [skipKey, skipped] of pendingSkipped) {
      spqrState.MKSKIPPED[skipKey] = skipped;
    }
    receiveChain.CK = encodedChainKey;
    receiveChain.N = currentN;
    committed = true;
    return messageKey;
  } finally {
    secureZeroBytes(currentChainKey);
    if (!committed && messageKey) secureZeroBytes(messageKey);
  }
}

/**
 * Try to get a skipped SPQR message key for out-of-order decryption.
 *
 * Checks MKSKIPPED for a previously stored key for out-of-order messages.
 *
 * @param spqrState - Current SPQR state
 * @param epoch - Epoch from message header
 * @param index - Message index from header (per Signal SPQR naming)
 * @returns Message key if found, null otherwise
 */
export async function tryGetSkippedSPQRKey(
  spqrState: SPQRState,
  epoch: number,
  index: number
): Promise<Uint8Array | null> {
  const skipKey = `${epoch}:${index}`;

  if (spqrState.MKSKIPPED[skipKey]) {
    const mk = base64ToBytes(spqrState.MKSKIPPED[skipKey].key);

    // Delete used key (forward secrecy)
    delete spqrState.MKSKIPPED[skipKey];

    return mk;
  }

  return null;
}

// ============================================================================
// Version Negotiation
// ============================================================================
//
// Version negotiation functions have been moved to ../version.ts
// Import them from there:
//   import { initVersionNegotiation, processVersionCapability, ... } from '../version';
//
// Or use the re-exports from ./index.ts.
//
// ============================================================================

// ============================================================================
// SPQR Cleanup
// ============================================================================

/**
 * Clean up old SPQR skipped message keys (Section 8.4).
 *
 * Epoch pruning and send-chain clearing happen immediately in
 * deriveSPQRSendKey() when the epoch advances. This function only needs
 * to handle TTL-based cleanup of skipped message keys.
 *
 * @param spqrState - Current SPQR state
 * @param maxAge - Maximum age in milliseconds (default: from state.limits or 7 days)
 */
export async function cleanupSPQRState(spqrState: SPQRState, maxAge?: number): Promise<void> {
  const now = Date.now();
  const resolvedMaxAge = maxAge ?? SPQR_CONFIG.MAX_SKIPPED_KEY_AGE;

  for (const [key, value] of Object.entries(spqrState.MKSKIPPED)) {
    if (now - value.timestamp > resolvedMaxAge) {
      delete spqrState.MKSKIPPED[key];
    }
  }
}

// ============================================================================
// Black-box SPQR API
// ============================================================================
//
// The cipher treats SPQR as an opaque box:
//   send(state) -> (msg_bytes, key)
//   recv(state, msg_bytes) -> key
//
// The cipher layer never inspects pq_ratchet contents. These functions
// implement that pattern so cipher.ts only needs to call spqrSend/spqrRecv.
// ============================================================================

// Cached braid state machine singleton. The state machine is stateless — all
// mutable state is passed as arguments to Send/Receive — so a single instance
// is safe to reuse across calls.
import type { IMLKEMBraidStateMachine } from './ml-kem-braid/types';
import { createStateMachine, MessageType } from './ml-kem-braid';
let braidStateMachine: IMLKEMBraidStateMachine | undefined;

/**
 * Result of spqrSend(): opaque bytes + optional message key.
 *
 * - Bootstrap: msgBytes may be empty, messageKey=null
 * - Active: msgBytes=encoded PqRatchetMessage, messageKey=32 bytes
 */
export interface SPQRSendResult {
  /** Opaque bytes for pq_ratchet field 5 in SignalMessage protobuf */
  msgBytes: Uint8Array;
  /** Combined SPQR message key (null during bootstrap) */
  messageKey: Uint8Array | null;
}

/**
 * Result of spqrRecv(): the PQ message key.
 *
 * Returns the single opaque post-quantum message-key result.
 */
export interface SPQRRecvResult {
  /** Combined SPQR message key (null during bootstrap) */
  messageKey: Uint8Array | null;
}

/**
 * Black-box SPQR send: produce opaque pq_ratchet bytes + message key.
 *
 * This is the Signal `pq_ratchet_send()` pattern.
 * The cipher layer calls this to get opaque bytes for the wire and an optional
 * PQ message key to combine with the EC key via KDF_HYBRID.
 *
 * Internally handles ALL PQ operations:
 * - Lazy KEM: encapsulation + keypair generation when needsSendRatchet is true
 * - Bootstrap: keypair generation when theirKyberPublicKey is null
 * - SPQR key derivation (epoch/index)
 * - Version negotiation capability
 *
 * The DH ratchet never touches post-quantum state.
 *
 * @param state - SPQR state (mutated: KEM state, chain advanced)
 * @returns Opaque bytes and optional message key
 */
export async function spqrSend(
  state: SPQRState,
  logger: Required<ILogger> = defaultSignalLogger
): Promise<SPQRSendResult> {
  const emptyResult: SPQRSendResult = { msgBytes: new Uint8Array(0), messageKey: null };

  // Perform the full SPQR ratchet internally when the state requests it.
  let kyberCiphertextToSend: Uint8Array | undefined;
  let kyberPublicKeyToSend: Uint8Array | undefined;
  // Direct mode only: needsSendRatchet triggers KEM ratchet step.
  // Braid mode doesn't use this flag — the state machine handles KEM internally,
  // matching the profile, where send() inspects state rather than an external flag.
  if (state.needsSendRatchet && state.mode !== 'braid') {
    if (state.sckaState.theirKyberPublicKey) {
      // Direct mode: full ratchet: encapsulate + advance epoch + derive chains
      const result = await performSPQRRatchetStep(state);
      kyberCiphertextToSend = result.kyberCiphertextToSend ?? undefined;
      kyberPublicKeyToSend = result.kyberPublicKeyToSend ?? undefined;
    } else {
      // Bootstrap: generate ML-KEM-768 keypair, send public key
      const newKyberKeyPair = await generateKyber768KeyPair();
      state.sckaState.ourKyberPrivateKey = bytesToBase64(newKyberKeyPair.privateKey);
      kyberPublicKeyToSend = newKyberKeyPair.publicKey;
    }
    state.needsSendRatchet = false;
  }

  // Braid mode: generate one chunk per message (matches the profile's send() pattern)
  let braidMessage:
    | { type: number; epoch: bigint; chunkIndex?: number; data?: Uint8Array }
    | undefined;
  if (state.mode === 'braid' && state.braidState) {
    // Stateless singleton — all state is passed as arguments to Send/Receive
    const sm = (braidStateMachine ??= createStateMachine());
    const result = await sm.Send(state.braidState);

    if (result.message.type !== MessageType.None) {
      braidMessage = {
        type: result.message.type,
        epoch: result.message.epoch,
        chunkIndex: result.message.chunkIndex,
        data: result.message.data,
      };
    }

    if (result.output_key) {
      await addSPQRBraidEpoch(state, result.output_key);
    }
  }

  // Derive SPQR send key (returns null during bootstrap).
  //
  // In braid mode this must happen after the state-machine send so any returned
  // epoch secret is added before deriving the key for the serialized message.
  const sendKeyEpoch =
    braidMessage !== undefined ? spqrWireEpochToInternalEpoch(braidMessage.epoch) : undefined;
  const spqrKeyResult = await deriveSPQRSendKey(state, logger, sendKeyEpoch);

  // Check if there's any data to send
  const hasData = spqrKeyResult || kyberCiphertextToSend || kyberPublicKeyToSend || braidMessage;

  if (!hasData) {
    return emptyResult;
  }

  // Determine mode
  const isBraid = !!braidMessage;
  const isDirect = !!(kyberCiphertextToSend || kyberPublicKeyToSend);
  const mode: 'braid' | 'direct' | 'none' = isBraid ? 'braid' : isDirect ? 'direct' : 'none';

  // Encode to compact binary wire format (replaces protobuf envelope)
  // In braid mode, use the braid state machine's epoch (from the message).
  // In direct/none mode, convert the zero-based internal SPQR KDF epoch to
  // the `SPQR` one-based wire epoch.
  const wireEpoch = isBraid
    ? braidMessage!.epoch
    : spqrInternalEpochToWireEpoch(spqrKeyResult?.epoch ?? state.epoch);
  const msgBytes = encodeSPQRWire({
    version: 1,
    epoch: wireEpoch,
    chainIndex: spqrKeyResult?.index,
    mode,
    // Braid fields
    braidMsgType: braidMessage?.type,
    braidChunkIndex: braidMessage?.chunkIndex,
    braidChunkData: braidMessage?.data,
    // Direct fields
    kyberCiphertext: kyberCiphertextToSend,
    kyberPublicKey: kyberPublicKeyToSend,
  });

  return {
    msgBytes,
    messageKey: spqrKeyResult?.messageKey ?? null,
  };
}

/**
 * Black-box SPQR receive: decode opaque pq_ratchet bytes → message key.
 *
 * This is the Signal `pq_ratchet_recv()` pattern.
 * Called AFTER the DH ratchet step.
 *
 * Internally handles ALL PQ operations:
 * - Version negotiation (process peer's capability)
 * - Kyber public key storage (bootstrap sequence)
 * - Kyber ciphertext decapsulation + epoch advancement
 * - SPQR key derivation (epoch/index)
 * - Sets needsSendRatchet flag for next spqrSend()
 *
 * The cipher layer treats this as an opaque black box — it passes in bytes
 * and gets back an optional key. No SPQR internals leak to the cipher.
 *
 * @param state - SPQR state (mutated: version negotiation, sckaState, chains, needsSendRatchet)
 * @param msgBytes - Opaque pq_ratchet bytes from wire (undefined = no PQ data)
 * @returns PQ message key to combine with EC key via KDF_HYBRID (or null)
 */
export async function spqrRecv(
  state: SPQRState,
  msgBytes: Uint8Array | undefined,
  logger: Required<ILogger> = defaultSignalLogger
): Promise<SPQRRecvResult> {
  // No PQ data during bootstrap or malformed transport with no pq_ratchet field.
  if (!msgBytes || msgBytes.length === 0) {
    return { messageKey: null };
  }

  // Decode compact binary wire format
  const pqr = decodeSPQRWire(msgBytes);

  // 1. Version negotiation via wire format byte 0
  // The `SPQR` format uses the version byte as the capability advertisement.
  if (state.versionNegotiation?.status === 'negotiating') {
    processVersionFromByte(state.versionNegotiation, pqr.version);
  }

  // 2. Process based on mode
  if (pqr.mode === 'direct') {
    // Store their Kyber public key (bootstrap sequence)
    if (pqr.kyberPublicKey?.length) {
      state.sckaState.theirKyberPublicKey = bytesToBase64(pqr.kyberPublicKey);
    }

    // Decapsulate kyber ciphertext → advance epoch + derive receive chains
    if (pqr.kyberCiphertext?.length) {
      await processSPQRReceivedCiphertext(state, pqr.kyberCiphertext);
      state.needsSendRatchet = true;
    }
  } else if (pqr.mode === 'braid' && state.mode === 'braid' && state.braidState) {
    // Process braid chunk directly from wire fields (no intermediate serialization)
    // Stateless singleton — all state is passed as arguments to Send/Receive
    const sm = (braidStateMachine ??= createStateMachine());

    const chunk = {
      epoch: spqrWireEpochToBigInt(pqr.epoch ?? 0),
      type: pqr.braidMsgType ?? 0,
      chunkIndex: pqr.braidChunkIndex,
      data: pqr.braidChunkData,
    };

    const result = await sm.Receive(state.braidState, chunk);

    if (result.output_key) {
      await addSPQRBraidEpoch(state, result.output_key);
    }
    // No needsSendRatchet flag — braid state machine drives send behavior
    // via its own state transitions, matching the profile pattern.
  }

  // 3. Derive receive key (epoch now correct after step 2)
  // Only derive when chainIndex >= 1 — SPQR uses 1-indexed counters (pre-incremented
  // per the profile). chainIndex 0 means the sender had no SPQR key
  // result (bootstrap phase), so there's no message key to derive.
  let messageKey: Uint8Array | null = null;
  if (pqr.epoch !== undefined && pqr.chainIndex !== undefined && pqr.chainIndex >= 1) {
    const internalEpoch = spqrWireEpochToInternalEpoch(pqr.epoch);
    messageKey = await deriveSPQRReceiveKey(state, pqr.chainIndex, internalEpoch, logger);
  }

  return { messageKey };
}
