/**
 * ML-KEM Braid SPQR Mode
 *
 * Provides SPQR initialization using the Signal Protocol ML-KEM Braid
 * specification. Braid is the package default because it follows the SPQR v1
 * state machine while also improving packet-loss and per-message payload shape.
 *
 * ## When to Use ML-KEM Braid
 *
 * This mode is required by default. Direct SPQR is available only through
 * explicit product policy when a reviewed constraint calls for it.
 *
 * ## How It Works
 *
 * Instead of sending a single 1,088-byte ML-KEM ciphertext, ML-KEM Braid:
 * 1. Uses incremental KEM (Encaps1 + Encaps2) for split transmission
 * 2. Applies Reed-Solomon erasure coding for packet loss resilience
 * 3. Spreads ~32-byte chunks across multiple messages
 * 4. Uses ratcheted authenticator for per-chunk MACs
 *
 * ## Protocol Flow
 *
 * The 11-state machine manages:
 * - Alice: KeysUnsampled → KeysSampled → HeaderSent → Ct1Received → EkSentCt1Received
 * - Bob: NoHeaderReceived → HeaderReceived → Ct1Sampled → EkReceivedCt1Sampled → Ct2Sampled
 *
 * @see https://signal.org/docs/specifications/mlkembraid/ - ML-KEM Braid spec
 */

import type { SPQRInitOptions } from './index';
import type { SPQRState, SPQRChunkResult } from './spqr';
import type { SCKAState } from '../../../types/session';
import { initVersionNegotiation } from '../version';
import { bytesToBase64, kdfSpqrInit, resolveSPQRInfoStrings } from '../../crypto';
import { asBase64 } from '../../../types/utils';
import { EncryptionError, EncryptionErrorCode } from '../../../types/errors';

// ML-KEM Braid state machine and types
import { createStateMachine } from './ml-kem-braid/state-machine';
import type {
  MLKEMBraidAgentState,
  MLKEMBraidMessage,
  SendResult,
  ReceiveResult,
} from './ml-kem-braid/types';
import { MessageType } from './ml-kem-braid/types';

// =============================================================================
// Constants
// =============================================================================

/**
 * Maximum chunks to generate in a single spqrBraidSend call.
 *
 * This is a safety limit to prevent infinite loops if the state machine
 * malfunctions. Normal operation generates ~76 chunks per epoch.
 *
 * @internal
 */
export {};
const MAX_CHUNKS_PER_SEND = 100;

// =============================================================================
// Braid Mode Initialization
// =============================================================================

/**
 * Initialize SPQR state using ML-KEM Braid mode.
 *
 * This creates a fully integrated ML-KEM Braid state machine for bandwidth-
 * constrained scenarios. The returned state includes both:
 * - Standard SPQR state (KDF chains for message key derivation)
 * - Braid agent state (11-state machine for chunked key exchange)
 *
 * @param options - SPQR initialization options
 * @returns Initialized SPQR state configured for braid mode
 *
 * @example
 * ```typescript
 * const spqrState = await initializeSPQRBraid({
 *   mode: 'braid',
 *   initialRootKey: SKscka,
 *   direction: 'A2B',
 *   ourKyberPrivateKey,
 *   theirKyberPublicKey
 * });
 *
 * // Generate chunks to send
 * const result = await spqrBraidSend(spqrState);
 * for (const chunk of result.chunks) {
 *   // Embed chunk in Double Ratchet message header
 * }
 * ```
 */
export async function initializeSPQRBraid(options: SPQRInitOptions): Promise<SPQRState> {
  const {
    initialRootKey,
    direction,
    ourKyberPrivateKey,
    theirKyberPublicKey,
    maxVersion = 'v1',
    minVersion = 'v1',
  } = options;

  // Create state machine instance
  const stateMachine = createStateMachine();

  // Initialize as Alice (A2B) or Bob (B2A) based on direction
  // Alice initiates key exchange, Bob responds
  const braidState: MLKEMBraidAgentState =
    direction === 'A2B'
      ? await stateMachine.InitAlice(initialRootKey)
      : await stateMachine.InitBob(initialRootKey);

  // Initialize SPQR KDF chains (same as direct mode for KDF_HYBRID compatibility)
  // These chains are used for message key derivation once epoch keys are available
  // M12: Pass custom info string (default: pinned-reference CHAIN_START)
  const resolvedInfoStrings = resolveSPQRInfoStrings(options.spqrInfoStrings);
  const chainStartInfo = resolvedInfoStrings.chainStart;
  const {
    rootKey: newRootKey,
    a2bChainKey,
    b2aChainKey,
  } = await kdfSpqrInit(initialRootKey, chainStartInfo);

  // Output reordering per Signal Protocol Section 5.4
  const sendChainKey = direction === 'A2B' ? a2bChainKey : b2aChainKey;
  const receiveChainKey = direction === 'A2B' ? b2aChainKey : a2bChainKey;

  // Initialize SCKA state (for direct mode compatibility tracking)
  const sckaState: SCKAState = {
    epoch: 0,
    direction,
    ourKyberPrivateKey: ourKyberPrivateKey ? asBase64(ourKyberPrivateKey) : null,
    theirKyberPublicKey: theirKyberPublicKey ? asBase64(theirKyberPublicKey) : null,
    lastRefreshTimestamp: Date.now(),
    lastRefreshMessageCount: 0,
  };

  // Return fully initialized braid mode state
  const spqrState: SPQRState = {
    RK: bytesToBase64(newRootKey),
    epoch: 0,
    sendEpoch: 0,
    kdfChains: {
      0: {
        send: {
          CK: bytesToBase64(sendChainKey),
          N: 0,
        },
        receive: {
          CK: bytesToBase64(receiveChainKey),
          N: 0,
        },
      },
    },
    MKSKIPPED: {},
    direction,
    sckaState,
    mode: 'braid',

    // Braid-specific state
    braidState,
    pendingOutgoingChunks: [],

    // Version negotiation
    versionNegotiation: initVersionNegotiation(maxVersion, minVersion),
  };

  return spqrState;
}

// =============================================================================
// Braid Mode Operations
// =============================================================================

/**
 * Generate chunks for braid mode transmission.
 *
 * Advances the braid state machine and collects all available chunks
 * for transmission. These chunks should be embedded in Double Ratchet
 * message headers.
 *
 * @param spqrState - Current SPQR state (must be in braid mode)
 * @returns Chunks to send and optional output key if epoch completes
 *
 * @example
 * ```typescript
 * const result = await spqrBraidSend(spqrState);
 *
 * // Embed chunks in outgoing messages
 * for (const chunk of result.chunks) {
 *   const header = embedSPQRChunk(drHeader, chunk);
 *   await sendMessage(header, ciphertext);
 * }
 *
 * // Handle epoch completion
 * if (result.outputKey) {
 *   const hybridKey = await kdfHybrid(ecKey, result.outputKey.epoch_secret);
 * }
 * ```
 */
export async function spqrBraidSend(spqrState: SPQRState): Promise<SPQRChunkResult> {
  if (spqrState.mode !== 'braid') {
    throw new EncryptionError(
      'spqrBraidSend requires braid mode',
      EncryptionErrorCode.INVALID_STATE,
      { operation: 'spqrBraidSend', actualMode: spqrState.mode }
    );
  }

  if (!spqrState.braidState) {
    throw new EncryptionError(
      'Missing braidState - state may be corrupted',
      EncryptionErrorCode.INVALID_STATE,
      { operation: 'spqrBraidSend' }
    );
  }

  const stateMachine = createStateMachine();
  const chunks: MLKEMBraidMessage[] = [];
  let outputKey: SPQRChunkResult['outputKey'];
  let currentEpoch = spqrState.braidState.epoch;

  // Generate chunks until no more available
  // The state machine returns MessageType.None when nothing to send
  let result: SendResult;
  do {
    result = await stateMachine.Send(spqrState.braidState);

    // Collect chunk if present
    if (result.message.type !== MessageType.None && result.message.data) {
      chunks.push(result.message);
    }

    // Capture output key if epoch completed
    if (result.output_key) {
      outputKey = result.output_key;
    }

    currentEpoch = result.sending_epoch;
  } while (result.message.type !== MessageType.None && chunks.length < MAX_CHUNKS_PER_SEND);

  // Warn if safety limit was reached (may indicate state machine issue)
  if (chunks.length >= MAX_CHUNKS_PER_SEND) {
    console.warn(
      `[SPQR] spqrBraidSend hit MAX_CHUNKS_PER_SEND (${MAX_CHUNKS_PER_SEND}). ` +
        `This may indicate a state machine issue.`
    );
  }

  return {
    chunks,
    outputKey,
    epoch: currentEpoch,
  };
}

/**
 * Process received braid chunk.
 *
 * Feeds a received chunk into the braid state machine for decoding.
 * Returns an output key when enough chunks have been received to
 * complete the epoch.
 *
 * @param spqrState - Current SPQR state (must be in braid mode)
 * @param message - Received braid message chunk
 * @returns Receiving epoch and optional output key if epoch completes
 *
 * @example
 * ```typescript
 * // Extract chunk from received message header
 * const chunk = extractSPQRChunk(header);
 *
 * // Process the chunk
 * const result = await spqrBraidReceive(spqrState, chunk);
 *
 * // Handle epoch completion
 * if (result.outputKey) {
 *   // Mix with EC key via KDF_HYBRID
 *   const hybridKey = await kdfHybrid(ecKey, result.outputKey.epoch_secret);
 * }
 * ```
 */
export async function spqrBraidReceive(
  spqrState: SPQRState,
  message: MLKEMBraidMessage
): Promise<SPQRChunkResult> {
  if (spqrState.mode !== 'braid') {
    throw new EncryptionError(
      'spqrBraidReceive requires braid mode',
      EncryptionErrorCode.INVALID_STATE,
      { operation: 'spqrBraidReceive', actualMode: spqrState.mode }
    );
  }

  if (!spqrState.braidState) {
    throw new EncryptionError(
      'Missing braidState - state may be corrupted',
      EncryptionErrorCode.INVALID_STATE,
      { operation: 'spqrBraidReceive' }
    );
  }

  const stateMachine = createStateMachine();
  const result: ReceiveResult = await stateMachine.Receive(spqrState.braidState, message);

  return {
    chunks: [], // No chunks generated during receive
    outputKey: result.output_key,
    epoch: result.receiving_epoch,
  };
}

/**
 * Get the next pending chunk for transmission.
 *
 * Retrieves and removes the next chunk from the pending queue.
 * Use this when embedding chunks in outgoing messages.
 *
 * @param spqrState - Current SPQR state
 * @returns Next chunk to send, or null if queue is empty
 *
 * @example
 * ```typescript
 * // In message encryption
 * const chunk = getNextBraidChunk(spqrState);
 * if (chunk) {
 *   header.spqr = chunk;
 * }
 * ```
 */
export function getNextBraidChunk(spqrState: SPQRState): MLKEMBraidMessage | null {
  if (spqrState.mode !== 'braid') {
    return null;
  }

  if (!spqrState.pendingOutgoingChunks || spqrState.pendingOutgoingChunks.length === 0) {
    return null;
  }

  return spqrState.pendingOutgoingChunks.shift() ?? null;
}

/**
 * Check if there are pending chunks to send.
 *
 * @param spqrState - Current SPQR state
 * @returns true if there are chunks waiting to be sent
 */
export function hasPendingBraidChunks(spqrState: SPQRState): boolean {
  if (spqrState.mode !== 'braid') {
    return false;
  }

  return (spqrState.pendingOutgoingChunks?.length ?? 0) > 0;
}

/**
 * Check if SPQR state is using ML-KEM Braid mode.
 *
 * @param state - SPQR state to check
 * @returns true if state is configured for braid mode
 */
export function isBraidMode(state: SPQRState): boolean {
  return state.mode === 'braid';
}

/**
 * Get the current braid state machine state name.
 *
 * Useful for debugging and logging.
 *
 * @param spqrState - Current SPQR state
 * @returns State name (e.g., 'KeysUnsampled', 'HeaderSent') or null if not braid mode
 */
export function getBraidStateName(spqrState: SPQRState): string | null {
  if (spqrState.mode !== 'braid' || !spqrState.braidState) {
    return null;
  }

  return spqrState.braidState.state;
}

/**
 * Get the current braid epoch.
 *
 * @param spqrState - Current SPQR state
 * @returns Current epoch as bigint, or null if not braid mode
 */
export function getBraidEpoch(spqrState: SPQRState): bigint | null {
  if (spqrState.mode !== 'braid' || !spqrState.braidState) {
    return null;
  }

  return spqrState.braidState.epoch;
}
