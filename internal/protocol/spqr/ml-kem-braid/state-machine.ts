/**
 * ML-KEM Braid State Machine
 *
 * Implementation of the 11-state protocol machine for ML-KEM Braid.
 *
 * @module ml-kem-braid/state-machine
 * @see https://signal.org/docs/specifications/mlkembraid/
 *
 * Status: Implemented
 */

import type {
  MLKEMBraidState,
  MLKEMBraidAgentState,
  MLKEMBraidMessage,
  SendResult,
  ReceiveResult,
  IMLKEMBraidStateMachine,
  EncoderState,
  DecoderState,
} from './types';

import {
  MessageType,
  PROTOCOL_CONSTANTS,
  MLKEM_768_SIZES,
  isInAliceRole,
  BOB_STATES,
} from './types';
import { computeHek, createIncrementalKEM } from './incremental-kem';
import { createAuthenticator, initAuthenticatorState } from './authenticator';
import { PolyEncoder, createEncoder, createDecoder } from './rs';
import { KDF_OK } from './kdf';
import { generateRandomBytes } from '../../../crypto/random';
import { constantTimeEqual, cloneProtocolState, secureZeroBytes } from '../../../crypto';
import { StateTransitionError, AuthenticatorError } from './errors';
import { assertBraidChunkIndex } from './chunk-domain';

/**
 * State transition table
 *
 * Maps (currentState, event) → nextState
 */
// prettier-ignore
export default {}
export const STATE_TRANSITIONS: Record<
  MLKEMBraidState,
  Partial<Record<string, MLKEMBraidState>>
> = {
  // Alice's states
  KeysUnsampled: {
    KEYGEN: 'KeysSampled',
  },
  KeysSampled: {
    RECEIVE_CT1: 'HeaderSent',
  },
  HeaderSent: {
    CT1_COMPLETE: 'Ct1Received',
  },
  Ct1Received: {
    RECEIVE_CT2: 'EkSentCt1Received',
  },
  EkSentCt1Received: {
    CT2_COMPLETE: 'NoHeaderReceived', // Emits key, epoch++
  },

  // Bob's states
  NoHeaderReceived: {
    HEADER_COMPLETE: 'HeaderReceived',
  },
  HeaderReceived: {
    SAMPLE_CT1: 'Ct1Sampled', // Emits key on Send()
  },
  Ct1Sampled: {
    EK_COMPLETE_NO_ACK: 'EkReceivedCt1Sampled',
    EKCT1_ACK_EK_INCOMPLETE: 'Ct1Acknowledged',
    EKCT1_ACK_EK_COMPLETE: 'Ct2Sampled',
  },
  EkReceivedCt1Sampled: {
    EKCT1_ACK: 'Ct2Sampled',
  },
  Ct1Acknowledged: {
    EK_COMPLETE: 'Ct2Sampled',
  },
  Ct2Sampled: {
    BOB_NEW_EPOCH: 'KeysUnsampled', // Role swap: Bob becomes Alice
  },
};

// Header size: ek_seed (32) + hek (32) + MAC (32) = 96 bytes
const HEADER_SIZE = MLKEM_768_SIZES.EK_SEED_SIZE + 32 + PROTOCOL_CONSTANTS.MAC_SIZE;
// EK Vector size: 1152 bytes (NO MAC - authenticated via hash binding to hek)
const EK_SIZE = MLKEM_768_SIZES.EK_VECTOR_SIZE;
// CT1 size: 960 bytes (NO MAC - combined MAC with CT2)
const CT1_SIZE = MLKEM_768_SIZES.CT1_SIZE;
// CT2 size: 128 bytes + combined MAC for ct1||ct2 (32) = 160 bytes
const CT2_SIZE = MLKEM_768_SIZES.CT2_SIZE + PROTOCOL_CONSTANTS.MAC_SIZE;

/**
 * ML-KEM Braid State Machine Implementation
 *
 * Manages the 11-state protocol for chunked ML-KEM key agreement.
 */
export class MLKEMBraidStateMachine implements IMLKEMBraidStateMachine {
  private kem = createIncrementalKEM();
  private authenticator = createAuthenticator();

  constructor(
    private readonly randomBytes: (length: number) => Promise<Uint8Array> = generateRandomBytes
  ) {}

  /**
   * Initialize Alice (initiator) state
   *
   * Alice starts in KeysUnsampled, ready to generate a new keypair.
   *
   * @param initial_shared_secret - Shared secret from PQXDH handshake
   * @returns Initial agent state for Alice
   */
  async InitAlice(initial_shared_secret: Uint8Array): Promise<MLKEMBraidAgentState> {
    const auth = await initAuthenticatorState(initial_shared_secret);

    return {
      state: 'KeysUnsampled',
      epoch: 1n,
      auth,
    };
  }

  /**
   * Initialize Bob (responder) state
   *
   * Bob starts in NoHeaderReceived, waiting for Alice's first header.
   *
   * @param initial_shared_secret - Shared secret from PQXDH handshake
   * @returns Initial agent state for Bob
   */
  async InitBob(initial_shared_secret: Uint8Array): Promise<MLKEMBraidAgentState> {
    const auth = await initAuthenticatorState(initial_shared_secret);

    return {
      state: 'NoHeaderReceived',
      epoch: 1n,
      auth,
      headerDecoder: this.createDecoderState(HEADER_SIZE),
    };
  }

  /**
   * Process Send operation
   *
   * Updates state and returns message to transmit.
   *
   * @param state - Current agent state (will be mutated)
   * @returns Message, sending epoch, and optional output key
   */
  async Send(state: MLKEMBraidAgentState): Promise<SendResult> {
    if (isInAliceRole(state)) {
      return this.sendAlice(state);
    } else {
      return this.sendBob(state);
    }
  }

  /**
   * Process Receive operation
   *
   * Updates state based on received message.
   *
   * @param state - Current agent state (will be mutated)
   * @param message - Received ML-KEM Braid message
   * @returns Receiving epoch and optional output key
   */
  async Receive(state: MLKEMBraidAgentState, message: MLKEMBraidMessage): Promise<ReceiveResult> {
    if (isInAliceRole(state)) {
      return this.receiveAlice(state, message);
    } else {
      return this.receiveBob(state, message);
    }
  }

  // ===========================================================================
  // Private: Alice Send Handlers
  // ===========================================================================

  private async sendAlice(state: MLKEMBraidAgentState): Promise<SendResult> {
    switch (state.state) {
      case 'KeysUnsampled':
        return this.aliceSendFromKeysUnsampled(state);

      case 'KeysSampled':
        return this.aliceSendFromKeysSampled(state);

      case 'HeaderSent':
        // Continue sending ek chunks
        return this.aliceSendFromHeaderSent(state);

      case 'Ct1Received':
        return this.aliceSendFromCt1Received(state);

      case 'EkSentCt1Received':
        // Waiting for more CT2 chunks; send bare CT1 acknowledgements.
        return this.aliceSendFromEkSentCt1Received(state);

      default:
        throw StateTransitionError.invalidTransition(state.state, 'SEND');
    }
  }

  private async aliceSendFromKeysUnsampled(state: MLKEMBraidAgentState): Promise<SendResult> {
    // Generate new keypair
    const randomness = await this.randomBytes(64);
    let keyPair: Awaited<ReturnType<typeof this.kem.KeyGen>>;
    try {
      keyPair = await this.kem.KeyGen(randomness);
    } finally {
      secureZeroBytes(randomness);
    }
    const { dk, ek_seed, ek_vector, hek } = keyPair;

    state.dk = dk;
    state.ek_seed = ek_seed;
    state.ek_vector = ek_vector;
    state.hek = hek;

    // Create header: ek_seed || hek
    const header = new Uint8Array(MLKEM_768_SIZES.EK_SEED_SIZE + 32);
    header.set(ek_seed, 0);
    header.set(hek, MLKEM_768_SIZES.EK_SEED_SIZE);

    // Add MAC
    const headerMac = this.authenticator.MacHdr(state.auth, state.epoch, header);
    const headerWithMac = new Uint8Array(header.length + headerMac.length);
    headerWithMac.set(header, 0);
    headerWithMac.set(headerMac, header.length);

    // Create encoder for header
    state.headerEncoder = await this.createEncoderState(headerWithMac);

    // Create encoder for ek_vector (NO MAC - authenticated via hash binding to hek)
    // The specification HEK = SHA3-256(ek_seed || ek_vector) is transmitted in
    // the authenticated header. Bob verifies EK integrity by recomputing it.
    state.ekEncoder = await this.createEncoderState(ek_vector);

    // Transition to KeysSampled
    this.transition(state, 'KEYGEN');

    // Send first header chunk
    return this.aliceSendHeaderChunk(state);
  }

  private async aliceSendFromKeysSampled(state: MLKEMBraidAgentState): Promise<SendResult> {
    // Continue sending header chunks
    return this.aliceSendHeaderChunk(state);
  }

  private async aliceSendHeaderChunk(state: MLKEMBraidAgentState): Promise<SendResult> {
    if (!state.headerEncoder) {
      throw new Error('No header encoder');
    }

    const { chunk, index } = this.getNextEncoderChunk(state.headerEncoder);

    return {
      message: {
        epoch: state.epoch,
        type: MessageType.Hdr,
        chunkIndex: index,
        data: chunk,
      },
      sending_epoch: state.epoch,
    };
  }

  private async aliceSendFromHeaderSent(state: MLKEMBraidAgentState): Promise<SendResult> {
    // Send ek_vector chunks
    return this.aliceSendEkChunk(state, MessageType.Ek);
  }

  private async aliceSendFromCt1Received(state: MLKEMBraidAgentState): Promise<SendResult> {
    // Continue sending ek_vector chunks with CT1 acknowledgement until CT2 arrives.
    return this.aliceSendEkChunk(state, MessageType.EkCt1Ack);
  }

  private async aliceSendFromEkSentCt1Received(state: MLKEMBraidAgentState): Promise<SendResult> {
    // The SPQR v1 Ct1Ack is acknowledgement-only after CT2 reception.
    return {
      message: {
        epoch: state.epoch,
        type: MessageType.Ct1Ack,
      },
      sending_epoch: state.epoch,
    };
  }

  private async aliceSendEkChunk(
    state: MLKEMBraidAgentState,
    type: MessageType.Ek | MessageType.EkCt1Ack
  ): Promise<SendResult> {
    if (!state.ekEncoder) {
      throw new Error('No ek encoder');
    }

    const { chunk, index } = this.getNextEncoderChunk(state.ekEncoder);

    return {
      message: {
        epoch: state.epoch,
        type,
        chunkIndex: index,
        data: chunk,
      },
      sending_epoch: state.epoch,
    };
  }

  // ===========================================================================
  // Private: Alice Receive Handlers
  // ===========================================================================

  private async receiveAlice(
    state: MLKEMBraidAgentState,
    message: MLKEMBraidMessage
  ): Promise<ReceiveResult> {
    const result: ReceiveResult = {
      receiving_epoch: message.epoch,
    };

    if (message.epoch < state.epoch) {
      return result;
    }
    if (message.epoch > state.epoch) {
      throw StateTransitionError.epochMismatch(state.epoch, message.epoch);
    }

    switch (message.type) {
      case MessageType.Ct1:
        // Bob sending CT1 chunk
        if (message.data && (state.state === 'KeysSampled' || state.state === 'HeaderSent')) {
          const receivedFirstCt1Chunk = state.state === 'KeysSampled';

          // Add CT1 chunk
          if (!state.ct1Decoder) {
            state.ct1Decoder = this.createDecoderState(CT1_SIZE);
          }
          // Use explicit chunkIndex if provided, otherwise fallback to sequential
          const ct1ChunkIndex = message.chunkIndex ?? state.ct1Decoder.receivedChunks;
          this.addDecoderChunk(state.ct1Decoder, ct1ChunkIndex, message.data);

          if (receivedFirstCt1Chunk) {
            this.transition(state, 'RECEIVE_CT1');
          }

          if (this.isDecoderComplete(state.ct1Decoder)) {
            // CT1 complete (NO MAC verification here - combined MAC verified with CT2)
            // The reference implementation authenticates ct1||ct2 together with a single MAC attached to CT2
            const ct1 = await this.getDecodedMessage(state.ct1Decoder);

            // Store CT1 for combined MAC verification when CT2 arrives
            state.ct1_decoded = Uint8Array.from(ct1);

            this.transition(state, 'CT1_COMPLETE');
          }
        }
        break;

      case MessageType.Ct2:
        // CT2 chunk from Bob
        if (
          message.data &&
          (state.state === 'Ct1Received' || state.state === 'EkSentCt1Received')
        ) {
          // CT2 is attacker-controlled. Work on a clone so decapsulation and
          // authenticator updates cannot mutate live state before MAC success.
          // Force the portable clone to keep Map identity in cross-realm runtimes.
          const candidateState = cloneProtocolState(state, true);
          const receivedFirstCt2Chunk = candidateState.state === 'Ct1Received';

          if (!candidateState.ct2Decoder) {
            candidateState.ct2Decoder = this.createDecoderState(CT2_SIZE);
          }
          // Use explicit chunkIndex if provided, otherwise fallback to sequential
          const ct2ChunkIndex = message.chunkIndex ?? candidateState.ct2Decoder.receivedChunks;
          this.addDecoderChunk(candidateState.ct2Decoder, ct2ChunkIndex, message.data);

          if (receivedFirstCt2Chunk) {
            this.transition(candidateState, 'RECEIVE_CT2');
          }

          if (
            this.isDecoderComplete(candidateState.ct2Decoder) &&
            candidateState.state === 'EkSentCt1Received'
          ) {
            // CT2 complete - decapsulate, update authenticator, verify MAC, derive key
            // Order: Decapsulate → Update → Verify (Bob updated before computing MAC)
            if (!candidateState.ct1_decoded) {
              throw new Error('CT1 not decoded - state corruption');
            }

            const ct2Data = await this.getDecodedMessage(candidateState.ct2Decoder);

            // Extract CT2 and combined MAC
            const ct1 = candidateState.ct1_decoded;
            const ct2 = ct2Data.subarray(0, MLKEM_768_SIZES.CT2_SIZE);
            const combinedMac = ct2Data.subarray(MLKEM_768_SIZES.CT2_SIZE);
            const combined = new Uint8Array(ct1.length + ct2.length);
            combined.set(ct1, 0);
            combined.set(ct2, ct1.length);
            let shared_secret: Uint8Array | undefined;
            let outputKeyBytes: Uint8Array | undefined;
            let outputRetained = false;
            try {
              // Decapsulate first (ML-KEM implicit rejection makes tampering pseudorandom).
              shared_secret = await this.kem.Decaps(candidateState.dk!, ct1, ct2);
              outputKeyBytes = await KDF_OK(shared_secret, candidateState.epoch);

              await this.authenticator.Update(
                candidateState.auth,
                candidateState.epoch,
                outputKeyBytes
              );
              this.authenticator.VfyCt(
                candidateState.auth,
                message.epoch,
                combined,
                combinedMac
              );

              result.output_key = {
                epoch: candidateState.epoch,
                epoch_secret: outputKeyBytes,
              };

              this.transition(candidateState, 'CT2_COMPLETE');
              candidateState.epoch += 1n;
              this.resetForNewEpoch(candidateState, candidateState.state);

              // The candidate is now authenticated; commit it in one assignment boundary.
              Object.assign(state, candidateState);
              outputRetained = true;
            } finally {
              if (shared_secret) secureZeroBytes(shared_secret);
              if (!outputRetained && outputKeyBytes) secureZeroBytes(outputKeyBytes);
              secureZeroBytes(combined);
            }
          } else {
            // Persist only unauthenticated erasure-decoder progress. No key or
            // authenticator state has been changed on this path.
            Object.assign(state, candidateState);
          }
        }
        break;
    }

    return result;
  }

  // ===========================================================================
  // Private: Bob Send Handlers
  // ===========================================================================

  private async sendBob(state: MLKEMBraidAgentState): Promise<SendResult> {
    switch (state.state) {
      case 'NoHeaderReceived':
        // Nothing to send yet
        return {
          message: { epoch: state.epoch, type: MessageType.None },
          sending_epoch: state.epoch,
        };

      case 'HeaderReceived':
        return this.bobSendFromHeaderReceived(state);

      case 'Ct1Sampled':
        return this.bobSendFromCt1Sampled(state);

      case 'EkReceivedCt1Sampled':
        return this.bobSendFromEkReceivedCt1Sampled(state);

      case 'Ct1Acknowledged':
        return {
          message: { epoch: state.epoch, type: MessageType.None },
          sending_epoch: state.epoch,
        };

      case 'Ct2Sampled':
        return this.bobSendFromCt2Sampled(state);

      default:
        throw StateTransitionError.invalidTransition(state.state, 'SEND');
    }
  }

  private async bobSendFromHeaderReceived(state: MLKEMBraidAgentState): Promise<SendResult> {
    // Sample CT1
    if (!state.ek_seed || !state.hek) {
      throw new Error('Missing ek_seed or hek');
    }

    const randomness = await this.randomBytes(32);
    let sharedSecret: Uint8Array | undefined;
    let outputKeyBytes: Uint8Array | undefined;
    let completed = false;
    try {
      const encapsulation = await this.kem.Encaps1(state.ek_seed, state.hek, randomness);
      sharedSecret = encapsulation.shared_secret;
      state.encaps_secret = encapsulation.encaps_secret;
      state.ct1 = encapsulation.ct1;

      // Create CT1 encoder (NO MAC - will be combined with CT2).
      state.ct1Encoder = await this.createEncoderState(encapsulation.ct1);
      state.ct1_for_mac = Uint8Array.from(encapsulation.ct1);

      outputKeyBytes = await KDF_OK(sharedSecret, state.epoch);
      // the profile updates at the current epoch.
      await this.authenticator.Update(state.auth, state.epoch, outputKeyBytes);

      this.transition(state, 'SAMPLE_CT1');
      const { chunk, index } = this.getNextEncoderChunk(state.ct1Encoder);
      completed = true;
      return {
        message: {
          epoch: state.epoch,
          type: MessageType.Ct1,
          chunkIndex: index,
          data: chunk,
        },
        sending_epoch: state.epoch,
        output_key: {
          epoch: state.epoch,
          epoch_secret: outputKeyBytes,
        },
      };
    } finally {
      secureZeroBytes(randomness);
      if (sharedSecret) secureZeroBytes(sharedSecret);
      // A successfully returned OutputKey transfers ownership to the caller.
      if (!completed && outputKeyBytes) secureZeroBytes(outputKeyBytes);
      if (!completed) {
        if (state.encaps_secret) secureZeroBytes(state.encaps_secret);
        if (state.ct1_for_mac) secureZeroBytes(state.ct1_for_mac);
        state.encaps_secret = undefined;
        state.ct1_for_mac = undefined;
        state.ct1 = undefined;
        state.ct1Encoder = undefined;
      }
    }
  }

  private async bobSendFromCt1Sampled(state: MLKEMBraidAgentState): Promise<SendResult> {
    // Continue sending CT1 chunks
    return this.bobSendCt1Chunk(state);
  }

  private async bobSendFromEkReceivedCt1Sampled(state: MLKEMBraidAgentState): Promise<SendResult> {
    // EK is complete, but the reference implementation waits for CT1 acknowledgement before CT2.
    // Continue sending CT1 chunks, including parity, until the peer ACK arrives.
    return this.bobSendCt1Chunk(state);
  }

  private async bobSendCt1Chunk(state: MLKEMBraidAgentState): Promise<SendResult> {
    if (!state.ct1Encoder) {
      throw new Error('No CT1 encoder');
    }

    const { chunk, index } = this.getNextEncoderChunk(state.ct1Encoder);

    return {
      message: {
        epoch: state.epoch,
        type: MessageType.Ct1,
        chunkIndex: index,
        data: chunk,
      },
      sending_epoch: state.epoch,
    };
  }

  private async bobSendFromCt2Sampled(state: MLKEMBraidAgentState): Promise<SendResult> {
    if (!state.ct2Encoder) {
      throw new Error('No CT2 encoder');
    }

    const { chunk, index } = this.getNextEncoderChunk(state.ct2Encoder);

    return {
      message: {
        epoch: state.epoch,
        type: MessageType.Ct2,
        chunkIndex: index,
        data: chunk,
      },
      sending_epoch: state.epoch,
    };
  }

  // ===========================================================================
  // Private: Bob Receive Handlers
  // ===========================================================================

  private async receiveBob(
    state: MLKEMBraidAgentState,
    message: MLKEMBraidMessage
  ): Promise<ReceiveResult> {
    const result: ReceiveResult = {
      receiving_epoch: message.epoch,
    };

    if (message.epoch < state.epoch) {
      return result;
    }

    // Ct2Sampled: next-epoch message triggers role swap
    // The reference implementation does NOT re-process the message — just transitions and returns
    if (state.state === 'Ct2Sampled' && message.epoch === state.epoch + 1n) {
      this.transition(state, 'BOB_NEW_EPOCH');
      state.epoch += 1n;
      this.resetForNewEpoch(state, state.state);
      return { receiving_epoch: message.epoch };
    }

    if (message.epoch > state.epoch) {
      throw StateTransitionError.epochMismatch(state.epoch, message.epoch);
    }

    switch (message.type) {
      case MessageType.Hdr:
        // Header chunk from Alice
        if (message.data && state.state === 'NoHeaderReceived') {
          // The completing chunk is unauthenticated until the reconstructed
          // header MAC verifies. Work against a candidate and commit once.
          const candidateState = cloneProtocolState(state, true);
          if (!candidateState.headerDecoder) {
            candidateState.headerDecoder = this.createDecoderState(HEADER_SIZE);
          }
          // Use explicit chunkIndex if provided, otherwise fallback to sequential
          const hdrChunkIndex =
            message.chunkIndex ?? candidateState.headerDecoder.receivedChunks;
          this.addDecoderChunk(candidateState.headerDecoder, hdrChunkIndex, message.data);

          if (this.isDecoderComplete(candidateState.headerDecoder)) {
            // Header complete - parse and verify
            const headerData = await this.getDecodedMessage(candidateState.headerDecoder);

            // Extract header components and MAC
            const headerSize = MLKEM_768_SIZES.EK_SEED_SIZE + 32; // ek_seed + hek
            const header = headerData.subarray(0, headerSize);
            const headerMac = headerData.subarray(headerSize);

            // Verify header MAC
            this.authenticator.VfyHdr(candidateState.auth, message.epoch, header, headerMac);

            // Parse ek_seed and hek
            candidateState.ek_seed = Uint8Array.from(
              header.subarray(0, MLKEM_768_SIZES.EK_SEED_SIZE)
            );
            candidateState.hek = Uint8Array.from(
              header.subarray(MLKEM_768_SIZES.EK_SEED_SIZE)
            );

            this.transition(candidateState, 'HEADER_COMPLETE');
          }
          Object.assign(state, candidateState);
        }
        break;

      case MessageType.Ek:
      case MessageType.EkCt1Ack:
        // EK vector chunk from Alice
        if (state.state === 'EkReceivedCt1Sampled' && message.type === MessageType.EkCt1Ack) {
          this.transition(state, 'EKCT1_ACK');
          await this.bobSampleCt2(state);
        } else if (
          message.data &&
          (state.state === 'Ct1Sampled' || state.state === 'Ct1Acknowledged')
        ) {
          // EK completion verifies the authenticated header commitment and may
          // consume Encaps2 state, so isolate it until both operations succeed.
          const candidateState = cloneProtocolState(state, true);
          if (!candidateState.ekDecoder) {
            candidateState.ekDecoder = this.createDecoderState(EK_SIZE);
          }
          // Use explicit chunkIndex if provided, otherwise fallback to sequential
          const ekChunkIndex = message.chunkIndex ?? candidateState.ekDecoder.receivedChunks;
          this.addDecoderChunk(candidateState.ekDecoder, ekChunkIndex, message.data);

          // Handle state transitions based on EK completion
          if (this.isDecoderComplete(candidateState.ekDecoder)) {
            const ekVector = await this.getDecodedMessage(candidateState.ekDecoder);

            // Verify the specification's seed-first hash binding.
            // The hek was transmitted in the authenticated header, so this provides integrity
            this.verifyEkHashBinding(
              candidateState.ek_seed!,
              ekVector,
              candidateState.hek!,
              message.epoch
            );

            candidateState.ek_vector = Uint8Array.from(ekVector);

            if (candidateState.state === 'Ct1Sampled') {
              if (message.type === MessageType.EkCt1Ack) {
                // EK complete and CT1 acknowledged
                this.transition(candidateState, 'EKCT1_ACK_EK_COMPLETE');
                await this.bobSampleCt2(candidateState);
              } else {
                // EK complete, no ack yet
                this.transition(candidateState, 'EK_COMPLETE_NO_ACK');
              }
            } else if (candidateState.state === 'Ct1Acknowledged') {
              this.transition(candidateState, 'EK_COMPLETE');
              await this.bobSampleCt2(candidateState);
            }
          } else if (
            message.type === MessageType.EkCt1Ack &&
            candidateState.state === 'Ct1Sampled'
          ) {
            // CT1 was acknowledged, but EK is still incomplete.
            this.transition(candidateState, 'EKCT1_ACK_EK_INCOMPLETE');
          }
          Object.assign(state, candidateState);
        }
        break;

      case MessageType.Ct1Ack:
        if (state.state === 'EkReceivedCt1Sampled') {
          this.transition(state, 'EKCT1_ACK');
          await this.bobSampleCt2(state);
        }
        break;
    }

    return result;
  }

  private async bobSampleCt2(state: MLKEMBraidAgentState): Promise<void> {
    if (!state.encaps_secret || !state.ek_seed || !state.ek_vector) {
      throw new Error('Missing encaps_secret, ek_seed, or ek_vector');
    }

    // Complete encapsulation. The state machine owns this one-shot secret and
    // clears its field whether Encaps2 succeeds or rejects.
    const encapsSecret = state.encaps_secret;
    let ct2: Uint8Array;
    try {
      ct2 = await this.kem.Encaps2(encapsSecret, state.ek_seed, state.ek_vector);
    } finally {
      secureZeroBytes(encapsSecret);
      state.encaps_secret = undefined;
    }
    state.ct2 = ct2;

    // Create CT2 encoder with COMBINED MAC on ct1||ct2
    // The reference implementation authenticates both ciphertext components together
    if (!state.ct1_for_mac) {
      throw new Error('CT1 not stored for combined MAC - state corruption');
    }
    const combined = new Uint8Array(state.ct1_for_mac.length + ct2.length);
    combined.set(state.ct1_for_mac, 0);
    combined.set(ct2, state.ct1_for_mac.length);
    const combinedMac = this.authenticator.MacCt(state.auth, state.epoch, combined);

    // Encode ct2 || combinedMac
    const ct2WithMac = new Uint8Array(ct2.length + combinedMac.length);
    ct2WithMac.set(ct2, 0);
    ct2WithMac.set(combinedMac, ct2.length);
    state.ct2Encoder = await this.createEncoderState(ct2WithMac);

    // Best-effort clear ct1_for_mac (no longer needed).
    state.ct1_for_mac.fill(0);
    state.ct1_for_mac = undefined;

  }

  // ===========================================================================
  // Private: Epoch Reset
  // ===========================================================================

  /**
   * Reset state for a new epoch after role swap.
   * Zeros sensitive material and clears role-specific fields.
   * Only epoch and auth survive.
   */
  private resetForNewEpoch(state: MLKEMBraidAgentState, newState: MLKEMBraidState): void {
    // Zero all sensitive Uint8Array fields present on the state
    const uint8Fields: (keyof MLKEMBraidAgentState)[] = [
      'dk',
      'ek_seed',
      'ek_vector',
      'hek',
      'encaps_secret',
      'ct1',
      'ct2',
      'ct1_for_mac',
      'ct1_decoded',
    ];
    for (const field of uint8Fields) {
      const val = state[field];
      if (val instanceof Uint8Array && val.length > 0) val.fill(0);
    }

    // Zero encoder data buffers
    for (const field of ['headerEncoder', 'ekEncoder', 'ct1Encoder', 'ct2Encoder'] as const) {
      if (state[field]?.data instanceof Uint8Array) state[field]!.data.fill(0);
    }

    // Zero decoder chunk Map entries
    for (const field of ['headerDecoder', 'ekDecoder', 'ct1Decoder', 'ct2Decoder'] as const) {
      const decoder = state[field];
      if (decoder?.chunks) {
        for (const chunk of decoder.chunks.values()) {
          chunk.fill(0);
        }
        decoder.chunks.clear();
      }
    }

    // Clear all role-specific fields
    state.dk = undefined;
    state.ek_seed = undefined;
    state.ek_vector = undefined;
    state.hek = undefined;
    state.encaps_secret = undefined;
    state.ct1 = undefined;
    state.ct2 = undefined;
    state.ct1_for_mac = undefined;
    state.ct1_decoded = undefined;
    state.headerEncoder = undefined;
    state.ekEncoder = undefined;
    state.ct1Decoder = undefined;
    state.ct2Decoder = undefined;
    state.headerDecoder = undefined;
    state.ekDecoder = undefined;
    state.ct1Encoder = undefined;
    state.ct2Encoder = undefined;

    // Update the state
    state.state = newState;

    // Initialize role-specific state for the new epoch
    if (BOB_STATES.has(newState)) {
      // Bob needs a header decoder immediately
      state.headerDecoder = this.createDecoderState(HEADER_SIZE);
    }
    // Alice needs nothing — keys generated lazily on first Send()
  }

  // ===========================================================================
  // Private: Encoder/Decoder Helpers
  // ===========================================================================

  private async createEncoderState(data: Uint8Array): Promise<EncoderState> {
    // Use SPQR-compliant polynomial encoder (PolyEncoder)
    // PolyEncoder validates message size internally (max 1152 bytes)
    const encoder = await createEncoder(data);

    const totalChunks = Math.ceil(data.length / PROTOCOL_CONSTANTS.CHUNK_SIZE);

    return {
      data,
      currentChunk: 0,
      totalChunks: Math.ceil(totalChunks * 1.3), // Include ~30% parity
      isComplete: false,
      encoder, // Cache encoder for O(1) chunk retrieval
    };
  }

  private createDecoderState(messageSize: number): DecoderState {
    return {
      receivedChunks: 0,
      requiredChunks: Math.ceil(messageSize / PROTOCOL_CONSTANTS.CHUNK_SIZE),
      messageSize,
      chunks: new Map(),
    };
  }

  private normalizeEncoderData(data: unknown): Uint8Array {
    if (data instanceof Uint8Array) {
      return data;
    }

    if (ArrayBuffer.isView(data) && !(data instanceof DataView)) {
      const view = data as Uint8Array;
      return new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
    }

    if (Array.isArray(data)) {
      return new Uint8Array(data);
    }

    if (data && typeof data === 'object') {
      const record = data as Record<string, unknown>;

      if (record.type === 'Buffer' && Array.isArray(record.data)) {
        return new Uint8Array(record.data);
      }

      const numericKeys = Object.keys(record)
        .filter((key) => /^\d+$/.test(key))
        .sort((a, b) => Number(a) - Number(b));
      if (numericKeys.length > 0) {
        return new Uint8Array(numericKeys.map((key) => Number(record[key])));
      }
    }

    throw new Error('Cannot restore Braid encoder data from persisted state');
  }

  private restoreEncoder(state: EncoderState): PolyEncoder {
    const cachedEncoder = state.encoder as
      | (Partial<PolyEncoder> & { nextChunk?: unknown; isDataComplete?: unknown })
      | undefined;
    if (
      cachedEncoder &&
      typeof cachedEncoder.nextChunk === 'function' &&
      typeof cachedEncoder.isDataComplete === 'function'
    ) {
      return cachedEncoder as PolyEncoder;
    }

    state.data = this.normalizeEncoderData(state.data);
    const encoder = PolyEncoder.restore(state.data, state.currentChunk);
    state.encoder = encoder;
    return encoder;
  }

  private getNextEncoderChunk(state: EncoderState): { chunk: Uint8Array; index: number } {
    // Encoder instances are runtime caches. Storage/decrypt-attempt clone
    // boundaries can restore them as plain objects, so rebuild on demand from
    // the durable encoder state before emitting the next chunk.
    const encoder = this.restoreEncoder(state);
    if (!encoder.hasMoreChunks()) {
      throw new Error('Braid encoder exhausted all GF(2^16) evaluation points');
    }
    const index = state.currentChunk;
    const chunk = encoder.nextChunk();
    state.currentChunk++;
    state.isComplete = encoder.isDataComplete();
    return { chunk, index };
  }

  private restoreDecoderChunks(state: DecoderState): Map<number, Uint8Array> {
    if (state.chunks instanceof Map) {
      return state.chunks;
    }

    const rawChunks = state.chunks as unknown;
    const chunks = new Map<number, Uint8Array>();

    if (Array.isArray(rawChunks)) {
      for (const entry of rawChunks) {
        if (!Array.isArray(entry) || entry.length !== 2) {
          continue;
        }
        const [index, chunk] = entry;
        if (Number.isInteger(Number(index))) {
          chunks.set(Number(index), this.normalizeEncoderData(chunk));
        }
      }
    } else if (rawChunks && typeof rawChunks === 'object') {
      const maybeTaggedMap = rawChunks as {
        __signalProtocolJsonType?: string;
        entries?: unknown[];
      };
      if (
        maybeTaggedMap.__signalProtocolJsonType === 'map' &&
        Array.isArray(maybeTaggedMap.entries)
      ) {
        for (const entry of maybeTaggedMap.entries) {
          if (!Array.isArray(entry) || entry.length !== 2) {
            continue;
          }
          const [index, chunk] = entry;
          if (Number.isInteger(Number(index))) {
            chunks.set(Number(index), this.normalizeEncoderData(chunk));
          }
        }
      } else {
        for (const [index, chunk] of Object.entries(rawChunks)) {
          if (Number.isInteger(Number(index))) {
            chunks.set(Number(index), this.normalizeEncoderData(chunk));
          }
        }
      }
    }

    state.chunks = chunks;
    state.receivedChunks = chunks.size;
    return chunks;
  }

  private addDecoderChunk(state: DecoderState, chunkIndex: number, chunk: Uint8Array): void {
    const chunks = this.restoreDecoderChunks(state);

    assertBraidChunkIndex(chunkIndex);
    if (chunk.length !== PROTOCOL_CONSTANTS.CHUNK_SIZE) {
      throw new Error(`Braid chunk must contain exactly ${PROTOCOL_CONSTANTS.CHUNK_SIZE} bytes`);
    }

    const existing = chunks.get(chunkIndex);
    if (existing) {
      if (!constantTimeEqual(existing, chunk)) {
        throw new Error(`Conflicting duplicate Braid chunk at index ${chunkIndex}`);
      }
      return;
    }

    chunks.set(chunkIndex, Uint8Array.from(chunk));
    state.receivedChunks = chunks.size;
  }

  private isDecoderComplete(state: DecoderState): boolean {
    return this.restoreDecoderChunks(state).size >= state.requiredChunks;
  }

  private async getDecodedMessage(state: DecoderState): Promise<Uint8Array> {
    const decoder = await createDecoder(state.messageSize);
    this.restoreDecoderChunks(state).forEach((chunk, index) => {
      decoder.addChunk(index, chunk);
    });
    const message = decoder.message();
    if (!message) {
      throw new Error('Failed to decode message');
    }
    return message;
  }

  /**
   * Verify EK vector integrity via hash binding
   *
   * The ML-KEM Braid specification authenticates EK through the header's hek:
   * hek = SHA3-256(ek_seed || ek_vector)
   *
   * The header (containing hek) is MAC-authenticated, so verifying
   * the hash provides integrity for the EK vector.
   *
   * @param ekSeed - The ek_seed (rho) from the header
   * @param ekVector - The received EK vector (tHat)
   * @param expectedHek - The hek from the authenticated header
   * @param epoch - Current epoch for error reporting
   * @throws AuthenticatorError if hash doesn't match
   */
  private verifyEkHashBinding(
    ekSeed: Uint8Array,
    ekVector: Uint8Array,
    expectedHek: Uint8Array,
    epoch: bigint
  ): void {
    const computedHek = computeHek(ekSeed, ekVector);

    // Best-effort full-scan comparison; JavaScript provides no timing guarantee.
    if (!constantTimeEqual(computedHek, expectedHek)) {
      throw AuthenticatorError.ekHashBindingFailed(epoch);
    }
  }

  /**
   * Transition state machine
   *
   * @param state - Current state (will be mutated)
   * @param event - Transition event name
   */
  private transition(state: MLKEMBraidAgentState, event: string): void {
    const transitions = STATE_TRANSITIONS[state.state];
    const nextState = transitions?.[event];

    if (!nextState) {
      throw StateTransitionError.invalidTransition(state.state, event);
    }

    state.state = nextState;
  }
}

/**
 * Create a new ML-KEM Braid state machine
 */
export function createStateMachine(
  randomBytes?: (length: number) => Promise<Uint8Array>
): IMLKEMBraidStateMachine {
  return new MLKEMBraidStateMachine(randomBytes);
}
