/**
 * ML-KEM Braid chunk progress
 *
 * The state machine keeps its chunk counts on the encoders and decoders it
 * opens for an epoch, and nothing outside this module knows which of those are
 * live at a given state. Reading them belongs here, where the encoder and
 * decoder shapes are owned, rather than at the SPQR seam that reports them.
 *
 * @module ml-kem-braid/progress
 * @see https://signal.org/docs/specifications/mlkembraid/
 */

import type { MLKEMBraidAgentState } from './types';

export {};

/**
 * Chunk counts for one agent's current epoch.
 */
export interface BraidChunkProgress {
  /** Chunks emitted by this agent's encoders plus chunks its decoders hold. */
  carried: number;
  /** Chunks the open encoders and decoders account for. */
  required: number;
}

/**
 * Read the chunk counts of every transfer open in the agent's current epoch.
 *
 * `resetForNewEpoch` clears the encoders and decoders at an epoch boundary, so
 * these counts describe the epoch in `state.epoch` and nothing before it.
 */
export function readBraidChunkProgress(state: MLKEMBraidAgentState): BraidChunkProgress {
  let carried = 0;
  let required = 0;

  for (const encoder of [
    state.headerEncoder,
    state.ekEncoder,
    state.ct1Encoder,
    state.ct2Encoder,
  ]) {
    if (!encoder) continue;
    carried += encoder.currentChunk;
    required += encoder.totalChunks;
  }

  for (const decoder of [
    state.headerDecoder,
    state.ekDecoder,
    state.ct1Decoder,
    state.ct2Decoder,
  ]) {
    if (!decoder) continue;
    carried += decoder.receivedChunks;
    required += decoder.requiredChunks;
  }

  return { carried, required };
}
