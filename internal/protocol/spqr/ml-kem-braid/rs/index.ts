/**
 * Reed-Solomon erasure coding for ML-KEM Braid
 *
 * Implements the ML-KEM Braid polynomial-based erasure coding profile using
 * GF(2^16).
 * Uses 16-parallel polynomials with streaming parity generation.
 *
 * ## Usage
 *
 * ```typescript
 * // Initialize GF(2^16) tables (384KB, cached after first load)
 * await initGF16();
 *
 * // Encoding
 * const encoder = new PolyEncoder(data);
 * while (encoder.hasMoreChunks()) {
 *   const chunk = encoder.nextChunk();
 *   sendChunk(chunk);
 * }
 *
 * // Decoding (any k chunks can reconstruct)
 * const decoder = new PolyDecoder(originalSize);
 * for (const chunk of receivedChunks) {
 *   decoder.addChunk(chunk.index, chunk.data);
 * }
 * if (decoder.hasMessage()) {
 *   const original = decoder.message();
 * }
 * ```
 *
 * @module rs
 */

// =============================================================================
// Types (from codec.ts)
// =============================================================================
export {};
export type {
  Decoder,
  Encoder,
  ErasureConfig,
  FieldSize,
  InterleavedConfig,
  Polynomial16,
} from './codec';

// Note: CHUNK_SIZE and POLYNOMIAL_LIMITS are internal to rs/.
// For protocol constants, use PROTOCOL_CONSTANTS from '../types'.

// =============================================================================
// Encoder (Signal: PolyEncoder)
// =============================================================================

export { CHUNK_COUNTS, CHUNK_SIZE, createEncoder, PolyEncoder, POLYNOMIAL_LIMITS } from './codec';

// =============================================================================
// Decoder (Signal: PolyDecoder)
// =============================================================================

export { createDecoder, PolyDecoder } from './codec';

// =============================================================================
// Galois Field
// =============================================================================

export {
  createGF16,
  getGF16Sync,
  GF16_GENERATOR,
  GF16_SIZE,
  initGF16,
  isGF16Ready,
  type GaloisField,
} from './galois';

// =============================================================================
// Math Operations (Lagrange + Polynomial)
// =============================================================================

export {
  createLagrangeInterpolator,
  hasPrecomputedDenominators,
  interpolateAt,
  LagrangeInterpolator,
  PRECOMPUTED_SIZES,
  recoverMissingShards,
} from './lagrange';

export { Polynomial } from './polynomial';
