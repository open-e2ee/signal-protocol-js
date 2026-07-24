/**
 * Interleaved Reed-Solomon codec
 *
 * Implements the 16-parallel polynomial encoding used by ML-KEM Braid.
 * Each 32-byte chunk contains 16 GF(2^16) elements, with each element
 * contributing a coefficient to its corresponding polynomial.
 *
 * **Streaming Architecture**:
 * - Data chunks are returned immediately from stored data
 * - Parity chunks are generated on-demand via Lagrange interpolation
 * - No fixed parity ratio - generates until receiver signals success
 *
 * @module rs/codec
 */

import { LagrangeInterpolator } from './lagrange';
import { getGF16Sync, isGF16Ready, type GaloisField } from './galois';
import {
  BRAID_CHUNK_POINT_COUNT,
  assertBraidChunkIndex,
  assertBraidEncoderCursor,
} from '../chunk-domain';

// =============================================================================
// Core Constants
// =============================================================================

/** Chunk size for erasure coding (Signal protocol default) */
export {};
export const CHUNK_SIZE = 32;

// =============================================================================
// Streaming Encoder/Decoder Interfaces (Signal: Encoder/Decoder traits)
// =============================================================================

/**
 * Erasure encoder interface (Signal: Encoder trait)
 *
 * Generates chunks on-demand for transmission. First k calls return
 * systematic (data) chunks, subsequent calls generate parity chunks
 * via Lagrange interpolation until field limit is reached.
 *
 */
export interface Encoder {
  /** Get next chunk for transmission (data first, then parity) */
  nextChunk(): Uint8Array;
  /** Current chunk index (0-based) */
  currentChunkIndex(): number;
  /** Number of data chunks (k) - minimum needed for reconstruction */
  dataChunkCount(): number;
  /** True if another field evaluation point remains */
  hasMoreChunks(): boolean;
  /** Check if all systematic (data) chunks have been sent */
  isDataComplete(): boolean;
}

/**
 * Erasure decoder interface (Signal: Decoder trait)
 *
 * Accepts chunks in any order and reconstructs the original message
 * once k chunks (data or parity) have been received.
 *
 */
export interface Decoder {
  /** Add received chunk (any order) */
  addChunk(chunkIndex: number, chunk: Uint8Array): void;
  /** Check if enough chunks received for reconstruction */
  hasMessage(): boolean;
  /** Reconstruct original message */
  message(): Uint8Array | null;
  /** Number of chunks received so far */
  chunksReceived(): number;
}

// =============================================================================
// Field Types
// =============================================================================

/**
 * Galois field size: 8-bit or 16-bit
 */
export type FieldSize = 8 | 16;

// =============================================================================
// Configuration
// =============================================================================

/**
 * Reed-Solomon erasure coding configuration
 *
 * With streaming encoding, parityChunks and totalChunks
 * are not fixed at encode time. They represent the current/estimated values.
 */
export interface ErasureConfig {
  /** Galois field size: 256 for GF(2^8), 65536 for GF(2^16) */
  fieldSize: 256 | 65536;
  /** Field bits: 8 or 16 */
  fieldBits: FieldSize;
  /** Protocol chunk size in bytes. */
  chunkSize: number;
  /** Number of data chunks (k) - fixed at encode time */
  dataChunks: number;
  /** Number of parity chunks generated so far (streaming: increases over time) */
  parityChunks: number;
  /** Total chunks generated so far (dataChunks + parityChunks) */
  totalChunks: number;
}

// =============================================================================
// Chunk Count Constants
// =============================================================================

/**
 * Chunk counts for standard ML-KEM-768 components
 * Based on 32-byte chunk size
 */
export const CHUNK_COUNTS = {
  /** Header (64 bytes) + MAC (32 bytes) = 96 bytes / 32 = 3 chunks */
  HEADER: 3,
  /** EK Vector: 1152 bytes / 32 = 36 chunks + ~30% parity = 37 chunks sent */
  EK_VECTOR: 37,
  /** CT1: 960 bytes / 32 = 30 chunks + ~30% parity = 31 chunks sent */
  CT1: 31,
  /** CT2 (128 bytes) + Combined MAC (32 bytes) = 160 bytes / 32 = 5 chunks */
  CT2: 5,
} as const;

// =============================================================================
// Polynomial Encoding Limits
// =============================================================================

/**
 * Limits for 16-polynomial interleaved Reed-Solomon encoding.
 */
export const POLYNOMIAL_LIMITS = {
  /** Number of parallel polynomials (CHUNK_SIZE / 2 = 32 / 2 = 16) */
  NUM_POLYS: 16,
  /** Maximum polynomial degree for data chunks */
  MAX_DEGREE: 35,
  /** Maximum degree during intermediate computation */
  MAX_INTERMEDIATE_DEGREE: 36,
  /** Maximum message size: (MAX_DEGREE + 1) × CHUNK_SIZE = 36 × 32 = 1,152 bytes */
  MAX_MESSAGE_SIZE: 1152,
} as const;

// =============================================================================
// 16-Parallel Polynomial Types (Signal Compliance)
// =============================================================================

/**
 * Represents a single polynomial in the 16-polynomial interleaved system.
 *
 * In the reference encoding, each 32-byte chunk contains 16 GF(2^16) elements,
 * and each element becomes a coefficient in its corresponding polynomial.
 *
 */
export interface Polynomial16 {
  /** Polynomial index [0, 15] */
  index: number;
  /** Coefficients as GF(2^16) elements, indexed by chunk position */
  coefficients: number[];
}

/**
 * Configuration for interleaved polynomial encoding.
 *
 * Extends ErasureConfig with 16-polynomial specific settings.
 */
export interface InterleavedConfig extends ErasureConfig {
  /** Fixed at 16 by the interleaved encoding. */
  numPolynomials: 16;
  /** Maximum message size: 36 chunks × 32 bytes = 1,152 bytes */
  maxMessageSize: number;
}

const { NUM_POLYS, MAX_MESSAGE_SIZE } = POLYNOMIAL_LIMITS;

// =============================================================================
// Lazy polynomial conversion (lazy polynomial encoding)
// =============================================================================

/**
 * Encoder state machine for lazy polynomial conversion
 *
 * The encoder uses two states:
 * - Points: Raw GF16 values per polynomial (compact, O(1) lookup for idx < k)
 * - Polys: Interpolated polynomial coefficients (O(k) evaluation anywhere)
 *
 * The conversion happens exactly once, on first parity chunk request,
 * avoiding O(k²) × 16 polynomial computation when only data chunks are needed.
 *
 */
type EncoderState =
  | { type: 'Points'; data: number[][] } // 16 vectors of raw GF16 values
  | { type: 'Polys'; data: Polynomial16[] }; // 16 interpolated polynomials

/**
 * Interleaved polynomial encoder
 *
 * Uses 16 parallel GF(2^16) polynomials with chunk-based interleaving.
 * Generates parity chunks on demand using the profile design.
 *
 * **Lazy polynomial conversion**:
 * - Initially stores data as raw GF16 point vectors (EncoderState::Points)
 * - Converts to interpolated polynomials only on first parity chunk request
 * - Avoids O(k²) × 16 computation when only data chunks are needed
 *
 * Algorithm:
 * 1. Store raw GF16 values as 16 parallel point vectors
 * 2. Return data chunks immediately (systematic encoding, O(1) lookup)
 * 3. On first parity request: convert Points → Polys (one-time O(k²) cost)
 * 4. Generate subsequent parity chunks via polynomial evaluation (O(k) each)
 *
 */
export class PolyEncoder implements Encoder {
  private config: InterleavedConfig;
  private state: EncoderState;
  private dataChunks: Uint8Array[];
  private currentChunkIdx: number = 0;
  private originalDataSize: number;
  private field: GaloisField;
  private k: number;

  // Cached interpolation data for O(k) parity generation
  private interpolator: LagrangeInterpolator;
  private xs: number[];
  private denominators: number[];

  /**
   * Create streaming encoder for data using 16-parallel polynomial interleaving
   *
   * @param data - Raw bytes to encode (max 1,152 bytes)
   * @throws Error if data is empty, too large, or GF(2^16) not loaded
   */
  constructor(data: Uint8Array) {
    // Input validation
    if (!data || data.length === 0) {
      throw new Error('Cannot encode empty data');
    }
    if (data.length > MAX_MESSAGE_SIZE) {
      throw new Error(
        `Message size ${data.length} exceeds maximum for interleaved encoding (${MAX_MESSAGE_SIZE} bytes)`
      );
    }

    // Validate GF(2^16) is loaded
    if (!isGF16Ready()) {
      throw new Error(
        'GF(2^16) tables not loaded. Call initGF16() before creating interleaved encoder.'
      );
    }
    this.field = getGF16Sync()!;

    this.originalDataSize = data.length;

    // Calculate configuration (streaming: parity generated on demand)
    this.k = Math.ceil(data.length / CHUNK_SIZE);

    this.config = {
      fieldSize: 65536,
      fieldBits: 16,
      chunkSize: CHUNK_SIZE,
      dataChunks: this.k,
      parityChunks: 0, // Streaming: not fixed
      totalChunks: this.k, // Will increase as parity is generated
      numPolynomials: 16,
      maxMessageSize: MAX_MESSAGE_SIZE,
    };

    // Lazy initialization: start in the reference's Points state.
    // Polynomial conversion deferred until first parity chunk request
    this.state = { type: 'Points', data: this.parseDataToPoints(data) };

    // Store data chunks directly for O(1) systematic retrieval
    this.dataChunks = this.extractDataChunks(data);

    // Pre-compute interpolation denominators for efficient parity generation
    // Uses cached denominators for common ML-KEM Braid sizes (1, 3, 5, 30, 34, 36)
    this.interpolator = new LagrangeInterpolator(this.field);
    this.xs = Array.from({ length: this.k }, (_, i) => i);
    this.denominators = this.interpolator.getConsecutiveDenominators(this.k);
  }

  /**
   * Restore the deterministic streaming encoder at a persisted next-chunk cursor.
   *
   * Chunk generation has no rolling state beyond the cursor: systematic chunks
   * are immutable and parity chunks are pure polynomial evaluations. Restoring
   * the cursor directly avoids replaying up to 65,536 prior chunks while still
   * rebuilding the same lazy polynomial state on the next parity request.
   */
  static restore(data: Uint8Array, currentChunkIndex: number): PolyEncoder {
    assertBraidEncoderCursor(currentChunkIndex, 'Encoder cursor');

    const encoder = new PolyEncoder(data);
    encoder.currentChunkIdx = currentChunkIndex;
    encoder.config.parityChunks = Math.max(0, currentChunkIndex - encoder.config.dataChunks);
    encoder.config.totalChunks = encoder.config.dataChunks + encoder.config.parityChunks;
    return encoder;
  }

  /**
   * Parse data into 16 parallel GF16 point vectors (lazy Points state)
   *
   * Each vector contains the y-values for one polynomial at evaluation
   * points [0, 1, ..., k-1]. Polynomial interpolation is deferred.
   *
   * @param data - Raw data bytes
   * @returns 16 vectors of GF16 values
   */
  private parseDataToPoints(data: Uint8Array): number[][] {
    const k = this.k;

    // Pad data to chunk boundary
    const paddedLength = k * CHUNK_SIZE;
    const paddedData = new Uint8Array(paddedLength);
    paddedData.set(data);

    // Initialize 16 point vectors
    const points: number[][] = Array.from({ length: NUM_POLYS }, () => []);

    // Parse into 16 parallel point vectors
    for (let chunkIdx = 0; chunkIdx < k; chunkIdx++) {
      const chunkOffset = chunkIdx * CHUNK_SIZE;

      for (let polyIdx = 0; polyIdx < NUM_POLYS; polyIdx++) {
        const byteOffset = chunkOffset + polyIdx * 2;
        // Big-endian: high byte first, then low byte
        const gf16Value = (paddedData[byteOffset] << 8) | paddedData[byteOffset + 1];
        points[polyIdx][chunkIdx] = gf16Value;
      }
    }

    return points;
  }

  /**
   * Extract data chunks for systematic encoding
   *
   * @param data - Raw data bytes
   * @returns Array of 32-byte data chunks
   */
  private extractDataChunks(data: Uint8Array): Uint8Array[] {
    const k = this.k;

    // Pad data to chunk boundary
    const paddedLength = k * CHUNK_SIZE;
    const paddedData = new Uint8Array(paddedLength);
    paddedData.set(data);

    // Create data chunks (systematic - original padded data)
    const chunks: Uint8Array[] = [];
    for (let chunkIdx = 0; chunkIdx < k; chunkIdx++) {
      const chunk = paddedData.slice(chunkIdx * CHUNK_SIZE, (chunkIdx + 1) * CHUNK_SIZE);
      chunks.push(chunk);
    }

    return chunks;
  }

  /**
   * Get value of polynomial at evaluation point (lazy conversion trigger)
   *
   * For data chunks (chunkIdx < k): O(1) lookup from Points state
   * For parity chunks (chunkIdx >= k): Triggers Points→Polys conversion on first call
   *
   * @param polyIdx - Polynomial index [0, 15]
   * @param chunkIdx - Chunk/evaluation point index
   * @returns GF16 value at that point
   */
  private pointAt(polyIdx: number, chunkIdx: number): number {
    if (this.state.type === 'Points') {
      const points = this.state.data;

      // Fast path: in-range lookup (O(1))
      if (chunkIdx < points[polyIdx].length) {
        return points[polyIdx][chunkIdx];
      }

      // Out-of-range: Trigger conversion to polynomials
      // This is the one-time O(k²) × 16 cost
      this.convertToPolynomials();
    }

    // Now in Polys state: evaluate polynomial at chunkIdx
    const polys = (this.state as { type: 'Polys'; data: Polynomial16[] }).data;
    return this.evaluatePolynomial(polys[polyIdx], chunkIdx);
  }

  /**
   * Convert from Points state to Polys state (one-time cost)
   *
   * Uses Lagrange interpolation to compute polynomial coefficients
   * from the stored point values. This is O(k²) per polynomial.
   */
  private convertToPolynomials(): void {
    if (this.state.type !== 'Points') {
      return; // Already converted
    }

    const pointVectors = this.state.data;
    const polys: Polynomial16[] = [];

    // Convert each of the 16 point vectors to a polynomial
    for (let polyIdx = 0; polyIdx < NUM_POLYS; polyIdx++) {
      const ys = pointVectors[polyIdx];

      // Compute polynomial coefficients via Lagrange interpolation
      // Uses cached denominators for efficiency
      const coefficients = this.computePolynomialCoefficients(ys);

      polys.push({
        index: polyIdx,
        coefficients,
      });
    }

    // Transition to Polys state (one-way, never goes back)
    this.state = { type: 'Polys', data: polys };
  }

  /**
   * Compute polynomial coefficients from point values using Newton's Divided Differences
   *
   * Algorithm: Given y-values at consecutive integer points [0, 1, ..., k-1],
   * computes coefficients of the unique interpolating polynomial.
   *
   * The algorithm has two phases:
   * 1. Divided Differences Table: Compute d[i][j] = (d[i][j-1] - d[i-1][j-1]) / (x[i] - x[i-j])
   *    In GF(2^n), subtraction is XOR and division uses field.div()
   *
   * 2. Newton-to-Standard Conversion: Expand Newton form into standard coefficients
   *    Newton: f(x) = d_0 + d_1(x-0) + d_2(x-0)(x-1) + ...
   *    Standard: f(x) = c_0 + c_1*x + c_2*x^2 + ...
   *
   * Time complexity: O(k^2)
   * Space complexity: O(k)
   *
   * @param ys - Y-values at points 0, 1, ..., k-1
   * @returns Polynomial coefficients [c_0, c_1, ..., c_{k-1}]
   *
   * @see BBC WHP-031 Section 6 - Reed-Solomon Tutorial
   * @see https://en.wikipedia.org/wiki/Newton_polynomial
   */
  private computePolynomialCoefficients(ys: number[]): number[] {
    const k = ys.length;
    if (k === 0) return [];
    if (k === 1) return [ys[0]];

    // Newton's divided differences for coefficient computation
    // This produces coefficients in Newton form which we convert to standard form
    const divDiff: number[] = [...ys];

    // Phase 1: Compute divided differences table
    for (let j = 1; j < k; j++) {
      for (let i = k - 1; i >= j; i--) {
        // In GF(2^n): subtraction is XOR (same as addition), division uses field.div
        const numerator = divDiff[i] ^ divDiff[i - 1]; // Subtraction in GF(2^n)
        const denominator = i ^ (i - j); // x_i - x_{i-j} = i XOR (i-j)
        divDiff[i] = this.field.div(numerator, denominator);
      }
    }

    // Phase 2: Convert Newton form to standard polynomial coefficients
    // Newton form: f(x) = d_0 + d_1(x-0) + d_2(x-0)(x-1) + ...
    const coeffs = new Array(k).fill(0);
    coeffs[0] = divDiff[0];

    // Expand (x - 0)(x - 1)...(x - (j-1)) and multiply by d_j
    const expansion = new Array(k).fill(0);
    expansion[0] = 1;

    for (let j = 1; j < k; j++) {
      // Multiply expansion by (x - (j-1)) = (x XOR (j-1))
      for (let i = j; i >= 1; i--) {
        expansion[i] = this.field.add(expansion[i - 1], this.field.mul(expansion[i], j - 1));
      }
      expansion[0] = this.field.mul(expansion[0], j - 1);

      // Add d_j * expansion to coefficients
      for (let i = 0; i <= j; i++) {
        coeffs[i] = this.field.add(coeffs[i], this.field.mul(divDiff[j], expansion[i]));
      }
    }

    return coeffs;
  }

  /**
   * Evaluate polynomial at a given point using Horner's method
   *
   * @param poly - Polynomial with coefficients
   * @param x - Evaluation point
   * @returns f(x) in GF(2^16)
   */
  private evaluatePolynomial(poly: Polynomial16, x: number): number {
    const coeffs = poly.coefficients;
    if (coeffs.length === 0) return 0;

    // Horner's method: f(x) = c_0 + x(c_1 + x(c_2 + ...))
    let result = coeffs[coeffs.length - 1];
    for (let i = coeffs.length - 2; i >= 0; i--) {
      result = this.field.add(this.field.mul(result, x), coeffs[i]);
    }
    return result;
  }

  /**
   * Generate a parity chunk on demand
   *
   * Uses pointAt() which triggers lazy conversion on first parity request.
   *
   * @param chunkIndex - The chunk index (must be >= dataChunks)
   * @returns 32-byte parity chunk
   */
  private generateParityChunk(chunkIndex: number): Uint8Array {
    const chunk = new Uint8Array(CHUNK_SIZE);

    // Evaluate each polynomial at the chunk index
    // pointAt() handles lazy Points→Polys conversion on first call
    for (let polyIdx = 0; polyIdx < NUM_POLYS; polyIdx++) {
      const gf16Value = this.pointAt(polyIdx, chunkIndex);

      // Big-endian encoding
      const byteOffset = polyIdx * 2;
      chunk[byteOffset] = (gf16Value >> 8) & 0xff;
      chunk[byteOffset + 1] = gf16Value & 0xff;
    }

    return chunk;
  }

  /**
   * Get next chunk for transmission (data first, then parity on demand)
   *
   * @returns 32-byte codeword shard
   */
  nextChunk(): Uint8Array {
    if (!this.hasMoreChunks()) {
      throw new Error(`Braid encoder exhausted all ${BRAID_CHUNK_POINT_COUNT} GF(2^16) points`);
    }
    const idx = this.currentChunkIdx++;

    // Data chunks: return from stored array
    if (idx < this.config.dataChunks) {
      return this.dataChunks[idx];
    }

    // Parity chunks: generate on demand through the final u16 point.
    this.config.parityChunks = idx - this.config.dataChunks + 1;
    this.config.totalChunks = this.config.dataChunks + this.config.parityChunks;
    return this.generateParityChunk(idx);
  }

  /**
   * Current chunk index (0-based, incremented after each nextChunk())
   */
  currentChunkIndex(): number {
    return this.currentChunkIdx;
  }

  /**
   * Number of data chunks (k) - the minimum needed for reconstruction
   */
  dataChunkCount(): number {
    return this.config.dataChunks;
  }

  /**
   * True if another field evaluation point remains
   */
  hasMoreChunks(): boolean {
    return this.currentChunkIdx < BRAID_CHUNK_POINT_COUNT;
  }

  /**
   * Check if all systematic (data) chunks have been sent
   */
  isDataComplete(): boolean {
    return this.currentChunkIdx >= this.config.dataChunks;
  }

  /**
   * Get total number of chunks generated so far
   * Note: With streaming, this increases as parity is generated
   */
  totalChunks(): number {
    return this.config.totalChunks;
  }

  /**
   * Get current configuration
   */
  getConfig(): ErasureConfig {
    return { ...this.config };
  }

  /**
   * Get original data size (needed for decoding)
   */
  getOriginalDataSize(): number {
    return this.originalDataSize;
  }

  /**
   * Get the 16 polynomials for diagnostics.
   *
   * In Points state: returns point values as "coefficients" (y-values at x=0,1,2,...)
   * In Polys state: returns actual polynomial coefficients
   *
   * To inspect lazy conversion, use isInPointsState().
   */
  getPolynomials(): readonly Polynomial16[] {
    if (this.state.type === 'Points') {
      // Return points wrapped in Polynomial16 format (y-values as "coefficients")
      // This preserves the established byte-distribution behavior.
      return this.state.data.map((points, index) => ({
        index,
        coefficients: points,
      }));
    }
    return this.state.data;
  }

  /**
   * Check if encoder is still in lazy Points state
   *
   * Returns true if no parity chunks have been generated yet
   * (polynomials have not been computed).
   *
   * Exposes lazy-conversion state for deterministic inspection.
   */
  isInPointsState(): boolean {
    return this.state.type === 'Points';
  }

  /**
   * Serialize encoder state to JSON for persistence
   *
   * @returns JSON-serializable object
   */
  toJSON(): {
    idx: number;
    pts: string[];
    polys: string[];
    messageSize: number;
    stateType: 'Points' | 'Polys';
  } {
    // Convert data chunks to hex strings
    const pts = this.dataChunks.map((chunk) =>
      Array.from(chunk)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('')
    );

    // Convert polynomial state to hex strings
    let polys: string[];
    if (this.state.type === 'Points') {
      // Store Points data as hex
      polys = this.state.data.map((pointVec) => {
        const bytes = new Uint8Array(pointVec.length * 2);
        for (let i = 0; i < pointVec.length; i++) {
          const c = pointVec[i];
          bytes[i * 2] = (c >> 8) & 0xff;
          bytes[i * 2 + 1] = c & 0xff;
        }
        return Array.from(bytes)
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('');
      });
    } else {
      // Store Polys coefficients as hex
      polys = this.state.data.map((p) => {
        const bytes = new Uint8Array(p.coefficients.length * 2);
        for (let i = 0; i < p.coefficients.length; i++) {
          const c = p.coefficients[i];
          bytes[i * 2] = (c >> 8) & 0xff;
          bytes[i * 2 + 1] = c & 0xff;
        }
        return Array.from(bytes)
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('');
      });
    }

    return {
      idx: this.currentChunkIdx,
      pts,
      polys,
      messageSize: this.originalDataSize,
      stateType: this.state.type,
    };
  }

  /**
   * Restore encoder from JSON state (requires re-creating with original data)
   *
   * Note: Full state restoration requires the original data since the encoder
   * needs access to the data chunks and polynomial coefficients.
   *
   * @param json - Serialized encoder state
   * @param currentIdx - Current chunk index to restore to
   * @returns Restored encoder (positioned at currentIdx)
   */
  static fromJSON(json: {
    idx: number;
    pts: string[];
    polys: string[];
    messageSize: number;
  }): PolyEncoder {
    // Reconstruct original data from pts (data chunks)
    const dataChunks = json.pts.map((hex) => {
      const bytes = new Uint8Array(hex.length / 2);
      for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
      }
      return bytes;
    });

    // Concatenate data chunks
    const totalLen = Math.min(json.messageSize, dataChunks.length * CHUNK_SIZE);
    const data = new Uint8Array(totalLen);
    let offset = 0;
    for (const chunk of dataChunks) {
      const copyLen = Math.min(CHUNK_SIZE, totalLen - offset);
      data.set(chunk.subarray(0, copyLen), offset);
      offset += copyLen;
      if (offset >= totalLen) break;
    }

    return PolyEncoder.restore(data, json.idx);
  }
}

/**
 * Create the selected-profile polynomial encoder (async).
 *
 * Automatically loads GF(2^16) tables if needed.
 *
 * @param data - Raw bytes to encode (max 1,152 bytes)
 * @returns Promise resolving to streaming encoder
 */
export async function createEncoder(data: Uint8Array): Promise<PolyEncoder> {
  const { initGF16 } = await import('./galois');
  await initGF16();
  return new PolyEncoder(data);
}

// =============================================================================
// Polynomial decoder
// =============================================================================

/**
 * Interleaved polynomial decoder
 *
 * Decodes chunks from 16-parallel polynomial interleaved encoding.
 * Supports out-of-order chunk delivery and erasure recovery.
 *
 * **Streaming Compatibility**:
 * - Works with streaming encoders that generate parity on demand
 * - Only requires k (dataChunks) chunks for reconstruction
 * - No assumption about fixed parity count
 *
 * Algorithm:
 * 1. Parse received chunks into 16 polynomial coefficient maps
 * 2. Identify missing data chunk indices
 * 3. Recover via Lagrange interpolation (per polynomial)
 * 4. Reconstruct message from recovered coefficients
 *
 */
export class PolyDecoder implements Decoder {
  private config: InterleavedConfig;
  private receivedChunks: Map<number, Uint8Array> = new Map();
  private messageSize: number;
  private field: GaloisField;
  private totalShardsSet: boolean = false;

  /**
   * Create decoder expecting message of given size
   *
   * @param messageSize - Expected decoded message size in bytes (max 1,152)
   * @throws Error if messageSize is invalid or GF(2^16) not loaded
   */
  constructor(messageSize: number) {
    // Input validation
    if (messageSize <= 0) {
      throw new Error('Message size must be positive');
    }
    if (messageSize > MAX_MESSAGE_SIZE) {
      throw new Error(
        `Message size ${messageSize} exceeds maximum for interleaved decoding (${MAX_MESSAGE_SIZE} bytes)`
      );
    }

    // Validate GF(2^16) is loaded
    if (!isGF16Ready()) {
      throw new Error(
        'GF(2^16) tables not loaded. Call initGF16() before creating interleaved decoder.'
      );
    }
    this.field = getGF16Sync()!;

    this.messageSize = messageSize;

    // Calculate configuration (streaming: parity count not fixed)
    const dataChunks = Math.ceil(messageSize / CHUNK_SIZE);

    this.config = {
      fieldSize: 65536,
      fieldBits: 16,
      chunkSize: CHUNK_SIZE,
      dataChunks,
      parityChunks: 0, // Streaming: not fixed, updated as chunks received
      totalChunks: dataChunks, // Will increase as parity chunks are received
      numPolynomials: 16,
      maxMessageSize: MAX_MESSAGE_SIZE,
    };
  }

  /**
   * Add received chunk to decoder
   *
   * @param chunkIndex - Position of chunk (evaluation point), must be >= 0
   * @param chunk - 32-byte codeword shard
   * @throws Error if chunkIndex is negative, exceeds totalChunks (when set), or chunk is invalid
   */
  addChunk(chunkIndex: number, chunk: Uint8Array): void {
    // Input validation
    assertBraidChunkIndex(chunkIndex, 'Chunk index');
    // Only enforce upper bound if setTotalShards() was called
    if (this.totalShardsSet && chunkIndex >= this.config.totalChunks) {
      throw new Error(`Chunk index ${chunkIndex} exceeds maximum (${this.config.totalChunks - 1})`);
    }
    if (!chunk || chunk.length === 0) {
      throw new Error('Chunk cannot be empty');
    }
    if (chunk.length !== CHUNK_SIZE) {
      throw new Error(`Invalid chunk size: expected ${CHUNK_SIZE}, got ${chunk.length}`);
    }

    const existing = this.receivedChunks.get(chunkIndex);
    if (existing) {
      let equal = true;
      for (let index = 0; index < CHUNK_SIZE; index += 1) {
        equal = equal && existing[index] === chunk[index];
      }
      if (!equal) {
        throw new Error(`Conflicting duplicate chunk at index ${chunkIndex}`);
      }
      return;
    }

    // Bound retained public transcript data and isolate it from caller mutation.
    this.receivedChunks.set(chunkIndex, Uint8Array.from(chunk));
  }

  /**
   * Check if enough chunks received to reconstruct message
   *
   * For Reed-Solomon, need at least k (dataChunks) chunks.
   */
  hasMessage(): boolean {
    return this.receivedChunks.size >= this.config.dataChunks;
  }

  /**
   * Get current configuration
   */
  getConfig(): ErasureConfig {
    return { ...this.config };
  }

  /**
   * Get number of chunks received
   */
  chunksReceived(): number {
    return this.receivedChunks.size;
  }

  /**
   * Set the expected total shard count
   *
   * When set, addChunk() will enforce bounds checking (chunkIndex < totalShards).
   */
  setTotalShards(count: number): void {
    if (
      !Number.isSafeInteger(count) ||
      count < this.config.dataChunks ||
      count > BRAID_CHUNK_POINT_COUNT
    ) {
      throw new Error(
        `Total shard count must be an integer between ${this.config.dataChunks} and ${BRAID_CHUNK_POINT_COUNT}`
      );
    }
    this.config.totalChunks = count;
    this.totalShardsSet = true;
  }

  /**
   * Reconstruct original message from received chunks
   *
   * Uses 16-parallel polynomial Lagrange interpolation for erasure recovery.
   *
   * @returns Decoded message or null if insufficient chunks
   */
  message(): Uint8Array | null {
    if (!this.hasMessage()) {
      return null;
    }

    const k = this.config.dataChunks;

    // Step 1: Identify missing data chunks
    const missingDataChunks: number[] = [];
    for (let i = 0; i < k; i++) {
      if (!this.receivedChunks.has(i)) {
        missingDataChunks.push(i);
      }
    }

    // Fast path: all data chunks present, just concatenate
    if (missingDataChunks.length === 0) {
      return this.concatenateDataChunks();
    }

    // Step 2: Parse received chunks into 16 polynomial coefficient maps
    // polynomialCoeffs[polyIdx] = Map<chunkIndex, gf16Value>
    const polynomialCoeffs: Map<number, number>[] = Array.from(
      { length: NUM_POLYS },
      () => new Map()
    );

    for (const [chunkIndex, chunk] of this.receivedChunks) {
      for (let polyIdx = 0; polyIdx < NUM_POLYS; polyIdx++) {
        const byteOffset = polyIdx * 2;
        // Big-endian: high byte first, then low byte
        const gf16Value = (chunk[byteOffset] << 8) | chunk[byteOffset + 1];
        polynomialCoeffs[polyIdx].set(chunkIndex, gf16Value);
      }
    }

    // Step 3: Select k available chunk indices for interpolation
    const availableIndices = Array.from(this.receivedChunks.keys()).slice(0, k);

    // Step 4: Recover missing data chunks via Lagrange interpolation
    const interpolator = new LagrangeInterpolator(this.field);
    const denominators = interpolator.computeDenominators(availableIndices);

    // recoveredChunks[chunkIndex] = reconstructed 32-byte chunk
    const recoveredChunks = new Map<number, Uint8Array>();

    for (const missingIdx of missingDataChunks) {
      const chunk = new Uint8Array(CHUNK_SIZE);

      for (let polyIdx = 0; polyIdx < NUM_POLYS; polyIdx++) {
        // Get y values for this polynomial at available indices
        const ys = availableIndices.map((idx) => polynomialCoeffs[polyIdx].get(idx)!);

        // Interpolate to find value at missing index
        const gf16Value = interpolator.interpolateWithDenominators(
          availableIndices,
          ys,
          denominators,
          missingIdx
        );

        // Store in big-endian format
        const byteOffset = polyIdx * 2;
        chunk[byteOffset] = (gf16Value >> 8) & 0xff;
        chunk[byteOffset + 1] = gf16Value & 0xff;
      }

      recoveredChunks.set(missingIdx, chunk);
    }

    // Step 5: Reconstruct message from data chunks
    const result = new Uint8Array(this.messageSize);
    let offset = 0;

    for (let chunkIdx = 0; chunkIdx < k && offset < this.messageSize; chunkIdx++) {
      const chunk = recoveredChunks.get(chunkIdx) ?? this.receivedChunks.get(chunkIdx)!;
      const copyLen = Math.min(CHUNK_SIZE, this.messageSize - offset);
      result.set(chunk.subarray(0, copyLen), offset);
      offset += copyLen;
    }

    return result;
  }

  /**
   * Fast path: concatenate data chunks when all are present
   */
  private concatenateDataChunks(): Uint8Array {
    const result = new Uint8Array(this.messageSize);
    let offset = 0;

    for (
      let chunkIdx = 0;
      chunkIdx < this.config.dataChunks && offset < this.messageSize;
      chunkIdx++
    ) {
      const chunk = this.receivedChunks.get(chunkIdx)!;
      const copyLen = Math.min(CHUNK_SIZE, this.messageSize - offset);
      result.set(chunk.subarray(0, copyLen), offset);
      offset += copyLen;
    }

    return result;
  }

  /**
   * Serialize decoder state to JSON for persistence
   *
   * @returns JSON-serializable object
   */
  toJSON(): {
    ptsNeeded: number;
    polys: number;
    chunks: Array<{ index: number; data: string }>;
    isComplete: boolean;
    messageSize: number;
  } {
    // Convert received chunks to JSON-serializable format
    const chunks: Array<{ index: number; data: string }> = [];
    for (const [index, data] of this.receivedChunks) {
      const hex = Array.from(data)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
      chunks.push({ index, data: hex });
    }

    return {
      ptsNeeded: this.config.dataChunks,
      polys: NUM_POLYS,
      chunks,
      isComplete: this.hasMessage(),
      messageSize: this.messageSize,
    };
  }

  /**
   * Restore decoder from JSON state
   *
   * @param json - Serialized decoder state
   * @returns Restored decoder with received chunks
   */
  static fromJSON(json: {
    ptsNeeded: number;
    polys: number;
    chunks: Array<{ index: number; data: string }>;
    isComplete: boolean;
    messageSize: number;
  }): PolyDecoder {
    const decoder = new PolyDecoder(json.messageSize);

    // Restore received chunks
    for (const { index, data: hex } of json.chunks) {
      const bytes = new Uint8Array(hex.length / 2);
      for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
      }
      decoder.addChunk(index, bytes);
    }

    return decoder;
  }
}

/**
 * Create the selected-profile polynomial decoder (async).
 *
 * Automatically loads GF(2^16) tables if needed.
 *
 * @param messageSize - Expected decoded message size in bytes (max 1,152)
 * @returns Promise resolving to stateful decoder
 */
export async function createDecoder(messageSize: number): Promise<PolyDecoder> {
  const { initGF16 } = await import('./galois');
  await initGF16();
  return new PolyDecoder(messageSize);
}
