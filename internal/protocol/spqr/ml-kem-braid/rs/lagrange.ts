/**
 * Lagrange Polynomial Interpolation over Galois Fields
 *
 * Implements erasure recovery via Lagrange interpolation. Given k points
 * (x_i, y_i), this module reconstructs the unique polynomial f(x) of
 * degree < k such that f(x_i) = y_i for all i.
 *
 * This is used for Reed-Solomon erasure recovery where we know which
 * shards are missing (erasure positions are known).
 *
 * @module rs/lagrange
 * @see BBC WHP-031 Section 6.3
 */

import type { GaloisField } from './galois';

// =============================================================================
// Precomputed Lagrange bases (lazy polynomial encoding)
// =============================================================================

/**
 * Common chunk counts for ML-KEM Braid protocol (SPQR V1)
 *
 * These sizes are precomputed for O(1) lookup of Lagrange denominators:
 * - 1: Single chunk (32 bytes)
 * - 3: Header with MAC (96 bytes)
 * - 5: CT2 with MAC (160 bytes)
 * - 30: CT1 (960 bytes)
 * - 34: Common 1088-byte shard size
 * - 36: EK vector / max message (1152 bytes)
 *
 */
export {};
export const PRECOMPUTED_SIZES = [1, 3, 5, 30, 34, 36] as const;
export type PrecomputedSize = (typeof PRECOMPUTED_SIZES)[number];

/**
 * Cache for precomputed Lagrange denominators
 *
 * Maps chunk count to precomputed denominators for consecutive integer
 * evaluation points [0, 1, 2, ..., n-1]. This is the common case in
 * ML-KEM Braid where chunk indices are used directly as evaluation points.
 *
 * Denominators are computed lazily on first access for each size.
 */
const denominatorCache = new Map<number, number[]>();

/**
 * Check if a size has precomputed denominators available
 */
export function hasPrecomputedDenominators(size: number): boolean {
  return (PRECOMPUTED_SIZES as readonly number[]).includes(size);
}

/**
 * Point on a polynomial curve
 */
export interface Point {
  /** X coordinate (evaluation point) */
  x: number;
  /** Y coordinate (polynomial value at x) */
  y: number;
}

/**
 * Lagrange Interpolator for erasure recovery
 *
 * Provides efficient Lagrange polynomial interpolation over a Galois field.
 * Optimized for batch reconstruction of multiple missing values.
 *
 */
export class LagrangeInterpolator {
  constructor(private readonly field: GaloisField) {}

  /**
   * Get precomputed denominators for consecutive integer evaluation points
   *
   * For common sizes used in ML-KEM Braid (1, 3, 5, 30, 34, 36), this method
   * returns cached denominators computed once per field. For other sizes,
   * falls back to dynamic computation.
   *
   * @param n - Number of points (chunk count)
   * @returns Precomputed denominators for points [0, 1, ..., n-1]
   */
  getConsecutiveDenominators(n: number): number[] {
    // Check cache first
    const cached = denominatorCache.get(n);
    if (cached) {
      return cached;
    }

    // Compute denominators for consecutive integers [0, 1, ..., n-1]
    const xs = Array.from({ length: n }, (_, i) => i);
    const denominators = this.computeDenominators(xs);

    // Cache for precomputed sizes (common ML-KEM Braid message sizes)
    if (hasPrecomputedDenominators(n)) {
      denominatorCache.set(n, denominators);
    }

    return denominators;
  }

  /**
   * Clear the denominator cache for controlled resets.
   */
  static clearCache(): void {
    denominatorCache.clear();
  }

  /**
   * Compute Lagrange basis polynomial denominators
   *
   * For a set of x-coordinates {x_0, ..., x_{k-1}}, computes:
   *   d_i = Π_{j≠i} (x_i - x_j)
   *
   * These denominators are constant for a given set of x-coordinates and
   * can be precomputed for efficiency when interpolating multiple times.
   *
   * @param xs - Array of distinct x-coordinates
   * @returns Array of denominators d_i for each x_i
   */
  computeDenominators(xs: number[]): number[] {
    const n = xs.length;

    // Validate evaluation points are in field range and distinct
    const seen = new Set<number>();
    for (let i = 0; i < n; i++) {
      const x = xs[i];
      if (x < 0 || x >= this.field.size) {
        throw new Error(`Evaluation point ${x} out of field range [0, ${this.field.size - 1}]`);
      }
      if (seen.has(x)) {
        throw new Error(`Duplicate evaluation point: ${x}`);
      }
      seen.add(x);
    }

    const denominators = new Array(n);

    for (let i = 0; i < n; i++) {
      // d starts at 1 (multiplicative identity in the field)
      let d = 1;
      for (let j = 0; j < n; j++) {
        if (i !== j) {
          // In GF(2^n), subtraction is XOR
          const diff = xs[i] ^ xs[j];
          d = this.field.mul(d, diff);
        }
      }
      denominators[i] = d;
    }

    return denominators;
  }

  /**
   * Evaluate the Lagrange interpolated polynomial at a target point
   *
   * Given k points (x_i, y_i), computes f(targetX) where f is the unique
   * polynomial of degree < k passing through all points.
   *
   * Uses the Lagrange interpolation formula:
   *   f(x) = Σ y_i · L_i(x)
   *
   * where L_i(x) = Π_{j≠i} (x - x_j) / (x_i - x_j)
   *
   * @param points - Array of (x, y) points defining the polynomial
   * @param targetX - X-coordinate to evaluate at
   * @returns f(targetX)
   */
  interpolate(points: Point[], targetX: number): number {
    const n = points.length;
    if (n === 0) {
      return 0;
    }

    // Extract x and y coordinates
    const xs = points.map((p) => p.x);
    const ys = points.map((p) => p.y);

    // Precompute denominators
    const denominators = this.computeDenominators(xs);

    // Compute interpolated value
    let result = 0;
    for (let i = 0; i < n; i++) {
      // Compute numerator: Π_{j≠i} (targetX - x_j)
      let numerator = 1;
      for (let j = 0; j < n; j++) {
        if (i !== j) {
          // In GF(2^n), subtraction is XOR
          numerator = this.field.mul(numerator, targetX ^ xs[j]);
        }
      }

      // L_i(targetX) = numerator / denominator
      const basis = this.field.div(numerator, denominators[i]);

      // Accumulate y_i * L_i(targetX)
      result = this.field.add(result, this.field.mul(ys[i], basis));
    }

    return result;
  }

  /**
   * Interpolate with precomputed denominators
   *
   * More efficient when interpolating at multiple target points with
   * the same set of source x-coordinates.
   *
   * @param xs - Array of x-coordinates
   * @param ys - Array of y-coordinates (same order as xs)
   * @param denominators - Precomputed denominators from computeDenominators(xs)
   * @param targetX - X-coordinate to evaluate at
   * @returns f(targetX)
   */
  interpolateWithDenominators(
    xs: number[],
    ys: number[],
    denominators: number[],
    targetX: number
  ): number {
    const n = xs.length;
    let result = 0;

    for (let i = 0; i < n; i++) {
      // Compute numerator: Π_{j≠i} (targetX - x_j)
      let numerator = 1;
      for (let j = 0; j < n; j++) {
        if (i !== j) {
          numerator = this.field.mul(numerator, targetX ^ xs[j]);
        }
      }

      // L_i(targetX) = numerator / denominator
      const basis = this.field.div(numerator, denominators[i]);

      // Accumulate y_i * L_i(targetX)
      result = this.field.add(result, this.field.mul(ys[i], basis));
    }

    return result;
  }

  /**
   * Batch interpolation for recovering multiple missing values
   *
   * Given available points and indices of missing values, reconstructs
   * the polynomial values at each missing index.
   *
   * @param available - Map of index -> value for available shards
   * @param missing - Array of indices for missing values
   * @param evaluationPoint - Function mapping index to field evaluation point (default: consecutive integers)
   * @returns Map of index -> recovered value
   */
  recoverMissing(
    available: Map<number, number>,
    missing: number[],
    evaluationPoint: (idx: number) => number = (idx) => idx
  ): Map<number, number> {
    // Build points from available data
    const points: Point[] = [];
    for (const [idx, value] of available) {
      points.push({ x: evaluationPoint(idx), y: value });
    }

    // Precompute denominators for efficiency
    const xs = points.map((p) => p.x);
    const ys = points.map((p) => p.y);
    const denominators = this.computeDenominators(xs);

    // Recover each missing value
    const recovered = new Map<number, number>();
    for (const idx of missing) {
      const targetX = evaluationPoint(idx);
      const value = this.interpolateWithDenominators(xs, ys, denominators, targetX);
      recovered.set(idx, value);
    }

    return recovered;
  }
}

/**
 * Create a Lagrange interpolator for the given field
 */
export function createLagrangeInterpolator(field: GaloisField): LagrangeInterpolator {
  return new LagrangeInterpolator(field);
}

/**
 * Convenience function: interpolate polynomial value at a target point
 *
 * @param points - Array of (x, y) points
 * @param targetX - X-coordinate to evaluate at
 * @param field - Galois field for arithmetic
 * @returns f(targetX)
 */
export function interpolateAt(points: Point[], targetX: number, field: GaloisField): number {
  const interpolator = new LagrangeInterpolator(field);
  return interpolator.interpolate(points, targetX);
}

/**
 * Recover missing shards using Lagrange interpolation
 *
 * This is the main entry point for Reed-Solomon erasure recovery.
 * Given available shards and their indices, reconstructs the values
 * at missing indices.
 *
 * @param availableShards - Map of shard index -> shard data (as Uint8Array)
 * @param missingIndices - Indices of missing shards
 * @param k - Number of data shards (minimum needed for reconstruction)
 * @param field - Galois field for arithmetic
 * @returns Map of missing index -> recovered shard data
 * @throws Error if fewer than k shards available
 */
export function recoverMissingShards(
  availableShards: Map<number, Uint8Array>,
  missingIndices: number[],
  k: number,
  field: GaloisField
): Map<number, Uint8Array> {
  // Validate we have enough shards
  if (availableShards.size < k) {
    throw new Error(`Insufficient shards for recovery: ${availableShards.size} < ${k}`);
  }

  // Determine shard size from first available shard
  const firstShard = availableShards.values().next().value;
  if (!firstShard) {
    throw new Error('No shards available');
  }
  const shardSize = firstShard.length;

  // Create interpolator
  const interpolator = new LagrangeInterpolator(field);

  // The reference implementation uses consecutive integers as evaluation points (not α^i)
  // Use the deterministic evaluation points defined by the codec.
  const evalPoint = (idx: number) => idx;

  // Build x-coordinates and precompute denominators once
  const availableIndices = Array.from(availableShards.keys()).slice(0, k);
  const xs = availableIndices.map(evalPoint);
  const denominators = interpolator.computeDenominators(xs);

  // Recover each missing shard
  const recovered = new Map<number, Uint8Array>();

  for (const missingIdx of missingIndices) {
    const recoveredShard = new Uint8Array(shardSize);

    // For each byte position in the shard
    for (let pos = 0; pos < shardSize; pos++) {
      // Collect y values at this position from available shards
      const ys = availableIndices.map((idx) => {
        const shard = availableShards.get(idx);
        if (!shard) {
          throw new Error(`Shard at index ${idx} not found in available shards`);
        }
        if (pos >= shard.length) {
          throw new Error(
            `Position ${pos} out of bounds for shard at index ${idx} (length: ${shard.length})`
          );
        }
        return shard[pos];
      });

      // Interpolate to find the missing value
      const targetX = evalPoint(missingIdx);
      const value = interpolator.interpolateWithDenominators(xs, ys, denominators, targetX);

      recoveredShard[pos] = value;
    }

    recovered.set(missingIdx, recoveredShard);
  }

  return recovered;
}
