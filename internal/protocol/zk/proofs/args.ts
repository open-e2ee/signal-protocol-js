/**
 * Type-safe argument containers for ZK proof statements
 *
 *
 * ScalarArgs and PointArgs are string-keyed maps for named scalars/points
 * used when instantiating a Statement with concrete values.
 */

import type { RistrettoPoint } from './sho';

/**
 * Named scalar arguments for proof generation.
 * Maps variable names (e.g., "a", "private_key") to scalar values.
 */
export {};
export class ScalarArgs {
  readonly map: Map<string, bigint>;

  constructor() {
    this.map = new Map();
  }

  add(name: string, value: bigint): void {
    this.map.set(name, value);
  }

  get(name: string): bigint | undefined {
    return this.map.get(name);
  }

  get size(): number {
    return this.map.size;
  }
}

/**
 * Named point arguments for proof generation/verification.
 * Maps variable names (e.g., "A", "public_key") to Ristretto points.
 * Note: "G" (base point) is implicit and should NOT be included.
 */
export class PointArgs {
  readonly map: Map<string, RistrettoPoint>;

  constructor() {
    this.map = new Map();
  }

  add(name: string, value: RistrettoPoint): void {
    this.map.set(name, value);
  }

  get(name: string): RistrettoPoint | undefined {
    return this.map.get(name);
  }

  get size(): number {
    return this.map.size;
  }
}
