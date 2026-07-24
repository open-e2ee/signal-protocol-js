/**
 * GF(2^16) Galois Field for Reed-Solomon Erasure Coding
 *
 * Provides GF(2^16) arithmetic for interleaved Reed-Solomon encoding.
 * Used by PolyEncoder/PolyDecoder in ML-KEM Braid.
 *
 * Tables (384KB) load eagerly on module import via dynamic import.
 *
 * @remarks Bounds checking is enabled in development mode (__DEV__) only.
 *
 * @module rs/galois/field
 * @see https://signal.org/docs/specifications/mlkembraid/ (Section 4)
 *
 * ## GF(2^16) Properties
 *
 * - Elements: 65,536
 * - Max shards: 65,535
 * - Table size: 384 KB
 * - Blocking resistance: >99.9% packet blocking required for attack
 */

// React Native development mode flag (tree-shaken in production)
export {};
declare const __DEV__: boolean;

/**
 * Galois Field interface for finite field arithmetic
 *
 * All operations are defined over GF(2^16).
 * Elements are represented as integers in [0, 65535].
 */
export interface GaloisField {
  /** Field size: 65536 for GF(2^16) */
  readonly size: number;

  /** Field bits: 16 */
  readonly fieldBits: 16;

  /**
   * Multiply two field elements
   * @param x - First operand [0, size-1]
   * @param y - Second operand [0, size-1]
   * @returns x * y in the field
   */
  mul(x: number, y: number): number;

  /**
   * Divide two field elements
   * @param x - Dividend [0, size-1]
   * @param y - Divisor [1, size-1] (non-zero)
   * @returns x / y in the field
   * @throws Error if y is zero
   */
  div(x: number, y: number): number;

  /**
   * Add two field elements
   *
   * In GF(2^n), addition is XOR. This method provides semantic consistency
   * across all field operations instead of using raw XOR directly.
   *
   * @param x - First operand [0, size-1]
   * @param y - Second operand [0, size-1]
   * @returns x + y in the field (equivalent to x XOR y)
   */
  add(x: number, y: number): number;

  /**
   * Exponentiation table lookup
   * @param i - Exponent index
   * @returns alpha^i where alpha is the primitive element
   */
  exp(i: number): number;

  /**
   * Logarithm table lookup
   * @param x - Field element [1, size-1] (non-zero)
   * @returns i such that alpha^i = x
   */
  log(x: number): number;

  /**
   * Get field mask (size - 1)
   * Used for modular arithmetic
   */
  mask(): number;
}

// ============================================================================
// GF(2^16) Implementation
// ============================================================================

/**
 * GF(2^16) field generator polynomial: x^16 + x^12 + x^3 + x + 1
 * This is commonly used in Reed-Solomon implementations.
 * Binary representation: 0x1100B (with x^16 bit) or 0x100B (reduction polynomial)
 */
export const GF16_GENERATOR = 0x100b;

/**
 * GF(2^16) field size
 */
export const GF16_SIZE = 65536;

/**
 * GF(2^16) Implementation
 *
 * Uses pre-computed exp/log tables for O(1) multiplication and division.
 * Tables are ~384KB and loaded eagerly via dynamic import.
 */
class GaloisField16 implements GaloisField {
  readonly size = GF16_SIZE;
  readonly fieldBits = 16 as const;

  constructor(
    private readonly expTable: Uint16Array,
    private readonly logTable: Uint16Array
  ) {}

  mask(): number {
    return this.size - 1;
  }

  exp(i: number): number {
    if (__DEV__ && (i < 0 || i >= this.expTable.length)) {
      throw new Error(`GF(2^16) exp index out of bounds: ${i}`);
    }
    return this.expTable[i];
  }

  log(x: number): number {
    if (__DEV__ && (x <= 0 || x >= this.size)) {
      throw new Error(`GF(2^16) log argument out of bounds: ${x} (must be 1-65535)`);
    }
    return this.logTable[x];
  }

  mul(x: number, y: number): number {
    if (x === 0 || y === 0) return 0;
    // exp(log(x) + log(y)) with implicit modulo via doubled table
    return this.expTable[this.logTable[x] + this.logTable[y]];
  }

  div(x: number, y: number): number {
    if (y === 0) throw new Error('Division by zero in GF(2^16)');
    // These table indices and branches depend only on public erasure-coded
    // transcript bytes. JavaScript/JIT execution is variable-time; no
    // confidentiality claim relies on this selection pattern.
    const safeX = x === 0 ? 1 : x; // Use 1 as placeholder to avoid invalid lookup
    const computedResult = this.expTable[this.logTable[safeX] + 65535 - this.logTable[y]];
    // Return the public zero case without claiming constant-time selection.
    return x === 0 ? 0 : computedResult;
  }

  add(x: number, y: number): number {
    // In GF(2^n), addition is XOR
    return x ^ y;
  }
}

// ============================================================================
// Factory Functions
// ============================================================================

// Singleton instance (set when loading completes)
let gf16Instance: GaloisField | null = null;

// Start loading immediately when module is imported.
// Dynamic import keeps tables out of the main bundle while still loading eagerly.
const gf16LoadingPromise: Promise<GaloisField> = (async () => {
  const { EXP_TABLE, LOG_TABLE } = await import('./tables-16');
  gf16Instance = new GaloisField16(EXP_TABLE, LOG_TABLE);
  return gf16Instance;
})();

/**
 * Get GF(2^16) field instance
 *
 * Tables load eagerly when the module is imported. This function returns
 * the loading promise, which resolves immediately if tables are already loaded.
 *
 * @returns Promise resolving to GF(2^16) field instance
 */
export async function createGF16(): Promise<GaloisField> {
  return gf16LoadingPromise;
}

/**
 * Check if GF(2^16) tables are loaded
 *
 * Useful for determining if encode/decode will be sync or async.
 */
export function isGF16Loaded(): boolean {
  return gf16Instance !== null;
}

/**
 * Get GF(2^16) field synchronously (if already loaded)
 *
 * @returns GF(2^16) field instance or null if not yet loaded
 */
export function getGF16Sync(): GaloisField | null {
  return gf16Instance;
}
