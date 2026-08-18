/** ML-KEM polynomial modulus. */
export const MLKEM_Q = 3329;

/**
 * Reduce an integer modulo q into the canonical [0, q) range.
 *
 * JavaScript `%` has no constant-time contract and remains an accepted timing
 * risk for the pure-JavaScript profile. The sign normalization is branch-free.
 * The result of `% MLKEM_Q` is in [-3328, 3328]. Its signed right shift is
 * therefore exactly 0 or -1, which conditionally adds q without truncating the
 * arithmetic input.
 */
export function reduceModQ(value: number): number {
  const remainder = (value % MLKEM_Q) | 0;
  return (remainder + ((remainder >> 31) & MLKEM_Q)) | 0;
}
