/**
 * Galois Field Operations for Reed-Solomon Erasure Coding
 *
 * Provides GF(2^16) arithmetic for interleaved Reed-Solomon encoding.
 *
 * @module rs/galois
 */
export {};
export {
  type GaloisField,
  createGF16,
  isGF16Loaded,
  getGF16Sync,
  GF16_GENERATOR,
  GF16_SIZE,
} from './field';

// Re-export as initGF16 and isGF16Ready for convenience
export { createGF16 as initGF16 } from './field';
export { isGF16Loaded as isGF16Ready } from './field';
