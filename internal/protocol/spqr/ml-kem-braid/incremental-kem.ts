/**
 * Incremental ML-KEM Interface
 *
 * Implements the incremental KEM interface required by ML-KEM Braid.
 * Uses forked @noble/post-quantum with split encapsulation.
 *
 * @module ml-kem-braid/incremental-kem
 * @see https://signal.org/docs/specifications/mlkembraid/
 *
 * Status: Implemented via ./noble-pq (internal fork of @noble/post-quantum)
 */

import type { IIncrementalKEM, KeyGenResult, Encaps1Result } from './types';

import { MLKEM_768_SIZES } from './types';
import { IncrementalKEMError } from './errors';
import {
  KeyGen as IncrementalKeyGen,
  Encaps1 as IncrementalEncaps1,
  Encaps2 as IncrementalEncaps2,
  Decaps as IncrementalDecaps,
  computeHek,
} from './noble-pq';

/**
 * Incremental ML-KEM-768 Implementation
 *
 * Splits standard ML-KEM operations into incremental phases for
 * chunked transmission.
 *
 */
export {};
export class IncrementalMLKEM768 implements IIncrementalKEM {
  /** Stored hek for Encaps2 verification */
  private currentHek: Uint8Array | null = null;

  /**
   * Generate key pair with separated components
   *
   * Standard ML-KEM KeyGen produces (dk, ek) where ek is 1184 bytes.
   * Incremental KeyGen splits ek into:
   * - ek_seed: 32 bytes (compressed seed / rho)
   * - ek_vector: 1152 bytes (tHat polynomial vector)
   *
   * @param randomness - 64 bytes of cryptographic randomness (seed)
   * @returns (dk, ek_seed, ek_vector, hek)
   */
  async KeyGen(randomness: Uint8Array): Promise<KeyGenResult> {
    // Validate input - ML-KEM-768 keygen expects 64-byte seed
    if (randomness.length !== 64) {
      throw IncrementalKEMError.invalidSize('randomness', randomness.length, 64);
    }

    const result = IncrementalKeyGen(randomness);

    return {
      dk: result.dk,
      ek_seed: result.ek_seed,
      ek_vector: result.ek_vector,
      hek: result.hek,
    };
  }

  /**
   * Phase 1: Encapsulate using only header (ek_seed + hek)
   *
   * This enables parallel transmission: ct1 can be sent before
   * ek_vector is fully received.
   *
   * @param ek_seed - 32-byte encapsulation key seed (rho)
   * @param hek - SHA3-256(ek_seed || ek_vector), as defined by the ML-KEM
   *   Braid specification, 32 bytes
   * @param randomness - 32 bytes of cryptographic randomness (message)
   * @returns (encaps_secret, ct1, shared_secret)
   */
  async Encaps1(
    ek_seed: Uint8Array,
    hek: Uint8Array,
    randomness: Uint8Array
  ): Promise<Encaps1Result> {
    // Validate inputs
    if (ek_seed.length !== MLKEM_768_SIZES.EK_SEED_SIZE) {
      throw IncrementalKEMError.invalidSize(
        'ek_seed',
        ek_seed.length,
        MLKEM_768_SIZES.EK_SEED_SIZE
      );
    }
    if (hek.length !== 32) {
      throw IncrementalKEMError.invalidSize('hek', hek.length, 32);
    }
    if (randomness.length !== 32) {
      throw IncrementalKEMError.invalidSize('randomness', randomness.length, 32);
    }

    // Store hek for Encaps2
    this.currentHek = hek;

    const result = IncrementalEncaps1(ek_seed, hek, randomness);

    return {
      encaps_secret: result.encaps_secret,
      ct1: result.ct1,
      shared_secret: result.shared_secret,
    };
  }

  /**
   * Phase 2: Complete encapsulation using ek_vector
   *
   * Called after receiving the full ek_vector.
   * Produces ct2 (reconciliation message).
   *
   * @param encaps_secret - Internal state from Encaps1
   * @param ek_seed - 32-byte encapsulation key seed
   * @param ek_vector - 1152-byte encapsulation key vector
   * @returns ct2 reconciliation (128 bytes)
   */
  async Encaps2(
    encaps_secret: Uint8Array,
    ek_seed: Uint8Array,
    ek_vector: Uint8Array
  ): Promise<Uint8Array> {
    // Validate ek_vector
    if (ek_vector.length !== MLKEM_768_SIZES.EK_VECTOR_SIZE) {
      throw IncrementalKEMError.invalidSize(
        'ek_vector',
        ek_vector.length,
        MLKEM_768_SIZES.EK_VECTOR_SIZE
      );
    }
    if (ek_seed.length !== MLKEM_768_SIZES.EK_SEED_SIZE) {
      throw IncrementalKEMError.invalidSize(
        'ek_seed',
        ek_seed.length,
        MLKEM_768_SIZES.EK_SEED_SIZE
      );
    }

    // Get hek for verification (use stored or compute)
    const hek = this.currentHek ?? computeHek(ek_seed, ek_vector);

    const ct2 = IncrementalEncaps2(encaps_secret, ek_seed, ek_vector, hek);

    // Clear cached hek reference after use (defense-in-depth).
    // Note: we only null the reference, not zero the bytes, because the caller
    // may hold the same Uint8Array reference (e.g., reusing hek across rounds).
    this.currentHek = null;

    return ct2;
  }

  /**
   * Decapsulate using ct1 + ct2
   *
   * Standard decapsulation, but with split ciphertext inputs.
   *
   * @param dk - Decapsulation key (2400 bytes)
   * @param ct1 - First ciphertext component (960 bytes)
   * @param ct2 - Second ciphertext component (128 bytes)
   * @returns shared_secret (32 bytes)
   */
  async Decaps(dk: Uint8Array, ct1: Uint8Array, ct2: Uint8Array): Promise<Uint8Array> {
    // Validate inputs
    if (dk.length !== MLKEM_768_SIZES.DK_SIZE) {
      throw IncrementalKEMError.invalidSize('dk', dk.length, MLKEM_768_SIZES.DK_SIZE);
    }
    if (ct1.length !== MLKEM_768_SIZES.CT1_SIZE) {
      throw IncrementalKEMError.invalidSize('ct1', ct1.length, MLKEM_768_SIZES.CT1_SIZE);
    }
    if (ct2.length !== MLKEM_768_SIZES.CT2_SIZE) {
      throw IncrementalKEMError.invalidSize('ct2', ct2.length, MLKEM_768_SIZES.CT2_SIZE);
    }

    return IncrementalDecaps(dk, ct1, ct2);
  }
}

/**
 * Create incremental ML-KEM-768 instance
 *
 * @returns Incremental ML-KEM-768 implementation
 */
export function createIncrementalKEM(): IIncrementalKEM {
  return new IncrementalMLKEM768();
}

/**
 * Re-export computeHek for convenience
 */
export { computeHek };
