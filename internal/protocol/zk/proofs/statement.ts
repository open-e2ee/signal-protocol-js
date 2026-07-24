/**
 * ZK Statement DSL — Schnorr/Sigma protocol for arbitrary linear relations
 *
 *
 * Implements the "Sigma protocol for arbitrary linear relations" described in
 * section 19.5.3 of Boneh-Shoup's cryptography textbook.
 *
 * Proves knowledge of the preimage of a group homomorphism from G1 → G2,
 * where G1 elements are vectors of scalars and G2 elements are vectors of
 * Ristretto points.
 *
 * Example: A = a*G + b*H (prove knowledge of a,b given A,G,H)
 *
 * @see https://crypto.stanford.edu/~dabo/cryptobook/BonehShoup_0_4.pdf §19.5.3
 */

import { ScalarArgs, PointArgs } from './args';
import { proofFromBytes, proofToBytes } from './proof';
import {
  ShoHmacSha256,
  RistrettoPoint,
  bytesToScalarWide,
  scalarToBytes,
  SCALAR_ORDER,
} from './sho';
import { constantTimeEqual } from '../../../crypto/utils';
export {};
const Point = RistrettoPoint;
const Fn = Point.Fn;

/** Errors that can occur during proof operations */
export enum PokshoError {
  BadArgs = 'BadArgs',
  BadArgsWrongNumberOfScalarArgs = 'BadArgsWrongNumberOfScalarArgs',
  BadArgsWrongNumberOfPointArgs = 'BadArgsWrongNumberOfPointArgs',
  BadArgsMissingScalarArg = 'BadArgsMissingScalarArg',
  BadArgsMissingPointArg = 'BadArgsMissingPointArg',
  VerificationFailure = 'VerificationFailure',
  ProofCreationVerificationFailure = 'ProofCreationVerificationFailure',
}

export class PokshoException extends Error {
  constructor(public readonly code: PokshoError) {
    super(code);
    this.name = 'PokshoException';
  }
}

type ScalarIndex = number; // u8
type PointIndex = number; // u8

interface Term {
  scalar: ScalarIndex;
  point: PointIndex;
}

interface Equation {
  lhs: PointIndex;
  rhs: Term[];
}

/**
 * A ZK proof statement: a system of linear equations over scalars and points.
 *
 * Usage:
 *   const st = new Statement();
 *   st.add("A", [["a", "G"], ["b", "H"]]);  // A = a*G + b*H
 *   const proof = st.prove(scalarArgs, pointArgs, message, randomness);
 *   st.verifyProof(proof, pointArgs, message);
 */
export class Statement {
  private equations: Equation[] = [];
  private scalarMap: Map<string, ScalarIndex> = new Map();
  private scalarVec: string[] = [];
  private pointMap: Map<string, PointIndex> = new Map();
  private pointVec: string[] = [];

  constructor() {
    // "G" is pre-assigned to index 0 (base point)
    this.pointMap.set('G', 0);
    this.pointVec.push('G');
  }

  /**
   * Add an equation: lhs = sum(scalar_i * point_i)
   * @param lhs Name of the left-hand-side point variable
   * @param rhsPairs Array of [scalarName, pointName] pairs
   */
  add(lhs: string, rhsPairs: [string, string][]): void {
    if (!lhs || !rhsPairs.length || rhsPairs.length > 255 || this.equations.length >= 255) {
      throw new PokshoException(PokshoError.BadArgs);
    }

    const lhsIdx = this.addPoint(lhs);
    const rhs: Term[] = [];

    for (const [scalarName, pointName] of rhsPairs) {
      if (!scalarName || !pointName) {
        throw new PokshoException(PokshoError.BadArgs);
      }
      rhs.push({
        scalar: this.addScalar(scalarName),
        point: this.addPoint(pointName),
      });
    }

    this.equations.push({ lhs: lhsIdx, rhs });
  }

  /**
   * Generate a ZK proof.
   *
   * @param scalarArgs Named scalar values (the witness / secret)
   * @param pointArgs Named point values (public, excluding "G")
   * @param message Message to bind to the proof
   * @param randomness 32 bytes of randomness for synthetic nonce generation
   */
  prove(
    scalarArgs: ScalarArgs,
    pointArgs: PointArgs,
    message: Uint8Array,
    randomness: Uint8Array
  ): Uint8Array {
    if (randomness.length !== 32) {
      throw new PokshoException(PokshoError.BadArgs);
    }

    const g1 = this.sortScalars(scalarArgs);
    const allPoints = this.sortPoints(pointArgs);

    // Absorb protocol label L, statement description D, and point values A
    const sho = new ShoHmacSha256(PROTOCOL_LABEL);
    sho.absorb(this.toBytes()); // D
    for (const point of allPoints) {
      sho.absorb(point.toBytes()); // A
    }
    sho.ratchet();

    // Synthetic nonce: hash randomness + witness + message
    const sho2 = sho.clone();
    sho2.absorb(randomness); // Z
    for (const scalar of g1) {
      sho2.absorb(scalarToBytes(scalar)); // a (witness)
    }
    sho2.ratchet();
    sho2.absorbAndRatchet(message); // M
    const blindingScalarBytes = sho2.squeezeAndRatchet(g1.length * 64);

    // Parse blinding scalars (nonces)
    const nonce: bigint[] = [];
    for (let i = 0; i < g1.length; i++) {
      nonce.push(bytesToScalarWide(blindingScalarBytes.subarray(i * 64, (i + 1) * 64)));
    }

    // Commitment: apply homomorphism F(nonce) → G2
    const commitment = this.homomorphismWithSubtraction(nonce, allPoints, null);

    // Challenge: hash commitment + message
    for (const point of commitment) {
      sho.absorb(point.toBytes()); // R
    }
    sho.absorbAndRatchet(message); // M
    const challengeBytes = sho.squeezeAndRatchet(64);
    const challenge = bytesToScalarWide(challengeBytes);

    // Response: r_i = nonce_i + g1_i * challenge
    const response = nonce.map((n, i) => Fn.create(n + g1[i] * challenge));

    const proofBytes = proofToBytes({ challenge, response });

    // Verify before returning (safety check against faulty computation)
    try {
      this.verifyProof(proofBytes, pointArgs, message);
    } catch (e) {
      if (e instanceof PokshoException && e.code === PokshoError.VerificationFailure) {
        throw new PokshoException(PokshoError.ProofCreationVerificationFailure);
      }
      throw e;
    }

    return proofBytes;
  }

  /**
   * Verify a ZK proof.
   *
   * @param proofBytes Serialized proof bytes
   * @param pointArgs Named point values (public, excluding "G")
   * @param message Message bound to the proof
   */
  verifyProof(proofBytes: Uint8Array, pointArgs: PointArgs, message: Uint8Array): void {
    const proof = proofFromBytes(proofBytes);
    if (!proof) {
      throw new PokshoException(PokshoError.VerificationFailure);
    }
    if (proof.response.length !== this.scalarVec.length) {
      throw new PokshoException(PokshoError.VerificationFailure);
    }

    const allPoints = this.sortPoints(pointArgs);

    // Absorb protocol label L, statement description D, and point values A
    const sho = new ShoHmacSha256(PROTOCOL_LABEL);
    sho.absorb(this.toBytes()); // D
    for (const point of allPoints) {
      sho.absorb(point.toBytes()); // A
    }
    sho.ratchet();

    // Reconstruct commitment: R = F(response) - challenge * A
    const commitment = this.homomorphismWithSubtraction(proof.response, allPoints, proof.challenge);

    // Reconstruct challenge
    for (const point of commitment) {
      sho.absorb(point.toBytes()); // R
    }
    sho.absorbAndRatchet(message); // M
    const challengeBytes = sho.squeezeAndRatchet(64);
    const expectedChallenge = bytesToScalarWide(challengeBytes);

    // Compare canonical scalar encodings without a source-level early exit.
    if (!constantTimeEqual(scalarToBytes(expectedChallenge), scalarToBytes(proof.challenge))) {
      throw new PokshoException(PokshoError.VerificationFailure);
    }
  }

  /**
   * Serialize the statement description to bytes.
   * Format:
   *   Ne (1 byte) — number of equations
   *   for each equation:
   *     lhs_point_index (1 byte)
   *     Nt (1 byte) — number of terms
   *     for each term:
   *       scalar_index (1 byte)
   *       point_index (1 byte)
   */
  toBytes(): Uint8Array {
    const parts: number[] = [this.equations.length];
    for (const { lhs, rhs } of this.equations) {
      parts.push(lhs);
      parts.push(rhs.length);
      for (const { scalar, point } of rhs) {
        parts.push(scalar);
        parts.push(point);
      }
    }
    return new Uint8Array(parts);
  }

  // --- Private helpers ---

  private addScalar(name: string): ScalarIndex {
    const existing = this.scalarMap.get(name);
    if (existing !== undefined) return existing;
    const idx = this.scalarVec.length;
    if (idx > 255) throw new PokshoException(PokshoError.BadArgs);
    this.scalarMap.set(name, idx);
    this.scalarVec.push(name);
    return idx;
  }

  private addPoint(name: string): PointIndex {
    const existing = this.pointMap.get(name);
    if (existing !== undefined) return existing;
    const idx = this.pointVec.length;
    if (idx > 255) throw new PokshoException(PokshoError.BadArgs);
    this.pointMap.set(name, idx);
    this.pointVec.push(name);
    return idx;
  }

  /**
   * Sort scalar args into the order defined by the statement.
   */
  private sortScalars(scalarArgs: ScalarArgs): bigint[] {
    if (scalarArgs.size !== this.scalarVec.length) {
      throw new PokshoException(PokshoError.BadArgsWrongNumberOfScalarArgs);
    }
    return this.scalarVec.map((name) => {
      const val = scalarArgs.get(name);
      if (val === undefined) {
        throw new PokshoException(PokshoError.BadArgsMissingScalarArg);
      }
      return val;
    });
  }

  /**
   * Sort point args into the order defined by the statement.
   * Index 0 = BASE (implicit), then user-provided points.
   */
  private sortPoints(pointArgs: PointArgs): RistrettoPoint[] {
    if (pointArgs.size !== this.pointVec.length - 1) {
      throw new PokshoException(PokshoError.BadArgsWrongNumberOfPointArgs);
    }
    const allPoints: RistrettoPoint[] = [Point.BASE]; // index 0 = G
    for (let i = 1; i < this.pointVec.length; i++) {
      const val = pointArgs.get(this.pointVec[i]);
      if (!val) {
        throw new PokshoException(PokshoError.BadArgsMissingPointArg);
      }
      allPoints.push(val);
    }
    return allPoints;
  }

  /**
   * Apply the group homomorphism F: G1 → G2
   * For each equation: result = sum(scalar[i] * point[i]) - challenge * lhs_point
   *
   * If challenge is null, just computes F(scalars).
   * If challenge is provided, computes F(scalars) - challenge * lhs (for verification).
   */
  private homomorphismWithSubtraction(
    g1: bigint[],
    allPoints: RistrettoPoint[],
    challenge: bigint | null
  ): RistrettoPoint[] {
    return this.equations.map((eq) => {
      // Compute sum of scalar * point for each term in RHS
      let result = Point.ZERO;
      for (const term of eq.rhs) {
        result = result.add(allPoints[term.point].multiply(g1[term.scalar]));
      }

      // Subtract challenge * lhs_point if verifying
      if (challenge !== null) {
        const negChallenge = Fn.create(SCALAR_ORDER - challenge);
        result = result.add(allPoints[eq.lhs].multiply(negChallenge));
      }

      return result;
    });
  }
}

/** Protocol label for the SHO */
const PROTOCOL_LABEL = new TextEncoder().encode('POKSHO_Ristretto_SHOHMACSHA256');
