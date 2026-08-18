/**
 * Group Send Endorsements -- lightweight alternative to credentials
 *
 *
 * An endorsement can be used instead of a full credential when two conditions
 * hold. No attributes are hidden from the verifying server, and exactly one
 * attribute point is hidden from the issuing server.
 *
 * Endorsement issuance uses the same homogeneous elliptic-curve-based
 * encryption as the full credential system. Verification is much cheaper, and
 * the tokens generated from endorsements can be reused for multiple requests.
 *
 * At a high level:
 *   1. Client and server agree on "tag info" (public attributes) -> derived key
 *   2. Server issues endorsements for hidden attribute points + batch proof
 *   3. Client receives response, validates proof, extracts endorsements
 *   4. Client may combine/remove endorsements (set operations)
 *   5. Client generates a token by unblinding + hashing
 *   6. Verifying server recreates token from revealed attributes and checks match
 *
 * @see https://eprint.iacr.org/2021/864 -- 3HashSDHI
 * @see https://privacypass.github.io -- PrivacyPass
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { ShoHmacSha256, RistrettoPoint } from '../proofs/sho';
import { Statement } from '../proofs/statement';
import { ScalarArgs, PointArgs } from '../proofs/args';
import { RANDOMNESS_LEN } from './credentials';
import { VerificationFailure } from './issuance';
import { constantTimeEqual } from '../../../crypto/utils';
export {};
const Point = RistrettoPoint;
const Fn = Point.Fn;

const enc = new TextEncoder();

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Token length in bytes -- enough randomness to prevent guessing. */
const TOKEN_LEN = 16;

/** Small scalar size for batch proof weights (< 2^127 for faster multiply). */
const SMALL_SCALAR_BYTES = 16;

// ---------------------------------------------------------------------------
// ServerRootKeyPair
// ---------------------------------------------------------------------------

/**
 * A server's root secret key for issuing and verifying endorsements.
 *
 * Endorsements are not issued directly with this key. Instead, the server
 * derives a {@link ServerDerivedKeyPair} for domain separation, rotation,
 * and additional authenticated info.
 */
export class ServerRootKeyPair {
  readonly sk: bigint;
  readonly public: ServerRootPublicKey;

  private constructor(sk: bigint) {
    this.sk = sk;
    this.public = new ServerRootPublicKey(Point.BASE.multiply(sk));
  }

  /**
   * Derives a root key by hashing `randomness`.
   */
  static generate(randomness: Uint8Array): ServerRootKeyPair {
    if (randomness.length < RANDOMNESS_LEN) {
      throw new Error(`ServerRootKeyPair.generate: need ${RANDOMNESS_LEN} bytes of randomness`);
    }
    const sho = new ShoHmacSha256(
      enc.encode('Signal_ZKCredential_Endorsements_ServerRootKeyPair_generate_20240207')
    );
    sho.absorbAndRatchet(randomness);
    return new ServerRootKeyPair(sho.getScalar());
  }

  /**
   * Construct from an existing secret scalar.
   */
  static fromRaw(sk: bigint): ServerRootKeyPair {
    return new ServerRootKeyPair(sk);
  }

  /**
   * Returns the corresponding public key.
   */
  publicKey(): ServerRootPublicKey {
    return this.public;
  }

  /**
   * Derives a specific key for issuing endorsements.
   *
   * The `tagInfoSho` should have already absorbed domain separation and
   * any "public attributes" specific to the endorsements it issues.
   */
  deriveKey(tagInfoSho: ShoHmacSha256): ServerDerivedKeyPair {
    const t = tagInfoSho.getScalar();
    const skPrime = Fn.inv(Fn.create(this.sk + t));
    const publicKey = this.public.deriveKeyFromTagScalar(t);
    return new ServerDerivedKeyPair(skPrime, publicKey);
  }
}

// ---------------------------------------------------------------------------
// ServerRootPublicKey
// ---------------------------------------------------------------------------

/**
 * The public counterpart of {@link ServerRootKeyPair}.
 *
 * Verify issuance with a {@link ServerDerivedPublicKey}.
 */
export class ServerRootPublicKey {
  readonly PK: RistrettoPoint;

  constructor(PK: RistrettoPoint) {
    this.PK = PK;
  }

  /**
   * Construct from an existing point (expected to be sk * G).
   */
  static fromRaw(PK: RistrettoPoint): ServerRootPublicKey {
    return new ServerRootPublicKey(PK);
  }

  /**
   * Derives a specific public key for endorsement verification.
   *
   * The `tagInfoSho` must match what the server used in
   * {@link ServerRootKeyPair.deriveKey}.
   */
  deriveKey(tagInfoSho: ShoHmacSha256): ServerDerivedPublicKey {
    const t = tagInfoSho.getScalar();
    return this.deriveKeyFromTagScalar(t);
  }

  /** @internal */
  deriveKeyFromTagScalar(t: bigint): ServerDerivedPublicKey {
    const PK_prime = this.PK.add(Point.BASE.multiply(t));
    return new ServerDerivedPublicKey(PK_prime);
  }
}

// ---------------------------------------------------------------------------
// ServerDerivedKeyPair
// ---------------------------------------------------------------------------

/**
 * A specific secret key pair for issuing and verifying endorsements.
 *
 * Derived from a {@link ServerRootKeyPair} via
 * {@link ServerRootKeyPair.deriveKey}.
 */
export class ServerDerivedKeyPair {
  readonly skPrime: bigint;
  readonly public: ServerDerivedPublicKey;

  constructor(skPrime: bigint, pub: ServerDerivedPublicKey) {
    this.skPrime = skPrime;
    this.public = pub;
  }

  /**
   * Verifies that a token is valid for `point` according to this key.
   *
   * Throws {@link VerificationFailure} on mismatch.
   */
  verify(point: RistrettoPoint, token: Uint8Array): void {
    const P = point.multiply(this.skPrime);
    const expected = tokenRaw(P);
    if (!constantTimeEqual(token, expected)) {
      throw new VerificationFailure();
    }
  }
}

// ---------------------------------------------------------------------------
// ServerDerivedPublicKey
// ---------------------------------------------------------------------------

/**
 * The public counterpart of {@link ServerDerivedKeyPair}.
 *
 * Derived from a {@link ServerRootPublicKey}.
 */
export class ServerDerivedPublicKey {
  readonly PK_prime: RistrettoPoint;

  constructor(PK_prime: RistrettoPoint) {
    this.PK_prime = PK_prime;
  }
}

// ---------------------------------------------------------------------------
// ClientDecryptionKey
// ---------------------------------------------------------------------------

/**
 * A key used to transform endorsements of encrypted/blinded values
 * to endorsements of the original plaintext values.
 */
export class ClientDecryptionKey {
  readonly aInv: bigint;

  private constructor(aInv: bigint) {
    this.aInv = aInv;
  }

  /**
   * Produces a decryption key from a scalar used to blind arbitrary points.
   *
   * This is essentially `scalar.invert()`.
   */
  static fromBlindingScalar(scalar: bigint): ClientDecryptionKey {
    return new ClientDecryptionKey(Fn.inv(scalar));
  }

  /**
   * Produces a decryption key from the first scalar (a1) of an attribute keypair.
   *
   * Appropriate for endorsements issued on the **first points** of encrypted
   * attributes.
   */
  static forFirstPointOfAttribute(keyPairA1: bigint): ClientDecryptionKey {
    return ClientDecryptionKey.fromBlindingScalar(keyPairA1);
  }
}

// ---------------------------------------------------------------------------
// EndorsementResponse
// ---------------------------------------------------------------------------

/**
 * A set of endorsements issued by a server, along with a batch proof of
 * their validity.
 */
export class EndorsementResponse {
  /** Compressed endorsement points (32 bytes each). */
  readonly R: Uint8Array[];
  /** The Schnorr batch proof bytes. */
  readonly proof: Uint8Array;

  constructor(R: Uint8Array[], proof: Uint8Array) {
    this.R = R;
    this.proof = proof;
  }

  /**
   * Issues an endorsement for every point in `hiddenAttributePoints`,
   * along with a batch proof of validity.
   *
   * The order of the points matters. The endorsements eventually received
   * by the client will be in the same order.
   */
  static issue(
    hiddenAttributePoints: RistrettoPoint[],
    privateKey: ServerDerivedKeyPair,
    randomness: Uint8Array
  ): EndorsementResponse {
    if (randomness.length < RANDOMNESS_LEN) {
      throw new Error(`EndorsementResponse.issue: need ${RANDOMNESS_LEN} bytes of randomness`);
    }

    const E = hiddenAttributePoints;
    // R_i = sk_prime * E_i
    const RPoints = E.map((Ei) => Ei.multiply(privateKey.skPrime));
    const RCompressed = RPoints.map((r) => r.toBytes());

    const weightsForProof = generateWeightsForProof(privateKey.public, E, RCompressed);

    // weighted_sum(E) = E[0] + sum(weights[i] * E[i+1])
    const sumE = weightedSum(E, weightsForProof);
    // weighted_sum(R) = sk_prime * weighted_sum(E)
    const sumR = sumE.multiply(privateKey.skPrime);

    const statement = proofStatement();
    const pointArgs = new PointArgs();
    pointArgs.add('weighted_sum(E)', sumE);
    pointArgs.add('weighted_sum(R)', sumR);
    pointArgs.add('PK_prime', privateKey.public.PK_prime);
    const scalarArgs = new ScalarArgs();
    scalarArgs.add('sk_prime', privateKey.skPrime);

    const proof = statement.prove(scalarArgs, pointArgs, new Uint8Array(0), randomness);

    return new EndorsementResponse(RCompressed, proof);
  }

  /**
   * Validates and retrieves the endorsements stored in this response.
   *
   * `hiddenAttributePoints` should be the same points seen by the issuing
   * server (blinded/encrypted), in the same order.
   *
   * Throws {@link VerificationFailure} if the proof fails to validate or
   * if the number of points does not match the number of endorsements.
   */
  receive(
    hiddenAttributePoints: RistrettoPoint[],
    serverPublicKey: ServerDerivedPublicKey
  ): ReceivedEndorsements {
    if (hiddenAttributePoints.length !== this.R.length) {
      throw new VerificationFailure();
    }

    const E = hiddenAttributePoints;

    const weightsForProof = generateWeightsForProof(serverPublicKey, E, this.R);

    // Decompress R points, substituting ZERO on failure so proof will fail
    const RPoints = this.R.map((compressed) => {
      try {
        return Point.fromBytes(compressed);
      } catch {
        return Point.ZERO;
      }
    });

    // Compute weighted sums (vartime is acceptable on client side)
    const sumR = weightedSum(RPoints, weightsForProof);
    const sumE = weightedSum(E, weightsForProof);

    const statement = proofStatement();
    const pointArgs = new PointArgs();
    pointArgs.add('weighted_sum(E)', sumE);
    pointArgs.add('weighted_sum(R)', sumR);
    pointArgs.add('PK_prime', serverPublicKey.PK_prime);

    try {
      statement.verifyProof(this.proof, pointArgs, new Uint8Array(0));
    } catch {
      throw new VerificationFailure();
    }

    const endorsements = RPoints.map((Ri) => new Endorsement(Ri));
    const compressedEndorsements = this.R.map(
      (compressed) => new CompressedEndorsement(compressed)
    );

    return {
      decompressed: endorsements,
      compressed: compressedEndorsements,
    };
  }

  /**
   * Serialize to bytes: [count(u32 LE)] [R_0..R_n (32 each)] [proof]
   */
  toBytes(): Uint8Array {
    const count = this.R.length;
    const proofLen = this.proof.length;
    const buf = new Uint8Array(4 + count * 32 + proofLen);
    const view = new DataView(buf.buffer);
    view.setUint32(0, count, true);
    for (let i = 0; i < count; i++) {
      buf.set(this.R[i], 4 + i * 32);
    }
    buf.set(this.proof, 4 + count * 32);
    return buf;
  }

  /**
   * Deserialize from bytes.
   */
  static fromBytes(bytes: Uint8Array): EndorsementResponse {
    if (bytes.length < 4) {
      throw new Error('EndorsementResponse.fromBytes: too short');
    }
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const count = view.getUint32(0, true);
    const expectedMinLen = 4 + count * 32;
    if (bytes.length < expectedMinLen) {
      throw new Error('EndorsementResponse.fromBytes: truncated');
    }
    const R: Uint8Array[] = [];
    for (let i = 0; i < count; i++) {
      R.push(bytes.slice(4 + i * 32, 4 + (i + 1) * 32));
    }
    const proof = bytes.slice(expectedMinLen);
    return new EndorsementResponse(R, proof);
  }
}

// ---------------------------------------------------------------------------
// Endorsement
// ---------------------------------------------------------------------------

/**
 * Compressed endorsement -- for storage/serialization only.
 *
 * Holds the endorsement point as compressed bytes (32 bytes).
 * Call {@link decompress} to get an {@link Endorsement} for
 * combine/remove/toToken operations.
 */
export class CompressedEndorsement {
  readonly R: Uint8Array;

  constructor(R: Uint8Array) {
    this.R = R;
  }

  /**
   * Decompress to an {@link Endorsement} for algebraic operations.
   * Throws {@link VerificationFailure} on invalid bytes.
   */
  decompress(): Endorsement {
    try {
      return new Endorsement(Point.fromBytes(this.R));
    } catch {
      throw new VerificationFailure();
    }
  }
}

/**
 * Decompressed endorsement -- supports combine/remove/toToken.
 *
 * Holds the endorsement point as a live RistrettoPoint.
 * No unsafe casts -- all algebraic operations are type-safe.
 */
export class Endorsement {
  readonly R: RistrettoPoint;

  constructor(R: RistrettoPoint) {
    this.R = R;
  }

  /**
   * Combines several endorsements into one.
   *
   * All endorsements must have been signed with the same server key,
   * and they must be for points hidden with the same client key.
   *
   * This is a set-like operation: order does not matter.
   */
  static combine(endorsements: Endorsement[]): Endorsement {
    let sum = Point.ZERO;
    for (const e of endorsements) {
      sum = sum.add(e.R);
    }
    return new Endorsement(sum);
  }

  /**
   * Combines this endorsement with another.
   */
  combineWith(other: Endorsement): Endorsement {
    return new Endorsement(this.R.add(other.R));
  }

  /**
   * Creates an endorsement with `other` removed from `self`.
   *
   * This is useful when `self` represents a combined endorsement and
   * you want to remove some attributes from the set.
   */
  remove(other: Endorsement): Endorsement {
    return new Endorsement(this.R.subtract(other.R));
  }

  /**
   * Generates a token from this endorsement, for sending to the verifying
   * server.
   *
   * The client key is used to unblind the endorsement before hashing.
   */
  toToken(clientKey: ClientDecryptionKey): Uint8Array {
    const P = this.R.multiply(clientKey.aInv);
    return tokenRaw(P);
  }

  /**
   * Compress this endorsement for storage.
   */
  compress(): CompressedEndorsement {
    return new CompressedEndorsement(this.R.toBytes());
  }

  /**
   * Returns the default (identity) endorsement, which is the neutral
   * element for combine/remove operations.
   */
  static identity(): Endorsement {
    return new Endorsement(Point.ZERO);
  }
}

// ---------------------------------------------------------------------------
// ReceivedEndorsements
// ---------------------------------------------------------------------------

/**
 * Endorsements extracted from an {@link EndorsementResponse}.
 *
 * The `receive` process works with endorsements in both compressed and
 * decompressed forms, so it provides both to the caller.
 */
export interface ReceivedEndorsements {
  /** Decompressed endorsements -- support further operations (combine, toToken). */
  decompressed: Endorsement[];
  /** Compressed endorsements -- appropriate for serialization/storage. */
  compressed: CompressedEndorsement[];
}

// ---------------------------------------------------------------------------
// Proof statement for batch verification
// ---------------------------------------------------------------------------

/**
 * The ZK statement for endorsement batch verification:
 *
 *   weighted_sum(R) = sk_prime * weighted_sum(E)
 *   G = sk_prime * PK_prime
 *
 * "G" is implicit at index 0 in the Statement constructor, so the second
 * equation has lhsIdx = 0 and "G" is NOT added to PointArgs.
 */
function proofStatement(): Statement {
  const st = new Statement();
  st.add('weighted_sum(R)', [['sk_prime', 'weighted_sum(E)']]);
  st.add('G', [['sk_prime', 'PK_prime']]);
  return st;
}

// ---------------------------------------------------------------------------
// Weight generation for batch proof
// ---------------------------------------------------------------------------

/**
 * Generate weights for the random-linear-combination batch proof.
 *
 * Uses the "RME+" approach. The first weight is implicitly 1 and is not
 * generated. The remaining N-1 weights are 16-byte scalars with bit 127
 * cleared, which keeps them below 2^127 for efficiency.
 *
 * The weights are derived by hashing PK_prime, doubled E points, and R points.
 */
function generateWeightsForProof(
  publicKey: ServerDerivedPublicKey,
  E: RistrettoPoint[],
  R: Uint8Array[]
): bigint[] {
  const hasher = new ShoHmacSha256(
    enc.encode('Signal_ZKCredential_Endorsements_EndorsementResponse_ProofWeights_20240207')
  );

  // Absorb PK_prime bytes
  hasher.absorb(publicKey.PK_prime.toBytes());

  // Absorb doubled E points (double_and_compress_batch equivalent)
  // Doubling binds the prover to E values just as well as compressing directly
  for (const Ei of E) {
    const doubled = Ei.add(Ei);
    hasher.absorb(doubled.toBytes());
  }

  // Absorb compressed R points
  for (const Ri of R) {
    hasher.absorb(Ri);
  }

  hasher.ratchet();

  // Squeeze (N-1) * 16 bytes for the non-trivial weights
  // The first weight is implicitly 1 (RME+ approach)
  const numWeights = E.length - 1;
  if (numWeights <= 0) {
    return [];
  }
  const randomBytes = hasher.squeezeAndRatchet(numWeights * SMALL_SCALAR_BYTES);

  const weights: bigint[] = [];
  for (let i = 0; i < numWeights; i++) {
    const chunk = randomBytes.subarray(i * SMALL_SCALAR_BYTES, (i + 1) * SMALL_SCALAR_BYTES);
    // Parse as 32-byte LE scalar with bit 127 cleared
    const scalarBytes = new Uint8Array(32);
    scalarBytes.set(chunk, 0);
    scalarBytes[15] &= 0b0111_1111;
    // Scalar::from_bytes_mod_order -- since value < 2^127 < L, mod is a no-op
    let n = 0n;
    for (let j = 15; j >= 0; j--) {
      n = (n << 8n) | BigInt(scalarBytes[j]);
    }
    weights.push(n);
  }

  return weights;
}

// ---------------------------------------------------------------------------
// Weighted sum helper
// ---------------------------------------------------------------------------

/**
 * Compute weighted_sum = points[0] + sum(weights[i] * points[i+1])
 *
 * The first element has implicit weight 1 (RME+ approach).
 */
function weightedSum(points: RistrettoPoint[], weights: bigint[]): RistrettoPoint {
  let sum = points[0];
  for (let i = 0; i < weights.length; i++) {
    sum = sum.add(points[i + 1].multiply(weights[i]));
  }
  return sum;
}

// ---------------------------------------------------------------------------
// Token generation
// ---------------------------------------------------------------------------

/**
 * Hash an unblinded endorsement point into a token.
 *
 * SHA-256 of the compressed point, truncated to TOKEN_LEN bytes.
 * No domain separation at this level because it should already be
 * in the computation of the endorsement point.
 */
function tokenRaw(unblinedEndorsement: RistrettoPoint): Uint8Array {
  const hash = sha256(unblinedEndorsement.toBytes());
  return hash.slice(0, TOKEN_LEN);
}

// ---------------------------------------------------------------------------
