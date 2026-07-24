/**
 * Credential presentation -- proof generation and verification
 *
 *
 * When a client wishes to use a credential, it generates a _presentation
 * proof_ over the same attributes that went into the original credential.
 * This allows the client to demonstrate that it holds a credential over
 * certain attributes without actually revealing those attributes. The
 * verifying server checks the proof against the encrypted forms of those
 * attributes and is thus assured the client holds a credential from the
 * issuing server.
 *
 * Credential presentation is defined in Chase-Perrin-Zaverucha section 3.2;
 * proofs for verifiable encryption are defined in section 4.1.
 *
 * @see https://eprint.iacr.org/2019/1416.pdf -- Signal Private Group System
 */

import { ShoHmacSha256, RistrettoPoint } from '../proofs/sho';
import { Statement } from '../proofs/statement';
import { ScalarArgs, PointArgs } from '../proofs/args';
import type {
  Attribute,
  PublicAttribute,
  RevealedAttribute,
  PublicKey,
  KeyPair,
} from './attributes';
import {
  NUM_SUPPORTED_ATTRS,
  RANDOMNESS_LEN,
  getSystemParams,
  getPublicKeyI,
  type Credential,
  type CredentialKeyPair,
  type CredentialPublicKey,
} from './credentials';
import { VerificationFailure, G_Y_NAMES } from './issuance';
export {};
const Point = RistrettoPoint;
const Fn = Point.Fn;

// ---------------------------------------------------------------------------
// Exported types
// ---------------------------------------------------------------------------

/** Demonstrates to the verifying server that the client holds a credential. */
export interface PresentationProof {
  C_x0: RistrettoPoint;
  C_x1: RistrettoPoint;
  C_V: RistrettoPoint;
  C_y: RistrettoPoint[];
  pokshoProof: Uint8Array;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/** Reference to an attribute within the builder's point vector. */
interface AttributeRef {
  keyIndex: number | null;
  firstPointIndex: number;
  secondPointIndex: number;
}

/**
 * Type-erased encryption key info used by the builder.
 * Stores the domain ID, optional G_a generator points, optional A public key
 * point, and the private scalars (a1, a2).
 */
interface AnyKeyInfo {
  id: string;
  /** G_a generator points, present when we have a verified public key. */
  G_a: (() => [RistrettoPoint, RistrettoPoint]) | null;
  /** A = a1*G_a1 + a2*G_a2, present when we have a verified public key. */
  A: RistrettoPoint | null;
  /** Private scalar a1 (only present on builder side). */
  a1: bigint | null;
  /** Private scalar a2 (only present on builder side). */
  a2: bigint | null;
}

// ---------------------------------------------------------------------------
// Shared statement + point-args logic
// ---------------------------------------------------------------------------

/**
 * Build the poksho Statement for presentation proofs.
 *
 * Shared between builder and verifier -- the statement is identical
 * for both sides (it describes the algebraic relation, not the witness).
 */
function getPokshoStatement(
  encryptionKeys: AnyKeyInfo[],
  attributes: AttributeRef[],
  _attrPointCount: number
): Statement {
  const st = new Statement();

  // Chase-Perrin-Zaverucha section 3.2
  st.add('Z', [['z', 'I']]);
  st.add('C_x1', [
    ['t', 'C_x0'],
    ['z0', 'G_x0'],
    ['z', 'G_x1'],
  ]);

  // Chase-Perrin-Zaverucha section 4.1 -- encryption key validity
  const encryptionSumTerms: [string, string][] = [];
  for (const key of encryptionKeys) {
    const keyId = key.id;
    const a1Name = `a1_${keyId}`;

    // Trevor Perrin addition: ensure encryption keys are valid
    // 0 = z1_{id} * I + a1_{id} * Z
    st.add('0', [
      [`z1_${keyId}`, 'I'],
      [a1Name, 'Z'],
    ]);

    if (key.G_a !== null) {
      encryptionSumTerms.push([a1Name, `G_a1_${keyId}`]);
      encryptionSumTerms.push([`a2_${keyId}`, `G_a2_${keyId}`]);
    }
  }
  if (encryptionSumTerms.length > 0) {
    // sum(A) = a1_uid * G_a1_uid + a2_uid * G_a2_uid + ...
    st.add('sum(A)', encryptionSumTerms);
  }

  // Per-attribute equations
  for (const attr of attributes) {
    if (attr.keyIndex !== null) {
      // Encrypted attribute (section 4.1)
      const keyId = encryptionKeys[attr.keyIndex].id;
      // E_A{first} = a1_{id} * C_y{first} + z1_{id} * G_y{first}
      st.add(`E_A${attr.firstPointIndex}`, [
        [`a1_${keyId}`, `C_y${attr.firstPointIndex}`],
        [`z1_${keyId}`, `G_y${attr.firstPointIndex}`],
      ]);
      // C_y{second}-E_A{second} = z * G_y{second} + a2_{id} * -E_A{first}
      st.add(`C_y${attr.secondPointIndex}-E_A${attr.secondPointIndex}`, [
        ['z', `G_y${attr.secondPointIndex}`],
        [`a2_${keyId}`, `-E_A${attr.firstPointIndex}`],
      ]);
    } else {
      // Revealed attribute (section 3.2)
      // C_y{idx} = z * G_y{idx}
      st.add(`C_y${attr.firstPointIndex}`, [['z', `G_y${attr.firstPointIndex}`]]);
    }
  }

  // Point 0 is a hardcoded public attribute
  st.add('C_y0', [['z', 'G_y0']]);

  return st;
}

/**
 * Prepare PointArgs containing all points NOT derived from per-attribute
 * specifics. Shared between builder and verifier.
 *
 * Includes: I, C_x0, C_x1, G_x0, G_x1, G_y{0..n}, C_y0,
 * and encryption key points (0, G_a1_{id}, G_a2_{id}, sum(A)).
 *
 * The caller is responsible for adding: Z, per-attribute C_y{i},
 * E_A{i}, -E_A{i}, and C_y{j}-E_A{j}.
 */
function prepareNonAttributePointArgs(
  encryptionKeys: AnyKeyInfo[],
  attrPointCount: number,
  I: RistrettoPoint,
  C_x0: RistrettoPoint,
  C_x1: RistrettoPoint,
  C_y: RistrettoPoint[]
): PointArgs {
  const sys = getSystemParams();
  const pointArgs = new PointArgs();

  pointArgs.add('I', I);
  pointArgs.add('C_x0', C_x0);
  pointArgs.add('C_x1', C_x1);
  pointArgs.add('G_x0', sys.G_x0);
  pointArgs.add('G_x1', sys.G_x1);

  if (encryptionKeys.length > 0) {
    pointArgs.add('0', Point.ZERO);
    let sumA = Point.ZERO;
    for (const key of encryptionKeys) {
      if (key.G_a !== null && key.A !== null) {
        const [G_a1, G_a2] = key.G_a();
        pointArgs.add(`G_a1_${key.id}`, G_a1);
        pointArgs.add(`G_a2_${key.id}`, G_a2);
        sumA = sumA.add(key.A);
      }
    }
    if (!sumA.equals(Point.ZERO)) {
      pointArgs.add('sum(A)', sumA);
    }
  }

  for (let i = 0; i < attrPointCount; i++) {
    pointArgs.add(G_Y_NAMES[i], sys.G_y[i]);
  }

  pointArgs.add('C_y0', C_y[0]);

  return pointArgs;
}

// ---------------------------------------------------------------------------
// Core add-attribute logic
// ---------------------------------------------------------------------------

/**
 * Add an attribute (as raw points) plus optional encryption key info to the
 * tracking arrays. Returns the updated state. Deduplicates keys by domain ID.
 */
function addAttributeCore(
  attrPointValues: RistrettoPoint[],
  key: AnyKeyInfo | null,
  encryptionKeys: AnyKeyInfo[],
  attributes: AttributeRef[],
  attrPoints: RistrettoPoint[]
): void {
  const firstIndex = attrPoints.length;
  for (const p of attrPointValues) {
    attrPoints.push(p);
  }
  if (attrPoints.length > NUM_SUPPORTED_ATTRS) {
    throw new Error(`more than ${NUM_SUPPORTED_ATTRS - 1} hidden attribute points not supported`);
  }

  let keyIndex: number | null = null;
  if (key !== null) {
    const keyId = key.id;
    const existing = encryptionKeys.findIndex((k) => k.id === keyId);
    if (existing >= 0) {
      keyIndex = existing;
    } else {
      keyIndex = encryptionKeys.length;
      encryptionKeys.push(key);
    }
  }

  attributes.push({
    keyIndex,
    firstPointIndex: firstIndex,
    secondPointIndex: firstIndex + attrPointValues.length - 1,
  });
}

// ---------------------------------------------------------------------------
// PresentationProofBuilder
// ---------------------------------------------------------------------------

/**
 * Used to generate presentation proofs.
 *
 * Public attributes are not included in the presentation proof; when the
 * proof is verified, the verifying server provides its own copy of the
 * public attributes to ensure they have not been tampered with.
 *
 * @see PresentationProofVerifier
 */
export class PresentationProofBuilder {
  private encryptionKeys: AnyKeyInfo[] = [];
  private attributes: AttributeRef[] = [];
  /** Index 0 is reserved for the public attribute point (identity). */
  private attrPoints: RistrettoPoint[];
  private authenticatedMessage: Uint8Array;

  /**
   * @param _label A mandatory public attribute that should uniquely identify
   *   the credential. Ignored on the builder side (kept for symmetry with
   *   PresentationProofVerifier).
   * @param message Optional authenticated message bound to the proof but
   *   not part of the original credential.
   */
  constructor(_label: Uint8Array, message: Uint8Array = new Uint8Array(0)) {
    // Reserve the first point for public attributes (identity on builder side)
    this.attrPoints = [Point.ZERO];
    this.authenticatedMessage = message;
  }

  /**
   * Add an attribute to the proof, encrypted under `keyPair`.
   *
   * Includes a proof that the attribute was correctly encrypted AND that the
   * encryption used the given key (which the verifier can check).
   *
   * Order-sensitive: must match the order used during issuance and verification.
   */
  addAttribute(attr: Attribute, keyPair: KeyPair): this {
    const domain = keyPair.publicKey.domain;
    addAttributeCore(
      attr.asPoints(),
      {
        id: domain.ID,
        G_a: domain.G_a.bind(domain),
        A: keyPair.publicKey.A,
        a1: keyPair.a1,
        a2: keyPair.a2,
      },
      this.encryptionKeys,
      this.attributes,
      this.attrPoints
    );
    return this;
  }

  /**
   * Add an attribute to the proof, encrypted under `keyPair`, but without
   * proving which key performed the encryption.
   *
   * The verifying server still checks that the attribute was correctly
   * encrypted; it just cannot enforce which key did so.
   *
   * Order-sensitive.
   */
  addAttributeWithoutVerifiedKey(attr: Attribute, keyPair: KeyPair): this {
    const domain = keyPair.publicKey.domain;
    addAttributeCore(
      attr.asPoints(),
      {
        id: domain.ID,
        G_a: null,
        A: null,
        a1: keyPair.a1,
        a2: keyPair.a2,
      },
      this.encryptionKeys,
      this.attributes,
      this.attrPoints
    );
    return this;
  }

  /**
   * Add a revealed (unencrypted) attribute to check against the credential.
   *
   * In practice `attr` is ignored in favor of letting the verifying server
   * check the attribute itself, but this method must be called to indicate
   * that there *is* an attribute.
   *
   * Order-sensitive.
   */
  addRevealedAttribute(_attr: RevealedAttribute): this {
    addAttributeCore([Point.ZERO], null, this.encryptionKeys, this.attributes, this.attrPoints);
    return this;
  }

  /**
   * Generate a presentation of `credential` using the server-provided
   * `publicKey`.
   *
   * CRITICAL: Use different randomness each time. Reusing randomness allows
   * different presentations to be linked to the same credential and
   * effectively reveals hidden Attributes and their encryption keys.
   */
  present(
    publicKey: CredentialPublicKey,
    credential: Credential,
    randomness: Uint8Array
  ): PresentationProof {
    if (randomness.length < RANDOMNESS_LEN) {
      throw new Error(
        `present: need at least ${RANDOMNESS_LEN} bytes of randomness, got ${randomness.length}`
      );
    }

    const sys = getSystemParams();

    const sho = new ShoHmacSha256(
      new TextEncoder().encode('Signal_ZKCredential_Presentation_20230410')
    );
    sho.absorbAndRatchet(randomness);
    const z = sho.getScalar();

    // C_y[i] = z * G_y[i] + M[i]
    // For public attrs (index 0) and revealed attrs, M is identity, so this
    // simplifies to z * G_y[i] as in Chase-Perrin-Zaverucha section 3.2.
    const C_y = sys.G_y.slice(0, this.attrPoints.length).map((G_yn, i) =>
      G_yn.multiply(z).add(this.attrPoints[i])
    );

    const C_x0 = sys.G_x0.multiply(z).add(credential.U);
    const C_V = sys.G_V.multiply(z).add(credential.V);
    const C_x1 = sys.G_x1.multiply(z).add(credential.U.multiply(credential.t));

    const z0 = Fn.neg(Fn.create(z * credential.t));

    const I = getPublicKeyI(publicKey, this.attrPoints.length);
    const Z = I.multiply(z);

    // --- Scalar arguments (the witness) ---
    const scalarArgs = new ScalarArgs();
    scalarArgs.add('z', z);
    scalarArgs.add('t', credential.t);
    scalarArgs.add('z0', z0);
    for (const key of this.encryptionKeys) {
      const keyId = key.id;
      scalarArgs.add(`a1_${keyId}`, key.a1!);
      scalarArgs.add(`a2_${keyId}`, key.a2!);
      scalarArgs.add(`z1_${keyId}`, Fn.neg(Fn.create(z * key.a1!)));
    }

    // --- Point arguments ---
    const pointArgs = prepareNonAttributePointArgs(
      this.encryptionKeys,
      this.attrPoints.length,
      I,
      C_x0,
      C_x1,
      C_y
    );
    pointArgs.add('Z', Z);

    for (const attr of this.attributes) {
      const { keyIndex, firstPointIndex, secondPointIndex } = attr;
      pointArgs.add(`C_y${firstPointIndex}`, C_y[firstPointIndex]);

      if (keyIndex !== null) {
        const key = this.encryptionKeys[keyIndex];
        // E_A1 = a1 * M[first]
        const E_A1 = this.attrPoints[firstPointIndex].multiply(key.a1!);
        // E_A2 = a2 * E_A1 + M[second]
        const E_A2 = E_A1.multiply(key.a2!).add(this.attrPoints[secondPointIndex]);
        pointArgs.add(`E_A${firstPointIndex}`, E_A1);
        pointArgs.add(`-E_A${firstPointIndex}`, E_A1.negate());
        pointArgs.add(
          `C_y${secondPointIndex}-E_A${secondPointIndex}`,
          C_y[secondPointIndex].subtract(E_A2)
        );
      }
      // For revealed attrs, the point is identity; the server incorporates
      // the real value during verification.
    }

    const statement = getPokshoStatement(
      this.encryptionKeys,
      this.attributes,
      this.attrPoints.length
    );
    const proofRandomness = sho.squeezeAndRatchet(RANDOMNESS_LEN);
    const pokshoProof = statement.prove(
      scalarArgs,
      pointArgs,
      this.authenticatedMessage,
      proofRandomness
    );

    return { C_x0, C_x1, C_V, C_y, pokshoProof };
  }
}

// ---------------------------------------------------------------------------
// PresentationProofVerifier
// ---------------------------------------------------------------------------

/**
 * Used to verify presentation proofs.
 *
 * By providing the same attributes in the same order, a proof can be
 * generated and verified with parallel invocations. The size of the proof
 * scales linearly with the number of attributes.
 *
 * Public attributes are not included in the presentation proof; the
 * verifying server provides its own copy to ensure they have not been
 * tampered with (Chase-Perrin-Zaverucha section 3.2).
 *
 * @see PresentationProofBuilder
 */
export class PresentationProofVerifier {
  private encryptionKeys: AnyKeyInfo[] = [];
  private attributes: AttributeRef[] = [];
  /** Index 0 is reserved for public attributes (initially identity). */
  private attrPoints: RistrettoPoint[];
  private publicAttrs: ShoHmacSha256;
  private authenticatedMessage: Uint8Array;

  /**
   * @param label A mandatory public attribute that should uniquely identify
   *   the credential.
   * @param message Optional authenticated message bound to the proof.
   */
  constructor(label: Uint8Array, message: Uint8Array = new Uint8Array(0)) {
    this.attrPoints = [Point.ZERO];
    this.publicAttrs = new ShoHmacSha256(label);
    this.authenticatedMessage = message;
  }

  /**
   * Add a public attribute to check against the credential.
   *
   * Order-sensitive.
   */
  addPublicAttribute(attr: PublicAttribute): this {
    attr.hashInto(this.publicAttrs);
    this.publicAttrs.ratchet();
    return this;
  }

  /**
   * Add an encrypted attribute to check, along with the public key it was
   * encrypted with.
   *
   * Order-sensitive.
   */
  addAttribute(attr: Attribute, publicKey: PublicKey): this {
    const domain = publicKey.domain;
    addAttributeCore(
      attr.asPoints(),
      {
        id: domain.ID,
        G_a: domain.G_a.bind(domain),
        A: publicKey.A,
        a1: null,
        a2: null,
      },
      this.encryptionKeys,
      this.attributes,
      this.attrPoints
    );
    return this;
  }

  /**
   * Add an encrypted attribute to check, omitting the key it was encrypted
   * with. Still checks correct encryption, but cannot enforce which key
   * performed it.
   *
   * Order-sensitive.
   */
  addAttributeWithoutVerifiedKey(attr: Attribute, keyId: string): this {
    addAttributeCore(
      attr.asPoints(),
      {
        id: keyId,
        G_a: null,
        A: null,
        a1: null,
        a2: null,
      },
      this.encryptionKeys,
      this.attributes,
      this.attrPoints
    );
    return this;
  }

  /**
   * Add an attribute to check against the credential, unencrypted.
   *
   * Should only be used when the attribute is blinded from the issuing
   * server but visible to the verifying server.
   *
   * Order-sensitive.
   */
  addRevealedAttribute(attr: RevealedAttribute): this {
    addAttributeCore([attr.asPoint()], null, this.encryptionKeys, this.attributes, this.attrPoints);
    return this;
  }

  /**
   * Finalize public attributes by hashing them into a Ristretto point
   * and storing in attrPoints[0].
   */
  private finalizePublicAttrs(): void {
    this.attrPoints[0] = this.publicAttrs.getPoint();
  }

  /**
   * Verify the given proof over the accrued attributes using `keyPair`.
   *
   * @throws VerificationFailure if the proof is invalid.
   */
  verify(keyPair: CredentialKeyPair, proof: PresentationProof): void {
    this.finalizePublicAttrs();

    const { C_x0, C_x1, C_V, C_y, pokshoProof } = proof;

    if (C_y.length !== this.attrPoints.length) {
      throw new VerificationFailure();
    }

    const priv = keyPair.privateKey;

    // Z = C_V - W - x0*C_x0 - x1*C_x1 - sum(y[i]*C_y[i]) - y[0]*M_pub
    let Z = C_V.subtract(priv.W).subtract(C_x0.multiply(priv.x0)).subtract(C_x1.multiply(priv.x1));

    for (let i = 0; i < C_y.length; i++) {
      Z = Z.subtract(C_y[i].multiply(priv.y[i]));
    }
    // Incorporate public attributes so the server can check they match
    Z = Z.subtract(this.attrPoints[0].multiply(priv.y[0]));

    const pub = keyPair.publicKey;
    const I = getPublicKeyI(pub, this.attrPoints.length);

    const pointArgs = prepareNonAttributePointArgs(
      this.encryptionKeys,
      this.attrPoints.length,
      I,
      C_x0,
      C_x1,
      C_y
    );

    for (const attr of this.attributes) {
      const { firstPointIndex, secondPointIndex, keyIndex } = attr;
      pointArgs.add(`C_y${firstPointIndex}`, C_y[firstPointIndex]);

      if (keyIndex !== null) {
        // For the verifier, attrPoints[i] stores E_A (the ciphertext points)
        pointArgs.add(`E_A${firstPointIndex}`, this.attrPoints[firstPointIndex]);
        pointArgs.add(`-E_A${firstPointIndex}`, this.attrPoints[firstPointIndex].negate());
        pointArgs.add(
          `C_y${secondPointIndex}-E_A${secondPointIndex}`,
          C_y[secondPointIndex].subtract(this.attrPoints[secondPointIndex])
        );
      } else {
        // Revealed attribute: subtract its contribution from Z
        Z = Z.subtract(this.attrPoints[firstPointIndex].multiply(priv.y[firstPointIndex]));
      }
    }

    pointArgs.add('Z', Z);

    const statement = getPokshoStatement(
      this.encryptionKeys,
      this.attributes,
      this.attrPoints.length
    );

    try {
      statement.verifyProof(pokshoProof, pointArgs, this.authenticatedMessage);
    } catch {
      throw new VerificationFailure();
    }
  }
}
