/**
 * Credential issuance — plain and blinded
 *
 *
 * When the issuing server issues a credential, it also generates a proof that
 * the credential covers the correct attributes. The client receives the proof
 * and credential together, verifies the proof, and extracts the credential.
 *
 * Blinded issuance allows the client to request credentials over attributes
 * the server cannot see (e.g., profile keys).
 *
 * @see Chase-Perrin-Zaverucha section 3.2
 */

import { ShoHmacSha256, RistrettoPoint } from '../proofs/sho';
import { Statement } from '../proofs/statement';
import { ScalarArgs, PointArgs } from '../proofs/args';
import type { Attribute, PublicAttribute, RevealedAttribute } from './attributes';
import {
  NUM_SUPPORTED_ATTRS,
  RANDOMNESS_LEN,
  getSystemParams,
  credentialCore,
  getPublicKeyI,
  type Credential,
  type CredentialKeyPair,
  type CredentialPublicKey,
} from './credentials';
export {};
const Point = RistrettoPoint;

// --- Error ---

export class VerificationFailure extends Error {
  constructor() {
    super('VerificationFailure');
    this.name = 'VerificationFailure';
  }
}

// --- IssuanceProof ---

export interface IssuanceProof {
  credential: Credential;
  pokshoProof: Uint8Array;
}

// --- Blinded types ---

export interface BlindedPoint {
  D1: RistrettoPoint;
  D2: RistrettoPoint;
}

export interface BlindedPointWithNonce extends BlindedPoint {
  r: bigint;
}

export interface BlindedAttribute {
  blindedPoints: [BlindedPoint, BlindedPoint];
}

export interface BlindedAttributeWithNonce {
  blindedPoints: [BlindedPointWithNonce, BlindedPointWithNonce];
}

export interface BlindingPublicKey {
  Y: RistrettoPoint;
}

interface BlindedCredential {
  t: bigint;
  U: RistrettoPoint;
  S1: RistrettoPoint;
  S2: RistrettoPoint;
}

export interface BlindedIssuanceProof {
  credential: BlindedCredential;
  pokshoProof: Uint8Array;
}

// --- BlindingKeyPair ---

export class BlindingKeyPair {
  readonly y: bigint;
  readonly publicKey: BlindingPublicKey;

  private constructor(y: bigint) {
    this.y = y;
    this.publicKey = { Y: Point.BASE.multiply(y) };
  }

  static generate(sho: { getScalar(): bigint }): BlindingKeyPair {
    return new BlindingKeyPair(sho.getScalar());
  }

  blind(attr: RevealedAttribute, sho: { getScalar(): bigint }): BlindedPointWithNonce {
    const r = sho.getScalar();
    const D1 = Point.BASE.multiply(r);
    const D2 = this.publicKey.Y.multiply(r).add(attr.asPoint());
    return { D1, D2, r };
  }

  encrypt(attr: Attribute, sho: { getScalar(): bigint }): BlindedAttributeWithNonce {
    const [p1, p2] = attr.asPoints();
    return {
      blindedPoints: [
        this.blind({ asPoint: () => p1 }, sho),
        this.blind({ asPoint: () => p2 }, sho),
      ],
    };
  }
}

// --- Scalar/point name arrays ---

const Y_NAMES = ['y0', 'y1', 'y2', 'y3', 'y4', 'y5', 'y6'] as const;
export const G_Y_NAMES = ['G_y0', 'G_y1', 'G_y2', 'G_y3', 'G_y4', 'G_y5', 'G_y6'] as const;
const M_NAMES = ['M0', 'M1', 'M2', 'M3', 'M4', 'M5', 'M6'] as const;

// --- IssuanceProofBuilder ---

/**
 * Builder for issuing and verifying credential issuance proofs.
 *
 * Usage (server, issuing):
 *   const builder = new IssuanceProofBuilder(label);
 *   builder.addPublicAttribute(attr);
 *   builder.addAttribute(attr);
 *   const proof = builder.issue(keyPair, randomness);
 *
 * Usage (client, verifying):
 *   const builder = new IssuanceProofBuilder(label);
 *   builder.addPublicAttribute(attr);
 *   builder.addAttribute(attr);
 *   const credential = builder.verify(publicKey, proof);
 */
export class IssuanceProofBuilder {
  private publicAttrs: ShoHmacSha256;
  /** Index 0 is reserved for the public attribute point. */
  attrPoints: RistrettoPoint[];
  authenticatedMessage: Uint8Array;

  constructor(label: Uint8Array, message: Uint8Array = new Uint8Array(0)) {
    this.publicAttrs = new ShoHmacSha256(label);
    this.attrPoints = [Point.ZERO]; // Reserve slot 0 for public attrs
    this.authenticatedMessage = message;
  }

  addPublicAttribute(attr: PublicAttribute): this {
    attr.hashInto(this.publicAttrs);
    this.publicAttrs.ratchet();
    return this;
  }

  addAttribute(attr: Attribute): this {
    const [p1, p2] = attr.asPoints();
    this.attrPoints.push(p1, p2);
    if (this.attrPoints.length > NUM_SUPPORTED_ATTRS) {
      throw new Error(
        `IssuanceProofBuilder: more than ${NUM_SUPPORTED_ATTRS - 1} hidden attribute points not supported`
      );
    }
    return this;
  }

  finalizePublicAttrs(): void {
    this.attrPoints[0] = this.publicAttrs.getPoint();
  }

  private getPokshoStatement(): Statement {
    const st = new Statement();
    st.add('C_W', [
      ['w', 'G_w'],
      ['wprime', 'G_wprime'],
    ]);

    // G_V - I = x0 * G_x0 + x1 * G_x1 + sum(yi * G_yi)
    const gvTerms: [string, string][] = [
      ['x0', 'G_x0'],
      ['x1', 'G_x1'],
      ...Y_NAMES.map((y, i) => [y, G_Y_NAMES[i]] as [string, string]),
    ];
    st.add('G_V-I', gvTerms.slice(0, 2 + this.attrPoints.length));

    // V = w * G_w + x0 * U + x1 * tU + sum(yi * Mi)
    const vTerms: [string, string][] = [
      ['w', 'G_w'],
      ['x0', 'U'],
      ['x1', 'tU'],
      ...Y_NAMES.map((y, i) => [y, M_NAMES[i]] as [string, string]),
    ];
    st.add('V', vTerms.slice(0, 3 + this.attrPoints.length));

    return st;
  }

  prepareScalarArgs(keyPair: CredentialKeyPair, totalAttrCount: number): ScalarArgs {
    const priv = keyPair.privateKey;
    const args = new ScalarArgs();
    args.add('w', priv.w);
    args.add('wprime', priv.wprime);
    args.add('x0', priv.x0);
    args.add('x1', priv.x1);
    for (let i = 0; i < totalAttrCount; i++) {
      args.add(Y_NAMES[i], priv.y[i]);
    }
    return args;
  }

  preparePointArgs(
    publicKey: CredentialPublicKey,
    totalAttrCount: number,
    credential: Credential | null
  ): PointArgs {
    const sys = getSystemParams();
    const args = new PointArgs();

    args.add('C_W', publicKey.C_W);
    args.add('G_w', sys.G_w);
    args.add('G_wprime', sys.G_wprime);
    args.add('G_V-I', sys.G_V.subtract(getPublicKeyI(publicKey, totalAttrCount)));
    args.add('G_x0', sys.G_x0);
    args.add('G_x1', sys.G_x1);

    for (let i = 0; i < totalAttrCount; i++) {
      args.add(G_Y_NAMES[i], sys.G_y[i]);
    }

    if (credential) {
      args.add('V', credential.V);
      args.add('U', credential.U);
      args.add('tU', credential.U.multiply(credential.t));
    }

    for (let i = 0; i < this.attrPoints.length; i++) {
      args.add(M_NAMES[i], this.attrPoints[i]);
    }

    return args;
  }

  /**
   * Issue a credential over the accumulated attributes.
   *
   * CRITICAL: Use different randomness each time. Reusing randomness
   * effectively reveals the server's private key.
   */
  issue(keyPair: CredentialKeyPair, randomness: Uint8Array): IssuanceProof {
    this.finalizePublicAttrs();

    const sho = new ShoHmacSha256(
      new TextEncoder().encode('Signal_ZKCredential_Issuance_20230410')
    );
    sho.absorbAndRatchet(randomness);

    const credential = credentialCore(keyPair.privateKey, this.attrPoints, sho);
    const scalarArgs = this.prepareScalarArgs(keyPair, this.attrPoints.length);
    const pointArgs = this.preparePointArgs(keyPair.publicKey, this.attrPoints.length, credential);

    const proofRandomness = sho.squeezeAndRatchet(RANDOMNESS_LEN);
    const pokshoProof = this.getPokshoStatement().prove(
      scalarArgs,
      pointArgs,
      this.authenticatedMessage,
      proofRandomness
    );

    return { credential, pokshoProof };
  }

  /**
   * Verify an issuance proof and extract the credential.
   */
  verify(publicKey: CredentialPublicKey, proof: IssuanceProof): Credential {
    this.finalizePublicAttrs();

    const pointArgs = this.preparePointArgs(publicKey, this.attrPoints.length, proof.credential);

    try {
      this.getPokshoStatement().verifyProof(
        proof.pokshoProof,
        pointArgs,
        this.authenticatedMessage
      );
    } catch {
      throw new VerificationFailure();
    }

    return proof.credential;
  }

  // --- Transition to blinded issuance ---

  addBlindedAttribute(attr: BlindedAttribute): BlindedIssuanceProofBuilder {
    return new BlindedIssuanceProofBuilder(this).addBlindedAttribute(attr);
  }

  addBlindedRevealedAttribute(attr: BlindedPoint): BlindedIssuanceProofBuilder {
    return new BlindedIssuanceProofBuilder(this).addBlindedRevealedAttribute(attr);
  }
}

// --- D1/D2 point name arrays for blind issuance ---

const D1_NAMES = ['D1_0', 'D1_1', 'D1_2', 'D1_3', 'D1_4', 'D1_5', 'D1_6'] as const;
const D2_NAMES = ['D2_0', 'D2_1', 'D2_2', 'D2_3', 'D2_4', 'D2_5', 'D2_6'] as const;

// --- BlindedIssuanceProofBuilder ---

/**
 * Builder for issuing and verifying blinded credential issuance proofs.
 *
 * Created from IssuanceProofBuilder via addBlindedAttribute(). Blinded
 * attributes must come after all plain attributes.
 */
export class BlindedIssuanceProofBuilder {
  readonly inner: IssuanceProofBuilder;
  private blindedAttrPoints: BlindedPoint[];

  constructor(inner: IssuanceProofBuilder) {
    this.inner = inner;
    this.blindedAttrPoints = [];
  }

  addBlindedAttribute(attr: BlindedAttribute): this {
    return this.addBlindedRevealedAttribute(attr.blindedPoints[0]).addBlindedRevealedAttribute(
      attr.blindedPoints[1]
    );
  }

  addBlindedRevealedAttribute(attr: BlindedPoint): this {
    this.blindedAttrPoints.push(attr);
    if (this.inner.attrPoints.length + this.blindedAttrPoints.length > NUM_SUPPORTED_ATTRS) {
      throw new Error(
        `BlindedIssuanceProofBuilder: more than ${NUM_SUPPORTED_ATTRS - 1} hidden attribute points not supported`
      );
    }
    return this;
  }

  private get totalCount(): number {
    return this.inner.attrPoints.length + this.blindedAttrPoints.length;
  }

  private getPokshoStatement(): Statement {
    const st = new Statement();
    st.add('C_W', [
      ['w', 'G_w'],
      ['wprime', 'G_wprime'],
    ]);

    // G_V - I (same as plain but with total count)
    const gvTerms: [string, string][] = [
      ['x0', 'G_x0'],
      ['x1', 'G_x1'],
      ...Y_NAMES.map((y, i) => [y, G_Y_NAMES[i]] as [string, string]),
    ];
    st.add('G_V-I', gvTerms.slice(0, 2 + this.totalCount));

    // S1 = rprime * G + sum(yi * D1_i, i = nV'..n)
    const nPlain = this.inner.attrPoints.length;
    const S1: [string, string][] = [];
    for (let i = 0; i < this.blindedAttrPoints.length; i++) {
      S1.push([Y_NAMES[nPlain + i], D1_NAMES[nPlain + i]]);
    }
    S1.push(['rprime', 'G']);
    st.add('S1', S1);

    // S2 = rprime * Y + V' + sum(yi * D2_i, i = nV'..n)
    //   where V' = w * G_w + x0 * U + x1 * tU + sum(yi * Mi, i = 0..nV')
    const S2: [string, string][] = [
      ['rprime', 'Y'],
      ['w', 'G_w'],
      ['x0', 'U'],
      ['x1', 'tU'],
    ];
    for (let i = 0; i < nPlain; i++) {
      S2.push([Y_NAMES[i], M_NAMES[i]]);
    }
    for (let i = 0; i < this.blindedAttrPoints.length; i++) {
      S2.push([Y_NAMES[nPlain + i], D2_NAMES[nPlain + i]]);
    }
    st.add('S2', S2);

    return st;
  }

  private prepareScalarArgs(keyPair: CredentialKeyPair, rprime: bigint): ScalarArgs {
    const args = this.inner.prepareScalarArgs(keyPair, this.totalCount);
    args.add('rprime', rprime);
    return args;
  }

  private preparePointArgs(
    publicKey: CredentialPublicKey,
    blindingKey: BlindingPublicKey,
    credential: BlindedCredential
  ): PointArgs {
    const args = this.inner.preparePointArgs(publicKey, this.totalCount, null);
    const nPlain = this.inner.attrPoints.length;

    for (let i = 0; i < this.blindedAttrPoints.length; i++) {
      args.add(D1_NAMES[nPlain + i], this.blindedAttrPoints[i].D1);
      args.add(D2_NAMES[nPlain + i], this.blindedAttrPoints[i].D2);
    }

    args.add('S1', credential.S1);
    args.add('S2', credential.S2);
    args.add('U', credential.U);
    args.add('tU', credential.U.multiply(credential.t));
    args.add('Y', blindingKey.Y);

    return args;
  }

  /**
   * Issue a blinded credential.
   *
   * CRITICAL: Use different randomness each time.
   */
  issue(
    keyPair: CredentialKeyPair,
    blindingKey: BlindingPublicKey,
    randomness: Uint8Array
  ): BlindedIssuanceProof {
    this.inner.finalizePublicAttrs();

    const sho = new ShoHmacSha256(
      new TextEncoder().encode('Signal_ZKCredential_BlindIssuance_20230410')
    );
    sho.absorbAndRatchet(randomness);

    const rprime = sho.getScalar();

    // S1 = rprime * G + sum(yi * D1_i)
    let S1 = Point.BASE.multiply(rprime);
    const nPlain = this.inner.attrPoints.length;
    for (let i = 0; i < this.blindedAttrPoints.length; i++) {
      S1 = S1.add(this.blindedAttrPoints[i].D1.multiply(keyPair.privateKey.y[nPlain + i]));
    }

    // Base credential over unblinded attrs
    const baseCredential = credentialCore(keyPair.privateKey, this.inner.attrPoints, sho);

    // S2 = rprime * Y + V + sum(yi * D2_i)
    let S2 = blindingKey.Y.multiply(rprime).add(baseCredential.V);
    for (let i = 0; i < this.blindedAttrPoints.length; i++) {
      S2 = S2.add(this.blindedAttrPoints[i].D2.multiply(keyPair.privateKey.y[nPlain + i]));
    }

    const credential: BlindedCredential = {
      t: baseCredential.t,
      U: baseCredential.U,
      S1,
      S2,
    };

    const scalarArgs = this.prepareScalarArgs(keyPair, rprime);
    const pointArgs = this.preparePointArgs(keyPair.publicKey, blindingKey, credential);

    const proofRandomness = sho.squeezeAndRatchet(RANDOMNESS_LEN);
    const pokshoProof = this.getPokshoStatement().prove(
      scalarArgs,
      pointArgs,
      this.inner.authenticatedMessage,
      proofRandomness
    );

    return { credential, pokshoProof };
  }

  /**
   * Verify a blinded issuance proof, decrypt and extract the credential.
   */
  verify(
    publicKey: CredentialPublicKey,
    blindingKey: BlindingKeyPair,
    proof: BlindedIssuanceProof
  ): Credential {
    this.inner.finalizePublicAttrs();

    const pointArgs = this.preparePointArgs(publicKey, blindingKey.publicKey, proof.credential);

    try {
      this.getPokshoStatement().verifyProof(
        proof.pokshoProof,
        pointArgs,
        this.inner.authenticatedMessage
      );
    } catch {
      throw new VerificationFailure();
    }

    // Decrypt: V = S2 - y * S1
    const V = proof.credential.S2.subtract(proof.credential.S1.multiply(blindingKey.y));

    return {
      t: proof.credential.t,
      U: proof.credential.U,
      V,
    };
  }
}
