/**
 * ZK Credential Attributes: ElGamal encryption over Ristretto255
 *
 *
 * Provides typed attribute encryption for anonymous credential systems.
 * Attributes are pairs of Ristretto points (M1, M2) that can be encrypted
 * under domain-specific ElGamal keypairs and proven in zero knowledge.
 *
 * The ElGamal scheme uses per-domain generator points G_a derived from a
 * domain identifier via SHO, which gives cryptographic domain separation.
 *
 * @see https://eprint.iacr.org/2019/1416.pdf (Signal Private Group System)
 */

import { ShoHmacSha256, RistrettoPoint } from '../proofs/sho';
import type { ShoSha256 } from '../proofs/sho-sha256';
export {};
const Point = RistrettoPoint;
const Fn = Point.Fn;

// --- Domain label for generator point derivation ---

const DOMAIN_LABEL = new TextEncoder().encode('Signal_ZKCredential_Domain_20231011');

// --- Interfaces ---

/**
 * An attribute represented as a pair of Ristretto points.
 * Used as the plaintext in the ElGamal encryption scheme.
 */
export interface Attribute {
  asPoints(): [RistrettoPoint, RistrettoPoint];
}

/**
 * A public (non-encrypted) attribute that is hashed into the SHO
 * during credential issuance and presentation.
 */
export interface PublicAttribute {
  hashInto(sho: ShoHmacSha256): void;
}

/**
 * A revealed attribute represented as a single Ristretto point.
 * Used when one component of the attribute pair is publicly known.
 */
export interface RevealedAttribute {
  asPoint(): RistrettoPoint;
}

/**
 * A credential domain providing an identifier and domain-specific
 * generator points for ElGamal encryption.
 */
export interface Domain {
  readonly ID: string;
  G_a(): [RistrettoPoint, RistrettoPoint];
}

// --- Generator point derivation ---

/**
 * Derive a pair of domain-specific generator points from a domain identifier.
 *
 * Uses SHO(DOMAIN_LABEL).absorb(domainId).getPoint() x2 to produce
 * two independent Ristretto points bound to the domain.
 *
 * @param domainId - The domain identifier string
 * @returns A pair of Ristretto generator points [G_a1, G_a2]
 */
export function deriveDefaultGeneratorPoints(domainId: string): [RistrettoPoint, RistrettoPoint] {
  const sho = new ShoHmacSha256(DOMAIN_LABEL);
  sho.absorbAndRatchet(new TextEncoder().encode(domainId));
  const g1 = sho.getPoint();
  const g2 = sho.getPoint();
  return [g1, g2];
}

// --- PublicKey ---

/**
 * Public key for attribute encryption within a specific domain.
 *
 * A = a1 * G_a[0] + a2 * G_a[1]
 */
export class PublicKey {
  constructor(
    readonly A: RistrettoPoint,
    readonly domain: Domain
  ) {}
}

// --- Ciphertext ---

/**
 * ElGamal ciphertext for an encrypted attribute.
 *
 * E_A1 = a1 * M1
 * E_A2 = a2 * E_A1 + M2
 *
 * Implements the Attribute interface so ciphertexts can be used
 * as inputs to further credential operations.
 */
export class Ciphertext implements Attribute {
  constructor(
    readonly E_A1: RistrettoPoint,
    readonly E_A2: RistrettoPoint,
    readonly domain: Domain
  ) {}

  asPoints(): [RistrettoPoint, RistrettoPoint] {
    return [this.E_A1, this.E_A2];
  }
}

// --- KeyPair ---

/**
 * ElGamal keypair for attribute encryption within a specific domain.
 *
 * The keypair consists of two scalars (a1, a2) and a derived public key.
 * Encryption:
 *   E_A1 = a1 * M1
 *   E_A2 = a2 * E_A1 + M2
 *
 * Decryption (second point only):
 *   M2 = E_A2 - a2 * E_A1
 */
export class KeyPair {
  readonly a1: bigint;
  readonly a2: bigint;
  readonly publicKey: PublicKey;

  private constructor(a1: bigint, a2: bigint, domain: Domain) {
    this.a1 = a1;
    this.a2 = a2;

    const [G_a1, G_a2] = domain.G_a();
    const A = G_a1.multiply(a1).add(G_a2.multiply(a2));
    this.publicKey = new PublicKey(A, domain);
  }

  /**
   * Derive a keypair from a Stateful Hash Object and domain.
   *
   * Draws two scalars from the SHO and computes the public key.
   * Works with both ShoHmacSha256 and ShoSha256 since both expose getScalar().
   *
   * @param sho - A stateful hash object in RATCHETED state
   * @param domain - The credential domain
   */
  static deriveFrom(sho: ShoHmacSha256 | ShoSha256, domain: Domain): KeyPair {
    const a1 = sho.getScalar();
    const a2 = sho.getScalar();
    return new KeyPair(a1, a2, domain);
  }

  /**
   * Construct a keypair from raw scalar values.
   *
   * @param a1 - First scalar component
   * @param a2 - Second scalar component
   * @param domain - The credential domain
   */
  static fromScalars(a1: bigint, a2: bigint, domain: Domain): KeyPair {
    return new KeyPair(a1, a2, domain);
  }

  /**
   * Encrypt an attribute under this keypair.
   *
   * E_A1 = a1 * M1
   * E_A2 = a2 * E_A1 + M2
   *
   * @param attr - The attribute to encrypt
   * @returns The ciphertext in the same domain as this keypair
   */
  encrypt(attr: Attribute): Ciphertext {
    const [M1, M2] = attr.asPoints();
    const E_A1 = M1.multiply(this.a1);
    const E_A2 = E_A1.multiply(this.a2).add(M2);
    return new Ciphertext(E_A1, E_A2, this.publicKey.domain);
  }

  /**
   * Decrypt to recover the second point (M2) from a ciphertext.
   *
   * M2 = E_A2 - a2 * E_A1
   *
   * Rejects if E_A1 is the identity element (zero point), which would
   * indicate a malformed ciphertext that leaks M2 directly.
   *
   * @param ciphertext - The ciphertext to partially decrypt
   * @returns The second point M2
   * @throws Error if E_A1 is the identity point
   */
  decryptToSecondPoint(ciphertext: Ciphertext): RistrettoPoint {
    const { E_A1, E_A2 } = ciphertext;

    if (E_A1.equals(Point.ZERO)) {
      throw new Error('decryptToSecondPoint: E_A1 is the identity point; ciphertext is malformed');
    }

    return E_A2.subtract(E_A1.multiply(this.a2));
  }

  /**
   * Compute the "inverse" keypair relative to another keypair.
   *
   * Given keypair (b1, b2), produces a new keypair (a1', a2') such that:
   *   a1' = invert(b1)
   *   a2' = -(b2 * invert(b1))
   *
   * This is used to "undo" one layer of encryption. Encrypt with the original
   * keypair and then with its inverse. The result is an identity
   * transformation on the first point, and a negation relationship on the
   * second.
   *
   * @param other - The keypair to invert
   * @param newDomain - The domain for the resulting keypair
   * @returns A new keypair that is the inverse of `other` in `newDomain`
   */
  static inverseOf(other: KeyPair, newDomain: Domain): KeyPair {
    const a1Inv = Fn.inv(other.a1);
    // a2' = -(other.a2 * invert(other.a1))  mod L
    const a2Prime = Fn.neg(Fn.create(other.a2 * a1Inv));
    return new KeyPair(a1Inv, a2Prime, newDomain);
  }
}
