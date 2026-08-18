/**
 * ZK Credential system -- credential issuance and key management
 *
 *
 * Provides:
 *  - SystemParams: deterministic system-wide generator points
 *  - CredentialPrivateKey / CredentialPublicKey / CredentialKeyPair
 *  - Credential: the issued (t, U, V) triple
 *
 * @see https://signal.org/docs/
 */

import { ShoSha256 } from '../proofs/sho-sha256';
import { ShoHmacSha256, RistrettoPoint } from '../proofs/sho';
export {};
const Point = RistrettoPoint;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Maximum number of hidden attributes a credential can carry. */
export const NUM_SUPPORTED_ATTRS = 7;

/** Length in bytes of randomness required for key generation. */
export const RANDOMNESS_LEN = 32;

// Scalar field helper -- mod-L arithmetic on bigints.
const Fn = RistrettoPoint.Fn;

// ---------------------------------------------------------------------------
// SystemParams
// ---------------------------------------------------------------------------

/**
 * System-wide generator points, derived deterministically from a fixed label.
 *
 * These are "nothing-up-my-sleeve" points: everyone can recompute them and
 * verify that no trapdoor was baked in.
 */
export interface SystemParams {
  G_w: RistrettoPoint;
  G_wprime: RistrettoPoint;
  G_x0: RistrettoPoint;
  G_x1: RistrettoPoint;
  G_V: RistrettoPoint;
  G_z: RistrettoPoint;
  G_y: RistrettoPoint[]; // length NUM_SUPPORTED_ATTRS (7)
}

// Lazy singleton ---------------------------------------------------------

let _systemParams: SystemParams | undefined;

/**
 * Return the singleton SystemParams, generating on first call.
 *
 * Generation uses ShoSha256 with a fixed label. Each point is produced by
 * `sho.getPoint()` in the canonical order defined by the profile.
 */
export function getSystemParams(): SystemParams {
  if (_systemParams !== undefined) {
    return _systemParams;
  }

  const label = new TextEncoder().encode(
    'Signal_ZKCredential_ConstantSystemParams_generate_20230410'
  );
  const sho = new ShoSha256(label);

  const G_w = sho.getPoint();
  const G_wprime = sho.getPoint();
  const G_x0 = sho.getPoint();
  const G_x1 = sho.getPoint();
  const G_V = sho.getPoint();
  const G_z = sho.getPoint();

  const G_y: RistrettoPoint[] = [];
  for (let i = 0; i < NUM_SUPPORTED_ATTRS; i++) {
    G_y.push(sho.getPoint());
  }

  _systemParams = { G_w, G_wprime, G_x0, G_x1, G_V, G_z, G_y };
  return _systemParams;
}

/**
 * Serialize the system params to bytes (13 points x 32 bytes = 416 bytes).
 * Provides a deterministic representation for verification and transport.
 */
export function systemParamsToBytes(params: SystemParams): Uint8Array {
  const out = new Uint8Array(13 * 32);
  let offset = 0;
  const write = (p: RistrettoPoint): void => {
    out.set(p.toBytes(), offset);
    offset += 32;
  };
  write(params.G_w);
  write(params.G_wprime);
  write(params.G_x0);
  write(params.G_x1);
  write(params.G_V);
  write(params.G_z);
  for (const p of params.G_y) {
    write(p);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Credential
// ---------------------------------------------------------------------------

/** An issued credential: blinded tag `t`, base point `U`, MAC point `V`. */
export interface Credential {
  t: bigint;
  U: RistrettoPoint;
  V: RistrettoPoint;
}

// ---------------------------------------------------------------------------
// CredentialPrivateKey
// ---------------------------------------------------------------------------

export interface CredentialPrivateKey {
  w: bigint;
  wprime: bigint;
  W: RistrettoPoint;
  x0: bigint;
  x1: bigint;
  y: bigint[]; // length NUM_SUPPORTED_ATTRS (7)
}

/**
 * Derive a credential private key deterministically from randomness.
 *
 * Uses ShoHmacSha256 keyed with a fixed label, absorbing the provided
 * randomness, then deriving each scalar via `sho.getScalar()`.
 */
export function generatePrivateKey(randomness: Uint8Array): CredentialPrivateKey {
  if (randomness.length < RANDOMNESS_LEN) {
    throw new Error(
      `CredentialPrivateKey.generate: need at least ${RANDOMNESS_LEN} bytes of randomness, got ${randomness.length}`
    );
  }

  const sys = getSystemParams();

  const label = new TextEncoder().encode(
    'Signal_ZKCredential_CredentialPrivateKey_generate_20230410'
  );
  const sho = new ShoHmacSha256(label);
  sho.absorbAndRatchet(randomness);

  const w = sho.getScalar();
  const W = sys.G_w.multiply(w);
  const wprime = sho.getScalar();
  const x0 = sho.getScalar();
  const x1 = sho.getScalar();

  const y: bigint[] = [];
  for (let i = 0; i < NUM_SUPPORTED_ATTRS; i++) {
    y.push(sho.getScalar());
  }

  return { w, wprime, W, x0, x1, y };
}

/**
 * Issue a credential over a vector of attribute points M.
 *
 * Computes:
 *   t = sho.getScalar()
 *   U = sho.getPoint()
 *   V = W + (x0 + x1*t)*U + sum(y[i]*M[i])
 *
 * The caller must supply a ShoHmacSha256 that has already absorbed any
 * context binding data (e.g. the public key, attribute commitments).
 */
export function credentialCore(
  key: CredentialPrivateKey,
  M: RistrettoPoint[],
  sho: ShoHmacSha256
): Credential {
  if (M.length > NUM_SUPPORTED_ATTRS) {
    throw new Error(`credentialCore: too many attributes (${M.length} > ${NUM_SUPPORTED_ATTRS})`);
  }

  const t = sho.getScalar();
  const U = sho.getPoint();

  // V = W + (x0 + x1*t) * U + sum(y[i] * M[i])
  const x0_plus_x1t = Fn.create(key.x0 + Fn.create(key.x1 * t));
  let V = key.W.add(U.multiply(x0_plus_x1t));

  for (let i = 0; i < M.length; i++) {
    V = V.add(M[i].multiply(key.y[i]));
  }

  return { t, U, V };
}

// ---------------------------------------------------------------------------
// CredentialPublicKey
// ---------------------------------------------------------------------------

export interface CredentialPublicKey {
  /**
   * Commitment to W: C_W = W + wprime * G_wprime
   */
  C_W: RistrettoPoint;

  /**
   * Iterative public-key images for different attribute counts.
   * I[0] is for numAttrs=2, I[5] is for numAttrs=7.
   * Length: NUM_SUPPORTED_ATTRS - 1 = 6
   */
  I: RistrettoPoint[];
}

/**
 * Derive the public key from a private key.
 *
 * C_W = W + wprime * G_wprime
 *
 * I is computed iteratively for attributes 1 through NUM_SUPPORTED_ATTRS - 1:
 *   accum = G_V - x0*G_x0 - x1*G_x1 - y[0]*G_y[0]
 *   for n = 1 .. NUM_SUPPORTED_ATTRS-1:
 *     accum -= y[n]*G_y[n]
 *     I.push(accum)
 *
 * I has length NUM_SUPPORTED_ATTRS - 1 = 6.
 * I[0] includes subtraction through y[1] (numAttrs=2).
 * getI(numAttrs) returns I[numAttrs - 2].
 */
export function derivePublicKey(priv: CredentialPrivateKey): CredentialPublicKey {
  const sys = getSystemParams();

  const C_W = priv.W.add(sys.G_wprime.multiply(priv.wprime));

  // Start: G_V - x0*G_x0 - x1*G_x1 - y[0]*G_y[0]
  let accum = sys.G_V.subtract(sys.G_x0.multiply(priv.x0))
    .subtract(sys.G_x1.multiply(priv.x1))
    .subtract(sys.G_y[0].multiply(priv.y[0]));

  const I: RistrettoPoint[] = [];
  for (let n = 1; n < NUM_SUPPORTED_ATTRS; n++) {
    accum = accum.subtract(sys.G_y[n].multiply(priv.y[n]));
    I.push(accum);
  }

  return { C_W, I };
}

/**
 * Retrieve the public key image for a credential with `numAttrs` attributes.
 * numAttrs must be in [2, NUM_SUPPORTED_ATTRS].
 */
export function getPublicKeyI(pub: CredentialPublicKey, numAttrs: number): RistrettoPoint {
  if (numAttrs < 2 || numAttrs > NUM_SUPPORTED_ATTRS) {
    throw new Error(
      `getPublicKeyI: numAttrs must be in [2, ${NUM_SUPPORTED_ATTRS}], got ${numAttrs}`
    );
  }
  return pub.I[numAttrs - 2];
}

// ---------------------------------------------------------------------------
// CredentialKeyPair
// ---------------------------------------------------------------------------

export interface CredentialKeyPair {
  privateKey: CredentialPrivateKey;
  publicKey: CredentialPublicKey;
}

/**
 * Generate a full credential key pair from randomness.
 */
export function generateKeyPair(randomness: Uint8Array): CredentialKeyPair {
  const privateKey = generatePrivateKey(randomness);
  const publicKey = derivePublicKey(privateKey);
  return { privateKey, publicKey };
}

// ---------------------------------------------------------------------------
// CredentialPublicKey serialization
// ---------------------------------------------------------------------------

/**
 * Serialize a CredentialPublicKey to bytes.
 *
 * Format: [C_W: 32 bytes] [I[0]: 32 bytes] ... [I[5]: 32 bytes] = 7 * 32 = 224 bytes.
 */
export function serializeCredentialPublicKey(pub: CredentialPublicKey): Uint8Array {
  const buf = new Uint8Array(7 * 32);
  let offset = 0;
  buf.set(pub.C_W.toBytes(), offset);
  offset += 32;
  for (const p of pub.I) {
    buf.set(p.toBytes(), offset);
    offset += 32;
  }
  return buf;
}

/**
 * Deserialize a CredentialPublicKey from bytes.
 */
export function deserializeCredentialPublicKey(bytes: Uint8Array): CredentialPublicKey {
  if (bytes.length < 7 * 32) {
    throw new Error('deserializeCredentialPublicKey: too short');
  }
  const C_W = Point.fromBytes(bytes.subarray(0, 32)) as RistrettoPoint;
  const I: RistrettoPoint[] = [];
  for (let i = 0; i < NUM_SUPPORTED_ATTRS - 1; i++) {
    const start = 32 + i * 32;
    I.push(Point.fromBytes(bytes.subarray(start, start + 32)) as RistrettoPoint);
  }
  return { C_W, I };
}
