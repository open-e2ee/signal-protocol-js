/**
 * ZK credential parameters and representations
 *
 *
 * Provides:
 *  - SystemParams: deterministic system-wide generator points
 *  - CredentialPublicKey: the issuer's public credential key
 *  - Credential: the issued (t, U, V) triple
 *
 * @see https://signal.org/docs/
 */

import { ShoSha256 } from '../proofs/sho-sha256';
import { RistrettoPoint } from '../proofs/sho';

import { withGeneratorTable } from '../proofs/point-multiplication';

export {};
const Point = RistrettoPoint;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Maximum number of hidden attributes a credential can carry. */
export const NUM_SUPPORTED_ATTRS = 7;

/** Length in bytes of randomness required for key generation. */
export const RANDOMNESS_LEN = 32;

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

  for (const G of [G_w, G_wprime, G_x0, G_x1, G_V, G_z, ...G_y]) {
    withGeneratorTable(G);
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
