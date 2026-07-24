/**
 * Profile Key Commitment — Ristretto25519 commitment
 *
 *
 * Commits a profile key to a user identity, producing a 96-byte value
 * (J1 || J2 || J3) that can be verified without knowing the profile key.
 *
 * @see https://eprint.iacr.org/2019/1416.pdf — Signal Private Group System
 */

import { ShoHmacSha256, RistrettoPoint } from '../proofs/sho';
import { profileKeyStructNew } from './profile-key-struct';
import { concatBytes } from '../../../crypto/utils';
export {};
const enc = new TextEncoder();
const Point = RistrettoPoint;

// Fixed input sizes
const PROFILE_KEY_LEN = 32;
const UUID_LEN = 16;

// ---------------------------------------------------------------------------
// System parameters
// ---------------------------------------------------------------------------

/**
 * Hardcoded system parameters for profile key commitment.
 * Three serialized Ristretto points (32 bytes each = 96 bytes total).
 */
const SYSTEM_HARDCODED = new Uint8Array([
  0xa8, 0xca, 0x0b, 0xbd, 0x11, 0x48, 0xc4, 0x66, 0x72, 0x58, 0x60, 0x64, 0x0a, 0xc5, 0x3d, 0x27,
  0x72, 0xb1, 0x4e, 0xea, 0xe0, 0x17, 0x0a, 0x38, 0xc6, 0x2c, 0x7b, 0x3d, 0xd2, 0x9c, 0x3e, 0x4a,
  0x14, 0xb9, 0x46, 0x2d, 0x94, 0x8f, 0x05, 0x94, 0x50, 0x79, 0x9f, 0x4c, 0xc2, 0xa0, 0x6e, 0x55,
  0xde, 0xc8, 0x07, 0x73, 0x56, 0x70, 0xb9, 0x4a, 0x5c, 0xe8, 0x0f, 0x59, 0xf1, 0x95, 0x08, 0x61,
  0xb0, 0xc0, 0xf7, 0xb9, 0x1f, 0x6e, 0xf9, 0xc7, 0x55, 0x60, 0x93, 0xd8, 0x93, 0x0a, 0x86, 0xbd,
  0x36, 0x18, 0x8c, 0xec, 0x74, 0x05, 0x54, 0x65, 0x7d, 0x92, 0xdc, 0xd8, 0x6a, 0xad, 0x25, 0x1c,
]);

let _systemParams: { G_j1: RistrettoPoint; G_j2: RistrettoPoint; G_j3: RistrettoPoint } | undefined;

function getCommitmentSystemParams(): {
  G_j1: RistrettoPoint;
  G_j2: RistrettoPoint;
  G_j3: RistrettoPoint;
} {
  if (_systemParams) return _systemParams;
  const G_j1 = Point.fromBytes(SYSTEM_HARDCODED.slice(0, 32));
  const G_j2 = Point.fromBytes(SYSTEM_HARDCODED.slice(32, 64));
  const G_j3 = Point.fromBytes(SYSTEM_HARDCODED.slice(64, 96));
  _systemParams = { G_j1, G_j2, G_j3 };
  return _systemParams;
}

/**
 * Verify that generating system params from scratch matches the hardcoded values.
 * This ensures no tampering with the system parameters.
 */
export function verifyCommitmentSystemParams(): boolean {
  const sho = new ShoHmacSha256(
    enc.encode('Signal_ZKGroup_20200424_Constant_ProfileKeyCommitment_SystemParams_Generate')
  );
  sho.absorbAndRatchet(new Uint8Array(0));
  const G_j1 = sho.getPoint();
  const G_j2 = sho.getPoint();
  const G_j3 = sho.getPoint();

  const hardcoded = getCommitmentSystemParams();
  return G_j1.equals(hardcoded.G_j1) && G_j2.equals(hardcoded.G_j2) && G_j3.equals(hardcoded.G_j3);
}

// ---------------------------------------------------------------------------
// CommitmentWithSecretNonce
// ---------------------------------------------------------------------------

export interface CommitmentWithSecretNonce {
  readonly J1: RistrettoPoint;
  readonly J2: RistrettoPoint;
  readonly J3: RistrettoPoint;
  readonly j3: bigint;
}

/**
 * Compute j3 scalar from profile key bytes and UID bytes.
 */
function calcJ3(profileKeyBytes: Uint8Array, uidBytes: Uint8Array): bigint {
  const combined = new Uint8Array(PROFILE_KEY_LEN + UUID_LEN);
  combined.set(profileKeyBytes, 0);
  combined.set(uidBytes, PROFILE_KEY_LEN);

  const sho = new ShoHmacSha256(
    enc.encode('Signal_ZKGroup_20200424_ProfileKeyAndUid_ProfileKeyCommitment_Calcj3')
  );
  sho.absorbAndRatchet(combined);
  return sho.getScalar();
}

/**
 * Create a profile key commitment with secret nonce.
 *
 * Returns the commitment points (J1, J2, J3) and the secret nonce j3.
 */
export function commitmentWithSecretNonceNew(
  profileKeyBytes: Uint8Array,
  uidBytes: Uint8Array
): CommitmentWithSecretNonce {
  if (profileKeyBytes.length !== PROFILE_KEY_LEN) {
    throw new Error(`Profile key must be ${PROFILE_KEY_LEN} bytes, got ${profileKeyBytes.length}`);
  }
  if (uidBytes.length !== UUID_LEN) {
    throw new Error(`UID must be ${UUID_LEN} bytes, got ${uidBytes.length}`);
  }

  const pks = profileKeyStructNew(profileKeyBytes, uidBytes);
  const { G_j1, G_j2, G_j3 } = getCommitmentSystemParams();

  const j3 = calcJ3(profileKeyBytes, uidBytes);

  // J1 = j3 * G_j1 + M3
  const J1 = G_j1.multiply(j3).add(pks.M3);
  // J2 = j3 * G_j2 + M4
  const J2 = G_j2.multiply(j3).add(pks.M4);
  // J3 = j3 * G_j3
  const J3 = G_j3.multiply(j3);

  return { J1, J2, J3, j3 };
}

/**
 * Compute a profile key commitment (public part only, 96 bytes).
 *
 * Returns J1 || J2 || J3 as 96 bytes.
 */
export function computeProfileKeyCommitment(
  profileKeyBytes: Uint8Array,
  uidBytes: Uint8Array
): Uint8Array {
  const { J1, J2, J3 } = commitmentWithSecretNonceNew(profileKeyBytes, uidBytes);
  return concatBytes(J1.toBytes(), J2.toBytes(), J3.toBytes());
}
