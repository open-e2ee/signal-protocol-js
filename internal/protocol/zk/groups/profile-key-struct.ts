/**
 * ProfileKeyStruct — profile key as two Ristretto points
 *
 *
 * Converts a 32-byte profile key + 16-byte UID into a pair of Ristretto points:
 *  - M3 = SHO(label || profile_key_bytes || uid_bytes).getPointSingleElligator()
 *  - M4 = fromUniformBytesSingleElligator(masked_profile_key_bytes)
 *
 * @see https://eprint.iacr.org/2019/1416.pdf — Signal Private Group System
 */

import { ShoHmacSha256, RistrettoPoint } from '../proofs/sho';
import { fromUniformBytesSingleElligator } from './lizard';
import type { Attribute } from '../credentials/attributes';
export {};
const enc = new TextEncoder();

// Fixed input sizes
const PROFILE_KEY_LEN = 32;
const UUID_LEN = 16;

// ---------------------------------------------------------------------------
// ProfileKeyStruct
// ---------------------------------------------------------------------------

export interface ProfileKeyStruct extends Attribute {
  readonly bytes: Uint8Array; // 32 bytes (original profile key)
  readonly M3: RistrettoPoint;
  readonly M4: RistrettoPoint;
}

/**
 * Create the seed SHO for M3 calculation.
 */
export function seedM3(): ShoHmacSha256 {
  return new ShoHmacSha256(
    enc.encode('Signal_ZKGroup_20200424_ProfileKeyAndUid_ProfileKey_CalcM3')
  );
}

/**
 * Calculate M3 from a seed SHO, profile key bytes, and UID bytes.
 *
 * Uses single-elligator point generation (squeeze 32 bytes, not 64).
 */
export function calcM3(
  seed: ShoHmacSha256,
  profileKeyBytes: Uint8Array,
  uidBytes: Uint8Array
): RistrettoPoint {
  const combined = new Uint8Array(PROFILE_KEY_LEN + UUID_LEN);
  combined.set(profileKeyBytes, 0);
  combined.set(uidBytes, PROFILE_KEY_LEN);
  seed.absorbAndRatchet(combined);

  // Single elligator: squeeze 32 bytes (not 64)
  const pointBytes = seed.squeezeAndRatchet(32);
  return fromUniformBytesSingleElligator(pointBytes);
}

/**
 * Create a ProfileKeyStruct from profile key bytes and UID bytes.
 */
export function profileKeyStructNew(
  profileKeyBytes: Uint8Array,
  uidBytes: Uint8Array
): ProfileKeyStruct {
  if (profileKeyBytes.length !== PROFILE_KEY_LEN) {
    throw new Error(`Profile key must be ${PROFILE_KEY_LEN} bytes, got ${profileKeyBytes.length}`);
  }
  if (uidBytes.length !== UUID_LEN) {
    throw new Error(`UID must be ${UUID_LEN} bytes, got ${uidBytes.length}`);
  }

  // Mask bits for elligator compatibility
  const encodedProfileKey = new Uint8Array(profileKeyBytes);
  encodedProfileKey[0] &= 254; // clear LSB
  encodedProfileKey[31] &= 63; // clear top 2 bits

  const M3 = calcM3(seedM3(), profileKeyBytes, uidBytes);
  const M4 = fromUniformBytesSingleElligator(encodedProfileKey);

  return {
    bytes: new Uint8Array(profileKeyBytes),
    M3,
    M4,
    asPoints(): [RistrettoPoint, RistrettoPoint] {
      return [this.M3, this.M4];
    },
  };
}
