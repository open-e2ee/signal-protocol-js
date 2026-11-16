/**
 * ECVRF-EDWARDS25519-SHA512-TAI verification (RFC 9381 sections 5.2 to 5.5,
 * suite 0x03), the VRF of the identity log index.
 *
 * - Suite string 0x03. Domain separators 0x01 (encode to curve), 0x02
 *   (challenge), 0x03 (proof to hash), and 0x00 (back).
 * - Encode to curve is try-and-increment (section 5.4.1.1). The salt is the
 *   public key as given. The counter is one byte, so the loop stops after 256
 *   attempts. Each candidate takes the first 32 hash bytes, is multiplied by
 *   the cofactor 8, and an identity result is skipped.
 * - The challenge is the first 16 bytes of the challenge hash over the public
 *   key, H, Gamma, U, and V. The public key and Gamma enter the hash as the
 *   bytes of the input.
 * - The proof is Gamma (32 bytes) || c (16 bytes, little-endian) || s (32
 *   bytes, little-endian). s must be less than the group order.
 * - validate_key is TRUE: a public key that does not decode, or that has
 *   small order, is invalid.
 * - Points decode as RFC 8032 section 5.1.3 requires: y >= p, and x = 0 with
 *   the sign bit set, are invalid.
 *
 * The functions use only public inputs, so they need no constant-time code.
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToNumberLE, concatBytes, equalBytes } from '@noble/curves/utils.js';
import { sha512 } from '@noble/hashes/sha2.js';

const SUITE = 0x03;
const ENCODE_FRONT = 0x01;
const CHALLENGE_FRONT = 0x02;
const PROOF_TO_HASH_FRONT = 0x03;
const BACK = 0x00;

const POINT_BYTES = 32;
const CHALLENGE_BYTES = 16;

/** The bytes of a VRF public key. */
export const VRF_PUBLIC_KEY_BYTES = POINT_BYTES;
/** The bytes of a VRF proof. */
export const VRF_PROOF_BYTES = POINT_BYTES + CHALLENGE_BYTES + 32;
/** The bytes of a VRF output (beta). */
export const VRF_OUTPUT_BYTES = 64;

const Point = ed25519.Point;
type Point = typeof Point.BASE;

function decodePoint(bytes: Uint8Array): Point | null {
  try {
    return Point.fromBytes(bytes, false);
  } catch {
    return null;
  }
}

function encodeToCurve(salt: Uint8Array, alpha: Uint8Array): Point | null {
  for (let counter = 0; counter <= 0xff; counter += 1) {
    const hash = sha512(
      concatBytes(Uint8Array.of(SUITE, ENCODE_FRONT), salt, alpha, Uint8Array.of(counter, BACK))
    );
    const candidate = decodePoint(hash.subarray(0, POINT_BYTES));
    if (candidate === null) continue;
    const point = candidate.clearCofactor();
    if (!point.is0()) return point;
  }
  return null;
}

/**
 * ECVRF_verify with validate_key TRUE (RFC 9381 section 5.3). Returns the
 * 64-byte output beta when the proof is valid for the public key and alpha,
 * and `null` when it is not.
 */
export function verifyVrfProof(
  publicKey: Uint8Array,
  alpha: Uint8Array,
  proof: Uint8Array
): Uint8Array | null {
  if (publicKey.length !== VRF_PUBLIC_KEY_BYTES || proof.length !== VRF_PROOF_BYTES) return null;
  const y = decodePoint(publicKey);
  if (y === null || y.isSmallOrder()) return null;
  const gammaBytes = proof.subarray(0, POINT_BYTES);
  const challengeBytes = proof.subarray(POINT_BYTES, POINT_BYTES + CHALLENGE_BYTES);
  const gamma = decodePoint(gammaBytes);
  if (gamma === null) return null;
  const s = bytesToNumberLE(proof.subarray(POINT_BYTES + CHALLENGE_BYTES));
  if (s >= Point.Fn.ORDER) return null;
  const c = bytesToNumberLE(challengeBytes);
  const h = encodeToCurve(publicKey, alpha);
  if (h === null) return null;
  const u = Point.BASE.multiplyUnsafe(s).subtract(y.multiplyUnsafe(c));
  const v = h.multiplyUnsafe(s).subtract(gamma.multiplyUnsafe(c));
  const expected = sha512(
    concatBytes(
      Uint8Array.of(SUITE, CHALLENGE_FRONT),
      publicKey,
      h.toBytes(),
      gammaBytes,
      u.toBytes(),
      v.toBytes(),
      Uint8Array.of(BACK)
    )
  ).subarray(0, CHALLENGE_BYTES);
  if (!equalBytes(expected, challengeBytes)) return null;
  return sha512(
    concatBytes(
      Uint8Array.of(SUITE, PROOF_TO_HASH_FRONT),
      gamma.clearCofactor().toBytes(),
      Uint8Array.of(BACK)
    )
  );
}
