/**
 * X25519 Public Key Validation
 *
 * Validates X25519 public keys with canonical-range and torsion checks.
 *
 * Two-part validation):
 * 1. scalar_is_in_range(): Reject non-canonical encodings >= p (2^255-19)
 * 2. is_torsion_free(): Montgomery->Edwards conversion + cofactor check
 *
 */

import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToNumberLE, numberToBytesLE } from '@noble/curves/utils.js';
import { Field } from '@noble/curves/abstract/modular.js';
import { EncryptionError, EncryptionErrorCode } from '../../../types/errors';
import type { Base64 } from '../../../types';
import { base64ToBytes } from '../utils';
import type { PublicKey } from '../../../keys/branded';
import { defaultSignalProtocolLogger, type ILogger } from '../../../logger';

/**
 * The prime field for Curve25519: p = 2^255 - 19
 */
export {};
const P = 2n ** 255n - 19n;

/**
 * Field arithmetic mod p for Montgomery <-> Edwards conversions
 */
const Fp = Field(P);

/**
 * Check that a 32-byte X25519 scalar (public key u-coordinate) is in
 * the canonical range [0, p).
 *
 * Rejects:
 * - Values >= 2^255 (high bit of byte 31 is set)
 * - Values in [p, 2^255) (non-canonical encodings of values < 19)
 *
 * @param keyBytes 32-byte X25519 public key (little-endian u-coordinate)
 * @returns true if the value is in [0, p)
 */
export function scalarIsInRange(keyBytes: Uint8Array): boolean {
  // Reject if high bit is set: value >= 2^255
  if ((keyBytes[31] & 0x80) !== 0) return false;

  // Reject non-canonical values in [p, 2^255).
  // In LE, p = [0xED, 0xFF, ..., 0xFF, 0x7F].
  // Values >= p but < 2^255 have:
  // - byte[31] = 0x7F
  // - bytes[1..30] = 0xFF
  // - byte[0] >= 0xED (237)
  if (keyBytes[31] === 0x7f) {
    let allFF = true;
    for (let i = 1; i < 31; i++) {
      if (keyBytes[i] !== 0xff) {
        allFF = false;
        break;
      }
    }
    if (allFF && keyBytes[0] >= 0xed) {
      return false;
    }
  }

  return true;
}

/**
 * Check that an X25519 public key represents a torsion-free point on
 * the curve (i.e., a point of prime order in the large subgroup).
 *
 * Algorithm:
 * 1. Get u-coordinate from key bytes (Montgomery x-coordinate)
 * 2. Convert Montgomery u to Edwards y: y_ed = (u - 1) / (u + 1) mod p
 * 3. Encode as compressed Edwards point (32 bytes LE y, sign bit = 0)
 * 4. Decode with ed25519.Point.fromBytes() -- validates on-curve
 * 5. Call .isTorsionFree() -- multiplies by n, checks for identity
 *
 * Both Edwards points corresponding to a Montgomery u-coordinate have
 * the same order, so checking sign=0 is sufficient.
 *
 * @param keyBytes 32-byte X25519 public key (little-endian u-coordinate)
 * @returns true if the corresponding Edwards point is torsion-free
 */
export function isTorsionFree(
  keyBytes: Uint8Array,
  logger: Required<ILogger> = defaultSignalProtocolLogger
): boolean {
  try {
    const u = bytesToNumberLE(keyBytes);

    // Special case: if u + 1 === 0 mod p (i.e., u = p - 1), the
    // Montgomery -> Edwards mapping is undefined (division by zero).
    // Return false since the mapping does not produce a valid point.
    const denom = Fp.add(u, 1n);
    if (Fp.eql(denom, 0n)) {
      return false;
    }

    // Montgomery u -> Edwards y: y = (u - 1) / (u + 1) mod p
    const yEd = Fp.div(Fp.sub(u, 1n), denom);

    // Encode as compressed Edwards point: 32 bytes LE y-coordinate, sign bit = 0
    const yBytes = numberToBytesLE(yEd, 32);
    // Clear sign bit (high bit of last byte) to select x >= 0
    yBytes[31] = yBytes[31] & 0x7f;

    // Decode Edwards point (validates the point is on the curve)
    const point = ed25519.Point.fromBytes(yBytes);

    // Check torsion-free: multiplies by the group order n and checks identity
    return point.isTorsionFree();
  } catch (err) {
    // Expected for invalid points (e.g. not on curve). Log at debug level
    // so unexpected @noble/curves API changes during upgrades are observable.
    logger.debug('X25519 torsion-free check failed', {
      category: 'E2EE',
      data: { error: err instanceof Error ? err.message : String(err) },
    });
    return false;
  }
}

/**
 * Combined canonical X25519 point validation.
 *
 * Two-part check:
 * 1. scalar_is_in_range(): Reject non-canonical encodings >= p
 * 2. is_torsion_free(): Montgomery->Edwards conversion + cofactor check
 *
 * @param keyBytes 32-byte X25519 public key
 * @returns true if the key is canonical and torsion-free
 */
export function isCanonicalX25519Point(
  keyBytes: Uint8Array,
  logger: Required<ILogger> = defaultSignalProtocolLogger
): boolean {
  if (keyBytes.length !== 32) return false;
  if (!scalarIsInRange(keyBytes)) return false;
  return isTorsionFree(keyBytes, logger);
}

/**
 * Validate an X25519 public key, throwing if non-canonical.
 *
 * Same interface as the previous local validators in x3dh.ts and pqxdh.ts.
 * Uses algebraic torsion-free + scalar range checks instead of a hardcoded
 * low-order point table.
 *
 * @param publicKey Base64-encoded X25519 public key
 * @param context Description for error message (e.g., "remote identity key")
 * @throws EncryptionError with INVALID_DH_KEY code if key is non-canonical
 */
export function validateX25519PublicKey(
  publicKey: PublicKey,
  context: string,
  logger: Required<ILogger> = defaultSignalProtocolLogger
): void {
  const keyBytes = base64ToBytes(publicKey as Base64);
  if (!isCanonicalX25519Point(keyBytes, logger)) {
    throw new EncryptionError(
      `Non-canonical X25519 public key (${context})`,
      EncryptionErrorCode.INVALID_DH_KEY,
      { context, keyLength: keyBytes.length }
    );
  }
}
