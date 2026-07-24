/**
 * Stateful Hash Object (SHO) — HMAC-SHA256 variant
 *
 * + ShoExt trait from the profile
 *
 * Implements the SHO construct using HMAC-SHA256 as the internal function.
 * Provides absorb/ratchet/squeeze operations for building ZK proof systems.
 *
 * The ShoExt extensions (getPoint/getScalar) are included here since SHO
 * is the natural home for these Ristretto group element generation methods.
 *
 * @see https://eprint.iacr.org/2019/1416.pdf — Signal Private Group System
 */

import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { ristretto255, ristretto255_hasher } from '@noble/curves/ed25519.js';
export {};
const HASH_LEN = 32;

export interface RistrettoPoint {
  add(other: RistrettoPoint): RistrettoPoint;
  subtract(other: RistrettoPoint): RistrettoPoint;
  multiply(scalar: bigint): RistrettoPoint;
  negate(): RistrettoPoint;
  equals(other: RistrettoPoint): boolean;
  toBytes(): Uint8Array;
}

export interface RistrettoScalarNamespace {
  readonly ORDER: bigint;
  create(value: bigint): bigint;
  inv(value: bigint): bigint;
  neg(value: bigint): bigint;
}

export interface RistrettoPointConstructor {
  readonly BASE: RistrettoPoint;
  readonly ZERO: RistrettoPoint;
  readonly Fn: RistrettoScalarNamespace;
  fromHex(hex: string): RistrettoPoint;
  fromBytes(bytes: Uint8Array): RistrettoPoint;
}

const InternalRistrettoPoint = ristretto255.Point;
export const RistrettoPoint = InternalRistrettoPoint as unknown as RistrettoPointConstructor;

const enum Mode {
  ABSORBING,
  RATCHETED,
}

/**
 * ShoHmacSha256 — Stateful Hash Object built on HMAC-SHA256
 *
 * State machine:
 *   new(label) → RATCHETED
 *   absorb() → ABSORBING (creates new HMAC from cv if was RATCHETED)
 *   ratchet() → RATCHETED (finalizes HMAC into cv)
 *   squeezeAndRatchet() → RATCHETED (only valid from RATCHETED state)
 */
export class ShoHmacSha256 {
  private cv: Uint8Array;
  private hasherKey: Uint8Array;
  private hasherData: Uint8Array[];
  private mode: Mode;

  constructor(label: Uint8Array) {
    this.cv = new Uint8Array(HASH_LEN);
    this.hasherKey = new Uint8Array(HASH_LEN);
    this.hasherData = [];
    this.mode = Mode.RATCHETED;
    this.absorbAndRatchet(label);
  }

  /**
   * Clone this SHO instance (for synthetic nonce generation)
   */
  clone(): ShoHmacSha256 {
    const copy = Object.create(ShoHmacSha256.prototype) as ShoHmacSha256;
    copy.cv = new Uint8Array(this.cv);
    copy.hasherKey = new Uint8Array(this.hasherKey);
    copy.hasherData = this.hasherData.map((d) => new Uint8Array(d));
    copy.mode = this.mode;
    return copy;
  }

  /**
   * Absorb input data into the hash state.
   * If currently RATCHETED, starts a new HMAC keyed with the current cv.
   */
  absorb(input: Uint8Array): void {
    if (this.mode === Mode.RATCHETED) {
      this.hasherKey = new Uint8Array(this.cv);
      this.hasherData = [];
      this.mode = Mode.ABSORBING;
    }
    this.hasherData.push(input);
  }

  /**
   * Ratchet the state: finalize current HMAC into cv.
   * No-op if already RATCHETED.
   */
  ratchet(): void {
    if (this.mode === Mode.RATCHETED) {
      return;
    }
    // Append 0x00 byte, then finalize
    this.hasherData.push(new Uint8Array([0x00]));
    this.cv = this._finalizeHmac();
    this.hasherData = [];
    this.mode = Mode.RATCHETED;
  }

  /**
   * Convenience: absorb + ratchet in one call.
   */
  absorbAndRatchet(input: Uint8Array): void {
    this.absorb(input);
    this.ratchet();
  }

  /**
   * Squeeze output bytes and ratchet.
   * Must be called from RATCHETED state.
   *
   * Uses a counter-mode HMAC expansion:
   *   output[i] = HMAC(cv, i || 0x01)  for each 32-byte block
   *   new_cv = HMAC(cv, outlen || 0x02)
   */
  squeezeAndRatchet(outlen: number): Uint8Array {
    const target = new Uint8Array(outlen);
    this.squeezeAndRatchetInto(target);
    return target;
  }

  /**
   * Squeeze into a pre-allocated buffer and ratchet.
   */
  squeezeAndRatchetInto(target: Uint8Array): void {
    if (this.mode !== Mode.RATCHETED) {
      throw new Error('SHO: squeezeAndRatchet called in non-RATCHETED state');
    }

    const outlen = target.length;
    let offset = 0;
    let i = 0;

    while (i * HASH_LEN < outlen) {
      // HMAC(cv, i_be_u64 || 0x01)
      const counterBuf = new Uint8Array(9);
      const view = new DataView(counterBuf.buffer);
      view.setBigUint64(0, BigInt(i), false); // big-endian u64
      counterBuf[8] = 0x01;
      const digest = hmac(sha256, this.cv, counterBuf);

      const numBytes = Math.min(HASH_LEN, outlen - i * HASH_LEN);
      target.set(digest.subarray(0, numBytes), offset);
      offset += numBytes;
      i++;
    }

    // Ratchet: new cv = HMAC(cv, outlen_be_u64 || 0x02)
    const ratchetBuf = new Uint8Array(9);
    const ratchetView = new DataView(ratchetBuf.buffer);
    ratchetView.setBigUint64(0, BigInt(outlen), false);
    ratchetBuf[8] = 0x02;
    this.cv = hmac(sha256, this.cv, ratchetBuf);
    this.mode = Mode.RATCHETED;
  }

  // --- ShoExt extensions ---

  /**
   * Generate a pseudorandom Ristretto point.
   * Squeezes 64 bytes → Ristretto from_uniform_bytes (Elligator map)
   */
  getPoint(): RistrettoPoint {
    const pointBytes = this.squeezeAndRatchet(64);
    return ristretto255_hasher.deriveToCurve!(pointBytes);
  }

  /**
   * Generate a pseudorandom scalar (mod L).
   * Squeezes 64 bytes → Scalar.from_bytes_mod_order_wide()
   */
  getScalar(): bigint {
    const scalarBytes = this.squeezeAndRatchet(64);
    return bytesToScalarWide(scalarBytes);
  }

  // --- Static convenience ---

  /**
   * One-shot hash: SHO(label).absorbAndRatchet(input).squeezeAndRatchet(outlen)
   */
  static hash(label: Uint8Array, input: Uint8Array, outlen: number): Uint8Array {
    const sho = new ShoHmacSha256(label);
    sho.absorbAndRatchet(input);
    return sho.squeezeAndRatchet(outlen);
  }

  /**
   * Finalize HMAC with accumulated data.
   */
  private _finalizeHmac(): Uint8Array {
    // Concatenate all accumulated data
    let totalLen = 0;
    for (const d of this.hasherData) totalLen += d.length;
    const data = new Uint8Array(totalLen);
    let offset = 0;
    for (const d of this.hasherData) {
      data.set(d, offset);
      offset += d.length;
    }
    return hmac(sha256, this.hasherKey, data);
  }
}

// --- Scalar utilities ---

/**
 * Convert 64 little-endian bytes to a scalar (mod L).
 */
export function bytesToScalarWide(bytes: Uint8Array): bigint {
  if (bytes.length !== 64) {
    throw new Error(`Expected 64 bytes, got ${bytes.length}`);
  }
  let n = 0n;
  for (let i = 63; i >= 0; i--) {
    n = (n << 8n) | BigInt(bytes[i]);
  }
  return RistrettoPoint.Fn.create(n);
}

/**
 * Convert 32 little-endian bytes to a scalar, rejecting non-canonical values (>= L).
 */
export function bytesToScalarCanonical(bytes: Uint8Array): bigint | null {
  if (bytes.length !== 32) return null;
  let n = 0n;
  for (let i = 31; i >= 0; i--) {
    n = (n << 8n) | BigInt(bytes[i]);
  }
  if (n >= RistrettoPoint.Fn.ORDER) return null;
  return n;
}

/**
 * Serialize a scalar to 32 little-endian bytes.
 */
export function scalarToBytes(scalar: bigint): Uint8Array {
  const bytes = new Uint8Array(32);
  let n = scalar;
  for (let i = 0; i < 32; i++) {
    bytes[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return bytes;
}

/**
 * Scalar order L (Ristretto255 / Ed25519 group order).
 */
export const SCALAR_ORDER = RistrettoPoint.Fn.ORDER;

export { ristretto255_hasher };
