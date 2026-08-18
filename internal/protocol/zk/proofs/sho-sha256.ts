/**
 * Stateful Hash Object (SHO): SHA-256 "innerpad" variant
 *
 *
 * Uses plain SHA-256 (not HMAC) with an "innerpad" domain separation.
 * Used for deterministic system parameter generation where HMAC keying is not needed.
 *
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { ristretto255_hasher } from '@noble/curves/ed25519.js';
import { RistrettoPoint, bytesToScalarWide } from './sho';
export {};
const BLOCK_LEN = 64;
const HASH_LEN = 32;

const enum Mode {
  ABSORBING,
  RATCHETED,
}

/**
 * ShoSha256: Stateful Hash Object built on plain SHA-256.
 *
 * Same state machine as ShoHmacSha256, but uses SHA-256 with "innerpad"
 * domain separation instead of HMAC.
 */
export class ShoSha256 {
  private cv: Uint8Array;
  private hasherData: Uint8Array[];
  private mode: Mode;

  constructor(label: Uint8Array) {
    this.cv = new Uint8Array(HASH_LEN);
    this.hasherData = [];
    this.mode = Mode.RATCHETED;
    this.absorbAndRatchet(label);
  }

  clone(): ShoSha256 {
    const copy = Object.create(ShoSha256.prototype) as ShoSha256;
    copy.cv = new Uint8Array(this.cv);
    copy.hasherData = this.hasherData.map((d) => new Uint8Array(d));
    copy.mode = this.mode;
    return copy;
  }

  absorb(input: Uint8Array): void {
    if (this.mode === Mode.RATCHETED) {
      // Start absorbing: prepend BLOCK_LEN zero bytes + cv
      this.hasherData = [new Uint8Array(BLOCK_LEN), new Uint8Array(this.cv)];
      this.mode = Mode.ABSORBING;
    }
    this.hasherData.push(input);
  }

  ratchet(): void {
    if (this.mode === Mode.RATCHETED) {
      return;
    }
    // Double hash: SHA256(SHA256(accumulated data))
    const innerHash = sha256(this._concat());
    this.cv = sha256(innerHash);
    this.hasherData = [];
    this.mode = Mode.RATCHETED;
  }

  absorbAndRatchet(input: Uint8Array): void {
    this.absorb(input);
    this.ratchet();
  }

  squeezeAndRatchet(outlen: number): Uint8Array {
    const target = new Uint8Array(outlen);
    this.squeezeAndRatchetInto(target);
    return target;
  }

  squeezeAndRatchetInto(target: Uint8Array): void {
    if (this.mode !== Mode.RATCHETED) {
      throw new Error('ShoSha256: squeezeAndRatchet called in non-RATCHETED state');
    }

    const outlen = target.length;
    let offset = 0;
    let i = 0;

    // Prefix: (BLOCK_LEN - 1) zero bytes + 0x01 byte + cv
    const prefix = new Uint8Array(BLOCK_LEN - 1 + 1 + HASH_LEN);
    prefix[BLOCK_LEN - 1] = 0x01; // domain separator
    prefix.set(this.cv, BLOCK_LEN);

    while (i * HASH_LEN < outlen) {
      // SHA256(prefix || i_be_u64)
      const counterBuf = new Uint8Array(8);
      new DataView(counterBuf.buffer).setBigUint64(0, BigInt(i), false);
      const digest = sha256(this._concatArrays([prefix, counterBuf]));
      const numBytes = Math.min(HASH_LEN, outlen - i * HASH_LEN);
      target.set(digest.subarray(0, numBytes), offset);
      offset += numBytes;
      i++;
    }

    // Ratchet: new cv = SHA256((BLOCK_LEN-1) zeros || 0x02 || cv || outlen_be_u64)
    const ratchetPrefix = new Uint8Array(BLOCK_LEN - 1 + 1 + HASH_LEN + 8);
    ratchetPrefix[BLOCK_LEN - 1] = 0x02; // domain separator
    ratchetPrefix.set(this.cv, BLOCK_LEN);
    new DataView(ratchetPrefix.buffer).setBigUint64(BLOCK_LEN + HASH_LEN, BigInt(outlen), false);
    this.cv = sha256(ratchetPrefix);
    this.mode = Mode.RATCHETED;
  }

  // --- ShoExt extensions ---

  getPoint(): RistrettoPoint {
    const pointBytes = this.squeezeAndRatchet(64);
    return ristretto255_hasher.deriveToCurve!(pointBytes);
  }

  getScalar(): bigint {
    const scalarBytes = this.squeezeAndRatchet(64);
    return bytesToScalarWide(scalarBytes);
  }

  // --- Static convenience ---

  static hash(label: Uint8Array, input: Uint8Array, outlen: number): Uint8Array {
    const sho = new ShoSha256(label);
    sho.absorbAndRatchet(input);
    return sho.squeezeAndRatchet(outlen);
  }

  private _concat(): Uint8Array {
    let totalLen = 0;
    for (const d of this.hasherData) totalLen += d.length;
    const data = new Uint8Array(totalLen);
    let offset = 0;
    for (const d of this.hasherData) {
      data.set(d, offset);
      offset += d.length;
    }
    return data;
  }

  private _concatArrays(arrays: Uint8Array[]): Uint8Array {
    let totalLen = 0;
    for (const a of arrays) totalLen += a.length;
    const result = new Uint8Array(totalLen);
    let offset = 0;
    for (const a of arrays) {
      result.set(a, offset);
      offset += a.length;
    }
    return result;
  }
}
