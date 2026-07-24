/**
 * Incremental ML-KEM-768 for ML-KEM Braid
 *
 * Internal fork of @noble/post-quantum providing split encapsulation
 * for bandwidth-constrained environments:
 * - Encaps1: Generate ct1 using only ek_seed (32 bytes)
 * - Encaps2: Generate ct2 using ek_vector (1152 bytes)
 *
 * @see https://signal.org/docs/specifications/mlkembraid/
 * @license MIT (based on @noble/post-quantum by Paul Miller)
 * @module ml-kem-braid/noble-pq
 */

import { sha3_256, sha3_512, shake128, shake256 } from '@noble/hashes/sha3.js';
import { u32, randomBytes, swap32IfBE } from '@noble/hashes/utils.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { constantTimeEqual } from '../../../../crypto/utils';
import { MLKEM_Q as Q, reduceModQ as mod } from './arithmetic';

// =============================================================================
// Security Helpers
// =============================================================================

/**
 * Best-effort clearing of an owned buffer (3-pass with forced read).
 * JavaScript/JIT runtimes provide no physical-erasure guarantee.
 */
export {};
function secureZero(buffer: Uint8Array): void {
  for (let pass = 0; pass < 3; pass++) {
    for (let i = 0; i < buffer.length; i++) {
      buffer[i] = 0;
    }
  }
  // Force a read so the overwrite remains observable to this function.
  let sum = 0;
  for (let i = 0; i < buffer.length; i++) {
    sum |= buffer[i];
  }
  if (sum !== 0) {
    throw new Error('secureZero: buffer not zeroed');
  }
}

/** Best-effort clearing for owned polynomial storage. */
function secureZeroPolynomials(polynomials: Uint16Array[] | undefined): void {
  if (!polynomials) return;
  for (const polynomial of polynomials) {
    secureZero(new Uint8Array(polynomial.buffer, polynomial.byteOffset, polynomial.byteLength));
  }
}

/** Best-effort clearing for one owned polynomial. */
function secureZeroPolynomial(polynomial: Uint16Array | undefined): void {
  if (!polynomial) return;
  secureZero(new Uint8Array(polynomial.buffer, polynomial.byteOffset, polynomial.byteLength));
}

// =============================================================================
// Constants
// =============================================================================

const N = 256; // Polynomial degree
const K = 3; // ML-KEM-768 security parameter
const ETA1 = 2; // Noise parameter 1
const ETA2 = 2; // Noise parameter 2
const DU = 10; // Compression parameter for u
const DV = 4; // Compression parameter for v
const F = 3303; // Montgomery constant: 128^(-1) mod Q

/** ML-KEM-768 sizes for incremental mode */
export const SIZES = {
  EK_SEED: 32, // rho (public key seed)
  EK_VECTOR: 384 * K, // 1152 bytes (tHat encoded)
  PUBLIC_KEY: 384 * K + 32, // 1184 bytes
  SECRET_KEY: 2400, // dk
  CT1: 32 * DU * K, // 960 bytes (u encoded)
  CT2: 32 * DV, // 128 bytes (v encoded)
  CIPHERTEXT: 32 * DU * K + 32 * DV, // 1088 bytes
  SHARED_SECRET: 32,
  HEK: 32, // SHA3-256 commitment
  ENCAPS_SECRET: 32 + 32 + K * N * 2, // msg + kr_second_half + rHat (serialized)
} as const;

// =============================================================================
// Types
// =============================================================================

export interface KeyGenResult {
  /** Decapsulation key (2400 bytes) */
  dk: Uint8Array;
  /** Encapsulation key seed - rho (32 bytes) */
  ek_seed: Uint8Array;
  /** Encapsulation key vector - tHat (1152 bytes) */
  ek_vector: Uint8Array;
  /** Public key commitment SHA3-256(ek) (32 bytes) */
  hek: Uint8Array;
}

export interface Encaps1Result {
  /** Internal state for Encaps2 */
  encaps_secret: Uint8Array;
  /** First ciphertext component - u (960 bytes) */
  ct1: Uint8Array;
  /** Shared secret (32 bytes) */
  shared_secret: Uint8Array;
}

// =============================================================================
// Internal Helpers (from @noble/post-quantum)
// =============================================================================

const getMask = (bits: number): number => (bits === 32 ? 0xffffffff : ~(-1 << bits) >>> 0);

// Compression functions from FIPS-203
const compress = (d: number) => {
  if (d >= 12) return { encode: (i: number) => i, decode: (i: number) => (i >= Q ? i - Q : i) };
  const a = 2 ** (d - 1);
  return {
    encode: (i: number) => ((i << d) + Q / 2) / Q,
    decode: (i: number) => (i * Q + a) >>> d,
  };
};

// Polynomial encoder
const polyCoder = (d: number, compressor = compress(d)) => {
  const mask = getMask(d);
  const bytesLen = d * (N / 8);
  return {
    bytesLen,
    encode: (poly: Uint16Array): Uint8Array => {
      const r = new Uint8Array(bytesLen);
      let buf = 0;
      let bufLen = 0;
      let pos = 0;
      for (let i = 0; i < poly.length; i++) {
        buf |= (compressor.encode(poly[i]) & mask) << bufLen;
        bufLen += d;
        for (; bufLen >= 8; bufLen -= 8, buf >>= 8) {
          r[pos++] = buf & getMask(bufLen);
        }
      }
      return r;
    },
    decode: (bytes: Uint8Array): Uint16Array => {
      const r = new Uint16Array(N);
      let buf = 0;
      let bufLen = 0;
      let pos = 0;
      for (let i = 0; i < bytes.length; i++) {
        buf |= bytes[i] << bufLen;
        bufLen += 8;
        for (; bufLen >= d; bufLen -= d, buf >>= d) {
          r[pos++] = compressor.decode(buf & mask);
        }
      }
      return r;
    },
  };
};

// Vector coder (for K polynomials)
const vecCoder = (coder: ReturnType<typeof polyCoder>, k: number) => {
  const bytesLen = coder.bytesLen * k;
  return {
    bytesLen,
    encode: (polys: Uint16Array[]): Uint8Array => {
      const r = new Uint8Array(bytesLen);
      for (let i = 0; i < k; i++) {
        r.set(coder.encode(polys[i]), i * coder.bytesLen);
      }
      return r;
    },
    decode: (bytes: Uint8Array): Uint16Array[] => {
      const polys: Uint16Array[] = [];
      for (let i = 0; i < k; i++) {
        polys.push(coder.decode(bytes.subarray(i * coder.bytesLen, (i + 1) * coder.bytesLen)));
      }
      return polys;
    },
  };
};

// Pre-computed NTT tables (bit-reversed zetas)
const ROOT_OF_UNITY = 17;
function computeZetas(): Uint16Array {
  const zetas = new Uint16Array(N);
  for (let i = 0; i < N; i++) {
    let b = 0;
    for (let j = 0; j < 7; j++) {
      b |= ((i >> j) & 1) << (6 - j);
    }
    const p = BigInt(ROOT_OF_UNITY) ** BigInt(b) % BigInt(Q);
    zetas[i] = Number(p) | 0;
  }
  return zetas;
}
const nttZetas = computeZetas();

// NTT forward transform
function nttEncode(r: Uint16Array): Uint16Array {
  let len = 128;
  let k = 1;
  while (len >= 2) {
    for (let start = 0; start < N; start += 2 * len) {
      const zeta = nttZetas[k++];
      for (let j = start; j < start + len; j++) {
        const t = mod(zeta * r[j + len]);
        r[j + len] = mod(r[j] - t);
        r[j] = mod(r[j] + t);
      }
    }
    len >>= 1;
  }
  return r;
}

// NTT inverse transform
function nttDecode(r: Uint16Array): Uint16Array {
  let len = 2;
  let k = N / 2;
  while (len <= 128) {
    for (let start = 0; start < N; start += 2 * len) {
      const zeta = nttZetas[--k];
      for (let j = start; j < start + len; j++) {
        const t = r[j];
        r[j] = mod(t + r[j + len]);
        r[j + len] = mod(zeta * mod(r[j + len] - t));
      }
    }
    len <<= 1;
  }
  for (let i = 0; i < N; i++) {
    r[i] = mod(F * r[i]);
  }
  return r;
}

// Polynomial operations
function polyAdd(a: Uint16Array, b: Uint16Array): void {
  for (let i = 0; i < N; i++) a[i] = mod(a[i] + b[i]);
}

function polySub(a: Uint16Array, b: Uint16Array): void {
  for (let i = 0; i < N; i++) a[i] = mod(a[i] - b[i]);
}

function BaseCaseMultiply(
  a0: number,
  a1: number,
  b0: number,
  b1: number,
  zeta: number
): { c0: number; c1: number } {
  const c0 = mod(a1 * b1 * zeta + a0 * b0);
  const c1 = mod(a0 * b1 + a1 * b0);
  return { c0, c1 };
}

function MultiplyNTTs(f: Uint16Array, g: Uint16Array): Uint16Array {
  for (let i = 0; i < N / 2; i++) {
    let z = nttZetas[64 + (i >> 1)];
    if (i & 1) z = -z;
    const { c0, c1 } = BaseCaseMultiply(f[2 * i + 0], f[2 * i + 1], g[2 * i + 0], g[2 * i + 1], z);
    f[2 * i + 0] = c0;
    f[2 * i + 1] = c1;
  }
  return f;
}

// Sample from centered binomial distribution
function sampleCBD(seed: Uint8Array, nonce: number, eta: number): Uint16Array {
  const buf = shake256
    .create({ dkLen: (eta * N) / 4 })
    .update(seed)
    .update(new Uint8Array([nonce]))
    .digest();
  try {
    const r = new Uint16Array(N);
    const b32 = u32(buf);
    swap32IfBE(b32);
    let len = 0;
    let p = 0;
    let bb = 0;
    let t0 = 0;
    for (let i = 0; i < b32.length; i++) {
      let b = b32[i];
      for (let j = 0; j < 32; j++) {
        bb += b & 1;
        b >>= 1;
        len += 1;
        if (len === eta) {
          t0 = bb;
          bb = 0;
        } else if (len === 2 * eta) {
          r[p++] = mod(t0 - bb);
          bb = 0;
          len = 0;
        }
      }
    }
    return r;
  } finally {
    secureZero(buf);
  }
}

// Sample NTT polynomial from XOF
function SampleNTT(seed: Uint8Array, i: number, j: number): Uint16Array {
  const extSeed = new Uint8Array(seed.length + 2);
  extSeed.set(seed);
  extSeed[seed.length] = i;
  extSeed[seed.length + 1] = j;
  const xof = shake128.create({}).update(extSeed);
  const r = new Uint16Array(N);
  const blockSize = 168; // shake128 block size
  let pos = 0;
  while (pos < N) {
    const b = xof.xofInto(new Uint8Array(blockSize));
    for (let k = 0; pos < N && k + 3 <= b.length; k += 3) {
      const d1 = ((b[k + 0] >> 0) | (b[k + 1] << 8)) & 0xfff;
      const d2 = ((b[k + 1] >> 4) | (b[k + 2] << 4)) & 0xfff;
      if (d1 < Q) r[pos++] = d1;
      if (pos < N && d2 < Q) r[pos++] = d2;
    }
  }
  xof.destroy();
  return r;
}

// Coders
const poly12Coder = polyCoder(12);
const polyDuCoder = polyCoder(DU);
const polyDvCoder = polyCoder(DV);
const poly1Coder = polyCoder(1);
const vecTHatCoder = vecCoder(poly12Coder, K);
const vecUCoder = vecCoder(polyDuCoder, K);

/**
 * Enforce FIPS 203's public-key modulus check before KEM arithmetic:
 * ByteEncode12(ByteDecode12(ek_vector)) must reproduce the supplied bytes.
 * The decoded coefficients are public; the owned canonical byte copy is wiped.
 */
function decodeCanonicalPublicVector(ek_vector: Uint8Array): Uint16Array[] {
  const decoded = vecTHatCoder.decode(ek_vector);
  const canonical = vecTHatCoder.encode(decoded);
  try {
    if (!constantTimeEqual(canonical, ek_vector)) {
      throw new Error('Encaps2: noncanonical ek_vector coefficient encoding');
    }
    return decoded;
  } finally {
    secureZero(canonical);
  }
}

function writeUint16ArrayLE(values: Uint16Array, into: Uint8Array, offset: number): void {
  const view = new DataView(into.buffer, into.byteOffset + offset, values.length * 2);
  for (let i = 0; i < values.length; i++) {
    view.setUint16(i * 2, values[i], true);
  }
}

function readUint16ArrayLE(from: Uint8Array, offset: number, length: number): Uint16Array {
  const values = new Uint16Array(length);
  const view = new DataView(from.buffer, from.byteOffset + offset, length * 2);
  for (let i = 0; i < length; i++) {
    values[i] = view.getUint16(i * 2, true);
  }
  return values;
}

// =============================================================================
// Encryption Helpers (factored for code reuse)
// =============================================================================

/**
 * Sample ephemeral polynomial vector from noise distribution
 * @param rSeed Randomness seed (32 bytes)
 * @returns rHat - polynomial vector in NTT domain
 */
function sampleRHat(rSeed: Uint8Array): Uint16Array[] {
  const rHat: Uint16Array[] = [];
  let completed = false;
  try {
    for (let i = 0; i < K; i++) {
      rHat.push(nttEncode(sampleCBD(rSeed, i, ETA1)));
    }
    completed = true;
    return rHat;
  } finally {
    if (!completed) secureZeroPolynomials(rHat);
  }
}

/**
 * Compute u = A^T * r + e1 (matrix-vector product + noise)
 * @param rHat Ephemeral polynomial vector in NTT domain
 * @param ek_seed Public key seed (rho) for deriving matrix A
 * @param rSeed Seed for sampling noise e1
 * @returns Polynomial vector u (unencoded)
 */
function computeU(rHat: Uint16Array[], ek_seed: Uint8Array, rSeed: Uint8Array): Uint16Array[] {
  const u: Uint16Array[] = [];
  let completed = false;
  try {
    for (let i = 0; i < K; i++) {
      let e1: Uint16Array | undefined = sampleCBD(rSeed, K + i, ETA2);
      const tmp = new Uint16Array(N);
      try {
        for (let j = 0; j < K; j++) {
          const aij = SampleNTT(ek_seed, i, j);
          const product = new Uint16Array(aij);
          try {
            MultiplyNTTs(product, rHat[j]);
            polyAdd(tmp, product);
          } finally {
            secureZeroPolynomial(product);
          }
        }
        polyAdd(e1, nttDecode(tmp));
        u.push(e1);
        e1 = undefined;
      } finally {
        secureZeroPolynomial(tmp);
        secureZeroPolynomial(e1);
      }
    }
    completed = true;
    return u;
  } finally {
    if (!completed) secureZeroPolynomials(u);
  }
}

/**
 * Compute v = t^T * r + e2 + encode(m)
 * @param rHat Ephemeral polynomial vector in NTT domain
 * @param tHat Public key polynomial vector (in NTT domain)
 * @param m Message bytes (32 bytes)
 * @param rSeed Seed for sampling noise e2
 * @returns Polynomial v (unencoded)
 */
function computeV(
  rHat: Uint16Array[],
  tHat: Uint16Array[],
  m: Uint8Array,
  rSeed: Uint8Array
): Uint16Array {
  const tmp = new Uint16Array(N);
  let e2: Uint16Array | undefined;
  let v: Uint16Array | undefined;
  let completed = false;
  try {
    for (let i = 0; i < K; i++) {
      const tHatCopy = new Uint16Array(tHat[i]);
      const rHatCopy = new Uint16Array(rHat[i]);
      try {
        MultiplyNTTs(tHatCopy, rHatCopy);
        polyAdd(tmp, tHatCopy);
      } finally {
        secureZeroPolynomial(tHatCopy);
        secureZeroPolynomial(rHatCopy);
      }
    }
    e2 = sampleCBD(rSeed, 2 * K, ETA2);
    polyAdd(e2, nttDecode(tmp));
    v = poly1Coder.decode(m);
    polyAdd(v, e2);
    completed = true;
    return v;
  } finally {
    secureZeroPolynomial(tmp);
    secureZeroPolynomial(e2);
    if (!completed) secureZeroPolynomial(v);
  }
}

// =============================================================================
// Incremental ML-KEM-768 API
// =============================================================================

/**
 * Generate ML-KEM-768 key pair with separated components
 *
 * Splits the public key into:
 * - ek_seed (rho): 32 bytes - seed for matrix A generation
 * - ek_vector (tHat): 1152 bytes - encoded polynomial vector
 *
 * @param seed Optional 64-byte seed for deterministic generation
 * @returns KeyGenResult with dk, ek_seed, ek_vector, hek
 */
export function KeyGen(seed?: Uint8Array): KeyGenResult {
  // Use standard keygen
  const keyPair = ml_kem768.keygen(seed);

  // Split public key: ML-KEM format is [tHat (1152), rho (32)]
  const ek_vector = keyPair.publicKey.subarray(0, SIZES.EK_VECTOR);
  const ek_seed = keyPair.publicKey.subarray(SIZES.EK_VECTOR);

  // Follow the ML-KEM Braid specification: hash the transmitted seed first,
  // followed by the public-key vector.
  const hek = computeHek(ek_seed, ek_vector);

  return {
    dk: keyPair.secretKey,
    ek_seed: Uint8Array.from(ek_seed),
    ek_vector: Uint8Array.from(ek_vector),
    hek,
  };
}

/**
 * Encapsulation Phase 1: Generate ct1 using only ek_seed
 *
 * Computes:
 * - u = A^T * r + e1 (ct1) using rho to derive A
 * - shared_secret = G(m || hek)[0:32]
 *
 * The shared secret is derived using hek (commitment) rather than
 * the full public key, allowing immediate derivation.
 *
 * @param ek_seed Encapsulation key seed (rho, 32 bytes)
 * @param hek Public key commitment SHA3-256(ek) (32 bytes)
 * @param msg Optional 32-byte message (random if not provided)
 * @returns Encaps1Result with encaps_secret, ct1, shared_secret
 */
export function Encaps1(ek_seed: Uint8Array, hek: Uint8Array, msg?: Uint8Array): Encaps1Result {
  if (ek_seed.length !== SIZES.EK_SEED) {
    throw new Error(`Invalid ek_seed length: expected ${SIZES.EK_SEED}, got ${ek_seed.length}`);
  }
  if (hek.length !== SIZES.HEK) {
    throw new Error(`Invalid hek length: expected ${SIZES.HEK}, got ${hek.length}`);
  }

  // Generate or use provided message (using @noble/hashes portable randomBytes)
  const m = msg ?? randomBytes(32);
  const ownsMessage = msg === undefined;

  // Derive randomness: kr = G(m || hek) = SHA3-512(m || hek)
  const kr = sha3_512.create().update(m).update(hek).digest();
  let sharedSecret: Uint8Array | undefined;
  let rHat: Uint16Array[] | undefined;
  let u: Uint16Array[] | undefined;
  let encapsSecret: Uint8Array | undefined;
  let completed = false;
  try {
    sharedSecret = Uint8Array.from(kr.subarray(0, 32));
    const rSeed = kr.subarray(32, 64);

    // Generate rHat (ephemeral NTT polynomials) using helper.
    rHat = sampleRHat(rSeed);
    u = computeU(rHat, ek_seed, rSeed);
    const ct1 = vecUCoder.encode(u);

    // Serialize encaps_secret: [m (32) | r_seed (32) | rHat (K*N*2)].
    encapsSecret = new Uint8Array(SIZES.ENCAPS_SECRET);
    encapsSecret.set(m, 0);
    encapsSecret.set(rSeed, 32);
    // Explicit little-endian encoding avoids host-dependent persisted state.
    let offset = 64;
    for (let i = 0; i < K; i++) {
      writeUint16ArrayLE(rHat[i], encapsSecret, offset);
      offset += N * 2;
    }

    completed = true;
    return { encaps_secret: encapsSecret, ct1, shared_secret: sharedSecret };
  } finally {
    secureZero(kr);
    secureZeroPolynomials(rHat);
    secureZeroPolynomials(u);
    if (ownsMessage) secureZero(m);
    if (!completed) {
      if (sharedSecret) secureZero(sharedSecret);
      if (encapsSecret) secureZero(encapsSecret);
    }
  }
}

/**
 * Encapsulation Phase 2: Complete with ct2 using ek_vector
 *
 * Verifies the commitment and computes:
 * - v = t^T * r + e2 + m (ct2)
 *
 * @param encaps_secret Internal state from Encaps1
 * @param ek_seed Encapsulation key seed (rho, 32 bytes)
 * @param ek_vector Encapsulation key vector (tHat, 1152 bytes)
 * @param hek Expected public key commitment (32 bytes)
 * @returns ct2 (128 bytes)
 * @throws Error if commitment verification fails
 */
export function Encaps2(
  encaps_secret: Uint8Array,
  ek_seed: Uint8Array,
  ek_vector: Uint8Array,
  hek: Uint8Array
): Uint8Array {
  // Validate inputs
  if (encaps_secret.length !== SIZES.ENCAPS_SECRET) {
    throw new Error(
      `Invalid encaps_secret length: expected ${SIZES.ENCAPS_SECRET}, got ${encaps_secret.length}`
    );
  }
  if (ek_vector.length !== SIZES.EK_VECTOR) {
    throw new Error(
      `Invalid ek_vector length: expected ${SIZES.EK_VECTOR}, got ${ek_vector.length}`
    );
  }
  if (ek_seed.length !== SIZES.EK_SEED) {
    throw new Error(`Invalid ek_seed length: expected ${SIZES.EK_SEED}, got ${ek_seed.length}`);
  }
  if (hek.length !== SIZES.HEK) {
    throw new Error(`Invalid hek length: expected ${SIZES.HEK}, got ${hek.length}`);
  }

  // Verify commitment with a best-effort full-scan comparison.
  const computedHek = computeHek(ek_seed, ek_vector);
  try {
    if (!constantTimeEqual(computedHek, hek)) {
      throw new Error('Encaps2: commitment verification failed (hek mismatch)');
    }
  } finally {
    secureZero(computedHek);
  }

  // Reject noncanonical public coefficients before reading encaps_secret.
  const tHat = decodeCanonicalPublicVector(ek_vector);

  const rHat: Uint16Array[] = [];
  let v: Uint16Array | undefined;
  try {
    // After public validation, encaps_secret ownership is consumed for this
    // one-shot operation and cleared on both success and arithmetic failure.
    const m = encaps_secret.subarray(0, 32);
    const rSeed = encaps_secret.subarray(32, 64);
    let offset = 64;
    for (let i = 0; i < K; i++) {
      rHat.push(readUint16ArrayLE(encaps_secret, offset, N));
      offset += N * 2;
    }

    v = computeV(rHat, tHat, m, rSeed);
    return polyDvCoder.encode(v);
  } finally {
    secureZeroPolynomials(rHat);
    secureZeroPolynomial(v);
    secureZero(encaps_secret);
  }
}

/**
 * Re-encrypt message to verify ciphertext (FO transform)
 *
 * @param m Message to encrypt
 * @param rSeed Randomness seed
 * @param ek_seed Encapsulation key seed (rho)
 * @param tHat Public key polynomial vector (in NTT domain)
 * @returns { ct1, ct2 } Re-encrypted ciphertext components
 */
function reencrypt(
  m: Uint8Array,
  rSeed: Uint8Array,
  ek_seed: Uint8Array,
  tHat: Uint16Array[]
): { ct1: Uint8Array; ct2: Uint8Array } {
  let rHat: Uint16Array[] | undefined;
  let u: Uint16Array[] | undefined;
  let v: Uint16Array | undefined;
  try {
    rHat = sampleRHat(rSeed);
    u = computeU(rHat, ek_seed, rSeed);
    v = computeV(rHat, tHat, m, rSeed);
    return {
      ct1: vecUCoder.encode(u),
      ct2: polyDvCoder.encode(v),
    };
  } finally {
    secureZeroPolynomials(rHat);
    secureZeroPolynomials(u);
    secureZeroPolynomial(v);
  }
}

/**
 * Decapsulation: Recover shared secret from ct1 + ct2
 *
 * Custom implementation that applies the SAME PRF as Encaps1:
 * shared_secret = SHA3-512(m' || hek)[0:32]
 *
 * Includes Fujisaki-Okamoto transform for CCA security.
 *
 * @param dk Decapsulation key (2400 bytes)
 * @param ct1 First ciphertext component (960 bytes)
 * @param ct2 Second ciphertext component (128 bytes)
 * @returns shared_secret (32 bytes)
 */
export function Decaps(dk: Uint8Array, ct1: Uint8Array, ct2: Uint8Array): Uint8Array {
  // Validate inputs
  if (dk.length !== SIZES.SECRET_KEY) {
    throw new Error(`Invalid dk length: expected ${SIZES.SECRET_KEY}, got ${dk.length}`);
  }
  if (ct1.length !== SIZES.CT1) {
    throw new Error(`Invalid ct1 length: expected ${SIZES.CT1}, got ${ct1.length}`);
  }
  if (ct2.length !== SIZES.CT2) {
    throw new Error(`Invalid ct2 length: expected ${SIZES.CT2}, got ${ct2.length}`);
  }

  // Extract public components from the secret key (ML-KEM-768 format):
  // dk = [sHat (1152) | pk (1184) | H(pk) (32) | z (32)]. Verify H(pk)
  // before decoding or using the secret polynomial vector.
  const pk = dk.subarray(SIZES.EK_VECTOR, SIZES.EK_VECTOR + SIZES.PUBLIC_KEY);
  const storedPublicKeyHash = dk.subarray(
    SIZES.EK_VECTOR + SIZES.PUBLIC_KEY,
    SIZES.EK_VECTOR + SIZES.PUBLIC_KEY + SIZES.HEK
  );
  const computedPublicKeyHash = sha3_256(pk);
  try {
    if (!constantTimeEqual(computedPublicKeyHash, storedPublicKeyHash)) {
      throw new Error('Decaps: decapsulation key public-key hash mismatch');
    }
  } finally {
    secureZero(computedPublicKeyHash);
  }

  const z = dk.subarray(SIZES.SECRET_KEY - 32); // Last 32 bytes

  // Extract ek_seed and ek_vector from pk (ML-KEM format: [tHat | rho])
  const ek_vector = pk.subarray(0, SIZES.EK_VECTOR);
  const ek_seed = pk.subarray(SIZES.EK_VECTOR);

  // The stored decapsulation-key hash above is standard ML-KEM H(ek), whose
  // serialized public-key order is ek_vector || ek_seed. Braid deliberately
  // defines a different protocol commitment: SHA3-256(ek_seed || ek_vector).
  // Do not reuse storedPublicKeyHash as hek.
  const hek = computeHek(ek_seed, ek_vector);
  let sHat: Uint16Array[] | undefined;
  let u: Uint16Array[] | undefined;
  let v: Uint16Array | undefined;
  let tmp: Uint16Array | undefined;
  let w: Uint16Array | undefined;
  let mPrime: Uint8Array | undefined;
  let kr: Uint8Array | undefined;
  let tHat: Uint16Array[] | undefined;
  let ct1Prime: Uint8Array | undefined;
  let ct2Prime: Uint8Array | undefined;
  let ctFull: Uint8Array | undefined;
  let candidateSecret: Uint8Array | undefined;
  let rejectionSecret: Uint8Array | undefined;
  let result: Uint8Array | undefined;
  let completed = false;
  try {
    sHat = vecTHatCoder.decode(dk.subarray(0, SIZES.EK_VECTOR));
    u = vecUCoder.decode(ct1);
    v = polyDvCoder.decode(ct2);

    // Compute m' = v - s^T * u in NTT domain.
    tmp = new Uint16Array(N);
    for (let i = 0; i < K; i++) {
      const sHatCopy = new Uint16Array(sHat[i]);
      const uNtt = nttEncode(new Uint16Array(u[i]));
      try {
        MultiplyNTTs(sHatCopy, uNtt);
        polyAdd(tmp, sHatCopy);
      } finally {
        secureZeroPolynomial(sHatCopy);
        secureZeroPolynomial(uNtt);
      }
    }

    w = new Uint16Array(v);
    polySub(w, nttDecode(tmp));
    mPrime = poly1Coder.encode(w);
    kr = sha3_512.create().update(mPrime).update(hek).digest();

    // Re-encrypt to verify the Fujisaki-Okamoto transform.
    const rSeed = kr.subarray(32, 64);
    tHat = vecTHatCoder.decode(ek_vector);
    ({ ct1: ct1Prime, ct2: ct2Prime } = reencrypt(mPrime, rSeed, ek_seed, tHat));

    // Evaluate both comparisons before combining to avoid short-circuit work.
    const ct1Valid = constantTimeEqual(ct1, ct1Prime);
    const ct2Valid = constantTimeEqual(ct2, ct2Prime);
    const validityBit = Number(ct1Valid) & Number(ct2Valid);

    // Always derive both candidates before fixed-work selection. JavaScript/JIT
    // execution still does not provide a hard constant-time guarantee.
    ctFull = new Uint8Array(SIZES.CIPHERTEXT);
    ctFull.set(ct1, 0);
    ctFull.set(ct2, SIZES.CT1);
    candidateSecret = Uint8Array.from(kr.subarray(0, 32));
    // FIPS 203 implicit-rejection secret: J(z || c).
    rejectionSecret = shake256.create({ dkLen: 32 }).update(z).update(ctFull).digest();
    result = new Uint8Array(32);

    // 0xFF for valid, 0x00 for invalid. Selection has no validity-dependent
    // branch or array bound; both candidate buffers are always read in full.
    const candidateMask = (-validityBit & 0xff) >>> 0;
    const rejectionMask = candidateMask ^ 0xff;
    for (let i = 0; i < result.length; i++) {
      result[i] =
        (candidateSecret[i]! & candidateMask) | (rejectionSecret[i]! & rejectionMask);
    }
    completed = true;
    return result;
  } finally {
    secureZeroPolynomials(sHat);
    secureZeroPolynomials(u);
    secureZeroPolynomial(v);
    secureZeroPolynomial(tmp);
    secureZeroPolynomial(w);
    secureZeroPolynomials(tHat);
    if (mPrime) secureZero(mPrime);
    if (kr) secureZero(kr);
    if (ct1Prime) secureZero(ct1Prime);
    if (ct2Prime) secureZero(ct2Prime);
    if (ctFull) secureZero(ctFull);
    if (candidateSecret) secureZero(candidateSecret);
    if (rejectionSecret) secureZero(rejectionSecret);
    secureZero(hek);
    if (!completed && result) secureZero(result);
  }
}

// =============================================================================
// Utility Functions
// =============================================================================

/**
 * Compute the public-key commitment defined by the ML-KEM Braid specification.
 *
 * The specification requires SHA3-256(ek_seed || ek_vector). Keep this order
 * explicit: it is a protocol input order, not serialized-public-key order.
 *
 * @param ek_seed Encapsulation key seed (32 bytes)
 * @param ek_vector Encapsulation key vector (1152 bytes)
 * @returns SHA3-256(ek_seed || ek_vector)
 */
export function computeHek(ek_seed: Uint8Array, ek_vector: Uint8Array): Uint8Array {
  return sha3_256.create().update(ek_seed).update(ek_vector).digest();
}

/**
 * Reconstruct full public key from components
 *
 * @param ek_seed Encapsulation key seed (32 bytes)
 * @param ek_vector Encapsulation key vector (1152 bytes)
 * @returns Full public key (1184 bytes)
 */
export function reconstructPublicKey(ek_seed: Uint8Array, ek_vector: Uint8Array): Uint8Array {
  const pk = new Uint8Array(SIZES.PUBLIC_KEY);
  pk.set(ek_vector, 0);
  pk.set(ek_seed, SIZES.EK_VECTOR);
  return pk;
}

/**
 * Standard (non-incremental) encapsulation using full public key
 *
 * Convenience function that wraps Encaps1 + Encaps2.
 *
 * @param publicKey Full public key (1184 bytes)
 * @param msg Optional 32-byte message
 * @returns { cipherText, sharedSecret }
 */
export function Encapsulate(
  publicKey: Uint8Array,
  msg?: Uint8Array
): { cipherText: Uint8Array; sharedSecret: Uint8Array } {
  const ek_vector = publicKey.subarray(0, SIZES.EK_VECTOR);
  const ek_seed = publicKey.subarray(SIZES.EK_VECTOR);
  // Follow the ML-KEM Braid specification's seed-first HEK derivation.
  const hek = computeHek(ek_seed, ek_vector);

  const { encaps_secret, ct1, shared_secret } = Encaps1(ek_seed, hek, msg);
  const ct2 = Encaps2(encaps_secret, ek_seed, ek_vector, hek);

  const cipherText = new Uint8Array(SIZES.CIPHERTEXT);
  cipherText.set(ct1, 0);
  cipherText.set(ct2, SIZES.CT1);

  return { cipherText, sharedSecret: shared_secret };
}
