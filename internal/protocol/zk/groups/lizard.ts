/**
 * Lizard encoding: embeds/extracts 16 bytes into/from Ristretto255 points.
 *
 * Provides `lizardEncode`, `lizardDecode`,
 * `fromUniformBytesSingleElligator`, and `decode253Bits`.
 *
 * Uses field arithmetic from @noble/curves (GF(2^255-19)) and implements:
 * - Forward Ristretto elligator map (calcElligatorRistrettoMap equivalent)
 * - Ristretto encode/decode (for internal coordinate access)
 * - Jacobi quartic operations (for inverse elligator)
 * - Inverse Ristretto elligator map
 *
 * @see https://ristretto.group/formulas/elligator.html
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { ristretto255 } from '@noble/curves/ed25519.js';
import type { RistrettoPoint, RistrettoPointConstructor } from '../proofs/sho';
export {};
const Point = ristretto255.Point as unknown as RistrettoPointConstructor;

// ---------------------------------------------------------------------------
// Field GF(2^255 - 19)
// ---------------------------------------------------------------------------

const Fp = ristretto255.Point.Fp;
const P = Fp.ORDER; // 2^255 - 19

const _0n = 0n;
const _1n = 1n;
const _2n = 2n;

// Edwards curve parameter: d = -121665/121666 mod p
const D = BigInt('0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3');

// sqrt(-1) mod p
const SQRT_M1 = BigInt(
  '19681161376707505956807079304988542015446066515923890162744021073123829784752'
);

// Field helpers (thin wrappers for readability)
const fmod = (n: bigint): bigint => Fp.create(n);
const fmul = (a: bigint, b: bigint): bigint => Fp.mul(a, b);
const fadd = (a: bigint, b: bigint): bigint => Fp.add(a, b);
const fsub = (a: bigint, b: bigint): bigint => Fp.sub(a, b);
const fsqr = (a: bigint): bigint => Fp.sqr(a);
const fneg = (a: bigint): bigint => Fp.neg(a);
const finv = (a: bigint): bigint => Fp.inv(a);
const fisNeg = (a: bigint): boolean => (a & _1n) === _1n; // odd = "negative"

// Byte serialization (little-endian, 32 bytes)
function feFromBytes(bytes: Uint8Array): bigint {
  let n = _0n;
  for (let i = 31; i >= 0; i--) {
    n = (n << 8n) | BigInt(bytes[i]);
  }
  // Clear top bit (255 bits max) and reduce mod p
  n &= (_1n << 255n) - _1n;
  return fmod(n);
}

function feToBytes(n: bigint): Uint8Array {
  const reduced = fmod(n);
  const bytes = new Uint8Array(32);
  let v = reduced;
  for (let i = 0; i < 32; i++) {
    bytes[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return bytes;
}

// ---------------------------------------------------------------------------
// Ristretto constants (matching noble-curves internal values)
// ---------------------------------------------------------------------------

// sqrt(a*d - 1) where a = -1
const SQRT_AD_MINUS_ONE = BigInt(
  '25063068953384623474111414158702152701244531502492656460079210482610430750235'
);

// 1 / sqrt(a - d) where a = -1
const INVSQRT_A_MINUS_D = BigInt(
  '54469307008909316920995813868745141605393597292927456921205312896311721017578'
);

// 1 - d^2
const ONE_MINUS_D_SQ = BigInt(
  '1159843021668779879193775521855586647937357759715417654439879720876111806838'
);

// (d - 1)^2
const D_MINUS_ONE_SQ = BigInt(
  '40440834346308536858101042469323190826248399146238708352240133220865137265952'
);

// ---------------------------------------------------------------------------
// Lizard constants (computed from curve params)
// ---------------------------------------------------------------------------

// (d+1)/(d-1)
const DP1_OVER_DM1 = fmul(fadd(D, _1n), finv(fsub(D, _1n)));

// sqrt(i*d) where i = sqrt(-1)
const SQRT_ID = (() => {
  const id = fmul(SQRT_M1, D);
  // i*d is a square mod p. Compute sqrt and force positive (even)
  const r = Fp.sqrt(id);
  return fisNeg(r) ? fneg(r) : r;
})();

// -2/sqrt(a-d) = -2 * (1/sqrt(a-d))
const MDOUBLE_INVSQRT_A_MINUS_D = fneg(fmul(_2n, INVSQRT_A_MINUS_D));

// -1/sqrt(1+d)
// -1/sqrt(1+d). Negate the inverse of the canonical sqrt
const MINVSQRT_ONE_PLUS_D = fneg(finv(Fp.sqrt(fadd(_1n, D))));

// -2*i/sqrt(a-d)
const MIDOUBLE_INVSQRT_A_MINUS_D = fmul(fneg(fmul(_2n, SQRT_M1)), INVSQRT_A_MINUS_D);

// ---------------------------------------------------------------------------
// Square-root utilities
// ---------------------------------------------------------------------------

/**
 * Compute x^((p-5)/8) mod p.
 * Uses the same optimized chain as noble-curves' ed25519_pow_2_252_3.
 */
function powP58(x: bigint): bigint {
  // (p-5)/8 = (2^255 - 24) / 8 = 2^252 - 3
  return Fp.pow(x, (P - 5n) / 8n);
}

/**
 * Compute sqrt(u/v), or sqrt(i*u/v) when u/v is not square.
 *
 * Returns:
 * - { isValid: true, value: +sqrt(u/v) }  if u/v is a square
 * - { isValid: false, value: +sqrt(i*u/v) } if u/v is a non-square
 *
 * The value is always non-negative (even).
 */
function sqrtRatioI(u: bigint, v: bigint): { isValid: boolean; value: bigint } {
  const v3 = fmul(fmul(v, v), v); // v^3
  const v7 = fmul(fmul(v3, v3), v); // v^7
  const pow = powP58(fmul(u, v7)); // (u*v^7)^((p-5)/8)
  let x = fmul(fmul(u, v3), pow); // u * v^3 * (u*v^7)^((p-5)/8)

  const vx2 = fmul(v, fsqr(x)); // v * x^2
  const root1 = x;
  const root2 = fmul(x, SQRT_M1);

  const useRoot1 = vx2 === u;
  const useRoot2 = vx2 === fneg(u);
  const noRoot = vx2 === fmul(fneg(u), SQRT_M1);

  if (useRoot1) x = root1;
  if (useRoot2 || noRoot) x = root2;
  if (fisNeg(x)) x = fneg(x);

  return { isValid: useRoot1 || useRoot2, value: x };
}

/**
 * Computes sqrt(1/self). The inverse square root.
 *
 * Returns:
 * - { isValid: true, value: +sqrt(1/x) }   if x is a nonzero square
 * - { isValid: false, value: 0 }            if x is zero
 * - { isValid: false, value: +sqrt(i/x) }   if x is a nonzero non-square
 */
function inverseSqrt(x: bigint): { isValid: boolean; value: bigint } {
  return sqrtRatioI(_1n, x);
}

// ---------------------------------------------------------------------------
// Forward elligator map: field element → Edwards point
// ---------------------------------------------------------------------------

interface EdwardsCoords {
  X: bigint;
  Y: bigint;
  Z: bigint;
  T: bigint;
}

/**
 * Elligator Ristretto flavor: maps a field element to an Edwards point.
 * Equivalent to noble-curves' calcElligatorRistrettoMap.
 *
 * @see https://ristretto.group/formulas/elligator.html
 */
function elligatorRistrettoFlavor(r0: bigint): EdwardsCoords {
  const r = fmod(SQRT_M1 * r0 * r0); // 1
  const Ns = fmod((r + _1n) * ONE_MINUS_D_SQ); // 2
  let c = P - _1n; // -1 mod p // 3
  const Dv = fmod((c - D * r) * fmod(r + D)); // 4
  const { isValid: Ns_D_is_sq, value: sqrtRatio } = sqrtRatioI(Ns, Dv); // 5
  let s = sqrtRatio;
  let s_ = fmod(s * r0); // 6
  if (!fisNeg(s_)) s_ = fneg(s_);
  if (!Ns_D_is_sq) s = s_; // 7
  if (!Ns_D_is_sq) c = r; // 8
  const Nt = fmod(c * (r - _1n) * D_MINUS_ONE_SQ - Dv); // 9
  const s2 = fmul(s, s);
  const W0 = fmod((s + s) * Dv); // 10
  const W1 = fmod(Nt * SQRT_AD_MINUS_ONE); // 11
  const W2 = fmod(_1n - s2); // 12
  const W3 = fmod(_1n + s2); // 13
  return {
    X: fmod(W0 * W3),
    Y: fmod(W2 * W1),
    Z: fmod(W1 * W3),
    T: fmod(W0 * W2),
  };
}

// ---------------------------------------------------------------------------
// Ristretto encode (compress): Edwards (X,Y,Z,T) → 32 bytes
// ---------------------------------------------------------------------------

/**
 * Compress an Edwards point to Ristretto255 bytes.
 * Matches noble-curves' _RistrettoPoint.toBytes().
 */
function ristrettoEncode(pt: EdwardsCoords): Uint8Array {
  let { X, Y } = pt;
  const { Z, T } = pt;
  const u1 = fmod(fmod(Z + Y) * fmod(Z - Y)); // 1
  const u2 = fmod(X * Y); // 2
  const u2sq = fmod(u2 * u2);
  const { value: invsqrtVal } = sqrtRatioI(_1n, fmod(u1 * u2sq)); // 3
  const D1 = fmod(invsqrtVal * u1); // 4
  const D2 = fmod(invsqrtVal * u2); // 5
  const zInv = fmod(D1 * D2 * T); // 6
  let Ds: bigint; // 7
  if (fisNeg(fmod(T * zInv))) {
    const _x = fmod(Y * SQRT_M1);
    const _y = fmod(X * SQRT_M1);
    X = _x;
    Y = _y;
    Ds = fmod(D1 * INVSQRT_A_MINUS_D);
  } else {
    Ds = D2; // 8
  }
  if (fisNeg(fmod(X * zInv))) Y = fneg(Y); // 9
  let s = fmod((Z - Y) * Ds); // 10
  if (fisNeg(s)) s = fneg(s);
  return feToBytes(s); // 11
}

// ---------------------------------------------------------------------------
// Ristretto decode (decompress): 32 bytes → Edwards (X,Y,Z,T)
// ---------------------------------------------------------------------------

/**
 * Decompress Ristretto255 bytes to Edwards (X,Y,Z,T) coordinates.
 * Matches noble-curves' _RistrettoPoint.fromBytes() (but returns coords, not a point).
 */
function ristrettoDecode(bytes: Uint8Array): EdwardsCoords {
  const s = feFromBytes(bytes);
  // Verify canonical encoding and non-negative
  const reencoded = feToBytes(s);
  for (let i = 0; i < 32; i++) {
    if (reencoded[i] !== bytes[i]) throw new Error('non-canonical ristretto255 encoding');
  }
  if (fisNeg(s)) throw new Error('negative ristretto255 encoding');

  const a = P - _1n; // a = -1
  const s2 = fmod(s * s);
  const u1 = fmod(_1n + a * s2); // 1 + a*s^2 = 1 - s^2
  const u2 = fmod(_1n - a * s2); // 1 - a*s^2 = 1 + s^2
  const u1_2 = fmod(u1 * u1);
  const u2_2 = fmod(u2 * u2);
  const v = fmod(a * D * u1_2 - u2_2); // a*d*u1^2 - u2^2

  // invertSqrt(n) = sqrtRatioI(1, n)
  const invSqrt = sqrtRatioI(_1n, fmod(v * u2_2));

  const Dx = fmod(invSqrt.value * u2);
  const Dy = fmod(invSqrt.value * Dx * v);
  let x = fmod((s + s) * Dx);
  if (fisNeg(x)) x = fneg(x);
  const y = fmod(u1 * Dy);
  const t = fmod(x * y);

  if (!invSqrt.isValid || fisNeg(t) || y === _0n) {
    throw new Error('invalid ristretto255 encoding');
  }

  return { X: x, Y: y, Z: _1n, T: t };
}

// ---------------------------------------------------------------------------
// Jacobi quartic (for inverse elligator)
// ---------------------------------------------------------------------------

interface JacobiPoint {
  S: bigint;
  T: bigint;
}

/**
 * Find the 4 Jacobi quartic points corresponding to the Ristretto coset
 * of the given Edwards point.
 *
 */
function toJacobiQuarticRistretto(X: bigint, Y: bigint, Z: bigint): JacobiPoint[] {
  const x2 = fsqr(X);
  const y2 = fsqr(Y);
  const y4 = fsqr(y2);
  const z2 = fsqr(Z);
  const z_min_y = fsub(Z, Y);
  const z_pl_y = fadd(Z, Y);
  const z2_min_y2 = fsub(z2, y2);

  // gamma := 1/sqrt( Y^4 * X^2 * (Z^2 - Y^2) )
  const gammaInput = fmul(fmul(y4, x2), z2_min_y2);
  const { value: gamma } = inverseSqrt(gammaInput);

  const den = fmul(gamma, y2);

  const s_over_x = fmul(den, z_min_y);
  const sp_over_xp = fmul(den, z_pl_y);

  let s0 = fmul(s_over_x, X);
  let s1 = fmul(fneg(sp_over_xp), X);

  // t_0 := -2/sqrt(-d-1) * Z * sOverX
  // t_1 := -2/sqrt(-d-1) * Z * spOverXp
  const tmp1 = fmul(MDOUBLE_INVSQRT_A_MINUS_D, Z);
  let t0 = fmul(tmp1, s_over_x);
  let t1 = fmul(tmp1, sp_over_xp);

  // den := -1/sqrt(1+d) * (Y^2 - Z^2) * gamma
  // Note: Y^2 - Z^2 = -(Z^2 - Y^2)
  const den2 = fmul(fmul(fneg(z2_min_y2), MINVSQRT_ONE_PLUS_D), gamma);

  // Same as before but with the substitution (X, Y, Z) = (Y, X, i*Z)
  const iz = fmul(SQRT_M1, Z);
  const iz_min_x = fsub(iz, X);
  const iz_pl_x = fadd(iz, X);

  const s_over_y = fmul(den2, iz_min_x);
  const sp_over_yp = fmul(den2, iz_pl_x);

  let s2 = fmul(s_over_y, Y);
  let s3 = fmul(fneg(sp_over_yp), Y);

  // t_2 := -2/sqrt(-d-1) * i*Z * sOverY
  // t_3 := -2/sqrt(-d-1) * i*Z * spOverYp
  const tmp2 = fmul(MDOUBLE_INVSQRT_A_MINUS_D, iz);
  let t2 = fmul(tmp2, s_over_y);
  let t3 = fmul(tmp2, sp_over_yp);

  // Special case: X=0 or Y=0
  const xIsZero = X === _0n;
  const yIsZero = Y === _0n;
  const x_or_y_is_zero = xIsZero || yIsZero;

  if (x_or_y_is_zero) {
    s0 = _0n;
    s1 = _0n;
    t0 = _1n;
    t1 = _1n;
    s2 = _1n;
    s3 = fneg(_1n);
    t2 = MIDOUBLE_INVSQRT_A_MINUS_D;
    t3 = MIDOUBLE_INVSQRT_A_MINUS_D;
  }

  return [
    { S: s0, T: t0 },
    { S: s1, T: t1 },
    { S: s2, T: t2 },
    { S: s3, T: t3 },
  ];
}

/**
 * Compute the inverse of the Elligator map for a single Jacobi quartic point.
 * Returns the field element r such that elligator(r) maps to the corresponding
 * Edwards point, or { isValid: false } if no such r exists.
 */
function jacobiElligatorInv(jc: JacobiPoint): { isValid: boolean; value: bigint } {
  let out = _0n;
  let ret = false;
  let done = false;

  // Special case: S = 0
  const s_is_zero = jc.S === _0n;
  const t_equals_one = jc.T === _1n;
  if (s_is_zero) {
    out = t_equals_one ? SQRT_ID : _0n;
    ret = true;
    done = true;
  }

  if (!done) {
    // a := (T+1) * (d+1)/(d-1)
    const a = fmul(fadd(jc.T, _1n), DP1_OVER_DM1);
    const a2 = fsqr(a);

    // invSqY := (s^4 - a^2) * i
    // y := invsqrt(invSqY) = sqrt(1/invSqY) if invSqY is QR
    // No preimage exists if invSqY is not a QR.
    const s2 = fsqr(jc.S);
    const s4 = fsqr(s2);
    const invSqY = fmul(fsub(s4, a2), SQRT_M1);
    const { isValid: sq, value: y } = inverseSqrt(invSqY);
    if (!sq) {
      return { isValid: false, value: _0n };
    }

    // x := (a + sign(s)*s^2) * y
    let pms2 = s2;
    if (fisNeg(jc.S)) pms2 = fneg(pms2);
    let x = fmul(fadd(a, pms2), y);
    // Make x non-negative
    if (fisNeg(x)) x = fneg(x);
    out = x;
    ret = true;
  }

  return { isValid: ret, value: out };
}

/**
 * Compute the dual of a Jacobi quartic point: (S, T) → (-S, -T)
 */
function jacobiDual(jc: JacobiPoint): JacobiPoint {
  return { S: fneg(jc.S), T: fneg(jc.T) };
}

// ---------------------------------------------------------------------------
// Inverse elligator: Ristretto point → up to 8 field elements
// ---------------------------------------------------------------------------

/**
 * Compute the at most 8 field elements that map to the given Ristretto point
 * via the forward elligator.
 */
function elligatorRistrettoFlavorInverse(pt: EdwardsCoords): { mask: number; values: bigint[] } {
  let mask = 0;
  const jcs = toJacobiQuarticRistretto(pt.X, pt.Y, pt.Z);
  const ret: bigint[] = new Array(8).fill(_1n);

  for (let i = 0; i < 4; i++) {
    const { isValid: ok1, value: fe1 } = jacobiElligatorInv(jcs[i]);
    ret[2 * i] = fe1;
    if (ok1) mask |= 1 << (2 * i);

    const dual = jacobiDual(jcs[i]);
    const { isValid: ok2, value: fe2 } = jacobiElligatorInv(dual);
    ret[2 * i + 1] = fe2;
    if (ok2) mask |= 1 << (2 * i + 1);
  }

  return { mask, values: ret };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Apply a single Ristretto elligator map to 32 bytes.
 *
 * @param bytes 32 bytes interpreted as a field element
 * @returns A Ristretto255 point
 */
export function fromUniformBytesSingleElligator(bytes: Uint8Array): RistrettoPoint {
  if (bytes.length !== 32) throw new Error(`Expected 32 bytes, got ${bytes.length}`);
  const fe = feFromBytes(bytes);
  const edwards = elligatorRistrettoFlavor(fe);
  const compressed = ristrettoEncode(edwards);
  return Point.fromBytes(compressed);
}

/**
 * Decode a Ristretto point into at most 8 candidate 32-byte field elements.
 * Used by profile key decryption.
 *
 * @returns { mask, candidates } where bit j of mask indicates candidates[j] is valid
 */
export function decode253Bits(point: RistrettoPoint): { mask: number; candidates: Uint8Array[] } {
  const bytes = point.toBytes();
  const coords = ristrettoDecode(bytes);
  const { mask, values } = elligatorRistrettoFlavorInverse(coords);

  const candidates: Uint8Array[] = [];
  for (let j = 0; j < 8; j++) {
    candidates.push(feToBytes(values[j]));
  }
  return { mask, candidates };
}

/**
 * Encode 16 bytes of data to a Ristretto255 point using the Lizard method.
 * The data is embedded in the middle of a field element (bytes 8..24),
 * with a SHA-256 hash providing the surrounding bytes.
 *
 * @param data Exactly 16 bytes
 * @returns A Ristretto255 point encoding the data
 */
export function lizardEncode(data: Uint8Array): RistrettoPoint {
  if (data.length !== 16) throw new Error(`Expected 16 bytes, got ${data.length}`);

  const feBytes = new Uint8Array(32);

  // Hash the 16 bytes with SHA-256 to fill surrounding bytes
  const digest = sha256(data);
  feBytes.set(digest, 0); // SHA-256(data) fills all 32 bytes
  // Overwrite bytes 8..24 with the actual data
  feBytes.set(data, 8);
  // Mask bits for Elligator compatibility
  feBytes[0] &= 254; // clear LSB (make positive since elligator(r) == elligator(-r))
  feBytes[31] &= 63; // clear top 2 bits (fit in 253 bits)

  const fe = feFromBytes(feBytes);
  const edwards = elligatorRistrettoFlavor(fe);
  const compressed = ristrettoEncode(edwards);
  return Point.fromBytes(compressed);
}

/**
 * Decode 16 bytes of data from a Ristretto255 point using the Lizard method.
 * Inverts lizardEncode by finding a valid field element preimage and
 * extracting bytes 8..24.
 *
 * @returns The original 16 bytes, or null if the point does not encode valid data
 */
export function lizardDecode(point: RistrettoPoint): Uint8Array | null {
  const result = new Uint8Array(16);
  const { mask, candidates } = decode253Bits(point);

  let nFound = 0;

  for (let j = 0; j < 8; j++) {
    const ok = (mask >> j) & 1;
    if (!ok) continue;

    const buf2 = candidates[j]; // 32-byte field element

    // Verify Lizard structure: SHA-256(buf2[8..24]) should match surrounding bytes
    const h = new Uint8Array(32);
    const hashResult = sha256(buf2.subarray(8, 24));
    h.set(hashResult, 0);
    h.set(buf2.subarray(8, 24), 8);
    h[0] &= 254;
    h[31] &= 63;

    // Constant-time comparison (but we branch at the end)
    let match = true;
    for (let i = 0; i < 32; i++) {
      if (h[i] !== buf2[i]) {
        match = false;
        break;
      }
    }

    if (match) {
      result.set(buf2.subarray(8, 24));
      nFound++;
    }
  }

  return nFound === 1 ? result : null;
}
