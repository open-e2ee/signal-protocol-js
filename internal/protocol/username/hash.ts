/**
 * Username hashing (Ristretto25519 + discriminators), compatible with the reference implementation
 *
 * Uses Ristretto25519.
 * multiscalar multiplication.
 *
 * Hash: point = s0*G1 + s1*G2 + s2*G3 → toBytes() → 32 bytes
 *
 * Format: nickname.discriminator (e.g., "cool_tiger.42")
 *
 */

import { sha512 } from '@noble/hashes/sha2.js';
import { bytesToScalarWide, RistrettoPoint } from '../zk/proofs/sho';
export {};
const Fn = RistrettoPoint.Fn;

// ---------------------------------------------------------------------------
// Username-hashing constants
// ---------------------------------------------------------------------------

export const G1: RistrettoPoint = RistrettoPoint.fromHex(
  '60b993663a3daecc4c852f533547e305388c2a50a58393ea277de4abf3de543a'
);
export const G2: RistrettoPoint = RistrettoPoint.fromHex(
  'f2b6f1c826fa3640206f3b58b2286bdefdfda6a54ff902f204a72de737d26157'
);
export const G3: RistrettoPoint = RistrettoPoint.fromHex(
  '0606bd3abfce4e9617d448fb2caeb6cc028ec9a2b62b10b3d9eb2948da6f3f53'
);

// Discriminator bucket ranges
const DISCRIMINATOR_RANGES: readonly [number, number][] = [
  [1, 100],
  [100, 1_000],
  [1_000, 10_000],
  [10_000, 100_000],
  [100_000, 1_000_000],
  [1_000_000, 10_000_000],
  [10_000_000, 100_000_000],
  [100_000_000, 1_000_000_000],
];
const CANDIDATES_PER_RANGE = [4, 3, 3, 2, 2, 2, 2, 2] as const; // total = 20

export const USERNAME_HASH_LENGTH = 32;
export const MAX_NICKNAME_LENGTH = 48;
const MIN_NICKNAME_LENGTH = 3;
const MAX_DISCRIMINATOR = 999_999_999;

// ---------------------------------------------------------------------------
// Internal: char → base-37 byte
// ---------------------------------------------------------------------------

function charToByte(c: string): number {
  if (c === '_') return 1;
  const code = c.charCodeAt(0);
  // a-z → 2-27
  if (code >= 0x61 && code <= 0x7a) return code - 0x61 + 2;
  // 0-9 → 28-37
  if (code >= 0x30 && code <= 0x39) return code - 0x30 + 28;
  throw new Error(`Invalid nickname character: '${c}'`);
}

// ---------------------------------------------------------------------------
// Internal: nickname → base-37 scalar
// ---------------------------------------------------------------------------

function toBase37Scalar(nickname: string): bigint {
  const lower = nickname.toLowerCase();
  const bytes = Array.from(lower, charToByte);

  // Horner with special first-byte handling:
  // - For bytes[1..N] in reverse: scalar = scalar * 37 + bytes[i]
  // - Final: scalar = scalar * 27 + bytes[0]
  //
  // The first byte uses 27 (not 37) because the first character cannot be a
  // digit (values 1-27 only).
  let scalar = 0n;
  for (let i = bytes.length - 1; i >= 1; i--) {
    scalar = scalar * 37n + BigInt(bytes[i]);
  }
  scalar = scalar * 27n + BigInt(bytes[0]);

  return Fn.create(scalar); // mod L
}

// ---------------------------------------------------------------------------
// Internal: SHA-512 scalar
// ---------------------------------------------------------------------------

function usernameShaScalar(nickname: string, discriminator: number): bigint {
  const lower = nickname.toLowerCase();
  const nicknameBytes = new TextEncoder().encode(lower);

  // input = nickname_bytes || 0x00 || discriminator_as_u64_big_endian_8_bytes
  const input = new Uint8Array(nicknameBytes.length + 1 + 8);
  input.set(nicknameBytes, 0);
  input[nicknameBytes.length] = 0x00;

  // discriminator as u64 big-endian (8 bytes)
  const dv = new DataView(input.buffer, input.byteOffset + nicknameBytes.length + 1, 8);
  // Write as two 32-bit values (JS does not have native u64 write)
  dv.setUint32(0, 0, false); // high 32 bits = 0 (discriminator < 1B)
  dv.setUint32(4, discriminator, false); // low 32 bits

  const digest = sha512(input); // 64 bytes
  return bytesToScalarWide(digest); // 64 LE bytes → scalar mod L
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Hash a username (nickname + discriminator) to a Ristretto25519 point.
 *
 * hash = s0*G1 + s1*G2 + s2*G3
 * where:
 *   s0 = SHA-512(nickname || 0x00 || disc_u64_be) mod L
 *   s1 = base37_polynomial(nickname) mod L
 *   s2 = discriminator (as scalar)
 *
 * @returns 32-byte compressed Ristretto point
 */
export function hashUsername(nickname: string, discriminator: number): Uint8Array {
  validateNickname(nickname);
  validateDiscriminator(discriminator);

  const s0 = usernameShaScalar(nickname, discriminator);
  const s1 = toBase37Scalar(nickname);
  const s2 = Fn.create(BigInt(discriminator));

  const point = G1.multiply(s0).add(G2.multiply(s1)).add(G3.multiply(s2));
  return point.toBytes();
}

/**
 * Compute the three scalars used in the username hash multiscalar multiplication.
 *
 * hash = s0*G1 + s1*G2 + s2*G3
 *
 * Useful for constructing ZK proofs of username knowledge.
 */
export function usernameScalars(
  nickname: string,
  discriminator: number
): { s0: bigint; s1: bigint; s2: bigint } {
  validateNickname(nickname);
  validateDiscriminator(discriminator);
  return {
    s0: usernameShaScalar(nickname, discriminator),
    s1: toBase37Scalar(nickname),
    s2: Fn.create(BigInt(discriminator)),
  };
}

/**
 * Parse a "nickname.discriminator" string into its components.
 * Splits on the LAST dot to handle edge cases.
 */
export function parseUsername(username: string): {
  nickname: string;
  discriminator: number;
} {
  const lastDot = username.lastIndexOf('.');
  if (lastDot === -1) {
    throw new Error(`Invalid username format: missing dot separator in "${username}"`);
  }

  const nickname = username.substring(0, lastDot);
  const discStr = username.substring(lastDot + 1);

  if (discStr.length === 0) {
    throw new Error(`Invalid username format: empty discriminator in "${username}"`);
  }

  // Parse discriminator
  const discriminator = parseInt(discStr, 10);
  if (isNaN(discriminator)) {
    throw new Error(`Invalid discriminator: "${discStr}" is not a number`);
  }

  // Validate components (will throw on invalid)
  validateNickname(nickname);
  validateDiscriminator(discriminator);

  // The username format requires at least two discriminator digits.
  // Single-digit discriminators are invalid (must be zero-padded: "01" not "1")
  if (discStr.length < 2) {
    throw new Error(`Invalid discriminator: must be at least 2 digits ("${discStr}")`);
  }

  // Reject invalid leading zeros: 3+ digit values with leading zero (e.g., "001")
  // 2-digit leading zeros are OK ("01"-"09")
  if (discStr.length >= 3 && discStr[0] === '0') {
    throw new Error(
      `Invalid discriminator: leading zeros not allowed for 3+ digit values ("${discStr}")`
    );
  }

  return { nickname, discriminator };
}

/**
 * Format a nickname and discriminator into the display string.
 * Zero-pads discriminators to minimum 2 digits.
 */
export function formatUsername(nickname: string, discriminator: number): string {
  const discStr =
    discriminator < 10
      ? `0${discriminator}` // zero-pad single digits: 7 → "07"
      : String(discriminator);
  return `${nickname}.${discStr}`;
}

/**
 * Generate 20 discriminator candidates across the configured bucket ranges.
 * Biased toward short discriminators (7 of 20 are 2-3 digits).
 */
export function generateDiscriminatorCandidates(): number[] {
  const candidates: number[] = [];
  const buf = new Uint32Array(1);

  for (let i = 0; i < DISCRIMINATOR_RANGES.length; i++) {
    const [min, max] = DISCRIMINATOR_RANGES[i];
    const count = CANDIDATES_PER_RANGE[i];
    const range = max - min;

    // Sample without replacement within each bucket
    const used = new Set<number>();
    for (let j = 0; j < count; j++) {
      let value: number;
      do {
        crypto.getRandomValues(buf);
        value = min + (buf[0] % range);
      } while (used.has(value));
      used.add(value);
      candidates.push(value);
    }
  }

  return candidates;
}

/**
 * Validate a nickname for the SDK username format.
 * - 3-48 characters
 * - Only [a-zA-Z0-9_]
 * - Cannot start with a digit
 */
export function validateNickname(nickname: string): void {
  if (nickname.length < MIN_NICKNAME_LENGTH) {
    throw new Error(
      `Nickname too short: ${nickname.length} chars (minimum ${MIN_NICKNAME_LENGTH})`
    );
  }
  if (nickname.length > MAX_NICKNAME_LENGTH) {
    throw new Error(`Nickname too long: ${nickname.length} chars (maximum ${MAX_NICKNAME_LENGTH})`);
  }
  if (/^\d/.test(nickname)) {
    throw new Error('Nickname cannot start with a digit');
  }
  if (!/^[a-zA-Z0-9_]+$/.test(nickname)) {
    throw new Error('Nickname can only contain letters, digits, and underscores');
  }
}

/**
 * Validate a discriminator for the SDK username format.
 * - Must be >= 1 (zero is invalid)
 * - Must be <= 999,999,999
 */
export function validateDiscriminator(discriminator: number): void {
  if (!Number.isInteger(discriminator) || discriminator < 1) {
    throw new Error(`Invalid discriminator: must be a positive integer, got ${discriminator}`);
  }
  if (discriminator > MAX_DISCRIMINATOR) {
    throw new Error(`Discriminator too large: ${discriminator} (maximum ${MAX_DISCRIMINATOR})`);
  }
}
