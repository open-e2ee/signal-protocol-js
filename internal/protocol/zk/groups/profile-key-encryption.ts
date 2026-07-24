/**
 * Profile key encryption — ElGamal encryption of profile keys for group membership
 *
 *
 * Provides domain-specific ElGamal encryption for ProfileKeyStruct attributes.
 * Uses pinned, domain-separated system parameters.
 *
 * Decryption recovers the original 32-byte profile key by:
 *  1. Decrypting M4 from the ciphertext
 *  2. Running decode_253_bits to get 8 candidate field elements
 *  3. Brute-forcing the 3 masked bits (8 variations per candidate = 64 total)
 *  4. Checking which candidate matches the expected M3 point
 *
 * @see https://eprint.iacr.org/2019/1416.pdf — Signal Private Group System
 */

import { ShoHmacSha256, RistrettoPoint } from '../proofs/sho';
import { type Domain, KeyPair, Ciphertext } from '../credentials/attributes';
import type { ShoSha256 } from '../proofs/sho-sha256';
import { decode253Bits } from './lizard';
import { profileKeyStructNew, seedM3, calcM3 } from './profile-key-struct';
export {};
const enc = new TextEncoder();
const Point = RistrettoPoint;

// ---------------------------------------------------------------------------
// Pinned system parameters
// ---------------------------------------------------------------------------

/**
 * Hardcoded system parameters for profile key encryption.
 * Two serialized Ristretto points (32 bytes each = 64 bytes total).
 */
const SYSTEM_HARDCODED = new Uint8Array([
  0xf6, 0xba, 0xa3, 0x17, 0xce, 0x18, 0x39, 0xc9, 0x3d, 0x61, 0x7e, 0x0c, 0xd8, 0x37, 0xd1, 0x9d,
  0xa9, 0xc8, 0xa4, 0xc5, 0x20, 0xbf, 0x7c, 0x51, 0xb1, 0xe6, 0xc2, 0xcb, 0x2a, 0x04, 0x9c, 0x61,
  0x2e, 0x01, 0x75, 0x89, 0x4c, 0x87, 0x30, 0xb2, 0x03, 0xab, 0x3b, 0xd9, 0x8e, 0xcb, 0x2d, 0x81,
  0xab, 0xac, 0xb6, 0x5f, 0x8a, 0x61, 0x24, 0xf4, 0x97, 0x71, 0xd1, 0x4a, 0x98, 0x52, 0x12, 0x0c,
]);

let _systemParams: { G_b1: RistrettoPoint; G_b2: RistrettoPoint } | undefined;

function getSystemParams(): { G_b1: RistrettoPoint; G_b2: RistrettoPoint } {
  if (_systemParams) return _systemParams;
  const G_b1 = Point.fromBytes(SYSTEM_HARDCODED.slice(0, 32));
  const G_b2 = Point.fromBytes(SYSTEM_HARDCODED.slice(32, 64));
  _systemParams = { G_b1, G_b2 };
  return _systemParams;
}

/**
 * Verify that generating system params from scratch matches the hardcoded values.
 */
export function verifySystemParams(): boolean {
  const sho = new ShoHmacSha256(
    enc.encode('Signal_ZKGroup_20200424_Constant_ProfileKeyEncryption_SystemParams_Generate')
  );
  sho.absorbAndRatchet(new Uint8Array(0));
  const G_b1 = sho.getPoint();
  const G_b2 = sho.getPoint();

  const hardcoded = getSystemParams();
  return G_b1.equals(hardcoded.G_b1) && G_b2.equals(hardcoded.G_b2);
}

// ---------------------------------------------------------------------------
// ProfileKeyEncryptionDomain
// ---------------------------------------------------------------------------

export const ProfileKeyEncryptionDomain: Domain = {
  ID: 'Signal_ZKGroup_20231011_ProfileKeyEncryption',
  G_a(): [RistrettoPoint, RistrettoPoint] {
    const sys = getSystemParams();
    return [sys.G_b1, sys.G_b2];
  },
};

// Type aliases for clarity
export type ProfileKeyEncKeyPair = KeyPair;
export type ProfileKeyEncCiphertext = Ciphertext;

/**
 * Derive a profile key encryption keypair from a SHO.
 */
export function deriveProfileKeyEncKeyPair(sho: ShoHmacSha256 | ShoSha256): ProfileKeyEncKeyPair {
  return KeyPair.deriveFrom(sho, ProfileKeyEncryptionDomain);
}

/**
 * Encrypt a profile key using a profile key encryption keypair.
 */
export function encryptProfileKey(
  keyPair: ProfileKeyEncKeyPair,
  profileKeyBytes: Uint8Array,
  uidBytes: Uint8Array
): ProfileKeyEncCiphertext {
  const profileKey = profileKeyStructNew(profileKeyBytes, uidBytes);
  return keyPair.encrypt(profileKey);
}

/**
 * Decrypt a profile key ciphertext back to the original 32-byte profile key.
 *
 * This is computationally expensive: it tries up to 64 candidate profile keys
 * (8 field element candidates x 8 bit variations for the 3 masked bits).
 *
 * @returns The decrypted ProfileKeyStruct (with .bytes being the profile key)
 * @throws Error if decryption fails
 */
export function decryptProfileKey(
  keyPair: ProfileKeyEncKeyPair,
  ciphertext: ProfileKeyEncCiphertext,
  uidBytes: Uint8Array
): Uint8Array {
  // Recover M4 from ciphertext
  const M4 = keyPair.decryptToSecondPoint(ciphertext);

  // Recover M3 target: M1 = E_A1 / a1
  const a1Inv = Point.Fn.inv(keyPair.a1);
  const targetM3 = ciphertext.E_A1.multiply(a1Inv);

  // Get candidate field elements from inverse elligator
  const { mask, candidates } = decode253Bits(M4);

  const seedSho = seedM3();
  let nFound = 0;
  let result = new Uint8Array(32);

  // Try each valid candidate
  for (let i = 0; i < 8; i++) {
    const isValidFe = (mask >> i) & 1;
    if (!isValidFe) continue;

    const profileKeyCandidate = candidates[i]; // 32-byte field element

    // Try all 8 combinations of the 3 masked bits
    for (let j = 0; j < 8; j++) {
      const pk = new Uint8Array(profileKeyCandidate);
      if ((j >> 2) & 1) pk[0] |= 0x01; // bit 0 of byte 0
      if ((j >> 1) & 1) pk[31] |= 0x80; // bit 7 of byte 31
      if (j & 1) pk[31] |= 0x40; // bit 6 of byte 31

      const M3 = calcM3(seedSho.clone(), pk, uidBytes);

      if (M3.equals(targetM3)) {
        result = pk;
        nFound++;
      }
    }
  }

  if (nFound === 1) {
    return result;
  }

  throw new Error(`Profile key decryption failed: found ${nFound} candidates (expected 1)`);
}
