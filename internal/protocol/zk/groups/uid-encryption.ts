/**
 * UID encryption — ElGamal encryption of UIDs for group membership
 *
 *
 * Provides domain-specific ElGamal encryption for UidStruct attributes.
 * Uses pinned, domain-separated system parameters.
 *
 * @see https://eprint.iacr.org/2019/1416.pdf — Signal Private Group System
 */

import { ShoHmacSha256, RistrettoPoint } from '../proofs/sho';
import { type Domain, KeyPair, Ciphertext } from '../credentials/attributes';
import type { ShoSha256 } from '../proofs/sho-sha256';
import {
  type ServiceId,
  uidStructFromServiceId,
  seedM1,
  calcM1,
  SERVICE_ID_ACI,
  SERVICE_ID_PNI,
} from './uid-struct';
import { lizardDecode } from './lizard';
export {};
const enc = new TextEncoder();
const Point = RistrettoPoint;

// ---------------------------------------------------------------------------
// Pinned system parameters
// ---------------------------------------------------------------------------

/**
 * Hardcoded system parameters for UID encryption.
 * These are two serialized Ristretto points (32 bytes each = 64 bytes total).
 */
const SYSTEM_HARDCODED = new Uint8Array([
  0xa6, 0x32, 0x4c, 0x36, 0x8d, 0xf7, 0x34, 0x69, 0x11, 0x47, 0x98, 0x13, 0x48, 0xb6, 0xe7, 0xeb,
  0x42, 0xc3, 0x30, 0x7e, 0x71, 0x1b, 0x6c, 0x7e, 0xcc, 0xd3, 0x03, 0x2d, 0x45, 0x69, 0x3f, 0x5a,
  0x04, 0x80, 0x13, 0x52, 0x5b, 0x76, 0x12, 0x4b, 0xf2, 0x64, 0x0c, 0x5e, 0x93, 0x69, 0xc7, 0x6e,
  0xfb, 0xe8, 0x0a, 0xba, 0x2a, 0x24, 0xaa, 0x5d, 0x8e, 0x18, 0xa9, 0x8e, 0xba, 0x14, 0xf8, 0x37,
]);

let _systemParams: { G_a1: RistrettoPoint; G_a2: RistrettoPoint } | undefined;

function getSystemParams(): { G_a1: RistrettoPoint; G_a2: RistrettoPoint } {
  if (_systemParams) return _systemParams;
  const G_a1 = Point.fromBytes(SYSTEM_HARDCODED.slice(0, 32));
  const G_a2 = Point.fromBytes(SYSTEM_HARDCODED.slice(32, 64));
  _systemParams = { G_a1, G_a2 };
  return _systemParams;
}

/**
 * Verify that generating system params from scratch matches the hardcoded values.
 * This ensures no tampering with the system parameters.
 */
export function verifySystemParams(): boolean {
  const sho = new ShoHmacSha256(
    enc.encode('Signal_ZKGroup_20200424_Constant_UidEncryption_SystemParams_Generate')
  );
  sho.absorbAndRatchet(new Uint8Array(0));
  const G_a1 = sho.getPoint();
  const G_a2 = sho.getPoint();

  const hardcoded = getSystemParams();
  return G_a1.equals(hardcoded.G_a1) && G_a2.equals(hardcoded.G_a2);
}

// ---------------------------------------------------------------------------
// UidEncryptionDomain
// ---------------------------------------------------------------------------

export const UidEncryptionDomain: Domain = {
  ID: 'Signal_ZKGroup_20230419_UidEncryption',
  G_a(): [RistrettoPoint, RistrettoPoint] {
    const sys = getSystemParams();
    return [sys.G_a1, sys.G_a2];
  },
};

// Type aliases for clarity
export type UidEncKeyPair = KeyPair;
export type UidEncCiphertext = Ciphertext;

/**
 * Derive a UID encryption keypair from a SHO.
 */
export function deriveUidEncKeyPair(sho: ShoHmacSha256 | ShoSha256): UidEncKeyPair {
  return KeyPair.deriveFrom(sho, UidEncryptionDomain);
}

/**
 * Encrypt a ServiceId using a UID encryption keypair.
 */
export function encryptServiceId(keyPair: UidEncKeyPair, serviceId: ServiceId): UidEncCiphertext {
  const uid = uidStructFromServiceId(serviceId);
  return keyPair.encrypt(uid);
}

/**
 * Decrypt a UID ciphertext back to a ServiceId.
 *
 * Tries both ACI and PNI interpretations of the decoded UUID,
 * comparing the computed M1 point to find the correct variant.
 *
 * @returns The decrypted ServiceId
 * @throws Error if decryption fails or the UUID doesn't match either ACI or PNI
 */
export function decryptServiceId(keyPair: UidEncKeyPair, ciphertext: UidEncCiphertext): ServiceId {
  // Recover M2 from ciphertext
  const M2 = keyPair.decryptToSecondPoint(ciphertext);

  // Lizard-decode M2 back to raw UUID bytes
  const decodedBytes = lizardDecode(M2);
  if (decodedBytes === null) {
    throw new Error('UID decryption failed: lizard decode returned null');
  }

  // Try both ACI and PNI interpretations
  const aciServiceId: ServiceId = {
    kind: SERVICE_ID_ACI,
    uuid: decodedBytes,
  };
  const pniServiceId: ServiceId = {
    kind: SERVICE_ID_PNI,
    uuid: decodedBytes,
  };

  const shoSeed = seedM1();
  const aciM1 = calcM1(shoSeed.clone(), aciServiceId);
  const pniM1 = calcM1(seedM1(), pniServiceId);

  // Recover M1 from ciphertext: M1 = E_A1 / a1 = E_A1 * invert(a1)
  const a1Inv = Point.Fn.inv(keyPair.a1);
  const decryptedM1 = ciphertext.E_A1.multiply(a1Inv);

  if (decryptedM1.equals(aciM1)) {
    return aciServiceId;
  }
  if (decryptedM1.equals(pniM1)) {
    return pniServiceId;
  }

  throw new Error('UID decryption failed: M1 does not match ACI or PNI interpretation');
}
