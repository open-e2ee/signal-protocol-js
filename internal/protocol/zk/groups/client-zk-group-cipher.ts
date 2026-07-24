/**
 * ClientZkGroupCipher — client-side encryption/decryption of UIDs and profile keys
 *
 *
 * This is a convenience wrapper that provides named encrypt/decrypt operations
 * for UIDs and profile keys using GroupSecretParams. Each method delegates to
 * the corresponding function in group-params.ts and handles serialization of
 * the ciphertext into the wire format expected by the Signal server.
 *
 * Wire formats:
 *  - UuidCiphertext:       65 bytes = 1 byte ServiceIdKind + 32 bytes E_A1 + 32 bytes E_A2
 *  - ProfileKeyCiphertext: 65 bytes = 1 byte reserved (0x00) + 32 bytes E_A1 + 32 bytes E_A2
 *
 * @see https://eprint.iacr.org/2019/1416.pdf — Signal Private Group System
 */

import type { GroupSecretParams } from './group-params';
import {
  encryptServiceId,
  decryptServiceId,
  encryptProfileKey,
  decryptProfileKey,
  UUID_CIPHERTEXT_LEN,
  PROFILE_KEY_CIPHERTEXT_LEN,
} from './group-params';
import type { ServiceId } from './uid-struct';
import type { UidEncCiphertext } from './uid-encryption';
import type { ProfileKeyEncCiphertext } from './profile-key-encryption';
import { UidEncryptionDomain } from './uid-encryption';
import { ProfileKeyEncryptionDomain } from './profile-key-encryption';
import { RistrettoPoint } from '../proofs/sho';
import { Ciphertext } from '../credentials/attributes';

// ---------------------------------------------------------------------------
// Serialized ciphertext types
// ---------------------------------------------------------------------------

/**
 * Serialized UUID ciphertext (65 bytes).
 *
 * Layout: [ServiceIdKind (1 byte)] [E_A1 (32 bytes)] [E_A2 (32 bytes)]
 */
export {};
export type UuidCiphertext = Uint8Array;

/**
 * Serialized profile key ciphertext (65 bytes).
 *
 * Layout: [reserved 0x00 (1 byte)] [E_A1 (32 bytes)] [E_A2 (32 bytes)]
 */
export type ProfileKeyCiphertext = Uint8Array;

// ---------------------------------------------------------------------------
// Serialization helpers
// ---------------------------------------------------------------------------

/**
 * Serialize a UID ElGamal ciphertext into the 65-byte UuidCiphertext wire format.
 *
 * @param kind - The ServiceIdKind byte (0x00 for ACI, 0x01 for PNI)
 * @param ciphertext - The ElGamal ciphertext containing E_A1 and E_A2
 * @returns 65-byte UuidCiphertext
 */
function serializeUuidCiphertext(kind: number, ciphertext: UidEncCiphertext): UuidCiphertext {
  const result = new Uint8Array(UUID_CIPHERTEXT_LEN);
  result[0] = kind;
  result.set(ciphertext.E_A1.toBytes(), 1);
  result.set(ciphertext.E_A2.toBytes(), 33);
  return result;
}

/**
 * Deserialize a 65-byte UuidCiphertext back into a ServiceIdKind and ElGamal ciphertext.
 *
 * @param data - 65-byte serialized UuidCiphertext
 * @returns Object containing the kind byte and the reconstituted Ciphertext
 * @throws Error if data is not exactly 65 bytes
 */
function deserializeUuidCiphertext(data: UuidCiphertext): {
  kind: number;
  ciphertext: UidEncCiphertext;
} {
  if (data.length !== UUID_CIPHERTEXT_LEN) {
    throw new Error(`UuidCiphertext must be ${UUID_CIPHERTEXT_LEN} bytes, got ${data.length}`);
  }
  const kind = data[0];
  const E_A1 = RistrettoPoint.fromBytes(data.slice(1, 33));
  const E_A2 = RistrettoPoint.fromBytes(data.slice(33, 65));
  return { kind, ciphertext: new Ciphertext(E_A1, E_A2, UidEncryptionDomain) };
}

/**
 * Serialize a profile key ElGamal ciphertext into the 65-byte ProfileKeyCiphertext wire format.
 *
 * @param ciphertext - The ElGamal ciphertext containing E_A1 and E_A2
 * @returns 65-byte ProfileKeyCiphertext
 */
function serializeProfileKeyCiphertext(ciphertext: ProfileKeyEncCiphertext): ProfileKeyCiphertext {
  const result = new Uint8Array(PROFILE_KEY_CIPHERTEXT_LEN);
  result[0] = 0x00; // reserved byte
  result.set(ciphertext.E_A1.toBytes(), 1);
  result.set(ciphertext.E_A2.toBytes(), 33);
  return result;
}

/**
 * Deserialize a 65-byte ProfileKeyCiphertext back into an ElGamal ciphertext.
 *
 * @param data - 65-byte serialized ProfileKeyCiphertext
 * @returns The reconstituted Ciphertext
 * @throws Error if data is not exactly 65 bytes
 */
function deserializeProfileKeyCiphertext(data: ProfileKeyCiphertext): ProfileKeyEncCiphertext {
  if (data.length !== PROFILE_KEY_CIPHERTEXT_LEN) {
    throw new Error(
      `ProfileKeyCiphertext must be ${PROFILE_KEY_CIPHERTEXT_LEN} bytes, got ${data.length}`
    );
  }
  // byte 0 is reserved, skip it
  const E_A1 = RistrettoPoint.fromBytes(data.slice(1, 33));
  const E_A2 = RistrettoPoint.fromBytes(data.slice(33, 65));
  return new Ciphertext(E_A1, E_A2, ProfileKeyEncryptionDomain);
}

// ---------------------------------------------------------------------------
// ClientZkGroupCipher operations
// ---------------------------------------------------------------------------

/**
 * Encrypt a ServiceId (UUID) under the group's UID encryption key.
 *
 * Produces a serialized 65-byte UuidCiphertext suitable for sending to the
 * Signal server or storing in the group state.
 *
 * @param groupSecretParams - The group's secret parameters
 * @param serviceId - The ServiceId to encrypt (ACI or PNI)
 * @returns 65-byte serialized UuidCiphertext
 */
export function encryptUuid(
  groupSecretParams: GroupSecretParams,
  serviceId: ServiceId
): UuidCiphertext {
  const ciphertext = encryptServiceId(groupSecretParams, serviceId);
  return serializeUuidCiphertext(serviceId.kind, ciphertext);
}

/**
 * Decrypt a serialized UuidCiphertext back to a ServiceId.
 *
 * @param groupSecretParams - The group's secret parameters
 * @param ciphertext - 65-byte serialized UuidCiphertext
 * @returns The decrypted ServiceId
 * @throws Error if the ciphertext is malformed or decryption fails
 */
export function decryptUuid(
  groupSecretParams: GroupSecretParams,
  ciphertext: UuidCiphertext
): ServiceId {
  const { ciphertext: ct } = deserializeUuidCiphertext(ciphertext);
  return decryptServiceId(groupSecretParams, ct);
}

/**
 * Encrypt a profile key under the group's profile key encryption key.
 *
 * The profile key is bound to a specific UUID so that the ciphertext can
 * only be decrypted with knowledge of both the group secret and the UUID.
 *
 * @param groupSecretParams - The group's secret parameters
 * @param profileKey - 32-byte profile key
 * @param uuid - 16-byte raw UUID of the profile key owner
 * @returns 65-byte serialized ProfileKeyCiphertext
 */
export function encryptProfileKeyCiphertext(
  groupSecretParams: GroupSecretParams,
  profileKey: Uint8Array,
  uuid: Uint8Array
): ProfileKeyCiphertext {
  const ciphertext = encryptProfileKey(groupSecretParams, profileKey, uuid);
  return serializeProfileKeyCiphertext(ciphertext);
}

/**
 * Decrypt a serialized ProfileKeyCiphertext back to the 32-byte profile key.
 *
 * @param groupSecretParams - The group's secret parameters
 * @param ciphertext - 65-byte serialized ProfileKeyCiphertext
 * @param uuid - 16-byte raw UUID of the profile key owner
 * @returns 32-byte profile key
 * @throws Error if the ciphertext is malformed or decryption fails
 */
export function decryptProfileKeyCiphertext(
  groupSecretParams: GroupSecretParams,
  ciphertext: ProfileKeyCiphertext,
  uuid: Uint8Array
): Uint8Array {
  const ct = deserializeProfileKeyCiphertext(ciphertext);
  return decryptProfileKey(groupSecretParams, ct, uuid);
}
