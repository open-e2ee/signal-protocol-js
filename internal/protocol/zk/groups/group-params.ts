/**
 * Group parameters — GroupMasterKey, GroupSecretParams, GroupPublicParams
 *
 *
 * The GroupMasterKey is the root secret for a group. From it, all group
 * secrets are derived deterministically via SHO:
 *  - groupId: 32-byte group identifier
 *  - blobKey: 32-byte AES-256-GCM-SIV key for blob encryption
 *  - uidEncKeyPair: ElGamal keypair for UID encryption
 *  - profileKeyEncKeyPair: ElGamal keypair for profile key encryption
 *
 * @see https://eprint.iacr.org/2019/1416.pdf — Signal Private Group System
 */

import { gcmsiv } from '@noble/ciphers/aes.js';
import { ShoHmacSha256 } from '../proofs/sho';
import type { PublicKey } from '../credentials/attributes';
import {
  deriveUidEncKeyPair,
  encryptServiceId as uidEncryptServiceId,
  decryptServiceId as uidDecryptServiceId,
  type UidEncKeyPair,
  type UidEncCiphertext,
} from './uid-encryption';
import {
  deriveProfileKeyEncKeyPair,
  encryptProfileKey as pkEncryptProfileKey,
  decryptProfileKey as pkDecryptProfileKey,
  type ProfileKeyEncKeyPair,
  type ProfileKeyEncCiphertext,
} from './profile-key-encryption';
import type { ServiceId } from './uid-struct';
export {};
const enc = new TextEncoder();

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const GROUP_MASTER_KEY_LEN = 32;
export const GROUP_IDENTIFIER_LEN = 32;
export const AES_KEY_LEN = 32;
export const AESGCM_NONCE_LEN = 12;
export const AESGCM_TAG_LEN = 16;
export const UUID_CIPHERTEXT_LEN = 65;
export const PROFILE_KEY_CIPHERTEXT_LEN = 65;
export const RANDOMNESS_LEN = 32;
export const SECONDS_PER_DAY = 86400;

// ---------------------------------------------------------------------------
// GroupMasterKey
// ---------------------------------------------------------------------------

export type GroupMasterKey = Uint8Array; // 32 bytes

/**
 * Create a new GroupMasterKey from raw bytes.
 */
export function groupMasterKey(bytes: Uint8Array): GroupMasterKey {
  if (bytes.length !== GROUP_MASTER_KEY_LEN) {
    throw new Error(`GroupMasterKey must be ${GROUP_MASTER_KEY_LEN} bytes, got ${bytes.length}`);
  }
  return new Uint8Array(bytes);
}

// ---------------------------------------------------------------------------
// GroupSecretParams
// ---------------------------------------------------------------------------

export interface GroupSecretParams {
  readonly masterKey: GroupMasterKey;
  readonly groupId: Uint8Array; // 32 bytes
  readonly blobKey: Uint8Array; // 32 bytes (AES-256 key)
  readonly uidEncKeyPair: UidEncKeyPair;
  readonly profileKeyEncKeyPair: ProfileKeyEncKeyPair;
}

/**
 * Derive all group secrets from a GroupMasterKey.
 */
export function deriveGroupSecretParams(masterKey: GroupMasterKey): GroupSecretParams {
  const sho = new ShoHmacSha256(
    enc.encode('Signal_ZKGroup_20200424_GroupMasterKey_GroupSecretParams_DeriveFromMasterKey')
  );
  sho.absorbAndRatchet(masterKey);

  // Squeeze group ID and blob key (32 bytes each)
  const groupId = sho.squeezeAndRatchet(GROUP_IDENTIFIER_LEN);
  const blobKey = sho.squeezeAndRatchet(AES_KEY_LEN);

  // Derive encryption keypairs from the continuing SHO state
  const uidEncKeyPair = deriveUidEncKeyPair(sho);
  const profileKeyEncKeyPair = deriveProfileKeyEncKeyPair(sho);

  return {
    masterKey: new Uint8Array(masterKey),
    groupId,
    blobKey,
    uidEncKeyPair,
    profileKeyEncKeyPair,
  };
}

/**
 * Generate random GroupSecretParams from 32 bytes of randomness.
 */
export function generateGroupSecretParams(randomness: Uint8Array): GroupSecretParams {
  if (randomness.length !== RANDOMNESS_LEN) {
    throw new Error(`Randomness must be ${RANDOMNESS_LEN} bytes, got ${randomness.length}`);
  }
  const sho = new ShoHmacSha256(
    enc.encode('Signal_ZKGroup_20200424_Random_GroupSecretParams_Generate')
  );
  sho.absorbAndRatchet(randomness);
  const masterKeyBytes = sho.squeezeAndRatchet(GROUP_MASTER_KEY_LEN);
  return deriveGroupSecretParams(masterKeyBytes);
}

// ---------------------------------------------------------------------------
// GroupPublicParams
// ---------------------------------------------------------------------------

export interface GroupPublicParams {
  readonly groupId: Uint8Array;
  readonly uidEncPublicKey: PublicKey;
  readonly profileKeyEncPublicKey: PublicKey;
}

/**
 * Extract public parameters from secret parameters.
 */
export function getGroupPublicParams(secretParams: GroupSecretParams): GroupPublicParams {
  return {
    groupId: new Uint8Array(secretParams.groupId),
    uidEncPublicKey: secretParams.uidEncKeyPair.publicKey,
    profileKeyEncPublicKey: secretParams.profileKeyEncKeyPair.publicKey,
  };
}

// ---------------------------------------------------------------------------
// UID encryption/decryption
// ---------------------------------------------------------------------------

/**
 * Encrypt a ServiceId using the group's UID encryption key.
 */
export function encryptServiceId(
  params: GroupSecretParams,
  serviceId: ServiceId
): UidEncCiphertext {
  return uidEncryptServiceId(params.uidEncKeyPair, serviceId);
}

/**
 * Decrypt a UID ciphertext back to a ServiceId.
 */
export function decryptServiceId(
  params: GroupSecretParams,
  ciphertext: UidEncCiphertext
): ServiceId {
  return uidDecryptServiceId(params.uidEncKeyPair, ciphertext);
}

// ---------------------------------------------------------------------------
// Profile key encryption/decryption
// ---------------------------------------------------------------------------

/**
 * Encrypt a profile key using the group's profile key encryption key.
 */
export function encryptProfileKey(
  params: GroupSecretParams,
  profileKeyBytes: Uint8Array,
  uidBytes: Uint8Array
): ProfileKeyEncCiphertext {
  return pkEncryptProfileKey(params.profileKeyEncKeyPair, profileKeyBytes, uidBytes);
}

/**
 * Decrypt a profile key ciphertext back to the 32-byte profile key.
 */
export function decryptProfileKey(
  params: GroupSecretParams,
  ciphertext: ProfileKeyEncCiphertext,
  uidBytes: Uint8Array
): Uint8Array {
  return pkDecryptProfileKey(params.profileKeyEncKeyPair, ciphertext, uidBytes);
}

// ---------------------------------------------------------------------------
// Blob encryption (AES-256-GCM-SIV)
// ---------------------------------------------------------------------------

/**
 * Encrypt a blob using AES-256-GCM-SIV with a nonce derived from randomness.
 *
 * Output format: ciphertext || tag || nonce(12) || reserved(1)
 */
export function encryptBlob(
  params: GroupSecretParams,
  randomness: Uint8Array,
  plaintext: Uint8Array
): Uint8Array {
  if (randomness.length !== RANDOMNESS_LEN) {
    throw new Error(`Randomness must be ${RANDOMNESS_LEN} bytes, got ${randomness.length}`);
  }

  const sho = new ShoHmacSha256(
    enc.encode('Signal_ZKGroup_20200424_Random_GroupSecretParams_EncryptBlob')
  );
  sho.absorbAndRatchet(randomness);
  const nonce = sho.squeezeAndRatchet(AESGCM_NONCE_LEN);

  const cipher = gcmsiv(params.blobKey, nonce);
  const ciphertextWithTag = cipher.encrypt(plaintext);

  // Output: ciphertext+tag || nonce || reserved_byte
  const result = new Uint8Array(ciphertextWithTag.length + AESGCM_NONCE_LEN + 1);
  result.set(ciphertextWithTag, 0);
  result.set(nonce, ciphertextWithTag.length);
  result[result.length - 1] = 0x00; // reserved byte
  return result;
}

/**
 * Encrypt a blob with padding.
 *
 * Plaintext format: BE_u32(padding_len) || plaintext || zeros(padding_len)
 */
export function encryptBlobWithPadding(
  params: GroupSecretParams,
  randomness: Uint8Array,
  plaintext: Uint8Array,
  paddingLen: number
): Uint8Array {
  const fullLength = 4 + plaintext.length + paddingLen;
  const padded = new Uint8Array(fullLength);
  // Write padding length as big-endian u32
  new DataView(padded.buffer).setUint32(0, paddingLen, false);
  padded.set(plaintext, 4);
  // Remaining bytes are already zero (padding)
  return encryptBlob(params, randomness, padded);
}

/**
 * Decrypt a blob encrypted with encryptBlob.
 */
export function decryptBlob(params: GroupSecretParams, ciphertext: Uint8Array): Uint8Array {
  if (ciphertext.length < AESGCM_NONCE_LEN + 1) {
    throw new Error('Blob ciphertext too short');
  }

  // Strip reserved byte
  const unreservedLen = ciphertext.length - 1;
  // Last 12 bytes before reserved = nonce
  const nonceStart = unreservedLen - AESGCM_NONCE_LEN;
  const nonce = ciphertext.slice(nonceStart, unreservedLen);
  const ciphertextWithTag = ciphertext.slice(0, nonceStart);

  if (ciphertextWithTag.length < AESGCM_TAG_LEN) {
    throw new Error('Blob ciphertext too short for tag');
  }

  const cipher = gcmsiv(params.blobKey, nonce);
  return cipher.decrypt(ciphertextWithTag);
}

/**
 * Decrypt a blob encrypted with encryptBlobWithPadding.
 */
export function decryptBlobWithPadding(
  params: GroupSecretParams,
  ciphertext: Uint8Array
): Uint8Array {
  const decrypted = decryptBlob(params, ciphertext);

  if (decrypted.length < 4) {
    throw new Error('Decrypted blob too short for padding header');
  }

  const paddingLen = new DataView(decrypted.buffer, decrypted.byteOffset).getUint32(0, false);

  if (decrypted.length - 4 < paddingLen) {
    throw new Error('Invalid padding length');
  }

  // Return plaintext without padding header and trailing padding
  return decrypted.slice(4, decrypted.length - paddingLen);
}
