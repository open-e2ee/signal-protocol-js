/**
 * Profile Cipher -- SDK padded profile field encryption
 *
 * Composes padding + AES-256-GCM encryption for profile fields.
 * Provides fixed-length padded profile-field encryption.
 */

import { encryptProfileData, decryptProfileData } from './crypto';
import { stringToBytes, bytesToString } from '../internal/crypto/utils';

// ============================================================================
// Profile-field padding buckets
// ============================================================================

/** Padding buckets for profile name (given + family). */
export {};
export const PROFILE_NAME_PADDED_LENGTHS = [53, 257] as const;

/** Padding buckets for "about" / bio text. */
export const PROFILE_ABOUT_PADDED_LENGTHS = [128, 254, 512] as const;

/** Padding bucket for emoji. */
export const PROFILE_EMOJI_PADDED_LENGTHS = [32] as const;

// ============================================================================
// Low-level Padding
// ============================================================================

/**
 * Pad data to the first bucket size >= data.length.
 *
 * Signal pads profile fields to fixed bucket sizes to prevent the server
 * from inferring field length from ciphertext size.
 *
 * @param data - Raw data to pad
 * @param paddedLengths - Ascending bucket sizes
 * @returns Data padded with trailing 0x00 bytes
 * @throws If data exceeds all bucket sizes
 */
export function padProfileField(data: Uint8Array, paddedLengths: readonly number[]): Uint8Array {
  const targetLength = paddedLengths.find((len) => len >= data.length);
  if (targetLength === undefined) {
    throw new Error(
      `Profile field too long: ${data.length} exceeds max bucket ${paddedLengths[paddedLengths.length - 1]}`
    );
  }
  const padded = new Uint8Array(targetLength);
  padded.set(data, 0);
  // Remaining bytes are already 0x00 (Uint8Array default)
  return padded;
}

/**
 * Remove trailing 0x00 padding from decrypted profile field.
 *
 * Finds the last non-zero byte and returns everything up to and including it.
 * If the entire buffer is zeros, returns an empty Uint8Array.
 *
 * @param data - Padded data
 * @returns Unpadded data
 */
export function unpadProfileField(data: Uint8Array): Uint8Array {
  let lastNonZero = -1;
  for (let i = data.length - 1; i >= 0; i--) {
    if (data[i] !== 0) {
      lastNonZero = i;
      break;
    }
  }
  if (lastNonZero === -1) {
    return new Uint8Array(0);
  }
  return data.slice(0, lastNonZero + 1);
}

// ============================================================================
// Field Encrypt / Decrypt (pad -> encryptProfileData / decryptProfileData -> unpad)
// ============================================================================

/**
 * Encrypt a profile field: pad then encrypt.
 *
 * @param profileKey - 32-byte AES key
 * @param plaintext - Raw field data
 * @param paddedLengths - Bucket sizes for this field type
 * @returns Encrypted [nonce || ciphertext || tag]
 */
export async function encryptProfileField(
  profileKey: Uint8Array,
  plaintext: Uint8Array,
  paddedLengths: readonly number[]
): Promise<Uint8Array> {
  const padded = padProfileField(plaintext, paddedLengths);
  return encryptProfileData(profileKey, padded);
}

/**
 * Decrypt a profile field: decrypt then unpad.
 *
 * @param profileKey - 32-byte AES key
 * @param encrypted - Encrypted field data
 * @returns Unpadded plaintext
 */
export async function decryptProfileField(
  profileKey: Uint8Array,
  encrypted: Uint8Array
): Promise<Uint8Array> {
  const padded = await decryptProfileData(profileKey, encrypted);
  return unpadProfileField(padded);
}

// ============================================================================
// Name Encoding
// ============================================================================

/**
 * Encrypt a profile name.
 *
 * @param profileKey - 32-byte AES key
 * @param name - Name to encrypt
 * @returns Encrypted name field
 *
 */
export async function encryptProfileName(
  profileKey: Uint8Array,
  name: string
): Promise<Uint8Array> {
  const nameBytes = stringToBytes(name);
  return encryptProfileField(profileKey, nameBytes, PROFILE_NAME_PADDED_LENGTHS);
}

/**
 * Decrypt a profile name.
 *
 * @param profileKey - 32-byte AES key
 * @param encrypted - Encrypted name field
 * @returns Object with name
 */
export async function decryptProfileName(
  profileKey: Uint8Array,
  encrypted: Uint8Array
): Promise<{ name: string }> {
  const nameBytes = await decryptProfileField(profileKey, encrypted);
  const nameStr = bytesToString(nameBytes);

  // Legacy wire compat: if a \0 separator exists, join parts with a space
  const separatorIndex = nameStr.indexOf('\0');
  if (separatorIndex === -1) {
    return { name: nameStr };
  }

  const first = nameStr.slice(0, separatorIndex);
  const second = nameStr.slice(separatorIndex + 1);
  return { name: second ? `${first} ${second}` : first };
}

// ============================================================================
// String Field Helpers
// ============================================================================

/**
 * Encrypt a string profile field (e.g., about/bio, emoji).
 *
 * @param profileKey - 32-byte AES key
 * @param text - Plain string to encrypt
 * @param paddedLengths - Bucket sizes for this field type
 * @returns Encrypted field data
 */
export async function encryptProfileString(
  profileKey: Uint8Array,
  text: string,
  paddedLengths: readonly number[]
): Promise<Uint8Array> {
  const textBytes = stringToBytes(text);
  return encryptProfileField(profileKey, textBytes, paddedLengths);
}

/**
 * Decrypt a string profile field.
 *
 * @param profileKey - 32-byte AES key
 * @param encrypted - Encrypted field data
 * @returns Decrypted string
 */
export async function decryptProfileString(
  profileKey: Uint8Array,
  encrypted: Uint8Array
): Promise<string> {
  const textBytes = await decryptProfileField(profileKey, encrypted);
  return bytesToString(textBytes);
}

// ============================================================================
// Opaque Application Profile Data
// ============================================================================

/**
 * Padding buckets for app-specific profile data.
 *
 * | Bucket   | Encrypted size | Covers                          |
 * |----------|---------------|---------------------------------|
 * | 256 bytes | 284 bytes    | 3–8 tags (most new users)       |
 * | 512 bytes | 540 bytes    | 9–20 tags (typical engaged)     |
 * | 1024 bytes| 1052 bytes   | 21–30+ tags + future fields     |
 */
export const PROFILE_APP_DATA_PADDED_LENGTHS = [256, 512, 1024] as const;

/**
 * Versioned opaque application data. The SDK encrypts and carries these bytes
 * without defining or interpreting the host application's schema.
 */
export interface ApplicationProfileData {
  version: number;
  data: Uint8Array;
}

/**
 * Encrypt app-specific profile data.
 *
 * Serializes to versioned JSON, pads, then encrypts with profile key.
 *
 * @param profileKey - 32-byte AES key
 * @param appData - Versioned opaque bytes owned by the host application
 * @returns Encrypted [nonce(12) || ciphertext || tag(16)]
 */
export async function encryptProfileAppData(
  profileKey: Uint8Array,
  appData: ApplicationProfileData
): Promise<Uint8Array> {
  if (!Number.isInteger(appData.version) || appData.version < 0 || appData.version > 0xffffffff) {
    throw new Error('Application profile data version must be a uint32');
  }
  const encoded = new Uint8Array(8 + appData.data.length);
  const view = new DataView(encoded.buffer);
  view.setUint32(0, appData.version, false);
  view.setUint32(4, appData.data.length, false);
  encoded.set(appData.data, 8);
  return encryptProfileField(profileKey, encoded, PROFILE_APP_DATA_PADDED_LENGTHS);
}

/**
 * Decrypt app-specific profile data.
 *
 * @param profileKey - 32-byte AES key
 * @param encrypted - Encrypted appData field
 * @returns Versioned opaque bytes for interpretation by the host application
 */
export async function decryptProfileAppData(
  profileKey: Uint8Array,
  encrypted: Uint8Array
): Promise<ApplicationProfileData> {
  const padded = await decryptProfileData(profileKey, encrypted);
  if (padded.length < 8) throw new Error('Invalid application profile data header');
  const view = new DataView(padded.buffer, padded.byteOffset, padded.byteLength);
  const version = view.getUint32(0, false);
  const length = view.getUint32(4, false);
  if (length > padded.length - 8) throw new Error('Invalid application profile data length');
  return { version, data: Uint8Array.from(padded.subarray(8, 8 + length)) };
}
