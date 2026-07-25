/**
 * Username link encryption/decryption, compatible with the reference implementation
 *
 * Uses:
 * - AES-256-CBC for encryption
 * - HMAC-SHA256 for authentication
 * - HKDF-SHA256 for key derivation from 32-byte entropy
 *
 * Format: [IV(16) || ciphertext || HMAC(32)]
 *
 */

import { hkdf } from '../../crypto/kdf/hkdf';
import { hmac } from '../../crypto/symmetric/hmac';
import { aesCbcEncryptBytes, aesCbcDecryptBytes } from '../../crypto/symmetric/aes';
import { generateRandomBytes } from '../../crypto/random';
import { concatBytes, constantTimeEqual, stringToBytes } from '../../crypto/utils';
import {
  encodeBytesField,
  concatFields,
  decodeTag,
  decodeVarint,
  skipUnknownField,
} from '../../encoding/proto/primitives';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
export {};
export const USERNAME_LINK_ENTROPY_SIZE = 32;
const USERNAME_LINK_KEY_SIZE = 32;
const USERNAME_LINK_IV_SIZE = 16;
const USERNAME_LINK_HMAC_LEN = 32;
const LABEL_ENCRYPTION_KEY = 'Signal Username Link Encryption Key';
const LABEL_AUTHENTICATION_KEY = 'Signal Username Link Authentication Key';
const AES_BLOCK_SIZE = 16;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

export class UsernameLinkError extends Error {
  constructor(
    public readonly code:
      | 'INPUT_DATA_TOO_LONG'
      | 'INVALID_ENTROPY_LENGTH'
      | 'DATA_TOO_SHORT'
      | 'HMAC_MISMATCH'
      | 'BAD_CIPHERTEXT'
      | 'INVALID_STRUCTURE'
  ) {
    super(`Username link error: ${code}`);
    this.name = 'UsernameLinkError';
  }
}

// ---------------------------------------------------------------------------
// Protobuf encoding/decoding for UsernameData { username, padding }
// ---------------------------------------------------------------------------

/**
 * Encode UsernameData protobuf matching prost's proto3 behavior.
 *
 * CRITICAL: When padding is empty (username >= 48 chars), field 2 is OMITTED
 * entirely. prost omits default-valued bytes fields in proto3 serialization.
 */
function encodeUsernameData(usernameBytes: Uint8Array, padding: Uint8Array): Uint8Array {
  if (padding.length > 0) {
    return concatFields(encodeBytesField(1, usernameBytes), encodeBytesField(2, padding));
  }
  // proto3: empty bytes field is omitted
  return encodeBytesField(1, usernameBytes);
}

/**
 * Decode UsernameData protobuf, extracting the username string from field 1.
 * Skips field 2 (padding) and any unknown fields for forward compatibility.
 *
 */
function decodeUsernameData(data: Uint8Array): string {
  let offset = 0;
  let username: string | null = null;

  while (offset < data.length) {
    const { fieldNumber, wireType, bytesRead: tagBytes } = decodeTag(data, offset);
    offset += tagBytes;

    if (fieldNumber === 1 && wireType === 2) {
      // Length-delimited string field
      const { value: length, bytesRead: lenBytes } = decodeVarint(data, offset);
      offset += lenBytes;
      username = new TextDecoder().decode(data.slice(offset, offset + length));
      offset += length;
    } else if (fieldNumber === 2 && wireType === 2) {
      // Skip padding field
      const { value: length, bytesRead: lenBytes } = decodeVarint(data, offset);
      offset += lenBytes + length;
    } else {
      // Skip unknown fields (forward compatibility)
      offset = skipUnknownField(wireType, data, offset);
    }
  }

  if (username === null) {
    throw new UsernameLinkError('INVALID_STRUCTURE');
  }

  return username;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Encrypt a username for a shareable link.
 *
 * Algorithm:
 * 1. Pad username to fill 3 AES blocks, encode as protobuf
 * 2. Derive MAC key and AES key from entropy via HKDF
 * 3. Encrypt with AES-256-CBC using random IV
 * 4. Authenticate with HMAC-SHA256 over [IV || ciphertext]
 * 5. Output: [IV(16) || ciphertext || HMAC(32)]
 *
 * @param username - Full "nickname.discriminator" string
 * @param entropy - Optional 32-byte entropy (generated if not provided)
 * @returns entropy and encrypted username bytes
 */
export async function encryptUsernameForLink(
  username: string,
  entropy?: Uint8Array
): Promise<{ entropy: Uint8Array; encryptedUsername: Uint8Array }> {
  // Validate entropy if provided
  if (entropy !== undefined && entropy.length !== USERNAME_LINK_ENTROPY_SIZE) {
    throw new UsernameLinkError('INVALID_ENTROPY_LENGTH');
  }

  // Step 1: Pad and encode as protobuf
  const usernameBytes = stringToBytes(username);
  const paddingLength = Math.max(0, AES_BLOCK_SIZE * 3 - usernameBytes.length);
  const padding = new Uint8Array(paddingLength);
  const ptext = encodeUsernameData(usernameBytes, padding);

  // Validate encoded size
  if (ptext.length >= AES_BLOCK_SIZE * 4) {
    throw new UsernameLinkError('INPUT_DATA_TOO_LONG');
  }

  // Step 2: Entropy (generate or reuse)
  const finalEntropy = entropy ?? (await generateRandomBytes(USERNAME_LINK_ENTROPY_SIZE));

  // Step 3: Derive keys via HKDF
  const emptySalt = new Uint8Array(0);
  const aesKey = await hkdf(
    finalEntropy,
    emptySalt,
    stringToBytes(LABEL_ENCRYPTION_KEY),
    USERNAME_LINK_KEY_SIZE
  );
  const macKey = await hkdf(
    finalEntropy,
    emptySalt,
    stringToBytes(LABEL_AUTHENTICATION_KEY),
    USERNAME_LINK_HMAC_LEN
  );

  // Step 4: Encrypt with random IV
  const iv = await generateRandomBytes(USERNAME_LINK_IV_SIZE);
  const ctext = await aesCbcEncryptBytes(aesKey, iv, ptext);

  // Step 5: Build output buffer [IV || ciphertext || HMAC(macKey, IV || ciphertext)]
  const ivAndCtext = concatBytes(iv, ctext);
  const mac = hmac(macKey, ivAndCtext);
  const encryptedUsername = concatBytes(ivAndCtext, mac);

  return { entropy: finalEntropy, encryptedUsername };
}

/**
 * Decrypt a username from link data.
 *
 * Algorithm:
 * 1. Validate minimum length
 * 2. Split off HMAC, verify with MAC key (derived FIRST)
 * 3. Only after MAC passes, derive AES key and decrypt
 * 4. Decode protobuf to extract username string
 *
 * @param entropy - 32-byte entropy used during encryption
 * @param encryptedUsername - Encrypted bytes from encryptUsernameForLink
 * @returns Decrypted username string
 */
export async function decryptUsernameFromLink(
  entropy: Uint8Array,
  encryptedUsername: Uint8Array
): Promise<string> {
  // Validate entropy
  if (entropy.length !== USERNAME_LINK_ENTROPY_SIZE) {
    throw new UsernameLinkError('INVALID_ENTROPY_LENGTH');
  }

  // Step 1: Validate minimum length
  if (encryptedUsername.length <= USERNAME_LINK_IV_SIZE + USERNAME_LINK_HMAC_LEN) {
    throw new UsernameLinkError('DATA_TOO_SHORT');
  }

  // Step 2: Split [iv_and_ctext, expected_mac]
  const macOffset = encryptedUsername.length - USERNAME_LINK_HMAC_LEN;
  const ivAndCtext = encryptedUsername.slice(0, macOffset);
  const expectedMac = encryptedUsername.slice(macOffset);

  // Step 3: Derive MAC key FIRST
  const emptySalt = new Uint8Array(0);
  const macKey = await hkdf(
    entropy,
    emptySalt,
    stringToBytes(LABEL_AUTHENTICATION_KEY),
    USERNAME_LINK_HMAC_LEN
  );

  // Step 4: Verify HMAC
  const actualMac = hmac(macKey, ivAndCtext);
  if (!constantTimeEqual(expectedMac, actualMac)) {
    throw new UsernameLinkError('HMAC_MISMATCH');
  }

  // Step 5: ONLY NOW derive AES key
  const aesKey = await hkdf(
    entropy,
    emptySalt,
    stringToBytes(LABEL_ENCRYPTION_KEY),
    USERNAME_LINK_KEY_SIZE
  );

  // Step 6: Split IV and ciphertext, decrypt
  const iv = ivAndCtext.slice(0, USERNAME_LINK_IV_SIZE);
  const ctext = ivAndCtext.slice(USERNAME_LINK_IV_SIZE);

  let ptext: Uint8Array;
  try {
    ptext = await aesCbcDecryptBytes(aesKey, iv, ctext);
  } catch {
    throw new UsernameLinkError('BAD_CIPHERTEXT');
  }

  // Step 7: Decode protobuf
  try {
    return decodeUsernameData(ptext);
  } catch (e) {
    if (e instanceof UsernameLinkError) throw e;
    throw new UsernameLinkError('INVALID_STRUCTURE');
  }
}
