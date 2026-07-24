/**
 * Device Name Encryption/Decryption
 *
 * Encrypts device names with an identity-bound synthetic-IV scheme:
 * 1. Generate ephemeral X25519 key pair
 * 2. masterSecret = ECDH(ephemeralPrivate, identityPublic)
 * 3. syntheticIV = HMAC(HMAC(masterSecret, "auth"), plaintext)[0:16]
 * 4. cipherKey = HMAC(HMAC(masterSecret, "cipher"), syntheticIV)
 * 5. ciphertext = AES-256-CTR(cipherKey, plaintext, iv=0)
 * 6. Encode a protobuf payload with:
 *    field 1 = ephemeralPublic
 *    field 2 = syntheticIv
 *    field 3 = ciphertext
 *
 * The server stores opaque encrypted bytes. Only the device owner
 * (who has the identity private key) can decrypt.
 *
 * Public keys use the package's raw 32-byte X25519 representation.
 *
 */

import {
  generateECDHKeyPair,
  computeSharedSecret,
  hmac,
  aesCtrEncrypt,
  aesCtrDecrypt,
  constantTimeEqual,
  stringToBytes,
  base64ToBytes,
  bytesToBase64,
} from '../internal/crypto';
import {
  concatFields,
  decodeTag,
  decodeVarint,
  encodeBytesField,
  skipUnknownField,
  WIRE_TYPE_LENGTH_DELIMITED,
} from '../internal/encoding/proto/primitives';
import type { Base64 } from '../types/utils';
export {};
const SYNTHETIC_IV_LENGTH = 16;
const X25519_PUBLIC_KEY_LENGTH = 32;
const AUTH_INFO = stringToBytes('auth');
const CIPHER_INFO = stringToBytes('cipher');
const DEVICE_NAME_EPHEMERAL_PUBLIC_FIELD = 1;
const DEVICE_NAME_SYNTHETIC_IV_FIELD = 2;
const DEVICE_NAME_CIPHERTEXT_FIELD = 3;

/**
 * Encrypt a device name for server storage.
 *
 * @param plaintext - Human-readable device name (e.g., "iPhone 15 Pro")
 * @param identityPublicKeyBase64 - Account identity X25519 public key (Base64)
 * @returns Encrypted device name as ArrayBuffer (for v.bytes())
 */
export async function encryptDeviceName(
  plaintext: string,
  identityPublicKeyBase64: Base64
): Promise<ArrayBuffer> {
  if (!plaintext) {
    throw new Error('Device name cannot be empty');
  }

  const plaintextBytes = stringToBytes(plaintext);

  // 1. Generate ephemeral X25519 key pair
  const ephemeralKeyPair = await generateECDHKeyPair();

  // 2. masterSecret = ECDH(ephemeralPrivate, identityPublic)
  const masterSecretBytes = await computeSharedSecret(
    ephemeralKeyPair.privateKey,
    identityPublicKeyBase64
  );

  // 3. syntheticIV = HMAC(HMAC(masterSecret, "auth"), plaintext)[0:16]
  const syntheticIV = computeSyntheticIV(masterSecretBytes, plaintextBytes);

  // 4. cipherKey = HMAC(HMAC(masterSecret, "cipher"), syntheticIV)
  const cipherKey = computeCipherKey(masterSecretBytes, syntheticIV);

  // 5. ciphertext = AES-256-CTR(cipherKey, plaintext, iv=zeros(16))
  const zeroIV = new Uint8Array(16); // All-zeros IV = counter 0
  const ciphertextBytes = aesCtrEncrypt(cipherKey, zeroIV, plaintextBytes);

  // 6. Encode the device-name protobuf payload.
  const ephemeralPublicBytes = base64ToBytes(ephemeralKeyPair.publicKey);
  const encoded = encodeDeviceNamePayload(ephemeralPublicBytes, syntheticIV, ciphertextBytes);

  // Copy into a clean ArrayBuffer (avoids SharedArrayBuffer type widening in TS 5.x)
  const result = new ArrayBuffer(encoded.byteLength);
  new Uint8Array(result).set(encoded);
  return result;
}

/**
 * Decrypt a device name from server storage.
 *
 * @param encryptedBytes - Encrypted device name (from v.bytes())
 * @param identityPrivateKeyBase64 - Account identity X25519 private key (Base64)
 * @returns Decrypted plaintext device name
 */
export async function decryptDeviceName(
  encryptedBytes: ArrayBuffer,
  identityPrivateKeyBase64: Base64
): Promise<string> {
  const data = new Uint8Array(encryptedBytes);
  const { ephemeralPublicBytes, syntheticIV, ciphertextBytes } = decodeDeviceNamePayload(data);

  const ephemeralPublicBase64 = bytesToBase64(ephemeralPublicBytes);

  // 1. masterSecret = ECDH(identityPrivate, ephemeralPublic)
  const masterSecretBytes = await computeSharedSecret(
    identityPrivateKeyBase64,
    ephemeralPublicBase64
  );

  // 2. cipherKey = HMAC(HMAC(masterSecret, "cipher"), syntheticIV)
  const cipherKey = computeCipherKey(masterSecretBytes, syntheticIV);

  // 3. plaintext = AES-256-CTR(cipherKey, ciphertext, iv=zeros(16))
  const zeroIV = new Uint8Array(16);
  const plaintextBytes = aesCtrDecrypt(cipherKey, zeroIV, ciphertextBytes);

  // 4. Verify synthetic IV (constant-time)
  const computedSyntheticIV = computeSyntheticIV(masterSecretBytes, plaintextBytes);
  if (!constantTimeEqual(syntheticIV, computedSyntheticIV)) {
    throw new Error('Device name decryption failed: synthetic IV mismatch');
  }

  // Reject invalid UTF-8 after authenticated decryption.
  const decoder = new TextDecoder('utf-8', { fatal: true });
  try {
    return decoder.decode(plaintextBytes);
  } catch {
    throw new Error('Device name decryption failed: invalid UTF-8');
  }
}

/**
 * syntheticIV = HMAC(HMAC(masterSecret, "auth"), plaintext)[0:16]
 */
function computeSyntheticIV(masterSecret: Uint8Array, plaintext: Uint8Array): Uint8Array {
  const syntheticIVKey = hmac(masterSecret, AUTH_INFO);
  const fullHmac = hmac(syntheticIVKey, plaintext);
  return fullHmac.slice(0, SYNTHETIC_IV_LENGTH);
}

/**
 * cipherKey = HMAC(HMAC(masterSecret, "cipher"), syntheticIV)
 */
function computeCipherKey(masterSecret: Uint8Array, syntheticIV: Uint8Array): Uint8Array {
  const cipherKeyKey = hmac(masterSecret, CIPHER_INFO);
  return hmac(cipherKeyKey, syntheticIV);
}

function encodeDeviceNamePayload(
  ephemeralPublic: Uint8Array,
  syntheticIV: Uint8Array,
  ciphertext: Uint8Array
): Uint8Array {
  return concatFields(
    encodeBytesField(DEVICE_NAME_EPHEMERAL_PUBLIC_FIELD, ephemeralPublic),
    encodeBytesField(DEVICE_NAME_SYNTHETIC_IV_FIELD, syntheticIV),
    encodeBytesField(DEVICE_NAME_CIPHERTEXT_FIELD, ciphertext)
  );
}

function decodeDeviceNamePayload(data: Uint8Array): {
  ephemeralPublicBytes: Uint8Array;
  syntheticIV: Uint8Array;
  ciphertextBytes: Uint8Array;
} {
  let offset = 0;
  let ephemeralPublicBytes: Uint8Array | null = null;
  let syntheticIV: Uint8Array | null = null;
  let ciphertextBytes: Uint8Array | null = null;

  while (offset < data.length) {
    const { fieldNumber, wireType, bytesRead } = decodeTag(data, offset);
    offset += bytesRead;

    if (wireType !== WIRE_TYPE_LENGTH_DELIMITED) {
      offset = skipUnknownField(wireType, data, offset);
      continue;
    }

    const { value: length, bytesRead: lengthBytes } = decodeVarint(data, offset);
    offset += lengthBytes;
    const fieldValue = data.slice(offset, offset + length);
    if (fieldValue.length !== length) {
      throw new Error('Invalid encrypted device name: truncated field');
    }
    offset += length;

    switch (fieldNumber) {
      case DEVICE_NAME_EPHEMERAL_PUBLIC_FIELD:
        ephemeralPublicBytes = fieldValue;
        break;
      case DEVICE_NAME_SYNTHETIC_IV_FIELD:
        syntheticIV = fieldValue;
        break;
      case DEVICE_NAME_CIPHERTEXT_FIELD:
        ciphertextBytes = fieldValue;
        break;
      default:
        break;
    }
  }

  if (!ephemeralPublicBytes) {
    throw new Error('Invalid encrypted device name: missing ephemeral public key');
  }
  if (!syntheticIV) {
    throw new Error('Invalid encrypted device name: missing synthetic IV');
  }
  if (!ciphertextBytes || ciphertextBytes.length === 0) {
    throw new Error('Invalid encrypted device name: missing ciphertext');
  }
  if (ephemeralPublicBytes.length !== X25519_PUBLIC_KEY_LENGTH) {
    throw new Error('Invalid encrypted device name: bad public key length');
  }
  if (syntheticIV.length !== SYNTHETIC_IV_LENGTH) {
    throw new Error('Invalid encrypted device name: bad synthetic IV length');
  }

  return {
    ephemeralPublicBytes,
    syntheticIV,
    ciphertextBytes,
  };
}
