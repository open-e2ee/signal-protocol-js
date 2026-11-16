/**
 * The device link code and the device link envelope, version 1.
 *
 * A new device N shows a link code. The primary device P reads the code,
 * reads the ML-KEM-768 public key of N from the Relay, and checks the key
 * against the hash in the code. P then seals the account identity in an
 * envelope that only N can open:
 *
 * - The key comes from two shared secrets: X25519 with the key in the code,
 *   and ML-KEM-768 with the key from the Relay. HKDF-SHA256 combines them
 *   with a transcript hash as the salt.
 * - AES-256-GCM encrypts the padded plaintext. The header is the associated
 *   data.
 * - The plaintext is padded to a multiple of 4,096 bytes, so the Relay sees
 *   only the bucket of the message length.
 *
 * Each refusal is a `HostedSignalProtocolRelayDeviceProvisioningError`:
 * `LINK_CODE_INVALID` for a bad code or KEM key, `ENVELOPE_TOO_LARGE` for a
 * message above the limit, and `ENVELOPE_INVALID` for a body that N cannot
 * open or read. A `RangeError` reports caller input that the format cannot
 * hold.
 */
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { bytesToHex } from "../encoding/hex";
import {
  AES_GCM_IV_BYTES,
  AES_GCM_TAG_BYTES,
  ED25519_KEY_BYTES,
  KYBER_768_CIPHERTEXT_BYTES,
  KYBER_768_PUBLIC_KEY_BYTES,
  KYBER_768_SECRET_KEY_BYTES,
  X25519_KEY_BYTES,
  aesGcmDecryptWithIVBytes,
  aesGcmEncryptWithIVBytes,
  base64ToBytes,
  bytesToUrlSafeBase64,
  concatBytes,
  constantTimeEqual,
  generateRandomBytes,
  hkdf,
  kyber768Decapsulate,
  secureZeroBytes,
  sha256,
  stringToBytes,
  urlSafeToBase64,
} from "../internal/crypto";
import { ProtoReader, concatFields, encodeBytesField, encodeMessageField, encodeUint32Field, encodeUint64Field } from "../internal/encoding/proto/primitives";

import { utf8Decode } from "../internal/platform";
import { deriveGroupSecretParams } from "../internal/protocol/zk/groups";
import type { Base64 } from "../types";
import { HostedSignalProtocolRelayDeviceProvisioningError } from "./hosted-device-provisioning-error";

/** The prefix of a version 1 link code, with the scheme and the version. */
export const DEVICE_LINK_CODE_PREFIX = "oe-link:v1?";
/** The length of a link code in characters. */
export const DEVICE_LINK_CODE_LENGTH = 127;
/** The length of the channel address `A` in bytes. */
export const DEVICE_LINK_ADDRESS_BYTES = 16;
/** Byte 0 of a version 1 envelope. */
export const DEVICE_LINK_ENVELOPE_VERSION = 1;
/** The version 1 envelope header: version, `xP.pub`, ML-KEM ciphertext, nonce. */
export const DEVICE_LINK_HEADER_BYTES =
  1 + X25519_KEY_BYTES + KYBER_768_CIPHERTEXT_BYTES + AES_GCM_IV_BYTES;
/** The padded plaintext length is a multiple of this value. */
export const DEVICE_LINK_PADDING_BUCKET_BYTES = 4_096;
/** The smallest body: the header, one bucket, and the GCM tag. */
export const DEVICE_LINK_BODY_MIN_BYTES =
  DEVICE_LINK_HEADER_BYTES + DEVICE_LINK_PADDING_BUCKET_BYTES + AES_GCM_TAG_BYTES;
/** The body limit of the provisioning channel. */
export const DEVICE_LINK_BODY_MAX_BYTES = 262_144;
/** The largest padded plaintext that fits under the body limit. */
export const DEVICE_LINK_PADDED_MAX_BYTES =
  Math.floor(
    (DEVICE_LINK_BODY_MAX_BYTES - DEVICE_LINK_HEADER_BYTES - AES_GCM_TAG_BYTES) /
      DEVICE_LINK_PADDING_BUCKET_BYTES,
  ) * DEVICE_LINK_PADDING_BUCKET_BYTES;
/** The largest plaintext message: the largest padded length minus the length prefix. */
export const DEVICE_LINK_MESSAGE_MAX_BYTES = DEVICE_LINK_PADDED_MAX_BYTES - 4;
/** The limit of the `encryptedDeviceName` field. */
export const DEVICE_LINK_ENCRYPTED_DEVICE_NAME_MAX_BYTES = 512;
/** The limit of the `applicationData` field. */
export const DEVICE_LINK_APPLICATION_DATA_MAX_BYTES = 16_384;
/** Field 1 of a version 1 plaintext. */
export const DEVICE_LINK_PLAINTEXT_VERSION = 1;

const TRANSCRIPT_LABEL = stringToBytes("OpenE2EE device link v1");
const ENVELOPE_INFO = stringToBytes("OpenE2EE device link envelope v1");
const ENVELOPE_KEY_BYTES = 32;
const GROUP_MASTER_KEY_BYTES = 32;
const KEM_SEED_BYTES = 64;
const KEM_ENCAPSULATION_RANDOMNESS_BYTES = 32;
const LINK_CODE_HASH_BYTES = 32;
const LINK_CODE_PATTERN =
  /^oe-link:v1\?a=([A-Za-z0-9_-]{22})&k=([A-Za-z0-9_-]{43})&h=([A-Za-z0-9_-]{43})$/u;

/** The values of a link code. */
export interface DeviceLinkCode {
  /** The channel address `A`, 16 bytes. */
  readonly address: Uint8Array;
  /** The X25519 public key `xN.pub` of the new device, 32 bytes. */
  readonly x25519PublicKey: Uint8Array;
  /** SHA-256 of the ML-KEM-768 public key `kN.pub`, 32 bytes. */
  readonly kemPublicKeyHash: Uint8Array;
}

/** The keys that the new device keeps while it waits for an envelope. */
export interface DeviceLinkReceiverKeys {
  /** `xN.private`, 32 bytes. */
  readonly x25519PrivateKey: Uint8Array;
  /** `xN.pub`, 32 bytes. */
  readonly x25519PublicKey: Uint8Array;
  /** `kN.pub`, 1,184 bytes. */
  readonly kemPublicKey: Uint8Array;
  /** `kN.secret`, 2,400 bytes. */
  readonly kemSecretKey: Uint8Array;
}

/** An X25519 key pair and an Ed25519 key pair of one account identity. */
export interface DeviceLinkIdentityKeyPair {
  /** X25519, 32 bytes. */
  readonly dhPublicKey: Uint8Array;
  /** X25519, 32 bytes. */
  readonly dhPrivateKey: Uint8Array;
  /** Ed25519, 32 bytes. */
  readonly signingPublicKey: Uint8Array;
  /** The Ed25519 seed, 32 bytes. */
  readonly signingPrivateKey: Uint8Array;
}

/** A group that the primary device copies to the new device. */
export interface DeviceLinkGroup {
  /** The lowercase hex group ID that the master key derives. */
  readonly groupId: string;
  /** The group master key, 32 bytes. */
  readonly masterKey: Uint8Array;
}

/** The account state in a version 1 envelope. */
export interface DeviceLinkPlaintext {
  readonly aci: DeviceLinkIdentityKeyPair;
  /** Absent when the account has no PNI. */
  readonly pni?: DeviceLinkIdentityKeyPair;
  readonly accountAddress: string;
  readonly linkToken: string;
  /** The encoder sorts the groups by the UTF-8 bytes of `groupId`. */
  readonly groups: readonly DeviceLinkGroup[];
  /** 512 bytes or less. */
  readonly encryptedDeviceName?: Uint8Array;
  /** 16,384 bytes or less. */
  readonly applicationData?: Uint8Array;
  /** Information only. */
  readonly createdAtMs: number;
}

/** The input of a seal on the primary device. */
export interface DeviceLinkEnvelopeSealInput {
  /** The parsed link code of the new device. */
  readonly linkCode: DeviceLinkCode;
  /** `kN.pub` as the Relay returned it. The seal checks it against the code. */
  readonly kemPublicKey: Uint8Array;
  readonly plaintext: DeviceLinkPlaintext;
}

/** The random values of one seal. Each value must be new for each envelope. */
export interface DeviceLinkEnvelopeSealRandomness {
  /** `xP.private`, 32 bytes. */
  readonly x25519PrivateKey: Uint8Array;
  /** The ML-KEM-768 encapsulation randomness, 32 bytes. */
  readonly kemEncapsulationRandomness: Uint8Array;
  /** The AES-GCM nonce, 12 bytes. */
  readonly nonce: Uint8Array;
}

/** The input of an open on the new device. */
export interface DeviceLinkEnvelopeReceiver {
  /** The channel address `A` of the link code, 16 bytes. */
  readonly address: Uint8Array;
  readonly keys: DeviceLinkReceiverKeys;
}

// ---------------------------------------------------------------- link code

/**
 * Parses a link code. Only the exact version 1 form is accepted.
 *
 * @throws HostedSignalProtocolRelayDeviceProvisioningError `LINK_CODE_INVALID`
 */
export function parseDeviceLinkCode(code: unknown): DeviceLinkCode {
  if (typeof code !== "string" || !code.startsWith(DEVICE_LINK_CODE_PREFIX)) {
    throw linkCodeInvalid("The device link code has an unknown scheme or version");
  }
  const match = LINK_CODE_PATTERN.exec(code);
  if (match === null) {
    throw linkCodeInvalid("The device link code is malformed");
  }
  return {
    address: decodeLinkCodeValue(match[1]!, DEVICE_LINK_ADDRESS_BYTES),
    x25519PublicKey: decodeLinkCodeValue(match[2]!, X25519_KEY_BYTES),
    kemPublicKeyHash: decodeLinkCodeValue(match[3]!, LINK_CODE_HASH_BYTES),
  };
}

/**
 * Formats the link code that the new device shows.
 *
 * @throws RangeError when a value has the wrong length.
 */
export async function formatDeviceLinkCode(
  address: Uint8Array,
  keys: Pick<DeviceLinkReceiverKeys, "x25519PublicKey" | "kemPublicKey">,
): Promise<string> {
  requireLength(address, DEVICE_LINK_ADDRESS_BYTES, "The device link address");
  requireLength(keys.x25519PublicKey, X25519_KEY_BYTES, "The device link X25519 public key");
  requireLength(keys.kemPublicKey, KYBER_768_PUBLIC_KEY_BYTES, "The device link KEM public key");
  const hash = await sha256(keys.kemPublicKey);
  return (
    `${DEVICE_LINK_CODE_PREFIX}a=${bytesToUrlSafeBase64(address)}` +
    `&k=${bytesToUrlSafeBase64(keys.x25519PublicKey)}` +
    `&h=${bytesToUrlSafeBase64(hash)}`
  );
}

/**
 * Checks the KEM public key from the Relay against the hash in the link code.
 * The primary device runs this check before it asks for a link token, and
 * the seal runs it again.
 *
 * @throws HostedSignalProtocolRelayDeviceProvisioningError `LINK_CODE_INVALID`
 */
export async function verifyDeviceLinkKemPublicKey(
  code: DeviceLinkCode,
  kemPublicKey: Uint8Array,
): Promise<void> {
  if (kemPublicKey.length !== KYBER_768_PUBLIC_KEY_BYTES) {
    throw linkCodeInvalid("The device link KEM public key has the wrong length");
  }
  if (!constantTimeEqual(await sha256(kemPublicKey), code.kemPublicKeyHash)) {
    throw linkCodeInvalid("The device link KEM public key does not match the link code");
  }
}

// ------------------------------------------------------------ receiver keys

/** Makes new receiver keys for one provisioning channel. */
export async function generateDeviceLinkReceiverKeys(): Promise<DeviceLinkReceiverKeys> {
  const x25519PrivateKey = await generateRandomBytes(X25519_KEY_BYTES);
  const kemSeed = await generateRandomBytes(KEM_SEED_BYTES);
  try {
    return deviceLinkReceiverKeysFromSeed(x25519PrivateKey, kemSeed);
  } finally {
    secureZeroBytes(x25519PrivateKey);
    secureZeroBytes(kemSeed);
  }
}

/**
 * Derives receiver keys from a 32-byte X25519 private key and a 64-byte
 * ML-KEM-768 key generation seed. The result holds its own copy of the
 * private key.
 *
 * @throws RangeError when a value has the wrong length.
 */
export function deviceLinkReceiverKeysFromSeed(
  x25519PrivateKey: Uint8Array,
  kemSeed: Uint8Array,
): DeviceLinkReceiverKeys {
  requireLength(x25519PrivateKey, X25519_KEY_BYTES, "The device link X25519 private key");
  requireLength(kemSeed, KEM_SEED_BYTES, "The device link KEM seed");
  const kem = ml_kem768.keygen(kemSeed);
  return {
    x25519PrivateKey: x25519PrivateKey.slice(),
    x25519PublicKey: x25519.getPublicKey(x25519PrivateKey),
    kemPublicKey: kem.publicKey,
    kemSecretKey: kem.secretKey,
  };
}

// ---------------------------------------------------------------- plaintext

/**
 * Encodes the plaintext message. The fields are in number order, and the
 * groups are sorted by the UTF-8 bytes of `groupId`.
 *
 * @throws RangeError when the input breaks a field rule.
 */
export function encodeDeviceLinkPlaintext(plaintext: DeviceLinkPlaintext): Uint8Array {
  if (!Number.isSafeInteger(plaintext.createdAtMs) || plaintext.createdAtMs < 0) {
    throw new RangeError("The device link createdAtMs must be a non-negative safe integer");
  }
  if (plaintext.accountAddress === "") {
    throw new RangeError("The device link accountAddress must not be empty");
  }
  if (plaintext.linkToken === "") {
    throw new RangeError("The device link linkToken must not be empty");
  }
  // The intermediate encodings hold private keys and master keys.
  const parts: Uint8Array[] = [];
  const fields: Uint8Array[] = [];
  try {
    const groups = encodeGroups(plaintext.groups);
    parts.push(...groups);
    const aci = encodeIdentityKeyPair(plaintext.aci, "aci");
    parts.push(aci);
    fields.push(encodeUint32Field(1, DEVICE_LINK_PLAINTEXT_VERSION), encodeMessageField(2, aci));
    if (plaintext.pni !== undefined) {
      const pni = encodeIdentityKeyPair(plaintext.pni, "pni");
      parts.push(pni);
      fields.push(encodeMessageField(3, pni));
    }
    fields.push(
      encodeBytesField(4, utf8EncodeStrict(plaintext.accountAddress, "accountAddress")),
      encodeBytesField(5, utf8EncodeStrict(plaintext.linkToken, "linkToken")),
      ...groups.map((group) => encodeMessageField(6, group)),
    );
    if (plaintext.encryptedDeviceName !== undefined) {
      requireAtMost(
        plaintext.encryptedDeviceName,
        DEVICE_LINK_ENCRYPTED_DEVICE_NAME_MAX_BYTES,
        "The device link encryptedDeviceName",
      );
      fields.push(encodeBytesField(7, plaintext.encryptedDeviceName));
    }
    if (plaintext.applicationData !== undefined) {
      requireAtMost(
        plaintext.applicationData,
        DEVICE_LINK_APPLICATION_DATA_MAX_BYTES,
        "The device link applicationData",
      );
      fields.push(encodeBytesField(8, plaintext.applicationData));
    }
    fields.push(encodeUint64Field(9, BigInt(plaintext.createdAtMs)));
    return concatFields(...fields);
  } finally {
    for (const part of parts) secureZeroBytes(part);
    for (const field of fields) secureZeroBytes(field);
  }
}

/**
 * Decodes the plaintext message. The decoder skips an unknown field and
 * refuses a repeated single field, a missing required field, an unknown
 * version, a key of the wrong length, a key pair whose public key does not
 * match its private key, and groups that are not in strict `groupId` order.
 *
 * @throws HostedSignalProtocolRelayDeviceProvisioningError `ENVELOPE_INVALID`
 */
export function decodeDeviceLinkPlaintext(message: Uint8Array): DeviceLinkPlaintext {
  try {
    return decodePlaintextFields(message);
  } catch (error) {
    if (error instanceof HostedSignalProtocolRelayDeviceProvisioningError) throw error;
    throw envelopeInvalid("The device link plaintext is malformed", error);
  }
}

// ------------------------------------------------------------------ padding

/**
 * Pads a message to the smallest multiple of 4,096 bytes that holds a
 * 4-byte big-endian length and the message.
 *
 * @throws HostedSignalProtocolRelayDeviceProvisioningError `ENVELOPE_TOO_LARGE`
 */
export function padDeviceLinkMessage(message: Uint8Array): Uint8Array {
  if (message.length > DEVICE_LINK_MESSAGE_MAX_BYTES) {
    throw new HostedSignalProtocolRelayDeviceProvisioningError(
      "ENVELOPE_TOO_LARGE",
      `The device link message has ${message.length} bytes. The limit is ${DEVICE_LINK_MESSAGE_MAX_BYTES} bytes`,
    );
  }
  const padded = new Uint8Array(paddedLength(message.length));
  new DataView(padded.buffer, padded.byteOffset, padded.byteLength).setUint32(0, message.length);
  padded.set(message, 4);
  return padded;
}

/**
 * Removes the padding. It refuses a length that is not a bucket multiple, a
 * message length larger than the padded length minus 4, a bucket that is
 * not the smallest for the message, and a padding byte that is not zero.
 *
 * @throws HostedSignalProtocolRelayDeviceProvisioningError `ENVELOPE_INVALID`
 */
export function unpadDeviceLinkMessage(padded: Uint8Array): Uint8Array {
  if (padded.length === 0 || padded.length % DEVICE_LINK_PADDING_BUCKET_BYTES !== 0) {
    throw envelopeInvalid("The device link padded length is not a bucket multiple");
  }
  const length = new DataView(padded.buffer, padded.byteOffset, padded.byteLength).getUint32(0);
  if (length > padded.length - 4) {
    throw envelopeInvalid("The device link message length is larger than its padding");
  }
  if (paddedLength(length) !== padded.length) {
    throw envelopeInvalid("The device link padding is not the smallest bucket");
  }
  let nonZero = 0;
  for (let index = 4 + length; index < padded.length; index += 1) {
    nonZero |= padded[index]!;
  }
  if (nonZero !== 0) {
    throw envelopeInvalid("The device link padding holds a byte that is not zero");
  }
  return padded.slice(4, 4 + length);
}

// --------------------------------------------------------------------- seal

/**
 * Seals the plaintext for the new device with new random values.
 *
 * @throws HostedSignalProtocolRelayDeviceProvisioningError `LINK_CODE_INVALID`
 *   when the KEM key does not match the code, or `ENVELOPE_TOO_LARGE`.
 * @throws RangeError when the plaintext breaks a field rule.
 */
export async function sealDeviceLinkEnvelope(input: DeviceLinkEnvelopeSealInput): Promise<Uint8Array> {
  const randomness = {
    x25519PrivateKey: await generateRandomBytes(X25519_KEY_BYTES),
    kemEncapsulationRandomness: await generateRandomBytes(KEM_ENCAPSULATION_RANDOMNESS_BYTES),
    nonce: await generateRandomBytes(AES_GCM_IV_BYTES),
  };
  try {
    return await sealDeviceLinkEnvelopeWithRandomness(input, randomness);
  } finally {
    secureZeroBytes(randomness.x25519PrivateKey);
    secureZeroBytes(randomness.kemEncapsulationRandomness);
  }
}

/**
 * Seals the plaintext with the given random values. Use
 * `sealDeviceLinkEnvelope` to send. This form exists to reproduce the fixed
 * contract values.
 *
 * @throws HostedSignalProtocolRelayDeviceProvisioningError `LINK_CODE_INVALID`
 *   or `ENVELOPE_TOO_LARGE`.
 * @throws RangeError when an input breaks a field rule.
 */
export async function sealDeviceLinkEnvelopeWithRandomness(
  input: DeviceLinkEnvelopeSealInput,
  randomness: DeviceLinkEnvelopeSealRandomness,
): Promise<Uint8Array> {
  requireLength(randomness.x25519PrivateKey, X25519_KEY_BYTES, "The device link X25519 private key");
  requireLength(
    randomness.kemEncapsulationRandomness,
    KEM_ENCAPSULATION_RANDOMNESS_BYTES,
    "The device link KEM encapsulation randomness",
  );
  requireLength(randomness.nonce, AES_GCM_IV_BYTES, "The device link nonce");
  const { linkCode, kemPublicKey } = input;
  requireLength(linkCode.address, DEVICE_LINK_ADDRESS_BYTES, "The device link address");
  requireLength(linkCode.x25519PublicKey, X25519_KEY_BYTES, "The device link X25519 public key");
  await verifyDeviceLinkKemPublicKey(linkCode, kemPublicKey);

  const message = encodeDeviceLinkPlaintext(input.plaintext);
  let padded: Uint8Array;
  try {
    padded = padDeviceLinkMessage(message);
  } finally {
    secureZeroBytes(message);
  }

  const senderPublicKey = x25519.getPublicKey(randomness.x25519PrivateKey);
  const secrets: Uint8Array[] = [padded];
  try {
    const ss1 = x25519SharedSecret(randomness.x25519PrivateKey, linkCode.x25519PublicKey);
    if (ss1 === null) {
      throw linkCodeInvalid("The device link X25519 public key gives no shared secret");
    }
    secrets.push(ss1);
    let encapsulation: { cipherText: Uint8Array; sharedSecret: Uint8Array };
    try {
      encapsulation = ml_kem768.encapsulate(kemPublicKey, randomness.kemEncapsulationRandomness);
    } catch (error) {
      throw linkCodeInvalid("The device link KEM public key is not a valid key", error);
    }
    secrets.push(encapsulation.sharedSecret);
    const header = concatBytes(
      Uint8Array.of(DEVICE_LINK_ENVELOPE_VERSION),
      senderPublicKey,
      encapsulation.cipherText,
      randomness.nonce,
    );
    const key = await deriveEnvelopeKey({
      ss1,
      ss2: encapsulation.sharedSecret,
      address: linkCode.address,
      receiverX25519PublicKey: linkCode.x25519PublicKey,
      kemPublicKey,
      senderX25519PublicKey: senderPublicKey,
      kemCiphertext: encapsulation.cipherText,
    });
    secrets.push(key);
    const sealed = await aesGcmEncryptWithIVBytes(key, padded, randomness.nonce, header);
    return concatBytes(header, sealed);
  } finally {
    for (const secret of secrets) secureZeroBytes(secret);
  }
}

// --------------------------------------------------------------------- open

/**
 * Opens an envelope on the new device. The checks run in this order: body
 * length, padding bucket, version, key derivation and GCM, padding, plaintext
 * decode, and group IDs.
 *
 * @throws HostedSignalProtocolRelayDeviceProvisioningError `ENVELOPE_INVALID`
 * @throws RangeError when a receiver key or the address has the wrong length.
 */
export async function openDeviceLinkEnvelope(
  body: Uint8Array,
  receiver: DeviceLinkEnvelopeReceiver,
): Promise<DeviceLinkPlaintext> {
  const { address, keys } = receiver;
  requireLength(address, DEVICE_LINK_ADDRESS_BYTES, "The device link address");
  requireLength(keys.x25519PrivateKey, X25519_KEY_BYTES, "The device link X25519 private key");
  requireLength(keys.x25519PublicKey, X25519_KEY_BYTES, "The device link X25519 public key");
  requireLength(keys.kemPublicKey, KYBER_768_PUBLIC_KEY_BYTES, "The device link KEM public key");
  requireLength(keys.kemSecretKey, KYBER_768_SECRET_KEY_BYTES, "The device link KEM secret key");

  if (body.length < DEVICE_LINK_BODY_MIN_BYTES || body.length > DEVICE_LINK_BODY_MAX_BYTES) {
    throw envelopeInvalid("The device link envelope length is out of range");
  }
  if ((body.length - DEVICE_LINK_HEADER_BYTES - AES_GCM_TAG_BYTES) % DEVICE_LINK_PADDING_BUCKET_BYTES !== 0) {
    throw envelopeInvalid("The device link envelope length is not a padding bucket");
  }
  if (body[0] !== DEVICE_LINK_ENVELOPE_VERSION) {
    throw envelopeInvalid("The device link envelope has an unknown version");
  }

  const header = body.subarray(0, DEVICE_LINK_HEADER_BYTES);
  const senderPublicKey = header.subarray(1, 1 + X25519_KEY_BYTES);
  const kemCiphertext = header.subarray(
    1 + X25519_KEY_BYTES,
    1 + X25519_KEY_BYTES + KYBER_768_CIPHERTEXT_BYTES,
  );
  const nonce = header.subarray(DEVICE_LINK_HEADER_BYTES - AES_GCM_IV_BYTES);

  const secrets: Uint8Array[] = [];
  let padded: Uint8Array;
  try {
    const ss1 = x25519SharedSecret(keys.x25519PrivateKey, senderPublicKey);
    if (ss1 === null) {
      throw envelopeInvalid("The device link envelope X25519 key gives no shared secret");
    }
    secrets.push(ss1);
    const ss2 = await kyber768Decapsulate(kemCiphertext, keys.kemSecretKey);
    secrets.push(ss2);
    const key = await deriveEnvelopeKey({
      ss1,
      ss2,
      address,
      receiverX25519PublicKey: keys.x25519PublicKey,
      kemPublicKey: keys.kemPublicKey,
      senderX25519PublicKey: senderPublicKey,
      kemCiphertext,
    });
    secrets.push(key);
    try {
      padded = await aesGcmDecryptWithIVBytes(
        key,
        body.subarray(DEVICE_LINK_HEADER_BYTES),
        nonce,
        header,
      );
    } catch (error) {
      throw envelopeInvalid("The device link envelope does not open", error);
    }
  } finally {
    for (const secret of secrets) secureZeroBytes(secret);
  }

  let message: Uint8Array | undefined;
  try {
    message = unpadDeviceLinkMessage(padded);
    const plaintext = decodeDeviceLinkPlaintext(message);
    for (const group of plaintext.groups) {
      if (bytesToHex(deriveGroupSecretParams(group.masterKey).groupId) !== group.groupId) {
        for (const secret of plaintextSecrets(plaintext)) secureZeroBytes(secret);
        throw envelopeInvalid("A device link group ID does not match its master key");
      }
    }
    return plaintext;
  } finally {
    secureZeroBytes(padded);
    if (message !== undefined) secureZeroBytes(message);
  }
}

// ---------------------------------------------------------------- internals

interface EnvelopeKeyInput {
  readonly ss1: Uint8Array;
  readonly ss2: Uint8Array;
  readonly address: Uint8Array;
  readonly receiverX25519PublicKey: Uint8Array;
  readonly kemPublicKey: Uint8Array;
  readonly senderX25519PublicKey: Uint8Array;
  readonly kemCiphertext: Uint8Array;
}

async function deriveEnvelopeKey(input: EnvelopeKeyInput): Promise<Uint8Array> {
  const transcript = await sha256(
    concatBytes(
      TRANSCRIPT_LABEL,
      input.address,
      input.receiverX25519PublicKey,
      input.kemPublicKey,
      input.senderX25519PublicKey,
      input.kemCiphertext,
    ),
  );
  const inputKeyMaterial = concatBytes(input.ss1, input.ss2);
  try {
    return await hkdf(inputKeyMaterial, transcript, ENVELOPE_INFO, ENVELOPE_KEY_BYTES);
  } finally {
    secureZeroBytes(inputKeyMaterial);
  }
}

/** X25519, or null when the result is all zero or the library refuses the key. */
function x25519SharedSecret(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array | null {
  let shared: Uint8Array;
  try {
    shared = x25519.getSharedSecret(privateKey, publicKey);
  } catch {
    return null;
  }
  if (constantTimeEqual(shared, new Uint8Array(X25519_KEY_BYTES))) {
    return null;
  }
  return shared;
}

function paddedLength(messageLength: number): number {
  return (
    Math.ceil((4 + messageLength) / DEVICE_LINK_PADDING_BUCKET_BYTES) *
    DEVICE_LINK_PADDING_BUCKET_BYTES
  );
}

function decodeLinkCodeValue(value: string, length: number): Uint8Array {
  let decoded: Uint8Array;
  try {
    decoded = base64ToBytes(urlSafeToBase64(value) as Base64);
  } catch (error) {
    throw linkCodeInvalid("The device link code holds a value that is not base64url", error);
  }
  if (decoded.length !== length || bytesToUrlSafeBase64(decoded) !== value) {
    throw linkCodeInvalid("The device link code holds a value that is not canonical base64url");
  }
  return decoded;
}

function encodeIdentityKeyPair(pair: DeviceLinkIdentityKeyPair, name: string): Uint8Array {
  requireLength(pair.dhPublicKey, X25519_KEY_BYTES, `The device link ${name} dhPublicKey`);
  requireLength(pair.dhPrivateKey, X25519_KEY_BYTES, `The device link ${name} dhPrivateKey`);
  requireLength(pair.signingPublicKey, ED25519_KEY_BYTES, `The device link ${name} signingPublicKey`);
  requireLength(pair.signingPrivateKey, ED25519_KEY_BYTES, `The device link ${name} signingPrivateKey`);
  if (!identityKeyPairMatches(pair)) {
    throw new RangeError(`The device link ${name} public keys do not match its private keys`);
  }
  const fields = [
    encodeBytesField(1, pair.dhPublicKey),
    encodeBytesField(2, pair.dhPrivateKey),
    encodeBytesField(3, pair.signingPublicKey),
    encodeBytesField(4, pair.signingPrivateKey),
  ];
  try {
    return concatFields(...fields);
  } finally {
    for (const field of fields) secureZeroBytes(field);
  }
}

function encodeGroups(groups: readonly DeviceLinkGroup[]): Uint8Array[] {
  const entries = groups.map((group) => {
    if (group.groupId.length === 0) {
      throw new RangeError("A device link groupId must not be empty");
    }
    requireLength(group.masterKey, GROUP_MASTER_KEY_BYTES, "A device link group masterKey");
    return { id: utf8EncodeStrict(group.groupId, "groupId"), masterKey: group.masterKey };
  });
  entries.sort((left, right) => compareBytes(left.id, right.id));
  for (let index = 1; index < entries.length; index += 1) {
    if (compareBytes(entries[index - 1]!.id, entries[index]!.id) === 0) {
      throw new RangeError("The device link groups hold one groupId twice");
    }
  }
  return entries.map((entry) => {
    const masterKey = encodeBytesField(2, entry.masterKey);
    try {
      return concatFields(encodeBytesField(1, entry.id), masterKey);
    } finally {
      secureZeroBytes(masterKey);
    }
  });
}

function decodePlaintextFields(message: Uint8Array): DeviceLinkPlaintext {
  const decodedSecrets: Uint8Array[] = [];
  try {
    return decodePlaintextFieldsInto(message, decodedSecrets);
  } catch (error) {
    for (const secret of decodedSecrets) secureZeroBytes(secret);
    throw error;
  }
}

/** Decodes the plaintext. It adds each private key and master key that it reads to `decodedSecrets`. */
function decodePlaintextFieldsInto(message: Uint8Array, decodedSecrets: Uint8Array[]): DeviceLinkPlaintext {
  const reader = new ProtoReader(message);
  const seen = new Set<number>();
  let version: bigint | undefined;
  let aci: DeviceLinkIdentityKeyPair | undefined;
  let pni: DeviceLinkIdentityKeyPair | undefined;
  let accountAddress: string | undefined;
  let linkToken: string | undefined;
  const groups: DeviceLinkGroup[] = [];
  let previousGroupId: Uint8Array | undefined;
  let encryptedDeviceName: Uint8Array | undefined;
  let applicationData: Uint8Array | undefined;
  let createdAtMs: bigint | undefined;

  while (reader.hasMore()) {
    const { fieldNumber } = reader.readTag();
    if (fieldNumber >= 1 && fieldNumber <= 9 && fieldNumber !== 6) {
      if (seen.has(fieldNumber)) {
        throw envelopeInvalid(`The device link plaintext holds field ${fieldNumber} twice`);
      }
      seen.add(fieldNumber);
    }
    switch (fieldNumber) {
      case 1:
        version = reader.readUint64();
        break;
      case 2:
        aci = readIdentityKeyPair(reader, "aci", decodedSecrets);
        break;
      case 3:
        pni = readIdentityKeyPair(reader, "pni", decodedSecrets);
        break;
      case 4:
        accountAddress = readStrictString(reader);
        break;
      case 5:
        linkToken = readStrictString(reader);
        break;
      case 6: {
        const submessage = reader.readMessage();
        let group: ReturnType<typeof decodeGroup>;
        try {
          group = decodeGroup(submessage, decodedSecrets);
        } finally {
          secureZeroBytes(submessage);
        }
        if (previousGroupId !== undefined && compareBytes(previousGroupId, group.id) >= 0) {
          throw envelopeInvalid("The device link groups are not in strict groupId order");
        }
        previousGroupId = group.id;
        groups.push({ groupId: group.groupId, masterKey: group.masterKey });
        break;
      }
      case 7:
        encryptedDeviceName = reader.readBytes();
        if (encryptedDeviceName.length > DEVICE_LINK_ENCRYPTED_DEVICE_NAME_MAX_BYTES) {
          throw envelopeInvalid("The device link encryptedDeviceName is too large");
        }
        break;
      case 8:
        applicationData = reader.readBytes();
        if (applicationData.length > DEVICE_LINK_APPLICATION_DATA_MAX_BYTES) {
          throw envelopeInvalid("The device link applicationData is too large");
        }
        break;
      case 9:
        createdAtMs = reader.readUint64();
        break;
      default:
        reader.skipField();
    }
  }

  if (version === undefined) throw missingField("version");
  if (version !== BigInt(DEVICE_LINK_PLAINTEXT_VERSION)) {
    throw envelopeInvalid("The device link plaintext has an unknown version");
  }
  if (aci === undefined) throw missingField("aci");
  if (accountAddress === undefined) throw missingField("accountAddress");
  if (linkToken === undefined) throw missingField("linkToken");
  if (accountAddress === "") throw envelopeInvalid("The device link plaintext has an empty accountAddress");
  if (linkToken === "") throw envelopeInvalid("The device link plaintext has an empty linkToken");
  if (createdAtMs === undefined) throw missingField("createdAtMs");
  if (createdAtMs > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw envelopeInvalid("The device link createdAtMs is out of range");
  }

  return {
    aci,
    ...(pni !== undefined && { pni }),
    accountAddress,
    linkToken,
    groups,
    ...(encryptedDeviceName !== undefined && { encryptedDeviceName }),
    ...(applicationData !== undefined && { applicationData }),
    createdAtMs: Number(createdAtMs),
  };
}

function readIdentityKeyPair(
  reader: ProtoReader,
  name: string,
  decodedSecrets: Uint8Array[],
): DeviceLinkIdentityKeyPair {
  const submessage = reader.readMessage();
  try {
    return decodeIdentityKeyPair(submessage, name, decodedSecrets);
  } finally {
    secureZeroBytes(submessage);
  }
}

function decodeIdentityKeyPair(
  message: Uint8Array,
  name: string,
  decodedSecrets: Uint8Array[],
): DeviceLinkIdentityKeyPair {
  const reader = new ProtoReader(message);
  const fields = new Map<number, Uint8Array>();
  while (reader.hasMore()) {
    const { fieldNumber } = reader.readTag();
    if (fieldNumber >= 1 && fieldNumber <= 4) {
      if (fields.has(fieldNumber)) {
        throw envelopeInvalid(`The device link ${name} holds field ${fieldNumber} twice`);
      }
      const value = reader.readBytes();
      fields.set(fieldNumber, value);
      if (fieldNumber === 2 || fieldNumber === 4) decodedSecrets.push(value);
    } else {
      reader.skipField();
    }
  }
  const pair = {
    dhPublicKey: requiredKey(fields.get(1), X25519_KEY_BYTES, `${name} dhPublicKey`),
    dhPrivateKey: requiredKey(fields.get(2), X25519_KEY_BYTES, `${name} dhPrivateKey`),
    signingPublicKey: requiredKey(fields.get(3), ED25519_KEY_BYTES, `${name} signingPublicKey`),
    signingPrivateKey: requiredKey(fields.get(4), ED25519_KEY_BYTES, `${name} signingPrivateKey`),
  };
  if (!identityKeyPairMatches(pair)) {
    throw envelopeInvalid(`The device link ${name} public keys do not match its private keys`);
  }
  return pair;
}

function decodeGroup(
  message: Uint8Array,
  decodedSecrets: Uint8Array[],
): DeviceLinkGroup & { readonly id: Uint8Array } {
  const reader = new ProtoReader(message);
  let id: Uint8Array | undefined;
  let masterKey: Uint8Array | undefined;
  while (reader.hasMore()) {
    const { fieldNumber } = reader.readTag();
    if (fieldNumber === 1 || fieldNumber === 2) {
      if ((fieldNumber === 1 ? id : masterKey) !== undefined) {
        throw envelopeInvalid(`A device link group holds field ${fieldNumber} twice`);
      }
      if (fieldNumber === 1) id = reader.readBytes();
      else {
        masterKey = reader.readBytes();
        decodedSecrets.push(masterKey);
      }
    } else {
      reader.skipField();
    }
  }
  if (id === undefined || id.length === 0) throw missingField("groupId");
  return {
    id,
    groupId: utf8DecodeStrict(id),
    masterKey: requiredKey(masterKey, GROUP_MASTER_KEY_BYTES, "group masterKey"),
  };
}

function identityKeyPairMatches(pair: DeviceLinkIdentityKeyPair): boolean {
  const dhMatches = constantTimeEqual(x25519.getPublicKey(pair.dhPrivateKey), pair.dhPublicKey);
  const signingMatches = constantTimeEqual(
    ed25519.getPublicKey(pair.signingPrivateKey),
    pair.signingPublicKey,
  );
  return dhMatches && signingMatches;
}

/** The private keys and master keys of a decoded plaintext. */
function plaintextSecrets(plaintext: DeviceLinkPlaintext): Uint8Array[] {
  const pairs = plaintext.pni === undefined ? [plaintext.aci] : [plaintext.aci, plaintext.pni];
  return [
    ...pairs.flatMap((pair) => [pair.dhPrivateKey, pair.signingPrivateKey]),
    ...plaintext.groups.map((group) => group.masterKey),
  ];
}

function requiredKey(value: Uint8Array | undefined, length: number, name: string): Uint8Array {
  if (value === undefined) throw missingField(name);
  if (value.length !== length) {
    throw envelopeInvalid(`The device link ${name} has the wrong length`);
  }
  return value;
}

function readStrictString(reader: ProtoReader): string {
  return utf8DecodeStrict(reader.readBytes());
}

/** Decodes UTF-8 and refuses input that does not encode back to the same bytes. */
function utf8DecodeStrict(bytes: Uint8Array): string {
  const value = utf8Decode(bytes, { fatal: true });
  if (!constantTimeEqual(stringToBytes(value), bytes)) {
    throw envelopeInvalid("The device link plaintext holds a string that is not canonical UTF-8");
  }
  return value;
}

/** Encodes UTF-8 and refuses a string with an unpaired surrogate. */
function utf8EncodeStrict(value: string, name: string): Uint8Array {
  const bytes = stringToBytes(value);
  if (utf8Decode(bytes) !== value) {
    throw new RangeError(`The device link ${name} is not well-formed Unicode`);
  }
  return bytes;
}

function compareBytes(left: Uint8Array, right: Uint8Array): number {
  const length = Math.min(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    const difference = left[index]! - right[index]!;
    if (difference !== 0) return difference;
  }
  return left.length - right.length;
}

function requireLength(value: Uint8Array, length: number, name: string): void {
  if (!(value instanceof Uint8Array) || value.length !== length) {
    throw new RangeError(`${name} must be ${length} bytes`);
  }
}

function requireAtMost(value: Uint8Array, limit: number, name: string): void {
  if (!(value instanceof Uint8Array) || value.length > limit) {
    throw new RangeError(`${name} must be ${limit} bytes or less`);
  }
}

function missingField(name: string): HostedSignalProtocolRelayDeviceProvisioningError {
  return envelopeInvalid(`The device link plaintext has no ${name}`);
}

function linkCodeInvalid(
  message: string,
  cause?: unknown,
): HostedSignalProtocolRelayDeviceProvisioningError {
  return new HostedSignalProtocolRelayDeviceProvisioningError(
    "LINK_CODE_INVALID",
    message,
    cause === undefined ? undefined : { cause },
  );
}

function envelopeInvalid(
  message: string,
  cause?: unknown,
): HostedSignalProtocolRelayDeviceProvisioningError {
  return new HostedSignalProtocolRelayDeviceProvisioningError(
    "ENVELOPE_INVALID",
    message,
    cause === undefined ? undefined : { cause },
  );
}
