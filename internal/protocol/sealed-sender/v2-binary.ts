/**
 * V2 Multi-Recipient Sealed Sender Binary Serialization
 *
 * Implements custom binary wire format for V2 multi-recipient
 * sealed sender messages. This is NOT protobuf - it's a compact binary
 * format designed for efficient multi-recipient fan-out.
 *
 * Wire format (sent message):
 *   [version(1)][recipient_count(varint)][per-recipient data][e_pub(32)][ciphertext]
 *
 * Wire format (received message):
 *   [version(1)][C_i(32)][AT_i(16)][e_pub(32)][ciphertext]
 *
 * @see https://signal.org/blog/sealed-sender/
 */

import { encodeVarint, decodeVarint, concatFields } from '../../encoding/proto/primitives';
import { SEALED_SENDER_V2_UUID_VERSION, SEALED_SENDER_V2_SERVICE_ID_VERSION } from './types';

// ============================================================================
// Constants
// ============================================================================

/** ACI service ID type marker byte */
export {};
const ACI_MARKER = 0x00;

/** Size of a ServiceId on the wire: 1 marker + 16 UUID bytes */
const SERVICE_ID_WIRE_SIZE = 17;

/** Size of UUID bytes (without marker) */
const UUID_BYTES = 16;

/** Encrypted message key size */
const ENCRYPTED_KEY_SIZE = 32;

/** Authentication tag size */
const AUTH_TAG_SIZE = 16;

/** Ephemeral public key size (raw X25519, no 0x05 prefix) */
const EPHEMERAL_PUBLIC_SIZE = 32;

/** Bit mask for 14-bit registration ID */
const REG_ID_MASK = 0x3fff;

/** Flag bit indicating more devices follow */
const HAS_MORE_DEVICES_FLAG = 0x8000;

/** Device ID zero signals an excluded recipient (no devices) */
const EXCLUDED_RECIPIENT_DEVICE_ID = 0x00;

// ============================================================================
// ServiceId Encoding
// ============================================================================

/**
 * Convert a service ID string to 16 bytes for wire format.
 *
 * ServiceIds must use UUID format (8-4-4-4-12 hexadecimal digits).
 *
 */
export function serviceIdToBytes(serviceId: string): Uint8Array {
  const hex = serviceId.replace(/-/g, '');
  if (!/^[0-9a-f]{32}$/i.test(hex)) {
    throw new Error('serviceId must be a valid UUID');
  }
  const bytes = new Uint8Array(UUID_BYTES);
  for (let i = 0; i < UUID_BYTES; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Convert 16 bytes back to a UUID-formatted string.
 *
 * Always formats as UUID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx).
 * For non-UUID original IDs, the caller must map back by position.
 */
export function bytesToServiceId(bytes: Uint8Array): string {
  if (bytes.length !== UUID_BYTES) {
    throw new Error(`Expected ${UUID_BYTES} bytes for ServiceId, got ${bytes.length}`);
  }
  const hex = Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

// ============================================================================
// Sent Message Serialization (Client -> Server)
// ============================================================================

/**
 * Recipient data for serialization.
 */
export interface SentMessageRecipient {
  serviceId: string;
  devices: Array<{ deviceId: number; registrationId: number }>;
  encryptedMessageKey: Uint8Array; // C_i, 32 bytes
  authenticationTag: Uint8Array; // AT_i, 16 bytes
}

/**
 * Excluded recipient (receives no key material).
 */
export interface ExcludedRecipient {
  serviceId: string;
}

/**
 * Serialize a V2 multi-recipient sealed-sender message.
 *
 * Format: [0x23(1)][count(varint)][per-recipient data][e_pub(32)][ciphertext]
 *
 * @param recipients - Included recipients with per-device data and key material
 * @param excludedRecipients - Excluded recipients (ServiceId + no-devices marker)
 * @param ephemeralPublic - 32 bytes raw X25519 public key (no 0x05 prefix)
 * @param messageCiphertext - Encrypted message content
 * @returns Serialized binary blob
 *
 */
export function serializeSentMessage(
  recipients: SentMessageRecipient[],
  excludedRecipients: ExcludedRecipient[],
  ephemeralPublic: Uint8Array,
  messageCiphertext: Uint8Array
): Uint8Array {
  if (ephemeralPublic.length !== EPHEMERAL_PUBLIC_SIZE) {
    throw new Error(
      `ephemeralPublic must be ${EPHEMERAL_PUBLIC_SIZE} bytes, got ${ephemeralPublic.length}`
    );
  }

  const parts: Uint8Array[] = [];

  // 1. Version byte
  parts.push(new Uint8Array([SEALED_SENDER_V2_SERVICE_ID_VERSION]));

  // 2. Total recipient count (included + excluded)
  const totalCount = recipients.length + excludedRecipients.length;
  parts.push(encodeVarint(totalCount));

  // 3. Included recipients
  for (const recipient of recipients) {
    if (recipient.devices.length === 0) {
      throw new Error(`Included recipient ${recipient.serviceId} must have at least one device`);
    }
    if (recipient.encryptedMessageKey.length !== ENCRYPTED_KEY_SIZE) {
      throw new Error(
        `encryptedMessageKey must be ${ENCRYPTED_KEY_SIZE} bytes, got ${recipient.encryptedMessageKey.length}`
      );
    }
    if (recipient.authenticationTag.length !== AUTH_TAG_SIZE) {
      throw new Error(
        `authenticationTag must be ${AUTH_TAG_SIZE} bytes, got ${recipient.authenticationTag.length}`
      );
    }

    // ServiceId: [ACI_MARKER(1)][UUID bytes(16)]
    const serviceIdBytes = new Uint8Array(SERVICE_ID_WIRE_SIZE);
    serviceIdBytes[0] = ACI_MARKER;
    serviceIdBytes.set(serviceIdToBytes(recipient.serviceId), 1);
    parts.push(serviceIdBytes);

    // Device list: for each device [deviceId(1)][regId_with_flag(2 BE)]
    for (let i = 0; i < recipient.devices.length; i++) {
      const device = recipient.devices[i];
      const isLast = i === recipient.devices.length - 1;
      const regIdWithFlag =
        (device.registrationId & REG_ID_MASK) | (isLast ? 0x0000 : HAS_MORE_DEVICES_FLAG);

      const deviceBytes = new Uint8Array(3);
      deviceBytes[0] = device.deviceId & 0xff;
      // Big-endian 16-bit registration ID with flag
      deviceBytes[1] = (regIdWithFlag >> 8) & 0xff;
      deviceBytes[2] = regIdWithFlag & 0xff;
      parts.push(deviceBytes);
    }

    // Key material: [C_i(32)][AT_i(16)]
    parts.push(recipient.encryptedMessageKey);
    parts.push(recipient.authenticationTag);
  }

  // 4. Excluded recipients
  for (const excluded of excludedRecipients) {
    // ServiceId: [ACI_MARKER(1)][UUID bytes(16)]
    const serviceIdBytes = new Uint8Array(SERVICE_ID_WIRE_SIZE);
    serviceIdBytes[0] = ACI_MARKER;
    serviceIdBytes.set(serviceIdToBytes(excluded.serviceId), 1);
    parts.push(serviceIdBytes);

    // No-devices marker: single zero byte
    parts.push(new Uint8Array([EXCLUDED_RECIPIENT_DEVICE_ID]));
  }

  // 5. Ephemeral public key (32 bytes, raw)
  parts.push(ephemeralPublic);

  // 6. Message ciphertext (remaining bytes)
  parts.push(messageCiphertext);

  return concatFields(...parts);
}

// ============================================================================
// Sent Message Deserialization
// ============================================================================

/**
 * Parsed recipient from a deserialized sent message.
 */
export interface ParsedSentRecipient {
  serviceId: string;
  devices: Array<{ deviceId: number; registrationId: number }>;
  encryptedMessageKey: Uint8Array;
  authenticationTag: Uint8Array;
}

/**
 * Result of deserializing a sent message.
 */
export interface DeserializedSentMessage {
  version: number;
  recipients: ParsedSentRecipient[];
  excludedRecipients: Array<{ serviceId: string }>;
  ephemeralPublic: Uint8Array;
  messageCiphertext: Uint8Array;
}

/**
 * Deserialize a V2 multi-recipient sealed-sender message.
 *
 * @param data - Serialized binary blob
 * @returns Parsed message structure
 *
 */
export function deserializeSentMessage(data: Uint8Array): DeserializedSentMessage {
  if (data.length < 1) {
    throw new Error('Empty sealed sender V2 message');
  }

  let offset = 0;

  // 1. Version byte
  const version = data[offset++];
  if (version !== SEALED_SENDER_V2_SERVICE_ID_VERSION) {
    throw new Error(
      `Unexpected version byte: 0x${version.toString(16).padStart(2, '0')}, ` +
        `expected 0x${SEALED_SENDER_V2_SERVICE_ID_VERSION.toString(16).padStart(2, '0')}`
    );
  }

  // 2. Recipient count (varint)
  const { value: recipientCount, bytesRead: countBytes } = decodeVarint(data, offset);
  offset += countBytes;

  // 3. Parse each recipient
  const recipients: ParsedSentRecipient[] = [];
  const excludedRecipients: Array<{ serviceId: string }> = [];

  for (let r = 0; r < recipientCount; r++) {
    // ServiceId: [marker(1)][UUID bytes(16)]
    if (offset + SERVICE_ID_WIRE_SIZE > data.length) {
      throw new Error('Truncated ServiceId');
    }
    // Skip the marker byte (ACI_MARKER = 0x00)
    offset += 1;
    const uuidBytes = data.slice(offset, offset + UUID_BYTES);
    offset += UUID_BYTES;
    const serviceId = bytesToServiceId(uuidBytes);

    // First device byte — if 0x00, this is an excluded recipient
    if (offset >= data.length) {
      throw new Error('Truncated device list');
    }
    const firstDeviceByte = data[offset];

    if (firstDeviceByte === EXCLUDED_RECIPIENT_DEVICE_ID) {
      // Excluded recipient: just the zero byte, no key material
      offset += 1;
      excludedRecipients.push({ serviceId });
      continue;
    }

    // Included recipient: parse device list
    const devices: Array<{ deviceId: number; registrationId: number }> = [];
    let hasMore = true;

    while (hasMore) {
      if (offset + 3 > data.length) {
        throw new Error('Truncated device entry');
      }
      const deviceId = data[offset++];
      // Big-endian 16-bit registration ID with flag
      const regIdWithFlag = (data[offset] << 8) | data[offset + 1];
      offset += 2;

      const registrationId = regIdWithFlag & REG_ID_MASK;
      hasMore = (regIdWithFlag & HAS_MORE_DEVICES_FLAG) !== 0;

      devices.push({ deviceId, registrationId });
    }

    // Key material: [C_i(32)][AT_i(16)]
    if (offset + ENCRYPTED_KEY_SIZE + AUTH_TAG_SIZE > data.length) {
      throw new Error('Truncated key material');
    }
    const encryptedMessageKey = data.slice(offset, offset + ENCRYPTED_KEY_SIZE);
    offset += ENCRYPTED_KEY_SIZE;
    const authenticationTag = data.slice(offset, offset + AUTH_TAG_SIZE);
    offset += AUTH_TAG_SIZE;

    recipients.push({
      serviceId,
      devices,
      encryptedMessageKey,
      authenticationTag,
    });
  }

  // 4. Ephemeral public key (32 bytes)
  if (offset + EPHEMERAL_PUBLIC_SIZE > data.length) {
    throw new Error('Truncated ephemeral public key');
  }
  const ephemeralPublic = data.slice(offset, offset + EPHEMERAL_PUBLIC_SIZE);
  offset += EPHEMERAL_PUBLIC_SIZE;

  // 5. Message ciphertext (remaining bytes)
  const messageCiphertext = data.slice(offset);

  return {
    version,
    recipients,
    excludedRecipients,
    ephemeralPublic,
    messageCiphertext,
  };
}

// ============================================================================
// Received Message Serialization (Per-Device View)
// ============================================================================

/**
 * Serialize a per-device received message view.
 *
 * Format: [0x22(1)][C_i(32)][AT_i(16)][e_pub(32)][ciphertext]
 *
 * @param encryptedMessageKey - 32 bytes encrypted message key (C_i)
 * @param authenticationTag - 16 bytes authentication tag (AT_i)
 * @param ephemeralPublic - 32 bytes raw X25519 public key
 * @param messageCiphertext - Encrypted message content
 * @returns Serialized per-device blob
 */
export function serializeReceivedMessage(
  encryptedMessageKey: Uint8Array,
  authenticationTag: Uint8Array,
  ephemeralPublic: Uint8Array,
  messageCiphertext: Uint8Array
): Uint8Array {
  if (encryptedMessageKey.length !== ENCRYPTED_KEY_SIZE) {
    throw new Error(
      `encryptedMessageKey must be ${ENCRYPTED_KEY_SIZE} bytes, got ${encryptedMessageKey.length}`
    );
  }
  if (authenticationTag.length !== AUTH_TAG_SIZE) {
    throw new Error(
      `authenticationTag must be ${AUTH_TAG_SIZE} bytes, got ${authenticationTag.length}`
    );
  }
  if (ephemeralPublic.length !== EPHEMERAL_PUBLIC_SIZE) {
    throw new Error(
      `ephemeralPublic must be ${EPHEMERAL_PUBLIC_SIZE} bytes, got ${ephemeralPublic.length}`
    );
  }

  return concatFields(
    new Uint8Array([SEALED_SENDER_V2_UUID_VERSION]),
    encryptedMessageKey,
    authenticationTag,
    ephemeralPublic,
    messageCiphertext
  );
}

// ============================================================================
// Received Message Deserialization
// ============================================================================

/**
 * Result of deserializing a per-device received message.
 */
export interface DeserializedReceivedMessage {
  version: number;
  encryptedMessageKey: Uint8Array;
  authenticationTag: Uint8Array;
  ephemeralPublic: Uint8Array;
  messageCiphertext: Uint8Array;
}

/**
 * Deserialize a per-device received message view.
 *
 * @param data - Serialized per-device blob
 * @returns Parsed message fields
 */
export function deserializeReceivedMessage(data: Uint8Array): DeserializedReceivedMessage {
  // Minimum size: 1 (version) + 32 (C_i) + 16 (AT_i) + 32 (e_pub) = 81 bytes
  const HEADER_SIZE = 1 + ENCRYPTED_KEY_SIZE + AUTH_TAG_SIZE + EPHEMERAL_PUBLIC_SIZE;
  if (data.length < HEADER_SIZE) {
    throw new Error(`Received message too short: ${data.length} bytes, minimum ${HEADER_SIZE}`);
  }

  let offset = 0;

  // Version byte
  const version = data[offset++];
  if (version !== SEALED_SENDER_V2_UUID_VERSION) {
    throw new Error(
      `Unexpected received message version: 0x${version.toString(16).padStart(2, '0')}, ` +
        `expected 0x${SEALED_SENDER_V2_UUID_VERSION.toString(16).padStart(2, '0')}`
    );
  }

  // C_i (32 bytes)
  const encryptedMessageKey = data.slice(offset, offset + ENCRYPTED_KEY_SIZE);
  offset += ENCRYPTED_KEY_SIZE;

  // AT_i (16 bytes)
  const authenticationTag = data.slice(offset, offset + AUTH_TAG_SIZE);
  offset += AUTH_TAG_SIZE;

  // e_pub (32 bytes)
  const ephemeralPublic = data.slice(offset, offset + EPHEMERAL_PUBLIC_SIZE);
  offset += EPHEMERAL_PUBLIC_SIZE;

  // Ciphertext (remaining)
  const messageCiphertext = data.slice(offset);

  return {
    version,
    encryptedMessageKey,
    authenticationTag,
    ephemeralPublic,
    messageCiphertext,
  };
}
