/**
 * Protobuf encoding for safety number QR codes.
 * Follows Signal Protocol's CombinedFingerprints format.
 *
 * Wire format (protobuf):
 * - Field 1 (version): varint
 * - Field 2 (local_fingerprint): length-delimited, contains nested field 1 (content: bytes)
 * - Field 3 (remote_fingerprint): length-delimited, contains nested field 1 (content: bytes)
 *
 */

import {
  decodeVarint,
  encodeBytesField,
  encodeUint32Field,
  skipUnknownField,
  concatFields,
  WIRE_TYPE_VARINT,
  WIRE_TYPE_LENGTH_DELIMITED,
} from '../internal/encoding/proto/primitives';

// ============================================================================
// Types
// ============================================================================
export {};
export interface CombinedFingerprints {
  /** Protocol version (currently 2) */
  version: number;
  /** Local user's fingerprint (32 bytes) */
  localFingerprint: Uint8Array;
  /** Remote user's fingerprint (32 bytes) */
  remoteFingerprint: Uint8Array;
}

// ============================================================================
// Internal: LogicalFingerprint sub-message
// ============================================================================

/**
 * Encode a LogicalFingerprint message.
 * message LogicalFingerprint { optional bytes content = 1; }
 */
function encodeLogicalFingerprint(content: Uint8Array): Uint8Array {
  return encodeBytesField(1, content);
}

/**
 * Decode a LogicalFingerprint message.
 * Returns the content bytes.
 */
function decodeLogicalFingerprint(buffer: Uint8Array): Uint8Array {
  let offset = 0;

  // Read tag
  const { value: tag, bytesRead: tagBytes } = decodeVarint(buffer, offset);
  offset += tagBytes;

  // Verify it's field 1, length-delimited
  const expectedFieldNumber = 1;
  const expectedWireType = WIRE_TYPE_LENGTH_DELIMITED;
  const fieldNumber = tag >>> 3;
  const wireType = tag & 0x07;
  if (fieldNumber !== expectedFieldNumber || wireType !== expectedWireType) {
    throw new Error(
      `Invalid LogicalFingerprint tag: expected field ${expectedFieldNumber} wire type ${expectedWireType}, got field ${fieldNumber} wire type ${wireType}`
    );
  }

  // Read length
  const { value: length, bytesRead: lengthBytes } = decodeVarint(buffer, offset);
  offset += lengthBytes;

  // Read content
  const content = buffer.slice(offset, offset + length);
  if (content.length !== length) {
    throw new Error(
      `Truncated LogicalFingerprint: expected ${length} bytes, got ${content.length}`
    );
  }

  return content;
}

// ============================================================================
// Public API
// ============================================================================

/**
 * Encode CombinedFingerprints to protobuf bytes for QR code.
 *
 * @param data Combined fingerprints data
 * @returns Protobuf-encoded bytes
 */
export function encodeCombinedFingerprints(data: CombinedFingerprints): Uint8Array {
  const parts: Uint8Array[] = [];

  // Field 1: version (varint)
  parts.push(encodeUint32Field(1, data.version));

  // Field 2: local_fingerprint (length-delimited nested message)
  const localFp = encodeLogicalFingerprint(data.localFingerprint);
  parts.push(encodeBytesField(2, localFp));

  // Field 3: remote_fingerprint (length-delimited nested message)
  const remoteFp = encodeLogicalFingerprint(data.remoteFingerprint);
  parts.push(encodeBytesField(3, remoteFp));

  return concatFields(...parts);
}

/**
 * Decode CombinedFingerprints from protobuf bytes.
 *
 * @param data Protobuf-encoded bytes
 * @returns Decoded combined fingerprints
 */
export function decodeCombinedFingerprints(data: Uint8Array): CombinedFingerprints {
  let version: number | null = null;
  let localFingerprint: Uint8Array | null = null;
  let remoteFingerprint: Uint8Array | null = null;

  let offset = 0;

  while (offset < data.length) {
    // Read field tag
    const { value: tag, bytesRead: tagBytes } = decodeVarint(data, offset);
    offset += tagBytes;

    const fieldNumber = tag >>> 3;
    const wireType = tag & 0x7;

    switch (fieldNumber) {
      case 1: // version
        if (wireType !== WIRE_TYPE_VARINT) {
          throw new Error(
            `Invalid wire type for version: expected ${WIRE_TYPE_VARINT}, got ${wireType}`
          );
        }
        {
          const { value: v, bytesRead: vBytes } = decodeVarint(data, offset);
          version = v;
          offset += vBytes;
        }
        break;

      case 2: // local_fingerprint
        if (wireType !== WIRE_TYPE_LENGTH_DELIMITED) {
          throw new Error(
            `Invalid wire type for local_fingerprint: expected ${WIRE_TYPE_LENGTH_DELIMITED}, got ${wireType}`
          );
        }
        {
          const { value: localLen, bytesRead: localLenBytes } = decodeVarint(data, offset);
          offset += localLenBytes;
          const localData = data.slice(offset, offset + localLen);
          localFingerprint = decodeLogicalFingerprint(localData);
          offset += localLen;
        }
        break;

      case 3: // remote_fingerprint
        if (wireType !== WIRE_TYPE_LENGTH_DELIMITED) {
          throw new Error(
            `Invalid wire type for remote_fingerprint: expected ${WIRE_TYPE_LENGTH_DELIMITED}, got ${wireType}`
          );
        }
        {
          const { value: remoteLen, bytesRead: remoteLenBytes } = decodeVarint(data, offset);
          offset += remoteLenBytes;
          const remoteData = data.slice(offset, offset + remoteLen);
          remoteFingerprint = decodeLogicalFingerprint(remoteData);
          offset += remoteLen;
        }
        break;

      default:
        offset = skipUnknownField(wireType, data, offset);
        break;
    }
  }

  if (version === null) {
    throw new Error('Missing version field in CombinedFingerprints');
  }
  if (localFingerprint === null) {
    throw new Error('Missing local_fingerprint field in CombinedFingerprints');
  }
  if (remoteFingerprint === null) {
    throw new Error('Missing remote_fingerprint field in CombinedFingerprints');
  }

  return {
    version,
    localFingerprint,
    remoteFingerprint,
  };
}
