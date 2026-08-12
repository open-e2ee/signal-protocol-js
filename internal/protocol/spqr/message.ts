/**
 * SPQR Message Header Integration
 *
 * Defines how SPQR chunks embed in Double Ratchet message headers.
 * The `V1Msg` layout is pinned for protocol interoperability.
 *
 * ## Wire Format
 *
 * SPQR V1Msg structure:
 * ```
 * V1Msg {
 *   epoch: uint64
 *   index: uint32 (chunk index for erasure decoding)
 *   inner_msg: oneof {
 *     hdr: Chunk
 *     ek: Chunk
 *     ek_ct1_ack: Chunk
 *     ct1_ack: bool
 *     ct1: Chunk
 *     ct2: Chunk
 *   }
 * }
 * ```
 *
 * @module spqr/message
 */

import { MessageType } from './ml-kem-braid/types';
import type { MLKEMBraidMessage } from './ml-kem-braid/types';
import {
  serializeMessageProto,
  deserializeMessageProto,
  bytesToHex,
  hexToBytes,
} from './ml-kem-braid/serialize';

// =============================================================================
// Message Header Types
// =============================================================================

/**
 * SPQR extension for Double Ratchet message headers.
 *
 * This structure is embedded in each Double Ratchet message header
 * when using SPQR for post-quantum security.
 *
 * @example
 * ```typescript
 * interface DoubleRatchetHeader {
 *   dh: Uint8Array;        // EC public key
 *   pn: number;            // Previous chain length
 *   n: number;             // Message number
 *   spqr?: SPQRMessageHeader;  // PQ security extension
 * }
 * ```
 */
export {};
export interface SPQRMessageHeader {
  /** Protocol format version */
  version: 'v1';
  /** Current SPQR epoch */
  epoch: bigint;
  /** Chunk index for erasure decoding */
  chunkIndex: number;
  /** Message type: Hdr, Ek, Ct1, Ct2, etc. */
  type: MessageType;
  /** Chunk data (typically 32 bytes) */
  data?: Uint8Array;

  // =========================================================================
  // Version Negotiation (only in first message of session)
  // =========================================================================

  /**
   * Version capability advertisement.
   *
   * Included in the first message(s) during version negotiation.
   * Contains our supported version range for the peer to process.
   * After negotiation completes, this field is omitted.
   */
  versionCapability?: {
    /** Maximum version we support */
    maxVersion: 'v1';
    /** Minimum version we accept */
    minVersion: 'v1';
  };
}

/**
 * JSON representation of SPQR message header.
 *
 * Used for debugging and logging.
 */
export interface SPQRMessageHeaderJSON {
  version: 'v1';
  epoch: string;
  chunkIndex: number;
  type: string;
  data?: string;
  versionCapability?: {
    maxVersion: 'v1';
    minVersion: 'v1';
  };
}

// =============================================================================
// Header Embedding Functions
// =============================================================================

/**
 * Create SPQR header from a braid message chunk.
 *
 * Converts an MLKEMBraidMessage to the header format suitable for
 * embedding in Double Ratchet message headers.
 *
 * @param chunk - Braid message chunk to convert
 * @param versionCapability - Optional version capability for negotiation (first message only)
 * @returns SPQR header for embedding
 *
 * @example
 * ```typescript
 * const result = await spqrBraidSend(spqrState);
 * // Version is implicit in byte 0 of every message (binary wire format)
 * for (const chunk of result.chunks) {
 *   const header = createSPQRHeader(chunk, versionCap);
 *   drMessage.header.spqr = header;
 * }
 * ```
 */
export function createSPQRHeader(
  chunk: MLKEMBraidMessage,
  versionCapability?: { maxVersion: 'v1'; minVersion: 'v1' }
): SPQRMessageHeader {
  return {
    version: 'v1',
    epoch: chunk.epoch,
    chunkIndex: chunk.chunkIndex ?? 0,
    type: chunk.type,
    data: chunk.data,
    versionCapability,
  };
}

/**
 * Convert SPQR header back to braid message format.
 *
 * Used when receiving a message with an embedded SPQR header.
 *
 * @param header - SPQR header from received message
 * @returns Braid message for processing
 *
 * @example
 * ```typescript
 * if (receivedMessage.header.spqr) {
 *   const chunk = headerToBraidMessage(receivedMessage.header.spqr);
 *   const result = await spqrBraidReceive(spqrState, chunk);
 * }
 * ```
 */
export function headerToBraidMessage(header: SPQRMessageHeader): MLKEMBraidMessage {
  return {
    epoch: header.epoch,
    type: header.type,
    chunkIndex: header.chunkIndex,
    data: header.data,
  };
}

/**
 * Check if a message header contains SPQR data.
 *
 * @param header - Double Ratchet header to check
 * @returns true if SPQR extension is present
 */
export function hasSPQRHeader(header: { spqr?: SPQRMessageHeader }): boolean {
  return header.spqr !== undefined && header.spqr.type !== MessageType.None;
}

/**
 * Get message type name for debugging.
 *
 * @param type - MessageType enum value
 * @returns Human-readable type name
 */
export function getMessageTypeName(type: MessageType): string {
  const names: Record<MessageType, string> = {
    [MessageType.None]: 'None',
    [MessageType.Hdr]: 'Hdr',
    [MessageType.Ek]: 'Ek',
    [MessageType.EkCt1Ack]: 'EkCt1Ack',
    [MessageType.Ct1Ack]: 'Ct1Ack',
    [MessageType.Ct1]: 'Ct1',
    [MessageType.Ct2]: 'Ct2',
  };
  return names[type] ?? 'Unknown';
}

// =============================================================================
// Serialization
// =============================================================================

/**
 * Serialize SPQR header to Protocol Buffer format.
 *
 * Uses the protobuf format that carries version capability.
 *
 * @param header - Header to serialize
 * @returns Promise resolving to protobuf binary representation
 */
export async function serializeSPQRHeaderProto(header: SPQRMessageHeader): Promise<Uint8Array> {
  const msg: MLKEMBraidMessage = {
    epoch: header.epoch,
    type: header.type,
    chunkIndex: header.chunkIndex,
    data: header.data,
    versionCapability: header.versionCapability,
  };
  return serializeMessageProto(msg);
}

/**
 * Deserialize SPQR header from Protocol Buffer format.
 *
 * @param bytes - Protobuf binary data to deserialize
 * @returns Promise resolving to deserialized header
 */
export async function deserializeSPQRHeaderProto(bytes: Uint8Array): Promise<SPQRMessageHeader> {
  const msg = await deserializeMessageProto(bytes);
  return {
    version: 'v1',
    epoch: msg.epoch,
    chunkIndex: msg.chunkIndex ?? 0,
    type: msg.type,
    data: msg.data,
    versionCapability: msg.versionCapability,
  };
}

/**
 * Serialize SPQR header to JSON for debugging.
 *
 * @param header - Header to serialize
 * @returns JSON representation
 */
export function serializeSPQRHeaderJSON(header: SPQRMessageHeader): SPQRMessageHeaderJSON {
  return {
    version: 'v1',
    epoch: header.epoch.toString(),
    chunkIndex: header.chunkIndex,
    type: getMessageTypeName(header.type),
    data: header.data ? bytesToHex(header.data) : undefined,
    versionCapability: header.versionCapability,
  };
}

/**
 * Deserialize SPQR header from JSON.
 *
 * @param json - JSON representation
 * @returns Deserialized header
 */
export function deserializeSPQRHeaderJSON(json: SPQRMessageHeaderJSON): SPQRMessageHeader {
  const typeMap: Record<string, MessageType> = {
    None: MessageType.None,
    Hdr: MessageType.Hdr,
    Ek: MessageType.Ek,
    EkCt1Ack: MessageType.EkCt1Ack,
    Ct1Ack: MessageType.Ct1Ack,
    Ct1: MessageType.Ct1,
    Ct2: MessageType.Ct2,
  };

  return {
    version: 'v1',
    epoch: BigInt(json.epoch),
    chunkIndex: json.chunkIndex,
    type: typeMap[json.type] ?? MessageType.None,
    data: json.data ? hexToBytes(json.data) : undefined,
    versionCapability: json.versionCapability,
  };
}

// =============================================================================
// Integration Helpers
// =============================================================================

/**
 * Create an empty SPQR header (for direct mode or when no chunk to send).
 *
 * @returns Empty header with None type
 */
export function createEmptySPQRHeader(): SPQRMessageHeader {
  return {
    version: 'v1',
    epoch: 0n,
    chunkIndex: 0,
    type: MessageType.None,
  };
}

/**
 * Calculate overhead of SPQR header in bytes.
 *
 * Binary format: 9 bytes header + optional 34 bytes (2 index + 32 data)
 *
 * @param header - Header to measure
 * @returns Size in bytes
 */
export function getSPQRHeaderSize(header: SPQRMessageHeader): number {
  // Base: 8 bytes epoch + 1 byte type
  let size = 9;
  if (header.data) {
    // Chunk: 2 bytes index + data length
    size += 2 + header.data.length;
  }
  return size;
}

/**
 * Merge SPQR header into Double Ratchet header.
 *
 * Helper for embedding SPQR in existing Double Ratchet messages.
 *
 * @param drHeader - Double Ratchet header to extend
 * @param spqrChunk - SPQR chunk to embed
 * @returns Extended header
 *
 * @example
 * ```typescript
 * const chunk = getNextBraidChunk(spqrState);
 * if (chunk) {
 *   const fullHeader = embedSPQRInHeader(drHeader, chunk);
 *   await sendMessage(fullHeader, ciphertext);
 * }
 * ```
 */
export function embedSPQRInHeader<T extends object>(
  drHeader: T,
  spqrChunk: MLKEMBraidMessage | null
): T & { spqr: SPQRMessageHeader } {
  const spqr = spqrChunk ? createSPQRHeader(spqrChunk) : createEmptySPQRHeader();
  return {
    ...drHeader,
    spqr,
  };
}

/**
 * Extract SPQR chunk from message header if present.
 *
 * @param header - Header that may contain SPQR extension
 * @returns Braid message chunk or null if not present
 */
export function extractSPQRFromHeader(header: {
  spqr?: SPQRMessageHeader;
}): MLKEMBraidMessage | null {
  if (!header.spqr || header.spqr.type === MessageType.None) {
    return null;
  }
  return headerToBraidMessage(header.spqr);
}
