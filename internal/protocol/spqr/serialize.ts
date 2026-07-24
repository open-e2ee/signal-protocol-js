/**
 * SPQR State Serialization
 *
 * @module spqr/serialize
 *
 * Provides serialization and deserialization of SPQR state for persistence.
 * Extracted from spqr.ts for modularity (target: 400 LOC).
 *
 * WARNING: Serialized state contains sensitive cryptographic material.
 * Ensure it is stored securely (encrypted at rest).
 */

import { base64ToBytes, bytesToBase64, type ResolvedSPQRInfoStrings } from '../../crypto';
import type { ResolvedSPQRLimits } from '../../../types/protocol-config';
import { asBase64 } from '../../../types/utils';
import { assertBraidChunkIndex } from './ml-kem-braid/chunk-domain';

// Type-only imports to avoid circular dependency
import type { SPQRState, EpochChains, SkippedSPQRKey } from './spqr';

const SPQR_STATE_FORMAT_VERSION = 2 as const;
const MAX_RESTORED_STATE_BYTES = 1024 * 1024;
const MAX_PERSISTED_EPOCH_CHAINS = 4096;
const MAX_PERSISTED_SKIPPED_KEYS = 10_000;
const MAX_PENDING_BRAID_CHUNKS = 100;

function assertRecord(value: unknown, label: string): asserts value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
}

function assertInteger(value: unknown, label: string, min = 0, max = Number.MAX_SAFE_INTEGER): number {
  if (!Number.isSafeInteger(value) || (value as number) < min || (value as number) > max) {
    throw new Error(`${label} must be an integer between ${min} and ${max}`);
  }
  return value as number;
}

function assertDirection(value: unknown, label: string): asserts value is 'A2B' | 'B2A' {
  if (value !== 'A2B' && value !== 'B2A') throw new Error(`${label} must be A2B or B2A`);
}

function assertCanonicalBase64(value: unknown, label: string, expectedLength: number): string {
  if (typeof value !== 'string') throw new Error(`${label} must be canonical base64`);
  let bytes: Uint8Array;
  try {
    bytes = base64ToBytes(asBase64(value));
  } catch (error) {
    throw new Error(`${label} must be canonical base64`, { cause: error });
  }
  if (bytes.length !== expectedLength || bytesToBase64(bytes) !== value) {
    throw new Error(`${label} must be canonical base64 for exactly ${expectedLength} bytes`);
  }
  return value;
}

function validateChain(value: unknown, label: string): void {
  assertRecord(value, label);
  assertCanonicalBase64(value.CK, `${label}.CK`, 32);
  assertInteger(value.N, `${label}.N`, 0, 0xffffffff);
}

function validateSPQRStateJSON(value: unknown): asserts value is SPQRStateJSON {
  assertRecord(value, 'SPQR state');
  if (value.formatVersion !== SPQR_STATE_FORMAT_VERSION) {
    throw new Error(
      `Unsupported SPQR state format; reset required (expected ${SPQR_STATE_FORMAT_VERSION})`
    );
  }
  assertCanonicalBase64(value.RK, 'SPQR root key', 32);
  assertInteger(value.epoch, 'SPQR epoch', 0, 0xffffffff);
  if (value.sendEpoch !== undefined) assertInteger(value.sendEpoch, 'SPQR sendEpoch', 0, 0xffffffff);
  assertDirection(value.direction, 'SPQR direction');
  if (value.mode !== 'direct' && value.mode !== 'braid') {
    throw new Error('SPQR mode must be direct or braid');
  }

  assertRecord(value.kdfChains, 'SPQR kdfChains');
  const chainEntries = Object.entries(value.kdfChains);
  if (chainEntries.length > MAX_PERSISTED_EPOCH_CHAINS) {
    throw new Error(`SPQR kdfChains exceeds ${MAX_PERSISTED_EPOCH_CHAINS}-entry limit`);
  }
  for (const [epoch, chains] of chainEntries) {
    if (!/^(?:0|[1-9]\d*)$/.test(epoch) || Number(epoch) > 0xffffffff) {
      throw new Error(`Invalid SPQR KDF epoch key: ${epoch}`);
    }
    assertRecord(chains, `SPQR kdfChains[${epoch}]`);
    validateChain(chains.send, `SPQR kdfChains[${epoch}].send`);
    validateChain(chains.receive, `SPQR kdfChains[${epoch}].receive`);
  }

  assertRecord(value.sckaState, 'SPQR sckaState');
  if (Object.prototype.hasOwnProperty.call(value.sckaState, 'previousSharedSecret')) {
    throw new Error('Legacy SPQR state contains previousSharedSecret; reset required');
  }
  assertInteger(value.sckaState.epoch, 'SPQR sckaState.epoch', 0, 0xffffffff);
  assertDirection(value.sckaState.direction, 'SPQR sckaState.direction');
  assertInteger(
    value.sckaState.lastRefreshTimestamp,
    'SPQR sckaState.lastRefreshTimestamp'
  );
  assertInteger(
    value.sckaState.lastRefreshMessageCount,
    'SPQR sckaState.lastRefreshMessageCount',
    0,
    0xffffffff
  );
  if (value.sckaState.ourKyberPrivateKey !== null) {
    assertCanonicalBase64(value.sckaState.ourKyberPrivateKey, 'SPQR private ML-KEM key', 2400);
  }
  if (value.sckaState.theirKyberPublicKey !== null) {
    assertCanonicalBase64(value.sckaState.theirKyberPublicKey, 'SPQR public ML-KEM key', 1184);
  }

  if (value.limits !== undefined) {
    assertRecord(value.limits, 'SPQR limits');
    assertInteger(value.limits.maxMessageJump, 'SPQR maxMessageJump', 1, 1_000_000);
    assertInteger(value.limits.maxOutOfOrderKeys, 'SPQR maxOutOfOrderKeys', 1, MAX_PERSISTED_SKIPPED_KEYS);
  }
  const skippedLimit =
    value.limits && typeof value.limits.maxOutOfOrderKeys === 'number'
      ? value.limits.maxOutOfOrderKeys
      : MAX_PERSISTED_SKIPPED_KEYS;
  assertRecord(value.MKSKIPPED, 'SPQR MKSKIPPED');
  const skippedEntries = Object.entries(value.MKSKIPPED);
  if (skippedEntries.length > skippedLimit) {
    throw new Error(`SPQR MKSKIPPED exceeds ${skippedLimit}-entry limit`);
  }
  for (const [name, skipped] of skippedEntries) {
    assertRecord(skipped, `SPQR MKSKIPPED[${name}]`);
    assertCanonicalBase64(skipped.key, `SPQR MKSKIPPED[${name}].key`, 32);
    assertInteger(skipped.timestamp, `SPQR MKSKIPPED[${name}].timestamp`);
  }

  if (value.versionNegotiation !== undefined) {
    assertRecord(value.versionNegotiation, 'SPQR versionNegotiation');
    if (
      (value.versionNegotiation.status !== 'negotiating' &&
        value.versionNegotiation.status !== 'complete') ||
      value.versionNegotiation.maxVersion !== 'v1' ||
      value.versionNegotiation.minVersion !== 'v1' ||
      (value.versionNegotiation.negotiatedVersion !== undefined &&
        value.versionNegotiation.negotiatedVersion !== 'v1') ||
      (value.versionNegotiation.peerVersion !== undefined &&
        value.versionNegotiation.peerVersion !== 'v1')
    ) {
      throw new Error('Invalid SPQR version negotiation state');
    }
  }
  if (value.infoStrings !== undefined) {
    assertRecord(value.infoStrings, 'SPQR infoStrings');
    for (const field of ['chainStart', 'chainAddEpoch', 'chainNext']) {
      const info = value.infoStrings[field];
      if (typeof info !== 'string' || info.length === 0 || info.length > 1024) {
        throw new Error(`SPQR infoStrings.${field} must contain 1 to 1024 characters`);
      }
    }
  }
  if (value.needsSendRatchet !== undefined && typeof value.needsSendRatchet !== 'boolean') {
    throw new Error('SPQR needsSendRatchet must be boolean');
  }

  if (value.mode === 'braid') {
    if (typeof value.braidState !== 'string') throw new Error('Braid mode requires braidState');
    if (value.pendingOutgoingChunks !== undefined) {
      if (
        !Array.isArray(value.pendingOutgoingChunks) ||
        value.pendingOutgoingChunks.length > MAX_PENDING_BRAID_CHUNKS
      ) {
        throw new Error(`SPQR pending braid chunks exceeds ${MAX_PENDING_BRAID_CHUNKS}-entry limit`);
      }
      for (const [index, chunk] of value.pendingOutgoingChunks.entries()) {
        assertRecord(chunk, `SPQR pendingOutgoingChunks[${index}]`);
        if (typeof chunk.epoch !== 'string' || !/^(?:0|[1-9]\d*)$/.test(chunk.epoch)) {
          throw new Error(`Invalid pending Braid epoch at index ${index}`);
        }
        assertInteger(chunk.type, `SPQR pending Braid type ${index}`, 0, 6);
        if (chunk.chunkIndex !== undefined) {
          assertBraidChunkIndex(
            chunk.chunkIndex,
            `SPQR pending Braid chunk index ${index}`
          );
        }
        if (chunk.data !== undefined) {
          assertCanonicalBase64(chunk.data, `SPQR pending Braid data ${index}`, 32);
        }
      }
    }
  } else if (value.braidState !== undefined || value.pendingOutgoingChunks !== undefined) {
    throw new Error('Direct SPQR state cannot contain Braid state');
  }
}

// ============================================================================
// JSON Type Definitions (for serialization)
// ============================================================================

/**
 * JSON representation of a KDF chain
 */
export {};
export interface KDFChainJSON {
  CK: string;
  N: number;
}

/**
 * JSON representation of epoch chains
 */
export interface EpochChainsJSON {
  send: KDFChainJSON;
  receive: KDFChainJSON;
}

/**
 * JSON representation of a skipped SPQR key
 */
export interface SkippedSPQRKeyJSON {
  /** Message key (Base64 string) */
  key: string;
  timestamp: number;
}

/**
 * JSON representation of SCKA state
 */
export interface SCKAStateJSON {
  epoch: number;
  direction: 'A2B' | 'B2A';
  ourKyberPrivateKey: string | null;
  theirKyberPublicKey: string | null;
  lastRefreshTimestamp: number;
  lastRefreshMessageCount: number;
}

/**
 * JSON representation of pending braid message
 */
export interface PendingBraidMessageJSON {
  epoch: string;
  type: number;
  chunkIndex?: number;
  data?: string;
}

/**
 * JSON representation of version negotiation state
 */
export interface VersionNegotiationStateJSON {
  status: 'negotiating' | 'complete';
  maxVersion: 'v1';
  minVersion: 'v1';
  negotiatedVersion?: 'v1';
  peerVersion?: 'v1';
}

/**
 * JSON representation of full SPQR state for persistence.
 *
 * This interface captures the complete SPQR state including:
 * - Root key and epoch
 * - KDF chains for message key derivation
 * - Skipped message keys for out-of-order handling
 * - SCKA state (direction, Kyber keys)
 * - Mode and version
 * - Braid state (when in braid mode)
 */
export interface SPQRStateJSON {
  /** Persistence schema version. Earlier unversioned state must be reset. */
  formatVersion: typeof SPQR_STATE_FORMAT_VERSION;
  /** Root key (Base64) */
  RK: string;
  /** Current epoch */
  epoch: number;
  /** Latest epoch used for sending (M13: send_epoch-based cleanup) */
  sendEpoch?: number;
  /** KDF chains by epoch */
  kdfChains: Record<number, EpochChainsJSON>;
  /** Skipped message keys */
  MKSKIPPED: Record<string, SkippedSPQRKeyJSON>;
  /** Communication direction */
  direction: 'A2B' | 'B2A';
  /** SCKA state */
  sckaState: SCKAStateJSON;
  /** SCKA mode */
  mode: 'direct' | 'braid';
  /** Protocol version (legacy, use versionNegotiation instead) */
  version?: 'v1';
  /** Version negotiation state */
  versionNegotiation?: VersionNegotiationStateJSON;
  /** Custom HKDF info strings (only persisted if non-default) */
  infoStrings?: ResolvedSPQRInfoStrings;
  /** Security limits (only persisted if non-default) */
  limits?: ResolvedSPQRLimits;

  /** Whether next spqrSend() should do full KEM ratchet */
  needsSendRatchet?: boolean;

  // Braid mode fields (when mode === 'braid')
  /** Serialized braid agent state */
  braidState?: string;
  /** Pending outgoing chunks */
  pendingOutgoingChunks?: PendingBraidMessageJSON[];
}

// ============================================================================
// Serialization Functions
// ============================================================================

/**
 * Serialize SPQR state to JSON for persistence.
 *
 * This enables full state persistence for app backgrounding/restoration.
 * Both direct and braid modes are supported.
 *
 * WARNING: The serialized state contains sensitive cryptographic material
 * (keys, chain state). Ensure it is stored securely (encrypted at rest).
 *
 * @param state - SPQR state to serialize
 * @returns JSON string representation
 *
 * @example
 * ```typescript
 * const json = await serializeSPQRState(spqrState);
 * await secureStorage.set('spqrState', json);
 * ```
 */
export async function serializeSPQRState(state: SPQRState): Promise<string> {
  // Serialize KDF chains
  const kdfChainsJSON: Record<number, EpochChainsJSON> = {};
  for (const [epochStr, chains] of Object.entries(state.kdfChains)) {
    const epoch = parseInt(epochStr, 10);
    kdfChainsJSON[epoch] = {
      send: {
        CK: chains.send.CK,
        N: chains.send.N,
      },
      receive: {
        CK: chains.receive.CK,
        N: chains.receive.N,
      },
    };
  }

  // Serialize skipped keys
  const mkSkippedJSON: Record<string, SkippedSPQRKeyJSON> = {};
  for (const [keyName, value] of Object.entries(state.MKSKIPPED)) {
    mkSkippedJSON[keyName] = {
      key: value.key,
      timestamp: value.timestamp,
    };
  }

  const json: SPQRStateJSON = {
    formatVersion: SPQR_STATE_FORMAT_VERSION,
    RK: state.RK,
    epoch: state.epoch,
    sendEpoch: state.sendEpoch,
    kdfChains: kdfChainsJSON,
    MKSKIPPED: mkSkippedJSON,
    direction: state.direction,
    sckaState: {
      epoch: state.sckaState.epoch,
      direction: state.sckaState.direction,
      ourKyberPrivateKey: state.sckaState.ourKyberPrivateKey,
      theirKyberPublicKey: state.sckaState.theirKyberPublicKey,
      lastRefreshTimestamp: state.sckaState.lastRefreshTimestamp,
      lastRefreshMessageCount: state.sckaState.lastRefreshMessageCount,
    },
    mode: state.mode ?? 'direct',
    // Serialize version negotiation state if present
    versionNegotiation: state.versionNegotiation
      ? {
          status: state.versionNegotiation.status,
          maxVersion: state.versionNegotiation.maxVersion,
          minVersion: state.versionNegotiation.minVersion,
          negotiatedVersion: state.versionNegotiation.negotiatedVersion,
          peerVersion: state.versionNegotiation.peerVersion,
        }
      : undefined,
    // Serialize custom info strings if present
    infoStrings: state.infoStrings,
    // Serialize security limits if present
    limits: state.limits,
    // Serialize needsSendRatchet flag
    needsSendRatchet: state.needsSendRatchet,
  };

  // Serialize braid-specific state if present
  if (state.mode === 'braid' && state.braidState) {
    // Import braid serialization dynamically to avoid circular dependency
    const { serializeBraidAgentState } = await import('./braid-serialize');
    json.braidState = serializeBraidAgentState(state.braidState);

    // Serialize pending chunks
    if (state.pendingOutgoingChunks && state.pendingOutgoingChunks.length > 0) {
      json.pendingOutgoingChunks = state.pendingOutgoingChunks.map((msg) => {
        const chunk: PendingBraidMessageJSON = {
          epoch: msg.epoch.toString(),
          type: msg.type,
        };
        if (msg.chunkIndex !== undefined) {
          chunk.chunkIndex = msg.chunkIndex;
        }
        if (msg.data) {
          chunk.data = bytesToBase64(msg.data);
        }
        return chunk;
      });
    }
  }

  return JSON.stringify(json);
}

/**
 * Deserialize SPQR state from JSON.
 *
 * Restores full SPQR state for resuming after app backgrounding.
 * Both direct and braid modes are supported.
 *
 * @param jsonStr - JSON string from serializeSPQRState
 * @returns Restored SPQR state
 *
 * @example
 * ```typescript
 * const json = await secureStorage.get('spqrState');
 * const spqrState = await deserializeSPQRState(json);
 * ```
 */
export async function deserializeSPQRState(jsonStr: string): Promise<SPQRState> {
  if (new TextEncoder().encode(jsonStr).length > MAX_RESTORED_STATE_BYTES) {
    throw new Error(`SPQR state exceeds ${MAX_RESTORED_STATE_BYTES}-byte input limit`);
  }
  const parsed: unknown = JSON.parse(jsonStr);
  validateSPQRStateJSON(parsed);
  const json = parsed;

  // Restore KDF chains
  const kdfChains: Record<number, EpochChains> = {};
  for (const [epochStr, chains] of Object.entries(json.kdfChains)) {
    const epochNum = parseInt(epochStr, 10);
    kdfChains[epochNum] = {
      send: {
        CK: asBase64(chains.send.CK),
        N: chains.send.N,
      },
      receive: {
        CK: asBase64(chains.receive.CK),
        N: chains.receive.N,
      },
    };
  }

  // Restore skipped keys
  const MKSKIPPED: Record<string, SkippedSPQRKey> = {};
  for (const [keyName, value] of Object.entries(json.MKSKIPPED)) {
    MKSKIPPED[keyName] = {
      key: asBase64(value.key),
      timestamp: value.timestamp,
    };
  }

  const state: SPQRState = {
    RK: asBase64(json.RK),
    epoch: json.epoch,
    sendEpoch: json.sendEpoch,
    kdfChains,
    MKSKIPPED,
    direction: json.direction,
    sckaState: {
      epoch: json.sckaState.epoch,
      direction: json.sckaState.direction,
      ourKyberPrivateKey: json.sckaState.ourKyberPrivateKey
        ? asBase64(json.sckaState.ourKyberPrivateKey)
        : null,
      theirKyberPublicKey: json.sckaState.theirKyberPublicKey
        ? asBase64(json.sckaState.theirKyberPublicKey)
        : null,
      lastRefreshTimestamp: json.sckaState.lastRefreshTimestamp,
      lastRefreshMessageCount: json.sckaState.lastRefreshMessageCount,
    },
    mode: json.mode,
    // Restore version negotiation state if present
    versionNegotiation: json.versionNegotiation
      ? {
          status: json.versionNegotiation.status,
          maxVersion: json.versionNegotiation.maxVersion,
          minVersion: json.versionNegotiation.minVersion,
          negotiatedVersion: json.versionNegotiation.negotiatedVersion,
          peerVersion: json.versionNegotiation.peerVersion,
        }
      : undefined,
    // Restore custom info strings if present
    infoStrings: json.infoStrings,
    // Restore security limits if present
    limits: json.limits,
    // Restore needsSendRatchet flag
    needsSendRatchet: json.needsSendRatchet,
  };

  // Restore braid-specific state if present
  if (json.mode === 'braid' && json.braidState) {
    // Import braid deserialization dynamically to avoid circular dependency
    const { deserializeBraidAgentState } = await import('./braid-serialize');
    state.braidState = deserializeBraidAgentState(json.braidState);

    // Restore pending chunks
    if (json.pendingOutgoingChunks && json.pendingOutgoingChunks.length > 0) {
      state.pendingOutgoingChunks = json.pendingOutgoingChunks.map((chunk) => ({
        epoch: BigInt(chunk.epoch),
        type: chunk.type,
        chunkIndex: chunk.chunkIndex,
        data: chunk.data ? base64ToBytes(asBase64(chunk.data)) : undefined,
      }));
    } else {
      state.pendingOutgoingChunks = [];
    }
  }

  return state;
}
