/**
 * Sender Keys Protocol Implementation (Signal Protocol Group V2)
 *
 * Implements the package's Sender Keys construction for efficient group messaging.
 * Each group member has a sender key that encrypts messages for all members.
 *
 * Key Features:
 * - O(1) encryption complexity (encrypt once, N recipients decrypt)
 * - Per-device sender keys (multi-device support)
 * - Automatic key rotation on membership changes (forward secrecy)
 * - Ed25519 signatures for message authenticity
 *
 * KDF Pattern (same as Double Ratchet symmetric ratchet):
 * - Message Key = HMAC-SHA256(Chain Key, 0x01)
 * - Next Chain Key = HMAC-SHA256(Chain Key, 0x02)
 *
 * @see https://signal.org/docs/specifications/doubleratchet/ (Section 7.2 for KDF)
 */

import * as crypto from '../../crypto';
import type { ISignalLocalStore } from '../../../types/api';
import type { Signature, PublicKey, PrivateKey } from '../../../keys';
import { SENDER_KEY_FORMAT, SENDER_KEY_MESSAGE_VERSION } from '../../../versions';
import { defaultSignalLogger, type ILogger } from '../../../logger';
import { asBase64, type Base64 } from '../../../types/utils';
import {
  type SenderKeysConfig,
  SENDER_KEYS_DEFAULTS,
  MAX_SENDER_KEY_STATES,
} from '../../../types/protocol-config';
import { EncryptionError, EncryptionErrorCode } from '../../../types/errors';
import {
  encodeSenderKeyMessage,
  decodeSenderKeyMessage,
  frameSenderKeyMessage,
  parseSenderKeyMessage,
  SENDERKEY_MESSAGE_CURRENT_VERSION,
} from '../../encoding/proto/sender-key-message';

// ============================================================================
// Types
// ============================================================================
export {};
export interface SenderKeyState {
  senderKeyId: string; // Unique identifier: {groupId}:{userId}:{deviceId}:{timestamp}

  /**
   * Sender key wire format version for protocol evolution.
   *
   * Format 'v1' (current): Ed25519 signatures, AES-256-CBC encryption
   * Future versions may support format changes or algorithm upgrades.
   */
  senderKeyVersion: string;

  /**
   * Chain identifier serialized as uint32 field 2.
   *
   * Derived deterministically from senderKeyId via FNV-1a hash.
   * Included in protobuf-encoded messages for wire compatibility.
   */
  chainId: number;

  generation: number; // Key generation (increments on rotation)
  chainKey: string; // Current chain key (ratchets forward on each message) - Base64
  signatureKey: string; // Ed25519 private key for signing - Base64
  publicSignatureKey: string; // Ed25519 public key for verification - Base64
  chainIndex: number; // Current message number in chain

  /**
   * Creation timestamp (ms since epoch) for time-based rotation.
   *
   * Only locally created encryption keys are checked for expiration. Received
   * decryption keys remain usable for delayed messages.
   */
  createdAt: number;
}

export interface SenderKeyDistributionMessage {
  senderKeyId: string;
  chainId: number;
  generation: number;
  chainIndex: number; // Chain index at distribution time (typically 0, allows resync)
  chainKey: string; // Base64
  publicSignatureKey: string; // Base64
}

export interface EncryptedGroupMessage {
  senderKeyId: string;
  generation: number; // Key generation (for spec compliance - Section 3.5)
  chainIndex: number;
  ciphertext: string; // Base64-encoded AES-256-CBC encrypted content
  signature: string; // Base64-encoded Ed25519 signature (provides authenticity)
}

// ============================================================================
// KDF Constants (Signal Protocol - same as Double Ratchet symmetric ratchet)
// ============================================================================

/**
 * Signal Protocol KDF constants for chain key derivation.
 *
 * From Double Ratchet spec Section 7.2 -
 * "HMAC with SHA-256 or SHA-512 is recommended, using ck as the HMAC key
 * and using separate constants as input (e.g. a single byte 0x01 as input
 * to produce the message key, and a single byte 0x02 as input to produce
 * the next chain key)."
 *
 * @see https://signal.org/docs/specifications/doubleratchet/#external-functions
 */
const MESSAGE_KEY_CONSTANT = new Uint8Array([0x01]);
const CHAIN_KEY_CONSTANT = new Uint8Array([0x02]);

// ============================================================================
// Sender Key Manager
// ============================================================================

export class SenderKeyManager {
  /** Resolved configuration values */
  private readonly hkdfInfoString: string;
  private readonly maxChainAdvance: number;
  private readonly maxSkippedKeys: number;
  private readonly maxSenderKeyAge: number;

  /**
   * In-memory cache of previous sender key states for rotation transitions.
   *
   * Keep up to MAX_SENDER_KEY_STATES per sender to decrypt in-flight
   * messages encrypted with a previous key during the rotation window.
   *
   * This cache is backed by persistent storage via storeSenderKeyRecord/
   * getSenderKeyRecord (when available). On cache miss, previous states
   * are loaded from storage.
   *
   * Key format: `${groupId}:${userId}:${deviceId}`
   * Value: Array of previous states (most recent first), capped at MAX_SENDER_KEY_STATES - 1
   *        (the current state is in storage, previous states are here)
   */
  private readonly previousStates = new Map<string, SenderKeyState[]>();
  private readonly logger: Required<ILogger>;

  constructor(
    private storage: ISignalLocalStore,
    config?: SenderKeysConfig,
    logger: Required<ILogger> = defaultSignalLogger
  ) {
    this.logger = logger;
    // Resolve config with defaults
    this.hkdfInfoString = config?.hkdfInfoString ?? SENDER_KEYS_DEFAULTS.hkdfInfoString;
    this.maxChainAdvance = config?.maxChainAdvance ?? SENDER_KEYS_DEFAULTS.maxChainAdvance;
    this.maxSkippedKeys = config?.maxSkippedKeys ?? SENDER_KEYS_DEFAULTS.maxSkippedKeys;
    this.maxSenderKeyAge = config?.maxSenderKeyAge ?? SENDER_KEYS_DEFAULTS.maxSenderKeyAge;
  }

  /**
   * Get the storage key for the previousStates map.
   */
  private stateKey(groupId: string, userId: string, deviceId: number): string {
    return `${groupId}:${userId}:${deviceId}`;
  }

  /**
   * Convert decrypted bytes into a lossless string representation.
   *
   * Plain UTF-8 text and JSON round-trip unchanged. Binary protobuf payloads do
   * not, so we return base64 for those and let the content layer deserialize it.
   */
  private encodeLosslessPlaintext(plaintextBytes: Uint8Array): string {
    const text = new TextDecoder().decode(plaintextBytes);
    const roundTrip = new TextEncoder().encode(text);

    if (
      roundTrip.length === plaintextBytes.length &&
      roundTrip.every((byte, index) => byte === plaintextBytes[index])
    ) {
      return text;
    }

    return crypto.bytesToBase64(plaintextBytes);
  }

  /**
   * Generate a deterministic uint32 chain ID from senderKeyId using FNV-1a hash.
   *
   * The value is serialized as the uint32 `chain_id` field.
   */
  private generateChainId(senderKeyId: string): number {
    let hash = 0x811c9dc5; // FNV-1a offset basis
    for (let i = 0; i < senderKeyId.length; i++) {
      hash ^= senderKeyId.charCodeAt(i);
      hash = Math.imul(hash, 0x01000193); // FNV prime
    }
    return hash >>> 0; // Ensure unsigned 32-bit
  }

  /**
   * Persist the full sender key record (current + previous states) to storage.
   *
   * Per Sender Keys spec Section 5.1 - "Implementations MUST store sender key
   * state persistently." This persists the full record atomically.
   */
  private async persistSenderKeyRecord(
    groupId: string,
    userId: string,
    deviceId: number,
    currentState: SenderKeyState,
    previousStatesList: SenderKeyState[]
  ): Promise<void> {
    const allStates = [currentState, ...previousStatesList];
    await this.storage.storeSenderKeyRecord(groupId, userId, deviceId, allStates);
  }

  /**
   * Load previous states from storage, populating the in-memory cache.
   *
   * Called on cache miss when trying to decrypt with previous states.
   * Uses getSenderKeyRecord if available, otherwise returns empty array.
   */
  private async loadPreviousStates(
    groupId: string,
    userId: string,
    deviceId: number
  ): Promise<SenderKeyState[]> {
    const key = this.stateKey(groupId, userId, deviceId);

    // Check cache first
    const cached = this.previousStates.get(key);
    if (cached !== undefined) {
      return cached;
    }

    // Load from persistent storage
    const record = await this.storage.getSenderKeyRecord(groupId, userId, deviceId);
    if (record && record.length > 1) {
      // First element is current state (already in storage via getSenderKey),
      // remaining elements are previous states.
      // Cap at MAX_SENDER_KEY_STATES - 1 defensively (storage may have stale extras).
      const prev = record.slice(1, MAX_SENDER_KEY_STATES);
      this.previousStates.set(key, prev);
      return prev;
    }

    // No previous states available
    const empty: SenderKeyState[] = [];
    this.previousStates.set(key, empty);
    return empty;
  }

  /**
   * Create new sender key for group
   * Called when joining a group or rotating keys
   *
   * @param groupId - Group identifier
   * @param userId - User identifier
   * @param deviceId - Device identifier
   * @returns Sender key ID and distribution message to share with group
   */
  async createSenderKey(
    groupId: string,
    userId: string,
    deviceId: number
  ): Promise<{
    senderKeyId: string;
    distributionMessage: SenderKeyDistributionMessage;
  }> {
    // Generate unique sender key ID
    const senderKeyId = `${groupId}:${userId}:${deviceId}:${Date.now()}`;
    const chainId = this.generateChainId(senderKeyId);

    // Generate key material
    const chainKey = await crypto.generateRandomBytes(32);
    const signatureKeyPair = await crypto.generateSigningKeyPair();

    // Create sender key state
    const now = Date.now();
    const state: SenderKeyState = {
      senderKeyId,
      senderKeyVersion: SENDER_KEY_FORMAT,
      chainId,
      generation: 1,
      chainKey: crypto.bytesToBase64(chainKey),
      signatureKey: signatureKeyPair.privateKey, // Already Base64-encoded PrivateKey
      publicSignatureKey: signatureKeyPair.publicKey, // Already Base64-encoded PublicKey
      chainIndex: 0,
      createdAt: now,
    };

    // Store sender key (with empty previous states for a new key)
    await this.persistSenderKeyRecord(groupId, userId, deviceId, state, []);
    this.previousStates.set(this.stateKey(groupId, userId, deviceId), []);

    // Create distribution message (to send to other members)
    const distributionMessage: SenderKeyDistributionMessage = {
      senderKeyId,
      chainId,
      generation: 1,
      chainIndex: 0,
      chainKey: crypto.bytesToBase64(chainKey),
      publicSignatureKey: signatureKeyPair.publicKey, // Already Base64-encoded PublicKey
    };

    this.logger.debug('Created sender key', {
      category: 'E2EE',
      data: { senderKeyId, groupId },
    });

    return { senderKeyId, distributionMessage };
  }

  /**
   * Process received sender key distribution message
   * Store sender key for another member
   *
   * Validates against existing state per spec Section 3.4 -
   * - Rejects if generation < existing (stale distribution)
   * - Rejects if generation == existing AND chainIndex <= existing (replay)
   * - Accepts if generation > existing (key rotation)
   *
   * @param groupId - Group identifier
   * @param senderId - Sender user identifier
   * @param senderDeviceId - Sender device identifier
   * @param message - Distribution message with key material
   */
  async processSenderKeyDistribution(
    groupId: string,
    senderId: string,
    senderDeviceId: number,
    message: SenderKeyDistributionMessage
  ): Promise<void> {
    // Validate against existing state (Specification Section 3.4)
    const existing = await this.storage.getSenderKey(groupId, senderId, senderDeviceId);

    if (existing !== null) {
      // Reject if generation is lower (stale distribution)
      if (message.generation < existing.generation) {
        this.logger.debug('Rejected stale distribution (lower generation)', {
          category: 'E2EE',
          data: {
            senderKeyId: message.senderKeyId,
            existingGen: existing.generation,
            receivedGen: message.generation,
          },
        });
        return;
      }

      // Same generation: always keep existing state.
      // The existing state may have advanced beyond the distribution's chainIndex
      // via message decryption, so overwriting would lose chain progress.
      if (message.generation === existing.generation) {
        const receivedChainIndex = message.chainIndex ?? 0;
        if (receivedChainIndex <= existing.chainIndex) {
          this.logger.debug('Rejected stale distribution (same gen, not newer chain)', {
            category: 'E2EE',
            data: {
              senderKeyId: message.senderKeyId,
              existingChain: existing.chainIndex,
              receivedChain: receivedChainIndex,
            },
          });
          return;
        }
        // Same generation but distribution has higher chainIndex:
        // This is a re-broadcast. Keep existing chain progress if it's more advanced,
        // The existing state may have advanced beyond the distribution's chainIndex
        // via message decryption, so don't overwrite.
        this.logger.debug(
          'Received re-broadcast distribution (same gen, higher chain), keeping existing state',
          {
            category: 'E2EE',
            data: {
              senderKeyId: message.senderKeyId,
              existingChain: existing.chainIndex,
              receivedChain: receivedChainIndex,
            },
          }
        );
        return;
      }
    }

    // Create state from distribution message
    const state: SenderKeyState = {
      senderKeyId: message.senderKeyId,
      senderKeyVersion: SENDER_KEY_FORMAT,
      chainId: message.chainId,
      generation: message.generation,
      chainKey: message.chainKey,
      signatureKey: '', // Don't store sender's private key
      publicSignatureKey: message.publicSignatureKey,
      chainIndex: message.chainIndex ?? 0,
      createdAt: Date.now(), // Received keys track when we got them (not checked for expiration)
    };

    // M11: Save existing state to previousStates before overwriting.
    // This allows decryption of in-flight messages encrypted with the
    // previous key during the rotation window.
    const key = this.stateKey(groupId, senderId, senderDeviceId);
    let prev: SenderKeyState[];
    if (existing !== null) {
      prev = await this.loadPreviousStates(groupId, senderId, senderDeviceId);

      // Add current state to front of previous states (most recent first)
      prev.unshift(existing);

      // Cap at MAX_SENDER_KEY_STATES - 1 (the new state goes to storage)
      while (prev.length >= MAX_SENDER_KEY_STATES) {
        prev.pop();
      }

      this.previousStates.set(key, prev);
    } else {
      prev = [];
      this.previousStates.set(key, prev);
    }

    // Store sender key record (current + previous states) for this member
    await this.persistSenderKeyRecord(groupId, senderId, senderDeviceId, state, prev);

    this.logger.debug('Stored sender key', {
      category: 'E2EE',
      data: { senderKeyId: message.senderKeyId, senderId, senderDeviceId },
    });
  }

  /**
   * Encrypt message for group using sender key
   * Returns ciphertext + signature (O(1) encryption)
   *
   * @param groupId - Group identifier
   * @param userId - Sender user identifier
   * @param deviceId - Sender device identifier
   * @param plaintextBytes - Message bytes to encrypt (Uint8Array)
   * @returns Encrypted message with signature
   */
  async encryptGroupMessage(
    groupId: string,
    userId: string,
    deviceId: number,
    plaintextBytes: Uint8Array
  ): Promise<Uint8Array> {
    // Get sender key state
    const state = await this.storage.getSenderKey(groupId, userId, deviceId);
    if (!state) {
      throw new Error('SENDER_KEY_NOT_FOUND: No sender key for this group');
    }

    // Received keys have no private signature key, so time-based expiration
    // applies only to locally created encryption keys.
    if (state.signatureKey && state.createdAt > 0) {
      const age = Date.now() - state.createdAt;
      if (age > this.maxSenderKeyAge) {
        throw new EncryptionError(
          `Sender key expired after ${Math.floor(age / (24 * 60 * 60 * 1000))} days (max: ${Math.floor(this.maxSenderKeyAge / (24 * 60 * 60 * 1000))} days). Auto-rotation required.`,
          EncryptionErrorCode.SENDER_KEY_EXPIRED,
          { senderKeyId: state.senderKeyId, groupId, ageMs: age, maxAgeMs: this.maxSenderKeyAge }
        );
      }
    }

    // L6: Check for chain index overflow before encrypting
    // Sender keys use uint32 in protobuf, so max is 2^32-1 (0xffffffff).
    // We reject at 0xfffffffe because the next increment would overflow.
    if (state.chainIndex >= 0xfffffffe) {
      throw new EncryptionError(
        'Sender key chain index overflow - key rotation required',
        EncryptionErrorCode.ENCRYPTION_FAILED,
        {
          senderKeyId: state.senderKeyId,
          chainIndex: state.chainIndex,
          reason: 'chain_index_overflow',
        }
      );
    }

    // Derive message key from chain key (Signal Protocol KDF_CK pattern)
    // Two-step derivation:
    // 1. Seed = HMAC-SHA256(Chain Key, 0x01)
    // 2. Derived = HKDF-Expand(Seed, "WhisperGroup", 48 bytes) → IV[0:16] + CipherKey[16:48]
    const { cipherKey, iv } = await this.deriveMessageKey(state.chainKey);

    let ciphertextBase64: string;
    try {
      // Encrypt plaintext bytes with AES-256-CBC using derived IV
      // Authenticity is provided by the Ed25519 signature (no authTag needed)
      ciphertextBase64 = await crypto.aesCbcEncrypt(cipherKey, iv, plaintextBytes);
    } finally {
      crypto.secureZeroBytes(cipherKey);
      crypto.secureZeroBytes(iv);
    }

    // Build SenderKeyMessage protobuf
    const protoBytes = encodeSenderKeyMessage({
      distributionUuid: crypto.stringToBytes(state.senderKeyId),
      chainId: state.chainId,
      iteration: state.chainIndex,
      ciphertext: crypto.base64ToBytes(asBase64(ciphertextBase64)),
    });

    // Sign [version_byte || protobuf_bytes]
    const versionByte = new Uint8Array([
      (SENDERKEY_MESSAGE_CURRENT_VERSION << 4) | SENDERKEY_MESSAGE_CURRENT_VERSION,
    ]);
    const messageToSign = crypto.concatBytes(versionByte, protoBytes);
    const signatureStr = await crypto.sign(state.signatureKey as PrivateKey, messageToSign);
    const signatureBytes = crypto.base64ToBytes(signatureStr as Base64);

    // Advance chain key (ratchet forward)
    const newChainKey = this.advanceChainKey(state.chainKey);
    state.chainKey = newChainKey;
    const currentIndex = state.chainIndex;
    state.chainIndex++;

    // Store updated state
    await this.storage.storeSenderKey(groupId, userId, deviceId, state);

    this.logger.debug('Encrypted message with sender key', {
      category: 'E2EE',
      data: { senderKeyId: state.senderKeyId, chainIndex: currentIndex },
    });

    // Frame: [version_byte(1)] [protobuf(N)] [signature(64)]
    return frameSenderKeyMessage(protoBytes, signatureBytes);
  }

  /**
   * Decrypt group message using sender's key
   *
   * Supports out-of-order message delivery via skipped key storage (Spec Section 4.1).
   *
   * @param groupId - Group identifier
   * @param senderId - Sender user identifier
   * @param senderDeviceId - Sender device identifier
   * @param message - Encrypted message
   * @returns Decrypted plaintext
   */
  async decryptGroupMessage(
    groupId: string,
    senderId: string,
    senderDeviceId: number,
    framedMessage: Uint8Array
  ): Promise<string> {
    // Parse framed SenderKeyMessage: [version_byte(1)] [protobuf(N)] [signature(64)]
    const { protobufBytes, signature } = parseSenderKeyMessage(framedMessage);
    const decoded = decodeSenderKeyMessage(protobufBytes);

    // Convert to internal representation
    const message: EncryptedGroupMessage = {
      senderKeyId: decoded.distributionUuid
        ? new TextDecoder().decode(decoded.distributionUuid)
        : '',
      generation: 0, // Not in SenderKeyMessage wire format (derived from state)
      chainIndex: decoded.iteration,
      ciphertext: crypto.bytesToBase64(decoded.ciphertext),
      signature: crypto.bytesToBase64(signature),
    };

    // Get sender's key
    const state = await this.storage.getSenderKey(groupId, senderId, senderDeviceId);

    if (!state) {
      throw new Error(`SENDER_KEY_NOT_FOUND: No sender key for ${senderId}.${senderDeviceId}`);
    }

    // M11: If current state doesn't match, try previous states (rotation window)
    // This allows decryption of in-flight messages encrypted with a previous key.
    if (state.senderKeyId !== message.senderKeyId) {
      const prevResult = await this.tryDecryptWithPreviousState(
        groupId,
        senderId,
        senderDeviceId,
        message
      );

      if (prevResult !== null) {
        return prevResult;
      }

      throw new Error('SENDER_KEY_MISMATCH: Key rotation needed (use newer sender key)');
    }

    // Verify signature over [version_byte + protobuf_bytes]
    const messageToVerify = this.serializeForSigning(
      message.chainIndex,
      message.ciphertext,
      message.senderKeyId,
      state.chainId
    );

    const isValid = await crypto.verify(
      state.publicSignatureKey as PublicKey,
      messageToVerify,
      message.signature as Signature
    );

    if (!isValid) {
      throw new Error('INVALID_SIGNATURE: Message signature verification failed');
    }

    // Handle out-of-order messages (chain index gaps)
    if (message.chainIndex > state.chainIndex) {
      // DoS protection: Limit chain advancement to prevent CPU exhaustion
      const chainGap = message.chainIndex - state.chainIndex;
      if (chainGap > this.maxChainAdvance) {
        throw new Error(
          `CHAIN_GAP_TOO_LARGE: Message chain index ${message.chainIndex} exceeds ` +
            `current ${state.chainIndex} by ${chainGap} (max: ${this.maxChainAdvance}). ` +
            `Request sender key redistribution.`
        );
      }

      // Advance chain key to match message, storing skipped keys for out-of-order delivery
      // (the reference implementation uses capacity-only limits, no time-based expiration)
      for (let i = state.chainIndex; i < message.chainIndex; i++) {
        // Derive and store the skipped message key
        const { cipherKey, iv } = await this.deriveMessageKey(state.chainKey);

        try {
          await this.storeSkippedKeyWithLimit(groupId, senderId, senderDeviceId, i, {
            cipherKey: crypto.bytesToBase64(cipherKey),
            iv: crypto.bytesToBase64(iv),
          });
        } finally {
          crypto.secureZeroBytes(cipherKey);
          crypto.secureZeroBytes(iv);
        }

        // Advance chain
        state.chainKey = this.advanceChainKey(state.chainKey);
        state.chainIndex++;
      }
    } else if (message.chainIndex < state.chainIndex) {
      // Old message - try skipped keys (Spec Section 4.1)
      return await this.decryptWithSkippedKey(groupId, senderId, senderDeviceId, message);
    }

    // Derive message key from chain key (Signal Protocol KDF_CK pattern)
    // Two-step derivation:
    // 1. Seed = HMAC-SHA256(Chain Key, 0x01)
    // 2. Derived = HKDF-Expand(Seed, "WhisperGroup", 48 bytes) → IV[0:16] + CipherKey[16:48]
    const { cipherKey, iv } = await this.deriveMessageKey(state.chainKey);

    let plaintextBytes: Uint8Array;
    try {
      // Decrypt ciphertext using AES-256-CBC with derived IV
      // Authenticity was already verified by Ed25519 signature above
      plaintextBytes = await crypto.aesCbcDecrypt(cipherKey, iv, asBase64(message.ciphertext));
    } finally {
      crypto.secureZeroBytes(cipherKey);
      crypto.secureZeroBytes(iv);
    }
    const plaintext = this.encodeLosslessPlaintext(plaintextBytes);

    // Advance chain key (ratchet forward)
    state.chainKey = this.advanceChainKey(state.chainKey);
    state.chainIndex++;

    // Store updated state
    await this.storage.storeSenderKey(groupId, senderId, senderDeviceId, state);

    this.logger.debug('Decrypted message with sender key', {
      category: 'E2EE',
      data: { senderId, senderDeviceId, chainIndex: message.chainIndex },
    });

    return plaintext;
  }

  /**
   * Decrypt message using stored skipped key (out-of-order delivery).
   *
   * @param groupId - Group identifier
   * @param senderId - Sender user identifier
   * @param senderDeviceId - Sender device identifier
   * @param message - Encrypted message
   * @returns Decrypted plaintext
   * @throws Error if skipped key not found or decryption fails
   */
  private async decryptWithSkippedKey(
    groupId: string,
    senderId: string,
    senderDeviceId: number,
    message: EncryptedGroupMessage
  ): Promise<string> {
    const skippedKey = await this.storage.getSkippedSenderKey(
      groupId,
      senderId,
      senderDeviceId,
      message.chainIndex
    );

    if (!skippedKey) {
      // If chainIndex < state.chainIndex
      // but no skipped key exists, the message was already consumed (duplicate).
      throw new EncryptionError(
        `Duplicate message at chain index ${message.chainIndex} (already consumed or beyond skipped key window)`,
        EncryptionErrorCode.MESSAGE_DUPLICATE,
        { chainIndex: message.chainIndex, senderKeyId: message.senderKeyId }
      );
    }

    // Decrypt using stored key (AES-256-CBC, authenticity from Ed25519 signature)
    const skippedCipherKey = crypto.base64ToBytes(asBase64(skippedKey.cipherKey));
    const skippedIv = crypto.base64ToBytes(asBase64(skippedKey.iv));

    let plaintextBytes: Uint8Array;
    try {
      plaintextBytes = await crypto.aesCbcDecrypt(
        skippedCipherKey,
        skippedIv,
        asBase64(message.ciphertext)
      );
    } finally {
      crypto.secureZeroBytes(skippedCipherKey);
      crypto.secureZeroBytes(skippedIv);
    }
    const plaintext = this.encodeLosslessPlaintext(plaintextBytes);

    // Delete used skipped key (one-time use)
    await this.storage.deleteSkippedSenderKey(
      groupId,
      senderId,
      senderDeviceId,
      message.chainIndex
    );

    this.logger.debug('Decrypted out-of-order message with skipped key', {
      category: 'E2EE',
      data: { senderId, senderDeviceId, chainIndex: message.chainIndex },
    });

    return plaintext;
  }

  /**
   * Try to decrypt using a previous sender key state (rotation window).
   *
   * When a sender rotates their key, in-flight messages encrypted with the
   * old key may arrive after the receiver has processed the new distribution.
   * This method searches up to MAX_SENDER_KEY_STATES previous states to find
   * a matching one for decryption.
   *
   * - States are searched by senderKeyId match
   * - On successful decryption, the previous state is updated in place
   * - States are capped at MAX_SENDER_KEY_STATES total
   *
   * @param groupId - Group identifier
   * @param senderId - Sender user identifier
   * @param senderDeviceId - Sender device identifier
   * @param message - Encrypted message to try decrypting
   * @returns Decrypted plaintext, or null if no matching state found
   */
  private async tryDecryptWithPreviousState(
    groupId: string,
    senderId: string,
    senderDeviceId: number,
    message: EncryptedGroupMessage
  ): Promise<string | null> {
    // Load previous states from storage (populates cache on miss)
    const prevStates = await this.loadPreviousStates(groupId, senderId, senderDeviceId);

    if (prevStates.length === 0) {
      return null;
    }

    // Search previous states for a matching senderKeyId
    const matchIdx = prevStates.findIndex((s) => s.senderKeyId === message.senderKeyId);

    if (matchIdx === -1) {
      return null;
    }

    const prevState = prevStates[matchIdx];

    // Verify signature with previous state's public key
    const messageToVerify = this.serializeForSigning(
      message.chainIndex,
      message.ciphertext,
      message.senderKeyId,
      prevState.chainId
    );
    const isValid = await crypto.verify(
      prevState.publicSignatureKey as PublicKey,
      messageToVerify,
      message.signature as Signature
    );

    if (!isValid) {
      throw new Error('INVALID_SIGNATURE: Message signature verification failed');
    }

    // Handle chain advancement for out-of-order messages
    if (message.chainIndex > prevState.chainIndex) {
      const chainGap = message.chainIndex - prevState.chainIndex;
      if (chainGap > this.maxChainAdvance) {
        throw new Error(
          `CHAIN_GAP_TOO_LARGE: Message chain index ${message.chainIndex} exceeds ` +
            `current ${prevState.chainIndex} by ${chainGap} (max: ${this.maxChainAdvance}). ` +
            `Request sender key redistribution.`
        );
      }

      // Advance chain to target, storing skipped keys
      for (let i = prevState.chainIndex; i < message.chainIndex; i++) {
        const { cipherKey, iv } = await this.deriveMessageKey(prevState.chainKey);

        try {
          await this.storeSkippedKeyWithLimit(groupId, senderId, senderDeviceId, i, {
            cipherKey: crypto.bytesToBase64(cipherKey),
            iv: crypto.bytesToBase64(iv),
          });
        } finally {
          crypto.secureZeroBytes(cipherKey);
          crypto.secureZeroBytes(iv);
        }
        prevState.chainKey = this.advanceChainKey(prevState.chainKey);
        prevState.chainIndex++;
      }
    } else if (message.chainIndex < prevState.chainIndex) {
      // Old message in previous state - try skipped keys
      return await this.decryptWithSkippedKey(groupId, senderId, senderDeviceId, message);
    }

    // Derive message key and decrypt (AES-256-CBC, authenticity from Ed25519 signature)
    const { cipherKey, iv } = await this.deriveMessageKey(prevState.chainKey);

    let plaintextBytes: Uint8Array;
    try {
      plaintextBytes = await crypto.aesCbcDecrypt(cipherKey, iv, asBase64(message.ciphertext));
    } finally {
      crypto.secureZeroBytes(cipherKey);
      crypto.secureZeroBytes(iv);
    }
    const plaintext = this.encodeLosslessPlaintext(plaintextBytes);

    // Advance chain in previous state
    prevState.chainKey = this.advanceChainKey(prevState.chainKey);
    prevState.chainIndex++;

    // Persist updated previous states to storage
    const currentState = await this.storage.getSenderKey(groupId, senderId, senderDeviceId);
    if (currentState) {
      const key = this.stateKey(groupId, senderId, senderDeviceId);
      const updatedPrev = this.previousStates.get(key) ?? prevStates;
      await this.storage.storeSenderKeyRecord(groupId, senderId, senderDeviceId, [
        currentState,
        ...updatedPrev,
      ]);
    }

    this.logger.debug('Decrypted message with previous sender key state', {
      category: 'E2EE',
      data: {
        senderId,
        senderDeviceId,
        chainIndex: message.chainIndex,
        senderKeyId: prevState.senderKeyId,
        generation: prevState.generation,
      },
    });

    return plaintext;
  }

  /**
   * Store skipped key with enforcement of maxSkippedKeys limit.
   *
   * If the limit is reached, deletes oldest keys to make room.
   * The reference implementation uses capacity-only limits (no time-based expiration).
   */
  private async storeSkippedKeyWithLimit(
    groupId: string,
    senderId: string,
    senderDeviceId: number,
    chainIndex: number,
    messageKey: { cipherKey: string; iv: string }
  ): Promise<void> {
    // Check current count
    const currentCount = await this.storage.countSkippedSenderKeys(
      groupId,
      senderId,
      senderDeviceId
    );

    // If at limit, delete oldest to make room
    if (currentCount >= this.maxSkippedKeys) {
      const toDelete = currentCount - this.maxSkippedKeys + 1;
      await this.storage.deleteOldestSkippedSenderKeys(groupId, senderId, senderDeviceId, toDelete);
    }

    // Store the new skipped key
    await this.storage.storeSkippedSenderKey(
      groupId,
      senderId,
      senderDeviceId,
      chainIndex,
      messageKey
    );
  }

  /**
   * Rotate sender key (forward secrecy on membership changes)
   *
   * @param groupId - Group identifier
   * @param userId - User identifier
   * @param deviceId - Device identifier
   * @returns New sender key ID and distribution message
   */
  async rotateSenderKey(
    groupId: string,
    userId: string,
    deviceId: number
  ): Promise<{
    senderKeyId: string;
    distributionMessage: SenderKeyDistributionMessage;
  }> {
    // Get old sender key state
    const oldState = await this.storage.getSenderKey(groupId, userId, deviceId);

    // Generate new sender key ID
    const senderKeyId = `${groupId}:${userId}:${deviceId}:${Date.now()}`;
    const chainId = this.generateChainId(senderKeyId);

    // Generate new key material
    const chainKey = await crypto.generateRandomBytes(32);
    const signatureKeyPair = await crypto.generateSigningKeyPair();

    // Create new sender key state
    const newState: SenderKeyState = {
      senderKeyId,
      senderKeyVersion: SENDER_KEY_FORMAT,
      chainId,
      generation: oldState ? oldState.generation + 1 : 1,
      chainKey: crypto.bytesToBase64(chainKey),
      signatureKey: signatureKeyPair.privateKey, // Already Base64-encoded PrivateKey
      publicSignatureKey: signatureKeyPair.publicKey, // Already Base64-encoded PublicKey
      chainIndex: 0,
      createdAt: Date.now(),
    };

    // M11: Save old state to previousStates for in-flight message decryption
    const key = this.stateKey(groupId, userId, deviceId);
    let prev: SenderKeyState[];
    if (oldState) {
      prev = await this.loadPreviousStates(groupId, userId, deviceId);
      prev.unshift(oldState);
      while (prev.length >= MAX_SENDER_KEY_STATES) {
        prev.pop();
      }
      this.previousStates.set(key, prev);
    } else {
      prev = [];
      this.previousStates.set(key, prev);
    }

    // Store new sender key record (current + previous states)
    await this.persistSenderKeyRecord(groupId, userId, deviceId, newState, prev);

    // Create distribution message
    const distributionMessage: SenderKeyDistributionMessage = {
      senderKeyId,
      chainId,
      generation: newState.generation,
      chainIndex: 0,
      chainKey: crypto.bytesToBase64(chainKey),
      publicSignatureKey: signatureKeyPair.publicKey, // Already Base64-encoded PublicKey
    };

    this.logger.debug('Rotated sender key', {
      category: 'E2EE',
      data: { senderKeyId, generation: newState.generation },
    });

    return { senderKeyId, distributionMessage };
  }

  /**
   * Delete sender key (when leaving group or revoking device)
   *
   * @param groupId - Group identifier
   * @param userId - User identifier
   * @param deviceId - Device identifier
   */
  async deleteSenderKey(groupId: string, userId: string, deviceId: number): Promise<void> {
    await this.storage.deleteSenderKey(groupId, userId, deviceId);

    // M11: Also clear previous states
    const key = this.stateKey(groupId, userId, deviceId);
    this.previousStates.delete(key);

    this.logger.debug('Deleted sender key', {
      category: 'E2EE',
      data: { userId, deviceId, groupId },
    });
  }

  /**
   * Get statistics for a sender key.
   *
   * Useful for debugging and monitoring group messaging health.
   *
   * @param groupId - Group identifier
   * @param senderId - Sender user identifier
   * @param senderDeviceId - Sender device identifier
   * @returns Stats including chain position, generation, and skipped keys count
   */
  async getStats(
    groupId: string,
    senderId: string,
    senderDeviceId: number
  ): Promise<{
    chainIndex: number;
    generation: number;
    skippedKeysCount: number;
  }> {
    const state = await this.storage.getSenderKey(groupId, senderId, senderDeviceId);

    if (!state) {
      return { chainIndex: 0, generation: 0, skippedKeysCount: 0 };
    }

    const skippedKeysCount = await this.storage.countSkippedSenderKeys(
      groupId,
      senderId,
      senderDeviceId
    );

    return {
      chainIndex: state.chainIndex,
      generation: state.generation,
      skippedKeysCount,
    };
  }

  // ==========================================================================
  // Private Helper Methods
  // ==========================================================================

  /**
   * Derive a message key from the Sender Keys chain key.
   *
   * Two-step derivation:
   * 1. Seed = HMAC-SHA256(Chain Key, 0x01)
   * 2. Derived = HKDF-Expand(Seed, info, 48 bytes)
   *    - IV: bytes 0-15 (16 bytes for AES-CBC)
   *    - Cipher Key: bytes 16-47 (32 bytes)
   *
   * The info parameter (default "WhisperGroup") provides domain separation for
   * sender key operations. Configurable via `senderKeys.hkdfInfoString`.
   *
   */
  private async deriveMessageKey(chainKeyBase64: string): Promise<{
    cipherKey: Uint8Array;
    iv: Uint8Array;
  }> {
    const chainKey = crypto.base64ToBytes(asBase64(chainKeyBase64));

    let seed: Uint8Array | undefined;
    let derived: Uint8Array | undefined;

    try {
      // Step 1: Derive seed using HMAC (Signal Protocol KDF_CK pattern)
      seed = crypto.hmac(chainKey, MESSAGE_KEY_CONSTANT);

      // Step 2: Expand seed using HKDF with configurable info string
      const info = crypto.stringToBytes(this.hkdfInfoString);
      derived = await crypto.hkdfExpand(seed, info, 48);

      // Step 3: Split into IV (16 bytes for AES-CBC) and cipher key (32 bytes)
      return {
        iv: derived.slice(0, 16),
        cipherKey: derived.slice(16, 48),
      };
    } finally {
      crypto.secureZeroBytes(chainKey);
      if (seed) crypto.secureZeroBytes(seed);
      if (derived) crypto.secureZeroBytes(derived);
    }
  }

  /**
   * Advance chain key (ratchet forward) using Signal Protocol KDF_CK pattern.
   *
   * Signal Protocol spec: Next Chain Key = HMAC-SHA256(Chain Key, 0x02)
   *
   * This provides forward secrecy - old chain keys cannot be derived from
   * current chain key, so compromising current state doesn't reveal past
   * messages.
   *
   * @see https://signal.org/docs/specifications/doubleratchet/#external-functions
   */
  private advanceChainKey(chainKeyBase64: string): string {
    const chainKey = crypto.base64ToBytes(asBase64(chainKeyBase64));

    try {
      const result = crypto.hmac(chainKey, CHAIN_KEY_CONSTANT);

      try {
        return crypto.bytesToBase64(result);
      } finally {
        crypto.secureZeroBytes(result);
      }
    } finally {
      crypto.secureZeroBytes(chainKey);
    }
  }

  /**
   * Serialize sender key message for signing (protobuf format).
   *
   * Format: version_byte || protobuf_encode(SenderKeyMessage)
   *
   * The Ed25519 signature covers the version byte and protobuf message bytes.
   *
   * Proto schema (wire.proto):
   *   message SenderKeyMessage {
   *     optional bytes  distribution_uuid = 1;  // our senderKeyId
   *     optional uint32 chain_id          = 2;  // FNV-1a hash of senderKeyId
   *     optional uint32 iteration         = 3;  // our chainIndex
   *     optional bytes  ciphertext        = 4;
   *   }
   *
   * The senderKeyId is encoded as distribution_uuid (field 1) which binds
   * the signature to the distribution, preventing cross-session replay.
   *
   * @param chainIndex - Message number in chain (0-based)
   * @param ciphertext - Base64-encoded ciphertext
   * @param senderKeyId - Optional sender key ID (bound into signature as distribution_uuid)
   * @param chainId - Optional chain identifier (uint32, included in protobuf encoding)
   * @returns Binary data to be signed
   *
   */
  private serializeForSigning(
    chainIndex: number,
    ciphertext: string,
    senderKeyId?: string,
    chainId?: number
  ): Uint8Array {
    // Version byte | 3 = 0x33)
    const versionByte = new Uint8Array([SENDER_KEY_MESSAGE_VERSION]);

    // Canonical signing format: version_byte || protobuf_encode(SenderKeyMessage)
    // This is stable regardless of transport format (JSON or protobuf).
    // Switching transport from JSON to protobuf will NOT require re-signing
    // because the signed bytes are already protobuf.
    const protoBytes = encodeSenderKeyMessage({
      distributionUuid: senderKeyId ? crypto.stringToBytes(senderKeyId) : undefined,
      chainId,
      iteration: chainIndex,
      ciphertext: crypto.base64ToBytes(asBase64(ciphertext)),
    });

    return crypto.concatBytes(versionByte, protoBytes);
  }
}
