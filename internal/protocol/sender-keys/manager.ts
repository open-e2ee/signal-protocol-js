/**
 * Sender Keys protocol implementation for group messaging
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

import { utf8Decode } from '../../platform';
import * as crypto from '../../crypto';
import type {
  SenderKeyReceiveCommit,
  SenderKeyRecordWriteOptions,
  SenderKeyStore,
  SignalProtocolLocalStore,
} from '../../../types/api';
import type { Signature, PublicKey, PrivateKey } from '../../../keys';
import { SENDER_KEY_FORMAT, SENDER_KEY_MESSAGE_VERSION } from '../../../versions';
import { defaultSignalProtocolLogger, type Logger } from '../../../logger';
import { asBase64, type Base64 } from '../../../types/utils';
import {
  type SenderKeysConfig,
  SENDER_KEYS_DEFAULTS,
  SENDER_KEY_AGE_CEILING,
  SENDER_KEY_AGE_FLOOR,
  MAX_SENDER_KEY_STATES,
} from '../../../types/protocol-config';
import { EncryptionError, EncryptionErrorCode } from '../../../types/errors';
import type { ReceiveWorkSeed } from '../../../types/api';
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
  /**
   * Opaque random UUID identifying this sender key.
   *
   * Written to the wire as the SenderKeyMessage `distribution_uuid`, which
   * sits in the *unencrypted* frame. A relay reads it off every group
   * message. It therefore carries no derivable content: no group, no sender,
   * no device, no timestamp. Matching the reference, which likewise uses a
   * random UUID distinct from the group identifier.
   *
   * Randomness also makes rotation unambiguous. Receivers detect a rotation by
   * comparing this value against their stored state. An identifier built from a
   * millisecond clock would collide for two rotations inside the same
   * millisecond, and hide the second one.
   */
  senderKeyId: string;

  /**
   * Sender key wire format version for protocol evolution.
   *
   * Format 'v2': Ed25519 signatures, AES-256-CBC, and HKDF-Extract then Expand
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

  generation: number; // Key generation, incremented on rotation.
  chainKey: string; // Current chain key, base64 encoded, ratcheted forward per message.
  signatureKey: string; // Ed25519 private key for signing, base64 encoded.
  publicSignatureKey: string; // Ed25519 public key for verification, base64 encoded.
  chainIndex: number; // Current message number in the chain.

  /**
   * Creation timestamp (ms since epoch) for time-based rotation.
   *
   * The manager checks only locally created encryption keys for expiry. Received
   * decryption keys remain usable for delayed messages.
   */
  createdAt: number;
}

/** Why a locally created sender key is past the age bound. */
type OwnSenderKeyExpiry = { kind: 'no-creation-time' } | { kind: 'aged'; ageMs: number };

export interface SenderKeyDistributionMessage {
  senderKeyVersion: string;
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
 * From Double Ratchet spec Section 7.2:
 *
 * > "HMAC with SHA-256 or SHA-512 is recommended, using ck as the HMAC key
 * > and using separate constants as input (e.g. a single byte 0x01 as input
 * > to produce the message key, and a single byte 0x02 as input to produce
 * > the next chain key)."
 *
 * @see https://signal.org/docs/specifications/doubleratchet/#external-functions
 */
const MESSAGE_KEY_CONSTANT = new Uint8Array([0x01]);
const CHAIN_KEY_CONSTANT = new Uint8Array([0x02]);

// ============================================================================
// Sender Key Manager
// ============================================================================

/**
 * Resolve the configured sender key age against the default and the bounds.
 *
 * A host-supplied age can be wrong in three ways, and they warrant different
 * treatment.
 *
 * An age above {@link SENDER_KEY_AGE_CEILING}, or below
 * {@link SENDER_KEY_AGE_FLOOR}, is a coherent policy that reaches past what
 * the implementation can honor. It is either too long to bound a key's life,
 * or too short for the rotate-and-redistribute path to beat. The bound it
 * passed is used, and the direction of its intent is kept.
 *
 * A value that is not a positive finite number is not a policy at all. Unlike
 * an out-of-range one, it does not say which way the host wanted to move. A
 * zero in particular is far more often an absent or uninitialized field than a
 * request to rotate constantly. Reading it as the latter would impose the
 * tightest rotation the SDK allows on a host that asked for nothing. So it
 * falls back to the default. A host that genuinely wants maximal rotation can
 * say so with any positive value and get the floor.
 *
 * All three are logged: a silent clamp would leave a host believing a rotation
 * interval it is not getting.
 */
function resolveMaxSenderKeyAge(configured: number | undefined, logger: Required<Logger>): number {
  if (configured === undefined) return SENDER_KEYS_DEFAULTS.maxSenderKeyAge;

  if (!Number.isFinite(configured) || configured <= 0) {
    logger.warn('Ignoring invalid maxSenderKeyAge; using the default', {
      category: 'E2EE',
      data: { configured, using: SENDER_KEYS_DEFAULTS.maxSenderKeyAge },
    });
    return SENDER_KEYS_DEFAULTS.maxSenderKeyAge;
  }

  if (configured > SENDER_KEY_AGE_CEILING) {
    logger.warn('Clamping maxSenderKeyAge to the ceiling', {
      category: 'E2EE',
      data: { configured, ceiling: SENDER_KEY_AGE_CEILING },
    });
    return SENDER_KEY_AGE_CEILING;
  }

  if (configured < SENDER_KEY_AGE_FLOOR) {
    logger.warn('Raising maxSenderKeyAge to the floor', {
      category: 'E2EE',
      data: { configured, floor: SENDER_KEY_AGE_FLOOR },
    });
    return SENDER_KEY_AGE_FLOOR;
  }

  return configured;
}

/**
 * Classify a sender key against the age bound. Only a locally created key
 * expires: a received key has no private signature key, and it stays usable
 * for delayed messages.
 *
 * A locally created key always records when it was created, at creation and
 * again at every rotation. One that does not is damaged or predates the
 * field, so its age cannot be established. Establishing the age is the single
 * thing this bound exists for. Skipping the check would exempt the only keys
 * whose life is genuinely unbounded. Such a key counts as expired instead.
 * The caller answers that by rotating, which costs a redistribution and
 * restores a key whose age is known.
 *
 * @returns Null when the key is within the bound.
 */
function ownSenderKeyExpiry(
  state: SenderKeyState,
  maxSenderKeyAge: number
): OwnSenderKeyExpiry | null {
  if (!state.signatureKey) return null;
  if (!Number.isFinite(state.createdAt) || state.createdAt <= 0) {
    return { kind: 'no-creation-time' };
  }
  const ageMs = Date.now() - state.createdAt;
  return ageMs > maxSenderKeyAge ? { kind: 'aged', ageMs } : null;
}

/** Reject sender-key state or a distribution in an unsupported format. */
export function assertSenderKeyVersion(state: { senderKeyVersion: string }): void {
  if (state.senderKeyVersion !== SENDER_KEY_FORMAT) {
    throw new Error(
      'Unsupported sender-key format. Reset group sender-key state and redistribute keys.'
    );
  }
}

/**
 * A sender key state with only the fields of `SenderKeyState`. A state that
 * an earlier SDK version wrote can carry a retired field. The manager keeps
 * only the current fields of each state that it loads, so no code path reads
 * a retired field and the next write of the state omits it. The mapped type
 * makes the compiler require each field of `SenderKeyState` here.
 */
function withoutRetiredFields(state: SenderKeyState): SenderKeyState {
  const current: { [K in keyof Required<SenderKeyState>]: SenderKeyState[K] } = {
    senderKeyId: state.senderKeyId,
    senderKeyVersion: state.senderKeyVersion,
    chainId: state.chainId,
    generation: state.generation,
    chainKey: state.chainKey,
    signatureKey: state.signatureKey,
    publicSignatureKey: state.publicSignatureKey,
    chainIndex: state.chainIndex,
    createdAt: state.createdAt,
  };
  return current;
}

/** The distribution of a sender key state at its current chain index. */
function currentDistribution(state: SenderKeyState): SenderKeyDistributionMessage {
  assertSenderKeyVersion(state);
  return {
    senderKeyVersion: SENDER_KEY_FORMAT,
    senderKeyId: state.senderKeyId,
    chainId: state.chainId,
    generation: state.generation,
    chainIndex: state.chainIndex,
    chainKey: state.chainKey,
    publicSignatureKey: state.publicSignatureKey,
  };
}

/**
 * Resolve the group a framed SenderKeyMessage belongs to.
 *
 * A group envelope names no group. It carries the sender's identity and an
 * opaque distribution identifier inside the frame. The receiver maps that
 * identifier back to a group through its own sender key store. The store is
 * the only thing that knows the association, which is why the relay cannot
 * learn it.
 *
 * Parsing here reads unauthenticated bytes: the signature is not checked
 * until `decryptGroupMessage`. That is safe because the only thing taken
 * from them is an identifier used as a lookup key. A forged identifier
 * either matches no record, or matches one. Matching one is not an
 * escalation. The caller's own state already binds that identifier to a
 * public signature key, and the subsequent verification rejects the forgery
 * against it.
 *
 * @param store - The sender key store of the receiving device
 * @param framedMessage - Framed SenderKeyMessage bytes from the envelope
 * @param senderId - Sender user identifier, from the envelope
 * @param senderDeviceId - Sender device identifier, from the envelope
 * @returns The group identifier, or null if no sender key matches
 */
export async function resolveGroupForFramedMessage(
  store: Pick<SenderKeyStore, 'resolveGroupForSenderKeyId'>,
  framedMessage: Uint8Array,
  senderId: string,
  senderDeviceId: number
): Promise<string | null> {
  let senderKeyId: string;
  try {
    const { protobufBytes } = parseSenderKeyMessage(framedMessage);
    const decoded = decodeSenderKeyMessage(protobufBytes);
    if (!decoded.distributionUuid) return null;
    senderKeyId = utf8Decode(decoded.distributionUuid);
  } catch {
    // Not a well-formed frame, so it names no distribution and no group.
    return null;
  }

  if (!senderKeyId) return null;

  return store.resolveGroupForSenderKeyId(senderKeyId, senderId, senderDeviceId);
}

export class SenderKeyManager {
  /** Resolved configuration values */
  private readonly hkdfInfoString: string;
  private readonly maxChainAdvance: number;
  private readonly maxSkippedKeys: number;
  private readonly maxSenderKeyAge: number;

  private readonly logger: Required<Logger>;

  constructor(
    private storage: SignalProtocolLocalStore,
    config?: SenderKeysConfig,
    logger: Required<Logger> = defaultSignalProtocolLogger
  ) {
    this.logger = logger;
    // Resolve config with defaults
    this.hkdfInfoString = config?.hkdfInfoString ?? SENDER_KEYS_DEFAULTS.hkdfInfoString;
    this.maxChainAdvance = config?.maxChainAdvance ?? SENDER_KEYS_DEFAULTS.maxChainAdvance;
    this.maxSkippedKeys = config?.maxSkippedKeys ?? SENDER_KEYS_DEFAULTS.maxSkippedKeys;
    this.maxSenderKeyAge = resolveMaxSenderKeyAge(config?.maxSenderKeyAge, this.logger);
  }

  /**
   * Convert decrypted bytes into a lossless string representation.
   *
   * Plain UTF-8 text and JSON round-trip unchanged. Binary protobuf payloads do
   * not, so we return base64 for those and let the content layer deserialize it.
   */
  private encodeLosslessPlaintext(plaintextBytes: Uint8Array): string {
    const text = utf8Decode(plaintextBytes);
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
    return hash >>> 0; // Force unsigned 32-bit
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
    previousStatesList: SenderKeyState[],
    options?: SenderKeyRecordWriteOptions
  ): Promise<void> {
    const allStates = [currentState, ...previousStatesList];
    await this.storage.storeSenderKeyRecord(
      groupId,
      userId,
      deviceId,
      allStates,
      undefined,
      options
    );
  }

  /**
   * Load the previous states of a sender from the stored record, most recent
   * first. The manager keeps no copy: each call reads the store, so a
   * rotation or a receive that another tab or manager wrote is kept.
   */
  private async loadPreviousStates(
    groupId: string,
    userId: string,
    deviceId: number
  ): Promise<SenderKeyState[]> {
    const record = await this.loadSenderKeyRecord(groupId, userId, deviceId);
    if (record && record.length > 1) {
      // First element is current state (already in storage via getSenderKey),
      // remaining elements are previous states.
      // Cap at MAX_SENDER_KEY_STATES - 1 defensively (storage may have stale extras).
      return record.slice(1, MAX_SENDER_KEY_STATES);
    }
    return [];
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
    const senderKeyId = await crypto.generateUuidV4();
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

    // Store sender key (with empty previous states for a new key). The new
    // senderKeyId replaces the old key, so the same write deletes the
    // handoff rows of the group.
    await this.persistSenderKeyRecord(groupId, userId, deviceId, state, [], {
      deleteSenderKeyHandoffs: true,
    });

    // Create distribution message (to send to other members)
    const distributionMessage: SenderKeyDistributionMessage = {
      senderKeyVersion: SENDER_KEY_FORMAT,
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
   * The receiver matches a key by its identity, the senderKeyId, as
   * Signal's published implementation matches a state by its chain ID and
   * signing key. A sender that creates a key again starts at generation 1
   * with a new senderKeyId, so the generation does not order two different
   * keys.
   * - The same key as the current state: the generation rules of spec
   *   Section 3.4 apply. A lower generation changes nothing. The same
   *   generation changes nothing at any chainIndex, because the existing
   *   state can be ahead through decryption. A higher generation replaces
   *   the current state in place, and the previous states do not change.
   * - The key of a previous state: a late copy changes nothing, and the
   *   state stays in its place.
   * - Another key: it becomes the current state, and the existing state
   *   moves to the front of the previous states, so a message in flight
   *   under it still decrypts. When the record already holds
   *   MAX_SENDER_KEY_STATES states, the oldest state goes.
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
    assertSenderKeyVersion(message);
    // Validate against existing state (Specification Section 3.4)
    const existing = await this.loadSenderKey(groupId, senderId, senderDeviceId);
    const sameKey = existing !== null && existing.senderKeyId === message.senderKeyId;
    const previous =
      existing !== null ? await this.loadPreviousStates(groupId, senderId, senderDeviceId) : [];

    if (existing !== null && !sameKey) {
      assertSenderKeyVersion(existing);
      if (previous.some((state) => state.senderKeyId === message.senderKeyId)) {
        this.logger.debug('Rejected late distribution of a previous sender key', {
          category: 'E2EE',
          data: { senderKeyId: message.senderKeyId },
        });
        return;
      }
    } else if (existing !== null) {
      assertSenderKeyVersion(existing);
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
        // This is a re-broadcast. Keep existing chain progress if it is more advanced,
        // The existing state may have advanced beyond the distribution's chainIndex
        // via message decryption, so do not overwrite.
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
      signatureKey: '', // Do not store sender's private key
      publicSignatureKey: message.publicSignatureKey,
      chainIndex: message.chainIndex ?? 0,
      createdAt: Date.now(), // Received keys track when we got them (not checked for expiration)
    };

    // Build the archive from the stored record. A later generation of the
    // same key replaces the current state in place, so the record never
    // holds two states with one senderKeyId.
    const prev =
      existing === null
        ? []
        : sameKey
          ? previous
          : [existing, ...previous].slice(0, MAX_SENDER_KEY_STATES - 1);

    await this.persistSenderKeyRecord(groupId, senderId, senderDeviceId, state, prev);

    this.logger.debug('Stored sender key', {
      category: 'E2EE',
      data: { senderKeyId: message.senderKeyId, senderId, senderDeviceId },
    });
  }

  /**
   * Report whether the local sender key of a group is past the age bound,
   * by the same rule that makes {@link encryptGroupMessage} refuse it with
   * `SENDER_KEY_EXPIRED`. A send reads it before it distributes a pending
   * key, so it rotates instead of distributing a key that it cannot use.
   *
   * @returns False when there is no sender key for the group.
   */
  async isOwnSenderKeyExpired(groupId: string, userId: string, deviceId: number): Promise<boolean> {
    const state = await this.loadSenderKey(groupId, userId, deviceId);
    return state !== null && ownSenderKeyExpiry(state, this.maxSenderKeyAge) !== null;
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
    const state = await this.loadSenderKey(groupId, userId, deviceId);
    if (!state) {
      throw new Error('SENDER_KEY_NOT_FOUND: No sender key for this group');
    }

    assertSenderKeyVersion(state);

    const expiry = ownSenderKeyExpiry(state, this.maxSenderKeyAge);
    if (expiry?.kind === 'no-creation-time') {
      throw new EncryptionError(
        'Sender key has no usable creation time, so its age cannot be checked. Auto-rotation required.',
        EncryptionErrorCode.SENDER_KEY_EXPIRED,
        {
          senderKeyId: state.senderKeyId,
          groupId,
          createdAt: state.createdAt,
          maxAgeMs: this.maxSenderKeyAge,
        }
      );
    }
    if (expiry?.kind === 'aged') {
      throw new EncryptionError(
        `Sender key expired after ${Math.floor(expiry.ageMs / (24 * 60 * 60 * 1000))} days (max: ${Math.floor(this.maxSenderKeyAge / (24 * 60 * 60 * 1000))} days). Auto-rotation required.`,
        EncryptionErrorCode.SENDER_KEY_EXPIRED,
        {
          senderKeyId: state.senderKeyId,
          groupId,
          ageMs: expiry.ageMs,
          maxAgeMs: this.maxSenderKeyAge,
        }
      );
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
    // 2. Derived = HKDF(Seed, zero salt, "WhisperGroup", 48 bytes) → IV[0:16] + CipherKey[16:48]
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
  /**
   * Resolve the group a framed SenderKeyMessage belongs to, from the store
   * of this manager, as `resolveGroupForFramedMessage` tells.
   *
   * @param framedMessage - Framed SenderKeyMessage bytes from the envelope
   * @param senderId - Sender user identifier, from the envelope
   * @param senderDeviceId - Sender device identifier, from the envelope
   * @returns The group identifier, or null if no sender key matches
   */
  async resolveGroupForFramedMessage(
    framedMessage: Uint8Array,
    senderId: string,
    senderDeviceId: number
  ): Promise<string | null> {
    return resolveGroupForFramedMessage(this.storage, framedMessage, senderId, senderDeviceId);
  }

  async decryptGroupMessage(
    groupId: string,
    senderId: string,
    senderDeviceId: number,
    framedMessage: Uint8Array,
    receiveWork?: ReceiveWorkSeed
  ): Promise<string> {
    // Parse framed SenderKeyMessage: [version_byte(1)] [protobuf(N)] [signature(64)]
    const { protobufBytes, signature } = parseSenderKeyMessage(framedMessage);
    const decoded = decodeSenderKeyMessage(protobufBytes);

    // Convert to internal representation
    const message: EncryptedGroupMessage = {
      senderKeyId: decoded.distributionUuid
        ? utf8Decode(decoded.distributionUuid)
        : '',
      generation: 0, // Not in SenderKeyMessage wire format (derived from state)
      chainIndex: decoded.iteration,
      ciphertext: crypto.bytesToBase64(decoded.ciphertext),
      signature: crypto.bytesToBase64(signature),
    };

    // Get sender's key
    const state = await this.loadSenderKey(groupId, senderId, senderDeviceId);

    if (!state) {
      throw new Error(`SENDER_KEY_NOT_FOUND: No sender key for ${senderId}.${senderDeviceId}`);
    }

    assertSenderKeyVersion(state);

    // M11: If current state does not match, try previous states (rotation window)
    // This allows decryption of in-flight messages encrypted with a previous key.
    if (state.senderKeyId !== message.senderKeyId) {
      const prevResult = await this.tryDecryptWithPreviousState(
        groupId,
        senderId,
        senderDeviceId,
        message,
        receiveWork
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

    const skippedKeys: NonNullable<SenderKeyReceiveCommit['skippedKeys']> = {
      maxSkippedKeys: this.maxSkippedKeys,
      keys: [],
    };

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

      // Stage skipped keys until successful decryption and the receive commit
      // (the reference implementation uses capacity-only limits, no time-based expiration)
      for (let i = state.chainIndex; i < message.chainIndex; i++) {
        // Derive the skipped message key
        const { cipherKey, iv } = await this.deriveMessageKey(state.chainKey);

        try {
          skippedKeys.keys.push({
            senderKeyId: state.senderKeyId,
            chainIndex: i,
            messageKey: {
              cipherKey: crypto.bytesToBase64(cipherKey),
              iv: crypto.bytesToBase64(iv),
            },
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
      return await this.decryptWithSkippedKey(
        groupId,
        senderId,
        senderDeviceId,
        message,
        receiveWork
      );
    }

    // Derive message key from chain key (Signal Protocol KDF_CK pattern)
    // Two-step derivation:
    // 1. Seed = HMAC-SHA256(Chain Key, 0x01)
    // 2. Derived = HKDF(Seed, zero salt, "WhisperGroup", 48 bytes) → IV[0:16] + CipherKey[16:48]
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
    const previous = await this.loadPreviousStates(groupId, senderId, senderDeviceId);
    await this.storage.storeSenderKeyRecord(
      groupId,
      senderId,
      senderDeviceId,
      [state, ...previous],
      {
        skippedKeys,
        work: receiveWork?.({ plaintext, groupId }),
      }
    );

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
    message: EncryptedGroupMessage,
    receiveWork?: ReceiveWorkSeed
  ): Promise<string> {
    const skippedKey = await this.storage.getSkippedSenderKey(
      groupId,
      senderId,
      senderDeviceId,
      message.senderKeyId,
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

    const states = await this.loadSenderKeyRecord(groupId, senderId, senderDeviceId);
    if (!states?.length) throw new Error('Missing sender-key record during receive');
    await this.storage.storeSenderKeyRecord(groupId, senderId, senderDeviceId, states, {
      work: receiveWork?.({ plaintext, groupId }),
      consumedSkippedKey: {
        senderKeyId: message.senderKeyId,
        chainIndex: message.chainIndex,
      },
    });

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
    message: EncryptedGroupMessage,
    receiveWork?: ReceiveWorkSeed
  ): Promise<string | null> {
    // Load previous states from the stored record
    const prevStates = (await this.loadPreviousStates(groupId, senderId, senderDeviceId)).map(
      (state) => ({ ...state })
    );

    if (prevStates.length === 0) {
      return null;
    }

    // Search previous states for a matching senderKeyId
    const matchIdx = prevStates.findIndex((s) => s.senderKeyId === message.senderKeyId);

    if (matchIdx === -1) {
      return null;
    }

    const prevState = prevStates[matchIdx];
    assertSenderKeyVersion(prevState);

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

    const skippedKeys: NonNullable<SenderKeyReceiveCommit['skippedKeys']> = {
      maxSkippedKeys: this.maxSkippedKeys,
      keys: [],
    };

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

      // Stage skipped keys until successful decryption and the receive commit
      for (let i = prevState.chainIndex; i < message.chainIndex; i++) {
        const { cipherKey, iv } = await this.deriveMessageKey(prevState.chainKey);

        try {
          skippedKeys.keys.push({
            senderKeyId: prevState.senderKeyId,
            chainIndex: i,
            messageKey: {
              cipherKey: crypto.bytesToBase64(cipherKey),
              iv: crypto.bytesToBase64(iv),
            },
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
      return await this.decryptWithSkippedKey(
        groupId,
        senderId,
        senderDeviceId,
        message,
        receiveWork
      );
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
    const currentState = await this.loadSenderKey(groupId, senderId, senderDeviceId);
    if (!currentState) throw new Error('Missing sender-key record during receive');
    await this.storage.storeSenderKeyRecord(
      groupId,
      senderId,
      senderDeviceId,
      [currentState, ...prevStates],
      {
        skippedKeys,
        work: receiveWork?.({ plaintext, groupId }),
      }
    );

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
    const oldState = await this.loadSenderKey(groupId, userId, deviceId);
    if (oldState) assertSenderKeyVersion(oldState);

    const senderKeyId = await crypto.generateUuidV4();
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

    // Build the archive from the stored record.
    const prev = oldState
      ? [oldState, ...(await this.loadPreviousStates(groupId, userId, deviceId))].slice(
          0,
          MAX_SENDER_KEY_STATES - 1
        )
      : [];

    // The same write deletes the handoff rows of the group, so the next send
    // gives the new key to every listed device.
    await this.persistSenderKeyRecord(groupId, userId, deviceId, newState, prev, {
      deleteSenderKeyHandoffs: true,
    });

    // Create distribution message
    const distributionMessage: SenderKeyDistributionMessage = {
      senderKeyVersion: SENDER_KEY_FORMAT,
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
   * The distribution of the current sender key at its current chain index,
   * or null when the device has no sender key for the group. A receiver that
   * installs it decrypts the later group messages of the sender, but no
   * earlier one.
   */
  async getCurrentSenderKeyDistribution(
    groupId: string,
    userId: string,
    deviceId: number
  ): Promise<SenderKeyDistributionMessage | null> {
    const state = await this.loadSenderKey(groupId, userId, deviceId);
    return state ? currentDistribution(state) : null;
  }

  /**
   * Delete sender key (when leaving group or revoking device)
   *
   * The delete of an own sender key, which holds a private signature key,
   * also deletes the handoff rows of the group in the same write. The delete
   * of a received key keeps them.
   *
   * @param groupId - Group identifier
   * @param userId - User identifier
   * @param deviceId - Device identifier
   */
  async deleteSenderKey(groupId: string, userId: string, deviceId: number): Promise<void> {
    const state = await this.loadSenderKey(groupId, userId, deviceId);
    await this.storage.deleteSenderKey(
      groupId,
      userId,
      deviceId,
      state?.signatureKey ? { deleteSenderKeyHandoffs: true } : undefined
    );

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
    const state = await this.loadSenderKey(groupId, senderId, senderDeviceId);

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

  /** Load the current sender key state, with no retired fields. */
  private async loadSenderKey(
    groupId: string,
    userId: string,
    deviceId: number
  ): Promise<SenderKeyState | null> {
    const state = await this.storage.getSenderKey(groupId, userId, deviceId);
    return state ? withoutRetiredFields(state) : null;
  }

  /** Load every stored sender key state, with no retired fields. */
  private async loadSenderKeyRecord(
    groupId: string,
    userId: string,
    deviceId: number
  ): Promise<SenderKeyState[] | null> {
    const record = await this.storage.getSenderKeyRecord(groupId, userId, deviceId);
    return record ? record.map(withoutRetiredFields) : null;
  }

  /**
   * Derive a message key from the Sender Keys chain key.
   *
   * Two-step derivation:
   * 1. Seed = HMAC-SHA256(Chain Key, 0x01)
   * 2. Derived = HKDF(Seed, zero salt, info, 48 bytes)
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

      // Step 2: Extract and expand the seed with the configured info string
      const info = crypto.stringToBytes(this.hkdfInfoString);
      derived = await crypto.hkdf(seed, new Uint8Array(32), info, 48);

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
   * current chain key, so compromising current state does not reveal past
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
   * ```proto
   *   message SenderKeyMessage {
   *     optional bytes  distribution_uuid = 1;  // our senderKeyId
   *     optional uint32 chain_id          = 2;  // FNV-1a hash of senderKeyId
   *     optional uint32 iteration         = 3;  // our chainIndex
   *     optional bytes  ciphertext        = 4;
   *   }
   * ```
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
    // Current sender-key profile version
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
