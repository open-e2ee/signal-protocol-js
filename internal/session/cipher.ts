/**
 * Session Cipher - Signal Protocol Encrypt/Decrypt Operations
 *
 * @module session/cipher
 *
 * Implements Signal Protocol Double Ratchet encryption and decryption while
 * keeping message processing separate from session establishment.
 *
 * ## Overview
 *
 * SessionCipher handles the core encrypt/decrypt operations for an established
 * Signal Protocol session. It implements:
 *
 * - **RatchetEncrypt** (Section 3.4): Encrypt messages with Double Ratchet
 * - **RatchetDecrypt** (Section 3.5): Decrypt messages with Double Ratchet
 * - **Plaintext Headers + MAC** (Section 3): Identity-bound MAC authentication
 * - **Out-of-Order Handling**: Store/retrieve skipped message keys (receiverChains)
 * - **Triple Ratchet Integration**: Combined EC + PQ key derivation when SPQR enabled
 *
 * ## Message Flow
 *
 * ### Encryption (RatchetEncrypt)
 * ```
 * 1. Derive message key from sending chain (CKs)
 * 2. Expand key to 80 bytes: 32 enc + 32 auth + 16 IV
 * 3. Encrypt plaintext with AES-CBC
 * 4. Compute identity-bound MAC: HMAC(auth_key, version || sender_id || receiver_id || header || ciphertext)
 * 5. Advance sending chain: CKs, Ns++
 * 6. First message? → Send as PreKeyMessage with X3DH info
 * ```
 *
 * ### Decryption (RatchetDecrypt)
 * ```
 * 1. Try skipped message keys (receiverChains) first
 * 2. Check if DH public key changed → DH ratchet needed
 * 3. Parse plaintext header (ratchetKey, counter, previousCounter)
 * 4. Perform DH ratchet step if needed
 * 5. Skip/store any missed message keys
 * 6. Derive message key from receiving chain (CKr)
 * 7. Verify identity-bound MAC, then decrypt
 * 8. Advance receiving chain: CKr, Nr++
 * ```
 *
 * ## Security Properties
 *
 * - **Forward Secrecy**: Message keys are derived then deleted
 * - **Break-in Recovery**: DH ratchet restores security after compromise
 * - **Session Binding**: Identity keys in MAC prevent cross-session attacks
 * - **Replay Protection**: Message numbers prevent replay attacks
 * - **Out-of-Order Support**: receiverChains allows delayed message delivery
 *
 * ## Concurrency Safety
 *
 * All operations are protected by per-session AsyncLock to prevent race
 * conditions when multiple encrypt/decrypt operations occur simultaneously.
 *
 * ## Specification References
 *
 * @see https://signal.org/docs/specifications/doubleratchet/#encrypting-messages - Section 3.4
 * @see https://signal.org/docs/specifications/doubleratchet/#decrypting-messages - Section 3.5
 * @see https://signal.org/docs/specifications/doubleratchet/#handling-missing-messages - Skipped keys
 *
 * @internal This module is INTERNAL. Use SignalProtocolClient for public encryption API.
 *
 * @example Basic usage (internal)
 * ```typescript
 * import { SessionCipher } from './';
 *
 * const cipher = new SessionCipher(storage, establishCallback, lock, { maxSkip: 1000 });
 *
 * // Encrypt message
 * const ciphertext = await cipher.encrypt('session-123', 'Hello, world!');
 *
 * // Decrypt message
 * const plaintext = await cipher.decrypt('session-123', ciphertext);
 * ```
 */

import AsyncLock from 'async-lock';
import { defaultSignalProtocolLogger, type ILogger } from '../../logger';
import { MAX_UNACKNOWLEDGED_SESSION_AGE_MS } from '../../types/protocol-config';
import type { Ciphertext, IdentityType, PublicKey } from '../../keys';
import {
  compositeIdentitiesEqual,
  decodeCompositeIdentityV1,
  encodeCompositeIdentityV1,
} from '../../keys/identity';
import type {
  ISignalProtocolLocalStore,
  PreKeyMessage,
  RatchetMessage,
  SessionState,
  SessionRecord,
  Base64,
} from '../../types';
import {
  CURRENT_SESSION_RECORD_VERSION,
  SessionRecord as SessionRecordNS,
} from '../../types/session';
import {
  EncryptionError,
  EncryptionErrorCode,
  MessageType,
  DuplicatedMessageError,
  UntrustedIdentityError,
  TrustDirection,
} from '../../types';
import { ProtocolAddress } from '../../types/address';
import { MESSAGE_FORMAT } from '../../versions';
import * as CryptoUtils from '../crypto';
import {
  deriveSendingKey as moduleDeriveKey,
  deriveReceivingKey as moduleReceiveKey,
  storeMessageKeyInChain,
  DEFAULT_RATCHET_CONFIG,
} from '../protocol/double-ratchet';
import { asBase64 } from '../../types/utils';
// Black-box SPQR API
// DH ratchet is purely classical; ALL PQ work happens inside spqrSend/spqrRecv
import { spqrSend, spqrRecv } from '../protocol/spqr';
import type { SessionEstablishmentCallback, SessionCipherConfig } from './types';
import {
  assertValidatedSession,
  performDHRatchetStep,
  storeSkippedMessageKeys,
  cleanupExpiredMessageKeys,
} from './ratchet';
import {
  trySkippedMessageKeys,
  decryptWithKey,
  performReplayRejectionWork,
  createProtobufMacContext,
  type ProtobufMacContext,
} from './decryption';
import {
  validateSessionKeyOwnership,
  validateSessionStateIntegrity,
  getMaxSkipForSession,
} from './validation';
import { SessionResolver } from './session-resolver';
import type { DoubleRatchetState } from '../protocol/double-ratchet';
import {
  encodeSignalProtocolMessage,
  decodeSignalProtocolMessage,
  encodePreKeySignalProtocolMessage,
  decodePreKeySignalProtocolMessage,
  frameSignalProtocolMessage,
  parseSignalProtocolMessageEnvelope,
  framePreKeySignalProtocolMessage,
  parsePreKeySignalProtocolMessageEnvelope,
  makeVersionByte,
  serializeSignalProtocolMessageAddresses,
} from '../encoding/proto';
import { computeCompositeIdentityMessageMac } from './identity-binding';

function identityTypeToWire(identityType: IdentityType): 1 | 2 {
  return identityType === 'aci' ? 1 : 2;
}

function identityTypeFromWire(value: number): IdentityType {
  if (value === 1) return 'aci';
  if (value === 2) return 'pni';
  throw new Error('Recipient identity type must be ACI=1 or PNI=2');
}

/**
 * Clone session state for a single decrypt attempt.
 *
 * Decryption operates on a clone and persists it only after authentication and
 * plaintext recovery succeed.
 */
function cloneSessionStateForDecryptAttempt(session: SessionState): SessionState {
  return CryptoUtils.cloneProtocolState(session);
}

interface MatchingPreKeySession {
  session: SessionState;
  archivedBaseKey: Base64 | null;
}

/**
 * If a retried PreKeyMessage references an existing base key, decrypt with the
 * matching session. Re-running X3DH/PQXDH could require one-time prekeys that
 * the first attempt already consumed.
 */
function findMatchingPreKeySession(
  record: SessionRecord | null,
  prekeyMessage: PreKeyMessage
): MatchingPreKeySession | null {
  if (!record) {
    return null;
  }

  const baseKey = prekeyMessage.senderEphemeralKey as Base64;
  const matchingSession = SessionRecordNS.findSession(record, baseKey);
  if (
    !matchingSession ||
    !compositeIdentitiesEqual(matchingSession.remoteIdentity, prekeyMessage.senderIdentity)
  ) {
    return null;
  }

  return {
    session: matchingSession,
    archivedBaseKey: record.currentSession?.baseKey === baseKey ? null : baseKey,
  };
}

/**
 * SessionCipher handles encrypt/decrypt operations for a Signal Protocol session
 *
 * Unlike SessionBuilder which handles session establishment, SessionCipher
 * handles the ongoing message encryption/decryption using the Double Ratchet
 * algorithm. It is the core encryption engine for Signal Protocol messaging.
 *
 * ## Responsibilities
 *
 * - **Encryption**: Derive message keys, encrypt with AES-CBC, compute identity-bound MAC
 * - **Decryption**: Verify MAC, decrypt, handle out-of-order messages
 * - **Session Binding**: Include identity keys in MAC for cross-session attack prevention
 * - **PreKey Messages**: Create/process first messages with X3DH key agreement
 * - **Triple Ratchet**: Integrate SPQR for post-quantum forward secrecy
 *
 * ## Thread Safety
 *
 * All operations are protected by per-session locks. Multiple sessions can
 * operate concurrently, but operations on the same session are serialized.
 *
 * ## Security Considerations
 *
 * - Owned message-key byte arrays are best-effort overwritten after use
 * - MAX_SKIP limits prevent DoS from excessive key derivation
 * - Expired skipped keys are cleaned up to bound memory usage
 *
 * @example Basic encrypt/decrypt
 * ```typescript
 * const cipher = new SessionCipher(keyStorage, establishSession, lock);
 *
 * // Encrypt - returns JSON-serialized Ciphertext
 * const ciphertext = await cipher.encrypt(sessionId, 'Hello!');
 *
 * // Decrypt - handles PreKeyMessage or RatchetMessage automatically
 * const plaintext = await cipher.decrypt(sessionId, ciphertext);
 * ```
 *
 * @example With configuration
 * ```typescript
 * const cipher = new SessionCipher(keyStorage, establishSession, lock, {
 *   maxSkip: 500,  // Limit skipped message keys (default: 1000)
 * });
 * ```
 *
 * @see https://signal.org/docs/specifications/doubleratchet/
 */
export {};
export class SessionCipher {
  /**
   * Maximum number of message keys to skip in a single receiving chain.
   * The 25,000-key limit bounds adversarial key derivation and storage.
   */
  private static readonly DEFAULT_MAX_SKIP = 25000;

  /** Storage adapter for session state and keys */
  private readonly keyStorage: ISignalProtocolLocalStore;
  private readonly logger: Required<ILogger>;

  /** Callback to establish new sessions from PreKeyMessages */
  private readonly establishSession: SessionEstablishmentCallback;

  /** Per-session lock for concurrency safety */
  private readonly lock: AsyncLock;

  /** Maximum message keys to skip in one chain (DoS protection) */
  private readonly maxSkip: number;

  /**
   * Create a new SessionCipher instance
   *
   * @param keyStorage - Storage adapter for session state, identity keys, prekeys
   * @param establishSession - Callback invoked when a PreKeyMessage is received
   *   and a new session needs to be established. The callback should perform
   *   X3DH key agreement and return initialized session state.
   * @param lock - AsyncLock instance for per-session concurrency control.
   *   Sessions are locked by ID to prevent race conditions.
   * @param config - Optional configuration
   * @param config.maxSkip - Maximum message keys to skip (default: 1000).
   *   Higher values allow more out-of-order messages but increase memory/CPU.
   */
  constructor(
    keyStorage: ISignalProtocolLocalStore,
    establishSession: SessionEstablishmentCallback,
    lock: AsyncLock,
    config: SessionCipherConfig = {},
    logger: Required<ILogger> = defaultSignalProtocolLogger
  ) {
    this.keyStorage = keyStorage;
    this.establishSession = establishSession;
    this.lock = lock;
    this.maxSkip = config.maxSkip ?? SessionCipher.DEFAULT_MAX_SKIP;
    this.logger = logger;
  }

  /**
   * Get lock key for a specific session
   * Each session has its own lock to prevent cross-conversation blocking
   */
  private getLockKey(address: ProtocolAddress): string {
    return `session:${ProtocolAddress.toString(address)}`;
  }

  /**
   * Create a SessionRecord wrapper for storage
   */
  private wrapSession(session: SessionState): SessionRecord {
    return {
      currentSession: session,
      archivedSessions: {},
      version: CURRENT_SESSION_RECORD_VERSION,
    };
  }

  private markSessionAcknowledged(session: SessionState): void {
    session.hasReceivedMessage = true;
    session.unacknowledgedPreKeyMessage = false;
    delete session.kyberCiphertext;
    delete session.kemOneTimePreKeyCiphertext;
  }

  // ============================================================================
  // Encryption
  // ============================================================================

  /**
   * Encrypt a message using Full Double Ratchet
   *
   * Implements Signal Protocol Section 3.4 RatchetEncrypt.
   * Encrypts plaintext using the sending chain key, advances the sending chain,
   * and includes the DH ratchet public key and message counter in the header.
   *
   * ## Algorithm Steps
   *
   * 1. Load and validate session state
   * 2. Derive message key (Triple Ratchet if SPQR enabled, else Double Ratchet)
   * 3. Expand to 80-byte key material (32 enc + 32 auth + 16 IV)
   * 4. Encrypt message counters with header key (AES-256-CTR)
   * 5. Encrypt plaintext (AES-256-CBC + HMAC-SHA256)
   * 6. Package as RatchetMessage or PreKeyMessage (first message)
   * 7. Advance sending chain (CKs, Ns++)
   * 8. Best-effort overwrite owned temporary key arrays
   *
   * ## Message Types
   *
   * - **PreKeyMessage**: First message from session initiator, includes X3DH info
   * - **RatchetMessage**: All subsequent messages with Double Ratchet header
   *
   * ## Concurrency
   *
   * Protected by per-session lock to prevent race conditions when multiple
   * messages are encrypted simultaneously for the same conversation.
   *
   * @param remoteAddress - Protocol address for the session (userId:deviceId)
   * @param plaintext - Message content to encrypt (UTF-8 string)
   * @returns JSON-serialized ciphertext (PreKeyMessage or RatchetMessage)
   * @throws {EncryptionError} SESSION_NOT_FOUND if no session exists
   * @throws {EncryptionError} ENCRYPTION_FAILED on any encryption error
   *
   * @see https://signal.org/docs/specifications/doubleratchet/#encrypting-messages
   */
  async encrypt(remoteAddress: ProtocolAddress, plaintext: string): Promise<Ciphertext> {
    return await this.lock.acquire(this.getLockKey(remoteAddress), async () => {
      try {
        const record = await this.keyStorage.getSessionRecord(remoteAddress);
        if (record && record.version !== CURRENT_SESSION_RECORD_VERSION) {
          await this.keyStorage.deleteSessionRecord(remoteAddress);
          throw new EncryptionError(
            `Unsupported session record version ${record.version}; session was reset`,
            EncryptionErrorCode.SESSION_NOT_FOUND
          );
        }
        const session = record?.currentSession
          ? cloneSessionStateForDecryptAttempt(record.currentSession)
          : null;
        if (!session) {
          throw new EncryptionError(
            `No session found for ${ProtocolAddress.toString(remoteAddress)}`,
            EncryptionErrorCode.SESSION_NOT_FOUND
          );
        }

        validateSessionStateIntegrity(session, this.logger);

        // Validate session has required DH keys (narrows type for structural typing)
        assertValidatedSession(session, 'encrypt');

        // Reject untrusted identities before advancing the send chain.
        const isTrusted = await this.keyStorage.isTrustedIdentity(
          remoteAddress,
          session.remoteIdentity,
          TrustDirection.SENDING,
          session.remoteIdentityType
        );
        if (!isTrusted) {
          throw new UntrustedIdentityError(remoteAddress, session.remoteIdentity);
        }

        // Reject expired, unacknowledged PreKey sessions.
        // PreKey sessions that haven't received a reply within 30 days are rejected
        if (session.hasReceivedMessage === false) {
          const sessionAge = Date.now() - session.createdAt;
          if (sessionAge > MAX_UNACKNOWLEDGED_SESSION_AGE_MS) {
            throw new EncryptionError(
              'Unacknowledged session expired (no reply received within 30 days)',
              EncryptionErrorCode.SESSION_NOT_FOUND,
              {
                sessionAge: Math.floor(sessionAge / (24 * 60 * 60 * 1000)),
                maxAge: 30,
                remoteAddress: ProtocolAddress.toString(remoteAddress),
              }
            );
          }
        }

        // Validate session key ownership to detect corrupted sessions BEFORE encrypting
        // This prevents sending messages that the recipient cannot decrypt
        const signedPreKey = await this.keyStorage.getEcSignedPreKey();
        if (signedPreKey) {
          validateSessionKeyOwnership(session, signedPreKey.publicKey, this.logger);
        }

        // Cleanup expired message keys before encryption (Section 8.4)
        cleanupExpiredMessageKeys(session, undefined, this.logger);

        // Step 1: Derive message key using ratchet (Triple or Double)
        // Session is now validated - passes directly to double-ratchet via structural typing
        const originalNs = session.Ns;

        let finalMessageKey: Uint8Array;
        let pqMessageKeySalt: Uint8Array | undefined;
        let pqRatchetBytes: Uint8Array | undefined;

        if (session.tripleRatchet?.enabled && session.tripleRatchet.spqrState) {
          // Triple Ratchet: Combined EC + PQ key derivation (Section 6)
          this.logger.debug('Triple Ratchet: Deriving combined EC + PQ message key', {
            category: 'E2EE',
            data: {
              operation: 'triple-ratchet-encrypt',
              counter: session.Ns,
              spqrEpoch: session.tripleRatchet.spqrState.epoch,
            },
          });

          // Step A: EC message key from Double Ratchet
          const ecResult = await moduleDeriveKey(session as DoubleRatchetState, this.logger);

          // Step B: PQ message key + opaque bytes from black-box SPQR
          // spqrSend handles ALL PQ: lazy KEM, version capability, key derivation
          const spqrResult = await spqrSend(session.tripleRatchet.spqrState, this.logger);
          if (spqrResult.msgBytes.length > 0) {
            pqRatchetBytes = spqrResult.msgBytes;
          }

          // Step C: Use profile key expansion:
          // EC message key as input key material + PQ message key as optional HKDF salt.
          if (spqrResult.messageKey) {
            finalMessageKey = ecResult.messageKey;
            pqMessageKeySalt = spqrResult.messageKey;
          } else {
            finalMessageKey = ecResult.messageKey;
          }

          this.logger.breadcrumb('Triple Ratchet: Combined EC + PQ message keys', {
            category: 'E2EE',
            level: 'debug',
            data: {
              operation: 'triple-ratchet-encrypt',
              ecMessageNumber: session.Ns - 1,
              hasPqRatchet: !!pqRatchetBytes,
              hasPqKey: !!pqMessageKeySalt,
            },
          });
        } else {
          // Double Ratchet only: EC key derivation
          this.logger.debug('Double Ratchet: Deriving EC message key', {
            category: 'E2EE',
            data: {
              operation: 'encrypt',
              counter: session.Ns,
              hasChainKey: !!session.CKs,
            },
          });

          // Pass session directly - mutations happen in place
          const doubleResult = await moduleDeriveKey(session as DoubleRatchetState, this.logger);
          finalMessageKey = doubleResult.messageKey;
        }

        // No applyRatchetState needed - mutations happened directly on session

        // Step 2: Expand message key to 80 bytes (32 enc + 32 auth + 16 IV)
        // using profile optional salt for Triple Ratchet.
        let encryptionKey: Uint8Array | undefined;
        let authKey: Uint8Array | undefined;
        let iv: Uint8Array | undefined;
        let protobufFramedSignalProtocolMsg: Uint8Array | undefined;
        let authenticatedRecipientIdentityType: 1 | 2 | undefined;
        try {
          ({ encryptionKey, authKey, iv } = await CryptoUtils.expandMessageKey(
            finalMessageKey,
            pqMessageKeySalt
          ));

          // Step 3: Prepare plaintext header components (Section 3 variant)
          const ratchetKey = session.DHs.publicKey;
          const previousCounter = session.PN;
          const counter = originalNs;

          this.logger.debug('Preparing plaintext message header', {
            category: 'E2EE',
            data: {
              operation: 'encrypt',
              counter,
              previousCounter,
            },
          });

          // Step 4: Pad and encrypt plaintext with AES-256-CBC (encrypt-only, MAC computed separately)
          // ISO/IEC 7816-4 padding reduces plaintext-length disclosure.
          const plaintextBytes = CryptoUtils.stringToBytes(plaintext);
          const paddedPlaintext = CryptoUtils.padMessage(plaintextBytes);
          const ciphertextBase64 = await CryptoUtils.aesCbcEncrypt(
            encryptionKey,
            iv,
            paddedPlaintext
          );

          // Step 5: Compute identity-bound MAC (Section 3 variant)
          // MAC input: MESSAGE_VERSION_BYTE || sender_identity_key || receiver_identity_key || serialized_header || ciphertext
          // Per Signal Protocol Section 3 - "associated_data SHOULD contain sender's and receiver's identity public keys"

          {
            // Protobuf wire format: encode SignalProtocolMessage, compute the pinned-reference MAC shape.
            const ratchetKeyBytes33 = CryptoUtils.ensureSerializedPublicKey(
              CryptoUtils.base64ToBytes(ratchetKey)
            );
            const ciphertextBytes = CryptoUtils.base64ToBytes(ciphertextBase64);

            // pqRatchetBytes is already opaque bytes from spqrSend() above

            if (session.unacknowledgedPreKeyMessage === true) {
              if (!session.recipientIdentityType) {
                throw new EncryptionError(
                  'Initiator session is missing its recipient identity namespace',
                  EncryptionErrorCode.SESSION_CORRUPTED
                );
              }
              authenticatedRecipientIdentityType = identityTypeToWire(
                session.recipientIdentityType
              );
            }

            // Encode SignalProtocolMessage protobuf (no version byte or MAC yet)
            const protobufBytes = encodeSignalProtocolMessage({
              ratchetKey: ratchetKeyBytes33,
              counter,
              previousCounter,
              ciphertext: ciphertextBytes,
              pqRatchet: pqRatchetBytes,
              addresses: serializeSignalProtocolMessageAddresses(session.localAddress, remoteAddress),
              recipientIdentityType: authenticatedRecipientIdentityType,
            });

            // Build serializedForMac: version_byte + protobuf_bytes (everything except trailing MAC)
            const serializedForMac = new Uint8Array(1 + protobufBytes.length);
            serializedForMac[0] = makeVersionByte();
            serializedForMac.set(protobufBytes, 1);

            // Bind both locally-derived composite identity commitments.
            const macBytes = computeCompositeIdentityMessageMac(
              authKey,
              session.localIdentity,
              session.remoteIdentity,
              serializedForMac
            );

            // Frame: [version_byte][protobuf_bytes][MAC(8)]
            protobufFramedSignalProtocolMsg = frameSignalProtocolMessage(protobufBytes, macBytes);
          }
        } finally {
          if (pqMessageKeySalt) {
            CryptoUtils.secureZeroBytes(pqMessageKeySalt);
            pqMessageKeySalt = undefined;
          }

          // Best-effort overwrite owned message-key bytes after use.
          CryptoUtils.secureZeroBytes(finalMessageKey);
          if (encryptionKey) CryptoUtils.secureZeroBytes(encryptionKey);
          if (authKey) CryptoUtils.secureZeroBytes(authKey);
          if (iv) CryptoUtils.secureZeroBytes(iv);
        }

        // Step 6: Check if this should be a PreKeyMessage
        // Uses persistent flag so that if the first PreKeyMessage is lost,
        // subsequent messages are still sent as PreKeyMessages until acknowledged
        const shouldSendPreKeyMessage = session.unacknowledgedPreKeyMessage === true;

        if (shouldSendPreKeyMessage) {
          this.logger.breadcrumb(
            'Created PreKeyMessage for session establishment (initiator first message)',
            {
              category: 'E2EE',
              level: 'info',
              data: {
                messageType: 'PreKeyMessage',
                role: 'initiator',
                // Diagnostic: KEM one-time prekey fields for debugging IKM mismatch
                usedKemOneTimePreKeyId: session.usedKemOneTimePreKeyId,
                hasKemOneTimeCiphertext: !!session.kemOneTimePreKeyCiphertext,
                kemOneTimeCiphertextLen: session.kemOneTimePreKeyCiphertext?.length,
              },
            }
          );
        } else if (session.Ns === 0) {
          this.logger.breadcrumb('Sending regular RatchetMessage (responder first send, Ns=0)', {
            category: 'E2EE',
            level: 'info',
            data: { messageType: 'RatchetMessage', role: 'responder', Ns: 0 },
          });
        }

        // Step 8: Update session state
        session.lastUsedAt = Date.now();

        // Snapshot PQXDH fields for protobuf PreKeySignalProtocolMessage encoding.
        // Retain the complete PreKeySignalProtocolMessage material until the session is
        // acknowledged so a lost first message can be retried.
        const kyberCiphertextForPreKey = session.kyberCiphertext;
        const kemOneTimeCiphertextForPreKey = session.kemOneTimePreKeyCiphertext;

        // Note: spqrSend() already clears pending Kyber data and marks version capability sent

        // Serialize: protobuf binary transport format
        let encodedCiphertext: Ciphertext;
        if (shouldSendPreKeyMessage) {
          // Wrap inner framed SignalProtocolMessage in PreKeySignalProtocolMessage protobuf
          const identityKeyForPreKey = await this.keyStorage.getIdentityKey();
          if (!identityKeyForPreKey) {
            throw new EncryptionError(
              'Identity key not found for PreKeySignalProtocolMessage encoding',
              EncryptionErrorCode.INITIALIZATION_FAILED
            );
          }
          const preKeyProtobuf = encodePreKeySignalProtocolMessage({
            ecOneTimePreKeyId: session.usedOneTimePreKeyId,
            baseKey: CryptoUtils.ensureSerializedPublicKey(
              CryptoUtils.base64ToBytes(session.DHs.publicKey)
            ),
            identityKey: encodeCompositeIdentityV1(session.localIdentity),
            message: protobufFramedSignalProtocolMsg!, // field 4 = complete framed inner SignalProtocolMessage
            registrationId: session.localRegistrationId,
            ecSignedPreKeyId: session.usedSignedPreKeyId!,
            recipientIdentityType: authenticatedRecipientIdentityType!,
            kemLastResortPreKeyId: session.usedKyberPreKeyId,
            kemLastResortCiphertext: kyberCiphertextForPreKey
              ? CryptoUtils.base64ToBytes(kyberCiphertextForPreKey)
              : undefined,
            kemOneTimePreKeyId: session.usedKemOneTimePreKeyId,
            kemOneTimeCiphertext: kemOneTimeCiphertextForPreKey
              ? CryptoUtils.base64ToBytes(kemOneTimeCiphertextForPreKey)
              : undefined,
          });
          encodedCiphertext = CryptoUtils.bytesToBase64(
            framePreKeySignalProtocolMessage(preKeyProtobuf)
          ) as Ciphertext;
        } else {
          encodedCiphertext = CryptoUtils.bytesToBase64(protobufFramedSignalProtocolMsg!) as Ciphertext;
        }

        // Preserve archivedSessions from existing record (same pattern as decrypt)
        const recordToStore = record
          ? { ...record, currentSession: session }
          : this.wrapSession(session);
        // Commit the matched/pinned TOFU identity and advanced send state
        // together, after the outgoing ciphertext has been fully constructed.
        await this.keyStorage.commitSessionTrust({
          address: remoteAddress,
          record: recordToStore,
          contactIdentity: session.remoteIdentity,
          contactIdentityType: session.remoteIdentityType,
          localIdentityType: session.localIdentityType,
        });

        return encodedCiphertext;
      } catch (error) {
        // Preserve specific error codes (e.g., SESSION_CORRUPTED from validation)
        if (error instanceof EncryptionError) {
          throw error;
        }
        throw new EncryptionError(
          'Failed to encrypt message',
          EncryptionErrorCode.ENCRYPTION_FAILED,
          { originalError: error as Error }
        );
      }
    });
  }

  // ============================================================================
  // Decryption
  // ============================================================================

  /**
   * Decrypt a message using Full Double Ratchet
   *
   * Implements Signal Protocol Section 3.5 RatchetDecrypt.
   * Handles out-of-order messages, DH ratchet steps, and header encryption.
   *
   * ## Algorithm Steps
   *
   * 1. Parse message (validate required fields)
   * 2. Try skipped message keys first (receiverChains for out-of-order)
   * 3. Check if DH public key changed → DH ratchet needed
   * 4. Decrypt message header to get counters
   * 5. Perform DH ratchet step if needed (with PQ if SPQR enabled)
   * 6. Store any skipped message keys
   * 7. Derive message key (Triple or Double Ratchet)
   * 8. Decrypt and verify MAC
   * 9. Advance receiving chain (CKr, Nr++)
   * 10. Update next receiving header key (NHKr)
   * 11. Best-effort overwrite owned temporary key arrays
   *
   * ## Session Establishment
   *
   * If the session doesn't exist and the message is a PreKeyMessage, this method
   * will establish the session as the responder by calling the establishSession
   * callback to perform X3DH key agreement.
   *
   * ## Out-of-Order Handling
   *
   * Messages can arrive out of order due to network conditions. The algorithm
   * handles this by:
   * - Trying all stored skipped keys (receiverChains) first
   * - Storing keys for skipped messages when receiving a message with higher number
   * - Cleaning up expired skipped keys (Section 8.4)
   *
   * ## Concurrency
   *
   * Protected by per-session lock to prevent race conditions when multiple
   * messages are decrypted simultaneously for the same conversation.
   *
   * @param remoteAddress - Protocol address for the session (userId:deviceId)
   * @param ciphertext - JSON-serialized PreKeyMessage or RatchetMessage
   * @returns Decrypted plaintext (UTF-8 string)
   * @throws {EncryptionError} SESSION_NOT_FOUND if no session and not PreKeyMessage
   * @throws {EncryptionError} INVALID_CIPHERTEXT if message format is invalid
   * @throws {EncryptionError} DECRYPTION_FAILED on MAC failure or other error
   *
   * @see https://signal.org/docs/specifications/doubleratchet/#decrypting-messages
   */
  async decrypt(remoteAddress: ProtocolAddress, ciphertext: Ciphertext): Promise<string> {
    return await this.lock.acquire(this.getLockKey(remoteAddress), async () => {
      try {
        // Parse message FIRST (before loading session)
        // Detect format and parse: protobuf binary (base64) or JSON
        let message: RatchetMessage | PreKeyMessage;
        let protobufMacContext: ProtobufMacContext | undefined;
        let receivedPqRatchetBytes: Uint8Array | undefined;

        {
          // Binary protobuf format (base64-encoded)
          const framedBytes = CryptoUtils.base64ToBytes(ciphertext as Base64);

          // Detect message type from first protobuf tag (after version byte)
          // SignalProtocolMessage field 1 (bytes) -> tag 0x0A
          // PreKeySignalProtocolMessage field 1 (uint32) -> tag 0x08, or field 2 (bytes) -> tag 0x12
          const firstProtoTag = framedBytes[1];
          const isBinaryPreKey = firstProtoTag === 0x08 || firstProtoTag === 0x12;

          if (isBinaryPreKey) {
            // PreKeySignalProtocolMessage: [version_byte][protobuf] (no MAC)
            const { protobufBytes: outerProtobuf } = parsePreKeySignalProtocolMessageEnvelope(framedBytes);
            const preKeyFields = decodePreKeySignalProtocolMessage(outerProtobuf);

            // Inner framed SignalProtocolMessage from field 4
            const innerFramed = preKeyFields.message;
            const { protobufBytes: innerProtobuf, mac: innerMac } =
              parseSignalProtocolMessageEnvelope(innerFramed);
            const signalFields = decodeSignalProtocolMessage(innerProtobuf);

            // The outer field selects the local key namespace before MAC
            // verification. Requiring an identical value inside the MACed
            // SignalProtocolMessage prevents an attacker from switching that choice.
            if (signalFields.recipientIdentityType !== preKeyFields.recipientIdentityType) {
              throw new EncryptionError(
                'PreKeySignalProtocolMessage recipient identity namespace is not MAC-bound',
                EncryptionErrorCode.INVALID_CIPHERTEXT
              );
            }
            const recipientIdentityType = identityTypeFromWire(
              preKeyFields.recipientIdentityType
            );

            protobufMacContext = createProtobufMacContext(
              innerFramed,
              innerMac,
              signalFields.addresses
            );

            // Keep raw pqRatchet bytes (opaque — decoded by spqrRecv later)
            const pqRatchetRaw = signalFields.pqRatchet;

            // Convert protobuf fields back to PreKeyMessage JS object
            // ratchetKey: strip 0x05 prefix (33->32 bytes), convert to base64
            // The ratchet key is a public header field, so its length check does
            // not depend on secret data.
            const ratchetKeyRaw =
              signalFields.ratchetKey.length === 33
                ? CryptoUtils.deserializePublicKey(signalFields.ratchetKey)
                : signalFields.ratchetKey;
            const baseKeyRaw =
              preKeyFields.baseKey.length === 33
                ? CryptoUtils.deserializePublicKey(preKeyFields.baseKey)
                : preKeyFields.baseKey;
            const senderIdentity = decodeCompositeIdentityV1(preKeyFields.identityKey);

            message = {
              type: MessageType.PREKEY,
              messageVersion: MESSAGE_FORMAT,
              ratchetKey: CryptoUtils.bytesToBase64(ratchetKeyRaw),
              counter: signalFields.counter,
              previousCounter: signalFields.previousCounter,
              ciphertext: CryptoUtils.bytesToBase64(signalFields.ciphertext),
              mac: CryptoUtils.bytesToBase64(innerMac), // Store envelope MAC for reference
              senderId: remoteAddress.userId,
              senderDeviceId: remoteAddress.deviceId,
              senderIdentity,
              senderEphemeralKey: CryptoUtils.bytesToBase64(baseKeyRaw),
              senderRegistrationId: preKeyFields.registrationId,
              recipientIdentityType,
              usedSignedPreKeyId: preKeyFields.ecSignedPreKeyId,
              usedOneTimePreKeyId: preKeyFields.ecOneTimePreKeyId,
              usedKyberPreKeyId: preKeyFields.kemLastResortPreKeyId,
              kyberCiphertext: preKeyFields.kemLastResortCiphertext?.length
                ? CryptoUtils.bytesToBase64(preKeyFields.kemLastResortCiphertext)
                : undefined,
              usedKemOneTimePreKeyId: preKeyFields.kemOneTimePreKeyId,
              kemOneTimePreKeyCiphertext: preKeyFields.kemOneTimeCiphertext?.length
                ? CryptoUtils.bytesToBase64(preKeyFields.kemOneTimeCiphertext)
                : undefined,
            } as PreKeyMessage;
            // Store raw pqRatchet bytes for opaque processing by spqrRecv
            receivedPqRatchetBytes = pqRatchetRaw;
          } else {
            // SignalProtocolMessage: [version_byte][protobuf][MAC(8)]
            const { protobufBytes, mac: envelopeMac } = parseSignalProtocolMessageEnvelope(framedBytes);
            const signalFields = decodeSignalProtocolMessage(protobufBytes);

            protobufMacContext = createProtobufMacContext(
              framedBytes,
              envelopeMac,
              signalFields.addresses
            );

            // Keep raw pqRatchet bytes (opaque — decoded by spqrRecv later)
            const pqRatchetRaw = signalFields.pqRatchet;

            const ratchetKeyRaw =
              signalFields.ratchetKey.length === 33
                ? CryptoUtils.deserializePublicKey(signalFields.ratchetKey)
                : signalFields.ratchetKey;

            message = {
              type: MessageType.RATCHET,
              messageVersion: MESSAGE_FORMAT,
              ratchetKey: CryptoUtils.bytesToBase64(ratchetKeyRaw) as PublicKey,
              counter: signalFields.counter,
              previousCounter: signalFields.previousCounter,
              ciphertext: CryptoUtils.bytesToBase64(signalFields.ciphertext),
              mac: CryptoUtils.bytesToBase64(envelopeMac),
            };
            // Store raw pqRatchet bytes for opaque processing by spqrRecv
            receivedPqRatchetBytes = pqRatchetRaw;
          }
        }
        const ratchetKeyFromMessage = message.ratchetKey;
        const previousCounterFromMessage = message.previousCounter;
        const counterFromMessage = message.counter;

        // Check if this is a PreKeyMessage (first message from initiator)
        const isPreKeyMessage = message.type === MessageType.PREKEY;

        // A PreKeyMessage can legitimately arrive before a session exists.
        let existingRecord = await this.keyStorage.getSessionRecord(remoteAddress);
        if (existingRecord && existingRecord.version !== CURRENT_SESSION_RECORD_VERSION) {
          await this.keyStorage.deleteSessionRecord(remoteAddress);
          existingRecord = null;
        }
        let session = existingRecord?.currentSession
          ? cloneSessionStateForDecryptAttempt(existingRecord.currentSession)
          : null;

        // SESAME §3.2 & §3.4: For RatchetMessages, get ALL session candidates (current + archived)
        // This supports decryption of delayed messages using archived sessions.
        // PreKeyMessages either use an existing matching base-key session or establish a new one.
        const sessionCandidates =
          !isPreKeyMessage && existingRecord
            ? SessionResolver.findDecryptingSessions(existingRecord)
            : [];
        // Track which candidate index to try next on failure.
        // If we already have a current session, we've effectively "used" index 0 (the current session),
        // so on failure we should start from index 1 (archived sessions).
        let currentCandidateIndex = session ? 1 : 0;
        let usedArchivedCandidate: { baseKey: Base64 } | null = null;

        // If no current session but have archived candidates, try first archived
        // This handles the case where currentSession is null but archived sessions exist
        if (!isPreKeyMessage && !session && sessionCandidates.length > 0) {
          const firstCandidate = sessionCandidates[currentCandidateIndex++];
          session = cloneSessionStateForDecryptAttempt(firstCandidate.session);
          if (!firstCandidate.isActive && firstCandidate.baseKey) {
            usedArchivedCandidate = { baseKey: firstCandidate.baseKey };
          }
          this.logger.debug('Using archived session candidate (no current session)', {
            category: 'E2EE',
            data: {
              operation: 'decrypt',
              isActive: firstCandidate.isActive,
              candidateIndex: currentCandidateIndex - 1,
              totalCandidates: sessionCandidates.length,
            },
          });
        }

        // DIAGNOSTIC: Log session state on load to detect key corruption
        if (session) {
          this.logger.breadcrumb('decrypt: Loaded existing session', {
            category: 'E2EE',
            level: 'debug',
            data: {
              operation: 'session-load',
              isInitiator: session.isInitiator,
              DHsPublicKey: session.DHs?.publicKey?.substring(0, 20) ?? 'undefined',
              DHr: session.DHr?.substring(0, 20) ?? 'undefined',
              hasCKs: !!session.CKs,
              hasCKr: !!session.CKr,
              remoteAddress: ProtocolAddress.toString(remoteAddress),
            },
          });
        }

        let retriedAfterArchive = false;
        let preKeyMatchedExistingSession = false;
        const prekeyMessage = isPreKeyMessage ? (message as PreKeyMessage) : null;
        let prekeyRemoteProtocolAddress: ProtocolAddress | null = null;

        if (prekeyMessage) {
          if (prekeyMessage.senderDeviceId === undefined) {
            throw new EncryptionError(
              'PreKeyMessage missing senderDeviceId - multi-device protocol requires explicit device ID',
              EncryptionErrorCode.INVALID_CIPHERTEXT
            );
          }
          prekeyRemoteProtocolAddress = ProtocolAddress.create(
            prekeyMessage.senderId,
            prekeyMessage.senderDeviceId
          );

          // SECURITY: Validate sender matches expected address for every PreKeyMessage.
          // This prevents session hijacking even when a current session already exists.
          if (!ProtocolAddress.equals(prekeyRemoteProtocolAddress, remoteAddress)) {
            throw new EncryptionError(
              `Sender identity mismatch: message from ${ProtocolAddress.toString(prekeyRemoteProtocolAddress)} ` +
                `but expected ${ProtocolAddress.toString(remoteAddress)}. ` +
                'This may indicate a session hijacking attempt.',
              EncryptionErrorCode.IDENTITY_MISMATCH
            );
          }
        }

        // CRITICAL: Check for identity key change when receiving PreKeyMessage with existing session
        // This handles the device reset scenario where the sender has reinstalled their app
        // and generated a new identity key, but we have an old session that can't decrypt.
        if (session && prekeyMessage) {
          const storedIdentity = session.remoteIdentity;
          const incomingIdentity = prekeyMessage.senderIdentity;

          // Compare identity keys (both are base64 PublicKey strings)
          if (!compositeIdentitiesEqual(storedIdentity, incomingIdentity)) {
            // Sender matches expected address - this is a legitimate identity key change (device reset)
            this.logger.warn('Identity key changed detected - sender may have reinstalled', {
              category: 'SECURITY',
              data: {
                remoteAddress: ProtocolAddress.toString(remoteAddress),
                event: 'identity_key_changed',
              },
            });

            // Discard old session (it's useless now - different identity key)
            // Set session to null to trigger new session establishment below
            session = null;

            this.logger.info('Old session discarded, establishing new session from PreKeyMessage', {
              category: 'E2EE',
              data: { remoteAddress: ProtocolAddress.toString(remoteAddress) },
            });
          }
        }

        if (prekeyMessage) {
          const isTrustedPreKeyIdentity = await this.keyStorage.isTrustedIdentity(
            remoteAddress,
            prekeyMessage.senderIdentity,
            TrustDirection.RECEIVING,
            'aci'
          );
          if (!isTrustedPreKeyIdentity) {
            throw new UntrustedIdentityError(remoteAddress, prekeyMessage.senderIdentity);
          }

          const matchingPreKeySession = findMatchingPreKeySession(existingRecord, prekeyMessage);
          if (matchingPreKeySession) {
            session = cloneSessionStateForDecryptAttempt(matchingPreKeySession.session);
            preKeyMatchedExistingSession = true;
            usedArchivedCandidate = matchingPreKeySession.archivedBaseKey
              ? { baseKey: matchingPreKeySession.archivedBaseKey }
              : null;
            this.logger.debug(
              'PreKeyMessage matched existing base-key session; skipping X3DH/PQXDH establishment',
              {
                category: 'E2EE',
                data: {
                  operation: 'prekey-existing-session',
                  archived: matchingPreKeySession.archivedBaseKey !== null,
                  remoteAddress: ProtocolAddress.toString(remoteAddress),
                },
              }
            );
          }
        }

        // Track for auto-recovery: if PreKeyMessage decryption fails on an existing session,
        // we archive the corrupted session and retry with fresh establishment.
        const hadExistingSession = session !== null;

        // Auto-recovery retry loop for:
        // 1. PreKeyMessage failures on existing sessions (archive and retry once) - needs max 2 attempts
        // 2. RatchetMessage failures (try all archived session candidates per SESAME §3.2)
        // For RatchetMessages, we only need sessionCandidates.length attempts (or 1 if empty).
        // For PreKeyMessages, we need at least 2 for the archive-and-retry pattern.
        const maxAttempts = isPreKeyMessage ? 2 : Math.max(1, sessionCandidates.length);
        for (let attempt = 0; attempt < maxAttempts; attempt++) {
          try {
            // On retry: archive corrupted session and reset for fresh establishment
            if (retriedAfterArchive) {
              if (existingRecord) {
                // Stage recovery against a deep clone. Persisting (or mutating an
                // adapter-owned object) here would let a message that ultimately
                // fails authentication archive a valid durable session.
                const candidateRecord = CryptoUtils.cloneProtocolState(existingRecord);
                const archivedRecord = SessionRecordNS.archiveCurrentState(candidateRecord);
                existingRecord = archivedRecord;
              }
              session = null;
              retriedAfterArchive = false; // Reset flag after archiving
              this.logger.info('Staged corrupted-session archive; retrying PreKeyMessage establishment', {
                category: 'E2EE',
                data: { remoteAddress: ProtocolAddress.toString(remoteAddress), attempt },
              });
            }

            // If no session exists AND this is a PreKeyMessage, establish session as responder
            if (!session && isPreKeyMessage) {
              this.logger.breadcrumb('Received PreKeyMessage - establishing session as responder', {
                category: 'E2EE',
                level: 'info',
                data: { messageType: 'PreKeyMessage', role: 'responder' },
              });

              if (!prekeyMessage || !prekeyRemoteProtocolAddress) {
                throw new EncryptionError(
                  'PreKeyMessage missing establishment metadata',
                  EncryptionErrorCode.INVALID_CIPHERTEXT
                );
              }

              this.logger.breadcrumb('Establishing session as responder', {
                category: 'E2EE',
                level: 'info',
                data: {
                  remoteAddress: ProtocolAddress.toString(prekeyRemoteProtocolAddress),
                  role: 'responder',
                },
              });

              // Delegate session establishment to callback (handled by manager)
              session = await this.establishSession(prekeyRemoteProtocolAddress, prekeyMessage);

              // Note: Session is stored at line 1053 AFTER successful decryption.
              // This ensures partial/incomplete sessions from failed decrypts don't pollute storage.

              this.logger.breadcrumb('Session established from PreKeyMessage - ready to decrypt', {
                category: 'E2EE',
                level: 'info',
                data: { messageType: 'PreKeyMessage', role: 'responder' },
              });

              // DIAGNOSTIC: Log newly established session keys to detect corruption
              this.logger.breadcrumb('decrypt: Newly established session keys', {
                category: 'E2EE',
                level: 'debug',
                data: {
                  operation: 'session-established',
                  isInitiator: session.isInitiator,
                  DHsPublicKey: session.DHs?.publicKey?.substring(0, 20) ?? 'undefined',
                  DHr: session.DHr?.substring(0, 20) ?? 'undefined',
                  hasCKs: !!session.CKs,
                  hasCKr: !!session.CKr,
                  baseKey: session.baseKey?.substring(0, 20) ?? 'undefined',
                },
              });
            } else if (!session) {
              throw new EncryptionError(
                `No session found for ${ProtocolAddress.toString(remoteAddress)}`,
                EncryptionErrorCode.SESSION_NOT_FOUND
              );
            }

            // Validate session state integrity FIRST (receiverChains, etc.)
            // This catches corruption that would cause runtime errors in subsequent operations
            // MUST run before cleanupExpiredMessageKeys which accesses receiverChains
            validateSessionStateIntegrity(session, this.logger);

            // Cleanup expired message keys before decryption (Section 8.4)
            cleanupExpiredMessageKeys(session, undefined, this.logger);

            // Validate session key ownership to detect corrupted sessions
            // This catches the "swapped keys" bug where DHr equals our own signed prekey
            const signedPreKey = await this.keyStorage.getEcSignedPreKey();
            if (signedPreKey) {
              validateSessionKeyOwnership(session, signedPreKey.publicKey, this.logger);
            }

            // Plaintext counters from message (Section 3 variant - no header decryption needed)
            const counters = {
              previousCounter: previousCounterFromMessage,
              counter: counterFromMessage,
            };

            this.logger.debug('Processing message with plaintext header', {
              category: 'E2EE',
              data: {
                operation: 'decrypt',
                counter: counters.counter,
                previousCounter: counters.previousCounter,
                ratchetKeyPreview: ratchetKeyFromMessage?.substring(0, 20),
              },
            });

            // Step 1: Try all skipped message keys first (using DHr:N key format)
            // Pass pqRatchetBytes so skipped key path can decode SPQR epoch/messageNumber
            // for PQ key combination (without advancing the main SPQR receive chain)
            const skippedPlaintext = await trySkippedMessageKeys(
              session,
              ratchetKeyFromMessage,
              counters.counter,
              message,
              protobufMacContext,
              receivedPqRatchetBytes,
              this.logger
            );

            if (skippedPlaintext !== null) {
              const isTrustedReceivingIdentity = await this.keyStorage.isTrustedIdentity(
                remoteAddress,
                session.remoteIdentity,
                TrustDirection.RECEIVING,
                session.remoteIdentityType
              );
              if (!isTrustedReceivingIdentity) {
                throw new UntrustedIdentityError(remoteAddress, session.remoteIdentity);
              }

              // H3: Mark session as acknowledged and clear unacknowledged PreKey items.
              this.markSessionAcknowledged(session);

              // Preserve archivedSessions when storing after skipped key decryption
              const recordToStore = existingRecord
                ? { ...existingRecord, currentSession: session }
                : this.wrapSession(session);
              const pendingDeletion = session.pendingPreKeyDeletion;
              if (isPreKeyMessage) {
                delete session.pendingPreKeyDeletion;
                await this.keyStorage.commitSessionTrust({
                  address: remoteAddress,
                  record: recordToStore,
                  contactIdentity: session.remoteIdentity,
                  contactIdentityType: session.remoteIdentityType,
                  localIdentityType: pendingDeletion?.identityType ?? session.localIdentityType,
                  oneTimePreKeyId: pendingDeletion?.oneTimePreKeyId,
                  kemOneTimePreKeyId: pendingDeletion?.kemOneTimePreKeyId,
                });
              } else {
                await this.keyStorage.commitSessionTrust({
                  address: remoteAddress,
                  record: recordToStore,
                  contactIdentity: session.remoteIdentity,
                  contactIdentityType: session.remoteIdentityType,
                  localIdentityType: session.localIdentityType,
                });
              }
              return skippedPlaintext;
            }

            // Step 2: Check if DH ratchet is needed
            // Per Signal Protocol Section 3.3 - DH ratchet is triggered when:
            // - DHr is undefined (lazy initialization - responder's first message)
            // - DHr differs from message's ratchet key (sender ratcheted)
            // String equality is fine here — DHr is transmitted in plaintext message
            // headers and is not secret.
            //
            const isLazyInit = session.DHr === undefined;
            const dhChanged = !isLazyInit && ratchetKeyFromMessage !== session.DHr;

            // SECURITY: Check if this is a replay from an old chain
            // If ratchetKey is in processedChains but NOT in receiverChains, it's a replay attack
            // (The message was already processed or all keys from that chain were consumed)
            if (dhChanged) {
              // Initialize processedChains if not present
              if (!session.processedChains) {
                session.processedChains = {};
              }

              // Check if this ratchet key was from a previous chain that we've already processed
              const previousChainInfo = session.processedChains[ratchetKeyFromMessage];
              if (previousChainInfo) {
                // This is an old chain - if not in receiverChains, it's a replay
                // (trySkippedMessageKeys already checked receiverChains and returned null)
                this.logger.warn('Replay attack detected: message from processed chain', {
                  category: 'E2EE',
                  data: {
                    operation: 'replay-detected-old-chain',
                    counter: counters.counter,
                    ratchetKeyPreview: ratchetKeyFromMessage?.substring(0, 20),
                    lastNrOnChain: previousChainInfo.lastNr,
                  },
                });

                // Reduce gross replay-vs-decrypt path differences without a
                // JavaScript constant-time or timing-equivalence claim.
                await performReplayRejectionWork();

                throw new EncryptionError(
                  `Message replay detected: ratchet key from processed chain (message ${counters.counter} on chain processed up to Nr=${previousChainInfo.lastNr})`,
                  EncryptionErrorCode.MESSAGE_DUPLICATE,
                  { counter: counters.counter }
                );
              }
            }

            const needsDHRatchet = isLazyInit || dhChanged;

            if (needsDHRatchet) {
              this.logger.debug('DH ratchet needed', {
                category: 'E2EE',
                data: {
                  operation: 'decrypt',
                  isLazyInit,
                  dhChanged,
                  ratchetKeyPreview: ratchetKeyFromMessage?.substring(0, 20),
                  sessionDHrPreview: session.DHr?.substring(0, 20),
                },
              });

              // Step 3: Skip keys from old receiving chain before DH ratchet
              // (only if not lazy init - Bob's first message has no old chain)
              if (!isLazyInit && counters.previousCounter > 0 && session.CKr && session.DHr) {
                const oldDHr = session.DHr;
                const oldNr = session.Nr;
                let currentChainKey = CryptoUtils.base64ToBytes(session.CKr);

                // DoS protection: previousCounter is an unauthenticated header field, and
                // the message key that would authenticate this sender is only derived by
                // the loop below. Bound the catch-up the same way the current-chain path
                // is bounded in storeSkippedMessageKeys, before deriving anything.
                const maxOldChainSkip = getMaxSkipForSession(session, this.maxSkip);
                if (oldNr + maxOldChainSkip < counters.previousCounter) {
                  throw new Error(
                    `Too many skipped messages (gap of ${counters.previousCounter - oldNr} exceeds limit of ${maxOldChainSkip})`
                  );
                }

                this.logger.debug('Skipping keys from old receiving chain before DH ratchet', {
                  category: 'E2EE',
                  data: {
                    operation: 'decrypt',
                    previousCounter: counters.previousCounter,
                    oldNr,
                  },
                });

                // Initialize receiverChains if not present
                if (!session.receiverChains) {
                  session.receiverChains = [];
                }

                for (let i = oldNr; i < counters.previousCounter; i++) {
                  const { chainKey: newChainKey, messageKey } =
                    CryptoUtils.kdfChainKey(currentChainKey);

                  // Store skipped key in receiverChains structure (v3 protobuf-compatible)
                  storeMessageKeyInChain(
                    session as DoubleRatchetState,
                    asBase64(oldDHr),
                    i,
                    messageKey,
                    undefined,
                    this.logger
                  );

                  CryptoUtils.secureZeroBytes(messageKey);
                  CryptoUtils.secureZeroBytes(currentChainKey);
                  currentChainKey = newChainKey;
                }

                CryptoUtils.secureZeroBytes(currentChainKey);

                // Store this chain as processed for replay detection
                // Initialize processedChains if not present
                if (!session.processedChains) {
                  session.processedChains = {};
                }
                session.processedChains[oldDHr] = {
                  lastNr: counters.previousCounter,
                  timestamp: Date.now(),
                };

                this.logger.debug('Stored processed chain for replay detection', {
                  category: 'E2EE',
                  data: {
                    operation: 'store-processed-chain',
                    oldDHrPreview: oldDHr.substring(0, 20),
                    lastNr: counters.previousCounter,
                  },
                });
              }

              // Step 4: perform the classical DH ratchet without touching SPQR.
              await performDHRatchetStep(session, ratchetKeyFromMessage, this.logger);

              this.logger.debug('DH ratchet completed', {
                category: 'E2EE',
                data: { operation: 'decrypt', newDHr: ratchetKeyFromMessage?.substring(0, 20) },
              });
            }

            // Self-sessions use the larger Note-to-Self skip limit.
            const maxSkippedMessages = getMaxSkipForSession(session, this.maxSkip);
            await storeSkippedMessageKeys(
              session,
              counters.counter,
              {
                ...DEFAULT_RATCHET_CONFIG,
                maxSkippedMessages,
              },
              this.logger
            );

            // Process SPQR after the DH ratchet. The SPQR boundary owns:
            // version negotiation, kyber key storage, decapsulation, epoch advancement, key derivation
            let spqrRecvResult: { messageKey: Uint8Array | null } | undefined;
            if (session.tripleRatchet?.enabled && session.tripleRatchet.spqrState) {
              spqrRecvResult = await spqrRecv(
                session.tripleRatchet.spqrState,
                receivedPqRatchetBytes,
                this.logger
              );
            }

            // Step 7: Derive message key using ratchet (Triple or Double)
            // Session was validated earlier (via storeSkippedMessageKeys) - pass directly
            let finalMessageKey: Uint8Array;
            let pqMessageKeySalt: Uint8Array | undefined;

            if (spqrRecvResult?.messageKey) {
              // Triple Ratchet: profile message key derivation (Section 6)
              this.logger.debug('Triple Ratchet: Deriving combined EC + PQ message key', {
                category: 'E2EE',
                data: {
                  operation: 'triple-ratchet-decrypt',
                  counter: counters.counter,
                },
              });

              // Step A: EC message key from Double Ratchet
              const ecResult = await moduleReceiveKey(session as DoubleRatchetState, this.logger);

              // Step B: Expand with EC input key + PQ optional salt
              finalMessageKey = ecResult.messageKey;
              pqMessageKeySalt = spqrRecvResult.messageKey;

              this.logger.breadcrumb('Triple Ratchet: Combined EC + PQ message keys', {
                category: 'E2EE',
                level: 'debug',
                data: {
                  operation: 'triple-ratchet-decrypt',
                  ecMessageNumber: session.Nr - 1,
                },
              });
            } else {
              this.logger.debug('Double Ratchet: Deriving EC message key', {
                category: 'E2EE',
                data: { operation: 'decrypt', counter: counters.counter },
              });

              // Pass session directly - mutations happen in place
              const doubleResult = await moduleReceiveKey(
                session as DoubleRatchetState,
                this.logger
              );
              finalMessageKey = doubleResult.messageKey;
            }

            // No applyRatchetState needed - mutations happened directly on session

            // Step 7: Decrypt message with MAC verification
            let plaintext: string;
            try {
              plaintext = await decryptWithKey(
                finalMessageKey,
                message as RatchetMessage,
                session,
                protobufMacContext,
                pqMessageKeySalt,
                this.logger
              );
            } finally {
              // Best-effort overwrite owned message-key bytes after use.
              CryptoUtils.secureZeroBytes(finalMessageKey);
              if (pqMessageKeySalt) {
                CryptoUtils.secureZeroBytes(pqMessageKeySalt);
                pqMessageKeySalt = undefined;
              }
            }

            session.lastUsedAt = Date.now();

            // H2: Authenticate before checking receiving trust. PreKey identity
            // persistence is deferred into the atomic responder commit below.
            const isTrustedReceivingIdentity = await this.keyStorage.isTrustedIdentity(
              remoteAddress,
              session.remoteIdentity,
              TrustDirection.RECEIVING,
              session.remoteIdentityType
            );
            if (!isTrustedReceivingIdentity) {
              throw new UntrustedIdentityError(remoteAddress, session.remoteIdentity);
            }

            // SESAME §3.4: Session Convergence - promote archived session to active if used
            // This ensures both parties converge to the same session for future messages
            let recordToStore: SessionRecord;
            if (usedArchivedCandidate && existingRecord) {
              const promotedRecord = SessionResolver.promoteSession(
                existingRecord,
                usedArchivedCandidate.baseKey
              );
              if (promotedRecord) {
                // Update the promoted session with latest state
                promotedRecord.currentSession = session;
                recordToStore = promotedRecord;
                this.logger.info(
                  'SESAME: Promoted archived session after successful decrypt (convergence)',
                  {
                    category: 'E2EE',
                    data: {
                      operation: 'session-convergence',
                      baseKey: usedArchivedCandidate.baseKey.substring(0, 20) + '...',
                    },
                  }
                );
              } else {
                // Fallback if promotion fails (shouldn't happen)
                recordToStore = { ...existingRecord, currentSession: session };
                this.logger.warn('SESAME: Failed to promote archived session, using as-is', {
                  category: 'E2EE',
                  data: { baseKey: usedArchivedCandidate.baseKey.substring(0, 20) + '...' },
                });
              }
            } else {
              // Use existingRecord if available to preserve archivedSessions (from auto-recovery)
              // Otherwise create fresh wrapper for new sessions
              recordToStore = existingRecord
                ? { ...existingRecord, currentSession: session }
                : this.wrapSession(session);
            }

            // H3: Mark session as acknowledged and clear unacknowledged PreKey items.
            // This prevents unacknowledged session timeout from blocking future sends.
            this.markSessionAcknowledged(session);

            const pendingDeletion = session.pendingPreKeyDeletion;
            if (isPreKeyMessage) {
              delete session.pendingPreKeyDeletion;
              await this.keyStorage.commitSessionTrust({
                address: remoteAddress,
                record: recordToStore,
                contactIdentity: session.remoteIdentity,
                contactIdentityType: session.remoteIdentityType,
                localIdentityType: pendingDeletion?.identityType ?? session.localIdentityType,
                oneTimePreKeyId: pendingDeletion?.oneTimePreKeyId,
                kemOneTimePreKeyId: pendingDeletion?.kemOneTimePreKeyId,
              });
            } else {
              await this.keyStorage.commitSessionTrust({
                address: remoteAddress,
                record: recordToStore,
                contactIdentity: session.remoteIdentity,
                contactIdentityType: session.remoteIdentityType,
                localIdentityType: session.localIdentityType,
              });
            }

            this.logger.debug('Session saved after message decryption', {
              category: 'E2EE',
              data: { operation: 'decrypt', Nr: session.Nr },
            });

            return plaintext;
          } catch (innerError) {
            // SECURITY: Never auto-recover from replay attacks (MESSAGE_DUPLICATE)
            // Replaying a PreKeyMessage could allow an attacker to bypass fingerprint checks
            // PREKEY_NOT_FOUND: Sender has stale bundle (e.g., Kyber prekey ID mismatch) - recovery via SESAME retry
            if (
              innerError instanceof EncryptionError &&
              (innerError.code === EncryptionErrorCode.MESSAGE_DUPLICATE ||
                innerError.code === EncryptionErrorCode.PREKEY_NOT_FOUND)
            ) {
              throw innerError;
            }

            // Auto-recovery: if PreKeyMessage fails on existing session, archive and retry once
            // This handles legitimate cases like key rotation or device reset, NOT replays
            if (
              isPreKeyMessage &&
              hadExistingSession &&
              !preKeyMatchedExistingSession &&
              !retriedAfterArchive
            ) {
              retriedAfterArchive = true;
              this.logger.warn(
                'PreKeyMessage decryption failed on existing session - will archive and retry',
                {
                  category: 'E2EE',
                  data: {
                    error: innerError instanceof Error ? innerError.message : String(innerError),
                    remoteAddress: ProtocolAddress.toString(remoteAddress),
                  },
                }
              );
              continue; // Try again with archived session
            }

            // SESAME §3.2: For RatchetMessages, try next archived session candidate
            // This supports decryption of delayed messages that were encrypted with a now-archived session
            if (!isPreKeyMessage && currentCandidateIndex < sessionCandidates.length) {
              const nextCandidate = sessionCandidates[currentCandidateIndex++];
              session = cloneSessionStateForDecryptAttempt(nextCandidate.session);
              usedArchivedCandidate =
                !nextCandidate.isActive && nextCandidate.baseKey
                  ? { baseKey: nextCandidate.baseKey }
                  : null;

              this.logger.debug('Trying next archived session candidate after decryption failure', {
                category: 'E2EE',
                data: {
                  operation: 'decrypt-retry',
                  candidateIndex: currentCandidateIndex - 1,
                  totalCandidates: sessionCandidates.length,
                  isActive: nextCandidate.isActive,
                  error: innerError instanceof Error ? innerError.message : String(innerError),
                },
              });

              // Retry decryption with the newly assigned archived session candidate
              // Note: existingRecord is preserved to maintain archivedSessions
              continue;
            }

            throw innerError; // Re-throw if not recoverable
          }
        } // End of retry loop

        // Should never reach here - loop always returns or throws
        throw new EncryptionError(
          'Unexpected end of decrypt retry loop',
          EncryptionErrorCode.DECRYPTION_FAILED
        );
      } catch (error) {
        // Enhance MESSAGE_DUPLICATE errors with address context for better debugging
        if (
          error instanceof EncryptionError &&
          error.code === EncryptionErrorCode.MESSAGE_DUPLICATE
        ) {
          throw new DuplicatedMessageError(remoteAddress, {
            counter: error.context?.counter as number | undefined,
            epoch: error.context?.epoch as number | undefined,
          });
        }

        // L7: Comprehensive decryption failure diagnostics
        // Log error details for debugging (variables in this outer scope only)
        this.logger.error('Decryption failed - diagnostic summary', {
          category: 'E2EE',
          data: {
            operation: 'decrypt-failed',
            remoteAddress: ProtocolAddress.toString(remoteAddress),
            errorCode: error instanceof EncryptionError ? error.code : 'UNKNOWN',
            errorMessage: error instanceof Error ? error.message : String(error),
            // Include context from inner EncryptionError if available
            errorContext: error instanceof EncryptionError ? error.context : undefined,
          },
        });

        // Preserve other specific EncryptionError codes
        if (error instanceof EncryptionError) {
          throw error;
        }
        throw new EncryptionError(
          'Failed to decrypt message',
          EncryptionErrorCode.DECRYPTION_FAILED,
          { originalError: error as Error }
        );
      }
    });
  }
}
