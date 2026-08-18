/**
 * SESAME (Secure Encrypted Stored Authenticated Messaging Extension)
 *
 * Signal Protocol Section 7 - SESAME
 * Multi-device session management for encrypted asynchronous messaging.
 *
 * Key Features:
 * - Generic support for SESAME's per-user and per-device identity-key models.
 *   The client provisions one composite tuple per user and identity type
 * - Session convergence through receive-activated switching
 * - 3-phase message sending process
 * - Automatic session expiration and cleanup
 * - Retry request mechanism for failed decryption
 * - Stale record cleanup to prevent storage growth
 *
 * @see https://signal.org/docs/specifications/sesame/
 */

import { defaultSignalProtocolLogger, type ILogger } from '../../logger';
import { getErrorMessage } from '../../utils/errors';
import {
  ISesameManager,
  ISesameStorage,
  UserID,
  DeviceID,
  SessionID,
  UserRecord,
  DeviceRecord,
  SesameMessage,
  RetryRequest,
  RetryReason,
  SesameConfig,
  SesameStats,
  DEFAULT_SESAME_CONFIG,
  SesameError,
  SesameDeviceNotFoundError,
  NoActiveSessionError,
  DecryptionFailedError,
  StaleDeviceListError,
  DeviceListResponse,
  RetryResult,
  RetryHandlingOptions,
  MIN_DEVICE_ID,
  MAX_DEVICE_ID,
  // Session record helpers
  updateSessionRecordAfterSend,
  updateSessionRecordAfterReceive,
  // Event system
  SesameEvents,
  // Batch message types
  OutgoingMessageBatch,
  // Send options
  SesameSendOptions,
} from './types';
import type { IMessageRecordStore } from '../../local/store';
import { validateSesameConfig } from './validation';
import type { SessionState, SessionRecord } from '../../types/session';
import { ProtocolAddress } from '../../types/address';
import { base64ToBytes, bytesToBase64 } from '../crypto/utils';
import { type Base64 } from '../../types/utils';
import { deserializePublicKey } from '../crypto/key-prefix';
import {
  parsePreKeySignalProtocolMessageEnvelope,
  decodePreKeySignalProtocolMessage,
  parseSignalProtocolMessageEnvelope,
  decodeSignalProtocolMessage,
} from '../encoding/proto';
import { SessionResolver } from '../session/session-resolver';
import type { Ciphertext } from '../../keys';
import { EncryptionError } from '../../types/errors';
import {
  canonicalizeDeviceIdentityKey,
  compareDeviceIdentityKeys,
  decodeCompositeIdentityV1,
  encodeCompositeIdentityV1,
  UNPINNED_DEVICE_IDENTITY_KEY,
} from '../../keys/identity';

/**
 * Maximum number of retry attempts for the SESAME sending loop.
 *
 * Per SESAME spec §3.3 and §6.5:
 *
 * > "To avoid excessive looping in case of a malicious or buggy server,
 * > devices should impose some limit on the number of times they are willing
 * > to repeat the message sending loop for a recipient user."
 */
export {};
export const MAX_SEND_RETRIES = 3;

/**
 * Detect if a ciphertext is a PreKeyMessage (initiating message)
 *
 * PreKeyMessages are sent to establish new sessions and contain
 * the sender's identity key and prekey information.
 *
 * @param ciphertext - The encrypted message content
 * @returns true if this is a PreKeyMessage (initiating), false otherwise
 */
function isPreKeyMessage(ciphertext: string): boolean {
  // Binary protobuf format: base64 decode, check version byte + first protobuf tag
  try {
    const bytes = base64ToBytes(ciphertext as Base64);
    if (bytes.length < 2) return false;

    // Check for valid version byte (high nibble should be protocol version)
    const version = bytes[0]! >> 4;
    if (version < 2 || version > 15) return false;

    // Detect message type from first protobuf tag:
    // - PreKeySignalProtocolMessage wire field 1 (uint32, oneTimePreKeyId/ecOneTimePreKeyId) → wire type 0 → tag 0x08
    // - PreKeySignalProtocolMessage wire field 2 (bytes, baseKey) → wire type 2 → tag 0x12
    // - SignalProtocolMessage wire field 1 (bytes, ratchetKey) → wire type 2 → tag 0x0A
    const firstTag = bytes[1];
    return firstTag === 0x08 || firstTag === 0x12;
  } catch {
    return false;
  }
}

/**
 * Result of PreKeyMessage handling with pending records.
 *
 * TRANSACTIONAL DESIGN: Records are NOT persisted by handlePreKeyMessage.
 * Caller must persist after confirming decryption succeeded.
 * This prevents session state corruption if decryption fails.
 */
interface PreKeyMessageResult {
  /** Decrypted plaintext */
  plaintext: Uint8Array;
  /** DeviceRecord to persist (not yet stored) */
  pendingDeviceRecord: DeviceRecord;
  /** UserRecord to persist if new sender (not yet stored) */
  pendingUserRecord?: UserRecord;
}

/**
 * Protocol manager interface for encryption/decryption
 * Uses ProtocolAddress for type-safe session identification
 */
export interface IProtocolManager {
  encrypt(remoteAddress: ProtocolAddress, plaintext: string): Promise<Ciphertext>;
  decrypt(remoteAddress: ProtocolAddress, ciphertext: Ciphertext): Promise<string>;
  /**
   * Get the session record for a remote address.
   * Used by SESAME to sync sessions after PreKeyMessage decryption.
   * @param remoteAddress - The remote protocol address
   * @returns The session record, or null if no session exists
   */
  getSession(remoteAddress: ProtocolAddress): Promise<SessionRecord | null>;
}

/**
 * SESAME Manager implementation
 *
 * Manages multi-device sessions following the Signal Protocol SESAME specification.
 *
 * Supports event callbacks for observability via the SesameEvents interface.
 */
export class SesameManager implements ISesameManager {
  private storage: ISesameStorage;
  private config: SesameConfig;
  private localUserId: UserID | null = null;
  private localDeviceId: DeviceID | null = null;
  private protocol: IProtocolManager | null = null;
  private readonly logger: Required<ILogger>;

  /**
   * Optional MessageRecord store for SESAME retry request support.
   * When set, sent messages are stored so they can be resent on retry request.
   * Per SESAME Specification Section 6.2.
   */
  private messageRecordStore: IMessageRecordStore | null = null;

  /**
   * O(1) session lookup index: sessionId -> { userId, deviceId }
   *
   * Maps sessionId (from ProtocolAddress.toString() of the session's remoteAddress)
   * to the userId and deviceId of the DeviceRecord containing that session.
   * Maintained during registerSession(), setSession(), removeDevice(),
   * and related methods to avoid O(n*m) scans in findSession().
   */
  private sessionIndex = new Map<string, { userId: string; deviceId: number }>();

  /**
   * Event callbacks for session lifecycle events.
   * Set via setEvents() or constructor options.
   */
  private events: SesameEvents = {};

  constructor(
    storage: ISesameStorage,
    config?: Partial<SesameConfig>,
    protocol?: IProtocolManager,
    events?: SesameEvents,
    logger: Required<ILogger> = defaultSignalProtocolLogger
  ) {
    this.logger = logger;
    // Validate configuration per SESAME specification
    const validation = validateSesameConfig(config);
    if (!validation.valid) {
      const errorMsg = `Invalid SESAME configuration: ${validation.errors.join('; ')}`;
      this.logger.error(errorMsg, {
        category: 'SESAME',
        data: { errors: validation.errors },
      });
      throw new SesameError(errorMsg, 'INVALID_CONFIG');
    }

    // Log warnings but allow configuration
    if (validation.warnings.length > 0) {
      this.logger.warn('SESAME configuration warnings', {
        category: 'SESAME',
        data: { warnings: validation.warnings },
      });
    }

    this.storage = storage;
    this.config = { ...DEFAULT_SESAME_CONFIG, ...config };
    this.protocol = protocol || null;
    this.events = events || {};
  }

  /**
   * Set the Signal Protocol manager for encryption/decryption
   * This must be called before using send/receive
   */
  setProtocolManager(protocol: IProtocolManager): void {
    this.protocol = protocol;
  }

  /**
   * Set the MessageRecord store for retry request support.
   * Per SESAME Specification Section 6.2 - "Each MessageRecord stores
   * the plaintext of the encrypted message."
   *
   * When set, sent messages are stored so they can be resent on retry request.
   */
  setMessageRecordStore(store: IMessageRecordStore): void {
    this.messageRecordStore = store;
  }

  /**
   * Set event callbacks for session lifecycle events.
   *
   * @param events - Event callbacks to set
   */
  setEvents(events: SesameEvents): void {
    this.events = events;
  }

  /**
   * Get current event callbacks
   */
  getEvents(): SesameEvents {
    return this.events;
  }

  /**
   * Initialize SESAME manager with local device information
   */
  async initialize(localUserId: UserID, localDeviceId: DeviceID): Promise<void> {
    this.localUserId = localUserId;
    this.localDeviceId = localDeviceId;

    this.logger.debug('SESAME: Initialized', {
      category: 'E2EE',
      data: {
        operation: 'sesame-init',
        userId: localUserId,
        deviceId: localDeviceId,
      },
    });
  }

  /**
   * Add a device for a user with its identity key
   *
   * @throws {SesameError} if deviceId is outside valid range (1-5)
   */
  async addDevice(
    userId: UserID,
    deviceId: DeviceID,
    identityKey: Uint8Array,
    _prekeyBundle?: unknown
  ): Promise<void> {
    // Validate device ID range (Signal Protocol limits to 1-5 devices per user)
    if (deviceId < MIN_DEVICE_ID || deviceId > MAX_DEVICE_ID) {
      throw new SesameError(
        `Device ID must be between ${MIN_DEVICE_ID} and ${MAX_DEVICE_ID}, got ${deviceId}`,
        'INVALID_DEVICE_ID'
      );
    }

    this.logger.debug('SESAME: Adding device', {
      category: 'E2EE',
      data: {
        operation: 'sesame-add-device',
        userId,
        deviceId,
      },
    });

    // Get or create user record
    let userRecord = await this.storage.getUserRecord(userId);

    if (!userRecord) {
      userRecord = {
        userId,
        devices: new Map(),
        createdAt: Date.now(),
        updatedAt: Date.now(),
      };
    }

    // Create device record. Identity bytes are canonicalized here so that a
    // single encoding reaches storage regardless of which caller supplied them.
    const deviceRecord: DeviceRecord = {
      userId,
      deviceId,
      identityKey: canonicalizeDeviceIdentityKey(
        identityKey,
        `Identity key for ${userId}:${deviceId}`
      ),
      session: null, // SessionRecord, not SesameSessionRecord
      createdAt: Date.now(),
      updatedAt: Date.now(),
    };

    // Add device to user record
    userRecord.devices.set(deviceId, deviceRecord);
    userRecord.updatedAt = Date.now();

    // Save device record
    await this.storage.setDeviceRecord(userId, deviceId, deviceRecord);

    // Save user record
    await this.storage.setUserRecord(userId, userRecord);

    // Emit device added event
    this.events.onDeviceAdded?.(userId, deviceId);
  }

  /**
   * Remove a device from a user
   */
  async removeDevice(userId: UserID, deviceId: DeviceID): Promise<void> {
    this.logger.debug('SESAME: Removing device', {
      category: 'E2EE',
      data: {
        operation: 'sesame-remove-device',
        userId,
        deviceId,
      },
    });

    const userRecord = await this.storage.getUserRecord(userId);
    if (!userRecord) return;

    // Remove session index entries for this device
    this.removeDeviceFromSessionIndex(userId, deviceId);

    // Remove device
    userRecord.devices.delete(deviceId);
    userRecord.updatedAt = Date.now();

    // Delete device record from storage
    await this.storage.deleteDeviceRecord(userId, deviceId);

    // Update user record (or clean up if empty)
    if (userRecord.devices.size > 0) {
      await this.storage.setUserRecord(userId, userRecord);
    }

    // Emit device removed event
    this.events.onDeviceRemoved?.(userId, deviceId);
  }

  /**
   * Clear pending verification flag for a device after user verifies safety numbers.
   * This unblocks messaging to the device.
   */
  async clearPendingVerification(userId: UserID, deviceId: DeviceID): Promise<void> {
    const record = await this.storage.getDeviceRecord(userId, deviceId);
    if (record && record.pendingVerification) {
      record.pendingVerification = false;
      await this.storage.setDeviceRecord(userId, deviceId, record);
      this.logger.info('SESAME: Cleared pending verification', {
        category: 'E2EE',
        data: {
          operation: 'sesame-clear-verification',
          userId,
          deviceId,
        },
      });
    }
  }

  /**
   * Get device record for a specific user and device
   */
  async getDeviceRecord(userId: UserID, deviceId: DeviceID): Promise<DeviceRecord | null> {
    return await this.storage.getDeviceRecord(userId, deviceId);
  }

  /**
   * Get user record with all devices
   */
  async getUserRecord(userId: UserID): Promise<UserRecord | null> {
    return await this.storage.getUserRecord(userId);
  }

  /**
   * Get the full session record for a device.
   * Returns the SessionRecord which includes currentSession and archivedSessions.
   */
  async getSession(userId: UserID, deviceId: DeviceID): Promise<SessionRecord | null> {
    const deviceRecord = await this.storage.getDeviceRecord(userId, deviceId);
    return deviceRecord?.session ?? null;
  }

  /**
   * Get the active session state for a device.
   * Returns SessionRecord.currentSession.
   */
  async getActiveSession(userId: UserID, deviceId: DeviceID): Promise<SessionState | null> {
    const sessionRecord = await this.getSession(userId, deviceId);
    return sessionRecord?.currentSession ?? null;
  }

  /**
   * Set the session record for a device (internal helper).
   * Uses SessionRecord.archiveCurrent() to move the previous active session to archived.
   */
  async setSession(
    userId: UserID,
    deviceId: DeviceID,
    sessionRecord: SessionRecord
  ): Promise<void> {
    const deviceRecord = await this.storage.getDeviceRecord(userId, deviceId);
    if (!deviceRecord) {
      throw new SesameDeviceNotFoundError(`Device not found: ${userId}/${deviceId}`);
    }

    // Clear old index entries and add new ones
    this.removeDeviceFromSessionIndex(userId, deviceId);
    this.indexSessionRecord(userId, deviceId, sessionRecord);

    // Update device record with new session
    deviceRecord.session = sessionRecord;
    deviceRecord.updatedAt = Date.now();
    await this.storage.setDeviceRecord(userId, deviceId, deviceRecord);

    const sessionId = sessionRecord.currentSession?.remoteAddress
      ? ProtocolAddress.toString(sessionRecord.currentSession.remoteAddress)
      : 'none';

    this.logger.debug('SESAME: Session updated', {
      category: 'E2EE',
      data: {
        operation: 'sesame-set-session',
        userId,
        deviceId,
        sessionId,
        archivedCount: Object.keys(sessionRecord.archivedSessions).length,
      },
    });
  }

  /**
   * Register a newly established Double Ratchet session with SESAME.
   *
   * Creates a SessionRecord with SESAME metadata and sets it as the device's session.
   * Any existing session is archived in SessionRecord.archivedSessions.
   *
   * This bridges the Double Ratchet layer with the SESAME multi-device layer,
   * so sessions established via SignalProtocolClient.establishSession() are
   * automatically tracked for multi-device messaging.
   *
   * @param userId - Remote user's ID
   * @param deviceId - Remote device's ID
   * @param sessionState - The Double Ratchet session state
   * @param isInitiator - Whether we initiated the session (true) or responded (false)
   */
  async registerSession(
    userId: UserID,
    deviceId: DeviceID,
    sessionState: SessionState,
    isInitiator: boolean
  ): Promise<void> {
    const address = ProtocolAddress.create(userId, deviceId);
    const sessionId = ProtocolAddress.toString(address);

    // Create the device record if it is missing
    let deviceRecord = await this.storage.getDeviceRecord(userId, deviceId);
    if (!deviceRecord) {
      // Auto-create device record if it does not exist. Pin the peer identity the
      // session was actually negotiated against. A placeholder here would later
      // compare unequal to that same identity and forge an identity-change event.
      await this.addDevice(
        userId,
        deviceId,
        sessionState.remoteIdentity
          ? encodeCompositeIdentityV1(sessionState.remoteIdentity)
          : UNPINNED_DEVICE_IDENTITY_KEY
      );
      deviceRecord = await this.storage.getDeviceRecord(userId, deviceId);
    }

    // Create or update session record using SessionResolver
    const sessionRecord = SessionResolver.insertSession(
      deviceRecord?.session ?? null,
      sessionState,
      isInitiator,
      this.config.maxInactiveSessions
    );

    // Set the session record
    await this.setSession(userId, deviceId, sessionRecord);

    this.logger.debug('SESAME: Session registered', {
      category: 'E2EE',
      data: {
        operation: 'sesame-register-session',
        userId,
        deviceId,
        sessionId,
        isInitiator,
      },
    });

    // Emit session established event (reuse address from above)
    this.events.onSessionEstablished?.(address);
  }

  /**
   * Send a message to a specific device
   * Implements SESAME 3-phase sending process
   *
   * SESAME 3-Phase Sending (from specification):
   * - Phase 1: Identify devices with non-stale active sessions
   * - Phase 2: Encrypt message for each device using Double Ratchet
   * - Phase 3: Validate device list is current before sending
   */
  async sendMessage(
    recipientUserId: UserID,
    recipientDeviceId: DeviceID,
    plaintext: Uint8Array,
    options?: SesameSendOptions
  ): Promise<SesameMessage> {
    if (!this.localUserId || !this.localDeviceId) {
      throw new SesameError('SesameManager not initialized', 'NOT_INITIALIZED');
    }

    if (!this.protocol) {
      throw new SesameError(
        'Signal Protocol manager not set. Call setProtocolManager() first.',
        'PROTOCOL_NOT_SET'
      );
    }

    // Check if device requires identity verification before messaging
    const deviceRecord = await this.getDeviceRecord(recipientUserId, recipientDeviceId);
    if (deviceRecord?.pendingVerification) {
      throw new SesameError(
        `Cannot send to ${recipientUserId}:${recipientDeviceId} - identity key changed, verification required`,
        'IDENTITY_KEY_PENDING_VERIFICATION'
      );
    }

    this.logger.debug('SESAME: Sending message', {
      category: 'E2EE',
      data: {
        operation: 'sesame-send',
        recipientUserId,
        recipientDeviceId,
      },
    });

    // Phase 1: Check session state and get/create session
    const activeSession = await this.getActiveSession(recipientUserId, recipientDeviceId);

    // If no active session exists, we need to establish one
    if (!activeSession) {
      throw new NoActiveSessionError(recipientUserId, recipientDeviceId);
    }

    // Check if session is too old to send on
    const sessionId = ProtocolAddress.toString(activeSession.remoteAddress);
    const canSend = await this.canSendOnSession(sessionId);
    if (!canSend) {
      throw new SesameError(
        `Session ${sessionId} is too old to send (age > MAXSEND)`,
        'SESSION_TOO_OLD'
      );
    }

    // Phase 2: Encrypt message using Double Ratchet
    const recipientAddress = ProtocolAddress.create(recipientUserId, recipientDeviceId);

    try {
      // Encrypt the plaintext using the Signal Protocol
      const plaintextString = new TextDecoder().decode(plaintext);
      const ciphertext = await this.protocol.encrypt(recipientAddress, plaintextString);

      // Phase 3: Validate device list version (SESAME spec §3.3)
      // MUST happen BEFORE persisting session metadata.
      // Per §3.3: "If any error occurs in encrypting to a particular user,
      // then the sending device shall discard any changes to the relevant UserRecord."
      const localDeviceListVersion = options?.localDeviceListVersion;
      if (localDeviceListVersion !== undefined) {
        const userRecord = await this.getUserRecord(recipientUserId);
        const serverVersion = userRecord?.deviceListVersion ?? 0;
        if (localDeviceListVersion < serverVersion) {
          throw new StaleDeviceListError(recipientUserId, localDeviceListVersion, serverVersion);
        }
      }

      // Update session lastSentAt timestamp via SessionRecord
      // Placed AFTER Phase 3 validation so metadata is not persisted if validation fails
      const deviceRecord = await this.getDeviceRecord(recipientUserId, recipientDeviceId);
      if (deviceRecord?.session) {
        const updatedSession = updateSessionRecordAfterSend(deviceRecord.session);
        deviceRecord.session = updatedSession;
        deviceRecord.updatedAt = Date.now();
        await this.storage.setDeviceRecord(recipientUserId, recipientDeviceId, deviceRecord);
      }

      // Convert Ciphertext to Uint8Array for SesameMessage
      const ciphertextBytes = this.serializeCiphertext(ciphertext);

      // Client timestamp for envelope alignment (application send-pipeline ordering)
      // Threaded explicitly via SesameSendOptions. No plaintext parsing needed
      const clientTimestamp = options?.clientTimestamp ?? Date.now();

      // Store MessageRecord for retry request support (SESAME spec §6.2)
      // "Each MessageRecord stores the plaintext of the encrypted message"
      if (this.messageRecordStore) {
        try {
          await this.messageRecordStore.storeMessageRecord({
            sessionId,
            timestamp: clientTimestamp,
            recipientUserId,
            recipientDeviceId,
            plaintext: plaintextString,
            createdAt: clientTimestamp,
            // store sender's
            // current ratchet key (DHs) for retry session matching. Detects intra-session
            // ratchet advancement, not just cross-session changes.
            sessionStateId: (activeSession.DHs?.publicKey as string) ?? '',
          });
        } catch (storeError) {
          // CRITICAL: If this fails, retry requests will not work after reinstall
          // Upgraded from warn to error to track failures in Sentry
          this.logger.error('SESAME: Failed to store MessageRecord - retry flow may fail', {
            category: 'E2EE',
            data: {
              sessionId,
              timestamp: clientTimestamp,
              recipientUserId,
              recipientDeviceId,
              error: getErrorMessage(storeError),
              errorStack:
                storeError instanceof Error ? storeError.stack?.substring(0, 500) : undefined,
            },
          });
        }
      }

      this.logger.debug('SESAME: Message encrypted', {
        category: 'E2EE',
        data: {
          operation: 'sesame-send',
          recipientUserId,
          recipientDeviceId,
          sessionId,
          timestamp: clientTimestamp,
        },
      });

      // Return SESAME message
      // Note: Message ordering is handled by Double Ratchet's N/PN counters (spec Section 2.6)
      return {
        senderUserId: this.localUserId,
        senderDeviceId: this.localDeviceId,
        recipientUserId,
        recipientDeviceId,
        sessionId,
        ciphertext: ciphertextBytes,
        isInitiating: isPreKeyMessage(ciphertext),
        initHeader: null,
        // Client timestamp for message identification
        // Same value stored in MessageRecord for retry request matching
        timestamp: clientTimestamp,
      };
    } catch (error) {
      // Re-throw SesameError subclasses (StaleDeviceListError, etc.) without wrapping
      // so callers can distinguish Phase 3 validation failures from encryption errors
      if (error instanceof SesameError) {
        throw error;
      }
      throw new SesameError(
        `Failed to encrypt message: ${getErrorMessage(error)}`,
        'ENCRYPTION_FAILED'
      );
    }
  }

  /**
   * Serialize a Ciphertext object to Uint8Array
   */
  private serializeCiphertext(ciphertext: Ciphertext): Uint8Array {
    // Ciphertext is a branded base64 string, encode it directly
    return new TextEncoder().encode(ciphertext);
  }

  /**
   * Deserialize Uint8Array back to Ciphertext object
   */
  private deserializeCiphertext(bytes: Uint8Array): Ciphertext {
    const text = new TextDecoder().decode(bytes);
    return text as Ciphertext;
  }

  /**
   * Send an encrypted message to all devices of a user.
   *
   * Implements the 3-phase sending process from SESAME spec:
   * - Phase 1: Identify devices with non-stale active sessions
   * - Phase 2: Encrypt message for each device using Double Ratchet
   * - Phase 3: Validate device list is current before sending
   *
   * Returns an OutgoingMessageBatch that separates:
   * - deviceMessages: Messages for recipient's devices
   * - syncMessages: Messages for our own other devices (multi-device sync)
   *
   * Per SESAME spec §3.3: if Phase 3 device list validation fails with
   * StaleDeviceListError, the device list is refetched and the send is
   * retried. Retries are bounded by MAX_SEND_RETRIES. The UserRecord is
   * marked stale per §3.3 to trigger a fresh fetch on next access.
   *
   * @param recipientUserId - Target user ID
   * @param plaintext - Message to encrypt
   * @param options - Optional SESAME send controls, including stale-device-list retry hooks
   * @returns OutgoingMessageBatch with separated device and sync messages
   *
   * @see https://signal.org/docs/specifications/sesame/
   */
  async send(
    recipientUserId: UserID,
    plaintext: Uint8Array,
    options?: SesameSendOptions
  ): Promise<OutgoingMessageBatch> {
    if (!this.localUserId || !this.localDeviceId) {
      throw new SesameError('SesameManager not initialized', 'NOT_INITIALIZED');
    }

    if (!this.protocol) {
      throw new SesameError(
        'Signal Protocol manager not set. Call setProtocolManager() first.',
        'PROTOCOL_NOT_SET'
      );
    }

    // M14: Retry loop for stale device list (SESAME spec §3.3 step 8 + §6.5)
    //
    // > "To avoid excessive looping in case of a malicious or buggy server,
    // > devices should impose some limit on the number of times they are
    // > willing to repeat the message sending loop for a recipient user."
    let currentDeviceListVersion = options?.localDeviceListVersion;
    const fetchDeviceList = options?.fetchDeviceList;

    for (let attempt = 0; attempt < MAX_SEND_RETRIES; attempt++) {
      try {
        return await this.sendAttempt(recipientUserId, plaintext, {
          ...options,
          localDeviceListVersion: currentDeviceListVersion,
        });
      } catch (error) {
        // M18: Re-throw StaleDeviceListError specifically for retry logic
        // M15: Mark the UserRecord as stale when StaleDeviceListError occurs
        if (error instanceof StaleDeviceListError) {
          // Mark the UserRecord as stale per SESAME spec §3.3
          await this.markUserRecordStale(recipientUserId);

          // If this is the last attempt, throw the error
          if (attempt >= MAX_SEND_RETRIES - 1) {
            this.logger.error('SESAME: Max send retries exceeded for stale device list', {
              category: 'E2EE',
              data: {
                operation: 'sesame-send-retry',
                recipientUserId,
                attempts: attempt + 1,
                maxRetries: MAX_SEND_RETRIES,
              },
            });
            throw error;
          }

          // M14: Refetch device list and retry
          if (fetchDeviceList) {
            try {
              const freshDeviceList = await fetchDeviceList(recipientUserId);
              await this.syncDeviceList(freshDeviceList);
              currentDeviceListVersion = freshDeviceList.version;

              this.logger.info('SESAME: Retrying send after device list refresh', {
                category: 'E2EE',
                data: {
                  operation: 'sesame-send-retry',
                  recipientUserId,
                  attempt: attempt + 1,
                  newVersion: freshDeviceList.version,
                },
              });
              continue; // Retry with fresh device list
            } catch (fetchError) {
              this.logger.error('SESAME: Failed to refetch device list during retry', {
                category: 'E2EE',
                data: {
                  operation: 'sesame-send-retry',
                  recipientUserId,
                  error: getErrorMessage(fetchError),
                },
              });
              throw error; // Re-throw the original StaleDeviceListError
            }
          } else {
            // No fetchDeviceList callback provided - throw immediately
            // Caller is responsible for handling the stale device list
            throw error;
          }
        }

        // Non-StaleDeviceListError: throw immediately without retry
        throw error;
      }
    }

    // This should be unreachable due to the loop structure, but TypeScript requires it
    throw new SesameError('Send retry loop exhausted', 'SEND_RETRY_EXHAUSTED');
  }

  async sendToLocalOtherDevices(
    plaintext: Uint8Array,
    options?: SesameSendOptions
  ): Promise<SesameMessage[]> {
    if (!this.localUserId || !this.localDeviceId) {
      throw new SesameError('SesameManager not initialized', 'NOT_INITIALIZED');
    }

    const localUserRecord = await this.getUserRecord(this.localUserId);
    if (!localUserRecord) {
      return [];
    }

    const syncMessages: SesameMessage[] = [];
    for (const [deviceId, deviceRecord] of localUserRecord.devices.entries()) {
      if (deviceId === this.localDeviceId) continue;

      try {
        const activeSession = deviceRecord.session?.currentSession;
        if (!activeSession) continue;

        const sessionId = ProtocolAddress.toString(activeSession.remoteAddress);
        const canSend = await this.canSendOnSession(sessionId);
        if (!canSend) continue;

        const syncMessage = await this.sendMessage(this.localUserId, deviceId, plaintext, options);
        syncMessages.push(syncMessage);
      } catch {
        this.logger.debug('SESAME: Sync message failed for device', {
          category: 'E2EE',
          data: {
            operation: 'sesame-send-sync',
            deviceId,
          },
        });
      }
    }

    return syncMessages;
  }

  /**
   * Single attempt to send an encrypted message to all devices of a user.
   * Extracted from send() to support the retry loop for stale device lists.
   *
   * @param recipientUserId - Target user ID
   * @param plaintext - Message to encrypt
   * @param options - Optional SESAME send controls for a single send attempt
   * @returns OutgoingMessageBatch with separated device and sync messages
   */
  private async sendAttempt(
    recipientUserId: UserID,
    plaintext: Uint8Array,
    options?: SesameSendOptions
  ): Promise<OutgoingMessageBatch> {
    const includeSyncMessages = options?.includeSyncMessages ?? true;
    // M15: Check if UserRecord is marked stale and clear it for this attempt.
    // Per SESAME spec §3.3: stale records trigger a fresh device list fetch.
    const userRecord = await this.getUserRecord(recipientUserId);
    if (!userRecord) {
      throw new SesameError(`No user record found for ${recipientUserId}`, 'USER_NOT_FOUND');
    }

    if (userRecord.stale) {
      // Clear stale flag since we are about to use this record
      // (caller should have refreshed the device list before retrying)
      userRecord.stale = false;
      userRecord.updatedAt = Date.now();
      await this.storage.setUserRecord(recipientUserId, userRecord);
    }

    if (userRecord.devices.size === 0) {
      throw new SesameError(`User ${recipientUserId} has no devices`, 'NO_DEVICES');
    }

    const timestamp = Date.now();
    const deviceMessages: SesameMessage[] = [];
    const syncMessages: SesameMessage[] = [];
    const failures: Array<{ deviceId: DeviceID; error: Error }> = [];
    let attemptedDevices = 0;

    this.logger.debug('SESAME: Sending to all devices', {
      category: 'E2EE',
      data: {
        operation: 'sesame-send-user',
        recipientUserId,
        deviceCount: userRecord.devices.size,
        includeSyncMessages,
      },
    });

    // Phase 1 & 2: Encrypt message for each recipient device
    for (const [deviceId, deviceRecord] of userRecord.devices.entries()) {
      attemptedDevices++;
      try {
        // Check if device has an active session
        const activeSession = deviceRecord.session?.currentSession;
        if (!activeSession) {
          failures.push({
            deviceId,
            error: new NoActiveSessionError(recipientUserId, deviceId),
          });
          continue;
        }

        // Check if session is too old
        const sessionId = ProtocolAddress.toString(activeSession.remoteAddress);
        const canSend = await this.canSendOnSession(sessionId);
        if (!canSend) {
          failures.push({
            deviceId,
            error: new SesameError(
              `Session for device ${deviceId} is too old (age > MAXSEND)`,
              'SESSION_TOO_OLD'
            ),
          });
          continue;
        }

        // Encrypt message for this device (Phase 3 validation happens inside)
        const message = await this.sendMessage(recipientUserId, deviceId, plaintext, options);
        deviceMessages.push(message);
      } catch (error) {
        // M18: Re-throw StaleDeviceListError without wrapping so the retry
        // loop in send() can catch it and refetch the device list.
        //
        // Per SESAME spec §3.3:
        //
        // > "If any error occurs in encrypting to a particular user, then the
        // > sending device shall discard any changes to the relevant
        // > UserRecord."
        if (error instanceof StaleDeviceListError) {
          throw error;
        }
        failures.push({
          deviceId,
          error: error instanceof Error ? error : new Error('Unknown error'),
        });
      }
    }

    // If all recipient devices failed, throw error
    if (deviceMessages.length === 0 && failures.length > 0) {
      throw new SesameError(
        `Failed to send message to all ${failures.length} devices: ${failures.map((f) => `${f.deviceId}: ${f.error.message}`).join(', ')}`,
        'ALL_DEVICES_FAILED'
      );
    }

    // Encrypt sync messages for our own other devices (multi-device sync)
    if (includeSyncMessages) {
      if (this.localUserId) {
        const localUserRecord = await this.getUserRecord(this.localUserId);
        if (localUserRecord) {
          attemptedDevices += Array.from(localUserRecord.devices.keys()).filter(
            (deviceId) => deviceId !== this.localDeviceId
          ).length;
        }
      }
      const syncPayload = options?.syncPlaintext ?? plaintext;
      const localSyncMessages = await this.sendToLocalOtherDevices(syncPayload, options);
      syncMessages.push(...localSyncMessages);
    }

    // Log partial failures
    if (failures.length > 0) {
      this.logger.warn('SESAME: Partial send failure', {
        category: 'E2EE',
        data: {
          operation: 'sesame-send-user',
          recipientUserId,
          successCount: deviceMessages.length,
          failureCount: failures.length,
          failedDevices: failures.map((f) => f.deviceId),
        },
      });
    }

    return {
      deviceMessages,
      syncMessages,
      recipientUserId,
      timestamp,
      attemptedDevices,
      failedDevices: failures.length,
    };
  }

  /**
   * Receive and decrypt a message
   * Implements session convergence through receive-activated switching
   *
   * SESAME Session Convergence (from specification):
   * - Try to decrypt with active session first
   * - If that fails, try inactive sessions
   * - If decryption succeeds on inactive session, activate it
   * - This allows devices to automatically converge on matching session pairs
   *
   * @see https://signal.org/docs/specifications/sesame/
   */
  async receive(message: SesameMessage): Promise<Uint8Array> {
    if (!this.localUserId || !this.localDeviceId) {
      throw new SesameError('SesameManager not initialized', 'NOT_INITIALIZED');
    }

    if (!this.protocol) {
      throw new SesameError(
        'Signal Protocol manager not set. Call setProtocolManager() first.',
        'PROTOCOL_NOT_SET'
      );
    }

    // 1. Validate message is addressed to this device
    if (message.recipientUserId !== this.localUserId) {
      throw new SesameError(
        `Message not addressed to this user (expected ${this.localUserId}, got ${message.recipientUserId})`,
        'WRONG_RECIPIENT_USER'
      );
    }

    if (message.recipientDeviceId !== this.localDeviceId) {
      throw new SesameError(
        `Message not addressed to this device (expected ${this.localDeviceId}, got ${message.recipientDeviceId})`,
        'WRONG_RECIPIENT_DEVICE'
      );
    }

    this.logger.debug('SESAME: Receiving message', {
      category: 'E2EE',
      data: {
        operation: 'sesame-receive',
        senderUserId: message.senderUserId,
        senderDeviceId: message.senderDeviceId,
      },
    });

    // Deserialize ciphertext
    const ciphertext = this.deserializeCiphertext(message.ciphertext);
    const senderAddress = ProtocolAddress.create(message.senderUserId, message.senderDeviceId);

    // 3. Get session record and all decryption candidates
    const sessionRecord = await this.getSession(message.senderUserId, message.senderDeviceId);

    const candidates = SessionResolver.findDecryptingSessions(sessionRecord);

    // If no existing sessions, try protocol.decrypt() anyway - it handles PreKeyMessage
    // session establishment for first messages from new senders
    if (candidates.length === 0) {
      try {
        const result = await this.handlePreKeyMessage(message, senderAddress, ciphertext);

        // TRANSACTIONAL: Only persist after successful decrypt
        // This prevents session state corruption if decryption fails
        if (result.pendingUserRecord) {
          await this.storage.setUserRecord(message.senderUserId, result.pendingUserRecord);
        }
        // Update session index for the newly established session
        this.removeDeviceFromSessionIndex(message.senderUserId, message.senderDeviceId);
        this.indexSessionRecord(
          message.senderUserId,
          message.senderDeviceId,
          result.pendingDeviceRecord.session
        );
        await this.storage.setDeviceRecord(
          message.senderUserId,
          message.senderDeviceId,
          result.pendingDeviceRecord
        );

        this.logger.debug('SESAME: Session established from PreKeyMessage (persisted)', {
          category: 'E2EE',
          data: {
            operation: 'sesame-receive',
            senderUserId: message.senderUserId,
            senderDeviceId: message.senderDeviceId,
          },
        });

        return result.plaintext;
      } catch (error) {
        // TRANSACTIONAL: No session state was persisted, so no cleanup needed
        this.logger.debug('SESAME: PreKeyMessage handling failed, no sessions available', {
          category: 'E2EE',
          data: {
            operation: 'sesame-receive',
            senderUserId: message.senderUserId,
            senderDeviceId: message.senderDeviceId,
            error: (error as Error).message,
          },
        });
        // Preserve EncryptionError for client-layer handling (e.g., PREKEY_NOT_FOUND triggers key rotation)
        if (error instanceof EncryptionError) {
          throw error;
        }
        throw new DecryptionFailedError(message.sessionId, 0);
      }
    }

    // 4. Try each session in order (active first, then archived)
    let decryptedPlaintext: Uint8Array | null = null;
    let successfulCandidate: (typeof candidates)[0] | null = null;

    for (const candidate of candidates) {
      try {
        const plaintextString = await this.protocol.decrypt(senderAddress, ciphertext);
        decryptedPlaintext = new TextEncoder().encode(plaintextString);
        successfulCandidate = candidate;
        break;
      } catch {
        // This session failed - try next one
        continue;
      }
    }

    // 5. Handle successful decryption
    if (decryptedPlaintext && successfulCandidate && sessionRecord) {
      // CRITICAL: Sync session from protocol layer to get updated state (Nr, chain keys, etc.)
      // The protocol.decrypt() call above mutates and saves the session to KeyStorage.
      // We MUST read it back to avoid overwriting with stale data from sessionRecord.
      // The protocol layer also handles archived session promotion internally.
      const sessionFromProtocol = await this.protocol!.getSession(senderAddress);

      // Use the protocol's updated session (includes updated Nr, chain keys, and any promotion)
      // Fall back to original sessionRecord only if sync fails (should not happen)
      const updatedSession = sessionFromProtocol || sessionRecord;

      // If we decrypted on an archived session, emit convergence event for observability
      // Note: The actual promotion is already handled by the protocol layer (cipher.ts)
      if (!successfulCandidate.isActive && successfulCandidate.baseKey) {
        this.logger.debug('SESAME: Session convergence - archived session used', {
          category: 'E2EE',
          data: {
            operation: 'sesame-receive',
            senderUserId: message.senderUserId,
            senderDeviceId: message.senderDeviceId,
            baseKey: successfulCandidate.baseKey,
          },
        });

        // Emit session convergence event
        this.events.onSessionConverged?.(senderAddress, successfulCandidate.baseKey);
      } else {
        this.logger.debug('SESAME: Message decrypted with active session', {
          category: 'E2EE',
          data: {
            operation: 'sesame-receive',
            senderUserId: message.senderUserId,
            senderDeviceId: message.senderDeviceId,
          },
        });
      }

      // Update session metadata and persist
      await this.persistSessionAfterReceive(
        message.senderUserId,
        message.senderDeviceId,
        updatedSession
      );

      return decryptedPlaintext;
    }

    // 6. All sessions failed - try PreKeyMessage handling as fallback.
    //
    // This handles the device reset scenario. The sender has a new identity
    // key and is sending a PreKeyMessage, but we have an old session that
    // cannot decrypt it.
    this.logger.debug('SESAME: All existing sessions failed, trying PreKeyMessage fallback', {
      category: 'E2EE',
      data: {
        operation: 'sesame-receive',
        senderUserId: message.senderUserId,
        senderDeviceId: message.senderDeviceId,
        candidatesTried: candidates.length,
      },
    });

    try {
      const result = await this.handlePreKeyMessage(message, senderAddress, ciphertext);

      // TRANSACTIONAL: Only persist after successful decrypt
      // This prevents session state corruption if decryption fails
      if (result.pendingUserRecord) {
        await this.storage.setUserRecord(message.senderUserId, result.pendingUserRecord);
      }
      // Update session index for the newly established session
      this.removeDeviceFromSessionIndex(message.senderUserId, message.senderDeviceId);
      this.indexSessionRecord(
        message.senderUserId,
        message.senderDeviceId,
        result.pendingDeviceRecord.session
      );
      await this.storage.setDeviceRecord(
        message.senderUserId,
        message.senderDeviceId,
        result.pendingDeviceRecord
      );

      this.logger.debug('SESAME: Session established from PreKeyMessage fallback (persisted)', {
        category: 'E2EE',
        data: {
          operation: 'sesame-receive',
          senderUserId: message.senderUserId,
          senderDeviceId: message.senderDeviceId,
        },
      });

      return result.plaintext;
    } catch (error) {
      // TRANSACTIONAL: No session state was persisted, so no cleanup needed
      this.logger.debug('SESAME: PreKeyMessage fallback failed', {
        category: 'E2EE',
        data: {
          operation: 'sesame-receive',
          senderUserId: message.senderUserId,
          senderDeviceId: message.senderDeviceId,
          error: (error as Error).message,
        },
      });
      // Preserve EncryptionError for client-layer handling (e.g., PREKEY_NOT_FOUND triggers key rotation)
      if (error instanceof EncryptionError) {
        throw error;
      }
      throw new DecryptionFailedError(message.sessionId, candidates.length);
    }
  }

  /**
   * Create a retry request for a failed message
   */
  async createRetryRequest(
    failedMessage: SesameMessage,
    reason: RetryReason
  ): Promise<RetryRequest> {
    if (!this.config.enableRetryRequests) {
      throw new SesameError('Retry requests are disabled in configuration', 'RETRY_DISABLED');
    }

    if (!this.localUserId || !this.localDeviceId) {
      throw new SesameError('SesameManager not initialized', 'NOT_INITIALIZED');
    }

    // Require timestamp for retry request
    // Client timestamp is the primary identifier for message lookup
    if (failedMessage.timestamp === undefined) {
      throw new SesameError(
        'Cannot create retry request: message has no timestamp',
        'MISSING_TIMESTAMP'
      );
    }

    const ratchetKey = this.extractRetryRatchetKey(failedMessage.ciphertext);

    const retryRequest: RetryRequest = {
      requesterUserId: this.localUserId,
      requesterDeviceId: this.localDeviceId,
      originalSenderUserId: failedMessage.senderUserId,
      originalSenderDeviceId: failedMessage.senderDeviceId,
      // Primary identifier: client timestamp
      failedTimestamp: failedMessage.timestamp,
      timestamp: Date.now(),
      reason,
      ...(ratchetKey !== undefined && { ratchetKey }),
    };

    this.logger.debug('SESAME: Created retry request', {
      category: 'E2EE',
      data: {
        operation: 'sesame-retry-request',
        reason,
        failedTimestamp: failedMessage.timestamp,
        originalSender: `${failedMessage.senderUserId}:${failedMessage.senderDeviceId}`,
        hasRatchetKey: ratchetKey !== undefined,
      },
    });

    return retryRequest;
  }

  /**
   * Handle an incoming retry request
   *
   * Processes retry requests from recipients who failed to decrypt a message.
   * Takes appropriate action based on the failure reason:
   *
   * - NO_SESSION: Archives our session, signals that a new session is needed
   * - DECRYPTION_FAILED: Archives our session, signals session reset needed
   * - SESSION_EXPIRED: Archives our session, signals new session needed
   * - STALE_DEVICE_LIST: No local action needed, requester should refresh their list
   * - IDENTITY_KEY_MISMATCH: Logs security event, requires user verification
   *
   * @param retryRequest - The retry request from the recipient
   * @param options - Optional lifecycle handling overrides
   * @returns Result indicating what actions were taken and what the caller should do
   */
  async handleRetryRequest(
    retryRequest: RetryRequest,
    options?: RetryHandlingOptions
  ): Promise<RetryResult> {
    if (!this.config.enableRetryRequests) {
      throw new SesameError('Retry requests are disabled in configuration', 'RETRY_DISABLED');
    }

    if (!this.localUserId || !this.localDeviceId) {
      throw new SesameError('SesameManager not initialized', 'NOT_INITIALIZED');
    }

    // Validate retry request is addressed to this device
    if (
      retryRequest.originalSenderUserId !== this.localUserId ||
      retryRequest.originalSenderDeviceId !== this.localDeviceId
    ) {
      throw new SesameError('Retry request not addressed to this device', 'WRONG_RETRY_DEVICE');
    }

    const requesterUserId = retryRequest.requesterUserId;
    const requesterDeviceId = retryRequest.requesterDeviceId;

    const lifecycleOnly = options?.skipMessageRecordValidation === true;

    if (!lifecycleOnly) {
      // Validate the message corresponds to one we actually sent.
      // This prevents attackers from forging retry requests to force session renegotiation.
      // Per SESAME spec §4.1: message existence MUST be verified before processing retries.
      if (!this.messageRecordStore) {
        this.logger.warn('SESAME: Retry request rejected - no MessageRecordStore configured', {
          category: 'SECURITY',
          data: { requester: `${requesterUserId}:${requesterDeviceId}` },
        });
        return {
          action: 'NO_ACTION',
          requiresNewSession: false,
          requiresUserVerification: false,
          reason: 'MessageRecordStore not configured - cannot validate retry request.',
        };
      }

      // Scope the original-message lookup to the requesting device so one
      // device cannot trigger a resend intended for another.
      const requesterSessionId = `${requesterUserId}:${requesterDeviceId}`;
      const originalMessage = await this.messageRecordStore.getMessageRecord(
        requesterSessionId,
        retryRequest.failedTimestamp
      );

      if (!originalMessage) {
        this.logger.warn('SESAME: Retry request for unknown message', {
          category: 'SECURITY',
          data: {
            requester: `${requesterUserId}:${requesterDeviceId}`,
            failedTimestamp: retryRequest.failedTimestamp,
          },
        });
        return {
          action: 'NO_ACTION',
          requiresNewSession: false,
          requiresUserVerification: false,
          reason: 'No message found for the specified timestamp.',
        };
      }
    } else {
      if (retryRequest.reason === RetryReason.DECRYPTION_FAILED) {
        const activeSession = await this.getActiveSession(requesterUserId, requesterDeviceId);
        const currentRatchetKey = activeSession?.DHs?.publicKey as string | undefined;

        // Reference implementation behavior (Android/iOS): only reset session on retry if the ratchet
        // key from DecryptionErrorMessage matches the current active session.
        if (
          !retryRequest.ratchetKey ||
          !currentRatchetKey ||
          currentRatchetKey !== retryRequest.ratchetKey
        ) {
          this.logger.warn('SESAME: Lifecycle-only retry rejected due to ratchet key mismatch', {
            category: 'SECURITY',
            data: {
              requester: `${requesterUserId}:${requesterDeviceId}`,
              hasRetryRatchetKey: retryRequest.ratchetKey !== undefined,
              hasActiveRatchetKey: currentRatchetKey !== undefined,
            },
          });
          return {
            action: 'NO_ACTION',
            requiresNewSession: false,
            requiresUserVerification: false,
            reason:
              'Retry ratchet key did not match active session; skipping lifecycle-only session reset.',
          };
        }
      }

      this.logger.info('SESAME: Handling retry request in lifecycle-only mode', {
        category: 'E2EE',
        data: {
          requester: `${requesterUserId}:${requesterDeviceId}`,
          failedTimestamp: retryRequest.failedTimestamp,
          reason: retryRequest.reason,
        },
      });
    }

    this.logger.info('SESAME: Handling retry request (lifecycle)', {
      category: 'E2EE',
      data: {
        operation: 'sesame-handle-retry',
        reason: retryRequest.reason,
        requester: `${requesterUserId}:${requesterDeviceId}`,
        failedTimestamp: retryRequest.failedTimestamp,
        localSender: `${this.localUserId}:${this.localDeviceId}`,
      },
    });

    // Based on the retry reason, take appropriate action
    switch (retryRequest.reason) {
      case RetryReason.NO_SESSION:
        // Requester has no session - archive our session and signal that a
        // new session is needed. The caller should establish a new session
        // and resend the message.
        await this.archiveSessionForDevice(requesterUserId, requesterDeviceId);
        this.logger.info('SESAME: Session archived due to NO_SESSION retry request', {
          category: 'E2EE',
          data: {
            requester: `${requesterUserId}:${requesterDeviceId}`,
            failedTimestamp: retryRequest.failedTimestamp,
          },
        });
        return {
          action: 'SESSION_ARCHIVED',
          requiresNewSession: true,
          requiresUserVerification: false,
          reason: 'Recipient has no session. Establish a new session and resend the message.',
        };

      case RetryReason.DECRYPTION_FAILED:
        // Requester could not decrypt - session is likely desynchronized
        // Archive our session so a new one will be established on next send
        await this.archiveSessionForDevice(requesterUserId, requesterDeviceId);
        this.logger.warn('SESAME: Session archived due to DECRYPTION_FAILED retry request', {
          category: 'E2EE',
          data: {
            requester: `${requesterUserId}:${requesterDeviceId}`,
            failedTimestamp: retryRequest.failedTimestamp,
          },
        });
        return {
          action: 'SESSION_ARCHIVED',
          requiresNewSession: true,
          requiresUserVerification: false,
          reason:
            'Decryption failed, session may be desynchronized. Establish a new session and resend.',
        };

      case RetryReason.SESSION_EXPIRED:
        // Requester's session is expired - same as NO_SESSION
        await this.archiveSessionForDevice(requesterUserId, requesterDeviceId);
        this.logger.info('SESAME: Session archived due to SESSION_EXPIRED retry request', {
          category: 'E2EE',
          data: {
            requester: `${requesterUserId}:${requesterDeviceId}`,
            failedTimestamp: retryRequest.failedTimestamp,
          },
        });
        return {
          action: 'SESSION_ARCHIVED',
          requiresNewSession: true,
          requiresUserVerification: false,
          reason: 'Recipient session expired. Establish a new session and resend the message.',
        };

      case RetryReason.STALE_DEVICE_LIST:
        // Requester has outdated device list - they should refresh
        // No local action needed on our side
        this.logger.debug('SESAME: STALE_DEVICE_LIST retry request - no local action needed', {
          category: 'E2EE',
          data: {
            requester: `${requesterUserId}:${requesterDeviceId}`,
          },
        });
        return {
          action: 'NO_ACTION',
          requiresNewSession: false,
          requiresUserVerification: false,
          reason: 'Recipient has stale device list. They should refresh and retry.',
        };

      case RetryReason.IDENTITY_KEY_MISMATCH:
        // Security issue - identity key changed
        // This requires user verification before proceeding
        this.logger.error('SESAME: IDENTITY_KEY_MISMATCH - potential security issue', {
          category: 'SECURITY',
          data: {
            requester: `${requesterUserId}:${requesterDeviceId}`,
            failedTimestamp: retryRequest.failedTimestamp,
          },
        });
        return {
          action: 'SECURITY_ALERT',
          requiresNewSession: false,
          requiresUserVerification: true,
          reason:
            'Identity key mismatch detected. User must verify safety numbers before proceeding.',
        };

      default:
        this.logger.warn('SESAME: Unknown retry reason', {
          category: 'E2EE',
          data: {
            reason: retryRequest.reason,
            requester: `${requesterUserId}:${requesterDeviceId}`,
          },
        });
        return {
          action: 'UNKNOWN',
          requiresNewSession: false,
          requiresUserVerification: false,
          reason: `Unknown retry reason: ${retryRequest.reason}`,
        };
    }
  }

  /**
   * Handle PreKeyMessage decryption when no existing sessions are found.
   *
   * This method handles the first message from a new sender by:
   * 1. Attempting to decrypt using protocol.decrypt() (handles session establishment)
   * 2. Creating DeviceRecord if sender is unknown
   * 3. Detecting identity key changes for existing senders (device reinstall scenario)
   * 4. Persisting the new session
   *
   * @param message - The incoming SESAME message
   * @param senderAddress - Protocol address of the sender
   * @param ciphertext - The encrypted ciphertext
   * @returns Decrypted plaintext as Uint8Array
   * @throws DecryptionFailedError if decryption fails
   */
  private async handlePreKeyMessage(
    message: SesameMessage,
    senderAddress: ProtocolAddress,
    ciphertext: Ciphertext
  ): Promise<PreKeyMessageResult> {
    this.logger.debug('SESAME: No existing sessions, trying PreKeyMessage handling', {
      category: 'E2EE',
      data: {
        operation: 'sesame-receive',
        senderUserId: message.senderUserId,
        senderDeviceId: message.senderDeviceId,
      },
    });

    // Snapshot SESAME state before protocol.decrypt() establishes a responder
    // session. Some storage adapters synthesize DeviceRecord from live
    // protocol state. Looking this up only after decrypt would make a
    // brand-new session appear pre-existing and archive it into itself.
    let deviceRecord = await this.getDeviceRecord(
      message.senderUserId,
      message.senderDeviceId
    );

    // Note: this.protocol is guaranteed non-null because receive() checks it before calling this method
    const plaintextString = await this.protocol!.decrypt(senderAddress, ciphertext);
    const decryptedPlaintext = new TextEncoder().encode(plaintextString);

    // CRITICAL: Sync session from KeyStorage to SESAME layer
    // The protocol.decrypt() call above establishes the session in KeyStorage (protocol layer).
    // SESAME needs this session in DeviceRecord.session (SESAME layer) for subsequent messages.
    // Without this sync, the responder path fails to find the session on later messages.
    const sessionFromProtocol = await this.protocol!.getSession(senderAddress);

    // Parse PreKeyMessage to get sender's identity key (binary protobuf format)
    // This is needed for both new senders AND existing senders (to detect identity key changes)
    let incomingIdentityKey: Uint8Array;
    try {
      const bytes = base64ToBytes(ciphertext as Base64);
      if (bytes.length < 2) throw new Error('Too short');

      // Parse PreKeySignalProtocolMessage to get identity key
      const { protobufBytes } = parsePreKeySignalProtocolMessageEnvelope(bytes);
      const preKeyFields = decodePreKeySignalProtocolMessage(protobufBytes);

      if (!preKeyFields.identityKey?.length) {
        throw new DecryptionFailedError(message.sessionId, 0);
      }

      // The independent profile carries exactly one canonical 67-byte composite
      // tuple. Decode and re-encode so unknown tags/profile bytes fail before
      // any SESAME user or device record is prepared.
      incomingIdentityKey = encodeCompositeIdentityV1(
        decodeCompositeIdentityV1(preKeyFields.identityKey)
      );
    } catch (e) {
      if (e instanceof DecryptionFailedError) throw e;
      throw new DecryptionFailedError(message.sessionId, 0);
    }

    // Track if we need to create/update UserRecord (for new senders only)
    let pendingUserRecord: UserRecord | undefined;

    if (!deviceRecord) {
      // First message from new sender - create DeviceRecord with synced session
      deviceRecord = {
        userId: message.senderUserId,
        deviceId: message.senderDeviceId,
        identityKey: incomingIdentityKey,
        session: sessionFromProtocol ? updateSessionRecordAfterReceive(sessionFromProtocol) : null, // Sync session from protocol layer with metadata
        createdAt: Date.now(),
        updatedAt: Date.now(),
      };

      // Prepare UserRecord (will be persisted by caller after successful decrypt)
      let userRecord = await this.storage.getUserRecord(message.senderUserId);
      if (!userRecord) {
        userRecord = {
          userId: message.senderUserId,
          devices: new Map(),
          createdAt: Date.now(),
          updatedAt: Date.now(),
        };
      }
      userRecord.devices.set(message.senderDeviceId, deviceRecord);
      userRecord.updatedAt = Date.now();
      pendingUserRecord = userRecord;

      // TRANSACTIONAL: DO NOT persist here - caller will persist after successful decrypt
      // This prevents session state corruption if subsequent processing fails

      this.logger.debug('SESAME: Prepared DeviceRecord for new sender (pending persist)', {
        category: 'E2EE',
        data: { userId: message.senderUserId, deviceId: message.senderDeviceId },
      });
    } else {
      // Existing device record - compare the pinned identity against the one
      // this PreKeyMessage was authenticated with. Both sides are canonical
      // composite tuples, so a difference is a real identity change and not an
      // encoding artifact. A record that carries no pinned identity yet is
      // first contact, because session bookkeeping created it before any
      // identity was observed. TOFU-pin it silently rather than reporting a
      // change.
      const comparison = compareDeviceIdentityKeys(deviceRecord.identityKey, incomingIdentityKey);

      if (comparison === 'unpinned') {
        deviceRecord.identityKey = incomingIdentityKey;

        this.logger.debug('SESAME: Pinned identity key on first contact (TOFU)', {
          category: 'E2EE',
          data: {
            userId: message.senderUserId,
            deviceId: message.senderDeviceId,
          },
        });
      }

      if (comparison === 'changed') {
        // CRITICAL: Identity key changed - this is either a device reinstall
        // or a potential security issue (man-in-the-middle attack)
        this.logger.warn('SESAME: Identity key changed detected in PreKeyMessage', {
          category: 'SECURITY',
          data: {
            userId: message.senderUserId,
            deviceId: message.senderDeviceId,
            event: 'identity_key_changed',
          },
        });

        // Update the identity key to the new one
        deviceRecord.identityKey = incomingIdentityKey;
        deviceRecord.pendingVerification = true;

        // Emit identity key changed event (safety number changed)
        this.events.onIdentityKeyChanged?.(message.senderUserId, incomingIdentityKey);

        // Also emit security event
        this.events.onSecurityEvent?.(senderAddress, 'identity_key_changed');

        this.logger.info(
          'SESAME: Session archived and identity key updated after device reinstall',
          {
            category: 'E2EE',
            data: {
              userId: message.senderUserId,
              deviceId: message.senderDeviceId,
            },
          }
        );
      }

      // Sync the new session from protocol layer to DeviceRecord.
      // This is needed whether identity changed or not. The PreKeyMessage
      // established a new session that needs to be synced to SESAME layer.
      if (sessionFromProtocol) {
        // If there was an old session, archive it before setting the new one
        // This preserves session history for convergence per SESAME spec
        if (deviceRecord.session?.currentSession) {
          const archivedRecord = SessionResolver.archiveCurrentSession(
            deviceRecord.session,
            this.config.maxInactiveSessions
          );
          // Merge archived sessions: preserve ALL sessions from both sources
          // Use explicit merge to avoid collision-related data loss from spread operator
          const mergedArchived: Record<string, SessionState> = {};

          // First, add all from archived record (preserves existing session history)
          for (const [key, session] of Object.entries(archivedRecord.archivedSessions)) {
            if (session) mergedArchived[key] = session;
          }

          // Then add from protocol (only if not already present - do not overwrite history)
          for (const [key, session] of Object.entries(sessionFromProtocol.archivedSessions || {})) {
            if (session && !(key in mergedArchived)) {
              mergedArchived[key] = session;
            }
          }

          sessionFromProtocol.archivedSessions = mergedArchived;
        }
        deviceRecord.session = updateSessionRecordAfterReceive(sessionFromProtocol);
      }
      deviceRecord.updatedAt = Date.now();

      // TRANSACTIONAL: DO NOT persist here - caller will persist after successful decrypt
      // This prevents session state corruption if subsequent processing fails
    }

    this.logger.debug('SESAME: Session prepared from PreKeyMessage (pending persist)', {
      category: 'E2EE',
      data: {
        operation: 'sesame-receive',
        senderUserId: message.senderUserId,
        senderDeviceId: message.senderDeviceId,
      },
    });

    // Return result with pending records - caller MUST persist after confirming success
    return {
      plaintext: decryptedPlaintext,
      pendingDeviceRecord: deviceRecord,
      pendingUserRecord,
    };
  }

  /**
   * Update session metadata after receiving a message and persist to storage.
   *
   * This is a helper method that reduces duplication between the PreKeyMessage
   * handling path and the normal receive path.
   *
   * @param userId - Sender's user ID
   * @param deviceId - Sender's device ID
   * @param session - The session record to update
   */
  private async persistSessionAfterReceive(
    userId: UserID,
    deviceId: DeviceID,
    session: SessionRecord
  ): Promise<void> {
    const updatedSession = updateSessionRecordAfterReceive(session);
    const deviceRecord = await this.storage.getDeviceRecord(userId, deviceId);
    if (deviceRecord) {
      // Update session index for the new session state
      this.removeDeviceFromSessionIndex(userId, deviceId);
      this.indexSessionRecord(userId, deviceId, updatedSession);

      deviceRecord.session = updatedSession;
      deviceRecord.updatedAt = Date.now();
      await this.storage.setDeviceRecord(userId, deviceId, deviceRecord);
    }
  }

  /**
   * Mark a UserRecord as stale, triggering a fresh device list fetch on next access.
   * Per SESAME spec §3.3: When a StaleDeviceListError occurs, the UserRecord
   * is marked stale so the sending device knows to refetch the device list.
   *
   * @param userId - The user whose record should be marked stale
   */
  private async markUserRecordStale(userId: UserID): Promise<void> {
    const userRecord = await this.storage.getUserRecord(userId);
    if (userRecord) {
      userRecord.stale = true;
      userRecord.updatedAt = Date.now();
      await this.storage.setUserRecord(userId, userRecord);

      this.logger.info('SESAME: UserRecord marked stale', {
        category: 'E2EE',
        data: {
          operation: 'sesame-mark-stale',
          userId,
        },
      });
    }
  }

  /**
   * Archive the active session for a specific device
   *
   * Moves the current session to archived, clearing the active session
   * to allow a new session to be established on the next send attempt.
   */
  private async archiveSessionForDevice(userId: UserID, deviceId: DeviceID): Promise<void> {
    const deviceRecord = await this.storage.getDeviceRecord(userId, deviceId);
    if (!deviceRecord?.session?.currentSession) {
      // No active session to archive
      return;
    }

    const sessionId = ProtocolAddress.toString(deviceRecord.session.currentSession.remoteAddress);

    // Archive the current session and clear it using SessionResolver
    deviceRecord.session = SessionResolver.archiveCurrentSession(
      deviceRecord.session,
      this.config.maxInactiveSessions
    );

    // Rebuild session index for this device (session moved from current to archived)
    this.removeDeviceFromSessionIndex(userId, deviceId);
    this.indexSessionRecord(userId, deviceId, deviceRecord.session);

    await this.storage.setDeviceRecord(userId, deviceId, deviceRecord);

    this.logger.debug('SESAME: Session archived', {
      category: 'E2EE',
      data: {
        operation: 'sesame-archive-session',
        userId,
        deviceId,
        sessionId,
      },
    });
  }

  /**
   * Extract sender ratchet key from failed message ciphertext for retry requests.
   *
   * Retry metadata includes the sender ratchet key for one-to-one
   * SignalProtocolMessage/PreKeySignalProtocolMessage failures and omits it for
   * sender-key messages.
   */
  private extractRetryRatchetKey(ciphertext: Uint8Array): string | undefined {
    if (ciphertext.length < 2) {
      return undefined;
    }

    try {
      let signalMessageProtobuf: Uint8Array;
      const firstTag = ciphertext[1];
      const isPreKey = firstTag === 0x08 || firstTag === 0x12;

      if (isPreKey) {
        const { protobufBytes: outerProto } = parsePreKeySignalProtocolMessageEnvelope(ciphertext);
        const preKeyFields = decodePreKeySignalProtocolMessage(outerProto);
        const { protobufBytes: innerProto } = parseSignalProtocolMessageEnvelope(preKeyFields.message);
        signalMessageProtobuf = innerProto;
      } else {
        const { protobufBytes } = parseSignalProtocolMessageEnvelope(ciphertext);
        signalMessageProtobuf = protobufBytes;
      }

      const signalFields = decodeSignalProtocolMessage(signalMessageProtobuf);
      if (!signalFields.ratchetKey?.length) {
        return undefined;
      }

      const ratchetKeyRaw =
        signalFields.ratchetKey.length === 33
          ? deserializePublicKey(signalFields.ratchetKey)
          : signalFields.ratchetKey;

      return bytesToBase64(ratchetKeyRaw);
    } catch {
      return undefined;
    }
  }

  /**
   * Extract the creation timestamp from a SessionRecord.
   *
   * Prefers SessionRecordMetadata.createdAt (set by SESAME registerSession),
   * then falls back to SessionState.createdAt (set by Double Ratchet init).
   * Returns 0 only if neither is available (fail closed, treats session as
   * expired at Unix epoch).
   */
  private getSessionCreatedAt(session: SessionRecord): number {
    return session.metadata?.createdAt ?? session.currentSession?.createdAt ?? 0;
  }

  /**
   * Check if a session can be used for sending.
   *
   * Only check age on unacknowledged sessions (no reply received yet).
   * Acknowledged sessions have no age-based send expiration.
   */
  async canSendOnSession(sessionId: SessionID): Promise<boolean> {
    const session = await this.findSession(sessionId);
    if (!session?.currentSession) {
      return false;
    }

    // Only check age on unacknowledged sessions (no reply received yet).
    // Acknowledged sessions have no age-based send expiration.
    if (session.currentSession.hasReceivedMessage === false) {
      const createdAt = this.getSessionCreatedAt(session);
      return Date.now() - createdAt <= this.config.maxUnacknowledgedSessionAge;
    }
    return true;
  }

  /**
   * Index all session IDs from a DeviceRecord's SessionRecord into sessionIndex.
   * Indexes both the current session and all archived sessions.
   */
  private indexSessionRecord(
    userId: string,
    deviceId: number,
    sessionRecord: SessionRecord | null
  ): void {
    if (!sessionRecord) return;

    const entry = { userId, deviceId };

    if (sessionRecord.currentSession?.remoteAddress) {
      const sid = ProtocolAddress.toString(sessionRecord.currentSession.remoteAddress);
      this.sessionIndex.set(sid, entry);
    }

    for (const archivedSession of Object.values(sessionRecord.archivedSessions)) {
      if (!archivedSession?.remoteAddress) continue;
      const sid = ProtocolAddress.toString(archivedSession.remoteAddress);
      this.sessionIndex.set(sid, entry);
    }
  }

  /**
   * Remove all session IDs belonging to a specific device from sessionIndex.
   */
  private removeDeviceFromSessionIndex(userId: string, deviceId: number): void {
    for (const [sid, entry] of this.sessionIndex) {
      if (entry.userId === userId && entry.deviceId === deviceId) {
        this.sessionIndex.delete(sid);
      }
    }
  }

  /**
   * Find a session by ID using the O(1) session index.
   * Falls back to direct storage lookup (parsing the sessionId) if the index
   * has no entry. This handles app restart where the in-memory index is empty
   * but sessions are persisted in storage.
   */
  private async findSession(sessionId: SessionID): Promise<SessionRecord | null> {
    const entry = this.sessionIndex.get(sessionId);

    if (entry) {
      const deviceRecord = await this.storage.getDeviceRecord(entry.userId, entry.deviceId);
      if (!deviceRecord?.session) {
        // Index is stale - clean it up
        this.sessionIndex.delete(sessionId);
        return null;
      }
      return deviceRecord.session;
    }

    // Index miss. Parse sessionId and look up directly from storage.
    // This covers the case where the app restarted and the in-memory index
    // was not rebuilt.
    let parsed: ProtocolAddress;
    try {
      parsed = ProtocolAddress.parse(sessionId);
    } catch {
      return null;
    }

    const deviceRecord = await this.storage.getDeviceRecord(parsed.userId, parsed.deviceId);
    if (!deviceRecord?.session) {
      return null;
    }

    // Rebuild the index entry so subsequent lookups are O(1)
    this.indexSessionRecord(parsed.userId, parsed.deviceId, deviceRecord.session);

    return deviceRecord.session;
  }

  /**
   * Clean up expired sessions based on maxRecv threshold
   */
  async cleanupExpiredSessions(): Promise<number> {
    const count = await this.storage.cleanupExpiredSessions(this.config.maxRecv);

    this.logger.debug('SESAME: Cleaned up expired sessions', {
      category: 'E2EE',
      data: {
        operation: 'sesame-cleanup',
        expiredCount: count,
      },
    });

    return count;
  }

  /**
   * Clean up stale device records with no sessions and age > maxLatency
   */
  async cleanupStaleRecords(): Promise<number> {
    if (!this.config.enableStaleRecordCleanup) {
      return 0;
    }

    const count = await this.storage.deleteStaleRecords(this.config.maxLatency);

    this.logger.debug('SESAME: Cleaned up stale records', {
      category: 'E2EE',
      data: {
        operation: 'sesame-cleanup',
        staleCount: count,
      },
    });

    return count;
  }

  /**
   * Synchronize device list from server response
   *
   * SESAME Phase 3 in message sending requires validating the device list is current.
   */
  async syncDeviceList(deviceListResponse: DeviceListResponse): Promise<void> {
    const { userId, deviceIds, version } = deviceListResponse;

    this.logger.debug('SESAME: Syncing device list', {
      category: 'E2EE',
      data: {
        operation: 'sesame-sync-devices',
        userId,
        deviceCount: deviceIds.length,
        version,
      },
    });

    // Convert deviceIds to devices array, using identity keys from response when
    // available. A device the server listed without an identity key stays
    // unpinned rather than being pinned to placeholder bytes.
    const { identityKeys } = deviceListResponse;
    const devices = deviceIds.map((deviceId: DeviceID) => ({
      deviceId,
      identityKey: canonicalizeDeviceIdentityKey(
        identityKeys?.get(deviceId) ?? UNPINNED_DEVICE_IDENTITY_KEY,
        `Device list identity key for ${userId}:${deviceId}`
      ),
      isActive: true,
    }));

    // Get current user record
    const userRecord = await this.storage.getUserRecord(userId);

    if (!userRecord) {
      // New user - create record with all devices
      for (const device of devices) {
        if (device.isActive) {
          await this.addDevice(userId, device.deviceId, device.identityKey);
        }
      }
      return;
    }

    // Track which devices exist on server
    const serverDeviceIds = new Set(devices.map((d) => d.deviceId));

    // Remove devices that no longer exist on server
    for (const [deviceId] of userRecord.devices.entries()) {
      if (!serverDeviceIds.has(deviceId)) {
        await this.removeDevice(userId, deviceId);
      }
    }

    // Add or update devices from server
    for (const device of devices) {
      if (!device.isActive) {
        await this.removeDevice(userId, device.deviceId);
        continue;
      }

      const existingDevice = await this.getDeviceRecord(userId, device.deviceId);

      if (!existingDevice) {
        await this.addDevice(userId, device.deviceId, device.identityKey);
      } else if (device.identityKey.length > 0) {
        // Only a device list that actually carries an identity key can tell us
        // the identity changed. A response that omits it carries no
        // information about identity, and must not be read as a change.
        // Reading it as a change would drop every live session and raise a
        // security event on each sync.
        const comparison = compareDeviceIdentityKeys(
          existingDevice.identityKey,
          device.identityKey
        );

        if (comparison === 'unpinned') {
          // Device was tracked before its identity was known - TOFU-pin it.
          existingDevice.identityKey = device.identityKey;
          await this.storage.setDeviceRecord(userId, device.deviceId, existingDevice);
        }

        if (comparison === 'changed') {
          // Identity key changed - security event
          // Remove old device and add new one (clears sessions)
          await this.removeDevice(userId, device.deviceId);
          await this.addDevice(userId, device.deviceId, device.identityKey);

          // Mark device as pending verification to block messaging until user verifies
          const newRecord = await this.getDeviceRecord(userId, device.deviceId);
          if (newRecord) {
            newRecord.pendingVerification = true;
            await this.storage.setDeviceRecord(userId, device.deviceId, newRecord);
          }

          // Emit identity key changed event (SECURITY)
          this.events.onIdentityKeyChanged?.(userId, device.identityKey);

          // Also emit security event with description
          const address = ProtocolAddress.create(userId, device.deviceId);
          this.events.onSecurityEvent?.(address, 'identity_key_changed');
        }
      }
    }

    // Update user record version if provided (Phase 3 version tracking)
    if (version !== undefined) {
      const updatedUserRecord = await this.storage.getUserRecord(userId);
      if (updatedUserRecord) {
        updatedUserRecord.deviceListVersion = version;
        updatedUserRecord.updatedAt = Date.now();
        await this.storage.setUserRecord(userId, updatedUserRecord);
      }
    }
  }

  /**
   * Get statistics about SESAME state
   */
  async getStats(): Promise<SesameStats> {
    const allUserIds = await this.storage.getAllUserIds();
    const now = Date.now();

    let totalUsers = 0;
    let totalDevices = 0;
    let totalActiveSessions = 0;
    let totalInactiveSessions = 0;
    let expiredSessions = 0;
    let staleRecords = 0;

    for (const userId of allUserIds) {
      const userRecord = await this.storage.getUserRecord(userId);
      if (!userRecord) continue;

      totalUsers++;

      for (const [, deviceRecord] of userRecord.devices.entries()) {
        totalDevices++;

        // Check if device record is stale (no sessions and old)
        const hasCurrentSession = deviceRecord.session?.currentSession != null;
        const archivedSessionCount = deviceRecord.session
          ? Object.keys(deviceRecord.session.archivedSessions).length
          : 0;
        const hasNoSessions = !hasCurrentSession && archivedSessionCount === 0;
        const isOld = now - deviceRecord.createdAt > this.config.maxLatency;
        if (hasNoSessions && isOld) {
          staleRecords++;
        }

        // Count active session and check if expired
        if (hasCurrentSession) {
          totalActiveSessions++;
          const createdAt = deviceRecord.session!.metadata?.createdAt ?? 0;
          const sessionAge = now - createdAt;
          if (sessionAge > this.config.maxRecv) {
            expiredSessions++;
          }
        }

        // Count archived sessions and check for expired ones
        if (deviceRecord.session) {
          for (const archivedSession of Object.values(deviceRecord.session.archivedSessions)) {
            if (!archivedSession) continue;
            totalInactiveSessions++;
            // Archived sessions do not have their own createdAt - use the session record's
            const createdAt = deviceRecord.session.metadata?.createdAt ?? 0;
            const sessionAge = now - createdAt;
            if (sessionAge > this.config.maxRecv) {
              expiredSessions++;
            }
          }
        }
      }
    }

    return {
      totalUsers,
      totalDevices,
      totalActiveSessions,
      totalInactiveSessions,
      expiredSessions,
      staleRecords,
    };
  }
}
