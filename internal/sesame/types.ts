/**
 * SESAME (Secure Encrypted Stored Authenticated Messaging Extension) Types
 *
 * Signal Protocol Section 7 - SESAME
 * Multi-device session management for encrypted asynchronous messaging.
 *
 * Key features:
 * - Generic support for the specification's per-user or per-device identity-key models
 * - Session convergence through receive-activated switching
 * - 3-phase message sending process
 * - Automatic session expiration and cleanup
 * - Retry request mechanism for failed decryption
 *
 * @see https://signal.org/docs/specifications/sesame/
 */

import {
  CURRENT_SESSION_RECORD_VERSION,
  type SessionState,
  type SessionRecord,
} from '../../types/session';
import type { ProtocolAddress } from '../../types/address';
import type { IMessageRecordStore } from '../../local/store';

// ============================================================================
// ID Types (Plain types per Signal Protocol spec)
// ============================================================================

/**
 * Unique identifier for a user across all devices
 * Plain string for flexibility with external ID formats
 */
export {};
export type UserID = string;

/**
 * Unique identifier for a specific device belonging to a user
 * Integer per Signal Protocol spec (1-5 for multi-device)
 */
export type DeviceID = number;

/**
 * Minimum valid device ID (primary device)
 */
export const MIN_DEVICE_ID = 1;

/**
 * Maximum valid device ID (Signal Protocol limits devices to prevent resource exhaustion)
 */
export const MAX_DEVICE_ID = 5;

/**
 * Unique identifier for a SESAME session between two devices
 * Format: "userId:deviceId" for remote party
 */
export type SessionID = string;

// ============================================================================
// Configuration Constants
// ============================================================================

/**
 * SESAME protocol configuration parameters
 */
export interface SesameConfig {
  /**
   * Maximum message latency (milliseconds)
   * Messages older than MAXLATENCY count as lost
   * Used for stale record cleanup
   * Default: 30 days (2,592,000,000 ms)
   */
  maxLatency: number;

  /**
   * Maximum age for unacknowledged sessions (milliseconds)
   * Sessions that have not received a reply within this period cannot send.
   * Default: 30 days (2,592,000,000 ms)
   */
  maxUnacknowledgedSessionAge: number;

  /**
   * Maximum receive age for sessions (milliseconds)
   * The store deletes sessions older than MAXRECV entirely
   * Default: 180 days (15,552,000,000 ms)
   */
  maxRecv: number;

  /**
   * Maximum number of inactive sessions to retain per device
   * Prevents unbounded storage growth
   * Default: 40 (per Signal Protocol recommendation)
   */
  maxInactiveSessions: number;

  /**
   * Whether to enable retry request feature
   * Allows recipients to request resends when decryption fails
   * Default: true
   */
  enableRetryRequests: boolean;

  /**
   * Whether to enable automatic stale record cleanup
   * Default: true
   */
  enableStaleRecordCleanup: boolean;
}

/**
 * Default SESAME configuration
 */
export const DEFAULT_SESAME_CONFIG: SesameConfig = {
  maxLatency: 30 * 24 * 60 * 60 * 1000, // 30 days
  maxUnacknowledgedSessionAge: 30 * 24 * 60 * 60 * 1000, // 30 days
  maxRecv: 180 * 24 * 60 * 60 * 1000, // 180 days
  maxInactiveSessions: 40,
  enableRetryRequests: true,
  enableStaleRecordCleanup: true,
};

// ============================================================================
// Session State Enum (for logging/debugging)
// ============================================================================

/**
 * Computed session state for logging and debugging.
 *
 * This enum follows the SESAME specification terminology:
 * - Active: Session actively exchanging messages
 * - Inactive/Archived: Session established but dormant
 * - Stale: Session exceeded timeout thresholds
 *
 * NOTE: This is computed at runtime from SessionRecord + timestamps,
 * NOT stored in the session record. The underlying storage uses
 * SessionRecord.currentSession and SessionRecord.archivedSessions.
 *
 * @see https://signal.org/docs/specifications/sesame/
 */
export enum ComputedSessionState {
  /** No session exists for this device */
  NO_SESSION = 'NO_SESSION',

  /** Session is active and can send/receive messages */
  ACTIVE = 'ACTIVE',

  /** Session can receive but not send (age > MAXSEND, age < MAXRECV) */
  SEND_EXPIRED = 'SEND_EXPIRED',

  /** Archived session (in archivedSessions collection, for fallback decryption) */
  ARCHIVED = 'ARCHIVED',

  /** Session/device record is stale and awaiting cleanup (age > MAXRECV) */
  STALE = 'STALE',
}

/**
 * Compute the session state from a SessionRecord and its metadata.
 *
 * This function determines the runtime state of a session based on:
 * - Whether a session exists (currentSession != null)
 * - Session age compared to MAXSEND and MAXRECV thresholds
 *
 * @param sessionRecord - The session record to evaluate
 * @param config - SESAME configuration with thresholds (optional, uses defaults)
 * @returns The computed session state
 *
 * @example
 * ```typescript
 * const state = computeSessionState(deviceRecord.session);
 * if (state === ComputedSessionState.SEND_EXPIRED) {
 *   // Need to establish new session before sending
 * }
 * ```
 */
export function computeSessionState(
  sessionRecord: SessionRecord | null,
  config: Pick<SesameConfig, 'maxUnacknowledgedSessionAge' | 'maxRecv'> = DEFAULT_SESAME_CONFIG
): ComputedSessionState {
  if (!sessionRecord?.currentSession) {
    return ComputedSessionState.NO_SESSION;
  }

  const createdAt = sessionRecord.metadata?.createdAt ?? Date.now();
  const age = Date.now() - createdAt;

  if (age > config.maxRecv) {
    return ComputedSessionState.STALE;
  }

  // Only unacknowledged sessions have age-based send expiration.
  if (
    sessionRecord.currentSession.hasReceivedMessage === false &&
    age > config.maxUnacknowledgedSessionAge
  ) {
    return ComputedSessionState.SEND_EXPIRED;
  }

  return ComputedSessionState.ACTIVE;
}

/**
 * Check if a session is in an archived state (in archivedSessions collection).
 *
 * @param sessionRecord - The session record containing archived sessions
 * @param baseKey - The baseKey of the session to check
 * @returns true if the session exists in archivedSessions
 */
export function isSessionArchived(sessionRecord: SessionRecord | null, baseKey: string): boolean {
  if (!sessionRecord?.archivedSessions) return false;
  return baseKey in sessionRecord.archivedSessions;
}

// ============================================================================
// Outgoing Message Batch
// ============================================================================

/**
 * Outgoing message batch that separates recipient device messages from sync messages.
 *
 * - `deviceMessages` are encrypted for the recipient's devices
 * - `syncMessages` are encrypted for our own other devices (multi-device sync)
 *
 * The separation allows for:
 * - Different delivery handling (device messages go to recipient, sync messages stay local)
 * - Clearer logging and debugging
 * - Potential future optimizations (e.g., batch sync messages differently)
 *
 */
export interface OutgoingMessageBatch {
  /**
   * Messages encrypted for the recipient's devices.
   * One message per active device belonging to the recipient user.
   */
  deviceMessages: SesameMessage[];

  /**
   * Messages encrypted for our own other devices (sync/transcript).
   * Allows other devices we own to stay synchronized.
   * Excludes the sending device.
   */
  syncMessages: SesameMessage[];

  /**
   * Recipient user ID for this batch
   */
  recipientUserId: UserID;

  /**
   * Timestamp of the moment this batch began
   */
  timestamp: number;

  /**
   * Number of devices we attempted to encrypt for
   * Useful for debugging when some devices fail
   */
  attemptedDevices: number;

  /**
   * Number of devices that failed encryption (if any)
   */
  failedDevices: number;
}

//
// DeviceRecord now has:
//   - session: SessionRecord | null (replaces activeSession + inactiveSessions)
//
// Session archiving is handled by SessionRecord.archivedSessions.
// Session convergence uses SessionRecord.promoteSession().

// ============================================================================
// Device Records
// ============================================================================

/**
 * Record of a remote device and its session.
 *
 * Uses SessionRecord directly instead of a separate
 * SesameSessionRecord wrapper. SessionRecord.archivedSessions handles session
 * archiving, which eliminates the need for a separate
 * inactiveSessions list.
 *
 * @see https://signal.org/docs/specifications/sesame/
 */
export interface DeviceRecord {
  /**
   * User ID of the device owner
   */
  userId: UserID;

  /**
   * Unique device identifier
   */
  deviceId: DeviceID;

  /**
   * Identity public key for this device
   * Used for authentication and safety number generation
   */
  identityKey: Uint8Array;

  /**
   * The session record for this device.
   *
   * Contains:
   * - currentSession: Active session for sending (SessionState)
   * - archivedSessions: Archived sessions for receiving (indexed by baseKey)
   * - metadata: SESAME lifecycle info (createdAt, lastSentAt, lastReceivedAt, isInitiator)
   *
   * Null if no session exists yet.
   *
   * Note: Session convergence (receive-activated switching) uses
   * SessionRecord.promoteSession() to swap archived ↔ current.
   */
  session: SessionRecord | null;

  /**
   * Timestamp of the moment this device record began
   */
  createdAt: number;

  /**
   * Timestamp when this device record was last updated
   */
  updatedAt: number;

  /**
   * Whether this device's identity key requires user verification.
   * Set to true when identity key changes unexpectedly.
   * The client blocks messaging until the user verifies safety numbers.
   */
  pendingVerification?: boolean;
}

// ============================================================================
// Session Record Helpers (SESAME integration)
// ============================================================================

/**
 * Create a SessionRecord with SESAME metadata from a SessionState.
 *
 * This bridges the Double Ratchet layer (SessionState) with the SESAME layer
 * (SessionRecord with lifecycle metadata).
 *
 * @param sessionState - The Double Ratchet session state
 * @param isInitiator - Whether we initiated the session
 * @returns SessionRecord with SESAME metadata
 */
export function createSesameSessionRecord(
  sessionState: SessionState,
  isInitiator: boolean
): SessionRecord {
  const now = Date.now();
  return {
    currentSession: sessionState,
    archivedSessions: {},
    version: CURRENT_SESSION_RECORD_VERSION,
    metadata: {
      createdAt: now,
      lastSentAt: null,
      lastReceivedAt: null,
      isInitiator,
      isActive: true,
    },
  };
}

/**
 * Update SESAME metadata on a SessionRecord after sending.
 * @param record - The SessionRecord to update
 * @returns Updated SessionRecord
 */
export function updateSessionRecordAfterSend(record: SessionRecord): SessionRecord {
  return {
    ...record,
    metadata: {
      ...record.metadata,
      lastSentAt: Date.now(),
      lastUsedAt: Date.now(),
      messagesSent: (record.metadata?.messagesSent ?? 0) + 1,
    },
  };
}

/**
 * Update SESAME metadata on a SessionRecord after receiving.
 * @param record - The SessionRecord to update
 * @returns Updated SessionRecord
 */
export function updateSessionRecordAfterReceive(record: SessionRecord): SessionRecord {
  const now = Date.now();
  return {
    ...record,
    metadata: {
      createdAt: record.metadata?.createdAt ?? now,
      lastSentAt: record.metadata?.lastSentAt ?? null,
      isInitiator: record.metadata?.isInitiator ?? false,
      isActive: record.metadata?.isActive ?? true,
      ...record.metadata,
      lastReceivedAt: now,
      lastUsedAt: now,
      messagesReceived: (record.metadata?.messagesReceived ?? 0) + 1,
    },
  };
}

/**
 * Get session metadata with null-safe defaults.
 *
 * This helper provides safe access to SessionRecord.metadata, returning
 * sensible defaults when metadata or its fields are undefined.
 *
 * @param record - The SessionRecord to extract metadata from
 * @returns Complete metadata with default values for missing fields
 */
export function getSessionMetadata(record: SessionRecord): {
  createdAt: number;
  lastSentAt: number | null;
  lastReceivedAt: number | null;
  isInitiator: boolean;
  isActive: boolean;
  lastUsedAt: number | undefined;
  messagesSent: number;
  messagesReceived: number;
} {
  return {
    createdAt: record.metadata?.createdAt ?? Date.now(),
    lastSentAt: record.metadata?.lastSentAt ?? null,
    lastReceivedAt: record.metadata?.lastReceivedAt ?? null,
    isInitiator: record.metadata?.isInitiator ?? false,
    isActive: record.metadata?.isActive ?? true,
    lastUsedAt: record.metadata?.lastUsedAt,
    messagesSent: record.metadata?.messagesSent ?? 0,
    messagesReceived: record.metadata?.messagesReceived ?? 0,
  };
}

// ============================================================================
// User Records
// ============================================================================

/**
 * Record of a remote user and all their devices
 * Top-level organizational structure in SESAME
 */
export interface UserRecord {
  /**
   * Unique user identifier
   */
  userId: UserID;

  /**
   * Map of device ID to device record
   * Contains all known devices for this user
   */
  devices: Map<DeviceID, DeviceRecord>;

  /**
   * Timestamp of the moment this user record began
   */
  createdAt: number;

  /**
   * Timestamp when this user record was last updated
   */
  updatedAt: number;

  /**
   * Server's device list version for this user
   * Used for Phase 3 validation to detect stale device lists
   * @see SESAME spec §3.3 (Sending Messages - Phase 3)
   */
  deviceListVersion?: number;

  /**
   * Whether this UserRecord's device list is stale and needs a fresh fetch.
   * Set to true when sending meets a StaleDeviceListError.
   * When true, the next send operation should refetch the device list before proceeding.
   * Cleared after a successful device list sync.
   * @see SESAME spec §3.3 (Sending Messages - Phase 3)
   */
  stale?: boolean;
}

// ============================================================================
// Message Types
// ============================================================================

/**
 * SESAME message structure for encrypted communication
 */
export interface SesameMessage {
  /**
   * Sender's user ID
   */
  senderUserId: UserID;

  /**
   * Sender's device ID
   */
  senderDeviceId: DeviceID;

  /**
   * Recipient's user ID
   */
  recipientUserId: UserID;

  /**
   * Recipient's device ID
   */
  recipientDeviceId: DeviceID;

  /**
   * Session ID used for this message
   */
  sessionId: SessionID;

  /**
   * Encrypted message ciphertext (from Double Ratchet)
   */
  ciphertext: Uint8Array;

  /**
   * Whether this is an initiating message (contains X3DH/PQXDH header)
   */
  isInitiating: boolean;

  /**
   * X3DH/PQXDH header data for initiating messages
   * Null for non-initiating messages
   */
  initHeader: Uint8Array | null;

  /**
   * Client timestamp for message identification.
   * Set by sender BEFORE encryption. Same value stored in MessageRecord.
   * Used for: retry request matching, delivery receipt correlation.
   */
  timestamp: number;
}

/**
 * Retry request message sent when decryption fails
 * Unencrypted message requesting sender to resend with updated session state
 */
export interface RetryRequest {
  /**
   * Requester's user ID
   */
  requesterUserId: UserID;

  /**
   * Requester's device ID
   */
  requesterDeviceId: DeviceID;

  /**
   * Original sender's user ID
   */
  originalSenderUserId: UserID;

  /**
   * Original sender's device ID
   */
  originalSenderDeviceId: DeviceID;

  /**
   * Timestamp of the message that failed to decrypt.
   * Used to look up original message in MessageSendLog for resend.
   */
  failedTimestamp: number;

  /**
   * Timestamp of this retry request
   */
  timestamp: number;

  /**
   * Reason for retry (for debugging/logging)
   */
  reason: RetryReason;

  /**
   * Sender ratchet key from the failed message (1:1 messages only).
   *
   * Allows the sender to verify that a session-reset request targets the active
   * ratchet.
   *
   * Undefined for sender-key/group failures.
   */
  ratchetKey?: string;
}

/**
 * Reasons why a retry request might be sent
 */
export enum RetryReason {
  /** No matching session found for decryption */
  NO_SESSION = 'NO_SESSION',

  /** Decryption failed on all available sessions */
  DECRYPTION_FAILED = 'DECRYPTION_FAILED',

  /** Session was deleted/expired before message arrived */
  SESSION_EXPIRED = 'SESSION_EXPIRED',

  /** Device list is out of date - resync required */
  STALE_DEVICE_LIST = 'STALE_DEVICE_LIST',

  /** Identity key does not match expected value */
  IDENTITY_KEY_MISMATCH = 'IDENTITY_KEY_MISMATCH',
}

/**
 * Result of handling a retry request
 *
 * Returned by SesameManager.handleRetryRequest() to indicate
 * what actions were taken and what the caller should do next.
 */
export interface RetryResult {
  /**
   * Action taken by the retry handler
   * - SESSION_ARCHIVED: Active session was moved to inactive list
   * - SECURITY_ALERT: Identity key mismatch detected (security issue)
   * - NO_ACTION: No local action needed
   * - UNKNOWN: Unknown retry reason
   */
  action: 'SESSION_ARCHIVED' | 'SECURITY_ALERT' | 'NO_ACTION' | 'UNKNOWN';

  /**
   * Whether a new session needs to be established before resending
   * If true, caller should call establishSession() before resending
   */
  requiresNewSession: boolean;

  /**
   * Whether user verification is required before proceeding
   * If true, show safety numbers and get user confirmation
   */
  requiresUserVerification: boolean;

  /**
   * Human-readable description of what happened and what to do
   */
  reason: string;
}

/**
 * Options controlling retry-request lifecycle handling.
 */
export interface RetryHandlingOptions {
  /**
   * Skip MessageRecordStore validation for lifecycle-only handling.
   *
   * Used by resend fallback paths when payload lookup already failed and only
   * session-reset semantics remain.
   */
  skipMessageRecordValidation?: boolean;
}

// ============================================================================
// Device List Management
// ============================================================================

/**
 * Server response containing current device list for a user
 * Used to validate device list currency during sending
 */
export interface DeviceListResponse {
  /**
   * User ID this device list belongs to
   */
  userId: UserID;

  /**
   * List of currently active device IDs
   */
  deviceIds: DeviceID[];

  /**
   * Version/timestamp of this device list
   * Used to detect stale local device records
   */
  version: number;

  /**
   * Map of device ID to identity key
   * For newly discovered devices
   */
  identityKeys: Map<DeviceID, Uint8Array>;

  /**
   * Map of device ID to prekey bundle
   * For establishing new sessions with newly discovered devices
   */
  prekeyBundles: Map<DeviceID, PreKeyBundleData>;
}

/**
 * Prekey bundle data for establishing new sessions
 * Contains public keys needed for X3DH/PQXDH key agreement
 */
export interface PreKeyBundleData {
  /**
   * Device's identity public key
   */
  identityKey: Uint8Array;

  /**
   * Device's signed prekey
   */
  ecSignedPreKey: Uint8Array;

  /**
   * Signature of signed prekey
   */
  ecSignedPreKeySignature: Uint8Array;

  /**
   * One-time prekey (optional, consumed after use)
   */
  ecOneTimePreKey: Uint8Array | null;

  /**
   * Post-quantum Kyber public key (for PQXDH)
   */
  kemLastResortPreKey: Uint8Array | null;
}

// ============================================================================
// SESAME Manager Interface
// ============================================================================

/**
 * Options for SESAME send operations.
 *
 * Replaces positional parameters on send()/sendMessage() with one options
 * object. The timestamp is explicit rather than parsed from plaintext.
 */
export interface SesameSendOptions {
  localDeviceListVersion?: number;
  includeSyncMessages?: boolean;
  fetchDeviceList?: (userId: UserID) => Promise<DeviceListResponse>;
  /** Explicit client timestamp. Eliminates need to parse plaintext */
  clientTimestamp?: number;
  /** Optional alternate payload for linked-device sync transcripts */
  syncPlaintext?: Uint8Array;
}

/**
 * Public API for SESAME session management
 */
export interface ISesameManager {
  /**
   * Initialize the SESAME manager with local device information
   */
  initialize(localUserId: UserID, localDeviceId: DeviceID): Promise<void>;

  /**
   * Set the MessageRecord store for retry request support.
   * Per SESAME Specification Section 6.2 - "Each MessageRecord stores
   * the plaintext of the encrypted message."
   *
   * When set, sent messages are stored so they can be resent on retry request.
   */
  setMessageRecordStore(store: IMessageRecordStore): void;

  /**
   * Register a newly established Double Ratchet session with SESAME
   * Bridges the Double Ratchet and SESAME layers for multi-device support
   *
   * @param userId - Remote user's ID
   * @param deviceId - Remote device's ID
   * @param sessionState - The Double Ratchet session state
   * @param isInitiator - Whether we initiated the session
   */
  registerSession(
    userId: UserID,
    deviceId: DeviceID,
    sessionState: SessionState,
    isInitiator: boolean
  ): Promise<void>;

  /**
   * Send an encrypted message to a specific recipient device
   * Handles session establishment if needed
   *
   * @param recipientUserId - Target user ID
   * @param recipientDeviceId - Target device ID
   * @param plaintext - Message to encrypt
   * @returns The encrypted SESAME message
   */
  sendMessage(
    recipientUserId: UserID,
    recipientDeviceId: DeviceID,
    plaintext: Uint8Array,
    options?: SesameSendOptions
  ): Promise<SesameMessage>;

  /**
   * Send an encrypted message to all devices of a user.
   *
   * Implements the 3-phase sending process from SESAME spec:
   *
   * - Phase 1: Identify devices with non-stale active sessions
   * - Phase 2: Encrypt message for each device using Double Ratchet
   * - Phase 3: Validate device list is current before sending
   *
   * Returns an OutgoingMessageBatch that separates:
   * - deviceMessages: Messages for recipient's devices
   * - syncMessages: Messages for our own other devices (multi-device sync)
   *
   * @param recipientUserId - Target user ID
   * @param plaintext - Message to encrypt
   * @param options - Optional SESAME send controls, including stale-device-list validation
   * @returns OutgoingMessageBatch with separated device and sync messages
   * @see https://signal.org/docs/specifications/sesame/
   */
  send(
    recipientUserId: UserID,
    plaintext: Uint8Array,
    options?: SesameSendOptions
  ): Promise<OutgoingMessageBatch>;

  /**
   * Encrypt a sync payload for this account's other linked devices.
   *
   * Excludes the current sending device and never recursively produces more
   * sync messages. Used for multi-device transcript fanout.
   */
  sendToLocalOtherDevices(
    plaintext: Uint8Array,
    options?: SesameSendOptions
  ): Promise<SesameMessage[]>;

  /**
   * Receive and decrypt an encrypted message.
   *
   * Handles session convergence per SESAME spec. If decryption succeeds on an
   * inactive session, that session becomes the new active session.
   *
   * @param message - The received SESAME message
   * @returns Decrypted plaintext
   * @see https://signal.org/docs/specifications/sesame/
   */
  receive(message: SesameMessage): Promise<Uint8Array>;

  /**
   * Handle a retry request from a recipient
   *
   * Processes the retry request and takes appropriate action based on the failure reason.
   * Returns a result indicating what actions were taken and what the caller should do.
   *
   * @param retryRequest - The retry request to handle
   * @returns Result indicating session state changes and required caller actions
   */
  handleRetryRequest(
    retryRequest: RetryRequest,
    options?: RetryHandlingOptions
  ): Promise<RetryResult>;

  /**
   * Create a retry request for a message that failed to decrypt
   *
   * @param failedMessage - The message that could not be decrypted
   * @param reason - Why decryption failed
   * @returns The retry request to send
   */
  createRetryRequest(failedMessage: SesameMessage, reason: RetryReason): Promise<RetryRequest>;

  /**
   * Get the session record for a specific device.
   * Returns the full SessionRecord which includes currentSession and archivedSessions.
   * Returns null if no session exists.
   */
  getSession(userId: UserID, deviceId: DeviceID): Promise<SessionRecord | null>;

  /**
   * Get the active session state for a specific device.
   * Convenience method that returns SessionRecord.currentSession.
   * Returns null if no active session exists.
   */
  getActiveSession(userId: UserID, deviceId: DeviceID): Promise<SessionState | null>;

  /**
   * Get device record for a specific user's device
   * Returns null if device not found
   */
  getDeviceRecord(userId: UserID, deviceId: DeviceID): Promise<DeviceRecord | null>;

  /**
   * Get user record containing all devices for a user
   * Returns null if user not found
   */
  getUserRecord(userId: UserID): Promise<UserRecord | null>;

  /**
   * Add a new device for a user
   * Used when discovering new devices via server device list
   */
  addDevice(
    userId: UserID,
    deviceId: DeviceID,
    identityKey: Uint8Array,
    prekeyBundle?: PreKeyBundleData
  ): Promise<void>;

  /**
   * Remove a device for a user
   * Deletes all sessions associated with that device
   */
  removeDevice(userId: UserID, deviceId: DeviceID): Promise<void>;

  /**
   * Update local device list based on server response
   * Adds new devices, removes deleted devices
   */
  syncDeviceList(deviceListResponse: DeviceListResponse): Promise<void>;

  /**
   * Delete sessions older than MAXRECV threshold
   * Callers should run this periodically
   */
  cleanupExpiredSessions(): Promise<number>;

  /**
   * Delete stale device records (orphaned sessions older than MAXLATENCY)
   * Callers should run this periodically
   */
  cleanupStaleRecords(): Promise<number>;

  /**
   * Check if a session can be used for sending
   * False if unacknowledged session age > maxUnacknowledgedSessionAge
   */
  canSendOnSession(sessionId: SessionID): Promise<boolean>;

  /**
   * Get SESAME statistics for debugging/monitoring
   */
  getStats(): Promise<SesameStats>;
}

/**
 * Statistics about SESAME state for debugging/monitoring
 */
export interface SesameStats {
  /** Total number of user records */
  totalUsers: number;

  /** Total number of device records across all users */
  totalDevices: number;

  /** Total number of active sessions */
  totalActiveSessions: number;

  /** Total number of inactive sessions */
  totalInactiveSessions: number;

  /** Number of sessions eligible for cleanup (age > MAXRECV) */
  expiredSessions: number;

  /** Number of stale device records eligible for cleanup */
  staleRecords: number;
}

// ============================================================================
// Event system
// ============================================================================

/**
 * Events emitted by SesameManager for observability and logging.
 *
 * Address-based callbacks expose key session lifecycle events for logging,
 * debugging, and UI updates.
 *
 * @see https://signal.org/docs/specifications/sesame/
 */
export interface SesameEvents {
  /**
   * Fired when a new session is established with a device.
   * This happens after successful X3DH/PQXDH key agreement.
   *
   * @param address - The ProtocolAddress of the remote device
   */
  onSessionEstablished?: (address: ProtocolAddress) => void;

  /**
   * Fired when an archived session is promoted to active (session convergence).
   * This happens during receive when decryption succeeds on an archived session.
   *
   * @param address - The ProtocolAddress of the remote device
   * @param fromBaseKey - The baseKey of the session that was promoted
   */
  onSessionConverged?: (address: ProtocolAddress, fromBaseKey: string) => void;

  /**
   * Fired when a new device is discovered for a user.
   * This happens when syncing the device list from the server.
   *
   * @param userId - The user who owns the new device
   * @param deviceId - The newly discovered device ID
   */
  onDeviceAdded?: (userId: UserID, deviceId: DeviceID) => void;

  /**
   * Fired when a device is removed from a user's account.
   * This happens when syncing the device list from the server.
   *
   * @param userId - The user who owned the removed device
   * @param deviceId - The removed device ID
   */
  onDeviceRemoved?: (userId: UserID, deviceId: DeviceID) => void;

  /**
   * Fired when a user's identity key changes (safety number change).
   * SECURITY EVENT: This could indicate a device reinstall OR a potential MITM attack.
   * Applications should prompt users to re-verify safety numbers.
   *
   * @param userId - The user whose identity key changed
   * @param newKey - The new identity public key
   */
  onIdentityKeyChanged?: (userId: UserID, newKey: Uint8Array) => void;

  /**
   * Fired when a session expires due to age thresholds.
   * - SEND_EXPIRED: Session can no longer send (age > MAXSEND)
   * - STALE: Session is ready for deletion (age > MAXRECV)
   *
   * @param address - The ProtocolAddress of the expired session
   * @param state - The new computed state (SEND_EXPIRED or STALE)
   */
  onSessionExpired?: (address: ProtocolAddress, state: ComputedSessionState) => void;

  /**
   * Fired when a security event occurs that may require user attention.
   * This is a catch-all for security-relevant events without a narrower hook.
   *
   * @param address - The ProtocolAddress involved
   * @param event - Description of the security event
   */
  onSecurityEvent?: (address: ProtocolAddress, event: string) => void;
}

// ============================================================================
// Error Types
// ============================================================================

/**
 * Base error class for SESAME-specific errors
 */
export class SesameError extends Error {
  constructor(
    message: string,
    public readonly code: string
  ) {
    super(message);
    this.name = 'SesameError';
  }
}

/**
 * Thrown when trying to send to a device with no active session
 * and session establishment fails
 */
export class NoActiveSessionError extends SesameError {
  constructor(userId: UserID, deviceId: DeviceID) {
    super(`No active session for device ${deviceId} of user ${userId}`, 'NO_ACTIVE_SESSION');
    this.name = 'NoActiveSessionError';
  }
}

/**
 * Thrown when message decryption fails on all available sessions
 */
export class DecryptionFailedError extends SesameError {
  constructor(sessionId: SessionID, attemptedSessions: number) {
    super(
      `Failed to decrypt message on session ${sessionId} (tried ${attemptedSessions} sessions)`,
      'DECRYPTION_FAILED'
    );
    this.name = 'DecryptionFailedError';
  }
}

/**
 * Thrown when device list is stale and needs refresh
 */
export class StaleDeviceListError extends SesameError {
  constructor(userId: UserID, localVersion: number, serverVersion: number) {
    super(
      `Device list stale for user ${userId}: local=${localVersion}, server=${serverVersion}`,
      'STALE_DEVICE_LIST'
    );
    this.name = 'StaleDeviceListError';
  }
}

/**
 * Thrown when a session expired and no longer works
 */
export class SessionExpiredError extends SesameError {
  constructor(sessionId: SessionID, age: number, threshold: number) {
    super(
      `Session ${sessionId} expired: age=${age}ms, threshold=${threshold}ms`,
      'SESSION_EXPIRED'
    );
    this.name = 'SessionExpiredError';
  }
}

/**
 * Thrown when a device record is not found
 */
export class SesameDeviceNotFoundError extends SesameError {
  constructor(message: string) {
    super(message, 'DEVICE_NOT_FOUND');
    this.name = 'SesameDeviceNotFoundError';
  }
}

/**
 * Thrown when a session record is not found
 */
export class SesameSessionNotFoundError extends SesameError {
  constructor(message: string) {
    super(message, 'SESSION_NOT_FOUND');
    this.name = 'SesameSessionNotFoundError';
  }
}

/**
 * Thrown when message decryption fails
 */
export class SesameDecryptionError extends SesameError {
  constructor(message: string) {
    super(message, 'DECRYPTION_ERROR');
    this.name = 'SesameDecryptionError';
  }
}

// ============================================================================
// Storage Interface
// ============================================================================

/**
 * Storage interface for SESAME session management.
 *
 * Each `DeviceRecord` carries its current session record and metadata.
 *
 * Implementations must be provided for different platforms.
 */
export interface ISesameStorage {
  // User record operations
  getUserRecord(userId: UserID): Promise<UserRecord | null>;
  setUserRecord(userId: UserID, record: UserRecord): Promise<void>;
  getAllUserIds(): Promise<UserID[]>;

  // Device record operations (includes session via DeviceRecord.session)
  getDeviceRecord(userId: UserID, deviceId: DeviceID): Promise<DeviceRecord | null>;
  setDeviceRecord(userId: UserID, deviceId: DeviceID, record: DeviceRecord): Promise<void>;
  deleteDeviceRecord(userId: UserID, deviceId: DeviceID): Promise<void>;

  // Session operations (convenience methods - delegate to DeviceRecord.session)
  /**
   * Get the session for a device.
   * @returns The SessionRecord, or null if no session exists.
   */
  getDeviceSession(userId: UserID, deviceId: DeviceID): Promise<SessionRecord | null>;

  /**
   * Set the session for a device.
   * This updates DeviceRecord.session.
   */
  setDeviceSession(userId: UserID, deviceId: DeviceID, session: SessionRecord): Promise<void>;

  // Cleanup operations
  cleanupExpiredSessions(maxRecv: number): Promise<number>;
  deleteStaleRecords(maxLatency: number): Promise<number>;
}
