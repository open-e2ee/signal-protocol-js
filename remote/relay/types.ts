/**
 * Signal relay interfaces for remote infrastructure.
 *
 * These are the DI contracts for relay-oriented remote services:
 * - ISignalRelayServer: Envelope delivery, device registry, prekey management
 * - ISignalRemoteSenderStateStore: Optional remote sender-key/skipped-key state
 *
 * @see docs/INTERFACES.md for full documentation
 */

// Import PreKeyBundle from keys module (uses branded types)
import type { PreKeyBundle, IdentityType, CompositeIdentityV1 } from '../../keys/types';
import type { SenderKeyState } from '../../internal/protocol/sender-keys/manager';
import type { RetryRequest } from '../../internal/sesame/types';
import { ContentHint } from '../../types/messages';
import type { GroupAuthorization } from '../../internal/groups-v2/manager';

// Re-export for consumers of this module
export {};
export type { PreKeyBundle, RetryRequest, IdentityType, CompositeIdentityV1 };

/** Device metadata used when attaching a device to an account identity. */
export interface AccountIdentityProvisioning {
  userId: string;
  deviceId: number;
  identity: CompositeIdentityV1;
  registrationId: number;
  identityType?: IdentityType;
}

/** Explicit account identity rotation guarded by the previously trusted tuple. */
export interface AccountIdentityRotation extends AccountIdentityProvisioning {
  expectedCurrentCommitment: Uint8Array;
}

// ════════════════════════════════════════════════════════════════════════════
// ISIGNALREMOTESENDERSTATESTORE
// ════════════════════════════════════════════════════════════════════════════

/**
 * Optional remote sender-state store for ExpoSignalStore.
 *
 * Provides server-side storage for:
 * - Sender Keys (group messaging)
 * - Skipped message keys (out-of-order decryption)
 *
 * NOTE: SESAME session metadata is stored locally only, following the Signal
 * Protocol SESAME specification.
 * The server only stores device registry, prekeys, and message mailbox.
 *
 * All methods are optional - ExpoSignalStore checks with `?.` before calling.
 * Pass a ConvexSignalRelayServer or similar backend to enable server-side storage.
 *
 * @example
 * ```typescript
 * const relay = new ConvexSignalRelayServer(convex, signalApi, {
 *   currentUserId: userId,
 * });
 * const keyStore = new ExpoSignalStore(relay);
 * ```
 */
export interface ISignalRemoteSenderStateStore {
  // ════════════════════════════════════════════════════════════
  // SENDER KEYS (GROUP MESSAGING)
  // ════════════════════════════════════════════════════════════

  /** Store sender key state */
  storeSenderKey?(
    senderKeyId: string,
    groupId: string,
    userId: string,
    deviceId: number,
    chainKey: string,
    signingKey: string,
    iteration: number,
    generation: number
  ): Promise<void>;

  /** Load sender key for a device */
  loadSenderKeyForDevice?(
    groupId: string,
    userId: string,
    deviceId: number
  ): Promise<SenderKeyState | null>;

  /** Delete a sender key */
  deleteSenderKey?(senderKeyId: string): Promise<void>;

  /** Load all sender keys for a group */
  loadAllSenderKeysForGroup?(groupId: string): Promise<SenderKeyState[]>;

  /** Delete all sender keys for a group */
  deleteAllSenderKeysForGroup?(groupId: string): Promise<number>;

  // ════════════════════════════════════════════════════════════
  // SKIPPED SENDER KEYS (OUT-OF-ORDER MESSAGES)
  // ════════════════════════════════════════════════════════════

  /** Store skipped message key for out-of-order decryption */
  storeSkippedSenderKey?(
    groupId: string,
    senderId: string,
    senderDeviceId: number,
    chainIndex: number,
    cipherKey: string,
    iv: string
  ): Promise<void>;

  /** Get skipped message key */
  getSkippedSenderKey?(
    groupId: string,
    senderId: string,
    senderDeviceId: number,
    chainIndex: number
  ): Promise<{ iv: string; cipherKey: string } | null>;

  /** Delete skipped message key after use */
  deleteSkippedSenderKey?(
    groupId: string,
    senderId: string,
    senderDeviceId: number,
    chainIndex: number
  ): Promise<void>;

  /** Count skipped keys for a sender */
  countSkippedSenderKeys?(
    groupId: string,
    senderId: string,
    senderDeviceId: number
  ): Promise<number>;

  /** Delete oldest skipped keys */
  deleteOldestSkippedSenderKeys?(
    groupId: string,
    senderId: string,
    senderDeviceId: number,
    count: number
  ): Promise<number>;
}

// ════════════════════════════════════════════════════════════════════════════
// IPROVISIONINGSERVICE
// ════════════════════════════════════════════════════════════════════════════

/**
 * Device provisioning service interface.
 *
 * Handles secure device linking via QR code scanning:
 * 1. Primary device creates session with ephemeral key
 * 2. New device scans QR, performs ECDH key agreement
 * 3. Primary encrypts and sends identity key
 * 4. New device decrypts and initializes
 *
 */
export interface IProvisioningService {
  /**
   * Create a new provisioning session.
   *
   * @param userId - User ID creating the session
   * @param ephemeralPublicKey - Base64-encoded ECDH public key for key agreement
   * @returns Session ID for the provisioning flow
   */
  createProvisioningSession(
    userId: string,
    ephemeralPublicKey: string
  ): Promise<{ sessionId: string }>;

  /**
   * Connect a new device to an existing provisioning session.
   *
   * @param sessionId - Provisioning session ID from QR code
   * @param ephemeralPublicKey - New device's ECDH public key (Base64)
   * @param deviceMetadata - Non-sensitive device information available before provisioning completes
   */
  connectNewDevice(
    sessionId: string,
    ephemeralPublicKey: string,
    deviceMetadata: {
      platform?: string;
      appVersion?: string;
      osVersion?: string;
    }
  ): Promise<void>;

  /**
   * Send encrypted provisioning message from primary to new device.
   *
   * @param sessionId - Provisioning session ID
   * @param encryptedMessage - AES-GCM encrypted payload (JSON string with ciphertext, iv, authTag)
   */
  sendProvisioningMessage(
    sessionId: string,
    encryptedMessage: string,
    userId?: string
  ): Promise<void>;

  /**
   * Get provisioning message for new device.
   *
   * @param sessionId - Provisioning session ID
   * @returns Status and encrypted message (if ready)
   */
  getProvisioningMessage(sessionId: string): Promise<{
    status:
      | 'waiting'
      | 'connected'
      | 'ready'
      | 'linked_pending_ack'
      | 'completed'
      | 'rolled_back'
      | 'expired';
    message: string | null;
  }>;

  /**
   * Mark provisioning as complete and finalize linked-device registration.
   *
   * @param sessionId - Session ID to complete
   * @param deviceMetadata - Final device metadata, including the encrypted device name
   */
  completeProvisioning(
    sessionId: string,
    deviceMetadata: {
      encryptedDeviceName: ArrayBuffer;
      platform?: string;
      appVersion?: string;
      osVersion?: string;
    }
  ): Promise<{ deviceId: number }>;

  /**
   * Acknowledge that the linked device finished persisting its local
   * bootstrap state, allowing the backend to clear the reversible
   * provisioning session state.
   *
   * @param sessionId - Session ID to finalize
   */
  acknowledgeProvisioning(sessionId: string): Promise<void>;

  /**
   * Undo a completed provisioning link if the new device fails to persist its
   * local bootstrap state after the server-side link succeeded.
   *
   * @param sessionId - Session ID to roll back
   */
  rollbackProvisioning(sessionId: string): Promise<void>;

  /**
   * Delete/cancel a provisioning session.
   *
   * @param sessionId - Session ID to delete
   */
  deleteProvisioningSession(sessionId: string, userId?: string): Promise<void>;
}

// ════════════════════════════════════════════════════════════════════════════
// IKEYROTATIONSERVICE
// ════════════════════════════════════════════════════════════════════════════

/**
 * Key rotation metadata service interface.
 *
 * Provides metadata queries for key rotation decisions.
 * Note: The actual key upload methods (uploadEcSignedPreKey, uploadKemLastResortPreKey, getPreKeyCount)
 * are already on ISignalRelayServer.
 *
 */
export interface IKeyRotationService {
  /**
   * Get EC signed prekey metadata for rotation checks and server key verification.
   *
   * @param userId - User ID
   * @param deviceId - Device ID
   * @param identityType - 'aci' or 'pni' (defaults to 'aci')
   * @returns Metadata with timestamps and publicKey, or null if no key exists
   */
  getEcSignedPreKeyMetadata(
    userId: string,
    deviceId: number,
    identityType?: IdentityType
  ): Promise<{
    keyId: number;
    createdAt: number;
    expiresAt: number;
    publicKey: string;
  } | null>;

  /**
   * Get KEM last-resort prekey metadata for rotation checks and server key verification.
   *
   * @param userId - User ID
   * @param deviceId - Device ID
   * @param identityType - 'aci' or 'pni' (defaults to 'aci')
   * @returns Metadata with timestamps, publicKey, and keyId, or null if no key exists
   */
  getKemLastResortPreKeyMetadata(
    userId: string,
    deviceId: number,
    identityType?: IdentityType
  ): Promise<{
    keyId: number;
    createdAt: number;
    expiresAt: number;
    publicKey: string;
  } | null>;
}

// ════════════════════════════════════════════════════════════════════════════
// ISIGNALRELAYSERVER
// ════════════════════════════════════════════════════════════════════════════

/**
 * Server-side relay for encrypted envelope push delivery.
 *
 * Responsibilities:
 * - Envelope delivery (push to devices via real-time subscription)
 * - Device registry (multi-device support, max 5 devices per user)
 * - Prekey management (X3DH/PQXDH key exchange)
 *
 * Maps to 17 Convex tables.
 *
 * @example
 * ```typescript
 * const relay: ISignalRelayServer = new ConvexSignalRelayServer(convex, signalApi, {
 *   currentUserId: userId,
 * });
 *
 * // Subscribe to incoming envelopes
 * const unsubscribe = relay.subscribe(userId, deviceId, (envelope) => {
 *   // Decrypt and process
 * });
 *
 * // Send encrypted envelope
 * await relay.send({
 *   targetUserId: 'bob',
 *   targetDeviceId: 1,
 *   senderUserId: 'alice',
 *   senderDeviceId: 1,
 *   ciphertext: encryptedBytes,
 *   messageType: 'ciphertext',
 * });
 * ```
 */
export interface ISignalRelayServer extends IProvisioningService, IKeyRotationService {
  // ════════════════════════════════════════════════════════════
  // ENVELOPE DELIVERY
  // Maps to: envelopes table
  // ════════════════════════════════════════════════════════════

  /**
   * Send encrypted envelope to a device.
   * Server pushes to recipient via their subscription.
   *
   * @param envelope - Encrypted envelope with targeting info
   * @returns Message ID and server timestamp (for delivery receipt matching)
   */
  send(envelope: Envelope): Promise<{ messageId: string; serverTimestamp: number }>;

  /**
   * Subscribe to incoming envelopes for this device.
   * Real-time push via Convex subscription / WebSocket.
   *
   * @param userId - Current user ID
   * @param deviceId - This device's ID (1-5)
   * @param onEnvelope - Callback for each incoming envelope
   * @param options - Optional batching callbacks for notification coalescing
   * @param options.onBatchStart - Called when first message in a batch arrives
   * @param options.onBatchEnd - Called when batch is complete (idle detected)
   * @returns Unsubscribe function
   */
  subscribe(
    userId: string,
    deviceId: number,
    onEnvelope: (envelope: Envelope) => void,
    options?: {
      onBatchStart?: () => void;
      onBatchEnd?: () => void;
    }
  ): Unsubscribe;

  /**
   * Mark envelope as delivered.
   * Depending on privacy settings, may delete immediately or mark for cleanup.
   *
   * @param envelopeId - ID from send() or subscription
   */
  markDelivered(envelopeId: string): Promise<void>;

  // ════════════════════════════════════════════════════════════
  // DEVICE REGISTRY
  // Maps to: devices table
  // ════════════════════════════════════════════════════════════

  /**
   * Get all active devices for a user.
   * Used for multi-device fanout during encryption.
   *
   * @param userId - Target user ID
   * @returns Array of device info (max 5 devices)
   */
  getDevices(userId: string): Promise<DeviceInfo[]>;

  /**
   * Register this device with the server.
   *
   * For first device: deviceId = 1 (PRIMARY_ID)
   * For linked devices: server assigns 2-5
   *
   * @param userId - Current user ID
   * @param device - Device registration info
   * @returns Assigned device ID
   */
  registerDevice(userId: string, device: DeviceRegistration): Promise<number>;

  /**
   * Remove a device from the registry.
   * Also deletes all prekeys and pending envelopes for that device.
   *
   * @param userId - User ID
   * @param deviceId - Device to remove
   */
  removeDevice(userId: string, deviceId: number): Promise<void>;

  // Note: Push token management is handled by convex/signal/push.ts
  // using @convex-dev/expo-push-notifications with device-aware composite keys.
  // See api.signal.push.recordToken/removeToken for token management.

  /**
   * Mark device as connected (online).
   * Called when WebSocket connects.
   * userId is derived from JWT server-side.
   *
   * @param deviceId - Device ID (1-5)
   */
  markDeviceConnected(deviceId: number): Promise<void>;

  /**
   * Mark device as disconnected (offline).
   * Called when WebSocket disconnects gracefully.
   * userId is derived from JWT server-side.
   *
   * @param deviceId - Device ID (1-5)
   */
  markDeviceDisconnected(deviceId: number): Promise<void>;

  /** Lightweight heartbeat — writes only to heartbeat table, triggers 0 query reruns */
  heartbeat(deviceId: number): Promise<void>;

  // ════════════════════════════════════════════════════════════
  // IDENTITY KEYS
  // Maps to: accounts table (account-level identity keys)
  // ════════════════════════════════════════════════════════════

  /**
   * Provision a device against the account-level canonical composite identity.
   * Creates an absent identity, accepts an exact tuple match for linked
   * devices, and rejects a different tuple without mutating device metadata.
   */
  provisionIdentityKey(request: AccountIdentityProvisioning): Promise<void>;

  /**
   * Rotate an existing account-level composite identity using compare-and-swap.
   * A successful rotation invalidates prekeys for every linked device in the
   * selected identity namespace.
   */
  rotateIdentityKey(request: AccountIdentityRotation): Promise<void>;

  /**
   * Get the account-level canonical composite identity.
   *
   * @param userId - Target user ID
   * @param identityType - 'aci' or 'pni' (defaults to 'aci')
   * @returns Composite identity or null if not found
   */
  getIdentityKey(userId: string, identityType?: IdentityType): Promise<CompositeIdentityV1 | null>;

  // ════════════════════════════════════════════════════════════
  // PREKEY MANAGEMENT (X3DH/PQXDH)
  // Maps to: ecPreKeys, ecSignedPreKeys, kemOneTimePreKeys, kemLastResortPreKeys
  // ════════════════════════════════════════════════════════════

  /**
   * Upload prekeys for this device (batch upload).
   *
   * Typically called:
   * - On registration: 100 EC + 1 signed + 100 KEM + 1 last-resort
   * - When count < 10: replenish one-time keys
   *
   * @param userId - User ID
   * @param deviceId - Device ID
   * @param keys - Array of prekeys to upload
   * @param identityType - 'aci' or 'pni' (defaults to 'aci')
   */
  uploadPreKeys(
    userId: string,
    deviceId: number,
    keys: PreKeyUpload[],
    identityType?: IdentityType
  ): Promise<void>;

  /**
   * Fetch prekey bundle for session establishment.
   *
   * Atomically consumes one EC and one KEM one-time prekey.
   * Returns bundle with identity key, signed prekey, and optional one-time keys.
   *
   * @param userId - Target user ID
   * @param deviceId - Target device ID
   * @param fetcherUserId - Deprecated, ignored. Fetcher identity is derived from auth server-side.
   * @param identityType - 'aci' or 'pni' (defaults to 'aci')
   * @returns Prekey bundle or null if device not found
   */
  fetchPreKeyBundle(
    userId: string,
    deviceId: number,
    fetcherUserId?: string,
    identityType?: IdentityType
  ): Promise<PreKeyBundle | null>;

  /**
   * Get count of remaining one-time prekeys.
   * Client should upload more when count < 10.
   *
   * @param userId - User ID
   * @param deviceId - Device ID
   * @param type - 'ec' for X25519, 'kem' for ML-KEM-1024
   * @param identityType - 'aci' or 'pni' (defaults to 'aci')
   */
  getPreKeyCount(
    userId: string,
    deviceId: number,
    type: 'ec' | 'kem',
    identityType?: IdentityType
  ): Promise<number>;

  /**
   * Clear stale KEM one-time prekeys during recovery.
   *
   * Called when PREKEY_NOT_FOUND indicates Bob has stale one-time KEM keys
   * on the server that he no longer has private keys for. Clearing them lets
   * subsequent bundle fetches select a current one-time or last-resort key.
   *
   * @param userId - User ID
   * @param deviceId - Device ID
   * @returns Number of keys cleared
   */
  clearStaleKemPreKeys(
    userId: string,
    deviceId: number,
    identityType?: IdentityType
  ): Promise<{ cleared: number }>;

  // ════════════════════════════════════════════════════════════
  // CONVENIENCE METHODS (wrap uploadPreKeys for common operations)
  // ════════════════════════════════════════════════════════════

  /**
   * Upload an EC signed prekey.
   * Convenience wrapper around uploadPreKeys for key rotation.
   *
   * @param userId - User ID
   * @param ecSignedPreKey - EC signed prekey to upload
   * @param identityType - 'aci' or 'pni' (defaults to 'aci')
   */
  uploadEcSignedPreKey(
    userId: string,
    ecSignedPreKey: EcSignedPreKeyUpload,
    identityType?: IdentityType
  ): Promise<void>;

  /**
   * Upload a KEM last-resort (post-quantum) prekey.
   * Convenience wrapper around uploadPreKeys for key rotation.
   *
   * @param userId - User ID
   * @param kemLastResortPreKey - KEM last-resort prekey to upload
   * @param identityType - 'aci' or 'pni' (defaults to 'aci')
   */
  uploadKemLastResortPreKey(
    userId: string,
    kemLastResortPreKey: KemLastResortPreKeyUpload,
    identityType?: IdentityType
  ): Promise<void>;

  // ════════════════════════════════════════════════════════════
  // GROUP MEMBER QUERY (Sender Keys)
  // ════════════════════════════════════════════════════════════

  /**
   * Get all devices in a group for message fanout.
   * Used for Sender Key group message delivery.
   *
   * @param groupId - Group identifier
   * @returns Array of member devices
   */
  getGroupMembers(groupId: string): Promise<GroupMemberDevice[]>;

  /**
   * Get all active devices for a user.
   * Used for local-first member resolution (caller provides user IDs,
   * relay resolves to device IDs).
   */
  getActiveDevices(userId: string): Promise<GroupMemberDevice[]>;

  // ════════════════════════════════════════════════════════════
  // GROUP STATE (GroupsV2 — encrypted, server-opaque)
  // Maps to: encryptedGroups + groupChangeLogs tables
  // ════════════════════════════════════════════════════════════

  /**
   * Create a new encrypted group on the server.
   * Server stores opaque ciphertext and never decrypts.
   *
   * @param groupId - 32-byte group identifier
   * @param encryptedState - Serialized EncryptedGroup (opaque to server)
   * @param authorization - ZK auth credential for anonymous group access
   */
  createGroupState(
    groupId: Uint8Array,
    encryptedState: Uint8Array,
    authorization: GroupAuthorization
  ): Promise<void>;

  /**
   * Get the latest encrypted group state.
   *
   * @param groupId - 32-byte group identifier
   * @param authorization - ZK auth credential for anonymous group access
   * @returns Encrypted state + current version, or null if not found
   */
  getGroupState(
    groupId: Uint8Array,
    authorization: GroupAuthorization
  ): Promise<{
    encryptedState: Uint8Array;
    version: number;
  } | null>;

  /**
   * Get group change log entries after a given version.
   * Used for incremental state synchronization.
   *
   * @param groupId - 32-byte group identifier
   * @param fromVersion - Fetch changes with version > fromVersion
   * @param authorization - ZK auth credential for anonymous group access
   * @returns Array of change log entries in version order
   */
  getGroupChanges(
    groupId: Uint8Array,
    fromVersion: number,
    authorization: GroupAuthorization
  ): Promise<GroupChangeEntry[]>;

  /**
   * Submit a group change with optimistic concurrency control.
   * Server validates expectedVersion === currentVersion before accepting.
   *
   * @param groupId - 32-byte group identifier
   * @param expectedVersion - Expected current version (for optimistic concurrency)
   * @param encryptedChange - Serialized GroupChange (opaque)
   * @param updatedEncryptedState - New full encrypted state after this change
   * @param authorization - ZK auth credential for anonymous group access
   * @returns Server signature binding this change
   * @throws ConflictError if expectedVersion !== currentVersion
   */
  submitGroupChange(
    groupId: Uint8Array,
    expectedVersion: number,
    encryptedChange: Uint8Array,
    updatedEncryptedState: Uint8Array,
    authorization: GroupAuthorization
  ): Promise<{ serverSignature: Uint8Array }>;

  // ════════════════════════════════════════════════════════════
  // ZK AUTH CREDENTIALS (anonymous group access)
  // ════════════════════════════════════════════════════════════

  /**
   * Issue a blinded auth credential for anonymous group access.
   *
   * @param userId - User requesting the credential
   * @returns Blinded auth credential bytes
   */
  issueAuthCredential(userId: string): Promise<Uint8Array>;

  /**
   * Refresh group send endorsements from the server.
   * Returns serialized endorsement response and expiration.
   *
   * @param groupId - 32-byte group identifier
   * @param authorization - ZK auth presentation + group public params
   * @returns Endorsement response bytes and expiration epoch seconds
   */
  refreshGroupSendEndorsements?(
    groupId: Uint8Array,
    authorization: GroupAuthorization
  ): Promise<{ endorsements: Uint8Array; expiration: number }>;

  // ════════════════════════════════════════════════════════════
  // SEALED SENDER (Anonymous Delivery)
  // Maps to: certificates (server-side issuance)
  // ════════════════════════════════════════════════════════════

  /**
   * Fetch a sender certificate for sealed sender messaging.
   *
   * The certificate binds the user's uuid, deviceId, and identity key,
   * signed by the server's trust root key. Expires after 24 hours.
   *
   * @param deviceId - Device ID (1-5) to bind the certificate to
   * @returns Base64-encoded serialized SenderCertificate
   */
  fetchSenderCertificate?(deviceId: number): Promise<string>;

  /**
   * Send a sealed sender message (anonymous delivery).
   *
   * The server does NOT know the sender. The ciphertext is an
   * UnidentifiedSenderMessage that the recipient unseals to discover
   * the sender's identity via the embedded certificate.
   *
   * @param envelope - Sealed sender envelope (senderUserId/senderDeviceId are empty strings/0)
   * @param auth - Authentication for anonymous delivery (access key or group send token)
   * @returns Message ID and server timestamp
   */
  sendUnidentified?(
    envelope: Envelope,
    auth: SealedSenderAuth
  ): Promise<{ messageId: string; serverTimestamp: number }>;

  /**
   * Send a V2 multi-recipient sealed sender message.
   *
   * Client sends the full V2 binary blob (base64-encoded).
   * Relay parses client-side, sends structured JSON to mutation.
   * Server constructs per-device ReceivedMessage blobs and fans out.
   *
   * @param sentMessageBase64 - Base64-encoded V2 multi-recipient binary blob
   * @param auth - Sealed sender authentication (access key or group send token)
   * @param timestamp - Client timestamp for message identification
   * @param groupId - Optional group ID for group messages
   * @param recipientUserIds - Original user IDs in same order as binary recipients
   * @returns Message ID, server timestamp, and list of unknown recipient UUIDs
   *
   */
  sendMultiRecipientUnidentified?(
    sentMessageBase64: string,
    auth: SealedSenderAuth,
    timestamp: number,
    groupId?: string,
    recipientUserIds?: string[],
    clientMessageId?: string
  ): Promise<{
    messageId: string;
    serverTimestamp: number;
    uuids404: string[];
  }>;

  // ════════════════════════════════════════════════════════════
  // RETRY REQUESTS (SESAME Spec §6.2)
  // Maps to: retryRequests table
  // ════════════════════════════════════════════════════════════

  /**
   * Send retry request to the original sender.
   *
   * Called by recipient when decryption fails. The retry request is
   * unencrypted (per SESAME spec) and contains only the message ID
   * and reason. Transport is TLS-secured.
   *
   * @param request - Retry request with sender/requester info and failed sequence number
   */
  sendRetryRequest?(request: RetryRequest): Promise<void>;

  /**
   * Subscribe to incoming retry requests for this device.
   *
   * Called by sender to listen for retry requests from recipients.
   * When a retry request arrives, the sender should:
   * 1. Look up the MessageRecord by sequence number
   * 2. Fetch the requester's current prekey bundle
   * 3. Establish a new session (X3DH/PQXDH)
   * 4. Re-encrypt and send the original message
   *
   * @param userId - Current user ID (the original sender)
   * @param deviceId - This device's ID
   * @param handler - Callback for each incoming retry request
   * @returns Unsubscribe function
   */
  subscribeRetryRequests?(
    userId: string,
    deviceId: number,
    handler: (request: RetryRequest) => Promise<void>
  ): Unsubscribe;
}

// ════════════════════════════════════════════════════════════════════════════
// SUPPORTING TYPES
// ════════════════════════════════════════════════════════════════════════════

/** Unsubscribe function returned by subscribe() */
export type Unsubscribe = () => void;

/**
 * Discriminated union for sealed sender authentication.
 *
 * Two auth paths for anonymous delivery:
 * - accessKey: Derived from recipient's profile key (pairwise messages)
 * - groupSendToken: ZK group send endorsement token (group messages)
 *
 */
export type SealedSenderAuth =
  | { type: 'accessKey'; unidentifiedAccessKey: string }
  | { type: 'groupSendToken'; groupSendToken: Uint8Array };

/**
 * Envelope for delivery (profile naming)
 *
 * Server treats ciphertext as opaque bytes (zero-knowledge).
 */
export interface Envelope {
  /** Target user ID */
  targetUserId: string;
  /** Target device ID (1-5) */
  targetDeviceId: number;

  /** Sender user ID */
  senderUserId: string;
  /** Sender device ID */
  senderDeviceId: number;

  /** Encrypted payload (base64 or Uint8Array) */
  ciphertext: string | Uint8Array;

  /**
   * Relay-visible envelope type.
   * Client-to-client types (delivery_receipt, typing_indicator, sender_key_distribution)
   * are encrypted content types inside a ciphertext envelope; the relay
   * contract carries only the outer envelope type.
   *
   * - ciphertext: Standard Double Ratchet message (contains encrypted Content)
   * - prekey_bundle: Session initiation (X3DH/PQXDH)
   * - plaintext_content: Sealed sender envelope
   * - server_delivery_receipt: Server-generated delivery receipts
   * - unidentified_sender: Sealed sender protocol messages
   */
  messageType:
    | 'ciphertext'
    | 'prekey_bundle'
    | 'plaintext_content'
    | 'server_delivery_receipt'
    | 'unidentified_sender';

  /** Push notification priority (default true). Non-urgent = silent push. */
  urgent?: boolean;

  /** Skip persistence if recipient offline (for typing indicators, receipts). */
  ephemeral?: boolean;

  /** Group ID (for group messages) */
  groupId?: string;

  /** Server-assigned envelope ID (set by server) */
  id?: string;

  /** Server timestamp (set by server) */
  serverTimestamp?: number;

  /**
   * Client timestamp for message identification.
   * Set by sender BEFORE encryption. Same value embedded in dataMessage.timestamp.
   * Used for: retry request matching, delivery receipt correlation, replay prevention.
   */
  timestamp: number;

  /**
   * Stable client-generated send identifier for idempotent retry.
   *
   * If a client retries after an unknown relay result, it should reuse the
   * same value so the relay can return the original accept metadata instead
   * of inserting a duplicate pending envelope.
   */
  clientMessageId?: string;

  // ════════════════════════════════════════════════════════════
  // STALE-DEVICE HANDLING
  // PreKeyMessages carry the registration ID for relay-side stale-device
  // detection. Stale-prekey detection remains client-side through
  // authentication failure and retry.
  // ════════════════════════════════════════════════════════════

  /**
   * Recipient's registration ID from the prekey bundle.
   * For PreKeyMessages only. Server validates this matches recipient's current registration.
   * If mismatch (device reinstalled), server returns STALE_DEVICE error (equivalent to HTTP 410).
   */
  recipientRegistrationId?: number;

  /**
   * Content hint for retry behavior per Signal Protocol.
   *
   * - IMPLICIT: Ephemeral messages (typing indicators, receipts) - silently discard on failure
   * - RESENDABLE: Content messages - can trigger retry requests
   * - DEFAULT: Standard handling
   *
   * Set by sender, used by recipient to decide retry behavior on decryption failure.
   */
  contentHint?: ContentHint;
}

// ════════════════════════════════════════════════════════════════════════════
// STALE SESSION ERROR TYPES
// ════════════════════════════════════════════════════════════════════════════

/** Error codes for stale session detection */
export type StaleSessionErrorCode = 'STALE_DEVICE';

/**
 * Error data for stale session errors.
 * Returned by server when session freshness validation fails.
 *
 * This SDK checks the registration ID at the relay boundary. Stale-prekey
 * detection remains client-side through authentication failure and retry.
 */
export interface StaleSessionErrorData {
  /** Error code identifying the type of staleness */
  code: StaleSessionErrorCode;
  /** List of stale device IDs */
  staleDevices: number[];
  /** Reason for staleness */
  reason: 'device_reinstalled';
  /** Human-readable error message */
  message: string;
  /** The registration ID sender expected */
  expectedRegistrationId?: number;
  /** The actual current registration ID */
  currentRegistrationId?: number;
}

/** Device info returned by getDevices() */
export interface DeviceInfo {
  deviceId: number;
  encryptedDeviceName?: ArrayBuffer;
  deviceType?: DeviceType;
  /** Device completed setup (has keys) - false = soft deleted */
  registered: boolean;
  /** Secondary device linked to primary (always false for primary deviceId=1) */
  linked: boolean;
  /** Whether device can receive messages (user-controlled) */
  enabled: boolean;
  /** Whether device is currently online (system-controlled) */
  active: boolean;
  lastSeen: number;
  createdAt: number;
  /** When the device was linked (for secondary devices) */
  linkedAt?: number;
}

/** Device type */
export type DeviceType = 'mobile' | 'desktop' | 'tablet' | 'web';

/** Device registration info */
export interface DeviceRegistration {
  deviceId?: number; // 1 = primary, undefined = auto-assign linked
  encryptedDeviceName?: ArrayBuffer;
  deviceType?: DeviceType;
  // Note: Push tokens are managed separately via convex/signal/push.ts
}

// Note: PushToken interface was removed - push tokens are now managed by
// @convex-dev/expo-push-notifications component via convex/signal/push.ts

/**
 * Prekey upload (batch).
 * Server stores in appropriate table based on `type`.
 */
export interface PreKeyUpload {
  /** Table to store in */
  type: 'ecPreKey' | 'ecSignedPreKey' | 'kemOneTimePreKey' | 'kemLastResortPreKey';
  /** Key ID (unique per type per device) */
  keyId: number;
  /** Public key (base64 encoded) */
  publicKey: string;
  /** Signature (for signed keys only) */
  signature?: string;
}

/**
 * EC signed prekey upload for key rotation.
 * Contains the full key including private key for local storage.
 */
export interface EcSignedPreKeyUpload {
  /** Key ID */
  keyId: number;
  /** Device ID (1=primary, 2-5=linked) */
  deviceId: number;
  /** Public key (base64 encoded) */
  publicKey: string;
  /** Signature from identity key (base64 encoded) */
  signature: string;
  /** Timestamp when generated */
  timestamp: number;
}

/**
 * KEM last-resort prekey upload for key rotation.
 * Contains the full key including private key for local storage.
 */
export interface KemLastResortPreKeyUpload {
  /** Key ID (always 1 per PQXDH spec Section 3.2) */
  keyId: number;
  /** Device ID (1=primary, 2-5=linked) */
  deviceId: number;
  /** Public key (base64 encoded, ~1.5KB for ML-KEM-1024) */
  publicKey: string;
  /** Signature from identity key (base64 encoded) */
  signature: string;
  /** Timestamp when generated */
  timestamp: number;
}

/**
 * Group member device info for message fanout.
 * Used by getGroupMembers() for Sender Key distribution.
 */
export interface GroupMemberDevice {
  /** User ID of the group member */
  userId: string;
  /** Device ID of the member's device */
  deviceId: number;
}

/**
 * Group change log entry returned by getGroupChanges().
 * All content is opaque to the server.
 */
export interface GroupChangeEntry {
  /** Revision number this change produces */
  version: number;
  /** Serialized GroupChange (opaque to server) */
  encryptedChange: Uint8Array;
  /** Server's binding signature for this change */
  serverSignature: Uint8Array;
  /** When the server accepted this change */
  timestamp: number;
}
