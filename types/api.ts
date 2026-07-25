/**
 * API interface definitions for Signal Protocol
 */

import type {
  PublicKey,
  Ciphertext,
  PreKeyBundle,
  IdentityKeyPair,
  EcSignedPreKey,
  EcOneTimePreKey,
  KyberPreKey,
  KemOneTimePreKey,
  IdentityType,
  CompositeIdentityV1,
  ContactIdentityRecord,
} from '../keys';
import type { SessionState, SessionRecord } from './session';
import type { ProtocolAddress } from './address';
import type { TrustDirection, IdentityKeyChange } from './trust';
import type { UserRecord, DeviceRecord } from '../internal/sesame/types';
import type { SenderKeyState } from '../internal/protocol/sender-keys/manager';
import type { ILogger } from '../logger';

// Re-export IdentityType for consumers
export {};
export type { IdentityType };

// Re-export SessionRecord for convenient access
export type { SessionRecord };

/**
 * All durable trust/session effects of establishing or advancing a session.
 * Optional one-time-prekey identifiers are consumed in the same transaction
 * for responder-side PreKey decrypts. The local identity namespace remains
 * explicit even when no prekey is consumed so every commit is fully scoped.
 */
export interface SessionTrustCommit {
  address: ProtocolAddress;
  record: SessionRecord;
  /** Sender tuple to pin or match in the same durable commit. */
  contactIdentity: CompositeIdentityV1;
  contactIdentityType: IdentityType;
  /** Local identity namespace; also scopes any consumed recipient prekeys. */
  localIdentityType: IdentityType;
  oneTimePreKeyId?: number;
  kemOneTimePreKeyId?: number;
}

/**
 * High-level encrypted messaging client interface.
 *
 * All methods accept a ProtocolAddress (userId + deviceId) instead of
 * string sessionId. This provides type safety and prevents format errors.
 *
 * @example
 * ```typescript
 * import { ProtocolAddress } from '@open-e2ee/signal-protocol-sdk';
 *
 * const bob = ProtocolAddress.create('bob', 1);
 * const encrypted = await signal.encryptMessage(bob, 'Hello!');
 * ```
 */
export interface ISignalProtocolClient {
  // ============================================================================
  // IDENTITY PROPERTIES
  // ============================================================================

  /**
   * User ID for this client instance
   */
  readonly userId: string;

  /**
   * Device ID for this client instance (1 = primary, 2-5 = linked)
   */
  readonly deviceId: number;

  /**
   * Resolved logger for this client instance.
   *
   * This is the client-scoped logger used throughout the Signal Protocol runtime.
   */
  readonly logger: Required<ILogger>;

  // ============================================================================
  // LIFECYCLE METHODS
  // ============================================================================

  /**
   * Register an event hook for Signal Protocol events
   *
   * Allows post-construction hook registration for flexibility.
   * Useful when the app needs to construct storage or content services after the
   * Signal Protocol client exists.
   *
   * @param name - Hook name
   * @param callback - Hook callback function
   *
   * @example
   * ```typescript
   * signal.registerHook('onMessageDecrypted', async (envelope) => {
   *   await contentManager.storeMessage(envelope);
   * });
   * ```
   */
  registerHook(name: string, callback: (...args: unknown[]) => void | Promise<void>): void;

  /**
   * Start the relay subscription for receiving encrypted messages.
   *
   * Startup is explicit so applications can register hooks before delivery
   * begins.
   */
  startRelaySubscription(): void;

  /**
   * Stop the relay subscription
   *
   * Pauses message processing without destroying client state.
   * Use when app backgrounds to let background task handle messages.
   * Call startRelaySubscription() to resume when app foregrounds.
   */
  stopRelaySubscription(): void;

  /**
   * Stop the client and cleanup resources
   *
   * Should be called on logout or app shutdown.
   */
  stop(): Promise<void>;

  /**
   * Run periodic cleanup of internal tracking state.
   *
   * Safe to call frequently - internally throttled to avoid overhead.
   * Recommended call sites:
   * - App foreground transition
   * - After successful message batch processing
   * - Periodically during long sessions
   *
   * Cleans up:
   * - Expired retry dedup entries (recentRetryRequests)
   *
   * @returns Number of entries cleaned up
   */
  runPeriodicCleanup(): number;

  // ============================================================================
  // KEY ROTATION
  // ============================================================================

  /**
   * Rotate EC signed prekey
   *
   * Rotates only once the current prekey is older than the configured refresh
   * interval ({@link KEY_REFRESH_INTERVAL_MS_DEFAULT}, 2 days by default).
   * Returns false if rotation is not needed yet.
   */
  rotateEcSignedPreKey(): Promise<boolean>;

  /**
   * Rotate Kyber prekey (post-quantum)
   *
   * Shares the signed prekey's refresh interval
   * ({@link KEY_REFRESH_INTERVAL_MS_DEFAULT}, 2 days by default).
   * Returns false if rotation is not needed yet.
   */
  rotateKyberPreKey(): Promise<boolean>;

  /** Explicit compare-and-swap rotation of the account-level relay identity. */
  rotateAccountIdentity(
    expectedCurrentCommitment: Uint8Array,
    identityType?: IdentityType
  ): Promise<void>;

  // ============================================================================
  // HIGH-LEVEL SEND API
  // ============================================================================

  /**
   * Send content to a recipient
   *
   * This is the primary API for sending encrypted content.
   * Automatically handles:
   * - Group vs user detection (Signal Protocol V2 prefix)
   * - Content type routing (DataMessageInput, string, Uint8Array)
   * - Multi-device fan-out
   * - Sender key distribution for groups
   *
   * @param recipientId - Group ID with V2 prefix or userId for direct messages
   * @param content - DataMessageInput, string, or raw Uint8Array bytes
   * @param options - Optional send options
   * @returns SendResult with messageId, timestamp, recipientDeviceCount
   *
   * @example
   * ```typescript
   * import { createGroupId } from '@open-e2ee/signal-protocol-sdk';
   *
   * // Send to group (use createGroupId helper)
   * await signal.send(createGroupId(groupId), content);
   *
   * // Send to user
   * await signal.send(userId, content);
   *
   * // Send raw bytes
   * await signal.send(recipient, new Uint8Array([...]));
   * ```
   */
  send(
    recipientId: string,
    content: import('../client/types').DataMessageInput | string | Uint8Array,
    options?: import('../client/types').SendOptions
  ): Promise<import('../client/types').SendResult>;

  /**
   * Encrypt and upload an attachment without sending a standalone message.
   *
   * Used by higher-level content types that want to carry attachment metadata
   * atomically inside another message payload.
   */
  uploadAttachment(
    data: Uint8Array,
    options: import('../client/types').SendOptions & { mimeType: string }
  ): Promise<import('../client/types').PreparedAttachmentUpload>;

  /**
   * Download, verify, and decrypt an uploaded attachment pointer.
   *
   * The client validates pointer metadata, verifies the encrypted blob digest,
   * and only returns plaintext after streaming AEAD authentication succeeds.
   */
  downloadAttachment(
    attachment: import('../media').MediaAttachmentPointer,
    options?: import('../client/types').AttachmentTransferOptions
  ): Promise<import('../client/types').DownloadedAttachment>;

  /**
   * Delete the encrypted remote object referenced by an attachment pointer.
   *
   * This only touches remote object storage. App-owned local message rows and
   * local media caches must be deleted by the application.
   */
  deleteRemoteAttachment(
    attachment: import('../media').MediaAttachmentPointer,
    options?: Pick<import('../client/types').AttachmentTransferOptions, 'signal' | 'onProgress'>
  ): Promise<void>;

  // ============================================================================
  // ENCRYPTION OPERATIONS
  // ============================================================================

  /**
   * Encrypt a message for a remote address
   *
   * @param remoteAddress - Remote party's protocol address (userId:deviceId)
   * @param plaintext - Message to encrypt
   */
  encryptMessage(remoteAddress: ProtocolAddress, plaintext: string): Promise<Ciphertext>;

  /**
   * Decrypt a message from a remote address
   *
   * @param remoteAddress - Remote party's protocol address (userId:deviceId)
   * @param ciphertext - Message to decrypt
   */
  decryptMessage(remoteAddress: ProtocolAddress, ciphertext: Ciphertext): Promise<string>;

  /**
   * Process an incoming encrypted message envelope.
   *
   * Unified entry point for both foreground (relay) and background (HTTP) message processing.
   * Handles decryption and automatically sends SESAME retry requests on retryable failures.
   *
   * This method:
   * 1. Decodes base64 ciphertext
   * 2. Decrypts message using Double Ratchet
   * 3. On retryable error: sends retry request via relay or options callback
   * 4. Re-throws error for caller to handle
   *
   * @param envelope - The encrypted message envelope
   * @param options - Transport callbacks for background (no relay) scenarios
   * @returns Decrypted plaintext
   * @throws EncryptionError after sending retry request if decryption fails
   *
   * @example
   * ```typescript
   * // Foreground (relay available)
   * const plaintext = await signal.processIncomingEnvelope(envelope);
   *
   * // Background (no relay)
   * const plaintext = await signal.processIncomingEnvelope(envelope, {
   *   sendRetryRequest: async (req) => {
   *     await convex.mutation(api.signal.messages.sendRetryRequest, req);
   *   }
   * });
   * ```
   */
  processIncomingEnvelope(
    envelope: import('../client/types').IncomingEnvelope,
    options?: import('../client/types').ProcessEnvelopeOptions
  ): Promise<string>;

  /**
   * Encrypt file blob with two-layer encryption
   * Returns encrypted blob and encrypted key
   *
   * @param remoteAddress - Remote party's protocol address (userId:deviceId)
   * @param fileBlob - File data to encrypt
   * @param mimeType - Optional MIME type for the file
   */
  encryptFile(
    remoteAddress: ProtocolAddress,
    fileBlob: Blob,
    mimeType?: string
  ): Promise<{
    encryptedBlob: Blob;
    keyId: string;
    encryptedKey: Ciphertext;
  }>;

  /**
   * Decrypt file blob
   *
   * @param remoteAddress - Remote party's protocol address (userId:deviceId)
   * @param encryptedBlob - Encrypted file data
   * @param encryptedKey - Encrypted file key
   */
  decryptFile(
    remoteAddress: ProtocolAddress,
    encryptedBlob: Blob,
    encryptedKey: Ciphertext
  ): Promise<Blob>;

  /**
   * Check if a session exists for a remote address
   *
   * @param remoteAddress - Remote party's protocol address (userId:deviceId)
   */
  hasSession(remoteAddress: ProtocolAddress): Promise<boolean>;

  /**
   * Establish a new session using remote party's prekey bundle
   *
   * @param remoteAddress - Remote party's protocol address (userId:deviceId)
   * @param prekeyBundle - Remote party's prekey bundle from server
   */
  establishSession(remoteAddress: ProtocolAddress, prekeyBundle: PreKeyBundle): Promise<void>;

  /**
   * Delete session (for session reset)
   *
   * @param remoteAddress - Remote party's protocol address (userId:deviceId)
   */
  deleteSession(remoteAddress: ProtocolAddress): Promise<void>;

  /**
   * Get health status for encryption sessions with a specific user.
   *
   * Checks session existence, key validity, key freshness, and expiration.
   * This is a client-side check that doesn't require server calls.
   *
   * @param userId - The user ID to check session health for
   * @returns SessionHealthResult with status and detailed diagnostics
   */
  getSessionHealth(userId: string): Promise<import('../client/types').SessionHealthResult>;

  // ============================================================================
  // GROUP MESSAGING (Sender Keys)
  // ============================================================================

  /**
   * Create a new sender key for group messaging
   *
   * @param groupId - Group identifier
   * @returns Sender key ID and distribution message to share with group members
   */
  createGroupSenderKey(groupId: string): Promise<{
    senderKeyId: string;
    distributionMessage: import('../internal/protocol/sender-keys').SenderKeyDistributionMessage;
  }>;

  /**
   * Process a sender key distribution message from another group member
   *
   * @param groupId - Group identifier
   * @param senderId - Sender's user ID
   * @param senderDeviceId - Sender's device ID
   * @param message - Distribution message containing the sender key
   */
  processGroupSenderKeyDistribution(
    groupId: string,
    senderId: string,
    senderDeviceId: number,
    message: import('../internal/protocol/sender-keys').SenderKeyDistributionMessage
  ): Promise<void>;

  /**
   * Encrypt a message for group using sender key (O(1) encryption)
   *
   * @param groupId - Group identifier
   * @param plaintext - Message to encrypt
   * @returns Framed SenderKeyMessage bytes
   */
  encryptGroupMessage(groupId: string, plaintext: string): Promise<Uint8Array>;

  /**
   * Decrypt a group message from a sender
   *
   * @param groupId - Group identifier
   * @param senderId - Sender's user ID
   * @param senderDeviceId - Sender's device ID
   * @param framedMessage - Framed SenderKeyMessage bytes
   * @returns Decrypted plaintext
   */
  decryptGroupMessage(
    groupId: string,
    senderId: string,
    senderDeviceId: number,
    framedMessage: Uint8Array
  ): Promise<string>;

  /**
   * Rotate sender key for a group (forward secrecy on membership changes)
   *
   * @param groupId - Group identifier
   * @returns New sender key ID and distribution message
   */
  rotateGroupSenderKey(groupId: string): Promise<{
    senderKeyId: string;
    distributionMessage: import('../internal/protocol/sender-keys').SenderKeyDistributionMessage;
  }>;

  /**
   * Delete sender key when leaving a group
   *
   * @param groupId - Group identifier
   */
  deleteGroupSenderKey(groupId: string): Promise<void>;

  /**
   * Check if we have a sender key for a group
   *
   * @param groupId - Group identifier
   * @returns True if sender key exists
   */
  hasGroupSenderKey(groupId: string): Promise<boolean>;

  /**
   * Get the current sender key distribution message for a group
   *
   * @param groupId - Group identifier
   * @returns Distribution message or null if no key exists
   */
  getGroupSenderKeyDistribution(
    groupId: string
  ): Promise<import('../internal/protocol/sender-keys').SenderKeyDistributionMessage | null>;

  /**
   * Distribute sender key to a specific user via pairwise encryption
   *
   * @param groupId - Group identifier
   * @param recipientUserId - Recipient user ID to distribute key to
   */
  distributeSenderKeyToUser(groupId: string, recipientUserId: string): Promise<void>;

  /**
   * Distribute sender key to all group members
   *
   * @param groupId - Group identifier
   * @param memberUserIds - Array of all member user IDs
   */
  distributeGroupSenderKey(groupId: string, memberUserIds: string[]): Promise<void>;

  /**
   * Handle group membership change with appropriate sender key actions
   *
   * @param groupId - Group identifier
   * @param change - Type of membership change
   * @returns Distribution message if rotation occurred
   */
  handleGroupMembershipChange(
    groupId: string,
    change: 'member_added' | 'member_removed' | 'metadata_changed'
  ): Promise<{
    rotated: boolean;
    distributionMessage?: import('../internal/protocol/sender-keys').SenderKeyDistributionMessage;
  }>;

  // ============================================================================
  // READ RECEIPTS
  // ============================================================================

  /**
   * Send read receipt to original message sender (all devices)
   *
   * Called when the user views messages in a conversation.
   * Similar to delivery receipts but indicates message was actually read.
   * Multi-device: fans out to all known devices for the sender.
   *
   * @param recipientUserId - Original sender's user ID
   * @param timestamps - Server timestamps of messages that were read
   */
  sendReadReceipt(recipientUserId: string, timestamps: number[]): Promise<void>;

  /**
   * Send viewed receipt to original message sender (all devices).
   *
   * Used for content where "opened" matters semantically, such as view-once
   * attachments. This follows the same privacy gate as read receipts.
   */
  sendViewedReceipt(recipientUserId: string, timestamps: number[]): Promise<void>;

  /**
   * Sync local read state to the account's other linked devices.
   *
   * This is separate from read receipts: it updates our own devices so they
   * stay in sync even when remote read receipts are disabled.
   */
  syncReadToLinkedDevices(
    entries: import('../client/content-adapter').ReadSyncEntryInput[]
  ): Promise<void>;

  /**
   * Sync a local view-once open event to the account's other linked devices.
   *
   * This is account-local device state, not a sender-facing receipt.
   */
  syncViewOnceOpenToLinkedDevices(
    entry: import('../client/content-adapter').ViewOnceOpenSyncInput
  ): Promise<void>;

  /**
   * Sync a local media attachment delete event to the account's other linked devices.
   *
   * This is account-local device state, not a sender-facing receipt. The app
   * remains responsible for applying the delete to its local media cache.
   */
  syncMediaAttachmentDeleteToLinkedDevices(
    entry: import('../client/content-adapter').MediaAttachmentDeleteSyncInput
  ): Promise<void>;

  /**
   * Sync account-level communication/privacy configuration to linked devices.
   *
   * This is linked-device state, not a sender-facing receipt. It should carry
   * the current local snapshot for supported fields.
   */
  syncConfigurationToLinkedDevices(
    configuration: import('../client/content-adapter').ConfigurationSyncInput
  ): Promise<void>;

  /**
   * Sync local username and username-link state to linked devices.
   *
   * This is account-local state, not sender-facing content.
   */
  syncUsernameStateToLinkedDevices(
    usernameState: import('../client/content-adapter').UsernameStateSyncInput
  ): Promise<void>;

  /**
   * Sync learned recipient username metadata to linked devices.
   *
   * Remote usernames are transient lookup data, but once learned on one device
   * they should be available on the account's other linked devices.
   */
  syncRecipientUsernameToLinkedDevices(
    recipientUsername: import('../client/content-adapter').RecipientUsernameSyncInput
  ): Promise<void>;

  /**
   * Sync explicit safety-number verification state to the account's other linked devices.
   *
   * Only explicit `verified` and cleared-to-`default` states belong here;
   * conflict/untrusted state is still derived locally from identity-key changes.
   */
  syncVerificationStateToLinkedDevices(
    verificationState: import('../client/content-adapter').VerificationStateSyncInput
  ): Promise<void>;

  /**
   * Sync task-notification acknowledgment state to the account's other linked devices.
   *
   * This is app-level linked-device notification state, not sender-facing content.
   */
  syncTaskNotificationAckToLinkedDevices(
    input: Omit<
      import('../client/content-adapter').TaskNotificationAckSyncInput,
      'acknowledgedOnDevice'
    >
  ): Promise<void>;

  /**
   * Sync the current blocked-recipient snapshot to linked devices.
   *
   * The full current snapshot replaces the local linked-device projection
   * instead of applying deltas.
   */
  syncBlockedRecipientsToLinkedDevices(
    blocked: import('../client/content-adapter').BlockedRecipientsSyncInput
  ): Promise<void>;

  /**
   * Send typing indicator to conversation recipient
   *
   * Typing indicators are application-layer messages that:
   * - Use the same encrypted channel as regular messages
   * - Are NOT stored on the server (transient)
   * - Respect privacy settings (mutual opt-in required)
   *
   * @param recipientUserId - Recipient's user ID
   * @param recipientDeviceId - Recipient's device ID
   * @param conversationId - The conversation ID
   * @param action - Whether user STARTED or STOPPED typing
   * @param groupId - Optional group ID for group conversations
   */
  sendTypingIndicator(
    recipientUserId: string,
    recipientDeviceId: number,
    conversationId: string,
    action: import('../client/types').TypingAction,
    groupId?: string
  ): Promise<void>;
}

/**
 * Signal Protocol manager interface
 */
export interface ISignalProtocolManager {
  /**
   * Initialize identity keys on first launch
   * @param identityTypes - Identity types to generate keys for (defaults to ['aci', 'pni'])
   */
  initialize(identityTypes?: readonly IdentityType[]): Promise<void>;

  /**
   * Set local user and device identity.
   *
   * This must be called before any session operations (encrypt/decrypt).
   * It's normally called by generatePreKeyBundle, but can be called directly
   * when keys already exist and don't need regeneration.
   *
   * @param userId - User ID for this client
   * @param deviceId - Device ID (1 for primary, 2-5 for linked devices)
   */
  setLocalIdentity(userId: string, deviceId: number): void;

  /**
   * Generate and upload prekey bundle
   * @param userId - Local user's ID
   * @param deviceId - Local device's ID (required, no default)
   * @param identityType - 'aci' or 'pni' (defaults to 'aci')
   */
  generatePreKeyBundle(
    userId: string,
    deviceId: number,
    identityType?: IdentityType
  ): Promise<void>;

  /**
   * Start a new session with a remote party
   *
   * @param remoteAddress - Remote party's protocol address (userId:deviceId)
   * @param prekeyBundle - Remote user's prekey bundle
   */
  startSession(
    remoteAddress: ProtocolAddress,
    prekeyBundle: PreKeyBundle,
    recipientIdentityType?: IdentityType
  ): Promise<void>;

  /**
   * Encrypt a message using existing session
   *
   * @param remoteAddress - Remote party's protocol address (userId:deviceId)
   * @param plaintext - Message to encrypt
   */
  encrypt(remoteAddress: ProtocolAddress, plaintext: string): Promise<Ciphertext>;

  /**
   * Decrypt a message using existing session
   *
   * @param remoteAddress - Remote party's protocol address (userId:deviceId)
   * @param ciphertext - Message to decrypt
   */
  decrypt(remoteAddress: ProtocolAddress, ciphertext: Ciphertext): Promise<string>;

  /**
   * Get the session record for a remote address.
   *
   * Used by SESAME to sync sessions after PreKeyMessage decryption.
   * Per SESAME specification, after the responder decrypts a PreKeyMessage,
   * the session needs to be synced from KeyStorage to DeviceRecord.
   *
   * @param remoteAddress - Remote party's protocol address (userId:deviceId)
   * @returns The session record, or null if no session exists
   */
  getSession(remoteAddress: ProtocolAddress): Promise<SessionRecord | null>;

  /**
   * Rotate EC signed prekey (on the configured refresh interval, 2 days by default)
   */
  rotateEcSignedPreKey(userId: string): Promise<void>;

  /**
   * Rotate Kyber prekey (post-quantum security, same interval as the signed prekey)
   */
  rotateKyberPreKey(userId: string): Promise<void>;

  /**
   * Clean up expired message keys for a session
   *
   * Signal Protocol Section 8.4 recommends deleting message keys older than
   * one week to avoid excessive storage. This method explicitly triggers cleanup.
   *
   * Note: Cleanup also happens automatically during encrypt/decrypt operations.
   *
   * @param remoteAddress - Remote party's protocol address (userId:deviceId)
   */
  cleanupExpiredKeys(remoteAddress: ProtocolAddress): Promise<void>;

  /**
   * Get identity public key
   */
  getIdentityPublicKey(): Promise<PublicKey>;
}

// ============================================================================
// FOCUSED STORE INTERFACES
// ============================================================================
//
// Breaking ISignalLocalStore into focused interfaces provides:
//
// 1. Interface Segregation: Implementations only need to implement what they use
// 2. Verifiable seams: substitute individual stores without implementing everything
// 3. Clearer responsibility boundaries
// 4. Independently replaceable persistence responsibilities
//
// ============================================================================

/**
 * Identity store with an SDK-oriented API and SDK composite-identity values.
 *
 * Manages local identity keys and contact identity verification. TOFU detects
 * changes after a tuple is pinned; it does not authenticate first contact.
 *
 */
export interface IIdentityKeyStore {
  /**
   * Store our identity key pair (only done once per install per identity type).
   * @param keyPair - Identity key pair to store
   * @param identityType - 'aci' or 'pni' (defaults to 'aci')
   */
  storeIdentityKey(keyPair: IdentityKeyPair, identityType?: IdentityType): Promise<void>;

  /**
   * Retrieve our identity key pair.
   * @param identityType - 'aci' or 'pni' (defaults to 'aci')
   */
  getIdentityKey(identityType?: IdentityType): Promise<IdentityKeyPair | null>;

  /**
   * Check if identity key exists.
   * @param identityType - 'aci' or 'pni' (defaults to 'aci')
   */
  hasIdentityKey(identityType?: IdentityType): Promise<boolean>;

  /**
   * Get our local registration ID.
   *
   * Registration ID is a random 16-bit integer generated once per install.
   * Used to detect session resets when app is reinstalled.
   * @param identityType - 'aci' or 'pni' (defaults to 'aci')
   */
  getLocalRegistrationId(identityType?: IdentityType): Promise<number>;

  /**
   * Set our local registration ID.
   *
   * Should only be called once during initialization.
   * @param id - Registration ID
   * @param identityType - 'aci' or 'pni' (defaults to 'aci')
   */
  setLocalRegistrationId(id: number, identityType?: IdentityType): Promise<void>;

  /**
   * Save a contact's identity key and detect changes.
   *
   * This is used for Trust On First Use (TOFU) and post-pinning change
   * detection. Returns whether either composite component changed.
   *
   * @param address - Contact's protocol address
   * @param identity - Contact's complete canonical composite identity
   * @param identityType - ACI or PNI trust namespace
   * @param suppliedCommitment - Optional redundant commitment that must match
   * @returns IdentityKeyChange indicating if key is new or changed
   */
  saveContactIdentity(
    address: ProtocolAddress,
    identity: CompositeIdentityV1,
    identityType?: IdentityType,
    suppliedCommitment?: Uint8Array
  ): Promise<IdentityKeyChange>;

  /**
   * Get a contact's saved identity key.
   *
   * Returns null if no identity key has been saved for this address.
   *
   * @param address - Contact's protocol address
   * @returns Contact's identity key or null
   */
  getContactIdentity(
    address: ProtocolAddress,
    identityType?: IdentityType
  ): Promise<ContactIdentityRecord | null>;

  /**
   * Explicitly accept a changed tuple and atomically delete every session for
   * that user; the previous tuple becomes rollback history.
   */
  acceptContactIdentityRotation(
    address: ProtocolAddress,
    identity: CompositeIdentityV1,
    identityType?: IdentityType,
    suppliedCommitment?: Uint8Array
  ): Promise<ContactIdentityRecord>;

  /** Promote the exact current tuple after authenticated comparison. */
  verifyContactIdentity(
    address: ProtocolAddress,
    identity: CompositeIdentityV1,
    identityType?: IdentityType,
    suppliedCommitment?: Uint8Array
  ): Promise<ContactIdentityRecord>;

  /**
   * Check if a contact's identity key is trusted.
   *
   * Trust verification behavior depends on direction:
   * - SENDING: Stricter - don't send to untrusted identities
   * - RECEIVING: More permissive - allow receiving but warn user
   *
   * From Signal Protocol:
   * "It's safer to receive from an unknown identity than to send to one"
   *
   * @param address - Contact's protocol address
   * @param identity - Complete composite identity candidate
   * @param direction - Whether we're sending or receiving
   * @param identityType - ACI or PNI trust namespace
   * @returns true if identity is trusted
   */
  isTrustedIdentity(
    address: ProtocolAddress,
    identity: CompositeIdentityV1,
    direction: TrustDirection,
    identityType?: IdentityType
  ): Promise<boolean>;
}

/**
 * EC one-time PreKey store with an SDK-oriented API.
 *
 * Manages EC one-time prekeys for forward secrecy.
 * One-time prekeys are consumed after use and cannot be reused.
 *
 */
export interface IEcOneTimePreKeyStore {
  /**
   * Store EC one-time prekeys.
   * @param identityType - 'aci' or 'pni' (defaults to 'aci')
   */
  storeEcOneTimePreKeys(prekeys: EcOneTimePreKey[], identityType?: IdentityType): Promise<void>;

  /**
   * Retrieve all EC one-time prekeys.
   * @param identityType - 'aci' or 'pni' (defaults to 'aci')
   */
  getEcOneTimePreKeys(identityType?: IdentityType): Promise<EcOneTimePreKey[]>;

  /**
   * Remove an EC one-time prekey after it has been used.
   *
   * @param preKeyId - ID of the prekey to remove
   * @param identityType - 'aci' or 'pni' (defaults to 'aci')
   */
  removeEcOneTimePreKey(preKeyId: number, identityType?: IdentityType): Promise<void>;
}

/**
 * EC Signed PreKey store with an SDK-oriented API.
 *
 * Manages rotating EC signed prekeys for medium-term forward secrecy.
 * EC signed prekeys are rotated on the configured refresh interval (2 days by
 * default), but OLD prekeys must be kept for a grace period (~30 days) to
 * handle in-flight messages.
 *
 * Per X3DH Spec Section 4.4:
 * "After uploading a new signed prekey, Bob may keep the private key
 * corresponding to the previous signed prekey around for some period
 * of time, to handle messages using it that have been delayed in transit."
 *
 * @see https://signal.org/docs/specifications/x3dh/
 */
export interface IEcSignedPreKeyStore {
  /**
   * Store EC signed prekey.
   *
   * When storing a new EC signed prekey (rotation), the old one should be
   * archived (not deleted) to handle in-flight messages.
   * @param identityType - 'aci' or 'pni' (defaults to 'aci')
   */
  storeEcSignedPreKey(signedPreKey: EcSignedPreKey, identityType?: IdentityType): Promise<void>;

  /**
   * Retrieve EC signed prekey by ID.
   *
   * @param keyId - Optional key ID to retrieve. If not provided, returns the current (most recent) EC signed prekey.
   * @param identityType - 'aci' or 'pni' (defaults to 'aci')
   * @returns The EC signed prekey, or null if not found
   */
  getEcSignedPreKey(keyId?: number, identityType?: IdentityType): Promise<EcSignedPreKey | null>;

  /**
   * Get all stored EC signed prekeys (current + archived).
   *
   * Used for cleanup and debugging.
   * @param identityType - 'aci' or 'pni' (defaults to 'aci')
   */
  getAllEcSignedPreKeys?(identityType?: IdentityType): Promise<EcSignedPreKey[]>;

  /**
   * Remove an EC signed prekey by ID.
   *
   * Called during cleanup to remove expired archived prekeys.
   * Should NEVER remove the current (most recent) EC signed prekey.
   *
   * @param keyId - The key ID to remove
   * @param identityType - 'aci' or 'pni' (defaults to 'aci')
   */
  removeEcSignedPreKey?(keyId: number, identityType?: IdentityType): Promise<void>;
}

/**
 * Kyber Last-Resort PreKey store interface (post-quantum security).
 *
 * Manages the ML-KEM-1024 (Kyber) last-resort prekey for post-quantum forward secrecy.
 * This is a reusable fallback key (like EC signed prekeys) that rotates on the
 * configured refresh interval (2 days by default).
 *
 * Naming convention matches EC prekeys:
 * - `IEcOneTimePreKeyStore` → one-time EC prekeys (`ecPreKeys`)
 * - `IEcSignedPreKeyStore` → reusable EC prekey (`ecSignedPreKeys`)
 * - `IKemPreKeyStore` → one-time KEM prekeys (`kemOneTimePreKeys`) - FUTURE
 * - `IKyberLastResortPreKeyStore` → reusable KEM prekey (`kemLastResortPreKeys`)
 *
 * @see https://signal.org/docs/specifications/pqxdh/
 */
export interface IKyberLastResortPreKeyStore {
  /**
   * Store Kyber prekey (post-quantum security).
   * @param identityType - 'aci' or 'pni' (defaults to 'aci')
   */
  storeKyberPreKey(kyberPreKey: KyberPreKey, identityType?: IdentityType): Promise<void>;

  /**
   * Retrieve Kyber prekey.
   * @param identityType - 'aci' or 'pni' (defaults to 'aci')
   */
  getKyberPreKey(identityType?: IdentityType): Promise<KyberPreKey | null>;

  /**
   * Mark a Kyber prekey as used.
   *
   * Kyber prekeys can be reused (unlike one-time prekeys) but should be
   * tracked to ensure proper rotation.
   *
   * @param kyberPreKeyId - ID of the Kyber prekey that was used
   * @param signedPreKeyId - ID of the signed prekey used in combination
   * @param baseKeyBytes - Base key bytes for the session
   * @param identityType - 'aci' or 'pni' (defaults to 'aci')
   */
  markKyberPreKeyUsed(
    kyberPreKeyId: number,
    signedPreKeyId: number,
    baseKeyBytes: Uint8Array,
    identityType?: IdentityType
  ): Promise<void>;
}

/**
 * Kyber One-Time PreKey store interface (post-quantum security).
 *
 * Manages one-time ML-KEM-1024 (Kyber) prekeys for per-session post-quantum forward secrecy.
 * One-time KEM prekeys are consumed after use and provide additional security layer
 * beyond the last-resort Kyber prekey.
 *
 * Naming convention matches EC prekeys:
 * - `IEcOneTimePreKeyStore` → one-time EC prekeys (`ecPreKeys`)
 * - `IKemPreKeyStore` → one-time KEM prekeys (`kemOneTimePreKeys`)
 *
 * @see https://signal.org/docs/specifications/pqxdh/ Section 3.2
 */
export interface IKemPreKeyStore {
  /**
   * Store one-time KEM prekeys (batch storage).
   * @param identityType - 'aci' or 'pni' (defaults to 'aci')
   */
  storeKemOneTimePreKeys(prekeys: KemOneTimePreKey[], identityType?: IdentityType): Promise<void>;

  /**
   * Retrieve all one-time KEM prekeys.
   * @param identityType - 'aci' or 'pni' (defaults to 'aci')
   */
  getKemOneTimePreKeys(identityType?: IdentityType): Promise<KemOneTimePreKey[]>;

  /**
   * Retrieve a specific one-time KEM prekey by ID.
   * Used during session establishment to find the key for decapsulation.
   * @param identityType - 'aci' or 'pni' (defaults to 'aci')
   */
  getKemOneTimePreKey(keyId: number, identityType?: IdentityType): Promise<KemOneTimePreKey | null>;

  /**
   * Remove a one-time KEM prekey after it has been used.
   *
   * CRITICAL: Must be called immediately after successful decapsulation
   * to provide per-session post-quantum forward secrecy.
   *
   * @param keyId - ID of the prekey to remove
   * @param identityType - 'aci' or 'pni' (defaults to 'aci')
   */
  removeKemOneTimePreKey(keyId: number, identityType?: IdentityType): Promise<void>;

  /**
   * Get count of available one-time KEM prekeys.
   * Used to determine when to replenish the prekey pool.
   * @param identityType - 'aci' or 'pni' (defaults to 'aci')
   */
  getKemOneTimePreKeyCount(identityType?: IdentityType): Promise<number>;
}

/**
 * Session store for current package session records.
 *
 * Manages Double Ratchet session state with support for session archiving
 * and the Sesame algorithm for session convergence.
 *
 */
export interface ISessionStore {
  /**
   * Store session record with current + archived sessions.
   *
   * This is the preferred API for session storage, supporting session archiving
   * and handling race conditions.
   *
   * @param address - Protocol address for this session
   * @param record - SessionRecord containing current and archived sessions
   */
  storeSessionRecord(address: ProtocolAddress, record: SessionRecord): Promise<void>;

  /**
   * Retrieve session record.
   *
   * @param address - Protocol address
   * @returns SessionRecord or null if no session exists
   */
  getSessionRecord(address: ProtocolAddress): Promise<SessionRecord | null>;

  /**
   * Delete session record.
   *
   * @param address - Protocol address
   */
  deleteSessionRecord(address: ProtocolAddress): Promise<void>;

  /**
   * Archive the current session and optionally start a new one.
   *
   * Used when:
   * - Identity key changes (possible MITM)
   * - Registration ID changes (app reinstall detected)
   * - Manual session reset
   *
   * @param address - Protocol address
   * @param newSession - Optional new session to set as current
   */
  archiveCurrentSession(address: ProtocolAddress, newSession?: SessionState | null): Promise<void>;

  /**
   * Get all sessions for a user (across all their devices).
   *
   * Useful for multi-device scenarios where one user has multiple devices.
   *
   * @param userId - User ID (not including device ID)
   * @returns Array of session records for all of this user's devices
   */
  getSessionsForUser(userId: string): Promise<SessionRecord[]>;

  /**
   * Check if a session exists for the given address.
   *
   * @param address - Protocol address
   * @returns true if session exists
   */
  hasSession(address: ProtocolAddress): Promise<boolean>;

  /**
   * Get the count of active sessions.
   *
   * @returns Number of sessions stored
   */
  getSessionCount(): Promise<number>;
}

/**
 * SESAME store interface for multi-device session management.
 *
 * Implements the SESAME algorithm for automatic session convergence
 * across multiple devices.
 *
 * Session state is stored directly on each `DeviceRecord`.
 *
 * @see https://signal.org/docs/specifications/sesame/
 */
export interface ISesameStore {
  /**
   * Get user record containing all devices for a user.
   */
  getUserRecord(userId: string): Promise<UserRecord | null>;

  /**
   * Store user record.
   */
  setUserRecord(userId: string, record: UserRecord): Promise<void>;

  /**
   * Get device record for a specific user's device.
   */
  getDeviceRecord(userId: string, deviceId: number): Promise<DeviceRecord | null>;

  /**
   * Store device record.
   */
  setDeviceRecord(userId: string, deviceId: number, record: DeviceRecord): Promise<void>;

  /**
   * Delete device record.
   */
  deleteDeviceRecord(userId: string, deviceId: number): Promise<void>;

  /**
   * Get the session for a device.
   * @returns The SessionRecord, or null if no session exists.
   */
  getDeviceSession(userId: string, deviceId: number): Promise<SessionRecord | null>;

  /**
   * Set the session for a device.
   * This updates DeviceRecord.session.
   */
  setDeviceSession(userId: string, deviceId: number, session: SessionRecord): Promise<void>;

  /**
   * Delete stale device records (orphaned sessions older than MAXLATENCY).
   */
  deleteStaleRecords(maxLatency: number): Promise<number>;

  /**
   * Delete expired sessions (sessions older than MAXRECV threshold).
   */
  cleanupExpiredSessions(maxRecv: number): Promise<number>;

  /**
   * Get all user IDs with SESAME records.
   */
  getAllUserIds(): Promise<string[]>;

  /**
   * Get all device IDs for a specific user.
   */
  getSesameDeviceIds(userId: string): Promise<number[]>;
}

/**
 * Sender Key store interface for group messaging.
 *
 * Manages sender keys for efficient group encryption using the
 * Sender Key Distribution Message protocol.
 */
export interface ISenderKeyStore {
  /**
   * Store sender key state for a group member device.
   */
  storeSenderKey(
    groupId: string,
    userId: string,
    deviceId: number,
    state: SenderKeyState
  ): Promise<void>;

  /**
   * Retrieve sender key state for a group member device.
   */
  getSenderKey(groupId: string, userId: string, deviceId: number): Promise<SenderKeyState | null>;

  /**
   * Delete sender key for a group member device.
   */
  deleteSenderKey(groupId: string, userId: string, deviceId: number): Promise<void>;

  /**
   * Get all sender keys for a group (for admin operations).
   */
  getAllSenderKeysForGroup(groupId: string): Promise<SenderKeyState[]>;

  /**
   * Delete all sender keys for a group (when group is deleted).
   */
  deleteAllSenderKeysForGroup(groupId: string): Promise<number>;

  // ════════════════════════════════════════════════════════════════
  // SENDER KEY RECORD (current + previous states for rotation window)
  // ════════════════════════════════════════════════════════════════

  /**
   * Store all sender key states (current + previous) for a group member device.
   *
   * The first element is the current state; remaining are previous states
   * retained during the rotation window for decrypting in-flight messages.
   *
   * Per Sender Keys spec Section 5.1: "Implementations MUST store sender key
   * state persistently." This method persists the full record atomically.
   *
   * @param groupId - Group identifier
   * @param userId - User identifier
   * @param deviceId - Device identifier
   * @param states - Array of states (current first, then previous, capped at MAX_SENDER_KEY_STATES)
   */
  storeSenderKeyRecord(
    groupId: string,
    userId: string,
    deviceId: number,
    states: SenderKeyState[]
  ): Promise<void>;

  /**
   * Retrieve all sender key states (current + previous) for a group member device.
   *
   * First element is the current state; remaining are previous states.
   *
   * @param groupId - Group identifier
   * @param userId - User identifier
   * @param deviceId - Device identifier
   * @returns Array of states, or null if none exist
   */
  getSenderKeyRecord(
    groupId: string,
    userId: string,
    deviceId: number
  ): Promise<SenderKeyState[] | null>;

  // ════════════════════════════════════════════════════════════════
  // SKIPPED SENDER KEYS (for out-of-order message handling - Spec 4.1)
  // ════════════════════════════════════════════════════════════════

  /**
   * Store skipped message key for out-of-order decryption.
   *
   * When chain is advanced past a message (gap in chainIndex),
   * store the derived key so the skipped message can be decrypted later.
   *
   * @param groupId - Group identifier
   * @param senderId - Sender user identifier
   * @param senderDeviceId - Sender device identifier
   * @param chainIndex - The message index this key is for
   * @param messageKey - Derived IV and cipher key (base64 encoded)
   */
  storeSkippedSenderKey(
    groupId: string,
    senderId: string,
    senderDeviceId: number,
    chainIndex: number,
    messageKey: SkippedSenderMessageKey
  ): Promise<void>;

  /**
   * Retrieve skipped message key for out-of-order decryption.
   *
   * @param groupId - Group identifier
   * @param senderId - Sender user identifier
   * @param senderDeviceId - Sender device identifier
   * @param chainIndex - The message index to look up
   * @returns Message key or null if not found/expired
   */
  getSkippedSenderKey(
    groupId: string,
    senderId: string,
    senderDeviceId: number,
    chainIndex: number
  ): Promise<SkippedSenderMessageKey | null>;

  /**
   * Delete skipped message key after use.
   *
   * Called after successfully decrypting an out-of-order message.
   *
   * @param groupId - Group identifier
   * @param senderId - Sender user identifier
   * @param senderDeviceId - Sender device identifier
   * @param chainIndex - The message index to delete
   */
  deleteSkippedSenderKey(
    groupId: string,
    senderId: string,
    senderDeviceId: number,
    chainIndex: number
  ): Promise<void>;

  /**
   * Count skipped keys for a sender (for enforcing maxSkippedKeys limit).
   *
   * @param groupId - Group identifier
   * @param senderId - Sender user identifier
   * @param senderDeviceId - Sender device identifier
   * @returns Number of stored skipped keys for this sender
   */
  countSkippedSenderKeys(
    groupId: string,
    senderId: string,
    senderDeviceId: number
  ): Promise<number>;

  /**
   * Delete oldest skipped keys to make room for new ones.
   *
   * Called when maxSkippedKeys limit is reached.
   *
   * @param groupId - Group identifier
   * @param senderId - Sender user identifier
   * @param senderDeviceId - Sender device identifier
   * @param count - Number of oldest keys to delete
   * @returns Number of deleted keys
   */
  deleteOldestSkippedSenderKeys(
    groupId: string,
    senderId: string,
    senderDeviceId: number,
    count: number
  ): Promise<number>;
}

/**
 * Skipped message key for out-of-order sender key decryption.
 * Contains pre-derived IV and cipher key in base64 format.
 */
export interface SkippedSenderMessageKey {
  /** AES-256-GCM cipher key (base64) */
  cipherKey: string;
  /** Initialization vector (base64) */
  iv: string;
}

/**
 * Aggregate protocol store interface.
 *
 * Combines the five focused local-store responsibilities into one interface.
 *
 */
export interface IProtocolStore
  extends
    IIdentityKeyStore,
    IEcOneTimePreKeyStore,
    IEcSignedPreKeyStore,
    IKyberLastResortPreKeyStore,
    IKemPreKeyStore,
    ISessionStore {
  /** Atomically pin/match trust, store the session, and consume referenced one-time prekeys. */
  commitSessionTrust(commit: SessionTrustCommit): Promise<void>;

  /** Atomically rotate one per-user identity tuple and delete every bound device session. */
  acceptContactIdentityRotationAndDeleteSessions(
    address: ProtocolAddress,
    identity: CompositeIdentityV1,
    identityType?: IdentityType,
    suppliedCommitment?: Uint8Array
  ): Promise<ContactIdentityRecord>;
}

/**
 * Signal Protocol local store interface.
 *
 * Canonical device/browser-local persistence for Signal Protocol state:
 * - identity keys and registrations
 * - sessions and sender keys
 * - SESAME multi-device state
 * - message records and local metadata
 *
 * This is the interface that local store adapters should implement.
 *
 */
export interface ISignalLocalStore
  extends IProtocolStore, ISesameStore, ISenderKeyStore, IMessageRecordStore {
  /**
   * Clear all encryption keys (use with caution!).
   *
   * This should only be used for:
   * - Account deletion
   * - Reset after security incident
   * - Local development
   */
  clearAllKeys(): Promise<void>;

  // ============================================================================
  // Key Recovery Methods (Bug #7 - Identifier Collision Recovery)
  // Per PQXDH §4.13: "Identifier collisions can cause MAC verification failures"
  // ============================================================================

  /**
   * Get the maximum EC signed prekey ID in storage.
   * Used to generate new keyIds that won't collide with existing ones.
   *
   * @param identityType - 'aci' or 'pni' (defaults to 'aci')
   * @returns The highest EC signed prekey ID, or 0 if none exist
   */
  getEcSignedPreKeyMaxId(identityType?: IdentityType): Promise<number>;

  /**
   * Get the maximum Kyber prekey ID in storage.
   * Used to generate new keyIds that won't collide with existing ones.
   *
   * @param identityType - 'aci' or 'pni' (defaults to 'aci')
   * @returns The highest Kyber prekey ID, or 0 if none exist
   */
  getKyberPreKeyMaxId(identityType?: IdentityType): Promise<number>;

  /**
   * Delete all prekeys from storage (preserves identity keys and sessions).
   * Used for recovery from identifier collision per PQXDH §4.13.
   *
   * @param identityType - 'aci' or 'pni' (defaults to 'aci')
   * @returns Counts of deleted prekeys by type
   */
  deleteAllPreKeys(identityType?: IdentityType): Promise<{
    ecSignedPreKeys: number;
    ecOneTimePreKeys: number;
    kyberPreKeys: number;
    kemOneTimePreKeys: number;
  }>;

  /**
   * Clear all sessions from storage.
   * Used during force key reset.
   */
  clearAllSessions(): Promise<void>;

  /**
   * Get detailed statistics about stored data.
   */
  getDetailedStats(): Promise<{
    sessions: number;
    ecSignedPreKeys: number;
    ecOneTimePreKeys: number;
    kyberPreKeys: number;
    kemOneTimePreKeys: number;
    users: number;
  }>;

  // ============================================================================
  // Metadata storage
  // ============================================================================

  /**
   * Get a metadata value by key.
   * Used for persisting operational timestamps (e.g., lastForcedPreKeyRotation).
   */
  getMetadata(key: string): Promise<string | null>;

  /**
   * Set a metadata value by key.
   */
  setMetadata(key: string, value: string): Promise<void>;
}

/**
 * Small local secret vault used to bootstrap a local Signal Protocol store.
 *
 * This interface is intentionally narrow: it exists for secrets that must
 * remain outside the main local store, such as a database encryption key.
 * It is not a second general-purpose Signal Protocol data store.
 */
export interface ISignalLocalSecretVault {
  /**
   * Read a named secret from local secure storage.
   */
  getSecret(name: string): Promise<Uint8Array | null>;

  /**
   * Persist a named secret to local secure storage.
   */
  setSecret(name: string, value: Uint8Array): Promise<void>;

  /**
   * Delete a named secret from local secure storage.
   */
  deleteSecret(name: string): Promise<void>;
}

// ============================================================================
// MESSAGE RECORD TYPES (SESAME Spec Section 6.2)
// ============================================================================

/**
 * MessageRecord for SESAME retry request resending
 *
 * Per SESAME Specification Section 4.1:
 * "Each MessageRecord stores the following values:
 *  - The plaintext of the encrypted message
 *  - The UserID for the recipient device
 *  - The SessionID for the session the message was encrypted with"
 *
 * The SessionID is used to detect orphaned sessions during resending:
 * "If the DeviceRecord's active session matches the SessionID from the relevant
 * MessageRecord, then the sending device creates a new initiating session...
 * This prevents the sending device from repeatedly sending a message using an
 * orphaned session which doesn't match any recipient session."
 *
 * Messages are indexed by the client timestamp assigned before encryption.
 * Retry count enforces SESAME's bounded-resend requirement.
 */
export interface MessageRecord {
  /** Device address (userId:deviceId format) for the recipient device */
  sessionId: string;

  /**
   * Client timestamp for message identification.
   * Set by sender BEFORE encryption. Used for retry request matching.
   * This is the PRIMARY key for message lookup.
   */
  timestamp: number;

  /** Recipient's user ID */
  recipientUserId: string;

  /** Recipient's device ID */
  recipientDeviceId: number;

  /** Original plaintext message (stored for resending) */
  plaintext: string;

  /** Timestamp when record was created */
  createdAt: number;

  /**
   * Sender's ratchet key (DHs.publicKey) at send time — for retry session matching.
   *
   * If the sender's current DHs differs from this stored value, the DH ratchet has advanced
   * and the session is healthy — reuse it. If it matches, the session hasn't
   * advanced and may need a fresh bundle.
   */
  sessionStateId: string;
}

/**
 * Interface for MessageRecord storage operations
 *
 * Used by SESAME manager to store sent messages for potential retry.
 *
 * Messages are indexed by the client timestamp assigned before encryption. The
 * primary lookup method is getMessageRecord(sessionId, timestamp).
 */
export interface IMessageRecordStore {
  /** Store a message record after encryption */
  storeMessageRecord(record: MessageRecord): Promise<void>;

  /**
   * Get a message record by session and timestamp (PRIMARY lookup method).
   *
   * Per Signal Protocol, messages are identified by client timestamp.
   */
  getMessageRecord(sessionId: string, timestamp: number): Promise<MessageRecord | null>;

  /**
   * Delete a message record by session and timestamp.
   *
   * Called when processing delivery receipts to clean up confirmed messages.
   */
  deleteMessageRecord(sessionId: string, timestamp: number): Promise<void>;

  /** Delete all expired message records older than maxAgeMs */
  deleteExpiredMessageRecords(maxAgeMs: number): Promise<number>;

  /** Clear all message records (for device re-registration) */
  clearAllMessageRecords(): Promise<number>;

  /** Delete all message records for a session */
  deleteMessageRecordsForSession(sessionId: string): Promise<number>;
}

// ════════════════════════════════════════════════════════════════════════════
// GroupsV2 Re-exports (defined in internal/groups-v2/manager.ts)
// ════════════════════════════════════════════════════════════════════════════

export type {
  IGroupStateStore,
  IGroupServer,
  GroupChangeLogEntry,
} from '../internal/groups-v2/manager';
