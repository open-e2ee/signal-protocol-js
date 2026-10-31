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
import type { Logger } from '../logger';
import type { ContentHint } from './messages';
import type { ContentRecoveryStatus } from './protocol-config';
import type { RelayConnectionState, Unsubscribe } from '../remote/relay/types';
import type { ReceivedMessageKey } from '../local/store/reliability';

// Re-export IdentityType for consumers
export {};
export type { IdentityType };

// Re-export SessionRecord for convenient access
export type { SessionRecord };

/**
 * Result of one prekey rotation.
 *
 * Each boolean is true when the rotation published that kind of key for any
 * identity type. `errors` holds one message per identity type whose rotation
 * failed; the other identity types still complete.
 */
export interface PreKeyRotationResult {
  /** Whether the rotation published a new EC signed prekey */
  signedRotated: boolean;
  /** Whether the rotation published a new KEM last-resort prekey */
  kyberRotated: boolean;
  /** Whether the rotation published a fresh one-time prekey batch */
  oneTimeReplenished: boolean;
  /** One message per failed identity type (non-fatal) */
  errors: string[];
}

/**
 * All durable trust/session effects of establishing or advancing a session.
 * The same transaction consumes optional one-time-prekey identifiers
 * for responder-side PreKey decrypts. The local identity namespace remains
 * explicit even when the transaction consumes no prekey, so every commit
 * is fully scoped.
 */
export interface SessionTrustCommit {
  address: ProtocolAddress;
  record: SessionRecord;
  /** Sender tuple to pin or match in the same durable commit. */
  contactIdentity: CompositeIdentityV1;
  contactIdentityType: IdentityType;
  /** Local identity namespace. It also scopes any consumed recipient prekeys. */
  localIdentityType: IdentityType;
  oneTimePreKeyId?: number;
  kemOneTimePreKeyId?: number;
  /** Reusable Kyber-prekey replay evidence committed with the accepted session. */
  kyberPreKeyUse?: {
    kyberPreKeyId: number;
    kyberPreKeyInstanceId: string;
    signedPreKeyId: number;
    baseKeyBytes: Uint8Array;
  };
  /**
   * The receive record of the decrypted message. The store writes it in the
   * same transaction as the session state, so the ratchet step and the
   * record roll back together.
   */
  receiveWork?: ReceiveWorkRecord;
  /**
   * The device whose sender-key handoffs this commit invalidates. The store
   * deletes the rows of that device in every group in the same transaction.
   * The session layer sets it for an inbound PreKey session and for an
   * outbound bundle session that archives a current session.
   */
  senderKeyHandoffInvalidation?: SenderKeyHandoffDevice;
}

export interface RetainedKyberPreKey {
  preKey: KyberPreKey;
  instanceId: string;
}

/**
 * The legacy row of recoverable plaintext that SDK 11 stored. A store that
 * opens such a row converts it to a receive record with
 * `awaitingEnvelope: true`. No store writes this shape any more.
 *
 * @deprecated Use `ReceiveWorkRecord` and the receive-work store methods.
 *   The next major SDK version removes this type and the conversion of
 *   these rows at the first open of a durable store. Open each durable
 *   store once on SDK 13.x before that version.
 */
export interface ReceivedContent {
  id: string;
  plaintext: string;
  receivedAt: number;
  groupId?: string;
}

/**
 * The stage of one receive record.
 *
 * - `decrypted`: the ratchet step and the plaintext are committed, and the
 *   application has not got the content yet.
 * - `receipt-due`: the application got the content, and a delivery receipt
 *   is owed. The record holds no plaintext.
 * - `awaiting-completion`: the helper returned the content, and the
 *   application has not called `completeReceive` yet.
 */
export type ReceiveWorkStage = 'decrypted' | 'receipt-due' | 'awaiting-completion';

/**
 * One received message that the device decrypted and has not finished.
 * The record is protocol state: the store keeps it with the same protection
 * as its sessions.
 */
export interface ReceiveWorkRecord {
  /** The delivered fingerprint of the envelope. */
  workId: string;
  /** Increases by one on each write. A write names the revision that it replaces. */
  revision: number;
  stage: ReceiveWorkStage;
  /** `relay` for a Relay delivery, `caller` for an envelope that the application passed. */
  origin: 'relay' | 'caller';
  /** The local arrival order. */
  arrivalSeq: number;
  /**
   * The time of the first durable local admission. No later write changes
   * it. It is the expiry base and the fallback receipt timestamp.
   */
  receivedAt: number;
  /** The record is not processed before this time. */
  dueAt: number;
  /** The UTF-8 size of the record. */
  sizeBytes: number;
  /** The decrypted content. Absent in `receipt-due`. */
  plaintext?: string;
  /** The message ID that the application sees. Absent on a converted legacy row. */
  messageId?: string;
  envelopeId?: string;
  senderUserId?: string;
  senderDeviceId?: number;
  messageType?: 'prekey_bundle' | 'ciphertext' | 'sender_key';
  serverTimestamp?: number;
  arrivedSealed?: boolean;
  /**
   * The timestamp of the sender.
   *
   * - `decrypted`: the timestamp of the Relay envelope. The restore of the
   *   record checks that the content carries the same timestamp. A caller
   *   envelope has none.
   * - `receipt-due`: the timestamp of the content, which the delivery
   *   receipt names. Without it, the receipt names `receivedAt`.
   */
  senderTimestamp?: number;
  /**
   * The raw group of the content. A sender-key record sets it at commit.
   * A record that waits for its group sets it when it blocks, or when it
   * waits behind an earlier record of its group.
   */
  groupId?: string;
  /** The record waits for an update of the state of `groupId`. */
  blockedOn?: 'group-update';
  /** The acknowledgment of the envelope, written in the commit. */
  ackIntent?: { at: number; hasReceiptJoin: boolean };
  /** The join decision of the Relay: true when the Relay sends the receipt. */
  relayOwnsReceipt?: boolean;
  /**
   * The number of `onMessageDecrypted` attempts that started for the
   * content. The count is written before each attempt, so an attempt that
   * ends the process counts. After 10, the record no longer holds back the
   * later records of its conversation. Absent before the first attempt.
   */
  hookAttempts?: number;
  /** The failed envelope that this record resends. */
  failedEnvelopeId?: string;
  /** A converted legacy row. The next delivery of its envelope gives the sender fields. */
  awaitingEnvelope?: true;
  /**
   * `receipt-due`: the key of the content that the application got. The
   * completion of the record records the key again, so a later copy with
   * the key is dropped.
   */
  received?: ReceivedMessageKey;
}

/**
 * Builds the receive record of decrypted content. The decrypt calls it in
 * its commit, with the plaintext and, for a sender-key message, the raw
 * group.
 */
export type ReceiveWorkSeed = (content: {
  plaintext: string;
  groupId?: string;
}) => ReceiveWorkRecord;

/** A query of the receive records, in arrival order. */
export interface ReceiveWorkQuery {
  stage?: ReceiveWorkStage;
  /** Only records with `dueAt` at or before this time. */
  dueBy?: number;
  /**
   * Only records after this position in arrival order: an `arrivalSeq`
   * above it, or an equal `arrivalSeq` with a `workId` above it. Pass the
   * last record of the page before.
   */
  after?: Pick<ReceiveWorkRecord, 'arrivalSeq' | 'workId'>;
  /** The most records to return. */
  limit?: number;
}

/** A query of the metadata keys that start with one prefix. */
export interface MetadataKeyQuery {
  /** Only keys that start with this prefix. */
  prefix: string;
  /** Only keys above this key, in UTF-16 code unit order. Pass the last key of the page before. */
  after?: string;
  /** The most keys to return. */
  limit?: number;
}

/** The number and the total size of receive records. */
export interface ReceiveWorkUsage {
  items: number;
  bytes: number;
}

/** One metadata write in the atomic completion of a receive record. Null deletes. */
export interface ReceiveWorkMetadataWrite {
  key: string;
  value: string | null;
}

/** Effects committed atomically with the sender-key record after successful decryption. */
export interface SenderKeyReceiveCommit {
  /** The receive record of the decrypted message. */
  work?: ReceiveWorkRecord;
  consumedSkippedKey?: { senderKeyId: string; chainIndex: number };
  /**
   * Add keys in order. Before each addition, evict the lowest chain indexes for
   * this group/member/device until fewer than maxSkippedKeys remain. Eviction,
   * additions, consumption, content, and the record must all roll back on failure.
   */
  skippedKeys?: {
    maxSkippedKeys: number;
    keys: Array<{
      senderKeyId: string;
      chainIndex: number;
      messageKey: SkippedSenderMessageKey;
    }>;
  };
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
export interface SignalProtocolClient {
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
  readonly logger: Required<Logger>;

  /**
   * Whether this client keeps resendable content to answer retry requests.
   *
   * The client decides at creation, from the `protection` that the local
   * store declares and from `protocol.contentRecovery`. When `enabled` is
   * false, `reason` says why, and the client deletes any resendable content
   * that the store already holds.
   */
  readonly contentRecoveryStatus: ContentRecoveryStatus;

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
   * starts. A call while `stop()` runs is refused and logged; start again
   * after `stop()` resolves.
   */
  startRelaySubscription(): void;

  /**
   * Stop the relay subscription
   *
   * Pauses message processing without destroying client state. It first
   * starts the send of the delivery receipts that wait in a batch. `stop()`
   * holds the receipt batches from its first flush until it clears its
   * tracking state. During the hold, `stopRelaySubscription()` does not send
   * them. `stop()` sends the batches that wait at each of its flushes and
   * drops a batch made during the hold after its last flush.
   * Use when app backgrounds to let background task handle messages.
   * Call startRelaySubscription() to resume when app foregrounds.
   * `bindRelayLifecycle` and the `useRelayLifecycle` hook make both calls
   * from the app state.
   */
  stopRelaySubscription(): void;

  /**
   * The connection state of the relay subscription.
   *
   * It reads `stopped` before `startRelaySubscription()`, after
   * `stopRelaySubscription()`, and when no relay is configured. Use it for a
   * local indicator of this device's connection.
   */
  readonly relayConnectionState: RelayConnectionState;

  /**
   * Subscribe to relay connection transitions.
   *
   * The listener receives each new state once. Read `relayConnectionState` for
   * the current state.
   *
   * @param listener - Callback for each transition
   * @returns Unsubscribe function
   */
  subscribeRelayConnectionState(
    listener: (state: RelayConnectionState) => void
  ): Unsubscribe;

  /**
   * Stop the client and cleanup resources
   *
   * Call this on logout or app shutdown. It first sends each delivery
   * receipt batch that waits, once. Then it waits for delivery receipt
   * sends, including their app hooks, until one deadline 5 s after `stop()`
   * starts. It waits for each receipt send that is in progress when `stop()`
   * starts, except a send that an earlier `stop()` stopped, and for the
   * sends that it starts. A delivery that finishes during the wait batches
   * its receipt. At the end of each wait, `stop()` sends the batches that
   * wait and waits for those sends until the same deadline. It does this
   * again while the deadline is not past. `stop()` holds the receipt batches
   * from its first flush until it clears its tracking state. During the
   * hold, `stopRelaySubscription()` does not send them, and `stop()` drops a
   * receipt batched after its last flush. At the deadline it stops each
   * receipt send that is left: a send that waits in an app hook stops, and
   * that receipt is not sent. A send that is in its relay call at the
   * deadline is waited for, and that receipt can still be sent. It also
   * resolves after the SDK work of the relay deliveries and retry requests
   * in progress finishes. Apart from the receipt wait, it does not wait for
   * app hooks, so a hook can await `stop()`. A hook of a delivery receipt
   * send that awaits `stop()` holds `stop()` until the deadline. `stop()`
   * does not wait for read and viewed receipt sends. When a hook returns
   * after `stop()`, the SDK drops the work after the hook and writes nothing
   * more. The relay delivers the envelope again after the next start.
   *
   * A call to `startRelaySubscription()` while `stop()` runs is refused and
   * logged; start again after `stop()` resolves. A `stop()` call that
   * overlaps a running `stop()` waits for it and settles as it settles.
   */
  stop(): Promise<void>;


  // ============================================================================
  // KEY ROTATION
  // ============================================================================

  /**
   * Rotate the device's prekeys in one publication.
   *
   * One inventory read decides whether the EC signed prekey, the KEM
   * last-resort prekey, or a one-time prekey batch is due. Signed keys rotate
   * once they are older than the configured refresh interval
   * ({@link KEY_REFRESH_INTERVAL_MS_DEFAULT}, 2 days by default). One-time
   * prekeys refill when a server count is below the threshold. Nothing due
   * costs one read and no publication, so the method is safe to call often.
   */
  rotatePreKeys(): Promise<PreKeyRotationResult>;

  /** Explicitly rotate the account-level relay identity with compare-and-swap. */
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
   * @param recipientId - Prefixed group ID or userId for direct messages
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
   * Post a send again, as a new message, after it ended at its posting
   * deadline without acceptance.
   *
   * Call it only for a send whose `send()` threw `SendAcceptanceUnknownError`
   * or `SendNeverAcceptedByRelayError`, or whose `onSendOutcome` event gave
   * `failed` or `acceptance-unknown`. The resend keeps the `clientMessageId`,
   * the client timestamp and the content of the send. It encrypts the
   * content again for each recipient device that the Relay did not accept,
   * and posts each copy under the message ID `<clientMessageId>:manual:N`,
   * N from 1. The receive queue of a recipient device that already holds
   * the message drops the copy by its sender device, its client timestamp
   * and its content. The drop needs the timestamp that the content adapter
   * reads from the message. Content with no timestamp, such as raw string or
   * byte content, takes no drop key, and a recipient that holds it receives
   * the copy again. The recipient records the message with the completion
   * of its receive record, or, when a receipt is due, right after the
   * receipt-due write and again with the completion of the receipt. The
   * record expires after 60 days. The caller-origin receive path gives every
   * decrypted message to the caller, and a caller that keeps its own records
   * removes a copy itself.
   *
   * Only a send younger than 30 days takes a new resend. An open resend of
   * an older send still posts until its own deadline.
   *
   * The resend is a new Relay operation with its own operation epoch, so the
   * Relay can charge a resend as a new message. It has its own posting
   * deadline, 24 hours after the call. Until that deadline, a later call
   * posts the same resend again, and the SDK send driver posts it again
   * after a restart. At the deadline it ends: `onSendOutcome` reports its end
   * once, with `manualResend` set. With `acceptance-unknown`, the resend
   * might have arrived.
   *
   * The content must still be stored: the message record of the send, or
   * its send log entry for a resendable group send. A resend of a group send
   * posts the content of its send log entry, so each copy carries the group
   * context of the original send, not the current one.
   *
   * @param clientMessageId - The `clientMessageId` of the send
   * @returns The result of the resend when the Relay accepted each device
   * @throws SendAcceptanceUnknownError or SendNeverAcceptedByRelayError when
   *   the resend ends at its posting deadline
   * @throws Error when the send is unknown, still open or completed, when
   *   the Relay accepted each recipient device, when the content is gone, or
   *   when the send is 30 days old or older and has no open resend
   */
  resendMessage(clientMessageId: string): Promise<import('../client/types').SendResult>;

  /**
   * Delete the resendable content of one group send.
   *
   * The client keeps the content of a resendable group send to answer a
   * retry request, until each recipient device confirms it with an E2EE
   * delivery receipt or the retention ends. Call this method when the
   * application deletes the message, so a later retry request gets no
   * content. The method does not delete pairwise message records.
   *
   * @param clientMessageId - The `clientMessageId` of the send
   * @returns True when the client held content for the send
   */
  forgetSentContent(clientMessageId: string): Promise<boolean>;

  /**
   * The recipient devices of a resendable group send that have not
   * confirmed it with an E2EE delivery receipt.
   *
   * A device leaves the list when its E2EE delivery receipt arrives. A Relay
   * delivery receipt does not remove it, because a device also acknowledges
   * a copy that it could not decrypt. The list is empty after the retention
   * ends, after `forgetSentContent`, and for a send that the client did not
   * log.
   *
   * @param clientMessageId - The `clientMessageId` of the send
   */
  getPendingRecipients(clientMessageId: string): Promise<SendLogDevice[]>;

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
   * This only touches the remote object store. The application must delete
   * app-owned local message rows and local media caches.
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
   * The receive helper for an application that pulls envelopes itself. It
   * decrypts the envelope and commits its content as a receive record with
   * the ratchet step, then decides the group of the content. Handles
   * decryption and automatically sends SESAME retry requests on retryable
   * failures. The content stays recoverable until the application calls
   * `completeReceive`, or until `onPersist` resolves.
   *
   * The outcome tells the caller what to do with the envelope:
   *
   * - `processed`: give the content to the application, then acknowledge
   *   the envelope. A redelivery of the envelope before `completeReceive`
   *   returns the same outcome again with no second decrypt. A second
   *   `completeReceive` is a no-op.
   * - `pending`: the content is stored and the client resumes it, for
   *   example when its group state must update first. Acknowledge the
   *   envelope. When the group updates, the client decides the content
   *   again, and `listPendingReceives({ ready: true })` then lists it.
   * - `duplicate`: this client processed the envelope, or the application
   *   already has the content of the failed envelope of a retry request.
   *   The client acknowledged the envelope.
   * - `null-message`: the envelope carries no content. The client consumes
   *   a null message when the content adapter reports `nullMessage: true`,
   *   and a custom adapter must report it for its own null encoding. The
   *   client acknowledged it. A null message for a failed envelope marks
   *   that envelope processed, so a redelivery of it is dropped, but a
   *   content resend for it that comes later still gives its content.
   * - `denied`: the client refused the content. The ratchet step is spent,
   *   so no resend can repair it. `onDecryptionError` ran, except for a
   *   group that the user blocked (reason `blocked`), which has no report.
   *   The client acknowledged the envelope. Content from another account that carries
   *   a sync message is denied in any envelope.
   * - `refused`: the receive queue has no room. Nothing is decrypted or
   *   stored. Do not acknowledge the envelope. Give it again later.
   *
   * The stored receives count toward `protocol.receiveQueue` and expire
   * after 30 days, with `onReceiveExpired`.
   *
   * A group message that fails with a retryable error gets a retry request
   * and is acknowledged, as a pairwise message is. A message with the
   * Implicit content hint gets no request and is acknowledged.
   *
   * A retry request follows the sealed sender delivery mode. With a relay
   * and the access key of the sender, the client posts it sealed. Otherwise
   * the client posts it identified only when the mode permits it. In
   * `'required'` mode a retry request that cannot be sealed is not posted:
   * it stays pending until its deadline. The `sendRetryRequest` callback
   * gets an identified envelope, so the client calls it only when the mode
   * permits identified delivery.
   *
   * A `retry_request` envelope holds no plaintext. This method rejects it,
   * identified or sealed, and sends no retry request. Give it to
   * `receiveIncomingEnvelopes`, which handles it.
   *
   * A failed envelope that this client asked a resend for, and each resend
   * or null message for it, gives content at most once on both receive
   * paths.
   *
   * A resend that brings only the sender key of a failed group message
   * gives no content. It does not mark the failed envelope processed, so a
   * redelivery of that envelope decrypts with the key. A resend that brings
   * the content beside the key gives that content and marks the failed
   * envelope processed.
   *
   * A resend or null message that fails to decrypt, or whose seal fails to
   * open, asks again for its failed envelope under the same retry ID. When
   * the processed record of the failed envelope fails to store after a
   * decrypt, the client writes a warning with the behavior
   * RETRY_FULFILL_WRITE_FAILED, as on every receive path, and this method
   * still returns the outcome. A redelivery of the failed envelope or of
   * another family member can then give the content again. When a
   * processed record of a null message or of its failed envelope fails to
   * store, the client writes a warning with the behavior
   * RETRY_NULL_WRITE_FAILED, as on every receive path, and this method
   * still returns `null-message`. A redelivery of the failed envelope can
   * then give the content.
   *
   * This method never throws `GroupResendDeferredError`, because it
   * rejects a retry request.
   * `receiveIncomingEnvelopes` reports a deferred retry request in
   * `failedMessageIds`, so the Relay keeps the request.
   *
   * @param envelope - The encrypted message envelope
   * @param options - Transport callbacks for background (no relay)
   *   scenarios, and `onPersist`
   * @returns The receive outcome
   * @throws EncryptionError after sending retry request if decryption fails
   * @throws EncryptionError INVALID_CIPHERTEXT for a `retry_request` envelope,
   *   identified or sealed
   *
   * @example
   * ```typescript
   * const outcome = await signal.processIncomingEnvelope(envelope, {
   *   // Background (the client has no relay)
   *   sendRetryRequest: async (envelope) => {
   *     // Post the retry_request envelope like any other envelope.
   *     await backgroundRelay.send(envelope);
   *   },
   *   // The client completes the receive when the content is stored.
   *   onPersist: (processed) => db.saveMessage(processed.messageId, processed.plaintext),
   * });
   * if (outcome.kind !== 'refused') await backgroundRelay.acknowledge(envelope.id);
   * ```
   */
  processIncomingEnvelope(
    envelope: import('../client/types').IncomingEnvelope,
    options?: import('../client/types').ProcessEnvelopeOptions
  ): Promise<import('../client/types').ReceiveOutcome>;

  /**
   * Complete a helper receive: delete its receive record and mark its
   * envelope processed. Call it after the application stored the content
   * of a `processed` outcome. An unknown or completed message ID is a no-op.
   *
   * @param messageId - The `messageId` of the `processed` outcome
   */
  completeReceive(messageId: string): Promise<void>;

  /**
   * List the stored receives in arrival order, one page at a time. A receive
   * whose content the application has, and whose receipt waits, is not
   * listed.
   *
   * @param query - `ready` lists only the helper receives whose content
   *   waits for `completeReceive`. `after` is the `next` value of the page
   *   before. `limit` is the page size, 100 by default.
   * @returns The page, and `next` when a later page can follow
   * @throws Error when `after` is not a `next` value or `limit` is not a
   *   positive integer
   */
  listPendingReceives(query?: {
    ready?: boolean;
    after?: string;
    limit?: number;
  }): Promise<{ items: import('../client/types').PendingReceive[]; next?: string }>;

  /**
   * Remove one stored receive that the application gives up on, such as a
   * receive whose `onMessageDecrypted` hook fails at each start. The client
   * deletes the receive and marks its envelope processed, so a redelivery
   * of the envelope is a duplicate. The call sends no receipt, calls no
   * hook, and runs no `onReceiveExpired`. A hook call that already started
   * for the receive still runs, and no receipt follows it.
   *
   * @param messageId - The `messageId` of a receive that
   *   `listPendingReceives` lists
   * @returns The removed receive, or null when the client removed nothing:
   *   no listed receive has the ID, or another path wrote the receive during
   *   the call and again after one read
   */
  discardPendingReceive(
    messageId: string
  ): Promise<import('../client/types').PendingReceive | null>;

  /**
   * Run one pass of the receive queue now, and stop between records at the
   * deadline. A host that wakes for a push calls it after it acknowledged
   * the pulled envelopes.
   *
   * @param options - `deadlineMs` bounds the pass. With no deadline, the
   *   pass runs until each record is handled.
   * @returns The receives that the pass handled, and the receives that
   *   still wait
   */
  processPendingReceives(options?: {
    deadlineMs?: number;
  }): Promise<{ processed: number; remaining: number }>;

  /**
   * Decrypt one envelope with no receive record.
   *
   * The decrypt installs a sender key distribution that the content
   * carries, and checks that a managed group context binds to the group of
   * the transport. It stores no content, decides no group state, and sends
   * no receipt.
   *
   * Warning: the decrypt spends the ratchet step. When the application
   * loses the returned plaintext, no later decrypt of the envelope gives it
   * again. Use `processIncomingEnvelope`, which keeps the content until the
   * application completes the receive.
   *
   * @param envelope - The encrypted message envelope
   * @returns The plaintext as its sender gave it, and the group context of
   *   managed-group content
   * @throws EncryptionError when the decrypt fails, and INVALID_CIPHERTEXT
   *   for a `retry_request` envelope, identified or sealed
   * @throws GroupReceiveRefusedError when the group context is malformed or
   *   names another group than the transport
   */
  decryptEnvelope(envelope: import('../client/types').IncomingEnvelope): Promise<{
    plaintext: string;
    groupContext?: import('../client/content-adapter').GroupContentContext;
  }>;

  /**
   * Encrypt file blob with two-layer encryption
   * Returns encrypted blob and encrypted key
   *
   * @param remoteAddress - Remote party's protocol address (userId:deviceId)
   * @param fileBlob - File data to encrypt
   * @param mimeType - Optional MIME type for the file
   * @throws EncryptionError with `BINARY_BLOB_UNAVAILABLE` when the runtime's
   * `Blob` cannot hold bytes, as on React Native. Use `streamingEncrypt` from
   * `@open-e2ee/signal-protocol-sdk/files` there.
   */
  encryptFile(
    remoteAddress: ProtocolAddress,
    fileBlob: Blob,
    mimeType?: string
  ): Promise<{ encryptedBlob: Blob; keyId: string; encryptedKey: Ciphertext }>;

  /**
   * Decrypt file blob
   *
   * @param remoteAddress - Remote party's protocol address (userId:deviceId)
   * @param encryptedBlob - Encrypted file data
   * @param encryptedKey - Encrypted file key
   * @throws EncryptionError with `BINARY_BLOB_UNAVAILABLE` when the runtime's
   * `Blob` cannot hold bytes, as on React Native. The key message stays
   * unconsumed. Use `streamingDecrypt` from `@open-e2ee/signal-protocol-sdk/files`
   * there.
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
   * This is a client-side check that does not require server calls.
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
  createGroupSenderKey(
    groupId: string
  ): Promise<{
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
   * The message passes the group decision of `processIncomingEnvelope`.
   * Content whose group state must update first stays stored, and a later
   * call with the same message decides it with no second decrypt.
   *
   * @deprecated Use `processIncomingEnvelope`, which returns a receive
   *   outcome and keeps the content until the application completes the
   *   receive. This method completes the receive before it returns, so a
   *   plaintext that the application loses is gone.
   *
   * @param groupId - Group identifier
   * @param senderId - Sender's user ID
   * @param senderDeviceId - Sender's device ID
   * @param framedMessage - Framed SenderKeyMessage bytes
   * @returns Decrypted plaintext
   * @throws GroupReceiveUnavailableError when the group state of the content
   *   is not current. Its `messageId` names the stored receive. Call again
   *   later with the same message.
   * @throws GroupReceiveRefusedError when the client refuses the content
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
  rotateGroupSenderKey(
    groupId: string
  ): Promise<{
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
   * @param timestamps - Server timestamps of the messages the user read
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
   * stay in sync even when the configuration disables remote read receipts.
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
   *
   * The `deletedAt` time is the epoch of the sync. The SDK accepts a safe positive
   * integer at most 5 minutes ahead of the SDK clock and at most 24 hours
   * behind it, and throws `InvalidSendTimestampError` for any other value
   * before it posts.
   */
  syncMediaAttachmentDeleteToLinkedDevices(
    entry: import('../client/content-adapter').MediaAttachmentDeleteSyncInput
  ): Promise<void>;

  /**
   * Sync account-level communication/privacy configuration to linked devices.
   *
   * This holds linked-device state, not a sender-facing receipt. It should carry
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
   *
   * The `learnedAt` time is the epoch of the sync. The SDK accepts a safe positive
   * integer at most 5 minutes ahead of the SDK clock and at most 24 hours
   * behind it, and throws `InvalidSendTimestampError` for any other value
   * before it posts.
   */
  syncRecipientUsernameToLinkedDevices(
    recipientUsername: import('../client/content-adapter').RecipientUsernameSyncInput
  ): Promise<void>;

  /**
   * Sync explicit safety-number verification state to the account's other linked devices.
   *
   * Only explicit `verified` and cleared-to-`default` states belong here.
   * Conflict and untrusted state is still derived locally from identity-key changes.
   *
   * The `changedAt` time is the epoch of the sync. The SDK accepts a safe positive
   * integer at most 5 minutes ahead of the SDK clock and at most 24 hours
   * behind it, and throws `InvalidSendTimestampError` for any other value
   * before it posts.
   */
  syncVerificationStateToLinkedDevices(
    verificationState: import('../client/content-adapter').VerificationStateSyncInput
  ): Promise<void>;

  /**
   * Sync task-notification acknowledgment state to the account's other linked devices.
   *
   * This is app-level linked-device notification state, not sender-facing content.
   *
   * The `acknowledgedAt` time is the epoch of the sync. The SDK accepts a safe positive
   * integer at most 5 minutes ahead of the SDK clock and at most 24 hours
   * behind it, and throws `InvalidSendTimestampError` for any other value
   * before it posts.
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
   *
   * The `syncedAt` time is the epoch of the sync. The SDK accepts a safe positive
   * integer at most 5 minutes ahead of the SDK clock and at most 24 hours
   * behind it, and throws `InvalidSendTimestampError` for any other value
   * before it posts.
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
export interface SignalProtocolManager {
  /**
   * Initialize identity keys on first launch
   * @param identityTypes - Identity types to generate keys for (defaults to ['aci', 'pni'])
   */
  initialize(identityTypes?: readonly IdentityType[]): Promise<void>;

  /**
   * Set local user and device identity.
   *
   * Call this before any session operations (encrypt/decrypt).
   * generatePreKeyBundle normally calls it. Callers can also call it directly
   * when keys already exist and do not need regeneration.
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
   * @param receiveWork - When set, the decrypt commits the receive record
   *   that it builds in the same transaction as the session state
   */
  decrypt(
    remoteAddress: ProtocolAddress,
    ciphertext: Ciphertext,
    receiveWork?: ReceiveWorkSeed
  ): Promise<string>;

  /**
   * Get the session record for a remote address.
   *
   * Used by SESAME to sync sessions after PreKeyMessage decryption.
   * Per SESAME specification, after the responder decrypts a PreKeyMessage,
   * the session must sync from KeyStorage to DeviceRecord.
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
// Breaking SignalProtocolLocalStore into focused interfaces provides:
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
 * changes after the store pins a tuple. It does not authenticate first contact.
 *
 */
export interface IdentityKeyStore {
  /**
   * Store our identity key pair and its registration ID for one identity type.
   *
   * A call for a type that already has a key pair overwrites the key pair and
   * the registration ID of that type. The other identity type stays
   * unchanged. A managed device link uses this overwrite to give the linked
   * device its own registration ID with the same keys:
   *
   * ```ts
   * const identity = await store.getIdentityKey('aci');
   * await store.storeIdentityKey({ ...identity!, registrationId: 4321 }, 'aci');
   * await store.getLocalRegistrationId('aci'); // 4321
   * (await store.getIdentityKey('aci'))!.registrationId; // 4321
   * ```
   *
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
   * The registration ID is a random integer from 1 through 16383. Each
   * install gets one, and a managed device link gives the linked device its
   * own. A peer uses it to detect that a device was installed again.
   * @param identityType - 'aci' or 'pni' (defaults to 'aci')
   */
  getLocalRegistrationId(identityType?: IdentityType): Promise<number>;

  /**
   * Set our local registration ID.
   *
   * A call overwrites the stored ID of `identityType` and leaves the other
   * identity type unchanged. Keep it equal to the `registrationId` of the
   * stored key pair of the same type.
   * @param id - Registration ID
   * @param identityType - 'aci' or 'pni' (defaults to 'aci')
   */
  setLocalRegistrationId(id: number, identityType?: IdentityType): Promise<void>;

  /**
   * Save a contact's identity key and detect changes.
   *
   * This supports Trust On First Use (TOFU) and post-pinning change
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
   * Returns null if the store holds no identity key for this address.
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
   * that user. The previous tuple becomes rollback history.
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
   * Check whether the store trusts a contact's identity key.
   *
   * Trust verification behavior depends on direction:
   * - SENDING: Stricter - do not send to untrusted identities
   * - RECEIVING: More permissive - allow receiving but warn user
   *
   * From Signal Protocol:
   * "It's safer to receive from an unknown identity than to send to one"
   *
   * @param address - Contact's protocol address
   * @param identity - Complete composite identity candidate
   * @param direction - Whether the local device sends or receives
   * @param identityType - ACI or PNI trust namespace
   * @returns true if the store trusts the identity
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
 * The protocol consumes a one-time prekey after use, and no caller may reuse it.
 *
 */
export interface EcOneTimePreKeyStore {
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
   * Remove an EC one-time prekey after a session uses it.
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
 * The client rotates EC signed prekeys on the configured refresh interval
 * (2 days by default). The store must keep OLD prekeys for a grace period
 * (~30 days) to handle in-flight messages.
 *
 * Per X3DH Spec Section 4.4:
 *
 * > "After uploading a new signed prekey, Bob may keep the private key
 * > corresponding to the previous signed prekey around for some period
 * > of time, to handle messages using it that have been delayed in transit."
 *
 * @see https://signal.org/docs/specifications/x3dh/
 */
export interface EcSignedPreKeyStore {
  /**
   * Store EC signed prekey.
   *
   * When storing a new EC signed prekey (rotation), archive the old one
   * instead of deleting it, to handle in-flight messages.
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
 * - `EcOneTimePreKeyStore` → one-time EC prekeys (`ecPreKeys`)
 * - `EcSignedPreKeyStore` → reusable EC prekey (`ecSignedPreKeys`)
 * - `KemPreKeyStore` → one-time KEM prekeys (`kemOneTimePreKeys`) - FUTURE
 * - `KyberLastResortPreKeyStore` → reusable KEM prekey (`kemLastResortPreKeys`)
 *
 * @see https://signal.org/docs/specifications/pqxdh/
 */
export interface KyberLastResortPreKeyStore {
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

  /** Retrieve the exact retained Kyber prekey instance named by a message. */
  getKyberPreKeyById(
    keyId: number,
    identityType?: IdentityType
  ): Promise<RetainedKyberPreKey | null>;

  /**
   * Mark a Kyber prekey as used.
   *
   * Callers may reuse Kyber prekeys (unlike one-time prekeys), and the store
   * must track them so rotation stays correct.
   *
   * @param kyberPreKeyId - ID of the Kyber prekey the session used
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
 * The protocol consumes a one-time KEM prekey after use. Each one adds a
 * security layer beyond the last-resort Kyber prekey.
 *
 * Naming convention matches EC prekeys:
 * - `EcOneTimePreKeyStore` → one-time EC prekeys (`ecPreKeys`)
 * - `KemPreKeyStore` → one-time KEM prekeys (`kemOneTimePreKeys`)
 *
 * @see https://signal.org/docs/specifications/pqxdh/ Section 3.2
 */
export interface KemPreKeyStore {
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
   * Remove a one-time KEM prekey after a session uses it.
   *
   * CRITICAL: Call this immediately after successful decapsulation
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
export interface SessionStore {
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
   * Delete session record. The same write deletes the sender-key handoff
   * rows of the device in every group.
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
   * The same write deletes the sender-key handoff rows of the device in every
   * group.
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
 * Each `DeviceRecord` holds its session state directly.
 *
 * @see https://signal.org/docs/specifications/sesame/
 */
export interface SesameStore {
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
   *
   * @param options - With `senderKeyHandoffInvalidation`, the same write
   *   deletes the sender-key handoff rows of that device in every group
   */
  setDeviceRecord(
    userId: string,
    deviceId: number,
    record: DeviceRecord,
    options?: SetDeviceRecordOptions
  ): Promise<void>;

  /**
   * Delete device record. The same write deletes the sender-key handoff rows
   * of the device in every group.
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
   * Delete the stale device records with their sessions. A record is stale
   * when it has no session and is older than `maxLatency`, or when it is
   * marked removed and its removal is older than `maxLatency`
   * (`isExpiredRemovedDevice`). A user record with no device left goes too.
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
   * Get all device IDs for a specific user. The list includes the devices
   * whose record is marked removed. A caller that sends to the devices skips
   * them with `isRemovedDevice`.
   */
  getSesameDeviceIds(userId: string): Promise<number[]>;
}

/** One device whose recorded sender-key handoffs an event invalidates. */
export interface SenderKeyHandoffDevice {
  userId: string;
  deviceId: number;
}

/**
 * The Relay accepted a distribution of the local device's own sender key for
 * this recipient device. A row records a handoff. It is never proof that the
 * recipient installed the key.
 */
export interface SenderKeyHandoffRecord {
  groupId: string;
  senderKeyId: string;
  generation: number;
  recipientUserId: string;
  recipientDeviceId: number;
  /** The registration ID of the recipient's current session when the Relay accepted the post. */
  recipientRegistrationId: number;
  acceptedAt: number;
}

/**
 * The sender-key handoff ledger of the local device.
 *
 * A group send gives the current own sender key to each listed device that
 * has no row for the current key. The store keeps the rows and deletes them.
 * It never decides which device needs the key. Rows have no expiry. A row
 * leaves the store only through an invalidation, a write that replaces or
 * deletes the own key, a reset of the store, or the sweep at client start.
 */
export interface SenderKeyHandoffStore {
  /**
   * Insert or replace the row keyed by group, sender key ID, generation,
   * recipient user, recipient device, and recipient registration ID.
   */
  recordSenderKeyHandoff(record: SenderKeyHandoffRecord): Promise<void>;

  /** The rows of one group at one generation. */
  listSenderKeyHandoffs(groupId: string, generation: number): Promise<SenderKeyHandoffRecord[]>;

  /**
   * Delete the rows of one device in one group.
   *
   * @returns True when at least one row was deleted
   */
  invalidateSenderKeyHandoff(groupId: string, device: SenderKeyHandoffDevice): Promise<boolean>;

  /**
   * Delete the rows of every device of one account in every group, as an
   * identity rotation of the account does.
   *
   * @returns True when at least one row was deleted
   */
  invalidateAccountSenderKeyHandoffs(userId: string): Promise<boolean>;

  /** The distinct group IDs that hold rows. For the sweep only. */
  listSenderKeyHandoffGroupIds(): Promise<string[]>;

  /**
   * Delete the rows of a group whose sender key ID differs from the given one.
   * Null deletes every row of the group.
   *
   * @returns The number of deleted rows
   */
  retainSenderKeyHandoffs(groupId: string, senderKeyId: string | null): Promise<number>;
}

/** Options for the own-key writes that replace or remove the key. */
export interface SenderKeyRecordWriteOptions {
  /** Delete every sender-key handoff row of the group in the same write. */
  deleteSenderKeyHandoffs?: true;
}

/** Options for a device-record write that replaces the current session. */
export interface SetDeviceRecordOptions {
  /** Delete the sender-key handoff rows of this device in every group in the same write. */
  senderKeyHandoffInvalidation?: SenderKeyHandoffDevice;
}

/**
 * Sender Key store interface for group messaging.
 *
 * Manages sender keys for efficient group encryption using the
 * Sender Key Distribution Message protocol.
 */
export interface SenderKeyStore {
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
   *
   * @param options - With `deleteSenderKeyHandoffs`, the same write deletes
   *   every sender-key handoff row of the group. The manager sets it when it
   *   deletes the local device's own key.
   */
  deleteSenderKey(
    groupId: string,
    userId: string,
    deviceId: number,
    options?: SenderKeyRecordWriteOptions
  ): Promise<void>;

  /**
   * Resolve the group a sender key belongs to, given only the identifier that
   * travels on the wire.
   *
   * A received group message names its sender key by `senderKeyId` and nothing
   * else. The identifier is opaque, and the envelope no longer carries a
   * group. This is the receiver's only way back to a group, so it is what
   * decides which sender key state to decrypt against.
   *
   * Searches previous states as well as current ones. A message encrypted just
   * before a rotation is still in flight when the rotation lands, and its
   * `senderKeyId` names the superseded key. Resolving only against current
   * state would strand exactly the messages the rotation window exists to
   * cover.
   *
   * @param senderKeyId - Opaque identifier read from the SenderKeyMessage frame
   * @param userId - Sender user identifier, from the envelope
   * @param deviceId - Sender device identifier, from the envelope
   * @returns The group ID, or null if this device has no such sender key
   */
  resolveGroupForSenderKeyId(
    senderKeyId: string,
    userId: string,
    deviceId: number
  ): Promise<string | null>;

  /**
   * Get all sender keys for a group (for admin operations).
   */
  getAllSenderKeysForGroup(groupId: string): Promise<SenderKeyState[]>;

  /**
   * Delete all sender keys, skipped sender message keys, and sender-key
   * handoff rows for a group (when the caller deletes the group), in one
   * write. Returns the number of sender keys deleted.
   */
  deleteAllSenderKeysForGroup(groupId: string): Promise<number>;

  // ════════════════════════════════════════════════════════════════
  // SENDER KEY RECORD (current + previous states for rotation window)
  // ════════════════════════════════════════════════════════════════

  /**
   * Store all sender key states (current + previous) for a group member device.
   *
   * The first element is the current state. The remaining entries are previous states
   * retained during the rotation window for decrypting in-flight messages.
   *
   * Per Sender Keys spec Section 5.1: "Implementations MUST store sender key
   * state persistently." This method persists the full record atomically with
   * every receive effect. A rejection preserves the prior record, skipped keys,
   * and received content. The same guarantee applies without a content receipt.
   *
   * @param groupId - Group identifier
   * @param userId - User identifier
   * @param deviceId - Device identifier
   * @param states - Array of states (current first, then previous, capped at MAX_SENDER_KEY_STATES)
   * @param receive - The receive effects to commit with the record
   * @param options - With `deleteSenderKeyHandoffs`, the same write deletes
   *   every sender-key handoff row of the group. The manager sets it when it
   *   writes a new own key.
   */
  storeSenderKeyRecord(
    groupId: string,
    userId: string,
    deviceId: number,
    states: SenderKeyState[],
    receive?: SenderKeyReceiveCommit,
    options?: SenderKeyRecordWriteOptions
  ): Promise<void>;

  /**
   * Retrieve all sender key states (current + previous) for a group member device.
   *
   * First element is the current state. The remaining entries are previous states.
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
   * When the chain advances past a message (gap in chainIndex),
   * store the derived key so a later call can decrypt the skipped message.
   *
   * @param groupId - Group identifier
   * @param senderId - Sender user identifier
   * @param senderDeviceId - Sender device identifier
   * @param senderKeyId - Distribution identifier for this sender-key generation
   * @param chainIndex - The message index this key is for
   * @param messageKey - Derived IV and cipher key (base64 encoded)
   */
  storeSkippedSenderKey(
    groupId: string,
    senderId: string,
    senderDeviceId: number,
    senderKeyId: string,
    chainIndex: number,
    messageKey: SkippedSenderMessageKey
  ): Promise<void>;

  /**
   * Retrieve skipped message key for out-of-order decryption.
   *
   * @param groupId - Group identifier
   * @param senderId - Sender user identifier
   * @param senderDeviceId - Sender device identifier
   * @param senderKeyId - Distribution identifier for this sender-key generation
   * @param chainIndex - The message index to look up
   * @returns Message key or null if not found/expired
   */
  getSkippedSenderKey(
    groupId: string,
    senderId: string,
    senderDeviceId: number,
    senderKeyId: string,
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
   * @param senderKeyId - Distribution identifier for this sender-key generation
   * @param chainIndex - The message index to delete
   */
  deleteSkippedSenderKey(
    groupId: string,
    senderId: string,
    senderDeviceId: number,
    senderKeyId: string,
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
   * The store calls this when the chain reaches the maxSkippedKeys limit.
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
  /** AES-256-CBC cipher key (base64) */
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
export interface ProtocolStore
  extends
    IdentityKeyStore,
    EcOneTimePreKeyStore,
    EcSignedPreKeyStore,
    KyberLastResortPreKeyStore,
    KemPreKeyStore,
    SessionStore {
  /** Atomically pin/match trust, store the session, and consume referenced one-time prekeys. */
  commitSessionTrust(commit: SessionTrustCommit): Promise<void>;

  /**
   * Atomically rotate one per-user identity tuple and delete every bound
   * device session. The same write deletes the sender-key handoff rows of
   * every device of the account.
   */
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
export interface SignalProtocolLocalStore
  extends
    ProtocolStore,
    SesameStore,
    SenderKeyStore,
    SenderKeyHandoffStore,
    MessageRecordStore,
    SendLogStore {
  /**
   * How this store protects its data at rest, and where its key is kept.
   */
  readonly protection: LocalStoreProtection;

  /**
   * The name of the stored data, the same in every tab, worker, and thread
   * of the origin that opens that data. When it is set and
   * `navigator.locks.request` exists, the client takes its session locks and
   * group-send locks as Web Locks under this name, so those contexts do not
   * change one session or one sender key at the same time. Without it, the
   * locks order the clients of one store object in one JavaScript context
   * only. The web SQLite store and the IndexedDB store give their database
   * names.
   */
  readonly storeIdentity?: string;
  /** Get one receive record, or null. */
  getReceiveWork(workId: string): Promise<ReceiveWorkRecord | null>;
  /**
   * Write one receive record. With `expectedRevision` null, the write
   * inserts and fails when a record exists. Otherwise it replaces the record
   * with that revision. Return false without writing on a mismatch.
   */
  putReceiveWork(record: ReceiveWorkRecord, expectedRevision: number | null): Promise<boolean>;
  /**
   * List receive records in ascending `(arrivalSeq, workId)` order. The
   * order compares `workId` values by UTF-16 code unit. With `after`, a
   * record passes when its `arrivalSeq` is above the cursor `arrivalSeq`,
   * or equal to it with a `workId` above the cursor `workId`. Return at
   * most `limit` records, 100 when not set.
   */
  listReceiveWork(query?: ReceiveWorkQuery): Promise<ReceiveWorkRecord[]>;
  /**
   * Count receive records. With `groupId`, count only the records of that
   * group that wait for a group update.
   */
  receiveWorkUsage(query?: { groupId?: string }): Promise<ReceiveWorkUsage>;
  /**
   * Delete one receive record and apply the metadata writes in one atomic
   * write. Return false without writing when the stored revision is not
   * `expectedRevision`.
   */
  completeReceiveWork(
    workId: string,
    expectedRevision: number,
    metadata?: readonly ReceiveWorkMetadataWrite[]
  ): Promise<boolean>;
  /**
   * Clear all encryption keys (use with caution!).
   *
   * Use this only for:
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
   * Used to generate new keyIds that will not collide with existing ones.
   *
   * @param identityType - 'aci' or 'pni' (defaults to 'aci')
   * @returns The highest EC signed prekey ID, or 0 if none exist
   */
  getEcSignedPreKeyMaxId(identityType?: IdentityType): Promise<number>;

  /**
   * Get the maximum Kyber prekey ID in storage.
   * Used to generate new keyIds that will not collide with existing ones.
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
  deleteAllPreKeys(
    identityType?: IdentityType
  ): Promise<{
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

  /**
   * Compare and replace one metadata value in the backing store's atomic write.
   * Null means absent or deletion. Return false without writing on a mismatch.
   * Reads and comparisons must use current backing state, not an adapter cache.
   */
  compareAndSetMetadata(
    key: string,
    expected: string | null,
    value: string | null
  ): Promise<boolean>;

  /** Delete one metadata value. */
  deleteMetadata(key: string): Promise<void>;

  /**
   * List the metadata keys that start with `prefix`, in ascending UTF-16
   * code unit order. With `after`, return only keys above it. Return at most
   * `limit` keys, 100 when not set.
   *
   * This method is optional. Without it, the SDK does not replay open sends
   * by itself.
   */
  listMetadataKeys?(query: MetadataKeyQuery): Promise<string[]>;
}

/**
 * Small local secret vault used to bootstrap a local Signal Protocol store.
 *
 * This interface is intentionally narrow: it exists for secrets that must
 * remain outside the main local store, such as a database encryption key.
 * It is not a second general-purpose Signal Protocol data store.
 */
export interface SignalProtocolLocalSecretVault {
  /**
   * Where this vault keeps its secrets. A vault that does not declare it
   * counts as `same-origin`.
   */
  readonly custody?: SecretVaultCustody;

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
 *
 * > "Each MessageRecord stores the following values:
 * >  - The plaintext of the encrypted message
 * >  - The UserID for the recipient device
 * >  - The SessionID for the session the message was encrypted with"
 *
 * The SessionID detects orphaned sessions during resending:
 *
 * > "If the DeviceRecord's active session matches the SessionID from the
 * > relevant MessageRecord, then the sending device creates a new initiating
 * > session... This prevents the sending device from repeatedly sending a
 * > message using an orphaned session which does not match any recipient
 * > session."
 *
 * The client timestamp assigned before encryption indexes a message.
 *
 * The client keeps a record only when `protocol.contentRecovery` keeps
 * content, and only for the content retention: 14 days from `createdAt` by
 * default, at most 30. The record holds no retry count. The client answers
 * at most `MAX_RETRY_RESPONSES_PER_MESSAGE` retry requests for one message.
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

  /**
   * The store clock when the store first wrote the record. Retention reads
   * this value, so the message timestamp never changes retention.
   */
  createdAt: number;

  /**
   * Sender's ratchet key (DHs.publicKey) at send time, for retry session matching.
   *
   * If the sender's current DHs differs from this stored value, the DH ratchet
   * advanced and the session is healthy. Reuse it. If it matches, the session has not
   * advanced and may need a fresh bundle.
   */
  sessionStateId: string;
}

/**
 * Interface for MessageRecord storage operations
 *
 * Used by SESAME manager to store sent messages for potential retry.
 *
 * The client timestamp assigned before encryption indexes a message. The
 * primary lookup method is getMessageRecord(sessionId, timestamp).
 */
export interface MessageRecordStore {
  /**
   * Store a message record after encryption. A record with the same
   * `sessionId` and `timestamp` is replaced. The store sets `createdAt` from
   * its clock on the first write and keeps that value on a replace, so the
   * value in `record` is not stored and a resend does not extend retention.
   */
  storeMessageRecord(record: MessageRecord): Promise<void>;

  /**
   * Get a message record by session and timestamp (PRIMARY lookup method).
   *
   * Per Signal Protocol, the client timestamp identifies a message.
   */
  getMessageRecord(sessionId: string, timestamp: number): Promise<MessageRecord | null>;

  /**
   * Delete a message record by session and timestamp.
   *
   * The client calls it after an E2EE delivery receipt from the recipient
   * device, for an expired record at a retry request, and for a record that
   * it must not resend: a null message, or a sender key distribution alone.
   */
  deleteMessageRecord(sessionId: string, timestamp: number): Promise<void>;

  /** Delete all expired message records older than maxAgeMs */
  deleteExpiredMessageRecords(maxAgeMs: number): Promise<number>;

  /** Clear all message records (for device re-registration) */
  clearAllMessageRecords(): Promise<number>;

  /** Delete all message records for a session */
  deleteMessageRecordsForSession(sessionId: string): Promise<number>;

  /**
   * Rewrite the plaintext of each record. `rewrite` returns the plaintext to
   * keep: the same string leaves the record as it is, another string
   * replaces the plaintext, and null deletes the record. A replaced record
   * keeps its `createdAt` and every other field. A record that another
   * write replaces between the read and the rewrite stays as that write
   * left it.
   *
   * @returns The number of records replaced or deleted
   */
  rewriteMessageRecords(rewrite: (record: MessageRecord) => string | null): Promise<number>;
}

// ============================================================================
// SEND LOG TYPES (resendable group content)
// ============================================================================

/**
 * One device that a logged message was sent to. The device can request the
 * content again with a retry request.
 */
export interface SendLogDevice {
  userId: string;
  deviceId: number;
}

/**
 * The content of one group send, kept for a resend to a device that could
 * not decrypt it. `clientMessageId` identifies the send. It is the Relay
 * operation ID of the group post.
 */
export interface SendLogPayload {
  clientMessageId: string;
  groupId: string;
  /** The client timestamp of the send, which a retry request names. */
  clientTimestamp: number;
  contentHint: ContentHint;
  /** The plaintext content of the send. */
  plaintext: Uint8Array;
  /**
   * The store clock when the store wrote the entry. Retention reads this
   * value, so an application-supplied timestamp never changes retention.
   */
  createdAt: number;
  /**
   * True after the send finished. A payload with no remaining recipient is
   * deleted only after the send finished, so a send in progress can still
   * add recipients.
   */
  sendComplete: boolean;
}

/** The content of a new send log entry. The store sets the other fields. */
export type NewSendLogPayload = Omit<SendLogPayload, 'createdAt' | 'sendComplete'>;

/**
 * One device that has not confirmed a logged send. The row authorizes a
 * resend to this exact device.
 */
export interface SendLogRecipient extends SendLogDevice {
  clientMessageId: string;
  /** The client timestamp of the send. A copy of the payload value, for lookup. */
  clientTimestamp: number;
  /** The number of resends to this device. It survives a restart. */
  responses: number;
}

/** A logged payload and the row of one recipient device. */
export interface SendLogEntry {
  payload: SendLogPayload;
  recipient: SendLogRecipient;
}

/** The state of a resend job. Only a `pending` job runs. */
export type SendLogResendJobState = 'pending' | 'posted' | 'abandoned';

/**
 * A persisted resend of logged content to one requesting device. A job
 * holds no plaintext. It names the logged entry.
 */
export interface SendLogResendJob {
  jobId: string;
  clientMessageId: string;
  requesterUserId: string;
  requesterDeviceId: number;
  /** The retry attempt ID of the request. */
  retryId: string;
  /** The Relay envelope ID of the retry request. */
  requestEnvelopeId: string;
  /**
   * The envelope that the requester could not decrypt. Only the job whose
   * resend answers the request attempt has it: when written, the job of
   * the first logged entry that the request names, and at the post, the
   * job of the first entry that the answer admits. Another job has none,
   * and its resend posts under a new ID.
   */
  failedEnvelopeId?: string;
  /** The store clock when the job was first written. */
  createdAt: number;
  attempts: number;
  state: SendLogResendJobState;
}

/**
 * Storage of resendable group content.
 *
 * The send log keeps the plaintext of each resendable group send with a row
 * for each recipient device, until that device confirms the message or the
 * entry expires. A recipient device that cannot decrypt the message asks
 * for it again, and only a device with a row gets the content.
 */
export interface SendLogStore {
  /**
   * Store a send log entry and its recipient rows in one transaction. An
   * entry with the same `clientMessageId` is replaced with its rows.
   */
  storeSendLogEntry(payload: NewSendLogPayload, recipients: readonly SendLogDevice[]): Promise<void>;

  /**
   * Add recipient rows to an entry. An existing row is kept unchanged. With
   * no entry, nothing is written.
   */
  appendSendLogRecipients(clientMessageId: string, recipients: readonly SendLogDevice[]): Promise<void>;

  /**
   * Mark the send finished. When no recipient row remains, the payload is
   * deleted.
   */
  markSendLogComplete(clientMessageId: string): Promise<void>;

  /** The entry of one send for one device, or null when the device has no row. */
  getSendLogEntry(clientMessageId: string, recipient: SendLogDevice): Promise<SendLogEntry | null>;

  /** Every entry for one device at one client timestamp, ordered by `clientMessageId`. */
  findSendLogEntries(recipient: SendLogDevice, clientTimestamp: number): Promise<SendLogEntry[]>;

  /** The remaining recipient rows of one send, ordered by user and device. */
  getSendLogRecipients(clientMessageId: string): Promise<SendLogRecipient[]>;

  /**
   * Delete the row of one device. When no row remains and the send is
   * finished, the payload is deleted. Returns true when a row was deleted.
   */
  deleteSendLogRecipient(clientMessageId: string, recipient: SendLogDevice): Promise<boolean>;

  /**
   * Delete the rows of one device at each of the client timestamps, with the
   * same payload rule as `deleteSendLogRecipient`. Returns the number of
   * deleted rows.
   */
  deleteSendLogRecipientsByTimestamp(
    recipient: SendLogDevice,
    clientTimestamps: readonly number[]
  ): Promise<number>;

  /**
   * Add one to the resend count of a row. Returns the new count, or null
   * when the device has no row.
   */
  incrementSendLogResendCount(clientMessageId: string, recipient: SendLogDevice): Promise<number | null>;

  /** Delete one entry and its rows. Returns true when an entry was deleted. */
  deleteSendLogEntry(clientMessageId: string): Promise<boolean>;

  /**
   * Delete each entry, and each resend job, that the store wrote more than
   * `maxAgeMs` ago. Returns the number of deleted entries.
   */
  deleteExpiredSendLog(maxAgeMs: number): Promise<number>;

  /** Delete every entry and resend job. Returns the number of deleted entries. */
  clearSendLog(): Promise<number>;

  /**
   * Store a resend job. A job with the same `jobId` is replaced. The store
   * sets `createdAt` from its clock on the first write and keeps that value
   * on a replace, so the value in `job` is not stored.
   */
  storeResendJob(job: SendLogResendJob): Promise<void>;

  /** One resend job, or null. */
  getResendJob(jobId: string): Promise<SendLogResendJob | null>;

  /** Every `pending` resend job, ordered by `createdAt`, then `jobId`. */
  getPendingResendJobs(): Promise<SendLogResendJob[]>;

  /** Set the final state of a resend job. With no job, nothing is written. */
  completeResendJob(jobId: string, state: Exclude<SendLogResendJobState, 'pending'>): Promise<void>;
}

// ============================================================================
// STORAGE PROTECTION
// ============================================================================

/**
 * How a local store encrypts its data at rest.
 *
 * - `file-cipher`: the database file is encrypted, as with SQLCipher.
 * - `record-cipher`: each stored value is encrypted.
 * - `none`: the data is stored in the clear.
 */
export type LocalStoreAtRest = 'file-cipher' | 'record-cipher' | 'none';

/**
 * Where the key of a secret vault is kept.
 *
 * - `os-keychain`: the operating system keychain or keystore.
 * - `app-vault`: a vault that the application controls and declares.
 * - `same-origin`: storage that the data shares, such as the same browser
 *   origin.
 */
export type SecretVaultCustody = 'os-keychain' | 'app-vault' | 'same-origin';

/** Where the key of a local store is kept. `none` means there is no key. */
export type LocalStoreKeyCustody = SecretVaultCustody | 'none';

/** The protection of the data in a local store. */
export interface LocalStoreProtection {
  readonly atRest: LocalStoreAtRest;
  readonly keyCustody: LocalStoreKeyCustody;
}

// ════════════════════════════════════════════════════════════════════════════
// Group re-exports (defined in internal/groups/manager.ts)
// ════════════════════════════════════════════════════════════════════════════

export type {
  GroupStateStore,
  GroupServer,
  GroupSnapshot,
  GroupChangeLogEntry,
} from '../internal/groups/manager';
