/**
 * Internal types for SignalProtocolClient module
 *
 * These types are used to pass dependencies between the core DefaultSignalProtocolClient class
 * and the extracted operation modules.
 */

import type { SealedSenderAuth, SignalProtocolRelayServer } from '../remote/relay/types';
import type { SignalProtocolRemoteObjectStore } from '../remote/object-store';
import type { SignalProtocolLocalStore, SignalProtocolManager } from '../types';
import type { SignalProtocolClientConfig } from './config';
import type { SesameManager } from '../internal/sesame/types';
import type { SignalProtocolClientHooks } from './event-hooks';
import { ContentHint } from '../types/messages';
import type { SignalProtocolContentAdapter } from './content-adapter';
import type { ProfileKeyExchange } from './profile-key-exchange';
import type { RetryTerminalResetSteps } from './retry-terminal-recovery';
import type { DeliveryStatusTracker } from './delivery-status';
import type { ResendableContent } from './resendable-content';
import type { Logger } from '../logger';
import type {
  MediaAttachmentCheckpointCallback,
  MediaAttachmentPointer,
  MediaAttachmentPolicy,
  MediaAttachmentProgressCallback,
  MediaAttachmentRetryOptions,
  MediaAttachmentResumeState,
  MediaAttachmentTransfer,
  ResolvedMediaAttachment,
} from '../media';

/**
 * Context passed to operation functions
 *
 * Contains all dependencies needed for SignalProtocolClient operations.
 * This enables extraction of operations into separate modules while
 * maintaining access to shared state.
 */
export {};
export interface SignalProtocolClientContext {
  /** User identifier */
  readonly userId: string;

  /** Device identifier (1 = primary, 2-5 = linked devices) */
  readonly deviceId: number;

  /** Protocol manager for encryption/decryption */
  readonly manager: SignalProtocolManager;

  /** Key and session storage */
  readonly storage: SignalProtocolLocalStore;

  /** Optional relay server for server sync */
  readonly relay?: SignalProtocolRelayServer;

  /** Optional brokered remote object store for encrypted attachments. */
  readonly remoteObjectStore?: SignalProtocolRemoteObjectStore;

  /** Client configuration */
  readonly config: SignalProtocolClientConfig;

  /** Resolved client logger */
  readonly logger: Required<Logger>;

  /** Optional lifecycle hooks */
  readonly hooks?: SignalProtocolClientHooks;

  /** Sesame manager for multi-device support */
  readonly sesameManager: SesameManager;

  /** App-provided content adapter */
  readonly contentAdapter: SignalProtocolContentAdapter;

  /**
   * The profile key exchange of a hosted client, or `undefined`
   *
   * @internal
   */
  readonly profileKeys?: ProfileKeyExchange;

  /**
   * Aborts when stop() stops relay work. The lock waits of that work read
   * it. Each receipt send reads the stop signal of the tracker, so stop()
   * clears the retry timer of a receipt send that started before stop()
   * stops its relay work.
   *
   * @internal
   */
  readonly stopSignal?: AbortSignal;

  /**
   * The delivery status of the outgoing messages of this client.
   *
   * @internal
   */
  readonly deliveries?: DeliveryStatusTracker;

  /**
   * The resendable content of this client and its retention.
   *
   * @internal
   */
  readonly resendableContent: ResendableContent;

  /**
   * Arm the retry request scheduler for the next attempt time or the
   * deadline of a request record.
   *
   * @internal
   */
  readonly scheduleRetryRequest?: (at: number) => void;

  /**
   * The session reset steps of a retry request that ended as
   * `expired-content` or `posting-deadline`, bound to the given context.
   * Undefined without a relay.
   *
   * @internal
   */
  readonly retryTerminalReset?: (
    context: SignalProtocolClientContext
  ) => RetryTerminalResetSteps | undefined;

  /**
   * The registration ID of the current session with one device, from the
   * cipher. An identified receipt and an identified retry request name it,
   * so the Relay refuses the post to a reinstalled device. Undefined when
   * this client has no session with the device.
   *
   * @internal
   */
  readonly recipientRegistrationId?: (
    recipientUserId: string,
    recipientDeviceId: number
  ) => Promise<number | undefined>;

  /**
   * Archive the session with a device that the Relay refused as stale, and
   * start a new session from a fresh bundle. The session hooks run through
   * the given context. Resolves to true when the new session is ready.
   * Resolves to false without a relay, and when the Relay has no bundle of
   * the device. Rejects with StaleSessionRefreshError when the bundle fetch
   * or the new session fails. A failed fetch keeps the stale session.
   *
   * @internal
   */
  readonly refreshStaleSession?: (
    context: SignalProtocolClientContext,
    recipientUserId: string,
    recipientDeviceId: number
  ) => Promise<boolean>;

  /**
   * Seal an encrypted receipt for anonymous delivery. Resolves to undefined
   * when the receipt goes identified. Rejects when sealed sender is required
   * and the receipt cannot be sealed.
   *
   * @internal
   */
  readonly sealReceipt?: (
    recipientUserId: string,
    recipientDeviceId: number,
    ciphertextBase64: string
  ) => Promise<SealedReceipt | undefined>;

  /**
   * Seal the payload of a retry request for anonymous delivery. Resolves to
   * undefined when the request goes identified. Rejects when sealed sender
   * is required and the request cannot be sealed.
   *
   * @internal
   */
  readonly sealRetryRequest?: (
    recipientUserId: string,
    recipientDeviceId: number,
    payloadBase64: string
  ) => Promise<SealedReceipt | undefined>;
}

/**
 * One encrypted receipt or one retry request sealed for anonymous delivery.
 *
 * @internal
 */
export interface SealedReceipt {
  readonly sentMessageBase64: string;
  readonly auth: SealedSenderAuth;
  /**
   * Whether a Relay that refuses the access key sends the envelope
   * identified. False when sealed sender is required, as for a message.
   */
  readonly identifiedFallback: boolean;
}

/**
 * Minimal structured message input for SignalProtocolClient.send().
 * Matches the shape of DataMessage from the content layer without importing it.
 * Any object with a `timestamp` field (and no Blob/Uint8Array prototype) qualifies.
 */
export interface DataMessageInput {
  /**
   * The send timestamp, in milliseconds since the epoch. Default: the SDK
   * clock. A new send accepts a safe positive integer at most 5 minutes ahead
   * of the SDK clock and at most 24 hours behind it, and throws
   * `InvalidSendTimestampError` for any other value.
   *
   * The next major SDK version makes each send timestamp unique per sender
   * device. A new send with a timestamp that a different send of the device
   * used then throws `InvalidSendTimestampError`. Give each send its own
   * timestamp, or omit it and read `SendResult.clientTimestamp`.
   */
  timestamp?: number;
  [key: string]: unknown;
}

export interface AttachmentTransferOptions {
  transfer?: MediaAttachmentTransfer;
  retry?: MediaAttachmentRetryOptions;
  policy?: MediaAttachmentPolicy;
  signal?: AbortSignal;
  onProgress?: MediaAttachmentProgressCallback;
  onCheckpoint?: MediaAttachmentCheckpointCallback;
  resume?: MediaAttachmentResumeState;
}

/**
 * Options for SignalProtocolClient.send()
 *
 * Extensible for future features like disappearing messages and threads.
 */
export interface SendOptions {
  /** MIME type for binary content (e.g., 'image/jpeg', 'application/pdf') */
  mimeType?: string;

  /**
   * Marks Uint8Array content as binary file data (vs protobuf/text bytes).
   * When true with Uint8Array content, routes to blob encryption flow.
   */
  isBinary?: boolean;

  /**
   * Upload/download lifecycle controls for attachment operations.
   */
  attachment?: AttachmentTransferOptions;

  /** Disappearing message duration in milliseconds (future feature) */
  expiresIn?: number;

  /** Message ID to reply to for thread support (future feature) */
  replyTo?: string;

  // profile attachment metadata
  /** BlurHash for instant placeholder (~25 chars, base-83 encoded) */
  blurHash?: string;

  /** Base64-encoded preview thumbnail stored inside encrypted attachment metadata */
  thumbnail?: string;

  /** Media width in pixels (for layout before download) */
  width?: number;

  /** Media height in pixels (for layout before download) */
  height?: number;

  /** Media duration in milliseconds for video/audio attachments */
  durationMs?: number;

  /** Voice-message waveform samples, each represented as an integer from 0 to 255 */
  waveform?: number[];

  /** Media attachment flags bitmap, for example MediaAttachmentFlag.VoiceMessage */
  flags?: number;

  /** Optional client-generated media identifier for cross-device reconciliation */
  clientUuid?: string;

  /** Optional CDN number when the remote object backend distinguishes CDN tiers */
  cdnNumber?: number;

  /** Original file name */
  fileName?: string;

  /** Caption text for attachment */
  caption?: string;

  /** Whether this is a view-once attachment */
  isViewOnce?: boolean;

  /**
   * Client timestamp for receipt matching.
   * Store the same timestamp locally for delivery receipt lookup.
   * A new send accepts a safe positive integer at most 5 minutes ahead of the
   * SDK clock and at most 24 hours behind it, and throws
   * `InvalidSendTimestampError` for any other value.
   *
   * The next major SDK version makes each send timestamp unique per sender
   * device. A new send with a timestamp that a different send of the device
   * used then throws `InvalidSendTimestampError`. Give each send its own
   * timestamp. A retry with the same `clientMessageId` keeps its timestamp.
   */
  timestamp?: number;

  /**
   * Stable client-generated send identifier for retry idempotency.
   *
   * The SDK generates this value when it is omitted. An application that
   * retries a failed send explicitly must reuse the identifier. If it also
   * supplies a timestamp, that timestamp must match the original send. The SDK
   * persists the exact encrypted transmission before it contacts the Relay, so
   * an unknown result never advances the protocol ratchet twice.
   *
   * On a relay that does not compare device sets, a first send that fails on
   * the read of the own device list throws before the SDK stores it. The
   * error carries this identifier, but the outbox holds no transmission for
   * it. The application calls `send()` again, and the SDK encrypts the
   * content again.
   */
  clientMessageId?: string;

  /**
   * Content hint for recipient retry behavior.
   *
   * A group send of a `DataMessage` defaults to `Resendable` when
   * `protocol.contentRecovery` keeps content, and the client logs its
   * content for a retry request before it sends. When the policy keeps no
   * content, the send goes out as `Default`. A group send of a string or
   * bytes keeps no content, so a `Resendable` hint on it goes out as
   * `Default`. Use `Implicit` for protocol and no-op payloads, such as
   * NullMessage resend responses, that the recipient discards on failure.
   */
  contentHint?: ContentHint;

  /**
   * Application user IDs of the group's members, for local-first fan-out.
   *
   * **Required for every group send**. A group send without it throws rather
   * than delivering to nobody. The relay keeps no `groupId -> member` map by
   * design, so it cannot supply the roster. The SDK cannot derive it either.
   * Decrypted group state identifies members by ACI
   * (`DecryptedMember.aciBytes`), while the relay routes by application
   * `userId`, and only the application holds that mapping.
   *
   * Resolve the roster from local group state, map each member's ACI to your
   * own account identifier, and pass the result. The cipher expands these to
   * devices via `relay.getActiveDevices()`.
   */
  groupMemberUserIds?: string[];
}

/**
 * Result of encrypting and uploading an attachment without sending a message.
 *
 * Used when a higher-level content payload wants to embed attachment metadata
 * atomically instead of sending a standalone attachment message.
 */
export type PreparedAttachmentUpload = MediaAttachmentPointer;

/**
 * Result of downloading and decrypting an attachment pointer.
 */
export type DownloadedAttachment = ResolvedMediaAttachment;

/**
 * Result from SignalProtocolClient.send()
 *
 * Provides uniform response regardless of content type (string/Blob) or
 * recipient type (user/group).
 */
export interface SendResult {
  /** Stable logical-send identifier used by the exact-ciphertext outbox. */
  clientMessageId: string;

  /** Server-assigned message ID for tracking and markAsRead() */
  messageId: string;

  /** Server timestamp when the relay accepted the message */
  timestamp: number;

  /**
   * Client timestamp from the proto.
   * Use this for storing outgoing messages to enable receipt matching.
   */
  clientTimestamp?: number;

  /**
   * Number of recipient devices that the relay accepted a copy of the message
   * for. Acceptance is not delivery: a device receives its copy when it next
   * reads its mailbox.
   */
  recipientDeviceCount: number;

  /**
   * True when the relay had already accepted every device post of this send,
   * so the send stored no new copy. This is the case when the application
   * calls `send()` again with the `clientMessageId` of a send whose posts the
   * relay accepted but whose result did not arrive. For a group send over a
   * group token, the shared post reports that the relay had already accepted
   * its fan-out, not that each destination stored a copy. The sender key
   * pre-messages of a group send do not count. Absent when a post did not
   * report it, as on a relay that does not report it.
   */
  duplicate?: boolean;

  /**
   * The earliest time, in milliseconds since the epoch, at which the relay
   * drops the copy of a device post that the device has not acknowledged.
   * The sender key pre-messages of a group send do not count. Absent when a
   * post did not report it.
   */
  expiresAt?: number;

  /**
   * For a group send over a group token, the number of destination devices
   * that the relay refused when it accepted the shared post. A refusal after
   * that acceptance is not counted. Absent for any other send, and when the
   * relay does not report it.
   */
  refusedDestinationCount?: number;

  /**
   * True when the relay accepted the send for every recipient device but the
   * copies for this account's other devices are not posted yet. The send is
   * delivered. Call `send()` again with the same `clientMessageId` before the
   * posting deadline of the send to post the pending copies. No sync post
   * starts at or after that deadline, and a replay of such a send returns
   * `syncPending` again. Absent when the copies were posted or none were due.
   */
  syncPending?: true;

  /** Group ID if sent to a group */
  groupId?: string;

  // Attachment-specific fields (only present for blob sends)
  /** Opaque remote object identifier for the encrypted attachment */
  storageId?: string;

  /** Base64-encoded AES-256 master key */
  aesKey?: string;

  /** Segment size for streaming AEAD format */
  segmentSize?: number;

  /** Base64-encoded SHA-256 digest for the encrypted blob */
  digest?: string;

  /** MIME content type for the encrypted media */
  contentType?: string;
}

/**
 * A send failure that carries the logical-send identifier.
 *
 * `isOutgoingMessageError` is true for every send error, also for an error
 * before the SDK stores the send, such as a failed content serialization or
 * a failed read of the own device list on a relay that does not compare
 * device sets. The exact encrypted transmission stays in the outbox only for a send
 * that the SDK already stored. In both cases, the application calls `send()`
 * again with the same `clientMessageId`. For a stored send, the durable
 * outbox supplies the original timestamp. For a send that the SDK did not
 * store, the SDK encrypts the content again.
 *
 * A direct send attempts every device of the recipient, also when a device
 * before it fails, and the error is that of the first failed device. A
 * replay sends to every device again, with the stored bytes and the stored
 * timestamp. The Relay keeps one copy for a device while it remembers the
 * result of that device. From the Relay release that follows v2026.10.25, it
 * remembers the result for 24 hours after the timestamp of the send.
 *
 * A direct or group send has a posting deadline, `deadlineAt`: the earlier of 24 hours
 * after the SDK first stores the send and 24 hours after its timestamp. A
 * replay or a restart never moves it. At or after it, the SDK starts no
 * request for the send, and the replay ends with the stored result or error.
 * The outbox keeps a send for 30 days after it stores it. A replay after that
 * time is a new send, with a new timestamp and a new deadline.
 */
export interface OutgoingMessageError extends Error {
  readonly clientMessageId: string;
  /**
   * The posting deadline of a stored send, in milliseconds since the epoch.
   * Absent when the SDK did not store the send.
   */
  readonly deadlineAt?: number;
  /**
   * True on a send error before `deadlineAt` that leaves a device open: a
   * replay with the same `clientMessageId` can post it. False when the send
   * ended at its deadline. Absent on an error that keeps its own retry rule.
   */
  readonly retryable?: boolean;
  /** The Relay's own `retryable` hint, when the SDK set `retryable`. */
  readonly relayRetryable?: boolean;
  /** The devices that the Relay accepted, when the send ended at its deadline. */
  readonly acceptedDevices?: readonly { readonly userId: string; readonly deviceId: number }[];
  /** The devices that the Relay refused, when the send ended at its deadline. */
  readonly refusedDevices?: readonly { readonly userId: string; readonly deviceId: number }[];
}

/** Return true when a send error exposes its logical-send identifier. */
export function isOutgoingMessageError(error: unknown): error is OutgoingMessageError {
  return (
    error instanceof Error &&
    'clientMessageId' in error &&
    typeof (error as { clientMessageId?: unknown }).clientMessageId === 'string'
  );
}

/**
 * Safety number for verifying identity with another user
 *
 * Generated by DefaultSignalProtocolClient.verify() for out-of-band verification.
 */
export interface SafetyNumber {
  /** 60-digit numeric code for voice/phone verification */
  numeric: string;

  /** Raw fingerprint bytes for QR code generation */
  fingerprint: Uint8Array;

  /** User ID this safety number is for */
  userId: string;

  /** Per-user identity namespace used for this comparison. */
  identityType: import('../keys').IdentityType;

  /** Generating a safety number never promotes this state. */
  trustState: import('../keys').IdentityTrustState | null;

  /**
   * Immutable evidence for the exact value displayed to the user.
   * Pass this object to confirmSafetyNumber() after authenticated comparison.
   */
  confirmation: SafetyNumberConfirmation;
}

/**
 * Exact safety-number comparison evidence.
 *
 * This uses strings instead of mutable Uint8Array instances, so application code
 * cannot accidentally change the value between display and confirmation.
 *
 * Version 2 carries the fingerprint in the byte order of the two display
 * strings. A version 1 confirmation from an older SDK is refused as an
 * unsupported version. Call `verify()` again to get a new one.
 */
export interface SafetyNumberConfirmation {
  readonly version: 2;
  readonly userId: string;
  readonly identityType: import('../keys').IdentityType;
  /** Canonical Base64 of the complete displayed composite fingerprint. */
  readonly fingerprint: import('../types/utils').Base64;
  /** Canonical Base64 of the locally derived remote composite commitment. */
  readonly remoteIdentityCommitment: import('../types/utils').Base64;
}

// ════════════════════════════════════════════════════════════════════════════
// SESSION HEALTH TYPES
// ════════════════════════════════════════════════════════════════════════════

/**
 * Session health status levels
 */
export type SessionHealthStatus = 'healthy' | 'warning' | 'error';

/**
 * Individual issue found during session health check
 */
export interface SessionHealthIssue {
  /** Machine-readable issue code */
  code: string;
  /** Issue severity */
  severity: 'warning' | 'error';
  /** Human-readable description */
  message: string;
  /** Additional details for debugging */
  details?: Record<string, unknown>;
}

/**
 * Result from session health check
 *
 * Provides detailed diagnostics about session state, key validity,
 * and any issues that may affect encryption.
 */
export interface SessionHealthResult {
  /** Overall health status */
  status: SessionHealthStatus;
  /** Whether a session exists with this user */
  sessionExists: boolean;
  /** List of issues found */
  issues: SessionHealthIssue[];

  /** Key status information */
  keyStatus: {
    hasIdentityKey: boolean;
    hasSignedPreKey: boolean;
    hasKyberPreKey: boolean;
    signedPreKeyAgeDays: number;
    kyberPreKeyAgeDays: number;
    needsRotation: boolean;
  };

  /** Session-specific status (only if session exists) */
  sessionStatus?: {
    createdAt: number;
    lastUsedAt: number;
    ageDays: number;
    isExpiredForSending: boolean;
    isExpiredForReceiving: boolean;
    messagesSent: number;
    messagesReceived: number;
  };

  /** When the client ran this check */
  checkedAt: number;
  /** Summary message for UI display */
  message: string;
}

// ════════════════════════════════════════════════════════════════════════════
// DELIVERY RECEIPT TYPES
// ════════════════════════════════════════════════════════════════════════════

/**
 * Receipt type enum for encrypted application messages.
 *
 */
export enum ReceiptType {
  /** Message was delivered to recipient's device */
  DELIVERY = 0,
  /** Message was read by recipient */
  READ = 1,
  /** Message was viewed by recipient (e.g., view-once media) */
  VIEWED = 2,
}

/**
 * Delivery receipt sent from recipient back to sender
 *
 * Receipts use timestamps, not sequence numbers, to identify messages and can
 * batch multiple timestamps:
 * ```protobuf
 * message ReceiptMessage {
 *   enum Type { DELIVERY = 0; READ = 1; VIEWED = 2; }
 *   optional Type   type      = 1;
 *   repeated uint64 timestamp = 2;
 * }
 * ```
 */
export interface DeliveryReceipt {
  /** Type of receipt (DELIVERY, READ, or VIEWED) */
  type: ReceiptType;

  /**
   * Array of message timestamps that this receipt confirms
   *
   * Per Signal Protocol, messages are identified by their timestamp (createdAt)
   * rather than sequence numbers in delivery receipts.
   */
  timestamps: number[];
}

// ════════════════════════════════════════════════════════════════════════════
// TYPING INDICATORS
// ════════════════════════════════════════════════════════════════════════════

/**
 * Typing-indicator action enum.
 *
 * Typing indicators are application-layer messages that use the same
 * encrypted messaging channel as regular messages, but are:
 * - Transient (not persisted)
 * - Real-time only (not queued if recipient offline)
 * - Privacy-respecting (mutual opt-in required)
 */
export enum TypingAction {
  /** User started typing */
  STARTED = 0,
  /** User stopped typing (cleared input, sent message, or navigated away) */
  STOPPED = 1,
}

/**
 * Typing indicator sent between users
 *
 * Typing indicators are ephemeral application messages that:
 * - Use the same encrypted channel as regular messages
 * - Are NOT stored on the server (transient)
 * - Respect sealed sender when available
 * - Auto-expire after 15 seconds if no refresh
 *
 * Application-message shape:
 * ```protobuf
 * message TypingMessage {
 *   enum Action { STARTED = 0; STOPPED = 1; }
 *   optional uint64 timestamp = 1;
 *   optional Action action    = 2;
 *   optional bytes  groupId   = 3;
 * }
 * ```
 */
export interface TypingIndicator {
  /** Whether user started or stopped typing */
  action: TypingAction;

  /** Timestamp when indicator was sent (for ordering/deduplication) */
  timestamp: number;

  /** Conversation ID for routing (dm:userId1_userId2 or group:groupId) */
  conversationId: string;

  /** Optional group ID for group conversations */
  groupId?: string;
}

// ════════════════════════════════════════════════════════════════════════════
// INCOMING ENVELOPE PROCESSING
// Unified entry point for foreground (relay) and background (HTTP) message handling
// ════════════════════════════════════════════════════════════════════════════

/**
 * Incoming message envelope structure.
 *
 * Matches both relay subscription envelopes and background pending messages.
 * Used by processIncomingEnvelope() for unified message handling.
 */
export interface IncomingEnvelope {
  /** Server-assigned message ID */
  id: string;

  /**
   * The SDK ID of the message, when the relay assigns its own `id` and
   * delivers the SDK ID with the envelope. The retry family of a resend or
   * a null message resolves by this ID, or by `id` when it is absent. The
   * processed record and the acknowledgment use `id`.
   */
  clientMessageId?: string;

  /** Sender's user ID (Convex _id) */
  senderUserId: string;

  /** Sender's device ID */
  senderDeviceId: number;

  /** Base64-encoded ciphertext */
  ciphertext: string;

  /**
   * Client timestamp for message identification.
   * Set by sender BEFORE encryption. Used for retry requests and replay prevention.
   */
  timestamp: number;

  /** Server timestamp when the relay received the message */
  serverTimestamp?: number;

  /**
   * Message type for filtering (ciphertext, prekey_bundle, etc.).
   *
   * `sender_key` marks group traffic: the payload is a framed
   * SenderKeyMessage. It names no group (no envelope does), and the receiver
   * resolves the group from the frame's opaque distribution identifier against the
   * local sender key store.
   */
  messageType?: string;

  /**
   * The content hint of the sender. It sets what the receiver does when a
   * decrypt fails with an error that a resend can repair.
   *
   * - `Default`: the client sends a retry request and runs
   *   `onDeliveryError` at once.
   * - `Resendable`: the client sends a retry request. It runs
   *   `onDeliveryError` one hour after the receive
   *   (`RETRY_PLACEHOLDER_DEADLINE_MS`) if the content has not arrived. It
   *   runs it at once when a rate limit refuses the request, when the
   *   request allowance for the sender is used up, or when the request
   *   ends.
   * - `Implicit`: disposable content, such as typing indicators and
   *   receipts. The client sends no retry request and never runs
   *   `onDeliveryError`. A resend that answers a retry request of this
   *   device still asks again.
   *
   * With no hint, the client uses the `Default` behavior.
   */
  contentHint?: ContentHint;
}

/**
 * Options for processing incoming message envelopes.
 *
 * Used when SignalProtocolClient does not have a relay (e.g., background tasks).
 * Provides callbacks for sending retry requests and marking messages delivered.
 */
export interface ProcessEnvelopeOptions {
  /**
   * Callback to send retry requests when no relay is available.
   *
   * Required for background processing where there is no WebSocket relay.
   * The callback receives a `retry_request` envelope for the device that sent
   * the failed message. Deliver it to that device as any other envelope.
   * The envelope is identified, and without a relay the client cannot seal
   * it. The client calls the callback only when the sealed sender delivery
   * mode permits identified delivery, so `'required'` never calls it.
   */
  sendRetryRequest?: (envelope: import('../remote/relay/types').Envelope) => Promise<void>;

  /**
   * Callback that acknowledges an envelope when no relay is available.
   *
   * The client calls it after it sends a retry request for a failed
   * envelope, and after it discards an envelope that it does not process
   * again, so the envelope is not fetched again.
   */
  markDelivered?: (messageId: string) => Promise<void>;

  /**
   * Force prekey rotation when the client detects a stale prekey.
   *
   * Generate new keys, clear stale KEM prekeys, and upload fresh bundle.
   *
   * Required for background processing where there is no relay.
   * Called before sending retry request when PREKEY_NOT_FOUND or MAC_FAILED
   * on PreKeyMessage indicates stale/corrupted keys.
   *
   */
  forcePreKeyRotation?: () => Promise<void>;

  /**
   * Save content that `processIncomingEnvelope` gives. The client calls it
   * with the `processed` outcome before the method returns. When it
   * resolves, the client completes the receive record, so you do not call
   * `completeReceive`. When it rejects, the method still returns the
   * `processed` outcome, and the record waits for `completeReceive` or for
   * its expiry. A redelivery of the envelope calls it again.
   */
  onPersist?: (outcome: ProcessedReceive) => Promise<void>;
}

/**
 * Content that `processIncomingEnvelope` gives. The client keeps it until
 * the application calls `completeReceive` with its `messageId`, or until
 * it expires after 30 days on this device. A redelivery of the
 * envelope gives it again with the same `messageId`.
 */
export interface ProcessedReceive {
  kind: 'processed';
  /** The content, as its sender gave it. */
  plaintext: string;
  /** The ID that `completeReceive` takes. */
  messageId: string;
  /** The group of group content. */
  groupId?: string;
}

/**
 * The outcome of `processIncomingEnvelope`.
 *
 * - `processed`: the client gives the content. Save it, then call
 *   `completeReceive`, or pass `onPersist`. Acknowledge the envelope.
 * - `pending`: the client stored the content, and it waits for its group
 *   state. The client resumes it and `listPendingReceives({ ready: true })`
 *   lists it when it is ready. Acknowledge the envelope.
 * - `duplicate`: the client processed the envelope before, or the
 *   application already has its content. Acknowledge the envelope.
 * - `null-message`: the envelope carries no content. Acknowledge it.
 * - `denied`: the client refused the content and ran `onDecryptionError`,
 *   except for a group that the user blocked (reason `blocked`), which has
 *   no report. Acknowledge the envelope.
 * - `refused`: the receive queue has no room, so the client decrypted
 *   nothing. Do not acknowledge the envelope. Give it again later.
 */
export type ReceiveOutcome =
  | ProcessedReceive
  | { kind: 'pending'; messageId: string; reason: string }
  | { kind: 'duplicate' }
  | { kind: 'null-message' }
  | { kind: 'denied'; reason: string }
  | { kind: 'refused'; persisted: false; reason: string };

/** One receive that `processIncomingEnvelope` stored and did not complete. */
export interface PendingReceive {
  /**
   * The ID that `completeReceive` and `discardPendingReceive` take. A
   * receive stored before the client kept message IDs gives its record ID.
   */
  messageId: string;
  /**
   * `awaiting-completion` when the content is ready and waits for
   * `completeReceive`. `decrypted` when it waits for its group state.
   */
  stage: 'decrypted' | 'awaiting-completion';
  /** `caller` for an envelope that the application gave. */
  origin: 'relay' | 'caller';
  /** The time of the first decrypt. */
  receivedAt: number;
  senderId?: string;
  senderDeviceId?: number;
  groupId?: string;
  /** The content of a ready receive, as its sender gave it. */
  plaintext?: string;
  /**
   * The calls of `onMessageDecrypted` that started for this receive and
   * did not complete it. At the cap of 10 attempts, the receive holds back
   * no later receive, and each start offers it to the hook once.
   */
  hookAttempts: number;
}
