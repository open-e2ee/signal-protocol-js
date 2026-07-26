/**
 * Internal types for SignalProtocolClient module
 *
 * These types are used to pass dependencies between the core SignalProtocolClient class
 * and the extracted operation modules.
 */

import type { ISignalProtocolRelayServer } from '../remote/relay/types';
import type { SignalProtocolRemoteObjectStore } from '../remote/object-store';
import type { ISignalProtocolLocalStore, ISignalProtocolManager } from '../types';
import type { SignalProtocolClientConfig } from './config';
import type { ISesameManager } from '../internal/sesame/types';
import type { SignalProtocolClientHooks } from './event-hooks';
import { ContentHint } from '../types/messages';
import type { SignalProtocolContentAdapter } from './content-adapter';
import type { ILogger } from '../logger';
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
  readonly manager: ISignalProtocolManager;

  /** Key and session storage */
  readonly storage: ISignalProtocolLocalStore;

  /** Optional relay server for server sync */
  readonly relay?: ISignalProtocolRelayServer;

  /** Optional brokered remote object storage for encrypted attachments. */
  readonly remoteObjectStore?: SignalProtocolRemoteObjectStore;

  /** Client configuration */
  readonly config: SignalProtocolClientConfig;

  /** Resolved client logger */
  readonly logger: Required<ILogger>;

  /** Optional lifecycle hooks */
  readonly hooks?: SignalProtocolClientHooks;

  /** Sesame manager for multi-device support */
  readonly sesameManager: ISesameManager;

  /** App-provided content adapter */
  readonly contentAdapter: SignalProtocolContentAdapter;
}

/**
 * Minimal structured message input for SignalProtocolClient.send().
 * Matches the shape of DataMessage from the content layer without importing it.
 * Any object with a `timestamp` field (and no Blob/Uint8Array prototype) qualifies.
 */
export interface DataMessageInput {
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
   * Same timestamp should be stored locally for delivery receipt lookup.
   */
  timestamp?: number;

  /**
   * Stable client-generated send identifier for retry idempotency.
   *
   * Retries of the same logical send should reuse this value with the same
   * timestamp. Relay adapters that support it can return the original accept
   * result instead of inserting a duplicate envelope after an unknown result.
   */
  clientMessageId?: string;

  /**
   * Content hint for recipient retry behavior.
   *
   * Used for protocol/no-op payloads (for example NullMessage resend responses)
   * that should be treated as IMPLICIT and silently discarded on failure.
   */
  contentHint?: ContentHint;

  /**
   * Pre-resolved group member user IDs (local-first member resolution).
   * The caller provides the member list from local SQLite since group membership
   * is not stored on the server. The cipher resolves these to device IDs via
   * relay.getActiveDevices().
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
  /** Server-assigned message ID for tracking and markAsRead() */
  messageId: string;

  /** Server timestamp when message was accepted */
  timestamp: number;

  /**
   * Client timestamp from the proto.
   * Use this for storing outgoing messages to enable receipt matching.
   */
  clientTimestamp?: number;

  /** Number of recipient devices that received the message */
  recipientDeviceCount: number;

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
 * Safety number for verifying identity with another user
 *
 * Generated by SignalProtocolClient.verify() for out-of-band verification.
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
 * Strings are used instead of mutable Uint8Array instances so application code
 * cannot accidentally change the value between display and confirmation.
 */
export interface SafetyNumberConfirmation {
  readonly version: 1;
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

  /** When this check was performed */
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

  /** Server timestamp when message was received */
  serverTimestamp?: number;

  /** Message type for filtering (ciphertext, prekey_bundle, etc.) */
  messageType?: string;

  /** Group ID for group messages */
  groupId?: string;

  /**
   * Content hint for retry behavior per Signal Protocol.
   *
   * - IMPLICIT: Ephemeral messages (typing indicators, receipts) - silently discard on failure
   * - RESENDABLE: Content messages - can trigger retry requests
   * - DEFAULT: Standard handling
   *
   * If not set, behavior is inferred from messageType via IMPLICIT_ENVELOPE_TYPES.
   */
  contentHint?: ContentHint;
}

/**
 * Options for processing incoming message envelopes.
 *
 * Used when SignalProtocolClient doesn't have a relay (e.g., background tasks).
 * Provides callbacks for sending retry requests and marking messages delivered.
 */
export interface ProcessEnvelopeOptions {
  /**
   * Callback to send retry requests when no relay is available.
   *
   * Required for background processing where there's no WebSocket relay.
   * The callback receives a fully-formed RetryRequest created by SesameManager.
   */
  sendRetryRequest?: (request: import('../internal/sesame/types').RetryRequest) => Promise<void>;

  /**
   * Callback to mark message as delivered when no relay is available.
   *
   * Called after retry request is sent to prevent the failed message
   * from being re-fetched indefinitely.
   */
  markDelivered?: (messageId: string) => Promise<void>;

  /**
   * Force prekey rotation when stale prekey is detected.
   *
   * Generate new keys, clear stale KEM prekeys, and upload fresh bundle.
   *
   * Required for background processing where there's no relay.
   * Called before sending retry request when PREKEY_NOT_FOUND or MAC_FAILED
   * on PreKeyMessage indicates stale/corrupted keys.
   *
   */
  forcePreKeyRotation?: () => Promise<void>;
}
