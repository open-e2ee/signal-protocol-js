/**
 * SignalProtocolServiceCipher - Cipher coordination for Signal Protocol
 *
 * @layer 1 - API
 *
 * Public coordination surface:
 * - `decrypt(envelope)` → DecryptedEnvelope
 * - `encrypt(recipientId, content)` → SendResult
 *
 * Separates cipher coordination (encrypt/decrypt routing) from lifecycle
 * management (sessions, keys, hooks, subscriptions) in SignalProtocolClient.
 *
 * @see https://signal.org/docs/specifications/sesame/
 */

import { utf8Decode } from '../internal/platform';
import AsyncLock from 'async-lock';
import type {
  SignalProtocolRelayServer,
  Envelope,
  StaleSessionErrorData,
  SealedSenderAuth,
  GroupMemberDevice,
  DeliveryClass,
} from '../remote/relay/types';
import type { SignalProtocolRemoteObjectStore } from '../remote/object-store';
import type {
  SignalProtocolLocalStore,
  Base64,
  ReceiveWorkRecord,
  ReceiveWorkSeed,
} from '../types';
import type { SenderKeyHandoffDevice } from '../types/api';
import { EncryptionError, EncryptionErrorCode } from '../types';
import { SealedSenderAuthError } from '../types/errors';
import { base64ToBytes } from '../internal/crypto';
import type { DecryptedEnvelope } from './event-hooks';
import { recordServerClockSample } from '../server-clock';
import { ProtocolAddress } from '../types/address';
import {
  isRemovedDevice,
  type SesameManager,
  type UserRecord,
  type SesameMessage,
  type OutgoingMessageBatch,
} from '../internal/sesame/types';
import { defaultSignalProtocolLogger, type Logger } from '../logger';
import {
  SenderKeyManager,
  type SenderKeyDistributionMessage,
} from '../internal/protocol/sender-keys';
import {
  SenderKeyHandoffLedger,
  type SenderKeyHandoffKey,
  type SenderKeyHandoffTarget,
} from '../internal/protocol/sender-keys/handoff-ledger';
import { isGroupId, extractGroupId } from '../internal/groups';
import type { EndorsementManager } from './endorsement-manager';
import {
  GroupReceiveRefusedError,
  GroupReceiveUnavailableError,
  refuseSyncFromOtherAccount,
  classifyGroupContent,
  groupOfContext,
  type GroupReceiveEvaluator,
} from './group-receive-authorization';
import { sizedReceiveWork } from '../local/store/receive-work';
import { envelopeCiphertextBytes } from './delivery-error';
import { GroupSenderKeyOperations } from './group-sender-key-operations';
import type { PreparedAttachmentUpload, SealedReceipt, SendOptions, SendResult } from './types';
import { ContentHint } from '../types/messages';

import {
  type BlockedRecipientsSyncInput,
  createDefaultSignalProtocolContentAdapter,
  type ConfigurationSyncInput,
  type GroupContentContext,
  type InspectedSignalProtocolContent,
  type MediaAttachmentDeleteSyncInput,
  type ReadSyncEntryInput,
  type RecipientUsernameSyncInput,
  type SignalProtocolContentAdapter,
  type TaskNotificationAckSyncInput,
  type UsernameStateSyncInput,
  type VerificationStateSyncInput,
  type ViewOnceOpenSyncInput,
} from './content-adapter';
import * as CryptoUtils from '../internal/crypto';
import {
  completeOutgoingMessageIntent,
  completeOutgoingSyncPhase,
  getOutgoingMessageIntent,
  markOutgoingDeviceSetUnresolved,
  outgoingMessageIntentResult,
  repairOutgoingDeviceSet,
  restartOutgoingDeviceSet,
  getRetryResend,
  getSentClientMessageIds,
  reconcileOutgoingDirectDeviceMessages,
  reconcileOutgoingSyncMessages,
  replaceOutgoingDirectDeviceMessage,
  replaceOutgoingGroupPreMessages,
  retryAttemptClientMessageId,
  retryNullMessageClientMessageId,
  retryRequestAttempt,
  retryResendClientMessageId,
  storeOutgoingMessageIntent,
  storeRetryResend,
  withOutgoingMessageIntentLock,
  type RetryResendTarget,
  type StoredDeviceSetUnresolved,
  type StoredOutgoingDeviceMessage,
  type StoredOutgoingMessageIntent,
  type StoredRetryResend,
} from '../local/store/reliability';
import { FanOutError, firstItemError, type BoundedFanOut } from '../utils/bounded-fan-out';
import { withRetry } from '../utils/retry';
import {
  acquireUntilStopped,
  createRelayFanOut,
  RelayWorkStopped,
  relaySendsSealedUnderItsBound,
  rethrowRelayWorkStopped,
} from './relay-work';
import {
  markRelayDeviceRefusal,
  refusesRemovedDevices,
  relayDeviceRefusal,
} from './relay-device-refusal';
import {
  aggregateRelayAcceptance,
  relayOperationRefusal,
  type RelayPostAcceptance,
} from './relay-acceptance';
import { forDirectSealedRoute, usedGroupRouteFallback } from './relay-sealed-route';
import { comparesDeviceSets, markDeviceSetRefusal } from '../remote/relay/device-set';
import {
  markRelayProtocolError,
  RelayProtocolError,
  runDeviceSetPhase,
  waitUnlessStopped,
  type DeviceSetAccountRepair,
  type DeviceSetDevice,
  type DeviceSetPhase,
  type DeviceSetPost,
  type DeviceSetUnresolved,
  syncPostReceipts,
  uncheckedDeclaredPost,
  type DeclaredPostReceipt,
  type DeclaredSyncOutcome,
} from './device-set-reconciliation';
import { prepareGroupSharedMessage } from './group-sealed-sender';
import { attachFailedGroup } from './retry-terminal-recovery';
import {
  sendGroupWithExactOutbox,
  type GroupDeviceSetContext,
  type PreMessagePostResult,
  type PreMessageTransport,
} from './group-outbox';
import { groupDeviceKey, listedOwnDeviceChange } from './group-device-set';
import {
  attachUnsealedEnvelope,
  reconstructEnvelope,
  resolveSealedSenderContext as resolveSealedSenderSendContext,
  SealedRetryRequestReceived,
  serializeDirectSealedSenderMessage as serializeDirectSealedSenderTransport,
  unsealMessage,
  type ResolvedSealedSenderContext,
  type SealedSenderProvider as SealedSenderProviderContract,
} from './sealed-sender';
import { prepareMediaAttachmentUpload, serializeMediaAttachmentMessage } from '../media';
import {
  UnidentifiedAccessMode,
  type ContactProfileStateStore,
  type UnidentifiedAccessModeType,
} from '../profile/contact-state';

/**
 * How long a recipient's relay device list stays current before a send reads
 * it again. A device linked or removed inside this window is found by the
 * first send after it ends.
 */
export const RECIPIENT_DEVICE_LIST_FRESH_MILLISECONDS = 60_000;

/**
 * The Relay message ID of the sync copy of a send to one own device. The ID
 * names the device, so a replay that adds or drops an own device keeps the
 * ID of each other copy.
 */
function syncMessageId(clientMessageId: string, message: { recipientDeviceId: number }): string {
  return `${clientMessageId}:sync:device:${message.recipientDeviceId}`;
}

/**
 * How old a recipient's device list can be for a direct send to post before
 * it reads the list again. Only a relay that refuses a removed device's
 * mailbox allows it, so the age bounds how long the client posts first on a
 * list that no read confirmed, not how long a removed device receives.
 */
const RECIPIENT_DEVICE_LIST_MAXIMUM_AGE_MILLISECONDS = 300_000;

/** How one device post of a send runs. */
interface DevicePostControl {
  /** The stop signal of the send. No post starts after it aborts. */
  readonly stopSignal?: AbortSignal;
  /** Runs just before the relay request, and refuses the post by throwing. */
  readonly admit?: () => void;
  /**
   * The operation epoch that the relay admits the post by. Without it, the
   * post uses the message timestamp.
   */
  readonly operationEpochMilliseconds?: number;
  /** The delivery class of the post. Without it, the post is user-visible. */
  readonly deliveryClass?: DeliveryClass;
  /**
   * The device IDs that the post declares for its recipient account. Only a
   * relay that compares device sets gets a declaration. Without it, the
   * relay does not compare.
   */
  readonly declaredDeviceIds?: readonly number[];
}

/** A distribution plaintext and the sender key that it gives. */
interface SenderKeyHandoffDistribution {
  key: SenderKeyHandoffKey;
  /**
   * The plaintext. A replay serializes it only when a device needs the key,
   * so a replay that gives the key to no device never reads it.
   */
  bytes: () => Uint8Array;
}

/** What a group send attempt holds for the repair of a refused post. */
interface PreMessageRepair {
  sessions?: SendSessionCallbacks;
  /**
   * The distribution of the attempt that prepared the send, at the chain
   * index of its group message. Its plaintext holds the sender chain key, so
   * it stays in memory and never reaches the outbox.
   */
  distribution?: SenderKeyHandoffDistribution;
}

/** What a sync post holds for the repair of a copy that the relay refuses as stale. */
interface SyncCopyRepair {
  /** The session callbacks that refresh the session of the own device. */
  sessions: SendSessionCallbacks | undefined;
  /** The intent that stores the copy, when the send has one. */
  intentId?: string;
  /**
   * Encrypt the transcript again for one own device. Resolves to undefined
   * when the device has no session, and the repair then throws.
   */
  rebuild(deviceId: number): Promise<StoredOutgoingDeviceMessage | undefined>;
}

/**
 * One declared phase of a send, as the cipher runs it (§5.3 of the device-set
 * contract). Each post declares every device of its account that the phase
 * addresses.
 */
interface DeclaredPhaseRun<T> {
  phase: DeviceSetPhase;
  /** The operation ID of the send, for the reconciliation error. */
  clientMessageId: string;
  /**
   * The stored intent of the send. With it, each repair and the new restart
   * count commit in one write. Without it, the repair changes only the
   * messages of this run.
   */
  intentId?: string;
  /** The restart count that the outbox holds for the phase. */
  restarts: number;
  messages: readonly StoredOutgoingDeviceMessage[];
  /**
   * The listed devices that had no prekey bundle at the last repair of the
   * phase, as the intent stores them. The first pass refuses each of them
   * as missing, so the repair starts a session with it again.
   */
  bundleMissing?: readonly DeviceSetDevice[];
  /**
   * The recipient account, when a pass with no message and no
   * bundle-missing device is an error, not a completed phase.
   */
  requirePostTo?: string;
  /** Post one message with the declared device IDs of its account. */
  post(message: StoredOutgoingDeviceMessage, declaredDeviceIds: readonly number[]): Promise<T>;
  /**
   * Encrypt the message of the phase again for one device that has a
   * current session. Resolves to undefined when the device has no session.
   */
  encrypt(device: DeviceSetDevice): Promise<StoredOutgoingDeviceMessage | undefined>;
  /** Forget a device that leaves the send, or whose registration changed. */
  forget?(device: DeviceSetDevice): Promise<void>;
  sessions: SendSessionCallbacks | undefined;
  stopSignal: AbortSignal | undefined;
}

/** The stored form of the terminal record of a declared phase. */
function storedDeviceSetUnresolved(unresolved: DeviceSetUnresolved): StoredDeviceSetUnresolved {
  return {
    phase: unresolved.phase,
    reason: unresolved.reason,
    restarts: unresolved.restarts,
    ...(unresolved.lastRefusal && {
      lastRefusal: {
        code: unresolved.lastRefusal.code,
        accounts: unresolved.lastRefusal.accounts.map((account) => ({
          userId: account.userId,
          missingDeviceIds: [...account.missingDeviceIds],
          extraDeviceIds: [...account.extraDeviceIds],
          staleDeviceIds: [...account.staleDeviceIds],
        })),
      },
    }),
  };
}

function declaredDeviceKey(device: DeviceSetDevice): string {
  return `${device.userId}\u0000${String(device.deviceId)}`;
}

/**
 * The device IDs of a user record that are not marked removed. A removed
 * record gets no fan-out, so a declared send neither declares it nor counts
 * it as a held device.
 */
function unremovedDeviceIds(record: UserRecord | null): number[] {
  return Array.from(record?.devices.entries() ?? [])
    .filter(([, device]) => !isRemovedDevice(device))
    .map(([deviceId]) => deviceId);
}

/** A send-first post that waits for the reconcile pass. */
class DeferredPost extends Error {
  constructor() {
    super('The post waits for the device-list read');
    this.name = 'DeferredPost';
  }
}

/** The posts of a send-first pass, by recipient device. */
interface DirectIntentPosts {
  readonly accepted: Map<number, RelayPostAcceptance>;
  readonly refused: Map<number, { error: unknown }>;
}

/** The result of a successful device-list read. */
interface RecipientDeviceList {
  readonly listed: ReadonlySet<number>;
  readonly established: readonly number[];
}

/**
 * Sort envelopes so PreKeyMessages are processed first
 *
 * PreKeyMessages establish new sessions, so they must be processed before
 * ciphertexts that depend on those sessions. That order keeps SESAME session
 * convergence correct.
 *
 * @param envelopes - Array of encrypted envelopes to sort
 * @returns New sorted array (does not mutate input)
 *
 * @internal Used by DefaultSignalProtocolClient.processIncomingEnvelopes and background sync
 * @see https://signal.org/docs/specifications/sesame/ Section 3.4
 */
export {};
export function sortEnvelopesForDecryption<T extends { messageType?: string }>(
  envelopes: T[]
): T[] {
  return [...envelopes].sort((a, b) => {
    // Treat undefined messageType as non-prekey (ciphertext comes after prekey_bundle)
    const aIsPreKey = a.messageType === 'prekey_bundle' ? 0 : 1;
    const bIsPreKey = b.messageType === 'prekey_bundle' ? 0 : 1;
    return aIsPreKey - bIsPreKey;
  });
}

/**
 * Detect actual message type from ciphertext for envelope metadata
 *
 * PreKeyMessages (first messages) should have messageType: 'prekey_bundle'
 * Regular ratchet messages should have messageType: 'ciphertext'
 *
 * @param ciphertext - The encrypted message content (string or Uint8Array)
 * @returns 'prekey_bundle' for PreKeyMessages, 'ciphertext' for regular messages
 */
function getEnvelopeMessageType(ciphertext: string | Uint8Array): 'prekey_bundle' | 'ciphertext' {
  const text = typeof ciphertext === 'string' ? ciphertext : utf8Decode(ciphertext);

  // Binary protobuf format: base64 decode, check first protobuf tag
  try {
    const bytes = CryptoUtils.base64ToBytes(text as Base64);
    if (bytes.length >= 2) {
      const firstTag = bytes[1];
      // PreKeySignalProtocolMessage: first tag is 0x08 (field 1 uint32) or 0x12 (field 2 bytes)
      if (firstTag === 0x08 || firstTag === 0x12) {
        return 'prekey_bundle';
      }
    }
  } catch {
    // Not valid base64 binary
  }

  return 'ciphertext';
}

/**
 * Give a send error the logical-send identifier of its send, so
 * `isOutgoingMessageError` is true for it.
 */
export function attachClientMessageId(error: unknown, clientMessageId: string): Error {
  const normalized = error instanceof Error ? error : new Error(String(error));
  try {
    Object.defineProperty(normalized, 'clientMessageId', {
      configurable: true,
      enumerable: true,
      value: clientMessageId,
    });
    return normalized;
  } catch {
    const wrapped = new Error(normalized.message);
    wrapped.name = normalized.name;
    Object.defineProperty(wrapped, 'clientMessageId', {
      enumerable: true,
      value: clientMessageId,
    });
    return wrapped;
  }
}

/**
 * Detect if an error is a stale session error from the server
 *
 * The relay returns STALE_DEVICE when a PreKeyMessage uses an outdated
 * registration ID.
 *
 * This SDK validates registration IDs at the relay boundary. Stale-prekey
 * detection remains client-side through authentication failure and retry.
 *
 * @param error - The error to check
 * @returns True if error indicates stale session requiring bundle refresh
 */
function isStaleSessionError(error: unknown): error is { data: StaleSessionErrorData } {
  if (error && typeof error === 'object' && 'data' in error) {
    const data = (error as { data: unknown }).data;
    if (data && typeof data === 'object' && 'code' in data) {
      const code = (data as { code: string }).code;
      return code === 'STALE_DEVICE';
    }
  }
  return false;
}

class SealedSenderRecipientRejectedError extends Error {
  constructor() {
    super('Sealed sender recipient was not accepted');
    this.name = 'SealedSenderRecipientRejectedError';
  }
}

function isConclusiveDeviceRejection(error: unknown): boolean {
  return (
    isStaleSessionError(error) ||
    error instanceof SealedSenderRecipientRejectedError ||
    relayDeviceRefusal(error)?.code === 'STALE_DEVICE'
  );
}

/** True when the relay refused this post because of the device that it names. */
function isRefusalOfDevice(error: unknown, message: StoredOutgoingDeviceMessage): boolean {
  const refusal = relayDeviceRefusal(error);
  return (
    refusal?.userId === message.recipientUserId && refusal.deviceId === message.recipientDeviceId
  );
}

/**
 * The transport identity of the repair of a refused pre-message or sync copy.
 * The repair payload changed, so it needs an identity that the relay has not
 * seen: `<id>:repair:1` for the first repair, and the next number for each
 * later one.
 */
function repairMessageId(refusedId: string): string {
  const repair = /^(.*):repair:(\d+)$/u.exec(refusedId);
  return repair ? `${repair[1]!}:repair:${Number(repair[2]) + 1}` : `${refusedId}:repair:1`;
}

/** The encrypted bytes of a resend, without the retry request that it answers. */
type EncryptedResend = Omit<StoredRetryResend, keyof RetryResendTarget | 'attempt'>;

/**
 * The options of one resend encryption. `senderKeyHandoff` names the own
 * sender key of the raw group that the content carries.
 */
interface ResendOptions {
  timestamp: number;
  contentHint?: ContentHint;
  senderKeyHandoff?: { groupId: string; senderKeyId: string; generation: number };
}

/** The client message ID of one attempt of a stored resend or null message. */
function retryResendAttemptId(resend: StoredRetryResend): string {
  const id =
    resend.kind === 'resend'
      ? retryResendClientMessageId(resend.retryId)
      : retryNullMessageClientMessageId(resend.retryId);
  return retryAttemptClientMessageId(id, resend.attempt);
}

/**
 * Sealed sender context provider callback
 *
 * Provides the sender certificate and identity key pair needed for sealing.
 * Injected by SignalProtocolClient so the cipher does not need to manage certificate
 * caching or key lookup directly.
 *
 * @returns Sender certificate (base64), sender private key (bytes), and config
 */
export type SealedSenderProvider = SealedSenderProviderContract;

/**
 * Callback for reconciling a recipient's sessions with the relay's device list
 * Allows SignalProtocolClient to inject its session establishment logic. When
 * the send already read the recipient's devices, it passes them, and the
 * callback does not read the list again.
 */
export type SessionEstablisher = (
  recipientUserId: string,
  listedDevices?: readonly GroupMemberDevice[]
) => Promise<{
  /** Device IDs the relay lists as receiving for the recipient */
  activeDevices: number[];
  establishedDevices: number[];
  failedDevices: number[];
  failedDeviceErrors: Array<{ deviceId: number; error: Error }>;
}>;

/**
 * Callback for refreshing a stale session after STALE_DEVICE error
 *
 * Stale-device recovery:
 * 1. Archive the stale session (preserves for delayed message decryption)
 * 2. Fetch fresh prekey bundle from server
 * 3. Establish new session with fresh keys
 *
 * @param recipientUserId - User ID whose session needs refresh
 * @param recipientDeviceId - Device ID that returned stale error
 * @returns True if session was successfully refreshed
 */
export type StaleSessionRefresher = (
  recipientUserId: string,
  recipientDeviceId: number
) => Promise<boolean>;

/**
 * The session callbacks of a send. The client binds them to the hooks of the
 * work that sends, so a resend in relay work calls the app through that work.
 */
export interface SendSessionCallbacks {
  establishSessions: SessionEstablisher;
  refreshStaleSession: StaleSessionRefresher;
}

/**
 * Callback for refreshing group send endorsements before V2 sealed sender send.
 *
 * Called when `shouldRefreshEndorsements()` indicates refresh is needed.
 * The implementation should fetch endorsements from the server and cache them.
 *
 * @param groupId - Group identifier
 * @param memberUserIds - User IDs of all group members to endorse (excluding self)
 * @returns true if endorsements were refreshed, false on failure
 *
 */
export type EndorsementRefresher = (groupId: string, memberUserIds: string[]) => Promise<boolean>;
export type GroupSendBarrierChecker = (groupId: string) => Promise<void>;

/**
 * The receive record that a decrypt commits with its ratchet step, and the
 * admission that runs the decrypt.
 */
export interface ReceiveCommit {
  /** The receive record ID: the delivered fingerprint of the envelope. */
  readonly workId: string;
  /**
   * Build the record seed for the envelope that the decrypt opens. The
   * envelope is the inner envelope of a seal. It never throws.
   */
  readonly seed: (envelope: Envelope, arrivedSealed: boolean) => ReceiveWorkSeed;
  /**
   * Run the decrypt under the receive admission. Null when the queue has no
   * room: then nothing is decrypted.
   *
   * @param groupId - The raw group of a sender-key message, or null
   */
  readonly admit: <T>(groupId: string | null, decrypt: () => Promise<T>) => Promise<{ value: T } | null>;
}

/** The options of one envelope commit. */
export interface EnvelopeCommitOptions {
  /** The trust roots of an unidentified_sender envelope. */
  sealedSender?: import('./config').SealedSenderConfig | undefined;
  /** When it aborts while the commit waits for a lock, the commit throws RelayWorkStopped. */
  stopSignal?: AbortSignal | undefined;
  /** The receive record to commit. Without it, the decrypt commits no record. */
  work?: ReceiveCommit | undefined;
}

/** The sender of committed content. */
export interface CommittedSender {
  /** The envelope ID, or the sender and the admission time for an envelope with no ID. */
  readonly messageId: string;
  readonly senderUserId: string;
  readonly senderDeviceId: number;
}

/** Content that a decrypt committed, checked, and whose distribution installed. */
export interface CommittedContent extends CommittedSender {
  readonly messageType: DecryptedEnvelope['messageType'];
  readonly serverTimestamp?: number;
  readonly arrivedSealed: boolean;
  readonly plaintext: string;
  readonly inspected: InspectedSignalProtocolContent;
  /** The raw group of the sender key that decrypted the content, or null. */
  readonly transportGroupId: string | null;
  /** The raw group of a distribution that the content carries, or null. */
  readonly distributionGroupId: string | null;
  /** The time of the first durable admission. */
  readonly receivedAt: number;
}

/** The result of one envelope commit. */
export type EnvelopeCommit =
  | {
      readonly kind: 'committed';
      /** The committed receive record. Null with no `work`. */
      readonly record: ReceiveWorkRecord | null;
      /** True when a stored record gave the content, with no ratchet step. */
      readonly reused: boolean;
      readonly content: CommittedContent;
    }
  /** The queue has no room. Nothing is decrypted. */
  | { readonly kind: 'refused' }
  /** The record holds no content any more: the application got it. */
  | { readonly kind: 'settled'; readonly record: ReceiveWorkRecord }
  /**
   * The content failed a check after its commit. The ratchet step is spent,
   * and no distribution installed.
   */
  | ({
      readonly kind: 'denied';
      readonly error: Error;
      readonly record: ReceiveWorkRecord | null;
    } & CommittedSender);

/** The group decision on committed content. */
export type GroupContentDecision =
  | { readonly kind: 'authorized'; readonly groupId: string | null }
  | { readonly kind: 'denied'; readonly error: GroupReceiveRefusedError }
  | {
      readonly kind: 'unavailable';
      readonly error: GroupReceiveUnavailableError;
      /** The raw group whose state must update first. */
      readonly groupId: string;
    };

/**
 * SignalProtocolServiceCipher - Routes encryption and decryption to appropriate ciphers
 *
 * Handles:
 * - Pairwise messages via SESAME/Double Ratchet
 * - Group messages via Sender Keys
 * - Binary content with two-layer encryption (AES-GCM + Signal Protocol)
 *
 * @example
 * ```typescript
 * // Created by SignalProtocolClient - not instantiated directly
 * const cipher = new SignalProtocolServiceCipher(userId, deviceId, sesameManager, ...);
 *
 * // Decrypt incoming envelope
 * const decrypted = await cipher.decrypt(envelope);
 *
 * // Encrypt outgoing message
 * const result = await cipher.encrypt('bob', 'Hello!');
 * ```
 */
export class SignalProtocolServiceCipher {
  private readonly lock = new AsyncLock();
  private readonly groupSenderKeys: GroupSenderKeyOperations;
  private readonly senderKeyHandoffs: SenderKeyHandoffLedger;
  private sessionCallbacks?: SendSessionCallbacks;
  private readonly recipientDeviceListCheckedAt = new Map<string, number>();
  private sealedSenderProvider?: SealedSenderProvider;
  private sealedSenderDeliveryMode: import('./config').SealedSenderDeliveryMode = 'preferred';
  private sealedSenderIdentifiedFallback?: import('./config').SealedSenderConfig['onIdentifiedFallback'];
  private relayProtocolErrorReporter?: (error: RelayProtocolError) => Promise<void>;
  private contactProfileStateStore?: ContactProfileStateStore;
  private endorsementManager?: EndorsementManager;
  private endorsementManagerResolver?: () => Promise<EndorsementManager | undefined>;
  private endorsementRefresher?: EndorsementRefresher;
  private groupSendBarrierChecker?: GroupSendBarrierChecker;
  private groupReceiveEvaluator?: GroupReceiveEvaluator;
  private groupSecretParamsProvider?: (
    groupId: string
  ) => Promise<import('../internal/protocol/zk/groups/group-params').GroupSecretParams | null>;
  private groupContextProvider?: (groupId: string) => Promise<GroupContentContext | null>;

  constructor(
    private readonly userId: string,
    private readonly deviceId: number,
    private readonly sesameManager: SesameManager,
    private readonly senderKeyManager: SenderKeyManager,
    private readonly storage: SignalProtocolLocalStore,
    private readonly relay?: SignalProtocolRelayServer,
    private readonly remoteObjectStore?: SignalProtocolRemoteObjectStore,
    private readonly contentAdapter?: SignalProtocolContentAdapter,
    private readonly logger: Required<Logger> = defaultSignalProtocolLogger,
    private readonly fanOut: BoundedFanOut = createRelayFanOut()
  ) {
    this.groupSenderKeys = new GroupSenderKeyOperations(storage, userId, deviceId);
    this.senderKeyHandoffs = new SenderKeyHandoffLedger(storage);
  }

  private getResolvedContentAdapter(): SignalProtocolContentAdapter {
    return this.contentAdapter ?? createDefaultSignalProtocolContentAdapter();
  }

  private getDirectConversationId(recipientUserId: string): string {
    const sortedIds = [this.userId, recipientUserId].sort();
    return `dm:${sortedIds[0]}_${sortedIds[1]}`;
  }

  private buildSentSyncTranscript(
    conversationId: string,
    plaintextBytes: Uint8Array,
    timestamp: number,
    recipientUserId?: string
  ): Uint8Array {
    return this.getResolvedContentAdapter().serializeSentTranscript({
      conversationId,
      serializedContent: plaintextBytes,
      timestamp,
      recipientUserId,
    });
  }

  private encodeLosslessPlaintext(plaintextBytes: Uint8Array): string {
    const text = utf8Decode(plaintextBytes);
    const roundTrip = new TextEncoder().encode(text);

    if (
      roundTrip.length === plaintextBytes.length &&
      roundTrip.every((byte, index) => byte === plaintextBytes[index])
    ) {
      return text;
    }

    return CryptoUtils.bytesToBase64(plaintextBytes);
  }

  private async uploadSyncMessages(
    syncMessages: SesameMessage[],
    payloadBytes: Uint8Array,
    timestamp: number
  ): Promise<void> {
    const relay = this.relay;
    if (!relay || syncMessages.length === 0) {
      return;
    }

    const prepared = await Promise.all(
      syncMessages.map((message) => this.prepareStoredSyncMessage(message))
    );
    const repair: SyncCopyRepair = {
      sessions: this.sessionCallbacks,
      rebuild: async (deviceId) => {
        const [message] = await this.sesameManager.sendToLocalOtherDevices(payloadBytes, {
          clientTimestamp: timestamp,
          includeSyncMessages: false,
          listedDeviceIds: [deviceId],
        });
        return message && this.prepareStoredSyncMessage(message);
      },
    };
    await this.sendPhase(
      prepared,
      (message) => this.postSyncMessage(relay, message, {}, repair),
      'sync'
    );
  }

  /** A stored sync copy that names the registration of the own device's current session. */
  private async prepareStoredSyncMessage(
    message: SesameMessage,
    clientMessageId?: string
  ): Promise<StoredOutgoingDeviceMessage> {
    const stored: StoredOutgoingDeviceMessage = {
      recipientUserId: message.recipientUserId,
      recipientDeviceId: message.recipientDeviceId,
      timestamp: message.timestamp,
      ...(clientMessageId !== undefined && { clientMessageId }),
      ciphertext:
        typeof message.ciphertext === 'string'
          ? message.ciphertext
          : CryptoUtils.bytesToBase64(message.ciphertext),
      messageType: getEnvelopeMessageType(message.ciphertext),
    };
    const registrationId = await this.sesameManager.getRemoteRegistrationId(
      message.recipientUserId,
      message.recipientDeviceId
    );
    if (registrationId !== undefined) stored.recipientRegistrationId = registrationId;
    return stored;
  }

  /**
   * Post one sync copy to an own device, identified, with the registration
   * of the device's session. When the relay refuses the device as stale, the
   * session of the device is refreshed once, `repair.rebuild` encrypts the
   * transcript again for the device, the new copy replaces the refused copy
   * in the intent named by `repair.intentId`, and the new copy is posted
   * under a repair ID. When the relay refuses the new copy as stale too, the
   * session of the device is archived, the copy leaves the intent, and a
   * warning is logged. The post then resolves, so the send completes without
   * the copy.
   *
   * @throws {EncryptionError} SESSION_ESTABLISHMENT_FAILED when the refresh
   *   fails or the rebuild gives the device no copy. The copy stays in the
   *   intent, so a replay posts it again.
   */
  private async postSyncMessage(
    relay: SignalProtocolRelayServer,
    message: StoredOutgoingDeviceMessage,
    control: DevicePostControl,
    repair: SyncCopyRepair
  ): Promise<void> {
    try {
      await this.postSyncCopy(relay, message, control);
      return;
    } catch (error) {
      if (!isConclusiveDeviceRejection(error)) throw error;
    }
    let refused = message;
    const sessions = repair.sessions;
    const replacement = sessions
      ? await this.inRepairTurn(message.recipientUserId, () =>
          this.repairRefusedSyncCopyInTurn(message, repair, sessions)
        )
      : undefined;
    if (replacement) {
      try {
        await this.postSyncCopy(relay, replacement, control);
        return;
      } catch (error) {
        if (!isConclusiveDeviceRejection(error)) throw error;
      }
      refused = replacement;
    }
    await this.archiveDeviceSession(
      refused.recipientUserId,
      refused.recipientDeviceId,
      control.stopSignal
    );
    if (repair.intentId !== undefined) {
      const removed = [refused.recipientDeviceId];
      await reconcileOutgoingSyncMessages(this.storage, repair.intentId, removed, []);
    }
    this.logger.warn('The relay refused a sync copy to a stale own device', {
      category: 'E2EE',
      data: { deviceId: refused.recipientDeviceId },
    });
  }

  /**
   * Refresh the session of an own device that refused a sync copy as stale,
   * encrypt the transcript again for the device, and replace the stored copy
   * before its post. The refused ciphertext is never posted again.
   *
   * @throws {EncryptionError} SESSION_ESTABLISHMENT_FAILED when the refresh
   *   fails or the rebuild gives the device no copy. The stored copy stays,
   *   and the refreshed session is not archived.
   */
  private async repairRefusedSyncCopyInTurn(
    refused: StoredOutgoingDeviceMessage,
    repair: SyncCopyRepair,
    sessions: SendSessionCallbacks
  ): Promise<StoredOutgoingDeviceMessage | undefined> {
    const refreshed = await sessions.refreshStaleSession(
      refused.recipientUserId,
      refused.recipientDeviceId
    );
    if (!refreshed) {
      throw new EncryptionError(
        'Failed to refresh a rejected own device',
        EncryptionErrorCode.SESSION_ESTABLISHMENT_FAILED,
        { recipientUserId: refused.recipientUserId }
      );
    }
    const fresh = await repair.rebuild(refused.recipientDeviceId);
    if (!fresh) {
      throw new EncryptionError(
        'Failed to encrypt a sync copy again for a refreshed own device',
        EncryptionErrorCode.SESSION_ESTABLISHMENT_FAILED,
        { recipientUserId: refused.recipientUserId }
      );
    }
    if (refused.clientMessageId !== undefined) {
      fresh.clientMessageId = repairMessageId(refused.clientMessageId);
    }
    if (repair.intentId !== undefined) {
      const removed = [refused.recipientDeviceId];
      await reconcileOutgoingSyncMessages(this.storage, repair.intentId, removed, [fresh]);
    }
    return fresh;
  }

  /**
   * Send one relay request of a sync copy to an own device.
   *
   * @returns The relay receipt of the post
   */
  private async postSyncCopy(
    relay: SignalProtocolRelayServer,
    message: StoredOutgoingDeviceMessage,
    control: DevicePostControl
  ): Promise<RelayPostAcceptance> {
    return this.postToRelay(
      () =>
        relay.send({
          targetUserId: message.recipientUserId,
          targetDeviceId: message.recipientDeviceId,
          senderUserId: this.userId,
          senderDeviceId: this.deviceId,
          ciphertext: message.ciphertext,
          messageType: message.messageType,
          deliveryClass: 'background-sync',
          timestamp: message.timestamp,
          ...(message.clientMessageId !== undefined && {
            clientMessageId: message.clientMessageId,
          }),
          ...(message.recipientRegistrationId !== undefined && {
            recipientRegistrationId: message.recipientRegistrationId,
          }),
          ...(control.declaredDeviceIds && { declaredDeviceIds: control.declaredDeviceIds }),
        }),
      false,
      control
    );
  }

  /**
   * Run one relay phase of a send: a task for each device message, at the same
   * time, under the client's relay request bound. Every device is attempted.
   * When devices fail, the phase rejects after every device settles, with the
   * error of the first failed device in input order, so a caller sees the
   * error type that a send in device order threw. Each other failure is logged.
   */
  private async sendPhase<T extends { recipientUserId: string; recipientDeviceId: number }, R>(
    messages: readonly T[],
    task: (message: T) => Promise<R>,
    phase: 'pre-message' | 'device' | 'sync',
    stopSignal?: AbortSignal
  ): Promise<R[]> {
    try {
      return await this.fanOut.all(messages, task, stopSignal);
    } catch (error) {
      if (!(error instanceof FanOutError)) throw error;
      const failed = error.outcomes.flatMap((outcome, index) =>
        outcome.ok ? [] : [{ message: messages[index]!, error: outcome.error }]
      );
      for (const { message, error: other } of failed.slice(1)) {
        this.logger.warn('A device post of a send failed', {
          category: 'E2EE',
          error: other as Error,
          data: {
            phase,
            recipientUserId: message.recipientUserId,
            deviceId: message.recipientDeviceId,
            failedDevices: failed.length,
          },
        });
      }
      throw failed[0]!.error;
    }
  }

  /**
   * Send one relay request of a device post under a slot of the client's
   * bound. An adapter that bounds its own sealed-sender posts takes a slot of
   * the same bound, so its sealed post runs without one here.
   */
  private postToRelay<T>(
    send: () => Promise<T>,
    sealed: boolean,
    control: DevicePostControl
  ): Promise<T> {
    const post = () => {
      control.admit?.();
      return send();
    };
    if (sealed && relaySendsSealedUnderItsBound(this.relay!)) {
      if (control.stopSignal?.aborted) return Promise.reject(new RelayWorkStopped());
      return new Promise<T>((resolve) => resolve(post()));
    }
    return this.fanOut.request(post, control.stopSignal);
  }

  private async sendSyncPayloadToLocalOtherDevices(
    payloadBytes: Uint8Array,
    timestamp: number
  ): Promise<void> {
    if (!this.relay) {
      return;
    }
    if (this.declaresDeviceSets()) {
      await this.sendDeclaredSyncPayload(payloadBytes, timestamp);
      return;
    }

    const listed = await this.readOwnDeviceList(this.sessionCallbacks, undefined);
    const syncMessages = await this.sesameManager.sendToLocalOtherDevices(payloadBytes, {
      clientTimestamp: timestamp,
      includeSyncMessages: false,
      listedDeviceIds: listed.map((device) => device.deviceId),
    });
    await this.uploadSyncMessages(syncMessages, payloadBytes, timestamp);
  }

  async sendReadSyncToLocalOtherDevices(entries: ReadSyncEntryInput[]): Promise<void> {
    if (entries.length === 0) {
      return;
    }

    const timestamp = Date.now();
    const payloadBytes = this.getResolvedContentAdapter().serializeReadSync(entries);
    await this.sendSyncPayloadToLocalOtherDevices(payloadBytes, timestamp);
  }

  async sendViewOnceOpenSyncToLocalOtherDevices(entry: ViewOnceOpenSyncInput): Promise<void> {
    const timestamp = Date.now();
    const payloadBytes = this.getResolvedContentAdapter().serializeViewOnceOpenSync(entry);
    await this.sendSyncPayloadToLocalOtherDevices(payloadBytes, timestamp);
  }

  async sendMediaAttachmentDeleteSyncToLocalOtherDevices(
    entry: MediaAttachmentDeleteSyncInput
  ): Promise<void> {
    const payloadBytes = this.getResolvedContentAdapter().serializeMediaAttachmentDeleteSync(entry);
    await this.sendSyncPayloadToLocalOtherDevices(payloadBytes, entry.deletedAt);
  }

  async sendConfigurationSyncToLocalOtherDevices(
    configuration: ConfigurationSyncInput
  ): Promise<void> {
    const timestamp = Date.now();
    const payloadBytes = this.getResolvedContentAdapter().serializeConfigurationSync(configuration);
    await this.sendSyncPayloadToLocalOtherDevices(payloadBytes, timestamp);
  }

  async sendUsernameStateSyncToLocalOtherDevices(
    usernameState: UsernameStateSyncInput
  ): Promise<void> {
    const timestamp = Date.now();
    const payloadBytes = this.getResolvedContentAdapter().serializeUsernameStateSync(usernameState);
    await this.sendSyncPayloadToLocalOtherDevices(payloadBytes, timestamp);
  }

  async sendRecipientUsernameSyncToLocalOtherDevices(
    recipientUsername: RecipientUsernameSyncInput
  ): Promise<void> {
    const payloadBytes =
      this.getResolvedContentAdapter().serializeRecipientUsernameSync(recipientUsername);
    await this.sendSyncPayloadToLocalOtherDevices(payloadBytes, recipientUsername.learnedAt);
  }

  async sendVerificationStateSyncToLocalOtherDevices(
    verificationState: VerificationStateSyncInput
  ): Promise<void> {
    const payloadBytes =
      this.getResolvedContentAdapter().serializeVerificationStateSync(verificationState);
    await this.sendSyncPayloadToLocalOtherDevices(payloadBytes, verificationState.changedAt);
  }

  async sendTaskNotificationAckSyncToLocalOtherDevices(
    ack: TaskNotificationAckSyncInput
  ): Promise<void> {
    const payloadBytes = this.getResolvedContentAdapter().serializeTaskNotificationAckSync(ack);
    await this.sendSyncPayloadToLocalOtherDevices(payloadBytes, ack.acknowledgedAt);
  }

  async sendBlockedRecipientsSyncToLocalOtherDevices(
    blocked: BlockedRecipientsSyncInput
  ): Promise<void> {
    const payloadBytes = this.getResolvedContentAdapter().serializeBlockedRecipientsSync(blocked);
    await this.sendSyncPayloadToLocalOtherDevices(payloadBytes, blocked.syncedAt);
  }

  /**
   * Set the session callbacks of a send that passes none
   * Called by SignalProtocolClient after construction to inject session establishment logic
   *
   * The stale-session refresher runs when the server returns STALE_DEVICE
   * errors (device reinstalled).
   */
  setSessionCallbacks(callbacks: SendSessionCallbacks): void {
    this.sessionCallbacks = callbacks;
  }

  /**
   * Set the sealed sender provider callback
   * Called by SignalProtocolClient after construction to inject sealed sender support.
   *
   * Provides the sender certificate and identity key needed for sealing messages.
   */
  setSealedSenderProvider(provider: SealedSenderProvider): void {
    this.sealedSenderProvider = provider;
  }

  setSealedSenderDeliveryMode(mode: import('./config').SealedSenderDeliveryMode): void {
    this.sealedSenderDeliveryMode = mode;
  }

  setSealedSenderIdentifiedFallback(
    callback: NonNullable<import('./config').SealedSenderConfig['onIdentifiedFallback']>
  ): void {
    this.sealedSenderIdentifiedFallback = callback;
  }

  /**
   * Set the reporter of a protocol error that no send result carries.
   * Called by SignalProtocolClient after construction. A sync payload has no
   * send result, so the reporter gives its error to the app.
   */
  setRelayProtocolErrorReporter(report: (error: RelayProtocolError) => Promise<void>): void {
    this.relayProtocolErrorReporter = report;
  }

  private async reportIdentifiedFallback(recipientUserId: string): Promise<void> {
    try {
      await this.sealedSenderIdentifiedFallback?.({
        recipientUserId,
        reason: 'authorization-rejected',
      });
    } catch (fallbackHookError) {
      this.logger.warn('Sealed sender identified-fallback hook failed', {
        category: 'E2EE',
        data: {
          recipientUserId,
          error: (fallbackHookError as Error).message,
        },
      });
    }
  }

  /**
   * Restrict the cached unidentified access mode of a recipient after the
   * relay rejects a sealed-sender authorization. A failure to update the mode
   * does not block delivery.
   */
  private async restrictUnidentifiedAccessMode(recipientUserId: string): Promise<void> {
    try {
      const contactProfileStateStore = this.contactProfileStateStore;
      if (!contactProfileStateStore) {
        this.logger.debug('No contact profile state store configured after sealed sender failure', {
          category: 'E2EE',
          data: { recipientUserId },
        });
        return;
      }
      // The device posts of a send run at the same time. The lock orders
      // their steps, so two failures step down twice, as posts in device
      // order do.
      await this.lock.acquire(`unidentified-access-mode:${recipientUserId}`, async () => {
        const currentMode = await contactProfileStateStore.getUnidentifiedAccessMode(
          recipientUserId
        );
        let newMode: UnidentifiedAccessModeType;
        switch (currentMode) {
          case UnidentifiedAccessMode.UNRESTRICTED:
            newMode = UnidentifiedAccessMode.UNKNOWN;
            break;
          case UnidentifiedAccessMode.ENABLED:
          case UnidentifiedAccessMode.UNKNOWN:
          default:
            newMode = UnidentifiedAccessMode.DISABLED;
            break;
        }
        await contactProfileStateStore.updateUnidentifiedAccessMode(recipientUserId, newMode);

        this.logger.info('Sealed sender auth failed, transitioned unidentified access mode', {
          category: 'E2EE',
          data: { recipientUserId, previousMode: currentMode, newMode },
        });
      });
    } catch (modeError) {
      // Non-fatal: mode transition failure should not block message delivery
      this.logger.warn('Failed to update unidentified access mode after auth failure', {
        category: 'E2EE',
        data: {
          recipientUserId,
          error: (modeError as Error).message,
        },
      });
    }
  }

  private useIdentifiedDeliveryOrThrow(recipientUserId: string, reason: string): null {
    if (this.sealedSenderDeliveryMode === 'required') {
      throw new EncryptionError(
        `Sealed sender is required but unavailable: ${reason}`,
        EncryptionErrorCode.SEALED_SENDER_REQUIRED,
        { recipientUserId, operation: 'resolveSealedSenderContext', reason }
      );
    }
    return null;
  }

  setContactProfileStateStore(store: ContactProfileStateStore): void {
    this.contactProfileStateStore = store;
  }

  /**
   * Set the endorsement manager for group send endorsement-based auth.
   *
   * When set, group messages will prefer endorsement tokens over UAK-based
   * sealed sender. This avoids needing the recipient's profile key for
   * group messages and provides stronger group membership verification.
   *
   */
  setEndorsementManager(manager: EndorsementManager, resolve?: () => Promise<EndorsementManager | undefined>): void {
    this.endorsementManager = manager;
    this.endorsementManagerResolver = resolve;
  }

  /**
   * Set the endorsement refresher callback.
   *
   * Called before V2 multi-recipient sends when endorsements are missing or
   * expiring soon. The implementation fetches endorsements from the server
   * and caches them via EndorsementManager.
   *
   */
  setEndorsementRefresher(refresher: EndorsementRefresher): void {
    this.endorsementRefresher = refresher;
  }

  /** Enforce the group-system C7 barrier at the sender-key send boundary. */
  setGroupSendBarrierChecker(checker: GroupSendBarrierChecker): void {
    this.groupSendBarrierChecker = checker;
  }

  /**
   * Set the group secret params provider callback.
   *
   * Required for endorsement-based sealed sender in groups. The provider
   * looks up GroupSecretParams from the local database for a given group ID.
   *
   * @param provider - Async callback returning GroupSecretParams or null
   */
  setGroupSecretParamsProvider(
    provider: (
      groupId: string
    ) => Promise<import('../internal/protocol/zk/groups/group-params').GroupSecretParams | null>
  ): void {
    this.groupSecretParamsProvider = provider;
  }

  /**
   * Set the provider of the group context that each new send to a managed
   * group carries. It answers null for a group with no master key.
   */
  setGroupContextProvider(
    provider: (groupId: string) => Promise<GroupContentContext | null>
  ): void {
    this.groupContextProvider = provider;
  }

  /** The content of a new group send, with the context of a managed group in it. */
  private async contentWithGroupContext(
    groupId: string,
    plaintextBytes: Uint8Array
  ): Promise<Uint8Array> {
    const context = await this.groupContextProvider?.(groupId);
    return context
      ? this.getResolvedContentAdapter().serializeContentWithGroupContext(plaintextBytes, context)
      : plaintextBytes;
  }

  // ============================================================================
  // Public API
  // ============================================================================

  /**
   * Decide on received managed-group content against verified group state.
   * Without an evaluator, managed-group content is refused.
   */
  setGroupReceiveEvaluator(evaluate: GroupReceiveEvaluator): void {
    this.groupReceiveEvaluator = evaluate;
  }

  /**
   * Decrypt incoming envelope - routes to appropriate cipher
   *
   * Routes based on envelope type:
   * - sender_key → Group cipher (Sender Keys)
   * - otherwise → Pairwise cipher (SESAME/Double Ratchet)
   *
   * The decrypt commits no receive record. It installs a distribution that
   * the content carries, and it runs the group decision of managed-group
   * content before it returns, as `commitEnvelope`, `decideGroupContent`,
   * and `decryptedEnvelopeOf` tell.
   *
   * @param envelope - Encrypted envelope from relay
   * @param sealedSenderConfig - The trust roots of an unidentified_sender envelope
   * @param stopSignal - When it aborts while the decrypt waits for a lock,
   *   the decrypt throws RelayWorkStopped
   * @returns Decrypted envelope ready for ContentManager
   * @throws {EncryptionError} DECRYPTION_FAILED if decryption fails
   * @throws {SealedRetryRequestReceived} for a seal that holds a retry request
   *
   * @see https://signal.org/docs/specifications/sesame/
   */
  async decrypt(
    envelope: Envelope,
    sealedSenderConfig?: import('./config').SealedSenderConfig,
    stopSignal?: AbortSignal
  ): Promise<DecryptedEnvelope> {
    const commit = await this.commitEnvelope(envelope, {
      ...(sealedSenderConfig !== undefined && { sealedSender: sealedSenderConfig }),
      ...(stopSignal !== undefined && { stopSignal }),
    });
    if (commit.kind === 'denied') throw commit.error;
    if (commit.kind !== 'committed') {
      throw new Error(`A decrypt with no receive record cannot end ${commit.kind}`);
    }
    const decision = await this.decideGroupContent(commit.content);
    if (decision.kind !== 'authorized') throw decision.error;
    return this.decryptedEnvelopeOf(commit.content, decision.groupId);
  }

  /**
   * Decrypt one envelope and commit its receive record in the same store
   * transaction as the ratchet step. Then check the content and install a
   * distribution that it carries. The group decision does not run here.
   *
   * With `work`, the commit first reads the record of `work.workId`. A
   * record that holds plaintext is a redelivery: the commit reuses the
   * plaintext, spends no ratchet step, and installs the distribution of a
   * Relay record again. A caller record installs nothing.
   * A record that holds no plaintext ends `settled`. With no record, the
   * admission of `work` runs the decrypt, so a full queue ends `refused`
   * with nothing decrypted. A check that fails after the commit ends
   * `denied`, because the ratchet step is spent.
   *
   * @throws {EncryptionError} when the decrypt fails. Nothing is committed.
   * @throws {SealedRetryRequestReceived} for a seal that holds a retry request
   */
  async commitEnvelope(
    envelope: Envelope,
    options: EnvelopeCommitOptions = {}
  ): Promise<EnvelopeCommit> {
    return this.commitAt(envelope, false, options);
  }

  private async commitAt(
    envelope: Envelope,
    arrivedSealed: boolean,
    options: EnvelopeCommitOptions
  ): Promise<EnvelopeCommit> {
    const { stopSignal, work } = options;
    // Handle sealed sender (unidentified_sender) envelopes by unsealing first
    if (envelope.messageType === 'unidentified_sender') {
      const innerEnvelope = await this.unsealEnvelope(envelope, options.sealedSender);
      // A retry request has no ratchet ciphertext. The caller routes it.
      if (innerEnvelope.messageType === 'retry_request') {
        throw new SealedRetryRequestReceived(innerEnvelope);
      }
      try {
        return await this.commitAt(innerEnvelope, true, { ...options, sealedSender: undefined });
      } catch (error) {
        attachUnsealedEnvelope(error, innerEnvelope);
        throw error;
      }
    }

    // Validate message type before processing
    // Server only sends the 5 envelope types. Client-to-client types (typing_indicator,
    // delivery_receipt, sender_key_distribution) are encrypted Content inside ciphertext.
    const validMessageTypes = [
      'prekey_bundle',
      'ciphertext',
      'sender_key',
      'unidentified_sender',
    ] as const;
    if (!validMessageTypes.includes(envelope.messageType as (typeof validMessageTypes)[number])) {
      throw new EncryptionError(
        `Unknown message type: ${envelope.messageType}`,
        EncryptionErrorCode.INVALID_CIPHERTEXT,
        { messageType: envelope.messageType, senderId: envelope.senderUserId }
      );
    }

    const lockKey = `decrypt:${envelope.senderUserId}:${envelope.senderDeviceId}`;

    return acquireUntilStopped(this.lock, lockKey, async (): Promise<EnvelopeCommit> => {
      this.logger.debug('Handling incoming envelope', {
        category: 'E2EE',
        data: {
          envelopeId: envelope.id,
          senderId: envelope.senderUserId,
          senderDeviceId: envelope.senderDeviceId,
          messageType: envelope.messageType,
        },
      });

      const existing = work ? await this.storage.getReceiveWork(work.workId) : null;
      // The application got the content. Only its receipt can wait.
      if (existing && existing.plaintext === undefined) return { kind: 'settled', record: existing };
      const seed = work?.seed(envelope, arrivedSealed);

      let plaintext: string;
      // Set for group messages once the frame's distribution identifier has
      // been resolved against the local sender key store. The envelope carries
      // no group, so this is the only place a group becomes known on receive.
      let transportGroupId: string | null = null;
      let record: ReceiveWorkRecord | null = existing;
      if (existing) {
        // A redelivery of committed content spends no ratchet step.
        plaintext = existing.plaintext!;
        if (envelope.messageType === 'sender_key') {
          transportGroupId =
            existing.groupId ??
            (await this.resolveFramedGroup(envelope, envelopeCiphertextBytes(envelope.ciphertext)));
        }
        if (existing.awaitingEnvelope && seed) {
          record = await this.fillAwaitingEnvelope(existing, seed, transportGroupId);
        }
      } else {
        // Route on the envelope type. `sender_key` says "decrypt this as a
        // framed SenderKeyMessage". It does not say which group, and cannot.
        // That is the point of not putting a group on the envelope.
        if (envelope.messageType === 'sender_key') {
          const group = await this.decryptGroup(envelope, seed, work?.admit, stopSignal);
          if (group === null) return { kind: 'refused' };
          plaintext = group.plaintext;
          transportGroupId = group.groupId;
        } else {
          // Pairwise message - use SESAME for session convergence
          const sesameMessage = this.toSesameMessage(envelope);
          const decrypt = () => this.decryptPairwise(sesameMessage, seed);
          const pairwise = work ? await work.admit(null, decrypt) : { value: await decrypt() };
          if (pairwise === null) return { kind: 'refused' };
          plaintext = pairwise.value;
        }
        if (work) {
          record = await this.storage.getReceiveWork(work.workId);
          // An ack after this point must find the content stored.
          if (!record) throw new Error('The store did not commit the receive record');
        }
      }

      // The admission time is the time of the first commit. A retry, a
      // redelivery, and a restart read the same value, so the receipt
      // fallback timestamp and the age of waiting content stay fixed.
      const receivedAt = record?.receivedAt ?? Date.now();
      const sender = {
        messageId: envelope.id || `${envelope.senderUserId}-${receivedAt}`,
        senderUserId: envelope.senderUserId,
        senderDeviceId: envelope.senderDeviceId,
      };

      let inspected: InspectedSignalProtocolContent;
      try {
        inspected = this.getResolvedContentAdapter().inspectContent(plaintext);
        this.checkCommittedContent(
          envelope.senderUserId,
          envelope.timestamp,
          inspected,
          transportGroupId
        );
      } catch (error) {
        // The ratchet step is spent, so a resend cannot repair the content.
        return { kind: 'denied', error: error as Error, record, ...sender };
      }

      // Signal installs a distribution from an authenticated session before
      // it looks at the group: the key decrypts nothing until group content
      // that names it passes the group checks. A caller record installs
      // nothing, as in restoreCommitted, so a Relay redelivery that reuses
      // it gives the distribution to the caller only.
      const distribution = inspected.senderKeyDistribution;
      let distributionGroupId: string | null = null;
      if (distribution && (record === null || record.origin === 'relay')) {
        distributionGroupId = await this.installDistribution(
          envelope.senderUserId,
          envelope.senderDeviceId,
          distribution,
          stopSignal
        );
      } else if (distribution) {
        distributionGroupId = extractGroupId(distribution.groupId);
      }

      recordServerClockSample(envelope.serverTimestamp, receivedAt);

      return {
        kind: 'committed',
        record,
        reused: existing !== null,
        content: {
          ...sender,
          messageType: envelope.messageType as CommittedContent['messageType'],
          ...(envelope.serverTimestamp !== undefined && {
            serverTimestamp: envelope.serverTimestamp,
          }),
          arrivedSealed,
          plaintext,
          inspected,
          transportGroupId,
          distributionGroupId,
          receivedAt,
        },
      };
    }, stopSignal);
  }

  /** Open a sealed envelope and return the envelope that it holds. */
  private async unsealEnvelope(
    envelope: Envelope,
    sealedSenderConfig: import('./config').SealedSenderConfig | undefined
  ): Promise<Envelope> {
    if (!sealedSenderConfig || sealedSenderConfig.trustRoots.length === 0) {
      throw new EncryptionError(
        'Received sealed sender message but no trust roots configured',
        EncryptionErrorCode.INVALID_CIPHERTEXT,
        { messageType: envelope.messageType }
      );
    }

    // Get recipient's X25519 identity private key for unsealing
    const identityKeyPair = await this.storage.getIdentityKey();
    if (!identityKeyPair) {
      throw new EncryptionError(
        'No identity key pair for sealed sender decryption',
        EncryptionErrorCode.DECRYPTION_FAILED
      );
    }

    // Convert branded Base64 private key to Uint8Array for sealed sender
    const recipientPrivateKeyBytes = base64ToBytes(identityKeyPair.dhKey.privateKey);

    const ciphertextStr =
      typeof envelope.ciphertext === 'string'
        ? envelope.ciphertext
        : CryptoUtils.bytesToBase64(envelope.ciphertext);

    const unsealed = await unsealMessage(
      ciphertextStr,
      recipientPrivateKeyBytes,
      this.userId,
      this.deviceId,
      sealedSenderConfig,
      envelope.serverTimestamp,
      this.logger
    );

    // Reconstruct envelope with revealed sender identity
    return reconstructEnvelope(envelope, unsealed);
  }

  /**
   * Fill the sender fields of a converted legacy record from its
   * redelivered envelope. The record keeps its age and its arrival order.
   */
  private async fillAwaitingEnvelope(
    existing: ReceiveWorkRecord,
    seed: ReceiveWorkSeed,
    groupId: string | null
  ): Promise<ReceiveWorkRecord> {
    const seeded = seed({
      plaintext: existing.plaintext!,
      ...(groupId !== null && { groupId }),
    });
    const filled = sizedReceiveWork({
      ...seeded,
      workId: existing.workId,
      revision: existing.revision + 1,
      stage: existing.stage,
      arrivalSeq: existing.arrivalSeq,
      receivedAt: existing.receivedAt,
      dueAt: existing.dueAt,
      plaintext: existing.plaintext!,
      ...(existing.groupId !== undefined && { groupId: existing.groupId }),
      ...(existing.blockedOn !== undefined && { blockedOn: existing.blockedOn }),
    });
    if (await this.storage.putReceiveWork(filled, existing.revision)) return filled;
    return (await this.storage.getReceiveWork(existing.workId)) ?? existing;
  }

  /**
   * The checks of committed content that run before its distribution
   * installs: the replay check, sync content from another account, and a
   * distribution inside a sender-key message.
   */
  private checkCommittedContent(
    senderUserId: string,
    envelopeTimestamp: number | undefined,
    inspected: InspectedSignalProtocolContent,
    transportGroupId: string | null
  ): void {
    // Replay attack prevention
    // Validate envelope.timestamp matches content timestamp after decryption.
    // A replayed envelope installs no sender key, so the check runs first.
    const contentTimestamp = inspected?.timestamp;
    if (
      envelopeTimestamp !== undefined &&
      typeof contentTimestamp === 'number' &&
      envelopeTimestamp !== contentTimestamp
    ) {
      throw new EncryptionError(
        `Timestamp mismatch: envelope=${envelopeTimestamp}, content=${contentTimestamp}. Potential replay attack.`,
        EncryptionErrorCode.REPLAY_DETECTED
      );
    }

    // Sync content is content of the own account. Content from another
    // account that carries a sync message is refused before it installs a
    // distribution or any group decision runs.
    refuseSyncFromOtherAccount(inspected, senderUserId, this.userId);

    if (inspected.senderKeyDistribution && transportGroupId !== null) {
      throw new EncryptionError(
        'Sender-key distributions require pairwise encryption',
        EncryptionErrorCode.INVALID_CIPHERTEXT
      );
    }
  }

  /**
   * The committed content of a stored receive record, for the receive queue
   * after the release of the record and for a helper receive. It decrypts nothing.
   * It runs the content checks again, so a crash between a failed check and
   * its denied record denies again.
   *
   * For a Relay record it installs the distribution of the content again.
   * One Signal client puts the install in the buffered store of the ratchet step
   * and writes both in one transaction before the acknowledgment. The local
   * store contract commits a session
   * with its receive record, and sender keys apart from it under the group
   * lock, so the commit stores the record before its install, and an install
   * can fail after the commit. A redelivery replays the install, but a pass
   * can complete the record before the redelivery comes, and the key is then
   * lost. A replay of an installed distribution changes nothing while its
   * key is the current state or one of the kept previous states. When the
   * key is neither, the replay installs it again as the current state, and
   * when the record already holds 5 states, the oldest state goes. Test: "the
   * subscription handler returns true only after the commit, the sender key
   * install, and the outcome-1 write". A caller record installs nothing: its
   * commit gives the distribution to the caller and installs no sender key.
   * Test: "gives the content once, and the failed message is a duplicate
   * after a restart".
   *
   * @param record - A record that holds plaintext and its sender. A
   *   converted legacy record waits for its envelope, and has no sender.
   * @param stopSignal - Stops the wait for the sender key lock.
   * @returns `committed` with the content, or `denied` when a check fails
   */
  async restoreCommitted(
    record: ReceiveWorkRecord,
    stopSignal?: AbortSignal
  ): Promise<Extract<EnvelopeCommit, { kind: 'committed' | 'denied' }>> {
    const { plaintext, senderUserId, senderDeviceId, messageType, messageId } = record;
    if (
      plaintext === undefined ||
      senderUserId === undefined ||
      senderDeviceId === undefined ||
      messageType === undefined ||
      messageId === undefined
    ) {
      throw new Error('A receive record without content or sender cannot be restored');
    }
    const sender = { messageId, senderUserId, senderDeviceId };
    const transportGroupId = messageType === 'sender_key' ? (record.groupId ?? null) : null;
    let inspected: InspectedSignalProtocolContent;
    try {
      inspected = this.getResolvedContentAdapter().inspectContent(plaintext);
      this.checkCommittedContent(senderUserId, record.senderTimestamp, inspected, transportGroupId);
    } catch (error) {
      return { kind: 'denied', error: error as Error, record, ...sender };
    }
    const distribution = inspected.senderKeyDistribution;
    let distributionGroupId: string | null = null;
    if (distribution && record.origin === 'relay') {
      distributionGroupId = await this.installDistribution(
        senderUserId,
        senderDeviceId,
        distribution,
        stopSignal
      );
    } else if (distribution) {
      distributionGroupId = extractGroupId(distribution.groupId);
    }
    return {
      kind: 'committed',
      record,
      reused: true,
      content: {
        ...sender,
        messageType,
        ...(record.serverTimestamp !== undefined && { serverTimestamp: record.serverTimestamp }),
        arrivedSealed: record.arrivedSealed === true,
        plaintext,
        inspected,
        transportGroupId,
        distributionGroupId,
        receivedAt: record.receivedAt,
      },
    };
  }

  /**
   * Install an authenticated distribution. A copy of an installed
   * distribution changes nothing while its key is the current state or a
   * kept previous state, so a replay of the install is safe. A copy of a key
   * that is neither installs again as the current state, and when the
   * record already holds 5 states, the oldest state goes.
   *
   * @returns The raw group of the distribution
   */
  async installDistribution(
    senderUserId: string,
    senderDeviceId: number,
    distribution: NonNullable<InspectedSignalProtocolContent['senderKeyDistribution']>,
    stopSignal?: AbortSignal
  ): Promise<string> {
    return this.groupSenderKeys.run(
      distribution.groupId,
      async (rawGroupId) => {
        await this.senderKeyManager.processSenderKeyDistribution(
          rawGroupId,
          senderUserId,
          senderDeviceId,
          distribution.distribution
        );
        return rawGroupId;
      },
      stopSignal
    );
  }

  /**
   * Decide on committed managed-group content against verified group state.
   * Content that names no managed group and carries no context needs no
   * decision.
   *
   * @returns `authorized` with the group of the content, or null for content
   *   of no group. `denied` with the refusal. `unavailable` with the raw
   *   group whose state must update first.
   */
  async decideGroupContent(content: CommittedContent): Promise<GroupContentDecision> {
    // Content beside a distribution is content of that group: a retry
    // resend carries the logged group message with the current sender key.
    const resolvedGroupId =
      content.transportGroupId ??
      (content.inspected.senderKeyDistributionOnly === false ? content.distributionGroupId : null);
    // Managed-group content is delivered only when verified group state at
    // the revision of its context authorizes it.
    const claim = classifyGroupContent(
      content.messageType === 'sender_key' ? content.transportGroupId : null,
      content.inspected
    );
    if (!claim) return { kind: 'authorized', groupId: resolvedGroupId };
    if (!this.groupReceiveEvaluator) {
      return { kind: 'denied', error: new GroupReceiveRefusedError('configuration') };
    }
    const verdict = await this.groupReceiveEvaluator({
      claim,
      senderId: content.senderUserId,
      senderDeviceId: content.senderDeviceId,
    });
    if (verdict.kind === 'authorized') {
      return { kind: 'authorized', groupId: claim.transcript ? resolvedGroupId : verdict.groupId };
    }
    if (verdict.kind === 'denied') {
      return { kind: 'denied', error: new GroupReceiveRefusedError(verdict.reason) };
    }
    const group = groupOfContext(claim);
    return {
      kind: 'unavailable',
      error: new GroupReceiveUnavailableError(verdict.reason, verdict.retryAfterMs, content.messageId),
      groupId: 'groupId' in group ? group.groupId : claim.groupId!,
    };
  }

  /**
   * The envelope that the application gets for authorized content.
   *
   * @param resolvedGroupId - The group of the content, from `decideGroupContent`
   */
  decryptedEnvelopeOf(content: CommittedContent, resolvedGroupId: string | null): DecryptedEnvelope {
    // For DMs, compute canonical conversation ID: dm:${sorted(user1, user2)}
    // Groups, and group content beside a distribution, use their group ID
    // directly. A sent sync transcript of this account overrides this with
    // the transcript's destination conversation. Sender-key content from
    // another account is content of its transport group.
    const transportGroupOnly =
      content.messageType === 'sender_key' && content.senderUserId !== this.userId;
    const conversationId =
      (transportGroupOnly ? resolvedGroupId : content.inspected?.conversationId) ||
      resolvedGroupId ||
      this.getDirectConversationId(content.senderUserId);
    // Extract client timestamp from decrypted content
    // Text messages: dataMessage.timestamp, Attachments: timestamp at top level
    const contentTimestamp = content.inspected?.timestamp;

    return {
      messageId: content.messageId,
      sessionId: ProtocolAddress.toString(
        ProtocolAddress.create(content.senderUserId, content.senderDeviceId)
      ),
      senderId: content.senderUserId,
      senderDeviceId: content.senderDeviceId,
      conversationId,
      content: content.plaintext,
      // Use client timestamp for receipt matching
      timestamp: typeof contentTimestamp === 'number' ? contentTimestamp : content.receivedAt,
      ...(content.serverTimestamp !== undefined && { serverTimestamp: content.serverTimestamp }),
      receivedAt: content.receivedAt,
      isGroup: resolvedGroupId !== null,
      arrivedSealed: content.arrivedSealed,
      messageType: content.messageType,
    };
  }

  /**
   * Encrypt outgoing message - routes based on recipient type
   *
   * Routes based on recipientId:
   * - Group ID (prefixed) → encryptToGroup (Sender Keys)
   * - Binary content with mimeType → encryptBlob (two-layer encryption)
   * - User ID → encryptToUser (SESAME)
   *
   * @param recipientId - User ID or group ID (groups use the package group ID prefix)
   * @param content - Uint8Array bytes to encrypt and send
   * @param options - Optional send options (mimeType for binary content, etc.)
   * @param sessions - Session callbacks of this send. Default: the callbacks
   *   that setSessionCallbacks set
   * @param stopSignal - The stop signal of the relay work that sends. When it
   *   aborts while the send waits for the recipient's lock, the send throws
   *   RelayWorkStopped. Default: none, and the send waits
   * @returns SendResult with messageId, timestamp, and device count
   *
   * @see https://signal.org/docs/specifications/sesame/
   */
  async encrypt(
    recipientId: string,
    content: Uint8Array,
    options?: SendOptions,
    sessions = this.sessionCallbacks,
    stopSignal?: AbortSignal
  ): Promise<SendResult> {
    const clientMessageId = options?.clientMessageId ?? (await CryptoUtils.generateUuidV4());
    const durableOptions = { ...options, clientMessageId };
    const encrypt = async () => {
      if (durableOptions.isBinary) {
        return this.encryptBinaryAttachment(
          recipientId,
          content,
          durableOptions,
          sessions,
          stopSignal
        );
      }
      if (isGroupId(recipientId)) {
        return this.encryptToGroup(recipientId, content, durableOptions, sessions, stopSignal);
      }
      return this.encryptToUser(recipientId, content, durableOptions, sessions, stopSignal);
    };

    try {
      // This lock keeps the sends to one recipient in order, also across an
      // attachment upload. A group send takes the group's Sender Key lock
      // only in encryptToGroup, so a receive does not wait for an upload.
      const orderKey = isGroupId(recipientId) ? extractGroupId(recipientId) : recipientId;
      return await acquireUntilStopped(this.lock, `encrypt:${orderKey}`, encrypt, stopSignal);
    } catch (error) {
      throw attachClientMessageId(error, clientMessageId);
    }
  }

  /**
   * Encrypt content for one device of a user and post it to that device only.
   * The send makes no outbox intent and no sent-sync transcript. A retry
   * resend uses it: the retry request is the durable job, and only the device
   * that asked gets the message again. The post uses the sealed-sender
   * context of a direct send to the user.
   *
   * With a retry target, the resend stores its encryption under the device
   * and the failed envelope ID. The resend carries the attempt number of
   * the request that it answers, from the request envelope ID. Its client
   * message ID is `<retryId>:resend` or `<retryId>:null`, with
   * `:<attempt>` from attempt 2. A call for the request envelope and the
   * kind of the stored record posts the stored bytes with their epoch
   * again, and does not encrypt: that is the sender's own retry of a post
   * that did not complete. A call for another request envelope or kind
   * encrypts with a fresh epoch, replaces the record in one write, and
   * posts it. So does a call whose stored bytes the Relay refuses with
   * OPERATION_EXPIRED: the new bytes post under the same ID. A
   * RETRY_CONFLICT answer to a post means that the Relay holds an earlier
   * encryption under this ID, so the answer is complete. When the Relay
   * admits the new bytes after the recipient acknowledged the earlier
   * ones, the recipient drops them as processed. Nothing deletes the
   * record before `RELIABILITY_RECORD_TTL_MS`.
   *
   * @param recipientUserId - The user of the device
   * @param recipientDeviceId - The device that gets the message
   * @param content - The plaintext to encrypt. Null when the plaintext is
   *   gone: then only a stored attempt can post
   * @param options - The client timestamp and the content hint of the
   *   message, and the retry request that a retry resend answers. Without a
   *   retry target, the client message ID is a new UUID and nothing is
   *   stored. The timestamp goes in the envelope. With `senderKeyHandoff`,
   *   the content carries that own sender key of the raw group: each
   *   encryption keeps the key, and when the Relay accepts the bytes, the
   *   send records a handoff row of the key that they carry. A post that the
   *   Relay answers with RETRY_CONFLICT records no row, because the Relay
   *   holds an earlier encryption
   * @param stopSignal - The stop signal of the relay work that sends. When it
   *   aborts while the send waits for the recipient's lock, the send throws
   *   RelayWorkStopped
   * @returns False only when the content is null and no stored attempt can
   *   post: there is none for this request attempt, or the Relay refused it
   *   with OPERATION_EXPIRED
   * @throws Error when the request envelope ID is not a retry request of
   *   the retry ID. Nothing is posted
   */
  async resendToDevice(
    recipientUserId: string,
    recipientDeviceId: number,
    content: string | null,
    options: {
      timestamp: number;
      contentHint?: ContentHint;
      retry?: RetryResendTarget;
      senderKeyHandoff?: { groupId: string; senderKeyId: string; generation: number };
    },
    stopSignal?: AbortSignal
  ): Promise<boolean> {
    if (!this.relay) throw new Error('Relay not configured - cannot resend');
    const { retry } = options;
    if (content === null && retry === undefined) {
      throw new Error('A resend without content needs a stored attempt');
    }
    // The answer carries the attempt number of its request.
    const target = retry && { ...retry, attempt: retryRequestAttempt(retry) };
    const handoffGroupId = options.senderKeyHandoff?.groupId;
    const post = async (resend: StoredRetryResend): Promise<void> => {
      try {
        await this.postResend(resend, retryResendAttemptId(resend), stopSignal);
      } catch (error) {
        if (relayOperationRefusal(error) !== 'RETRY_CONFLICT') throw error;
        // Only this sender posts this ID. A new encryption for the same
        // request attempt and kind posts the same ID, so a conflict means
        // that the Relay holds the earlier encryption.
        this.logger.info('The Relay holds an earlier encryption of a retry resend attempt', {
          category: 'E2EE',
          data: { retryId: resend.retryId, kind: resend.kind, attempt: resend.attempt },
        });
        return;
      }
      if (handoffGroupId !== undefined) {
        await this.recordSenderKeyHandoff(handoffGroupId, resend.message);
      }
    };
    return await acquireUntilStopped(
      this.lock,
      `encrypt:${recipientUserId}`,
      async () => {
        if (target === undefined) {
          const resend = await this.encryptResend(
            recipientUserId,
            recipientDeviceId,
            content!,
            options
          );
          await this.postResend(resend, await CryptoUtils.generateUuidV4(), stopSignal);
          if (handoffGroupId !== undefined) {
            await this.recordSenderKeyHandoff(handoffGroupId, resend.message);
          }
          return true;
        }
        const stored = await getRetryResend(
          this.storage,
          recipientUserId,
          recipientDeviceId,
          target.failedEnvelopeId
        );
        // A terminal record holds no resend to post again.
        if (
          stored !== null &&
          stored.terminal === undefined &&
          stored.requestEnvelopeId === target.requestEnvelopeId &&
          stored.kind === target.kind
        ) {
          try {
            await post(stored);
            return true;
          } catch (error) {
            if (relayOperationRefusal(error) !== 'OPERATION_EXPIRED') throw error;
          }
          // The Relay no longer admits or replays the stored operation.
          if (content === null) {
            this.logger.info('A stored retry resend expired, and its plaintext is gone', {
              category: 'E2EE',
              data: { retryId: stored.retryId, attempt: stored.attempt },
            });
            return false;
          }
        }
        if (content === null) return false;
        // A new encryption replaces the record before its post.
        const resend: StoredRetryResend = {
          ...target,
          ...(await this.encryptResend(recipientUserId, recipientDeviceId, content, options)),
        };
        await storeRetryResend(this.storage, resend);
        await post(resend);
        return true;
      },
      stopSignal
    );
  }

  /** Post the encrypted bytes of a resend with their operation epoch, under one client message ID. */
  private async postResend(
    resend: EncryptedResend,
    clientMessageId: string,
    stopSignal?: AbortSignal
  ): Promise<void> {
    const { message } = resend;
    if (
      resend.transportMode !== 'identified' &&
      (!message.sealedSenderMessage || !resend.sealedSenderAuth)
    ) {
      throw new Error('Corrupt retry-resend record');
    }
    const required = resend.transportMode === 'sealed_sender_required';
    const auth = await this.resolveResendAuthorization(resend);
    if (auth === null && required) {
      throw new EncryptionError(
        'Required group sealed-sender authorization is unavailable',
        EncryptionErrorCode.SEALED_SENDER_REQUIRED,
        { recipientUserId: message.recipientUserId }
      );
    }
    await this.sendToDevice(
      message,
      message.ciphertext,
      message.messageType,
      message.recipientRegistrationId,
      null,
      resend.contentHint,
      clientMessageId,
      auth === null
        ? undefined
        : {
            sentMessageBase64: message.sealedSenderMessage!,
            auth,
            deliveryMode: required ? 'required' : 'preferred',
          },
      {
        ...(stopSignal && { stopSignal }),
        operationEpochMilliseconds: resend.operationEpochMilliseconds,
      }
    );
  }

  /**
   * The sealed authorization of one resend post, or null when the post goes
   * identified. A stored group endorsement resolves again for the device's
   * account, and resolves to null when the group has none for it.
   */
  private async resolveResendAuthorization(
    resend: EncryptedResend
  ): Promise<SealedSenderAuth | null> {
    const stored = resend.transportMode === 'identified' ? undefined : resend.sealedSenderAuth;
    if (stored === undefined) return null;
    if (stored.type === 'accessKey') return { ...stored };
    return this.resolveGroupSendAuthorization(stored.groupId, [resend.message.recipientUserId]);
  }

  /**
   * The group of the group send that this client sent to the user at this
   * client timestamp, if any. A retry request names the failed message by
   * its timestamp, and the pre-messages of a group send have the timestamp
   * of the send. The members of a send name only its recipients. They are
   * never a source of current membership.
   */
  async findSentGroupId(
    recipientUserId: string,
    clientTimestamp: number
  ): Promise<string | undefined> {
    for (const clientMessageId of await getSentClientMessageIds(this.storage, clientTimestamp)) {
      const intent = await getOutgoingMessageIntent(this.storage, clientMessageId);
      if (intent?.kind === 'group' && intent.groupMemberUserIds?.includes(recipientUserId)) {
        return intent.recipientId;
      }
    }
    return undefined;
  }

  /**
   * The current sender-key distribution of this device for a group, at the
   * current chain index, or null when the device has no sender key for the
   * group. It is read in the group operation, so no send or rotation of the
   * group runs at the same time.
   */
  async currentGroupDistribution(
    groupId: string,
    stopSignal?: AbortSignal
  ): Promise<{ groupId: string; distribution: SenderKeyDistributionMessage } | null> {
    return this.groupSenderKeys.run(
      groupId,
      async (rawGroupId) => {
        const distribution = await this.senderKeyManager.getCurrentSenderKeyDistribution(
          rawGroupId,
          this.userId,
          this.deviceId
        );
        return distribution && { groupId: rawGroupId, distribution };
      },
      stopSignal
    );
  }

  /**
   * Encrypt one attempt of a resend, with the current time as its operation
   * epoch. The resend of a group send's message takes the sealed
   * authorization of a pre-message: the recipient's access key first, then
   * the group endorsement of the recipient's account.
   */
  private async encryptResend(
    recipientUserId: string,
    recipientDeviceId: number,
    content: string,
    options: ResendOptions
  ): Promise<EncryptedResend> {
    const operationEpochMilliseconds = Date.now();
    const groupId = await this.findSentGroupId(recipientUserId, options.timestamp);
    const sealedSender =
      groupId === undefined
        ? await this.resolveSealedSenderContext(recipientUserId)
        : await this.resolveDistributionSealedSender(recipientUserId, groupId);
    const directSealedSender =
      sealedSender && this.relay?.sendMultiRecipientUnidentified ? sealedSender : null;
    let sealedSenderAuth: EncryptedResend['sealedSenderAuth'];
    if (directSealedSender?.auth.type === 'accessKey') {
      sealedSenderAuth = { ...directSealedSender.auth };
    } else if (directSealedSender && groupId !== undefined) {
      sealedSenderAuth = { type: 'groupSendToken', groupId };
    } else if (directSealedSender) {
      // Only a group send resolves an endorsement.
      throw new Error('Direct sealed-sender delivery requires access-key authorization');
    }
    const message = await this.sesameManager.sendMessage(
      recipientUserId,
      recipientDeviceId,
      new TextEncoder().encode(content),
      { clientTimestamp: options.timestamp, includeSyncMessages: false }
    );
    return {
      operationEpochMilliseconds,
      transportMode: directSealedSender
        ? directSealedSender.config.deliveryMode === 'required'
          ? 'sealed_sender_required'
          : 'sealed_sender_preferred'
        : 'identified',
      ...(sealedSenderAuth && { sealedSenderAuth }),
      ...(options.contentHint !== undefined && { contentHint: options.contentHint }),
      message: {
        ...(await this.prepareStoredDirectDeviceMessage(
          message,
          directSealedSender,
          options.contentHint
        )),
        ...(options.senderKeyHandoff && {
          senderKeyHandoff: {
            senderKeyId: options.senderKeyHandoff.senderKeyId,
            generation: options.senderKeyHandoff.generation,
          },
        }),
      },
    };
  }

  /**
   * Encrypt and upload attachment data without sending a standalone message.
   */
  async uploadAttachment(
    data: Uint8Array,
    options: SendOptions & { mimeType: string }
  ): Promise<PreparedAttachmentUpload> {
    const lockKey = `attachment-upload:${options.mimeType}`;
    return this.lock.acquire(lockKey, async () => this.prepareAttachmentUpload(data, options));
  }

  // ============================================================================
  // PRIVATE - Decryption
  // ============================================================================

  /**
   * Convert Envelope to SesameMessage for SESAME receive path
   */
  private toSesameMessage(envelope: Envelope): SesameMessage {
    // SessionID format is "userId:deviceId" (from ProtocolAddress.toString())
    const sessionId = `${envelope.senderUserId}:${envelope.senderDeviceId}`;

    return {
      senderUserId: envelope.senderUserId,
      senderDeviceId: envelope.senderDeviceId,
      recipientUserId: this.userId, // We are the recipient
      recipientDeviceId: this.deviceId,
      sessionId,
      // Ciphertext is base64-encoded on relay, convert back to Uint8Array
      // SESAME will deserialize it back to Ciphertext (branded base64 string) internally
      ciphertext: envelopeCiphertextBytes(envelope.ciphertext),
      isInitiating: envelope.messageType === 'prekey_bundle',
      initHeader: null, // Extracted from ciphertext by SESAME
      timestamp: envelope.timestamp,
    };
  }

  /**
   * Archive the session with one device, for the session reset of a retry
   * request that ended as `expired-content`.
   *
   * The archive takes the decrypt lock of the device first, so each decrypt
   * from the device in progress ends before it, and a decrypt that starts
   * later reads the archived state. Under the device locks of the session
   * manager, it then archives the session in the protocol store and in the
   * device record. The next send to the user reads its device list again
   * and starts a new session with the device.
   *
   * @param stopSignal - When it aborts while the archive waits for the
   *   decrypt lock, nothing is archived and the call throws RelayWorkStopped
   */
  async archiveDeviceSession(
    userId: string,
    deviceId: number,
    stopSignal?: AbortSignal
  ): Promise<void> {
    await acquireUntilStopped(
      this.lock,
      `decrypt:${userId}:${deviceId}`,
      () =>
        this.sesameManager.archiveSession(userId, deviceId, () =>
          this.storage.archiveCurrentSession(ProtocolAddress.create(userId, deviceId), null)
        ),
      stopSignal
    );
    this.recipientDeviceListCheckedAt.delete(userId);
  }

  /**
   * Decrypt a pairwise message via SESAME
   *
   * Public for use by DefaultSignalProtocolClient.receive() which takes raw SesameMessage.
   *
   * @throws {EncryptionError} DECRYPTION_FAILED if decryption fails
   */
  async decryptPairwise(sesameMessage: SesameMessage, seed?: ReceiveWorkSeed): Promise<string> {
    try {
      const plaintextBytes = await this.sesameManager.receive(sesameMessage, seed);
      const plaintext = this.encodeLosslessPlaintext(plaintextBytes);

      this.logger.debug('Message received and decrypted', {
        category: 'E2EE',
        data: {
          senderUserId: sesameMessage.senderUserId,
          senderDeviceId: sesameMessage.senderDeviceId,
        },
      });

      return plaintext;
    } catch (error) {
      // Preserve EncryptionError for client-layer handling (e.g., PREKEY_NOT_FOUND triggers key rotation)
      if (error instanceof EncryptionError) {
        throw error;
      }
      throw new EncryptionError(
        'Failed to decrypt message',
        EncryptionErrorCode.DECRYPTION_FAILED,
        {
          originalError: error as Error,
          senderUserId: sesameMessage.senderUserId,
        }
      );
    }
  }

  /**
   * Resolve the group of a framed SenderKeyMessage from the distribution
   * identifier inside the frame.
   *
   * @throws {EncryptionError} SESSION_NOT_FOUND when no stored sender key
   *   claims the identifier
   */
  private async resolveFramedGroup(envelope: Envelope, framedBytes: Uint8Array): Promise<string> {
    const groupId = await this.senderKeyManager.resolveGroupForFramedMessage(
      framedBytes,
      envelope.senderUserId,
      envelope.senderDeviceId
    );
    if (groupId === null) {
      // No stored sender key claims this distribution identifier, so there is
      // nothing to decrypt against. Same remedy as a missing key: ask the
      // sender to redistribute.
      throw new EncryptionError(
        `No sender key from ${envelope.senderUserId} matches this group message - request key distribution`,
        EncryptionErrorCode.SESSION_NOT_FOUND
      );
    }
    return groupId;
  }

  /**
   * Decrypt a group message via Sender Keys.
   *
   * The envelope names no group, so the group is resolved from the opaque
   * distribution identifier inside the frame and returned alongside the
   * plaintext. Callers need it for the conversation ID and cannot read it off
   * the envelope. The admission runs inside the group lock, so it sees the
   * group before the decrypt.
   *
   * @param seed - Builds the receive record that commits with the ratchet step
   * @param admit - Runs the decrypt under the receive admission
   * @returns Null when the admission refuses the decrypt
   * @throws {EncryptionError} DECRYPTION_FAILED if decryption fails
   */
  private async decryptGroup(
    envelope: Envelope,
    seed?: ReceiveWorkSeed,
    admit?: ReceiveCommit['admit'],
    stopSignal?: AbortSignal
  ): Promise<{
    plaintext: string;
    groupId: string;
  } | null> {
    // Get the framed SenderKeyMessage bytes
    const framedBytes = envelopeCiphertextBytes(envelope.ciphertext);
    const groupId = await this.resolveFramedGroup(envelope, framedBytes);

    return this.groupSenderKeys.run(groupId, async (rawGroupId) => {
      const decrypt = async () => {
        try {
          return await this.senderKeyManager.decryptGroupMessage(
            rawGroupId,
            envelope.senderUserId,
            envelope.senderDeviceId,
            framedBytes,
            seed
          );
        } catch (error) {
          const err = error as Error;
          if (err.message?.includes('SENDER_KEY_NOT_FOUND')) {
            throw new EncryptionError(
              `No sender key from ${envelope.senderUserId} for group ${rawGroupId} - request key distribution`,
              EncryptionErrorCode.SESSION_NOT_FOUND,
              { originalError: err }
            );
          }
          if (err.message?.includes('INVALID_SIGNATURE')) {
            throw new EncryptionError(
              `Invalid signature on group message from ${envelope.senderUserId}`,
              EncryptionErrorCode.DECRYPTION_FAILED,
              { originalError: err }
            );
          }
          if (err.message?.includes('MESSAGE_TOO_OLD')) {
            throw new EncryptionError(
              'Cannot decrypt old group message (forward secrecy)',
              EncryptionErrorCode.DECRYPTION_FAILED,
              { originalError: err }
            );
          }
          throw new EncryptionError(
            `Failed to decrypt group message from ${envelope.senderUserId}`,
            EncryptionErrorCode.DECRYPTION_FAILED,
            { originalError: err }
          );
        }
      };
      const admitted = admit ? await admit(rawGroupId, decrypt) : { value: await decrypt() };
      if (admitted === null) return null;

      this.logger.debug('Decrypted group message', {
        category: 'E2EE',
        data: {
          groupId: rawGroupId,
          senderId: envelope.senderUserId,
        },
      });

      return { plaintext: admitted.value, groupId: rawGroupId };
    }, stopSignal).catch((error: unknown) => {
      // The retry request record of the failed envelope keeps its group.
      attachFailedGroup(error, extractGroupId(groupId));
      throw error;
    });
  }

  // ============================================================================
  // PRIVATE - Encryption
  // ============================================================================

  /**
   * Reconcile a recipient's sessions with the relay's device list
   *
   * A send must reach every device the relay lists for the recipient, and no
   * device the relay no longer lists. The session establisher reads that list
   * again when the last read is older than
   * RECIPIENT_DEVICE_LIST_FRESH_MILLISECONDS, creates a session for each listed
   * device that has none, and this method removes each local device that is not
   * listed. Inside the window, a recipient with an active session is sent to
   * without a relay read. The relay gives no device-set version, so the window
   * is the only bound on how long a linked or removed device goes unseen.
   *
   * A relay that compares device sets refuses a declared post that misses a
   * device or names a removed one, so on such a relay a recipient with an
   * active session is sent to without a relay read at any age. Only a
   * recipient with no session has its list read.
   *
   * A direct send may post before the read when the relay refuses every post
   * to a removed device's mailbox, this client read the list in this process,
   * and that read is younger than
   * RECIPIENT_DEVICE_LIST_MAXIMUM_AGE_MILLISECONDS. This method then returns
   * true without a read, and the send reads the list while it posts and
   * reconciles after the read. Other relays, and a list that this process did
   * not read or that is too old, await the read. A list time later than the
   * clock is too old.
   *
   * @param sendFirst - The caller can post before the read and reconcile after it
   * @param readDevices - The recipient's devices that this send read. When
   *   they are given, a reconcile uses them and does not read the list again
   * @returns True when the caller must read the list after it posts
   * @throws {EncryptionError} SESSION_NOT_FOUND if sessions cannot be established
   */
  private async ensureSessionsForUser(
    recipientUserId: string,
    sessions: SendSessionCallbacks | undefined,
    sendFirst = false,
    readDevices?: readonly GroupMemberDevice[]
  ): Promise<boolean> {
    const hasActiveSession = await this.hasActiveSession(recipientUserId);
    // A relay that compares device sets refuses a declared post that misses
    // a device, so a recipient with a session needs no list read.
    if (hasActiveSession && this.declaresDeviceSets()) return false;
    const listAge = this.recipientDeviceListAge(recipientUserId);
    if (hasActiveSession && listAge < RECIPIENT_DEVICE_LIST_FRESH_MILLISECONDS) {
      return false;
    }

    this.logger.debug('Reconciling recipient devices with the relay', {
      category: 'E2EE',
      data: { recipientUserId, hasActiveSession },
    });

    if (!sessions) {
      if (hasActiveSession) return false;
      throw new EncryptionError(
        `No session with ${recipientUserId} and auto-establishment not configured`,
        EncryptionErrorCode.SESSION_NOT_FOUND,
        { recipientUserId }
      );
    }

    if (!this.relay) {
      if (hasActiveSession) return false;
      throw new EncryptionError(
        'Cannot auto-establish session: relay server not configured',
        EncryptionErrorCode.INITIALIZATION_FAILED,
        { recipientUserId }
      );
    }

    if (
      sendFirst &&
      hasActiveSession &&
      listAge < RECIPIENT_DEVICE_LIST_MAXIMUM_AGE_MILLISECONDS &&
      refusesRemovedDevices(this.relay)
    ) {
      return true;
    }

    await this.readRecipientDeviceList(
      recipientUserId,
      sessions,
      hasActiveSession,
      undefined,
      readDevices
    );
    return false;
  }

  private async hasActiveSession(recipientUserId: string): Promise<boolean> {
    const userRecord = await this.sesameManager.getUserRecord(recipientUserId);
    return (
      !!userRecord &&
      Array.from(userRecord.devices.values()).some(
        (device) => !isRemovedDevice(device) && device.session?.currentSession != null
      )
    );
  }

  /** The age of this process's last successful read. A read in the future has no age. */
  private recipientDeviceListAge(recipientUserId: string): number {
    const checkedAt = this.recipientDeviceListCheckedAt.get(recipientUserId);
    const age = checkedAt === undefined ? Number.POSITIVE_INFINITY : Date.now() - checkedAt;
    return age >= 0 ? age : Number.POSITIVE_INFINITY;
  }

  /**
   * Read the recipient's device list, create the missing sessions, and remove
   * each local device that the list does not show.
   *
   * @param onList - Called with the listed devices as soon as the list arrives,
   *   before the unlisted records are removed
   * @param readDevices - The devices that this send read. When they are
   *   given, the list is not read again
   * @returns The listed and established devices, or undefined when the read
   *   failed and the known devices still receive
   */
  private async readRecipientDeviceList(
    recipientUserId: string,
    sessions: SendSessionCallbacks,
    hasActiveSession: boolean,
    onList?: (listed: ReadonlySet<number>) => void,
    readDevices?: readonly GroupMemberDevice[]
  ): Promise<RecipientDeviceList | undefined> {
    let result: Awaited<ReturnType<SessionEstablisher>>;
    try {
      // Use retry logic for transient network failures
      result = await withRetry(
        async () => {
          const attempt = await sessions.establishSessions(recipientUserId, readDevices);
          if (attempt.establishedDevices.length === 0 && attempt.failedDeviceErrors.length > 0) {
            throw attempt.failedDeviceErrors[0]!.error;
          }
          return attempt;
        },
        {
          operationName: 'establishSession',
          maxRetries: 2,
          baseDelay: 500,
          shouldRetry: (error) => !(error instanceof RelayWorkStopped),
        }
      );
    } catch (error) {
      rethrowRelayWorkStopped(error);
      if (hasActiveSession) {
        // The known devices still receive; the next send reads the list again.
        this.logger.warn('Recipient device list refresh failed, sending to known devices', {
          category: 'E2EE',
          error: error as Error,
          data: { recipientUserId },
        });
        return undefined;
      }

      // Re-throw EncryptionErrors, wrap others
      if (error instanceof EncryptionError) {
        throw error;
      }

      // Check for rate limiting
      const errorMessage = (error as Error).message?.toLowerCase() || '';
      if (errorMessage.includes('rate limit')) {
        throw new EncryptionError(
          `Rate limited while establishing session with ${recipientUserId}`,
          EncryptionErrorCode.PREKEY_FETCH_RATE_LIMITED,
          { originalError: error as Error, recipientUserId }
        );
      }

      throw new EncryptionError(
        `Failed to establish session with ${recipientUserId} after retries`,
        EncryptionErrorCode.SESSION_ESTABLISHMENT_FAILED,
        { originalError: error as Error, recipientUserId }
      );
    }

    const listedDevices = new Set(result.activeDevices);
    onList?.(listedDevices);
    const removedDevices = await this.reconcileDeviceRecords(recipientUserId, listedDevices);

    if (result.establishedDevices.length === 0) {
      throw new EncryptionError(
        `Recipient ${recipientUserId} has no available prekey bundles - they may not have registered encryption keys`,
        EncryptionErrorCode.RECIPIENT_NOT_REGISTERED,
        { recipientUserId, failedDevices: result.failedDevices }
      );
    }

    // A device that failed stays unreached until the window ends, which keeps
    // a recipient with a broken device from costing a relay read on every send.
    this.recipientDeviceListCheckedAt.set(recipientUserId, Date.now());

    this.logger.info('Reconciled recipient devices', {
      category: 'E2EE',
      data: {
        recipientUserId,
        establishedDevices: result.establishedDevices,
        failedDevices: result.failedDevices,
        removedDevices,
      },
    });
    return { listed: listedDevices, established: result.establishedDevices };
  }

  /**
   * Read the sender's own device list.
   *
   * A listed own device with no session gets one first, and each own device
   * record that the list does not show is removed. With no relay there is no
   * list and no sync copy.
   *
   * On a relay that compares device sets, a send declares the own devices
   * that it holds records for, and reads no own list before its recipient
   * post. A 409 or a declared 410 answer to a sync post repairs the own
   * records, as Signal learns of a new or removed own device. A declared
   * direct send reads the own list only when a recipient receipt sets
   * `needsSync` and the send holds no own device record, and a failed read
   * leaves the sync phase pending without failing the send. On a relay that
   * does not compare, each send reads the own list before its recipient
   * post, and a failed read fails the send.
   *
   * @returns The listed own devices other than this device, in list order
   */
  private async readOwnDeviceList(
    sessions: SendSessionCallbacks | undefined,
    stopSignal: AbortSignal | undefined
  ): Promise<GroupMemberDevice[]> {
    const relay = this.relay;
    if (!relay) return [];
    const listed = await this.fanOut.request(
      () => relay.getActiveDevices(this.userId),
      stopSignal
    );
    const others = listed.filter(
      (device) => device.userId === this.userId && device.deviceId !== this.deviceId
    );
    if (others.length > 0 && sessions) {
      try {
        // A device that fails gets no copy from this send.
        await sessions.establishSessions(this.userId, others);
      } catch (error) {
        rethrowRelayWorkStopped(error);
        this.logger.warn('Could not start sessions with listed own devices', {
          category: 'E2EE',
          error: error as Error,
        });
      }
    }

    const listedIds = new Set(others.map((device) => device.deviceId));
    listedIds.add(this.deviceId);
    await this.reconcileDeviceRecords(this.userId, listedIds);
    return others;
  }

  /**
   * Remove each device record that the device list does not name, and
   * relist each removed record that it names again. A record that is already
   * removed and still unlisted stays as it is, so a second sweep writes no
   * archive and emits no event.
   *
   * @returns The devices that this sweep removed
   */
  private async reconcileDeviceRecords(
    userId: string,
    listed: ReadonlySet<number>
  ): Promise<number[]> {
    const removed: number[] = [];
    const record = await this.sesameManager.getUserRecord(userId);
    for (const [deviceId, device] of Array.from(record?.devices ?? [])) {
      if (listed.has(deviceId)) {
        if (isRemovedDevice(device)) await this.sesameManager.relistDevice(userId, deviceId);
      } else if (!isRemovedDevice(device)) {
        await this.sesameManager.removeDevice(userId, deviceId);
        removed.push(deviceId);
      }
    }
    return removed;
  }

  /**
   * Encrypt to a single user (all their devices) via SESAME
   */
  private async encryptToUser(
    recipientUserId: string,
    plaintextBytes: Uint8Array,
    options: SendOptions & { clientMessageId: string },
    sessions: SendSessionCallbacks | undefined,
    stopSignal?: AbortSignal
  ): Promise<SendResult> {
    return this.encryptToUserWithOutbox(
      recipientUserId,
      plaintextBytes,
      options,
      sessions,
      stopSignal
    );
  }
  private async encryptToUserWithOutbox(
    recipientUserId: string,
    plaintextBytes: Uint8Array,
    options: SendOptions & { clientMessageId: string },
    sessions: SendSessionCallbacks | undefined,
    stopSignal: AbortSignal | undefined
  ): Promise<SendResult> {
    return withOutgoingMessageIntentLock(this.storage, options.clientMessageId, () =>
      this.encryptToUserWithOutboxLocked(
        recipientUserId,
        plaintextBytes,
        options,
        sessions,
        stopSignal
      )
    );
  }

  private async encryptToUserWithOutboxLocked(
    recipientUserId: string,
    plaintextBytes: Uint8Array,
    options: SendOptions & { clientMessageId: string },
    sessions: SendSessionCallbacks | undefined,
    stopSignal: AbortSignal | undefined
  ): Promise<SendResult> {
    const plaintextDigest = CryptoUtils.bytesToBase64(await CryptoUtils.sha256(plaintextBytes));
    const existing = await getOutgoingMessageIntent(this.storage, options.clientMessageId);

    if (existing) {
      if (
        existing.recipientId !== recipientUserId ||
        existing.plaintextDigest !== plaintextDigest ||
        (options.timestamp !== undefined && existing.clientTimestamp !== options.timestamp) ||
        existing.contentHint !== options.contentHint
      ) {
        throw new Error('A clientMessageId cannot identify two different logical sends');
      }
      if (this.declaresDeviceSets() && existing.kind === 'direct') {
        return this.replayDeclaredDirectIntent(existing, plaintextBytes, sessions, stopSignal);
      }
      if (existing.result) return existing.result;
      const reconciled = await this.reconcilePendingDirectIntent(
        existing,
        plaintextBytes,
        sessions
      );
      return this.sendStoredDirectIntent(
        await this.reconcileDirectSyncDevices(reconciled, plaintextBytes, sessions, stopSignal),
        plaintextBytes,
        sessions,
        stopSignal
      );
    }

    const sendFirst = await this.ensureSessionsForUser(recipientUserId, sessions, true);
    const sealedSender = this.relay ? await this.resolveSealedSenderContext(recipientUserId) : null;
    const directSealedSender =
      sealedSender && this.relay?.sendMultiRecipientUnidentified ? sealedSender : null;
    const transportMode = directSealedSender
      ? directSealedSender.config.deliveryMode === 'required'
        ? 'sealed_sender_required'
        : 'sealed_sender_preferred'
      : 'identified';
    if (directSealedSender && directSealedSender.auth.type !== 'accessKey') {
      throw new Error('Direct sealed-sender delivery requires access-key authorization');
    }
    const sealedSenderAuth =
      directSealedSender?.auth.type === 'accessKey' ? { ...directSealedSender.auth } : undefined;

    const clientTimestamp = options.timestamp ?? Date.now();
    const syncPlaintext = this.buildSentSyncTranscript(
      this.getDirectConversationId(recipientUserId),
      plaintextBytes,
      clientTimestamp,
      recipientUserId
    );
    const declared = this.declaresDeviceSets();
    const ownDevices = declared
      ? await this.localOwnDevices()
      : await this.readOwnDeviceList(sessions, stopSignal);
    let batch: OutgoingMessageBatch;
    try {
      batch = await this.sesameManager.send(recipientUserId, plaintextBytes, {
        clientTimestamp,
        includeSyncMessages: false,
      });
      batch.syncMessages.push(
        ...(await this.sesameManager.sendToLocalOtherDevices(syncPlaintext, {
          clientTimestamp,
          includeSyncMessages: false,
          listedDeviceIds: ownDevices.map((device) => device.deviceId),
        }))
      );
    } catch (error) {
      if (error instanceof EncryptionError) throw error;
      throw new EncryptionError(
        'Failed to encrypt message for user',
        EncryptionErrorCode.ENCRYPTION_FAILED,
        { originalError: error as Error, recipientUserId }
      );
    }

    this.logger.debug('Message encrypted for user devices', {
      category: 'E2EE',
      data: {
        recipientUserId,
        deviceCount: batch.deviceMessages.length,
        syncCount: batch.syncMessages.length,
      },
    });

    // Local work: a stop does not end it, so the intent keeps the ciphertext.
    const deviceMessages = await this.fanOut
      .all(batch.deviceMessages, (message) =>
        this.prepareStoredDirectDeviceMessage(message, directSealedSender, options.contentHint)
      )
      .catch((error: unknown) => {
        throw firstItemError(error);
      });

    const syncMessages = await Promise.all(
      batch.syncMessages.map((message) =>
        this.prepareStoredSyncMessage(message, syncMessageId(options.clientMessageId, message))
      )
    );

    const intent: StoredOutgoingMessageIntent = {
      kind: 'direct',
      clientMessageId: options.clientMessageId,
      recipientId: recipientUserId,
      plaintextDigest,
      clientTimestamp,
      createdAt: Date.now(),
      transportMode,
      ...(sealedSenderAuth && { sealedSenderAuth }),
      ...(options.contentHint !== undefined && {
        contentHint: options.contentHint,
      }),
      ...(sendFirst && { reconcilePending: true as const }),
      deviceMessages,
      syncMessages,
    };
    await storeOutgoingMessageIntent(this.storage, intent);
    if (declared) return this.sendDeclaredDirectIntent(intent, plaintextBytes, sessions, stopSignal);
    if (sendFirst && sessions) {
      return this.sendDirectIntentBeforeDeviceListRead(
        intent,
        plaintextBytes,
        sessions,
        stopSignal
      );
    }
    return this.sendStoredDirectIntent(intent, plaintextBytes, sessions, stopSignal);
  }

  /**
   * Post a direct intent to its known devices while the recipient's device
   * list is read, then reconcile the intent with the list and post the rest.
   *
   * The known devices are posted at the same time. A post that the relay
   * refuses because of its device waits for the read, and the read decides it:
   * an unlisted device leaves the intent without a repair, a listed device
   * with STALE_DEVICE is repaired, and a listed device with NOT_FOUND fails
   * the send. A post that has not started when the list arrives waits for the
   * reconcile pass, which starts after the read removes the unlisted device
   * records, so no message goes to a device after the read that shows its
   * removal.
   */
  private async sendDirectIntentBeforeDeviceListRead(
    intent: StoredOutgoingMessageIntent,
    plaintextBytes: Uint8Array,
    sessions: SendSessionCallbacks,
    stopSignal: AbortSignal | undefined
  ): Promise<SendResult> {
    const arrived: { listed?: ReadonlySet<number> } = {};
    const read = this.readRecipientDeviceList(intent.recipientId, sessions, true, (listed) => {
      arrived.listed = listed;
    });
    // Every path below awaits the read. This handler only covers the posts.
    read.catch(() => undefined);

    const posts: DirectIntentPosts = { accepted: new Map(), refused: new Map() };
    const control: DevicePostControl = {
      ...(stopSignal && { stopSignal }),
      admit: () => {
        if (arrived.listed) throw new DeferredPost();
      },
    };
    try {
      await this.sendPhase(
        intent.deviceMessages,
        async (message) => {
          try {
            posts.accepted.set(
              message.recipientDeviceId,
              await this.sendStoredDirectDeviceMessage(intent, message, control)
            );
          } catch (error) {
            if (error instanceof DeferredPost) return;
            if (!isRefusalOfDevice(error, message)) throw error;
            posts.refused.set(message.recipientDeviceId, { error });
          }
        },
        'device',
        stopSignal
      );
    } catch (error) {
      // The read commits sessions. It ends before the send fails.
      await read.catch(() => undefined);
      throw error;
    }

    const list = await read;
    const reconciled = list
      ? await this.reconcileDirectIntent(intent, list, plaintextBytes)
      : intent;
    return this.sendStoredDirectIntent(reconciled, plaintextBytes, sessions, stopSignal, posts);
  }

  /** A replay whose first attempt posted before its read reads and reconciles first. */
  private async reconcilePendingDirectIntent(
    intent: StoredOutgoingMessageIntent,
    plaintextBytes: Uint8Array,
    sessions: SendSessionCallbacks | undefined
  ): Promise<StoredOutgoingMessageIntent> {
    if (!intent.reconcilePending || !sessions || !this.relay) return intent;
    const list = await this.readRecipientDeviceList(
      intent.recipientId,
      sessions,
      await this.hasActiveSession(intent.recipientId)
    );
    return list ? this.reconcileDirectIntent(intent, list, plaintextBytes) : intent;
  }

  /**
   * Apply a device-list read to a direct intent: remove each device that the
   * list does not show, and encrypt the message for each established device
   * that the intent does not address. A new transmission keeps the intent's
   * timestamp, so each device receives the same message.
   */
  private async reconcileDirectIntent(
    intent: StoredOutgoingMessageIntent,
    list: RecipientDeviceList,
    plaintextBytes: Uint8Array
  ): Promise<StoredOutgoingMessageIntent> {
    const removed = intent.deviceMessages
      .map((message) => message.recipientDeviceId)
      .filter((deviceId) => !list.listed.has(deviceId));
    const addressed = new Set(intent.deviceMessages.map((message) => message.recipientDeviceId));
    const added: StoredOutgoingDeviceMessage[] = [];
    let sealedSender: ResolvedSealedSenderContext | null | undefined;
    for (const deviceId of list.established) {
      if (addressed.has(deviceId)) continue;
      let message: SesameMessage;
      try {
        message = await this.sesameManager.sendMessage(intent.recipientId, deviceId, plaintextBytes, {
          clientTimestamp: intent.clientTimestamp,
          includeSyncMessages: false,
        });
      } catch (error) {
        this.logger.warn('Could not encrypt a direct message for a newly listed device', {
          category: 'E2EE',
          error: error as Error,
          data: { recipientUserId: intent.recipientId, deviceId },
        });
        continue;
      }
      if (sealedSender === undefined) {
        sealedSender = await this.resolveStoredDirectSealedSender(intent);
      }
      added.push(
        await this.prepareStoredDirectDeviceMessage(message, sealedSender, intent.contentHint)
      );
    }
    if (removed.length === 0 && added.length === 0) return intent;
    return reconcileOutgoingDirectDeviceMessages(
      this.storage,
      intent.clientMessageId,
      removed,
      added
    );
  }

  /**
   * Apply a read of the sender's own device list to a direct intent on
   * replay: drop the sync copy of each own device that the list does not
   * show, and add a sent transcript of the caller's content for each listed
   * own device that the intent does not address.
   */
  private async reconcileDirectSyncDevices(
    intent: StoredOutgoingMessageIntent,
    plaintextBytes: Uint8Array,
    sessions: SendSessionCallbacks | undefined,
    stopSignal: AbortSignal | undefined
  ): Promise<StoredOutgoingMessageIntent> {
    if (!this.relay) return intent;
    const listed = await this.readOwnDeviceList(sessions, stopSignal);
    const { unlisted, added } = listedOwnDeviceChange(
      intent.syncMessages,
      listed.map((device) => device.deviceId)
    );
    if (unlisted.length === 0 && added.length === 0) return intent;
    const additions = await this.prepareDirectSyncMessages(intent, plaintextBytes, added);
    return reconcileOutgoingSyncMessages(this.storage, intent.clientMessageId, unlisted, additions);
  }

  /**
   * A sent transcript of a stored direct send for each own device in
   * `deviceIds` that has a session.
   */
  private async prepareDirectSyncMessages(
    intent: StoredOutgoingMessageIntent,
    plaintextBytes: Uint8Array,
    deviceIds: readonly number[]
  ): Promise<StoredOutgoingDeviceMessage[]> {
    const transcript = this.buildSentSyncTranscript(
      this.getDirectConversationId(intent.recipientId),
      plaintextBytes,
      intent.clientTimestamp,
      intent.recipientId
    );
    const copies = await this.sesameManager.sendToLocalOtherDevices(transcript, {
      clientTimestamp: intent.clientTimestamp,
      includeSyncMessages: false,
      listedDeviceIds: deviceIds,
    });
    return Promise.all(
      copies.map((message) =>
        this.prepareStoredSyncMessage(message, syncMessageId(intent.clientMessageId, message))
      )
    );
  }

  /** The sealed-sender context of a new transmission for a stored direct intent. */
  private async resolveStoredDirectSealedSender(
    intent: StoredOutgoingMessageIntent
  ): Promise<ResolvedSealedSenderContext | null> {
    if (intent.transportMode === 'identified') return null;
    const sealedSender = await this.resolveSealedSenderContext(intent.recipientId);
    if (!sealedSender || sealedSender.auth.type !== 'accessKey') {
      throw new Error('Cannot build a sealed-sender transmission for a stored direct intent');
    }
    return sealedSender;
  }

  private async prepareStoredDirectDeviceMessage(
    message: import('../internal/sesame/types').SesameMessage,
    sealedSender: ResolvedSealedSenderContext | null,
    contentHint: ContentHint | undefined
  ): Promise<StoredOutgoingDeviceMessage> {
    const messageType = getEnvelopeMessageType(message.ciphertext);
    // Each post names the registration of the current session, so the Relay
    // refuses it when the device was reinstalled.
    const registrationId = await this.sesameManager.getRemoteRegistrationId(
      message.recipientUserId,
      message.recipientDeviceId
    );
    const storedMessage: StoredOutgoingDeviceMessage = {
      recipientUserId: message.recipientUserId,
      recipientDeviceId: message.recipientDeviceId,
      timestamp: message.timestamp,
      ciphertext:
        typeof message.ciphertext === 'string'
          ? message.ciphertext
          : CryptoUtils.bytesToBase64(message.ciphertext),
      messageType,
      ...(registrationId !== undefined && { recipientRegistrationId: registrationId }),
    };
    if (sealedSender) {
      storedMessage.sealedSenderMessage = await this.serializeDirectSealedSenderMessage(
        storedMessage,
        storedMessage.ciphertext,
        storedMessage.messageType,
        storedMessage.recipientRegistrationId,
        sealedSender,
        contentHint
      );
    }
    return storedMessage;
  }

  /**
   * Run the session repair of one recipient in turn. The device posts of a
   * send run at the same time, so the repairs for one recipient take turns:
   * the first session commit with a user pins the user's contact identity,
   * and a concurrent commit that read the store before it fails.
   */
  private inRepairTurn<T>(recipientUserId: string, repair: () => Promise<T>): Promise<T> {
    return this.lock.acquire(`session-repair:${recipientUserId}`, repair);
  }

  /** Refresh the session of a rejected device and replace its transmission. */
  private async repairRejectedDirectDeviceMessage(
    intent: StoredOutgoingMessageIntent,
    rejected: StoredOutgoingDeviceMessage,
    plaintextBytes: Uint8Array,
    sessions: SendSessionCallbacks | undefined
  ): Promise<StoredOutgoingDeviceMessage> {
    if (!sessions) throw new Error('Stale-session refresh is not configured');
    return this.inRepairTurn(rejected.recipientUserId, () =>
      this.repairRejectedDirectDeviceMessageInTurn(intent, rejected, plaintextBytes, sessions)
    );
  }

  private async repairRejectedDirectDeviceMessageInTurn(
    intent: StoredOutgoingMessageIntent,
    rejected: StoredOutgoingDeviceMessage,
    plaintextBytes: Uint8Array,
    sessions: SendSessionCallbacks
  ): Promise<StoredOutgoingDeviceMessage> {
    const refreshed = await sessions.refreshStaleSession(
      rejected.recipientUserId,
      rejected.recipientDeviceId
    );
    if (!refreshed) {
      throw new EncryptionError(
        'Failed to refresh a rejected recipient device',
        EncryptionErrorCode.SESSION_ESTABLISHMENT_FAILED,
        { recipientUserId: rejected.recipientUserId }
      );
    }

    const freshMessage = await this.sesameManager.sendMessage(
      rejected.recipientUserId,
      rejected.recipientDeviceId,
      plaintextBytes,
      { clientTimestamp: intent.clientTimestamp, includeSyncMessages: false }
    );
    const replacement = await this.prepareStoredDirectDeviceMessage(
      freshMessage,
      await this.resolveStoredDirectSealedSender(intent),
      intent.contentHint
    );
    await replaceOutgoingDirectDeviceMessage(
      this.storage,
      intent.clientMessageId,
      rejected,
      replacement
    );
    return replacement;
  }

  private async sendStoredDirectDeviceMessage(
    intent: StoredOutgoingMessageIntent,
    message: StoredOutgoingDeviceMessage,
    control: DevicePostControl
  ): Promise<RelayPostAcceptance> {
    if (
      intent.transportMode !== 'identified' &&
      (!message.sealedSenderMessage || !intent.sealedSenderAuth)
    ) {
      throw new Error('Corrupt sealed-sender outbox intent');
    }
    return intent.transportMode === 'identified'
      ? this.sendToDevice(
          message,
          message.ciphertext,
          message.messageType,
          message.recipientRegistrationId,
          null,
          intent.contentHint,
          intent.clientMessageId,
          undefined,
          control
        )
      : this.sendToDevice(
          message,
          message.ciphertext,
          message.messageType,
          message.recipientRegistrationId,
          null,
          intent.contentHint,
          intent.clientMessageId,
          {
            sentMessageBase64: message.sealedSenderMessage!,
            auth: intent.sealedSenderAuth!,
            deliveryMode:
              intent.transportMode === 'sealed_sender_required' ? 'required' : 'preferred',
          },
          control
        );
  }

  /** Post one device message, and repair its session once if the device rejects it. */
  private async postStoredDirectDeviceMessage(
    intent: StoredOutgoingMessageIntent,
    message: StoredOutgoingDeviceMessage,
    plaintextBytes: Uint8Array,
    sessions: SendSessionCallbacks | undefined,
    control: DevicePostControl,
    refusal?: { error: unknown }
  ): Promise<RelayPostAcceptance> {
    let rejection: unknown;
    if (refusal) {
      rejection = refusal.error;
    } else {
      try {
        return await this.sendStoredDirectDeviceMessage(intent, message, control);
      } catch (error) {
        rejection = error;
      }
    }
    if (!isConclusiveDeviceRejection(rejection)) throw rejection;
    const replacement = await this.repairRejectedDirectDeviceMessage(
      intent,
      message,
      plaintextBytes,
      sessions
    );
    return this.sendStoredDirectDeviceMessage(intent, replacement, control);
  }

  /**
   * Post each device message of a direct intent, then the sync messages, and
   * complete the intent. A device that a send-first pass already posted keeps
   * its result or its refusal.
   */
  private async sendStoredDirectIntent(
    intent: StoredOutgoingMessageIntent,
    plaintextBytes: Uint8Array,
    sessions: SendSessionCallbacks | undefined,
    stopSignal: AbortSignal | undefined,
    posts?: DirectIntentPosts
  ): Promise<SendResult> {
    if (intent.kind !== 'direct') throw new Error('Expected a direct outbox intent');
    if (!this.relay) {
      const result = {
        clientMessageId: intent.clientMessageId,
        messageId: `local-${intent.clientTimestamp}`,
        timestamp: intent.clientTimestamp,
        recipientDeviceCount: intent.deviceMessages.length,
      };
      await completeOutgoingMessageIntent(this.storage, intent.clientMessageId, result);
      return result;
    }

    const relay = this.relay;
    let messageId = `local-${intent.clientTimestamp}`;
    let timestamp = intent.clientTimestamp;
    const control: DevicePostControl = { ...(stopSignal && { stopSignal }) };

    const results = await this.sendPhase(
      intent.deviceMessages,
      async (msg) =>
        posts?.accepted.get(msg.recipientDeviceId) ??
        this.postStoredDirectDeviceMessage(
          intent,
          msg,
          plaintextBytes,
          sessions,
          control,
          posts?.refused.get(msg.recipientDeviceId)
        ),
      'device',
      stopSignal
    );
    for (const result of results) {
      if (messageId.startsWith('local-')) {
        messageId = result.messageId;
        timestamp = result.serverTimestamp;
      }
    }

    // The sync copies start only after every device post settled.
    const syncRepair: SyncCopyRepair = {
      sessions,
      intentId: intent.clientMessageId,
      rebuild: async (deviceId) =>
        (await this.prepareDirectSyncMessages(intent, plaintextBytes, [deviceId]))[0],
    };
    await this.sendPhase(
      intent.syncMessages,
      (message) => this.postSyncMessage(relay, message, control, syncRepair),
      'sync',
      stopSignal
    );

    const result = {
      clientMessageId: intent.clientMessageId,
      messageId,
      timestamp,
      recipientDeviceCount: intent.deviceMessages.length,
      ...aggregateRelayAcceptance(results),
    };
    await completeOutgoingMessageIntent(this.storage, intent.clientMessageId, result);
    return result;
  }

  /** True when the relay compares declared device sets, so each send declares them. */
  private declaresDeviceSets(): boolean {
    return this.relay !== undefined && this.relay !== null && comparesDeviceSets(this.relay);
  }

  /**
   * The own devices other than this device that have a local device record
   * not marked removed.
   */
  private async localOwnDevices(): Promise<GroupMemberDevice[]> {
    const record = await this.sesameManager.getUserRecord(this.userId);
    return unremovedDeviceIds(record)
      .filter((deviceId) => deviceId !== this.deviceId)
      .sort((a, b) => a - b)
      .map((deviceId) => ({ userId: this.userId, deviceId }));
  }

  /**
   * Run one declared phase of a send until the relay accepts every post.
   *
   * Each pass posts every message of the phase, and each post declares every
   * device of its account that the phase addresses. A device that an earlier
   * pass posted gets its stored bytes again. After a refusal, the repair
   * archives and removes each extra device, refreshes the session of each
   * stale device, starts a session with each missing device, and encrypts the
   * message again only for each refreshed or added device. A listed device
   * with no prekey bundle gets no message, so the next pass declares the
   * account without it and the relay refuses the account again. The repair
   * write stores each such device in the intent, so a replay after a restart
   * or a stop starts a session with it before its first post.
   *
   * An account whose stored devices all lack a bundle has no post, so the
   * pass refuses it here. For such an account, a bundle fetch that answers
   * NOT_FOUND removes the device record. Each other device that the record
   * still holds gets a message in the same repair when it has a session or a
   * bundle. An account left with no device record gets one list read.
   *
   * @returns The answers of the last pass and the messages that it posted
   * @throws {DeviceSetReconciliationError} when the phase ends unresolved
   */
  private async runDeclaredPhase<T>(
    run: DeclaredPhaseRun<T>
  ): Promise<{ values: T[]; messages: StoredOutgoingDeviceMessage[] }> {
    // A declared post never names the sender device, so a send to the own
    // account posts only to the other own devices.
    const postable = (list: readonly StoredOutgoingDeviceMessage[]) =>
      list.filter(
        (message) =>
          message.recipientUserId !== this.userId || message.recipientDeviceId !== this.deviceId
      );
    let messages = postable(run.messages);
    let unposted: DeviceSetDevice[] = [...(run.bundleMissing ?? [])];
    // The accounts that the last pass refused here, because they had no post.
    let unpostedAccounts = new Set<string>();
    const posts = await runDeviceSetPhase<T>({
      phase: run.phase,
      clientMessageId: run.clientMessageId,
      restarts: run.restarts,
      pass: async () => {
        const declared = new Map<string, number[]>();
        for (const message of messages) {
          const deviceIds = declared.get(message.recipientUserId) ?? [];
          deviceIds.push(message.recipientDeviceId);
          declared.set(message.recipientUserId, deviceIds);
        }
        for (const deviceIds of declared.values()) deviceIds.sort((a, b) => a - b);
        // An account whose devices all lack a bundle has no post to refuse.
        // It is refused here as missing those devices, so the pass counts.
        const refusedHere = new Map<string, number[]>();
        for (const device of unposted) {
          if (declared.has(device.userId)) continue;
          refusedHere.set(device.userId, [...(refusedHere.get(device.userId) ?? []), device.deviceId]);
        }
        unpostedAccounts = new Set(refusedHere.keys());
        if (messages.length === 0 && refusedHere.size === 0 && run.requirePostTo !== undefined) {
          throw new EncryptionError(
            'The send has no device to post to',
            EncryptionErrorCode.SESSION_NOT_FOUND,
            { recipientUserId: run.requirePostTo }
          );
        }
        const posted = await this.fanOut.all(
          messages,
          async (message): Promise<DeviceSetPost<T>> => {
            const device = {
              userId: message.recipientUserId,
              deviceId: message.recipientDeviceId,
            };
            try {
              const value = await run.post(message, declared.get(message.recipientUserId)!);
              return { device, outcome: { ok: true, value } };
            } catch (error) {
              return { device, outcome: { ok: false, error } };
            }
          },
          run.stopSignal
        );
        const refused = [...refusedHere].map(
          ([userId, missingDeviceIds]): DeviceSetPost<T> => ({
            device: { userId, deviceId: missingDeviceIds[0]! },
            outcome: {
              ok: false,
              error: markDeviceSetRefusal(new Error('No device of the account has a session'), {
                kind: 'mismatch',
                accounts: [{ userId, missingDeviceIds, extraDeviceIds: [] }],
              }),
            },
          })
        );
        return [...posted, ...refused];
      },
      repair: async (repairs, restarts) => {
        const sessions = run.sessions;
        if (!sessions) {
          throw new EncryptionError(
            'Session establishment is not configured',
            EncryptionErrorCode.SESSION_ESTABLISHMENT_FAILED,
            { recipientUserId: repairs[0]?.userId ?? '' }
          );
        }
        const removed: DeviceSetDevice[] = [];
        const added: StoredOutgoingDeviceMessage[] = [];
        const bundleMissing: DeviceSetDevice[] = [];
        const posted = new Map(
          messages.map((message) => [
            declaredDeviceKey({
              userId: message.recipientUserId,
              deviceId: message.recipientDeviceId,
            }),
            message.recipientRegistrationId,
          ])
        );
        for (const repair of repairs) {
          await this.inRepairTurn(repair.userId, async () => {
            const repaired = await this.repairRefusedDevices(sessions, repair, {
              phase: run.phase,
              stopSignal: run.stopSignal,
              postedRegistration: (device) => posted.get(declaredDeviceKey(device)),
              unposted: unpostedAccounts.has(repair.userId),
              ...(run.forget && { forget: run.forget }),
            });
            removed.push(...repaired.removed);
            bundleMissing.push(...repaired.bundleMissing);
            for (const device of repaired.ready) {
              const message = await run.encrypt(device);
              if (message) added.push(message);
              else bundleMissing.push(device);
            }
          });
        }
        if (run.intentId !== undefined) {
          const intent = await repairOutgoingDeviceSet(this.storage, run.intentId, {
            phase: run.phase,
            restarts,
            removed,
            bundleMissing,
            ...(run.phase === 'recipient' ? { deviceMessages: added } : { syncMessages: added }),
          });
          messages = postable(
            run.phase === 'recipient' ? intent.deviceMessages : intent.syncMessages
          );
        } else {
          const gone = new Set(removed.map(declaredDeviceKey));
          messages = [
            ...messages.filter(
              (message) =>
                !gone.has(
                  declaredDeviceKey({
                    userId: message.recipientUserId,
                    deviceId: message.recipientDeviceId,
                  })
                )
            ),
            ...added,
          ];
        }
        unposted = bundleMissing;
        return { bundleMissing };
      },
      unresolve: async (unresolved) => {
        if (run.intentId === undefined) return;
        await markOutgoingDeviceSetUnresolved(
          this.storage,
          run.intentId,
          storedDeviceSetUnresolved(unresolved)
        );
      },
      wait: (milliseconds) => waitUnlessStopped(milliseconds, run.stopSignal),
      logFailure: (device, error) => {
        this.logger.warn('A device post of a send failed', {
          category: 'E2EE',
          error: error as Error,
          data: { phase: run.phase, recipientUserId: device.userId, deviceId: device.deviceId },
        });
      },
    });
    return {
      values: posts.flatMap((post) => (post.outcome.ok ? [post.outcome.value] : [])),
      messages,
    };
  }

  /**
   * Repair the devices of one account that a refusal names. The caller runs
   * it in the repair turn of the account. An extra device loses its session,
   * its handoff rows, and its record. A stale device gets a new session,
   * unless its current session already has a registration other than the
   * one that the refused post named. A missing device gets a session.
   *
   * Only a listed device with no prekey bundle is bundle-missing, and the
   * loop waits for it. Any other failure to start a session, such as an
   * identity that the store does not trust, ends the send with its error.
   *
   * An unposted account is one that the pass refused here, because each of
   * its stored devices lacked a bundle. The Relay answers NOT_FOUND for the
   * bundle of a device that it does not register, and for a registered
   * device that has no uploaded prekeys. Thus such a device of an unposted
   * account loses its record and leaves the send. The repair then starts a
   * session with each other device that the account record still holds. A
   * device that has a session already counts as started, so it gets a
   * message in the same repair turn. When the account holds no device
   * record, the repair reads its device list once and starts a session with
   * each listed device. A device with no bundle is bundle-missing again, and
   * the restart bound stops the loop.
   *
   * @returns The devices that leave the send, the refreshed or added devices
   *   that have a current session, and the devices that got no session
   * @throws The first error of a session start that failed for a reason other
   *   than a missing prekey bundle
   */
  private async repairRefusedDevices(
    sessions: SendSessionCallbacks,
    repair: DeviceSetAccountRepair,
    options: {
      phase: DeviceSetPhase;
      stopSignal: AbortSignal | undefined;
      /** The registration that the refused post named for a device. */
      postedRegistration(device: DeviceSetDevice): number | undefined;
      /** True when the pass refused the account here, because it had no post. */
      unposted: boolean;
      forget?(device: DeviceSetDevice): Promise<void>;
    }
  ): Promise<{
    removed: DeviceSetDevice[];
    ready: DeviceSetDevice[];
    bundleMissing: DeviceSetDevice[];
  }> {
    const { userId } = repair;
    const removed: DeviceSetDevice[] = [];
    const ready: DeviceSetDevice[] = [];
    const bundleMissing: DeviceSetDevice[] = [];
    /**
     * Start sessions with devices that have none. A missing bundle is not an
     * error. A started session clears the removed marker of its record, so
     * the next pass declares the device.
     */
    const establish = async (deviceIds: readonly number[]): Promise<void> => {
      const result = await sessions.establishSessions(
        userId,
        deviceIds.map((deviceId) => ({ userId, deviceId }))
      );
      const failure = result.failedDeviceErrors[0];
      if (failure) throw failure.error;
      const established = new Set(result.establishedDevices);
      for (const deviceId of deviceIds) {
        if (established.has(deviceId)) {
          await this.sesameManager.relistDevice(userId, deviceId);
          ready.push({ userId, deviceId });
        } else {
          bundleMissing.push({ userId, deviceId });
        }
      }
    };
    for (const deviceId of repair.extraDeviceIds) {
      const device = { userId, deviceId };
      await this.archiveDeviceSession(userId, deviceId, options.stopSignal);
      await this.sesameManager.removeDevice(userId, deviceId);
      await options.forget?.(device);
      removed.push(device);
    }
    for (const deviceId of repair.staleDeviceIds) {
      const device = { userId, deviceId };
      removed.push(device);
      await options.forget?.(device);
      // A repair earlier in the send can have refreshed the session already.
      const posted = options.postedRegistration(device);
      const current = await this.sesameManager.getRemoteRegistrationId(userId, deviceId);
      let refreshed = posted !== undefined && current !== undefined && current !== posted;
      if (!refreshed) {
        try {
          refreshed = await sessions.refreshStaleSession(userId, deviceId);
        } catch (error) {
          rethrowRelayWorkStopped(error);
          this.logger.warn('Could not refresh the session of a stale device', {
            category: 'E2EE',
            error: error as Error,
            data: { phase: options.phase, recipientUserId: userId, deviceId },
          });
        }
      }
      if (refreshed) {
        ready.push(device);
      } else {
        // The refresh archived the stale session or found none. A second
        // start tells a missing bundle from a session start that failed.
        await establish([deviceId]);
      }
    }
    if (repair.missingDeviceIds.length > 0) await establish(repair.missingDeviceIds);
    if (options.unposted && bundleMissing.length > 0) {
      for (const device of bundleMissing.splice(0)) {
        await this.sesameManager.removeDevice(userId, device.deviceId);
        await options.forget?.(device);
        removed.push(device);
      }
      const own = (deviceId: number) => userId === this.userId && deviceId === this.deviceId;
      const record = await this.sesameManager.getUserRecord(userId);
      const held = unremovedDeviceIds(record).filter((id) => !own(id));
      const handled = new Set(ready.map((device) => device.deviceId));
      const remainingIds = held.filter((id) => !handled.has(id));
      const relay = this.relay;
      if (remainingIds.length > 0) {
        await establish(remainingIds);
      } else if (relay && held.length === 0) {
        const listed = await this.fanOut.request(
          () => relay.getActiveDevices(userId),
          options.stopSignal
        );
        const deviceIds = listed
          .filter((device) => device.userId === userId && !own(device.deviceId))
          .map((device) => device.deviceId);
        if (deviceIds.length > 0) await establish(deviceIds);
      }
    }
    return { removed, ready, bundleMissing };
  }

  /**
   * Mark a send result whose relay accepted a declared post without the
   * `deviceSetChecked` mark. The send is delivered, and a second post could
   * deliver it twice, so the result does not change. The client reports the
   * error once through `onRelayProtocolError`.
   */
  private markUncheckedDeclaredPosts<T extends object>(
    result: T,
    receipts: readonly DeclaredPostReceipt[],
    clientMessageId: string
  ): T {
    const error = this.uncheckedDeclaredPostError(receipts, clientMessageId);
    return error ? markRelayProtocolError(result, error) : result;
  }

  /**
   * The protocol error of declared posts that the relay accepted without the
   * `deviceSetChecked` mark. The client logs one warning for it.
   */
  private uncheckedDeclaredPostError(
    receipts: readonly DeclaredPostReceipt[],
    clientMessageId: string | undefined
  ): RelayProtocolError | undefined {
    const error = uncheckedDeclaredPost(receipts, clientMessageId);
    if (error) {
      this.logger.warn('The Relay accepted a declared post without comparing its device set', {
        category: 'E2EE',
        data: { code: error.code, route: error.route },
      });
    }
    return error;
  }

  /**
   * Replay a stored direct send on a relay that compares device sets. A
   * terminal send starts a new run at 0 restarts. A completed send with a
   * pending sync phase posts only its sync messages. It first reads the own
   * device list when the send could not read it: the phase has no sync
   * message and stores no own device with no bundle. A stored device with no
   * bundle goes through the sync phase, which refuses it as missing and
   * retries it as the live run does. A send that is not terminal resumes
   * with its stored restart counts.
   */
  private async replayDeclaredDirectIntent(
    existing: StoredOutgoingMessageIntent,
    plaintextBytes: Uint8Array,
    sessions: SendSessionCallbacks | undefined,
    stopSignal: AbortSignal | undefined
  ): Promise<SendResult> {
    const intent = await restartOutgoingDeviceSet(this.storage, existing.clientMessageId);
    const stored = outgoingMessageIntentResult(intent);
    if (!stored) return this.sendDeclaredDirectIntent(intent, plaintextBytes, sessions, stopSignal);
    if (!intent.syncPending) return stored;
    const { syncPending: _pending, ...result } = stored;
    let current = intent;
    if (
      current.syncMessages.length === 0 &&
      (current.deviceSetBundleMissing?.sync ?? []).length === 0
    ) {
      const added = await this.addDeclaredDirectSync(current, plaintextBytes, sessions, stopSignal);
      if (added.unread) return stored;
      current = added.intent;
      if (current.syncMessages.length === 0) {
        await completeOutgoingSyncPhase(this.storage, current.clientMessageId);
        return result;
      }
    }
    const sync = await this.finishDeclaredSync(
      current,
      this.directSyncEncrypt(current, plaintextBytes),
      sessions,
      stopSignal
    );
    return this.markUncheckedDeclaredPosts(
      sync.synced ? result : { ...result, syncPending: true as const },
      syncPostReceipts(sync.accepted),
      current.clientMessageId
    );
  }

  /**
   * Add the sync copies of a direct intent from one read of the own device
   * list. A failed read is logged and does not fail the send.
   *
   * @returns The intent, and true when the read failed
   */
  private async addDeclaredDirectSync(
    intent: StoredOutgoingMessageIntent,
    plaintextBytes: Uint8Array,
    sessions: SendSessionCallbacks | undefined,
    stopSignal: AbortSignal | undefined
  ): Promise<{ intent: StoredOutgoingMessageIntent; unread: boolean }> {
    try {
      const listed = await this.readOwnDeviceList(sessions, stopSignal);
      const additions = await this.prepareDirectSyncMessages(
        intent,
        plaintextBytes,
        listed.map((device) => device.deviceId)
      );
      if (additions.length === 0) return { intent, unread: false };
      return {
        intent: await reconcileOutgoingSyncMessages(
          this.storage,
          intent.clientMessageId,
          [],
          additions
        ),
        unread: false,
      };
    } catch (error) {
      this.logger.warn('Could not read the own device list for the sync phase of a send', {
        category: 'E2EE',
        error: error as Error,
      });
      return { intent, unread: true };
    }
  }

  /**
   * Post a stored direct intent on a relay that compares device sets: the
   * recipient phase first, then the sync phase (§5.4, §5.6). The recipient
   * result is stored before the sync phase starts. A failed sync phase gives
   * `syncPending` and does not fail the send, and the intent keeps the sync
   * messages for a replay.
   */
  private async sendDeclaredDirectIntent(
    intent: StoredOutgoingMessageIntent,
    plaintextBytes: Uint8Array,
    sessions: SendSessionCallbacks | undefined,
    stopSignal: AbortSignal | undefined
  ): Promise<SendResult> {
    const control: DevicePostControl = { ...(stopSignal && { stopSignal }) };
    let sealedSender: ResolvedSealedSenderContext | null | undefined;
    const recipient = await this.runDeclaredPhase<RelayPostAcceptance>({
      phase: 'recipient',
      clientMessageId: intent.clientMessageId,
      intentId: intent.clientMessageId,
      restarts: intent.deviceSetRestarts?.recipient ?? 0,
      messages: intent.deviceMessages,
      bundleMissing: intent.deviceSetBundleMissing?.recipient ?? [],
      ...(intent.recipientId !== this.userId && { requirePostTo: intent.recipientId }),
      post: (message, declaredDeviceIds) =>
        this.sendStoredDirectDeviceMessage(intent, message, { ...control, declaredDeviceIds }),
      encrypt: async (device) => {
        const message = await this.sesameManager.sendMessage(
          device.userId,
          device.deviceId,
          plaintextBytes,
          { clientTimestamp: intent.clientTimestamp, includeSyncMessages: false }
        );
        if (sealedSender === undefined) {
          sealedSender = await this.resolveStoredDirectSealedSender(intent);
        }
        return this.prepareStoredDirectDeviceMessage(message, sealedSender, intent.contentHint);
      },
      sessions,
      stopSignal,
    });

    const accepted = recipient.values;
    let messageId = `local-${intent.clientTimestamp}`;
    let timestamp = intent.clientTimestamp;
    for (const acceptance of accepted) {
      if (messageId.startsWith('local-')) {
        messageId = acceptance.messageId;
        timestamp = acceptance.serverTimestamp;
      }
    }
    const result = {
      clientMessageId: intent.clientMessageId,
      messageId,
      timestamp,
      recipientDeviceCount: recipient.messages.length,
      ...aggregateRelayAcceptance(accepted),
    };

    // The sync phase runs when a recipient receipt sets needsSync or the
    // send holds an own device record. With needsSync and no own record,
    // the send reads the own list once. When that read fails, the sync
    // phase stays pending with no sync messages, and a replay reads it.
    let current =
      (await getOutgoingMessageIntent(this.storage, intent.clientMessageId)) ?? intent;
    let syncUnread = false;
    if (
      current.syncMessages.length === 0 &&
      accepted.some((acceptance) => acceptance.needsSync === true)
    ) {
      const added = await this.addDeclaredDirectSync(current, plaintextBytes, sessions, stopSignal);
      current = added.intent;
      syncUnread = added.unread;
    }
    const syncPhase = current.syncMessages.length > 0;
    await completeOutgoingMessageIntent(this.storage, intent.clientMessageId, result, {
      syncPending: syncPhase || syncUnread,
    });
    const sync: DeclaredSyncOutcome = syncPhase
      ? await this.finishDeclaredSync(
          current,
          this.directSyncEncrypt(current, plaintextBytes),
          sessions,
          stopSignal
        )
      : { synced: true, accepted: [] };
    const route = intent.transportMode === 'identified' ? 'identified-direct' : 'anonymous-direct';
    return this.markUncheckedDeclaredPosts(
      { ...result, ...((!sync.synced || syncUnread) && { syncPending: true as const }) },
      [
        ...accepted.map((acceptance): DeclaredPostReceipt => [acceptance, route]),
        ...syncPostReceipts(sync.accepted),
      ],
      intent.clientMessageId
    );
  }

  /** Encrypt the sync copy of a direct intent again for one own device. */
  private directSyncEncrypt(
    intent: StoredOutgoingMessageIntent,
    plaintextBytes: Uint8Array
  ): (device: DeviceSetDevice) => Promise<StoredOutgoingDeviceMessage | undefined> {
    return async (device) =>
      (await this.prepareDirectSyncMessages(intent, plaintextBytes, [device.deviceId]))[0];
  }

  /**
   * Run the declared sync phase of a completed intent. The phase has its own
   * restart count. A failure or an unresolved end is logged and leaves the
   * phase pending. The outcome keeps the receipt of each accepted sync post,
   * also when the phase fails, so the send reports a receipt without the
   * `deviceSetChecked` mark.
   */
  private async finishDeclaredSync(
    intent: StoredOutgoingMessageIntent,
    encrypt: (device: DeviceSetDevice) => Promise<StoredOutgoingDeviceMessage | undefined>,
    sessions: SendSessionCallbacks | undefined,
    stopSignal: AbortSignal | undefined
  ): Promise<DeclaredSyncOutcome> {
    const relay = this.relay!;
    const control: DevicePostControl = { ...(stopSignal && { stopSignal }) };
    const accepted: RelayPostAcceptance[] = [];
    try {
      await this.runDeclaredPhase<void>({
        phase: 'sync',
        clientMessageId: intent.clientMessageId,
        intentId: intent.clientMessageId,
        restarts: intent.deviceSetRestarts?.sync ?? 0,
        messages: intent.syncMessages,
        bundleMissing: intent.deviceSetBundleMissing?.sync ?? [],
        post: async (message, declaredDeviceIds) => {
          accepted.push(
            await this.postSyncCopy(relay, message, { ...control, declaredDeviceIds })
          );
        },
        encrypt,
        sessions,
        stopSignal,
      });
      await completeOutgoingSyncPhase(this.storage, intent.clientMessageId);
      return { synced: true, accepted };
    } catch (error) {
      this.logger.warn('The sync phase of a send did not complete', {
        category: 'E2EE',
        error: error as Error,
        data: { phase: 'sync' },
      });
      return { synced: false, accepted };
    }
  }

  /**
   * Post a sync payload to the own devices that this device holds records
   * for, on a relay that compares device sets. The posts share one operation
   * ID, so a restart posts the stored bytes of an accepted device again
   * under the same ID. With no own device record, nothing is posted. A sync
   * payload has no send result, so the reporter gives the protocol error of
   * an accepted post without the `deviceSetChecked` mark to the app.
   *
   * @throws {DeviceSetReconciliationError} when the phase ends unresolved
   */
  private async sendDeclaredSyncPayload(payloadBytes: Uint8Array, timestamp: number): Promise<void> {
    const relay = this.relay!;
    const ownDevices = await this.localOwnDevices();
    if (ownDevices.length === 0) return;
    const copies = await this.sesameManager.sendToLocalOtherDevices(payloadBytes, {
      clientTimestamp: timestamp,
      includeSyncMessages: false,
      listedDeviceIds: ownDevices.map((device) => device.deviceId),
    });
    if (copies.length === 0) return;
    const operationId = await CryptoUtils.generateUuidV4();
    const prepare = (message: SesameMessage) =>
      this.prepareStoredSyncMessage(message, syncMessageId(operationId, message));
    const accepted: RelayPostAcceptance[] = [];
    try {
      await this.runDeclaredPhase<void>({
        phase: 'sync',
        clientMessageId: operationId,
        restarts: 0,
        messages: await Promise.all(copies.map(prepare)),
        post: async (message, declaredDeviceIds) => {
          accepted.push(await this.postSyncCopy(relay, message, { declaredDeviceIds }));
        },
        encrypt: async (device) => {
          const [message] = await this.sesameManager.sendToLocalOtherDevices(payloadBytes, {
            clientTimestamp: timestamp,
            includeSyncMessages: false,
            listedDeviceIds: [device.deviceId],
          });
          return message && prepare(message);
        },
        sessions: this.sessionCallbacks,
        stopSignal: undefined,
      });
    } finally {
      // The payload is delivered to each accepted device, also when the
      // phase fails. The app knows no clientMessageId for the payload.
      const error = this.uncheckedDeclaredPostError(syncPostReceipts(accepted), undefined);
      if (error) await this.relayProtocolErrorReporter?.(error);
    }
  }

  private async encryptToGroupWithOutbox(
    actualGroupId: string,
    plaintextBytes: Uint8Array,
    options: SendOptions & { clientMessageId: string },
    sessions: SendSessionCallbacks | undefined,
    stopSignal: AbortSignal | undefined
  ): Promise<SendResult> {
    const control: DevicePostControl = { ...(stopSignal && { stopSignal }) };
    // A send prepared in this attempt keeps its distribution for a repair.
    const repair: PreMessageRepair = { ...(sessions && { sessions }) };
    const declared = this.declaresDeviceSets();
    return sendGroupWithExactOutbox(
      {
        storage: this.storage,
        ...(this.relay && { relay: this.relay }),
        senderUserId: this.userId,
        senderDeviceId: this.deviceId,
        deliveryMode: this.sealedSenderDeliveryMode,
        preparePayload: async (groupId, bytes, sendOptions, readMembers) => {
          const prepared = await this.prepareGroupSenderKeyPayload(
            groupId,
            bytes,
            sendOptions,
            sessions,
            readMembers,
            stopSignal
          );
          if (prepared.distribution) repair.distribution = prepared.distribution;
          return {
            ciphertext: CryptoUtils.bytesToBase64(prepared.ciphertext),
            preMessages: prepared.preMessages,
            ...(prepared.senderKeyDistributionId && {
              senderKeyDistributionId: prepared.senderKeyDistributionId,
            }),
          };
        },
        prepareContent: (groupId, bytes) => this.contentWithGroupContext(groupId, bytes),
        recordSenderKeyHandoff: (groupId, message) =>
          this.recordSenderKeyHandoff(groupId, message),
        resolveMemberDevices: (groupId, sendOptions) =>
          declared
            ? this.localGroupMemberDevices(groupId, sendOptions, stopSignal)
            : this.resolveGroupMemberDevices(groupId, sendOptions, stopSignal),
        prepareSharedMessage: async (groupId, members, ciphertext, contentHint) => {
          if (
            members.length === 0 ||
            this.sealedSenderDeliveryMode === 'disabled' ||
            !this.sealedSenderProvider ||
            !this.endorsementManager ||
            !this.relay?.sendMultiRecipientUnidentified
          ) {
            return undefined;
          }
          const prepared = await prepareGroupSharedMessage({
            storage: this.storage,
            senderKeys: await this.sealedSenderProvider(),
            members,
            encryptedMessageBase64: ciphertext,
            contentHint,
          });
          return prepared
            ? {
                groupId,
                sentMessageBase64: prepared.sentMessageBase64,
                recipientUserIds: prepared.recipientUserIds,
                deliveryMode:
                  this.sealedSenderDeliveryMode === 'required' ? 'required' : 'preferred',
              }
            : undefined;
        },
        prepareDeviceMessage: (member, groupId, ciphertext, timestamp, contentHint) =>
          this.prepareStoredGroupDeviceMessage(member, groupId, ciphertext, timestamp, contentHint),
        resolveOwnDevices: () =>
          declared ? this.localOwnDevices() : this.readOwnDeviceList(sessions, stopSignal),
        prepareSyncMessages: async (groupId, bytes, timestamp, clientMessageId, ownDevices) => {
          if (!this.relay || ownDevices.length === 0) return [];
          const syncPayload = this.buildSentSyncTranscript(groupId, bytes, timestamp);
          const prepared = await this.sesameManager.sendToLocalOtherDevices(syncPayload, {
            clientTimestamp: timestamp,
            includeSyncMessages: false,
            listedDeviceIds: ownDevices.map((device) => device.deviceId),
          });
          return Promise.all(
            prepared.map((message) =>
              this.prepareStoredSyncMessage(message, syncMessageId(clientMessageId, message))
            )
          );
        },
        postSyncMessage: (intent, message, rebuild) =>
          this.postSyncMessage(this.relay!, message, control, {
            sessions: repair.sessions,
            intentId: intent.clientMessageId,
            rebuild,
          }),
        resolveGroupAuthorization: (groupId, recipients) =>
          this.resolveGroupSendAuthorization(groupId, recipients),
        reportIdentifiedFallback: (recipientUserId) =>
          this.reportIdentifiedFallback(recipientUserId),
        refreshPreMessageEndorsements: (groupId, recipientUserIds) =>
          this.refreshPreMessageEndorsements(groupId, recipientUserIds),
        authorizePreMessage: (groupId, message, required) =>
          this.authorizePreMessage(groupId, message, required),
        postPreMessage: (intent, transport, required) =>
          this.postPreMessage(intent, transport, required, repair, control),
        prepareSenderKeyHandoffs: (intent, listed) =>
          this.prepareIntentSenderKeyHandoffs(intent, listed, repair, repair.sessions, stopSignal),
        remoteRegistrationId: (device) =>
          this.sesameManager.getRemoteRegistrationId(device.userId, device.deviceId),
        isConclusiveDeviceRejection: (error) => isConclusiveDeviceRejection(error),
        repairStaleDevice: (intent, message) =>
          this.repairStaleGroupDevice(intent, message, repair, stopSignal),
        sendPreparedSealedDevice: (intent, message, auth, declaredDeviceIds) =>
          this.sendToDevice(
            message,
            message.ciphertext,
            message.messageType,
            message.recipientRegistrationId,
            null,
            undefined,
            intent.clientMessageId,
            {
              sentMessageBase64: message.sealedSenderMessage!,
              auth,
              deliveryMode: message.sealedSenderDeliveryMode ?? 'preferred',
            },
            { ...control, ...(declaredDeviceIds && { declaredDeviceIds }) }
          ),
        prepareEach: (items, task) =>
          this.fanOut.all(items, task).catch((error: unknown) => {
            throw firstItemError(error);
          }),
        sendPhase: (messages, task, phase) => this.sendPhase(messages, task, phase, stopSignal),
        postToRelay: (send, sealed) => this.postToRelay(send, sealed, control),
        ...(declared && {
          deviceSets: this.groupDeviceSetContext(sessions, stopSignal),
        }),
      },
      actualGroupId,
      plaintextBytes,
      options
    );
  }

  /**
   * The declared work of a group send on a relay that compares device sets
   * (§5.5 of the device-set contract).
   */
  private groupDeviceSetContext(
    sessions: SendSessionCallbacks | undefined,
    stopSignal: AbortSignal | undefined
  ): GroupDeviceSetContext {
    return {
      repairDevices: (account, postedRegistration, unposted) => {
        if (!sessions) {
          throw new EncryptionError(
            'Session establishment is not configured',
            EncryptionErrorCode.SESSION_ESTABLISHMENT_FAILED,
            { recipientUserId: account.userId }
          );
        }
        return this.inRepairTurn(account.userId, () =>
          this.repairRefusedDevices(sessions, account, {
            phase: 'recipient',
            stopSignal,
            postedRegistration,
            unposted,
          })
        );
      },
      readOwnDevices: () => this.readOwnDeviceList(sessions, stopSignal),
      runSyncPhase: (intent, rebuild) =>
        this.finishDeclaredSync(intent, rebuild, sessions, stopSignal),
      unresolve: async (clientMessageId, unresolved) => {
        await markOutgoingDeviceSetUnresolved(
          this.storage,
          clientMessageId,
          storedDeviceSetUnresolved(unresolved)
        );
      },
      wait: (milliseconds) => waitUnlessStopped(milliseconds, stopSignal),
      logFailure: (device, error) => {
        this.logger.warn('A device post of a send failed', {
          category: 'E2EE',
          error: error as Error,
          data: { phase: 'recipient', recipientUserId: device.userId, deviceId: device.deviceId },
        });
      },
      warn: (message, error) => {
        this.logger.warn(message, { category: 'E2EE', error: error as Error });
      },
      markUnchecked: (result, receipts, clientMessageId) =>
        this.markUncheckedDeclaredPosts(result, receipts, clientMessageId),
    };
  }

  /**
   * The devices of the group members on a relay that compares device sets.
   * Each member with a local device record gives the devices of that record,
   * and the sender device is left out. Only another member with no record
   * has its device list read (§5.2 of the device-set contract).
   */
  private async localGroupMemberDevices(
    groupId: string,
    options: SendOptions | undefined,
    stopSignal: AbortSignal | undefined
  ): Promise<GroupMemberDevice[]> {
    const memberUserIds = options?.groupMemberUserIds ?? [];
    if (memberUserIds.length === 0) {
      return this.resolveGroupMemberDevices(groupId, options, stopSignal);
    }
    const local = await Promise.all(
      memberUserIds.map(async (userId) => {
        const record = await this.sesameManager.getUserRecord(userId);
        const held = unremovedDeviceIds(record);
        const deviceIds = held
          .filter((deviceId) => userId !== this.userId || deviceId !== this.deviceId)
          .sort((a, b) => a - b);
        // The own account is never read here. The send leaves it out of the
        // members, and the sync phase reads the own list only on needsSync.
        const own = userId === this.userId;
        return { userId, deviceIds, known: own || held.length > 0 };
      })
    );
    const unknown = local.filter((member) => !member.known).map((member) => member.userId);
    const listed =
      unknown.length > 0
        ? await this.resolveGroupMemberDevices(
            groupId,
            { ...options, groupMemberUserIds: unknown },
            stopSignal
          )
        : [];
    return [
      ...local.flatMap((member) =>
        member.deviceIds.map((deviceId) => ({ userId: member.userId, deviceId }))
      ),
      ...listed,
    ];
  }

  private async prepareStoredGroupDeviceMessage(
    member: GroupMemberDevice,
    groupId: string,
    ciphertext: string,
    timestamp: number,
    contentHint: ContentHint | undefined
  ): Promise<StoredOutgoingDeviceMessage> {
    const stored: StoredOutgoingDeviceMessage = {
      recipientUserId: member.userId,
      recipientDeviceId: member.deviceId,
      timestamp,
      ciphertext,
      messageType: 'sender_key',
    };
    // The post names the registration of the current session, so the Relay
    // refuses it when the device was reinstalled.
    const registrationId = await this.sesameManager.getRemoteRegistrationId(
      member.userId,
      member.deviceId
    );
    if (registrationId !== undefined) stored.recipientRegistrationId = registrationId;
    const sealedSender = await this.resolveSealedSenderContext(member.userId, groupId);
    if (!sealedSender || !this.relay?.sendMultiRecipientUnidentified) return stored;
    return this.sealStoredDeviceMessage(
      stored,
      sealedSender,
      sealedSender.config.deliveryMode === 'required' ? 'required' : 'preferred',
      contentHint
    );
  }

  /** A copy of a stored device message with the sealed transport of its ciphertext. */
  private async sealStoredDeviceMessage(
    message: StoredOutgoingDeviceMessage,
    sealedSender: ResolvedSealedSenderContext,
    deliveryMode: 'preferred' | 'required',
    contentHint?: ContentHint
  ): Promise<StoredOutgoingDeviceMessage> {
    const sealed: StoredOutgoingDeviceMessage = { ...message };
    sealed.sealedSenderMessage = await this.serializeDirectSealedSenderMessage(
      message,
      message.ciphertext,
      message.messageType,
      message.recipientRegistrationId,
      sealedSender,
      contentHint
    );
    sealed.sealedSenderDeliveryMode = deliveryMode;
    if (sealedSender.auth.type === 'accessKey') {
      sealed.sealedSenderAuthorization = 'access_key';
      sealed.sealedSenderAccessKey = sealedSender.auth.unidentifiedAccessKey;
    } else {
      sealed.sealedSenderAuthorization = 'group_send_token';
    }
    return sealed;
  }

  /**
   * The sealed-sender context of a sender-key pre-message. A pre-message goes
   * to one recipient, so the recipient's access key comes first, and the
   * group endorsement serves a member with no access key. Resolves to null
   * when the pre-message goes identified, and throws SEALED_SENDER_REQUIRED
   * in required mode when neither authorization resolves.
   */
  private async resolveDistributionSealedSender(
    recipientUserId: string,
    groupId: string
  ): Promise<ResolvedSealedSenderContext | null> {
    try {
      const accessKey = await this.resolveSealedSenderContext(recipientUserId);
      if (accessKey) return accessKey;
    } catch (error) {
      if (
        !(error instanceof EncryptionError) ||
        error.code !== EncryptionErrorCode.SEALED_SENDER_REQUIRED
      ) {
        throw error;
      }
    }
    return this.resolveSealedSenderContext(recipientUserId, groupId);
  }

  /**
   * The transport of one stored pre-message for this dispatch. The
   * authorization resolves again at each dispatch, so a required send checks
   * its privacy before any post. A pre-message that has no sealed transport
   * is sealed from its stored ciphertext, with no new ratchet effect.
   */
  private async authorizePreMessage(
    groupId: string,
    message: StoredOutgoingDeviceMessage,
    required: boolean
  ): Promise<PreMessageTransport> {
    const sealedSender = await this.resolveDistributionSealedSender(
      message.recipientUserId,
      groupId
    );
    if (!sealedSender || !this.relay?.sendMultiRecipientUnidentified) {
      if (required) {
        throw new EncryptionError(
          'Required group sealed-sender authorization is unavailable',
          EncryptionErrorCode.SEALED_SENDER_REQUIRED,
          { recipientUserId: message.recipientUserId, groupId }
        );
      }
      return { message };
    }
    return {
      message: message.sealedSenderMessage
        ? message
        : await this.sealStoredDeviceMessage(
            message,
            sealedSender,
            required ? 'required' : 'preferred'
          ),
      auth: sealedSender.auth,
    };
  }

  /**
   * Post one pre-message once, sealed when its transport has an
   * authorization. The relay can reject an access key that the client
   * guessed, for a recipient whose access mode it never learned. The
   * rejection restricts the cached mode, and the post goes again with the
   * group endorsement. A preferred post goes identified only when no sealed
   * authorization is accepted. A required post fails then.
   */
  private async sendPreMessage(
    intent: StoredOutgoingMessageIntent,
    { message, auth }: PreMessageTransport,
    required: boolean,
    control: DevicePostControl
  ): Promise<RelayPostAcceptance> {
    if (auth?.type !== 'accessKey' || !message.sealedSenderMessage) {
      return this.postStoredPreMessage(intent, message, auth, required, control);
    }
    let rejection: SealedSenderAuthError;
    try {
      return await this.postStoredPreMessage(intent, message, auth, true, control);
    } catch (error) {
      if (!(error instanceof SealedSenderAuthError)) throw error;
      rejection = error;
    }
    await this.restrictUnidentifiedAccessMode(message.recipientUserId);
    // The rejected post started, so the next post continues it.
    const continued: DevicePostControl = {
      ...(control.stopSignal && { stopSignal: control.stopSignal }),
      ...(control.operationEpochMilliseconds !== undefined && {
        operationEpochMilliseconds: control.operationEpochMilliseconds,
      }),
    };
    const endorsement = await this.resolveDistributionEndorsement(
      message.recipientUserId,
      intent.recipientId
    );
    if (endorsement) {
      try {
        return await this.postStoredPreMessage(intent, message, endorsement, true, continued);
      } catch (error) {
        if (!(error instanceof SealedSenderAuthError)) throw error;
        rejection = error;
      }
    }
    if (required) throw rejection;
    await this.reportIdentifiedFallback(message.recipientUserId);
    return this.postStoredPreMessage(intent, message, undefined, false, continued);
  }

  /**
   * The group endorsement of one pre-message recipient, or null when the
   * group has none for the recipient.
   */
  private async resolveDistributionEndorsement(
    recipientUserId: string,
    groupId: string
  ): Promise<Extract<SealedSenderAuth, { type: 'groupSendToken' }> | null> {
    let context: ResolvedSealedSenderContext | null;
    try {
      context = await this.resolveSealedSenderContext(recipientUserId, groupId);
    } catch (error) {
      if (
        error instanceof EncryptionError &&
        error.code === EncryptionErrorCode.SEALED_SENDER_REQUIRED
      ) {
        return null;
      }
      throw error;
    }
    return context?.auth.type === 'groupSendToken' ? context.auth : null;
  }

  /** One relay post of a stored pre-message, sealed when `auth` is given. */
  private postStoredPreMessage(
    intent: StoredOutgoingMessageIntent,
    message: StoredOutgoingDeviceMessage,
    auth: SealedSenderAuth | undefined,
    required: boolean,
    control: DevicePostControl
  ): Promise<RelayPostAcceptance> {
    return this.sendToDevice(
      message,
      message.ciphertext,
      message.messageType,
      message.recipientRegistrationId,
      null,
      undefined,
      intent.clientMessageId,
      auth && message.sealedSenderMessage
        ? {
            sentMessageBase64: message.sealedSenderMessage,
            auth,
            deliveryMode: required ? 'required' : 'preferred',
          }
        : undefined,
      { ...control, deliveryClass: 'background-sync' }
    );
  }

  /**
   * Post one pre-message, and repair its session once if the device refuses
   * it conclusively. A NOT_FOUND refusal of a device that the recipient's
   * device list no longer shows drops the pre-message, as a direct send
   * drops a removed device. A replay whose sender key rotated since the send
   * refreshes the session and drops the pre-message, because it has no
   * distribution of the key of the send. Resolves to the pre-message that the
   * relay accepted or that the send dropped, with the outcome.
   */
  private async postPreMessage(
    intent: StoredOutgoingMessageIntent,
    transport: PreMessageTransport,
    required: boolean,
    repair: PreMessageRepair,
    control: DevicePostControl
  ): Promise<PreMessagePostResult> {
    try {
      await this.sendPreMessage(intent, transport, required, control);
      return { message: transport.message, outcome: 'accepted' };
    } catch (error) {
      if (await this.isRemovedDeviceRefusal(error, transport.message, control)) {
        return { message: transport.message, outcome: 'removed' };
      }
      if (!isConclusiveDeviceRejection(error)) throw error;
    }
    if (!repair.sessions) throw new Error('Stale-session refresh is not configured');
    const sessions = repair.sessions;
    const repaired = await this.inRepairTurn(transport.message.recipientUserId, () =>
      this.repairRejectedPreMessageInTurn(intent, transport.message, required, repair, sessions)
    );
    if (!repaired) return { message: transport.message, outcome: 'dropped', refreshed: true };
    try {
      await this.sendPreMessage(intent, repaired, required, control);
    } catch (error) {
      if (!(await this.isRemovedDeviceRefusal(error, repaired.message, control))) throw error;
      return { message: repaired.message, outcome: 'removed' };
    }
    return { message: repaired.message, outcome: 'accepted', refreshed: true };
  }

  /**
   * Delete the sender-key handoff rows of one device in one group, so the
   * next send gives the current key to that device. True when a row was
   * deleted. The caller runs it in the sender-key turn of the group.
   */
  invalidateSenderKeyHandoff(groupId: string, device: SenderKeyHandoffDevice): Promise<boolean> {
    return this.senderKeyHandoffs.invalidate(groupId, device);
  }

  /**
   * Delete the sender-key handoff rows of every device of one account in
   * every group. True when a row was deleted.
   */
  invalidateAccountSenderKeyHandoffs(userId: string): Promise<boolean> {
    return this.senderKeyHandoffs.invalidateAccount(userId);
  }

  /**
   * Delete the sender-key handoff rows that no current own key covers: every
   * row of a group with no own sender key, and each row whose senderKeyId is
   * not the current one. Each group runs in its own sender-key turn.
   *
   * @returns The count of deleted rows.
   */
  sweepSenderKeyHandoffs(): Promise<number> {
    return this.senderKeyHandoffs.sweep({
      currentSenderKeyId: async (groupId) =>
        (
          await this.senderKeyManager.getCurrentSenderKeyDistribution(
            groupId,
            this.userId,
            this.deviceId
          )
        )?.senderKeyId ?? null,
      inTurn: (groupId, task) => this.groupSenderKeys.run(groupId, () => task()),
    });
  }

  /**
   * Record the handoff row of a pre-message that the Relay accepted. A
   * pre-message with no handoff key or no registration ID, as an intent from
   * an earlier SDK version stores it, records no row, so the next send gives
   * the key again.
   */
  private async recordSenderKeyHandoff(
    groupId: string,
    message: StoredOutgoingDeviceMessage
  ): Promise<void> {
    if (!message.senderKeyHandoff || message.recipientRegistrationId === undefined) return;
    await this.senderKeyHandoffs.record(
      groupId,
      message.senderKeyHandoff,
      { userId: message.recipientUserId, deviceId: message.recipientDeviceId },
      message.recipientRegistrationId
    );
  }

  /**
   * True when the relay refused this pre-message with NOT_FOUND and the
   * recipient's device list no longer shows the device. A device that the
   * list still shows keeps the refusal as a failure.
   */
  private async isRemovedDeviceRefusal(
    error: unknown,
    message: StoredOutgoingDeviceMessage,
    control: DevicePostControl
  ): Promise<boolean> {
    if (relayDeviceRefusal(error)?.code !== 'NOT_FOUND' || !isRefusalOfDevice(error, message)) {
      return false;
    }
    const listed = await this.fanOut.request(
      () => this.relay!.getActiveDevices(message.recipientUserId),
      control.stopSignal
    );
    if (listed.some(({ deviceId }) => deviceId === message.recipientDeviceId)) return false;
    this.logger.info('Dropped the sender-key pre-message of a removed device', {
      category: 'E2EE',
      data: {
        recipientUserId: message.recipientUserId,
        recipientDeviceId: message.recipientDeviceId,
      },
    });
    return true;
  }

  /**
   * Refresh the session of a device that refused a pre-message, encrypt the
   * distribution again, and replace the stored pre-message before its post.
   * The saved refused ciphertext is never posted again. Resolves to
   * undefined when a replay has no distribution of the key of the send.
   */
  private async repairRejectedPreMessageInTurn(
    intent: StoredOutgoingMessageIntent,
    rejected: StoredOutgoingDeviceMessage,
    required: boolean,
    repair: PreMessageRepair,
    sessions: SendSessionCallbacks
  ): Promise<PreMessageTransport | undefined> {
    const refreshed = await sessions.refreshStaleSession(
      rejected.recipientUserId,
      rejected.recipientDeviceId
    );
    if (!refreshed) {
      throw new EncryptionError(
        'Failed to refresh a rejected recipient device',
        EncryptionErrorCode.SESSION_ESTABLISHMENT_FAILED,
        { recipientUserId: rejected.recipientUserId }
      );
    }

    const distribution = repair.distribution ?? (await this.currentDistribution(intent));
    if (!distribution) return undefined;
    const freshMessage = await this.sesameManager.sendMessage(
      rejected.recipientUserId,
      rejected.recipientDeviceId,
      distribution.bytes(),
      { clientTimestamp: intent.clientTimestamp, includeSyncMessages: false }
    );
    const fresh = await this.prepareStoredDirectDeviceMessage(freshMessage, null, undefined);
    fresh.clientMessageId = repairMessageId(rejected.clientMessageId ?? intent.clientMessageId);
    const registrationId = await this.sesameManager.getRemoteRegistrationId(
      rejected.recipientUserId,
      rejected.recipientDeviceId
    );
    if (registrationId !== undefined) fresh.recipientRegistrationId = registrationId;
    if (rejected.senderKeyHandoff) fresh.senderKeyHandoff = rejected.senderKeyHandoff;
    const transport = await this.authorizePreMessage(intent.recipientId, fresh, required);
    await replaceOutgoingGroupPreMessages(this.storage, intent.clientMessageId, [
      { expected: rejected, replacement: transport.message },
    ]);
    return transport;
  }

  /**
   * The distribution of a replayed send. The attempt that prepared the send
   * kept its distribution in memory only, because the outbox is not
   * encrypted and must hold no chain key. A replay rebuilds the distribution
   * from the current sender key. Its chain index is past the group message
   * of the send, so a device that installs it decrypts the later group
   * messages of the sender, but not this one. Resolves to undefined when the
   * current sender key is not the key of the send: a rotation since the
   * send deleted the handoff rows of the group, and the next send gives the
   * current key to each device.
   */
  private async currentDistribution(
    intent: StoredOutgoingMessageIntent
  ): Promise<SenderKeyHandoffDistribution | undefined> {
    const groupId = intent.recipientId;
    const current = await this.senderKeyManager.getCurrentSenderKeyDistribution(
      groupId,
      this.userId,
      this.deviceId
    );
    if (!current || current.senderKeyId !== intent.groupSenderKeyDistributionId) {
      this.logger.info('The sender key of a replayed group send is no longer current', {
        category: 'E2EE',
        data: { groupId, behavior: 'REPLAY_SENDER_KEY_ROTATED' },
      });
      return undefined;
    }
    return {
      key: { senderKeyId: current.senderKeyId, generation: current.generation },
      bytes: () => this.serializeSenderKeyDistribution(groupId, current),
    };
  }

  /**
   * The sender-key pre-messages that give the key of a stored group send to
   * the listed devices of other members that need it. The attempt that
   * prepared the send gives the distribution at the chain index of its group
   * message. A replay gives the current distribution when the current key is
   * still the key of the send. When the key rotated, a replay gives no
   * pre-message. The added devices recover through a retry request, and the
   * next send gives them the current key. `listed` holds only the devices
   * that can get a pre-message, as `GroupOutboxContext.prepareSenderKeyHandoffs`
   * states. A device that a stored pre-message of the intent targets gets no
   * second one. Each pre-message gets a new transport identity.
   */
  private async prepareIntentSenderKeyHandoffs(
    intent: StoredOutgoingMessageIntent,
    listed: readonly GroupMemberDevice[],
    repair: PreMessageRepair,
    sessions: SendSessionCallbacks | undefined,
    stopSignal: AbortSignal | undefined
  ): Promise<StoredOutgoingDeviceMessage[]> {
    const otherMembers = listed.filter((member) => member.userId !== this.userId);
    if (otherMembers.length === 0) return [];
    const distribution = repair.distribution ?? (await this.currentDistribution(intent));
    if (!distribution) return [];
    const preMessages = await this.prepareSenderKeyHandoffMessages(
      intent.recipientId,
      otherMembers,
      distribution.key,
      distribution.bytes,
      intent.clientTimestamp,
      sessions,
      stopSignal,
      intent.preMessages ?? []
    );
    for (const message of preMessages) {
      const handoffId = await CryptoUtils.generateUuidV4();
      message.clientMessageId = `${intent.clientMessageId}:sender-key-distribution:${handoffId}`;
    }
    return preMessages;
  }

  /**
   * Repair a group device post that the Relay refused as a stale device. When
   * the session still has the refused registration, the repair refreshes the
   * session, and the archive deletes the handoff rows of the device. When an
   * earlier repair of this attempt already refreshed it, the session stays.
   * Then the device gets the key of the send when it has no row, and a new
   * device message with the registration of the current session.
   */
  private async repairStaleGroupDevice(
    intent: StoredOutgoingMessageIntent,
    refused: StoredOutgoingDeviceMessage,
    repair: PreMessageRepair,
    stopSignal: AbortSignal | undefined
  ): Promise<{
    preMessages: StoredOutgoingDeviceMessage[];
    deviceMessage: StoredOutgoingDeviceMessage;
  }> {
    const groupCiphertext = intent.groupCiphertext;
    if (!groupCiphertext) throw new Error('Corrupt group outbox intent');
    const sessions = repair.sessions;
    if (!sessions) throw new Error('Stale-session refresh is not configured');
    const device = { userId: refused.recipientUserId, deviceId: refused.recipientDeviceId };
    return this.inRepairTurn(device.userId, async () => {
      const current = await this.sesameManager.getRemoteRegistrationId(
        device.userId,
        device.deviceId
      );
      if (current === undefined || current === refused.recipientRegistrationId) {
        const refreshed = await sessions.refreshStaleSession(device.userId, device.deviceId);
        if (!refreshed) {
          throw new EncryptionError(
            'Failed to refresh a rejected recipient device',
            EncryptionErrorCode.SESSION_ESTABLISHMENT_FAILED,
            { recipientUserId: device.userId }
          );
        }
      }
      // The device has a session now, so the preparation reads no device
      // list and needs no session callbacks.
      const preMessages = await this.prepareIntentSenderKeyHandoffs(
        intent,
        [device],
        repair,
        undefined,
        stopSignal
      );
      const deviceMessage = await this.prepareStoredGroupDeviceMessage(
        device,
        intent.recipientId,
        groupCiphertext,
        intent.clientTimestamp,
        intent.contentHint
      );
      return { preMessages, deviceMessage };
    });
  }

  /** The plaintext bytes of a sender-key distribution pre-message. */
  private serializeSenderKeyDistribution(
    groupId: string,
    distributionMessage: SenderKeyDistributionMessage
  ): Uint8Array {
    return this.contentAdapter
      ? this.contentAdapter.serializeSenderKeyDistributionBytes(groupId, distributionMessage)
      : new TextEncoder().encode(
          JSON.stringify({
            senderKeyDistributionMessage: JSON.stringify({
              groupId,
              ...distributionMessage,
            }),
          })
        );
  }

  /**
   * Refresh the group's endorsements when the cache lacks one of the
   * recipients or expires soon. Resolves to the endorsement manager, or to
   * null when the client has none.
   */
  private async refreshGroupSendEndorsements(
    groupId: string,
    recipientUserIds: string[]
  ): Promise<EndorsementManager | null> {
    const manager = this.endorsementManagerResolver ? await this.endorsementManagerResolver() : this.endorsementManager;
    if (!manager || recipientUserIds.length === 0) return null;
    // The device posts of a send run at the same time. The lock makes them
    // check and refresh the group's endorsements one at a time, so one
    // refresh serves them all. The lock is taken before a slot.
    await this.lock.acquire(`group-send-endorsements:${groupId}`, async () => {
      const { needsRefresh, reason } = await manager.shouldRefreshEndorsements(
        groupId,
        recipientUserIds
      );
      if (needsRefresh && this.endorsementRefresher) {
        await this.endorsementRefresher(groupId, recipientUserIds);
        this.logger.debug('Refreshed endorsements before durable group send', {
          category: 'E2EE',
          data: { groupId, reason },
        });
      }
    });
    return manager;
  }

  /**
   * Refresh the endorsements of a send's pre-messages before their
   * authorization resolves. A membership change clears the endorsements, and
   * a pre-message to a member with no access key needs one to stay sealed.
   * The refresh takes every recipient at once, so the group message reuses
   * it. It runs only when the send can seal a post with an endorsement.
   */
  private async refreshPreMessageEndorsements(
    groupId: string,
    recipientUserIds: string[]
  ): Promise<void> {
    if (
      this.sealedSenderDeliveryMode === 'disabled' ||
      !this.sealedSenderProvider ||
      !this.relay?.sendMultiRecipientUnidentified
    ) {
      return;
    }
    await this.refreshGroupSendEndorsements(groupId, recipientUserIds);
  }

  private async resolveGroupSendAuthorization(
    groupId: string,
    recipientUserIds: string[]
  ): Promise<Extract<SealedSenderAuth, { type: 'groupSendToken' }> | null> {
    const manager = await this.refreshGroupSendEndorsements(groupId, recipientUserIds);
    if (!manager) return null;
    const groupSecretParams = this.groupSecretParamsProvider
      ? await this.groupSecretParamsProvider(groupId)
      : null;
    const combined = await manager.getCombinedToken(
      groupId,
      recipientUserIds,
      groupSecretParams ?? undefined
    );
    return combined
      ? {
          type: 'groupSendToken',
          groupSendToken: combined.token,
          recipientAciBytes: combined.aciBytesByUserId,
        }
      : null;
  }

  private async serializeDirectSealedSenderMessage(
    msg: {
      recipientUserId: string;
      recipientDeviceId: number;
    },
    ciphertextBase64: string,
    messageType: 'prekey_bundle' | 'ciphertext' | 'sender_key' | 'retry_request',
    recipientRegistrationId: number | undefined,
    sealedSender: ResolvedSealedSenderContext,
    contentHint: ContentHint | undefined
  ): Promise<string> {
    return serializeDirectSealedSenderTransport(
      msg,
      ciphertextBase64,
      messageType,
      recipientRegistrationId,
      sealedSender,
      contentHint
    );
  }

  /**
   * Resolve sealed sender context for a recipient.
   *
   * Authorization priority:
   * 1. GroupSend endorsement token (for group messages when endorsementManager is set)
   * 2. Per-contact mode-based UAK (existing path)
   *
   * Mode-aware selection for priority 2:
   *
   * | Mode         | Behavior                                                       |
   * |--------------|----------------------------------------------------------------|
   * | DISABLED     | Return null immediately (skip sealed sender)                   |
   * | UNRESTRICTED | Use zeroed 16-byte key (no profile key needed)                 |
   * | ENABLED      | Derive UAK from profile key; return null if no profile key     |
   * | UNKNOWN      | Use derived UAK if profile key available, else use zeroed key  |
   *
   * Returns null if sealed sender is not enabled or recipient identity is not known.
   * Pre-fetches the sender certificate and identity keys so they can be reused
   * across all device messages in a send batch.
   *
   * @param recipientUserId - User ID of the message recipient
   * @param groupId - Optional group ID. When provided, endorsement-based auth is attempted first
   *
   */
  private async resolveSealedSenderContext(
    recipientUserId: string,
    groupId?: string
  ): Promise<ResolvedSealedSenderContext | null> {
    const manager = groupId && this.endorsementManagerResolver ? await this.endorsementManagerResolver() : this.endorsementManager;
    return resolveSealedSenderSendContext(
      {
        storage: this.storage,
        deliveryMode: this.sealedSenderDeliveryMode,
        relaySupportsUnidentified: Boolean(this.relay?.sendMultiRecipientUnidentified),
        ...(this.sealedSenderProvider && {
          provider: this.sealedSenderProvider,
        }),
        ...(this.contactProfileStateStore && {
          contactProfileStateStore: this.contactProfileStateStore,
        }),
        ...(manager && {
          endorsementManager: manager,
        }),
        ...(this.groupSecretParamsProvider && {
          groupSecretParamsProvider: this.groupSecretParamsProvider,
        }),
        logger: this.logger,
        useIdentifiedDeliveryOrThrow: (userId, reason) =>
          this.useIdentifiedDeliveryOrThrow(userId, reason),
      },
      recipientUserId,
      groupId
    );
  }

  /**
   * Seal an encrypted delivery receipt for anonymous delivery. A receipt
   * follows the sealed sender delivery mode of a message. Resolves to
   * undefined when the receipt goes identified: sealed sender is disabled,
   * or it is preferred and the relay has no anonymous delivery or this
   * client knows no access key of the recipient. In `'required'` mode a
   * receipt that cannot be sealed throws `SEALED_SENDER_REQUIRED`, and the
   * sealed receipt permits no identified fallback. A receipt never uses a
   * group send endorsement.
   */
  async sealReceipt(
    recipientUserId: string,
    recipientDeviceId: number,
    ciphertextBase64: string
  ): Promise<SealedReceipt | undefined> {
    return this.sealWithAccessKey(recipientUserId, recipientDeviceId, ciphertextBase64, 'ciphertext');
  }

  /**
   * Seal a retry request for anonymous delivery. The seal holds the payload
   * of the identified envelope as `PLAINTEXT_CONTENT`, and the certificate in
   * the seal names the requester. A retry request follows the sealed sender
   * delivery mode, as a receipt does. Resolves to undefined when the request
   * goes identified: sealed sender is disabled, or it is preferred and the
   * relay has no anonymous delivery or this client knows no access key of
   * the recipient. In `'required'` mode a request that cannot be sealed
   * throws `SEALED_SENDER_REQUIRED`, and the sealed request permits no
   * identified fallback. A retry request never uses a group send
   * endorsement.
   */
  async sealRetryRequest(
    recipientUserId: string,
    recipientDeviceId: number,
    payloadBase64: string
  ): Promise<SealedReceipt | undefined> {
    return this.sealWithAccessKey(recipientUserId, recipientDeviceId, payloadBase64, 'retry_request');
  }

  /**
   * The registration ID of the current session with one device. A receipt
   * and a retry request name it, in the sealed body and on the identified
   * envelope, so the Relay refuses the post to a reinstalled device.
   * Undefined when this client has no session with the device.
   */
  recipientRegistrationId(userId: string, deviceId: number): Promise<number | undefined> {
    return this.sesameManager.getRemoteRegistrationId(userId, deviceId);
  }

  /**
   * Seal one direct control envelope under the access key of its recipient.
   * The body names the registration of the current session with the device.
   */
  private async sealWithAccessKey(
    recipientUserId: string,
    recipientDeviceId: number,
    contentBase64: string,
    messageType: 'ciphertext' | 'retry_request'
  ): Promise<SealedReceipt | undefined> {
    // The resolver returns null, or throws in required mode, when the relay
    // has no anonymous delivery. Without a group ID it never uses an
    // endorsement.
    const sealedSender = await this.resolveSealedSenderContext(recipientUserId);
    if (!sealedSender) return undefined;
    if (sealedSender.auth.type !== 'accessKey') {
      // A direct context carries an access key. This guards the type.
      const what = messageType === 'retry_request' ? 'retry request' : 'receipt';
      this.useIdentifiedDeliveryOrThrow(recipientUserId, `${what} needs an access key`);
      return undefined;
    }
    return {
      sentMessageBase64: await this.serializeDirectSealedSenderMessage(
        { recipientUserId, recipientDeviceId },
        contentBase64,
        messageType,
        await this.recipientRegistrationId(recipientUserId, recipientDeviceId),
        sealedSender,
        ContentHint.Implicit
      ),
      auth: sealedSender.auth,
      identifiedFallback: sealedSender.config.deliveryMode !== 'required',
    };
  }

  /**
   * Send a single ciphertext to a device, optionally wrapping with sealed sender.
   *
   * When sealed sender context is available:
   * 1. Wraps the ciphertext with the multi-recipient format for one recipient
   * 2. Uses relay.sendMultiRecipientUnidentified() for anonymous delivery
   *
   * On sealed sender auth failure, transitions the recipient's
   * UnidentifiedAccessMode before falling back to identified delivery:
   *
   * | Current Mode   | -> New Mode | Rationale                        |
   * |----------------|-------------|----------------------------------|
   * | UNRESTRICTED   | UNKNOWN     | Might have wrong info, re-verify |
   * | ENABLED        | DISABLED    | Key definitely wrong             |
   * | UNKNOWN        | DISABLED    | Confirmed doesn't work           |
   *
   */
  private async sendToDevice(
    msg: {
      recipientUserId: string;
      recipientDeviceId: number;
      timestamp: number;
      clientMessageId?: string;
    },
    ciphertextBase64: string,
    messageType: 'prekey_bundle' | 'ciphertext' | 'sender_key',
    recipientRegistrationId: number | undefined,
    sealedSender: Awaited<
      ReturnType<typeof SignalProtocolServiceCipher.prototype.resolveSealedSenderContext>
    >,
    contentHint?: ContentHint,
    clientMessageId?: string,
    preparedSealedSender?: {
      sentMessageBase64: string;
      auth: SealedSenderAuth;
      deliveryMode: 'preferred' | 'required';
    },
    control: DevicePostControl = {}
  ): Promise<RelayPostAcceptance> {
    const effectiveClientMessageId = msg.clientMessageId ?? clientMessageId;
    // A fallback continues a post that started, so only the first request is
    // admitted.
    let identifiedControl = control;

    if (preparedSealedSender && !this.relay!.sendMultiRecipientUnidentified) {
      if (preparedSealedSender.deliveryMode === 'required') {
        throw new EncryptionError(
          'Required sealed-sender relay capability is unavailable',
          EncryptionErrorCode.SEALED_SENDER_REQUIRED,
          { recipientUserId: msg.recipientUserId }
        );
      }
    }

    // Sealed sender path: use the V2 upload format for one recipient. V2 has
    // no two-recipient minimum; its recipient-count field permits this exact
    // direct-delivery shape.
    if ((sealedSender || preparedSealedSender) && this.relay!.sendMultiRecipientUnidentified) {
      // The sealed body names the registration of its device, as the
      // identified post does.
      const prepared =
        preparedSealedSender ??
        (sealedSender
          ? {
              sentMessageBase64: await this.serializeDirectSealedSenderMessage(
                msg,
                ciphertextBase64,
                messageType,
                recipientRegistrationId,
                sealedSender,
                contentHint
              ),
              auth: sealedSender.auth,
              deliveryMode:
                sealedSender.config.deliveryMode === 'required' ? 'required' : 'preferred',
            }
          : undefined);
      if (!prepared) throw new Error('Missing sealed-sender delivery state');
      // This post has one destination device, so a group endorsement takes
      // the direct sealed route.
      const sealedAuth =
        prepared.auth.type === 'groupSendToken'
          ? forDirectSealedRoute(prepared.auth)
          : prepared.auth;

      // The identified fallback declares the same device set as the sealed
      // post, because both name the same account.
      identifiedControl = {
        ...(control.stopSignal && { stopSignal: control.stopSignal }),
        ...(control.operationEpochMilliseconds !== undefined && {
          operationEpochMilliseconds: control.operationEpochMilliseconds,
        }),
        ...(control.deliveryClass && { deliveryClass: control.deliveryClass }),
        ...(control.declaredDeviceIds && { declaredDeviceIds: control.declaredDeviceIds }),
      };
      const declaredDeviceIds = control.declaredDeviceIds;
      try {
        const result = await this.postToRelay(
          () =>
            declaredDeviceIds
              ? this.relay!.sendMultiRecipientUnidentified!(
                  prepared.sentMessageBase64,
                  sealedAuth,
                  msg.timestamp,
                  control.deliveryClass ?? 'user-visible',
                  [msg.recipientUserId],
                  effectiveClientMessageId,
                  control.operationEpochMilliseconds,
                  undefined,
                  [{ userId: msg.recipientUserId, deviceIds: declaredDeviceIds }]
                )
              : this.relay!.sendMultiRecipientUnidentified!(
                  prepared.sentMessageBase64,
                  sealedAuth,
                  msg.timestamp,
                  control.deliveryClass ?? 'user-visible',
                  [msg.recipientUserId],
                  effectiveClientMessageId,
                  ...(control.operationEpochMilliseconds !== undefined
                    ? ([control.operationEpochMilliseconds] as const)
                    : ([] as const))
                ),
          true,
          control
        );
        if (result.uuids404.length > 0) {
          throw new SealedSenderRecipientRejectedError();
        }
        if (usedGroupRouteFallback(result)) {
          // The privacy of the post is the same on both routes. The record
          // shows that the Relay does not take the endorsement on the
          // direct route.
          this.logger.info('The Relay refused the group endorsement on the direct sealed route', {
            category: 'E2EE',
            data: {
              recipientUserId: msg.recipientUserId,
              recipientDeviceId: msg.recipientDeviceId,
              behavior: 'GROUP_ROUTE_FALLBACK',
            },
          });
        }
        // The group-token receipt names each refused destination with its
        // code. A declared post gets a whole-post refusal for a stale
        // registration instead. The refused count alone names no device, so
        // the send infers nothing from it.
        if (
          result.refusals?.some(
            (refusal) =>
              refusal.code === 'STALE_DEVICE' &&
              refusal.userId === msg.recipientUserId &&
              refusal.deviceId === msg.recipientDeviceId
          )
        ) {
          throw markRelayDeviceRefusal(new Error('Recipient device registration changed'), {
            code: 'STALE_DEVICE',
            userId: msg.recipientUserId,
            deviceId: msg.recipientDeviceId,
          });
        }
        return result;
      } catch (error) {
        // Fall back to identified delivery only for sealed-sender authorization
        // failures. Other failures retain their original error semantics.
        if (error instanceof SealedSenderAuthError) {
          if (prepared.deliveryMode === 'required') {
            throw error;
          }
          await this.restrictUnidentifiedAccessMode(msg.recipientUserId);
          await this.reportIdentifiedFallback(msg.recipientUserId);
          // Fall through to identified path below
        } else {
          throw error;
        }
      }
    }

    // Identified sender path: standard relay send
    return this.postToRelay(
      () =>
        this.relay!.send({
          targetUserId: msg.recipientUserId,
          targetDeviceId: msg.recipientDeviceId,
          senderUserId: this.userId,
          senderDeviceId: this.deviceId,
          ciphertext: ciphertextBase64,
          messageType,
          deliveryClass: identifiedControl.deliveryClass ?? 'user-visible',
          timestamp: msg.timestamp,
          ...(identifiedControl.operationEpochMilliseconds !== undefined && {
            operationEpochMilliseconds: identifiedControl.operationEpochMilliseconds,
          }),
          clientMessageId: effectiveClientMessageId,
          recipientRegistrationId,
          contentHint,
          ...(identifiedControl.declaredDeviceIds && {
            declaredDeviceIds: identifiedControl.declaredDeviceIds,
          }),
        }),
      false,
      identifiedControl
    );
  }

  /**
   * Resolve the group roster to concrete devices via the relay.
   *
   * `options.groupMemberUserIds` is required for relayed group sends. Group
   * membership is local-first: each client derives it from its own decrypted
   * group state, and the relay deliberately keeps no server-side membership
   * map. A groupId → member lookup would hand the relay the social graph
   * the zero-knowledge group design exists to hide.
   */
  private async resolveGroupMemberDevices(
    groupId: string,
    options: SendOptions | undefined,
    stopSignal: AbortSignal | undefined
  ): Promise<GroupMemberDevice[]> {
    if (!options?.groupMemberUserIds?.length) {
      throw new EncryptionError(
        `Group send for ${groupId} requires options.groupMemberUserIds. ` +
          'The relay keeps no server-side membership map; resolve the roster ' +
          'from local group state and pass the member user IDs.',
        EncryptionErrorCode.ENCRYPTION_FAILED,
        { groupId }
      );
    }
    const deviceResults = await this.fanOut
      .all(
        options.groupMemberUserIds,
        (userId) => this.fanOut.request(() => this.relay!.getActiveDevices(userId), stopSignal),
        stopSignal
      )
      .catch((error: unknown) => {
        throw firstItemError(error);
      });
    return deviceResults.flat();
  }

  private async prepareGroupSenderKeyPayload(
    actualGroupId: string,
    plaintextBytes: Uint8Array,
    options: SendOptions & { clientMessageId: string; timestamp: number },
    sessions: SendSessionCallbacks | undefined,
    readMembers: () => Promise<GroupMemberDevice[]>,
    stopSignal: AbortSignal | undefined
  ): Promise<{
    ciphertext: Uint8Array;
    preMessages: StoredOutgoingDeviceMessage[];
    senderKeyDistributionId?: string;
    /** The distribution, for a repair in this attempt only. */
    distribution?: SenderKeyHandoffDistribution;
  }> {
    const existingKey = await this.storage.getSenderKey(actualGroupId, this.userId, this.deviceId);
    if (!existingKey) {
      throw new EncryptionError(
        `No sender key for group ${actualGroupId}. Call createGroupSenderKey() first to create and distribute the key.`,
        EncryptionErrorCode.SESSION_NOT_FOUND,
        {
          groupId: actualGroupId,
          userId: this.userId,
          deviceId: this.deviceId,
        }
      );
    }

    // The age bound refuses an expired key at the encrypt below. An expired
    // key therefore rotates first. The rotation deletes the handoff rows of
    // the group, so every listed device gets the new key.
    if (await this.senderKeyManager.isOwnSenderKeyExpired(actualGroupId, this.userId, this.deviceId)) {
      this.logger.info('Sender key expired, auto-rotating', {
        category: 'E2EE',
        data: { groupId: actualGroupId },
      });
      await this.senderKeyManager.rotateSenderKey(actualGroupId, this.userId, this.deviceId);
    }
    let encrypted: { distribution: SenderKeyDistributionMessage; ciphertext: Uint8Array };
    try {
      encrypted = await this.encryptWithCurrentDistribution(actualGroupId, plaintextBytes);
    } catch (error) {
      if (
        !(error instanceof EncryptionError) ||
        error.code !== EncryptionErrorCode.SENDER_KEY_EXPIRED
      ) {
        throw error;
      }
      this.logger.info('Sender key expired, auto-rotating', {
        category: 'E2EE',
        data: { groupId: actualGroupId },
      });
      await this.senderKeyManager.rotateSenderKey(actualGroupId, this.userId, this.deviceId);
      encrypted = await this.encryptWithCurrentDistribution(actualGroupId, plaintextBytes);
    }
    const { distribution, ciphertext } = encrypted;
    if (!this.relay) return { ciphertext, preMessages: [] };

    // The distribution is at the chain index of this message, so a device
    // that installs it decrypts this message. The bytes hold the chain key:
    // they stay in memory and never reach the outbox.
    const serialized = this.serializeSenderKeyDistribution(actualGroupId, distribution);
    const distributionBytes = () => serialized;
    const key: SenderKeyHandoffKey = {
      senderKeyId: distribution.senderKeyId,
      generation: distribution.generation,
    };
    const members = await readMembers();
    const preMessages = await this.prepareSenderKeyHandoffMessages(
      actualGroupId,
      members.filter((member) => member.userId !== this.userId),
      key,
      distributionBytes,
      options.timestamp,
      sessions,
      stopSignal
    );
    // The index of each pre-message follows the member order.
    preMessages.forEach((message, index) => {
      message.clientMessageId = `${options.clientMessageId}:sender-key-distribution:${index}`;
    });
    return {
      ciphertext,
      preMessages,
      senderKeyDistributionId: distribution.senderKeyId,
      distribution: { key, bytes: distributionBytes },
    };
  }

  /**
   * Read the current distribution of the own sender key, then encrypt the
   * group message with that key. The distribution is at the chain index of
   * the message.
   */
  private async encryptWithCurrentDistribution(
    groupId: string,
    plaintextBytes: Uint8Array
  ): Promise<{ distribution: SenderKeyDistributionMessage; ciphertext: Uint8Array }> {
    const distribution = await this.senderKeyManager.getCurrentSenderKeyDistribution(
      groupId,
      this.userId,
      this.deviceId
    );
    if (!distribution) {
      throw new EncryptionError(
        `No sender key for group ${groupId}. Call createGroupSenderKey() first to create and distribute the key.`,
        EncryptionErrorCode.SESSION_NOT_FOUND,
        { groupId, userId: this.userId, deviceId: this.deviceId }
      );
    }
    const ciphertext = await this.senderKeyManager.encryptGroupMessage(
      groupId,
      this.userId,
      this.deviceId,
      plaintextBytes
    );
    return { distribution, ciphertext };
  }

  /**
   * The sender-key pre-messages of a send: one distribution pre-message for
   * each listed device of another member that has no handoff row for the
   * current key and the current session with the device. A device with no
   * session gets one first, and the freshness window of the device list
   * does not apply to it. The sender's own devices are never targets: they
   * get the transcript.
   *
   * Each recipient has a session and a resolved privacy policy before the
   * first distribution encryption, so a required send that cannot seal a
   * pre-message makes no peer ratchet effect.
   *
   * A device that cannot take the distribution is skipped, and the next send
   * tries it again, because it has no row. Only the listed devices count for
   * the failure rule. The send fails for a member when each listed device of
   * the member that needs the key fails, and no other listed device of the
   * member has the key. A listed device has the key when it has a row, or
   * when a `pending` pre-message targets it, so such a device is not a
   * target. `GroupOutboxContext.prepareSenderKeyHandoffs` states the same
   * rule.
   */
  private async prepareSenderKeyHandoffMessages(
    groupId: string,
    otherMembers: readonly GroupMemberDevice[],
    key: SenderKeyHandoffKey,
    distributionBytes: () => Uint8Array,
    timestamp: number,
    sessions: SendSessionCallbacks | undefined,
    stopSignal: AbortSignal | undefined,
    pending: readonly StoredOutgoingDeviceMessage[] = []
  ): Promise<StoredOutgoingDeviceMessage[]> {
    const targets = await this.senderKeyHandoffTargets(otherMembers);
    const pendingDevices = new Set(
      pending.map((message) =>
        groupDeviceKey({ userId: message.recipientUserId, deviceId: message.recipientDeviceId })
      )
    );
    const needing = (await this.senderKeyHandoffs.devicesNeedingKey(groupId, key, targets)).filter(
      (target) => !pendingDevices.has(groupDeviceKey(target))
    );
    if (needing.length === 0) return [];
    const bytes = distributionBytes();
    const recipientUserIds = [...new Set(needing.map((target) => target.userId))];
    await this.refreshPreMessageEndorsements(groupId, recipientUserIds);
    const sealedSenders = await this.fanOut
      .all(
        recipientUserIds,
        async (recipientUserId) => {
          await this.ensureSenderKeyHandoffSessions(
            recipientUserId,
            needing.filter((target) => target.userId === recipientUserId),
            otherMembers.filter((member) => member.userId === recipientUserId),
            sessions
          );
          return this.relay?.sendMultiRecipientUnidentified
            ? this.resolveDistributionSealedSender(recipientUserId, groupId)
            : this.useIdentifiedDeliveryOrThrow(
                recipientUserId,
                'anonymous relay capability is not configured'
              );
        },
        stopSignal
      )
      .catch((error: unknown) => {
        throw firstItemError(error);
      });
    const prepared = await this.fanOut
      .all(
        recipientUserIds,
        (recipientUserId, index) =>
          this.prepareUserSenderKeyHandoffs(
            groupId,
            recipientUserId,
            needing.filter((target) => target.userId === recipientUserId),
            targets.filter(
              (target) => target.userId === recipientUserId && !needing.includes(target)
            ).length,
            key,
            bytes,
            timestamp,
            sealedSenders[index] ?? null
          ),
        stopSignal
      )
      .catch((error: unknown) => {
        throw firstItemError(error);
      });
    return prepared.flat();
  }

  /**
   * Each member device with the registration ID of its current session. A
   * device whose record is marked removed has none, so it needs the key and
   * the session step reads its device list again, which relists it.
   */
  private senderKeyHandoffTargets(
    members: readonly GroupMemberDevice[]
  ): Promise<SenderKeyHandoffTarget[]> {
    return Promise.all(
      members.map(async ({ userId, deviceId }) => {
        const record = await this.sesameManager.getDeviceRecord(userId, deviceId);
        return {
          userId,
          deviceId,
          registrationId:
            record && !isRemovedDevice(record)
              ? record.session?.currentSession?.remoteRegistrationId
              : undefined,
        };
      })
    );
  }

  /**
   * Give a session to each device of one member that needs the sender key
   * and has none. The freshness window of the device list does not apply.
   * The list is the one that this send read.
   */
  private async ensureSenderKeyHandoffSessions(
    recipientUserId: string,
    needing: readonly SenderKeyHandoffTarget[],
    listed: readonly GroupMemberDevice[],
    sessions: SendSessionCallbacks | undefined
  ): Promise<void> {
    if (needing.every((target) => target.registrationId !== undefined)) return;
    const hasActiveSession = await this.hasActiveSession(recipientUserId);
    if (!sessions) {
      if (hasActiveSession) return;
      throw new EncryptionError(
        `No session with ${recipientUserId} and auto-establishment not configured`,
        EncryptionErrorCode.SESSION_NOT_FOUND,
        { recipientUserId }
      );
    }
    await this.readRecipientDeviceList(
      recipientUserId,
      sessions,
      hasActiveSession,
      undefined,
      listed
    );
  }

  /**
   * Encrypt the distribution for each device of one member that needs it.
   * Each pre-message carries the registration ID of the session that
   * encrypted it and the key that it gives, for the handoff row.
   *
   * @param handedOff - The count of listed devices of the member that have a
   *   row or that a pending pre-message targets
   */
  private async prepareUserSenderKeyHandoffs(
    groupId: string,
    recipientUserId: string,
    needing: readonly SenderKeyHandoffTarget[],
    handedOff: number,
    key: SenderKeyHandoffKey,
    distributionBytes: Uint8Array,
    timestamp: number,
    sealedSender: ResolvedSealedSenderContext | null
  ): Promise<StoredOutgoingDeviceMessage[]> {
    const stored: StoredOutgoingDeviceMessage[] = [];
    const failures: string[] = [];
    for (const { deviceId } of needing) {
      let message: SesameMessage;
      let registrationId: number | undefined;
      try {
        // A device that is still removed after the session step gets no
        // distribution. Its device list read failed, and the next send tries
        // it again, because it has no row.
        const record = await this.sesameManager.getDeviceRecord(recipientUserId, deviceId);
        if (record && isRemovedDevice(record)) {
          throw new Error('the device record is marked removed');
        }
        message = await this.sesameManager.sendMessage(recipientUserId, deviceId, distributionBytes, {
          clientTimestamp: timestamp,
          includeSyncMessages: false,
        });
        registrationId = await this.sesameManager.getRemoteRegistrationId(
          recipientUserId,
          deviceId
        );
      } catch (error) {
        if (error instanceof RelayWorkStopped) throw error;
        const reason = error instanceof Error ? error.message : String(error);
        failures.push(`${String(deviceId)}: ${reason}`);
        this.logger.warn('Skipped the sender-key distribution of a device', {
          category: 'E2EE',
          error: error instanceof Error ? error : new Error(reason),
          data: { groupId, recipientUserId, recipientDeviceId: deviceId },
        });
        continue;
      }
      const identified = await this.prepareStoredDirectDeviceMessage(message, null, undefined);
      if (registrationId !== undefined) identified.recipientRegistrationId = registrationId;
      identified.senderKeyHandoff = { senderKeyId: key.senderKeyId, generation: key.generation };
      stored.push(
        sealedSender
          ? await this.sealStoredDeviceMessage(
              identified,
              sealedSender,
              sealedSender.config.deliveryMode === 'required' ? 'required' : 'preferred'
            )
          : identified
      );
    }
    if (stored.length === 0 && failures.length > 0 && handedOff === 0) {
      throw new EncryptionError(
        `Failed to send the sender key to all ${String(failures.length)} devices of ${recipientUserId}: ${failures.join(', ')}`,
        EncryptionErrorCode.ENCRYPTION_FAILED,
        { groupId, recipientUserId }
      );
    }
    return stored;
  }

  /**
   * Encrypt to a group via Sender Keys (O(1) encryption)
   *
   * Uses the multi-recipient sealed-sender transport when anonymous delivery
   * is available, with exact per-device identified delivery otherwise.
   */
  private async encryptToGroup(
    groupId: string,
    plaintextBytes: Uint8Array,
    options: SendOptions & { clientMessageId: string },
    sessions: SendSessionCallbacks | undefined,
    stopSignal?: AbortSignal
  ): Promise<SendResult> {
    // The group operation owns preparation, persistence, posting, and key confirmation.
    return this.groupSenderKeys.run(
      groupId,
      async (actualGroupId) => {
        await this.groupSendBarrierChecker?.(actualGroupId);
        return this.encryptToGroupWithOutbox(
          actualGroupId,
          plaintextBytes,
          options,
          sessions,
          stopSignal
        );
      },
      stopSignal
    );
  }
  /**
   * Encrypt binary attachment with two-layer encryption
   *
   * Layer 1: AES-GCM-HKDF Streaming encrypts the file (Tink format)
   * Layer 2: Signal Protocol encrypts the AES key + metadata
   *
   * Uses streaming AEAD for:
   * - Per-chunk integrity verification
   * - Streaming decryption (video playback while downloading)
   * - Truncation detection via last-segment flag
   *
   * @param recipientId - User or group ID to send to
   * @param data - Binary file data as Uint8Array (use expo-file-system File.bytes())
   * @param options - Send options including mimeType, blurHash, dimensions
   *
   * @see https://developers.google.com/tink/streaming-aead/aes_gcm_hkdf_streaming
   */
  private async encryptBinaryAttachment(
    recipientId: string,
    data: Uint8Array,
    options: SendOptions & { clientMessageId: string },
    sessions: SendSessionCallbacks | undefined,
    stopSignal: AbortSignal | undefined
  ): Promise<SendResult> {
    if (!this.relay) {
      throw new EncryptionError(
        'Relay server not configured. Cannot send attachments without server connection.',
        EncryptionErrorCode.INITIALIZATION_FAILED
      );
    }

    const uploaded = await this.prepareAttachmentUpload(data, options);

    const attachmentPayload = serializeMediaAttachmentMessage({
      attachment: uploaded,
      timestamp: options.timestamp ?? Date.now(),
    });
    const attachmentBytes = new TextEncoder().encode(attachmentPayload);
    let result: SendResult;
    if (isGroupId(recipientId)) {
      result = await this.encryptToGroup(
        recipientId,
        attachmentBytes,
        options,
        sessions,
        stopSignal
      );
    } else {
      result = await this.encryptToUser(recipientId, attachmentBytes, options, sessions);
    }

    return {
      ...result,
      storageId: uploaded.storageId,
      aesKey: uploaded.key,
      segmentSize: uploaded.segmentSize,
      digest: uploaded.digest,
      contentType: uploaded.contentType,
    };
  }

  private async prepareAttachmentUpload(
    data: Uint8Array,
    options?: SendOptions
  ): Promise<PreparedAttachmentUpload> {
    if (!this.remoteObjectStore) {
      throw new EncryptionError(
        'Remote object storage not configured. Provide remoteObjectStore in DefaultSignalProtocolClient.create() config.',
        EncryptionErrorCode.INITIALIZATION_FAILED
      );
    }

    return prepareMediaAttachmentUpload(data, {
      remoteObjectStore: this.remoteObjectStore,
      transfer: options?.attachment?.transfer,
      retry: options?.attachment?.retry,
      policy: options?.attachment?.policy,
      signal: options?.attachment?.signal,
      onProgress: options?.attachment?.onProgress,
      onCheckpoint: options?.attachment?.onCheckpoint,
      resume: options?.attachment?.resume,
      contentType: options?.mimeType || 'application/octet-stream',
      blurHash: options?.blurHash,
      thumbnail: options?.thumbnail,
      width: options?.width,
      height: options?.height,
      durationMs: options?.durationMs,
      waveform: options?.waveform,
      fileName: options?.fileName,
      caption: options?.caption,
      isViewOnce: options?.isViewOnce,
      flags: options?.flags,
      clientUuid: options?.clientUuid,
      cdnNumber: options?.cdnNumber,
    });
  }
}
