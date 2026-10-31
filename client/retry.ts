/**
 * Retry operations for SignalProtocolClient (SESAME Protocol)
 *
 * Extracted from DefaultSignalProtocolClient class to reduce file size.
 * Handles retry request creation, sending, and response handling.
 */

import type { Envelope, SignalProtocolRelayServer } from '../remote/relay/types';
import type { PreKeyBundle } from '../keys';
import { EncryptionError, EncryptionErrorCode } from '../types';
import { ContentHint } from '../types/messages';
import { ProtocolAddress } from '../types/address';
import { determineRetryReason, retryFailedEnvelope } from './retry-utils';
import { acknowledgesRetryRequest, requestRetryInFamily } from './retry-request-lifecycle';
import { retryRequestPost } from './retry-request-envelope';
import type { RetryFamilyReceive } from './retry-family';
import type {
  SignalProtocolClientContext,
  IncomingEnvelope,
  ProcessEnvelopeOptions,
} from './types';
import {
  RetryReason,
  SesameError,
  type SesameManager,
  type SesameMessage,
  type RetryRequest,
} from '../internal/sesame/types';
import {
  isImplicitContentType,
  MAX_RETRY_RESPONSES_PER_MESSAGE,
  SEND_LOG_RESEND_JOB_TTL_MS,
} from './constants';
import { SIGNAL_PROTOCOL_CLIENT_CONSTANTS } from './state';
import { base64ToBytes, bytesToString } from '../internal/crypto/utils';
import type { Base64 } from '../types/utils';
import type {
  MessageRecord,
  SendLogDevice,
  SendLogEntry,
  SendLogPayload,
  SendLogResendJob,
} from '../types/api';
import type { SenderKeyDistributionMessage } from '../internal/protocol/sender-keys';
import { extractGroupId } from '../internal/groups/group-id';
import { GroupResendDeferredError, type GroupMembershipChecker } from './group-receive-authorization';
import {
  getRetryResend,
  RELIABILITY_RECORD_TTL_MS,
  retryRequestAttempt,
  storeRetryResend,
  type RetryResendTarget,
  type RetryResendTerminal,
  type RetryTerminalClass,
} from '../local/store/reliability';
import { createKeyedLocks, withKeyedLock } from '../utils/keyed-lock';

/**
 * Retry response state (passed by client, mutated in place)
 */
export {};
export interface RetryResponseState {
  /**
   * Retry responses per message: key = `${sessionId}:${failedTimestamp}`,
   * value = response count. The row of a logged group send counts its
   * resends instead, and that count survives a restart.
   */
  retryResponseCounts: Map<string, number>;
  /**
   * The groups with no source of current membership whose refused resend
   * the client logged, by raw group ID. Each is logged once.
   */
  refusedGroupResends: Set<string>;
}

/**
 * Extended context for retry operations (adds sesame and relay)
 */
export interface RetryContext extends SignalProtocolClientContext {
  sesameManager: SesameManager;
}

/**
 * The request attempt that a retry request envelope is: the failed envelope,
 * the retry ID of its request record and the ID of the request envelope.
 */
export type RetryRequestAttempt = Omit<RetryResendTarget, 'kind'>;

/**
 * The requesting device of an answer and the client timestamp of the
 * message that it asks for. A retry request is one. A resend job names the
 * same values from its logged entry.
 */
type AnswerRequester = Pick<
  RetryRequest,
  'requesterUserId' | 'requesterDeviceId' | 'failedTimestamp'
> &
  Partial<Pick<RetryRequest, 'reason'>>;

/** One resend job of a store runs at a time in this process. */
const resendJobLocks = createKeyedLocks();

/**
 * The ID of the resend job of one logged send for one request envelope. A
 * redelivery of the request envelope names the same job.
 */
export function resendJobId(requestEnvelopeId: string, clientMessageId: string): string {
  return `${requestEnvelopeId}:${clientMessageId}`;
}

/**
 * Callbacks for operations that need to delegate back to SignalProtocolClient
 */
export interface RetryCallbacks {
  /** Archive a session (for orphaned session handling) */
  archiveSession: (address: ProtocolAddress) => Promise<void>;
  /** Establish a new session with prekey bundle */
  establishSession: (address: ProtocolAddress, bundle: PreKeyBundle) => Promise<void>;
  /**
   * Encrypt content for one device of a user and post it to that device
   * only. The send makes no sent-sync transcript. With a retry target, the
   * sender keeps one resend record for the device and the failed envelope.
   * A call for the request attempt and the kind of that record posts its
   * stored bytes again under their own ID. A call for another request
   * attempt or kind encrypts once under its own attempt ID, and the resend
   * takes the attempt number of the request. When the Relay refuses the
   * stored bytes as expired, the record is marked acceptance-unknown, and
   * nothing more posts under that ID: no new encryption replaces it. Null
   * content posts only a stored attempt. It returns false when null content
   * posted no stored bytes in this call. It returns true when the stored
   * bytes posted, or when content exists and the stored attempt has unknown
   * acceptance, and then nothing posts.
   */
  resend: (
    userId: string,
    deviceId: number,
    content: string | null,
    options: {
      timestamp: number;
      contentHint?: ContentHint;
      retry?: RetryResendTarget;
      /**
       * The own sender key of the raw group that the content carries. When
       * the Relay accepts the encryption that carries it, the sender records
       * a handoff row of that key for the device.
       */
      senderKeyHandoff?: { groupId: string; senderKeyId: string; generation: number };
    }
  ) => Promise<boolean>;
  /** Generate replacement prekeys and upload their public material. */
  forcePreKeyRotation: () => Promise<void>;
  /** The current membership of a user in a group, before group content goes to it again. */
  groupMembership: GroupMembershipChecker;
  /**
   * The group of the group send that this client sent to the user at this
   * client timestamp, if any.
   */
  findSentGroupId: (userId: string, clientTimestamp: number) => Promise<string | undefined>;
  /**
   * The current sender-key distribution of this device for a group, with
   * the raw group ID, or null when the device has no sender key for it.
   */
  currentGroupDistribution: (
    groupId: string
  ) => Promise<{ groupId: string; distribution: SenderKeyDistributionMessage } | null>;
  /**
   * Delete the sender-key handoff rows of one device in one group, so the
   * next group send gives the current key to that device. It returns true
   * when a row was deleted.
   */
  invalidateSenderKeyHandoff: (
    groupId: string,
    device: { userId: string; deviceId: number }
  ) => Promise<boolean>;
}

/**
 * Configuration constants for retry operations
 */
export interface RetryConfig {
  /** Debounce interval for forced prekey rotations in ms */
  keyRotationDebounceMs: number;
}

// Max 10 retry requests per sender per 3-hour window
export const MAX_RETRY_REQUESTS_PER_SENDER = 10;
export const RETRY_REQUEST_WINDOW_MS = 3 * 60 * 60 * 1000; // 3 hours

/**
 * State for receiver-side retry rate limiting.
 * Uses reset-if-idle struct instead of sliding window.
 */
export interface RetryRateLimitState {
  /** LRU-evicted map: senderId → {count, lastReceivedTime}. */
  retryRateLimitCounts: Map<string, { count: number; lastReceivedTime: number }>;
  /** Timestamp of last forced prekey rotation (for debounce) */
  lastPreKeyRotationTime: number;
}

const MAX_RATE_LIMIT_ENTRIES = 100;

/**
 * Check receiver-side retry rate limit for a sender.
 * Returns true if the request is allowed, false if rate-limited.
 *
 * Reset-if-idle struct with LRU eviction.
 */
export function checkRetryRateLimit(
  rateLimitState: RetryRateLimitState,
  senderId: string,
  now: number = Date.now()
): boolean {
  const entry = rateLimitState.retryRateLimitCounts.get(senderId);

  if (entry) {
    // Reset the count after a full idle window.
    if (now - entry.lastReceivedTime > RETRY_REQUEST_WINDOW_MS && entry.count > 0) {
      entry.count = 0;
    }

    // Increment before checking so exactly ten requests remain allowed.
    entry.count++;
    // Update blocked requests too so sustained abuse cannot reset the window.
    entry.lastReceivedTime = now;

    // Move the entry to the newest position in Map iteration order.
    rateLimitState.retryRateLimitCounts.delete(senderId);
    rateLimitState.retryRateLimitCounts.set(senderId, entry);

    if (entry.count > MAX_RETRY_REQUESTS_PER_SENDER) {
      return false;
    }
    return true;
  }

  // New sender. Evict least-recently-used entry if at capacity
  if (rateLimitState.retryRateLimitCounts.size >= MAX_RATE_LIMIT_ENTRIES) {
    const oldestKey = rateLimitState.retryRateLimitCounts.keys().next().value;
    if (oldestKey) rateLimitState.retryRateLimitCounts.delete(oldestKey);
  }

  rateLimitState.retryRateLimitCounts.set(senderId, { count: 1, lastReceivedTime: now });
  return true;
}

/**
 * Default configuration values
 */
export const DEFAULT_RETRY_CONFIG: RetryConfig = {
  keyRotationDebounceMs: SIGNAL_PROTOCOL_CLIENT_CONSTANTS.KEY_ROTATION_DEBOUNCE_MS,
};

/**
 * Mark a message as delivered silently (without throwing on failure)
 */
async function markMessageDeliveredSilently(
  messageId: string | undefined,
  relay: SignalProtocolRelayServer | undefined,
  logger: RetryContext['logger'],
  options?: ProcessEnvelopeOptions
): Promise<void> {
  if (!messageId) return;

  try {
    if (relay?.markDelivered) {
      await relay.markDelivered(messageId);
    } else if (options?.markDelivered) {
      await options.markDelivered(messageId);
    }
  } catch (error) {
    logger.warn('Failed to mark message as delivered silently', {
      category: 'E2EE',
      data: { messageId, error: (error as Error).message },
    });
  }
}

/**
 * Send a NullMessage to complete session reset when resend payload is unavailable.
 *
 * A null message lets the peer confirm a reset when the original payload is no
 * longer available.
 */
async function sendNullMessageForRetryReset(
  callbacks: RetryCallbacks,
  retryRequest: RetryRequest,
  ctx: RetryContext,
  retry: RetryRequestAttempt | undefined
): Promise<boolean> {
  return await callbacks.resend(
    retryRequest.requesterUserId,
    retryRequest.requesterDeviceId,
    ctx.contentAdapter.serializeNullMessage(),
    {
      // Reuse failed timestamp for correlation with the retry request.
      timestamp: retryRequest.failedTimestamp,
      // The reference implementation treats null-message reset responses as implicit/protocol content.
      contentHint: ContentHint.Implicit,
      ...(retry && { retry: { ...retry, kind: 'null' } }),
    }
  );
}

/**
 * Store the terminal state of the answer to a request attempt, call the
 * `onRetryTerminal` hook, and then store the state as emitted, as
 * `emitRetryResendTerminal` tells.
 */
async function endRetryResend(
  ctx: RetryContext,
  retryRequest: AnswerRequester,
  retry: RetryRequestAttempt,
  terminalClass: RetryTerminalClass
): Promise<void> {
  const ended: RetryResendTerminal = {
    ...retry,
    kind: 'resend',
    attempt: retryRequestAttempt(retry),
    recipientUserId: retryRequest.requesterUserId,
    recipientDeviceId: retryRequest.requesterDeviceId,
    terminal: { class: terminalClass, at: Date.now(), emitted: false },
  };
  await storeRetryResend(ctx.storage, ended);
  await emitRetryResendTerminal(ctx, ended);
}

/**
 * Call the hook for a terminal answer that is not emitted, and then store it
 * as emitted. The hook is called directly, not through `callHook`, so a hook
 * that throws, and the RelayWorkStopped of a stop, propagate and leave the
 * answer not emitted. The rule is: mark only after the hook returns. The
 * error fails the handling of the request envelope, so the relay delivers it
 * again, and the redelivery calls the hook again.
 */
async function emitRetryResendTerminal(
  ctx: RetryContext,
  ended: RetryResendTerminal
): Promise<void> {
  if (ended.terminal.emitted) return;
  const hook = ctx.hooks?.onRetryTerminal;
  if (hook) {
    await hook({ class: ended.terminal.class, failedEnvelopeId: ended.failedEnvelopeId });
  }
  await storeRetryResend(ctx.storage, {
    ...ended,
    terminal: { ...ended.terminal, emitted: true },
  });
}

/**
 * Post the stored resend or null message that answered this request
 * envelope again: the post of that answer did not complete. It does no
 * session work. When the Relay refuses the stored answer as expired, or
 * marked it so earlier, the answer has unknown acceptance and nothing more
 * posts under its ID. It returns false when the sender stored no answer to
 * this request envelope, or when the plaintext is gone and no stored bytes
 * posted. Then only a null-message reset under its own ID can follow. A
 * stored answer to another request envelope is an earlier attempt: the
 * caller answers this one with a new encryption.
 */
async function replayStoredResend(
  ctx: RetryContext,
  retryRequest: RetryRequest,
  record: MessageRecord | null,
  callbacks: RetryCallbacks,
  retry: RetryRequestAttempt
): Promise<boolean> {
  const { requesterUserId, requesterDeviceId } = retryRequest;
  const stored = await getRetryResend(
    ctx.storage,
    requesterUserId,
    requesterDeviceId,
    retry.failedEnvelopeId
  );
  if (stored?.requestEnvelopeId !== retry.requestEnvelopeId) return false;
  if (stored.kind === 'null') {
    const posted = await sendNullMessageForRetryReset(callbacks, retryRequest, ctx, retry);
    // As after the first post, delete the record that the send of the null
    // message stored, so no later request resends the null message as content.
    await ctx.storage
      .deleteMessageRecord(`${requesterUserId}:${requesterDeviceId}`, retryRequest.failedTimestamp)
      .catch(() => {
        // Non-fatal: the null message is posted.
      });
    return posted;
  }
  // The plaintext is gone after a delivery receipt or the content retention.
  const plaintext = record?.recipientUserId === requesterUserId ? record.plaintext : null;
  return await callbacks.resend(requesterUserId, requesterDeviceId, plaintext, {
    timestamp: record?.timestamp ?? retryRequest.failedTimestamp,
    retry: { ...retry, kind: 'resend' },
  });
}

/**
 * The message record of a peer session and client timestamp, without a
 * sender key distribution. A distribution holds a chain key, which rests
 * only in the sender key store: the lookup stores the record without it,
 * or deletes a record that holds only a distribution and returns null, so
 * the request is answered as for a missing record.
 */
async function getResendableMessageRecord(
  ctx: RetryContext,
  sessionId: string,
  timestamp: number
): Promise<MessageRecord | null> {
  const record = await ctx.storage.getMessageRecord(sessionId, timestamp);
  if (record === null) return null;
  const plaintext = ctx.contentAdapter.withoutSenderKeyDistribution(record.plaintext);
  if (plaintext === record.plaintext) return record;
  ctx.logger.info('Removed a sender key distribution from a message record', {
    category: 'E2EE',
    data: { sessionId, timestamp, deleted: plaintext === null },
  });
  if (plaintext === null) {
    await ctx.storage.deleteMessageRecord(sessionId, timestamp);
    return null;
  }
  // A replace keeps the stored createdAt, so the retention does not move.
  await ctx.storage.storeMessageRecord({ ...record, plaintext });
  return { ...record, plaintext };
}

/**
 * Get session key string from userId and deviceId
 */
export function getSessionKey(userId: string, deviceId: number): string {
  return `${userId}:${deviceId}`;
}

/**
 * Send retry request for failed decryption (internal)
 *
 * Sends a `retry_request` envelope to the failed sender device through the
 * relay. Without a relay, it gives the envelope to the options callback.
 * Handles IMPLICIT content type discarding, rate limiting, and stale prekey rotation.
 * An envelope without an identified sender, or from the local device, gets
 * one warn line and no request. The request is stored under the failed
 * envelope ID before its post, and the request record then owns it, as
 * `requestRetryInFamily` tells. A redelivery of the failed envelope posts
 * nothing. A failed resend or null message asks again for its failed
 * envelope through the retry family, whatever its content hint. A member
 * that fails with an error that is not retryable posts nothing here, and its
 * redelivery on the pull path asks again.
 *
 * @param ctx - Retry context with dependencies
 * @param envelope - The failed message envelope
 * @param error - The decryption error
 * @param rateLimitState - State for rate limiting (mutated in place)
 * @param callbacks - Callbacks for operations needing SignalProtocolClient
 * @param config - Configuration constants
 * @param family - The retry family of the envelope
 * @param fingerprint - The fingerprint of the envelope as the Relay delivered
 *   it, before any unseal. The stored request binds to it.
 * @param options - Optional transport callbacks (for background without relay)
 */
export async function sendRetryRequestInternal(
  ctx: RetryContext,
  envelope: IncomingEnvelope,
  error: Error,
  rateLimitState: RetryRateLimitState,
  callbacks: Pick<RetryCallbacks, 'forcePreKeyRotation'>,
  config: RetryConfig,
  family: RetryFamilyReceive,
  fingerprint: string | undefined,
  options?: ProcessEnvelopeOptions
): Promise<void> {
  try {
    // Implicit messages (typing indicators, receipts) do not store MessageRecords -
    // retry would always fail. The Signal Protocol behavior is to discard it.
    if (family.member === undefined && isImplicitContentType(envelope)) {
      ctx.logger.debug('Skipping retry request for protocol message (IMPLICIT)', {
        category: 'E2EE',
        data: {
          messageType: envelope.messageType,
          timestamp: envelope.timestamp,
          behavior: 'IMPLICIT_DISCARD',
        },
      });

      await markMessageDeliveredSilently(envelope.id, ctx.relay, ctx.logger, options);
      return;
    }

    // An anonymous envelope names no device to ask.
    if (!envelope.senderUserId || !(envelope.senderDeviceId >= 1)) {
      ctx.logger.warn('No retry request for a failed envelope without an identified sender', {
        category: 'E2EE',
        data: {
          envelopeId: envelope.id,
          messageType: envelope.messageType,
          behavior: 'RETRY_REQUEST_SKIP',
        },
      });
      return;
    }

    // A device never asks itself for a resend. Its resend would fail again.
    if (envelope.senderUserId === ctx.userId && envelope.senderDeviceId === ctx.deviceId) {
      ctx.logger.warn('No retry request for a failed envelope from the local device', {
        category: 'E2EE',
        data: {
          envelopeId: envelope.id,
          messageType: envelope.messageType,
          behavior: 'RETRY_REQUEST_SKIP',
        },
      });
      return;
    }

    const retryReason = determineRetryReason(error);

    // Send via relay (foreground) or callback (background)
    const relay = ctx.relay;
    // The seal also applies to the background callback. With no relay it
    // has no anonymous delivery, so the request goes identified only when
    // the sealed sender delivery mode permits it.
    const sendIdentified = relay
      ? (request: Envelope) => relay.send(request)
      : options?.sendRetryRequest;
    const send =
      sendIdentified &&
      retryRequestPost(
        ctx.sealRetryRequest,
        relay,
        sendIdentified,
        ctx.recipientRegistrationId,
        (userId, deviceId) => ctx.refreshStaleSession?.(ctx, userId, deviceId) ?? Promise.resolve(false)
      );
    const createRequest = async (senderKey: boolean): Promise<RetryRequest> => {
      // Rotate before sending a retry request for a stale-prekey failure.
      const isStalePreKeyIndicator =
        error instanceof EncryptionError &&
        (error.code === EncryptionErrorCode.PREKEY_NOT_FOUND ||
          (error.code === EncryptionErrorCode.DECRYPTION_FAILED &&
            envelope.messageType === 'prekey_bundle'));

      if (isStalePreKeyIndicator) {
        // Debounce to prevent excessive rotations
        const now = Date.now();
        const timeSinceLastRotation = now - rateLimitState.lastPreKeyRotationTime;

        if (timeSinceLastRotation > config.keyRotationDebounceMs || timeSinceLastRotation < 0) {
          try {
            if (ctx.relay) {
              await callbacks.forcePreKeyRotation();
              rateLimitState.lastPreKeyRotationTime = Date.now();
              ctx.logger.info('Forced prekey rotation before retry (relay)', {
                category: 'E2EE',
                data: { errorCode: (error as EncryptionError).code },
              });
            } else if (options?.forcePreKeyRotation) {
              await options.forcePreKeyRotation();
              rateLimitState.lastPreKeyRotationTime = Date.now();
              ctx.logger.info('Forced prekey rotation before retry (callback)', {
                category: 'E2EE',
                data: { errorCode: (error as EncryptionError).code },
              });
            } else {
              ctx.logger.warn('Cannot force prekey rotation: no relay or callback available', {
                category: 'E2EE',
                data: { errorCode: (error as EncryptionError).code },
              });
            }
          } catch (rotationError) {
            ctx.logger.warn('Failed to force prekey rotation before retry', {
              category: 'E2EE',
              data: { error: (rotationError as Error).message },
            });
          }
        } else {
          ctx.logger.debug('Skipping prekey rotation (debounced)', {
            category: 'E2EE',
            data: {
              timeSinceLastRotationMs: timeSinceLastRotation,
              debounceMs: config.keyRotationDebounceMs,
            },
          });
        }
      }

      // Create SesameMessage for sesameManager
      let failedCiphertext: Uint8Array<ArrayBufferLike> = new Uint8Array();
      try {
        // A seal that fails to open gives no ratchet key.
        if (envelope.messageType !== 'unidentified_sender') {
          failedCiphertext = base64ToBytes(envelope.ciphertext as Base64);
        }
      } catch {
        // Keep empty ciphertext for malformed envelopes. The retry request still proceeds.
      }

      const failedMessage: SesameMessage = {
        senderUserId: envelope.senderUserId,
        senderDeviceId: envelope.senderDeviceId,
        recipientUserId: ctx.userId,
        recipientDeviceId: ctx.deviceId,
        sessionId: `${envelope.senderUserId}:${envelope.senderDeviceId}`,
        // Used to extract sender ratchet key for SDK retry validation.
        ciphertext: failedCiphertext,
        isInitiating: false,
        initHeader: null,
        timestamp: envelope.timestamp,
      };

      // Create retry request via SesameManager
      return ctx.sesameManager.createRetryRequest(failedMessage, retryReason, { senderKey });
    };
    const outcome = await requestRetryInFamily(family, fingerprint, {
      storage: ctx.storage,
      logger: ctx.logger,
      hooks: ctx.hooks,
      local: { userId: ctx.userId, deviceId: ctx.deviceId },
      senderUserId: envelope.senderUserId,
      senderDeviceId: envelope.senderDeviceId,
      // Receiver-side rate limiting. A failed envelope with a request record
      // spends nothing, as `requestRetryInFamily` tells.
      allow: () => checkRetryRateLimit(rateLimitState, envelope.senderUserId),
      windowMs: RETRY_REQUEST_WINDOW_MS,
      send,
      failedEnvelope: await retryFailedEnvelope(ctx.storage, envelope),
      createRequest,
      schedule: ctx.scheduleRetryRequest,
      reset: ctx.retryTerminalReset?.(ctx),
    });
    if (outcome === 'posted' || outcome === 'pending') {
      ctx.logger.info('Sent retry request for failed decryption', {
        category: 'E2EE',
        data: {
          sender: `${envelope.senderUserId}:${envelope.senderDeviceId}`,
          timestamp: envelope.timestamp,
          reason: retryReason,
          outcome,
        },
      });
    }
    // The record of the failed envelope owns its request, so the envelope
    // is acknowledged. A member is acknowledged only when its request
    // attempt is posted, waiting (nothing to post), or ended: a deferred
    // member asks again on its redelivery after the rate limit window.
    if (!acknowledgesRetryRequest(outcome, family.member !== undefined)) return;

    // Mark failed message as delivered so it does not reappear
    if (ctx.relay?.markDelivered) {
      await ctx.relay.markDelivered(envelope.id).catch((err) => {
        ctx.logger.warn('Failed to mark message delivered after retry request (relay)', {
          category: 'E2EE',
          data: { messageId: envelope.id, error: (err as Error).message },
        });
      });
    } else if (options?.markDelivered) {
      await options.markDelivered(envelope.id).catch((err) => {
        ctx.logger.warn('Failed to mark message delivered after retry request (callback)', {
          category: 'E2EE',
          data: { messageId: envelope.id, error: (err as Error).message },
        });
      });
    }
  } catch (retryError) {
    ctx.logger.warn('Failed to send retry request', {
      category: 'E2EE',
      data: { error: (retryError as Error).message },
    });
  }
}

/**
 * Handle incoming retry request and resend the original message
 *
 * Per SESAME spec §4.1, this method:
 * 1. Drops a request for another device of this user. Then it looks up the
 *    content that the requesting device can get again: the rows of that
 *    exact device in the send log, by the failed client message ID, then by
 *    the failed envelope ID, then by the failed timestamp, and else the
 *    MessageRecord of the device at the failed timestamp. When the sender
 *    already stored a resend or a null message for this request envelope,
 *    it posts the stored bytes again and does no session work
 * 2. Sends logged group content only to a current member of its group.
 *    A requester that is not a current member, or a group with no source
 *    of current membership, gets no content, and the answer to the failed
 *    envelope ends with `membership-refused`. Each row counts its resends,
 *    and the count survives a restart. A row with
 *    `MAX_RETRY_RESPONSES_PER_MESSAGE` resends gets no more
 * 3. For a request without a ratchet key, a sender-key failure, with no
 *    row: when this client sent a group to the requester at the failed
 *    timestamp, only a current member of that group gets an answer. With no
 *    record of the device at that timestamp, the answer is the current
 *    sender-key distribution alone. A sender-key failure never resets the
 *    pairwise session
 * 4. For a pairwise MessageRecord: verifies that the requester is its
 *    recipient and checks the content retention. With the ratchet key of
 *    the failed message, it creates a new session if the session is
 *    orphaned, or uses the existing different session
 * 5. Re-encrypts and sends the content, which replaces the old
 *    MessageRecord with the record of the new encryption. Only a delivery
 *    receipt from the device or the content retention deletes that record
 *    or the row.
 *
 * It refuses a request for a message stored more than
 * `RELIABILITY_RECORD_TTL_MS` ago, before it reads a stored resend. The
 * store clock at local persistence (`createdAt` of the MessageRecord or of
 * the send log entry) sets that age, so the message timestamp never moves
 * it. With no stored content, the failed timestamp sets it. The Relay can
 * keep the last resend post for that time again, and the requester keeps
 * its retry records for both periods. The content
 * retention (`protocol.contentRecovery.retentionMs`, 14 days by default) is
 * shorter. A request after it gets no content.
 *
 * It returns normally when it resends the message or refuses the request.
 * It throws every other error, so the caller keeps the request envelope and
 * a later pull gives it again.
 *
 * @param ctx - Retry context with dependencies
 * @param retryRequest - The retry request from the recipient
 * @param responseState - Retry response counts (mutated in place)
 * @param callbacks - Callbacks for SignalProtocolClient operations
 * @param config - Configuration constants
 * @param retry - The ID of the envelope that the requester could not
 *   decrypt and the retry ID of its request record, from the request, and
 *   the ID of the request envelope. Each request attempt gets one
 *   encryption. The content resend has the ID `<retryId>:resend`, and the
 *   null message has the ID `<retryId>:null`. Attempt n of either adds
 *   `:<n>` from attempt 2.
 */
export async function handleRetryRequestAndResend(
  ctx: RetryContext,
  retryRequest: RetryRequest,
  responseState: RetryResponseState,
  callbacks: RetryCallbacks,
  config: RetryConfig,
  retry?: RetryRequestAttempt
): Promise<void> {
  const sessionId = `${retryRequest.requesterUserId}:${retryRequest.requesterDeviceId}`;

  // Another device of this user sent the failed message. Only that device
  // can answer.
  if (
    retryRequest.originalSenderUserId !== ctx.userId ||
    retryRequest.originalSenderDeviceId !== ctx.deviceId
  ) {
    ctx.logger.warn('Dropping a retry request for another device', {
      category: 'E2EE',
      data: {
        sessionId,
        failedTimestamp: retryRequest.failedTimestamp,
        behavior: 'RETRY_REQUEST_OTHER_DEVICE',
      },
    });
    return;
  }

  // The response count of one message is keyed by its session and timestamp.
  const dedupKey = `${sessionId}:${retryRequest.failedTimestamp}`;

  ctx.logger.info('Processing retry request', {
    category: 'E2EE',
    data: {
      from: sessionId,
      failedTimestamp: retryRequest.failedTimestamp,
      reason: retryRequest.reason,
    },
  });

  try {
    // The rows of this exact device name the logged group content.
    const entries = await ctx.resendableContent.lookup(
      { userId: retryRequest.requesterUserId, deviceId: retryRequest.requesterDeviceId },
      [retryRequest.failedClientMessageId, retry?.failedEnvelopeId],
      retryRequest.failedTimestamp
    );
    // Look up the original outbound record by peer session and timestamp.
    const record = await getResendableMessageRecord(ctx, sessionId, retryRequest.failedTimestamp);

    // The age of the request runs from the local persistence of the content.
    const storedAt =
      record?.createdAt ?? entries[0]?.payload.createdAt ?? retryRequest.failedTimestamp;
    if (Date.now() - storedAt > RELIABILITY_RECORD_TTL_MS) {
      ctx.logger.warn('Refusing a retry request for a message older than the retry TTL', {
        category: 'E2EE',
        data: {
          sessionId,
          failedTimestamp: retryRequest.failedTimestamp,
          behavior: 'RETRY_REQUEST_EXPIRED',
        },
      });
      return;
    }

    // The answer to this failed envelope ended. A redelivery of a request
    // only calls the hook when no earlier call returned.
    if (retry !== undefined) {
      const stored = await getRetryResend(
        ctx.storage,
        retryRequest.requesterUserId,
        retryRequest.requesterDeviceId,
        retry.failedEnvelopeId
      );
      if (stored?.terminal !== undefined) {
        await emitRetryResendTerminal(ctx, stored);
        return;
      }
    }

    // The sender already answered this request envelope, and the post did
    // not complete. Post the stored bytes again, with no session work. A
    // group answer posts only stored bytes here. When they expired, the
    // record is marked acceptance-unknown, and only a null-message reset
    // under its own ID can follow.
    if (
      retry !== undefined &&
      (await replayStoredResend(
        ctx,
        retryRequest,
        entries.length > 0 ? null : record,
        callbacks,
        retry
      ))
    ) {
      if (entries.length === 0) {
        responseState.retryResponseCounts.set(
          dedupKey,
          (responseState.retryResponseCounts.get(dedupKey) ?? 0) + 1
        );
      }
      ctx.logger.info('Answered the stored resend of this request attempt', {
        category: 'E2EE',
        data: { sessionId, failedTimestamp: retryRequest.failedTimestamp },
      });
      return;
    }

    if (entries.length > 0) {
      await resendLoggedGroupContent(ctx, retryRequest, entries, responseState, callbacks, retry);
      return;
    }

    // Enforce retry response limit
    // Prevents infinite retry loops when decryption consistently fails
    const responseCount = responseState.retryResponseCounts.get(dedupKey) ?? 0;
    if (responseCount >= MAX_RETRY_RESPONSES_PER_MESSAGE) {
      ctx.logger.warn('Retry response limit reached, ignoring further retry requests', {
        category: 'E2EE',
        data: {
          dedupKey,
          responseCount,
          limit: MAX_RETRY_RESPONSES_PER_MESSAGE,
        },
      });
      return;
    }

    // A sender-key failure with no row: the sender did not log the content,
    // or the device was no recipient of it. Only a current member of the
    // group of the failed timestamp gets an answer. With no record, the
    // current distribution answers alone, so the later group messages of
    // this device decrypt. No record holds a distribution: the lookup
    // deleted a distribution-only record above, and a record with content
    // answers below with that content alone.
    if (retryRequest.ratchetKey === undefined) {
      const groupId = await callbacks.findSentGroupId(
        retryRequest.requesterUserId,
        retryRequest.failedTimestamp
      );
      if (groupId !== undefined) {
        if (!(await admitsGroupResend(ctx, retryRequest, groupId, responseState, callbacks))) {
          if (retry !== undefined) {
            await endRetryResend(ctx, retryRequest, retry, 'membership-refused');
          }
          return;
        }
        if (!record) {
          // The device reports that it cannot decrypt a message of the group,
          // so it can lack the current key. Its rows in the group go first,
          // and the accepted distribution records a new row. The scope is the
          // group only, as in the sender-key retry receipt of one Signal client.
          await callbacks.invalidateSenderKeyHandoff(groupId, {
            userId: retryRequest.requesterUserId,
            deviceId: retryRequest.requesterDeviceId,
          });
          const sent = await resendCurrentDistribution(
            ctx,
            retryRequest,
            groupId,
            callbacks,
            retry
          );
          if (sent) responseState.retryResponseCounts.set(dedupKey, responseCount + 1);
          return;
        }
      }
    }

    if (!record) {
      ctx.logger.warn('MessageRecord not found for retry request', {
        category: 'E2EE',
        data: {
          sessionId,
          failedTimestamp: retryRequest.failedTimestamp,
        },
      });

      // A null message completes the reset when the original resend payload is
      // no longer present in the send log. A sender-key failure resets no
      // pairwise session.
      const shouldAttemptNullFallback =
        retryRequest.reason === RetryReason.DECRYPTION_FAILED &&
        retryRequest.ratchetKey !== undefined;
      if (!shouldAttemptNullFallback) {
        return;
      }

      const activeSession = await ctx.sesameManager.getActiveSession(
        retryRequest.requesterUserId,
        retryRequest.requesterDeviceId
      );
      if (!activeSession) {
        return;
      }

      const lifecycle = await ctx.sesameManager.handleRetryRequest(retryRequest, {
        // Lifecycle-only mode is used strictly when payload lookup already failed.
        // Null-message fallback still depends on session-reset state when the
        // send-log payload is unavailable.
        skipMessageRecordValidation: true,
      });
      if (lifecycle.action === 'SESSION_ARCHIVED' && lifecycle.requiresNewSession) {
        // The reset archived the session, so the null message starts a new
        // one from a fresh prekey bundle.
        const sessionAfterReset = await ctx.sesameManager.getActiveSession(
          retryRequest.requesterUserId,
          retryRequest.requesterDeviceId
        );
        if (
          !sessionAfterReset &&
          !(await startAnswerSession(ctx, retryRequest, callbacks, retry, true))
        ) {
          return;
        }
        await sendNullMessageForRetryReset(callbacks, retryRequest, ctx, retry);
        // Null-message fallbacks are not retryable payloads. Delete the
        // synthetic record created by the generic send pipeline.
        await ctx.storage.deleteMessageRecord(sessionId, retryRequest.failedTimestamp).catch(() => {
          // Non-fatal: retry fallback already sent.
        });
        responseState.retryResponseCounts.set(dedupKey, responseCount + 1);

        ctx.logger.info('Sent null-message retry response after session reset', {
          category: 'E2EE',
          data: {
            sessionId,
            failedTimestamp: retryRequest.failedTimestamp,
          },
        });
      }
      return;
    }

    // SESAME Spec Step 2: Verify requester is the intended recipient
    if (record.recipientUserId !== retryRequest.requesterUserId) {
      ctx.logger.warn('Retry request from wrong recipient - discarding for security', {
        category: 'E2EE',
        data: {
          expectedRecipient: record.recipientUserId,
          actualRequester: retryRequest.requesterUserId,
          sessionId,
          failedTimestamp: retryRequest.failedTimestamp,
        },
      });
      return;
    }

    ctx.logger.info('MessageRecord found for retry request', {
      category: 'E2EE',
      data: {
        sessionId,
        failedTimestamp: retryRequest.failedTimestamp,
        ageMs: Date.now() - record.createdAt,
        sessionStateId: record.sessionStateId?.substring(0, 20),
        plaintextLength: record.plaintext.length,
      },
    });

    // 2. Check the content retention
    if (ctx.resendableContent.isExpired(record.createdAt)) {
      ctx.logger.warn('Message expired, cannot resend', {
        category: 'E2EE',
        data: {
          sessionId,
          failedTimestamp: retryRequest.failedTimestamp,
          age: Date.now() - record.createdAt,
        },
      });
      await ctx.storage.deleteMessageRecord(sessionId, record.timestamp);
      return;
    }

    // 3-4. A request with a ratchet key resets an orphaned session. The send
    // record captures the local ratchet key at send time.
    const sessionReady = await prepareAnswerSession(
      ctx,
      retryRequest,
      callbacks,
      retry,
      retryRequest.ratchetKey === undefined
        ? null
        : {
            request: retryRequest,
            sentRatchetKey: record.sessionStateId,
            validated: 'message-record',
          }
    );
    if (!sessionReady) return;

    // 5. SESAME Step 4-5: Re-encrypt the original message and send it only
    // to the device that asked. Reuse the original timestamp for envelope
    // alignment. A new request attempt gets one encryption under its own ID.
    await callbacks.resend(
      retryRequest.requesterUserId,
      retryRequest.requesterDeviceId,
      record.plaintext,
      {
        timestamp: record.timestamp,
        ...(retry && { retry: { ...retry, kind: 'resend' } }),
      }
    );

    // Track retry response count
    responseState.retryResponseCounts.set(dedupKey, responseCount + 1);

    // 6. The resend replaced the MessageRecord at the same timestamp with the
    // record of the new encryption. A delivery receipt from the device or the
    // content retention deletes it, so a failed resend can be requested again.
    // The store keeps the createdAt of the first write on the replace, so the
    // resend does not extend the retention.

    ctx.logger.info('Message resent successfully after retry request', {
      category: 'E2EE',
      data: {
        recipient: sessionId,
        failedTimestamp: retryRequest.failedTimestamp,
      },
    });
  } catch (error) {
    if (isRetryRefusal(error)) {
      ctx.logger.warn('Retry request refused', {
        category: 'E2EE',
        data: {
          sessionId,
          failedTimestamp: retryRequest.failedTimestamp,
          code: error.code,
        },
      });
      return;
    }
    throw error;
  }
}

/**
 * Answer a request with the logged group content that the rows of the
 * requesting device name. With a request attempt, each entry first gets a
 * pending resend job, before the membership check, so the resend job driver
 * finishes the answer after a restart or a failed post. Each entry is
 * checked and counted on its own row: the requester must be a current
 * member of the group of the entry, and the row must have fewer than
 * `MAX_RETRY_RESPONSES_PER_MESSAGE` resends. The job of an entry that is
 * not admitted is abandoned. When no entry is admitted and the membership
 * refused one, the answer ends with `membership-refused`. A group state that
 * waits for an update throws `GroupResendDeferredError` and leaves the
 * stored jobs pending. The first
 * answered entry carries the retry target, so a redelivery of the request
 * posts its stored bytes again. A later entry at the same timestamp posts
 * under a new ID, because one request attempt has one resend ID.
 */
async function resendLoggedGroupContent(
  ctx: RetryContext,
  retryRequest: RetryRequest,
  entries: readonly SendLogEntry[],
  responseState: RetryResponseState,
  callbacks: RetryCallbacks,
  retry: RetryRequestAttempt | undefined
): Promise<void> {
  const device = { userId: retryRequest.requesterUserId, deviceId: retryRequest.requesterDeviceId };
  const jobs = new Map<string, SendLogResendJob>();
  if (retry !== undefined) {
    for (const [index, { payload }] of entries.entries()) {
      const job = await storePendingResendJob(ctx, device, payload, retry, index === 0);
      jobs.set(payload.clientMessageId, job);
    }
  }
  const abandon = async (entry: SendLogEntry) => {
    const job = jobs.get(entry.payload.clientMessageId);
    if (job) await ctx.storage.completeResendJob(job.jobId, 'abandoned');
  };
  const admittedGroups = new Map<string, boolean>();
  const admitted: SendLogEntry[] = [];
  let refused = false;
  for (const entry of entries) {
    const { groupId } = entry.payload;
    let member = admittedGroups.get(groupId);
    if (member === undefined) {
      member = await admitsGroupResend(ctx, retryRequest, groupId, responseState, callbacks);
      admittedGroups.set(groupId, member);
    }
    if (!member) {
      refused = true;
      await abandon(entry);
      continue;
    }
    if (reachedResendCap(ctx, entry)) {
      await abandon(entry);
      continue;
    }
    admitted.push(entry);
  }
  if (admitted.length === 0) {
    // A refused membership ends the answer. No later request for the
    // failed envelope from this device gets content.
    if (refused && retry !== undefined) {
      await endRetryResend(ctx, retryRequest, retry, 'membership-refused');
    }
    return;
  }

  const sessionReady = await prepareAnswerSession(
    ctx,
    retryRequest,
    callbacks,
    retry,
    retryRequest.ratchetKey === undefined
      ? null
      : { request: retryRequest, sentRatchetKey: retryRequest.ratchetKey, validated: 'send-log' }
  );
  if (!sessionReady) {
    for (const entry of admitted) await abandon(entry);
    return;
  }

  let target: RetryResendTarget | undefined = retry && { ...retry, kind: 'resend' };
  for (const entry of admitted) {
    const job = jobs.get(entry.payload.clientMessageId);
    if (job === undefined) {
      await postLoggedGroupContent(ctx, device, entry.payload, callbacks, target);
    } else {
      await withResendJob(ctx, job.jobId, (pending) =>
        postLoggedGroupContent(ctx, device, entry.payload, callbacks, target, pending)
      );
    }
    target = undefined;
  }
}

/**
 * Write the pending resend job of one logged entry for a request attempt.
 * The job of the first entry that the request names holds the failed
 * envelope. A redelivered request envelope writes the same job again and
 * keeps its creation time and its attempts, so the one-day end of the job
 * counts from the first write.
 */
async function storePendingResendJob(
  ctx: RetryContext,
  device: SendLogDevice,
  payload: SendLogPayload,
  retry: RetryRequestAttempt,
  answersFailedEnvelope: boolean
): Promise<SendLogResendJob> {
  const jobId = resendJobId(retry.requestEnvelopeId, payload.clientMessageId);
  const existing = await ctx.storage.getResendJob(jobId);
  const job: SendLogResendJob = {
    jobId,
    clientMessageId: payload.clientMessageId,
    requesterUserId: device.userId,
    requesterDeviceId: device.deviceId,
    retryId: retry.retryId,
    requestEnvelopeId: retry.requestEnvelopeId,
    ...(answersFailedEnvelope && { failedEnvelopeId: retry.failedEnvelopeId }),
    createdAt: existing?.createdAt ?? Date.now(),
    attempts: existing?.attempts ?? 0,
    state: 'pending',
  };
  await ctx.storage.storeResendJob(job);
  return job;
}

/**
 * Run an operation on one pending resend job, under the lock of the job.
 * The job is read again under the lock: a job that another run finished
 * meanwhile does not run again.
 */
async function withResendJob(
  ctx: RetryContext,
  jobId: string,
  operation: (job: SendLogResendJob) => Promise<void>
): Promise<void> {
  await withKeyedLock(resendJobLocks, ctx.storage, jobId, async () => {
    const job = await ctx.storage.getResendJob(jobId);
    if (job?.state === 'pending') await operation(job);
  });
}

/** True, with a warning, when the row of the entry has its maximum count of resends. */
function reachedResendCap(ctx: RetryContext, entry: SendLogEntry): boolean {
  if (entry.recipient.responses < MAX_RETRY_RESPONSES_PER_MESSAGE) return false;
  ctx.logger.warn('Retry response limit reached, ignoring further retry requests', {
    category: 'E2EE',
    data: {
      clientMessageId: entry.payload.clientMessageId,
      responseCount: entry.recipient.responses,
      limit: MAX_RETRY_RESPONSES_PER_MESSAGE,
    },
  });
  return true;
}

/**
 * Post the logged content of one group send again to the requesting device,
 * with the current sender-key distribution of the group beside it, at the
 * original timestamp. The distribution is read in the group operation at
 * the current chain index, so the device also decrypts the later group
 * messages of this sender. With no sender key for the group, the content
 * goes alone. A job counts the attempt and holds the failed envelope of the
 * target before the post, and is posted after it. The caller checked the
 * membership of the requester and prepared the session.
 */
async function postLoggedGroupContent(
  ctx: RetryContext,
  device: SendLogDevice,
  payload: SendLogPayload,
  callbacks: RetryCallbacks,
  target: RetryResendTarget | undefined,
  job?: SendLogResendJob
): Promise<void> {
  const text = bytesToString(payload.plaintext);
  // The device reports that it cannot decrypt a message of the group, so it
  // can lack the current key. Its rows in the group go first, and an
  // accepted resend that carries the distribution records a new row. The
  // scope is the group only, as in the sender-key retry receipt of one
  // Signal client.
  await callbacks.invalidateSenderKeyHandoff(payload.groupId, device);
  const current = await callbacks.currentGroupDistribution(payload.groupId);
  const content =
    current === null
      ? text
      : ctx.contentAdapter.serializeContentBesideSenderKeyDistribution(
          text,
          current.groupId,
          current.distribution
        );
  if (job !== undefined) {
    const { failedEnvelopeId: _previous, ...rest } = job;
    await ctx.storage.storeResendJob({
      ...rest,
      ...(target && { failedEnvelopeId: target.failedEnvelopeId }),
      attempts: job.attempts + 1,
    });
  }
  await callbacks.resend(device.userId, device.deviceId, content, {
    timestamp: payload.clientTimestamp,
    contentHint: payload.contentHint,
    ...(target && { retry: target }),
    ...(current && { senderKeyHandoff: handoffOf(current) }),
  });
  const responses = await ctx.resendableContent.countResend(payload.clientMessageId, device);
  if (job !== undefined) await ctx.storage.completeResendJob(job.jobId, 'posted');
  ctx.logger.info('Resent logged group content after a retry request', {
    category: 'E2EE',
    data: {
      recipient: `${device.userId}:${device.deviceId}`,
      clientMessageId: payload.clientMessageId,
      responses,
      distribution: current !== null,
    },
  });
}

/**
 * Run one pending resend job, as the resend job driver does after a restart,
 * a reconnect or a failed post. The job ends as abandoned when it is older
 * than `SEND_LOG_RESEND_JOB_TTL_MS`, when its logged entry or the row of
 * the device is gone or expired, when the answer to its failed envelope
 * ended, when the row has its maximum count of resends, when the requester
 * is not a current member of the group, or when no session to the device
 * can be made. A membership refusal of the job that holds the failed
 * envelope also ends the answer with `membership-refused`. The membership
 * is checked again here. A group state that waits for an update defers the
 * job with `GroupResendDeferredError`. The job never resets a session: a
 * session is made only when there is none. A deferral and any other error
 * leave the job pending and propagate, so the driver runs it again later.
 */
export async function runResendJob(
  ctx: RetryContext,
  jobId: string,
  responseState: RetryResponseState,
  callbacks: RetryCallbacks
): Promise<void> {
  await withResendJob(ctx, jobId, async (job) => {
    const abandon = async (reason: string) => {
      ctx.logger.info('Abandoned a resend job', {
        category: 'E2EE',
        data: { jobId: job.jobId, clientMessageId: job.clientMessageId, reason },
      });
      await ctx.storage.completeResendJob(job.jobId, 'abandoned');
    };
    if (Date.now() - job.createdAt > SEND_LOG_RESEND_JOB_TTL_MS) return abandon('expired');
    const device = { userId: job.requesterUserId, deviceId: job.requesterDeviceId };
    const entry = await ctx.resendableContent.entry(job.clientMessageId, device);
    if (entry === null) return abandon('no-content');
    const retry: RetryRequestAttempt | undefined =
      job.failedEnvelopeId === undefined
        ? undefined
        : {
            failedEnvelopeId: job.failedEnvelopeId,
            retryId: job.retryId,
            requestEnvelopeId: job.requestEnvelopeId,
          };
    if (retry !== undefined) {
      const stored = await getRetryResend(
        ctx.storage,
        device.userId,
        device.deviceId,
        retry.failedEnvelopeId
      );
      if (stored?.terminal !== undefined) {
        await emitRetryResendTerminal(ctx, stored);
        return abandon('answer-ended');
      }
    }
    const requester: AnswerRequester = {
      requesterUserId: device.userId,
      requesterDeviceId: device.deviceId,
      failedTimestamp: entry.payload.clientTimestamp,
    };
    if (
      !(await admitsGroupResend(ctx, requester, entry.payload.groupId, responseState, callbacks))
    ) {
      if (retry !== undefined) await endRetryResend(ctx, requester, retry, 'membership-refused');
      return abandon('membership-refused');
    }
    if (reachedResendCap(ctx, entry)) return abandon('resend-limit');
    if (!(await prepareAnswerSession(ctx, requester, callbacks, retry, null))) {
      return abandon('no-session');
    }
    await postLoggedGroupContent(
      ctx,
      device,
      entry.payload,
      callbacks,
      retry && { ...retry, kind: 'resend' },
      job
    );
  });
}

/** The handoff that a resend with this distribution records on acceptance. */
function handoffOf(current: { groupId: string; distribution: SenderKeyDistributionMessage }): {
  groupId: string;
  senderKeyId: string;
  generation: number;
} {
  return {
    groupId: current.groupId,
    senderKeyId: current.distribution.senderKeyId,
    generation: current.distribution.generation,
  };
}

/**
 * Answer a sender-key failure with no row and no record with the current
 * sender-key distribution of the group alone. The caller checked the
 * membership of the requester. The requester then decrypts the later group
 * messages of this device, but not the failed one. It returns true when it
 * posted the distribution, or when the stored answer of this request attempt
 * has unknown acceptance. In that case nothing posts.
 */
async function resendCurrentDistribution(
  ctx: RetryContext,
  retryRequest: RetryRequest,
  groupId: string,
  callbacks: RetryCallbacks,
  retry: RetryRequestAttempt | undefined
): Promise<boolean> {
  const current = await callbacks.currentGroupDistribution(groupId);
  if (current === null) {
    ctx.logger.info('No sender key to distribute for a group retry request', {
      category: 'E2EE',
      data: { groupId, failedTimestamp: retryRequest.failedTimestamp },
    });
    return false;
  }
  if (!(await prepareAnswerSession(ctx, retryRequest, callbacks, retry, null))) return false;
  const answered = await callbacks.resend(
    retryRequest.requesterUserId,
    retryRequest.requesterDeviceId,
    ctx.contentAdapter.serializeSenderKeyDistributionText(current.groupId, current.distribution),
    {
      timestamp: retryRequest.failedTimestamp,
      ...(retry && { retry: { ...retry, kind: 'resend' } }),
      senderKeyHandoff: handoffOf(current),
    }
  );
  if (answered) {
    ctx.logger.info('Answered a group retry request with the current sender-key distribution', {
      category: 'E2EE',
      data: {
        recipient: `${retryRequest.requesterUserId}:${retryRequest.requesterDeviceId}`,
        groupId: current.groupId,
        failedTimestamp: retryRequest.failedTimestamp,
      },
    });
  }
  return answered;
}

/**
 * True when the requester is a current member of the group. A group with no
 * source of current membership refuses every resend, and the refusal is
 * logged once for the group. A group whose state waits for an update throws
 * `GroupResendDeferredError`: the resend is deferred, not refused, so a
 * stored job stays pending and the retry request stays unacknowledged.
 */
async function admitsGroupResend(
  ctx: RetryContext,
  retryRequest: AnswerRequester,
  groupId: string,
  responseState: RetryResponseState,
  callbacks: RetryCallbacks
): Promise<boolean> {
  const membership = await callbacks.groupMembership(groupId, retryRequest.requesterUserId);
  if (membership === 'member') return true;
  if (membership === 'unavailable') {
    ctx.logger.info('Deferring a group resend until the group state is current', {
      category: 'E2EE',
      data: {
        groupId,
        requester: `${retryRequest.requesterUserId}:${retryRequest.requesterDeviceId}`,
        failedTimestamp: retryRequest.failedTimestamp,
        behavior: 'RETRY_GROUP_RESEND_DEFERRED',
      },
    });
    throw new GroupResendDeferredError(groupId);
  }
  if (membership === 'no-source') {
    const rawGroupId = extractGroupId(groupId);
    if (!responseState.refusedGroupResends.has(rawGroupId)) {
      responseState.refusedGroupResends.add(rawGroupId);
      ctx.logger.warn('Refusing group resends: no source of current group membership', {
        category: 'E2EE',
        data: { groupId: rawGroupId, behavior: 'RETRY_GROUP_RESEND_REFUSED' },
      });
    }
    return false;
  }
  ctx.logger.warn('Refusing a group resend to a user who is not a current member', {
    category: 'E2EE',
    data: {
      groupId,
      requester: `${retryRequest.requesterUserId}:${retryRequest.requesterDeviceId}`,
      failedTimestamp: retryRequest.failedTimestamp,
    },
  });
  return false;
}

/**
 * Make the pairwise session to the requesting device ready for an answer.
 * With `reset`, the request carries the ratchet key of the failed message:
 * a session that did not advance since the sent message is archived and
 * replaced, as `sesameManager.handleRetryRequest` decides. A send log row
 * validates the request in place of a MessageRecord. Without `reset`, the
 * request names a sender-key failure: an existing session is used as it is,
 * and a new session is made only when there is none. It returns false when
 * the answer ends here.
 */
async function prepareAnswerSession(
  ctx: RetryContext,
  retryRequest: AnswerRequester,
  callbacks: RetryCallbacks,
  retry: RetryRequestAttempt | undefined,
  reset: {
    request: RetryRequest;
    sentRatchetKey: string;
    validated: 'message-record' | 'send-log';
  } | null
): Promise<boolean> {
  const currentSession = await ctx.sesameManager.getActiveSession(
    retryRequest.requesterUserId,
    retryRequest.requesterDeviceId
  );

  const address = ProtocolAddress.create(
    retryRequest.requesterUserId,
    retryRequest.requesterDeviceId
  );

  // Compare our current ratchet key (DHs) against the DHs at send time.
  // If DHs advanced (DH ratchet occurred), session is healthy. Reuse it.
  // If DHs matches or is missing, session has not advanced. Needs fresh bundle.
  const currentRatchetKey = currentSession?.DHs?.publicKey as string | undefined;
  const usable =
    reset === null
      ? currentSession !== null && currentSession !== undefined
      : currentSession !== null &&
        currentSession !== undefined &&
        currentRatchetKey !== undefined &&
        currentRatchetKey !== reset.sentRatchetKey;

  if (usable) {
    ctx.logger.debug('Using existing different session for retry (no prekey fetch)', {
      category: 'E2EE',
      data: {
        address: ProtocolAddress.toString(address),
        activeRatchetKey: currentRatchetKey?.substring(0, 12) + '...',
        ...(reset && { storedRatchetKey: reset.sentRatchetKey.substring(0, 12) + '...' }),
      },
    });
    return true;
  }

  if (reset !== null) {
    // Archive old session and create new session
    const result = await ctx.sesameManager.handleRetryRequest(
      reset.request,
      reset.validated === 'send-log' ? { skipMessageRecordValidation: true } : undefined
    );

    if (!result.requiresNewSession) {
      ctx.logger.debug('Retry request handled without resend', {
        category: 'E2EE',
        data: { action: result.action },
      });
      return false;
    }
  }

  return await startAnswerSession(ctx, retryRequest, callbacks, retry, !currentSession);
}

/**
 * Start a new initiating session to the requesting device from a fresh
 * prekey bundle. When the requester has no bundle, the answer ends with
 * `missing-prekey`, and it returns false.
 */
async function startAnswerSession(
  ctx: RetryContext,
  retryRequest: AnswerRequester,
  callbacks: RetryCallbacks,
  retry: RetryRequestAttempt | undefined,
  hadNoSession = false
): Promise<boolean> {
  const address = ProtocolAddress.create(
    retryRequest.requesterUserId,
    retryRequest.requesterDeviceId
  );
  // Fetch prekey bundle and create new initiating session
  if (!ctx.relay) {
    throw new Error('Relay not configured - cannot fetch prekey bundle');
  }

  const bundle = await ctx.relay.fetchPreKeyBundle(
    retryRequest.requesterUserId,
    retryRequest.requesterDeviceId
  );

  if (!bundle) {
    ctx.logger.warn('Failed to fetch prekey bundle for retry', {
      category: 'E2EE',
      data: {
        userId: retryRequest.requesterUserId,
        deviceId: retryRequest.requesterDeviceId,
      },
    });
    // The requester has no prekey bundle, so no resend can reach it.
    // The answer ends, and the request envelope is acknowledged.
    if (retry !== undefined) {
      await endRetryResend(ctx, retryRequest, retry, 'missing-prekey');
    }
    return false;
  }

  await callbacks.establishSession(address, bundle);

  ctx.logger.debug('Created new session for retry', {
    category: 'E2EE',
    data: {
      address: ProtocolAddress.toString(address),
      reason: hadNoSession ? 'no_session' : 'orphaned',
      retryReason: retryRequest.reason,
    },
  });
  return true;
}

/** A SesameError that refuses the retry request. A later attempt gets the same refusal. */
function isRetryRefusal(error: unknown): error is SesameError {
  return (
    error instanceof SesameError &&
    (error.code === 'RETRY_DISABLED' || error.code === 'WRONG_RETRY_DEVICE')
  );
}
