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
import { determineRetryReason } from './retry-utils';
import { postRetryRequest } from './retry-request-envelope';
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
  MESSAGE_RECORD_TTL_MS,
  MAX_RETRY_RESPONSES_PER_MESSAGE,
} from './constants';
import { SIGNAL_PROTOCOL_CLIENT_CONSTANTS } from './state';
import { base64ToBytes } from '../internal/crypto/utils';
import type { Base64 } from '../types/utils';
import type { MessageRecord } from '../types/api';
import {
  getRetryResend,
  RELIABILITY_RECORD_TTL_MS,
  type RetryResendTarget,
} from '../local/store/reliability';

/**
 * Retry response state (passed by client, mutated in place)
 */
export {};
export interface RetryResponseState {
  /** Retry responses per message: key = `${sessionId}:${failedTimestamp}`, value = response count */
  retryResponseCounts: Map<string, number>;
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
   * attempt or kind encrypts again, and the resend takes the attempt
   * number of the request. A new encryption for the same request attempt,
   * as after the Relay refuses the stored bytes as expired, posts the same
   * ID: the processed ledger of the requester and the RETRY_CONFLICT
   * answer of the Relay cover the new bytes. Null content posts only a
   * stored attempt. It returns false only when null content has no stored
   * attempt to post.
   */
  resend: (
    userId: string,
    deviceId: number,
    content: string | null,
    options: { timestamp: number; contentHint?: ContentHint; retry?: RetryResendTarget }
  ) => Promise<boolean>;
  /** Generate replacement prekeys and upload their public material. */
  forcePreKeyRotation: () => Promise<void>;
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
 * Post the stored resend or null message that answered this request
 * envelope again: the post of that answer did not complete. It does no
 * session work. It returns false when the sender stored no answer to this
 * request envelope, or when the Relay refuses the stored answer as expired
 * and the plaintext is gone. A stored answer to another request envelope is
 * an earlier attempt: the caller answers this one with a new encryption.
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
  // The plaintext is gone after a delivery receipt or the record TTL.
  const plaintext = record?.recipientUserId === requesterUserId ? record.plaintext : null;
  return await callbacks.resend(requesterUserId, requesterDeviceId, plaintext, {
    timestamp: record?.timestamp ?? retryRequest.failedTimestamp,
    retry: { ...retry, kind: 'resend' },
  });
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
 * envelope ID before its post, and a later failure of the same envelope posts
 * the stored request again. The rate limit counts each post. A failed resend
 * or null message asks again for its failed envelope through the retry
 * family, whatever its content hint. A member that fails with an error that
 * is not retryable posts nothing here, and its redelivery on the pull path
 * asks again.
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
    const send = relay ? (request: Envelope) => relay.send(request) : options?.sendRetryRequest;
    const createRequest = async (): Promise<RetryRequest> => {
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
      return ctx.sesameManager.createRetryRequest(failedMessage, retryReason);
    };
    const posted = await family.requestRetry(fingerprint, async (failed) => {
      // Receiver-side rate limiting. A post of a stored request counts too.
      if (!checkRetryRateLimit(rateLimitState, envelope.senderUserId)) {
        ctx.logger.warn('Retry rate limit exceeded for sender', {
          category: 'E2EE',
          data: { senderId: envelope.senderUserId, windowMs: RETRY_REQUEST_WINDOW_MS },
        });
        // A member stays unacknowledged, so its redelivery after the
        // window asks again.
        if (family.member === undefined) {
          await markMessageDeliveredSilently(envelope.id, ctx.relay, ctx.logger, options);
        }
        return false;
      }
      if (!send) {
        ctx.logger.warn('Cannot send retry request: no relay or callback', { category: 'E2EE' });
        return false;
      }
      await postRetryRequest(
        ctx.storage,
        failed,
        createRequest,
        { userId: ctx.userId, deviceId: ctx.deviceId },
        send
      );
      return true;
    });
    // An envelope with no post stays unacknowledged.
    if (!posted) return;

    ctx.logger.info('Sent retry request for failed decryption', {
      category: 'E2EE',
      data: {
        sender: `${envelope.senderUserId}:${envelope.senderDeviceId}`,
        timestamp: envelope.timestamp,
        reason: retryReason,
      },
    });

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
 * 1. Looks up the MessageRecord for the failed sequence number. When the
 *    sender already stored a resend or a null message for this request
 *    envelope, it posts the stored bytes again and does no session work
 * 2. Verifies the requester is the intended recipient
 * 3. Checks retry limits and TTL
 * 4. Creates new session if orphaned, or uses existing different session
 * 5. Re-encrypts and sends the original message, which replaces the old
 *    MessageRecord with the record of the new encryption. Only a delivery
 *    receipt from the device or the TTL deletes that record.
 *
 * It refuses a request for a message sent more than
 * `RELIABILITY_RECORD_TTL_MS` ago, before it reads a stored resend. The
 * Relay can keep the last resend post for that time again, and the
 * requester keeps its retry records for both periods.
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

  if (Date.now() - retryRequest.failedTimestamp > RELIABILITY_RECORD_TTL_MS) {
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

  // The response count of one message is keyed by its session and timestamp.
  const dedupKey = `${sessionId}:${retryRequest.failedTimestamp}`;

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

  ctx.logger.info('Processing retry request', {
    category: 'E2EE',
    data: {
      from: sessionId,
      failedTimestamp: retryRequest.failedTimestamp,
      reason: retryRequest.reason,
    },
  });

  try {
    // Look up the original outbound record by peer session and timestamp.
    const record = await ctx.storage.getMessageRecord(sessionId, retryRequest.failedTimestamp);

    // The sender already answered this request envelope, and the post did
    // not complete. Post the stored bytes again, with no session work.
    if (
      retry !== undefined &&
      (await replayStoredResend(ctx, retryRequest, record, callbacks, retry))
    ) {
      responseState.retryResponseCounts.set(dedupKey, responseCount + 1);
      ctx.logger.info('Posted the stored resend of this request attempt again', {
        category: 'E2EE',
        data: { sessionId, failedTimestamp: retryRequest.failedTimestamp },
      });
      return;
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
      // no longer present in the send log.
      const shouldAttemptNullFallback = retryRequest.reason === RetryReason.DECRYPTION_FAILED;
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

    // 2. Check message TTL
    if (Date.now() - record.createdAt > MESSAGE_RECORD_TTL_MS) {
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

    // 3. Get current session to check for orphaned session
    const currentSession = await ctx.sesameManager.getActiveSession(
      retryRequest.requesterUserId,
      retryRequest.requesterDeviceId
    );

    const address = ProtocolAddress.create(
      retryRequest.requesterUserId,
      retryRequest.requesterDeviceId
    );

    // Compare our current ratchet key (DHs) against the DHs stored at send time (sessionStateId).
    // If DHs advanced (DH ratchet occurred), session is healthy. Reuse it.
    // If DHs matches or is missing, session has not advanced. Needs fresh bundle.
    // The send record captures the local ratchet key because the retry request
    // does not carry a peer-authenticated copy.
    const senderRatchetKey = currentSession?.DHs?.publicKey as string | undefined;
    const isOrphanedSession =
      !currentSession || !senderRatchetKey || senderRatchetKey === record.sessionStateId;
    const needsFreshBundle = isOrphanedSession;

    if (needsFreshBundle) {
      // 4a. Need fresh bundle: Archive old session and create new session
      const result = await ctx.sesameManager.handleRetryRequest(retryRequest);

      if (!result.requiresNewSession) {
        ctx.logger.debug('Retry request handled without resend', {
          category: 'E2EE',
          data: { action: result.action },
        });
        return;
      }

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
        return;
      }

      await callbacks.establishSession(address, bundle);

      const sessionReason = !currentSession ? 'no_session' : 'orphaned';

      ctx.logger.debug('Created new session for retry', {
        category: 'E2EE',
        data: {
          address: ProtocolAddress.toString(address),
          reason: sessionReason,
          retryReason: retryRequest.reason,
        },
      });
    } else {
      // 4b. Different active session exists AND not MAC failure - use it directly
      ctx.logger.debug('Using existing different session for retry (no prekey fetch)', {
        category: 'E2EE',
        data: {
          address: ProtocolAddress.toString(address),
          activeRatchetKey:
            (currentSession.DHs?.publicKey as string | undefined)?.substring(0, 12) + '...',
          storedRatchetKey: record.sessionStateId.substring(0, 12) + '...',
        },
      });
    }

    // 5. SESAME Step 4-5: Re-encrypt the original message and send it only
    // to the device that asked. Reuse the original timestamp for envelope
    // alignment. The post has a fresh operation epoch.
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
    // TTL deletes it, so a failed resend can be requested again.

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

/** A SesameError that refuses the retry request. A later attempt gets the same refusal. */
function isRetryRefusal(error: unknown): error is SesameError {
  return (
    error instanceof SesameError &&
    (error.code === 'RETRY_DISABLED' || error.code === 'WRONG_RETRY_DEVICE')
  );
}
