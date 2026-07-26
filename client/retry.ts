/**
 * Retry operations for SignalProtocolClient (SESAME Protocol)
 *
 * Extracted from SignalProtocolClient class to reduce file size.
 * Handles retry request creation, sending, and response handling.
 */

import type { ISignalProtocolRelayServer } from '../remote/relay/types';
import type { PreKeyBundle } from '../keys';
import { EncryptionError, EncryptionErrorCode } from '../types';
import { ContentHint } from '../types/messages';
import { ProtocolAddress } from '../types/address';
import { determineRetryReason } from './retry-utils';
import type {
  SignalProtocolClientContext,
  IncomingEnvelope,
  ProcessEnvelopeOptions,
  SendResult,
  DataMessageInput,
} from './types';
import {
  RetryReason,
  type ISesameManager,
  type SesameMessage,
  type RetryRequest,
} from '../internal/sesame/types';
import {
  isImplicitContentType,
  MESSAGE_RECORD_TTL_MS,
  MAX_RETRY_RESPONSES_PER_MESSAGE,
} from './constants';
import { DEFAULT_STATE_CONFIG, SIGNAL_PROTOCOL_CLIENT_CONSTANTS } from './state';
import { base64ToBytes } from '../internal/crypto/utils';
import type { Base64 } from '../types/utils';

/**
 * State for retry deduplication (passed by client, mutated in place)
 */
export {};
export interface RetryDedupState {
  /** Tracks recent retry requests: key = `${sessionId}:${timestamp}`, value = request time */
  recentRetryRequests: Map<string, number>;
  /** Timestamp of last cleanup */
  lastRetryCleanupTime: number;
  /** Tracks retry response counts per message: key = dedupKey, value = response count */
  retryResponseCounts: Map<string, number>;
}

/**
 * Extended context for retry operations (adds sesame and relay)
 */
export interface RetryContext extends SignalProtocolClientContext {
  sesameManager: ISesameManager;
}

/**
 * Callbacks for operations that need to delegate back to SignalProtocolClient
 */
export interface RetryCallbacks {
  /** Archive a session (for orphaned session handling) */
  archiveSession: (address: ProtocolAddress) => Promise<void>;
  /** Establish a new session with prekey bundle */
  establishSession: (address: ProtocolAddress, bundle: PreKeyBundle) => Promise<void>;
  /** Send a message to a recipient */
  send: (
    recipientId: string,
    content: DataMessageInput | string | Uint8Array,
    options?: { timestamp?: number; contentHint?: ContentHint }
  ) => Promise<SendResult>;
  /** Generate replacement prekeys and upload their public material. */
  forcePreKeyRotation: () => Promise<void>;
}

/**
 * Configuration constants for retry operations
 */
export interface RetryConfig {
  /** Debounce interval for forced prekey rotations in ms */
  keyRotationDebounceMs: number;
  /** Deduplication window for retry requests in ms */
  retryDedupWindowMs: number;
  /** Cleanup interval for retry dedup entries in ms */
  retryCleanupIntervalMs: number;
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

  // New sender — evict least-recently-used entry if at capacity
  if (rateLimitState.retryRateLimitCounts.size >= MAX_RATE_LIMIT_ENTRIES) {
    const oldestKey = rateLimitState.retryRateLimitCounts.keys().next().value;
    if (oldestKey) rateLimitState.retryRateLimitCounts.delete(oldestKey);
  }

  rateLimitState.retryRateLimitCounts.set(senderId, { count: 1, lastReceivedTime: now });
  return true;
}

/**
 * Default configuration values
 * Imports common values from state.ts to avoid duplication
 */
export const DEFAULT_RETRY_CONFIG: RetryConfig = {
  // Import shared values from SignalProtocolClientStateConfig
  retryDedupWindowMs: DEFAULT_STATE_CONFIG.retryDedupWindowMs,
  retryCleanupIntervalMs: DEFAULT_STATE_CONFIG.retryCleanupIntervalMs,
  // Retry-specific values
  keyRotationDebounceMs: SIGNAL_PROTOCOL_CLIENT_CONSTANTS.KEY_ROTATION_DEBOUNCE_MS,
};

/**
 * Mark a message as delivered silently (without throwing on failure)
 */
async function markMessageDeliveredSilently(
  messageId: string | undefined,
  relay: ISignalProtocolRelayServer | undefined,
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
  ctx: RetryContext
): Promise<void> {
  await callbacks.send(retryRequest.requesterUserId, ctx.contentAdapter.serializeNullMessage(), {
    // Reuse failed timestamp for correlation with the retry request.
    timestamp: retryRequest.failedTimestamp,
    // The reference implementation treats null-message reset responses as implicit/protocol content.
    contentHint: ContentHint.Implicit,
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
 * Uses relay if available, otherwise falls back to options callback.
 * Handles IMPLICIT content type discarding, rate limiting, and stale prekey rotation.
 *
 * @param ctx - Retry context with dependencies
 * @param envelope - The failed message envelope
 * @param error - The decryption error
 * @param rateLimitState - State for rate limiting (mutated in place)
 * @param callbacks - Callbacks for operations needing SignalProtocolClient
 * @param config - Configuration constants
 * @param options - Optional transport callbacks (for background without relay)
 */
export async function sendRetryRequestInternal(
  ctx: RetryContext,
  envelope: IncomingEnvelope,
  error: Error,
  rateLimitState: RetryRateLimitState,
  callbacks: Pick<RetryCallbacks, 'forcePreKeyRotation'>,
  config: RetryConfig,
  options?: ProcessEnvelopeOptions
): Promise<void> {
  try {
    // Implicit messages (typing indicators, receipts) don't store MessageRecords -
    // retry would always fail. The Signal Protocol behavior is to discard it.
    if (isImplicitContentType(envelope)) {
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

    const retryReason = determineRetryReason(error);

    // Receiver-side rate limiting
    if (!checkRetryRateLimit(rateLimitState, envelope.senderUserId)) {
      ctx.logger.warn('Retry rate limit exceeded for sender', {
        category: 'E2EE',
        data: { senderId: envelope.senderUserId, windowMs: RETRY_REQUEST_WINDOW_MS },
      });
      await markMessageDeliveredSilently(envelope.id, ctx.relay, ctx.logger, options);
      return;
    }

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
      failedCiphertext = base64ToBytes(envelope.ciphertext as Base64);
    } catch {
      // Keep empty ciphertext for malformed envelopes; retry request still proceeds.
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
    const retryRequest = await ctx.sesameManager.createRetryRequest(failedMessage, retryReason);

    // Send via relay (foreground) or callback (background)
    if (ctx.relay?.sendRetryRequest) {
      await ctx.relay.sendRetryRequest(retryRequest);
    } else if (options?.sendRetryRequest) {
      await options.sendRetryRequest(retryRequest);
    } else {
      ctx.logger.warn('Cannot send retry request: no relay or callback', { category: 'E2EE' });
      return;
    }

    ctx.logger.info('Sent retry request for failed decryption', {
      category: 'E2EE',
      data: {
        sender: `${envelope.senderUserId}:${envelope.senderDeviceId}`,
        timestamp: envelope.timestamp,
        reason: retryReason,
      },
    });

    // Mark failed message as delivered so it doesn't reappear
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
 * 1. Looks up the MessageRecord for the failed sequence number
 * 2. Verifies the requester is the intended recipient
 * 3. Checks retry limits and TTL
 * 4. Creates new session if orphaned, or uses existing different session
 * 5. Re-encrypts and sends the original message
 * 6. Deletes the old MessageRecord
 *
 * @param ctx - Retry context with dependencies
 * @param retryRequest - The retry request from the recipient
 * @param dedupState - State for deduplication (mutated in place)
 * @param callbacks - Callbacks for SignalProtocolClient operations
 * @param config - Configuration constants
 */
export async function handleRetryRequestAndResend(
  ctx: RetryContext,
  retryRequest: RetryRequest,
  dedupState: RetryDedupState,
  callbacks: RetryCallbacks,
  config: RetryConfig
): Promise<void> {
  const sessionId = `${retryRequest.requesterUserId}:${retryRequest.requesterDeviceId}`;

  // Deduplication check: ignore duplicate retry requests within the window
  // Use timestamp for dedup key
  const dedupKey = `${sessionId}:${retryRequest.failedTimestamp}`;
  const now = Date.now();
  const lastProcessed = dedupState.recentRetryRequests.get(dedupKey);

  if (lastProcessed && now - lastProcessed < config.retryDedupWindowMs) {
    ctx.logger.debug('Ignoring duplicate retry request within dedup window', {
      category: 'E2EE',
      data: {
        dedupKey,
        msSinceLastProcess: now - lastProcessed,
        windowMs: config.retryDedupWindowMs,
      },
    });
    return;
  }

  // Enforce retry response limit
  // Prevents infinite retry loops when decryption consistently fails
  const responseCount = dedupState.retryResponseCounts.get(dedupKey) ?? 0;
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

  // Mark this retry request as being processed
  dedupState.recentRetryRequests.set(dedupKey, now);

  // Clean up old entries periodically
  if (now - dedupState.lastRetryCleanupTime > config.retryCleanupIntervalMs) {
    dedupState.lastRetryCleanupTime = now;
    const cutoff = now - config.retryDedupWindowMs * 2;
    for (const [key, timestamp] of dedupState.recentRetryRequests) {
      if (timestamp < cutoff) {
        dedupState.recentRetryRequests.delete(key);
      }
    }
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
        await sendNullMessageForRetryReset(callbacks, retryRequest, ctx);
        // Null-message fallbacks are not retryable payloads. Delete the
        // synthetic record created by the generic send pipeline.
        await ctx.storage.deleteMessageRecord(sessionId, retryRequest.failedTimestamp).catch(() => {
          // Non-fatal: retry fallback already sent.
        });
        dedupState.retryResponseCounts.set(dedupKey, responseCount + 1);

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

    // 4. Get current session to check for orphaned session
    const currentSession = await ctx.sesameManager.getActiveSession(
      retryRequest.requesterUserId,
      retryRequest.requesterDeviceId
    );

    const address = ProtocolAddress.create(
      retryRequest.requesterUserId,
      retryRequest.requesterDeviceId
    );

    // Compare our current ratchet key (DHs) against the DHs stored at send time (sessionStateId).
    // If DHs advanced (DH ratchet occurred), session is healthy — reuse it.
    // If DHs matches or is missing, session hasn't advanced — needs fresh bundle.
    // The send record captures the local ratchet key because the retry request
    // does not carry a peer-authenticated copy.
    const senderRatchetKey = currentSession?.DHs?.publicKey as string | undefined;
    const isOrphanedSession =
      !currentSession || !senderRatchetKey || senderRatchetKey === record.sessionStateId;
    const needsFreshBundle = isOrphanedSession;

    if (needsFreshBundle) {
      // 5a. Need fresh bundle: Archive old session and create new session
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
      // 5b. Different active session exists AND not MAC failure - use it directly
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

    // 6. SESAME Step 4-5: Re-encrypt and send the original message
    // reuse original timestamp for envelope alignment
    await callbacks.send(retryRequest.requesterUserId, record.plaintext, {
      timestamp: record.timestamp,
    });

    // Track retry response count
    dedupState.retryResponseCounts.set(dedupKey, responseCount + 1);

    // 7. Delete old MessageRecord after successful resend (using timestamp as primary identifier)
    await ctx.storage.deleteMessageRecord(sessionId, record.timestamp);

    ctx.logger.info('Message resent successfully after retry request', {
      category: 'E2EE',
      data: {
        recipient: sessionId,
        failedTimestamp: retryRequest.failedTimestamp,
      },
    });
  } catch (error) {
    ctx.logger.error('Failed to handle retry request', {
      category: 'E2EE',
      error: error as Error,
      data: {
        sessionId,
        failedTimestamp: retryRequest.failedTimestamp,
      },
    });
    // Don't rethrow - let the subscription continue processing other requests
  }
}
