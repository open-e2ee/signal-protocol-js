/**
 * Relay subscription operations for SignalProtocolClient
 *
 * Extracted from DefaultSignalProtocolClient class to reduce file size (~330 lines).
 * Handles the relay subscription callback logic for incoming message processing.
 */

import type { Envelope } from '../remote/relay/types';
import { EncryptionError, EncryptionErrorCode, type Base64 } from '../types';
import { determineRetryReason, isRetryableDecryptionError } from './retry-utils';
import { checkRetryRateLimit, RETRY_REQUEST_WINDOW_MS } from './retry';
import type { DecryptedEnvelope } from './event-hooks';
import type { ParsedReceiptContent, ParsedTypingContent } from './content-adapter';
import type { SignalProtocolClientContext } from './types';
import type { SesameMessage } from '../internal/sesame/types';
import { base64ToBytes } from '../internal/crypto';
import {
  hasProcessedEnvelope,
  storeProcessedEnvelope,
  withProcessedEnvelopeLock,
} from '../local/store/reliability';
import { receivedContentId, pruneReceivedContent } from '../local/store/received-content';
import { isImplicitContentType } from './constants';
import type { SignalProtocolServiceCipher } from './signal-service-cipher';
import { rethrowRelayWorkStopped } from './relay-work';

// ════════════════════════════════════════════════════════════════════════════
// TYPES
// ════════════════════════════════════════════════════════════════════════════

/**
 * Extended context for relay subscription operations
 */
export {};
export interface RelaySubscriptionContext extends SignalProtocolClientContext {
  cipher: SignalProtocolServiceCipher;
  /** Ends lock waits when the tracked receive work stops. */
  stopSignal?: AbortSignal;
}

/** Accumulates delivery receipt timestamps per sender for batching */
export interface ReceiptAccumulator {
  /** senderUserId → the waiting timestamps, and when the first of them arrived */
  pending: Map<string, { timestamps: number[]; firstArrivalAt: number }>;
  timers: Map<string, ReturnType<typeof setTimeout>>; // senderUserId → flush timer
  /**
   * True from the first receipt flush of stop() to the end of the step that
   * clears its tracking state. The hold also ends when stop() throws in
   * those steps. A batch then sets no timer and does not flush at
   * RECEIPT_BATCH_MAX, and stopRelaySubscription() does not flush it. stop()
   * sends the batches that wait at each of its flushes and drops a batch
   * made during the hold after its last flush.
   */
  held: boolean;
}

/** A batch flushes this long after its last arrival. */
export const RECEIPT_BATCH_DELAY_MS = 3_000;
/** A batch flushes no later than this long after its first arrival. */
export const RECEIPT_BATCH_MAX_AGE_MS = 30_000;
/** A batch flushes when it holds this many timestamps. */
export const RECEIPT_BATCH_MAX = 100;
/**
 * stop() waits this long, from its start, for the delivery receipt sends in
 * progress and for the receipt sends that it starts.
 */
export const STOP_RECEIPT_FLUSH_MS = 5_000;

/**
 * Mutable state for relay subscription (passed by client, mutated in place)
 */
export interface RelaySubscriptionState {
  /** Timestamp of last forced prekey rotation */
  lastPreKeyRotationTime: number;
  /** LRU-capped map: senderId → {count, lastReceivedTime} for rate limiting */
  retryRateLimitCounts: Map<string, { count: number; lastReceivedTime: number }>;
  /** Accumulator for batching delivery receipts */
  receiptAccumulator: ReceiptAccumulator;
}

/**
 * Callbacks that delegate back to SignalProtocolClient methods
 */
export interface RelaySubscriptionCallbacks {
  /** Generate replacement prekeys and upload their public material. */
  forcePreKeyRotation: () => Promise<void>;
  /** Handle delivery receipt message */
  handleDeliveryReceipt: (
    envelope: Envelope,
    receipt: ParsedReceiptContent | null
  ) => Promise<void>;
  /** Handle typing indicator message */
  handleTypingIndicator: (envelope: Envelope, typing: ParsedTypingContent | null) => Promise<void>;
  /** Send delivery receipt back to sender (all devices) */
  sendDeliveryReceipt: (userId: string, timestamps: number[]) => Promise<void>;
}

/**
 * Configuration constants for relay subscription
 */
export interface RelaySubscriptionConfig {
  /** Debounce interval for forced prekey rotations in ms */
  keyRotationDebounceMs: number;
  /** Background pulls retain failed envelopes instead of acknowledging retry requests. */
  acknowledgeFailures?: boolean;
}

// ════════════════════════════════════════════════════════════════════════════
// HELPERS
// ════════════════════════════════════════════════════════════════════════════

/**
 * Mark a message as delivered on the relay, silently ignoring errors
 */
async function markDeliveredSilently(
  relay: { markDelivered?: (id: string) => Promise<void> } | undefined,
  envelopeId: string | undefined,
  logger: RelaySubscriptionContext['logger']
): Promise<void> {
  if (!envelopeId || !relay?.markDelivered) return;

  try {
    await relay.markDelivered(envelopeId);
  } catch (error) {
    logger.warn('Failed to mark message as delivered', {
      category: 'E2EE',
      data: { envelopeId, error: (error as Error).message },
    });
  }
}

// ════════════════════════════════════════════════════════════════════════════
// MAIN HANDLER
// ════════════════════════════════════════════════════════════════════════════

/**
 * Handle incoming relay message - main subscription callback
 *
 * This is the core logic extracted from SignalProtocolClient.startRelaySubscription().
 * Handles decryption, success paths (hooks, delivery receipts), and error paths
 * (ContentHint classification, retry requests, stale prekey handling).
 *
 * MESSAGE ROUTING ARCHITECTURE (profile):
 *
 * ```
 * ┌─────────────────────────────────────────────────────────────────┐
 * │ All messages arrive as 'ciphertext' envelopes (or 'prekey_bundle')
 * │ The relay contract carries only the outer ciphertext type.      │
 * │                                                                 │
 * │ After decryption, the Content proto is inspected:               │
 * │   → dataMessage: Content → onMessageDecrypted → ContentRouter   │
 * │   → receiptMessage: Receipt → handleDeliveryReceipt             │
 * │   → typingMessage: Typing → handleTypingIndicator               │
 * └─────────────────────────────────────────────────────────────────┘
 * ```
 *
 * Why receipts/typing bypass ContentRouter:
 * - Receipts update message STATUS, not create new content
 * - Typing indicators are ephemeral (no storage needed)
 * - No schema validation or domain routing needed for these
 */
export async function handleRelayMessage(
  ctx: RelaySubscriptionContext,
  envelope: Envelope,
  state: RelaySubscriptionState,
  callbacks: RelaySubscriptionCallbacks,
  config: RelaySubscriptionConfig
): Promise<void> {
  if (await processRelayMessage(ctx, envelope, state, callbacks, config)) {
    await markDeliveredSilently(ctx.relay, envelope.id, ctx.logger);
  }
}

/** Process content before either foreground or background transport acknowledges it. */
export async function processRelayMessage(
  ctx: RelaySubscriptionContext,
  envelope: Envelope,
  state: RelaySubscriptionState,
  callbacks: RelaySubscriptionCallbacks,
  config: RelaySubscriptionConfig
): Promise<boolean> {
  if (!envelope.id) {
    return handleRelayMessageLocked(ctx, envelope, state, callbacks, config);
  }
  return withProcessedEnvelopeLock(ctx.storage, envelope.id, () =>
    handleRelayMessageLocked(ctx, envelope, state, callbacks, config)
  );
}

async function handleRelayMessageLocked(
  ctx: RelaySubscriptionContext,
  envelope: Envelope,
  state: RelaySubscriptionState,
  callbacks: RelaySubscriptionCallbacks,
  config: RelaySubscriptionConfig
): Promise<boolean> {
  const receiveId = envelope.id
    ? await receivedContentId(ctx.userId, ctx.deviceId, envelope)
    : undefined;
  await pruneReceivedContent(ctx.storage);
  if (
    envelope.id &&
    (await hasProcessedEnvelope(ctx.storage, envelope.id, Date.now(), receiveId))
  ) {
    if (receiveId) await ctx.storage.deleteReceivedContent(receiveId);
    ctx.logger.debug('Acknowledging previously processed relay envelope', {
      category: 'E2EE',
      data: {
        envelopeId: envelope.id,
        behavior: 'PERSISTENT_DUPLICATE_DISCARD',
      },
    });
    return true;
  }

  if (!ctx.hooks?.onMessageDecrypted) {
    throw new Error('Register onMessageDecrypted before receiving Relay messages');
  }
  let decryptedEnvelope: DecryptedEnvelope;
  try {
    // Delegate decryption to SignalProtocolServiceCipher
    // Pass sealed sender config for unidentified_sender envelope handling
    decryptedEnvelope = await ctx.cipher.decrypt(
      envelope, ctx.config.sealedSender, receiveId, ctx.stopSignal
    );
  } catch (error) {
    rethrowRelayWorkStopped(error);
    // ERROR: Handle decryption failure
    await handleDecryptionError(ctx, envelope, error as Error, state, callbacks, config);
    return false;
  }

  await handleDecryptionSuccess(ctx, envelope, decryptedEnvelope, state, callbacks);
  if (envelope.id) await storeProcessedEnvelope(ctx.storage, envelope.id, Date.now(), receiveId);
  if (receiveId) await ctx.storage.deleteReceivedContent(receiveId);
  return true;
}

/**
 * Handle successful message decryption
 */
async function handleDecryptionSuccess(
  ctx: RelaySubscriptionContext,
  envelope: Envelope,
  decryptedEnvelope: DecryptedEnvelope,
  state: RelaySubscriptionState,
  callbacks: RelaySubscriptionCallbacks
): Promise<void> {
  // Route by decrypted content type, not the outer relay-envelope type.
  // Parse content to determine if it is a receipt, typing indicator, or data message.
  const inspectedContent = ctx.contentAdapter.inspectContent(decryptedEnvelope.content);
  const { receipt, typing } = inspectedContent;
  const authenticatedEnvelope = {
    ...envelope,
    senderUserId: decryptedEnvelope.senderId,
    senderDeviceId: decryptedEnvelope.senderDeviceId,
  };

  // A peer's profile key in authenticated 1:1 content. The exchange never throws.
  if (
    inspectedContent.profileKey !== undefined &&
    !decryptedEnvelope.isGroup &&
    decryptedEnvelope.senderId !== ctx.userId
  ) {
    await ctx.profileKeys?.incoming(decryptedEnvelope.senderId, inspectedContent.profileKey);
  }

  if (inspectedContent.senderKeyDistribution) {
    // The cipher installed this authenticated distribution before returning.
    return;
  } else if (inspectedContent.profileKeyUpdate) {
    // A key-update DataMessage carries only the profile key, kept above.
    return;
  } else if (receipt) {
    await callbacks.handleDeliveryReceipt(authenticatedEnvelope, receipt);
  } else if (typing) {
    // Typing indicators are transient - no storage, no delivery receipt
    await callbacks.handleTypingIndicator(authenticatedEnvelope, typing);
  } else {
    // Call hook: message decrypted (ContentManager stores in encrypted DB)
    const receive = ctx.hooks?.onMessageDecrypted;
    if (!receive) throw new Error('Register onMessageDecrypted before receiving Relay messages');
    await receive(decryptedEnvelope);

    // Batch delivery receipts before sending
    // Multi-device: sendDeliveryReceipt fans out to all sender's devices
    // 'auto' is the default, and it sends as 'always' does, for a sealed,
    // identified, or unknown arrival.
    const receipts = ctx.config.deliveryReceipts ?? 'auto';
    if (decryptedEnvelope.timestamp && ctx.relay && receipts !== 'off') {
      if (inspectedContent.shouldSendDeliveryReceipt) {
        accumulateDeliveryReceipt(
          state.receiptAccumulator,
          decryptedEnvelope.senderId,
          decryptedEnvelope.timestamp,
          callbacks.sendDeliveryReceipt,
          ctx.logger
        );
      }
    }
  }
}

// ════════════════════════════════════════════════════════════════════════════
// DELIVERY RECEIPT BATCHING
// ════════════════════════════════════════════════════════════════════════════

/**
 * Accumulate a delivery receipt timestamp for batched sending.
 *
 * Receipts are collected per sender. A batch flushes when it reaches
 * RECEIPT_BATCH_MAX, or at the earlier of RECEIPT_BATCH_DELAY_MS after its
 * last arrival and RECEIPT_BATCH_MAX_AGE_MS after its first arrival. So steady
 * traffic delays a receipt by at most RECEIPT_BATCH_MAX_AGE_MS. While the
 * accumulator is held, the batch waits for stop() to flush it.
 */
function accumulateDeliveryReceipt(
  acc: ReceiptAccumulator,
  senderUserId: string,
  timestamp: number,
  flush: (userId: string, timestamps: number[]) => Promise<void>,
  logger: RelaySubscriptionContext['logger']
): void {
  const now = Date.now();
  const batch = acc.pending.get(senderUserId) ?? { timestamps: [], firstArrivalAt: now };
  batch.timestamps.push(timestamp);
  acc.pending.set(senderUserId, batch);
  if (acc.held) return;

  if (batch.timestamps.length >= RECEIPT_BATCH_MAX) {
    flushReceipts(acc, senderUserId, flush, logger);
    return;
  }

  const existingTimer = acc.timers.get(senderUserId);
  if (existingTimer) clearTimeout(existingTimer);

  const flushAt = Math.min(
    now + RECEIPT_BATCH_DELAY_MS,
    batch.firstArrivalAt + RECEIPT_BATCH_MAX_AGE_MS
  );
  acc.timers.set(
    senderUserId,
    setTimeout(() => {
      flushReceipts(acc, senderUserId, flush, logger);
    }, Math.max(0, flushAt - now))
  );
}

/**
 * Flush the waiting delivery receipts of every sender, once each.
 *
 * Each batch leaves the accumulator and its timer stops, so no later timer
 * sends it again. Call this before the relay subscription closes. The
 * returned promises settle when the sends finish. They never reject.
 */
export function flushPendingReceipts(
  acc: ReceiptAccumulator,
  flush: (userId: string, timestamps: number[]) => Promise<void>,
  logger: RelaySubscriptionContext['logger']
): Promise<void>[] {
  const sends: Promise<void>[] = [];
  for (const senderUserId of [...acc.pending.keys()]) {
    const send = flushReceipts(acc, senderUserId, flush, logger);
    if (send) sends.push(send);
  }
  return sends;
}

/**
 * Flush accumulated delivery receipts for a sender. The returned promise
 * settles when the send finishes, and never rejects. It is undefined when the
 * sender has no waiting receipt.
 */
function flushReceipts(
  acc: ReceiptAccumulator,
  senderUserId: string,
  flush: (userId: string, timestamps: number[]) => Promise<void>,
  logger: RelaySubscriptionContext['logger']
): Promise<void> | undefined {
  const timer = acc.timers.get(senderUserId);
  if (timer) clearTimeout(timer);
  acc.timers.delete(senderUserId);

  const batch = acc.pending.get(senderUserId);
  acc.pending.delete(senderUserId);
  if (!batch?.timestamps.length) return undefined;

  // The batch timer does not wait for the send. stop() does.
  return flush(senderUserId, batch.timestamps).catch((err) =>
    logger.warn('Failed to flush delivery receipts', {
      category: 'E2EE',
      data: { senderUserId, error: (err as Error).message },
    })
  );
}

/**
 * Handle decryption error with retry logic
 *
 * Classifies failures by ContentHint:
 * - IMPLICIT: silently discard (typing indicators, receipts, legacy messages)
 * - RESENDABLE: request retry from sender
 */
async function handleDecryptionError(
  ctx: RelaySubscriptionContext,
  envelope: Envelope,
  error: Error,
  state: RelaySubscriptionState,
  callbacks: RelaySubscriptionCallbacks,
  config: RelaySubscriptionConfig
): Promise<void> {
  // A consumed ratchet key proves decryption, not application persistence.
  // Only the processed-envelope receipt above can authorize duplicate ACKs.
  if (error instanceof EncryptionError && error.code === EncryptionErrorCode.MESSAGE_DUPLICATE) {
    ctx.logger.debug('Retaining unhandled duplicate relay envelope without retry', {
      category: 'E2EE',
      data: {
        envelopeId: envelope.id,
        senderUserId: envelope.senderUserId,
        senderDeviceId: envelope.senderDeviceId,
        behavior: 'UNHANDLED_DUPLICATE',
      },
    });
    return;
  }

  // Early exit: Implicit messages (typing indicators, receipts) should be
  // silently discarded without ERROR-level logs. This prevents log spam
  // for expected failures on messages that will not be retried anyway.
  if (isImplicitContentType(envelope)) {
    ctx.logger.debug('Discarding undecryptable protocol message (IMPLICIT)', {
      category: 'E2EE',
      data: {
        senderUserId: envelope.senderUserId,
        senderDeviceId: envelope.senderDeviceId,
        messageType: envelope.messageType,
        deliveryClass: envelope.deliveryClass,
        timestamp: envelope.timestamp,
        reason: 'Protocol message - ephemeral, no retry',
        behavior: 'IMPLICIT_DISCARD',
        errorType: error.name,
      },
    });

    if (config.acknowledgeFailures !== false) {
      await markDeliveredSilently(ctx.relay, envelope.id, ctx.logger);
    }
    return;
  }

  // Log errors for non-implicit messages that actually matter
  const isExpectedRetryCase = isRetryableDecryptionError(error);

  if (isExpectedRetryCase) {
    ctx.logger.info('Message requires retry (expected recovery flow)', {
      category: 'E2EE',
      data: {
        envelopeId: envelope.id,
        senderId: envelope.senderUserId,
        messageType: envelope.messageType,
        deliveryClass: envelope.deliveryClass,
        reason: error.message,
      },
    });
  } else {
    ctx.logger.error('Error handling incoming envelope', {
      category: 'E2EE',
      error,
      data: {
        envelopeId: envelope.id,
        senderId: envelope.senderUserId,
        messageType: envelope.messageType,
        deliveryClass: envelope.deliveryClass,
      },
    });
  }

  // Check if message can be retried (requires timestamp for identification)
  // Per Signal Protocol, retry requests use timestamp, not sequenceNumber
  const canRetry = envelope.timestamp !== undefined && envelope.timestamp > 0;

  if (!canRetry) {
    // IMPLICIT behavior: silently discard legacy messages without timestamp
    ctx.logger.warn('Discarding undecryptable legacy message (IMPLICIT)', {
      category: 'E2EE',
      data: {
        senderUserId: envelope.senderUserId,
        senderDeviceId: envelope.senderDeviceId,
        messageType: envelope.messageType,
        reason: 'No timestamp - cannot request retry',
        behavior: 'IMPLICIT_DISCARD',
      },
    });

    if (config.acknowledgeFailures !== false) {
      await markDeliveredSilently(ctx.relay, envelope.id, ctx.logger);
    }
    return;
  }

  // RESENDABLE behavior: request retry from sender
  await sendRetryRequest(ctx, envelope, error, state, callbacks, config);
}

/**
 * Send retry request for failed message decryption
 */
async function sendRetryRequest(
  ctx: RelaySubscriptionContext,
  envelope: Envelope,
  error: Error,
  state: RelaySubscriptionState,
  callbacks: RelaySubscriptionCallbacks,
  config: RelaySubscriptionConfig
): Promise<void> {
  try {
    // Convert envelope to SesameMessage format for retry request
    const failedMessage: SesameMessage = {
      senderUserId: envelope.senderUserId,
      senderDeviceId: envelope.senderDeviceId,
      recipientUserId: ctx.userId,
      recipientDeviceId: ctx.deviceId,
      sessionId: `${envelope.senderUserId}:${envelope.senderDeviceId}`,
      ciphertext:
        typeof envelope.ciphertext === 'string'
          ? base64ToBytes(envelope.ciphertext as Base64)
          : (envelope.ciphertext as Uint8Array),
      isInitiating: envelope.messageType === 'prekey_bundle',
      initHeader: null,
      timestamp: envelope.timestamp,
    };

    const retryReason = determineRetryReason(error);

    // Receiver-side rate limiting
    if (!checkRetryRateLimit(state, envelope.senderUserId)) {
      ctx.logger.warn('Retry rate limit exceeded for sender', {
        category: 'E2EE',
        data: {
          senderId: envelope.senderUserId,
          windowMs: RETRY_REQUEST_WINDOW_MS,
        },
      });
      if (config.acknowledgeFailures !== false) {
        await markDeliveredSilently(ctx.relay, envelope.id, ctx.logger);
      }
      return;
    }

    // Handle stale prekey indicators
    await handleStalePreKeyIndicator(ctx, envelope, error, state, callbacks, config);

    // Create retry request via SESAME manager
    const retryRequest = await ctx.sesameManager.createRetryRequest(failedMessage, retryReason);

    ctx.logger.info('Retry request created for failed message', {
      category: 'E2EE',
      data: {
        sender: `${envelope.senderUserId}:${envelope.senderDeviceId}`,
        timestamp: envelope.timestamp,
        reason: retryReason,
        localUserId: ctx.userId,
        localDeviceId: ctx.deviceId,
      },
    });

    // Send retry request via relay
    if (ctx.relay?.sendRetryRequest) {
      await ctx.relay.sendRetryRequest(retryRequest);
      ctx.logger.info('Retry request sent to sender', {
        category: 'E2EE',
        data: {
          originalSender: `${envelope.senderUserId}:${envelope.senderDeviceId}`,
          timestamp: envelope.timestamp,
          reason: retryReason,
        },
      });

      // Mark failed message as delivered so it does not reappear
      if (envelope.id && config.acknowledgeFailures !== false) {
        try {
          await ctx.relay.markDelivered(envelope.id);
          ctx.logger.debug('Marked failed message as delivered after retry request', {
            category: 'E2EE',
            data: { envelopeId: envelope.id },
          });
        } catch (markError) {
          ctx.logger.warn('Failed to mark message as delivered after retry', {
            category: 'E2EE',
            data: {
              envelopeId: envelope.id,
              error: (markError as Error).message,
            },
          });
        }
      }
    } else {
      ctx.logger.debug('Relay does not support retry requests', {
        category: 'E2EE',
      });
    }
  } catch (retryError) {
    ctx.logger.warn('Failed to send retry request', {
      category: 'E2EE',
      data: {
        originalError: error.message,
        retryError: (retryError as Error).message,
      },
    });
  }
}

/**
 * Handle stale prekey indicators by forcing prekey rotation
 *
 * Generate new keys and upload to server before sending retry request.
 * This handles both server-lost-keys AND local key corruption / PQXDH §4.13
 * identifier collisions.
 *
 * Triggers on:
 * 1. PREKEY_NOT_FOUND - server does not have the key we expect
 * 2. DECRYPTION_FAILED on PreKeyMessage - MAC failure on fresh session
 */
async function handleStalePreKeyIndicator(
  ctx: RelaySubscriptionContext,
  envelope: Envelope,
  error: Error,
  state: RelaySubscriptionState,
  callbacks: RelaySubscriptionCallbacks,
  config: RelaySubscriptionConfig
): Promise<void> {
  const isStalePreKeyIndicator =
    error instanceof EncryptionError &&
    (error.code === EncryptionErrorCode.PREKEY_NOT_FOUND ||
      (error.code === EncryptionErrorCode.DECRYPTION_FAILED &&
        envelope.messageType === 'prekey_bundle'));

  if (!isStalePreKeyIndicator) return;

  // Debounce forced rotation across repeated stale-prekey indicators.
  const now = Date.now();
  const timeSinceLastRotation = now - state.lastPreKeyRotationTime;

  if (timeSinceLastRotation > config.keyRotationDebounceMs || timeSinceLastRotation < 0) {
    try {
      const reason =
        error.code === EncryptionErrorCode.PREKEY_NOT_FOUND
          ? 'PREKEY_NOT_FOUND'
          : 'MAC_FAILED_ON_PREKEY_MESSAGE';

      ctx.logger.info('Stale prekey detected: forcing prekey rotation before retry', {
        category: 'E2EE',
        data: {
          reason,
          messageType: envelope.messageType,
        },
      });

      await callbacks.forcePreKeyRotation();
      state.lastPreKeyRotationTime = Date.now();
    } catch (rotationError) {
      ctx.logger.warn('Failed to force prekey rotation', {
        category: 'E2EE',
        data: { error: (rotationError as Error).message },
      });
    }
  } else {
    ctx.logger.debug('Stale prekey detected: skipping rotation (debounced)', {
      category: 'E2EE',
      data: { timeSinceLastRotationMs: timeSinceLastRotation },
    });
  }
}
