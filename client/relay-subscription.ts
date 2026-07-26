/**
 * Relay subscription operations for SignalProtocolClient
 *
 * Extracted from SignalProtocolClient class to reduce file size (~330 lines).
 * Handles the relay subscription callback logic for incoming message processing.
 */

import type { Envelope } from '../remote/relay/types';
import { EncryptionError, EncryptionErrorCode, type Base64 } from '../types';
import { determineRetryReason, isRetryableDecryptionError } from './retry-utils';
import { checkRetryRateLimit, RETRY_REQUEST_WINDOW_MS } from './retry';
import { callHook, type DecryptedEnvelope } from './event-hooks';
import type { ParsedReceiptContent, ParsedTypingContent } from './content-adapter';
import type { SignalProtocolClientContext } from './types';
import type { SesameMessage } from '../internal/sesame/types';
import { base64ToBytes } from '../internal/crypto';
import { isImplicitContentType } from './constants';
import type { SignalProtocolServiceCipher } from './signal-service-cipher';

// ════════════════════════════════════════════════════════════════════════════
// TYPES
// ════════════════════════════════════════════════════════════════════════════

/**
 * Extended context for relay subscription operations
 */
export {};
export interface RelaySubscriptionContext extends SignalProtocolClientContext {
  cipher: SignalProtocolServiceCipher;
}

/** Accumulates delivery receipt timestamps per sender for batching */
export interface ReceiptAccumulator {
  pending: Map<string, number[]>; // senderUserId → timestamps
  timers: Map<string, ReturnType<typeof setTimeout>>; // senderUserId → flush timer
}

export const RECEIPT_BATCH_DELAY_MS = 3_000;
export const RECEIPT_BATCH_MAX = 100;

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
 * ┌─────────────────────────────────────────────────────────────────┐
 * │ All messages arrive as 'ciphertext' envelopes (or 'prekey_bundle')
 * │ The relay contract carries only the outer ciphertext type.      │
 * │                                                                 │
 * │ After decryption, the Content proto is inspected:               │
 * │   → dataMessage: Content → onMessageDecrypted → ContentRouter   │
 * │   → receiptMessage: Receipt → handleDeliveryReceipt             │
 * │   → typingMessage: Typing → handleTypingIndicator               │
 * └─────────────────────────────────────────────────────────────────┘
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
  try {
    // Delegate decryption to SignalProtocolServiceCipher
    // Pass sealed sender config for unidentified_sender envelope handling
    const decryptedEnvelope = await ctx.cipher.decrypt(envelope, ctx.config.sealedSender);

    // SUCCESS: Handle successful decryption
    await handleDecryptionSuccess(ctx, envelope, decryptedEnvelope, state, callbacks);
  } catch (error) {
    // ERROR: Handle decryption failure
    await handleDecryptionError(ctx, envelope, error as Error, state, callbacks, config);
  }
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
  // Parse content to determine if it's a receipt, typing indicator, or data message.
  const inspectedContent = ctx.contentAdapter.inspectContent(decryptedEnvelope.content);
  const { receipt, typing } = inspectedContent;

  if (receipt) {
    await callbacks.handleDeliveryReceipt(envelope, receipt);
  } else if (typing) {
    // Typing indicators are transient - no storage, no delivery receipt
    await callbacks.handleTypingIndicator(envelope, typing);
  } else {
    // Call hook: message decrypted (ContentManager stores in encrypted DB)
    await callHook(ctx.hooks, 'onMessageDecrypted', decryptedEnvelope);

    // Batch delivery receipts before sending
    // Multi-device: sendDeliveryReceipt fans out to all sender's devices
    if (decryptedEnvelope.timestamp && ctx.relay) {
      if (inspectedContent.shouldSendDeliveryReceipt) {
        accumulateDeliveryReceipt(
          state.receiptAccumulator,
          envelope.senderUserId,
          decryptedEnvelope.timestamp,
          callbacks.sendDeliveryReceipt,
          ctx.logger
        );
      }
    }
  }

  // Mark as delivered on relay
  await markDeliveredSilently(ctx.relay, envelope.id, ctx.logger);
}

// ════════════════════════════════════════════════════════════════════════════
// DELIVERY RECEIPT BATCHING
// ════════════════════════════════════════════════════════════════════════════

/**
 * Accumulate a delivery receipt timestamp for batched sending.
 *
 * Receipts are collected per-sender and flushed either when the batch
 * reaches RECEIPT_BATCH_MAX or after RECEIPT_BATCH_DELAY_MS, whichever
 * comes first.
 */
function accumulateDeliveryReceipt(
  acc: ReceiptAccumulator,
  senderUserId: string,
  timestamp: number,
  flush: (userId: string, timestamps: number[]) => Promise<void>,
  logger: RelaySubscriptionContext['logger']
): void {
  const existing = acc.pending.get(senderUserId) ?? [];
  existing.push(timestamp);
  acc.pending.set(senderUserId, existing);

  if (existing.length >= RECEIPT_BATCH_MAX) {
    flushReceipts(acc, senderUserId, flush, logger);
    return;
  }

  // Reset timer for this sender
  const existingTimer = acc.timers.get(senderUserId);
  if (existingTimer) clearTimeout(existingTimer);

  acc.timers.set(
    senderUserId,
    setTimeout(() => {
      flushReceipts(acc, senderUserId, flush, logger);
    }, RECEIPT_BATCH_DELAY_MS)
  );
}

/**
 * Flush accumulated delivery receipts for a sender
 */
function flushReceipts(
  acc: ReceiptAccumulator,
  senderUserId: string,
  flush: (userId: string, timestamps: number[]) => Promise<void>,
  logger: RelaySubscriptionContext['logger']
): void {
  const timestamps = acc.pending.get(senderUserId);
  if (!timestamps?.length) return;

  acc.pending.delete(senderUserId);
  const timer = acc.timers.get(senderUserId);
  if (timer) clearTimeout(timer);
  acc.timers.delete(senderUserId);

  // Fire and forget
  flush(senderUserId, timestamps).catch((err) =>
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
  // An at-least-once relay may redeliver the same envelope. The session layer
  // has already rejected the replay, so acknowledge it without asking the
  // sender to create a fresh ciphertext for plaintext already delivered.
  if (
    error instanceof EncryptionError &&
    error.code === EncryptionErrorCode.MESSAGE_DUPLICATE
  ) {
    ctx.logger.debug('Discarding duplicate relay envelope without retry', {
      category: 'E2EE',
      data: {
        envelopeId: envelope.id,
        senderUserId: envelope.senderUserId,
        senderDeviceId: envelope.senderDeviceId,
        behavior: 'DUPLICATE_DISCARD',
      },
    });
    await markDeliveredSilently(ctx.relay, envelope.id, ctx.logger);
    return;
  }

  // Early exit: Implicit messages (typing indicators, receipts) should be
  // silently discarded without ERROR-level logs. This prevents log spam
  // for expected failures on messages that won't be retried anyway.
  if (isImplicitContentType(envelope)) {
    ctx.logger.debug('Discarding undecryptable protocol message (IMPLICIT)', {
      category: 'E2EE',
      data: {
        senderUserId: envelope.senderUserId,
        senderDeviceId: envelope.senderDeviceId,
        messageType: envelope.messageType,
        timestamp: envelope.timestamp,
        reason: 'Protocol message - ephemeral, no retry',
        behavior: 'IMPLICIT_DISCARD',
        errorType: error.name,
      },
    });

    await markDeliveredSilently(ctx.relay, envelope.id, ctx.logger);
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

    await markDeliveredSilently(ctx.relay, envelope.id, ctx.logger);
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
        data: { senderId: envelope.senderUserId, windowMs: RETRY_REQUEST_WINDOW_MS },
      });
      await markDeliveredSilently(ctx.relay, envelope.id, ctx.logger);
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

      // Mark failed message as delivered so it doesn't reappear
      if (envelope.id) {
        try {
          await ctx.relay.markDelivered(envelope.id);
          ctx.logger.debug('Marked failed message as delivered after retry request', {
            category: 'E2EE',
            data: { envelopeId: envelope.id },
          });
        } catch (markError) {
          ctx.logger.warn('Failed to mark message as delivered after retry', {
            category: 'E2EE',
            data: { envelopeId: envelope.id, error: (markError as Error).message },
          });
        }
      }
    } else {
      ctx.logger.debug('Relay does not support retry requests', { category: 'E2EE' });
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
 * 1. PREKEY_NOT_FOUND - server doesn't have the key we expect
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
