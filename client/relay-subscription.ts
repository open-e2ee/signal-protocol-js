/**
 * Relay subscription operations for SignalProtocolClient
 *
 * Extracted from DefaultSignalProtocolClient class to reduce file size (~330 lines).
 * Handles the relay subscription callback logic for incoming message processing.
 */

import type { Envelope } from '../remote/relay/types';
import { EncryptionError, EncryptionErrorCode, type Base64 } from '../types';
import { determineRetryReason, isRetryableDecryptionError } from './retry-utils';
import { checkRetryRateLimit, RETRY_REQUEST_WINDOW_MS, type RetryRequestAttempt } from './retry';
import type { DecryptedEnvelope } from './event-hooks';
import type {
  InspectedSignalProtocolContent,
  ParsedReceiptContent,
  ParsedTypingContent,
} from './content-adapter';
import type { SignalProtocolClientContext } from './types';
import type { RetryRequest, SesameMessage } from '../internal/sesame/types';
import { base64ToBytes } from '../internal/crypto';
import {
  getProcessedEnvelope,
  retryFamilyMember,
  storeProcessedEnvelope,
} from '../local/store/reliability';
import {
  deliveredEnvelopeFingerprint,
  pruneReceivedContent,
} from '../local/store/received-content';
import { isImplicitContentType } from './constants';
import type { SignalProtocolServiceCipher } from './signal-service-cipher';
import { rethrowRelayWorkStopped } from './relay-work';
import { postRetryRequest, readRetryRequestEnvelope } from './retry-request-envelope';
import { receiveInRetryFamily, type RetryFamilyReceive } from './retry-family';
import { unsealedEnvelopeOf } from './sealed-sender';
import { relayReceiptJoinOf } from './relay-receipt-join';

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
  /**
   * Resend the message that a `retry_request` envelope asks for, or refuse
   * it. A throw keeps the request envelope unacknowledged. The resend
   * derives its client message ID from the retry ID that the request
   * carries. The sender encrypts one resend for each request envelope ID.
   */
  handleRetryRequest: (
    request: RetryRequest,
    retry: RetryRequestAttempt | undefined
  ) => Promise<void>;
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
 * │                                                                 │
 * │ A 'retry_request' envelope is not encrypted. It skips           │
 * │ decryption and goes to handleRetryRequest.                      │
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
  return receiveInRetryFamily(ctx.storage, ctx.logger, envelope, (family) =>
    handleRelayMessageLocked(ctx, envelope, family, state, callbacks, config)
  );
}

async function handleRelayMessageLocked(
  ctx: RelaySubscriptionContext,
  envelope: Envelope,
  family: RetryFamilyReceive,
  state: RelaySubscriptionState,
  callbacks: RelaySubscriptionCallbacks,
  config: RelaySubscriptionConfig
): Promise<boolean> {
  const receiveId = envelope.id
    ? await deliveredEnvelopeFingerprint(ctx.userId, ctx.deviceId, envelope)
    : undefined;
  await pruneReceivedContent(ctx.storage);
  const processed = envelope.id ? await getProcessedEnvelope(ctx.storage, envelope.id) : null;
  if (processed) {
    if (receiveId) await ctx.storage.deleteReceivedContent(receiveId);
    // After the Relay forgets a row, the same ID can carry a new encryption.
    // The local device processed that ID, so it drops the new bytes too.
    const identityChanged = receiveId !== undefined && receiveId !== processed.fingerprint;
    ctx.logger.debug(
      identityChanged
        ? 'Acknowledging a processed relay envelope ID with changed content'
        : 'Acknowledging previously processed relay envelope',
      {
        category: 'E2EE',
        data: {
          envelopeId: envelope.id,
          behavior: 'PERSISTENT_DUPLICATE_DISCARD',
        },
      }
    );
    return true;
  }

  if (envelope.messageType === 'retry_request') {
    await handleRetryRequestEnvelope(ctx, envelope, callbacks);
    if (envelope.id) {
      await storeProcessedEnvelope(ctx.storage, envelope.id, Date.now(), receiveId);
    }
    return true;
  }

  if (!(await family.admit())) {
    if (envelope.id) await storeProcessedEnvelope(ctx.storage, envelope.id, Date.now(), receiveId);
    if (receiveId) await ctx.storage.deleteReceivedContent(receiveId);
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
    // A failure inside the seal names the unsealed sender, so the retry
    // request goes to that device. The unsealed envelope keeps the ID. A
    // member whose seal fails to open asks the device of its request.
    const failed = family.withRequestedSender(unsealedEnvelopeOf(error) ?? envelope);
    await handleDecryptionError(
      ctx,
      failed,
      error as Error,
      state,
      callbacks,
      config,
      receiveId,
      family
    );
    return false;
  }

  // Route by decrypted content type, not the outer relay-envelope type.
  const inspectedContent = ctx.contentAdapter.inspectContent(decryptedEnvelope.content);
  // A null message carries no content, so the application never gets it
  // and it fulfills nothing. It is acknowledged as a duplicate is.
  if (inspectedContent.nullMessage) {
    await family.consumeNull(receiveId);
  } else {
    await handleDecryptionSuccess(
      ctx,
      envelope,
      decryptedEnvelope,
      inspectedContent,
      state,
      callbacks
    );
    await family.fulfill();
    if (envelope.id) {
      await storeProcessedEnvelope(ctx.storage, envelope.id, Date.now(), receiveId);
    }
  }
  if (receiveId) await ctx.storage.deleteReceivedContent(receiveId);
  return true;
}

/**
 * Handle a `retry_request` envelope. The payload is not encrypted, so the
 * envelope never reaches decryption.
 *
 * The function returns normally when the request is handled, refused or
 * dropped, and the caller then acknowledges the envelope. It drops an
 * envelope from an anonymous sender and an envelope that does not decode,
 * with one warn line. An error from the handler propagates, so the envelope
 * stays in the mailbox for the next pull.
 */
async function handleRetryRequestEnvelope(
  ctx: RelaySubscriptionContext,
  envelope: Envelope,
  callbacks: RelaySubscriptionCallbacks
): Promise<void> {
  if (!envelope.senderUserId || !(envelope.senderDeviceId >= 1)) {
    ctx.logger.warn('Dropping retry request without an identified sender', {
      category: 'E2EE',
      data: { envelopeId: envelope.id, behavior: 'RETRY_REQUEST_DROP' },
    });
    return;
  }

  const read = readRetryRequestEnvelope(envelope, { userId: ctx.userId, deviceId: ctx.deviceId });
  if (!read.ok) {
    ctx.logger.warn('Dropping malformed retry request', {
      category: 'E2EE',
      data: {
        envelopeId: envelope.id,
        sender: `${envelope.senderUserId}:${envelope.senderDeviceId}`,
        cause: read.cause,
        behavior: 'RETRY_REQUEST_DROP',
      },
    });
    return;
  }

  // The requester names each request attempt
  // `<retryId>:retry-request[:n]`. The Signal Protocol Relay delivers that
  // name as the envelope ID. A relay that assigns its own envelope IDs
  // delivers it as the client message ID. The sender keys one resend
  // encryption by it and answers with its attempt number, so a redelivery
  // of the same request replays the stored resend.
  const requestEnvelopeId = envelope.clientMessageId ?? envelope.id;
  const member = requestEnvelopeId ? retryFamilyMember(requestEnvelopeId) : undefined;
  if (
    read.retry &&
    (member?.kind !== 'retry-request' || member.retryId !== read.retry.retryId)
  ) {
    ctx.logger.warn('Dropping malformed retry request', {
      category: 'E2EE',
      data: {
        envelopeId: envelope.id,
        sender: `${envelope.senderUserId}:${envelope.senderDeviceId}`,
        cause: 'envelope ID is not a request attempt of the retry ID',
        behavior: 'RETRY_REQUEST_DROP',
      },
    });
    return;
  }
  await callbacks.handleRetryRequest(
    read.request,
    read.retry && { ...read.retry, requestEnvelopeId: requestEnvelopeId! }
  );
}

/**
 * Handle successful message decryption
 */
async function handleDecryptionSuccess(
  ctx: RelaySubscriptionContext,
  envelope: Envelope,
  decryptedEnvelope: DecryptedEnvelope,
  inspectedContent: InspectedSignalProtocolContent,
  state: RelaySubscriptionState,
  callbacks: RelaySubscriptionCallbacks
): Promise<void> {
  // The inspected content tells a receipt, a typing indicator and a data
  // message apart.
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
    const receipts = ctx.config.deliveryReceipts ?? 'auto';
    if (decryptedEnvelope.timestamp && ctx.relay && receipts !== 'off') {
      if (inspectedContent.shouldSendDeliveryReceipt) {
        const { senderId, timestamp } = decryptedEnvelope;
        const accumulate = () =>
          accumulateDeliveryReceipt(
            state.receiptAccumulator,
            senderId,
            timestamp,
            callbacks.sendDeliveryReceipt,
            ctx.logger
          );
        // 'auto' leaves the receipt of an identified or unknown arrival to
        // the Relay when the reply to its acknowledgment lists it. A sealed
        // arrival, an ephemeral one, and one through a relay without a
        // receipt join always get the E2EE receipt.
        const join = receipts === 'auto' ? relayReceiptJoinOf(ctx.relay) : undefined;
        if (
          join !== undefined &&
          envelope.id !== undefined &&
          decryptedEnvelope.arrivedSealed !== true &&
          envelope.deliveryClass !== 'ephemeral'
        ) {
          join.await(envelope.id, (relayOwnsReceipt) => {
            if (!relayOwnsReceipt) accumulate();
          });
        } else {
          accumulate();
        }
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
 *
 * A failed resend or null message of a retry request asks again for its
 * failed envelope, whatever its content hint: the failed envelope still has
 * no content.
 */
async function handleDecryptionError(
  ctx: RelaySubscriptionContext,
  envelope: Envelope,
  error: Error,
  state: RelaySubscriptionState,
  callbacks: RelaySubscriptionCallbacks,
  config: RelaySubscriptionConfig,
  receiveId: string | undefined,
  family: RetryFamilyReceive
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

  if (family.member !== undefined && envelope.timestamp > 0) {
    await sendRetryRequest(ctx, envelope, error, state, callbacks, config, receiveId, family);
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
  await sendRetryRequest(ctx, envelope, error, state, callbacks, config, receiveId, family);
}

/**
 * Send a `retry_request` envelope to the device that sent a failed message.
 *
 * The checks run in this order: an identified sender that is not the local
 * device, then the per-sender rate limit, which counts each post. A failed
 * envelope that does not pass them gets no request, and the caller keeps it
 * or acknowledges it as for any failed envelope. The request is stored
 * under the failed envelope ID before its post, and a later failure of the
 * same envelope posts the stored request again.
 *
 * A failed resend or null message asks again for its failed envelope
 * through the retry family (`RetryFamilyReceive.requestRetry`).
 */
async function sendRetryRequest(
  ctx: RelaySubscriptionContext,
  envelope: Envelope,
  error: Error,
  state: RelaySubscriptionState,
  callbacks: RelaySubscriptionCallbacks,
  config: RelaySubscriptionConfig,
  receiveId: string | undefined,
  family: RetryFamilyReceive
): Promise<void> {
  try {
    // An anonymous envelope names no device to ask. A member stays
    // unacknowledged, so the content of its failed envelope is not lost.
    if (!envelope.senderUserId || !(envelope.senderDeviceId >= 1)) {
      ctx.logger.warn('No retry request for a failed envelope without an identified sender', {
        category: 'E2EE',
        data: {
          envelopeId: envelope.id,
          messageType: envelope.messageType,
          behavior: 'RETRY_REQUEST_SKIP',
        },
      });
      if (config.acknowledgeFailures !== false && family.member === undefined) {
        await markDeliveredSilently(ctx.relay, envelope.id, ctx.logger);
      }
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
      if (config.acknowledgeFailures !== false) {
        await markDeliveredSilently(ctx.relay, envelope.id, ctx.logger);
      }
      return;
    }

    // Convert envelope to SesameMessage format for retry request
    const failedMessage: SesameMessage = {
      senderUserId: envelope.senderUserId,
      senderDeviceId: envelope.senderDeviceId,
      recipientUserId: ctx.userId,
      recipientDeviceId: ctx.deviceId,
      sessionId: `${envelope.senderUserId}:${envelope.senderDeviceId}`,
      // A seal that fails to open gives no ratchet key.
      ciphertext:
        envelope.messageType === 'unidentified_sender'
          ? new Uint8Array()
          : typeof envelope.ciphertext === 'string'
            ? base64ToBytes(envelope.ciphertext as Base64)
            : (envelope.ciphertext as Uint8Array),
      isInitiating: envelope.messageType === 'prekey_bundle',
      initHeader: null,
      timestamp: envelope.timestamp,
    };

    const retryReason = determineRetryReason(error);

    if (!ctx.relay) throw new Error('Relay not configured - cannot send a retry request');
    const relay = ctx.relay;
    const posted = await family.requestRetry(receiveId, async (failed) => {
      // Receiver-side rate limiting. A post of a stored request counts too.
      if (!checkRetryRateLimit(state, envelope.senderUserId)) {
        ctx.logger.warn('Retry rate limit exceeded for sender', {
          category: 'E2EE',
          data: {
            senderId: envelope.senderUserId,
            windowMs: RETRY_REQUEST_WINDOW_MS,
          },
        });
        // A member stays unacknowledged, so its redelivery after the
        // window asks again.
        if (config.acknowledgeFailures !== false && family.member === undefined) {
          await markDeliveredSilently(ctx.relay, envelope.id, ctx.logger);
        }
        return false;
      }
      await postRetryRequest(
        ctx.storage,
        failed,
        async () => {
          // Handle stale prekey indicators
          await handleStalePreKeyIndicator(ctx, envelope, error, state, callbacks, config);
          const retryRequest = await ctx.sesameManager.createRetryRequest(
            failedMessage,
            retryReason
          );
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
          return retryRequest;
        },
        { userId: ctx.userId, deviceId: ctx.deviceId },
        (request) => relay.send(request)
      );
      ctx.logger.info('Retry request sent to sender', {
        category: 'E2EE',
        data: {
          originalSender: `${envelope.senderUserId}:${envelope.senderDeviceId}`,
          timestamp: envelope.timestamp,
          reason: retryReason,
          stored: failed.stored !== null,
        },
      });
      return true;
    });
    // An envelope with no post stays unacknowledged.
    if (!posted) return;

    // Mark failed message as delivered so it does not reappear
    if (envelope.id && config.acknowledgeFailures !== false) {
      try {
        await relay.markDelivered(envelope.id);
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
