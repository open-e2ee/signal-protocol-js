/**
 * Relay subscription operations for SignalProtocolClient
 *
 * Extracted from DefaultSignalProtocolClient class to reduce file size (~330 lines).
 * Handles the relay subscription callback logic for incoming message processing.
 */

import type { Envelope } from '../remote/relay/types';
import { EncryptionError, EncryptionErrorCode, type Base64 } from '../types';
import {
  determineRetryReason,
  isRetryableDecryptionError,
  retryFailedEnvelope,
} from './retry-utils';
import { checkRetryRateLimit, RETRY_REQUEST_WINDOW_MS, type RetryRequestAttempt } from './retry';
import { receiveRefusal, reportReceiveRefusal } from './delivery-error';
import type {
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
import { deliveredEnvelopeFingerprint } from '../local/store/received-content';
import { isImplicitContentType } from './constants';
import type {
  CommittedContent,
  EnvelopeCommit,
  SignalProtocolServiceCipher,
} from './signal-service-cipher';
import { rethrowRelayWorkStopped } from './relay-work';
import { readRetryRequestEnvelope, retryRequestPost } from './retry-request-envelope';
import { acknowledgesRetryRequest, requestRetryInFamily } from './retry-request-lifecycle';
import { receiveInRetryFamily, type RetryFamilyReceive } from './retry-family';
import { SealedRetryRequestReceived, unsealedEnvelopeOf } from './sealed-sender';
import { failedGroupOf } from './retry-terminal-recovery';
import { relayReceiptJoinOf } from './relay-receipt-join';
import { createReceiveCommit } from './receive-work-seed';
import { completeReceiveWork, denyReceiveWork, type ReceiveQueue } from './receive-queue';

// ════════════════════════════════════════════════════════════════════════════
// TYPES
// ════════════════════════════════════════════════════════════════════════════

/**
 * Extended context for relay subscription operations
 */
export {};
export interface RelaySubscriptionContext extends SignalProtocolClientContext {
  cipher: SignalProtocolServiceCipher;
  /** The processor of the committed receive records. */
  receiveQueue: ReceiveQueue;
  /** Ends lock waits when the tracked receive work stops. */
  stopSignal?: AbortSignal;
}

/** Accumulates delivery receipt timestamps per sender for batching */
export interface ReceiptAccumulator {
  /**
   * senderUserId → the waiting timestamps, when the first of them arrived,
   * and the settle callback of each timestamp
   */
  pending: Map<string, ReceiptBatch>;
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

/** The waiting delivery receipts of one sender. */
export interface ReceiptBatch {
  timestamps: number[];
  firstArrivalAt: number;
  /** One callback per timestamp. It gets the error of a failed send. */
  settles: Array<(error?: unknown) => void>;
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
 * The handler commits the envelope and acknowledges it once its content is
 * stored (`processRelayMessage`). The receive queue then decides on its
 * group, gives it to the application, and sends its delivery receipt. The
 * handler also runs the error paths: ContentHint classification, retry
 * requests, and stale prekey handling.
 *
 * MESSAGE ROUTING ARCHITECTURE (profile):
 *
 * ```
 * ┌─────────────────────────────────────────────────────────────────┐
 * │ All messages arrive as 'ciphertext' envelopes (or 'prekey_bundle')
 * │ The relay contract carries only the outer ciphertext type.      │
 * │                                                                 │
 * │ After the commit, the receive queue inspects the Content proto: │
 * │   → dataMessage: Content → onMessageDecrypted → ContentRouter   │
 * │   → receiptMessage: Receipt → handleDeliveryReceipt             │
 * │   → typingMessage: Typing → handleTypingIndicator               │
 * │                                                                 │
 * │ A 'retry_request' envelope is not ratchet-encrypted. An         │
 * │ identified one skips decryption. A sealed one is routed after   │
 * │ the unseal. Both go to handleRetryRequest.                      │
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
  // A queue pass skips the record until the transport has its acknowledgment.
  const release = ctx.receiveQueue.hold(
    await deliveredEnvelopeFingerprint(ctx.userId, ctx.deviceId, envelope)
  );
  try {
    if (await processRelayMessage(ctx, envelope, state, callbacks, config)) {
      await markDeliveredSilently(ctx.relay, envelope.id, ctx.logger);
    }
  } finally {
    release();
    ctx.receiveQueue.wake();
  }
}

/**
 * Commit one Relay envelope before either foreground or background
 * transport acknowledges it.
 *
 * @returns True when the transport can acknowledge the envelope: its
 *   content is committed as a receive record, its distribution is
 *   installed when the record is a Relay record or there is no record (a
 *   reused caller record leaves the distribution with its caller), and the
 *   retry family recorded its arrival (outcome 1). Also
 *   true for an envelope that the client drops or refuses. False when the
 *   envelope must stay at the Relay.
 */
export async function processRelayMessage(
  ctx: RelaySubscriptionContext,
  envelope: Envelope,
  state: RelaySubscriptionState,
  callbacks: RelaySubscriptionCallbacks,
  config: RelaySubscriptionConfig
): Promise<boolean> {
  // The record sorts after the stored records once the resume ends. The
  // wait comes before the retry family lock, which the resume also takes.
  await ctx.receiveQueue.seeded();
  return receiveInRetryFamily(ctx.storage, ctx.logger, ctx.hooks, envelope, (family) =>
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
  const workId = await deliveredEnvelopeFingerprint(ctx.userId, ctx.deviceId, envelope);
  // The processed record of an envelope with no ID has no key.
  const receiveId = envelope.id ? workId : undefined;
  const processed = envelope.id ? await getProcessedEnvelope(ctx.storage, envelope.id) : null;
  if (processed) {
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
    // SDK 11 could stop between its processed write and the delete of its
    // received content, and it deleted that row on the redelivery. The
    // converted record of that row completes here. The application has its
    // content, so no hook runs.
    const converted = await ctx.storage.getReceiveWork(workId);
    if (converted?.awaitingEnvelope) await completeReceiveWork(ctx, converted);
    return true;
  }

  if (envelope.messageType === 'retry_request') {
    await handleRetryRequestEnvelope(ctx, envelope, callbacks);
    if (envelope.id) {
      await storeProcessedEnvelope(ctx.storage, envelope.id, Date.now(), receiveId);
    }
    return true;
  }

  if (!(await family.admit(receiveId))) {
    if (envelope.id) await storeProcessedEnvelope(ctx.storage, envelope.id, Date.now(), receiveId);
    return true;
  }

  const receipts = ctx.config.deliveryReceipts ?? 'auto';
  const join =
    receipts === 'auto' && ctx.relay !== undefined ? relayReceiptJoinOf(ctx.relay) : undefined;
  const handle = createReceiveCommit({
    storage: ctx.storage,
    policy: ctx.receiveQueue.policy,
    logger: ctx.logger,
    contentAdapter: ctx.contentAdapter,
    family,
    workId,
    origin: 'relay',
    receiptJoin: join !== undefined,
  });
  let commit: EnvelopeCommit;
  try {
    // The commit stores the decrypted content with the ratchet step.
    commit = await ctx.cipher.commitEnvelope(envelope, {
      sealedSender: ctx.config.sealedSender,
      stopSignal: ctx.stopSignal,
      work: handle.commit,
    });
  } catch (error) {
    rethrowRelayWorkStopped(error);
    // A seal that holds a retry request goes to the same handler as an
    // identified one. It never asks for a resend of itself.
    if (error instanceof SealedRetryRequestReceived) {
      await handleRetryRequestEnvelope(ctx, error.envelope, callbacks);
      if (envelope.id) {
        await storeProcessedEnvelope(ctx.storage, envelope.id, Date.now(), receiveId);
      }
      return true;
    }
    // The decrypt succeeded and its store commit failed. The ratchet step
    // rolled back, so the redelivery decrypts again. It asks for no resend.
    // One Signal client also sends no acknowledgment when its commit fails.
    if (handle.seeded()) {
      ctx.logger.warn('The receive record of a decrypted envelope failed to commit', {
        category: 'E2EE',
        data: {
          envelopeId: envelope.id,
          behavior: 'RECEIVE_COMMIT_FAILED',
          error: (error as Error).message,
        },
      });
      return false;
    }
    // A failure inside the seal names the unsealed sender, so the retry
    // request goes to that device. The unsealed envelope keeps the ID. A
    // member whose seal fails to open asks the device of its request.
    const failed = family.withRequestedSender(unsealedEnvelopeOf(error) ?? envelope);
    // A failure that no resend can repair asks for nothing. The envelope
    // is processed and acknowledged, on this path and on the other.
    const refusal = receiveRefusal(error);
    if (refusal !== null) {
      ctx.logger.error('Error handling incoming envelope', {
        category: 'E2EE',
        error,
        data: {
          envelopeId: failed.id,
          senderId: failed.senderUserId,
          messageType: failed.messageType,
          deliveryClass: failed.deliveryClass,
          refusal,
        },
      });
      await reportReceiveRefusal(ctx.storage, ctx.hooks, failed, error as Error, receiveId);
      return true;
    }
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

  switch (commit.kind) {
    // The queue has no room. The envelope stays at the Relay.
    case 'refused':
      return false;
    // The application has the content. The queue owns the rest.
    case 'settled':
      return true;
    // The ratchet step is spent, so a resend cannot repair the content.
    case 'denied':
      await denyReceiveWork(
        ctx,
        commit.record,
        { ...commit, ...(envelope.id && { envelopeId: envelope.id, workId }) },
        commit.error
      );
      return true;
  }
  const { content, record } = commit;
  // A null message carries no content, so the application never gets it
  // and it fulfills nothing. It is acknowledged as a duplicate is.
  if (content.inspected.nullMessage) {
    await family.consumeNull(receiveId);
    if (record) await completeReceiveWork(ctx, record);
    return true;
  }
  // Outcome 1: the arrival of a resend, before the acknowledgment.
  await family.fulfill({
    senderKeyDistribution: content.inspected.senderKeyDistribution !== undefined,
    content:
      content.inspected.senderKeyDistribution === undefined ||
      content.inspected.senderKeyDistributionOnly === false,
    ...groupOfFulfill(content),
  });
  // 'auto' leaves the receipt of an identified arrival to the Relay when
  // the reply to its acknowledgment lists it. The record keeps the intent,
  // and the queue keeps the decision.
  if (join !== undefined && envelope.id && record?.ackIntent?.hasReceiptJoin) {
    const queue = ctx.receiveQueue;
    join.await(envelope.id, (relayOwnsReceipt) => queue.joinDecided(workId, relayOwnsReceipt));
  }
  return true;
}

/** The raw group of committed content, for the request record of a resend. */
export function groupOfFulfill(content: CommittedContent): { groupId?: string } {
  const groupId =
    content.transportGroupId ??
    (content.inspected.senderKeyDistributionOnly === false ? content.distributionGroupId : null);
  return groupId === null ? {} : { groupId };
}

/**
 * Handle a `retry_request` envelope: an identified one, or the unsealed
 * envelope of a sealed one, whose sender comes from the validated sender
 * certificate. The payload is not ratchet-encrypted, so the envelope never
 * reaches a ratchet decrypt.
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
 *
 * @returns Resolves when the batch that holds the timestamp is sent, and
 *   rejects with the error of a failed send. It never settles for a batch
 *   that stop() drops: the receive queue sends that receipt again after
 *   the next start.
 */
export function accumulateDeliveryReceipt(
  acc: ReceiptAccumulator,
  senderUserId: string,
  timestamp: number,
  flush: (userId: string, timestamps: number[]) => Promise<void>,
  logger: RelaySubscriptionContext['logger']
): Promise<void> {
  const now = Date.now();
  const batch = acc.pending.get(senderUserId) ?? {
    timestamps: [],
    firstArrivalAt: now,
    settles: [],
  };
  const sent = new Promise<void>((resolve, reject) => {
    batch.settles.push((error) => (error === undefined ? resolve() : reject(error)));
  });
  batch.timestamps.push(timestamp);
  acc.pending.set(senderUserId, batch);
  if (acc.held) return sent;

  if (batch.timestamps.length >= RECEIPT_BATCH_MAX) {
    void flushReceipts(acc, senderUserId, flush, logger);
    return sent;
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
      void flushReceipts(acc, senderUserId, flush, logger);
    }, Math.max(0, flushAt - now))
  );
  return sent;
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

  // The batch timer does not wait for the send. stop() does. Each
  // timestamp learns the result, so the receive queue keeps a receipt that
  // failed and sends it again.
  return flush(senderUserId, batch.timestamps).then(
    () => {
      for (const settle of batch.settles) settle();
    },
    (err: unknown) => {
      logger.warn('Failed to flush delivery receipts', {
        category: 'E2EE',
        data: { senderUserId, error: (err as Error).message },
      });
      for (const settle of batch.settles) settle(err ?? new Error('Receipt send failed'));
    }
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
 * device, then the per-sender rate limit. A failed envelope that does not
 * pass the sender checks gets no request, and the caller keeps it or
 * acknowledges it as for any failed envelope. The request is stored under
 * the failed envelope ID before its post, and the request record then owns
 * it, as `requestRetryInFamily` tells. A redelivery of the same envelope
 * posts nothing.
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
    const outcome = await requestRetryInFamily(family, receiveId, {
      storage: ctx.storage,
      logger: ctx.logger,
      hooks: ctx.hooks,
      local: { userId: ctx.userId, deviceId: ctx.deviceId },
      senderUserId: envelope.senderUserId,
      senderDeviceId: envelope.senderDeviceId,
      // Receiver-side rate limiting. A failed envelope with a request record
      // spends nothing, as `requestRetryInFamily` tells.
      allow: () => checkRetryRateLimit(state, envelope.senderUserId),
      windowMs: RETRY_REQUEST_WINDOW_MS,
      send: retryRequestPost(
        ctx.sealRetryRequest,
        relay,
        (request) => relay.send(request),
        ctx.recipientRegistrationId,
        (userId, deviceId) => ctx.refreshStaleSession?.(ctx, userId, deviceId) ?? Promise.resolve(false)
      ),
      failedEnvelope: await retryFailedEnvelope(ctx.storage, envelope),
      createRequest: async (senderKey) => {
        // Handle stale prekey indicators
        await handleStalePreKeyIndicator(ctx, envelope, error, state, callbacks, config);
        const retryRequest = await ctx.sesameManager.createRetryRequest(
          failedMessage,
          retryReason,
          { senderKey }
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
      schedule: ctx.scheduleRetryRequest,
      groupId: failedGroupOf(error),
      reset: ctx.retryTerminalReset?.(ctx),
    });
    if (outcome === 'posted' || outcome === 'pending') {
      ctx.logger.info('Retry request sent to sender', {
        category: 'E2EE',
        data: {
          originalSender: `${envelope.senderUserId}:${envelope.senderDeviceId}`,
          timestamp: envelope.timestamp,
          reason: retryReason,
          outcome,
        },
      });
    }
    // The record of the failed envelope owns its request, so the envelope
    // is acknowledged. A deferred member stays unacknowledged, so its
    // redelivery after the rate limit window asks again.
    if (!acknowledgesRetryRequest(outcome, family.member !== undefined)) return;

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
