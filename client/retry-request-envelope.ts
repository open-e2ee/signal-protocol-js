/**
 * Wire form of a retry request.
 *
 * A retry request is a mailbox envelope with `messageType: 'retry_request'`.
 * The envelope sender is the requester, so the payload never carries it.
 * The `ciphertext` field holds canonical base64 of a small UTF-8 JSON
 * payload. The payload is not ratchet-encrypted. It holds only what the
 * requester knows about the failed message.
 *
 * The request record stores the identified form of the envelope.
 * `retryRequestPost` seals it at each post when an access key of the target
 * permits it: the seal holds the same payload as `PLAINTEXT_CONTENT`, and
 * the sender certificate in the seal names the requester. Otherwise the
 * post is identified, and the relay stamps the requester, only when the
 * sealed sender delivery mode permits it.
 *
 * The requester keeps one request record for each failed envelope. The record
 * holds a random retry ID, and every wire ID of the request family derives from
 * it: `<retryId>:retry-request`, `<retryId>:resend` and `<retryId>:null`, with
 * `:<n>` from attempt 2. The resend and the null message carry the attempt
 * number of the request that they answer. The failed envelope ID travels
 * only in the payload.
 * The requester stores each request envelope before the post. After a post
 * that fails with a retryable class, the retry request scheduler posts the
 * stored envelope again, until the deadline of the record.
 *
 * A relay can assign its own envelope ID. The payload then also carries the
 * client message ID of the failed envelope, the ID that the sender chose. A
 * request without a ratchet key names a failed sender-key message.
 */

import type { Envelope, SignalProtocolRelayServer } from '../remote/relay/types';
import { SealedSenderAuthError } from '../types/errors';
import type { SealedReceipt } from './types';
import { RetryReason, type RetryRequest } from '../internal/sesame/types';
import { base64ToBytes, bytesToBase64, generateUuidV4, stringToBytes } from '../internal/crypto';
import { utf8Decode } from '../internal/platform';
import type { Base64 } from '../types';
import type { ContentHint } from '../types/messages';
import {
  isRetryId,
  RETRY_REQUEST_DEADLINE_MS,
  RETRY_REQUEST_POSTING_WINDOW_MS,
  retryAttemptClientMessageId,
  retryRequestClientMessageId,
  retryRequestPostingDeadlineAt,
  storeRetryRequest,
  updateRetryRequest,
  type RetryRequestIds,
  type StoredRetryRequest,
} from '../local/store/reliability';
import {
  classifyRetryRequestPostFailure,
  relayHoldsMessageId,
  relayOperationRefusal,
  type RetryRequestPostFailure,
} from './relay-acceptance';
import { rethrowRelayWorkStopped } from './relay-work';
import { isStaleDeviceRefusal } from './relay-device-refusal';
import { MAX_RETRY_RESPONSES_PER_MESSAGE } from './constants';

/** The payload version that this client writes and reads. */
const RETRY_REQUEST_PAYLOAD_VERSION = 1;

/** The decoder refuses a longer `ciphertext` value before it decodes it. */
export const MAX_RETRY_REQUEST_CIPHERTEXT_LENGTH = 2_048;

/**
 * The Relay refuses a longer message ID, so a failed envelope ID and a
 * failed client message ID are 1 to this many characters.
 */
const MAX_MESSAGE_ID_LENGTH = 128;

/** The decoded ratchet key is 1 to this many bytes. */
const MAX_RATCHET_KEY_BYTES = 64;

const RETRY_REASONS: ReadonlySet<string> = new Set(Object.values(RetryReason));

/** A user and one of its devices. */
export interface RetryRequestDevice {
  userId: string;
  deviceId: number;
}

/** The payload keys. The decoder reads only these keys. */
interface RetryRequestPayload {
  v: number;
  failedTimestamp: number;
  deviceId: number;
  reason: RetryReason;
  timestamp: number;
  ratchetKey?: string;
  failedEnvelopeId?: string;
  retryId?: string;
  failedClientMessageId?: string;
}

/**
 * The result of `readRetryRequestEnvelope`. `retry` holds the ID of the
 * envelope that the requester could not decrypt and the retry ID of its
 * request record, when the requester knew the failed envelope. The resend
 * IDs of the request derive from the retry ID.
 */
export type RetryRequestEnvelopeRead =
  | { ok: true; request: RetryRequest; retry?: RetryRequestIds }
  | { ok: false; cause: string };

/** The failed envelope that a retry request names, and its stored request. */
export interface RetryRequestFailure {
  /** The Relay message ID of the failed envelope. Without it, nothing is stored. */
  id?: string;
  /** The fingerprint of the failed envelope. */
  fingerprint?: string;
  /** The stored attempt of the request for this envelope, from `getRetryRequest`. */
  stored: StoredRetryRequest | null;
  /**
   * True when the failed envelope is a sender-key group message. A new
   * record stores it. A new attempt keeps the value of the stored record.
   */
  groupMessage?: boolean;
  /**
   * The client message ID of the failed envelope. Set it only when the
   * failed envelope itself failed, because a member has its own ID. A new
   * record stores it. A new attempt keeps the value of the stored record.
   */
  clientMessageId?: string;
  /**
   * The raw group ID of the failed envelope, when the local device knows
   * it. Set it only when the failed envelope itself failed. A new record
   * stores it. A new attempt keeps the value of the stored record.
   */
  groupId?: string;
  /**
   * The content hint of the failed envelope. Set it only when the failed
   * envelope itself failed. A new record stores it. A new attempt keeps the
   * value of the stored record.
   */
  contentHint?: ContentHint;
  /**
   * The device that sent the failed envelope. A new record stores it. A
   * new attempt keeps the value of the stored record.
   */
  sender?: { userId: string; deviceId: number };
  /**
   * The envelope ID of the resend or the null message that failed to
   * decrypt. Undefined when the failed envelope itself failed.
   */
  member?: string;
}

/**
 * Make the envelope that asks the original sender device for a resend.
 *
 * @param request - The retry request. Its original sender is the target.
 * @param sender - The local identity, which sends the envelope.
 * @param failed - The ID of the failed envelope, the retry ID of its request
 *   record and the attempt number. The client message ID derives from the
 *   retry ID and the attempt. Without them, it is a new UUID.
 */
export async function retryRequestEnvelope(
  request: RetryRequest,
  sender: RetryRequestDevice,
  failed?: RetryRequestIds & { attempt: number }
): Promise<Envelope> {
  const payload: RetryRequestPayload = {
    v: RETRY_REQUEST_PAYLOAD_VERSION,
    failedTimestamp: request.failedTimestamp,
    deviceId: request.originalSenderDeviceId,
    reason: request.reason,
    timestamp: request.timestamp,
    ...(request.ratchetKey === undefined ? {} : { ratchetKey: request.ratchetKey }),
    ...(failed && { failedEnvelopeId: failed.failedEnvelopeId, retryId: failed.retryId }),
    // The sender chose this ID. A value that the decoder refuses is left out.
    ...(isMessageId(request.failedClientMessageId) && {
      failedClientMessageId: request.failedClientMessageId,
    }),
  };
  return {
    targetUserId: request.originalSenderUserId,
    targetDeviceId: request.originalSenderDeviceId,
    senderUserId: sender.userId,
    senderDeviceId: sender.deviceId,
    ciphertext: bytesToBase64(stringToBytes(JSON.stringify(payload))),
    messageType: 'retry_request',
    deliveryClass: 'background-sync',
    timestamp: Date.now(),
    clientMessageId: failed
      ? retryAttemptClientMessageId(retryRequestClientMessageId(failed.retryId), failed.attempt)
      : await generateUuidV4(),
  };
}

/**
 * Seals the payload of one retry request for its target device, or resolves
 * to undefined when the request goes identified. It throws when sealed
 * sender is required and the request cannot be sealed.
 */
export type SealRetryRequest = (
  recipientUserId: string,
  recipientDeviceId: number,
  payloadBase64: string
) => Promise<SealedReceipt | undefined>;

/**
 * Make the function that posts one retry request envelope, by the sealed
 * sender delivery mode, as a receipt goes.
 *
 * With an access key of the target, the post is sealed: the Relay sees the
 * target, the timing and the size, and not the requester. The sealed post
 * keeps the client message ID and the timestamp of the envelope, so the
 * Relay deduplicates the attempt by the same operation as an identified
 * post. When the Relay refuses the access key, the post goes identified
 * only when the delivery mode permits it. When `seal` resolves to
 * undefined, the post goes identified. In `'required'` mode `seal` throws
 * instead, and nothing goes identified. The caller classifies each error
 * of the post.
 *
 * When the Relay refuses the post as `STALE_DEVICE`, the target device has
 * a new registration. The post then refreshes the session with the device
 * once from a fresh bundle, and posts the same envelope again, sealed and
 * named with the new session, as a receipt goes. The request is plaintext,
 * so nothing is encrypted again. A refresh that finds no bundle,
 * or a second refusal, throws the refusal. A refresh that fails for another
 * reason throws StaleSessionRefreshError, which classifies as a transport
 * outage, so the next post refreshes again.
 *
 * @param seal - Seals the payload. Without it, each post is identified.
 * @param relay - Posts the sealed envelope.
 * @param sendIdentified - Posts the identified envelope.
 * @param registrationOf - The registration ID of the current session with
 *   the target device. The identified envelope names it, as the sealed body
 *   does, so the Relay refuses the post to a reinstalled device. With no
 *   session, or without this function, the envelope names none.
 * @param refreshStaleSession - Refreshes the session with a refused device.
 *   Resolves to true when the new session is ready. Without it, a stale
 *   refusal throws.
 */
export function retryRequestPost(
  seal: SealRetryRequest | undefined,
  relay: Pick<SignalProtocolRelayServer, 'sendMultiRecipientUnidentified'> | undefined,
  sendIdentified: (envelope: Envelope) => Promise<unknown>,
  registrationOf?: (userId: string, deviceId: number) => Promise<number | undefined>,
  refreshStaleSession?: (userId: string, deviceId: number) => Promise<boolean>
): (envelope: Envelope) => Promise<unknown> {
  const post = async (envelope: Envelope): Promise<unknown> => {
    const payloadBase64 =
      typeof envelope.ciphertext === 'string'
        ? envelope.ciphertext
        : bytesToBase64(envelope.ciphertext);
    const sealed = await seal?.(envelope.targetUserId, envelope.targetDeviceId, payloadBase64);
    if (sealed) {
      // The seal resolves only when the relay has anonymous delivery.
      if (!relay?.sendMultiRecipientUnidentified) {
        throw new Error('Relay has no anonymous delivery for a sealed retry request');
      }
      try {
        return await relay.sendMultiRecipientUnidentified(
          sealed.sentMessageBase64,
          sealed.auth,
          envelope.timestamp,
          envelope.deliveryClass,
          [envelope.targetUserId],
          envelope.clientMessageId
        );
      } catch (error) {
        if (!(error instanceof SealedSenderAuthError) || !sealed.identifiedFallback) throw error;
      }
    }
    const recipientRegistrationId = await registrationOf?.(
      envelope.targetUserId,
      envelope.targetDeviceId
    );
    return sendIdentified(
      recipientRegistrationId === undefined ? envelope : { ...envelope, recipientRegistrationId }
    );
  };
  return async (envelope) => {
    try {
      return await post(envelope);
    } catch (error) {
      if (!refreshStaleSession || !isStaleDeviceRefusal(error)) throw error;
      const refreshed = await refreshStaleSession(envelope.targetUserId, envelope.targetDeviceId);
      if (!refreshed) throw error;
      return post(envelope);
    }
  };
}

/** What a retry request post did. */
export type RetryPostOutcome =
  /** The Relay holds the request attempt. */
  | 'posted'
  /** The request attempt stays as stored and nothing was posted. */
  | 'waiting'
  /** The post failed with a retryable class. The record holds the next attempt time. */
  | 'pending'
  /** The request ended. The record holds the terminal state. */
  | 'terminal';

/**
 * Tell whether a stored request attempt is answered and is the last
 * attempt of its request. A sender answers at most
 * `MAX_RETRY_RESPONSES_PER_MESSAGE` requests for one message, so when the
 * resend that answered this attempt also fails, the request ends.
 */
export function answeredLastRetryAttempt(stored: StoredRetryRequest): boolean {
  return stored.answered && stored.attempt >= MAX_RETRY_RESPONSES_PER_MESSAGE;
}

/** The shortest wait before the next post of a stored attempt. */
const MIN_RETRY_REQUEST_BACKOFF_MS = 60_000;

/** The longest wait before the next post of a stored attempt. */
const MAX_RETRY_REQUEST_BACKOFF_MS = 60 * 60_000;

/**
 * Post the retry request for one failed envelope.
 *
 * Without a failed envelope ID, it creates a request and posts it under a
 * new UUID, stores nothing, and throws when the post fails. Otherwise the
 * request record owns the request. With no record, it creates attempt 1
 * with a new retry ID and stores it before the post, due at once. A
 * record that ended posts nothing. At the deadline of the record, the
 * request ends as `expired-content` and posts nothing. When a member
 * failed and the stored attempt is answered, it creates the next attempt
 * under the same retry ID, with the same deadlines, and posts it. When that
 * answered attempt is the last one, as `answeredLastRetryAttempt` tells,
 * the request ends as `attempts-exhausted` and posts nothing. At or after
 * the posting deadline, `retryRequestPostingDeadlineAt`, an answered
 * attempt gets no next attempt and gives `waiting`: the Relay accepted the
 * request, so it waits, and its deadline ends it as `expired-content`. The
 * Relay also holds a stored attempt with no next attempt time, so after
 * the posting deadline that attempt is not posted again and gives
 * `waiting`. Otherwise it posts the stored attempt, as
 * `postStoredRetryRequest` does.
 *
 * Each new attempt carries the failed client message ID, the content hint,
 * the sender, the receive time and the delivery error state of the stored
 * record. Attempt 1 takes them from `failed`, with the time of now as the
 * receive time.
 *
 * @param store - The local store that keeps the request records.
 * @param failed - The failed envelope and its stored request.
 * @param createRequest - Creates the request of a new attempt. Only a new
 *   attempt calls it.
 * @param sender - The local identity, which sends the envelope.
 * @param send - Posts one request envelope.
 */
export async function postRetryRequest(
  store: Parameters<typeof storeRetryRequest>[0],
  failed: RetryRequestFailure,
  createRequest: () => Promise<RetryRequest>,
  sender: RetryRequestDevice,
  send: (envelope: Envelope) => Promise<unknown>
): Promise<RetryPostOutcome> {
  const failedEnvelopeId = failed.id;
  if (failedEnvelopeId === undefined) {
    const request = withFailedClientMessageId(await createRequest(), failed.clientMessageId);
    await send(await retryRequestEnvelope(request, sender));
    return 'posted';
  }
  const attempts = retryRequestAttempts(store, createRequest, sender, send);
  const { stored } = failed;
  if (!stored) {
    return attempts.postNew(
      await attempts.create({
        failedEnvelopeId,
        retryId: await generateUuidV4(),
        attempt: 1,
        ...(failed.fingerprint !== undefined && { fingerprint: failed.fingerprint }),
        ...(failed.groupMessage && { groupMessage: true }),
        ...(failed.clientMessageId !== undefined && {
          failedClientMessageId: failed.clientMessageId,
        }),
        ...(failed.groupId !== undefined && { groupId: failed.groupId }),
        receivedAt: Date.now(),
        ...(failed.contentHint !== undefined && { contentHint: failed.contentHint }),
        ...(failed.sender !== undefined && { failedSender: failed.sender }),
      })
    );
  }
  if (stored.terminal !== undefined || stored.envelope === undefined) return 'terminal';
  if (Date.now() >= stored.deadlineAt) return attempts.end(stored, 'expired-content');
  if (failed.member !== undefined && stored.answered) {
    if (answeredLastRetryAttempt(stored)) return attempts.end(stored, 'attempts-exhausted');
    // The answer proves that the Relay accepted the request, so it waits
    // for its deadline.
    if (Date.now() >= retryRequestPostingDeadlineAt(stored)) return 'waiting';
    return attempts.postNew(await attempts.next(stored));
  }
  if (stored.nextAttemptAt === undefined && Date.now() >= retryRequestPostingDeadlineAt(stored)) {
    return 'waiting';
  }
  return attempts.postStored(stored);
}

/**
 * Post the stored attempt of a retry request again, with its stored bytes
 * and ID. At or after its posting deadline, `retryRequestPostingDeadlineAt`,
 * the request ends as `posting-deadline` and posts nothing. When the Relay
 * refuses the post with OPERATION_EXPIRED, the request ends as
 * `posting-deadline` with acceptance unknown, and posts no replacement.
 *
 * Each post classifies its failure. A RETRY_CONFLICT answer, or a
 * DELIVERY_ALREADY_ACCEPTED answer under protocol version 2, completes the
 * attempt, because the Relay holds an earlier post of it. A
 * conclusive class stores the terminal state, with `emitted` false, and
 * gives 'terminal'. A retryable class stores the class and the next
 * attempt time, the age of the attempt from 1 minute to 1 hour from now,
 * and gives 'pending'. A post that the Relay accepts clears both.
 *
 * @param store - The local store that keeps the request records.
 * @param stored - The stored attempt. It has an envelope.
 * @param createRequest - Creates the request of a new attempt.
 * @param sender - The local identity, which sends the envelope.
 * @param send - Posts one request envelope.
 */
export async function postStoredRetryRequest(
  store: Parameters<typeof storeRetryRequest>[0],
  stored: StoredRetryRequest,
  createRequest: () => Promise<RetryRequest>,
  sender: RetryRequestDevice,
  send: (envelope: Envelope) => Promise<unknown>
): Promise<RetryPostOutcome> {
  return retryRequestAttempts(store, createRequest, sender, send).postStored(stored);
}

/** The attempt steps of one retry request. */
function retryRequestAttempts(
  store: Parameters<typeof storeRetryRequest>[0],
  createRequest: () => Promise<RetryRequest>,
  sender: RetryRequestDevice,
  send: (envelope: Envelope) => Promise<unknown>
) {
  const update = (
    record: StoredRetryRequest,
    changes: Parameters<typeof updateRetryRequest>[4]
  ): Promise<unknown> =>
    updateRetryRequest(store, record.failedEnvelopeId, record.retryId, record.attempt, changes);

  /**
   * Create and store a new attempt. Attempt 1 sets the deadline from its
   * own time, and the posting deadline from the first failure,
   * `receivedAt`. The attempt is due at its own time until its post
   * settles, so the scheduler posts it again when a stop or a crash ends
   * the post.
   */
  const create = async (
    attempt: Pick<
      StoredRetryRequest,
      | 'failedEnvelopeId'
      | 'retryId'
      | 'attempt'
      | 'fingerprint'
      | 'groupMessage'
      | 'failedClientMessageId'
      | 'groupId'
      | 'receivedAt'
      | 'contentHint'
      | 'failedSender'
      | 'errorShown'
      | 'recoveredEmitted'
    > & { deadlineAt?: number; postingDeadlineAt?: number }
  ): Promise<StoredRetryRequest> => {
    const request = withFailedClientMessageId(
      await createRequest(),
      attempt.failedClientMessageId
    );
    const envelope = await retryRequestEnvelope(request, sender, attempt);
    const record: StoredRetryRequest = {
      failedEnvelopeId: attempt.failedEnvelopeId,
      retryId: attempt.retryId,
      attempt: attempt.attempt,
      requestedAt: envelope.timestamp,
      ...(attempt.fingerprint !== undefined && { fingerprint: attempt.fingerprint }),
      ...(attempt.groupId !== undefined && { groupId: attempt.groupId }),
      answered: false,
      ...(attempt.groupMessage && { groupMessage: true }),
      ...(attempt.failedClientMessageId !== undefined && {
        failedClientMessageId: attempt.failedClientMessageId,
      }),
      ...(attempt.groupId !== undefined && { groupId: attempt.groupId }),
      ...(attempt.receivedAt !== undefined && { receivedAt: attempt.receivedAt }),
      ...(attempt.contentHint !== undefined && { contentHint: attempt.contentHint }),
      ...(attempt.failedSender !== undefined && { failedSender: attempt.failedSender }),
      ...(attempt.errorShown && { errorShown: true }),
      ...(attempt.recoveredEmitted && { recoveredEmitted: true }),
      deadlineAt: attempt.deadlineAt ?? envelope.timestamp + RETRY_REQUEST_DEADLINE_MS,
      postingDeadlineAt:
        attempt.postingDeadlineAt ??
        (attempt.receivedAt ?? envelope.timestamp) + RETRY_REQUEST_POSTING_WINDOW_MS,
      nextAttemptAt: envelope.timestamp,
      envelope,
    };
    await storeRetryRequest(store, record);
    return record;
  };

  /** Create the attempt after the stored one, with the same retry ID and deadlines. */
  const next = (stored: StoredRetryRequest): Promise<StoredRetryRequest> =>
    create({
      failedEnvelopeId: stored.failedEnvelopeId,
      retryId: stored.retryId,
      attempt: stored.attempt + 1,
      fingerprint: stored.fingerprint,
      groupMessage: stored.groupMessage,
      failedClientMessageId: stored.failedClientMessageId,
      groupId: stored.groupId,
      receivedAt: stored.receivedAt,
      contentHint: stored.contentHint,
      failedSender: stored.failedSender,
      errorShown: stored.errorShown,
      recoveredEmitted: stored.recoveredEmitted,
      deadlineAt: stored.deadlineAt,
      postingDeadlineAt: retryRequestPostingDeadlineAt(stored),
    });

  const end = async (
    stored: StoredRetryRequest,
    terminal: 'expired-content' | 'posting-deadline' | 'attempts-exhausted'
  ): Promise<RetryPostOutcome> => {
    await update(stored, {
      terminal: { class: terminal, at: Date.now(), emitted: false },
      nextAttemptAt: undefined,
      lastFailureClass: undefined,
    });
    return 'terminal';
  };

  /**
   * Post one attempt. At or after its posting deadline, the request ends as
   * `posting-deadline` and posts nothing.
   *
   * OPERATION_EXPIRED ends the request as `posting-deadline` with
   * acceptance unknown, and no replacement posts. The Relay may have
   * accepted an earlier post of the attempt and since dropped it.
   *
   * DELIVERY_ALREADY_ACCEPTED under protocol version 2 means that the
   * Relay already holds an accepted post, or a delivered row, under the
   * message ID of the attempt. Each attempt has its own message ID, so the
   * attempt is at the Relay or was delivered. The call reads the code as
   * it reads RETRY_CONFLICT: the request is posted, and no replacement
   * posts. Attempts advance only when a member answers the stored attempt.
   */
  const post = async (record: StoredRetryRequest): Promise<RetryPostOutcome> => {
    if (Date.now() >= retryRequestPostingDeadlineAt(record)) {
      return end(record, 'posting-deadline');
    }
    try {
      await send(record.envelope!);
    } catch (error) {
      rethrowRelayWorkStopped(error);
      const refusal = relayOperationRefusal(error);
      if (refusal === 'OPERATION_EXPIRED') return end(record, 'posting-deadline');
      if (!relayHoldsMessageId(error)) {
        const failure: RetryRequestPostFailure = classifyRetryRequestPostFailure(error);
        if ('terminal' in failure) {
          await update(record, {
            terminal: { class: failure.terminal, at: Date.now(), emitted: false },
            nextAttemptAt: undefined,
            lastFailureClass: undefined,
          });
          return 'terminal';
        }
        const now = Date.now();
        const wait = Math.min(
          MAX_RETRY_REQUEST_BACKOFF_MS,
          Math.max(MIN_RETRY_REQUEST_BACKOFF_MS, now - record.requestedAt)
        );
        await update(record, { lastFailureClass: failure.retry, nextAttemptAt: now + wait });
        return 'pending';
      }
    }
    if (record.nextAttemptAt !== undefined || record.lastFailureClass !== undefined) {
      await update(record, { nextAttemptAt: undefined, lastFailureClass: undefined });
    }
    return 'posted';
  };

  return {
    create,
    next,
    end,
    postNew: (record: StoredRetryRequest) => post(record),
    postStored: (stored: StoredRetryRequest) => post(stored),
  };
}

/**
 * Read a `retry_request` envelope that the local device received.
 *
 * The requester is the envelope sender. The original sender is the local
 * identity. The other fields come from the payload. A `Uint8Array`
 * ciphertext is read as its base64 form. The function ignores
 * every payload key that it does not read, a requester key included. It does
 * not check the envelope sender: the caller does that first.
 *
 * @param envelope - The received envelope.
 * @param local - The local identity.
 * @returns The retry request, or the cause of the refusal. The cause never
 *   holds payload bytes.
 */
export function readRetryRequestEnvelope(
  envelope: Envelope,
  local: RetryRequestDevice
): RetryRequestEnvelopeRead {
  // A relay can deliver raw bytes. The checks apply to their base64 form.
  const ciphertext: string =
    typeof envelope.ciphertext === 'string'
      ? envelope.ciphertext
      : bytesToBase64(envelope.ciphertext);
  if (ciphertext.length > MAX_RETRY_REQUEST_CIPHERTEXT_LENGTH) {
    return { ok: false, cause: 'payload is too long' };
  }
  const bytes = canonicalBase64Bytes(ciphertext);
  if (bytes === undefined) {
    return { ok: false, cause: 'payload is not canonical base64' };
  }

  let value: unknown;
  try {
    value = JSON.parse(utf8Decode(bytes, { fatal: true }));
  } catch {
    return { ok: false, cause: 'payload is not JSON' };
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return { ok: false, cause: 'payload is not a JSON object' };
  }
  const payload = value as Record<string, unknown>;

  if (payload.v !== RETRY_REQUEST_PAYLOAD_VERSION) {
    return { ok: false, cause: 'payload version is not supported' };
  }
  const {
    failedTimestamp,
    deviceId,
    reason,
    timestamp,
    ratchetKey,
    failedEnvelopeId,
    retryId,
    failedClientMessageId,
  } = payload;
  if (!Number.isSafeInteger(failedTimestamp) || (failedTimestamp as number) <= 0) {
    return { ok: false, cause: 'failedTimestamp is not valid' };
  }
  if (!Number.isSafeInteger(deviceId) || (deviceId as number) < 1) {
    return { ok: false, cause: 'deviceId is not valid' };
  }
  if (typeof reason !== 'string' || !RETRY_REASONS.has(reason)) {
    return { ok: false, cause: 'reason is not known' };
  }
  if (!Number.isSafeInteger(timestamp)) {
    return { ok: false, cause: 'timestamp is not valid' };
  }
  if (ratchetKey !== undefined) {
    const ratchetKeyBytes =
      typeof ratchetKey === 'string' ? canonicalBase64Bytes(ratchetKey) : undefined;
    if (
      ratchetKeyBytes === undefined ||
      ratchetKeyBytes.length < 1 ||
      ratchetKeyBytes.length > MAX_RATCHET_KEY_BYTES
    ) {
      return { ok: false, cause: 'ratchetKey is not valid' };
    }
  }
  if (
    failedEnvelopeId !== undefined &&
    (typeof failedEnvelopeId !== 'string' ||
      failedEnvelopeId.length < 1 ||
      failedEnvelopeId.length > MAX_MESSAGE_ID_LENGTH)
  ) {
    return { ok: false, cause: 'failedEnvelopeId is not valid' };
  }
  if (retryId !== undefined && !isRetryId(retryId)) {
    return { ok: false, cause: 'retryId is not valid' };
  }
  if (failedClientMessageId !== undefined && !isMessageId(failedClientMessageId)) {
    return { ok: false, cause: 'failedClientMessageId is not valid' };
  }
  // The sender derives the resend IDs from the retry ID and keys its record by
  // the failed envelope ID, so a payload carries both or neither.
  if ((failedEnvelopeId === undefined) !== (retryId === undefined)) {
    return { ok: false, cause: 'failedEnvelopeId and retryId are not both present' };
  }
  if (deviceId !== local.deviceId) {
    return { ok: false, cause: 'deviceId is not the local device' };
  }

  return {
    ok: true,
    request: {
      requesterUserId: envelope.senderUserId,
      requesterDeviceId: envelope.senderDeviceId,
      originalSenderUserId: local.userId,
      originalSenderDeviceId: local.deviceId,
      failedTimestamp: failedTimestamp as number,
      timestamp: timestamp as number,
      reason: reason as RetryReason,
      ...(ratchetKey === undefined ? {} : { ratchetKey: ratchetKey as string }),
      ...(failedClientMessageId === undefined ? {} : { failedClientMessageId }),
    },
    ...(retryId === undefined
      ? {}
      : { retry: { failedEnvelopeId: failedEnvelopeId as string, retryId: retryId as string } }),
  };
}

/** The request with the failed client message ID, when there is one. */
function withFailedClientMessageId(
  request: RetryRequest,
  failedClientMessageId: string | undefined
): RetryRequest {
  return failedClientMessageId === undefined ? request : { ...request, failedClientMessageId };
}

/** True for a string of 1 to `MAX_MESSAGE_ID_LENGTH` characters. */
function isMessageId(value: unknown): value is string {
  return typeof value === 'string' && value.length >= 1 && value.length <= MAX_MESSAGE_ID_LENGTH;
}

/** Decode canonical base64, or return undefined. */
function canonicalBase64Bytes(value: string): Uint8Array | undefined {
  try {
    const bytes = base64ToBytes(value as Base64);
    return bytesToBase64(bytes) === value ? bytes : undefined;
  } catch {
    return undefined;
  }
}
