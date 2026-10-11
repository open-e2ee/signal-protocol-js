/**
 * Wire form of a retry request.
 *
 * A retry request travels as an identified mailbox envelope with
 * `messageType: 'retry_request'`. The envelope sender is the requester: the
 * relay stamps it, so the payload never carries it. The `ciphertext` field
 * holds canonical base64 of a small UTF-8 JSON payload. The payload is not
 * encrypted. It holds only what the requester knows about the failed message.
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
 */

import type { Envelope } from '../remote/relay/types';
import { RetryReason, type RetryRequest } from '../internal/sesame/types';
import { base64ToBytes, bytesToBase64, generateUuidV4, stringToBytes } from '../internal/crypto';
import { utf8Decode } from '../internal/platform';
import type { Base64 } from '../types';
import {
  isRetryId,
  RELIABILITY_RECORD_TTL_MS,
  RETRY_REQUEST_DEADLINE_MS,
  retryAttemptClientMessageId,
  retryRequestClientMessageId,
  storeRetryRequest,
  updateRetryRequest,
  type RetryRequestIds,
  type StoredRetryRequest,
} from '../local/store/reliability';
import {
  classifyRetryRequestPostFailure,
  relayOperationRefusal,
  type RetryRequestPostFailure,
} from './relay-acceptance';
import { rethrowRelayWorkStopped } from './relay-work';

/** The payload version that this client writes and reads. */
const RETRY_REQUEST_PAYLOAD_VERSION = 1;

/** The decoder refuses a longer `ciphertext` value before it decodes it. */
export const MAX_RETRY_REQUEST_CIPHERTEXT_LENGTH = 2_048;

/** The Relay refuses a longer message ID, so a failed envelope ID is 1 to this many characters. */
const MAX_FAILED_ENVELOPE_ID_LENGTH = 128;

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

/** What a retry request post did. */
export type RetryPostOutcome =
  /** The Relay holds the request attempt. */
  | 'posted'
  /** The post failed with a retryable class. The record holds the next attempt time. */
  | 'pending'
  /** The request ended. The record holds the terminal state. */
  | 'terminal';

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
 * under the same retry ID, with the same deadline, and posts it. Otherwise
 * it posts the stored attempt, as `postStoredRetryRequest` does.
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
    await send(await retryRequestEnvelope(await createRequest(), sender));
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
      })
    );
  }
  if (stored.terminal !== undefined || stored.envelope === undefined) return 'terminal';
  if (Date.now() >= stored.deadlineAt) return attempts.expire(stored);
  if (failed.member !== undefined && stored.answered) {
    return attempts.postNew(await attempts.next(stored));
  }
  return attempts.postStored(stored);
}

/**
 * Post the stored attempt of a retry request again, with its stored bytes
 * and ID. When the Relay refuses it with OPERATION_EXPIRED, it creates the
 * next attempt under the same retry ID, with the same deadline, replaces
 * the record in one write, and posts it.
 *
 * Each post classifies its failure. A RETRY_CONFLICT answer completes the
 * attempt, because the Relay holds an earlier encryption of it. A
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
   * Create and store a new attempt. Attempt 1 sets the deadline. The
   * attempt is due at its own time until its post settles, so the
   * scheduler posts it again when a stop or a crash ends the post.
   */
  const create = async (
    attempt: Pick<StoredRetryRequest, 'failedEnvelopeId' | 'retryId' | 'attempt' | 'fingerprint'> & {
      deadlineAt?: number;
    }
  ): Promise<StoredRetryRequest> => {
    const request = await createRequest();
    const envelope = await retryRequestEnvelope(request, sender, attempt);
    const record: StoredRetryRequest = {
      failedEnvelopeId: attempt.failedEnvelopeId,
      retryId: attempt.retryId,
      attempt: attempt.attempt,
      requestedAt: envelope.timestamp,
      ...(attempt.fingerprint !== undefined && { fingerprint: attempt.fingerprint }),
      answered: false,
      deadlineAt:
        attempt.deadlineAt ??
        Math.min(
          envelope.timestamp + RETRY_REQUEST_DEADLINE_MS,
          request.failedTimestamp + RELIABILITY_RECORD_TTL_MS
        ),
      nextAttemptAt: envelope.timestamp,
      envelope,
    };
    await storeRetryRequest(store, record);
    return record;
  };

  /** Create the attempt after the stored one, with the same retry ID and deadline. */
  const next = (stored: StoredRetryRequest): Promise<StoredRetryRequest> =>
    create({
      failedEnvelopeId: stored.failedEnvelopeId,
      retryId: stored.retryId,
      attempt: stored.attempt + 1,
      fingerprint: stored.fingerprint,
      deadlineAt: stored.deadlineAt,
    });

  const expire = async (stored: StoredRetryRequest): Promise<RetryPostOutcome> => {
    await update(stored, {
      terminal: { class: 'expired-content', at: Date.now(), emitted: false },
      nextAttemptAt: undefined,
    });
    return 'terminal';
  };

  /**
   * Post one attempt. `fresh` is true for an attempt that this call
   * created: OPERATION_EXPIRED then means a clock outside the admission
   * window, and counts as a transport outage.
   */
  const post = async (record: StoredRetryRequest, fresh: boolean): Promise<RetryPostOutcome> => {
    try {
      await send(record.envelope!);
    } catch (error) {
      rethrowRelayWorkStopped(error);
      const refusal = relayOperationRefusal(error);
      if (refusal === 'OPERATION_EXPIRED' && !fresh) {
        // The Relay no longer admits or replays the stored operation. The
        // new attempt replaces the record before its post.
        return post(await next(record), true);
      }
      if (refusal !== 'RETRY_CONFLICT') {
        const failure: RetryRequestPostFailure =
          refusal === 'OPERATION_EXPIRED'
            ? { retry: 'transport-outage' }
            : classifyRetryRequestPostFailure(error);
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
    expire,
    postNew: (record: StoredRetryRequest) => post(record, true),
    postStored: (stored: StoredRetryRequest) => post(stored, false),
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
  const { failedTimestamp, deviceId, reason, timestamp, ratchetKey, failedEnvelopeId, retryId } =
    payload;
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
      failedEnvelopeId.length > MAX_FAILED_ENVELOPE_ID_LENGTH)
  ) {
    return { ok: false, cause: 'failedEnvelopeId is not valid' };
  }
  if (retryId !== undefined && !isRetryId(retryId)) {
    return { ok: false, cause: 'retryId is not valid' };
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
    },
    ...(retryId === undefined
      ? {}
      : { retry: { failedEnvelopeId: failedEnvelopeId as string, retryId: retryId as string } }),
  };
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
