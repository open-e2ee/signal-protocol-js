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
 * The requester stores each request envelope before the post, and posts the
 * stored envelope again on a later decrypt failure of the same envelope.
 */

import type { Envelope } from '../remote/relay/types';
import { RetryReason, type RetryRequest } from '../internal/sesame/types';
import { base64ToBytes, bytesToBase64, generateUuidV4, stringToBytes } from '../internal/crypto';
import { utf8Decode } from '../internal/platform';
import type { Base64 } from '../types';
import {
  isRetryId,
  retryAttemptClientMessageId,
  retryRequestClientMessageId,
  storeRetryRequest,
  type RetryRequestIds,
  type StoredRetryRequest,
} from '../local/store/reliability';
import { relayOperationRefusal } from './relay-acceptance';

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

/**
 * Post the retry request for one failed envelope.
 *
 * Without a failed envelope ID, it creates a request and posts it under a
 * new UUID, and stores nothing. With a stored attempt, it posts the stored
 * envelope again. Otherwise it creates attempt 1 with a new retry ID and
 * stores it before the post. Each later attempt keeps the retry ID. When
 * the Relay refuses a stored attempt with OPERATION_EXPIRED, or when a
 * member failed and the stored attempt is answered, it creates the next
 * attempt, replaces the record in one write, and posts it. Each new
 * attempt is not answered. A RETRY_CONFLICT answer to any post completes
 * the attempt, because the Relay holds an earlier encryption of this
 * attempt.
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
): Promise<void> {
  const failedEnvelopeId = failed.id;
  if (failedEnvelopeId === undefined) {
    await send(await retryRequestEnvelope(await createRequest(), sender));
    return;
  }
  const post = async (envelope: Envelope): Promise<void> => {
    try {
      await send(envelope);
    } catch (error) {
      if (relayOperationRefusal(error) !== 'RETRY_CONFLICT') throw error;
    }
  };
  const create = async (attempt: number, retryId: string): Promise<Envelope> => {
    const envelope = await retryRequestEnvelope(await createRequest(), sender, {
      failedEnvelopeId,
      retryId,
      attempt,
    });
    await storeRetryRequest(store, {
      failedEnvelopeId,
      retryId,
      attempt,
      requestedAt: envelope.timestamp,
      ...(failed.fingerprint !== undefined && { fingerprint: failed.fingerprint }),
      answered: false,
      envelope,
    });
    return envelope;
  };
  if (!failed.stored) {
    await post(await create(1, await generateUuidV4()));
    return;
  }
  const { attempt, retryId } = failed.stored;
  if (failed.member !== undefined && failed.stored.answered) {
    await post(await create(attempt + 1, retryId));
    return;
  }
  try {
    await post(failed.stored.envelope);
    return;
  } catch (error) {
    if (relayOperationRefusal(error) !== 'OPERATION_EXPIRED') throw error;
  }
  // The Relay no longer admits or replays the stored operation. The new
  // attempt replaces the record before its post.
  await post(await create(attempt + 1, retryId));
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
