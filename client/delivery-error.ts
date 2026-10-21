/**
 * The delivery error of a failed incoming envelope on the requester device.
 *
 * A failed decrypt that asks the sender for a resend stores a request
 * record and acknowledges the failed envelope. The record decides when the
 * application learns that the content did not come: `onDeliveryError` runs
 * for the record, and `onDeliveryRecovered` runs when the content comes
 * back after the error. Each hook runs at least once. The record is marked
 * only after the hook returns, as `reportDeliveryError` and
 * `reportDeliveryRecovered` tell. The content hint of the failed envelope
 * sets the time of the error:
 *
 * - `Default`, or no hint: at the first failure.
 * - `Resendable`: `RETRY_PLACEHOLDER_DEADLINE_MS` after the first failure.
 * - `Implicit`: never. The receive paths store no record for it.
 *
 * A rate limit that refused the request, and the end of the request, make
 * the error due at once. The error deletes nothing, and the attempts of the
 * request continue after it. Each function runs under the processed lock
 * of the failed envelope, as each write of its record does.
 *
 * A failure that no resend can repair stores no request record. The
 * application hears about it through `onDecryptionError`, and the receive
 * path acknowledges the envelope. `receiveRefusal` decides this for both
 * receive paths.
 */

import { base64ToBytes } from '../internal/crypto';
import {
  getProcessedEnvelope,
  getRetryRequest,
  storeProcessedEnvelope,
  updateRetryRequest,
  type StoredRetryRequest,
} from '../local/store/reliability';
import type { Base64 } from '../types';
import { EncryptionError, EncryptionErrorCode } from '../types/errors';
import { ContentHint } from '../types/messages';
import { RETRY_PLACEHOLDER_DEADLINE_MS } from './constants';
import {
  callHook,
  type DeliveryErrorCause,
  type DeliveryRecoveredEvent,
  type SignalProtocolClientHooks,
} from './event-hooks';
import { GroupReceiveRefusedError } from './group-receive-authorization';

type DeliveryErrorStore = Parameters<typeof getRetryRequest>[0];

/**
 * When the delivery error of a request record is due, and why. Null when
 * the record reports no error: the error ran, the failed envelope has the
 * Implicit hint, or the record has no receive time or sender.
 *
 * @param record - The stored request record.
 * @returns The time when the error is due, 0 for at once, and its cause.
 */
export function deliveryErrorDue(
  record: StoredRetryRequest
): { readonly at: number; readonly cause: DeliveryErrorCause } | null {
  if (
    record.errorShown ||
    record.receivedAt === undefined ||
    record.failedSender === undefined ||
    record.contentHint === ContentHint.Implicit
  ) {
    return null;
  }
  if (
    record.terminal?.class === 'abuse-allowance-exhausted' ||
    record.lastFailureClass === 'rate-refusal'
  ) {
    return { at: 0, cause: 'rate-limit' };
  }
  if (record.terminal) return { at: 0, cause: 'request-ended' };
  if (record.contentHint === ContentHint.Resendable) {
    return { at: record.receivedAt + RETRY_PLACEHOLDER_DEADLINE_MS, cause: 'deadline' };
  }
  return { at: 0, cause: 'content-hint' };
}

/**
 * Run `onDeliveryError` for one failed envelope when its error is due, and
 * then store the record as shown. A failed envelope whose content the
 * application has gets no error.
 *
 * The hook is called directly, not through `callHook`, so a hook that
 * throws, and the RelayWorkStopped of a stop, propagate and leave the record
 * not shown. The rule is: mark only after the hook returns, and keep the
 * caller alive. The scheduler logs the error, keeps the next attempt time
 * of the record, and goes on with the next record. The receive path does
 * not acknowledge the failed envelope. The next scheduler pass, at the next
 * start or the next armed time, or the redelivery runs the hook again.
 *
 * @param storage - The local store that keeps the request records.
 * @param hooks - The client hooks.
 * @param failedEnvelopeId - The failed envelope of the record.
 * @param now - The current time.
 * @returns The time when the error of the record is due later, or
 *   Infinity when the record needs no later check.
 */
export async function reportDeliveryError(
  storage: DeliveryErrorStore,
  hooks: SignalProtocolClientHooks | undefined,
  failedEnvelopeId: string,
  now = Date.now()
): Promise<number> {
  const record = await getRetryRequest(storage, failedEnvelopeId, now);
  const due = record ? deliveryErrorDue(record) : null;
  if (!record || !due) return Infinity;
  if ((await getProcessedEnvelope(storage, failedEnvelopeId, now))?.fulfilled) return Infinity;
  if (due.at > now) return due.at;
  const hook = hooks?.onDeliveryError;
  if (hook) await hook({ ...deliveryEvent(record)!, cause: due.cause });
  await updateRetryRequest(storage, failedEnvelopeId, record.retryId, record.attempt, {
    errorShown: true,
  });
  return Infinity;
}

/**
 * Run `onDeliveryRecovered` for a failed envelope whose content came back,
 * when `onDeliveryError` ran for it, and then store the record as
 * recovered. It does nothing until the application finished the content:
 * the receive record of the resend completed and marked the failed envelope
 * `completed`. A fulfilled envelope only stops the retry scheduler. It
 * does nothing when the record is stored as recovered. The receive queue
 * runs it after each completion of a resend. Each receive in the family,
 * and each scheduler pass, runs it again for a record that the hook did not
 * mark.
 *
 * The hook is called directly, not through `callHook`, so a hook that
 * throws, and the RelayWorkStopped of a stop, propagate and leave the record
 * not recovered. The rule is: mark only after the hook returns. The record
 * stays until its retention ends, so the hook runs at least once.
 *
 * @param storage - The local store that keeps the request records.
 * @param hooks - The client hooks.
 * @param failedEnvelopeId - The failed envelope of the record.
 * @param now - The current time.
 */
export async function reportDeliveryRecovered(
  storage: DeliveryErrorStore,
  hooks: SignalProtocolClientHooks | undefined,
  failedEnvelopeId: string,
  now = Date.now()
): Promise<void> {
  const record = await getRetryRequest(storage, failedEnvelopeId, now);
  if (!record?.errorShown || record.recoveredEmitted) return;
  const event = deliveryEvent(record);
  if (!event) return;
  if (!(await getProcessedEnvelope(storage, failedEnvelopeId, now))?.completed) return;
  const hook = hooks?.onDeliveryRecovered;
  if (hook) await hook(event);
  await updateRetryRequest(storage, failedEnvelopeId, record.retryId, record.attempt, {
    recoveredEmitted: true,
  });
}

/** The event fields of a record, or undefined when it has no receive time or sender. */
function deliveryEvent(record: StoredRetryRequest): DeliveryRecoveredEvent | undefined {
  const { receivedAt, failedSender } = record;
  if (receivedAt === undefined || failedSender === undefined) return undefined;
  return {
    failedEnvelopeId: record.failedEnvelopeId,
    ...(record.failedClientMessageId !== undefined && {
      clientMessageId: record.failedClientMessageId,
    }),
    ...(record.groupId !== undefined && { groupId: record.groupId }),
    senderUserId: failedSender.userId,
    senderDeviceId: failedSender.deviceId,
    groupMessage: record.groupMessage === true,
    receivedAt,
  };
}

/**
 * A receive failure that no resend can repair. The sender would send the
 * same content again, and it would fail again.
 *
 * - `authorization`: the verified group state refuses the sender.
 * - `untrusted-identity`: the local device does not trust the identity
 *   of the sender.
 * - `malformed`: the envelope does not decode, or its message does not
 *   parse.
 */
export type ReceiveRefusal = 'authorization' | 'untrusted-identity' | 'malformed';

/**
 * The refusal of a failed decrypt, or null when a resend can repair the
 * failure. The relay subscription route and `processIncomingEnvelope`
 * both decide with this function.
 *
 * @param error - The error of the failed decrypt.
 */
export function receiveRefusal(error: unknown): ReceiveRefusal | null {
  if (error instanceof GroupReceiveRefusedError) return 'authorization';
  if (!(error instanceof EncryptionError)) return null;
  if (error.code === EncryptionErrorCode.UNTRUSTED_IDENTITY) return 'untrusted-identity';
  if (error.code === EncryptionErrorCode.INVALID_CIPHERTEXT) return 'malformed';
  return null;
}

/**
 * The bytes of the ciphertext of a delivered envelope.
 *
 * @param ciphertext - The ciphertext as the envelope holds it.
 * @throws EncryptionError INVALID_CIPHERTEXT when the ciphertext is not
 *   base64, which makes the envelope malformed.
 */
export function envelopeCiphertextBytes(ciphertext: string | Uint8Array): Uint8Array {
  if (typeof ciphertext !== 'string') return ciphertext;
  try {
    return base64ToBytes(ciphertext as Base64);
  } catch (error) {
    throw new EncryptionError(
      'The envelope ciphertext is not base64',
      EncryptionErrorCode.INVALID_CIPHERTEXT,
      { originalError: error as Error }
    );
  }
}

/**
 * Report a refused envelope to the application, and store the envelope
 * as processed. A redelivery on either receive path is then dropped with
 * no decrypt, so the application hears about the refusal once. The
 * caller acknowledges the envelope after this. The hook runs before the
 * write, so a stop between the two runs the hook again at the
 * redelivery. Content of a group that the user blocked is dropped with
 * no report, as Signal drops it.
 *
 * @param storage - The local store that keeps the processed records.
 * @param hooks - The client hooks.
 * @param envelope - The refused envelope. For a sealed envelope, its
 *   sender is the unsealed sender.
 * @param error - The error of the failed decrypt.
 * @param fingerprint - The fingerprint of the delivered envelope.
 * @param reported - True when the decrypt already ran
 *   `onDecryptionError` for the error.
 */
export async function reportReceiveRefusal(
  storage: DeliveryErrorStore,
  hooks: SignalProtocolClientHooks | undefined,
  envelope: {
    readonly id?: string;
    readonly senderUserId: string;
    readonly senderDeviceId: number;
  },
  error: Error,
  fingerprint: string | undefined,
  reported = false
): Promise<void> {
  if (!reported) await reportReceiveDenial(hooks, envelope, error);
  if (envelope.id) await storeProcessedEnvelope(storage, envelope.id, Date.now(), fingerprint);
}

/**
 * Report a refusal to the application with `onDecryptionError`, and write
 * nothing. The receive queue writes the denied record of committed
 * content after this, in the completion of the receive record. Content of
 * a group that the user blocked has no report.
 *
 * @param hooks - The client hooks.
 * @param sender - The sender of the refused content.
 * @param error - The refusal.
 */
export async function reportReceiveDenial(
  hooks: SignalProtocolClientHooks | undefined,
  sender: { readonly senderUserId: string; readonly senderDeviceId: number },
  error: Error
): Promise<void> {
  if (error instanceof GroupReceiveRefusedError && error.reason === 'blocked') return;
  const sessionId = `${sender.senderUserId}:${sender.senderDeviceId}`;
  await callHook(hooks, 'onDecryptionError', sessionId, error);
}
