/**
 * The client timestamp of a new send, which is the operation epoch of the
 * send.
 *
 * The SDK stores the timestamp with the send intent, and each retry of the
 * send keeps it, so the Relay sees one operation however often the SDK posts
 * it. From the Relay release that follows v2026.10.25, the Relay admits a
 * mailbox delivery epoch and a new group fan-out operation at most 5 minutes
 * ahead of its clock and at most 24 hours behind it. Earlier Relay releases
 * admit a new operation only within 5 minutes of its epoch. The SDK check
 * uses the same bounds, so a new send checks an application-supplied
 * timestamp against the SDK clock before it stores the intent or posts
 * anything. A sync to linked devices whose epoch is an application-supplied
 * time gets the same check before it posts.
 *
 * Each send timestamp is unique per sender device. A new send reserves its
 * timestamp in the sent-timestamp index of the store before it writes its
 * intent and before it posts anything. A timestamp that the SDK reads from
 * its clock and that a different send holds moves to the next free
 * millisecond, and the moved value must stay at most 5 minutes ahead of the
 * SDK clock. An application-supplied timestamp that a different send holds
 * throws `InvalidSendTimestampError` with the reason `already_used`. A send
 * that fails before its intent write removes its reservation. A reservation
 * that a crash left before its intent write holds its timestamp only for
 * `SEND_TIMESTAMP_RESERVATION_GRACE_MILLISECONDS`.
 *
 * A send that repeats a stored `clientMessageId` with its stored timestamp
 * is not checked again: its epoch can be older than 24 hours, and the Relay
 * replays an accepted operation by its epoch. With another timestamp, the
 * send is refused. A manual resend, a retry-receipt answer and a group
 * resend use the timestamp of their intent and reserve nothing. A timestamp
 * that the SDK reads from its own clock is never checked against the window.
 *
 * The client checks a new send once, at the entry of the send, against one
 * clock reading. It then marks the options with the origin of the timestamp,
 * so the inner checks of that send do not check it again with a later clock.
 * A send entry that reserved the timestamp marks it `checked`, and the inner
 * reservation of the send finds the entry with its own ID. The mark has a
 * symbol key that no package subpath exports, and the client sets it after it
 * spreads the application's options, so an application cannot set it.
 */

import {
  releaseSendTimestamp,
  reserveSendTimestamp,
  withOutgoingMessageIntentLock,
} from '../local/store/reliability';
import { InvalidSendTimestampError } from '../types/errors';
import type { SendOptions } from './types';

/** A new send refuses a timestamp more than this far ahead of the SDK clock. */
export const SEND_TIMESTAMP_FUTURE_SKEW_MILLISECONDS = 5 * 60 * 1_000;

/**
 * The grace period of a pending send timestamp reservation: 5 minutes.
 *
 * A reservation is pending from the reservation until the intent write of
 * its send. A new send that meets a different ID at its timestamp counts
 * that ID as committed when it has no pending reservation, as in flight when
 * its pending reservation is younger than this period, and as an orphan when
 * its pending reservation is this old or older and no intent exists. An
 * orphan is what a crash or a closed tab leaves between the reservation and
 * the intent write. The new send removes each orphan and takes the
 * timestamp. Only a committed or an in-flight ID refuses an application
 * timestamp with `already_used`, or moves a timestamp from the SDK clock.
 *
 * A send that spends longer than this period between its reservation and its
 * intent write, and whose timestamp another send took in the meantime, throws
 * `InvalidSendTimestampError` with the reason `already_used` at the intent
 * write. It stores and posts nothing, so the device never posts two messages
 * with one timestamp.
 */
export const SEND_TIMESTAMP_RESERVATION_GRACE_MILLISECONDS = 5 * 60 * 1_000;

/** A new send refuses a timestamp more than this far behind the SDK clock. */
export const SEND_TIMESTAMP_MAX_AGE_MILLISECONDS = 24 * 60 * 60 * 1_000;

/** The key of the timestamp origin mark. No package subpath exports it. */
export const SEND_TIMESTAMP_ORIGIN: unique symbol = Symbol('sendTimestampOrigin');

/**
 * The origin of a timestamp that a send does not check again: `sdk-clock`
 * when the SDK read it from its own clock, and `checked` when the entry of
 * the send already checked it.
 */
export type SendTimestampOriginKind = 'sdk-clock' | 'checked';

/** The options of a send, with the mark of the origin of their `timestamp`. */
export interface SendTimestampOrigin {
  readonly [SEND_TIMESTAMP_ORIGIN]?: SendTimestampOriginKind;
}

/**
 * Check the timestamp of a new send, and throw when the SDK refuses it.
 *
 * @throws {InvalidSendTimestampError} when an application-supplied timestamp
 *   is not a safe positive integer, or is outside the window
 */
export function checkNewSendTimestamp(
  options: Pick<SendOptions, 'timestamp'> & SendTimestampOrigin,
  now: number = Date.now()
): void {
  const timestamp = options.timestamp;
  if (timestamp == null || options[SEND_TIMESTAMP_ORIGIN] !== undefined) return;
  const window = {
    earliest: now - SEND_TIMESTAMP_MAX_AGE_MILLISECONDS,
    latest: now + SEND_TIMESTAMP_FUTURE_SKEW_MILLISECONDS,
  };
  if (!Number.isSafeInteger(timestamp) || timestamp < 1) {
    throw new InvalidSendTimestampError(timestamp, 'not_safe_positive_integer', window);
  }
  if (timestamp > window.latest) {
    throw new InvalidSendTimestampError(timestamp, 'too_far_ahead', window);
  }
  if (timestamp < window.earliest) {
    throw new InvalidSendTimestampError(timestamp, 'too_old', window);
  }
}

/** The store of a send timestamp reservation. */
export type SendTimestampStore = Parameters<typeof reserveSendTimestamp>[0];

/** The timestamp that a new send reserved. */
export interface ReservedSendTimestamp {
  readonly clientMessageId: string;
  /** The client timestamp of the send. */
  readonly timestamp: number;
  /** The SDK clock at the reservation. */
  readonly reservedAt: number;
  /** True when this call wrote the reservation, so its error path removes it. */
  readonly reserved: boolean;
}

/**
 * Check and reserve the client timestamp of a new send. Without a timestamp
 * in the options, the SDK clock gives it. Call it before the intent write and
 * before any post of the send.
 *
 * @throws {InvalidSendTimestampError} as `checkNewSendTimestamp` does, with
 *   `already_used` when a different send holds an application-supplied
 *   timestamp, and with `too_far_ahead` when the next free millisecond after
 *   a timestamp from the SDK clock is more than 5 minutes ahead of the clock
 */
export async function reserveNewSendTimestamp(
  store: SendTimestampStore,
  options: Pick<SendOptions, 'timestamp'> & SendTimestampOrigin & { clientMessageId: string },
  now: number = Date.now()
): Promise<ReservedSendTimestamp> {
  checkNewSendTimestamp(options, now);
  const latest = now + SEND_TIMESTAMP_FUTURE_SKEW_MILLISECONDS;
  const fromClock = options.timestamp == null || options[SEND_TIMESTAMP_ORIGIN] === 'sdk-clock';
  const reservation = await reserveSendTimestamp(
    store,
    {
      clientMessageId: options.clientMessageId,
      timestamp: options.timestamp ?? now,
      origin: fromClock ? 'sdk-clock' : 'caller',
      latest,
      grace: SEND_TIMESTAMP_RESERVATION_GRACE_MILLISECONDS,
    },
    now
  );
  if (reservation.kind === 'used') {
    throw new InvalidSendTimestampError(reservation.timestamp, 'already_used');
  }
  if (reservation.kind === 'past-latest') {
    throw new InvalidSendTimestampError(reservation.timestamp, 'too_far_ahead', {
      earliest: now - SEND_TIMESTAMP_MAX_AGE_MILLISECONDS,
      latest,
    });
  }
  return {
    clientMessageId: options.clientMessageId,
    timestamp: reservation.timestamp,
    reservedAt: reservation.reservedAt,
    reserved: reservation.kind === 'reserved',
  };
}

/**
 * Remove the reservation of a new send that failed. A reservation that this
 * call did not write, or that the intent of the send owns, stays.
 */
export async function releaseNewSendTimestamp(
  store: SendTimestampStore,
  reservation: ReservedSendTimestamp
): Promise<void> {
  if (reservation.reserved) await releaseSendTimestamp(store, reservation);
}

/**
 * Remove the reservation of a new send that failed outside the intent lock,
 * as `releaseNewSendTimestamp` does. The release takes the intent lock of
 * the send first, so it does not run between the reservation check and the
 * intent write of a concurrent send with the same `clientMessageId`.
 */
export async function releaseNewSendTimestampWithLock(
  store: SendTimestampStore,
  reservation: ReservedSendTimestamp
): Promise<void> {
  if (!reservation.reserved) return;
  await withOutgoingMessageIntentLock(store, reservation.clientMessageId, () =>
    releaseSendTimestamp(store, reservation)
  );
}
