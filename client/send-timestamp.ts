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
 * A send that repeats a stored `clientMessageId` with its stored timestamp
 * is not checked again: its epoch can be older than 24 hours, and the Relay
 * replays an accepted operation by its epoch. With another timestamp, the
 * check applies. A timestamp that the SDK
 * reads from its own clock is never checked.
 *
 * The client checks a new send once, at the entry of the send, against one
 * clock reading. It then marks the options with the origin of the timestamp,
 * so the inner checks of that send do not check it again with a later clock.
 * The mark has a symbol key that no package subpath exports, and the client
 * sets it after it spreads the application's options, so an application
 * cannot set it.
 */

import { InvalidSendTimestampError } from '../types/errors';
import type { SendOptions } from './types';

/** A new send refuses a timestamp more than this far ahead of the SDK clock. */
export const SEND_TIMESTAMP_FUTURE_SKEW_MILLISECONDS = 5 * 60 * 1_000;

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

/**
 * Check the timestamp of a new send once, and return the options with the
 * mark that stops the inner checks of the send.
 *
 * @throws {InvalidSendTimestampError} as `checkNewSendTimestamp` does
 */
export function withCheckedSendTimestamp<
  T extends Pick<SendOptions, 'timestamp'> & SendTimestampOrigin,
>(options: T, now: number = Date.now()): T {
  if (options.timestamp == null || options[SEND_TIMESTAMP_ORIGIN] !== undefined) return options;
  checkNewSendTimestamp(options, now);
  return { ...options, [SEND_TIMESTAMP_ORIGIN]: 'checked' };
}

/**
 * The client timestamp of a new send: the checked timestamp of the options,
 * or the SDK clock when the options have none.
 *
 * @throws {InvalidSendTimestampError} as `checkNewSendTimestamp` does
 */
export function newSendClientTimestamp(
  options: Pick<SendOptions, 'timestamp'> & SendTimestampOrigin,
  now: number = Date.now()
): number {
  checkNewSendTimestamp(options, now);
  return options.timestamp ?? now;
}
