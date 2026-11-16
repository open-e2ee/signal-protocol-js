/**
 * The recheck rules of a contact check. A result that a Relay delay can
 * cause gets a new check later, and the event comes only when the later
 * check confirms it.
 *
 * | Previous | Outcome | Next | Event |
 * | --- | --- | --- | --- |
 * | any | pass | none | no |
 * | none, or 0 strikes | `LOGGED_KEY_MISMATCH`, or not-logged | 1 strike, check at + 2 h | no |
 * | 1 strike | `LOGGED_KEY_MISMATCH`, or not-logged | none | yes, the code of this outcome |
 * | any | append pending, less than 24 h since the first | pending, check after the wait | no |
 * | any | append pending, 24 h or more since the first | none | `LOG_APPEND_OVERDUE` |
 * | any | another failure | none | yes, its code |
 * | none | unavailable | none | no |
 * | a recheck | unavailable | unchanged, check after its wait | no |
 *
 * - Not-logged here means a not-logged result without `appendPending`. Its
 *   event code is `IDENTITY_NOT_LOGGED`.
 * - `not-logged.ts` owns the waits of a pending append and its limit.
 * - A pending append is not a strike and keeps the strikes. A not-logged
 *   result without `appendPending` ends the run of pending appends.
 */
import type { KeyTransparencyVerificationError } from '../../internal/protocol/key-transparency/errors';
import {
  APPEND_PENDING_FIRST_WAIT_MILLISECONDS,
  identityNotLoggedError,
  nextAppendPending,
} from './not-logged';
import type { ContactRecheckSchedule } from './state';
import type { KeyTransparencyCheckOutcome } from './verified-search';

/** The wait before the recheck of a key mismatch or a not-logged result. */
export const CONTACT_RECHECK_DELAY_MILLISECONDS = 2 * 60 * 60 * 1_000;

/** The recheck after one outcome, and the event to raise, if any. */
export interface ContactRecheckTransition {
  readonly recheck: ContactRecheckSchedule | undefined;
  readonly event: KeyTransparencyVerificationError | undefined;
}

const NO_CHANGE: ContactRecheckTransition = { recheck: undefined, event: undefined };

function strike(
  previous: ContactRecheckSchedule | undefined,
  error: KeyTransparencyVerificationError,
  now: number
): ContactRecheckTransition {
  if (previous?.strikes === 1) return { recheck: undefined, event: error };
  return {
    recheck: { nextCheckAt: now + CONTACT_RECHECK_DELAY_MILLISECONDS, strikes: 1 },
    event: undefined,
  };
}

function pending(
  previous: ContactRecheckSchedule | undefined,
  now: number
): ContactRecheckTransition {
  const step = nextAppendPending(previous, now);
  if (step.kind === 'overdue') return { recheck: undefined, event: step.error };
  return {
    recheck: { nextCheckAt: step.nextCheckAt, strikes: previous?.strikes ?? 0, ...step.run },
    event: undefined,
  };
}

/** Applies one outcome to the recheck of a pair. See the table above. */
export function nextContactRecheck(
  previous: ContactRecheckSchedule | undefined,
  outcome: KeyTransparencyCheckOutcome,
  now: number
): ContactRecheckTransition {
  switch (outcome.kind) {
    case 'pass':
      return NO_CHANGE;
    case 'not-logged':
      return outcome.appendPending
        ? pending(previous, now)
        : strike(previous, identityNotLoggedError(), now);
    case 'failure':
      return outcome.error.code === 'LOGGED_KEY_MISMATCH'
        ? strike(previous, outcome.error, now)
        : { recheck: undefined, event: outcome.error };
    case 'unavailable':
      if (previous === undefined) return NO_CHANGE;
      return {
        recheck: {
          ...previous,
          nextCheckAt:
            now +
            (previous.pendingSince === undefined
              ? CONTACT_RECHECK_DELAY_MILLISECONDS
              : (previous.wait ?? APPEND_PENDING_FIRST_WAIT_MILLISECONDS)),
        },
        event: undefined,
      };
  }
}
