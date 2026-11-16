/**
 * The rules of a not-logged search result. The contact recheck and the
 * self-check use the same rules.
 *
 * - A plain not-logged result is a strike. A second strike in a row is a
 *   failure with `IDENTITY_NOT_LOGGED`. A lane gets pinned keys only after
 *   the Relay logged the existing identities of that lane, so the log has an
 *   entry for each identity that a correct Relay serves.
 * - A not-logged result with `appendPending` is not a pass and not a
 *   failure. The client checks again after a wait. The wait starts at 2 min
 *   and doubles to at most 1 h. The last check of a run of pending appends
 *   is 24 h after the first pending result. A pending append at that check
 *   gives `LOG_APPEND_OVERDUE`.
 */
import { KeyTransparencyVerificationError } from '../../internal/protocol/key-transparency/errors';

/** The first wait before the check after a pending append. */
export const APPEND_PENDING_FIRST_WAIT_MILLISECONDS = 2 * 60 * 1_000;
/** The longest wait before the check after a pending append. */
export const APPEND_PENDING_MAXIMUM_WAIT_MILLISECONDS = 60 * 60 * 1_000;
/** The time after the first pending append result that gives the failure. */
export const APPEND_PENDING_LIMIT_MILLISECONDS = 24 * 60 * 60 * 1_000;

/** A run of pending append results. */
export interface AppendPendingRun {
  /** The time of the first pending append result of the run. */
  readonly pendingSince: number;
  /** The wait before the next check. */
  readonly wait: number;
}

/** The next step of a run of pending appends after one more pending result. */
export type AppendPendingStep =
  | { readonly kind: 'waiting'; readonly run: AppendPendingRun; readonly nextCheckAt: number }
  | { readonly kind: 'overdue'; readonly error: KeyTransparencyVerificationError };

/**
 * Applies one pending append result at `now` to the run in `previous`. A
 * `previous` with no `pendingSince` starts a new run.
 */
export function nextAppendPending(
  previous: { readonly pendingSince?: number; readonly wait?: number } | undefined,
  now: number
): AppendPendingStep {
  const pendingSince = previous?.pendingSince ?? now;
  const limit = pendingSince + APPEND_PENDING_LIMIT_MILLISECONDS;
  if (now >= limit) {
    return {
      kind: 'overdue',
      error: new KeyTransparencyVerificationError(
        'LOG_APPEND_OVERDUE',
        'The Relay said for 24 hours that the identity log append waits'
      ),
    };
  }
  const wait =
    previous?.pendingSince === undefined || previous.wait === undefined
      ? APPEND_PENDING_FIRST_WAIT_MILLISECONDS
      : Math.min(previous.wait * 2, APPEND_PENDING_MAXIMUM_WAIT_MILLISECONDS);
  return { kind: 'waiting', run: { pendingSince, wait }, nextCheckAt: Math.min(now + wait, limit) };
}

/** The failure of a second plain not-logged result in a row. */
export function identityNotLoggedError(): KeyTransparencyVerificationError {
  return new KeyTransparencyVerificationError(
    'IDENTITY_NOT_LOGGED',
    'Two identity log searches found no entry for the identity'
  );
}
