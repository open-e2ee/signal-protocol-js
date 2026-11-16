/**
 * The self-check schedule. All times are Unix milliseconds of the local
 * clock. `random` gives a value in [0, 1).
 *
 * - The first check runs at a random time in [now, now + 168 h).
 * - After a pass, a not-logged result, or a second failure, the next check
 *   runs at completion + 7 d + a random time in [0, 8 h].
 * - After a first failure or an unavailable result, the next check runs at
 *   completion + 24 h.
 * - A timer waits at most 24 h and then reads the record again. An overdue
 *   check runs once, and the next time counts from its completion, so missed
 *   weeks give no backlog.
 */

const HOUR_MILLISECONDS = 60 * 60 * 1_000;
const DAY_MILLISECONDS = 24 * HOUR_MILLISECONDS;

/** The window of the first self-check after the record is created. */
export const FIRST_SELF_CHECK_WINDOW_MILLISECONDS = 168 * HOUR_MILLISECONDS;
/** The interval between two self-checks that did not fail for the first time. */
export const SELF_CHECK_INTERVAL_MILLISECONDS = 7 * DAY_MILLISECONDS;
/** The largest random delay that the interval gets. */
export const SELF_CHECK_JITTER_MILLISECONDS = 8 * HOUR_MILLISECONDS;
/** The delay after a first failure or an unavailable result. */
export const SELF_CHECK_RETRY_MILLISECONDS = DAY_MILLISECONDS;
/** The longest wait of one schedule timer. */
export const MAXIMUM_SELF_CHECK_TIMER_MILLISECONDS = DAY_MILLISECONDS;

/** The time of the first self-check. */
export function firstSelfCheckAt(now: number, random: () => number): number {
  return now + Math.floor(random() * FIRST_SELF_CHECK_WINDOW_MILLISECONDS);
}

/** The time of the next weekly self-check after `completion`. */
export function weeklySelfCheckAt(completion: number, random: () => number): number {
  return (
    completion +
    SELF_CHECK_INTERVAL_MILLISECONDS +
    Math.floor(random() * (SELF_CHECK_JITTER_MILLISECONDS + 1))
  );
}

/** The time of the self-check after a first failure or an unavailable result. */
export function retrySelfCheckAt(completion: number): number {
  return completion + SELF_CHECK_RETRY_MILLISECONDS;
}

/** The wait of the schedule timer: 0 for an overdue check, at most 24 h. */
export function selfCheckTimerDelay(nextCheckAt: number, now: number): number {
  return Math.min(Math.max(nextCheckAt - now, 0), MAXIMUM_SELF_CHECK_TIMER_MILLISECONDS);
}
