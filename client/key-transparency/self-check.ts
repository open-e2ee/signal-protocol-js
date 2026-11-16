/**
 * The weekly self-check: the client searches the log for its own account
 * and compares the latest entry with its own identity. A device link makes
 * no entry, so each device of the account expects the same identity.
 *
 * Health transitions, with the next check time:
 *
 * | From | Outcome | To | Next check | Event |
 * | --- | --- | --- | --- | --- |
 * | any | pass | `ok` | completion + 7 d + [0, 8 h] | no |
 * | any | pending append, less than 24 h since the first | unchanged | completion + the pending wait | no |
 * | `failing` | pending append, 24 h or more since the first | `failing` | completion + 7 d + [0, 8 h] | no |
 * | another health | pending append, 24 h or more since the first | `failing` | completion + 7 d + [0, 8 h] | yes, `LOG_APPEND_OVERDUE` |
 * | `unknown` or `ok` | failure | `intermittent` | completion + 24 h | no |
 * | `intermittent` | failure | `failing` | completion + 7 d + [0, 8 h] | yes |
 * | `failing` | failure | `failing` | completion + 7 d + [0, 8 h] | no |
 * | any | unavailable | unchanged | completion + 24 h, or the pending wait | no |
 *
 * So the event comes on the second consecutive failure, once for each
 * failing streak. The 24 h retry also covers the Relay append delay after an
 * own key rotation.
 *
 * - A `mismatch` search result is a failure with `LOGGED_KEY_MISMATCH`.
 * - A plain not-logged result is a failure with `IDENTITY_NOT_LOGGED`.
 * - A pending append is not a pass and not a failure, and keeps the health.
 *   `not-logged.ts` owns its waits and its 24 h limit. A pass, a failure, or
 *   an overdue append ends the run of pending appends.
 */
import type { KeyTransparencyVerificationError } from '../../internal/protocol/key-transparency/errors';
import {
  APPEND_PENDING_FIRST_WAIT_MILLISECONDS,
  identityNotLoggedError,
  nextAppendPending,
} from './not-logged';
import { firstSelfCheckAt, retrySelfCheckAt, weeklySelfCheckAt } from './schedule';
import {
  claimSelfCheckLease,
  readSelfCheck,
  releaseSelfCheckLease,
  writeSelfCheck,
  type SelfCheckHealth,
  type SelfCheckRecord,
} from './state';
import {
  checkLoggedIdentity,
  type IdentityLogSearchContext,
  type KeyTransparencyCheckOutcome,
} from './verified-search';

/** A self-check record after one outcome, and the event to raise, if any. */
export interface SelfCheckTransition {
  readonly record: SelfCheckRecord;
  readonly event: KeyTransparencyVerificationError | undefined;
}

function failed(
  health: SelfCheckHealth,
  error: KeyTransparencyVerificationError,
  completion: number,
  random: () => number
): SelfCheckTransition {
  const lastOutcome = { at: completion, kind: 'failure', code: error.code } as const;
  if (health === 'unknown' || health === 'ok') {
    return {
      record: { nextCheckAt: retrySelfCheckAt(completion), health: 'intermittent', lastOutcome },
      event: undefined,
    };
  }
  return {
    record: { nextCheckAt: weeklySelfCheckAt(completion, random), health: 'failing', lastOutcome },
    event: health === 'intermittent' ? error : undefined,
  };
}

function pending(
  previous: SelfCheckRecord | undefined,
  health: SelfCheckHealth,
  completion: number,
  random: () => number
): SelfCheckTransition {
  const step = nextAppendPending(previous, completion);
  if (step.kind === 'overdue') {
    return {
      record: {
        nextCheckAt: weeklySelfCheckAt(completion, random),
        health: 'failing',
        lastOutcome: { at: completion, kind: 'failure', code: step.error.code },
      },
      event: health === 'failing' ? undefined : step.error,
    };
  }
  return {
    record: {
      nextCheckAt: step.nextCheckAt,
      health,
      lastOutcome: { at: completion, kind: 'not-logged' },
      ...step.run,
    },
    event: undefined,
  };
}

/** Applies one outcome to the record. See the table above. */
export function nextSelfCheckRecord(
  previous: SelfCheckRecord | undefined,
  outcome: KeyTransparencyCheckOutcome,
  completion: number,
  random: () => number
): SelfCheckTransition {
  const health: SelfCheckHealth = previous?.health ?? 'unknown';
  switch (outcome.kind) {
    case 'pass':
      return {
        record: {
          nextCheckAt: weeklySelfCheckAt(completion, random),
          health: 'ok',
          lastOutcome: { at: completion, kind: 'pass' },
        },
        event: undefined,
      };
    case 'not-logged':
      return outcome.appendPending
        ? pending(previous, health, completion, random)
        : failed(health, identityNotLoggedError(), completion, random);
    case 'unavailable': {
      const run =
        previous?.pendingSince === undefined
          ? undefined
          : {
              pendingSince: previous.pendingSince,
              wait: previous.wait ?? APPEND_PENDING_FIRST_WAIT_MILLISECONDS,
            };
      return {
        record: {
          nextCheckAt: run === undefined ? retrySelfCheckAt(completion) : completion + run.wait,
          health,
          lastOutcome: { at: completion, kind: 'unavailable' },
          ...run,
        },
        event: undefined,
      };
    }
    case 'failure':
      return failed(health, outcome.error, completion, random);
  }
}

/** What the self-check needs. */
export interface SelfCheckContext {
  readonly search: IdentityLogSearchContext;
  readonly ownUserId: string;
  /** The encoded own identity, or `undefined` when the store has none. */
  readonly ownIdentity: () => Promise<Uint8Array | undefined>;
  /** A random name of this client for the lease. */
  readonly holder: string;
  readonly random: () => number;
  /** Raises the self-check failure event. It must not throw. */
  readonly report: (error: KeyTransparencyVerificationError, detectedAt: number) => void;
}

/** The result of one call to `runDueSelfCheck`. */
export type SelfCheckRun =
  | { readonly kind: 'not-due'; readonly nextCheckAt: number }
  | { readonly kind: 'checked'; readonly nextCheckAt: number }
  | { readonly kind: 'busy'; readonly until: number }
  | { readonly kind: 'no-registration' }
  | { readonly kind: 'not-recorded' };

/**
 * Reads the schedule, and runs the self-check when it is due. A store with
 * no record gets a first check time and no check. Only the lease holder
 * checks.
 */
export async function runDueSelfCheck(context: SelfCheckContext): Promise<SelfCheckRun> {
  const { store, keys, now } = context.search;
  const stored = await readSelfCheck(store, keys);
  if (stored.value === undefined) {
    const record: SelfCheckRecord = {
      nextCheckAt: firstSelfCheckAt(now(), context.random),
      health: 'unknown',
    };
    if (await writeSelfCheck(store, keys, stored.raw, record)) {
      return { kind: 'not-due', nextCheckAt: record.nextCheckAt };
    }
    const current = (await readSelfCheck(store, keys)).value;
    return current === undefined
      ? { kind: 'not-recorded' }
      : { kind: 'not-due', nextCheckAt: current.nextCheckAt };
  }
  if (stored.value.nextCheckAt > now()) {
    return { kind: 'not-due', nextCheckAt: stored.value.nextCheckAt };
  }
  const identity = await context.ownIdentity();
  if (identity === undefined) return { kind: 'no-registration' };
  const claim = await claimSelfCheckLease(store, keys, context.holder, now());
  if (claim.kind === 'busy') return claim;
  try {
    // Another client can have checked and released the lease after the
    // first read.
    const due = await readSelfCheck(store, keys);
    if (due.value !== undefined && due.value.nextCheckAt > now()) {
      return { kind: 'not-due', nextCheckAt: due.value.nextCheckAt };
    }
    const outcome = await checkLoggedIdentity(context.search, context.ownUserId, identity);
    const completion = now();
    let expected = due;
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const transition = nextSelfCheckRecord(expected.value, outcome, completion, context.random);
      if (await writeSelfCheck(store, keys, expected.raw, transition.record)) {
        if (transition.event !== undefined) context.report(transition.event, completion);
        return { kind: 'checked', nextCheckAt: transition.record.nextCheckAt };
      }
      expected = await readSelfCheck(store, keys);
    }
    return { kind: 'not-recorded' };
  } finally {
    await releaseSelfCheckLease(store, keys, claim.lease);
  }
}
