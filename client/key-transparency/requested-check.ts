/**
 * The contact checks that the app requests. One request checks the pinned
 * identity of one contact against the log, and returns the outcome of one
 * verified search.
 *
 * - The own account and a user with no pinned identity give
 *   `not-a-contact`, with no Relay read.
 * - While the stored self-check health is `failing`, a request gives
 *   `self-check-failing`, with no Relay read. A Relay that serves a wrong
 *   own identity can also serve wrong contact results.
 * - Concurrent requests for one `(userId, identity)` pair share one search.
 * - At most 10 requests start a search in each 60 s. A further request gives
 *   `rate-limited` at once. The background checks have a separate window, so
 *   a background burst never refuses a request. The Relay limits the reads of
 *   one IP address, and all clients behind it share that limit.
 * - A request applies no recheck rule. It raises no event, and it reads and
 *   writes no recheck. The search writes only the verified head.
 */
import { CONTACT_CHECK_WINDOW_MILLISECONDS, pairKey } from './contact-check';
import { readSelfCheck, type KeyTransparencyRecordKeys, type KeyTransparencyStore } from './state';
import type {
  KeyTransparencyCheckOutcome,
  KeyTransparencyUnavailableReason,
} from './verified-search';

/** The most requested checks that start a search in one window. */
export const REQUESTED_CONTACT_CHECKS_PER_WINDOW = 10;

/** What the requested checks need. */
export interface RequestedContactChecksOptions {
  /** The account address of the client. */
  readonly ownUserId: string;
  readonly store: KeyTransparencyStore;
  readonly keys: KeyTransparencyRecordKeys;
  readonly now: () => number;
  /** Runs one search for an encoded identity, after the check that runs now. */
  readonly search: (userId: string, identity: Uint8Array) => Promise<KeyTransparencyCheckOutcome>;
}

/** Gives the encoded pinned identity of the user, or `undefined` when there is none. */
export type PinnedIdentityRead = () => Promise<Uint8Array | undefined>;

/** Returns an `unavailable` outcome. */
export function unavailableCheck(
  reason: KeyTransparencyUnavailableReason
): KeyTransparencyCheckOutcome {
  return { kind: 'unavailable', reason };
}

/** The gates, the shared searches, and the window of the requested checks. */
export class RequestedContactChecks {
  readonly #options: RequestedContactChecksOptions;
  readonly #searches = new Map<string, Promise<KeyTransparencyCheckOutcome>>();
  /** The start times of the searches in the current window. */
  #starts: number[] = [];

  constructor(options: RequestedContactChecksOptions) {
    this.#options = options;
  }

  /** Checks the pinned identity of `userId`. A store error gives `unavailable` with `store`. */
  async check(userId: string, pinnedIdentity: PinnedIdentityRead): Promise<KeyTransparencyCheckOutcome> {
    const { ownUserId, store, keys, now, search } = this.#options;
    if (userId === ownUserId) return unavailableCheck('not-a-contact');
    let identity: Uint8Array | undefined;
    let failing: boolean;
    try {
      identity = await pinnedIdentity();
      if (identity === undefined) return unavailableCheck('not-a-contact');
      failing = (await readSelfCheck(store, keys)).value?.health === 'failing';
    } catch {
      return unavailableCheck('store');
    }
    if (failing) return unavailableCheck('self-check-failing');
    const key = pairKey(userId, identity);
    const running = this.#searches.get(key);
    if (running !== undefined) return running;
    const at = now();
    this.#starts = this.#starts.filter((start) => at - start < CONTACT_CHECK_WINDOW_MILLISECONDS);
    if (this.#starts.length >= REQUESTED_CONTACT_CHECKS_PER_WINDOW) {
      return unavailableCheck('rate-limited');
    }
    this.#starts.push(at);
    const result = search(userId, identity).finally(() => {
      this.#searches.delete(key);
    });
    this.#searches.set(key, result);
    return result;
  }
}
