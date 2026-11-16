/**
 * The background contact checks. After the client fetches the identity of a
 * contact, it checks that identity against the log.
 *
 * - Each `(userId, identity)` pair gets one first check for the life of the
 *   client. A new identity of the same user is a new pair.
 * - A result that a Relay delay can cause gets rechecks
 *   (`nextContactRecheck`). The rechecks are in the store, so a restart
 *   keeps them. When the store cannot keep a recheck, the client keeps it
 *   until it stops.
 * - One check runs at a time.
 * - At most 20 checks start in each 60 s. A further check waits until the
 *   oldest start of the window is 60 s old. The Relay limits the reads of
 *   one IP address, and all clients behind it share that limit.
 * - `offer` returns at once, so a send never waits for a check, and a check
 *   never refuses a send.
 *
 * Clients on one store share the rechecks. A client applies a recheck
 * result only when the stored recheck is still the one that it checked, and
 * it raises the event only after that write. A first check never replaces
 * a stored recheck.
 */
import { bytesToUrlSafeBase64 } from '../../internal/crypto';
import type { KeyTransparencyVerificationError } from '../../internal/protocol/key-transparency/errors';
import { nextContactRecheck } from './contact-recheck';
import {
  MAXIMUM_CONTACT_RECHECKS,
  readContactRechecks,
  writeContactRechecks,
  type ContactRecheckRecord,
  type ContactRecheckSchedule,
  type KeyTransparencyRecordKeys,
  type KeyTransparencyStore,
} from './state';
import type { KeyTransparencyCheckOutcome } from './verified-search';

/** The most contact checks that start in one window. */
export const CONTACT_CHECKS_PER_WINDOW = 20;
/** The length of the contact check window. */
export const CONTACT_CHECK_WINDOW_MILLISECONDS = 60_000;
/** The longest wait of the recheck timer. The timer then reads the times again. */
const MAXIMUM_RECHECK_TIMER_MILLISECONDS = 24 * 60 * 60 * 1_000;
/** The compare-and-set attempts of one recheck write. */
const RECHECK_WRITE_ATTEMPTS = 3;

/** The timer functions of the queue. */
export interface KeyTransparencyTimers {
  set(callback: () => void, delay: number): unknown;
  clear(handle: unknown): void;
}

/** What the contact queue needs. */
export interface ContactCheckQueueOptions {
  /** Checks one encoded contact identity against the log. */
  readonly check: (userId: string, identity: Uint8Array) => Promise<KeyTransparencyCheckOutcome>;
  /** Raises the contact failure event. It must not throw. */
  readonly report: (userId: string, error: KeyTransparencyVerificationError, detectedAt: number) => void;
  /** Gets each error that a check or a store call throws. It must not throw. */
  readonly onError: (error: unknown) => void;
  readonly now: () => number;
  readonly timers: KeyTransparencyTimers;
  /** The store of the rechecks. */
  readonly store: KeyTransparencyStore;
  readonly keys: KeyTransparencyRecordKeys;
}

/** A recheck that the client holds. */
interface HeldRecheck {
  readonly userId: string;
  readonly identity: Uint8Array;
  readonly schedule: ContactRecheckSchedule;
  /** True when the store has this schedule. */
  readonly persisted: boolean;
}

interface QueuedContactCheck {
  readonly key: string;
  readonly userId: string;
  readonly identity: Uint8Array;
  /** The recheck that this check runs for, or `undefined` for a first check. */
  readonly recheck: HeldRecheck | undefined;
}

type RecheckWrite =
  | { readonly kind: 'applied'; readonly persisted: boolean }
  | { readonly kind: 'superseded'; readonly stored: ContactRecheckRecord | undefined };

/** The key of one `(userId, identity)` pair. */
export function pairKey(userId: string, identity: Uint8Array): string {
  return `${userId}\u0000${bytesToUrlSafeBase64(identity)}`;
}

function sameSchedule(a: ContactRecheckSchedule, b: ContactRecheckSchedule): boolean {
  return (
    a.nextCheckAt === b.nextCheckAt &&
    a.strikes === b.strikes &&
    a.pendingSince === b.pendingSince &&
    a.wait === b.wait
  );
}

function scheduleOf(record: ContactRecheckRecord): ContactRecheckSchedule {
  return {
    nextCheckAt: record.nextCheckAt,
    strikes: record.strikes,
    ...(record.pendingSince === undefined ? {} : { pendingSince: record.pendingSince }),
    ...(record.wait === undefined ? {} : { wait: record.wait }),
  };
}

/** The queue of the background contact checks. */
export class ContactCheckQueue {
  readonly #options: ContactCheckQueueOptions;
  /** Each pair that was offered, that waits, or that has a recheck, for the life of the client. */
  readonly #seen = new Set<string>();
  readonly #rechecks = new Map<string, HeldRecheck>();
  /** The rechecks that wait in `#pending` or run. */
  readonly #queuedRechecks = new Set<string>();
  #pending: QueuedContactCheck[] = [];
  /** The start times of the checks in the current window. */
  #starts: number[] = [];
  #active = false;
  #running = false;
  #timer: unknown = undefined;
  #recheckTimer: unknown = undefined;
  /** Changes at each start and stop, so a late store read has no effect. */
  #generation = 0;

  constructor(options: ContactCheckQueueOptions) {
    this.#options = options;
  }

  /** Starts the checks and reads the stored rechecks. Offers before `start` are ignored. */
  start(): void {
    if (this.#active) return;
    this.#active = true;
    this.#generation += 1;
    void this.#load(this.#generation);
    this.#scheduleRechecks();
    this.#drain();
  }

  /**
   * Stops the checks. A check that runs completes. The waiting first checks
   * are dropped and not marked as checked, so a later offer can take them.
   * The rechecks stay, and a new start schedules them again.
   */
  stop(): void {
    if (!this.#active) return;
    this.#active = false;
    this.#generation += 1;
    for (const pending of this.#pending) {
      if (pending.recheck === undefined) this.#seen.delete(pending.key);
      else this.#queuedRechecks.delete(pending.key);
    }
    this.#pending = [];
    if (this.#timer !== undefined) this.#options.timers.clear(this.#timer);
    this.#timer = undefined;
    this.#clearRecheckTimer();
  }

  /** Offers one fetched contact identity. It returns at once. */
  offer(userId: string, identity: Uint8Array): void {
    if (!this.#active) return;
    const key = pairKey(userId, identity);
    if (this.#seen.has(key)) return;
    this.#seen.add(key);
    this.#pending.push({ key, userId, identity: identity.slice(), recheck: undefined });
    this.#drain();
  }

  async #load(generation: number): Promise<void> {
    let stored: readonly ContactRecheckRecord[];
    try {
      stored = (await readContactRechecks(this.#options.store, this.#options.keys)).value ?? [];
    } catch (error) {
      this.#options.onError(error);
      return;
    }
    if (generation !== this.#generation) return;
    for (const record of stored) {
      const key = pairKey(record.userId, record.identity);
      // A pair that this client has seen settles against the store itself.
      if (this.#seen.has(key)) continue;
      this.#seen.add(key);
      this.#rechecks.set(key, {
        userId: record.userId,
        identity: record.identity,
        schedule: scheduleOf(record),
        persisted: true,
      });
    }
    this.#scheduleRechecks();
  }

  #clearRecheckTimer(): void {
    if (this.#recheckTimer !== undefined) this.#options.timers.clear(this.#recheckTimer);
    this.#recheckTimer = undefined;
  }

  #scheduleRechecks(): void {
    this.#clearRecheckTimer();
    if (!this.#active) return;
    let earliest: number | undefined;
    for (const [key, recheck] of this.#rechecks) {
      if (this.#queuedRechecks.has(key)) continue;
      if (earliest === undefined || recheck.schedule.nextCheckAt < earliest) {
        earliest = recheck.schedule.nextCheckAt;
      }
    }
    if (earliest === undefined) return;
    const delay = Math.min(
      Math.max(earliest - this.#options.now(), 0),
      MAXIMUM_RECHECK_TIMER_MILLISECONDS
    );
    this.#recheckTimer = this.#options.timers.set(() => {
      this.#recheckTimer = undefined;
      this.#queueDueRechecks();
    }, delay);
  }

  #queueDueRechecks(): void {
    if (!this.#active) return;
    const now = this.#options.now();
    for (const [key, recheck] of this.#rechecks) {
      if (this.#queuedRechecks.has(key) || recheck.schedule.nextCheckAt > now) continue;
      this.#queuedRechecks.add(key);
      this.#pending.push({ key, userId: recheck.userId, identity: recheck.identity, recheck });
    }
    this.#drain();
    this.#scheduleRechecks();
  }

  #drain(): void {
    if (!this.#active || this.#running || this.#timer !== undefined) return;
    const next = this.#pending[0];
    if (next === undefined) return;
    const now = this.#options.now();
    this.#starts = this.#starts.filter(
      (start) => now - start < CONTACT_CHECK_WINDOW_MILLISECONDS
    );
    if (this.#starts.length >= CONTACT_CHECKS_PER_WINDOW) {
      this.#timer = this.#options.timers.set(() => {
        this.#timer = undefined;
        this.#drain();
      }, this.#starts[0]! + CONTACT_CHECK_WINDOW_MILLISECONDS - now);
      return;
    }
    this.#pending.shift();
    this.#starts.push(now);
    this.#running = true;
    void this.#run(next).finally(() => {
      this.#running = false;
      this.#queuedRechecks.delete(next.key);
      this.#scheduleRechecks();
      this.#drain();
    });
  }

  async #run(item: QueuedContactCheck): Promise<void> {
    try {
      const outcome = await this.#options.check(item.userId, item.identity);
      const now = this.#options.now();
      const transition = nextContactRecheck(item.recheck?.schedule, outcome, now);
      if (item.recheck === undefined && transition.recheck === undefined) {
        if (transition.event !== undefined) this.#options.report(item.userId, transition.event, now);
        return;
      }
      const write = await this.#write(item, transition.recheck);
      if (write.kind === 'superseded') {
        this.#adopt(item.key, write.stored);
        return;
      }
      if (transition.recheck === undefined) {
        this.#rechecks.delete(item.key);
      } else {
        this.#rechecks.set(item.key, {
          userId: item.userId,
          identity: item.identity,
          schedule: transition.recheck,
          persisted: write.persisted,
        });
      }
      if (transition.event !== undefined) this.#options.report(item.userId, transition.event, now);
    } catch (error) {
      this.#options.onError(error);
    }
  }

  #adopt(key: string, stored: ContactRecheckRecord | undefined): void {
    if (stored === undefined) {
      this.#rechecks.delete(key);
      return;
    }
    this.#rechecks.set(key, {
      userId: stored.userId,
      identity: stored.identity,
      schedule: scheduleOf(stored),
      persisted: true,
    });
  }

  /**
   * Writes the next recheck of `item`, or removes its recheck when `next` is
   * `undefined`. Gives `superseded` with the stored recheck when the store
   * has another recheck than the one that `item` checked. When the store
   * fails or is full, the result is `applied` without persistence.
   */
  async #write(
    item: QueuedContactCheck,
    next: ContactRecheckSchedule | undefined
  ): Promise<RecheckWrite> {
    const { store, keys } = this.#options;
    const checked = item.recheck;
    for (let attempt = 0; attempt < RECHECK_WRITE_ATTEMPTS; attempt += 1) {
      let raw: string | null;
      let list: readonly ContactRecheckRecord[];
      try {
        const stored = await readContactRechecks(store, keys);
        raw = stored.raw;
        list = stored.value ?? [];
      } catch (error) {
        this.#options.onError(error);
        return { kind: 'applied', persisted: false };
      }
      const current = list.find((record) => pairKey(record.userId, record.identity) === item.key);
      if (
        (checked === undefined && current !== undefined) ||
        (checked?.persisted === true &&
          (current === undefined || !sameSchedule(scheduleOf(current), checked.schedule))) ||
        (checked?.persisted === false &&
          current !== undefined &&
          !sameSchedule(scheduleOf(current), checked.schedule))
      ) {
        return { kind: 'superseded', stored: current };
      }
      const others = list.filter((record) => record !== current);
      const fits = next !== undefined && others.length < MAXIMUM_CONTACT_RECHECKS;
      if (current === undefined && !fits) return { kind: 'applied', persisted: false };
      const updated =
        fits && next !== undefined
          ? [...others, { userId: item.userId, identity: item.identity, ...next }]
          : others;
      try {
        if (await writeContactRechecks(store, keys, raw, updated)) {
          return { kind: 'applied', persisted: fits };
        }
      } catch (error) {
        this.#options.onError(error);
        return { kind: 'applied', persisted: false };
      }
    }
    return { kind: 'applied', persisted: false };
  }
}
