/**
 * The key transparency runtime of one hosted client. It runs the background
 * contact checks and the weekly self-check while the client lifecycle runs.
 *
 * - With no pinned keys, the runtime does nothing: no Relay read, no record,
 *   and no event.
 * - The checks run one at a time, so the checks of one client never race
 *   for the last verified head. Compare-and-set writes cover other clients
 *   on the same store.
 * - The self-check reads its schedule at start and on each transition to
 *   `connected`. A timer reads it again at the next check time, after at
 *   most 24 h. While the Relay connection is not `connected`, no self-check
 *   runs and no timer waits.
 * - A background check that throws an unexpected error is logged with no
 *   account address and no key, and counts as unavailable.
 * - `checkContact` runs a check that the app requests
 *   (`RequestedContactChecks`). It waits in the same chain as the background
 *   checks. Before start and after stop, it gives `stopped` with no Relay
 *   read. The idle runtime gives `not-pinned`.
 */
import { bytesToUrlSafeBase64, generateRandomBytesSync } from '../../internal/crypto';
import type { IdentityLogTrust } from '../../internal/protocol/key-transparency/search-verification';
import { createCompositeIdentityV1, encodeCompositeIdentityV1 } from '../../keys/identity';
import type { CompositeIdentityV1 } from '../../keys/types';
import type { Logger } from '../../logger';
import type {
  SignalProtocolRelayConnectionState,
  Unsubscribe,
} from '../../remote/signal-relay/types';
import type { SignalProtocolLocalStore } from '../../types';
import { ContactCheckQueue, type KeyTransparencyTimers } from './contact-check';
import {
  RequestedContactChecks,
  unavailableCheck,
  type PinnedIdentityRead,
} from './requested-check';
import type { KeyTransparencyFailureEvent } from './event';
import {
  MAXIMUM_SELF_CHECK_TIMER_MILLISECONDS,
  selfCheckTimerDelay,
} from './schedule';
import { runDueSelfCheck, type SelfCheckRun } from './self-check';
import {
  keyTransparencyRecordKeys,
  SELF_CHECK_LEASE_MILLISECONDS,
  type KeyTransparencyStore,
} from './state';
import {
  checkLoggedIdentity,
  type IdentityLogPost,
  type IdentityLogSearchContext,
  type KeyTransparencyCheckOutcome,
} from './verified-search';

/** The transport functions that the runtime uses. */
export interface KeyTransparencyTransport {
  /** Posts one identity log read, with the publishable key, and returns the body. */
  readonly postIdentityLog: IdentityLogPost;
  /** Gets each contact identity that the transport fetched. */
  observeContactIdentity(
    listener: (userId: string, identity: CompositeIdentityV1) => void
  ): Unsubscribe;
  readonly relayConnectionState: SignalProtocolRelayConnectionState;
  subscribeRelayConnectionState(
    listener: (state: SignalProtocolRelayConnectionState) => void
  ): Unsubscribe;
}

/** What the runtime needs. */
export interface KeyTransparencyRuntimeOptions {
  /** The pinned keys, or `undefined` when the lane has none. */
  readonly trust: IdentityLogTrust | undefined;
  readonly environment: string;
  /** The project scope string of the connection. */
  readonly scope: string;
  /** The account address of the client. */
  readonly ownUserId: string;
  readonly store: KeyTransparencyStore & Pick<SignalProtocolLocalStore, 'getIdentityKey'>;
  readonly transport: KeyTransparencyTransport;
  /** Raises the failure event. */
  readonly report: (event: KeyTransparencyFailureEvent) => Promise<void>;
  readonly logger?: Logger;
  readonly now?: () => number;
  /** Gives a value in [0, 1). */
  readonly random?: () => number;
  readonly timers?: KeyTransparencyTimers;
}

/** The runtime. `start` and `stop` are idempotent. */
export interface KeyTransparencyRuntime {
  start(): void;
  stop(): void;
  /** Checks the pinned identity of a contact on request. It never throws a key transparency error. */
  checkContact(userId: string, pinnedIdentity: PinnedIdentityRead): Promise<KeyTransparencyCheckOutcome>;
}

const IDLE_RUNTIME: KeyTransparencyRuntime = {
  start: () => {},
  stop: () => {},
  checkContact: async () => unavailableCheck('not-pinned'),
};

const DEFAULT_TIMERS: KeyTransparencyTimers = {
  set: (callback, delay) => setTimeout(callback, delay),
  clear: (handle) => clearTimeout(handle as ReturnType<typeof setTimeout>),
};

/** Returns the runtime, or an idle runtime when the lane has no pins. */
export function createKeyTransparencyRuntime(
  options: KeyTransparencyRuntimeOptions
): KeyTransparencyRuntime {
  const { trust } = options;
  if (trust === undefined) return IDLE_RUNTIME;
  return new ActiveKeyTransparencyRuntime(options, trust);
}

class ActiveKeyTransparencyRuntime implements KeyTransparencyRuntime {
  readonly #options: KeyTransparencyRuntimeOptions;
  readonly #search: IdentityLogSearchContext;
  readonly #contacts: ContactCheckQueue;
  readonly #requested: RequestedContactChecks;
  readonly #timers: KeyTransparencyTimers;
  readonly #random: () => number;
  readonly #holder = bytesToUrlSafeBase64(generateRandomBytesSync(16));
  /** The end of the last queued check, so that the checks run one at a time. */
  #tail: Promise<unknown> = Promise.resolve();
  #active = false;
  #selfCheckQueued = false;
  #timer: unknown = undefined;
  #unsubscribes: Unsubscribe[] = [];

  constructor(options: KeyTransparencyRuntimeOptions, trust: IdentityLogTrust) {
    this.#options = options;
    this.#timers = options.timers ?? DEFAULT_TIMERS;
    this.#random = options.random ?? Math.random;
    const now = options.now ?? Date.now;
    this.#search = {
      trust,
      scope: options.scope,
      store: options.store,
      keys: keyTransparencyRecordKeys(options.environment, options.scope),
      post: (path, body) => options.transport.postIdentityLog(path, body),
      now,
    };
    this.#contacts = new ContactCheckQueue({
      check: (userId, identity) =>
        this.#serial(() => checkLoggedIdentity(this.#search, userId, identity)),
      report: (userId, error, detectedAt) =>
        this.#report({ subject: 'contact', userId, error, detectedAt }),
      onError: (error) => this.#logError(error),
      now,
      timers: this.#timers,
      store: options.store,
      keys: this.#search.keys,
    });
    this.#requested = new RequestedContactChecks({
      ownUserId: options.ownUserId,
      store: options.store,
      keys: this.#search.keys,
      now,
      search: (userId, identity) =>
        this.#serial(() =>
          this.#active
            ? checkLoggedIdentity(this.#search, userId, identity)
            : Promise.resolve(unavailableCheck('stopped'))
        ),
    });
  }

  checkContact(userId: string, pinnedIdentity: PinnedIdentityRead): Promise<KeyTransparencyCheckOutcome> {
    if (!this.#active) return Promise.resolve(unavailableCheck('stopped'));
    return this.#requested.check(userId, pinnedIdentity);
  }

  start(): void {
    if (this.#active) return;
    this.#active = true;
    const { transport, ownUserId } = this.#options;
    this.#contacts.start();
    this.#unsubscribes = [
      transport.observeContactIdentity((userId, identity) => {
        if (userId === ownUserId) return;
        let encoded: Uint8Array;
        try {
          encoded = encodeCompositeIdentityV1(identity);
        } catch {
          return;
        }
        this.#contacts.offer(userId, encoded);
      }),
      transport.subscribeRelayConnectionState((state) => {
        if (state.state === 'connected') this.#tick();
      }),
    ];
    this.#tick();
  }

  stop(): void {
    if (!this.#active) return;
    this.#active = false;
    for (const unsubscribe of this.#unsubscribes) unsubscribe();
    this.#unsubscribes = [];
    this.#contacts.stop();
    this.#clearTimer();
  }

  #serial<T>(task: () => Promise<T>): Promise<T> {
    const result = this.#tail.then(task);
    this.#tail = result.catch(() => undefined);
    return result;
  }

  #clearTimer(): void {
    if (this.#timer !== undefined) this.#timers.clear(this.#timer);
    this.#timer = undefined;
  }

  #schedule(delay: number): void {
    this.#clearTimer();
    if (!this.#active) return;
    this.#timer = this.#timers.set(() => {
      this.#timer = undefined;
      this.#tick();
    }, delay);
  }

  /** Reads the schedule and runs a due self-check, once at a time. */
  #tick(): void {
    if (!this.#active || this.#selfCheckQueued) return;
    if (this.#options.transport.relayConnectionState.state !== 'connected') {
      this.#clearTimer();
      return;
    }
    this.#selfCheckQueued = true;
    this.#clearTimer();
    void this.#serial(() => this.#runSelfCheck())
      .then(
        (run) => this.#afterSelfCheck(run),
        (error: unknown) => {
          this.#logError(error);
          this.#schedule(MAXIMUM_SELF_CHECK_TIMER_MILLISECONDS);
        }
      )
      .finally(() => {
        this.#selfCheckQueued = false;
      });
  }

  #runSelfCheck(): Promise<SelfCheckRun> {
    const { store, ownUserId } = this.#options;
    return runDueSelfCheck({
      search: this.#search,
      ownUserId,
      ownIdentity: async () => {
        const pair = await store.getIdentityKey('aci');
        return pair === null ? undefined : encodeCompositeIdentityV1(createCompositeIdentityV1(pair));
      },
      holder: this.#holder,
      random: this.#random,
      report: (error, detectedAt) => this.#report({ subject: 'self', error, detectedAt }),
    });
  }

  #afterSelfCheck(run: SelfCheckRun): void {
    const now = this.#search.now();
    switch (run.kind) {
      case 'not-due':
      case 'checked':
        this.#schedule(selfCheckTimerDelay(run.nextCheckAt, now));
        return;
      case 'busy':
        this.#schedule(selfCheckTimerDelay(run.until, now));
        return;
      case 'not-recorded':
        this.#schedule(SELF_CHECK_LEASE_MILLISECONDS);
        return;
      case 'no-registration':
        this.#schedule(MAXIMUM_SELF_CHECK_TIMER_MILLISECONDS);
        return;
    }
  }

  #report(event: KeyTransparencyFailureEvent): void {
    void Promise.resolve()
      .then(() => this.#options.report(event))
      .catch((error: unknown) => this.#logError(error));
  }

  #logError(error: unknown): void {
    this.#options.logger?.warn?.('A key transparency check did not run', {
      category: 'E2EE',
      data: {
        behavior: 'KEY_TRANSPARENCY_CHECK_ERROR',
        error: error instanceof Error ? error.name : typeof error,
      },
    });
  }
}
