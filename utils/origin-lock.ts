/**
 * A lock shared by every context of one origin: the browser tabs, the
 * workers, and the threads of one process. It uses the Web Locks API
 * (`navigator.locks`).
 *
 * A store that sets `storeIdentity` gets origin locks wherever
 * `navigator.locks.request` exists, Node included. Where the API does not
 * exist, or the store has no identity, the caller uses its in-process lock.
 *
 * Requests for one lock name are granted one at a time in request order. The
 * lock is not reentrant: an operation that requests a name that it holds
 * waits for itself. The API sets no bound on the number of waiting requests.
 */

export {};

/** The error message of a wait for an origin lock that is longer than its timeout. */
export const ORIGIN_LOCK_TIMEOUT_MESSAGE = 'The origin lock timed out in queue';

/**
 * The store identity of `store` for origin lock names, or null when the
 * caller must use its in-process lock: `navigator.locks.request` does not
 * exist, or the store has no `storeIdentity` string.
 */
export function originLockScope(store: object): string | null {
  if (typeof navigator === 'undefined') return null;
  const locks: unknown = Reflect.get(navigator, 'locks');
  if (typeof locks !== 'object' || locks === null) return null;
  if (typeof Reflect.get(locks, 'request') !== 'function') return null;
  const identity: unknown = Reflect.get(store, 'storeIdentity');
  return typeof identity === 'string' && identity.length > 0 ? identity : null;
}

/** The options of one origin lock request. */
export interface OriginLockOptions {
  /** Reject when the wait for the lock is longer than this. A held lock has no time limit. */
  timeoutMs?: number;
  /**
   * End the wait for the lock when this signal aborts. A held lock is not
   * released. When the signal aborted before the request, a free lock is
   * still taken, and a held lock rejects at once.
   */
  signal?: AbortSignal;
  /** The error for a wait that `signal` ended. */
  stopped?: () => Error;
}

/**
 * Run `operation` while this context holds the exclusive origin lock `name`.
 * Call it only when {@link originLockScope} gives an identity.
 *
 * @throws Error with {@link ORIGIN_LOCK_TIMEOUT_MESSAGE} when the wait is
 *   longer than `timeoutMs`, and the error of `stopped` when `signal` ends the
 *   wait. The operation does not run in either case.
 */
export function withOriginLock<T>(
  name: string,
  operation: () => Promise<T>,
  options: OriginLockOptions = {}
): Promise<T> {
  const { timeoutMs, signal } = options;
  const stopped = options.stopped ?? (() => new Error('The wait for the origin lock was stopped'));
  if (signal?.aborted) {
    return navigator.locks.request(name, { ifAvailable: true }, async (lock) => {
      if (lock === null) throw stopped();
      return operation();
    });
  }
  const wait = new AbortController();
  let reason: Error | undefined;
  let granted = false;
  const end = (error: Error) => {
    if (granted || reason) return;
    reason = error;
    wait.abort(error);
  };
  const onStop = () => end(stopped());
  signal?.addEventListener('abort', onStop);
  const timer =
    timeoutMs === undefined
      ? undefined
      : setTimeout(() => end(new Error(ORIGIN_LOCK_TIMEOUT_MESSAGE)), timeoutMs);
  const endWait = () => {
    if (timer !== undefined) clearTimeout(timer);
    signal?.removeEventListener('abort', onStop);
  };
  return navigator.locks
    .request(name, { signal: wait.signal }, async () => {
      granted = true;
      endWait();
      return operation();
    })
    .catch((error: unknown) => {
      endWait();
      throw !granted && reason ? reason : error;
    });
}
