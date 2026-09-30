/**
 * An in-process lock keyed by an owner object and a string key.
 *
 * Operations with the same owner and key run one at a time in call order.
 * Operations with a different owner or key do not wait for each other. The
 * lock is not reentrant: an operation that takes the same lock again waits
 * for itself and never completes.
 *
 * The lock orders one JavaScript process only. It does not order two browser
 * tabs, two workers, or two processes that share one store.
 */

export {};

export type KeyedLocks = WeakMap<object, Map<string, Promise<void>>>;

export function createKeyedLocks(): KeyedLocks {
  return new WeakMap();
}

export async function withKeyedLock<T>(
  collections: KeyedLocks,
  owner: object,
  key: string,
  operation: () => Promise<T>
): Promise<T> {
  let locks = collections.get(owner);
  if (!locks) {
    locks = new Map();
    collections.set(owner, locks);
  }
  const previous = locks.get(key) ?? Promise.resolve();
  let release!: () => void;
  const current = new Promise<void>((resolve) => {
    release = resolve;
  });
  locks.set(key, current);
  await previous.catch(() => undefined);
  try {
    return await operation();
  } finally {
    release();
    if (locks.get(key) === current) locks.delete(key);
    if (locks.size === 0) collections.delete(owner);
  }
}
