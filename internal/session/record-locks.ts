/**
 * The locks that order writes of one remote device's records.
 *
 * The session lock orders every write of the session under one protocol
 * address. The user lock orders every read-modify-write of one user's SESAME
 * user record and device records. The device-list sync lock orders the
 * device-list syncs of one user. The store object keys each lock, so every
 * protocol manager, SESAME manager, and store sweep over one store shares
 * them.
 *
 * Take the device-list sync lock first, the session lock second, and the
 * user lock last. Only a device-list sync takes the device-list sync lock. An
 * operation that holds a user lock must not take a session lock. No lock is
 * reentrant: an operation that takes a lock that it holds waits for itself.
 * A session lock or a device-list sync lock that waits longer than its
 * timeout rejects.
 *
 * When `navigator.locks.request` exists and the store sets `storeIdentity`,
 * each lock is the Web Lock `open-e2ee:session:<store identity>:<lock key>`.
 * The tabs, workers, and threads of one origin that share the store then
 * share the lock, and a wait has no bound on the number of waiting requests.
 * Otherwise the locks are in-process locks keyed by the store object: they
 * do not order two browser tabs, two workers, or two processes that share
 * one store, and a session lock refuses a request when 1,000 wait.
 */

import AsyncLock from 'async-lock';

import { ProtocolAddress } from '../../types/address';
import { createKeyedLocks, withKeyedLock } from '../../utils/keyed-lock';
import { originLockScope, withOriginLock } from '../../utils/origin-lock';

export {};

/** The longest wait for a session lock or a device-list sync lock. */
const RECORD_LOCK_TIMEOUT_MS = 5000;

/** A lock keyed by a string. Operations with one key run one at a time. */
export interface RecordLock {
  acquire<T>(key: string, operation: () => Promise<T>): Promise<T>;
}

const sessionLocks = new WeakMap<object, AsyncLock>();
const sessionRecordLocks = new WeakMap<object, RecordLock>();
const userRecordLocks = createKeyedLocks();
const deviceListSyncLocks = new WeakMap<object, AsyncLock>();

function asyncLockFor(locks: WeakMap<object, AsyncLock>, store: object): AsyncLock {
  let lock = locks.get(store);
  if (!lock) {
    lock = new AsyncLock({
      timeout: RECORD_LOCK_TIMEOUT_MS, // prevents deadlocks
      maxPending: 1000, // Max 1000 queued operations per key
    });
    locks.set(store, lock);
  }
  return lock;
}

/** The Web Lock name of `key` in `store`, or null for the in-process lock. */
function originLockName(store: object, key: string): string | null {
  const scope = originLockScope(store);
  return scope === null ? null : `open-e2ee:session:${scope}:${key}`;
}

/**
 * The session lock of `store`. Every caller with the same store gets one
 * lock. Each acquire chooses the Web Lock or the in-process lock again.
 */
export function sessionLockFor(store: object): RecordLock {
  let lock = sessionRecordLocks.get(store);
  if (!lock) {
    lock = {
      acquire: <T>(key: string, operation: () => Promise<T>): Promise<T> => {
        const name = originLockName(store, key);
        if (name === null) return asyncLockFor(sessionLocks, store).acquire(key, operation);
        return withOriginLock(name, operation, { timeoutMs: RECORD_LOCK_TIMEOUT_MS });
      },
    };
    sessionRecordLocks.set(store, lock);
  }
  return lock;
}

/** The session lock key of one protocol address. */
export function sessionLockKey(address: ProtocolAddress): string {
  return `session:${ProtocolAddress.toString(address)}`;
}

/** Run `operation` under the session lock of `address`. */
export function withSessionLock<T>(
  store: object,
  address: ProtocolAddress,
  operation: () => Promise<T>
): Promise<T> {
  return sessionLockFor(store).acquire(sessionLockKey(address), operation);
}

/**
 * Run a read-modify-write of one user's SESAME records under the user lock.
 * The operation must not write a session that it read before the lock.
 */
export function withUserRecordLock<T>(
  store: object,
  userId: string,
  operation: () => Promise<T>
): Promise<T> {
  const name = originLockName(store, `user:${userId}`);
  if (name !== null) return withOriginLock(name, operation);
  return withKeyedLock(userRecordLocks, store, userId, operation);
}

/**
 * Run a read-modify-write of one device record and its session under the
 * session lock of the device and then the user lock of its user.
 */
export function withDeviceRecordLocks<T>(
  store: object,
  userId: string,
  deviceId: number,
  operation: () => Promise<T>
): Promise<T> {
  return withSessionLock(store, { userId, deviceId }, () =>
    withUserRecordLock(store, userId, operation)
  );
}

/**
 * Run one device-list sync of `userId` under the device-list sync lock, so
 * two syncs of one user do not interleave. The operation can take the session
 * lock and the user lock. Syncs of different users run in parallel.
 */
export function withDeviceListSyncLock<T>(
  store: object,
  userId: string,
  operation: () => Promise<T>
): Promise<T> {
  const key = `device-list:${userId}`;
  const name = originLockName(store, key);
  if (name !== null) return withOriginLock(name, operation, { timeoutMs: RECORD_LOCK_TIMEOUT_MS });
  return asyncLockFor(deviceListSyncLocks, store).acquire(key, operation);
}
