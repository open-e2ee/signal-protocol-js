/**
 * The in-process locks that order writes of one remote device's records.
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
 * The locks order one JavaScript process only. They do not order two browser
 * tabs, two workers, or two processes that share one store.
 */

import AsyncLock from 'async-lock';

import { ProtocolAddress } from '../../types/address';
import { createKeyedLocks, withKeyedLock } from '../../utils/keyed-lock';

export {};

const sessionLocks = new WeakMap<object, AsyncLock>();
const userRecordLocks = createKeyedLocks();
const deviceListSyncLocks = new WeakMap<object, AsyncLock>();

function asyncLockFor(locks: WeakMap<object, AsyncLock>, store: object): AsyncLock {
  let lock = locks.get(store);
  if (!lock) {
    lock = new AsyncLock({
      timeout: 5000, // 5 second timeout prevents deadlocks
      maxPending: 1000, // Max 1000 queued operations per key
    });
    locks.set(store, lock);
  }
  return lock;
}

/** The session lock of `store`. Every caller with the same store gets one lock. */
export function sessionLockFor(store: object): AsyncLock {
  return asyncLockFor(sessionLocks, store);
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
  return asyncLockFor(deviceListSyncLocks, store).acquire(`device-list:${userId}`, operation);
}
