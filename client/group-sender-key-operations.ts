import AsyncLock from 'async-lock';
import type { SignalProtocolLocalStore } from '../types';
import { extractGroupId } from '../internal/groups/group-id';
import { originLockScope, withOriginLock } from '../utils/origin-lock';
import { acquireUntilStopped, RelayWorkStopped } from './relay-work';

const storageLocks = new WeakMap<SignalProtocolLocalStore, AsyncLock>();

/**
 * Serialize a client's Sender Key operations under the canonical group ID.
 *
 * When `navigator.locks.request` exists and the store sets `storeIdentity`,
 * the operation runs under the Web Lock
 * `open-e2ee:group-send:<store identity>:<lock key>`, so the tabs, workers,
 * and clients of one origin that share the store run one operation of a group
 * at a time. Otherwise the clients that share one store object share a
 * process-local lock, and separate store objects or processes need exclusive
 * access from the application.
 */
export class GroupSenderKeyOperations {
  private readonly lock: AsyncLock;

  constructor(
    private readonly storage: SignalProtocolLocalStore,
    private readonly userId: string,
    private readonly deviceId: number
  ) {
    let lock = storageLocks.get(storage);
    if (!lock) {
      lock = new AsyncLock();
      storageLocks.set(storage, lock);
    }
    this.lock = lock;
  }

  /**
   * Run `operation` under the lock of the group. A stop that ends the wait
   * rejects with RelayWorkStopped, and the operation does not run. The
   * operation must not acquire this group's lock again.
   */
  run<T>(
    groupId: string,
    operation: (rawGroupId: string) => Promise<T>,
    stopSignal?: AbortSignal
  ): Promise<T> {
    const rawGroupId = extractGroupId(groupId);
    const key = JSON.stringify([this.userId, this.deviceId, rawGroupId]);
    const task = () => operation(rawGroupId);
    const scope = originLockScope(this.storage);
    if (scope !== null) {
      return withOriginLock(`open-e2ee:group-send:${scope}:${key}`, task, {
        signal: stopSignal,
        stopped: () => new RelayWorkStopped(),
      });
    }
    return acquireUntilStopped(this.lock, key, task, stopSignal);
  }
}
