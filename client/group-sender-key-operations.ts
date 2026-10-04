import AsyncLock from 'async-lock';
import type { SignalProtocolLocalStore } from '../types';
import { extractGroupId } from '../internal/groups/group-id';
import { acquireUntilStopped } from './relay-work';

const storageLocks = new WeakMap<SignalProtocolLocalStore, AsyncLock>();

/**
 * Serialize a client's Sender Key operations under the canonical group ID.
 * Clients that share one storage adapter share these process-local locks.
 * Separate adapters or processes require exclusive access from the application.
 */
export class GroupSenderKeyOperations {
  private readonly lock: AsyncLock;

  constructor(
    storage: SignalProtocolLocalStore,
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

  /** The operation must not acquire this group's lock again. */
  run<T>(
    groupId: string,
    operation: (rawGroupId: string) => Promise<T>,
    stopSignal?: AbortSignal
  ): Promise<T> {
    const rawGroupId = extractGroupId(groupId);
    const key = JSON.stringify([this.userId, this.deviceId, rawGroupId]);
    return acquireUntilStopped(this.lock, key, () => operation(rawGroupId), stopSignal);
  }
}
