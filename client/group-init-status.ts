/**
 * The init status of each group on this device, and the store that reports a
 * change of it.
 */

import type { Logger } from '../logger';
import type { GroupStateStore } from '../internal/groups/manager';
import type { DecryptedGroup } from '../internal/groups/types';
import {
  groupReceiveStatus,
  type GroupReceiveRecord,
} from '../internal/groups/receive-record';

/**
 * The init status of a group on this device.
 *
 * - `'ready'`: the device holds the group key and the group state at the
 *   newest revision that it knows.
 * - `'stale'`: the device holds the group key and the group state, but a
 *   sender named a newer revision. The client fetches the newer state.
 * - `'pending'`: the device holds the group key and has no group state yet.
 *   The client fetches the state.
 * - `'no-key'`: the device knows the group but holds no group key. The client
 *   cannot fetch the group until the device gets the key.
 * - `'denied'`: the group server refused the newest revision that the device
 *   knows, for example because this account is not a member. A sender that
 *   names a newer revision makes the client try again.
 */
export type GroupInitStatus = 'ready' | 'stale' | 'pending' | 'no-key' | 'denied';

/**
 * The init status of a group in `store`, or null when the store has no
 * record of the group.
 *
 * @internal
 */
export async function readGroupInitStatus(
  store: GroupStateStore,
  groupId: string
): Promise<GroupInitStatus | null> {
  const [record, state, masterKey] = await Promise.all([
    store.getGroupReceiveRecord(groupId),
    store.getGroupState(groupId),
    store.getMasterKey(groupId),
  ]);
  if (record === null) return null;
  const status = groupReceiveStatus(record, state?.revision ?? null);
  if (status !== 'denied' && masterKey === null) return 'no-key';
  return status;
}

/**
 * A group store that reads the init status of a group after each write to its
 * record, and reports each value that differs from the last value it read.
 *
 * The store reads no status while `isObserved` returns false. Each report
 * runs after the earlier reports, and no write waits for a report. So a
 * report can call a client method that writes the same group.
 *
 * @internal
 */
export function observeGroupInitStatus(
  store: GroupStateStore,
  options: {
    isObserved: () => boolean;
    report: (groupId: string, status: GroupInitStatus) => Promise<void>;
    logger: Required<Logger>;
  }
): GroupStateStore {
  return new GroupInitStatusStore(store, options);
}

class GroupInitStatusStore implements GroupStateStore {
  /** The last status that this store read for each group. */
  private readonly known = new Map<string, GroupInitStatus | null>();
  /** The last status read of each group, so that the reads run in order. */
  private readonly reads = new Map<string, Promise<void>>();
  /** The last report, so that the reports run in order. */
  private reported: Promise<void> = Promise.resolve();

  constructor(
    private readonly store: GroupStateStore,
    private readonly options: Parameters<typeof observeGroupInitStatus>[1]
  ) {}

  storeMasterKey(groupId: string, masterKey: Uint8Array): Promise<void> {
    return this.write(groupId, () => this.store.storeMasterKey(groupId, masterKey));
  }

  getMasterKey(groupId: string): Promise<Uint8Array | null> {
    return this.store.getMasterKey(groupId);
  }

  deleteMasterKey(groupId: string): Promise<void> {
    return this.write(groupId, () => this.store.deleteMasterKey(groupId));
  }

  storeGroupState(groupId: string, state: DecryptedGroup): Promise<void> {
    return this.write(groupId, () => this.store.storeGroupState(groupId, state));
  }

  storeGroupStateWithSenderKeyRotationBarrier(
    groupId: string,
    state: DecryptedGroup
  ): Promise<void> {
    return this.write(groupId, () =>
      this.store.storeGroupStateWithSenderKeyRotationBarrier(groupId, state)
    );
  }

  getGroupState(groupId: string): Promise<DecryptedGroup | null> {
    return this.store.getGroupState(groupId);
  }

  getSenderKeyRotationBarrier(groupId: string): Promise<number | null> {
    return this.store.getSenderKeyRotationBarrier(groupId);
  }

  /** The barrier is not part of the init status. */
  clearSenderKeyRotationBarrier(groupId: string, expectedRevision: number): Promise<void> {
    return this.store.clearSenderKeyRotationBarrier(groupId, expectedRevision);
  }

  deleteGroupState(groupId: string): Promise<void> {
    return this.write(groupId, () => this.store.deleteGroupState(groupId));
  }

  getGroupReceiveRecord(groupId: string): Promise<GroupReceiveRecord | null> {
    return this.store.getGroupReceiveRecord(groupId);
  }

  updateGroupReceiveRecord(
    groupId: string,
    apply: (current: GroupReceiveRecord | null) => GroupReceiveRecord | null
  ): Promise<GroupReceiveRecord | null> {
    return this.write(groupId, () => this.store.updateGroupReceiveRecord(groupId, apply));
  }

  listGroupReceiveRecords(): Promise<string[]> {
    return this.store.listGroupReceiveRecords();
  }

  /**
   * Run one write. The status before the write is known before the write
   * starts, and the status after the write is read before the write returns.
   */
  private async write<T>(groupId: string, run: () => Promise<T>): Promise<T> {
    if (!this.options.isObserved()) {
      // A value from before the hook was removed can be out of date.
      this.known.delete(groupId);
      return run();
    }
    await this.inOrder(groupId, async () => {
      if (this.known.has(groupId)) return;
      this.known.set(groupId, await readGroupInitStatus(this.store, groupId));
    });
    try {
      return await run();
    } finally {
      await this.inOrder(groupId, async () => {
        // A failed read before the write left no value to compare with.
        if (!this.known.has(groupId)) return;
        const previous = this.known.get(groupId);
        const status = await readGroupInitStatus(this.store, groupId);
        this.known.set(groupId, status);
        if (status !== null && status !== previous) this.report(groupId, status);
      });
    }
  }

  /** Run one status read of a group after the earlier reads of that group. */
  private inOrder(groupId: string, step: () => Promise<void>): Promise<void> {
    const run = (this.reads.get(groupId) ?? Promise.resolve())
      .then(step)
      .catch((error: unknown) => {
        // The next write reads the status again before it compares.
        this.known.delete(groupId);
        this.options.logger.warn('The group init status read failed', {
          category: 'E2EE',
          data: {
            behavior: 'GROUP_INIT_STATUS_READ_FAILED',
            error: error instanceof Error ? error.message : String(error),
          },
        });
      });
    this.reads.set(groupId, run);
    void run.then(() => {
      if (this.reads.get(groupId) === run) this.reads.delete(groupId);
    });
    return run;
  }

  /** Queue one report after the earlier reports. No write waits for it. */
  private report(groupId: string, status: GroupInitStatus): void {
    this.reported = this.reported
      .then(() => this.options.report(groupId, status))
      .catch((error: unknown) => {
        this.options.logger.warn('The group init status report failed', {
          category: 'E2EE',
          data: {
            behavior: 'GROUP_INIT_STATUS_REPORT_FAILED',
            error: error instanceof Error ? error.message : String(error),
          },
        });
      });
  }
}
