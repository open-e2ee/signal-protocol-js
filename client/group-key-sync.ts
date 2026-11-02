/**
 * The own-device group key sync of a client.
 *
 * A device that creates or joins a managed group sends one `GroupKeySync`
 * with the group master key and the revision to each other own device. A
 * device that sees an own device for the first time sends the key of each
 * group to that device only. Each start sends the key of each group to each
 * own device whose pair the key sync ledger does not mark, so the first start
 * after an upgrade sends one `GroupKeySync` for each group and own device,
 * and a start after a complete run sends none. A group sends no key while
 * its record is unverified, while it has no stored state, or while its
 * stored state does not list this account as a member.
 *
 * The ledger mark is written after the send returns, for the devices whose
 * copy the relay accepted. A send that fails marks the devices whose copy
 * the relay accepted before the failure. A relay refusal, a failed send, or
 * a fault before the mark leaves the pair unmarked, and the next start sends
 * again. A device that receives the key of a group from an own device marks
 * that device, so it does not send the key back. The mark names the
 * registration of the sender's session when this device consumes the sync.
 * A sender device reinstalled with the same device ID between the arrival
 * and the consumption of its `GroupKeySync` is marked with the new
 * registration, and that install gets the key from another own device or
 * from group traffic. A failed mark is logged, and the receive completes.
 * The jobs run one at a time, so a first-sight job reads the marks of a
 * trigger job that came before it.
 * A failure in one group of a pass is logged, and the pass continues with
 * the next group.
 */

import type { Logger } from '../logger';
import { isMember } from '../internal/groups/access-control';
import type { GroupStateStore } from '../internal/groups/manager';
import {
  deleteGroupKeySync,
  isGroupKeySynced,
  markGroupKeySynced,
  syncDevicesAcceptedBefore,
  type GroupKeySyncDevice,
} from '../internal/groups/key-sync-ledger';
import type { GroupReceiveRecord } from '../internal/groups/receive-record';
import type { DecryptedGroup } from '../internal/groups/types';
import type { SignalProtocolLocalStore } from '../types/api';
import type { GroupKeySyncInput } from './content-adapter';
import { RelayWorkStopped } from './relay-work';

/** An own device that this device holds a record of. */
export interface KnownOwnDevice {
  readonly deviceId: number;
  /** The registration of the current session, when one is known. */
  readonly registrationId?: number;
}

/** What the group key sync needs from its client. */
export interface GroupKeySyncOptions {
  /** The local store that holds the key sync ledger. */
  readonly storage: SignalProtocolLocalStore;
  readonly store: GroupStateStore;
  /**
   * The ACI of this account. With it, a group whose stored state does not
   * list the account as a member sends no key.
   */
  readonly localAci?: Uint8Array;
  /** The other own devices that this device holds a record of. */
  readonly ownDevices: () => Promise<readonly KnownOwnDevice[]>;
  /**
   * Send one `GroupKeySync` to the given own devices, or to each own device.
   * It resolves to the devices whose copy the relay accepted. A failed send
   * rejects with an error that carries the devices whose copy the relay
   * accepted before the failure. No post or wait starts after the stop
   * signal aborts.
   */
  readonly send: (
    input: GroupKeySyncInput,
    deviceIds: readonly number[] | undefined,
    stopSignal: AbortSignal
  ) => Promise<GroupKeySyncDevice[]>;
  /** Run one job as tracked client work, with the stop signal of the work. */
  readonly runInBackground: (job: (stopSignal: AbortSignal) => Promise<void>) => Promise<void>;
  readonly logger: Required<Logger>;
}

/** @internal */
export class GroupKeySync {
  private queue: Promise<void> = Promise.resolve();
  private stopped = false;

  constructor(private readonly options: GroupKeySyncOptions) {}

  /** Send the key of each group to each own device of an unmarked pair. */
  start(): Promise<void> {
    this.stopped = false;
    return this.enqueue('start', (stopSignal) => this.sendUnmarked('start', stopSignal));
  }

  /**
   * Stop the jobs. A running pass ends after the group that it sends now,
   * and a job that starts before the next start sends nothing. Each
   * unmarked pair stays unmarked, so the next start sends it.
   */
  stop(): void {
    this.stopped = true;
  }

  /**
   * Send the key of a group that this device created or joined to each
   * other own device.
   */
  groupJoined(groupId: string): Promise<void> {
    return this.enqueue('group', async (stopSignal) => {
      if (this.halted(stopSignal)) return;
      const input = await this.inputOf(groupId);
      if (input) await this.sendAndMark('group', groupId, input, undefined, stopSignal);
    });
  }

  /** Send the key of each group to own devices that this device sees first. */
  devicesFirstSeen(deviceIds: readonly number[]): Promise<void> {
    return this.enqueue('first-seen', (stopSignal) =>
      this.sendUnmarked('first-seen', stopSignal, deviceIds)
    );
  }

  /**
   * Mark the own device that sent this device the key of a group, so this
   * device does not send the key back. A device whose session names no
   * registration is not marked. A failed mark is logged and does not
   * reject, so the receive of the sync completes.
   */
  async receivedFrom(groupId: string, device: KnownOwnDevice): Promise<void> {
    if (device.registrationId === undefined) return;
    try {
      await this.mark(groupId, [
        { deviceId: device.deviceId, registrationId: device.registrationId },
      ]);
    } catch (error) {
      this.warnFailed('received', error, groupId);
    }
  }

  /** Resolve when each job queued before the call has ended. */
  idle(): Promise<void> {
    return this.queue;
  }

  private halted(stopSignal: AbortSignal): boolean {
    return this.stopped || stopSignal.aborted;
  }

  private enqueue(
    trigger: string,
    job: (stopSignal: AbortSignal) => Promise<void>
  ): Promise<void> {
    const run = this.queue.then(() =>
      this.options.runInBackground(job).catch((error: unknown) => {
        this.warnFailed(trigger, error);
      })
    );
    this.queue = run;
    return run;
  }

  private warnFailed(trigger: string, error: unknown, groupId?: string): void {
    this.options.logger.warn('The group key sync failed', {
      category: 'E2EE',
      data: {
        behavior: 'GROUP_KEY_SYNC_FAILED',
        trigger,
        ...(groupId !== undefined && { groupId }),
        error: error instanceof Error ? error.message : String(error),
      },
    });
  }

  /**
   * Send the key of each group to each own device whose pair is unmarked.
   * With `only`, the pass sends only to those devices. Without a record of
   * an own device, the pass sends the first group to each own device, so
   * the send reads the own device list. The pass ends between groups after
   * a stop. A failure in one group is logged, and the pass continues with
   * the next group.
   */
  private async sendUnmarked(
    trigger: string,
    stopSignal: AbortSignal,
    only?: readonly number[]
  ): Promise<void> {
    const { store, storage } = this.options;
    let devices = await this.knownDevices(only);
    let listRead = only !== undefined;
    for (const groupId of await store.listGroupReceiveRecords()) {
      if (this.halted(stopSignal)) return;
      try {
        const input = await this.inputOf(groupId);
        if (!input) continue;
        if (devices.length === 0) {
          if (listRead) return;
          listRead = true;
          try {
            await this.sendAndMark(trigger, groupId, input, undefined, stopSignal);
          } finally {
            devices = await this.knownDevices(only);
          }
          continue;
        }
        const unmarked: number[] = [];
        for (const device of devices) {
          if (
            device.registrationId === undefined ||
            !(await isGroupKeySynced(storage, groupId, {
              deviceId: device.deviceId,
              registrationId: device.registrationId,
            }))
          ) {
            unmarked.push(device.deviceId);
          }
        }
        if (unmarked.length > 0) {
          await this.sendAndMark(trigger, groupId, input, unmarked, stopSignal);
        }
      } catch (error) {
        if (error instanceof RelayWorkStopped || this.halted(stopSignal)) throw error;
        this.warnFailed(trigger, error, groupId);
      }
    }
  }

  private async knownDevices(only?: readonly number[]): Promise<readonly KnownOwnDevice[]> {
    const devices = await this.options.ownDevices();
    return only === undefined
      ? devices
      : devices.filter((device) => only.includes(device.deviceId));
  }

  /**
   * The key and the revision of a group, or null when the group sends no
   * key: with no master key, with an unverified receive record, with no
   * stored state, or with stored state that does not list this account as a
   * member. A join that waits for approval or fails stores the master key
   * and no state, so no pass sends its key until its state arrives. The
   * next start, join or first sight of an own device after that sends it.
   */
  private async inputOf(groupId: string): Promise<GroupKeySyncInput | null> {
    const { store, localAci } = this.options;
    const masterKey = await store.getMasterKey(groupId);
    if (!masterKey) return null;
    if ((await store.getGroupReceiveRecord(groupId))?.unverified) return null;
    const state = await store.getGroupState(groupId);
    if (!state || (localAci && !isMember(state, localAci))) return null;
    return { masterKey, revision: state.revision };
  }

  /**
   * Send, then mark the devices whose copy the relay accepted. A send that
   * fails marks the devices whose copy the relay accepted before the
   * failure, then rethrows the send error. A failure of that mark is logged
   * with the trigger and the group, and the send error still propagates.
   */
  private async sendAndMark(
    trigger: string,
    groupId: string,
    input: GroupKeySyncInput,
    deviceIds: readonly number[] | undefined,
    stopSignal: AbortSignal
  ): Promise<void> {
    let accepted: readonly GroupKeySyncDevice[];
    try {
      accepted = await this.options.send(input, deviceIds, stopSignal);
    } catch (error) {
      try {
        await this.mark(groupId, syncDevicesAcceptedBefore(error));
      } catch (markError) {
        this.warnFailed(trigger, markError, groupId);
      }
      throw error;
    }
    await this.mark(groupId, accepted);
  }

  /**
   * Mark the devices for the group. A deletion of the group's record that
   * ran before the mark deleted the ledger value already, so the mark of a
   * group with no record is deleted again.
   */
  private async mark(groupId: string, devices: readonly GroupKeySyncDevice[]): Promise<void> {
    if (devices.length === 0) return;
    const { storage, store } = this.options;
    await markGroupKeySynced(storage, groupId, devices);
    if ((await store.getGroupReceiveRecord(groupId)) === null) {
      await deleteGroupKeySync(storage, groupId);
    }
  }
}

/**
 * A group store that deletes the key sync ledger value of a group when an
 * update deletes the group's record.
 *
 * @internal
 */
export function deleteGroupKeySyncWithRecord(
  store: GroupStateStore,
  storage: SignalProtocolLocalStore
): GroupStateStore {
  return new GroupKeySyncLedgerStore(store, storage);
}

class GroupKeySyncLedgerStore implements GroupStateStore {
  constructor(
    private readonly store: GroupStateStore,
    private readonly storage: SignalProtocolLocalStore
  ) {}

  storeMasterKey(groupId: string, masterKey: Uint8Array): Promise<void> {
    return this.store.storeMasterKey(groupId, masterKey);
  }

  getMasterKey(groupId: string): Promise<Uint8Array | null> {
    return this.store.getMasterKey(groupId);
  }

  deleteMasterKey(groupId: string): Promise<void> {
    return this.store.deleteMasterKey(groupId);
  }

  storeGroupState(groupId: string, state: DecryptedGroup): Promise<void> {
    return this.store.storeGroupState(groupId, state);
  }

  storeGroupStateWithSenderKeyRotationBarrier(
    groupId: string,
    state: DecryptedGroup
  ): Promise<void> {
    return this.store.storeGroupStateWithSenderKeyRotationBarrier(groupId, state);
  }

  getGroupState(groupId: string): Promise<DecryptedGroup | null> {
    return this.store.getGroupState(groupId);
  }

  getSenderKeyRotationBarrier(groupId: string): Promise<number | null> {
    return this.store.getSenderKeyRotationBarrier(groupId);
  }

  clearSenderKeyRotationBarrier(groupId: string, expectedRevision: number): Promise<void> {
    return this.store.clearSenderKeyRotationBarrier(groupId, expectedRevision);
  }

  deleteGroupState(groupId: string): Promise<void> {
    return this.store.deleteGroupState(groupId);
  }

  getGroupReceiveRecord(groupId: string): Promise<GroupReceiveRecord | null> {
    return this.store.getGroupReceiveRecord(groupId);
  }

  /** A null result deleted the group's record, so the ledger value goes too. */
  async updateGroupReceiveRecord(
    groupId: string,
    apply: (current: GroupReceiveRecord | null) => GroupReceiveRecord | null
  ): Promise<GroupReceiveRecord | null> {
    const next = await this.store.updateGroupReceiveRecord(groupId, apply);
    if (next === null) await deleteGroupKeySync(this.storage, groupId);
    return next;
  }

  listGroupReceiveRecords(): Promise<string[]> {
    return this.store.listGroupReceiveRecords();
  }
}
