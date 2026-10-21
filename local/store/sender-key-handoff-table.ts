/**
 * Sender-key handoff rows held in process memory.
 *
 * The in-memory store keeps its ledger here. Each method is synchronous, so a
 * store can delete rows in the same synchronous section as the write that
 * invalidates them. A read returns copies, and a write stores a copy.
 */

import type { SenderKeyHandoffDevice, SenderKeyHandoffRecord } from '../../types/api';

/** JSON quotes each name, so a name that contains a separator cannot collide. */
function rowKey(record: SenderKeyHandoffRecord): string {
  return JSON.stringify([
    record.senderKeyId,
    record.generation,
    record.recipientUserId,
    record.recipientDeviceId,
    record.recipientRegistrationId,
  ]);
}

function copy(record: SenderKeyHandoffRecord): SenderKeyHandoffRecord {
  return {
    groupId: record.groupId,
    senderKeyId: record.senderKeyId,
    generation: record.generation,
    recipientUserId: record.recipientUserId,
    recipientDeviceId: record.recipientDeviceId,
    recipientRegistrationId: record.recipientRegistrationId,
    acceptedAt: record.acceptedAt,
  };
}

function isDevice(record: SenderKeyHandoffRecord, device: SenderKeyHandoffDevice): boolean {
  return record.recipientUserId === device.userId && record.recipientDeviceId === device.deviceId;
}

export class SenderKeyHandoffTable {
  /** Group ID to rows keyed by sender key ID, generation, user, device, and registration ID. */
  private readonly groups = new Map<string, Map<string, SenderKeyHandoffRecord>>();

  record(record: SenderKeyHandoffRecord): void {
    let rows = this.groups.get(record.groupId);
    if (!rows) {
      rows = new Map();
      this.groups.set(record.groupId, rows);
    }
    rows.set(rowKey(record), copy(record));
  }

  list(groupId: string, generation: number): SenderKeyHandoffRecord[] {
    return Array.from(this.groups.get(groupId)?.values() ?? [])
      .filter((record) => record.generation === generation)
      .map(copy);
  }

  /** The group IDs that hold at least one row. */
  groupIds(): string[] {
    return Array.from(this.groups.keys());
  }

  /** Delete the rows of one device in one group. True when a row was deleted. */
  deleteDeviceInGroup(groupId: string, device: SenderKeyHandoffDevice): boolean {
    return this.deleteWhere(groupId, (record) => isDevice(record, device)) > 0;
  }

  /** Delete the rows of one device in every group. */
  deleteDevice(device: SenderKeyHandoffDevice): void {
    for (const groupId of this.groupIds()) {
      this.deleteWhere(groupId, (record) => isDevice(record, device));
    }
  }

  /** Delete the rows of every device of one account in every group. True when a row was deleted. */
  deleteAccount(userId: string): boolean {
    let deleted = 0;
    for (const groupId of this.groupIds()) {
      deleted += this.deleteWhere(groupId, (record) => record.recipientUserId === userId);
    }
    return deleted > 0;
  }

  /** Delete every row of one group. */
  deleteGroup(groupId: string): void {
    this.groups.delete(groupId);
  }

  /** Delete the rows of a group whose sender key ID differs. Null deletes all. */
  retain(groupId: string, senderKeyId: string | null): number {
    return this.deleteWhere(
      groupId,
      (record) => senderKeyId === null || record.senderKeyId !== senderKeyId
    );
  }

  clear(): void {
    this.groups.clear();
  }

  private deleteWhere(
    groupId: string,
    predicate: (record: SenderKeyHandoffRecord) => boolean
  ): number {
    const rows = this.groups.get(groupId);
    if (!rows) return 0;
    let deleted = 0;
    for (const [key, record] of rows) {
      if (!predicate(record)) continue;
      rows.delete(key);
      deleted++;
    }
    if (rows.size === 0) this.groups.delete(groupId);
    return deleted;
  }
}
