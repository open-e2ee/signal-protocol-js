/**
 * The keyed index and the record codec of the sender-key handoff rows, for the
 * stores that encrypt their records.
 *
 * A row is found by keyed hashes, not by the group ID, the account ID, or the
 * device. The record itself is encrypted. A read decrypts the record and
 * accepts it only when it hashes to the place where it is stored.
 */

import type { SenderKeyHandoffDevice, SenderKeyHandoffRecord } from '../../types/api';
import { keyedFieldsHash, keyedGroupHash, keyedIndexSubkey } from './keyed-index';

/** The keyed hashes of one row. */
export interface SenderKeyHandoffHashes {
  groupHash: string;
  /** The recipient account. */
  accountHash: string;
  /** The recipient device. */
  recipientHash: string;
  /** The recipient device, its registration ID, and the sender key ID. */
  entryHash: string;
}

/** The keyed hashes of the handoff rows under one store key. */
export class SenderKeyHandoffIndex {
  private constructor(private readonly subkey: Uint8Array) {}

  /** Derive the index of one store key. Derive it again after each key replacement. */
  static async derive(storeKey: Uint8Array): Promise<SenderKeyHandoffIndex> {
    return new SenderKeyHandoffIndex(await keyedIndexSubkey(storeKey));
  }

  group(groupId: string): string {
    return keyedGroupHash(this.subkey, groupId);
  }

  account(userId: string): string {
    return keyedFieldsHash(this.subkey, 'sender-key-handoff account', [userId]);
  }

  recipient(device: SenderKeyHandoffDevice): string {
    return keyedFieldsHash(this.subkey, 'sender-key-handoff recipient', [
      device.userId,
      device.deviceId,
    ]);
  }

  hashes(record: SenderKeyHandoffRecord): SenderKeyHandoffHashes {
    const device = { userId: record.recipientUserId, deviceId: record.recipientDeviceId };
    return {
      groupHash: this.group(record.groupId),
      accountHash: this.account(record.recipientUserId),
      recipientHash: this.recipient(device),
      entryHash: keyedFieldsHash(this.subkey, 'sender-key-handoff entry', [
        record.recipientUserId,
        record.recipientDeviceId,
        record.recipientRegistrationId,
        record.senderKeyId,
      ]),
    };
  }

  /** True when the record hashes to the stored place of its row. */
  matches(
    record: SenderKeyHandoffRecord,
    stored: SenderKeyHandoffHashes & { generation: number }
  ): boolean {
    const hashes = this.hashes(record);
    return (
      record.generation === stored.generation &&
      hashes.groupHash === stored.groupHash &&
      hashes.accountHash === stored.accountHash &&
      hashes.recipientHash === stored.recipientHash &&
      hashes.entryHash === stored.entryHash
    );
  }
}

export function encodeSenderKeyHandoff(record: SenderKeyHandoffRecord): string {
  return JSON.stringify({
    groupId: record.groupId,
    senderKeyId: record.senderKeyId,
    generation: record.generation,
    recipientUserId: record.recipientUserId,
    recipientDeviceId: record.recipientDeviceId,
    recipientRegistrationId: record.recipientRegistrationId,
    acceptedAt: record.acceptedAt,
  });
}

function isInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value);
}

/** The record of one row, or null when the JSON is not a handoff record. */
export function decodeSenderKeyHandoff(json: string): SenderKeyHandoffRecord | null {
  let value: unknown;
  try {
    value = JSON.parse(json);
  } catch {
    return null;
  }
  if (typeof value !== 'object' || value === null) return null;
  const row = value as Record<string, unknown>;
  if (
    typeof row.groupId !== 'string' ||
    typeof row.senderKeyId !== 'string' ||
    !isInteger(row.generation) ||
    typeof row.recipientUserId !== 'string' ||
    !isInteger(row.recipientDeviceId) ||
    !isInteger(row.recipientRegistrationId) ||
    !isInteger(row.acceptedAt)
  ) {
    return null;
  }
  return {
    groupId: row.groupId,
    senderKeyId: row.senderKeyId,
    generation: row.generation,
    recipientUserId: row.recipientUserId,
    recipientDeviceId: row.recipientDeviceId,
    recipientRegistrationId: row.recipientRegistrationId,
    acceptedAt: row.acceptedAt,
  };
}
