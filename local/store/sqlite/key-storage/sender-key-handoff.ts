/**
 * The sender-key handoff rows of the SQLite store.
 *
 * Each function takes the executor of the caller, so a store write and the
 * row deletes that it causes run in one transaction. SQLite keeps the columns
 * in the clear. SQLCipher encrypts the file when the store is configured with
 * a key.
 */

import type { SenderKeyHandoffDevice, SenderKeyHandoffRecord } from '../../../../types/api';
import type { SqliteExecutor } from '../driver';

type SenderKeyHandoffRow = {
  group_id: string;
  generation: number;
  recipient_user_id: string;
  recipient_device_id: number;
  recipient_registration_id: number;
  sender_key_id: string;
  accepted_at: number;
};

function toRecord(row: SenderKeyHandoffRow): SenderKeyHandoffRecord {
  return {
    groupId: row.group_id,
    senderKeyId: row.sender_key_id,
    generation: Number(row.generation),
    recipientUserId: row.recipient_user_id,
    recipientDeviceId: Number(row.recipient_device_id),
    recipientRegistrationId: Number(row.recipient_registration_id),
    acceptedAt: Number(row.accepted_at),
  };
}

/** Insert the row, or replace the acceptance time of the row with the same key. */
export async function recordSenderKeyHandoff(
  db: SqliteExecutor,
  record: SenderKeyHandoffRecord
): Promise<void> {
  await db.run(
    `INSERT INTO sender_key_handoff (
       group_id, generation, recipient_user_id, recipient_device_id,
       recipient_registration_id, sender_key_id, accepted_at
     ) VALUES (?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT (
       group_id, generation, recipient_user_id, recipient_device_id,
       recipient_registration_id, sender_key_id
     ) DO UPDATE SET accepted_at = excluded.accepted_at`,
    [
      record.groupId,
      record.generation,
      record.recipientUserId,
      record.recipientDeviceId,
      record.recipientRegistrationId,
      record.senderKeyId,
      record.acceptedAt,
    ]
  );
}

/** The rows of one group at one generation. */
export async function listSenderKeyHandoffs(
  db: SqliteExecutor,
  groupId: string,
  generation: number
): Promise<SenderKeyHandoffRecord[]> {
  const rows = await db.all<SenderKeyHandoffRow>(
    `SELECT * FROM sender_key_handoff WHERE group_id = ? AND generation = ?`,
    [groupId, generation]
  );
  return rows.map(toRecord);
}

/** The distinct group IDs that hold rows. */
export async function listSenderKeyHandoffGroupIds(db: SqliteExecutor): Promise<string[]> {
  const rows = await db.all<{ group_id: string }>(
    `SELECT DISTINCT group_id FROM sender_key_handoff`
  );
  return rows.map((row) => row.group_id);
}

/** Delete the rows of one device in every group. Returns the deleted count. */
export function deleteDeviceSenderKeyHandoffs(
  db: SqliteExecutor,
  device: SenderKeyHandoffDevice
): Promise<number> {
  return db.run(
    `DELETE FROM sender_key_handoff WHERE recipient_user_id = ? AND recipient_device_id = ?`,
    [device.userId, device.deviceId]
  );
}

/** Delete the rows of one device in one group. Returns the deleted count. */
export function deleteDeviceSenderKeyHandoffsInGroup(
  db: SqliteExecutor,
  groupId: string,
  device: SenderKeyHandoffDevice
): Promise<number> {
  return db.run(
    `DELETE FROM sender_key_handoff
     WHERE group_id = ? AND recipient_user_id = ? AND recipient_device_id = ?`,
    [groupId, device.userId, device.deviceId]
  );
}

/** Delete the rows of every device of one account in every group. Returns the deleted count. */
export function deleteAccountSenderKeyHandoffs(
  db: SqliteExecutor,
  userId: string
): Promise<number> {
  return db.run(`DELETE FROM sender_key_handoff WHERE recipient_user_id = ?`, [userId]);
}

/** Delete every row of one group. Returns the deleted count. */
export function deleteGroupSenderKeyHandoffs(db: SqliteExecutor, groupId: string): Promise<number> {
  return db.run(`DELETE FROM sender_key_handoff WHERE group_id = ?`, [groupId]);
}

/** Delete the rows of a group whose sender key ID differs. Null deletes all. */
export function retainSenderKeyHandoffs(
  db: SqliteExecutor,
  groupId: string,
  senderKeyId: string | null
): Promise<number> {
  return senderKeyId === null
    ? deleteGroupSenderKeyHandoffs(db, groupId)
    : db.run(`DELETE FROM sender_key_handoff WHERE group_id = ? AND sender_key_id <> ?`, [
        groupId,
        senderKeyId,
      ]);
}
