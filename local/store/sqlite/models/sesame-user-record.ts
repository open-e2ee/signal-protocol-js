/**
 * SESAME User Record Model
 *
 * A row holds a user's devices, each with its identity pin and lifecycle
 * fields, and no session. A device's session lives only in `sessions`, the
 * record the protocol layer reads and writes, and the store joins the two on
 * read. So a write of a user record that was read earlier never replaces a
 * newer session. The row uses the key-value store's record encoding.
 */

import type { SqliteExecutor } from '../driver';
import type { DeviceID, DeviceRecord, UserRecord } from '../../../../types';
import { ProtocolAddress } from '../../../../types/address';
import { decodeUserRecord, encodeUserRecord } from '../../key-value/device-record';
import { createSessionFromRecord, deleteAllSessions, deleteSessionById } from './session';

/** The stored user record, each device with a null session. */
export async function getSesameUserRecord(
  db: SqliteExecutor,
  userId: string
): Promise<UserRecord | null> {
  const row = await db.first<{ recordJson: string }>(
    'SELECT record_json AS recordJson FROM sesame_user_records WHERE user_id = ?',
    [userId]
  );
  return row ? decodeUserRecord(JSON.parse(row.recordJson)) : null;
}

/** Store the user record without the session of any device. */
export async function saveSesameUserRecord(
  db: SqliteExecutor,
  userId: string,
  record: UserRecord
): Promise<void> {
  await db.run(
    'INSERT OR REPLACE INTO sesame_user_records (user_id, record_json, updated_at) VALUES (?, ?, ?)',
    [userId, JSON.stringify(encodeUserRecord(record)), Date.now()]
  );
}

export async function getSesameUserIds(db: SqliteExecutor): Promise<string[]> {
  const rows = await db.all<{ userId: string }>(
    'SELECT user_id AS userId FROM sesame_user_records ORDER BY user_id'
  );
  return rows.map((row) => row.userId);
}

/**
 * Store a device in its user record, and its session when it has one, in one
 * transaction.
 */
export async function saveSesameDevice(
  db: SqliteExecutor,
  userId: string,
  deviceId: DeviceID,
  device: DeviceRecord
): Promise<void> {
  // Check the session before the transaction starts, so a bad record writes nothing.
  const session = device.session
    ? createSessionFromRecord(ProtocolAddress.toString({ userId, deviceId }), device.session)
    : null;
  await db.transaction(async (tx) => {
    const now = Date.now();
    const record = (await getSesameUserRecord(tx, userId)) ?? {
      userId,
      devices: new Map(),
      createdAt: now,
      updatedAt: now,
    };
    record.devices.set(deviceId, device);
    record.updatedAt = now;
    await saveSesameUserRecord(tx, userId, record);
    await session?.save(tx);
  });
}

/**
 * Delete a device's session, and the device from its user record, in one
 * transaction. A user record with no device left is deleted.
 */
export async function deleteSesameDevice(
  db: SqliteExecutor,
  userId: string,
  deviceId: DeviceID
): Promise<void> {
  await db.transaction(async (tx) => {
    await deleteSessionById(tx, ProtocolAddress.toString({ userId, deviceId }));
    const record = await getSesameUserRecord(tx, userId);
    if (!record) return;
    record.devices.delete(deviceId);
    if (record.devices.size === 0) {
      await tx.run('DELETE FROM sesame_user_records WHERE user_id = ?', [userId]);
      return;
    }
    record.updatedAt = Date.now();
    await saveSesameUserRecord(tx, userId, record);
  });
}

/**
 * Delete every session and every user record in one transaction. A device
 * record whose session is gone is not a device the store can reach.
 */
export async function clearSesameState(db: SqliteExecutor): Promise<void> {
  await db.transaction(async (tx) => {
    await deleteAllSessions(tx);
    await tx.run('DELETE FROM sesame_user_records');
  });
}
