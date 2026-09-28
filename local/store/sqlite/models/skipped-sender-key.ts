/**
 * Skipped sender message keys, kept for out-of-order group messages.
 *
 * These are the message keys themselves, so they are device-local only.
 */

import type { SqliteExecutor } from '../driver';
import { placeholders } from '../schema';

export type SkippedSenderMessageKey = { iv: string; cipherKey: string };

const SENDER_WHERE = 'group_id = ? AND sender_id = ? AND sender_device_id = ?';

export async function storeSkippedSenderKey(
  db: SqliteExecutor,
  groupId: string,
  senderId: string,
  senderDeviceId: number,
  chainIndex: number,
  messageKey: SkippedSenderMessageKey
): Promise<void> {
  await db.run(
    `INSERT INTO skipped_sender_keys
       (group_id, sender_id, sender_device_id, chain_index, cipher_key, iv, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT (group_id, sender_id, sender_device_id, chain_index) DO UPDATE SET
       cipher_key = excluded.cipher_key,
       iv = excluded.iv`,
    [
      groupId,
      senderId,
      senderDeviceId,
      chainIndex,
      messageKey.cipherKey,
      messageKey.iv,
      Date.now(),
    ]
  );
}

export async function getSkippedSenderKey(
  db: SqliteExecutor,
  groupId: string,
  senderId: string,
  senderDeviceId: number,
  chainIndex: number
): Promise<SkippedSenderMessageKey | null> {
  const row = await db.first<{ iv: string; cipherKey: string }>(
    `SELECT iv, cipher_key AS cipherKey FROM skipped_sender_keys
     WHERE ${SENDER_WHERE} AND chain_index = ? LIMIT 1`,
    [groupId, senderId, senderDeviceId, chainIndex]
  );
  return row ? { iv: row.iv, cipherKey: row.cipherKey } : null;
}

export async function deleteSkippedSenderKey(
  db: SqliteExecutor,
  groupId: string,
  senderId: string,
  senderDeviceId: number,
  chainIndex: number
): Promise<void> {
  await db.run(`DELETE FROM skipped_sender_keys WHERE ${SENDER_WHERE} AND chain_index = ?`, [
    groupId,
    senderId,
    senderDeviceId,
    chainIndex,
  ]);
}

export async function countSkippedSenderKeys(
  db: SqliteExecutor,
  groupId: string,
  senderId: string,
  senderDeviceId: number
): Promise<number> {
  const row = await db.first<{ count: number }>(
    `SELECT COUNT(*) AS count FROM skipped_sender_keys WHERE ${SENDER_WHERE}`,
    [groupId, senderId, senderDeviceId]
  );
  return row?.count ?? 0;
}

/**
 * Evict the oldest skipped keys for a sender, so a peer cannot grow this
 * table without bound by sending messages that skip ever further ahead.
 *
 * Oldest by chain index, not by insertion time. Index order is the order the
 * sender ratcheted. The lowest index is therefore the key least likely to
 * still have a message in flight behind it.
 */
export async function deleteOldestSkippedSenderKeys(
  db: SqliteExecutor,
  groupId: string,
  senderId: string,
  senderDeviceId: number,
  count: number
): Promise<number> {
  if (count <= 0) return 0;

  return await db.transaction(async (tx) => {
    const oldest = await tx.all<{ chainIndex: number }>(
      `SELECT chain_index AS chainIndex FROM skipped_sender_keys
       WHERE ${SENDER_WHERE} ORDER BY chain_index ASC LIMIT ?`,
      [groupId, senderId, senderDeviceId, count]
    );
    if (oldest.length === 0) return 0;

    await tx.run(
      `DELETE FROM skipped_sender_keys
       WHERE ${SENDER_WHERE} AND chain_index IN (${placeholders(oldest.length)})`,
      [groupId, senderId, senderDeviceId, ...oldest.map((row) => row.chainIndex)]
    );
    return oldest.length;
  });
}
