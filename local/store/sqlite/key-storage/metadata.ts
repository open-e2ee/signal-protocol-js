/**
 * The key-value metadata table, and the received content that it holds under
 * `received-content:` keys. Each function takes the executor, so a
 * transaction can pass its own scope.
 */

import type { ReceivedContent } from '../../../../types';
import type { SqliteExecutor } from '../driver';
import { parseReceivedContent, receivedContentKey } from '../../received-content';

export async function getMetadata(db: SqliteExecutor, key: string): Promise<string | null> {
  const row = await db.first<{ value: string }>('SELECT value FROM metadata WHERE key = ?', [key]);
  return row?.value ?? null;
}

export async function setMetadata(db: SqliteExecutor, key: string, value: string): Promise<void> {
  await db.run('INSERT OR REPLACE INTO metadata (key, value, updated_at) VALUES (?, ?, ?)', [
    key,
    value,
    Date.now(),
  ]);
}

export async function deleteMetadata(db: SqliteExecutor, key: string): Promise<void> {
  await db.run('DELETE FROM metadata WHERE key = ?', [key]);
}

export async function compareAndSetMetadata(
  db: SqliteExecutor,
  key: string,
  expected: string | null,
  value: string | null
): Promise<boolean> {
  if (expected === null && value === null) return (await getMetadata(db, key)) === null;
  const changes =
    expected === null
      ? await db.run('INSERT OR IGNORE INTO metadata (key, value, updated_at) VALUES (?, ?, ?)', [
          key,
          value,
          Date.now(),
        ])
      : value === null
        ? await db.run('DELETE FROM metadata WHERE key = ? AND value = ?', [key, expected])
        : await db.run('UPDATE metadata SET value = ?, updated_at = ? WHERE key = ? AND value = ?', [
            value,
            Date.now(),
            key,
            expected,
          ]);
  return changes === 1;
}

export async function setReceivedContent(
  db: SqliteExecutor,
  content: ReceivedContent
): Promise<void> {
  await setMetadata(db, receivedContentKey(content.id), JSON.stringify(content));
}

export async function getReceivedContent(
  db: SqliteExecutor,
  id: string
): Promise<ReceivedContent | null> {
  const value = await getMetadata(db, receivedContentKey(id));
  return value ? parseReceivedContent(value, id) : null;
}

export async function deleteReceivedContent(db: SqliteExecutor, id: string): Promise<void> {
  await deleteMetadata(db, receivedContentKey(id));
}

export async function deleteExpiredReceivedContent(
  db: SqliteExecutor,
  before: number
): Promise<number> {
  return await db.run(
    "DELETE FROM metadata WHERE key LIKE 'received-content:%' AND CAST(json_extract(value, '$.receivedAt') AS INTEGER) < ?",
    [before]
  );
}
