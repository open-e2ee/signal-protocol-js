/**
 * The key-value metadata table, and the legacy received content rows that it
 * holds under `received-content:` keys. Each function takes the executor, so a
 * transaction can pass its own scope.
 */

import type { MetadataKeyQuery } from '../../../../types/api';
import type { SqliteExecutor } from '../driver';
import { selectMetadataKeys } from '../../metadata-keys';
import { receivedContentKey } from '../../received-content';
import type { LegacyReceivedContentSource } from '../../receive-work';

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

/**
 * The metadata keys that start with the prefix of `query`, in UTF-16 code
 * unit order. SQLite compares text in UTF-8 byte order, which is not UTF-16
 * order for every key, so the query selects by prefix only and the order and
 * the page come from `selectMetadataKeys`. `length` and `substr` count
 * characters, so the prefix test is exact.
 */
export async function listMetadataKeys(
  db: SqliteExecutor,
  query: MetadataKeyQuery
): Promise<string[]> {
  const rows = await db.all<{ key: string }>(
    'SELECT key FROM metadata WHERE substr(key, 1, length(?)) = ?',
    [query.prefix, query.prefix]
  );
  return selectMetadataKeys(rows.map((row) => row.key), query);
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

/**
 * The legacy received content rows, for the conversion at open. A row
 * holds the JSON of one `ReceivedContent`.
 */
export function legacyReceivedContentSource(db: SqliteExecutor): LegacyReceivedContentSource {
  const prefix = receivedContentKey('');
  return {
    async listIds() {
      const rows = await db.all<{ key: string }>(
        'SELECT key FROM metadata WHERE substr(key, 1, ?) = ? ORDER BY key',
        [prefix.length, prefix]
      );
      return rows.map((row) => row.key.slice(prefix.length));
    },
    read: (id) => getMetadata(db, receivedContentKey(id)),
    delete: (id) => deleteMetadata(db, receivedContentKey(id)),
  };
}
