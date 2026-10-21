/**
 * The receive records in the `receive_work` table. The `record` column holds
 * the record JSON. The index columns hold the arrival order, the stage, the
 * due time, the size, and the group of a record that waits for its group, so
 * a listing filters and a usage count sums without a parse of each record.
 * Each function takes the executor, so a transaction can pass its own scope.
 */

import type {
  ReceiveWorkMetadataWrite,
  ReceiveWorkQuery,
  ReceiveWorkRecord,
  ReceiveWorkUsage,
} from '../../../../types/api';
import type { SqliteExecutor, SqliteValue } from '../driver';
import { assertReceiveWork, parseReceiveWork, receiveWorkLimit } from '../../receive-work';
import { deleteMetadata, setMetadata } from './metadata';

/** The group of a record that waits for its group, else null. */
function blockedGroup(record: ReceiveWorkRecord): string | null {
  return record.blockedOn === 'group-update' ? (record.groupId ?? null) : null;
}

function rowValues(record: ReceiveWorkRecord): SqliteValue[] {
  return [
    record.revision,
    JSON.stringify(record),
    record.arrivalSeq,
    record.stage,
    record.dueAt,
    record.sizeBytes,
    blockedGroup(record),
  ];
}

type UsageRow = { items: number; bytes: number };

const ROW_COLUMNS = 'revision, record, arrival_seq, stage, due_at, size_bytes, blocked_group';

export async function getReceiveWork(
  db: SqliteExecutor,
  workId: string
): Promise<ReceiveWorkRecord | null> {
  const row = await db.first<{ record: string }>(
    'SELECT record FROM receive_work WHERE work_id = ?',
    [workId]
  );
  return row ? parseReceiveWork(row.record, workId) : null;
}

/** Write one record and replace any stored record. A commit calls it in its transaction. */
export async function writeReceiveWork(db: SqliteExecutor, record: ReceiveWorkRecord): Promise<void> {
  assertReceiveWork(record);
  await db.run(
    `INSERT OR REPLACE INTO receive_work (work_id, ${ROW_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [record.workId, ...rowValues(record)]
  );
}

/**
 * Insert one record when `expectedRevision` is null, else replace the record
 * with that revision. One statement does the check and the write.
 */
export async function putReceiveWork(
  db: SqliteExecutor,
  record: ReceiveWorkRecord,
  expectedRevision: number | null
): Promise<boolean> {
  assertReceiveWork(record);
  const changes =
    expectedRevision === null
      ? await db.run(
          `INSERT OR IGNORE INTO receive_work (work_id, ${ROW_COLUMNS})
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
          [record.workId, ...rowValues(record)]
        )
      : await db.run(
          `UPDATE receive_work SET revision = ?, record = ?, arrival_seq = ?, stage = ?,
             due_at = ?, size_bytes = ?, blocked_group = ?
           WHERE work_id = ? AND revision = ?`,
          [...rowValues(record), record.workId, expectedRevision]
        );
  return changes === 1;
}

export async function listReceiveWork(
  db: SqliteExecutor,
  query: ReceiveWorkQuery = {}
): Promise<ReceiveWorkRecord[]> {
  const limit = receiveWorkLimit(query);
  const where: string[] = [];
  const params: SqliteValue[] = [];
  if (query.stage !== undefined) {
    where.push('stage = ?');
    params.push(query.stage);
  }
  if (query.dueBy !== undefined) {
    where.push('due_at <= ?');
    params.push(query.dueBy);
  }
  if (query.after !== undefined) {
    where.push('(arrival_seq > ? OR (arrival_seq = ? AND work_id > ?))');
    params.push(query.after.arrivalSeq, query.after.arrivalSeq, query.after.workId);
  }
  const rows = await db.all<{ workId: string; record: string }>(
    `SELECT work_id AS workId, record FROM receive_work
     ${where.length > 0 ? `WHERE ${where.join(' AND ')}` : ''}
     ORDER BY arrival_seq, work_id LIMIT ?`,
    [...params, limit]
  );
  return rows.map((row) => parseReceiveWork(row.record, row.workId));
}

export async function receiveWorkUsage(
  db: SqliteExecutor,
  query: { groupId?: string } = {}
): Promise<ReceiveWorkUsage> {
  const row =
    query.groupId === undefined
      ? await db.first<UsageRow>(
          'SELECT COUNT(*) AS items, COALESCE(SUM(size_bytes), 0) AS bytes FROM receive_work'
        )
      : await db.first<UsageRow>(
          `SELECT COUNT(*) AS items, COALESCE(SUM(size_bytes), 0) AS bytes
           FROM receive_work WHERE blocked_group = ?`,
          [query.groupId]
        );
  return { items: Number(row?.items ?? 0), bytes: Number(row?.bytes ?? 0) };
}

/**
 * Delete the record with `expectedRevision` and apply the metadata writes,
 * in one transaction. Return false and write nothing on a mismatch.
 */
export async function completeReceiveWork(
  db: SqliteExecutor,
  workId: string,
  expectedRevision: number,
  metadata: readonly ReceiveWorkMetadataWrite[] = []
): Promise<boolean> {
  return await db.transaction(async (tx) => {
    const changes = await tx.run('DELETE FROM receive_work WHERE work_id = ? AND revision = ?', [
      workId,
      expectedRevision,
    ]);
    if (changes !== 1) return false;
    for (const { key, value } of metadata) {
      if (value === null) await deleteMetadata(tx, key);
      else await setMetadata(tx, key, value);
    }
    return true;
  });
}
