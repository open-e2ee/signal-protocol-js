/**
 * The data side of the conversion of a plaintext SQLite store to an encrypted
 * one.
 *
 * The open in `./open-store` owns the steps, the keys, and the recovery. This
 * module checks a plaintext database before the first write. It also copies
 * the schema and the rows of one database into another in one transaction.
 * The driver seam has no rename, attach, or export, so the copy is the only
 * path, and it runs the same way on every driver.
 *
 * The copy keeps every row, its rowid, the `sqlite_sequence` counters, and
 * `PRAGMA user_version`. Only SDK tables are copied. A driver value is a
 * string, a number, or null, so a BLOB value or an integer outside the safe
 * JavaScript range cannot pass through the copy. The check refuses them
 * before anything is written.
 */

import { EncryptionError, EncryptionErrorCode } from '../../../types/errors';
import type { SqliteDriver, SqliteExecutor, SqliteRow, SqliteValue } from './driver';
import { SqliteSchemaTooNewError, SqliteStoreInUseError, classifySqliteError } from './errors';
import { createSqliteExecutor, type SqliteRootExecutor } from './executor';
import { SQLITE_STORE_MIGRATIONS } from './migrations';
import { SQLITE_STORE_TABLES } from './schema';

/**
 * The name ending of the temporary file of a conversion. The core refuses a
 * store name with this ending, so no store shares the file.
 */
export const SQLITE_CONVERT_SUFFIX = '.oe2e-convert';

/** The temporary file of the conversion of the store `name`. */
export function sqliteConvertTempName(name: string): string {
  return `${name}${SQLITE_CONVERT_SUFFIX}`;
}

/** The rows that one read of the copy returns. */
const PAGE_SIZE = 256;

/** The alias of the rowid in the reads of the copy. No SDK column has this name. */
const ROWID = 'oe2e_copy_rowid';

/** SQL that is true when `expression` is an integer outside the safe JavaScript range. */
function unsafeInteger(expression: string): string {
  return (
    `(typeof(${expression}) = 'integer' AND ` +
    `(${expression} > ${Number.MAX_SAFE_INTEGER} OR ${expression} < ${-Number.MAX_SAFE_INTEGER}))`
  );
}

function quote(identifier: string): string {
  return `"${identifier.replaceAll('"', '""')}"`;
}

function invalidState(message: string, originalError?: unknown): EncryptionError {
  return new EncryptionError(message, EncryptionErrorCode.INVALID_STATE, {
    operation: 'open',
    originalError: originalError as Error | undefined,
  });
}

async function readUserVersion(db: SqliteExecutor): Promise<number> {
  const row = await db.first<{ user_version: number }>('PRAGMA user_version');
  return row?.user_version ?? 0;
}

/** The tables of `db` in creation order, without the `sqlite_` tables. */
async function readTables(db: SqliteExecutor): Promise<string[]> {
  const rows = await db.all<{ name: string }>(
    "SELECT name FROM sqlite_master WHERE type = 'table' AND substr(name, 1, 7) <> 'sqlite_' " +
      'ORDER BY rowid'
  );
  return rows.map((row) => row.name);
}

async function readColumns(db: SqliteExecutor, table: string): Promise<string[]> {
  const rows = await db.all<{ name: string }>(
    'SELECT name FROM pragma_table_info(?) ORDER BY cid',
    [table]
  );
  return rows.map((row) => row.name);
}

async function hasSequenceTable(db: SqliteExecutor): Promise<boolean> {
  const row = await db.first(
    "SELECT 1 AS present FROM sqlite_master WHERE type = 'table' AND name = 'sqlite_sequence'"
  );
  return row !== null;
}

/**
 * Open the plaintext database `file` with no key, and check that the copy
 * can keep all of it. The open writes nothing. On a failure, it closes the
 * database before it throws.
 *
 * @throws EncryptionError with `INVALID_STATE` when the database holds no SDK
 *   schema, holds a table that is not an SDK table, or holds a BLOB value or
 *   an unsafe integer.
 * @throws SqliteSchemaTooNewError when a newer SDK wrote the database.
 * @throws SqliteStoreInUseError when another connection holds the file.
 */
export async function openSqliteConversionSource(
  driver: SqliteDriver,
  file: string
): Promise<SqliteRootExecutor> {
  let db: SqliteRootExecutor;
  try {
    db = createSqliteExecutor(await driver.open(file, null));
  } catch (error) {
    if (classifySqliteError(error) === 'busy') throw new SqliteStoreInUseError(driver.name, error);
    throw error;
  }
  try {
    await assertConvertible(db, file);
  } catch (error) {
    // The check error is the one to report. A failed close adds nothing.
    await db.close().catch(() => undefined);
    throw error;
  }
  return db;
}

async function assertConvertible(db: SqliteExecutor, file: string): Promise<void> {
  const version = await readUserVersion(db);
  if (version === 0) {
    throw invalidState(
      `The plaintext database ${file} holds no SDK schema, so there is nothing to convert. ` +
        'Reset the store to start an encrypted one.'
    );
  }
  const last = SQLITE_STORE_MIGRATIONS.at(-1)?.version ?? 0;
  if (version > last) throw new SqliteSchemaTooNewError(version, last);

  const known = new Set<string>(SQLITE_STORE_TABLES);
  const tables = await readTables(db);
  const foreign = tables.filter((table) => !known.has(table));
  if (foreign.length > 0) {
    throw invalidState(
      `The plaintext database ${file} holds tables that the SDK does not own: ` +
        `${foreign.join(', ')}. Move them to another database, then convert.`
    );
  }

  for (const table of tables) {
    const columns = (await readColumns(db, table)).map(quote);
    const blob = columns.map((column) => `typeof(${column}) = 'blob'`).join(' OR ') || '0';
    const unsafe = ['rowid', ...columns].map(unsafeInteger).join(' OR ');
    const row = await db.first<{ blobs: number; unsafe: number }>(
      `SELECT coalesce(sum(${blob}), 0) AS blobs, coalesce(sum(${unsafe}), 0) AS unsafe ` +
        `FROM ${quote(table)}`
    );
    if (row && row.blobs > 0) {
      throw invalidState(
        `The plaintext database ${file} holds BLOB values in table ${table}. ` +
          'The SDK stores no BLOB values, so the conversion cannot keep them.'
      );
    }
    if (row && row.unsafe > 0) {
      throw invalidState(
        `The plaintext database ${file} holds integers in table ${table} that a JavaScript ` +
          'number cannot hold exactly, so the conversion cannot keep them.'
      );
    }
  }
  if (await hasSequenceTable(db)) {
    const row = await db.first<{ unsafe: number }>(
      `SELECT count(*) AS unsafe FROM sqlite_sequence WHERE ${unsafeInteger('seq')}`
    );
    if (row && row.unsafe > 0) {
      throw invalidState(
        `The plaintext database ${file} holds a row counter that a JavaScript number cannot ` +
          'hold exactly, so the conversion cannot keep it.'
      );
    }
  }
}

/**
 * Copy the schema and the rows of `source` into the empty database `target`,
 * in one `BEGIN IMMEDIATE` transaction on `target`.
 *
 * The order is: the tables, their rows page by page in rowid order, the
 * `sqlite_sequence` counters, the other schema objects in creation order, and
 * `PRAGMA user_version` last. Indexes and triggers come after the rows, so no
 * trigger runs on a copied row. Foreign keys are off on `target`, so the
 * table order does not matter. The transaction checks the row count of each
 * table, and a difference rolls it back.
 *
 * @throws EncryptionError with `INVALID_STATE` when a table of `target` has
 *   another row count than the same table of `source`.
 */
export async function copySqliteDatabase(
  source: SqliteExecutor,
  target: SqliteRootExecutor
): Promise<void> {
  const objects = await source.all<{ type: string; name: string; sql: string }>(
    "SELECT type, name, sql FROM sqlite_master WHERE sql IS NOT NULL AND substr(name, 1, 7) <> 'sqlite_' " +
      'ORDER BY rowid'
  );
  const version = await readUserVersion(source);
  const sequence = (await hasSequenceTable(source))
    ? await source.all<{ name: string; seq: number }>('SELECT name, seq FROM sqlite_sequence')
    : null;

  // SQLite ignores this pragma inside a transaction.
  await target.run('PRAGMA foreign_keys = OFF');
  await target.transaction(async (tx) => {
    const tables = objects.filter((object) => object.type === 'table');
    for (const table of tables) await tx.run(table.sql);
    for (const table of tables) await copyRows(source, tx, table.name);
    if (sequence) {
      // Each copied row moved the counter to the largest rowid. The source
      // counter can be higher, because a delete does not lower it.
      await tx.run('DELETE FROM sqlite_sequence');
      for (const row of sequence) {
        await tx.run('INSERT INTO sqlite_sequence (name, seq) VALUES (?, ?)', [row.name, row.seq]);
      }
    }
    for (const object of objects) {
      if (object.type !== 'table') await tx.run(object.sql);
    }
    await tx.run(`PRAGMA user_version = ${version}`);
  });
}

async function copyRows(source: SqliteExecutor, target: SqliteExecutor, table: string): Promise<void> {
  const names = await readColumns(source, table);
  const columns = names.map(quote);
  const from = quote(table);
  const select = `SELECT rowid AS ${ROWID}${columns.map((column) => `, ${column}`).join('')} FROM ${from}`;
  const insert =
    `INSERT INTO ${from} (rowid${columns.map((column) => `, ${column}`).join('')}) ` +
    `VALUES (?${', ?'.repeat(columns.length)})`;

  let after: SqliteValue | null = null;
  for (;;) {
    const rows: readonly SqliteRow[] = await source.all(
      after === null
        ? `${select} ORDER BY rowid LIMIT ${PAGE_SIZE}`
        : `${select} WHERE rowid > ? ORDER BY rowid LIMIT ${PAGE_SIZE}`,
      after === null ? [] : [after]
    );
    for (const row of rows) {
      await target.run(insert, [row[ROWID], ...names.map((name) => row[name])]);
    }
    if (rows.length < PAGE_SIZE) break;
    after = rows[rows.length - 1][ROWID];
  }

  const count = `SELECT count(*) AS count FROM ${from}`;
  const expected = (await source.first<{ count: number }>(count))?.count ?? 0;
  const copied = (await target.first<{ count: number }>(count))?.count ?? 0;
  if (copied !== expected) {
    throw invalidState(
      `The conversion copied ${copied} rows of table ${table} instead of ${expected}. ` +
        'It wrote nothing.'
    );
  }
}

/**
 * Open the existing file `file` with `key`, read its `PRAGMA user_version`,
 * and close it. The read writes nothing. Return `null` when the key does not
 * open the file. Call it only for a file that exists, because a driver
 * creates a file that it opens.
 *
 * @throws SqliteStoreInUseError when another connection holds the file.
 */
export async function readSqliteUserVersion(
  driver: SqliteDriver,
  file: string,
  key: Uint8Array
): Promise<number | null> {
  let db: SqliteRootExecutor;
  try {
    db = createSqliteExecutor(await driver.open(file, key));
  } catch (error) {
    const kind = classifySqliteError(error);
    if (kind === 'not-a-database') return null;
    if (kind === 'busy') throw new SqliteStoreInUseError(driver.name, error);
    throw error;
  }
  try {
    return await readUserVersion(db);
  } finally {
    await db.close().catch(() => undefined);
  }
}
