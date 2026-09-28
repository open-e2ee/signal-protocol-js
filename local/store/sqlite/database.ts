/**
 * Open one database file through a driver.
 *
 * The driver applies the key and runs one verifying read inside `open`, so a
 * wrong key, a missing key, or a plaintext file opened with a key fails here
 * with `SQLITE_NOTADB`, before any store call. Only then does the core ask the
 * driver whether the file exists, so a successful open does not call
 * `exists`. A file that exists held data that the key or setting did not
 * read, so the core reports a key or setting mismatch, not corruption. When
 * no file exists, no earlier key or setting applies, so the core reports
 * corruption.
 *
 * Right after the open, the core enforces the encryption setting
 * (`./encryption`).
 */

import type { SqliteConnection, SqliteDriver } from './driver';
import {
  assertSqliteKeyMatchesSetting,
  enforceSqliteEncryption,
  type SqliteOpenOptions,
} from './encryption';
import {
  SqliteKeyMismatchError,
  SqliteStoreCorruptError,
  SqliteStoreInUseError,
  classifySqliteError,
} from './errors';
import { createSqliteExecutor, type SqliteRootExecutor } from './executor';

export async function openSqliteDatabase(
  driver: SqliteDriver,
  file: string,
  key: Uint8Array | null,
  options: SqliteOpenOptions = {}
): Promise<SqliteRootExecutor> {
  assertSqliteKeyMatchesSetting(key, options);
  const connection = await openConnection(driver, file, key);
  await enforceSqliteEncryption(connection, driver.name, options);
  return createSqliteExecutor(connection);
}

async function openConnection(
  driver: SqliteDriver,
  file: string,
  key: Uint8Array | null
): Promise<SqliteConnection> {
  try {
    return await driver.open(file, key);
  } catch (error) {
    const kind = classifySqliteError(error);
    if (kind === 'not-a-database') {
      throw (await driver.exists(file))
        ? new SqliteKeyMismatchError(driver.name, error)
        : new SqliteStoreCorruptError(driver.name, error);
    }
    if (kind === 'busy') throw new SqliteStoreInUseError(driver.name, error);
    throw error;
  }
}
