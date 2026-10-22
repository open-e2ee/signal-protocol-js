/**
 * The encryption policy of the shared SQLite core.
 *
 * Every SQLite entry opens an encrypted database unless the application
 * passes `encryptionAtRest: false`. A binding without a cipher accepts
 * `PRAGMA key` and writes plaintext with no error, so the core asks the
 * driver's cipher probe after each keyed open and refuses a connection that
 * reports no cipher.
 *
 * The core records the setting that created the database in
 * `PRAGMA application_id`, so a later open with the other setting fails
 * closed. The header field needs no table, so the account wipe and the
 * migrations do not touch it.
 */

import { EncryptionError, EncryptionErrorCode } from '../../../types/errors';
import { resolveSignalProtocolLogger, type Logger } from '../../../logger';

import type { LocalStoreAtRest } from '../../../types/api';

import type { SqliteConnection, SqliteDriver, SqliteExecutor } from './driver';
import {
  SqliteEncryptionUnavailableError,
  SqliteKeyMismatchError,
  SqliteStoreInUseError,
  classifySqliteError,
} from './errors';

/** The encryption option that every SQLite entry accepts. */
export interface SqliteEncryptionOptions {
  /**
   * Pass `false` to store the database without encryption. The store then
   * opens on a binding without a cipher, such as expo-sqlite on the web, and
   * logs a warning at every open. The setting is recorded in the database, so
   * a database created with one setting does not open with the other.
   *
   * Default: `true`. The open fails when the binding has no cipher.
   */
  readonly encryptionAtRest?: boolean;
  /**
   * Pass `true` to convert a plaintext database to an encrypted one at an
   * encrypted open. The store keeps every row and its schema version. The
   * open writes a new key to the vault, and it does not change the plaintext
   * file until the encrypted copy is complete. An open that stops during a
   * conversion leaves a state that the next encrypted open finishes or
   * starts again.
   *
   * The conversion refuses a database that holds tables of the application,
   * BLOB values, or integers outside the safe JavaScript range. The disk
   * blocks of the removed plaintext file can keep its data until the file
   * system reuses them.
   *
   * The option does nothing on an encrypted database or when no database
   * exists. With `encryptionAtRest: false`, the open fails with
   * `INVALID_STATE`.
   *
   * Default: `false`. An encrypted open of a plaintext database then fails
   * with `SqliteKeyMismatchError`.
   */
  readonly convertPlaintext?: boolean;
}

export interface SqliteOpenOptions extends SqliteEncryptionOptions {
  /**
   * Receives the warning of each open without encryption. Default: the SDK
   * logger, which writes warnings to the console outside tests.
   */
  readonly logger?: Logger;
}

// The application id is a 32-bit header field that SQLite stores and never
// reads. 0 is a database that no core open has recorded yet.
const ENCRYPTED_DATABASE_ID = 0x4f453245; // "OE2E"
const PLAINTEXT_DATABASE_ID = 0x4f453250; // "OE2P"

/**
 * Check the key against the setting before the driver opens the file. An
 * encrypted open without a key would create a plaintext file, and a key with
 * the opt-out means that the entry read the vault for a database that does
 * not use it.
 */
export function assertSqliteKeyMatchesSetting(
  key: Uint8Array | null,
  options: SqliteEncryptionOptions
): void {
  const encrypted = options.encryptionAtRest !== false;
  if (encrypted === (key !== null)) return;
  throw new EncryptionError(
    encrypted
      ? 'An encrypted SQLite open needs a database key.'
      : 'A SQLite open with encryptionAtRest: false takes no database key.',
    EncryptionErrorCode.INVALID_STATE,
    { operation: 'open' }
  );
}

/**
 * Enforce the encryption setting on a connection that the driver just opened.
 * On a failure, it closes the connection before it throws. Nothing is written
 * to the file until every check passes.
 */
export async function enforceSqliteEncryption(
  connection: SqliteConnection,
  driverName: string,
  options: SqliteOpenOptions
): Promise<void> {
  const encrypted = options.encryptionAtRest !== false;
  const expected = encrypted ? ENCRYPTED_DATABASE_ID : PLAINTEXT_DATABASE_ID;
  try {
    const { rows } = await connection.execute('PRAGMA application_id');
    const recorded = rows[0]?.application_id ?? 0;
    if (recorded !== 0 && recorded !== expected) {
      throw new SqliteKeyMismatchError(driverName);
    }
    if (encrypted && (await connection.probeCipher()) === null) {
      throw new SqliteEncryptionUnavailableError(driverName);
    }
    if (recorded === 0) {
      await connection.execute(`PRAGMA application_id = ${expected}`);
    }
  } catch (error) {
    // The policy error is the one to report. A failed close adds nothing.
    await connection.close().catch(() => undefined);
    throw error;
  }
  if (!encrypted) {
    resolveSignalProtocolLogger(options.logger).warn(
      `The ${driverName} database is not encrypted at rest (encryptionAtRest: false).`,
      { driver: driverName }
    );
  }
}

/**
 * Read how an open database is encrypted at rest from the setting that the
 * core recorded in `PRAGMA application_id`, not from an open option. A
 * database that the core did not record counts as `none`.
 */
export async function readSqliteAtRest(
  db: SqliteExecutor
): Promise<Extract<LocalStoreAtRest, 'file-cipher' | 'none'>> {
  const row = await db.first<{ application_id: number }>('PRAGMA application_id');
  return row?.application_id === ENCRYPTED_DATABASE_ID ? 'file-cipher' : 'none';
}

/**
 * Report whether an existing file is a database that the core recorded as
 * plaintext. An encrypted open with no key in the vault asks this before it
 * reports a lost key, because a plaintext store opened with the default
 * setting is a setting mismatch, and the remedy for a lost key deletes the
 * store.
 *
 * The check opens the file with no key, reads `PRAGMA application_id`, and
 * closes. It writes nothing. An encrypted file, a file that is not a
 * database, and a file with another id are not plaintext stores.
 */
export async function isPlaintextSqliteDatabase(
  driver: SqliteDriver,
  file: string
): Promise<boolean> {
  let connection: SqliteConnection;
  try {
    connection = await driver.open(file, null);
  } catch (error) {
    const kind = classifySqliteError(error);
    if (kind === 'not-a-database') return false;
    if (kind === 'busy') throw new SqliteStoreInUseError(driver.name, error);
    throw error;
  }
  try {
    const { rows } = await connection.execute('PRAGMA application_id');
    return rows[0]?.application_id === PLAINTEXT_DATABASE_ID;
  } finally {
    await connection.close().catch(() => undefined);
  }
}
