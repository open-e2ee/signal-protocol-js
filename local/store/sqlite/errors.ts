/**
 * SQLite error classification for the shared core.
 *
 * Not every binding reports the SQLite result code (op-sqlite does not), so
 * the core classifies an error from the SQLite message text that every driver
 * keeps in the error message. This module is the one place that reads it.
 */

import {
  EncryptionError,
  EncryptionErrorCode,
  StorageQuotaExceededError,
} from '../../../types/errors';

export type SqliteErrorKind =
  /** A UNIQUE or PRIMARY KEY constraint rejected the statement. */
  | 'unique-constraint'
  /** Another connection holds the lock: `SQLITE_BUSY`. */
  | 'busy'
  /** The file is not a database with this key and settings: `SQLITE_NOTADB`. */
  | 'not-a-database'
  /**
   * The file cannot grow: the disk or the storage quota is full, or the file
   * is at `PRAGMA max_page_count`. `SQLITE_FULL` has no extended codes.
   */
  | 'full'
  | 'other';

// A binding error can come from another realm and fail `instanceof Error`.
function messageOf(error: unknown): string {
  const message = (error as { message?: unknown } | null)?.message;
  return typeof message === 'string' ? message : String(error);
}

export function classifySqliteError(error: unknown): SqliteErrorKind {
  const message = messageOf(error);
  if (/UNIQUE constraint failed|PRIMARY KEY constraint failed/.test(message)) {
    return 'unique-constraint';
  }
  if (/database is locked|SQLITE_BUSY/.test(message)) return 'busy';
  if (/file is not a database|SQLITE_NOTADB/.test(message)) return 'not-a-database';
  if (/database or disk is full|SQLITE_FULL/.test(message)) return 'full';
  return 'other';
}

/**
 * Return a full file as `StorageQuotaExceededError`, with the driver error as
 * its original error. Return every other error unchanged. SQLite rolls back
 * the statement that failed, and the executor rolls back its transaction.
 */
export function toStorageQuotaError(error: unknown): unknown {
  if (classifySqliteError(error) !== 'full') return error;
  return new StorageQuotaExceededError('sqlite', error as Error);
}

/**
 * A call on a store or a transaction scope that has ended. No statement ran.
 */
export class SqliteStoreClosedError extends EncryptionError {
  override readonly name = 'SqliteStoreClosedError';
  constructor(message: string) {
    super(message, EncryptionErrorCode.INVALID_STATE, { operation: 'sqlite' });
  }
}

/**
 * An existing database file could not be read with the key and encryption
 * setting of this open. The file is not reported as corrupt: a wrong key, a
 * missing key, and a plaintext file opened with a key all fail the same way.
 * A database that records the other `encryptionAtRest` setting also fails
 * this way, with no original error.
 */
export class SqliteKeyMismatchError extends EncryptionError {
  override readonly name = 'SqliteKeyMismatchError';
  constructor(driver: string, originalError?: unknown) {
    super(
      `The ${driver} database exists but cannot be read with this key and encryption setting. ` +
        'Open it with the key and setting that created it, or reset the store.',
      EncryptionErrorCode.KEY_STORAGE_ERROR,
      { operation: 'open', originalError: originalError as Error | undefined }
    );
  }
}

/**
 * A keyed open would store the database as plaintext. The driver refuses
 * the key on a binding that has no cipher, or the binding reports no cipher
 * after the open because its driver did not apply the key.
 */
export class SqliteEncryptionUnavailableError extends EncryptionError {
  override readonly name = 'SqliteEncryptionUnavailableError';
  constructor(driver: string) {
    super(
      `The ${driver} database would not be encrypted, so the store did not ` +
        'open. Use a SQLite build with a cipher, or pass ' +
        'encryptionAtRest: false to store the database without encryption.',
      EncryptionErrorCode.KEY_STORAGE_ERROR,
      { operation: 'open' }
    );
  }
}

/**
 * A new database file could not be read right after the driver created it.
 * No key or setting from an earlier open applies, so the file is corrupt.
 */
export class SqliteStoreCorruptError extends EncryptionError {
  override readonly name = 'SqliteStoreCorruptError';
  constructor(driver: string, originalError: unknown) {
    super(
      `The ${driver} database file is corrupt. It did not exist before this open.`,
      EncryptionErrorCode.KEY_STORAGE_ERROR,
      { operation: 'open', originalError: originalError as Error }
    );
  }
}

/** Another connection or process holds the database file. */
export class SqliteStoreInUseError extends EncryptionError {
  override readonly name = 'SqliteStoreInUseError';
  constructor(driver: string, originalError: unknown) {
    super(
      `The ${driver} database is open in another connection or process.`,
      EncryptionErrorCode.KEY_STORAGE_ERROR,
      { operation: 'open', originalError: originalError as Error }
    );
  }
}

/**
 * A newer SDK wrote the database file. Its schema version is above the last
 * migration step that this SDK knows, so this SDK does not open it.
 */
export class SqliteSchemaTooNewError extends EncryptionError {
  override readonly name = 'SqliteSchemaTooNewError';
  constructor(fileVersion: number, knownVersion: number) {
    super(
      `The database schema is at version ${fileVersion}, but this SDK knows versions up to ` +
        `${knownVersion}. Open the file with the SDK version that wrote it, or a newer one.`,
      EncryptionErrorCode.INVALID_STATE,
      { operation: 'open' }
    );
  }
}
