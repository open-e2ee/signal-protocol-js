/**
 * The shared SQLite core of the local store.
 *
 * A platform entry supplies a driver. The core owns the database key custody,
 * the migrations, the statement queue, the transactions, the error classes,
 * the models, and the store above them. Nothing in this directory imports a
 * platform binding.
 */

export type {
  SqliteConnection,
  SqliteDriver,
  SqliteExecutor,
  SqliteMigration,
  SqliteRow,
  SqliteStatementResult,
  SqliteValue,
} from './driver';
export { createSqliteExecutor, type SqliteRootExecutor } from './executor';
export { openSqliteDatabase } from './database';
export type { SqliteEncryptionOptions, SqliteOpenOptions } from './encryption';
export {
  openSqliteStore,
  resetSqliteStore,
  sqliteDatabaseKeySlot,
  type SqliteStoreOpenOptions,
} from './open-store';
export {
  applySqliteMigrations,
  openMigratedSqliteDatabase,
  SQLITE_STORE_MIGRATIONS,
} from './migrations';
export {
  SqliteEncryptionUnavailableError,
  SqliteKeyMismatchError,
  SqliteSchemaTooNewError,
  SqliteStoreClosedError,
  SqliteStoreCorruptError,
  SqliteStoreInUseError,
  classifySqliteError,
  type SqliteErrorKind,
} from './errors';
export { SQLITE_STORE_TABLES } from './schema';
export {
  SqliteKeyStorage,
  type SqliteKeyStorageOptions,
  type DetailedStats,
  type DeletedPreKeyCounts,
} from './key-storage';
export { SqliteSignalProtocolStore } from './store';
export { createSqlitePreKeyMaintenanceStore } from './maintenance';
