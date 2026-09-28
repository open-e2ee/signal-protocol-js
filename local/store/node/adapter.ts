/**
 * Node and Electron Signal Protocol Store
 *
 * The SDK owns the database file. One call opens it in a directory that the
 * app chooses, gets or creates its key through the app's secret vault, applies
 * the SDK migrations, and returns the store.
 */

import type { Logger } from '../../../logger';
import type { SignalProtocolLocalSecretVault } from '../../../types/api';
import { createBetterSqlite3MultipleCiphersDriver } from '../sqlite/better-sqlite3-multiple-ciphers-driver';
import type { SqliteOpenOptions } from '../sqlite/encryption';
import type { SqliteRootExecutor } from '../sqlite/executor';
import {
  openSqliteStore,
  resetSqliteStore,
  type SqliteStoreOpenOptions,
} from '../sqlite/open-store';
import { SqliteSignalProtocolStore } from '../sqlite/store';
import { withOwnerLock } from './owner-lock';

/** The database file name when the options name none. */
const DEFAULT_DATABASE_NAME = 'open-e2ee-signal-protocol.db';

export interface NodeSignalProtocolStoreOptions extends SqliteOpenOptions {
  /**
   * The directory of the database file. The store creates it when it is
   * missing, readable only by the owner. Use a private directory on a local
   * file system, for example Electron's `app.getPath('userData')`.
   */
  readonly directory: string;
  /**
   * The database file name in `directory`. Letters, digits, `.`, `_`, and
   * `-` only, and no `.lock`, `-wal`, `-shm`, or `-journal` ending. Default:
   * `open-e2ee-signal-protocol.db`.
   */
  readonly name?: string;
  /**
   * The vault that holds the database key, for example an
   * `ElectronSafeStorageSignalProtocolSecretVault` in the Electron main
   * process. A store with `encryptionAtRest: false` does not use it.
   */
  readonly vault: SignalProtocolLocalSecretVault;
}

/** The database of each open store, for the helpers of this entry. */
const databases = new WeakMap<NodeSignalProtocolStore, SqliteRootExecutor>();

/** The executor of an open store. Not exported from the entry. */
export function nodeStoreDatabase(store: NodeSignalProtocolStore): SqliteRootExecutor {
  const database = databases.get(store);
  if (!database) throw new TypeError('Open the store with nodeStore().');
  return database;
}

/** Run `run` on the core options of the store, with the owner lock. */
async function withStoreOptions(
  options: NodeSignalProtocolStoreOptions,
  operation: 'open' | 'reset',
  run: (options: SqliteStoreOpenOptions) => Promise<SqliteRootExecutor>
): Promise<SqliteRootExecutor> {
  const driver = createBetterSqlite3MultipleCiphersDriver({ directory: options.directory });
  const storeOptions = { ...options, driver, name: options.name ?? DEFAULT_DATABASE_NAME };
  return withOwnerLock(driver, storeOptions.name, operation, () => run(storeOptions));
}

/**
 * Local Signal Protocol state for Node and the Electron main process, in an
 * SDK-owned SQLCipher database.
 *
 * Open it with {@link nodeStore}. The store holds the database file until
 * {@link NodeSignalProtocolStore.close}. A second open of the same file in
 * the process fails with `INVALID_STATE`, and an open in another process
 * fails with `SqliteStoreInUseError`.
 *
 * Every table holds material that must not leave the device, including the
 * group sender keys. SQLCipher encrypts the whole file, so the database key
 * in the vault is the only thing that protects it.
 *
 * @category Key Storage
 * @see {@link SignalProtocolLocalStore} for interface documentation
 */
export class NodeSignalProtocolStore extends SqliteSignalProtocolStore {
  private constructor(database: SqliteRootExecutor, logger: Logger | undefined) {
    super(database, { logger });
    databases.set(this, database);
  }

  /** @internal Use {@link nodeStore}. */
  static async open(options: NodeSignalProtocolStoreOptions): Promise<NodeSignalProtocolStore> {
    const database = await withStoreOptions(options, 'open', openSqliteStore);
    return new NodeSignalProtocolStore(database, options.logger);
  }

  /** @internal Use {@link resetNodeStore}. */
  static async reset(options: NodeSignalProtocolStoreOptions): Promise<NodeSignalProtocolStore> {
    const database = await withStoreOptions(options, 'reset', resetSqliteStore);
    return new NodeSignalProtocolStore(database, options.logger);
  }

  /**
   * Wait for the queued work, then close the database and release the file.
   * Every later call rejects with `SqliteStoreClosedError`.
   */
  close(): Promise<void> {
    return nodeStoreDatabase(this).close();
  }
}

/**
 * Open the store. On first use it creates the database key in the vault, then
 * the database file. With `encryptionAtRest: false` it does not use the vault.
 *
 * @throws SqliteStoreInUseError when a store in another process holds the
 *   file. The open reads no vault entry and does not touch the file.
 * @throws EncryptionError with `LOCAL_STORE_KEY_LOST` when the database file
 *   exists and the vault holds no key for it, also after the directory moved.
 *   Move the vault entry, restore it, or call {@link resetNodeStore}.
 * @throws EncryptionError with `KEY_STORAGE_ERROR` when the vault fails or
 *   holds a key of the wrong size, when the key does not open the file, or
 *   when the file was created with the other `encryptionAtRest` setting.
 * @throws EncryptionError with `INVALID_STATE` when the name is not valid,
 *   when a store of this process holds the file, or when a newer SDK wrote
 *   the file.
 */
export function nodeStore(
  options: NodeSignalProtocolStoreOptions
): Promise<NodeSignalProtocolStore> {
  return NodeSignalProtocolStore.open(options);
}

/**
 * Delete the database file, then create a new key, and return the open, empty
 * store. This is the only way to open a store whose key is lost.
 *
 * @throws SqliteStoreInUseError when a store in another process holds the
 *   file. The reset changes nothing.
 * @throws EncryptionError with `INVALID_STATE` when the name is not valid, or
 *   when a store of this process holds the file. Close that store first.
 */
export function resetNodeStore(
  options: NodeSignalProtocolStoreOptions
): Promise<NodeSignalProtocolStore> {
  return NodeSignalProtocolStore.reset(options);
}
