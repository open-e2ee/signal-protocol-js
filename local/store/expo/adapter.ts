/**
 * Expo Signal Protocol Store
 *
 * The SDK owns the database file. One call opens it in the expo-sqlite default
 * directory, gets or creates its key through the local secret vault, applies
 * the SDK migrations, and returns the store.
 */

import type { Logger } from '../../../logger';
import type { SignalProtocolLocalSecretVault } from '../../../types/api';
import { ExpoSecureStoreSignalProtocolSecretVault } from '../../vault/expo-secure-store';
import type { SqliteOpenOptions } from '../sqlite/encryption';
import type { SqliteRootExecutor } from '../sqlite/executor';
import {
  openSqliteStore,
  resetSqliteStore,
  type SqliteStoreOpenOptions,
} from '../sqlite/open-store';
import { SqliteSignalProtocolStore } from '../sqlite/store';
import { createExpoSqliteDriver } from './driver';

/** The database file name when the options name none. */
const DEFAULT_DATABASE_NAME = 'open-e2ee-signal-protocol.db';

export interface ExpoSignalProtocolStoreOptions extends SqliteOpenOptions {
  /**
   * The database file name in the expo-sqlite default directory. It also
   * names the vault slot of the database key. Letters, digits, `.`, `_`, and
   * `-` only. Default: `open-e2ee-signal-protocol.db`.
   */
  readonly name?: string;
  /**
   * The vault that holds the database key. Default: an
   * `ExpoSecureStoreSignalProtocolSecretVault`. A store with
   * `encryptionAtRest: false` does not use it.
   */
  readonly vault?: SignalProtocolLocalSecretVault;
}

function storeOptions(options: ExpoSignalProtocolStoreOptions): SqliteStoreOpenOptions {
  return {
    ...options,
    driver: createExpoSqliteDriver(),
    name: options.name ?? DEFAULT_DATABASE_NAME,
    vault: options.vault ?? new ExpoSecureStoreSignalProtocolSecretVault(),
  };
}

/** The database of each open store, for the helpers of this entry. */
const databases = new WeakMap<ExpoSignalProtocolStore, SqliteRootExecutor>();

/** The executor of an open store. Not exported from the entry. */
export function expoStoreDatabase(store: ExpoSignalProtocolStore): SqliteRootExecutor {
  const database = databases.get(store);
  if (!database) throw new TypeError('Open the store with expoStore().');
  return database;
}

/**
 * Local Signal Protocol state for Expo, in an SDK-owned SQLCipher database.
 *
 * Open it with {@link expoStore}. The store holds the database file until
 * {@link ExpoSignalProtocolStore.close}. A second open of the same name in
 * the process fails with `INVALID_STATE`.
 *
 * Every table holds material that must not leave the device, including the
 * group sender keys. SQLCipher encrypts the whole file, so the database key
 * in the vault is the only thing that protects it.
 *
 * @category Key Storage
 * @see {@link SignalProtocolLocalStore} for interface documentation
 */
export class ExpoSignalProtocolStore extends SqliteSignalProtocolStore {
  private constructor(database: SqliteRootExecutor, logger: Logger | undefined) {
    super(database, { logger });
    databases.set(this, database);
  }

  /** @internal Use {@link expoStore}. */
  static async open(options: ExpoSignalProtocolStoreOptions): Promise<ExpoSignalProtocolStore> {
    const database = await openSqliteStore(storeOptions(options));
    return new ExpoSignalProtocolStore(database, options.logger);
  }

  /** @internal Use {@link resetExpoStore}. */
  static async reset(options: ExpoSignalProtocolStoreOptions): Promise<ExpoSignalProtocolStore> {
    const database = await resetSqliteStore(storeOptions(options));
    return new ExpoSignalProtocolStore(database, options.logger);
  }

  /**
   * Wait for the queued work, then close the database. Every later call
   * rejects with `SqliteStoreClosedError`.
   */
  close(): Promise<void> {
    return expoStoreDatabase(this).close();
  }
}

/**
 * Open the store. On first use it creates the database key in the vault, then
 * the database file. With `encryptionAtRest: false` it does not use the vault.
 *
 * @throws EncryptionError with `LOCAL_STORE_KEY_LOST` when the database file
 *   exists and the vault holds no key for it. Restore the vault entry, or call
 *   {@link resetExpoStore}.
 * @throws EncryptionError with `KEY_STORAGE_ERROR` when the vault fails or
 *   holds a key of the wrong size, when the key does not open the file, when
 *   the file was created with the other `encryptionAtRest` setting, when the
 *   binding has no cipher, or when another connection holds the file.
 * @throws EncryptionError with `INVALID_STATE` when the name is not valid,
 *   when a store of this process holds the name, or when a newer SDK wrote
 *   the file.
 */
export function expoStore(
  options: ExpoSignalProtocolStoreOptions = {}
): Promise<ExpoSignalProtocolStore> {
  return ExpoSignalProtocolStore.open(options);
}

/**
 * Delete the database file, then create a new key, and return the open, empty
 * store. This is the only way to open a store whose key is lost.
 *
 * @throws EncryptionError with `INVALID_STATE` when the name is not valid, or
 *   when a store of this process holds the name. Close that store first.
 */
export function resetExpoStore(
  options: ExpoSignalProtocolStoreOptions = {}
): Promise<ExpoSignalProtocolStore> {
  return ExpoSignalProtocolStore.reset(options);
}
