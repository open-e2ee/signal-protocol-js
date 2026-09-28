/**
 * Web SQLite Signal Protocol Store
 *
 * The SDK owns the database file. One call opens it in the origin private
 * file system through the SQLite Wasm worker, gets or creates its key through
 * the local secret vault, applies the SDK migrations, and returns the store.
 */

import type { Logger } from '../../../logger';
import type { SignalProtocolLocalSecretVault } from '../../../types/api';
import { IndexedDbSignalProtocolSecretVault } from '../../vault/indexed-db';
import type { SqliteOpenOptions } from '../sqlite/encryption';
import type { SqliteRootExecutor } from '../sqlite/executor';
import {
  openSqliteStore,
  resetSqliteStore,
  type SqliteStoreOpenOptions,
} from '../sqlite/open-store';
import { SqliteSignalProtocolStore } from '../sqlite/store';
import { createWebSqliteDriver, type WebSqliteDriver } from '../sqlite/web/driver';
import { acquireSqliteStoreLock, withSqliteOpenLock } from './store-locks';

/** The database name when the options name none. */
const DEFAULT_DATABASE_NAME = 'open-e2ee-signal-protocol.db';

export interface WebSqliteSignalProtocolStoreOptions extends SqliteOpenOptions {
  /**
   * The database name in the origin private file system. It also names the
   * vault slot of the database key. A letter or digit, then up to 63
   * letters, digits, `.`, `_`, and `-`. Default:
   * `open-e2ee-signal-protocol.db`.
   */
  readonly name?: string;
  /**
   * The vault that holds the database key. Default: the SDK's IndexedDB
   * vault in the same origin. A store with `encryptionAtRest: false` does not
   * use it.
   */
  readonly vault?: SignalProtocolLocalSecretVault;
  /**
   * The URL of the compiled worker module. Default: `./worker.js` next to
   * the driver module, which most bundlers resolve.
   */
  readonly workerUrl?: string | URL;
  /**
   * The URL of `sqlite3.wasm`, served as `application/wasm`. Default:
   * `./sqlite3mc/sqlite3.wasm` next to the driver module.
   */
  readonly wasmUrl?: string | URL;
}

/** The core options, with the store's own driver and worker. */
interface WebSqliteStoreOpenOptions extends SqliteStoreOpenOptions {
  readonly driver: WebSqliteDriver;
}

function storeOptions(options: WebSqliteSignalProtocolStoreOptions): WebSqliteStoreOpenOptions {
  const { workerUrl, wasmUrl, ...open } = options;
  return {
    ...open,
    driver: createWebSqliteDriver({ workerUrl, wasmUrl }),
    name: options.name ?? DEFAULT_DATABASE_NAME,
    vault: options.vault ?? new IndexedDbSignalProtocolSecretVault(),
  };
}

/** Stop the store's worker, then release its store lock. */
function stopper(driver: WebSqliteDriver, releaseLock: () => void): () => void {
  return () => {
    driver.terminate();
    releaseLock();
  };
}

/** Run `release`, then rethrow. */
function failed(release: () => void): (error: unknown) => never {
  return (error) => {
    release();
    throw error;
  };
}

/** The database, with a `close()` that also stops the worker and releases the store lock. */
function releasedOnClose(database: SqliteRootExecutor, release: () => void): SqliteRootExecutor {
  let closing: Promise<void> | null = null;
  return {
    ...database,
    close() {
      closing ??= database.close().finally(release);
      return closing;
    },
  };
}

/** The database of each open store, for the helpers of this entry. */
const databases = new WeakMap<WebSqliteSignalProtocolStore, SqliteRootExecutor>();

/** The executor of an open store. Not exported from the entry. */
export function webSqliteStoreDatabase(store: WebSqliteSignalProtocolStore): SqliteRootExecutor {
  const database = databases.get(store);
  if (!database) throw new TypeError('Open the store with webSqliteStore().');
  return database;
}

/**
 * Local Signal Protocol state for the web, in an SDK-owned SQLite database
 * that SQLite3 Multiple Ciphers encrypts, in the origin private file system.
 *
 * Open it with {@link webSqliteStore}. The store holds the database until
 * {@link WebSqliteSignalProtocolStore.close}. A second open of the same name
 * in the same JavaScript context fails with `INVALID_STATE`. The tabs of an
 * origin share the database: each tab opens its own store, and the driver
 * hands the file from tab to tab between transactions. A reset fails while a
 * store of the name is open in any tab or worker of the origin.
 *
 * The database key sits in the vault, by default in IndexedDB in the same
 * origin. It protects a copy of the database file. It is not an XSS defense.
 *
 * @category Key Storage
 * @see {@link SignalProtocolLocalStore} for interface documentation
 */
export class WebSqliteSignalProtocolStore extends SqliteSignalProtocolStore {
  private constructor(database: SqliteRootExecutor, logger: Logger | undefined) {
    super(database, { logger });
    databases.set(this, database);
  }

  /** @internal Use {@link webSqliteStore}. */
  static async open(
    options: WebSqliteSignalProtocolStoreOptions
  ): Promise<WebSqliteSignalProtocolStore> {
    const open = storeOptions(options);
    const database = await withSqliteOpenLock(open.name, 'open', async () => {
      const release = stopper(open.driver, await acquireSqliteStoreLock(open.name, 'shared', 'open'));
      return releasedOnClose(await openSqliteStore(open).catch(failed(release)), release);
    });
    return new WebSqliteSignalProtocolStore(database, options.logger);
  }

  /** @internal Use {@link resetWebSqliteStore}. */
  static async reset(
    options: WebSqliteSignalProtocolStoreOptions
  ): Promise<WebSqliteSignalProtocolStore> {
    const open = storeOptions(options);
    const database = await withSqliteOpenLock(open.name, 'reset', async () => {
      const releaseExclusive = await acquireSqliteStoreLock(open.name, 'exclusive', 'reset');
      const reset = await resetSqliteStore(open)
        .catch(failed(() => open.driver.terminate()))
        .finally(releaseExclusive);
      const release = await acquireSqliteStoreLock(open.name, 'shared', 'reset').catch(async (error) => {
        await reset.close().finally(() => open.driver.terminate());
        throw error;
      });
      return releasedOnClose(reset, stopper(open.driver, release));
    });
    return new WebSqliteSignalProtocolStore(database, options.logger);
  }

  /**
   * Wait for the queued work, then close the database and stop its worker.
   * Every later call rejects with `SqliteStoreClosedError`.
   */
  close(): Promise<void> {
    return webSqliteStoreDatabase(this).close();
  }
}

/**
 * Open the store. On first use it creates the database key in the vault, then
 * the database file. With `encryptionAtRest: false` it does not use the vault.
 * The opens and resets of a name run one at a time across the tabs of the
 * origin.
 *
 * @throws EncryptionError with `LOCAL_STORE_KEY_LOST` when the database file
 *   exists and the vault holds no key for it. Restore the vault entry, or call
 *   {@link resetWebSqliteStore}.
 * @throws EncryptionError with `KEY_STORAGE_ERROR` when the vault fails or
 *   holds a key of the wrong size, when the key does not open the file, or
 *   when the file was created with the other `encryptionAtRest` setting.
 * @throws EncryptionError with `OPFS_UNAVAILABLE` when the context has no
 *   origin private file system with synchronous access handles, or no Web
 *   Locks.
 * @throws EncryptionError with `OPFS_FILE_BUSY` when the files of the
 *   database stay locked, for example by a tab that is closing. Retry later.
 * @throws EncryptionError with `SQLITE_ENGINE_UNAVAILABLE` when the worker or
 *   the Wasm engine does not load, for example under a Content Security
 *   Policy without `'wasm-unsafe-eval'`.
 * @throws EncryptionError with `INVALID_STATE` when the name is not valid,
 *   when a store of this context holds the name, or when a newer SDK wrote
 *   the file.
 */
export function webSqliteStore(
  options: WebSqliteSignalProtocolStoreOptions = {}
): Promise<WebSqliteSignalProtocolStore> {
  return WebSqliteSignalProtocolStore.open(options);
}

/**
 * Delete the database file, then create a new key, and return the open, empty
 * store. This is the only way to open a store whose key is lost.
 *
 * @throws EncryptionError with `INVALID_STATE` when the name is not valid, or
 *   when a store of the name is open in any tab or worker of the origin.
 *   Close it everywhere first.
 */
export function resetWebSqliteStore(
  options: WebSqliteSignalProtocolStoreOptions = {}
): Promise<WebSqliteSignalProtocolStore> {
  return WebSqliteSignalProtocolStore.reset(options);
}
