/**
 * Open the database of an SDK-owned SQLite store, and hold the custody of its
 * key.
 *
 * Each platform entry is a driver plus a vault on {@link openSqliteStore} and
 * {@link resetSqliteStore}. The driver maps the name to a file, and
 * `driver.identify(name)` names the database that the file is. That identity
 * keys the vault slot of the key and the one-at-a-time open below.
 *
 * An encrypted store has one 32-byte key in one slot of the secret vault. The
 * key lives only in the vault, never in the file beside the data it encrypts.
 * The vault write comes before the driver creates the file, so a file never
 * exists without its key. A file that exists while the vault holds no key is
 * a lost key: opening reports it and changes nothing, because a new key
 * cannot read the old file. The exception is a file that the core recorded as
 * plaintext: opening reports a setting mismatch, as the other direction does.
 * Only an explicit reset deletes the file and makes a new key. A store with
 * `encryptionAtRest: false` has no key, and its open and reset do not touch
 * the vault.
 *
 * In one process, the open and the reset of a database run one at a time, and
 * a database has at most one open store. Two first opens therefore cannot write
 * two different keys, and a reset or the driver's `exists` never runs on a
 * file under a live connection. This does not cover other processes: an
 * entry whose files other processes can open holds its own cross-process lock
 * over each call.
 */

import { generateRandomBytes } from '../../../internal/crypto/random';
import type { SignalProtocolLocalSecretVault } from '../../../types/api';
import { EncryptionError, EncryptionErrorCode } from '../../../types/errors';
import type { SqliteDriver } from './driver';
import { isPlaintextSqliteDatabase, type SqliteOpenOptions } from './encryption';
import { SqliteKeyMismatchError } from './errors';
import type { SqliteRootExecutor } from './executor';
import { openMigratedSqliteDatabase } from './migrations';

/** SQLCipher raw key size. */
const DATABASE_KEY_SIZE = 32;

/** A name that is safe as a file name and as a vault slot on every platform. */
const STORE_NAME = /^[A-Za-z0-9._-]+$/;

/** The options of {@link openSqliteStore} and {@link resetSqliteStore}. */
export interface SqliteStoreOpenOptions extends SqliteOpenOptions {
  readonly driver: SqliteDriver;
  /**
   * The database name. The driver maps it to a file and to the identity that
   * names the vault slot of the key. Letters, digits, `.`, `_`, and `-` only.
   */
  readonly name: string;
  /** The vault that holds the database key. */
  readonly vault: SignalProtocolLocalSecretVault;
}

/**
 * The vault slot that holds the key of the database `identity`, the value of
 * `driver.identify(name)`.
 */
export function sqliteDatabaseKeySlot(identity: string): string {
  return `signal_protocol_sqlite_key.${identity}`;
}

/**
 * Reject a name that is not safe as a file name on every platform, with the
 * error of {@link openSqliteStore}.
 */
export function assertSqliteStoreName(name: string, operation: 'open' | 'reset'): void {
  if (STORE_NAME.test(name)) return;
  throw new EncryptionError(
    `The SQLite store name ${JSON.stringify(name)} may contain only letters, digits, ` +
      '".", "_", and "-".',
    EncryptionErrorCode.INVALID_STATE,
    { operation }
  );
}

/** The tail of the queued opens and resets of each database identity. */
const pending = new Map<string, Promise<unknown>>();

/** The database identities that have an open store in this process. */
const held = new Set<string>();

/**
 * Open the database of the store `name`. The open applies the SDK
 * migrations. On an encrypted store, the key comes from the vault. The key,
 * then the file, are created only when the file does not exist.
 *
 * `close()` on the result closes the database and releases the name.
 *
 * @throws EncryptionError with `INVALID_STATE` when the name is not valid or
 *   its database already has an open store in this process, or when a newer
 *   SDK wrote the file.
 * @throws EncryptionError with `LOCAL_STORE_KEY_LOST` when the file exists
 *   and the vault holds no key for it.
 * @throws EncryptionError with `KEY_STORAGE_ERROR` when the vault fails or
 *   holds a key of the wrong size, or when the file was created with the
 *   other `encryptionAtRest` setting (`SqliteKeyMismatchError`).
 */
export function openSqliteStore(options: SqliteStoreOpenOptions): Promise<SqliteRootExecutor> {
  return oneAtATime(options, 'open', async () => {
    const { driver, name, vault } = options;
    if (options.encryptionAtRest === false) {
      return openMigratedSqliteDatabase(driver, name, null, options);
    }
    const slot = sqliteDatabaseKeySlot(driver.identify(name));
    const storedKey = await readDatabaseKey(vault, slot);
    if (storedKey) return openMigratedSqliteDatabase(driver, name, storedKey, options);

    if (await driver.exists(name)) {
      if (await isPlaintextSqliteDatabase(driver, name)) {
        throw new SqliteKeyMismatchError(driver.name);
      }
      throw new EncryptionError(
        `The ${driver.name} database ${name} exists, but the secret vault holds no key for it. ` +
          'Restore the vault entry, or reset the store to delete the database.',
        EncryptionErrorCode.LOCAL_STORE_KEY_LOST,
        { operation: 'open' }
      );
    }
    return openMigratedSqliteDatabase(driver, name, await replaceDatabaseKey(vault, slot), options);
  });
}

/**
 * Delete the database of the store `name`, then create a new key, then open a
 * new, empty database.
 *
 * The order is the crash contract. A process that stops after the deletion
 * and before the vault write leaves no file and the old key or none, and
 * {@link openSqliteStore} opens that state as a new store. The other order
 * would leave the old file under a key that no longer exists.
 *
 * @throws EncryptionError with `INVALID_STATE` when the name is not valid or
 *   its database already has an open store in this process.
 */
export function resetSqliteStore(options: SqliteStoreOpenOptions): Promise<SqliteRootExecutor> {
  return oneAtATime(options, 'reset', async () => {
    const { driver, name, vault } = options;
    await driver.remove(name);
    const key =
      options.encryptionAtRest === false
        ? null
        : await replaceDatabaseKey(vault, sqliteDatabaseKeySlot(driver.identify(name)));
    return openMigratedSqliteDatabase(driver, name, key, options);
  });
}

/**
 * Run `task` after every earlier open and reset of the database, and refuse
 * it while the database has an open store. The database stays held until the
 * returned executor closes.
 */
function oneAtATime(
  { driver, name }: SqliteStoreOpenOptions,
  operation: 'open' | 'reset',
  task: () => Promise<SqliteRootExecutor>
): Promise<SqliteRootExecutor> {
  try {
    assertSqliteStoreName(name, operation);
  } catch (error) {
    return Promise.reject(error);
  }
  const identity = driver.identify(name);

  const run = async (): Promise<SqliteRootExecutor> => {
    if (held.has(identity)) {
      throw new EncryptionError(
        `The SQLite store ${name} is already open in this process. Close it first.`,
        EncryptionErrorCode.INVALID_STATE,
        { operation }
      );
    }
    const db = await task();
    held.add(identity);
    let closing: Promise<void> | null = null;
    return {
      ...db,
      close() {
        closing ??= db.close().finally(() => held.delete(identity));
        return closing;
      },
    };
  };

  const result = (pending.get(identity) ?? Promise.resolve()).then(run);
  const tail = result.catch(() => undefined);
  pending.set(identity, tail);
  void tail.then(() => {
    if (pending.get(identity) === tail) pending.delete(identity);
  });
  return result;
}

async function readDatabaseKey(
  vault: SignalProtocolLocalSecretVault,
  slot: string
): Promise<Uint8Array | null> {
  let key: Uint8Array | null;
  try {
    key = await vault.getSecret(slot);
  } catch (error) {
    throw new EncryptionError(
      'Failed to read the database key from the secret vault',
      EncryptionErrorCode.KEY_STORAGE_ERROR,
      { operation: 'open', originalError: error as Error }
    );
  }
  if (key && key.length !== DATABASE_KEY_SIZE) {
    throw new EncryptionError(
      `The secret vault holds a database key of ${key.length} bytes; expected ${DATABASE_KEY_SIZE}`,
      EncryptionErrorCode.KEY_STORAGE_ERROR,
      { operation: 'open' }
    );
  }
  return key;
}

/** Create a new database key and write it to the vault, over any old key. */
async function replaceDatabaseKey(
  vault: SignalProtocolLocalSecretVault,
  slot: string
): Promise<Uint8Array> {
  const key = await generateRandomBytes(DATABASE_KEY_SIZE);
  try {
    await vault.setSecret(slot, key);
  } catch (error) {
    throw new EncryptionError(
      'Failed to write the database key to the secret vault',
      EncryptionErrorCode.KEY_STORAGE_ERROR,
      { operation: 'open', originalError: error as Error }
    );
  }
  return key;
}
