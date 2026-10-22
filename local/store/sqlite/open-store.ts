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
 * With `convertPlaintext: true`, an encrypted open converts a plaintext file
 * and keeps its data. The driver seam has no rename, so the conversion copies
 * twice: the plaintext file to a temporary encrypted file, then that file back
 * to the store name. A pending vault slot holds the new key until the copy
 * back is complete. Removing the plaintext file is the commit point. Before
 * it, a failed conversion leaves the plaintext file, and the next conversion
 * starts again with a new key. After it, the next encrypted open finishes the
 * conversion, with or without the option.
 *
 * In one process, the open and the reset of a database run one at a time, and
 * a database has at most one open store. Two first opens therefore cannot write
 * two different keys, and a reset or the driver's `exists` never runs on a
 * file under a live connection. This does not cover other processes: an
 * entry whose files other processes can open holds its own cross-process lock
 * over each call.
 */

import { generateRandomBytes } from '../../../internal/crypto/random';
import type { LocalStoreProtection, SignalProtocolLocalSecretVault } from '../../../types/api';
import { EncryptionError, EncryptionErrorCode } from '../../../types/errors';
import type { SqliteDriver } from './driver';
import { secretVaultCustody } from '../../vault/custody';
import {
  SQLITE_CONVERT_SUFFIX,
  copySqliteDatabase,
  openSqliteConversionSource,
  readSqliteUserVersion,
  sqliteConvertTempName,
} from './convert-plaintext';
import { openSqliteDatabase } from './database';
import { isPlaintextSqliteDatabase, readSqliteAtRest, type SqliteOpenOptions } from './encryption';
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
  /**
   * Take the lock that a conversion needs, and return the function that
   * releases it. The open calls it before a conversion or its recovery
   * changes a file or a vault slot, and releases the lock before it returns.
   * Default: no lock beyond the one-at-a-time open.
   */
  readonly lockConversion?: () => Promise<() => void>;
}

/**
 * The vault slot that holds the key of the database `identity`, the value of
 * `driver.identify(name)`.
 */
export function sqliteDatabaseKeySlot(identity: string): string {
  return `signal_protocol_sqlite_key.${identity}`;
}

/**
 * The vault slot that holds the new key of the database `identity` while a
 * conversion of it is incomplete. The prefix differs from the main slot.
 */
function sqlitePendingKeySlot(identity: string): string {
  return `signal_protocol_sqlite_pending_key.${identity}`;
}

/**
 * Reject a name that is not safe as a file name on every platform, or that
 * names the temporary file of a conversion, with the error of
 * {@link openSqliteStore}.
 */
export function assertSqliteStoreName(name: string, operation: 'open' | 'reset'): void {
  if (!STORE_NAME.test(name)) {
    throw new EncryptionError(
      `The SQLite store name ${JSON.stringify(name)} may contain only letters, digits, ` +
        '".", "_", and "-".',
      EncryptionErrorCode.INVALID_STATE,
      { operation }
    );
  }
  if (name.endsWith(SQLITE_CONVERT_SUFFIX)) {
    throw new EncryptionError(
      `The SQLite store name ${JSON.stringify(name)} ends in ${SQLITE_CONVERT_SUFFIX}. ` +
        'The conversion to encryption uses that ending for its temporary file.',
      EncryptionErrorCode.INVALID_STATE,
      { operation }
    );
  }
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
 * With `convertPlaintext: true`, an encrypted open of a plaintext file
 * converts it. The store keeps every row and its schema version. An
 * encrypted open also finishes a conversion that stopped after its commit
 * point, with or without the option.
 *
 * `close()` on the result closes the database and releases the name.
 *
 * @throws EncryptionError with `INVALID_STATE` when the name is not valid or
 *   its database already has an open store in this process, or when a newer
 *   SDK wrote the file. Also when `convertPlaintext` comes with
 *   `encryptionAtRest: false`, when an open with `encryptionAtRest: false`
 *   finds an incomplete conversion, or when a plaintext file cannot be
 *   converted.
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
      await refuseIncompleteConversion(driver, name, 'open');
      return openMigratedSqliteDatabase(driver, name, null, options);
    }
    const slot = sqliteDatabaseKeySlot(driver.identify(name));
    const storedKey = await readDatabaseKey(vault, slot);
    if (storedKey) return openMigratedSqliteDatabase(driver, name, storedKey, options);
    return openWithoutMainKey(options, slot);
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
 * An encrypted reset also ends an incomplete conversion. It deletes the
 * pending key first, then the temporary file, then the database. A process
 * that stops after the key deletion cannot finish the conversion of the old
 * data.
 *
 * @throws EncryptionError with `INVALID_STATE` when the name is not valid or
 *   its database already has an open store in this process. Also when
 *   `convertPlaintext` comes with `encryptionAtRest: false`, or when a reset
 *   with `encryptionAtRest: false` finds an incomplete conversion.
 */
export function resetSqliteStore(options: SqliteStoreOpenOptions): Promise<SqliteRootExecutor> {
  return oneAtATime(options, 'reset', async () => {
    const { driver, name, vault } = options;
    if (options.encryptionAtRest === false) {
      await refuseIncompleteConversion(driver, name, 'reset');
      await driver.remove(name);
      return openMigratedSqliteDatabase(driver, name, null, options);
    }
    const identity = driver.identify(name);
    await deleteDatabaseKey(vault, sqlitePendingKeySlot(identity));
    const temp = sqliteConvertTempName(name);
    if (await tempExists(driver, temp)) await driver.remove(temp);
    await driver.remove(name);
    const key = await replaceDatabaseKey(vault, sqliteDatabaseKeySlot(identity));
    return openMigratedSqliteDatabase(driver, name, key, options);
  });
}

/**
 * The open of an encrypted store whose main slot holds no key. It creates a
 * new store, converts a plaintext file, or finishes a conversion. Each state
 * that a conversion can leave has one action.
 *
 * - The file is plaintext: convert it with the option, else report the
 *   setting mismatch.
 * - The file is encrypted and the pending key opens it: the copy back ran.
 *   Copy back again when it did not commit, then finish.
 * - Any other existing file: the key is lost.
 * - No file, a pending key, and a complete temporary file: the plaintext
 *   file was removed. Copy back, then finish.
 * - No file and no pending key, with a temporary file: refuse. Its key is
 *   not in this vault.
 * - No file and no pending key: a new store.
 * - No file, a pending key, and no complete temporary file: no data exists,
 *   so discard both and create a new store.
 *
 * The first read of the state takes no lock. Before the first write of a
 * conversion or its recovery, the open takes the conversion lock and reads
 * the state again.
 */
async function openWithoutMainKey(
  options: SqliteStoreOpenOptions,
  slot: string,
  locked = false
): Promise<SqliteRootExecutor> {
  const { driver, name, vault } = options;
  const pendingSlot = sqlitePendingKeySlot(driver.identify(name));
  const temp = sqliteConvertTempName(name);
  const relock = () =>
    withConversionLock(options, async () => {
      const storedKey = await readDatabaseKey(vault, slot);
      if (storedKey) return openMigratedSqliteDatabase(driver, name, storedKey, options);
      return openWithoutMainKey(options, slot, true);
    });

  if (await driver.exists(name)) {
    if (await isPlaintextSqliteDatabase(driver, name)) {
      await refuseCompleteCopy(options, pendingSlot);
      if (!options.convertPlaintext) throw new SqliteKeyMismatchError(driver.name);
      if (!locked) return relock();
      const key = await convertPlaintextFile(options, pendingSlot);
      return finish(options, slot, pendingSlot, key);
    }
    const pendingKey = await readDatabaseKey(vault, pendingSlot);
    const version = pendingKey && (await readSqliteUserVersion(driver, name, pendingKey));
    if (!pendingKey || version === null) {
      throw new EncryptionError(
        `The ${driver.name} database ${name} exists, but the secret vault holds no key for it. ` +
          'Restore the vault entry, or reset the store to delete the database.',
        EncryptionErrorCode.LOCAL_STORE_KEY_LOST,
        { operation: 'open' }
      );
    }
    if (!locked) return relock();
    if (version > 0) return finish(options, slot, pendingSlot, pendingKey);
    // The copy back did not commit, so the file holds no rows. The
    // temporary file still holds them.
    await driver.remove(name);
  }

  const pendingKey = await readDatabaseKey(vault, pendingSlot);
  const tempPresent = await tempExists(driver, temp);
  if (!pendingKey) {
    if (tempPresent) {
      throw new EncryptionError(
        `The temporary file ${temp} of a conversion to encryption exists without its database ` +
          `${name}, and the secret vault holds no key for it. The store did not change it. ` +
          'Restore the vault entry, or reset the store to delete all data.',
        EncryptionErrorCode.INVALID_STATE,
        { operation: 'open' }
      );
    }
    return openMigratedSqliteDatabase(driver, name, await replaceDatabaseKey(vault, slot), options);
  }
  if (!locked) return relock();
  if (tempPresent && ((await readSqliteUserVersion(driver, temp, pendingKey)) ?? 0) > 0) {
    return finish(options, slot, pendingSlot, pendingKey);
  }
  // No step of a conversion leaves a pending key without the database and
  // without a complete temporary file. Nothing holds data, so start anew.
  await deleteDatabaseKey(vault, pendingSlot);
  if (tempPresent) await driver.remove(temp);
  const key = await replaceDatabaseKey(vault, slot);
  return openMigratedSqliteDatabase(driver, name, key, options);
}

/**
 * Refuse to convert a plaintext file when a complete encrypted copy of a
 * conversion exists beside it. This SDK removes the plaintext file right
 * after the copy commits. An older SDK can create a new, empty plaintext
 * file after that removal. The open does not choose between the two files.
 */
async function refuseCompleteCopy(
  { driver, name, vault }: SqliteStoreOpenOptions,
  pendingSlot: string
): Promise<void> {
  const pendingKey = await readDatabaseKey(vault, pendingSlot);
  if (!pendingKey) return;
  const temp = sqliteConvertTempName(name);
  if (!(await tempExists(driver, temp))) return;
  if (((await readSqliteUserVersion(driver, temp, pendingKey)) ?? 0) === 0) return;
  throw new EncryptionError(
    `The plaintext database ${name} and the complete encrypted copy ${temp} of a conversion ` +
      `both exist, so the store did not open. Remove ${name} to finish the conversion from ` +
      'the copy, or reset the store to delete all data.',
    EncryptionErrorCode.INVALID_STATE,
    { operation: 'open' }
  );
}

/**
 * Convert the plaintext file of the store to an encrypted temporary file, and
 * remove the plaintext file. Return the pending key, which encrypts the
 * temporary file. The removal is the commit point. The caller holds the
 * conversion lock.
 */
async function convertPlaintextFile(
  options: SqliteStoreOpenOptions,
  pendingSlot: string
): Promise<Uint8Array> {
  const { driver, name, vault } = options;
  const temp = sqliteConvertTempName(name);
  let source: SqliteRootExecutor | null = await openSqliteConversionSource(driver, name);
  let committed = false;
  try {
    const tempPresent = await tempExistsForConversion(driver, temp);
    // A conversion that stopped before its commit point leaves its key and
    // its temporary file. Discard both, and start again with a new key.
    await deleteDatabaseKey(vault, pendingSlot);
    const pendingKey = await replaceDatabaseKey(vault, pendingSlot);
    if (tempPresent) await driver.remove(temp);
    const target = await openSqliteDatabase(driver, temp, pendingKey, options);
    try {
      await copySqliteDatabase(source, target);
    } finally {
      await target.close();
    }
    const closing = source;
    source = null;
    await closing.close();
    await driver.remove(name);
    committed = true;
    return pendingKey;
  } catch (error) {
    // The conversion error is the one to report. A failed close adds nothing.
    await source?.close().catch(() => undefined);
    if (!committed) await discardConversion(options, pendingSlot);
    throw error;
  }
}

/**
 * Copy the complete temporary file back to the store name, under the
 * pending key that encrypts both.
 */
async function copyBack(options: SqliteStoreOpenOptions, pendingKey: Uint8Array): Promise<void> {
  const { driver, name } = options;
  const source = await openSqliteDatabase(driver, sqliteConvertTempName(name), pendingKey, options);
  try {
    const target = await openSqliteDatabase(driver, name, pendingKey, options);
    try {
      await copySqliteDatabase(source, target);
    } finally {
      await target.close();
    }
  } finally {
    await source.close();
  }
}

/**
 * Finish a conversion whose copy back committed: remove the temporary file,
 * move the pending key to the main slot, and open the store.
 */
async function finish(
  options: SqliteStoreOpenOptions,
  slot: string,
  pendingSlot: string,
  key: Uint8Array
): Promise<SqliteRootExecutor> {
  const { driver, name, vault } = options;
  if (!(await driver.exists(name))) await copyBack(options, key);
  const temp = sqliteConvertTempName(name);
  if (await tempExists(driver, temp)) await driver.remove(temp);
  // The vault has no atomic move. A stop between the two writes leaves the
  // same key in both slots. The open ignores the pending slot then, and a
  // reset deletes it.
  await writeDatabaseKey(vault, slot, key);
  await deleteDatabaseKey(vault, pendingSlot);
  return openMigratedSqliteDatabase(driver, name, key, options);
}

/**
 * Undo a conversion that failed before its commit point: remove the
 * temporary file, then delete the pending key. A failure here leaves a state
 * that the next conversion discards.
 */
async function discardConversion(
  { driver, name, vault }: SqliteStoreOpenOptions,
  pendingSlot: string
): Promise<void> {
  try {
    const temp = sqliteConvertTempName(name);
    if (await tempExists(driver, temp)) await driver.remove(temp);
    await vault.deleteSecret(pendingSlot);
  } catch {
    // The conversion error is the one to report.
  }
}

/** Run `task` while the entry holds the lock that a conversion needs. */
async function withConversionLock<T>(
  options: SqliteStoreOpenOptions,
  task: () => Promise<T>
): Promise<T> {
  const release = options.lockConversion ? await options.lockConversion() : undefined;
  try {
    return await task();
  } finally {
    release?.();
  }
}

/**
 * Refuse an open or a reset with `encryptionAtRest: false` while a
 * conversion to encryption is incomplete. Such an open would create a new
 * plaintext file, and such a reset would leave the encrypted copy.
 */
async function refuseIncompleteConversion(
  driver: SqliteDriver,
  name: string,
  operation: 'open' | 'reset'
): Promise<void> {
  const temp = sqliteConvertTempName(name);
  if (!(await tempExists(driver, temp))) return;
  throw new EncryptionError(
    `The SQLite store ${name} has an incomplete conversion to encryption: its temporary file ` +
      `${temp} exists. Open the store with encryption to finish the conversion, or reset it ` +
      'with encryption to delete all data.',
    EncryptionErrorCode.INVALID_STATE,
    { operation }
  );
}

/**
 * Report whether the temporary file of a conversion exists. A driver that
 * refuses the name, such as the web driver for a name that is too long, has
 * no such file.
 */
async function tempExists(driver: SqliteDriver, temp: string): Promise<boolean> {
  try {
    return await driver.exists(temp);
  } catch (error) {
    if (isInvalidState(error)) return false;
    throw error;
  }
}

/**
 * Report whether the temporary file of a conversion exists, and refuse a
 * conversion on a driver that does not accept its name. The check runs
 * before the first write.
 */
async function tempExistsForConversion(driver: SqliteDriver, temp: string): Promise<boolean> {
  try {
    return await driver.exists(temp);
  } catch (error) {
    if (!isInvalidState(error)) throw error;
    throw new EncryptionError(
      `The ${driver.name} driver does not accept the name ${temp} of the temporary file of a ` +
        'conversion. Use a shorter store name.',
      EncryptionErrorCode.INVALID_STATE,
      { operation: 'open', originalError: error as Error }
    );
  }
}

function isInvalidState(error: unknown): boolean {
  return error instanceof EncryptionError && error.code === EncryptionErrorCode.INVALID_STATE;
}

/**
 * Read the protection of a database that {@link openSqliteStore} or
 * {@link resetSqliteStore} opened: the encryption that the database records,
 * and the custody of the vault that holds its key. A database without
 * encryption has no key. On a failure, it closes the database before it
 * throws.
 */
export async function readSqliteStoreProtection(
  db: SqliteRootExecutor,
  vault: SignalProtocolLocalSecretVault
): Promise<LocalStoreProtection> {
  try {
    const atRest = await readSqliteAtRest(db);
    return { atRest, keyCustody: atRest === 'none' ? 'none' : secretVaultCustody(vault) };
  } catch (error) {
    // The read error is the one to report. A failed close adds nothing.
    await db.close().catch(() => undefined);
    throw error;
  }
}

/**
 * Run `task` after every earlier open and reset of the database, and refuse
 * it while the database has an open store. The database stays held until the
 * returned executor closes.
 */
function oneAtATime(
  { driver, name, encryptionAtRest, convertPlaintext }: SqliteStoreOpenOptions,
  operation: 'open' | 'reset',
  task: () => Promise<SqliteRootExecutor>
): Promise<SqliteRootExecutor> {
  try {
    assertSqliteStoreName(name, operation);
    if (convertPlaintext === true && encryptionAtRest === false) {
      throw new EncryptionError(
        'convertPlaintext converts a plaintext SQLite store to an encrypted one, so it does ' +
          'not apply with encryptionAtRest: false.',
        EncryptionErrorCode.INVALID_STATE,
        { operation }
      );
    }
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
  await writeDatabaseKey(vault, slot, key);
  return key;
}

async function writeDatabaseKey(
  vault: SignalProtocolLocalSecretVault,
  slot: string,
  key: Uint8Array
): Promise<void> {
  try {
    await vault.setSecret(slot, key);
  } catch (error) {
    throw new EncryptionError(
      'Failed to write the database key to the secret vault',
      EncryptionErrorCode.KEY_STORAGE_ERROR,
      { operation: 'open', originalError: error as Error }
    );
  }
}

async function deleteDatabaseKey(
  vault: SignalProtocolLocalSecretVault,
  slot: string
): Promise<void> {
  try {
    await vault.deleteSecret(slot);
  } catch (error) {
    throw new EncryptionError(
      'Failed to delete a database key from the secret vault',
      EncryptionErrorCode.KEY_STORAGE_ERROR,
      { operation: 'open', originalError: error as Error }
    );
  }
}
