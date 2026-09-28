/**
 * The owner lock of a Node store: one process at a time owns a database.
 *
 * The core runs the opens and resets of a database one at a time, but only in
 * one process. Two processes that open a new store at the same time both find
 * no key, and each writes its own key: the vault then keeps a key that does
 * not open the file. A reset in one process also deletes the live file of
 * another. So each open and reset first takes the driver's owner lock of the
 * database, and an open store holds it until it closes. A second process
 * fails at once, before it reads the vault or touches the file.
 *
 * In the process that owns the database, the core's own refusal stays the
 * answer: a second open or reset of an open store fails with the core's
 * `INVALID_STATE`, not with an in-use error.
 */

import { EncryptionError, EncryptionErrorCode } from '../../../types/errors';
import type {
  BetterSqlite3MultipleCiphersDriver,
  SqliteOwnerLock,
} from '../sqlite/better-sqlite3-multiple-ciphers-driver';
import type { SqliteRootExecutor } from '../sqlite/executor';
import { assertSqliteStoreName } from '../sqlite/open-store';

/**
 * Name endings that the driver uses for the files beside a database. A store
 * with such a name would share a file with the store of the shorter name, and
 * its reset would delete that file.
 */
const RESERVED_SUFFIXES = ['.lock', '-wal', '-shm', '-journal'];

/** The tail of the queued opens, resets, and closes of each database identity. */
const pending = new Map<string, Promise<unknown>>();

/** The owner lock of each database that an open store of this process holds. */
const owned = new Map<string, SqliteOwnerLock>();

/**
 * Run `open` with the owner lock of the database `name`, and keep the lock
 * until the returned executor closes. Release it when `open` fails.
 *
 * @throws EncryptionError with `INVALID_STATE` when the name is not valid.
 * @throws SqliteStoreInUseError when another process owns the database.
 */
export function withOwnerLock(
  driver: BetterSqlite3MultipleCiphersDriver,
  name: string,
  operation: 'open' | 'reset',
  open: () => Promise<SqliteRootExecutor>
): Promise<SqliteRootExecutor> {
  try {
    assertSqliteStoreName(name, operation);
    assertNotReserved(name, operation);
  } catch (error) {
    return Promise.reject(error);
  }
  const identity = driver.identify(name);

  return oneAtATime(identity, async () => {
    // This process owns the database, so the core refuses the call.
    if (owned.has(identity)) return open();

    const lock = await driver.lock(name);
    let db: SqliteRootExecutor;
    try {
      db = await open();
    } catch (error) {
      lock.release();
      throw error;
    }
    owned.set(identity, lock);
    let closing: Promise<void> | null = null;
    return {
      ...db,
      close() {
        closing ??= oneAtATime(identity, () =>
          db.close().finally(() => {
            owned.delete(identity);
            lock.release();
          })
        );
        return closing;
      },
    };
  });
}

function assertNotReserved(name: string, operation: 'open' | 'reset'): void {
  const suffix = RESERVED_SUFFIXES.find((ending) => name.endsWith(ending));
  if (!suffix) return;
  throw new EncryptionError(
    `The SQLite store name ${JSON.stringify(name)} must not end with ${JSON.stringify(suffix)}.`,
    EncryptionErrorCode.INVALID_STATE,
    { operation }
  );
}

/** Run `task` after every earlier queued call for `identity`. */
function oneAtATime<T>(identity: string, task: () => Promise<T>): Promise<T> {
  const result = (pending.get(identity) ?? Promise.resolve()).then(task);
  const tail = result.catch(() => undefined);
  pending.set(identity, tail);
  void tail.then(() => {
    if (pending.get(identity) === tail) pending.delete(identity);
  });
  return result;
}
