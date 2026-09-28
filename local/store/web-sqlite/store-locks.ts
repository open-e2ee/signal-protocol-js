/**
 * The Web Locks that order the stores of one name across the tabs and
 * workers of an origin.
 *
 * The open lock. A first open reads the vault, finds no key, checks that the
 * file does not exist, writes a new key, and creates the file. Two tabs that
 * run this sequence at the same time both find no key, and each writes its
 * own key. The key that the vault keeps can then differ from the key that
 * created the file, and the store cannot open that file again. So the entry
 * holds one lock for each store name over the whole open or reset, and the
 * next tab finds the key that the first tab wrote.
 *
 * The store lock. Each open store holds it in shared mode until it closes. A
 * reset takes it in exclusive mode, and fails at once when a store of the
 * name is open in any context. So a reset never deletes a file that another
 * tab still uses. The reset runs inside the open lock, so no open can take
 * the store lock between the reset and the new store.
 *
 * Both names differ from the name of the driver's file lock, which the
 * driver's worker takes inside each call. The tabs share the file of an open
 * store through the driver.
 */

import { EncryptionError, EncryptionErrorCode } from '../../../types/errors';

function assertWebLocks(operation: string): void {
  if (typeof navigator.locks?.request !== 'function') {
    throw new EncryptionError(
      'This browser context cannot keep a SQLite database in the origin private file system: missing Web Locks',
      EncryptionErrorCode.OPFS_UNAVAILABLE,
      { operation }
    );
  }
}

/** Run `run` while this context holds the open lock of the store `name`. */
export async function withSqliteOpenLock<T>(
  name: string,
  operation: string,
  run: () => Promise<T>
): Promise<T> {
  assertWebLocks(operation);
  return navigator.locks.request(`open-e2ee:sqlite-open:${name}`, run);
}

/**
 * Take the store lock of `name`, and return the function that releases it.
 * Call it only inside the open lock of the same name.
 *
 * @throws EncryptionError with `INVALID_STATE` when `mode` is `exclusive` and
 *   a store of the name is open in any context of the origin.
 */
export async function acquireSqliteStoreLock(
  name: string,
  mode: LockMode,
  operation: string
): Promise<() => void> {
  assertWebLocks(operation);
  let release!: () => void;
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  const granted = await new Promise<boolean>((resolve, reject) => {
    navigator.locks
      .request(
        `open-e2ee:sqlite-store:${name}`,
        { mode, ifAvailable: mode === 'exclusive' },
        (lock) => {
          resolve(lock !== null);
          return lock === null ? undefined : held;
        }
      )
      .catch(reject);
  });
  if (!granted) {
    throw new EncryptionError(
      `The SQLite store ${name} is open in this or another tab or worker. Close it everywhere first.`,
      EncryptionErrorCode.INVALID_STATE,
      { operation }
    );
  }
  return release;
}
