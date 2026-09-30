/**
 * The `SqliteDriver` for Expo, over expo-sqlite.
 *
 * A file is a database name in the expo-sqlite default directory. A keyed file
 * is in the SQLCipher format of the expo-sqlite SQLCipher build (the
 * `useSQLCipher` config-plugin option), with the raw key `x'<64 hex>'`. Each
 * open is a new connection (`useNewConnection`), so the expo-sqlite
 * connection cache never hands the store's connection to other code.
 *
 * expo-sqlite has no call that reports whether a file exists, and an open
 * creates an empty file. `exists` therefore opens the file without a key and
 * reads it, and deletes the file again when it is empty.
 */

import {
  deleteDatabaseAsync,
  openDatabaseAsync,
  type SQLiteBindValue,
  type SQLiteDatabase,
} from 'expo-sqlite';

import { bytesToHex } from '../../../encoding/hex';
import type {
  SqliteConnection,
  SqliteDriver,
  SqliteRow,
  SqliteStatementResult,
  SqliteValue,
} from '../sqlite/driver';
import { classifySqliteError } from '../sqlite/errors';

const KEY_BYTES = 32;

class ExpoSqliteConnection implements SqliteConnection {
  constructor(private readonly database: SQLiteDatabase) {}

  async execute(
    sql: string,
    params: readonly SqliteValue[] = []
  ): Promise<SqliteStatementResult> {
    const statement = await this.database.prepareAsync(sql);
    try {
      const result = await statement.executeAsync<SqliteRow>(params as SQLiteBindValue[]);
      const rows = await result.getAllAsync();
      return { rows, changes: result.changes };
    } finally {
      await statement.finalizeAsync();
    }
  }

  /**
   * SQLCipher answers `PRAGMA cipher_version` on every connection, with or
   * without a key. `PRAGMA cipher_provider` returns a row only when the
   * connection has a codec, so the probe asks it first.
   */
  async probeCipher(): Promise<string | null> {
    const provider = await this.execute('PRAGMA cipher_provider');
    if (provider.rows.length === 0) return null;
    const { rows } = await this.execute('PRAGMA cipher_version');
    const version = rows[0]?.cipher_version;
    return typeof version === 'string' && version !== '' ? version : null;
  }

  async close(): Promise<void> {
    await this.database.closeAsync();
  }
}

function openConnection(file: string): Promise<SQLiteDatabase> {
  return openDatabaseAsync(file, { useNewConnection: true });
}

/** Delete one file of the default directory, present or not. */
async function deleteFile(name: string): Promise<void> {
  // The delete rejects a missing file with the same error code as a file in
  // use. An open creates the file, so the delete then has a file to remove.
  await (await openConnection(name)).closeAsync();
  await deleteDatabaseAsync(name);
}

async function applyKey(database: SQLiteDatabase, key: Uint8Array): Promise<void> {
  if (key.length !== KEY_BYTES) {
    throw new Error(`The SQLCipher raw key must be ${KEY_BYTES} bytes.`);
  }
  try {
    await database.execAsync(`PRAGMA key = "x'${bytesToHex(key)}'"`);
  } catch {
    // The binding error can carry statement text, so none of it is kept.
    throw new Error('SQLite rejected the database key.');
  }
}

/**
 * Open the file on one connection that owns it until `close`.
 *
 * The settings and their order follow the Node driver:
 * `locking_mode=EXCLUSIVE` before the verifying read makes the read take the
 * owner lock, so a second connection fails at its first read with `database
 * is locked`. Then WAL, and `synchronous=FULL` so that a power loss cannot
 * roll back ratchet or prekey state.
 */
async function openDatabase(file: string, key: Uint8Array | null): Promise<SQLiteDatabase> {
  const database = await openConnection(file);
  try {
    if (key !== null) await applyKey(database, key);
    await database.execAsync('PRAGMA locking_mode = EXCLUSIVE');
    await database.getFirstAsync('SELECT count(*) FROM sqlite_master');
    const mode = await database.getFirstAsync<{ journal_mode: string }>('PRAGMA journal_mode = WAL');
    if (mode?.journal_mode !== 'wal') {
      throw new Error(`SQLite kept journal mode ${String(mode?.journal_mode)} instead of wal.`);
    }
    await database.execAsync('PRAGMA synchronous = FULL');
    return database;
  } catch (error) {
    await database.closeAsync();
    throw error;
  }
}

/**
 * Whether this expo-sqlite build has SQLCipher. SQLCipher answers
 * `PRAGMA cipher_version` on every connection, also on an in-memory database
 * without a key. The web build of expo-sqlite and a native build without the
 * `useSQLCipher` config-plugin option return no row.
 */
export async function expoSqliteHasCipher(): Promise<boolean> {
  const database = await openConnection(':memory:');
  try {
    const row = await database.getFirstAsync<{ cipher_version?: unknown }>('PRAGMA cipher_version');
    return typeof row?.cipher_version === 'string' && row.cipher_version !== '';
  } finally {
    await database.closeAsync();
  }
}

export function createExpoSqliteDriver(): SqliteDriver {
  return {
    name: 'expo-sqlite',

    // The expo-sqlite default directory is fixed for the app.
    identify: (file) => file,

    async exists(file) {
      const database = await openConnection(file);
      let pages: number;
      try {
        const row = await database.getFirstAsync<{ page_count: number }>('PRAGMA page_count');
        pages = row?.page_count ?? 0;
      } catch (error) {
        // An encrypted file cannot be read without its key, and a file that
        // another connection owns is locked. Both exist.
        const kind = classifySqliteError(error);
        if (kind === 'not-a-database' || kind === 'busy') return true;
        throw error;
      } finally {
        await database.closeAsync();
      }
      if (pages > 0) return true;
      await deleteDatabaseAsync(file);
      return false;
    },

    async open(file, key) {
      return new ExpoSqliteConnection(await openDatabase(file, key));
    },

    async remove(file) {
      // The sidecars go first, so an interrupted remove never leaves an old
      // journal or WAL for a new database with the same name to find.
      for (const suffix of ['-wal', '-shm', '-journal']) await deleteFile(`${file}${suffix}`);
      await deleteFile(file);
    },
  };
}
