import { mkdirSync, realpathSync } from 'node:fs';
import { access, rm } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { bytesToHex } from '../../../encoding/hex';
import type {
  SqliteConnection,
  SqliteDriver,
  SqliteRow,
  SqliteStatementResult,
  SqliteValue,
} from './driver';
import { classifySqliteError, SqliteStoreInUseError } from './errors';

const require = createRequire(import.meta.url);
const BINDING = 'better-sqlite3-multiple-ciphers';
const KEY_BYTES = 32;

/**
 * The part of the binding that the driver uses. A local structural type keeps
 * the package out of the type graph: it is not installed where the driver is
 * built without it.
 */
interface Statement {
  readonly reader: boolean;
  all(...params: SqliteValue[]): unknown[];
  get(...params: SqliteValue[]): unknown;
  run(...params: SqliteValue[]): { changes: number };
}

interface Database {
  prepare(sql: string): Statement;
  pragma(source: string, options: { simple: true }): unknown;
  exec(sql: string): unknown;
  close(): unknown;
}

type DatabaseConstructor = new (file: string, options: { timeout: number }) => Database;

function loadBinding(): DatabaseConstructor {
  try {
    return require(BINDING) as DatabaseConstructor;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'MODULE_NOT_FOUND') throw error;
    throw new Error(
      `The Node SQLite driver requires ${BINDING} 13.0.3 or later. Install it before opening the store.`,
      { cause: error }
    );
  }
}

function toValue(column: string, value: unknown): SqliteValue {
  if (value === null || typeof value === 'string' || typeof value === 'number') return value;
  if (typeof value === 'bigint' || typeof value === 'boolean') return Number(value);
  throw new TypeError(`SQLite column ${column} returned a value that is not TEXT, INTEGER, or NULL.`);
}

function toRow(row: unknown): SqliteRow {
  const values: Record<string, SqliteValue> = {};
  for (const [column, value] of Object.entries(row as Record<string, unknown>)) {
    values[column] = toValue(column, value);
  }
  return values;
}

class BetterSqlite3MultipleCiphersConnection implements SqliteConnection {
  /**
   * The strong reference keeps the connection alive. The binding closes a
   * collected `Database` and rolls back its open transaction with no error,
   * which also drops the owner lock.
   */
  readonly #database: Database;

  constructor(database: Database) {
    this.#database = database;
  }

  async execute(
    sql: string,
    params: readonly SqliteValue[] = []
  ): Promise<SqliteStatementResult> {
    const statement = this.#database.prepare(sql);
    if (!statement.reader) {
      return { rows: [], changes: statement.run(...params).changes };
    }
    const rows = statement.all(...params).map(toRow);
    // A statement with RETURNING is a reader too. sqlite3_changes() counts
    // its rows once the statement has run to completion.
    const { changes } = this.#database.prepare('SELECT changes() AS changes').get() as {
      changes: number;
    };
    return { rows, changes };
  }

  /**
   * `PRAGMA cipher` also answers on an unkeyed plaintext database, so it
   * proves only that the binding has a cipher. The cipher salt is NULL unless
   * the database is encrypted.
   */
  async probeCipher(): Promise<string | null> {
    const { salt } = this.#database
      .prepare("SELECT sqlite3mc_codec_data('cipher_salt') AS salt")
      .get() as { salt: unknown };
    if (salt === null) return null;
    return this.#database.pragma('cipher', { simple: true }) as string;
  }

  async close(): Promise<void> {
    this.#database.close();
  }
}

function applyKey(database: Database, key: Uint8Array): void {
  if (key.length !== KEY_BYTES) {
    throw new Error(`The SQLCipher raw key must be ${KEY_BYTES} bytes.`);
  }
  database.pragma("cipher='sqlcipher'", { simple: true });
  database.pragma('legacy=4', { simple: true });
  try {
    database.pragma(`key="x'${bytesToHex(key)}'"`, { simple: true });
  } catch (error) {
    // The binding error can carry statement text, so none of it is kept.
    const code = (error as { code?: unknown }).code;
    throw new Error(`SQLite rejected the database key (${String(code)}).`);
  }
}

/**
 * Open the file on one connection that owns it until `close`.
 *
 * `locking_mode=EXCLUSIVE` is the one setting between the key and the
 * verifying read, for two reasons. First, it makes that read take the file
 * lock and keep it. That lock is the cross-process owner lock: another
 * connection, in this process or another, fails at its own first read with
 * `database is locked`, and the operating system drops the lock when the owner
 * process dies. Second, SQLite must not create the `-shm` file before it opens
 * the WAL of an owner that was killed. With the mode set before the first WAL
 * access, SQLite never creates the `-shm` file. The busy timeout is 0, so a
 * second owner fails at once.
 *
 * A wrong key, a missing key on an encrypted file, and a key on a plaintext
 * file all pass `PRAGMA key` and fail at the first read with `file is not a
 * database`. The verifying read therefore runs inside `open`.
 *
 * `synchronous=FULL` syncs the WAL at each commit. With `NORMAL`, the binding
 * default in WAL mode, a power loss can roll back ratchet or prekey state.
 */
function openDatabase(Binding: DatabaseConstructor, file: string, key: Uint8Array | null): Database {
  const database = new Binding(file, { timeout: 0 });
  try {
    if (key !== null) applyKey(database, key);
    database.pragma('locking_mode=EXCLUSIVE', { simple: true });
    database.prepare('SELECT count(*) FROM sqlite_master').get();
    const journalMode = database.pragma('journal_mode=WAL', { simple: true });
    if (journalMode !== 'wal') {
      throw new Error(`SQLite kept journal mode ${String(journalMode)} instead of wal.`);
    }
    database.pragma('synchronous=FULL', { simple: true });
    return database;
  } catch (error) {
    database.close();
    throw new Error(
      `${BINDING} could not open the database: ${(error as Error).message}`,
      { cause: error }
    );
  }
}

export interface BetterSqlite3MultipleCiphersDriverOptions {
  /**
   * The directory that holds the database files. The driver creates it when
   * the driver is created, readable only by the owner, and keeps its real
   * path. A relative path resolves against the working directory.
   */
  readonly directory: string;
}

/** The owner lock of one database, held until `release`. */
export interface SqliteOwnerLock {
  release(): void;
}

export interface BetterSqlite3MultipleCiphersDriver extends SqliteDriver {
  /**
   * Take the owner lock of `file`: an exclusive lock on `<file>.lock` in the
   * driver's directory, on a connection of its own. The operating system drops
   * the lock when the process dies. `remove` never deletes the lock file.
   *
   * @throws SqliteStoreInUseError when another connection, in this process or
   *   another, holds the lock.
   */
  lock(file: string): Promise<SqliteOwnerLock>;
}

/**
 * The `SqliteDriver` for Node and the Electron main process, over
 * `better-sqlite3-multiple-ciphers`.
 *
 * A file is a name in the driver's directory. The core validates the name
 * before it reaches the driver. The identity of a file is its path under the
 * real path of the directory, so a symbolic link to the directory reaches the
 * same identity. A keyed file is in the SQLCipher 4 format
 * (`cipher='sqlcipher'`, `legacy=4`, raw key `x'<64 hex>'`), which the
 * SQLCipher CLI opens. The binding is synchronous, so each call runs on the
 * calling thread and settles its promise when the statement finishes.
 */
export function createBetterSqlite3MultipleCiphersDriver({
  directory,
}: BetterSqlite3MultipleCiphersDriverOptions): BetterSqlite3MultipleCiphersDriver {
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const root = realpathSync.native(directory);
  const path = (file: string) => join(root, file);

  return {
    name: BINDING,

    identify: path,

    async exists(file) {
      try {
        await access(path(file));
        return true;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false;
        throw error;
      }
    },

    async open(file, key) {
      const Binding = loadBinding();
      return new BetterSqlite3MultipleCiphersConnection(openDatabase(Binding, path(file), key));
    },

    async remove(file) {
      // The sidecars go first, so an interrupted remove never leaves an old
      // journal or WAL for a new database with the same name to find.
      for (const suffix of ['-wal', '-shm', '-journal']) {
        await rm(path(`${file}${suffix}`), { force: true });
      }
      await rm(path(file), { force: true });
    },

    async lock(file) {
      const Binding = loadBinding();
      const database = new Binding(path(`${file}.lock`), { timeout: 0 });
      try {
        // In exclusive locking mode, the connection keeps the lock of its
        // first write transaction until it closes.
        database.pragma('locking_mode=EXCLUSIVE', { simple: true });
        database.exec('BEGIN EXCLUSIVE');
        database.exec('COMMIT');
      } catch (error) {
        database.close();
        if (classifySqliteError(error) === 'busy') throw new SqliteStoreInUseError(BINDING, error);
        throw error;
      }
      let released = false;
      return {
        release() {
          if (released) return;
          released = true;
          database.close();
        },
      };
    },
  };
}
