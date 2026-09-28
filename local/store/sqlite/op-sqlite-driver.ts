import { isSQLCipher, open, type DB, type Scalar } from '@op-engineering/op-sqlite';

import { bytesToHex } from '../../../encoding/hex';
import type {
  SqliteConnection,
  SqliteDriver,
  SqliteRow,
  SqliteStatementResult,
  SqliteValue,
} from './driver';
import { SqliteEncryptionUnavailableError } from './errors';

const BINDING = 'op-sqlite';
const KEY_BYTES = 32;

/**
 * SQLite's message for `SQLITE_CANTOPEN`. op-sqlite reports no result code
 * (op-sqlite#462), so the driver reads the message text, as the core does.
 */
const CANT_OPEN = 'unable to open database file';

function messageOf(error: unknown): string {
  const message = (error as { message?: unknown } | null)?.message;
  return typeof message === 'string' ? message : String(error);
}

/**
 * op-sqlite reads every INTEGER as a double, TEXT as a string, and a BLOB as
 * an `ArrayBuffer`. Every SDK column is TEXT or INTEGER.
 */
function toValue(column: string, value: Scalar): SqliteValue {
  if (value === null || typeof value === 'string' || typeof value === 'number') return value;
  if (typeof value === 'boolean') return Number(value);
  throw new TypeError(`SQLite column ${column} returned a value that is not TEXT, INTEGER, or NULL.`);
}

function toRow(row: Record<string, Scalar>): SqliteRow {
  const values: Record<string, SqliteValue> = {};
  for (const [column, value] of Object.entries(row)) {
    values[column] = toValue(column, value);
  }
  return values;
}

class OpSqliteConnection implements SqliteConnection {
  readonly #database: DB;

  constructor(database: DB) {
    this.#database = database;
  }

  /**
   * `execute` is the only statement call. op-sqlite's `transaction` and
   * `executeBatch` queue only against each other, so they would not keep the
   * core's order.
   */
  async execute(
    sql: string,
    params: readonly SqliteValue[] = []
  ): Promise<SqliteStatementResult> {
    const result = await this.#database.execute(sql, [...params]);
    // `rowsAffected` is sqlite3_changes() after the statement ran to
    // completion, so a statement with RETURNING counts its rows too.
    return { rows: result.rows.map(toRow), changes: result.rowsAffected };
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

  /**
   * op-sqlite's `close` interrupts the connection first, so SQLite does not
   * checkpoint at close and the WAL stays. The checkpoint is best effort: the
   * connection always closes, and a failure path keeps its own error.
   */
  async close(): Promise<void> {
    try {
      await this.#database.execute('PRAGMA wal_checkpoint(TRUNCATE)');
    } catch {
      // The WAL stays, and the next open reads it.
    } finally {
      this.#database.close();
    }
  }
}

/** The SQLCipher raw-key form: SQLCipher uses the bytes with no key derivation. */
function rawKey(key: Uint8Array): string {
  if (key.length !== KEY_BYTES) {
    throw new Error(`The SQLCipher raw key must be ${KEY_BYTES} bytes.`);
  }
  // A build without SQLCipher ignores `encryptionKey` and writes plaintext,
  // so the driver refuses the key before `open` creates the file.
  if (!isSQLCipher()) throw new SqliteEncryptionUnavailableError(BINDING);
  return `x'${bytesToHex(key)}'`;
}

/**
 * Open `file` with the op-sqlite `failOnCreate` flag, or return `null` when
 * the file does not exist. SQLite opens the file without reading a page, so
 * this works on a file that the connection has no key for.
 */
function openExisting(file: string): DB | null {
  try {
    return open({ name: file, failOnCreate: true });
  } catch (error) {
    if (messageOf(error).includes(CANT_OPEN)) return null;
    throw error;
  }
}

/**
 * Open the file on one connection that the store keeps until `close`.
 *
 * op-sqlite applies the key with `sqlite3_key_v2` inside `open`, before any
 * statement. SQLCipher accepts a wrong key there, and a wrong key, a missing
 * key on an encrypted file, and a key on a plaintext file all fail at the
 * first read with `file is not a database`. The verifying read therefore runs
 * inside `open`, before any setting that touches the file.
 *
 * `synchronous=FULL` syncs the WAL at each commit. With `NORMAL`, a power loss
 * can roll back ratchet or prekey state.
 */
async function openDatabase(file: string, key: Uint8Array | null): Promise<DB> {
  const options = key === null ? { name: file } : { name: file, encryptionKey: rawKey(key) };
  let database: DB;
  try {
    database = open(options);
  } catch (error) {
    throw new Error(`${BINDING} could not open the database: ${messageOf(error)}`, {
      cause: error,
    });
  }
  try {
    await database.execute('SELECT count(*) FROM sqlite_master');
    const { rows } = await database.execute('PRAGMA journal_mode=WAL');
    const journalMode = rows[0]?.journal_mode;
    if (journalMode !== 'wal') {
      throw new Error(`SQLite kept journal mode ${String(journalMode)} instead of wal.`);
    }
    await database.execute('PRAGMA synchronous=FULL');
    return database;
  } catch (error) {
    database.close();
    throw new Error(`${BINDING} could not open the database: ${messageOf(error)}`, {
      cause: error,
    });
  }
}

/**
 * The `SqliteDriver` for bare React Native, over `@op-engineering/op-sqlite`.
 *
 * `file` is the op-sqlite database name in the op-sqlite default location. A
 * keyed file is in the SQLCipher format of the op-sqlite SQLCipher build, with
 * the raw key `x'<64 hex>'`. Each open makes one op-sqlite connection, and
 * every statement of the store runs on it.
 *
 * op-sqlite has no file API. `exists` and `remove` open each file with
 * `failOnCreate`, and `remove` deletes it with the op-sqlite `delete`.
 */
export function createOpSqliteDriver(): SqliteDriver {
  return {
    name: BINDING,

    // The op-sqlite default location is fixed for the app.
    identify: (file) => file,

    async exists(file) {
      const database = openExisting(file);
      if (database === null) return false;
      database.close();
      return true;
    },

    async open(file, key) {
      return new OpSqliteConnection(await openDatabase(file, key));
    },

    async remove(file) {
      // The sidecars go first, so an interrupted remove never leaves an old
      // journal or WAL for a new database with the same name to find.
      for (const name of [`${file}-wal`, `${file}-shm`, `${file}-journal`, file]) {
        openExisting(name)?.delete();
      }
    },
  };
}
