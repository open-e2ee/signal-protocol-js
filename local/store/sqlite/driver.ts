/**
 * Driver seam for the shared SQLite core.
 *
 * Each platform entry supplies one `SqliteDriver` over its binding. The core
 * owns everything above it: the schema, the migrations, the statement queue,
 * the transactions, the cipher policy, and the key custody. A driver runs
 * statements and nothing else, so each binding has one small code path.
 */

/**
 * A value that SQLite binds or returns. Every SDK column is TEXT or INTEGER,
 * and every SDK integer fits in a double. A driver converts a binding's
 * bigint or boolean to `number`.
 */
export type SqliteValue = string | number | null;

/** One result row, keyed by column name or alias. */
export type SqliteRow = Readonly<Record<string, SqliteValue>>;

export interface SqliteStatementResult {
  /** The rows the statement returned. Empty for a statement without rows. */
  readonly rows: readonly SqliteRow[];
  /**
   * The rows that an INSERT, UPDATE, or DELETE changed. The core reads it only
   * after one of those statements.
   */
  readonly changes: number;
}

/**
 * One pinned connection to one database file.
 *
 * The core never starts a statement before the previous one settles, so a
 * driver does not queue. A driver never moves a statement to another
 * connection: BEGIN, the statements, and COMMIT must reach the same one.
 *
 * The web driver shares each file between the tabs of an origin. When another
 * tab asks for the file, the driver closes the physical connection at an
 * autocommit boundary, and it opens the file again at the next call. The
 * reopen restores only `PRAGMA foreign_keys`, and it rejects with
 * `INVALID_STATE` when another tab changed `PRAGMA user_version`. TEMP tables
 * and other TEMP objects, every other PRAGMA, and `last_insert_rowid()` do not
 * survive a reopen. The core must not keep any of them across statements.
 *
 * A failed statement rejects with an `Error` whose message contains the
 * SQLite message text, for example `UNIQUE constraint failed`. The core
 * classifies errors from that text in one place, because not every binding
 * reports the SQLite result code.
 */
export interface SqliteConnection {
  /** Run one statement with positional `?` parameters. */
  execute(
    sql: string,
    params?: readonly SqliteValue[],
  ): Promise<SqliteStatementResult>;

  /**
   * Return the cipher that protects this connection, or `null` when the
   * connection has no codec. The probe reports a cipher only when a codec is
   * attached, because a cipher build also answers its version pragma on a
   * connection with no key. SQLCipher answers `PRAGMA cipher_version` on
   * every connection, so `cipher_version` alone is not proof: the probe
   * returns `null` when `PRAGMA cipher_provider` returns no row, and only
   * then reads `cipher_version`. SQLite3 Multiple Ciphers reads
   * `PRAGMA cipher` and returns it only when
   * `sqlite3mc_codec_data('cipher_salt')` is not NULL, because
   * `PRAGMA cipher` also answers on an unkeyed plaintext database.
   */
  probeCipher(): Promise<string | null>;

  close(): Promise<void>;
}

/** The binding for one platform. The driver owns the file location. */
export interface SqliteDriver {
  /** A short binding name for errors and logs, for example `op-sqlite`. */
  readonly name: string;

  /**
   * The identity of the database that `file` reaches: the same string for
   * every file name and driver that reach the same database in this process,
   * and a different string otherwise. The core keys its one-at-a-time open
   * and the vault slot of the key on it.
   *
   * A driver whose directory is fixed for the app returns `file`. A driver
   * whose directory the app chooses returns the canonical path of the file.
   */
  identify(file: string): string;

  /** Report whether the database file exists, without creating it. */
  exists(file: string): Promise<boolean>;

  /**
   * Open or create the file on one dedicated connection.
   *
   * With a key, the driver applies the key before any other statement, in the
   * raw-key encoding of its cipher, and never logs it. With `null`, the driver
   * applies no key. The core decides between the two.
   *
   * Then the driver runs one read before journal mode or any other setting
   * that touches the file. A driver that takes an owner lock through a lock
   * mode, which does no I/O, sets it before the read, so that the read takes
   * the lock.
   *
   * A cipher accepts any key and fails only at the first statement, so a wrong
   * key, a missing key, or a key on a plaintext file rejects the open at the
   * read, with the SQLite message text (`file is not a database`). The core
   * runs no second read.
   */
  open(file: string, key: Uint8Array | null): Promise<SqliteConnection>;

  /** Delete the file and its journal, WAL, and shared-memory files. */
  remove(file: string): Promise<void>;
}

/**
 * The statement surface that the core gives to its models. The root executor
 * and each transaction executor have this shape.
 *
 * Every call goes through the FIFO queue of its executor. A transaction holds
 * the queue of its parent from begin to end, so a call on the parent from
 * inside the callback waits for the transaction and never settles. A model
 * takes the executor as a parameter and uses only that executor.
 */
export interface SqliteExecutor {
  /** Run a write statement and return the changed row count. */
  run(sql: string, params?: readonly SqliteValue[]): Promise<number>;

  /** Run a query and return every row. */
  all<Row extends SqliteRow = SqliteRow>(
    sql: string,
    params?: readonly SqliteValue[],
  ): Promise<readonly Row[]>;

  /** Run a query and return the first row, or `null`. */
  first<Row extends SqliteRow = SqliteRow>(
    sql: string,
    params?: readonly SqliteValue[],
  ): Promise<Row | null>;

  /**
   * Run `operation` in one transaction and return its result.
   *
   * On the root executor this is `BEGIN IMMEDIATE`, then `COMMIT`. On a
   * transaction executor it is a `SAVEPOINT`, then `RELEASE`. When
   * `operation` throws, the core rolls back that scope and rethrows the
   * original error. After the scope ends, a call on its executor rejects.
   */
  transaction<T>(operation: (tx: SqliteExecutor) => Promise<T>): Promise<T>;
}

/**
 * One schema step. The core applies the missing steps in version order in one
 * `BEGIN IMMEDIATE` transaction, and sets `PRAGMA user_version` to the last
 * version in the same transaction.
 */
export interface SqliteMigration {
  /** Consecutive from 1. */
  readonly version: number;
  /** Statements without parameters, run in order. */
  readonly statements: readonly string[];
}
