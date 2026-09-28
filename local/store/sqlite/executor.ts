/**
 * Statement queue and transaction scopes for one pinned connection.
 *
 * The root executor runs every statement and transaction of one connection in
 * one FIFO queue, reads included. A transaction holds the root queue from
 * `BEGIN IMMEDIATE` to `COMMIT`, so no statement from outside can join it or
 * be discarded by its rollback. Inside, the transaction executor has its own
 * FIFO queue, and a nested scope is a savepoint.
 */

import type {
  SqliteConnection,
  SqliteExecutor,
  SqliteRow,
  SqliteStatementResult,
  SqliteValue,
} from './driver';
import { SqliteStoreClosedError, toStorageQuotaError } from './errors';

/** A root executor that also owns the end of its connection. */
export interface SqliteRootExecutor extends SqliteExecutor {
  /**
   * Wait for the queued work, then close the connection. Every later call
   * rejects with `SqliteStoreClosedError`. A second call returns the first
   * call's promise.
   */
  close(): Promise<void>;
}

/** A FIFO queue: each task starts after the previous task settles. */
class TaskQueue {
  private tail: Promise<unknown> = Promise.resolve();

  enqueue<T>(task: () => Promise<T>): Promise<T> {
    const result = this.tail.then(task, task);
    this.tail = result.catch(() => undefined);
    return result;
  }

  /** Settle after every task enqueued so far. */
  drain(): Promise<void> {
    return this.tail.then(() => undefined);
  }
}

/**
 * One executor surface over one queue. `closedError` returns the error for a
 * new call after the scope ends, or `null` while the scope is open. A call
 * accepted before the end still runs.
 */
class QueuedExecutor implements SqliteExecutor {
  readonly queue = new TaskQueue();

  constructor(
    private readonly connection: SqliteConnection,
    private readonly depth: number,
    private readonly closedError: () => Error | null
  ) {}

  async run(sql: string, params?: readonly SqliteValue[]): Promise<number> {
    const result = await this.statement(sql, params);
    return result.changes;
  }

  async all<Row extends SqliteRow = SqliteRow>(
    sql: string,
    params?: readonly SqliteValue[]
  ): Promise<readonly Row[]> {
    const result = await this.statement(sql, params);
    return result.rows as readonly Row[];
  }

  async first<Row extends SqliteRow = SqliteRow>(
    sql: string,
    params?: readonly SqliteValue[]
  ): Promise<Row | null> {
    const rows = await this.all<Row>(sql, params);
    return rows[0] ?? null;
  }

  transaction<T>(operation: (tx: SqliteExecutor) => Promise<T>): Promise<T> {
    return this.guarded(() => this.scope(operation));
  }

  private statement(sql: string, params?: readonly SqliteValue[]) {
    return this.guarded(() => this.execute(sql, params));
  }

  /**
   * Every statement of the connection runs here, `BEGIN` and `COMMIT`
   * included, so a full file rejects with `StorageQuotaExceededError`.
   */
  private async execute(
    sql: string,
    params?: readonly SqliteValue[]
  ): Promise<SqliteStatementResult> {
    try {
      return await this.connection.execute(sql, params);
    } catch (error) {
      throw toStorageQuotaError(error);
    }
  }

  private guarded<T>(task: () => Promise<T>): Promise<T> {
    const closed = this.closedError();
    return closed ? Promise.reject(closed) : this.queue.enqueue(task);
  }

  private async scope<T>(operation: (tx: SqliteExecutor) => Promise<T>): Promise<T> {
    const root = this.depth === 0;
    const savepoint = `s${this.depth + 1}`;
    let ended = false;
    const child = new QueuedExecutor(this.connection, this.depth + 1, () =>
      ended ? new SqliteStoreClosedError('The transaction has ended.') : null
    );

    // A call that the operation started and did not await still belongs to
    // this scope. The second drain runs the calls accepted before the end.
    const endScope = async () => {
      await child.queue.drain();
      ended = true;
      await child.queue.drain();
    };

    await this.execute(root ? 'BEGIN IMMEDIATE' : `SAVEPOINT ${savepoint}`);
    try {
      const result = await operation(child);
      await endScope();
      await this.execute(root ? 'COMMIT' : `RELEASE ${savepoint}`);
      return result;
    } catch (error) {
      await endScope();
      await this.rollback(root, savepoint);
      throw error;
    }
  }

  /** Roll back one scope. A failed rollback never replaces the original error. */
  private async rollback(root: boolean, savepoint: string): Promise<void> {
    try {
      if (root) {
        await this.execute('ROLLBACK');
      } else {
        await this.execute(`ROLLBACK TO ${savepoint}`);
        await this.execute(`RELEASE ${savepoint}`);
      }
    } catch {
      // The original error is the one the caller needs.
    }
  }
}

/** Create the root executor for one connection. The executor owns the connection. */
export function createSqliteExecutor(connection: SqliteConnection): SqliteRootExecutor {
  let closing: Promise<void> | null = null;
  const executor = new QueuedExecutor(connection, 0, () =>
    closing ? new SqliteStoreClosedError('The SQLite store is closed.') : null
  );

  return {
    run: (sql, params) => executor.run(sql, params),
    all: (sql, params) => executor.all(sql, params),
    first: (sql, params) => executor.first(sql, params),
    transaction: (operation) => executor.transaction(operation),
    close() {
      closing ??= executor.queue.enqueue(() => connection.close());
      return closing;
    },
  };
}
