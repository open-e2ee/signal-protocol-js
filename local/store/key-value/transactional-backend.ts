/**
 * A key-value backend over an engine's own transaction.
 *
 * The rules of `atomicWrite` (checks first against the pre-batch state,
 * writes in order, the session scan, and skipped-key pruning) have one owner: the store's batch
 * function. An application that writes a backend for its storage engine does
 * not copy them. It supplies the engine's transaction and a handle over it,
 * and {@link createTransactionalKeyValueBackend} runs every write as one batch
 * inside that transaction.
 *
 * The handle is synchronous. The batch runs from the first check to the last
 * write in one synchronous call, so no other JavaScript runs between the
 * check and the writes. Realm's `write` commits when its synchronous callback
 * returns, so it cannot hold an asynchronous batch. An engine with an
 * asynchronous transaction, such as op-sqlite's `db.transaction`, runs the
 * synchronous body inside it with its synchronous statement calls.
 */

import { EncryptionError, EncryptionErrorCode } from '../../../types/errors';
import { applyKeyValueBatch, type KeyValueTransaction } from './batch';
import type { KeyValueOperation, KeyValueStorage } from './storage';

/** The read calls of a {@link KeyValueTransaction}, over committed data. */
export type KeyValueReader = Pick<KeyValueTransaction, 'get' | 'keysWithPrefix'>;

/** The two ways the backend reaches the application's storage engine. */
export interface TransactionalKeyValueEngine {
  /**
   * Open one write transaction and call `body` once with a handle over it.
   * Commit when `body` returns. When `body` throws, roll back and rethrow.
   * Return or resolve only after the commit is durable. `body` must run
   * synchronously inside the transaction.
   */
  transaction(body: (transaction: KeyValueTransaction) => void): void | Promise<void>;
  /**
   * Call `body` once with a reader over committed data, and return its
   * result. `body` only reads.
   */
  read<T>(body: (reader: KeyValueReader) => T): T | Promise<T>;
}

/**
 * Create a `KeyValueStorage` over an engine transaction. Every
 * write, including `setItem`, `removeItem`, and `removeMany`, runs as one
 * batch in one engine transaction. Calls run one at a time, in the order the
 * store makes them.
 *
 * A batch that fails commits nothing, provided that the engine rolls back
 * when `body` throws. When the engine returns without calling `body`, or
 * calls it twice, the write rejects with `INVALID_STATE`. To signal a full
 * disk, the engine throws an error whose `name` is `'QuotaExceededError'`
 * before it commits. Run the backend-conformance kit over the result.
 */
export function createTransactionalKeyValueBackend(
  engine: TransactionalKeyValueEngine
): KeyValueStorage {
  let queue: Promise<unknown> = Promise.resolve();
  function serialized<T>(run: () => T | Promise<T>): Promise<T> {
    const next = queue.then(run);
    queue = next.then(
      () => undefined,
      () => undefined
    );
    return next;
  }

  async function write(operations: readonly KeyValueOperation[]): Promise<void> {
    let calls = 0;
    let batchFailed = false;
    let batchError: unknown;
    let repeatError: EncryptionError | undefined;
    await engine.transaction((transaction) => {
      calls += 1;
      if (calls > 1) {
        repeatError = new EncryptionError(
          'The key-value engine called the transaction body twice; a batch runs once.',
          EncryptionErrorCode.INVALID_STATE
        );
        throw repeatError;
      }
      try {
        applyKeyValueBatch(transaction, operations);
      } catch (error) {
        batchFailed = true;
        batchError = error;
        throw error;
      }
    });
    // The batch failed, or the engine ran it twice, so the write failed, even
    // when the engine did not pass the error on.
    if (batchFailed) throw batchError;
    if (repeatError) throw repeatError;
    if (calls === 0) {
      throw new EncryptionError(
        'The key-value engine returned without running the transaction body; nothing was written.',
        EncryptionErrorCode.INVALID_STATE
      );
    }
  }

  return {
    getItem(key: string): Promise<string | null> {
      return serialized(() => engine.read((reader) => reader.get(key)));
    },
    setItem(key: string, value: string): Promise<void> {
      return serialized(() => write([{ type: 'set', key, value }]));
    },
    removeItem(key: string): Promise<void> {
      return serialized(() => write([{ type: 'remove', key }]));
    },
    getAllKeys(): Promise<string[]> {
      return serialized(() => engine.read((reader) => [...reader.keysWithPrefix('')]));
    },
    removeMany(keys: string[]): Promise<void> {
      return serialized(() =>
        write(keys.map((key): KeyValueOperation => ({ type: 'remove', key })))
      );
    },
    atomicWrite(operations: readonly KeyValueOperation[]): Promise<void> {
      return serialized(() => write(operations));
    },
  };
}
