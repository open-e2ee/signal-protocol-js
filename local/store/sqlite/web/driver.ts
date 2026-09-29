/**
 * The web binding of the SQLite driver seam.
 *
 * The driver runs the SQLite3 Multiple Ciphers Wasm engine in one dedicated
 * module worker, `./worker.ts`. The engine and its Wasm load only in that
 * worker, so they do not add to the bundle of the page. Each database file
 * lives in the origin private file system, encrypted in the SQLCipher 4
 * format. The worker shares each file with the other tabs of the origin; see
 * the worker for the hand-over rules.
 *
 * Each call checks the file name first (`INVALID_STATE`), then OPFS: the
 * storage APIs in the worker and one synchronous access handle on a new probe
 * file (`OPFS_UNAVAILABLE`). It loads the engine last
 * (`SQLITE_ENGINE_UNAVAILABLE`). So a context without OPFS reports
 * `OPFS_UNAVAILABLE` and never downloads the Wasm, also when its CSP refuses
 * the engine.
 */

import { resolveUrl } from '../../../../internal/platform/url';
import {
  EncryptionError,
  EncryptionErrorCode,
  StorageQuotaExceededError,
} from '../../../../types/errors';
import type {
  SqliteConnection,
  SqliteDriver,
  SqliteStatementResult,
  SqliteValue,
} from '../driver';
import type {
  WireError,
  WorkerConfiguration,
  WorkerRequest,
  WorkerResponse,
  WorkerValue,
} from './protocol';

/** Distributes `WorkerRequest` over its members, so each keeps its own fields. */
type RequestBody<Request> = Request extends unknown ? Omit<Request, 'id'> : never;

export interface WebSqliteDriverOptions {
  /**
   * The URL of the compiled worker module. By default the driver starts
   * `./worker.js` next to this module, which most bundlers resolve.
   */
  readonly workerUrl?: string | URL;
  /**
   * The URL of `sqlite3.wasm`. By default the worker loads it from
   * `./sqlite3mc/sqlite3.wasm` next to this module. The server must send it
   * as `application/wasm`. A relative URL resolves against the page, and
   * it must not contain `.` or `..` segments.
   */
  readonly wasmUrl?: string | URL;
}

/** The web SQLite driver, which owns its worker. */
export interface WebSqliteDriver extends SqliteDriver {
  /**
   * Stop the worker, and with it the Wasm engine and the Web Locks that the
   * worker holds. Every pending call rejects with `INVALID_STATE`. The open
   * connections of the worker are lost, so close each one first. The next
   * call starts a new worker.
   */
  terminate(): void;
}

interface Pending {
  resolve(value: WorkerValue): void;
  reject(error: unknown): void;
}

function engineUnavailable(message: string): EncryptionError {
  return new EncryptionError(message, EncryptionErrorCode.SQLITE_ENGINE_UNAVAILABLE, {
    operation: 'startWorker',
  });
}

/** Rebuilds a worker failure. A code outside `WorkerErrorCode` stays a plain `Error`. */
function fromWireError(error: WireError): Error {
  if (error.kind === 'sdk') {
    switch (error.code) {
      case EncryptionErrorCode.INVALID_STATE:
        return new EncryptionError(error.message, EncryptionErrorCode.INVALID_STATE, error.context);
      case EncryptionErrorCode.SQLITE_ENGINE_UNAVAILABLE:
        return new EncryptionError(
          error.message,
          EncryptionErrorCode.SQLITE_ENGINE_UNAVAILABLE,
          error.context
        );
      case EncryptionErrorCode.OPFS_UNAVAILABLE:
        return new EncryptionError(error.message, EncryptionErrorCode.OPFS_UNAVAILABLE, error.context);
      case EncryptionErrorCode.OPFS_FILE_BUSY:
        return new EncryptionError(error.message, EncryptionErrorCode.OPFS_FILE_BUSY, error.context);
      case EncryptionErrorCode.STORAGE_QUOTA_EXCEEDED:
        return new StorageQuotaExceededError(
          error.context?.operation ?? 'attachPool',
          new Error(error.message)
        );
    }
  }
  return new Error(error.message);
}

function startWorker(options: WebSqliteDriverOptions): Worker {
  if (typeof Worker !== 'function') {
    throw engineUnavailable('This context has no Worker, so the SQLite engine cannot start');
  }
  // The default keeps `new Worker(new URL(..., import.meta.url))` literal, so
  // that bundlers find and emit the worker.
  const worker =
    options.workerUrl === undefined
      ? new Worker(new URL('./worker.js', import.meta.url), { type: 'module' })
      : new Worker(options.workerUrl, { type: 'module' });
  const wasmUrl = options.wasmUrl ?? new URL('./sqlite3mc/sqlite3.wasm', import.meta.url);
  const configuration: WorkerConfiguration = {
    type: 'configure',
    // The query and the fragment of the page do not take part in resolution.
    wasmUrl: resolveUrl(
      typeof wasmUrl === 'string' ? wasmUrl : wasmUrl.href,
      `${globalThis.location.origin}${globalThis.location.pathname}`
    ),
  };
  worker.postMessage(configuration);
  return worker;
}

/**
 * Create the web SQLite driver. Each driver starts one worker on its first
 * call. When the worker fails, the driver rejects every pending call with
 * `SQLITE_ENGINE_UNAVAILABLE` and starts a new worker on the next call. The
 * connections of the failed worker stay closed.
 */
export function createWebSqliteDriver(options: WebSqliteDriverOptions = {}): WebSqliteDriver {
  let worker: Worker | null = null;
  let nextRequest = 1;
  let nextConnection = 1;
  const pending = new Map<number, Pending>();

  /** Stops `stopped` when it is the current worker, and rejects every pending call. */
  function stop(stopped: Worker, error: EncryptionError): void {
    if (worker !== stopped) return;
    worker = null;
    stopped.terminate();
    const calls = [...pending.values()];
    pending.clear();
    for (const call of calls) call.reject(error);
  }

  function fail(failed: Worker, message: string): void {
    stop(failed, engineUnavailable(message));
  }

  function ensureWorker(): Worker {
    if (worker !== null) return worker;
    const started = startWorker(options);
    started.addEventListener('message', (event: MessageEvent<WorkerResponse>) => {
      const response = event.data;
      const call = pending.get(response.id);
      if (call === undefined) return;
      pending.delete(response.id);
      if (response.ok) {
        call.resolve(response.value);
      } else {
        call.reject(fromWireError(response.error));
      }
    });
    started.addEventListener('error', (event: ErrorEvent) => {
      event.preventDefault();
      fail(started, `The SQLite worker failed: ${event.message || 'the worker script did not load'}`);
    });
    started.addEventListener('messageerror', () => {
      fail(started, 'The SQLite worker sent a message that could not be read');
    });
    worker = started;
    return started;
  }

  function call(body: RequestBody<WorkerRequest>, transfer: Transferable[] = []): Promise<WorkerValue> {
    return new Promise((resolve, reject) => {
      const target = ensureWorker();
      const id = nextRequest++;
      pending.set(id, { resolve, reject });
      target.postMessage({ ...body, id } as WorkerRequest, transfer);
    });
  }

  return {
    name: 'sqlite3mc-wasm',

    // The OPFS directory of the worker is fixed for the origin.
    identify: (file) => file,

    async exists(file) {
      return (await call({ type: 'exists', file })) as boolean;
    },

    async open(file, key) {
      const connection = nextConnection++;
      // The worker gets its own copy. The copy moves to the worker, so no
      // second copy stays in this context.
      const copy = key === null ? null : key.slice();
      await call({ type: 'open', file, connection, key: copy }, copy === null ? [] : [copy.buffer]);
      let closed: Promise<void> | null = null;
      const handle: SqliteConnection = {
        async execute(sql: string, params: readonly SqliteValue[] = []) {
          if (closed !== null) {
            throw new EncryptionError('The SQLite connection is closed', EncryptionErrorCode.INVALID_STATE, {
              operation: 'execute',
            });
          }
          return (await call({ type: 'execute', file, connection, sql, params })) as SqliteStatementResult;
        },
        async probeCipher() {
          if (closed !== null) {
            throw new EncryptionError('The SQLite connection is closed', EncryptionErrorCode.INVALID_STATE, {
              operation: 'probeCipher',
            });
          }
          return (await call({ type: 'probeCipher', file, connection })) as string | null;
        },
        close() {
          closed ??= call({ type: 'close', file, connection }).then(() => undefined);
          return closed;
        },
      };
      return handle;
    },

    async remove(file) {
      await call({ type: 'remove', file });
    },

    terminate() {
      if (worker === null) return;
      stop(
        worker,
        new EncryptionError('The SQLite worker was stopped', EncryptionErrorCode.INVALID_STATE, {
          operation: 'terminate',
        })
      );
    },
  };
}
