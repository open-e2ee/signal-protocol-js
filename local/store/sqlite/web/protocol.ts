/**
 * Messages between the web SQLite driver and its worker.
 *
 * The driver posts one `WorkerConfiguration`, then one `WorkerRequest` per
 * driver or connection call. The worker answers each request with one
 * `WorkerResponse` that has the same `id`, in any order.
 *
 * The driver chooses each `connection` number. The worker runs a connection
 * request only for the connection that it opened with that number, so a
 * request cannot reach a connection that a restarted worker never opened.
 */

import type { EncryptionErrorCode, EncryptionErrorContext } from '../../../../types/errors';
import type { SqliteStatementResult, SqliteValue } from '../driver';

export interface WorkerConfiguration {
  readonly type: 'configure';
  /** The absolute URL of `sqlite3.wasm`. */
  readonly wasmUrl: string;
}

export type WorkerRequest =
  | { readonly id: number; readonly type: 'exists'; readonly file: string }
  | { readonly id: number; readonly type: 'remove'; readonly file: string }
  | {
      readonly id: number;
      readonly type: 'open';
      readonly file: string;
      readonly connection: number;
      /** A copy for the worker. The worker zeroes it when the connection closes. */
      readonly key: Uint8Array | null;
    }
  | {
      readonly id: number;
      readonly type: 'execute';
      readonly file: string;
      readonly connection: number;
      readonly sql: string;
      readonly params: readonly SqliteValue[];
    }
  | {
      readonly id: number;
      readonly type: 'probeCipher';
      readonly file: string;
      readonly connection: number;
    }
  | { readonly id: number; readonly type: 'close'; readonly file: string; readonly connection: number };

/** The result of one request. */
export type WorkerValue = boolean | string | null | SqliteStatementResult | undefined;

/** The codes that the worker raises. No other code crosses the boundary. */
export type WorkerErrorCode =
  | EncryptionErrorCode.INVALID_STATE
  | EncryptionErrorCode.SQLITE_ENGINE_UNAVAILABLE
  | EncryptionErrorCode.OPFS_UNAVAILABLE
  | EncryptionErrorCode.OPFS_FILE_BUSY
  | EncryptionErrorCode.STORAGE_QUOTA_EXCEEDED;

/**
 * A failure that crosses the worker boundary. An `sdk` failure becomes an
 * `EncryptionError` with the same code. An `error` failure becomes an `Error`
 * with the same message, which keeps the SQLite message text that the driver
 * contract requires.
 */
export type WireError =
  | {
      readonly kind: 'sdk';
      readonly code: WorkerErrorCode;
      readonly message: string;
      readonly context?: Pick<EncryptionErrorContext, 'operation'>;
    }
  | { readonly kind: 'error'; readonly message: string };

export type WorkerResponse =
  | {
      readonly id: number;
      readonly ok: true;
      readonly value: WorkerValue;
    }
  | { readonly id: number; readonly ok: false; readonly error: WireError };
