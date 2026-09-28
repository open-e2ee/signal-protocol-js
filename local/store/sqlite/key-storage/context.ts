/**
 * The state that every key storage operation shares: one executor and the
 * logger. Each concept module takes this context first.
 */

import type { SqliteExecutor } from '../driver';
import type { Logger } from '../../../../logger';
import {
  EncryptionError,
  EncryptionErrorCode,
  StorageQuotaExceededError,
} from '../../../../types/errors';

export interface KeyStorageContext {
  readonly db: SqliteExecutor;
  /** Mutable, so `setLogger` applies to every later operation. */
  logger: Required<Logger>;
}

/**
 * The error that a key storage operation throws for a failed step. A full
 * file keeps its `StorageQuotaExceededError`, so the caller can free space and
 * retry.
 */
export function keyStorageError(message: string, error: unknown): EncryptionError {
  if (error instanceof StorageQuotaExceededError) return error;
  return new EncryptionError(message, EncryptionErrorCode.KEY_STORAGE_ERROR, {
    originalError: error as Error,
  });
}
