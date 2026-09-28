/**
 * The batch semantics of `KeyValueStorage.atomicWrite`, owned once.
 *
 * `atomicWrite` carries more than a batch write. Every `check` runs against
 * the state from before the batch, before any write. Operations apply in
 * order, and each one sees the writes before it. `removeSessionsForUser`
 * scans a key prefix and reads the store's own session envelope for its
 * `userId`. A backend that copies these rules can get one of them wrong, and
 * a wrong copy can roll ratchet state back. So each backend the SDK ships
 * opens its engine's transaction and hands this function a handle over it.
 *
 * The function is synchronous. An engine whose transaction commits when a
 * synchronous callback returns, such as Realm's `write`, runs it inside that
 * callback, so no other JavaScript can run between the check and apply
 * phases. A throw leaves the batch half applied inside the transaction; the
 * caller must cancel the transaction so that nothing commits.
 */

import type { KeyValueOperation } from './storage';

/** One open engine transaction, seen through the four calls a batch needs. */
export interface KeyValueTransaction {
  /** The value in this transaction, including earlier writes of the batch. */
  get(key: string): string | null;
  set(key: string, value: string): void;
  /** Delete the key. A missing key is not an error. */
  delete(key: string): void;
  /** Every key that starts with the prefix, compared case-sensitively. */
  keysWithPrefix(prefix: string): readonly string[];
}

/**
 * The quota signal: an error whose `name` is `'QuotaExceededError'`. The
 * store maps it to its typed `StorageQuotaExceededError`. A backend throws it
 * before its transaction commits, so the rejected write commits nothing.
 */
export function quotaExceededError(message: string): Error {
  const error = new Error(message);
  // Signaled by name, not by a shared class: the store's boundary matches
  // `error.name` so any backend can raise the same signal.
  error.name = 'QuotaExceededError';
  return error;
}

function envelopeUserId(value: string | null): unknown {
  if (value === null) return null;
  try {
    const envelope = JSON.parse(value) as { userId?: unknown } | null;
    return envelope === null || typeof envelope !== 'object' ? null : envelope.userId;
  } catch {
    // A non-JSON value under the prefix is not a session envelope the store
    // wrote. Leave it for the owner to account for.
    return null;
  }
}

function removeSessionsForUser(
  transaction: KeyValueTransaction,
  keyPrefix: string,
  userId: string
): void {
  const doomed: string[] = [];
  for (const key of transaction.keysWithPrefix(keyPrefix)) {
    if (envelopeUserId(transaction.get(key)) === userId) doomed.push(key);
  }
  for (const key of doomed) transaction.delete(key);
}

/**
 * Apply one `atomicWrite` batch inside an open transaction: every check
 * first, against the pre-batch state, then every write in order. A failed
 * check throws before the first write.
 */
export function applyKeyValueBatch(
  transaction: KeyValueTransaction,
  operations: readonly KeyValueOperation[]
): void {
  for (const operation of operations) {
    if (operation.type !== 'check') continue;
    if (transaction.get(operation.key) !== operation.expectedValue) {
      throw new Error(
        'atomicWrite check failed for key ' + operation.key + '; nothing was applied'
      );
    }
  }
  for (const operation of operations) {
    if (operation.type === 'set') {
      transaction.set(operation.key, operation.value);
    } else if (operation.type === 'remove') {
      transaction.delete(operation.key);
    } else if (operation.type === 'removeSessionsForUser') {
      removeSessionsForUser(transaction, operation.keyPrefix, operation.userId);
    }
  }
}
