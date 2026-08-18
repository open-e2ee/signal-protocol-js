/**
 * Reference implementation of `ReactNativeKeyValueStorage`.
 *
 * This backend is the executable specification the backend-conformance kit is
 * written against. The contract requires full serialization, checks evaluated
 * against pre-batch state, in-order application with in-batch visibility, and
 * exact-userId session removal. It also requires all-or-nothing commit,
 * including under quota exhaustion. Every one of those semantics is
 * implemented here in the plainest form that satisfies it.
 *
 * It holds data in memory, so it is not a production backend: a real
 * application supplies storage that survives process termination. Continuous
 * integration runs the kit against this backend on the Hermes engine React
 * Native ships with, which is why the module avoids class syntax.
 *
 * Passing `state` lets separate instances share one persistence medium, which
 * models a process restart. Create a second backend over the same map, and the
 * first instance's committed writes are visible to it. The model is
 * sequential. The old instance stops before the new one starts, as a killed
 * process stops before its replacement launches. Serialization is per
 * instance, so two instances used concurrently over one map do not get the
 * single-winner guarantee.
 */

import type { ReactNativeKeyValueOperation, ReactNativeKeyValueStorage } from './storage';

export interface ReferenceReactNativeBackendOptions {
  /**
   * Reject any write that would grow the total stored bytes (UTF-8 keys plus
   * values) past this limit, with an error named `QuotaExceededError` and
   * nothing committed. The quota signal the store's boundary maps to its
   * typed `StorageQuotaExceededError`. Unlimited when omitted.
   */
  quotaBytes?: number;
  /** The backing map. Supply the same map to a later instance to model reopening after a restart. */
  state?: Map<string, string>;
}

/**
 * UTF-8 byte length without `TextEncoder` or `Buffer`, neither of which the
 * Hermes CLI provides.
 */
function utf8ByteLength(value: string): number {
  let bytes = 0;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code < 0x80) {
      bytes += 1;
    } else if (code < 0x800) {
      bytes += 2;
    } else if (code >= 0xd800 && code <= 0xdbff) {
      // A surrogate pair encodes as 4 bytes. An unpaired surrogate encodes
      // as the 3-byte replacement character either way.
      const next = index + 1 < value.length ? value.charCodeAt(index + 1) : 0;
      if (next >= 0xdc00 && next <= 0xdfff) {
        bytes += 4;
        index += 1;
      } else {
        bytes += 3;
      }
    } else {
      bytes += 3;
    }
  }
  return bytes;
}

function usedBytes(entries: Map<string, string>): number {
  let total = 0;
  for (const entry of entries) {
    total += utf8ByteLength(entry[0]) + utf8ByteLength(entry[1]);
  }
  return total;
}

function quotaError(): Error {
  const error = new Error('Reference backend storage quota exhausted');
  // Signalled by name, not by a shared class: the store's boundary matches
  // `error.name` so any backend can raise the same signal.
  error.name = 'QuotaExceededError';
  return error;
}

/**
 * Create a reference backend. Every method is serialized through one internal
 * queue, so two in-flight `atomicWrite` calls can never interleave their
 * check and apply phases. The exclusion the contract's compare-and-swap
 * guard depends on.
 */
export function createReferenceReactNativeBackend(
  options?: ReferenceReactNativeBackendOptions
): ReactNativeKeyValueStorage {
  const committed = options?.state ?? new Map<string, string>();
  const quotaBytes = options?.quotaBytes ?? Infinity;

  let queue: Promise<unknown> = Promise.resolve();
  function serialized<T>(run: () => Promise<T>): Promise<T> {
    const next = queue.then(run);
    queue = next.then(
      function settled() {},
      function swallowedForQueue() {}
    );
    return next;
  }

  function ensureQuota(entries: Map<string, string>): void {
    if (usedBytes(entries) > quotaBytes) throw quotaError();
  }

  async function applyAtomically(
    operations: readonly ReactNativeKeyValueOperation[]
  ): Promise<void> {
    // Phase 1: every check, against the committed pre-batch state.
    for (const operation of operations) {
      if (operation.type !== 'check') continue;
      const current = committed.get(operation.key) ?? null;
      if (current !== operation.expectedValue) {
        throw new Error(
          'atomicWrite check failed for key ' + operation.key + '; nothing was applied'
        );
      }
    }
    // The yield keeps the serialization queue honest: without the mutex the
    // conformance kit's concurrent-batch case would observe two winners here.
    await Promise.resolve();
    // Phase 2: apply in order over a snapshot, so a failure commits nothing
    // and `removeSessionsForUser` sees writes from earlier in the batch.
    const next = new Map(committed);
    for (const operation of operations) {
      if (operation.type === 'set') {
        next.set(operation.key, operation.value);
      } else if (operation.type === 'remove') {
        next.delete(operation.key);
      } else if (operation.type === 'removeSessionsForUser') {
        const doomed: string[] = [];
        for (const entry of next) {
          if (!entry[0].startsWith(operation.keyPrefix)) continue;
          let userId: unknown = null;
          try {
            const envelope = JSON.parse(entry[1]) as { userId?: unknown };
            userId = envelope === null ? null : envelope.userId;
          } catch {
            // A non-JSON value under the prefix is not a session envelope the
            // store wrote. Leave it for the owner to account for.
            continue;
          }
          if (userId === operation.userId) doomed.push(entry[0]);
        }
        for (const key of doomed) next.delete(key);
      }
    }
    ensureQuota(next);
    // Phase 3: commit by swapping contents in place, so instances sharing
    // the `state` map observe the batch all at once.
    committed.clear();
    for (const entry of next) committed.set(entry[0], entry[1]);
  }

  return {
    getItem(key: string): Promise<string | null> {
      return serialized(async function getItem() {
        return committed.get(key) ?? null;
      });
    },
    setItem(key: string, value: string): Promise<void> {
      return serialized(async function setItem() {
        const next = new Map(committed);
        next.set(key, value);
        ensureQuota(next);
        committed.set(key, value);
      });
    },
    removeItem(key: string): Promise<void> {
      return serialized(async function removeItem() {
        committed.delete(key);
      });
    },
    getAllKeys(): Promise<string[]> {
      return serialized(async function getAllKeys() {
        return Array.from(committed.keys());
      });
    },
    removeMany(keys: string[]): Promise<void> {
      return serialized(async function removeMany() {
        for (const key of keys) committed.delete(key);
      });
    },
    atomicWrite(operations: readonly ReactNativeKeyValueOperation[]): Promise<void> {
      return serialized(function atomicWrite() {
        return applyAtomically(operations);
      });
    },
  };
}
