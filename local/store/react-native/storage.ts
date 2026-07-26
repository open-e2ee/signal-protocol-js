/**
 * Minimal persistent key-value backend required by ReactNativeSignalProtocolStore.
 *
 * Bare React Native consumers must provide their own implementation so the
 * Signal Protocol package does not hard-code a specific storage library.
 */
export interface ReactNativeKeyValueStorage {
  getItem(key: string): Promise<string | null>;
  setItem(key: string, value: string): Promise<void>;
  removeItem(key: string): Promise<void>;
  getAllKeys(): Promise<string[]>;
  removeMany(keys: string[]): Promise<void>;
  /** Commit every operation all-or-nothing, including across process termination. */
  atomicWrite(operations: readonly ReactNativeKeyValueOperation[]): Promise<void>;
}

export type ReactNativeKeyValueOperation =
  | { readonly type: 'set'; readonly key: string; readonly value: string }
  | { readonly type: 'remove'; readonly key: string }
  /** Compare-and-swap guard evaluated before any write in the batch. */
  | { readonly type: 'check'; readonly key: string; readonly expectedValue: string | null }
  /**
   * Enumerate and remove session envelopes whose plaintext routing metadata
   * has the exact userId, inside the same durable transaction.
   */
  | {
      readonly type: 'removeSessionsForUser';
      readonly keyPrefix: string;
      readonly userId: string;
    };
