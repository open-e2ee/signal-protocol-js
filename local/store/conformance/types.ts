/**
 * The options, the result, and the case shape of the local store
 * conformance kit.
 */

import type { LocalStoreProtection, SignalProtocolLocalStore } from '../../../types/api';

export interface LocalStoreConformanceOptions {
  /** A fresh, empty store for each case. */
  createStore(): Promise<SignalProtocolLocalStore>;
  /** Close and open the same store. Durability cases skip without it. */
  reopen?(store: SignalProtocolLocalStore): Promise<SignalProtocolLocalStore>;
  /** Make the next atomic commit fail after its first write. Atomic cases skip without it. */
  armWriteFailure?(store: SignalProtocolLocalStore): void;
  /** The stored bytes. The ciphertext scan skips without it. */
  readRawBytes?(store: SignalProtocolLocalStore): Promise<Uint8Array[]>;
  /** Release a store after its case. */
  closeStore?(store: SignalProtocolLocalStore): Promise<void>;
}

export interface LocalStoreConformanceFailure {
  name: string;
  message: string;
}

export interface LocalStoreConformanceResult {
  /** Number of cases in the kit, including skipped ones. */
  total: number;
  passed: string[];
  skipped: string[];
  failures: LocalStoreConformanceFailure[];
  /** The declaration of the store, as the protection declaration case reads it. Null when that case fails. */
  protection: LocalStoreProtection | null;
}

/**
 * The store of one case and the optional hooks of the application. A
 * reopen replaces `store`.
 */
export interface LocalStoreConformanceContext {
  readonly store: SignalProtocolLocalStore;
  /** Close the store and open it again. The new store replaces `store`. */
  reopen(): Promise<SignalProtocolLocalStore>;
  /** Make the next atomic commit of `store` fail after its first write. */
  armWriteFailure(): void;
  /** The bytes that `store` keeps. */
  readRawBytes(): Promise<Uint8Array[]>;
  /** Put the protection declaration of the store in the result. */
  reportProtection(protection: LocalStoreProtection): void;
}

/** One named case of the kit. */
export interface LocalStoreConformanceCase {
  name: string;
  /** The option that the case needs. The case is skipped without it. */
  needs?: 'reopen' | 'armWriteFailure' | 'readRawBytes';
  /** Tell whether the case applies to the store. The case is skipped when it does not. */
  applies?(store: SignalProtocolLocalStore): boolean;
  run(context: LocalStoreConformanceContext): Promise<void>;
}
