/**
 * Key-Value Storage Package (Bare Workflow)
 *
 * Storage for React Native without Expo.
 * Consumers must provide their own persistent key-value backend and a platform
 * secret vault, and construct the store with
 * `await KeyValueSignalProtocolStore.create({ storage, vault })`.
 * The adapter implements the core store contract. Its durability rests on the
 * injected backend, so verify the backend with the exported
 * backend-conformance kit (`assertBackendConformance`).
 */
export {};
import { KeyValueSignalProtocolStore } from './adapter';
import type { KeyValueSignalProtocolStoreOptions } from './adapter';

export { KeyValueSignalProtocolStore } from './adapter';
export type { KeyValueSignalProtocolStoreOptions } from './adapter';
export type { KeyValueOperation, KeyValueStorage } from './storage';
export { createTransactionalKeyValueBackend } from './transactional-backend';
export type { KeyValueReader, TransactionalKeyValueEngine } from './transactional-backend';
export type { KeyValueTransaction } from './batch';
export { assertBackendConformance, runBackendConformance } from './backend-conformance';
export type {
  BackendConformanceFailure,
  BackendConformanceOptions,
  BackendConformanceResult,
} from './backend-conformance';

export function keyValueStore(
  options: KeyValueSignalProtocolStoreOptions
): Promise<KeyValueSignalProtocolStore> {
  return KeyValueSignalProtocolStore.create(options);
}
