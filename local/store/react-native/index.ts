/**
 * React Native Storage Package (Bare Workflow)
 *
 * Storage for React Native without Expo.
 * Consumers must provide their own persistent key-value backend and construct
 * the store with `await ReactNativeSignalProtocolStore.create({ storage })`.
 * The adapter implements the core store contract; its durability rests on the
 * injected backend, so verify the backend with the exported
 * backend-conformance kit (`assertBackendConformance`).
 */
export {};
import { ReactNativeSignalProtocolStore } from './adapter';
import type { ReactNativeKeyValueStorage } from './storage';

export { ReactNativeSignalProtocolStore } from './adapter';
export type { ReactNativeKeyValueOperation, ReactNativeKeyValueStorage } from './storage';
export { assertBackendConformance, runBackendConformance } from './backend-conformance';
export type {
  BackendConformanceFailure,
  BackendConformanceOptions,
  BackendConformanceResult,
} from './backend-conformance';
export { createReferenceReactNativeBackend } from './reference-backend';
export type { ReferenceReactNativeBackendOptions } from './reference-backend';

export interface ReactNativeStoreFactoryOptions {
  storage: ReactNativeKeyValueStorage;
}

export function reactNativeStore(
  options: ReactNativeStoreFactoryOptions
): Promise<ReactNativeSignalProtocolStore> {
  return ReactNativeSignalProtocolStore.create(options);
}
