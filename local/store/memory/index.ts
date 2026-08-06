/**
 * In-Memory Storage Package
 *
 * In-memory storage for local development - DO NOT use in production!
 */
export {};
import { InMemorySignalProtocolStore, type InMemorySignalProtocolStoreOptions } from './adapter';

export { InMemorySignalProtocolStore, type InMemorySignalProtocolStoreOptions } from './adapter';
export {
  InjectedStorageWriteError,
  StoreFailureController,
  type StoreFailureOptions,
} from './failures';

export function inMemoryStore(options?: InMemorySignalProtocolStoreOptions): InMemorySignalProtocolStore {
  return new InMemorySignalProtocolStore(options);
}
