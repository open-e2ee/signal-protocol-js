/**
 * Mock Storage Package
 *
 * In-memory storage for local development - DO NOT use in production!
 */
export {};
import { MockSignalStore, type MockSignalStoreOptions } from './adapter';

export { MockSignalStore, type MockSignalStoreOptions } from './adapter';
export {
  MockStorageWriteError,
  MockStoreFailureController,
  type MockStoreFailureOptions,
} from './failures';

export function mockStore(options?: MockSignalStoreOptions): MockSignalStore {
  return new MockSignalStore(options);
}
