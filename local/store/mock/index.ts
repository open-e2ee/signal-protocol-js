/**
 * Mock Storage Package
 *
 * In-memory storage for local development - DO NOT use in production!
 */
export {};
import { MockSignalProtocolStore, type MockSignalProtocolStoreOptions } from './adapter';

export { MockSignalProtocolStore, type MockSignalProtocolStoreOptions } from './adapter';
export {
  MockStorageWriteError,
  MockStoreFailureController,
  type MockStoreFailureOptions,
} from './failures';

export function mockStore(options?: MockSignalProtocolStoreOptions): MockSignalProtocolStore {
  return new MockSignalProtocolStore(options);
}
