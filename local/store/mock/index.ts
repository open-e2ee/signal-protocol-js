/**
 * Mock Storage Package
 *
 * In-memory storage for local development - DO NOT use in production!
 */
export {};
import { MockSignalStore } from './adapter';

export { MockSignalStore } from './adapter';

export function mockStore(): MockSignalStore {
  return new MockSignalStore();
}
