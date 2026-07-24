/**
 * Mock Backend Package
 *
 * In-memory backend for local development - DO NOT use in production!
 */
export {};
import { MockSignalRelayServer } from './adapter';

export { MockSignalRelayServer } from './adapter';

export function mockRelay(): MockSignalRelayServer {
  return new MockSignalRelayServer();
}
