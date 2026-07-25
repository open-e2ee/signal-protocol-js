/**
 * Mock Backend Package
 *
 * In-memory backend for local development - DO NOT use in production!
 */
export {};
import { MockSignalRelayServer, type MockSignalRelayServerOptions } from './adapter';

export {
  MockSignalRelayServer,
  type MockSignalRelayServerOptions,
} from './adapter';
export {
  MockRelayFailureController,
  type MockRelayFailureOptions,
} from './failures';

export function mockRelay(options?: MockSignalRelayServerOptions): MockSignalRelayServer {
  return new MockSignalRelayServer(options);
}
