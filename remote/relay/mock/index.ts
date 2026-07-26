/**
 * Mock Backend Package
 *
 * In-memory backend for local development - DO NOT use in production!
 */
export {};
import { MockSignalProtocolRelayServer, type MockSignalProtocolRelayServerOptions } from './adapter';

export {
  MockSignalProtocolRelayServer,
  type MockSignalProtocolRelayServerOptions,
} from './adapter';
export {
  MockRelayFailureController,
  type MockRelayFailureOptions,
} from './failures';

export function mockRelay(options?: MockSignalProtocolRelayServerOptions): MockSignalProtocolRelayServer {
  return new MockSignalProtocolRelayServer(options);
}
