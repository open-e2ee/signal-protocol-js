/**
 * In-Memory Relay Package
 *
 * In-memory backend for local development - DO NOT use in production!
 */
export {};
import { InMemorySignalProtocolRelayServer, type InMemorySignalProtocolRelayServerOptions } from './adapter';

export {
  InMemorySignalProtocolRelayServer,
  type InMemorySignalProtocolRelayServerOptions,
} from './adapter';
export {
  RelayFailureController,
  type RelayFailureOptions,
} from './failures';

export function inMemoryRelay(options?: InMemorySignalProtocolRelayServerOptions): InMemorySignalProtocolRelayServer {
  return new InMemorySignalProtocolRelayServer(options);
}
