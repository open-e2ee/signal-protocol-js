/**
 * Convex Relay Package
 *
 * Convex integration for Signal Protocol relay state, prekeys, devices, and encrypted
 * envelope delivery.
 *
 * ```typescript
 * import { createSignalProtocolClient } from '@open-e2ee/signal-protocol-sdk';
 * import { expoStore } from '@open-e2ee/signal-protocol-sdk/local/store/expo';
 * import { convexRelay, type ConvexSignalProtocolRelayApi } from '@open-e2ee/signal-protocol-sdk/remote/relay/convex';
 * import { api } from '../convex/_generated/api';
 *
 * const signalApi = api.signal satisfies ConvexSignalProtocolRelayApi;
 * const relay = convexRelay({ convex, api: signalApi, currentUserId: userId });
 *
 * const signal = await createSignalProtocolClient({
 *   identity: { userId },
 *   adapters: { storage: expoStore({ relay }), relay },
 *   onProgress: ({ stage, percent, message }) => console.log(`${stage}: ${percent}%`)
 * });
 *
 * await signal.syncToServer();
 * await signal.rotateEcSignedPreKey();
 * await signal.rotateKyberPreKey();
 * ```
 */

export {};
import {
  ConvexSignalProtocolRelayServer,
  type ConvexSignalProtocolRelayApi,
  type ConvexSignalProtocolRelayOptions,
} from './relay';

export { ConvexSignalProtocolRelayServer } from './relay';
export type { ConvexSignalProtocolRelayApi, ConvexSignalProtocolRelayOptions } from './relay';
export { ConvexGroupServer } from './group-server';
export type { ConvexGroupServerApi } from './group-server';

// Type conversion utilities
export * from './types';

export interface ConvexSignalProtocolRelayFactoryOptions extends ConvexSignalProtocolRelayOptions {
  convex: ConstructorParameters<typeof ConvexSignalProtocolRelayServer>[0];
  api: ConvexSignalProtocolRelayApi;
}

export function convexRelay(options: ConvexSignalProtocolRelayFactoryOptions): ConvexSignalProtocolRelayServer {
  const { convex, api, ...relayOptions } = options;
  return new ConvexSignalProtocolRelayServer(convex, api, relayOptions);
}
