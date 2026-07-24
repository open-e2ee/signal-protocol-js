/**
 * Convex Relay Package
 *
 * Convex integration for Signal relay state, prekeys, devices, and encrypted
 * envelope delivery.
 *
 * ```typescript
 * import { createSignalProtocolClient } from '@open-e2ee/signal-protocol-sdk';
 * import { expoStore } from '@open-e2ee/signal-protocol-sdk/local/store/expo';
 * import { convexRelay, type ConvexSignalRelayApi } from '@open-e2ee/signal-protocol-sdk/remote/relay/convex';
 * import { api } from '../convex/_generated/api';
 *
 * const signalApi = api.signal satisfies ConvexSignalRelayApi;
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
  ConvexSignalRelayServer,
  type ConvexSignalRelayApi,
  type ConvexSignalRelayOptions,
} from './relay';

export { ConvexSignalRelayServer } from './relay';
export type { ConvexSignalRelayApi, ConvexSignalRelayOptions } from './relay';
export { ConvexGroupServer } from './group-server';
export type { ConvexGroupServerApi } from './group-server';

// Type conversion utilities
export * from './types';

export interface ConvexSignalRelayFactoryOptions extends ConvexSignalRelayOptions {
  convex: ConstructorParameters<typeof ConvexSignalRelayServer>[0];
  api: ConvexSignalRelayApi;
}

export function convexRelay(options: ConvexSignalRelayFactoryOptions): ConvexSignalRelayServer {
  const { convex, api, ...relayOptions } = options;
  return new ConvexSignalRelayServer(convex, api, relayOptions);
}
