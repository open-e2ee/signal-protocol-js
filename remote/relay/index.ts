/**
 * Provider-neutral relay contracts and adapters.
 *
 * `ISignalRelayServer` separates protocol operations from backend transport,
 * persistence, authentication, and authorization. Applications can supply
 * their own adapter or use a provider-specific subpath.
 *
 * ## Usage
 *
 * ```typescript
 * import type { ISignalRelayServer } from '@open-e2ee/signal-protocol-sdk/remote/relay';
 * import {
 *   convexRelay,
 *   type ConvexSignalRelayApi,
 * } from '@open-e2ee/signal-protocol-sdk/remote/relay/convex';
 * import { api } from '../convex/_generated/api';
 *
 * const signalApi = api.signal satisfies ConvexSignalRelayApi;
 * const relay: ISignalRelayServer = convexRelay({
 *   convex,
 *   api: signalApi,
 *   currentUserId: userId,
 * });
 * ```
 */

/**
 * Relay operations for envelope delivery, device registration, and prekeys.
 *
 * @see docs/INTERFACES.md
 */
export {};
export type {
  ISignalRelayServer,
  ISignalRemoteSenderStateStore,
  Envelope,
  DeviceInfo,
  DeviceType,
  DeviceRegistration,
  PreKeyUpload,
  PreKeyBundle,
  Unsubscribe,
  AccountIdentityProvisioning,
  AccountIdentityRotation,
} from './types';

// Mock adapter is exported here for convenient local composition.
export { MockSignalRelayServer } from './mock';
