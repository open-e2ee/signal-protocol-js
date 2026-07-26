/**
 * Provider-neutral relay contracts and adapters.
 *
 * `ISignalProtocolRelayServer` separates protocol operations from backend transport,
 * persistence, authentication, and authorization. Applications can supply
 * their own adapter or use a provider-specific subpath.
 *
 * ## Usage
 *
 * ```typescript
 * import type { ISignalProtocolRelayServer } from '@open-e2ee/signal-protocol-sdk/remote/relay';
 * import {
 *   convexRelay,
 *   type ConvexSignalProtocolRelayApi,
 * } from '@open-e2ee/signal-protocol-sdk/remote/relay/convex';
 * import { api } from '../convex/_generated/api';
 *
 * const signalApi = api.signal satisfies ConvexSignalProtocolRelayApi;
 * const relay: ISignalProtocolRelayServer = convexRelay({
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
  ISignalProtocolRelayServer,
  ISignalProtocolRemoteSenderStateStore,
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
export { MockSignalProtocolRelayServer } from './mock';
