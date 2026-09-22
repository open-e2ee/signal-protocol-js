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
 * import { inMemoryRelay } from '@open-e2ee/signal-protocol-sdk/remote/relay/memory';
 *
 * // Development relay. Production connects to the OpenE2EE Signal Protocol Relay
 * // through `createHostedSignalProtocolClient()` from the package root.
 * const relay: ISignalProtocolRelayServer = inMemoryRelay();
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
  DeliveryClass,
  Envelope,
  DeviceInfo,
  DeviceType,
  DeviceRegistration,
  PreKeyUpload,
  PreKeyBundle,
  PreKeyInventory,
  PreKeyMetadata,
  Unsubscribe,
  AccountIdentityProvisioning,
  AccountIdentityRotation,
  IRelayGroupServer,
} from './types';

// The in-memory adapter is exported here for convenient local composition.
export { InMemorySignalProtocolRelayServer } from './memory';
