/**
 * Provider-neutral client contracts for relay operations.
 *
 * `SignalProtocolRelayServer` separates protocol operations from backend transport,
 * persistence, authentication, and authorization. Applications can supply
 * their own transport or use `createHostedSignalProtocolClient()`.
 *
 * ## Usage
 *
 * ```typescript
 * import type { SignalProtocolRelayServer } from '@open-e2ee/signal-protocol-sdk/remote/relay';
 *
 * // Advanced integration with an application-owned client transport.
 * const relay: SignalProtocolRelayServer = appRelayTransport;
 * ```
 */

/**
 * Relay operations for envelope delivery, device registration, and prekeys.
 *
 * @see docs/INTERFACES.md
 */
export {};
export type {
  SignalProtocolRelayServer,
  ContentKind,
  DeliveryClass,
  Envelope,
  DeviceInfo,
  DeviceType,
  DeviceRegistration,
  PreKeyUpload,
  PreKeyBundle,
  PreKeyInventory,
  PreKeyMetadata,
  RelayConnectionReason,
  RelayConnectionState,
  Unsubscribe,
  AccountIdentityProvisioning,
  AccountIdentityRotation,
  RelayGroupServer,
} from './types';

// The in-memory adapter is exported here for convenient local composition.

