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
 * import type { SignalProtocolRelayServer } from '@open-e2ee/signal-protocol-sdk/remote/signal-relay';
 *
 * // Advanced integration with an application-owned client transport.
 * const relay: SignalProtocolRelayServer = appSignalProtocolRelayTransport;
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
  SignalProtocolRelayConnectionReason,
  RelayConnectionReason,
  SignalProtocolRelayConnectionState,
  RelayConnectionState,
  Unsubscribe,
  AccountIdentityProvisioning,
  AccountIdentityRotation,
  SignalProtocolRelayGroupServer,
  RelayGroupServer,
} from './types';

// The in-memory adapter is exported here for convenient local composition.

