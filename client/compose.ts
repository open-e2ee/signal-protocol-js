import { SignalProtocolClient } from './client';
import type { SignalProtocolClientConfig, SignalProtocolConfig } from './config';
import type { SignalProtocolRemoteObjectStore } from '../remote/object-store';
import type { ISignalProtocolRelayServer } from '../remote/relay/types';
import type { ISignalProtocolLocalStore, ISignalProtocolManager } from '../types/api';

/**
 * Stable identity inputs for one Signal Protocol client instance.
 *
 * A client represents one app install for one account and one device.
 */
export interface SignalProtocolClientIdentityConfig {
  /** Canonical account/user identifier. */
  userId: string;
  /** Signal Protocol device identifier. Defaults to primary device 1. */
  deviceId?: number;
  /** Generate and sync both ACI and PNI key material when true. */
  enablePniKeys?: boolean;
}

/**
 * Concrete infrastructure adapters for a Signal Protocol client.
 *
 * Apps normally provide local storage and a relay. A remote object store is
 * only needed for encrypted attachments.
 */
export interface SignalProtocolClientAdapterConfig {
  /** Required local protocol store for the current runtime. */
  storage: ISignalProtocolLocalStore;
  /** Optional relay for server sync, prekeys, fanout, and subscriptions. */
  relay?: ISignalProtocolRelayServer;
  /** Optional brokered remote object store for encrypted attachments. */
  remoteObjectStore?: SignalProtocolRemoteObjectStore;
  /** Advanced protocol manager override for tests and specialized integrations. */
  protocolManager?: ISignalProtocolManager;
}

/**
 * App-facing Signal Protocol client composition contract.
 *
 * Keep account/device identity in `identity`, platform/backend choices in
 * `adapters`, and product security policy in `protocol`.
 *
 * The secure default protocol policy is strict post-quantum messaging with
 * the ML-KEM Braid specification. Most apps can omit `protocol`.
 *
 * @example Minimal local client
 * ```typescript
 * import { createSignalProtocolClient } from '@open-e2ee/signal-protocol-sdk';
 * import { mockStore } from '@open-e2ee/signal-protocol-sdk/local/store/mock';
 *
 * const signal = await createSignalProtocolClient({
 *   identity: { userId: 'alice' },
 *   adapters: { storage: mockStore() },
 * });
 * ```
 *
 * @example App client with relay
 * ```typescript
 * const signal = await createSignalProtocolClient({
 *   identity: { userId },
 *   adapters: { storage, relay },
 *   hooks: {
 *     onMessageDecrypted: async (message) => {
 *       await appMessages.insert({
 *         conversationId: message.conversationId,
 *         senderId: message.senderId,
 *         body: message.content,
 *       });
 *     },
 *   },
 * });
 *
 * await signal.syncToServer();
 * signal.startRelaySubscription();
 * ```
 */
export interface SignalProtocolClientCompositionOptions extends Omit<
  SignalProtocolClientConfig,
  | 'remoteObjectStore'
  | 'deviceId'
  | 'enablePniKeys'
  | 'protocol'
  | 'protocolManager'
  | 'protocolStrategy'
  | 'relay'
  | 'storage'
> {
  identity: SignalProtocolClientIdentityConfig;
  adapters: SignalProtocolClientAdapterConfig;
  protocol?: SignalProtocolConfig;
}

/**
 * Build the low-level `SignalProtocolClientConfig` from the public composition shape.
 *
 * Use this when an integration needs to inspect or pass through the underlying
 * config without constructing a client immediately.
 */
export function createSignalProtocolClientConfig(
  options: SignalProtocolClientCompositionOptions
): SignalProtocolClientConfig {
  const { adapters, identity, protocol, ...config } = options;

  return {
    ...config,
    remoteObjectStore: adapters.remoteObjectStore,
    deviceId: identity.deviceId,
    enablePniKeys: identity.enablePniKeys,
    protocolManager: adapters.protocolManager,
    protocol,
    relay: adapters.relay,
    storage: adapters.storage,
  };
}

/**
 * Create and initialize a Signal Protocol client from the app-facing composition shape.
 *
 * This is the recommended entry point for application code.
 *
 * @example
 * ```typescript
 * import { createSignalProtocolClient } from '@open-e2ee/signal-protocol-sdk';
 *
 * const signal = await createSignalProtocolClient({
 *   identity: { userId },
 *   adapters: { storage, relay },
 * });
 *
 * await signal.send('bob', 'hello');
 * ```
 */
export async function createSignalProtocolClient(
  options: SignalProtocolClientCompositionOptions
): Promise<SignalProtocolClient> {
  return SignalProtocolClient.create(
    options.identity.userId,
    createSignalProtocolClientConfig(options)
  );
}
