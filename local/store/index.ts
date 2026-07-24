/**
 * Provider-neutral local-store contracts and adapters.
 *
 * ## Cross-Platform Design
 *
 * This barrel file exports ONLY platform-agnostic local-store code:
 * - Interfaces and types (DI contracts)
 * - MockSignalStore (for local development)
 *
 * Platform-specific adapters must be imported from their subpaths:
 * - `@open-e2ee/signal-protocol-sdk/local/store/expo` → Expo adapter
 * - `@open-e2ee/signal-protocol-sdk/local/store/web` → browser adapter
 * - `@open-e2ee/signal-protocol-sdk/local/store/react-native` → bare React Native adapter
 * - `@open-e2ee/signal-protocol-sdk/local/store/node` → Node.js adapter
 *
 * ## Usage
 *
 * ```typescript
 * // Types (any platform)
 * import type { ISignalLocalStore } from '@open-e2ee/signal-protocol-sdk/local/store';
 *
 * // Local development (any platform)
 * import { MockSignalStore } from '@open-e2ee/signal-protocol-sdk/local/store';
 *
 * // Platform-specific (choose one)
 * import { ExpoSignalStore, getKeyStorage } from '@open-e2ee/signal-protocol-sdk/local/store/expo';
 * import { IndexedDbSignalStore } from '@open-e2ee/signal-protocol-sdk/local/store/web';
 * import { ReactNativeSignalStore } from '@open-e2ee/signal-protocol-sdk/local/store/react-native';
 * import { NodeSignalStore } from '@open-e2ee/signal-protocol-sdk/local/store/node';
 * ```
 */

/**
 * Canonical local Signal Protocol state used by `SignalProtocolClient`.
 *
 * @see docs/INTERFACES.md
 */
export {};
export type { ISignalLocalStore } from '../../types';

// MessageRecord types for SESAME retry request support
export type { MessageRecord, IMessageRecordStore } from '../../types';

// Mock local store (for local development on any platform)
export { MockSignalStore } from './mock';
