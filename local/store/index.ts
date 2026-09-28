/**
 * Provider-neutral local-store contracts and adapters.
 *
 * ## Cross-Platform Design
 *
 * This barrel file exports ONLY platform-agnostic local-store code:
 * - Interfaces and types (DI contracts)
 * - InMemorySignalProtocolStore (for local development)
 *
 * Platform-specific adapters must be imported from their subpaths:
 * - `@open-e2ee/signal-protocol-sdk/local/store/expo` → Expo adapter
 * - `@open-e2ee/signal-protocol-sdk/local/store/react-native` → bare React Native SQLite adapter
 * - `@open-e2ee/signal-protocol-sdk/local/store/web` → browser adapter
 * - `@open-e2ee/signal-protocol-sdk/local/store/web-sqlite` → browser SQLite store in OPFS
 * - `@open-e2ee/signal-protocol-sdk/local/store/key-value` → key-value store over an application-supplied engine
 * - `@open-e2ee/signal-protocol-sdk/local/store/key-value/realm` → Realm backend for the key-value store
 * - `@open-e2ee/signal-protocol-sdk/local/store/node` → Node and Electron SQLite store
 *
 * ## Usage
 *
 * ```typescript
 * // Types (any platform)
 * import type { SignalProtocolLocalStore } from '@open-e2ee/signal-protocol-sdk/local/store';
 *
 * // Local development (any platform)
 * import { InMemorySignalProtocolStore } from '@open-e2ee/signal-protocol-sdk/local/store';
 *
 * // Platform-specific (choose one)
 * import { expoStore } from '@open-e2ee/signal-protocol-sdk/local/store/expo';
 * import { reactNativeStore } from '@open-e2ee/signal-protocol-sdk/local/store/react-native';
 * import { IndexedDbSignalProtocolStore } from '@open-e2ee/signal-protocol-sdk/local/store/web';
 * import { webSqliteStore } from '@open-e2ee/signal-protocol-sdk/local/store/web-sqlite';
 * import { KeyValueSignalProtocolStore } from '@open-e2ee/signal-protocol-sdk/local/store/key-value';
 * import { nodeStore } from '@open-e2ee/signal-protocol-sdk/local/store/node';
 * ```
 */

/**
 * Canonical local Signal Protocol state used by `SignalProtocolClient`.
 *
 * @see docs/INTERFACES.md
 */
export {};
export type { SignalProtocolLocalStore } from '../../types';

// MessageRecord types for SESAME retry request support
export type { MessageRecord, MessageRecordStore } from '../../types';

// In-memory local store (for local development on any platform)
export { InMemorySignalProtocolStore } from './memory';
