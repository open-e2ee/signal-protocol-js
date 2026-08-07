/**
 * Local secret vaults used to bootstrap local Signal Protocol stores.
 *
 * The contract only. Each implementation is bound to the platform whose secret
 * storage it wraps, and is imported from its own subpath —
 * `./local/vault/expo-secure-store` for Expo — so that naming the interface
 * does not drag a platform in behind it.
 */
export {};
export type { ISignalProtocolLocalSecretVault } from '../../types';
