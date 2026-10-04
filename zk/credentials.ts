/**
 * Public zkcredential API.
 *
 * Client integrations use this module for credential response verification,
 * presentation creation, and public-key serialization.
 */

export {};
export * from '../internal/protocol/zk/credentials';

export {
  serializeCredentialPublicKey,
  deserializeCredentialPublicKey,
} from '../internal/protocol/zk/credentials/credentials';
