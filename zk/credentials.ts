/**
 * Public zkcredential API.
 *
 * This is the supported import surface for credential serialization and key
 * helpers used by server wrappers and advanced integrations.
 */

export {};
export * from '../internal/protocol/zk/credentials';

export {
  serializeCredentialPublicKey,
  deserializeCredentialPublicKey,
} from '../internal/protocol/zk/credentials/credentials';
