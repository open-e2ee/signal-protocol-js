/**
 * Public zkgroup API.
 *
 * Server-side wrappers and advanced app integrations should use this module
 * rather than importing Signal protocol internals directly.
 */

export {};
export * from '../internal/protocol/zk/groups';

export {
  uuidToBytes,
  serviceIdBinary,
  uidStructFromServiceId,
  type ServiceId,
  type ServiceIdKind,
  SERVICE_ID_ACI,
  SERVICE_ID_PNI,
} from '../internal/protocol/zk/groups/uid-struct';

export { computeProfileKeyVersion } from '../internal/protocol/zk/groups/profile-key-version';

export {
  serializeAuthCredentialResponse,
  deserializeAuthCredentialResponse,
  deserializeAuthCredentialPresentation,
  deserializeGroupPublicParams,
} from '../internal/protocol/zk/groups/auth-credential';
