/**
 * Public zkgroup API.
 *
 * Client integrations use this module for group encryption, credential requests,
 * response verification, and presentation creation.
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

export { deserializeAuthCredentialResponse } from '../internal/protocol/zk/groups/auth-credential';

