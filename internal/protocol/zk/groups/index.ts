/**
 * Zero-knowledge group cryptography.
 *
 * Exposes credential, presentation, encryption, and parameter operations used
 * by the SDK's private-group layer.
 */
export {};
export {
  type ServiceId,
  type ServiceIdKind,
  SERVICE_ID_ACI,
  SERVICE_ID_PNI,
  serviceIdBinary,
  type UidStruct,
  uidStructFromServiceId,
  seedM1,
  calcM1,
} from './uid-struct';

export { type ProfileKeyStruct, profileKeyStructNew, seedM3, calcM3 } from './profile-key-struct';

export {
  UidEncryptionDomain,
  type UidEncKeyPair,
  type UidEncCiphertext,
  deriveUidEncKeyPair,
  encryptServiceId as uidEncryptServiceId,
  decryptServiceId as uidDecryptServiceId,
  verifySystemParams as verifyUidEncSystemParams,
} from './uid-encryption';

export {
  ProfileKeyEncryptionDomain,
  type ProfileKeyEncKeyPair,
  type ProfileKeyEncCiphertext,
  deriveProfileKeyEncKeyPair,
  encryptProfileKey as pkEncryptProfileKey,
  decryptProfileKey as pkDecryptProfileKey,
  verifySystemParams as verifyProfileKeyEncSystemParams,
} from './profile-key-encryption';

export {
  type GroupMasterKey,
  type GroupSecretParams,
  type GroupPublicParams,
  groupMasterKey,
  deriveGroupSecretParams,
  generateGroupSecretParams,
  getGroupPublicParams,
  encryptServiceId,
  decryptServiceId,
  encryptProfileKey,
  decryptProfileKey,
  encryptBlob,
  encryptBlobWithPadding,
  decryptBlob,
  decryptBlobWithPadding,
  GROUP_MASTER_KEY_LEN,
  GROUP_IDENTIFIER_LEN,
  RANDOMNESS_LEN,
  SECONDS_PER_DAY,
} from './group-params';

export {
  lizardEncode,
  lizardDecode,
  fromUniformBytesSingleElligator,
  decode253Bits,
} from './lizard';

export {
  type UuidCiphertext,
  type ProfileKeyCiphertext,
  encryptUuid,
  decryptUuid,
  encryptProfileKeyCiphertext,
  decryptProfileKeyCiphertext,
} from './client-zk-group-cipher';

export {
  type ServerSecretParams,
  type ServerPublicParams,
  generateServerSecretParams,
  getServerPublicParams,
  serverSign,
  serverVerifySignature,
  SIGNATURE_LEN,
} from './server-params';

export {
  type AuthCredentialWithPniResponse,
  type AuthCredentialWithPni,
  type AuthCredentialPresentation,
  issueAuthCredential,
  receiveAuthCredential,
  presentAuthCredential,
  verifyAuthCredentialPresentation,
} from './auth-credential';

export {
  type ExpiringProfileKeyCredentialResponse,
  type ExpiringProfileKeyCredential,
  type ProfileKeyCredentialPresentation,
  issueProfileKeyCredential,
  receiveProfileKeyCredential,
  presentProfileKeyCredential,
  verifyProfileKeyCredentialPresentation,
  serializeProfileKeyCredentialResponse,
  deserializeProfileKeyCredentialResponse,
  serializeProfileKeyCredentialPresentation,
  deserializeProfileKeyCredentialPresentation,
} from './profile-key-credential';

export {
  type GroupSendDerivedKeyPair,
  type GroupSendEndorsementsResponse,
  type ReceivedEndorsement,
  type GroupSendToken,
  type GroupSendFullToken,
  deriveForExpiration,
  defaultExpiration,
  issueEndorsements,
  receiveEndorsements,
  combineEndorsements,
  removeEndorsement,
  createFullToken,
  verifyFullToken,
  serializeEndorsementsResponse,
  deserializeEndorsementsResponse,
  serializeFullToken,
  deserializeFullToken,
} from './group-send-endorsement';
