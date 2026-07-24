/**
 * Encrypted Profile Module
 *
 * Profile-key management and encrypted profile-field handling.
 *
 * Key Distribution:
 * - Profile keys travel inside DataMessage (field 6) with regular messages
 * - The profile service contract receives encrypted fields, not profile keys
 *
 * Blob Format:
 * ```
 * [nonce (12 bytes) || ciphertext || auth_tag (16 bytes)]
 * ```
 *
 */

// Profile key generation
export {};
export { generateProfileKey } from './profile-key';

// Profile data encryption/decryption
export { encryptProfileData, decryptProfileData } from './profile-key';

// Own profile-key management
export {
  getOwnProfileKey,
  setOwnProfileKey,
  getOrCreateOwnProfileKey,
  getOwnProfileKeyBase64,
  rotateOwnProfileKey,
} from './profile-key';

// Application-selectable profile-key persistence
export {
  createMemoryStorage,
  getProfileKeyStorage,
  resetProfileKeyStorage,
  setProfileKeyStorage,
  type ProfileKeyStorage,
} from './storage';

// SDK-managed contact profile state contracts
export {
  UnidentifiedAccessMode,
  type UnidentifiedAccessModeType,
  type ContactProfileStateStore,
  type MutableContactProfileStateStore,
  verifyUnidentifiedAccessMode,
  storeReceivedProfileKey,
} from './contact-state';

// Profile cipher (padded field encryption/decryption)
export {
  encryptProfileName,
  decryptProfileName,
  encryptProfileString,
  decryptProfileString,
  encryptProfileField,
  decryptProfileField,
  padProfileField,
  unpadProfileField,
  encryptProfileAppData,
  decryptProfileAppData,
  PROFILE_NAME_PADDED_LENGTHS,
  PROFILE_ABOUT_PADDED_LENGTHS,
  PROFILE_EMOJI_PADDED_LENGTHS,
  PROFILE_APP_DATA_PADDED_LENGTHS,
  type ApplicationProfileData,
} from './cipher';

// Profile upload orchestration
export {
  updateEncryptedProfile,
  type UpdateEncryptedProfileApi,
  type UpdateEncryptedProfileParams,
} from './update-service';

// Advanced profile orchestration types
export type {
  ProfileKeyApi,
  OwnEncryptedProfileSnapshot,
  OwnEncryptedProfileStateStore,
  ProfileKeyRotationStage,
} from './profile-key';
export { ProfileKeyRotationError } from './profile-key';
