/**
 * Profile Key Manager
 *
 * Profile-key management for encrypted profile fields and avatars.
 * Profile keys are 32-byte AES keys used to encrypt profile data (avatars, names).
 *
 * Key distribution:
 * - Profile keys travel inside DataMessage (field 6) with regular messages
 * - The profile service contract receives encrypted fields, not profile keys
 * - When receiving a message, extract profileKey and store it for that sender
 *
 * Blob format:
 * ```
 * [nonce (12 bytes) || ciphertext || auth_tag (16 bytes)]
 * ```
 * The IV is embedded in the blob - no separate IV storage needed.
 *
 */

import type { ConvexReactClient } from 'convex/react';
import type { FunctionReference } from 'convex/server';
import { uploadBinary, downloadBinary } from '../utils/binary-transfer';
import { getProfileKeyStorage } from './storage';
import { bytesToBase64, base64ToBytes } from '../internal/crypto';
import { asBase64 } from '../types/utils';
import type { UpdateEncryptedProfileApi } from './update-service';
import { resolveSignalProtocolLogger, type ILogger } from '../logger';
import { deriveAccessKey } from '../internal/protocol/sealed-sender/delivery-token';
import type { ApplicationProfileData } from './cipher';

// Re-export pure crypto functions from testable module
export {};
export {
  generateProfileKey,
  encryptProfileData,
  decryptProfileData,
  PROFILE_KEY_SIZE,
  NONCE_SIZE,
  AUTH_TAG_SIZE,
} from './crypto';

// Import for local use in this module
import {
  generateProfileKey,
  PROFILE_KEY_SIZE,
  encryptProfileData,
  decryptProfileData,
} from './crypto';

// ============================================================================
// Constants
// ============================================================================

/** Storage key for own profile key */
const OWN_PROFILE_KEY_ID = 'signal_profile_key_v1';

export interface ProfileKeyApi {
  users: {
    getCurrentUser: FunctionReference<'query'>;
  };
  storage: {
    getBlobUrl: FunctionReference<'query'>;
    generateUploadUrl: FunctionReference<'mutation'>;
  };
  accounts: {
    setUnidentifiedAccess: FunctionReference<'mutation'>;
    getUnidentifiedAccessChecksum: FunctionReference<'query'>;
  };
}

export interface OwnEncryptedProfileSnapshot {
  name: string | null;
  about: string | null;
  avatarStorageId: string | null;
  applicationData: ApplicationProfileData | null;
}

export interface OwnEncryptedProfileStateStore {
  getOwnProfileSnapshot(userId: string): Promise<OwnEncryptedProfileSnapshot | null>;
}

export type ProfileKeyRotationStage =
  | 'load-profile'
  | 'encrypted-profile-upload'
  | 'unidentified-access-update'
  | 'avatar-upload'
  | 'local-key-commit';

export class ProfileKeyRotationError extends Error {
  readonly retryRequired = true;

  constructor(
    readonly stage: ProfileKeyRotationStage,
    cause: unknown
  ) {
    super(`Profile key rotation incomplete at ${stage}; retry is required`, { cause });
    this.name = 'ProfileKeyRotationError';
  }
}

// ============================================================================
// Own Profile Key (Secure Storage)
// ============================================================================

/**
 * Get the current user's profile key from the configured profile-key storage.
 *
 * The default React Native path uses `expo-secure-store`; the browser fallback
 * uses JavaScript-accessible localStorage and should be replaced when the host
 * requires a stronger storage boundary.
 *
 * @returns Profile key as Uint8Array, or null if not set
 */
export async function getOwnProfileKey(): Promise<Uint8Array | null> {
  const storage = getProfileKeyStorage();
  const stored = await storage.getItem(OWN_PROFILE_KEY_ID);
  if (!stored) {
    return null;
  }
  return base64ToBytes(asBase64(stored));
}

/**
 * Set own profile key in secure storage
 *
 * @param key - 32-byte profile key
 */
export async function setOwnProfileKey(key: Uint8Array): Promise<void> {
  if (key.length !== PROFILE_KEY_SIZE) {
    throw new Error(`Profile key must be ${PROFILE_KEY_SIZE} bytes, got ${key.length}`);
  }
  const storage = getProfileKeyStorage();
  await storage.setItem(OWN_PROFILE_KEY_ID, bytesToBase64(key));
}

/**
 * Get or create own profile key
 *
 * If no profile key exists, generates a new one and stores it.
 *
 * @returns Profile key as Uint8Array
 */
export async function getOrCreateOwnProfileKey(): Promise<Uint8Array> {
  const existing = await getOwnProfileKey();
  if (existing) {
    return existing;
  }

  const newKey = await generateProfileKey();
  await setOwnProfileKey(newKey);
  return newKey;
}

/**
 * Get own profile key as base64 string (for DataMessage.profileKey)
 *
 * @returns Profile key as base64 string
 */
export async function getOwnProfileKeyBase64(): Promise<string> {
  const key = await getOrCreateOwnProfileKey();
  return bytesToBase64(key);
}

// ============================================================================
// Profile Key Rotation
// ============================================================================

/**
 * Rotate own profile key (security event)
 *
 * Call this after revoking a recipient's profile access. It generates a new
 * key, re-encrypts the avatar, and uploads the new profile.
 *
 * Flow:
 * 1. Generate new profile key
 * 2. Re-encrypt and re-upload avatar with new key (mustReuploadAvatar: true)
 * 3. Only AFTER successful upload, store new key in secure storage
 *
 * This ensures the blocked user can't decrypt any future profile fetches.
 *
 * @param convex - Convex client for avatar re-upload
 * @returns New profile key (base64)
 *
 */
export async function rotateOwnProfileKey(
  convex: ConvexReactClient,
  api: ProfileKeyApi,
  encryptedProfileApi: UpdateEncryptedProfileApi,
  localStore: OwnEncryptedProfileStateStore,
  providedLogger?: ILogger
): Promise<string> {
  const logger = resolveSignalProtocolLogger(providedLogger);
  logger.info('Starting profile key rotation', { category: 'Profile' });

  // 1. Get current profile key (needed to decrypt existing avatar)
  const oldKey = await getOwnProfileKey();

  // 2. Generate new profile key
  const newKey = await generateProfileKey();
  const newKeyBase64 = bytesToBase64(newKey);

  let stage: ProfileKeyRotationStage = 'load-profile';
  try {
    const currentUser = await convex.query(api.users.getCurrentUser, {});
    if (!currentUser?.uuid) {
      throw new Error('Cannot rotate profile key without a current user UUID');
    }
    const localProfile = await localStore.getOwnProfileSnapshot(currentUser._id);

    // Upload every new-key artifact while the old key remains locally active.
    stage = 'encrypted-profile-upload';
    const { updateEncryptedProfile } = await import('./update-service');
    await updateEncryptedProfile({
      convex,
      api: encryptedProfileApi,
      uuid: currentUser.uuid,
      name: localProfile?.name || '',
      about: localProfile?.about ?? undefined,
      avatarStorageId: localProfile?.avatarStorageId ?? undefined,
      applicationData: localProfile?.applicationData ?? undefined,
      profileKey: newKey,
      logger,
    });

    stage = 'unidentified-access-update';
    const newAccessKey = await deriveAccessKey(newKey);
    const newAccessKeyBase64 = bytesToBase64(newAccessKey);
    await convex.mutation(api.accounts.setUnidentifiedAccess, {
      unidentifiedAccessKey: newAccessKeyBase64,
    });

    stage = 'avatar-upload';
    await reencryptAndUploadAvatar(
      oldKey,
      newKey,
      convex,
      api,
      localProfile?.avatarStorageId ?? null,
      logger
    );

    // The local active key is the transaction's commit marker.
    stage = 'local-key-commit';
    await getProfileKeyStorage().setItem(OWN_PROFILE_KEY_ID, newKeyBase64);
  } catch (cause) {
    logger.error('Profile key rotation incomplete; retry is mandatory', {
      category: 'Profile',
      error: cause instanceof Error ? cause : new Error('Unknown rotation failure'),
      data: { stage },
    });
    throw new ProfileKeyRotationError(stage, cause);
  }

  logger.info('Profile key rotation completed', { category: 'Profile' });

  return newKeyBase64;
}

/**
 * Re-encrypt current avatar with new profile key
 *
 * Reference pattern: Must re-upload avatar immediately during rotation
 * so blocked user can't decrypt any future profile fetches.
 *
 * If user has no avatar, this is a no-op.
 *
 * @param oldKey - Previous profile key (for decryption)
 * @param newKey - New profile key (for encryption)
 * @param convex - Convex client for storage operations
 */
async function reencryptAndUploadAvatar(
  oldKey: Uint8Array | null,
  newKey: Uint8Array,
  convex: ConvexReactClient,
  api: ProfileKeyApi,
  avatarKey: string | null,
  logger: Required<ILogger>
): Promise<void> {
  if (!avatarKey) {
    logger.debug('No avatar to re-encrypt during rotation', { category: 'Profile' });
    return;
  }

  // 2. Download encrypted blob from R2
  const downloadUrl = await convex.query(api.storage.getBlobUrl, {
    key: avatarKey,
  });

  if (!downloadUrl) {
    // Must throw - if we can't re-encrypt the avatar, we can't complete rotation
    // Returning silently would leave avatar encrypted with old key while new key is stored
    logger.error('Could not get download URL for own avatar during rotation', {
      category: 'Profile',
      data: { avatarKey },
    });
    throw new Error('Cannot rotate: failed to get avatar download URL');
  }

  // 2. Download encrypted blob
  const encryptedBytes = await downloadBinary(downloadUrl);

  // 3. Decrypt with OLD key
  if (!oldKey) {
    // This shouldn't happen - if we have an avatar, we should have a key
    logger.error('No old profile key for avatar decryption during rotation', {
      category: 'Profile',
    });
    throw new Error('Cannot rotate: missing old profile key');
  }

  const decryptedBytes = await decryptProfileData(oldKey, encryptedBytes);

  // 4. Re-encrypt with NEW key
  const reencryptedBytes = await encryptProfileData(newKey, decryptedBytes);

  // 5. Upload new blob with SAME R2 key (overwrites in place - no orphaned blobs!)
  const { url: uploadUrl } = await convex.mutation(api.storage.generateUploadUrl, {
    key: avatarKey,
  });
  const uploadResponse = await uploadBinary(uploadUrl, reencryptedBytes);
  if (!uploadResponse.ok) {
    throw new Error(`Failed to upload re-encrypted avatar: ${uploadResponse.statusText}`);
  }

  // 6. R2 key is unchanged (we overwrote the existing blob in place)

  // 7. No deletion needed - we overwrote in place!

  logger.info('Avatar re-encrypted and uploaded with new profile key', {
    category: 'Profile',
    data: { key: avatarKey },
  });
}
