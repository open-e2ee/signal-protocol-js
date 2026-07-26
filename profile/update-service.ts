/**
 * Encrypted Profile Update Service
 *
 * Client-side encrypt-then-upload orchestration for versioned profiles.
 *
 * Encrypts profile fields with the user's profile key and uploads the
 * ciphertext to the profile service. The service contract does not accept
 * plaintext profile fields.
 */

import type { ConvexReactClient } from 'convex/react';
import type { FunctionReference } from 'convex/server';
import { getOrCreateOwnProfileKey } from './profile-key';
import { computeProfileKeyVersion } from '../internal/protocol/zk/groups/profile-key-version';
import { computeProfileKeyCommitment } from '../internal/protocol/zk/groups/profile-key-commitment';
import {
  encryptProfileName,
  encryptProfileString,
  encryptProfileAppData,
  PROFILE_ABOUT_PADDED_LENGTHS,
  PROFILE_EMOJI_PADDED_LENGTHS,
  type ApplicationProfileData,
} from './cipher';
import { uuidToBytes } from '../internal/protocol/zk/groups/uid-struct';
import { resolveSignalProtocolLogger, type ILogger } from '../logger';

// ============================================================================
// Types
// ============================================================================
export {};
export interface UpdateEncryptedProfileApi {
  setVersionedProfile: FunctionReference<'mutation'>;
}

export interface UpdateEncryptedProfileParams {
  /** Convex client for mutations */
  convex: ConvexReactClient;
  /** App-owned Convex function references for encrypted profile writes */
  api: UpdateEncryptedProfileApi;
  /** Signal Protocol ACI UUID string (e.g., '550e8400-e29b-41d4-a716-446655440000') */
  uuid: string;
  /** Required profile name (Signal Protocol wire name) */
  name: string;
  /** Optional about/bio text */
  about?: string;
  /** Optional about emoji */
  aboutEmoji?: string;
  /** Optional R2 storage ID for avatar */
  avatarStorageId?: string;
  /** Optional versioned opaque application data */
  applicationData?: ApplicationProfileData;
  /** Explicit key used by staged rotations before it becomes locally active. */
  profileKey?: Uint8Array;
  /** Optional logger for the profile-update flow. */
  logger?: ILogger;
}

// ============================================================================
// Update Function
// ============================================================================

/**
 * Encrypt and upload a versioned profile.
 *
 * Flow:
 * 1. Get own profile key
 * 2. Convert UUID to bytes
 * 3. Compute version + commitment
 * 4. Encrypt fields
 * 5. Upload to server
 *
 * @param params - Profile data to encrypt and upload
 */
export async function updateEncryptedProfile(params: UpdateEncryptedProfileParams): Promise<void> {
  const { convex, api, uuid, name, about, aboutEmoji, avatarStorageId, applicationData } = params;
  const logger = resolveSignalProtocolLogger(params.logger);

  // 1. Get own profile key
  const profileKey = params.profileKey ?? (await getOrCreateOwnProfileKey());

  // 2. Convert UUID string to 16-byte raw bytes
  const uidBytes = uuidToBytes(uuid);

  // 3. Compute version + commitment
  const version = computeProfileKeyVersion(profileKey, uidBytes);
  const commitment = computeProfileKeyCommitment(profileKey, uidBytes);

  // 4. Encrypt fields
  const encryptedName = await encryptProfileName(profileKey, name);

  const encryptedAbout = about
    ? await encryptProfileString(profileKey, about, PROFILE_ABOUT_PADDED_LENGTHS)
    : undefined;

  const encryptedEmoji = aboutEmoji
    ? await encryptProfileString(profileKey, aboutEmoji, PROFILE_EMOJI_PADDED_LENGTHS)
    : undefined;

  const encryptedAppData = applicationData
    ? await encryptProfileAppData(profileKey, applicationData)
    : undefined;

  // 5. Upload to server (Convex v.bytes() expects ArrayBuffer)
  await convex.mutation(api.setVersionedProfile, {
    version,
    name: encryptedName.buffer as ArrayBuffer,
    about: encryptedAbout ? (encryptedAbout.buffer as ArrayBuffer) : undefined,
    aboutEmoji: encryptedEmoji ? (encryptedEmoji.buffer as ArrayBuffer) : undefined,
    commitment: commitment.buffer as ArrayBuffer,
    avatar: avatarStorageId,
    appData: encryptedAppData ? (encryptedAppData.buffer as ArrayBuffer) : undefined,
  });

  logger.info('Encrypted profile uploaded', {
    category: 'Profile',
    data: { version: version.slice(0, 16) + '...' },
  });
}
