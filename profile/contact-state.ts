/**
 * SDK-managed contact profile state contracts and logic.
 *
 * The host app provides persistence; Signal owns the protocol semantics.
 */

import type { ConvexReactClient } from 'convex/react';
import { resolveSignalLogger, type ILogger } from '../logger';
import { base64ToBytes, constantTimeEqual } from '../internal/crypto';
import { deriveAccessKey } from '../internal/protocol/sealed-sender/delivery-token';
import { asBase64 } from '../types/utils';
import { PROFILE_KEY_SIZE } from './crypto';
import type { ProfileKeyApi } from './profile-key';

export const UnidentifiedAccessMode = {
  UNKNOWN: 0,
  ENABLED: 1,
  DISABLED: 2,
  UNRESTRICTED: 3,
} as const;

export type UnidentifiedAccessModeType =
  (typeof UnidentifiedAccessMode)[keyof typeof UnidentifiedAccessMode];

export interface ContactProfileStateStore {
  getContactProfileKey(userId: string): Promise<Uint8Array | null>;
  getUnidentifiedAccessMode(userId: string): Promise<UnidentifiedAccessModeType>;
  updateUnidentifiedAccessMode(userId: string, mode: UnidentifiedAccessModeType): Promise<void>;
}

export interface MutableContactProfileStateStore extends ContactProfileStateStore {
  storeContactProfileKey(
    userId: string,
    profileKeyBase64: string
  ): Promise<{ stored: boolean; previousProfileKeyBase64: string | null }>;
  deleteContactProfileKey(userId: string): Promise<void>;
}

export async function verifyUnidentifiedAccessMode(
  userId: string,
  targetUuid: string,
  convex: ConvexReactClient,
  api: ProfileKeyApi,
  store: ContactProfileStateStore
): Promise<UnidentifiedAccessModeType> {
  const serverResult = await convex.query(api.accounts.getUnidentifiedAccessChecksum, {
    targetUuid,
  });

  if (!serverResult) {
    await store.updateUnidentifiedAccessMode(userId, UnidentifiedAccessMode.DISABLED);
    return UnidentifiedAccessMode.DISABLED;
  }

  // Server unrestricted mode is authoritative and does not require a checksum.
  if (serverResult.unrestricted) {
    await store.updateUnidentifiedAccessMode(userId, UnidentifiedAccessMode.UNRESTRICTED);
    return UnidentifiedAccessMode.UNRESTRICTED;
  }

  if (!serverResult.checksum) {
    await store.updateUnidentifiedAccessMode(userId, UnidentifiedAccessMode.DISABLED);
    return UnidentifiedAccessMode.DISABLED;
  }

  const profileKey = await store.getContactProfileKey(userId);
  if (!profileKey) {
    await store.updateUnidentifiedAccessMode(userId, UnidentifiedAccessMode.DISABLED);
    return UnidentifiedAccessMode.DISABLED;
  }

  const accessKey = await deriveAccessKey(profileKey);
  const hmacKey = await crypto.subtle.importKey(
    'raw',
    accessKey as Uint8Array<ArrayBuffer>,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const localChecksum = await crypto.subtle.sign(
    'HMAC',
    hmacKey,
    new Uint8Array(32) as Uint8Array<ArrayBuffer>
  );

  const localChecksumBytes = new Uint8Array(localChecksum);
  const serverChecksumBytes = base64ToBytes(asBase64(serverResult.checksum));
  const match = constantTimeEqual(localChecksumBytes, serverChecksumBytes);

  const mode = match ? UnidentifiedAccessMode.ENABLED : UnidentifiedAccessMode.DISABLED;
  await store.updateUnidentifiedAccessMode(userId, mode);
  return mode;
}

export async function storeReceivedProfileKey(
  userId: string,
  profileKeyBase64: string,
  store: MutableContactProfileStateStore,
  providedLogger?: ILogger
): Promise<{ stored: boolean; keyChanged: boolean }> {
  const logger = resolveSignalLogger(providedLogger);
  const keyBytes = base64ToBytes(asBase64(profileKeyBase64));
  if (keyBytes.length !== PROFILE_KEY_SIZE) {
    logger.warn('Invalid profile key length, ignoring', {
      category: 'E2EE',
      data: { userId, length: keyBytes.length, expected: PROFILE_KEY_SIZE },
    });
    return { stored: false, keyChanged: false };
  }

  const result = await store.storeContactProfileKey(userId, profileKeyBase64);
  const keyChanged = result.previousProfileKeyBase64 !== profileKeyBase64;

  if (result.previousProfileKeyBase64 === profileKeyBase64) {
    logger.debug('Profile key unchanged, skipping update', {
      category: 'E2EE',
      data: { userId },
    });
    return { stored: false, keyChanged: false };
  }

  if (keyChanged) {
    await store.updateUnidentifiedAccessMode(userId, UnidentifiedAccessMode.UNKNOWN);
  }

  logger.debug('Stored profile key for contact', {
    category: 'E2EE',
    data: { userId, keyChanged },
  });

  return { stored: result.stored, keyChanged };
}
