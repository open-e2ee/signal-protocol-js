/**
 * SDK-managed contact profile state contracts and logic.
 *
 * The host app provides persistence. The Signal Protocol SDK owns the protocol semantics.
 */

import { resolveSignalProtocolLogger, type Logger } from '../logger';
import { base64ToBytes } from '../internal/crypto';
import { asBase64 } from '../types/utils';
import { PROFILE_KEY_SIZE } from './crypto';

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

export async function storeReceivedProfileKey(
  userId: string,
  profileKeyBase64: string,
  store: MutableContactProfileStateStore,
  providedLogger?: Logger
): Promise<{ stored: boolean; keyChanged: boolean }> {
  const logger = resolveSignalProtocolLogger(providedLogger);
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
