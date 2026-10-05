/**
 * Unidentified access verification against the Convex account service.
 *
 * The contact state contracts in `./contact-state` do not depend on Convex.
 * This module holds the one operation that queries the Convex service, so
 * only the code that calls it loads the Convex types.
 */

import type { ConvexReactClient } from 'convex/react';
import { base64ToBytes, constantTimeEqual, hmac } from '../internal/crypto';
import { deriveAccessKey } from '../internal/protocol/sealed-sender/delivery-token';
import { asBase64 } from '../types/utils';
import {
  UnidentifiedAccessMode,
  type ContactProfileStateStore,
  type UnidentifiedAccessModeType,
} from './contact-state';
import type { ProfileKeyApi } from './profile-key';

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
  const localChecksumBytes = hmac(accessKey, new Uint8Array(32));
  const serverChecksumBytes = base64ToBytes(asBase64(serverResult.checksum));
  const match = constantTimeEqual(localChecksumBytes, serverChecksumBytes);

  const mode = match ? UnidentifiedAccessMode.ENABLED : UnidentifiedAccessMode.DISABLED;
  await store.updateUnidentifiedAccessMode(userId, mode);
  return mode;
}
