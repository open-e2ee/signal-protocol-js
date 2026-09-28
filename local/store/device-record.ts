/**
 * How a store joins a SESAME device record with its session.
 *
 * A store keeps each device's identity pin and lifecycle fields apart from
 * the session that the protocol layer reads and writes under the device
 * address. A read joins the two, so the SESAME layer sees the session that
 * the protocol layer established.
 */

import { encodeCompositeIdentityV1, UNPINNED_DEVICE_IDENTITY_KEY } from '../../keys/identity';
import type { DeviceID, DeviceRecord } from '../../types';
import type { SessionRecord } from '../../types/session';

/**
 * Join a stored device with the session under its address. The identity pin
 * is a trust decision, so it comes from what was stored, not from the current
 * session. Re-deriving it would unpin a device as soon as its session is
 * archived.
 */
export function withSession(
  userId: string,
  deviceId: DeviceID,
  stored: DeviceRecord | null,
  session: SessionRecord | null
): DeviceRecord | null {
  if (!session) return stored;
  const now = Date.now();
  return {
    ...stored,
    userId,
    deviceId,
    identityKey: stored?.identityKey.length
      ? stored.identityKey
      : session.currentSession?.remoteIdentity
        ? encodeCompositeIdentityV1(session.currentSession.remoteIdentity)
        : UNPINNED_DEVICE_IDENTITY_KEY,
    session,
    createdAt: session.metadata?.createdAt ?? stored?.createdAt ?? now,
    updatedAt: now,
  };
}
