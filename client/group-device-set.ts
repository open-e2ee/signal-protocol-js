/**
 * The listed device set of one send. A replay reads the device lists of the
 * members and of the sender's own account again, and this module finds how
 * the read changes the stored set: the stored targets that the read no longer
 * lists, and the listed devices that the send does not reach yet. It does not
 * post or encrypt.
 */

import { base64ToBytes } from '../internal/crypto';
import { deserializeSentMessage } from '../internal/protocol/sealed-sender/multi-recipient-message';
import type {
  OutgoingGroupDevice,
  StoredGroupSharedMessage,
  StoredOutgoingDeviceMessage,
  StoredOutgoingMessageIntent,
} from '../local/store/reliability';
import type { GroupMemberDevice } from '../remote/relay/types';
import { asBase64 } from '../types/utils';

/** The change that a new read of the member device lists makes to a stored group send. */
export interface ListedGroupDeviceChange {
  /**
   * The devices of other members that a stored pre-message or device message
   * targets, and that the read no longer lists.
   */
  unlisted: OutgoingGroupDevice[];
  /** The listed devices of other members that no stored device message targets. */
  added: GroupMemberDevice[];
}

/** The change that a new read of the sender's own device list makes to the sync copies of a send. */
export interface ListedOwnDeviceChange {
  /** The own devices that a stored sync copy targets, and that the read no longer lists. */
  unlisted: number[];
  /** The listed own devices that no stored sync copy targets, in list order. */
  added: number[];
}

/** One key for each device of an account. */
export function groupDeviceKey({ userId, deviceId }: OutgoingGroupDevice): string {
  return `${userId}\u0000${String(deviceId)}`;
}

/** The key of the device that a stored message targets. */
function targetKey(message: StoredOutgoingDeviceMessage): string {
  return groupDeviceKey({ userId: message.recipientUserId, deviceId: message.recipientDeviceId });
}

/**
 * The change that `listed` makes to the stored targets of `intent`. `listed`
 * holds the complete device list of each member of the send. The devices of
 * the sender's own account are not member targets.
 */
export function listedGroupDeviceChange(
  intent: StoredOutgoingMessageIntent,
  listed: readonly GroupMemberDevice[],
  senderUserId: string
): ListedGroupDeviceChange {
  const others = listed.filter((member) => member.userId !== senderUserId);
  const listedKeys = new Set(others.map(groupDeviceKey));
  const unlisted = new Map<string, OutgoingGroupDevice>();
  for (const message of [...(intent.preMessages ?? []), ...intent.deviceMessages]) {
    const key = targetKey(message);
    if (!listedKeys.has(key)) {
      unlisted.set(key, { userId: message.recipientUserId, deviceId: message.recipientDeviceId });
    }
  }
  const targeted = new Set(intent.deviceMessages.map(targetKey));
  return {
    unlisted: [...unlisted.values()],
    added: others.filter((member) => !targeted.has(groupDeviceKey(member))),
  };
}

/**
 * The change that `listedDeviceIds` makes to the stored sync copies of a
 * send. `listedDeviceIds` holds the sender's own listed devices other than
 * the sending device.
 */
export function listedOwnDeviceChange(
  syncMessages: readonly StoredOutgoingDeviceMessage[],
  listedDeviceIds: readonly number[]
): ListedOwnDeviceChange {
  const listed = new Set(listedDeviceIds);
  const stored = new Set(syncMessages.map((message) => message.recipientDeviceId));
  return {
    unlisted: [...stored].filter((deviceId) => !listed.has(deviceId)),
    added: [...listed].filter((deviceId) => !stored.has(deviceId)),
  };
}

/**
 * The devices that a stored shared body names, as keys, each with the
 * registration that the body names for it. The body names the devices of
 * each account in the order of `recipientUserIds`.
 */
export function sharedBodyDevices(shared: StoredGroupSharedMessage): Map<string, number> {
  const { recipients } = deserializeSentMessage(
    base64ToBytes(asBase64(shared.sentMessageBase64))
  );
  return new Map(
    recipients.flatMap(({ devices }, index) =>
      devices.map(({ deviceId, registrationId }): [string, number] => [
        groupDeviceKey({ userId: shared.recipientUserIds[index]!, deviceId }),
        registrationId,
      ])
    )
  );
}
