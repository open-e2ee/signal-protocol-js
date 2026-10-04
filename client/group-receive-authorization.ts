import { constantTimeEqual } from '../internal/crypto';
import { GroupAction, canPerformAction } from '../internal/groups/access-control';
import { extractGroupId } from '../internal/groups/group-id';
import type { GroupStateStore } from '../internal/groups/manager';
import { GROUP_IDENTIFIER_LEN } from '../internal/protocol/zk/groups/group-params';
import { SERVICE_ID_ACI, serviceIdBinary } from '../internal/protocol/zk/groups/uid-struct';

// A managed group's raw ID is its group identifier in lowercase hex.
const MANAGED_GROUP_ID = new RegExp(`^[0-9a-f]{${GROUP_IDENTIFIER_LEN * 2}}$`);

export type GroupReceiveAuthorizer = (
  groupId: string,
  senderId: string,
  contentType: 'message' | 'distribution'
) => Promise<void>;

/** Check managed group content against verified local membership and roles. */
export function createGroupReceiveAuthorizer(
  store: GroupStateStore,
  localAci: Uint8Array | undefined,
  resolveAcis: ((userIds: string[]) => Promise<Map<string, Uint8Array>>) | undefined
): GroupReceiveAuthorizer {
  return async (groupId, senderId, contentType) => {
    const rawGroupId = extractGroupId(groupId);
    // Other IDs name ad-hoc Sender Keys. A managed ID without a stored master
    // key has no verified state, so the check below rejects it.
    if (!MANAGED_GROUP_ID.test(rawGroupId)) return;
    if (!resolveAcis || !localAci) {
      throw new Error('Group reception requires authenticated account ACI resolution');
    }
    const state = await store.getGroupState(rawGroupId);
    const senderAci = (await resolveAcis([senderId])).get(senderId);
    if (
      !state || !senderAci ||
      !state.members.some((member) => constantTimeEqual(member.aciBytes, senderAci)) ||
      !state.members.some((member) => constantTimeEqual(member.aciBytes, localAci))
    ) {
      throw new Error('Group sender and recipient must be members of the verified local group');
    }
    if (
      contentType === 'message' &&
      !canPerformAction(
        state,
        serviceIdBinary({ kind: SERVICE_ID_ACI, uuid: senderAci }),
        GroupAction.SEND_MESSAGE
      )
    ) {
      throw new Error('Group sender cannot send messages under the verified group permissions');
    }
  };
}
