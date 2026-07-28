/**
 * Group change authorization
 *
 * Maps every field carried by DecryptedGroupChange to the normative §6.4
 * authorization action. Structural validation remains separate.
 *
 * @module groups/change-authorization
 */

import type { DecryptedGroup, DecryptedGroupChange } from './types';
import { canPerformAction, GroupAction, type GroupActionContext } from './access-control';
import {
  SERVICE_ID_ACI,
  SERVICE_ID_PNI,
} from '../protocol/zk/groups/uid-struct';
import { constantTimeEqual as bytesEqual } from '../crypto/utils';

function authorize(
  state: DecryptedGroup,
  change: DecryptedGroupChange,
  action: GroupAction,
  context: GroupActionContext,
  errors: string[]
): void {
  if (!canPerformAction(state, change.editorServiceIdBytes, action, context)) {
    errors.push(`Unauthorized action: ${action}`);
  }
}

/**
 * Validate every action in a change against the pre-change decrypted state.
 *
 * @returns one error per unauthorized action instance
 */
export function validateChangeAuthorization(
  state: DecryptedGroup,
  change: DecryptedGroupChange
): string[] {
  const errors: string[] = [];
  const check = (action: GroupAction, context: GroupActionContext = {}): void =>
    authorize(state, change, action, context, errors);

  for (const member of change.newMembers) {
    check(GroupAction.ADD_MEMBER, {
      targetAciBytes: member.aciBytes,
      assignedRole: member.role,
    });
  }
  for (const aciBytes of change.deleteMembers) {
    check(GroupAction.REMOVE_MEMBER, { targetAciBytes: aciBytes });
  }
  for (const modification of change.modifyMemberRoles) {
    check(GroupAction.MODIFY_MEMBER_ROLE, { targetAciBytes: modification.aciBytes });
  }
  for (const modification of change.modifiedProfileKeys) {
    check(GroupAction.MODIFY_MEMBER_PROFILE_KEY, { targetAciBytes: modification.aciBytes });
  }

  for (const member of change.newPendingMembers) {
    check(GroupAction.ADD_MEMBER_PENDING_PROFILE_KEY, {
      targetServiceIdBytes: member.serviceIdBytes,
      assignedRole: member.role,
    });
  }
  for (const removal of change.deletePendingMembers) {
    check(GroupAction.DELETE_MEMBER_PENDING_PROFILE_KEY, {
      targetServiceIdBytes: removal.serviceIdBytes,
    });
  }
  for (const promotion of change.promotePendingMembers) {
    check(GroupAction.PROMOTE_MEMBER_PENDING_PROFILE_KEY, {
      targetAciBytes: promotion.aciBytes,
    });
  }
  for (const promotion of change.promotePendingPniAciMembers) {
    check(GroupAction.PROMOTE_MEMBER_PENDING_PNI_ACI_PROFILE_KEY, {
      targetServiceIdBytes: new Uint8Array([
        SERVICE_ID_PNI,
        ...promotion.pniBytes,
      ]),
    });
    const pniPending = state.pendingMembers.find(
      (member) =>
        member.serviceIdBytes[0] === SERVICE_ID_PNI &&
        bytesEqual(member.serviceIdBytes.subarray(1), promotion.pniBytes)
    );
    const aciPending = state.pendingMembers.find(
      (member) =>
        member.serviceIdBytes[0] === SERVICE_ID_ACI &&
        bytesEqual(member.serviceIdBytes.subarray(1), promotion.aciBytes)
    );
    if (
      pniPending &&
      aciPending &&
      pniPending.role !== aciPending.role
    ) {
      errors.push(
        'Unauthorized action: PROMOTE_MEMBER_PENDING_PNI_ACI_PROFILE_KEY has conflicting pending alias roles'
      );
    }
  }

  if (change.newTitle !== undefined) check(GroupAction.MODIFY_TITLE);
  if (change.newAvatar !== undefined) check(GroupAction.MODIFY_AVATAR);
  if (change.newTimer !== undefined) check(GroupAction.MODIFY_DISAPPEARING_MESSAGES);
  if (change.newDescription !== undefined) check(GroupAction.MODIFY_DESCRIPTION);

  if (change.newAttributeAccess !== undefined) check(GroupAction.MODIFY_ATTRIBUTES_ACCESS);
  if (change.newMemberAccess !== undefined) check(GroupAction.MODIFY_MEMBERS_ACCESS);
  if (change.newInviteLinkAccess !== undefined) check(GroupAction.MODIFY_INVITE_LINK_ACCESS);
  if (change.newMemberLabelAccess !== undefined) check(GroupAction.MODIFY_MEMBER_LABEL_ACCESS);
  if (change['newInviteLinkPassword'] !== undefined) {
    check(GroupAction.MODIFY_INVITE_LINK_PASSWORD);
  }
  if (change.newIsAnnouncementGroup !== undefined) check(GroupAction.MODIFY_ANNOUNCEMENTS);

  for (const member of change.newRequestingMembers) {
    check(GroupAction.ADD_MEMBER_PENDING_ADMIN_APPROVAL, {
      targetAciBytes: member.aciBytes,
    });
  }
  for (const aciBytes of change.deleteRequestingMembers) {
    check(GroupAction.DELETE_MEMBER_PENDING_ADMIN_APPROVAL, { targetAciBytes: aciBytes });
  }
  for (const promotion of change.promoteRequestingMembers) {
    check(GroupAction.PROMOTE_MEMBER_PENDING_ADMIN_APPROVAL, {
      targetAciBytes: promotion.aciBytes,
    });
  }

  for (const member of change.newBannedMembers) {
    check(GroupAction.BAN_MEMBER, { targetServiceIdBytes: member.serviceIdBytes });
  }
  for (const member of change.deleteBannedMembers) {
    check(GroupAction.UNBAN_MEMBER, { targetServiceIdBytes: member.serviceIdBytes });
  }
  for (const modification of change.modifyMemberLabels) {
    check(GroupAction.MODIFY_MEMBER_LABEL, { targetAciBytes: modification.aciBytes });
  }
  if (change.terminate === true) check(GroupAction.TERMINATE_GROUP);

  return errors;
}
