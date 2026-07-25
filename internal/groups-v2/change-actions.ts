/**
 * Group Change Application
 *
 * Pure functions for applying DecryptedGroupChange operations to DecryptedGroup state.
 *
 * Operations are applied in ascending DecryptedGroupChange field-number order.
 * That ordering is this SDK's choice, taken from the proto field numbering for
 * determinism; the Signal Protocol group specifications do not define a
 * normative application order.
 *
 * @module change-actions
 */

import {
  type DecryptedGroup,
  type DecryptedMember,
  type DecryptedGroupChange,
  MemberRole,
  AccessRequired,
  EnabledState,
} from './types';
import { constantTimeEqual as bytesEqual } from '../crypto/utils';

/**
 * Deep clone a DecryptedGroup to ensure immutability.
 */
export {};
function cloneGroup(group: DecryptedGroup): DecryptedGroup {
  return {
    ...group,
    members: group.members.map((m) => ({ ...m })),
    pendingMembers: group.pendingMembers.map((m) => ({ ...m })),
    requestingMembers: group.requestingMembers.map((m) => ({ ...m })),
    bannedMembers: group.bannedMembers.map((m) => ({ ...m })),
    accessControl: { ...group.accessControl },
  };
}

/**
 * Apply a DecryptedGroupChange to a DecryptedGroup state.
 *
 * This is a pure function that returns a new state object without mutating the input.
 * Changes are applied in ascending DecryptedGroupChange proto field-number
 * order. See the module header: this ordering is chosen for determinism, not
 * mandated by a specification.
 *
 * @param state - Current group state
 * @param change - Change to apply
 * @returns New group state with changes applied
 * @throws Error if revision is not sequential
 */
export function applyGroupChange(
  state: DecryptedGroup,
  change: DecryptedGroupChange
): DecryptedGroup {
  // Validate revision is sequential
  if (change.revision !== state.revision + 1) {
    throw new Error(`Invalid revision: expected ${state.revision + 1}, got ${change.revision}`);
  }

  // Start with a deep clone to ensure immutability
  const newState = cloneGroup(state);

  // Field 3: Add new members
  if (change.newMembers) {
    for (const newMember of change.newMembers) {
      // Skip if already a member
      const exists = newState.members.some((m) => bytesEqual(m.aciBytes, newMember.aciBytes));
      if (!exists) {
        newState.members = [...newState.members, { ...newMember }];
      }
    }
  }

  // Field 4: Delete members
  if (change.deleteMembers) {
    for (const aciBytes of change.deleteMembers) {
      newState.members = newState.members.filter((m) => !bytesEqual(m.aciBytes, aciBytes));
    }
  }

  // Field 5: Modify member roles
  if (change.modifyMemberRoles) {
    for (const modification of change.modifyMemberRoles) {
      const memberIndex = newState.members.findIndex((m) =>
        bytesEqual(m.aciBytes, modification.aciBytes)
      );
      if (memberIndex !== -1) {
        newState.members[memberIndex] = {
          ...newState.members[memberIndex],
          role: modification.role,
        };
      }
    }
  }

  // Field 6: Modify profile keys
  if (change.modifiedProfileKeys) {
    for (const modification of change.modifiedProfileKeys) {
      const memberIndex = newState.members.findIndex((m) =>
        bytesEqual(m.aciBytes, modification.aciBytes)
      );
      if (memberIndex !== -1) {
        newState.members[memberIndex] = {
          ...newState.members[memberIndex],
          profileKey: modification.profileKey,
        };
      }
    }
  }

  // Field 7: Add new pending members
  if (change.newPendingMembers) {
    for (const newPending of change.newPendingMembers) {
      newState.pendingMembers = [...newState.pendingMembers, { ...newPending }];
    }
  }

  // Field 8: Delete pending members
  if (change.deletePendingMembers) {
    for (const removal of change.deletePendingMembers) {
      newState.pendingMembers = newState.pendingMembers.filter(
        (m) => !bytesEqual(m.serviceIdBytes, removal.serviceIdBytes)
      );
    }
  }

  // Field 9: Promote pending members
  if (change.promotePendingMembers) {
    for (const promotion of change.promotePendingMembers) {
      // Remove from pending
      const pending = newState.pendingMembers.find((m) =>
        bytesEqual(m.serviceIdBytes, promotion.aciBytes)
      );
      if (pending) {
        newState.pendingMembers = newState.pendingMembers.filter(
          (m) => !bytesEqual(m.serviceIdBytes, promotion.aciBytes)
        );

        // Add to members
        const newMember: DecryptedMember = {
          aciBytes: promotion.aciBytes,
          role: MemberRole.DEFAULT,
          profileKey: promotion.profileKey,
          joinedAtRevision: change.revision,
          pniBytes: new Uint8Array(0),
          labelEmoji: '',
          labelString: '',
        };
        newState.members = [...newState.members, newMember];
      }
    }
  }

  // Field 10: New title
  if (change.newTitle !== undefined) {
    newState.title = change.newTitle.value;
  }

  // Field 11: New avatar
  if (change.newAvatar !== undefined) {
    newState.avatar = change.newAvatar.value;
  }

  // Field 12: New disappearing messages timer
  if (change.newTimer !== undefined) {
    newState.disappearingMessagesTimer = change.newTimer;
  }

  // Field 13: New attribute access
  if (
    change.newAttributeAccess !== undefined &&
    change.newAttributeAccess !== AccessRequired.UNKNOWN
  ) {
    newState.accessControl = {
      ...newState.accessControl,
      attributes: change.newAttributeAccess,
    };
  }

  // Field 14: New member access
  if (change.newMemberAccess !== undefined && change.newMemberAccess !== AccessRequired.UNKNOWN) {
    newState.accessControl = {
      ...newState.accessControl,
      members: change.newMemberAccess,
    };
  }

  // Field 15: New invite link access
  if (
    change.newInviteLinkAccess !== undefined &&
    change.newInviteLinkAccess !== AccessRequired.UNKNOWN
  ) {
    newState.accessControl = {
      ...newState.accessControl,
      addFromInviteLink: change.newInviteLinkAccess,
    };
  }

  // Field 16: New requesting members
  if (change.newRequestingMembers) {
    for (const newRequesting of change.newRequestingMembers) {
      newState.requestingMembers = [...newState.requestingMembers, { ...newRequesting }];
    }
  }

  // Field 17: Delete requesting members
  if (change.deleteRequestingMembers) {
    for (const aciBytes of change.deleteRequestingMembers) {
      newState.requestingMembers = newState.requestingMembers.filter(
        (m) => !bytesEqual(m.aciBytes, aciBytes)
      );
    }
  }

  // Field 18: Promote requesting members
  if (change.promoteRequestingMembers) {
    for (const approval of change.promoteRequestingMembers) {
      // Find requesting member to preserve their profile key
      const requestingMember = newState.requestingMembers.find((m) =>
        bytesEqual(m.aciBytes, approval.aciBytes)
      );

      // Remove from requesting
      newState.requestingMembers = newState.requestingMembers.filter(
        (m) => !bytesEqual(m.aciBytes, approval.aciBytes)
      );

      // Add to members (preserve profile key from requesting entry)
      const newMember: DecryptedMember = {
        aciBytes: approval.aciBytes,
        role: approval.role,
        profileKey: requestingMember?.profileKey ?? new Uint8Array(0),
        joinedAtRevision: change.revision,
        pniBytes: new Uint8Array(0),
        labelEmoji: '',
        labelString: '',
      };
      newState.members = [...newState.members, newMember];
    }
  }

  // Field 19: New invite link password
  if (change.newInviteLinkPassword !== undefined) {
    newState.inviteLinkPassword = change.newInviteLinkPassword;
  }

  // Field 20: New description
  if (change.newDescription !== undefined) {
    newState.description = change.newDescription.value;
  }

  // Field 21: New announcement group setting
  if (
    change.newIsAnnouncementGroup !== undefined &&
    change.newIsAnnouncementGroup !== EnabledState.UNKNOWN
  ) {
    newState.isAnnouncementGroup = change.newIsAnnouncementGroup;
  }

  // Field 22: New banned members
  if (change.newBannedMembers) {
    for (const newBanned of change.newBannedMembers) {
      newState.bannedMembers = [...newState.bannedMembers, { ...newBanned }];
    }
  }

  // Field 23: Delete banned members
  if (change.deleteBannedMembers) {
    for (const removal of change.deleteBannedMembers) {
      newState.bannedMembers = newState.bannedMembers.filter(
        (m) => !bytesEqual(m.serviceIdBytes, removal.serviceIdBytes)
      );
    }
  }

  // Field 24: Promote pending PNI/ACI members
  if (change.promotePendingPniAciMembers) {
    for (const promotion of change.promotePendingPniAciMembers) {
      // Promotion is valid only for an existing pending PNI member.
      const pendingIndex = newState.pendingMembers.findIndex((m) =>
        bytesEqual(m.serviceIdBytes, promotion.pniBytes)
      );
      if (pendingIndex === -1) {
        throw new Error(
          'INVALID_CHANGE: Cannot promote PNI member — PNI not found in pending list'
        );
      }

      newState.pendingMembers = newState.pendingMembers.filter((_, i) => i !== pendingIndex);

      // Add to members with ACI
      const newMember: DecryptedMember = {
        aciBytes: promotion.aciBytes,
        role: MemberRole.DEFAULT,
        profileKey: promotion.profileKey,
        joinedAtRevision: change.revision,
        pniBytes: new Uint8Array(0),
        labelEmoji: '',
        labelString: '',
      };
      newState.members = [...newState.members, newMember];
    }
  }

  // Field 26: Modify member labels
  if (change.modifyMemberLabels) {
    for (const modification of change.modifyMemberLabels) {
      const memberIndex = newState.members.findIndex((m) =>
        bytesEqual(m.aciBytes, modification.aciBytes)
      );
      if (memberIndex !== -1) {
        newState.members[memberIndex] = {
          ...newState.members[memberIndex],
          labelEmoji: modification.labelEmoji ?? '',
          labelString: modification.labelString ?? '',
        };
      }
    }
  }

  // Update revision
  newState.revision = change.revision;

  return newState;
}

/**
 * Validate a DecryptedGroupChange against current group state.
 *
 * @param state - Current group state
 * @param change - Change to validate
 * @returns Array of validation error strings (empty if valid)
 */
export function validateChange(state: DecryptedGroup, change: DecryptedGroupChange): string[] {
  const errors: string[] = [];

  // Check revision is sequential
  if (change.revision !== state.revision + 1) {
    errors.push(`Invalid revision: expected ${state.revision + 1}, got ${change.revision}`);
  }

  // Validate deleted members exist
  if (change.deleteMembers) {
    for (const aciBytes of change.deleteMembers) {
      const exists = state.members.some((m) => bytesEqual(m.aciBytes, aciBytes));
      if (!exists) {
        errors.push('Attempted to delete non-existent member');
      }
    }
  }

  // Validate new members aren't already members
  if (change.newMembers) {
    for (const newMember of change.newMembers) {
      const exists = state.members.some((m) => bytesEqual(m.aciBytes, newMember.aciBytes));
      if (exists) {
        errors.push('Attempted to add existing member');
      }
    }
  }

  // Validate modified member roles reference existing members
  if (change.modifyMemberRoles) {
    for (const modification of change.modifyMemberRoles) {
      const exists = state.members.some((m) => bytesEqual(m.aciBytes, modification.aciBytes));
      if (!exists) {
        errors.push('Attempted to modify role of non-existent member');
      }
    }
  }

  // Validate modified profile keys reference existing members
  if (change.modifiedProfileKeys) {
    for (const modification of change.modifiedProfileKeys) {
      const exists = state.members.some((m) => bytesEqual(m.aciBytes, modification.aciBytes));
      if (!exists) {
        errors.push('Attempted to modify profile key of non-existent member');
      }
    }
  }

  // Validate deleted pending members exist
  if (change.deletePendingMembers) {
    for (const removal of change.deletePendingMembers) {
      const exists = state.pendingMembers.some((m) =>
        bytesEqual(m.serviceIdBytes, removal.serviceIdBytes)
      );
      if (!exists) {
        errors.push('Attempted to delete non-existent pending member');
      }
    }
  }

  // Validate promoted pending members exist
  if (change.promotePendingMembers) {
    for (const promotion of change.promotePendingMembers) {
      const exists = state.pendingMembers.some((m) =>
        bytesEqual(m.serviceIdBytes, promotion.aciBytes)
      );
      if (!exists) {
        errors.push('Attempted to promote non-existent pending member');
      }
    }
  }

  // Validate deleted requesting members exist
  if (change.deleteRequestingMembers) {
    for (const aciBytes of change.deleteRequestingMembers) {
      const exists = state.requestingMembers.some((m) => bytesEqual(m.aciBytes, aciBytes));
      if (!exists) {
        errors.push('Attempted to delete non-existent requesting member');
      }
    }
  }

  // Validate promoted requesting members exist
  if (change.promoteRequestingMembers) {
    for (const approval of change.promoteRequestingMembers) {
      const exists = state.requestingMembers.some((m) => bytesEqual(m.aciBytes, approval.aciBytes));
      if (!exists) {
        errors.push('Attempted to promote non-existent requesting member');
      }
    }
  }

  // Validate deleted banned members exist
  if (change.deleteBannedMembers) {
    for (const removal of change.deleteBannedMembers) {
      const exists = state.bannedMembers.some((m) =>
        bytesEqual(m.serviceIdBytes, removal.serviceIdBytes)
      );
      if (!exists) {
        errors.push('Attempted to unban non-existent banned member');
      }
    }
  }

  // Validate promoted PNI/ACI members exist
  if (change.promotePendingPniAciMembers) {
    for (const promotion of change.promotePendingPniAciMembers) {
      const exists = state.pendingMembers.some((m) =>
        bytesEqual(m.serviceIdBytes, promotion.pniBytes)
      );
      if (!exists) {
        errors.push('Attempted to promote PNI/ACI member not in pending list');
      }
    }
  }

  // Validate modified member labels reference existing members
  if (change.modifyMemberLabels) {
    for (const modification of change.modifyMemberLabels) {
      const exists = state.members.some((m) => bytesEqual(m.aciBytes, modification.aciBytes));
      if (!exists) {
        errors.push('Attempted to modify labels of non-existent member');
      }
    }
  }

  return errors;
}
