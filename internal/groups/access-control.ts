/**
 * Group access control
 *
 * Authorization checks for group operations based on member roles and
 * access control settings.
 *
 * The plaintext client and ciphertext-only reference server both delegate to
 * the representation-independent policy in this module. The server identifies
 * principals by deterministic UID ciphertext and never decrypts group state.
 *
 * @module groups/access-control
 */

import {
  type DecryptedGroup,
  type DecryptedMember,
  MemberRole,
  AccessRequired,
  EnabledState,
} from './types';
import { constantTimeEqual as bytesEqual } from '../crypto/utils';
import { SERVICE_ID_ACI, SERVICE_ID_PNI } from '../protocol/zk/groups/uid-struct';

/**
 * Actions that a member can take on a group.
 * Each action has specific authorization requirements.
 */
export {};
export enum GroupAction {
  // Attribute modifications
  MODIFY_TITLE = 'MODIFY_TITLE',
  MODIFY_AVATAR = 'MODIFY_AVATAR',
  MODIFY_DESCRIPTION = 'MODIFY_DESCRIPTION',
  MODIFY_DISAPPEARING_MESSAGES = 'MODIFY_DISAPPEARING_MESSAGES',

  // Membership operations
  ADD_MEMBER = 'ADD_MEMBER',
  REMOVE_MEMBER = 'REMOVE_MEMBER',
  MODIFY_MEMBER_ROLE = 'MODIFY_MEMBER_ROLE',
  MODIFY_MEMBER_LABEL = 'MODIFY_MEMBER_LABEL',
  MODIFY_MEMBER_PROFILE_KEY = 'MODIFY_MEMBER_PROFILE_KEY',

  // Access control modifications (admin only)
  MODIFY_ATTRIBUTES_ACCESS = 'MODIFY_ATTRIBUTES_ACCESS',
  MODIFY_MEMBERS_ACCESS = 'MODIFY_MEMBERS_ACCESS',
  MODIFY_INVITE_LINK_ACCESS = 'MODIFY_INVITE_LINK_ACCESS',
  MODIFY_INVITE_LINK_PASSWORD = 'MODIFY_INVITE_LINK_PASSWORD',

  // Announcement mode (admin only)
  MODIFY_ANNOUNCEMENTS = 'MODIFY_ANNOUNCEMENTS',

  // Member-label access modification (admin only)
  MODIFY_MEMBER_LABEL_ACCESS = 'MODIFY_MEMBER_LABEL_ACCESS',

  // Ban operations (admin only)
  BAN_MEMBER = 'BAN_MEMBER',
  UNBAN_MEMBER = 'UNBAN_MEMBER',

  // Pending profile-key membership
  ADD_MEMBER_PENDING_PROFILE_KEY = 'ADD_MEMBER_PENDING_PROFILE_KEY',
  DELETE_MEMBER_PENDING_PROFILE_KEY = 'DELETE_MEMBER_PENDING_PROFILE_KEY',
  PROMOTE_MEMBER_PENDING_PROFILE_KEY = 'PROMOTE_MEMBER_PENDING_PROFILE_KEY',
  PROMOTE_MEMBER_PENDING_PNI_ACI_PROFILE_KEY = 'PROMOTE_MEMBER_PENDING_PNI_ACI_PROFILE_KEY',

  // Pending administrator approval
  ADD_MEMBER_PENDING_ADMIN_APPROVAL = 'ADD_MEMBER_PENDING_ADMIN_APPROVAL',
  DELETE_MEMBER_PENDING_ADMIN_APPROVAL = 'DELETE_MEMBER_PENDING_ADMIN_APPROVAL',
  PROMOTE_MEMBER_PENDING_ADMIN_APPROVAL = 'PROMOTE_MEMBER_PENDING_ADMIN_APPROVAL',

  // Group lifecycle
  TERMINATE_GROUP = 'TERMINATE_GROUP',

  // Message sending
  SEND_MESSAGE = 'SEND_MESSAGE',
}

/**
 * §6.9: a live group must retain at least one stored administrator.
 *
 * The state representations share the only fields this result-state invariant
 * needs, so clients and the ciphertext-only reference server use one check.
 */
export function satisfiesLiveGroupAdministratorInvariant(group: {
  terminated: boolean;
  members: ReadonlyArray<{ role: MemberRole }>;
}): boolean {
  return (
    group.terminated ||
    group.members.some((member) => member.role === MemberRole.ADMINISTRATOR)
  );
}

/**
 * Action-specific values needed to evaluate target-sensitive authorization.
 *
 * ACI targets are 16 raw UUID bytes. Pending profile-key targets are the full
 * 17-byte ServiceId because they may be either ACI or PNI entries.
 */
export interface GroupActionContext {
  targetAciBytes?: Uint8Array;
  targetServiceIdBytes?: Uint8Array;
  /** Initial role carried by ADD_MEMBER or ADD_MEMBER_PENDING_PROFILE_KEY. */
  assignedRole?: MemberRole;
}

/**
 * State-decidable facts consumed by the shared authorization policy.
 *
 * The client derives these from plaintext identifiers. A conforming server
 * derives them by comparing deterministic UID ciphertexts.
 */
export interface GroupActionAuthorizationContext {
  requesterIsBanned?: boolean;
  targetIsRequester?: boolean;
  /** Initial role carried by ADD_MEMBER or ADD_MEMBER_PENDING_PROFILE_KEY. */
  assignedRole?: MemberRole;
}

/**
 * Find a member in the group by their ACI (Account Identity).
 *
 * @param group - Decrypted group state
 * @param aciBytes - Member's ACI as 16 raw UUID bytes
 * @returns Member object if found, undefined otherwise
 */
export function findMember(
  group: DecryptedGroup,
  aciBytes: Uint8Array
): DecryptedMember | undefined {
  return group.members.find((member) => bytesEqual(member.aciBytes, aciBytes));
}

/**
 * Get a member's role in the group.
 *
 * @param group - Decrypted group state
 * @param aciBytes - Member's ACI as 16 raw UUID bytes
 * @returns Member's role, or UNKNOWN if not a member
 */
export function getMemberRole(group: DecryptedGroup, aciBytes: Uint8Array): MemberRole {
  const member = findMember(group, aciBytes);
  return member?.role ?? MemberRole.UNKNOWN;
}

/**
 * Check if a member role satisfies an access requirement.
 *
 * @param memberRole - The member's current role
 * @param requirement - The required access level
 * @returns True if the member role meets the requirement
 */
export function meetsAccessRequirement(
  memberRole: MemberRole,
  requirement: AccessRequired
): boolean {
  switch (requirement) {
    case AccessRequired.ANY:
      return true;

    case AccessRequired.MEMBER:
      return memberRole === MemberRole.DEFAULT || memberRole === MemberRole.ADMINISTRATOR;

    case AccessRequired.ADMINISTRATOR:
      // Only administrators can take the action
      return memberRole === MemberRole.ADMINISTRATOR;

    case AccessRequired.UNSATISFIABLE:
      // The feature is off, so no one can take the action
      return false;

    case AccessRequired.UNKNOWN:
    default:
      // Unknown access level, deny by default
      return false;
  }
}

/**
 * Whether a role-gated access-control field contains a legal §6.7 value.
 *
 * `ANY` remains part of the shared lattice for invite-link evaluation, but is
 * deliberately not a legal value for fields consumed through `meets()`.
 */
export function isRoleAccessRequirement(
  requirement: unknown
): requirement is AccessRequired.MEMBER | AccessRequired.ADMINISTRATOR {
  return (
    requirement === AccessRequired.MEMBER ||
    requirement === AccessRequired.ADMINISTRATOR
  );
}

/** Whether the invite-link mode contains a legal §6.7 value. */
export function isInviteLinkAccessRequirement(
  requirement: unknown
): requirement is
  | AccessRequired.UNSATISFIABLE
  | AccessRequired.ANY
  | AccessRequired.ADMINISTRATOR {
  return (
    requirement === AccessRequired.UNSATISFIABLE ||
    requirement === AccessRequired.ANY ||
    requirement === AccessRequired.ADMINISTRATOR
  );
}

/** Whether a stored member or pending-member role is legal under §6.8. */
export function isStoredMemberRole(
  role: unknown
): role is MemberRole.DEFAULT | MemberRole.ADMINISTRATOR {
  return role === MemberRole.DEFAULT || role === MemberRole.ADMINISTRATOR;
}

function canAssignInitialRole(
  requesterRole: MemberRole,
  assignedRole: MemberRole | undefined
): boolean {
  return (
    assignedRole === MemberRole.DEFAULT ||
    (assignedRole === MemberRole.ADMINISTRATOR &&
      requesterRole === MemberRole.ADMINISTRATOR)
  );
}

function meetsRoleAccessRequirement(
  memberRole: MemberRole,
  requirement: AccessRequired
): boolean {
  return (
    isRoleAccessRequirement(requirement) &&
    meetsAccessRequirement(memberRole, requirement)
  );
}

/**
 * Check whether a member can take a specific action on the group.
 * Core authorization function for all group operations.
 *
 * @param group - Decrypted group state
 * @param requesterServiceIdBytes - Requester's 17-byte ServiceId
 * @param action - The action to check
 * @param context - Target and invite-link facts required by some actions
 * @returns True if the member may take the action
 */
export function canPerformAction(
  group: DecryptedGroup,
  requesterServiceIdBytes: Uint8Array,
  action: GroupAction,
  context: GroupActionContext = {}
): boolean {
  if (
    requesterServiceIdBytes.length !== 17 ||
    (requesterServiceIdBytes[0] !== SERVICE_ID_ACI && requesterServiceIdBytes[0] !== SERVICE_ID_PNI)
  ) {
    return false;
  }

  const requesterAciBytes =
    requesterServiceIdBytes[0] === SERVICE_ID_ACI ? requesterServiceIdBytes.slice(1) : undefined;
  const role =
    requesterAciBytes === undefined ? MemberRole.UNKNOWN : getMemberRole(group, requesterAciBytes);
  const targetsRequesterAci =
    requesterAciBytes !== undefined &&
    context.targetAciBytes !== undefined &&
    bytesEqual(context.targetAciBytes, requesterAciBytes);
  const targetsRequesterServiceId =
    context.targetServiceIdBytes !== undefined &&
    bytesEqual(context.targetServiceIdBytes, requesterServiceIdBytes);

  return canRolePerformAction(group, role, action, {
    requesterIsBanned: isBanned(group, requesterServiceIdBytes),
    targetIsRequester: targetsRequesterAci || targetsRequesterServiceId,
    assignedRole: context.assignedRole,
  });
}

/**
 * Evaluate the normative §6.4 table from state-decidable facts.
 *
 * Keeping this policy independent of identifier representation lets the
 * plaintext client and ciphertext-only reference server enforce one table.
 */
export function canRolePerformAction(
  group: Pick<DecryptedGroup, 'accessControl' | 'isAnnouncementGroup'>,
  role: MemberRole,
  action: GroupAction,
  context: GroupActionAuthorizationContext = {}
): boolean {
  if (context.requesterIsBanned === true) {
    return false;
  }

  switch (action) {
    // Message sending
    case GroupAction.SEND_MESSAGE:
      // In announcement groups, only admins can send messages
      if (group.isAnnouncementGroup === EnabledState.ENABLED) {
        return role === MemberRole.ADMINISTRATOR;
      }
      return role === MemberRole.DEFAULT || role === MemberRole.ADMINISTRATOR;

    // Attribute modifications
    case GroupAction.MODIFY_TITLE:
    case GroupAction.MODIFY_AVATAR:
    case GroupAction.MODIFY_DESCRIPTION:
    case GroupAction.MODIFY_DISAPPEARING_MESSAGES:
      return meetsRoleAccessRequirement(role, group.accessControl.attributes);

    // Membership operations
    case GroupAction.ADD_MEMBER:
      return (
        canAssignInitialRole(role, context.assignedRole) &&
        (
          meetsRoleAccessRequirement(role, group.accessControl.members) ||
          (context.targetIsRequester === true &&
            group.accessControl.addFromInviteLink === AccessRequired.ANY)
        )
      );

    case GroupAction.REMOVE_MEMBER:
      return role === MemberRole.ADMINISTRATOR || context.targetIsRequester === true;

    case GroupAction.MODIFY_MEMBER_ROLE:
      return role === MemberRole.ADMINISTRATOR;

    case GroupAction.MODIFY_MEMBER_LABEL:
      return (
        context.targetIsRequester === true ||
        meetsRoleAccessRequirement(role, group.accessControl.memberLabel)
      );

    case GroupAction.MODIFY_MEMBER_PROFILE_KEY:
      return context.targetIsRequester === true;

    // Access control modifications (admin only)
    case GroupAction.MODIFY_ATTRIBUTES_ACCESS:
    case GroupAction.MODIFY_MEMBERS_ACCESS:
    case GroupAction.MODIFY_INVITE_LINK_ACCESS:
    case GroupAction.MODIFY_INVITE_LINK_PASSWORD:
    case GroupAction.MODIFY_MEMBER_LABEL_ACCESS:
      return role === MemberRole.ADMINISTRATOR;

    // Announcement mode (admin only)
    case GroupAction.MODIFY_ANNOUNCEMENTS:
      return role === MemberRole.ADMINISTRATOR;

    // Ban operations (admin only)
    case GroupAction.BAN_MEMBER:
    case GroupAction.UNBAN_MEMBER:
      return role === MemberRole.ADMINISTRATOR;

    case GroupAction.ADD_MEMBER_PENDING_PROFILE_KEY:
      return (
        canAssignInitialRole(role, context.assignedRole) &&
        meetsRoleAccessRequirement(role, group.accessControl.members)
      );

    case GroupAction.DELETE_MEMBER_PENDING_PROFILE_KEY:
      return role === MemberRole.ADMINISTRATOR || context.targetIsRequester === true;

    case GroupAction.PROMOTE_MEMBER_PENDING_PROFILE_KEY:
    case GroupAction.PROMOTE_MEMBER_PENDING_PNI_ACI_PROFILE_KEY:
      return context.targetIsRequester === true;

    case GroupAction.ADD_MEMBER_PENDING_ADMIN_APPROVAL:
      return (
        context.targetIsRequester === true &&
        group.accessControl.addFromInviteLink === AccessRequired.ADMINISTRATOR
      );

    case GroupAction.DELETE_MEMBER_PENDING_ADMIN_APPROVAL:
      return role === MemberRole.ADMINISTRATOR || context.targetIsRequester === true;

    case GroupAction.PROMOTE_MEMBER_PENDING_ADMIN_APPROVAL:
    case GroupAction.TERMINATE_GROUP:
      return role === MemberRole.ADMINISTRATOR;

    default:
      // Unknown action, deny by default
      return false;
  }
}

/**
 * Check if a member is an administrator of the group.
 * Convenience function for common authorization check.
 *
 * @param group - Decrypted group state
 * @param aciBytes - Member's ACI as bytes
 * @returns True if the member is an administrator
 */
export function isAdmin(group: DecryptedGroup, aciBytes: Uint8Array): boolean {
  return getMemberRole(group, aciBytes) === MemberRole.ADMINISTRATOR;
}

/**
 * Check if a user is a member of the group.
 * Convenience function to check membership status.
 *
 * @param group - Decrypted group state
 * @param aciBytes - User's ACI as bytes
 * @returns True if the user is a member
 */
export function isMember(group: DecryptedGroup, aciBytes: Uint8Array): boolean {
  return findMember(group, aciBytes) !== undefined;
}

/**
 * Check if a user has a pending membership invitation.
 *
 * @param group - Decrypted group state
 * @param serviceIdBytes - User's service ID (ACI or PNI) as bytes
 * @returns True if the user has a pending invitation
 */
export function isPending(group: DecryptedGroup, serviceIdBytes: Uint8Array): boolean {
  return group.pendingMembers.some((pending) => bytesEqual(pending.serviceIdBytes, serviceIdBytes));
}

/**
 * Check whether the group bans a user.
 *
 * @param group - Decrypted group state
 * @param serviceIdBytes - User's service ID (ACI or PNI) as bytes
 * @returns True if the group bans the user
 */
export function isBanned(group: DecryptedGroup, serviceIdBytes: Uint8Array): boolean {
  return group.bannedMembers.some((banned) => bytesEqual(banned.serviceIdBytes, serviceIdBytes));
}
