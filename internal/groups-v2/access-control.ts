/**
 * GroupsV2 Access Control
 *
 * Authorization checks for group operations based on member roles and
 * access control settings.
 *
 * These are client-local checks over already-decrypted group state. They use
 * the role and access-required vocabulary of the Signal Protocol group system,
 * but they are not that system's enforcement model: there, the server
 * validates each change against embedded zero-knowledge presentations. Here
 * the server sees only opaque state and a version number, so these checks
 * bind an honest client, not a hostile one.
 *
 * @module groups-v2/access-control
 */

import {
  type DecryptedGroup,
  type DecryptedMember,
  MemberRole,
  AccessRequired,
  EnabledState,
} from './types';
import { constantTimeEqual as bytesEqual } from '../crypto/utils';

/**
 * Actions that can be performed on a group.
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

  // Access control modifications (admin only)
  MODIFY_ATTRIBUTES_ACCESS = 'MODIFY_ATTRIBUTES_ACCESS',
  MODIFY_MEMBERS_ACCESS = 'MODIFY_MEMBERS_ACCESS',
  MODIFY_INVITE_LINK_ACCESS = 'MODIFY_INVITE_LINK_ACCESS',
  MODIFY_INVITE_LINK_PASSWORD = 'MODIFY_INVITE_LINK_PASSWORD',

  // Announcement mode (admin only)
  MODIFY_ANNOUNCEMENTS = 'MODIFY_ANNOUNCEMENTS',

  // Ban operations (admin only)
  BAN_MEMBER = 'BAN_MEMBER',
  UNBAN_MEMBER = 'UNBAN_MEMBER',

  // Message sending
  SEND_MESSAGE = 'SEND_MESSAGE',
}

/**
 * Find a member in the group by their ACI (Account Identity).
 *
 * @param group - Decrypted group state
 * @param aciBytes - Member's ACI as bytes (32 bytes UUID)
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
 * @param aciBytes - Member's ACI as bytes
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
    case AccessRequired.MEMBER:
      // Any member (DEFAULT or ADMINISTRATOR) can perform the action
      return memberRole === MemberRole.DEFAULT || memberRole === MemberRole.ADMINISTRATOR;

    case AccessRequired.ADMINISTRATOR:
      // Only administrators can perform the action
      return memberRole === MemberRole.ADMINISTRATOR;

    case AccessRequired.UNSATISFIABLE:
      // Feature is disabled, no one can perform the action
      return false;

    case AccessRequired.UNKNOWN:
    default:
      // Unknown access level, deny by default
      return false;
  }
}

/**
 * Check if a member can perform a specific action on the group.
 * Core authorization function for all group operations.
 *
 * @param group - Decrypted group state
 * @param aciBytes - Member's ACI as bytes
 * @param action - The action to check
 * @returns True if the member is authorized to perform the action
 */
export function canPerformAction(
  group: DecryptedGroup,
  aciBytes: Uint8Array,
  action: GroupAction
): boolean {
  const member = findMember(group, aciBytes);
  if (!member) {
    // Not a member, cannot perform any action
    return false;
  }

  const role = member.role;

  switch (action) {
    // Message sending
    case GroupAction.SEND_MESSAGE:
      // In announcement groups, only admins can send messages
      if (group.isAnnouncementGroup === EnabledState.ENABLED) {
        return role === MemberRole.ADMINISTRATOR;
      }
      // Otherwise, any member can send messages
      return true;

    // Attribute modifications
    case GroupAction.MODIFY_TITLE:
    case GroupAction.MODIFY_AVATAR:
    case GroupAction.MODIFY_DESCRIPTION:
    case GroupAction.MODIFY_DISAPPEARING_MESSAGES:
      return meetsAccessRequirement(role, group.accessControl.attributes);

    // Membership operations
    case GroupAction.ADD_MEMBER:
      return meetsAccessRequirement(role, group.accessControl.members);

    case GroupAction.REMOVE_MEMBER:
      // Admins can remove any member
      // Non-admins can only remove themselves (self-leave)
      return role === MemberRole.ADMINISTRATOR;

    case GroupAction.MODIFY_MEMBER_ROLE:
    case GroupAction.MODIFY_MEMBER_LABEL:
      // Only admins can modify member roles and labels
      return role === MemberRole.ADMINISTRATOR;

    // Access control modifications (admin only)
    case GroupAction.MODIFY_ATTRIBUTES_ACCESS:
    case GroupAction.MODIFY_MEMBERS_ACCESS:
    case GroupAction.MODIFY_INVITE_LINK_ACCESS:
    case GroupAction.MODIFY_INVITE_LINK_PASSWORD:
      return role === MemberRole.ADMINISTRATOR;

    // Announcement mode (admin only)
    case GroupAction.MODIFY_ANNOUNCEMENTS:
      return role === MemberRole.ADMINISTRATOR;

    // Ban operations (admin only)
    case GroupAction.BAN_MEMBER:
    case GroupAction.UNBAN_MEMBER:
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
 * Check if a user is banned from the group.
 *
 * @param group - Decrypted group state
 * @param serviceIdBytes - User's service ID (ACI or PNI) as bytes
 * @returns True if the user is banned
 */
export function isBanned(group: DecryptedGroup, serviceIdBytes: Uint8Array): boolean {
  return group.bannedMembers.some((banned) => bytesEqual(banned.serviceIdBytes, serviceIdBytes));
}
