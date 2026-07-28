/**
 * Group state management
 *
 * @module groups
 *
 * Group identifiers, encrypted state, changes, access control, invite links,
 * and orchestration.
 *
 * The anonymous-credential layer beneath this follows "The Signal Private
 * Group System" (Chase, Perrin, Zaverucha, eprint 2019/1416). The group state
 * and change formats above it are this SDK's own and are not interoperable
 * with other implementations. See docs/DEVIATIONS.md.
 */
export {};
export { GROUP_ID_PREFIX, isGroupId, createGroupId, extractGroupId } from './group-id';
export type { GroupId } from './group-id';

export {
  MemberRole,
  AccessRequired,
  EnabledState,
  type AccessControl,
  type EncryptedGroup,
  type EncryptedMember,
  type EncryptedPendingMember,
  type EncryptedRequestingMember,
  type EncryptedBannedMember,
  type GroupAttributeBlob,
  type DecryptedGroup,
  type DecryptedMember,
  type DecryptedPendingMember,
  type DecryptedRequestingMember,
  type DecryptedBannedMember,
  type DecryptedGroupChange,
  type DecryptedTimer,
  type DecryptedString,
  type DecryptedModifyMemberRole,
  type DecryptedModifyMemberLabel,
  type DecryptedPendingMemberRemoval,
  type DecryptedApproveMember,
  type GroupChangeState,
  type SerializedGroupChange,
  type GroupResponse,
  type GroupChangesResponse,
  type GroupChangeResponse,
  type DecryptedGroupJoinInfo,
  type EncryptedGroupJoinInfo,
  defaultAccessControl,
  emptyGroupChange,
} from './types';

export {
  encryptGroupState,
  decryptGroupState,
  decryptGroupJoinInfo,
  encryptGroupTitle,
  decryptGroupTitle,
  encryptGroupDescription,
  decryptGroupDescription,
  encryptDisappearingMessagesTimer,
  decryptDisappearingMessagesTimer,
  encryptMember,
  decryptMember,
  encryptRequestingMember,
} from './encrypted-state';

export { applyGroupChange, validateChangeStructure } from './change-actions';
export { validateChangeAuthorization } from './change-authorization';

export {
  GroupAction,
  type GroupActionContext,
  type GroupActionAuthorizationContext,
  canPerformAction,
  canRolePerformAction,
  meetsAccessRequirement,
  isRoleAccessRequirement,
  isInviteLinkAccessRequirement,
  isStoredMemberRole,
  findMember,
  getMemberRole,
  isAdmin,
  isMember,
  isPending,
  isBanned,
} from './access-control';

export {
  createGroupInviteLink,
  parseGroupInviteLink,
  generateInviteLinkPassword,
  INVITE_LINK_PASSWORD_LEN,
  INVITE_LINK_VERSION,
  INVITE_LINK_PREFIX,
} from './invite-link';

export {
  GROUP_TRUST_ROOT_VERSION,
  decodeGroupTrustRoot,
  encodeGroupTrustRoot,
  type GroupTrustRoot,
} from './trust-root';

export {
  GroupManager,
  MAX_GROUP_SIZE,
  MAX_SUPPORTED_CHANGE_EPOCH,
  type IGroupStateStore,
  type IGroupServer,
  type GroupSnapshot,
  type GroupChangeLogEntry,
  type OnSenderKeyRotation,
  type OnEndorsementsInvalidated,
  type GroupManagerOptions,
  type GroupConfigurationWarning,
  type GroupMemberInput,
  type PresentedGroupMemberInput,
  type InvitedGroupMemberInput,
} from './manager';
