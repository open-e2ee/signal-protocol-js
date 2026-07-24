/**
 * GroupsV2 State Management
 *
 * Signal Private Group System — group state, changes, access control,
 * invite links, and orchestration manager.
 */
export {};
export {
  // Enums
  MemberRole,
  AccessRequired,
  EnabledState,
  // Access control type
  type AccessControl,
  // Encrypted types (server-stored)
  type EncryptedGroup,
  type EncryptedMember,
  type EncryptedPendingMember,
  type EncryptedRequestingMember,
  type EncryptedBannedMember,
  type GroupAttributeBlob,
  // Decrypted types (local)
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
  // Server response types
  type GroupChangeState,
  type SerializedGroupChange,
  type GroupResponse,
  type GroupChangesResponse,
  type GroupChangeResponse,
  type DecryptedGroupJoinInfo,
  // Factories
  defaultAccessControl,
  emptyGroupChange,
} from './types';

export {
  encryptGroupState,
  decryptGroupState,
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

export { applyGroupChange, validateChange } from './change-actions';

export {
  GroupAction,
  canPerformAction,
  meetsAccessRequirement,
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
  GroupsV2Manager,
  MAX_GROUP_SIZE,
  type IGroupStateStore,
  type IGroupServer,
  type GroupChangeLogEntry,
  type OnSenderKeyRotation,
  type OnEndorsementsInvalidated,
  type GroupsV2ManagerOptions,
} from './manager';
