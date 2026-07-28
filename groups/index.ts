/**
 * Public groups API.
 *
 * Group identity helpers and group state/contracts live here. This is the
 * supported import surface for app code instead of internal groups modules.
 */

export {};
export { GROUP_ID_PREFIX, isGroupId, createGroupId, extractGroupId } from '../internal/groups';
export type { GroupId } from '../internal/groups';

export {
  GroupManager,
  GroupAction,
  MemberRole,
  AccessRequired,
  EnabledState,
  applyGroupChange,
  validateChangeStructure,
  canPerformAction,
  createGroupInviteLink,
  parseGroupInviteLink,
  GROUP_TRUST_ROOT_VERSION,
  decodeGroupTrustRoot,
  encodeGroupTrustRoot,
} from '../internal/groups';

export type {
  DecryptedGroup,
  DecryptedMember,
  DecryptedGroupChange,
  AccessControl,
  DecryptedTimer,
  EncryptedGroup,
  IGroupStateStore,
  IGroupServer,
  GroupSnapshot,
  GroupChangeLogEntry,
  GroupManagerOptions,
  GroupMemberInput,
  PresentedGroupMemberInput,
  InvitedGroupMemberInput,
  OnSenderKeyRotation,
  OnEndorsementsInvalidated,
  GroupActionContext,
  GroupTrustRoot,
} from '../internal/groups';
