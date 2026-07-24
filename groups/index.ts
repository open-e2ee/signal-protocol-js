/**
 * Public groups API.
 *
 * Group identity helpers and GroupsV2 state/contracts live here. This is the
 * supported import surface for app code instead of internal groups modules.
 */

export {};
export { GROUP_V2_PREFIX, isGroupId, createGroupId, extractGroupId } from '../internal/groups';
export type { GroupId } from '../internal/groups';

export {
  GroupsV2Manager,
  GroupAction,
  MemberRole,
  AccessRequired,
  EnabledState,
  applyGroupChange,
  validateChange,
  canPerformAction,
  createGroupInviteLink,
  parseGroupInviteLink,
} from '../internal/groups-v2';

export type {
  DecryptedGroup,
  DecryptedMember,
  DecryptedGroupChange,
  AccessControl,
  DecryptedTimer,
  EncryptedGroup,
  IGroupStateStore,
  IGroupServer,
  GroupChangeLogEntry,
  GroupsV2ManagerOptions,
  OnSenderKeyRotation,
  OnEndorsementsInvalidated,
} from '../internal/groups-v2';
