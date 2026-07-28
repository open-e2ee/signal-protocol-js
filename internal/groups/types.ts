/**
 * Group state types
 *
 * Encrypted wire-state and decrypted local-state types.
 *
 */

// ---------------------------------------------------------------------------
// Enums (from Groups.proto)
// ---------------------------------------------------------------------------

/** Member role within a group. Matches Member.Role in Groups.proto. */
export {};
export enum MemberRole {
  UNKNOWN = 0,
  DEFAULT = 1,
  ADMINISTRATOR = 2,
}

/** Access level required for group actions. Matches AccessControl.AccessRequired. */
export enum AccessRequired {
  UNKNOWN = 0,
  ANY = 1,
  MEMBER = 2,
  ADMINISTRATOR = 3,
  UNSATISFIABLE = 4,
}

/** Announcement group toggle state. Matches EnabledState in DecryptedGroups.proto. */
export enum EnabledState {
  UNKNOWN = 0,
  ENABLED = 1,
  DISABLED = 2,
}

// ---------------------------------------------------------------------------
// Access Control (shared between encrypted and decrypted)
// ---------------------------------------------------------------------------

/** Access control settings for a group. Matches AccessControl in Groups.proto. */
export interface AccessControl {
  /** Who can change title, avatar, description. */
  attributes: AccessRequired;
  /** Who can add/remove members. */
  members: AccessRequired;
  /** Who can join via invite link. */
  addFromInviteLink: AccessRequired;
  /** Who can modify another member's label. */
  memberLabel: AccessRequired;
}

// ---------------------------------------------------------------------------
// Encrypted Types (server-stored, opaque to server)
// ---------------------------------------------------------------------------

/** Encrypted member record. Matches Member in Groups.proto. */
export interface EncryptedMember {
  /** UID ciphertext (encrypted ServiceId). */
  userId: Uint8Array;
  role: MemberRole;
  /** Encrypted profile key ciphertext. */
  profileKey: Uint8Array;
  /** Credential presentation bytes. */
  presentation: Uint8Array;
  joinedAtVersion: number;
  /** Encrypted blob — decrypts to UTF-8 string. */
  labelEmoji: Uint8Array;
  /** Encrypted blob — decrypts to UTF-8 string. */
  labelString: Uint8Array;
}

/** Pending member awaiting profile key acceptance. Matches MemberPendingProfileKey. */
export interface EncryptedPendingMember {
  member: EncryptedMember;
  /** UID ciphertext of who added this pending member. */
  addedByUserId: Uint8Array;
  /** Milliseconds since epoch. */
  timestamp: number;
}

/**
 * A pending invitation in a group-creation submission.
 *
 * Provenance is deliberately absent: the enforcing server derives the creator
 * and its clock value before signing canonical version zero.
 */
export interface EncryptedCreationPendingMember {
  userId: Uint8Array;
  role: MemberRole;
}

/** Member requesting admin approval. Matches MemberPendingAdminApproval. */
export interface EncryptedRequestingMember {
  userId: Uint8Array;
  profileKey: Uint8Array;
  presentation: Uint8Array;
  timestamp: number;
}

/** Banned member. Matches MemberBanned. */
export interface EncryptedBannedMember {
  userId: Uint8Array;
  timestamp: number;
}

/** Encrypted group state stored on server. Matches Group in Groups.proto. */
export interface EncryptedGroup {
  /** Serialized GroupPublicParams. */
  publicKey: Uint8Array;
  /** Encrypted blob (title). */
  title: Uint8Array;
  /** Encrypted blob (description). */
  description: Uint8Array;
  /** URL for the group avatar. The SDK does not encrypt avatar content. */
  avatarUrl: string;
  /** Encrypted blob (disappearing messages timer). */
  disappearingMessagesTimer: Uint8Array;
  accessControl: AccessControl;
  /** Monotonically increasing revision counter. */
  version: number;
  members: EncryptedMember[];
  membersPendingProfileKey: EncryptedPendingMember[];
  membersPendingAdminApproval: EncryptedRequestingMember[];
  inviteLinkPassword: Uint8Array;
  announcementsOnly: boolean;
  membersBanned: EncryptedBannedMember[];
  terminated: boolean;
}

/**
 * The untrusted client submission accepted by the group-creation endpoint.
 *
 * Requesting and banned entries cannot exist before the group does. They stay
 * in the wire shape as empty arrays so every group-state field remains
 * explicit, while invitation provenance is server-derived.
 */
export interface EncryptedGroupCreationSubmission
  extends Omit<
    EncryptedGroup,
    | 'membersPendingProfileKey'
    | 'membersPendingAdminApproval'
    | 'membersBanned'
  > {
  membersPendingProfileKey: EncryptedCreationPendingMember[];
  membersPendingAdminApproval: never[];
  membersBanned: never[];
}

// ---------------------------------------------------------------------------
// Group Attribute Blob (encrypted wrapper for title/avatar/description/timer)
// ---------------------------------------------------------------------------

/** Attribute blob content type discriminator. Matches GroupAttributeBlob oneof. */
export type GroupAttributeBlob =
  | { type: 'title'; title: string }
  | { type: 'avatar'; avatar: Uint8Array }
  | { type: 'disappearingMessagesDuration'; duration: number }
  | { type: 'descriptionText'; descriptionText: string };

// ---------------------------------------------------------------------------
// Decrypted Types (local plaintext)
// ---------------------------------------------------------------------------

/** Decrypted timer. Matches DecryptedTimer in DecryptedGroups.proto. */
export interface DecryptedTimer {
  /** Duration in seconds. 0 = disabled. */
  duration: number;
}

/** Decrypted string wrapper. Matches DecryptedString. */
export interface DecryptedString {
  value: string;
}

/** Decrypted member. Matches DecryptedMember in DecryptedGroups.proto. */
export interface DecryptedMember {
  /** 16-byte ACI UUID. */
  aciBytes: Uint8Array;
  role: MemberRole;
  /** 32-byte profile key. */
  profileKey: Uint8Array;
  joinedAtRevision: number;
  /** 16-byte PNI UUID. */
  pniBytes: Uint8Array;
  labelEmoji: string;
  labelString: string;
}

/** ADD_MEMBER action. joinedAtRevision is server-derived after acceptance. */
export interface DecryptedAddMember {
  aciBytes: Uint8Array;
  role: MemberRole;
  profileKey: Uint8Array;
  joinedAtRevision?: number;
}

/** MODIFY_MEMBER_PROFILE_KEY action. */
export interface DecryptedProfileKeyUpdate {
  aciBytes: Uint8Array;
  profileKey: Uint8Array;
}

/** ACI-keyed pending-member promotion with server-derived result metadata. */
export interface DecryptedPendingMemberPromotion {
  aciBytes: Uint8Array;
  profileKey: Uint8Array;
  role?: MemberRole;
  joinedAtRevision?: number;
}

/** PNI-to-ACI pending-member promotion. */
export interface DecryptedPniAciMemberPromotion
  extends DecryptedPendingMemberPromotion {
  pniBytes: Uint8Array;
}

/** Decrypted pending member. Matches DecryptedPendingMember. */
export interface DecryptedPendingMember {
  /** 17-byte ServiceId, or empty when the target is quarantined. */
  serviceIdBytes: Uint8Array;
  role: MemberRole;
  /** 16-byte ACI of who added this member. */
  addedByAci: Uint8Array;
  timestamp: number;
  /** Preserved ciphertext for re-encryption on removal. */
  serviceIdCipherText: Uint8Array;
  /** The target could not be safely decrypted and is inert under §9.5. */
  quarantined?: true;
}

/** ADD_MEMBER_PENDING_PROFILE_KEY action with server-derived provenance. */
export interface DecryptedAddPendingMember {
  /** 17-byte ServiceId, or empty when the target is quarantined. */
  serviceIdBytes: Uint8Array;
  role: MemberRole;
  addedByAci?: Uint8Array;
  timestamp?: number;
  /** Locally preserved ciphertext; not a distinct wire field. */
  serviceIdCipherText?: Uint8Array;
  /** The target could not be safely decrypted and is inert under §9.5. */
  quarantined?: true;
}

/** Decrypted requesting member. Matches DecryptedRequestingMember. */
export interface DecryptedRequestingMember {
  /** 16-byte ACI, or empty when the target is quarantined. */
  aciBytes: Uint8Array;
  profileKey: Uint8Array;
  timestamp: number;
  /** Preserved ciphertexts for a quarantined entry. */
  aciCipherText?: Uint8Array;
  profileKeyCipherText?: Uint8Array;
  /** The target could not be safely decrypted and is inert under §9.5. */
  quarantined?: true;
}

/** ADD_MEMBER_PENDING_ADMIN_APPROVAL action. */
export interface DecryptedAddRequestingMember {
  /** 16-byte ACI, or empty when the target is quarantined. */
  aciBytes: Uint8Array;
  profileKey: Uint8Array;
  timestamp?: number;
  /** Preserved ciphertexts for a quarantined entry. */
  aciCipherText?: Uint8Array;
  profileKeyCipherText?: Uint8Array;
  /** The target could not be safely decrypted and is inert under §9.5. */
  quarantined?: true;
}

/** Decrypted banned member. Matches DecryptedBannedMember. */
export interface DecryptedBannedMember {
  /** 17-byte ServiceId, or empty when the target is quarantined. */
  serviceIdBytes: Uint8Array;
  timestamp: number;
  /** Preserved ciphertext for a quarantined entry. */
  serviceIdCipherText?: Uint8Array;
  /** The target could not be safely decrypted and is inert under §9.5. */
  quarantined?: true;
}

/** BAN_MEMBER action. */
export interface DecryptedAddBannedMember {
  /** 17-byte ServiceId, or empty when the target is quarantined. */
  serviceIdBytes: Uint8Array;
  timestamp?: number;
  /** Preserved ciphertext for a quarantined entry. */
  serviceIdCipherText?: Uint8Array;
  /** The target could not be safely decrypted and is inert under §9.5. */
  quarantined?: true;
}

/** UNBAN_MEMBER action. */
export interface DecryptedDeleteBannedMember {
  /** 17-byte ServiceId, or empty when the target is quarantined. */
  serviceIdBytes: Uint8Array;
  /** Preserved ciphertext when deleting a quarantined entry. */
  serviceIdCipherText?: Uint8Array;
}

/** Decrypted pending member removal. Matches DecryptedPendingMemberRemoval. */
export interface DecryptedPendingMemberRemoval {
  serviceIdBytes: Uint8Array;
  serviceIdCipherText: Uint8Array;
}

/** Decrypted approval. Matches DecryptedApproveMember. */
export interface DecryptedApproveMember {
  aciBytes: Uint8Array;
  role: MemberRole;
}

/** Decrypted role modification. Matches DecryptedModifyMemberRole. */
export interface DecryptedModifyMemberRole {
  aciBytes: Uint8Array;
  role: MemberRole;
}

/** Decrypted label modification. Matches DecryptedModifyMemberLabel. */
export interface DecryptedModifyMemberLabel {
  aciBytes: Uint8Array;
  labelEmoji: string;
  labelString: string;
}

/**
 * Decrypted group state. Matches DecryptedGroup in DecryptedGroups.proto.
 *
 * This is the canonical local representation of group state. It is derived
 * from EncryptedGroup by decrypting with GroupSecretParams.
 */
export interface DecryptedGroup {
  title: string;
  avatar: string;
  disappearingMessagesTimer: DecryptedTimer;
  accessControl: AccessControl;
  /** Sequential revision counter (0-based, increments with each change). */
  revision: number;
  members: DecryptedMember[];
  pendingMembers: DecryptedPendingMember[];
  requestingMembers: DecryptedRequestingMember[];
  inviteLinkPassword: Uint8Array;
  description: string;
  isAnnouncementGroup: EnabledState;
  bannedMembers: DecryptedBannedMember[];
  terminated: boolean;
}

/**
 * Decrypted group change. Matches DecryptedGroupChange in DecryptedGroups.proto.
 *
 * Represents a single atomic mutation to group state. Applied sequentially
 * to advance the group from revision N to N+1.
 */
export interface DecryptedGroupChange {
  /** ServiceId of the user who made this change. */
  editorServiceIdBytes: Uint8Array;
  /** Revision this change produces (must be previousRevision + 1). */
  revision: number;

  // Membership changes
  newMembers: DecryptedAddMember[];
  deleteMembers: Uint8Array[]; // ACI bytes of members to remove
  modifyMemberRoles: DecryptedModifyMemberRole[];
  modifiedProfileKeys: DecryptedProfileKeyUpdate[];

  // Pending member changes
  newPendingMembers: DecryptedAddPendingMember[];
  deletePendingMembers: DecryptedPendingMemberRemoval[];
  promotePendingMembers: DecryptedPendingMemberPromotion[];

  // Attribute changes
  newTitle?: DecryptedString;
  newAvatar?: DecryptedString;
  newTimer?: DecryptedTimer;

  // Access control changes
  newAttributeAccess?: AccessRequired;
  newMemberAccess?: AccessRequired;
  newInviteLinkAccess?: AccessRequired;
  newMemberLabelAccess?: AccessRequired;

  // Requesting member changes (admin approval flow)
  newRequestingMembers: DecryptedAddRequestingMember[];
  /**
   * ACI bytes, or a preserved 65-byte ciphertext when deleting a quarantined
   * requesting entry.
   */
  deleteRequestingMembers: Uint8Array[];
  promoteRequestingMembers: DecryptedApproveMember[];

  // Invite link
  newInviteLinkPassword?: Uint8Array;

  // Description
  newDescription?: DecryptedString;

  // Announcements
  newIsAnnouncementGroup?: EnabledState;

  // Ban list
  newBannedMembers: DecryptedAddBannedMember[];
  deleteBannedMembers: DecryptedDeleteBannedMember[];

  // PNI-ACI promotion (change epoch 5)
  promotePendingPniAciMembers: DecryptedPniAciMemberPromotion[];

  // Labels (change epoch 6)
  modifyMemberLabels: DecryptedModifyMemberLabel[];

  // Group lifecycle
  terminate?: boolean;
}

// ---------------------------------------------------------------------------
// Encrypted Change Types (encrypted wire format for group changes)
// ---------------------------------------------------------------------------

/** Encrypted ADD_MEMBER action. joinedAtRevision is server-derived. */
export interface EncryptedChangeAddMember {
  aciCiphertext: Uint8Array;
  role: MemberRole;
  profileKeyCiphertext: Uint8Array;
  presentation: Uint8Array;
  joinedAtRevision?: number;
}

/** Encrypted MODIFY_MEMBER_PROFILE_KEY action. */
export interface EncryptedChangeProfileKeyUpdate {
  aciCiphertext: Uint8Array;
  profileKeyCiphertext: Uint8Array;
  presentation: Uint8Array;
}

/** Encrypted ACI-keyed promotion. */
export interface EncryptedChangePendingMemberPromotion {
  aciCiphertext: Uint8Array;
  profileKeyCiphertext: Uint8Array;
  presentation: Uint8Array;
  role?: MemberRole;
  joinedAtRevision?: number;
}

/** Encrypted PNI-to-ACI promotion. */
export interface EncryptedChangePniAciMemberPromotion
  extends EncryptedChangePendingMemberPromotion {
  pniCiphertext: Uint8Array;
}

/** Encrypted pending member in a group change. */
export interface EncryptedChangePendingMember {
  /** Encrypted ServiceId (65-byte UuidCiphertext). */
  serviceIdCiphertext: Uint8Array;
  role: MemberRole;
  /** Server-derived canonical inviter. */
  addedByAciCiphertext?: Uint8Array;
  /** Server-derived canonical timestamp. */
  timestamp?: number;
}

/** Encrypted pending member removal in a group change. */
export interface EncryptedChangePendingMemberRemoval {
  /** Encrypted ServiceId (65-byte UuidCiphertext). */
  serviceIdCiphertext: Uint8Array;
}

/** Encrypted requesting member in a group change. */
export interface EncryptedChangeRequestingMember {
  /** Encrypted ACI (65-byte UuidCiphertext). */
  aciCiphertext: Uint8Array;
  /** Encrypted profile key (65-byte ProfileKeyCiphertext). */
  profileKeyCiphertext: Uint8Array;
  /** Profile-key credential presentation for server verification. */
  presentation: Uint8Array;
  /** Server-derived canonical timestamp. */
  timestamp?: number;
}

/** Encrypted approve member in a group change. */
export interface EncryptedChangeApproveMember {
  /** Encrypted ACI (65-byte UuidCiphertext). */
  aciCiphertext: Uint8Array;
  role: MemberRole;
}

/** Encrypted modify member role in a group change. */
export interface EncryptedChangeModifyMemberRole {
  /** Encrypted ACI (65-byte UuidCiphertext). */
  aciCiphertext: Uint8Array;
  role: MemberRole;
}

/** Encrypted banned member in a group change. */
export interface EncryptedChangeBannedMember {
  /** Encrypted ServiceId (65-byte UuidCiphertext). */
  serviceIdCiphertext: Uint8Array;
  /** Server-derived canonical timestamp. */
  timestamp?: number;
}

/** Encrypted UNBAN_MEMBER action. */
export interface EncryptedChangeBannedMemberRemoval {
  serviceIdCiphertext: Uint8Array;
}

/** Encrypted modify member label in a group change. */
export interface EncryptedChangeModifyMemberLabel {
  /** Encrypted ACI (65-byte UuidCiphertext). */
  aciCiphertext: Uint8Array;
  labelEmojiCiphertext: Uint8Array;
  labelStringCiphertext: Uint8Array;
}

/**
 * Encrypted group change. Mirrors DecryptedGroupChange but with identity
 * fields (ACI, PNI, profileKey) encrypted as ciphertext.
 *
 * Roles, revisions, timestamps, access-control enums, and avatar URLs remain
 * plaintext. Group attributes, member labels, identities, and profile keys
 * are ciphertexts.
 *
 * The client leaves `sourceUserId` and `groupId` unset. A conforming server
 * derives and sets both before serializing and signing the accepted Actions.
 */
export interface EncryptedGroupChange {
  /** Server-derived encrypted ACI of the editor (65-byte UuidCiphertext). */
  sourceUserId?: Uint8Array;
  /** Server-set 32-byte group identifier. */
  groupId?: Uint8Array;
  revision: number;

  // Membership changes
  newMembers: EncryptedChangeAddMember[];
  deleteMembers: Uint8Array[]; // Encrypted ACI ciphertexts
  modifyMemberRoles: EncryptedChangeModifyMemberRole[];
  modifiedProfileKeys: EncryptedChangeProfileKeyUpdate[];

  // Pending member changes
  newPendingMembers: EncryptedChangePendingMember[];
  deletePendingMembers: EncryptedChangePendingMemberRemoval[];
  promotePendingMembers: EncryptedChangePendingMemberPromotion[];

  // Attribute changes (encrypted blobs)
  newTitle?: Uint8Array;
  newAvatar?: DecryptedString;
  newTimer?: Uint8Array;

  // Access control changes (plaintext enums)
  newAttributeAccess?: AccessRequired;
  newMemberAccess?: AccessRequired;
  newInviteLinkAccess?: AccessRequired;
  newMemberLabelAccess?: AccessRequired;

  // Requesting member changes
  newRequestingMembers: EncryptedChangeRequestingMember[];
  deleteRequestingMembers: Uint8Array[]; // Encrypted ACI ciphertexts
  promoteRequestingMembers: EncryptedChangeApproveMember[];

  // Invite link
  newInviteLinkPassword?: Uint8Array;

  // Description
  newDescription?: Uint8Array;

  // Announcements
  newIsAnnouncementGroup?: EnabledState;

  // Ban list
  newBannedMembers: EncryptedChangeBannedMember[];
  deleteBannedMembers: EncryptedChangeBannedMemberRemoval[];

  // PNI-ACI promotion (change epoch 5)
  promotePendingPniAciMembers: EncryptedChangePniAciMemberPromotion[];

  // Labels (change epoch 6)
  modifyMemberLabels: EncryptedChangeModifyMemberLabel[];

  // Group lifecycle
  terminate?: boolean;
}

// ---------------------------------------------------------------------------
// Server response types (from Groups.proto)
// ---------------------------------------------------------------------------

/** A single change + resulting state snapshot. Matches GroupChanges.GroupChangeState. */
export interface GroupChangeState {
  /** The serialized group change. */
  change: SerializedGroupChange;
  /** The group state after applying the change. */
  groupState: EncryptedGroup;
}

/** Serialized group change (wire format). Matches GroupChange. */
export interface SerializedGroupChange {
  /** Serialized GroupChange.Actions. */
  actions: Uint8Array;
  /** Server's binding signature over the actions. */
  serverSignature: Uint8Array;
  /** Protocol epoch for feature gating. */
  changeEpoch: number;
}

/** Server response when fetching group state. Matches GroupResponse. */
export interface GroupResponse {
  group: EncryptedGroup;
  groupSendEndorsementsResponse?: Uint8Array;
}

/** Server response when fetching change log. Matches GroupChanges. */
export interface GroupChangesResponse {
  groupChanges: GroupChangeState[];
  groupSendEndorsementsResponse?: Uint8Array;
}

/** Server response after submitting a change. Matches GroupChangeResponse. */
export interface GroupChangeResponse {
  groupChange: SerializedGroupChange;
  groupSendEndorsementsResponse?: Uint8Array;
}

// ---------------------------------------------------------------------------
// Group join info (for invite links)
// ---------------------------------------------------------------------------

/** Public group info visible via invite link. Matches DecryptedGroupJoinInfo. */
export interface DecryptedGroupJoinInfo {
  publicKey: Uint8Array;
  title: string;
  avatar: string;
  memberCount: number;
  addFromInviteLink: AccessRequired;
  revision: number;
  pendingAdminApproval: boolean;
  description: string;
}

/** Reduced encrypted projection served to an invite-link holder. */
export interface EncryptedGroupJoinInfo {
  publicKey: Uint8Array;
  title: Uint8Array;
  avatar: string;
  memberCount: number;
  addFromInviteLink: AccessRequired;
  revision: number;
  pendingAdminApproval: boolean;
  description: Uint8Array;
}

// ---------------------------------------------------------------------------
// Default factories
// ---------------------------------------------------------------------------

/** Create default access control (MEMBER for attributes and members, ANY for invite link). */
export function defaultAccessControl(): AccessControl {
  return {
    attributes: AccessRequired.MEMBER,
    members: AccessRequired.MEMBER,
    addFromInviteLink: AccessRequired.UNSATISFIABLE,
    memberLabel: AccessRequired.ADMINISTRATOR,
  };
}

/** Create an empty DecryptedGroupChange for a given revision. */
export function emptyGroupChange(
  editorServiceIdBytes: Uint8Array,
  revision: number
): DecryptedGroupChange {
  return {
    editorServiceIdBytes,
    revision,
    newMembers: [],
    deleteMembers: [],
    modifyMemberRoles: [],
    modifiedProfileKeys: [],
    newPendingMembers: [],
    deletePendingMembers: [],
    promotePendingMembers: [],
    newRequestingMembers: [],
    deleteRequestingMembers: [],
    promoteRequestingMembers: [],
    newBannedMembers: [],
    deleteBannedMembers: [],
    promotePendingPniAciMembers: [],
    modifyMemberLabels: [],
  };
}
