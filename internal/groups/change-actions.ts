/**
 * Group Change Application
 *
 * Pure functions for applying DecryptedGroupChange operations to DecryptedGroup state.
 *
 * Operations are applied in the normative order from the group-system
 * specification: deletions, bans, promotions, additions, modifications,
 * then attributes and access control.
 *
 * @module change-actions
 */

import {
  type DecryptedGroup,
  type DecryptedMember,
  type DecryptedPendingMemberPromotion,
  type DecryptedGroupChange,
  MemberRole,
  AccessRequired,
  EnabledState,
  emptyGroupChange,
} from './types';
import { constantTimeEqual as bytesEqual } from '../crypto/utils';
import {
  SERVICE_ID_ACI,
  SERVICE_ID_PNI,
  isNilUuid,
} from '../protocol/zk/groups/uid-struct';
import {
  isInviteLinkAccessRequirement,
  isRoleAccessRequirement,
  isStoredMemberRole,
} from './access-control';

function nilUuidError(value: Uint8Array, label: string, errors: string[]): void {
  if (isNilUuid(value)) {
    errors.push(`${label} uses the reserved nil UUID`);
  }
}

function nilServiceIdError(
  value: Uint8Array,
  label: string,
  errors: string[]
): void {
  if (value.length === 17 && isNilUuid(value.subarray(1))) {
    errors.push(`${label} uses the reserved nil UUID`);
  }
}

/** Validate C6's non-nil identifier invariant over decrypted group state. */
export function validateGroupIdentifiers(group: DecryptedGroup): string[] {
  const errors: string[] = [];
  for (const [index, member] of group.members.entries()) {
    nilUuidError(member.aciBytes, `members[${index}].aciBytes`, errors);
    if (member.pniBytes.length > 0) {
      nilUuidError(member.pniBytes, `members[${index}].pniBytes`, errors);
    }
  }
  for (const [index, member] of group.pendingMembers.entries()) {
    nilServiceIdError(
      member.serviceIdBytes,
      `pendingMembers[${index}].serviceIdBytes`,
      errors
    );
    nilUuidError(
      member.addedByAci,
      `pendingMembers[${index}].addedByAci`,
      errors
    );
  }
  for (const [index, member] of group.requestingMembers.entries()) {
    nilUuidError(
      member.aciBytes,
      `requestingMembers[${index}].aciBytes`,
      errors
    );
  }
  for (const [index, member] of group.bannedMembers.entries()) {
    nilServiceIdError(
      member.serviceIdBytes,
      `bannedMembers[${index}].serviceIdBytes`,
      errors
    );
  }
  return errors;
}

/** Validate §6.7's field-specific access-control domains. */
export function validateGroupAccessControl(group: DecryptedGroup): string[] {
  const errors: string[] = [];
  if (!isRoleAccessRequirement(group.accessControl.attributes)) {
    errors.push('accessControl.attributes is outside its §6.7 domain');
  }
  if (!isRoleAccessRequirement(group.accessControl.members)) {
    errors.push('accessControl.members is outside its §6.7 domain');
  }
  if (!isRoleAccessRequirement(group.accessControl.memberLabel)) {
    errors.push('accessControl.memberLabel is outside its §6.7 domain');
  }
  if (!isInviteLinkAccessRequirement(group.accessControl.addFromInviteLink)) {
    errors.push('accessControl.addFromInviteLink is outside its §6.7 domain');
  }
  return errors;
}

/** Validate §6.8's stored member and pending-member role domain. */
export function validateGroupMemberRoles(group: DecryptedGroup): string[] {
  const errors: string[] = [];
  for (const [index, member] of group.members.entries()) {
    if (!isStoredMemberRole(member.role)) {
      errors.push(`members[${index}].role is outside its §6.8 domain`);
    }
  }
  for (const [index, member] of group.pendingMembers.entries()) {
    if (!isStoredMemberRole(member.role)) {
      errors.push(`pendingMembers[${index}].role is outside its §6.8 domain`);
    }
  }
  return errors;
}

function isCanonicalTimestamp(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0;
}

/** Validate §7.8's plaintext stored-state domains. */
export function validateGroupCanonicalFields(group: DecryptedGroup): string[] {
  const errors: string[] = [];
  if (!Number.isSafeInteger(group.revision) || group.revision < 0) {
    errors.push('revision must be a non-negative safe integer');
  }
  if (
    group.isAnnouncementGroup !== EnabledState.ENABLED &&
    group.isAnnouncementGroup !== EnabledState.DISABLED
  ) {
    errors.push('isAnnouncementGroup is outside its §7.8 domain');
  }
  if (typeof group.terminated !== 'boolean') {
    errors.push('terminated must be a boolean');
  }
  if (
    group.inviteLinkPassword.length !== 0 &&
    group.inviteLinkPassword.length !== 16
  ) {
    errors.push('inviteLinkPassword must be empty or exactly 16 bytes');
  }
  for (const [index, member] of group.members.entries()) {
    if (
      !Number.isSafeInteger(member.joinedAtRevision) ||
      member.joinedAtRevision < 0 ||
      member.joinedAtRevision > group.revision
    ) {
      errors.push(
        `members[${index}].joinedAtRevision is outside its §7.8 domain`
      );
    }
  }
  for (const [label, entries] of [
    ['pendingMembers', group.pendingMembers],
    ['requestingMembers', group.requestingMembers],
    ['bannedMembers', group.bannedMembers],
  ] as const) {
    for (const [index, entry] of entries.entries()) {
      if (!isCanonicalTimestamp(entry.timestamp)) {
        errors.push(`${label}[${index}].timestamp is outside its §7.8 domain`);
      }
    }
  }
  return errors;
}

/** Validate C6's non-nil identifier invariant over a decrypted change. */
export function validateChangeIdentifiers(change: DecryptedGroupChange): string[] {
  const errors: string[] = [];
  nilServiceIdError(
    change.editorServiceIdBytes,
    'editorServiceIdBytes',
    errors
  );
  const members: Array<
    [
      string,
      Array<{ aciBytes: Uint8Array; pniBytes?: Uint8Array }>,
    ]
  > = [
    ['newMembers', change.newMembers],
    ['modifiedProfileKeys', change.modifiedProfileKeys],
    ['promotePendingMembers', change.promotePendingMembers],
    ['promotePendingPniAciMembers', change.promotePendingPniAciMembers],
  ];
  for (const [label, entries] of members) {
    for (const [index, member] of entries.entries()) {
      nilUuidError(member.aciBytes, `${label}[${index}].aciBytes`, errors);
      if (member.pniBytes !== undefined && member.pniBytes.length > 0) {
        nilUuidError(member.pniBytes, `${label}[${index}].pniBytes`, errors);
      }
    }
  }
  for (const [index, aciBytes] of change.deleteMembers.entries()) {
    nilUuidError(aciBytes, `deleteMembers[${index}]`, errors);
  }
  for (const [index, member] of change.modifyMemberRoles.entries()) {
    nilUuidError(
      member.aciBytes,
      `modifyMemberRoles[${index}].aciBytes`,
      errors
    );
  }
  for (const [index, member] of change.newPendingMembers.entries()) {
    nilServiceIdError(
      member.serviceIdBytes,
      `newPendingMembers[${index}].serviceIdBytes`,
      errors
    );
    if (member.addedByAci !== undefined) {
      nilUuidError(
        member.addedByAci,
        `newPendingMembers[${index}].addedByAci`,
        errors
      );
    }
  }
  for (const [index, member] of change.deletePendingMembers.entries()) {
    nilServiceIdError(
      member.serviceIdBytes,
      `deletePendingMembers[${index}].serviceIdBytes`,
      errors
    );
  }
  for (const [index, member] of change.newRequestingMembers.entries()) {
    nilUuidError(
      member.aciBytes,
      `newRequestingMembers[${index}].aciBytes`,
      errors
    );
  }
  for (const [index, aciBytes] of change.deleteRequestingMembers.entries()) {
    nilUuidError(aciBytes, `deleteRequestingMembers[${index}]`, errors);
  }
  for (const [index, member] of change.promoteRequestingMembers.entries()) {
    nilUuidError(
      member.aciBytes,
      `promoteRequestingMembers[${index}].aciBytes`,
      errors
    );
  }
  const banned: Array<[string, DecryptedGroupChange['newBannedMembers']]> = [
    ['newBannedMembers', change.newBannedMembers],
    ['deleteBannedMembers', change.deleteBannedMembers],
  ];
  for (const [label, entries] of banned) {
    for (const [index, member] of entries.entries()) {
      nilServiceIdError(
        member.serviceIdBytes,
        `${label}[${index}].serviceIdBytes`,
        errors
      );
    }
  }
  for (const [index, member] of change.modifyMemberLabels.entries()) {
    nilUuidError(
      member.aciBytes,
      `modifyMemberLabels[${index}].aciBytes`,
      errors
    );
  }
  return errors;
}

/** Validate access-control values introduced by a change under §6.7. */
export function validateChangeAccessControl(
  change: DecryptedGroupChange
): string[] {
  const errors: string[] = [];
  for (const [label, value] of [
    ['newAttributeAccess', change.newAttributeAccess],
    ['newMemberAccess', change.newMemberAccess],
    ['newMemberLabelAccess', change.newMemberLabelAccess],
  ] as const) {
    if (value !== undefined && !isRoleAccessRequirement(value)) {
      errors.push(`${label} is outside its §6.7 domain`);
    }
  }
  if (
    change.newInviteLinkAccess !== undefined &&
    !isInviteLinkAccessRequirement(change.newInviteLinkAccess)
  ) {
    errors.push('newInviteLinkAccess is outside its §6.7 domain');
  }
  return errors;
}

/** Validate every role-bearing action field under §6.8. */
export function validateChangeMemberRoles(
  change: DecryptedGroupChange
): string[] {
  const errors: string[] = [];
  for (const [label, members] of [
    ['newMembers', change.newMembers],
    ['promotePendingMembers', change.promotePendingMembers],
    ['promotePendingPniAciMembers', change.promotePendingPniAciMembers],
  ] as const) {
    for (const [index, member] of members.entries()) {
      if (member.role !== undefined && !isStoredMemberRole(member.role)) {
        errors.push(`${label}[${index}].role is outside its §6.8 domain`);
      }
    }
  }
  for (const [index, member] of change.newPendingMembers.entries()) {
    if (!isStoredMemberRole(member.role)) {
      errors.push(
        `newPendingMembers[${index}].role is outside its §6.8 domain`
      );
    }
  }
  for (const [index, member] of change.modifyMemberRoles.entries()) {
    if (!isStoredMemberRole(member.role)) {
      errors.push(
        `modifyMemberRoles[${index}].role is outside its §6.8 domain`
      );
    }
  }
  for (const [index, member] of change.promoteRequestingMembers.entries()) {
    if (!isStoredMemberRole(member.role)) {
      errors.push(
        `promoteRequestingMembers[${index}].role is outside its §6.8 domain`
      );
    }
  }
  return errors;
}

export type DecryptedGroupChangeForm = 'submission' | 'canonical';

/** Validate §7.8's derived-field presence and plaintext action domains. */
export function validateChangeCanonicalFields(
  state: DecryptedGroup,
  change: DecryptedGroupChange,
  form: DecryptedGroupChangeForm
): string[] {
  const errors: string[] = [];
  const canonical = form === 'canonical';
  const expectDerived = (
    present: boolean,
    label: string
  ): void => {
    if (present !== canonical) {
      errors.push(
        `${label} must be ${canonical ? 'present' : 'absent'} in ${form} form`
      );
    }
  };

  if (!Number.isSafeInteger(change.revision) || change.revision < 1) {
    errors.push('change revision must be a positive safe integer');
  }
  if (
    change.newIsAnnouncementGroup !== undefined &&
    change.newIsAnnouncementGroup !== EnabledState.ENABLED &&
    change.newIsAnnouncementGroup !== EnabledState.DISABLED
  ) {
    errors.push('newIsAnnouncementGroup is outside its §7.8 domain');
  }
  const { newInviteLinkPassword: actionPw } = change;
  if (actionPw !== undefined && actionPw.length !== 16) {
    errors.push('newInviteLinkPassword must be exactly 16 bytes');
  }

  for (const [index, member] of change.newMembers.entries()) {
    expectDerived(
      member.joinedAtRevision !== undefined,
      `newMembers[${index}].joinedAtRevision`
    );
    if (
      canonical &&
      member.joinedAtRevision !== change.revision
    ) {
      errors.push(
        `newMembers[${index}].joinedAtRevision must equal the change revision`
      );
    }
  }

  const promotions: Array<
    [
      string,
      typeof change.promotePendingMembers,
      (index: number) => MemberRole | undefined,
    ]
  > = [
    [
      'promotePendingMembers',
      change.promotePendingMembers,
      (index) => {
        const aci = change.promotePendingMembers[index]!.aciBytes;
        return state.pendingMembers.find(
          (member) =>
            member.serviceIdBytes[0] === SERVICE_ID_ACI &&
            bytesEqual(member.serviceIdBytes.subarray(1), aci)
        )?.role;
      },
    ],
    [
      'promotePendingPniAciMembers',
      change.promotePendingPniAciMembers,
      (index) => {
        const pni = change.promotePendingPniAciMembers[index]!.pniBytes;
        return state.pendingMembers.find(
          (member) =>
            member.serviceIdBytes[0] === SERVICE_ID_PNI &&
            bytesEqual(member.serviceIdBytes.subarray(1), pni)
        )?.role;
      },
    ],
  ];
  for (const [label, entries, expectedRole] of promotions) {
    for (const [index, promotion] of entries.entries()) {
      expectDerived(promotion.role !== undefined, `${label}[${index}].role`);
      expectDerived(
        promotion.joinedAtRevision !== undefined,
        `${label}[${index}].joinedAtRevision`
      );
      if (canonical && promotion.role !== expectedRole(index)) {
        errors.push(`${label}[${index}].role must equal the pending role`);
      }
      if (
        canonical &&
        promotion.joinedAtRevision !== change.revision
      ) {
        errors.push(
          `${label}[${index}].joinedAtRevision must equal the change revision`
        );
      }
    }
  }

  for (const [index, pending] of change.newPendingMembers.entries()) {
    expectDerived(
      pending.addedByAci !== undefined,
      `newPendingMembers[${index}].addedByAci`
    );
    expectDerived(
      pending.timestamp !== undefined,
      `newPendingMembers[${index}].timestamp`
    );
    if (canonical) {
      if (
        change.editorServiceIdBytes[0] !== SERVICE_ID_ACI ||
        !bytesEqual(
          pending.addedByAci!,
          change.editorServiceIdBytes.subarray(1)
        )
      ) {
        errors.push(
          `newPendingMembers[${index}].addedByAci must equal sourceUserId`
        );
      }
      if (!isCanonicalTimestamp(pending.timestamp)) {
        errors.push(
          `newPendingMembers[${index}].timestamp is outside its §7.8 domain`
        );
      }
    }
  }
  for (const [label, entries] of [
    ['newRequestingMembers', change.newRequestingMembers],
    ['newBannedMembers', change.newBannedMembers],
  ] as const) {
    for (const [index, entry] of entries.entries()) {
      expectDerived(
        entry.timestamp !== undefined,
        `${label}[${index}].timestamp`
      );
      if (canonical && !isCanonicalTimestamp(entry.timestamp)) {
        errors.push(`${label}[${index}].timestamp is outside its §7.8 domain`);
      }
    }
  }

  return errors;
}

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

function pendingTargetMatches(
  member: DecryptedGroup['pendingMembers'][number],
  target: DecryptedGroupChange['deletePendingMembers'][number]
): boolean {
  return (
    (target.serviceIdCipherText.length > 0 &&
      bytesEqual(member.serviceIdCipherText, target.serviceIdCipherText)) ||
    (member.quarantined !== true &&
      bytesEqual(member.serviceIdBytes, target.serviceIdBytes))
  );
}

function requestingTargetMatches(
  member: DecryptedGroup['requestingMembers'][number],
  target: Uint8Array
): boolean {
  return target.length === 65
    ? member.aciCipherText !== undefined &&
        bytesEqual(member.aciCipherText, target)
    : member.quarantined !== true && bytesEqual(member.aciBytes, target);
}

function bannedTargetMatches(
  member: DecryptedGroup['bannedMembers'][number],
  target: DecryptedGroupChange['deleteBannedMembers'][number]
): boolean {
  return target.serviceIdCipherText !== undefined
    ? member.serviceIdCipherText !== undefined &&
        bytesEqual(member.serviceIdCipherText, target.serviceIdCipherText)
    : member.quarantined !== true &&
        bytesEqual(member.serviceIdBytes, target.serviceIdBytes);
}

/**
 * Apply a DecryptedGroupChange to a DecryptedGroup state.
 *
 * This is a pure function that returns a new state object without mutating the input.
 * Changes are applied in the normative order from §7.4.
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
  if (state.terminated) {
    throw new Error('INVALID_CHANGE: Group is terminated');
  }
  if (change.revision !== state.revision + 1) {
    throw new Error(`Invalid revision: expected ${state.revision + 1}, got ${change.revision}`);
  }

  const newState = cloneGroup(state);

  applyDeletions(newState, change);
  applyBans(newState, change);
  applyPromotions(newState, change);
  applyAdditions(newState, change);
  applyMemberModifications(newState, change);
  applyAttributesAndAccessControl(newState, change);
  applyTermination(newState, change);
  newState.revision = change.revision;

  return newState;
}

function applyTermination(state: DecryptedGroup, change: DecryptedGroupChange): void {
  if (change.terminate !== undefined) {
    if (change.terminate !== true) {
      throw new Error('INVALID_CHANGE: Termination action must be true');
    }
    state.terminated = true;
  }
}

function applyDeletions(state: DecryptedGroup, change: DecryptedGroupChange): void {
  for (const removal of change.deletePendingMembers) {
    if (
      !state.pendingMembers.some((member) =>
        pendingTargetMatches(member, removal)
      )
    ) {
      throw new Error('INVALID_CHANGE: Attempted to delete non-existent pending member');
    }
    state.pendingMembers = state.pendingMembers.filter(
      (member) => !pendingTargetMatches(member, removal)
    );
  }
  for (const target of change.deleteRequestingMembers) {
    if (!state.requestingMembers.some((member) => requestingTargetMatches(member, target))) {
      throw new Error('INVALID_CHANGE: Attempted to delete non-existent requesting member');
    }
    state.requestingMembers = state.requestingMembers.filter(
      (member) => !requestingTargetMatches(member, target)
    );
  }
  for (const removal of change.deleteBannedMembers) {
    if (
      !state.bannedMembers.some((member) =>
        bannedTargetMatches(member, removal)
      )
    ) {
      throw new Error('INVALID_CHANGE: Attempted to unban non-existent banned member');
    }
    state.bannedMembers = state.bannedMembers.filter(
      (member) => !bannedTargetMatches(member, removal)
    );
  }
  for (const aciBytes of change.deleteMembers) {
    if (!state.members.some((member) => bytesEqual(member.aciBytes, aciBytes))) {
      throw new Error('INVALID_CHANGE: Attempted to delete non-existent member');
    }
    state.members = state.members.filter((member) => !bytesEqual(member.aciBytes, aciBytes));
  }
}

function applyBans(state: DecryptedGroup, change: DecryptedGroupChange): void {
  for (const banned of change.newBannedMembers) {
    if (
      state.bannedMembers.some((member) =>
        banned.serviceIdCipherText !== undefined
          ? member.serviceIdCipherText !== undefined &&
              bytesEqual(
                member.serviceIdCipherText,
                banned.serviceIdCipherText
              )
          : member.quarantined !== true &&
              bytesEqual(member.serviceIdBytes, banned.serviceIdBytes)
      )
    ) {
      throw new Error('INVALID_CHANGE: Attempted to ban already-banned member');
    }
    state.bannedMembers = [
      ...state.bannedMembers,
      {
        serviceIdBytes: banned.serviceIdBytes,
        timestamp: banned.timestamp!,
        ...(banned.serviceIdCipherText === undefined
          ? {}
          : {
              serviceIdCipherText: banned.serviceIdCipherText,
              quarantined: true as const,
            }),
      },
    ];
  }
}

function assertMemberDestinationAvailable(
  state: DecryptedGroup,
  aciBytes: Uint8Array,
  errorMessage: string
): void {
  if (state.members.some((member) => bytesEqual(member.aciBytes, aciBytes))) {
    throw new Error(`INVALID_CHANGE: ${errorMessage}`);
  }
}

function memberFromPromotion(
  promotion: DecryptedPendingMemberPromotion,
  role: MemberRole,
  revision: number
): DecryptedMember {
  return {
    aciBytes: promotion.aciBytes,
    role,
    profileKey: promotion.profileKey,
    joinedAtRevision: revision,
    pniBytes: new Uint8Array(0),
    labelEmoji: '',
    labelString: '',
  };
}

function applyPromotions(state: DecryptedGroup, change: DecryptedGroupChange): void {
  for (const promotion of change.promotePendingMembers) {
    if (promotion.aciBytes.length !== 16) {
      throw new Error(
        `INVALID_CHANGE: Pending promotion ACI must be 16 bytes, got ${promotion.aciBytes.length}`
      );
    }
    assertMemberDestinationAvailable(
      state,
      promotion.aciBytes,
      'Attempted to promote pending member who is already a member'
    );
    const pendingServiceIdBytes = new Uint8Array([SERVICE_ID_ACI, ...promotion.aciBytes]);
    const pendingIndex = state.pendingMembers.findIndex((member) =>
      bytesEqual(member.serviceIdBytes, pendingServiceIdBytes)
    );
    if (pendingIndex === -1) {
      throw new Error('INVALID_CHANGE: Attempted to promote non-existent pending member');
    }

    const pending = state.pendingMembers[pendingIndex];
    state.pendingMembers = state.pendingMembers.filter(
      (_, index) => index !== pendingIndex
    );
    state.members = [
      ...state.members,
      memberFromPromotion(promotion, pending.role, change.revision),
    ];
  }

  for (const promotion of change.promotePendingPniAciMembers) {
    if (promotion.aciBytes.length !== 16) {
      throw new Error(
        `INVALID_CHANGE: Pending PNI promotion ACI must be 16 bytes, got ${promotion.aciBytes.length}`
      );
    }
    if (promotion.pniBytes.length !== 16) {
      throw new Error(
        `INVALID_CHANGE: Pending promotion PNI must be 16 bytes, got ${promotion.pniBytes.length}`
      );
    }
    assertMemberDestinationAvailable(
      state,
      promotion.aciBytes,
      'Attempted to promote PNI/ACI member who is already a member'
    );
    const pendingServiceIdBytes = new Uint8Array([SERVICE_ID_PNI, ...promotion.pniBytes]);
    const pendingIndex = state.pendingMembers.findIndex((member) =>
      bytesEqual(member.serviceIdBytes, pendingServiceIdBytes)
    );
    if (pendingIndex === -1) {
      throw new Error('INVALID_CHANGE: Attempted to promote PNI/ACI member not in pending list');
    }

    const pending = state.pendingMembers[pendingIndex];
    const aciServiceIdBytes = new Uint8Array([
      SERVICE_ID_ACI,
      ...promotion.aciBytes,
    ]);
    const aciPending = state.pendingMembers.find((member) =>
      bytesEqual(member.serviceIdBytes, aciServiceIdBytes)
    );
    if (aciPending && aciPending.role !== pending.role) {
      throw new Error(
        'INVALID_CHANGE: PNI-to-ACI promotion cannot consume pending aliases with different roles'
      );
    }
    state.pendingMembers = state.pendingMembers.filter(
      (member, index) =>
        index !== pendingIndex &&
        !bytesEqual(member.serviceIdBytes, aciServiceIdBytes)
    );
    state.members = [
      ...state.members,
      memberFromPromotion(promotion, pending.role, change.revision),
    ];
  }

  for (const approval of change.promoteRequestingMembers) {
    assertMemberDestinationAvailable(
      state,
      approval.aciBytes,
      'Attempted to promote requesting member who is already a member'
    );
    const requestingIndex = state.requestingMembers.findIndex((member) =>
      bytesEqual(member.aciBytes, approval.aciBytes)
    );
    if (requestingIndex === -1) {
      throw new Error('INVALID_CHANGE: Attempted to promote non-existent requesting member');
    }

    const requestingMember = state.requestingMembers[requestingIndex];
    state.requestingMembers = state.requestingMembers.filter(
      (_, index) => index !== requestingIndex
    );
    state.members = [
      ...state.members,
      {
        aciBytes: approval.aciBytes,
        role: approval.role,
        profileKey: requestingMember.profileKey,
        joinedAtRevision: change.revision,
        pniBytes: new Uint8Array(0),
        labelEmoji: '',
        labelString: '',
      },
    ];
  }
}

function applyAdditions(state: DecryptedGroup, change: DecryptedGroupChange): void {
  for (const member of change.newMembers) {
    assertMemberDestinationAvailable(
      state,
      member.aciBytes,
      'Attempted to add existing member'
    );
    state.members = [
      ...state.members,
      {
        aciBytes: member.aciBytes,
        role: member.role,
        profileKey: member.profileKey,
        joinedAtRevision: member.joinedAtRevision!,
        pniBytes: new Uint8Array(0),
        labelEmoji: '',
        labelString: '',
      },
    ];
  }
  for (const pending of change.newPendingMembers) {
    if (
      state.pendingMembers.some((member) =>
        pending.serviceIdCipherText !== undefined &&
        pending.quarantined === true
          ? bytesEqual(
              member.serviceIdCipherText,
              pending.serviceIdCipherText
            )
          : member.quarantined !== true &&
              bytesEqual(member.serviceIdBytes, pending.serviceIdBytes)
      )
    ) {
      throw new Error('INVALID_CHANGE: Attempted to add existing pending member');
    }
    state.pendingMembers = [
      ...state.pendingMembers,
      {
        serviceIdBytes: pending.serviceIdBytes,
        role: pending.role,
        addedByAci: pending.addedByAci!,
        timestamp: pending.timestamp!,
        serviceIdCipherText:
          pending.serviceIdCipherText ?? new Uint8Array(0),
        ...(pending.quarantined === true
          ? { quarantined: true as const }
          : {}),
      },
    ];
  }
  for (const requesting of change.newRequestingMembers) {
    if (
      state.requestingMembers.some((member) =>
        requesting.quarantined === true &&
        requesting.aciCipherText !== undefined
          ? member.aciCipherText !== undefined &&
              bytesEqual(member.aciCipherText, requesting.aciCipherText)
          : member.quarantined !== true &&
              bytesEqual(member.aciBytes, requesting.aciBytes)
      )
    ) {
      throw new Error('INVALID_CHANGE: Attempted to add existing requesting member');
    }
    state.requestingMembers = [
      ...state.requestingMembers,
      {
        aciBytes: requesting.aciBytes,
        profileKey: requesting.profileKey,
        timestamp: requesting.timestamp!,
        ...(requesting.quarantined === true
          ? {
              aciCipherText: requesting.aciCipherText,
              profileKeyCipherText: requesting.profileKeyCipherText,
              quarantined: true as const,
            }
          : {}),
      },
    ];
  }
}

function applyMemberModifications(state: DecryptedGroup, change: DecryptedGroupChange): void {
  for (const modification of change.modifyMemberRoles) {
    const memberIndex = state.members.findIndex((member) =>
      bytesEqual(member.aciBytes, modification.aciBytes)
    );
    if (memberIndex !== -1) {
      state.members[memberIndex] = {
        ...state.members[memberIndex],
        role: modification.role,
      };
    } else {
      throw new Error('INVALID_CHANGE: Attempted to modify role of non-existent member');
    }
  }
  for (const modification of change.modifyMemberLabels) {
    const memberIndex = state.members.findIndex((member) =>
      bytesEqual(member.aciBytes, modification.aciBytes)
    );
    if (memberIndex !== -1) {
      state.members[memberIndex] = {
        ...state.members[memberIndex],
        labelEmoji: modification.labelEmoji ?? '',
        labelString: modification.labelString ?? '',
      };
    } else {
      throw new Error('INVALID_CHANGE: Attempted to modify labels of non-existent member');
    }
  }
  for (const modification of change.modifiedProfileKeys) {
    const memberIndex = state.members.findIndex((member) =>
      bytesEqual(member.aciBytes, modification.aciBytes)
    );
    if (memberIndex !== -1) {
      state.members[memberIndex] = {
        ...state.members[memberIndex],
        profileKey: modification.profileKey,
      };
    } else {
      throw new Error('INVALID_CHANGE: Attempted to modify profile key of non-existent member');
    }
  }
}

function applyAttributesAndAccessControl(
  state: DecryptedGroup,
  change: DecryptedGroupChange
): void {
  if (change.newTitle !== undefined) state.title = change.newTitle.value;
  if (change.newAvatar !== undefined) state.avatar = change.newAvatar.value;
  if (change.newTimer !== undefined) state.disappearingMessagesTimer = change.newTimer;
  if (change.newDescription !== undefined) state.description = change.newDescription.value;
  if (change.newInviteLinkPassword !== undefined) {
    state.inviteLinkPassword = change.newInviteLinkPassword;
  }
  if (
    change.newIsAnnouncementGroup !== undefined &&
    change.newIsAnnouncementGroup !== EnabledState.UNKNOWN
  ) {
    state.isAnnouncementGroup = change.newIsAnnouncementGroup;
  }

  if (
    change.newAttributeAccess !== undefined &&
    change.newAttributeAccess !== AccessRequired.UNKNOWN
  ) {
    state.accessControl = { ...state.accessControl, attributes: change.newAttributeAccess };
  }
  if (change.newMemberAccess !== undefined && change.newMemberAccess !== AccessRequired.UNKNOWN) {
    state.accessControl = { ...state.accessControl, members: change.newMemberAccess };
  }
  if (
    change.newInviteLinkAccess !== undefined &&
    change.newInviteLinkAccess !== AccessRequired.UNKNOWN
  ) {
    state.accessControl = {
      ...state.accessControl,
      addFromInviteLink: change.newInviteLinkAccess,
    };
  }
  if (
    change.newMemberLabelAccess !== undefined &&
    change.newMemberLabelAccess !== AccessRequired.UNKNOWN
  ) {
    state.accessControl = { ...state.accessControl, memberLabel: change.newMemberLabelAccess };
  }
}

/**
 * Validate the structure of a DecryptedGroupChange against current group state.
 *
 * This answers only whether the change is well-formed. It does not determine
 * whether the editor was authorized to perform the actions.
 *
 * @param state - Current group state
 * @param change - Change to validate
 * @returns Array of validation error strings (empty if valid)
 */
export function validateChangeStructure(
  state: DecryptedGroup,
  change: DecryptedGroupChange,
  form: DecryptedGroupChangeForm = 'canonical'
): string[] {
  const errors = [
    ...validateGroupIdentifiers(state),
    ...validateGroupAccessControl(state),
    ...validateGroupMemberRoles(state),
    ...validateGroupCanonicalFields(state),
    ...validateChangeIdentifiers(change),
    ...validateChangeAccessControl(change),
    ...validateChangeMemberRoles(change),
    ...validateChangeCanonicalFields(state, change, form),
  ];
  if (change.revision !== state.revision + 1) {
    errors.push(`Invalid revision: expected ${state.revision + 1}, got ${change.revision}`);
  }
  if (state.terminated) {
    errors.push('Group is terminated');
    return errors;
  }
  const hasArrayAction =
    change.newMembers.length > 0 ||
    change.deleteMembers.length > 0 ||
    change.modifyMemberRoles.length > 0 ||
    change.modifiedProfileKeys.length > 0 ||
    change.newPendingMembers.length > 0 ||
    change.deletePendingMembers.length > 0 ||
    change.promotePendingMembers.length > 0 ||
    change.promotePendingPniAciMembers.length > 0 ||
    change.newRequestingMembers.length > 0 ||
    change.deleteRequestingMembers.length > 0 ||
    change.promoteRequestingMembers.length > 0 ||
    change.newBannedMembers.length > 0 ||
    change.deleteBannedMembers.length > 0 ||
    change.modifyMemberLabels.length > 0;
  const hasScalarAction =
    change.newTitle !== undefined ||
    change.newAvatar !== undefined ||
    change.newTimer !== undefined ||
    change.newAttributeAccess !== undefined ||
    change.newMemberAccess !== undefined ||
    change.newInviteLinkAccess !== undefined ||
    change.newMemberLabelAccess !== undefined ||
    change['newInviteLinkPassword'] !== undefined ||
    change.newDescription !== undefined ||
    change.newIsAnnouncementGroup !== undefined ||
    change.terminate !== undefined;
  if (!hasArrayAction && !hasScalarAction) {
    errors.push('Change contains no actions');
    return errors;
  }

  const shadow = cloneGroup(state);
  const step = (): DecryptedGroupChange =>
    emptyGroupChange(change.editorServiceIdBytes, change.revision);
  const validateStep = (apply: () => void): void => {
    try {
      apply();
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      errors.push(message.replace(/^INVALID_CHANGE: /, ''));
    }
  };

  // Mirror §7.4 exactly so validation and application cannot disagree about
  // which targets exist at each phase.
  for (const removal of change.deletePendingMembers) {
    validateStep(() => {
      const current = step();
      current.deletePendingMembers = [removal];
      applyDeletions(shadow, current);
    });
  }
  for (const aciBytes of change.deleteRequestingMembers) {
    validateStep(() => {
      const current = step();
      current.deleteRequestingMembers = [aciBytes];
      applyDeletions(shadow, current);
    });
  }
  for (const removal of change.deleteBannedMembers) {
    validateStep(() => {
      const current = step();
      current.deleteBannedMembers = [removal];
      applyDeletions(shadow, current);
    });
  }
  for (const aciBytes of change.deleteMembers) {
    validateStep(() => {
      const current = step();
      current.deleteMembers = [aciBytes];
      applyDeletions(shadow, current);
    });
  }
  for (const banned of change.newBannedMembers) {
    validateStep(() => {
      const current = step();
      current.newBannedMembers = [banned];
      applyBans(shadow, current);
    });
  }
  for (const promotion of change.promotePendingMembers) {
    validateStep(() => {
      const current = step();
      current.promotePendingMembers = [promotion];
      applyPromotions(shadow, current);
    });
  }
  for (const promotion of change.promotePendingPniAciMembers) {
    validateStep(() => {
      const current = step();
      current.promotePendingPniAciMembers = [promotion];
      applyPromotions(shadow, current);
    });
  }
  for (const approval of change.promoteRequestingMembers) {
    validateStep(() => {
      const current = step();
      current.promoteRequestingMembers = [approval];
      applyPromotions(shadow, current);
    });
  }
  for (const member of change.newMembers) {
    validateStep(() => {
      const current = step();
      current.newMembers = [member];
      applyAdditions(shadow, current);
    });
  }
  for (const pending of change.newPendingMembers) {
    validateStep(() => {
      const current = step();
      current.newPendingMembers = [pending];
      applyAdditions(shadow, current);
    });
  }
  for (const requesting of change.newRequestingMembers) {
    validateStep(() => {
      const current = step();
      current.newRequestingMembers = [requesting];
      applyAdditions(shadow, current);
    });
  }
  for (const modification of change.modifyMemberRoles) {
    validateStep(() => {
      const current = step();
      current.modifyMemberRoles = [modification];
      applyMemberModifications(shadow, current);
    });
  }
  for (const modification of change.modifyMemberLabels) {
    validateStep(() => {
      const current = step();
      current.modifyMemberLabels = [modification];
      applyMemberModifications(shadow, current);
    });
  }
  for (const modification of change.modifiedProfileKeys) {
    validateStep(() => {
      const current = step();
      current.modifiedProfileKeys = [modification];
      applyMemberModifications(shadow, current);
    });
  }
  if (change.terminate !== undefined) {
    validateStep(() => {
      const current = step();
      current.terminate = change.terminate;
      applyTermination(shadow, current);
    });
  }

  return errors;
}
