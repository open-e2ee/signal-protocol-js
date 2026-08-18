/**
 * Group wire serialization
 *
 * The group transport uses JSON with explicit byte markers. Clients and the
 * executable reference server share these helpers, so they store and sign
 * accepted Actions byte-for-byte.
 *
 * @module groups/wire
 */

import { bytesToHex, hexToBytes } from '../../encoding/hex';
import {
  EnabledState,
  type EncryptedGroup,
  type EncryptedGroupCreationSubmission,
  type EncryptedGroupChange,
  type EncryptedGroupJoinInfo,
} from './types';
import {
  isInviteLinkAccessRequirement,
  isRoleAccessRequirement,
  isStoredMemberRole,
  satisfiesLiveGroupAdministratorInvariant,
} from './access-control';
import {
  SERVICE_ID_ACI,
  SERVICE_ID_PNI,
} from '../protocol/zk/groups/uid-struct';
import { RistrettoPoint } from '../protocol/zk/proofs/sho';

const ENCRYPTED_CHANGE_ARRAY_ACTION_KEYS = [
  'newMembers',
  'deleteMembers',
  'modifyMemberRoles',
  'modifiedProfileKeys',
  'newPendingMembers',
  'deletePendingMembers',
  'promotePendingMembers',
  'newRequestingMembers',
  'deleteRequestingMembers',
  'promoteRequestingMembers',
  'newBannedMembers',
  'deleteBannedMembers',
  'promotePendingPniAciMembers',
  'modifyMemberLabels',
] as const satisfies ReadonlyArray<keyof EncryptedGroupChange>;

const ENCRYPTED_CHANGE_SCALAR_ACTION_KEYS = [
  'newTitle',
  'newAvatar',
  'newTimer',
  'newAttributeAccess',
  'newMemberAccess',
  'newInviteLinkAccess',
  'newMemberLabelAccess',
  'newInviteLinkPassword',
  'newDescription',
  'newIsAnnouncementGroup',
  'terminate',
] as const satisfies ReadonlyArray<keyof EncryptedGroupChange>;

type EncryptedGroupActionKey = Exclude<
  keyof EncryptedGroupChange,
  'sourceUserId' | 'groupId' | 'revision'
>;

const ENCRYPTED_CHANGE_MINIMUM_EPOCH = {
  newMembers: 0,
  deleteMembers: 0,
  modifyMemberRoles: 0,
  modifiedProfileKeys: 0,
  newPendingMembers: 0,
  deletePendingMembers: 0,
  promotePendingMembers: 0,
  newRequestingMembers: 0,
  deleteRequestingMembers: 0,
  promoteRequestingMembers: 0,
  newBannedMembers: 0,
  deleteBannedMembers: 0,
  promotePendingPniAciMembers: 5,
  modifyMemberLabels: 6,
  newTitle: 0,
  newAvatar: 0,
  newTimer: 0,
  newAttributeAccess: 0,
  newMemberAccess: 0,
  newInviteLinkAccess: 0,
  newMemberLabelAccess: 0,
  newInviteLinkPassword: 0,
  newDescription: 0,
  newIsAnnouncementGroup: 0,
  terminate: 0,
} as const satisfies Record<EncryptedGroupActionKey, number>;

const ENCRYPTED_CHANGE_KEYS = new Set<keyof EncryptedGroupChange>([
  'sourceUserId',
  'groupId',
  'revision',
  ...ENCRYPTED_CHANGE_ARRAY_ACTION_KEYS,
  ...ENCRYPTED_CHANGE_SCALAR_ACTION_KEYS,
]);

export function serializeGroupWire(value: unknown): Uint8Array {
  const json = JSON.stringify(value, (_key, item) =>
    item instanceof Uint8Array ? { __bytes: bytesToHex(item) } : item
  );
  return new TextEncoder().encode(json);
}

export function deserializeGroupWire<T>(bytes: Uint8Array): T {
  return JSON.parse(new TextDecoder().decode(bytes), (_key, item) => {
    if (item && typeof item === 'object' && '__bytes' in item) {
      if (
        Object.keys(item).length !== 1 ||
        typeof (item as { __bytes?: unknown }).__bytes !== 'string'
      ) {
        throw new Error('Byte marker must contain exactly one hexadecimal string');
      }
      return hexToBytes((item as { __bytes: string }).__bytes);
    }
    return item;
  }) as T;
}

export function serializeEncryptedGroup(group: EncryptedGroup): Uint8Array {
  return serializeGroupWire(group);
}

export function deserializeEncryptedGroup(bytes: Uint8Array): EncryptedGroup {
  return deserializeGroupWire<EncryptedGroup>(bytes);
}

export function serializeEncryptedGroupCreationSubmission(
  group: EncryptedGroupCreationSubmission
): Uint8Array {
  return serializeGroupWire(group);
}

export function deserializeEncryptedGroupCreationSubmission(
  bytes: Uint8Array
): EncryptedGroupCreationSubmission {
  return deserializeGroupWire<EncryptedGroupCreationSubmission>(bytes);
}

/**
 * Remove server-derived creation fields from an encrypted candidate state.
 *
 * Callers cannot smuggle pre-existing requesting or banned entries into
 * version zero.
 */
export function toEncryptedGroupCreationSubmission(
  group: EncryptedGroup
): EncryptedGroupCreationSubmission {
  if (group.membersPendingAdminApproval.length !== 0) {
    throw new Error(
      'Group creation submission must not contain requesting members'
    );
  }
  if (group.membersBanned.length !== 0) {
    throw new Error('Group creation submission must not contain banned members');
  }
  return {
    ...group,
    membersPendingProfileKey: group.membersPendingProfileKey.map(
      ({ member }) => ({
        userId: member.userId,
        role: member.role,
      })
    ),
    membersPendingAdminApproval: [],
    membersBanned: [],
  };
}

/**
 * Serialize the exact S14 commitment signed for a full-state response.
 *
 * `canonicalGroupState` is already the canonical serialized EncryptedGroup.
 * Wrapping the tuple in the group wire format makes the three variable-width
 * values unambiguous while preserving the state bytes exactly as served.
 */
export function serializeGroupBaseline(
  groupId: Uint8Array,
  version: number,
  canonicalGroupState: Uint8Array
): Uint8Array {
  if (!Number.isSafeInteger(version) || version < 0) {
    throw new Error('Baseline version must be a non-negative safe integer');
  }
  return serializeGroupWire({
    groupId,
    version,
    canonicalGroupState,
  });
}

/** Serialize Revision 16's exact S7 signature commitment. */
export function serializeGroupChangeCommitment(
  changeEpoch: number,
  actions: Uint8Array
): Uint8Array {
  if (
    !Number.isInteger(changeEpoch) ||
    changeEpoch < 0 ||
    changeEpoch > 0xffffffff
  ) {
    throw new Error('Change epoch must be an unsigned 32-bit integer');
  }
  if (!(actions instanceof Uint8Array)) {
    throw new Error('Committed Actions must be bytes');
  }
  return serializeGroupWire({
    changeEpoch,
    actions,
  });
}

export function serializeEncryptedGroupChange(change: EncryptedGroupChange): Uint8Array {
  return serializeGroupWire(change);
}

export function deserializeEncryptedGroupChange(bytes: Uint8Array): EncryptedGroupChange {
  return deserializeGroupWire<EncryptedGroupChange>(bytes);
}

/** Compute Revision 19's authoritative compatibility epoch from populated actions. */
export function requiredGroupChangeEpoch(
  change: EncryptedGroupChange
): number {
  let required = 0;
  for (const key of ENCRYPTED_CHANGE_ARRAY_ACTION_KEYS) {
    if ((change[key] as unknown[]).length > 0) {
      required = Math.max(required, ENCRYPTED_CHANGE_MINIMUM_EPOCH[key]);
    }
  }
  for (const key of ENCRYPTED_CHANGE_SCALAR_ACTION_KEYS) {
    if (change[key] !== undefined) {
      required = Math.max(required, ENCRYPTED_CHANGE_MINIMUM_EPOCH[key]);
    }
  }
  return required;
}

/** Count populated actions, including every element of repeated action fields. */
export function countGroupChangeActions(
  change: EncryptedGroupChange
): number {
  let count = 0;
  for (const key of ENCRYPTED_CHANGE_ARRAY_ACTION_KEYS) {
    count += (change[key] as unknown[]).length;
  }
  for (const key of ENCRYPTED_CHANGE_SCALAR_ACTION_KEYS) {
    count += Number(change[key] !== undefined);
  }
  return count;
}

/**
 * Reject unknown, missing-array, and actionless signed Actions values.
 *
 * The server and client share this representation-level check. One side
 * therefore cannot apply an unknown field that the other silently discards.
 */
export function assertRecognizedEncryptedGroupChange(
  change: EncryptedGroupChange
): void {
  if (typeof change !== 'object' || change === null) {
    throw new Error('Actions must be an object');
  }
  for (const key of Object.keys(change)) {
    if (!ENCRYPTED_CHANGE_KEYS.has(key as keyof EncryptedGroupChange)) {
      throw new Error(`Actions contain unsupported field ${key}`);
    }
  }
  for (const key of ENCRYPTED_CHANGE_ARRAY_ACTION_KEYS) {
    if (!Array.isArray(change[key])) {
      throw new Error(`Actions.${key} must be an array`);
    }
  }
  const hasArrayAction = ENCRYPTED_CHANGE_ARRAY_ACTION_KEYS.some(
    (key) => (change[key] as unknown[]).length > 0
  );
  const hasScalarAction = ENCRYPTED_CHANGE_SCALAR_ACTION_KEYS.some(
    (key) => change[key] !== undefined
  );
  if (!hasArrayAction && !hasScalarAction) {
    throw new Error('Actions contain no action');
  }
}

export type EncryptedGroupChangeForm = 'submission' | 'canonical';

function assertExactActionFields(
  value: unknown,
  label: string,
  expectedFields: readonly string[]
): void {
  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value) ||
    value instanceof Uint8Array
  ) {
    throw new Error(`${label} must be an action object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...expectedFields].sort();
  if (
    actual.length !== expected.length ||
    actual.some((field, index) => field !== expected[index])
  ) {
    throw new Error(
      `${label} has non-canonical fields: expected ${expected.join(', ')}, got ${actual.join(', ')}`
    );
  }
}

/**
 * Enforce §7.8's exact action surfaces.
 *
 * Server-derived fields must be absent in submissions and present in signed
 * canonical Actions. Every other action field has one exact surface.
 */
export function assertEncryptedGroupChangeForm(
  change: EncryptedGroupChange,
  form: EncryptedGroupChangeForm
): void {
  const canonical = form === 'canonical';
  const check = (
    entries: readonly unknown[],
    label: string,
    fields: readonly string[]
  ): void => {
    entries.forEach((entry, index) =>
      assertExactActionFields(entry, `${label}[${index}]`, fields)
    );
  };

  check(change.newMembers, 'Actions.newMembers', [
    'aciCiphertext',
    'role',
    'profileKeyCiphertext',
    'presentation',
    ...(canonical ? ['joinedAtRevision'] : []),
  ]);
  check(change.modifyMemberRoles, 'Actions.modifyMemberRoles', [
    'aciCiphertext',
    'role',
  ]);
  check(change.modifiedProfileKeys, 'Actions.modifiedProfileKeys', [
    'aciCiphertext',
    'profileKeyCiphertext',
    'presentation',
  ]);
  check(change.newPendingMembers, 'Actions.newPendingMembers', [
    'serviceIdCiphertext',
    'role',
    ...(canonical ? ['addedByAciCiphertext', 'timestamp'] : []),
  ]);
  check(change.deletePendingMembers, 'Actions.deletePendingMembers', [
    'serviceIdCiphertext',
  ]);
  check(change.promotePendingMembers, 'Actions.promotePendingMembers', [
    'aciCiphertext',
    'profileKeyCiphertext',
    'presentation',
    ...(canonical ? ['role', 'joinedAtRevision'] : []),
  ]);
  check(change.newRequestingMembers, 'Actions.newRequestingMembers', [
    'aciCiphertext',
    'profileKeyCiphertext',
    'presentation',
    ...(canonical ? ['timestamp'] : []),
  ]);
  check(change.promoteRequestingMembers, 'Actions.promoteRequestingMembers', [
    'aciCiphertext',
    'role',
  ]);
  check(change.newBannedMembers, 'Actions.newBannedMembers', [
    'serviceIdCiphertext',
    ...(canonical ? ['timestamp'] : []),
  ]);
  check(change.deleteBannedMembers, 'Actions.deleteBannedMembers', [
    'serviceIdCiphertext',
  ]);
  check(
    change.promotePendingPniAciMembers,
    'Actions.promotePendingPniAciMembers',
    [
      'pniCiphertext',
      'aciCiphertext',
      'profileKeyCiphertext',
      'presentation',
      ...(canonical ? ['role', 'joinedAtRevision'] : []),
    ]
  );
  check(change.modifyMemberLabels, 'Actions.modifyMemberLabels', [
    'aciCiphertext',
    'labelEmojiCiphertext',
    'labelStringCiphertext',
  ]);
  if (change.newAvatar !== undefined) {
    assertExactActionFields(change.newAvatar, 'Actions.newAvatar', ['value']);
  }
}

type CiphertextKind = 'aci' | 'pni' | 'service-id' | 'profile-key';

function assertByteArray(
  value: unknown,
  label: string,
  length?: number
): asserts value is Uint8Array {
  if (
    !(value instanceof Uint8Array) ||
    (length !== undefined && value.length !== length)
  ) {
    throw new Error(
      `${label} must be ${length === undefined ? 'bytes' : `${length}-byte data`}`
    );
  }
}

function assertCiphertextEncoding(
  value: unknown,
  label: string,
  kind: CiphertextKind
): asserts value is Uint8Array {
  assertByteArray(value, label, 65);
  if (kind === 'aci' && value[0] !== SERVICE_ID_ACI) {
    throw new Error(`${label} must carry an ACI ciphertext`);
  }
  if (kind === 'pni' && value[0] !== SERVICE_ID_PNI) {
    throw new Error(`${label} must carry a PNI ciphertext`);
  }
  if (
    kind === 'service-id' &&
    value[0] !== SERVICE_ID_ACI &&
    value[0] !== SERVICE_ID_PNI
  ) {
    throw new Error(`${label} must carry an ACI or PNI ciphertext`);
  }
  if (kind === 'profile-key' && value[0] !== 0) {
    throw new Error(`${label} has an invalid reserved byte`);
  }
  try {
    RistrettoPoint.fromBytes(value.slice(1, 33));
    RistrettoPoint.fromBytes(value.slice(33, 65));
  } catch {
    throw new Error(`${label} contains an invalid Ristretto ciphertext point`);
  }
}

function assertBlobEncoding(
  value: unknown,
  label: string,
  allowEmpty = true
): asserts value is Uint8Array {
  assertByteArray(value, label);
  if (allowEmpty && value.length === 0) return;
  if (
    value.length < 65 ||
    (value.length - 65) % 32 !== 0 ||
    value[value.length - 1] !== 0
  ) {
    throw new Error(`${label} has an invalid encrypted-blob envelope`);
  }
}

function assertTimestamp(value: unknown, label: string): asserts value is number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new Error(`${label} is outside its §7.8 domain`);
  }
}

/**
 * Enforce Revision 16's complete encrypted Actions wire domain.
 *
 * The accepting server and the receiving client share this validator.
 */
export function assertValidEncryptedGroupChangeWire(
  change: EncryptedGroupChange,
  form: EncryptedGroupChangeForm
): void {
  assertRecognizedEncryptedGroupChange(change);
  assertEncryptedGroupChangeForm(change, form);
  const canonical = form === 'canonical';

  if (!Number.isSafeInteger(change.revision) || change.revision < 1) {
    throw new Error('Actions.revision must be a positive safe integer');
  }
  if (change.sourceUserId !== undefined) {
    assertCiphertextEncoding(
      change.sourceUserId,
      'Actions.sourceUserId',
      'service-id'
    );
  } else if (canonical) {
    throw new Error('Actions.sourceUserId is required in canonical form');
  }
  if (change.groupId !== undefined) {
    assertByteArray(change.groupId, 'Actions.groupId', 32);
  } else if (canonical) {
    throw new Error('Actions.groupId is required in canonical form');
  }
  if (change.terminate !== undefined && change.terminate !== true) {
    throw new Error('Actions.terminate must be true when present');
  }

  const assertProfileKeyAction = (
    member: {
      aciCiphertext: unknown;
      profileKeyCiphertext: unknown;
      presentation: unknown;
    },
    label: string
  ): void => {
    assertCiphertextEncoding(
      member.aciCiphertext,
      `${label}.aciCiphertext`,
      'aci'
    );
    assertCiphertextEncoding(
      member.profileKeyCiphertext,
      `${label}.profileKeyCiphertext`,
      'profile-key'
    );
    assertByteArray(member.presentation, `${label}.presentation`);
  };

  for (const [index, member] of change.newMembers.entries()) {
    const label = `Actions.newMembers[${index}]`;
    assertProfileKeyAction(member, label);
    if (!isStoredMemberRole(member.role)) {
      throw new Error(`${label}.role is outside its stored-role domain`);
    }
    if (canonical && member.joinedAtRevision !== change.revision) {
      throw new Error(
        `${label}.joinedAtRevision must equal the change revision`
      );
    }
  }
  for (const [index, ciphertext] of change.deleteMembers.entries()) {
    assertCiphertextEncoding(
      ciphertext,
      `Actions.deleteMembers[${index}]`,
      'aci'
    );
  }
  for (const [index, member] of change.modifyMemberRoles.entries()) {
    const label = `Actions.modifyMemberRoles[${index}]`;
    assertCiphertextEncoding(member.aciCiphertext, `${label}.aciCiphertext`, 'aci');
    if (!isStoredMemberRole(member.role)) {
      throw new Error(`${label}.role is outside its stored-role domain`);
    }
  }
  for (const [index, member] of change.modifiedProfileKeys.entries()) {
    assertProfileKeyAction(
      member,
      `Actions.modifiedProfileKeys[${index}]`
    );
  }
  for (const [index, member] of change.newPendingMembers.entries()) {
    const label = `Actions.newPendingMembers[${index}]`;
    assertCiphertextEncoding(
      member.serviceIdCiphertext,
      `${label}.serviceIdCiphertext`,
      'service-id'
    );
    if (!isStoredMemberRole(member.role)) {
      throw new Error(`${label}.role is outside its stored-role domain`);
    }
    if (canonical) {
      assertCiphertextEncoding(
        member.addedByAciCiphertext,
        `${label}.addedByAciCiphertext`,
        'aci'
      );
      assertTimestamp(member.timestamp, `${label}.timestamp`);
    }
  }
  for (const [index, member] of change.deletePendingMembers.entries()) {
    assertCiphertextEncoding(
      member.serviceIdCiphertext,
      `Actions.deletePendingMembers[${index}].serviceIdCiphertext`,
      'service-id'
    );
  }
  for (const [index, member] of change.promotePendingMembers.entries()) {
    const label = `Actions.promotePendingMembers[${index}]`;
    assertProfileKeyAction(member, label);
    if (
      canonical &&
      (!isStoredMemberRole(member.role) ||
        member.joinedAtRevision !== change.revision)
    ) {
      throw new Error(`${label} has invalid server-derived fields`);
    }
  }
  for (const [index, member] of change.newRequestingMembers.entries()) {
    const label = `Actions.newRequestingMembers[${index}]`;
    assertProfileKeyAction(member, label);
    if (canonical) {
      assertTimestamp(member.timestamp, `${label}.timestamp`);
    }
  }
  for (const [index, ciphertext] of change.deleteRequestingMembers.entries()) {
    assertCiphertextEncoding(
      ciphertext,
      `Actions.deleteRequestingMembers[${index}]`,
      'aci'
    );
  }
  for (const [index, member] of change.promoteRequestingMembers.entries()) {
    const label = `Actions.promoteRequestingMembers[${index}]`;
    assertCiphertextEncoding(member.aciCiphertext, `${label}.aciCiphertext`, 'aci');
    if (!isStoredMemberRole(member.role)) {
      throw new Error(`${label}.role is outside its stored-role domain`);
    }
  }
  for (const [index, member] of change.newBannedMembers.entries()) {
    const label = `Actions.newBannedMembers[${index}]`;
    assertCiphertextEncoding(
      member.serviceIdCiphertext,
      `${label}.serviceIdCiphertext`,
      'service-id'
    );
    if (canonical) {
      assertTimestamp(member.timestamp, `${label}.timestamp`);
    }
  }
  for (const [index, member] of change.deleteBannedMembers.entries()) {
    assertCiphertextEncoding(
      member.serviceIdCiphertext,
      `Actions.deleteBannedMembers[${index}].serviceIdCiphertext`,
      'service-id'
    );
  }
  for (const [index, member] of change.promotePendingPniAciMembers.entries()) {
    const label = `Actions.promotePendingPniAciMembers[${index}]`;
    assertProfileKeyAction(member, label);
    assertCiphertextEncoding(
      member.pniCiphertext,
      `${label}.pniCiphertext`,
      'pni'
    );
    if (
      canonical &&
      (!isStoredMemberRole(member.role) ||
        member.joinedAtRevision !== change.revision)
    ) {
      throw new Error(`${label} has invalid server-derived fields`);
    }
  }
  for (const [index, member] of change.modifyMemberLabels.entries()) {
    const label = `Actions.modifyMemberLabels[${index}]`;
    assertCiphertextEncoding(member.aciCiphertext, `${label}.aciCiphertext`, 'aci');
    assertBlobEncoding(
      member.labelEmojiCiphertext,
      `${label}.labelEmojiCiphertext`
    );
    assertBlobEncoding(
      member.labelStringCiphertext,
      `${label}.labelStringCiphertext`
    );
  }

  for (const [value, label] of [
    [change.newTitle, 'Actions.newTitle'],
    [change.newTimer, 'Actions.newTimer'],
    [change.newDescription, 'Actions.newDescription'],
  ] as const) {
    if (value !== undefined) {
      assertBlobEncoding(value, label, false);
    }
  }
  if (
    change.newAvatar !== undefined &&
    typeof change.newAvatar.value !== 'string'
  ) {
    throw new Error('Actions.newAvatar.value must be a string');
  }
  for (const [value, label] of [
    [change.newAttributeAccess, 'Actions.newAttributeAccess'],
    [change.newMemberAccess, 'Actions.newMemberAccess'],
    [change.newMemberLabelAccess, 'Actions.newMemberLabelAccess'],
  ] as const) {
    if (value !== undefined && !isRoleAccessRequirement(value)) {
      throw new Error(`${label} is outside its access-control domain`);
    }
  }
  if (
    change.newInviteLinkAccess !== undefined &&
    !isInviteLinkAccessRequirement(change.newInviteLinkAccess)
  ) {
    throw new Error(
      'Actions.newInviteLinkAccess is outside its access-control domain'
    );
  }
  if (
    change.newIsAnnouncementGroup !== undefined &&
    change.newIsAnnouncementGroup !== EnabledState.ENABLED &&
    change.newIsAnnouncementGroup !== EnabledState.DISABLED
  ) {
    throw new Error(
      'newIsAnnouncementGroup is outside its §7.8 domain'
    );
  }
  if (change.newInviteLinkPassword !== undefined) {
    if (!(change.newInviteLinkPassword instanceof Uint8Array)) {
      throw new Error('Actions.newInviteLinkPassword must be bytes');
    }
    if (change.newInviteLinkPassword.length !== 16) {
      throw new Error(
        'newInviteLinkPassword must be exactly 16 bytes'
      );
    }
  }
}

const ENCRYPTED_GROUP_FIELDS = [
  'publicKey',
  'title',
  'description',
  'avatarUrl',
  'disappearingMessagesTimer',
  'accessControl',
  'version',
  'members',
  'membersPendingProfileKey',
  'membersPendingAdminApproval',
  'inviteLinkPassword',
  'announcementsOnly',
  'membersBanned',
  'terminated',
] as const satisfies ReadonlyArray<keyof EncryptedGroup>;

type EncryptedGroupWire =
  | EncryptedGroup
  | EncryptedGroupCreationSubmission;

function assertValidEncryptedGroupWireForm(
  group: EncryptedGroupWire,
  form: 'canonical' | 'creation-submission'
): void {
  assertExactActionFields(group, 'Group', ENCRYPTED_GROUP_FIELDS);
  if (!Number.isSafeInteger(group.version) || group.version < 0) {
    throw new Error('Group.version must be a non-negative safe integer');
  }
  if (form === 'creation-submission' && group.version !== 0) {
    throw new Error('Group creation submission version must be zero');
  }
  if (
    !Array.isArray(group.members) ||
    !Array.isArray(group.membersPendingProfileKey) ||
    !Array.isArray(group.membersPendingAdminApproval) ||
    !Array.isArray(group.membersBanned)
  ) {
    throw new Error('Group membership fields must be arrays');
  }
  if (group.members.length > 1000) {
    throw new Error('Group exceeds the 1000-member limit');
  }
  if (group.membersPendingProfileKey.length > 1000) {
    throw new Error('Group exceeds the 1000-pending-member limit');
  }
  if (group.membersPendingAdminApproval.length > 1000) {
    throw new Error('Group exceeds the 1000-requesting-member limit');
  }
  if (group.membersBanned.length > 1000) {
    throw new Error('Group exceeds the 1000-banned-member limit');
  }
  assertByteArray(group.publicKey, 'Group.publicKey', 96);
  assertBlobEncoding(group.title, 'Group.title');
  assertBlobEncoding(group.description, 'Group.description');
  assertBlobEncoding(
    group.disappearingMessagesTimer,
    'Group.disappearingMessagesTimer'
  );
  if (typeof group.avatarUrl !== 'string') {
    throw new Error('Group.avatarUrl must be a string');
  }
  if (typeof group.announcementsOnly !== 'boolean') {
    throw new Error('Group.announcementsOnly must be a boolean');
  }
  if (typeof group.terminated !== 'boolean') {
    throw new Error('Group.terminated must be a boolean');
  }
  assertByteArray(group.inviteLinkPassword, 'Group.inviteLinkPassword');
  if (
    group.inviteLinkPassword.length !== 0 &&
    group.inviteLinkPassword.length !== 16
  ) {
    throw new Error('Group.inviteLinkPassword must be empty or 16 bytes');
  }
  assertExactActionFields(group.accessControl, 'Group.accessControl', [
    'attributes',
    'members',
    'addFromInviteLink',
    'memberLabel',
  ]);
  if (
    !isRoleAccessRequirement(group.accessControl.attributes) ||
    !isRoleAccessRequirement(group.accessControl.members) ||
    !isRoleAccessRequirement(group.accessControl.memberLabel) ||
    !isInviteLinkAccessRequirement(group.accessControl.addFromInviteLink)
  ) {
    throw new Error('Group.accessControl is outside its domain');
  }

  const occupied = new Set<string>();
  const occupy = (ciphertext: Uint8Array, label: string): void => {
    const key = bytesToHex(ciphertext);
    if (occupied.has(key)) {
      throw new Error(
        `Principal appears in multiple group-state entries (${label})`
      );
    }
    occupied.add(key);
  };
  for (const [index, member] of group.members.entries()) {
    const label = `Group.members[${index}]`;
    assertExactActionFields(member, label, [
      'userId',
      'role',
      'profileKey',
      'presentation',
      'joinedAtVersion',
      'labelEmoji',
      'labelString',
    ]);
    assertCiphertextEncoding(member.userId, `${label}.userId`, 'aci');
    assertCiphertextEncoding(
      member.profileKey,
      `${label}.profileKey`,
      'profile-key'
    );
    assertByteArray(member.presentation, `${label}.presentation`);
    assertBlobEncoding(member.labelEmoji, `${label}.labelEmoji`);
    assertBlobEncoding(member.labelString, `${label}.labelString`);
    if (!isStoredMemberRole(member.role)) {
      throw new Error(`${label}.role is outside its stored-role domain`);
    }
    if (
      !Number.isSafeInteger(member.joinedAtVersion) ||
      member.joinedAtVersion < 0 ||
      member.joinedAtVersion > group.version
    ) {
      throw new Error(`${label}.joinedAtVersion is outside its domain`);
    }
    occupy(member.userId, label);
  }
  for (const [index, pending] of group.membersPendingProfileKey.entries()) {
    const label = `Group.membersPendingProfileKey[${index}]`;
    if (form === 'creation-submission') {
      const submitted =
        pending as EncryptedGroupCreationSubmission['membersPendingProfileKey'][number];
      assertExactActionFields(submitted, label, ['userId', 'role']);
      assertCiphertextEncoding(
        submitted.userId,
        `${label}.userId`,
        'service-id'
      );
      if (!isStoredMemberRole(submitted.role)) {
        throw new Error(`${label}.role is outside its stored-role domain`);
      }
      occupy(submitted.userId, label);
      continue;
    }
    const canonical =
      pending as EncryptedGroup['membersPendingProfileKey'][number];
    assertExactActionFields(canonical, label, [
      'member',
      'addedByUserId',
      'timestamp',
    ]);
    assertExactActionFields(canonical.member, `${label}.member`, [
      'userId',
      'role',
      'profileKey',
      'presentation',
      'joinedAtVersion',
      'labelEmoji',
      'labelString',
    ]);
    assertCiphertextEncoding(
      canonical.member.userId,
      `${label}.member.userId`,
      'service-id'
    );
    assertCiphertextEncoding(
      canonical.addedByUserId,
      `${label}.addedByUserId`,
      'aci'
    );
    assertTimestamp(canonical.timestamp, `${label}.timestamp`);
    if (!isStoredMemberRole(canonical.member.role)) {
      throw new Error(`${label}.member.role is outside its stored-role domain`);
    }
    assertByteArray(canonical.member.profileKey, `${label}.member.profileKey`, 0);
    assertByteArray(
      canonical.member.presentation,
      `${label}.member.presentation`,
      0
    );
    assertByteArray(canonical.member.labelEmoji, `${label}.member.labelEmoji`, 0);
    assertByteArray(
      canonical.member.labelString,
      `${label}.member.labelString`,
      0
    );
    if (canonical.member.joinedAtVersion !== 0) {
      throw new Error(`${label}.member.joinedAtVersion must be zero`);
    }
    occupy(canonical.member.userId, label);
  }
  if (
    form === 'creation-submission' &&
    group.membersPendingAdminApproval.length !== 0
  ) {
    throw new Error(
      'Group creation submission must not contain requesting members'
    );
  }
  for (const [index, requesting] of group.membersPendingAdminApproval.entries()) {
    const label = `Group.membersPendingAdminApproval[${index}]`;
    assertExactActionFields(requesting, label, [
      'userId',
      'profileKey',
      'presentation',
      'timestamp',
    ]);
    assertCiphertextEncoding(requesting.userId, `${label}.userId`, 'aci');
    assertCiphertextEncoding(
      requesting.profileKey,
      `${label}.profileKey`,
      'profile-key'
    );
    assertByteArray(requesting.presentation, `${label}.presentation`);
    assertTimestamp(requesting.timestamp, `${label}.timestamp`);
    occupy(requesting.userId, label);
  }
  if (form === 'creation-submission' && group.membersBanned.length !== 0) {
    throw new Error('Group creation submission must not contain banned members');
  }
  for (const [index, banned] of group.membersBanned.entries()) {
    const label = `Group.membersBanned[${index}]`;
    assertExactActionFields(banned, label, ['userId', 'timestamp']);
    assertCiphertextEncoding(banned.userId, `${label}.userId`, 'service-id');
    assertTimestamp(banned.timestamp, `${label}.timestamp`);
    occupy(banned.userId, label);
  }
  if (!satisfiesLiveGroupAdministratorInvariant(group)) {
    throw new Error(
      'Every non-terminated group must have at least one administrator'
    );
  }
}

/** Enforce Revision 16's complete encrypted S14 baseline wire domain. */
export function assertValidEncryptedGroupWire(group: EncryptedGroup): void {
  assertValidEncryptedGroupWireForm(group, 'canonical');
}

/** Enforce Revision 18's provenance-free creation submission domain. */
export function assertValidEncryptedGroupCreationSubmissionWire(
  group: EncryptedGroupCreationSubmission
): void {
  assertValidEncryptedGroupWireForm(group, 'creation-submission');
}

export function serializeEncryptedGroupJoinInfo(info: EncryptedGroupJoinInfo): Uint8Array {
  return serializeGroupWire(info);
}

export function deserializeEncryptedGroupJoinInfo(bytes: Uint8Array): EncryptedGroupJoinInfo {
  return deserializeGroupWire<EncryptedGroupJoinInfo>(bytes);
}
