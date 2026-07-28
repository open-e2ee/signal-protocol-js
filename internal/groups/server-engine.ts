/**
 * Shared enforcing engine for the group-server contract.
 *
 * The engine operates only on encrypted group state. Storage adapters hydrate
 * one group into the engine, execute an operation, and persist the resulting
 * canonical state, signed log, and versioned snapshots atomically.
 */

import type {
  GroupAuthorization,
  GroupChangeLogEntry,
  IGroupServer,
} from './manager';
import {
  AccessRequired,
  EnabledState,
  MemberRole,
  type EncryptedChangeAddMember,
  type EncryptedChangePendingMemberPromotion,
  type EncryptedGroup,
  type EncryptedGroupCreationSubmission,
  type EncryptedGroupChange,
  type EncryptedGroupJoinInfo,
} from './types';
import {
  assertEncryptedGroupChangeForm,
  assertRecognizedEncryptedGroupChange,
  assertValidEncryptedGroupChangeWire,
  assertValidEncryptedGroupCreationSubmissionWire,
  assertValidEncryptedGroupWire,
  deserializeEncryptedGroupCreationSubmission,
  deserializeEncryptedGroup,
  deserializeEncryptedGroupChange,
  serializeEncryptedGroup,
  serializeEncryptedGroupChange,
  serializeEncryptedGroupJoinInfo,
  serializeGroupBaseline,
  serializeGroupChangeCommitment,
  requiredGroupChangeEpoch,
} from './wire';
import {
  GroupAction,
  canRolePerformAction,
  isInviteLinkAccessRequirement,
  isRoleAccessRequirement,
  isStoredMemberRole,
} from './access-control';
import { constantTimeEqual } from '../crypto/utils';
import {
  deserializeAuthCredentialPresentation,
  deserializeGroupPublicParams,
  serializeGroupPublicParams,
  verifyAuthCredentialPresentation,
} from '../protocol/zk/groups/auth-credential';
import {
  SERVICE_ID_ACI,
  SERVICE_ID_PNI,
} from '../protocol/zk/groups/uid-struct';
import { SECONDS_PER_DAY } from '../protocol/zk/groups/group-params';
import {
  getServerPublicParams,
  serverSign,
  type ServerPublicParams,
  type ServerSecretParams,
} from '../protocol/zk/groups/server-params';
import {
  deserializeProfileKeyCredentialPresentation,
  verifyProfileKeyCredentialPresentation,
} from '../protocol/zk/groups/profile-key-credential';
import type { UidEncCiphertext } from '../protocol/zk/groups/uid-encryption';
import { RistrettoPoint } from '../protocol/zk/proofs/sho';

const MAX_GROUP_SIZE = 1000;
const INVITE_LINK_PASSWORD_LENGTH = 16;

interface StoredSnapshot {
  state: EncryptedGroup;
  baselineSignature: Uint8Array;
}

interface StoredGroup {
  state: EncryptedGroup;
  changes: GroupChangeLogEntry[];
  snapshots: Map<number, StoredSnapshot>;
}

interface VerifiedRequester {
  aciCiphertext: Uint8Array;
  pniCiphertext?: Uint8Array;
}

export interface GroupServerPersistedSnapshot {
  version: number;
  encryptedState: Uint8Array;
  baselineSignature: Uint8Array;
}

export interface GroupServerPersistedGroup {
  encryptedState: Uint8Array;
  changes: GroupChangeLogEntry[];
  snapshots: GroupServerPersistedSnapshot[];
}

export interface GroupServerEngineRuntime {
  now(): number;
  randomBytes(length: number): Uint8Array;
}

const defaultRuntime: GroupServerEngineRuntime = {
  now: () => Date.now(),
  randomBytes: (length) => crypto.getRandomValues(new Uint8Array(length)),
};

/**
 * Machine-readable cause carried on a FORBIDDEN rejection.
 *
 * Two different questions produce a 403 on the read paths, and clients act
 * on the difference: `not_readable` answers "may you read this group at
 * all" (the requester is banned or absent from the authorizing roster) and
 * is what a client may interpret as revocation; `before_join` answers "may
 * you read this version of it" (the join-version floor) and says nothing
 * about current access; `not_a_member` refuses the change log to a
 * requester the snapshot lists only as pending — readable, but holding no
 * tenure the log could narrate. Discriminating by code rather than by
 * message text keeps the distinction out of prose, where it cannot be
 * asserted on without coupling tests — and the manager's revocation
 * handling — to error-message wording.
 */
export type GroupForbiddenReason =
  | 'not_readable'
  | 'before_join'
  | 'not_a_member';

class GroupServerError extends Error {
  readonly data: { code: string; status: number; reason?: string };

  constructor(
    code: string,
    status: number,
    message: string,
    reason?: string
  ) {
    super(`${code}: ${message}`);
    this.name = 'GroupServerError';
    this.data = reason === undefined ? { code, status } : { code, status, reason };
  }
}

function rejectBadRequest(message: string): never {
  throw new GroupServerError('INVALID_REQUEST', 400, message);
}

function rejectUnauthorized(message: string): never {
  throw new GroupServerError('UNAUTHORIZED', 403, message);
}

function rejectForbidden(
  message: string,
  reason?: GroupForbiddenReason
): never {
  throw new GroupServerError('FORBIDDEN', 403, message, reason);
}

function rejectConflict(message: string): never {
  throw new GroupServerError('VERSION_CONFLICT', 409, message);
}

function equal(a: Uint8Array, b: Uint8Array): boolean {
  return constantTimeEqual(a, b);
}

function requireCiphertextEncoding(
  value: unknown,
  label: string,
  kind: 'aci' | 'service-id' | 'profile-key'
): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== 65) {
    rejectBadRequest(`${label} must be a 65-byte ciphertext`);
  }
  if (kind === 'aci' && value[0] !== SERVICE_ID_ACI) {
    rejectBadRequest(`${label} must carry an ACI ciphertext`);
  }
  if (
    kind === 'service-id' &&
    value[0] !== SERVICE_ID_ACI &&
    value[0] !== SERVICE_ID_PNI
  ) {
    rejectBadRequest(`${label} must carry an ACI or PNI ciphertext`);
  }
  if (kind === 'profile-key' && value[0] !== 0) {
    rejectBadRequest(`${label} has an invalid reserved byte`);
  }
  try {
    RistrettoPoint.fromBytes(value.slice(1, 33));
    RistrettoPoint.fromBytes(value.slice(33, 65));
  } catch {
    rejectBadRequest(`${label} contains an invalid Ristretto ciphertext point`);
  }
}

function requireBlobEncoding(
  value: unknown,
  label: string,
  allowEmpty = true
): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array)) {
    rejectBadRequest(`${label} must be ciphertext bytes`);
  }
  if (allowEmpty && value.length === 0) return;
  if (
    value.length < 65 ||
    (value.length - 65) % 32 !== 0 ||
    value[value.length - 1] !== 0
  ) {
    rejectBadRequest(`${label} has an invalid encrypted-blob envelope`);
  }
}

function serializePresentationCiphertext(
  kind: typeof SERVICE_ID_ACI | typeof SERVICE_ID_PNI,
  ciphertext: UidEncCiphertext
): Uint8Array {
  const result = new Uint8Array(65);
  result[0] = kind;
  result.set(ciphertext.E_A1.toBytes(), 1);
  result.set(ciphertext.E_A2.toBytes(), 33);
  return result;
}

function serializeProfileKeyPresentationCiphertext(
  ciphertext: ReturnType<
    typeof deserializeProfileKeyCredentialPresentation
  >['profileKeyEncCiphertext']
): Uint8Array {
  const result = new Uint8Array(65);
  result[0] = 0;
  result.set(ciphertext.E_A1.toBytes(), 1);
  result.set(ciphertext.E_A2.toBytes(), 33);
  return result;
}

function verifyProfileKeyPresentation(
  serverSecretParams: ServerSecretParams,
  groupPublicParams: ReturnType<typeof deserializeGroupPublicParams>,
  aciCiphertext: Uint8Array,
  profileKeyCiphertext: Uint8Array,
  presentationBytes: Uint8Array,
  nowSeconds: number
): void {
  if (presentationBytes.length === 0) {
    rejectForbidden('Profile-key credential presentation is required');
  }
  try {
    const presentation =
      deserializeProfileKeyCredentialPresentation(presentationBytes);
    verifyProfileKeyCredentialPresentation(
      serverSecretParams.profileKeyCredentialKeyPair,
      groupPublicParams,
      presentation,
      nowSeconds
    );
    if (
      !equal(
        aciCiphertext,
        serializePresentationCiphertext(
          SERVICE_ID_ACI,
          presentation.uidEncCiphertext
        )
      ) ||
      !equal(
        profileKeyCiphertext,
        serializeProfileKeyPresentationCiphertext(
          presentation.profileKeyEncCiphertext
        )
      )
    ) {
      rejectForbidden('Profile-key presentation does not bind the submitted member');
    }
  } catch (error) {
    if (error instanceof GroupServerError) throw error;
    rejectForbidden('Profile-key credential presentation verification failed');
  }
}

function stripStateProfileKeyPresentations(state: EncryptedGroup): EncryptedGroup {
  const stripped = structuredClone(state);
  for (const member of stripped.members) {
    member.presentation = new Uint8Array(0);
  }
  for (const member of stripped.membersPendingAdminApproval) {
    member.presentation = new Uint8Array(0);
  }
  return stripped;
}

function stripChangeProfileKeyPresentations(
  change: EncryptedGroupChange
): EncryptedGroupChange {
  const stripped = structuredClone(change);
  for (const members of [
    stripped.newMembers,
    stripped.modifiedProfileKeys,
    stripped.promotePendingMembers,
    stripped.promotePendingPniAciMembers,
  ]) {
    for (const member of members) {
      member.presentation = new Uint8Array(0);
    }
  }
  for (const member of stripped.newRequestingMembers) {
    member.presentation = new Uint8Array(0);
  }
  return stripped;
}

function verifyStateProfileKeyPresentations(
  state: EncryptedGroup,
  serverSecretParams: ServerSecretParams,
  nowSeconds: number
): void {
  const groupPublicParams = deserializeGroupPublicParams(state.publicKey);
  for (const member of state.members) {
    verifyProfileKeyPresentation(
      serverSecretParams,
      groupPublicParams,
      member.userId,
      member.profileKey,
      member.presentation,
      nowSeconds
    );
  }
  for (const member of state.membersPendingAdminApproval) {
    verifyProfileKeyPresentation(
      serverSecretParams,
      groupPublicParams,
      member.userId,
      member.profileKey,
      member.presentation,
      nowSeconds
    );
  }
}

function verifyChangeProfileKeyPresentations(
  state: EncryptedGroup,
  change: EncryptedGroupChange,
  serverSecretParams: ServerSecretParams,
  nowSeconds: number
): void {
  const groupPublicParams = deserializeGroupPublicParams(state.publicKey);
  const members = [
    ...change.newMembers,
    ...change.modifiedProfileKeys,
    ...change.promotePendingMembers,
    ...change.promotePendingPniAciMembers,
  ];
  for (const member of members) {
    verifyProfileKeyPresentation(
      serverSecretParams,
      groupPublicParams,
      member.aciCiphertext,
      member.profileKeyCiphertext,
      member.presentation,
      nowSeconds
    );
  }
  for (const member of change.newRequestingMembers) {
    verifyProfileKeyPresentation(
      serverSecretParams,
      groupPublicParams,
      member.aciCiphertext,
      member.profileKeyCiphertext,
      member.presentation,
      nowSeconds
    );
  }
}

function memberFromAction(
  action: EncryptedChangeAddMember | EncryptedChangePendingMemberPromotion,
  role: MemberRole,
  joinedAtVersion: number
): EncryptedGroup['members'][number] {
  return {
    userId: action.aciCiphertext,
    role,
    profileKey: action.profileKeyCiphertext,
    presentation: action.presentation,
    joinedAtVersion,
    labelEmoji: new Uint8Array(0),
    labelString: new Uint8Array(0),
  };
}

function validTimestamp(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0;
}

function assertRecognizedActionShape(
  change: EncryptedGroupChange,
  form: 'submission' | 'canonical'
): void {
  try {
    assertValidEncryptedGroupChangeWire(change, form);
    assertRecognizedEncryptedGroupChange(change);
    assertEncryptedGroupChangeForm(change, form);
  } catch (error) {
    rejectBadRequest(error instanceof Error ? error.message : 'Actions are malformed');
  }
  if (!Number.isSafeInteger(change.revision) || change.revision < 1) {
    rejectBadRequest('Actions revision must be a positive safe integer');
  }
  if (change.terminate !== undefined && change.terminate !== true) {
    rejectBadRequest('Termination action must be true');
  }

  const requireProfileKeyAction = (
    member: {
      aciCiphertext: Uint8Array;
      profileKeyCiphertext: Uint8Array;
      presentation: Uint8Array;
    },
    label: string
  ): void => {
    requireCiphertextEncoding(member.aciCiphertext, `${label}.aciCiphertext`, 'aci');
    requireCiphertextEncoding(
      member.profileKeyCiphertext,
      `${label}.profileKeyCiphertext`,
      'profile-key'
    );
    if (!(member.presentation instanceof Uint8Array)) {
      rejectBadRequest(`${label}.presentation must be bytes`);
    }
  };

  for (const [index, member] of change.newMembers.entries()) {
    requireProfileKeyAction(member, `Actions.newMembers[${index}]`);
    if (!isStoredMemberRole(member.role)) {
      rejectBadRequest(`Actions.newMembers[${index}].role is invalid`);
    }
    if (form === 'canonical' && member.joinedAtRevision !== change.revision) {
      rejectBadRequest(
        `Actions.newMembers[${index}].joinedAtRevision must equal the change revision`
      );
    }
  }
  for (const [index, member] of change.modifiedProfileKeys.entries()) {
    requireProfileKeyAction(member, `Actions.modifiedProfileKeys[${index}]`);
  }
  for (const [index, member] of change.promotePendingMembers.entries()) {
    requireProfileKeyAction(member, `Actions.promotePendingMembers[${index}]`);
    if (
      form === 'canonical' &&
      (!isStoredMemberRole(member.role) ||
        member.joinedAtRevision !== change.revision)
    ) {
      rejectBadRequest(
        `Actions.promotePendingMembers[${index}] has invalid derived role or joinedAtRevision`
      );
    }
  }
  for (const [index, member] of change.promotePendingPniAciMembers.entries()) {
    requireProfileKeyAction(
      member,
      `Actions.promotePendingPniAciMembers[${index}]`
    );
    if (
      form === 'canonical' &&
      (!isStoredMemberRole(member.role) ||
        member.joinedAtRevision !== change.revision)
    ) {
      rejectBadRequest(
        `Actions.promotePendingPniAciMembers[${index}] has invalid derived role or joinedAtRevision`
      );
    }
    if (member.pniCiphertext.length !== 65) {
      rejectBadRequest(
        `Actions.promotePendingPniAciMembers[${index}].pniCiphertext is required`
      );
    }
  }
  for (const [index, ciphertext] of change.deleteMembers.entries()) {
    requireCiphertextEncoding(ciphertext, `Actions.deleteMembers[${index}]`, 'aci');
  }
  for (const [index, member] of change.modifyMemberRoles.entries()) {
    requireCiphertextEncoding(
      member.aciCiphertext,
      `Actions.modifyMemberRoles[${index}].aciCiphertext`,
      'aci'
    );
    if (!isStoredMemberRole(member.role)) {
      rejectBadRequest(`Actions.modifyMemberRoles[${index}].role is invalid`);
    }
  }
  for (const [index, member] of change.modifyMemberLabels.entries()) {
    requireCiphertextEncoding(
      member.aciCiphertext,
      `Actions.modifyMemberLabels[${index}].aciCiphertext`,
      'aci'
    );
    requireBlobEncoding(
      member.labelEmojiCiphertext,
      `Actions.modifyMemberLabels[${index}].labelEmojiCiphertext`
    );
    requireBlobEncoding(
      member.labelStringCiphertext,
      `Actions.modifyMemberLabels[${index}].labelStringCiphertext`
    );
  }
  for (const [index, member] of change.newPendingMembers.entries()) {
    requireCiphertextEncoding(
      member.serviceIdCiphertext,
      `Actions.newPendingMembers[${index}].serviceIdCiphertext`,
      'service-id'
    );
    if (!isStoredMemberRole(member.role)) {
      rejectBadRequest(`Actions.newPendingMembers[${index}].role is invalid`);
    }
    if (form === 'canonical') {
      requireCiphertextEncoding(
        member.addedByAciCiphertext!,
        `Actions.newPendingMembers[${index}].addedByAciCiphertext`,
        'aci'
      );
      if (!validTimestamp(member.timestamp)) {
        rejectBadRequest(
          `Actions.newPendingMembers[${index}].timestamp is invalid`
        );
      }
    }
  }
  for (const [index, member] of change.deletePendingMembers.entries()) {
    requireCiphertextEncoding(
      member.serviceIdCiphertext,
      `Actions.deletePendingMembers[${index}].serviceIdCiphertext`,
      'service-id'
    );
  }
  for (const [index, member] of change.newRequestingMembers.entries()) {
    requireCiphertextEncoding(
      member.aciCiphertext,
      `Actions.newRequestingMembers[${index}].aciCiphertext`,
      'aci'
    );
    requireCiphertextEncoding(
      member.profileKeyCiphertext,
      `Actions.newRequestingMembers[${index}].profileKeyCiphertext`,
      'profile-key'
    );
    if (!(member.presentation instanceof Uint8Array)) {
      rejectBadRequest(
        `Actions.newRequestingMembers[${index}].presentation must be bytes`
      );
    }
    if (form === 'canonical' && !validTimestamp(member.timestamp)) {
      rejectBadRequest(
        `Actions.newRequestingMembers[${index}].timestamp is invalid`
      );
    }
  }
  for (const [index, ciphertext] of change.deleteRequestingMembers.entries()) {
    requireCiphertextEncoding(
      ciphertext,
      `Actions.deleteRequestingMembers[${index}]`,
      'aci'
    );
  }
  for (const [index, member] of change.promoteRequestingMembers.entries()) {
    requireCiphertextEncoding(
      member.aciCiphertext,
      `Actions.promoteRequestingMembers[${index}].aciCiphertext`,
      'aci'
    );
    if (!isStoredMemberRole(member.role)) {
      rejectBadRequest(`Actions.promoteRequestingMembers[${index}].role is invalid`);
    }
  }
  for (const [index, member] of change.newBannedMembers.entries()) {
    requireCiphertextEncoding(
      member.serviceIdCiphertext,
      `Actions.newBannedMembers[${index}].serviceIdCiphertext`,
      'service-id'
    );
    if (form === 'canonical' && !validTimestamp(member.timestamp)) {
      rejectBadRequest(`Actions.newBannedMembers[${index}].timestamp is invalid`);
    }
  }
  for (const [index, member] of change.deleteBannedMembers.entries()) {
    requireCiphertextEncoding(
      member.serviceIdCiphertext,
      `Actions.deleteBannedMembers[${index}].serviceIdCiphertext`,
      'service-id'
    );
  }

  for (const [value, label] of [
    [change.newTitle, 'Actions.newTitle'],
    [change.newTimer, 'Actions.newTimer'],
    [change.newDescription, 'Actions.newDescription'],
  ] as const) {
    if (value !== undefined) {
      requireBlobEncoding(value, label, false);
    }
  }
  if (
    change.newAvatar !== undefined &&
    (typeof change.newAvatar !== 'object' ||
      change.newAvatar === null ||
      typeof change.newAvatar.value !== 'string')
  ) {
    rejectBadRequest('Actions.newAvatar must carry a string value');
  }
  for (const [value, label] of [
    [change.newAttributeAccess, 'Actions.newAttributeAccess'],
    [change.newMemberAccess, 'Actions.newMemberAccess'],
    [change.newMemberLabelAccess, 'Actions.newMemberLabelAccess'],
  ] as const) {
    if (value !== undefined && !isRoleAccessRequirement(value)) {
      rejectBadRequest(`${label} is outside its §6.7 domain`);
    }
  }
  if (
    change.newInviteLinkAccess !== undefined &&
    !isInviteLinkAccessRequirement(change.newInviteLinkAccess)
  ) {
    rejectBadRequest('Actions.newInviteLinkAccess is outside its §6.7 domain');
  }
  if (
    change.newIsAnnouncementGroup !== undefined &&
    change.newIsAnnouncementGroup !== EnabledState.ENABLED &&
    change.newIsAnnouncementGroup !== EnabledState.DISABLED
  ) {
    rejectBadRequest('Actions.newIsAnnouncementGroup is invalid');
  }
  const { newInviteLinkPassword } = change;
  if (
    newInviteLinkPassword !== undefined &&
    (!(newInviteLinkPassword instanceof Uint8Array) ||
      newInviteLinkPassword.length !== 16)
  ) {
    rejectBadRequest('Actions.newInviteLinkPassword must be 16 bytes');
  }
}

function assertEncryptedStateStructure(state: EncryptedGroup): void {
  try {
    assertValidEncryptedGroupWire(state);
  } catch (error) {
    rejectBadRequest(
      error instanceof Error ? error.message : 'Encrypted group state is malformed'
    );
  }
  if (!Number.isSafeInteger(state.version) || state.version < 0) {
    rejectBadRequest('Group version must be a non-negative safe integer');
  }
  if (
    !Array.isArray(state.members) ||
    !Array.isArray(state.membersPendingProfileKey) ||
    !Array.isArray(state.membersPendingAdminApproval) ||
    !Array.isArray(state.membersBanned)
  ) {
    rejectBadRequest('Group membership fields must be arrays');
  }
  if (state.members.length > MAX_GROUP_SIZE) {
    rejectBadRequest(`Group exceeds the ${MAX_GROUP_SIZE}-member limit`);
  }
  if (state.membersPendingProfileKey.length > MAX_GROUP_SIZE) {
    rejectBadRequest(
      `Group exceeds the ${MAX_GROUP_SIZE}-pending-member limit`
    );
  }
  if (state.membersPendingAdminApproval.length > MAX_GROUP_SIZE) {
    rejectBadRequest(
      `Group exceeds the ${MAX_GROUP_SIZE}-requesting-member limit`
    );
  }
  if (state.membersBanned.length > MAX_GROUP_SIZE) {
    rejectBadRequest(
      `Group exceeds the ${MAX_GROUP_SIZE}-banned-member limit`
    );
  }
  if (
    !(state.publicKey instanceof Uint8Array) ||
    !(state.title instanceof Uint8Array) ||
    !(state.description instanceof Uint8Array) ||
    !(state.disappearingMessagesTimer instanceof Uint8Array) ||
    !(state.inviteLinkPassword instanceof Uint8Array) ||
    (state.inviteLinkPassword.length !== 0 &&
      state.inviteLinkPassword.length !== 16) ||
    typeof state.avatarUrl !== 'string' ||
    typeof state.announcementsOnly !== 'boolean' ||
    typeof state.terminated !== 'boolean'
  ) {
    rejectBadRequest('Group scalar or encrypted attribute fields are malformed');
  }
  if (
    !isRoleAccessRequirement(state.accessControl?.attributes) ||
    !isRoleAccessRequirement(state.accessControl?.members) ||
    !isRoleAccessRequirement(state.accessControl?.memberLabel) ||
    !isInviteLinkAccessRequirement(state.accessControl?.addFromInviteLink)
  ) {
    rejectBadRequest('Group access control is invalid');
  }

  const occupied = new Set<string>();
  const occupy = (ciphertext: Uint8Array, label: string): void => {
    const key = Array.from(ciphertext, (byte) =>
      byte.toString(16).padStart(2, '0')
    ).join('');
    if (occupied.has(key)) {
      rejectBadRequest(`Principal appears in multiple group-state entries (${label})`);
    }
    occupied.add(key);
  };
  requireBlobEncoding(state.title, 'Group.title');
  requireBlobEncoding(state.description, 'Group.description');
  requireBlobEncoding(
    state.disappearingMessagesTimer,
    'Group.disappearingMessagesTimer'
  );

  for (const member of state.members) {
    requireCiphertextEncoding(member.userId, 'members.userId', 'aci');
    requireCiphertextEncoding(member.profileKey, 'members.profileKey', 'profile-key');
    if (
      !isStoredMemberRole(member.role) ||
      !(member.presentation instanceof Uint8Array) ||
      !Number.isSafeInteger(member.joinedAtVersion) ||
      member.joinedAtVersion < 0 ||
      member.joinedAtVersion > state.version ||
      !(member.labelEmoji instanceof Uint8Array) ||
      !(member.labelString instanceof Uint8Array)
    ) {
      rejectBadRequest('Stored member fields are malformed');
    }
    requireBlobEncoding(member.labelEmoji, 'members.labelEmoji');
    requireBlobEncoding(member.labelString, 'members.labelString');
    occupy(member.userId, 'members');
  }
  for (const pending of state.membersPendingProfileKey) {
    requireCiphertextEncoding(
      pending.member.userId,
      'membersPendingProfileKey.userId',
      'service-id'
    );
    requireCiphertextEncoding(
      pending.addedByUserId,
      'membersPendingProfileKey.addedByUserId',
      'aci'
    );
    if (
      !isStoredMemberRole(pending.member.role) ||
      !validTimestamp(pending.timestamp) ||
      pending.member.profileKey.length !== 0 ||
      pending.member.presentation.length !== 0
    ) {
      rejectBadRequest('Stored pending-member fields are malformed');
    }
    occupy(pending.member.userId, 'membersPendingProfileKey');
  }
  for (const requesting of state.membersPendingAdminApproval) {
    requireCiphertextEncoding(
      requesting.userId,
      'membersPendingAdminApproval.userId',
      'aci'
    );
    requireCiphertextEncoding(
      requesting.profileKey,
      'membersPendingAdminApproval.profileKey',
      'profile-key'
    );
    if (
      !(requesting.presentation instanceof Uint8Array) ||
      !validTimestamp(requesting.timestamp)
    ) {
      rejectBadRequest('Stored requesting-member fields are malformed');
    }
    occupy(requesting.userId, 'membersPendingAdminApproval');
  }
  for (const banned of state.membersBanned) {
    requireCiphertextEncoding(banned.userId, 'membersBanned.userId', 'service-id');
    if (!validTimestamp(banned.timestamp)) {
      rejectBadRequest('Stored banned-member timestamp is invalid');
    }
    occupy(banned.userId, 'membersBanned');
  }
}

function assertEncryptedCreationStateStructure(
  state: EncryptedGroupCreationSubmission
): void {
  try {
    assertValidEncryptedGroupCreationSubmissionWire(state);
  } catch (error) {
    rejectBadRequest(
      error instanceof Error
        ? error.message
        : 'Encrypted group creation submission is malformed'
    );
  }
}

function requesterMatches(requester: VerifiedRequester, userId: Uint8Array): boolean {
  return (
    equal(userId, requester.aciCiphertext) ||
    (requester.pniCiphertext !== undefined &&
      equal(userId, requester.pniCiphertext))
  );
}

function roleForSource(
  state: EncryptedGroup,
  sourceUserId: Uint8Array
): MemberRole {
  return (
    state.members.find((member) => equal(member.userId, sourceUserId))?.role ??
    MemberRole.UNKNOWN
  );
}

function roleForRequesterAliases(
  state: EncryptedGroup,
  requester: VerifiedRequester
): MemberRole {
  return (
    state.members.find((member) =>
      requesterMatches(requester, member.userId)
    )?.role ??
    MemberRole.UNKNOWN
  );
}

function requesterIsBanned(
  state: EncryptedGroup,
  requester: VerifiedRequester
): boolean {
  return state.membersBanned.some((member) =>
    requesterMatches(requester, member.userId)
  );
}

function matchingRequesterIds(
  state: EncryptedGroup,
  requester: VerifiedRequester
): Uint8Array[] {
  return [
    ...state.members.map((member) => member.userId),
    ...state.membersPendingProfileKey.map((pending) => pending.member.userId),
    ...state.membersPendingAdminApproval.map((pending) => pending.userId),
  ].filter((userId) => requesterMatches(requester, userId));
}

function sourceUserIdForChange(
  state: EncryptedGroup,
  change: EncryptedGroupChange,
  requester: VerifiedRequester
): Uint8Array {
  const actionNamedRequesterIds = [
    ...change.promotePendingPniAciMembers.map(
      (promotion) => promotion.pniCiphertext
    ),
    ...change.deletePendingMembers
      .map((removal) => removal.serviceIdCiphertext)
      .filter((target) => requesterMatches(requester, target)),
    ...change.deleteRequestingMembers.filter((target) =>
      requesterMatches(requester, target)
    ),
  ].filter(
    (candidate, index, candidates) =>
      candidates.findIndex((other) => equal(candidate, other)) === index
  );
  if (actionNamedRequesterIds.length > 1) {
    rejectForbidden(
      'A change cannot exercise self-rights under multiple requester aliases'
    );
  }
  if (actionNamedRequesterIds.length === 1) {
    return actionNamedRequesterIds[0]!;
  }

  const preChangeMatches = matchingRequesterIds(state, requester);
  const matches =
    preChangeMatches.length > 0
      ? preChangeMatches
      : [
          ...change.newMembers.map((member) => member.aciCiphertext),
          ...change.newRequestingMembers.map(
            (member) => member.aciCiphertext
          ),
        ].filter((userId) => requesterMatches(requester, userId));
  const aciMatch = matches.find((userId) =>
    equal(userId, requester.aciCiphertext)
  );
  const sourceUserId = aciMatch ?? matches[0];
  if (!sourceUserId) {
    rejectForbidden('Requester does not match the pre- or post-change group state');
  }
  return sourceUserId;
}

function pendingRole(
  state: EncryptedGroup,
  userId: Uint8Array,
  label: string
): MemberRole {
  const pending = state.membersPendingProfileKey.find((member) =>
    equal(member.member.userId, userId)
  );
  if (!pending) {
    rejectBadRequest(`Cannot derive role for missing ${label}`);
  }
  return pending.member.role;
}

function canonicalizeAcceptedChange(
  state: EncryptedGroup,
  submitted: EncryptedGroupChange,
  sourceUserId: Uint8Array,
  groupId: Uint8Array,
  timestamp: number
): EncryptedGroupChange {
  const stripped = stripChangeProfileKeyPresentations(submitted);
  return {
    ...stripped,
    sourceUserId,
    groupId: new Uint8Array(groupId),
    newMembers: stripped.newMembers.map((member) => ({
      ...member,
      joinedAtRevision: stripped.revision,
    })),
    newPendingMembers: stripped.newPendingMembers.map((member) => ({
      ...member,
      addedByAciCiphertext: new Uint8Array(sourceUserId),
      timestamp,
    })),
    promotePendingMembers: stripped.promotePendingMembers.map((member) => ({
      ...member,
      role: pendingRole(
        state,
        member.aciCiphertext,
        'pending ACI member'
      ),
      joinedAtRevision: stripped.revision,
    })),
    promotePendingPniAciMembers:
      stripped.promotePendingPniAciMembers.map((member) => ({
        ...member,
        role: pendingRole(
          state,
          member.pniCiphertext,
          'pending PNI member'
        ),
        joinedAtRevision: stripped.revision,
      })),
    newRequestingMembers: stripped.newRequestingMembers.map((member) => ({
      ...member,
      timestamp,
    })),
    newBannedMembers: stripped.newBannedMembers.map((member) => ({
      ...member,
      timestamp,
    })),
  };
}

function targetIsRequester(target: Uint8Array, sourceUserId: Uint8Array): boolean {
  return equal(target, sourceUserId);
}

function authorizeEncryptedChange(
  state: EncryptedGroup,
  change: EncryptedGroupChange,
  sourceUserId: Uint8Array,
  requester: VerifiedRequester
): void {
  const role = roleForSource(state, sourceUserId);
  const banned = requesterIsBanned(state, requester);
  const policyState = {
    accessControl: state.accessControl,
    isAnnouncementGroup: state.announcementsOnly
      ? EnabledState.ENABLED
      : EnabledState.DISABLED,
  };
  const check = (
    action: GroupAction,
    target?: Uint8Array,
    assignedRole?: MemberRole
  ): void => {
    if (
      !canRolePerformAction(policyState, role, action, {
        requesterIsBanned: banned,
        targetIsRequester: target
          ? targetIsRequester(target, sourceUserId)
          : false,
        assignedRole,
      })
    ) {
      rejectForbidden(`Requester cannot perform ${action}`);
    }
  };

  for (const member of change.newMembers) {
    check(GroupAction.ADD_MEMBER, member.aciCiphertext, member.role);
  }
  for (const member of change.deleteMembers) check(GroupAction.REMOVE_MEMBER, member);
  for (const member of change.modifyMemberRoles) {
    check(GroupAction.MODIFY_MEMBER_ROLE, member.aciCiphertext);
  }
  for (const member of change.modifiedProfileKeys) {
    check(GroupAction.MODIFY_MEMBER_PROFILE_KEY, member.aciCiphertext);
  }
  for (const member of change.newPendingMembers) {
    check(
      GroupAction.ADD_MEMBER_PENDING_PROFILE_KEY,
      member.serviceIdCiphertext,
      member.role
    );
  }
  for (const member of change.deletePendingMembers) {
    check(GroupAction.DELETE_MEMBER_PENDING_PROFILE_KEY, member.serviceIdCiphertext);
  }
  for (const member of change.promotePendingMembers) {
    check(GroupAction.PROMOTE_MEMBER_PENDING_PROFILE_KEY, member.aciCiphertext);
  }
  for (const member of change.promotePendingPniAciMembers) {
    const pniPending = state.membersPendingProfileKey.find((pending) =>
      equal(pending.member.userId, member.pniCiphertext)
    );
    const aciPending = state.membersPendingProfileKey.find((pending) =>
      equal(pending.member.userId, member.aciCiphertext)
    );
    if (
      pniPending &&
      aciPending &&
      pniPending.member.role !== aciPending.member.role
    ) {
      rejectForbidden(
        'PNI-to-ACI promotion cannot consume pending aliases with different roles'
      );
    }
    check(
      GroupAction.PROMOTE_MEMBER_PENDING_PNI_ACI_PROFILE_KEY,
      member.pniCiphertext
    );
  }
  if (change.newTitle !== undefined) check(GroupAction.MODIFY_TITLE);
  if (change.newAvatar !== undefined) check(GroupAction.MODIFY_AVATAR);
  if (change.newTimer !== undefined) check(GroupAction.MODIFY_DISAPPEARING_MESSAGES);
  if (change.newDescription !== undefined) check(GroupAction.MODIFY_DESCRIPTION);
  if (change.newAttributeAccess !== undefined) check(GroupAction.MODIFY_ATTRIBUTES_ACCESS);
  if (change.newMemberAccess !== undefined) check(GroupAction.MODIFY_MEMBERS_ACCESS);
  if (change.newInviteLinkAccess !== undefined) {
    check(GroupAction.MODIFY_INVITE_LINK_ACCESS);
  }
  if (change.newMemberLabelAccess !== undefined) {
    check(GroupAction.MODIFY_MEMBER_LABEL_ACCESS);
  }
  if (change['newInviteLinkPassword'] !== undefined) {
    check(GroupAction.MODIFY_INVITE_LINK_PASSWORD);
  }
  if (change.newIsAnnouncementGroup !== undefined) {
    check(GroupAction.MODIFY_ANNOUNCEMENTS);
  }
  for (const member of change.newRequestingMembers) {
    check(GroupAction.ADD_MEMBER_PENDING_ADMIN_APPROVAL, member.aciCiphertext);
  }
  for (const member of change.deleteRequestingMembers) {
    check(GroupAction.DELETE_MEMBER_PENDING_ADMIN_APPROVAL, member);
  }
  for (const member of change.promoteRequestingMembers) {
    check(GroupAction.PROMOTE_MEMBER_PENDING_ADMIN_APPROVAL, member.aciCiphertext);
  }
  for (const member of change.newBannedMembers) {
    check(GroupAction.BAN_MEMBER, member.serviceIdCiphertext);
  }
  for (const member of change.deleteBannedMembers) {
    check(GroupAction.UNBAN_MEMBER, member.serviceIdCiphertext);
  }
  for (const member of change.modifyMemberLabels) {
    check(GroupAction.MODIFY_MEMBER_LABEL, member.aciCiphertext);
  }
  if (change.terminate === true) check(GroupAction.TERMINATE_GROUP);
}

function requirePniAciBinding(
  change: EncryptedGroupChange,
  requester: VerifiedRequester
): void {
  for (const promotion of change.promotePendingPniAciMembers) {
    if (
      !equal(promotion.aciCiphertext, requester.aciCiphertext) ||
      requester.pniCiphertext === undefined ||
      promotion.pniCiphertext.length === 0 ||
      !equal(promotion.pniCiphertext, requester.pniCiphertext)
    ) {
      rejectForbidden('PNI-to-ACI promotion is not bound to the requester presentation');
    }
  }
}

function isLinkJoin(
  state: EncryptedGroup,
  change: EncryptedGroupChange,
  requester: VerifiedRequester
): boolean {
  if (roleForRequesterAliases(state, requester) !== MemberRole.UNKNOWN) {
    return false;
  }
  return (
    change.newMembers.some((member) => equal(member.aciCiphertext, requester.aciCiphertext)) ||
    change.newRequestingMembers.some((member) =>
      equal(member.aciCiphertext, requester.aciCiphertext)
    )
  );
}

function requireInviteLinkPassword(
  state: EncryptedGroup,
  change: EncryptedGroupChange,
  requester: VerifiedRequester,
  password: Uint8Array
): void {
  if (
    isLinkJoin(state, change, requester) &&
    (state.inviteLinkPassword.length !== INVITE_LINK_PASSWORD_LENGTH ||
      password.length !== INVITE_LINK_PASSWORD_LENGTH ||
      !constantTimeEqual(state.inviteLinkPassword, password))
  ) {
    rejectForbidden('Invite-link password is absent or invalid');
  }
}

function applyEncryptedChange(
  state: EncryptedGroup,
  change: EncryptedGroupChange
): EncryptedGroup {
  if (state.terminated) rejectBadRequest('Group is terminated');
  const next = structuredClone(state);
  const { newInviteLinkPassword } = change;
  const missing = (description: string): never =>
    rejectBadRequest(`Action targets a missing ${description}`);
  const duplicate = (description: string): never =>
    rejectBadRequest(`Action creates a duplicate ${description}`);

  for (const removal of change.deletePendingMembers) {
    const index = next.membersPendingProfileKey.findIndex((member) =>
      equal(member.member.userId, removal.serviceIdCiphertext)
    );
    if (index < 0) missing('pending member');
    next.membersPendingProfileKey.splice(index, 1);
  }
  for (const userId of change.deleteRequestingMembers) {
    const index = next.membersPendingAdminApproval.findIndex((member) =>
      equal(member.userId, userId)
    );
    if (index < 0) missing('requesting member');
    next.membersPendingAdminApproval.splice(index, 1);
  }
  for (const removal of change.deleteBannedMembers) {
    const index = next.membersBanned.findIndex((member) =>
      equal(member.userId, removal.serviceIdCiphertext)
    );
    if (index < 0) missing('banned member');
    next.membersBanned.splice(index, 1);
  }
  for (const userId of change.deleteMembers) {
    const index = next.members.findIndex((member) => equal(member.userId, userId));
    if (index < 0) missing('member');
    next.members.splice(index, 1);
  }

  for (const addition of change.newBannedMembers) {
    if (next.membersBanned.some((member) => equal(member.userId, addition.serviceIdCiphertext))) {
      duplicate('banned member');
    }
    if (next.membersBanned.length >= MAX_GROUP_SIZE) {
      rejectBadRequest('Group banned-member list is full');
    }
    next.membersBanned.push({
      userId: addition.serviceIdCiphertext,
      timestamp: addition.timestamp!,
    });
  }

  for (const promotion of change.promotePendingMembers) {
    if (next.members.some((member) => equal(member.userId, promotion.aciCiphertext))) {
      duplicate('member');
    }
    const index = next.membersPendingProfileKey.findIndex((member) =>
      equal(member.member.userId, promotion.aciCiphertext)
    );
    if (index < 0) missing('pending ACI member');
    const [pending] = next.membersPendingProfileKey.splice(index, 1);
    next.members.push(memberFromAction(promotion, pending!.member.role, change.revision));
  }
  for (const promotion of change.promotePendingPniAciMembers) {
    if (next.members.some((member) => equal(member.userId, promotion.aciCiphertext))) {
      duplicate('member');
    }
    const index = next.membersPendingProfileKey.findIndex((member) =>
      equal(member.member.userId, promotion.pniCiphertext)
    );
    if (index < 0) missing('pending PNI member');
    const [pending] = next.membersPendingProfileKey.splice(index, 1);
    const aciAliasIndex = next.membersPendingProfileKey.findIndex((member) =>
      equal(member.member.userId, promotion.aciCiphertext)
    );
    if (aciAliasIndex >= 0) {
      const [aciPending] = next.membersPendingProfileKey.splice(
        aciAliasIndex,
        1
      );
      if (aciPending!.member.role !== pending!.member.role) {
        rejectForbidden(
          'PNI-to-ACI promotion cannot consume pending aliases with different roles'
        );
      }
    }
    next.members.push(memberFromAction(promotion, pending!.member.role, change.revision));
  }
  for (const promotion of change.promoteRequestingMembers) {
    if (next.members.some((member) => equal(member.userId, promotion.aciCiphertext))) {
      duplicate('member');
    }
    const index = next.membersPendingAdminApproval.findIndex((member) =>
      equal(member.userId, promotion.aciCiphertext)
    );
    if (index < 0) missing('requesting member');
    const [requesting] = next.membersPendingAdminApproval.splice(index, 1);
    next.members.push({
      userId: requesting!.userId,
      role: promotion.role,
      profileKey: requesting!.profileKey,
      presentation: requesting!.presentation,
      joinedAtVersion: change.revision,
      labelEmoji: new Uint8Array(0),
      labelString: new Uint8Array(0),
    });
  }

  for (const addition of change.newMembers) {
    if (next.members.some((member) => equal(member.userId, addition.aciCiphertext))) {
      duplicate('member');
    }
    if (next.members.length >= MAX_GROUP_SIZE) rejectBadRequest('Group is full');
    next.members.push(
      memberFromAction(
        addition,
        addition.role,
        addition.joinedAtRevision!
      )
    );
  }
  for (const addition of change.newPendingMembers) {
    if (
      next.membersPendingProfileKey.some((member) =>
        equal(member.member.userId, addition.serviceIdCiphertext)
      )
    ) {
      duplicate('pending member');
    }
    if (next.membersPendingProfileKey.length >= MAX_GROUP_SIZE) {
      rejectBadRequest('Group pending-member list is full');
    }
    next.membersPendingProfileKey.push({
      member: {
        userId: addition.serviceIdCiphertext,
        role: addition.role,
        profileKey: new Uint8Array(0),
        presentation: new Uint8Array(0),
        joinedAtVersion: 0,
        labelEmoji: new Uint8Array(0),
        labelString: new Uint8Array(0),
      },
      addedByUserId: addition.addedByAciCiphertext!,
      timestamp: addition.timestamp!,
    });
  }
  for (const addition of change.newRequestingMembers) {
    if (
      next.membersPendingAdminApproval.some((member) =>
        equal(member.userId, addition.aciCiphertext)
      )
    ) {
      duplicate('requesting member');
    }
    if (next.membersPendingAdminApproval.length >= MAX_GROUP_SIZE) {
      rejectBadRequest('Group requesting-member list is full');
    }
    next.membersPendingAdminApproval.push({
      userId: addition.aciCiphertext,
      profileKey: addition.profileKeyCiphertext,
      presentation: addition.presentation,
      timestamp: addition.timestamp!,
    });
  }

  for (const modification of change.modifyMemberRoles) {
    const member = next.members.find((candidate) =>
      equal(candidate.userId, modification.aciCiphertext)
    );
    if (!member) return missing('member role target');
    member.role = modification.role;
  }
  for (const modification of change.modifyMemberLabels) {
    const member = next.members.find((candidate) =>
      equal(candidate.userId, modification.aciCiphertext)
    );
    if (!member) return missing('member label target');
    member.labelEmoji = modification.labelEmojiCiphertext;
    member.labelString = modification.labelStringCiphertext;
  }
  for (const modification of change.modifiedProfileKeys) {
    const member = next.members.find((candidate) =>
      equal(candidate.userId, modification.aciCiphertext)
    );
    if (!member) return missing('member profile-key target');
    member.profileKey = modification.profileKeyCiphertext;
    member.presentation = modification.presentation;
  }

  if (change.newTitle !== undefined) next.title = change.newTitle;
  if (change.newAvatar !== undefined) next.avatarUrl = change.newAvatar.value;
  if (change.newTimer !== undefined) next.disappearingMessagesTimer = change.newTimer;
  if (change.newDescription !== undefined) next.description = change.newDescription;
  if (newInviteLinkPassword !== undefined) {
    next.inviteLinkPassword = newInviteLinkPassword.slice();
  }
  if (change.newAttributeAccess !== undefined) {
    next.accessControl.attributes = change.newAttributeAccess;
  }
  if (change.newMemberAccess !== undefined) {
    next.accessControl.members = change.newMemberAccess;
  }
  if (change.newInviteLinkAccess !== undefined) {
    next.accessControl.addFromInviteLink = change.newInviteLinkAccess;
  }
  if (change.newMemberLabelAccess !== undefined) {
    next.accessControl.memberLabel = change.newMemberLabelAccess;
  }
  if (change.newIsAnnouncementGroup !== undefined) {
    next.announcementsOnly = change.newIsAnnouncementGroup === EnabledState.ENABLED;
  }
  if (change.terminate === true) next.terminated = true;
  next.version = change.revision;
  return next;
}

export class GroupAuthorizationServerEngine implements IGroupServer {
  private readonly groups = new Map<string, StoredGroup>();

  constructor(
    private readonly serverSecretParams: ServerSecretParams,
    private readonly runtime: GroupServerEngineRuntime = defaultRuntime
  ) {}

  get publicParams(): ServerPublicParams {
    return getServerPublicParams(this.serverSecretParams);
  }

  clear(): void {
    this.groups.clear();
  }

  inspectEncryptedState(groupId: Uint8Array): Uint8Array | null {
    const stored = this.groups.get(this.key(groupId));
    return stored ? serializeEncryptedGroup(stored.state) : null;
  }

  restoreGroup(
    groupId: Uint8Array,
    persisted: GroupServerPersistedGroup
  ): void {
    const state = deserializeEncryptedGroup(persisted.encryptedState);
    const snapshots = new Map<number, StoredSnapshot>(
      persisted.snapshots.map((snapshot) => [
        snapshot.version,
        {
          state: deserializeEncryptedGroup(snapshot.encryptedState),
          baselineSignature: new Uint8Array(snapshot.baselineSignature),
        },
      ])
    );
    this.groups.set(this.key(groupId), {
      state,
      changes: structuredClone(persisted.changes),
      snapshots,
    });
  }

  exportGroup(groupId: Uint8Array): GroupServerPersistedGroup | null {
    const stored = this.groups.get(this.key(groupId));
    if (!stored) return null;
    return {
      encryptedState: serializeEncryptedGroup(stored.state),
      changes: structuredClone(stored.changes),
      snapshots: [...stored.snapshots.entries()]
        .sort(([left], [right]) => left - right)
        .map(([version, snapshot]) => ({
          version,
          encryptedState: serializeEncryptedGroup(snapshot.state),
          baselineSignature: new Uint8Array(snapshot.baselineSignature),
        })),
    };
  }

  private key(groupId: Uint8Array): string {
    return Array.from(groupId, (byte) => byte.toString(16).padStart(2, '0')).join('');
  }

  private createStoredSnapshot(
    groupId: Uint8Array,
    state: EncryptedGroup
  ): StoredSnapshot {
    const encryptedState = serializeEncryptedGroup(state);
    return {
      state: structuredClone(state),
      baselineSignature: serverSign(
        this.serverSecretParams,
        this.runtime.randomBytes(32),
        serializeGroupBaseline(groupId, state.version, encryptedState)
      ),
    };
  }

  private authenticate(
    groupId: Uint8Array,
    authorization: GroupAuthorization,
    state?: EncryptedGroup
  ): VerifiedRequester {
    try {
      const groupPublicParams = deserializeGroupPublicParams(
        new Uint8Array(authorization.groupPublicParams)
      );
      if (!equal(groupPublicParams.groupId, groupId)) {
        rejectUnauthorized('Presentation is bound to a different group');
      }
      if (
        state &&
        !equal(state.publicKey, serializeGroupPublicParams(groupPublicParams))
      ) {
        rejectUnauthorized('Presentation parameters do not match stored group parameters');
      }

      const presentation = deserializeAuthCredentialPresentation(
        new Uint8Array(authorization.presentation)
      );
      const nowSeconds = Math.floor(this.runtime.now() / 1000);
      const today =
        Math.floor(nowSeconds / SECONDS_PER_DAY) * SECONDS_PER_DAY;
      if (
        presentation.redemptionTime % SECONDS_PER_DAY !== 0 ||
        Math.abs(presentation.redemptionTime - today) > SECONDS_PER_DAY
      ) {
        rejectUnauthorized('Credential redemption time is outside current day ± one day');
      }
      verifyAuthCredentialPresentation(
        this.serverSecretParams.credentialKeyPair,
        groupPublicParams,
        presentation,
        nowSeconds
      );
      return {
        aciCiphertext: serializePresentationCiphertext(
          SERVICE_ID_ACI,
          presentation.aciCiphertext
        ),
        pniCiphertext:
          presentation.pniCiphertext === undefined
            ? undefined
            : serializePresentationCiphertext(
                SERVICE_ID_PNI,
                presentation.pniCiphertext
              ),
      };
    } catch (error) {
      if (error instanceof GroupServerError) throw error;
      rejectUnauthorized(
        error instanceof Error ? error.message : 'Credential presentation verification failed'
      );
    }
  }

  private isReadable(state: EncryptedGroup, requester: VerifiedRequester): boolean {
    if (requesterIsBanned(state, requester)) return false;
    return (
      state.members.some((member) => requesterMatches(requester, member.userId)) ||
      state.membersPendingProfileKey.some((pending) =>
        requesterMatches(requester, pending.member.userId)
      )
    );
  }

  private requireReadable(state: EncryptedGroup, requester: VerifiedRequester): void {
    if (!this.isReadable(state, requester)) {
      rejectForbidden('Requester may not read full group state', 'not_readable');
    }
  }

  /**
   * The version at which the requester's current tenure began, or undefined
   * when the requester has no tenure to read.
   *
   * Deliberately consults `members` only. A pending-profile-key entry is an
   * invitation, not a tenure: its wire format pins `joinedAtVersion` to
   * zero, so reading it here would hand every invitee a floor of "the
   * beginning of time" — an invitee who never accepts could page through the
   * group's entire pre-invitation history, which is more than acceptance
   * itself would grant. An invitee reads the *current* state (that is what
   * an invitation entitles, and what acceptance needs); versioned history
   * starts existing for them when they join and their member entry records
   * where.
   */
  private requesterJoinedAtVersion(
    state: EncryptedGroup,
    requester: VerifiedRequester
  ): number | undefined {
    return state.members.find((candidate) =>
      requesterMatches(requester, candidate.userId)
    )?.joinedAtVersion;
  }

  async createGroup(
    groupId: Uint8Array,
    encryptedState: Uint8Array,
    authorization: GroupAuthorization
  ): Promise<void> {
    const key = this.key(groupId);
    if (this.groups.has(key)) rejectConflict('Group already exists');

    let submission: EncryptedGroupCreationSubmission;
    try {
      submission = deserializeEncryptedGroupCreationSubmission(encryptedState);
    } catch {
      return rejectBadRequest('Encrypted group state is malformed');
    }
    const requester = this.authenticate(groupId, authorization);
    if (!equal(submission.publicKey, authorization.groupPublicParams)) {
      rejectBadRequest('Stored publicKey must be serialized GroupPublicParams');
    }
    assertEncryptedCreationStateStructure(submission);
    const now = this.runtime.now();
    const state: EncryptedGroup = {
      ...submission,
      membersPendingProfileKey: submission.membersPendingProfileKey.map(
        ({ userId, role }) => ({
          member: {
            userId,
            role,
            profileKey: new Uint8Array(0),
            presentation: new Uint8Array(0),
            joinedAtVersion: 0,
            labelEmoji: new Uint8Array(0),
            labelString: new Uint8Array(0),
          },
          addedByUserId: new Uint8Array(requester.aciCiphertext),
          timestamp: now,
        })
      ),
      membersPendingAdminApproval: [],
      membersBanned: [],
    };
    assertEncryptedStateStructure(state);
    verifyStateProfileKeyPresentations(
      state,
      this.serverSecretParams,
      Math.floor(now / 1000)
    );
    const creator = state.members.find((member) =>
      equal(member.userId, requester.aciCiphertext)
    );
    if (!creator) {
      rejectForbidden('Creator presentation is not an initial member');
    }
    if (creator.role !== MemberRole.ADMINISTRATOR) {
      rejectForbidden('Creator must be an initial administrator');
    }
    const storedState = stripStateProfileKeyPresentations(state);
    const initialSnapshot = this.createStoredSnapshot(groupId, storedState);
    this.groups.set(key, {
      state: storedState,
      changes: [],
      snapshots: new Map([[0, initialSnapshot]]),
    });
  }

  async getGroup(
    groupId: Uint8Array,
    authorization: GroupAuthorization,
    version?: number
  ): Promise<{
    encryptedState: Uint8Array;
    version: number;
    baselineSignature: Uint8Array;
  } | null> {
    const stored = this.groups.get(this.key(groupId));
    if (!stored) return null;
    // Authorization is evaluated against the group as it is *now*, never
    // against the requested snapshot. Historical snapshots each contain a
    // roster, and authorizing against the requested one let anyone removed or
    // banned at version N keep reading every version of their tenure forever
    // — a removal that does not revoke read access is not a removal. Current
    // membership answers "may you read this group"; the join-version floor
    // below answers "may you read this version of it".
    const requester = this.authenticate(groupId, authorization, stored.state);
    this.requireReadable(stored.state, requester);
    const snapshot =
      version === undefined
        ? stored.snapshots.get(stored.state.version)
        : stored.snapshots.get(version);
    if (!snapshot) return null;
    if (version !== undefined) {
      // Under snapshot-based authorization this floor was implicit — a
      // pre-join snapshot simply did not list the requester. Authorizing
      // against the current state removes that accident, so the floor has to
      // be stated: membership grants the group from when you joined, not its
      // history.
      const joinedAtVersion = this.requesterJoinedAtVersion(
        stored.state,
        requester
      );
      if (joinedAtVersion === undefined || version < joinedAtVersion) {
        rejectForbidden(
          'Requester may not read state from before they joined',
          'before_join'
        );
      }
    }
    const { state } = snapshot;
    const encryptedState = serializeEncryptedGroup(state);
    return {
      encryptedState,
      version: state.version,
      baselineSignature: new Uint8Array(snapshot.baselineSignature),
    };
  }

  async getGroupJoinInfo(
    groupId: Uint8Array,
    inviteLinkPassword: Uint8Array,
    authorization: GroupAuthorization
  ): Promise<{ encryptedJoinInfo: Uint8Array; version: number } | null> {
    const stored = this.groups.get(this.key(groupId));
    if (!stored) return null;
    const requester = this.authenticate(groupId, authorization, stored.state);
    if (requesterIsBanned(stored.state, requester)) {
      rejectForbidden('Banned requester may not read group join info');
    }
    if (stored.state.terminated) {
      rejectForbidden('Terminated group has no join info');
    }
    const pendingAdminApproval =
      stored.state.membersPendingAdminApproval.some((pending) =>
        requesterMatches(requester, pending.userId)
      );
    if (!pendingAdminApproval) {
      if (
        stored.state.accessControl.addFromInviteLink === AccessRequired.UNSATISFIABLE ||
        stored.state.accessControl.addFromInviteLink === AccessRequired.UNKNOWN
      ) {
        rejectForbidden('Invite-link access is disabled or unknown');
      }
      if (
        stored.state.inviteLinkPassword.length !== INVITE_LINK_PASSWORD_LENGTH ||
        inviteLinkPassword.length !== INVITE_LINK_PASSWORD_LENGTH ||
        !constantTimeEqual(stored.state.inviteLinkPassword, inviteLinkPassword)
      ) {
        rejectForbidden('Invite-link password is absent or invalid');
      }
    }
    const info: EncryptedGroupJoinInfo = {
      publicKey: stored.state.publicKey,
      title: stored.state.title,
      avatar: stored.state.avatarUrl,
      memberCount: stored.state.members.length,
      addFromInviteLink: stored.state.accessControl.addFromInviteLink,
      revision: stored.state.version,
      pendingAdminApproval,
      description: stored.state.description,
    };
    return {
      encryptedJoinInfo: serializeEncryptedGroupJoinInfo(info),
      version: stored.state.version,
    };
  }

  async getGroupChanges(
    groupId: Uint8Array,
    fromVersion: number,
    authorization: GroupAuthorization
  ): Promise<GroupChangeLogEntry[]> {
    // Unlike getGroup, this deliberately authorizes against the *requested*
    // snapshot. The walk below serves entries only while the requester stays
    // readable, stopping at — and including — the change that removed them,
    // which is how a removed member learns of their removal when they poll;
    // authorizing against the current state would 403 them into silence
    // instead. The exposure this leaves is bounded and not new: a former
    // member can re-fetch changes from within their own tenure, ending at
    // their removal — bytes they were served while entitled.
    //
    // The log is for members. A pending-profile-key entry entitles its
    // holder to the current state — acceptance needs that, and getGroup
    // serves it — but the log names the actor behind every change, and an
    // invitation is not a tenure, so a requester who is merely pending in
    // the snapshot at `fromVersion` is refused below even though that
    // snapshot lists them as readable. Pending principals catch up by
    // fetching a fresh signed snapshot instead (S10a), which is also how
    // the reference ecosystem's clients behave: their state processor
    // updates straight to the latest server state whenever the server does
    // not recognize the requester as a member. This membership requirement
    // is what closes history: for members it bounds the log at their
    // tenure (a pre-join snapshot does not list them in `members`), and
    // for invitees it closes the log outright.

    const stored = this.groups.get(this.key(groupId));
    if (!stored) return [];
    const snapshot = stored.snapshots.get(fromVersion);
    if (!snapshot) {
      rejectBadRequest(`Group snapshot ${fromVersion} does not exist`);
    }
    const requester = this.authenticate(groupId, authorization, snapshot.state);
    this.requireReadable(snapshot.state, requester);
    if (
      !snapshot.state.members.some((member) =>
        requesterMatches(requester, member.userId)
      )
    ) {
      rejectForbidden(
        'Only members may read the change log',
        'not_a_member'
      );
    }

    const readablePrefix: GroupChangeLogEntry[] = [];
    for (const entry of stored.changes) {
      if (entry.version <= fromVersion) continue;
      readablePrefix.push(entry);
      const postState = stored.snapshots.get(entry.version);
      if (!postState) {
        throw new Error(`Missing group snapshot ${entry.version}`);
      }
      if (!this.isReadable(postState.state, requester)) break;
    }
    return structuredClone(readablePrefix);
  }

  async submitGroupChange(
    groupId: Uint8Array,
    expectedVersion: number,
    actions: Uint8Array,
    inviteLinkPassword: Uint8Array,
    authorization: GroupAuthorization
  ): Promise<GroupChangeLogEntry> {
    if (arguments.length !== 5) {
      rejectBadRequest('Group change submission must not carry an epoch');
    }
    const stored = this.groups.get(this.key(groupId));
    if (!stored) rejectBadRequest('Group does not exist');
    const operationTime = this.runtime.now();
    const requester = this.authenticate(groupId, authorization, stored.state);
    if (stored.state.version !== expectedVersion) {
      rejectConflict(`Expected ${expectedVersion}, current version is ${stored.state.version}`);
    }
    let change: EncryptedGroupChange;
    try {
      change = deserializeEncryptedGroupChange(actions);
      assertRecognizedActionShape(change, 'submission');
    } catch (error) {
      if (error instanceof GroupServerError) throw error;
      return rejectBadRequest('Actions are malformed');
    }
    if (change.groupId !== undefined) {
      rejectBadRequest('Client must not set Actions.groupId');
    }
    if (change.revision !== stored.state.version + 1) {
      rejectConflict(
        `Actions revision ${change.revision} does not follow ${stored.state.version}`
      );
    }
    verifyChangeProfileKeyPresentations(
      stored.state,
      change,
      this.serverSecretParams,
      Math.floor(operationTime / 1000)
    );

    requirePniAciBinding(change, requester);
    const sourceUserId = sourceUserIdForChange(
      stored.state,
      change,
      requester
    );

    // All authorization facts are evaluated against the unchanged pre-state.
    authorizeEncryptedChange(stored.state, change, sourceUserId, requester);
    requireInviteLinkPassword(
      stored.state,
      change,
      requester,
      inviteLinkPassword
    );

    const acceptedChange = canonicalizeAcceptedChange(
      stored.state,
      change,
      sourceUserId,
      groupId,
      operationTime
    );
    assertRecognizedActionShape(acceptedChange, 'canonical');
    const nextState = applyEncryptedChange(stored.state, acceptedChange);
    assertEncryptedStateStructure(nextState);
    const acceptedActions = serializeEncryptedGroupChange(acceptedChange);
    const changeEpoch = requiredGroupChangeEpoch(acceptedChange);
    const signature = serverSign(
      this.serverSecretParams,
      this.runtime.randomBytes(32),
      serializeGroupChangeCommitment(changeEpoch, acceptedActions)
    );
    const entry: GroupChangeLogEntry = {
      version: acceptedChange.revision,
      actions: acceptedActions,
      serverSignature: signature,
      changeEpoch,
      timestamp: operationTime,
    };

    stored.state = nextState;
    stored.snapshots.set(
      nextState.version,
      this.createStoredSnapshot(groupId, nextState)
    );
    stored.changes.push(structuredClone(entry));
    return structuredClone(entry);
  }
}
