/**
 * Group state encryption/decryption using zkgroup primitives.
 *
 * Provides functions to encrypt and decrypt group attributes (title, description, timer)
 * and member information (ACIs, profile keys, labels) using GroupSecretParams.
 *
 * Uses encryptUuid/decryptUuid and encryptProfileKeyCiphertext/decryptProfileKeyCiphertext
 * from client-zk-group-cipher for serialized (Uint8Array) ciphertext handling.
 *
 * Blob encoding uses JSON format instead of protobuf for simplicity.
 */

import {
  type EncryptedGroup,
  type EncryptedMember,
  type EncryptedPendingMember,
  type EncryptedRequestingMember,
  type EncryptedBannedMember,
  type EncryptedGroupJoinInfo,
  type DecryptedGroup,
  type DecryptedMember,
  type DecryptedPendingMember,
  type DecryptedRequestingMember,
  type DecryptedBannedMember,
  type DecryptedGroupJoinInfo,
  type DecryptedTimer,
  type GroupAttributeBlob,
  EnabledState,
} from './types';

import { getGroupPublicParams } from '../protocol/zk/groups';
import { serializeGroupPublicParams } from '../protocol/zk/groups/auth-credential';
import {
  type GroupSecretParams,
  type ServiceId,
  SERVICE_ID_ACI,
  SERVICE_ID_PNI,
  serviceIdBinary,
  encryptBlobWithPadding,
  decryptBlobWithPadding,
  encryptUuid,
  decryptUuid,
  encryptProfileKeyCiphertext,
  decryptProfileKeyCiphertext,
} from '../protocol/zk/groups';
import { isNilUuid } from '../protocol/zk/groups/uid-struct';

import type { ExpiringProfileKeyCredential } from '../protocol/zk/groups/profile-key-credential';
import type { CredentialPublicKey } from '../protocol/zk/credentials/credentials';
import {
  presentProfileKeyCredential,
  serializeProfileKeyCredentialPresentation,
} from '../protocol/zk/groups/profile-key-credential';
import {
  validateGroupAccessControl,
  validateGroupCanonicalFields,
  validateGroupIdentifiers,
  validateGroupMemberRoles,
} from './change-actions';

// ---------------------------------------------------------------------------
// Padding helpers
// ---------------------------------------------------------------------------

/**
 * Calculate padded length to nearest 32-byte boundary (minimum 32 bytes).
 */
export {};
function paddedLength(len: number): number {
  const blockSize = 32;
  return Math.max(blockSize, Math.ceil(len / blockSize) * blockSize);
}

// ---------------------------------------------------------------------------
// Blob encoding
// ---------------------------------------------------------------------------

/**
 * Encode a GroupAttributeBlob as JSON and convert to UTF-8 bytes.
 */
function encodeAttributeBlob(blob: GroupAttributeBlob): Uint8Array {
  const json = JSON.stringify(blob);
  return new TextEncoder().encode(json);
}

/**
 * Decode UTF-8 bytes to JSON and parse as GroupAttributeBlob.
 */
function decodeAttributeBlob(bytes: Uint8Array): GroupAttributeBlob {
  const json = new TextDecoder().decode(bytes);
  return JSON.parse(json) as GroupAttributeBlob;
}

// ---------------------------------------------------------------------------
// Label encryption helpers (reused for labelEmoji and labelString)
// ---------------------------------------------------------------------------

/**
 * Encrypt a label string as a blob.
 */
export function encryptLabelAsBlob(secretParams: GroupSecretParams, label: string): Uint8Array {
  if (!label) return new Uint8Array(0);
  const randomness = crypto.getRandomValues(new Uint8Array(32));
  const blob: GroupAttributeBlob = { type: 'title', title: label };
  const plaintext = encodeAttributeBlob(blob);
  const paddingLen = paddedLength(plaintext.length) - plaintext.length;
  return encryptBlobWithPadding(secretParams, randomness, plaintext, paddingLen);
}

/**
 * Decrypt a label blob back to a string.
 */
export function decryptLabelFromBlob(
  secretParams: GroupSecretParams,
  ciphertext: Uint8Array
): string {
  if (ciphertext.length === 0) return '';
  const plaintext = decryptBlobWithPadding(secretParams, ciphertext);
  const blob = decodeAttributeBlob(plaintext);
  if (blob.type === 'title') return blob.title;
  return '';
}

// ---------------------------------------------------------------------------
// ServiceId byte helpers
// ---------------------------------------------------------------------------

/**
 * Parse 17-byte serviceIdBytes into a ServiceId object.
 *
 * Validates the ServiceId length and kind byte.
 */
function parseServiceIdBytes(bytes: Uint8Array): ServiceId {
  if (bytes.length !== 17) {
    throw new Error(`ServiceIdBytes must be 17 bytes, got ${bytes.length}`);
  }
  const kind = bytes[0];
  if (kind !== SERVICE_ID_ACI && kind !== SERVICE_ID_PNI) {
    throw new Error(`Invalid ServiceId kind byte: 0x${kind.toString(16).padStart(2, '0')}`);
  }
  return { kind, uuid: bytes.slice(1) };
}

// NOTE: serializeServiceId() removed — use serviceIdBinary() from uid-struct (DRY)

// ---------------------------------------------------------------------------
// Attribute encryption/decryption (title, description, timer)
// ---------------------------------------------------------------------------

/**
 * Encrypt a group title.
 *
 * @param secretParams - Group secret parameters
 * @param randomness - 32-byte randomness for encryption
 * @param title - Plain text title
 * @returns Encrypted title ciphertext
 */
export function encryptGroupTitle(
  secretParams: GroupSecretParams,
  randomness: Uint8Array,
  title: string
): Uint8Array {
  const blob: GroupAttributeBlob = { type: 'title', title };
  const plaintext = encodeAttributeBlob(blob);
  const paddingLen = paddedLength(plaintext.length) - plaintext.length;
  return encryptBlobWithPadding(secretParams, randomness, plaintext, paddingLen);
}

/**
 * Decrypt a group title.
 *
 * @param secretParams - Group secret parameters
 * @param ciphertext - Encrypted title ciphertext
 * @returns Plain text title
 */
export function decryptGroupTitle(secretParams: GroupSecretParams, ciphertext: Uint8Array): string {
  if (ciphertext.length === 0) return '';
  const plaintext = decryptBlobWithPadding(secretParams, ciphertext);
  const blob = decodeAttributeBlob(plaintext);
  if (blob.type !== 'title') {
    throw new Error(`Expected title blob, got ${blob.type}`);
  }
  return blob.title;
}

/**
 * Encrypt a group description.
 *
 * @param secretParams - Group secret parameters
 * @param randomness - 32-byte randomness for encryption
 * @param description - Plain text description
 * @returns Encrypted description ciphertext
 */
export function encryptGroupDescription(
  secretParams: GroupSecretParams,
  randomness: Uint8Array,
  description: string
): Uint8Array {
  const blob: GroupAttributeBlob = {
    type: 'descriptionText',
    descriptionText: description,
  };
  const plaintext = encodeAttributeBlob(blob);
  const paddingLen = paddedLength(plaintext.length) - plaintext.length;
  return encryptBlobWithPadding(secretParams, randomness, plaintext, paddingLen);
}

/**
 * Decrypt a group description.
 *
 * @param secretParams - Group secret parameters
 * @param ciphertext - Encrypted description ciphertext
 * @returns Plain text description
 */
export function decryptGroupDescription(
  secretParams: GroupSecretParams,
  ciphertext: Uint8Array
): string {
  if (ciphertext.length === 0) return '';
  const plaintext = decryptBlobWithPadding(secretParams, ciphertext);
  const blob = decodeAttributeBlob(plaintext);
  if (blob.type !== 'descriptionText') {
    throw new Error(`Expected descriptionText blob, got ${blob.type}`);
  }
  return blob.descriptionText;
}

/**
 * Encrypt a disappearing messages timer.
 *
 * @param secretParams - Group secret parameters
 * @param randomness - 32-byte randomness for encryption
 * @param duration - Timer duration in seconds
 * @returns Encrypted timer ciphertext
 */
export function encryptDisappearingMessagesTimer(
  secretParams: GroupSecretParams,
  randomness: Uint8Array,
  duration: number
): Uint8Array {
  const blob: GroupAttributeBlob = {
    type: 'disappearingMessagesDuration',
    duration,
  };
  const plaintext = encodeAttributeBlob(blob);
  const paddingLen = paddedLength(plaintext.length) - plaintext.length;
  return encryptBlobWithPadding(secretParams, randomness, plaintext, paddingLen);
}

/**
 * Decrypt a disappearing messages timer.
 *
 * @param secretParams - Group secret parameters
 * @param ciphertext - Encrypted timer ciphertext
 * @returns Decrypted timer object
 */
export function decryptDisappearingMessagesTimer(
  secretParams: GroupSecretParams,
  ciphertext: Uint8Array
): DecryptedTimer {
  if (ciphertext.length === 0) return { duration: 0 };
  const plaintext = decryptBlobWithPadding(secretParams, ciphertext);
  const blob = decodeAttributeBlob(plaintext);
  if (blob.type !== 'disappearingMessagesDuration') {
    throw new Error(`Expected disappearingMessagesDuration blob, got ${blob.type}`);
  }
  return { duration: blob.duration };
}

// ---------------------------------------------------------------------------
// Member encryption/decryption
// ---------------------------------------------------------------------------

/**
 * Context for generating a ProfileKeyCredentialPresentation during member encryption.
 */
export interface PresentationContext {
  /** The client's verified profile key credential. */
  credential: ExpiringProfileKeyCredential;
  /** The server's profile key credential public key. */
  credentialPublicKey: CredentialPublicKey;
}

/**
 * Encrypt a group member.
 *
 * Encrypts ACI → UuidCiphertext (65 bytes), profile key → ProfileKeyCiphertext (65 bytes),
 * and labels → encrypted blobs.
 *
 * When a presentationContext is provided, generates a ProfileKeyCredentialPresentation
 * that lets the server verify the encrypted data without decrypting it.
 *
 * @param secretParams - Group secret parameters
 * @param member - Decrypted member
 * @param presentationContext - Optional credential for presentation generation
 * @returns Encrypted member
 */
export function encryptMember(
  secretParams: GroupSecretParams,
  member: DecryptedMember,
  presentationContext?: PresentationContext
): EncryptedMember {
  // Encrypt ACI as ServiceId → 65-byte UuidCiphertext
  const aciServiceId: ServiceId = {
    kind: SERVICE_ID_ACI,
    uuid: member.aciBytes,
  };
  const encryptedUserId = encryptUuid(secretParams, aciServiceId);

  // Encrypt profile key (bound to ACI for security)
  const encryptedProfileKey = encryptProfileKeyCiphertext(
    secretParams,
    member.profileKey,
    member.aciBytes
  );

  // Encrypt labels as blobs
  const encryptedLabelEmoji = encryptLabelAsBlob(secretParams, member.labelEmoji);
  const encryptedLabelString = encryptLabelAsBlob(secretParams, member.labelString);

  // Generate presentation if credential is provided
  let presentation = new Uint8Array(0);
  if (presentationContext) {
    const randomness = crypto.getRandomValues(new Uint8Array(32));
    const pres = presentProfileKeyCredential(
      presentationContext.credentialPublicKey,
      presentationContext.credential,
      secretParams,
      randomness
    );
    presentation = new Uint8Array(serializeProfileKeyCredentialPresentation(pres));
  }

  return {
    userId: encryptedUserId,
    role: member.role,
    profileKey: encryptedProfileKey,
    presentation,
    joinedAtVersion: member.joinedAtRevision,
    labelEmoji: encryptedLabelEmoji,
    labelString: encryptedLabelString,
  };
}

/**
 * Decrypt a group member.
 *
 * @param secretParams - Group secret parameters
 * @param member - Encrypted member
 * @returns Decrypted member
 */
export function decryptMember(
  secretParams: GroupSecretParams,
  member: EncryptedMember
): DecryptedMember {
  // Decrypt userId → ServiceId
  const serviceId = decryptUuid(secretParams, member.userId);
  if (serviceId.kind !== SERVICE_ID_ACI) {
    throw new Error(`Expected ACI service ID, got kind ${serviceId.kind}`);
  }

  // Decrypt profile key (bound to the ACI)
  const profileKey =
    member.profileKey.length > 0
      ? decryptProfileKeyCiphertext(secretParams, member.profileKey, serviceId.uuid)
      : new Uint8Array(0);

  // Decrypt labels
  const labelEmoji = decryptLabelFromBlob(secretParams, member.labelEmoji);
  const labelString = decryptLabelFromBlob(secretParams, member.labelString);

  return {
    aciBytes: serviceId.uuid,
    role: member.role,
    profileKey,
    joinedAtRevision: member.joinedAtVersion,
    pniBytes: new Uint8Array(0),
    labelEmoji,
    labelString,
  };
}

// ---------------------------------------------------------------------------
// Pending member encryption/decryption
// ---------------------------------------------------------------------------

function encryptPendingMember(
  secretParams: GroupSecretParams,
  pending: DecryptedPendingMember
): EncryptedPendingMember {
  if (pending.quarantined === true) {
    throw new Error(
      'INVALID_GROUP: Quarantined pending entries cannot be submitted'
    );
  }
  const encryptedUserId = encryptUuid(
    secretParams,
    parseServiceIdBytes(pending.serviceIdBytes)
  );

  // Create minimal EncryptedMember for the pending entry
  const member: EncryptedMember = {
    userId: encryptedUserId,
    role: pending.role,
    profileKey: new Uint8Array(0),
    presentation: new Uint8Array(0),
    joinedAtVersion: 0,
    labelEmoji: new Uint8Array(0),
    labelString: new Uint8Array(0),
  };

  // Encrypt addedBy ACI
  const addedByServiceId: ServiceId = {
    kind: SERVICE_ID_ACI,
    uuid: pending.addedByAci,
  };
  const encryptedAddedBy = encryptUuid(secretParams, addedByServiceId);

  return {
    member,
    addedByUserId: encryptedAddedBy,
    timestamp: pending.timestamp,
  };
}

function decryptPendingMember(
  secretParams: GroupSecretParams,
  pending: EncryptedPendingMember
): DecryptedPendingMember {
  if (
    pending.member.profileKey.length !== 0 ||
    pending.member.presentation.length !== 0
  ) {
    throw new Error(
      'INVALID_GROUP: Pending profile-key member must not carry a profile key or presentation'
    );
  }
  // Decrypt addedBy
  const addedByServiceId = decryptUuid(secretParams, pending.addedByUserId);
  if (
    addedByServiceId.kind !== SERVICE_ID_ACI ||
    isNilUuid(addedByServiceId.uuid)
  ) {
    throw new Error('INVALID_GROUP: Pending-member inviter must be a non-nil ACI');
  }

  const common = {
    role: pending.member.role,
    addedByAci: addedByServiceId.uuid,
    timestamp: pending.timestamp,
    serviceIdCipherText: new Uint8Array(pending.member.userId),
  };
  try {
    const serviceId = decryptUuid(secretParams, pending.member.userId);
    if (isNilUuid(serviceId.uuid)) throw new Error('nil target');
    return {
      ...common,
      serviceIdBytes: serviceIdBinary(serviceId),
    };
  } catch {
    return {
      ...common,
      serviceIdBytes: new Uint8Array(0),
      quarantined: true,
    };
  }
}

// ---------------------------------------------------------------------------
// Requesting member encryption/decryption
// ---------------------------------------------------------------------------

export function encryptRequestingMember(
  secretParams: GroupSecretParams,
  member: DecryptedRequestingMember,
  presentationContext?: PresentationContext
): EncryptedRequestingMember {
  if (member.quarantined === true) {
    throw new Error(
      'INVALID_GROUP: Quarantined requesting entries cannot be submitted'
    );
  }
  const aciServiceId: ServiceId = {
    kind: SERVICE_ID_ACI,
    uuid: member.aciBytes,
  };
  const encryptedUserId = encryptUuid(secretParams, aciServiceId);
  const encryptedProfileKey = encryptProfileKeyCiphertext(
    secretParams,
    member.profileKey,
    member.aciBytes
  );

  // Generate presentation if credential is provided
  let presentation = new Uint8Array(0);
  if (presentationContext) {
    const randomness = crypto.getRandomValues(new Uint8Array(32));
    const pres = presentProfileKeyCredential(
      presentationContext.credentialPublicKey,
      presentationContext.credential,
      secretParams,
      randomness
    );
    presentation = new Uint8Array(serializeProfileKeyCredentialPresentation(pres));
  }

  return {
    userId: encryptedUserId,
    profileKey: encryptedProfileKey,
    presentation,
    timestamp: member.timestamp,
  };
}

function decryptRequestingMember(
  secretParams: GroupSecretParams,
  member: EncryptedRequestingMember
): DecryptedRequestingMember {
  let serviceId: ServiceId;
  try {
    serviceId = decryptUuid(secretParams, member.userId);
  } catch {
    return {
      aciBytes: new Uint8Array(0),
      profileKey: new Uint8Array(0),
      timestamp: member.timestamp,
      aciCipherText: new Uint8Array(member.userId),
      profileKeyCipherText: new Uint8Array(member.profileKey),
      quarantined: true,
    };
  }
  if (serviceId.kind !== SERVICE_ID_ACI) {
    throw new Error(`Expected ACI service ID, got kind ${serviceId.kind}`);
  }
  if (isNilUuid(serviceId.uuid)) {
    return {
      aciBytes: new Uint8Array(0),
      profileKey: new Uint8Array(0),
      timestamp: member.timestamp,
      aciCipherText: new Uint8Array(member.userId),
      profileKeyCipherText: new Uint8Array(member.profileKey),
      quarantined: true,
    };
  }

  const profileKey =
    member.profileKey.length > 0
      ? decryptProfileKeyCiphertext(secretParams, member.profileKey, serviceId.uuid)
      : new Uint8Array(0);

  return {
    aciBytes: serviceId.uuid,
    profileKey,
    timestamp: member.timestamp,
  };
}

// ---------------------------------------------------------------------------
// Banned member encryption/decryption
// ---------------------------------------------------------------------------

function encryptBannedMember(
  secretParams: GroupSecretParams,
  member: DecryptedBannedMember
): EncryptedBannedMember {
  if (member.quarantined === true) {
    throw new Error(
      'INVALID_GROUP: Quarantined banned entries cannot be submitted'
    );
  }
  const encryptedUserId = encryptUuid(
    secretParams,
    parseServiceIdBytes(member.serviceIdBytes)
  );

  return {
    userId: encryptedUserId,
    timestamp: member.timestamp,
  };
}

function decryptBannedMember(
  secretParams: GroupSecretParams,
  member: EncryptedBannedMember
): DecryptedBannedMember {
  try {
    const serviceId = decryptUuid(secretParams, member.userId);
    if (isNilUuid(serviceId.uuid)) throw new Error('nil target');
    return {
      serviceIdBytes: serviceIdBinary(serviceId),
      timestamp: member.timestamp,
    };
  } catch {
    return {
      serviceIdBytes: new Uint8Array(0),
      timestamp: member.timestamp,
      serviceIdCipherText: new Uint8Array(member.userId),
      quarantined: true,
    };
  }
}

// ---------------------------------------------------------------------------
// Full group state encryption/decryption
// ---------------------------------------------------------------------------

/**
 * Encrypt full group state.
 *
 * @param secretParams - Group secret parameters
 * @param group - Decrypted group state
 * @param memberPresentationContexts - Optional map of member ACI hex to presentation context
 * @returns Encrypted group state
 */
export function encryptGroupState(
  secretParams: GroupSecretParams,
  group: DecryptedGroup,
  memberPresentationContexts?: ReadonlyMap<string, PresentationContext>
): EncryptedGroup {
  const structuralErrors = [
    ...validateGroupIdentifiers(group),
    ...validateGroupAccessControl(group),
    ...validateGroupMemberRoles(group),
    ...validateGroupCanonicalFields(group),
  ];
  if (structuralErrors.length > 0) {
    throw new Error(`INVALID_GROUP: ${structuralErrors.join('; ')}`);
  }

  // Encrypt title
  const titleRandomness = crypto.getRandomValues(new Uint8Array(32));
  const title = group.title
    ? encryptGroupTitle(secretParams, titleRandomness, group.title)
    : new Uint8Array(0);

  // Encrypt description
  const descriptionRandomness = crypto.getRandomValues(new Uint8Array(32));
  const description = group.description
    ? encryptGroupDescription(secretParams, descriptionRandomness, group.description)
    : new Uint8Array(0);

  // Encrypt disappearing messages timer
  const timerRandomness = crypto.getRandomValues(new Uint8Array(32));
  const disappearingMessagesTimer = group.disappearingMessagesTimer
    ? encryptDisappearingMessagesTimer(
        secretParams,
        timerRandomness,
        group.disappearingMessagesTimer.duration
      )
    : new Uint8Array(0);

  // Encrypt members (with optional presentation contexts)
  const members = group.members.map((m) => {
    const aciHex = Array.from(m.aciBytes)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
    const ctx = memberPresentationContexts?.get(aciHex);
    return encryptMember(secretParams, m, ctx);
  });

  // Encrypt pending members
  const membersPendingProfileKey = group.pendingMembers.map((m) =>
    encryptPendingMember(secretParams, m)
  );

  // Encrypt requesting members
  const membersPendingAdminApproval = group.requestingMembers.map((m) =>
    encryptRequestingMember(secretParams, m)
  );

  // Encrypt banned members
  const membersBanned = group.bannedMembers.map((m) => encryptBannedMember(secretParams, m));

  return {
    terminated: group.terminated,
    publicKey: serializeGroupPublicParams(getGroupPublicParams(secretParams)),
    title,
    description,
    avatarUrl: group.avatar || '',
    disappearingMessagesTimer,
    accessControl: group.accessControl,
    version: group.revision,
    members,
    membersPendingProfileKey,
    membersPendingAdminApproval,
    inviteLinkPassword: group.inviteLinkPassword || new Uint8Array(0),
    announcementsOnly: group.isAnnouncementGroup === EnabledState.ENABLED,
    membersBanned,
  };
}

/**
 * Decrypt full group state.
 *
 * @param secretParams - Group secret parameters
 * @param encrypted - Encrypted group state
 * @returns Decrypted group state
 */
export function decryptGroupState(
  secretParams: GroupSecretParams,
  encrypted: EncryptedGroup
): DecryptedGroup {
  // Decrypt title
  const title = encrypted.title.length > 0 ? decryptGroupTitle(secretParams, encrypted.title) : '';

  // Decrypt description
  const description =
    encrypted.description.length > 0
      ? decryptGroupDescription(secretParams, encrypted.description)
      : '';

  // Decrypt disappearing messages timer
  const disappearingMessagesTimer =
    encrypted.disappearingMessagesTimer.length > 0
      ? decryptDisappearingMessagesTimer(secretParams, encrypted.disappearingMessagesTimer)
      : { duration: 0 };

  // Decrypt members
  const members = encrypted.members.map((m) => decryptMember(secretParams, m));

  // Decrypt pending members
  const pendingMembers = encrypted.membersPendingProfileKey.map((m) =>
    decryptPendingMember(secretParams, m)
  );

  // Decrypt requesting members
  const requestingMembers = encrypted.membersPendingAdminApproval.map((m) =>
    decryptRequestingMember(secretParams, m)
  );

  // Decrypt banned members
  const bannedMembers = encrypted.membersBanned.map((m) => decryptBannedMember(secretParams, m));

  const group: DecryptedGroup = {
    title,
    avatar: encrypted.avatarUrl || '',
    disappearingMessagesTimer,
    accessControl: encrypted.accessControl,
    revision: encrypted.version,
    members,
    pendingMembers,
    requestingMembers,
    inviteLinkPassword: encrypted.inviteLinkPassword,
    description,
    isAnnouncementGroup: encrypted.announcementsOnly ? EnabledState.ENABLED : EnabledState.DISABLED,
    bannedMembers,
    terminated: encrypted.terminated,
  };
  const structuralErrors = [
    ...validateGroupIdentifiers(group),
    ...validateGroupAccessControl(group),
    ...validateGroupMemberRoles(group),
    ...validateGroupCanonicalFields(group),
  ];
  if (structuralErrors.length > 0) {
    throw new Error(`INVALID_GROUP: ${structuralErrors.join('; ')}`);
  }
  return group;
}

/** Decrypt the reduced projection returned to an invite-link holder. */
export function decryptGroupJoinInfo(
  secretParams: GroupSecretParams,
  encrypted: EncryptedGroupJoinInfo
): DecryptedGroupJoinInfo {
  return {
    publicKey: encrypted.publicKey,
    title: encrypted.title.length > 0 ? decryptGroupTitle(secretParams, encrypted.title) : '',
    avatar: encrypted.avatar,
    memberCount: encrypted.memberCount,
    addFromInviteLink: encrypted.addFromInviteLink,
    revision: encrypted.revision,
    pendingAdminApproval: encrypted.pendingAdminApproval,
    description:
      encrypted.description.length > 0
        ? decryptGroupDescription(secretParams, encrypted.description)
        : '',
  };
}
