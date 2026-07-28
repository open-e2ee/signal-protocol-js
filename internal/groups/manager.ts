/**
 * Group manager
 *
 * Orchestrates group lifecycle operations:
 * - Group creation/deletion
 * - Membership changes (add, remove, promote, ban)
 * - Attribute updates (title, description, avatar, timer)
 * - State sync from server (change log replay)
 * - Invite link management
 * - Sender key rotation on membership removal
 *
 * The manager coordinates between:
 * - zero-knowledge group cryptography for encryption/decryption
 * - Encrypted state layer for serialization
 * - Change actions for state transitions
 * - Access control for authorization
 * - SenderKeyManager for group messaging key rotation
 * - Server relay for state storage
 *
 * @module groups/manager
 */

import {
  type GroupSecretParams,
  type ServiceId,
  SERVICE_ID_ACI,
  SERVICE_ID_PNI,
  serviceIdBinary,
  groupMasterKey,
  deriveGroupSecretParams,
  getGroupPublicParams,
  GROUP_MASTER_KEY_LEN,
  encryptUuid,
  decryptUuid,
  decryptProfileKeyCiphertext,
  serverVerifySignature,
} from '../protocol/zk/groups';
import { isNilUuid } from '../protocol/zk/groups/uid-struct';

import {
  type DecryptedGroup,
  type DecryptedMember,
  type DecryptedAddMember,
  type DecryptedProfileKeyUpdate,
  type DecryptedPendingMemberPromotion,
  type DecryptedPniAciMemberPromotion,
  type DecryptedGroupChange,
  type DecryptedPendingMember,
  type DecryptedAddPendingMember,
  type DecryptedPendingMemberRemoval,
  type DecryptedRequestingMember,
  type DecryptedAddRequestingMember,
  type DecryptedBannedMember,
  type DecryptedAddBannedMember,
  type DecryptedDeleteBannedMember,
  type DecryptedApproveMember,
  type DecryptedModifyMemberRole,
  type DecryptedModifyMemberLabel,
  type EncryptedGroupChange,
  type EncryptedChangeAddMember,
  type EncryptedChangeProfileKeyUpdate,
  type EncryptedChangePendingMemberPromotion,
  type EncryptedChangePniAciMemberPromotion,
  type EncryptedChangePendingMember,
  type EncryptedChangePendingMemberRemoval,
  type EncryptedChangeRequestingMember,
  type EncryptedChangeBannedMember,
  type EncryptedChangeBannedMemberRemoval,
  type EncryptedChangeApproveMember,
  type EncryptedChangeModifyMemberRole,
  type EncryptedChangeModifyMemberLabel,
  type AccessControl,
  MemberRole,
  AccessRequired,
  EnabledState,
  defaultAccessControl,
  emptyGroupChange,
} from './types';

import {
  encryptGroupState,
  decryptGroupState,
  decryptGroupJoinInfo,
  encryptMember,
  decryptMember,
  encryptRequestingMember,
  encryptLabelAsBlob,
  decryptLabelFromBlob,
  encryptGroupTitle,
  decryptGroupTitle,
  encryptGroupDescription,
  decryptGroupDescription,
  encryptDisappearingMessagesTimer,
  decryptDisappearingMessagesTimer,
} from './encrypted-state';
import {
  applyGroupChange,
  validateChangeAccessControl,
  validateChangeIdentifiers,
  validateChangeMemberRoles,
  validateChangeStructure,
} from './change-actions';
import {
  canPerformAction,
  GroupAction,
  isMember,
  isPending,
  isBanned,
  isStoredMemberRole,
  satisfiesLiveGroupAdministratorInvariant,
} from './access-control';
import { validateChangeAuthorization } from './change-authorization';
import {
  createGroupInviteLink,
  parseGroupInviteLink,
  generateInviteLinkPassword,
} from './invite-link';
import type { GroupId } from '../groups/group-id';
import { createGroupId, extractGroupId } from '../groups/group-id';
import { constantTimeEqual as bytesEqual } from '../crypto/utils';
import { bytesToHex } from '../../encoding/hex';
import type { CredentialPublicKey } from '../protocol/zk/credentials/credentials';
import type { AuthCredentialWithPni } from '../protocol/zk/groups/auth-credential';
import {
  receiveAuthCredential,
  presentAuthCredential,
  deserializeAuthCredentialResponse,
  serializeAuthCredentialPresentation,
  serializeGroupPublicParams,
} from '../protocol/zk/groups/auth-credential';
import type { ExpiringProfileKeyCredential } from '../protocol/zk/groups/profile-key-credential';
import {
  receiveProfileKeyCredential,
  deserializeProfileKeyCredentialResponse,
} from '../protocol/zk/groups/profile-key-credential';
import type { PresentationContext } from './encrypted-state';
import { SECONDS_PER_DAY } from '../protocol/zk/groups/group-params';
import AsyncLock from 'async-lock';
import {
  assertEncryptedGroupChangeForm,
  assertValidEncryptedGroupChangeWire,
  assertValidEncryptedGroupWire,
  deserializeEncryptedGroup,
  deserializeEncryptedGroupChange,
  deserializeEncryptedGroupJoinInfo,
  serializeEncryptedGroupCreationSubmission,
  serializeEncryptedGroupChange,
  serializeGroupBaseline,
  serializeGroupChangeCommitment,
  countGroupChangeActions,
  requiredGroupChangeEpoch,
  toEncryptedGroupCreationSubmission,
} from './wire';

/**
 * Serialized auth credential for server verification.
 *
 * The value combines group public parameters with an authentication credential
 * presentation. Relay adapters pass both byte strings explicitly.
 */
export {};
export interface GroupAuthorization {
  /** Serialized AuthCredentialPresentation (ZK proof of group membership). */
  presentation: Uint8Array;
  /** Serialized GroupPublicParams (identifies the group for credential verification). */
  groupPublicParams: Uint8Array;
}

/**
 * Interface for local group state storage.
 *
 * Stores master keys (the root secret for each group) and decrypted state
 * cache for offline access.
 */
export interface IGroupStateStore {
  /** Store a group master key. */
  storeMasterKey(groupId: string, masterKey: Uint8Array): Promise<void>;
  /** Get a group master key. */
  getMasterKey(groupId: string): Promise<Uint8Array | null>;
  /** Delete a group master key. */
  deleteMasterKey(groupId: string): Promise<void>;

  /** Store decrypted group state cache. */
  storeGroupState(groupId: string, state: DecryptedGroup): Promise<void>;
  /**
   * Atomically store accepted group state and establish C7's sender-key
   * rotation barrier at that state's revision.
   */
  storeGroupStateWithSenderKeyRotationBarrier(
    groupId: string,
    state: DecryptedGroup
  ): Promise<void>;
  /** Get cached decrypted group state. */
  getGroupState(groupId: string): Promise<DecryptedGroup | null>;
  /** Get the accepted revision whose C7 rotation is still pending. */
  getSenderKeyRotationBarrier(groupId: string): Promise<number | null>;
  /**
   * Clear C7's barrier only when it still names `expectedRevision`.
   * A stale completion must never clear a newer accepted transition.
   */
  clearSenderKeyRotationBarrier(
    groupId: string,
    expectedRevision: number
  ): Promise<void>;
  /** Delete cached group state. */
  deleteGroupState(groupId: string): Promise<void>;
}

/**
 * Interface for server-side group operations.
 *
 * The server stores encrypted group state, verifies presentations, evaluates
 * policy through deterministic ciphertext comparison, and enforces version
 * sequencing. It never decrypts group content.
 */
export interface IGroupServer {
  /** Create a new group on the server. */
  createGroup(
    groupId: Uint8Array,
    encryptedState: Uint8Array,
    authorization: GroupAuthorization
  ): Promise<void>;

  /**
   * Get encrypted group state.
   *
   * When `version` is supplied, the server must return that exact historical
   * snapshot or null. Versioned reads make the post-join baseline race-safe:
   * clients must not jump over unverified changes to a newer snapshot.
   */
  getGroup(
    groupId: Uint8Array,
    authorization: GroupAuthorization,
    version?: number
  ): Promise<GroupSnapshot | null>;

  /** Get the reduced invite-link projection after server-side password verification. */
  getGroupJoinInfo(
    groupId: Uint8Array,
    inviteLinkPassword: Uint8Array,
    authorization: GroupAuthorization
  ): Promise<{ encryptedJoinInfo: Uint8Array; version: number } | null>;

  /**
   * Get one page of the authorized change log after a historical version.
   *
   * Authorization is evaluated at the `fromVersion` snapshot, and the
   * requester must be a member there (S10; S10a governs how a refused
   * pending requester advances instead). The page includes the first
   * transition whose post-state drops the requester from `members`, then
   * stops; a requester who is not a member at that snapshot is refused.
   * `hasMore` signals a page cut for size, resumable from the last served
   * version.
   */
  getGroupChanges(
    groupId: Uint8Array,
    fromVersion: number,
    authorization: GroupAuthorization
  ): Promise<GroupChangeLogPage>;

  /** Submit a group change (optimistic concurrency). */
  submitGroupChange(
    groupId: Uint8Array,
    expectedVersion: number,
    actions: Uint8Array,
    inviteLinkPassword: Uint8Array,
    authorization: GroupAuthorization
  ): Promise<GroupChangeLogEntry>;
}

/** A canonical encrypted state and the server's S14 commitment to it. */
export interface GroupSnapshot {
  encryptedState: Uint8Array;
  version: number;
  baselineSignature: Uint8Array;
}

/** A single change log entry from the server. */
export interface GroupChangeLogEntry {
  version: number;
  actions: Uint8Array;
  serverSignature: Uint8Array;
  changeEpoch: number;
  timestamp: number;
}

/**
 * One page of the change log.
 *
 * The log is served in bounded pages so one request cannot be made to carry
 * a group's whole history. `hasMore` is true only when the server stopped
 * for size with the requester still readable — the client resumes from the
 * version of the last entry served. A walk that ends at the log's tip, or
 * at the transition that revokes the requester, is complete and says so.
 */
export interface GroupChangeLogPage {
  entries: GroupChangeLogEntry[];
  hasMore: boolean;
}

// ---------------------------------------------------------------------------
// Sender key rotation callback
// ---------------------------------------------------------------------------

/**
 * Callback to rotate sender keys when membership changes.
 *
 * Called by the manager when a member is removed or banned,
 * delegating to SenderKeyManager.
 */
export type OnSenderKeyRotation = (groupId: GroupId) => Promise<void>;

/**
 * Callback to invalidate endorsement cache when membership changes.
 *
 * Called by the manager when members are added, removed, or banned.
 * The implementation should delegate to the app-owned endorsement cache adapter.
 * Non-fatal — endorsements are lazily refreshed on next send.
 */
export type OnEndorsementsInvalidated = (groupId: string) => Promise<void>;

// ---------------------------------------------------------------------------
// Manager options
// ---------------------------------------------------------------------------

export interface GroupManagerOptions {
  /** Local group state storage. */
  store: IGroupStateStore;
  /** Server-side group operations. */
  server: IGroupServer;
  /** Callback for sender key rotation on membership removal. */
  onSenderKeyRotation?: OnSenderKeyRotation;
  /** Callback to invalidate endorsement cache on membership changes. */
  onEndorsementsInvalidated?: OnEndorsementsInvalidated;
  /** Issue a fresh auth credential from the server (calls relay.issueAuthCredential). */
  issueCredential: () => Promise<Uint8Array>;
  /** Server's credential public key for verifying issuance proofs. */
  credentialPublicKey: CredentialPublicKey;
  /**
   * Pinned server change-signing key.
   *
   * When omitted, `allowUnauthenticatedGroupHistory` must be explicitly set
   * to enter the documented non-conforming deployment mode.
   */
  serverSigningPublicKey?: Uint8Array;
  /**
   * Explicitly accept group history without server signatures.
   *
   * This is a security downgrade for deployments whose group server does not
   * implement the enforcing-server obligations. It is consulted only when
   * `serverSigningPublicKey` is absent.
   */
  allowUnauthenticatedGroupHistory?: boolean;
  /** Receive non-conforming group-server configuration warnings. */
  onConfigurationWarning?: (warning: GroupConfigurationWarning) => void;
  /** User's ACI for credential presentation. */
  aci: ServiceId;
  /** User's PNI for credential presentation, when the account has one. */
  pni?: ServiceId;
  /** Issue a fresh profile key credential from the server. Returns serialized response. */
  issueProfileKeyCredential: () => Promise<Uint8Array>;
  /** Server's profile key credential public key. */
  profileKeyCredentialPublicKey: CredentialPublicKey;
  /** User's 32-byte profile key for profile key credential. */
  profileKey: Uint8Array;
}

/** A target whose profile-key credential is available for an immediate add. */
export interface PresentedGroupMemberInput {
  aciBytes: Uint8Array;
  profileKey: Uint8Array;
  profileKeyCredential: ReturnType<typeof receiveProfileKeyCredential>;
  role?: MemberRole;
}

/** A target invited without a profile key; they present when accepting. */
export interface InvitedGroupMemberInput {
  serviceIdBytes: Uint8Array;
  role?: MemberRole;
}

/** A member introduction accepted by createGroup() and addMember(). */
export type GroupMemberInput =
  | PresentedGroupMemberInput
  | InvitedGroupMemberInput;

function classifyGroupMemberInput(
  member: GroupMemberInput
): 'presented' | 'invited' {
  const invalid = (detail: string): never => {
    throw new Error(`INVALID_GROUP_MEMBER_INPUT: ${detail}`);
  };
  if (
    typeof member !== 'object' ||
    member === null ||
    Array.isArray(member)
  ) {
    return invalid('Member must be exactly one supported input variant');
  }
  const hasOwn = (field: string): boolean =>
    Object.prototype.hasOwnProperty.call(member, field);
  const hasPresentation = hasOwn('profileKeyCredential');
  const hasServiceId = hasOwn('serviceIdBytes');
  if (hasPresentation === hasServiceId) {
    return invalid(
      'Member must be exactly one of a presented member or an invitation'
    );
  }

  const allowedFields = new Set(
    hasPresentation
      ? ['aciBytes', 'profileKey', 'profileKeyCredential', 'role']
      : ['serviceIdBytes', 'role']
  );
  const unexpected = Object.keys(member).find(
    (field) => !allowedFields.has(field)
  );
  if (unexpected !== undefined) {
    return invalid(`Member contains unsupported field ${unexpected}`);
  }
  if (
    member.role !== undefined &&
    !isStoredMemberRole(member.role)
  ) {
    return invalid('Member role is outside its stored-role domain');
  }

  if (hasPresentation) {
    const presented = member as PresentedGroupMemberInput;
    if (
      !(presented.aciBytes instanceof Uint8Array) ||
      presented.aciBytes.length !== 16
    ) {
      return invalid('Presented member ACI must be 16-byte data');
    }
    if (
      !(presented.profileKey instanceof Uint8Array) ||
      presented.profileKey.length !== 32
    ) {
      return invalid('Presented member profile key must be 32-byte data');
    }
    const credential = presented.profileKeyCredential as unknown;
    const credentialRecord =
      typeof credential === 'object' && credential !== null
        ? (credential as Record<string, unknown>)
        : undefined;
    const hasObjectField = (field: string): boolean => {
      const value = credentialRecord?.[field];
      return typeof value === 'object' && value !== null;
    };
    if (
      credentialRecord === undefined ||
      !hasObjectField('credential') ||
      !hasObjectField('aci') ||
      !hasObjectField('profileKey') ||
      !Number.isSafeInteger(credentialRecord.redemptionTime)
    ) {
      return invalid(
        'Presented member must carry a complete verified profile-key credential'
      );
    }
    return 'presented';
  }

  const invited = member as InvitedGroupMemberInput;
  if (!(invited.serviceIdBytes instanceof Uint8Array)) {
    return invalid('Invitation ServiceId must be byte data');
  }
  try {
    assertServiceIdBytes(invited.serviceIdBytes);
  } catch (error) {
    return invalid(
      error instanceof Error ? error.message : 'Invitation ServiceId is invalid'
    );
  }
  return 'invited';
}

export interface GroupConfigurationWarning {
  code: 'GROUP_SERVER_SIGNATURE_VERIFICATION_DISABLED';
  message: string;
}

// ---------------------------------------------------------------------------
// GroupManager
// ---------------------------------------------------------------------------

/**
 * Manages group lifecycle and state.
 *
 * This is the primary entry point for group operations. It coordinates
 * between crypto primitives, storage, and server communication.
 */
/** Default maximum group size enforced by the manager. */
export const MAX_GROUP_SIZE = 1000;
export const MAX_SUPPORTED_CHANGE_EPOCH = 6;

export class GroupManager {
  private readonly store: IGroupStateStore;
  private readonly server: IGroupServer;
  private readonly onSenderKeyRotation?: OnSenderKeyRotation;
  private readonly onEndorsementsInvalidated?: OnEndorsementsInvalidated;
  private readonly issueCredential: () => Promise<Uint8Array>;
  private readonly credentialPublicKey: CredentialPublicKey;
  private readonly serverSigningPublicKey?: Uint8Array;
  private readonly aci: ServiceId;
  private readonly pni?: ServiceId;
  private readonly issueProfileKeyCredentialFn: () => Promise<Uint8Array>;
  private readonly profileKeyCredentialPublicKey: CredentialPublicKey;
  private readonly profileKey: Uint8Array;
  private cachedCredential: { redemptionTime: number; credential: AuthCredentialWithPni } | null =
    null;
  private cachedProfileKeyCredential: {
    redemptionTime: number;
    credential: ExpiringProfileKeyCredential;
  } | null = null;
  /** Serializes credential fetches to prevent duplicate network requests. */
  private readonly credentialLock = new AsyncLock();

  constructor(options: GroupManagerOptions) {
    this.store = options.store;
    this.server = options.server;
    this.onSenderKeyRotation = options.onSenderKeyRotation;
    this.onEndorsementsInvalidated = options.onEndorsementsInvalidated;
    this.issueCredential = options.issueCredential;
    this.credentialPublicKey = options.credentialPublicKey;
    this.serverSigningPublicKey = options.serverSigningPublicKey
      ? new Uint8Array(options.serverSigningPublicKey)
      : undefined;
    if (this.serverSigningPublicKey && this.serverSigningPublicKey.length !== 32) {
      throw new Error(
        `Server signing public key must be 32 bytes, got ${this.serverSigningPublicKey.length}`
      );
    }
    if (!this.serverSigningPublicKey) {
      if (options.allowUnauthenticatedGroupHistory !== true) {
        throw new Error(
          'Group server signing key is required unless allowUnauthenticatedGroupHistory is explicitly enabled'
        );
      }
      const warning: GroupConfigurationWarning = {
        code: 'GROUP_SERVER_SIGNATURE_VERIFICATION_DISABLED',
        message:
          'Group server signing key is not configured; authenticated group history is disabled.',
      };
      if (options.onConfigurationWarning) {
        options.onConfigurationWarning(warning);
      } else {
        console.warn(warning.message);
      }
    }
    this.aci = options.aci;
    this.pni = options.pni;
    this.issueProfileKeyCredentialFn = options.issueProfileKeyCredential;
    this.profileKeyCredentialPublicKey = options.profileKeyCredentialPublicKey;
    this.profileKey = new Uint8Array(options.profileKey);
    if (this.profileKey.length !== 32) {
      throw new Error(`Profile key must be 32 bytes, got ${this.profileKey.length}`);
    }
  }

  // =========================================================================
  // Authorization
  // =========================================================================

  /**
   * Build authorization for a group operation.
   *
   * Flow: issue credential -> receive (verify issuance) -> present (create ZK proof)
   *
   * Public so the endorsement refresher (SignalProtocolClient) can build auth for
   * relay.refreshGroupSendEndorsements(). Safe because:
   *  - Credential is day-cached (one server round-trip per UTC day max)
   *  - Each presentation uses fresh randomness → unlinkable
   *  - No secret material is exposed; only the ZK proof + group public params
   */
  async getAuthorization(rawGroupId: string): Promise<GroupAuthorization> {
    const secretParams = await this.getSecretParams(rawGroupId);
    const groupPublicParams = getGroupPublicParams(secretParams);

    // Get or refresh credential (day-aligned).
    // The lock prevents concurrent fetches for the same day-scoped credential.
    const credential = await this.credentialLock.acquire('credential', async () => {
      const today = Math.floor(Date.now() / 1000 / SECONDS_PER_DAY) * SECONDS_PER_DAY;

      if (this.cachedCredential?.redemptionTime === today) {
        return this.cachedCredential.credential;
      }

      const responseBytes = await this.issueCredential();
      const response = deserializeAuthCredentialResponse(new Uint8Array(responseBytes));
      const cred = receiveAuthCredential(
        this.credentialPublicKey,
        response,
        this.aci,
        this.pni,
        today
      );
      this.cachedCredential = { redemptionTime: today, credential: cred };
      return cred;
    });

    // Create fresh presentation (new randomness each time for unlinkability)
    const presentation = presentAuthCredential(
      this.credentialPublicKey,
      credential,
      secretParams,
      crypto.getRandomValues(new Uint8Array(32))
    );

    return {
      presentation: serializeAuthCredentialPresentation(presentation),
      groupPublicParams: serializeGroupPublicParams(groupPublicParams),
    };
  }

  /**
   * Get or refresh the profile key credential for the current user.
   * Group profile-key introductions are never permitted without this proof.
   */
  private async getPresentationContext(): Promise<PresentationContext> {
    const today = Math.floor(Date.now() / 1000 / SECONDS_PER_DAY) * SECONDS_PER_DAY;

    if (
      !this.cachedProfileKeyCredential ||
      this.cachedProfileKeyCredential.redemptionTime !== today
    ) {
      const responseBytes = await this.issueProfileKeyCredentialFn();
      const response = deserializeProfileKeyCredentialResponse(new Uint8Array(responseBytes));
      const credential = receiveProfileKeyCredential(
        this.profileKeyCredentialPublicKey,
        response,
        this.aci,
        this.profileKey,
        response.redemptionTime,
        Math.floor(Date.now() / 1000)
      );
      this.cachedProfileKeyCredential = { redemptionTime: today, credential };
    }

    return {
      credential: this.cachedProfileKeyCredential.credential,
      credentialPublicKey: this.profileKeyCredentialPublicKey,
    };
  }

  /**
   * Execute a group server operation with one credential-refresh retry.
   * On `UNAUTHORIZED`, clears the credential cache and retries once.
   *
   * This is an SDK transport convenience, not specified behaviour: day-aligned
   * auth credentials can expire mid-flight, and one refresh is cheaper than
   * surfacing a spurious authorization failure.
   */
  private async withAuthRetry<T>(
    rawGroupId: string,
    operation: (authorization: GroupAuthorization) => Promise<T>
  ): Promise<T> {
    const authorization = await this.getAuthorization(rawGroupId);
    try {
      return await operation(authorization);
    } catch (err: unknown) {
      const isUnauthorized = err instanceof Error && err.message.includes('UNAUTHORIZED');
      if (!isUnauthorized) throw err;

      // Clear stale credential and retry once
      this.cachedCredential = null;
      const freshAuth = await this.getAuthorization(rawGroupId);
      return await operation(freshAuth);
    }
  }

  /**
   * Invalidate endorsement cache for a group (non-fatal).
   *
   * Called after membership changes. Failures are logged but do not
   * propagate — endorsements are lazily refreshed on next send.
   */
  private async invalidateEndorsements(rawGroupId: string): Promise<void> {
    if (!this.onEndorsementsInvalidated) return;
    try {
      await this.onEndorsementsInvalidated(rawGroupId);
    } catch {
      // Non-fatal — endorsements will be refreshed on next send
    }
  }

  // =========================================================================
  // Group Creation
  // =========================================================================

  /**
   * Create a new group.
   *
   * Generates a GroupMasterKey, derives all secrets, creates the initial
   * encrypted state, and uploads to the server.
   *
   * @param creatorAci - 16-byte ACI of the group creator
   * @param creatorProfileKey - 32-byte profile key of the creator
   * @param members - Targets with presentation material to add, or ServiceIds
   *   to invite without profile material
   * @param title - Group title
   * @param options - Optional settings (description, access control, avatar, timer)
   * @returns GroupId and master key
   */
  async createGroup(
    creatorAci: Uint8Array,
    creatorProfileKey: Uint8Array,
    members: GroupMemberInput[],
    title: string,
    options?: {
      description?: string;
      accessControl?: Partial<AccessControl>;
      avatarUrl?: string;
      disappearingMessagesDuration?: number;
    }
  ): Promise<{ groupId: GroupId; masterKey: Uint8Array }> {
    // Generate random master key
    const masterKeyBytes = new Uint8Array(GROUP_MASTER_KEY_LEN);
    crypto.getRandomValues(masterKeyBytes);
    const mk = groupMasterKey(masterKeyBytes);

    // Derive all group secrets
    const secretParams = deriveGroupSecretParams(mk);

    // Build initial decrypted state
    const ac = {
      ...defaultAccessControl(),
      ...options?.accessControl,
    };

    const creatorMember: DecryptedMember = {
      aciBytes: creatorAci,
      role: MemberRole.ADMINISTRATOR,
      profileKey: creatorProfileKey,
      joinedAtRevision: 0,
      pniBytes: new Uint8Array(0),
      labelEmoji: '',
      labelString: '',
    };

    const presentedMembers: PresentedGroupMemberInput[] = [];
    const invitedMembers: InvitedGroupMemberInput[] = [];
    for (const member of members) {
      if (classifyGroupMemberInput(member) === 'presented') {
        presentedMembers.push(member as PresentedGroupMemberInput);
      } else {
        invitedMembers.push(member as InvitedGroupMemberInput);
      }
    }
    const additionalMembers: DecryptedMember[] = presentedMembers.map((member) => ({
      aciBytes: member.aciBytes,
      role: member.role ?? MemberRole.DEFAULT,
      profileKey: member.profileKey,
      joinedAtRevision: 0,
      pniBytes: new Uint8Array(0),
      labelEmoji: '',
      labelString: '',
    }));
    const pendingMembers: DecryptedPendingMember[] = invitedMembers.map((member) => {
      assertServiceIdBytes(member.serviceIdBytes);
      return {
        serviceIdBytes: member.serviceIdBytes,
        role: member.role ?? MemberRole.DEFAULT,
        addedByAci: creatorAci,
        timestamp: Date.now(),
        serviceIdCipherText: new Uint8Array(0),
      };
    });

    const initialState: DecryptedGroup = {
      title,
      avatar: options?.avatarUrl ?? '',
      disappearingMessagesTimer: {
        duration: options?.disappearingMessagesDuration ?? 0,
      },
      accessControl: ac,
      revision: 0,
      members: [creatorMember, ...additionalMembers],
      pendingMembers,
      requestingMembers: [],
      inviteLinkPassword: new Uint8Array(0),
      description: options?.description ?? '',
      isAnnouncementGroup: EnabledState.DISABLED,
      bannedMembers: [],
      terminated: false,
    };

    // Get presentation context for the creator's member entry
    const presentationCtx = await this.getPresentationContext();
    const memberContexts = new Map<string, PresentationContext>();
    const creatorAciHex = Array.from(creatorAci)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
    memberContexts.set(creatorAciHex, presentationCtx);
    for (const member of presentedMembers) {
      const { profileKeyCredential: proof } = member;
      memberContexts.set(bytesToHex(member.aciBytes), {
        credential: proof,
        credentialPublicKey: this.profileKeyCredentialPublicKey,
      });
    }

    // Encrypt the initial state
    const encryptedState = encryptGroupState(
      secretParams,
      initialState,
      memberContexts
    );

    // Creation submits no provenance. The server derives it before signing
    // canonical version zero.
    const serialized = serializeEncryptedGroupCreationSubmission(
      toEncryptedGroupCreationSubmission(encryptedState)
    );

    // Derive group identifier
    const groupIdHex = bytesToHex(secretParams.groupId);
    const groupId = createGroupId(groupIdHex);

    // Store master key first so getAuthorization can derive secret params
    await this.store.storeMasterKey(groupIdHex, masterKeyBytes);

    try {
      // Upload to server with auth credential (+ retry on UNAUTHORIZED)
      await this.withAuthRetry(groupIdHex, (auth) =>
        this.server.createGroup(secretParams.groupId, serialized, auth)
      );
    } catch (err) {
      // Clean up orphan master key — server doesn't have this group
      await this.store.deleteMasterKey(groupIdHex);
      throw err;
    }

    // Creation is C9's first-baseline path. Cache only the exact canonical
    // version-zero state the server signed, never the optimistic submission.
    const snapshot = await this.withAuthRetry(groupIdHex, (auth) =>
      this.server.getGroup(secretParams.groupId, auth, 0)
    );
    if (!snapshot) {
      throw new Error(
        'GROUP_SNAPSHOT_NOT_FOUND: Server did not return canonical version zero'
      );
    }
    const canonicalState = this.decryptVerifiedSnapshot(secretParams, snapshot);
    await this.store.storeGroupState(groupIdHex, canonicalState);

    return { groupId, masterKey: masterKeyBytes };
  }

  // =========================================================================
  // State Retrieval
  // =========================================================================

  /**
   * Get the decrypted group state.
   *
   * Returns cached state if available, otherwise fetches from server.
   *
   * @param groupId - Group identifier
   * @returns Decrypted group state
   */
  async getGroupState(groupId: GroupId): Promise<DecryptedGroup> {
    const rawId = extractGroupId(groupId);

    // Try cache first
    const cached = await this.store.getGroupState(rawId);
    if (cached) return cached;

    // Fetch from server
    return this.syncGroup(groupId);
  }

  /**
   * Sync group state from server.
   *
   * Fetches the latest state or change log and applies updates.
   *
   * @param groupId - Group identifier
   * @returns Updated decrypted group state
   */
  async syncGroup(groupId: GroupId): Promise<DecryptedGroup> {
    const rawId = extractGroupId(groupId);
    await this.retryPendingSenderKeyRotation(groupId);
    const secretParams = await this.getSecretParams(rawId);

    // Check current cached revision
    const cached = await this.store.getGroupState(rawId);
    const currentRevision = cached?.revision ?? -1;

    if (currentRevision >= 0) {
      if (!this.isReadableBySelf(cached!)) {
        const baseline = await this.withAuthRetry(rawId, (auth) =>
          this.server.getGroup(secretParams.groupId, auth)
        );
        if (!baseline) {
          throw new Error(`GROUP_NOT_FOUND: Group ${rawId} not found on server`);
        }
        const restored = this.decryptVerifiedSnapshot(secretParams, baseline);
        if (
          restored.revision <= currentRevision ||
          !this.isReadableBySelf(restored)
        ) {
          throw new Error(
            'INVALID_CHANGE_SEQUENCE: Re-entitlement baseline does not follow the revoked span'
          );
        }
        await this.store.storeGroupState(rawId, restored);
        return restored;
      }

      // A pending principal holds an entitlement to the current state, not a
      // tenure: the server refuses them the change log outright, and C1/C3's
      // verified-transition requirement starts at the baseline their
      // acceptance will establish, not at the invitation (S10a). So they
      // catch up the way the reference ecosystem's clients do when the
      // server does not recognize them as a member — a fresh signed
      // snapshot, verified and installed whole.
      if (!isMember(cached!, this.aci.uuid)) {
        let result: GroupSnapshot | null;
        try {
          result = await this.withAuthRetry(rawId, (auth) =>
            this.server.getGroup(secretParams.groupId, auth)
          );
        } catch (error: unknown) {
          if (!GroupManager.isNotReadableRejection(error)) throw error;
          // The invitation this principal held was revoked. Nothing is
          // installed: the cached pending view stays the last verified
          // state, and a later re-invitation serves a fresh snapshot.
          throw new Error(
            'GROUP_ACCESS_REVOKED: Invitation was revoked before it could be accepted'
          );
        }
        if (!result) {
          throw new Error(`GROUP_NOT_FOUND: Group ${rawId} not found on server`);
        }
        const state = this.decryptVerifiedSnapshot(secretParams, result);
        if (state.revision < currentRevision) {
          throw new Error(
            'INVALID_CHANGE_SEQUENCE: Server snapshot regressed behind the verified baseline'
          );
        }
        await this.store.storeGroupState(rawId, state);
        return state;
      }

      // Once a member has a baseline it may advance only through
      // individually verified transitions. A full snapshot must never bypass
      // a bad or missing log entry (C1/C3). The log arrives in pages; each
      // page resumes from the last verified revision, so an aborted sync
      // resumes exactly where the applied prefix ends.
      let state = cached!;
      for (;;) {
        const page = await this.withAuthRetry(rawId, (auth) =>
          this.server.getGroupChanges(secretParams.groupId, state.revision, auth)
        );
        for (const entry of page.entries) {
          state = await this.applyVerifiedChange(rawId, state, entry);
        }
        if (!page.hasMore) break;
        // hasMore with an empty page is a server that claims progress it
        // did not make; looping on it would spin forever, and breaking
        // would report a stale state as current.
        if (page.entries.length === 0) {
          throw new Error(
            'INVALID_CHANGE_SEQUENCE: Server reported more changes but served none'
          );
        }
      }
      if (!this.isReadableBySelf(state)) {
        let baseline: GroupSnapshot | null = null;
        try {
          baseline = await this.withAuthRetry(rawId, (auth) =>
            this.server.getGroup(secretParams.groupId, auth)
          );
        } catch (error: unknown) {
          if (!GroupManager.isNotReadableRejection(error)) throw error;
        }
        if (baseline) {
          const restored = this.decryptVerifiedSnapshot(
            secretParams,
            baseline
          );
          if (
            restored.revision <= state.revision ||
            !this.isReadableBySelf(restored)
          ) {
            throw new Error(
              'INVALID_CHANGE_SEQUENCE: Re-entitlement baseline does not follow the revoked span'
            );
          }
          await this.store.storeGroupState(rawId, restored);
          return restored;
        }
      }
      return state;
    }

    // Full state fetch
    const result = await this.withAuthRetry(rawId, (auth) =>
      this.server.getGroup(secretParams.groupId, auth)
    );
    if (!result) {
      throw new Error(`GROUP_NOT_FOUND: Group ${rawId} not found on server`);
    }

    const state = this.decryptVerifiedSnapshot(secretParams, result);
    await this.store.storeGroupState(rawId, state);
    return state;
  }

  /**
   * Verify, authorize, structurally validate, and apply one server change.
   *
   * This is the only path by which a signed Actions value advances cached
   * state. Each successful prefix is persisted before the next entry is read.
   */
  private async applyVerifiedChange(
    rawGroupId: string,
    state: DecryptedGroup,
    entry: GroupChangeLogEntry,
    options: {
      persist?: boolean;
      react?: boolean;
      stateVisibility?: 'complete' | 'group_join_info';
    } = {}
  ): Promise<DecryptedGroup> {
    if (
      this.serverSigningPublicKey &&
      !serverVerifySignature(
        { signingPublicKey: this.serverSigningPublicKey },
        serializeGroupChangeCommitment(entry.changeEpoch, entry.actions),
        entry.serverSignature
      )
    ) {
      throw new Error('INVALID_SERVER_SIGNATURE: Group change signature verification failed');
    }
    if (
      !Number.isInteger(entry.changeEpoch) ||
      entry.changeEpoch < 0 ||
      entry.changeEpoch > MAX_SUPPORTED_CHANGE_EPOCH
    ) {
      throw new Error(
        `UNSUPPORTED_CHANGE_EPOCH: Maximum ${MAX_SUPPORTED_CHANGE_EPOCH}, got ${entry.changeEpoch}`
      );
    }

    const encrypted = deserializeEncryptedGroupChange(entry.actions);
    try {
      assertValidEncryptedGroupChangeWire(encrypted, 'canonical');
    } catch (error) {
      throw new Error(
        `INVALID_CHANGE: ${
          error instanceof Error ? error.message : 'Signed Actions are malformed'
        }`
      );
    }
    const requiredEpoch = requiredGroupChangeEpoch(encrypted);
    if (entry.changeEpoch !== requiredEpoch) {
      throw new Error(
        `INVALID_CHANGE_EPOCH: Signed epoch ${entry.changeEpoch} does not match required epoch ${requiredEpoch}`
      );
    }
    const secretParams = await this.getSecretParams(rawGroupId);
    if (!encrypted.groupId || !bytesEqual(encrypted.groupId, secretParams.groupId)) {
      throw new Error('GROUP_BINDING_MISMATCH: Signed change names a different group');
    }
    if (encrypted.revision !== state.revision + 1 || entry.version !== encrypted.revision) {
      throw new Error(
        `INVALID_CHANGE_SEQUENCE: Expected ${state.revision + 1}, got Actions ${encrypted.revision} / entry ${entry.version}`
      );
    }

    const change = decryptChangeFields(encrypted, secretParams);
    const authorizationErrors = validateChangeAuthorization(state, change);
    if (authorizationErrors.length > 0) {
      throw new Error(`UNAUTHORIZED_CHANGE: ${authorizationErrors.join(', ')}`);
    }
    const structuralErrors = validateChangeStructure(state, change);
    if (structuralErrors.length > 0) {
      throw new Error(`INVALID_CHANGE: ${structuralErrors.join(', ')}`);
    }

    const nextState = applyGroupChange(state, change);
    if (options.stateVisibility === 'group_join_info') {
      if (
        !this.isRestrictedGroupJoinInfoChange(
          change,
          countGroupChangeActions(encrypted)
        )
      ) {
        throw new Error(
          'INVALID_CHANGE: GroupJoinInfo validation is restricted to one link-join action'
        );
      }
    } else if (!satisfiesLiveGroupAdministratorInvariant(nextState)) {
      throw new Error(
        'INVALID_CHANGE: Every non-terminated group must have at least one administrator'
      );
    }
    if (options.persist !== false) {
      if (this.requiresSenderKeyRotation(change)) {
        await this.store.storeGroupStateWithSenderKeyRotationBarrier(
          rawGroupId,
          nextState
        );
      } else {
        await this.store.storeGroupState(rawGroupId, nextState);
      }
    }
    if (options.react !== false) {
      if (this.requiresSenderKeyRotation(change)) {
        if (options.persist === false) {
          throw new Error(
            'INVALID_GROUP_REACTION: Cannot rotate without a persisted C7 barrier'
          );
        }
        await this.completePendingSenderKeyRotation(
          rawGroupId,
          nextState.revision
        );
      }
      if (this.changesMembership(change)) {
        await this.invalidateEndorsements(rawGroupId);
      }
    }
    return nextState;
  }

  /**
   * Revision 20's two §11 projection-only action surfaces.
   *
   * The normal C6 path evaluates result-state invariants against complete
   * verified state. A prospective link joiner cannot see the member list, so
   * only these additive self-actions may skip predicates that need it.
   */
  private isRestrictedGroupJoinInfoChange(
    change: DecryptedGroupChange,
    actionCount: number
  ): boolean {
    if (actionCount !== 1) return false;
    if (!bytesEqual(change.editorServiceIdBytes, serviceIdBinary(this.aci))) {
      return false;
    }
    if (change.newMembers.length === 1) {
      const member = change.newMembers[0]!;
      return (
        member.role === MemberRole.DEFAULT &&
        bytesEqual(member.aciBytes, this.aci.uuid)
      );
    }
    if (change.newRequestingMembers.length === 1) {
      return bytesEqual(
        change.newRequestingMembers[0]!.aciBytes,
        this.aci.uuid
      );
    }
    return false;
  }

  private changesMembership(
    change: DecryptedGroupChange
  ): boolean {
    return (
      change.newMembers.length > 0 ||
      change.deleteMembers.length > 0 ||
      change.newPendingMembers.length > 0 ||
      change.deletePendingMembers.length > 0 ||
      change.promotePendingMembers.length > 0 ||
      change.promotePendingPniAciMembers.length > 0 ||
      change.newRequestingMembers.length > 0 ||
      change.deleteRequestingMembers.length > 0 ||
      change.promoteRequestingMembers.length > 0 ||
      change.newBannedMembers.length > 0 ||
      change.deleteBannedMembers.length > 0
    );
  }

  private requiresSenderKeyRotation(
    change: DecryptedGroupChange
  ): boolean {
    return (
      change.deleteMembers.length > 0 ||
      change.newBannedMembers.length > 0 ||
      change.terminate === true
    );
  }

  private securityReactionPendingError(
    rawGroupId: string,
    revision: number,
    cause?: unknown
  ): Error {
    const error = new Error(
      `GROUP_CHANGE_ACCEPTED_SECURITY_REACTION_PENDING: Group ${rawGroupId} accepted revision ${revision}, but sender-key rotation remains pending`
    );
    error.name = 'GroupSecurityReactionPendingError';
    if (cause !== undefined) {
      (error as Error & { cause?: unknown }).cause = cause;
    }
    return error;
  }

  private async completePendingSenderKeyRotation(
    rawGroupId: string,
    revision: number
  ): Promise<void> {
    const acceptedState = await this.store.getGroupState(rawGroupId);
    if (!acceptedState || acceptedState.revision < revision) {
      throw this.securityReactionPendingError(rawGroupId, revision);
    }
    if (!this.onSenderKeyRotation) {
      throw this.securityReactionPendingError(rawGroupId, revision);
    }
    try {
      await this.onSenderKeyRotation(createGroupId(rawGroupId));
      await this.store.clearSenderKeyRotationBarrier(rawGroupId, revision);
    } catch (cause) {
      throw this.securityReactionPendingError(
        rawGroupId,
        revision,
        cause
      );
    }
  }

  /**
   * Retry and clear a durable C7 barrier, including after reconstruction.
   */
  async retryPendingSenderKeyRotation(
    groupId: GroupId | string
  ): Promise<void> {
    const rawGroupId = extractGroupId(groupId);
    const revision =
      await this.store.getSenderKeyRotationBarrier(rawGroupId);
    if (revision === null) return;
    await this.completePendingSenderKeyRotation(rawGroupId, revision);
    await this.invalidateEndorsements(rawGroupId);
  }

  /**
   * Enforce C7 rotation readiness and C10 send eligibility.
   */
  async assertGroupSendAllowed(groupId: GroupId | string): Promise<void> {
    const rawGroupId = extractGroupId(groupId);
    const revision =
      await this.store.getSenderKeyRotationBarrier(rawGroupId);
    if (revision !== null) {
      throw new Error(
        `GROUP_SEND_BLOCKED_BY_SECURITY_REACTION: Sender-key rotation is pending for group ${rawGroupId} at accepted revision ${revision}`
      );
    }

    // The durable master key is the local boundary between Group System
    // groups and the pre-existing ad-hoc Sender Keys API. No master key means
    // this manager has no group authorization state to enforce.
    const masterKey = await this.store.getMasterKey(rawGroupId);
    if (masterKey === null) return;

    const state = await this.store.getGroupState(rawGroupId);
    if (state === null) {
      throw new Error(
        `GROUP_SEND_BLOCKED_BY_ELIGIBILITY: Managed group ${rawGroupId} has no verified accepted state`
      );
    }
    if (state.terminated) {
      throw new Error(
        `GROUP_SEND_BLOCKED_BY_ELIGIBILITY: Group ${rawGroupId} is terminated`
      );
    }
    if (!isMember(state, this.aci.uuid)) {
      throw new Error(
        `GROUP_SEND_BLOCKED_BY_ELIGIBILITY: Sender is not a member of group ${rawGroupId}`
      );
    }
    const aciServiceId = serviceIdBinary(this.aci);
    const pniServiceId =
      this.pni === undefined ? undefined : serviceIdBinary(this.pni);
    if (
      isBanned(state, aciServiceId) ||
      (pniServiceId !== undefined && isBanned(state, pniServiceId))
    ) {
      throw new Error(
        `GROUP_SEND_BLOCKED_BY_ELIGIBILITY: Sender is banned from group ${rawGroupId}`
      );
    }
  }

  // =========================================================================
  // Membership Operations
  // =========================================================================

  /**
   * Add a member to the group.
   *
   * @param groupId - Group identifier
   * @param editorAci - ACI of the user performing the action
   * A target with presentation material is added immediately. Otherwise the
   * target is invited without a profile key and presents when accepting.
   */
  async addMember(
    groupId: GroupId,
    editorAci: Uint8Array,
    member: GroupMemberInput
  ): Promise<void> {
    const inputKind = classifyGroupMemberInput(member);
    const rawId = extractGroupId(groupId);
    const state = await this.getGroupState(groupId);

    // Authorization check
    const editorServiceIdBytes = aciToServiceIdBytes(editorAci);
    const change = emptyGroupChange(editorServiceIdBytes, state.revision + 1);
    if (inputKind === 'presented') {
      const presentedMember = member as PresentedGroupMemberInput;
      const assignedRole = member.role ?? MemberRole.DEFAULT;
      if (
        !canPerformAction(state, editorServiceIdBytes, GroupAction.ADD_MEMBER, {
          targetAciBytes: presentedMember.aciBytes,
          assignedRole,
        })
      ) {
        throw new Error('UNAUTHORIZED: Insufficient permissions to add member');
      }
      if (isMember(state, presentedMember.aciBytes)) {
        throw new Error('ALREADY_MEMBER: User is already a group member');
      }
      const targetServiceId = aciToServiceIdBytes(presentedMember.aciBytes);
      if (isBanned(state, targetServiceId)) {
        throw new Error('BANNED_MEMBER: User is banned from this group');
      }
      change.newMembers = [
        {
          aciBytes: presentedMember.aciBytes,
          role: assignedRole,
          profileKey: presentedMember.profileKey,
        },
      ];
      const { profileKeyCredential: proof } = presentedMember;
      const contexts = new Map<string, PresentationContext>([
        [
          bytesToHex(presentedMember.aciBytes),
          {
            credential: proof,
            credentialPublicKey: this.profileKeyCredentialPublicKey,
          },
        ],
      ]);
      await this.submitChange(rawId, state, change, contexts);
      return;
    }

    const invitedMember = member as InvitedGroupMemberInput;
    assertServiceIdBytes(invitedMember.serviceIdBytes);
    if (
      !canPerformAction(
        state,
        editorServiceIdBytes,
        GroupAction.ADD_MEMBER_PENDING_PROFILE_KEY,
        {
          targetServiceIdBytes: invitedMember.serviceIdBytes,
          assignedRole: invitedMember.role ?? MemberRole.DEFAULT,
        }
      )
    ) {
      throw new Error('UNAUTHORIZED: Insufficient permissions to invite member');
    }
    if (isPending(state, invitedMember.serviceIdBytes)) {
      throw new Error('ALREADY_PENDING: User already has an invitation');
    }
    if (isBanned(state, invitedMember.serviceIdBytes)) {
      throw new Error('BANNED_MEMBER: User is banned from this group');
    }
    change.newPendingMembers = [
      {
        serviceIdBytes: invitedMember.serviceIdBytes,
        role: invitedMember.role ?? MemberRole.DEFAULT,
      },
    ];
    await this.submitChange(rawId, state, change);
  }

  /**
   * Accept this client's pending profile-key invitation.
   *
   * The pending entry carries no profile key. Acceptance introduces the
   * client's own profile-key ciphertext together with the mandatory S12
   * presentation, using the PNI-to-ACI promotion when the invitation is
   * keyed by this account's PNI.
   */
  async acceptMemberInvitation(groupId: GroupId): Promise<void> {
    const rawId = extractGroupId(groupId);
    const state = await this.getGroupState(groupId);
    const aciServiceIdBytes = serviceIdBinary(this.aci);
    const pniServiceIdBytes =
      this.pni === undefined ? undefined : serviceIdBinary(this.pni);
    const pendingByPni =
      pniServiceIdBytes === undefined
        ? undefined
        : state.pendingMembers.find((member) =>
            bytesEqual(member.serviceIdBytes, pniServiceIdBytes)
          );
    const pendingByAci = state.pendingMembers.find((member) =>
      bytesEqual(member.serviceIdBytes, aciServiceIdBytes)
    );
    const pending = pendingByPni ?? pendingByAci;
    if (!pending) {
      throw new Error('INVITATION_NOT_FOUND: No pending invitation for this account');
    }
    if (
      pendingByPni &&
      pendingByAci &&
      pendingByPni.role !== pendingByAci.role
    ) {
      throw new Error(
        'INVITATION_ROLE_CONFLICT: ACI and PNI invitations assign different roles; decline one invitation before accepting'
      );
    }

    const change = emptyGroupChange(
      pendingByPni ? pniServiceIdBytes! : aciServiceIdBytes,
      state.revision + 1
    );
    const promoted: DecryptedPendingMemberPromotion = {
      aciBytes: this.aci.uuid,
      profileKey: this.profileKey,
    };
    if (pendingByPni) {
      change.promotePendingPniAciMembers = [
        { ...promoted, pniBytes: this.pni!.uuid },
      ];
    } else {
      change.promotePendingMembers = [promoted];
    }

    const presentationContext = await this.getPresentationContext();
    await this.submitChange(
      rawId,
      state,
      change,
      new Map([[bytesToHex(this.aci.uuid), presentationContext]])
    );
  }

  /**
   * Decline one of this account's pending profile-key invitations.
   *
   * Selecting the ACI invitation is the self-service resolution for a
   * conflicting dual ACI+PNI invitation before accepting the PNI invitation.
   */
  async declineMemberInvitation(
    groupId: GroupId,
    identity: 'aci' | 'pni' = 'aci'
  ): Promise<void> {
    const rawId = extractGroupId(groupId);
    const state = await this.getGroupState(groupId);
    const serviceId =
      identity === 'aci'
        ? this.aci
        : this.pni;
    if (!serviceId) {
      throw new Error(
        'INVITATION_NOT_FOUND: This account has no PNI invitation identity'
      );
    }
    const serviceIdBytes = serviceIdBinary(serviceId);
    const pending = state.pendingMembers.find((member) =>
      bytesEqual(member.serviceIdBytes, serviceIdBytes)
    );
    if (!pending) {
      throw new Error(
        `INVITATION_NOT_FOUND: No pending ${identity.toUpperCase()} invitation for this account`
      );
    }

    const change = emptyGroupChange(serviceIdBytes, state.revision + 1);
    change.deletePendingMembers = [
      {
        serviceIdBytes,
        serviceIdCipherText: pending.serviceIdCipherText,
      },
    ];
    await this.submitChange(rawId, state, change);
  }

  /**
   * Remove a member from the group.
   *
   * Triggers sender key rotation for forward secrecy.
   *
   * @param groupId - Group identifier
   * @param editorAci - ACI of the user performing the action
   * @param targetAci - ACI of the member to remove
   */
  async removeMember(
    groupId: GroupId,
    editorAci: Uint8Array,
    targetAci: Uint8Array
  ): Promise<void> {
    const rawId = extractGroupId(groupId);
    const state = await this.getGroupState(groupId);

    if (
      !canPerformAction(state, aciToServiceIdBytes(editorAci), GroupAction.REMOVE_MEMBER, {
        targetAciBytes: targetAci,
      })
    ) {
      throw new Error('UNAUTHORIZED: Insufficient permissions to remove member');
    }

    if (!isMember(state, targetAci)) {
      throw new Error('NOT_MEMBER: User is not a group member');
    }

    const change = emptyGroupChange(aciToServiceIdBytes(editorAci), state.revision + 1);
    change.deleteMembers = [targetAci];

    await this.submitChange(rawId, state, change);
  }

  /**
   * Leave the group (self-remove).
   *
   * @param groupId - Group identifier
   * @param userAci - ACI of the user leaving
   */
  async leaveGroup(groupId: GroupId, userAci: Uint8Array): Promise<void> {
    await this.removeMember(groupId, userAci, userAci);
  }

  /**
   * Modify a member's role.
   *
   * @param groupId - Group identifier
   * @param editorAci - ACI of the admin performing the action
   * @param targetAci - ACI of the member to modify
   * @param newRole - New role
   */
  async modifyMemberRole(
    groupId: GroupId,
    editorAci: Uint8Array,
    targetAci: Uint8Array,
    newRole: MemberRole
  ): Promise<void> {
    const rawId = extractGroupId(groupId);
    const state = await this.getGroupState(groupId);

    const editorServiceIdBytes = aciToServiceIdBytes(editorAci);
    if (!canPerformAction(state, editorServiceIdBytes, GroupAction.MODIFY_MEMBER_ROLE)) {
      throw new Error('UNAUTHORIZED: Only admins can modify member roles');
    }

    if (!isMember(state, targetAci)) {
      throw new Error('NOT_MEMBER: User is not a group member');
    }

    const change = emptyGroupChange(editorServiceIdBytes, state.revision + 1);
    change.modifyMemberRoles = [{ aciBytes: targetAci, role: newRole }];

    await this.submitChange(rawId, state, change);
  }

  /**
   * Ban a member from the group.
   *
   * Removes the member if present and adds to ban list.
   * Triggers sender key rotation.
   *
   * @param groupId - Group identifier
   * @param editorAci - ACI of the admin
   * @param targetServiceId - ServiceId bytes of the user to ban
   */
  async banMember(
    groupId: GroupId,
    editorAci: Uint8Array,
    targetServiceId: Uint8Array
  ): Promise<void> {
    const rawId = extractGroupId(groupId);
    const state = await this.getGroupState(groupId);
    assertServiceIdBytes(targetServiceId);

    const editorServiceIdBytes = aciToServiceIdBytes(editorAci);
    if (!canPerformAction(state, editorServiceIdBytes, GroupAction.BAN_MEMBER)) {
      throw new Error('UNAUTHORIZED: Only admins can ban members');
    }

    const change = emptyGroupChange(editorServiceIdBytes, state.revision + 1);

    // Only an ACI principal can occupy the full-member list.
    if (targetServiceId[0] === SERVICE_ID_ACI) {
      const targetAci = targetServiceId.slice(1);
      if (isMember(state, targetAci)) {
        change.deleteMembers = [targetAci];
      }
    }

    change.newBannedMembers = [{ serviceIdBytes: targetServiceId }];

    await this.submitChange(rawId, state, change);
  }

  // =========================================================================
  // Attribute Updates
  // =========================================================================

  /**
   * Apply a single attribute change to a group.
   *
   * Handles the common pattern: load state, check permissions, create change,
   * apply mutation, submit to server.
   */
  private async applyAttributeChange(
    groupId: GroupId,
    editorAci: Uint8Array,
    action: GroupAction,
    mutate: (change: DecryptedGroupChange) => void
  ): Promise<void> {
    const rawId = extractGroupId(groupId);
    const state = await this.getGroupState(groupId);
    const editorServiceIdBytes = aciToServiceIdBytes(editorAci);
    if (!canPerformAction(state, editorServiceIdBytes, action)) {
      throw new Error(`UNAUTHORIZED: Cannot perform ${action} — insufficient permissions`);
    }
    const change = emptyGroupChange(editorServiceIdBytes, state.revision + 1);
    mutate(change);
    await this.submitChange(rawId, state, change);
  }

  /**
   * Update the group title.
   */
  async updateTitle(groupId: GroupId, editorAci: Uint8Array, title: string): Promise<void> {
    await this.applyAttributeChange(groupId, editorAci, GroupAction.MODIFY_TITLE, (change) => {
      change.newTitle = { value: title };
    });
  }

  /**
   * Update the group description.
   */
  async updateDescription(
    groupId: GroupId,
    editorAci: Uint8Array,
    description: string
  ): Promise<void> {
    await this.applyAttributeChange(
      groupId,
      editorAci,
      GroupAction.MODIFY_DESCRIPTION,
      (change) => {
        change.newDescription = { value: description };
      }
    );
  }

  /**
   * Update the disappearing messages timer.
   */
  async updateDisappearingMessagesTimer(
    groupId: GroupId,
    editorAci: Uint8Array,
    duration: number
  ): Promise<void> {
    await this.applyAttributeChange(
      groupId,
      editorAci,
      GroupAction.MODIFY_DISAPPEARING_MESSAGES,
      (change) => {
        change.newTimer = { duration };
      }
    );
  }

  /**
   * Update access control settings.
   */
  async updateAccessControl(
    groupId: GroupId,
    editorAci: Uint8Array,
    updates: Partial<AccessControl>
  ): Promise<void> {
    const rawId = extractGroupId(groupId);
    const state = await this.getGroupState(groupId);

    // All access control changes require admin
    const actions = [
      updates.attributes !== undefined && GroupAction.MODIFY_ATTRIBUTES_ACCESS,
      updates.members !== undefined && GroupAction.MODIFY_MEMBERS_ACCESS,
      updates.addFromInviteLink !== undefined && GroupAction.MODIFY_INVITE_LINK_ACCESS,
      updates.memberLabel !== undefined && GroupAction.MODIFY_MEMBER_LABEL_ACCESS,
    ].filter(Boolean) as GroupAction[];

    for (const action of actions) {
      if (!canPerformAction(state, aciToServiceIdBytes(editorAci), action)) {
        throw new Error('UNAUTHORIZED: Only admins can modify access control');
      }
    }

    const change = emptyGroupChange(aciToServiceIdBytes(editorAci), state.revision + 1);
    if (updates.attributes !== undefined) {
      change.newAttributeAccess = updates.attributes;
    }
    if (updates.members !== undefined) {
      change.newMemberAccess = updates.members;
    }
    if (updates.addFromInviteLink !== undefined) {
      change.newInviteLinkAccess = updates.addFromInviteLink;
    }
    if (updates.memberLabel !== undefined) {
      change.newMemberLabelAccess = updates.memberLabel;
    }

    await this.submitChange(rawId, state, change);
  }

  /**
   * Toggle announcement-only mode.
   */
  async setAnnouncementMode(
    groupId: GroupId,
    editorAci: Uint8Array,
    enabled: boolean
  ): Promise<void> {
    await this.applyAttributeChange(
      groupId,
      editorAci,
      GroupAction.MODIFY_ANNOUNCEMENTS,
      (change) => {
        change.newIsAnnouncementGroup = enabled ? EnabledState.ENABLED : EnabledState.DISABLED;
      }
    );
  }

  /**
   * Permanently terminate a group.
   *
   * Termination is an administrator-only, irreversible state transition and
   * triggers sender-key rotation through the verified-change reaction path.
   */
  async terminateGroup(groupId: GroupId, editorAci: Uint8Array): Promise<void> {
    await this.applyAttributeChange(
      groupId,
      editorAci,
      GroupAction.TERMINATE_GROUP,
      (change) => {
        change.terminate = true;
      }
    );
  }

  // =========================================================================
  // Invite Links
  // =========================================================================

  /**
   * Create an invite link for the group.
   *
   * @param groupId - Group identifier
   * @param editorAci - ACI of the admin
   * @returns The invite link URL
   */
  async createInviteLink(groupId: GroupId, editorAci: Uint8Array): Promise<string> {
    const rawId = extractGroupId(groupId);
    const state = await this.getGroupState(groupId);

    if (
      !canPerformAction(
        state,
        aciToServiceIdBytes(editorAci),
        GroupAction.MODIFY_INVITE_LINK_PASSWORD
      )
    ) {
      throw new Error('UNAUTHORIZED: Only admins can create invite links');
    }

    const masterKeyBytes = await this.store.getMasterKey(rawId);
    if (!masterKeyBytes) {
      throw new Error('MASTER_KEY_NOT_FOUND: No master key for group');
    }

    const password = generateInviteLinkPassword();

    // Update group state with new invite link password
    // editorServiceIdBytes must be 17 bytes (1 byte kind + 16 byte UUID)
    const editorServiceIdBytes = aciToServiceIdBytes(editorAci);
    const change = emptyGroupChange(editorServiceIdBytes, state.revision + 1);
    change.newInviteLinkPassword = password;
    // Enable invite link access if not already
    if (state.accessControl.addFromInviteLink === AccessRequired.UNSATISFIABLE) {
      change.newInviteLinkAccess = AccessRequired.ANY;
    }

    await this.submitChange(rawId, state, change);

    return createGroupInviteLink(masterKeyBytes, password);
  }

  /**
   * Join a group via invite link.
   *
   * When `addFromInviteLink` is `AccessRequired.ADMINISTRATOR`, the user is
   * added to `requestingMembers` instead of `members`, requiring admin approval.
   *
   * @param url - Invite link URL
   * @param userAci - ACI of the joining user
   * @param userProfileKey - Profile key of the joining user
   * @returns GroupId and join status ('joined' or 'pending_approval')
   */
  async joinViaInviteLink(
    url: string,
    userAci: Uint8Array,
    userProfileKey: Uint8Array
  ): Promise<{ groupId: GroupId; status: 'joined' | 'pending_approval' }> {
    if (!bytesEqual(userAci, this.aci.uuid)) {
      throw new Error('INVALID_JOIN_PRINCIPAL: Join target must match the authenticated ACI');
    }
    const parsed = parseGroupInviteLink(url);
    if (!parsed) {
      throw new Error('INVALID_INVITE_LINK: Could not parse invite link');
    }

    const mk = groupMasterKey(parsed.masterKey);
    const secretParams = deriveGroupSecretParams(mk);
    const groupIdHex = bytesToHex(secretParams.groupId);
    const groupIdPrefixed = createGroupId(groupIdHex);

    // Store master key locally (needed for getAuthorization)
    await this.store.storeMasterKey(groupIdHex, parsed.masterKey);
    const cachedBaseline = await this.store.getGroupState(groupIdHex);

    // A non-member receives only the reduced projection. The password is
    // independently checked here and again with the eventual submission
    // (S10/S11).
    const result = await this.withAuthRetry(groupIdHex, (auth) =>
      this.server.getGroupJoinInfo(secretParams.groupId, parsed.inviteLinkPassword, auth)
    );
    if (!result) {
      throw new Error('GROUP_NOT_FOUND: Group no longer exists');
    }

    const encryptedJoinInfo = deserializeEncryptedGroupJoinInfo(result.encryptedJoinInfo);
    const joinInfo = decryptGroupJoinInfo(secretParams, encryptedJoinInfo);
    const expectedPublicParams = serializeGroupPublicParams(
      getGroupPublicParams(secretParams)
    );
    if (!bytesEqual(joinInfo.publicKey, expectedPublicParams)) {
      throw new Error(
        'GROUP_BINDING_MISMATCH: Join-info public parameters do not match invite'
      );
    }
    if (joinInfo.revision !== result.version) {
      throw new Error(
        `INVALID_CHANGE_SEQUENCE: Join info is ${joinInfo.revision}, response is ${result.version}`
      );
    }

    // An existing request is enough to read its own pending status even after
    // link rotation or disablement. It does not grant access to full state.
    if (joinInfo.pendingAdminApproval) {
      return { groupId: groupIdPrefixed, status: 'pending_approval' };
    }

    // Validate invite link access is enabled for a new request.
    if (
      joinInfo.addFromInviteLink === AccessRequired.UNSATISFIABLE ||
      joinInfo.addFromInviteLink === AccessRequired.UNKNOWN
    ) {
      throw new Error('INVITE_LINK_DISABLED: Invite links are disabled');
    }

    const decryptBoundSnapshot = (
      snapshot: GroupSnapshot,
      expectedVersion?: number
    ): DecryptedGroup => {
      if (expectedVersion !== undefined && snapshot.version !== expectedVersion) {
        throw new Error(
          `INVALID_CHANGE_SEQUENCE: Expected snapshot ${expectedVersion}, got ${snapshot.version}`
        );
      }
      return this.decryptVerifiedSnapshot(secretParams, snapshot);
    };

    // Preserve idempotency without exposing member lists to non-members. The
    // server either returns a full state because the authenticated requester is
    // already readable under S10, or rejects with FORBIDDEN and the link flow
    // continues using only GroupJoinInfo.
    let readableResult: GroupSnapshot | null = null;
    try {
      readableResult = await this.withAuthRetry(groupIdHex, (auth) =>
        this.server.getGroup(secretParams.groupId, auth)
      );
    } catch (error: unknown) {
      if (!GroupManager.isNotReadableRejection(error)) throw error;
    }
    if (readableResult) {
      const readableState = decryptBoundSnapshot(readableResult);
      if (isMember(readableState, userAci)) {
        if (!cachedBaseline) {
          await this.store.storeGroupState(groupIdHex, readableState);
          return { groupId: groupIdPrefixed, status: 'joined' };
        }

        if (!this.isReadableBySelf(cachedBaseline)) {
          if (readableState.revision <= cachedBaseline.revision) {
            throw new Error(
              'INVALID_CHANGE_SEQUENCE: Re-entitlement baseline does not follow the revoked span'
            );
          }
          await this.store.storeGroupState(groupIdHex, readableState);
          return { groupId: groupIdPrefixed, status: 'joined' };
        }

        const synced = await this.syncGroup(groupIdPrefixed);
        if (synced.revision < readableState.revision) {
          if (this.isReadableBySelf(synced)) {
            throw new Error(
              'INVALID_CHANGE_SEQUENCE: Snapshot cannot bridge living group history'
            );
          }
          await this.store.storeGroupState(groupIdHex, readableState);
          return { groupId: groupIdPrefixed, status: 'joined' };
        }
        if (!isMember(synced, userAci)) {
          throw new Error(
            'INVALID_GROUP_STATE: Idempotent join no longer has member status'
          );
        }
        return { groupId: groupIdPrefixed, status: 'joined' };
      }
    }

    // Check group capacity
    if (joinInfo.memberCount >= MAX_GROUP_SIZE) {
      throw new Error(
        `GROUP_FULL: Group has reached maximum capacity of ${MAX_GROUP_SIZE} members`
      );
    }

    // This intentionally contains no member list. It is sufficient for the
    // state-decidable half of link-join authorization and for validating the
    // self-add transition without exposing existing membership (S10).
    const state: DecryptedGroup = {
      title: joinInfo.title,
      avatar: joinInfo.avatar,
      disappearingMessagesTimer: { duration: 0 },
      accessControl: {
        ...defaultAccessControl(),
        addFromInviteLink: joinInfo.addFromInviteLink,
      },
      revision: joinInfo.revision,
      members: [],
      pendingMembers: [],
      requestingMembers: [],
      inviteLinkPassword: new Uint8Array(0),
      description: joinInfo.description,
      isAnnouncementGroup: EnabledState.DISABLED,
      bannedMembers: [],
      terminated: false,
    };

    // editorServiceIdBytes must be 17 bytes (1 byte kind + 16 byte UUID)
    const editorServiceIdBytes = aciToServiceIdBytes(userAci);
    const change = emptyGroupChange(editorServiceIdBytes, state.revision + 1);
    const presentationCtx = await this.getPresentationContext();
    const memberContexts = new Map<string, PresentationContext>([
      [bytesToHex(userAci), presentationCtx],
    ]);

    // Admin approval path: add to requestingMembers instead of members
    if (joinInfo.addFromInviteLink === AccessRequired.ADMINISTRATOR) {
      change.newRequestingMembers = [
        {
          aciBytes: userAci,
          profileKey: userProfileKey,
        },
      ];

      const actions = encryptAndSerializeChange(change, secretParams, memberContexts);
      const entry = await this.withAuthRetry(groupIdHex, (auth) =>
        this.server.submitGroupChange(
          secretParams.groupId,
          state.revision,
          actions,
          parsed.inviteLinkPassword,
          auth
        )
      );
      await this.applyVerifiedChange(groupIdHex, state, entry, {
        persist: false,
        react: false,
        stateVisibility: 'group_join_info',
      });
      await this.invalidateEndorsements(groupIdHex);
      return { groupId: groupIdPrefixed, status: 'pending_approval' };
    }
    if (joinInfo.addFromInviteLink !== AccessRequired.ANY) {
      throw new Error(`INVITE_LINK_DISABLED: Unsupported invite-link mode`);
    }

    // Direct join path: add self as member
    change.newMembers = [
      {
        aciBytes: userAci,
        role: MemberRole.DEFAULT,
        profileKey: userProfileKey,
      },
    ];

    const actions = encryptAndSerializeChange(change, secretParams, memberContexts);
    const entry = await this.withAuthRetry(groupIdHex, (auth) =>
      this.server.submitGroupChange(
        secretParams.groupId,
        state.revision,
        actions,
        parsed.inviteLinkPassword,
        auth
      )
    );
    await this.applyVerifiedChange(groupIdHex, state, entry, {
      persist: false,
      react: false,
      stateVisibility: 'group_join_info',
    });

    if (cachedBaseline && this.isReadableBySelf(cachedBaseline)) {
      const synced = await this.syncGroup(groupIdPrefixed);
      if (isMember(synced, userAci)) {
        await this.invalidateEndorsements(groupIdHex);
        return { groupId: groupIdPrefixed, status: 'joined' };
      }
      if (this.isReadableBySelf(synced)) {
        throw new Error(
          'INVALID_CHANGE_SEQUENCE: Snapshot cannot bridge living group history'
        );
      }
      if (entry.version <= synced.revision) {
        throw new Error(
          'INVALID_CHANGE_SEQUENCE: Re-entitlement baseline does not follow the revoked span'
        );
      }
      // S10 intentionally stops a stale reader at its own revoking
      // transition. The accepted, signed rejoin establishes a new entitlement
      // boundary, so continue below and install that exact accepted snapshot
      // as the new baseline.
    } else if (cachedBaseline && entry.version <= cachedBaseline.revision) {
      throw new Error(
        'INVALID_CHANGE_SEQUENCE: Re-entitlement baseline does not follow the revoked span'
      );
    }

    // The accepted, signed self-add makes the requester a member. Only now may
    // the client request the full state. Fetch the exact historical version
    // established by that verified transition so a concurrent later mutation
    // cannot force an unverified snapshot jump.
    let fullResult: GroupSnapshot | null;
    try {
      fullResult = await this.withAuthRetry(groupIdHex, (auth) =>
        this.server.getGroup(secretParams.groupId, auth, entry.version)
      );
    } catch (error: unknown) {
      // This is a *versioned* read, so a 403 can carry three answers.
      // `not_readable` is revocation outright. `not_a_member` means the
      // membership the accepted self-add just established is already gone —
      // the requester is at most pending again, so the join was revoked
      // between acceptance and this read. `before_join` is the one benign
      // 403 here: the engine raises it only for a requester holding a live
      // tenure whose floor sits above the requested version, and
      // translating that into GROUP_ACCESS_REVOKED would report a live
      // member as removed — so it, like every unreasoned rejection,
      // propagates untranslated.
      const reason = GroupManager.forbiddenReason(error);
      if (reason !== 'not_readable' && reason !== 'not_a_member') throw error;
      // The join was accepted and signed, then revoked before this read: the
      // server authorizes reads at the current state, and the current state
      // no longer lists us. Surface the revocation instead of claiming a
      // membership we can neither read nor verify — no state is installed,
      // and from here this principal is the ordinary re-entitlement case: a
      // later re-add or approval serves a fresh signed baseline.
      throw new Error(
        'GROUP_ACCESS_REVOKED: Join was accepted, then revoked before its baseline could be read'
      );
    }
    if (!fullResult) {
      throw new Error(
        `GROUP_SNAPSHOT_NOT_FOUND: Accepted join snapshot ${entry.version} is unavailable`
      );
    }
    const joinedState = decryptBoundSnapshot(fullResult, entry.version);
    if (!isMember(joinedState, userAci)) {
      throw new Error('INVALID_GROUP_SNAPSHOT: Accepted join is absent from returned state');
    }
    await this.store.storeGroupState(groupIdHex, joinedState);
    await this.invalidateEndorsements(groupIdHex);

    return { groupId: groupIdPrefixed, status: 'joined' };
  }

  // =========================================================================
  // Internal helpers
  // =========================================================================

  /**
   * Whether a server rejection means "you may not read this group at all".
   *
   * Only the `not_readable` FORBIDDEN carries that meaning — it is what the
   * server raises when the requester is banned or absent from the
   * authorizing roster, and it is the sole rejection a client may interpret
   * as revocation. The same code with reason `before_join` is the
   * join-version floor: it refuses one historical version while saying
   * nothing about current access, so treating it as revocation would
   * mistranslate a live membership into "revoked". Anything else (bad
   * presentation, malformed request) is not an access answer at all.
   */
  private static isNotReadableRejection(error: unknown): boolean {
    return GroupManager.forbiddenReason(error) === 'not_readable';
  }

  /** The FORBIDDEN reason a server rejection carries, if any. */
  private static forbiddenReason(error: unknown): string | undefined {
    const data =
      error != null && typeof error === 'object' && 'data' in error
        ? (error as { data?: { code?: string; reason?: string } }).data
        : undefined;
    return data?.code === 'FORBIDDEN' ? data.reason : undefined;
  }

  /** Whether this client's verified local span still carries full-state read access. */
  private isReadableBySelf(state: DecryptedGroup): boolean {
    const aciServiceId = serviceIdBinary(this.aci);
    const pniServiceId =
      this.pni === undefined ? undefined : serviceIdBinary(this.pni);
    if (
      isBanned(state, aciServiceId) ||
      (pniServiceId !== undefined && isBanned(state, pniServiceId))
    ) {
      return false;
    }
    return (
      isMember(state, this.aci.uuid) ||
      isPending(state, aciServiceId) ||
      (pniServiceId !== undefined && isPending(state, pniServiceId))
    );
  }

  /** Verify the S14 commitment before parsing or installing a snapshot. */
  private verifyBaselineSignature(
    groupId: Uint8Array,
    snapshot: GroupSnapshot
  ): void {
    if (
      this.serverSigningPublicKey &&
      !serverVerifySignature(
        { signingPublicKey: this.serverSigningPublicKey },
        serializeGroupBaseline(
          groupId,
          snapshot.version,
          snapshot.encryptedState
        ),
        snapshot.baselineSignature
      )
    ) {
      throw new Error(
        'INVALID_SERVER_SIGNATURE: Group baseline signature verification failed'
      );
    }
  }

  /** Verify, bind, and decrypt one canonical full-state response. */
  private decryptVerifiedSnapshot(
    secretParams: GroupSecretParams,
    snapshot: GroupSnapshot
  ): DecryptedGroup {
    this.verifyBaselineSignature(secretParams.groupId, snapshot);
    const encryptedState = deserializeEncryptedGroup(snapshot.encryptedState);
    try {
      assertValidEncryptedGroupWire(encryptedState);
    } catch (error) {
      throw new Error(
        `INVALID_GROUP_SNAPSHOT: ${
          error instanceof Error ? error.message : 'Encrypted state is malformed'
        }`
      );
    }
    const expectedPublicParams = serializeGroupPublicParams(
      getGroupPublicParams(secretParams)
    );
    if (!bytesEqual(encryptedState.publicKey, expectedPublicParams)) {
      throw new Error(
        'GROUP_BINDING_MISMATCH: Snapshot public parameters do not match group'
      );
    }
    if (encryptedState.version !== snapshot.version) {
      throw new Error(
        `INVALID_CHANGE_SEQUENCE: Snapshot is ${encryptedState.version}, response is ${snapshot.version}`
      );
    }
    const state = decryptGroupState(secretParams, encryptedState);
    if (state.revision !== snapshot.version) {
      throw new Error(
        `INVALID_GROUP_SNAPSHOT: State revision ${state.revision} does not match ${snapshot.version}`
      );
    }
    return state;
  }

  /**
   * Get GroupSecretParams for a group from stored master key.
   */
  private async getSecretParams(rawGroupId: string): Promise<GroupSecretParams> {
    const masterKeyBytes = await this.store.getMasterKey(rawGroupId);
    if (!masterKeyBytes) {
      throw new Error(`MASTER_KEY_NOT_FOUND: No master key for group ${rawGroupId}`);
    }
    const mk = groupMasterKey(masterKeyBytes);
    return deriveGroupSecretParams(mk);
  }

  /**
   * Submit a change to the server and update local state.
   *
   * @param memberPresentationContexts - Optional presentation contexts for members
   *   being added. Keyed by ACI hex. The reference implementation always includes a presentation when
   *   adding a full member (AddMemberAction, PromotePending, etc.).
   */
  private async submitChange(
    rawGroupId: string,
    currentState: DecryptedGroup,
    change: DecryptedGroupChange,
    memberPresentationContexts?: ReadonlyMap<string, PresentationContext>
  ): Promise<void> {
    const MAX_VERSION_CONFLICT_RETRIES = 3;

    let state = currentState;
    for (let attempt = 0; attempt <= MAX_VERSION_CONFLICT_RETRIES; attempt++) {
      const editorServiceIdBytes =
        this.actionNamedSourceServiceId(change) ??
        this.sourceServiceIdForState(state);
      // Re-base the change onto the current state revision
      const rebasedChange = {
        ...change,
        editorServiceIdBytes,
        revision: state.revision + 1,
      };

      // Authorization and structural validity are deliberately independent.
      const authorizationErrors = validateChangeAuthorization(state, rebasedChange);
      if (authorizationErrors.length > 0) {
        throw new Error(`UNAUTHORIZED_CHANGE: ${authorizationErrors.join(', ')}`);
      }
      const structuralErrors = validateChangeStructure(
        state,
        rebasedChange,
        'submission'
      );
      if (structuralErrors.length > 0) {
        throw new Error(`INVALID_CHANGE: ${structuralErrors.join(', ')}`);
      }

      // The server applies ciphertext actions to its own pre-change state.
      // Sending a client-computed replacement snapshot would make S4/S5
      // enforcement meaningless.
      const secretParams = await this.getSecretParams(rawGroupId);
      const actions = encryptAndSerializeChange(
        rebasedChange,
        secretParams,
        memberPresentationContexts
      );

      try {
        const entry = await this.withAuthRetry(rawGroupId, (auth) =>
          this.server.submitGroupChange(
            secretParams.groupId,
            state.revision,
            actions,
            new Uint8Array(0),
            auth
          )
        );

        await this.applyVerifiedChange(rawGroupId, state, entry);
        return;
      } catch (err: unknown) {
        const conflictData =
          err != null && typeof err === 'object' && 'data' in err
            ? (err as { data?: { code?: string } }).data
            : undefined;

        // Detect VERSION_CONFLICT from ConvexError structured data
        const isVersionConflict = conflictData?.code === 'VERSION_CONFLICT';

        if (!isVersionConflict || attempt === MAX_VERSION_CONFLICT_RETRIES) {
          throw err;
        }

        // Re-sync group state from server and retry
        const groupId = createGroupId(rawGroupId);
        state = await this.syncGroup(groupId);
      }
    }
  }

  /**
   * Mirror S3's action-named attribution before falling back to state lookup.
   *
   * A self-targeted pending delete exercises the named alias, as does a
   * PNI-to-ACI promotion. One accepted change may exercise only one alias.
   */
  private actionNamedSourceServiceId(
    change: DecryptedGroupChange
  ): Uint8Array | undefined {
    const aciServiceId = serviceIdBinary(this.aci);
    const pniServiceId =
      this.pni === undefined ? undefined : serviceIdBinary(this.pni);
    const candidates: Uint8Array[] = [];
    const addCandidate = (candidate: Uint8Array): void => {
      if (!candidates.some((current) => bytesEqual(current, candidate))) {
        candidates.push(candidate);
      }
    };

    for (const promotion of change.promotePendingPniAciMembers) {
      if (
        pniServiceId !== undefined &&
        bytesEqual(promotion.pniBytes, this.pni!.uuid)
      ) {
        addCandidate(pniServiceId);
      }
    }
    for (const removal of change.deletePendingMembers) {
      if (bytesEqual(removal.serviceIdBytes, aciServiceId)) {
        addCandidate(aciServiceId);
      } else if (
        pniServiceId !== undefined &&
        bytesEqual(removal.serviceIdBytes, pniServiceId)
      ) {
        addCandidate(pniServiceId);
      }
    }
    if (
      change.deleteRequestingMembers.some((target) =>
        bytesEqual(target, this.aci.uuid)
      )
    ) {
      addCandidate(aciServiceId);
    }

    if (candidates.length > 1) {
      throw new Error(
        'AMBIGUOUS_CHANGE_ATTRIBUTION: A change cannot exercise self-rights under multiple aliases'
      );
    }
    return candidates[0];
  }

  /**
   * Mirror S3's deterministic pre-state attribution for ordinary actions.
   *
   * ACI wins when both aliases occur in state; a PNI-only pending invitee is
   * attributed to that PNI so self-decline remains possible.
   */
  private sourceServiceIdForState(state: DecryptedGroup): Uint8Array {
    const aciServiceId = serviceIdBinary(this.aci);
    const aciMatches =
      isMember(state, this.aci.uuid) ||
      isPending(state, aciServiceId) ||
      state.requestingMembers.some((member) =>
        bytesEqual(member.aciBytes, this.aci.uuid)
      );
    if (aciMatches || this.pni === undefined) return aciServiceId;

    const pniServiceId = serviceIdBinary(this.pni);
    return isPending(state, pniServiceId)
      ? pniServiceId
      : aciServiceId;
  }
}

/**
 * Encrypt and serialize a DecryptedGroupChange for server submission.
 *
 * The client deliberately leaves sourceUserId and groupId unset. A conforming
 * server derives and sets both before signing the accepted Actions.
 */
export function encryptAndSerializeChange(
  change: DecryptedGroupChange,
  secretParams: GroupSecretParams,
  memberPresentationContexts?: ReadonlyMap<string, PresentationContext>
): Uint8Array {
  const errors = [
    ...validateChangeIdentifiers(change),
    ...validateChangeAccessControl(change),
    ...validateChangeMemberRoles(change),
  ];
  if (errors.length > 0) {
    throw new Error(`INVALID_CHANGE: ${errors.join('; ')}`);
  }
  if (!Number.isSafeInteger(change.revision) || change.revision < 1) {
    throw new Error(
      'INVALID_CHANGE: change revision must be a positive safe integer'
    );
  }
  if (
    change.newIsAnnouncementGroup !== undefined &&
    change.newIsAnnouncementGroup !== EnabledState.ENABLED &&
    change.newIsAnnouncementGroup !== EnabledState.DISABLED
  ) {
    throw new Error(
      'INVALID_CHANGE: newIsAnnouncementGroup is outside its §7.8 domain'
    );
  }
  const { newInviteLinkPassword: actionPw } = change;
  if (
    actionPw !== undefined &&
    actionPw.length !== 16
  ) {
    throw new Error(
      'INVALID_CHANGE: newInviteLinkPassword must be exactly 16 bytes'
    );
  }
  const encrypted = encryptChangeFields(
    change,
    secretParams,
    memberPresentationContexts
  );
  assertEncryptedGroupChangeForm(encrypted, 'submission');
  return serializeEncryptedGroupChange(encrypted);
}

/**
 * Deserialize and decrypt a change from server.
 *
 * Restores JSON from bytes, then decrypts identity fields back to plaintext.
 */
export function deserializeAndDecryptChange(
  bytes: Uint8Array,
  secretParams: GroupSecretParams
): DecryptedGroupChange {
  return decryptChangeFields(deserializeEncryptedGroupChange(bytes), secretParams);
}

// ---------------------------------------------------------------------------
// Change field encryption helpers
// ---------------------------------------------------------------------------

/** Encrypt a 16-byte ACI as a UuidCiphertext. */
function encryptAci(secretParams: GroupSecretParams, aciBytes: Uint8Array): Uint8Array {
  const serviceId: ServiceId = { kind: SERVICE_ID_ACI, uuid: aciBytes };
  return encryptUuid(secretParams, serviceId);
}

/** Encrypt a 17-byte ServiceId (kind + uuid) as a UuidCiphertext. */
function encryptServiceIdBytes(
  secretParams: GroupSecretParams,
  serviceIdBytes: Uint8Array
): Uint8Array {
  if (serviceIdBytes.length !== 17) {
    throw new Error(`ServiceIdBytes must be 17 bytes, got ${serviceIdBytes.length}`);
  }
  const kind = serviceIdBytes[0];
  if (kind !== SERVICE_ID_ACI && kind !== SERVICE_ID_PNI) {
    throw new Error(`Invalid ServiceId kind byte: 0x${kind.toString(16).padStart(2, '0')}`);
  }
  const serviceId: ServiceId = { kind, uuid: serviceIdBytes.slice(1) };
  return encryptUuid(secretParams, serviceId);
}

/** Decrypt a UuidCiphertext back to 16-byte ACI UUID. */
function decryptAci(secretParams: GroupSecretParams, ciphertext: Uint8Array): Uint8Array {
  const serviceId = decryptUuid(secretParams, ciphertext);
  if (serviceId.kind !== SERVICE_ID_ACI) {
    throw new Error(`Expected ACI service ID, got kind ${serviceId.kind}`);
  }
  return serviceId.uuid;
}

/** Decrypt a UuidCiphertext back to 17-byte ServiceId binary. */
function decryptServiceIdBytes(
  secretParams: GroupSecretParams,
  ciphertext: Uint8Array
): Uint8Array {
  const serviceId = decryptUuid(secretParams, ciphertext);
  return serviceIdBinary(serviceId);
}

function decryptQuarantinableServiceId(
  secretParams: GroupSecretParams,
  ciphertext: Uint8Array,
  requiredKind?: typeof SERVICE_ID_ACI | typeof SERVICE_ID_PNI
): Uint8Array | undefined {
  let serviceId: ServiceId;
  try {
    serviceId = decryptUuid(secretParams, ciphertext);
  } catch {
    return undefined;
  }
  if (requiredKind !== undefined && serviceId.kind !== requiredKind) {
    throw new Error(
      `Expected service ID kind ${requiredKind}, got ${serviceId.kind}`
    );
  }
  return isNilUuid(serviceId.uuid)
    ? undefined
    : serviceIdBinary(serviceId);
}

// ---------------------------------------------------------------------------
// Member-level encryption/decryption for change actions
// ---------------------------------------------------------------------------

function encryptProfileKeyActionFields(
  secretParams: GroupSecretParams,
  member: { aciBytes: Uint8Array; profileKey: Uint8Array },
  presentationContext?: PresentationContext
): EncryptedChangeProfileKeyUpdate {
  const encryptedMember = encryptMember(
    secretParams,
    {
      ...member,
      role: MemberRole.DEFAULT,
      joinedAtRevision: 0,
      pniBytes: new Uint8Array(0),
      labelEmoji: '',
      labelString: '',
    },
    presentationContext
  );
  return {
    aciCiphertext: encryptedMember.userId,
    profileKeyCiphertext: encryptedMember.profileKey,
    presentation: encryptedMember.presentation,
  };
}

function decryptProfileKeyActionFields(
  secretParams: GroupSecretParams,
  member: EncryptedChangeProfileKeyUpdate
): DecryptedProfileKeyUpdate {
  const aciBytes = decryptAci(secretParams, member.aciCiphertext);
  return {
    aciBytes,
    profileKey: decryptProfileKeyCiphertext(
      secretParams,
      member.profileKeyCiphertext,
      aciBytes
    ),
  };
}

function encryptChangeAddMember(
  secretParams: GroupSecretParams,
  member: DecryptedAddMember,
  presentationContext?: PresentationContext
): EncryptedChangeAddMember {
  return {
    ...encryptProfileKeyActionFields(
      secretParams,
      member,
      presentationContext
    ),
    role: member.role,
    ...(member.joinedAtRevision === undefined
      ? {}
      : { joinedAtRevision: member.joinedAtRevision }),
  };
}

function decryptChangeAddMember(
  secretParams: GroupSecretParams,
  member: EncryptedChangeAddMember
): DecryptedAddMember {
  return {
    ...decryptProfileKeyActionFields(secretParams, member),
    role: member.role,
    ...(member.joinedAtRevision === undefined
      ? {}
      : { joinedAtRevision: member.joinedAtRevision }),
  };
}

function encryptChangePendingPromotion(
  secretParams: GroupSecretParams,
  member: DecryptedPendingMemberPromotion,
  presentationContext?: PresentationContext
): EncryptedChangePendingMemberPromotion {
  return {
    ...encryptProfileKeyActionFields(
      secretParams,
      member,
      presentationContext
    ),
    ...(member.role === undefined ? {} : { role: member.role }),
    ...(member.joinedAtRevision === undefined
      ? {}
      : { joinedAtRevision: member.joinedAtRevision }),
  };
}

function decryptChangePendingPromotion(
  secretParams: GroupSecretParams,
  member: EncryptedChangePendingMemberPromotion
): DecryptedPendingMemberPromotion {
  return {
    ...decryptProfileKeyActionFields(secretParams, member),
    ...(member.role === undefined ? {} : { role: member.role }),
    ...(member.joinedAtRevision === undefined
      ? {}
      : { joinedAtRevision: member.joinedAtRevision }),
  };
}

function encryptChangePniAciPromotion(
  secretParams: GroupSecretParams,
  member: DecryptedPniAciMemberPromotion,
  presentationContext?: PresentationContext
): EncryptedChangePniAciMemberPromotion {
  return {
    ...encryptChangePendingPromotion(
      secretParams,
      member,
      presentationContext
    ),
    pniCiphertext: encryptUuid(secretParams, {
      kind: SERVICE_ID_PNI,
      uuid: member.pniBytes,
    }),
  };
}

function decryptChangePniAciPromotion(
  secretParams: GroupSecretParams,
  member: EncryptedChangePniAciMemberPromotion
): DecryptedPniAciMemberPromotion {
  const pni = decryptUuid(secretParams, member.pniCiphertext);
  if (pni.kind !== SERVICE_ID_PNI) {
    throw new Error(`Expected PNI service ID, got kind ${pni.kind}`);
  }
  return {
    ...decryptChangePendingPromotion(secretParams, member),
    pniBytes: pni.uuid,
  };
}

function encryptChangePendingMember(
  secretParams: GroupSecretParams,
  pending: DecryptedAddPendingMember
): EncryptedChangePendingMember {
  if (pending.quarantined === true) {
    throw new Error(
      'INVALID_CHANGE: Quarantined pending entries cannot be submitted'
    );
  }
  return {
    serviceIdCiphertext: encryptServiceIdBytes(
      secretParams,
      pending.serviceIdBytes
    ),
    role: pending.role,
    ...(pending.addedByAci === undefined
      ? {}
      : { addedByAciCiphertext: encryptAci(secretParams, pending.addedByAci) }),
    ...(pending.timestamp === undefined ? {} : { timestamp: pending.timestamp }),
  };
}

function decryptChangePendingMember(
  secretParams: GroupSecretParams,
  pending: EncryptedChangePendingMember
): DecryptedAddPendingMember {
  const serviceIdBytes = decryptQuarantinableServiceId(
    secretParams,
    pending.serviceIdCiphertext
  );
  return {
    serviceIdBytes: serviceIdBytes ?? new Uint8Array(0),
    role: pending.role,
    ...(pending.addedByAciCiphertext === undefined
      ? {}
      : {
          addedByAci: decryptAci(
            secretParams,
            pending.addedByAciCiphertext
          ),
        }),
    ...(pending.timestamp === undefined ? {} : { timestamp: pending.timestamp }),
    // Preserve ciphertext for re-encryption on removal
    serviceIdCipherText: new Uint8Array(pending.serviceIdCiphertext),
    ...(serviceIdBytes === undefined ? { quarantined: true } : {}),
  };
}

function encryptChangePendingMemberRemoval(
  secretParams: GroupSecretParams,
  removal: DecryptedPendingMemberRemoval
): EncryptedChangePendingMemberRemoval {
  // Use the preserved ciphertext if available; otherwise encrypt from plaintext
  if (removal.serviceIdCipherText.length > 0) {
    return { serviceIdCiphertext: removal.serviceIdCipherText };
  }
  return {
    serviceIdCiphertext: encryptServiceIdBytes(secretParams, removal.serviceIdBytes),
  };
}

function decryptChangePendingMemberRemoval(
  secretParams: GroupSecretParams,
  removal: EncryptedChangePendingMemberRemoval
): DecryptedPendingMemberRemoval {
  const serviceIdBytes = decryptQuarantinableServiceId(
    secretParams,
    removal.serviceIdCiphertext
  );
  return {
    serviceIdBytes: serviceIdBytes ?? new Uint8Array(0),
    serviceIdCipherText: new Uint8Array(removal.serviceIdCiphertext),
  };
}

function encryptChangeRequestingMember(
  secretParams: GroupSecretParams,
  member: DecryptedAddRequestingMember,
  presentationContext?: PresentationContext
): EncryptedChangeRequestingMember {
  if (member.quarantined === true) {
    throw new Error(
      'INVALID_CHANGE: Quarantined requesting entries cannot be submitted'
    );
  }
  const encryptedMember = encryptProfileKeyActionFields(
    secretParams,
    member,
    presentationContext
  );
  return {
    aciCiphertext: encryptedMember.aciCiphertext,
    profileKeyCiphertext: encryptedMember.profileKeyCiphertext,
    presentation: encryptedMember.presentation,
    ...(member.timestamp === undefined ? {} : { timestamp: member.timestamp }),
  };
}

function decryptChangeRequestingMember(
  secretParams: GroupSecretParams,
  member: EncryptedChangeRequestingMember
): DecryptedAddRequestingMember {
  const serviceIdBytes = decryptQuarantinableServiceId(
    secretParams,
    member.aciCiphertext,
    SERVICE_ID_ACI
  );
  if (serviceIdBytes === undefined) {
    return {
      aciBytes: new Uint8Array(0),
      profileKey: new Uint8Array(0),
      aciCipherText: new Uint8Array(member.aciCiphertext),
      profileKeyCipherText: new Uint8Array(member.profileKeyCiphertext),
      quarantined: true,
      ...(member.timestamp === undefined ? {} : { timestamp: member.timestamp }),
    };
  }
  return {
    ...decryptProfileKeyActionFields(secretParams, member),
    ...(member.timestamp === undefined ? {} : { timestamp: member.timestamp }),
  };
}

function encryptChangeApproveMember(
  secretParams: GroupSecretParams,
  member: DecryptedApproveMember
): EncryptedChangeApproveMember {
  return {
    aciCiphertext: encryptAci(secretParams, member.aciBytes),
    role: member.role,
  };
}

function decryptChangeApproveMember(
  secretParams: GroupSecretParams,
  member: EncryptedChangeApproveMember
): DecryptedApproveMember {
  return {
    aciBytes: decryptAci(secretParams, member.aciCiphertext),
    role: member.role,
  };
}

function encryptChangeModifyMemberRole(
  secretParams: GroupSecretParams,
  modify: DecryptedModifyMemberRole
): EncryptedChangeModifyMemberRole {
  return {
    aciCiphertext: encryptAci(secretParams, modify.aciBytes),
    role: modify.role,
  };
}

function decryptChangeModifyMemberRole(
  secretParams: GroupSecretParams,
  modify: EncryptedChangeModifyMemberRole
): DecryptedModifyMemberRole {
  return {
    aciBytes: decryptAci(secretParams, modify.aciCiphertext),
    role: modify.role,
  };
}

function encryptChangeBannedMember(
  secretParams: GroupSecretParams,
  member: DecryptedAddBannedMember
): EncryptedChangeBannedMember {
  if (member.quarantined === true) {
    throw new Error(
      'INVALID_CHANGE: Quarantined banned entries cannot be submitted'
    );
  }
  return {
    serviceIdCiphertext: encryptServiceIdBytes(
      secretParams,
      member.serviceIdBytes
    ),
    ...(member.timestamp === undefined ? {} : { timestamp: member.timestamp }),
  };
}

function decryptChangeBannedMember(
  secretParams: GroupSecretParams,
  member: EncryptedChangeBannedMember
): DecryptedAddBannedMember {
  const serviceIdBytes = decryptQuarantinableServiceId(
    secretParams,
    member.serviceIdCiphertext
  );
  return {
    serviceIdBytes: serviceIdBytes ?? new Uint8Array(0),
    ...(serviceIdBytes === undefined
      ? {
          serviceIdCipherText: new Uint8Array(member.serviceIdCiphertext),
          quarantined: true as const,
        }
      : {}),
    ...(member.timestamp === undefined ? {} : { timestamp: member.timestamp }),
  };
}

function encryptChangeBannedMemberRemoval(
  secretParams: GroupSecretParams,
  member: DecryptedDeleteBannedMember
): EncryptedChangeBannedMemberRemoval {
  return {
    serviceIdCiphertext:
      member.serviceIdCipherText !== undefined
        ? new Uint8Array(member.serviceIdCipherText)
        : encryptServiceIdBytes(secretParams, member.serviceIdBytes),
  };
}

function decryptChangeBannedMemberRemoval(
  secretParams: GroupSecretParams,
  member: EncryptedChangeBannedMemberRemoval
): DecryptedDeleteBannedMember {
  const serviceIdBytes = decryptQuarantinableServiceId(
    secretParams,
    member.serviceIdCiphertext
  );
  return {
    serviceIdBytes: serviceIdBytes ?? new Uint8Array(0),
    ...(serviceIdBytes === undefined
      ? { serviceIdCipherText: new Uint8Array(member.serviceIdCiphertext) }
      : {}),
  };
}

function encryptChangeModifyMemberLabel(
  secretParams: GroupSecretParams,
  modify: DecryptedModifyMemberLabel
): EncryptedChangeModifyMemberLabel {
  return {
    aciCiphertext: encryptAci(secretParams, modify.aciBytes),
    labelEmojiCiphertext: encryptLabelAsBlob(secretParams, modify.labelEmoji),
    labelStringCiphertext: encryptLabelAsBlob(secretParams, modify.labelString),
  };
}

function decryptChangeModifyMemberLabel(
  secretParams: GroupSecretParams,
  modify: EncryptedChangeModifyMemberLabel
): DecryptedModifyMemberLabel {
  return {
    aciBytes: decryptAci(secretParams, modify.aciCiphertext),
    labelEmoji: decryptLabelFromBlob(secretParams, modify.labelEmojiCiphertext),
    labelString: decryptLabelFromBlob(secretParams, modify.labelStringCiphertext),
  };
}

// ---------------------------------------------------------------------------
// Top-level change encryption/decryption
// ---------------------------------------------------------------------------

/**
 * Encrypt all identity fields in a DecryptedGroupChange.
 *
 * Walks each action type and encrypts ACI, PNI, and profileKey fields
 * using zkgroup primitives. Public policy and sequencing fields pass through.
 */
function encryptChangeFields(
  change: DecryptedGroupChange,
  secretParams: GroupSecretParams,
  memberPresentationContexts?: ReadonlyMap<string, PresentationContext>
): EncryptedGroupChange {
  const presentationFor = (aciBytes: Uint8Array): PresentationContext | undefined =>
    memberPresentationContexts?.get(bytesToHex(aciBytes));
  const randomness = (): Uint8Array => crypto.getRandomValues(new Uint8Array(32));

  return {
    revision: change.revision,

    // Membership
    newMembers: change.newMembers.map((m) =>
      encryptChangeAddMember(secretParams, m, presentationFor(m.aciBytes))
    ),
    deleteMembers: change.deleteMembers.map((aci) => encryptAci(secretParams, aci)),
    modifyMemberRoles: change.modifyMemberRoles.map((m) =>
      encryptChangeModifyMemberRole(secretParams, m)
    ),
    modifiedProfileKeys: change.modifiedProfileKeys.map((m) =>
      encryptProfileKeyActionFields(secretParams, m, presentationFor(m.aciBytes))
    ),

    // Pending members
    newPendingMembers: change.newPendingMembers.map((m) =>
      encryptChangePendingMember(secretParams, m)
    ),
    deletePendingMembers: change.deletePendingMembers.map((m) =>
      encryptChangePendingMemberRemoval(secretParams, m)
    ),
    promotePendingMembers: change.promotePendingMembers.map((m) =>
      encryptChangePendingPromotion(
        secretParams,
        m,
        presentationFor(m.aciBytes)
      )
    ),

    // Attributes
    newTitle:
      change.newTitle === undefined
        ? undefined
        : encryptGroupTitle(secretParams, randomness(), change.newTitle.value),
    newAvatar: change.newAvatar,
    newTimer:
      change.newTimer === undefined
        ? undefined
        : encryptDisappearingMessagesTimer(
            secretParams,
            randomness(),
            change.newTimer.duration
          ),

    // Access control (pass through)
    newAttributeAccess: change.newAttributeAccess,
    newMemberAccess: change.newMemberAccess,
    newInviteLinkAccess: change.newInviteLinkAccess,
    newMemberLabelAccess: change.newMemberLabelAccess,

    // Requesting members
    newRequestingMembers: change.newRequestingMembers.map((m) =>
      encryptChangeRequestingMember(secretParams, m, presentationFor(m.aciBytes))
    ),
    deleteRequestingMembers: change.deleteRequestingMembers.map((aciOrCiphertext) =>
      aciOrCiphertext.length === 65
        ? new Uint8Array(aciOrCiphertext)
        : encryptAci(secretParams, aciOrCiphertext)
    ),
    promoteRequestingMembers: change.promoteRequestingMembers.map((m) =>
      encryptChangeApproveMember(secretParams, m)
    ),

    // Invite link (pass through)
    newInviteLinkPassword: change.newInviteLinkPassword,

    // Description
    newDescription:
      change.newDescription === undefined
        ? undefined
        : encryptGroupDescription(secretParams, randomness(), change.newDescription.value),

    // Announcements (pass through)
    newIsAnnouncementGroup: change.newIsAnnouncementGroup,

    // Ban list
    newBannedMembers: change.newBannedMembers.map((m) =>
      encryptChangeBannedMember(secretParams, m)
    ),
    deleteBannedMembers: change.deleteBannedMembers.map((m) =>
      encryptChangeBannedMemberRemoval(secretParams, m)
    ),

    // PNI-ACI promotion
    promotePendingPniAciMembers: change.promotePendingPniAciMembers.map((m) =>
      encryptChangePniAciPromotion(
        secretParams,
        m,
        presentationFor(m.aciBytes)
      )
    ),

    // Labels
    modifyMemberLabels: change.modifyMemberLabels.map((m) =>
      encryptChangeModifyMemberLabel(secretParams, m)
    ),

    terminate: change.terminate,
  };
}

/**
 * Decrypt all identity fields in an EncryptedGroupChange.
 *
 * Reverses the encryption performed by encryptChangeFields().
 */
function decryptChangeFields(
  encrypted: EncryptedGroupChange,
  secretParams: GroupSecretParams
): DecryptedGroupChange {
  if (!encrypted.sourceUserId) {
    throw new Error('INVALID_CHANGE: Signed Actions are missing server-set sourceUserId');
  }
  const change: DecryptedGroupChange = {
    editorServiceIdBytes: decryptServiceIdBytes(secretParams, encrypted.sourceUserId),
    revision: encrypted.revision,

    // Membership
    newMembers: encrypted.newMembers.map((m) =>
      decryptChangeAddMember(secretParams, m)
    ),
    deleteMembers: encrypted.deleteMembers.map((ct) => decryptAci(secretParams, ct)),
    modifyMemberRoles: encrypted.modifyMemberRoles.map((m) =>
      decryptChangeModifyMemberRole(secretParams, m)
    ),
    modifiedProfileKeys: encrypted.modifiedProfileKeys.map((m) =>
      decryptProfileKeyActionFields(secretParams, m)
    ),

    // Pending members
    newPendingMembers: encrypted.newPendingMembers.map((m) =>
      decryptChangePendingMember(secretParams, m)
    ),
    deletePendingMembers: encrypted.deletePendingMembers.map((m) =>
      decryptChangePendingMemberRemoval(secretParams, m)
    ),
    promotePendingMembers: encrypted.promotePendingMembers.map((m) =>
      decryptChangePendingPromotion(secretParams, m)
    ),

    // Attributes
    newTitle:
      encrypted.newTitle === undefined
        ? undefined
        : { value: decryptGroupTitle(secretParams, encrypted.newTitle) },
    newAvatar: encrypted.newAvatar,
    newTimer:
      encrypted.newTimer === undefined
        ? undefined
        : decryptDisappearingMessagesTimer(secretParams, encrypted.newTimer),

    // Access control (pass through)
    newAttributeAccess: encrypted.newAttributeAccess,
    newMemberAccess: encrypted.newMemberAccess,
    newInviteLinkAccess: encrypted.newInviteLinkAccess,
    newMemberLabelAccess: encrypted.newMemberLabelAccess,

    // Requesting members
    newRequestingMembers: encrypted.newRequestingMembers.map((m) =>
      decryptChangeRequestingMember(secretParams, m)
    ),
    deleteRequestingMembers: encrypted.deleteRequestingMembers.map((ct) => {
      const serviceIdBytes = decryptQuarantinableServiceId(
        secretParams,
        ct,
        SERVICE_ID_ACI
      );
      return serviceIdBytes === undefined
        ? new Uint8Array(ct)
        : serviceIdBytes.subarray(1);
    }),
    promoteRequestingMembers: encrypted.promoteRequestingMembers.map((m) =>
      decryptChangeApproveMember(secretParams, m)
    ),

    // Invite link (pass through)
    newInviteLinkPassword: encrypted.newInviteLinkPassword,

    // Description
    newDescription:
      encrypted.newDescription === undefined
        ? undefined
        : { value: decryptGroupDescription(secretParams, encrypted.newDescription) },

    // Announcements (pass through)
    newIsAnnouncementGroup: encrypted.newIsAnnouncementGroup,

    // Ban list
    newBannedMembers: encrypted.newBannedMembers.map((m) =>
      decryptChangeBannedMember(secretParams, m)
    ),
    deleteBannedMembers: encrypted.deleteBannedMembers.map((m) =>
      decryptChangeBannedMemberRemoval(secretParams, m)
    ),

    // PNI-ACI promotion
    promotePendingPniAciMembers: encrypted.promotePendingPniAciMembers.map((m) =>
      decryptChangePniAciPromotion(secretParams, m)
    ),

    // Labels
    modifyMemberLabels: encrypted.modifyMemberLabels.map((m) =>
      decryptChangeModifyMemberLabel(secretParams, m)
    ),

    terminate: encrypted.terminate,
  };
  const identifierErrors = validateChangeIdentifiers(change);
  if (identifierErrors.length > 0) {
    throw new Error(`INVALID_CHANGE: ${identifierErrors.join('; ')}`);
  }
  return change;
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

/**
 * Convert a 16-byte ACI UUID to a 17-byte ServiceId binary (ACI kind prefix + UUID).
 *
 * Used for `editorServiceIdBytes` in DecryptedGroupChange, which requires
 * the full ServiceId format for encryption.
 */
function aciToServiceIdBytes(aciBytes: Uint8Array): Uint8Array {
  if (aciBytes.length !== 16) {
    throw new Error(`ACI must be 16 bytes, got ${aciBytes.length}`);
  }
  const sid = new Uint8Array(17);
  sid[0] = SERVICE_ID_ACI;
  sid.set(aciBytes, 1);
  return sid;
}

function assertServiceIdBytes(serviceIdBytes: Uint8Array): void {
  if (serviceIdBytes.length !== 17) {
    throw new Error(`ServiceId must be 17 bytes, got ${serviceIdBytes.length}`);
  }
  if (serviceIdBytes[0] !== SERVICE_ID_ACI && serviceIdBytes[0] !== SERVICE_ID_PNI) {
    throw new Error(`Invalid ServiceId kind: ${serviceIdBytes[0]}`);
  }
}
