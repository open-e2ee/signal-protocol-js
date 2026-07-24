/**
 * GroupsV2 Manager
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
 * @module groups-v2/manager
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
  encryptProfileKeyCiphertext,
  decryptProfileKeyCiphertext,
} from '../protocol/zk/groups';

import {
  type DecryptedGroup,
  type DecryptedMember,
  type DecryptedGroupChange,
  type DecryptedPendingMember,
  type DecryptedPendingMemberRemoval,
  type DecryptedRequestingMember,
  type DecryptedBannedMember,
  type DecryptedApproveMember,
  type DecryptedModifyMemberRole,
  type DecryptedModifyMemberLabel,
  type EncryptedGroup,
  type EncryptedGroupChange,
  type EncryptedChangeMember,
  type EncryptedChangePendingMember,
  type EncryptedChangePendingMemberRemoval,
  type EncryptedChangeRequestingMember,
  type EncryptedChangeBannedMember,
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

import { encryptGroupState, decryptGroupState } from './encrypted-state';
import { applyGroupChange, validateChange } from './change-actions';
import { canPerformAction, GroupAction, isMember, isBanned } from './access-control';
import {
  createGroupInviteLink,
  parseGroupInviteLink,
  generateInviteLinkPassword,
} from './invite-link';
import type { GroupId } from '../groups/group-id';
import { createGroupId, extractGroupId } from '../groups/group-id';
import { constantTimeEqual as bytesEqual } from '../crypto/utils';
import { bytesToHex, hexToBytes } from '../../encoding/hex';
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
  /** Get cached decrypted group state. */
  getGroupState(groupId: string): Promise<DecryptedGroup | null>;
  /** Delete cached group state. */
  deleteGroupState(groupId: string): Promise<void>;
}

/**
 * Interface for server-side group operations.
 *
 * The server stores encrypted (opaque) group state and enforces
 * version sequencing. It never decrypts group content.
 */
export interface IGroupServer {
  /** Create a new group on the server. */
  createGroup(
    groupId: Uint8Array,
    encryptedState: Uint8Array,
    authorization: GroupAuthorization
  ): Promise<void>;

  /** Get the latest encrypted group state. */
  getGroup(
    groupId: Uint8Array,
    authorization: GroupAuthorization
  ): Promise<{ encryptedState: Uint8Array; version: number } | null>;

  /** Get change log entries from a given version. */
  getGroupChanges(
    groupId: Uint8Array,
    fromVersion: number,
    authorization: GroupAuthorization
  ): Promise<GroupChangeLogEntry[]>;

  /** Submit a group change (optimistic concurrency). */
  submitGroupChange(
    groupId: Uint8Array,
    expectedVersion: number,
    encryptedChange: Uint8Array,
    updatedEncryptedState: Uint8Array,
    authorization: GroupAuthorization
  ): Promise<{ serverSignature: Uint8Array }>;
}

/** A single change log entry from the server. */
export interface GroupChangeLogEntry {
  version: number;
  encryptedChange: Uint8Array;
  serverSignature: Uint8Array;
  timestamp: number;
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

export interface GroupsV2ManagerOptions {
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
  /** User's ACI for credential presentation. */
  aci: ServiceId;
  /** User's PNI for credential presentation (optional — nil UUID used for non-phone apps). */
  pni?: ServiceId;
  /** Issue a fresh profile key credential from the server. Returns serialized response. */
  issueProfileKeyCredential?: () => Promise<Uint8Array>;
  /** Server's profile key credential public key. */
  profileKeyCredentialPublicKey?: CredentialPublicKey;
  /** User's 32-byte profile key for profile key credential. */
  profileKey?: Uint8Array;
}

// ---------------------------------------------------------------------------
// GroupsV2Manager
// ---------------------------------------------------------------------------

/**
 * Manages GroupsV2 lifecycle and state.
 *
 * This is the primary entry point for group operations. It coordinates
 * between crypto primitives, storage, and server communication.
 */
/** Default maximum group size enforced by the manager. */
export const MAX_GROUP_SIZE = 1000;

export class GroupsV2Manager {
  private readonly store: IGroupStateStore;
  private readonly server: IGroupServer;
  private readonly onSenderKeyRotation?: OnSenderKeyRotation;
  private readonly onEndorsementsInvalidated?: OnEndorsementsInvalidated;
  private readonly issueCredential: () => Promise<Uint8Array>;
  private readonly credentialPublicKey: CredentialPublicKey;
  private readonly aci: ServiceId;
  private readonly pni: ServiceId;
  private readonly issueProfileKeyCredentialFn?: () => Promise<Uint8Array>;
  private readonly profileKeyCredentialPublicKey?: CredentialPublicKey;
  private readonly profileKey?: Uint8Array;
  private cachedCredential: { redemptionTime: number; credential: AuthCredentialWithPni } | null =
    null;
  private cachedProfileKeyCredential: {
    redemptionTime: number;
    credential: ExpiringProfileKeyCredential;
  } | null = null;
  /** Serializes credential fetches to prevent duplicate network requests. */
  private readonly credentialLock = new AsyncLock();

  constructor(options: GroupsV2ManagerOptions) {
    this.store = options.store;
    this.server = options.server;
    this.onSenderKeyRotation = options.onSenderKeyRotation;
    this.onEndorsementsInvalidated = options.onEndorsementsInvalidated;
    this.issueCredential = options.issueCredential;
    this.credentialPublicKey = options.credentialPublicKey;
    this.aci = options.aci;
    // Nil PNI for non-phone apps — credential math only needs consistency between issuance and reception
    this.pni = options.pni ?? { kind: SERVICE_ID_PNI, uuid: new Uint8Array(16) };
    this.issueProfileKeyCredentialFn = options.issueProfileKeyCredential;
    this.profileKeyCredentialPublicKey = options.profileKeyCredentialPublicKey;
    this.profileKey = options.profileKey;
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
   * Returns a PresentationContext if profile key credentials are configured,
   * otherwise undefined.
   */
  private async getPresentationContext(): Promise<PresentationContext | undefined> {
    if (
      !this.issueProfileKeyCredentialFn ||
      !this.profileKeyCredentialPublicKey ||
      !this.profileKey
    ) {
      return undefined;
    }

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
   * @see Signal Private Group System (eprint 2019/1416) Section 4.3
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
   * @param members - Additional members to add (ACI + profile key + role)
   * @param title - Group title
   * @param options - Optional settings (description, access control, avatar, timer)
   * @returns GroupId and master key
   */
  async createGroup(
    creatorAci: Uint8Array,
    creatorProfileKey: Uint8Array,
    members: Array<{
      aciBytes: Uint8Array;
      profileKey: Uint8Array;
      role?: MemberRole;
    }>,
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

    const additionalMembers: DecryptedMember[] = members.map((m) => ({
      aciBytes: m.aciBytes,
      role: m.role ?? MemberRole.DEFAULT,
      profileKey: m.profileKey,
      joinedAtRevision: 0,
      pniBytes: new Uint8Array(0),
      labelEmoji: '',
      labelString: '',
    }));

    const initialState: DecryptedGroup = {
      title,
      avatar: options?.avatarUrl ?? '',
      disappearingMessagesTimer: {
        duration: options?.disappearingMessagesDuration ?? 0,
      },
      accessControl: ac,
      revision: 0,
      members: [creatorMember, ...additionalMembers],
      pendingMembers: [],
      requestingMembers: [],
      inviteLinkPassword: new Uint8Array(0),
      description: options?.description ?? '',
      isAnnouncementGroup: EnabledState.DISABLED,
      bannedMembers: [],
    };

    // Get presentation context for the creator's member entry
    const presentationCtx = await this.getPresentationContext();
    const memberContexts = new Map<string, PresentationContext>();
    if (presentationCtx) {
      const creatorAciHex = Array.from(creatorAci)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
      memberContexts.set(creatorAciHex, presentationCtx);
    }

    // Encrypt the initial state
    const encryptedState = encryptGroupState(
      secretParams,
      initialState,
      memberContexts.size > 0 ? memberContexts : undefined
    );

    // Serialize encrypted state for server storage
    const serialized = serializeEncryptedGroup(encryptedState);

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

    // Store local state (only after server confirms group exists)
    await this.store.storeGroupState(groupIdHex, initialState);

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
    const secretParams = await this.getSecretParams(rawId);

    // Check current cached revision
    const cached = await this.store.getGroupState(rawId);
    const currentRevision = cached?.revision ?? -1;

    if (currentRevision >= 0) {
      // Try incremental sync via change log
      const changes = await this.withAuthRetry(rawId, (auth) =>
        this.server.getGroupChanges(secretParams.groupId, currentRevision, auth)
      );

      if (changes.length > 0) {
        let state = cached!;
        let membershipChanged = false;
        for (const entry of changes) {
          const decryptedChange = deserializeAndDecryptChange(entry.encryptedChange, secretParams);
          const errors = validateChange(state, decryptedChange);
          if (errors.length > 0) {
            // Skip invalid changes (server may have sent stale data)
            continue;
          }
          // Detect membership changes that invalidate endorsements
          if (
            decryptedChange.newMembers.length > 0 ||
            decryptedChange.deleteMembers.length > 0 ||
            decryptedChange.promotePendingMembers.length > 0 ||
            decryptedChange.promoteRequestingMembers.length > 0 ||
            decryptedChange.newBannedMembers.length > 0 ||
            decryptedChange.promotePendingPniAciMembers.length > 0
          ) {
            membershipChanged = true;
          }
          state = applyGroupChange(state, decryptedChange);
        }
        await this.store.storeGroupState(rawId, state);

        // Invalidate endorsement cache if membership changed during sync
        if (membershipChanged) {
          await this.invalidateEndorsements(rawId);
        }

        return state;
      }
    }

    // Full state fetch
    const result = await this.withAuthRetry(rawId, (auth) =>
      this.server.getGroup(secretParams.groupId, auth)
    );
    if (!result) {
      throw new Error(`GROUP_NOT_FOUND: Group ${rawId} not found on server`);
    }

    const encryptedState = deserializeEncryptedGroup(result.encryptedState);
    const state = decryptGroupState(secretParams, encryptedState);
    await this.store.storeGroupState(rawId, state);
    return state;
  }

  // =========================================================================
  // Membership Operations
  // =========================================================================

  /**
   * Add a member to the group.
   *
   * @param groupId - Group identifier
   * @param editorAci - ACI of the user performing the action
   * @param newMemberAci - ACI of the new member
   * @param newMemberProfileKey - Profile key of the new member
   * @param role - Role for the new member (default: DEFAULT)
   */
  async addMember(
    groupId: GroupId,
    editorAci: Uint8Array,
    newMemberAci: Uint8Array,
    newMemberProfileKey: Uint8Array,
    role: MemberRole = MemberRole.DEFAULT
  ): Promise<void> {
    const rawId = extractGroupId(groupId);
    const state = await this.getGroupState(groupId);

    // Authorization check
    if (!canPerformAction(state, editorAci, GroupAction.ADD_MEMBER)) {
      throw new Error('UNAUTHORIZED: Insufficient permissions to add member');
    }

    // Check if already a member or banned
    if (isMember(state, newMemberAci)) {
      throw new Error('ALREADY_MEMBER: User is already a group member');
    }
    if (isBanned(state, newMemberAci)) {
      throw new Error('BANNED_MEMBER: User is banned from this group');
    }

    const change = emptyGroupChange(editorAci, state.revision + 1);
    change.newMembers = [
      {
        aciBytes: newMemberAci,
        role,
        profileKey: newMemberProfileKey,
        joinedAtRevision: state.revision + 1,
        pniBytes: new Uint8Array(0),
        labelEmoji: '',
        labelString: '',
      },
    ];

    await this.submitChange(rawId, state, change);

    // Invalidate endorsement cache — new member needs fresh endorsements
    await this.invalidateEndorsements(rawId);
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

    // Self-leave: any member can leave
    const isSelfLeave = bytesEqual(editorAci, targetAci);
    if (!isSelfLeave) {
      // Remove others: need permission
      if (!canPerformAction(state, editorAci, GroupAction.REMOVE_MEMBER)) {
        throw new Error('UNAUTHORIZED: Insufficient permissions to remove member');
      }
    }

    if (!isMember(state, targetAci)) {
      throw new Error('NOT_MEMBER: User is not a group member');
    }

    const change = emptyGroupChange(editorAci, state.revision + 1);
    change.deleteMembers = [targetAci];

    await this.submitChange(rawId, state, change);

    // Trigger sender key rotation for forward secrecy
    if (this.onSenderKeyRotation) {
      await this.onSenderKeyRotation(groupId);
    }

    // Invalidate endorsement cache — removed member's endorsement is stale
    await this.invalidateEndorsements(rawId);
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

    if (!canPerformAction(state, editorAci, GroupAction.MODIFY_MEMBER_ROLE)) {
      throw new Error('UNAUTHORIZED: Only admins can modify member roles');
    }

    if (!isMember(state, targetAci)) {
      throw new Error('NOT_MEMBER: User is not a group member');
    }

    const change = emptyGroupChange(editorAci, state.revision + 1);
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

    if (!canPerformAction(state, editorAci, GroupAction.BAN_MEMBER)) {
      throw new Error('UNAUTHORIZED: Only admins can ban members');
    }

    const change = emptyGroupChange(editorAci, state.revision + 1);

    // Remove from members if present (extract ACI from ServiceId)
    const targetAci = targetServiceId.length === 17 ? targetServiceId.slice(1) : targetServiceId;
    if (isMember(state, targetAci)) {
      change.deleteMembers = [targetAci];
    }

    change.newBannedMembers = [{ serviceIdBytes: targetServiceId, timestamp: Date.now() }];

    await this.submitChange(rawId, state, change);

    // Trigger sender key rotation
    if (this.onSenderKeyRotation) {
      await this.onSenderKeyRotation(groupId);
    }

    // Invalidate endorsement cache — banned member's endorsement is stale
    await this.invalidateEndorsements(rawId);
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
    if (!canPerformAction(state, editorAci, action)) {
      throw new Error(`UNAUTHORIZED: Cannot perform ${action} — insufficient permissions`);
    }
    const change = emptyGroupChange(editorAci, state.revision + 1);
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
    ].filter(Boolean) as GroupAction[];

    for (const action of actions) {
      if (!canPerformAction(state, editorAci, action)) {
        throw new Error('UNAUTHORIZED: Only admins can modify access control');
      }
    }

    const change = emptyGroupChange(editorAci, state.revision + 1);
    if (updates.attributes !== undefined) {
      change.newAttributeAccess = updates.attributes;
    }
    if (updates.members !== undefined) {
      change.newMemberAccess = updates.members;
    }
    if (updates.addFromInviteLink !== undefined) {
      change.newInviteLinkAccess = updates.addFromInviteLink;
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

    if (!canPerformAction(state, editorAci, GroupAction.MODIFY_INVITE_LINK_PASSWORD)) {
      throw new Error('UNAUTHORIZED: Only admins can create invite links');
    }

    const masterKeyBytes = await this.store.getMasterKey(rawId);
    if (!masterKeyBytes) {
      throw new Error('MASTER_KEY_NOT_FOUND: No master key for group');
    }

    const password = generateInviteLinkPassword();

    // Update group state with new invite link password
    // editorServiceIdBytes must be 17 bytes (1 byte kind + 16 byte UUID)
    const editorServiceIdBytes =
      editorAci.length === 17 ? editorAci : aciToServiceIdBytes(editorAci);
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

    // Fetch current state to validate invite link
    const result = await this.withAuthRetry(groupIdHex, (auth) =>
      this.server.getGroup(secretParams.groupId, auth)
    );
    if (!result) {
      throw new Error('GROUP_NOT_FOUND: Group no longer exists');
    }

    const encryptedState = deserializeEncryptedGroup(result.encryptedState);
    const state = decryptGroupState(secretParams, encryptedState);

    // Validate invite link access is enabled
    if (state.accessControl.addFromInviteLink === AccessRequired.UNSATISFIABLE) {
      throw new Error('INVITE_LINK_DISABLED: Invite links are disabled');
    }

    // Validate invite link password
    if (!bytesEqual(state.inviteLinkPassword, parsed.inviteLinkPassword)) {
      throw new Error('INVALID_INVITE_PASSWORD: Invite link password mismatch');
    }

    // Check if banned
    if (isBanned(state, userAci)) {
      throw new Error('BANNED: User is banned from this group');
    }

    // Check if already a member
    if (isMember(state, userAci)) {
      await this.store.storeGroupState(groupIdHex, state);
      return { groupId: groupIdPrefixed, status: 'joined' };
    }

    // Check group capacity
    if (state.members.length >= MAX_GROUP_SIZE) {
      throw new Error(
        `GROUP_FULL: Group has reached maximum capacity of ${MAX_GROUP_SIZE} members`
      );
    }

    // editorServiceIdBytes must be 17 bytes (1 byte kind + 16 byte UUID)
    const editorServiceIdBytes = aciToServiceIdBytes(userAci);
    const change = emptyGroupChange(editorServiceIdBytes, state.revision + 1);

    // Admin approval path: add to requestingMembers instead of members
    if (state.accessControl.addFromInviteLink === AccessRequired.ADMINISTRATOR) {
      change.newRequestingMembers = [
        {
          aciBytes: userAci,
          profileKey: userProfileKey,
          timestamp: Date.now(),
        },
      ];

      // Submit to server first (server is source of truth)
      const newState = applyGroupChange(state, change);
      const encryptedChange = encryptAndSerializeChange(change, secretParams);
      const updatedState = encryptGroupState(secretParams, newState);
      const updatedEncryptedState = serializeEncryptedGroup(updatedState);

      await this.withAuthRetry(groupIdHex, (auth) =>
        this.server.submitGroupChange(
          secretParams.groupId,
          state.revision,
          encryptedChange,
          updatedEncryptedState,
          auth
        )
      );

      await this.store.storeGroupState(groupIdHex, newState);
      return { groupId: groupIdPrefixed, status: 'pending_approval' };
    }

    // Direct join path: add self as member
    change.newMembers = [
      {
        aciBytes: userAci,
        role: MemberRole.DEFAULT,
        profileKey: userProfileKey,
        joinedAtRevision: state.revision + 1,
        pniBytes: new Uint8Array(0),
        labelEmoji: '',
        labelString: '',
      },
    ];

    // Get self-presentation for the new member entry (Signal always includes
    // a presentation when adding a full member)
    const presentationCtx = await this.getPresentationContext();
    let memberContexts: Map<string, PresentationContext> | undefined;
    if (presentationCtx) {
      memberContexts = new Map();
      const aciHex = Array.from(userAci)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
      memberContexts.set(aciHex, presentationCtx);
    }

    // Submit to server first (server is source of truth)
    const newState = applyGroupChange(state, change);
    const encryptedChange = encryptAndSerializeChange(change, secretParams);
    const updatedState = encryptGroupState(secretParams, newState, memberContexts);
    const updatedEncryptedState = serializeEncryptedGroup(updatedState);

    await this.withAuthRetry(groupIdHex, (auth) =>
      this.server.submitGroupChange(
        secretParams.groupId,
        state.revision,
        encryptedChange,
        updatedEncryptedState,
        auth
      )
    );

    // Update local state only after server confirms
    await this.store.storeGroupState(groupIdHex, newState);

    return { groupId: groupIdPrefixed, status: 'joined' };
  }

  // =========================================================================
  // Internal helpers
  // =========================================================================

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
   *   being added. Keyed by ACI hex. Signal always includes a presentation when
   *   adding a full member (AddMemberAction, PromotePending, etc.).
   */
  private async submitChange(
    rawGroupId: string,
    currentState: DecryptedGroup,
    change: DecryptedGroupChange,
    memberPresentationContexts?: Map<string, PresentationContext>
  ): Promise<void> {
    const MAX_VERSION_CONFLICT_RETRIES = 3;

    let state = currentState;
    for (let attempt = 0; attempt <= MAX_VERSION_CONFLICT_RETRIES; attempt++) {
      // Re-base the change onto the current state revision
      const rebasedChange = { ...change, revision: state.revision + 1 };

      // Validate locally first
      const errors = validateChange(state, rebasedChange);
      if (errors.length > 0) {
        throw new Error(`INVALID_CHANGE: ${errors.join(', ')}`);
      }

      // Apply locally
      const newState = applyGroupChange(state, rebasedChange);

      // Encrypt change and updated state for server
      const secretParams = await this.getSecretParams(rawGroupId);
      const encryptedChange = encryptAndSerializeChange(rebasedChange, secretParams);
      const updatedEncState = encryptGroupState(secretParams, newState, memberPresentationContexts);
      const updatedEncryptedState = serializeEncryptedGroup(updatedEncState);

      try {
        await this.withAuthRetry(rawGroupId, (auth) =>
          this.server.submitGroupChange(
            secretParams.groupId,
            state.revision,
            encryptedChange,
            updatedEncryptedState,
            auth
          )
        );

        // Update local cache on success
        await this.store.storeGroupState(rawGroupId, newState);
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
}

// ---------------------------------------------------------------------------
// Serialization helpers
// ---------------------------------------------------------------------------

/**
 * Serialize any object to JSON, converting Uint8Array fields to `{ __bytes: hex }`.
 *
 * This is the single serialization primitive used by all group wire formats.
 * Pairs with {@link deserializeFromJson} for round-trip fidelity.
 */
function serializeToJson(obj: unknown): string {
  return JSON.stringify(obj, (_key, value) => {
    if (value instanceof Uint8Array) {
      return { __bytes: bytesToHex(value) };
    }
    return value;
  });
}

/**
 * Deserialize JSON produced by {@link serializeToJson}, restoring
 * `{ __bytes: hex }` markers back to Uint8Array instances.
 */
function deserializeFromJson<T>(json: string): T {
  return JSON.parse(json, (_key, value) => {
    if (value && typeof value === 'object' && '__bytes' in value) {
      return hexToBytes((value as { __bytes: string }).__bytes);
    }
    return value;
  }) as T;
}

function serializeEncryptedGroup(group: EncryptedGroup): Uint8Array {
  return new TextEncoder().encode(serializeToJson(group));
}

function deserializeEncryptedGroup(bytes: Uint8Array): EncryptedGroup {
  return deserializeFromJson<EncryptedGroup>(new TextDecoder().decode(bytes));
}

/**
 * Encrypt and serialize a DecryptedGroupChange for server submission.
 *
 * Encrypts identity fields (ACI, PNI, profileKey) using zkgroup primitives,
 * then serializes as JSON with hex-encoded binary fields.
 * The server treats the resulting bytes as opaque.
 */
export function encryptAndSerializeChange(
  change: DecryptedGroupChange,
  secretParams: GroupSecretParams
): Uint8Array {
  const encrypted = encryptChangeFields(change, secretParams);
  return new TextEncoder().encode(serializeToJson(encrypted));
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
  const encrypted = deserializeFromJson<EncryptedGroupChange>(new TextDecoder().decode(bytes));
  return decryptChangeFields(encrypted, secretParams);
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

// ---------------------------------------------------------------------------
// Member-level encryption/decryption for change actions
// ---------------------------------------------------------------------------

function encryptChangeMember(
  secretParams: GroupSecretParams,
  member: DecryptedMember
): EncryptedChangeMember {
  const aciCiphertext = encryptAci(secretParams, member.aciBytes);
  const profileKeyCiphertext =
    member.profileKey.length > 0
      ? encryptProfileKeyCiphertext(secretParams, member.profileKey, member.aciBytes)
      : new Uint8Array(0);
  const pniCiphertext =
    member.pniBytes.length > 0
      ? encryptUuid(secretParams, {
          kind: SERVICE_ID_PNI,
          uuid: member.pniBytes,
        })
      : new Uint8Array(0);

  return {
    aciCiphertext,
    role: member.role,
    profileKeyCiphertext,
    joinedAtRevision: member.joinedAtRevision,
    pniCiphertext,
    labelEmoji: member.labelEmoji,
    labelString: member.labelString,
  };
}

function decryptChangeMember(
  secretParams: GroupSecretParams,
  member: EncryptedChangeMember
): DecryptedMember {
  const aciBytes = decryptAci(secretParams, member.aciCiphertext);
  const profileKey =
    member.profileKeyCiphertext.length > 0
      ? decryptProfileKeyCiphertext(secretParams, member.profileKeyCiphertext, aciBytes)
      : new Uint8Array(0);
  let pniBytes: Uint8Array = new Uint8Array(0);
  if (member.pniCiphertext.length > 0) {
    const pniServiceId = decryptUuid(secretParams, member.pniCiphertext);
    pniBytes = pniServiceId.uuid;
  }

  return {
    aciBytes,
    role: member.role,
    profileKey,
    joinedAtRevision: member.joinedAtRevision,
    pniBytes,
    labelEmoji: member.labelEmoji,
    labelString: member.labelString,
  };
}

function encryptChangePendingMember(
  secretParams: GroupSecretParams,
  pending: DecryptedPendingMember
): EncryptedChangePendingMember {
  return {
    serviceIdCiphertext: encryptServiceIdBytes(secretParams, pending.serviceIdBytes),
    role: pending.role,
    addedByAciCiphertext: encryptAci(secretParams, pending.addedByAci),
    timestamp: pending.timestamp,
  };
}

function decryptChangePendingMember(
  secretParams: GroupSecretParams,
  pending: EncryptedChangePendingMember
): DecryptedPendingMember {
  return {
    serviceIdBytes: decryptServiceIdBytes(secretParams, pending.serviceIdCiphertext),
    role: pending.role,
    addedByAci: decryptAci(secretParams, pending.addedByAciCiphertext),
    timestamp: pending.timestamp,
    // Preserve ciphertext for re-encryption on removal
    serviceIdCipherText: pending.serviceIdCiphertext,
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
  return {
    serviceIdBytes: decryptServiceIdBytes(secretParams, removal.serviceIdCiphertext),
    serviceIdCipherText: removal.serviceIdCiphertext,
  };
}

function encryptChangeRequestingMember(
  secretParams: GroupSecretParams,
  member: DecryptedRequestingMember
): EncryptedChangeRequestingMember {
  return {
    aciCiphertext: encryptAci(secretParams, member.aciBytes),
    profileKeyCiphertext: encryptProfileKeyCiphertext(
      secretParams,
      member.profileKey,
      member.aciBytes
    ),
    timestamp: member.timestamp,
  };
}

function decryptChangeRequestingMember(
  secretParams: GroupSecretParams,
  member: EncryptedChangeRequestingMember
): DecryptedRequestingMember {
  const aciBytes = decryptAci(secretParams, member.aciCiphertext);
  const profileKey = decryptProfileKeyCiphertext(
    secretParams,
    member.profileKeyCiphertext,
    aciBytes
  );
  return { aciBytes, profileKey, timestamp: member.timestamp };
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
  member: DecryptedBannedMember
): EncryptedChangeBannedMember {
  return {
    serviceIdCiphertext: encryptServiceIdBytes(secretParams, member.serviceIdBytes),
    timestamp: member.timestamp,
  };
}

function decryptChangeBannedMember(
  secretParams: GroupSecretParams,
  member: EncryptedChangeBannedMember
): DecryptedBannedMember {
  return {
    serviceIdBytes: decryptServiceIdBytes(secretParams, member.serviceIdCiphertext),
    timestamp: member.timestamp,
  };
}

function encryptChangeModifyMemberLabel(
  secretParams: GroupSecretParams,
  modify: DecryptedModifyMemberLabel
): EncryptedChangeModifyMemberLabel {
  return {
    aciCiphertext: encryptAci(secretParams, modify.aciBytes),
    labelEmoji: modify.labelEmoji,
    labelString: modify.labelString,
  };
}

function decryptChangeModifyMemberLabel(
  secretParams: GroupSecretParams,
  modify: EncryptedChangeModifyMemberLabel
): DecryptedModifyMemberLabel {
  return {
    aciBytes: decryptAci(secretParams, modify.aciCiphertext),
    labelEmoji: modify.labelEmoji,
    labelString: modify.labelString,
  };
}

// ---------------------------------------------------------------------------
// Top-level change encryption/decryption
// ---------------------------------------------------------------------------

/**
 * Encrypt all identity fields in a DecryptedGroupChange.
 *
 * Walks each action type and encrypts ACI, PNI, and profileKey fields
 * using zkgroup primitives. Non-identity fields pass through unchanged.
 */
function encryptChangeFields(
  change: DecryptedGroupChange,
  secretParams: GroupSecretParams
): EncryptedGroupChange {
  return {
    editorCiphertext: encryptServiceIdBytes(secretParams, change.editorServiceIdBytes),
    revision: change.revision,

    // Membership
    newMembers: change.newMembers.map((m) => encryptChangeMember(secretParams, m)),
    deleteMembers: change.deleteMembers.map((aci) => encryptAci(secretParams, aci)),
    modifyMemberRoles: change.modifyMemberRoles.map((m) =>
      encryptChangeModifyMemberRole(secretParams, m)
    ),
    modifiedProfileKeys: change.modifiedProfileKeys.map((m) =>
      encryptChangeMember(secretParams, m)
    ),

    // Pending members
    newPendingMembers: change.newPendingMembers.map((m) =>
      encryptChangePendingMember(secretParams, m)
    ),
    deletePendingMembers: change.deletePendingMembers.map((m) =>
      encryptChangePendingMemberRemoval(secretParams, m)
    ),
    promotePendingMembers: change.promotePendingMembers.map((m) =>
      encryptChangeMember(secretParams, m)
    ),

    // Attributes (pass through)
    newTitle: change.newTitle,
    newAvatar: change.newAvatar,
    newTimer: change.newTimer,

    // Access control (pass through)
    newAttributeAccess: change.newAttributeAccess,
    newMemberAccess: change.newMemberAccess,
    newInviteLinkAccess: change.newInviteLinkAccess,

    // Requesting members
    newRequestingMembers: change.newRequestingMembers.map((m) =>
      encryptChangeRequestingMember(secretParams, m)
    ),
    deleteRequestingMembers: change.deleteRequestingMembers.map((aci) =>
      encryptAci(secretParams, aci)
    ),
    promoteRequestingMembers: change.promoteRequestingMembers.map((m) =>
      encryptChangeApproveMember(secretParams, m)
    ),

    // Invite link (pass through)
    newInviteLinkPassword: change.newInviteLinkPassword,

    // Description (pass through)
    newDescription: change.newDescription,

    // Announcements (pass through)
    newIsAnnouncementGroup: change.newIsAnnouncementGroup,

    // Ban list
    newBannedMembers: change.newBannedMembers.map((m) =>
      encryptChangeBannedMember(secretParams, m)
    ),
    deleteBannedMembers: change.deleteBannedMembers.map((m) =>
      encryptChangeBannedMember(secretParams, m)
    ),

    // PNI-ACI promotion
    promotePendingPniAciMembers: change.promotePendingPniAciMembers.map((m) =>
      encryptChangeMember(secretParams, m)
    ),

    // Labels
    modifyMemberLabels: change.modifyMemberLabels.map((m) =>
      encryptChangeModifyMemberLabel(secretParams, m)
    ),
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
  return {
    editorServiceIdBytes: decryptServiceIdBytes(secretParams, encrypted.editorCiphertext),
    revision: encrypted.revision,

    // Membership
    newMembers: encrypted.newMembers.map((m) => decryptChangeMember(secretParams, m)),
    deleteMembers: encrypted.deleteMembers.map((ct) => decryptAci(secretParams, ct)),
    modifyMemberRoles: encrypted.modifyMemberRoles.map((m) =>
      decryptChangeModifyMemberRole(secretParams, m)
    ),
    modifiedProfileKeys: encrypted.modifiedProfileKeys.map((m) =>
      decryptChangeMember(secretParams, m)
    ),

    // Pending members
    newPendingMembers: encrypted.newPendingMembers.map((m) =>
      decryptChangePendingMember(secretParams, m)
    ),
    deletePendingMembers: encrypted.deletePendingMembers.map((m) =>
      decryptChangePendingMemberRemoval(secretParams, m)
    ),
    promotePendingMembers: encrypted.promotePendingMembers.map((m) =>
      decryptChangeMember(secretParams, m)
    ),

    // Attributes (pass through)
    newTitle: encrypted.newTitle,
    newAvatar: encrypted.newAvatar,
    newTimer: encrypted.newTimer,

    // Access control (pass through)
    newAttributeAccess: encrypted.newAttributeAccess,
    newMemberAccess: encrypted.newMemberAccess,
    newInviteLinkAccess: encrypted.newInviteLinkAccess,

    // Requesting members
    newRequestingMembers: encrypted.newRequestingMembers.map((m) =>
      decryptChangeRequestingMember(secretParams, m)
    ),
    deleteRequestingMembers: encrypted.deleteRequestingMembers.map((ct) =>
      decryptAci(secretParams, ct)
    ),
    promoteRequestingMembers: encrypted.promoteRequestingMembers.map((m) =>
      decryptChangeApproveMember(secretParams, m)
    ),

    // Invite link (pass through)
    newInviteLinkPassword: encrypted.newInviteLinkPassword,

    // Description (pass through)
    newDescription: encrypted.newDescription,

    // Announcements (pass through)
    newIsAnnouncementGroup: encrypted.newIsAnnouncementGroup,

    // Ban list
    newBannedMembers: encrypted.newBannedMembers.map((m) =>
      decryptChangeBannedMember(secretParams, m)
    ),
    deleteBannedMembers: encrypted.deleteBannedMembers.map((m) =>
      decryptChangeBannedMember(secretParams, m)
    ),

    // PNI-ACI promotion
    promotePendingPniAciMembers: encrypted.promotePendingPniAciMembers.map((m) =>
      decryptChangeMember(secretParams, m)
    ),

    // Labels
    modifyMemberLabels: encrypted.modifyMemberLabels.map((m) =>
      decryptChangeModifyMemberLabel(secretParams, m)
    ),
  };
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
  const sid = new Uint8Array(17);
  sid[0] = SERVICE_ID_ACI;
  sid.set(aciBytes, 1);
  return sid;
}
