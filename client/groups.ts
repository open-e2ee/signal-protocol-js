/**
 * Group messaging operations for SignalProtocolClient (Sender Keys)
 *
 * Extracted from SignalProtocolClient class to reduce file size.
 * Implements Signal Protocol's Sender Keys for efficient group encryption.
 */

import { EncryptionError, EncryptionErrorCode } from '../types';
import type { SignalProtocolClientContext } from './types';
import type {
  SenderKeyManager,
  SenderKeyDistributionMessage,
} from '../internal/protocol/sender-keys';
import type { GroupsV2Manager } from '../internal/groups-v2';
import type { DecryptedGroup, AccessControl, MemberRole } from '../internal/groups-v2';
import type { GroupId } from '../internal/groups/group-id';

/**
 * Create a sender key for group messaging
 *
 * Creates the sender key state needed for O(1) group encryption.
 * Returns a distribution message that must be shared with group members.
 *
 * @param ctx - Client context with dependencies
 * @param senderKeyManager - Sender key manager
 * @param groupId - Group identifier
 * @returns Sender key ID and distribution message
 */
export {};
export async function createGroupSenderKey(
  ctx: SignalProtocolClientContext,
  senderKeyManager: SenderKeyManager,
  groupId: string
): Promise<{ senderKeyId: string; distributionMessage: SenderKeyDistributionMessage }> {
  try {
    const result = await senderKeyManager.createSenderKey(groupId, ctx.userId, ctx.deviceId);

    ctx.logger.debug('Created group sender key', {
      category: 'E2EE',
      data: { groupId, senderKeyId: result.senderKeyId },
    });

    return result;
  } catch (error) {
    throw new EncryptionError(
      `Failed to create sender key for group ${groupId}`,
      EncryptionErrorCode.INITIALIZATION_FAILED,
      { originalError: error as Error }
    );
  }
}

/**
 * Process sender key distribution message from a group member
 *
 * Must be called before decrypting messages from that member.
 *
 * @param ctx - Client context with dependencies
 * @param senderKeyManager - Sender key manager
 * @param groupId - Group identifier
 * @param senderId - Sender's user ID
 * @param senderDeviceId - Sender's device ID
 * @param message - Distribution message
 */
export async function processSenderKeyDistribution(
  ctx: SignalProtocolClientContext,
  senderKeyManager: SenderKeyManager,
  groupId: string,
  senderId: string,
  senderDeviceId: number,
  message: SenderKeyDistributionMessage
): Promise<void> {
  try {
    await senderKeyManager.processSenderKeyDistribution(groupId, senderId, senderDeviceId, message);

    ctx.logger.debug('Processed group sender key distribution', {
      category: 'E2EE',
      data: { groupId, senderId, senderDeviceId },
    });
  } catch (error) {
    throw new EncryptionError(
      `Failed to process sender key distribution from ${senderId}`,
      EncryptionErrorCode.SESSION_CORRUPTED,
      { originalError: error as Error }
    );
  }
}

/**
 * Encrypt a message for group using sender key (O(1) encryption)
 *
 * After creating your sender key and distributing it to members,
 * use this to encrypt messages. All group members can decrypt
 * the same ciphertext, making it efficient for large groups.
 *
 * @param ctx - Client context with dependencies
 * @param senderKeyManager - Sender key manager
 * @param groupId - Group identifier
 * @param plaintext - Message to encrypt (string or Uint8Array)
 * @returns Framed SenderKeyMessage bytes
 */
export async function encryptGroupMessage(
  ctx: SignalProtocolClientContext,
  senderKeyManager: SenderKeyManager,
  groupId: string,
  plaintext: string | Uint8Array
): Promise<Uint8Array> {
  try {
    const plaintextBytes =
      typeof plaintext === 'string' ? new TextEncoder().encode(plaintext) : plaintext;
    const encrypted = await senderKeyManager.encryptGroupMessage(
      groupId,
      ctx.userId,
      ctx.deviceId,
      plaintextBytes
    );

    ctx.logger.debug('Encrypted group message', {
      category: 'E2EE',
      data: { groupId },
    });

    return encrypted;
  } catch (error) {
    // Preserve typed EncryptionErrors (e.g., SENDER_KEY_EXPIRED)
    if (error instanceof EncryptionError) {
      throw error;
    }
    const err = error as Error;
    if (err.message?.includes('SENDER_KEY_NOT_FOUND')) {
      throw new EncryptionError(
        `No sender key for group ${groupId} - call createGroupSenderKey() first`,
        EncryptionErrorCode.SESSION_NOT_FOUND,
        { originalError: err }
      );
    }
    throw new EncryptionError(
      `Failed to encrypt group message for ${groupId}`,
      EncryptionErrorCode.ENCRYPTION_FAILED,
      { originalError: err }
    );
  }
}

/**
 * Decrypt a group message from a sender
 *
 * Use this to decrypt messages from other group members.
 * You must have processed the sender's distribution message first.
 *
 * @param ctx - Client context with dependencies
 * @param senderKeyManager - Sender key manager
 * @param groupId - Group identifier
 * @param senderId - Sender's user ID
 * @param senderDeviceId - Sender's device ID
 * @param framedMessage - Framed SenderKeyMessage bytes
 * @returns Decrypted plaintext
 */
export async function decryptGroupMessage(
  ctx: SignalProtocolClientContext,
  senderKeyManager: SenderKeyManager,
  groupId: string,
  senderId: string,
  senderDeviceId: number,
  framedMessage: Uint8Array
): Promise<string> {
  try {
    const plaintext = await senderKeyManager.decryptGroupMessage(
      groupId,
      senderId,
      senderDeviceId,
      framedMessage
    );

    ctx.logger.debug('Decrypted group message', {
      category: 'E2EE',
      data: { groupId, senderId },
    });

    return plaintext;
  } catch (error) {
    const err = error as Error;
    if (err.message?.includes('SENDER_KEY_NOT_FOUND')) {
      throw new EncryptionError(
        `No sender key from ${senderId} for group ${groupId} - request key distribution`,
        EncryptionErrorCode.SESSION_NOT_FOUND,
        { originalError: err }
      );
    }
    if (err.message?.includes('INVALID_SIGNATURE')) {
      throw new EncryptionError(
        `Invalid signature on group message from ${senderId}`,
        EncryptionErrorCode.DECRYPTION_FAILED,
        { originalError: err }
      );
    }
    if (err.message?.includes('MESSAGE_TOO_OLD')) {
      throw new EncryptionError(
        `Cannot decrypt old group message (forward secrecy)`,
        EncryptionErrorCode.DECRYPTION_FAILED,
        { originalError: err }
      );
    }
    throw new EncryptionError(
      `Failed to decrypt group message from ${senderId}`,
      EncryptionErrorCode.DECRYPTION_FAILED,
      { originalError: err }
    );
  }
}

/**
 * Rotate sender key for a group (forward secrecy on membership changes).
 *
 * Per Signal Protocol specification, rotate sender keys on **membership changes**:
 *
 * | Event | Action |
 * |-------|--------|
 * | Member REMOVED | **ALL members** must rotate (forward secrecy) |
 * | Member ADDED | Distribute current key to new member (no rotation needed) |
 * | Group metadata changed | Rotate recommended |
 *
 * @param ctx - Client context with dependencies
 * @param senderKeyManager - Sender key manager
 * @param groupId - Group identifier
 * @param onRotated - Optional callback when rotation completes
 * @returns New distribution message to share with remaining members
 */
export async function rotateGroupSenderKey(
  ctx: SignalProtocolClientContext,
  senderKeyManager: SenderKeyManager,
  groupId: string,
  onRotated?: (groupId: string, generation: number) => void
): Promise<{ senderKeyId: string; distributionMessage: SenderKeyDistributionMessage }> {
  try {
    const result = await senderKeyManager.rotateSenderKey(groupId, ctx.userId, ctx.deviceId);

    ctx.logger.debug('Rotated group sender key', {
      category: 'E2EE',
      data: { groupId, newSenderKeyId: result.senderKeyId },
    });

    // Call rotation callback if configured
    if (onRotated) {
      try {
        onRotated(groupId, result.distributionMessage.generation);
      } catch (callbackError) {
        ctx.logger.warn('onGroupSenderKeyRotated callback failed', {
          category: 'E2EE',
          data: { error: (callbackError as Error).message, groupId },
        });
      }
    }

    return result;
  } catch (error) {
    throw new EncryptionError(
      `Failed to rotate sender key for group ${groupId}`,
      EncryptionErrorCode.INITIALIZATION_FAILED,
      { originalError: error as Error }
    );
  }
}

/**
 * Delete sender key when leaving a group
 *
 * @param ctx - Client context with dependencies
 * @param senderKeyManager - Sender key manager
 * @param groupId - Group identifier
 */
export async function deleteGroupSenderKey(
  ctx: SignalProtocolClientContext,
  senderKeyManager: SenderKeyManager,
  groupId: string
): Promise<void> {
  try {
    await senderKeyManager.deleteSenderKey(groupId, ctx.userId, ctx.deviceId);

    ctx.logger.debug('Deleted group sender key', {
      category: 'E2EE',
      data: { groupId },
    });
  } catch (error) {
    throw new EncryptionError(
      `Failed to delete sender key for group ${groupId}`,
      EncryptionErrorCode.SESSION_CORRUPTED,
      { originalError: error as Error }
    );
  }
}

/**
 * Check if we have a sender key for a group
 *
 * @param ctx - Client context with dependencies
 * @param groupId - Group identifier
 * @returns True if sender key exists for this device
 */
export async function hasGroupSenderKey(
  ctx: SignalProtocolClientContext,
  groupId: string
): Promise<boolean> {
  const senderKey = await ctx.storage.getSenderKey(groupId, ctx.userId, ctx.deviceId);
  return senderKey !== null;
}

/**
 * Get the current sender key distribution message for a group
 *
 * If no sender key exists, returns null. Use createGroupSenderKey() first.
 *
 * @param ctx - Client context with dependencies
 * @param groupId - Group identifier
 * @returns Distribution message or null if no key exists
 */
export async function getGroupSenderKeyDistribution(
  ctx: SignalProtocolClientContext,
  groupId: string
): Promise<SenderKeyDistributionMessage | null> {
  const senderKey = await ctx.storage.getSenderKey(groupId, ctx.userId, ctx.deviceId);
  if (!senderKey) {
    return null;
  }

  // Create distribution message from stored state
  return {
    senderKeyId: senderKey.senderKeyId,
    chainId: senderKey.chainId,
    generation: senderKey.generation,
    chainIndex: senderKey.chainIndex,
    chainKey: senderKey.chainKey,
    publicSignatureKey: senderKey.publicSignatureKey,
  };
}

/**
 * Get sender key stats for debugging
 *
 * @param ctx - Client context with dependencies
 * @param groupId - Group identifier
 * @param senderId - Sender's user ID
 * @param senderDeviceId - Sender's device ID
 * @returns Stats object or null if no key exists
 */
export async function getGroupSenderKeyStats(
  ctx: SignalProtocolClientContext,
  groupId: string,
  senderId: string,
  senderDeviceId: number
): Promise<{
  senderKeyId: string;
  generation: number;
  chainIndex: number;
} | null> {
  const state = await ctx.storage.getSenderKey(groupId, senderId, senderDeviceId);
  if (!state) {
    return null;
  }
  return {
    senderKeyId: state.senderKeyId,
    generation: state.generation,
    chainIndex: state.chainIndex,
  };
}

// ============================================================================
// GROUPS V2 OPERATIONS (Signal Private Group System)
// ============================================================================

/**
 * Wrap a GroupsV2 operation with consistent logging and error handling.
 *
 * All V2 functions follow the same pattern: call manager, log success, throw
 * EncryptionError on failure. This helper eliminates that boilerplate.
 */
async function wrapGroupOp<T>(
  label: string,
  logger: SignalProtocolClientContext['logger'],
  op: () => Promise<T>,
  logData?: Record<string, unknown>,
  errorCode: EncryptionErrorCode = EncryptionErrorCode.INVALID_STATE
): Promise<T> {
  try {
    const result = await op();
    logger.debug(label, { category: 'E2EE', data: logData });
    return result;
  } catch (error) {
    throw new EncryptionError(label, errorCode, { originalError: error as Error });
  }
}

/**
 * Create a new GroupsV2 group
 *
 * Generates a master key, builds initial encrypted state, and uploads
 * to the server. The creator is added as an administrator.
 */
export async function createGroupV2(
  ctx: SignalProtocolClientContext,
  manager: GroupsV2Manager,
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
  return wrapGroupOp(
    `Created GroupsV2 group "${title}"`,
    ctx.logger,
    () => manager.createGroup(creatorAci, creatorProfileKey, members, title, options),
    { memberCount: members.length + 1, title },
    EncryptionErrorCode.INITIALIZATION_FAILED
  );
}

/**
 * Get the decrypted state for a GroupsV2 group
 *
 * Returns cached state if available, otherwise fetches from server.
 */
export async function getGroupStateV2(
  ctx: SignalProtocolClientContext,
  manager: GroupsV2Manager,
  groupId: GroupId
): Promise<DecryptedGroup> {
  return wrapGroupOp(
    `Retrieved GroupsV2 state for ${groupId}`,
    ctx.logger,
    async () => {
      const state = await manager.getGroupState(groupId);
      return state;
    },
    { groupId }
  );
}

/**
 * Sync GroupsV2 group state from server
 *
 * Fetches the latest state or replays the change log to bring
 * local state up to date.
 */
export async function syncGroupV2(
  ctx: SignalProtocolClientContext,
  manager: GroupsV2Manager,
  groupId: GroupId
): Promise<DecryptedGroup> {
  return wrapGroupOp(
    `Synced GroupsV2 state for ${groupId}`,
    ctx.logger,
    async () => {
      const state = await manager.syncGroup(groupId);
      return state;
    },
    { groupId }
  );
}

/**
 * Add a member to a GroupsV2 group
 */
export async function addGroupMemberV2(
  ctx: SignalProtocolClientContext,
  manager: GroupsV2Manager,
  groupId: GroupId,
  editorAci: Uint8Array,
  newMemberAci: Uint8Array,
  newMemberProfileKey: Uint8Array
): Promise<void> {
  return wrapGroupOp(
    `Added member to GroupsV2 group ${groupId}`,
    ctx.logger,
    () => manager.addMember(groupId, editorAci, newMemberAci, newMemberProfileKey),
    { groupId }
  );
}

/**
 * Remove a member from a GroupsV2 group
 *
 * Triggers sender key rotation for forward secrecy.
 */
export async function removeGroupMemberV2(
  ctx: SignalProtocolClientContext,
  manager: GroupsV2Manager,
  groupId: GroupId,
  editorAci: Uint8Array,
  targetAci: Uint8Array
): Promise<void> {
  return wrapGroupOp(
    `Removed member from GroupsV2 group ${groupId}`,
    ctx.logger,
    () => manager.removeMember(groupId, editorAci, targetAci),
    { groupId }
  );
}

/**
 * Leave a GroupsV2 group (self-remove)
 */
export async function leaveGroupV2(
  ctx: SignalProtocolClientContext,
  manager: GroupsV2Manager,
  groupId: GroupId,
  userAci: Uint8Array
): Promise<void> {
  return wrapGroupOp(
    `Left GroupsV2 group ${groupId}`,
    ctx.logger,
    () => manager.leaveGroup(groupId, userAci),
    {
      groupId,
    }
  );
}

/**
 * Update the title of a GroupsV2 group
 */
export async function updateGroupTitleV2(
  ctx: SignalProtocolClientContext,
  manager: GroupsV2Manager,
  groupId: GroupId,
  editorAci: Uint8Array,
  title: string
): Promise<void> {
  return wrapGroupOp(
    `Updated GroupsV2 group title for ${groupId}`,
    ctx.logger,
    () => manager.updateTitle(groupId, editorAci, title),
    { groupId, title }
  );
}

/**
 * Update the description of a GroupsV2 group
 */
export async function updateGroupDescriptionV2(
  ctx: SignalProtocolClientContext,
  manager: GroupsV2Manager,
  groupId: GroupId,
  editorAci: Uint8Array,
  description: string
): Promise<void> {
  return wrapGroupOp(
    `Updated GroupsV2 group description for ${groupId}`,
    ctx.logger,
    () => manager.updateDescription(groupId, editorAci, description),
    { groupId }
  );
}

/**
 * Update access control settings for a GroupsV2 group
 */
export async function updateGroupAccessControlV2(
  ctx: SignalProtocolClientContext,
  manager: GroupsV2Manager,
  groupId: GroupId,
  editorAci: Uint8Array,
  updates: Partial<AccessControl>
): Promise<void> {
  return wrapGroupOp(
    `Updated GroupsV2 group access control for ${groupId}`,
    ctx.logger,
    () => manager.updateAccessControl(groupId, editorAci, updates),
    { groupId, updates }
  );
}

/**
 * Create an invite link for a GroupsV2 group
 */
export async function createGroupInviteLinkV2(
  ctx: SignalProtocolClientContext,
  manager: GroupsV2Manager,
  groupId: GroupId,
  editorAci: Uint8Array
): Promise<string> {
  return wrapGroupOp(
    `Created GroupsV2 invite link for ${groupId}`,
    ctx.logger,
    () => manager.createInviteLink(groupId, editorAci),
    { groupId }
  );
}

/**
 * Join a GroupsV2 group via invite link
 *
 * Parses the invite link, validates the password, and adds
 * the user as a member or to the requesting members list
 * (if admin approval is required).
 */
export async function joinGroupViaInviteLinkV2(
  ctx: SignalProtocolClientContext,
  manager: GroupsV2Manager,
  url: string,
  userAci: Uint8Array,
  userProfileKey: Uint8Array
): Promise<{ groupId: GroupId; status: 'joined' | 'pending_approval' }> {
  return wrapGroupOp(
    `Joined GroupsV2 group via invite link`,
    ctx.logger,
    () => manager.joinViaInviteLink(url, userAci, userProfileKey),
    {},
    EncryptionErrorCode.INITIALIZATION_FAILED
  );
}
