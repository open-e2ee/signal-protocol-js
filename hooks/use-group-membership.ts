/**
 * useGroupMembership Hook
 *
 * React hook for handling group membership changes and sender key rotation.
 * Removing a member rotates the sender key before it is redistributed to the
 * remaining members.
 *
 * @example
 * ```typescript
 * function GroupSettings({ groupId }: { groupId: string }) {
 *   const { handleMemberRemoved, handleMemberAdded, isProcessing } = useGroupMembership({
 *     signal,
 *     clearEndorsements,
 *   });
 *
 *   const onRemoveMember = async (userId: string) => {
 *     await removeMemberFromDB(userId);
 *     await handleMemberRemoved(groupId, getRemainingMemberIds());
 *   };
 * }
 * ```
 */

import { useCallback, useState } from 'react';
import type { ILogger } from '../logger';
import type { ISignalProtocolClient } from '../types/api';

/**
 * Hook result type
 */
export {};
export interface UseGroupMembershipResult {
  /**
   * Handle member removal from a group.
   * Rotates sender key and distributes to remaining members.
   *
   * @param groupId - Signal group ID (from createGroupId)
   * @param remainingMemberIds - ACIs of members still in the group
   */
  handleMemberRemoved: (groupId: string, remainingMemberIds: string[]) => Promise<void>;

  /**
   * Handle member added to a group.
   * Distributes existing sender key to the new member.
   *
   * @param groupId - Signal group ID (from createGroupId)
   * @param newMemberId - ACI of the new member
   */
  handleMemberAdded: (groupId: string, newMemberId: string) => Promise<void>;

  /** Whether a membership change is being processed */
  isProcessing: boolean;

  /** Last error that occurred, if any */
  error: Error | null;
}

export interface UseGroupMembershipOptions {
  /** Signal Protocol client used for sender-key rotation and distribution */
  signal: Pick<
    ISignalProtocolClient,
    | 'rotateGroupSenderKey'
    | 'distributeGroupSenderKey'
    | 'distributeSenderKeyToUser'
    | 'hasGroupSenderKey'
    | 'logger'
  >;
  /** App-owned cache invalidation callback for stale endorsements */
  clearEndorsements: (groupId: string) => Promise<void>;
}

/**
 * Hook for handling group membership changes
 *
 * Provides callbacks for membership changes that properly handle
 * sender key rotation per Signal Protocol specification.
 *
 * @param options - Membership-change dependencies and app-owned invalidation hooks
 * @returns Callbacks for membership changes with loading/error states
 */
export function useGroupMembership({
  signal,
  clearEndorsements,
}: UseGroupMembershipOptions): UseGroupMembershipResult {
  const [isProcessing, setIsProcessing] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const logger: Required<ILogger> = signal.logger;

  /**
   * Handle member removal - rotate and redistribute sender key
   *
   * CRITICAL: The removed member must NOT be in remainingMemberIds
   */
  const handleMemberRemoved = useCallback(
    async (groupId: string, remainingMemberIds: string[]) => {
      setIsProcessing(true);
      setError(null);

      try {
        // Rotate our sender key (creates new key material with gen++)
        const { distributionMessage } = await signal.rotateGroupSenderKey(groupId);

        logger.debug('Rotated sender key after member removal', {
          category: 'E2EE',
          data: {
            groupId,
            newGeneration: distributionMessage.generation,
            remainingMembers: remainingMemberIds.length,
          },
        });

        // Distribute new key to remaining members (excludes removed member)
        if (remainingMemberIds.length > 0) {
          await signal.distributeGroupSenderKey(groupId, remainingMemberIds);

          logger.info('Distributed rotated sender key to remaining members', {
            category: 'E2EE',
            data: {
              groupId,
              memberCount: remainingMemberIds.length,
            },
          });
        }

        // Clear endorsement cache — membership changed, endorsements are stale
        try {
          await clearEndorsements(groupId);
        } catch (endorsementError) {
          // Non-fatal — endorsements will be refreshed on next send
          logger.warn('Failed to clear endorsements on member removal', {
            category: 'E2EE',
            data: { groupId, error: (endorsementError as Error).message },
          });
        }
      } catch (e) {
        const err = e as Error;
        setError(err);

        logger.error('Failed to rotate sender key after member removal', {
          category: 'E2EE',
          error: err,
          data: { groupId },
        });

        throw err;
      } finally {
        setIsProcessing(false);
      }
    },
    [clearEndorsements, logger, signal]
  );

  /**
   * Handle member added - distribute existing sender key
   *
   * New member needs our existing sender key to decrypt our messages.
   * They will create and distribute their own key when they first send.
   */
  const handleMemberAdded = useCallback(
    async (groupId: string, newMemberId: string) => {
      setIsProcessing(true);
      setError(null);

      try {
        // Check if we have a sender key for this group
        const hasSenderKey = await signal.hasGroupSenderKey(groupId);

        if (hasSenderKey) {
          // Distribute our existing key to the new member
          await signal.distributeSenderKeyToUser(groupId, newMemberId);

          logger.info('Distributed sender key to new group member', {
            category: 'E2EE',
            data: {
              groupId,
              newMemberId,
            },
          });
        } else {
          // We don't have a key yet - we'll create one when we send our first message
          logger.debug('No sender key to distribute to new member - will create on first send', {
            category: 'E2EE',
            data: { groupId, newMemberId },
          });
        }

        // Clear endorsement cache — membership changed, endorsements are stale
        try {
          await clearEndorsements(groupId);
        } catch (endorsementError) {
          // Non-fatal — endorsements will be refreshed on next send
          logger.warn('Failed to clear endorsements on member addition', {
            category: 'E2EE',
            data: { groupId, error: (endorsementError as Error).message },
          });
        }
      } catch (e) {
        const err = e as Error;
        setError(err);

        logger.error('Failed to distribute sender key to new member', {
          category: 'E2EE',
          error: err,
          data: { groupId, newMemberId },
        });

        throw err;
      } finally {
        setIsProcessing(false);
      }
    },
    [clearEndorsements, logger, signal]
  );

  return {
    handleMemberRemoved,
    handleMemberAdded,
    isProcessing,
    error,
  };
}
