import { constantTimeEqual } from '../internal/crypto';
import { bytesToHex } from '../encoding/hex';
import { GroupAction, canPerformAction } from '../internal/groups/access-control';
import { createGroupId, extractGroupId, type GroupId } from '../internal/groups/group-id';
import type { GroupStateStore } from '../internal/groups/manager';
import type { GroupFetchDenial } from '../internal/groups/receive-record';
import type { DecryptedGroup } from '../internal/groups/types';
import {
  GROUP_IDENTIFIER_LEN,
  deriveGroupSecretParams,
} from '../internal/protocol/zk/groups/group-params';
import { SERVICE_ID_ACI, serviceIdBinary } from '../internal/protocol/zk/groups/uid-struct';
import type { GroupContentContext, InspectedSignalProtocolContent } from './content-adapter';
import type { GroupFetcher } from './group-fetcher';

// A managed group's raw ID is its group identifier in lowercase hex.
const MANAGED_GROUP_ID = new RegExp(`^[0-9a-f]{${GROUP_IDENTIFIER_LEN * 2}}$`);
const MASTER_KEY_LEN = 32;
/** How long a receive waits before it tries an unresolved sender again. */
const SENDER_RESOLUTION_RETRY_MS = 30_000;

/**
 * Why the client delivers no group content and never will.
 *
 * `legacy-no-context`: the content of a managed group carries no group
 * context, and the client has no state of the group. SDK 12.0.0 and later
 * put the group context in group content. The next major SDK version no
 * longer decides group content that has no group context, so content from
 * an SDK 11 sender is not delivered. Move every sender to SDK 12.0.0 or
 * later before that version.
 */
export type GroupReceiveDenial =
  | 'malformed-context'
  | 'context-mismatch'
  | 'blocked'
  | 'sender-not-member'
  | 'recipient-not-member'
  | 'sender-lacks-permission'
  | GroupFetchDenial
  | 'legacy-no-context'
  | 'configuration'
  | 'unverified-cap'
  | 'sync-from-other-account';

/** Why the client cannot decide on group content yet. */
export type GroupReceiveUnavailability =
  | 'update-pending'
  | 'update-failed'
  | 'sender-unresolved'
  | 'aci-resolution-failed';

/** The decision on received group content. */
export type GroupReceiveVerdict =
  | { kind: 'authorized'; groupId: string; revision: number }
  | { kind: 'unavailable'; reason: GroupReceiveUnavailability; retryAfterMs: number }
  | { kind: 'denied'; reason: GroupReceiveDenial };

/**
 * The client delivers no group content: its context is malformed or names
 * another group, the group is blocked, or the verified group state refuses
 * it. A resend of the content would be refused again, so the receive paths
 * ask for no resend.
 */
export class GroupReceiveRefusedError extends Error {
  override readonly name = 'GroupReceiveRefusedError';

  constructor(readonly reason: GroupReceiveDenial) {
    super(`Group content refused: ${reason}`);
  }
}

/**
 * The client cannot decide on group content yet, because its group state
 * is not current. The content is committed in a receive record under
 * `messageId`, and the receive queue decides it when the group state
 * updates. `decryptGroupMessage` throws it for a `pending` receive. A
 * repeat call with the same message finds the record and spends no second
 * ratchet step. `messageId` is absent only on an error that no receive
 * record backs.
 */
export class GroupReceiveUnavailableError extends Error {
  override readonly name = 'GroupReceiveUnavailableError';

  constructor(
    readonly reason: GroupReceiveUnavailability,
    readonly retryAfterMs: number,
    readonly messageId?: string
  ) {
    super(`Group content waits for its group: ${reason}`);
  }
}

/**
 * Refuse content that carries a sync message from another account. Sync
 * content is content of the own account. A sent transcript names the
 * conversation that its content is delivered under, so the refusal comes
 * before any group decision on the content.
 *
 * @param inspected - The inspection of the content
 * @param senderId - The sender of the content
 * @param ownUserId - The user ID of this account
 * @throws GroupReceiveRefusedError `sync-from-other-account` when the
 *   content carries a sync message and the sender is another account
 */
export function refuseSyncFromOtherAccount(
  inspected: InspectedSignalProtocolContent,
  senderId: string,
  ownUserId: string
): void {
  if (inspected.sync && senderId !== ownUserId) {
    throw new GroupReceiveRefusedError('sync-from-other-account');
  }
}

/** The group part of received content. */
export interface GroupContentClaim {
  /**
   * The raw group ID that the transport bound the content to: the group of
   * the sender key, the label of the distribution beside the content, or
   * the destination of a sent transcript. Absent for pairwise content that
   * only its context names.
   */
  groupId?: string;
  context: GroupContentContext | 'malformed' | undefined;
  /** True for a sent transcript from another device of this account. */
  transcript: boolean;
}

/**
 * Find the group part of decrypted content. Null when the content belongs
 * to no managed group and carries no context, so it needs no group decision.
 *
 * @param transportGroupId - The raw group of a sender-key message, or null
 * @param inspected - The inspection of the content
 */
export function classifyGroupContent(
  transportGroupId: string | null,
  inspected: InspectedSignalProtocolContent
): GroupContentClaim | null {
  const context = inspected.groupContext;
  const managedOrContext = (groupId: string | undefined) =>
    context !== undefined || (groupId !== undefined && MANAGED_GROUP_ID.test(groupId));
  // The transport binds content to a group before the content names one:
  // content that a sender key decrypted, or that came beside a distribution,
  // is content of that group whatever its shape, and never a transcript.
  if (transportGroupId !== null) {
    const groupId = extractGroupId(transportGroupId);
    return managedOrContext(groupId) ? { groupId, context, transcript: false } : null;
  }
  const distribution = inspected.senderKeyDistribution;
  if (distribution) {
    // A distribution alone is no group content. It installs and stops.
    if (inspected.senderKeyDistributionOnly !== false) return null;
    const groupId = extractGroupId(distribution.groupId);
    return managedOrContext(groupId) ? { groupId, context, transcript: false } : null;
  }
  if (inspected.sync?.type === 'sent') {
    const groupId = inspected.sync.conversationId;
    return groupId !== undefined && managedOrContext(groupId)
      ? { groupId, context, transcript: true }
      : null;
  }
  return context !== undefined ? { context, transcript: false } : null;
}

/** The raw group ID that a valid group context names, or the denial. */
export function groupOfContext(
  claim: GroupContentClaim
): { groupId: string; context?: GroupContentContext } | { denial: GroupReceiveDenial } {
  const { context } = claim;
  if (context === undefined) return { groupId: claim.groupId! };
  if (
    context === 'malformed' ||
    !(context.masterKey instanceof Uint8Array) ||
    context.masterKey.length !== MASTER_KEY_LEN ||
    !Number.isSafeInteger(context.revision) ||
    context.revision < 0
  ) {
    return { denial: 'malformed-context' };
  }
  const groupId = bytesToHex(deriveGroupSecretParams(context.masterKey).groupId);
  if (claim.groupId !== undefined && claim.groupId !== groupId) {
    return { denial: 'context-mismatch' };
  }
  return { groupId, context };
}

/** The sender of one group content and its claim. */
export interface GroupReceiveInput {
  readonly claim: GroupContentClaim;
  readonly senderId: string;
  readonly senderDeviceId: number;
}

/** Decide on received group content. */
export type GroupReceiveEvaluator = (input: GroupReceiveInput) => Promise<GroupReceiveVerdict>;

/**
 * What the evaluator needs from its client.
 * @internal
 */
export interface GroupReceiveEvaluatorOptions {
  readonly store: GroupStateStore;
  readonly fetcher: GroupFetcher;
  readonly ownUserId: string;
  readonly localAci: Uint8Array | undefined;
  readonly resolveAcis: ((userIds: string[]) => Promise<Map<string, Uint8Array>>) | undefined;
  readonly isGroupBlocked?: (groupId: GroupId) => boolean | Promise<boolean>;
}

/**
 * Decide on received group content as Signal does:
 *
 * 1. A context must be valid, and the group ID that its master key derives
 *    must be the group that the transport bound the content to.
 * 2. The master key of a new group is stored, under the unverified-group
 *    cap of the sender device. The revision raises the group's required
 *    revision.
 * 3. A blocked group drops the content with no report.
 * 4. When no state covers the claimed revision, the fetcher updates the
 *    group first. Content with no context is evaluated against local state
 *    only, and with no state it is denied.
 * 5. The recipient and the sender must be members, and the sender must be
 *    allowed to send. A sent transcript checks only the recipient.
 *
 * An unavailable verdict keeps no state here. The receive queue owns the
 * content that waits on the group.
 * @internal
 */
export function createGroupReceiveEvaluator(
  options: GroupReceiveEvaluatorOptions
): GroupReceiveEvaluator {
  const { store, fetcher } = options;

  const evaluate = async (
    input: GroupReceiveInput,
    groupId: string,
    context: GroupContentContext | undefined
  ): Promise<GroupReceiveVerdict> => {
    const { claim, senderId } = input;
    if (claim.transcript && senderId !== options.ownUserId) {
      return { kind: 'denied', reason: 'sender-not-member' };
    }
    if (context) {
      const admitted = await fetcher.admitContext(groupId, context.masterKey, context.revision, {
        senderId,
        senderDeviceId: input.senderDeviceId,
      });
      if (admitted === 'unverified-cap') return { kind: 'denied', reason: 'unverified-cap' };
    }
    if (await options.isGroupBlocked?.(createGroupId(groupId))) {
      return { kind: 'denied', reason: 'blocked' };
    }
    let state: DecryptedGroup | null = await store.getGroupState(groupId);
    if (!context) {
      if (!state) return { kind: 'denied', reason: 'legacy-no-context' };
    } else if (!state || state.revision < context.revision) {
      const freshness = await fetcher.ensureFresh(groupId, {
        revision: context.revision,
        ...(context.groupChange && { change: context.groupChange }),
      });
      if (freshness.kind !== 'fresh') {
        return freshness.kind === 'denied'
          ? { kind: 'denied', reason: freshness.reason }
          : freshness;
      }
      state = await store.getGroupState(groupId);
      if (!state) {
        return { kind: 'unavailable', reason: 'update-failed', retryAfterMs: SENDER_RESOLUTION_RETRY_MS };
      }
    }
    return authorize(input, groupId, state);
  };

  const authorize = async (
    input: GroupReceiveInput,
    groupId: string,
    state: DecryptedGroup
  ): Promise<GroupReceiveVerdict> => {
    const { localAci, resolveAcis } = options;
    if (!localAci || !resolveAcis) return { kind: 'denied', reason: 'configuration' };
    const isMember = (aci: Uint8Array) =>
      state.members.some((member) => constantTimeEqual(member.aciBytes, aci));
    if (!isMember(localAci)) return { kind: 'denied', reason: 'recipient-not-member' };
    if (input.claim.transcript) return { kind: 'authorized', groupId, revision: state.revision };
    let senderAci: Uint8Array | undefined;
    try {
      senderAci = (await resolveAcis([input.senderId])).get(input.senderId);
    } catch {
      return {
        kind: 'unavailable',
        reason: 'aci-resolution-failed',
        retryAfterMs: SENDER_RESOLUTION_RETRY_MS,
      };
    }
    if (!senderAci) {
      return {
        kind: 'unavailable',
        reason: 'sender-unresolved',
        retryAfterMs: SENDER_RESOLUTION_RETRY_MS,
      };
    }
    if (!isMember(senderAci)) return { kind: 'denied', reason: 'sender-not-member' };
    if (
      !canPerformAction(
        state,
        serviceIdBinary({ kind: SERVICE_ID_ACI, uuid: senderAci }),
        GroupAction.SEND_MESSAGE
      )
    ) {
      return { kind: 'denied', reason: 'sender-lacks-permission' };
    }
    return { kind: 'authorized', groupId, revision: state.revision };
  };

  return async (input) => {
    const group = groupOfContext(input.claim);
    if ('denial' in group) return { kind: 'denied', reason: group.denial };
    return evaluate(input, group.groupId, group.context);
  };
}

/** The error that a verdict other than `authorized` throws on a receive path. */
export function groupReceiveError(
  verdict: Exclude<GroupReceiveVerdict, { kind: 'authorized' }>,
  messageId?: string
): GroupReceiveRefusedError | GroupReceiveUnavailableError {
  return verdict.kind === 'denied'
    ? new GroupReceiveRefusedError(verdict.reason)
    : new GroupReceiveUnavailableError(verdict.reason, verdict.retryAfterMs, messageId);
}

/**
 * The membership of a user in a group, as a retry resend needs it.
 * `no-source` means that the client has no way to know: an ad hoc group
 * with no `isCurrentMember` hook, or a managed group with no group store or
 * no ACI resolution. With a fetcher, the checker first updates a managed
 * group that has a master key to its required revision. `unavailable` means
 * only that this update answered unavailable: it failed, waits for its fetch
 * window or backoff, did not end before its deadline, or spent its three
 * rounds on fetches that other callers started and that ended in time. It
 * defers the resend and does not refuse it. A denied update answers
 * `not-member`.
 * Otherwise the answer is `member` or `not-member` from the local state,
 * also when a false claim keeps the required revision above it.
 */
export type GroupMembership = 'member' | 'not-member' | 'no-source' | 'unavailable';

/** Check whether a user is a current member of a group. */
export type GroupMembershipChecker = (groupId: string, userId: string) => Promise<GroupMembership>;

/**
 * A group resend waits for the group state, because the membership checker
 * answered `unavailable`. The resend job stays pending and the retry
 * request stays unacknowledged, so a later run decides again. Nothing ends
 * the answer to the failed envelope.
 */
export class GroupResendDeferredError extends Error {
  override readonly name = 'GroupResendDeferredError';

  constructor(readonly groupId: string) {
    super('Group resend waits for its group state');
  }
}

/**
 * Check the current membership of a user before the client gives group
 * content to that user again.
 *
 * A managed group is checked against the verified local group state. With
 * a fetcher, a state below the `requiredRevision` of the receive record is
 * updated first, through the same record, fetch window and backoff as a
 * receive, as Signal's `getGroupUpdates` serves both. A failed update
 * answers `unavailable`, and a denied update answers `not-member`. When the
 * update is fresh, the answer is `member` or `not-member` from the local
 * state, also when a false claim keeps the required revision above it. An
 * ad hoc group is checked through
 * `protocol.contentRecovery.isCurrentMember`, which gets the prefixed group
 * ID that `createGroupId` makes. The group members of a send never count:
 * they are what the sender knew then.
 *
 * @param store - The verified group state, when the client has groups.
 * @param resolveAcis - Resolves user IDs to ACI bytes for a managed group.
 * @param isCurrentMember - The hook of the application for ad hoc groups.
 * @param fetcher - Updates a managed group to its required revision.
 * @internal
 */
export function createGroupMembershipChecker(
  store: GroupStateStore | undefined,
  resolveAcis: ((userIds: string[]) => Promise<Map<string, Uint8Array>>) | undefined,
  isCurrentMember: ((groupId: string, userId: string) => Promise<boolean>) | undefined,
  fetcher?: Pick<GroupFetcher, 'ensureFresh'>
): GroupMembershipChecker {
  return async (groupId, userId) => {
    const rawGroupId = extractGroupId(groupId);
    if (!MANAGED_GROUP_ID.test(rawGroupId)) {
      if (!isCurrentMember) return 'no-source';
      return (await isCurrentMember(createGroupId(rawGroupId), userId)) ? 'member' : 'not-member';
    }
    if (!store || !resolveAcis) return 'no-source';
    if (fetcher && (await store.getMasterKey(rawGroupId))) {
      const freshness = await fetcher.ensureFresh(rawGroupId);
      if (freshness.kind === 'unavailable') return 'unavailable';
      if (freshness.kind === 'denied') return 'not-member';
    }
    const state = await store.getGroupState(rawGroupId);
    const aci = (await resolveAcis([userId])).get(userId);
    if (state && aci && state.members.some((member) => constantTimeEqual(member.aciBytes, aci))) {
      return 'member';
    }
    return 'not-member';
  };
}
