/**
 * The session reset of the requester after a retry request ends as
 * `expired-content` or `posting-deadline`.
 *
 * The request got no content before its deadline, or it can post no more
 * before its posting deadline, so the session with the device that sent
 * the failed envelope can be out of step. The requester
 * archives that session, deletes its sender-key handoff rows for each device
 * of that account in every group, and sends one null message to the
 * device, at most once an hour for each device. The null message, or else
 * the next ordinary message, starts a new session with the device. The
 * other terminal classes and a retryable post failure reset nothing.
 *
 * Each step is stored on the request record when it ends, so a replay of
 * the terminal state after a restart or a client stop does not archive a
 * newer session.
 */

import type { Logger } from '../logger';
import {
  getRetryRequest,
  listRetryRequestIds,
  RETRY_TERMINAL_NULL_MESSAGE_INTERVAL_MS,
  updateRetryRequest,
  type RetryTerminalNullMessage,
  type RetryTerminalRecovery,
  type StoredRetryRequest,
} from '../local/store/reliability';
import { createKeyedLocks, withKeyedLock } from '../utils/keyed-lock';
import { callHook, type SignalProtocolClientHooks } from './event-hooks';
import { rethrowRelayWorkStopped } from './relay-work';

type RetryRecordStore = Parameters<typeof getRetryRequest>[0];

/** The device that sent a failed envelope. */
export interface RetryTerminalDevice {
  readonly userId: string;
  readonly deviceId: number;
}

/**
 * The session reset steps. The client gives them, bound to the relay work
 * that runs the reset.
 */
export interface RetryTerminalResetSteps {
  /**
   * Wait for each decrypt from the device that is in progress, and then
   * archive the session with the device in the protocol store and in its
   * device record. The next send to the user reads its device list again.
   */
  archiveSession(device: RetryTerminalDevice): Promise<void>;
  /**
   * Delete the sender-key handoff rows of every device of the account in
   * every group, with no rotation, so the next send of each group gives the
   * current key to each of those devices. With the raw group ID of the
   * failed envelope, the delete runs in the sender-key turn of that group.
   * True when the requester has a sender key for that group, false when it
   * has none or no group is given. A client stop does not stop it, so a
   * stop does not split the archive from the invalidation.
   */
  invalidateAccountSenderKeyHandoffs(userId: string, groupId: string | undefined): Promise<boolean>;
  /**
   * Start a session with the device when there is none, and post one null
   * message to it with the implicit content hint.
   */
  sendNullMessage(device: RetryTerminalDevice): Promise<void>;
}

/** What the reset of one terminal state uses. */
export interface RetryTerminalResetContext {
  readonly storage: RetryRecordStore;
  readonly logger: Required<Logger>;
  readonly hooks: SignalProtocolClientHooks | undefined;
  /** Without them, the terminal state resets nothing. */
  readonly reset: RetryTerminalResetSteps | undefined;
}

/**
 * Reset the session with the sender device of an `expired-content` or
 * `posting-deadline` request whose terminal state is not emitted. Another
 * class, an emitted state, and a context with no reset steps do nothing.
 *
 * The steps run in this order. A step that a stored marker shows as done
 * does not run again.
 *
 * 1. The session with the device is archived, after its decrypts that are
 *    in progress end.
 * 2. The handoff rows of each device of the account in every group are
 *    deleted, after the archive, as one Signal client does at an automatic
 *    session reset. The step runs for a group message and for a
 *    pairwise message. The next send of each group gives its current key to
 *    each device of the account, and to the device through the new session.
 * 3. The record stores the archived device and the sender key outcome,
 *    and the `onSessionArchived` hook runs.
 * 4. Under one lock for each device, a null message goes to the device
 *    when no other request sent one to it in the last hour. The record
 *    stores the outcome.
 *
 * A RelayWorkStopped while the archive waits for the decrypt lock
 * propagates, and the replay runs the reset again. A failure of steps 1 to
 * 3 also propagates. A crash between the archive and its stored marker
 * archives again at the replay. A failed null message is stored as
 * `failed`.
 *
 * @returns The stored record after the reset of an `expired-content` or
 *   `posting-deadline` end, else the stored record.
 */
export async function resetRetryTerminalSession(
  context: RetryTerminalResetContext,
  failedEnvelopeId: string
): Promise<StoredRetryRequest | null> {
  const { storage, reset } = context;
  let record = await getRetryRequest(storage, failedEnvelopeId);
  const terminal = record?.terminal;
  if (
    !record ||
    !terminal ||
    terminal.emitted ||
    (terminal.class !== 'expired-content' && terminal.class !== 'posting-deadline')
  ) {
    return record;
  }
  // An expired or posting-deadline request always has its stored envelope.
  // Its target is the device that sent the failed envelope.
  if (!reset || !record.envelope) return record;
  const device: RetryTerminalDevice = {
    userId: record.envelope.targetUserId,
    deviceId: record.envelope.targetDeviceId,
  };

  let recovery = record.recovery;
  if (!recovery) {
    await reset.archiveSession(device);
    const senderKey = (await reset.invalidateAccountSenderKeyHandoffs(
      device.userId,
      record.groupId
    ))
      ? 'applied'
      : 'skipped';
    recovery = { userId: device.userId, deviceId: device.deviceId, senderKey };
    record = await updateRetryRequest(storage, failedEnvelopeId, record.retryId, record.attempt, {
      recovery,
    });
    if (!record) return null;
    context.logger.info('Archived the session with the sender of an ended retry request', {
      category: 'E2EE',
      data: {
        failedEnvelopeId,
        sender: `${device.userId}:${device.deviceId}`,
        senderKey,
        behavior: 'RETRY_TERMINAL_SESSION_RESET',
      },
    });
    await callHook(context.hooks, 'onSessionArchived', `${device.userId}:${device.deviceId}`);
  }

  if (recovery.nullMessage) return record;
  const archived = recovery;
  const stored = record;
  return withKeyedLock(nullMessageLocks, storage, `${device.userId}:${device.deviceId}`, async () => {
    const nullMessage = await sendResetNullMessage(context, reset, device);
    return updateRetryRequest(storage, failedEnvelopeId, stored.retryId, stored.attempt, {
      recovery: { ...archived, nullMessage },
    });
  });
}

/** One null message check and send at a time for each device of a store. */
const nullMessageLocks = createKeyedLocks();

/** Send the null message of a reset, unless the limit for the device refuses it. */
async function sendResetNullMessage(
  context: RetryTerminalResetContext,
  reset: RetryTerminalResetSteps,
  device: RetryTerminalDevice
): Promise<RetryTerminalNullMessage> {
  const now = Date.now();
  if (await sentNullMessageSince(context, device, now - RETRY_TERMINAL_NULL_MESSAGE_INTERVAL_MS)) {
    return { outcome: 'limited', at: now };
  }
  try {
    await reset.sendNullMessage(device);
    return { outcome: 'sent', at: Date.now() };
  } catch (error) {
    rethrowRelayWorkStopped(error);
    // The archived session stays archived, so the next ordinary message
    // starts the new session.
    context.logger.warn('The null message of a session reset failed', {
      category: 'E2EE',
      data: {
        recipient: `${device.userId}:${device.deviceId}`,
        behavior: 'RETRY_TERMINAL_NULL_MESSAGE_FAILED',
        error: (error as Error).message,
      },
    });
    return { outcome: 'failed', at: Date.now() };
  }
}

/**
 * True when a stored reset sent a null message to the device at or after
 * the given time. The request records hold the send times, and they live
 * longer than the limit interval.
 */
async function sentNullMessageSince(
  context: RetryTerminalResetContext,
  device: RetryTerminalDevice,
  since: number
): Promise<boolean> {
  for (const id of await listRetryRequestIds(context.storage)) {
    let recovery: RetryTerminalRecovery | undefined;
    try {
      recovery = (await getRetryRequest(context.storage, id))?.recovery;
    } catch {
      // A corrupt record holds no send time. The scheduler reports it.
      continue;
    }
    if (
      recovery?.userId === device.userId &&
      recovery.deviceId === device.deviceId &&
      recovery.nullMessage?.outcome === 'sent' &&
      recovery.nullMessage.at >= since
    ) {
      return true;
    }
  }
  return false;
}

const failedGroups = new WeakMap<object, string>();

/**
 * Attach the raw group ID of a group message to an error that its decrypt
 * threw. The retry request record of the failed envelope then keeps the
 * group, so an `expired-content` or `posting-deadline` end marks the sender
 * key of that group.
 */
export function attachFailedGroup(error: unknown, groupId: string): void {
  if (typeof error === 'object' && error !== null) failedGroups.set(error, groupId);
}

/** The raw group ID that `attachFailedGroup` attached to an error. */
export function failedGroupOf(error: unknown): string | undefined {
  return typeof error === 'object' && error !== null ? failedGroups.get(error) : undefined;
}
