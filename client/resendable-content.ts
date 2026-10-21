/**
 * Resendable content and its retention.
 *
 * A sender keeps the plaintext of a resendable message to answer a retry
 * request: each group send in the send log, and each pairwise message in a
 * MessageRecord. The retention runs from the store clock when the store
 * first wrote the content, and a retry never extends it. This module
 * enforces the retention at each send log lookup and at each sweep. A sweep
 * runs at client creation, at stop, and before the first resendable group
 * send of each day.
 *
 * When content recovery is off, the client keeps no resendable content, and
 * the start of each client clears the content that an earlier policy kept.
 * A metadata marker records the clear, so a start with nothing kept since
 * the last clear reads one value and scans nothing.
 *
 * An E2EE delivery receipt from a device deletes its row (see
 * `DeliveryStatusTracker`). A Relay delivery receipt deletes nothing, because
 * a device also acknowledges a copy that it could not decrypt.
 *
 * Deletion in an encrypted store is logical. The retention bounds the time
 * that the client keeps the content. It does not promise erasure from the
 * storage medium.
 *
 * @internal
 */

import type {
  SendLogDevice,
  SendLogEntry,
  SignalProtocolLocalStore,
} from '../types/api';

const DAY_MS = 24 * 60 * 60 * 1_000;

/**
 * The metadata key that records a clear of all resendable content. Its
 * presence means the store kept no resendable content since that clear.
 */
export const RESENDABLE_CONTENT_CLEARED_MARKER = 'resendable-content:cleared';

type ResendableContentStore = Pick<
  SignalProtocolLocalStore,
  | 'getMetadata'
  | 'setMetadata'
  | 'deleteMetadata'
  | 'clearAllMessageRecords'
  | 'clearSendLog'
  | 'deleteExpiredSendLog'
  | 'deleteExpiredMessageRecords'
  | 'getSendLogEntry'
  | 'findSendLogEntries'
  | 'getSendLogRecipients'
  | 'deleteSendLogEntry'
  | 'incrementSendLogResendCount'
>;

/** The number of entries and records that one sweep deleted. */
export interface ResendableContentSweep {
  readonly sendLogEntries: number;
  readonly messageRecords: number;
}

export class ResendableContent {
  /** The day of the last sweep, in whole days since the epoch. */
  private sweptDay: number | undefined;

  constructor(
    private readonly store: ResendableContentStore,
    /** The retention of the content, from `protocol.contentRecovery`. */
    public readonly retentionMs: number,
    private readonly now: () => number = Date.now
  ) {}

  /** True when content that the store wrote at `createdAt` is past the retention. */
  public isExpired(createdAt: number): boolean {
    return this.now() - createdAt > this.retentionMs;
  }

  /** Delete each send log entry and each message record past the retention. */
  public async sweep(): Promise<ResendableContentSweep> {
    this.sweptDay = Math.floor(this.now() / DAY_MS);
    const sendLogEntries = await this.store.deleteExpiredSendLog(this.retentionMs);
    const messageRecords = await this.store.deleteExpiredMessageRecords(this.retentionMs);
    return { sendLogEntries, messageRecords };
  }

  /**
   * Sweep when no sweep ran today. A long-running client that never stops
   * still deletes expired content each day that it sends.
   */
  public async sweepDaily(): Promise<ResendableContentSweep | null> {
    return this.sweptDay === Math.floor(this.now() / DAY_MS) ? null : this.sweep();
  }

  /**
   * The logged entries that a retry request from one device names, after
   * expired entries are deleted. The first message ID with a row for the
   * device wins. With none, every entry of the device at the client
   * timestamp answers, ordered by `clientMessageId`. Only the row of this
   * exact device authorizes a resend.
   */
  public async lookup(
    device: SendLogDevice,
    clientMessageIds: readonly (string | undefined)[],
    clientTimestamp: number
  ): Promise<SendLogEntry[]> {
    await this.store.deleteExpiredSendLog(this.retentionMs);
    for (const clientMessageId of clientMessageIds) {
      if (clientMessageId === undefined) continue;
      const entry = await this.store.getSendLogEntry(clientMessageId, device);
      if (entry) return [entry];
    }
    return this.store.findSendLogEntries(device, clientTimestamp);
  }

  /**
   * The logged entry of one send and the row of one device, after expired
   * entries are deleted, or null when the device has no row.
   */
  public async entry(clientMessageId: string, device: SendLogDevice): Promise<SendLogEntry | null> {
    await this.store.deleteExpiredSendLog(this.retentionMs);
    return this.store.getSendLogEntry(clientMessageId, device);
  }

  /**
   * Count one resend of a logged send to one device. The count survives a
   * restart. Returns the new count, or null when the device has no row.
   */
  public async countResend(clientMessageId: string, device: SendLogDevice): Promise<number | null> {
    return this.store.incrementSendLogResendCount(clientMessageId, device);
  }

  /**
   * The devices that have not confirmed a logged send with an E2EE delivery
   * receipt, after expired entries are deleted.
   */
  public async pendingRecipients(clientMessageId: string): Promise<SendLogDevice[]> {
    await this.store.deleteExpiredSendLog(this.retentionMs);
    return (await this.store.getSendLogRecipients(clientMessageId)).map(({ userId, deviceId }) => ({
      userId,
      deviceId,
    }));
  }

  /**
   * Delete all resendable content, for a client with content recovery off.
   * The clear is skipped when the store kept no content since the last
   * clear. The marker is written only after the clear succeeds, and a
   * failure propagates.
   *
   * @returns The deleted entries and records, or null for a skipped clear
   */
  public async clear(): Promise<ResendableContentSweep | null> {
    if ((await this.store.getMetadata(RESENDABLE_CONTENT_CLEARED_MARKER)) !== null) return null;
    const messageRecords = await this.store.clearAllMessageRecords();
    const sendLogEntries = await this.store.clearSendLog();
    await this.store.setMetadata(RESENDABLE_CONTENT_CLEARED_MARKER, String(this.now()));
    return { sendLogEntries, messageRecords };
  }

  /**
   * Record that the client can keep resendable content, so the next clear
   * runs. Call it before the client writes any content.
   */
  public async keepContent(): Promise<void> {
    await this.store.deleteMetadata(RESENDABLE_CONTENT_CLEARED_MARKER);
  }

  /** Delete the logged content of one send and its rows. */
  public async forget(clientMessageId: string): Promise<boolean> {
    return this.store.deleteSendLogEntry(clientMessageId);
  }
}
