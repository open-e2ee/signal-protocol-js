/**
 * The send log of the in-memory store: resendable group content, its
 * recipient rows keyed by device, and the persisted resend jobs.
 *
 * Each value crosses the same ownership boundary as in a durable store. A
 * read returns a copy, and a write stores a copy.
 */

import type {
  NewSendLogPayload,
  SendLogDevice,
  SendLogEntry,
  SendLogPayload,
  SendLogRecipient,
  SendLogResendJob,
  SendLogResendJobState,
  SendLogStore,
} from '../../../types/api';
import { cloneProtocolState } from '../../../internal/crypto/utils';
import { compareResendJobs, compareSendLogDevices, compareSendLogEntries } from '../send-log-order';
import type { StoreFailureController } from './failures';

function deviceKey(device: SendLogDevice): string {
  return JSON.stringify([device.userId, device.deviceId]);
}

export class MemorySendLog implements SendLogStore {
  private readonly payloads = new Map<string, SendLogPayload>();
  private readonly recipients = new Map<string, Map<string, SendLogRecipient>>();
  private readonly resendJobs = new Map<string, SendLogResendJob>();

  constructor(private readonly failures: StoreFailureController) {}

  /** Delete every entry and job without a write check. The owning store's reset calls it. */
  clear(): void {
    this.payloads.clear();
    this.recipients.clear();
    this.resendJobs.clear();
  }

  async storeSendLogEntry(
    payload: NewSendLogPayload,
    recipients: readonly SendLogDevice[]
  ): Promise<void> {
    this.failures.beforeWrite('storeSendLogEntry');
    const stored: SendLogPayload = {
      ...cloneProtocolState(payload),
      createdAt: Date.now(),
      sendComplete: false,
    };
    this.removePayload(payload.clientMessageId);
    this.payloads.set(payload.clientMessageId, stored);
    this.addRecipients(stored, recipients);
  }

  async appendSendLogRecipients(
    clientMessageId: string,
    recipients: readonly SendLogDevice[]
  ): Promise<void> {
    this.failures.beforeWrite('appendSendLogRecipients');
    const payload = this.payloads.get(clientMessageId);
    if (payload) this.addRecipients(payload, recipients);
  }

  async markSendLogComplete(clientMessageId: string): Promise<void> {
    this.failures.beforeWrite('markSendLogComplete');
    const payload = this.payloads.get(clientMessageId);
    if (!payload) return;
    payload.sendComplete = true;
    this.removeFinishedPayload(clientMessageId);
  }

  async getSendLogEntry(
    clientMessageId: string,
    recipient: SendLogDevice
  ): Promise<SendLogEntry | null> {
    return this.entry(clientMessageId, recipient);
  }

  async findSendLogEntries(
    recipient: SendLogDevice,
    clientTimestamp: number
  ): Promise<SendLogEntry[]> {
    const entries: SendLogEntry[] = [];
    for (const [clientMessageId, payload] of this.payloads) {
      if (payload.clientTimestamp !== clientTimestamp) continue;
      const entry = this.entry(clientMessageId, recipient);
      if (entry) entries.push(entry);
    }
    return entries.sort(compareSendLogEntries);
  }

  async getSendLogRecipients(clientMessageId: string): Promise<SendLogRecipient[]> {
    const rows = this.recipients.get(clientMessageId);
    if (!rows) return [];
    return [...rows.values()].map((row) => cloneProtocolState(row)).sort(compareSendLogDevices);
  }

  async deleteSendLogRecipient(
    clientMessageId: string,
    recipient: SendLogDevice
  ): Promise<boolean> {
    this.failures.beforeWrite('deleteSendLogRecipient');
    return this.removeRecipient(clientMessageId, recipient);
  }

  async deleteSendLogRecipientsByTimestamp(
    recipient: SendLogDevice,
    clientTimestamps: readonly number[]
  ): Promise<number> {
    this.failures.beforeWrite('deleteSendLogRecipientsByTimestamp');
    const timestamps = new Set(clientTimestamps);
    let deleted = 0;
    for (const [clientMessageId, payload] of [...this.payloads]) {
      if (!timestamps.has(payload.clientTimestamp)) continue;
      if (this.removeRecipient(clientMessageId, recipient)) deleted++;
    }
    return deleted;
  }

  async incrementSendLogResendCount(
    clientMessageId: string,
    recipient: SendLogDevice
  ): Promise<number | null> {
    this.failures.beforeWrite('incrementSendLogResendCount');
    const row = this.recipients.get(clientMessageId)?.get(deviceKey(recipient));
    if (!row) return null;
    row.responses += 1;
    return row.responses;
  }

  async deleteSendLogEntry(clientMessageId: string): Promise<boolean> {
    this.failures.beforeWrite('deleteSendLogEntry');
    return this.removePayload(clientMessageId);
  }

  async deleteExpiredSendLog(maxAgeMs: number): Promise<number> {
    this.failures.beforeWrite('deleteExpiredSendLog');
    const cutoff = Date.now() - maxAgeMs;
    let deleted = 0;
    for (const [clientMessageId, payload] of [...this.payloads]) {
      if (payload.createdAt < cutoff && this.removePayload(clientMessageId)) deleted++;
    }
    for (const [jobId, job] of [...this.resendJobs]) {
      if (job.createdAt < cutoff) this.resendJobs.delete(jobId);
    }
    return deleted;
  }

  async clearSendLog(): Promise<number> {
    this.failures.beforeWrite('clearSendLog');
    const deleted = this.payloads.size;
    this.clear();
    return deleted;
  }

  async storeResendJob(job: SendLogResendJob): Promise<void> {
    this.failures.beforeWrite('storeResendJob');
    const createdAt = this.resendJobs.get(job.jobId)?.createdAt ?? Date.now();
    this.resendJobs.set(job.jobId, { ...cloneProtocolState(job), createdAt });
  }

  async getResendJob(jobId: string): Promise<SendLogResendJob | null> {
    const job = this.resendJobs.get(jobId);
    return job ? cloneProtocolState(job) : null;
  }

  async getPendingResendJobs(): Promise<SendLogResendJob[]> {
    return [...this.resendJobs.values()]
      .filter((job) => job.state === 'pending')
      .map((job) => cloneProtocolState(job))
      .sort(compareResendJobs);
  }

  async completeResendJob(
    jobId: string,
    state: Exclude<SendLogResendJobState, 'pending'>
  ): Promise<void> {
    this.failures.beforeWrite('completeResendJob');
    const job = this.resendJobs.get(jobId);
    if (job) job.state = state;
  }

  private entry(clientMessageId: string, device: SendLogDevice): SendLogEntry | null {
    const payload = this.payloads.get(clientMessageId);
    const recipient = this.recipients.get(clientMessageId)?.get(deviceKey(device));
    if (!payload || !recipient) return null;
    return { payload: cloneProtocolState(payload), recipient: cloneProtocolState(recipient) };
  }

  /** Add a row for each device that has none. An existing row is kept. */
  private addRecipients(payload: SendLogPayload, devices: readonly SendLogDevice[]): void {
    let rows = this.recipients.get(payload.clientMessageId);
    if (!rows) {
      rows = new Map();
      this.recipients.set(payload.clientMessageId, rows);
    }
    for (const device of devices) {
      const key = deviceKey(device);
      if (rows.has(key)) continue;
      rows.set(key, {
        clientMessageId: payload.clientMessageId,
        userId: device.userId,
        deviceId: device.deviceId,
        clientTimestamp: payload.clientTimestamp,
        responses: 0,
      });
    }
  }

  private removePayload(clientMessageId: string): boolean {
    this.recipients.delete(clientMessageId);
    return this.payloads.delete(clientMessageId);
  }

  /** Delete a finished payload that has no recipient row. */
  private removeFinishedPayload(clientMessageId: string): void {
    if (!this.payloads.get(clientMessageId)?.sendComplete) return;
    if ((this.recipients.get(clientMessageId)?.size ?? 0) > 0) return;
    this.removePayload(clientMessageId);
  }

  private removeRecipient(clientMessageId: string, device: SendLogDevice): boolean {
    const rows = this.recipients.get(clientMessageId);
    if (!rows?.delete(deviceKey(device))) return false;
    if (rows.size === 0) this.recipients.delete(clientMessageId);
    this.removeFinishedPayload(clientMessageId);
    return true;
  }
}
