/**
 * The send log of the key-value store: resendable group content, its
 * recipient rows, and the persisted resend jobs.
 *
 * Key layout, under `@signal:send-log:`:
 *
 * - `payload:<send>` holds the encrypted payload.
 * - `created:<createdAt>:<send>` is a clear index of the store clock, so
 *   retention runs without a decryption.
 * - `recipient:<user>:<device>:<clientTimestamp>:<send>` is the row of one
 *   device. Its value is the clear resend count. The key is the by-device
 *   index that a retry request reads.
 * - `job:<jobId>` holds an encrypted resend job.
 *
 * The send ID, the user, the device, and the timestamps stay in the clear for
 * the indexes, as the message record keys do. The content and the group stay
 * encrypted. Each key component is URI-encoded, so it holds no `:`.
 *
 * Each write runs under one in-process lock per backend, and each change of
 * more than one key is one `atomicWrite`. A `check` operation guards each
 * value that a write read, so a second store over the same backend fails its
 * write instead of losing an update.
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
import type { ContentHint } from '../../../types';
import { base64ToBytes, bytesToBase64 } from '../../../internal/crypto/utils';
import { asBase64 } from '../../../types/utils';
import { createKeyedLocks, withKeyedLock } from '../../../utils/keyed-lock';
import { compareResendJobs, compareSendLogDevices, compareSendLogEntries } from '../send-log-order';
import type { KeyValueOperation, KeyValueStorage } from './storage';

const PREFIX = '@signal:send-log:';
const PAYLOAD_PREFIX = `${PREFIX}payload:`;
const CREATED_PREFIX = `${PREFIX}created:`;
const RECIPIENT_PREFIX = `${PREFIX}recipient:`;
const JOB_PREFIX = `${PREFIX}job:`;

/** One lock per backend, so two stores over one backend in one process take turns. */
const sendLogLocks = createKeyedLocks();
const SEND_LOG_LOCK = 'send-log';

/** The encrypted form of a payload. */
interface StoredPayload {
  clientMessageId: string;
  groupId: string;
  clientTimestamp: number;
  contentHint: ContentHint;
  plaintext: string;
  createdAt: number;
  sendComplete: boolean;
}

/** A recipient row as its key names it. */
interface RowKey extends SendLogDevice {
  key: string;
  clientMessageId: string;
  clientTimestamp: number;
}

/** The value cipher of the owning store. */
export interface KeyValueSendLogCipher {
  encrypt(plaintext: string): Promise<string>;
  decrypt(encrypted: string): Promise<string>;
}

function component(value: string): string {
  return encodeURIComponent(value);
}

function payloadKey(clientMessageId: string): string {
  return `${PAYLOAD_PREFIX}${component(clientMessageId)}`;
}

function createdKey(createdAt: number, clientMessageId: string): string {
  return `${CREATED_PREFIX}${createdAt}:${component(clientMessageId)}`;
}

function deviceTimestampPrefix(device: SendLogDevice, clientTimestamp: number): string {
  return `${RECIPIENT_PREFIX}${component(device.userId)}:${device.deviceId}:${clientTimestamp}:`;
}

function recipientKey(
  device: SendLogDevice,
  clientTimestamp: number,
  clientMessageId: string
): string {
  return `${deviceTimestampPrefix(device, clientTimestamp)}${component(clientMessageId)}`;
}

function jobKey(jobId: string): string {
  return `${JOB_PREFIX}${component(jobId)}`;
}

function parseRowKey(key: string): RowKey | null {
  if (!key.startsWith(RECIPIENT_PREFIX)) return null;
  const parts = key.slice(RECIPIENT_PREFIX.length).split(':');
  if (parts.length !== 4) return null;
  const [userId, deviceId, clientTimestamp, clientMessageId] = parts as [
    string,
    string,
    string,
    string,
  ];
  return {
    key,
    userId: decodeURIComponent(userId),
    deviceId: Number(deviceId),
    clientTimestamp: Number(clientTimestamp),
    clientMessageId: decodeURIComponent(clientMessageId),
  };
}

function rowKeysOf(allKeys: readonly string[], clientMessageId: string): RowKey[] {
  const rows: RowKey[] = [];
  for (const key of allKeys) {
    const row = parseRowKey(key);
    if (row?.clientMessageId === clientMessageId) rows.push(row);
  }
  return rows;
}

function createdKeysOf(allKeys: readonly string[], clientMessageId: string): string[] {
  const suffix = `:${component(clientMessageId)}`;
  return allKeys.filter((key) => key.startsWith(CREATED_PREFIX) && key.endsWith(suffix));
}

function parseCount(value: string): number {
  const count = Number(value);
  if (!Number.isSafeInteger(count) || count < 0) {
    throw new Error('Send log row holds an invalid resend count');
  }
  return count;
}

/**
 * The final operations of one write. A later operation on a key replaces an
 * earlier one, and every `check` runs before every write.
 */
class WriteBatch {
  private readonly checks: KeyValueOperation[] = [];
  private readonly writes = new Map<string, KeyValueOperation>();

  check(key: string, expectedValue: string | null): void {
    this.checks.push({ type: 'check', key, expectedValue });
  }

  set(key: string, value: string): void {
    this.writes.set(key, { type: 'set', key, value });
  }

  remove(key: string): void {
    this.writes.set(key, { type: 'remove', key });
  }

  async commit(backend: KeyValueStorage): Promise<void> {
    if (this.writes.size === 0) return;
    await backend.atomicWrite([...this.checks, ...this.writes.values()]);
  }
}

export class KeyValueSendLog implements SendLogStore {
  constructor(
    private readonly backend: KeyValueStorage,
    private readonly cipher: KeyValueSendLogCipher
  ) {}

  async storeSendLogEntry(
    payload: NewSendLogPayload,
    recipients: readonly SendLogDevice[]
  ): Promise<void> {
    await this.write(async () => {
      const allKeys = await this.backend.getAllKeys();
      const key = payloadKey(payload.clientMessageId);
      const batch = new WriteBatch();
      batch.check(key, await this.backend.getItem(key));
      this.removeEntry(batch, allKeys, payload.clientMessageId);
      const stored: SendLogPayload = { ...payload, createdAt: Date.now(), sendComplete: false };
      await this.setPayload(batch, stored);
      batch.set(createdKey(stored.createdAt, stored.clientMessageId), '');
      for (const device of recipients) {
        batch.set(recipientKey(device, stored.clientTimestamp, stored.clientMessageId), '0');
      }
      await batch.commit(this.backend);
    });
  }

  async appendSendLogRecipients(
    clientMessageId: string,
    recipients: readonly SendLogDevice[]
  ): Promise<void> {
    await this.write(async () => {
      const read = await this.readPayload(clientMessageId);
      if (!read) return;
      const batch = new WriteBatch();
      batch.check(payloadKey(clientMessageId), read.raw);
      for (const device of recipients) {
        const key = recipientKey(device, read.payload.clientTimestamp, clientMessageId);
        if ((await this.backend.getItem(key)) === null) batch.set(key, '0');
      }
      await batch.commit(this.backend);
    });
  }

  async markSendLogComplete(clientMessageId: string): Promise<void> {
    await this.write(async () => {
      const read = await this.readPayload(clientMessageId);
      if (!read) return;
      const allKeys = await this.backend.getAllKeys();
      const batch = new WriteBatch();
      batch.check(payloadKey(clientMessageId), read.raw);
      if (rowKeysOf(allKeys, clientMessageId).length === 0) {
        this.removeEntry(batch, allKeys, clientMessageId);
      } else {
        await this.setPayload(batch, { ...read.payload, sendComplete: true });
      }
      await batch.commit(this.backend);
    });
  }

  async getSendLogEntry(
    clientMessageId: string,
    recipient: SendLogDevice
  ): Promise<SendLogEntry | null> {
    const read = await this.readPayload(clientMessageId);
    if (!read) return null;
    const { clientTimestamp } = read.payload;
    const value = await this.backend.getItem(
      recipientKey(recipient, clientTimestamp, clientMessageId)
    );
    if (value === null) return null;
    return {
      payload: read.payload,
      recipient: {
        clientMessageId,
        userId: recipient.userId,
        deviceId: recipient.deviceId,
        clientTimestamp,
        responses: parseCount(value),
      },
    };
  }

  async findSendLogEntries(
    recipient: SendLogDevice,
    clientTimestamp: number
  ): Promise<SendLogEntry[]> {
    const entries: SendLogEntry[] = [];
    const allKeys = await this.backend.getAllKeys();
    for (const row of this.deviceRows(allKeys, recipient, clientTimestamp)) {
      const entry = await this.getSendLogEntry(row.clientMessageId, recipient);
      if (entry) entries.push(entry);
    }
    return entries.sort(compareSendLogEntries);
  }

  async getSendLogRecipients(clientMessageId: string): Promise<SendLogRecipient[]> {
    const rows: SendLogRecipient[] = [];
    for (const row of rowKeysOf(await this.backend.getAllKeys(), clientMessageId)) {
      const value = await this.backend.getItem(row.key);
      if (value === null) continue;
      rows.push({
        clientMessageId,
        userId: row.userId,
        deviceId: row.deviceId,
        clientTimestamp: row.clientTimestamp,
        responses: parseCount(value),
      });
    }
    return rows.sort(compareSendLogDevices);
  }

  async deleteSendLogRecipient(
    clientMessageId: string,
    recipient: SendLogDevice
  ): Promise<boolean> {
    return this.write(async () => {
      const read = await this.readPayload(clientMessageId);
      if (!read) return false;
      const key = recipientKey(recipient, read.payload.clientTimestamp, clientMessageId);
      const value = await this.backend.getItem(key);
      if (value === null) return false;
      const allKeys = await this.backend.getAllKeys();
      const batch = new WriteBatch();
      batch.check(payloadKey(clientMessageId), read.raw);
      batch.check(key, value);
      batch.remove(key);
      this.removeIfFinished(batch, allKeys, read.payload, new Set([key]));
      await batch.commit(this.backend);
      return true;
    });
  }

  async deleteSendLogRecipientsByTimestamp(
    recipient: SendLogDevice,
    clientTimestamps: readonly number[]
  ): Promise<number> {
    return this.write(async () => {
      const allKeys = await this.backend.getAllKeys();
      const removed = new Set<string>();
      const touched = new Set<string>();
      for (const clientTimestamp of new Set(clientTimestamps)) {
        for (const row of this.deviceRows(allKeys, recipient, clientTimestamp)) {
          removed.add(row.key);
          touched.add(row.clientMessageId);
        }
      }
      const batch = new WriteBatch();
      for (const key of removed) {
        batch.check(key, await this.backend.getItem(key));
        batch.remove(key);
      }
      for (const clientMessageId of touched) {
        const read = await this.readPayload(clientMessageId);
        if (!read) continue;
        batch.check(payloadKey(clientMessageId), read.raw);
        this.removeIfFinished(batch, allKeys, read.payload, removed);
      }
      await batch.commit(this.backend);
      return removed.size;
    });
  }

  async incrementSendLogResendCount(
    clientMessageId: string,
    recipient: SendLogDevice
  ): Promise<number | null> {
    return this.write(async () => {
      const read = await this.readPayload(clientMessageId);
      if (!read) return null;
      const key = recipientKey(recipient, read.payload.clientTimestamp, clientMessageId);
      const value = await this.backend.getItem(key);
      if (value === null) return null;
      const responses = parseCount(value) + 1;
      const batch = new WriteBatch();
      batch.check(key, value);
      batch.set(key, String(responses));
      await batch.commit(this.backend);
      return responses;
    });
  }

  async deleteSendLogEntry(clientMessageId: string): Promise<boolean> {
    return this.write(async () => {
      const key = payloadKey(clientMessageId);
      const raw = await this.backend.getItem(key);
      if (raw === null) return false;
      const batch = new WriteBatch();
      batch.check(key, raw);
      this.removeEntry(batch, await this.backend.getAllKeys(), clientMessageId);
      await batch.commit(this.backend);
      return true;
    });
  }

  async deleteExpiredSendLog(maxAgeMs: number): Promise<number> {
    return this.write(async () => {
      const cutoff = Date.now() - maxAgeMs;
      const allKeys = await this.backend.getAllKeys();
      const expired = new Set<string>();
      for (const key of allKeys) {
        if (!key.startsWith(CREATED_PREFIX)) continue;
        const [createdAt, clientMessageId] = key.slice(CREATED_PREFIX.length).split(':');
        if (Number(createdAt) < cutoff && clientMessageId !== undefined) {
          expired.add(decodeURIComponent(clientMessageId));
        }
      }
      const present = new Set(allKeys);
      const batch = new WriteBatch();
      let deleted = 0;
      for (const clientMessageId of expired) {
        if (present.has(payloadKey(clientMessageId))) deleted++;
        this.removeEntry(batch, allKeys, clientMessageId);
      }
      for (const key of allKeys) {
        if (!key.startsWith(JOB_PREFIX)) continue;
        const raw = await this.backend.getItem(key);
        if (raw === null) continue;
        if ((await this.decodeJob(raw)).createdAt < cutoff) {
          batch.check(key, raw);
          batch.remove(key);
        }
      }
      await batch.commit(this.backend);
      return deleted;
    });
  }

  async clearSendLog(): Promise<number> {
    return this.write(async () => {
      const keys = (await this.backend.getAllKeys()).filter((key) => key.startsWith(PREFIX));
      const batch = new WriteBatch();
      for (const key of keys) batch.remove(key);
      await batch.commit(this.backend);
      return keys.filter((key) => key.startsWith(PAYLOAD_PREFIX)).length;
    });
  }

  async storeResendJob(job: SendLogResendJob): Promise<void> {
    await this.write(async () => {
      const key = jobKey(job.jobId);
      const raw = await this.backend.getItem(key);
      const createdAt = raw === null ? Date.now() : (await this.decodeJob(raw)).createdAt;
      const batch = new WriteBatch();
      batch.check(key, raw);
      batch.set(key, await this.cipher.encrypt(JSON.stringify({ ...job, createdAt })));
      await batch.commit(this.backend);
    });
  }

  async getResendJob(jobId: string): Promise<SendLogResendJob | null> {
    const raw = await this.backend.getItem(jobKey(jobId));
    return raw === null ? null : this.decodeJob(raw);
  }

  async getPendingResendJobs(): Promise<SendLogResendJob[]> {
    const jobs: SendLogResendJob[] = [];
    for (const key of await this.backend.getAllKeys()) {
      if (!key.startsWith(JOB_PREFIX)) continue;
      const raw = await this.backend.getItem(key);
      if (raw === null) continue;
      const job = await this.decodeJob(raw);
      if (job.state === 'pending') jobs.push(job);
    }
    return jobs.sort(compareResendJobs);
  }

  async completeResendJob(
    jobId: string,
    state: Exclude<SendLogResendJobState, 'pending'>
  ): Promise<void> {
    await this.write(async () => {
      const key = jobKey(jobId);
      const raw = await this.backend.getItem(key);
      if (raw === null) return;
      const batch = new WriteBatch();
      batch.check(key, raw);
      const job = await this.decodeJob(raw);
      batch.set(key, await this.cipher.encrypt(JSON.stringify({ ...job, state })));
      await batch.commit(this.backend);
    });
  }

  private write<T>(operation: () => Promise<T>): Promise<T> {
    return withKeyedLock(sendLogLocks, this.backend, SEND_LOG_LOCK, operation);
  }

  private async readPayload(
    clientMessageId: string
  ): Promise<{ raw: string; payload: SendLogPayload } | null> {
    const raw = await this.backend.getItem(payloadKey(clientMessageId));
    if (raw === null) return null;
    const stored = JSON.parse(await this.cipher.decrypt(raw)) as StoredPayload;
    return { raw, payload: { ...stored, plaintext: base64ToBytes(asBase64(stored.plaintext)) } };
  }

  private async setPayload(batch: WriteBatch, payload: SendLogPayload): Promise<void> {
    const stored: StoredPayload = {
      clientMessageId: payload.clientMessageId,
      groupId: payload.groupId,
      clientTimestamp: payload.clientTimestamp,
      contentHint: payload.contentHint,
      plaintext: bytesToBase64(payload.plaintext),
      createdAt: payload.createdAt,
      sendComplete: payload.sendComplete,
    };
    batch.set(
      payloadKey(payload.clientMessageId),
      await this.cipher.encrypt(JSON.stringify(stored))
    );
  }

  private async decodeJob(raw: string): Promise<SendLogResendJob> {
    return JSON.parse(await this.cipher.decrypt(raw)) as SendLogResendJob;
  }

  private deviceRows(
    allKeys: readonly string[],
    device: SendLogDevice,
    clientTimestamp: number
  ): RowKey[] {
    const prefix = deviceTimestampPrefix(device, clientTimestamp);
    const rows: RowKey[] = [];
    for (const key of allKeys) {
      if (!key.startsWith(prefix)) continue;
      const row = parseRowKey(key);
      if (row) rows.push(row);
    }
    return rows;
  }

  /** Remove the payload, its index key, and its rows. */
  private removeEntry(
    batch: WriteBatch,
    allKeys: readonly string[],
    clientMessageId: string
  ): void {
    batch.remove(payloadKey(clientMessageId));
    for (const key of createdKeysOf(allKeys, clientMessageId)) batch.remove(key);
    for (const row of rowKeysOf(allKeys, clientMessageId)) batch.remove(row.key);
  }

  /** Remove a finished payload when every one of its rows is in `removed`. */
  private removeIfFinished(
    batch: WriteBatch,
    allKeys: readonly string[],
    payload: SendLogPayload,
    removed: ReadonlySet<string>
  ): void {
    if (!payload.sendComplete) return;
    const rows = rowKeysOf(allKeys, payload.clientMessageId);
    if (rows.some((row) => !removed.has(row.key))) return;
    this.removeEntry(batch, allKeys, payload.clientMessageId);
  }
}
