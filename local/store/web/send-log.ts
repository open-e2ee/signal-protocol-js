/**
 * The send log of the IndexedDB store: resendable group content, its
 * recipient rows, and the persisted resend jobs.
 *
 * - `sendLogPayloads` holds one payload per send. The group, the content
 *   hint, and the content are encrypted in `data`. The send ID, the client
 *   timestamp, the store clock, and the finished flag stay in the clear.
 * - `sendLogRecipients` holds one row per device. The row is clear: the send
 *   ID, the user, the device, the client timestamp, and the resend count.
 *   The `by-device` index serves a retry request.
 * - `sendLogResendJobs` holds the resend jobs in the clear. A job holds no
 *   content, and each identifier in it is also clear in a recipient row.
 *
 * A transaction must not wait for anything other than IndexedDB, or it
 * commits early. Each write therefore encrypts before its transaction opens,
 * and each read decrypts after its transaction ends. Each change of more
 * than one record is one transaction.
 */

import type { DBSchema, IDBPDatabase, IDBPTransaction } from 'idb';

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
import { compareResendJobs, compareSendLogDevices, compareSendLogEntries } from '../send-log-order';

/** The IndexedDB key of one recipient row. */
type SendLogRecipientId = [clientMessageId: string, userId: string, deviceId: number];

/** The `by-device` index key of one recipient row. */
type SendLogDeviceTimestamp = [userId: string, deviceId: number, clientTimestamp: number];

interface StoredSendLogPayload {
  clientMessageId: string;
  clientTimestamp: number;
  createdAt: number;
  sendComplete: boolean;
  /** The encrypted `SendLogPayloadContent`. */
  data: Uint8Array;
}

/** The encrypted part of a payload. */
interface SendLogPayloadContent {
  groupId: string;
  contentHint: ContentHint;
  /** Base64 of the plaintext of the send. */
  plaintext: string;
}

export interface SendLogDBSchema extends DBSchema {
  sendLogPayloads: {
    key: string;
    value: StoredSendLogPayload;
    indexes: { 'by-created': number };
  };
  sendLogRecipients: {
    key: SendLogRecipientId;
    value: SendLogRecipient;
    indexes: { 'by-device': SendLogDeviceTimestamp };
  };
  sendLogResendJobs: {
    key: string;
    value: SendLogResendJob;
    indexes: { 'by-state': SendLogResendJobState; 'by-created': number };
  };
}

/** The value cipher of the owning store. */
export interface IndexedDbSendLogCipher {
  encrypt(plaintext: string): Promise<Uint8Array>;
  decrypt(encrypted: Uint8Array): Promise<string>;
}

/** Create the send log object stores that the database does not have. */
export function upgradeSendLogStores(db: IDBPDatabase<SendLogDBSchema>): void {
  if (!db.objectStoreNames.contains('sendLogPayloads')) {
    const payloads = db.createObjectStore('sendLogPayloads', { keyPath: 'clientMessageId' });
    payloads.createIndex('by-created', 'createdAt');
  }
  if (!db.objectStoreNames.contains('sendLogRecipients')) {
    const recipients = db.createObjectStore('sendLogRecipients', {
      keyPath: ['clientMessageId', 'userId', 'deviceId'],
    });
    recipients.createIndex('by-device', ['userId', 'deviceId', 'clientTimestamp']);
  }
  if (!db.objectStoreNames.contains('sendLogResendJobs')) {
    const jobs = db.createObjectStore('sendLogResendJobs', { keyPath: 'jobId' });
    jobs.createIndex('by-state', 'state');
    jobs.createIndex('by-created', 'createdAt');
  }
}

/** The send log object stores, for a store reset. */
export const SEND_LOG_STORE_NAMES = [
  'sendLogPayloads',
  'sendLogRecipients',
  'sendLogResendJobs',
] as const;

/** Every recipient row of one send: the keys from `[send]` to `[send, []]`. */
function rowsOf(clientMessageId: string): IDBKeyRange {
  return IDBKeyRange.bound([clientMessageId], [clientMessageId, []]);
}

function rowId(clientMessageId: string, device: SendLogDevice): SendLogRecipientId {
  return [clientMessageId, device.userId, device.deviceId];
}

export class IndexedDbSendLog implements SendLogStore {
  constructor(
    private readonly database: () => IDBPDatabase<SendLogDBSchema>,
    private readonly cipher: IndexedDbSendLogCipher
  ) {}

  async storeSendLogEntry(
    payload: NewSendLogPayload,
    recipients: readonly SendLogDevice[]
  ): Promise<void> {
    const content: SendLogPayloadContent = {
      groupId: payload.groupId,
      contentHint: payload.contentHint,
      plaintext: bytesToBase64(payload.plaintext),
    };
    const data = await this.cipher.encrypt(JSON.stringify(content));
    const tx = this.database().transaction(['sendLogPayloads', 'sendLogRecipients'], 'readwrite');
    const rows = tx.objectStore('sendLogRecipients');
    await rows.delete(rowsOf(payload.clientMessageId));
    await tx.objectStore('sendLogPayloads').put({
      clientMessageId: payload.clientMessageId,
      clientTimestamp: payload.clientTimestamp,
      createdAt: Date.now(),
      sendComplete: false,
      data,
    });
    for (const device of recipients) {
      await rows.put(this.newRow(payload.clientMessageId, payload.clientTimestamp, device));
    }
    await tx.done;
  }

  async appendSendLogRecipients(
    clientMessageId: string,
    recipients: readonly SendLogDevice[]
  ): Promise<void> {
    const tx = this.database().transaction(['sendLogPayloads', 'sendLogRecipients'], 'readwrite');
    const payload = await tx.objectStore('sendLogPayloads').get(clientMessageId);
    if (payload) {
      const rows = tx.objectStore('sendLogRecipients');
      for (const device of recipients) {
        if ((await rows.count(rowId(clientMessageId, device))) > 0) continue;
        await rows.put(this.newRow(clientMessageId, payload.clientTimestamp, device));
      }
    }
    await tx.done;
  }

  async markSendLogComplete(clientMessageId: string): Promise<void> {
    const tx = this.database().transaction(['sendLogPayloads', 'sendLogRecipients'], 'readwrite');
    const payloads = tx.objectStore('sendLogPayloads');
    const payload = await payloads.get(clientMessageId);
    if (payload) {
      if ((await tx.objectStore('sendLogRecipients').count(rowsOf(clientMessageId))) === 0) {
        await payloads.delete(clientMessageId);
      } else {
        await payloads.put({ ...payload, sendComplete: true });
      }
    }
    await tx.done;
  }

  async getSendLogEntry(
    clientMessageId: string,
    recipient: SendLogDevice
  ): Promise<SendLogEntry | null> {
    const tx = this.database().transaction(['sendLogPayloads', 'sendLogRecipients'], 'readonly');
    const payload = await tx.objectStore('sendLogPayloads').get(clientMessageId);
    const row = await tx.objectStore('sendLogRecipients').get(rowId(clientMessageId, recipient));
    await tx.done;
    if (!payload || !row) return null;
    return { payload: await this.openPayload(payload), recipient: row };
  }

  async findSendLogEntries(
    recipient: SendLogDevice,
    clientTimestamp: number
  ): Promise<SendLogEntry[]> {
    const tx = this.database().transaction(['sendLogPayloads', 'sendLogRecipients'], 'readonly');
    const rows = await tx
      .objectStore('sendLogRecipients')
      .index('by-device')
      .getAll([recipient.userId, recipient.deviceId, clientTimestamp]);
    const found: Array<{ payload: StoredSendLogPayload; row: SendLogRecipient }> = [];
    for (const row of rows) {
      const payload = await tx.objectStore('sendLogPayloads').get(row.clientMessageId);
      if (payload) found.push({ payload, row });
    }
    await tx.done;
    const entries: SendLogEntry[] = [];
    for (const { payload, row } of found) {
      entries.push({ payload: await this.openPayload(payload), recipient: row });
    }
    return entries.sort(compareSendLogEntries);
  }

  async getSendLogRecipients(clientMessageId: string): Promise<SendLogRecipient[]> {
    const rows = await this.database().getAll('sendLogRecipients', rowsOf(clientMessageId));
    return rows.sort(compareSendLogDevices);
  }

  async deleteSendLogRecipient(
    clientMessageId: string,
    recipient: SendLogDevice
  ): Promise<boolean> {
    const tx = this.database().transaction(['sendLogPayloads', 'sendLogRecipients'], 'readwrite');
    const rows = tx.objectStore('sendLogRecipients');
    const id = rowId(clientMessageId, recipient);
    const deleted = (await rows.count(id)) > 0;
    if (deleted) {
      await rows.delete(id);
      await this.deleteIfFinished(tx, clientMessageId);
    }
    await tx.done;
    return deleted;
  }

  async deleteSendLogRecipientsByTimestamp(
    recipient: SendLogDevice,
    clientTimestamps: readonly number[]
  ): Promise<number> {
    const tx = this.database().transaction(['sendLogPayloads', 'sendLogRecipients'], 'readwrite');
    const rows = tx.objectStore('sendLogRecipients');
    let deleted = 0;
    for (const clientTimestamp of new Set(clientTimestamps)) {
      const found = await rows
        .index('by-device')
        .getAll([recipient.userId, recipient.deviceId, clientTimestamp]);
      for (const row of found) {
        await rows.delete(rowId(row.clientMessageId, row));
        await this.deleteIfFinished(tx, row.clientMessageId);
        deleted++;
      }
    }
    await tx.done;
    return deleted;
  }

  async incrementSendLogResendCount(
    clientMessageId: string,
    recipient: SendLogDevice
  ): Promise<number | null> {
    const tx = this.database().transaction('sendLogRecipients', 'readwrite');
    const row = await tx.store.get(rowId(clientMessageId, recipient));
    let responses: number | null = null;
    if (row) {
      responses = row.responses + 1;
      await tx.store.put({ ...row, responses });
    }
    await tx.done;
    return responses;
  }

  async deleteSendLogEntry(clientMessageId: string): Promise<boolean> {
    const tx = this.database().transaction(['sendLogPayloads', 'sendLogRecipients'], 'readwrite');
    const payloads = tx.objectStore('sendLogPayloads');
    const deleted = (await payloads.count(clientMessageId)) > 0;
    await tx.objectStore('sendLogRecipients').delete(rowsOf(clientMessageId));
    await payloads.delete(clientMessageId);
    await tx.done;
    return deleted;
  }

  async deleteExpiredSendLog(maxAgeMs: number): Promise<number> {
    const cutoff = Date.now() - maxAgeMs;
    const before = IDBKeyRange.upperBound(cutoff, true);
    const tx = this.database().transaction([...SEND_LOG_STORE_NAMES], 'readwrite');
    const payloads = tx.objectStore('sendLogPayloads');
    const expired = await payloads.index('by-created').getAllKeys(before);
    for (const clientMessageId of expired) {
      await tx.objectStore('sendLogRecipients').delete(rowsOf(clientMessageId));
      await payloads.delete(clientMessageId);
    }
    const jobs = tx.objectStore('sendLogResendJobs');
    for (const jobId of await jobs.index('by-created').getAllKeys(before)) {
      await jobs.delete(jobId);
    }
    await tx.done;
    return expired.length;
  }

  async clearSendLog(): Promise<number> {
    const tx = this.database().transaction([...SEND_LOG_STORE_NAMES], 'readwrite');
    const deleted = await tx.objectStore('sendLogPayloads').count();
    for (const name of SEND_LOG_STORE_NAMES) await tx.objectStore(name).clear();
    await tx.done;
    return deleted;
  }

  async storeResendJob(job: SendLogResendJob): Promise<void> {
    const tx = this.database().transaction('sendLogResendJobs', 'readwrite');
    const existing = await tx.store.get(job.jobId);
    await tx.store.put({ ...job, createdAt: existing?.createdAt ?? Date.now() });
    await tx.done;
  }

  async getResendJob(jobId: string): Promise<SendLogResendJob | null> {
    return (await this.database().get('sendLogResendJobs', jobId)) ?? null;
  }

  async getPendingResendJobs(): Promise<SendLogResendJob[]> {
    const jobs = await this.database().getAllFromIndex('sendLogResendJobs', 'by-state', 'pending');
    return jobs.sort(compareResendJobs);
  }

  async completeResendJob(
    jobId: string,
    state: Exclude<SendLogResendJobState, 'pending'>
  ): Promise<void> {
    const tx = this.database().transaction('sendLogResendJobs', 'readwrite');
    const job = await tx.store.get(jobId);
    if (job) await tx.store.put({ ...job, state });
    await tx.done;
  }

  private newRow(
    clientMessageId: string,
    clientTimestamp: number,
    device: SendLogDevice
  ): SendLogRecipient {
    return {
      clientMessageId,
      userId: device.userId,
      deviceId: device.deviceId,
      clientTimestamp,
      responses: 0,
    };
  }

  /** Delete a finished payload that has no recipient row, inside `tx`. */
  private async deleteIfFinished(
    tx: IDBPTransaction<SendLogDBSchema, ('sendLogPayloads' | 'sendLogRecipients')[], 'readwrite'>,
    clientMessageId: string
  ): Promise<void> {
    const payloads = tx.objectStore('sendLogPayloads');
    const payload = await payloads.get(clientMessageId);
    if (!payload?.sendComplete) return;
    if ((await tx.objectStore('sendLogRecipients').count(rowsOf(clientMessageId))) > 0) return;
    await payloads.delete(clientMessageId);
  }

  private async openPayload(stored: StoredSendLogPayload): Promise<SendLogPayload> {
    const content = JSON.parse(await this.cipher.decrypt(stored.data)) as SendLogPayloadContent;
    return {
      clientMessageId: stored.clientMessageId,
      groupId: content.groupId,
      clientTimestamp: stored.clientTimestamp,
      contentHint: content.contentHint,
      plaintext: base64ToBytes(asBase64(content.plaintext)),
      createdAt: stored.createdAt,
      sendComplete: stored.sendComplete,
    };
  }
}
