/**
 * The receive records of the key-value store.
 *
 * Each record is one value under `@signal:receive-work:<workId>`. The value
 * is a JSON envelope. The index fields stay in the clear: the revision, the
 * arrival order, the stage, the due time, the size, and, for a record that
 * waits for its group, the group key (a keyed hash, not the group ID). The
 * record JSON is encrypted in `data`. A listing filters on the clear fields
 * and decrypts only the records that it returns. A usage count reads only the
 * clear fields.
 *
 * A write that depends on the stored revision is one `atomicWrite` with a
 * `check` on the value that it read, so a concurrent writer makes the write
 * fail instead of losing an update.
 */

import type { ReceiveWorkQuery, ReceiveWorkRecord, ReceiveWorkUsage } from '../../../types/api';
import {
  assertReceiveWork,
  indexMatchesReceiveWorkQuery,
  parseReceiveWork,
  receiveWorkGroupKey,
  receiveWorkIndex,
  receiveWorkLimit,
  type LegacyReceivedContentSource,
  type ReceiveWorkIndex,
} from '../receive-work';
import type { KeyValueOperation, KeyValueStorage } from './storage';

/** The key prefix of the receive records. */
export const RECEIVE_WORK_PREFIX = '@signal:receive-work:';

/** The key prefix of the legacy received-content rows. */
export const LEGACY_RECEIVED_CONTENT_PREFIX = '@signal:received-content:';

/** The stored envelope of one record. */
interface StoredReceiveWork extends ReceiveWorkIndex {
  /** The encrypted record JSON. */
  data: string;
}

/** The record cipher and the database key of the owning store. */
export interface KeyValueReceiveWorkCipher {
  encrypt(plaintext: string): Promise<string>;
  decrypt(encrypted: string): Promise<string>;
  databaseKey(): Promise<Uint8Array>;
}

function receiveWorkKey(workId: string): string {
  return `${RECEIVE_WORK_PREFIX}${workId}`;
}

function parseEnvelope(value: string): StoredReceiveWork {
  const envelope = JSON.parse(value) as StoredReceiveWork;
  if (
    envelope === null ||
    typeof envelope !== 'object' ||
    !Number.isSafeInteger(envelope.revision) ||
    !Number.isSafeInteger(envelope.arrivalSeq) ||
    !Number.isSafeInteger(envelope.dueAt) ||
    !Number.isSafeInteger(envelope.sizeBytes) ||
    typeof envelope.data !== 'string'
  ) {
    throw new Error('Invalid receive-work envelope');
  }
  return envelope;
}

function isQuotaExceededError(error: unknown): boolean {
  return (
    !!error && typeof error === 'object' && 'name' in error && error.name === 'QuotaExceededError'
  );
}

export class KeyValueReceiveWork {
  constructor(
    private readonly backend: KeyValueStorage,
    private readonly cipher: KeyValueReceiveWorkCipher
  ) {}

  /** The write of one record, for a batch that commits it with other changes. */
  async seal(record: ReceiveWorkRecord): Promise<KeyValueOperation> {
    assertReceiveWork(record);
    const envelope: StoredReceiveWork = {
      ...(await receiveWorkIndex(record, await this.cipher.databaseKey())),
      data: await this.cipher.encrypt(JSON.stringify(record)),
    };
    return { type: 'set', key: receiveWorkKey(record.workId), value: JSON.stringify(envelope) };
  }

  async get(workId: string): Promise<ReceiveWorkRecord | null> {
    const value = await this.backend.getItem(receiveWorkKey(workId));
    return value === null ? null : this.open(workId, parseEnvelope(value));
  }

  async put(record: ReceiveWorkRecord, expectedRevision: number | null): Promise<boolean> {
    const write = await this.seal(record);
    return this.writeIfRevision(record.workId, expectedRevision, [write]);
  }

  async list(query: ReceiveWorkQuery = {}): Promise<ReceiveWorkRecord[]> {
    const limit = receiveWorkLimit(query);
    const matches: Array<{ workId: string; envelope: StoredReceiveWork }> = [];
    for (const key of await this.backend.getAllKeys()) {
      if (!key.startsWith(RECEIVE_WORK_PREFIX)) continue;
      const value = await this.backend.getItem(key);
      if (value === null) continue;
      const envelope = parseEnvelope(value);
      const workId = key.slice(RECEIVE_WORK_PREFIX.length);
      if (!indexMatchesReceiveWorkQuery(envelope, workId, query)) continue;
      matches.push({ workId, envelope });
    }
    matches.sort(
      (a, b) =>
        a.envelope.arrivalSeq - b.envelope.arrivalSeq ||
        (a.workId < b.workId ? -1 : a.workId > b.workId ? 1 : 0)
    );
    const page: ReceiveWorkRecord[] = [];
    for (const { workId, envelope } of matches.slice(0, limit)) {
      page.push(await this.open(workId, envelope));
    }
    return page;
  }

  async usage(query: { groupId?: string } = {}): Promise<ReceiveWorkUsage> {
    const groupKey =
      query.groupId === undefined
        ? undefined
        : await receiveWorkGroupKey(await this.cipher.databaseKey(), query.groupId);
    let items = 0;
    let bytes = 0;
    for (const key of await this.backend.getAllKeys()) {
      if (!key.startsWith(RECEIVE_WORK_PREFIX)) continue;
      const value = await this.backend.getItem(key);
      if (value === null) continue;
      const envelope = parseEnvelope(value);
      if (groupKey !== undefined && envelope.blockedGroup !== groupKey) continue;
      items += 1;
      bytes += envelope.sizeBytes;
    }
    return { items, bytes };
  }

  /**
   * Delete one record and apply the given writes in one batch, when the
   * record holds the expected revision.
   */
  async complete(
    workId: string,
    expectedRevision: number,
    writes: readonly KeyValueOperation[]
  ): Promise<boolean> {
    return this.writeIfRevision(workId, expectedRevision, [
      { type: 'remove', key: receiveWorkKey(workId) },
      ...writes,
    ]);
  }

  /** The legacy received-content rows of this backend. Their values are encrypted. */
  legacySource(): LegacyReceivedContentSource {
    return {
      listIds: async () =>
        (await this.backend.getAllKeys())
          .filter((key) => key.startsWith(LEGACY_RECEIVED_CONTENT_PREFIX))
          .map((key) => key.slice(LEGACY_RECEIVED_CONTENT_PREFIX.length))
          .sort(),
      read: async (id) => {
        const value = await this.backend.getItem(`${LEGACY_RECEIVED_CONTENT_PREFIX}${id}`);
        return value === null ? null : this.cipher.decrypt(value);
      },
      delete: (id) => this.backend.removeItem(`${LEGACY_RECEIVED_CONTENT_PREFIX}${id}`),
    };
  }

  /**
   * Apply the operations when the stored record holds the expected revision.
   * Null expects no record. The batch checks the value that was read.
   */
  private async writeIfRevision(
    workId: string,
    expectedRevision: number | null,
    operations: readonly KeyValueOperation[]
  ): Promise<boolean> {
    const key = receiveWorkKey(workId);
    const observed = await this.backend.getItem(key);
    const revision = observed === null ? null : parseEnvelope(observed).revision;
    if (revision !== expectedRevision) return false;
    try {
      await this.backend.atomicWrite([{ type: 'check', key, expectedValue: observed }, ...operations]);
      return true;
    } catch (error) {
      // A failed batch commits nothing. Do not report capacity failure as contention.
      if (isQuotaExceededError(error)) throw error;
      if ((await this.backend.getItem(key)) !== observed) return false;
      throw error;
    }
  }

  private async open(workId: string, envelope: StoredReceiveWork): Promise<ReceiveWorkRecord> {
    const record = parseReceiveWork(await this.cipher.decrypt(envelope.data), workId);
    if (record.revision !== envelope.revision) {
      throw new Error('Invalid receive-work record');
    }
    return record;
  }
}
