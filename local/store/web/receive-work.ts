/**
 * The receive records of the IndexedDB store.
 *
 * `receiveWork` holds one row per record. The record JSON is encrypted in
 * `data`. The index fields stay in the clear: the revision, the arrival
 * order, the stage, the due time, the size, and, for a record that waits for
 * its group, the group key (a keyed hash, not the group ID). A listing
 * filters on these fields and decrypts only the records that it returns. A
 * usage count reads only these fields.
 *
 * A transaction must not wait for anything other than IndexedDB, or it
 * commits early. Each write therefore encrypts before its transaction opens,
 * and each read decrypts after its transaction ends.
 */

import type { DBSchema, IDBPDatabase } from 'idb';

import type { ReceiveWorkQuery, ReceiveWorkRecord, ReceiveWorkUsage } from '../../../types/api';
import {
  assertReceiveWork,
  indexMatchesReceiveWorkQuery,
  parseReceiveWork,
  receiveWorkGroupKey,
  receiveWorkIndex,
  receiveWorkLimit,
  type ReceiveWorkIndex,
} from '../receive-work';

/** One stored receive record. */
export interface StoredReceiveWork extends ReceiveWorkIndex {
  workId: string;
  /** The encrypted record JSON. */
  data: Uint8Array;
}

export interface ReceiveWorkDBSchema extends DBSchema {
  receiveWork: {
    key: string;
    value: StoredReceiveWork;
    indexes: { 'by-arrival': [number, string]; 'by-group': string };
  };
}

/** The record cipher and the database key of the owning store. */
export interface IndexedDbReceiveWorkCipher {
  encrypt(plaintext: string): Promise<Uint8Array>;
  decrypt(encrypted: Uint8Array): Promise<string>;
  databaseKey(): Promise<Uint8Array>;
}

/** Create the receive record object store when the database does not have it. */
export function upgradeReceiveWorkStore(db: IDBPDatabase<ReceiveWorkDBSchema>): void {
  if (!db.objectStoreNames.contains('receiveWork')) {
    const store = db.createObjectStore('receiveWork', { keyPath: 'workId' });
    store.createIndex('by-arrival', ['arrivalSeq', 'workId']);
    store.createIndex('by-group', 'blockedGroup');
  }
}

export class IndexedDbReceiveWork {
  constructor(
    private readonly database: () => IDBPDatabase<ReceiveWorkDBSchema>,
    private readonly cipher: IndexedDbReceiveWorkCipher
  ) {}

  /** Encrypt one record and compute its index fields, before a transaction opens. */
  async seal(record: ReceiveWorkRecord): Promise<StoredReceiveWork> {
    assertReceiveWork(record);
    const index = await receiveWorkIndex(record, await this.cipher.databaseKey());
    return {
      workId: record.workId,
      ...index,
      data: await this.cipher.encrypt(JSON.stringify(record)),
    };
  }

  async get(workId: string): Promise<ReceiveWorkRecord | null> {
    const row = await this.database().get('receiveWork', workId);
    return row ? await this.open(row) : null;
  }

  async put(record: ReceiveWorkRecord, expectedRevision: number | null): Promise<boolean> {
    const row = await this.seal(record);
    const tx = this.database().transaction('receiveWork', 'readwrite');
    try {
      const current = await tx.store.get(row.workId);
      if ((current?.revision ?? null) !== expectedRevision) {
        await tx.done;
        return false;
      }
      await tx.store.put(row);
      await tx.done;
      return true;
    } catch (error) {
      await tx.done.catch(() => undefined);
      throw error;
    }
  }

  async list(query: ReceiveWorkQuery = {}): Promise<ReceiveWorkRecord[]> {
    const limit = receiveWorkLimit(query);
    const range =
      query.after === undefined
        ? undefined
        : IDBKeyRange.lowerBound([query.after.arrivalSeq, query.after.workId], true);
    const rows: StoredReceiveWork[] = [];
    const tx = this.database().transaction('receiveWork', 'readonly');
    let cursor = await tx.store.index('by-arrival').openCursor(range);
    while (cursor && rows.length < limit) {
      if (indexMatchesReceiveWorkQuery(cursor.value, cursor.value.workId, query)) {
        rows.push(cursor.value);
      }
      cursor = await cursor.continue();
    }
    await tx.done;
    return await Promise.all(rows.map((row) => this.open(row)));
  }

  async usage(query: { groupId?: string } = {}): Promise<ReceiveWorkUsage> {
    const db = this.database();
    const rows =
      query.groupId === undefined
        ? await db.getAll('receiveWork')
        : await db.getAllFromIndex(
            'receiveWork',
            'by-group',
            await receiveWorkGroupKey(await this.cipher.databaseKey(), query.groupId)
          );
    let bytes = 0;
    for (const row of rows) bytes += row.sizeBytes;
    return { items: rows.length, bytes };
  }

  /** Decrypt one row. The clear revision must match the encrypted record. */
  private async open(row: StoredReceiveWork): Promise<ReceiveWorkRecord> {
    const record = parseReceiveWork(await this.cipher.decrypt(row.data), row.workId);
    if (record.revision !== row.revision) {
      throw new Error('Receive record revision does not match its encrypted record');
    }
    return record;
  }
}
