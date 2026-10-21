/**
 * The sender-key handoff rows of the IndexedDB store.
 *
 * `senderKeyHandoff` holds one row per handoff. The row JSON is encrypted in
 * `data`. The key and the index fields are keyed hashes, not the group ID,
 * the account ID, or the device. Only the generation stays in the clear.
 *
 * A transaction must not wait for anything other than IndexedDB, or it
 * commits early. Each write therefore computes its hashes and encrypts before
 * its transaction opens, and each read decrypts after its transaction ends. A
 * store write that deletes rows reads the row keys by index inside its own
 * transaction and deletes them in the same batch as the write.
 */

import type { DBSchema, IDBPDatabase, IDBPObjectStore } from 'idb';

import type { SenderKeyHandoffDevice, SenderKeyHandoffRecord } from '../../../types/api';
import {
  decodeSenderKeyHandoff,
  encodeSenderKeyHandoff,
  SenderKeyHandoffIndex,
} from '../sender-key-handoff-index';

/** One stored handoff row. */
export interface StoredSenderKeyHandoff {
  /** The group key of the row's group. */
  groupHash: string;
  generation: number;
  /** A keyed hash of the recipient device, its registration ID, and the sender key ID. */
  entryHash: string;
  /** A keyed hash of the recipient account. */
  accountHash: string;
  /** A keyed hash of the recipient device. */
  recipientHash: string;
  /** The encrypted row JSON. */
  data: Uint8Array;
}

export interface SenderKeyHandoffDBSchema extends DBSchema {
  senderKeyHandoff: {
    key: [string, number, string];
    value: StoredSenderKeyHandoff;
    indexes: { 'by-group': string; 'by-recipient': string; 'by-account': string };
  };
}

/** Create the handoff object store when the database does not have it. */
export function upgradeSenderKeyHandoffStore(db: IDBPDatabase<SenderKeyHandoffDBSchema>): void {
  if (!db.objectStoreNames.contains('senderKeyHandoff')) {
    const store = db.createObjectStore('senderKeyHandoff', {
      keyPath: ['groupHash', 'generation', 'entryHash'],
    });
    store.createIndex('by-group', 'groupHash');
    store.createIndex('by-recipient', 'recipientHash');
    store.createIndex('by-account', 'accountHash');
  }
}

/** The record cipher and the database key of the owning store. */
export interface IndexedDbSenderKeyHandoffCipher {
  encrypt(plaintext: string): Promise<Uint8Array>;
  decrypt(encrypted: Uint8Array): Promise<string>;
  databaseKey(): Promise<Uint8Array>;
}

type HandoffKey = [string, number, string];

type HandoffStore = IDBPObjectStore<
  SenderKeyHandoffDBSchema,
  ['senderKeyHandoff'],
  'senderKeyHandoff',
  'readwrite'
>;

/** All row keys of one group at one generation. */
function generationRange(groupHash: string, generation: number): IDBKeyRange {
  // An array sorts after every string, so the upper bound follows every entry hash.
  return IDBKeyRange.bound([groupHash, generation, ''], [groupHash, generation, []]);
}

export class IndexedDbSenderKeyHandoffs {
  private derived: { key: Uint8Array; index: Promise<SenderKeyHandoffIndex> } | null = null;

  constructor(
    private readonly database: () => IDBPDatabase<SenderKeyHandoffDBSchema>,
    private readonly cipher: IndexedDbSenderKeyHandoffCipher
  ) {}

  /**
   * The keyed index of the current database key. A new database key derives
   * a new index.
   */
  async index(): Promise<SenderKeyHandoffIndex> {
    const key = await this.cipher.databaseKey();
    if (this.derived?.key !== key) {
      this.derived = { key, index: SenderKeyHandoffIndex.derive(key) };
    }
    return this.derived.index;
  }

  async record(record: SenderKeyHandoffRecord): Promise<void> {
    const hashes = (await this.index()).hashes(record);
    const data = await this.cipher.encrypt(encodeSenderKeyHandoff(record));
    await this.database().put('senderKeyHandoff', {
      ...hashes,
      generation: record.generation,
      data,
    });
  }

  async list(groupId: string, generation: number): Promise<SenderKeyHandoffRecord[]> {
    const index = await this.index();
    const rows = await this.database().getAll(
      'senderKeyHandoff',
      generationRange(index.group(groupId), generation)
    );
    const records: SenderKeyHandoffRecord[] = [];
    for (const row of rows) {
      const record = await this.open(index, row);
      if (record) records.push(record);
    }
    return records;
  }

  /** The group IDs of the readable rows. */
  async groupIds(): Promise<string[]> {
    const index = await this.index();
    const groups = new Map<string, string>();
    for (const row of await this.database().getAll('senderKeyHandoff')) {
      if (groups.has(row.groupHash)) continue;
      const record = await this.open(index, row);
      if (record) groups.set(row.groupHash, record.groupId);
    }
    return Array.from(groups.values());
  }

  /** Delete the rows of one device in one group. True when a row was deleted. */
  async deleteDeviceInGroup(groupId: string, device: SenderKeyHandoffDevice): Promise<boolean> {
    const index = await this.index();
    const groupHash = index.group(groupId);
    const recipientHash = index.recipient(device);
    return (
      (await this.deleteKeys(async (store) =>
        (await store.index('by-recipient').getAllKeys(recipientHash)).filter(
          (key) => key[0] === groupHash
        )
      )) > 0
    );
  }

  /** Delete the rows of every device of one account. True when a row was deleted. */
  async deleteAccount(userId: string): Promise<boolean> {
    const accountHash = (await this.index()).account(userId);
    return (
      (await this.deleteKeys((store) => store.index('by-account').getAllKeys(accountHash))) > 0
    );
  }

  /**
   * Delete the rows of a group whose sender key ID differs, and the rows that
   * do not decrypt to a record at their place. Null deletes every row.
   */
  async retain(groupId: string, senderKeyId: string | null): Promise<number> {
    const index = await this.index();
    const groupHash = index.group(groupId);
    const db = this.database();
    const rows = await db.getAllFromIndex('senderKeyHandoff', 'by-group', groupHash);
    const doomed = new Set<string>();
    for (const row of rows) {
      const record = senderKeyId === null ? null : await this.open(index, row);
      if (record?.senderKeyId !== senderKeyId) {
        doomed.add(JSON.stringify([row.groupHash, row.generation, row.entryHash]));
      }
    }
    if (doomed.size === 0) return 0;
    return this.deleteKeys(async (store) =>
      (await store.index('by-group').getAllKeys(groupHash)).filter((key) =>
        doomed.has(JSON.stringify(key))
      )
    );
  }

  /**
   * Read the doomed keys in one transaction, then delete them in one batch.
   * Returns the deleted count.
   */
  private async deleteKeys(
    select: (store: HandoffStore) => Promise<HandoffKey[]>
  ): Promise<number> {
    const tx = this.database().transaction('senderKeyHandoff', 'readwrite');
    const store = tx.objectStore('senderKeyHandoff');
    const deletes: Promise<unknown>[] = [];
    try {
      const keys = await select(store);
      // Push each request as it is created. A later synchronous throw must
      // not leave an earlier request outside the settled set.
      for (const key of keys) deletes.push(store.delete(key));
      await Promise.all([...deletes, tx.done]);
      return keys.length;
    } catch (error) {
      try {
        tx.abort();
      } catch {
        /* The failed transaction can already be inactive. */
      }
      await Promise.allSettled([...deletes, tx.done]);
      throw error;
    }
  }

  /** Decrypt one row. Null when it is unreadable or not stored at its own hashes. */
  private async open(
    index: SenderKeyHandoffIndex,
    row: StoredSenderKeyHandoff
  ): Promise<SenderKeyHandoffRecord | null> {
    let json: string;
    try {
      json = await this.cipher.decrypt(row.data);
    } catch {
      return null;
    }
    const record = decodeSenderKeyHandoff(json);
    return record && index.matches(record, row) ? record : null;
  }
}
