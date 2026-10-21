/**
 * The sender-key handoff rows of the key-value store.
 *
 * Each row is one value under
 * `@signal:sk-handoff:<groupHash>:<generation>:<accountHash>:<recipientHash>:<entryHash>`.
 * The hashes are keyed hashes, not the group ID, the account ID, or the
 * device. Only the generation stays in the clear. The value is the encrypted
 * row JSON.
 *
 * The backend has no secondary index. A store write that deletes rows adds a
 * `removeSenderKeyHandoffs` operation to its own `atomicWrite`, and the
 * backend matches the key segments inside that transaction.
 */

import type { SenderKeyHandoffDevice, SenderKeyHandoffRecord } from '../../../types/api';
import {
  decodeSenderKeyHandoff,
  encodeSenderKeyHandoff,
  SenderKeyHandoffIndex,
  type SenderKeyHandoffHashes,
} from '../sender-key-handoff-index';
import type { KeyValueOperation, KeyValueStorage } from './storage';

/** The key prefix of the handoff rows. */
export const SENDER_KEY_HANDOFF_PREFIX = '@signal:sk-handoff:';

/** The record cipher and the database key of the owning store. */
export interface KeyValueSenderKeyHandoffCipher {
  encrypt(plaintext: string): Promise<string>;
  decrypt(encrypted: string): Promise<string>;
  databaseKey(): Promise<Uint8Array>;
}

type RemoveSenderKeyHandoffs = Extract<KeyValueOperation, { type: 'removeSenderKeyHandoffs' }>;

type StoredPlace = SenderKeyHandoffHashes & { generation: number };

function handoffKey(hashes: SenderKeyHandoffHashes, generation: number): string {
  return (
    SENDER_KEY_HANDOFF_PREFIX +
    [hashes.groupHash, generation, hashes.accountHash, hashes.recipientHash, hashes.entryHash].join(
      ':'
    )
  );
}

/** The place of one row key, or null for a key of another shape. */
function parseHandoffKey(key: string): StoredPlace | null {
  if (!key.startsWith(SENDER_KEY_HANDOFF_PREFIX)) return null;
  const segments = key.slice(SENDER_KEY_HANDOFF_PREFIX.length).split(':');
  if (segments.length !== 5) return null;
  const [groupHash, generationText, accountHash, recipientHash, entryHash] = segments;
  const generation = Number(generationText);
  if (!Number.isSafeInteger(generation) || String(generation) !== generationText) return null;
  return { groupHash, generation, accountHash, recipientHash, entryHash };
}

/** True when the place has every hash of the operation. */
function placeMatches(place: StoredPlace, operation: RemoveSenderKeyHandoffs): boolean {
  return (
    (operation.groupHash === undefined || place.groupHash === operation.groupHash) &&
    (operation.accountHash === undefined || place.accountHash === operation.accountHash) &&
    (operation.recipientHash === undefined || place.recipientHash === operation.recipientHash)
  );
}

export class KeyValueSenderKeyHandoffs {
  private derived: { key: Uint8Array; index: Promise<SenderKeyHandoffIndex> } | null = null;

  constructor(
    private readonly backend: KeyValueStorage,
    private readonly cipher: KeyValueSenderKeyHandoffCipher
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

  /** The operation that removes the rows of one group. */
  async removeGroup(groupId: string): Promise<RemoveSenderKeyHandoffs> {
    const index = await this.index();
    return {
      type: 'removeSenderKeyHandoffs',
      keyPrefix: SENDER_KEY_HANDOFF_PREFIX,
      groupHash: index.group(groupId),
    };
  }

  /** The operation that removes the rows of every device of one account. */
  async removeAccount(userId: string): Promise<RemoveSenderKeyHandoffs> {
    const index = await this.index();
    return {
      type: 'removeSenderKeyHandoffs',
      keyPrefix: SENDER_KEY_HANDOFF_PREFIX,
      accountHash: index.account(userId),
    };
  }

  /** The operation that removes the rows of one device in every group. */
  async removeDevice(device: SenderKeyHandoffDevice): Promise<RemoveSenderKeyHandoffs> {
    const index = await this.index();
    return {
      type: 'removeSenderKeyHandoffs',
      keyPrefix: SENDER_KEY_HANDOFF_PREFIX,
      recipientHash: index.recipient(device),
    };
  }

  async record(record: SenderKeyHandoffRecord): Promise<void> {
    const hashes = (await this.index()).hashes(record);
    const value = await this.cipher.encrypt(encodeSenderKeyHandoff(record));
    await this.backend.setItem(handoffKey(hashes, record.generation), value);
  }

  async list(groupId: string, generation: number): Promise<SenderKeyHandoffRecord[]> {
    const index = await this.index();
    const groupHash = index.group(groupId);
    const records: SenderKeyHandoffRecord[] = [];
    for (const { key, place } of await this.places()) {
      if (place.groupHash !== groupHash || place.generation !== generation) continue;
      const record = await this.open(index, key, place);
      if (record) records.push(record);
    }
    return records;
  }

  /** The group IDs of the readable rows. */
  async groupIds(): Promise<string[]> {
    const index = await this.index();
    const groups = new Map<string, string>();
    for (const { key, place } of await this.places()) {
      if (groups.has(place.groupHash)) continue;
      const record = await this.open(index, key, place);
      if (record) groups.set(place.groupHash, record.groupId);
    }
    return Array.from(groups.values());
  }

  /** Delete the rows of one device in one group. True when a row was deleted. */
  async deleteDeviceInGroup(groupId: string, device: SenderKeyHandoffDevice): Promise<boolean> {
    const index = await this.index();
    return (
      (await this.remove({
        type: 'removeSenderKeyHandoffs',
        keyPrefix: SENDER_KEY_HANDOFF_PREFIX,
        groupHash: index.group(groupId),
        recipientHash: index.recipient(device),
      })) > 0
    );
  }

  /** Delete the rows of every device of one account. True when a row was deleted. */
  async deleteAccount(userId: string): Promise<boolean> {
    return (await this.remove(await this.removeAccount(userId))) > 0;
  }

  /**
   * Delete the rows of a group whose sender key ID differs, and the rows that
   * do not decrypt to a record at their place. Null deletes every row.
   */
  async retain(groupId: string, senderKeyId: string | null): Promise<number> {
    if (senderKeyId === null) return this.remove(await this.removeGroup(groupId));
    const index = await this.index();
    const groupHash = index.group(groupId);
    const doomed: KeyValueOperation[] = [];
    for (const { key, place } of await this.places()) {
      if (place.groupHash !== groupHash) continue;
      const record = await this.open(index, key, place);
      if (record?.senderKeyId !== senderKeyId) doomed.push({ type: 'remove', key });
    }
    if (doomed.length > 0) await this.backend.atomicWrite(doomed);
    return doomed.length;
  }

  /**
   * Remove the matching rows in one batch. Returns the count of matching rows
   * that the scan before the batch saw.
   */
  private async remove(operation: RemoveSenderKeyHandoffs): Promise<number> {
    const count = (await this.places()).filter(({ place }) => placeMatches(place, operation))
      .length;
    if (count > 0) await this.backend.atomicWrite([operation]);
    return count;
  }

  /** Every row key and its place. */
  private async places(): Promise<Array<{ key: string; place: StoredPlace }>> {
    const places: Array<{ key: string; place: StoredPlace }> = [];
    for (const key of await this.backend.getAllKeys()) {
      const place = parseHandoffKey(key);
      if (place) places.push({ key, place });
    }
    return places;
  }

  /** Decrypt one row. Null when it is absent, unreadable, or not stored at its own hashes. */
  private async open(
    index: SenderKeyHandoffIndex,
    key: string,
    place: StoredPlace
  ): Promise<SenderKeyHandoffRecord | null> {
    const value = await this.backend.getItem(key);
    if (value === null) return null;
    let json: string;
    try {
      json = await this.cipher.decrypt(value);
    } catch {
      return null;
    }
    const record = decodeSenderKeyHandoff(json);
    return record && index.matches(record, place) ? record : null;
  }
}
