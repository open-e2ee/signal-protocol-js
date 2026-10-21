/**
 * Group-state persistence backed by the SDK's configured local store.
 */

import AsyncLock from 'async-lock';
import type { SignalProtocolLocalStore } from '../../types/api';
import { base64ToBytes, bytesToBase64 } from '../../encoding/base64';
import { asBase64 } from '../../types/utils';
import { cloneProtocolState } from '../crypto/utils';
import type { GroupStateStore } from './manager';
import {
  cloneGroupReceiveRecord,
  newGroupReceiveRecord,
  type GroupReceiveRecord,
} from './receive-record';
import type { DecryptedGroup } from './types';

export {};

const RECORD_VERSION = 2;
const RECORD_PREFIX = 'open-e2ee:group-state:v2:';
const V1_RECORD_PREFIX = 'open-e2ee:group-state:v1:';
const INDEX_KEY = 'open-e2ee:group-state:v2-index';
const BYTES_TAG = '__openE2eeGroupBytes';

interface StoredGroupRecordV1 {
  version: 1;
  masterKey?: Uint8Array;
  state?: DecryptedGroup;
  senderKeyRotationBarrier?: number;
}

interface StoredGroupRecord extends GroupReceiveRecord {
  version: typeof RECORD_VERSION;
  masterKey?: Uint8Array;
  state?: DecryptedGroup;
  senderKeyRotationBarrier?: number;
}

function encodeRecord(record: StoredGroupRecord): string {
  return JSON.stringify(record, (_key, value: unknown) => {
    if (value instanceof Uint8Array) {
      return { [BYTES_TAG]: bytesToBase64(value) };
    }
    return value;
  });
}

function decodeBytes(encoded: string): { version?: unknown } {
  return JSON.parse(encoded, (_key, value: unknown) => {
    if (
      typeof value === 'object' &&
      value !== null &&
      Object.keys(value).length === 1 &&
      typeof (value as Record<string, unknown>)[BYTES_TAG] === 'string'
    ) {
      return base64ToBytes(
        asBase64((value as Record<string, string>)[BYTES_TAG]!)
      );
    }
    return value;
  }) as { version?: unknown };
}

function decodeRecord<T extends { version: number }>(
  encoded: string,
  version: T['version']
): T {
  const decoded = decodeBytes(encoded);
  if (decoded.version !== version) {
    throw new Error(
      `Unsupported SDK group-state record version ${String(decoded.version)}`
    );
  }
  return decoded as T;
}

/**
 * The v2 form of a v1 record. A v1 group has no claims and no fetch history,
 * so it starts at required revision 0 as a locally known group.
 */
function migrateV1Record(record: StoredGroupRecordV1): StoredGroupRecord {
  const { version: _version, ...fields } = record;
  return {
    ...fields,
    ...newGroupReceiveRecord('local'),
    version: RECORD_VERSION,
  };
}

function receivePart(record: StoredGroupRecord): GroupReceiveRecord {
  const {
    version: _version,
    masterKey: _masterKey,
    state: _state,
    senderKeyRotationBarrier: _barrier,
    ...receive
  } = record;
  return cloneGroupReceiveRecord(receive);
}

function parseIndex(encoded: string | null): string[] {
  if (encoded === null) return [];
  const parsed: unknown = JSON.parse(encoded);
  if (!Array.isArray(parsed) || !parsed.every((id) => typeof id === 'string')) {
    throw new Error('The SDK group-state index is malformed');
  }
  return parsed as string[];
}

/**
 * Adapts the SDK local store to the group manager's focused storage contract.
 *
 * One versioned metadata record owns the master key, cached state, sender key
 * rotation barrier, and receive record of a group. State-and-barrier writes
 * therefore cross the local-store boundary atomically. An index lists the
 * groups that have a v2 record.
 *
 * A v1 record migrates forward when the group is first read or written. The
 * migration indexes the group, writes the v2 record, and then deletes the v1
 * record. Each step is idempotent, so a crash at any step reruns safely. A v1
 * group that is never read again stays unlisted, which is correct for a group
 * whose state the device already holds.
 */
export class SignalProtocolGroupStateStore implements GroupStateStore {
  private readonly lock = new AsyncLock();
  /** Groups whose v1 record this process has confirmed deleted. */
  private readonly migrated = new Set<string>();
  /** Groups that this process has confirmed in the index. */
  private readonly indexed = new Set<string>();

  constructor(private readonly storage: SignalProtocolLocalStore) {}

  async storeMasterKey(
    groupId: string,
    masterKey: Uint8Array
  ): Promise<void> {
    await this.update(groupId, (record) => {
      record.masterKey = new Uint8Array(masterKey);
      return record;
    });
  }

  async getMasterKey(groupId: string): Promise<Uint8Array | null> {
    const record = await this.read(groupId);
    return record?.masterKey ? new Uint8Array(record.masterKey) : null;
  }

  async deleteMasterKey(groupId: string): Promise<void> {
    await this.update(groupId, (record) => {
      delete record.masterKey;
      return record;
    });
  }

  async storeGroupState(
    groupId: string,
    state: DecryptedGroup
  ): Promise<void> {
    await this.update(groupId, (record) => {
      record.state = cloneProtocolState(state);
      delete record.unverified;
      return record;
    });
  }

  async storeGroupStateWithSenderKeyRotationBarrier(
    groupId: string,
    state: DecryptedGroup
  ): Promise<void> {
    await this.update(groupId, (record) => {
      record.state = cloneProtocolState(state);
      record.senderKeyRotationBarrier = state.revision;
      delete record.unverified;
      return record;
    });
  }

  async getGroupState(groupId: string): Promise<DecryptedGroup | null> {
    const record = await this.read(groupId);
    return record?.state ? cloneProtocolState(record.state) : null;
  }

  async getSenderKeyRotationBarrier(
    groupId: string
  ): Promise<number | null> {
    const record = await this.read(groupId);
    return record?.senderKeyRotationBarrier ?? null;
  }

  async clearSenderKeyRotationBarrier(
    groupId: string,
    expectedRevision: number
  ): Promise<void> {
    await this.update(groupId, (record) => {
      if (record.senderKeyRotationBarrier === expectedRevision) {
        delete record.senderKeyRotationBarrier;
      }
      return record;
    });
  }

  async deleteGroupState(groupId: string): Promise<void> {
    await this.update(groupId, (record) => {
      delete record.state;
      delete record.senderKeyRotationBarrier;
      return record;
    });
  }

  async getGroupReceiveRecord(
    groupId: string
  ): Promise<GroupReceiveRecord | null> {
    const record = await this.read(groupId);
    return record ? receivePart(record) : null;
  }

  async updateGroupReceiveRecord(
    groupId: string,
    apply: (current: GroupReceiveRecord | null) => GroupReceiveRecord | null
  ): Promise<GroupReceiveRecord | null> {
    let written: GroupReceiveRecord | null = null;
    await this.lock.acquire(groupId, async () => {
      const current = await this.load(groupId);
      const next = apply(current ? receivePart(current) : null);
      if (next === null) {
        if (current) await this.remove(groupId);
        return;
      }
      const receive = cloneGroupReceiveRecord(next);
      const record: StoredGroupRecord = {
        ...(current?.masterKey ? { masterKey: current.masterKey } : {}),
        ...(current?.state ? { state: current.state } : {}),
        ...(current?.senderKeyRotationBarrier !== undefined
          ? { senderKeyRotationBarrier: current.senderKeyRotationBarrier }
          : {}),
        ...receive,
        version: RECORD_VERSION,
      };
      await this.write(groupId, record);
      written = receivePart(record);
    });
    return written;
  }

  async listGroupReceiveRecords(): Promise<string[]> {
    return parseIndex(await this.storage.getMetadata(INDEX_KEY));
  }

  private key(groupId: string): string {
    return `${RECORD_PREFIX}${groupId}`;
  }

  private v1Key(groupId: string): string {
    return `${V1_RECORD_PREFIX}${groupId}`;
  }

  private async read(groupId: string): Promise<StoredGroupRecord | null> {
    return this.lock.acquire(groupId, () => this.load(groupId));
  }

  /** Read the v2 record, and migrate a v1 record first. Runs under the group lock. */
  private async load(groupId: string): Promise<StoredGroupRecord | null> {
    const encoded = await this.storage.getMetadata(this.key(groupId));
    if (encoded !== null) {
      if (!this.migrated.has(groupId)) {
        // A crash after the v2 write left the v1 record. Finish the migration.
        await this.storage.deleteMetadata(this.v1Key(groupId));
        this.migrated.add(groupId);
      }
      return decodeRecord<StoredGroupRecord>(encoded, RECORD_VERSION);
    }
    const legacy = await this.storage.getMetadata(this.v1Key(groupId));
    if (legacy === null) return null;
    const migrated = migrateV1Record(
      decodeRecord<StoredGroupRecordV1>(legacy, 1)
    );
    await this.write(groupId, migrated);
    await this.storage.deleteMetadata(this.v1Key(groupId));
    this.migrated.add(groupId);
    return migrated;
  }

  private async update(
    groupId: string,
    apply: (record: StoredGroupRecord) => StoredGroupRecord
  ): Promise<void> {
    await this.lock.acquire(groupId, async () => {
      const record =
        (await this.load(groupId)) ?? {
          ...newGroupReceiveRecord('local'),
          version: RECORD_VERSION,
        };
      await this.write(groupId, apply(record));
    });
  }

  /** Index the group, then write its record. */
  private async write(
    groupId: string,
    record: StoredGroupRecord
  ): Promise<void> {
    await this.addToIndex(groupId);
    await this.storage.setMetadata(this.key(groupId), encodeRecord(record));
  }

  /** Delete both record versions, then drop the group from the index. */
  private async remove(groupId: string): Promise<void> {
    await this.storage.deleteMetadata(this.v1Key(groupId));
    await this.storage.deleteMetadata(this.key(groupId));
    await this.changeIndex((ids) =>
      ids.includes(groupId) ? ids.filter((id) => id !== groupId) : ids
    );
    this.indexed.delete(groupId);
  }

  private async addToIndex(groupId: string): Promise<void> {
    if (this.indexed.has(groupId)) return;
    await this.changeIndex((ids) =>
      ids.includes(groupId) ? ids : [...ids, groupId]
    );
    this.indexed.add(groupId);
  }

  private async changeIndex(
    change: (ids: string[]) => string[]
  ): Promise<void> {
    for (;;) {
      const encoded = await this.storage.getMetadata(INDEX_KEY);
      const ids = parseIndex(encoded);
      const next = change(ids);
      if (next === ids) return;
      if (
        await this.storage.compareAndSetMetadata(
          INDEX_KEY,
          encoded,
          JSON.stringify(next)
        )
      ) {
        return;
      }
    }
  }
}
