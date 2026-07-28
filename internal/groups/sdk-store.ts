/**
 * Group-state persistence backed by the SDK's configured local store.
 */

import AsyncLock from 'async-lock';
import type { ISignalProtocolLocalStore } from '../../types/api';
import { base64ToBytes, bytesToBase64 } from '../../encoding/base64';
import { asBase64 } from '../../types/utils';
import type { IGroupStateStore } from './manager';
import type { DecryptedGroup } from './types';

export {};

const RECORD_VERSION = 1;
const RECORD_PREFIX = 'open-e2ee:group-state:v1:';
const BYTES_TAG = '__openE2eeGroupBytes';

interface StoredGroupRecord {
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

function decodeRecord(encoded: string): StoredGroupRecord {
  const decoded = JSON.parse(encoded, (_key, value: unknown) => {
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
  }) as StoredGroupRecord;

  if (decoded.version !== RECORD_VERSION) {
    throw new Error(
      `Unsupported SDK group-state record version ${String(decoded.version)}`
    );
  }
  return decoded;
}

/**
 * Adapts the SDK local store to the group manager's focused storage contract.
 *
 * One versioned metadata record owns the master key, cached state, and sender
 * key rotation barrier for a group. State-and-barrier writes therefore cross
 * the local-store boundary atomically.
 */
export class SignalProtocolGroupStateStore implements IGroupStateStore {
  private readonly lock = new AsyncLock();

  constructor(private readonly storage: ISignalProtocolLocalStore) {}

  async storeMasterKey(
    groupId: string,
    masterKey: Uint8Array
  ): Promise<void> {
    await this.update(groupId, (record) => {
      record.masterKey = new Uint8Array(masterKey);
    });
  }

  async getMasterKey(groupId: string): Promise<Uint8Array | null> {
    const record = await this.read(groupId);
    return record.masterKey
      ? new Uint8Array(record.masterKey)
      : null;
  }

  async deleteMasterKey(groupId: string): Promise<void> {
    await this.update(groupId, (record) => {
      delete record.masterKey;
    });
  }

  async storeGroupState(
    groupId: string,
    state: DecryptedGroup
  ): Promise<void> {
    await this.update(groupId, (record) => {
      record.state = structuredClone(state);
    });
  }

  async storeGroupStateWithSenderKeyRotationBarrier(
    groupId: string,
    state: DecryptedGroup
  ): Promise<void> {
    await this.update(groupId, (record) => {
      record.state = structuredClone(state);
      record.senderKeyRotationBarrier = state.revision;
    });
  }

  async getGroupState(groupId: string): Promise<DecryptedGroup | null> {
    const record = await this.read(groupId);
    return record.state ? structuredClone(record.state) : null;
  }

  async getSenderKeyRotationBarrier(
    groupId: string
  ): Promise<number | null> {
    const record = await this.read(groupId);
    return record.senderKeyRotationBarrier ?? null;
  }

  async clearSenderKeyRotationBarrier(
    groupId: string,
    expectedRevision: number
  ): Promise<void> {
    await this.update(groupId, (record) => {
      if (record.senderKeyRotationBarrier === expectedRevision) {
        delete record.senderKeyRotationBarrier;
      }
    });
  }

  async deleteGroupState(groupId: string): Promise<void> {
    await this.update(groupId, (record) => {
      delete record.state;
      delete record.senderKeyRotationBarrier;
    });
  }

  private key(groupId: string): string {
    return `${RECORD_PREFIX}${groupId}`;
  }

  private async read(groupId: string): Promise<StoredGroupRecord> {
    const encoded = await this.storage.getMetadata(this.key(groupId));
    return encoded === null
      ? { version: RECORD_VERSION }
      : decodeRecord(encoded);
  }

  private async update(
    groupId: string,
    apply: (record: StoredGroupRecord) => void
  ): Promise<void> {
    await this.lock.acquire(groupId, async () => {
      const record = await this.read(groupId);
      apply(record);
      await this.storage.setMetadata(this.key(groupId), encodeRecord(record));
    });
  }
}
