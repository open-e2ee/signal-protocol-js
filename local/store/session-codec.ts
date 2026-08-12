/** Lossless JSON codec shared by every persistent SessionRecord adapter. */

import {
  assertCurrentSessionRecord,
  type SessionRecord,
} from '../../types/session';

const SESSION_JSON_TYPE_TAG = '__signalProtocolJsonType';

export function serializeSessionRecord(record: SessionRecord): string {
  assertCurrentSessionRecord(record);
  return JSON.stringify(record, (_key, value) => {
    if (typeof value === 'bigint') {
      return { [SESSION_JSON_TYPE_TAG]: 'bigint', value: value.toString() };
    }
    if (value instanceof Uint8Array) {
      return { [SESSION_JSON_TYPE_TAG]: 'uint8array', value: Array.from(value) };
    }
    if (value instanceof Map) {
      return { [SESSION_JSON_TYPE_TAG]: 'map', entries: Array.from(value.entries()) };
    }
    return value;
  });
}

export function deserializeSessionRecord(json: string): SessionRecord {
  const record = JSON.parse(json, (_key, value) => {
    if (value && typeof value === 'object' && value[SESSION_JSON_TYPE_TAG] === 'bigint') {
      if (typeof value.value !== 'string' || !/^-?\d+$/.test(value.value)) {
        throw new Error('Invalid BigInt encoding in session record');
      }
      return BigInt(value.value);
    }
    if (value && typeof value === 'object' && value[SESSION_JSON_TYPE_TAG] === 'uint8array') {
      if (!Array.isArray(value.value)) throw new Error('Invalid Uint8Array encoding in session record');
      return Uint8Array.from(value.value);
    }
    if (value && typeof value === 'object' && value[SESSION_JSON_TYPE_TAG] === 'map') {
      const entries: unknown = value.entries;
      if (
        !Array.isArray(entries) ||
        !entries.every((entry) => Array.isArray(entry) && entry.length === 2)
      ) {
        throw new Error('Invalid Map encoding in session record');
      }
      return new Map(entries as [unknown, unknown][]);
    }
    return value;
  }) as SessionRecord;
  assertCurrentSessionRecord(record);
  return record;
}
