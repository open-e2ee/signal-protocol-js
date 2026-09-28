/**
 * Realm backend for the key-value store.
 *
 * The adapter is structural: it takes any object shaped like a Realm and never
 * imports `realm`, so the SDK has no dependency or peer on it. The application
 * installs `realm`, opens the Realm with {@link realmKeyValueSchema} in its
 * schema list, and hands the open Realm to
 * {@link createRealmKeyValueBackend}.
 *
 * Each `atomicWrite` runs the store's batch function inside one `realm.write`,
 * through {@link createTransactionalKeyValueBackend}. Realm commits the
 * transaction when the callback returns and cancels it when the callback
 * throws, so a failed check or a failed write commits nothing.
 *
 * @example
 * ```typescript
 * // Realm is the default export of the application's own realm package.
 * import { KeyValueSignalProtocolStore } from '@open-e2ee/signal-protocol-sdk/local/store/key-value';
 * import {
 *   createRealmKeyValueBackend,
 *   realmKeyValueSchema,
 * } from '@open-e2ee/signal-protocol-sdk/local/store/key-value/realm';
 *
 * const realm = await Realm.open({ path: 'signal-protocol.realm', schema: [realmKeyValueSchema] });
 * const store = await KeyValueSignalProtocolStore.create({
 *   storage: createRealmKeyValueBackend(realm),
 *   vault: yourPlatformSecretVault,
 * });
 * ```
 */

import { EncryptionError, EncryptionErrorCode } from '../../../../types/errors';
import type { KeyValueTransaction } from '../batch';
import type { KeyValueStorage } from '../storage';
import { createTransactionalKeyValueBackend } from '../transactional-backend';

/** The Realm object type that holds the store's records. */
export const REALM_KEY_VALUE_SCHEMA_NAME = 'SignalProtocolKeyValue';

/**
 * The object schema to add to the application's Realm schema list. Each
 * record is one store key and its string value. The key is the primary key.
 */
export const realmKeyValueSchema = {
  name: REALM_KEY_VALUE_SCHEMA_NAME,
  primaryKey: 'key',
  properties: {
    key: 'string',
    value: 'string',
  },
} as const;

/** A stored record as Realm returns it: an object with untyped fields. */
export interface RealmRecordLike {
  readonly [field: string]: unknown;
}

/** The part of a Realm `Results` collection the adapter uses. */
export interface RealmResultsLike extends Iterable<RealmRecordLike> {
  filtered(query: string, ...args: unknown[]): RealmResultsLike;
}

/**
 * The part of an open Realm the adapter uses. A `Realm` instance from the
 * `realm` package satisfies it.
 */
export interface RealmLike {
  readonly isInTransaction: boolean;
  write<T>(callback: () => T): T;
  objectForPrimaryKey(type: string, primaryKey: string): RealmRecordLike | null;
  objects(type: string): RealmResultsLike;
  /** `mode` is `true`: update the record when its primary key exists. */
  create(type: string, values: { key: string; value: string }, mode: true): unknown;
  delete(subject: RealmRecordLike): void;
}

function stringField(record: RealmRecordLike, field: 'key' | 'value'): string {
  const value = record[field];
  if (typeof value !== 'string') {
    throw new EncryptionError(
      `A ${REALM_KEY_VALUE_SCHEMA_NAME} record has a non-string ${field}; the Realm schema does not match realmKeyValueSchema`,
      EncryptionErrorCode.INVALID_STATE
    );
  }
  return value;
}

function realmTransaction(realm: RealmLike): KeyValueTransaction {
  return {
    get(key: string): string | null {
      const record = realm.objectForPrimaryKey(REALM_KEY_VALUE_SCHEMA_NAME, key);
      return record === null ? null : stringField(record, 'value');
    },
    set(key: string, value: string): void {
      realm.create(REALM_KEY_VALUE_SCHEMA_NAME, { key, value }, true);
    },
    delete(key: string): void {
      const record = realm.objectForPrimaryKey(REALM_KEY_VALUE_SCHEMA_NAME, key);
      if (record !== null) realm.delete(record);
    },
    keysWithPrefix(prefix: string): string[] {
      const matches = realm
        .objects(REALM_KEY_VALUE_SCHEMA_NAME)
        .filtered('key BEGINSWITH $0', prefix);
      return Array.from(matches, (record) => stringField(record, 'key'));
    },
  };
}

/**
 * Create a `KeyValueStorage` over an open Realm whose schema
 * includes {@link realmKeyValueSchema}.
 *
 * The backend is {@link createTransactionalKeyValueBackend} with a Realm
 * engine: each write runs as one batch in one `realm.write`, and each read
 * reads the Realm directly. A write call made while the Realm is already in a
 * write transaction rejects with `INVALID_STATE`, because the batch would join
 * a transaction that the store does not control. A write that Realm rejects,
 * for example on a full disk, rejects with Realm's own error and commits
 * nothing.
 */
export function createRealmKeyValueBackend(realm: RealmLike): KeyValueStorage {
  const handle = realmTransaction(realm);
  return createTransactionalKeyValueBackend({
    transaction(body) {
      if (realm.isInTransaction) {
        throw new EncryptionError(
          'The Realm is already in a write transaction. Commit or cancel it before the key-value store writes.',
          EncryptionErrorCode.INVALID_STATE
        );
      }
      realm.write(() => body(handle));
    },
    read(body) {
      return body(handle);
    },
  });
}
