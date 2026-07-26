import {
  and as ormAnd,
  asc as ormAsc,
  count as ormCount,
  desc as ormDesc,
  eq as ormEq,
  gt as ormGt,
  gte as ormGte,
  inArray as ormInArray,
  isNotNull as ormIsNotNull,
  isNull as ormIsNull,
  lt as ormLt,
  lte as ormLte,
  ne as ormNe,
  notInArray as ormNotInArray,
  or as ormOr,
  sql as ormSql,
} from 'drizzle-orm';
import type { ExpoSQLiteDatabase } from 'drizzle-orm/expo-sqlite';
import type { SQLiteDatabase } from 'expo-sqlite';

import * as schema from './schema';

export type {
  AuthCredentialCacheRow,
  EcOneTimePreKey,
  EcSignedPreKey,
  GroupMasterKeyRow,
  GroupStateCacheRow,
  IdentityKey,
  KyberOneTimePreKey,
  KyberPreKey,
  MessageRecord,
  NewAuthCredentialCacheRow,
  NewEcOneTimePreKey,
  NewEcSignedPreKey,
  NewGroupMasterKeyRow,
  NewGroupStateCacheRow,
  NewIdentityKey,
  NewKyberOneTimePreKey,
  NewKyberPreKey,
  NewMessageRecord,
  NewProfileKey,
  NewRecipientIdentity,
  NewSenderKey,
  NewSession,
  ProfileKey,
  RecipientIdentity,
  SenderKey,
  Session,
} from './schema';

export type SignalProtocolExpoDrizzleDB = ExpoSQLiteDatabase<typeof schema>;
export type SignalProtocolExpoRawDatabase = SQLiteDatabase;

export interface SignalProtocolExpoDbBindings {
  getDrizzle?: () => Promise<SignalProtocolExpoDrizzleDB>;
  getRawDatabase?: () => SignalProtocolExpoRawDatabase;
  eq?: typeof ormEq;
  and?: typeof ormAnd;
  or?: typeof ormOr;
  gt?: typeof ormGt;
  gte?: typeof ormGte;
  lt?: typeof ormLt;
  lte?: typeof ormLte;
  ne?: typeof ormNe;
  isNull?: typeof ormIsNull;
  isNotNull?: typeof ormIsNotNull;
  inArray?: typeof ormInArray;
  notInArray?: typeof ormNotInArray;
  sql?: typeof ormSql;
  desc?: typeof ormDesc;
  asc?: typeof ormAsc;
  count?: typeof ormCount;
  profileKeys?: typeof schema.profileKeys;
  identityKeys?: typeof schema.identityKeys;
  recipientIdentities?: typeof schema.recipientIdentities;
  ecSignedPreKeys?: typeof schema.ecSignedPreKeys;
  ecOneTimePreKeys?: typeof schema.ecOneTimePreKeys;
  kyberPreKeys?: typeof schema.kyberPreKeys;
  kyberPreKeyUsed?: typeof schema.kyberPreKeyUsed;
  kyberOneTimePreKeys?: typeof schema.kyberOneTimePreKeys;
  sessions?: typeof schema.sessions;
  senderKeys?: typeof schema.senderKeys;
  messageRecords?: typeof schema.messageRecords;
  groupMasterKeys?: typeof schema.groupMasterKeys;
  groupStateCache?: typeof schema.groupStateCache;
  authCredentialCache?: typeof schema.authCredentialCache;
}

let bindings: SignalProtocolExpoDbBindings = {};

export function configureSignalProtocolExpoDbBindings(next: SignalProtocolExpoDbBindings): void {
  bindings = { ...bindings, ...next };
}

export function resetSignalProtocolExpoDbBindings(): void {
  bindings = {};
}

function requireBinding<K extends keyof SignalProtocolExpoDbBindings>(
  key: K
): NonNullable<SignalProtocolExpoDbBindings[K]> {
  const value = bindings[key];
  if (!value) {
    throw new Error(
      'Expo storage DB bindings not configured. Configure them from the host app before using Expo storage.'
    );
  }

  return value as NonNullable<SignalProtocolExpoDbBindings[K]>;
}

export async function getDrizzle(): Promise<SignalProtocolExpoDrizzleDB> {
  return requireBinding('getDrizzle')();
}

export function getRawDatabase(): SignalProtocolExpoRawDatabase {
  return requireBinding('getRawDatabase')();
}

export const eq: typeof ormEq = ((...args: Parameters<typeof ormEq>) =>
  (bindings.eq ?? ormEq)(...args)) as typeof ormEq;
export const and: typeof ormAnd = ((...args: Parameters<typeof ormAnd>) =>
  (bindings.and ?? ormAnd)(...args)) as typeof ormAnd;
export const or: typeof ormOr = ((...args: Parameters<typeof ormOr>) =>
  (bindings.or ?? ormOr)(...args)) as typeof ormOr;
export const gt: typeof ormGt = ((...args: Parameters<typeof ormGt>) =>
  (bindings.gt ?? ormGt)(...args)) as typeof ormGt;
export const gte: typeof ormGte = ((...args: Parameters<typeof ormGte>) =>
  (bindings.gte ?? ormGte)(...args)) as typeof ormGte;
export const lt: typeof ormLt = ((...args: Parameters<typeof ormLt>) =>
  (bindings.lt ?? ormLt)(...args)) as typeof ormLt;
export const lte: typeof ormLte = ((...args: Parameters<typeof ormLte>) =>
  (bindings.lte ?? ormLte)(...args)) as typeof ormLte;
export const ne: typeof ormNe = ((...args: Parameters<typeof ormNe>) =>
  (bindings.ne ?? ormNe)(...args)) as typeof ormNe;
export const isNull: typeof ormIsNull = ((...args: Parameters<typeof ormIsNull>) =>
  (bindings.isNull ?? ormIsNull)(...args)) as typeof ormIsNull;
export const isNotNull: typeof ormIsNotNull = ((...args: Parameters<typeof ormIsNotNull>) =>
  (bindings.isNotNull ?? ormIsNotNull)(...args)) as typeof ormIsNotNull;
export const inArray: typeof ormInArray = ((...args: Parameters<typeof ormInArray>) =>
  (bindings.inArray ?? ormInArray)(...args)) as typeof ormInArray;
export const notInArray: typeof ormNotInArray = ((...args: Parameters<typeof ormNotInArray>) =>
  (bindings.notInArray ?? ormNotInArray)(...args)) as typeof ormNotInArray;
export const sql: typeof ormSql = ((...args: Parameters<typeof ormSql>) =>
  (bindings.sql ?? ormSql)(...args)) as typeof ormSql;
export const desc: typeof ormDesc = ((...args: Parameters<typeof ormDesc>) =>
  (bindings.desc ?? ormDesc)(...args)) as typeof ormDesc;
export const asc: typeof ormAsc = ((...args: Parameters<typeof ormAsc>) =>
  (bindings.asc ?? ormAsc)(...args)) as typeof ormAsc;
export const count: typeof ormCount = ((...args: Parameters<typeof ormCount>) =>
  (bindings.count ?? ormCount)(...args)) as typeof ormCount;

const fallbackTables = {
  profileKeys: schema.profileKeys,
  identityKeys: schema.identityKeys,
  recipientIdentities: schema.recipientIdentities,
  ecSignedPreKeys: schema.ecSignedPreKeys,
  ecOneTimePreKeys: schema.ecOneTimePreKeys,
  kyberPreKeys: schema.kyberPreKeys,
  kyberPreKeyUsed: schema.kyberPreKeyUsed,
  kyberOneTimePreKeys: schema.kyberOneTimePreKeys,
  sessions: schema.sessions,
  senderKeys: schema.senderKeys,
  messageRecords: schema.messageRecords,
  groupMasterKeys: schema.groupMasterKeys,
  groupStateCache: schema.groupStateCache,
  authCredentialCache: schema.authCredentialCache,
};

type TableBindingKey = keyof typeof fallbackTables;
type TableBindingMap = typeof fallbackTables;

function getCurrentTable<K extends TableBindingKey>(
  key: K,
  self?: TableBindingMap[K]
): TableBindingMap[K] {
  const bound = bindings[key] as TableBindingMap[K] | undefined;
  if (bound && bound !== self) {
    return bound;
  }

  return fallbackTables[key];
}

function createTableProxy<T extends object>(target: T, getCurrent: () => T): T {
  return new Proxy(target, {
    get(_target, prop) {
      return (getCurrent() as Record<string | symbol, unknown>)[prop];
    },
    has(_target, prop) {
      return prop in getCurrent();
    },
    ownKeys() {
      return Reflect.ownKeys(getCurrent());
    },
    getOwnPropertyDescriptor(_target, prop) {
      return Object.getOwnPropertyDescriptor(getCurrent(), prop);
    },
  });
}

function createBoundTableProxy<K extends TableBindingKey>(key: K): TableBindingMap[K] {
  const proxyRef: { current: TableBindingMap[K] } = { current: fallbackTables[key] };
  const proxy = createTableProxy(fallbackTables[key], () => getCurrentTable(key, proxyRef.current));
  proxyRef.current = proxy;
  return proxy;
}

export const profileKeys: typeof schema.profileKeys = createBoundTableProxy('profileKeys');
export const identityKeys: typeof schema.identityKeys = createBoundTableProxy('identityKeys');
export const recipientIdentities: typeof schema.recipientIdentities =
  createBoundTableProxy('recipientIdentities');
export const ecSignedPreKeys: typeof schema.ecSignedPreKeys =
  createBoundTableProxy('ecSignedPreKeys');
export const ecOneTimePreKeys: typeof schema.ecOneTimePreKeys =
  createBoundTableProxy('ecOneTimePreKeys');
export const kyberPreKeys: typeof schema.kyberPreKeys = createBoundTableProxy('kyberPreKeys');
export const kyberPreKeyUsed: typeof schema.kyberPreKeyUsed =
  createBoundTableProxy('kyberPreKeyUsed');
export const kyberOneTimePreKeys: typeof schema.kyberOneTimePreKeys =
  createBoundTableProxy('kyberOneTimePreKeys');
export const sessions: typeof schema.sessions = createBoundTableProxy('sessions');
export const senderKeys: typeof schema.senderKeys = createBoundTableProxy('senderKeys');
export const messageRecords: typeof schema.messageRecords = createBoundTableProxy('messageRecords');
export const groupMasterKeys: typeof schema.groupMasterKeys =
  createBoundTableProxy('groupMasterKeys');
export const groupStateCache: typeof schema.groupStateCache =
  createBoundTableProxy('groupStateCache');
export const authCredentialCache: typeof schema.authCredentialCache =
  createBoundTableProxy('authCredentialCache');

export const tables = {
  get profileKeys(): typeof schema.profileKeys {
    return getCurrentTable('profileKeys', profileKeys);
  },
  get identityKeys(): typeof schema.identityKeys {
    return getCurrentTable('identityKeys', identityKeys);
  },
  get recipientIdentities(): typeof schema.recipientIdentities {
    return getCurrentTable('recipientIdentities', recipientIdentities);
  },
  get ecSignedPreKeys(): typeof schema.ecSignedPreKeys {
    return getCurrentTable('ecSignedPreKeys', ecSignedPreKeys);
  },
  get ecOneTimePreKeys(): typeof schema.ecOneTimePreKeys {
    return getCurrentTable('ecOneTimePreKeys', ecOneTimePreKeys);
  },
  get kyberPreKeys(): typeof schema.kyberPreKeys {
    return getCurrentTable('kyberPreKeys', kyberPreKeys);
  },
  get kyberPreKeyUsed(): typeof schema.kyberPreKeyUsed {
    return getCurrentTable('kyberPreKeyUsed', kyberPreKeyUsed);
  },
  get kyberOneTimePreKeys(): typeof schema.kyberOneTimePreKeys {
    return getCurrentTable('kyberOneTimePreKeys', kyberOneTimePreKeys);
  },
  get sessions(): typeof schema.sessions {
    return getCurrentTable('sessions', sessions);
  },
  get senderKeys(): typeof schema.senderKeys {
    return getCurrentTable('senderKeys', senderKeys);
  },
  get messageRecords(): typeof schema.messageRecords {
    return getCurrentTable('messageRecords', messageRecords);
  },
  get groupMasterKeys(): typeof schema.groupMasterKeys {
    return getCurrentTable('groupMasterKeys', groupMasterKeys);
  },
  get groupStateCache(): typeof schema.groupStateCache {
    return getCurrentTable('groupStateCache', groupStateCache);
  },
  get authCredentialCache(): typeof schema.authCredentialCache {
    return getCurrentTable('authCredentialCache', authCredentialCache);
  },
};
