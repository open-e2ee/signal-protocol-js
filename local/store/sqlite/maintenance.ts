/**
 * Replaced-prekey maintenance over one SQLite executor.
 */

import type {
  PreKeyMaintenanceStore,
  ReplacedOneTimePreKeyCullResult,
  ReplacedPreKeyCullResult,
} from '../../../types/protocol-config';
import type { IdentityType } from '../../../keys/types';
import type { SqliteExecutor } from './driver';
import {
  cullReplacedEcOneTimePreKeys,
  cullReplacedEcSignedPreKeys,
  cullReplacedKyberOneTimePreKeys,
  cullReplacedKyberPreKeys,
  markAllEcOneTimePreKeysReplaced,
  markAllKyberOneTimePreKeysReplaced,
} from './models';

async function cullReplacedOneTimePreKeys(
  db: SqliteExecutor,
  maxReplacedAgeMs: number,
  identityType?: IdentityType
): Promise<ReplacedOneTimePreKeyCullResult> {
  const ecOneTimePreKeys = await cullReplacedEcOneTimePreKeys(db, maxReplacedAgeMs, identityType);
  const kyberOneTimePreKeys = await cullReplacedKyberOneTimePreKeys(
    db,
    maxReplacedAgeMs,
    identityType
  );

  return {
    ecOneTimePreKeys,
    kyberOneTimePreKeys,
  };
}

async function cullReplacedPreKeys(
  db: SqliteExecutor,
  maxReplacedAgeMs: number
): Promise<ReplacedPreKeyCullResult> {
  const ecSignedPreKeys = await cullReplacedEcSignedPreKeys(db, maxReplacedAgeMs);
  const kyberPreKeys = await cullReplacedKyberPreKeys(db, maxReplacedAgeMs);
  const oneTimeCounts = await cullReplacedOneTimePreKeys(db, maxReplacedAgeMs);

  return {
    ecSignedPreKeys,
    kyberPreKeys,
    ecOneTimePreKeys: oneTimeCounts.ecOneTimePreKeys,
    kyberOneTimePreKeys: oneTimeCounts.kyberOneTimePreKeys,
  };
}

export function createSqlitePreKeyMaintenanceStore(db: SqliteExecutor): PreKeyMaintenanceStore {
  return {
    markEcOneTimePreKeysReplaced: (identityType) =>
      markAllEcOneTimePreKeysReplaced(db, identityType),
    markKyberOneTimePreKeysReplaced: (identityType) =>
      markAllKyberOneTimePreKeysReplaced(db, identityType),
    cullReplacedOneTimePreKeys: (maxReplacedAgeMs, identityType) =>
      cullReplacedOneTimePreKeys(db, maxReplacedAgeMs, identityType),
    cullReplacedPreKeys: (maxReplacedAgeMs) => cullReplacedPreKeys(db, maxReplacedAgeMs),
  };
}
