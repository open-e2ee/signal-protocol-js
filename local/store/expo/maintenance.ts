import type {
  PreKeyMaintenanceStore,
  ReplacedOneTimePreKeyCullResult,
  ReplacedPreKeyCullResult,
} from '../../../types/protocol-config';
import { cullReplacedEcSignedPreKeys } from './models/ec-signed-prekey';
import {
  cullReplacedEcOneTimePreKeys,
  markAllEcOneTimePreKeysReplaced,
} from './models/ec-one-time-prekey';
import { cullReplacedKyberPreKeys } from './models/kyber-prekey';
import {
  cullReplacedKyberOneTimePreKeys,
  markAllKyberOneTimePreKeysReplaced,
} from './models/kyber-one-time-prekey';
import type { IdentityType } from '../../../keys/types';

export {};

async function cullReplacedOneTimePreKeys(
  maxReplacedAgeMs: number,
  identityType?: IdentityType
): Promise<ReplacedOneTimePreKeyCullResult> {
  const [ecOneTimePreKeys, kyberOneTimePreKeys] = await Promise.all([
    cullReplacedEcOneTimePreKeys(maxReplacedAgeMs, identityType),
    cullReplacedKyberOneTimePreKeys(maxReplacedAgeMs, identityType),
  ]);

  return {
    ecOneTimePreKeys,
    kyberOneTimePreKeys,
  };
}

async function cullReplacedPreKeys(maxReplacedAgeMs: number): Promise<ReplacedPreKeyCullResult> {
  const [ecSignedPreKeys, kyberPreKeys, oneTimeCounts] = await Promise.all([
    cullReplacedEcSignedPreKeys(maxReplacedAgeMs),
    cullReplacedKyberPreKeys(maxReplacedAgeMs),
    cullReplacedOneTimePreKeys(maxReplacedAgeMs),
  ]);

  return {
    ecSignedPreKeys,
    kyberPreKeys,
    ecOneTimePreKeys: oneTimeCounts.ecOneTimePreKeys,
    kyberOneTimePreKeys: oneTimeCounts.kyberOneTimePreKeys,
  };
}

export function createPreKeyMaintenanceStore(): PreKeyMaintenanceStore {
  return {
    markEcOneTimePreKeysReplaced: markAllEcOneTimePreKeysReplaced,
    markKyberOneTimePreKeysReplaced: markAllKyberOneTimePreKeysReplaced,
    cullReplacedOneTimePreKeys,
    cullReplacedPreKeys,
  };
}
