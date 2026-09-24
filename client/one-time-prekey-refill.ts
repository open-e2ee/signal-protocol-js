/**
 * One-time prekey refill
 *
 * One owner for the refill decision and the fresh batch. The rotation core
 * (background and headless rotation) and the server sync path call this
 * function with the server counts they already hold, so neither keeps its own
 * copy of the rules:
 *
 * - The EC set and the KEM set are checked against the threshold separately.
 * - A set is marked replaced only when this call makes a new batch of that
 *   type. Retained keys stay decrypt-only until the maintenance store culls
 *   them after the grace period.
 * - Each batch starts at the highest local ID of its type plus one. The local
 *   read includes retained replaced keys, so a fresh batch never reuses an ID
 *   whose private key a peer may still address.
 *
 * The caller publishes the returned uploads. This module makes no relay call.
 */

import { defaultSignalProtocolLogger, type Logger } from '../logger';
import type { SignalProtocolLocalStore } from '../types';
import { ONE_TIME_PREKEY_BATCH_SIZE } from '../types';
import type { IdentityType } from '../keys/types';
import type { PreKeyUpload } from '../remote/relay/types';
import { generateEcOneTimePreKeys, generateKemOneTimePreKeys } from '../keys';
import type { PreKeyMaintenanceStore } from './config';

/**
 * Minimum one-time prekeys before a refill starts.
 * When a server count drops below this threshold, the client generates and
 * uploads a new batch of that type.
 */
export const MIN_PREKEY_REPLENISHMENT_THRESHOLD = 10;

export interface OneTimePreKeyRefillInput {
  storage: SignalProtocolLocalStore;
  identityType: IdentityType;
  /** Server count of unconsumed EC one-time prekeys. */
  serverEcCount: number;
  /** Server count of unconsumed KEM one-time prekeys. */
  serverKemCount: number;
  threshold?: number;
  preKeyMaintenance?: PreKeyMaintenanceStore;
  logger?: Required<Logger>;
}

export interface OneTimePreKeyRefill {
  /** Public halves of every fresh key, in generation order: EC first, then KEM. */
  uploads: PreKeyUpload[];
  ecGenerated: number;
  kemGenerated: number;
}

function nextOneTimePreKeyId(retained: readonly { keyId: number }[]): number {
  return retained.reduce((max, key) => Math.max(max, key.keyId), -1) + 1;
}

/**
 * Generate and store the one-time prekey batches that the server counts call
 * for, and return their public halves for the caller's publication.
 */
export async function refillOneTimePreKeys(
  input: OneTimePreKeyRefillInput
): Promise<OneTimePreKeyRefill> {
  const {
    storage,
    identityType,
    serverEcCount,
    serverKemCount,
    threshold = MIN_PREKEY_REPLENISHMENT_THRESHOLD,
    preKeyMaintenance,
    logger = defaultSignalProtocolLogger,
  } = input;
  const uploads: PreKeyUpload[] = [];
  let ecGenerated = 0;
  let kemGenerated = 0;

  if (serverEcCount < threshold) {
    await preKeyMaintenance?.markEcOneTimePreKeysReplaced(identityType);
    const startId = nextOneTimePreKeyId(await storage.getEcOneTimePreKeys(identityType));
    const batch = await generateEcOneTimePreKeys(ONE_TIME_PREKEY_BATCH_SIZE, startId);
    await storage.storeEcOneTimePreKeys(batch, identityType);
    uploads.push(
      ...batch.map((key) => ({
        type: 'ecPreKey' as const,
        keyId: key.keyId,
        publicKey: key.publicKey as string,
      }))
    );
    ecGenerated = batch.length;
    logger.debug('Generated fresh EC one-time prekeys', {
      category: 'E2EE',
      data: { identityType, count: batch.length, startId, serverEcCount, threshold },
    });
  }

  if (serverKemCount < threshold) {
    const identityKey = await storage.getIdentityKey(identityType);
    if (!identityKey) {
      throw new Error(`Identity key missing, cannot sign KEM one-time prekeys (${identityType})`);
    }
    await preKeyMaintenance?.markKyberOneTimePreKeysReplaced(identityType);
    const startId = nextOneTimePreKeyId(await storage.getKemOneTimePreKeys(identityType));
    const batch = await generateKemOneTimePreKeys(identityKey, ONE_TIME_PREKEY_BATCH_SIZE, startId);
    await storage.storeKemOneTimePreKeys(batch, identityType);
    uploads.push(
      ...batch.map((key) => ({
        type: 'kemOneTimePreKey' as const,
        keyId: key.keyId,
        publicKey: key.publicKey as string,
        signature: key.signature as string,
      }))
    );
    kemGenerated = batch.length;
    logger.debug('Generated fresh KEM one-time prekeys', {
      category: 'E2EE',
      data: { identityType, count: batch.length, startId, serverKemCount, threshold },
    });
  }

  return { uploads, ecGenerated, kemGenerated };
}
