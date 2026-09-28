/**
 * The one-time prekeys that a bundle publishes: EC one-time prekeys and the
 * signed one-time KEM prekeys. Each is consumed once, on session setup.
 */

import type { EcOneTimePreKey, IdentityType, KemOneTimePreKey } from '../../../../keys';
import {
  countEcOneTimePreKeys,
  countKyberOneTimePreKeys,
  createEcOneTimePreKey,
  createKyberOneTimePreKey,
  deleteEcOneTimePreKeyByKeyId,
  deleteKyberOneTimePreKeyByKeyId,
  getAllEcOneTimePreKeys,
  getAllKyberOneTimePreKeys,
  getKyberOneTimePreKeyByKeyId,
  storeBatchEcOneTimePreKeys,
  storeBatchKyberOneTimePreKeys,
} from '../models';
import { keyStorageError, type KeyStorageContext } from './context';

// ============================================================================
// EC One-Time Prekeys
// ============================================================================

/** Store EC one-time prekeys (batch storage) */
export async function storeEcOneTimePreKeys(
  ctx: KeyStorageContext,
  prekeys: EcOneTimePreKey[],
  identityType: IdentityType
): Promise<void> {
  try {
    const modelPreKeys = prekeys.map((pk) =>
      createEcOneTimePreKey({
        keyId: pk.keyId,
        publicKey: pk.publicKey,
        privateKey: pk.privateKey,
        identityType,
      })
    );

    await storeBatchEcOneTimePreKeys(ctx.db, modelPreKeys);
  } catch (error) {
    throw keyStorageError('Failed to store EC one-time prekeys', error);
  }
}

/** Retrieve all EC one-time prekeys */
export async function getEcOneTimePreKeys(
  ctx: KeyStorageContext,
  identityType: IdentityType
): Promise<EcOneTimePreKey[]> {
  try {
    const prekeys = await getAllEcOneTimePreKeys(ctx.db, identityType);
    return prekeys.map((pk) => pk.toEcOneTimePreKey() as EcOneTimePreKey);
  } catch (error) {
    throw keyStorageError('Failed to retrieve EC one-time prekeys', error);
  }
}

/** Remove consumed EC one-time prekey */
export async function removeEcOneTimePreKey(
  ctx: KeyStorageContext,
  preKeyId: number,
  identityType: IdentityType
): Promise<void> {
  try {
    await deleteEcOneTimePreKeyByKeyId(ctx.db, preKeyId, identityType);
  } catch (error) {
    throw keyStorageError('Failed to remove EC one-time prekey', error);
  }
}

export async function getEcOneTimePreKeyCount(
  ctx: KeyStorageContext,
  identityType: IdentityType
): Promise<number> {
  try {
    return await countEcOneTimePreKeys(ctx.db, identityType);
  } catch (error) {
    throw keyStorageError('Failed to get EC one-time prekey count', error);
  }
}

// ============================================================================
// Kyber One-Time Prekeys (Post-Quantum, Consumed on Use)
// ============================================================================

/**
 * Store one-time KEM prekeys (batch storage)
 *
 * Per PQXDH spec Section 3.2, these are signed one-time pqkem prekeys
 * that provide per-session post-quantum forward secrecy.
 */
export async function storeKemOneTimePreKeys(
  ctx: KeyStorageContext,
  prekeys: KemOneTimePreKey[],
  identityType: IdentityType
): Promise<void> {
  try {
    const modelPreKeys = prekeys.map((pk) =>
      createKyberOneTimePreKey({
        keyId: pk.keyId,
        publicKey: pk.publicKey,
        privateKey: pk.privateKey,
        signature: pk.signature,
        timestamp: pk.timestamp,
        identityType,
      })
    );

    await storeBatchKyberOneTimePreKeys(ctx.db, modelPreKeys);
  } catch (error) {
    throw keyStorageError('Failed to store one-time Kyber prekeys', error);
  }
}

/** Retrieve all one-time KEM prekeys */
export async function getKemOneTimePreKeys(
  ctx: KeyStorageContext,
  identityType: IdentityType
): Promise<KemOneTimePreKey[]> {
  try {
    const prekeys = await getAllKyberOneTimePreKeys(ctx.db, identityType);
    return prekeys.map((pk) => pk.toKemOneTimePreKey() as KemOneTimePreKey);
  } catch (error) {
    throw keyStorageError('Failed to retrieve one-time Kyber prekeys', error);
  }
}

/**
 * Retrieve a specific one-time KEM prekey by ID
 * Used during session establishment for decapsulation
 */
export async function getKemOneTimePreKey(
  ctx: KeyStorageContext,
  keyId: number,
  identityType: IdentityType
): Promise<KemOneTimePreKey | null> {
  try {
    const prekey = await getKyberOneTimePreKeyByKeyId(ctx.db, keyId, identityType);
    if (!prekey) {
      return null;
    }
    return prekey.toKemOneTimePreKey() as KemOneTimePreKey;
  } catch (error) {
    throw keyStorageError(`Failed to retrieve one-time Kyber prekey ${keyId}`, error);
  }
}

/**
 * Remove one-time KEM prekey after consumption
 *
 * CRITICAL: Must be called immediately after successful decapsulation
 * to provide per-session post-quantum forward secrecy.
 */
export async function removeKemOneTimePreKey(
  ctx: KeyStorageContext,
  keyId: number,
  identityType: IdentityType
): Promise<void> {
  try {
    await deleteKyberOneTimePreKeyByKeyId(ctx.db, keyId, identityType);

    ctx.logger.debug('Removed one-time KEM prekey after consumption', {
      category: 'KeyStorage',
      data: { keyId },
    });
  } catch (error) {
    throw keyStorageError(`Failed to remove one-time Kyber prekey ${keyId}`, error);
  }
}

export async function getKemOneTimePreKeyCount(
  ctx: KeyStorageContext,
  identityType: IdentityType
): Promise<number> {
  try {
    return await countKyberOneTimePreKeys(ctx.db, identityType);
  } catch (error) {
    throw keyStorageError('Failed to get one-time Kyber prekey count', error);
  }
}
