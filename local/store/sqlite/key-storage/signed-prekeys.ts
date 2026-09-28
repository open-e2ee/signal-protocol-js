/**
 * The signed prekeys that a bundle publishes: the EC signed prekey and the
 * last-resort Kyber prekey, with PQXDH replay detection for the Kyber prekey.
 */

import type { EcSignedPreKey, IdentityType, KyberPreKey } from '../../../../keys';
import type { RetainedKyberPreKey } from '../../../../types';
import { bytesToBase64 } from '../../../../internal/crypto/utils';
import {
  ReusedBaseKeyError,
  createEcSignedPreKey,
  createKyberPreKey,
  deleteEcSignedPreKeyByKeyId,
  deleteKyberPreKeyByKeyId,
  getAllEcSignedPreKeys as modelGetAllEcSignedPreKeys,
  getCurrentEcSignedPreKey,
  getCurrentKyberPreKey,
  getEcSignedPreKeyByKeyId,
  getKyberPreKeyByKeyId,
  getMaxEcSignedPreKeyId,
  getMaxKyberPreKeyId,
  markKyberPreKeyUsed as modelMarkKyberPreKeyUsed,
  storeReplacingEcSignedPreKey,
} from '../models';
import { keyStorageError, type KeyStorageContext } from './context';

// ============================================================================
// EC Signed Prekeys
// ============================================================================

/**
 * Store EC signed prekey.
 *
 * IMPORTANT: This marks every active EC signed prekey of the identity type
 * replaced before it inserts the new one, so the new key is the only active
 * one. This matches the server-side behavior and prevents the "stale keyId"
 * bug. The replaced keys stay for in-flight messages until the cull.
 */
export async function storeEcSignedPreKey(
  ctx: KeyStorageContext,
  signedPreKey: EcSignedPreKey,
  identityType: IdentityType
): Promise<void> {
  try {
    const publicKey =
      typeof signedPreKey.publicKey === 'string'
        ? signedPreKey.publicKey
        : bytesToBase64(signedPreKey.publicKey);
    const privateKey =
      typeof signedPreKey.privateKey === 'string'
        ? signedPreKey.privateKey
        : bytesToBase64(signedPreKey.privateKey);
    const signature =
      typeof signedPreKey.signature === 'string'
        ? signedPreKey.signature
        : bytesToBase64(signedPreKey.signature);

    const prekey = createEcSignedPreKey({
      keyId: signedPreKey.keyId,
      publicKey,
      privateKey,
      signature,
      timestamp: signedPreKey.timestamp,
      identityType,
    });

    // storeReplacingEcSignedPreKey marks the active keys replaced and inserts
    // the new key in one transaction.
    await storeReplacingEcSignedPreKey(ctx.db, prekey, identityType);

    // DIAGNOSTIC: Log EC signed prekey storage for tracing
    ctx.logger.debug('storeEcSignedPreKey: Stored EC signed prekey', {
      category: 'E2EE',
      data: {
        keyId: signedPreKey.keyId,
        publicKeyPrefix: publicKey.substring(0, 20),
        timestamp: Date.now(),
        identityType,
      },
    });
  } catch (error) {
    throw keyStorageError('Failed to store EC signed prekey', error);
  }
}

/**
 * Retrieve EC signed prekey by ID.
 *
 * @param keyId - Optional key ID to retrieve. If not provided, returns the current (most recent) EC signed prekey.
 * @param identityType - 'aci' or 'pni'
 * @returns The EC signed prekey, or null if not found
 */
export async function getEcSignedPreKey(
  ctx: KeyStorageContext,
  keyId: number | undefined,
  identityType: IdentityType
): Promise<EcSignedPreKey | null> {
  try {
    let prekey;

    if (keyId !== undefined) {
      prekey = await getEcSignedPreKeyByKeyId(ctx.db, keyId, identityType);

      // DIAGNOSTIC: Log lookup result for debugging EC signed prekey issues
      if (!prekey) {
        const allPreKeys = await modelGetAllEcSignedPreKeys(ctx.db, identityType);
        ctx.logger.warn('getEcSignedPreKey: Key not found by ID', {
          category: 'E2EE',
          data: {
            requestedKeyId: keyId,
            availableKeyIds: allPreKeys.map((k) => k.keyId),
            totalAvailable: allPreKeys.length,
            identityType,
          },
        });
      }
    } else {
      prekey = await getCurrentEcSignedPreKey(ctx.db, identityType);
    }

    if (!prekey) {
      return null;
    }

    return prekey.toEcSignedPreKey() as EcSignedPreKey;
  } catch (error) {
    throw keyStorageError('Failed to retrieve EC signed prekey', error);
  }
}

/** Get the active EC signed prekeys. Replaced keys are not returned. */
export async function getAllEcSignedPreKeys(
  ctx: KeyStorageContext,
  identityType: IdentityType
): Promise<EcSignedPreKey[]> {
  try {
    const prekeys = await modelGetAllEcSignedPreKeys(ctx.db, identityType);
    return prekeys.map((prekey) => prekey.toEcSignedPreKey() as EcSignedPreKey);
  } catch (error) {
    throw keyStorageError('Failed to retrieve all EC signed prekeys', error);
  }
}

/**
 * Mark an EC signed prekey as stale by ID.
 *
 * Called during cleanup to retire expired archived prekeys.
 * The prekey is retained for in-flight message decryption and
 * can be permanently purged later via purgeStaleEcSignedPreKeys().
 */
export async function removeEcSignedPreKey(
  ctx: KeyStorageContext,
  keyId: number,
  identityType: IdentityType
): Promise<void> {
  try {
    await deleteEcSignedPreKeyByKeyId(ctx.db, keyId, identityType);
  } catch (error) {
    throw keyStorageError('Failed to mark EC signed prekey as stale', error);
  }
}

// ============================================================================
// Kyber Prekeys (Post-Quantum)
// ============================================================================

/** Store Kyber prekey (post-quantum resistance) */
export async function storeKyberPreKey(
  ctx: KeyStorageContext,
  kyberPreKey: KyberPreKey,
  identityType: IdentityType
): Promise<void> {
  try {
    const prekey = createKyberPreKey({
      keyId: kyberPreKey.keyId,
      publicKey: kyberPreKey.publicKey,
      privateKey: kyberPreKey.privateKey,
      signature: kyberPreKey.signature,
      timestamp: kyberPreKey.timestamp,
      identityType,
    });
    await prekey.save(ctx.db);
  } catch (error) {
    throw keyStorageError(`Failed to store Kyber prekey ${kyberPreKey.keyId}`, error);
  }
}

/** Retrieve the current Kyber prekey */
export async function getKyberPreKey(
  ctx: KeyStorageContext,
  identityType: IdentityType
): Promise<{
  keyId: number;
  publicKey: string;
  privateKey: string;
  signature: string;
  timestamp: number;
} | null> {
  try {
    const prekey = await getCurrentKyberPreKey(ctx.db, identityType);
    if (!prekey) {
      return null;
    }
    return prekey.toKyberPreKey();
  } catch (error) {
    throw keyStorageError('Failed to retrieve Kyber prekey', error);
  }
}

export async function getKyberPreKeyById(
  ctx: KeyStorageContext,
  keyId: number,
  identityType: IdentityType
): Promise<RetainedKyberPreKey | null> {
  try {
    const prekey = await getKyberPreKeyByKeyId(ctx.db, keyId, identityType);
    return prekey
      ? { preKey: prekey.toKyberPreKey() as KyberPreKey, instanceId: prekey.instanceId }
      : null;
  } catch (error) {
    throw keyStorageError(`Failed to retrieve Kyber prekey ${keyId}`, error);
  }
}

/**
 * Mark Kyber prekey as used: PQXDH replay detection
 *
 * Inserts a (kyberPreKeyId, signedPreKeyIdentity, signedPreKeyId, baseKey) tuple.
 * Duplicate tuple = replay attack -> throws ReusedBaseKeyError.
 */
export async function markKyberPreKeyUsed(
  ctx: KeyStorageContext,
  kyberPreKeyId: number,
  signedPreKeyId: number,
  baseKeyBytes: Uint8Array,
  identityType: IdentityType
): Promise<void> {
  try {
    await modelMarkKyberPreKeyUsed(
      ctx.db,
      kyberPreKeyId,
      signedPreKeyId,
      baseKeyBytes,
      identityType
    );
  } catch (error: unknown) {
    if (error instanceof ReusedBaseKeyError) throw error;
    throw keyStorageError(`Failed to mark Kyber prekey ${kyberPreKeyId} as used`, error);
  }
}

export async function deleteKyberPreKey(
  ctx: KeyStorageContext,
  id: number,
  identityType: IdentityType
): Promise<void> {
  try {
    await deleteKyberPreKeyByKeyId(ctx.db, id, identityType);
  } catch (error) {
    throw keyStorageError(`Failed to delete Kyber prekey ${id}`, error);
  }
}

// ============================================================================
// Key Recovery Support (PQXDH §4.13 Identifier Collision Recovery)
// ============================================================================

/**
 * Get the maximum signed prekey ID in storage.
 *
 * Used during key recovery to generate new prekeys with fresh IDs
 * that avoid identifier collisions (PQXDH §4.13).
 *
 * @returns The highest prekey_id, or 0 if no signed prekeys exist
 */
export async function getEcSignedPreKeyMaxId(
  ctx: KeyStorageContext,
  identityType: IdentityType
): Promise<number> {
  try {
    return await getMaxEcSignedPreKeyId(ctx.db, identityType);
  } catch (error) {
    throw keyStorageError('Failed to get max signed prekey ID', error);
  }
}

/**
 * Get the maximum Kyber prekey ID in storage.
 *
 * @returns The highest prekey_id, or 0 if no Kyber prekeys exist
 */
export async function getKyberPreKeyMaxId(
  ctx: KeyStorageContext,
  identityType: IdentityType
): Promise<number> {
  try {
    return await getMaxKyberPreKeyId(ctx.db, identityType);
  } catch (error) {
    throw keyStorageError('Failed to get max Kyber prekey ID', error);
  }
}
