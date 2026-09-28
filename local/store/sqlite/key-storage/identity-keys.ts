/** The local identity key pair and registration ID of each identity type. */

import type { IdentityKeyPair, IdentityType } from '../../../../keys';
import type { PublicKey, PrivateKey, KeyPair } from '../../../../keys/branded';
import {
  createPrimaryIdentityKey,
  deletePrimaryIdentityKey,
  getLocalRegistrationId as modelGetLocalRegistrationId,
  getPrimaryIdentityKey,
  setLocalRegistrationId as modelSetLocalRegistrationId,
} from '../models';
import { keyStorageError, type KeyStorageContext } from './context';

/**
 * Store identity key pair (only done once per device per identity type)
 *
 * IdentityKeyPair has nested structure:
 * - dhKey: { publicKey, privateKey } (X25519 for DH)
 * - signingKey: { publicKey, privateKey } (Ed25519 for signatures)
 * - registrationId: number, kept as the local registration ID of the type
 */
export async function storeIdentityKey(
  ctx: KeyStorageContext,
  keyPair: IdentityKeyPair,
  identityType: IdentityType
): Promise<void> {
  try {
    const identity = createPrimaryIdentityKey({
      publicKey: keyPair.dhKey.publicKey,
      dhKey: keyPair.dhKey,
      signingKey: keyPair.signingKey,
      identityType,
    });
    await ctx.db.transaction(async (tx) => {
      await identity.save(tx);
      await modelSetLocalRegistrationId(tx, keyPair.registrationId, identityType);
    });
  } catch (error) {
    ctx.logger.error('[KeyStorage] storeIdentityKey failed', {
      category: 'E2EE',
      error: error instanceof Error ? error : new Error(String(error)),
    });
    throw keyStorageError('Failed to store identity key', error);
  }
}

export async function getIdentityKey(
  ctx: KeyStorageContext,
  identityType: IdentityType
): Promise<IdentityKeyPair | null> {
  try {
    const identity = await getPrimaryIdentityKey(ctx.db, identityType);

    if (!identity) {
      return null;
    }

    const dhKeyRaw = identity.dhKey;
    const signingKeyRaw = identity.signingKey;
    const registrationId = await modelGetLocalRegistrationId(ctx.db, identityType);

    if (!dhKeyRaw || !signingKeyRaw || registrationId === null) {
      return null;
    }

    // Cast strings to branded types for type safety
    const dhKey: KeyPair = {
      publicKey: dhKeyRaw.publicKey as PublicKey,
      privateKey: dhKeyRaw.privateKey as PrivateKey,
    };
    const signingKey: KeyPair = {
      publicKey: signingKeyRaw.publicKey as PublicKey,
      privateKey: signingKeyRaw.privateKey as PrivateKey,
    };

    return { dhKey, signingKey, registrationId };
  } catch (error) {
    ctx.logger.error('[KeyStorage] getIdentityKey failed', {
      category: 'E2EE',
      error: error instanceof Error ? error : new Error(String(error)),
    });
    throw keyStorageError('Failed to retrieve identity key', error);
  }
}

export async function deleteIdentityKey(
  ctx: KeyStorageContext,
  identityType: IdentityType
): Promise<void> {
  try {
    await deletePrimaryIdentityKey(ctx.db, identityType);
  } catch (error) {
    throw keyStorageError('Failed to delete identity key', error);
  }
}

export async function hasIdentityKey(
  ctx: KeyStorageContext,
  identityType: IdentityType
): Promise<boolean> {
  try {
    const key = await getIdentityKey(ctx, identityType);
    return key !== null;
  } catch {
    return false;
  }
}

export async function getLocalRegistrationId(
  ctx: KeyStorageContext,
  identityType: IdentityType
): Promise<number> {
  const registrationId = await modelGetLocalRegistrationId(ctx.db, identityType);
  return registrationId ?? 0;
}

export async function setLocalRegistrationId(
  ctx: KeyStorageContext,
  id: number,
  identityType: IdentityType
): Promise<void> {
  await modelSetLocalRegistrationId(ctx.db, id, identityType);
}
