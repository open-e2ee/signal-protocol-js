/**
 * Prekey management and server synchronization for SignalProtocolClient
 *
 * Extracted from SignalProtocolClient class to reduce file size.
 * Handles prekey bundle upload, verification, and regeneration.
 */

import type { PreKeyUpload } from '../remote/relay/types';
import { EncryptionError, EncryptionErrorCode, ONE_TIME_PREKEY_BATCH_SIZE } from '../types';
import { base64ToBytes } from '../internal/crypto';
import {
  generateKemOneTimePreKeys,
  generateEcOneTimePreKeys,
  generateEcSignedPreKey,
  generateKyberLastResortPreKey,
} from '../keys';
import type { IdentityType } from '../keys/types';
import {
  getActiveIdentityTypes,
  PREKEY_CHECK_THROTTLE_MS_DEFAULT,
  type ProgressCallback,
} from './config';
import { MAX_UNACKNOWLEDGED_SESSION_AGE_MS } from './config';
import { MIN_PREKEY_REPLENISHMENT_THRESHOLD } from './key-rotation-core';
import type { SignalProtocolClientContext } from './types';

/** Timestamp of last prekey check (for throttling). */
export {};
const lastPreKeySyncTimeByClient = new Map<string, number>();
const lastPreKeyStatusCheckTimeByIdentity = new Map<string, number>();

function getClientThrottleKey(ctx: SignalProtocolClientContext): string {
  return `${ctx.userId}:${ctx.deviceId}`;
}

function getStatusThrottleKey(
  ctx: SignalProtocolClientContext,
  identityType: IdentityType
): string {
  return `${ctx.userId}:${ctx.deviceId}:${identityType}`;
}

async function isServerInSyncForIdentity(
  ctx: SignalProtocolClientContext,
  identityType: IdentityType
): Promise<boolean> {
  if (!ctx.relay) return false;

  const [localSignedPreKey, localKyberPreKey] = await Promise.all([
    ctx.storage.getEcSignedPreKey(undefined, identityType),
    ctx.storage.getKyberPreKey(identityType),
  ]);

  // Local key material is incomplete, so throttled sync must not skip.
  if (!localSignedPreKey || !localKyberPreKey) {
    return false;
  }

  const [serverSignedMeta, serverKyberMeta, serverEcCount, serverKemCount] = await Promise.all([
    ctx.relay.getEcSignedPreKeyMetadata(ctx.userId, ctx.deviceId, identityType),
    ctx.relay.getKemLastResortPreKeyMetadata(ctx.userId, ctx.deviceId, identityType),
    ctx.relay.getPreKeyCount(ctx.userId, ctx.deviceId, 'ec', identityType),
    ctx.relay.getPreKeyCount(ctx.userId, ctx.deviceId, 'kem', identityType),
  ]);

  if (!serverSignedMeta || !serverKyberMeta) {
    return false;
  }

  const signedKeyMatches =
    serverSignedMeta.keyId === localSignedPreKey.keyId &&
    serverSignedMeta.publicKey === (localSignedPreKey.publicKey as string);
  const kyberKeyMatches =
    serverKyberMeta.keyId === localKyberPreKey.keyId &&
    serverKyberMeta.publicKey === (localKyberPreKey.publicKey as string);
  const hasEnoughPreKeys =
    serverEcCount >= MIN_PREKEY_REPLENISHMENT_THRESHOLD &&
    serverKemCount >= MIN_PREKEY_REPLENISHMENT_THRESHOLD;

  return signedKeyMatches && kyberKeyMatches && hasEnoughPreKeys;
}

async function isServerInSyncForAllActiveIdentities(
  ctx: SignalProtocolClientContext
): Promise<boolean> {
  if (!ctx.relay) return false;

  for (const identityType of getActiveIdentityTypes(ctx.config)) {
    const inSync = await isServerInSyncForIdentity(ctx, identityType);
    if (!inSync) {
      return false;
    }
  }

  return true;
}

/**
 * Reset the prekey-check throttle for controlled local resets.
 */
export function resetPreKeyCheckThrottle(): void {
  lastPreKeySyncTimeByClient.clear();
  lastPreKeyStatusCheckTimeByIdentity.clear();
}

/**
 * Sync the public prekey bundle to the configured relay.
 *
 * Steps:
 * 1. Generates prekey bundle if not already present (identity, signed, one-time prekeys)
 * 2. Generates KEM prekey material if not already present
 * 3. Uploads public keys to the relay server
 * 4. Provides progress updates
 *
 * @param ctx - Prekey context with dependencies
 * @param onProgress - Optional progress callback
 * @param options - Optional options (e.g., force to bypass throttle)
 */
export async function syncToServer(
  ctx: SignalProtocolClientContext,
  onProgress?: ProgressCallback,
  options?: { force?: boolean }
): Promise<void> {
  if (!ctx.relay) {
    throw new EncryptionError(
      'Relay server not configured',
      EncryptionErrorCode.INITIALIZATION_FAILED
    );
  }

  // Throttle prekey checks (skip if within throttle window), but never skip
  // when the server is missing bootstrap material for any active identity type.
  const clientKey = getClientThrottleKey(ctx);
  const lastSync = lastPreKeySyncTimeByClient.get(clientKey) ?? 0;
  if (!options?.force && lastSync > 0) {
    const throttleMs = ctx.config.preKeyCheckThrottleMs ?? PREKEY_CHECK_THROTTLE_MS_DEFAULT;
    if (Date.now() - lastSync < throttleMs) {
      const serverReady = await isServerInSyncForAllActiveIdentities(ctx);
      if (serverReady) {
        ctx.logger.debug('Prekey sync throttled', { category: 'E2EE' });
        return;
      }
    }
  }

  try {
    onProgress?.({
      stage: 'generating-keys',
      percent: 20,
      message: 'Creating your encryption keys...',
    });

    // Sync active identity types (ACI always, PNI only for phone-number apps)
    for (const identityType of getActiveIdentityTypes(ctx.config)) {
      await syncIdentityToServer(ctx, identityType, onProgress);
    }

    onProgress?.({
      stage: 'complete',
      percent: 100,
      message: 'Your device is secured',
    });

    ctx.logger.debug('Synced identity types to server with PQXDH support', {
      category: 'E2EE',
      data: {
        userId: ctx.userId,
        deviceId: ctx.deviceId,
      },
    });

    lastPreKeySyncTimeByClient.set(clientKey, Date.now());
  } catch (error) {
    throw new EncryptionError(
      'Failed to sync with server',
      EncryptionErrorCode.INITIALIZATION_FAILED,
      { originalError: error as Error }
    );
  }
}

/**
 * Sync the public prekey bundle for a specific identity type to the relay.
 *
 * Steps per identity type:
 * 1. Generates prekey bundle if not already present
 * 2. Generates KEM prekey material if not already present
 * 3. Uploads public keys to the relay
 *
 * ACI and PNI inventories synchronize independently.
 *
 * @param ctx - Prekey context with dependencies
 * @param identityType - 'aci' or 'pni'
 * @param onProgress - Optional progress callback
 */
export async function syncIdentityToServer(
  ctx: SignalProtocolClientContext,
  identityType: IdentityType,
  onProgress?: ProgressCallback
): Promise<void> {
  const preKeyMaintenance = ctx.config.preKeyMaintenance;

  // Generate prekey bundle if signed prekey does not exist
  // Note: initialize() generates identity key, but generatePreKeyBundle()
  // is needed to create signed prekey and one-time prekeys
  const existingSignedPreKey = await ctx.storage.getEcSignedPreKey(undefined, identityType);
  if (!existingSignedPreKey) {
    await ctx.manager.generatePreKeyBundle(ctx.userId, ctx.deviceId, identityType);
  }

  // Get keys from storage
  const identityKey = await ctx.storage.getIdentityKey(identityType);
  const signedPreKey = await ctx.storage.getEcSignedPreKey(undefined, identityType);
  const oneTimePreKeys = await ctx.storage.getEcOneTimePreKeys(identityType);

  if (!identityKey || !signedPreKey) {
    throw new Error(`Keys not generated - identity or signed prekey missing (${identityType})`);
  }

  // Check if Kyber prekey already exists
  let kyberPreKey = await ctx.storage.getKyberPreKey(identityType);

  if (!kyberPreKey) {
    onProgress?.({
      stage: 'generating-kyber',
      percent: 50,
      message: 'Generating post-quantum prekeys...',
      detail: { current: 0, total: 1 },
    });

    kyberPreKey = await generateKyberLastResortPreKey(identityKey, 1);

    // Store Kyber prekey locally
    await ctx.storage.storeKyberPreKey(kyberPreKey, identityType);

    onProgress?.({
      stage: 'generating-kyber',
      percent: 60,
      message: 'Post-quantum prekeys ready',
      detail: { current: 1, total: 1 },
    });
  }

  // Quick check: is the server already in sync for this identity type?
  // This turns a 5+ mutation sequence into 3 lightweight query checks on most app opens.
  const serverSignedMeta = await ctx.relay!.getEcSignedPreKeyMetadata(
    ctx.userId,
    ctx.deviceId,
    identityType
  );
  const serverKyberMeta = await ctx.relay!.getKemLastResortPreKeyMetadata(
    ctx.userId,
    ctx.deviceId,
    identityType
  );
  const serverEcCount = await ctx.relay!.getPreKeyCount(
    ctx.userId,
    ctx.deviceId,
    'ec',
    identityType
  );
  const serverKemCount = await ctx.relay!.getPreKeyCount(
    ctx.userId,
    ctx.deviceId,
    'kem',
    identityType
  );

  const signedKeyMatches =
    serverSignedMeta &&
    serverSignedMeta.keyId === signedPreKey.keyId &&
    serverSignedMeta.publicKey === (signedPreKey.publicKey as string);
  const kyberKeyMatches =
    !kyberPreKey ||
    (serverKyberMeta &&
      serverKyberMeta.keyId === kyberPreKey.keyId &&
      serverKyberMeta.publicKey === (kyberPreKey.publicKey as string));
  // Require independent EC and KEM inventory thresholds.
  const hasEnoughPreKeys =
    serverEcCount >= MIN_PREKEY_REPLENISHMENT_THRESHOLD &&
    serverKemCount >= MIN_PREKEY_REPLENISHMENT_THRESHOLD;

  if (signedKeyMatches && kyberKeyMatches && hasEnoughPreKeys) {
    ctx.logger.debug(`syncToServer: ${identityType} server already in sync, skipping uploads`, {
      category: 'E2EE',
      data: { identityType, serverEcCount, serverKemCount },
    });
    return;
  }

  onProgress?.({
    stage: 'uploading',
    percent: 75,
    message: 'Syncing keys to your account...',
  });

  // Provision this device against the account identity. A different tuple must
  // go through the relay's explicit compare-and-swap rotation operation.
  const { createCompositeIdentityV1 } = await import('../keys/identity');
  await ctx.relay!.provisionIdentityKey({
    userId: ctx.userId,
    deviceId: ctx.deviceId,
    identity: createCompositeIdentityV1(identityKey),
    registrationId: identityKey.registrationId,
    identityType,
  });

  // Replenish EC one-time prekeys if server is low (mirrors KEM replenishment below)
  const MAX_EC_PREKEYS = 200;
  const availableSlots = Math.max(0, MAX_EC_PREKEYS - serverEcCount);

  if (
    serverEcCount < MIN_PREKEY_REPLENISHMENT_THRESHOLD &&
    oneTimePreKeys.length < availableSlots
  ) {
    // Mark existing active one-time prekeys as replaced before generating new batch
    await preKeyMaintenance?.markEcOneTimePreKeysReplaced(identityType);

    // Determine next key ID from existing local prekeys
    const maxExistingId = oneTimePreKeys.reduce((max, k) => Math.max(max, k.keyId), -1);
    const startId = maxExistingId + 1;
    const toGenerate = Math.min(ONE_TIME_PREKEY_BATCH_SIZE, availableSlots - oneTimePreKeys.length);

    const freshPreKeys = await generateEcOneTimePreKeys(toGenerate, startId);
    await ctx.storage.storeEcOneTimePreKeys(freshPreKeys, identityType);
    oneTimePreKeys.push(...freshPreKeys);

    onProgress?.({
      stage: 'generating-keys',
      percent: 30,
      message: 'Encryption keys ready',
      detail: { current: freshPreKeys.length, total: toGenerate },
    });

    ctx.logger.debug('Generated fresh EC one-time prekeys', {
      category: 'E2EE',
      data: { identityType, count: freshPreKeys.length, startId },
    });
  }

  const oneTimePreKeysToUpload = oneTimePreKeys.slice(0, availableSlots);

  ctx.logger.debug('One-time prekey upload calculation', {
    category: 'E2EE',
    data: {
      identityType,
      serverPreKeyCount: serverEcCount,
      availableSlots,
      uploading: oneTimePreKeysToUpload.length,
    },
  });

  // Build prekey batch for upload
  const preKeyUploads: PreKeyUpload[] = [
    // Signed prekey (rotated on the configured refresh interval, 2 days by default)
    {
      type: 'ecSignedPreKey',
      keyId: signedPreKey.keyId,
      publicKey: signedPreKey.publicKey as string,
      signature: signedPreKey.signature as string,
    },
    // One-time prekeys (consumed on use) - only upload what server can accept
    ...oneTimePreKeysToUpload.map((k) => ({
      type: 'ecPreKey' as const,
      keyId: k.keyId,
      publicKey: k.publicKey as string,
    })),
  ];

  // Add Kyber last-resort prekey if available (for post-quantum security)
  if (kyberPreKey) {
    preKeyUploads.push({
      type: 'kemLastResortPreKey',
      keyId: kyberPreKey.keyId,
      publicKey: kyberPreKey.publicKey as string,
      signature: kyberPreKey.signature as string,
    });
  }

  // Check and upload KEM one-time prekeys (per-session post-quantum forward secrecy)
  // Re-fetch KEM count because a concurrent consumer may have changed it.
  const serverKemPreKeyCount = await ctx.relay!.getPreKeyCount(
    ctx.userId,
    ctx.deviceId,
    'kem',
    identityType
  );

  if (serverKemPreKeyCount < MIN_PREKEY_REPLENISHMENT_THRESHOLD) {
    // Mark existing active KEM one-time prekeys as replaced before generating new batch
    await preKeyMaintenance?.markKyberOneTimePreKeysReplaced(identityType);

    // Get existing local KEM one-time prekeys to determine next ID
    const existingKemPreKeys = await ctx.storage.getKemOneTimePreKeys(identityType);
    const maxExistingId = existingKemPreKeys.reduce((max, k) => Math.max(max, k.keyId), -1);
    const startId = maxExistingId + 1;

    // Generate new KEM one-time prekeys
    const kemOneTimePreKeys = await generateKemOneTimePreKeys(
      identityKey,
      ONE_TIME_PREKEY_BATCH_SIZE,
      startId
    );

    // Store locally
    await ctx.storage.storeKemOneTimePreKeys(kemOneTimePreKeys, identityType);

    onProgress?.({
      stage: 'generating-kyber',
      percent: 65,
      message: 'Post-quantum prekeys ready',
      detail: { current: kemOneTimePreKeys.length, total: ONE_TIME_PREKEY_BATCH_SIZE },
    });

    // Add to upload batch
    for (const k of kemOneTimePreKeys) {
      preKeyUploads.push({
        type: 'kemOneTimePreKey',
        keyId: k.keyId,
        publicKey: k.publicKey as string,
        signature: k.signature as string,
      });
    }

    ctx.logger.debug('Generated and uploading KEM one-time prekeys', {
      category: 'E2EE',
      data: { identityType, count: kemOneTimePreKeys.length, startId },
    });
  }

  // Upload all prekeys to server (with identity type)
  onProgress?.({
    stage: 'uploading',
    percent: 85,
    message: 'Syncing keys to your account...',
  });

  await ctx.relay!.uploadPreKeys(ctx.userId, ctx.deviceId, preKeyUploads, identityType);

  onProgress?.({
    stage: 'uploading',
    percent: 95,
    message: 'Keys synced',
  });

  // Cull replaced one-time prekeys only after the replacement upload succeeds.
  if (preKeyMaintenance) {
    try {
      await preKeyMaintenance.cullReplacedOneTimePreKeys(
        MAX_UNACKNOWLEDGED_SESSION_AGE_MS,
        identityType
      );
    } catch {
      // Best-effort cleanup. Non-critical
    }
  }

  ctx.logger.debug(`Synced ${identityType} to server with PQXDH support`, {
    category: 'E2EE',
    data: {
      userId: ctx.userId,
      deviceId: ctx.deviceId,
      identityType,
      hasKyberPreKey: true,
    },
  });
}

/**
 * Regenerate prekeys with fresh IDs
 *
 * Per PQXDH §4.13, identifier collisions (same keyId, different publicKey)
 * cause MAC verification failures. This method:
 * 1. Gets the current max keyId from storage
 * 2. Generates NEW prekeys with incremented IDs
 * 3. Uploads to server (replacing old bundle)
 *
 * Called automatically on stale-prekey detection and as a recovery mechanism
 * for persistent MAC verification failures.
 *
 * @param ctx - Prekey context with dependencies
 * @throws EncryptionError if relay not configured or operation fails
 */
export async function regeneratePreKeysWithFreshIds(
  ctx: SignalProtocolClientContext,
  identityType: IdentityType = 'aci'
): Promise<void> {
  if (!ctx.relay) {
    throw new EncryptionError(
      'Cannot regenerate prekeys: relay not configured',
      EncryptionErrorCode.INITIALIZATION_FAILED
    );
  }

  // Get identity key for signing new prekeys
  const identityKey = await ctx.storage.getIdentityKey(identityType);
  if (!identityKey) {
    throw new EncryptionError(
      'Cannot regenerate prekeys: identity key not found',
      EncryptionErrorCode.INITIALIZATION_FAILED
    );
  }

  // Get current max ID for signed prekey (uses sequential IDs)
  const currentSignedId = await ctx.storage.getEcSignedPreKeyMaxId(identityType);
  const newSignedId = currentSignedId + 1;

  // Per PQXDH spec Section 3.2: Kyber last-resort prekey always uses ID 1
  // Unlike signed prekeys, Kyber prekeys use upsert semantics (replace, not accumulate)
  const newKyberId = 1;

  ctx.logger.info('Regenerating prekeys with fresh IDs (identifier collision recovery)', {
    category: 'E2EE',
    data: {
      oldSignedId: currentSignedId,
      newSignedId,
      kyberIdFixed: newKyberId, // Always 1 per PQXDH spec
    },
  });

  // Generate new signed prekey with fresh sequential ID
  const newSignedPreKey = await generateEcSignedPreKey(
    identityKey,
    newSignedId
  );

  // Generate new Kyber prekey with fresh ID
  const newKyberPreKey = await generateKyberLastResortPreKey(
    identityKey,
    newKyberId
  );

  // Store new prekeys (replaces old ones)
  await ctx.storage.storeEcSignedPreKey(newSignedPreKey, identityType);
  await ctx.storage.storeKyberPreKey(newKyberPreKey, identityType);

  // Build prekey upload batch
  const preKeyUploads: PreKeyUpload[] = [
    {
      type: 'ecSignedPreKey',
      keyId: newSignedPreKey.keyId,
      publicKey: newSignedPreKey.publicKey as string,
      signature: newSignedPreKey.signature as string,
    },
    {
      type: 'kemLastResortPreKey',
      keyId: newKyberPreKey.keyId,
      publicKey: newKyberPreKey.publicKey as string,
      signature: newKyberPreKey.signature as string,
    },
  ];

  // Clear stale KEM one-time prekeys before uploading fresh bundle
  // Prevents PQXDH §4.13 identifier collisions (old one-time keys with stale IDs)
  const clearResult = await ctx.relay.clearStaleKemPreKeys(ctx.userId, ctx.deviceId, identityType);
  if (clearResult.cleared > 0) {
    ctx.logger.info('Cleared stale KEM one-time prekeys before rotation', {
      category: 'E2EE',
      data: { clearedCount: clearResult.cleared },
    });
  }

  // Upload to server
  await ctx.relay.uploadPreKeys(ctx.userId, ctx.deviceId, preKeyUploads, identityType);

  // Verify server has correct keys
  await verifyServerKeys(
    ctx,
    { keyId: newSignedPreKey.keyId, publicKey: newSignedPreKey.publicKey as string },
    { keyId: newKyberPreKey.keyId, publicKey: newKyberPreKey.publicKey as string },
    'regeneratePreKeysWithFreshIds',
    identityType
  );

  ctx.logger.info('Prekey rotation complete - fresh bundle uploaded', {
    category: 'E2EE',
    data: {
      signedPreKeyId: newSignedPreKey.keyId,
      kyberPreKeyId: newKyberPreKey.keyId,
      verified: true,
    },
  });
}

/**
 * Force complete key reset result type
 */
export interface ForceKeyResetResult {
  deletedSessions: number;
  deletedPreKeys: {
    ecSignedPreKeys: number;
    ecOneTimePreKeys: number;
    kyberPreKeys: number;
    kemOneTimePreKeys: number;
  };
}

/**
 * Force complete key reset (development/debugging only).
 *
 * WARNING: This is a "nuclear option" that will:
 * - Delete ALL sessions (breaking existing conversations)
 * - Delete ALL prekeys
 * - Generate fresh prekeys with keyId=1
 * - Upload new bundle to server
 *
 * Use only when:
 * - Keys are known to be desynchronized (development)
 * - Automated recovery has failed
 * - User explicitly requests key reset
 *
 * @param ctx - Prekey context with dependencies
 * @throws EncryptionError if relay not configured or operation fails
 */
export async function forceCompleteKeyReset(
  ctx: SignalProtocolClientContext,
  identityType: IdentityType = 'aci'
): Promise<ForceKeyResetResult> {
  if (!ctx.relay) {
    throw new EncryptionError(
      'Cannot force key reset: relay not configured',
      EncryptionErrorCode.INITIALIZATION_FAILED
    );
  }

  ctx.logger.warn('Force key reset triggered - all sessions will be invalidated', {
    category: 'E2EE',
  });

  // Get identity key for signing (we keep identity, just reset sessions and prekeys)
  const identityKey = await ctx.storage.getIdentityKey(identityType);
  if (!identityKey) {
    throw new EncryptionError(
      'Cannot force key reset: identity key not found',
      EncryptionErrorCode.INITIALIZATION_FAILED
    );
  }

  // Delete all sessions
  await ctx.storage.clearAllSessions();
  const sessionStats = await ctx.storage.getDetailedStats();
  const deletedSessions = sessionStats.sessions; // Should be 0 after clear

  // Delete all prekeys
  const deletedPreKeys = await ctx.storage.deleteAllPreKeys(identityType);

  // Generate fresh prekeys with keyId=1
  const newSignedPreKey = await generateEcSignedPreKey(
    identityKey,
    1 // Start fresh with ID 1
  );

  const newKyberPreKey = await generateKyberLastResortPreKey(
    identityKey,
    1 // Start fresh with ID 1
  );

  // Store new prekeys
  await ctx.storage.storeEcSignedPreKey(newSignedPreKey, identityType);
  await ctx.storage.storeKyberPreKey(newKyberPreKey, identityType);

  // Build prekey upload batch
  const preKeyUploads: PreKeyUpload[] = [
    {
      type: 'ecSignedPreKey',
      keyId: newSignedPreKey.keyId,
      publicKey: newSignedPreKey.publicKey as string,
      signature: newSignedPreKey.signature as string,
    },
    {
      type: 'kemLastResortPreKey',
      keyId: newKyberPreKey.keyId,
      publicKey: newKyberPreKey.publicKey as string,
      signature: newKyberPreKey.signature as string,
    },
  ];

  // Clear stale KEM one-time prekeys before uploading fresh bundle
  const clearResult = await ctx.relay.clearStaleKemPreKeys(ctx.userId, ctx.deviceId, identityType);
  if (clearResult.cleared > 0) {
    ctx.logger.info('Cleared stale KEM one-time prekeys during key reset', {
      category: 'E2EE',
      data: { clearedCount: clearResult.cleared },
    });
  }

  // Upload to server
  await ctx.relay.uploadPreKeys(ctx.userId, ctx.deviceId, preKeyUploads, identityType);

  // Verify server has correct keys
  await verifyServerKeys(
    ctx,
    { keyId: newSignedPreKey.keyId, publicKey: newSignedPreKey.publicKey as string },
    { keyId: newKyberPreKey.keyId, publicKey: newKyberPreKey.publicKey as string },
    'forceCompleteKeyReset',
    identityType
  );

  ctx.logger.warn('Force key reset complete - fresh bundle uploaded', {
    category: 'E2EE',
    data: {
      deletedSessions,
      deletedPreKeys,
      newSignedPreKeyId: newSignedPreKey.keyId,
      newKyberPreKeyId: newKyberPreKey.keyId,
    },
  });

  return {
    deletedSessions,
    deletedPreKeys,
  };
}

/**
 * Verify server has correct keys after upload
 *
 * Called after uploadPreKeys() to confirm the server received our keys correctly.
 * This catches silent upload failures or server-side issues that could cause
 * MAC failures when remote clients fetch stale bundles.
 *
 * @param ctx - Prekey context with dependencies
 * @param signedPreKey - The signed prekey the client uploaded
 * @param kyberPreKey - Optional Kyber prekey the client uploaded
 * @param operation - Operation name for logging context
 * @throws EncryptionError if verification fails
 */
export async function verifyServerKeys(
  ctx: SignalProtocolClientContext,
  signedPreKey: { keyId: number; publicKey: string },
  kyberPreKey: { keyId: number; publicKey: string } | null,
  operation: string,
  identityType: IdentityType = 'aci'
): Promise<void> {
  if (!ctx.relay) {
    throw new EncryptionError(
      'Cannot verify server keys: relay not configured',
      EncryptionErrorCode.INITIALIZATION_FAILED
    );
  }

  // Verify signed prekey
  const serverSignedMetadata = await ctx.relay.getEcSignedPreKeyMetadata(
    ctx.userId,
    ctx.deviceId,
    identityType
  );

  if (!serverSignedMetadata) {
    throw new EncryptionError(
      'Server has no signed prekey after upload',
      EncryptionErrorCode.INITIALIZATION_FAILED
    );
  }

  if (serverSignedMetadata.publicKey !== signedPreKey.publicKey) {
    ctx.logger.error('Server signed prekey mismatch after upload', {
      category: 'E2EE',
      data: {
        local: signedPreKey.publicKey.substring(0, 20) + '...',
        server: serverSignedMetadata.publicKey.substring(0, 20) + '...',
        operation,
      },
    });
    throw new EncryptionError(
      'Failed to verify signed prekey on server - key mismatch detected',
      EncryptionErrorCode.INITIALIZATION_FAILED
    );
  }

  // Verify Kyber prekey if provided
  if (kyberPreKey) {
    const serverKyberMetadata = await ctx.relay.getKemLastResortPreKeyMetadata(
      ctx.userId,
      ctx.deviceId,
      identityType
    );

    if (!serverKyberMetadata) {
      throw new EncryptionError(
        'Server has no Kyber prekey after upload',
        EncryptionErrorCode.INITIALIZATION_FAILED
      );
    }

    if (serverKyberMetadata.publicKey !== kyberPreKey.publicKey) {
      ctx.logger.error('Server Kyber prekey mismatch after upload', {
        category: 'E2EE',
        data: {
          local: kyberPreKey.publicKey.substring(0, 20) + '...',
          server: serverKyberMetadata.publicKey.substring(0, 20) + '...',
          operation,
        },
      });
      throw new EncryptionError(
        'Failed to verify Kyber prekey on server - key mismatch detected',
        EncryptionErrorCode.INITIALIZATION_FAILED
      );
    }
  }

  ctx.logger.debug('Server key verification passed', {
    category: 'E2EE',
    data: { operation, hasKyberKey: !!kyberPreKey },
  });
}

/**
 * Check prekey status result
 */
export interface PreKeyStatusResult {
  oneTimePreKeysRemaining: number;
  needsReplenishment: boolean;
}

/**
 * Check prekey status and decide whether the client must replenish
 *
 * @param ctx - Client context with dependencies
 * @param threshold - Threshold below which the client replenishes (default: 50)
 * @param onPreKeyLow - Optional callback when prekeys are low
 * @param identityType - Identity type to check (default: 'aci')
 * @param options - Optional options (e.g., force to bypass throttle)
 * @returns Prekey status with remaining count and replenishment flag
 */
export async function checkPreKeyStatus(
  ctx: SignalProtocolClientContext,
  threshold: number = 50,
  onPreKeyLow?: (remaining: number) => void,
  identityType: IdentityType = 'aci',
  options?: { force?: boolean }
): Promise<PreKeyStatusResult> {
  const statusKey = getStatusThrottleKey(ctx, identityType);
  const lastStatusCheck = lastPreKeyStatusCheckTimeByIdentity.get(statusKey) ?? 0;

  // Throttle check (unless forced or first check)
  if (!options?.force && lastStatusCheck > 0) {
    const throttleMs = ctx.config.preKeyCheckThrottleMs ?? PREKEY_CHECK_THROTTLE_MS_DEFAULT;
    if (Date.now() - lastStatusCheck < throttleMs) {
      ctx.logger.debug('Prekey status check throttled', { category: 'E2EE' });
      return { oneTimePreKeysRemaining: -1, needsReplenishment: false };
    }
  }

  const prekeys = await ctx.storage.getEcOneTimePreKeys(identityType);
  const remaining = prekeys.length;
  const needsReplenishment = remaining < threshold;

  // Call the onPreKeyLow callback if configured and below threshold
  if (needsReplenishment && onPreKeyLow) {
    try {
      onPreKeyLow(remaining);
    } catch (error) {
      ctx.logger.warn('onPreKeyLow callback failed', {
        category: 'E2EE',
        data: { error: (error as Error).message },
      });
    }
  }

  // Log warning when prekeys are running low
  if (needsReplenishment) {
    ctx.logger.warn('One-time prekeys running low', {
      category: 'E2EE',
      data: { remaining, threshold },
    });
  }

  lastPreKeyStatusCheckTimeByIdentity.set(statusKey, Date.now());

  return {
    oneTimePreKeysRemaining: remaining,
    needsReplenishment,
  };
}
