/**
 * Key Rotation Core
 *
 * Shared rotation logic that works with ISignalRelayServer interface.
 * Used by both:
 * - SignalProtocolClient (foreground, via key-rotation.ts)
 * - Background tasks (headless, via headless.ts)
 *
 * This module handles the actual key generation and upload logic,
 * independent of React context or specific backend implementation.
 *
 * ## Thread Safety
 *
 * Uses per-key-type AsyncLock to prevent race conditions when multiple
 * callers attempt key rotation concurrently. This protects against:
 * - Multiple React components calling rotation simultaneously
 * - Background tasks racing with foreground rotation
 * - Network requests completing out of order
 *
 * The lock wraps the entire check → generate → upload → store sequence
 * to ensure atomic key rotation operations.
 *
 * ## Transactional Pattern
 *
 * Key rotation uses upload-first ordering for consistency:
 * 1. Check if rotation needed (metadata from server)
 * 2. Generate new key locally
 * 3. Upload to server (may fail - local state unchanged)
 * 4. Store locally only after successful upload
 *
 * This ensures client and server stay in sync. If upload fails,
 * local state is unchanged and rotation can be safely retried.
 */

import AsyncLock from 'async-lock';
import { defaultSignalLogger, type ILogger } from '../logger';
import type { ISignalLocalStore } from '../types';
import type { IdentityKeyPair } from '../keys';
import type { IdentityType } from '../keys/types';
import type { PublicKey, PrivateKey, Signature } from '../keys/branded';
import { ONE_TIME_PREKEY_BATCH_SIZE } from '../types';
import type { ISignalRelayServer } from '../remote/relay/types';
import {
  KEY_REFRESH_INTERVAL_MS_DEFAULT,
  MAX_PREKEY_AGE_MS_DEFAULT,
  type PreKeyMaintenanceStore,
} from './config';

/**
 * Lock for key rotation operations.
 *
 * Prevents concurrent callers from both generating and uploading different keys,
 * which would result in one upload overwriting the other.
 *
 * Uses per-key-type locks so signed and Kyber rotations don't block each other.
 */
export {};
const rotationLock = new AsyncLock({
  timeout: 60000, // 60 second timeout for entire rotation operation
  maxPending: 10, // Limit queued rotation requests
});

// ============================================================================
// SHARED HELPERS
// ============================================================================

/**
 * Resolve storage instance or fail fast when the caller forgot to provide one.
 */
async function resolveStorage(
  providedStorage?: ISignalLocalStore,
  logger: Required<ILogger> = defaultSignalLogger
): Promise<ISignalLocalStore> {
  if (providedStorage) {
    return providedStorage;
  }
  logger.error('Missing local store for key rotation', {
    category: 'E2EE',
  });
  throw new Error(
    'Key rotation requires an ISignalLocalStore. ' +
      'Create the runtime-specific local store in app code and pass it explicitly.'
  );
}

/**
 * Get identity key from storage, throwing if not found
 */
async function getRequiredIdentityKey(
  storage: ISignalLocalStore,
  identityType: IdentityType = 'aci'
): Promise<IdentityKeyPair> {
  const identityKey = await storage.getIdentityKey(identityType);
  if (!identityKey) {
    throw new Error(`Identity key not found (${identityType})`);
  }
  return identityKey;
}

/**
 * Key type for rotation operations.
 * Includes identity-type-scoped variants (e.g., 'signed:aci', 'kyber:pni').
 */
type KeyType = string;

/**
 * Execute a rotation operation with locking and error handling
 */
async function withRotationLock<T>(
  userId: string,
  deviceId: number,
  keyType: KeyType,
  operation: () => Promise<T>,
  errorMessage: string,
  logger: Required<ILogger>
): Promise<T | false> {
  const lockKey = `${userId}:${deviceId}:${keyType}`;

  return rotationLock.acquire(lockKey, async () => {
    try {
      return await operation();
    } catch (error) {
      logger.error(errorMessage, {
        category: 'E2EE',
        error: error as Error,
        data: { userId, deviceId },
      });
      return false;
    }
  });
}

/**
 * Check if rotation is needed based on metadata
 */
interface KeyMetadata {
  createdAt: number;
  expiresAt: number;
}

function checkRotationNeeded(
  metadata: KeyMetadata | null,
  refreshIntervalMs: number,
  keyTypeName: string,
  logger: Required<ILogger>
): boolean {
  if (!metadata) {
    return true; // No metadata = needs rotation
  }

  if (shouldRotateKey(metadata.createdAt, metadata.expiresAt, refreshIntervalMs)) {
    return true;
  }

  const ageDays = Math.floor((Date.now() - metadata.createdAt) / (24 * 60 * 60 * 1000));
  logger.breadcrumb(`${keyTypeName} is current, no rotation needed`, {
    category: 'E2EE',
    level: 'debug',
    data: { ageDays },
  });
  return false;
}

// ============================================================================
// EXPORTS
// ============================================================================

/**
 * Minimum one-time prekeys before replenishment is triggered.
 * When count drops below this threshold, new prekeys are generated and uploaded.
 */
export const MIN_PREKEY_REPLENISHMENT_THRESHOLD = 10;

/**
 * Check if a key needs rotation based on age
 *
 * Used for BOTH signed and Kyber prekeys. Per PQXDH spec Section 3.2,
 * both key types use identical rotation thresholds to ensure synchronized
 * post-quantum security maintenance.
 *
 * @param createdAt - Key creation timestamp (milliseconds)
 * @param expiresAt - Key expiration timestamp (milliseconds)
 * @param refreshIntervalMs - Custom refresh interval (defaults to 2 days)
 * @returns true if key should be rotated
 *
 * @see https://signal.org/docs/specifications/pqxdh/#publishing-keys
 */
export function shouldRotateKey(
  createdAt: number,
  expiresAt: number,
  refreshIntervalMs: number = KEY_REFRESH_INTERVAL_MS_DEFAULT
): boolean {
  const now = Date.now();
  const age = now - createdAt;

  // Rotate if age >= refresh interval OR expiration time reached
  return age >= refreshIntervalMs || now >= expiresAt;
}

/**
 * Check if prekeys have exceeded maximum allowed age.
 *
 * If prekeys are older than MAX_PREKEY_AGE_MS (14 days), message sending
 * should be blocked until rotation succeeds.
 *
 * This provides a 12-day safety buffer above the 2-day refresh interval.
 *
 * @param createdAt - Key creation timestamp (milliseconds)
 * @param maxAgeMs - Maximum allowed age (default: 14 days)
 * @returns true if prekey is too old and should block sending
 *
 * @see https://signal.org/docs/specifications/pqxdh/#publishing-keys
 */
export function isPreKeyExpired(
  createdAt: number,
  maxAgeMs: number = MAX_PREKEY_AGE_MS_DEFAULT
): boolean {
  const age = Date.now() - createdAt;
  return age >= maxAgeMs;
}

/**
 * Core signed prekey rotation
 *
 * Generates a new signed prekey and uploads to server.
 * Works without React context.
 *
 * @param relay - Signal Protocol relay server interface
 * @param userId - User identifier
 * @param deviceId - Device identifier
 * @param providedStorage - Local store instance for the current runtime
 * @param refreshIntervalMs - Custom refresh interval (defaults to 2 days)
 * @returns true if rotation was performed
 */
export async function rotateEcSignedPreKeyCore(
  relay: ISignalRelayServer,
  userId: string,
  deviceId: number,
  providedStorage?: ISignalLocalStore,
  refreshIntervalMs: number = KEY_REFRESH_INTERVAL_MS_DEFAULT,
  identityTypes: readonly IdentityType[] = ['aci', 'pni'],
  logger: Required<ILogger> = defaultSignalLogger
): Promise<boolean> {
  // Rotate for active identity types (the reference implementation rotates PNI on the same schedule as ACI)
  // Use && so the function only returns true when ALL identities succeed.
  // The reference implementation uses exception propagation — if any identity fails, the entire job
  // fails and is retried on the next rotation cycle.
  let allRotated = true;
  for (const type of identityTypes) {
    const rotated = await rotateEcSignedPreKeyForIdentity(
      relay,
      userId,
      deviceId,
      type,
      providedStorage,
      refreshIntervalMs,
      logger
    );
    allRotated = allRotated && rotated;
  }
  return allRotated;
}

/**
 * Rotate signed prekey for a specific identity type.
 *
 * @param relay - Signal Protocol relay server interface
 * @param userId - User identifier
 * @param deviceId - Device identifier
 * @param identityType - 'aci' or 'pni'
 * @param providedStorage - Optional storage instance
 * @param refreshIntervalMs - Custom refresh interval
 * @returns true if rotation was performed
 */
async function rotateEcSignedPreKeyForIdentity(
  relay: ISignalRelayServer,
  userId: string,
  deviceId: number,
  identityType: IdentityType,
  providedStorage?: ISignalLocalStore,
  refreshIntervalMs: number = KEY_REFRESH_INTERVAL_MS_DEFAULT,
  logger: Required<ILogger> = defaultSignalLogger
): Promise<boolean> {
  return withRotationLock(
    userId,
    deviceId,
    `signed:${identityType}` as KeyType,
    async () => {
      // Check if rotation is needed for this identity type
      const metadata = await relay.getEcSignedPreKeyMetadata(userId, deviceId, identityType);
      if (
        !checkRotationNeeded(
          metadata,
          refreshIntervalMs,
          `EC signed prekey (${identityType})`,
          logger
        )
      ) {
        return false;
      }

      logger.info(`Rotating EC signed prekey (${identityType})`, {
        category: 'E2EE',
        data: { userId, deviceId, identityType },
      });

      const { generateEcSignedPreKey } = await import('../keys');
      const storage = await resolveStorage(providedStorage, logger);
      const identityKey = await getRequiredIdentityKey(storage, identityType);

      // Generate new EC signed prekey (but don't store yet)
      const newSignedPreKey = await generateEcSignedPreKey(identityKey);

      // TRANSACTIONAL PATTERN: Upload first, then commit locally
      // If upload fails, local state is unchanged - safe to retry.
      await relay.uploadEcSignedPreKey(
        userId,
        {
          keyId: newSignedPreKey.keyId,
          deviceId,
          publicKey: newSignedPreKey.publicKey as string,
          signature: newSignedPreKey.signature as string,
          timestamp: newSignedPreKey.timestamp,
        },
        identityType
      );

      await storage.storeEcSignedPreKey(newSignedPreKey, identityType);

      logger.info(`EC signed prekey rotated successfully (${identityType})`, {
        category: 'E2EE',
        data: { userId, deviceId, identityType },
      });

      return true;
    },
    `Failed to rotate EC signed prekey (${identityType})`,
    logger
  ) as Promise<boolean>;
}

/**
 * Core post-quantum KEM prekey rotation.
 *
 * Generates fresh ML-KEM/Kyber-compatible key material and uploads it to the
 * relay.
 * Works without React context.
 *
 * @param relay - Signal Protocol relay server interface
 * @param userId - User identifier
 * @param deviceId - Device identifier
 * @param providedStorage - Local store instance for the current runtime
 * @param refreshIntervalMs - Custom refresh interval (defaults to 2 days)
 * @returns true if rotation was performed
 */
export async function rotateKyberPreKeyCore(
  relay: ISignalRelayServer,
  userId: string,
  deviceId: number,
  providedStorage?: ISignalLocalStore,
  refreshIntervalMs: number = KEY_REFRESH_INTERVAL_MS_DEFAULT,
  identityTypes: readonly IdentityType[] = ['aci', 'pni'],
  logger: Required<ILogger> = defaultSignalLogger
): Promise<boolean> {
  // Rotate for active identity types (the reference implementation rotates PNI on the same schedule as ACI)
  // Use && so the function only returns true when ALL identities succeed.
  // The reference implementation uses exception propagation — if any identity fails, the entire job
  // fails and is retried on the next rotation cycle.
  let allRotated = true;
  for (const type of identityTypes) {
    const rotated = await rotateKyberPreKeyForIdentity(
      relay,
      userId,
      deviceId,
      type,
      providedStorage,
      refreshIntervalMs,
      logger
    );
    allRotated = allRotated && rotated;
  }
  return allRotated;
}

/**
 * Rotate Kyber prekey for a specific identity type.
 *
 * @param relay - Signal Protocol relay server interface
 * @param userId - User identifier
 * @param deviceId - Device identifier
 * @param identityType - 'aci' or 'pni'
 * @param providedStorage - Optional storage instance
 * @param refreshIntervalMs - Custom refresh interval
 * @returns true if rotation was performed
 */
async function rotateKyberPreKeyForIdentity(
  relay: ISignalRelayServer,
  userId: string,
  deviceId: number,
  identityType: IdentityType,
  providedStorage?: ISignalLocalStore,
  refreshIntervalMs: number = KEY_REFRESH_INTERVAL_MS_DEFAULT,
  logger: Required<ILogger> = defaultSignalLogger
): Promise<boolean> {
  return withRotationLock(
    userId,
    deviceId,
    `kyber:${identityType}` as KeyType,
    async () => {
      // Check if rotation is needed for this identity type
      const metadata = await relay.getKemLastResortPreKeyMetadata(userId, deviceId, identityType);
      if (
        !checkRotationNeeded(metadata, refreshIntervalMs, `Kyber prekey (${identityType})`, logger)
      ) {
        return false;
      }

      logger.info(`Rotating Kyber prekey for post-quantum security (${identityType})`, {
        category: 'E2EE',
        data: { userId, deviceId, identityType },
      });

      const storage = await resolveStorage(providedStorage, logger);
      const identityKey = await getRequiredIdentityKey(storage, identityType);

      const { generateKyberLastResortPreKey } = await import('../keys/generation');
      const kyberPreKey = await generateKyberLastResortPreKey(identityKey, 1);

      // TRANSACTIONAL PATTERN: Upload first, then commit locally
      // If upload fails, local state is unchanged - safe to retry.
      const publicKyberPreKey = {
        keyId: kyberPreKey.keyId,
        publicKey: kyberPreKey.publicKey,
        signature: kyberPreKey.signature,
        timestamp: kyberPreKey.timestamp,
      };
      await relay.uploadKemLastResortPreKey(
        userId,
        { ...publicKyberPreKey, deviceId },
        identityType
      );

      await storage.storeKyberPreKey(
        {
          ...kyberPreKey,
          publicKey: kyberPreKey.publicKey as PublicKey,
          privateKey: kyberPreKey.privateKey as PrivateKey,
          signature: kyberPreKey.signature as Signature,
        },
        identityType
      );

      logger.info(
        `Kyber prekey rotated successfully (${identityType}, PQXDH security maintained)`,
        {
          category: 'E2EE',
          data: { userId, deviceId, identityType },
        }
      );

      return true;
    },
    `Failed to rotate Kyber prekey (${identityType})`,
    logger
  ) as Promise<boolean>;
}

/**
 * Check and replenish one-time prekeys if running low
 *
 * Iterates both ACI and PNI identity types for consistency with
 * rotateEcSignedPreKeyCore and rotateKyberPreKeyCore.
 *
 * @param relay - Signal Protocol relay server interface
 * @param userId - User identifier
 * @param deviceId - Device identifier
 * @param storage - Key storage for local persistence
 * @param threshold - Minimum number of prekeys before replenishment (default: 10)
 * @returns true if replenishment was performed for both identity types
 */
export async function replenishOneTimePreKeysCore(
  relay: ISignalRelayServer,
  userId: string,
  deviceId: number,
  storage: ISignalLocalStore,
  threshold: number = MIN_PREKEY_REPLENISHMENT_THRESHOLD,
  identityTypes: readonly IdentityType[] = ['aci', 'pni'],
  preKeyMaintenance?: PreKeyMaintenanceStore,
  logger: Required<ILogger> = defaultSignalLogger
): Promise<boolean> {
  // Replenish for active identity types (consistent with rotateEcSignedPreKeyCore/rotateKyberPreKeyCore)
  let allReplenished = true;
  for (const type of identityTypes) {
    const replenished = await replenishOneTimePreKeysForIdentity(
      relay,
      userId,
      deviceId,
      storage,
      threshold,
      type,
      preKeyMaintenance,
      logger
    );
    allReplenished = allReplenished && replenished;
  }
  return allReplenished;
}

/**
 * Replenish one-time prekeys for a specific identity type.
 *
 * @param relay - Signal Protocol relay server interface
 * @param userId - User identifier
 * @param deviceId - Device identifier
 * @param storage - Key storage for local persistence
 * @param threshold - Minimum number of prekeys before replenishment
 * @param identityType - 'aci' or 'pni'
 * @returns true if replenishment was performed
 */
async function replenishOneTimePreKeysForIdentity(
  relay: ISignalRelayServer,
  userId: string,
  deviceId: number,
  storage: ISignalLocalStore,
  threshold: number,
  identityType: IdentityType,
  preKeyMaintenance?: PreKeyMaintenanceStore,
  logger: Required<ILogger> = defaultSignalLogger
): Promise<boolean> {
  return withRotationLock(
    userId,
    deviceId,
    `prekeys:${identityType}`,
    async () => {
      const count = await relay.getPreKeyCount(userId, deviceId, 'ec', identityType);

      if (count >= threshold) {
        logger.breadcrumb('One-time prekeys sufficient, no replenishment needed', {
          category: 'E2EE',
          level: 'debug',
          data: { count, threshold, identityType },
        });
        return false;
      }

      logger.info('Replenishing one-time prekeys', {
        category: 'E2EE',
        data: { currentCount: count, threshold, identityType },
      });

      // Mark active one-time prekeys as replaced before generating a new batch.
      await preKeyMaintenance?.markEcOneTimePreKeysReplaced(identityType);
      await preKeyMaintenance?.markKyberOneTimePreKeysReplaced(identityType);

      const keys = await import('../keys');
      const newPreKeys = await keys.generateEcOneTimePreKeys(ONE_TIME_PREKEY_BATCH_SIZE);

      // Store locally first (private keys needed for decryption)
      await storage.storeEcOneTimePreKeys(newPreKeys, identityType);

      // Upload public keys to server (with identity type)
      await relay.uploadPreKeys(
        userId,
        deviceId,
        newPreKeys.map((pk) => ({
          type: 'ecPreKey' as const,
          keyId: pk.keyId,
          publicKey: pk.publicKey as string,
        })),
        identityType
      );

      logger.info('One-time prekeys replenished', {
        category: 'E2EE',
        data: { addedCount: newPreKeys.length, previousCount: count, identityType },
      });

      return true;
    },
    `Failed to replenish one-time prekeys (${identityType})`,
    logger
  ) as Promise<boolean>;
}

// ============================================================================
// PRE-SEND VALIDATION
// ============================================================================

/**
 * Result of pre-send prekey validation
 */
export interface PreKeySendCheckResult {
  /** Whether sending should proceed */
  canSend: boolean;
  /** Whether rotation was attempted */
  rotationAttempted: boolean;
  /** Whether rotation succeeded (if attempted) */
  rotationSucceeded: boolean;
  /** Error message if rotation failed */
  errorMessage?: string;
}

/**
 * Check prekey age and rotate if needed before sending a message.
 *
 * If prekeys exceed MAX_PREKEY_AGE_MS (14 days), rotation is attempted.
 * If rotation fails, sending should be blocked to maintain security.
 *
 * @param relay - Signal Protocol relay server interface
 * @param userId - User identifier
 * @param deviceId - Device identifier
 * @param storage - Optional storage instance
 * @param maxAgeMs - Maximum allowed prekey age (default: 14 days)
 * @returns Result indicating whether sending can proceed
 *
 * @example
 * ```typescript
 * const result = await ensurePreKeysValid(relay, userId, deviceId);
 * if (!result.canSend) {
 *   throw new EncryptionError(
 *     result.errorMessage || 'Prekey rotation failed',
 *     EncryptionErrorCode.PREKEY_ROTATION_REQUIRED
 *   );
 * }
 * // Proceed with encryption
 * ```
 *
 * @see https://signal.org/docs/specifications/pqxdh/#publishing-keys
 */
export async function ensurePreKeysValid(
  relay: ISignalRelayServer,
  userId: string,
  deviceId: number,
  storage?: ISignalLocalStore,
  maxAgeMs: number = MAX_PREKEY_AGE_MS_DEFAULT,
  identityType: IdentityType = 'aci',
  logger: Required<ILogger> = defaultSignalLogger
): Promise<PreKeySendCheckResult> {
  // Check EC signed prekey metadata for the specified identity type
  const signedMetadata = await relay.getEcSignedPreKeyMetadata(userId, deviceId, identityType);
  const signedExpired = signedMetadata ? isPreKeyExpired(signedMetadata.createdAt, maxAgeMs) : true;

  // Check Kyber prekey metadata for the specified identity type
  const kyberMetadata = await relay.getKemLastResortPreKeyMetadata(userId, deviceId, identityType);
  const kyberExpired = kyberMetadata ? isPreKeyExpired(kyberMetadata.createdAt, maxAgeMs) : true;

  // If neither is expired, sending can proceed
  if (!signedExpired && !kyberExpired) {
    return {
      canSend: true,
      rotationAttempted: false,
      rotationSucceeded: false,
    };
  }

  // Prekeys are expired - attempt rotation (rotate before blocking)
  logger.warn('Prekeys expired, attempting rotation before send', {
    category: 'E2EE',
    data: {
      identityType,
      signedExpired,
      kyberExpired,
      signedAge: signedMetadata
        ? Math.floor((Date.now() - signedMetadata.createdAt) / (24 * 60 * 60 * 1000))
        : null,
      kyberAge: kyberMetadata
        ? Math.floor((Date.now() - kyberMetadata.createdAt) / (24 * 60 * 60 * 1000))
        : null,
    },
  });

  let signedRotated = !signedExpired;
  let kyberRotated = !kyberExpired;

  // Rotate signed prekey if expired
  if (signedExpired) {
    signedRotated = await rotateEcSignedPreKeyCore(
      relay,
      userId,
      deviceId,
      storage,
      undefined,
      [identityType],
      logger
    );
    if (!signedRotated) {
      logger.error('Failed to rotate EC signed prekey before send', {
        category: 'E2EE',
        error: new Error('EC signed prekey rotation failed'),
        data: { userId, deviceId, identityType },
      });
    }
  }

  // Rotate Kyber prekey if expired
  if (kyberExpired) {
    kyberRotated = await rotateKyberPreKeyCore(
      relay,
      userId,
      deviceId,
      storage,
      undefined,
      [identityType],
      logger
    );
    if (!kyberRotated) {
      logger.error('Failed to rotate Kyber prekey before send', {
        category: 'E2EE',
        error: new Error('Kyber prekey rotation failed'),
        data: { userId, deviceId, identityType },
      });
    }
  }

  const allRotated = signedRotated && kyberRotated;

  if (!allRotated) {
    return {
      canSend: false,
      rotationAttempted: true,
      rotationSucceeded: false,
      errorMessage: `Prekey rotation failed (signed: ${signedRotated}, kyber: ${kyberRotated}). Message sending blocked.`,
    };
  }

  logger.info('Prekeys rotated successfully, proceeding with send', {
    category: 'E2EE',
    data: { userId, deviceId, identityType, signedRotated, kyberRotated },
  });

  return {
    canSend: true,
    rotationAttempted: true,
    rotationSucceeded: true,
  };
}
