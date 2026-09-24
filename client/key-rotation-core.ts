/**
 * Key Rotation Core
 *
 * Shared rotation logic that works with the SignalProtocolRelayServer
 * interface. Used by both:
 * - SignalProtocolClient (foreground, via key-rotation.ts)
 * - Background tasks (headless, via headless.ts)
 *
 * One rotation reads the inventory once, decides which of the EC signed
 * prekey, the KEM last-resort prekey, and the one-time prekey batches are due,
 * and publishes every due key in one publication. A rotation with nothing due
 * costs one inventory read and no publication.
 *
 * ## Thread Safety
 *
 * A per-identity AsyncLock serializes concurrent rotations for one device, so
 * two callers cannot both generate and publish different keys. The lock wraps
 * the whole read → decide → generate → publish → store sequence.
 *
 * ## Transactional Pattern
 *
 * Signed keys use publish-first ordering:
 * 1. Read the inventory (through the relay adapter's publication fence)
 * 2. Generate the due keys locally
 * 3. Publish (may fail - the signed keys are not stored)
 * 4. Store the signed keys locally only after the publication succeeds
 *
 * One-time prekeys are stored before the publication, because their private
 * halves must exist before a peer can consume the public halves.
 */

import AsyncLock from 'async-lock';
import { defaultSignalProtocolLogger, type Logger } from '../logger';
import type { PreKeyRotationResult, SignalProtocolLocalStore } from '../types';
import type { EcSignedPreKey, IdentityKeyPair, KyberPreKey } from '../keys';
import { generateEcSignedPreKey, generateKyberLastResortPreKey } from '../keys';
import type { IdentityType } from '../keys/types';
import type { PublicKey, PrivateKey, Signature } from '../keys/branded';
import type { PreKeyInventory, PreKeyUpload, SignalProtocolRelayServer } from '../remote/relay/types';
import { getErrorMessage } from '../utils/errors';
import {
  getActiveIdentityTypes,
  KEY_REFRESH_INTERVAL_MS_DEFAULT,
  MAX_PREKEY_AGE_MS_DEFAULT,
  type PreKeyMaintenanceStore,
} from './config';
import {
  MIN_PREKEY_REPLENISHMENT_THRESHOLD,
  refillOneTimePreKeys,
  type OneTimePreKeyRefill,
} from './one-time-prekey-refill';

/**
 * Lock for key rotation operations.
 *
 * One lock per user, device, and identity type. A rotation holds it for the
 * whole read, decide, publish, and store sequence.
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
  providedStorage?: SignalProtocolLocalStore,
  logger: Required<Logger> = defaultSignalProtocolLogger
): Promise<SignalProtocolLocalStore> {
  if (providedStorage) {
    return providedStorage;
  }
  logger.error('Missing local store for key rotation', {
    category: 'E2EE',
  });
  throw new Error(
    'Key rotation requires an SignalProtocolLocalStore. ' +
      'Create the runtime-specific local store in app code and pass it explicitly.'
  );
}

/**
 * Get identity key from storage, throwing if not found
 */
async function getRequiredIdentityKey(
  storage: SignalProtocolLocalStore,
  identityType: IdentityType = 'aci'
): Promise<IdentityKeyPair> {
  const identityKey = await storage.getIdentityKey(identityType);
  if (!identityKey) {
    throw new Error(`Identity key not found (${identityType})`);
  }
  return identityKey;
}

type LockedOutcome<T> = { ok: true; value: T } | { ok: false; error: string };

/**
 * Run one rotation step under the per-identity lock. A thrown error is logged
 * and returned as a message, so one failed identity type does not stop the
 * others.
 */
async function withRotationLock<T>(
  userId: string,
  deviceId: number,
  identityType: IdentityType,
  operation: () => Promise<T>,
  errorMessage: string,
  logger: Required<Logger>
): Promise<LockedOutcome<T>> {
  const lockKey = `${userId}:${deviceId}:rotation:${identityType}`;

  return rotationLock.acquire(lockKey, async (): Promise<LockedOutcome<T>> => {
    try {
      return { ok: true, value: await operation() };
    } catch (error) {
      logger.error(errorMessage, {
        category: 'E2EE',
        error: error as Error,
        data: { userId, deviceId, identityType },
      });
      return { ok: false, error: getErrorMessage(error) };
    }
  });
}

/**
 * Check whether the metadata calls for rotation
 */
interface KeyMetadata {
  createdAt: number;
  expiresAt: number;
}

function checkRotationNeeded(
  metadata: KeyMetadata | null,
  refreshIntervalMs: number,
  keyTypeName: string,
  logger: Required<Logger>
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

export { MIN_PREKEY_REPLENISHMENT_THRESHOLD } from './one-time-prekey-refill';

/**
 * Check if a key needs rotation based on age
 *
 * Used for BOTH signed and Kyber prekeys. Per PQXDH spec Section 3.2,
 * both key types use identical rotation thresholds, which synchronizes
 * post-quantum security maintenance.
 *
 * @param createdAt - Key creation timestamp (milliseconds)
 * @param expiresAt - Key expiration timestamp (milliseconds)
 * @param refreshIntervalMs - Custom refresh interval (defaults to 2 days)
 * @returns true if the key needs rotation
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
 * Check whether prekeys exceed the maximum allowed age.
 *
 * If prekeys are older than MAX_PREKEY_AGE_MS (14 days), the caller must block
 * message sending until rotation succeeds.
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
 * The key id for the next Kyber last-resort prekey of one identity type.
 *
 * Each retained Kyber prekey keeps its own id, so a session that names an id
 * resolves to exactly one key. The next id follows the current key, and a store
 * with no current key starts at 1.
 */
export async function nextKyberLastResortPreKeyId(
  storage: Pick<SignalProtocolLocalStore, 'getKyberPreKey'>,
  identityType: IdentityType
): Promise<number> {
  const current = await storage.getKyberPreKey(identityType);
  return (current?.keyId ?? 0) + 1;
}

/** Options for one prekey rotation. */
export interface PreKeyRotationOptions {
  /** Signed-key refresh interval (defaults to 2 days). */
  refreshIntervalMs?: number;
  /** One-time prekey count below which a refill starts (defaults to 10). */
  threshold?: number;
  /** Identity types to rotate (defaults to the active identity types). */
  identityTypes?: readonly IdentityType[];
  /** App-provided replaced-prekey maintenance store. */
  preKeyMaintenance?: PreKeyMaintenanceStore;
  logger?: Required<Logger>;
}

/** The keys one rotation generated and the publication accepted. */
interface PlannedKeys {
  signed: EcSignedPreKey | null;
  kyber: KyberPreKey | null;
  refill: OneTimePreKeyRefill | null;
}

/** Whether one inventory calls for a refill of either one-time prekey set. */
export function oneTimePreKeysDue(inventory: PreKeyInventory, threshold: number): boolean {
  return inventory.ecOneTimePreKeyCount < threshold || inventory.kemOneTimePreKeyCount < threshold;
}

/**
 * Rotate the prekeys of one device: one inventory read and one publication
 * per identity type.
 *
 * Per PQXDH spec Section 3.2, the EC signed prekey and the KEM last-resort
 * prekey rotate on the same schedule. The one-time prekey batches refill in
 * the same publication when a server count is below the threshold. Nothing
 * due costs one inventory read.
 *
 * A failed identity type is reported in `errors` and does not stop the other
 * identity types. The result booleans are true when any identity type rotated
 * that key.
 *
 * @see https://signal.org/docs/specifications/pqxdh/#publishing-keys
 */
export async function rotatePreKeysCore(
  relay: SignalProtocolRelayServer,
  userId: string,
  deviceId: number,
  providedStorage?: SignalProtocolLocalStore,
  options: PreKeyRotationOptions = {}
): Promise<PreKeyRotationResult> {
  const {
    refreshIntervalMs = KEY_REFRESH_INTERVAL_MS_DEFAULT,
    threshold = MIN_PREKEY_REPLENISHMENT_THRESHOLD,
    identityTypes = getActiveIdentityTypes(),
    preKeyMaintenance,
    logger = defaultSignalProtocolLogger,
  } = options;
  const result: PreKeyRotationResult = {
    signedRotated: false,
    kyberRotated: false,
    oneTimeReplenished: false,
    errors: [],
  };
  const storage = await resolveStorage(providedStorage, logger);

  for (const identityType of identityTypes) {
    const outcome = await withRotationLock(
      userId,
      deviceId,
      identityType,
      () =>
        rotatePreKeysForIdentity(relay, userId, deviceId, storage, identityType, {
          refreshIntervalMs,
          threshold,
          preKeyMaintenance,
          logger,
        }),
      `Failed to rotate prekeys (${identityType})`,
      logger
    );
    if (!outcome.ok) {
      result.errors.push(`${identityType}: ${outcome.error}`);
      continue;
    }
    result.signedRotated = result.signedRotated || outcome.value.signed !== null;
    result.kyberRotated = result.kyberRotated || outcome.value.kyber !== null;
    result.oneTimeReplenished = result.oneTimeReplenished || outcome.value.refill !== null;
  }

  return result;
}

/**
 * Rotate the prekeys of one identity type under the caller's lock.
 *
 * The plan runs inside the relay adapter's publication fence with the
 * inventory the adapter read. The signed keys are stored only after the
 * publication returns.
 */
async function rotatePreKeysForIdentity(
  relay: SignalProtocolRelayServer,
  userId: string,
  deviceId: number,
  storage: SignalProtocolLocalStore,
  identityType: IdentityType,
  options: Required<Pick<PreKeyRotationOptions, 'refreshIntervalMs' | 'threshold' | 'logger'>> &
    Pick<PreKeyRotationOptions, 'preKeyMaintenance'>
): Promise<PlannedKeys> {
  const { refreshIntervalMs, threshold, preKeyMaintenance, logger } = options;
  const planned: PlannedKeys = { signed: null, kyber: null, refill: null };

  await relay.publishPlannedPreKeys(
    userId,
    deviceId,
    async (inventory) => {
      const signedDue = checkRotationNeeded(
        inventory.ecSignedPreKey,
        refreshIntervalMs,
        `EC signed prekey (${identityType})`,
        logger
      );
      const kyberDue = checkRotationNeeded(
        inventory.kemLastResortPreKey,
        refreshIntervalMs,
        `Kyber prekey (${identityType})`,
        logger
      );
      const refillDue = oneTimePreKeysDue(inventory, threshold);
      if (!signedDue && !kyberDue && !refillDue) {
        logger.breadcrumb('Prekeys current, no publication needed', {
          category: 'E2EE',
          level: 'debug',
          data: { identityType, threshold },
        });
        return [];
      }

      logger.info('Rotating prekeys', {
        category: 'E2EE',
        data: { userId, deviceId, identityType, signedDue, kyberDue, refillDue },
      });
      const uploads: PreKeyUpload[] = [];
      if (signedDue || kyberDue) {
        const identityKey = await getRequiredIdentityKey(storage, identityType);
        if (signedDue) {
          planned.signed = await generateEcSignedPreKey(identityKey);
          uploads.push({
            type: 'ecSignedPreKey',
            keyId: planned.signed.keyId,
            publicKey: planned.signed.publicKey as string,
            signature: planned.signed.signature as string,
          });
        }
        if (kyberDue) {
          planned.kyber = await generateKyberLastResortPreKey(
            identityKey,
            await nextKyberLastResortPreKeyId(storage, identityType)
          );
          uploads.push({
            type: 'kemLastResortPreKey',
            keyId: planned.kyber.keyId,
            publicKey: planned.kyber.publicKey as string,
            signature: planned.kyber.signature as string,
          });
        }
      }
      if (refillDue) {
        // Local store first (private keys needed for decryption), then one upload.
        planned.refill = await refillOneTimePreKeys({
          storage,
          identityType,
          serverEcCount: inventory.ecOneTimePreKeyCount,
          serverKemCount: inventory.kemOneTimePreKeyCount,
          threshold,
          preKeyMaintenance,
          logger,
        });
        uploads.push(...planned.refill.uploads);
      }
      return uploads;
    },
    identityType
  );

  // TRANSACTIONAL PATTERN: the publication succeeded, so commit the signed keys locally.
  if (planned.signed) {
    await storage.storeEcSignedPreKey(planned.signed, identityType);
  }
  if (planned.kyber) {
    await storage.storeKyberPreKey(
      {
        ...planned.kyber,
        publicKey: planned.kyber.publicKey as PublicKey,
        privateKey: planned.kyber.privateKey as PrivateKey,
        signature: planned.kyber.signature as Signature,
      },
      identityType
    );
  }
  if (planned.signed || planned.kyber || planned.refill) {
    logger.info('Prekeys rotated', {
      category: 'E2EE',
      data: {
        userId,
        deviceId,
        identityType,
        signedRotated: planned.signed !== null,
        kyberRotated: planned.kyber !== null,
        ecAdded: planned.refill?.ecGenerated ?? 0,
        kemAdded: planned.refill?.kemGenerated ?? 0,
      },
    });
  }
  return planned;
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
  /** Whether the check attempted a rotation */
  rotationAttempted: boolean;
  /** Whether rotation succeeded (if attempted) */
  rotationSucceeded: boolean;
  /** Error message if rotation failed */
  errorMessage?: string;
}

/**
 * Check prekey age and rotate if needed before sending a message.
 *
 * If prekeys exceed MAX_PREKEY_AGE_MS (14 days), this function attempts a
 * rotation. If rotation fails, the caller must block sending to maintain
 * security.
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
  relay: SignalProtocolRelayServer,
  userId: string,
  deviceId: number,
  storage?: SignalProtocolLocalStore,
  maxAgeMs: number = MAX_PREKEY_AGE_MS_DEFAULT,
  identityType: IdentityType = 'aci',
  logger: Required<Logger> = defaultSignalProtocolLogger
): Promise<PreKeySendCheckResult> {
  // One inventory read gives both signed-key records for the identity type.
  const inventory = await relay.getPreKeyInventory(userId, deviceId, identityType);
  const { ecSignedPreKey: signedMetadata, kemLastResortPreKey: kyberMetadata } = inventory;
  const signedExpired = signedMetadata ? isPreKeyExpired(signedMetadata.createdAt, maxAgeMs) : true;
  const kyberExpired = kyberMetadata ? isPreKeyExpired(kyberMetadata.createdAt, maxAgeMs) : true;

  // If neither key expired, sending can proceed
  if (!signedExpired && !kyberExpired) {
    return {
      canSend: true,
      rotationAttempted: false,
      rotationSucceeded: false,
    };
  }

  // The prekeys expired - attempt rotation (rotate before blocking)
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

  // An expired key is older than the refresh interval, so the rotation finds it due.
  const rotation = await rotatePreKeysCore(relay, userId, deviceId, storage, {
    identityTypes: [identityType],
    logger,
  });
  const signedRotated = !signedExpired || rotation.signedRotated;
  const kyberRotated = !kyberExpired || rotation.kyberRotated;

  if (!signedRotated || !kyberRotated) {
    logger.error('Failed to rotate prekeys before send', {
      category: 'E2EE',
      error: new Error(rotation.errors.join('; ') || 'Prekey rotation left an expired key'),
      data: { userId, deviceId, identityType, signedRotated, kyberRotated },
    });
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
