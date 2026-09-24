/**
 * Headless Key Rotation
 *
 * Key rotation API for background jobs and other runtimes without a component
 * lifecycle.
 *
 * @example
 * ```typescript
 * // In background task (no React)
 * import { rotateKeysHeadless } from '@open-e2ee/signal-protocol-sdk/client/headless';
 * import { expoStore } from '@open-e2ee/signal-protocol-sdk/local/store/expo';
 *
 * // Any SignalProtocolRelayServer the app composes, authenticated for this user.
 * const relay = createAuthenticatedRelay({ authToken, userId });
 * const storage = expoStore();
 *
 * const result = await rotateKeysHeadless(relay, userId, deviceId, { storage });
 * console.log(result); // { signedRotated: true, kyberRotated: false, oneTimeReplenished: true, errors: [] }
 * ```
 */

import { resolveSignalProtocolLogger, type Logger } from '../logger';
import type { PreKeyRotationResult, SignalProtocolLocalStore } from '../types';
import type { SignalProtocolRelayServer } from '../remote/relay/types';
import type { IdentityType } from '../keys/types';
import { MAX_UNACKNOWLEDGED_SESSION_AGE_MS, type PreKeyMaintenanceStore } from './config';
import { oneTimePreKeysDue, rotatePreKeysCore, shouldRotateKey } from './key-rotation-core';
import { MIN_PREKEY_REPLENISHMENT_THRESHOLD } from './one-time-prekey-refill';

export {};
export type { PreKeyRotationResult };

/**
 * Options for headless key rotation
 */
export interface HeadlessRotationOptions {
  /** Local store implementation for the current runtime. */
  storage?: SignalProtocolLocalStore;
  /** Identity types to rotate (defaults to the active identity types, `['aci']` unless PNI keys are enabled) */
  identityTypes?: readonly IdentityType[];
  /** App-provided replaced-prekey maintenance store. */
  preKeyMaintenance?: PreKeyMaintenanceStore;
  /** Optional logger for headless/background execution. */
  logger?: Logger;
}

/**
 * Rotate encryption keys in headless/background mode
 *
 * Per PQXDH spec Section 3.2, rotates BOTH signed and Kyber prekeys
 * together to maintain synchronized post-quantum forward secrecy, and refills
 * the one-time prekey batches in the same publication.
 *
 * This function suits background tasks that have no React
 * context. It uses the same core rotation logic
 * as SignalProtocolClient but works with any SignalProtocolRelayServer implementation.
 *
 * Features:
 * - Works with any SignalProtocolRelayServer implementation
 * - One inventory read decides what is due; nothing due publishes nothing
 * - Handles errors gracefully (returns partial success)
 * - Logs all operations for debugging
 *
 * @param relay - Signal Protocol relay server interface
 * @param userId - User identifier
 * @param deviceId - Device identifier
 * @param options - Optional configuration (storage, identityTypes)
 * @returns Rotation results for each key type
 *
 * @see https://signal.org/docs/specifications/pqxdh/#publishing-keys
 */
export async function rotateKeysHeadless(
  relay: SignalProtocolRelayServer,
  userId: string,
  deviceId: number,
  options?: HeadlessRotationOptions
): Promise<PreKeyRotationResult> {
  const { storage, identityTypes, preKeyMaintenance, logger: providedLogger } = options ?? {};
  const logger = resolveSignalProtocolLogger(providedLogger);

  logger.info('Starting headless key rotation', {
    category: 'E2EE',
    data: { userId, deviceId, context: 'headless' },
  });

  if (!storage) {
    throw new Error(
      'rotateKeysHeadless() requires a local store. ' +
        'Create the runtime-specific store in app code and pass it explicitly.'
    );
  }

  const result = await rotatePreKeysCore(relay, userId, deviceId, storage, {
    identityTypes,
    preKeyMaintenance,
    logger,
  });

  logger.info('Headless key rotation completed', {
    category: 'E2EE',
    data: {
      userId,
      deviceId,
      signedRotated: result.signedRotated,
      kyberRotated: result.kyberRotated,
      oneTimeReplenished: result.oneTimeReplenished,
      errorCount: result.errors.length,
    },
  });

  if (
    preKeyMaintenance &&
    (result.signedRotated || result.kyberRotated || result.oneTimeReplenished)
  ) {
    try {
      await preKeyMaintenance.cullReplacedPreKeys(MAX_UNACKNOWLEDGED_SESSION_AGE_MS);
    } catch (error) {
      logger.warn('Failed to cull replaced prekeys after headless rotation (non-critical)', {
        category: 'E2EE',
        error: error as Error,
      });
    }
  }

  return result;
}

/**
 * Check if any keys need rotation
 *
 * One inventory read that does not rotate anything.
 * Useful for deciding whether to run the full rotation.
 *
 * @param relay - Signal Protocol relay server interface
 * @param userId - User identifier
 * @param deviceId - Device identifier
 * @returns Object indicating which keys need rotation
 */
export async function checkRotationNeeded(
  relay: SignalProtocolRelayServer,
  userId: string,
  deviceId: number
): Promise<{
  signedPreKeyNeeded: boolean;
  kyberPreKeyNeeded: boolean;
  oneTimePreKeysNeeded: boolean;
}> {
  const inventory = await relay.getPreKeyInventory(userId, deviceId);
  const { ecSignedPreKey: signedMeta, kemLastResortPreKey: kyberMeta } = inventory;

  return {
    signedPreKeyNeeded: signedMeta
      ? shouldRotateKey(signedMeta.createdAt, signedMeta.expiresAt)
      : true,
    kyberPreKeyNeeded: kyberMeta ? shouldRotateKey(kyberMeta.createdAt, kyberMeta.expiresAt) : true,
    oneTimePreKeysNeeded: oneTimePreKeysDue(inventory, MIN_PREKEY_REPLENISHMENT_THRESHOLD),
  };
}
