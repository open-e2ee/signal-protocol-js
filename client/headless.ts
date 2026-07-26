/**
 * Headless Key Rotation
 *
 * Key rotation API for background jobs and other runtimes without a component
 * lifecycle.
 *
 * @example
 * ```typescript
 * // In background task (no React)
 * import { ConvexHttpClient } from 'convex/browser';
 * import { rotateKeysHeadless } from '@open-e2ee/signal-protocol-sdk/client/headless';
 * import { expoStore } from '@open-e2ee/signal-protocol-sdk/local/store/expo';
 * import { convexRelay, type ConvexSignalProtocolRelayApi } from '@open-e2ee/signal-protocol-sdk/remote/relay/convex';
 * import { api } from '../convex/_generated/api';
 *
 * const convex = new ConvexHttpClient(CONVEX_URL);
 * convex.setAuth(authToken);
 * const signalApi = api.signal satisfies ConvexSignalProtocolRelayApi;
 * const relay = convexRelay({ convex, api: signalApi, currentUserId: userId });
 * const storage = expoStore({ relay });
 *
 * const result = await rotateKeysHeadless(relay, userId, deviceId, { storage });
 * console.log(result); // { signedRotated: true, kyberRotated: false, oneTimeReplenished: true }
 * ```
 */

import { resolveSignalProtocolLogger, type ILogger } from '../logger';
import { getErrorMessage } from '../utils/errors';
import type { ISignalProtocolLocalStore } from '../types';
import type { ISignalProtocolRelayServer } from '../remote/relay/types';
import type { IdentityType } from '../keys/types';
import { MAX_UNACKNOWLEDGED_SESSION_AGE_MS, type PreKeyMaintenanceStore } from './config';
import {
  rotateEcSignedPreKeyCore,
  rotateKyberPreKeyCore,
  replenishOneTimePreKeysCore,
  MIN_PREKEY_REPLENISHMENT_THRESHOLD,
} from './key-rotation-core';

/**
 * Result of headless key rotation
 */
export {};
export interface HeadlessRotationResult {
  /** Whether signed prekey was rotated */
  signedRotated: boolean;
  /** Whether Kyber prekey was rotated */
  kyberRotated: boolean;
  /** Whether one-time prekeys were replenished */
  oneTimeReplenished: boolean;
  /** Any errors that occurred (non-fatal) */
  errors: string[];
}

/**
 * Options for headless key rotation
 */
export interface HeadlessRotationOptions {
  /** Local store implementation for the current runtime. */
  storage?: ISignalProtocolLocalStore;
  /** Identity types to rotate (defaults to ['aci', 'pni']) */
  identityTypes?: readonly IdentityType[];
  /** App-provided replaced-prekey maintenance store. */
  preKeyMaintenance?: PreKeyMaintenanceStore;
  /** Optional logger for headless/background execution. */
  logger?: ILogger;
}

/**
 * Rotate encryption keys in headless/background mode
 *
 * Per PQXDH spec Section 3.2, rotates BOTH signed and Kyber prekeys
 * together to maintain synchronized post-quantum forward secrecy.
 *
 * This function is designed for background tasks where no React
 * context is available. It uses the same core rotation logic
 * as SignalProtocolClient but works with any ISignalProtocolRelayServer implementation.
 *
 * Features:
 * - Works with ConvexSignalProtocolRelayServer or any ISignalProtocolRelayServer implementation
 * - Checks if rotation is needed before performing it
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
  relay: ISignalProtocolRelayServer,
  userId: string,
  deviceId: number,
  options?: HeadlessRotationOptions
): Promise<HeadlessRotationResult> {
  const { storage, identityTypes, preKeyMaintenance, logger: providedLogger } = options ?? {};
  const logger = resolveSignalProtocolLogger(providedLogger);
  const errors: string[] = [];

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

  // Rotate signed prekey
  let signedRotated = false;
  try {
    signedRotated = await rotateEcSignedPreKeyCore(
      relay,
      userId,
      deviceId,
      storage,
      undefined,
      identityTypes,
      logger
    );
  } catch (error) {
    const message = getErrorMessage(error);
    errors.push(`signedPreKey: ${message}`);
    logger.error('Headless signed prekey rotation failed', {
      category: 'E2EE',
      error: error as Error,
      data: { userId, deviceId },
    });
  }

  // Rotate Kyber prekey
  let kyberRotated = false;
  try {
    kyberRotated = await rotateKyberPreKeyCore(
      relay,
      userId,
      deviceId,
      storage,
      undefined,
      identityTypes,
      logger
    );
  } catch (error) {
    const message = getErrorMessage(error);
    errors.push(`kyberPreKey: ${message}`);
    logger.error('Headless Kyber prekey rotation failed', {
      category: 'E2EE',
      error: error as Error,
      data: { userId, deviceId },
    });
  }

  // Replenish one-time prekeys
  let oneTimeReplenished = false;
  try {
    oneTimeReplenished = await replenishOneTimePreKeysCore(
      relay,
      userId,
      deviceId,
      storage,
      undefined,
      identityTypes,
      preKeyMaintenance,
      logger
    );
  } catch (error) {
    const message = getErrorMessage(error);
    errors.push(`oneTimePreKeys: ${message}`);
    logger.error('Headless one-time prekey replenishment failed', {
      category: 'E2EE',
      error: error as Error,
      data: { userId, deviceId },
    });
  }

  logger.info('Headless key rotation completed', {
    category: 'E2EE',
    data: {
      userId,
      deviceId,
      signedRotated,
      kyberRotated,
      oneTimeReplenished,
      errorCount: errors.length,
    },
  });

  if (preKeyMaintenance && (signedRotated || kyberRotated || oneTimeReplenished)) {
    try {
      await preKeyMaintenance.cullReplacedPreKeys(MAX_UNACKNOWLEDGED_SESSION_AGE_MS);
    } catch (error) {
      logger.warn('Failed to cull replaced prekeys after headless rotation (non-critical)', {
        category: 'E2EE',
        error: error as Error,
      });
    }
  }

  return {
    signedRotated,
    kyberRotated,
    oneTimeReplenished,
    errors,
  };
}

/**
 * Check if any keys need rotation
 *
 * Lightweight check that doesn't perform rotation.
 * Useful for deciding whether to run the full rotation.
 *
 * @param relay - Signal Protocol relay server interface
 * @param userId - User identifier
 * @param deviceId - Device identifier
 * @returns Object indicating which keys need rotation
 */
export async function checkRotationNeeded(
  relay: ISignalProtocolRelayServer,
  userId: string,
  deviceId: number
): Promise<{
  signedPreKeyNeeded: boolean;
  kyberPreKeyNeeded: boolean;
  oneTimePreKeysNeeded: boolean;
}> {
  const { shouldRotateKey } = await import('./key-rotation-core');

  const [signedMeta, kyberMeta, oneTimeCount] = await Promise.all([
    relay.getEcSignedPreKeyMetadata(userId, deviceId),
    relay.getKemLastResortPreKeyMetadata(userId, deviceId),
    relay.getPreKeyCount(userId, deviceId, 'ec'),
  ]);

  return {
    signedPreKeyNeeded: signedMeta
      ? shouldRotateKey(signedMeta.createdAt, signedMeta.expiresAt)
      : true,
    kyberPreKeyNeeded: kyberMeta ? shouldRotateKey(kyberMeta.createdAt, kyberMeta.expiresAt) : true,
    oneTimePreKeysNeeded: oneTimeCount < MIN_PREKEY_REPLENISHMENT_THRESHOLD,
  };
}
