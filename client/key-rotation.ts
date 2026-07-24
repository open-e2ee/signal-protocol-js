/**
 * Key rotation operations for SignalProtocolClient
 *
 * Extracted from SignalProtocolClient class to reduce file size.
 * Handles rotation of EC signed prekeys and Kyber (post-quantum) prekeys.
 *
 * With relay configured: Delegates to key-rotation-core.ts for metadata-based
 * rotation decisions (skips if key is fresh).
 *
 * Without relay (local-only): Always rotates unconditionally since we can't
 * check server metadata.
 */

import { EncryptionError, EncryptionErrorCode } from '../types';
import { callHook } from './event-hooks';
import type { SignalProtocolClientContext } from './types';
import type { IdentityType } from '../keys/types';
import {
  KEY_REFRESH_INTERVAL_MS_DEFAULT,
  MAX_UNACKNOWLEDGED_SESSION_AGE_MS,
  getActiveIdentityTypes,
} from './config';
import { rotateEcSignedPreKeyCore, rotateKyberPreKeyCore } from './key-rotation-core';

/**
 * Rotate EC signed prekey
 *
 * Should be called periodically (default: every 2 days) to maintain forward secrecy.
 * Generates new EC signed prekey and uploads to relay server if configured.
 *
 * With relay: Checks if rotation is needed based on key age and config.keyRefreshIntervalMs.
 * Without relay: Always rotates (local-only development mode).
 *
 * @param ctx - Client context with dependencies
 * @returns True if rotation was performed, false if not needed yet
 */
export {};
export async function rotateEcSignedPreKey(ctx: SignalProtocolClientContext): Promise<boolean> {
  // Use config value if provided, otherwise use profile default (2 days)
  const refreshIntervalMs = ctx.config.keyRefreshIntervalMs ?? KEY_REFRESH_INTERVAL_MS_DEFAULT;

  // With relay: delegate to core function for metadata-based rotation check
  if (ctx.relay) {
    const rotated = await rotateEcSignedPreKeyCore(
      ctx.relay,
      ctx.userId,
      ctx.deviceId,
      ctx.storage,
      refreshIntervalMs,
      getActiveIdentityTypes(ctx.config),
      ctx.logger
    );

    if (rotated) {
      ctx.logger.debug('EC signed prekey rotated', {
        category: 'E2EE',
        data: { userId: ctx.userId, refreshIntervalMs },
      });
      await callHook(ctx.hooks, 'onKeyRotated', 'ecSignedPreKey');
      await cullReplacedPreKeysQuietly(ctx);
    }

    return rotated;
  }

  // Without relay: unconditional local-only rotation
  const localResult = await rotateEcSignedPreKeyLocalOnly(ctx);
  if (localResult) {
    await cullReplacedPreKeysQuietly(ctx);
  }
  return localResult;
}

/**
 * Local-only EC signed prekey rotation (no relay)
 *
 * Always rotates unconditionally since we can't check server metadata.
 * Used for local development without a backend.
 */
async function rotateEcSignedPreKeyLocalOnly(
  ctx: SignalProtocolClientContext,
  identityType: IdentityType = 'aci'
): Promise<boolean> {
  const { withRetry } = await import('../utils/retry');
  const { generateEcSignedPreKey } = await import('../keys');

  try {
    const identityKey = await ctx.storage.getIdentityKey(identityType);
    if (!identityKey) {
      throw new EncryptionError(
        `Identity key not found (${identityType}) - cannot rotate EC signed prekey`,
        EncryptionErrorCode.INITIALIZATION_FAILED
      );
    }

    await withRetry(
      async () => {
        const newSignedPreKey = await generateEcSignedPreKey(identityKey);
        await ctx.storage.storeEcSignedPreKey(newSignedPreKey, identityType);
      },
      { operationName: 'rotateEcSignedPreKey', maxRetries: 2, baseDelay: 2000 }
    );

    ctx.logger.debug('EC signed prekey rotated (local-only)', {
      category: 'E2EE',
      data: { userId: ctx.userId },
    });

    await callHook(ctx.hooks, 'onKeyRotated', 'ecSignedPreKey');
    return true;
  } catch (error) {
    ctx.logger.error('Failed to rotate EC signed prekey (local-only)', {
      category: 'E2EE',
      error: error as Error,
      data: { userId: ctx.userId },
    });
    return false;
  }
}

/**
 * Rotate the post-quantum KEM last-resort prekey.
 *
 * Should be called periodically (default: every 2 days) alongside signed prekey rotation.
 * Generates fresh ML-KEM/Kyber-compatible key material and uploads it to the
 * relay if configured.
 *
 * Per PQXDH spec Section 3.2: Always use ID 1 (replaces previous).
 * Uses the same timing as signed prekey rotation for synchronized PQ security.
 *
 * With relay: Checks if rotation is needed based on key age and config.keyRefreshIntervalMs.
 * Without relay: Always rotates (local-only development mode).
 *
 * @param ctx - Client context with dependencies
 * @returns True if rotation was performed, false if not needed yet
 */
export async function rotateKyberPreKey(ctx: SignalProtocolClientContext): Promise<boolean> {
  // Use config value if provided, otherwise use profile default (2 days)
  const refreshIntervalMs = ctx.config.keyRefreshIntervalMs ?? KEY_REFRESH_INTERVAL_MS_DEFAULT;

  // With relay: delegate to core function for metadata-based rotation check
  if (ctx.relay) {
    const rotated = await rotateKyberPreKeyCore(
      ctx.relay,
      ctx.userId,
      ctx.deviceId,
      ctx.storage,
      refreshIntervalMs,
      getActiveIdentityTypes(ctx.config),
      ctx.logger
    );

    if (rotated) {
      ctx.logger.debug('Kyber prekey rotated (PQXDH security maintained)', {
        category: 'E2EE',
        data: { userId: ctx.userId, refreshIntervalMs },
      });
      await callHook(ctx.hooks, 'onKeyRotated', 'kemLastResortPreKey');
      await cullReplacedPreKeysQuietly(ctx);
    }

    return rotated;
  }

  // Without relay: unconditional local-only rotation
  const localResult = await rotateKyberPreKeyLocalOnly(ctx);
  if (localResult) {
    await cullReplacedPreKeysQuietly(ctx);
  }
  return localResult;
}

/**
 * Local-only Kyber prekey rotation (no relay)
 *
 * Always rotates unconditionally since we can't check server metadata.
 * Used for local development without a backend.
 */
async function rotateKyberPreKeyLocalOnly(
  ctx: SignalProtocolClientContext,
  identityType: IdentityType = 'aci'
): Promise<boolean> {
  const { withRetry } = await import('../utils/retry');
  const { generateKyberLastResortPreKey } = await import('../keys');

  try {
    const identityKey = await ctx.storage.getIdentityKey(identityType);
    if (!identityKey) {
      throw new EncryptionError(
        `Identity key not found (${identityType}) - cannot rotate Kyber prekey`,
        EncryptionErrorCode.INITIALIZATION_FAILED
      );
    }

    await withRetry(
      async () => {
        // Per PQXDH spec Section 3.2: Always use ID 1 (replaces previous)
        const newKyberPreKey = await generateKyberLastResortPreKey(
          identityKey,
          1
        );
        await ctx.storage.storeKyberPreKey(newKyberPreKey, identityType);
      },
      { operationName: 'rotateKyberPreKey', maxRetries: 2, baseDelay: 2000 }
    );

    ctx.logger.debug('Kyber prekey rotated (local-only, PQXDH security maintained)', {
      category: 'E2EE',
      data: { userId: ctx.userId },
    });

    await callHook(ctx.hooks, 'onKeyRotated', 'kemLastResortPreKey');
    return true;
  } catch (error) {
    ctx.logger.error('Failed to rotate Kyber prekey (local-only)', {
      category: 'E2EE',
      error: error as Error,
      data: { userId: ctx.userId },
    });
    return false;
  }
}

/**
 * Cull replaced prekeys that have exceeded the grace period.
 * Best-effort: logs but never throws (culling is non-critical).
 */
async function cullReplacedPreKeysQuietly(ctx: SignalProtocolClientContext): Promise<void> {
  const maintenance = ctx.config.preKeyMaintenance;
  if (!maintenance) {
    return;
  }

  try {
    const {
      ecSignedPreKeys: signedCulled,
      kyberPreKeys: kyberCulled,
      ecOneTimePreKeys: ecOneTimeCulled,
      kyberOneTimePreKeys: kemOneTimeCulled,
    } = await maintenance.cullReplacedPreKeys(MAX_UNACKNOWLEDGED_SESSION_AGE_MS);

    const total = signedCulled + kyberCulled + ecOneTimeCulled + kemOneTimeCulled;
    if (total > 0) {
      ctx.logger.debug('Culled replaced prekeys', {
        category: 'E2EE',
        data: { signedCulled, kyberCulled, ecOneTimeCulled, kemOneTimeCulled },
      });
    }
  } catch (error) {
    ctx.logger.warn('Failed to cull replaced prekeys (non-critical)', {
      category: 'E2EE',
      error: error as Error,
    });
  }
}
