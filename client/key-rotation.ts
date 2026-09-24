/**
 * Key rotation operations for SignalProtocolClient
 *
 * Extracted from DefaultSignalProtocolClient class to reduce file size.
 * One entry point rotates the EC signed prekey, the Kyber (post-quantum)
 * last-resort prekey, and the one-time prekey batches.
 *
 * With relay configured: Delegates to key-rotation-core.ts, which reads the
 * inventory once and publishes every due key in one publication.
 *
 * Without relay (local-only): Always rotates both signed keys unconditionally
 * since we cannot check server metadata. No one-time refill runs.
 */

import { EncryptionError, EncryptionErrorCode, type PreKeyRotationResult } from '../types';
import { callHook } from './event-hooks';
import type { SignalProtocolClientContext } from './types';
import type { IdentityType } from '../keys/types';
import {
  KEY_REFRESH_INTERVAL_MS_DEFAULT,
  MAX_UNACKNOWLEDGED_SESSION_AGE_MS,
  getActiveIdentityTypes,
} from './config';
import { nextKyberLastResortPreKeyId, rotatePreKeysCore } from './key-rotation-core';

/**
 * Rotate the device's prekeys.
 *
 * Call this periodically (default: every 2 days) to maintain forward secrecy.
 * Safe to call more often: nothing due costs one inventory read.
 *
 * With relay: One inventory read decides on the signed keys (config.keyRefreshIntervalMs)
 * and the one-time refill, and one publication carries every due key.
 * Without relay: Always rotates both signed keys (local-only development mode).
 *
 * @param ctx - Client context with dependencies
 * @returns Which keys the rotation published, and one error per failed identity type
 */
export {};
export async function rotatePreKeys(ctx: SignalProtocolClientContext): Promise<PreKeyRotationResult> {
  // Use config value if provided, otherwise use profile default (2 days)
  const refreshIntervalMs = ctx.config.keyRefreshIntervalMs ?? KEY_REFRESH_INTERVAL_MS_DEFAULT;

  // With relay: delegate to the core for the inventory-based rotation decision
  if (ctx.relay) {
    const result = await rotatePreKeysCore(ctx.relay, ctx.userId, ctx.deviceId, ctx.storage, {
      refreshIntervalMs,
      identityTypes: getActiveIdentityTypes(ctx.config),
      preKeyMaintenance: ctx.config.preKeyMaintenance,
      logger: ctx.logger,
    });

    if (result.signedRotated) {
      await callHook(ctx.hooks, 'onKeyRotated', 'ecSignedPreKey');
    }
    if (result.kyberRotated) {
      await callHook(ctx.hooks, 'onKeyRotated', 'kemLastResortPreKey');
    }
    if (result.signedRotated || result.kyberRotated || result.oneTimeReplenished) {
      ctx.logger.debug('Prekeys rotated', {
        category: 'E2EE',
        data: { userId: ctx.userId, refreshIntervalMs, ...result, errors: result.errors.length },
      });
      await cullReplacedPreKeysQuietly(ctx);
    }

    return result;
  }

  // Without relay: unconditional local-only rotation of both signed keys
  const errors: string[] = [];
  const signedRotated = await rotateEcSignedPreKeyLocalOnly(ctx, errors);
  const kyberRotated = await rotateKyberPreKeyLocalOnly(ctx, errors);
  if (signedRotated || kyberRotated) {
    await cullReplacedPreKeysQuietly(ctx);
  }
  return { signedRotated, kyberRotated, oneTimeReplenished: false, errors };
}

/**
 * Local-only EC signed prekey rotation (no relay)
 *
 * Always rotates unconditionally since we cannot check server metadata.
 * Used for local development without a backend.
 */
async function rotateEcSignedPreKeyLocalOnly(
  ctx: SignalProtocolClientContext,
  errors: string[],
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
    errors.push(`ecSignedPreKey: ${(error as Error).message}`);
    return false;
  }
}

/**
 * Local-only Kyber prekey rotation (no relay)
 *
 * Always rotates unconditionally since we cannot check server metadata.
 * Each rotation takes the next key id, so a session that names an id resolves
 * to exactly one retained key.
 */
async function rotateKyberPreKeyLocalOnly(
  ctx: SignalProtocolClientContext,
  errors: string[],
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
        const newKyberPreKey = await generateKyberLastResortPreKey(
          identityKey,
          await nextKyberLastResortPreKeyId(ctx.storage, identityType)
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
    errors.push(`kemLastResortPreKey: ${(error as Error).message}`);
    return false;
  }
}

/**
 * Cull replaced prekeys that are past the grace period.
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
