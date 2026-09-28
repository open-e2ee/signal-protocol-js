/**
 * Device ID Helper
 *
 * Provides non-hook access to device ID for use in classes and utilities.
 * Reads the local secret vault that the application passes to
 * DeviceLifecycleManager.
 */

import { resolveSignalProtocolLogger, type Logger } from '../logger';
import { DEVICE_ID_KEY, DEFAULT_DEVICE_ID } from './constants';
import type { SignalProtocolLocalSecretVault } from '../types/api';
import { requireSecretVault } from '../local/vault/require';
import { readVaultText } from './vault-text';
export {};
let cachedDeviceId: number | null = null;

/**
 * Get the current device ID
 *
 * Callers can run this function from anywhere, including non-React contexts
 * like ContentManager. Pass the vault that the application passes to
 * DeviceLifecycleManager.
 *
 * @param vault - Local secret vault that holds the device ID
 * @returns Device ID (1-5), or DEFAULT_DEVICE_ID if not yet initialized
 */
export async function getDeviceId(
  vault: SignalProtocolLocalSecretVault,
  providedLogger?: Logger
): Promise<number> {
  const secretVault = requireSecretVault(vault, 'getDeviceId');
  const logger = resolveSignalProtocolLogger(providedLogger);
  // Return cached value if available
  if (cachedDeviceId !== null) {
    return cachedDeviceId;
  }

  try {
    const storedId = await readVaultText(secretVault, DEVICE_ID_KEY);

    if (storedId) {
      const id = parseInt(storedId, 10);
      if (id >= 1 && id <= 5) {
        cachedDeviceId = id;
        logger.debug('Retrieved device ID from the local secret vault', {
          category: 'Device',
          data: { deviceId: id },
        });
        return id;
      }
    }

    // Not yet initialized - return default
    logger.warn('Device ID not initialized, using default', {
      category: 'Device',
      data: { defaultId: DEFAULT_DEVICE_ID },
    });
    return DEFAULT_DEVICE_ID;
  } catch (error) {
    logger.error('Failed to get device ID', {
      category: 'Device',
      error: error as Error,
    });
    return DEFAULT_DEVICE_ID;
  }
}

/**
 * Get device ID synchronously (uses cached value)
 *
 * WARNING: This returns DEFAULT_DEVICE_ID if nothing called getDeviceId() yet.
 * Use this only if you are sure the device ID already loaded.
 *
 * @returns Cached device ID, or DEFAULT_DEVICE_ID if not cached
 */
export function getDeviceIdSync(): number {
  return cachedDeviceId ?? DEFAULT_DEVICE_ID;
}

/**
 * Clear the device ID cache
 *
 * Call this when:
 * - User logs out
 * - User switches accounts
 * - Device is reset/unlinked
 * - Controlled local resets
 *
 * host lifecycle.resetDevice() calls this automatically.
 */
export function clearDeviceIdCache(): void {
  cachedDeviceId = null;
}

/**
 * Preload device ID into cache
 *
 * Call this early in app initialization, so getDeviceIdSync() works correctly.
 *
 * @param vault - Local secret vault that holds the device ID
 */
export async function preloadDeviceId(
  vault: SignalProtocolLocalSecretVault,
  providedLogger?: Logger
): Promise<void> {
  await getDeviceId(requireSecretVault(vault, 'preloadDeviceId'), providedLogger);
}
