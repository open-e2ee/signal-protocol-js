/**
 * Device Lifecycle Utilities
 *
 * Helper functions for device metadata management.
 */

import type { DeviceInfo, DeviceLifecyclePlatform, DeviceMetadata } from './types';

/**
 * Get current device metadata from the facts that the application passes.
 *
 * Each absent fact is omitted.
 *
 * @param device - Local device facts, such as `getDeviceLifecyclePlatform()`
 *   from `./device/expo` or `./device/react-native`
 * @returns Current device metadata
 */
export {};
export async function getLocalDeviceMetadata(
  device: DeviceLifecyclePlatform
): Promise<DeviceMetadata> {
  const metadata: DeviceMetadata = {};
  if (device.platform) metadata.platform = device.platform;
  if (device.osVersion) metadata.osVersion = device.osVersion;
  if (device.appVersion) metadata.appVersion = device.appVersion;

  try {
    const idfv = await device.getDeviceFingerprint?.();
    if (idfv) metadata.idfv = idfv;
  } catch {
    // Non-fatal - IDFV may not be available on all platforms
  }

  return metadata;
}

/**
 * Compute which metadata fields a device record lacks.
 * Only returns fields the server record lacks.
 *
 * @param serverDevice - Device record from server (from getDevices query)
 * @param localMetadata - Current device metadata (from getLocalDeviceMetadata)
 * @returns Metadata object with only missing/outdated fields, or undefined if nothing to update
 *
 * @example
 * ```typescript
 * const devices = await relay.getDevices(userId);
 * const myDevice = devices.find(d => d.deviceId === deviceId);
 * const localMeta = await getLocalDeviceMetadata(getDeviceLifecyclePlatform());
 * const missingMeta = getMissingMetadata(myDevice, localMeta);
 *
 * if (missingMeta) {
 *   await backfillDeviceMetadata(deviceId, missingMeta);
 * }
 * ```
 */
export function getMissingMetadata(
  serverDevice: DeviceInfo | undefined,
  localMetadata: DeviceMetadata
): DeviceMetadata | undefined {
  if (!serverDevice) {
    // Device not found on server - send all metadata
    return localMetadata;
  }

  const missing: DeviceMetadata = {};
  let hasMissing = false;

  // IDFV: only send if server does not have it
  if (!serverDevice.idfv && localMetadata.idfv) {
    missing.idfv = localMetadata.idfv;
    hasMissing = true;
  }

  // Platform: only send if server does not have it
  if (!serverDevice.platform && localMetadata.platform) {
    missing.platform = localMetadata.platform;
    hasMissing = true;
  }

  // OS Version: only send if server does not have it
  if (!serverDevice.osVersion && localMetadata.osVersion) {
    missing.osVersion = localMetadata.osVersion;
    hasMissing = true;
  }

  // App Version: always send if different (tracks upgrades)
  if (localMetadata.appVersion && serverDevice.appVersion !== localMetadata.appVersion) {
    missing.appVersion = localMetadata.appVersion;
    hasMissing = true;
  }

  return hasMissing ? missing : undefined;
}
