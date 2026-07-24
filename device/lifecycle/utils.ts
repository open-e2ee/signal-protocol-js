/**
 * Device Lifecycle Utilities
 *
 * Helper functions for device metadata management.
 */

import { Platform } from 'react-native';
import * as Device from 'expo-device';
import RNDeviceInfo from 'react-native-device-info';
import type { DeviceInfo, DeviceMetadata } from './types';

/**
 * Get current device metadata from system APIs.
 *
 * @returns Current device metadata
 */
export {};
export async function getLocalDeviceMetadata(): Promise<DeviceMetadata> {
  const metadata: DeviceMetadata = {
    platform: Platform.OS,
    osVersion: Device.osVersion ?? undefined,
  };

  try {
    metadata.idfv = await RNDeviceInfo.getUniqueId();
  } catch {
    // Non-fatal - IDFV may not be available on all platforms
  }

  try {
    metadata.appVersion = RNDeviceInfo.getVersion();
  } catch {
    // Non-fatal - app version is optional
  }

  return metadata;
}

/**
 * Compute which metadata fields are missing from a device record.
 * Only returns fields that need to be sent in a heartbeat.
 *
 * @param serverDevice - Device record from server (from getDevices query)
 * @param localMetadata - Current device metadata (from getLocalDeviceMetadata)
 * @returns Metadata object with only missing/outdated fields, or undefined if nothing to update
 *
 * @example
 * ```typescript
 * const devices = await relay.getDevices(userId);
 * const myDevice = devices.find(d => d.deviceId === deviceId);
 * const localMeta = await getLocalDeviceMetadata();
 * const missingMeta = getMissingMetadata(myDevice, localMeta);
 *
 * if (missingMeta) {
 *   await relay.heartbeat(userId, deviceId, missingMeta);
 * } else {
 *   await relay.heartbeat(userId, deviceId); // No metadata needed
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

  // IDFV: only send if server doesn't have it
  if (!serverDevice.idfv && localMetadata.idfv) {
    missing.idfv = localMetadata.idfv;
    hasMissing = true;
  }

  // Platform: only send if server doesn't have it
  if (!serverDevice.platform && localMetadata.platform) {
    missing.platform = localMetadata.platform;
    hasMissing = true;
  }

  // OS Version: only send if server doesn't have it
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
