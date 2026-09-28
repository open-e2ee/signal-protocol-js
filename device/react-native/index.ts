/**
 * Local device metadata, read from bare React Native.
 *
 * The shared `./device` entry reads no platform API: provisioning, transfer,
 * and the device lifecycle take the device's description as a parameter. This
 * entry reads it on bare React Native, through `react-native-device-info` and
 * the React Native `Platform`. It reaches no Expo package. Expo apps use
 * `./device/expo`.
 */

import { Platform } from 'react-native';
import DeviceInfo from 'react-native-device-info';
import type { LocalDeviceMetadata } from '../provisioning';
import type { TransferDeviceInfo } from '../types';
import type { DeviceLifecyclePlatform } from '../lifecycle/types';

export {};

/**
 * Describe the device that runs this code, for device linking.
 *
 * The device name is the user's choice, not a property of the hardware, so it
 * is passed in.
 *
 * @param deviceName - Human-readable device name chosen on the new device
 * @returns Local device metadata, ready to hand to `connectToProvisioningSession`
 */
export function getDeviceMetadata(deviceName: string): LocalDeviceMetadata {
  return {
    deviceName,
    platform: Platform.OS,
    appVersion: DeviceInfo.getVersion(),
    osVersion: DeviceInfo.getSystemVersion(),
  };
}

/**
 * Describe the device that runs this code, for a transfer QR code and a
 * linked-device bundle.
 *
 * @returns Transfer device metadata
 */
export function getTransferDeviceInfo(): TransferDeviceInfo {
  return {
    ...(Platform.OS === 'ios' || Platform.OS === 'android' ? { platform: Platform.OS } : {}),
    osVersion: DeviceInfo.getSystemVersion(),
    appVersion: DeviceInfo.getVersion(),
  };
}

/**
 * Describe the device that runs this code, for `DeviceLifecycleManager`.
 *
 * Spread the result into the manager's dependencies. The fingerprint is
 * `getUniqueId()`: IDFV on iOS, Android ID on Android.
 *
 * @returns Device lifecycle facts
 */
export function getDeviceLifecyclePlatform(): DeviceLifecyclePlatform {
  const deviceType = DeviceInfo.getDeviceType();
  return {
    generateDeviceName: () => generateDeviceName(deviceType),
    getDeviceFingerprint: () => DeviceInfo.getUniqueId(),
    deviceType: deviceType === 'Tablet' ? 'tablet' : deviceType === 'Desktop' ? 'desktop' : 'mobile',
    platform: Platform.OS,
    osVersion: DeviceInfo.getSystemVersion(),
    appVersion: DeviceInfo.getVersion(),
  };
}

function generateDeviceName(deviceType: string): string {
  const modelName = DeviceInfo.getModel() || 'Unknown Device';
  switch (deviceType) {
    case 'Handset':
      return modelName;
    case 'Tablet':
      return `${modelName} (Tablet)`;
    case 'Desktop':
      return `${modelName} (Desktop)`;
    default:
      return `${Platform.OS === 'ios' ? 'iPhone' : 'Android'} Device`;
  }
}
