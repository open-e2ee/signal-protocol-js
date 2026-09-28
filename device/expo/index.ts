/**
 * Local device metadata, read from Expo and React Native.
 *
 * The shared `./device` entry reads no platform API: provisioning, transfer,
 * and the device lifecycle take the device's description as a parameter. This
 * entry reads it on Expo, through `expo-constants`, `expo-device`, and the
 * React Native `Platform`. Bare React Native apps use `./device/react-native`.
 * Callers on a platform this package cannot see build the metadata themselves.
 *
 * Expo exposes no device fingerprint without another package, so
 * `getDeviceLifecyclePlatform()` omits `getDeviceFingerprint`. Supply one to
 * enable reclaim detection.
 */

import { Platform } from 'react-native';
import Constants from 'expo-constants';
import * as Device from 'expo-device';
import type { LocalDeviceMetadata } from '../provisioning';
import type { TransferDeviceInfo } from '../types';
import type { DeviceLifecyclePlatform } from '../lifecycle/types';

export {};

/**
 * Describe the device that runs this code, for device linking.
 *
 * The device name stays local until provisioning delivers the account
 * identity key needed to encrypt it for server storage. That is why it is
 * passed in rather than read from the platform. The name is the user's choice,
 * not a property of the hardware.
 *
 * @param deviceName - Human-readable device name chosen on the new device
 * @returns Local device metadata, ready to hand to `connectToProvisioningSession`
 */
export function getDeviceMetadata(deviceName: string): LocalDeviceMetadata {
  return {
    deviceName,
    platform: Platform.OS,
    appVersion: Constants.expoConfig?.version ?? 'unknown',
    osVersion: Platform.Version.toString(),
  };
}

/**
 * Describe the device that runs this code, for a transfer QR code and a
 * linked-device bundle.
 *
 * @returns Transfer device metadata; an absent app version is omitted
 */
export function getTransferDeviceInfo(): TransferDeviceInfo {
  const appVersion = Constants.expoConfig?.version;
  return {
    ...(Platform.OS === 'ios' || Platform.OS === 'android' ? { platform: Platform.OS } : {}),
    osVersion: Platform.Version.toString(),
    ...(appVersion ? { appVersion } : {}),
  };
}

/**
 * Describe the device that runs this code, for `DeviceLifecycleManager`.
 *
 * Spread the result into the manager's dependencies.
 *
 * @returns Device lifecycle facts; each absent fact is omitted
 */
export function getDeviceLifecyclePlatform(): DeviceLifecyclePlatform {
  const appVersion = Constants.expoConfig?.version;
  const osVersion = Device.osVersion;
  return {
    generateDeviceName,
    deviceType:
      Device.deviceType === Device.DeviceType.TABLET
        ? 'tablet'
        : Device.deviceType === Device.DeviceType.DESKTOP
          ? 'desktop'
          : 'mobile',
    platform: Platform.OS,
    ...(osVersion ? { osVersion } : {}),
    ...(appVersion ? { appVersion } : {}),
  };
}

function generateDeviceName(): string {
  const modelName = Device.modelName || 'Unknown Device';
  switch (Device.deviceType) {
    case Device.DeviceType.PHONE:
      return modelName;
    case Device.DeviceType.TABLET:
      return `${modelName} (Tablet)`;
    case Device.DeviceType.DESKTOP:
      return `${modelName} (Desktop)`;
    default:
      return `${Platform.OS === 'ios' ? 'iPhone' : 'Android'} Device`;
  }
}
