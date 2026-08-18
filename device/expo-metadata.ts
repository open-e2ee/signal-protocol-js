/**
 * Local device metadata, read from Expo and React Native.
 *
 * Split out of `./provisioning` because it was the only thing there that needed
 * a platform. Provisioning is a protocol: ephemeral ECDH, an encrypted
 * payload, and a server-side link. It takes the device's description as a
 * parameter. A static `import` of `react-native` in that module made the whole
 * handshake unimportable in Node and in the browser. Three fields were the
 * reason.
 *
 * Callers on a platform this package cannot see build `LocalDeviceMetadata`
 * themselves. Callers on Expo use this.
 */

import { Platform } from 'react-native';
import Constants from 'expo-constants';
import type { LocalDeviceMetadata } from './provisioning';

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
