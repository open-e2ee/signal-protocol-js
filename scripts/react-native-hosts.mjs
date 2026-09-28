/*
 * The React Native and Expo release lines that the SDK claims to support.
 *
 * The Expo lines use the module versions that each Expo SDK's
 * bundledNativeModules.json names, which is what `npx expo install` writes.
 * The floor lines match the lowest versions in the SDK's peer ranges.
 */

export const expoLines = {
  55: {
    expo: '~55.0.31',
    'expo-constants': '~55.0.17',
    'expo-device': '~55.0.21',
    'expo-file-system': '~55.0.26',
    'expo-secure-store': '~55.0.18',
    'expo-sqlite': '~55.0.20',
    react: '19.2.0',
    'react-native': '0.83.10',
  },
  56: {
    expo: '~56.0.22',
    'expo-constants': '~56.0.26',
    'expo-device': '~56.0.4',
    'expo-file-system': '~56.0.11',
    'expo-secure-store': '~56.0.4',
    'expo-sqlite': '~56.0.6',
    react: '19.2.3',
    'react-native': '0.85.3',
  },
  57: {
    expo: '~57.0.25',
    'expo-constants': '~57.0.19',
    'expo-device': '~57.0.2',
    'expo-file-system': '~57.0.7',
    'expo-secure-store': '~57.0.4',
    'expo-sqlite': '~57.0.3',
    react: '19.2.3',
    'react-native': '0.86.3',
  },
};

const expo55Floor = {
  expo: '55.0.27',
  'expo-constants': '55.0.7',
  'expo-device': '55.0.15',
  'expo-secure-store': '55.0.15',
  'expo-sqlite': '55.0.17',
  react: '19.2.0',
  'react-native': '0.83.6',
};

/**
 * Host projects for the install gate. A host with `expectConflict` is outside
 * the supported range, and npm must refuse the SDK on that peer.
 */
export const installHosts = [
  { name: 'React Native 0.83.6 (floor)', dependencies: { react: '19.2.0', 'react-native': '0.83.6' } },
  { name: 'React Native 0.85', dependencies: { react: '19.2.3', 'react-native': '~0.85.3' } },
  { name: 'React Native 0.86', dependencies: { react: '19.2.3', 'react-native': '~0.86.3' } },
  { name: 'React Native 0.87', dependencies: { react: '19.2.3', 'react-native': '~0.87.1' } },
  { name: 'Expo SDK 55 (floor)', dependencies: expo55Floor },
  { name: 'Expo SDK 55', dependencies: expoLines[55] },
  { name: 'Expo SDK 56', dependencies: expoLines[56] },
  { name: 'Expo SDK 57', dependencies: expoLines[57] },
  {
    name: 'React Native 0.82 (below the floor)',
    dependencies: { react: '19.1.1', 'react-native': '~0.82.1' },
    expectConflict: 'react-native',
  },
];
