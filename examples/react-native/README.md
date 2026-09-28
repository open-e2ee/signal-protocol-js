# Encrypted exchange on bare React Native and Hermes

Run Alice and Bob inside a React Native app that has no Expo module. Alice stores her identity and sessions in the SDK's SQLite store on op-sqlite. SQLCipher encrypts the database file, and the keychain holds its key. Bob and the relay use memory.

The app sends your message, decrypts it on Bob, and sends an encrypted reply to Alice. The screen and console show the actual output.

## Requirements

Use Node.js 22.13 or later. This example pins React Native 0.87.1, which runs Hermes V1 on the New Architecture. The [README](../../README.md#use-your-apps-storage-and-relay) lists the supported React Native versions.

For Android, install Android Studio, the Android SDK, and JDK 17. For iOS, install Xcode and CocoaPods on macOS. See [Set up your environment](https://reactnative.dev/docs/set-up-your-environment).

The protocol code is pure TypeScript. [index.js](./index.js) loads `react-native-get-random-values` first, which gives the SDK its global random source. Every dependency is pinned to an exact version.

| Package | Version | Role |
|---|---|---|
| `react-native` | 0.87.1 | App runtime, Hermes V1 |
| `@op-engineering/op-sqlite` | 18.2.5 | SQLite engine, built with SQLCipher |
| `react-native-keychain` | 10.0.0 | Keychain and Keystore for the database key |
| `react-native-get-random-values` | 2.0.0 | Global `crypto.getRandomValues` |

## Run

From this directory:

```sh
npm ci
npm run android
```

For iOS:

```sh
cd ios && pod install && cd ..
npm run ios
```

The app starts on launch. It logs the global names of the runtime, checks the database encryption, and then runs the exchange. The first run generates keys and can take longer than later runs. Wait for both decrypted messages.

The output must identify `Hermes: true`. Each run also logs `SQLCipher version:`, `SDK database header:` (the first 16 bytes of the SDK database file in hex), and a `Wrong key:` line. The run fails when the build has no SQLCipher, when the file starts with the plaintext SQLite header `SQLite format 3\0`, or when a wrong key opens an SDK database. A completed run ends with:

```text
alice decrypted: Received: hello from Hermes
Alice identity and session state remain in the SQLite store. Close and reopen the app to check persistence.
PASS: both devices decrypted the expected messages.
```

Close the app process and reopen it. The next run must report `Resumed Alice identity` and complete another exchange. It compares Alice’s stored public identity with the previous run before it sends anything.

Each run creates a new Bob identity. The relay is local to this app. This example does not connect two phones.

## Release builds

```sh
npm run android -- --mode release
npm run ios -- --mode Release
```

These commands build the JavaScript bundle into the native app. Metro is not required at runtime. The Android release build signs with the debug key that the Android Gradle Plugin creates. Use your own key for a production app.

## Storage setup

[alice.ts](./alice.ts) opens Alice's store with one call, as the [React Native SQLite store guide](../../local/store/react-native/README.md) shows:

```ts
const store = await reactNativeStore();
```

On first use, the store creates a 32-byte database key in `react-native-keychain` and then creates the database file. The SDK owns that file and its tables. The example keeps its own run counters in a separate op-sqlite file.

The store needs the op-sqlite SQLCipher build. [package.json](./package.json) turns it on:

```json
"op-sqlite": {
  "sqlcipher": true
}
```

After you change that flag, run `pod install` again and rebuild the app. With SQLCipher on, op-sqlite conflicts on iOS with `expo-sqlite`, `expo-updates`, and `use_frameworks!`. The store guide describes each conflict.

[encryption.ts](./encryption.ts) shows the encryption on the device. It reads the SQLCipher version on an unkeyed connection and the first bytes of the SDK database file. It also creates a separate database with a key in memory, changes the key, and requires the next open to fail.

Read [exchange.ts](./exchange.ts) for the public SDK calls.

For separate devices, supply an authenticated relay adapter or use [OpenE2EE Signal Protocol Relay](https://open-e2ee.dev/relay). The relay never needs message plaintext or device private keys.
