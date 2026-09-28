# Encrypted exchange on Expo and Hermes

Run Alice and Bob inside an Expo application. Alice stores her identity and sessions in the SDK-owned SQLite database. Bob and the relay use memory.

The app sends your message, decrypts it on Bob, and sends an encrypted reply to Alice. The screen and console show the actual output.

## Requirements

Use Node.js 22.13 or later and Expo SDK 57. This example pins React Native 0.86, which runs Hermes V1 on the New Architecture. The SDK also supports earlier lines back to Expo SDK 55. The [README](../../README.md#use-your-apps-storage-and-relay) lists the supported versions.

For iOS, install Xcode 26.4 or later and CocoaPods on macOS. For Android, install Android Studio, the Android SDK, and JDK 17. See [Expo local development](https://docs.expo.dev/guides/local-app-development/).

SQLCipher requires a native build. This example does not run in Expo Go. The protocol code is Pure TypeScript. `index.ts` loads `react-native-get-random-values` first, which gives the SDK its global random source. Native Expo modules provide encrypted storage.

## Run

From this directory:

```sh
npm ci
npx expo run:ios
```

For Android:

```sh
npx expo run:android
```

The app starts an exchange on launch. The first run generates keys and can take longer than later runs. Wait for both decrypted messages.

The output must identify `Hermes: true`. Each run also logs `SQLCipher version:` and `SDK database header:`, the first 16 bytes of the SDK database file in hex. The run fails when the build has no SQLCipher, or when the file starts with the plaintext SQLite header `SQLite format 3\0`. A completed run ends with:

```text
alice decrypted: Received: hello from Hermes
Alice identity and session state remain in the device-local store. Close and reopen the app to check persistence.
PASS: both devices decrypted the expected messages.
```

Close the app process and reopen it. The next run must report `Resumed Alice identity` and complete another exchange. It compares Alice’s stored public identity with the previous run before it sends anything.

Each run creates a new Bob identity. The relay is local to this app. This example does not connect two phones.

## Release builds

```sh
npx expo run:ios --configuration Release
npx expo run:android --variant release
```

These commands build the JavaScript bundle into the native app. Metro is not required at runtime. See [Expo’s Hermes guide](https://docs.expo.dev/guides/using-hermes/).

## Storage setup

[app.json](./app.json) enables SQLCipher. [storage.ts](./storage.ts) opens the store with one call, `await expoStore()`. The SDK owns the database file: it keeps the database key in Expo SecureStore, applies the key, and applies its own migrations. The app has no SDK schema or migration code.

The example keeps its run counters in a separate file, `opene2ee-example-state.db`. Keep your own tables out of the SDK database.

Read [exchange.ts](./exchange.ts) for the public SDK calls. Use the [Expo integration guide](https://docs.open-e2ee.dev/start/expo) to add the SDK to your app.

For separate devices, supply an authenticated relay adapter or use [OpenE2EE Signal Protocol Relay](https://open-e2ee.dev/relay). The relay never needs message plaintext or device private keys.
