# Encrypted exchange on Expo and Hermes

Run Alice and Bob inside an Expo application. Alice stores her identity and sessions in SQLCipher. Bob and the relay use memory.

The app sends your message, decrypts it on Bob, and sends an encrypted reply to Alice. The screen and console show the actual output.

## Requirements

Use Node.js 20.19 or later and Expo SDK 55. This example pins React Native 0.83 and uses Hermes.

For iOS, install Xcode and CocoaPods on macOS. For Android, install Android Studio, the Android SDK, and JDK 17. See [Expo local development](https://docs.expo.dev/guides/local-app-development/).

SQLCipher requires a native build. This example does not run in Expo Go. The protocol code is Pure TypeScript. Native Expo modules provide secure randomness and encrypted storage.

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

The output must identify `Hermes: true` and a SQLCipher version. A completed run ends with:

```text
alice decrypted: Received: hello from Hermes
Alice identity and session state remain in SQLCipher. Close and reopen the app to check persistence.
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

[app.json](./app.json) enables SQLCipher. [storage.ts](./storage.ts) gets the database key from Expo SecureStore and applies it before schema access. It requires a SQLCipher version before it opens the SDK store.

The app applies the committed Drizzle migrations at startup. To regenerate them after a schema change:

```sh
npm run db:generate
```

Read [exchange.ts](./exchange.ts) for the public SDK calls. Use the [Expo integration guide](https://docs.open-e2ee.dev/start/expo) to add the SDK to your app.

For separate devices, supply an authenticated relay adapter or use [OpenE2EE Relay](https://open-e2ee.dev/relay). The relay never needs message plaintext or device private keys.
