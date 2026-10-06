# Assurance

The Signal Protocol SDK is open source under the MIT License or the Apache License 2.0, at your option. Its engineering tests remain private. We do not publish those tests or their private fixtures and comparison material.

This document states our testing methods, reported results, public checks, and review limits.

## What is public

The public repository contains SDK client source, documentation, and build checks. An export tool copies approved files from the engineering repository. It excludes private engineering material and its development dependencies.

You can inspect the client implementation and run the public checks. Relay server implementations and the internal runtime examples remain private. You cannot reproduce the private results from this repository alone.

Private testing also exists in other open-source projects. [SQLite publishes some checks and keeps TH3 private](https://www.sqlite.org/testing.html). [Convex documents a private testing framework](https://github.com/get-convex/convex-backend#readme). Those projects do not review or endorse this SDK.

## Reported engineering results

Engineering CI runs the default automated checks on pull requests that are ready for review and on changes to the main branch. Release preparation requires a passing run.

Most recent full run on 2026-10-06:

| | |
|---|---|
| Test modules | 496 |
| Test cases | 9,214 |
| Passed | 9,210 |
| Skipped | 4 |
| Failed | 0 |
| Wall time | 153 s |

The total counts test cases. One test case can contain several assertions. Separate commands run the longer performance and endurance checks.

Release tooling generates this table from a completed run. It refuses results from a failing run. The release gate rejects figures older than three days.

## Testing methods

- **Known answers:** compare cryptographic outputs with published reference data for ML-KEM, hashes, authenticated encryption, and signatures.
- **Protocol behavior:** check PQXDH, Double Ratchet, SPQR, and ML-KEM Braid state changes. Cover replay rejection, reordered messages, skipped-key limits, and required post-quantum operations.
- **Generated inputs:** check protocol and encoding properties across randomized inputs.
- **Messaging flows:** exercise device fanout, groups, device linking, provisioning, PNI-to-ACI changes, and relay delivery.
- **Storage contracts:** check persistence, concurrency, interruption, recovery, and storage pressure at adapter boundaries.
- **Runtime behavior:** run the browser storage contracts in Chromium, Firefox, and WebKit. Run each public flow on the Hermes V1 command-line engine that React Native 0.86 uses, with only the globals of a bare React Native app. A committed list records each flow step that fails on that engine and its error. The job fails when a result differs from that list. Run release builds of the Expo example and the bare React Native example on an Android emulator. Both use Hermes V1. The Expo build uses Expo SDK 57 and React Native 0.86, and the bare build uses React Native 0.87.1.
- **Public API:** check exported types, import paths, documented calls, and expected example output against the packed package.
- **React Native hosts:** add the packed package to React Native and Expo projects without an override of peer conflicts. The projects cover React Native 0.83 through 0.87 and the Expo SDK 55 through 57 lines. Build the Expo example's Hermes bundle on Expo SDK 55 and 57.
- **Errors:** check construction sites for exported error classes and codes. Reject unresolved code forwarding.

The browser storage job also runs 2,000 open, write, read, and close cycles of the IndexedDB store, and a soak of the web SQLite store. Each checks for upward memory and latency drift.

In Chromium, the browser storage job also builds an app with the Vite version of the browser example and the packed package. The entry module of the app completes an exchange in each direction with a top-level await. The job fails when the exchange does not finish in 30 seconds, or when a chunk of the build imports the entry chunk. A default automated check also fails when the SDK loads a module with a dynamic import and that module imports another module. Other bundlers are not checked.

A storage contract check does not prove a full encrypted exchange. Internal browser and Expo examples exercise message encryption, delivery, and decryption.

## SQLite store checks

Four package entries keep device-local state in a SQLite database: `./local/store/node`, `./local/store/expo`, `./local/store/react-native`, and `./local/store/web-sqlite`. A Tauri app uses `./local/store/web-sqlite`. Each row gives one runtime claim and the check that proves it. Rows that do not name public CI run in the project's engineering CI. A check runs on each change to the main branch and on each pull request that is ready for review, unless its row says otherwise. On a pull request, a job on macOS or Windows runs only when a maintainer requests it. Without that request, a pull request runs the Node store job only on Linux with Node 22, and the default automated checks run its tests on Linux with Node 26.

### Node and the Electron main process: `./local/store/node`

| Claim | Check | What the check runs |
|---|---|---|
| The store passes the shared storage contract on an encrypted file. | Default automated checks: Linux, Node 26 | The storage contract on `nodeStore` and the `better-sqlite3-multiple-ciphers` binding. |
| The driver writes SQLCipher 4 files. An encrypted file has no SQLite header, and a wrong key fails with a typed error. | Node store job: Linux, macOS, and Windows, each with Node 22 and Node 26 | Real files on the prebuilt binding. |
| Without `encryptionAtRest: false`, the store refuses a binding that has no cipher. The store refuses a file that has the other encryption setting. | Node store job: the same six runners | Real files on the prebuilt binding. |
| The store writes its key to the vault before it creates the file. A file without a key fails as a lost key and does not change. | Node store job: the same six runners | Real files and a vault. |
| One process at a time owns a store. After the owner process is killed, the next open succeeds and reads the committed data. | Node store job: the same six runners | A child process holds the store. The parent process tries to open it, then kills the child and opens it. |
| Every part of the store interface survives a close and a new open of the directory. | Node store job: the same six runners | Real files on the prebuilt binding. |
| In the Electron main process, the store passes the shared storage contract with its key in the real `safeStorage`. The file has no SQLite header, and the vault file keeps only a ciphertext of the key. | Electron store job: Electron 44 on Linux, macOS, and Windows, and Electron 42 on Linux | Electron from its npm package, with the GNOME keyring through libsecret on Linux, the Keychain on macOS, and DPAPI on Windows. A push to the main branch or a pull request runs this job only when it changes the store, the vault, the storage contract, the job, or a dependency. |
| In an app that Electron Forge packages with ASAR, the store opens in the main process and in a utility process with its key in the real `safeStorage`, and a value that one launch writes reads back after a relaunch. The binding loads from `app.asar.unpacked`, and the file has no SQLite header. | Electron package job: Linux x64, macOS arm64, and Windows x64 | `electron-forge package` with Electron Forge 7.11.2 of an app that installs the packed package, with the auto-unpack-natives plugin and the fuses that the [Node store guide](../local/store/node/README.md#packaging) gives. On macOS, the job signs the app ad hoc and requires `codesign --verify --deep --strict` to pass before the first launch. A push to the main branch or a pull request runs this job only when it changes the store, the vault, the packaged app, the job, or a dependency. |
| On Linux, the vault refuses the `basic_text` backend of `safeStorage`. The store does not open, and no key reaches the disk. | Electron store job: Linux, Electron 44 and 42 | Electron with `--password-store=basic`. |
| On Linux, the vault refuses the fixed fallback key that `safeStorage` uses when no secret service answers. The store does not open, and no key reaches the disk. | Electron store job: Linux, Electron 44 and 42 | Electron with `--password-store=gnome-libsecret` and no unlocked keyring on the D-Bus session. |
| On Linux, the store passes the shared storage contract with its key in KWallet, on the `kwallet5` and `kwallet6` backends of `safeStorage`. | Electron store job: Linux, Electron 44. KWallet 6 job: Ubuntu 26.04, Electron 44 | Electron with `--password-store=kwallet5` on KWallet 5, and with `--password-store=kwallet6` on KWallet 6.24. A new wallet opens with no prompt, through the `pamOpen` call that `pam_kwallet` makes at login. The test checks the backend that `safeStorage` selected, and the harness removes the key from the wallet. Run 36528132421 also passed `--password-store=kwallet5` on KWallet 6.24. No job runs that case again. |
| On Linux, with a running Secret portal and the default Chromium features, the store passes the shared storage contract. `safeStorage` does not use the key of the portal. | Electron store job: Linux, Electron 44 | Electron with `--password-store=gnome-libsecret`, and xdg-desktop-portal with the GNOME keyring as the back end of its Secret portal. |
| On Linux, the vault refuses the key of the Secret portal, which `safeStorage` uses with the Chromium feature `SecretPortalKeyProviderUseForEncryption`. The store does not open, and no key reaches the disk. | Electron store job: Linux, Electron 44 | Electron with that feature and a Secret portal, with the GNOME keyring as the back end of the portal. The test checks that the ciphertext starts with `v12`. Run 36528132421 also refused the key with KWallet 6 (`kwallet6`, Ubuntu 26.04) as the back end of the portal. No job runs that case again. |

No CI job signs the app with a Developer ID. On 2026-09-29, a manual check on macOS 15.7.2 arm64 with Xcode 26.3 built the packaged app twice from the main branch, as version 1.0.0 and version 1.0.1. The build used the SDK 8.1.0 package and Electron 44.4.5. Electron Forge signed each build with a Developer ID identity and the hardened runtime, and notarized and stapled it. For each build, `spctl -a -vv` reported `accepted` and `source=Notarized Developer ID`. A check script wrote a value with version 1.0.0 in the main process and in a utility process. Then it copied version 1.0.1 over the app, and the relaunches read each value back. The securityd log had no Keychain prompt for a launch. When the check copied an ad-hoc signed copy of version 1.0.1 over version 1.0.0, securityd logged a Keychain prompt for each read, and the check stopped the app. The access list of the Keychain item of the key holds the designated requirement of the app, which names the bundle identifier and the Developer ID team, not a code hash.

### Expo: `./local/store/expo`

| Claim | Check | What the check runs |
|---|---|---|
| The store passes the shared storage contract. | Default automated checks: Linux, Node 26 | The storage contract on the `expo-sqlite` JavaScript layer over `node:sqlite`. This check runs no native module and no SQLCipher. |
| A release build of the Expo example stores its state with SQLCipher on Android and keeps it across a process restart. | Android emulator job | A release APK on Hermes V1, run twice on an Android API 36 x86_64 emulator. Each run must log a SQLCipher version and a database header that is not the SQLite header. The second run must resume the stored identity and complete an exchange. This job runs on a change to the main branch that can reach the React Native runtime, and on demand. It does not run on a pull request. |
| The Expo example, which imports this entry, bundles with the Hermes compiler that React Native pins. | Engineering CI | The Android bundle of the Expo example with the packed package, on Expo SDK 55 and Expo SDK 57. |
| In an Expo web build, an encrypted open and a reset fail with `SqliteEncryptionUnavailableError` (`KEY_STORAGE_ERROR`) before they use the vault. With `encryptionAtRest: false`, the store opens and keeps its data across a page load. | Browser storage job: Chromium on Linux | An `expo export --platform web` of an Expo SDK 57 app that installs the packed package, loaded in Chromium. The page reads no `PRAGMA cipher_version` row, and Expo SecureStore reports that it is not available. The check does not open a store with `./local/store/web-sqlite` in the Expo web build. |

The Hermes flow job does not load a SQLite store. Its flows use the memory and key-value stores. The Android emulator job is the only CI job that runs the Expo store on Hermes.

### Bare React Native: `./local/store/react-native`

| Claim | Check | What the check runs |
|---|---|---|
| The store passes the shared storage contract on an encrypted file. | Default automated checks: Linux, Node 26 | The storage contract on `reactNativeStore` over a Node test double of op-sqlite. The double runs SQLite3 Multiple Ciphers in its SQLCipher 4 mode through the `better-sqlite3-multiple-ciphers` binding. |
| The first open writes a new 32-byte key to the keychain, with access after the first unlock on this device only. The file has no SQLite header, and that key opens it. A key that does not open the file fails with `KEY_STORAGE_ERROR`. | Default automated checks: Linux, Node 26 | The entry on the op-sqlite test double, with a test double of `react-native-keychain`. |
| A file without its key fails with `LOCAL_STORE_KEY_LOST` and does not change. A reset opens an empty store with a new key. | Default automated checks: Linux, Node 26 | The same test doubles. |
| Without `encryptionAtRest: false`, the store refuses an op-sqlite build without SQLCipher and creates no file. A plaintext file opened with encryption fails as a key mismatch and does not change. | Default automated checks: Linux, Node 26 | The same test doubles. The double answers as an op-sqlite build without SQLCipher. |
| Two parallel first opens of one name write one key, and the second open fails with `INVALID_STATE`. An open or a reset of a name that an open store holds fails with `INVALID_STATE`. | Default automated checks: Linux, Node 26 | The same test doubles. |
| A release build of the bare React Native example stores its state with SQLCipher on Android, with the default keychain vault, and keeps it across a process restart. A key that does not open the file fails with `KEY_STORAGE_ERROR`. | Android emulator job | A release APK on Hermes V1 with the native op-sqlite SQLCipher build, run twice on an Android API 36 x86_64 emulator. Each run must log a SQLCipher version, a database header that is not the SQLite header, and a wrong-key open that fails with `SqliteKeyMismatchError`. The second run must resume the stored identity and complete an exchange. This job runs on a change to the main branch that can reach the React Native runtime, and on demand. It does not run on a pull request. |
| The bare React Native example, which imports this entry, bundles with the Hermes compiler that React Native pins. | Engineering CI | The Android release bundle of the bare React Native example with the packed package. |

The Android emulator job is the only CI job that runs this store on Hermes with the native op-sqlite module. No CI job runs it on iOS. On 2026-09-28, a manual check of a development build of the SDK before 8.0.0 ran the bare React Native example in the iOS 26.2 simulator with Xcode 26.3. Each of four launches logged a SQLCipher version, a database header that is not the SQLite header, and the wrong-key failure. Each launch after the first resumed the stored identity.

On 2026-09-29, a manual check with Xcode 26.3 ran the release build of the example four times in the iOS 26.2 simulator. The check used the SDK 8.1.0 package built from the main branch. Each launch passed the same checks. A temporary native log in the app read the storage attributes. The example does not include this log:

- The keychain item of the database key has the accessibility class `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` (`cku`). The item does not synchronize. Its access control holds only that class. It has no user-presence flag, no biometric flag, and no token ID.
- The simulator reported no `NSFileProtectionKey` for the database file and its `-wal` and `-shm` files. The app also created a control file with `NSFileProtectionComplete`. The simulator reported no class for that file, so it does not keep the file class that an app requests. The store does not request a file class.

The simulator does not enforce Data Protection. These results do not show the protection on a device.

### Web: `./local/store/web-sqlite`

| Claim | Check | What the check runs |
|---|---|---|
| The store passes the shared storage contract in a real browser, with the Wasm engine in its worker and the file in the origin private file system (OPFS). | Browser storage job: Chromium and Firefox on Linux. WebKit store job: WebKit and Safari on macOS | The page has a Content Security Policy that adds only `'wasm-unsafe-eval'`. |
| An encrypted file keeps no plaintext in OPFS. A wrong key and no key cannot read it. The web driver reads a SQLCipher 4 file that the Node driver wrote. | Browser storage job: Chromium and Firefox on Linux. WebKit store job: WebKit and Safari on macOS | Real files in OPFS. |
| Two tabs share one file, and a tab hands it over only between transactions. A tab that dies in a transaction leaves the file readable without the writes of that transaction. | Browser storage job: Chromium and Firefox on Linux. WebKit store job: WebKit and Safari on macOS | Two real tabs of one origin. |
| Two tabs that open a new store at the same time write one key. A reset fails with `INVALID_STATE` while another tab has the store open. | Browser storage job: Chromium and Firefox on Linux. WebKit store job: WebKit and Safari on macOS | Two real tabs of one origin. |
| Without `'wasm-unsafe-eval'`, the open fails with `SQLITE_ENGINE_UNAVAILABLE` and writes no key. | Browser storage job: Chromium and Firefox on Linux. WebKit store job: WebKit and Safari on macOS | A page under a policy without `'wasm-unsafe-eval'`. |
| When the origin quota is full, a write and an atomic commit reject with `STORAGE_QUOTA_EXCEEDED` and leave no partial state. The store stays open, and after the clamp is removed, the same commit succeeds. A first open under a full quota rejects with `STORAGE_QUOTA_EXCEEDED`, writes no key and no database file, and succeeds after the clamp is removed. A store with two pool files opens, reads, and writes under a quota that has no room for a new pool. | Browser storage job: Chromium on Linux | A DevTools protocol call clamps the origin quota, and the store fills its real file in OPFS. Firefox and WebKit have no such call, so they do not run this check. |
| When a write of the engine fails with `QuotaExceededError`, the call fails with the SQLite full-disk error, which the store reports as `STORAGE_QUOTA_EXCEEDED`. The earlier rows stay, and after space frees, the same connection writes again and the file passes an integrity check. | Browser storage job: Chromium and Firefox on Linux. WebKit store job: WebKit and Safari on macOS | A fault in the worker makes each OPFS write that grows a file throw `QuotaExceededError`. It does not fill a real origin quota. |
| Over a long run, the store holds latency, memory, and file size flat. A closed store leaves no worker and no lock of the store. Two tabs that write in turn each read the last write of the other. | Browser storage job: Chromium on Linux | 150 open, write, read, and close cycles, one session of 2,000 churn operations over 250 sessions, and 100 writes that two tabs make in turn. The check compares the medians of the early and late thirds of the run. It reads the page heap, and the heap and Wasm memory of the store's worker, through the DevTools protocol. Firefox and WebKit have no such protocol in the test runner, and no CI job runs this check in them. |
| A worker without OPFS synchronous access handles fails with `OPFS_UNAVAILABLE` before it loads the engine. | Browser storage job: Chromium, Firefox, and WebKit on Linux | WebKit on Linux (WebKitGTK) has no OPFS synchronous access handles, so there WebKit runs only these checks and the checks that need no OPFS. |

The WebKit store job runs Playwright's WebKit on macOS, where WebKit has OPFS synchronous access handles. Playwright's WebKit is not Safari, so the same job then runs the same checks in the Safari of the macOS runner through `safaridriver`, and records the Safari version. A WebDriver runner runs the Playwright checks unchanged. It counts the workers of a page from inside the page, and it reports the uncaught errors of a page only after the page loads. Each browser context is a Safari WebDriver session, so the check for an ephemeral context that refuses OPFS access handles skips when that session has them. It runs only on a change to the web SQLite store, the SQLite core, the storage contract, the key vault, the job, or a dependency. On a pull request, it runs only when a maintainer requests it. In the browser storage job for Chromium and Firefox and in the WebKit store job, a check that skips for want of OPFS fails.

The internal code-generation check runs an encrypted exchange with the memory store. It does not load a SQLite store.

### Tauri

| Claim | Check | What the check runs |
|---|---|---|
| In a Tauri 2.12.0 app on Windows, the store opens in WebView2 with the default IndexedDB vault. Two new stores exchange one message each way. A second open of an open store fails with `INVALID_STATE`. After a close and a reopen, each store keeps its state and exchanges again. A relaunch in a new process reads the final state of the first launch and exchanges again. | Tauri example job: Windows x64, WebView2 153.0.4234.48 | A debug build of a Tauri example app that installs the packed package, launched twice. The app has no bundle and no installer. The app reports each step to its shell, and the job fails unless every step passes. A push to the main branch or a pull request runs this job only when it changes the example, the web SQLite entry, the web SQLite driver, or the job. On a pull request, the Windows leg runs only when a maintainer requests it. |
| In a Tauri 2.12.0 app on Linux, the first open fails with `OPFS_UNAVAILABLE`, because WebKitGTK has no OPFS synchronous access handles. No other step of the check runs. | Tauri example job: Linux x64, WebKitGTK 2.52.6 | The same app under Xvfb. The job fails when the first open succeeds or fails with a different code. |
| In a Tauri 2.12.0 app on Android, the store opens in the Android WebView with the default IndexedDB vault. Every step of the Windows check passes, including the relaunch in a new process. | Tauri example job: Android API 36 x86_64 emulator, Android WebView 133.0.6943.137 | A debug APK of the same app, installed on the emulator and launched twice. The app writes its report to its data directory, and the job reads the report with `adb`. The job fails unless every step passes. On a pull request, the Android leg runs only when a maintainer requests it. |

A Tauri 2 app uses `./local/store/web-sqlite` in its webview, with no Tauri-specific SDK code. The [web SQLite store guide](../local/store/web-sqlite/README.md#tauri) gives the Tauri setup. On 2026-09-28, a manual check of a development build of the SDK before 8.0.0, in a Tauri 2.12.0 app, passed in WKWebView on macOS 15.7.2 and in the iOS 18.0 simulator. The check covered a two-device exchange, a close and reopen, an app relaunch, a relaunch after the app was killed with both stores open, and the store locks.

On 2026-09-29, a manual check ran a debug build of the Tauri example with Tauri 2.12.0 in its shell. The app installed SDK 8.1.0, packed from the same commit as the example. On macOS 15.7.2 and in the iOS 17.5 simulator, every step of the first launch and of the relaunch passed. On macOS, two windows of the app shared one store. The second window opened the store that the first window held, and each window read the writes of the other. A reset in the second window failed with `INVALID_STATE`.

In the same check, `navigator.storage.persist()` returned `false` on macOS and in the iOS simulator. The app then cleared all website data of its webview, which removed the database file and the vault key. The next launch opened a new, empty store with no error.

### UNVERIFIED

No CI job checks these items:

- **A full origin quota in Firefox, WebKit, and Safari.** In these browsers, the quota check injects `QuotaExceededError` in the worker. No check fills a real origin quota there.
- **Tauri on macOS and iOS.** No CI job runs the Tauri example on macOS or iOS. The manual checks ran a debug build on macOS 15.7.2 and in the iOS 17.5 and 18.0 simulators. No check ran the store in a Tauri app on a physical iOS device.
- **A Tauri store that WebKit removes.** A check cleared all website data of the webview with a Tauri call. No check saw WebKit remove the data under storage pressure or after a period without use. No check removed the IndexedDB vault of a Tauri app while its database file stayed.
- **A Tauri release build, and Tauri on physical Android devices.** The Tauri example job runs a debug build with no bundle on Windows and Linux, and a debug APK on an Android API 36 emulator. No check ran the store in a release build, in an installed desktop app, on another Android API level, or on a physical Android device.
- **The React Native store on iOS and on physical devices.** No CI job opens `./local/store/react-native` on iOS. The manual checks used only the iOS simulator. No check ran the store on a physical Android or iOS device.
- **iOS devices.** No CI job runs on iOS. The manual checks used only the iOS simulator.
- **iOS Data Protection.** The simulator does not keep a file protection class. So no check recorded the class of the React Native store files. No check observed a file class or the keychain class enforced on a locked device.
- **An update of a notarized macOS Electron build through an updater.** The manual check copies the new build over the app. No check installed an update through Squirrel.Mac or another updater, or ran a notarized build on an Intel Mac.
- **Electron in a Flatpak or Snap sandbox.** There, the Secret portal gives each app its own key. No check ran it, and the vault refuses the portal key there too.
- **The `kwallet` backend (KWallet 4).** Ubuntu 24.04 and 26.04 do not have KWallet 4.
- **A KWallet wallet that the user opens.** The check opens a new wallet with `pamOpen`. No check opened a wallet at a password prompt or with `pam_kwallet` at login.

## Realm backend: `./local/store/key-value/realm`

| Claim | Check | What the check runs |
|---|---|---|
| The Realm backend passes the key-value backend-conformance kit, including a close and a new open of the same Realm file. | Default automated checks: Linux, Node 26 | The kit on realm 20.2.0 in Node, over real Realm files. |

No CI job runs the Realm backend in a React Native app. On 2026-09-29, a manual check with Xcode 26.3 ran the kit on realm 20.2.0 in the iOS 26.2 simulator. The kit ran in a release build of the bare React Native example, with the SDK 8.1.0 package built from the main branch. All 13 cases passed on each of two launches. The SQLite store of the example passed in the same process. A build in which the backend skipped one write failed 7 of the 13 cases.

On 2026-09-28, a manual check ran the same kit in an Android emulator, and all 13 cases passed. No check ran the Realm backend on a physical device.

## Runtime checks for 2.0.1

On 2026-09-12, the browser example completed encrypted exchanges in Chromium, Firefox, and WebKit. Nine checks covered fresh messages, replies, repeated runs, cancellation, reset, and worker-load errors under CSP.

The Expo example completed encrypted exchanges in development and release builds on Hermes. The checked targets were the iOS 26.1 simulator and Android 15 emulator, using Expo 55 and React Native 0.83.10.

Both platforms used SQLCipher 4.7.0. After a process restart, Alice retained her identity and completed another exchange. Release builds ran with Metro stopped. These results establish behavior on the listed targets, not device performance.

These application checks are separate from the recurring browser-storage and Hermes flow jobs.

## Review status

> Reviewed continuously by adversarial AI agents; not audited by any independent firm.

Our review policy requires adversarial AI review before substantive code changes merge. Recurring reviews inspect the engineering repository. We keep the review transcripts private.

This statement describes our process. It is not an independent security assessment. OpenE2EE has no audit engagement with an independent firm.

## Checks you can run

[Public CI](https://github.com/open-e2ee/signal-protocol-js/actions/workflows/ci.yml) runs on pushes and pull requests. On a draft pull request, it runs only the first two checks. Its logs show these checks:

- Install from the committed lockfile, compile the SDK, and check its types.
- Check dependencies for known advisories at moderate severity or higher.
- Run complete documentation programs and check their expected output.
- Check SDK imports and types in snippets that require application context.
- Check exported import paths in a separate consumer without optional peer dependencies. Verify the declared platform exceptions.

Hosted client snippets need a configured Relay project and identity provider. Public snippet checks validate their imports and types without calling a live Relay.

A passing build establishes that the checked code builds and the exercised behavior passes. It does not establish the absence of vulnerabilities.

## Limits

The SDK implements its documented Signal Protocol profile. It is not wire-compatible with Signal Messenger or libsignal. Read the [protocol policy](./PROTOCOL_POLICY.md) and [deviations](./DEVIATIONS.md).

JavaScript engines do not guarantee machine-level constant-time execution or reliable memory zeroization. The [security model](./SECURITY.md) describes endpoint, timing, storage, and metadata risks.

Applications must choose their authentication, device trust, backup, recovery, and retention policies. Automated checks do not make those decisions.

## Security review and reporting

Request a walkthrough of the methods and results at [security@open-e2ee.dev](mailto:security@open-e2ee.dev).

Report suspected vulnerabilities through [SECURITY.md](../SECURITY.md). Keep vulnerability details out of public issues.
