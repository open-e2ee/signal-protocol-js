# Assurance

The Signal Protocol SDK is open source under the MIT License or the Apache License 2.0, at your option. Its engineering tests remain private. We do not publish those tests or their private fixtures and comparison material.

This document states our testing methods, reported results, public checks, and review limits.

## What is public

The public repository contains the SDK source, documentation, examples, and build checks. An export tool copies approved files from the engineering repository. It excludes private engineering material and its development dependencies.

You can inspect the implementation and run the examples. You cannot reproduce the private results from this repository alone.

Private testing also exists in other open-source projects. [SQLite publishes some checks and keeps TH3 private](https://www.sqlite.org/testing.html). [Convex documents a private testing framework](https://github.com/get-convex/convex-backend#readme). Those projects do not review or endorse this SDK.

## Reported engineering results

Engineering CI runs the default automated checks on pull requests and changes to the main branch. Release preparation requires a passing run.

Most recent full run on 2026-09-28:

| | |
|---|---|
| Test modules | 466 |
| Test cases | 8,563 |
| Passed | 8,559 |
| Skipped | 4 |
| Failed | 0 |
| Wall time | 434 s |

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

The browser storage job also runs 2,000 open, write, read, and close cycles. It checks for upward memory and latency drift.

A storage contract check does not prove a full encrypted exchange. The [browser example](../examples/browser/README.md) and [Expo example](../examples/expo/README.md) exercise message encryption, delivery, and decryption.

## SQLite store checks

Four package entries keep device-local state in a SQLite database: `./local/store/node`, `./local/store/expo`, `./local/store/react-native`, and `./local/store/web-sqlite`. A Tauri app uses `./local/store/web-sqlite`. Each row gives one runtime claim and the check that proves it. Rows that do not name public CI run in the project's engineering CI. A check runs on each pull request and each change to the main branch, unless its row says otherwise.

### Node and the Electron main process: `./local/store/node`

| Claim | Check | What the check runs |
|---|---|---|
| The store passes the shared storage contract on an encrypted file. | Default automated checks: Linux, Node 26 | The storage contract on `nodeStore` and the `better-sqlite3-multiple-ciphers` binding. |
| The driver writes SQLCipher 4 files. An encrypted file has no SQLite header, and a wrong key fails with a typed error. | Node store job: Linux, macOS, and Windows, each with Node 22 and Node 26 | Real files on the prebuilt binding. |
| Without `encryptionAtRest: false`, the store refuses a binding that has no cipher. The store refuses a file that has the other encryption setting. | Node store job: the same six runners | Real files on the prebuilt binding. |
| The store writes its key to the vault before it creates the file. A file without a key fails as a lost key and does not change. | Node store job: the same six runners | Real files and a vault. |
| One process at a time owns a store. After the owner process is killed, the next open succeeds and reads the committed data. | Node store job: the same six runners | A child process holds the store. The parent process tries to open it, then kills the child and opens it. |
| Every part of the store interface survives a close and a new open of the directory. | Node store job: the same six runners | Real files on the prebuilt binding. |
| In the Electron main process, the store passes the shared storage contract with its key in the real `safeStorage`. The file has no SQLite header, and the vault file keeps only a ciphertext of the key. | Electron store job: Linux, macOS, and Windows | Electron from its npm package, with the GNOME keyring through libsecret on Linux, the Keychain on macOS, and DPAPI on Windows. A pull request runs this job only when it changes the store, the vault, the storage contract, the job, or a dependency. |
| On Linux, the vault refuses the `basic_text` backend of `safeStorage`. The store does not open, and no key reaches the disk. | Electron store job: Linux | Electron with `--password-store=basic`. |
| On Linux, the vault refuses the fixed fallback key that `safeStorage` uses when no secret service answers. The store does not open, and no key reaches the disk. | Electron store job: Linux | Electron with `--password-store=gnome-libsecret` and no unlocked keyring on the D-Bus session. |

### Expo: `./local/store/expo`

| Claim | Check | What the check runs |
|---|---|---|
| The store passes the shared storage contract. | Default automated checks: Linux, Node 26 | The storage contract on the `expo-sqlite` JavaScript layer over `node:sqlite`. This check runs no native module and no SQLCipher. |
| A release build of the Expo example stores its state with SQLCipher on Android and keeps it across a process restart. | Android emulator job | A release APK on Hermes V1, run twice on an Android API 36 x86_64 emulator. Each run must log a SQLCipher version and a database header that is not the SQLite header. The second run must resume the stored identity and complete an exchange. This job runs on a change to the main branch that can reach the React Native runtime, and on demand. It does not run on a pull request. |
| The Expo example, which imports this entry, bundles with the Hermes compiler that React Native pins. | Public CI (`Checks`) | The Android bundle of the Expo example with the packed package, on Expo SDK 55 and Expo SDK 57. |

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
| The bare React Native example, which imports this entry, bundles with the Hermes compiler that React Native pins. | Public CI (`Checks`) | The Android release bundle of the bare React Native example with the packed package. |

The Android emulator job is the only CI job that runs this store on Hermes with the native op-sqlite module. No CI job runs it on iOS. On 2026-09-28, a manual check of a development build of the SDK before 8.0.0 ran the bare React Native example in the iOS 26.2 simulator with Xcode 26.3. Each of four launches logged a SQLCipher version, a database header that is not the SQLite header, and the wrong-key failure. Each launch after the first resumed the stored identity.

### Web: `./local/store/web-sqlite`

| Claim | Check | What the check runs |
|---|---|---|
| The store passes the shared storage contract in a real browser, with the Wasm engine in its worker and the file in the origin private file system (OPFS). | Browser storage job: Chromium and Firefox on Linux. WebKit store job: WebKit on macOS | The page has a Content Security Policy that adds only `'wasm-unsafe-eval'`. |
| An encrypted file keeps no plaintext in OPFS. A wrong key and no key cannot read it. The web driver reads a SQLCipher 4 file that the Node driver wrote. | Browser storage job: Chromium and Firefox on Linux. WebKit store job: WebKit on macOS | Real files in OPFS. |
| Two tabs share one file, and a tab hands it over only between transactions. A tab that dies in a transaction leaves the file readable without the writes of that transaction. | Browser storage job: Chromium and Firefox on Linux. WebKit store job: WebKit on macOS | Two real tabs of one origin. |
| Two tabs that open a new store at the same time write one key. A reset fails with `INVALID_STATE` while another tab has the store open. | Browser storage job: Chromium and Firefox on Linux. WebKit store job: WebKit on macOS | Two real tabs of one origin. |
| Without `'wasm-unsafe-eval'`, the open fails with `SQLITE_ENGINE_UNAVAILABLE` and writes no key. | Browser storage job: Chromium and Firefox on Linux. WebKit store job: WebKit on macOS | A page under a policy without `'wasm-unsafe-eval'`. |
| When the origin quota is full, a write and an atomic commit reject with `STORAGE_QUOTA_EXCEEDED` and leave no partial state. The store stays open, and after the clamp is removed, the same commit succeeds. | Browser storage job: Chromium on Linux | A DevTools protocol call clamps the origin quota, and the store fills its real file in OPFS. Firefox and WebKit have no such call, so they do not run this check. |
| A worker without OPFS synchronous access handles fails with `OPFS_UNAVAILABLE` before it loads the engine. | Browser storage job: Chromium, Firefox, and WebKit on Linux | WebKit on Linux (WebKitGTK) has no OPFS synchronous access handles, so there WebKit runs only these checks and the checks that need no OPFS. |

The WebKit store job runs Playwright's WebKit on macOS, where WebKit has OPFS synchronous access handles. It runs only on a change to the web SQLite store, the SQLite core, the storage contract, the key vault, the job, or a dependency. In the browser storage job for Chromium and Firefox and in the WebKit store job, a check that skips for want of OPFS fails.

The code-generation check in public CI runs the README example with the memory store. It does not load a SQLite store.

### Tauri

No CI job runs a Tauri app. A Tauri 2 app uses `./local/store/web-sqlite` in its webview, with no Tauri-specific SDK code, so the web rows above check the same code in browsers. The [web SQLite store guide](../local/store/web-sqlite/README.md#tauri) gives the Tauri setup. On 2026-09-28, a manual check of a development build of the SDK before 8.0.0, in a Tauri 2.12.0 app, passed in WKWebView on macOS 15.7.2 and in the iOS 18.0 simulator. The check covered a two-device exchange, a close and reopen, an app relaunch, a relaunch after the app was killed with both stores open, and the store locks.

### UNVERIFIED

No CI job checks these items:

- **Safari.** The WebKit store job runs Playwright's WebKit, not Safari. No check ran the web store in Safari.
- **Tauri on WebView2 (Windows), the Android WebView, and WebKitGTK (Linux).** WebKitGTK 2.54 has no OPFS synchronous access handles, so the expected result of the open is `OPFS_UNAVAILABLE`. No run observed it.
- **The React Native store on iOS and on physical devices.** No CI job opens `./local/store/react-native` on iOS. The manual check used only the iOS simulator. No check ran the store on a physical Android or iOS device.
- **iOS devices.** No CI job runs on iOS. The manual checks used only the iOS simulator.
- **A packaged Electron app.** The Electron store job runs Electron from its npm package, not from an app build.

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

[Public CI](https://github.com/open-e2ee/signal-protocol-js/actions/workflows/ci.yml) runs on pushes and pull requests. Its logs show these checks:

- Install from the committed lockfile, compile the SDK, and check its types.
- Check dependencies for known advisories at moderate severity or higher.
- Extract the README example and run it against the packed package.
- Run the example with string-based code generation disabled.
- Run complete documentation programs and check their expected output.
- Check SDK imports and types in snippets that require application context.
- Check exported import paths in a separate consumer without optional peer dependencies. Verify the declared platform exceptions.

The examples include installation commands and expected output. The browser example shows ciphertext and decrypted messages in the page and console.

A passing build establishes that the checked code builds and the exercised behavior passes. It does not establish the absence of vulnerabilities.

## Limits

The SDK implements its documented Signal Protocol profile. It is not wire-compatible with Signal Messenger or libsignal. Read the [protocol policy](./PROTOCOL_POLICY.md) and [deviations](./DEVIATIONS.md).

JavaScript engines do not guarantee machine-level constant-time execution or reliable memory zeroization. The [security model](./SECURITY.md) describes endpoint, timing, storage, and metadata risks.

Applications must choose their authentication, device trust, backup, recovery, and retention policies. Automated checks do not make those decisions.

## Security review and reporting

Request a walkthrough of the methods and results at [security@open-e2ee.dev](mailto:security@open-e2ee.dev).

Report suspected vulnerabilities through [SECURITY.md](../SECURITY.md). Keep vulnerability details out of public issues.
