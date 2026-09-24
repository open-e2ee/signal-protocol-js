# Assurance

The Signal Protocol SDK is open source under the MIT License or the Apache License 2.0, at your option. Its engineering tests remain private. We do not publish those tests or their private fixtures and comparison material.

This document states our testing methods, reported results, public checks, and review limits.

## What is public

The public repository contains the SDK source, documentation, examples, and build checks. An export tool copies approved files from the engineering repository. It excludes private engineering material and its development dependencies.

You can inspect the implementation and run the examples. You cannot reproduce the private results from this repository alone.

Private testing also exists in other open-source projects. [SQLite publishes some checks and keeps TH3 private](https://www.sqlite.org/testing.html). [Convex documents a private testing framework](https://github.com/get-convex/convex-backend#readme). Those projects do not review or endorse this SDK.

## Reported engineering results

Engineering CI runs the default automated checks on pull requests and changes to the main branch. Release preparation requires a passing run.

Most recent full run on 2026-09-24:

| | |
|---|---|
| Test modules | 428 |
| Test cases | 7,565 |
| Passed | 7,563 |
| Skipped | 2 |
| Failed | 0 |
| Wall time | 208 s |

The total counts test cases. One test case can contain several assertions. Separate commands run the longer performance and endurance checks.

Release tooling generates this table from a completed run. It refuses results from a failing run. The release gate rejects figures older than three days.

## Testing methods

- **Known answers:** compare cryptographic outputs with published reference data for ML-KEM, hashes, authenticated encryption, and signatures.
- **Protocol behavior:** check PQXDH, Double Ratchet, SPQR, and ML-KEM Braid state changes. Cover replay rejection, reordered messages, skipped-key limits, and required post-quantum operations.
- **Generated inputs:** check protocol and encoding properties across randomized inputs.
- **Messaging flows:** exercise device fanout, groups, device linking, provisioning, PNI-to-ACI changes, and relay delivery.
- **Storage contracts:** check persistence, concurrency, interruption, recovery, and storage pressure at adapter boundaries.
- **Runtime behavior:** run the browser storage contracts in Chromium, Firefox, and WebKit. Run the React Native backend contract on Hermes.
- **Public API:** check exported types, import paths, documented calls, and expected example output against the packed package.
- **Errors:** check construction sites for exported error classes and codes. Reject unresolved code forwarding.

The browser storage job also runs 2,000 open, write, read, and close cycles. It checks for upward memory and latency drift.

A storage contract check does not prove a full encrypted exchange. The [browser example](../examples/browser/README.md) and [Expo example](../examples/expo/README.md) exercise message encryption, delivery, and decryption.

## Runtime checks for 2.0.1

On 2026-09-12, the browser example completed encrypted exchanges in Chromium, Firefox, and WebKit. Nine checks covered fresh messages, replies, repeated runs, cancellation, reset, and worker-load errors under CSP.

The Expo example completed encrypted exchanges in development and release builds on Hermes. The checked targets were the iOS 26.1 simulator and Android 15 emulator, using Expo 55 and React Native 0.83.10.

Both platforms used SQLCipher 4.7.0. After a process restart, Alice retained her identity and completed another exchange. Release builds ran with Metro stopped. These results establish behavior on the listed targets, not device performance.

These application checks are separate from the recurring browser-storage and Hermes backend-contract jobs.

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
