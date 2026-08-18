# Bare React Native Store

`ReactNativeSignalProtocolStore` implements `ISignalProtocolLocalStore` for bare React Native
through an application-provided persistent key-value backend.

## Why it exists

Bare React Native applications choose different native storage engines. The
adapter keeps that choice outside the SDK while requiring the atomic operations
needed for trust, session, and one-time-prekey transitions.

## Usage

```ts
import { createSignalProtocolClient } from "@open-e2ee/signal-protocol-sdk";
import {
  reactNativeStore,
  type ReactNativeKeyValueStorage,
} from "@open-e2ee/signal-protocol-sdk/local/store/react-native";

const keyValueStorage: ReactNativeKeyValueStorage = appProtocolStorage;
const storage = await reactNativeStore({ storage: keyValueStorage });

const client = await createSignalProtocolClient({
  identity: { userId },
  adapters: { storage, relay },
});
```

The injected backend's `atomicWrite()` is a security boundary. It must evaluate
compare-and-swap checks and commit all writes, removals, and exact per-user
session deletion atomically and durably, including across process termination.
Independent writes committed one after another are not sufficient.

## Verifying your backend

The adapter's guarantees hold only over a backend that honors the
`ReactNativeKeyValueStorage` contract, and the SDK cannot test the backend
your application supplies. The package therefore exports a
backend-conformance kit. Run it against your backend from your application's
own tests:

```ts
import {
  assertBackendConformance,
  createReferenceReactNativeBackend,
} from "@open-e2ee/signal-protocol-sdk/local/store/react-native";

await assertBackendConformance({
  createBackend: () => createMyBackend(),
  // Optional: return a new instance over the same persistence medium to
  // verify committed writes survive reopen. Reported as skipped when absent.
  reopen: (previous) => reopenMyBackend(previous),
});
```

The function `assertBackendConformance` throws one error that names every
failing case. The function `runBackendConformance` returns the structured
result instead. The SDK also ships `createReferenceReactNativeBackend`, which
specifies the contract in executable form. It is an in-memory backend that
passes the kit, and it is useful as a comparison point and as a test double.

Continuous integration runs the kit against the reference backend on the Hermes
engine. It also drives the adapter over that backend through interruption and
storage-pressure suites. The parent [storage guide](../README.md) holds the
checklist that graduated this adapter.

Key custody, crash durability, and backup behavior remain properties of your
chosen native storage engine. The kit verifies contract semantics, and your
deployment review must still cover the engine itself.

See the parent [storage guide](../README.md), [adapter guide](../../../ADAPTERS.md),
and [security model](../../../docs/SECURITY.md).
