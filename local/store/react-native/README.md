# Bare React Native Store

`ReactNativeSignalStore` implements `ISignalLocalStore` for bare React Native
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
A batched sequence of independent writes is not sufficient.

This adapter remains experimental because key custody, crash recovery, backup
behavior, and transaction guarantees depend on the supplied native backend.

See the parent [storage guide](../README.md), [adapter guide](../../../ADAPTERS.md),
and [security model](../../../docs/SECURITY.md).
