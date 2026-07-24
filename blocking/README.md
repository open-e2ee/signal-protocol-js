# Blocking

The blocking module keeps recipient-block state local to the current device
and optionally projects a snapshot to an application-owned mirror.

## Why it exists

Blocking is a product decision with protocol consequences: blocked recipients
must be rejected consistently without making a remote mirror a second,
conflicting source of truth. `SignalBlockingManager` centralizes that ordering.

## Usage

```ts
import {
  SignalBlockingManager,
  type SignalBlockingStore,
} from "@open-e2ee/signal-protocol-sdk/blocking";

const store: SignalBlockingStore = appBlockingStore;

const blocking = new SignalBlockingManager({
  store,
  mirror: {
    syncBlockedRecipients: (entries) =>
      appSync.publishBlockedRecipients(entries),
  },
});

await blocking.blockRecipient("bob");

if (await blocking.isBlocked("bob")) {
  // Do not send to or accept application messages from this recipient.
}
```

The local store is authoritative. Mirror failures are logged after the local
mutation succeeds; they do not roll back the local decision. Applications
should provide their own retry or reconciliation policy for the mirror.

See the [API reference](../docs/api/namespaces/blocking/README.md) and
[client guide](../client/README.md).
