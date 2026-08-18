# Blocking

The blocking module keeps recipient-block state local to the current device
and optionally projects a snapshot to an application-owned mirror.

## Why it exists

Blocking is a product decision with protocol consequences. The client must
reject blocked recipients consistently, and a remote mirror must not become a
second, conflicting source of truth. `SignalProtocolBlockingManager` centralizes that ordering.

## Usage

```ts
import {
  SignalProtocolBlockingManager,
  type SignalProtocolBlockingStore,
} from "@open-e2ee/signal-protocol-sdk/blocking";

const store: SignalProtocolBlockingStore = appBlockingStore;

const blocking = new SignalProtocolBlockingManager({
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

The local store is authoritative. The blocking manager logs mirror failures
after the local mutation succeeds. A mirror failure does not roll back the local
decision. Applications
should provide their own retry or reconciliation policy for the mirror.

See the [API reference](../docs/api/namespaces/blocking/README.md) and
[client guide](../client/README.md).
