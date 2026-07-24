# SignalProtocolClient Module

`SignalProtocolClient` is the primary high-level API for the package.

## Why it exists

The client coordinates session establishment, encryption, decryption, device
fanout, relay synchronization, retries, and application callbacks without
owning platform storage or backend infrastructure. Applications compose those
boundaries explicitly through `createSignalProtocolClient()`.

## Creation

`storage` is required. `relay` is optional for local use and expected for real
messaging. `protocol.postQuantum` and `protocol.braid` both default to
`'required'`.

```ts
import { createSignalProtocolClient, ProtocolAddress } from '@open-e2ee/signal-protocol-sdk';
import { mockStore } from '@open-e2ee/signal-protocol-sdk/local/store/mock';

const signal = await createSignalProtocolClient({
  // A local-only client still needs storage for this device's key/session state.
  identity: { userId: 'alice' },
  adapters: { storage: mockStore() },
});

// ProtocolAddress is for direct device-level APIs.
const bob = ProtocolAddress.create('bob', 1);
await signal.encryptMessage(bob, 'hello');
```

### With relay

```ts
import { createSignalProtocolClient } from '@open-e2ee/signal-protocol-sdk';
import { convexRelay, type ConvexSignalRelayApi } from '@open-e2ee/signal-protocol-sdk/remote/relay/convex';
import { expoStore } from '@open-e2ee/signal-protocol-sdk/local/store/expo';
import { api } from '../convex/_generated/api';

const signalApi = api.signal satisfies ConvexSignalRelayApi;

// The relay handles server-side device lists, public prekeys, and envelopes.
const relay = convexRelay({
  convex,
  api: signalApi,
  currentUserId: userId,
});

// Initialize the application-owned Expo/SQLCipher database bindings first.
const signal = await createSignalProtocolClient({
  identity: { userId },
  adapters: {
    // Expo storage owns this device's private keys and session state.
    storage: expoStore({ relay }),
    relay,
  },
});
```

See the [Expo storage guide](../local/store/expo/README.md) for the required
database-binding and SQLCipher bootstrap.

### Protocol policy

Use product/security terms at the client seam:

```ts
await createSignalProtocolClient({
  identity: { userId },
  adapters: { storage, relay },
  protocol: { postQuantum: 'required', braid: 'required' },
});
```

`postQuantum: 'required'` and `braid: 'required'` are the defaults. Use
`compatible` only for an explicit product decision to support peers that
publish no post-quantum material:

```ts
await createSignalProtocolClient({
  identity: { userId },
  adapters: { storage, relay },
  protocol: { postQuantum: 'compatible', braid: 'required' },
});
```

Use direct SPQR only as an explicit product-reviewed escape hatch:

```ts
await createSignalProtocolClient({
  identity: { userId },
  adapters: { storage, relay },
  protocol: { postQuantum: 'required', braid: 'disabled' },
});
```

## ProtocolAddress

Use typed device addresses instead of string session ids:

```ts
import { ProtocolAddress } from '@open-e2ee/signal-protocol-sdk';

const bob = ProtocolAddress.create('bob', 1);
const parsed = ProtocolAddress.parse('bob:1');
const asString = ProtocolAddress.toString(bob);
```

## Common Operations

### Direct session control

```ts
const bob = ProtocolAddress.create('bob', 1);

// Direct session control is for advanced integrations.
await signal.establishSession(bob, bundle);
const ciphertext = await signal.encryptMessage(bob, 'hello');
const plaintext = await signal.decryptMessage(bob, ciphertext);
```

### Multi-device send

```ts
const result = await signal.send(recipientUserId, 'hello');

// Store outgoing message state in your app database after relay acceptance.
await appMessages.insertOutgoing({
  messageId: result.messageId,
  body: 'hello',
  sentAt: result.clientTimestamp ?? result.timestamp,
  recipientDeviceCount: result.recipientDeviceCount,
});
```

### Server sync

```ts
// Publish fresh public prekeys and rotate long-lived prekeys on schedule.
await signal.syncToServer();
await signal.rotateEcSignedPreKey();
await signal.rotateKyberPreKey();
```

### Background key maintenance

Use the dedicated headless entry point from a background task after restoring
the same application-owned storage and relay boundaries:

```ts
import { rotateKeysHeadless } from '@open-e2ee/signal-protocol-sdk/client/headless';

const result = await rotateKeysHeadless(relay, userId, deviceId, { storage });
```

## Linked Devices

- device `1` is the primary device
- devices `2-5` are linked devices
- linked devices must already have provisioned identity material in the provided storage before `SignalProtocolClient.create(..., { deviceId: 2 })`

## Notes

- `SignalProtocolClient.create()` no longer provides hidden default adapters.
- `createSignalProtocolClient()` is the preferred generic composition helper for app
  setup code.
- App-specific React hooks and DB-backed view-state helpers should stay outside this module.
- Use the root package or explicit subpaths for utilities; do not import from `internal/*`.
