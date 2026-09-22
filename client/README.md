# SignalProtocolClient Module

`SignalProtocolClient` is the primary high-level API for the package.

## Why it exists

The client coordinates session establishment, encryption, decryption, device
fanout, relay synchronization, retries, and application callbacks without
owning platform storage or backend infrastructure. Applications compose those
boundaries explicitly through `createSignalProtocolClient()`.

## Creation

Every client needs `storage`. Local use can omit `relay`, and real messaging
needs it. `protocol.postQuantum` and `protocol.braid` both default to
`'required'`.

<!-- doc-snippet:skip requires-established-session -->
```ts
import { createSignalProtocolClient, ProtocolAddress } from '@open-e2ee/signal-protocol-sdk';
import { inMemoryStore } from '@open-e2ee/signal-protocol-sdk/local/store/memory';

const signal = await createSignalProtocolClient({
  // A local-only client still needs storage for this device's key/session state.
  identity: { userId: 'alice' },
  adapters: { storage: inMemoryStore() },
});

// ProtocolAddress is for direct device-level APIs.
const bob = ProtocolAddress.create('bob', 1);
await signal.encryptMessage(bob, 'hello');
```

### With relay

<!-- doc-snippet:skip requires-external-context -->
```ts
import { createHostedSignalProtocolClient } from '@open-e2ee/signal-protocol-sdk';
import { expoStore } from '@open-e2ee/signal-protocol-sdk/local/store/expo';

// Initialize the application-owned Expo/SQLCipher database bindings first.
const signal = await createHostedSignalProtocolClient({
  adapters: {
    // Expo storage owns this device's private keys and session state.
    storage: expoStore(),
  },
  hosted: {
    // The environment-scoped connection URL from the OpenE2EE console.
    relayUrl: process.env.EXPO_PUBLIC_OPEN_E2EE_RELAY_URL!,
    // Returns a short-lived signed assertion for the signed-in user.
    getIdentityAssertion,
  },
});
```

See the [Expo storage guide](../local/store/expo/README.md) for the required
database-binding and SQLCipher bootstrap.

### Protocol policy

Use product/security terms at the client boundary:

<!-- doc-snippet:skip requires-external-context -->
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

<!-- doc-snippet:skip requires-external-context -->
```ts
await createSignalProtocolClient({
  identity: { userId },
  adapters: { storage, relay },
  protocol: { postQuantum: 'compatible', braid: 'required' },
});
```

Use direct SPQR only as an explicit product-reviewed escape hatch:

<!-- doc-snippet:skip requires-external-context -->
```ts
await createSignalProtocolClient({
  identity: { userId },
  adapters: { storage, relay },
  protocol: { postQuantum: 'required', braid: 'disabled' },
});
```

## ProtocolAddress

Use typed device addresses instead of string session ids:

<!-- doc-snippet:skip requires-external-context -->
```ts
import { ProtocolAddress } from '@open-e2ee/signal-protocol-sdk';

const bob = ProtocolAddress.create('bob', 1);
const parsed = ProtocolAddress.parse('bob:1');
const asString = ProtocolAddress.toString(bob);
```

## Common Operations

### Direct session control

<!-- doc-snippet:skip requires-external-context -->
```ts
const bob = ProtocolAddress.create('bob', 1);

// Direct session control is for advanced integrations.
await signal.establishSession(bob, bundle);
const ciphertext = await signal.encryptMessage(bob, 'hello');
const plaintext = await signal.decryptMessage(bob, ciphertext);
```

### Multi-device send

<!-- doc-snippet:skip requires-external-context -->
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

<!-- doc-snippet:skip requires-external-context -->
```ts
// Publish fresh public prekeys and rotate long-lived prekeys on schedule.
await signal.syncToServer();
await signal.rotateEcSignedPreKey();
await signal.rotateKyberPreKey();
```

### Hosted mailbox receive

Register `onMessageDecrypted` before calling `pullHostedRelayAfterWake()`.
The handler must persist application content before it resolves. Use the message
ID for idempotent application writes. A rejected handler leaves the envelope
unacknowledged.

The hosted pull uses the same content handler as the foreground subscription.
It installs pairwise sender-key distributions only for members of the verified
local group. It handles receipts and typing separately from application messages.
Successful content receipts permit acknowledgment retries without decryption.

The device-local store commits recoverable content with the ratchet update or
skipped-key consumption. A restart can resume the application write from that
encrypted record without sender retransmission. The SDK deletes the content
after a successful processing receipt. Retry cleanup removes abandoned records
after the existing thirty-day retry horizon.

The application handler can run again if its write succeeds but the processing
receipt fails. Use the message ID to prevent duplicate application records.
Recovery rejects changes to the envelope identity or ciphertext.

`processIncomingEnvelopes()` remains a lower-level decryption API. It returns
plaintext to its caller. It does not run the application handler.

### Background key maintenance

Use the dedicated headless entry point from a background task after restoring
the same application-owned storage and relay boundaries:

<!-- doc-snippet:skip requires-external-context -->
```ts
import { rotateKeysHeadless } from '@open-e2ee/signal-protocol-sdk/client/headless';

const result = await rotateKeysHeadless(relay, userId, deviceId, { storage });
```

## Linked Devices

- device `1` is the primary device
- linked devices use device IDs `2-5`
- provision linked-device identity material into the provided storage before `DefaultSignalProtocolClient.create(..., { deviceId: 2 })`

## Notes

- `DefaultSignalProtocolClient.create()` no longer provides hidden default adapters.
- `createSignalProtocolClient()` is the preferred generic composition helper for app
  setup code.
- App-specific React hooks and DB-backed view-state helpers should stay outside this module.
- Use the root package or explicit subpaths for utilities. Do not import from `internal/*`.
