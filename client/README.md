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

Run `oe new` in the application directory. It creates the Relay project and
its Sandbox environment, and it writes the connection URL to `.env.local`. In
a Sandbox environment, `hostedRelaySandboxIdentity(storage)` supplies
`getIdentityAssertion` from a key in the device-local store. In production,
supply `getIdentityAssertion` from your authentication integration. It returns
a short-lived signed assertion for the signed-in user.

The hosted factory registers the device and publishes its public prekeys.
The published SDK contains client code and transport contracts. Relay server
implementations run separately.

<!-- doc-snippet:skip requires-external-context -->
```ts
import { createHostedSignalProtocolClient } from '@open-e2ee/signal-protocol-sdk';
import { expoStore } from '@open-e2ee/signal-protocol-sdk/local/store/expo';

const signal = await createHostedSignalProtocolClient({
  adapters: {
    // Expo storage owns this device's private keys and session state.
    storage: await expoStore(),
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
// Publish fresh public prekeys, then rotate every due prekey in one publication.
await signal.syncToServer();
const rotation = await signal.rotatePreKeys();
// { signedRotated, kyberRotated, oneTimeReplenished, errors }
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

### Delivery receipts

After the `onMessageDecrypted` handler resolves for a message that asks for a
receipt, the client sends an end-to-end encrypted delivery receipt to each
device of the sender. The `deliveryReceipts` option selects the messages:

| Value              | Receipt                                                     |
| ------------------ | ----------------------------------------------------------- |
| `'auto'` (default) | Leaves the receipt to the Signal Protocol Relay when it can |
| `'always'`         | For each message that asks for one, sealed or identified    |
| `'off'`            | None                                                        |

With `'auto'` on the Signal Protocol Relay, the client sends no end-to-end
receipt for an identified message that the Relay acknowledgment lists as
receipted. On any other relay, `'auto'` sends the same receipts as `'always'`.
`DecryptedEnvelope.arrivedSealed` tells whether a message arrived through sealed
sender. The client seals a receipt when it holds the access key of the sender,
and sends it identified otherwise. Read receipts are not affected.

The sender gets each receipt through the `onDelivered` hook, once for each
source and recipient device:

| `source`  | Sender                    | `decryptionConfirmed` |
| --------- | ------------------------- | --------------------- |
| `'relay'` | The Signal Protocol Relay | `false`               |
| `'e2ee'`  | The recipient device      | `true`                |

The status of a device only moves forward. `sources` holds each source that the
device has given so far, so an `'e2ee'` event after a `'relay'` event carries
both. A second receipt of the same source changes nothing. A receipt for a send
that has not resolved yet comes after the send resolves.

The sender keeps a copy of each message that it sends, plaintext included, so
that it can send the message again when the recipient asks for a retry. An
end-to-end receipt from a device deletes that copy for that device. A Relay
receipt does not delete it. A message that gets no end-to-end receipt keeps its
copy on the sender device until the copy is 14 days old. Only client creation
and `stop()` delete such old copies.

### Hosted presence

`hostedRelayPresence(client)` reads and writes presence over the mailbox
socket, so start the subscription first. A request without a connected
socket fails with `NOT_CONNECTED`, and the SDK does not send it over HTTP.

<!-- doc-snippet:skip requires-external-context -->
```ts
import { hostedRelayPresence } from '@open-e2ee/signal-protocol-sdk';

const presence = hostedRelayPresence(client);
const policy = await presence.policy(); // show or disable the toggle
await presence.setVisibility('hidden');

const stop = presence.watch(contactAccount, (status) => {
  // null, or { online, lastSeen }
});
```

A contact's presence needs the contact's presence key. Give the hosted client
`hosted.profileKeys`, and the SDK exchanges the keys with no app code:

<!-- doc-snippet:skip requires-external-context -->
```ts
const client = await createHostedSignalProtocolClient({
  adapters,
  hosted: {
    getIdentityAssertion,
    relayUrl,
    profileKeys: {
      getOwnProfileKey: async () => profileKey, // 32 bytes, or null
      contacts, // a MutableContactProfileStateStore
    },
  },
});
```

Each 1:1 DataMessage carries the profile key in `profileKey`, inside the
encrypted content. Before a 1:1 string or byte send, the SDK sends one key
update to a contact that does not have the current key. The receiving SDK
keeps the key in `contacts`, derives the presence key, and calls `grant()`.
The SDK calls `accessKey()` when the socket connects and when the profile key
changes. A new profile key revokes the old presence key, and the next message
delivers the new one. Each device of the account must return the same
profile key. Group messages do not carry the key.

`watch()` registers one presence watch for the first 16 watched accounts. It
registers when the socket connects, at each change of that set, and again
every 120 s. The Relay then pushes each change of a watched account. The
client reads the other accounts every 30 s. After a watch fails, or has no
answer in 10 s, it reads every account every 30 s until a watch answers
again. It calls the listener only on a change. With `bindRelayLifecycle`, the
socket closes in the background, so the watch and the poll stop there. On
web, a hidden tab keeps its watch and renews it.

A wake client has no socket. Use `hostedRelayWakePresence(client)` beside
`pullHostedRelayAfterWake()`. It has the same members without `watch()`, and
it sends each request as one authenticated HTTP request.

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
