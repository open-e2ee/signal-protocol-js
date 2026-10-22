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

### Unknown or revoked device

The hosted factory resumes the stored session. It throws
`HostedRelayDeviceUnknownError` when the Relay has no device for that session.
It throws `HostedRelayDeviceRevokedError` when an account recovery revoked the
device. It never registers a new device in their place, and it does not retry.

After an unknown device, ask the user to confirm. Then call the factory again
with `assertionPurpose: 'reregister'`. It registers the same identity and
device key again. The Relay can give a new device ID, so the messages queued
for the old device are lost. A Relay that recorded the revocation of a device
refuses its registration with `HostedRelayDeviceRevokedError`. See
[Relay Device Errors](../docs/ERROR_HANDLING.md#relay-device-errors).

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

`postQuantum: 'required'` and `braid: 'required'` are the defaults.
`'required'` is the only `postQuantum` value. The SDK has no classical key
agreement, so a session with a peer that publishes no ML-KEM prekeys fails
with `PQXDHRequiredError` (`PQXDH_REQUIRED`).

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
ID for idempotent application writes.

The hosted pull uses the same receive path as the foreground subscription. The
client decrypts each envelope and commits its content as a receive record with
the ratchet update or skipped-key consumption. It acknowledges the envelope only
after that commit. The receive queue then decides the group of the content,
gives the content to the handler, sends the E2EE delivery receipt, and deletes
the record. The E2EE receipt is the only proof that the application processed
the content. A Relay delivery receipt marks only the handoff to the device.
Content that waits for its group state stays on the device. A waiting record
holds back the later content of its conversation only. Group content waits by
its group, a sent transcript by its destination, and other content by its
sender account. A restart resumes the record with no sender retransmission. A
rejected handler runs again after a backoff. After 10 attempts, the record no
longer holds back the later content of its conversation. Each start then gives
it to the handler once, in the start pass or when `onMessageDecrypted` is
registered. After that, only `processPendingReceives` runs it again before the
next start. A pass that ends before the retry, at a deadline or at a failed
page read, leaves the retry to the next pass. That retry runs after the other
content of the pass, so a hook call that ends the process on it does not stop
the later content of its conversation. `listPendingReceives` gives the
`hookAttempts` of each record. `discardPendingReceive` removes a record that
the application cannot process, with no receipt, no handler call, and no
expiry report.

A receive pass waits for each hook for at most
`protocol.receiveQueue.receiveHookTimeoutMs`, 2 minutes by default. A timeout
of `onMessageDecrypted` counts as one failed attempt. A handler that settles
after the bound writes nothing. Content that waits
30 days on the device runs `onReceiveExpired`, and the client deletes its
record. The 30 days are fixed. Before the hook, the
client reads the record again. Content that the client completed before that
read, such as at the redelivery of its envelope, gets no expiry report. A
record that waits only for its E2EE delivery receipt completes 1 day after the
receipt becomes due, with no receipt and no expiry report.

At a receive queue bound, the client decrypts nothing more and does not
acknowledge the envelope, so the Relay keeps it. A refused envelope expires at
the Relay at the TTL of the Relay project, and no local hook reports that
expiry. While the mailbox of the device is full, the Relay refuses a new message
to it with `MAILBOX_FULL` to its sender. Refused envelopes do not stop the
messages behind them, on the socket or on an HTTP pull.
The client handles receipts and typing separately from application messages.

The handler can run again if its write succeeds but the record does not
complete. Use the message ID to prevent duplicate application records.

`processIncomingEnvelopes()` is the receive helper for an application that pulls
envelopes itself. It returns a receive outcome for each envelope and does not run
the application handler. A `processed` receive keeps its content until the
application calls `completeReceive()`.

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
sender. The client seals a receipt when it holds the access key of the sender.
Otherwise it sends the receipt identified only when the `deliveryMode` of
`sealedSender` permits it, and `'required'` sends no identified receipt. A
retry request follows the same rule. Read receipts are not affected.

The sender gets each receipt through the `onDelivered` hook, once for each
source and recipient device:

| `source`  | Sender                    | `decryptionConfirmed` |
| --------- | ------------------------- | --------------------- |
| `'relay'` | The Signal Protocol Relay | `false`               |
| `'e2ee'`  | The recipient device      | `true`                |

The status of a device only moves forward. `sources` holds each source that the
device has given so far, so an `'e2ee'` event after a `'relay'` event carries
both. A receipt for a send that has not resolved yet comes after the send
resolves.

The hook runs at least once for each source. The client marks a source
announced only after the hook returns. A hook that throws, a `stop()` during the
hook, or a crash leaves the source unannounced. An error from the hook fails the
receipt, so the relay delivers it again, and the hook runs again with the next
receipt for the message. A second receipt of the same source after the hook
returned changes nothing. Make the hook idempotent for one `clientMessageId`,
`recipientDeviceId`, and `source`.

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

### Group init status

`getGroupInitStatus(groupId)` gives the init status of a group on this device.
It gives null when the device has no record of the group.

- `ready` means that the device holds the group key and the newest group state
  that it knows.
- `stale` means that a sender named a newer revision than the stored state.
  The client fetches the newer state.
- `pending` means that the device holds the group key and has no group state
  yet. The client fetches the state.
- `no-key` means that the device knows the group but holds no group key. The
  client cannot fetch the group until the device gets the key.
- `denied` means that the group server refused the newest revision that the
  device knows.

`onGroupInitStatus(groupId, status)` runs when a client write to the record of
a group changes its status. It does not run when the status stays the same, or
when a write deletes the record. It also does not run for a status that the
store holds when the client starts, or for a write that the application makes
to the group store. So read each status at start, and then use the hook.

<!-- doc-snippet:skip requires-external-context -->
```ts
import { createSignalProtocolClient } from '@open-e2ee/signal-protocol-sdk';

const client = await createSignalProtocolClient({
  identity,
  adapters: { storage, relay },
  groups,
  hooks: {
    onGroupInitStatus: (groupId, status) => groupList.setInitStatus(groupId, status),
  },
});

for (const groupId of groupList.groupIds()) {
  groupList.setInitStatus(groupId, await client.getGroupInitStatus(groupId));
}
```

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
- put the account identity into the linked device's storage by device transfer or by a channel that the application owns before `DefaultSignalProtocolClient.create(..., { deviceId: 2 })`

## Notes

- `DefaultSignalProtocolClient.create()` no longer provides hidden default adapters.
- `createSignalProtocolClient()` is the preferred generic composition helper for app
  setup code.
- App-specific React hooks and DB-backed view-state helpers should stay outside this module.
- Use the root package or explicit subpaths for utilities. Do not import from `internal/*`.
