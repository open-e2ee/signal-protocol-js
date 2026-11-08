[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / hostedRelaySandboxIdentity

# ~~Variable: hostedRelaySandboxIdentity~~

> `const` **hostedRelaySandboxIdentity**: (`storage`) => [`GetIdentityAssertion`](../type-aliases/GetIdentityAssertion.md) = `hostedSignalProtocolRelaySandboxIdentity`

Creates the identity assertion callback for a Sandbox environment of the
Signal Protocol Relay.

The callback signs a short-lived device-owned assertion with an Ed25519 key
that it keeps in `storage`. It creates the key on the first call and uses the
same key after that, so the Relay returns the same account each time the
device registers. The key is separate for each publishable key. Pass the
same store as `adapters.storage`. A device that loses the store loses the
Sandbox account. Another device of the account joins through device linking.

The callback rejects a request for a production environment, for recovery,
for provider migration, or for recent or step-up assurance. This helper is
the Sandbox-only guard, and it is not deprecated. For a Production project in
device-owned mode, use [hostedSignalProtocolRelayDeviceOwnedIdentity](../functions/hostedSignalProtocolRelayDeviceOwnedIdentity.md). For a
Production project in application-bound mode, supply a `getIdentityAssertion`
callback that returns an assertion from your backend.

The key is stored under a metadata key prefix followed by the base64
SHA-256 digest of the publishable key. The helper reads the prefix
`'signalRelay.sandboxIdentity.v2:'` first and the prefix
`'hostedRelay.sandboxIdentity.v1:'` second. This release stores a new key
under `'hostedRelay.sandboxIdentity.v1:'`, the prefix that SDK 14.1.0 and
earlier read and write. A later release stores a new key under
`'signalRelay.sandboxIdentity.v2:'`. SDK 15 still reads the earlier prefix,
so an existing Sandbox account keeps its key. Both helpers keep this
persisted format. So for the same store and publishable key, both helpers
sign with the same key.

## Parameters

### storage

[`SignalProtocolLocalStore`](../interfaces/SignalProtocolLocalStore.md)

## Returns

[`GetIdentityAssertion`](../type-aliases/GetIdentityAssertion.md)

## Example

```ts
const storage = inMemoryStore();
const client = await createHostedSignalProtocolClient({
  adapters: { storage },
  hosted: {
    signalProtocolRelayUrl: process.env.OPEN_E2EE_SIGNAL_RELAY_URL ?? process.env.OPEN_E2EE_RELAY_URL!,
    getIdentityAssertion: hostedSignalProtocolRelaySandboxIdentity(storage),
  },
});
```

## Deprecated

Use `hostedSignalProtocolRelaySandboxIdentity`. SDK 15.0.0 removes this name.
