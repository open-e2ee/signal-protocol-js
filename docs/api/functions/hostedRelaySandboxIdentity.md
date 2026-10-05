[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / hostedRelaySandboxIdentity

# Function: hostedRelaySandboxIdentity()

> **hostedRelaySandboxIdentity**(`storage`): [`GetIdentityAssertion`](../type-aliases/GetIdentityAssertion.md)

Creates the identity assertion callback for a Sandbox environment of the
Signal Protocol Relay.

The callback signs a short-lived device-owned assertion with an Ed25519 key
that it keeps in `storage`. It creates the key on the first call and uses the
same key after that, so the Relay returns the same account each time the
device registers. The key is separate for each publishable key. Pass the
same store as `adapters.storage`. A device that loses the store loses the
Sandbox account. Another device of the account joins through device linking.

The callback rejects a request for a production environment, for recovery,
for provider migration, or for recent or step-up assurance. A production
environment needs a `getIdentityAssertion` that your identity provider
supplies.

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
    relayUrl: process.env.OPEN_E2EE_RELAY_URL!,
    getIdentityAssertion: hostedRelaySandboxIdentity(storage),
  },
});
```
