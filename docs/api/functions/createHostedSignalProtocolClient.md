[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / createHostedSignalProtocolClient

# Function: createHostedSignalProtocolClient()

> **createHostedSignalProtocolClient**(`options`): `Promise`\<[`DefaultSignalProtocolClient`](../classes/DefaultSignalProtocolClient.md)\>

Create a Signal Protocol Relay client without accepting a caller-supplied account or device ID.

The Relay verifies the assertion and device proof, then returns the canonical
account, registered device, scope, and authenticated transport used by the client.

In a Sandbox environment, [hostedRelaySandboxIdentity](hostedRelaySandboxIdentity.md) supplies the
assertion. In production, `getIdentityAssertion` gets the assertion from
your identity provider.

## Parameters

### options

[`HostedSignalProtocolClientOptions`](../interfaces/HostedSignalProtocolClientOptions.md)

## Returns

`Promise`\<[`DefaultSignalProtocolClient`](../classes/DefaultSignalProtocolClient.md)\>

## Example

```ts
const storage = inMemoryStore();
const client = await createHostedSignalProtocolClient({
  adapters: { storage },
  hosted: {
    getIdentityAssertion: hostedRelaySandboxIdentity(storage),
    relayUrl: process.env.OPEN_E2EE_RELAY_URL!,
  },
});
```
