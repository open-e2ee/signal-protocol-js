[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / createHostedSignalProtocolClient

# Function: createHostedSignalProtocolClient()

> **createHostedSignalProtocolClient**(`options`): `Promise`\<[`DefaultSignalProtocolClient`](../classes/DefaultSignalProtocolClient.md)\>

Create a Signal Protocol Relay client without accepting a caller-supplied account or device ID.

The Relay verifies the assertion and device proof, then returns the canonical
account, registered device, scope, and authenticated transport used by the client.

In a Sandbox environment, [hostedSignalProtocolRelaySandboxIdentity](hostedSignalProtocolRelaySandboxIdentity.md) supplies the
assertion. The Sandbox helper cannot serve Production. A Production project
in device-owned identity mode uses [hostedSignalProtocolRelayDeviceOwnedIdentity](hostedSignalProtocolRelayDeviceOwnedIdentity.md). A
Production project in application-bound mode needs an application callback
that returns an assertion from your backend. Recovery and provider migration
need an identity provider that authenticates the user.

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
    getIdentityAssertion: hostedSignalProtocolRelaySandboxIdentity(storage),
    signalProtocolRelayUrl: process.env.OPEN_E2EE_SIGNAL_RELAY_URL ?? process.env.OPEN_E2EE_RELAY_URL!,
  },
});
```
