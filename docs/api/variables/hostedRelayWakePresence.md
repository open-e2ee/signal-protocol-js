[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / hostedRelayWakePresence

# ~~Variable: hostedRelayWakePresence~~

> `const` **hostedRelayWakePresence**: (`client`) => [`HostedSignalProtocolRelayWakePresence`](../type-aliases/HostedSignalProtocolRelayWakePresence.md) = `hostedSignalProtocolRelayWakePresence`

The presence of a wake client, over HTTP. Use it only where the client runs
no mailbox subscription, for example beside `pullHostedSignalProtocolRelayAfterWake()`.

## Parameters

### client

[`HostedSignalProtocolRelayWakeClient`](../interfaces/HostedSignalProtocolRelayWakeClient.md)

## Returns

[`HostedSignalProtocolRelayWakePresence`](../type-aliases/HostedSignalProtocolRelayWakePresence.md)

## Deprecated

Use `hostedSignalProtocolRelayWakePresence`. SDK 15.0.0 removes this name.
