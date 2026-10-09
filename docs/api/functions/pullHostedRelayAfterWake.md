[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / pullHostedRelayAfterWake

# Function: pullHostedRelayAfterWake()

> **pullHostedRelayAfterWake**(`options`): `Promise`\<[`HostedRelayWakeResult`](../interfaces/HostedRelayWakeResult.md)\>

Authenticate, pull the durable mailbox, process each envelope, hand off
each Relay receipt after the envelopes, and acknowledge only handled work.
Register onMessageDecrypted to persist application content before calling
this function. Push is not required.

## Parameters

### options

[`HostedRelayWakeOptions`](../interfaces/HostedRelayWakeOptions.md)

## Returns

`Promise`\<[`HostedRelayWakeResult`](../interfaces/HostedRelayWakeResult.md)\>
